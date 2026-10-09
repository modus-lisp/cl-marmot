;;;; framing.lisp — RFC 9420 §6: signing, membership tags, PrivateMessage

(in-package #:cl-marmot)

(define-condition mls-error (error)
  ((message :initarg :message :reader mls-error-message))
  (:report (lambda (c s) (format s "MLS: ~A" (mls-error-message c)))))

(defun mls-fail (fmt &rest args)
  (error 'mls-error :message (apply #'format nil fmt args)))

;;; FramedContentTBS / AuthenticatedContent

(defun framed-content-tbs (wire-format fc group-context)
  (with-writer (w)
    (w-u16 w +mls10+)
    (w-u16 w wire-format)
    (encode-framed-content w fc)
    (when (member (sender-type (framed-content-sender fc))
                  (list +sender-member+ +sender-new-member-commit+))
      (encode-group-context w group-context))))

(defun sign-framed-content (signature-private-key wire-format fc group-context)
  (sign-with-label signature-private-key "FramedContentTBS"
                   (framed-content-tbs wire-format fc group-context)))

(defun verify-framed-content (signature-public-key wire-format fc group-context signature)
  (verify-with-label signature-public-key "FramedContentTBS"
                     (framed-content-tbs wire-format fc group-context) signature))

(defun authenticated-content-octets (wire-format fc auth)
  (with-writer (w)
    (w-u16 w wire-format)
    (encode-framed-content w fc)
    (encode-auth-data w auth (framed-content-content-type fc))))

(defun membership-tag (membership-key wire-format fc auth group-context)
  "MAC over AuthenticatedContentTBM = FramedContentTBS || FramedContentAuthData."
  (mls-mac membership-key
           (concat-octets (framed-content-tbs wire-format fc group-context)
                          (with-writer (w)
                            (encode-auth-data w auth (framed-content-content-type fc))))))

;;; Transcript hashes (§8.2)

(defun confirmed-transcript-hash-next (interim-prev wire-format fc signature)
  (mls-hash (concat-octets interim-prev
                           (with-writer (w)
                             (w-u16 w wire-format)
                             (encode-framed-content w fc)
                             (w-opaque w signature)))))

(defun interim-transcript-hash-next (confirmed confirmation-tag)
  (mls-hash (concat-octets confirmed (with-writer (w) (w-opaque w confirmation-tag)))))

;;; ---------------------------------------------------------------------------
;;; PrivateMessage (§6.3)

(defun %private-content-aad (group-id epoch content-type authenticated-data)
  (with-writer (w)
    (w-opaque w group-id)
    (w-u64 w epoch)
    (w-u8 w content-type)
    (w-opaque w authenticated-data)))

(defun %sender-data-aad (group-id epoch content-type)
  (with-writer (w)
    (w-opaque w group-id)
    (w-u64 w epoch)
    (w-u8 w content-type)))

(defun encrypt-private-message (fc auth secret-tree sender-data-secret &key (padding 0) reuse-guard)
  "Encrypt framed content FC (member sender) with AUTH into a PRIVATE-MESSAGE."
  (let* ((ct (framed-content-content-type fc))
         (leaf (sender-index (framed-content-sender fc)))
         (plaintext (with-writer (w)
                      (%encode-content-body w fc)
                      (encode-auth-data w auth ct)
                      (w-bytes w (make-octets padding))))
         (reuse-guard (or reuse-guard (random-octets 4))))
    (multiple-value-bind (key nonce generation)
        (secret-tree-next-key secret-tree leaf (if (= ct +content-application+) :application :handshake))
      (let ((nonce (copy-seq nonce)))
        (dotimes (i 4) (setf (aref nonce i) (logxor (aref nonce i) (aref reuse-guard i))))
        (let* ((ciphertext (mls-aead-encrypt key nonce plaintext
                                             (%private-content-aad (framed-content-group-id fc)
                                                                   (framed-content-epoch fc) ct
                                                                   (framed-content-authenticated-data fc))))
               (sender-data (with-writer (w) (w-u32 w leaf) (w-u32 w generation) (w-bytes w reuse-guard))))
          (multiple-value-bind (sd-key sd-nonce) (sender-data-key-nonce sender-data-secret ciphertext)
            (make-private-message
             :group-id (framed-content-group-id fc)
             :epoch (framed-content-epoch fc)
             :content-type ct
             :authenticated-data (framed-content-authenticated-data fc)
             :encrypted-sender-data (mls-aead-encrypt sd-key sd-nonce sender-data
                                                      (%sender-data-aad (framed-content-group-id fc)
                                                                        (framed-content-epoch fc) ct))
             :ciphertext ciphertext)))))))

(defun decrypt-private-message (pm secret-tree sender-data-secret)
  "Returns (values framed-content auth-data)."
  (let ((ct (private-message-content-type pm)))
    (multiple-value-bind (sd-key sd-nonce)
        (sender-data-key-nonce sender-data-secret (private-message-ciphertext pm))
      (let* ((sd (mls-aead-decrypt sd-key sd-nonce (private-message-encrypted-sender-data pm)
                                   (%sender-data-aad (private-message-group-id pm)
                                                     (private-message-epoch pm) ct)))
             (r (make-reader sd))
             (leaf (r-u32 r))
             (generation (r-u32 r))
             (reuse-guard (r-bytes r 4)))
        (reader-expect-done r "SenderData")
        (when (>= leaf (secret-tree-n-leaves secret-tree))
          (mls-fail "sender leaf ~D out of range" leaf))
        (multiple-value-bind (key nonce)
            (secret-tree-key-for secret-tree leaf
                                 (if (= ct +content-application+) :application :handshake)
                                 generation)
          (unless key (mls-fail "no key for generation ~D (replay or too far)" generation))
          (let ((nonce (copy-seq nonce)))
            (dotimes (i 4) (setf (aref nonce i) (logxor (aref nonce i) (aref reuse-guard i))))
            (let* ((plaintext (mls-aead-decrypt key nonce (private-message-ciphertext pm)
                                                (%private-content-aad
                                                 (private-message-group-id pm) (private-message-epoch pm)
                                                 ct (private-message-authenticated-data pm))))
                   (r2 (make-reader plaintext))
                   (fc (make-framed-content :group-id (private-message-group-id pm)
                                            :epoch (private-message-epoch pm)
                                            :sender (make-sender :type +sender-member+ :index leaf)
                                            :authenticated-data (private-message-authenticated-data pm)
                                            :content-type ct)))
              (%decode-content-body r2 fc)
              (let ((auth (decode-auth-data r2 ct)))
                (loop until (reader-done-p r2)
                      do (unless (zerop (r-u8 r2)) (mls-fail "non-zero padding")))
                (values fc auth)))))))))
