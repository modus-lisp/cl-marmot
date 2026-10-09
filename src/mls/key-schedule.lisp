;;;; key-schedule.lisp — RFC 9420 §8 key schedule and §9 secret tree

(in-package #:cl-marmot)

(defun zero-secret () (make-octets +nh+))

;;; ---------------------------------------------------------------------------
;;; Epoch secrets

(defstruct epoch-secrets
  joiner-secret welcome-secret epoch-secret
  sender-data-secret encryption-secret exporter-secret external-secret
  confirmation-key membership-key resumption-psk epoch-authenticator
  init-secret)

(defun psk-secret (psks)
  "PSKS: list of (psk-id-struct . psk-octets).  No PSKs => all-zero secret."
  (let ((secret (zero-secret))
        (count (length psks)))
    (loop for (id . psk) in psks
          for index from 0
          do (let* ((extracted (hkdf-extract (zero-secret) psk))
                    (label (with-writer (w)
                             (encode-pre-shared-key-id w id)
                             (w-u16 w index)
                             (w-u16 w count)))
                    (input (expand-with-label extracted "derived psk" label +nh+)))
               (setf secret (hkdf-extract input secret))))
    secret))

(defun joiner-secret-from (init-secret commit-secret group-context-octets)
  (expand-with-label (hkdf-extract init-secret commit-secret) "joiner"
                     group-context-octets +nh+))

(defun epoch-secrets-from-joiner (joiner-secret psk-secret group-context-octets)
  "Derive every epoch secret from the joiner secret (§8, figure 22)."
  (let* ((member (hkdf-extract joiner-secret psk-secret))
         (epoch (expand-with-label member "epoch" group-context-octets +nh+)))
    (make-epoch-secrets
     :joiner-secret joiner-secret
     :welcome-secret (derive-secret member "welcome")
     :epoch-secret epoch
     :sender-data-secret (derive-secret epoch "sender data")
     :encryption-secret (derive-secret epoch "encryption")
     :exporter-secret (derive-secret epoch "exporter")
     :external-secret (derive-secret epoch "external")
     :confirmation-key (derive-secret epoch "confirm")
     :membership-key (derive-secret epoch "membership")
     :resumption-psk (derive-secret epoch "resumption")
     :epoch-authenticator (derive-secret epoch "authentication")
     :init-secret (derive-secret epoch "init"))))

(defun welcome-key-nonce (welcome-secret)
  (values (expand-with-label welcome-secret "key" (make-octets 0) +nk+)
          (expand-with-label welcome-secret "nonce" (make-octets 0) +nn+)))

(defun mls-exporter (exporter-secret label context length)
  "§8.5 MLS-Exporter.  LABEL and CONTEXT may be strings or octets."
  (flet ((b (x) (if (stringp x) (string->utf8 x) x)))
    (expand-with-label (derive-secret exporter-secret (b label))
                       "exported" (mls-hash (b context)) length)))

;;; ---------------------------------------------------------------------------
;;; Secret tree (§9)
;;;
;;; Node secrets are derived lazily from the root and DELETED as they are
;;; consumed (§9.2's deletion schedule): descending replaces a node's secret
;;; by its two children's.  Each leaf then has two ratchets (handshake and
;;; application); a ratchet keeps its current secret and generation plus a
;;; bounded cache of keys for generations skipped over (out-of-order receipt).

(defparameter *max-forward-distance* 1000)
(defparameter *out-of-order-tolerance* 64)

(defstruct (ratchet (:constructor make-ratchet (secret)))
  secret
  (generation 0)
  (skipped (make-hash-table)))   ; generation -> (key . nonce)

(defstruct (secret-tree (:constructor %make-secret-tree))
  n-leaves
  (nodes (make-hash-table))      ; node index -> secret
  (ratchets (make-hash-table :test #'equal)))  ; (leaf . :handshake|:application) -> ratchet

(defun make-secret-tree (encryption-secret n-leaves)
  (let ((st (%make-secret-tree :n-leaves n-leaves)))
    (setf (gethash (tm-root n-leaves) (secret-tree-nodes st)) encryption-secret)
    st))

(defun %secret-tree-leaf-secret (st leaf-index)
  "Consume and return the leaf's tree secret, deriving down from the nearest
stored ancestor."
  (let* ((nodes (secret-tree-nodes st))
         (target (* 2 leaf-index))
         (path (cons target (tm-direct-path target (secret-tree-n-leaves st))))
         (start (find-if (lambda (n) (gethash n nodes)) path)))
    (unless start (error 'crypto-error))
    ;; walk down from START to TARGET
    (let ((x start))
      (loop until (= x target)
            do (let* ((secret (gethash x nodes))
                      (l (tm-left x)) (r (tm-right x)))
                 (setf (gethash l nodes) (expand-with-label secret "tree" (string->utf8 "left") +nh+)
                       (gethash r nodes) (expand-with-label secret "tree" (string->utf8 "right") +nh+))
                 (remhash x nodes)
                 (setf x (if (tm-is-ancestor l target) l r))))
      (prog1 (gethash target nodes)
        (remhash target nodes)))))

(defun %secret-tree-ratchet (st leaf-index type)
  (let ((key (cons leaf-index type))
        (table (secret-tree-ratchets st)))
    (or (gethash key table)
        (let ((leaf-secret (%secret-tree-leaf-secret st leaf-index)))
          ;; initialise BOTH ratchets from the leaf secret, which is then gone
          (setf (gethash (cons leaf-index :handshake) table)
                (make-ratchet (expand-with-label leaf-secret "handshake" (make-octets 0) +nh+))
                (gethash (cons leaf-index :application) table)
                (make-ratchet (expand-with-label leaf-secret "application" (make-octets 0) +nh+)))
          (gethash key table)))))

(defun %ratchet-key-nonce (secret generation)
  (values (derive-tree-secret secret "key" generation +nk+)
          (derive-tree-secret secret "nonce" generation +nn+)))

(defun %ratchet-advance (r)
  (setf (ratchet-secret r) (derive-tree-secret (ratchet-secret r) "secret"
                                               (ratchet-generation r) +nh+))
  (incf (ratchet-generation r)))

(defun secret-tree-next-key (st leaf-index type)
  "For SENDING: the key/nonce for the current generation, then advance.
Returns (values key nonce generation)."
  (let ((r (%secret-tree-ratchet st leaf-index type)))
    (multiple-value-bind (key nonce) (%ratchet-key-nonce (ratchet-secret r) (ratchet-generation r))
      (let ((g (ratchet-generation r)))
        (%ratchet-advance r)
        (values key nonce g)))))

(defun secret-tree-key-for (st leaf-index type generation)
  "For RECEIVING generation GENERATION: returns (values key nonce), or NIL if
the key was already used/deleted or is out of range."
  (let ((r (%secret-tree-ratchet st leaf-index type)))
    (cond ((< generation (ratchet-generation r))
           (let ((cached (gethash generation (ratchet-skipped r))))
             (when cached
               (remhash generation (ratchet-skipped r))
               (values (car cached) (cdr cached)))))
          ((> (- generation (ratchet-generation r)) *max-forward-distance*) nil)
          (t
           (loop while (< (ratchet-generation r) generation)
                 do (multiple-value-bind (k n)
                        (%ratchet-key-nonce (ratchet-secret r) (ratchet-generation r))
                      (setf (gethash (ratchet-generation r) (ratchet-skipped r)) (cons k n)))
                    (%ratchet-advance r))
           ;; bound the skipped cache
           (let ((skipped (ratchet-skipped r)))
             (loop for g being the hash-keys of skipped
                   when (< g (- generation *out-of-order-tolerance*))
                     do (remhash g skipped)))
           (multiple-value-bind (key nonce)
               (%ratchet-key-nonce (ratchet-secret r) (ratchet-generation r))
             (%ratchet-advance r)
             (values key nonce))))))

(defun sender-data-key-nonce (sender-data-secret ciphertext)
  (let ((sample (subseq-octets ciphertext 0 (min +nh+ (length ciphertext)))))
    (values (expand-with-label sender-data-secret "key" sample +nk+)
            (expand-with-label sender-data-secret "nonce" sample +nn+))))
