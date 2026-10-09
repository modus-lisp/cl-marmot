;;;; structs.lisp — RFC 9420 wire structures (+ draft-ietf-mls-extensions-10)
;;;;
;;;; Every structure has a DEFSTRUCT, an ENCODE-<name> (writer value) and a
;;;; DECODE-<name> (reader).  Simple sequential structures come from DEFMLS;
;;;; structures with a `select` are written out by hand below it.  Decoders are
;;;; strict (minimal varints, exact presence bytes), so encode(decode(x)) == x
;;;; and re-encoding is a valid way to recover bytes for hashing and signing.

(in-package #:cl-marmot)

;;; ---------------------------------------------------------------------------
;;; Code points

(defconstant +mls10+ 1)
(defconstant +cs-x25519-aes128gcm-sha256-ed25519+ 1)

;; WireFormat
(defconstant +wf-public-message+ 1)
(defconstant +wf-private-message+ 2)
(defconstant +wf-welcome+ 3)
(defconstant +wf-group-info+ 4)
(defconstant +wf-key-package+ 5)

;; ExtensionType
(defconstant +ext-application-id+ 1)
(defconstant +ext-ratchet-tree+ 2)
(defconstant +ext-required-capabilities+ 3)
(defconstant +ext-external-pub+ 4)
(defconstant +ext-external-senders+ 5)
(defconstant +ext-app-data-dictionary+ 6)      ; extensions draft

;; ProposalType
(defconstant +prop-add+ 1)
(defconstant +prop-update+ 2)
(defconstant +prop-remove+ 3)
(defconstant +prop-psk+ 4)
(defconstant +prop-reinit+ 5)
(defconstant +prop-external-init+ 6)
(defconstant +prop-group-context-extensions+ 7)
(defconstant +prop-app-data-update+ 8)         ; extensions draft
(defconstant +prop-app-ephemeral+ 9)           ; extensions draft
(defconstant +prop-self-remove+ 10)            ; extensions draft

;; CredentialType
(defconstant +cred-basic+ 1)
(defconstant +cred-x509+ 2)

;; LeafNodeSource
(defconstant +lns-key-package+ 1)
(defconstant +lns-update+ 2)
(defconstant +lns-commit+ 3)

;; SenderType
(defconstant +sender-member+ 1)
(defconstant +sender-external+ 2)
(defconstant +sender-new-member-proposal+ 3)
(defconstant +sender-new-member-commit+ 4)

;; ContentType
(defconstant +content-application+ 1)
(defconstant +content-proposal+ 2)
(defconstant +content-commit+ 3)

;; Component ids (extensions draft)
(defconstant +component-app-components+ 1)
(defconstant +component-safe-aad+ 2)
(defconstant +component-last-resort-key-package+ 4)

;;; ---------------------------------------------------------------------------
;;; DEFMLS

(eval-when (:compile-toplevel :load-toplevel :execute)
(defun %field-encoder (type w-form v-form)
  (cond ((eq type :u8) `(w-u8 ,w-form ,v-form))
        ((eq type :u16) `(w-u16 ,w-form ,v-form))
        ((eq type :u32) `(w-u32 ,w-form ,v-form))
        ((eq type :u64) `(w-u64 ,w-form ,v-form))
        ((eq type :opaque) `(w-opaque ,w-form ,v-form))
        ((and (consp type) (eq (car type) :fixed)) `(w-bytes ,w-form ,v-form))
        ((and (consp type) (eq (car type) :list))
         (let ((ww (gensym "W")) (it (gensym "IT")))
           `(w-vector ,w-form ,v-form
                      (lambda (,ww ,it) ,(%field-encoder (second type) ww it)))))
        ((and (consp type) (eq (car type) :optional))
         (let ((ww (gensym "W")) (it (gensym "IT")))
           `(w-optional ,w-form ,v-form
                        (lambda (,ww ,it) ,(%field-encoder (second type) ww it)))))
        ((symbolp type)
         `(,(intern (format nil "ENCODE-~A" type) '#:cl-marmot) ,w-form ,v-form))
        (t (error "bad field type ~S" type))))

(defun %field-decoder (type r-form)
  (cond ((eq type :u8) `(r-u8 ,r-form))
        ((eq type :u16) `(r-u16 ,r-form))
        ((eq type :u32) `(r-u32 ,r-form))
        ((eq type :u64) `(r-u64 ,r-form))
        ((eq type :opaque) `(r-opaque ,r-form))
        ((and (consp type) (eq (car type) :fixed)) `(r-bytes ,r-form ,(second type)))
        ((and (consp type) (eq (car type) :list))
         (let ((rr (gensym "R")))
           `(r-vector ,r-form (lambda (,rr) ,(%field-decoder (second type) rr)))))
        ((and (consp type) (eq (car type) :optional))
         (let ((rr (gensym "R")))
           `(r-optional ,r-form (lambda (,rr) ,(%field-decoder (second type) rr)))))
        ((symbolp type)
         `(,(intern (format nil "DECODE-~A" type) '#:cl-marmot) ,r-form))
        (t (error "bad field type ~S" type)))))

(defmacro defmls (name &body fields)
  "Define a sequential TLS struct: (defmls name (slot type) ...)."
  (let ((enc (intern (format nil "ENCODE-~A" name)))
        (dec (intern (format nil "DECODE-~A" name)))
        (make (intern (format nil "MAKE-~A" name)))
        (w (gensym "W")) (r (gensym "R")) (x (gensym "X")))
    `(progn
       (defstruct ,name ,@(mapcar (lambda (f) (list (first f) nil)) fields))
       (defun ,enc (,w ,x)
         ,@(mapcar (lambda (f)
                     (%field-encoder (second f) w
                                     `(,(intern (format nil "~A-~A" name (first f))) ,x)))
                   fields)
         ,x)
       (defun ,dec (,r)
         (,make ,@(mapcan (lambda (f)
                            (list (intern (symbol-name (first f)) :keyword)
                                  (%field-decoder (second f) r)))
                          fields)))
       ',name)))

(defun tls-serialize (type value)
  "Encode VALUE as TYPE (a DEFMLS / hand-written struct name) to octets."
  (let ((fn (intern (format nil "ENCODE-~A" type) '#:cl-marmot)))
    (with-writer (w) (funcall fn w value))))

(defun tls-deserialize (type octets)
  "Decode OCTETS as exactly one TYPE."
  (let ((fn (intern (format nil "DECODE-~A" type) '#:cl-marmot)))
    (decode-exactly octets fn type)))

;;; ---------------------------------------------------------------------------
;;; Basic structures

(defmls extension
  (type :u16)
  (data :opaque))

(defun find-extension (extensions type)
  (find type extensions :key #'extension-type))

(defun extension-data-of (extensions type)
  (let ((e (find-extension extensions type)))
    (and e (extension-data e))))

(defmls capabilities
  (versions (:list :u16))
  (cipher-suites (:list :u16))
  (extensions (:list :u16))
  (proposals (:list :u16))
  (credentials (:list :u16)))

(defmls lifetime
  (not-before :u64)
  (not-after :u64))

(defmls required-capabilities
  (extension-types (:list :u16))
  (proposal-types (:list :u16))
  (credential-types (:list :u16)))

(defmls hpke-ciphertext
  (kem-output :opaque)
  (ciphertext :opaque))

;;; Credential (select on credential_type)

(defstruct credential
  (type +cred-basic+)
  (identity nil)          ; basic
  (certificates nil))     ; x509: list of opaque

(defun encode-credential (w c)
  (w-u16 w (credential-type c))
  (cond ((= (credential-type c) +cred-basic+) (w-opaque w (credential-identity c)))
        ((= (credential-type c) +cred-x509+)
         (w-vector w (credential-certificates c) (lambda (w2 cert) (w-opaque w2 cert))))
        (t (error "cannot encode credential type ~D" (credential-type c)))))

(defun decode-credential (r)
  (let ((type (r-u16 r)))
    (cond ((= type +cred-basic+) (make-credential :type type :identity (r-opaque r)))
          ((= type +cred-x509+)
           (make-credential :type type :certificates (r-vector r #'r-opaque)))
          (t (decode-fail "unknown credential type ~D" type)))))

(defun basic-credential (identity)
  (make-credential :type +cred-basic+ :identity identity))

;;; ---------------------------------------------------------------------------
;;; LeafNode

(defstruct leaf-node
  encryption-key          ; HPKEPublicKey (opaque)
  signature-key           ; SignaturePublicKey (opaque)
  credential
  capabilities
  (source +lns-key-package+)
  lifetime                ; when source = key_package
  parent-hash             ; when source = commit
  (extensions '())
  signature)

(defun %encode-leaf-node-body (w ln)
  (w-opaque w (leaf-node-encryption-key ln))
  (w-opaque w (leaf-node-signature-key ln))
  (encode-credential w (leaf-node-credential ln))
  (encode-capabilities w (leaf-node-capabilities ln))
  (w-u8 w (leaf-node-source ln))
  (let ((src (leaf-node-source ln)))
    (cond ((= src +lns-key-package+) (encode-lifetime w (leaf-node-lifetime ln)))
          ((= src +lns-update+))
          ((= src +lns-commit+) (w-opaque w (leaf-node-parent-hash ln)))
          (t (error "bad leaf node source ~D" src))))
  (w-vector w (leaf-node-extensions ln) #'encode-extension))

(defun encode-leaf-node (w ln)
  (%encode-leaf-node-body w ln)
  (w-opaque w (leaf-node-signature ln)))

(defun decode-leaf-node (r)
  (let* ((enc (r-opaque r))
         (sig-key (r-opaque r))
         (cred (decode-credential r))
         (caps (decode-capabilities r))
         (src (r-u8 r))
         (ln (make-leaf-node :encryption-key enc :signature-key sig-key
                             :credential cred :capabilities caps :source src)))
    (cond ((= src +lns-key-package+) (setf (leaf-node-lifetime ln) (decode-lifetime r)))
          ((= src +lns-update+))
          ((= src +lns-commit+) (setf (leaf-node-parent-hash ln) (r-opaque r)))
          (t (decode-fail "bad leaf node source ~D" src)))
    (setf (leaf-node-extensions ln) (r-vector r #'decode-extension)
          (leaf-node-signature ln) (r-opaque r))
    ln))

(defun leaf-node-tbs (ln &key group-id leaf-index)
  "LeafNodeTBS: the body plus, for update/commit sources, group_id and leaf_index."
  (with-writer (w)
    (%encode-leaf-node-body w ln)
    (when (member (leaf-node-source ln) (list +lns-update+ +lns-commit+))
      (w-opaque w group-id)
      (w-u32 w leaf-index))))

;;; ---------------------------------------------------------------------------
;;; KeyPackage

(defstruct key-package
  (version +mls10+)
  (cipher-suite +cs-x25519-aes128gcm-sha256-ed25519+)
  init-key
  leaf-node
  (extensions '())
  signature)

(defun %encode-key-package-body (w kp)
  (w-u16 w (key-package-version kp))
  (w-u16 w (key-package-cipher-suite kp))
  (w-opaque w (key-package-init-key kp))
  (encode-leaf-node w (key-package-leaf-node kp))
  (w-vector w (key-package-extensions kp) #'encode-extension))

(defun encode-key-package (w kp)
  (%encode-key-package-body w kp)
  (w-opaque w (key-package-signature kp)))

(defun decode-key-package (r)
  (make-key-package :version (r-u16 r)
                    :cipher-suite (r-u16 r)
                    :init-key (r-opaque r)
                    :leaf-node (decode-leaf-node r)
                    :extensions (r-vector r #'decode-extension)
                    :signature (r-opaque r)))

(defun key-package-tbs (kp)
  (with-writer (w) (%encode-key-package-body w kp)))

;;; ---------------------------------------------------------------------------
;;; Ratchet tree nodes

(defmls parent-node
  (encryption-key :opaque)
  (parent-hash :opaque)
  (unmerged-leaves (:list :u32)))

(defun encode-tree-node (w node)
  "Node: tagged union of leaf-node / parent-node."
  (etypecase node
    (leaf-node (w-u8 w 1) (encode-leaf-node w node))
    (parent-node (w-u8 w 2) (encode-parent-node w node))))

(defun decode-tree-node (r)
  (case (r-u8 r)
    (1 (decode-leaf-node r))
    (2 (decode-parent-node r))
    (t (decode-fail "bad node type"))))

(defun encode-ratchet-tree (w nodes)
  "optional<Node> ratchet_tree<V>; NODES is a list with NIL for blanks."
  (w-vector w nodes (lambda (w2 n) (w-optional w2 n #'encode-tree-node))))

(defun decode-ratchet-tree (r)
  (r-vector r (lambda (r2) (r-optional r2 #'decode-tree-node))))

;;; ---------------------------------------------------------------------------
;;; GroupContext

(defmls group-context
  (version :u16)
  (cipher-suite :u16)
  (group-id :opaque)
  (epoch :u64)
  (tree-hash :opaque)
  (confirmed-transcript-hash :opaque)
  (extensions (:list extension)))

(defun copy-group-context-with (gc &rest args)
  (let ((new (copy-group-context gc)))
    (loop for (k v) on args by #'cddr
          do (ecase k
               (:epoch (setf (group-context-epoch new) v))
               (:tree-hash (setf (group-context-tree-hash new) v))
               (:confirmed-transcript-hash (setf (group-context-confirmed-transcript-hash new) v))
               (:extensions (setf (group-context-extensions new) v))))
    new))

;;; ---------------------------------------------------------------------------
;;; Proposals

(defstruct pre-shared-key-id
  (type 1)                ; 1 external, 2 resumption
  psk-id                  ; external
  (usage 0) group-id (epoch 0)  ; resumption
  psk-nonce)

(defun encode-pre-shared-key-id (w p)
  (w-u8 w (pre-shared-key-id-type p))
  (ecase (pre-shared-key-id-type p)
    (1 (w-opaque w (pre-shared-key-id-psk-id p)))
    (2 (w-u8 w (pre-shared-key-id-usage p))
       (w-opaque w (pre-shared-key-id-group-id p))
       (w-u64 w (pre-shared-key-id-epoch p))))
  (w-opaque w (pre-shared-key-id-psk-nonce p)))

(defun decode-pre-shared-key-id (r)
  (let ((p (make-pre-shared-key-id :type (r-u8 r))))
    (case (pre-shared-key-id-type p)
      (1 (setf (pre-shared-key-id-psk-id p) (r-opaque r)))
      (2 (setf (pre-shared-key-id-usage p) (r-u8 r)
               (pre-shared-key-id-group-id p) (r-opaque r)
               (pre-shared-key-id-epoch p) (r-u64 r)))
      (t (decode-fail "bad PSK type")))
    (setf (pre-shared-key-id-psk-nonce p) (r-opaque r))
    p))

(defstruct proposal
  type
  ;; payload, by type:
  key-package             ; add
  leaf-node               ; update
  removed                 ; remove (leaf index)
  psk                     ; psk
  reinit                  ; reinit: plist (:group-id :version :cipher-suite :extensions)
  kem-output              ; external_init
  extensions              ; group_context_extensions
  component-id            ; app_data_update / app_ephemeral
  operation               ; app_data_update: 1 update, 2 remove
  data                    ; app_data_update update bytes / app_ephemeral data
  raw)                    ; unknown proposal types: body cannot be delimited

(defun encode-proposal (w p)
  (let ((ty (proposal-type p)))
    (w-u16 w ty)
    (cond ((= ty +prop-add+) (encode-key-package w (proposal-key-package p)))
          ((= ty +prop-update+) (encode-leaf-node w (proposal-leaf-node p)))
          ((= ty +prop-remove+) (w-u32 w (proposal-removed p)))
          ((= ty +prop-psk+) (encode-pre-shared-key-id w (proposal-psk p)))
          ((= ty +prop-reinit+)
           (destructuring-bind (&key group-id version cipher-suite extensions) (proposal-reinit p)
             (w-opaque w group-id) (w-u16 w version) (w-u16 w cipher-suite)
             (w-vector w extensions #'encode-extension)))
          ((= ty +prop-external-init+) (w-opaque w (proposal-kem-output p)))
          ((= ty +prop-group-context-extensions+)
           (w-vector w (proposal-extensions p) #'encode-extension))
          ((= ty +prop-app-data-update+)
           (w-u16 w (proposal-component-id p))
           (w-u8 w (proposal-operation p))
           (when (= (proposal-operation p) 1) (w-opaque w (proposal-data p))))
          ((= ty +prop-app-ephemeral+)
           (w-u16 w (proposal-component-id p))
           (w-opaque w (proposal-data p)))
          ((= ty +prop-self-remove+))
          (t (error "cannot encode proposal type ~D" ty)))))

(defun decode-proposal (r)
  (let* ((ty (r-u16 r))
         (p (make-proposal :type ty)))
    (cond ((= ty +prop-add+) (setf (proposal-key-package p) (decode-key-package r)))
          ((= ty +prop-update+) (setf (proposal-leaf-node p) (decode-leaf-node r)))
          ((= ty +prop-remove+) (setf (proposal-removed p) (r-u32 r)))
          ((= ty +prop-psk+) (setf (proposal-psk p) (decode-pre-shared-key-id r)))
          ((= ty +prop-reinit+)
           (setf (proposal-reinit p)
                 (list :group-id (r-opaque r) :version (r-u16 r) :cipher-suite (r-u16 r)
                       :extensions (r-vector r #'decode-extension))))
          ((= ty +prop-external-init+) (setf (proposal-kem-output p) (r-opaque r)))
          ((= ty +prop-group-context-extensions+)
           (setf (proposal-extensions p) (r-vector r #'decode-extension)))
          ((= ty +prop-app-data-update+)
           (setf (proposal-component-id p) (r-u16 r)
                 (proposal-operation p) (r-u8 r))
           (case (proposal-operation p)
             (1 (setf (proposal-data p) (r-opaque r)))
             (2)
             (t (decode-fail "bad AppDataUpdate operation"))))
          ((= ty +prop-app-ephemeral+)
           (setf (proposal-component-id p) (r-u16 r)
                 (proposal-data p) (r-opaque r)))
          ((= ty +prop-self-remove+))
          (t (decode-fail "unknown proposal type ~D" ty)))
    p))

;;; ProposalOrRef

(defstruct proposal-or-ref
  proposal                ; when type = 1
  reference)              ; when type = 2 (ProposalRef bytes)

(defun encode-proposal-or-ref (w x)
  (if (proposal-or-ref-proposal x)
      (progn (w-u8 w 1) (encode-proposal w (proposal-or-ref-proposal x)))
      (progn (w-u8 w 2) (w-opaque w (proposal-or-ref-reference x)))))

(defun decode-proposal-or-ref (r)
  (case (r-u8 r)
    (1 (make-proposal-or-ref :proposal (decode-proposal r)))
    (2 (make-proposal-or-ref :reference (r-opaque r)))
    (t (decode-fail "bad ProposalOrRef type"))))

;;; Commit / UpdatePath

(defmls update-path-node
  (encryption-key :opaque)
  (encrypted-path-secret (:list hpke-ciphertext)))

(defmls update-path
  (leaf-node leaf-node)
  (nodes (:list update-path-node)))

(defmls commit
  (proposals (:list proposal-or-ref))
  (path (:optional update-path)))

;;; ---------------------------------------------------------------------------
;;; Framing

(defstruct sender
  (type +sender-member+)
  (index 0))              ; leaf_index (member) / sender_index (external)

(defun encode-sender (w s)
  (w-u8 w (sender-type s))
  (when (member (sender-type s) (list +sender-member+ +sender-external+))
    (w-u32 w (sender-index s))))

(defun decode-sender (r)
  (let ((ty (r-u8 r)))
    (cond ((member ty (list +sender-member+ +sender-external+))
           (make-sender :type ty :index (r-u32 r)))
          ((member ty (list +sender-new-member-proposal+ +sender-new-member-commit+))
           (make-sender :type ty :index nil))
          (t (decode-fail "bad sender type ~D" ty)))))

(defstruct framed-content
  group-id
  (epoch 0)
  sender
  (authenticated-data (make-octets 0))
  content-type
  application-data        ; application
  proposal                ; proposal
  commit)                 ; commit

(defun %encode-content-body (w fc)
  (let ((ct (framed-content-content-type fc)))
    (cond ((= ct +content-application+) (w-opaque w (framed-content-application-data fc)))
          ((= ct +content-proposal+) (encode-proposal w (framed-content-proposal fc)))
          ((= ct +content-commit+) (encode-commit w (framed-content-commit fc)))
          (t (error "bad content type")))))

(defun %decode-content-body (r fc)
  (let ((ct (framed-content-content-type fc)))
    (cond ((= ct +content-application+) (setf (framed-content-application-data fc) (r-opaque r)))
          ((= ct +content-proposal+) (setf (framed-content-proposal fc) (decode-proposal r)))
          ((= ct +content-commit+) (setf (framed-content-commit fc) (decode-commit r)))
          (t (decode-fail "bad content type ~D" ct)))
    fc))

(defun encode-framed-content (w fc)
  (w-opaque w (framed-content-group-id fc))
  (w-u64 w (framed-content-epoch fc))
  (encode-sender w (framed-content-sender fc))
  (w-opaque w (framed-content-authenticated-data fc))
  (w-u8 w (framed-content-content-type fc))
  (%encode-content-body w fc))

(defun decode-framed-content (r)
  (let ((fc (make-framed-content :group-id (r-opaque r)
                                 :epoch (r-u64 r)
                                 :sender (decode-sender r)
                                 :authenticated-data (r-opaque r)
                                 :content-type (r-u8 r))))
    (%decode-content-body r fc)))

(defstruct auth-data
  signature
  confirmation-tag)       ; commit only

(defun encode-auth-data (w a content-type)
  (w-opaque w (auth-data-signature a))
  (when (= content-type +content-commit+)
    (w-opaque w (auth-data-confirmation-tag a))))

(defun decode-auth-data (r content-type)
  (let ((a (make-auth-data :signature (r-opaque r))))
    (when (= content-type +content-commit+)
      (setf (auth-data-confirmation-tag a) (r-opaque r)))
    a))

(defstruct public-message
  content                 ; framed-content
  auth                    ; auth-data
  membership-tag)         ; member senders only

(defun encode-public-message (w pm)
  (let ((fc (public-message-content pm)))
    (encode-framed-content w fc)
    (encode-auth-data w (public-message-auth pm) (framed-content-content-type fc))
    (when (= (sender-type (framed-content-sender fc)) +sender-member+)
      (w-opaque w (public-message-membership-tag pm)))))

(defun decode-public-message (r)
  (let* ((fc (decode-framed-content r))
         (auth (decode-auth-data r (framed-content-content-type fc)))
         (pm (make-public-message :content fc :auth auth)))
    (when (= (sender-type (framed-content-sender fc)) +sender-member+)
      (setf (public-message-membership-tag pm) (r-opaque r)))
    pm))

(defmls private-message
  (group-id :opaque)
  (epoch :u64)
  (content-type :u8)
  (authenticated-data :opaque)
  (encrypted-sender-data :opaque)
  (ciphertext :opaque))

;;; Welcome / GroupInfo

(defmls encrypted-group-secrets
  (new-member :opaque)
  (encrypted-group-secrets hpke-ciphertext))

(defmls welcome
  (cipher-suite :u16)
  (secrets (:list encrypted-group-secrets))
  (encrypted-group-info :opaque))

(defmls group-secrets
  (joiner-secret :opaque)
  (path-secret (:optional :opaque))
  (psks (:list pre-shared-key-id)))

(defmls group-info
  (group-context group-context)
  (extensions (:list extension))
  (confirmation-tag :opaque)
  (signer :u32)
  (signature :opaque))

(defun group-info-tbs (gi)
  (with-writer (w)
    (encode-group-context w (group-info-group-context gi))
    (w-vector w (group-info-extensions gi) #'encode-extension)
    (w-opaque w (group-info-confirmation-tag gi))
    (w-u32 w (group-info-signer gi))))

;;; MLSMessage

(defstruct mls-message
  (version +mls10+)
  wire-format
  body)                   ; public-message / private-message / welcome / group-info / key-package

(defun encode-mls-message (w m)
  (w-u16 w (mls-message-version m))
  (w-u16 w (mls-message-wire-format m))
  (let ((b (mls-message-body m)))
    (ecase (mls-message-wire-format m)
      (1 (encode-public-message w b))
      (2 (encode-private-message w b))
      (3 (encode-welcome w b))
      (4 (encode-group-info w b))
      (5 (encode-key-package w b)))))

(defun decode-mls-message (r)
  (let* ((version (r-u16 r))
         (wf (r-u16 r)))
    (unless (= version +mls10+) (decode-fail "unsupported MLS version ~D" version))
    (make-mls-message
     :version version :wire-format wf
     :body (case wf
             (1 (decode-public-message r))
             (2 (decode-private-message r))
             (3 (decode-welcome r))
             (4 (decode-group-info r))
             (5 (decode-key-package r))
             (t (decode-fail "unknown wire format ~D" wf))))))

(defun mls-message-octets (wire-format body)
  (tls-serialize 'mls-message (make-mls-message :wire-format wire-format :body body)))

;;; ---------------------------------------------------------------------------
;;; Extensions draft: AppDataDictionary, component id lists

(defmls component-data
  (component-id :u16)
  (data :opaque))

(defun encode-app-data-dictionary (w entries)
  "ENTRIES: list of component-data, written in ascending component id order."
  (w-vector w (sort (copy-list entries) #'< :key #'component-data-component-id)
            #'encode-component-data))

(defun decode-app-data-dictionary (r)
  (let ((entries (r-vector r #'decode-component-data)))
    ;; sorted, unique
    (loop for (a b) on entries
          while b
          do (unless (< (component-data-component-id a) (component-data-component-id b))
               (decode-fail "AppDataDictionary entries not sorted/unique")))
    entries))

(defun app-data-get (entries component-id)
  (let ((e (find component-id entries :key #'component-data-component-id)))
    (and e (component-data-data e))))

(defun app-data-put (entries component-id data)
  "Return a new entry list with COMPONENT-ID set to DATA (NIL removes)."
  (let ((rest (remove component-id entries :key #'component-data-component-id)))
    (sort (if data
              (cons (make-component-data :component-id component-id :data data) rest)
              rest)
          #'< :key #'component-data-component-id)))

(defun encode-component-id-list (ids)
  "ComponentID component_ids<V> — the data of the app_components component."
  (with-writer (w) (w-vector w ids #'w-u16)))

(defun decode-component-id-list (octets)
  (decode-exactly octets (lambda (r) (r-vector r #'r-u16)) "component id list"))

(defun extensions-app-data (extensions)
  "The decoded AppDataDictionary in an extension list, or NIL."
  (let ((data (extension-data-of extensions +ext-app-data-dictionary+)))
    (and data (decode-exactly data #'decode-app-data-dictionary "AppDataDictionary"))))

(defun app-data-extension (entries)
  (make-extension :type +ext-app-data-dictionary+
                  :data (with-writer (w) (encode-app-data-dictionary w entries))))
