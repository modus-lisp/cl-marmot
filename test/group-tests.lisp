;;;; group-tests.lisp — two and three cl-marmot members, no network
;;;;
;;;; Exercises the full Marmot group flow in memory: founding creation with a
;;;; Welcome, kind 445 envelopes both ways, admin commits (rename, add,
;;;; remove), self-update, and a save/load of the account state mid-stream.

(in-package #:cl-marmot/test)

(defun %commit-envelope (mg)
  "Seal the pending commit under the pre-commit epoch (what PUBLISH-COMMIT sends)."
  (seal-group-message (marmot-group-mls mg) (staged-commit-message (marmot-group-pending mg))))

(defun %deliver (mg ev)
  (receive-group-event mg (json->event (event->json ev) :require-sig t)))

(defun %message-texts (results)
  (mapcar (lambda (r) (getf r :content)) (remove-if-not (lambda (r) (eq (getf r :type) :message)) results)))

(deftest marmot-group-lifecycle ()
  (let* ((alice-sk (generate-nostr-key)) (bob-sk (generate-nostr-key)) (carol-sk (generate-nostr-key))
         (alice-pk (secp256k1-xonly-pubkey alice-sk))
         (bob-pk (secp256k1-xonly-pubkey bob-sk))
         (bob-kp (make-marmot-key-package bob-sk))
         (carol-kp (make-marmot-key-package carol-sk))
         (a (create-marmot-group alice-sk :name "test" :relays '("ws://127.0.0.1:1"))))
    (is-equal 0 (mg-epoch a))
    ;; founding Add, merged locally
    (let ((staged (stage-commit a :proposals (add-proposals-for (list (key-package-bundle-key-package bob-kp))))))
      (merge-pending a)
      (is-equal 1 (mg-epoch a))
      (let ((b (join-marmot-group (mls-message-body (tls-deserialize 'mls-message (staged-commit-welcome staged)))
                                  bob-kp)))
        (is-equal 1 (mg-epoch b))
        (is-equal "test" (mg-name b))
        ;; messages both ways
        (is-equal '("hi bob") (%message-texts (%deliver b (send-app-message a alice-pk 9 "hi bob"))))
        (is-equal '("hi alice") (%message-texts (%deliver a (send-app-message b bob-pk 9 "hi alice"))))
        ;; duplicate delivery is recognised
        (let ((ev (send-app-message a alice-pk 9 "once")))
          (is-equal '("once") (%message-texts (%deliver b ev)))
          (is-equal :duplicate (getf (first (%deliver b ev)) :type)))
        ;; admin rename
        (stage-commit a :proposals (list (make-proposal :type +prop-app-data-update+ :component-id +c-profile+
                                                         :operation 1 :data (encode-group-profile "renamed" ""))))
        (let ((env (%commit-envelope a)))
          (merge-pending a)
          (%deliver b env))
        (is-equal 2 (mg-epoch b))
        (is-equal "renamed" (mg-name b))
        ;; bob (not an admin) self-updates
        (stage-commit b)
        (let ((env (%commit-envelope b)))
          (merge-pending b)
          (%deliver a env))
        (is-equal 3 (mg-epoch a))
        (is (octets= (epoch-secrets-epoch-authenticator (mls-group-secrets (marmot-group-mls a)))
                     (epoch-secrets-epoch-authenticator (mls-group-secrets (marmot-group-mls b))))
            "same epoch authenticator after bob's commit")
        ;; persistence round trip mid-stream
        (let* ((acct (make-account-from-secret bob-sk :relays '("ws://127.0.0.1:1"))))
          (setf (gethash (mg-id-hex b) (account-groups acct)) b)
          (let ((restored (sexp->account (read-from-string
                                          (with-standard-io-syntax
                                            (let ((*package* (find-package '#:cl-marmot)))
                                              (prin1-to-string (account->sexp acct))))))))
            (setf b (account-group restored (mg-id-hex b)))))
        (is-equal '("after restore") (%message-texts (%deliver b (send-app-message a alice-pk 9 "after restore"))))
        ;; add carol (with a path), then remove bob
        (let ((staged (stage-commit a :proposals (add-proposals-for (list (key-package-bundle-key-package carol-kp))))))
          (let ((env (%commit-envelope a)))
            (merge-pending a)
            (%deliver b env))
          (let ((c (join-marmot-group (mls-message-body (tls-deserialize 'mls-message (staged-commit-welcome staged)))
                                      carol-kp)))
            (is-equal 3 (length (mls-group-members (marmot-group-mls b))))
            (is-equal '("three") (%message-texts (%deliver c (send-app-message b bob-pk 9 "three"))))
            (stage-commit a :proposals (list (make-proposal :type +prop-remove+
                                                            :removed (car (find bob-pk (mls-group-members (marmot-group-mls a))
                                                                                :key (lambda (m) (leaf-account (cdr m)))
                                                                                :test #'octets=)))))
            (let ((env (%commit-envelope a)))
              (merge-pending a)
              (%deliver c env)
              (%deliver b env))
            (is-equal 2 (length (mls-group-members (marmot-group-mls c))))
            (is (not (mls-group-active (marmot-group-mls b))) "bob sees his own removal")
            (is-equal :undecryptable (getf (first (%deliver b (send-app-message a alice-pk 9 "secret"))) :type))
            (is-equal '("bye bob") (%message-texts (%deliver c (send-app-message a alice-pk 9 "bye bob"))))))))))

(deftest marmot-rejects-non-admin-welcome-author ()
  ;; a Welcome whose author is not an admin must be rejected
  (let* ((alice-sk (generate-nostr-key)) (bob-sk (generate-nostr-key))
         (other (secp256k1-xonly-pubkey (generate-nostr-key)))
         (bob-kp (make-marmot-key-package bob-sk))
         (a (create-marmot-group alice-sk :name "x" :relays '("ws://127.0.0.1:1"))))
    ;; make the admin list someone who is not the committer... which is invalid
    ;; state, so stage-commit itself must refuse
    (signals marmot-error
             (stage-commit a :proposals (list (make-proposal :type +prop-app-data-update+
                                                             :component-id +c-admin-policy+ :operation 1
                                                             :data (encode-admin-policy (list other))))))
    (is (null (marmot-group-pending a)))
    (stage-commit a :proposals (add-proposals-for (list (key-package-bundle-key-package bob-kp))))
    (is (marmot-group-pending a))))

(deftest marmot-self-remove-and-authorization ()
  (let* ((alice-sk (generate-nostr-key)) (bob-sk (generate-nostr-key))
         (bob-pk (secp256k1-xonly-pubkey bob-sk))
         (bob-kp (make-marmot-key-package bob-sk))
         (a (create-marmot-group alice-sk :name "t" :relays '("ws://127.0.0.1:1")))
         (staged (stage-commit a :proposals (add-proposals-for (list (key-package-bundle-key-package bob-kp))))))
    (merge-pending a)
    (let ((b (join-marmot-group (mls-message-body (tls-deserialize 'mls-message (staged-commit-welcome staged)))
                                bob-kp)))
      ;; a non-admin may not rename, add or remove
      (signals marmot-error
               (stage-commit b :proposals (list (make-proposal :type +prop-app-data-update+ :component-id +c-profile+
                                                               :operation 1 :data (encode-group-profile "x" "")))))
      (is (null (marmot-group-pending b)))
      ;; an admin may not SelfRemove
      (signals marmot-error (self-remove-message a))
      ;; bob leaves: proposal -> alice commits it by reference -> bob is out
      (let ((ev (self-remove-message b)))
        (setf (marmot-group-leaving b) t)
        (is-equal :proposal (getf (first (%deliver a ev)) :type)))
      (signals marmot-error (send-app-message b bob-pk 9 "while leaving"))
      (let ((removes (pending-self-removes a)))
        (is-equal 1 (length removes))
        (stage-commit a :by-reference removes)
        (let ((env (%commit-envelope a)))
          (merge-pending a)
          (is-equal :removed (getf (first (%deliver b env)) :type))))
      (is-equal 1 (length (mls-group-members (marmot-group-mls a))))
      (is (null (pending-self-removes a)) "consumed proposals are gone in the new epoch"))))

(deftest marmot-message-retention-tag ()
  (let* ((sk (generate-nostr-key))
         (a (create-marmot-group sk :name "r" :relays '("ws://127.0.0.1:1"))))
    (is (null (event-tags-named (send-app-message a (secp256k1-xonly-pubkey sk) 9 "x") "expiration"))
        "no tag while retention is off")
    (stage-commit a :proposals (list (make-proposal :type +prop-app-data-update+ :component-id +c-message-retention+
                                                    :operation 1 :data (encode-message-retention 3600))))
    (merge-pending a)
    (let* ((ev (send-app-message a (secp256k1-xonly-pubkey sk) 9 "y"))
           (m (first (marmot-group-messages a))))
      (is-equal (format nil "~D" (+ 3600 (getf m :created-at))) (event-tag-value ev "expiration")))))

(defun %roundtrip-group (mg)
  "Save and restore a MARMOT-GROUP through the account store's encoding."
  (sexp->marmot-group (read-from-string (with-standard-io-syntax
                                          (let ((*package* (find-package '#:cl-marmot)))
                                            (prin1-to-string (marmot-group->sexp mg)))))))

(deftest marmot-pending-commit-survives-restart ()
  ;; publish-lifecycle.md "Restart": a commit saved as pending before it was
  ;; published must become canonical when its bytes come back from a relay,
  ;; even in a fresh process
  (let* ((alice-sk (generate-nostr-key)) (bob-sk (generate-nostr-key))
         (bob-kp (make-marmot-key-package bob-sk))
         (a (create-marmot-group alice-sk :name "d" :relays '("ws://127.0.0.1:1")))
         (st (stage-commit a :proposals (add-proposals-for (list (key-package-bundle-key-package bob-kp))))))
    (merge-pending a)
    (let ((b (join-marmot-group (mls-message-body (tls-deserialize 'mls-message (staged-commit-welcome st))) bob-kp)))
      (stage-commit a :proposals (list (make-proposal :type +prop-app-data-update+ :component-id +c-profile+
                                                      :operation 1 :data (encode-group-profile "renamed" ""))))
      (let* ((env (%commit-envelope a))
             (restarted (%roundtrip-group a)))
        (is (marmot-group-pending restarted) "the pending commit was saved")
        (is-equal 1 (mg-epoch restarted) "and is not yet canonical")
        (let ((r (%deliver restarted env)))
          (is (find :own-commit-merged r :key (lambda (x) (getf x :type))) "its echo merges it"))
        (is-equal 2 (mg-epoch restarted))
        (is-equal "renamed" (mg-name restarted))
        (is (null (marmot-group-pending restarted)))
        ;; and the other member agrees
        (%deliver b env)
        (is (octets= (epoch-secrets-epoch-authenticator (mls-group-secrets (marmot-group-mls restarted)))
                     (epoch-secrets-epoch-authenticator (mls-group-secrets (marmot-group-mls b)))))))))

(deftest marmot-pending-commit-superseded ()
  ;; two members self-update at the same epoch; the commit applied first wins
  ;; locally, and the other's pending commit is dropped and reported
  (let* ((alice-sk (generate-nostr-key)) (bob-sk (generate-nostr-key))
         (bob-kp (make-marmot-key-package bob-sk))
         (a (create-marmot-group alice-sk :name "s" :relays '("ws://127.0.0.1:1"))))
    (let ((st (stage-commit a :proposals (add-proposals-for (list (key-package-bundle-key-package bob-kp))))))
      (merge-pending a)
      (let ((b (join-marmot-group (mls-message-body (tls-deserialize 'mls-message (staged-commit-welcome st))) bob-kp)))
        (stage-commit a)
        (stage-commit b)
        (let ((alice-env (%commit-envelope a)))
          (merge-pending a)
          (let ((r (%deliver b alice-env)))
            (is (find :pending-superseded r :key (lambda (x) (getf x :type))) "bob is told his commit lost"))
          (is (null (marmot-group-pending b)))
          (is-equal (mg-epoch a) (mg-epoch b))
          (is-equal '("after the race") (%message-texts (%deliver b (send-app-message a (secp256k1-xonly-pubkey alice-sk)
                                                                                     9 "after the race")))))))))
