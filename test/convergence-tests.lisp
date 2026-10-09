;;;; convergence-tests.lisp — competing commits converge (protocol-core/convergence.md)
;;;;
;;;; Four members; commits are delivered in different orders to different
;;;; members, and everyone must end on the same canonical state.

(in-package #:cl-marmot/test)

(defun %auth (mg) (epoch-secrets-epoch-authenticator (mls-group-secrets (marmot-group-mls mg))))

(defun %four-member-group ()
  "Returns (values groups secret-keys): alice (admin), bob, carol, dave, all at the same epoch."
  (let* ((sks (loop repeat 4 collect (generate-nostr-key)))
         (kps (mapcar #'make-marmot-key-package (rest sks)))
         (a (create-marmot-group (first sks) :name "race" :relays '("ws://127.0.0.1:1")))
         (st (stage-commit a :proposals (add-proposals-for (mapcar #'key-package-bundle-key-package kps)))))
    (merge-pending a)
    (let ((welcome (mls-message-body (tls-deserialize 'mls-message (staged-commit-welcome st)))))
      (values (cons a (mapcar (lambda (kp) (join-marmot-group welcome kp)) kps)) sks))))

(defun %publish-own (mg &rest args)
  "Stage a commit, take its envelope, and merge it locally (it was published)."
  (apply #'stage-commit mg args)
  (prog1 (%commit-envelope mg) (merge-pending mg)))

(defun %types (results) (mapcar (lambda (r) (getf r :type)) results))

(deftest convergence-same-epoch-race ()
  (multiple-value-bind (gs sks) (%four-member-group)
    (destructuring-bind (a b c d) gs
      (let ((env-a (%publish-own a))          ; alice self-updates ...
            (env-b (%publish-own b)))         ; ... and so does bob, from the same epoch
        (%deliver c env-a) (%deliver c env-b) ; carol: A then B
        (%deliver d env-b) (%deliver d env-a) ; dave:  B then A
        (%deliver a env-b)
        (%deliver b env-a)
        (let ((auth (%auth a)))
          (is (every (lambda (g) (octets= auth (%auth g))) gs) "all four agree")
          (is-equal 2 (mg-epoch a)))
        ;; both are ordinary, tied on depth and witnesses: the lower committer wins
        (let* ((pa (secp256k1-xonly-pubkey (first sks)))
               (pb (secp256k1-xonly-pubkey (second sks)))
               (winner (if (octets< pa pb) a b)))
          (is (octets= (%auth winner) (%auth c)) "the lower committer's commit won"))
        ;; and the group still works after the switch
        (is-equal '("after") (%message-texts (%deliver c (send-app-message d (secp256k1-xonly-pubkey (fourth sks))
                                                                          9 "after"))))))))

(deftest convergence-witness-quorum-beats-tiebreak ()
  (multiple-value-bind (gs sks) (%four-member-group)
    (destructuring-bind (a b c d) gs
      (let* ((pa (secp256k1-xonly-pubkey (first sks)))
             (pb (secp256k1-xonly-pubkey (second sks)))
             ;; make the LOSER of the plain tie-break carry the witnesses
             (loser (if (octets< pa pb) b a))
             (winner (if (eq loser a) b a))
             (env-l (%publish-own loser))
             (env-w (%publish-own winner)))
        ;; carol and dave both follow the loser's branch first and talk on it
        (%deliver c env-l) (%deliver d env-l)
        (let ((m1 (send-app-message c (secp256k1-xonly-pubkey (third sks)) 9 "carol on L"))
              (m2 (send-app-message d (secp256k1-xonly-pubkey (fourth sks)) 9 "dave on L")))
          (dolist (g (list loser c d)) (%deliver g m1) (%deliver g m2))
          ;; the tie-break winner hears all of it: the witnessed branch must win
          (%deliver winner env-l) (%deliver winner m1) (%deliver winner m2)
          (dolist (g (list c d loser)) (%deliver g env-w))
          (let ((auth (%auth c)))
            (is (every (lambda (g) (octets= auth (%auth g))) gs) "all four agree")
            (is (octets= auth (%auth loser)) "the branch with witness quorum won"))
          (is (member "carol on L" (mapcar (lambda (m) (getf m :content)) (marmot-group-messages winner))
                      :test #'equal)
              "the switching member received the winning branch's messages"))))))

(deftest convergence-deeper-branch-wins-and-invalidates ()
  (multiple-value-bind (gs sks) (%four-member-group)
    (destructuring-bind (a b c d) gs
      (declare (ignore d))
      ;; bob commits once; alice commits twice in a row
      (let* ((env-b (%publish-own b))
             (env-a1 (%publish-own a))
             (env-a2 (%publish-own a)))
        ;; carol first follows bob's branch and sees a message on it
        (%deliver c env-b)
        (let ((mb (send-app-message b (secp256k1-xonly-pubkey (second sks)) 9 "bob's branch")))
          (is-equal '("bob's branch") (%message-texts (%deliver c mb)))
          ;; then alice's longer branch arrives
          (%deliver c env-a1)
          (let ((r (%deliver c env-a2)))
            (is (member :commit-invalidated (%types r)) "bob's commit is withdrawn")
            (is (member :message-invalidated (%types r)) "and the message shown on it"))
          (is-equal 3 (mg-epoch c))
          (is (octets= (%auth a) (%auth c)) "carol is on alice's branch")
          (%deliver b env-a1) (%deliver b env-a2)
          (is (octets= (%auth a) (%auth b)) "bob too"))))))
