;;;; convergence.lisp — choosing the canonical branch (protocol-core/convergence.md)
;;;;
;;;; Each chat keeps a tree of retained group states (CNODEs): the canonical
;;;; path from the oldest retained state (the anchor) to the tip, plus any
;;;; competing branches.  A commit becomes a candidate edge from the retained
;;;; state whose epoch key and MLS authentication accept it; it is fully
;;;; validated (MLS, Marmot authorization against that parent, resulting-state
;;;; invariants) before the edge exists.  After every admission CONVERGE
;;;; compares the eligible branches with the v1 policy:
;;;;
;;;;   1. higher effective commit depth (raw depth + 1 with witness quorum)
;;;;   2. witness quorum beats none     3. higher app-witness score
;;;;   4. privileged tip before ordinary 5. lower tip committer  6. lower tip digest
;;;;
;;;; and, if a different branch wins, rolls back to the fork, reports what was
;;;; undone (commits and the messages delivered on them) and delivers what the
;;;; winning branch carried.  Linear advancement is the one-candidate case.
;;;;
;;;; Not implemented from the spec: the millisecond collection windows (a sync
;;;; batch plays that role: every commit it fetched is admitted before the
;;;; result is used), retained-history replay beyond the rollback horizon, and
;;;; the disband terminalization path.

(in-package #:cl-marmot)

;;; Convergence policy v1 (fixed for every client; not group state)
(defconstant +max-rewind-commits+ 5)
(defconstant +witness-quorum-senders-per-epoch+ 2)
(defconstant +witness-quorum-epochs+ 1)
(defconstant +max-witness-override-depth+ 1)


;;; ---------------------------------------------------------------------------
;;; The tree

(defun %ensure-tree (mg)
  "A chat created or joined without a tree gets one: its state is the anchor and tip."
  (unless (marmot-group-tip mg)
    (let ((n (make-cnode :state (marmot-group-mls mg))))
      (setf (marmot-group-tip mg) n
            (marmot-group-nodes mg) (list n))))
  mg)

(defun %path (n)
  "Nodes from the oldest retained ancestor down to N."
  (let ((path '()))
    (loop while n do (push n path) (setf n (cnode-parent n)))
    path))

(defun %canonical-p (mg n) (and (member n (%path (marmot-group-tip mg))) t))

(defun %children (mg n) (remove-if-not (lambda (c) (eq (cnode-parent c) n)) (marmot-group-nodes mg)))

(defun %candidate-nodes (mg)
  "States whose epoch key may open a kind 445 envelope: the tip first, then the
rest of the canonical path, then competing branches (transports/nostr.md
'Outer decryption and epoch selection')."
  (let ((canon (reverse (%path (marmot-group-tip mg)))))
    (append canon (remove-if (lambda (n) (member n canon)) (marmot-group-nodes mg)))))

(defun %commit-priority (proposal-types)
  "convergence.md: privileged exactly when the commit's authorization required
an active admin.  Self-updates and SelfRemove-only commits do not."
  (if (or (null proposal-types) (every (lambda (ty) (= ty +prop-self-remove+)) proposal-types))
      :ordinary
      :privileged))

(defun %add-node (mg parent new-state digest committer priority)
  (let ((n (make-cnode :state new-state :digest digest :parent parent
                       :committer committer :priority priority)))
    (push n (marmot-group-nodes mg))
    n))

(defun admit-commit (mg parent r digest)
  "Make the processed commit R (from PROCESS-MESSAGE against PARENT's state) a
candidate edge.  Returns NIL, or a string saying why it is invalid."
  (when (find digest (marmot-group-nodes mg) :key #'cnode-digest :test #'equal)
    (return-from admit-commit nil))
  (let* ((state (cnode-state parent))
         (sender (getf r :sender))
         (proposals (handler-case (%resolve-proposals state (getf r :commit) sender)
                      (mls-error (c) (return-from admit-commit (mls-error-message c)))))
         (why (commit-authorization-error state sender proposals))
         (new (getf r :new-group)))
    (when why (return-from admit-commit why))
    (when (mls-group-active new)
      (handler-case (validate-marmot-group-state new)
        (marmot-error (c) (return-from admit-commit (marmot-error-message c)))))
    (%add-node mg parent new digest (%leaf-account-at state sender)
               (%commit-priority (mapcar (lambda (ps) (proposal-type (car ps))) proposals)))
    nil))

(defun admit-own-commit (mg staged digest)
  "Our published commit, as a candidate edge from the tip it was built on."
  (let* ((tip (marmot-group-tip mg))
         (state (cnode-state tip))
         (fc (public-message-content (mls-message-body (tls-deserialize 'mls-message (staged-commit-message staged)))))
         (proposals (%resolve-proposals state (framed-content-commit fc) (mls-group-own-leaf state))))
    (%add-node mg tip (staged-commit-new-group staged) digest
               (%leaf-account-at state (mls-group-own-leaf state))
               (%commit-priority (mapcar (lambda (ps) (proposal-type (car ps))) proposals)))))

;;; ---------------------------------------------------------------------------
;;; Branch comparison

(defun %fork (a b)
  "The deepest node shared by the paths to A and B."
  (let ((pa (%path a)) (pb (%path b)) (fork nil))
    (loop for x in pa for y in pb while (eq x y) do (setf fork x))
    fork))

(defun %suffix (n fork)
  "Nodes after FORK on the path to N, oldest first."
  (let ((path (%path n)))
    (if fork (rest (member fork path)) path)))

(defun %branch-metrics (n fork)
  "(effective-depth quorum-p witness-score priority committer digest) of the
branch from FORK to N."
  (let* ((suffix (%suffix n fork))
         (per-epoch (mapcar (lambda (x) (min (length (cnode-senders x)) +witness-quorum-senders-per-epoch+)) suffix))
         (quorum (>= (count-if (lambda (k) (>= k +witness-quorum-senders-per-epoch+)) per-epoch)
                     +witness-quorum-epochs+))
         (depth (+ (length suffix) (if quorum +max-witness-override-depth+ 0))))
    (list depth quorum (reduce #'+ per-epoch) (cnode-priority n)
          (or (cnode-committer n) (make-octets 32 :initial-element 255))
          (or (cnode-digest n) ""))))

(defun %better-branch-p (a b)
  "Does the branch ending at A beat the one ending at B (convergence.md 'Branch selection')?"
  (let ((fork (%fork a b)))
    (destructuring-bind (da qa sa pa ca ga) (%branch-metrics a fork)
      (destructuring-bind (db qb sb pb cb gb) (%branch-metrics b fork)
        (cond ((/= da db) (> da db))
              ((not (eq qa qb)) qa)
              ((/= sa sb) (> sa sb))
              ((not (eq pa pb)) (eq pa :privileged))
              ((not (octets= ca cb)) (octets< ca cb))
              (t (string< ga gb)))))))

(defun %eligible-p (mg leaf base-epoch)
  (let ((fork (%fork leaf (marmot-group-tip mg))))
    (and fork (<= (- base-epoch (cnode-epoch fork)) *max-rewind-commits*))))

;;; ---------------------------------------------------------------------------
;;; Selection and application

(defun converge (mg)
  "Select the canonical branch; apply it if it changed.  Returns notifications."
  (%ensure-tree mg)
  (let* ((tip (marmot-group-tip mg))
         (base (cnode-epoch tip))
         (leaves (sort (remove-if (lambda (n) (%children mg n)) (copy-list (marmot-group-nodes mg)))
                       (lambda (a b) (string< (or (cnode-digest a) "") (or (cnode-digest b) "")))))
         (best tip))
    (dolist (leaf leaves)
      (when (and (not (eq leaf best)) (%eligible-p mg leaf base) (%better-branch-p leaf best))
        (setf best leaf)))
    (if (eq best tip)
        '()
        (prog1 (%switch-tip mg best)
          (%prune-tree mg)))))

(defun %switch-tip (mg best)
  (let* ((old (marmot-group-tip mg))
         (fork (%fork old best))
         (undone (%suffix old fork))
         (done (%suffix best fork))
         (out '()))
    (flet ((emit (x) (setf out (nconc out (list x)))))
      ;; what the losing branch had shown is withdrawn, newest commit first
      (dolist (n (reverse undone))
        (emit (%note mg :type :commit-invalidated :epoch (cnode-epoch n) :commit (cnode-digest n)))
        (loop for cell on (marmot-group-messages mg)
              for m = (car cell)
              when (and (equal (getf m :node) (cnode-digest n)) (not (getf m :invalidated)))
                do (setf (car cell) (list* :invalidated t m))
                   (emit (list :type :message-invalidated :id (getf m :id) :epoch (getf m :epoch)))))
      ;; the winning branch, commit by commit, with the messages it carried
      (dolist (n done)
        (dolist (x (%state-notes mg (cnode-state (cnode-parent n)) (cnode-state n)
                                 :committer (cnode-committer n) :digest (cnode-digest n)))
          (emit x))
        (dolist (m (reverse (cnode-held n)))
          (push m (marmot-group-messages mg))
          (emit m))
        (setf (cnode-held n) '()))
      (setf (marmot-group-tip mg) best
            (marmot-group-mls mg) (cnode-state best))
      ;; a pending commit of ours was built on the old tip
      (let ((staged (marmot-group-pending mg)))
        (when staged
          (setf (marmot-group-pending mg) nil)
          (emit (%note mg :type :pending-superseded :epoch (mg-epoch mg)
                          :invitees (mapcar #'car (staged-commit-invitees staged))))))
      out)))

(defun %prune-tree (mg)
  "Keep the anchor (the canonical state MAX-REWIND+1 commits back) and what
descends from it; drop branches forking before the rollback horizon."
  (let* ((tip (marmot-group-tip mg))
         (path (%path tip))
         (anchor (or (find-if (lambda (n) (>= (cnode-epoch n) (- (cnode-epoch tip) *max-rewind-commits* 1))) path)
                     (first path))))
    (setf (cnode-parent anchor) nil)
    (setf (marmot-group-nodes mg)
          (remove-if-not (lambda (n) (member anchor (%path n))) (marmot-group-nodes mg)))
    mg))
