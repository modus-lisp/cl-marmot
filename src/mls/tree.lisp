;;;; tree.lisp — the ratchet tree (RFC 9420 §4, §7, Appendix C)
;;;;
;;;; Array representation: node i is a leaf when i is even (leaf index i/2).
;;;; The tree is always full: the node vector has 2^(d+1) - 1 slots for 2^d
;;;; leaves.  A slot holds a LEAF-NODE, a PARENT-NODE, or NIL (blank).

(in-package #:cl-marmot)

;;; ---------------------------------------------------------------------------
;;; Tree math (Appendix C)

(defun tm-level (x)
  (if (evenp x) 0 (loop for k from 0 while (logbitp k x) finally (return k))))

(defun tm-node-width (n-leaves) (if (zerop n-leaves) 0 (1+ (* 2 (1- n-leaves)))))

(defun tm-root (n-leaves)
  (let ((w (tm-node-width n-leaves)))
    (1- (ash 1 (1- (integer-length w))))))

(defun tm-left (x)
  (let ((k (tm-level x)))
    (when (zerop k) (error "leaf has no children"))
    (logxor x (ash 1 (1- k)))))

(defun tm-right (x)
  (let ((k (tm-level x)))
    (when (zerop k) (error "leaf has no children"))
    (logxor x (ash 3 (1- k)))))

(defun %tm-parent-step (x)
  (let* ((k (tm-level x))
         (b (logand (ash x (- (1+ k))) 1)))
    (logxor (logior x (ash 1 k)) (ash b (1+ k)))))

(defun tm-parent (x n-leaves)
  (when (= x (tm-root n-leaves)) (error "root has no parent"))
  (let ((p (%tm-parent-step x)))
    (loop while (>= p (tm-node-width n-leaves)) do (setf p (%tm-parent-step p)))
    p))

(defun tm-sibling (x n-leaves)
  (let ((p (tm-parent x n-leaves)))
    (if (< x p) (tm-right p) (tm-left p))))

(defun tm-direct-path (x n-leaves)
  (let ((r (tm-root n-leaves)) (path '()))
    (loop until (= x r)
          do (setf x (tm-parent x n-leaves))
             (push x path))
    (nreverse path)))

(defun tm-copath (x n-leaves)
  (let ((d (tm-direct-path x n-leaves)))
    (if (null d)
        '()
        (mapcar (lambda (y) (tm-sibling y n-leaves))
                (butlast (cons x d))))))

(defun tm-is-ancestor (a x)
  "Is node A an ancestor of (or equal to) node X?"
  (let ((k (tm-level a)))
    (<= (- a (1- (ash 1 k))) x (+ a (1- (ash 1 k))))))

(defun tm-leaves-under (x)
  "Leaf indices in the subtree rooted at node X."
  (let* ((k (tm-level x))
         (lo (- x (1- (ash 1 k)))))
    (loop for node from lo to (+ x (1- (ash 1 k))) by 2 collect (/ node 2))))

(defun leaf-node-index (leaf-index) (* 2 leaf-index))

;;; ---------------------------------------------------------------------------
;;; The tree object

(defstruct (ratchet-tree (:constructor %make-ratchet-tree (nodes)))
  (nodes (vector) :type simple-vector))

(defun rt-size (tree) (length (ratchet-tree-nodes tree)))
(defun rt-n-leaves (tree) (/ (1+ (rt-size tree)) 2))
(defun rt-node (tree i) (svref (ratchet-tree-nodes tree) i))
(defun (setf rt-node) (value tree i) (setf (svref (ratchet-tree-nodes tree) i) value))
(defun rt-leaf (tree leaf-index) (rt-node tree (* 2 leaf-index)))

(defun copy-rt (tree)
  "Copy the node vector.  Nodes are treated as immutable values: every
mutation below replaces a slot rather than modifying a node in place."
  (%make-ratchet-tree (copy-seq (ratchet-tree-nodes tree))))

(defun make-ratchet-tree-from-nodes (nodes)
  "From the ratchet_tree extension's node list (trailing blanks may be
omitted): pad to a full tree."
  (let* ((n (length nodes)))
    (when (zerop n) (decode-fail "empty ratchet tree"))
    (when (evenp n) (decode-fail "ratchet tree has even node count"))
    (unless (car (last nodes)) (decode-fail "ratchet tree ends in a blank node"))
    (let* ((leaves (/ (1+ n) 2))
           (full-leaves (ash 1 (integer-length (1- leaves))))
           (v (make-array (tm-node-width full-leaves) :initial-element nil)))
      (loop for node in nodes for i from 0 do (setf (svref v i) node))
      ;; node types must match position
      (loop for i from 0 below (length v)
            for node = (svref v i)
            do (when (and node (if (evenp i)
                                   (not (leaf-node-p node))
                                   (not (parent-node-p node))))
                 (decode-fail "node ~D has the wrong type" i)))
      (%make-ratchet-tree v))))

(defun rt-export-nodes (tree)
  "Node list for the ratchet_tree extension, trailing blanks stripped."
  (let* ((v (ratchet-tree-nodes tree))
         (last (position-if-not #'null v :from-end t)))
    (coerce (subseq v 0 (1+ last)) 'list)))

(defun ratchet-tree-extension (tree)
  (make-extension :type +ext-ratchet-tree+
                  :data (with-writer (w) (encode-ratchet-tree w (rt-export-nodes tree)))))

(defun new-ratchet-tree-with-leaf (leaf)
  (%make-ratchet-tree (vector leaf)))

;;; Resolution / filtered direct path

(defun rt-resolution (tree x &key exclude-leaves)
  "Node indices of the resolution of X.  EXCLUDE-LEAVES (leaf indices) are
dropped from both leaf positions and unmerged lists."
  (let ((node (rt-node tree x)))
    (cond ((and node (evenp x))
           (if (member (/ x 2) exclude-leaves) '() (list x)))
          (node
           (cons x (loop for l in (parent-node-unmerged-leaves node)
                         unless (member l exclude-leaves)
                           collect (* 2 l))))
          ((evenp x) '())
          (t (append (rt-resolution tree (tm-left x) :exclude-leaves exclude-leaves)
                     (rt-resolution tree (tm-right x) :exclude-leaves exclude-leaves))))))

(defun rt-filtered-direct-path (tree leaf-index)
  "Direct-path nodes of LEAF-INDEX whose copath child has a non-empty resolution."
  (let* ((n (rt-n-leaves tree))
         (x (* 2 leaf-index)))
    (loop for p in (tm-direct-path x n)
          for c in (tm-copath x n)
          when (rt-resolution tree c)
            collect p)))

(defun rt-filtered-direct-path-with-copath (tree leaf-index)
  "List of (parent . copath-child) pairs for the filtered direct path."
  (let* ((n (rt-n-leaves tree))
         (x (* 2 leaf-index)))
    (loop for p in (tm-direct-path x n)
          for c in (tm-copath x n)
          when (rt-resolution tree c)
            collect (cons p c))))

;;; ---------------------------------------------------------------------------
;;; Membership changes (§7.7, Appendix C)

(defun rt-leaf-indices (tree)
  "Indices of non-blank leaves."
  (loop for i from 0 below (rt-n-leaves tree)
        when (rt-leaf tree i) collect i))

(defun rt-extend (tree)
  "Double the number of leaves."
  (let* ((old (ratchet-tree-nodes tree))
         (v (make-array (1+ (* 2 (length old))) :initial-element nil)))
    (replace v old)
    (setf (ratchet-tree-nodes tree) v)
    tree))

(defun rt-truncate (tree)
  "Drop the right half while it is entirely blank."
  (loop while (> (rt-n-leaves tree) 1)
        do (let* ((v (ratchet-tree-nodes tree))
                  (half (/ (1- (length v)) 2)))
             (if (every #'null (subseq v (1+ half)))
                 (setf (ratchet-tree-nodes tree) (subseq v 0 half))
                 (return))))
  tree)

(defun rt-blank-path (tree leaf-index)
  "Blank the direct path of LEAF-INDEX (not the leaf)."
  (dolist (p (tm-direct-path (* 2 leaf-index) (rt-n-leaves tree)))
    (setf (rt-node tree p) nil)))

(defun rt-add-leaf (tree leaf)
  "Insert LEAF at the leftmost blank leaf (extending if needed); add it to the
unmerged list of every non-blank parent on its direct path.  Returns the leaf index."
  (let ((idx (loop for i from 0 below (rt-n-leaves tree)
                   unless (rt-leaf tree i) return i)))
    (unless idx
      (setf idx (rt-n-leaves tree))
      (rt-extend tree))
    (setf (rt-node tree (* 2 idx)) leaf)
    (dolist (p (tm-direct-path (* 2 idx) (rt-n-leaves tree)))
      (let ((node (rt-node tree p)))
        (when node
          (let ((copy (copy-parent-node node)))
            (setf (parent-node-unmerged-leaves copy)
                  (append (parent-node-unmerged-leaves node) (list idx)))
            (setf (rt-node tree p) copy)))))
    idx))

(defun rt-update-leaf (tree leaf-index leaf)
  (setf (rt-node tree (* 2 leaf-index)) leaf)
  (rt-blank-path tree leaf-index))

(defun rt-remove-leaf (tree leaf-index)
  (setf (rt-node tree (* 2 leaf-index)) nil)
  (rt-blank-path tree leaf-index))

;;; ---------------------------------------------------------------------------
;;; Tree hash (§7.8)

(defun rt-tree-hash (tree &optional (x (tm-root (rt-n-leaves tree))) cache)
  "Tree hash of node X.  CACHE, if given, is a hash table node->hash."
  (or (and cache (gethash x cache))
      (let ((h (if (evenp x)
                   (let ((leaf (rt-node tree x)))
                     (mls-hash (with-writer (w)
                                 (w-u8 w 1)
                                 (w-u32 w (/ x 2))
                                 (w-optional w leaf #'encode-leaf-node))))
                   (let ((node (rt-node tree x))
                         (lh (rt-tree-hash tree (tm-left x) cache))
                         (rh (rt-tree-hash tree (tm-right x) cache)))
                     (mls-hash (with-writer (w)
                                 (w-u8 w 2)
                                 (w-optional w node #'encode-parent-node)
                                 (w-opaque w lh)
                                 (w-opaque w rh)))))))
        (when cache (setf (gethash x cache) h))
        h)))

;;; ---------------------------------------------------------------------------
;;; Parent hash (§7.9)

(defun parent-hash-of (parent-node original-sibling-tree-hash)
  (mls-hash (with-writer (w)
              (w-opaque w (parent-node-encryption-key parent-node))
              (w-opaque w (parent-node-parent-hash parent-node))
              (w-opaque w original-sibling-tree-hash))))

(defun rt-original-sibling-tree-hash (tree p s)
  "Tree hash of S after blanking P's unmerged leaves (and removing them from
every unmerged list)."
  (let ((unmerged (parent-node-unmerged-leaves (rt-node tree p))))
    (if (notany (lambda (l) (tm-is-ancestor s (* 2 l))) unmerged)
        (rt-tree-hash tree s)
        (let ((copy (copy-rt tree)))
          (dolist (l unmerged) (setf (rt-node copy (* 2 l)) nil))
          (loop for i from 1 below (rt-size copy) by 2
                for node = (rt-node copy i)
                when node
                  do (let ((c (copy-parent-node node)))
                       (setf (parent-node-unmerged-leaves c)
                             (set-difference (parent-node-unmerged-leaves node) unmerged))
                       ;; keep original order
                       (setf (parent-node-unmerged-leaves c)
                             (remove-if (lambda (l) (member l unmerged))
                                        (parent-node-unmerged-leaves node)))
                       (setf (rt-node copy i) c)))
          (rt-tree-hash copy s)))))

(defun rt-set-path-parent-hashes (tree leaf-index)
  "After an UpdatePath has been merged (filtered direct path nodes hold their
new keys with empty unmerged lists), compute parent hashes root->leaf, store
them in each parent node, and return the parent hash the LEAF must carry."
  (let ((fdp (rt-filtered-direct-path-with-copath tree leaf-index))
        (n (rt-n-leaves tree))
        (above (make-octets 0)))
    ;; walk from the root down
    (dolist (pc (reverse fdp))
      (destructuring-bind (p . c) pc
        (declare (ignore c))
        (let* ((node (copy-parent-node (rt-node tree p))))
          (setf (parent-node-parent-hash node) above)
          (setf (rt-node tree p) node)
          ;; sibling S = the child of P NOT on the leaf's direct path
          (let* ((x (* 2 leaf-index))
                 (s (if (tm-is-ancestor (tm-left p) x) (tm-right p) (tm-left p))))
            (setf above (parent-hash-of node (rt-tree-hash tree s)))))))
    (values above n)))

(defun rt-verify-parent-hashes (tree)
  "§7.9.2 top-down: every non-blank parent P must have exactly one descendant D
whose parent_hash is valid with respect to P."
  (let ((cache (make-hash-table)))
    (loop for p from 1 below (rt-size tree) by 2
          for pnode = (rt-node tree p)
          when pnode
            do (let ((count 0))
                 (dolist (side (list (cons (tm-left p) (tm-right p))
                                     (cons (tm-right p) (tm-left p))))
                   (destructuring-bind (c . s) side
                     (let ((ph (parent-hash-of pnode (rt-original-sibling-tree-hash tree p s)))
                           (unmerged-under-c
                             (remove-if-not (lambda (l) (tm-is-ancestor c (* 2 l)))
                                            (parent-node-unmerged-leaves pnode)))
                           (res (rt-resolution tree c)))
                       (dolist (d res)
                         (let* ((dnode (rt-node tree d))
                                (dph (if (evenp d)
                                         (and (= (leaf-node-source dnode) +lns-commit+)
                                              (leaf-node-parent-hash dnode))
                                         (parent-node-parent-hash dnode))))
                           (when (and dph (octets= dph ph)
                                      ;; resolution(C) minus D == unmerged leaves under C
                                      (let ((rest (remove d res)))
                                        (and (= (length rest) (length unmerged-under-c))
                                             (every (lambda (l) (member (* 2 l) rest))
                                                    unmerged-under-c))))
                             (incf count)))))))
                 (unless (= count 1)
                   (return-from rt-verify-parent-hashes
                     (values nil (format nil "parent node ~D is not parent-hash valid (~D)" p count))))))
    (clrhash cache)
    t))
