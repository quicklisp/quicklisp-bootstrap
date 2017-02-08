;;;;
;;;; This is quicklisp.lisp, the quickstart file for Quicklisp. To use
;;;; it, start Lisp, then (load "quicklisp.lisp")
;;;;
;;;; Quicklisp is beta software and comes with no warranty of any kind.
;;;;
;;;; For more information about the Quicklisp beta, see:
;;;;
;;;;    http://www.quicklisp.org/beta/
;;;;
;;;; If you have any questions or comments about Quicklisp, please
;;;; contact:
;;;;
;;;;    Zach Beane <zach@quicklisp.org>
;;;;

#|

This is the key for <release@quicklisp.org>, key id
307965AB028B5FF7. It is used to validate subsequent downloads.

It can be imported into gpg with "gpg --import quicklisp.lisp".

-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=LUL5
-----END PGP PUBLIC KEY BLOCK-----
|#

(cl:in-package #:cl-user)
(cl:defpackage #:qlqs-user
  (:use #:cl))
(cl:in-package #:qlqs-user)

(defpackage #:qlqs-info
  (:export #:*version*))

(defvar qlqs-info:*version* "2017-02-07")

(defpackage #:qlqs-impl
  (:use #:cl)
  (:export #:*implementation*)
  (:export #:definterface
           #:defimplementation)
  (:export #:lisp
           #:abcl
           #:allegro
           #:ccl
           #:clasp
           #:clisp
           #:cmucl
           #:cormanlisp
           #:ecl
           #:gcl
           #:lispworks
	   #:mkcl
           #:scl
           #:sbcl))

(defpackage #:qlqs-impl-util
  (:use #:cl #:qlqs-impl)
  (:export #:call-with-quiet-compilation))

(defpackage #:qlqs-network
  (:use #:cl #:qlqs-impl)
  (:export #:open-connection
           #:write-octets
           #:read-octets
           #:close-connection
           #:with-connection))

(defpackage #:qlqs-progress
  (:use #:cl)
  (:export #:make-progress-bar
           #:start-display
           #:update-progress
           #:finish-display))

(defpackage #:qlqs-http
  (:use #:cl #:qlqs-network #:qlqs-progress)
  (:export #:fetch
           #:*proxy-url*
           #:*maximum-redirects*
           #:*default-url-defaults*))

(defpackage #:qlqs-minitar
  (:use #:cl)
  (:export #:unpack-tarball))

(defpackage #:qlqs-openpgp
  (:use #:cl)
  (:export #:verify-signature
           #:load-signature
           #:load-public-key
           #:file-sha-string
           #:sha256))

(defpackage #:quicklisp-quickstart
  (:use #:cl
        #:qlqs-impl #:qlqs-impl-util
        #:qlqs-http #:qlqs-minitar #:qlqs-openpgp)
  (:export #:install
           #:help
           #:*proxy-url*
           #:*asdf-url*
           #:*quicklisp-tar-url*
           #:*setup-url*
           #:*help-message*
           #:*after-load-message*
           #:*after-initial-setup-message*))


;;;
;;; Defining implementation-specific packages and functionality
;;;

(in-package #:qlqs-impl)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun error-unimplemented (&rest args)
    (declare (ignore args))
    (error "Not implemented")))

(defmacro neuter-package (name)
  `(eval-when (:compile-toplevel :load-toplevel :execute)
     (let ((definition (fdefinition 'error-unimplemented)))
       (do-external-symbols (symbol ,(string name))
         (unless (fboundp symbol)
           (setf (fdefinition symbol) definition))))))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun feature-expression-passes-p (expression)
    (cond ((keywordp expression)
           (member expression *features*))
          ((consp expression)
           (case (first expression)
             (or
              (some 'feature-expression-passes-p (rest expression)))
             (and
              (every 'feature-expression-passes-p (rest expression)))))
          (t (error "Unrecognized feature expression -- ~S" expression)))))


(defmacro define-implementation-package (feature package-name &rest options)
  (let* ((output-options '((:use)
                           (:export #:lisp)))
         (prep (cdr (assoc :prep options)))
         (class-option (cdr (assoc :class options)))
         (class (first class-option))
         (superclasses (rest class-option))
         (import-options '())
         (effectivep (feature-expression-passes-p feature)))
    (dolist (option options)
      (ecase (first option)
        ((:prep :class))
        ((:import-from
          :import)
         (push option import-options))
        ((:export
          :shadow
          :intern
          :documentation)
         (push option output-options))
        ((:reexport-from)
         (push (cons :export (cddr option)) output-options)
         (push (cons :import-from (cdr option)) import-options))))
    `(eval-when (:compile-toplevel :load-toplevel :execute)
       ,@(when effectivep
               prep)
       (defclass ,class ,superclasses ())
       (defpackage ,package-name ,@output-options
                   ,@(when effectivep
                           import-options))
       ,@(when effectivep
               `((setf *implementation* (make-instance ',class))))
       ,@(unless effectivep
                 `((neuter-package ,package-name))))))

(defmacro definterface (name lambda-list &body options)
  (let* ((forbidden (intersection lambda-list lambda-list-keywords))
         (gf-options (remove :implementation options :key #'first))
         (implementations (set-difference options gf-options)))
    (when forbidden
      (error "~S not allowed in definterface lambda list" forbidden))
    (flet ((method-option (class body)
             `(:method ((*implementation* ,class) ,@lambda-list)
                ,@body)))
      (let ((generic-name (intern (format nil "%~A" name))))
        `(eval-when (:compile-toplevel :load-toplevel :execute)
           (defgeneric ,generic-name (lisp ,@lambda-list)
             ,@gf-options
             ,@(mapcar (lambda (implementation)
                         (destructuring-bind (class &rest body)
                             (rest implementation)
                           (method-option class body)))
                       implementations))
           (defun ,name ,lambda-list
             (,generic-name *implementation* ,@lambda-list)))))))

(defmacro defimplementation (name-and-options
                             lambda-list &body body)
  (destructuring-bind (name &key (for t) qualifier)
      (if (consp name-and-options)
          name-and-options
          (list name-and-options))
    (unless for
      (error "You must specify an implementation name."))
    (let ((generic-name (find-symbol (format nil "%~A" name))))
      (unless (and generic-name
                   (fboundp generic-name))
        (error "~S does not name an implementation function" name))
      `(defmethod ,generic-name
           ,@(when qualifier (list qualifier))
         ,(list* `(*implementation* ,for) lambda-list) ,@body))))


;;; Bootstrap implementations

(defvar *implementation* nil)
(defclass lisp () ())


;;; Allegro Common Lisp

(define-implementation-package :allegro #:qlqs-allegro
  (:documentation
   "Allegro Common Lisp - http://www.franz.com/products/allegrocl/")
  (:class allegro)
  (:reexport-from #:socket
                  #:make-socket)
  (:reexport-from #:excl
                  #:read-vector))


;;; Armed Bear Common Lisp

(define-implementation-package :abcl #:qlqs-abcl
  (:documentation
   "Armed Bear Common Lisp - http://common-lisp.net/project/armedbear/")
  (:class abcl)
  (:reexport-from #:system
                  #:make-socket
                  #:get-socket-stream))

;;; Clozure CL

(define-implementation-package :ccl #:qlqs-ccl
  (:documentation
   "Clozure Common Lisp - http://www.clozure.com/clozurecl.html")
  (:class ccl)
  (:reexport-from #:ccl
                  #:make-socket))


;;; CLASP

(define-implementation-package :clasp #:qlqs-clasp
  (:documentation "CLASP - http://github.com/drmeister/clasp")
  (:class clasp)
  (:prep
   (require 'sockets))
  (:intern #:host-network-address)
  (:reexport-from #:sb-bsd-sockets
                  #:get-host-by-name
                  #:host-ent-address
                  #:socket-connect
                  #:socket-make-stream
                  #:inet-socket))


;;; GNU CLISP

(define-implementation-package :clisp #:qlqs-clisp
  (:documentation "GNU CLISP - http://clisp.cons.org/")
  (:class clisp)
  (:reexport-from #:socket
                  #:socket-connect)
  (:reexport-from #:ext
                  #:read-byte-sequence))


;;; CMUCL

(define-implementation-package :cmu #:qlqs-cmucl
  (:documentation "CMU Common Lisp - http://www.cons.org/cmucl/")
  (:class cmucl)
  (:reexport-from #:ext
                  #:*gc-verbose*)
  (:reexport-from #:system
                  #:make-fd-stream)
  (:reexport-from #:extensions
                  #:connect-to-inet-socket))

(defvar qlqs-cmucl:*gc-verbose* nil)


;;; Scieneer CL

(define-implementation-package :scl #:qlqs-scl
  (:documentation "Scieneer Common Lisp - http://www.scieneer.com/scl/")
  (:class scl)
  (:reexport-from #:system
                  #:make-fd-stream)
  (:reexport-from #:extensions
                  #:connect-to-inet-socket))

;;; ECL

(define-implementation-package :ecl #:qlqs-ecl
  (:documentation "ECL - http://ecls.sourceforge.net/")
  (:class ecl)
  (:prep
   (require 'sockets))
  (:intern #:host-network-address)
  (:reexport-from #:sb-bsd-sockets
                  #:get-host-by-name
                  #:host-ent-address
                  #:socket-connect
                  #:socket-make-stream
                  #:inet-socket))


;;; LispWorks

(define-implementation-package :lispworks #:qlqs-lispworks
  (:documentation "LispWorks - http://www.lispworks.com/")
  (:class lispworks)
  (:prep
   (require "comm"))
  (:reexport-from #:comm
                  #:open-tcp-stream
                  #:get-host-entry))


;;; SBCL

(define-implementation-package :sbcl #:qlqs-sbcl
  (:class sbcl)
  (:documentation
   "Steel Bank Common Lisp - http://www.sbcl.org/")
  (:prep
   (require 'sb-bsd-sockets))
  (:intern #:host-network-address)
  (:reexport-from #:sb-ext
                  #:compiler-note)
  (:reexport-from #:sb-bsd-sockets
                  #:get-host-by-name
                  #:inet-socket
                  #:host-ent-address
                  #:socket-connect
                  #:socket-make-stream))

;;; MKCL

(define-implementation-package :mkcl #:qlqs-mkcl
  (:class mkcl)
  (:documentation
   "ManKai Common Lisp - http://common-lisp.net/project/mkcl/")
  (:prep
   (require 'sockets))
  (:intern #:host-network-address)
  (:reexport-from #:sb-bsd-sockets
                  #:get-host-by-name
                  #:inet-socket
                  #:host-ent-address
                  #:socket-connect
                  #:socket-make-stream))

;;;
;;; Utility function
;;;

(in-package #:qlqs-impl-util)

(definterface call-with-quiet-compilation (fun)
  (:implementation t
    (let ((*load-verbose* nil)
          (*compile-verbose* nil)
          (*load-print* nil)
          (*compile-print* nil))
      (handler-bind ((warning #'muffle-warning))
        (funcall fun)))))

(defimplementation (call-with-quiet-compilation :for sbcl :qualifier :around)
    (fun)
  (declare (ignorable fun))
  (handler-bind ((qlqs-sbcl:compiler-note #'muffle-warning))
    (call-next-method)))

(defimplementation (call-with-quiet-compilation :for cmucl :qualifier :around)
    (fun)
  (declare (ignorable fun))
  (let ((qlqs-cmucl:*gc-verbose* nil))
    (call-next-method)))


;;;
;;; Low-level networking implementations
;;;

(in-package #:qlqs-network)

(definterface host-address (host)
  (:implementation t
    host)
  (:implementation mkcl
    (qlqs-mkcl:host-ent-address (qlqs-mkcl:get-host-by-name host)))
  (:implementation sbcl
    (qlqs-sbcl:host-ent-address (qlqs-sbcl:get-host-by-name host))))

(definterface open-connection (host port)
  (:implementation t
    (declare (ignorable host port))
    (error "Sorry, quicklisp in implementation ~S is not supported yet."
           (lisp-implementation-type)))
  (:implementation allegro
    (qlqs-allegro:make-socket :remote-host host
                             :remote-port port))
  (:implementation abcl
    (let ((socket (qlqs-abcl:make-socket host port)))
      (qlqs-abcl:get-socket-stream socket :element-type '(unsigned-byte 8))))
  (:implementation ccl
    (qlqs-ccl:make-socket :remote-host host
                         :remote-port port))
  (:implementation clasp
    (let* ((endpoint (qlqs-clasp:host-ent-address
                      (qlqs-clasp:get-host-by-name host)))
           (socket (make-instance 'qlqs-clasp:inet-socket
                                  :protocol :tcp
                                  :type :stream)))
      (qlqs-clasp:socket-connect socket endpoint port)
      (qlqs-clasp:socket-make-stream socket
                                  :element-type '(unsigned-byte 8)
                                  :input t
                                  :output t
                                  :buffering :full)))
  (:implementation clisp
    (qlqs-clisp:socket-connect port host :element-type '(unsigned-byte 8)))
  (:implementation cmucl
    (let ((fd (qlqs-cmucl:connect-to-inet-socket host port)))
      (qlqs-cmucl:make-fd-stream fd
                                :element-type '(unsigned-byte 8)
                                :binary-stream-p t
                                :input t
                                :output t)))
  (:implementation scl
    (let ((fd (qlqs-scl:connect-to-inet-socket host port)))
      (qlqs-scl:make-fd-stream fd
			       :element-type '(unsigned-byte 8)
			       :input t
			       :output t)))
  (:implementation ecl
    (let* ((endpoint (qlqs-ecl:host-ent-address
                      (qlqs-ecl:get-host-by-name host)))
           (socket (make-instance 'qlqs-ecl:inet-socket
                                  :protocol :tcp
                                  :type :stream)))
      (qlqs-ecl:socket-connect socket endpoint port)
      (qlqs-ecl:socket-make-stream socket
                                  :element-type '(unsigned-byte 8)
                                  :input t
                                  :output t
                                  :buffering :full)))
  (:implementation lispworks
    (qlqs-lispworks:open-tcp-stream host port
                                   :direction :io
                                   :errorp t
                                   :read-timeout nil
                                   :element-type '(unsigned-byte 8)
                                   :timeout 5))
  (:implementation mkcl
    (let* ((endpoint (qlqs-mkcl:host-ent-address
                      (qlqs-mkcl:get-host-by-name host)))
           (socket (make-instance 'qlqs-mkcl:inet-socket
                                  :protocol :tcp
                                  :type :stream)))
      (qlqs-mkcl:socket-connect socket endpoint port)
      (qlqs-mkcl:socket-make-stream socket
                                   :element-type '(unsigned-byte 8)
                                   :input t
                                   :output t
                                   :buffering :full)))
  (:implementation sbcl
    (let* ((endpoint (qlqs-sbcl:host-ent-address
                      (qlqs-sbcl:get-host-by-name host)))
           (socket (make-instance 'qlqs-sbcl:inet-socket
                                  :protocol :tcp
                                  :type :stream)))
      (qlqs-sbcl:socket-connect socket endpoint port)
      (qlqs-sbcl:socket-make-stream socket
                                   :element-type '(unsigned-byte 8)
                                   :input t
                                   :output t
                                   :buffering :full))))

(definterface read-octets (buffer connection)
  (:implementation t
    (read-sequence buffer connection))
  (:implementation allegro
    (qlqs-allegro:read-vector buffer connection))
  (:implementation clisp
    (qlqs-clisp:read-byte-sequence buffer connection
                                  :no-hang nil
                                  :interactive t)))

(definterface write-octets (buffer connection)
  (:implementation t
    (write-sequence buffer connection)
    (finish-output connection)))

(definterface close-connection (connection)
  (:implementation t
    (ignore-errors (close connection))))

(definterface call-with-connection (host port fun)
  (:implementation t
    (let (connection)
      (unwind-protect
           (progn
             (setf connection (open-connection host port))
             (funcall fun connection))
        (when connection
          (close connection))))))

(defmacro with-connection ((connection host port) &body body)
  `(call-with-connection ,host ,port (lambda (,connection) ,@body)))


;;;
;;; A text progress bar
;;;

(in-package #:qlqs-progress)

(defclass progress-bar ()
  ((start-time
    :initarg :start-time
    :accessor start-time)
   (end-time
    :initarg :end-time
    :accessor end-time)
   (progress-character
    :initarg :progress-character
    :accessor progress-character)
   (character-count
    :initarg :character-count
    :accessor character-count
    :documentation "How many characters wide is the progress bar?")
   (characters-so-far
    :initarg :characters-so-far
    :accessor characters-so-far)
   (update-interval
    :initarg :update-interval
    :accessor update-interval
    :documentation "Update the progress bar display after this many
    internal-time units.")
   (last-update-time
    :initarg :last-update-time
    :accessor last-update-time
    :documentation "The display was last updated at this time.")
   (total
    :initarg :total
    :accessor total
    :documentation "The total number of units tracked by this progress bar.")
   (progress
    :initarg :progress
    :accessor progress
    :documentation "How far in the progress are we?")
   (pending
    :initarg :pending
    :accessor pending
    :documentation "How many raw units should be tracked in the next
    display update?"))
  (:default-initargs
   :progress-character #\=
   :character-count 50
   :characters-so-far 0
   :update-interval (floor internal-time-units-per-second 4)
   :last-update-time 0
   :total 0
   :progress 0
   :pending 0))

(defgeneric start-display (progress-bar))
(defgeneric update-progress (progress-bar unit-count))
(defgeneric update-display (progress-bar))
(defgeneric finish-display (progress-bar))
(defgeneric elapsed-time (progress-bar))
(defgeneric units-per-second (progress-bar))

(defmethod start-display (progress-bar)
  (setf (last-update-time progress-bar) (get-internal-real-time))
  (setf (start-time progress-bar) (get-internal-real-time))
  (fresh-line)
  (finish-output))

(defmethod update-display (progress-bar)
  (incf (progress progress-bar) (pending progress-bar))
  (setf (pending progress-bar) 0)
  (setf (last-update-time progress-bar) (get-internal-real-time))
  (let* ((showable (floor (character-count progress-bar)
                          (/ (total progress-bar) (progress progress-bar))))
         (needed (- showable (characters-so-far progress-bar))))
    (setf (characters-so-far progress-bar) showable)
    (dotimes (i needed)
      (write-char (progress-character progress-bar)))
    (finish-output)))

(defmethod update-progress (progress-bar unit-count)
  (incf (pending progress-bar) unit-count)
  (let ((now (get-internal-real-time)))
    (when (< (update-interval progress-bar)
             (- now (last-update-time progress-bar)))
      (update-display progress-bar))))

(defmethod finish-display (progress-bar)
  (update-display progress-bar)
  (setf (end-time progress-bar) (get-internal-real-time))
  (terpri)
  (format t "~:D bytes in ~$ seconds (~$KB/sec)"
          (total progress-bar)
          (elapsed-time progress-bar)
          (/  (units-per-second progress-bar) 1024))
  (finish-output))

(defmethod elapsed-time (progress-bar)
  (/ (- (end-time progress-bar) (start-time progress-bar))
     internal-time-units-per-second))

(defmethod units-per-second (progress-bar)
  (if (plusp (elapsed-time progress-bar))
      (/ (total progress-bar) (elapsed-time progress-bar))
      0))

(defun kb/sec (progress-bar)
  (/ (units-per-second progress-bar) 1024))



(defparameter *uncertain-progress-chars* "?")

(defclass uncertain-size-progress-bar (progress-bar)
  ((progress-char-index
    :initarg :progress-char-index
    :accessor progress-char-index)
   (units-per-char
    :initarg :units-per-char
    :accessor units-per-char))
  (:default-initargs
   :total 0
   :progress-char-index 0
   :units-per-char (floor (expt 1024 2) 50)))

(defmethod update-progress :after ((progress-bar uncertain-size-progress-bar)
                            unit-count)
  (incf (total progress-bar) unit-count))

(defmethod progress-character ((progress-bar uncertain-size-progress-bar))
  (let ((index (progress-char-index progress-bar)))
    (prog1
        (char *uncertain-progress-chars* index)
      (setf (progress-char-index progress-bar)
            (mod (1+ index) (length *uncertain-progress-chars*))))))

(defmethod update-display ((progress-bar uncertain-size-progress-bar))
  (setf (last-update-time progress-bar) (get-internal-real-time))
  (multiple-value-bind (chars pend)
      (floor (pending progress-bar) (units-per-char progress-bar))
    (setf (pending progress-bar) pend)
    (dotimes (i chars)
      (write-char (progress-character progress-bar))
      (incf (characters-so-far progress-bar))
      (when (<= (character-count progress-bar)
                (characters-so-far progress-bar))
        (terpri)
        (setf (characters-so-far progress-bar) 0)
        (finish-output)))
    (finish-output)))

(defun make-progress-bar (total)
  (if (or (not total) (zerop total))
      (make-instance 'uncertain-size-progress-bar)
      (make-instance 'progress-bar :total total)))

;;;
;;; A simple HTTP client
;;;

(in-package #:qlqs-http)

;;; Octet data

(deftype octet ()
  '(unsigned-byte 8))

(defun make-octet-vector (size)
  (make-array size :element-type 'octet
              :initial-element 0))

(defun octet-vector (&rest octets)
  (make-array (length octets) :element-type 'octet
              :initial-contents octets))

;;; ASCII characters as integers

(defun acode (char)
  (cond ((eql char :cr)
         13)
        ((eql char :lf)
         10)
        (t
         (let ((code (char-code char)))
           (if (<= 0 code 127)
               code
               (error "Character ~S is not in the ASCII character set"
                      char))))))

(defvar *whitespace*
  (list (acode #\Space) (acode #\Tab) (acode :cr) (acode :lf)))

(defun whitep (code)
  (member code *whitespace*))

(defun ascii-vector (string)
  (let ((vector (make-octet-vector (length string))))
    (loop for char across string
          for code = (char-code char)
          for i from 0
          if (< 127 code) do
          (error "Invalid character for ASCII -- ~A" char)
          else
          do (setf (aref vector i) code))
    vector))

(defun ascii-subseq (vector start end)
  "Return a subseq of octet-specialized VECTOR as a string."
  (let ((string (make-string (- end start))))
    (loop for i from 0
          for j from start below end
          do (setf (char string i) (code-char (aref vector j))))
    string))

(defun ascii-downcase (code)
  (if (<= 65 code 90)
      (+ code 32)
      code))

(defun ascii-equal (a b)
  (eql (ascii-downcase a) (ascii-downcase b)))

(defmacro acase (value &body cases)
  (flet ((convert-case-keys (keys)
           (mapcar (lambda (key)
                     (etypecase key
                       (integer key)
                       (character (char-code key))
                       (symbol
                        (ecase key
                          (:cr 13)
                          (:lf 10)
                          ((t) t)))))
                   (if (consp keys) keys (list keys)))))
    `(case ,value
       ,@(mapcar (lambda (case)
                   (destructuring-bind (keys &rest body)
                       case
                     `(,(if (eql keys t)
                            t
                            (convert-case-keys keys))
                        ,@body)))
                 cases))))

;;; Pattern matching (for finding headers)

(defclass matcher ()
  ((pattern
    :initarg :pattern
    :reader pattern)
   (pos
    :initform 0
    :accessor match-pos)
   (matchedp
    :initform nil
    :accessor matchedp)))

(defun reset-match (matcher)
  (setf (match-pos matcher) 0
        (matchedp matcher) nil))

(define-condition match-failure (error) ())

(defun match (matcher input &key (start 0) end error)
  (let ((i start)
        (end (or end (length input)))
        (match-end (length (pattern matcher))))
    (with-slots (pattern pos)
        matcher
      (loop
       (cond ((= pos match-end)
              (let ((match-start (- i pos)))
                (setf pos 0)
                (setf (matchedp matcher) t)
                (return (values match-start (+ match-start match-end)))))
             ((= i end)
              (return nil))
             ((= (aref pattern pos)
                 (aref input i))
              (incf i)
              (incf pos))
             (t
              (if error
                  (error 'match-failure)
                  (if (zerop pos)
                      (incf i)
                      (setf pos 0)))))))))

(defun ascii-matcher (string)
  (make-instance 'matcher
                 :pattern (ascii-vector string)))

(defun octet-matcher (&rest octets)
  (make-instance 'matcher
                 :pattern (apply 'octet-vector octets)))

(defun acode-matcher (&rest codes)
  (make-instance 'matcher
                 :pattern (make-array (length codes)
                                      :element-type 'octet
                                      :initial-contents
                                      (mapcar 'acode codes))))


;;; "Connection Buffers" are a kind of callback-driven,
;;; pattern-matching chunky stream. Callbacks can be called for a
;;; certain number of octets or until one or more patterns are seen in
;;; the input. cbufs automatically refill themselves from a
;;; connection as needed.

(defvar *cbuf-buffer-size* 8192)

(define-condition end-of-data (error) ())

(defclass cbuf ()
  ((data
    :initarg :data
    :accessor data)
   (connection
    :initarg :connection
    :accessor connection)
   (start
    :initarg :start
    :accessor start)
   (end
    :initarg :end
    :accessor end)
   (eofp
    :initarg :eofp
    :accessor eofp))
  (:default-initargs
   :data (make-octet-vector *cbuf-buffer-size*)
   :connection nil
   :start 0
   :end 0
   :eofp nil)
  (:documentation "A CBUF is a connection buffer that keeps track of
  incoming data from a connection. Several functions make it easy to
  treat a CBUF as a kind of chunky, callback-driven stream."))

(define-condition cbuf-progress ()
  ((size
    :initarg :size
    :accessor cbuf-progress-size
    :initform 0)))

(defun call-processor (fun cbuf start end)
  (signal 'cbuf-progress :size (- end start))
  (funcall fun (data cbuf) start end))

(defun make-cbuf (connection)
  (make-instance 'cbuf :connection connection))

(defun make-stream-writer (stream)
  "Create a callback for writing data to STREAM."
  (lambda (data start end)
    (write-sequence data stream :start start :end end)))

(defgeneric size (cbuf)
  (:method ((cbuf cbuf))
    (- (end cbuf) (start cbuf))))

(defgeneric emptyp (cbuf)
  (:method ((cbuf cbuf))
    (zerop (size cbuf))))

(defgeneric refill (cbuf)
  (:method ((cbuf cbuf))
    (when (eofp cbuf)
      (error 'end-of-data))
    (setf (start cbuf) 0)
    (setf (end cbuf)
          (read-octets (data cbuf)
                       (connection cbuf)))
    (cond ((emptyp cbuf)
           (setf (eofp cbuf) t)
           (error 'end-of-data))
          (t (size cbuf)))))

(defun process-all (fun cbuf)
  (unless (emptyp cbuf)
    (call-processor fun cbuf (start cbuf) (end cbuf))))

(defun multi-cmatch (matchers cbuf)
  (let (start end)
    (dolist (matcher matchers (values start end))
      (multiple-value-bind (s e)
          (match matcher (data cbuf)
                 :start (start cbuf)
                 :end (end cbuf))
        (when (and s (or (null start) (< s start)))
          (setf start s
                end e))))))

(defun cmatch (matcher cbuf)
  (if (consp matcher)
      (multi-cmatch matcher cbuf)
      (match matcher (data cbuf) :start (start cbuf) :end (end cbuf))))

(defun call-until-end (fun cbuf)
  (handler-case
      (loop
       (process-all fun cbuf)
       (refill cbuf))
    (end-of-data ()
      (return-from call-until-end))))

(defun show-cbuf (context cbuf)
  (format t "cbuf: ~A ~D - ~D~%" context (start cbuf) (end cbuf)))

(defun call-for-n-octets (n fun cbuf)
  (let ((remaining n))
    (loop
     (when (<= remaining (size cbuf))
       (let ((end (+ (start cbuf) remaining)))
         (call-processor fun cbuf (start cbuf) end)
         (setf (start cbuf) end)
         (return)))
     (process-all fun cbuf)
     (decf remaining (size cbuf))
     (refill cbuf))))

(defun call-until-matching (matcher fun cbuf)
  (loop
   (multiple-value-bind (start end)
       (cmatch matcher cbuf)
     (when start
       (call-processor fun cbuf (start cbuf) end)
       (setf (start cbuf) end)
       (return)))
   (process-all fun cbuf)
   (refill cbuf)))

(defun ignore-data (data start end)
  (declare (ignore data start end)))

(defun skip-until-matching (matcher cbuf)
  (call-until-matching matcher 'ignore-data cbuf))


;;; Creating HTTP requests as octet buffers

(defclass octet-sink ()
  ((storage
    :initarg :storage
    :accessor storage))
  (:default-initargs
   :storage (make-array 1024 :element-type 'octet
                        :fill-pointer 0
                        :adjustable t))
  (:documentation "A simple stream-like target for collecting
  octets."))

(defun add-octet (octet sink)
  (vector-push-extend octet (storage sink)))

(defun add-octets (octets sink &key (start 0) end)
  (setf end (or end (length octets)))
  (loop for i from start below end
        do (add-octet (aref octets i) sink)))

(defun add-string (string sink)
  (loop for char across string
        for code = (char-code char)
        do (add-octet code sink)))

(defun add-strings (sink &rest strings)
  (mapc (lambda (string) (add-string string sink)) strings))

(defun add-newline (sink)
  (add-octet 13 sink)
  (add-octet 10 sink))

(defun sink-buffer (sink)
  (subseq (storage sink) 0))

(defvar *proxy-url* nil)

(defun full-proxy-path (host port path)
  (format nil "~:[http~;https~]://~A~:[:~D~;~*~]~A"
                       (= port 443)
                       host
                       (or (= port 80)
                           (= port 443))
                       port
                       path))

(defun make-request-buffer (host port path &key (method "GET"))
  (setf method (string method))
  (when *proxy-url*
    (setf path (full-proxy-path host port path)))
  (let ((sink (make-instance 'octet-sink)))
    (flet ((add-line (&rest strings)
             (apply #'add-strings sink strings)
             (add-newline sink)))
      (add-line method " " path " HTTP/1.1")
      (add-line "Host: " host (if (= port 80) ""
                                  (format nil ":~D" port)))
      (add-line "Connection: close")
      ;; FIXME: get this version string from somewhere else.
      (add-line "User-Agent: quicklisp-bootstrap/"
                qlqs-info:*version*)
      (add-newline sink)
      (sink-buffer sink))))

(defun sink-until-matching (matcher cbuf)
  (let ((sink (make-instance 'octet-sink)))
    (call-until-matching
     matcher
     (lambda (buffer start end)
       (add-octets buffer sink :start start :end end))
     cbuf)
    (sink-buffer sink)))


;;; HTTP headers

(defclass header ()
  ((data
    :initarg :data
    :accessor data)
   (status
    :initarg :status
    :accessor status)
   (name-starts
    :initarg :name-starts
    :accessor name-starts)
   (name-ends
    :initarg :name-ends
    :accessor name-ends)
   (value-starts
    :initarg :value-starts
    :accessor value-starts)
   (value-ends
    :initarg :value-ends
    :accessor value-ends)))

(defmethod print-object ((header header) stream)
  (print-unreadable-object (header stream :type t)
    (prin1 (status header) stream)))

(defun matches-at (pattern target pos)
  (= (mismatch pattern target :start2 pos) (length pattern)))

(defun header-value-indexes (field-name header)
  (loop with data = (data header)
        with pattern = (ascii-vector (string-downcase field-name))
        for start across (name-starts header)
        for i from 0
        when (matches-at pattern data start)
        return (values (aref (value-starts header) i)
                       (aref (value-ends header) i))))

(defun ascii-header-value (field-name header)
  (multiple-value-bind (start end)
      (header-value-indexes field-name header)
    (when start
      (ascii-subseq (data header) start end))))

(defun all-field-names (header)
  (map 'list
       (lambda (start end)
         (ascii-subseq (data header) start end))
       (name-starts header)
       (name-ends header)))

(defun headers-alist (header)
  (mapcar (lambda (name)
            (cons name (ascii-header-value name header)))
          (all-field-names header)))

(defmethod describe-object :after ((header header) stream)
  (format stream "~&Decoded headers:~%  ~S~%" (headers-alist header)))

(defun content-length (header)
  (let ((field-value (ascii-header-value "content-length" header)))
    (when field-value
      (let ((value (ignore-errors (parse-integer field-value))))
        (or value
            (error "Content-Length header field value is not a number -- ~A"
                   field-value))))))

(defun chunkedp (header)
  (string= (ascii-header-value "transfer-encoding" header) "chunked"))

(defun location (header)
  (ascii-header-value "location" header))

(defun status-code (vector)
  (let* ((space (position (acode #\Space) vector))
         (c1 (- (aref vector (incf space)) 48))
         (c2 (- (aref vector (incf space)) 48))
         (c3 (- (aref vector (incf space)) 48)))
    (+ (* c1 100)
       (* c2  10)
       (* c3   1))))

(defun force-downcase-field-names (header)
  (loop with data = (data header)
        for start across (name-starts header)
        for end across (name-ends header)
        do (loop for i from start below end
                 for code = (aref data i)
                 do (setf (aref data i) (ascii-downcase code)))))

(defun skip-white-forward (pos vector)
  (position-if-not 'whitep vector :start pos))

(defun skip-white-backward (pos vector)
  (let ((nonwhite (position-if-not 'whitep vector :end pos :from-end t)))
    (if nonwhite
        (1+ nonwhite)
        pos)))

(defun contract-field-value-indexes (header)
  "Header field values exclude leading and trailing whitespace; adjust
the indexes in the header accordingly."
  (loop with starts = (value-starts header)
        with ends = (value-ends header)
        with data = (data header)
        for i from 0
        for start across starts
        for end across ends
        do
        (setf (aref starts i) (skip-white-forward start data))
        (setf (aref ends i) (skip-white-backward end data))))

(defun next-line-pos (vector)
  (let ((pos 0))
    (labels ((finish (&optional (i pos))
               (return-from next-line-pos i))
             (after-cr (code)
               (acase code
                 (:lf (finish pos))
                 (t (finish (1- pos)))))
             (pending (code)
               (acase code
                 (:cr #'after-cr)
                 (:lf (finish pos))
                 (t #'pending))))
      (let ((state #'pending))
        (loop
         (setf state (funcall state (aref vector pos)))
         (incf pos))))))

(defun make-hvector ()
  (make-array 16 :fill-pointer 0 :adjustable t))

(defun process-header (vector)
  "Create a HEADER instance from the octet data in VECTOR."
  (let* ((name-starts (make-hvector))
         (name-ends (make-hvector))
         (value-starts (make-hvector))
         (value-ends (make-hvector))
         (header (make-instance 'header
                                :data vector
                                :status 999
                                :name-starts name-starts
                                :name-ends name-ends
                                :value-starts value-starts
                                :value-ends value-ends))
         (mark nil)
         (pos (next-line-pos vector)))
    (unless pos
      (error "Unable to process HTTP header"))
    (setf (status header) (status-code vector))
    (labels ((save (value vector)
               (vector-push-extend value vector))
             (mark ()
               (setf mark pos))
             (clear-mark ()
               (setf mark nil))
             (finish ()
               (if mark
                   (save mark value-ends)
                   (save pos value-ends))
              (force-downcase-field-names header)
              (contract-field-value-indexes header)
              (return-from process-header header))
             (in-new-line (code)
               (acase code
                 ((#\Tab #\Space) (setf mark nil) #'in-value)
                 (t
                  (when mark
                    (save mark value-ends))
                  (clear-mark)
                  (save pos name-starts)
                  (in-name code))))
             (after-cr (code)
               (acase code
                 (:lf #'in-new-line)
                 (t (in-new-line code))))
             (pending-value (code)
               (acase code
                 ((#\Tab #\Space) #'pending-value)
                 (:cr #'after-cr)
                 (:lf #'in-new-line)
                 (t (save pos value-starts) #'in-value)))
             (in-name (code)
               (acase code
                 (#\:
                  (save pos name-ends)
                  (save (1+ pos) value-starts)
                  #'in-value)
                 ((:cr :lf)
                  (finish))
                 ((#\Tab #\Space)
                  (error "Unexpected whitespace in header field name"))
                 (t
                  (unless (<= 0 code 127)
                    (error "Unexpected non-ASCII header field name"))
                  #'in-name)))
             (in-value (code)
               (acase code
                 (:lf (mark) #'in-new-line)
                 (:cr (mark) #'after-cr)
                 (t #'in-value))))
      (let ((state #'in-new-line))
        (loop
         (incf pos)
         (when (<= (length vector) pos)
           (error "No header found in response"))
         (setf state (funcall state (aref vector pos))))))))


;;; HTTP URL parsing

(defclass url ()
  ((hostname
    :initarg :hostname
    :accessor hostname
    :initform nil)
   (port
    :initarg :port
    :accessor port
    :initform 80)
   (path
    :initarg :path
    :accessor path
    :initform "/")))

(defun parse-urlstring (urlstring)
  (setf urlstring (string-trim " " urlstring))
  (let* ((pos (mismatch urlstring "http://" :test 'char-equal))
         (mark pos)
         (url (make-instance 'url)))
    (labels ((save ()
               (subseq urlstring mark pos))
             (mark ()
               (setf mark pos))
             (finish ()
               (return-from parse-urlstring url))
             (hostname-char-p (char)
               (position char "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
                         :test 'char-equal))
             (at-start (char)
               (case char
                 (#\/
                  (setf (port url) nil)
                  (mark)
                  #'in-path)
                 (t
                  #'in-host)))
             (in-host (char)
               (case char
                 ((#\/ :end)
                  (setf (hostname url) (save))
                  (mark)
                  #'in-path)
                 (#\:
                  (setf (hostname url) (save))
                  (mark)
                  #'in-port)
                 (t
                  (unless (hostname-char-p char)
                    (error "~S is not a valid URL" urlstring))
                  #'in-host)))
             (in-port (char)
               (case char
                 ((#\/ :end)
                  (setf (port url)
                        (parse-integer urlstring
                                       :start (1+ mark)
                                       :end pos))
                  (mark)
                  #'in-path)
                 (t
                  (unless (digit-char-p char)
                    (error "Bad port in URL ~S" urlstring))
                  #'in-port)))
             (in-path (char)
               (case char
                 ((#\# :end)
                  (setf (path url) (save))
                  (finish)))
               #'in-path))
      (let ((state #'at-start))
        (loop
         (when (<= (length urlstring) pos)
           (funcall state :end)
           (finish))
         (setf state (funcall state (aref urlstring pos)))
         (incf pos))))))

(defun url (thing)
  (if (stringp thing)
      (parse-urlstring thing)
      thing))

(defgeneric request-buffer (method url)
  (:method (method url)
    (setf url (url url))
    (make-request-buffer (hostname url) (port url) (path url)
                         :method method)))

(defun urlstring (url)
  (format nil "~@[http://~A~]~@[:~D~]~A"
          (hostname url)
          (and (/= 80 (port url)) (port url))
          (path url)))

(defmethod print-object ((url url) stream)
  (print-unreadable-object (url stream :type t)
    (prin1 (urlstring url) stream)))

(defun merge-urls (url1 url2)
  (setf url1 (url url1))
  (setf url2 (url url2))
  (make-instance 'url
                 :hostname (or (hostname url1)
                               (hostname url2))
                 :port (or (port url1)
                           (port url2))
                 :path (or (path url1)
                           (path url2))))


;;; Requesting an URL and saving it to a file

(defparameter *maximum-redirects* 10)
(defvar *default-url-defaults* (url "http://src.quicklisp.org/"))

(defun read-http-header (cbuf)
  (let ((header-data (sink-until-matching (list (acode-matcher :lf :lf)
                                                (acode-matcher :cr :cr)
                                                (acode-matcher :cr :lf :cr :lf))
                                 cbuf)))
    (process-header header-data)))

(defun read-chunk-header (cbuf)
  (let* ((header-data (sink-until-matching (acode-matcher :cr :lf) cbuf))
         (end (or (position (acode :cr) header-data)
                  (position (acode #\;) header-data))))
    (values (parse-integer (ascii-subseq header-data 0 end) :radix 16))))

(defun save-chunk-response (stream cbuf)
  "For a chunked response, read all chunks and write them to STREAM."
  (let ((fun (make-stream-writer stream))
        (matcher (acode-matcher :cr :lf)))
    (loop
     (let ((chunk-size (read-chunk-header cbuf)))
       (when (zerop chunk-size)
         (return))
       (call-for-n-octets chunk-size fun cbuf)
       (skip-until-matching matcher cbuf)))))

(defun save-response (file header cbuf)
  (with-open-file (stream file
                          :direction :output
                          :if-exists :supersede
                          :element-type 'octet)
    (let ((content-length (content-length header)))
      (cond ((chunkedp header)
             (save-chunk-response stream cbuf))
            (content-length
             (call-for-n-octets content-length
                                (make-stream-writer stream)
                                cbuf))
            (t
             (call-until-end (make-stream-writer stream) cbuf))))))

(defun call-with-progress-bar (size fun)
  (let ((progress-bar (make-progress-bar size)))
    (start-display progress-bar)
    (flet ((update (condition)
             (update-progress progress-bar
                              (cbuf-progress-size condition))))
      (handler-bind ((cbuf-progress #'update))
        (funcall fun)))
    (finish-display progress-bar)))

(defun fetch (url file &key (follow-redirects t) quietly
              (maximum-redirects *maximum-redirects*))
  "Request URL and write the body of the response to FILE."
  (setf url (merge-urls url *default-url-defaults*))
  (setf file (merge-pathnames file))
  (let ((redirect-count 0)
        (original-url url)
        (connect-url (or (url *proxy-url*) url))
        (stream (if quietly
                    (make-broadcast-stream)
                    *trace-output*)))
    (loop
     (when (<= maximum-redirects redirect-count)
       (error "Too many redirects for ~A" original-url))
     (with-connection (connection (hostname connect-url) (port connect-url))
       (let ((cbuf (make-instance 'cbuf :connection connection))
             (request (request-buffer "GET" url)))
         (write-octets request connection)
         (let ((header (read-http-header cbuf)))
           (loop while (= (status header) 100)
                 do (setf header (read-http-header cbuf)))
           (cond ((= (status header) 200)
                  (let ((size (content-length header)))
                    (format stream "~&; Fetching ~A~%" url)
                    (if (and (numberp size)
                             (plusp size))
                        (format stream "; ~$KB~%" (/ size 1024))
                        (format stream "; Unknown size~%"))
                    (if quietly
                        (save-response file header cbuf)
                        (call-with-progress-bar (content-length header)
                                                (lambda ()
                                                  (save-response file header cbuf))))))
                 ((not (<= 300 (status header) 399))
                  (error "Unexpected status for ~A: ~A"
                         url (status header))))
           (if (and follow-redirects (<= 300 (status header) 399))
               (let ((new-urlstring (ascii-header-value "location" header)))
                 (when (not new-urlstring)
                   (error "Redirect code ~D received, but no Location: header"
                          (status header)))
                 (incf redirect-count)
                 (setf url (merge-urls new-urlstring
                                       url))
                 (format stream "~&; Redirecting to ~A~%" url))
               (return (values header (and file (probe-file file)))))))))))


;;; A primitive tar unpacker

(in-package #:qlqs-minitar)

(defun make-block-buffer ()
  (make-array 512 :element-type '(unsigned-byte 8) :initial-element 0))

(defun skip-n-blocks (n stream)
  (let ((block (make-block-buffer)))
    (dotimes (i n)
      (read-sequence block stream))))

(defun ascii-subseq (vector start end)
  (let ((string (make-string (- end start))))
    (loop for i from 0
          for j from start below end
          do (setf (char string i) (code-char (aref vector j))))
    string))

(defun block-asciiz-string (block start length)
  (let* ((end (+ start length))
         (eos (or (position 0 block :start start :end end)
                            end)))
    (ascii-subseq block start eos)))

(defun prefix (header)
  (when (plusp (aref header 345))
    (block-asciiz-string header 345 155)))

(defun name (header)
  (block-asciiz-string header 0 100))

(defun payload-size (header)
  (values (parse-integer (block-asciiz-string header 124 12) :radix 8)))

(defun nth-block (n file)
  (with-open-file (stream file :element-type '(unsigned-byte 8))
    (let ((block (make-block-buffer)))
      (skip-n-blocks (1- n) stream)
      (read-sequence block stream)
      block)))

(defun payload-type (code)
  (case code
    (0 :file)
    (48 :file)
    (53 :directory)
    (t :unsupported)))

(defun full-path (header)
  (let ((prefix (prefix header))
        (name (name header)))
    (if prefix
        (format nil "~A/~A" prefix name)
        name)))

(defun save-file (file size stream)
  (multiple-value-bind (full-blocks partial)
      (truncate size 512)
    (ensure-directories-exist file)
    (with-open-file (outstream file
                     :direction :output
                     :if-exists :supersede
                     :element-type '(unsigned-byte 8))
      (let ((block (make-block-buffer)))
        (dotimes (i full-blocks)
          (read-sequence block stream)
          (write-sequence block outstream))
        (when (plusp partial)
          (read-sequence block stream)
          (write-sequence block outstream :end partial))))))

(defun unpack-tarball (tarfile &key (directory *default-pathname-defaults*))
  (let ((block (make-block-buffer)))
    (with-open-file (stream tarfile :element-type '(unsigned-byte 8))
      (loop
       (let ((size (read-sequence block stream)))
         (when (zerop size)
           (return))
         (unless (= size 512)
           (error "Bad size on tarfile"))
         (when (every #'zerop block)
           (return))
         (let* ((payload-code (aref block 156))
                (payload-type (payload-type payload-code))
                (tar-path (full-path block))
                (full-path (merge-pathnames tar-path directory))
                (payload-size (payload-size block)))
         (case payload-type
           (:file
            (save-file full-path payload-size stream))
           (:directory
            (ensure-directories-exist full-path))
           (t
            (warn "Unknown tar block payload code -- ~D" payload-code)
            (skip-n-blocks (ceiling (payload-size block) 512) stream)))))))))

(defun contents (tarfile)
  (let ((block (make-block-buffer))
        (result '()))
    (with-open-file (stream tarfile :element-type '(unsigned-byte 8))
      (loop
        (let ((size (read-sequence block stream)))
          (when (zerop size)
            (return (nreverse result)))
          (unless (= size 512)
            (error "Bad size on tarfile"))
          (when (every #'zerop block)
            (return (nreverse result)))
          (let* ((payload-type (payload-type (aref block 156)))
                 (tar-path (full-path block))
                 (payload-size (payload-size block)))
            (skip-n-blocks (ceiling payload-size 512) stream)
            (case payload-type
              (:file
               (push tar-path result))
              (:directory
               (push tar-path result)))))))))


(in-package #:qlqs-openpgp)

;;;; utils.lisp

(deftype octet ()
  `(unsigned-byte 8))

(deftype ub32 ()
  `(unsigned-byte 32))

(deftype ub64 ()
  `(unsigned-byte 64))

(deftype octet-vector (&optional size)
  `(simple-array octet (,size)))

(defun octet-vector (&rest initial-contents)
  (make-array (length initial-contents)
              :element-type 'octet
              :initial-contents initial-contents))

(defun make-octet-vector (size)
  (make-array size :element-type 'octet))

(defun make-ub32-vector (size)
  (make-array size :element-type 'ub32))

(defun make-ub64-vector (size)
  (make-array size :element-type 'ub64))

(defun first-n-octets (n vector)
  (let ((length (length vector)))
    (unless (<= n length)
      (error "Vector too short to take ~A elements" n))
    (subseq vector 0 n)))

(defun octet-vector-hex (octet-vector)
  (nstring-downcase
   (with-output-to-string (s)
     (map nil (lambda (o) (format s "~2,'0X" o)) octet-vector))))

;;;; r64.lisp

(defvar *radix64-alphabet*
  (concatenate 'string
               "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
               "abcdefghijklmnopqrstuvwxyz"
               "0123456789"
               "+/"))
(defvar *whitespace-characters*
  '(#\Tab #\Newline #\Linefeed #\Page #\Return #\Space)
  "Whitespace standard characters as defined by http://l1sp.org/cl/2.1.4")

(defvar *whitespace-index* 255)

(defparameter *radix64-indexes*
  (let ((table (make-hash-table)))
    (setf (gethash #\= table) 0)
    (dolist (char *whitespace-characters*)
      (setf (gethash char table) *whitespace-index*))
    (loop for index from 0
          for char across *radix64-alphabet*
          do (setf (gethash char table) index))
    table))

(defstruct r64-decoder
  (state 0 :type (mod 4))
  (accumulator 0 :type (mod 256))
  (result (make-array 10 :element-type '(unsigned-byte 8)
                      :fill-pointer 0
                      :adjustable t)))

(defun update-decoder (decoder string)
  (declare (type r64-decoder decoder)
           (type string string)
           (optimize speed))
  (let ((state (r64-decoder-state decoder))
        (accumulator (r64-decoder-accumulator decoder))
        (result (r64-decoder-result decoder)))
    (dotimes (i (length string))
      (let* ((char (char string i))
             (index (gethash char *radix64-indexes* 100)))
        (declare (type (mod 256) index))
        (when (= index 100)
          (error "Invalid radix64 character ~S at ~A of ~S"
                 char i string))
        (when (eql index *whitespace-index*)
          (go skip))
        (ecase state
          (0
           (setf state 1)
           (setf accumulator (ash index 2)))
          (1
           (setf state 2)
           (unless (eql char #\=)
             (vector-push-extend (logior accumulator
                                         (ldb (byte 2 4) index))
                                 result))
           (setf accumulator (ash (ldb (byte 4 0) index) 4)))
          (2
           (setf state 3)
           (unless (eql char #\=)
             (vector-push-extend (logior accumulator (ldb (byte 4 2) index))
                                 result))
           (setf accumulator (ash (ldb (byte 2 0) index) 6)))
          (3
           (setf state 0)
           (unless (eql char #\=)
             (vector-push-extend (logior accumulator index)
                                 result))
           (setf accumulator 0)
           )))
      skip)
    (setf (r64-decoder-accumulator decoder) accumulator)
    (setf (r64-decoder-state decoder) state)
    decoder))

(defun r64-decode (string)
  "Decode a complete radix-64 message from STRING."
  (let ((decoder (make-r64-decoder)))
    (update-decoder decoder string)
    (r64-decoder-result decoder)))

;;;; sha.lisp


;;; SHA-oriented arithmetic.

;;; For every op, define 32 and 64 bit versions, binary versions, and
;;; n-ary versions that reduce by compiler macro to the binary
;;; version.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun make-mask (bits)
    (1- (ash 1 bits)))

  (defun expand-rest-to-binary (op args)
    (if (rest args)
        `(,op ,(first args)
              ,(expand-rest-to-binary op (rest args)))
        (first args)))

  (defun operation-expansion (lisp-fun type mask a b)
    `(logand ,mask (,lisp-fun (the ,type ,a)
                              (the ,type ,b))))

  (defun symconcat (symbol suffix)
    (intern (format nil "~A~A"
                    (symbol-name symbol)
                    suffix)
            *package*)))

(defmacro define-binary-op (name lisp-fun)
  (flet ((expand (name name/2 mask type)
           `((defun ,name/2 (a b)
               (declare (type ,type a b))
               (logand ,mask (,lisp-fun a b)))
             (define-compiler-macro ,name/2 (a b)
               (operation-expansion ',lisp-fun ',type ,mask a b))
             (defun ,name (&rest args)
               (reduce ',name/2 args))
             (define-compiler-macro ,name (&rest args)
               (expand-rest-to-binary ',name/2 args)))))
    (let* ((fun32 (symconcat name "32"))
           (fun64 (symconcat name "64"))
           (fun32/2 (symconcat fun32 "/2"))
           (fun64/2 (symconcat fun64 "/2"))
           (mask32 (make-mask 32))
           (mask64 (make-mask 64)))
      `(progn
         ,@(expand fun32 fun32/2 mask32 'ub32)
         ,@(expand fun64 fun64/2 mask64 'ub64)))))

(defmacro define-unary-op (name lisp-fun)
  (flet ((expand (name type mask)
           `((defun ,name (a)
               (declare (type ,type a))
               (logand ,mask (,lisp-fun a)))
             (define-compiler-macro ,name (a)
               `(logand ,',mask (,',lisp-fun (the ,',type ,a)))))))
    `(progn
       ,@(expand (symconcat name "32") 'ub32 (make-mask 32))
       ,@(expand (symconcat name "64") 'ub64 (make-mask 64)))))

(define-binary-op xor logxor)
(define-binary-op and logand)
(define-binary-op or logior)
(define-binary-op add +)
(define-unary-op not lognot)

(macrolet ((define-rotate (direction size)
             (let* ((type (ecase size (32 'ub32) (64 'ub64)))
                    (prefix (ecase direction (:left 'rol) (:right 'ror)))
                    (name (symconcat prefix (princ-to-string size)))
                    (mask (make-mask size)))
               (multiple-value-bind (shift1 shift2)
                   (ecase direction
                     (:right (values '(- count) `(- ,size count)))
                     (:left  (values 'count `(- count ,size))))
                 `(progn
                    (defun ,name (a count)
                      (declare (type ,type a)
                               (type (mod ,size) count))
                      (logand ,mask
                              (logior (ash a ,shift1)
                                      (logand ,mask (ash a ,shift2)))))
                    (define-compiler-macro ,name (&whole whole &rest args)
                      (declare (ignore args))
                      whole))))))
  (define-rotate :left 32)
  (define-rotate :left 64)
  (define-rotate :right 32)
  (define-rotate :right 64))

(macrolet ((define-shift (size)
             (let ((type (ecase size (32 'ub32) (64 'ub64)))
                   (name (symconcat 'shift (princ-to-string size)))
                   (mask (make-mask size)))
               `(progn
                  (defun ,name (a count)
                    (logand ,mask (ash (the ,type a) (- count))))
                  (define-compiler-macro ,name (a count)
                    `(logand ,',mask (ash (the ,',type ,a) (- ,count))))))))
  (define-shift 32)
  (define-shift 64))


;;; SHA

(defparameter *sha-buffer-size* 6400)

(defgeneric update-sha (sha source &key start end))
(defgeneric update-sha-from-file (sha file))
(defgeneric compress (sha buffer end))
(defgeneric block-octet-count (sha))
(defgeneric total-octet-count (sha))
(defgeneric make-trailer-octets (sha))
(defgeneric sha-word-size (sha))
(defgeneric hash-vector-octets (sha))
(defgeneric sha-trailer (sha))
(defgeneric finish-sha (sha))

(defun make-trailer (octet-count &key block-octet-count size-octets-count)
  "Returns a trailer suitable for use in SHA-1, SHA-256, or SHA-512
padding, depending on the parameters given in BLOCK-OCTET-COUNT and
SIZE-OCTETS-COUNT. OCTET-COUNT is the total number of octets hashed."
  ;; Need space for #(#x80 ...padding... <size-octets>)
  (let* ((room-needed (+ 1 size-octets-count))
         (room (- block-octet-count (rem octet-count block-octet-count)))
         (trailer-size room))
    (when (< room room-needed)
      (incf trailer-size block-octet-count))
    (let ((trailer (make-octet-vector trailer-size)))
      ;; Leading 1 bit
      (setf (aref trailer 0) #x80)
      (let ((bit-count (* octet-count 8)))
        (loop for i downfrom (1- trailer-size)
              for bit-offset from 0 by 8
              repeat size-octets-count
              do (setf (aref trailer i)
                       (ldb (byte 8 bit-offset) bit-count))))
      trailer)))


(defun decode-ub32-vector (octet-vector start count target-vector)
  "Convert the octets in OCTET-VECTOR as (unsigned-byte 32) values
into TARGET-VECTOR."
  (declare (optimize speed)
           (type octet-vector octet-vector)
           (type fixnum start count)
           (type (simple-array (unsigned-byte 32) (*)) target-vector))
  (flet ((decode (position)
           (logior (ash (aref octet-vector (+ position 0)) 24)
                   (ash (aref octet-vector (+ position 1)) 16)
                   (ash (aref octet-vector (+ position 2))  8)
                   (ash (aref octet-vector (+ position 3))  0))))
    (loop for i below count
          for j from start by 4
          do (setf (aref target-vector i) (decode j)))
    target-vector))

(defun decode-ub64-vector (octet-vector start count target-vector)
  "Convert the octets in OCTET-VECTOR as (unsigned-byte 64) values
into TARGET-VECTOR."
  (declare (optimize speed)
           (type octet-vector octet-vector)
           (type fixnum start count)
           (type (simple-array (unsigned-byte 64) (*)) target-vector))
  (flet ((decode (position)
           (logior (ash (aref octet-vector (+ position 0)) 56)
                   (ash (aref octet-vector (+ position 1)) 48)
                   (ash (aref octet-vector (+ position 2)) 40)
                   (ash (aref octet-vector (+ position 3)) 32)
                   (ash (aref octet-vector (+ position 4)) 24)
                   (ash (aref octet-vector (+ position 5)) 16)
                   (ash (aref octet-vector (+ position 6))  8)
                   (ash (aref octet-vector (+ position 7))  0))))
    (loop for i below count
          for j from start by 8
          do (setf (aref target-vector i) (decode j)))
    target-vector))


;;; Generic SHA structure

(defclass sha ()
  ((hash-vector
    :initarg :hash-vector
    :reader hash-vector)
   (work-vector
    :initarg :work-vector
    :reader work-vector)
   (buffer
    :initarg :buffer
    :reader buffer)
   (buffer-position
    :initarg :buffer-position
    :accessor buffer-position
    :initform 0)
   (total-octet-count
    :initarg :total-octet-count
    :initform 0
    :accessor total-octet-count)
   (block-octet-count
    :initarg :block-octet-count
    :reader block-octet-count)
   (word-size
    :initarg :word-size
    :reader sha-word-size)))

(defmethod sha-trailer (sha)
  (make-trailer (total-octet-count sha)
                :block-octet-count (block-octet-count sha)
                :size-octets-count (/ (sha-word-size sha) 4)))

(defun sha-result (sha)
  (hash-vector-octets sha))

(defmethod finish-sha (sha)
  (let ((trailer (sha-trailer sha)))
    (update-sha sha trailer)
    (compress sha (buffer sha) (buffer-position sha))
    (sha-result sha)))

(defmethod update-sha (sha octets &key start end)
  "Add OCTETS (delimited by START and END) to SHA."
  (unless start (setf start 0))
  (unless end (setf end (length octets)))
  ;; Copy as much of OCTETS to the SHA buffer as possible; if it
  ;; fills, COMPRESS it and copy more.
  (let* ((buffer (buffer sha))
         (pos (buffer-position sha))
         (buffer-size (length buffer))
         (capacity (- (length buffer) pos))
         (needed (- end start)))
    (incf (total-octet-count sha) needed)
    (loop
      (when (zerop capacity)
        (compress sha buffer buffer-size)
        (setf capacity buffer-size)
        (setf pos 0))
      (when (<= needed capacity)
        (replace buffer octets
                 :start1 pos
                 :start2 start
                 :end2 end)
        (incf (buffer-position sha) needed)
        (return))
      (replace buffer octets
               :start1 pos
               :end1 buffer-size
               :start2 start)
      (incf start capacity)
      (decf needed capacity)
      (setf capacity 0))))

(defmethod update-sha (sha (stream stream) &key start end)
  (declare (ignore start end))
  (let ((buffer (make-octet-vector *sha-buffer-size*)))
    (loop
      (let ((end (read-sequence buffer stream)))
        (when (zerop end)
          (return sha))
        (update-sha sha buffer :end end)))))

(defmethod update-sha-from-file (sha file)
  (with-open-file (stream file :element-type 'octet)
    (update-sha sha stream)))

(defmacro with-hash-vector (vars sha &body body)
  (let ((hash-vector (gensym "hash-vector")))
    `(let ((,hash-vector (hash-vector ,sha)))
       (let ,(loop for var in vars
                   for i from 0
                   collect (list var `(aref ,hash-vector ,i)))
         (progn
           ,@body)
         ,@(loop for var in vars
                 for i from 0
                 collect `(setf (aref ,hash-vector ,i) ,var))))))

(defun word-vector-octets (vector word-size)
  "Return an octet vector of the words of VECTOR, interpreting each
vector element as an unsigned-byte of size WORD-SIZE."
  (let ((result (make-octet-vector (* (length vector) (floor word-size 8)))))
    (dotimes (i (length result) result)
      (multiple-value-bind (word-index octet-index)
          (truncate (* i 8) word-size)
        (let ((ldb-position (- word-size octet-index 8)))
          (setf (aref result i)
                (ldb (byte 8 ldb-position) (aref vector word-index))))))))

(defmethod hash-vector-octets (sha)
  (word-vector-octets (hash-vector sha) (sha-word-size sha)))

;;; SHA-1

(defparameter *sha1-hash-vector*
  (vector #x67452301
          #xEFCDAB89
          #x98BADCFE
          #x10325476
          #xC3D2E1F0))

(defclass sha1 (sha)
  ()
  (:default-initargs
   :buffer (make-octet-vector *sha-buffer-size*)
   :hash-vector (replace (make-ub32-vector 5) *sha1-hash-vector*)
   :work-vector (make-ub32-vector 80)
   :block-octet-count 64
   :word-size 32))

(defmethod compress ((sha1 sha1) buffer end)
  (declare (optimize speed))
  (prog1 sha1
    (with-hash-vector (h0 h1 h2 h3 h4)
        sha1
      (let* ((f 0)
             (k 0)
             (w (work-vector sha1))
             (block-octet-count (block-octet-count sha1))
             (block-count (floor end block-octet-count)))
        (declare (type (simple-array ub32 (80)) w))
        (dotimes (ii block-count)
          (let ((a h0)
                (b h1)
                (c h2)
                (d h3)
                (e h4))
            (decode-ub32-vector buffer (* ii 64) 16 w)
            (loop for i from 16 to 79
                  do (setf (aref w i)
                           (rol32 (xor32 (aref w (- i 3))
                                         (aref w (- i 8))
                                         (aref w (- i 14))
                                         (aref w (- i 16)))
                                  1)))
            (dotimes (i 80)
              (cond ((<= 0 i 19)
                     (setf f (or32 (and32 b c)
                                   (and32 (not32 b) d)))
                     (setf k #x5A827999))
                    ((<= 20 i 39)
                     (setf f (xor32 b c d))
                     (setf k #x6ED9EBA1))
                    ((<= 40 i 59)
                     (setf f (or32 (and32 b c)
                                   (and32 b d)
                                   (and32 c d)))
                     (setf k #x8F1BBCDC))
                    ((<= 60 i 79)
                     (setf f (xor32 b c d))
                     (setf k #xCA62C1D6)))
              (let ((temp (add32 (rol32 a 5) f e k (aref w i))))
                (setf e d)
                (setf d c)
                (setf c (rol32 b 30))
                (setf b a)
                (setf a temp)))
            (setf h0 (add32 a h0))
            (setf h1 (add32 b h1))
            (setf h2 (add32 c h2))
            (setf h3 (add32 d h3))
            (setf h4 (add32 e h4))))
        (setf (buffer-position sha1) 0)))))


;;; SHA256

(defvar *sha256-round-constants*
  #(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5
    #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
    #xd807aa98 #x12835b01 #x243185be #x550c7dc3
    #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
    #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
    #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
    #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7
    #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
    #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
    #x650a7354 #x766a0abb #x81c2c92e #x92722c85
    #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3
    #xd192e819 #xd6990624 #xf40e3585 #x106aa070
    #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5
    #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
    #x748f82ee #x78a5636f #x84c87814 #x8cc70208
    #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2))

(defvar *sha256-hash-vector*
  #(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
    #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19))

(defclass sha256 (sha)
  ((constant-vector
    :initarg :constant-vector
    :reader constant-vector))
  (:default-initargs
   :block-octet-count 64
   :buffer (make-octet-vector *sha-buffer-size*)
   :work-vector (make-ub32-vector 64)
   :hash-vector (replace (make-ub32-vector 8) *sha256-hash-vector*)
   :constant-vector (replace (make-ub32-vector 64)
                             *sha256-round-constants*)
   :word-size 32))

(defmethod compress ((sha sha256) buffer end)
  (declare (optimize speed))
  (prog1 sha
    (with-hash-vector (h0 h1 h2 h3 h4 h5 h6 h7)
        sha
      (let* ((w (work-vector sha))
             (k (constant-vector sha))
             (block-octet-count (block-octet-count sha))
             (block-count (floor end block-octet-count)))
        (declare (type (simple-array ub32 (*)) w k))
        (dotimes (ii block-count)
          (let ((a h0) (b h1) (c h2) (d h3)
                (e h4) (f h5) (g h6) (h h7))
            (declare (type ub32 a b c d e f g h))
            (decode-ub32-vector buffer (* ii 64) 16 w)
            (loop for i from 16 to 63
                  do
                  (let* ((w15 (aref w (- i 15)))
                         (w2 (aref w (- i 2)))
                         (s0 (xor32 (ror32 w15 7)
                                    (ror32 w15 18)
                                    (shift32 w15 3)))
                         (s1 (xor32 (ror32 w2 17)
                                    (ror32 w2 19)
                                    (shift32 w2 10))))
                    (setf (aref w i)
                          (add32 (aref w (- i 16))
                                 s0
                                 (aref w (- i 7))
                                 s1))))
            (dotimes (i 64)
              (let* ((S1 (xor32 (ror32 e 6) (ror32 e 11) (ror32 e 25)))
                     (ch (xor32 (and32 e f) (and32 (not32 e) g)))
                     (temp1 (add32 h S1 ch (aref k i) (aref w i)))
                     (S0 (xor32 (ror32 a 2) (ror32 a 13) (ror32 a 22)))
                     (maj (xor32 (and32 a b) (and32 a c) (and32 b c)))
                     (temp2 (add32 S0 maj)))
                (setf h g
                      g f
                      f e
                      e (add32 d temp1)
                      d c
                      c b
                      b a
                      a (add32 temp1 temp2))))
            (setf h0 (add32 a h0)
                  h1 (add32 b h1)
                  h2 (add32 c h2)
                  h3 (add32 d h3)
                  h4 (add32 e h4)
                  h5 (add32 f h5)
                  h6 (add32 g h6)
                  h7 (add32 h h7)))))
      (setf (buffer-position sha) 0))))


;;; SHA-512

(defvar *sha512-constant-vector*
  #(#x428a2f98d728ae22 #x7137449123ef65cd #xb5c0fbcfec4d3b2f #xe9b5dba58189dbbc
    #x3956c25bf348b538 #x59f111f1b605d019 #x923f82a4af194f9b #xab1c5ed5da6d8118
    #xd807aa98a3030242 #x12835b0145706fbe #x243185be4ee4b28c #x550c7dc3d5ffb4e2
    #x72be5d74f27b896f #x80deb1fe3b1696b1 #x9bdc06a725c71235 #xc19bf174cf692694
    #xe49b69c19ef14ad2 #xefbe4786384f25e3 #x0fc19dc68b8cd5b5 #x240ca1cc77ac9c65
    #x2de92c6f592b0275 #x4a7484aa6ea6e483 #x5cb0a9dcbd41fbd4 #x76f988da831153b5
    #x983e5152ee66dfab #xa831c66d2db43210 #xb00327c898fb213f #xbf597fc7beef0ee4
    #xc6e00bf33da88fc2 #xd5a79147930aa725 #x06ca6351e003826f #x142929670a0e6e70
    #x27b70a8546d22ffc #x2e1b21385c26c926 #x4d2c6dfc5ac42aed #x53380d139d95b3df
    #x650a73548baf63de #x766a0abb3c77b2a8 #x81c2c92e47edaee6 #x92722c851482353b
    #xa2bfe8a14cf10364 #xa81a664bbc423001 #xc24b8b70d0f89791 #xc76c51a30654be30
    #xd192e819d6ef5218 #xd69906245565a910 #xf40e35855771202a #x106aa07032bbd1b8
    #x19a4c116b8d2d0c8 #x1e376c085141ab53 #x2748774cdf8eeb99 #x34b0bcb5e19b48a8
    #x391c0cb3c5c95a63 #x4ed8aa4ae3418acb #x5b9cca4f7763e373 #x682e6ff3d6b2b8a3
    #x748f82ee5defb2fc #x78a5636f43172f60 #x84c87814a1f0ab72 #x8cc702081a6439ec
    #x90befffa23631e28 #xa4506cebde82bde9 #xbef9a3f7b2c67915 #xc67178f2e372532b
    #xca273eceea26619c #xd186b8c721c0c207 #xeada7dd6cde0eb1e #xf57d4f7fee6ed178
    #x06f067aa72176fba #x0a637dc5a2c898a6 #x113f9804bef90dae #x1b710b35131c471b
    #x28db77f523047d84 #x32caab7b40c72493 #x3c9ebe0a15c9bebc #x431d67c49c100d4c
    #x4cc5d4becb3e42b6 #x597f299cfc657e2a #x5fcb6fab3ad6faec #x6c44198c4a475817))

(defparameter *sha512-hash-vector*
  #(#x6a09e667f3bcc908 #xbb67ae8584caa73b #x3c6ef372fe94f82b
    #xa54ff53a5f1d36f1 #x510e527fade682d1 #x9b05688c2b3e6c1f
    #x1f83d9abfb41bd6b #x5be0cd19137e2179))

(defclass sha512 (sha)
  ((constant-vector
    :initarg :constant-vector
    :reader constant-vector))
  (:default-initargs
   :block-octet-count 128
   :buffer (make-octet-vector *sha-buffer-size*)
   :work-vector (make-ub64-vector 80)
   :hash-vector (replace (make-ub64-vector 8) *sha512-hash-vector*)
   :constant-vector (replace (make-ub64-vector 80)
                             *sha512-constant-vector*)
   :word-size 64))

(defmethod compress ((sha sha512) buffer end)
  (declare (optimize speed))
  (prog1 sha
    (with-hash-vector (h0 h1 h2 h3 h4 h5 h6 h7)
        sha
      (let* ((w (work-vector sha))
             (k (constant-vector sha))
             (block-octet-count (block-octet-count sha))
             (block-count (floor end block-octet-count)))
        (declare (type (simple-array ub64 (*)) w k))
        (dotimes (ii block-count)
          (let ((a h0) (b h1) (c h2) (d h3)
                (e h4) (f h5) (g h6) (h h7))
            (declare (type ub64 a b c d e f g h))
            (decode-ub64-vector buffer (* ii 128) 16 w)
            (loop for i from 16 to 79
                  do
                  (let* ((w15 (aref w (- i 15)))
                         (w2 (aref w (- i 2)))
                         (s0 (xor64 (ror64 w15 1)
                                    (ror64 w15 8)
                                    (shift64 w15 7)))
                         (s1 (xor64 (ror64 w2 19)
                                    (ror64 w2 61)
                                    (shift64 w2 6))))
                    (setf (aref w i)
                          (add64 (aref w (- i 16))
                                 s0
                                 (aref w (- i 7))
                                 s1))))
            (dotimes (i 80)
              (let* ((S1 (xor64 (ror64 e 14) (ror64 e 18) (ror64 e 41)))
                     (ch (xor64 (and64 e f) (and64 (not64 e) g)))
                     (temp1 (add64 h S1 ch (aref k i) (aref w i)))
                     (S0 (xor64 (ror64 a 28) (ror64 a 34) (ror64 a 39)))
                     (maj (xor64 (and64 a b) (and64 a c) (and64 b c)))
                     (temp2 (add64 S0 maj)))
                (setf h g
                      g f
                      f e
                      e (add64 d temp1)
                      d c
                      c b
                      b a
                      a (add64 temp1 temp2))))
            (setf h0 (add64 a h0)
                  h1 (add64 b h1)
                  h2 (add64 c h2)
                  h3 (add64 d h3)
                  h4 (add64 e h4)
                  h5 (add64 f h5)
                  h6 (add64 g h6)
                  h7 (add64 h h7)))))
      (setf (buffer-position sha) 0))))


;;; Misc. utility

(defun file-sha (sha-class file)
  (let ((sha (make-instance sha-class)))
    (with-open-file (stream file :element-type 'octet)
      (update-sha sha stream))
    (finish-sha sha)))

(defun file-sha-string (sha-class file)
  (octet-vector-hex (file-sha sha-class file)))

;;;; packet.lisp

(defun key-string (key-id)
  "Convert the octet vector KEY-ID to a hex string."
  (octet-vector-hex key-id))

(defclass packet ()
  ((packet-type
    :initarg :packet-type
    :accessor packet-type)
   (hashed-data
    :initarg :hashed-data
    :accessor hashed-data)
   (data
    :initarg :data
    :accessor data)))

(defgeneric version (packet)
  (:method (packet)
    (aref (data packet) 0)))

(defmethod print-object ((packet packet) stream)
  (print-unreadable-object (packet stream :type t :identity t)
    (format stream "~S, size ~D"
            (packet-type packet)
            (length (data packet)))))

(defmethod initialize-instance :after ((packet packet)
                                       &key data
                                         &allow-other-keys)
  (unless data
    (error "DATA is required"))
  (unless (slot-boundp packet 'hashed-data)
    (setf (hashed-data packet) data)))

(defgeneric specialize-packet-by-type (packet-type packet)
  (:method ((packet-type t) packet)
    packet))

(defgeneric specialize-packet (packet)
  (:documentation "Change (via CHANGE-CLASS) a plain packet into a
  specialized packet by examining its type and data.")
  (:method (packet)
    (specialize-packet-by-type (packet-type packet) packet)))

(defclass rsa-signature-packet (packet)
  ((key-id
    :initarg :key-id
    :accessor key-id)
   (signature-type
    :initarg :signature-type
    :accessor signature-type)
   (hashed-data
    :initarg :hashed-data
    :accessor hashed-data)
   (creation-time
    :initarg :creation-time
    :accessor creation-time)
   (public-key-algorithm
    :initarg :public-key-algorithm
    :accessor public-key-algorithm)
   (hash-algorithm
    :initarg :hash-algorithm
    :accessor hash-algorithm)
   (quick-check-value
    :initarg :quick-check-value
    :accessor quick-check-value)
   (signature-value
    :initarg :signature-value
    :accessor signature-value)))

(defmethod print-object ((packet rsa-signature-packet) stream)
  (print-unreadable-object (packet stream :type t :identity t)
    (format stream "~A key id ~S"
            (public-key-algorithm packet)
            (key-string (key-id packet)))))


(defclass rsa-public-key-packet (packet)
  ((fingerprint
    :initarg :fingerprint
    :accessor fingerprint)
   (key-id
    :initarg :key-id
    :accessor key-id)
   (hashed-data
    :initarg :hashed-data
    :accessor hashed-data)
   (creation-time
    :initarg :creation-time
    :accessor creation-time)
   (n
    :initarg :n
    :accessor n)
   (e
    :initarg :e
    :accessor e)))

(defclass rsa-public-subkey-packet (rsa-public-key-packet) ())

(defmethod print-object ((packet rsa-public-key-packet) stream)
  (print-unreadable-object (packet stream :type t :identity t)
    (format stream "key id ~S" (key-string (key-id packet)))))

(defvar *initial-fingerprint-vector*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x99 ))

(defun compute-fingerprint (data)
  (let* ((sha1 (make-instance 'sha1))
         (length (length data))
         (length-vector (make-array 2 :element-type '(unsigned-byte 8))))
    (setf (aref length-vector 0) (ldb (byte 8 8) length))
    (setf (aref length-vector 1) (ldb (byte 8 0) length))
    (update-sha sha1 *initial-fingerprint-vector*)
    (update-sha sha1 length-vector)
    (update-sha sha1 data)
    (finish-sha sha1)))

(defun compute-key-id (public-key)
  (subseq (fingerprint public-key) 12))

(defclass user-id-packet (packet)
  ((user-id
    :initarg :user-id
    :accessor user-id)))

(defmethod print-object ((packet user-id-packet) stream)
  (print-unreadable-object (packet stream :type t)
    (format stream "~S" (user-id packet))))


(defgeneric key-id-string (object)
  (:method (object)
    (key-string (key-id object))))

;;;; ascii-armor.lisp

(defvar *supported-armor-header-lines*
  '("-----BEGIN PGP SIGNATURE-----"
    "-----BEGIN PGP PUBLIC KEY BLOCK-----"))

(defvar *supported-armor-tail-lines*
  '("-----END PGP SIGNATURE-----"
    "-----END PGP PUBLIC KEY BLOCK-----")
  "A list of supported tail lines. Must match up 1-to-1 with header
  lines.")

(defun starts-with (substring string)
  (and (<= (length substring) (length string))
       (string= substring string :end2 (length substring))))

(defun whitespacep (char)
  (member char '(#\Space #\Tab #\Newline #\Return)))

(defun marker-equal (marker string)
  "Does STRING match MARKER? To match, MARKER must appear at the
  start, and have only whitespace following."
  (and (starts-with marker string)
       (not (position-if-not #'whitespacep string
                             :start (length marker)))))

(defun checksum-line-p (line)
  (and (<= (length line) 5)
       (char= (char line 0) #\=)))

(defun tail-line (header-line)
  (let ((index (position header-line *supported-armor-header-lines*
                         :test #'marker-equal)))
    (unless index
      (error "Unknown header line -- ~S" header-line))
    (elt *supported-armor-tail-lines* index)))

(defun skip-to-armor-header-line (stream)
  (loop for line = (read-line stream)
        when (member line *supported-armor-header-lines* :test #'marker-equal)
        return line))

(defun ascii-armor-data (stream)
  "Return the ASCII-armored ASCII data from STREAM."
  (let* ((checksum-line nil)
         (header-line (skip-to-armor-header-line stream))
         (tail-line (tail-line header-line)))
    ;; Skip header lines, if present
    (loop for line = (read-line stream nil)
          if (null line)
          do (error "Missing armor header lines")
          until (marker-equal "" line))
    ;; Read data
    (values
     (with-output-to-string (s)
       (loop for line = (read-line stream nil)
             if (null line)
             do (error "End of file in stream")
             if (checksum-line-p line)
             ;; Skip leading #\=
             do (setf checksum-line (subseq line 1))
             until (marker-equal line tail-line)
             do (unless checksum-line (write-line line s))))
     checksum-line
     header-line)))

(defun ascii-armor-crc24 (octets)
  (let ((crc #xB704CE)
        (poly #x1864CFB))
    (map nil (lambda (octet)
               (setf crc (logand #xFFFFFF (logxor crc (ash octet 16))))
               (dotimes (i 8)
                 (setf crc (ash crc 1))
                 (when (logtest #x1000000 crc)
                   (setf crc (logxor crc poly)))))
         octets)
    (vector (ldb (byte 8 16) crc)
            (ldb (byte 8  8) crc)
            (ldb (byte 8  0) crc))))

(defun file-ascii-armor-data (file)
  (with-open-file (stream file)
    (multiple-value-bind (encoded-data encoded-checksum)
        (ascii-armor-data stream)
      (let* ((data (r64-decode encoded-data))
             (data-checksum (r64-decode encoded-checksum))
             (checksum (ascii-armor-crc24 data)))
        (unless (equalp checksum data-checksum)
          (error "Checksum mismatch -- ASCII armor data has ~S, locally computed ~S"
                 data-checksum
                 checksum))
        data))))




;;;; packet.lisp

(defclass packet-stream ()
  ((data
    :initarg :data
    :reader data)
   (data-length
    :reader data-length)
   (pos
    :initform 0
    :accessor pos)
   (eofp
    :initform nil
    :accessor eofp))
  (:documentation
   "A packet stream is a simple stream-like object for sequential
   access to an octet vector."))

(define-condition packet-stream-eof (error) ())

(defmethod initialize-instance :after ((packet-stream packet-stream)
                                       &key data &allow-other-keys)
  (unless data
    (error "DATA is required"))
  (setf (slot-value packet-stream 'data-length) (length data)))

(defun pstream (data)
  "Create a packet stream based on DATA."
  (make-instance 'packet-stream :data data))

(defun at-eof-p (packet-stream)
  (= (pos packet-stream) (data-length packet-stream)))

(defun check-eof (packet-stream)
  (when (or (eofp packet-stream)
            (setf (eofp packet-stream) (at-eof-p packet-stream)))
    (error 'packet-stream-eof)))


(defun read-u8 (packet-stream)
  (check-eof packet-stream)
  (prog1
      (aref (data packet-stream) (pos packet-stream))
    (incf (pos packet-stream))))

(defun read-n-octets (n pstream)
  (let ((vector (make-array n :element-type '(unsigned-byte 8))))
    (loop for i below n
          do (setf (aref vector i) (read-u8 pstream)))
    vector))

(defun read-u16 (packet-stream)
  (logior (ash (read-u8 packet-stream)  8)
          (ash (read-u8 packet-stream)  0)))

(defun read-u32 (packet-stream)
  (logior (ash (read-u8 packet-stream) 24)
          (ash (read-u8 packet-stream) 16)
          (ash (read-u8 packet-stream)  8)
          (ash (read-u8 packet-stream)  0)))

(defun read-mpi (packet-stream)
  (let* ((mpi-bits (read-u16 packet-stream))
         (octets (ceiling mpi-bits 8))
         (result 0))
    (dotimes (i octets result)
      (setf result (logior (ash result 8)
                           (read-u8 packet-stream))))))

(defun decode-u32 (vector)
  (logior (ash (aref vector 0) 24)
          (ash (aref vector 1) 16)
          (ash (aref vector 2)  8)
          (ash (aref vector 3)  0)))

(defun encode-u32 (u32)
  (make-array 4 :element-type '(unsigned-byte 8)
              :initial-contents (list (ldb (byte 8 24) u32)
                                      (ldb (byte 8 16) u32)
                                      (ldb (byte 8  8) u32)
                                      (ldb (byte 8  0) u32))))

(defun %reset (packet-stream)
  "Reset PACKET-STREAM so it can be read again from the beginning."
  (setf (pos packet-stream) 0)
  (setf (eofp packet-stream) nil)
  packet-stream)

(defun packet-type-value (packet-type)
  "Return a symbolic value for the integer PACKET-TYPE. Only supported
values are decoded; others signal an error. See RFC4880 section 4.3."
  (ecase packet-type
    (0 (error "0 is a reserved packet type and must not appear per RFC 4880"))
    (2 :signature)
    (6 :public-key)
    (13 :user-id)
    (14 :public-subkey)))


;;;
;;; Reading and decoding various packet fields from integers to
;;; symbolic constants.
;;;

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun find-type-reader (type)
    (ecase type
      (u8 'read-u8)
      (u16 'read-u16)
      (u32 'read-u32))))

(defmacro define-field (name (&key type) &body values-alist)
  `(progn
     (setf (get ',name 'reader-function) ',(find-type-reader type))
     (setf (get ',name 'values-alist) ',values-alist)))

(defun missing-reader-function (&rest args)
  (declare (ignore args))
  (error "No reader function available"))

(defun read-field (field pstream)
  "Read the integer value of FIELD (a symbol previously defined with
DEFINE-FIELD) from PSTREAM."
  (funcall (get field 'reader-function 'missing-reader-function) pstream))

(defun read-field-value (field pstream)
  "Read and FIELD from PSTREAM and look up and return its symbolic
value."
  (let* ((raw-value (read-field field pstream))
         (translation (assoc raw-value (get field 'values-alist))))
    (unless translation
      (error "Unsupported value ~A for field ~A"
             raw-value
             field))
    (cdr translation)))

(define-field signature-type (:type u8)
  ;; RFC 4880 section 5.2.1
  (0 . :binary-document)
  (16 . :generic-certification)
  (17 . :persona-certification)
  (18 . :casual-certification)
  (19 . :positive-user-id-certification)
  (24 . :subkey-binding-signature))


(define-field subpacket-type (:type u8)
  ;; RFC 4880 section 5.2.3.1
  (2 . :signature-creation-time)
  (3 . :signature-expiration-time)
  (9 . :key-expiration-time)
  (11 . :preferred-symmetric-algorithms)
  (16 . :issuer)
  (21 . :preferred-hash-algorithms)
  (22 . :preferred-compression-algorithms)
  (23 . :key-server-preferences)
  (27 . :key-flags)
  (30 . :features))

(define-field public-key-algorithm (:type u8)
  ;; RFC 4880 section 9.1
  (1 . :rsa)
  (3 . :rsa-sign-only)
  (17 . :dsa))

(define-field hash-algorithm (:type u8)
  ;; RFC 4880 section 9.4
  (1 . :md5)
  (2 . :sha-1)
  (8 . :sha-256)
  (9 . :sha-384)
  (10 . :sha-512)
  (11 . :sha-224))


(defun check-supported-value (description supported actual)
  "Signal an error unless SUPPORTED is EQL to ACTUAL"
  (unless (eql supported actual)
    (error "Value ~S for ~A not supported -- only ~A"
           actual description supported)))

(defun read-subpacket-length (pstream)
  "Read an encoded length value, which may be 1, 2, or 5 octets in
size, from PSTREAM. See RFC4880 5.2.3.1 for details."
  (let ((b1 (read-u8 pstream)))
    (cond ((< b1 192)
           b1)
          ((<= 192 b1 254)
           (let ((b2 (read-u8 pstream)))
             (logior (ash (- b1 192) 8)
                     b2
                     192)))
          ((= b1 255)
           (read-u32 pstream)))))

(defun read-signature-subpacket (pstream)
  "Read a single signature subpacket from PSTREAM. Returns the packet
  type and data as multiple values."
  (let* ((length (read-subpacket-length pstream))
         (type (read-field-value 'subpacket-type pstream))
         (data (read-n-octets (1- length) pstream)))
    (values type data)))

(defun read-signature-subpackets (pstream)
  "Read a list of subpackets from PSTREAM."
  (let* ((subpackets-total-length (read-u16 pstream))
         (end (+ (pos pstream) subpackets-total-length))
         (result '()))
    (loop
      (when (<= end (pos pstream))
        (return (nreverse result)))
      (multiple-value-bind (type data)
          (read-signature-subpacket pstream)
        (push (cons type data) result)))))

;;; Generic packet reading

(defun read-packet (pstream)
  "Read a packet from PSTREAM. Signals PACKET-STREAM-EOF if there is
no more data in PSTREAM. Format of binary packet data header is
specified in RFC 4880 section 4.2."
  (let ((tag (read-u8 pstream)))
    (unless (logbitp 7 tag)
      (error "Invalid packet tag -- bit 7 is zero -- ~A" tag))
    (when (logbitp 6 tag)
      (error "New packet format is not supported"))
    (let* ((packet-tag (ldb (byte 4 2) tag))
           (length-type (ldb (byte 2 0) tag))
           (length-size (expt 2 length-type)))
      (when (= length-type 3)
        (error "Indefinite length types not supported"))
      (let* ((length (ecase length-size
                       (1 (read-u8 pstream))
                       (2 (read-u16 pstream))
                       (4 (read-u16 pstream))))
             (data (read-n-octets length pstream)))
        (specialize-packet
         (make-instance 'packet
                        :data data
                        :packet-type (packet-type-value packet-tag)))))))

(defun read-packets (pstream)
  "Return a list of packets from PSTREAM."
  (loop for packet = (handler-case (read-packet pstream)
                       (packet-stream-eof () nil))
        while packet
        collect packet))

;;; User-id packets

(defun utf8-octets-to-string (octets)
  ;; FIXME: Handle real UTF-8
  (when (some (lambda (code) (logbitp 7 code)) octets)
    (error "Proper UTF-8 decoding is not implemented yet"))
  (map 'string 'code-char octets))

(defmethod specialize-packet-by-type ((packet-type (eql :user-id)) packet)
  (change-class packet
                'user-id-packet
                :user-id (utf8-octets-to-string (data packet))))


;;; Public key and subkey packets

(defmethod specialize-packet-by-type ((packet-type (eql :public-key)) packet)
  (let* ((pstream (pstream (data packet)))
         (version (read-u8 pstream)))
    (check-supported-value "version" 4 version)
    (let ((creation-time (read-u32 pstream))
          (public-key-algorithm (read-field-value 'public-key-algorithm
                                                  pstream)))
      (check-supported-value "public-key algorithm" :rsa public-key-algorithm)
      (let* ((n (read-mpi pstream))
             (e (read-mpi pstream))
             (fingerprint (compute-fingerprint (data packet)))
             (key-id (subseq fingerprint (- (length fingerprint) 8))))
        (change-class packet 'rsa-public-key-packet
                      :fingerprint fingerprint
                      :key-id key-id
                      :creation-time creation-time
                      :n n
                      :e e)))))

(defmethod specialize-packet-by-type ((packet-type (eql :public-subkey)) packet)
  (change-class (specialize-packet-by-type :public-key packet)
                'rsa-public-subkey-packet))


;;; Signature packet

(defmethod specialize-packet-by-type ((packet-type (eql :signature)) packet)
  (let* ((pstream (pstream (data packet)))
         (VERSION (read-u8 pstream)))
    (check-supported-value "version" 4 version)
    (let ((signature-type (read-field-value 'signature-type pstream))
          (public-key-algorithm (read-field-value 'public-key-algorithm
                                                  pstream))
          (hash-algorithm (read-field-value 'hash-algorithm pstream)))
      (check-supported-value "public-key algorithm"
                             :rsa
                             public-key-algorithm)
      (let* ((hashed-subpackets (read-signature-subpackets pstream))
             ;; Important to save the position immediately after
             ;; reading the hashed subpackets
             (end-of-hashed-data-pos (pos pstream))
             (unhashed-subpackets (read-signature-subpackets pstream))
             (subpackets (append hashed-subpackets unhashed-subpackets))
             (quick-check-value (read-n-octets 2 pstream))
             (rsa-signature-value (read-mpi pstream))
             (raw-creation-time (cdr (assoc :signature-creation-time subpackets)))
             (creation-time (and raw-creation-time
                                 (decode-u32 raw-creation-time))))
        (change-class packet 'rsa-signature-packet
                      :key-id (cdr (assoc :issuer subpackets))
                      :creation-time creation-time
                      :signature-type signature-type
                      :hash-algorithm hash-algorithm
                      :public-key-algorithm public-key-algorithm
                      :quick-check-value quick-check-value
                      :hashed-data (subseq (data packet)
                                           0 end-of-hashed-data-pos)
                      :signature-value rsa-signature-value)))))


;;; Misc

(defun load-packets-from-file (file)
  (let* ((data (file-ascii-armor-data file))
         (pstream (pstream data)))
    (read-packets pstream)))

(defun load-packet-from-file (file)
  (let* ((data (file-ascii-armor-data file))
         (pstream (pstream data)))
    (read-packet pstream)))

;;;; signature.lisp

(defun expt-mod (n exponent modulus)
  (loop with result = 1
        for i from 0 below (integer-length exponent)
        for sqr = n then (mod (* sqr sqr) modulus)
        when (logbitp i exponent) do
        (setf result (mod (* result sqr) modulus))
        finally (return result)))

(defun vector-integer (vector)
  "Convert the octet vector VECTOR to an integer."
  (let ((result 0))
    (dotimes (i (length vector) result)
      (setf result (logior (ash result 8) (aref vector i))))))


(defun load-signature (file)
  (let* ((packet (load-packet-from-file file)))
    (check-type packet rsa-signature-packet)
    packet))

(defun load-public-key (file)
  (let* ((packet (load-packet-from-file file)))
    (check-type packet rsa-public-key-packet)
    packet))

(defun verify-signature (file signature public-key)
  (unless (equalp (key-id public-key)
                  (key-id signature))
    (error "Signature and public key do not match"))
  (check-supported-value "hash algorithm" :sha-512 (hash-algorithm signature))
  (check-supported-value "public-key algorithm"
                         :rsa
                         (public-key-algorithm signature))
  (check-supported-value "signature type"
                         :binary-document
                         (signature-type signature))
  (let ((sha512 (make-instance 'sha512))
        (trailer (make-array 2 :element-type '(unsigned-byte 8)
                             :initial-contents (list (version signature) #xFF)))
        (size-vector (encode-u32 (length (hashed-data signature))))
        (quick-check-expected (quick-check-value signature)))
    (update-sha-from-file sha512 file)
    (update-sha sha512 (hashed-data signature))
    (update-sha sha512 trailer)
    (update-sha sha512 size-vector)
    (let* ((result (finish-sha sha512))
           (quick-check-actual (first-n-octets 2 result)))
      (when (equalp quick-check-actual quick-check-expected)
        (let* ((n (vector-integer result))
               (pk (ldb (byte 512 0)
                        (expt-mod (signature-value signature)
                                  (e public-key)
                                  (n public-key)))))
          (when (= n pk)
            :good-signature))))))

;;;
;;; The actual bootstrapping work
;;;

(in-package #:quicklisp-quickstart)

(defvar *home*
  (merge-pathnames (make-pathname :directory '(:relative "quicklisp"))
                   (user-homedir-pathname)))

(defvar *release-public-key-file* *load-truename*)
(defvar *release-public-key* nil)

(defun release-public-key ()
  (if *release-public-key*
      *release-public-key*
      (setf *release-public-key*
            (load-public-key *release-public-key-file*))))

(defun qmerge (pathname)
  (merge-pathnames pathname *home*))

(defun openpgp-checked-fetch (url file)
  (let ((sig-url (format nil "~A.asc" url))
        (sig-file (qmerge "tmp/signature.txt"))
        (temp-file (qmerge "tmp/signed-data.dat")))
    (fetch sig-url sig-file)
    (fetch url temp-file)
    (let ((signature (load-signature sig-file)))
      (unless (verify-signature temp-file
                                signature
                                (release-public-key))
        (error "OpenPGP signature validation of ~A FAILED ~
                -- signature from ~A ~
                -- ~A" url sig-url signature))
      (rename-file temp-file file))))

(defun sha256-checked-fetch (url expected-sha256-string file)
  (let ((temp-file (qmerge "tmp/sha256-data.dat")))
    (fetch url temp-file)
    (let ((actual-sha256-string (file-sha-string 'sha256
                                                 temp-file)))
      (unless (equalp expected-sha256-string actual-sha256-string)
        (error "SHA256 checked fetch of ~A failed: ~%~
                Expected: ~S~%~
                Actual--: ~S"
               url
               expected-sha256-string
               actual-sha256-string))
      (rename-file temp-file file))))

(defvar *quickstart-parameters* nil
  "This plist is populated with parameters that may carry over to the
  initial configuration of the client, e.g. :proxy-url
  or :initial-dist-url")

(defvar *quicklisp-hostname* "beta.quicklisp.org")

(defvar *client-info-url*
  (format nil "http://~A/client/quicklisp.sexp"
          *quicklisp-hostname*))

(defclass client-info ()
  ((setup-url
    :reader setup-url
    :initarg :setup-url)
   (asdf-url
    :reader asdf-url
    :initarg :asdf-url)
   (client-tar-url
    :reader client-tar-url
    :initarg :client-tar-url)
   (version
    :reader version
    :initarg :version)
   (plist
    :reader plist
    :initarg :plist)
   (source-file
    :reader source-file
    :initarg :source-file)))

(defmethod print-object ((client-info client-info) stream)
  (print-unreadable-object (client-info stream :type t)
    (prin1 (version client-info) stream)))

(defun safely-read (stream)
  (let ((*read-eval* nil))
    (read stream)))

(defun fetch-client-info-plist (url)
  "Fetch and return the client info data at URL."
  (let ((local-client-info-file (qmerge "tmp/client-info.sexp")))
    (ensure-directories-exist local-client-info-file)
    (openpgp-checked-fetch url local-client-info-file)
    (with-open-file (stream local-client-info-file)
      (list* :source-file local-client-info-file
             (safely-read stream)))))

(defun fetch-client-info (url)
  (let ((plist (fetch-client-info-plist url)))
    (destructuring-bind (&key setup asdf client-tar version
                              source-file
                              &allow-other-keys)
        plist
      (unless (and setup asdf client-tar version)
        (error "Invalid data from client info URL -- ~A" url))
      (make-instance 'client-info
                     :setup-url (getf setup :url)
                     :asdf-url (getf asdf :url)
                     :client-tar-url (getf client-tar :url)
                     :version version
                     :plist plist
                     :source-file source-file))))

(defun client-info-url-from-version (version)
  (format nil "http://~A/client/~A/client-info.sexp"
          *quicklisp-hostname*
          version))

(defun distinfo-url-from-version (version)
  (format nil "http://~A/dist/quicklisp/~A/distinfo.txt"
          *quicklisp-hostname*
          version))

(defun client-info-sha256 (client-info type)
  (let* ((plist (plist client-info))
         (info (getf plist type)))
    (unless info
      (error "Unknown client info type ~S" type))
    (getf info :sha256)))

(defvar *help-message*
  (format nil "~&~%  ==== quicklisp quickstart install help ====~%~%    ~
               quicklisp-quickstart:install can take the following ~
               optional arguments:~%~%      ~
                 :path \"/path/to/installation/\"~%~%      ~
                 :proxy \"http://your.proxy:port/\"~%~%      ~
                 :client-url <url>~%~%      ~
                 :client-version <version>~%~%      ~
                 :dist-url <url>~%~%      ~
                 :dist-version <version>~%~%"))

(defvar *after-load-message*
  (format nil "~&~%  ==== quicklisp quickstart ~A loaded ====~%~%    ~
               To continue with installation, evaluate: (quicklisp-quickstart:install)~%~%    ~
               For installation options, evaluate: (quicklisp-quickstart:help)~%~%"
          qlqs-info:*version*))

(defvar *after-initial-setup-message*
  (with-output-to-string (*standard-output*)
    (format t "~&~%  ==== quicklisp installed ====~%~%")
    (format t "    To load a system, use: (ql:quickload \"system-name\")~%~%")
    (format t "    To find systems, use: (ql:system-apropos \"term\")~%~%")
    (format t "    To load Quicklisp every time you start Lisp, use: (ql:add-to-init-file)~%~%")
    (format t "    For more information, see http://www.quicklisp.org/beta/~%~%")))

(defvar *quickstart-public-key-file*
  *load-truename*)


(defun initial-install (&key (client-url *client-info-url*) dist-url)
  (setf *quickstart-parameters*
        (list :proxy-url *proxy-url*
              :initial-dist-url dist-url))
  (ensure-directories-exist (qmerge "tmp/"))
  (let ((client-info (fetch-client-info client-url))
        (tmptar (qmerge "tmp/quicklisp.tar"))
        (setup (qmerge "setup.lisp"))
        (asdf (qmerge "asdf.lisp")))
    (sha256-checked-fetch (client-tar-url client-info)
                          (client-info-sha256 client-info :client-tar)
                          tmptar)
    (unpack-tarball tmptar :directory (qmerge "./"))
    (sha256-checked-fetch (setup-url client-info)
                          (client-info-sha256 client-info :setup)
                          setup)
    (sha256-checked-fetch (asdf-url client-info)
                          (client-info-sha256 client-info :asdf)
                          asdf)
    (rename-file (source-file client-info) (qmerge "client-info.sexp"))
    (load setup :verbose nil :print nil)
    (write-string *after-initial-setup-message*)
    (finish-output)))

(defun help ()
  (write-string *help-message*)
  t)

(defun non-empty-file-namestring (pathname)
  (let ((string (file-namestring pathname)))
    (unless (or (null string)
                (equal string ""))
      string)))

(defun install (&key ((:path *home*) *home*)
                  ((:proxy *proxy-url*) *proxy-url*)
                  client-url
                  client-version
                  dist-url
                  dist-version)
  (setf *home* (merge-pathnames *home* (truename *default-pathname-defaults*)))
  (let ((name (non-empty-file-namestring *home*)))
    (when name
      (warn "Making ~A part of the install pathname directory"
            name)
      ;; This corrects a pathname like "/foo/bar" to "/foo/bar/" and
      ;; "foo" to "foo/"
      (setf *home*
            (make-pathname :defaults *home*
                           :directory (append (pathname-directory *home*)
                                              (list name))))))
  (let ((setup-file (qmerge "setup.lisp")))
    (when (probe-file setup-file)
      (multiple-value-bind (result proceed)
          (with-simple-restart (load-setup "Load ~S" setup-file)
            (error "Quicklisp has already been installed. Load ~S instead."
                   setup-file))
        (declare (ignore result))
        (when proceed
          (return-from install (load setup-file))))))
  (if (find-package '#:ql)
      (progn
        (write-line "!!! Quicklisp has already been set up. !!!")
        (write-string *after-initial-setup-message*)
        t)
      (call-with-quiet-compilation
       (lambda ()
         (let ((client-url (or client-url
                               (and client-version
                                    (client-info-url-from-version client-version))
                               *client-info-url*))
               ;; It's ok for dist-url to be nil; there's a default in
               ;; the client
               (dist-url (or dist-url
                             (and dist-version
                                  (distinfo-url-from-version dist-version)))))
           (initial-install :client-url client-url
                            :dist-url dist-url))))))

(write-string *after-load-message*)

;;; End of quicklisp.lisp
