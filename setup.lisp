(defpackage #:ql-setup
  (:use #:cl)
  (:export #:*quicklisp-home*
           #:qmerge
           #:qenough))

(in-package #:ql-setup)

(unless *load-truename*
  (error "This file must be LOADed to set up quicklisp."))

(defvar *quicklisp-home*
  (pathname (directory-namestring *load-truename*)))

(defun qmerge (pathname)
  (merge-pathnames pathname *quicklisp-home*))

(defun qenough (pathname)
  (enough-namestring pathname *quicklisp-home*))

(defun file-date< (file1 file2)
  (and (probe-file file1)
       (probe-file file2)
       (< (file-write-date file1)
          (file-write-date file2))))

;;; ASDF is a hard requirement of quicklisp. Make sure it's either
;;; already loaded or load it from quicklisp's bundled version.

(defvar *required-asdf-version* "2.010")

(defun ensure-asdf-loaded ()
  (let* ((source (qmerge "asdf.lisp"))
         (fasl (compile-file-pathname source)))
    (labels ((asdf-symbol (name)
               (let ((asdf-package (find-package '#:asdf)))
                 (when asdf-package
                   (find-symbol (string name) asdf-package))))
             (version-satisfies (version)
               (let ((vs-fun (asdf-symbol '#:version-satisfies))
                     (vfun (asdf-symbol '#:asdf-version)))
                 (when (and vs-fun vfun
                            (fboundp vs-fun)
                            (fboundp vfun))
                   (funcall vs-fun (funcall vfun) version)))))
      (block nil
        (macrolet ((try (&body asdf-loading-forms)
                     `(progn
                        (handler-bind ((warning #'muffle-warning))
                          (ignore-errors
                            ,@asdf-loading-forms))
                        (when (version-satisfies *required-asdf-version*)
                          (return t)))))
          (try)
          (try (require 'asdf))
          (try (load fasl :verbose nil))
          (try (load (compile-file source :verbose nil)))
          (error "Could not load ASDF ~S or newer" *required-asdf-version*))))))

(ensure-asdf-loaded)

;;;
;;; Quicklisp sometimes must upgrade ASDF. Ugrading ASDF will blow
;;; away existing ASDF methods, so e.g. FASL recompilation :around
;;; methods would be lost. This config file will make it possible to
;;; ensure ASDF can be configured before loading Quicklisp itself via
;;; ASDF. Thanks to Nikodemus Siivola for pointing out this issue.
;;;

(let ((asdf-init (probe-file (qmerge "asdf-config/init.lisp"))))
  (when asdf-init
    (with-simple-restart (skip "Skip loading ~S" asdf-init)
      (load asdf-init :verbose nil :print nil))))

(push (qmerge "quicklisp/") asdf:*central-registry*)

(let ((*compile-print* nil)
      (*compile-verbose* nil)
      (*load-verbose* nil)
      (*load-print* nil))
  (asdf:oos 'asdf:load-op "quicklisp" :verbose nil))

(quicklisp:setup)
