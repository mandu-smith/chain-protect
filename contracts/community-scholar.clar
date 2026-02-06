;; title: ChainProtect
;; version:
;; summary:
;; description:

;; traits
;;

;; Define error codes
(define-constant ERR-NOT-AUTHORIZED (err u1000))
(define-constant ERR-INVALID-HASH-LENGTH (err u1001))
(define-constant ERR-HASH-ALL-ZEROS (err u1002))
(define-constant ERR-HASH-ALREADY-REGISTERED (err u1003))
(define-constant ERR-IP-NOT-FOUND (err u1004))
(define-constant ERR-INVALID-IP-ID (err u1005))
(define-constant ERR-IP-ID-OUT-OF-RANGE (err u1006))
(define-constant ERR-IP-EXPIRED (err u1007))
(define-constant ERR-INVALID-EXPIRATION (err u1008))
(define-constant ERR-NO-EXPIRATION-SET (err u1009))

;; Define the contract
(define-data-var owner principal tx-sender)

;; Define a map to store IP registrations
(define-map ip-registrations
  { ip-id: uint }
  {
    owner: principal,
    timestamp: uint,
    hash: (buff 32),
    expiration: (optional uint),
  }
)

;; Define a map to track registered hashes
(define-map registered-hashes
  { hash: (buff 32) }
  { ip-id: uint }
)