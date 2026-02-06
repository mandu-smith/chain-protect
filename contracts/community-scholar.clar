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

;; Define a counter for IP IDs
(define-data-var ip-counter uint u0)

;; Function to register new IP
(define-public (register-ip
    (ip-hash (buff 32))
    (expiration-block (optional uint))
  )
  (let (
      (new-id (+ (var-get ip-counter) u1))
      (current-block stacks-block-height)
    )
    ;; Perform input validation
    ;; Perform input validation
    (asserts! (is-eq (len ip-hash) u32) ERR-INVALID-HASH-LENGTH)
    (asserts!
      (not (is-eq ip-hash
        0x0000000000000000000000000000000000000000000000000000000000000000
      ))
      ERR-HASH-ALL-ZEROS
    )
    (asserts! (is-none (map-get? registered-hashes { hash: ip-hash }))
      ERR-HASH-ALREADY-REGISTERED
    )
    ;; Check expiration validity
    (asserts!
      (match expiration-block
        expiration (> expiration current-block)
        true
      )
      ERR-INVALID-EXPIRATION
    )
    ;; Register the IP
    (map-set ip-registrations { ip-id: new-id } {
      owner: tx-sender,
      timestamp: current-block,
      hash: ip-hash,
      expiration: expiration-block,
    })
    ;; Track the registered hash
    (map-set registered-hashes { hash: ip-hash } { ip-id: new-id })
    (var-set ip-counter new-id)
    (ok new-id)
  )
)