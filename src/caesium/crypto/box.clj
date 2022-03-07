(ns caesium.crypto.box
  "Bindings to the public key authenticated encryption scheme."
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb]))

(defn box-seal-to-buf!
  "Encrypts ptext into out with `crypto_box_seal` using given public key.

  All arguments must be `java.nio.ByteBuffer`.

  This function is only useful if you're managing your own output
  buffer, which includes in-place encryption. You probably
  want [[box-seal]]."
  [c m pk]
  (.crypto_box_seal b/sodium
                    c
                    m
                    (clojure.core/long
                      (caesium.byte-bufs/buflen m))
                    pk))

(defn box-seal-open-to-buf!
  "Decrypts ptext into out with `crypto_box_seal_open` using given
  public key and secret key.

  All arguments must be `java.nio.ByteBuffer`.

  This function is only useful if you're managing your own output
  buffer, which includes in-place decryption. You probably
  want [[box-seal-open]]."
  [m c pk sk]
  (let [res (b/call! seal-open m c plen pk sk)]
    (if (zero? res)
      m
      (throw (RuntimeException. "Ciphertext verification failed")))))

(defn box-seal
  "Encrypts ptext with `crypto_box_seal` using given public key.

  This creates the output ciphertext byte array for you, which is
  probably what you want. If you would like to manage the array
  yourself, or do in-place encryption, see [[box-seal-to-buf!]]."
  [ptext pk]
  (let [out (bb/alloc (+ (bb/buflen ptext) sealbytes))]
    (box-seal-to-buf!
      out
      (bb/->indirect-byte-buf ptext)
      (bb/->indirect-byte-buf pk))
    (bb/->bytes out)))

(defn box-seal-open
  "Decrypts ptext with `crypto_box_seal_open` using given public key, and
  secret key.

  This creates the output plaintext byte array for you, which is probably what
  you want. If you would like to manage the array yourself, or do in-place
  decryption, see [[box-seal-open-to-buf!]]."
  [ctext pk sk]
  (let [out (bb/alloc (- (bb/buflen ctext) sealbytes))]
    (box-seal-open-to-buf!
      out
      (bb/->indirect-byte-buf ctext)
      (bb/->indirect-byte-buf pk)
      (bb/->indirect-byte-buf sk))
    (bb/->bytes out)))

(defn anonymous-encrypt
  "Encrypt with `crypto_box_seal`.

  To encrypt, use the recipient's public key.

  This is an alias for [[box-seal]] with a different argument
  order. [[box-seal]] follows the same argument order as the libsodium
  function."
  [pk ptext]
  (box-seal ptext pk))

(defn anonymous-decrypt
  "Decrypt with `crypto_box_seal_open`.

  To decrypt, use the recipient's public key and recipient' secret
  key.

  This is an alias for [[box-seal-open]] with a different argument
  order. [[box-seal-open]] follows the same argument order as the
  libsodium function."
  [pk sk ctext]
  (box-seal-open ctext pk sk))
