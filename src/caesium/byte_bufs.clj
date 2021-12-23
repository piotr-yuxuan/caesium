(ns caesium.byte-bufs
  "Byte buffer utilities, like conversions and length."
  (:require [clj-commons.byte-streams :as bs])
  (:import (java.nio ByteBuffer)))

(def bytes= bs/bytes=)

(defn ^ByteBuffer ->indirect-byte-buf
  "Convert buffer to a [[ByteBuffer]].

  If the input is not a byte buffer already, will be converted to an
  indirect byte buffer. For example, a byte array will just be
  wrapped. If the input is already a byte buffer, return it
  unmodified, *even if it was a direct byte buffer*. (This might seem
  confusing, but is generally what callers of this API want.)"
  [x]
  (bs/convert x ByteBuffer {:direct? false}))

(defn ^ByteBuffer ->direct-byte-buf
  "Convert buffer to a [[ByteBuffer]].

  If the input is not a byte buffer already, will be converted to a
  direct byte buffer. For example, a byte array will be copied into a
  newly allocated direct byte buffer. If the input is already a byte
  buffer, return it unmodified, *even if it was an indirect byte
  buffer*. (This might seem confusing, but is generally what callers
  of this API want.)"
  [x]
  (bs/convert x ByteBuffer {:direct? true}))

(defn ^{:tag 'bytes} ->bytes
  [x]
  (bs/to-byte-array x))

(defn ^ByteBuffer alloc
  [n]
  (ByteBuffer/allocate n))

(defprotocol BufLen
  (^Long buflen [this]))

(extend (Class/forName "[B")
  BufLen
  {:buflen
   (fn [^bytes this]
     (long (alength this)))})

(extend-protocol BufLen
  ByteBuffer
  (buflen [this]
    (long (.remaining ^ByteBuffer this))))
