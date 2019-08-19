Return-Path: <kasan-dev+bncBDQ27FVWWUFRBBMD5HVAKGQEAZU6Z4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id CEE6691D09
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 08:28:22 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id l17sf2752837qtk.16
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Aug 2019 23:28:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566196102; cv=pass;
        d=google.com; s=arc-20160816;
        b=NW1FonVSN2kI3luwv8YcWmoR2x3H/arptXKrCbq5KPs/O+X46Opwi2a79t9NbV/dQ/
         GyvSPAlp6eYd91B6LbDQvTfRm4g7QBlOLlZdR13AvmwEJIPdIp1RzcChgWfKTc8WTNpo
         l6oLU2v8uQcnZ4IZsu1ixN9SFPj30g4Y5HpnRzDxt00NR8+kG7vqHkGRlp87StsPrbQF
         YC6W8IMIV2WLLCkZDkNMUd9e8olac7k5ts5gVRTX9f+UCBtEltYf/PenaT9jZpyjr2uA
         8PAzkq0NbS9cTGvVoz1CsM0C+/wajzln4UD2+TRRrsurMPK/ov2aS/mwzvhXKDRryApE
         ZeBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=JQIqmzaYuHAO4kid3MCOo3RH8rPwLlDQDMueR/BNpcM=;
        b=StqhFCM9DZpLwuzp6Ad3Mte8eafKAkTn6IgDEri4AV/LLd2M9Eepl+gECDPGrQ+PsX
         EFSD+ESXAHbZGERaHeKYq62k47WLKKPLDr11qMh2a+P6SO4tkME5XgxSj1x599sIZJWR
         7d1TrZ5Wrsh110hZJXLR1HTa8cKcw35Uh0iWYM0Ea9oACWv7/rzBeCSXgU3/MJvY1RRU
         kRcsGgIR7QNCn8RGAjg/T55ilV4fffaO5j5Ly06DC8WCW6q2IwSoNKJ3nRZ+9eMUrq4m
         6egtACvTMOS3JWHUltdhNwNk8U/6UtMDAfE0lcEbeOrb4pgYVhVwWimbWN9xLVdlYSWU
         T6Ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=XDJIYUfq;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JQIqmzaYuHAO4kid3MCOo3RH8rPwLlDQDMueR/BNpcM=;
        b=PZZXGbOYg6qMLnkZDuLgufHHYRugxTPJADUXRfMaajA9dAPztdtJcDgMShAX2ywLNO
         rSFBNR44rb4KTOhbQKMDJ7jWe6X6YQQqPf+Kat9fyvvL5olvmzVGnQAqpySbMOgMSGPD
         tSul1LjqdzdVhXjEY56W0C2I57nNvjae5An3J5Gb8aWXS+Xq9NMWITC8KnMHyKaUKdwy
         EQKIWmZSErkcMv9odxhLGq7LwhjngGWDxm+F/dKIs3O5o0ROzTQcEcyx+0qUK1uMfTTk
         xiz78dHCv3IMh6Ga+2nOGJf8GgUlFZN8QpeqyTmWimPQEGSKr+Q+1puP3tS3qbkvHNuQ
         keoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JQIqmzaYuHAO4kid3MCOo3RH8rPwLlDQDMueR/BNpcM=;
        b=plYrmeW4M+jpw0kr5BQk7070N8UVkmjslkDsUNs0qWr8Gf9DgvnCkNqpGvYxvNdWKE
         ZAMav6O7kcP4FDzSCQFF4NQYeK6w+/W6jeEEowKJW3VYK1+0jwv7NzNbJK4cVSuzz5zw
         yFHNTo/pyk7bFk462M8B4mgmKbr4QfGsFkHg6D6rcB5CMo0XKkW/pb2PJEjDRPmy2TR7
         PeU/oNwHjxz43Q4jMqhFsFRx0UpggDKeD+3ZV1T2vir7N9Wuc6gIlqKTUfZXZYVkvBdR
         XxwDLNn6NSKrB4eyuEKhvJjxvW+H+WDWmgpjmkoFgL5/AKkxp6W2ghyzrjhrg6Fxgm1C
         PILQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXx2tX4lbLEK4NLOHfHkjU5fB955X1xRqB+qWROuY3lfGhG0z9G
	2KeiEPUcl0Xn9SXz0DuzeaQ=
X-Google-Smtp-Source: APXvYqyE3IDDvFmCaEoVOFKwW8OVnVXlixQ+xgSrek/RVwWGRIvEyMtZ17jRLpO0/IXB05wBPR+U0A==
X-Received: by 2002:ae9:f441:: with SMTP id z1mr19164061qkl.211.1566196101848;
        Sun, 18 Aug 2019 23:28:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:15f6:: with SMTP id p22ls4061501qkm.8.gmail; Sun,
 18 Aug 2019 23:28:21 -0700 (PDT)
X-Received: by 2002:a37:61d4:: with SMTP id v203mr19261898qkb.458.1566196101522;
        Sun, 18 Aug 2019 23:28:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566196101; cv=none;
        d=google.com; s=arc-20160816;
        b=fqU1vA1ZLcGlFEIA3FYHgiwjAfOiNCn6sWsgMWmm9lZcTdKNu2ildCGhpuTxO6iAjv
         fCg1gdjdI0SpdBAfV5ZJhTgUhjuOo7/QDBi+osz9MFvIZJF4OaEQwRsmM79VjhBKGdy4
         phLKK3hsub5iztkpVdUG4PpCd4Zul0L+CUXHMgI4EjEm61ZlOCP3zSYYm6QBodsgDk25
         PlS4buFF++Naq9wRU922XO0zFGcC384630p/Bms35bpkxtc88gbE+c2BkRk0f2HyooHG
         v76r2HjqxyLJkeFrTIlK9IzES2cNn18z2WtUuliIOQqZcY80uinFePH55ocnCojCamVg
         A6VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=2QchgQKPhfgnzyJjz7DvkZyOhG/B9Buywq3Uf73BFlU=;
        b=OqJ/wPuUqQwBZwM5PfCgeWg5a5aDfZc2sb9ZRUeUYnNlEBtNgZSXgoriV2yggy6bAu
         OdstOtu+pWXIzlpRT51Xssz27X/nKXvol+Yfd72D0FoGPlkbkgzuklcZQUEox3zOGkrM
         TKLgsblm0UD0p7CzguWRdZAgMGQ8xZvJGIycyONsvT1k6a45ugIkvYHfmwJd8L6+8Ni/
         //oHfGfLJNe7h/Dt4Xn14+ybXeEHz9CENA9bKexwX54K9k/lBJLLFV0Z5LqqCx6sxjz3
         2zncwXmOItAonfl9vova+XQwhoEykIYIfequwL7S8nbXWKY4uheAKmS5yiMTkGIzIv0h
         oJiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=XDJIYUfq;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id p24si793272qtq.5.2019.08.18.23.28.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 18 Aug 2019 23:28:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id 196so559163pfz.8
        for <kasan-dev@googlegroups.com>; Sun, 18 Aug 2019 23:28:21 -0700 (PDT)
X-Received: by 2002:a62:7641:: with SMTP id r62mr21713543pfc.201.1566196100186;
        Sun, 18 Aug 2019 23:28:20 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id z19sm12879234pgv.35.2019.08.18.23.28.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 18 Aug 2019 23:28:19 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: christophe.leroy@c-s.fr,
	linux-s390@vger.kernel.org,
	linux-arch@vger.kernel.org,
	x86@kernel.org,
	linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH 1/2] kasan: support instrumented bitops combined with generic bitops
Date: Mon, 19 Aug 2019 16:28:13 +1000
Message-Id: <20190819062814.5315-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=XDJIYUfq;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Currently bitops-instrumented.h assumes that the architecture provides
atomic, non-atomic and locking bitops (e.g. both set_bit and __set_bit).
This is true on x86 and s390, but is not always true: there is a
generic bitops/non-atomic.h header that provides generic non-atomic
operations, and also a generic bitops/lock.h for locking operations.

powerpc uses the generic non-atomic version, so it does not have it's
own e.g. __set_bit that could be renamed arch___set_bit.

Split up bitops-instrumented.h to mirror the atomic/non-atomic/lock
split. This allows arches to only include the headers where they
have arch-specific versions to rename. Update x86 and s390.

(The generic operations are automatically instrumented because they're
written in C, not asm.)

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 Documentation/core-api/kernel-api.rst         |  17 +-
 arch/s390/include/asm/bitops.h                |   4 +-
 arch/x86/include/asm/bitops.h                 |   4 +-
 include/asm-generic/bitops-instrumented.h     | 263 ------------------
 .../asm-generic/bitops/instrumented-atomic.h  | 100 +++++++
 .../asm-generic/bitops/instrumented-lock.h    |  81 ++++++
 .../bitops/instrumented-non-atomic.h          | 114 ++++++++
 7 files changed, 317 insertions(+), 266 deletions(-)
 delete mode 100644 include/asm-generic/bitops-instrumented.h
 create mode 100644 include/asm-generic/bitops/instrumented-atomic.h
 create mode 100644 include/asm-generic/bitops/instrumented-lock.h
 create mode 100644 include/asm-generic/bitops/instrumented-non-atomic.h

diff --git a/Documentation/core-api/kernel-api.rst b/Documentation/core-api/kernel-api.rst
index 08af5caf036d..2e21248277e3 100644
--- a/Documentation/core-api/kernel-api.rst
+++ b/Documentation/core-api/kernel-api.rst
@@ -54,7 +54,22 @@ The Linux kernel provides more basic utility functions.
 Bit Operations
 --------------
 
-.. kernel-doc:: include/asm-generic/bitops-instrumented.h
+Atomic Operations
+~~~~~~~~~~~~~~~~~
+
+.. kernel-doc:: include/asm-generic/bitops/instrumented-atomic.h
+   :internal:
+
+Non-atomic Operations
+~~~~~~~~~~~~~~~~~~~~~
+
+.. kernel-doc:: include/asm-generic/bitops/instrumented-non-atomic.h
+   :internal:
+
+Locking Operations
+~~~~~~~~~~~~~~~~~~
+
+.. kernel-doc:: include/asm-generic/bitops/instrumented-lock.h
    :internal:
 
 Bitmap Operations
diff --git a/arch/s390/include/asm/bitops.h b/arch/s390/include/asm/bitops.h
index b8833ac983fa..0ceb12593a68 100644
--- a/arch/s390/include/asm/bitops.h
+++ b/arch/s390/include/asm/bitops.h
@@ -241,7 +241,9 @@ static inline void arch___clear_bit_unlock(unsigned long nr,
 	arch___clear_bit(nr, ptr);
 }
 
-#include <asm-generic/bitops-instrumented.h>
+#include <asm-generic/bitops/instrumented-atomic.h>
+#include <asm-generic/bitops/instrumented-non-atomic.h>
+#include <asm-generic/bitops/instrumented-lock.h>
 
 /*
  * Functions which use MSB0 bit numbering.
diff --git a/arch/x86/include/asm/bitops.h b/arch/x86/include/asm/bitops.h
index ba15d53c1ca7..4a2e2432238f 100644
--- a/arch/x86/include/asm/bitops.h
+++ b/arch/x86/include/asm/bitops.h
@@ -389,7 +389,9 @@ static __always_inline int fls64(__u64 x)
 
 #include <asm-generic/bitops/const_hweight.h>
 
-#include <asm-generic/bitops-instrumented.h>
+#include <asm-generic/bitops/instrumented-atomic.h>
+#include <asm-generic/bitops/instrumented-non-atomic.h>
+#include <asm-generic/bitops/instrumented-lock.h>
 
 #include <asm-generic/bitops/le.h>
 
diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-generic/bitops-instrumented.h
deleted file mode 100644
index ddd1c6d9d8db..000000000000
--- a/include/asm-generic/bitops-instrumented.h
+++ /dev/null
@@ -1,263 +0,0 @@
-/* SPDX-License-Identifier: GPL-2.0 */
-
-/*
- * This file provides wrappers with sanitizer instrumentation for bit
- * operations.
- *
- * To use this functionality, an arch's bitops.h file needs to define each of
- * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
- * arch___set_bit(), etc.).
- */
-#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_H
-#define _ASM_GENERIC_BITOPS_INSTRUMENTED_H
-
-#include <linux/kasan-checks.h>
-
-/**
- * set_bit - Atomically set a bit in memory
- * @nr: the bit to set
- * @addr: the address to start counting from
- *
- * This is a relaxed atomic operation (no implied memory barriers).
- *
- * Note that @nr may be almost arbitrarily large; this function is not
- * restricted to acting on a single-word quantity.
- */
-static inline void set_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch_set_bit(nr, addr);
-}
-
-/**
- * __set_bit - Set a bit in memory
- * @nr: the bit to set
- * @addr: the address to start counting from
- *
- * Unlike set_bit(), this function is non-atomic. If it is called on the same
- * region of memory concurrently, the effect may be that only one operation
- * succeeds.
- */
-static inline void __set_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch___set_bit(nr, addr);
-}
-
-/**
- * clear_bit - Clears a bit in memory
- * @nr: Bit to clear
- * @addr: Address to start counting from
- *
- * This is a relaxed atomic operation (no implied memory barriers).
- */
-static inline void clear_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch_clear_bit(nr, addr);
-}
-
-/**
- * __clear_bit - Clears a bit in memory
- * @nr: the bit to clear
- * @addr: the address to start counting from
- *
- * Unlike clear_bit(), this function is non-atomic. If it is called on the same
- * region of memory concurrently, the effect may be that only one operation
- * succeeds.
- */
-static inline void __clear_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch___clear_bit(nr, addr);
-}
-
-/**
- * clear_bit_unlock - Clear a bit in memory, for unlock
- * @nr: the bit to set
- * @addr: the address to start counting from
- *
- * This operation is atomic and provides release barrier semantics.
- */
-static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch_clear_bit_unlock(nr, addr);
-}
-
-/**
- * __clear_bit_unlock - Clears a bit in memory
- * @nr: Bit to clear
- * @addr: Address to start counting from
- *
- * This is a non-atomic operation but implies a release barrier before the
- * memory operation. It can be used for an unlock if no other CPUs can
- * concurrently modify other bits in the word.
- */
-static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch___clear_bit_unlock(nr, addr);
-}
-
-/**
- * change_bit - Toggle a bit in memory
- * @nr: Bit to change
- * @addr: Address to start counting from
- *
- * This is a relaxed atomic operation (no implied memory barriers).
- *
- * Note that @nr may be almost arbitrarily large; this function is not
- * restricted to acting on a single-word quantity.
- */
-static inline void change_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch_change_bit(nr, addr);
-}
-
-/**
- * __change_bit - Toggle a bit in memory
- * @nr: the bit to change
- * @addr: the address to start counting from
- *
- * Unlike change_bit(), this function is non-atomic. If it is called on the same
- * region of memory concurrently, the effect may be that only one operation
- * succeeds.
- */
-static inline void __change_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	arch___change_bit(nr, addr);
-}
-
-/**
- * test_and_set_bit - Set a bit and return its old value
- * @nr: Bit to set
- * @addr: Address to count from
- *
- * This is an atomic fully-ordered operation (implied full memory barrier).
- */
-static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch_test_and_set_bit(nr, addr);
-}
-
-/**
- * __test_and_set_bit - Set a bit and return its old value
- * @nr: Bit to set
- * @addr: Address to count from
- *
- * This operation is non-atomic. If two instances of this operation race, one
- * can appear to succeed but actually fail.
- */
-static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch___test_and_set_bit(nr, addr);
-}
-
-/**
- * test_and_set_bit_lock - Set a bit and return its old value, for lock
- * @nr: Bit to set
- * @addr: Address to count from
- *
- * This operation is atomic and provides acquire barrier semantics if
- * the returned value is 0.
- * It can be used to implement bit locks.
- */
-static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch_test_and_set_bit_lock(nr, addr);
-}
-
-/**
- * test_and_clear_bit - Clear a bit and return its old value
- * @nr: Bit to clear
- * @addr: Address to count from
- *
- * This is an atomic fully-ordered operation (implied full memory barrier).
- */
-static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch_test_and_clear_bit(nr, addr);
-}
-
-/**
- * __test_and_clear_bit - Clear a bit and return its old value
- * @nr: Bit to clear
- * @addr: Address to count from
- *
- * This operation is non-atomic. If two instances of this operation race, one
- * can appear to succeed but actually fail.
- */
-static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch___test_and_clear_bit(nr, addr);
-}
-
-/**
- * test_and_change_bit - Change a bit and return its old value
- * @nr: Bit to change
- * @addr: Address to count from
- *
- * This is an atomic fully-ordered operation (implied full memory barrier).
- */
-static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch_test_and_change_bit(nr, addr);
-}
-
-/**
- * __test_and_change_bit - Change a bit and return its old value
- * @nr: Bit to change
- * @addr: Address to count from
- *
- * This operation is non-atomic. If two instances of this operation race, one
- * can appear to succeed but actually fail.
- */
-static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch___test_and_change_bit(nr, addr);
-}
-
-/**
- * test_bit - Determine whether a bit is set
- * @nr: bit number to test
- * @addr: Address to start counting from
- */
-static inline bool test_bit(long nr, const volatile unsigned long *addr)
-{
-	kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
-	return arch_test_bit(nr, addr);
-}
-
-#if defined(arch_clear_bit_unlock_is_negative_byte)
-/**
- * clear_bit_unlock_is_negative_byte - Clear a bit in memory and test if bottom
- *                                     byte is negative, for unlock.
- * @nr: the bit to clear
- * @addr: the address to start counting from
- *
- * This operation is atomic and provides release barrier semantics.
- *
- * This is a bit of a one-trick-pony for the filemap code, which clears
- * PG_locked and tests PG_waiters,
- */
-static inline bool
-clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
-{
-	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
-	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
-}
-/* Let everybody know we have it. */
-#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_byte
-#endif
-
-#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_H */
diff --git a/include/asm-generic/bitops/instrumented-atomic.h b/include/asm-generic/bitops/instrumented-atomic.h
new file mode 100644
index 000000000000..18ce3c9e8eec
--- /dev/null
+++ b/include/asm-generic/bitops/instrumented-atomic.h
@@ -0,0 +1,100 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+/*
+ * This file provides wrappers with sanitizer instrumentation for atomic bit
+ * operations.
+ *
+ * To use this functionality, an arch's bitops.h file needs to define each of
+ * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
+ * arch___set_bit(), etc.).
+ */
+#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_ATOMIC_H
+#define _ASM_GENERIC_BITOPS_INSTRUMENTED_ATOMIC_H
+
+#include <linux/kasan-checks.h>
+
+/**
+ * set_bit - Atomically set a bit in memory
+ * @nr: the bit to set
+ * @addr: the address to start counting from
+ *
+ * This is a relaxed atomic operation (no implied memory barriers).
+ *
+ * Note that @nr may be almost arbitrarily large; this function is not
+ * restricted to acting on a single-word quantity.
+ */
+static inline void set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch_set_bit(nr, addr);
+}
+
+/**
+ * clear_bit - Clears a bit in memory
+ * @nr: Bit to clear
+ * @addr: Address to start counting from
+ *
+ * This is a relaxed atomic operation (no implied memory barriers).
+ */
+static inline void clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch_clear_bit(nr, addr);
+}
+
+/**
+ * change_bit - Toggle a bit in memory
+ * @nr: Bit to change
+ * @addr: Address to start counting from
+ *
+ * This is a relaxed atomic operation (no implied memory barriers).
+ *
+ * Note that @nr may be almost arbitrarily large; this function is not
+ * restricted to acting on a single-word quantity.
+ */
+static inline void change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch_change_bit(nr, addr);
+}
+
+/**
+ * test_and_set_bit - Set a bit and return its old value
+ * @nr: Bit to set
+ * @addr: Address to count from
+ *
+ * This is an atomic fully-ordered operation (implied full memory barrier).
+ */
+static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_and_set_bit(nr, addr);
+}
+
+/**
+ * test_and_clear_bit - Clear a bit and return its old value
+ * @nr: Bit to clear
+ * @addr: Address to count from
+ *
+ * This is an atomic fully-ordered operation (implied full memory barrier).
+ */
+static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_and_clear_bit(nr, addr);
+}
+
+/**
+ * test_and_change_bit - Change a bit and return its old value
+ * @nr: Bit to change
+ * @addr: Address to count from
+ *
+ * This is an atomic fully-ordered operation (implied full memory barrier).
+ */
+static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_and_change_bit(nr, addr);
+}
+
+#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H */
diff --git a/include/asm-generic/bitops/instrumented-lock.h b/include/asm-generic/bitops/instrumented-lock.h
new file mode 100644
index 000000000000..ec53fdeea9ec
--- /dev/null
+++ b/include/asm-generic/bitops/instrumented-lock.h
@@ -0,0 +1,81 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+/*
+ * This file provides wrappers with sanitizer instrumentation for bit
+ * locking operations.
+ *
+ * To use this functionality, an arch's bitops.h file needs to define each of
+ * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
+ * arch___set_bit(), etc.).
+ */
+#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H
+#define _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H
+
+#include <linux/kasan-checks.h>
+
+/**
+ * clear_bit_unlock - Clear a bit in memory, for unlock
+ * @nr: the bit to set
+ * @addr: the address to start counting from
+ *
+ * This operation is atomic and provides release barrier semantics.
+ */
+static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch_clear_bit_unlock(nr, addr);
+}
+
+/**
+ * __clear_bit_unlock - Clears a bit in memory
+ * @nr: Bit to clear
+ * @addr: Address to start counting from
+ *
+ * This is a non-atomic operation but implies a release barrier before the
+ * memory operation. It can be used for an unlock if no other CPUs can
+ * concurrently modify other bits in the word.
+ */
+static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___clear_bit_unlock(nr, addr);
+}
+
+/**
+ * test_and_set_bit_lock - Set a bit and return its old value, for lock
+ * @nr: Bit to set
+ * @addr: Address to count from
+ *
+ * This operation is atomic and provides acquire barrier semantics if
+ * the returned value is 0.
+ * It can be used to implement bit locks.
+ */
+static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_and_set_bit_lock(nr, addr);
+}
+
+#if defined(arch_clear_bit_unlock_is_negative_byte)
+/**
+ * clear_bit_unlock_is_negative_byte - Clear a bit in memory and test if bottom
+ *                                     byte is negative, for unlock.
+ * @nr: the bit to clear
+ * @addr: the address to start counting from
+ *
+ * This operation is atomic and provides release barrier semantics.
+ *
+ * This is a bit of a one-trick-pony for the filemap code, which clears
+ * PG_locked and tests PG_waiters,
+ */
+static inline bool
+clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
+}
+/* Let everybody know we have it. */
+#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_byte
+#endif
+
+#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H */
diff --git a/include/asm-generic/bitops/instrumented-non-atomic.h b/include/asm-generic/bitops/instrumented-non-atomic.h
new file mode 100644
index 000000000000..95ff28d128a1
--- /dev/null
+++ b/include/asm-generic/bitops/instrumented-non-atomic.h
@@ -0,0 +1,114 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+/*
+ * This file provides wrappers with sanitizer instrumentation for non-atomic
+ * bit operations.
+ *
+ * To use this functionality, an arch's bitops.h file needs to define each of
+ * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
+ * arch___set_bit(), etc.).
+ */
+#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H
+#define _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H
+
+#include <linux/kasan-checks.h>
+
+/**
+ * __set_bit - Set a bit in memory
+ * @nr: the bit to set
+ * @addr: the address to start counting from
+ *
+ * Unlike set_bit(), this function is non-atomic. If it is called on the same
+ * region of memory concurrently, the effect may be that only one operation
+ * succeeds.
+ */
+static inline void __set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___set_bit(nr, addr);
+}
+
+/**
+ * __clear_bit - Clears a bit in memory
+ * @nr: the bit to clear
+ * @addr: the address to start counting from
+ *
+ * Unlike clear_bit(), this function is non-atomic. If it is called on the same
+ * region of memory concurrently, the effect may be that only one operation
+ * succeeds.
+ */
+static inline void __clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___clear_bit(nr, addr);
+}
+
+/**
+ * __change_bit - Toggle a bit in memory
+ * @nr: the bit to change
+ * @addr: the address to start counting from
+ *
+ * Unlike change_bit(), this function is non-atomic. If it is called on the same
+ * region of memory concurrently, the effect may be that only one operation
+ * succeeds.
+ */
+static inline void __change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___change_bit(nr, addr);
+}
+
+/**
+ * __test_and_set_bit - Set a bit and return its old value
+ * @nr: Bit to set
+ * @addr: Address to count from
+ *
+ * This operation is non-atomic. If two instances of this operation race, one
+ * can appear to succeed but actually fail.
+ */
+static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch___test_and_set_bit(nr, addr);
+}
+
+/**
+ * __test_and_clear_bit - Clear a bit and return its old value
+ * @nr: Bit to clear
+ * @addr: Address to count from
+ *
+ * This operation is non-atomic. If two instances of this operation race, one
+ * can appear to succeed but actually fail.
+ */
+static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch___test_and_clear_bit(nr, addr);
+}
+
+/**
+ * __test_and_change_bit - Change a bit and return its old value
+ * @nr: Bit to change
+ * @addr: Address to count from
+ *
+ * This operation is non-atomic. If two instances of this operation race, one
+ * can appear to succeed but actually fail.
+ */
+static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch___test_and_change_bit(nr, addr);
+}
+
+/**
+ * test_bit - Determine whether a bit is set
+ * @nr: bit number to test
+ * @addr: Address to start counting from
+ */
+static inline bool test_bit(long nr, const volatile unsigned long *addr)
+{
+	kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_bit(nr, addr);
+}
+
+#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H */
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190819062814.5315-1-dja%40axtens.net.
