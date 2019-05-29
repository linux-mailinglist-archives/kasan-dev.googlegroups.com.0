Return-Path: <kasan-dev+bncBC7OBJGL2MHBB45LXLTQKGQEKXCWEPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc37.google.com (mail-yw1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id F216B2DFA1
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 16:23:48 +0200 (CEST)
Received: by mail-yw1-xc37.google.com with SMTP id p13sf2232221ywm.20
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 07:23:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559139828; cv=pass;
        d=google.com; s=arc-20160816;
        b=CMOC0OcS6h7KfttEQ+4ohGudOMJs5xe/2cAcq/0aQQCO+BXM/RFHeSkponKBGWexCe
         AzVNMrdvhgFWu8CM8NpmIbahsn55t7W2OSGUGfJtdqvmZcD+4iqd1jkw7KShugzHI1ct
         BLDbL8bcHGZ4TCSAJQW+9hRWIs2Ehd4tFRAHxyT9+aWQUHTpZQf8A5V+1NbuS3YSiSyz
         x1kyXtwr99gatjlxrU5WrZp+2quiILVR6tAQTpXlyVeo6cmmspogoE2ikR4tV5mIVde2
         FPUE0Tz6HuHihQOHWvWkSywz+vcZwcSo2dNagCtOnfzzbmT0eYBjBxHZVfe+EFdnuLtw
         HKYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=5XGQ7ILplIlCym81BGuXMMD7uQJGhh2Zbr11Yv7yPOU=;
        b=mFpAO+YIJGci82BMGC8lOwo8q/4A/5ybRLkj6rCKMg3sEsthOsQ88xaHnY7S2W/9kL
         j/OztykSYgpqU/u52Xomd8gLDVcXDFkS3tVUMSemPUCF+qFTzn9SQiS3tUdThe3bDaCj
         JCNcuAlPdGw5/00C34c3/xUQTryFv7cR0n81u+/fcu2ByO+BlDC15PWvvDsQuAgrz5d3
         uSBveVahgWpqmZU+5kKNrlXSBwZL7C4znZxwb2ERqHUeqjqxu9H3l3J3XJCqkIyzMjSe
         YDhJp4Q5GL/SC4OwU3m182zqWEtGm0R5v9rsQNCPhrnZ3Ixw0fiTrBi3ZhVwFCi4r7Ng
         uK4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=In93pZSG;
       spf=pass (google.com: domain of 385xuxaukccyqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::c49 as permitted sender) smtp.mailfrom=385XuXAUKCcYqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5XGQ7ILplIlCym81BGuXMMD7uQJGhh2Zbr11Yv7yPOU=;
        b=PrrIMQCq8FFpvwFNhH/tJKi6KnqA7qqWfVGDjLVZkSXVZILmsSV2RWZKZUq0eki+h/
         DVj11T2TZIdZveFefyw4L21cCJb7hlHhLjo7hRdgzkEU+4IRPilywZXlH/Kv9SNC2O6B
         EAGB6j0iYWb6bORhuYvRHZKlB9AY3EzNDagibSSLQqNEPTMKBAyybAegoanf6DJWSGSv
         Bs2Wx7ZDjLrydjjL1NSrFcKY3vrWIWPjuT5Hy1aK/spPWq9tsCNZC7LER08gCNIF+esT
         4uXp25gHqhtQvNZHhSM+68nwES7hsXsWMvkWV//Y/f2FO1uo+9mj2Lh7n1Y1UA8NEWQS
         ieEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5XGQ7ILplIlCym81BGuXMMD7uQJGhh2Zbr11Yv7yPOU=;
        b=F0tVgtZLiyzIEwoBGcC0KQxKWzP/o4NS5l2XjO/5oK+IWxEkbUkKc1GXvvvQeU5EaI
         PrRDCFk2RpeFUfgDz+nxuGH07Ol7YAizwkaugqWNqb78uq43Ldaa1MgAo+fBZtvGJuEH
         431RojVF6VG5mwqtNGGy86SaLvwPSIj6IXxAuVX0j/vFvfzkmMa/7C8fVEJjS+XEutWR
         jppEaS1G4tya3b4PltaKeB/EntypTWyQV9MwBOuQdw+EVIdhwRzZARTH0zTds/DCR7+f
         Q/EiOsVpqhciKrOL9fi7RqHQTc7U1qlj9ewZZgBN6ximzFtzfAz7XDHJvIGsRHu1XUom
         Of2w==
X-Gm-Message-State: APjAAAXyb6Ls/zOkN+Qp+XBjSrj/NKqK3lpSvsFowtn1tj3PEwgW6oI9
	K/deFesiFk0slMpyaIwv4FE=
X-Google-Smtp-Source: APXvYqwmrKG7+/GOAkYwVZ8461c4UajMrWkspo+z1u/9vLj2O5HLkoCcejN6kyvt/VZiimBo66OAeQ==
X-Received: by 2002:a5b:ec2:: with SMTP id a2mr10247527ybs.402.1559139828000;
        Wed, 29 May 2019 07:23:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:384:: with SMTP id 126ls244609ybd.1.gmail; Wed, 29 May
 2019 07:23:47 -0700 (PDT)
X-Received: by 2002:a25:7902:: with SMTP id u2mr9390275ybc.36.1559139827713;
        Wed, 29 May 2019 07:23:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559139827; cv=none;
        d=google.com; s=arc-20160816;
        b=rt9PzVUBNigxR016DNTpZP6NeN4zllN232+KohIdeV64S0BWrmbjpUfx7CuvlF8sr0
         KkZH8NFh9gIqOTpSLJZpScKh6HoJ6viTZEsox9KpSFSboF/fhmFKO8J8x8qz5hBYdCEj
         x//D+Nm03Z+YxLjMkhTSpkdoZSiMreGzMTxOvtSs3gZaMF+dwldrsa+lb94d9UDsRFoC
         embEL1U13ZKfNv7qRPJoVQDhhiOlQfImSNTQjyqKmXADgaLzde3jZ4Uju92Tp4k9LgRj
         zAqJEjzdy9WXaWuQu0ezf3Oyfi77gyIagCjbCSiq+wO29YHJK/eZ0Jo+MpLw65dNbRjn
         5wNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=VsfX0Vngnu+bLyWJxnLCfxl9j79fcyn/7gCV2ifA24k=;
        b=0zdsWydhlR6tfVjOjwQsMgMDfZ0/oK/Ac2LHfgMguUDk40UMsnpXnopCsos3q2Quse
         V3aSbAs1MFIWfR1Ca7sUNwC10hynt7hi0jTy+q+iuA2hJBstN2kUHMAGHC9NMiTEXhLl
         8dNNIHLodDJMjg6IxYKox7qCkeBbdvNuAqbL9X3Kj1X06CFh6xRWsKZiG6Nii4wOn/Ec
         U1a7MwzkSWvOB2mnYBv8fa0RjDT88dR3l3RKY3TMvIGADZinw5zQW6o1o+chZ4OqKMT8
         BJJyM+KoewIr/WewZhTQUBpWKG/Ym9o8K7Ob4U9DfUqA8XgEwXFQuVc4rwQmX1NPBFnK
         Vv+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=In93pZSG;
       spf=pass (google.com: domain of 385xuxaukccyqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::c49 as permitted sender) smtp.mailfrom=385XuXAUKCcYqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-xc49.google.com (mail-yw1-xc49.google.com. [2607:f8b0:4864:20::c49])
        by gmr-mx.google.com with ESMTPS id w81si491770yww.3.2019.05.29.07.23.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 07:23:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 385xuxaukccyqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::c49 as permitted sender) client-ip=2607:f8b0:4864:20::c49;
Received: by mail-yw1-xc49.google.com with SMTP id b189so2228846ywa.19
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2019 07:23:47 -0700 (PDT)
X-Received: by 2002:a25:1484:: with SMTP id 126mr58518877ybu.61.1559139827384;
 Wed, 29 May 2019 07:23:47 -0700 (PDT)
Date: Wed, 29 May 2019 16:15:01 +0200
In-Reply-To: <20190529141500.193390-1-elver@google.com>
Message-Id: <20190529141500.193390-4-elver@google.com>
Mime-Version: 1.0
References: <20190529141500.193390-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.rc1.257.g3120a18244-goog
Subject: [PATCH v2 3/3] asm-generic, x86: Add bitops instrumentation for KASAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, mark.rutland@arm.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	hpa@zytor.com, x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=In93pZSG;       spf=pass
 (google.com: domain of 385xuxaukccyqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::c49 as permitted sender) smtp.mailfrom=385XuXAUKCcYqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

This adds a new header to asm-generic to allow optionally instrumenting
architecture-specific asm implementations of bitops.

This change includes the required change for x86 as reference and
changes the kernel API doc to point to bitops-instrumented.h instead.
Rationale: the functions in x86's bitops.h are no longer the kernel API
functions, but instead the arch_ prefixed functions, which are then
instrumented via bitops-instrumented.h.

Other architectures can similarly add support for asm implementations of
bitops.

The documentation text has been copied/moved, and *no* changes to it
have been made in this patch.

Tested: using lib/test_kasan with bitops tests (pre-requisite patch).

Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=198439
Signed-off-by: Marco Elver <elver@google.com>
---
Changes in v2:
* Instrument word-sized accesses, as specified by the interface.
---
 Documentation/core-api/kernel-api.rst     |   2 +-
 arch/x86/include/asm/bitops.h             | 210 ++++----------
 include/asm-generic/bitops-instrumented.h | 317 ++++++++++++++++++++++
 3 files changed, 370 insertions(+), 159 deletions(-)
 create mode 100644 include/asm-generic/bitops-instrumented.h

diff --git a/Documentation/core-api/kernel-api.rst b/Documentation/core-api/kernel-api.rst
index a29c99d13331..65266fa1b706 100644
--- a/Documentation/core-api/kernel-api.rst
+++ b/Documentation/core-api/kernel-api.rst
@@ -51,7 +51,7 @@ The Linux kernel provides more basic utility functions.
 Bit Operations
 --------------
 
-.. kernel-doc:: arch/x86/include/asm/bitops.h
+.. kernel-doc:: include/asm-generic/bitops-instrumented.h
    :internal:
 
 Bitmap Operations
diff --git a/arch/x86/include/asm/bitops.h b/arch/x86/include/asm/bitops.h
index 8e790ec219a5..8ebf7af9a0f4 100644
--- a/arch/x86/include/asm/bitops.h
+++ b/arch/x86/include/asm/bitops.h
@@ -49,23 +49,8 @@
 #define CONST_MASK_ADDR(nr, addr)	WBYTE_ADDR((void *)(addr) + ((nr)>>3))
 #define CONST_MASK(nr)			(1 << ((nr) & 7))
 
-/**
- * set_bit - Atomically set a bit in memory
- * @nr: the bit to set
- * @addr: the address to start counting from
- *
- * This function is atomic and may not be reordered.  See __set_bit()
- * if you do not require the atomic guarantees.
- *
- * Note: there are no guarantees that this function will not be reordered
- * on non x86 architectures, so if you are writing portable code,
- * make sure not to rely on its reordering guarantees.
- *
- * Note that @nr may be almost arbitrarily large; this function is not
- * restricted to acting on a single-word quantity.
- */
 static __always_inline void
-set_bit(long nr, volatile unsigned long *addr)
+arch_set_bit(long nr, volatile unsigned long *addr)
 {
 	if (IS_IMMEDIATE(nr)) {
 		asm volatile(LOCK_PREFIX "orb %1,%0"
@@ -77,33 +62,17 @@ set_bit(long nr, volatile unsigned long *addr)
 			: : RLONG_ADDR(addr), "Ir" (nr) : "memory");
 	}
 }
+#define arch_set_bit arch_set_bit
 
-/**
- * __set_bit - Set a bit in memory
- * @nr: the bit to set
- * @addr: the address to start counting from
- *
- * Unlike set_bit(), this function is non-atomic and may be reordered.
- * If it's called on the same region of memory simultaneously, the effect
- * may be that only one operation succeeds.
- */
-static __always_inline void __set_bit(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch___set_bit(long nr, volatile unsigned long *addr)
 {
 	asm volatile(__ASM_SIZE(bts) " %1,%0" : : ADDR, "Ir" (nr) : "memory");
 }
+#define arch___set_bit arch___set_bit
 
-/**
- * clear_bit - Clears a bit in memory
- * @nr: Bit to clear
- * @addr: Address to start counting from
- *
- * clear_bit() is atomic and may not be reordered.  However, it does
- * not contain a memory barrier, so if it is used for locking purposes,
- * you should call smp_mb__before_atomic() and/or smp_mb__after_atomic()
- * in order to ensure changes are visible on other processors.
- */
 static __always_inline void
-clear_bit(long nr, volatile unsigned long *addr)
+arch_clear_bit(long nr, volatile unsigned long *addr)
 {
 	if (IS_IMMEDIATE(nr)) {
 		asm volatile(LOCK_PREFIX "andb %1,%0"
@@ -114,27 +83,25 @@ clear_bit(long nr, volatile unsigned long *addr)
 			: : RLONG_ADDR(addr), "Ir" (nr) : "memory");
 	}
 }
+#define arch_clear_bit arch_clear_bit
 
-/*
- * clear_bit_unlock - Clears a bit in memory
- * @nr: Bit to clear
- * @addr: Address to start counting from
- *
- * clear_bit() is atomic and implies release semantics before the memory
- * operation. It can be used for an unlock.
- */
-static __always_inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch_clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
 	barrier();
-	clear_bit(nr, addr);
+	arch_clear_bit(nr, addr);
 }
+#define arch_clear_bit_unlock arch_clear_bit_unlock
 
-static __always_inline void __clear_bit(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch___clear_bit(long nr, volatile unsigned long *addr)
 {
 	asm volatile(__ASM_SIZE(btr) " %1,%0" : : ADDR, "Ir" (nr) : "memory");
 }
+#define arch___clear_bit arch___clear_bit
 
-static __always_inline bool clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch_clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
 {
 	bool negative;
 	asm volatile(LOCK_PREFIX "andb %2,%1"
@@ -143,48 +110,25 @@ static __always_inline bool clear_bit_unlock_is_negative_byte(long nr, volatile
 		: "ir" ((char) ~(1 << nr)) : "memory");
 	return negative;
 }
+#define arch_clear_bit_unlock_is_negative_byte                                 \
+	arch_clear_bit_unlock_is_negative_byte
 
-// Let everybody know we have it
-#define clear_bit_unlock_is_negative_byte clear_bit_unlock_is_negative_byte
-
-/*
- * __clear_bit_unlock - Clears a bit in memory
- * @nr: Bit to clear
- * @addr: Address to start counting from
- *
- * __clear_bit() is non-atomic and implies release semantics before the memory
- * operation. It can be used for an unlock if no other CPUs can concurrently
- * modify other bits in the word.
- */
-static __always_inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch___clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
-	__clear_bit(nr, addr);
+	arch___clear_bit(nr, addr);
 }
+#define arch___clear_bit_unlock arch___clear_bit_unlock
 
-/**
- * __change_bit - Toggle a bit in memory
- * @nr: the bit to change
- * @addr: the address to start counting from
- *
- * Unlike change_bit(), this function is non-atomic and may be reordered.
- * If it's called on the same region of memory simultaneously, the effect
- * may be that only one operation succeeds.
- */
-static __always_inline void __change_bit(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch___change_bit(long nr, volatile unsigned long *addr)
 {
 	asm volatile(__ASM_SIZE(btc) " %1,%0" : : ADDR, "Ir" (nr) : "memory");
 }
+#define arch___change_bit arch___change_bit
 
-/**
- * change_bit - Toggle a bit in memory
- * @nr: Bit to change
- * @addr: Address to start counting from
- *
- * change_bit() is atomic and may not be reordered.
- * Note that @nr may be almost arbitrarily large; this function is not
- * restricted to acting on a single-word quantity.
- */
-static __always_inline void change_bit(long nr, volatile unsigned long *addr)
+static __always_inline void
+arch_change_bit(long nr, volatile unsigned long *addr)
 {
 	if (IS_IMMEDIATE(nr)) {
 		asm volatile(LOCK_PREFIX "xorb %1,%0"
@@ -195,43 +139,24 @@ static __always_inline void change_bit(long nr, volatile unsigned long *addr)
 			: : RLONG_ADDR(addr), "Ir" (nr) : "memory");
 	}
 }
+#define arch_change_bit arch_change_bit
 
-/**
- * test_and_set_bit - Set a bit and return its old value
- * @nr: Bit to set
- * @addr: Address to count from
- *
- * This operation is atomic and cannot be reordered.
- * It also implies a memory barrier.
- */
-static __always_inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch_test_and_set_bit(long nr, volatile unsigned long *addr)
 {
 	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(bts), *addr, c, "Ir", nr);
 }
+#define arch_test_and_set_bit arch_test_and_set_bit
 
-/**
- * test_and_set_bit_lock - Set a bit and return its old value for lock
- * @nr: Bit to set
- * @addr: Address to count from
- *
- * This is the same as test_and_set_bit on x86.
- */
 static __always_inline bool
-test_and_set_bit_lock(long nr, volatile unsigned long *addr)
+arch_test_and_set_bit_lock(long nr, volatile unsigned long *addr)
 {
-	return test_and_set_bit(nr, addr);
+	return arch_test_and_set_bit(nr, addr);
 }
+#define arch_test_and_set_bit_lock arch_test_and_set_bit_lock
 
-/**
- * __test_and_set_bit - Set a bit and return its old value
- * @nr: Bit to set
- * @addr: Address to count from
- *
- * This operation is non-atomic and can be reordered.
- * If two examples of this operation race, one can appear to succeed
- * but actually fail.  You must protect multiple accesses with a lock.
- */
-static __always_inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch___test_and_set_bit(long nr, volatile unsigned long *addr)
 {
 	bool oldbit;
 
@@ -241,37 +166,17 @@ static __always_inline bool __test_and_set_bit(long nr, volatile unsigned long *
 	    : ADDR, "Ir" (nr) : "memory");
 	return oldbit;
 }
+#define arch___test_and_set_bit arch___test_and_set_bit
 
-/**
- * test_and_clear_bit - Clear a bit and return its old value
- * @nr: Bit to clear
- * @addr: Address to count from
- *
- * This operation is atomic and cannot be reordered.
- * It also implies a memory barrier.
- */
-static __always_inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch_test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
 	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(btr), *addr, c, "Ir", nr);
 }
+#define arch_test_and_clear_bit arch_test_and_clear_bit
 
-/**
- * __test_and_clear_bit - Clear a bit and return its old value
- * @nr: Bit to clear
- * @addr: Address to count from
- *
- * This operation is non-atomic and can be reordered.
- * If two examples of this operation race, one can appear to succeed
- * but actually fail.  You must protect multiple accesses with a lock.
- *
- * Note: the operation is performed atomically with respect to
- * the local CPU, but not other CPUs. Portable code should not
- * rely on this behaviour.
- * KVM relies on this behaviour on x86 for modifying memory that is also
- * accessed from a hypervisor on the same CPU if running in a VM: don't change
- * this without also updating arch/x86/kernel/kvm.c
- */
-static __always_inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch___test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
 	bool oldbit;
 
@@ -281,9 +186,10 @@ static __always_inline bool __test_and_clear_bit(long nr, volatile unsigned long
 		     : ADDR, "Ir" (nr) : "memory");
 	return oldbit;
 }
+#define arch___test_and_clear_bit arch___test_and_clear_bit
 
-/* WARNING: non atomic and it can be reordered! */
-static __always_inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch___test_and_change_bit(long nr, volatile unsigned long *addr)
 {
 	bool oldbit;
 
@@ -294,19 +200,14 @@ static __always_inline bool __test_and_change_bit(long nr, volatile unsigned lon
 
 	return oldbit;
 }
+#define arch___test_and_change_bit arch___test_and_change_bit
 
-/**
- * test_and_change_bit - Change a bit and return its old value
- * @nr: Bit to change
- * @addr: Address to count from
- *
- * This operation is atomic and cannot be reordered.
- * It also implies a memory barrier.
- */
-static __always_inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
+static __always_inline bool
+arch_test_and_change_bit(long nr, volatile unsigned long *addr)
 {
 	return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(btc), *addr, c, "Ir", nr);
 }
+#define arch_test_and_change_bit arch_test_and_change_bit
 
 static __always_inline bool constant_test_bit(long nr, const volatile unsigned long *addr)
 {
@@ -326,16 +227,7 @@ static __always_inline bool variable_test_bit(long nr, volatile const unsigned l
 	return oldbit;
 }
 
-#if 0 /* Fool kernel-doc since it doesn't do macros yet */
-/**
- * test_bit - Determine whether a bit is set
- * @nr: bit number to test
- * @addr: Address to start counting from
- */
-static bool test_bit(int nr, const volatile unsigned long *addr);
-#endif
-
-#define test_bit(nr, addr)			\
+#define arch_test_bit(nr, addr)			\
 	(__builtin_constant_p((nr))		\
 	 ? constant_test_bit((nr), (addr))	\
 	 : variable_test_bit((nr), (addr)))
@@ -504,6 +396,8 @@ static __always_inline int fls64(__u64 x)
 
 #include <asm-generic/bitops/const_hweight.h>
 
+#include <asm-generic/bitops-instrumented.h>
+
 #include <asm-generic/bitops/le.h>
 
 #include <asm-generic/bitops/ext2-atomic-setbit.h>
diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-generic/bitops-instrumented.h
new file mode 100644
index 000000000000..b01b0dd93964
--- /dev/null
+++ b/include/asm-generic/bitops-instrumented.h
@@ -0,0 +1,317 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+/*
+ * This file provides wrappers with sanitizer instrumentation for bit
+ * operations.
+ *
+ * To use this functionality, an arch's bitops.h file needs to define each of
+ * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
+ * arch___set_bit(), etc.), #define each provided arch_ function, and include
+ * this file after their definitions. For undefined arch_ functions, it is
+ * assumed that they are provided via asm-generic/bitops, which are implicitly
+ * instrumented.
+ */
+#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_H
+#define _ASM_GENERIC_BITOPS_INSTRUMENTED_H
+
+#include <linux/kasan-checks.h>
+
+#if defined(arch_set_bit)
+/**
+ * set_bit - Atomically set a bit in memory
+ * @nr: the bit to set
+ * @addr: the address to start counting from
+ *
+ * This function is atomic and may not be reordered.  See __set_bit()
+ * if you do not require the atomic guarantees.
+ *
+ * Note: there are no guarantees that this function will not be reordered
+ * on non x86 architectures, so if you are writing portable code,
+ * make sure not to rely on its reordering guarantees.
+ *
+ * Note that @nr may be almost arbitrarily large; this function is not
+ * restricted to acting on a single-word quantity.
+ */
+static inline void set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch_set_bit(nr, addr);
+}
+#endif
+
+#if defined(arch___set_bit)
+/**
+ * __set_bit - Set a bit in memory
+ * @nr: the bit to set
+ * @addr: the address to start counting from
+ *
+ * Unlike set_bit(), this function is non-atomic and may be reordered.
+ * If it's called on the same region of memory simultaneously, the effect
+ * may be that only one operation succeeds.
+ */
+static inline void __set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___set_bit(nr, addr);
+}
+#endif
+
+#if defined(arch_clear_bit)
+/**
+ * clear_bit - Clears a bit in memory
+ * @nr: Bit to clear
+ * @addr: Address to start counting from
+ *
+ * clear_bit() is atomic and may not be reordered.  However, it does
+ * not contain a memory barrier, so if it is used for locking purposes,
+ * you should call smp_mb__before_atomic() and/or smp_mb__after_atomic()
+ * in order to ensure changes are visible on other processors.
+ */
+static inline void clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch_clear_bit(nr, addr);
+}
+#endif
+
+#if defined(arch___clear_bit)
+/**
+ * __clear_bit - Clears a bit in memory
+ * @nr: the bit to clear
+ * @addr: the address to start counting from
+ *
+ * Unlike clear_bit(), this function is non-atomic and may be reordered.
+ * If it's called on the same region of memory simultaneously, the effect
+ * may be that only one operation succeeds.
+ */
+static inline void __clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___clear_bit(nr, addr);
+}
+#endif
+
+#if defined(arch_clear_bit_unlock)
+/**
+ * clear_bit_unlock - Clears a bit in memory
+ * @nr: Bit to clear
+ * @addr: Address to start counting from
+ *
+ * clear_bit_unlock() is atomic and implies release semantics before the memory
+ * operation. It can be used for an unlock.
+ */
+static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch_clear_bit_unlock(nr, addr);
+}
+#endif
+
+#if defined(arch___clear_bit_unlock)
+/**
+ * __clear_bit_unlock - Clears a bit in memory
+ * @nr: Bit to clear
+ * @addr: Address to start counting from
+ *
+ * __clear_bit_unlock() is non-atomic and implies release semantics before the
+ * memory operation. It can be used for an unlock if no other CPUs can
+ * concurrently modify other bits in the word.
+ */
+static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___clear_bit_unlock(nr, addr);
+}
+#endif
+
+#if defined(arch_change_bit)
+/**
+ * change_bit - Toggle a bit in memory
+ * @nr: Bit to change
+ * @addr: Address to start counting from
+ *
+ * change_bit() is atomic and may not be reordered.
+ * Note that @nr may be almost arbitrarily large; this function is not
+ * restricted to acting on a single-word quantity.
+ */
+static inline void change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch_change_bit(nr, addr);
+}
+#endif
+
+#if defined(arch___change_bit)
+/**
+ * __change_bit - Toggle a bit in memory
+ * @nr: the bit to change
+ * @addr: the address to start counting from
+ *
+ * Unlike change_bit(), this function is non-atomic and may be reordered.
+ * If it's called on the same region of memory simultaneously, the effect
+ * may be that only one operation succeeds.
+ */
+static inline void __change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	arch___change_bit(nr, addr);
+}
+#endif
+
+#if defined(arch_test_and_set_bit)
+/**
+ * test_and_set_bit - Set a bit and return its old value
+ * @nr: Bit to set
+ * @addr: Address to count from
+ *
+ * This operation is atomic and cannot be reordered.
+ * It also implies a memory barrier.
+ */
+static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_and_set_bit(nr, addr);
+}
+#endif
+
+#if defined(arch___test_and_set_bit)
+/**
+ * __test_and_set_bit - Set a bit and return its old value
+ * @nr: Bit to set
+ * @addr: Address to count from
+ *
+ * This operation is non-atomic and can be reordered.
+ * If two examples of this operation race, one can appear to succeed
+ * but actually fail.  You must protect multiple accesses with a lock.
+ */
+static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch___test_and_set_bit(nr, addr);
+}
+#endif
+
+#if defined(arch_test_and_set_bit_lock)
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
+#endif
+
+#if defined(arch_test_and_clear_bit)
+/**
+ * test_and_clear_bit - Clear a bit and return its old value
+ * @nr: Bit to clear
+ * @addr: Address to count from
+ *
+ * This operation is atomic and cannot be reordered.
+ * It also implies a memory barrier.
+ */
+static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_and_clear_bit(nr, addr);
+}
+#endif
+
+#if defined(arch___test_and_clear_bit)
+/**
+ * __test_and_clear_bit - Clear a bit and return its old value
+ * @nr: Bit to clear
+ * @addr: Address to count from
+ *
+ * This operation is non-atomic and can be reordered.
+ * If two examples of this operation race, one can appear to succeed
+ * but actually fail.  You must protect multiple accesses with a lock.
+ *
+ * Note: the operation is performed atomically with respect to
+ * the local CPU, but not other CPUs. Portable code should not
+ * rely on this behaviour.
+ * KVM relies on this behaviour on x86 for modifying memory that is also
+ * accessed from a hypervisor on the same CPU if running in a VM: don't change
+ * this without also updating arch/x86/kernel/kvm.c
+ */
+static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch___test_and_clear_bit(nr, addr);
+}
+#endif
+
+#if defined(arch_test_and_change_bit)
+/**
+ * test_and_change_bit - Change a bit and return its old value
+ * @nr: Bit to change
+ * @addr: Address to count from
+ *
+ * This operation is atomic and cannot be reordered.
+ * It also implies a memory barrier.
+ */
+static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch_test_and_change_bit(nr, addr);
+}
+#endif
+
+#if defined(arch___test_and_change_bit)
+/**
+ * __test_and_change_bit - Change a bit and return its old value
+ * @nr: Bit to change
+ * @addr: Address to count from
+ *
+ * This operation is non-atomic and can be reordered.
+ * If two examples of this operation race, one can appear to succeed
+ * but actually fail.  You must protect multiple accesses with a lock.
+ */
+static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
+{
+	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	return arch___test_and_change_bit(nr, addr);
+}
+#endif
+
+#if defined(arch_test_bit)
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
+#endif
+
+#if defined(arch_clear_bit_unlock_is_negative_byte)
+/**
+ * clear_bit_unlock_is_negative_byte - Clear a bit in memory and test if bottom
+ *                                     byte is negative, for unlock.
+ * @nr: the bit to clear
+ * @addr: the address to start counting from
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
+#endif /* _ASM_GENERIC_BITOPS_INSTRUMENTED_H */
-- 
2.22.0.rc1.257.g3120a18244-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190529141500.193390-4-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
