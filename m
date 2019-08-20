Return-Path: <kasan-dev+bncBDQ27FVWWUFRBZN75XVAKGQE5QTU5MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E9129549D
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2019 04:50:14 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id m4sf3861539ybp.22
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 19:50:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566269413; cv=pass;
        d=google.com; s=arc-20160816;
        b=qFB/uR5ju1z5Av62yupBt9OKRZABHY1Yg7SIArlSBbRRgLV5WpVxTRIDSByzBp+QDs
         yv7XTGvp2LrA6hNjnqUMrpJD7uV8qwPCr4nrx1nGPox6IAXHigiY0cI+kjf/THEZB7Ef
         g/uADR8OXvecM+G+5gvYLzlnQvG3IiXtZa+xO1tRsJ/DXFfclQ45EHgAt9FRRbwvsvTz
         9DLFuNFWLA7VskWwm18xBeTqnFX+9v7E99UlKNDWjNF6nQeUp29CruisMSp4hxhxW2yz
         UVx5czqyEdELNPT5HCbOmSYfsifweyjMkiKcDLfkUVEmgrHq7Nm2ZF3YeA5wGh9fTy9B
         7Ujg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=iE9VpKiPdxVEnHK6HD8LZDI/wnEgHfRPTDHucofnk8s=;
        b=UYZP491oh76QOOEDjtX1uTkx9bdQPMBx/ZbEnxDyw65MxHiiO9LjmtvRQeQKfgEsn7
         LA+OEMAqFPeFkqRPoAwkq/KpbFdSslFQtf3S7qNkwgLJFERRAt9F+zjFezDckR2FXd0O
         MNi5ChKOMzWEJAODgidiXoT+xKwLTlHOgaVfbiZ+PW1tqRTQSV7sM4eYiIQnoctgU2K3
         JioN1mFofIUntNiDMpakx+UFDKSgx+UXFhpRoqoGCBKNx76o4NlyDQnqAF0rYDZb/vr3
         W0O8IZK+YokmUY8auIVPtY6DDd5jUTWdX/BOhPBMINDZqpnc/bp2GmMdRHDzCw8V/88H
         bTtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=PsibIzx5;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iE9VpKiPdxVEnHK6HD8LZDI/wnEgHfRPTDHucofnk8s=;
        b=NAQG9EgNbJUtXiPMavlbAHsk9QT+5JEEAfI5xu4R8H/35VtdVH5IR2eIFGh9UjusA4
         GrzlWckx2VWwG/xG6V2R2S0vnpgJWcI2xtjW23Rm7bRkLZ4sp0VKsZy+JuY9V2rQIKpL
         4M5aIZdyhbva2Xnne7gG4d2Tp7fTMKRQm5na1GkqXDIgHK/9KVBc3ZyyN/l+YzEVJuez
         7fXSC461YjEYIRTqeav/m1SXcDThuQFBi8YDhw3Kv4VgT1cTk3oLFxKwOWPjDwOwNiFy
         RyHvleVflayepIJDtdfYa9BEc+GpRavUzsGf0qLzsPU+Wax8cuWTcfPLgjstOYCoUbgP
         LQNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iE9VpKiPdxVEnHK6HD8LZDI/wnEgHfRPTDHucofnk8s=;
        b=Y7prB1EmsSHTwsASaX1LsHEVzUhKR2X6bRpQyqzHXn6o33+AULW7lerHW4h/WjFMUT
         UmhvYN6qC0d8eejlL8r0mbwUhPuV7VzODhdbYlsyUE2BV3y3gqzGYA6DKWVv4m7CZAYk
         8Ml2pkMqZSkFseaOJuPYzplAbRoE//zw38ddDD+nn4mqjHjyh2lLRJ2PHbgEzEZQsIig
         l1R0fQE3TBuw30O70oZosfKWJUZW+rXuRSgfot/NOyPhciFqXY6a7sLv8AYhxO7vXQGU
         8GM+8VAHCJKPMqIDd4z+UosQj6vXIqbiu/U3uhFx8/AkRtHgZcsUje7cK8F3/bi3+xZf
         ZDlQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVmX+kVmozqFDAhCAdHmf0LWBVNj4qjppzF+OS1YvXSqjcrF5I4
	ducz28NW7QOkt+5L4VxDFkE=
X-Google-Smtp-Source: APXvYqxswO4HDMLl8xVb/HC5vxyutIy80+0xW3Km2Mza8SA4EvDSBu3FgIrviZfgdRqn6r9u+ZZU8w==
X-Received: by 2002:a5b:5cd:: with SMTP id w13mr19646505ybp.138.1566269413276;
        Mon, 19 Aug 2019 19:50:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:210a:: with SMTP id h10ls2878189ybh.5.gmail; Mon, 19 Aug
 2019 19:50:13 -0700 (PDT)
X-Received: by 2002:a25:d44b:: with SMTP id m72mr19162173ybf.372.1566269413007;
        Mon, 19 Aug 2019 19:50:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566269413; cv=none;
        d=google.com; s=arc-20160816;
        b=vTMpoAtff3Vb9amYbyr71PiICahO0YFZZ0YF7qNRAMFGINcFMbNSLew9whFcOxubiG
         7dnAcAlH2hQMPLBc+h6lsb/KMJQhqqg/9Hneoz39rdWBJVuE2GSAg1nsxTXeYsO8CoWW
         CSLCW6w1AArKpDRh8Q2qCJqPey2/bCpSe6iXIBbNHPhtVrdGUfpctOSdjI0ExbCDVuUK
         jYPlCsXQPg4mBlSGY8ex+gOfpAi0vETgcNNnj7Xcfd9WYvSw51sBOUzY8uvNf+WrCf3i
         B1BCKEXKIJnwFqw5JlGEQeqREPGpJskZQ0A9KkSwCjLXMqILcVgv+Qj5LF334LcynbUC
         JxSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+Ljr2InsBtzDAS9Drpe0kzrEUQvzHekKKA+vOfzzLGA=;
        b=uVfn0M1GM260h/1u+YSkR8qgnCcMCI6VyGF+0M2lQFyhGV4+mwL7PPUEgVOopjvd/n
         j/3NX6z+EC2DQP1U4rA3GGOqHt3aKaSJSHQCaWn/En4OkIvN7SWgf2uYRQhOLgISGalQ
         ckcE/20cYyFZq0GnJVRlQVlAq+y5ijgPSV52F7tutO/PF5kPV7JB01zL4Johs2BzSr8Z
         iDO9pN7QapJs30z8TjHSrYsLILt/1AQdwKA+U3gRnmI3/eANBaDBNOLZctRzukfZe9/X
         Z9U5bC5tNeW1GSlGoEt4A6jhTOYtdWjXhlAhlA17KgvynfzymCeLWoRV3TIsNUnuetYy
         pi0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=PsibIzx5;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id r130si776623ywe.5.2019.08.19.19.50.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Aug 2019 19:50:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id d3so1948267plr.1
        for <kasan-dev@googlegroups.com>; Mon, 19 Aug 2019 19:50:12 -0700 (PDT)
X-Received: by 2002:a17:902:e2:: with SMTP id a89mr26250902pla.210.1566269411763;
        Mon, 19 Aug 2019 19:50:11 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id v15sm18777348pfn.69.2019.08.19.19.50.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Aug 2019 19:50:11 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: christophe.leroy@c-s.fr,
	linux-s390@vger.kernel.org,
	linux-arch@vger.kernel.org,
	x86@kernel.org,
	linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>,
	Nicholas Piggin <npiggin@gmail.com>
Subject: [PATCH v2 2/2] powerpc: support KASAN instrumentation of bitops
Date: Tue, 20 Aug 2019 12:49:41 +1000
Message-Id: <20190820024941.12640-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190820024941.12640-1-dja@axtens.net>
References: <20190820024941.12640-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=PsibIzx5;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as
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

The powerpc-specific bitops are not being picked up by the KASAN
test suite.

Instrumentation is done via the bitops/instrumented-{atomic,lock}.h
headers. They require that arch-specific versions of bitop functions
are renamed to arch_*. Do this renaming.

For clear_bit_unlock_is_negative_byte, the current implementation
uses the PG_waiters constant. This works because it's a preprocessor
macro - so it's only actually evaluated in contexts where PG_waiters
is defined. With instrumentation however, it becomes a static inline
function, and all of a sudden we need the actual value of PG_waiters.
Because of the order of header includes, it's not available and we
fail to compile. Instead, manually specify that we care about bit 7.
This is still correct: bit 7 is the bit that would mark a negative
byte.

While we're at it, replace __inline__ with inline across the file.

Cc: Nicholas Piggin <npiggin@gmail.com> # clear_bit_unlock_negative_byte
Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>

--
v2: Address Christophe review
---
 arch/powerpc/include/asm/bitops.h | 51 ++++++++++++++++++-------------
 1 file changed, 29 insertions(+), 22 deletions(-)

diff --git a/arch/powerpc/include/asm/bitops.h b/arch/powerpc/include/asm/bitops.h
index 603aed229af7..28dcf8222943 100644
--- a/arch/powerpc/include/asm/bitops.h
+++ b/arch/powerpc/include/asm/bitops.h
@@ -64,7 +64,7 @@
 
 /* Macro for generating the ***_bits() functions */
 #define DEFINE_BITOP(fn, op, prefix)		\
-static __inline__ void fn(unsigned long mask,	\
+static inline void fn(unsigned long mask,	\
 		volatile unsigned long *_p)	\
 {						\
 	unsigned long old;			\
@@ -86,22 +86,22 @@ DEFINE_BITOP(clear_bits, andc, "")
 DEFINE_BITOP(clear_bits_unlock, andc, PPC_RELEASE_BARRIER)
 DEFINE_BITOP(change_bits, xor, "")
 
-static __inline__ void set_bit(int nr, volatile unsigned long *addr)
+static inline void arch_set_bit(int nr, volatile unsigned long *addr)
 {
 	set_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
 }
 
-static __inline__ void clear_bit(int nr, volatile unsigned long *addr)
+static inline void arch_clear_bit(int nr, volatile unsigned long *addr)
 {
 	clear_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
 }
 
-static __inline__ void clear_bit_unlock(int nr, volatile unsigned long *addr)
+static inline void arch_clear_bit_unlock(int nr, volatile unsigned long *addr)
 {
 	clear_bits_unlock(BIT_MASK(nr), addr + BIT_WORD(nr));
 }
 
-static __inline__ void change_bit(int nr, volatile unsigned long *addr)
+static inline void arch_change_bit(int nr, volatile unsigned long *addr)
 {
 	change_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
 }
@@ -109,7 +109,7 @@ static __inline__ void change_bit(int nr, volatile unsigned long *addr)
 /* Like DEFINE_BITOP(), with changes to the arguments to 'op' and the output
  * operands. */
 #define DEFINE_TESTOP(fn, op, prefix, postfix, eh)	\
-static __inline__ unsigned long fn(			\
+static inline unsigned long fn(			\
 		unsigned long mask,			\
 		volatile unsigned long *_p)		\
 {							\
@@ -138,34 +138,34 @@ DEFINE_TESTOP(test_and_clear_bits, andc, PPC_ATOMIC_ENTRY_BARRIER,
 DEFINE_TESTOP(test_and_change_bits, xor, PPC_ATOMIC_ENTRY_BARRIER,
 	      PPC_ATOMIC_EXIT_BARRIER, 0)
 
-static __inline__ int test_and_set_bit(unsigned long nr,
-				       volatile unsigned long *addr)
+static inline int arch_test_and_set_bit(unsigned long nr,
+					volatile unsigned long *addr)
 {
 	return test_and_set_bits(BIT_MASK(nr), addr + BIT_WORD(nr)) != 0;
 }
 
-static __inline__ int test_and_set_bit_lock(unsigned long nr,
-				       volatile unsigned long *addr)
+static inline int arch_test_and_set_bit_lock(unsigned long nr,
+					     volatile unsigned long *addr)
 {
 	return test_and_set_bits_lock(BIT_MASK(nr),
 				addr + BIT_WORD(nr)) != 0;
 }
 
-static __inline__ int test_and_clear_bit(unsigned long nr,
-					 volatile unsigned long *addr)
+static inline int arch_test_and_clear_bit(unsigned long nr,
+					  volatile unsigned long *addr)
 {
 	return test_and_clear_bits(BIT_MASK(nr), addr + BIT_WORD(nr)) != 0;
 }
 
-static __inline__ int test_and_change_bit(unsigned long nr,
-					  volatile unsigned long *addr)
+static inline int arch_test_and_change_bit(unsigned long nr,
+					   volatile unsigned long *addr)
 {
 	return test_and_change_bits(BIT_MASK(nr), addr + BIT_WORD(nr)) != 0;
 }
 
 #ifdef CONFIG_PPC64
-static __inline__ unsigned long clear_bit_unlock_return_word(int nr,
-						volatile unsigned long *addr)
+static inline unsigned long
+clear_bit_unlock_return_word(int nr, volatile unsigned long *addr)
 {
 	unsigned long old, t;
 	unsigned long *p = (unsigned long *)addr + BIT_WORD(nr);
@@ -185,15 +185,18 @@ static __inline__ unsigned long clear_bit_unlock_return_word(int nr,
 	return old;
 }
 
-/* This is a special function for mm/filemap.c */
-#define clear_bit_unlock_is_negative_byte(nr, addr)			\
-	(clear_bit_unlock_return_word(nr, addr) & BIT_MASK(PG_waiters))
+/*
+ * This is a special function for mm/filemap.c
+ * Bit 7 corresponds to PG_waiters.
+ */
+#define arch_clear_bit_unlock_is_negative_byte(nr, addr)		\
+	(clear_bit_unlock_return_word(nr, addr) & BIT_MASK(7))
 
 #endif /* CONFIG_PPC64 */
 
 #include <asm-generic/bitops/non-atomic.h>
 
-static __inline__ void __clear_bit_unlock(int nr, volatile unsigned long *addr)
+static inline void arch___clear_bit_unlock(int nr, volatile unsigned long *addr)
 {
 	__asm__ __volatile__(PPC_RELEASE_BARRIER "" ::: "memory");
 	__clear_bit(nr, addr);
@@ -215,14 +218,14 @@ static __inline__ void __clear_bit_unlock(int nr, volatile unsigned long *addr)
  * fls: find last (most-significant) bit set.
  * Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
  */
-static __inline__ int fls(unsigned int x)
+static inline int fls(unsigned int x)
 {
 	return 32 - __builtin_clz(x);
 }
 
 #include <asm-generic/bitops/builtin-__fls.h>
 
-static __inline__ int fls64(__u64 x)
+static inline int fls64(__u64 x)
 {
 	return 64 - __builtin_clzll(x);
 }
@@ -239,6 +242,10 @@ unsigned long __arch_hweight64(__u64 w);
 
 #include <asm-generic/bitops/find.h>
 
+/* wrappers that deal with KASAN instrumentation */
+#include <asm-generic/bitops/instrumented-atomic.h>
+#include <asm-generic/bitops/instrumented-lock.h>
+
 /* Little-endian versions */
 #include <asm-generic/bitops/le.h>
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190820024941.12640-2-dja%40axtens.net.
