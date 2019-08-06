Return-Path: <kasan-dev+bncBDQ27FVWWUFRBC47VDVAKGQEKY2EQ3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id BFB2983DE1
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2019 01:38:52 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id w76sf22512833vsw.10
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Aug 2019 16:38:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565134731; cv=pass;
        d=google.com; s=arc-20160816;
        b=g5UqlT70OUxyUBizR4fyPII+d5Phbkz0sJiGarCdm7HnF3IAReM5HABjkn8wuRcQKw
         sx0tlP+6TxrHg8y6zbhkwzymDi/KrPpe4yaxy/HoyIIuZqD4JtN8jDJbtyd5GA9pm5mZ
         gI9e18nFqGCocciEkaNzPjLGLjas4KYSAVlYQGhO7LuS5CvSujlE+slpEGk4yls/Nkd4
         sCYv0vdjJkKBobv+qgMunRcrDTLkHt3yyTXUrS/+Xux/sYvzqUTDjAgaQ9u2nXczlnMD
         Ws/A6rxrneGzKd6ii2mkaludU88t66hJd0J1WqafKdLjHbWfY9lZIrKMbcNRZACoE1qH
         SybQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=g5Rtp/JzRkUBgnbZ55TYUiZ8POtQQY66t2KyEEOaM3I=;
        b=V2RDDiT56iosgxdvQEgsaHnrruPHhd7VnxQIM9bv2uZueftzAfoRqsggTWSZxobtaP
         GTvuHyBbIiUHfWsZwDVSkbY9Qa0qFevSlw8GlL/o+4iIS9vuc5hGHItY6z4uAFVvyaf+
         HeHvz442IHhMyyfDjj+FpIS6zXELQxEOpKGAcFxl3P58J8XzAk1UWJF5nwdUk2h8YeED
         DTxz3kdu4D/McmoyQ5NfB+GhxSj0bNkgiJcdF968k1axgwfBo5NCfRXeA0UqWS4UMl5A
         Wx1fftrABxmDumCL59UgjYy9GehGQQHkCnCAXbCVD6jmFxB4DFdO1/zcDywBfEqoO2nK
         xt+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="XcS54DC/";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g5Rtp/JzRkUBgnbZ55TYUiZ8POtQQY66t2KyEEOaM3I=;
        b=PzA9Ji52oG2QDVHNkLZNgofwjNDAvFYSbWDtxq6h9nZnYRmhqETEkhRSDZD8UD0oeb
         l9k382SI7m5RCOk5IsjQFMhoBSdgvCALpryYxi9WWa6Q2hgVK2Wcla7nzOl1dP0hMPrM
         Fz3Y6vigGd73VZGKcOqWMsD2mCMTbykBRAvfRB2SidQ3IsrSmsx+qIvod008jBpGfF/2
         Ro1+4VL+mURkDvJkm6bV6kDYlotb5zvnKA06C0qaWryiRenzV6LvAF3OAEg1AH85RcfH
         DXMjlGJVseQMveMZrzOWFTE4Xn/JmYkY1TwPb72UteI6rXvL3nGqkPtW2TqXsdjzuECx
         TjYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g5Rtp/JzRkUBgnbZ55TYUiZ8POtQQY66t2KyEEOaM3I=;
        b=sUdySJiGvAKVRsH115QSYL7yCrpdXolmVzk9xVqaV56VizDduGT6T0xpGWE1tzaU8Z
         jniwzuWORg52OMWwqxFIVaDqIAsWbPJ70WVBG2Cw3SulD1YRzy9KK/OIKYVYjqELLPY0
         +CLL6qTiSXSY5wZkAGaZY38TYnb0n6TTFIKer8e6DMxjoekjfxENr4GI21eXbt4HFuh2
         ehF2ySqAWau5K34GXud8XYLDa5GleE/1N//oP/dhOJAotwTfrnaYiPrA1kup5Lx9Wis9
         /VjHmTFkMC1JY3Zy52pV4bVXjfCcauK58aevJj+d5teRJHk+/+pskodnLHPAqS8cJAzy
         knHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXZteifdxqB/ULp9yWFkCtzMRZ6RADm0vuOqgfS+bcc857pvK0e
	OG7oKuIUCZPwLBriECft3Oc=
X-Google-Smtp-Source: APXvYqwKoSZh0gLaMYh9TpnI/1W3CemDRIBOlz4vtIF4cGGLYn0vgAsHaU1jY58kKcIkRs/vFrUV4g==
X-Received: by 2002:a05:6102:114:: with SMTP id z20mr2752352vsq.187.1565134731889;
        Tue, 06 Aug 2019 16:38:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c886:: with SMTP id v6ls11222531vsk.1.gmail; Tue, 06 Aug
 2019 16:38:51 -0700 (PDT)
X-Received: by 2002:a67:e446:: with SMTP id n6mr4372740vsm.142.1565134731572;
        Tue, 06 Aug 2019 16:38:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565134731; cv=none;
        d=google.com; s=arc-20160816;
        b=vC/eo/7cXjhj3svwTb74ee4UTX05BjXoc6pZWs2E0LtBpqMJjz6QbJ6ZvC4nMEQAMw
         yAW1VOjRH50/BOp3R5DG/35RvUED5sbIheY2kryiFwFclp8x5q1XBp6jUt011tOUR0pf
         uBxNI9hhcvTP3Bo8rZ9QBq4Ne4TiCp8eCmk+8XIuN1GzqhAJogXQFJscHcLg5gAEODeU
         HFLQzz6CG7einSQV9yihLEg70kG0ZspNTHlm7Qi6QuPGgQJSd97m6sh6IEcAxQz+IzcO
         yjS2pzY035l1YDePLR2xL56avp4Yie7YTdSMhfNzsTLC2rB8/OXonfmmU2Z0S81+Srnd
         oSUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QItJBQZK9T1seVQYKJ2PYQ+PjsrVTZaWuqJ1GoAJvEg=;
        b=qzVRZEcwlZI9bIqsLW9xQ28s513jEus7Dnyu2fPA49cwXEbk7tIbxsnSnleWEpi0UZ
         0CzCNu43VmK/RgXVTbcefz04YfoUKWca036+ROquFDaM6Zs+j4s172r6jrIxyNSe2v++
         452pRQIk7MKIIkMi8uCaGtTi3v30fv54n1HdpmcnmanaciTnfIct/l9H+PSV/ZKT32Eu
         1iOCh7y08Ix8HYh2qdWD0BvWxQyHXxNLpSo7te1nLfo6lMZ8BsCFGYsDuMg2AjuXybZ0
         WnbixAnKQ/L2T9hMk558FbVzH7xvz8IIchzpsVWMBtIoB8xgNYrNR5Eko1tTx5wXG+tN
         u/zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="XcS54DC/";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id b5si4266822vsd.2.2019.08.06.16.38.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 06 Aug 2019 16:38:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id c3so19220619pfa.13
        for <kasan-dev@googlegroups.com>; Tue, 06 Aug 2019 16:38:51 -0700 (PDT)
X-Received: by 2002:a62:1c93:: with SMTP id c141mr6480128pfc.9.1565134731039;
        Tue, 06 Aug 2019 16:38:51 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id b30sm121525557pfr.117.2019.08.06.16.38.49
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Tue, 06 Aug 2019 16:38:50 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: aneesh.kumar@linux.ibm.com,
	christophe.leroy@c-s.fr,
	bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>,
	Nicholas Piggin <npiggin@gmail.com>
Subject: [PATCH 3/4] powerpc: support KASAN instrumentation of bitops
Date: Wed,  7 Aug 2019 09:38:26 +1000
Message-Id: <20190806233827.16454-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190806233827.16454-1-dja@axtens.net>
References: <20190806233827.16454-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="XcS54DC/";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as
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

In KASAN development I noticed that the powerpc-specific bitops
were not being picked up by the KASAN test suite.

Instrumentation is done via the bitops-instrumented.h header. It
requies that arch-specific versions of bitop functions are renamed
to arch_*. Do this renaming.

For clear_bit_unlock_is_negative_byte, the current implementation
uses the PG_waiter constant. This works because it's a preprocessor
macro - so it's only actually evaluated in contexts where PG_waiter
is defined. With instrumentation however, it becomes a static inline
function, and all of a sudden we need the actual value of PG_waiter.
Because of the order of header includes, it's not available and we
fail to compile. Instead, manually specify that we care about bit 7.
This is still correct: bit 7 is the bit that would mark a negative
byte, but it does obscure the origin a little bit.

Cc: Nicholas Piggin <npiggin@gmail.com> # clear_bit_unlock_negative_byte
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 arch/powerpc/include/asm/bitops.h | 25 ++++++++++++++-----------
 1 file changed, 14 insertions(+), 11 deletions(-)

diff --git a/arch/powerpc/include/asm/bitops.h b/arch/powerpc/include/asm/bitops.h
index 603aed229af7..19dc16e62e6a 100644
--- a/arch/powerpc/include/asm/bitops.h
+++ b/arch/powerpc/include/asm/bitops.h
@@ -86,22 +86,22 @@ DEFINE_BITOP(clear_bits, andc, "")
 DEFINE_BITOP(clear_bits_unlock, andc, PPC_RELEASE_BARRIER)
 DEFINE_BITOP(change_bits, xor, "")
 
-static __inline__ void set_bit(int nr, volatile unsigned long *addr)
+static __inline__ void arch_set_bit(int nr, volatile unsigned long *addr)
 {
 	set_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
 }
 
-static __inline__ void clear_bit(int nr, volatile unsigned long *addr)
+static __inline__ void arch_clear_bit(int nr, volatile unsigned long *addr)
 {
 	clear_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
 }
 
-static __inline__ void clear_bit_unlock(int nr, volatile unsigned long *addr)
+static __inline__ void arch_clear_bit_unlock(int nr, volatile unsigned long *addr)
 {
 	clear_bits_unlock(BIT_MASK(nr), addr + BIT_WORD(nr));
 }
 
-static __inline__ void change_bit(int nr, volatile unsigned long *addr)
+static __inline__ void arch_change_bit(int nr, volatile unsigned long *addr)
 {
 	change_bits(BIT_MASK(nr), addr + BIT_WORD(nr));
 }
@@ -138,26 +138,26 @@ DEFINE_TESTOP(test_and_clear_bits, andc, PPC_ATOMIC_ENTRY_BARRIER,
 DEFINE_TESTOP(test_and_change_bits, xor, PPC_ATOMIC_ENTRY_BARRIER,
 	      PPC_ATOMIC_EXIT_BARRIER, 0)
 
-static __inline__ int test_and_set_bit(unsigned long nr,
+static __inline__ int arch_test_and_set_bit(unsigned long nr,
 				       volatile unsigned long *addr)
 {
 	return test_and_set_bits(BIT_MASK(nr), addr + BIT_WORD(nr)) != 0;
 }
 
-static __inline__ int test_and_set_bit_lock(unsigned long nr,
+static __inline__ int arch_test_and_set_bit_lock(unsigned long nr,
 				       volatile unsigned long *addr)
 {
 	return test_and_set_bits_lock(BIT_MASK(nr),
 				addr + BIT_WORD(nr)) != 0;
 }
 
-static __inline__ int test_and_clear_bit(unsigned long nr,
+static __inline__ int arch_test_and_clear_bit(unsigned long nr,
 					 volatile unsigned long *addr)
 {
 	return test_and_clear_bits(BIT_MASK(nr), addr + BIT_WORD(nr)) != 0;
 }
 
-static __inline__ int test_and_change_bit(unsigned long nr,
+static __inline__ int arch_test_and_change_bit(unsigned long nr,
 					  volatile unsigned long *addr)
 {
 	return test_and_change_bits(BIT_MASK(nr), addr + BIT_WORD(nr)) != 0;
@@ -186,14 +186,14 @@ static __inline__ unsigned long clear_bit_unlock_return_word(int nr,
 }
 
 /* This is a special function for mm/filemap.c */
-#define clear_bit_unlock_is_negative_byte(nr, addr)			\
-	(clear_bit_unlock_return_word(nr, addr) & BIT_MASK(PG_waiters))
+#define arch_clear_bit_unlock_is_negative_byte(nr, addr)		\
+	(clear_bit_unlock_return_word(nr, addr) & BIT_MASK(7))
 
 #endif /* CONFIG_PPC64 */
 
 #include <asm-generic/bitops/non-atomic.h>
 
-static __inline__ void __clear_bit_unlock(int nr, volatile unsigned long *addr)
+static __inline__ void arch___clear_bit_unlock(int nr, volatile unsigned long *addr)
 {
 	__asm__ __volatile__(PPC_RELEASE_BARRIER "" ::: "memory");
 	__clear_bit(nr, addr);
@@ -239,6 +239,9 @@ unsigned long __arch_hweight64(__u64 w);
 
 #include <asm-generic/bitops/find.h>
 
+/* wrappers that deal with KASAN instrumentation */
+#include <asm-generic/bitops-instrumented.h>
+
 /* Little-endian versions */
 #include <asm-generic/bitops/le.h>
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190806233827.16454-4-dja%40axtens.net.
