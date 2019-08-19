Return-Path: <kasan-dev+bncBDQ27FVWWUFRBCMD5HVAKGQET3C27FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id B2AC791D0A
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 08:28:26 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id p56sf2767713qtb.10
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Aug 2019 23:28:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566196105; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wxf3uXiYT7Wb535CJaTshn7QNnU8GjNzKEPC0qyKcJ0Wzd3qYWM92O1fMp8zhh8Xqa
         Vtf5GGt10fTNDgEWngOnuW0MuQ6I0NWxCYoacD7tAY1dWqgeUfJcWxgSPSkfggnEK7RF
         fCMewjTM+SdwopyDL0bsLoQJI3N07L9ajt6Ga3mqWyHsVtE4R8wIHEaxNYBohcBF63J7
         muY8oQpMVLD/B9Zf1tdxfbrDuZrwW6V15zYlcwashxXKfJapJwOCMHFYwFFolWJATw9a
         mycMVS37RezKBb2qefRY7BB4MFii07QvohymoGmIqjI1KILXDx4pw5qiz+9aoHvhCA3v
         xsLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hCTyMGIXkcIXNcYsQSYKC1PEK+U2iQCyh4zLCY6c6Kk=;
        b=M6EYmtVyxEw/IKLZDb6suiz8WdyqNf9gjXJ3pglX3LV5yTpPwsU0jCFR2wKKe/q4fH
         ngXMVCOzpoZLcRYoYxIMuBfVUijZbHpikQD8SByinqB45JbeJ3wz9ubg/oNDVt6ym5AT
         B7c4yi9tbcQmMniv+wcg8vWGEMNYRKbPL1Se0VQwd6EMDXEV3+IrkrpqevhYqdvM6J38
         7pXmZSvyWQ0NDoQLKd63xw67LeRt1kw8QDO1Vqk3sHDJtWz3HoVacoW3TIRBs75dCKuU
         KhnO5DtTvyoebRN6aOW4ELEZA86t0vksdcKCjfDLUnp2O5RSOOh4zXE+UV4HQvEz+of6
         Falg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Ks1ESLvC;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hCTyMGIXkcIXNcYsQSYKC1PEK+U2iQCyh4zLCY6c6Kk=;
        b=hyH/jZfQfT4RhWFL2XnWKvL+/kfg8McLm/WoN7ErxAUdGptcMpY18X4kbPlSG4igf1
         lmAnKr7O3GSRu/HJUIytQ1isXkxHJgkUy685i1fBE97Cqe1gy4rD612ovoEePTTaiO5j
         DRlYd7Ds3Cb0Ey0PRSDDxNRfaMDQKqs0NM10LZ0PHji6pTWjHlVgl2LdJUeidJw+89Gl
         utRsDU4OLTCd4H6rnVIGlwk5Z2D4z8K9MZ7fcSTZAz5Fz1sIx6hOhCI6Oa1EC/5GHWGI
         EfRNnrVLIn2Sf/7+YCKhMop/Cl8zZ9Rs+8wAvPyXdZDHKCKPx7O0AJ8HcQ1ShOUTjtW/
         lbow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hCTyMGIXkcIXNcYsQSYKC1PEK+U2iQCyh4zLCY6c6Kk=;
        b=VpsEuS8mk4SKMip5KOatCskoijlLnRbc9Kvdq8D3P03mfVPSY9fp/nR32Je5p0cEEM
         EXtJ4YPJwBii64M0SNewxyh5ZKVM6ygx2HtQykSy48j0DUXZqnr7RArVFzUj5S+X8d9Z
         zHcqxPc92TOxEZ7WUpme1mJD3CBBprNBLyTWJSRkAki/+wURv+r6E//I2Vpu5PZpCogD
         97DwVoE91oP9h6q2gKtbTbenmu7kXXEodcJNdXFr7PorVgrs9QVZq3QF+KnsDZ2paCtZ
         u2P8shIOAbn5OZXcE2bFFi5nmYD5zG9ZzBQGTatt0ix2EnHIrc/HMiKoVnbX5XNEZ1K2
         tf/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXaoaPdUHihgexof3jFQDgEHBsNyBtiTozJB4M2oJmIulo0xXTu
	ojM+nkJCTR7otaxoJA98tlo=
X-Google-Smtp-Source: APXvYqxIbOZmI+e9KYpUE8ntKvnAAYT3WFEm1Ah1Tz8kZbxJgv4NlJNIbDtOOOFz+bc7CHcTMkWvjg==
X-Received: by 2002:ac8:2f61:: with SMTP id k30mr20127967qta.340.1566196105831;
        Sun, 18 Aug 2019 23:28:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:75c1:: with SMTP id z1ls1872384qtq.3.gmail; Sun, 18 Aug
 2019 23:28:25 -0700 (PDT)
X-Received: by 2002:ac8:4808:: with SMTP id g8mr20370602qtq.0.1566196105546;
        Sun, 18 Aug 2019 23:28:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566196105; cv=none;
        d=google.com; s=arc-20160816;
        b=DR5hf3lbbiyBrHJt898zZ1ZSoXo+kOadUSaEUDLq4V+/NvsidbWESnzCo1VtZQw0Wx
         D4u+9IoeMIen2PbfMcD5RzRSLlCbQ7ZOlzOb5uT0hor08227nKHazFSo06++e68Qzraa
         pQpG+y4Ub4+G9knCmhH5U8CS0Sob4Qc1nD6sOdLToljJI6nio2CGxep5UIJX2NzbcZqh
         Fm9K6ToTrX1QONbUMQ4ztSBRQuB1EOCSm4Fd8zt/a8WHmFdCP7bOkgX5J+46+BZhMZA8
         1/Yw0CL3FpP2WX8SwYHJg0WKTajaSzb+3lkkKlBMd/UJJ7L/HOxZ+A5PS+owSP4xOyvV
         9bwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LPQB69yWRrfnt5mqgKFU9csZRzqxMbwma7Xig4WeJx0=;
        b=NaCKdIbJwaeqGAJVnk28DxNfMehXnO3WYVOgb3pUWoalCJIo67b1nGBLah+Pesn8/T
         TtrWZA+s2GsTmfGqszN6CfKmWtMg0+lh7lS4Hbuzy4bN+4wByAAp126QGOQ61iO2Dhbd
         pGZOuCizKEThPmW+bwAz/vPXhFbcQcA0MErjmXvPoSIZHB67/Y2Z68QZtaVYDJg2u2uO
         MwyU7iC4MmiXeODWlE+7lgjoIAkSRgjKw16ioTS8CDDRUQmvh3QXTLQet06qr9ml3dGC
         Xg4aaGvNAZ8JOLzLXDd228ShGTR/JppamFPYLiFdfy2XLzwHKDbq4O8ND21T8tKkH/EC
         3rXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Ks1ESLvC;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id v19si592588qth.1.2019.08.18.23.28.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 18 Aug 2019 23:28:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id u17so586435pgi.6
        for <kasan-dev@googlegroups.com>; Sun, 18 Aug 2019 23:28:25 -0700 (PDT)
X-Received: by 2002:a17:90a:3646:: with SMTP id s64mr19329426pjb.44.1566196104738;
        Sun, 18 Aug 2019 23:28:24 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id y13sm3557979pfb.48.2019.08.18.23.28.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 18 Aug 2019 23:28:24 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: christophe.leroy@c-s.fr,
	linux-s390@vger.kernel.org,
	linux-arch@vger.kernel.org,
	x86@kernel.org,
	linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>,
	Nicholas Piggin <npiggin@gmail.com>
Subject: [PATCH 2/2] powerpc: support KASAN instrumentation of bitops
Date: Mon, 19 Aug 2019 16:28:14 +1000
Message-Id: <20190819062814.5315-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190819062814.5315-1-dja@axtens.net>
References: <20190819062814.5315-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Ks1ESLvC;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as
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

Cc: Nicholas Piggin <npiggin@gmail.com> # clear_bit_unlock_negative_byte
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 arch/powerpc/include/asm/bitops.h | 31 +++++++++++++++++++------------
 1 file changed, 19 insertions(+), 12 deletions(-)

diff --git a/arch/powerpc/include/asm/bitops.h b/arch/powerpc/include/asm/bitops.h
index 603aed229af7..8615b2bc35fe 100644
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
+static __inline__ void arch___clear_bit_unlock(int nr, volatile unsigned long *addr)
 {
 	__asm__ __volatile__(PPC_RELEASE_BARRIER "" ::: "memory");
 	__clear_bit(nr, addr);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190819062814.5315-2-dja%40axtens.net.
