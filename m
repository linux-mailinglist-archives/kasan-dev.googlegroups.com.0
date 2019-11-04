Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOPLQDXAKGQEHY7H7EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 43857EE267
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2019 15:29:14 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id y12sf3289801ljc.8
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2019 06:29:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572877753; cv=pass;
        d=google.com; s=arc-20160816;
        b=oTY8TSSWxfCxXAiyBDPAJxnO6Wwf09b29l4hmSHpauITsCSm/8gLOxMr5pYxCJnH4N
         BQ+WWwOZ7LWVR/t2Sx3lx/XcL8ubgyhkpfKkK/DN1Ye/M65srbMeUaJWLhGLLep7C2E1
         nITvICT6Xf1tnAx1EqlqnCLv4vAmmJm219TdzJ6pcCrACmAS5FVcdk4FMIJTEaSbiL59
         otaQIlmhUI8pBKWgfItxso4XB6GGJavFO6Bljl7S7rT7w9b77qkc26q9qRFJ24NiaHcA
         nr7UZeou97U+XwBG9KEeh8assf6gSFmlbXSpdtsO53rbXHVaQHuz2+voDYyYVnZH8TsD
         aBtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=SbS+4kwgDSCVdPu73gdLW7bxzi84jvxkjmoKGwbWWGE=;
        b=o2sGIwwyOqWTBNl3/GKydOwN7RTxamCosVoVWzJ//hbvuf3UUPWUkEwHTEd85AGq4N
         /09cxS3ckHGkbsNHll/QknM2ltqAyprKZJgav1L4+NVg/rel1NDHGrgPjEKqpJAlE3nN
         jkw0LfNaMDMih9ODuy2ogbHE8hfOFUj/yzSVnHDMCX4hUpAjYN5iDf5AngAbnmTGRiHx
         Y4ESDwAmy8CfVhIKbC2WZN3eL2Ota4OSu+Rlg2kCisjCT8xMlZ7gIal3wjVb7flh4iph
         9qzDZYyY+EQh7n5jGkeoYqp0/k0gfgaPPLTOx5c9K2uahn7HD23K3tZxjGVOKYaDzlky
         fRhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="U/XYdcDe";
       spf=pass (google.com: domain of 3udxaxqukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3uDXAXQUKCRk3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SbS+4kwgDSCVdPu73gdLW7bxzi84jvxkjmoKGwbWWGE=;
        b=dT6i4YgwjnA0Ira9JMXvMS2kfUGQhi9lAHloCHfiKlcspb8si72b22tqOT0kSgTS0C
         FZCrgZXrlFfl357Iq4dFvbnT+Ct6l7ZeWHey3SDq3d0hvT6CJwa1jP424uUEqT75lgzH
         PdlS0xL3uEag/D6nvKnrCYEhnlK0j9GZTob6Z7X2f/HlH0bT8RKqNbE3rHMTtsh6Weos
         IL+ZSMSt9t8z150DmHQxmk4ZVow5/pL8a2Zhkseg7Jxj+5rplNfvGWu0G/rVe2qSo7jt
         jJBmS3nWyCcPvNPfmEPPjrrTSkWK77soPyzEBIwkgk10jZYGGnlBx6xEFrzNpQ0WSJxG
         Ep+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SbS+4kwgDSCVdPu73gdLW7bxzi84jvxkjmoKGwbWWGE=;
        b=m83aWHFPJAJjLD09kGIRelQESllyY6XhzrSkyNv/r7CVIHmCb+qVwVao2uDdE5IrYt
         8ksJ/MlG4yxI2rytFVG1dEvvSFjzO/lRPBx/tHKkD7Ng5uTBVCXlEftiu3xe9hUgXkQq
         7lFQzYhKlm+GTqsSQwku3s0gXslSAHZni9np3JzRWwPGNJ1+39oOkJuA9dtU0n422j72
         Xh2HwPtzGL49DKGq19USZnIN2kdxGMeIXyMCzKcJq356JEY1EYvmhD4cD68SNQuq0tYs
         azynQVqHDCuQ5R7rc/D+I9fnzLnsF/gBaexzRG/Ynt7SMKoOH61epfNh7UwRm27Gwzfy
         q38A==
X-Gm-Message-State: APjAAAX8YrNKb9AmDSwLls1xcuzVvB9l1JYqbC0dOjUJxQ/UYZJfDbyM
	O67TLN7jjIUPw+1wqF7QsC8=
X-Google-Smtp-Source: APXvYqwer/cdV3kBCD2DoUgBPzkysyOzAnAzevRSwM1C+Wv6/BgRgNOtlQu6fUZZmFedQR2REuJKmA==
X-Received: by 2002:a2e:81d2:: with SMTP id s18mr4379333ljg.189.1572877753900;
        Mon, 04 Nov 2019 06:29:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:c4:: with SMTP id 4ls785304ljr.6.gmail; Mon, 04 Nov
 2019 06:29:13 -0800 (PST)
X-Received: by 2002:a2e:b007:: with SMTP id y7mr2082260ljk.69.1572877753256;
        Mon, 04 Nov 2019 06:29:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572877753; cv=none;
        d=google.com; s=arc-20160816;
        b=KdWSBjlDm4bSANKeJ/Q7o5b9JGXEvqOyAoqei6I9X0e8urWMX3OJYIXEnUqkLsHjLL
         oZltuG3FtAq1RZLZ3rGZxoMXAbjjelCw8SBisMRs9tr7RfGagAXGmmrDAuZapcJVKdjJ
         RJo/LemSYyle4jQwXntZCJqmFG0Vpq5Yyy00sGpbowsjfjrQQXEcNfZ1WftaistT+y8E
         4LfUdNyjnr8WN8r98nARtkIkRJdoFsrZG163ZIr/aGcsMopVaeUqmcRGtFrLliEVVH7H
         thsqAkqTYlc2JMVgE/Fw7L5QIOIvRfyvi4aKgIaLgExixtVAcx1KvZZnBBZb12wXp2O9
         QwFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=dwkrnZGKd1o82vLncnnMx5+hskPdjM10M9XkepioArw=;
        b=Nv38dAmUawbmTKhsSOkSZKoJ5Em6e8fLTiDQfMeQoiyCfCb1K1K7Yrk+LALMjX3RU/
         VOndj5apE4e4UHea9VWrfIfTGgrI18p05+UuCLxCV1ytPW91GSihwYgZHoHbRk8DDWkw
         sKXTO8Pn9VzUwODpTUYsAHQxRHTLuCbMjR6iv9lF4+9mq1CRFHsxm8XYE8xU+PxOiE/9
         w1NNXstl9l/76BzxRezqu3Aj7fgnWXaLrE0YXHd+QPGF5E4RAULjy7Ag7+8pk+yEAS7e
         cyUUYu+b4z7bbon1lPhSZB4XD/C6w3tMZySBHFUL5Mz29wzn/3PLQzdbGdeKMZsxnKq+
         RYhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="U/XYdcDe";
       spf=pass (google.com: domain of 3udxaxqukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3uDXAXQUKCRk3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id b22si1056674ljo.3.2019.11.04.06.29.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2019 06:29:13 -0800 (PST)
Received-SPF: pass (google.com: domain of 3udxaxqukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id c7so2850291wmb.0
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2019 06:29:13 -0800 (PST)
X-Received: by 2002:a5d:5591:: with SMTP id i17mr22415611wrv.151.1572877752204;
 Mon, 04 Nov 2019 06:29:12 -0800 (PST)
Date: Mon,  4 Nov 2019 15:27:43 +0100
In-Reply-To: <20191104142745.14722-1-elver@google.com>
Message-Id: <20191104142745.14722-8-elver@google.com>
Mime-Version: 1.0
References: <20191104142745.14722-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.rc1.363.gb1bccd3e3d-goog
Subject: [PATCH v3 7/9] asm-generic, kcsan: Add KCSAN instrumentation for bitops
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@kernel.org, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="U/XYdcDe";       spf=pass
 (google.com: domain of 3udxaxqukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3uDXAXQUKCRk3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
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

Add explicit KCSAN checks for bitops.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Use kcsan_check{,_atomic}_{read,write} instead of
  kcsan_check_{access,atomic}.
---
 include/asm-generic/bitops-instrumented.h | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-generic/bitops-instrumented.h
index ddd1c6d9d8db..864d707cdb87 100644
--- a/include/asm-generic/bitops-instrumented.h
+++ b/include/asm-generic/bitops-instrumented.h
@@ -12,6 +12,7 @@
 #define _ASM_GENERIC_BITOPS_INSTRUMENTED_H
 
 #include <linux/kasan-checks.h>
+#include <linux/kcsan-checks.h>
 
 /**
  * set_bit - Atomically set a bit in memory
@@ -26,6 +27,7 @@
 static inline void set_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	arch_set_bit(nr, addr);
 }
 
@@ -41,6 +43,7 @@ static inline void set_bit(long nr, volatile unsigned long *addr)
 static inline void __set_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_write(addr + BIT_WORD(nr), sizeof(long));
 	arch___set_bit(nr, addr);
 }
 
@@ -54,6 +57,7 @@ static inline void __set_bit(long nr, volatile unsigned long *addr)
 static inline void clear_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	arch_clear_bit(nr, addr);
 }
 
@@ -69,6 +73,7 @@ static inline void clear_bit(long nr, volatile unsigned long *addr)
 static inline void __clear_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_write(addr + BIT_WORD(nr), sizeof(long));
 	arch___clear_bit(nr, addr);
 }
 
@@ -82,6 +87,7 @@ static inline void __clear_bit(long nr, volatile unsigned long *addr)
 static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	arch_clear_bit_unlock(nr, addr);
 }
 
@@ -97,6 +103,7 @@ static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
 static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_write(addr + BIT_WORD(nr), sizeof(long));
 	arch___clear_bit_unlock(nr, addr);
 }
 
@@ -113,6 +120,7 @@ static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
 static inline void change_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	arch_change_bit(nr, addr);
 }
 
@@ -128,6 +136,7 @@ static inline void change_bit(long nr, volatile unsigned long *addr)
 static inline void __change_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_write(addr + BIT_WORD(nr), sizeof(long));
 	arch___change_bit(nr, addr);
 }
 
@@ -141,6 +150,7 @@ static inline void __change_bit(long nr, volatile unsigned long *addr)
 static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_set_bit(nr, addr);
 }
 
@@ -155,6 +165,7 @@ static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
 static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch___test_and_set_bit(nr, addr);
 }
 
@@ -170,6 +181,7 @@ static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
 static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_set_bit_lock(nr, addr);
 }
 
@@ -183,6 +195,7 @@ static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
 static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_clear_bit(nr, addr);
 }
 
@@ -197,6 +210,7 @@ static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
 static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch___test_and_clear_bit(nr, addr);
 }
 
@@ -210,6 +224,7 @@ static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
 static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_change_bit(nr, addr);
 }
 
@@ -224,6 +239,7 @@ static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
 static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch___test_and_change_bit(nr, addr);
 }
 
@@ -235,6 +251,7 @@ static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
 static inline bool test_bit(long nr, const volatile unsigned long *addr)
 {
 	kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_read(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_bit(nr, addr);
 }
 
@@ -254,6 +271,7 @@ static inline bool
 clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
 }
 /* Let everybody know we have it. */
-- 
2.24.0.rc1.363.gb1bccd3e3d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104142745.14722-8-elver%40google.com.
