Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGXOUHWQKGQEATKEONA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F02BDAF6B
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 16:13:47 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id p56sf2411328qtj.14
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 07:13:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571321626; cv=pass;
        d=google.com; s=arc-20160816;
        b=MRN0gIPPTYo+1SOpRBRhGBAa49L2KqyG2tQB0cO0pnnBB9ajGzDTiSgAaxeLi8PXAx
         4legzyM0JP9MPDsbSkDebi/5uwxdJmfkokxePygnMefkxWcz/9Vv1EUwb3Vg03YMYv5+
         N6PlCJkq3v+dRKNbOiWDYWe5CuSPDThTkY/+AYReuaRGUyJ7cENJc4IZmKbQ9WIjC178
         hpRHq71h+hnm5qygw2DYj+jNywxAVE0tQCuMeYGWHz04xJIW8WLvcZLS65eRgpfYo3g1
         rVJtFC0EJ71BRaRJfCSPl4wXpz7+Po8pnL14oveCqoUa3Add+mYLlAta/ZbiqGD7kEyQ
         t3eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=db7hkHW75l+rhtQLSsdEI0aMUyHq4GLYUMd28WdGvMs=;
        b=NttmXHy9vpsfafWNqGwskGC4QfOdC7dwXeh1ByDgK6RNq9ktbpYK0a3pYLdkAxp3SB
         3HXhUP1cQkB/U+n4o1rkoR/Ex0PmXAP0LHhMlqseQ4bVXmbYixh4tRus4Y0wBIg+P/uH
         XmjydfBDzkp4cPIloQNUXicZy2J91pCPZ2jED/4rt1vGHFkmyMpRa3cf8KDXPkbiA55k
         ySjI6ehprbe7MMDP+3iMrspvsV+iM3TD6BYHiFWhSc4ocri2zlhV886ss8IfdZZKL4Nq
         JwMlfUeGed7kMuH4Z+uj0VPil4zmoVgdrcrPXaLnBuCloeG8Y2y/3aTbzcNz8Su2o3s9
         6GnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q2AICOUX;
       spf=pass (google.com: domain of 3gheoxqukczs9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::94a as permitted sender) smtp.mailfrom=3GHeoXQUKCZs9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=db7hkHW75l+rhtQLSsdEI0aMUyHq4GLYUMd28WdGvMs=;
        b=Xv9ixbOuVUrnEcHvOpm/8/nOIV/XEbHxGuA+rBmk9oPzHIhZnpURIBnpEEy/4+7MqR
         OzBNEU1g4vvh3fYX70YWmfr9veToUNecXhL4bEL8TwOkr/lRbcXmoQztYNB4GBSpuoOg
         zS4aqqX7xwrmdUJCMf0TyaGafNR4B+ZXTGvO/7i9QI2oEzISfVS3GZlx3XdEqaaCdoZd
         OlQS+Bw1+qGeQjWTZ0c0GRLgmIGO7gTkUOTqedZnc9lwoArfM+d5+IrJa7pJg6PRfiXg
         r+58k+yhxG6YBlea90y2qrI+SoEifB2iC+0KEg7nb62aBB62H7543o+14r2DCvnOnCOz
         OZyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=db7hkHW75l+rhtQLSsdEI0aMUyHq4GLYUMd28WdGvMs=;
        b=mp8T7fHSZpasXUxEw4cwjUXuCi1+t/BHFNjg07KTY8/lErEHr1ghwxDc0NV3Ed1WYW
         0KbVAH/+F4p/ZzcXZuFuivWXHVMJlzCIyAcb99woY6Gr9/nlDFXhoLiAtTaKYJaH/Om5
         0mcfkjOUj0fEWui7ultM08+95nhp/bl2Md5Fa32kfYdhNrOnloJ06so+xxp3eaBLFzQb
         vKUNbtcLeXnWRaK4PNlVEExh/Ruod/5Y8jxiFl0lk5T0JsKFTrLOs7n8teZg/o7BorEa
         FNbiZ0qFeXDExNHBcgZT260MQN2fEHJ+mYMVHu8GUvAC84J8dgrGVXDn7ieho/Cu1rpr
         JlMw==
X-Gm-Message-State: APjAAAUhDldWPnYZKeK4F1ahweE2GHGjO7th3l74b8jSuRW2jNJ5lzGL
	+epjj1HmK9VD2+Ftu/nxI8o=
X-Google-Smtp-Source: APXvYqzqLNHzmjE65mOUInAl4X9FbSOb0mi02tB05BvMWueAO4eSaf/+YrO2UdUcukW5Gex9paBzeA==
X-Received: by 2002:ac8:28a3:: with SMTP id i32mr3964334qti.42.1571321626113;
        Thu, 17 Oct 2019 07:13:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4893:: with SMTP id i19ls32240qtq.14.gmail; Thu, 17 Oct
 2019 07:13:45 -0700 (PDT)
X-Received: by 2002:aed:3e45:: with SMTP id m5mr4122427qtf.268.1571321625696;
        Thu, 17 Oct 2019 07:13:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571321625; cv=none;
        d=google.com; s=arc-20160816;
        b=SxcWMQ9slFDhclKGlIxqrNyPw1rJc+Zy2f7IYFk5aFjWPdrCxZ6wBTq5q8cF5wcxap
         xfP6UWdwaEHUtzxu28zWQ3fEmlpVnTTFOop8QKkzxs0zvKZDEImTaogRwExopWEMlCKv
         cSFvjgoJLUsCOScR5UPDXDMF9Cef+gytESmRcKmqG+UOtP4vkvptv1wknv6w9lDw88Bh
         +Hwj57gLZzGMwl3AFRr25JZgo/HqDTCGFXFkQIYHCSEUVKEKsLLH/tCwft0Zhm+CnWJA
         0avYPzwDJFK/yyr1bTcMXu8SvcLtOkedgFkZRnXVikaTOovC5Sv4O01psLv3HiKrnN4D
         qKzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=WK0XW0pj3angQDA5Q/f2RR4InnLdQcXEOv/B1XGqGcA=;
        b=RNN7jdljXxGrTNeJEBPfKEa4Te/VP08GAiLxE+XMbx1Pwu0HiUlfXPOLc/AP8MHlCs
         HuXcNpwzd0XM0kl3p37tKGFjVEmklT/+YADBbYTL94JKa9XZ5L0Gsy4wywN583h5LGUc
         da66pzfh5SmxgMIHS7ZSiUM6r3rC/oh7Ynck4hP2AEOGESqGQhH8Ys5pfx48OibuMCwG
         vLDbu6fJjB4grzEZO1wFsvCNwpweM2CEf8lCrMvkgn6p1b5vBf9X294J/JO4INaBiCfD
         g6MBe4NjBUL4eFlWuw6jwaGHLWbZPJK0yecVFy4rKPgkONGY0404X5KIsimd0dpWfBCR
         9Vqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q2AICOUX;
       spf=pass (google.com: domain of 3gheoxqukczs9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::94a as permitted sender) smtp.mailfrom=3GHeoXQUKCZs9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x94a.google.com (mail-ua1-x94a.google.com. [2607:f8b0:4864:20::94a])
        by gmr-mx.google.com with ESMTPS id l4si131126qtl.1.2019.10.17.07.13.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Oct 2019 07:13:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gheoxqukczs9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::94a as permitted sender) client-ip=2607:f8b0:4864:20::94a;
Received: by mail-ua1-x94a.google.com with SMTP id p17so370003uam.15
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2019 07:13:45 -0700 (PDT)
X-Received: by 2002:a1f:9e8e:: with SMTP id h136mr2074941vke.8.1571321624934;
 Thu, 17 Oct 2019 07:13:44 -0700 (PDT)
Date: Thu, 17 Oct 2019 16:13:03 +0200
In-Reply-To: <20191017141305.146193-1-elver@google.com>
Message-Id: <20191017141305.146193-7-elver@google.com>
Mime-Version: 1.0
References: <20191017141305.146193-1-elver@google.com>
X-Mailer: git-send-email 2.23.0.866.gb869b98d4c-goog
Subject: [PATCH v2 6/8] asm-generic, kcsan: Add KCSAN instrumentation for bitops
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@linux.ibm.com, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=q2AICOUX;       spf=pass
 (google.com: domain of 3gheoxqukczs9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::94a as permitted sender) smtp.mailfrom=3GHeoXQUKCZs9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
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
2.23.0.866.gb869b98d4c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191017141305.146193-7-elver%40google.com.
