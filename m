Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK4J7XYAKGQE6Y5P6LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 55AB213CA12
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 17:58:21 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id 199sf6562365oie.10
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 08:58:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579107500; cv=pass;
        d=google.com; s=arc-20160816;
        b=nWGQixssR+E6y8MaSYv+S6QJAMMu2dQkVe16CoXhf5e9f2IHvOmoqcyicNfm/8W4OV
         +zJsoKF6WOiO4/SQ1Q3wdVkPW6GiaR3il1OpE0ozgSv3Il1QhIFSMpSRMSHv9rEO83So
         nhspzV4S/VNY6a6/TGmVn+kOC8ENK5TdmRRyGMQwrrydpvNvmIVz7gDXm3G1n8FkFaiy
         zg6dew+KmWPqH8MPN+xU0zOzAz9Xc1kU0RQo9pF9PWbaV5yWvXLmoFa2GuMNsRgwrOvg
         Ibtu7HQbzrXIiukJVqii+xUY3nhHgvtRw8r6msKjdVZWtkPiHqMGQWw2vy6fiDN4BpEv
         16xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=AXFYqCcTGYpqNdW8klT3OAC1pWBz0ot52DvR0dUbpaQ=;
        b=ko3D1Eyxrb95mVsWO7Yt73pRRpgUZQ8ivLvRCKCxX5fpMfqPJy7k2LHaHoscnXnKdf
         Sqo9hfTO2k1I1ewDZH5/lq2QjiqHL8lFpDzk0aFNdJsgp7P5irk2B7Nvmj0uuZObCcXV
         kcNIZBRGIt00lWwuWRbX0nlYWkGtPYVIoCa0SFXjQh7I5I7AUi3NEPPoMc8teFaUfD5K
         i9C9JpCeWa7vXKF6+L227Blf2Vxfw9VN2rKBYqHEaAegfI1lyn1Aq5bg4K4orlidCdt7
         oBZHuWz3mSP50qy2hs+gl5JxlU3yzG/02KbxBMmQ2PxY79TqRnJ0WC9ONP0z+sFdL/YN
         eSzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aU2dtLHi;
       spf=pass (google.com: domain of 3qkqfxgukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3qkQfXgUKCacLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=AXFYqCcTGYpqNdW8klT3OAC1pWBz0ot52DvR0dUbpaQ=;
        b=ZGWHwqggYybnKaqMuxRisIkBKyXSZZVWnSy/zteztCpsvJjjtoGz58K6akCQGjy8au
         FHd0PLLEZ3ANBosaYlulNI7OvOt1odp5OR68JaD98MU/6NU8dEim2S+fpqCoG9Yih7EN
         7xw+GF1hsbGIUhbNRDyJqBB364FuvfhQkm7gpnsjBn0Tw76gjlngR3jGuAWEc8TP+yB/
         M/udmTWGvKX1JsMUgsd3xEBROBs7UHjf4hj0Fu4/shDhqVwyXeFFIkGMyu7Kx8mVfHA0
         mvps2XgAe3lCttxgqCNFI9ZQxgs5qRF03I9xeYKhA7apwluyg8LqnV1qRv/pD/7yhqMq
         yifg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AXFYqCcTGYpqNdW8klT3OAC1pWBz0ot52DvR0dUbpaQ=;
        b=PNBYRKR4G11jisPdlUGCYTBqS3UBjtGW4FZzfZts4/Ogs4ZtlX2/uzJzABHbUMTZ4T
         VJgd1pyaDfDp+1lRCiWPBXdoc3krYj8FZcVF5FajD8FIq/mcataHolQlag2ViZT+97et
         +FCmNbZBPlI8/o42C+H6BXRFfoIx+/wMPZgYO3lMQKRt1qgYHZ33tQzkDRTPz5yIPC1H
         lwZXIiyB3hC+kRzOWB6dZYAgyfXfJVTziV7O11jg8NYNlh6qe0LdZ9BrET7nulK2aDwD
         pRbLPTwKBwZW0rnLxeprcIIW5bhKmk0B/LryjqLYQ7fEGt3YEn3yIFYqPQ/+e3dlyig3
         lOyQ==
X-Gm-Message-State: APjAAAXC6fshKNnaLjPu5GXsJFwbkOWCG7hqSENr5QxstBVVjLKdl3++
	heUFFLOvuzu4/fJ+LB4djUc=
X-Google-Smtp-Source: APXvYqyzPa4uFgA59YAxT8TmOYLTe0N6JF5Pt5+ryvlLQZ7phaNClS33dnNa2r3V2PUtBOMYKycE2g==
X-Received: by 2002:a9d:da2:: with SMTP id 31mr3285506ots.319.1579107500142;
        Wed, 15 Jan 2020 08:58:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:6103:: with SMTP id v3ls3476121oib.8.gmail; Wed, 15 Jan
 2020 08:58:19 -0800 (PST)
X-Received: by 2002:aca:c494:: with SMTP id u142mr634699oif.86.1579107499233;
        Wed, 15 Jan 2020 08:58:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579107499; cv=none;
        d=google.com; s=arc-20160816;
        b=YQKzr0rwXB+YYohMv36IpzCWsbv30w1BF4/dtmgD1TjCZX6ZZJYGsCvrzkHRb+x0IO
         PQBu6VMkPOd09GoSPpYSuK9j9MBSOFvDb7L6HxaFGotcDqk4J3Oj+MF4Jj8D0mN6uCia
         E7w56EJjsEBTTp8VtZth7JduG1Ab6NXikbyfPaI9gMJM7K7vTfhgbeE1uW1YNa1HNOd7
         yRPrkOKvakMEu8FKSL2wySl5aXJkp4vunav6VqC9a7XK+V2rGySL44SCDjFw1X3wgb3t
         qw2KlDDRGEF0X57HvvSZZB0V1BWIFsHn5ULrbs6ZwX1i5FY2sFX2YlkNATzv1ki4R3p+
         O52w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=1xyFxbboVErs2lDyuCkQizXSlJ3hz4CWgsOgebKOGj4=;
        b=Qje/4gFKcyOxWMMHpoyRt8gm86Z8qPl1QvO+Ov6MH4R7BLQSzho5UH4Lq51DcnwbpI
         jUKUsNKemGFbZE9R6nLU6dvD4Aio+jTFiavK0a4MjfZ69Hnx4BVOkoM0cgsLhiKVXMGn
         UTysHh5psFUWhljCCXShFyHZ0b2kVBarxUcyauXMJGZZlJ0+1351YKSTaimZEm/7dNyS
         +XTs5Ktf4AfQZEfu4bLRrKBTaIzbVWg6bCHSzp+I+Ja4MVofn/xsSIMAoCuhMQ0WcxVx
         J2D0ZvL0e2ZY9KfmOcxPHkMpggiV6/w+f7JuDuAk9IeLfZR8oMp6Gcyr+7BeM45rDKit
         sOrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aU2dtLHi;
       spf=pass (google.com: domain of 3qkqfxgukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3qkQfXgUKCacLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id h11si936308otk.0.2020.01.15.08.58.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 08:58:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qkqfxgukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id 38so11644729qty.15
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 08:58:19 -0800 (PST)
X-Received: by 2002:ac8:330e:: with SMTP id t14mr4605524qta.232.1579107498675;
 Wed, 15 Jan 2020 08:58:18 -0800 (PST)
Date: Wed, 15 Jan 2020 17:57:49 +0100
Message-Id: <20200115165749.145649-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.rc1.283.g88dfdc4193-goog
Subject: [PATCH -rcu] asm-generic, kcsan: Add KCSAN instrumentation for bitops
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	arnd@arndb.de, mpe@ellerman.id.au, christophe.leroy@c-s.fr, dja@axtens.net, 
	linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aU2dtLHi;       spf=pass
 (google.com: domain of 3qkqfxgukcaclsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3qkQfXgUKCacLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
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
The same patch was previously sent, but at that point the updated bitops
instrumented infrastructure was not yet in mainline:
 http://lkml.kernel.org/r/20191115115524.GA77379@google.com

Note that test_bit() is an atomic bitop, and KCSAN treats it as such,
although it is in the non-atomic header. Currently it cannot be moved:
 http://lkml.kernel.org/r/87pnh5dlmn.fsf@dja-thinkpad.axtens.net
---
 include/asm-generic/bitops/instrumented-atomic.h     | 7 +++++++
 include/asm-generic/bitops/instrumented-lock.h       | 5 +++++
 include/asm-generic/bitops/instrumented-non-atomic.h | 8 ++++++++
 3 files changed, 20 insertions(+)

diff --git a/include/asm-generic/bitops/instrumented-atomic.h b/include/asm-generic/bitops/instrumented-atomic.h
index 18ce3c9e8eec..eb3abf7e5c08 100644
--- a/include/asm-generic/bitops/instrumented-atomic.h
+++ b/include/asm-generic/bitops/instrumented-atomic.h
@@ -12,6 +12,7 @@
 #define _ASM_GENERIC_BITOPS_INSTRUMENTED_ATOMIC_H
 
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
 
@@ -39,6 +41,7 @@ static inline void set_bit(long nr, volatile unsigned long *addr)
 static inline void clear_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	arch_clear_bit(nr, addr);
 }
 
@@ -55,6 +58,7 @@ static inline void clear_bit(long nr, volatile unsigned long *addr)
 static inline void change_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	arch_change_bit(nr, addr);
 }
 
@@ -68,6 +72,7 @@ static inline void change_bit(long nr, volatile unsigned long *addr)
 static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_set_bit(nr, addr);
 }
 
@@ -81,6 +86,7 @@ static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
 static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_clear_bit(nr, addr);
 }
 
@@ -94,6 +100,7 @@ static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
 static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_change_bit(nr, addr);
 }
 
diff --git a/include/asm-generic/bitops/instrumented-lock.h b/include/asm-generic/bitops/instrumented-lock.h
index ec53fdeea9ec..2c80dca31e27 100644
--- a/include/asm-generic/bitops/instrumented-lock.h
+++ b/include/asm-generic/bitops/instrumented-lock.h
@@ -12,6 +12,7 @@
 #define _ASM_GENERIC_BITOPS_INSTRUMENTED_LOCK_H
 
 #include <linux/kasan-checks.h>
+#include <linux/kcsan-checks.h>
 
 /**
  * clear_bit_unlock - Clear a bit in memory, for unlock
@@ -23,6 +24,7 @@
 static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	arch_clear_bit_unlock(nr, addr);
 }
 
@@ -38,6 +40,7 @@ static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
 static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_write(addr + BIT_WORD(nr), sizeof(long));
 	arch___clear_bit_unlock(nr, addr);
 }
 
@@ -53,6 +56,7 @@ static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
 static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_set_bit_lock(nr, addr);
 }
 
@@ -72,6 +76,7 @@ static inline bool
 clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
 }
 /* Let everybody know we have it. */
diff --git a/include/asm-generic/bitops/instrumented-non-atomic.h b/include/asm-generic/bitops/instrumented-non-atomic.h
index 95ff28d128a1..8479af8b3309 100644
--- a/include/asm-generic/bitops/instrumented-non-atomic.h
+++ b/include/asm-generic/bitops/instrumented-non-atomic.h
@@ -12,6 +12,7 @@
 #define _ASM_GENERIC_BITOPS_INSTRUMENTED_NON_ATOMIC_H
 
 #include <linux/kasan-checks.h>
+#include <linux/kcsan-checks.h>
 
 /**
  * __set_bit - Set a bit in memory
@@ -25,6 +26,7 @@
 static inline void __set_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_write(addr + BIT_WORD(nr), sizeof(long));
 	arch___set_bit(nr, addr);
 }
 
@@ -40,6 +42,7 @@ static inline void __set_bit(long nr, volatile unsigned long *addr)
 static inline void __clear_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_write(addr + BIT_WORD(nr), sizeof(long));
 	arch___clear_bit(nr, addr);
 }
 
@@ -55,6 +58,7 @@ static inline void __clear_bit(long nr, volatile unsigned long *addr)
 static inline void __change_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_write(addr + BIT_WORD(nr), sizeof(long));
 	arch___change_bit(nr, addr);
 }
 
@@ -69,6 +73,7 @@ static inline void __change_bit(long nr, volatile unsigned long *addr)
 static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch___test_and_set_bit(nr, addr);
 }
 
@@ -83,6 +88,7 @@ static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
 static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch___test_and_clear_bit(nr, addr);
 }
 
@@ -97,6 +103,7 @@ static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
 static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch___test_and_change_bit(nr, addr);
 }
 
@@ -108,6 +115,7 @@ static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
 static inline bool test_bit(long nr, const volatile unsigned long *addr)
 {
 	kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic_read(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_bit(nr, addr);
 }
 
-- 
2.25.0.rc1.283.g88dfdc4193-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200115165749.145649-1-elver%40google.com.
