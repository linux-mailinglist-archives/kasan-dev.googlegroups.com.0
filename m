Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNNEXLXAKGQETB45D3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 920EAFDCBC
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 12:55:33 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id v13sf3032080lfq.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 03:55:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573818933; cv=pass;
        d=google.com; s=arc-20160816;
        b=qrLgbE7krgUs5Cqltmpi0wQ/rNgdDvOODLLo0Nes6T3OzFXFLnc7TaLohTzI3VeRsV
         5pnvuwuenYEJswB5XQ+XBwCLXHeQZODU9zyRRCcNmkTDMqhznWJBEdpLV3KPgah8Pk7S
         XgEHyHAwKXKVImfM8AepyvfuYNGCzR+ZUrMNz0kV7V7bkDWWyJk0+gJ2bQm1aJohToSO
         F99WVch2StYKZg+dgnsOHuFFv4fwE0MhSY7jwDR2ONqr+yhfIW5JyYPwdkLjxPE/L7Hh
         AVBLCfKuSg+8inn+ouSc5j75MbY8JGP6rDprNVJ+V7Sr+rHcuwM68HA/seLP8DWdyJWO
         jjuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:to
         :from:date:dkim-signature;
        bh=RTyNAB+v2cv2prRWlMfWu96bCntWN8vnTLpXEH3ajws=;
        b=YLaDtenTMHbraz68Gby2fmWvQhwwJ/f7varagwxkqa84eYRTX6E7UfPmjNiBfxWU+d
         z3dNjUNUg6tlW4FJLPuwLxyl0gGE969SjICxW1Kx2+PCLGAyIoefny3HAl5R6qJIwo2t
         e2cNu58so6KrEdziXItL5m79sJwrVnOtxY0Px5h4DwLLNg1vUzv33asX83omSMtWMlgg
         WauuZcDLwxXwj19dFwE8gR3udc3kBh4FIiNP+GjAQq1unAjtwekHb/uQdKE2JKNk8sx1
         5pUSgS62FlbFbxRRNWEN3Z17L0jIspvVX9x6RrF0qchEFDSmu6s+ZJpVXpmvjp4bUuv2
         Qncw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d37xtxs0;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=RTyNAB+v2cv2prRWlMfWu96bCntWN8vnTLpXEH3ajws=;
        b=MRk0rbcQHSN9hjn8ZClk3H5gPuMc6gPohr3Rb6ubOjdQNuAK1k3z/2bI5ciP5tdJkD
         lV9H7yT4jvrFm4PPtbKKZYGZ5vtj6+srjTrIfm3CST/yQrJHe9b9RoYyh1o2SlHXvTTX
         XCl8NqAdVrfqsJamhmgyTgzhQvVIuyB+lUtGfJaPvUizgMYIv4BJ1JMSNqErpQGHaLdQ
         plHNfE9dv/563UVn7VxfvDcr0fM9NaRgKxqltXECzZVv5wnCZpY6YeV28vCc4NIxTMFP
         IFpMY3iYVoRNKjQ8pYEOSa7SJAqyDoRX2p3zhRtZIadi5/4l2mVqpoUB+CcN7Ouliztb
         QfHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RTyNAB+v2cv2prRWlMfWu96bCntWN8vnTLpXEH3ajws=;
        b=SdWnf8eUTYUg6x7RoJ4aBMbmaQG6yj46LvUsl9gOdvPcQZjAm7Sw5mDTcjqOQ2Grw2
         NRhQoemj2WdkLWEw+83lJnknirdow1MSMm/J06NIwHjaLgtBYSf/k7jBa0KxHN3nYP1q
         Wr2eoABZcllqI92ceN5dJty/pl6LLpqsWJVAIS69dHctoflz5C1savswHzmvA7kvde+d
         FzadBLsO89RP02r6Qmmltd54ELqIycKUjEnyjQycAaeLS5zQ52ZrJa2rMLF/YKWaHTGe
         IAB5L8gfAHqfRv/jrRLW2xn8hkeas1rWrrwycKLBH3u8VlU6kMeCoLPmn0n9KVzMVfoE
         yLcQ==
X-Gm-Message-State: APjAAAVRn5RIbmIrKZhQ5GCJcgR0wx6K2oHHEejltpnFWVBLUD1vJMnX
	0bIB01/O9S5Gf5LcCSRG9uo=
X-Google-Smtp-Source: APXvYqwCgtyZVokQwsLFGRJSEz7ny5/SMo3Ti2eJHWwtTj680KTPp4EVUAzE5CXhVc6jrmSaghISbA==
X-Received: by 2002:a2e:9083:: with SMTP id l3mr11114198ljg.127.1573818933181;
        Fri, 15 Nov 2019 03:55:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:40d7:: with SMTP id n206ls1686739lfa.10.gmail; Fri, 15
 Nov 2019 03:55:32 -0800 (PST)
X-Received: by 2002:ac2:5503:: with SMTP id j3mr2210138lfk.8.1573818932424;
        Fri, 15 Nov 2019 03:55:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573818932; cv=none;
        d=google.com; s=arc-20160816;
        b=r/bXFXqbncyAw6fn8Mm33UUApV3rpcK+EFvPTtXkr0jB5l5I12W2CuW5OL2XLLE1aT
         jsBnvs6mYZ8saCCNI6nIC3fXxh5lkGo/eoqvkMhekEf/MAfguIafBbH+3bnaJadVkYkj
         BSw/gF/gz8zUDdd5x4gluSYMCWSAmucgVHsfwIQB+qPCqQ9qNM/gG7cFRTE7/yCkRH7N
         4MEBD1TFAoJR1IrUUG+H+zWzZt6hZrpw1cdZfuN1rZb12NsR6iOwxRYdlX/ohyrtF7ZM
         y4KmwLSLtPa+g0eIR73THO8NVvx8cjhKV4IwR/pAaIUUMwwi9rGfqjLiM5uq3Z1JZlKT
         IPyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:to:from:date:dkim-signature;
        bh=Y2n2+Uz9lfxeIcRjHd5xKcgiwSj7xMIx4TZvu7ih+9A=;
        b=K7DUQ57D7efCXvprDQYbWAHzUrfhkFFD707bsMDf2Oy2VBF8jX/JxPRE4z58zlzHce
         SxuH3ifzOxP3b2KF/uoZTFkr/QSWwI1l634eNeLXw1EDpqXnyY+6PCEvDT+wCE7yqQXN
         N748umI/qKDMnw3nhdwhS8+qmq0j3ps5PwGELnbqxFdf6iMFT6dS3ckP6+0f6uduweLm
         SGSQfZ/vsoR6XqN8qTLUIhzCc4BVbvuJMao6+XIhtqHwzPo5dFWYUe2TyNwOD4QFWfi1
         GK2YgMBx8NKE6dKkidWOBltPpcGzkc9ZGPYAhIBRtY+vKPj5+JHnifwDpyWQEq7TMJoP
         BvHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d37xtxs0;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id h21si660135lja.5.2019.11.15.03.55.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Nov 2019 03:55:32 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id b17so10088636wmj.2
        for <kasan-dev@googlegroups.com>; Fri, 15 Nov 2019 03:55:32 -0800 (PST)
X-Received: by 2002:a1c:6a0d:: with SMTP id f13mr14719193wmc.164.1573818931176;
        Fri, 15 Nov 2019 03:55:31 -0800 (PST)
Received: from google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id d202sm8926257wmd.47.2019.11.15.03.55.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Nov 2019 03:55:30 -0800 (PST)
Date: Fri, 15 Nov 2019 12:55:24 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com,
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org,
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com,
	bp@alien8.de, dja@axtens.net, dlustig@nvidia.com,
	dave.hansen@linux.intel.com, dhowells@redhat.com,
	dvyukov@google.com, hpa@zytor.com, mingo@redhat.com,
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net,
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com,
	npiggin@gmail.com, paulmck@kernel.org, peterz@infradead.org,
	tglx@linutronix.de, will@kernel.org, edumazet@google.com,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-efi@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v4 08/10] asm-generic, kcsan: Add KCSAN instrumentation
 for bitops
Message-ID: <20191115115524.GA77379@google.com>
References: <20191114180303.66955-1-elver@google.com>
 <20191114180303.66955-9-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191114180303.66955-9-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=d37xtxs0;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

Signed-off-by: Marco Elver <elver@google.com>
---
Tentative version of the bitops patch that applies with the new
instrumented bitops infrastructure currently in linux-next. (Note that
that test_bit() is an atomic bitop, but is currently in the wrong
header.)

Otherwise there is no functional change compared to v4 that applies to
mainline.

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
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191115115524.GA77379%40google.com.
