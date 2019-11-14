Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKNOW3XAKGQE2YGQWDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9958AFCC98
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 19:04:26 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id a200sf5496920ybg.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 10:04:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573754665; cv=pass;
        d=google.com; s=arc-20160816;
        b=zGxWOai3eBP8CqeDxDy61T4dqIBMvesLJQ+N/OFr0TzgHbOQsJTSzesmKExDNRA/T5
         M839J+i9wFSqf999rntiwxdUbwlR7KH7uuSR1lnwS+/EpyIOoicJJNXkV1z/xUIRdLqa
         O4+ZVjTWzy4N9p+ksNt/bsFZ1R8eXBVKIGuWwF/2qIJKSp/FzkQ532hbffNRSrUjrAhD
         jiZfSsMCveehB5Ugol55p86Zol3HThGEPDlQlPm7AtjGNvV3KY4+v9BwMKVRjZXjNZpZ
         pjvIpD+vC4uEfE+T24NfUWuT/NfQ52NN1FfF3ESiYW6XuwM+8AO3cAtAsN5tLC3Uz5LO
         Song==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=PbPmgpVfXyaZNnIlrt2eEi4o0L2+7E/7slBxV28KPG0=;
        b=LmY78nYDW+SHfRSerLqriv/kdGZlHyA58FochDKoimcHrnRvbPD4Q83twzPyt0+ee7
         moWpKe5dpHRVwylj0dKaVER5ixpUr06xNAIF8/Fbv4Wy8WM/RV5NiUiDkfYqBe9mNT/O
         XI0XwJa5WzyQF09dKTrYFOuWt3RWoA5zbMmiLkbIhMCatLoOKboZ5WEQixy1ow0vlB0+
         fHzkjyFO9rmjIGWMHX7Uf8LN9/nLRYh/6ax039dvFyyJFm689s0KQAWuoylMSXAl8/sD
         43ANQzVp0if6d8u6RjPEodW8QqI3cHTF3rp0cUOLffmdN+QszoFIk85+mY4p3qbajQgM
         V8Jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=est4K7iO;
       spf=pass (google.com: domain of 3kjfnxqukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3KJfNXQUKCYEjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PbPmgpVfXyaZNnIlrt2eEi4o0L2+7E/7slBxV28KPG0=;
        b=sdBrj8lL4Jau6mjKxJZc6dk6FvXBEyiy5BKAQl31OgcTQv5ym3VU3s2MmW1DUrujli
         KpEyQk4Su3XTCY2wWXUzQ0q264dPUWI2kVr1A3IiIBYAKGiPwIQDb7ce8Xhuow1ml8DJ
         sXc9r3DhRpL8qbkXjD6yfcX4kqDsraY6wBVu+xNbOm6joH52VdtAHXprF/TYfiY30ax/
         ryXorAqQLphKr8WJb/TQQM1J5uR0AJJSHiVS+AP1rqeBDtgN3RI/JoPzmBbvh8oThGm/
         xk95H5CGn5VzV1qNECsYTfMFz8aMVoAkwYrertrlIPj+s3RPC6nkX7hkW2NooFxpAzxB
         7fJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PbPmgpVfXyaZNnIlrt2eEi4o0L2+7E/7slBxV28KPG0=;
        b=O2lUWP13S7xo3uksiFXHYFQvik+j7MAl2xFev/YM+kxlNT/ZyhO2FjXc3WvH5VGDDk
         OYFL+2Zx9N4RbUHRiOIYhMn0yNgiel2IuMgcmEcO/PBzmyqfVgu4GjATdekKxd0DLPRj
         OqlWKP62n1HO0pRcNJwak4uDiqI1ovyI5ZAGf33W74ngWrWaJzfgExVhwLZysgTbOM8/
         vlUNja9Lq6ZFf3sMxhsF1og5WX8DjFME4DdwxsMcMSAxWvuo6jKic6F9yOPnjwthdyXa
         7dMFSK/Av2EtoCdoV82684IqTnqIeof+dmTqSGkzclUMucuUQ0rmbpAALFdUwiIX/ADp
         4z/Q==
X-Gm-Message-State: APjAAAX9WKjcxElRMW5mIZpfoi7hioxjfhYap7cQGAi4rOkxTbfDIxh8
	E7N6Y9nXgGEC45ENrAn6Dig=
X-Google-Smtp-Source: APXvYqzqZpjuSpnJ30NWOefW/FcDRQ//W3eRR6GOFURiT3YQES0ms/VoY/it8XEOQj1C6l4OjWXEOQ==
X-Received: by 2002:a81:784a:: with SMTP id t71mr6501361ywc.414.1573754665285;
        Thu, 14 Nov 2019 10:04:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2acb:: with SMTP id q194ls552167ybq.14.gmail; Thu, 14
 Nov 2019 10:04:24 -0800 (PST)
X-Received: by 2002:a25:3d83:: with SMTP id k125mr8244687yba.226.1573754664866;
        Thu, 14 Nov 2019 10:04:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573754664; cv=none;
        d=google.com; s=arc-20160816;
        b=vcQp5rLM61LLMi2zwxG0g/6box4DexxBoJEf33xptd/uo0FPIIZ98htt3vIMc/aiBd
         I3VPofyrnWw/O+x3J8sidZ2mfr91ANH5hJ+aPvQXpYgkLE9wDOpmwvVINUi51/WGhCm2
         VnFTvSWIL+P5qIrj5fT/WSorLmjypAGkTRpNcGT2vIiFzqQjV6QedvVeVLngXliAJkBX
         oJKDrj8LT6juGrSWX0BzA14M1SvsVp+cv6CkIzD0FiShHVjnu8Rb5QE4y2p+y62rPY1H
         5df7n6Jo/5q6a2XGVhrFCsnoOwrJsTYaAwjIm+IvBjhCwTZCTSbaMx0yrt1XVEArVTf4
         /u1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=xAkKRCl18dUtGLIegx101F8gMb+vbOn4Uh1MduUK+cA=;
        b=QIRi033ba2l4gX1l+hQ7GS0iCozuo3iYUDf2YgJd3Rn26TIhY3QF1bcQcX6xPpEAjp
         A3BosLz21MlaUuxoQKATf2Y9lBUlcPyJ075pqx5oHC4S/in2ZaCtndqBYL/84DcXSRew
         WIa8vcZL9SUZEPQA2cPRZyXuZYVHDYJCN0lcNATmeWtVRQhW0gE3khsCrJybYgHEt4VN
         YHjWJYtOriEWNk/azXiQfxiTr3KfCwiBGwssizYc88MiujKZKVuJvzg8L1IaWNvOjXOT
         p5UIKjGtZWRR4CzZ+Vf6kly4GeLP/lLwmvxqQo0ZB69MC73gRZvZldBKpE5I6h24o6Cd
         NpCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=est4K7iO;
       spf=pass (google.com: domain of 3kjfnxqukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3KJfNXQUKCYEjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id f184si437406ybg.3.2019.11.14.10.04.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 10:04:24 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kjfnxqukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id g5so4543680qtc.5
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 10:04:24 -0800 (PST)
X-Received: by 2002:ac8:6697:: with SMTP id d23mr9028830qtp.32.1573754664102;
 Thu, 14 Nov 2019 10:04:24 -0800 (PST)
Date: Thu, 14 Nov 2019 19:03:01 +0100
In-Reply-To: <20191114180303.66955-1-elver@google.com>
Message-Id: <20191114180303.66955-9-elver@google.com>
Mime-Version: 1.0
References: <20191114180303.66955-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.rc1.363.gb1bccd3e3d-goog
Subject: [PATCH v4 08/10] asm-generic, kcsan: Add KCSAN instrumentation for bitops
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
	tglx@linutronix.de, will@kernel.org, edumazet@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-efi@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=est4K7iO;       spf=pass
 (google.com: domain of 3kjfnxqukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3KJfNXQUKCYEjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
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
Acked-by: Paul E. McKenney <paulmck@kernel.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114180303.66955-9-elver%40google.com.
