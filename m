Return-Path: <kasan-dev+bncBC7OBJGL2MHBBONPTPWQKGQE6SOZ2VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F144D8B57
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 10:41:29 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id c90sf13756729edf.17
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 01:41:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571215289; cv=pass;
        d=google.com; s=arc-20160816;
        b=VHve4BEzhlVoxSHy+Nz+V6SPXHu4UogZ5RLIVsxZQFTWdTKUZnJBwBC5kte8318zMu
         C18v7jL+Ajp7akq70ByST+OIACFUDkbYLnDeJdux9WMpOqk4owOZKPqc+pRJU/P26esL
         ZkosIHK41Y5CfP5ZzonbBPYMy9SsJUU5zL8eiKgZCNvTItoMLs31dsXXTiklc1jFwuxm
         B6iG0K69D7Qksru+Nff46wql6PNrshUfCBW4Kc3INdqybY+aYzZzwAIq2ueg3tqkLIG8
         6eVddLwT8nqSetaIx6kCebfoaZOzvOoACaSaMtG1JcGwNW84T1KrnnHQzXNeIiTugAQ3
         +4kQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=wfw1BOdM5x+AHS24jHHGv5yCCWezFz8frfEdvzEv7LM=;
        b=ASs84XCuEnuhaXRAl51Apo/t7nbSCHTUMTkIC94FfqjVUMth2F9+IVRd3FcVRhTWCy
         eha8b8SduKiZUAjIrWAD+mWmlCvfQzlf9STSUO8GHRGKIEmkaagnwBAMiv+myti2+SVv
         Ce0vw5LNsRFWFI6D4ZF64QUoIj4KpxXGDRu7gJZmpkJVwxPlDat+zVUjJmgAbmKELiax
         imRJ5of0Yj87riVbLffgc9qagoiivsKnz2aJMeplMIXqHHKkP0BpBDfcBr5sX7gJ6eHr
         G2LRuSY9N6GkCH2pAp0P1bK2/3dPZRT9OTlRoQ1qxBMqAwcMpePuoHgnBjTkShp43vGe
         QsXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ksjY6JoO;
       spf=pass (google.com: domain of 3t9emxqukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3t9emXQUKCfQahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wfw1BOdM5x+AHS24jHHGv5yCCWezFz8frfEdvzEv7LM=;
        b=e6PxpV0w6Bkq1/oXWTf6LDvqjmFs6nZhvtUckB8V9Cxh6wDX7AxvbF2aBiubhohj0S
         hjFRmamVVZArvKGYuBbkX6I36gz1r0XE8t4sHVB7J54+CKAjjqjE2qMim0VCIiy/ZIJZ
         DCKC+IAnJ8Mu6Oo8UI1kvACtU1QBYpiGyuqnVpRqty2mhduTpT7h8/MX2QvLcgiEl+As
         4X86sQoLM/zwCNk2uBtlP+bATiXu7h2UXfRicBHabSyvXxPG4wTvPy3A/rI+E59WPkW5
         M4APjoi/tZjW7J4rzD4uUCBk6NSFczFNUrfiTFzQKUnM6YlidfHYABDIGgU0KOCmvrDA
         IMFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wfw1BOdM5x+AHS24jHHGv5yCCWezFz8frfEdvzEv7LM=;
        b=aFNAbxhukVp7mMAV937BMH1vak1Z9FhN1rs/Mg8yWBU6YMEucETaUbGN8CUnI+ipTr
         ndDdgJunZsM/R5KDkFY9w4fwUBaDgie8l4oKVnDGBAPjzDhWg9Fv9LiWSl2+y34TwRAh
         hvLM1WykM7gxRrxtRs3W8RCcACHa/090THE0b1asZ4pdcPIGte4nsEsH81y2MfmpPcAz
         Rq567Id2uIUDqEl7FmgIaVDdZ2etCd52TKStGXi2ttJyopCJ1bYrLagjbEYz7ngs+uqZ
         ALs+c7DDtQskTn2b8tltN2gpV+/4f9psWIcPiDup0O4N4GYJVgoN9Sp3fnE5nI7gmpkd
         qK8w==
X-Gm-Message-State: APjAAAXFyZ4FKuYidQiLemocQaM/Ml1UFeDpp2fy7tDHi2/bhj297xDY
	E0HDHdDRufohzWfp1QRCn88=
X-Google-Smtp-Source: APXvYqxqd8++J4Mj2fbiVbJKQPOw7Rubw+vi+mvK/L4UPG9C2sP/nWQlXVuDjt2juH8tw1VCdK22CQ==
X-Received: by 2002:aa7:dd18:: with SMTP id i24mr38898998edv.239.1571215289079;
        Wed, 16 Oct 2019 01:41:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:d7a3:: with SMTP id pk3ls5363586ejb.3.gmail; Wed, 16
 Oct 2019 01:41:28 -0700 (PDT)
X-Received: by 2002:a17:906:c4a:: with SMTP id t10mr5130644ejf.290.1571215288521;
        Wed, 16 Oct 2019 01:41:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571215288; cv=none;
        d=google.com; s=arc-20160816;
        b=aZRR5CKDWqfsB23DfDodS7jRC+w3O8Flo7K0ThYQlbrEG5x3kO3HcIfYPOUIIEghSi
         dFkvTAs93q2A1kLXoL+wpbin4wWxjNA35F6+QkUrbCeegHPUtLvOOWCnFzGUwXsnZIX7
         /bcODE52OUF8BZkJeLLkqJ8YS7S8IWTx33vz4jf3yZXe2CRCzOsYrJPqcZqWXjdkm8gG
         AA4gMD81KF5rAvaIXbiWFCaOEHaLA7FN9MRlwmfIDdekAWrlRpM9J/aeSiSeyYyK+7m0
         1hjLck8tdydnSbja6VAxnV2F60wR3XD4wEqhePTpiWCPUtLsjpyRqbQBk17NinDUSL2f
         zAJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=3fadaJNY8io0I9mSUJYjT11edd0e7dEg1D1vHmOcbCo=;
        b=SZl6ABntvC6zJp0hJ0/Ao6bbu4tz9MO3gUrA6oLKzZcP/nabBqlciHmHSsgBhA44F4
         5WIxreSdJilUcmjs6gCNn4OmBbBmPFjU/CQewK1m/ulz8hOy74qNp4XC1Gvu5ZNZjlO6
         2dMOy2ZClxzc3thMRESrFadaBARBMxd6xUTtzZkxhVtOXuOAeyo6OJa2Y8Fn7eUJFysn
         8cHOVxdIqnRXY5Xhq6XNfjxKuSasY4FJknmqsLau+R9otxkJOTxflrZKl7De2Y+Oz+9o
         mJabRMoxzkBeuRcpqTIiXZtPNWgjsGMqzGsz/nt7AzaecFDGfkfH5cfCXBMumuYBpb2K
         NFHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ksjY6JoO;
       spf=pass (google.com: domain of 3t9emxqukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3t9emXQUKCfQahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id a27si1188149ejg.1.2019.10.16.01.41.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 01:41:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3t9emxqukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id f63so660926wma.7
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 01:41:28 -0700 (PDT)
X-Received: by 2002:adf:e688:: with SMTP id r8mr1726076wrm.342.1571215287907;
 Wed, 16 Oct 2019 01:41:27 -0700 (PDT)
Date: Wed, 16 Oct 2019 10:39:57 +0200
In-Reply-To: <20191016083959.186860-1-elver@google.com>
Message-Id: <20191016083959.186860-7-elver@google.com>
Mime-Version: 1.0
References: <20191016083959.186860-1-elver@google.com>
X-Mailer: git-send-email 2.23.0.700.g56cf767bdb-goog
Subject: [PATCH 6/8] asm-generic, kcsan: Add KCSAN instrumentation for bitops
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
 header.i=@google.com header.s=20161025 header.b=ksjY6JoO;       spf=pass
 (google.com: domain of 3t9emxqukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3t9emXQUKCfQahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
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
 include/asm-generic/bitops-instrumented.h | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-generic/bitops-instrumented.h
index ddd1c6d9d8db..5767debd4b52 100644
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
+	kcsan_check_atomic(addr + BIT_WORD(nr), sizeof(long), true);
 	arch_set_bit(nr, addr);
 }
 
@@ -41,6 +43,7 @@ static inline void set_bit(long nr, volatile unsigned long *addr)
 static inline void __set_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_access(addr + BIT_WORD(nr), sizeof(long), true);
 	arch___set_bit(nr, addr);
 }
 
@@ -54,6 +57,7 @@ static inline void __set_bit(long nr, volatile unsigned long *addr)
 static inline void clear_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic(addr + BIT_WORD(nr), sizeof(long), true);
 	arch_clear_bit(nr, addr);
 }
 
@@ -69,6 +73,7 @@ static inline void clear_bit(long nr, volatile unsigned long *addr)
 static inline void __clear_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_access(addr + BIT_WORD(nr), sizeof(long), true);
 	arch___clear_bit(nr, addr);
 }
 
@@ -82,6 +87,7 @@ static inline void __clear_bit(long nr, volatile unsigned long *addr)
 static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic(addr + BIT_WORD(nr), sizeof(long), true);
 	arch_clear_bit_unlock(nr, addr);
 }
 
@@ -97,6 +103,7 @@ static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
 static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_access(addr + BIT_WORD(nr), sizeof(long), true);
 	arch___clear_bit_unlock(nr, addr);
 }
 
@@ -113,6 +120,7 @@ static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
 static inline void change_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic(addr + BIT_WORD(nr), sizeof(long), true);
 	arch_change_bit(nr, addr);
 }
 
@@ -128,6 +136,7 @@ static inline void change_bit(long nr, volatile unsigned long *addr)
 static inline void __change_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_access(addr + BIT_WORD(nr), sizeof(long), true);
 	arch___change_bit(nr, addr);
 }
 
@@ -141,6 +150,7 @@ static inline void __change_bit(long nr, volatile unsigned long *addr)
 static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic(addr + BIT_WORD(nr), sizeof(long), true);
 	return arch_test_and_set_bit(nr, addr);
 }
 
@@ -155,6 +165,7 @@ static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
 static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_access(addr + BIT_WORD(nr), sizeof(long), true);
 	return arch___test_and_set_bit(nr, addr);
 }
 
@@ -170,6 +181,7 @@ static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
 static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic(addr + BIT_WORD(nr), sizeof(long), true);
 	return arch_test_and_set_bit_lock(nr, addr);
 }
 
@@ -183,6 +195,7 @@ static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
 static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic(addr + BIT_WORD(nr), sizeof(long), true);
 	return arch_test_and_clear_bit(nr, addr);
 }
 
@@ -197,6 +210,7 @@ static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
 static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_access(addr + BIT_WORD(nr), sizeof(long), true);
 	return arch___test_and_clear_bit(nr, addr);
 }
 
@@ -210,6 +224,7 @@ static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
 static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic(addr + BIT_WORD(nr), sizeof(long), true);
 	return arch_test_and_change_bit(nr, addr);
 }
 
@@ -224,6 +239,7 @@ static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
 static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_access(addr + BIT_WORD(nr), sizeof(long), true);
 	return arch___test_and_change_bit(nr, addr);
 }
 
@@ -235,6 +251,7 @@ static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
 static inline bool test_bit(long nr, const volatile unsigned long *addr)
 {
 	kasan_check_read(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic(addr + BIT_WORD(nr), sizeof(long), false);
 	return arch_test_bit(nr, addr);
 }
 
@@ -254,6 +271,7 @@ static inline bool
 clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
 {
 	kasan_check_write(addr + BIT_WORD(nr), sizeof(long));
+	kcsan_check_atomic(addr + BIT_WORD(nr), sizeof(long), true);
 	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
 }
 /* Let everybody know we have it. */
-- 
2.23.0.700.g56cf767bdb-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191016083959.186860-7-elver%40google.com.
