Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX6IQ3ZAKGQEGKKSCZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 11B951582E5
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 19:43:44 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id v10sf736984lfa.14
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 10:43:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581360223; cv=pass;
        d=google.com; s=arc-20160816;
        b=YvmoRb8cabLZyDJnzlDZZzI4neHjLg5KuGMvhQqB/6DiLCV16k+wEFBmZ1kLCYm2Cl
         v8EU4HWwRdCIDmJu7K9F43GpCa3cEo7GrBIGrl1odZyKOTZ9+y3zdnN50fbfU2pwmZ99
         zf1L3i8PBAAtw9rOKyb4vCJbqQk7RuWBKMM2ECX0YeIrqmZSt4iT3plvcJdgIpW35Sjs
         yALMDvqsvv9rXBGvu+2UTKvGwf3yhRKNNS6wj8OphMp0J/8r2aU/NTLiUE5wE29v25qa
         jMEW9n3pL/Jy3SW632IE3sfhTWCiuiYGAAJnG6tAW6I6psbl4enwWnDjy+BuEd7C9014
         NAKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=LQvSyH9VLxoUXrTCqFgMUrCo+KEn/i5uRI/HWbDqcvs=;
        b=tqeXKlE4d8NY5Ez1Vzk/5ili0TQJWlCoIa0MmXE88dYs1pp6qcYkifrYNDJyhty+Jj
         ormRLrQOqMDC/p2MjhQBFDKidIFavvaW7cPk6bEqvA1IoXS2Laeh+ZrhB3wBQcC53ldA
         vFQ1m5mOCF624aoGscG2Y1W05X1KYFlMGSp8hWrfsdJ5SvlkP5rd9vNBuWTUWBDWP9Q9
         q24jhF0m202GAZHK2k1a43WH/7xW6MUAvAuDsdQjRxSXxlSD0dNciQFVHroJCJmPL5Ek
         deTaBLMYCgxLGFKaJwn00x+c505L+27rBwunhTPKlViGgZrIKTrrYgZOJx1RdL9kwkmr
         K0Dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sB5OY1dU;
       spf=pass (google.com: domain of 3xarbxgukcaqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3XaRBXgUKCaQIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LQvSyH9VLxoUXrTCqFgMUrCo+KEn/i5uRI/HWbDqcvs=;
        b=hPe5t6bAknl3sPiTgP688lRzi6hRjqWdOwr0zEbn7hJRSET3ZgtRCDJKHB8nLLNv63
         4GofEvAEXtbwAAmLe4StSH6t0HimjsaZAiiBJRF64Io3qRIoU1jq5qBV5ogqfhGxxIGf
         ia9T9aocGsNv90mwEudfDA1sE/kXGGCMZ13WkYXfuFteeLLOCfEn+ymaNZf88jxTD/eJ
         BjxbLhmiMhZDrtWalSxnXUSRtt4RK1pmZyqINGI7co9YBfxTGYMFSPvFtr9yS4dc75X8
         UHemwH2SLh/PpSlmkJJZbXy8iBtwg1Z/MIDhbY34iz8LhWRiksX0bxZIRzVHX+qXb8Bq
         oIOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LQvSyH9VLxoUXrTCqFgMUrCo+KEn/i5uRI/HWbDqcvs=;
        b=pyp9IgMNuywXMGJ/H0WP/WBq9q8Rd4A7yK5Gni3ZqkzY+IBWwAR5SftKe80HhpKJ7s
         OwZMH47ehkp2m+nlx5e8RAAqgv7Cf8Ve0P7ZQEjmLHHWRJUZJOZnd1fAsDwrCQaOjhdM
         yJONgSnFmJZYeyChJ4EP5YWNfpX3Q9oTj95IbUQLhiK5x7N437X2cKwBdHFNkVrHKNjG
         MzqdHwTP1bhllseCYsSh2rHXBv8WL/O9snDkClMrsG1MzmZQEAlAhons+2fwK9aNqYvP
         WA+pUEGFodVZLH9QOxNU4JX8fj5/JQv6Ithkny6S5Bt4/9PcfS4ys7ze+az+u937rV1k
         /mFQ==
X-Gm-Message-State: APjAAAXJCXeXsak+p+BB7bzNZx9TXmhZOgOnIBTOpqZGfj2KZJ2KkQvB
	kxuQ3mQ8/O/KhIl8tuKEHoA=
X-Google-Smtp-Source: APXvYqzjXAwmA3rFdghqueOEMzahSJrxMAZv8ebXV1Hfnk6VZ6V2FMTB4sghj6MLPJEwH4uH9SBHFg==
X-Received: by 2002:a2e:81c3:: with SMTP id s3mr1769180ljg.168.1581360223614;
        Mon, 10 Feb 2020 10:43:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1051:: with SMTP id x17ls1617111ljm.8.gmail; Mon,
 10 Feb 2020 10:43:42 -0800 (PST)
X-Received: by 2002:a2e:8758:: with SMTP id q24mr1769541ljj.157.1581360222766;
        Mon, 10 Feb 2020 10:43:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581360222; cv=none;
        d=google.com; s=arc-20160816;
        b=A+xFh2pILUJXxNok+5MPbGhmBjhVjBJM+MN62y46w7BadPWpGxxoEodeBuwIBPVIsj
         UBn5GIH7hyphaSCY8PM+iniB/jhFJyGJpdE4KHys280C/lVx74v8wEpLYy/Re9VS40eL
         9hmAsQag/1lNo10VaPwWy2Mz3YEUWWfnHragJKgUg2Y5KtPtwybxSnD45QrJJE8EYgbJ
         Gs/oSZl1fsZwx/vKCYoNiRWoJN1KMVJvmUAadNr5CEU3Y5Ok8LaakdyPvaOeaC+uuTO7
         Ls6TP0s/s1Mj9cs6OA5K1JFpbRfoWAckwCFXYRywcktFYQrF/9yAZldZma4OkV3U0JMA
         MVDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ekjMPPG/6GfXWp+1AYZk+dASF82ToWENMAHOLhIQ8HA=;
        b=Ba6AWqdbQpdfIY4lUUPpI/juk7mM6uZ3IylC6aKHgdYiwiSI2ZdAZVXGIJyTVSnUAZ
         5G5xg3HfRuPur49u2wK+Z4ENmmjoGYU+jxL9IpR2OGleoODZ9Qi+ofxUfeGJDxiyUYar
         O2WucNUu2TU7B0DKYqOwzU5g9UIz9M1ky9XfTvB2TXBT9jpxFxv7gvbMVAqgtfZUEf1h
         ncHCJ3bvdI/yTdpMHA9NfPFVKWXvHKovD+2ucNPoNnfVYvkQy92RdAMB0k73h58WT+gF
         yWZygsdXWn1AQCQVSI0sBM3oNE8J6Bb8F+++ISN4YI1v6g/U4xOq8/G8ICUPSdDA3m04
         t8sA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sB5OY1dU;
       spf=pass (google.com: domain of 3xarbxgukcaqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3XaRBXgUKCaQIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id b29si80109lfo.2.2020.02.10.10.43.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 10:43:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xarbxgukcaqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id d8so5439395wrq.12
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 10:43:42 -0800 (PST)
X-Received: by 2002:a5d:4d0a:: with SMTP id z10mr3276542wrt.253.1581360221843;
 Mon, 10 Feb 2020 10:43:41 -0800 (PST)
Date: Mon, 10 Feb 2020 19:43:17 +0100
In-Reply-To: <20200210184317.233039-1-elver@google.com>
Message-Id: <20200210184317.233039-5-elver@google.com>
Mime-Version: 1.0
References: <20200210184317.233039-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH 5/5] kcsan: Introduce ASSERT_EXCLUSIVE_BITS(var, mask)
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, Jan Kara <jack@suse.cz>, 
	John Hubbard <jhubbard@nvidia.com>, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sB5OY1dU;       spf=pass
 (google.com: domain of 3xarbxgukcaqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3XaRBXgUKCaQIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
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

This introduces ASSERT_EXCLUSIVE_BITS(var, mask).
ASSERT_EXCLUSIVE_BITS(var, mask) will cause KCSAN to assume that the
following access is safe w.r.t. data races (however, please see the
docbook comment for disclaimer here).

For more context on why this was considered necessary, please see:
  http://lkml.kernel.org/r/1580995070-25139-1-git-send-email-cai@lca.pw

In particular, data races between reads (that use @mask bits of an
access that should not be modified concurrently) and writes (that change
~@mask bits not used by the read) should ordinarily be marked. After
marking these, we would no longer be able to detect harmful races
between reads to @mask bits and writes to @mask bits.

Therefore, by using ASSERT_EXCLUSIVE_BITS(var, mask), we accomplish:

  1. No new macros introduced elsewhere; since there are numerous ways in
     which we can extract the same bits, a one-size-fits-all macro is
     less preferred.

  2. The existing code does not need to be modified (although READ_ONCE()
     may still be advisable if we cannot prove that the data race is
     always safe).

  3. We catch bugs where the exclusive bits are modified concurrently.

  4. We document properties of the current code.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: David Hildenbrand <david@redhat.com>
Cc: Jan Kara <jack@suse.cz>
Cc: John Hubbard <jhubbard@nvidia.com>
Cc: Paul E. McKenney <paulmck@kernel.org>
Cc: Qian Cai <cai@lca.pw>
---
 include/linux/kcsan-checks.h | 57 ++++++++++++++++++++++++++++++++----
 kernel/kcsan/debugfs.c       | 15 +++++++++-
 2 files changed, 65 insertions(+), 7 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 4ef5233ff3f04..eae6030cd4348 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -152,9 +152,9 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
 #endif
 
 /**
- * ASSERT_EXCLUSIVE_WRITER - assert no other threads are writing @var
+ * ASSERT_EXCLUSIVE_WRITER - assert no concurrent writes to @var
  *
- * Assert that there are no other threads writing @var; other readers are
+ * Assert that there are no concurrent writes to @var; other readers are
  * allowed. This assertion can be used to specify properties of concurrent code,
  * where violation cannot be detected as a normal data race.
  *
@@ -171,11 +171,11 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
 	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
 
 /**
- * ASSERT_EXCLUSIVE_ACCESS - assert no other threads are accessing @var
+ * ASSERT_EXCLUSIVE_ACCESS - assert no concurrent accesses to @var
  *
- * Assert that no other thread is accessing @var (no readers nor writers). This
- * assertion can be used to specify properties of concurrent code, where
- * violation cannot be detected as a normal data race.
+ * Assert that there are no concurrent accesses to @var (no readers nor
+ * writers). This assertion can be used to specify properties of concurrent
+ * code, where violation cannot be detected as a normal data race.
  *
  * For example, in a reference-counting algorithm where exclusive access is
  * expected after the refcount reaches 0. We can check that this property
@@ -191,4 +191,49 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
 #define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
 	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
 
+/**
+ * ASSERT_EXCLUSIVE_BITS - assert no concurrent writes to subset of bits in @var
+ *
+ * [Bit-granular variant of ASSERT_EXCLUSIVE_WRITER(var)]
+ *
+ * Assert that there are no concurrent writes to a subset of bits in @var;
+ * concurrent readers are permitted. Concurrent writes (or reads) to ~@mask bits
+ * are ignored. This assertion can be used to specify properties of concurrent
+ * code, where marked accesses imply violations cannot be detected as a normal
+ * data race.
+ *
+ * For example, this may be used when certain bits of @var may only be modified
+ * when holding the appropriate lock, but other bits may still be modified
+ * concurrently. Writers, where other bits may change concurrently, could use
+ * the assertion as follows:
+ *
+ *	spin_lock(&foo_lock);
+ *	ASSERT_EXCLUSIVE_BITS(flags, FOO_MASK);
+ *	old_flags = READ_ONCE(flags);
+ *	new_flags = (old_flags & ~FOO_MASK) | (new_foo << FOO_SHIFT);
+ *	if (cmpxchg(&flags, old_flags, new_flags) != old_flags) { ... }
+ *	spin_unlock(&foo_lock);
+ *
+ * Readers, could use it as follows:
+ *
+ *	ASSERT_EXCLUSIVE_BITS(flags, FOO_MASK);
+ *	foo = (READ_ONCE(flags) & FOO_MASK) >> FOO_SHIFT;
+ *
+ * NOTE: The access that immediately follows is assumed to access the masked
+ * bits only, and safe w.r.t. data races. While marking this access is optional
+ * from KCSAN's point-of-view, it may still be advisable to do so, since we
+ * cannot reason about all possible compiler optimizations when it comes to bit
+ * manipulations (on the reader and writer side).
+ *
+ * @var variable to assert on
+ * @mask only check for modifications to bits set in @mask
+ */
+#define ASSERT_EXCLUSIVE_BITS(var, mask)                                       \
+	do {                                                                   \
+		kcsan_set_access_mask(mask);                                   \
+		__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT);\
+		kcsan_set_access_mask(0);                                      \
+		kcsan_atomic_next(1);                                          \
+	} while (0)
+
 #endif /* _LINUX_KCSAN_CHECKS_H */
diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 9bbba0e57c9b3..2ff1961239778 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -100,8 +100,10 @@ static noinline void microbenchmark(unsigned long iters)
  * debugfs file from multiple tasks to generate real conflicts and show reports.
  */
 static long test_dummy;
+static long test_flags;
 static noinline void test_thread(unsigned long iters)
 {
+	const long CHANGE_BITS = 0xff00ff00ff00ff00L;
 	const struct kcsan_ctx ctx_save = current->kcsan_ctx;
 	cycles_t cycles;
 
@@ -109,16 +111,27 @@ static noinline void test_thread(unsigned long iters)
 	memset(&current->kcsan_ctx, 0, sizeof(current->kcsan_ctx));
 
 	pr_info("KCSAN: %s begin | iters: %lu\n", __func__, iters);
+	pr_info("test_dummy@%px, test_flags@%px\n", &test_dummy, &test_flags);
 
 	cycles = get_cycles();
 	while (iters--) {
+		/* These all should generate reports. */
 		__kcsan_check_read(&test_dummy, sizeof(test_dummy));
-		__kcsan_check_write(&test_dummy, sizeof(test_dummy));
 		ASSERT_EXCLUSIVE_WRITER(test_dummy);
 		ASSERT_EXCLUSIVE_ACCESS(test_dummy);
 
+		ASSERT_EXCLUSIVE_BITS(test_flags, ~CHANGE_BITS); /* no report */
+		__kcsan_check_read(&test_flags, sizeof(test_flags)); /* no report */
+
+		ASSERT_EXCLUSIVE_BITS(test_flags, CHANGE_BITS); /* report */
+		__kcsan_check_read(&test_flags, sizeof(test_flags)); /* no report */
+
 		/* not actually instrumented */
 		WRITE_ONCE(test_dummy, iters);  /* to observe value-change */
+		__kcsan_check_write(&test_dummy, sizeof(test_dummy));
+
+		test_flags ^= CHANGE_BITS; /* generate value-change */
+		__kcsan_check_write(&test_flags, sizeof(test_flags));
 	}
 	cycles = get_cycles() - cycles;
 
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200210184317.233039-5-elver%40google.com.
