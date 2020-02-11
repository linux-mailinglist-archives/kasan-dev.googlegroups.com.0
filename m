Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2VBRPZAKGQEUXBJ5EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id E92FB159454
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 17:06:03 +0100 (CET)
Received: by mail-ua1-x93f.google.com with SMTP id a30sf2741450uae.6
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 08:06:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581437163; cv=pass;
        d=google.com; s=arc-20160816;
        b=jSghOocMIjZ+m8v+ifgRaDjEoUp/bbbedD1qQ9/IpDPguJUR0KOTofZ5SusZwFTMFU
         RtK4Du/GYQXagwa2RFn+PbXxUCL79jNyKNGDTjWrCzdNPM9UqH9gdQmx5Qt+SEsTiiN5
         ysFP7Euf8hwX/bZLGE1F1Q9S6Q2sF5ijI3O2csvCFD9PyAQ8C1zFlkFjWcJmpcO6qWPV
         enWG5YLAng0N/hI8vuctluWbrf/vMRhDD6zH6E6knbYJOXVg5GjBJG7r9Yzaq9BufZ/T
         PpDHYURm+F2qluPlYzlZPNNNKD3hVIGEJirFATi5xet3Dj27skr2Y0pXyIqumx/ZCn70
         iYMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=LQZ2rHNpysGsKDHWdSZdGg82amlkQapSaLesy9XTKfQ=;
        b=roj+awCq81mEoZJkG9L8aCxxoRakqeV05SAVbINSgjC8mQrTIm759YOt3nxItZxxbX
         AnE5FM8CEtqhQH5ogPSaC3q1mcV0xC56X9e0WQqInnlTloG7oEBGuv0eM65/hv4j9tsB
         fsAvr0AHYv4OvrTFxePPBSgtns3qWtb09iagkM+IvuPco8qMYRKxS0RMqWmGvXcXtblN
         huDIlNAzrNwhTlqIzTSzziD3skf9GqDUwSyRxh/oXQCfJwBSgTu+iLlMDyxSGCN5pMaV
         62rHYXp2qbdeN/ud5VYYAqK9YzZVI86oERTzzOId4hfow8kUW4Um2eUeTSkknE+cwobT
         Yhdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kgp0g39R;
       spf=pass (google.com: domain of 36dbcxgukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=36dBCXgUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LQZ2rHNpysGsKDHWdSZdGg82amlkQapSaLesy9XTKfQ=;
        b=nrxUWZCwWnL8nQx5atP2JpWOdvoucd3tfao+FYpeQJSv2R7u3SMfWqfm+TG+cm7Q/8
         nr2ZMIOX54vMLegtcpb0HcGpB7DUo42WD6wD8goB4lDIntqnHZ7DjmofUa6Li/426eFg
         1RWXFzdd2wfO5MaBRQy2bNJekMb0ZYmL3+sDpvflhX/0vu0dQflILWnKyXbAima1tsFN
         4Npx5aabcG5wSZNlBvbZKygBRf3eZw7j5TBlF73U3N6LeHpHEpd11yI8NLrdyXQcew6n
         HQAwJNgTQhrCG7E/maiaywsWtjx5BxXX3t/HskOThm8o9kcKEJ7j4X8/jrT9HxnhFxA+
         cucA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LQZ2rHNpysGsKDHWdSZdGg82amlkQapSaLesy9XTKfQ=;
        b=fSi+NeTrQ4glQ0+C53CfhpnB6HIhuXPbo0AAcPgIExQDkJlCuDzpm3ZYAO82igzYD/
         4zEoQaXeKGSna1mXDuQe7c1ALxi2b/KMPEOKNI6Vai5550K0Hll0SOUoxD5ZKPiq6Tyq
         8/JyrQa9UM75du3gzy9IwBROKpeguWvAbhWrPqcRvWPTsRCdogppZIU6LLakyQFGWyO8
         ZYkGEzv5rJlMkS9ngG4PR4C02lWGXIeKIdHdXi49ldd16zLS1uu02NdIZzd+0JlO781u
         EpWfWDN45LkN19LUhmxj4o1IToHg8EIY36BJxdWYMORnqunEr2/XGND/g5Rx0L9MazOz
         bXHg==
X-Gm-Message-State: APjAAAVn8neyOIcrG6JxI+55lb9+SRcaasgzudIrlIFnPYNqvI2Rldl/
	kgd/lYen7WoQlsCV0xSw2Kw=
X-Google-Smtp-Source: APXvYqz2zT/SAF4YywLzqtNSopPOvEkDTF/rOPFSrlfhSVVLyCGvP6Fwm4yK1xwXd4g2ohW8qbzsJg==
X-Received: by 2002:a1f:3ac9:: with SMTP id h192mr5117855vka.55.1581437162747;
        Tue, 11 Feb 2020 08:06:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c5d7:: with SMTP id g23ls554661vkl.9.gmail; Tue, 11 Feb
 2020 08:06:02 -0800 (PST)
X-Received: by 2002:a1f:8cd5:: with SMTP id o204mr5228558vkd.66.1581437162255;
        Tue, 11 Feb 2020 08:06:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581437162; cv=none;
        d=google.com; s=arc-20160816;
        b=f3xxIwHQ1nC9jOMjijDmpIkI7oEnZ1YAPxwdDQXYBZRefKNfE0hOd/9Y96/2ekBAV7
         0cXjFV94ldFKkoC/t8T68XICyYltc/Slx+LNpbo4AE3YiqodwOIYbxZ9NZVkl0+UIedG
         tj+nNXx5Pc1xvWYEuOCxEA96tQbcGY78mrkIypxb+/gPM4vJxHnPs4FP2Q19cDIows7D
         EPbBOZuyFddVhRaYrHp6WlWP7mk30PzhRhtSBNGT7Q6ADuV45MNs9BQgvDJLII17fZ8B
         ioLk+Bp+vtPm4BxhRRGJNzIGdQq+pZW+Z6gTMf7G9X6zCzqScDRIgu5fR82PXiDn8jl2
         XeuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=2lszCI7b1dFvBYcYwKVuzOflaaeTIqON317waSS3RBU=;
        b=wYV9Fhl4Fj0Zvnm/sT48ydOoExVss6910RL/Rxth79R+Dbecmi7nsvo4epj4w1Y/hl
         LSrYbKXVMqcoqpmisQkQPz/klTQZsxfsIFpuPVwaEsSS3ffIs78HH9vmGTZVgQwwpECS
         F+leONV5/dxyWFjnbCwhrr9ZwyzaAF4KSEPUV180+xnV1q9kwZzbJVZHWy4pPeCcVFQZ
         Px8ZehgC1y+gTJ0LQe4utOlTQToOQ1XufWJJkBYzaIdZYyH9UI8s2ZYZl1NmxBo+MXzB
         ezI2JWREzdLSOVOgfcMX/LWi+jQRpD9I5xQWFdteCUMiNh7a5deVxgAkeMTwcD15DcQr
         r70g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kgp0g39R;
       spf=pass (google.com: domain of 36dbcxgukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=36dBCXgUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa4a.google.com (mail-vk1-xa4a.google.com. [2607:f8b0:4864:20::a4a])
        by gmr-mx.google.com with ESMTPS id y126si194348vkc.5.2020.02.11.08.06.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 08:06:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 36dbcxgukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) client-ip=2607:f8b0:4864:20::a4a;
Received: by mail-vk1-xa4a.google.com with SMTP id u7so3647043vkb.1
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 08:06:02 -0800 (PST)
X-Received: by 2002:ac5:c844:: with SMTP id g4mr5107364vkm.25.1581437161869;
 Tue, 11 Feb 2020 08:06:01 -0800 (PST)
Date: Tue, 11 Feb 2020 17:04:23 +0100
In-Reply-To: <20200211160423.138870-1-elver@google.com>
Message-Id: <20200211160423.138870-5-elver@google.com>
Mime-Version: 1.0
References: <20200211160423.138870-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.225.g125e21ebc7-goog
Subject: [PATCH v2 5/5] kcsan: Introduce ASSERT_EXCLUSIVE_BITS(var, mask)
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, Jan Kara <jack@suse.cz>, 
	John Hubbard <jhubbard@nvidia.com>, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Kgp0g39R;       spf=pass
 (google.com: domain of 36dbcxgukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=36dBCXgUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
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

In particular, before this patch, data races between reads (that use
@mask bits of an access that should not be modified concurrently) and
writes (that change ~@mask bits not used by the readers) would have been
annotated with "data_race()" (or "READ_ONCE()"). However, doing so would
then hide real problems: we would no longer be able to detect harmful
races between reads to @mask bits and writes to @mask bits.

Therefore, by using ASSERT_EXCLUSIVE_BITS(var, mask), we accomplish:

  1. Avoid proliferation of specific macros at the call sites: by
     including a single mask in the argument list, we can use the same
     macro in a wide variety of call sites, regardless of how and which
     bits in a field each call site actually accesses.

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
v2:
* Update API documentation to be clearer about how this compares to the
  existing assertions, and update use-cases. [Based on suggestions from
  John Hubbard]
* Update commit message. [Suggestions from John Hubbard]
---
 include/linux/kcsan-checks.h | 69 ++++++++++++++++++++++++++++++++----
 kernel/kcsan/debugfs.c       | 15 +++++++-
 2 files changed, 77 insertions(+), 7 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 4ef5233ff3f04..1b8aac5d6a0b5 100644
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
@@ -191,4 +191,61 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
 #define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
 	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
 
+/**
+ * ASSERT_EXCLUSIVE_BITS - assert no concurrent writes to subset of bits in @var
+ *
+ * Bit-granular variant of ASSERT_EXCLUSIVE_WRITER(var).
+ *
+ * Assert that there are no concurrent writes to a subset of bits in @var;
+ * concurrent readers are permitted. This assertion captures more detailed
+ * bit-level properties, compared to the other (word granularity) assertions.
+ * Only the bits set in @mask are checked for concurrent modifications, while
+ * ignoring the remaining bits, i.e. concurrent writes (or reads) to ~@mask bits
+ * are ignored.
+ *
+ * Use this for variables, where some bits must not be modified concurrently,
+ * yet other bits are expected to be modified concurrently.
+ *
+ * For example, variables where, after initialization, some bits are read-only,
+ * but other bits may still be modified concurrently. A reader may wish to
+ * assert that this is true as follows:
+ *
+ *	ASSERT_EXCLUSIVE_BITS(flags, READ_ONLY_MASK);
+ *	foo = (READ_ONCE(flags) & READ_ONLY_MASK) >> READ_ONLY_SHIFT;
+ *
+ *   Note: The access that immediately follows ASSERT_EXCLUSIVE_BITS() is
+ *   assumed to access the masked bits only, and KCSAN optimistically assumes it
+ *   is therefore safe, even in the presence of data races, and marking it with
+ *   READ_ONCE() is optional from KCSAN's point-of-view. We caution, however,
+ *   that it may still be advisable to do so, since we cannot reason about all
+ *   compiler optimizations when it comes to bit manipulations (on the reader
+ *   and writer side). If you are sure nothing can go wrong, we can write the
+ *   above simply as:
+ *
+ * 	ASSERT_EXCLUSIVE_BITS(flags, READ_ONLY_MASK);
+ *	foo = (flags & READ_ONLY_MASK) >> READ_ONLY_SHIFT;
+ *
+ * Another example, where this may be used, is when certain bits of @var may
+ * only be modified when holding the appropriate lock, but other bits may still
+ * be modified concurrently. Writers, where other bits may change concurrently,
+ * could use the assertion as follows:
+ *
+ *	spin_lock(&foo_lock);
+ *	ASSERT_EXCLUSIVE_BITS(flags, FOO_MASK);
+ *	old_flags = READ_ONCE(flags);
+ *	new_flags = (old_flags & ~FOO_MASK) | (new_foo << FOO_SHIFT);
+ *	if (cmpxchg(&flags, old_flags, new_flags) != old_flags) { ... }
+ *	spin_unlock(&foo_lock);
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
2.25.0.225.g125e21ebc7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200211160423.138870-5-elver%40google.com.
