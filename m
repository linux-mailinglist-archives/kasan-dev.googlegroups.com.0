Return-Path: <kasan-dev+bncBAABBPNGTLZQKGQEHKXXC2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3c.google.com (mail-yw1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id DEDDF17E7DE
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:30 +0100 (CET)
Received: by mail-yw1-xc3c.google.com with SMTP id o79sf17031273ywo.14
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780670; cv=pass;
        d=google.com; s=arc-20160816;
        b=mf60JwH0RuoLaWEDtvw3umI8gvlKGIf5VJiGOdxCujyIPVFCmc7EZQBMss90gfzupB
         VtMYirQ3Qq0ZvTv5zUYv2qur0c42TLaHiTA/SY9XCioIHtl2tXIUa24f4TRNuiKCJv14
         mRrWQjiZ4pOSwkc04q3dMqJxFPP6FKAevOHjDdKpoTfycY+DO7hVRihjMGeB24b89YUx
         4W36AcaeokKjXh/PWK+a+cQK9ryn5JWtcPetTqIfCKo+xogd+KI3Ej+qebgG9VU8f9C1
         gC9bgFFhYp0qiDwZgtQJYT1TrGE/a8moJ7moQJpSqelPqCFMOOv7XHnFYddGKyveUpZs
         MN/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=bSJFLkPuTfXSH0vJyW1bO3L9TSg7L5K86uHZcRN1OOw=;
        b=ih5VajNnOXPNduBkGCwi5a/V4KO3XEhxr/HOuNTEZgnmBmuGk1YLrgruKQFOkiI4Up
         RTCp72v5QZKXJMiG12kCvYO/qUiCPcGS6KddiIUz8z7N7omp/xZa3KgS2GWXPHoG4/8/
         ZWOexjMzfzsa38SIUs/ZyzoEMiR5IQWwooYNMeAM6BD65JfYvfyZPjLV+2Yy0cIeccG4
         pFQpttss4qiGADqnYUxyuEBZANXk3uk/snogKQkc98yJityf1ZmP/tk5RcWlNvqzYN0d
         IE1lhL7ZWXI23GK5CXiQ06Yl/2G7/SBSDthgZLMoCk28Ez0cS55CRSKFrVVD2ihVRn8/
         NyNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=SJFbXoDZ;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bSJFLkPuTfXSH0vJyW1bO3L9TSg7L5K86uHZcRN1OOw=;
        b=ODkKRVhRNWV78y1xj0HP0Z1IaxVuDr4EYwPEZs/tdme0J2AhIDi8ZDPNjVZ4a2bzHo
         MKD2EWgQCb122njdAIHr4PljRzV8mSZpYoWYcxzF95WYzchKu91QpePkKsTytrIhkAlt
         Lb7czMtLiHHtE02otQmWM8O72C/doB5JUSFQY9JMdRbllA4ixxm0bFw5JzjBlN3VNyUW
         zDFj/TGFPzK6i1GHTkHym5WoNhUpoON2OX8l6EJ0CQWZH6gYRaTJNlDDUcO9DWKrqPtF
         dnHxqK5GEzUGJjWhejHk2Nz2ySELHByRGElYYXBKvRqu69D+gh5kDDuhqZixv3PeSLsZ
         zg4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bSJFLkPuTfXSH0vJyW1bO3L9TSg7L5K86uHZcRN1OOw=;
        b=kchfL+lV+tEQuK1nyMDuO8Jn/+q025s61BCX9rHgQkDihPx0Fk2pGKoBVN/OQsdr1X
         bS4Qkw97PyFJcct3dqne6Kd1MPfdsSuiAW78uXPsRk0EU3osSPj8IWFr+UfvPF7QlBcW
         mYY+VYizbBaeQ3KDYUCWVCvFADGnWvYYYqTcAzX8MNsmGRDQiDo98NojlNZr9UvTEryk
         X9dmBqWGAVmFYjBM7jA3fUGy3uoHguzyOD+aBdmq2RlKZTMTAksfpNrl1B8+zF8KY9ro
         ums1zSx9WF2uz5+LPgoEMxTo5YH+hv5EdCnkvHjZFkE7YaQ9JLEpPW6PlTeR+opWZYD8
         DNzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3Vv0r7SrEf3skk3n7R7nlns6OS9Jmryo3E/3meL8QolMRnAWpI
	3QvlBUTRGJV4nJpheDnbtHg=
X-Google-Smtp-Source: ADFU+vvxDbDwTY0Y7aJXZVJ9p5orfiGOUlcyzJU7gpocr0g0vqH+NcXMdNEZHwxSo0KSR6BJcEpyQw==
X-Received: by 2002:a81:49c3:: with SMTP id w186mr6531614ywa.329.1583780669770;
        Mon, 09 Mar 2020 12:04:29 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:8644:: with SMTP id w65ls2207770ywf.3.gmail; Mon, 09 Mar
 2020 12:04:29 -0700 (PDT)
X-Received: by 2002:a0d:d610:: with SMTP id y16mr17174105ywd.38.1583780669335;
        Mon, 09 Mar 2020 12:04:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780669; cv=none;
        d=google.com; s=arc-20160816;
        b=UUqgF6Vl0slrPo2vKKp9X4bl+WOC0cWr1MEkM4SZurwTMOmnwXc4f3G58ZdTU6MoWJ
         OIzl3Mp8aoUHOEIWaYh1/3b9jc6DnvlzEDJNoSf3LG3PjnJ1dv6vS0I1gZutib75kd16
         /ohcKFqDgYRCy/4AW7QWno/IOub0rPNv1CNT4GHTcfXyR+JLRkjZLEAeL3GRbeGPzpo7
         Fcfd88b7gOb0YCpeniJeeZnL+VUXxi262gwpgHERcKLm8Ojag0FZhwK+svx9NOzqTDdT
         3jwJO8Ak0QknukpVYxu0tlTIjwzUOZf0D8X21+o3IyXO25QRrFzBttxXU2hzQIFatQC1
         +w4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=q3o9IxybYU2ZEs1Q7aBtJmQIlY/JCQRqVN7aKBGb+d0=;
        b=JGjvwsuySn5WufGf64iCQsQlx1bgnhwa55A3gz3i9Y54EIqcOTbhpMOwXWwqLUCnQw
         FL4P71zZTmO5l3iu1tLi9LvBtnSuJlbK1TcHSDokpDkSxoyRrRiMUXnCMX9cIt6ZqqRD
         eG3++3vG86l5u2cHpcvuRqCfSj701UFY3jJ4Uj+ThtwrvcF9D2ucMKAAN8q/yNdrv6WT
         ujRsGZhfW2PRyKbUIM0N0/XRDmQ7OcjmvQXgNy7AH08okSrDf8MqsWXghCHICp8dD8Xh
         Cr5n0ANRgHthrEJjEMsYTNENaH7dIHM2JsTLFJu48UUXSg753aOlZTfet/x6+p0qaKpi
         paug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=SJFbXoDZ;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b130si689362ywe.2.2020.03.09.12.04.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 563BF24656;
	Mon,  9 Mar 2020 19:04:28 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Jan Kara <jack@suse.cz>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 25/32] kcsan: Introduce ASSERT_EXCLUSIVE_BITS(var, mask)
Date: Mon,  9 Mar 2020 12:04:13 -0700
Message-Id: <20200309190420.6100-25-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=SJFbXoDZ;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

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
Cc: Paul E. McKenney <paulmck@kernel.org>
Cc: Qian Cai <cai@lca.pw>
Acked-by: John Hubbard <jhubbard@nvidia.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/kcsan-checks.h | 69 ++++++++++++++++++++++++++++++++++++++++----
 kernel/kcsan/debugfs.c       | 15 +++++++++-
 2 files changed, 77 insertions(+), 7 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 4ef5233..1b8aac5 100644
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
index 9bbba0e..2ff1961 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-25-paulmck%40kernel.org.
