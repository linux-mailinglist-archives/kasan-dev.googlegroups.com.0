Return-Path: <kasan-dev+bncBAABBJ5H3X2AKGQEQ7K43UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CDA11AB0C7
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 20:34:16 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id c21sf719104pfn.14
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 11:34:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586975655; cv=pass;
        d=google.com; s=arc-20160816;
        b=YP6lDRP9H8+CZUJlrf7Eyw+EiX/arqFGxOXyEx8SVDmmYvWkH+ah/qHuCuau7CI9Rt
         kNqU3mwqLrCNoD7pdbpetJ1lUcOTJE/uTm4BbCSPfiA3X+iPlOucGm9Yd2+nj1lXkvKt
         LkPoW6ePXWPnyyF9VcZcmTVSK3YP7Avr7m937RzEHbL9Mm7V9TQXt4RbkFt3myWxFX7Z
         3gPmp8k9hCscFSiushFuDABpPfjYD+3EKyZ7dSMBXz0bOB93H+YcRg7GqblkmrIYORVh
         l+xsk6GbaDoYLZ5rjcjNthd81vD1a+9JZD6nOUowsQw7ssW66ksZsTOwRVjv30fq7g2j
         aREg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=pWNt0ycGmsU6AHCCi5JkbYbCTNEQJQAcXZ3cUn4eWyM=;
        b=UnbP4b6BOrnxPmKS5paXbsiLx4tnkqP1Egw3TCqID2WWPmb7cvY1002jlkVVBwILgn
         nBFp8EfmduZYnQs3yj0+3p6+oRbf/cgKablTy1AY/FhEYEVVcBdlKGK96uK/g8lCTn9C
         jswvGIwx1bH6AvKLWS8xBQLD9JqcqmgWAQQ4NkTgs/UvlAait0HspeFD00JhQrpSxCHP
         EdNgwlMh6TFa4xNGO7nSIPjwQqxpV40vCXh83J/OTH8lLXDg4JkQ+NEEtNlB7pP7jzRS
         ue1W6urfnvxablJa2mXyDZ3RDMM+RMeZ683ab44FcC0/3BLswWASfsgauf8vMzjR8cq3
         At7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=YBmPmEni;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pWNt0ycGmsU6AHCCi5JkbYbCTNEQJQAcXZ3cUn4eWyM=;
        b=TUrBsXZN4N1o6OBRcxxhnL9NPOqIvJmFPfOWmrZTjR7Yp6s4DpCMaCWx/VH07Bp0Df
         mDxpa/Y7Iaxi73sKkUTfQShI9SDseF68yf7NiECnNcWaXrAurcnrjhOAHQXdv6yst0v1
         BnWqd9s8gk+AW3IYKQNg0W96OpZyp08BM1Mewrn6XETe9tZfgdHZpgpW8uRSN0tUdWqR
         q6OwcNuL1YV9x80a0ueNVOHsqWDPVrXsjyovW3gwMKeXncurMip6ngSLHtHrtWyQKh/h
         xffDWQ3AMb6xiD4AavcRNKKoevH4ShvEKNOQKIvpEnM58oarjF/wjgOOc4R4UsBJhPXv
         LsSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pWNt0ycGmsU6AHCCi5JkbYbCTNEQJQAcXZ3cUn4eWyM=;
        b=W/KeksTaDHQR2RROm2eEAYfu5/PKU5y6fGKxMiHYdPDqOKbatzSgTZW889/hXWVUsB
         GzGOf9hIYbcXbaT+xqSm5pYWhgP778TFZGBayHX7WO1iQc9QrAgbU9IxBhbBT0vQ0zPK
         PXx+QJKK2Tzg9e9pqOgV4nymuXNJCQ/x1TGU43k0Ej8zSzubqi4ctM5u1MfpwG2KTZcd
         scjCiGug5dLhHvAMlBQ7bHB0djhtN35GWgk8l0oJrGXAk1sDZ5aPCD7l4LVGBp7ltl86
         RnYJrDUUW05BKejbLXM1piVayl/vSzMzlOF1RS+fiYtAM7H0NOe29juQ5nIZuD67VudW
         12Jw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuauamuB7Nwa5XutFP76WC5n9oUL7IcvMwLVj0lfdwIeK8SIN3hj
	f2BCfV9HduAecsLPSWeGK08=
X-Google-Smtp-Source: APiQypKG9tyRu7k8Liht+p7zDvy/TpENGBbC6BGZ18AYu+cAjk+tuqBdyWHkDkA95b2jTD5dDdsRLw==
X-Received: by 2002:a17:90a:c983:: with SMTP id w3mr655924pjt.102.1586975655198;
        Wed, 15 Apr 2020 11:34:15 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5d97:: with SMTP id t23ls768559pji.0.canary-gmail;
 Wed, 15 Apr 2020 11:34:14 -0700 (PDT)
X-Received: by 2002:a17:902:164:: with SMTP id 91mr6012606plb.207.1586975654859;
        Wed, 15 Apr 2020 11:34:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586975654; cv=none;
        d=google.com; s=arc-20160816;
        b=axHdco1X2G5zmj+nyWGTx6xEViACdiNZa6Dc7HIGMR6/Wm2+DryxxhWkwCgiHbKIvL
         usiqVya7GZn5bBiR/5g8CnX24R2oACiXGGjVQk8TfsMf3tmq/klTRx3BFE8ax8nPtUzq
         X+WCHs5opbrloAydRqeULVn5ZztC9OxvYa5LB3IJTacUDOmCPNHfkTLir26B0gI2H5LS
         G/YhEuiAhf0rtnWxCPed9dewc4yGEEvKHOwRe1nyzjtZmwRHdFk0UAbDgUgCjaFs8Phq
         9ByyCD2a42ixJQlHTwWfe1wgqfye9DopbpFobeM7yWIBJ4g2mjd/Bmck9wFuELblgBdK
         3GsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=2cNLfxGtDItUwSPi3Jodo8/yA9R7y3a0UOmM2xeN/Xg=;
        b=weVVb22hCwZRaDFuV8XPnxLkYkYNtItw7qQsQC7OfVCJQJcCRA/e2h8t1dFJKUW8ee
         kQN5y9zDmw6fCirhM8Fv7wZMf7SsPkU8nrkSo8ceTy9w3tuEw1TGNjpYsHi6DPyqtXLp
         S4i7Yj8sQsjx0l82cg1CmSf7oJYzyz5UJpNQojN22FCq+KURm1Ag06JJOoNBPxJMDvNo
         IYHyIM0pMRJKH+dOcFFUXaU/1k5A0br725/85LR9K3yml8bFl8nogWa174p82EfbNIV0
         eoOB9wBDHVDefziNLN4repCveGfLSD9Xeck5FT3cEPibYh6i1GCyW+cGdkDahAtYTuRT
         pn+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=YBmPmEni;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id br20si9357pjb.0.2020.04.15.11.34.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 11:34:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 7466B21707;
	Wed, 15 Apr 2020 18:34:14 +0000 (UTC)
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
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH v4 tip/core/rcu 06/15] kcsan: Update API documentation in kcsan-checks.h
Date: Wed, 15 Apr 2020 11:34:02 -0700
Message-Id: <20200415183411.12368-6-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200415183343.GA12265@paulmck-ThinkPad-P72>
References: <20200415183343.GA12265@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=YBmPmEni;       spf=pass
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

Update the API documentation for ASSERT_EXCLUSIVE_* macros and make them
generate readable documentation for the code examples.

All @variable short summaries were missing ':', which was updated for
the whole file.

Tested with "make htmldocs".

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/kcsan-checks.h | 98 +++++++++++++++++++++++++++-----------------
 1 file changed, 61 insertions(+), 37 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 8f9f6e2..3cd8bb0 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -26,9 +26,9 @@
 /**
  * __kcsan_check_access - check generic access for races
  *
- * @ptr address of access
- * @size size of access
- * @type access type modifier
+ * @ptr: address of access
+ * @size: size of access
+ * @type: access type modifier
  */
 void __kcsan_check_access(const volatile void *ptr, size_t size, int type);
 
@@ -64,7 +64,7 @@ void kcsan_flat_atomic_end(void);
  * Force treating the next n memory accesses for the current context as atomic
  * operations.
  *
- * @n number of following memory accesses to treat as atomic.
+ * @n: number of following memory accesses to treat as atomic.
  */
 void kcsan_atomic_next(int n);
 
@@ -74,7 +74,7 @@ void kcsan_atomic_next(int n);
  * Set the access mask for all accesses for the current context if non-zero.
  * Only value changes to bits set in the mask will be reported.
  *
- * @mask bitmask
+ * @mask: bitmask
  */
 void kcsan_set_access_mask(unsigned long mask);
 
@@ -106,16 +106,16 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
 /**
  * __kcsan_check_read - check regular read access for races
  *
- * @ptr address of access
- * @size size of access
+ * @ptr: address of access
+ * @size: size of access
  */
 #define __kcsan_check_read(ptr, size) __kcsan_check_access(ptr, size, 0)
 
 /**
  * __kcsan_check_write - check regular write access for races
  *
- * @ptr address of access
- * @size size of access
+ * @ptr: address of access
+ * @size: size of access
  */
 #define __kcsan_check_write(ptr, size)                                         \
 	__kcsan_check_access(ptr, size, KCSAN_ACCESS_WRITE)
@@ -123,16 +123,16 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
 /**
  * kcsan_check_read - check regular read access for races
  *
- * @ptr address of access
- * @size size of access
+ * @ptr: address of access
+ * @size: size of access
  */
 #define kcsan_check_read(ptr, size) kcsan_check_access(ptr, size, 0)
 
 /**
  * kcsan_check_write - check regular write access for races
  *
- * @ptr address of access
- * @size size of access
+ * @ptr: address of access
+ * @size: size of access
  */
 #define kcsan_check_write(ptr, size)                                           \
 	kcsan_check_access(ptr, size, KCSAN_ACCESS_WRITE)
@@ -158,14 +158,26 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
  * allowed. This assertion can be used to specify properties of concurrent code,
  * where violation cannot be detected as a normal data race.
  *
- * For example, if a per-CPU variable is only meant to be written by a single
- * CPU, but may be read from other CPUs; in this case, reads and writes must be
- * marked properly, however, if an off-CPU WRITE_ONCE() races with the owning
- * CPU's WRITE_ONCE(), would not constitute a data race but could be a harmful
- * race condition. Using this macro allows specifying this property in the code
- * and catch such bugs.
+ * For example, if we only have a single writer, but multiple concurrent
+ * readers, to avoid data races, all these accesses must be marked; even
+ * concurrent marked writes racing with the single writer are bugs.
+ * Unfortunately, due to being marked, they are no longer data races. For cases
+ * like these, we can use the macro as follows:
  *
- * @var variable to assert on
+ * .. code-block:: c
+ *
+ *	void writer(void) {
+ *		spin_lock(&update_foo_lock);
+ *		ASSERT_EXCLUSIVE_WRITER(shared_foo);
+ *		WRITE_ONCE(shared_foo, ...);
+ *		spin_unlock(&update_foo_lock);
+ *	}
+ *	void reader(void) {
+ *		// update_foo_lock does not need to be held!
+ *		... = READ_ONCE(shared_foo);
+ *	}
+ *
+ * @var: variable to assert on
  */
 #define ASSERT_EXCLUSIVE_WRITER(var)                                           \
 	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
@@ -177,16 +189,22 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
  * writers). This assertion can be used to specify properties of concurrent
  * code, where violation cannot be detected as a normal data race.
  *
- * For example, in a reference-counting algorithm where exclusive access is
- * expected after the refcount reaches 0. We can check that this property
- * actually holds as follows:
+ * For example, where exclusive access is expected after determining no other
+ * users of an object are left, but the object is not actually freed. We can
+ * check that this property actually holds as follows:
+ *
+ * .. code-block:: c
  *
  *	if (refcount_dec_and_test(&obj->refcnt)) {
  *		ASSERT_EXCLUSIVE_ACCESS(*obj);
- *		safely_dispose_of(obj);
+ *		do_some_cleanup(obj);
+ *		release_for_reuse(obj);
  *	}
  *
- * @var variable to assert on
+ * Note: For cases where the object is freed, `KASAN <kasan.html>`_ is a better
+ * fit to detect use-after-free bugs.
+ *
+ * @var: variable to assert on
  */
 #define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
 	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
@@ -200,7 +218,7 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
  * concurrent readers are permitted. This assertion captures more detailed
  * bit-level properties, compared to the other (word granularity) assertions.
  * Only the bits set in @mask are checked for concurrent modifications, while
- * ignoring the remaining bits, i.e. concurrent writes (or reads) to ~@mask bits
+ * ignoring the remaining bits, i.e. concurrent writes (or reads) to ~mask bits
  * are ignored.
  *
  * Use this for variables, where some bits must not be modified concurrently,
@@ -210,17 +228,21 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
  * but other bits may still be modified concurrently. A reader may wish to
  * assert that this is true as follows:
  *
+ * .. code-block:: c
+ *
  *	ASSERT_EXCLUSIVE_BITS(flags, READ_ONLY_MASK);
  *	foo = (READ_ONCE(flags) & READ_ONLY_MASK) >> READ_ONLY_SHIFT;
  *
- *   Note: The access that immediately follows ASSERT_EXCLUSIVE_BITS() is
- *   assumed to access the masked bits only, and KCSAN optimistically assumes it
- *   is therefore safe, even in the presence of data races, and marking it with
- *   READ_ONCE() is optional from KCSAN's point-of-view. We caution, however,
- *   that it may still be advisable to do so, since we cannot reason about all
- *   compiler optimizations when it comes to bit manipulations (on the reader
- *   and writer side). If you are sure nothing can go wrong, we can write the
- *   above simply as:
+ * Note: The access that immediately follows ASSERT_EXCLUSIVE_BITS() is assumed
+ * to access the masked bits only, and KCSAN optimistically assumes it is
+ * therefore safe, even in the presence of data races, and marking it with
+ * READ_ONCE() is optional from KCSAN's point-of-view. We caution, however, that
+ * it may still be advisable to do so, since we cannot reason about all compiler
+ * optimizations when it comes to bit manipulations (on the reader and writer
+ * side). If you are sure nothing can go wrong, we can write the above simply
+ * as:
+ *
+ * .. code-block:: c
  *
  *	ASSERT_EXCLUSIVE_BITS(flags, READ_ONLY_MASK);
  *	foo = (flags & READ_ONLY_MASK) >> READ_ONLY_SHIFT;
@@ -230,15 +252,17 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
  * be modified concurrently. Writers, where other bits may change concurrently,
  * could use the assertion as follows:
  *
+ * .. code-block:: c
+ *
  *	spin_lock(&foo_lock);
  *	ASSERT_EXCLUSIVE_BITS(flags, FOO_MASK);
- *	old_flags = READ_ONCE(flags);
+ *	old_flags = flags;
  *	new_flags = (old_flags & ~FOO_MASK) | (new_foo << FOO_SHIFT);
  *	if (cmpxchg(&flags, old_flags, new_flags) != old_flags) { ... }
  *	spin_unlock(&foo_lock);
  *
- * @var variable to assert on
- * @mask only check for modifications to bits set in @mask
+ * @var: variable to assert on
+ * @mask: only check for modifications to bits set in @mask
  */
 #define ASSERT_EXCLUSIVE_BITS(var, mask)                                       \
 	do {                                                                   \
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415183411.12368-6-paulmck%40kernel.org.
