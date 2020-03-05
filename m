Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ4VQTZQKGQEPWWRZPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id DA49B17A746
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 15:21:27 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id b12sf2392095wro.4
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2020 06:21:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583418087; cv=pass;
        d=google.com; s=arc-20160816;
        b=fIlZxKLFiPk2qmbQ13Fg74+mYt0QriMCmw/Da6j+PKMiciUmcgkFBL79aOHX+ZT+oz
         VKFQfORVe9UuwfqgeIvNk0GawEgaIuB2+70UeglWOWvT7v7BHMqbjUTHX9SnWZJxvPmP
         V0fofuS91FXg4emfuxU80Q6/nrStHhjZ3aH71GMYG+Vacxt0mlN3Qgu1Jj4169pvnKw3
         HIc8+V8pMeKycYbOMpivyDmUGS+1wlFuZflqBAZ/TgY2/dv/T54vDN8Nq7jjtNNzcdsl
         aKSyW8XWoyLPrvkq/WfraNahrEDIA7BA3jQa6cxAUW+jX4AOS9JFNEZmjZma+4eohGgV
         KiIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=clkOhA1kCygmclaPgqnM+E9qub+JX2rz/azuhie/L50=;
        b=uFJ30vCYJljRRy/nqZw1LD0V0AVqN0cFOIyY4O5T3J9l2RgI1dTJYOtkW+KVzOTa+t
         c5c+2OuICHXPMn5lMqXNFm2Pbi/adehO4hA+o8yZ+sLU+R+Or2CkGt0Znk5whnDHpxS0
         QplrdIu8X+i24+MfW4UTBxJR9Lt2r361imFYgqU+zfpOyAzbWa05kP2iW8HfkeRlYApf
         5N5RW/ZE2wmZEmMTON2JEymvj6jgAoB9E/jCTDHm61JHj6ZDgFiWsGbJpKJcvDFflkv6
         rvNIFdpqfwBM4ZfkW9/Fvf8Ehx7TbgyIyLUMDz4xhQWwLpYMxH8Bt9gimknbWtYhFlcf
         SAkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ji9tVXHn;
       spf=pass (google.com: domain of 35gphxgukcxkbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=35gphXgUKCXkbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=clkOhA1kCygmclaPgqnM+E9qub+JX2rz/azuhie/L50=;
        b=hrC/+pOR8R79kYRBXZzCJA58GHctea3QRPxUq+LOmHlFlYdqCj7OfebKJq73P43s1V
         I2DbvVeKBgD9HC3x86i7JBrFvz2bya34V4sN4j2kclhVdaKHWxcTO4c/ac3bACPGJaDI
         35IK7431duNZxj8RwnMOkYv6lHMboO34oFwzSq3icKoKME//D/izO5N470TQODIqRTdG
         6ieJ3sSWTxUVpx6/rptFs8fry6Rzt4DMWGWbfhzJcZ9DI4YnsI98Na1uMbYHxY4iCF2q
         2JrYyrhNKjdI2DRytbgCiGrO5uNvfb06VcovILYNTQ8aZz3AT+pFs5m4qP4nTnfNl9fW
         LPIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=clkOhA1kCygmclaPgqnM+E9qub+JX2rz/azuhie/L50=;
        b=UZHNA0SgwslF2Fz9vMqPVBXSmB5mXTUBP/84Ru3KEU4OUS+lP0bumzv+wBWPTxO64O
         eA08+AvK+1EhQq/uZXy6KtaAkNADWwhQyPucyF7sHGf9Q5qk8oRmvW9fzpHrFfsznyYJ
         h3tX012PTAwgRhJzvjKgKugQefGat6COv0EvnusELSCYWq+rsOCYnLExCFVfyOafrNdd
         oXvTPJitwNPBzx8BtbUy0jHddmIB45yCfqH9Y5EGeYbmnN2mzVddogOhh4Ihesbmho57
         MW1EXIRbl5fNOPZzukFCz5DadKbEenfe7w8DhzDxhexMNxZ4q2zudqxdeU/ifRZk6OGH
         BaTQ==
X-Gm-Message-State: ANhLgQ1ozcRZKNXKMr7YJtP8rdPRby0hjHnFyDEpYKqNKPCDSR4YMNp4
	ykOkZx3L/v/cya353xltV3k=
X-Google-Smtp-Source: ADFU+vv/aoGJIHAGEGldf4HmwtO4bESaCvtLMadIEIIdO+1ZxDpKzA0nUnpObIiWEaBCwr3LAhHEEw==
X-Received: by 2002:adf:f201:: with SMTP id p1mr10407544wro.212.1583418087577;
        Thu, 05 Mar 2020 06:21:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f091:: with SMTP id n17ls565948wro.8.gmail; Thu, 05 Mar
 2020 06:21:26 -0800 (PST)
X-Received: by 2002:adf:edd0:: with SMTP id v16mr10956019wro.357.1583418086786;
        Thu, 05 Mar 2020 06:21:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583418086; cv=none;
        d=google.com; s=arc-20160816;
        b=iEwFwaAxNy3xpghReSpz22+Pir/NGf8O9nTF9lwO6/syl/QkS2IuizA5j6UGRsrgOV
         kO+2W9VQCORtFu0Sfx6HsbA4UoUdV+ZkYHWS4d/tILYiq0mUtUgOKhsyjhjfTkSSTpVz
         ckUoKeYtAEgiXHmNCznXq/t9nJxY6oZL/9fqYo49hrHIQYw0ZQ+Asq0/6TFAzZgi8+fv
         Q5nIpNoGCiYL7RxSSeJJ4oQSxp0i4TTUaT4psiX4BQVABiTwKjcb9QhnkGK9Tub8r41J
         M1Ov5iUAzqjbO+3nw43Kx0/o3OcAriYCrRtpX5wR0X/GPjNb/K3Nq9Dy62cUc9oEs5Y8
         NYTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=R7b8JJ9ZwHsRnaGbo6IVVSmSzWDTP61ESXIDdbshLCY=;
        b=dAcFmjBnFdDcUfnb4qGbFkviPcOseNZzCHF0nfx5EKRXs8ne0iBOMCzkrlcd2HXtl5
         3nYKe5qkD9bsq5fGyaaq3Uin5iNTzgv2qiyJ0cjdPoJx3xjnc34fWjpaP9xQEgSUlG9Q
         4WhK7DFcUEK23BuPsQyVTRVooVdQS7azmtk2n42ejBUuf/2KIbYXER2CI4zpm+cO8TNl
         pHxBAXF3j5PKRWSREBrkUzxthQf1nCl/kdEr4TG4dIKY9KWiH6riwugSHBMzqnYbiBwC
         j3fvKCrcFQTGI6hQ5btGyi6Zu5oqxLqwXUBSRwDUkXhsb7Kf/EnvGXpv9E3WSZ4lz+6o
         mhAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ji9tVXHn;
       spf=pass (google.com: domain of 35gphxgukcxkbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=35gphXgUKCXkbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id s203si253229wme.1.2020.03.05.06.21.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Mar 2020 06:21:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 35gphxgukcxkbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id u18so2350262wrn.11
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2020 06:21:26 -0800 (PST)
X-Received: by 2002:adf:f504:: with SMTP id q4mr10007007wro.28.1583418086225;
 Thu, 05 Mar 2020 06:21:26 -0800 (PST)
Date: Thu,  5 Mar 2020 15:21:09 +0100
In-Reply-To: <20200305142109.50945-1-elver@google.com>
Message-Id: <20200305142109.50945-3-elver@google.com>
Mime-Version: 1.0
References: <20200305142109.50945-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH v2 3/3] kcsan: Update API documentation in kcsan-checks.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	corbet@lwn.net, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ji9tVXHn;       spf=pass
 (google.com: domain of 35gphxgukcxkbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=35gphXgUKCXkbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
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

Update the API documentation for ASSERT_EXCLUSIVE_* macros and make them
generate readable documentation for the code examples.

All @variable short summaries were missing ':', which was updated for
the whole file.

Tested with "make htmldocs".

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kcsan-checks.h | 98 ++++++++++++++++++++++--------------
 1 file changed, 61 insertions(+), 37 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 1b8aac5d6a0b5..14fd10e5a9177 100644
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
  * 	ASSERT_EXCLUSIVE_BITS(flags, READ_ONLY_MASK);
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
2.25.0.265.gbab2e86ba0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200305142109.50945-3-elver%40google.com.
