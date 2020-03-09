Return-Path: <kasan-dev+bncBAABBPVGTLZQKGQE2HH7G7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 38D2317E7E4
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:32 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id v11sf7100170pgs.10
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780671; cv=pass;
        d=google.com; s=arc-20160816;
        b=wKA+wjSD25sMSU7g/xYMBAFDqxDG0yxsomxlojhWMdAM852AkkqTC/YvAAEofYTzND
         CjBghgc9IeFx+FM9nMKwpXP35yqKYqdJJ3xxjBangzXlsttsJ2AIE8O2NX4+g+ouTrm8
         B9VDsQaZSMlSLT5r7bcei2gwk3eJx+9ZZ+dTSdbDikpBgD/XW4Ice3RO2ohv+/Pu85ku
         aJflbtCiNgySYsvAX0s6tPlS+udFREPT+XVCeE1y1DUte8zT4vUhz6mvSvbUCknq4Cvq
         HQ0HHBFWnVLsvjIJvmD6wcYMDVOiXh/NDvqglYKhITd3Sd58fh8q2xdBgpwBeWPVe3wE
         azzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=9qooYHiYDOGASt3SzLqmfXlz8+/cBYcLeyc2l8+es9U=;
        b=M2Jx1EkTWVjSXVpTE0DLKzfWNC4U/B9UIHC+FpT5Y9BcrwFIRlQCoyvFiQtermkE+4
         5yh4wE8AbD8ML5AbJ1yTNl4qPG+xocEOMVwRrR3G5cNC4MDSz06dkHPI3QMRfDZohNAJ
         fYnrGzoMqMM0RpLGNHR+jW1zgcSrB22sYcXkmZaTjmnYEYH6cgVtiLR0btIIyU1RPGCc
         g//R47+50BIFJRNEYOgYAPFWH+X898OyDK4NJapwv7yK2D8a4tkgBp4u+KMCHGH5yOhJ
         3Yd/H1KcOAeItrXTQTyaPfEYbMhEGa/bDPPn3Z4GafE0ZRgdNAxuV68YDohYR/Tn2sZY
         L9ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=aMiU5N8D;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9qooYHiYDOGASt3SzLqmfXlz8+/cBYcLeyc2l8+es9U=;
        b=IvtVoNpcDAGyO9QojbXV01F99wpn8ALq8Rnwdp1T0TLvEFAKdyjNxSqWq5MrbpxzzC
         +oPVcbe7+Tz1ujBGISDK8vg/qTIIQ9kjUTEVDQzM2TspWJGP9Gv8c3dD4OC8b8lQt3dB
         /PF0JHsWt3Dg51VrG0GK7AOpHXJ0dVSXqSVB2OTH/3gvvSKTa7OCM0ACL15mhJqimUpQ
         Oe9gBhVciKuRx/iK4Yam0ZfL08z7ZP8CaljhUAG2qtHvtmwTua1LvZ0vjR5z6EXgaGPN
         fALQ+rMuJ5LvIk9exbHI0IUpatWbaMHQyf9eI9GqH/ENepJfEUsnB5U0/dhc0TmK3DhJ
         +QIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9qooYHiYDOGASt3SzLqmfXlz8+/cBYcLeyc2l8+es9U=;
        b=REGeC7ewGTZiG6ulxMEJHjJEXf4wTF1oiWs70H2H5LJinjju/cL2mOFKYJYOipRTw9
         07G0cZO3W4EQamdL3jOMhO9QhnDUtxB1J19YV3yS+gmd7Hos625tzi1rymwOusKo8Ezw
         ORoJhL4jrf1pbPqhEyfgcuRiTG2avmWCWp2aIPkBt/vesZAi57OfMgYt/G6NKRtHlwDt
         yh/ONXzLOQI3Xk1QCJXq4BLtKH+cm6uDQw5iNAz7zoZSG2uFpXxoh0XXuiKY4ryKuLbu
         1KnmjjAkXlsK+NtPUYze8LwLaYTlfPr2nVbsuHkgqya+XTwXK+0y9N0i2T5AFIxoQW95
         y6oA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3ok/WUWfGx1zyz7jcQ348ZFe8y/F4C8lbu+m58Yoz0F4iyQoxp
	Y17nZNl5bfnBOdxekiRF51I=
X-Google-Smtp-Source: ADFU+vsvFV5yONcYCtwGGuYORA9tlfzA4FaqgiuCxkpX66IrW4gLb6nRzaIFdpjFiH4sEdcQW6mIAg==
X-Received: by 2002:a17:902:b090:: with SMTP id p16mr4891485plr.274.1583780670904;
        Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8597:: with SMTP id w23ls1113677pfn.8.gmail; Mon, 09 Mar
 2020 12:04:30 -0700 (PDT)
X-Received: by 2002:aa7:9464:: with SMTP id t4mr11664390pfq.260.1583780670560;
        Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780670; cv=none;
        d=google.com; s=arc-20160816;
        b=en5O0Y5Jlpq5ESbN2wleSOnDKPltnK0qE5PqINSpJPvj7QCknMmCZGKSQeocoZsLrY
         aGXJXNPkETreMPI40Nj+M52YAtwnWR9ZOEFdPVOCxHcI2GREeVIIE1d51v5kJ/SqUdsw
         Xmpv6WmVHI8tACONRp5M+eDM/hK8bB9a7UDi/rQeVCfPOHC6FR3MOcTqeN0OZkBER3tc
         Hqoy5ohwqnjOoZWULSeDYjIEK5bOfWV3JSycy+UH3lJqf7K44hVJrEbUy+KrVno/v5Ki
         ceAo/IJ0Sc7mRHEuWX8Sdja5pMp+hvKitrULCZAr7688XkU4vTah+oYHd32l7EaN0WFf
         Bpjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=tKrRlqFpoqZYOVwB7m+Pf/tjbRaT8Bob5W0jL43iEng=;
        b=w7JktYYz14bFpn9NoG2ipypjyIMNkgQT+zIcQxxSFyqrV1riR5uUV0SxgPQo3TdPSg
         AEGngtGiGzuSvVEemJDbcEqdmQ8yzkSecBbuTJ3IODp2+1dkwP+uRbSStr1wMgIFbnhl
         xtnccZa4b+j0WmGIUUk7Fbdyt4BXcIDr15qtUail+Kf6EfRDpqzWBKxF9ITQNKoVzW/1
         UAh7C/tTLXMqLuy3zVo/x+aW9003bWY8lSgs3OSkxvIs96kMkJQCZv4JWceSB4SsvDPg
         nJmbxw4x0Dr1bxw2kUKUiY9sWAjhUOZQY7OvKrUP9hLXnSFZWEk4wuDnBKnV+1Pk2VbM
         dcTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=aMiU5N8D;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x12si676776plv.3.2020.03.09.12.04.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2754B24680;
	Mon,  9 Mar 2020 19:04:30 +0000 (UTC)
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
Subject: [PATCH kcsan 32/32] kcsan: Update API documentation in kcsan-checks.h
Date: Mon,  9 Mar 2020 12:04:20 -0700
Message-Id: <20200309190420.6100-32-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=aMiU5N8D;       spf=pass
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
index 1b8aac5..14fd10e 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-32-paulmck%40kernel.org.
