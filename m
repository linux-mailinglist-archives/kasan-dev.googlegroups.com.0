Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUFN77ZAKGQEOB7WBQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 19329179516
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Mar 2020 17:26:57 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id d11sf2002677eds.7
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Mar 2020 08:26:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583339216; cv=pass;
        d=google.com; s=arc-20160816;
        b=MlxCc6fpsvkrLIDxJoUPyp+hnuDeEkj1E+jeegiLrEyIHJ3nEpUcYmpfNCgwILV/+S
         M20lzMzvK/UhFqV64M8u82riHNbakTssBWZJ7rMK135lfYC4Ncch0ZoHeovpdUXPm0PQ
         f6XbatVjVDrYEIYXw6YYfORqgGrgJBshLLpYoFYQf5lCy//uE/Yzdxw5F/jkz+dDxtMG
         yyaKNAHNTIp9bH2gHNgPPifNkavBh+ugBHxuHBxd8P8/83Y9tCibPq2zpmH7dKsLeOVf
         uHQxxUJJNUCN8ZEDnrX++/NLTAu/7FIY9FI/wCboCPwk4Ivcj6/zjE75wbPFS6Ymdf89
         Z/Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Dr49pSs2UczAnwdY27Ku00hqfxEUw6/AA6Vj+sCSZpI=;
        b=qAM4FaYHQfD3H+3O/YTP/EB9cMXFV19XBsCBlPjowOtBNvCwNZcDF+Iq+99zuuf/un
         AYnCadmQLNYM+LF1ZWgA2/jpfe3k6dFl6k/KyDJe6jQIRQ6gBMapTHPSW+IPbr3MfLLI
         R1uPo2yTwveIfQpvAlBW6J5SmwAJsKQ7tE05VRDWVZCmDZCWdtSrh+AlZve/AvHfplRE
         6vMMI0A9I8jVXPV8sbC65pAmWWy6MOaSm+ieB8HEe3XXYGQgEFcpSLDB/7uFRw4s0kBO
         3xqnw+Ox9XNL5N2d/yUj8z9WaB6YXBpeMANBPxXT93Q4agDSQlU+7BgW9QTAlmsbjADY
         nD0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g8pGpYPs;
       spf=pass (google.com: domain of 3z9zfxgukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3z9ZfXgUKCfQahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dr49pSs2UczAnwdY27Ku00hqfxEUw6/AA6Vj+sCSZpI=;
        b=F57KJfYTxaUXWtGHWTgEENfRUD52XSCIVXJm5PlbBs6ioyLxh9Dy7l7wL05cl9Td1O
         ke+HhHmTvgEWYxg+rSvEeKMwQDPJs0HHUxrDfhEj7PtU17rrVCzYRXI1Yz8ayaoXM4CV
         n47wpXImIYrUYXBCCL4IVoVdQuGfTIZAxV+rykVD+eof1dzvJH2Klr/0eJ6SLBTKAFyA
         M5GK6KIvRzXYy4f5iY7PMOU97FuzgO6p162mXvjM/culnhzahQSfmNvbTiVpwLXrELG6
         W8bDYYAqU8pbNO4LhXlnVxnJObYKyFhB98jm3I7DoKTF0pbD4fe7xoCKFL0NQvfOd1Zx
         RU5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dr49pSs2UczAnwdY27Ku00hqfxEUw6/AA6Vj+sCSZpI=;
        b=WTrUOjV1MHwUv+29IRLP/DF+uubDERop8SH+ECL6HyrE0hQ3npf2RBEDss5xl37pv5
         i/xTxz3PtXPa53WG6mfZdFspVzsPseRiylAnRs0TwE8N6wv1jatnEhGcKsLJ8pm10nAu
         vEGIcercbyik39lY2KM/X+kVkm94PVoXI66HAzWlxm9G4VkQOhIdcMswo4gMRqAJ1YGC
         8wjrynPVrMKfsyaqnAlAIsdPSXGF1ECqoBOql9ER5ZzkkpbSvb8ozp3oBxIHWN13BmfP
         oUKBTlENFq7dEYANFrryzT/7jOfyu11T72JhajIGcgLRRlPOA0LtzHWMZ/phW3ZeHYRw
         rAUA==
X-Gm-Message-State: ANhLgQ2LR+5PhglTYR7qUCjqrPtjcno374y35RVTjlUSpi9Am8AzLw11
	MJz0zPA0Oy7UyZStGg56ClA=
X-Google-Smtp-Source: ADFU+vsmqpeRZcbULHXMuYxSiXpQvH9yAK0VIIBzcebsKfzNdLMmzH6wWgfA5LuCKO/VicsdYfEKIA==
X-Received: by 2002:a05:6402:b59:: with SMTP id bx25mr3570917edb.5.1583339216788;
        Wed, 04 Mar 2020 08:26:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:4a95:: with SMTP id x21ls1158465eju.2.gmail; Wed, 04
 Mar 2020 08:26:56 -0800 (PST)
X-Received: by 2002:a17:906:2292:: with SMTP id p18mr3289189eja.272.1583339216071;
        Wed, 04 Mar 2020 08:26:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583339216; cv=none;
        d=google.com; s=arc-20160816;
        b=v62CEV8OTKxlTDG+aglJwM17ykUvNdVF6yG6hPaqz2N3tm6Bv4gIiqg45mhTHPghO0
         c6kUBMVjLIXEGT2vu45/4PCG2HLgJYLqojjPJrsfHjdKx2e+Wv7Nu9PDUPkvaOedBtcR
         hQfuGNfobCoeCh+weZu/olSUeCSVMhROAiQJQxljXle7rXBKp/hf6ve7q+wyVNXsGX0P
         dUB/qGrDa+kFw80MYtYVGeqIrWm0c4h6u7fsPYsUM+GJhU8WOge5JyinHf6dLU/vGMjN
         Qd4ftjpz13uORmBwy0bIyMluEvBFlDb9KimX2S/KFmOAF41cKUbRlEBuR0l+9kA2WQsf
         y2Ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=0XgZjHOQdGAxXnAanWU5HksJ52ua72n/XN1fQpNKAB0=;
        b=yEcvkaNnu3GZtrciBOxj552klVVvdquKO08+YKaRzFwiA8y7h1U5TEk5vCVA2UaiIB
         4JIyrzX22xadkNyudC0G/0Rt3tB92eVJ7t66HuSMFUuszj+dXsAFibfzxcMPZcr4SRU6
         8PVYLszmsdfcB7UcxjmkdXcBSxI8+5FSCZH4dBvC34DrbkJmeV23W7DVnEXMpj7x0BaL
         RmCzyFbH7pCQOjSWCur2B2+f1LG+xvAmyP7P7HGY2GyfIsj2Ag4K9UXrQffWaMGDv0O4
         fUiocmZgJrae+WLtayJ3GY+rMccyzC3U0bSElvSNNXHNRAaa2NpKShmyH7Svk6HYLHra
         lejQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g8pGpYPs;
       spf=pass (google.com: domain of 3z9zfxgukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3z9ZfXgUKCfQahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id s20si137204edy.5.2020.03.04.08.26.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Mar 2020 08:26:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3z9zfxgukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id y18so2061803wmi.1
        for <kasan-dev@googlegroups.com>; Wed, 04 Mar 2020 08:26:56 -0800 (PST)
X-Received: by 2002:adf:db84:: with SMTP id u4mr4877175wri.317.1583339215472;
 Wed, 04 Mar 2020 08:26:55 -0800 (PST)
Date: Wed,  4 Mar 2020 17:25:41 +0100
In-Reply-To: <20200304162541.46663-1-elver@google.com>
Message-Id: <20200304162541.46663-3-elver@google.com>
Mime-Version: 1.0
References: <20200304162541.46663-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH 3/3] kcsan: Update API documentation in kcsan-checks.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	corbet@lwn.net, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=g8pGpYPs;       spf=pass
 (google.com: domain of 3z9zfxgukcfqahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3z9ZfXgUKCfQahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
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

Tested with 'make htmldocs'.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200304162541.46663-3-elver%40google.com.
