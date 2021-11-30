Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTE5TCGQMGQE4XN5U3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id BB31A4632C6
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:16 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 144-20020a1c0496000000b003305ac0e03asf13597085wme.8
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272716; cv=pass;
        d=google.com; s=arc-20160816;
        b=my3uJYuDkTA59l/rHFSLu6pcRy3DHu66AaVff3uU2DuESotXueWHy10Zyr7bPbDFxj
         ZckZ4393MGuox715c7NtLxJvhYiTadS1eSZMyFPCiv8RQgGn6F24Kir16GWPYhwnpHIo
         RnXFU9Lafxcbs1HUAFZPNoOkz7XOWDvrb1FRIveNE3epu7sLU0PR1pIF7Z2ioQLcCHfB
         UQOYETAClTfXHMKyhMjrear47k46K2+Yzd+i0/ZTa13/Hqeevt/Sw9GFTXDqa3cs3SE2
         nSm10BqEw/7IJ1Uq3H7Rn8BWbYck1ZB4HEisKyMxwc7q2Djhy+OOpwNcExnAdNyzP1vD
         o0+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=i4gqJMVUO67yq1DObyz/9Ho3VQI2s8n9Mj63NOv4RO8=;
        b=Y1tziELXzm1Nhch6SSo9GCbtLipCjucGLoN2InkB9qUUZSjV7qCIzHUUEoSn8k8Q/n
         CHo36pVApIo8i7jNOI3Qz5Rv9f+mzA19vnHtmC3HLNfdVrBDk/KjiIxgMDGRIZmXC1H7
         P0B9dy4Tce+xVkJFI5UHckvYkKTBb0xQfRFfRMzntvjFRAw1NKC3VSkwjPCns/OdXMhr
         W8luJwaXBSAgQ+RrMIIM4nc9ryuFpvnKNgPhaVIE39fQF9b4qUN8dKWbJ/obgR1LSF3O
         iOuQ3WV2UywpJdr+XWEIoYhof5D1sHCrx54zAI1NwGkzYjheasPL1C3vafhmQyZ4RsXn
         NJPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WjwZ3pB6;
       spf=pass (google.com: domain of 3yw6myqukczq29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3yw6mYQUKCZQ29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i4gqJMVUO67yq1DObyz/9Ho3VQI2s8n9Mj63NOv4RO8=;
        b=cxuYBhqCO/7pr0dpXIsZtsZQTLkQ81YUgjmgJTWU2grPR/ReMbYhELG3AsUwbYXSAb
         oO8E2s9LIjjFR4my34vT2m4X9OHSdaqgswdHLnuBQLONNJ5R8wNdcX7pgomwrdSVRarZ
         2KQ56xhPqKVtqKMnv/B8Y+XaX7H/mhd+H7KV5uTF0n4zq5gi/O65eXEOlhgNu8d3gS6d
         gC2WXdBtJMjxb/hCYKGcVCRW90+lQQTnQdiiehNuObggxVlo7oNEvTRAVoKrnLGYP+Vc
         VUVUmXrBAwFZo7Fd2vScMj0SebSSbu2vyZIQggdY3KoAsH0d4fZChE4at65vyKERmjhg
         iAPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i4gqJMVUO67yq1DObyz/9Ho3VQI2s8n9Mj63NOv4RO8=;
        b=BGqc6a6sE8KBjomvv5SyG0Gjv1KD+iqhLHlnVpSCC0WBb5nJRN2UGSAACevLhza5s+
         AlRONtolvl5lZHFEUp6ajRdAqkiK0qvFlyZfYGDQhjdMWz36UldkhpY8eWVlO+Xaz1XH
         CzozZzfVQxxGw1GTcJw5vM93xIJGt15BNQoaJOTiTsbZ6A+vbjchCfbuRr+1Ir3BIREg
         WoBwOV2GpNc3XcKj6X6/kkx1xDut7ut4EuqBNU8lDzCQUL5CpkNV8zHWcL3arhDOCrNP
         lpT8iibfaJi3rI3bFB6bio3Ti/ARKpls2NRoYOQVtqs53S7yThmybctsuv1MAF2089Rz
         BX6Q==
X-Gm-Message-State: AOAM5336OV7f8NBse/ab0lbthVZ+83/golTFuA0LjzLnE8p4PRGaZnDH
	yyMVDkMszThbbTvErrQniiI=
X-Google-Smtp-Source: ABdhPJwMvUfhMNO9Q+iTtr56q6SPqcusFJixnIs+XB9tpjYegrYeeHH5YZkshyi3fkqx322hqSHrRg==
X-Received: by 2002:a5d:5251:: with SMTP id k17mr39921959wrc.482.1638272716536;
        Tue, 30 Nov 2021 03:45:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7e16:: with SMTP id z22ls1234921wmc.2.canary-gmail; Tue,
 30 Nov 2021 03:45:15 -0800 (PST)
X-Received: by 2002:a05:600c:1e8d:: with SMTP id be13mr4345307wmb.79.1638272715577;
        Tue, 30 Nov 2021 03:45:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272715; cv=none;
        d=google.com; s=arc-20160816;
        b=EvLB0hji3/pW97/0wEXCkubjcxsTtEy8PbWVnx+IPo3RDU1k5/Pfz4re+Oz1EREBRw
         67hG5HVGp7gblJf4bGfFlMuoHk9mE5qNWgOz8ocdyyIEloZ59hQvetTXu8lUdAey52RC
         xHxc6sKUnyPZ6Kskhc8bl22SH/YWrm4cNLSTuF23Z50+eOgghWtTwqLOQwTKTtja9wNF
         c0qWEgLxs8k0S7O56GMB1i81KTa6zS56bSDy6LR+CzUc56YskoPL9dIWnM7aJqgjH7Qh
         Hsh17IiMgAc5MqA19zOFviy1uZCN/lgDPCopFbMnPD7dhtaTgPtwqQs+kdyFc3Zle+YO
         dwIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=05D+KiscSDDxRASVdY9PJsfP2IqeJxlbD6WimO+AarQ=;
        b=wl4XHfAcG5Bwqrfr07xFjgzszGIHcYm/XQ9h6H8Dw3U+LKVZB6xmU+3SzKVVv9lBOB
         bnAzAPbQlKVNKhMetiVHj2HmMh2qH/RlasHa98hfs1xFSghXhBZ4wduhuq/HfZalbtGj
         b/A6dPaywhAbz3P/qb9rtwRxYJyvIgEXBXn3yCHDpECnNgdXDokJE3AZpICRP1dfyJWW
         kGcCkPVK6jI4Y0/0tPKszSXxPwVa/zLJkOeFm1g42QabAQVqxTw2FdX8reomU2R1Xi45
         8fS2kizOK1rUodrUupETy4kfB5ah/PRuEGwIYo9/oAn9hJfnoZcVqG5nIsoNwCDoWVBn
         NVDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WjwZ3pB6;
       spf=pass (google.com: domain of 3yw6myqukczq29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3yw6mYQUKCZQ29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id s138si176106wme.1.2021.11.30.03.45.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yw6myqukczq29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id z138-20020a1c7e90000000b003319c5f9164so13604723wmc.7
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:15 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:6000:168f:: with SMTP id
 y15mr39633411wrd.61.1638272715140; Tue, 30 Nov 2021 03:45:15 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:13 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-6-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 05/25] kcsan: Add core memory barrier instrumentation functions
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=WjwZ3pB6;       spf=pass
 (google.com: domain of 3yw6myqukczq29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3yw6mYQUKCZQ29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
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

Add the core memory barrier instrumentation functions. These invalidate
the current in-flight reordered access based on the rules for the
respective barrier types and in-flight access type.

To obtain barrier instrumentation that can be disabled via __no_kcsan
with appropriate compiler-support (and not just with objtool help),
barrier instrumentation repurposes __atomic_signal_fence(), instead of
inserting explicit calls. Crucially, __atomic_signal_fence() normally
does not map to any real instructions, but is still intercepted by
fsanitize=thread. As a result, like any other instrumentation done by
the compiler, barrier instrumentation can be disabled with __no_kcsan.

Unfortunately Clang and GCC currently differ in their __no_kcsan aka
__no_sanitize_thread behaviour with respect to builtin atomics (and
__tsan_func_{entry,exit}) instrumentation. This is already reflected in
Kconfig.kcsan's dependencies for KCSAN_WEAK_MEMORY. A later change will
introduce support for newer versions of Clang that can implement
__no_kcsan to also remove the additional instrumentation introduced by
KCSAN_WEAK_MEMORY.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Rework to avoid inserting explicit calls, and instead repurpose
  __atomic_signal_fence (see comment at __tsan_atomic_signal_fence),
  which is known to the ThreadSanitizer instrumentation and can
  therefore be removed via function attributes.

v2:
* Rename kcsan_atomic_release() to kcsan_atomic_builtin_memorder() to
  avoid confusion.
---
 include/linux/kcsan-checks.h | 71 +++++++++++++++++++++++++++++++++++-
 kernel/kcsan/core.c          | 68 +++++++++++++++++++++++++++++++++-
 2 files changed, 136 insertions(+), 3 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index a1c6a89fde71..9d2c869167f2 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -36,6 +36,36 @@
  */
 void __kcsan_check_access(const volatile void *ptr, size_t size, int type);
 
+/*
+ * See definition of __tsan_atomic_signal_fence() in kernel/kcsan/core.c.
+ * Note: The mappings are arbitrary, and do not reflect any real mappings of C11
+ * memory orders to the LKMM memory orders and vice-versa!
+ */
+#define __KCSAN_BARRIER_TO_SIGNAL_FENCE_mb	__ATOMIC_SEQ_CST
+#define __KCSAN_BARRIER_TO_SIGNAL_FENCE_wmb	__ATOMIC_ACQ_REL
+#define __KCSAN_BARRIER_TO_SIGNAL_FENCE_rmb	__ATOMIC_ACQUIRE
+#define __KCSAN_BARRIER_TO_SIGNAL_FENCE_release	__ATOMIC_RELEASE
+
+/**
+ * __kcsan_mb - full memory barrier instrumentation
+ */
+void __kcsan_mb(void);
+
+/**
+ * __kcsan_wmb - write memory barrier instrumentation
+ */
+void __kcsan_wmb(void);
+
+/**
+ * __kcsan_rmb - read memory barrier instrumentation
+ */
+void __kcsan_rmb(void);
+
+/**
+ * __kcsan_release - release barrier instrumentation
+ */
+void __kcsan_release(void);
+
 /**
  * kcsan_disable_current - disable KCSAN for the current context
  *
@@ -159,6 +189,10 @@ void kcsan_end_scoped_access(struct kcsan_scoped_access *sa);
 static inline void __kcsan_check_access(const volatile void *ptr, size_t size,
 					int type) { }
 
+static inline void __kcsan_mb(void)			{ }
+static inline void __kcsan_wmb(void)			{ }
+static inline void __kcsan_rmb(void)			{ }
+static inline void __kcsan_release(void)		{ }
 static inline void kcsan_disable_current(void)		{ }
 static inline void kcsan_enable_current(void)		{ }
 static inline void kcsan_enable_current_nowarn(void)	{ }
@@ -191,12 +225,45 @@ static inline void kcsan_end_scoped_access(struct kcsan_scoped_access *sa) { }
  */
 #define __kcsan_disable_current kcsan_disable_current
 #define __kcsan_enable_current kcsan_enable_current_nowarn
-#else
+#else /* __SANITIZE_THREAD__ */
 static inline void kcsan_check_access(const volatile void *ptr, size_t size,
 				      int type) { }
 static inline void __kcsan_enable_current(void)  { }
 static inline void __kcsan_disable_current(void) { }
-#endif
+#endif /* __SANITIZE_THREAD__ */
+
+#if defined(CONFIG_KCSAN_WEAK_MEMORY) && defined(__SANITIZE_THREAD__)
+/*
+ * Normal barrier instrumentation is not done via explicit calls, but by mapping
+ * to a repurposed __atomic_signal_fence(), which normally does not generate any
+ * real instructions, but is still intercepted by fsanitize=thread. This means,
+ * like any other compile-time instrumentation, barrier instrumentation can be
+ * disabled with the __no_kcsan function attribute.
+ *
+ * Also see definition of __tsan_atomic_signal_fence() in kernel/kcsan/core.c.
+ */
+#define __KCSAN_BARRIER_TO_SIGNAL_FENCE(name)					\
+	static __always_inline void kcsan_##name(void)				\
+	{									\
+		barrier();							\
+		__atomic_signal_fence(__KCSAN_BARRIER_TO_SIGNAL_FENCE_##name);	\
+		barrier();							\
+	}
+__KCSAN_BARRIER_TO_SIGNAL_FENCE(mb)
+__KCSAN_BARRIER_TO_SIGNAL_FENCE(wmb)
+__KCSAN_BARRIER_TO_SIGNAL_FENCE(rmb)
+__KCSAN_BARRIER_TO_SIGNAL_FENCE(release)
+#elif defined(CONFIG_KCSAN_WEAK_MEMORY) && defined(__KCSAN_INSTRUMENT_BARRIERS__)
+#define kcsan_mb	__kcsan_mb
+#define kcsan_wmb	__kcsan_wmb
+#define kcsan_rmb	__kcsan_rmb
+#define kcsan_release	__kcsan_release
+#else /* CONFIG_KCSAN_WEAK_MEMORY && ... */
+static inline void kcsan_mb(void)		{ }
+static inline void kcsan_wmb(void)		{ }
+static inline void kcsan_rmb(void)		{ }
+static inline void kcsan_release(void)		{ }
+#endif /* CONFIG_KCSAN_WEAK_MEMORY && ... */
 
 /**
  * __kcsan_check_read - check regular read access for races
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 36a75e79a0bd..2254cb75cbb0 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -942,6 +942,22 @@ void __kcsan_check_access(const volatile void *ptr, size_t size, int type)
 }
 EXPORT_SYMBOL(__kcsan_check_access);
 
+#define DEFINE_MEMORY_BARRIER(name, order_before_cond)				\
+	void __kcsan_##name(void)						\
+	{									\
+		struct kcsan_scoped_access *sa = get_reorder_access(get_ctx());	\
+		if (!sa)							\
+			return;							\
+		if (order_before_cond)						\
+			sa->size = 0;						\
+	}									\
+	EXPORT_SYMBOL(__kcsan_##name)
+
+DEFINE_MEMORY_BARRIER(mb, true);
+DEFINE_MEMORY_BARRIER(wmb, sa->type & (KCSAN_ACCESS_WRITE | KCSAN_ACCESS_COMPOUND));
+DEFINE_MEMORY_BARRIER(rmb, !(sa->type & KCSAN_ACCESS_WRITE) || (sa->type & KCSAN_ACCESS_COMPOUND));
+DEFINE_MEMORY_BARRIER(release, true);
+
 /*
  * KCSAN uses the same instrumentation that is emitted by supported compilers
  * for ThreadSanitizer (TSAN).
@@ -1130,10 +1146,19 @@ EXPORT_SYMBOL(__tsan_init);
  * functions, whose job is to also execute the operation itself.
  */
 
+static __always_inline void kcsan_atomic_builtin_memorder(int memorder)
+{
+	if (memorder == __ATOMIC_RELEASE ||
+	    memorder == __ATOMIC_SEQ_CST ||
+	    memorder == __ATOMIC_ACQ_REL)
+		__kcsan_release();
+}
+
 #define DEFINE_TSAN_ATOMIC_LOAD_STORE(bits)                                                        \
 	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder);                      \
 	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder)                       \
 	{                                                                                          \
+		kcsan_atomic_builtin_memorder(memorder);                                           \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC, _RET_IP_);    \
 		}                                                                                  \
@@ -1143,6 +1168,7 @@ EXPORT_SYMBOL(__tsan_init);
 	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
 	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
 	{                                                                                          \
+		kcsan_atomic_builtin_memorder(memorder);                                           \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC, _RET_IP_);          \
@@ -1155,6 +1181,7 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
 	{                                                                                          \
+		kcsan_atomic_builtin_memorder(memorder);                                           \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
@@ -1187,6 +1214,7 @@ EXPORT_SYMBOL(__tsan_init);
 	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
 							      u##bits val, int mo, int fail_mo)    \
 	{                                                                                          \
+		kcsan_atomic_builtin_memorder(mo);                                                 \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
@@ -1202,6 +1230,7 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
 							   int mo, int fail_mo)                    \
 	{                                                                                          \
+		kcsan_atomic_builtin_memorder(mo);                                                 \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
@@ -1233,10 +1262,47 @@ DEFINE_TSAN_ATOMIC_OPS(64);
 void __tsan_atomic_thread_fence(int memorder);
 void __tsan_atomic_thread_fence(int memorder)
 {
+	kcsan_atomic_builtin_memorder(memorder);
 	__atomic_thread_fence(memorder);
 }
 EXPORT_SYMBOL(__tsan_atomic_thread_fence);
 
+/*
+ * In instrumented files, we emit instrumentation for barriers by mapping the
+ * kernel barriers to an __atomic_signal_fence(), which is interpreted specially
+ * and otherwise has no relation to a real __atomic_signal_fence(). No known
+ * kernel code uses __atomic_signal_fence().
+ *
+ * Since fsanitize=thread instrumentation handles __atomic_signal_fence(), which
+ * are turned into calls to __tsan_atomic_signal_fence(), such instrumentation
+ * can be disabled via the __no_kcsan function attribute (vs. an explicit call
+ * which could not). When __no_kcsan is requested, __atomic_signal_fence()
+ * generates no code.
+ *
+ * Note: The result of using __atomic_signal_fence() with KCSAN enabled is
+ * potentially limiting the compiler's ability to reorder operations; however,
+ * if barriers were instrumented with explicit calls (without LTO), the compiler
+ * couldn't optimize much anyway. The result of a hypothetical architecture
+ * using __atomic_signal_fence() in normal code would be KCSAN false negatives.
+ */
 void __tsan_atomic_signal_fence(int memorder);
-void __tsan_atomic_signal_fence(int memorder) { }
+noinline void __tsan_atomic_signal_fence(int memorder)
+{
+	switch (memorder) {
+	case __KCSAN_BARRIER_TO_SIGNAL_FENCE_mb:
+		__kcsan_mb();
+		break;
+	case __KCSAN_BARRIER_TO_SIGNAL_FENCE_wmb:
+		__kcsan_wmb();
+		break;
+	case __KCSAN_BARRIER_TO_SIGNAL_FENCE_rmb:
+		__kcsan_rmb();
+		break;
+	case __KCSAN_BARRIER_TO_SIGNAL_FENCE_release:
+		__kcsan_release();
+		break;
+	default:
+		break;
+	}
+}
 EXPORT_SYMBOL(__tsan_atomic_signal_fence);
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-6-elver%40google.com.
