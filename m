Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHUV3CGAMGQEHBFWSWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A65245565E
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:11 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id c40-20020a05651223a800b004018e2f2512sf3444366lfv.11
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223071; cv=pass;
        d=google.com; s=arc-20160816;
        b=OeYcf+EYiX1ZSiXC6bgZE8z3CPTdT84O0847sWYroOw0F+gf6NiaLAbvfNjHZC1WQe
         rW5lkHxzHbuWJyBK7YeZgucJcXa3kqNrllX38pHQtyukEUefZ2pfjQPkFMDj5UL7adZH
         m1lHxvDOct6WstB+8y2pWktzAP/Sj9KXrzT/Q2RCKMe6TyWZV0QQsFo9TTt3wlE1UgGr
         5wxOmdrCx2bJ2PXQtg9DsUNc2uinPBKKyDCZZE9I2MVWfSb29QTmvqeNzs/epV8W8W4v
         QhB0gygplzYTQKKnq5sBlt2wHVsXH4Z3R356wt1iNMhQVtzZUgT/XC620lzX7jfwj1ar
         CNpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=8cyC2YEcJj2xf5T4I/gsp7ncamFmK+HFS8MZplpJXKo=;
        b=gS9H+F+I/peNIsbEOhgDfAWg28PAzXSL3c2OuwCiURqXh8/t686lSpr+u5LxeCUsKo
         6AekUzvMcd57eIeWOl04oIL80K7VVjLiGZGoQtRiRURCZY5csi+Ys0UwOb2/IeSKIOj7
         3nD7A2eDNfA7+CYGJGNlKoHqVyo7NWyu0sqROi1LR18i8RTUr+b0FHvPu8TlnJ+GoaLP
         KheEOuBgg/nP+ZiCL6TiqpLdDUc6Ge8f8qt8gVfPXjjuh8uusWd8iAUtbZ0Hqps9w7XI
         Vawn8aQUe1Z+4HnEPUc1LNWlDhTc7IsDCmgUH2KpkLAALqqdgz/egbh8i70F5D6VSrao
         cCaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZvljMtx+;
       spf=pass (google.com: domain of 3nqqwyqukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3nQqWYQUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8cyC2YEcJj2xf5T4I/gsp7ncamFmK+HFS8MZplpJXKo=;
        b=kNhoMeCMQ7307HgW9+4EOG6IpxaDkQkCsA1NNiqI/NkZG2XaVZVCZIlNeNDkxkARBQ
         s1JA2ywyW1l7ZHD8lYv4UNAOVcRWybCckEjxLeZtFktIS2KneL6vH6nhLOJn5nVp1Ix5
         1prrb8tt9T5tX0phUxPu2Vq9QklH6lVvobp+mQscG30lul/qyJTHf3XC9ashWPaaZAOf
         H7nHykecObXazotM4kCKV1rDVJP5FCrQee0+vJOzY7iYIFb8oMNxQngV00AnOIezOgnb
         9cVhLBxiqOu2Bx9Vr46VQobQjbDwvjpvpx5IV+ml+8PA0VjY9pW0EDpLDC5pOCmGCaUn
         KK3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8cyC2YEcJj2xf5T4I/gsp7ncamFmK+HFS8MZplpJXKo=;
        b=0n0XAmtr0AEfle+0LBFkE3FF2qZ8m5pHieTyX0Wzdg8qf8CXHr+HZR5Bo+H/7EnK71
         x5U0RvMy2k6Oa+l3ZlqN0zGnr9krCy705Ps2uSf++Jq/StzmISmWRf55ug+h2doLLlxz
         ua8OynPKVQcmu3vZcYuzE+h/47xjr2CBPkRqDFU215j7SBVJivWIsHtQTHx03Y6bMtX3
         3hPal4iaR8KWvdhMlbb26cSW0OOM0W8gjCAG1zFXEvSmE3T3oOATGuhmic0shxTodWPR
         d3ac6CBzvaEKIEN+ckMT1Q2OkiIYHfJSJSfSD6pOLn2BNLER5KRcL0MZpdcIHRnipHr0
         s94w==
X-Gm-Message-State: AOAM530cfKc52oblBxmq+mTEDqU2tghgqSbO+wcKqR/XWE9u//S8KtrD
	MRW7Z9rHaSe2fwrQYYywlg8=
X-Google-Smtp-Source: ABdhPJzDQSHaTVyz96Anmahn4KWvv6shS4Fphj9iLxbWB45bT7zTZ15YA+LKHitSFTUDWlNBRZf6MQ==
X-Received: by 2002:a05:6512:3f04:: with SMTP id y4mr21151142lfa.180.1637223070867;
        Thu, 18 Nov 2021 00:11:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2610:: with SMTP id bt16ls1606962lfb.2.gmail; Thu,
 18 Nov 2021 00:11:09 -0800 (PST)
X-Received: by 2002:a05:6512:33ca:: with SMTP id d10mr22390209lfg.360.1637223069804;
        Thu, 18 Nov 2021 00:11:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223069; cv=none;
        d=google.com; s=arc-20160816;
        b=fpbb2GqeCpeOl3iFVBRgini9CM1cHk9uWkH4t4u7exRFU8GJ17+pmnmYs0/ak3tzN8
         luJYHgoSgxC69YdES60S6ZUjEVshpLHmVfvJHiQ3o5Eb0w/AVQkZDucR43nfxiNaL0qD
         Z2Ott3JIN/Qxr34iwbSH3CkiftS3FzZnTpOG1sNqKXdhzqedJIxrDwcKBKQE4woS+qBi
         AX1TOqaELWqY5LxOag5nkNjk037epx/MDY6TVXw94rY7maLgS3t4rROUUKAg2wn513vk
         n0BRsJcqYyW56yZrY3kpDrDUl+XB/nL7ZPe3j2emEt+FPGsbc7D/YFYOL2JdYPlsF8BX
         //ZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=HAAXujUo7vJi9QoAYq1xZhWCtJcnOt42cvkKdKb2mZ0=;
        b=VZ1hKj2JoPN31fPBCFkwwEjRxHNwoyPLDWaJoswQ+/Xjny5M5kXrdEPfaMsZPn0JFS
         7l+JAucA7MtlXhWA22jTp+3NDUvNVO2gBMszEUrt/fyu1bNaRJhkr3P6SWWHF70pSvup
         vpeVnjNBbbA6bH1uMPtn8cg4FBxqfNovq2WtfoaeBzoN0pbgnudh0jfo/WjjmqACEYDu
         rjrJzJLbMsdZKkW9EWm5eAqJvLFWUayRTgySXqUyf54strAKXi3ReblzOn871nq18gX4
         aFZLyeBMm2+lLyu98R3o9NZqrxd94T1vkaWAbB8Fb4ruJlWvg8QlbpwlewIFclkZs1vr
         5Tvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZvljMtx+;
       spf=pass (google.com: domain of 3nqqwyqukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3nQqWYQUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id z1si158346lfu.5.2021.11.18.00.11.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 3nqqwyqukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id l187-20020a1c25c4000000b0030da46b76daso3985439wml.9
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:09 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a05:600c:1d97:: with SMTP id
 p23mr7679237wms.186.1637223069169; Thu, 18 Nov 2021 00:11:09 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:09 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-6-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 05/23] kcsan: Add core memory barrier instrumentation functions
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZvljMtx+;       spf=pass
 (google.com: domain of 3nqqwyqukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3nQqWYQUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
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

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Rename kcsan_atomic_release() to kcsan_atomic_builtin_memorder() to
  avoid confusion.
---
 include/linux/kcsan-checks.h | 41 ++++++++++++++++++++++++++++++++++--
 kernel/kcsan/core.c          | 36 +++++++++++++++++++++++++++++++
 2 files changed, 75 insertions(+), 2 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index a1c6a89fde71..c9e7c39a7d7b 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -36,6 +36,26 @@
  */
 void __kcsan_check_access(const volatile void *ptr, size_t size, int type);
 
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
@@ -159,6 +179,10 @@ void kcsan_end_scoped_access(struct kcsan_scoped_access *sa);
 static inline void __kcsan_check_access(const volatile void *ptr, size_t size,
 					int type) { }
 
+static inline void __kcsan_mb(void)			{ }
+static inline void __kcsan_wmb(void)			{ }
+static inline void __kcsan_rmb(void)			{ }
+static inline void __kcsan_release(void)		{ }
 static inline void kcsan_disable_current(void)		{ }
 static inline void kcsan_enable_current(void)		{ }
 static inline void kcsan_enable_current_nowarn(void)	{ }
@@ -191,12 +215,25 @@ static inline void kcsan_end_scoped_access(struct kcsan_scoped_access *sa) { }
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
+#if defined(CONFIG_KCSAN_WEAK_MEMORY) && \
+		(defined(__SANITIZE_THREAD__) || defined(__KCSAN_INSTRUMENT_BARRIERS__))
+#define kcsan_mb	__kcsan_mb
+#define kcsan_wmb	__kcsan_wmb
+#define kcsan_rmb	__kcsan_rmb
+#define kcsan_release	__kcsan_release
+#else /* CONFIG_KCSAN_WEAK_MEMORY && (__SANITIZE_THREAD__ || __KCSAN_INSTRUMENT_BARRIERS__) */
+static inline void kcsan_mb(void)		{ }
+static inline void kcsan_wmb(void)		{ }
+static inline void kcsan_rmb(void)		{ }
+static inline void kcsan_release(void)		{ }
+#endif /* CONFIG_KCSAN_WEAK_MEMORY && (__SANITIZE_THREAD__ || __KCSAN_INSTRUMENT_BARRIERS__) */
 
 /**
  * __kcsan_check_read - check regular read access for races
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 24d82baa807d..840ed8e35f75 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -955,6 +955,28 @@ void __kcsan_check_access(const volatile void *ptr, size_t size, int type)
 }
 EXPORT_SYMBOL(__kcsan_check_access);
 
+#define DEFINE_MEMORY_BARRIER(name, order_before_cond)                         \
+	kcsan_noinstr void __kcsan_##name(void)                                \
+	{                                                                      \
+		struct kcsan_scoped_access *sa;                                \
+		if (within_noinstr(_RET_IP_))                                  \
+			return;                                                \
+		instrumentation_begin();                                       \
+		sa = get_reorder_access(get_ctx());                            \
+		if (!sa)                                                       \
+			goto out;                                              \
+		if (order_before_cond)                                         \
+			sa->size = 0;                                          \
+	out:                                                                   \
+		instrumentation_end();                                         \
+	}                                                                      \
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
@@ -1143,10 +1165,19 @@ EXPORT_SYMBOL(__tsan_init);
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
@@ -1156,6 +1187,7 @@ EXPORT_SYMBOL(__tsan_init);
 	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
 	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
 	{                                                                                          \
+		kcsan_atomic_builtin_memorder(memorder);                                           \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC, _RET_IP_);          \
@@ -1168,6 +1200,7 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
 	{                                                                                          \
+		kcsan_atomic_builtin_memorder(memorder);                                           \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
@@ -1200,6 +1233,7 @@ EXPORT_SYMBOL(__tsan_init);
 	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
 							      u##bits val, int mo, int fail_mo)    \
 	{                                                                                          \
+		kcsan_atomic_builtin_memorder(mo);                                                 \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
@@ -1215,6 +1249,7 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
 							   int mo, int fail_mo)                    \
 	{                                                                                          \
+		kcsan_atomic_builtin_memorder(mo);                                                 \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
@@ -1246,6 +1281,7 @@ DEFINE_TSAN_ATOMIC_OPS(64);
 void __tsan_atomic_thread_fence(int memorder);
 void __tsan_atomic_thread_fence(int memorder)
 {
+	kcsan_atomic_builtin_memorder(memorder);
 	__atomic_thread_fence(memorder);
 }
 EXPORT_SYMBOL(__tsan_atomic_thread_fence);
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-6-elver%40google.com.
