Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK7A6CFAMGQEEY7ACFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 380D642240F
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 12:59:56 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5-20020a1c00050000b02902e67111d9f0sf8969796wma.4
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 03:59:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431596; cv=pass;
        d=google.com; s=arc-20160816;
        b=T/k8vNqg8/sBRW2vmgJ4hjLoW11HpXC9QoBpRCUKAc2Ys3ga29sfga0vSLBRv8oUG4
         p56Zh65sVxVYf9KNn4fv84BcYNgwMQ6KzLjfpwHpaqF6ruK8lUrN5+OF1GaLzAs/UPOx
         Cl18z6Nkr0yYKOel3QH13VJFuHzAshl7+TmZYqh8kL0w8eBMknXiNOtwTU5rDR7xcbiI
         xWZ10sQkX1Yp+kVMkNzY9GLAE2N69Jvd8QKuuQeSPW8nu0NxgBNBKPNg4Tps01RSZmmE
         5i0Zh4ZNoPWZue2j91UgOY44iFUoWUQI8FvnvWBedBjOGjFUXwYgWedprERHF5JV9Bq6
         MEsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=UGBjY5bPgGSMgwBoBPvexj41jGHrIEqO5LxoXxqFyDo=;
        b=iZ3YGOAj9COaxdoB40prxMufwASYQB8FPppG7PnX0m5NrYQ3z27JFcBj8XlsEqFR3j
         aPdf4trrA0wVIb4OLd3fV0dhowXberSO8Oc5PhQKxPuzU3cnZITYntBG0lX0ZaGpzA1r
         PGvOdSSsp2UITHesdxuP+wirVkTiT1EMirEf+hzyp2WVfcQUQqGexVQ/yLZIcYu3vQQP
         p280w2rUFTaWOu6kjTjXS8mTMAL0wdKyOTcswu/61bUkAtpWzyczRWnQnZmAqpMdu7TN
         yIX3AHcNHtRt4xP9bwlpGsfXZyyxLhG5RmYGoBsk7djpShqC8BNCZ7cD4rAfxHkc8lU2
         i+6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VeFEuwcJ;
       spf=pass (google.com: domain of 3kjbcyqukcq0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3KjBcYQUKCQ0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UGBjY5bPgGSMgwBoBPvexj41jGHrIEqO5LxoXxqFyDo=;
        b=BqZYXnQdAsai4aA1r8kOQhV6oyLX7YmMGt6ntTWPSi9yx7b8uSWMThFb7vygQy+iNd
         mhU/S2Szqqlp4x/IGULypEKhkyDh7xL7ZhKJW7RsaqHdHCJRKHmoEUJ2J/C5ur+BtRyq
         ZJqbtHy2qZxi5P3CL3lWcxzN6Tu41eLSzwVeEnbYvnYl+Kr8laCjMSpZERNdAHJ8z6By
         zjZufgZxc48oPwmbaULPJl1jlq9tLYzovWy8eOiAoR1ls4f8hHhyOVIVy9cwRjK3Gqzq
         mGmNLu5KUq4IZr6SqHjAyiW5PxNhw7Belg0kpBjT6zR6rS2kN8LK5AscPlH2zP42X01g
         7AsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UGBjY5bPgGSMgwBoBPvexj41jGHrIEqO5LxoXxqFyDo=;
        b=f1zWm76QRLJOeRsbC3HZ8SFZaWTxirb1LklSXmwnJHjbEyuS5sAjk4Q7sQy6MAfE1n
         V2GmfE/EhIe5eSt4IH51qWSd+Mcyt7hf1ZVRGEe3SLUFSpv6jR5vMAUugLuQ4EFaL8Qu
         0Vn3CuVmC6DVtY6WZ0B2vqBois/Yw+gV+M7yjghgeuu2+DnkQzJQYK+Z6jZg3ogi5HLf
         lvBzMUanU4EMeO1BXujutqJbJAAKT4GksuToKa+zIZS5ReHOZ2iRLM9hooTFCwBtWwSb
         M2xLB/UJiekjRY3XgcYqhoNqCIIbVqUJ8kJhT/4rpl4ca6zKMLVZ3KYAjLW7ZmoA3JdG
         /6jA==
X-Gm-Message-State: AOAM530yfyikPqOukcZf3hf24nMvhO58zrkaxcdKzttQdmZdym/gTsP1
	PWhphFRvralq6MicIHHtf1Y=
X-Google-Smtp-Source: ABdhPJxwuZ5iYBisQlVrEWcBfvOeFrk5HAVgc4VuFe+ErrxrCaL510FFjABEP00lSbBi0EjgQ9I1xg==
X-Received: by 2002:a5d:5234:: with SMTP id i20mr21020871wra.415.1633431595919;
        Tue, 05 Oct 2021 03:59:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2051:: with SMTP id g78ls799777wmg.0.canary-gmail; Tue,
 05 Oct 2021 03:59:55 -0700 (PDT)
X-Received: by 2002:a1c:2d6:: with SMTP id 205mr2598683wmc.48.1633431594925;
        Tue, 05 Oct 2021 03:59:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431594; cv=none;
        d=google.com; s=arc-20160816;
        b=t/oi8+7WFWAzc4w7vM5Jk0XdYtTyRZwbWQFRs0Xfif9r+k0eej5LwfiocP8MF92dOX
         9VAQSjC0TAg5h4bNddYmT21jNgTEOCCea4vlM+PXtdP2Y5pxX9mPw49I/fTPZ7ppg4aC
         LxlLqau2JQfIwv+9sjQJWsLIKnlvpUSJxbPz5D51KJiE8r5LqdCU0EzYEXUGmqiSC0Tr
         elKzPPeEDz6hVcBBL3FluxBS50diFOq6m97tSc+FZ9QRdmG9kY8/LbL+SvLrQ14n0Ren
         86qA8Me/fFcCnWh0FVoN48oox+/JQ4fN63U3ffRSJQ/z8Rj42MKX8Lf2iheIdZY2mm5Q
         GMTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Htf1lRwWL3x2PhAFdQAPTvq0cnntLMp/giO1a42w/Is=;
        b=UEDEea6UtamG+2sI7ofrzrZPZalGVwKU3UO7OqNpx6N7XRXfsE5stcpAhIrScw7oWm
         7UCEAkyvML8jFHFv+Z9z1uJN5L+CbyuuqLtu0ED/q2Bxb5pED2lgfS0BV6rgKF398LCt
         7fhZDfMs2DeSMp2MC2n7a0by2TeUysdunPUkFvAWuSxlZajR7OexkwLcVQjzH4hz10Lh
         fEtDQQcLDlTJE85gIUqxMYZMdB2TxBzT/Yx/mX6agYI2hx6+WBgbOXYFe2Zd3QzUkJec
         n+EQ8UOypX5fgI8nnNwbMQjDsWy39k6fms0n2kQWoDW8nizLJVdMSPve5p6eZTLEHTp3
         lEbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VeFEuwcJ;
       spf=pass (google.com: domain of 3kjbcyqukcq0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3KjBcYQUKCQ0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id g2si147522wmc.4.2021.10.05.03.59.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 03:59:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kjbcyqukcq0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id k2-20020adff5c2000000b00160b12639a5so1397552wrp.3
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 03:59:54 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a05:6000:144e:: with SMTP id
 v14mr20924428wrx.228.1633431594443; Tue, 05 Oct 2021 03:59:54 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:58:47 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-6-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 05/23] kcsan: Add core memory barrier
 instrumentation functions
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
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
 header.i=@google.com header.s=20210112 header.b=VeFEuwcJ;       spf=pass
 (google.com: domain of 3kjbcyqukcq0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3KjBcYQUKCQ0ry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
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
index 0e180d1cd53d..47c95ccff19f 100644
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
 
+static __always_inline void kcsan_atomic_release(int memorder)
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
+		kcsan_atomic_release(memorder);                                                    \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC, _RET_IP_);    \
 		}                                                                                  \
@@ -1156,6 +1187,7 @@ EXPORT_SYMBOL(__tsan_init);
 	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
 	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
 	{                                                                                          \
+		kcsan_atomic_release(memorder);                                                    \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC, _RET_IP_);          \
@@ -1168,6 +1200,7 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
 	{                                                                                          \
+		kcsan_atomic_release(memorder);                                                    \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
@@ -1200,6 +1233,7 @@ EXPORT_SYMBOL(__tsan_init);
 	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
 							      u##bits val, int mo, int fail_mo)    \
 	{                                                                                          \
+		kcsan_atomic_release(mo);                                                          \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
@@ -1215,6 +1249,7 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
 							   int mo, int fail_mo)                    \
 	{                                                                                          \
+		kcsan_atomic_release(mo);                                                          \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
@@ -1246,6 +1281,7 @@ DEFINE_TSAN_ATOMIC_OPS(64);
 void __tsan_atomic_thread_fence(int memorder);
 void __tsan_atomic_thread_fence(int memorder)
 {
+	kcsan_atomic_release(memorder);
 	__atomic_thread_fence(memorder);
 }
 EXPORT_SYMBOL(__tsan_atomic_thread_fence);
-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-6-elver%40google.com.
