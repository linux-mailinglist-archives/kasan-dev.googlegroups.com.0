Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7VJ4SGQMGQEPKJXLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AE2D474D94
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:48 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id y15-20020a056e02174f00b002a4222f24a5sf18991685ill.3
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519487; cv=pass;
        d=google.com; s=arc-20160816;
        b=pw7wMioSKqhZY1VF0z5DeFdvo4fwnmNA7jZL06PqOmbIRqaVwPEWqF38ZJAd6e7COG
         672L40ozDhpMYZkfXt8bwLrF8scxKHftA5UJJUkFRGKpfluzPakSFHHP3jmJc1JMdZp8
         1tn4gAQYtPM3l6/BJSrpTlZs1If1JWJdRhzPw4up8DdWDfIoctXpLjRB/m8pLs0+ehKV
         ASKBtbbvcCvsk6oOEx7UnvKeRVn6//txMdanR1Sur5j3AuO9PacY4uMtYJ32+mQ2Fb3P
         AKfbibRTS99lH/nAYBw77sJ4pE5aNGkKmEdHkzyHwgC8f2Dyy+cf+wroq235MXI0QOf1
         zUiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Js3FCpj841Rvfs61FIiOFvrLhLgEbkB3/dRh7wcZ38w=;
        b=ncO09SsgTUTQNRSxjwpy2vYAVODq/NbASa8ByOmLMWhzWjANpzi0BBFB+AepHCRbGx
         bU1FFPPesMZZe58IWOvRqDxk8yueK2TUOWfwnHgO45NiblPxXqnSsQwwWEbcgn9U3gUf
         b4F11QB0e3BlUCuyeSHQAoDZzgJ8QDywz7gYRPV5orWIQlaaWG3I/++mQ/k7TPADJYni
         wKPP24np1dCu/TE3x1PY75ZvoLhbp+6x41w35zWgpg4yAxI25Vk9iksfM6IDFWGI0TrX
         vWy6/2u1C+8V+0CYZZfG1Isqo94xBiRPF+K5KCG6cmh5lq9e0wRlKZ0vbncNb8s5ltFE
         JqRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=N82ruOjD;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Js3FCpj841Rvfs61FIiOFvrLhLgEbkB3/dRh7wcZ38w=;
        b=fOC3/RYeuQ7J9zhseEzHdYuZ3NZVmBM/FgOWTJ5Xo8qV/ImtPFXy99Tmsq0nC3JEwg
         3oAAK0y6MBOHPLoseVOlLFioj8jyDvJHJGB4YYjTmJj8bs5Gw+XiCtgDMEBUpoTA70R5
         BmOonpW9mdZEgt5F07fhrYEcBwwKgMq1ZYp4HVQiwQWl6Hw6mp9yqAmGHJw9/KKb3ChZ
         KFGQS2bDQEbRuVMy7Jr9Dld9hIhsfZGtEpocyC4iPoaRfQj6LGFB6GpXtpbRPaY2AuuS
         g7tJPOXGEjvyPZaE5srHExRQEvApYvw5y5nW0EH5YYaGeGSGQip6GGYx2zZexcPpKNfa
         dM/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Js3FCpj841Rvfs61FIiOFvrLhLgEbkB3/dRh7wcZ38w=;
        b=GrmyinUuFuEWvn4clPX2IorFEkxGksSdPcghL+yBinfnKP+IfuhEUM0ea8bwE16cT1
         ZZ2TulIuLqIEZD8Mn0Vft2EUgW/XLb82vP4r1v32180BNlvgD21XigeZj0FTcsOqnqbd
         iBCt/wf6MIpO/Vvb5QJPM48dWI8w5yBUtv/QR/ac/KYNwdlCjDzuE+7/AeWmdOd5dggg
         oV1Jz+pNl7cPlD9XdCKMKoMNMrr+JAF5VhBVPFoQZ8j8ta1wNFg3iL3u4DlNeqzk5E1k
         px+bAv+gzRbm1jXBSv9FlUcu/7dnTeq7SdZk2chuzdAswvT3BwmcLtopqRp2RKPKqR46
         zMsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5335I2sa4fSkYIJE7d4tEAbRY1j5JjSS/utBpra4oFcyTTko4L1O
	BHFKezieud6t1GBnxyMWvvM=
X-Google-Smtp-Source: ABdhPJz14D/aBDCyIGrcotzIqE6vTsJx56h0cblc5ALk/NCgk46+xfgNH2wAoZHhY5ev901fxmBTpg==
X-Received: by 2002:a02:9389:: with SMTP id z9mr4463267jah.473.1639519486960;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:2a02:: with SMTP id w2ls52059jaw.1.gmail; Tue, 14 Dec
 2021 14:04:46 -0800 (PST)
X-Received: by 2002:a05:6638:218e:: with SMTP id s14mr4410277jaj.391.1639519486460;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519486; cv=none;
        d=google.com; s=arc-20160816;
        b=1AzhhaLyN8ALrIXSePHmWEqVvKpK2wzg05tvosfQV7yTyEXfVbocNhIHxO0FjgPejI
         HNibiXlPyotbSWtGFItmeheBEWPICEn1CPUY5OZ7OmOkjxr/U4LBBVHui+LD/hpYbH0U
         yVtWGyEsWo4dDynInBMCysLskRf9PuYHgLn3Hp7lApOIxjm8Rhtmlgu07yxJNLVUpdeU
         +v2N1IsAuS1Jg4qeZi1k9vaSiN6e0f5E9LO9AqCOg8ReULgPvN5Sv94o/K5K7t5qZu2v
         TUmzFc6NaZgjNqJSQqP6zJuT2CBvCcZsaoqqAMjQNsABqpzZ76EtsjKTa553GbVwqvrJ
         csHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vVIkdON7wYp1mwliFuHozDNPjC2F9O9EKSn5tS86rrg=;
        b=DuvK0V7mLRuOqFyQrgDMQkvNAyAyETGb25YXVLQybarJUevrKtM+3Z0a27Y2epc45S
         DJ0Sr2W1a6uuWcT1Rks62EEoWiLkrGSjQ0tePkZcKghUbW3l8er5IdeGw1afJHzYbHdM
         xfGFwBPKBj9fuBLptjlJkc/NccCXs7YjASFVdNH6rE/Gy5RBZxZxc2cSBhG4HaYWgzcM
         1OtdvLPLr63m9IJMmQukl+J4HvoXuNHWQP2LZabg/kO5WQ74L7VHVkYA9m8FSjBB4Idr
         WpoHMiY/b8Xg6kuQY2IVypRvwx1gOLMwrJA4sBZ1+XDXo3VH7og3ZHh1i+8eajwP1qED
         wCkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=N82ruOjD;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-2faa6b53fc1si12580173.0.2021.12.14.14.04.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id EDF5FCE1AFA;
	Tue, 14 Dec 2021 22:04:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9D1D9C34608;
	Tue, 14 Dec 2021 22:04:41 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 62AB95C0DF2; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
From: "Paul E. McKenney" <paulmck@kernel.org>
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
Subject: [PATCH kcsan 05/29] kcsan: Add core memory barrier instrumentation functions
Date: Tue, 14 Dec 2021 14:04:15 -0800
Message-Id: <20211214220439.2236564-5-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=N82ruOjD;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/kcsan-checks.h | 71 +++++++++++++++++++++++++++++++++++-
 kernel/kcsan/core.c          | 68 +++++++++++++++++++++++++++++++++-
 2 files changed, 136 insertions(+), 3 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index a1c6a89fde710..9d2c869167f2e 100644
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
index 481f8a5240898..9160609139666 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -939,6 +939,22 @@ void __kcsan_check_access(const volatile void *ptr, size_t size, int type)
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
@@ -1123,10 +1139,19 @@ EXPORT_SYMBOL(__tsan_init);
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
@@ -1136,6 +1161,7 @@ EXPORT_SYMBOL(__tsan_init);
 	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
 	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
 	{                                                                                          \
+		kcsan_atomic_builtin_memorder(memorder);                                           \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC, _RET_IP_);          \
@@ -1148,6 +1174,7 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
 	{                                                                                          \
+		kcsan_atomic_builtin_memorder(memorder);                                           \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
@@ -1180,6 +1207,7 @@ EXPORT_SYMBOL(__tsan_init);
 	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
 							      u##bits val, int mo, int fail_mo)    \
 	{                                                                                          \
+		kcsan_atomic_builtin_memorder(mo);                                                 \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
@@ -1195,6 +1223,7 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
 							   int mo, int fail_mo)                    \
 	{                                                                                          \
+		kcsan_atomic_builtin_memorder(mo);                                                 \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
@@ -1226,10 +1255,47 @@ DEFINE_TSAN_ATOMIC_OPS(64);
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
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-5-paulmck%40kernel.org.
