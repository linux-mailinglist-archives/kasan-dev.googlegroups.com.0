Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXGIQ3ZAKGQEU2V6FTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 90ECA1582E3
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 19:43:40 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id p26sf129073wmg.5
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 10:43:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581360220; cv=pass;
        d=google.com; s=arc-20160816;
        b=SUd3TtBC9iMljtAP+D/Vy1RCbxIwmd4fNiZgEct+HtG0wR3RcpBp7WSwk8GAx4ewnA
         y0j++rBPB84j+JHMDgKqb5WdXYABmXK/xRF3qMyoJ7GGzhNpRGpbaoT/USF3me0MsNxH
         3oOHsy3Y4UzHFFfZu+9OobSqStUbrCs7KWaEsIpt1qGcd4u+zZeafzpVYAZW7/8BcP+m
         dy+kt8Nc7w/0kSbbk7m0osdY3G9YuMBi2+av+hT3FJomMpMOx0ziZDynK40CMVCAGbOm
         F8BgGqjHSlHVOtASAeLBL5k5ZTjtirkXsvnx/9+15ltEL2ws4hFLgXTmtVMUQy5vPsGY
         f0oQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=5HWFdNbs+N417qCPPacQCbRZyI3lQVM2ZfB0PKkpmIA=;
        b=qWOW5zJIvV9qw2Tv6Aa4E8BnUzpCHKxMfLRbEo4RDwHGMrU1FYF84Nc2JYjnebNRhB
         WBc5/tSr7pRly3imUy+AUOwqICJRPcfIcfX5tmYYO6C+umiZbf6hA0YI8458veG2LOz6
         w9yFOXoWHexM1gralljxXgW98EN26AgOh/NhJr1/NYaoDNWUXc/0LFSDAYitAKZDzZb8
         FNB83v040HeYQo9I4rKuiWglFeHhWCWokTlo2pEUn0imoKCpC0GgOdwEJCuQzoYKK3GS
         WcW8wnJ08k1/zk6rl1eCU1pOTitPHUKitW4ENyeL03dsr5gk+yhCCW0IZbsRLlf94gTj
         TSCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JQW96SML;
       spf=pass (google.com: domain of 3wqrbxgukcaefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3WqRBXgUKCaEFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5HWFdNbs+N417qCPPacQCbRZyI3lQVM2ZfB0PKkpmIA=;
        b=EsXqSFFv1TqF1I1SBQj6oyA2lhJUYyYa3te2lSQzcytwn/3+EwuM0QZpMcCjoKpQ6+
         8ja2AOTjrxz+NQ304lvUZfK+du6Dl0jiC8kkQcsvbjdp1sG4X+VouhbO7KhtMnhIb2uO
         t/VEOnnGE2ltPidylh03aSbj5W3TthVJye/X70ojvfT8WzdFcjJCRENlxQAoOnS8ycmo
         gF9rulF/dT5d0IJ/Iur/ZXWlmMp/OBUYRGx4Kup4+i/9u9q7ASFTxiuTX85Pn9I94Lbk
         NCkEMB6/7aNGdqxlumGWziuxiiVP0TMaOe2sgdaP/ivgMumZ/aXhwUkMhdbISn1jG2dE
         5Szw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5HWFdNbs+N417qCPPacQCbRZyI3lQVM2ZfB0PKkpmIA=;
        b=G8GhsTvUa+8IFtimYCdwoUeksrAUYjuO59w9TO5MWNiWXMwEpzCZOXev1rYFR1EuIH
         drnE+D5jyMSi1T3mH2aCXtSZTH8sJCxQ6UGo/Ye8Ci1NiddJ7xiKW4SjLcf/dNsFCMBd
         faH7O0+/46J+TFjBYVXnIaWv95qq6ZLmNfwvpw4IiXTSYrXIl6VmUcnoIuPQADxzdelU
         gB91I9Qj6xFTERny1dfclzIQ7c9nD7chkT757H8Xj/wU8XiAN06wixNPDbjTMcVzZUk/
         2vfl5ZLX+qcwVU75xq2L2zikREaEm65+3fnLimJhqLtYPeDzL6yOJcs7ErBpgGRvz9bw
         3ImA==
X-Gm-Message-State: APjAAAU0Ai/1bcX98AgQoT7ditKnR3qSnHo607gJ6KkLdwhFvEvNrjY4
	v5NyLVSlFk9kYQ+cGNLhG+4=
X-Google-Smtp-Source: APXvYqzj/qNrp1RFejYs++5YJFmXzqCZ/JDtfSPLUUH0ROq9Rk6X3NzIFV+rVzKwdwV4Xg7lgQyxhA==
X-Received: by 2002:adf:e2cf:: with SMTP id d15mr3348920wrj.225.1581360220316;
        Mon, 10 Feb 2020 10:43:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fac2:: with SMTP id a2ls5990884wrs.4.gmail; Mon, 10 Feb
 2020 10:43:39 -0800 (PST)
X-Received: by 2002:a5d:6a0f:: with SMTP id m15mr3544933wru.40.1581360219362;
        Mon, 10 Feb 2020 10:43:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581360219; cv=none;
        d=google.com; s=arc-20160816;
        b=JfaVcVaBBpqPErWbpj6AutFye1zyh/4jtgYeUJb1lbO/dSZrA5MDIH5NrnY4ypsnaJ
         c1/Q3oRnHRz25AY++ZVgZqBiAN2jiRIJcrImlSsdk8G2Ok/jbid1jd2oFI/yoOyX68g1
         c60paoQS6kwzfo1vNklAK+mwxe6mFdfapTcofSbsX6b4Hxt9fgLCFaiOBeO71UqhqNmK
         nufZTTtQaDd8diK7zoJNWs04FgW52ZcJ+yIcuaRxEMmpBffjXmO7B4VzDu8MqPeMziPV
         DlQS3Ig8QAL23mCOEMMGk1nPV4/YWJoW6UzwZfn170BNhNpa2rw14O7RFxpJZs3K+7LM
         7RGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=/uNmwRP5i1M3BzrZ/s9fqUFQKdmd/YrPMERWgsitzGo=;
        b=G5ObKAv6vco3Cm7WnEgkQ3yl/g2Q8HSVWEZUaaD5noentLxI3xZlqNtqJr4/UHsi6l
         UGx44qZD5stB5aUqvE4iaW7tiSWBFyiGl483+dEiZGLCnVtlaDCBOUxwgu8vZo1Zxqmk
         jLEMYhVu1ghkXPgFdPyHxoUCfAnmas5i67CDzI3iqF6Y9fH3KuzPr/qfiQ5yRuGmJCRC
         DiixFX2Y4K6SU9eX8P5eg2F2P4h+EkoFKBHDVyxHhesndyfCiehJwWrSeFIjQK4IU1b6
         g/FeKCxI1QZ+9Xj2+0Xv41eUmZOpzuBJiNbBdNfqXSDv12CRoCVrIP/uWBo7uiox1AUE
         crZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JQW96SML;
       spf=pass (google.com: domain of 3wqrbxgukcaefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3WqRBXgUKCaEFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id d191si22109wmd.2.2020.02.10.10.43.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 10:43:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wqrbxgukcaefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id o9so4856434wrw.14
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 10:43:39 -0800 (PST)
X-Received: by 2002:a5d:4e0a:: with SMTP id p10mr3516566wrt.229.1581360218892;
 Mon, 10 Feb 2020 10:43:38 -0800 (PST)
Date: Mon, 10 Feb 2020 19:43:16 +0100
In-Reply-To: <20200210184317.233039-1-elver@google.com>
Message-Id: <20200210184317.233039-4-elver@google.com>
Mime-Version: 1.0
References: <20200210184317.233039-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH 4/5] kcsan: Add kcsan_set_access_mask() support
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JQW96SML;       spf=pass
 (google.com: domain of 3wqrbxgukcaefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3WqRBXgUKCaEFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
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

When setting up an access mask with kcsan_set_access_mask(), KCSAN will
only report races if concurrent changes to bits set in access_mask are
observed. Conveying access_mask via a separate call avoids introducing
overhead in the common-case fast-path.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kcsan-checks.h | 11 +++++++++
 include/linux/kcsan.h        |  5 +++++
 init/init_task.c             |  1 +
 kernel/kcsan/core.c          | 43 ++++++++++++++++++++++++++++++++----
 kernel/kcsan/kcsan.h         |  5 +++++
 kernel/kcsan/report.c        | 13 ++++++++++-
 6 files changed, 73 insertions(+), 5 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 8675411c8dbcd..4ef5233ff3f04 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -68,6 +68,16 @@ void kcsan_flat_atomic_end(void);
  */
 void kcsan_atomic_next(int n);
 
+/**
+ * kcsan_set_access_mask - set access mask
+ *
+ * Set the access mask for all accesses for the current context if non-zero.
+ * Only value changes to bits set in the mask will be reported.
+ *
+ * @mask bitmask
+ */
+void kcsan_set_access_mask(unsigned long mask);
+
 #else /* CONFIG_KCSAN */
 
 static inline void __kcsan_check_access(const volatile void *ptr, size_t size,
@@ -78,6 +88,7 @@ static inline void kcsan_nestable_atomic_end(void)	{ }
 static inline void kcsan_flat_atomic_begin(void)	{ }
 static inline void kcsan_flat_atomic_end(void)		{ }
 static inline void kcsan_atomic_next(int n)		{ }
+static inline void kcsan_set_access_mask(unsigned long mask) { }
 
 #endif /* CONFIG_KCSAN */
 
diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
index 7a614ca558f65..3b84606e1e675 100644
--- a/include/linux/kcsan.h
+++ b/include/linux/kcsan.h
@@ -35,6 +35,11 @@ struct kcsan_ctx {
 	 */
 	int atomic_nest_count;
 	bool in_flat_atomic;
+
+	/*
+	 * Access mask for all accesses if non-zero.
+	 */
+	unsigned long access_mask;
 };
 
 /**
diff --git a/init/init_task.c b/init/init_task.c
index 2b4fe98b0f095..096191d177d5c 100644
--- a/init/init_task.c
+++ b/init/init_task.c
@@ -167,6 +167,7 @@ struct task_struct init_task
 		.atomic_next		= 0,
 		.atomic_nest_count	= 0,
 		.in_flat_atomic		= false,
+		.access_mask		= 0,
 	},
 #endif
 #ifdef CONFIG_TRACE_IRQFLAGS
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 3f89801161d33..589b1e7f0f253 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -39,6 +39,7 @@ static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
 	.atomic_next		= 0,
 	.atomic_nest_count	= 0,
 	.in_flat_atomic		= false,
+	.access_mask		= 0,
 };
 
 /*
@@ -298,6 +299,15 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 
 	if (!kcsan_is_enabled())
 		return;
+
+	/*
+	 * The access_mask check relies on value-change comparison. To avoid
+	 * reporting a race where e.g. the writer set up the watchpoint, but the
+	 * reader has access_mask!=0, we have to ignore the found watchpoint.
+	 */
+	if (get_ctx()->access_mask != 0)
+		return;
+
 	/*
 	 * Consume the watchpoint as soon as possible, to minimize the chances
 	 * of !consumed. Consuming the watchpoint must always be guarded by
@@ -341,6 +351,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		u32 _4;
 		u64 _8;
 	} expect_value;
+	unsigned long access_mask;
 	enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
 	unsigned long ua_flags = user_access_save();
 	unsigned long irq_flags;
@@ -435,18 +446,27 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 * Re-read value, and check if it is as expected; if not, we infer a
 	 * racy access.
 	 */
+	access_mask = get_ctx()->access_mask;
 	switch (size) {
 	case 1:
 		expect_value._1 ^= READ_ONCE(*(const u8 *)ptr);
+		if (access_mask)
+			expect_value._1 &= (u8)access_mask;
 		break;
 	case 2:
 		expect_value._2 ^= READ_ONCE(*(const u16 *)ptr);
+		if (access_mask)
+			expect_value._2 &= (u16)access_mask;
 		break;
 	case 4:
 		expect_value._4 ^= READ_ONCE(*(const u32 *)ptr);
+		if (access_mask)
+			expect_value._4 &= (u32)access_mask;
 		break;
 	case 8:
 		expect_value._8 ^= READ_ONCE(*(const u64 *)ptr);
+		if (access_mask)
+			expect_value._8 &= (u64)access_mask;
 		break;
 	default:
 		break; /* ignore; we do not diff the values */
@@ -460,11 +480,20 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	if (!remove_watchpoint(watchpoint)) {
 		/*
 		 * Depending on the access type, map a value_change of MAYBE to
-		 * TRUE (require reporting).
+		 * TRUE (always report) or FALSE (never report).
 		 */
-		if (value_change == KCSAN_VALUE_CHANGE_MAYBE && (size > 8 || is_assert)) {
-			/* Always assume a value-change. */
-			value_change = KCSAN_VALUE_CHANGE_TRUE;
+		if (value_change == KCSAN_VALUE_CHANGE_MAYBE) {
+			if (access_mask != 0) {
+				/*
+				 * For access with access_mask, we require a
+				 * value-change, as it is likely that races on
+				 * ~access_mask bits are expected.
+				 */
+				value_change = KCSAN_VALUE_CHANGE_FALSE;
+			} else if (size > 8 || is_assert) {
+				/* Always assume a value-change. */
+				value_change = KCSAN_VALUE_CHANGE_TRUE;
+			}
 		}
 
 		/*
@@ -622,6 +651,12 @@ void kcsan_atomic_next(int n)
 }
 EXPORT_SYMBOL(kcsan_atomic_next);
 
+void kcsan_set_access_mask(unsigned long mask)
+{
+	get_ctx()->access_mask = mask;
+}
+EXPORT_SYMBOL(kcsan_set_access_mask);
+
 void __kcsan_check_access(const volatile void *ptr, size_t size, int type)
 {
 	check_access(ptr, size, type);
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index 83a79b08b550e..892de5120c1b6 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -98,6 +98,11 @@ enum kcsan_value_change {
 	 */
 	KCSAN_VALUE_CHANGE_MAYBE,
 
+	/*
+	 * Did not observe a value-change, and it is invalid to report the race.
+	 */
+	KCSAN_VALUE_CHANGE_FALSE,
+
 	/*
 	 * The value was observed to change, and the race should be reported.
 	 */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 57805035868bc..70ccff816db81 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -132,6 +132,9 @@ static bool rate_limit_report(unsigned long frame1, unsigned long frame2)
 static bool
 skip_report(enum kcsan_value_change value_change, unsigned long top_frame)
 {
+	/* Should never get here if value_change==FALSE. */
+	WARN_ON_ONCE(value_change == KCSAN_VALUE_CHANGE_FALSE);
+
 	/*
 	 * The first call to skip_report always has value_change==TRUE, since we
 	 * cannot know the value written of an instrumented access. For the 2nd
@@ -475,7 +478,15 @@ void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 
 	kcsan_disable_current();
 	if (prepare_report(&flags, ptr, size, access_type, cpu_id, type)) {
-		if (print_report(ptr, size, access_type, value_change, cpu_id, type) && panic_on_warn)
+		/*
+		 * Never report if value_change is FALSE, only if we it is
+		 * either TRUE or MAYBE. In case of MAYBE, further filtering may
+		 * be done once we know the full stack trace in print_report().
+		 */
+		bool reported = value_change != KCSAN_VALUE_CHANGE_FALSE &&
+				print_report(ptr, size, access_type, value_change, cpu_id, type);
+
+		if (reported && panic_on_warn)
 			panic("panic_on_warn set ...\n");
 
 		release_report(&flags, type);
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200210184317.233039-4-elver%40google.com.
