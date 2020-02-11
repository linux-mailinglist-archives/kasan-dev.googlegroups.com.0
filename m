Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2FBRPZAKGQENL3V2PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id E88C5159453
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 17:06:00 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id u8sf7142533wrp.10
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 08:06:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581437160; cv=pass;
        d=google.com; s=arc-20160816;
        b=yQzZGVJwFoIY48QtHpAlrmz4YFW+Jd2gT+EaWP+MJdkZplMXUeX4ubEY8ZxMkiudSu
         5X39PgBnGR127UmPWenh0h1m/l3kiVH++uZE/POrJ6Yc90KHkSXtpwgAWMF7ISCmdpE9
         5HwktTwe3WN+swyPmqZkrTvgjD7I1IJa6uf+ALr3TRHiDrZfrDA/zhR8kT04j/n4X6F8
         V5KkoFWHn+IppYPBpfD8D6qFBpeb39TzYeZWSktNQhx/Js4/R31Bxp9Uv2ZtJXiPKiIa
         2Ojl83n9diUBjSg80Oxpg6yy43b57pSNAPGptbm4aad31Hg01E2x/+US8P66hgaqQx/E
         9Y9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=iojchEYgsLeu+Uj2Ld75O66yvcWFbb9f94YR1Gt4dGs=;
        b=GCIvkYMwQIZl6mBaQkvmGcXeOGuauDYbvG/SjR99LAdulMfEA8GarCLjb7OdSv2IKC
         IDMXPa3tRAtgRrzDv+2UhpKtszhSwFBjIQrIGm23ME1QemyV7+wRgrAb9MOYK2PMZu8O
         8Ym4v15BHwHCbr3OUZWz2EJR1d+sTJAAGevglhKEYXNpkrVXs/XcrurkA3JzeVbpj12f
         L0pAsAR/85uBTZNNsi9xLOpx70wzn4kW2DxTpxMOibeSH3cwUfOaX15GTy+zdSTsxoKt
         VMJoQ9pAV+FvmSfFotRInUMfUYRW90UJBB7bDHgrVL251WooggKc2s9Qs7AL/AmFtaEb
         taNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RZkbiYaU;
       spf=pass (google.com: domain of 35tbcxgukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=35tBCXgUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iojchEYgsLeu+Uj2Ld75O66yvcWFbb9f94YR1Gt4dGs=;
        b=CWFPQnN04YJtshLsHgxl+wPwS9ahiZf3gRCa1sulS5JvcsmX8BGIwxujpgnM1YMMzv
         yEfahmxpyUBV/lgaydDGfY2vJ/2U73GgSG1x1w6IIcgas0jdl4fQ5hyJToCZKfQwgwH0
         TQgPud/HpyARacyFwmMG9DrG2gEY9jicct70eAdgg6TlY0ftIoDbebDnj7zluWnf2Mx7
         F2jryrkk0ZHNjnj5RtDFBrl/HvwdNaXJPsKeN+8o6CEQCBrdlttOf0N5zhl9JyG+IH3w
         aMnHsEcHxzJyAZxjLltoZo0gQE1ro0mRcJzwiiX4QouiAUdwnrfhk8WIdGruptcFOg9l
         q9TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iojchEYgsLeu+Uj2Ld75O66yvcWFbb9f94YR1Gt4dGs=;
        b=NUN3sSFnyLmgar1UIjPXkOSE/AnzpRS5Ql4i6DO9gHYhdJ74hpdaLMxe4Mk7IZfO1k
         Q82tFmyrfDStBPiAQ8z1+kmO+2MV7T1o/fMpEP1p2vvzk1yoFDPK2Drl3Lvmj4/lwsx4
         R7m8Kx5wOObb4OJiosHZqb0BdRlQBa5ta0x4OXLqxJdVHHeO8MU0Y/IohEF8pLBpVaFx
         3dFk5AiGAYtfknew0kBQzS2wNaAwKPBTNjfEj7TzWZe6xyto8TI3qdoW15kPK9goNJjs
         AZcJmvZYs4xdnh/tpxMSc8TfZT8jMVZ+xUZCBMIKtRUOaS9hCRuzW/bDMVrP4kShcqLa
         YGWA==
X-Gm-Message-State: APjAAAUF4os79DSax3Wa3m4JKGrTJ8KXRpzJEBLRZKg0YyLNjL1HmEZ3
	ypyvyCCdf8SHB5+8vO8vTXI=
X-Google-Smtp-Source: APXvYqx3AtQg5w4x6g6PFPmuHYw0wxeirM0kgsqkvs5+rlUnc7er03fQQIwIVmx8zCWnNjUYtj1kNA==
X-Received: by 2002:adf:dc8d:: with SMTP id r13mr9602421wrj.357.1581437160328;
        Tue, 11 Feb 2020 08:06:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:65d0:: with SMTP id e16ls8508180wrw.1.gmail; Tue, 11 Feb
 2020 08:05:59 -0800 (PST)
X-Received: by 2002:a05:6000:108b:: with SMTP id y11mr9446261wrw.187.1581437159149;
        Tue, 11 Feb 2020 08:05:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581437159; cv=none;
        d=google.com; s=arc-20160816;
        b=ymlws71DdQYE0nYKO21scNYXIpKsBOKg+LRYXCKWRVyOM0sdyxD6H7WOhM8jTUpQr1
         5cd7caYyVktyNmJ2XOPzHCztrFutBWgXuLJnJxF7R2NiRfYoh62rkqDAc44MH1sTmc+8
         mM/1jx1vBHBt43NZ/dDUBFxnrDVoW1U/0KDybyPNqc75ccNH8a95xZfhRVy0FT2OZeFo
         MTK9VpBI7rHdaoC9ikMeB6srff5fgZdjRlBlnIqOLuT6L+/+uDL64c8CQ76T8D/qOS3E
         KgU6nUCdFzA8yEwExfn7MMNG8/7FFftZZ+y+44sK7ElNLLAJh1XlfaeepzFECicY6Mwk
         KMyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=rjIlJ1mSxL5OyN0zHkfQmfiVb4ET4hnV80pAWbyb5D8=;
        b=Kbfyy+4ny5Q76r1Ily8BQVSx+7DPhXKVXEUsBC2OE4Sbwr6jJ4cf3I64DRgPv6eP+P
         NsomvgmDrShLrE4jhCwQG7KOqBbZovmcxf2TFZNQs3Kz3rMCZjpX+7mwcHi1yuMDj4AD
         t7WXGVkQ1XJ4tFjNSnmNPmKcQcoW/AM4lTBjeC2k7CAfuEustse1/Es31uqXdjHWSzxG
         RM/sYY7aIVZNDsmYarKnqtXIioVPTSCzK0qJ/DivtTijvNUbCSrCgrqiKLmNPuGMA/as
         zE/VREHFj+KERbj6wJT+zupaECFhMLlMAxVCPI93oco2RZ6DmfUHAQ5l4cw3rW5iJ1/H
         2M6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RZkbiYaU;
       spf=pass (google.com: domain of 35tbcxgukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=35tBCXgUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id p23si157598wma.1.2020.02.11.08.05.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 08:05:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 35tbcxgukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id s13so7121502wrb.21
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 08:05:59 -0800 (PST)
X-Received: by 2002:a5d:610c:: with SMTP id v12mr8793286wrt.88.1581437158657;
 Tue, 11 Feb 2020 08:05:58 -0800 (PST)
Date: Tue, 11 Feb 2020 17:04:22 +0100
In-Reply-To: <20200211160423.138870-1-elver@google.com>
Message-Id: <20200211160423.138870-4-elver@google.com>
Mime-Version: 1.0
References: <20200211160423.138870-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.225.g125e21ebc7-goog
Subject: [PATCH v2 4/5] kcsan: Add kcsan_set_access_mask() support
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RZkbiYaU;       spf=pass
 (google.com: domain of 35tbcxgukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=35tBCXgUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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
index d871476dc1348..11c791b886f3c 100644
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
@@ -493,7 +496,15 @@ void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 
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
2.25.0.225.g125e21ebc7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200211160423.138870-4-elver%40google.com.
