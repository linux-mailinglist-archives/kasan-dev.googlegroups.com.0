Return-Path: <kasan-dev+bncBAABBPNGTLZQKGQEHKXXC2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc40.google.com (mail-yw1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 6ABF517E7DB
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:30 +0100 (CET)
Received: by mail-yw1-xc40.google.com with SMTP id h8sf17047722ywi.5
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780669; cv=pass;
        d=google.com; s=arc-20160816;
        b=lUFbozBVcCNmTAxMJ71aynWxKj5t6t0ODnY7k8EiVcISpwsuWHc/qa8SggBGjnuK0W
         iOP+xdgHPwwCnz5bnf2bi6Vys9QLQXFUFnmIXwwsTyLzrds/SO7xfcQtaQB8Ab/ZZE4e
         d3e39UXsNZcC5DeCC+kiFVfgPfcjSIrSt2L6gRDxFkosV6PzTWAbQgQo/ciaQ/XIJiV/
         lQcx9MmObwA5BI+ySL4b2sjQCqb4oTDGf9Pp68lVHSu1tmj4VRoXQE12g3yLp9Fz6RYz
         LgPiF0NHFrVOuKEY3+GF2ISMC/LJVFPWt0fE3qu+azi1Yyf2qP9FdGxuxhdKcUScUVgO
         AFPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=hlNV0aUKkeg7KsVg870H4tB1IUlqGXzC4HdHIjkA5H4=;
        b=LzfPR6/TkEIXP0J8OY0kRyzECjS9B+1mRM7gEsBBLb5/2pbxqmP9Ms3keu6N7CI6Bs
         LzSh6f7qxk45BrwePY5wKCs5vtI7HaqvEyo2AOfDMxPIUNQc6JCg8af4R0aG7Ml+woaC
         2AXbICh1QDjgQLv6HYQprC+/ksle3XDwfyfkOp/hR70CeDLDV4ciRiATdQ0piphwysZJ
         2ArC1IruSdYfyna/mvU6C/hGUbexo4KcJi2HzsRgBJ4b6sDZ2Owv49xa6wWQeT94bpyk
         bTuleeJvfgQU9wxvSgHgSacJ0j7toLcR36nPZdkyzxbttpNhM6WJTZ1GwwiISu+B0Ci3
         iJbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="jbMGV/zp";
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hlNV0aUKkeg7KsVg870H4tB1IUlqGXzC4HdHIjkA5H4=;
        b=k3MAm1Fh0L+nj5fvS7lqLWFBSmOSUDvMrPvF8MKIBxEYc+zBN30OgcsGblpT7lUYN6
         IpPjkqQWGLSKRCz+Qv/PP2rqZSHW607WA0Lm/paHiFheGpIB6zCvcFdh806JM7SQAUVr
         iVQB0U6/vnaD8RgserCu/xy6+QQbDMUae5cwMMhTeD+GGA9O6u9L1UA8s2p8nmrlBuZ+
         P29Oj7IbUEev4NYF+Mpt66cHuwwy6cwkHTe/ca4AcqVoaiAr9qyRwiY6Nc3PEiQBk/fs
         Dp6R2AMCNJG+hxZbKJ7bwURUhd6xwIJ48WfUhi7ZhMoVv/hndjQDjiiC9RdiOyA56Vsb
         bqKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hlNV0aUKkeg7KsVg870H4tB1IUlqGXzC4HdHIjkA5H4=;
        b=OwQz/mUnAyczcDk6A1xK7U0HuyerDfzN04CtwhQTX01GC0VSbK7QQtqImyljwRAK5q
         VmW5asa3nmWl1WKd+ypu5l0K6l+g5c8jxSQ+ynGfzkBxfThRfnL++tqdt3ILWaK0hP7I
         kJeJDqVwgzgVoqpCGq3JYjp5FkirZGKee4tB8pr2lTssA3aVwRjsvx7e1j573aG/55an
         hxnocOU5mRyWuoLcPYVjlILPYWSDC7dCJ2GUrYUGcfYswiLFYxIxlxKFDlOxcCKNyxQF
         WtbL491sgWRJrl3y+ytff8rH4xU6oXVrv5+pM07x07ZDCr53wYrmLTaa7Ems0tGZmW9s
         AfXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1NQqeGnNwkVJyzYdF4pxDjh/ChWvyx7RGwpcSFAbmurNKsb9k5
	YDLKG8oOcIhmzo1iY20jFLQ=
X-Google-Smtp-Source: ADFU+vufkhg2noczN921jttguzaRr5sJ54OEIUZeCX98ILnu35vgJdRIVk3RdPMKYdRP3qnf30VA7Q==
X-Received: by 2002:a25:cc8a:: with SMTP id l132mr19137364ybf.178.1583780669383;
        Mon, 09 Mar 2020 12:04:29 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:df89:: with SMTP id w131ls2943499ybg.2.gmail; Mon, 09
 Mar 2020 12:04:29 -0700 (PDT)
X-Received: by 2002:a25:2f44:: with SMTP id v65mr19656153ybv.442.1583780669042;
        Mon, 09 Mar 2020 12:04:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780669; cv=none;
        d=google.com; s=arc-20160816;
        b=nDybLS1M7yymRty/n2Nd3YInjr/6IfAQqukKdtlBxwd0x/uBrSgS0/kfNsw7vVNhKx
         8qUbX7RxxsdjlHDLkRFaj/ICL/U0fzSZFGDPzE7JSds9EA2RnFeqFz2Lq7QTLp0vG18k
         qFIe/QnqKvMvU3Ci9hbJzl4fndivJn/G9lpyX7JOMotq/D2eJBPXtqxCRdDaAysAwLLL
         kIrXyIDqgjGNmTfXp4buu/FJh7zudJqUe5T6hHavlzGZHX5B66qnz/yANST31T/sw15H
         klGWgI2Qsl0WMBHrvlrP2+WmHyEK/ATjHeibtRb8eX41/396uLB8nH0V09wDrepAvkwZ
         bKTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=84QBQaylsc7MeMLSPXn/T2P2X5nhpABl2K4HEFI035M=;
        b=XyAy9Hogg7WZN0NISyMi7fSBe+GlJ78/87KC5R2trIym1ZCJ1k1d463EFs9SHcVE5N
         75y4rizZZhX/oMw+aI36uuXLgI0KWhOrdUBnnE4aPY6WMAUCsAT5Px2uSyG/5C6Nd2KB
         h6w11yyX/hsWA2oas/BjTyRJtkiZ+If0/9ZLQjuECqhkV+032y7ZwEyG7hEj0lTsQ6Ud
         W9RBjH/A7S0pZJIHBnU4y42imQ/8K0U8Jqd86vfL2ZJU1G7H00oGPdjA9qYQFDzE4eeC
         YR76x8ho82AmWHBErRq/8xOUgHa69r52LYqzDtvc+WJYseHyNbT1iNunGv+5QUin3r6T
         HDeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="jbMGV/zp";
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e131si306171ybh.3.2020.03.09.12.04.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1810A2464B;
	Mon,  9 Mar 2020 19:04:28 +0000 (UTC)
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
Subject: [PATCH kcsan 24/32] kcsan: Add kcsan_set_access_mask() support
Date: Mon,  9 Mar 2020 12:04:12 -0700
Message-Id: <20200309190420.6100-24-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="jbMGV/zp";       spf=pass
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

When setting up an access mask with kcsan_set_access_mask(), KCSAN will
only report races if concurrent changes to bits set in access_mask are
observed. Conveying access_mask via a separate call avoids introducing
overhead in the common-case fast-path.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: John Hubbard <jhubbard@nvidia.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/kcsan-checks.h | 11 +++++++++++
 include/linux/kcsan.h        |  5 +++++
 init/init_task.c             |  1 +
 kernel/kcsan/core.c          | 43 +++++++++++++++++++++++++++++++++++++++----
 kernel/kcsan/kcsan.h         |  5 +++++
 kernel/kcsan/report.c        | 13 ++++++++++++-
 6 files changed, 73 insertions(+), 5 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 8675411..4ef5233 100644
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
index 7a614ca..3b84606 100644
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
index 2b4fe98..096191d 100644
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
index 3f89801..589b1e7 100644
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
index 83a79b0..892de51 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -99,6 +99,11 @@ enum kcsan_value_change {
 	KCSAN_VALUE_CHANGE_MAYBE,
 
 	/*
+	 * Did not observe a value-change, and it is invalid to report the race.
+	 */
+	KCSAN_VALUE_CHANGE_FALSE,
+
+	/*
 	 * The value was observed to change, and the race should be reported.
 	 */
 	KCSAN_VALUE_CHANGE_TRUE,
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index d871476..11c791b 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-24-paulmck%40kernel.org.
