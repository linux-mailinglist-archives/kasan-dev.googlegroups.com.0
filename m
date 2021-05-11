Return-Path: <kasan-dev+bncBCJZRXGY5YJBBGFE5SCAMGQE3XAFTEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id A57FD37B278
	for <lists+kasan-dev@lfdr.de>; Wed, 12 May 2021 01:24:09 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id u5-20020a92da850000b0290167339353besf17981584iln.23
        for <lists+kasan-dev@lfdr.de>; Tue, 11 May 2021 16:24:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620775448; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dx2hVRjNvAyok0ICGNX8kRTuJ2JBtsoMc8SY4AxM6eNSBDSmT1aKmIsuCa6Xk/Ss2e
         pCfDS1GsaznzIA+GnkelPBepz3hOSiqFefLqLwcc9YEAmKZ+ueJ/S71rWBJ8E11eFhgF
         aOXVR27Ttenpe6v4PnuS6DSgrA57BXo35csoQfR1hwRg3er5pEz23mWHMWPeVeTmr3XL
         vMh2d+kLqrrj6ExCMkKspMO37Z+S4QN4vlaDr/H6NQaLMAPmM++9ATo6HnHFHzAi/fx7
         BG7CK6LLeBPMfWcvznkzp8X6LQ6Gy5o1yoaw64N5iTJLE33Jf3imtG/xw/YoJLxR3R0F
         WJYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/MhpPiQFiEaBmU1HOs8e0a985Err5XTLj3Vlr7hse0I=;
        b=Woec1nB6MhJmAE0NXLmDMyMVt4voMFuWOalV0J/yM8Ddb1V0v55/k+hfpmvzQtmAQ+
         i1SjPpB9No6eYHnjJ51sBoQiF9KKBUYaZdqhiuzP145Siai0ybv+hU2+plir/4FB15bD
         cGHhdUJD345MOLVBode/L2QF8Z/S70DYNsyJrJTvBJ1yUMc2HiMaYAS/Lb2z5E1gGnXj
         Ck84SMJn4NlXGxsHGd4j8DfZFrjHXpjAM64Z5awpO9vugagxJM6g6NjZ4AEr7ibnj8d3
         HP2hDLwVOwT0jrnto+rE6h+Rgbcg3ZEd4YBfLo8773TeTnH4eWMa3OQaL4/5dzX7FkAq
         EOVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=B+j777nZ;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/MhpPiQFiEaBmU1HOs8e0a985Err5XTLj3Vlr7hse0I=;
        b=C1NiKQ3MSmO7AZGvM8bn1FuYRMOr1V1foZS/wdv36QS7WuNQMPxED1ibDCF2tx+pg2
         +XVyHPsf6gVjICXnfg5MIHlMvJ3dk1LzTnf+EMlObveUTGo4XuZzJBl2+xNK8UM0SVm6
         K7tQlC9kB1Lu25VnbmlnXzxfoxwa4EUxAWRm10O+SiqGQ/mNGY1Ijkg3QZrmDiAG5hPP
         S0yJ0S0tuM2yAYZWEasDZWRqkzI3Qldn6Lc1KD8TNTzuYIf4qfRNRFgx+WG91FLghDbq
         7BYJboHWtPfntLoiaAlNxa9CuUJY1DacXeO3a1VoodlICafYJFJ/JqAKD5f6YN3kgcgV
         F/gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/MhpPiQFiEaBmU1HOs8e0a985Err5XTLj3Vlr7hse0I=;
        b=TQkCYtrNRU93RV3NjItwEY8GWQP3YrqSxZ+j0hvHX7vPL/26hSui0MYi3+3Le3ifrV
         G8KpCrcFKQ5fkSYzAo+6TQJio5vv2JF/ffG7kQ/XjaVWjgWlCOYJXSEqahhwlZD0E12M
         K/rJFj4smbp6aNp7RFlvAuzH1b1ghjen461c9mEhNqADj6Iqxx1g+LOlfBoxotrvGrOB
         aF/Bf7RO8TJiy/8D1VkB/C3HMvsVC6UC6r8arhC2CLVqcgiCjhGB9BW3HdahOU4HxF01
         jPL9YbuVRZXKgX6aTsQRJCcoSrc43SdVFMgTEKpwi2ol3DmPrG9IU89E7cfOGgpNG5gS
         5OzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530U+lsFXRxp8+mL9q7ZEAVj0vYrZpaVp39fF79wlFqbhaTaRRBz
	5F6jqp8BUkNJp+NMSLCmzr4=
X-Google-Smtp-Source: ABdhPJw537AtEKRAzjaBJfhyk9YQxi78IV4rS7P5H/MB4Q+5BvqZoSo7JYRieSjTzqL++1/GJcqFag==
X-Received: by 2002:a5d:9612:: with SMTP id w18mr23382262iol.183.1620775448654;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:210f:: with SMTP id n15ls56597jaj.5.gmail; Tue, 11
 May 2021 16:24:08 -0700 (PDT)
X-Received: by 2002:a02:cab3:: with SMTP id e19mr28948080jap.64.1620775448364;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620775448; cv=none;
        d=google.com; s=arc-20160816;
        b=Aa4X8RJL6E7pxBO0aGmia56NC/HXf8DWMAzeTqsWKJbMd4CtVKIN0EcCXNJftz6DbN
         FaYdKdB6YsOm+o9+0hOLCIcfsSnMNdlnq4G2rkOaLMvUHvaLwz0GCkwgcdRmw4IiZcpu
         wVR64uDq512/SRlMHDywOLb+DsRKp7geFoZDy0KMHR68vdGvy53JiQHxMNKBvOhhBf38
         elvt5KG4j6veLaJvFj5ap3z1HXLZ8Nq8C49A3hzybVgNGd1fNj6KJWWm+/A1vf/FHvOm
         z1f0dqXp6iFHoOwfqtexFFPMJz3uc6E7D0x6ReBqKxtbmETM2SNrtgIpfZS/xaEw75Wt
         Ia2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sZwlYd7blUwv8Rjg+GBWvV84rAP1ndbESMNvv8E+H4s=;
        b=zIIqWhYf8oszUpfWOL1eEMbALcy+ACrBmuF7E9OnHFsJTb+ZaNDMTgOFqcKZY67Ca9
         cbfmjHK6WC9iRCYp8EQy09Ofg1dwypsHw57FTHyaGKhAlMFFUQliVU7eawk0XdUgFQDY
         znbsJWkFeiwHc/oMD1mgWB0mx0vuVIdHpvT/KpzsKbWn7y0R2sbr4067gFu5cW5guOeb
         pZeA10a2k754MzbnHneBIK7dShxVkDmtGyjGzJ0nTBoaB899/82Wua33VOdUINOYShcn
         I5KqGb1Ge8r3xCqb0dWPRJIbYwqGyBDtt+nndZ3F0iU6IOeujZhXPJIAsoHwRiwX3mGL
         MArQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=B+j777nZ;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y9si1221993ill.1.2021.05.11.16.24.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 54E6561939;
	Tue, 11 May 2021 23:24:07 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id A9F865C0DE7; Tue, 11 May 2021 16:24:06 -0700 (PDT)
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
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH tip/core/rcu 09/10] kcsan: Report observed value changes
Date: Tue, 11 May 2021 16:24:00 -0700
Message-Id: <20210511232401.2896217-9-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
References: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=B+j777nZ;       spf=pass
 (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

From: Mark Rutland <mark.rutland@arm.com>

When a thread detects that a memory location was modified without its
watchpoint being hit, the report notes that a change was detected, but
does not provide concrete values for the change. Knowing the concrete
values can be very helpful in tracking down any racy writers (e.g. as
specific values may only be written in some portions of code, or under
certain conditions).

When we detect a modification, let's report the concrete old/new values,
along with the access's mask of relevant bits (and which relevant bits
were modified). This can make it easier to identify potential racy
writers. As the snapshots are at most 8 bytes, we can only report values
for acceses up to this size, but this appears to cater for the common
case.

When we detect a race via a watchpoint, we may or may not have concrete
values for the modification. To be helpful, let's attempt to log them
when we do as they can be ignored where irrelevant.

The resulting reports appears as follows, with values zero-padded to the
access width:

| ==================================================================
| BUG: KCSAN: data-race in el0_svc_common+0x34/0x25c arch/arm64/kernel/syscall.c:96
|
| race at unknown origin, with read to 0xffff00007ae6aa00 of 8 bytes by task 223 on cpu 1:
|  el0_svc_common+0x34/0x25c arch/arm64/kernel/syscall.c:96
|  do_el0_svc+0x48/0xec arch/arm64/kernel/syscall.c:178
|  el0_svc arch/arm64/kernel/entry-common.c:226 [inline]
|  el0_sync_handler+0x1a4/0x390 arch/arm64/kernel/entry-common.c:236
|  el0_sync+0x140/0x180 arch/arm64/kernel/entry.S:674
|
| value changed: 0x0000000000000000 -> 0x0000000000000002
|
| Reported by Kernel Concurrency Sanitizer on:
| CPU: 1 PID: 223 Comm: syz-executor.1 Not tainted 5.8.0-rc3-00094-ga73f923ecc8e-dirty #3
| Hardware name: linux,dummy-virt (DT)
| ==================================================================

If an access mask is set, it is shown underneath the "value changed"
line as "bits changed: 0x<bits changed> with mask 0x<non-zero mask>".

Signed-off-by: Mark Rutland <mark.rutland@arm.com>
[ elver@google.com: align "value changed" and "bits changed" lines,
  which required massaging the message; do not print bits+mask if no
  mask set. ]
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c   |  5 +++--
 kernel/kcsan/kcsan.h  |  6 ++++--
 kernel/kcsan/report.c | 31 ++++++++++++++++++++++++++-----
 3 files changed, 33 insertions(+), 9 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 6fe1513e1e6a..26709ea65c71 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -557,7 +557,8 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 			atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);
 
 		kcsan_report_known_origin(ptr, size, type, value_change,
-					  watchpoint - watchpoints);
+					  watchpoint - watchpoints,
+					  old, new, access_mask);
 	} else if (value_change == KCSAN_VALUE_CHANGE_TRUE) {
 		/* Inferring a race, since the value should not have changed. */
 
@@ -566,7 +567,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 			atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);
 
 		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assert)
-			kcsan_report_unknown_origin(ptr, size, type);
+			kcsan_report_unknown_origin(ptr, size, type, old, new, access_mask);
 	}
 
 	/*
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index 572f119a19eb..f36e25c497ed 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -129,12 +129,14 @@ void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_typ
  * thread.
  */
 void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access_type,
-			       enum kcsan_value_change value_change, int watchpoint_idx);
+			       enum kcsan_value_change value_change, int watchpoint_idx,
+			       u64 old, u64 new, u64 mask);
 
 /*
  * No other thread was observed to race with the access, but the data value
  * before and after the stall differs. Reports a race of "unknown origin".
  */
-void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type);
+void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type,
+				 u64 old, u64 new, u64 mask);
 
 #endif /* _KERNEL_KCSAN_KCSAN_H */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 50cee2357885..e37e4386f86d 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -327,7 +327,8 @@ static void print_verbose_info(struct task_struct *task)
 
 static void print_report(enum kcsan_value_change value_change,
 			 const struct access_info *ai,
-			 const struct other_info *other_info)
+			 const struct other_info *other_info,
+			 u64 old, u64 new, u64 mask)
 {
 	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
 	int num_stack_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
@@ -407,6 +408,24 @@ static void print_report(enum kcsan_value_change value_change,
 	if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
 		print_verbose_info(current);
 
+	/* Print observed value change. */
+	if (ai->size <= 8) {
+		int hex_len = ai->size * 2;
+		u64 diff = old ^ new;
+
+		if (mask)
+			diff &= mask;
+		if (diff) {
+			pr_err("\n");
+			pr_err("value changed: 0x%0*llx -> 0x%0*llx\n",
+			       hex_len, old, hex_len, new);
+			if (mask) {
+				pr_err(" bits changed: 0x%0*llx with mask 0x%0*llx\n",
+				       hex_len, diff, hex_len, mask);
+			}
+		}
+	}
+
 	/* Print report footer. */
 	pr_err("\n");
 	pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
@@ -584,7 +603,8 @@ void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_typ
 }
 
 void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access_type,
-			       enum kcsan_value_change value_change, int watchpoint_idx)
+			       enum kcsan_value_change value_change, int watchpoint_idx,
+			       u64 old, u64 new, u64 mask)
 {
 	const struct access_info ai = prepare_access_info(ptr, size, access_type);
 	struct other_info *other_info = &other_infos[watchpoint_idx];
@@ -608,7 +628,7 @@ void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access
 	 * be done once we know the full stack trace in print_report().
 	 */
 	if (value_change != KCSAN_VALUE_CHANGE_FALSE)
-		print_report(value_change, &ai, other_info);
+		print_report(value_change, &ai, other_info, old, new, mask);
 
 	release_report(&flags, other_info);
 out:
@@ -616,7 +636,8 @@ void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access
 	kcsan_enable_current();
 }
 
-void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type)
+void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type,
+				 u64 old, u64 new, u64 mask)
 {
 	const struct access_info ai = prepare_access_info(ptr, size, access_type);
 	unsigned long flags;
@@ -625,7 +646,7 @@ void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int acce
 	lockdep_off(); /* See kcsan_report_known_origin(). */
 
 	raw_spin_lock_irqsave(&report_lock, flags);
-	print_report(KCSAN_VALUE_CHANGE_TRUE, &ai, NULL);
+	print_report(KCSAN_VALUE_CHANGE_TRUE, &ai, NULL, old, new, mask);
 	raw_spin_unlock_irqrestore(&report_lock, flags);
 
 	lockdep_on();
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210511232401.2896217-9-paulmck%40kernel.org.
