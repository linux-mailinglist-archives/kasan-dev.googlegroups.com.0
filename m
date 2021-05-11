Return-Path: <kasan-dev+bncBCJZRXGY5YJBBGFE5SCAMGQE3XAFTEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B40C37B275
	for <lists+kasan-dev@lfdr.de>; Wed, 12 May 2021 01:24:09 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id b19-20020a05620a0893b02902e956b29f5dsf15521684qka.16
        for <lists+kasan-dev@lfdr.de>; Tue, 11 May 2021 16:24:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620775448; cv=pass;
        d=google.com; s=arc-20160816;
        b=J8vibtwtb3V/77jQGaZAN2eAjyr0NLsqI8rUlnmZCty88W2UsB9fA0T9oUF0tuV+Ms
         hpPbcPgHPEYBuhuJTP398+hRee4NG5xkythDbE6BOsv0HYljl3iMtNAbzgWERUQESax7
         UJkrS75cEBcWsze+9Z23yFVVcQ/EO9GWZEmVEAEuGX31+lb7Gd3tbMB0i8MC/AdoG9db
         9MI00lL86JEeaGyHixHY7ulkF3iRLtcciiAu+KuVCBN72A+G5vT7fbYaX7eZnjfQnDQv
         lQ7OOhsqEPcV1RPM43uxKn7usIN+LxhVA4vjUIg6kRwfw0Vs+m1cUX7UUzVNqgBr+/6K
         Wsvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=f70+TI8R2iHgJv36mVm2U0xymxvwrc6/LoamtS8+pbk=;
        b=DcBf8cFa0mMJN3Sf8/wlaQu0hVb7EUsbSnm60/ULkMk72Hkw05GaJFG3UxcK4rsQ38
         BNRQ8oV7cdk+g483kWq1OHYaVRRCCHPDPN98CNqg+X/NZsndSsejvvWlpSgagZX95CiQ
         G5d6MPN9syifa5ZTjFs3SiRK+w2TYU6DnPKiLs6VtfElvfRWpnuxi7Oi2VaNcVC2H6pO
         mRCngkGLdYMDOlCzdQ4DdJ5EFIKYgVIpsET9ktxpctdn0i2Med5NzDMJL3eVaMb9Dsz8
         5crmT9FZeGa7o76U3KJzOgOfR/4ubwzrq9DnZzvQdGe5+eDrNRNXPZ6ouyXUsrS/f73y
         T1FA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=R0Lrq5ex;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f70+TI8R2iHgJv36mVm2U0xymxvwrc6/LoamtS8+pbk=;
        b=jr6kNme9KpmJQU9PURgJvlIAtUYywu7FfWJBhJFzwRYHtBWERecnB/14adOXjXWw1X
         kV4lfL03YerllU/bLr/AAPSod10r0uW9uRqiZl9g50yZTT99JRRq0qJlZJxollsg3D/1
         HphI4SzN3sp/50m9JeDl4dCEDCUqN7xlKb5j0m5RLAa7ZHf31fzlDtN7G0vFDLjBSKtx
         CZbxdKCYBKExvCJvxyEPUaS0lABTSM8jWRnWuO+JALRY7x4Rew29Zp2egrnK6AJDABYa
         UPTzAmF9kav0FdcXh+Al4b3KKg+9hNXjgVMqOuRuRJi9dKIHtwu7A6akO3U35WXg9P+Z
         rxBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f70+TI8R2iHgJv36mVm2U0xymxvwrc6/LoamtS8+pbk=;
        b=gAwOZM6D4M3pg8jlUYYtp5/3bgAUD1KK6C6721uPpGOiVM3S0uU+hEsCiIp3L9RUSO
         fnNkRTTugVQaR+FQ7GV6xTFLYOVGkomKp+NiKXm2KhMRoLlFIBYmaDSu8PmzNsIF/RNp
         bwfPHKk0O3oujSTghSBIMQy/24CE9c4Hfqopxw5vfdDdbahEwrVmM6RSan0bqoThZmRo
         fSzKxhhVvCuccBl6o/oUzYsBCB+XQ0yKdgvpDp64fSuIASA/nJTYDvrSxU9pqY9c7JM3
         epwtdQ9+z5vDi4Ottq6gXL5vO3gDdy5GkfoH1raWBmSj/LY0ZYKVuEceF+FLRCDGyUzD
         lR3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Ihf7r6ayIWPne+ZM7QJCerX4p57TeBIFP2sXAf1r20KbqNUsB
	SE66agjzfJ1gj7mo5p/CCaA=
X-Google-Smtp-Source: ABdhPJzejphwCi+TVRsYDPsYMt/9a6H9qH5CUErpIkzN5Us+XeFOij71xrue5LTZf6KMfHyTE+cT9w==
X-Received: by 2002:ac8:45c6:: with SMTP id e6mr26789833qto.67.1620775448633;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7684:: with SMTP id g4ls206420qtr.9.gmail; Tue, 11 May
 2021 16:24:08 -0700 (PDT)
X-Received: by 2002:ac8:5e90:: with SMTP id r16mr30820990qtx.77.1620775448252;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620775448; cv=none;
        d=google.com; s=arc-20160816;
        b=XzwQw098nsM48vwMcqcnvzzDD4SaPRPYCe4C9aZ7ez/1IPD8TZW2rUpRDHsHSqjTbN
         mVbeZRL+QQusOU2bW4TQXJH1QYIucQ0aklNRa0/y9CkZxoe5zVMcPkYtCiyb/YHzRPPa
         SkZbQXOZDG6HGs7uHPh7dp6lkC1e72SAOcJmvAmhsNOFlgG4hNPpkIL8L5txpcwmm+iq
         oqa2wWvIRp7jOE1Lblrj6dwM9W/jd4sGFhaXnho4AjGJ7OMcyxH5vmiyn4dedjJITmE0
         iCFKLre8oGHWJULCl9rHqEmcn8uhSybjay8RPa3iYTpRLE0NLHIiwUXH7XIR+gn50Qe6
         MKdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lakBTHiGe1qpKCvD4saPRyJ0c65ZOohMlPhrwiZc13c=;
        b=1B3qvH1pj2hmdcFfWEpeeYy0JCIOzRYcJXaFra+2KD3Gv8zBb4JGiNJknTZD4i2ewq
         c+wDUmOfpiLYBkF+bbr2fL2rTRcJn6Scn6eNRrs02pIFhYB5cxRzvyGdd7zbtfyNXDWn
         CIMcKKYsaB85otO0K5eO0vJ+mcs0y+BjHVzXQwgAs/61tDcNwrZuUHPDA7ISsKFpVe14
         36cPg/SnOOBjOG5MyxL42edwJu0mLqa6itALuB17dW2+EKopOTWfKcwIkXcDVHy8ODZG
         3+pJm6hWCz310hPTGmpv2Bq/2kHnWjZAK8+dtMhJZWse3Z2NglB5LFKYHtSjrYIXsEHK
         rGEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=R0Lrq5ex;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o4si977143qtm.3.2021.05.11.16.24.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id EA61E61288;
	Tue, 11 May 2021 23:24:06 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 9CB6A5C014E; Tue, 11 May 2021 16:24:06 -0700 (PDT)
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
Subject: [PATCH tip/core/rcu 02/10] kcsan: Simplify value change detection
Date: Tue, 11 May 2021 16:23:53 -0700
Message-Id: <20210511232401.2896217-2-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
References: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=R0Lrq5ex;       spf=pass
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

In kcsan_setup_watchpoint() we store snapshots of a watched value into a
union of u8/u16/u32/u64 sized fields, modify this in place using a
consistent field, then later check for any changes via the u64 field.

We can achieve the safe effect more simply by always treating the field
as a u64, as smaller values will be zero-extended. As the values are
zero-extended, we don't need to truncate the access_mask when we apply
it, and can always apply the full 64-bit access_mask to the 64-bit
value.

Finally, we can store the two snapshots and calculated difference
separately, which makes the code a little easier to read, and will
permit reporting the old/new values in subsequent patches.

There should be no functional change as a result of this patch.

Signed-off-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 40 ++++++++++++++++------------------------
 1 file changed, 16 insertions(+), 24 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 45c821d4e8bd..d360183002d6 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -407,12 +407,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	const bool is_write = (type & KCSAN_ACCESS_WRITE) != 0;
 	const bool is_assert = (type & KCSAN_ACCESS_ASSERT) != 0;
 	atomic_long_t *watchpoint;
-	union {
-		u8 _1;
-		u16 _2;
-		u32 _4;
-		u64 _8;
-	} expect_value;
+	u64 old, new, diff;
 	unsigned long access_mask;
 	enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
 	unsigned long ua_flags = user_access_save();
@@ -468,19 +463,19 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 * Read the current value, to later check and infer a race if the data
 	 * was modified via a non-instrumented access, e.g. from a device.
 	 */
-	expect_value._8 = 0;
+	old = 0;
 	switch (size) {
 	case 1:
-		expect_value._1 = READ_ONCE(*(const u8 *)ptr);
+		old = READ_ONCE(*(const u8 *)ptr);
 		break;
 	case 2:
-		expect_value._2 = READ_ONCE(*(const u16 *)ptr);
+		old = READ_ONCE(*(const u16 *)ptr);
 		break;
 	case 4:
-		expect_value._4 = READ_ONCE(*(const u32 *)ptr);
+		old = READ_ONCE(*(const u32 *)ptr);
 		break;
 	case 8:
-		expect_value._8 = READ_ONCE(*(const u64 *)ptr);
+		old = READ_ONCE(*(const u64 *)ptr);
 		break;
 	default:
 		break; /* ignore; we do not diff the values */
@@ -506,33 +501,30 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 * racy access.
 	 */
 	access_mask = get_ctx()->access_mask;
+	new = 0;
 	switch (size) {
 	case 1:
-		expect_value._1 ^= READ_ONCE(*(const u8 *)ptr);
-		if (access_mask)
-			expect_value._1 &= (u8)access_mask;
+		new = READ_ONCE(*(const u8 *)ptr);
 		break;
 	case 2:
-		expect_value._2 ^= READ_ONCE(*(const u16 *)ptr);
-		if (access_mask)
-			expect_value._2 &= (u16)access_mask;
+		new = READ_ONCE(*(const u16 *)ptr);
 		break;
 	case 4:
-		expect_value._4 ^= READ_ONCE(*(const u32 *)ptr);
-		if (access_mask)
-			expect_value._4 &= (u32)access_mask;
+		new = READ_ONCE(*(const u32 *)ptr);
 		break;
 	case 8:
-		expect_value._8 ^= READ_ONCE(*(const u64 *)ptr);
-		if (access_mask)
-			expect_value._8 &= (u64)access_mask;
+		new = READ_ONCE(*(const u64 *)ptr);
 		break;
 	default:
 		break; /* ignore; we do not diff the values */
 	}
 
+	diff = old ^ new;
+	if (access_mask)
+		diff &= access_mask;
+
 	/* Were we able to observe a value-change? */
-	if (expect_value._8 != 0)
+	if (diff != 0)
 		value_change = KCSAN_VALUE_CHANGE_TRUE;
 
 	/* Check if this access raced with another. */
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210511232401.2896217-2-paulmck%40kernel.org.
