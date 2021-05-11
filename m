Return-Path: <kasan-dev+bncBCJZRXGY5YJBBGFE5SCAMGQE3XAFTEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id C257A37B279
	for <lists+kasan-dev@lfdr.de>; Wed, 12 May 2021 01:24:09 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id y18-20020a0cd9920000b02901c32e3e18f7sf16846444qvj.15
        for <lists+kasan-dev@lfdr.de>; Tue, 11 May 2021 16:24:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620775448; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bpes26uVB8ZBQ3CQwF98GViIU8Eh4EJjQcbbF4YTKrThxqheDJSL0nxpwIeM1akdU1
         j+vS3yFLUo2Y7i7XWPejT/50NmJy5r/mq/xXJzRVtED9czDdDYQx+DKl3SQp7ITNI/5l
         PWddIiJBrmIdEWy6qPlNfmi0t3k+l9JMFXC51uUTzGMTw3Sh7q4IVDqRMG9q4ilIFr/g
         P45gcq1i/vu0js9wIv9cZRXoPgBPOmSnKr5/CMme6ORBfTinepp8SDHjdAOHsKEd1tR+
         QPBx2LJSaLzoK2PuIHAy5qfJdQRZu5u0g5Df3zdtIzkUEkp3da5mMEyLc0147eNahDMb
         JFEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=BnlZPbMD7nbjITvRVuO9JQUfZISCEAehFbKCypZ58fE=;
        b=A7X+DocYvcKgMt1kChvlthfPBAaOMApx7Djbhvh6V/gtzMd939Yn9dcazuA1M6KWei
         sGO9Ca+xSfiEu4Tjq6ZOd7XDgmHJvHh0CUXhuMP7KyKA2UyhQAqecC7LbX1Lf9Bt9bTd
         tbyW+pLl1eL59bwWDHXyxGtyIJSp/5cGPvGEddT3Q+7rkY+8gXJJDkydoHVuZJLsB48X
         BEzzmo4C7tkls69oIium8Lle+2eAnuYs8NgFVYnBpUzqFATcuwZmAVe3kkUEHG4SfTER
         3tFSCbGQGBAPnxt+UnScfPb3MehWTaqQHDp7nVasiKHaxFfMEO9mSVFLn8AM2IIFNXsx
         12gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iKRH2HKl;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BnlZPbMD7nbjITvRVuO9JQUfZISCEAehFbKCypZ58fE=;
        b=oR8dfFFrGG4K/2xhDBYWb10Q3NHYBrcEi3rOiIZkVFdKA+3W/tZkLHdFjCvcBfA+Mb
         hQdOMNpcTSNCAY+uCh6fa7yC72XBL9PvHW0v1CqC3E9EmDEbr3mLn+Nff3yOwEI6Rnz8
         KId+kBoDrJ0GRhabDH/8GHsXusojyr5Nor1pJ1ARj7PsZ02+Ir3/WUrOx3xxbQ5HmQsw
         3tlUhurgV6zditOLGrhjJWXn6/Tgf97Nt5SD4bENgKnlM5+mqGBIw8C7VtXaAmtT0Quv
         XYCiT2rHKu08JVBh5OlxmlZ0nsO1MXguYd8mfrbXW7bisGIxs37krlHUK1eQFquMs7d4
         IUyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BnlZPbMD7nbjITvRVuO9JQUfZISCEAehFbKCypZ58fE=;
        b=bqpT7+YcyBG0UHhQ1X2HD28yiF2DQBTlrciKO0wdRAw7RHAjxzvNHrxShASIqaYc3X
         PsMXitQQukxS0UzPWp0NpqSMrhUNfdGg+5/XqNhJlX8tNyooDMyPo3AL/G5AYchA3Yol
         1Km+OvFnPiLxS3db8Fp/lBJFVidXEzbTZ4FRdUSuGzkIJU5469uLarSw0Ci+zRnlBsy+
         l5yWs6pyPzs6YFSlGJYlGuJ5o2VKj9d0ublUNuaf19S2kC/xpzCWGhaGSA82vUsHDB8d
         3fvmAh1zlB8vnFcvvSAmWqMc3MUXzhEZsMtw7HdxBV5imAVS7PS9Oxc0pi4BOBHqcBme
         iB3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531XVxniYSbiIeMmpolPWoRMaaZb4RlOCuVI6flVF4TRSum3qlym
	6JykJi5VuRDYjIqQHjc5TGU=
X-Google-Smtp-Source: ABdhPJx9HngnMvHsM8feS+BGpk8l3E9l/ScmIUCpq2uW6XwnpB/Vd6nhNa4hMTR+vqUxVP+dXA2yQg==
X-Received: by 2002:a37:65ca:: with SMTP id z193mr29940731qkb.409.1620775448693;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4cca:: with SMTP id l10ls226051qtv.2.gmail; Tue, 11 May
 2021 16:24:08 -0700 (PDT)
X-Received: by 2002:ac8:7104:: with SMTP id z4mr30053517qto.379.1620775448254;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620775448; cv=none;
        d=google.com; s=arc-20160816;
        b=Unc/yuR8IPmMtYbRVZAp10G7tetRe8FkyqDVJYJrOk8gl9bojJTy2ys3Ph5Q7D6HgA
         V7z/xMFZs8ivgCYOOXixFFY158rsibpphAJpQYn+52E6oZFDHitwL/T5PUBOJqM2M40O
         FIcRTH68MNcSahjRpH1VOs2tg1zI9VyIbckegLZ4WMqoJDOpQLQLGtBdXIeI3TLI1Gnm
         DbBJXfy1ueFmYGgSLW7YIiX9IwByywYabprA7cJH462WoEYcRUas0Fug0H5o6o2uCIKD
         o6qC7djCIiQyK+Ce3IfGrvZ+MtmEVPNusIIvI6WupIp83uBBZ6Y5bwOOtjaHd7pV6jcH
         2eeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VXxgeBt32QvEXb7UM05EJnf9zqhVz1+A/JIfoypSniQ=;
        b=RdIlj8fAyAJl9K1ZkxtFKk0ugjhbWj6v3hRVzLMk+WnMtwHewGOAFsdPrZvAISRTIw
         TJvXmLQn4Vta+Ns16l4i+M5sdrOJRgZ8p2prqX5+cshERD3jmHZCnH4ZEXfI/A2Xa2O4
         87C04DYHyQHaIEnl1d6OFrd8yJrjpihIYHQ73i5Kx8ODC9PjN00mHiVuvyPj7339IOpV
         6p+s0ecyqo3+g+rF98mke4RTDnHu8IRp4QhgpAcq0s87P4ESuIeuS/s5O+0bM2fmNSme
         5f3WsJ+dX6zmxzu+0uZhncN5UmePq6Y9/liEL+I3jPGa4lF84CStOm9Wnnyjd4QhilFB
         +fSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iKRH2HKl;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e26si1127683qtr.1.2021.05.11.16.24.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id EF9476162A;
	Tue, 11 May 2021 23:24:06 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id A02C25C0B55; Tue, 11 May 2021 16:24:06 -0700 (PDT)
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
Subject: [PATCH tip/core/rcu 04/10] kcsan: Refactor passing watchpoint/other_info
Date: Tue, 11 May 2021 16:23:55 -0700
Message-Id: <20210511232401.2896217-4-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
References: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iKRH2HKl;       spf=pass
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

The `watchpoint_idx` argument to kcsan_report() isn't meaningful for
races which were not detected by a watchpoint, and it would be clearer
if callers passed the other_info directly so that a NULL value can be
passed in this case.

Given that callers manipulate their watchpoints before passing the index
into kcsan_report_*(), and given we index the `other_infos` array using
this before we sanity-check it, the subsequent sanity check isn't all
that useful.

Let's remove the `watchpoint_idx` sanity check, and move the job of
finding the `other_info` out of kcsan_report().

Other than the removal of the check, there should be no functional
change as a result of this patch.

Signed-off-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/report.c | 13 ++++---------
 1 file changed, 4 insertions(+), 9 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 5232bf218ea7..88225f6d471e 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -600,7 +600,7 @@ static noinline bool prepare_report(unsigned long *flags,
 
 static void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 			 enum kcsan_value_change value_change,
-			 enum kcsan_report_type type, int watchpoint_idx)
+			 enum kcsan_report_type type, struct other_info *other_info)
 {
 	unsigned long flags = 0;
 	const struct access_info ai = {
@@ -610,12 +610,8 @@ static void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 		.task_pid	= in_task() ? task_pid_nr(current) : -1,
 		.cpu_id		= raw_smp_processor_id()
 	};
-	struct other_info *other_info = type == KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
-					? NULL : &other_infos[watchpoint_idx];
 
 	kcsan_disable_current();
-	if (WARN_ON(watchpoint_idx < 0 || watchpoint_idx >= ARRAY_SIZE(other_infos)))
-		goto out;
 
 	/*
 	 * Because we may generate reports when we're in scheduler code, the use
@@ -642,7 +638,6 @@ static void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 	}
 
 	lockdep_on();
-out:
 	kcsan_enable_current();
 }
 
@@ -650,18 +645,18 @@ void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_typ
 			   int watchpoint_idx)
 {
 	kcsan_report(ptr, size, access_type, KCSAN_VALUE_CHANGE_MAYBE,
-		     KCSAN_REPORT_CONSUMED_WATCHPOINT, watchpoint_idx);
+		     KCSAN_REPORT_CONSUMED_WATCHPOINT, &other_infos[watchpoint_idx]);
 }
 
 void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access_type,
 			       enum kcsan_value_change value_change, int watchpoint_idx)
 {
 	kcsan_report(ptr, size, access_type, value_change,
-		     KCSAN_REPORT_RACE_SIGNAL, watchpoint_idx);
+		     KCSAN_REPORT_RACE_SIGNAL, &other_infos[watchpoint_idx]);
 }
 
 void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type)
 {
 	kcsan_report(ptr, size, access_type, KCSAN_VALUE_CHANGE_TRUE,
-		     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN, 0);
+		     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN, NULL);
 }
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210511232401.2896217-4-paulmck%40kernel.org.
