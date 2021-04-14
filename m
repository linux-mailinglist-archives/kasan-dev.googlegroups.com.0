Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5ND3OBQMGQEJCZOPPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 9619735F26C
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 13:28:53 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id o18-20020a05600c3792b0290128219cbc7bsf1974968wmr.4
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 04:28:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618399733; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rhbx2q/nSoC8S2gVpZz/8/aC9QD3EBfw49V+t0bQ7Y1GDGeQG4ACqVKTX3Op8MC8vm
         NKr3vSSOFdFHB56l7R5Fx5/5H2qlTWITcSVCi2lg0x4S4kFTsyLAOm0AA+zkBgg9wd1S
         Qq/IUttvOPSAc/l7ijs0ytFbjgr1JtSeCZBlYDzaR2gkwKmQloVnwyYQWS5baWNwt+/9
         FtXYEVmv4yfsDuJpXvMjBFieaY2nWcTOg4Lw7IPVeV6gT7ChzuhWAW/TvFQirBz301gH
         mtGj3IFtRuqKAmauZPl8dyxXfpQbeR05Z/rJ1b68e/D0SA65IUeYjFJ1nH4eMQFJsfna
         zstA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=7YE8wW8Mw3n7JmIDEvBnBNmy7im3O5+ZZWoRPgVXGI8=;
        b=CUE15aL8Dq6bav50VofbH19JBTi2Qt7Y+r0QAXHdPI3B87Xsp0dHue+7S+eNxxr4Y+
         Vqk6FXpITzDmqxPOk5PKx6MHZptRvN1IwVPkiBiV+ygC9ZMnX5Zl3AMwEqQmLx2VKY9y
         z79e41Tatbbes42TlrhhOBKv9diEnhcCr6y+cIZT67CDHwFx69KAPgfvr730FE2HJD8U
         iXw9c9ufam9nDhPWKW5GTZD06JmcreME4R+HPggUT5mqrp2sJUvhvmbQ0rVpFKCiEYq0
         VAIiln0u1oDJQjIwun7RNj0K5RkEoR1JhsHntIsLoaYcta43WG2jyJvOhkGlVIuHRzCQ
         8Ycw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bDu2hzRG;
       spf=pass (google.com: domain of 39nf2yaukcx0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=39NF2YAUKCX0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7YE8wW8Mw3n7JmIDEvBnBNmy7im3O5+ZZWoRPgVXGI8=;
        b=aIda5LQK/MTKFWmydpx/nsPYyaNCCO+Qpddvw+VDSfF07bGu8i3XM49/DIvuraSBCj
         eY8mvyQMoyQ4Wc35z1QK/E0PLHq4ALUoQa6dbMsqc+VpSi0Iew5POxZC0mpEE/jPIXY/
         H2gNYZLB9rNUDvQKtYOR96XVyDI6WDB4V8KFYkKK3IkX04SIgNK3o/bAIo/IYMbolJX1
         c+Z/x+yfMeNNoebeRCq/cmLegZby+TihO/WslMEO1gFG/WJcK06ofUTD/fIH3ZKmX/YC
         EUNaGiAGC5VkhhVeWk2krP0p9Iatjp187dZ7Q+X24gmRBh8wXg/uO0L+8D4MyYUmccnF
         mbLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7YE8wW8Mw3n7JmIDEvBnBNmy7im3O5+ZZWoRPgVXGI8=;
        b=aGic6F2zPMlb1RhFLiZlmYpHeIac7GdJknMo2jCBMGCDzoHLHaiGl0eSKBcHSvSu6X
         yIzBrKIjlxZlgNlfNMPktgVOyMnynOM5oQBX4XtoWffnIGY1R09BxN1LE5NITbrpWYsS
         UCfxEIsC27uN+dvNAAkfVh1JZNDZ45NnhyjmaelcctrBUNaA0Bw6hsQ/Zkvupp4WUelK
         tfxzJq3upj+B2VrLdzuSGUPsAYtm/f1ZdF+fCTIrslIlJmTWG1dxqJLqZkTFMrG9BZKC
         AK3adRG8bMpGA1CjyDnjWzhlaZOP6swrX7gbON0lM6q4oWgkpOMFEh2uA2xflVv4x7T7
         WTdg==
X-Gm-Message-State: AOAM533ekeTwByJ4X5ctPJkxYfa4+BawTuYDoQEl5yPiKK+e/jAhpxCd
	EObKJPbybweodzDMJfvEmxo=
X-Google-Smtp-Source: ABdhPJzRiMwrC7S5c6+tHb/8UeeXsCKJviaaSGS+L7hhTJEXq5/rJbK7HnRUZB0aA9Jgmx7wAN50NA==
X-Received: by 2002:a7b:c7c8:: with SMTP id z8mr2635690wmk.112.1618399733348;
        Wed, 14 Apr 2021 04:28:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:162d:: with SMTP id v13ls2481292wrb.1.gmail; Wed,
 14 Apr 2021 04:28:52 -0700 (PDT)
X-Received: by 2002:a5d:6d41:: with SMTP id k1mr43721879wri.66.1618399732448;
        Wed, 14 Apr 2021 04:28:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618399732; cv=none;
        d=google.com; s=arc-20160816;
        b=QQJSR764GRFyF8Yl+HeDFV8Mc+kYZvC+SkSjMpdAnvtCBoic8BCk28DVcURa0JVStO
         0RET+CXEPtJXR/18apJ9j2wBChKKX0zdCR/J2XS1wvqKNHd58cOLkyKBSwz/VKocOGwu
         BtjcCp0PU9iCNHY2LbyTrO08zZQ/kIzMX/P0RhFpC9Jxkixj6MNG8ycdL0UkCy6nbK+U
         Q/qdwvqLrdrc7mMsx2OK0yC4+f5ykgRs6OQJUFC62pOP1fHP+AQbekrZLsSNGJ04lByh
         KobSBtHWvVt3eY0yCq5xJ04Bkl+PueG4bOwHWG6C/QgJfeF/16BYPj/W/TvDfu+rJmSc
         Aw3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=aFuAorZMO5YBHQhcmgbMO4HXRRT5kxuCC9J8md9w088=;
        b=0avxgz35I2oq89wH5zpDj73o/cqX9JNtRsxtBpQ8KzgaHEROCVc6uZf/PJK59vVexO
         zjj+TxW2awIOwjc+uaWiI1sRhmX3HSZHqDAnNo5aLfOIeDPBqObgJR7826Iqahbw5JrU
         RMtKFvsX5f8d/mukPIgP9muJqJEyFhJZ1U39tUTVNZiiTFfHEgGVlqiQIdrekaOgQki/
         KPy7hr+irkD/8+p1iEawxO5y+I9ZLTpIkCpDOxzfc7oEI287F7yOcw6AIcaP572olFk4
         k2yRkqYpC1dlqjiVl0MFtkIW3GCjqEwxlTPQXLGpqabY+KSJGeMnifwU333GSYvdGlSD
         hnhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bDu2hzRG;
       spf=pass (google.com: domain of 39nf2yaukcx0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=39NF2YAUKCX0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id p189si214270wmp.1.2021.04.14.04.28.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Apr 2021 04:28:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39nf2yaukcx0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id i3-20020adffc030000b02900ffd75bf10aso936849wrr.14
        for <kasan-dev@googlegroups.com>; Wed, 14 Apr 2021 04:28:52 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:4051:8ddb:9de4:c1bb])
 (user=elver job=sendgmr) by 2002:a7b:c5c8:: with SMTP id n8mr2537018wmk.63.1618399732254;
 Wed, 14 Apr 2021 04:28:52 -0700 (PDT)
Date: Wed, 14 Apr 2021 13:28:20 +0200
In-Reply-To: <20210414112825.3008667-1-elver@google.com>
Message-Id: <20210414112825.3008667-5-elver@google.com>
Mime-Version: 1.0
References: <20210414112825.3008667-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.295.g9ea45b61b8-goog
Subject: [PATCH 4/9] kcsan: Fold panic() call into print_report()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, will@kernel.org, dvyukov@google.com, 
	glider@google.com, boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bDu2hzRG;       spf=pass
 (google.com: domain of 39nf2yaukcx0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=39NF2YAUKCX0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
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

From: Mark Rutland <mark.rutland@arm.com>

So that we can add more callers of print_report(), lets fold the panic()
call into print_report() so the caller doesn't have to handle this
explicitly.

There should be no functional change as a result of this patch.

Signed-off-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/report.c | 21 ++++++++-------------
 1 file changed, 8 insertions(+), 13 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 88225f6d471e..8bfa970965a1 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -325,10 +325,7 @@ static void print_verbose_info(struct task_struct *task)
 	print_irqtrace_events(task);
 }
 
-/*
- * Returns true if a report was generated, false otherwise.
- */
-static bool print_report(enum kcsan_value_change value_change,
+static void print_report(enum kcsan_value_change value_change,
 			 enum kcsan_report_type type,
 			 const struct access_info *ai,
 			 const struct other_info *other_info)
@@ -344,7 +341,7 @@ static bool print_report(enum kcsan_value_change value_change,
 	 * Must check report filter rules before starting to print.
 	 */
 	if (skip_report(KCSAN_VALUE_CHANGE_TRUE, stack_entries[skipnr]))
-		return false;
+		return;
 
 	if (type == KCSAN_REPORT_RACE_SIGNAL) {
 		other_skipnr = get_stack_skipnr(other_info->stack_entries,
@@ -353,11 +350,11 @@ static bool print_report(enum kcsan_value_change value_change,
 
 		/* @value_change is only known for the other thread */
 		if (skip_report(value_change, other_frame))
-			return false;
+			return;
 	}
 
 	if (rate_limit_report(this_frame, other_frame))
-		return false;
+		return;
 
 	/* Print report header. */
 	pr_err("==================================================================\n");
@@ -431,7 +428,8 @@ static bool print_report(enum kcsan_value_change value_change,
 	dump_stack_print_info(KERN_DEFAULT);
 	pr_err("==================================================================\n");
 
-	return true;
+	if (panic_on_warn)
+		panic("panic_on_warn set ...\n");
 }
 
 static void release_report(unsigned long *flags, struct other_info *other_info)
@@ -628,11 +626,8 @@ static void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 		 * either TRUE or MAYBE. In case of MAYBE, further filtering may
 		 * be done once we know the full stack trace in print_report().
 		 */
-		bool reported = value_change != KCSAN_VALUE_CHANGE_FALSE &&
-				print_report(value_change, type, &ai, other_info);
-
-		if (reported && panic_on_warn)
-			panic("panic_on_warn set ...\n");
+		if (value_change != KCSAN_VALUE_CHANGE_FALSE)
+			print_report(value_change, type, &ai, other_info);
 
 		release_report(&flags, other_info);
 	}
-- 
2.31.1.295.g9ea45b61b8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210414112825.3008667-5-elver%40google.com.
