Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDUUTWIQMGQEKHZXWBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D0084D1725
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Mar 2022 13:20:31 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id g13-20020a056512118d00b00445ade9f7fbsf4813211lfr.2
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 04:20:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646742031; cv=pass;
        d=google.com; s=arc-20160816;
        b=HETcqBgqSAziOr4M3MTrNnlw57fX9o+0Os3XsTCavj0yQZXIOeoTe3E000/o07MPEg
         upJ6AilyNewcR03ZZmQlc8Chj/IOjWGeCoSIbpXq1NaxLzKBgEWDt2Kuj95mU8WGMC6D
         53yej58KR2/Uv7ci4/pQL7YnUj6soJ6vjVT3iPzp8gkLk7gc7yqLsK5J55WtT6wvu/Np
         IzzjJG6bIZDV9LJHRKpp9wGrPyrSPhYpNjgLKapMRz6NDl3Rf6oNcXZ4amZ2eKMNQc1m
         g+sjIS8I9rm4gvwuxBvCn5PAoGMDBeU+Y/SDNlV9gDcafqKTzr2npeNaxKE+jYWsocyH
         nN9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=U2Jsd9jtY/KBLfyZLEY0BLrfYjs4/4y2lkkIzcq2HIQ=;
        b=KWTsUELYGaYgURUxLxDfADMse5CaKgOE1aYVjyIaLNqAMijOpPCgVNIDIbyj6pSjoN
         zqBXT8qTqWJAo6Af2Huenpyx8+fzIZBapekLHY01pwDysiJ9R0dHf8drizqNFC2bJvR5
         +V+rGpFLU/qZYwPM2nhJj67pClhjidxdvvCPejjUv9glf3P9XiaqdwHsPzbsSR8ksXMX
         y7X9JNKl9xaZPq1UPNOiu9QbQfkdNjKLACkpi0hS8Y4tp5Jv/vwkUykKDJcpwRXZXEU9
         YdagKrmkDREjqPh/E+Jf6T2fXXErV6xnDjzSOBKimYNmBOxWLXzVkmCKzlWn74Ws57ln
         Xjqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="e8o5OZ/P";
       spf=pass (google.com: domain of 3deonygukcvu18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3DEonYgUKCVU18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=U2Jsd9jtY/KBLfyZLEY0BLrfYjs4/4y2lkkIzcq2HIQ=;
        b=gOVDXtbRbY2IBII8bz7aq78iHlAMwkk+t5JC43WA4gE5LMYkbaODQ2bMWYXw879arv
         3oma3wbgl2aKVbo1hxBMPS2lSniYm69fT4un/uoZo4LXZ/FKeYi9zgI9JAt5vPSWHQvd
         05UZlnWilsQO0xqsOXO5ZCttbGsB6X42ul2QvJUCcD/WHPaWDtX8eE+iApM4vKz8Q6Oi
         NpjsVsCaf2IeNmmGvcOmM6rhsEcdlyjWOwF690Sf4e1mgoK6jgBiIxMsW6nNX8A84aFP
         BnsLCFjcp612miFT81VN9ulHadBfEJXh/XKBPzogFNvMP41A7PmDsG+D34C7Ok2Mmz7K
         lPyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=U2Jsd9jtY/KBLfyZLEY0BLrfYjs4/4y2lkkIzcq2HIQ=;
        b=uqfLW8WF4NtOYAd4rLR6ALAL0LKExdGQE5HDaVfVW67KCxntBcBWdp/gPf4ATRRPmi
         knhb5QPLJextkKLEyIEx9yPvFyNHjJDRDrn8b1kQqa2W/jCL/t8dBUIy6hX31tc51sdO
         DemJryHEVnTzRSd0rTxfaCyBEFBwg9KA0JEk9q451ABkKz6fgKrTir0ge2grSPVZFX8l
         Au8d71/cffs+sfZO5WCXZBgr1r+PBjw0a8s3mLwEOhv3yPRzFDAD4ooPx9efAz4AGxJv
         MvUtBNbcHQ8hAe0L1zJcqm6v9MYgyuasxwKKBeRciN6OYa20NG2Q4ojijqo3STRjA6ok
         Xmeg==
X-Gm-Message-State: AOAM531A7GDk8o+igzyBh2yH1S1ZwdYxXkKJoEj1xPwW6ncoKXutQELr
	lsPQYcxqardCmzU7qlUmhwc=
X-Google-Smtp-Source: ABdhPJz8ocqI/lXXds80uz6ol8HLikmFEYU12HCw8FnsTfjRwblshsLaKK0f6YIKBkw9XncpWr+LgA==
X-Received: by 2002:ac2:410d:0:b0:443:3c84:59a1 with SMTP id b13-20020ac2410d000000b004433c8459a1mr11245382lfi.44.1646742030345;
        Tue, 08 Mar 2022 04:20:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f8e:b0:448:2012:773d with SMTP id
 x14-20020a0565123f8e00b004482012773dls2902545lfa.3.gmail; Tue, 08 Mar 2022
 04:20:29 -0800 (PST)
X-Received: by 2002:a19:6b11:0:b0:448:1eb0:9782 with SMTP id d17-20020a196b11000000b004481eb09782mr11444872lfa.88.1646742029195;
        Tue, 08 Mar 2022 04:20:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646742029; cv=none;
        d=google.com; s=arc-20160816;
        b=PPeLb9jOVd2Ql/9IwJnQs7KyS+yBMtIxzIFc27yNX5VHmmSXf2Zzfwp10jNid/gZHN
         G0zmWrTNukxZfwmUaafnPBHjotTMxP6ZN9/AyKq/CYHEUEFA/IwI6CHAG2tXuQRdwYbb
         RR58pH+eIOqi+zTlMh2qi3v+dbJDzksaDS5WM6FvWhohRbWEF34OcHd5aTuTKHjG7ndG
         J7X68LwibypfwlpsR9zdF9rAUJWSFX433erQbOyqq8hz3tzvOKLFEwkaHau39o1WjdQ8
         AWypJJ/0r3YlFcGHw6dwUnxL55BYqUsIu4IvVHqeW6PacqaxxpgCDf9Um1tERc5FThrg
         kotw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=kl2sXhR1ZPN1zpyjxLJOZF6G4P4aj2NkEcWtAzkOw34=;
        b=z2XBrVny/+i+hQehXcZPXDaL1fc3reXPkX3U8y1Ym0eJsi0g0NuMP7qdw78/jqJeVS
         VX4/yQaN1BmkRaR/zBm6+FsUSvRZMIoZQgwoJtNaCdD+ua982rZQbMzHz/hesDATgTgO
         CtPvu1/hxdMaQCgoGMF0+D0WNmHqEbpB/ejN8wZBEZstkbnjgDxkOcYXqwt4eSwjFDxd
         gIBa+Lb6IyZ1/TU133w333jFBCcBUGSb3dv85x+cyZWm8sWPpevX2xDTR1J2bjVEcEfa
         eS4tZObbs8g62eGbhuBNYQIT1qK+KJ90EI1x4ZI+d4yWnJ5p6dPz1S2079UW4W+sPRQt
         BLFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="e8o5OZ/P";
       spf=pass (google.com: domain of 3deonygukcvu18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3DEonYgUKCVU18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id p16-20020a2e9ad0000000b00247f6f7df5esi75720ljj.7.2022.03.08.04.20.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Mar 2022 04:20:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3deonygukcvu18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id l14-20020a056402344e00b0041593c729adso10519570edc.18
        for <kasan-dev@googlegroups.com>; Tue, 08 Mar 2022 04:20:29 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:edd7:29ac:9b6f:1abd])
 (user=elver job=sendgmr) by 2002:a05:6402:50c8:b0:416:2ae0:4bb3 with SMTP id
 h8-20020a05640250c800b004162ae04bb3mr14109102edb.132.1646742028577; Tue, 08
 Mar 2022 04:20:28 -0800 (PST)
Date: Tue,  8 Mar 2022 13:20:23 +0100
Message-Id: <20220308122023.3068150-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.35.1.616.g0bdcbb4464-goog
Subject: [PATCH] kfence: allow use of a deferrable timer
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="e8o5OZ/P";       spf=pass
 (google.com: domain of 3deonygukcvu18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3DEonYgUKCVU18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
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

Allow the use of a deferrable timer, which does not force CPU wake-ups
when the system is idle. A consequence is that the sample interval
becomes very unpredictable, to the point that it is not guaranteed that
the KFENCE KUnit test still passes.

Nevertheless, on power-constrained systems this may be preferable, so
let's give the user the option should they accept the above trade-off.

Signed-off-by: Marco Elver <elver@google.com>
---
 lib/Kconfig.kfence | 12 ++++++++++++
 mm/kfence/core.c   | 15 +++++++++++++--
 2 files changed, 25 insertions(+), 2 deletions(-)

diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index 912f252a41fc..1cf2ea2a1ac7 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -45,6 +45,18 @@ config KFENCE_NUM_OBJECTS
 	  pages are required; with one containing the object and two adjacent
 	  ones used as guard pages.
 
+config KFENCE_DEFERRABLE
+	bool "Use a deferrable timer to trigger allocations" if EXPERT
+	help
+	  Use a deferrable timer to trigger allocations. This avoids forcing
+	  CPU wake-ups if the system is idle, at the risk of a less predictable
+	  sample interval.
+
+	  Warning: The KUnit test suite fails with this option enabled - due to
+	  the unpredictability of the sample interval!
+
+	  Say N if you are unsure.
+
 config KFENCE_STATIC_KEYS
 	bool "Use static keys to set up allocations" if EXPERT
 	depends on JUMP_LABEL
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index f126b53b9b85..451277b41bfb 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -95,6 +95,10 @@ module_param_cb(sample_interval, &sample_interval_param_ops, &kfence_sample_inte
 static unsigned long kfence_skip_covered_thresh __read_mostly = 75;
 module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ulong, 0644);
 
+/* If true, use a deferrable timer at the risk of unpredictable sample intervals. */
+static bool kfence_deferrable __read_mostly = IS_ENABLED(CONFIG_KFENCE_DEFERRABLE);
+module_param_named(deferrable, kfence_deferrable, bool, 0444);
+
 /* The pool of pages used for guard pages and objects. */
 char *__kfence_pool __read_mostly;
 EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */
@@ -740,6 +744,8 @@ late_initcall(kfence_debugfs_init);
 
 /* === Allocation Gate Timer ================================================ */
 
+static struct delayed_work kfence_timer;
+
 #ifdef CONFIG_KFENCE_STATIC_KEYS
 /* Wait queue to wake up allocation-gate timer task. */
 static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
@@ -762,7 +768,6 @@ static DEFINE_IRQ_WORK(wake_up_kfence_timer_work, wake_up_kfence_timer);
  * avoids IPIs, at the cost of not immediately capturing allocations if the
  * instructions remain cached.
  */
-static struct delayed_work kfence_timer;
 static void toggle_allocation_gate(struct work_struct *work)
 {
 	if (!READ_ONCE(kfence_enabled))
@@ -790,7 +795,6 @@ static void toggle_allocation_gate(struct work_struct *work)
 	queue_delayed_work(system_unbound_wq, &kfence_timer,
 			   msecs_to_jiffies(kfence_sample_interval));
 }
-static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
 
 /* === Public interface ===================================================== */
 
@@ -809,8 +813,15 @@ static void kfence_init_enable(void)
 {
 	if (!IS_ENABLED(CONFIG_KFENCE_STATIC_KEYS))
 		static_branch_enable(&kfence_allocation_key);
+
+	if (kfence_deferrable)
+		INIT_DEFERRABLE_WORK(&kfence_timer, toggle_allocation_gate);
+	else
+		INIT_DELAYED_WORK(&kfence_timer, toggle_allocation_gate);
+
 	WRITE_ONCE(kfence_enabled, true);
 	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
+
 	pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
 		CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
 		(void *)(__kfence_pool + KFENCE_POOL_SIZE));
-- 
2.35.1.616.g0bdcbb4464-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220308122023.3068150-1-elver%40google.com.
