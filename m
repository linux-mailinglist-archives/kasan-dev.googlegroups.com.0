Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBPH63YQKGQEEUAILLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 73FB1155E7A
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Feb 2020 19:59:18 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id z11sf68058ljm.15
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Feb 2020 10:59:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581101958; cv=pass;
        d=google.com; s=arc-20160816;
        b=km6e5uzX9oyXKMypXKaaUR6KruibE2JNCmCuetM20B2IDEtgX8EkaaTxUfIGAY2FG4
         9x3hiLwLJ3tmE2hNfTXs297k7V0ZiFdn5H3lzWgLBt7yF6uncFTMiFXryF+zwhlHh/Lb
         4vJTVgI0LwiyICw2rH8x1HtAbn+rt0kFs5uP4r0mJT7Bs1um4jqOq9iNWnd9c1vuAM+c
         jFhW7RWn9wqnPGCpNgqqgGNNkZfucC9bPdvMw3JAKHloHZQBdj0xhv47h1KanP64pnI4
         n5cMG+kHADF3DOG601gVqU+tWbcKbm9ZblO86T8pscWfrYALv5TV6iyGFiPMdPkwLY3F
         sBsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=Y78E7tTCX43BxZR/ul4iBMP/CoxWwXOHSTie0HfWkdQ=;
        b=zYb3kYVznVng52vWiGXr7gK/HddVnTEO1nj4TBl1R5jvY7XMi9aod8lV2IHFAJ/aid
         wuT1c4LejesxQwdhorU9uQjylxosfjV5FqmwmF24iFEhKHWWq216+IukU6qKzuyVZOnT
         0Xt5eQWCzfHqtZRapgW3vGsFFnhrAuns4Gr7fDRa42Y+eyTrawni6QV8ackQQqyuWKYr
         QIK4IsJxqil7QKJHsKqPE26L3Y6M//e2bDHGDelZPhHY6zWgcXIfZc9xC9OWhjrKyg7T
         0KUJ/QP9FyxW0KAIF1fuJVY4mS5+5QeZyXRq3DE8huQuv17d7vFq+TxpDugqK93GfoDC
         0qsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nP+4sZ11;
       spf=pass (google.com: domain of 3hlm9xgukcdk9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3hLM9XgUKCdk9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Y78E7tTCX43BxZR/ul4iBMP/CoxWwXOHSTie0HfWkdQ=;
        b=dtmEVJqeXcrkUI6B6uk4UG9JYfvr2qxEIcTdZWYgbNppH1F0f68+W9FulQG9qxeKKc
         U7t2RUXNm1sb99cDcHWagY7dqA03Qbd3El7lStWZgSnyRoi6UtBwsfYwwrcf1zfKGj6E
         sCJu+ct8dd2qPVEohggKYcUP3s3N6rZBaT/YShA5GPDbbTcG99BX1+f9ZeJXBMShBoZH
         MEi4/+/Vt+0WBANZaYvyuQpx1SPjkHXFo0LHffnLtXxRDcsanRTTFY1bc88jjmJsanVF
         w4j8DKdgvbeZbiXrjqmQVyMmU+4EocIHniAK3VOQv+3NnFU4eC/j6ae15/cqBu3mdO7V
         o5KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Y78E7tTCX43BxZR/ul4iBMP/CoxWwXOHSTie0HfWkdQ=;
        b=PyHC10bgBiai0+QrzEiRBYfzzmthfM/ew9mStxVK8p5PVfhKOSmuMKkCJ9MmocQ9vH
         DCwhlTLfb4IQO7GXRlBOnOaNyjlySRImIz8PPjNwMApVBcaUiUNk8S5LGzEWbx2EnR24
         LT0QCEqRDPce+FYaOEgY7a0M3CI4uAH2+HH+rkSpALKGXNxurDPawb/pSOmlqUXiXej4
         iQzrtFqNgZSQZNrx3XzPbc3AGJ1/hF7oXFW2S2PYd0ZtLVraimz98kuja1LGDVik9Ves
         rH1pEBecP/yV/iQbUs8qjqZG2VR2v+U6XcgFrbGcPqTLmXBIohumqjoY62BxiIz02al8
         M7QQ==
X-Gm-Message-State: APjAAAX9uiX/OMGAAunjGlzlOku00gAmr06tosFhEDN6TRh3o3bzI5aT
	ZQfxpYfe1sKRgbpRL7gte30=
X-Google-Smtp-Source: APXvYqxjAswwLlQOTzuZJD872w3wyPj5gf1Qn6+LLXAm9+Z4nR53AjD6fs4CEwjRoXsAq1t890pdBA==
X-Received: by 2002:a2e:9c85:: with SMTP id x5mr415050lji.50.1581101957950;
        Fri, 07 Feb 2020 10:59:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9c85:: with SMTP id x5ls79978lji.0.gmail; Fri, 07 Feb
 2020 10:59:17 -0800 (PST)
X-Received: by 2002:a2e:5304:: with SMTP id h4mr379399ljb.75.1581101956975;
        Fri, 07 Feb 2020 10:59:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581101956; cv=none;
        d=google.com; s=arc-20160816;
        b=0Tk90UthQyiu6KDmKL4tSN/hyvXl0FFhn/CeMe3YWtJlGQYCkXffw5tYz+2gZlW/26
         06TqYqGQ+LerIAYXaFbchJiPHMF698spU/FZWraEf4OEmZ6WqyHHt0es7U3dAzouydxm
         ect9hyn/bgNrciF5hgrzPVavf7bnw3TYhwLs0m1vEqeHGdApDT9mhrL8rMfZnLZjK9ze
         243OwQOLnFgE00W3aKDvDpOZSPTSGNDLEiTClxscD0mcotHyF0p0zIuWCOD2ZHaPuwAG
         LuF0njLFlGND6V7RumY4MXH0VX8gqVo8fg9DRlNNZSrtJeWK3z8uuagsgh2R0SRPfttQ
         zUhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=nR+y9oL83JIGNZtIre6/euwCwaqJGCzYCr1D5UPHiH4=;
        b=k48VS+fclaEhV6oSj8iqbH3u+xL4854A8FeuVhjndeayaPBmkoFv2Y528scHtACbHV
         ZnMcRAW6rtK+/UnrDVhOoC61JmhABoVoWK43WR2zE1DYfnTj2juotdH4r8QGWgbSnMBb
         YwVFGqeGWErmAZnS1vJB3h9g/mLfq7fxDqxivuL1JAGgRgANB1QR55UM6hyumQ0wpHR3
         Tq0X+YiimRMLzJCEA9cKJulwyF8OBAYh/B+NqsUPVR9/IjQ0ImliQ3GvSP1jEFVNIwke
         +iqHjVhyQHvrLrOtri+LbD98tbD+bC/yEyOIfT3hyCpTX777MvV+JnWn7UlFHxQ41EoC
         jjbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nP+4sZ11;
       spf=pass (google.com: domain of 3hlm9xgukcdk9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3hLM9XgUKCdk9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id j30si13839lfp.5.2020.02.07.10.59.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Feb 2020 10:59:16 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hlm9xgukcdk9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id s13so121931wru.7
        for <kasan-dev@googlegroups.com>; Fri, 07 Feb 2020 10:59:16 -0800 (PST)
X-Received: by 2002:a5d:40d1:: with SMTP id b17mr400665wrq.93.1581101956137;
 Fri, 07 Feb 2020 10:59:16 -0800 (PST)
Date: Fri,  7 Feb 2020 19:59:10 +0100
Message-Id: <20200207185910.162512-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH] kcsan: Expose core configuration parameters as module params
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nP+4sZ11;       spf=pass
 (google.com: domain of 3hlm9xgukcdk9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3hLM9XgUKCdk9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
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

This adds early_boot, udelay_{task,interrupt}, and skip_watch as module
params. The latter parameters are useful to modify at runtime to tune
KCSAN's performance on new systems. This will also permit auto-tuning
these parameters to maximize overall system performance and KCSAN's race
detection ability.

None of the parameters are used in the fast-path and referring to them
via static variables instead of CONFIG constants will not affect
performance.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Qian Cai <cai@lca.pw>
---
 kernel/kcsan/core.c | 24 +++++++++++++++++++-----
 1 file changed, 19 insertions(+), 5 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 87ef01e40199d..498b1eb3c1cda 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -6,6 +6,7 @@
 #include <linux/export.h>
 #include <linux/init.h>
 #include <linux/kernel.h>
+#include <linux/moduleparam.h>
 #include <linux/percpu.h>
 #include <linux/preempt.h>
 #include <linux/random.h>
@@ -16,6 +17,20 @@
 #include "encoding.h"
 #include "kcsan.h"
 
+static bool kcsan_early_enable = IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
+static unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
+static unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
+static long kcsan_skip_watch = CONFIG_KCSAN_SKIP_WATCH;
+
+#ifdef MODULE_PARAM_PREFIX
+#undef MODULE_PARAM_PREFIX
+#endif
+#define MODULE_PARAM_PREFIX "kcsan."
+module_param_named(early_enable, kcsan_early_enable, bool, 0);
+module_param_named(udelay_task, kcsan_udelay_task, uint, 0644);
+module_param_named(udelay_interrupt, kcsan_udelay_interrupt, uint, 0644);
+module_param_named(skip_watch, kcsan_skip_watch, long, 0644);
+
 bool kcsan_enabled;
 
 /* Per-CPU kcsan_ctx for interrupts */
@@ -239,9 +254,9 @@ should_watch(const volatile void *ptr, size_t size, int type)
 
 static inline void reset_kcsan_skip(void)
 {
-	long skip_count = CONFIG_KCSAN_SKIP_WATCH -
+	long skip_count = kcsan_skip_watch -
 			  (IS_ENABLED(CONFIG_KCSAN_SKIP_WATCH_RANDOMIZE) ?
-				   prandom_u32_max(CONFIG_KCSAN_SKIP_WATCH) :
+				   prandom_u32_max(kcsan_skip_watch) :
 				   0);
 	this_cpu_write(kcsan_skip, skip_count);
 }
@@ -253,8 +268,7 @@ static __always_inline bool kcsan_is_enabled(void)
 
 static inline unsigned int get_delay(void)
 {
-	unsigned int delay = in_task() ? CONFIG_KCSAN_UDELAY_TASK :
-					 CONFIG_KCSAN_UDELAY_INTERRUPT;
+	unsigned int delay = in_task() ? kcsan_udelay_task : kcsan_udelay_interrupt;
 	return delay - (IS_ENABLED(CONFIG_KCSAN_DELAY_RANDOMIZE) ?
 				prandom_u32_max(delay) :
 				0);
@@ -527,7 +541,7 @@ void __init kcsan_init(void)
 	 * We are in the init task, and no other tasks should be running;
 	 * WRITE_ONCE without memory barrier is sufficient.
 	 */
-	if (IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE))
+	if (kcsan_early_enable)
 		WRITE_ONCE(kcsan_enabled, true);
 }
 
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200207185910.162512-1-elver%40google.com.
