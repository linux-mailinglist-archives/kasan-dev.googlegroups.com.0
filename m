Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQOJTWIQMGQEFWG4V5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 89DD94D1A20
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Mar 2022 15:14:26 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id bf20-20020a2eaa14000000b0024634b36cdasf7763099ljb.0
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 06:14:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646748866; cv=pass;
        d=google.com; s=arc-20160816;
        b=FMGnVu8TfP924m3p3CYE9qeybyhCxH6RJgZVYK74+hAUGjZ+E3qZZz33B9GIGZsx5H
         gF/v0MuSuDmZD/CoLNiLxQi7dMcGaMhQFzgnW7lULcLvmZvA4g4Ctjs19yk27kRUBZpE
         RCw54D1EywrA8ZykNCsdHzV/Rbkv8/G3DN394m6R1OhvHmb6fxRS7ltCWa5qA21X/F6V
         KJuj6Tab8rVesTAiGXMxKIUWBmgQ+lEH7NLYU1HbcKEtQA5Fm3q/MSt0eCROgM7J7Obb
         uxeTV7No3qYagzJXLCpR8MdZZM/UxaXFWcnWL9HM17b2ZPgRG+K1O/r673xbozfCRsNR
         PsaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=gYopYn/KsH4Hc4ftvdxfYRr+c33eJe090cvzq7NxY2g=;
        b=vyf6Bc24q97MlJrX7eJhFamr4buPnBc2cmMYggq5KF3kPseAOhnbSB/Zhi8kyR06zL
         xfEkyefa9Wt7OOGFU9pgflu51Eg3gkTgKDfnHXS3Go9W3OVAbwvixveWgNJlTHRwSR5j
         MRMLK1qA6PT7+18/ySwYstX596e0Mx+Npv3TRFdb0z1t05UXuyQZl2PyvJ+mbrdMsSQV
         hUXhbEoXC+Dwg56TwWXGS49geKmAA9lbGtUathR/AsPSo0NRZR58td/8ImrYJMi7cC98
         fekYZDhENnF86kChOCrxjp+20JChu3zQPx5KM2bnu+pLacG3xJ1grmlKil67pe7QzZeh
         IePQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q2POkYW1;
       spf=pass (google.com: domain of 3wgqnygukct8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3wGQnYgUKCT8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=gYopYn/KsH4Hc4ftvdxfYRr+c33eJe090cvzq7NxY2g=;
        b=bTBTQjwOupYdR9XUQA1BGcd3cGoNPo1RaSHHWadFbtDw7W1c7KGV+aEKbo0EpSc9Cc
         OjWGsPFytLZ93kP9oLSv/5SHzCQ8mvRPr01bgfKFuhQHBD7D76dvwgyj/4676bg8WASC
         U8VOdALcnS0PGiyuTUx6C8ydw/R7bPq6U8AZ6lL2DVYFCSrRgrMPtQfZo55al2Zhqjnf
         n/gK3iMtjGlZn7p6F1vrXl2qUGVpfteI0Pd9ODcUiuvD8qss0NokHx+fHH76ssHTLnY0
         AvkjXYzqAV6Lqx4q+5bGdXNf6ZgMJWEV3slXdsbDri+iMxG+V3uL4I+bTqX5vuWmrYnW
         pimA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gYopYn/KsH4Hc4ftvdxfYRr+c33eJe090cvzq7NxY2g=;
        b=C/0SPHh7R/SukOs6Y2TEsuKdtNrIcgLlZcDHpG5YPdpeOFVpwmR7yFq92geemyH4Ow
         N0nwkHo+lK03rVgOVcBntMPnhVkfEQitiNLyszV7dsC4whV/gdnRErU13jInhLbrjelc
         +3JBWd4WO4qb9QGWLOq9o2F4ENTuaVFwoytUPjyj8+by0fs80xzcejsbdeiYDfXbxuRu
         A/3Re1UaSjC4qkU+ym8Lb5uzb4t7bmdBx3jyOfS5jULKL8puT7v689izidlcb0NkmuFv
         9bakhZmp9wz7Su32o2gD1CJX+d1NMWq+U0V5WIiQTVoum6XecU1JRETjycZroJbKZK7H
         VPvQ==
X-Gm-Message-State: AOAM531PitOemwNFEZ0ifjdyL4j6cEidOZ5O+Kb+Yztbds04Ur6ek4lF
	vB7mKXf1OJWJWjqs7SkY3V0=
X-Google-Smtp-Source: ABdhPJyxp5Wdv1+JRke/Ym5r6EZEdW6jkuYWNSILsS9IERqAk9t7jbQ5JL9or4GE2j8YWUnSyIN3MA==
X-Received: by 2002:a05:6512:c03:b0:447:7912:7e6b with SMTP id z3-20020a0565120c0300b0044779127e6bmr11191427lfu.508.1646748865904;
        Tue, 08 Mar 2022 06:14:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f8e:b0:448:2012:773d with SMTP id
 x14-20020a0565123f8e00b004482012773dls3153464lfa.3.gmail; Tue, 08 Mar 2022
 06:14:24 -0800 (PST)
X-Received: by 2002:a05:6512:2347:b0:448:2744:26f7 with SMTP id p7-20020a056512234700b00448274426f7mr9750146lfu.683.1646748864796;
        Tue, 08 Mar 2022 06:14:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646748864; cv=none;
        d=google.com; s=arc-20160816;
        b=at9ubolcj1xnuogkJDj0Q4bYSk94K3wqB13Y865jfupA710qU0kVaBwG+OyPI18ASU
         sRSl5EZ7xS98MLf/a4s4WT0ffcJOb0vmCJU+4ZEjnGGkF5eO/bsHF1eBx6lpx+/PVX3f
         FZ7wq56MSJZRfYGlNdX/ufdtPwpwZweRbdZ5Z8rEXW0XdEKSHsNjL6/8Fe1SFhTLA4Ky
         rPqSC9g2pQw/ykhaiHDXvXfvTsTXqzkco15WgIXlYzmZGJI9THYygWVmkZfHXmMtcFqQ
         Uo+raAUN3mtDfEkHeyVkQD1ONX5mej0tUMSyCs9jYu97rxdT3dgXWwHaFYWAuRwueugR
         r6ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=gyMGBvpuWMfS9cnvL/h1tsboqRL4o8fwiR0D5Pa1mrE=;
        b=vnDTKIQutuSAw8g/uaI7y1MaKeULSJ1/qXCORcWEqu12VeVoVBqNivcl0KbCXWYqpx
         /6ILA/8KxEMX+iy0928k8g38/QhZUrgACqxhPIl3+6TQJCNdVVJ/BOiu5zRm+2fm6B7x
         e65uzhUK6T0qHmdxERnEteWiGr237JoKRP+Rnj7ABE/1C8W/Z970OXzCeA/qDsziWXmi
         7W1Cs7ZiA0yTvvjBnS9fT74mHKaHuITPlQxTBguyIitBWOHhecqIOIg/3j/91MnJy0EU
         CKYGddHh1jRYk511tw7bvPVIc5O3rUwSFWs8+EDQKQCYvMr0qxZbTP3hSz8o9J+KEmYQ
         +4qA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q2POkYW1;
       spf=pass (google.com: domain of 3wgqnygukct8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3wGQnYgUKCT8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id r4-20020ac24d04000000b004481f144281si638461lfi.7.2022.03.08.06.14.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Mar 2022 06:14:24 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wgqnygukct8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id ey18-20020a1709070b9200b006da9614af58so6718546ejc.10
        for <kasan-dev@googlegroups.com>; Tue, 08 Mar 2022 06:14:24 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:edd7:29ac:9b6f:1abd])
 (user=elver job=sendgmr) by 2002:a17:907:7244:b0:6d9:c722:577a with SMTP id
 ds4-20020a170907724400b006d9c722577amr13651190ejc.0.1646748864121; Tue, 08
 Mar 2022 06:14:24 -0800 (PST)
Date: Tue,  8 Mar 2022 15:14:15 +0100
Message-Id: <20220308141415.3168078-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.35.1.616.g0bdcbb4464-goog
Subject: [PATCH v2] kfence: allow use of a deferrable timer
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=q2POkYW1;       spf=pass
 (google.com: domain of 3wgqnygukct8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3wGQnYgUKCT8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
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
v2:
* Add more documentation.
* Remove 'if EXPERT' from Kconfig option since it's configurable via
  kernel boot param anyway.
---
 Documentation/dev-tools/kfence.rst | 12 ++++++++++++
 lib/Kconfig.kfence                 | 12 ++++++++++++
 mm/kfence/core.c                   | 15 +++++++++++++--
 3 files changed, 37 insertions(+), 2 deletions(-)

diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
index ac6b89d1a8c3..936f6aaa75c8 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -41,6 +41,18 @@ guarded by KFENCE. The default is configurable via the Kconfig option
 ``CONFIG_KFENCE_SAMPLE_INTERVAL``. Setting ``kfence.sample_interval=0``
 disables KFENCE.
 
+The sample interval controls a timer that sets up KFENCE allocations. By
+default, to keep the real sample interval predictable, the normal timer also
+causes CPU wake-ups when the system is completely idle. This may be undesirable
+on power-constrained systems. The boot parameter ``kfence.deferrable=1``
+instead switches to a "deferrable" timer which does not force CPU wake-ups on
+idle systems, at the risk of unpredictable sample intervals. The default is
+configurable via the Kconfig option ``CONFIG_KFENCE_DEFERRABLE``.
+
+.. warning::
+   The KUnit test suite is very likely to fail when using a deferrable timer
+   since it currently causes very unpredictable sample intervals.
+
 The KFENCE memory pool is of fixed size, and if the pool is exhausted, no
 further KFENCE allocations occur. With ``CONFIG_KFENCE_NUM_OBJECTS`` (default
 255), the number of available guarded objects can be controlled. Each object
diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index 912f252a41fc..459dda9ef619 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -45,6 +45,18 @@ config KFENCE_NUM_OBJECTS
 	  pages are required; with one containing the object and two adjacent
 	  ones used as guard pages.
 
+config KFENCE_DEFERRABLE
+	bool "Use a deferrable timer to trigger allocations"
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
index f126b53b9b85..2f9fdfde1941 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -95,6 +95,10 @@ module_param_cb(sample_interval, &sample_interval_param_ops, &kfence_sample_inte
 static unsigned long kfence_skip_covered_thresh __read_mostly = 75;
 module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ulong, 0644);
 
+/* If true, use a deferrable timer. */
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220308141415.3168078-1-elver%40google.com.
