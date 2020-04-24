Return-Path: <kasan-dev+bncBC6OLHHDVUOBBMEHRL2QKGQE7FPESCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B90F1B6DDD
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 08:14:09 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id a144sf6242728oob.6
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 23:14:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587708848; cv=pass;
        d=google.com; s=arc-20160816;
        b=jmoqp6J3RqyVqtrXW0UUsOigURGouiXuIKWyyb8bqSS94xm6j0EQsTbgHhlqDk3NuY
         iDnxTCGcMIzT2M67q9qTEvTQvVw0UOCBKu7GzlAZ7Ng1GQEDekAhib0muxy5F1/uDDri
         lGgiZzvUl6DmrI68ZlT5RAcbeMLxVqSd3rc0iJUcJF4Fe6Q0L8NU5KMesYtKyaCKWyPZ
         YS9dV3Hd2v5+hYzOr4ot1vldYNLGO8aN7wzrcR92to/J6pDG6GQTUMyAFgp/HAaCx0vF
         AxuB9K6gt0r5bf1QQvpsJZqwOb49wXeI9r2ZYQ05d4/UckqR3wLJBtD3G5DRmqpxDL6z
         2F/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=/B29Bl+KahnqacmX1179Qy6XjwDsDJM6bR5qX5GX7B0=;
        b=Mf5LrMUrj3LcVPajodJcmlWhzQz0yy3LjSQ3UuxDfAa/DQoPDz02kn2BgTNBMzVDVN
         gACmG5Am1eKNY6fYcQQs6SRsevnLn913ddZccj+uKIp2SuXCpiSJk9SXBBaL/D00uCEW
         3jRo27ly6JHMGCMI3mIevze3jPwPqKFD/+C4OTNmlyxdbE8XZG2XIWDRRrCkzi9WStzN
         bfvfH2Auc4w4ceMaGTIrLWNqGFBOjw4Q9qAb9FIbPJZmHCXgLC9AiXlELpfYr44jHYzj
         pPycv/5jyz7gdeVXVPXPl4Nsv0oS4TBMqim5/bQOB4R4U1/lnccE6BtW/94z5radQYVz
         ENdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ChzEHTsG;
       spf=pass (google.com: domain of 3r4oixggkctwbytgbemuemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3r4OiXggKCTwbYtgbemuemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/B29Bl+KahnqacmX1179Qy6XjwDsDJM6bR5qX5GX7B0=;
        b=DBY8QNFoQmZjXbb1UrsCv+C+M7SBvHsbJqkEHRtJihHJLTQg2fXw6w+hN+RqTaEHmG
         ++Ma0xsHu+arZE8VB9Q86lOSWMWZON4dAfSIw1XAGNGboDlyHO7dBjMfW1LZ/PTGatPI
         Qipok9Jov6IUvwCTad+iyHzDI9obyvzU0ATvK184IdQKrRoI5OVShmouSuS1MTM+CBi9
         f/le5rSq6tyy8swHRoQyQXgxBKgqjd/ghBHtabyVTWuLZ/tf+C91+eRtpItzMkOKofsl
         O/nW2MjteoTCxhmj8FgwHaMcFMePGBXfG2wWhpbvxdhgEMsCmBPP28TkkqCCgkxCzwA6
         L8Og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/B29Bl+KahnqacmX1179Qy6XjwDsDJM6bR5qX5GX7B0=;
        b=dI7As2SJ51ZI7h8L3e5DON1gVuwAFZf7f9pZXaqTKGiKYhSDRvZsjC9iDZIUmGEi4e
         6m6e2exTrUerYE2kcK4Rg4XltjSfI2CJq5r+9LFNL8R4dj9C10TRRaFYuuTfAl9BYOVQ
         Wec1dw4Jg3KAR/aLDvviQIlxO8NbqBzTtbsHW8SElW+Qa1K5lC0ahWd9yHObsrtiE8bL
         nFivhXwlT9PxttrOob0cEMWNxG+zVrtcaOvZjV7phb/C/2JXZHeGrVq9a5kczaXyYuQz
         r4GKCbUdYjytDJ2h+xfgMKbwXN1SfZ15fvFy71fNt/ELwEKEvQ12dT1RootHAKCM33hI
         0R7g==
X-Gm-Message-State: AGi0PuY+Ul4Wb/K0i4s1fiA1apVCl4ezbx+OEW5fxhNlCsWSAoTzupyf
	AZR2hd9bdeIdJEMlDhSMkXQ=
X-Google-Smtp-Source: APiQypJAB3vZHUT4FzGfM2iJH0MgzCbeGybsFz3970QuVdzdmrkExUFClNDnYjntpWuYAUDT+bA9og==
X-Received: by 2002:a05:6808:910:: with SMTP id w16mr5733947oih.61.1587708848436;
        Thu, 23 Apr 2020 23:14:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:108e:: with SMTP id y14ls636088oto.9.gmail; Thu, 23
 Apr 2020 23:14:08 -0700 (PDT)
X-Received: by 2002:a05:6830:1e7c:: with SMTP id m28mr6950754otr.151.1587708848154;
        Thu, 23 Apr 2020 23:14:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587708848; cv=none;
        d=google.com; s=arc-20160816;
        b=ZKj9eTfsOaeJ+aJFG2Cc+W+qYz56qXlt2WmeOY7m48MXbeh6megyzzeyW/r47gcq3M
         5bcCxCxSUijBPUFkGNUy3RfTjOiWpcghzd84qeIVXLKGnAr/1Uyeheza5qvFzgNGKBo2
         uINQ06T8tgD+BQTWov2tVnPtoeoU6T+kr8orW8MCa67tqFWnVLtyhMSHecgPTdtGe+B1
         w4fSXPXs6cI+rPrpJMAOja93htQ+CIwipVATVPscr7zcQHwn2qCWtSF0m6eyN9EVb1N/
         Nx7P4M0XvwUWDMypAk6zRXTupXee9wFQhho4tNRkCxVWgrT+y9NBnaoQt4St7ZHRtWFw
         LTGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Ktlf9QISDdPRX1uK01ka9sL/IDfKnusqL4DRjBWXu7E=;
        b=rWYzjTEwJs0k7MFBOafEAO/RnsDcianPpMoO3B/2cIjacwURZbMzL8pc+eAU6ODmsO
         KGgiM2F/Lt8iMkrBK3e3GcBEs7vbjjHP3Cuw8dudohErymPa1khbPV9Z+yY5bkURw3Af
         G0H7QoG8fFgFsIUGEXK6CIoTIzDzlMUwwXzlabdcwAr2xftIfcz6246yzsXWHYjMqQVI
         wMm50BlFdq2ub9YGz5YBfY3qvZfAQQiNtnT+ag7cvUfDQGUAoLVF/gADy89F6oRMoh3w
         AmWirKG4S6yoPigeW3DNgMX6hq4C5Cwezz1roTkdVVyh6NAdYt3t3+zaSQ8GCMiy8GBu
         Iwxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ChzEHTsG;
       spf=pass (google.com: domain of 3r4oixggkctwbytgbemuemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3r4OiXggKCTwbYtgbemuemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x104a.google.com (mail-pj1-x104a.google.com. [2607:f8b0:4864:20::104a])
        by gmr-mx.google.com with ESMTPS id z4si351758otk.3.2020.04.23.23.14.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Apr 2020 23:14:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3r4oixggkctwbytgbemuemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) client-ip=2607:f8b0:4864:20::104a;
Received: by mail-pj1-x104a.google.com with SMTP id x6so6957178pjg.5
        for <kasan-dev@googlegroups.com>; Thu, 23 Apr 2020 23:14:08 -0700 (PDT)
X-Received: by 2002:a17:90a:ba88:: with SMTP id t8mr4757997pjr.182.1587708847422;
 Thu, 23 Apr 2020 23:14:07 -0700 (PDT)
Date: Thu, 23 Apr 2020 23:13:42 -0700
In-Reply-To: <20200424061342.212535-1-davidgow@google.com>
Message-Id: <20200424061342.212535-6-davidgow@google.com>
Mime-Version: 1.0
References: <20200424061342.212535-1-davidgow@google.com>
X-Mailer: git-send-email 2.26.2.303.gf8c07b1a785-goog
Subject: [PATCH v7 5/5] mm: kasan: Do not panic if both panic_on_warn and
 kasan_multishot set
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: David Gow <davidgow@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ChzEHTsG;       spf=pass
 (google.com: domain of 3r4oixggkctwbytgbemuemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3r4OiXggKCTwbYtgbemuemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

KASAN errors will currently trigger a panic when panic_on_warn is set.
This renders kasan_multishot useless, as further KASAN errors won't be
reported if the kernel has already paniced. By making kasan_multishot
disable this behaviour for KASAN errors, we can still have the benefits
of panic_on_warn for non-KASAN warnings, yet be able to use
kasan_multishot.

This is particularly important when running KASAN tests, which need to
trigger multiple KASAN errors: previously these would panic the system
if panic_on_warn was set, now they can run (and will panic the system
should non-KASAN warnings show up).

Signed-off-by: David Gow <davidgow@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 45f3c23f54cb..dc9fc5c09ea3 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -94,7 +94,7 @@ static void end_report(unsigned long *flags)
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn) {
+	if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags)) {
 		/*
 		 * This thread may hit another WARN() in the panic path.
 		 * Resetting this prevents additional WARN() from panicking the
-- 
2.26.2.303.gf8c07b1a785-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200424061342.212535-6-davidgow%40google.com.
