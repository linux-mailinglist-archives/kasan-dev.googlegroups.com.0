Return-Path: <kasan-dev+bncBDBK55H2UQKRBN4DUGMQMGQEQSRGPWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id D27925BC66D
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:27 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id p24-20020a05600c1d9800b003b4b226903dsf4456568wms.4
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582647; cv=pass;
        d=google.com; s=arc-20160816;
        b=0sYtVVeJdooSrrGhRszuAmTrneMeZcIs6wE+sQ69U8iHs2Y8ug6/HljctDvC1+hoeQ
         SbJVwyYRZwiQt1wKUKLL0c246w0vtb5+S/h2gRKtB32INfNkK+5Y9KX7R9f7Ln9QP8l9
         y3mdwY3OXpZBGTwjdvuj3otb2o2/axhORhUWFqba1nmuwwa5E5ZotG8L5l/isD8Mxdxm
         DwIRvC9tAM4EH42AsbQrBKyqVmNUSwkBrjNowMz5You3QEm05RzFwkloiErUkZyF5RIt
         xEAJq/0kTs8mT0CBHbBTcT4IbzAIs7JCZObv2vK9v5/2lAPSTMNqkDKMbmFf94qKdLbn
         hJtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=1u9+9WzTR2ao5zzUnlgpe1nfnQc486clxolDtdakUCk=;
        b=XEoK4smdB7EXbqpXOYFQe9cjptFUnl5B/wexSmpe/Nxo8CUFS3v/mgaW8JwxDjgjuC
         uUwff1/YTqP6YXisY+po28PBZWVLEtamoooQiPPce2EWQdF+eL2jfje7GDT1OK/QUZpe
         aiFURY4t4RSPFX8B5OTTGjy7CBVYWiuiXxq/I2SRKos619VniqRo2sq9P5GAbsEhDADA
         P05D43FCRN8I148kPN7/lLGUNhRmcSM7IY2tIVDZe7b2z0btrQop0poVxZiZiaWLdDz3
         T5Ecd7o/FXD5H8CiXZU/8TLw1BME975/whGGavbmRjUkZggbvJZWXn3pzUyo5wLKiwKs
         JTUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=RlUJ2AwC;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=1u9+9WzTR2ao5zzUnlgpe1nfnQc486clxolDtdakUCk=;
        b=K0Dqz/rRnUPo44D1dJcaY8gpvozXzR9SmeoDu2TPTmSLfU5sSCg4KSoByFR4mMfim5
         ihTHGzvJKZDn1sGhQYXKTrE/Yqw8mABywm//E14FWzlklP30NhFYYkj9I5JvBdJnURS2
         GAA6KbCOmHcCGtKiqy/ORA4BWXkIN5r6SQOERsTeKcm6fcEi1q+alD3YR/IWxtwJHNXY
         styIvSXPTgF5aFDWDzl/7K+0aOZ4HStQ/4pVo3S+Vf0N4V6pVcsuag3OmMfG5g3BOZfO
         Qf+r9FljpwDvur1TnLUg/q49nDuUCph8Bik3L/hqL+nP1ZY8kNHUcVK50YloDJjgyMkL
         IXTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=1u9+9WzTR2ao5zzUnlgpe1nfnQc486clxolDtdakUCk=;
        b=P9P3ksPmWPX3vL5AJNOCV+zDK/j7niYxV0ko6DePLI3r8PMlzYsYf0tSpO0v0/G1/V
         6r3gLKscstas+Zmh9EX5keTy8+PrWMfwVDk3VVROe1FdoDZ2z0DZ3W5tWEJQrZftuIg0
         IBLDu4JLXjf0dJRFD2T0k+5d2oGuW41oTgTGay/RSKM4tO9BYuAznCgL37Hr5S6s1ow9
         D+B3TQV5Bl/ZMmjuhxo+EymEYOV5WFNbHydYOt4UEJ/66gmXPiIQ/wlg1e73H64VkXc2
         KVQpTXBs+QZrG+PrivFdTo/1glz0Tj4xwN/tRcTlQePPmSu6WOV0nb3jOLuEm6jEQ39i
         UyTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1aYhQaAgW+Pl3dQObcKFVVSkUuBhXzTPT1wXSAIUG6nbD64m1u
	6mIbSN0VNpBaGuMEg90gwKY=
X-Google-Smtp-Source: AMsMyM4w4OGLQNqC7VzVIllqzKhSMvDiZQ99YxfAxbOrczXy4fI+u+h5TlOQvkAQFOjYz3od16vOgw==
X-Received: by 2002:a5d:5903:0:b0:22a:33de:f509 with SMTP id v3-20020a5d5903000000b0022a33def509mr10472457wrd.498.1663582647287;
        Mon, 19 Sep 2022 03:17:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f615:0:b0:3a6:6268:8eae with SMTP id w21-20020a1cf615000000b003a662688eaels1743836wmc.0.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:17:26 -0700 (PDT)
X-Received: by 2002:a05:600c:3d8a:b0:3b4:a4e1:8661 with SMTP id bi10-20020a05600c3d8a00b003b4a4e18661mr11658240wmb.30.1663582646138;
        Mon, 19 Sep 2022 03:17:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582646; cv=none;
        d=google.com; s=arc-20160816;
        b=JkOKYJ6ScFyFPGvLV7RlpPlKPZCQzw3WJyokuVGKIIh9ae5OhvIMh0VVwIxwdXwn8F
         sj4h7eGK1WQWtGXoWgMe1hZ5kXCiF5HC+a7iD7tnY5g4mQSBC2qH34kAx6p7Cm157yfI
         a8q/5JUeUlj5iDyGoY8avN5QhkfmEms/fJf8GuRz8G6YwyqgWwj2KPQ8bL/5MhKvSONg
         JVaBfgmKjpT+CWnx3nQWAeF39iAJdJjwxeDnLTnX7OKUanbjf1u7IFBQz7w236GgMWq7
         FV3aN01QcAznIjjBWLWWs503LNPBwWdVXpRcmI1FK3YNUvrbs5Ad8IwHmEEQm26i7/y1
         PTWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=2qey3zLroBQku0zom/Uqdc2w/ejv7qE6fMvFqUVfz0c=;
        b=TRgbui5BnsdJCsqrUUsGGNI0jVZN4apY1BmKgbKmDaU9en1pu90JiJLXEWZZqw/33c
         Y3wmgSnCrLryx9IG0lq7zonablEGQCI49nvPrsf8eSVqvxp/oQ+XcRRSZagr6DJhQgvT
         rXr7uvxpuhpN5vJqRs7eJLLl4TS7Gj0dN4V+QOcY/sSVxLG5pH5Z/RjLDMqiZLntxb3U
         P35eMy9Y8wHvx+EP8Ws+octWxsBeGiGSXGb1ykk9YfHSEcPZldXzWB1kFXtR4L9mMvY9
         3a6p0AM+0Q4QIF/HxOlGx/y09lv8GyGkiUl+rM1SRXVxT7j0Hl4A7C2oa6mzG0t23Jgn
         vQ1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=RlUJ2AwC;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id l21-20020a1ced15000000b003a5582cf0f0si236212wmh.0.2022.09.19.03.17.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:26 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDpH-004aiV-PM; Mon, 19 Sep 2022 10:16:31 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id E2743302EC4;
	Mon, 19 Sep 2022 12:16:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 144C32BA49048; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101521.340781451@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:54 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: peterz@infradead.org
Cc: richard.henderson@linaro.org,
 ink@jurassic.park.msu.ru,
 mattst88@gmail.com,
 vgupta@kernel.org,
 linux@armlinux.org.uk,
 ulli.kroll@googlemail.com,
 linus.walleij@linaro.org,
 shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>,
 kernel@pengutronix.de,
 festevam@gmail.com,
 linux-imx@nxp.com,
 tony@atomide.com,
 khilman@kernel.org,
 catalin.marinas@arm.com,
 will@kernel.org,
 guoren@kernel.org,
 bcain@quicinc.com,
 chenhuacai@kernel.org,
 kernel@xen0n.name,
 geert@linux-m68k.org,
 sammy@sammy.net,
 monstr@monstr.eu,
 tsbogend@alpha.franken.de,
 dinguyen@kernel.org,
 jonas@southpole.se,
 stefan.kristiansson@saunalahti.fi,
 shorne@gmail.com,
 James.Bottomley@HansenPartnership.com,
 deller@gmx.de,
 mpe@ellerman.id.au,
 npiggin@gmail.com,
 christophe.leroy@csgroup.eu,
 paul.walmsley@sifive.com,
 palmer@dabbelt.com,
 aou@eecs.berkeley.edu,
 hca@linux.ibm.com,
 gor@linux.ibm.com,
 agordeev@linux.ibm.com,
 borntraeger@linux.ibm.com,
 svens@linux.ibm.com,
 ysato@users.sourceforge.jp,
 dalias@libc.org,
 davem@davemloft.net,
 richard@nod.at,
 anton.ivanov@cambridgegreys.com,
 johannes@sipsolutions.net,
 tglx@linutronix.de,
 mingo@redhat.com,
 bp@alien8.de,
 dave.hansen@linux.intel.com,
 x86@kernel.org,
 hpa@zytor.com,
 acme@kernel.org,
 mark.rutland@arm.com,
 alexander.shishkin@linux.intel.com,
 jolsa@kernel.org,
 namhyung@kernel.org,
 jgross@suse.com,
 srivatsa@csail.mit.edu,
 amakhalov@vmware.com,
 pv-drivers@vmware.com,
 boris.ostrovsky@oracle.com,
 chris@zankel.net,
 jcmvbkbc@gmail.com,
 rafael@kernel.org,
 lenb@kernel.org,
 pavel@ucw.cz,
 gregkh@linuxfoundation.org,
 mturquette@baylibre.com,
 sboyd@kernel.org,
 daniel.lezcano@linaro.org,
 lpieralisi@kernel.org,
 sudeep.holla@arm.com,
 agross@kernel.org,
 bjorn.andersson@linaro.org,
 konrad.dybcio@somainline.org,
 anup@brainfault.org,
 thierry.reding@gmail.com,
 jonathanh@nvidia.com,
 jacob.jun.pan@linux.intel.com,
 atishp@atishpatra.org,
 Arnd Bergmann <arnd@arndb.de>,
 yury.norov@gmail.com,
 andriy.shevchenko@linux.intel.com,
 linux@rasmusvillemoes.dk,
 dennis@kernel.org,
 tj@kernel.org,
 cl@linux.com,
 rostedt@goodmis.org,
 pmladek@suse.com,
 senozhatsky@chromium.org,
 john.ogness@linutronix.de,
 juri.lelli@redhat.com,
 vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com,
 bsegall@google.com,
 mgorman@suse.de,
 bristot@redhat.com,
 vschneid@redhat.com,
 fweisbec@gmail.com,
 ryabinin.a.a@gmail.com,
 glider@google.com,
 andreyknvl@gmail.com,
 dvyukov@google.com,
 vincenzo.frascino@arm.com,
 Andrew Morton <akpm@linux-foundation.org>,
 jpoimboe@kernel.org,
 linux-alpha@vger.kernel.org,
 linux-kernel@vger.kernel.org,
 linux-snps-arc@lists.infradead.org,
 linux-omap@vger.kernel.org,
 linux-csky@vger.kernel.org,
 linux-hexagon@vger.kernel.org,
 linux-ia64@vger.kernel.org,
 loongarch@lists.linux.dev,
 linux-m68k@lists.linux-m68k.org,
 linux-mips@vger.kernel.org,
 openrisc@lists.librecores.org,
 linux-parisc@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org,
 linux-sh@vger.kernel.org,
 sparclinux@vger.kernel.org,
 linux-um@lists.infradead.org,
 linux-perf-users@vger.kernel.org,
 virtualization@lists.linux-foundation.org,
 linux-xtensa@linux-xtensa.org,
 linux-acpi@vger.kernel.org,
 linux-pm@vger.kernel.org,
 linux-clk@vger.kernel.org,
 linux-arm-msm@vger.kernel.org,
 linux-tegra@vger.kernel.org,
 linux-arch@vger.kernel.org,
 kasan-dev@googlegroups.com
Subject: [PATCH v2 15/44] acpi_idle: Remove tracing
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=RlUJ2AwC;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

All the idle routines are called with RCU disabled, as such there must
not be any tracing inside.

While there; clean-up the io-port idle thing.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 drivers/acpi/processor_idle.c |   24 +++++++++++++-----------
 1 file changed, 13 insertions(+), 11 deletions(-)

--- a/drivers/acpi/processor_idle.c
+++ b/drivers/acpi/processor_idle.c
@@ -108,8 +108,8 @@ static const struct dmi_system_id proces
 static void __cpuidle acpi_safe_halt(void)
 {
 	if (!tif_need_resched()) {
-		safe_halt();
-		local_irq_disable();
+		raw_safe_halt();
+		raw_local_irq_disable();
 	}
 }
 
@@ -524,16 +524,21 @@ static int acpi_idle_bm_check(void)
 	return bm_status;
 }
 
-static void wait_for_freeze(void)
+static __cpuidle void io_idle(unsigned long addr)
 {
+	/* IO port based C-state */
+	inb(addr);
+
 #ifdef	CONFIG_X86
 	/* No delay is needed if we are in guest */
 	if (boot_cpu_has(X86_FEATURE_HYPERVISOR))
 		return;
 #endif
-	/* Dummy wait op - must do something useless after P_LVL2 read
-	   because chipsets cannot guarantee that STPCLK# signal
-	   gets asserted in time to freeze execution properly. */
+	/*
+	 * Dummy wait op - must do something useless after P_LVL2 read
+	 * because chipsets cannot guarantee that STPCLK# signal
+	 * gets asserted in time to freeze execution properly.
+	 */
 	inl(acpi_gbl_FADT.xpm_timer_block.address);
 }
 
@@ -553,9 +558,7 @@ static void __cpuidle acpi_idle_do_entry
 	} else if (cx->entry_method == ACPI_CSTATE_HALT) {
 		acpi_safe_halt();
 	} else {
-		/* IO port based C-state */
-		inb(cx->address);
-		wait_for_freeze();
+		io_idle(cx->address);
 	}
 
 	perf_lopwr_cb(false);
@@ -577,8 +580,7 @@ static int acpi_idle_play_dead(struct cp
 		if (cx->entry_method == ACPI_CSTATE_HALT)
 			safe_halt();
 		else if (cx->entry_method == ACPI_CSTATE_SYSTEMIO) {
-			inb(cx->address);
-			wait_for_freeze();
+			io_idle(cx->address);
 		} else
 			return -ENODEV;
 


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101521.340781451%40infradead.org.
