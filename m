Return-Path: <kasan-dev+bncBDBK55H2UQKRB2WMQGPAMGQE5YWVWIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 27C18667FEA
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:35 +0100 (CET)
Received: by mail-ej1-x63b.google.com with SMTP id oz11-20020a1709077d8b00b007c0dd8018b6sf13466035ejc.17
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553514; cv=pass;
        d=google.com; s=arc-20160816;
        b=nnBplotxm4SZ5qydz/Qr9teh//4TQCCoN1SN49KuUnN7nmrou9+Zrs+J9/+IyoA9sf
         ePZYMhpOHpekHuL7fjO/kOYSqdTUQzf3ApRROSKoLmshvTWwQ49l42lTxQRganPWIjR8
         h9e1RsZro47SSjbfDzWCQLxRQriokWFL/rBTYp994VxvnMzWj4HX/Q65pf4GEWhAgn60
         YvmuQ56VvS4/SwYWWGiA65AnN+9ySp9biUrvJXaH2+6sPUIM6CKXa8R14kJ5slRDyH7T
         oC0PeeUup7HiDftz8z8Bu3ImCF90soQuJiz/A4/gvIJ8Qx9wkje2DSU43CGGjPLR9X9U
         ow9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=/m0gkVzIuY2CI6v5T3B96VsR7V+af3lq9nrKmD9gR5c=;
        b=Gxs3ULK1ebCvvmFFvBsb0sIQvg6OwsuGZngczB823hdMuxhC8SM8RqTO2OB2rXOMhG
         tdlhq83LgVkFF44CU3RB9th0Q8HsODVu8c9ECFOokZWF0CcwASdwXyqPqhpj5gOYVlz4
         w9PzwGp7LJUOdefZ8MQzY3TyJ2DkqpUBZwVH6R19s9c43wF+qyGwE0D5G8qwEEMxWAPv
         7I//BS7vnkQQhhjXLqQef8vncDmbtPY6aEl7VS+JeMzvoFSNXAZzlXY0PuY2wB6MXsJH
         hU0f9V86ziwKEbNGLS9LY2wZamOUEdsvmL+ytnFwE0SYo4Xt+0KEEXwywgR7O07zgHkW
         BGBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="JZ+QI/Rg";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/m0gkVzIuY2CI6v5T3B96VsR7V+af3lq9nrKmD9gR5c=;
        b=ebCdN8Na+1R3HYz8Kchoc0KLXI6w2oXaEfYphDJnAOSRXIAOqgNdi8zbHjAiha7R72
         cD2z4bk+gR5b8pDUfBy9jgBXi0UZAjZZIDFr+BXgJYdRBgUPIaxjEz+f0kYUDOXag/+U
         nioIxK293i+7x1EcWzrnUXSm5Qbc2D4lK9tv+B2TSosHbAXaAwHhQVwbH4/1dsePw+yf
         iRRMr7mstJxUQ4C5OEd3qxdS47koB6p+HRlQs5ZTH4gGlhPu9wiOY31fi9Cb9GzAVgTx
         MJXGkAxulFyAwjX3QXO7+/EvXvGmIuT5qca8+pi607CRUZTi9gI7faUNZyf3NzRFH8gs
         mSWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/m0gkVzIuY2CI6v5T3B96VsR7V+af3lq9nrKmD9gR5c=;
        b=lymsxBDplS44EBqz1MxJx5FOGoP+EuFB6u4nRYItsMnTqx0QyZHPDZHkefjQXEsYpd
         hmZnedjuOaSMzrPQwTTJd7NjpL/Z5xCI60GFwJSbn+bl55CJMXyV/p/hHAY4nzXTy+Wf
         lGcLjk6IzK5ggbEbciahfL3zPmJOav0DxqEHkHwtbNgRHQs+Sw53dNREzVUkBMoS88OS
         M0tnxFbsZ85zRokXF5bc5Zc/lHGRLiuX3xuY1f+v/nrGGf1jx4Pf/nlBUFx0u1T613gd
         kp0RUPzwnvUuECD6tZBA/PfHxBcfYeSynu1/1cXNoVUtzW9ayTv9IgpYcG6CARozGC5z
         pp6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koQYtcTIWudMCAk9HANZHU4ql3zSAUI1DNnP68/MMhG3UDm6plb
	tf0d+n/5V9Htkxxb84UK1j0=
X-Google-Smtp-Source: AMrXdXvYcuvv7QoMqHAfER0zXzJ0b9DAy89iwVevvhNjlwIdqhVdmHOCCICjXXwSrQmqGdWGQhgaCQ==
X-Received: by 2002:a05:6402:2985:b0:486:ecf1:b6fb with SMTP id eq5-20020a056402298500b00486ecf1b6fbmr6780507edb.48.1673553514746;
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:f2c6:b0:7c1:2050:cc5f with SMTP id
 gz6-20020a170906f2c600b007c12050cc5fls2057737ejb.0.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:33 -0800 (PST)
X-Received: by 2002:a17:906:8e0a:b0:7c1:1444:da41 with SMTP id rx10-20020a1709068e0a00b007c11444da41mr634386ejc.40.1673553513518;
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553513; cv=none;
        d=google.com; s=arc-20160816;
        b=uiWeyXcLCLYgOqG9Ao94tPUzsjWPhYs5kaJhcALnEq7lRS012K/a+MxnEG1swertFZ
         V5VzDMhsrkbYaQyOSexPSc3Yj1vBS6Q02sVbKh8XdnABE9FCtp0sypDd6E1RYYLGShxu
         qcguxhNLJ5Q40OBBifz9SiySx3tOb7yG6XJLWk0QjP+gcZzLulCKSYh8mVI5IWcrD5M9
         GSOJQ0I7d+AvuIO6AHgYQoRtSCQ8Nkls2Ss550FTlxQhDGts075BTpnMgKVY+yas+sVD
         G/FZEeLXHJ4+LMoWhvm89Z9E2tKX3WYCLP+dL5SCw6vSYGclESyWFaDN6ZUoI0/Rw7hw
         oDFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=FFPKfQhi1RR6oz0II4O36iNGEMWuMWROzeT05TgEQqM=;
        b=txtg6AtbGNnC1m4M/mQZv3JDIRXbNrW8/3jGJRfPvMWZMycPgDczBvckQ3/U5q23jm
         g1R2gdlzymWielCk7J1YGL5v4+/ylKVaVDy0isLjQes1KnH056586mDlQ589BSaFMA8Q
         io7/j2prD6Ek5SbDPa5LMxoXx/7QwdUYdQADFic3a3ncMAU4N5HP5ZKi0qXbkTq9Aj/v
         JRBhOqTyMJNaptdogrphRURUHffK8QJe6ljK+fZCVCqu7RKYOQHczHnC//vD3hkXudA/
         AMOsOKQbsMeDd29BMNXAT9suDTdqOgS/ObSss3z8iEQPSktMt87AeE4a6GeqQ8kz8SWs
         UJGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="JZ+QI/Rg";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id gv11-20020a1709072bcb00b0086728259fb3si86661ejc.1.2023.01.12.11.58.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3he-005OgM-L9; Thu, 12 Jan 2023 19:57:34 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id E0BBE30345B;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 41DA72CD01200; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195541.599561742@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:51 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: peterz@infradead.org
Cc: richard.henderson@linaro.org,
 ink@jurassic.park.msu.ru,
 mattst88@gmail.com,
 vgupta@kernel.org,
 linux@armlinux.org.uk,
 nsekhar@ti.com,
 brgl@bgdev.pl,
 ulli.kroll@googlemail.com,
 linus.walleij@linaro.org,
 shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>,
 kernel@pengutronix.de,
 festevam@gmail.com,
 linux-imx@nxp.com,
 tony@atomide.com,
 khilman@kernel.org,
 krzysztof.kozlowski@linaro.org,
 alim.akhtar@samsung.com,
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
 andersson@kernel.org,
 konrad.dybcio@linaro.org,
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
 mhiramat@kernel.org,
 frederic@kernel.org,
 paulmck@kernel.org,
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
 linux-samsung-soc@vger.kernel.org,
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
 linux-mm@kvack.org,
 linux-trace-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com,
 "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>,
 Ulf Hansson <ulf.hansson@linaro.org>
Subject: [PATCH v3 37/51] cpuidle,omap3: Push RCU-idle into omap_sram_idle()
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="JZ+QI/Rg";
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

OMAP3 uses full SoC suspend modes as idle states, as such it needs the
whole power-domain and clock-domain code from the idle path.

All that code is not suitable to run with RCU disabled, as such push
RCU-idle deeper still.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Tony Lindgren <tony@atomide.com>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/arm/mach-omap2/cpuidle34xx.c |    4 +---
 arch/arm/mach-omap2/pm.h          |    2 +-
 arch/arm/mach-omap2/pm34xx.c      |   12 ++++++++++--
 3 files changed, 12 insertions(+), 6 deletions(-)

--- a/arch/arm/mach-omap2/cpuidle34xx.c
+++ b/arch/arm/mach-omap2/cpuidle34xx.c
@@ -133,9 +133,7 @@ static int omap3_enter_idle(struct cpuid
 	}
 
 	/* Execute ARM wfi */
-	ct_cpuidle_enter();
-	omap_sram_idle();
-	ct_cpuidle_exit();
+	omap_sram_idle(true);
 
 	/*
 	 * Call idle CPU PM enter notifier chain to restore
--- a/arch/arm/mach-omap2/pm.h
+++ b/arch/arm/mach-omap2/pm.h
@@ -29,7 +29,7 @@ static inline int omap4_idle_init(void)
 
 extern void *omap3_secure_ram_storage;
 extern void omap3_pm_off_mode_enable(int);
-extern void omap_sram_idle(void);
+extern void omap_sram_idle(bool rcuidle);
 extern int omap_pm_clkdms_setup(struct clockdomain *clkdm, void *unused);
 
 #if defined(CONFIG_PM_OPP)
--- a/arch/arm/mach-omap2/pm34xx.c
+++ b/arch/arm/mach-omap2/pm34xx.c
@@ -26,6 +26,7 @@
 #include <linux/delay.h>
 #include <linux/slab.h>
 #include <linux/of.h>
+#include <linux/cpuidle.h>
 
 #include <trace/events/power.h>
 
@@ -174,7 +175,7 @@ static int omap34xx_do_sram_idle(unsigne
 	return 0;
 }
 
-void omap_sram_idle(void)
+void omap_sram_idle(bool rcuidle)
 {
 	/* Variable to tell what needs to be saved and restored
 	 * in omap_sram_idle*/
@@ -254,11 +255,18 @@ void omap_sram_idle(void)
 	 */
 	if (save_state)
 		omap34xx_save_context(omap3_arm_context);
+
+	if (rcuidle)
+		ct_cpuidle_enter();
+
 	if (save_state == 1 || save_state == 3)
 		cpu_suspend(save_state, omap34xx_do_sram_idle);
 	else
 		omap34xx_do_sram_idle(save_state);
 
+	if (rcuidle)
+		ct_cpuidle_exit();
+
 	/* Restore normal SDRC POWER settings */
 	if (cpu_is_omap3430() && omap_rev() >= OMAP3430_REV_ES3_0 &&
 	    (omap_type() == OMAP2_DEVICE_TYPE_EMU ||
@@ -316,7 +324,7 @@ static int omap3_pm_suspend(void)
 
 	omap3_intc_suspend();
 
-	omap_sram_idle();
+	omap_sram_idle(false);
 
 restore:
 	/* Restore next_pwrsts */


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195541.599561742%40infradead.org.
