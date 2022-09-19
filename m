Return-Path: <kasan-dev+bncBDBK55H2UQKRBTUDUGMQMGQEEJ5BCNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E50855BC68B
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:50 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id i132-20020a1c3b8a000000b003b339a8556esf5374999wma.4
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582670; cv=pass;
        d=google.com; s=arc-20160816;
        b=gBMX28lKEejcvhOa/hSBJLae2TTGCG98ps4bZKJMpJqSesrYv3pQK2jFRRpd02ys94
         kw1Yh9R9oeBBoxRm6hOjcP9kWaTkz49nTIQZJHRakZZh3uM5ZSPfq+WUPX2RKb4MX8fO
         tVTjO/tsaY4XVA0QiYjuz4dCimD29E+oiEfAYMxatJNyJCmVyFMT3R1zYwl5xxYPGj6y
         wJ+C6JwB6GGyVPAsUw8CyS0ZN6iLiMPayRsjv6MVBVzzOihbYO6bhM5otAEnqj/q6mz/
         n3q5Nixo0zFHVgz7o334C75BKHocw856Iw18ACGyl5xN1NyaDMY4eSc8c4htLpwYe6g0
         nuUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=hb6A5Ez1bZVO6H2vJdyCKdjqqxtPOhAuUY1H+wn4JT0=;
        b=xz6Wx7HSbLPxaGufWkwAPLWlIqgaYKyeZ0Cc8iIb1VYxTFrMn852LLgltGFHajpbMq
         x1lJm4e1zbAOtsduogAHKJwdfstM7i9hVTn8LysvzvcoPHUec8j7v7bRYWeIh84fW24R
         IoNe9DQEAbVj3vdrRhKk9ODjwO9oicg4g2FQowAp3szfLe0ZttMldhtM3HRzX1iu9fsF
         h2VaRadFQxvtA7vvkwwRKgwJR/O9dICtL5iSxPBxyelbtndaSlp5i2qrlm+0Iex7loTC
         ZjFtR5WdIAOSQfmwp0EFsKfztX0In7E56B6LYfVcPZVi2d1MSPtOgMfmLjDDv06RKY0/
         Swww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=uhzdpHZl;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=hb6A5Ez1bZVO6H2vJdyCKdjqqxtPOhAuUY1H+wn4JT0=;
        b=EC7gm5umHWz/x9VWEAT9S9UM/8ld3wZXIzGkzBW5DQPOsDkRcmAMNvGWzjPMPvsB+4
         QnA7BI33srRy3/fgK0noU0DOwO2letJHOmo8iff244imaUEf+cDvOIxSt8ASmYyN2sya
         SLDIsCKldXvwGqM0AvoFhisLa2iIqQvsOEarwxYBsH83+tRIg4h/nXEEWTe2x8HzPbkr
         tA9LKzPy5gI9BvaDg/YdzFs8BL1BoYiwLKU49mOdd0MVC/44dVxR/5VK+D1ahTioIXoP
         PHiIsGSqscN0p5i+K9ZDevNECmkYl6oJ02qI8OGnJynV6MtxJS2RIuKyBU/DHwfzhwco
         3vyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=hb6A5Ez1bZVO6H2vJdyCKdjqqxtPOhAuUY1H+wn4JT0=;
        b=HJom+a4G4em6yrh+GHw0NdWZ9V+X+oMq8zPU++7Nn1JQQH7KIANRnracbk6TuGlBUI
         EejaB2WtpBRr+XrO0oPgsU1GMRFTlueDkHh4toKlSkGUQ09dyQh5NwsFP6jurYUt7XoG
         GT+rTPS2XAIYxoLYhrVbVOP9fVtHxg1Fvr78Ry2qKO54M1TTB7C75t39RIsHVGN03qq3
         Z53iil9QuKdR9IJUXsQCGjMmvYO2+INiyQGF0st2RIhm+S6tLIDlDnS9MCec2Bp8fdMB
         8CQ/yVX3aV/3SNdMoELeKThHKgPVDZBj5mG/IHO+99xGUBGaNwzDVMGJSMd5ftTCjgTQ
         Q7UQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0xV8yXtgXE3TN2EZ/xY22xOemyALxr7q3wdydq2tLbkxQ/iVuJ
	myDD7WrTsNglC1lxfIYYx7w=
X-Google-Smtp-Source: AA6agR7oF9ftsIoFxh9N3sF4U+DHVSEdSNurVmB7aS25DCnWjwhcYBaijavzquNWZRZl1KYrikfpng==
X-Received: by 2002:a1c:2743:0:b0:3b3:f017:f23a with SMTP id n64-20020a1c2743000000b003b3f017f23amr19514212wmn.137.1663582670571;
        Mon, 19 Sep 2022 03:17:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d20c:0:b0:228:ddd7:f40e with SMTP id j12-20020adfd20c000000b00228ddd7f40els7610763wrh.3.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:17:49 -0700 (PDT)
X-Received: by 2002:adf:e806:0:b0:22a:f5c6:6954 with SMTP id o6-20020adfe806000000b0022af5c66954mr5065837wrm.539.1663582669490;
        Mon, 19 Sep 2022 03:17:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582669; cv=none;
        d=google.com; s=arc-20160816;
        b=WkZfGnQlpIY7juB1h86eeK25lhNCufZarv/Tt+bkamAPZlpsJLWwAvEAL/X34QxvP2
         ChSoEcSLYOf8+15o4PcVwXvGDyFewkaoZfGdwGDQhDMSOCMH7OxwxazvbWqdY4lYY1Wz
         Qb1L9VscP9KZ0ggwjsdnmk8UHquaQZieDwEkHxDvcJm1CqA3QDqicHksE1HR0y3xnj8w
         cwskfOUXiPn5ArnfZhRPP0+aJyHOcjLBEGqxs7jTpueaBjLZKFF9hj3X6DqKpcTHs6ES
         Mg88q4kHIRccm0nneNYl2WotpTmCqNEybet/8uVJUFv8UjHNcbHikZyD7J6IWJPSn/Tx
         QAmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=rkOK81skpZJ6vGDiywjg6par8UEvxeO3DasZhSxIJok=;
        b=L3rdbezgEi/APC00/E0wK1qmwJNaG8M51E5nG2NzGqFsSZka/tJQe/QvPa8yY0a/eE
         +OSaTFe9b5mVWOI91XYUzZDR7SKX3QNgBM/inM3urwWPzAw9U9TWge71eCFx+nE78NqU
         eBfSC5fy1vMx6D0zYNl5yl0eyAoR7IatbOxC8rNbfj7LSg9nMy33Cx2Ps8a3Qt/VePnK
         igdWh35u/0fRmlZrjMX80W8NhK814QsaqUBKMK+W5cJduVvelfccGln3jZXIR/w/Q0Gh
         VeMCqJtVQtRvqDcYHGyCZGoiKl9sGgulspaEP+dr8+xGrid6YJkawxvjycoC8ThbMz0s
         i1hA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=uhzdpHZl;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id ay4-20020a5d6f04000000b0022a5d8714b3si378809wrb.7.2022.09.19.03.17.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:49 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq9-004bBW-4b; Mon, 19 Sep 2022 10:17:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 72E86302F5A;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 822FD2BAC75B3; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101522.707997632@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:14 +0200
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
Subject: [PATCH v2 35/44] cpuidle,omap3: Push RCU-idle into omap_sram_idle()
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=uhzdpHZl;
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

OMAP3 uses full SoC suspend modes as idle states, as such it needs the
whole power-domain and clock-domain code from the idle path.

All that code is not suitable to run with RCU disabled, as such push
RCU-idle deeper still.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Tony Lindgren <tony@atomide.com>
Tested-by: Tony Lindgren <tony@atomide.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101522.707997632%40infradead.org.
