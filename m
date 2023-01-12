Return-Path: <kasan-dev+bncBDBK55H2UQKRB4WMQGPAMGQEUGKNKOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id CA690668018
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:42 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id i7-20020a05600c354700b003d62131fe46sf12971840wmq.5
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553522; cv=pass;
        d=google.com; s=arc-20160816;
        b=LJ/oi1FQSkojc1errPoqK8cP3JQLrwNxNluKJtsNsVXmSpQCsm5dryshl0+zprRf6w
         BcN4SrWq2AWpg9aU1/oAA2KvaqcZFfIy8WdmGi8ccz1Q0fxQyiNng+qaFfX6co64pww5
         OwWLfRawuSpN42zKHmJLHzRn6DffrX03GGoQKovUnKDypppMjS1zVkWc8dLIssF3USa9
         JiBYUxXiZCr7ObEeZLlYPNMnPiYf8oEokxJf7QwxfkxrQD3iNnrirZqGFaHB/HhCUTXS
         TwDIvyrAcG6/VKzPel2h9qQNjJIYC/gA1ppnHY3JG0duFmmaztXBA9O4gLqNaSCPrUKR
         zy0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=Wua+NxRnKnWy27t2wt7xKYer9aXNhLiI009ipL5OuVo=;
        b=EDCcL3kkmRR9ZcEkXzTPHBqr98PM+QbBuN94ZRdFzl2FD5vH73nN3qDKUwA3naErDB
         qKR9nN+oHWcpfHSSg83vtacZyfAsLsPpKsSMuYlkH5ceE7a3nCnlVJ5hNoUKQa4WYMZr
         leby13HwFP0wbTyTz3N/XWwP33N4OKIpVsjJq+B+jOBcTVy1WeqdWtcQaG0OzSNKTktV
         cGgm2KOqDueiieOx1pl8hlfyR2oIdQ1iIrUR5RiyEP3NO91pJ8TmM1Vcup4zJAXT1cIx
         eYXiIpUbi3NeezkbjxiYTTZROixqY3RYb89ur9F57F9D7eGqXqIwqlgquvhx3GrrqQf7
         4Nyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=EGHw1O+V;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Wua+NxRnKnWy27t2wt7xKYer9aXNhLiI009ipL5OuVo=;
        b=eG+aiwEj5+wGy0eYENO/vOKHzfaGvg80be93+bYfsEOg9s2kqa8xkAkI60QKMTQ+ux
         8MbibutEKU3CY1RnHnnMAtn9kAdYrI+7CY1pPgN+Sxce2ZAw5hQRhOEEVTchI65UMsDi
         Z2Ay7hM1F3dciduYKkRQGjS++U9kf/z72BEVOHaFxA3eGCjHsASkCo425SaibyL5+TRX
         BZVaUzTB86LgA3AZ8glYnCTOGvw/BCXS9So8+/F6AnDjDMNi0tTG2Ean/hCNVcQNXbci
         pv1fYX3RgFYDTmj/Oa6e2ztLFpqLxoCx80Nhp24mebCXhlu2Q7icyKLyRRLody6HKKX/
         f63w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Wua+NxRnKnWy27t2wt7xKYer9aXNhLiI009ipL5OuVo=;
        b=h68sVNWSNQYCNMf1T1L30iAeBnO8F13ExjSAuTn4yeatN7TFsGHqivR9fe6MAa7RK9
         qaudfQCq71JINhPNo03KWzbrOT07b9zXNuGOUXa0jzxaNgAg0Kb+5+KiuUj1lxAgtirk
         wUA9RtghJMWgXdl84p7mn/YLOwPNv8+L2KfaTdcbE7V3tUDdDzbj1/0QAvtFvTFI5QlF
         VdtQ0Rp4OgUOXOlrzg91PjE2RvLnvPB4NAHK1PW7Gf1rBNRO5rqzUNFww+3r88M0Ss7V
         /ietI2C2Rjgb7T2IR3acJovyDgJfE8u3GVRFf+czs6dX8duwGtgxXY7kb0VF6kx0hSF2
         xlBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koAEqwtjJEX4+PTqAFnYRgG/iqNBASmgkK8FrpBu8tVjsJyrMvQ
	ido6hHTgpAZeF9kGT/A2ylE=
X-Google-Smtp-Source: AMrXdXu1+TFpgf9fcAII0AeSfN6b6f554PXtsTFtOBLReeCH3br7dfVW/0Y5ebf5f//2SR4HQSRTUA==
X-Received: by 2002:a05:600c:4f95:b0:3d9:f21f:271e with SMTP id n21-20020a05600c4f9500b003d9f21f271emr1138369wmq.105.1673553522597;
        Thu, 12 Jan 2023 11:58:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:e909:0:b0:3d9:c8dd:fd3f with SMTP id q9-20020a1ce909000000b003d9c8ddfd3fls1628201wmc.0.-pod-control-gmail;
 Thu, 12 Jan 2023 11:58:41 -0800 (PST)
X-Received: by 2002:a05:600c:1c21:b0:3d2:2043:9cb7 with SMTP id j33-20020a05600c1c2100b003d220439cb7mr55069792wms.5.1673553521575;
        Thu, 12 Jan 2023 11:58:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553521; cv=none;
        d=google.com; s=arc-20160816;
        b=yB8xEX4E7caLUGhyUCTnNBtHHoVnHxRMYcIEWjtHSIj/M8lCvak/NWbTQSQfa9t+6g
         9yCtOA2w3g2bndJkzZ4q4FEva8AV57CkjV1AAP42r8vJmKu3H/ZbFq7wmVkm9JIOE5pv
         Q9xA5jXM61jzdPpgASXniwHALLO8KCDWXYvOiLCELklkcmNUZ3JORHQhxJlHv6kvB8D8
         qDgR3hfnQg7qnvDx5hLqa/9yVjTWaPDcUMGj4/QLcVzgqQ+i985rHrU/4FF8vzwQmFKb
         cAeTY51XZ+cYJRMMoY7gAtcP51SmkEIELMqcdheUge0p2Oh5wvAzsHy7pzi3UeCvlm+R
         jG2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=xUXFMmNjQb3UrGtSZK0a2nhjQSuKqnZvrBUrV/kGZ/M=;
        b=Gcrsgx9+NpaFpsT/m3OyQIM9AA7fAj7m3jLyRpOl01r1IyttjfuD0VimVfIw07ck6j
         wSJ9N5YEB5miTH4uCvfXZQLcIu9vEqXy6Q5fM6T51rEF78XAw8Q2lDcr06qjff0W3LdW
         PoMd1vmE0adGzuj/vpNyhLWeJ/VKVc5U+5F1zi0tJ4OS3SvuxXJ2pF8z7Vmz32iGmBVH
         dom+rrp1fTLDW30+Kz537hYs63PqJa6bc4aWNiO94w7sVAE+raZFZZsmWDoot81w4pa7
         MvBhUBJ7xXqZSmgfcpcqpQobW/PEayofggxK20UzBbcb1Mupw5PKlJte69rIInfTUdnS
         pF9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=EGHw1O+V;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id v6-20020a1cf706000000b003d9ae6cfd2esi918083wmh.2.2023.01.12.11.58.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:41 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hK-0045pe-0d;
	Thu, 12 Jan 2023 19:57:23 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id EC637303460;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 49A802CD0121F; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195541.721697850@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:53 +0100
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
Subject: [PATCH v3 39/51] arm,omap2: Use WFI for omap2_pm_idle()
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=EGHw1O+V;
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

arch_cpu_idle() is a very simple idle interface and exposes only a
single idle state and is expected to not require RCU and not do any
tracing/instrumentation.

As such, omap2_pm_idle() is not a valid implementation. Replace it
with a simple (shallow) omap2_do_wfi() call.

Omap2 doesn't have a cpuidle driver; but adding one would be the
recourse to (re)gain the other idle states.

Suggested-by: Tony Lindgren <tony@atomide.com>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/arm/mach-omap2/pm24xx.c |   51 +------------------------------------------
 1 file changed, 2 insertions(+), 49 deletions(-)

--- a/arch/arm/mach-omap2/pm24xx.c
+++ b/arch/arm/mach-omap2/pm24xx.c
@@ -116,50 +116,12 @@ static int omap2_enter_full_retention(vo
 
 static int sti_console_enabled;
 
-static int omap2_allow_mpu_retention(void)
-{
-	if (!omap2xxx_cm_mpu_retention_allowed())
-		return 0;
-	if (sti_console_enabled)
-		return 0;
-
-	return 1;
-}
-
-static void omap2_enter_mpu_retention(void)
+static void omap2_do_wfi(void)
 {
 	const int zero = 0;
 
-	/* The peripherals seem not to be able to wake up the MPU when
-	 * it is in retention mode. */
-	if (omap2_allow_mpu_retention()) {
-		/* REVISIT: These write to reserved bits? */
-		omap_prm_clear_mod_irqs(CORE_MOD, PM_WKST1, ~0);
-		omap_prm_clear_mod_irqs(CORE_MOD, OMAP24XX_PM_WKST2, ~0);
-		omap_prm_clear_mod_irqs(WKUP_MOD, PM_WKST, ~0);
-
-		/* Try to enter MPU retention */
-		pwrdm_set_next_pwrst(mpu_pwrdm, PWRDM_POWER_RET);
-
-	} else {
-		/* Block MPU retention */
-		pwrdm_set_next_pwrst(mpu_pwrdm, PWRDM_POWER_ON);
-	}
-
 	/* WFI */
 	asm("mcr p15, 0, %0, c7, c0, 4" : : "r" (zero) : "memory", "cc");
-
-	pwrdm_set_next_pwrst(mpu_pwrdm, PWRDM_POWER_ON);
-}
-
-static int omap2_can_sleep(void)
-{
-	if (omap2xxx_cm_fclks_active())
-		return 0;
-	if (__clk_is_enabled(osc_ck))
-		return 0;
-
-	return 1;
 }
 
 static void omap2_pm_idle(void)
@@ -169,16 +131,7 @@ static void omap2_pm_idle(void)
 	if (omap_irq_pending())
 		return;
 
-	error = cpu_cluster_pm_enter();
-	if (error || !omap2_can_sleep()) {
-		omap2_enter_mpu_retention();
-		goto out_cpu_cluster_pm;
-	}
-
-	omap2_enter_full_retention();
-
-out_cpu_cluster_pm:
-	cpu_cluster_pm_exit();
+	omap2_do_wfi();
 }
 
 static void __init prcm_setup_regs(void)


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195541.721697850%40infradead.org.
