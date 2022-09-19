Return-Path: <kasan-dev+bncBDBK55H2UQKRBT4DUGMQMGQEBREWNIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 841015BC68E
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:51 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id d9-20020adfa349000000b0022ad6fb2845sf1384692wrb.17
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582671; cv=pass;
        d=google.com; s=arc-20160816;
        b=AR6bVZXGXSCHi/UjtOHtEA6LiIx32nODcc4qv/qiO8ahhQ7/AQNDGcv2Mig+uuS0DV
         nuxglnETpqpoplQOehbvjtTbj5OQSUf3F0YBcZuE8ZxmZGQpvcsWvdSc88rQX9jI9fM1
         wwVLdAG9mmeGx3hYc3/T9PbLEM7gSOKqruWT1G/C+k3Eem8+liIVuzrEj9E+RAkkuwMT
         om1/prKFggIa9SYQd2LLg2Sn15ddik8WdK0GlZzLDSTypXERlgz/H+ZQ/YpD+SIHlgBU
         kf4DXwFNXBVYo4UmNuJlmgTDM6cUG1Tf9yBLCtOs5mKMAWOV1iE1gOQO9c5RuEQKYED2
         ih1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=XOkSB8zk2SPc3UFHgekCnseDLzQoWTHcu05PfwpbD7g=;
        b=P6yWAkqlPQHBuOXr2iCfWmZjJ++E5OWYq2j+8F03WvL4+DDzqGf7NFTDyiuAkB/8IR
         01BJMvEQDczwStvDdoCftZ0NxSW6g1+o1563nWXii2dVL3n/vrOPrKaD3ND/K1/KE3Ak
         2Z0lCl6F7LoBfpMv8CuyC85txE21QKIU8dOXXVZmyY3OT47qoVgHQ01uo79HzCFS1MTc
         yX1lRw1i4RPWBZYxw3SNdd5KjuJ0hTU7Ow3vHe5a2IW5XP6lMYCL9wOwaPWVDu/OxehE
         y16GcDdOtWNplCDGjXn2BV/CxCX5AE8P/KGLGQQiX1PawRt2wYJQ0pBwpRdrz17vMfa5
         A2Fw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=eB9R5mWQ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=XOkSB8zk2SPc3UFHgekCnseDLzQoWTHcu05PfwpbD7g=;
        b=T6asTaMvi+nBXLJBGV8aoZn0ota9GNnMEkXUxceOvYBrEJ6R7LPiSivjz1UNQ0nj4g
         brg+8D+/zjXrTcdjO6U1BznKw6XNlns7HOvw+GMTS/HTql0v/gqFAOZrt8yrvdEWYXuZ
         u0A1Qj4x0ITXd1Tw+qi4m7rTm1RLirA78aSeT+tbJdrVoAd4qJfQ6NZ9aYq+PSkTW6Dv
         vPHKqrVJg0sCA0n7IBgUsHy78KLkDhlyTsPyUPi9zyxyTRmMjBq6AYpB7yL8C3BYAq7Q
         jb+ZdIBC9F3PHiUj/sTHAtmjmP6cucQ8hmrYzImmamemUs6+Y3ngkf3hHHDDlc5JJHXY
         EFRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=XOkSB8zk2SPc3UFHgekCnseDLzQoWTHcu05PfwpbD7g=;
        b=lcPZAc99SY32SyPpsu9xNn6Tjlx1ddv0wZzG0KSWWBbt9JgZpO1SPHTXBPHVyavrEn
         wvDn29JIQUiPA7g8ZK+fhBnMJO10rTI0p7PG1soRem5mnwOTGbd9QhhU80sVMXUsh9D7
         kE4WMhhBztXr3G2DOHtexGdVqgZj9tVUgrJt7ftzh+xx6yLaWSJbO//Z6jvRDWjdKgil
         aeGN1w5HlTE++Gua6ot2C6ZbJCtjVngM1FceTamcUUqw9Rzoe1B3T8lswxETf+dqIwRM
         Gx4IFFxwRCnb+Ox5K77edgfA9iSh7fLWHoKVlDEi/RqSvjCN2Ovq9/1gjCsVZ0QyXck9
         RsNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2ckZVnB2QHW1LIpMw47a6Dpb/ZSmaGttTAPKzwhBI9/MCfHvL2
	oOZRtk1Z1tvuHwL24iaa130=
X-Google-Smtp-Source: AMsMyM685+Tx8xnp9Oc3xkp2DmfAHVZyaHxRFoeBRTFSlHGrGeL5Jn4Nd7CsUEfgwtRFVrox8Ry7SA==
X-Received: by 2002:a05:6000:1d9d:b0:22a:745b:9f00 with SMTP id bk29-20020a0560001d9d00b0022a745b9f00mr10118943wrb.280.1663582671166;
        Mon, 19 Sep 2022 03:17:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d20c:0:b0:228:ddd7:f40e with SMTP id j12-20020adfd20c000000b00228ddd7f40els7610801wrh.3.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:17:50 -0700 (PDT)
X-Received: by 2002:a5d:4688:0:b0:22a:f718:7f36 with SMTP id u8-20020a5d4688000000b0022af7187f36mr4294914wrq.315.1663582670135;
        Mon, 19 Sep 2022 03:17:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582670; cv=none;
        d=google.com; s=arc-20160816;
        b=vyz+sYaETE9OiEblI7K1NB+dORc7UTnAocmuCLlvRfB7AW4ujl6WF9DreZtSrGhmcb
         nrmXxPRr2t2Jf8U3IPUp+12CzbGYorvqLLPW83sg96SXNs6eSSRB+c/jvjxl+ojzteq1
         9UIpxWXIy+DAuxCtTjdmsPxjkCgZrOqhhooS1XqwauscDRE95fjw1uSkZ3Awgbw5wUo1
         lYAOAzyAC7GSBduSZqWdiMLj+Bb9d67MDt0oS4x+mK5+T1s1K9rTOBEsmIEvnr9nwQJP
         zXn0+TYH4C/wC1W7KJKJcspv6ku3YLmEqo5MtPQOuogBDJGIbgSWRhnWMauWEqvBfxqR
         7vBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=QBURQn+mxYjA6ZNht+ExoGHyL1lX5y6iU6jaWv/bZEo=;
        b=zp6E0RhFY8CCVwr8vE3itEYqq+m1v7MWKaoD6vwAMieXfx67yEfoMaiIH1Wx3gMf4W
         34wi5X71sIZwEp/okxGRrPEbevXJld+urx19qbH5KuD3typpqAeXDw5OtNy9yffeJDD+
         1svvYrgltaezqAs8d3veUThdN/I84WreDHqDhW/m2CyZ/EcgXeitPeFyggvUfVRyK9CO
         /R+cI/UECpwKzk8JysYdioeQNXhaZrBioRlk09PgGkX3HHdxPv/1ugjaK0/VaOe6hNnT
         rgtZUoXyl0iq5w/tTZCnk0XjmgnDx7XjaCqKB82f6KSdiBMi/NaJENraGNnPhlmbYegn
         oljA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=eB9R5mWQ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id n24-20020a7bcbd8000000b003b4924f599bsi351427wmi.2.2022.09.19.03.17.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:50 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq9-004bC6-9x; Mon, 19 Sep 2022 10:17:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 76F32302F61;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 8C73F2BAC75BF; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101522.842219871@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:16 +0200
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
Subject: [PATCH v2 37/44] arm,omap2: Use WFI for omap2_pm_idle()
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=eB9R5mWQ;
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

arch_cpu_idle() is a very simple idle interface and exposes only a
single idle state and is expected to not require RCU and not do any
tracing/instrumentation.

As such, omap2_pm_idle() is not a valid implementation. Replace it
with a simple (shallow) omap2_do_wfi() call.

Omap2 doesn't have a cpuidle driver; but adding one would be the
recourse to (re)gain the other idle states.

Suggested-by: Tony Lindgren <tony@atomide.com>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101522.842219871%40infradead.org.
