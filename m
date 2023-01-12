Return-Path: <kasan-dev+bncBDBK55H2UQKRB3OMQGPAMGQEUOPKHTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F959668005
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:38 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id x13-20020a05640226cd00b0047ac11c9774sf13025535edd.17
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553518; cv=pass;
        d=google.com; s=arc-20160816;
        b=DyoYhh0yYmJ3cwmNK1bzGfKmx5mXMeNQPydNyLYul4flXnXxT3Tz1c4NZj2lUCfTdE
         rvzo+7ngaoeE9oiCCnWAvam66/zUVqM5qG4Z+L1scCkYNTBlqL8zB6OLXBA3BORgRiOj
         lVK4UF8m9F7GRYjWxfXfBV2hxWs+7V9nPLGhhB+ts63H6gjijwpUH1JetntK4efXOG3H
         8WcwDQB1Obderwni3+3eglsZAnM35eleDMVJFFeQoWmvImc2LnTZGVnWEb7cQYzocSCA
         Iwtan+QgA/lU3eYRVbFnKlbqDQzs7dOMKK5oQ7CTJV0DABP+cbnUqYjfRgJUeCsdyIp7
         2s/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=6kG/A+GCIje96jOdpEoinbEfT4ZPLOiLJQ+Vaajq4wA=;
        b=k2cXahgEyeyCyVGP40NFu1b7l7oWVo7ntwgRAp46scby5+ApFn//QvRb8Kk4dvdFtK
         AMYkvnhG6XIPA/PeRXRb4i2JaQTXrG1H09OPZ/MbDjdmLJMHbVMs2Nf2P9SAlc5qah9e
         eUhKPcNqfXZRHZ+gytaMGGrxAcED3qhxaohvRnHE71nHWRKOGA3bSGVx921GYQCwyOrE
         r9xHGEPYoL8uL5oG9JGXMLsLu/VlG+EV1ydFVAWhg8MhuJ2Qsou5J7ENnhTVqGbccRvZ
         FzYmFpOYadcoa/1j0eZ8JzHrIqLcPuGalSZo753aEKVK4NYJfDc94lYi4eEdUcosX4CM
         j/0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=XHTa9fJQ;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6kG/A+GCIje96jOdpEoinbEfT4ZPLOiLJQ+Vaajq4wA=;
        b=GW4MUMKt6JhEGhgLKkkMyI1+QLB+05mWRxozxlJjCitt2Hp7gdmF+HjvADHlDch4W9
         0plA4gG0uoZcMn5hFa0zeqc6fNetxHuq3DdeXpLUfO3WFI44yyLBr18eYbdl2AuSk+Kc
         aRJis1zHvZoCzrUgpFLvrKjshUMCqWElwhdWlwrjNT4kZ4qTYsCRc7wJSSRZR9nXYeX0
         JZzrJ7QO8WoTBxpYemQGCjVqqkpX+aSksjwApfqd1Rgv52WNptvLdop+GFpRTahqQSWz
         lhnw0YdPTF+F1fI2JveijvU7pp3oYsWmmUgBybVNTgiMyqg4gh5qDkvl/u9vT2s4vwbu
         VuFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6kG/A+GCIje96jOdpEoinbEfT4ZPLOiLJQ+Vaajq4wA=;
        b=sjABlaez2rODoGHdFkId3vt3kBOMl2fpuuv8rrRYX+39g6Hu1OX2zSdmJoaF0MdKVU
         7QkQDfa9pBPyP+ilhctUqVZECGeOIV4IkfhsXCVoFRlzyh8Zt1C4YJHBNwsv7z0J5AJW
         HIqfuQgc9To6hJqloFrBZhCdnhd6VU2XyGK1n9MKW6Y/5ehC6r0vMZr1rZiGO4yWbnsG
         9yYs/ICgx6gTXT3qr8wZ9dvFdzqDwcdl9J7s1R/MduyISud6RnPJTpsia64OzwAm9z36
         Z7tDNCmypBijMspOA6G1IEfmuJvqVluOWOS/Nm1D4+YhAnDW5bWbIjtGEU/K9EZS7MN1
         ffGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krVODwWJ55h6SjgrhQL53ejxyQ5HN6iJOdIAK2Ee5KtRbK2vlC2
	ctoB2W4KpCQ1zK3tKK54NNY=
X-Google-Smtp-Source: AMrXdXsek3ZwZ0JozRwMHIyJ9TfHo2/Dv3qsc4C32LOetuJ+YsvWgxx255QI4t3EgQAc5wXhwlK4Yg==
X-Received: by 2002:a05:6402:550a:b0:46a:af31:7c4f with SMTP id fi10-20020a056402550a00b0046aaf317c4fmr7230409edb.320.1673553517893;
        Thu, 12 Jan 2023 11:58:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:2485:b0:84d:1543:d10e with SMTP id
 e5-20020a170906248500b0084d1543d10els2043032ejb.1.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:36 -0800 (PST)
X-Received: by 2002:a17:906:f6c1:b0:7cd:ffd:51f2 with SMTP id jo1-20020a170906f6c100b007cd0ffd51f2mr81500991ejb.57.1673553516701;
        Thu, 12 Jan 2023 11:58:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553516; cv=none;
        d=google.com; s=arc-20160816;
        b=xqxlgRY2pe4dOTZ7WcwRURJDWM8xCYq1zgBSn1wK63EwO2nysd7M9FR4VTo6kyxXPr
         iu7ioWqmJ9XvsPOvgRNOBBitAADNCNUQI2KHvvArh76Vy7JN6EhTS9Mke9uFFJr5bhD8
         0wONfXCDgVmiFOaBbae1WcCGPHjKSwsa6pVkh3bNmV1G9sm0i3UmnD1KlzMrkhcMWuCS
         pul5j6KKEFzkF0Cj6dkVdHeAv0PeRY8fsf2J7MOtcctEvIhv8wjZ8WT27nZE4Ipw+ubc
         Ko8KA5z4BtHlz1HRpBdPty3BclJkceq24pXUItbYYgi2y3kvvyKxocgcmXP0yKSTTKtl
         1KQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=WMNBIHuf5Xvagmacq/Rua4pXk5oPDpB6DgeHQM3GMNM=;
        b=EljvVrHSaiBxQksRfcqlF5IXOXRGSs/S6eqy0muDf1ZqzpOv1rBlTZXvPqivFSKeD6
         7q/EZLPn8ktB2NynLkBpcMKhKaUZcd2U5Lmdmc8KZVD/vpKWPjfBlpBajHZTUJuGFPCB
         E5/0olk5STzhd2tE1DTp3/vnElz1eX2+i2iyBwnKQqAMd6YPE7N8eziMUdzAhrar65yi
         qpHYI89Am5tHahMRNrY68yxDOGcRC+LczQVAXfe5XptyxMsX5AWfu3VP7FJhfRtEs+81
         lDMTl2R3edjmPeiARo3ReLD9H6cTjH+3vKqd3flxFi8X+GZ4StQI5PWVq49vU5AZWzwX
         9Lhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=XHTa9fJQ;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id mm6-20020a170906cc4600b007c16d82962dsi974208ejb.0.2023.01.12.11.58.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:36 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hX-005OcL-Bh; Thu, 12 Jan 2023 19:57:27 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id E69463033CF;
	Thu, 12 Jan 2023 20:57:12 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 9D69C2CCF1F4E; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195539.637185846@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:19 +0100
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
Subject: [PATCH v3 05/51] cpuidle,riscv: Push RCU-idle into driver
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=XHTa9fJQ;
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

Doing RCU-idle outside the driver, only to then temporarily enable it
again, at least twice, before going idle is daft.

That is, once implicitly through the cpu_pm_*() calls and once
explicitly doing ct_irq_*_irqon().

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Anup Patel <anup@brainfault.org>
Reviewed-by: Frederic Weisbecker <frederic@kernel.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 drivers/cpuidle/cpuidle-riscv-sbi.c |    9 +++++----
 1 file changed, 5 insertions(+), 4 deletions(-)

--- a/drivers/cpuidle/cpuidle-riscv-sbi.c
+++ b/drivers/cpuidle/cpuidle-riscv-sbi.c
@@ -116,12 +116,12 @@ static int __sbi_enter_domain_idle_state
 		return -1;
 
 	/* Do runtime PM to manage a hierarchical CPU toplogy. */
-	ct_irq_enter_irqson();
 	if (s2idle)
 		dev_pm_genpd_suspend(pd_dev);
 	else
 		pm_runtime_put_sync_suspend(pd_dev);
-	ct_irq_exit_irqson();
+
+	ct_idle_enter();
 
 	if (sbi_is_domain_state_available())
 		state = sbi_get_domain_state();
@@ -130,12 +130,12 @@ static int __sbi_enter_domain_idle_state
 
 	ret = sbi_suspend(state) ? -1 : idx;
 
-	ct_irq_enter_irqson();
+	ct_idle_exit();
+
 	if (s2idle)
 		dev_pm_genpd_resume(pd_dev);
 	else
 		pm_runtime_get_sync(pd_dev);
-	ct_irq_exit_irqson();
 
 	cpu_pm_exit();
 
@@ -246,6 +246,7 @@ static int sbi_dt_cpu_init_topology(stru
 	 * of a shared state for the domain, assumes the domain states are all
 	 * deeper states.
 	 */
+	drv->states[state_count - 1].flags |= CPUIDLE_FLAG_RCU_IDLE;
 	drv->states[state_count - 1].enter = sbi_enter_domain_idle_state;
 	drv->states[state_count - 1].enter_s2idle =
 					sbi_enter_s2idle_domain_idle_state;


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195539.637185846%40infradead.org.
