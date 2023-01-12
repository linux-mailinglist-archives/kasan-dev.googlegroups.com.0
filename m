Return-Path: <kasan-dev+bncBDBK55H2UQKRB2WMQGPAMGQE5YWVWIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E5C9667FEB
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:35 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id e29-20020adf9bdd000000b002bb0d0ea681sf3770864wrc.20
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553515; cv=pass;
        d=google.com; s=arc-20160816;
        b=yaJUO7chRQX4zM3N+FsNEkIGYz4T070NacU5fifmbESBrS7qvTjpFkzyhYsvt8ImIa
         7zBFc5w2I3fMW5Xm4yyP4vWp+BbNG3QNHvCKNe8UN+PsRC74DEz/RbfsInQJZ9nyT5cP
         rnDl67WCwnuOHNavTr7zSa14SFDG+NsWMXJYAmCjYr1tIT/ev46pJjLDBbQApoOv9NMG
         VwGUpLxZVT8ddZM3RN+g5dgs8dQ/60vtzAdn8iAXHWFSnacoE4Kr/m+qAhFKSgmMryTH
         6U+i4v2gBxzFHJl9CkyVNHrM7ycOCndNpeiOGlcJGYdhimMYyAt1YNNrMcNxHblLnq3P
         7PDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=mUUFvY5Y+Nz4VCE8oV/ve5lFzhDJ7+qa5QCfJqnJcK4=;
        b=UarvZDrfg4aep6JN3DeZOYEAd4h3OpGPHoidWJOjv2OK2WsHYCtdVn1dL72Z0QZGwV
         FJDCdJYnZzMym2BieVjN2F70Hx00MGvR4zs6bbVK7pPUJ4QMtlaup8mvccqQhzXZRB9e
         K1dCLS8IZCd4qzPbulSHKOL/1CayMWDV3FwNZjxOb29esUfcWt2AGkKs0F+4zxCjztI+
         YiD3AIsDhvefNy0T3tV1KJ/A2rLweOPL9MThvnRz7vuaDNV0PLWZdgTSrdJs9IKHd4rP
         a3SLHRGt8ks5GCzr4cEUaQHTOL/ndmoQttHB3TOEoR0nfuIFdxZ5N6GR7uw4hoKuUDsc
         r8FQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=T8OnHc73;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mUUFvY5Y+Nz4VCE8oV/ve5lFzhDJ7+qa5QCfJqnJcK4=;
        b=X6UoLoPGMQ722MzdATjmQO3yc88Kl1uApmYyZU7FH2dFxfmg1G820FuFwPL9Ps/nZY
         o3lD9bFbGORdj8Gh+UTvliVcmDK7Cw3HUSDoyK3qZvgwCz7SNtuNKfKs0JAuyXpMyGvm
         7HoyO2FFV04E3sSi2fI8oRnhN42yVjfxpTDxC3K68pJJpIZryc5NMsjF0YBihEkRW6lK
         wDRpVqUPKqqmOmohP6C+dURhAPmIHGRBLIXGOjkThWSl5/ajYMbRN1SbelPVVxhBN2at
         kAyQEW4WJuvIExzevO37q76GfbR2JOR7YoZCN+6zp9QG2Ymi/aVrdP3L+sZJnZQZbw/0
         U8YQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mUUFvY5Y+Nz4VCE8oV/ve5lFzhDJ7+qa5QCfJqnJcK4=;
        b=HAskBM4LjkXnOdWaN5jh9jombtasoN356PBvCdRuPTjTGoHl+TuKRuNDc1CH5SQmdi
         uaXAukQivxZ6gM8cOpxrUIN/sg62lvSe6ZNu31PKcFEi3Gr5tuQtL7C/k0iTFEFRBE3x
         vIZiv0JiExH9F5DpbOqs20mIsUxHyOdgNIw++XCD9CcoAdyeljiZ4nQ/5YUBeSxNcIQ9
         XZDzcqrWxZklleNHrPnAeuSqKuj7QMXDh0iP0iPbP0VkEWqh0TjYzxDUHp3irXmCUDxq
         kv8IxbmrtH9erbSL7S2AcSTK3egLNtU7rNvVfnTPr2d56hyhjRokxa1MgvfHvEtvF1iD
         XE5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kolQgjitEP+gQ59TluOhHvz3v00lzbXirC/qksYD6Fq9NeHILWv
	Ip2A9gLFvZW6DyoksDYLMDM=
X-Google-Smtp-Source: AMrXdXsOTScuq9R1eUjH3niXYjrh32uj+2rl7DBRRRwnkBJtGA+jQPQTpNpH3tVs55db44M9zm93ow==
X-Received: by 2002:a5d:500e:0:b0:2bd:dd46:99b7 with SMTP id e14-20020a5d500e000000b002bddd4699b7mr11790wrt.108.1673553514639;
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d234:0:b0:2b6:8e51:dcb with SMTP id k20-20020adfd234000000b002b68e510dcbls1471083wrh.3.-pod-prod-gmail;
 Thu, 12 Jan 2023 11:58:33 -0800 (PST)
X-Received: by 2002:adf:ec90:0:b0:2bb:5d8c:9575 with SMTP id z16-20020adfec90000000b002bb5d8c9575mr14805510wrn.12.1673553513495;
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553513; cv=none;
        d=google.com; s=arc-20160816;
        b=rscLI/7gBgY7oMX1csQe7LwcsTICBdSRMK0uGSkuh3hXy1mCyXAPTgB1WmfOLETy+4
         oNLuhEAIjn33jZ1W15HX6UA10UZ4RbvDFRHWt1Ttk/2qudzZDlRm1eIA5sy2M4/I2f0J
         eQArEUnQLtzlCgtrkDHDFTPTd9Otp8ccLJyHgRnprd0AeUeb3iKcklIn4EYnBd+ogXC8
         6erA7+ZmzPVYvIcXbdI5RuSkjUmNZD81wxqu/7Pqr0d7VLiuqPwA/89Z0xhtklowbBKY
         lU8XgIqdV3LMknDSJ+8b/1+Pq1PXAoKg3rT4YPVJie+t9H76+XezodZdGThFYLUfd3o7
         Q2hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=N/LoJ6QokuvkgqrdUyeUyAC9uk5r3NGpRlHTjN0UEk8=;
        b=RUGX36lgGe/tLDZ1ICXtSP6g/nWtKXPjxBfAiepwHKFviu2KiYeP1T4PfvT4QyYGRb
         hXp+1yyf+MtMo08mssOxGP64QP2BxqamvNErQLVl9L8Qf3iHERfeYhb8j1P77e7h9kEH
         VsHhUSp9Ex+Mn+WXRLMpl9YQN/D/WKCzHDZKdyyMB7PiEj5ubn1qKspSmdoWVBrdidzs
         4iuTAYtMzUmSfvOXLVJYiJwkPyGOJARwc/bQUcQTwKzuRu/cw8JPNKzeZEO4bHo8Uutc
         gnUdf+m50qXST+y/MUC5oz9W43I5GNWivFQJjiU9PD9+Sf8VPOxSFUPVzB3N4B3QcJYV
         fifA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=T8OnHc73;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id m7-20020a5d56c7000000b0023677081f0esi826727wrw.7.2023.01.12.11.58.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hZ-005OdY-6w; Thu, 12 Jan 2023 19:57:29 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 3C862303414;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id D46292CCF1F75; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195540.251666856@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:29 +0100
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
Subject: [PATCH v3 15/51] acpi_idle: Remove tracing
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=T8OnHc73;
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

All the idle routines are called with RCU disabled, as such there must
not be any tracing inside.

While there; clean-up the io-port idle thing.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 drivers/acpi/processor_idle.c |   16 ++++++++--------
 1 file changed, 8 insertions(+), 8 deletions(-)

--- a/drivers/acpi/processor_idle.c
+++ b/drivers/acpi/processor_idle.c
@@ -109,8 +109,8 @@ static const struct dmi_system_id proces
 static void __cpuidle acpi_safe_halt(void)
 {
 	if (!tif_need_resched()) {
-		safe_halt();
-		local_irq_disable();
+		raw_safe_halt();
+		raw_local_irq_disable();
 	}
 }
 
@@ -525,8 +525,11 @@ static int acpi_idle_bm_check(void)
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
@@ -571,9 +574,7 @@ static void __cpuidle acpi_idle_do_entry
 	} else if (cx->entry_method == ACPI_CSTATE_HALT) {
 		acpi_safe_halt();
 	} else {
-		/* IO port based C-state */
-		inb(cx->address);
-		wait_for_freeze();
+		io_idle(cx->address);
 	}
 
 	perf_lopwr_cb(false);
@@ -595,8 +596,7 @@ static int acpi_idle_play_dead(struct cp
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195540.251666856%40infradead.org.
