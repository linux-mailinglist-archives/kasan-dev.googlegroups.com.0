Return-Path: <kasan-dev+bncBDBK55H2UQKRB3GMQGPAMGQEEHHDFPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 3863A667FFC
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:37 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id a20-20020ac25214000000b004b57756f937sf7285549lfl.3
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553516; cv=pass;
        d=google.com; s=arc-20160816;
        b=oz2+HjSkDgYgjf+pEcBMO2A/RZVOBKIEhV301N0lR2fWhUjvcxDsxDTSDBvfkcI1CP
         PYlHU/6JEqSQ4V+lc5uyUWH5XjYcJB+P+2RdpyEcsrN8yXXjZoZGkXxavZn+80RmAacy
         DURgkBhuksHypMa1auJQKFRAn0wAWO5JcfGZlmlEHilOmP6FTl2r5Nb6b+mvD3b3dbLo
         +gN2YZpUzy3VZ4h4kfV7p6KM2uiigQY3+b6Qg+XYtQ5gA45FOo3M2FCxUToXF1sPxQ9c
         AJIutM2zBlXBskKLifv7kJF7nxH8d86YKIHz3ELZmWE3Q/QdbwZ0MIWXGGJw0dsrQQBH
         4QEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=NdvOyrZFBne90eGG/Zr0AZVyBKeb+tOZTJyYlnB5IMA=;
        b=k9zSagZAZ5pFJM+DJ777IFAdmQkbDFMDfWbPIi4MQYNxsi8eDi56LQKmolvt+ilykT
         HSrtw+ZCGuSuRWiCkNYV/PjkWQ9SbfPulPC0xrg0cdqhZs9imQPVr+NYY5/pooOVdj2d
         Xz2iX8CPgUKbHLuifHxIb2a/x7I4abiyubwLFK/yekM8cRN69JhkV1tysWW9SaXA7kq5
         sES1XYFuoRU1VLHEbIto0zaw8delwnSxhw3/1cKuCyjlMWMTmDlCPgAYQh8TAlqO8ioy
         quYDISuQXbxqUQOGJnEKke+041yugph/TnOp+RTYq2+f0xegTDSkrp59LnQbZscjDltM
         XEaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=YR175EZY;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NdvOyrZFBne90eGG/Zr0AZVyBKeb+tOZTJyYlnB5IMA=;
        b=df86NDjpLyqO10Y6LsVz0F9TFaZsMno+d0tNyO3mTHJhSbOrkEGYut8pQhT5yopTcS
         q0+84ar1IusJtj+38PiVxuCcGShXBZ1Nz2kovQy6FTbEMbaqR/rgmljSijsnX3H/LqrV
         yiFbIz8UP/Mb1u4/LzHCDunjzSP8yTh6Jle8dgNZvQY+eRY+0EKeNIEu3AyX1lXFAlQt
         NEJOJtQs42uWc+UrEpnl7ubDzETo31lco/4aoT1BlNjFQGUCQd3lc1hWZCVugyZiKQ3P
         g6Iyf5ocvWj/xhdI0S8wKpyA6io8OkQMuYMzHEPZKfiuqBTF4cdMcHhAbfSZXQEyPlyP
         6fMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NdvOyrZFBne90eGG/Zr0AZVyBKeb+tOZTJyYlnB5IMA=;
        b=Gv7G+rYws/gseMF/5dOfCVQw4GwVlkgMnlwK4x/XDT+13OzJE6gKNkFGb1m0QJf+Bb
         2rguf3WlrpkSDKAxX0wRkylzDenuzHTyIXqHYA7fZDdyyw8jVkRe5L7+dbxySjaOCNGs
         Ewpbf0X3ljnf6xu6Z6EpWdS3zi3Qa17AHLHZzSZdzdJSG5F1lOctgI6yfMGtJvMAjrCf
         ZbRugH2eeO3cPDN0nKaGRXSqPtv+pcxdB3ZDJcPM9PutlUhuhMk5qcnXU6dIYAdGuvvp
         o7tLTogbykTP8OHGC11mJVEanUXlFFV5a4RZbUsUkTxwqkWQkjZZXCifsed/hb6FocoG
         r0kw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqu9KyMEghE/WiG9FhFlLZAOj4h3Cei2ux7Ba1mqRJm/NXpVy9B
	9GtHqn9SCuFGDP59BVNEs1c=
X-Google-Smtp-Source: AMrXdXvctxyrG4YqpK9bJb1yKpJMxGXsZ5lc5+4Zic8X3HjpgFkjUqxNPQL7guO3vjuMCWbBTjAHTg==
X-Received: by 2002:a05:6512:3702:b0:4b5:b767:dda6 with SMTP id z2-20020a056512370200b004b5b767dda6mr6177109lfr.398.1673553516611;
        Thu, 12 Jan 2023 11:58:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:239f:b0:281:15f8:128c with SMTP id
 bk31-20020a05651c239f00b0028115f8128cls544007ljb.8.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:35 -0800 (PST)
X-Received: by 2002:a2e:94cd:0:b0:26f:db35:6036 with SMTP id r13-20020a2e94cd000000b0026fdb356036mr19321072ljh.1.1673553515261;
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553515; cv=none;
        d=google.com; s=arc-20160816;
        b=LB8ds1lCELr+0fFQOaoljWedQlr3q7Y+8TOFG0BBiJp0FOJP84P62XWYfgeRdZrI8K
         FVBPDESwP6AFUw52GBML0MemqU+Zu3WHZlCThPT2bqzDpk9J6q6hH4wBcuPQFHprR+t5
         60moAOrgh4aQwzg5wq3v1n288Rz06uOvJv796Xxx3iLN/YMQwPd8jLJvkn+WqWA8ObK7
         Cf9poOtyVp0Hv+Glykhh8vaB+DSASNCk66cll9vzcOWsaDpdMEOQEQfo780T9H/fR4z1
         paLiy6KRpbBMxAN7GkoN0NFUviI7mHPwTNGPDhvXfGuVwNIYKNnCAleiPbLEpUpgiJ2N
         u1xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=uinp+F1SpsUbDqJ/LD9jugydtpLudfVqOBpAkBm/Kuw=;
        b=YLYNbiWUuDIdAd+RnoyESmvg7XlbWbmof6zoVeVUChcBK5tmoyduxg77LaJHY3FgD4
         d2rhH//EXLE9eyjk0uYoPSITUyCaL7U543rFLU9MM/gEx1PYFnoISNO0TURpbZa8PW0q
         SnXUfdcRVdlf2fnWLFAE440LGNPIu/aHozw1FTvcgEk/9ije19kf0WGMubAR+fI5al1g
         BbknIVV43MC9uKPEr1PNwqSSAnrpuj3xKRNd3QlHWF/Q1b3EG2PwwRxHtleeXj+91b4i
         Ml2VqfgdS6c9BHMaK1wRICd5uKKes26Eui3ylsD0fmil6mJm2enZqwNTpG6dmmrCC91o
         dbgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=YR175EZY;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id b1-20020a2eb901000000b002837b090b3dsi801668ljb.8.2023.01.12.11.58.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hX-005OcR-Pe; Thu, 12 Jan 2023 19:57:27 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 0BC8D3033F6;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id ADA0F2CCF1F54; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195539.821714572@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:22 +0100
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
Subject: [PATCH v3 08/51] cpuidle,imx6: Push RCU-idle into driver
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=YR175EZY;
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

Notably both cpu_pm_enter() and cpu_cluster_pm_enter() implicity
re-enable RCU.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Frederic Weisbecker <frederic@kernel.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/arm/mach-imx/cpuidle-imx6sx.c |    5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

--- a/arch/arm/mach-imx/cpuidle-imx6sx.c
+++ b/arch/arm/mach-imx/cpuidle-imx6sx.c
@@ -47,7 +47,9 @@ static int imx6sx_enter_wait(struct cpui
 		cpu_pm_enter();
 		cpu_cluster_pm_enter();
 
+		ct_idle_enter();
 		cpu_suspend(0, imx6sx_idle_finish);
+		ct_idle_exit();
 
 		cpu_cluster_pm_exit();
 		cpu_pm_exit();
@@ -87,7 +89,8 @@ static struct cpuidle_driver imx6sx_cpui
 			 */
 			.exit_latency = 300,
 			.target_residency = 500,
-			.flags = CPUIDLE_FLAG_TIMER_STOP,
+			.flags = CPUIDLE_FLAG_TIMER_STOP |
+				 CPUIDLE_FLAG_RCU_IDLE,
 			.enter = imx6sx_enter_wait,
 			.name = "LOW-POWER-IDLE",
 			.desc = "ARM power off",


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195539.821714572%40infradead.org.
