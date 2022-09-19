Return-Path: <kasan-dev+bncBDBK55H2UQKRBLMDUGMQMGQEZB2565A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id A04BC5BC649
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:18 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id i129-20020a1c3b87000000b003b33e6160bdsf4446934wma.7
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582638; cv=pass;
        d=google.com; s=arc-20160816;
        b=cIH8E7KVOYfqz7x3ZjCj2pxEG4RPfL325LGLjhGOQ4wTkHKfAVysVXMWPCVvSNrt7q
         HrCIu2JGFfoI/5G1XcryIIuXtGZdH9fh38qQMEzullu8sIzwK8dpaqRZWZSaLoSNZlqQ
         Wh8FV4ktsof58h3XSgGq0jS+ZmyJpfNvfa0eP5/iweFPK8Hi+o84fmQLKH1IMf1wbyF5
         yWWjePRRQ2cpTTX/QIYY3PbbxQ1GYYx3LbEcupWHKV8wNRojgK5TjRT8Wemz+mmFIEWV
         p9cYVtGgSqSLsoSF/1qRcyIAuGe+EXL8MCotqPYuUo38QkXdzgZSS6wDI0Fo11nQeEvq
         dZ2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=baQUS7q2eIVG3BxqS3vFL2BZ+TD0P8BCjaG5+7/KAYE=;
        b=MBY9Qd+V8C2YbW76/TDDyYZGlnfZ1gF6eWHUZG0c3rNM2dSPL7uzEJyECVsWBCdO6e
         VqDgAUmo+mLE+6LS82cdFq/4HRRfkDOPSKWPke/N3SAyiKlz62S4aX4Bh5kyQtdO7zjD
         /cf7Cjmpe7g89x6A9MoEqEDY2wD/CA4lxWDd0/ZsoEwff3dZb6jBUFCnKv4kXscGnZcC
         LtLQ5w9NGsjHb3e7Cs2+3THGGtNVOg0ZjRKjjbiNADxOnbl3zwL5rgBkLKEyl9zjBcYe
         smOOzuY2vt0uKvtgEMvkXK++IkOJsm58fqnOcMRteQRJ45M23YdV1Vaj7QoiJr8ckuy+
         c7AQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=aw+ABMw4;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=baQUS7q2eIVG3BxqS3vFL2BZ+TD0P8BCjaG5+7/KAYE=;
        b=aRL4a7HpIpQRI4VPzyA1oKbm82zxuFOCUGTC2dB2S/BUY8j6zdGtFOhtkGW9Orm/Cb
         uhUsceQ3+FtaNbBSqL6WUnuJRR2hptrS+VG+D9smZ2//QxGKJDs2h+SSLC/oilo0OkIo
         s9udqlBEA+1mBiGnQg14PIAp/QUPS2Y7FccJZ91oMt6Xs0iB4q4/+BLbBlk9bfA/Ez/5
         oGaVbHI2A9TqsDq/lz82FZx4poEkir9wYflj3OS3Ee02+9gU/rPAAyYEE3i8qWWenlqJ
         ZAT+m4nqccdGi92u5Bi58eJEWZ0dUuThp4Tjaj+fUfmDfVZUAipJLMUhSrOulRKXSR6k
         7QtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=baQUS7q2eIVG3BxqS3vFL2BZ+TD0P8BCjaG5+7/KAYE=;
        b=lui7Ri1+PHbG0d3D9Lzo0Gyb7n8jYOvtjP6lrNb37+dRvwGRl9x1xLRFQGkhSQcNoR
         K5VHbwrKsO3ydP5OSJabybM+Pz8iwgRLP26wcVd97r8jMti7FF9SSGTUSpqnPSEzcT7H
         7Y19e1gIEhDJ58U6evBrHNurq/uuCq1Vk+bNtJXGdWvI0lJvmUhaQS0AtZpibL3aNIxT
         kkpMUlgkksXlmp+Lg0greJ5+Wumq4XMiheSdN9tB9vxOzeiTvDMnzZNKenMNyRx8ctJu
         otuDy0yeSFTpcAoSYmlwJkVUqDZYpJJhnQvZqZhYHgQrDEmBZ28p98tjfArTwi9gAYal
         VOkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1lcUHkMaHFxbch6sjbcuw/ZwXfE1XvQIFx1ALpzRanrdwLI/t9
	V2IyGj9BaJ8q/d//bTgNmwI=
X-Google-Smtp-Source: AMsMyM6jQCT1FxZlA759OYlWAWm9sulrhf+rz5rYc4kbOrdCnAT/RajloD4gHMpj5YEda1PLS7eobw==
X-Received: by 2002:a05:6000:1f1d:b0:22a:feb9:18a7 with SMTP id bv29-20020a0560001f1d00b0022afeb918a7mr2409194wrb.152.1663582638188;
        Mon, 19 Sep 2022 03:17:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3489:b0:3a3:13cc:215 with SMTP id
 a9-20020a05600c348900b003a313cc0215ls2665502wmq.3.-pod-canary-gmail; Mon, 19
 Sep 2022 03:17:16 -0700 (PDT)
X-Received: by 2002:a05:600c:1c03:b0:3b4:618b:5d14 with SMTP id j3-20020a05600c1c0300b003b4618b5d14mr11209052wms.59.1663582636699;
        Mon, 19 Sep 2022 03:17:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582636; cv=none;
        d=google.com; s=arc-20160816;
        b=tOeEV84l7VgTlOCDRzIvHLn8ipsumLkBSEuz++vmna3Kyfy/2egFWmXthXCZ1KpI6d
         /n/0j26w34wK23SOOlyWcD/6itRPmSUjkSTWDZSTid4CLSkcwE6Ma9CT8PuFDIuzavnc
         Xh4jYcxw0CLpc88NgllXWdn3iodGOsM9tzzk6Sy0QgtjcGA2IlkVvoiSsct6wIjZZlqM
         FwKvqjx7x5aTpt5S7dQ5zZ2IFIMT7Qf7MSwg0Nzran9TAwftpok3k4hMcrNEoBieIC9i
         pDRUyPPKfVhJMdWm+w/vrr+cH/vyaBcLEvjzx/iy4HPNRXI1+U4t7rkIFrsHWKqFOkiI
         rGng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=tHnqBkdMyvYunYXYVYlgcgUQQIKSwssAZ5pz8qcqKQY=;
        b=vhoYLbp7iWB6A6inqm8R50O81NsFM8CE2jBYhwumUOfD4KCtgSyGKwdRUVRED7YD2w
         iMVJMpH7e8Nk6GbyVzaiMjz9TsKPth8S0JCy9igpRk9cBAlIG9NyLpLnwUPG4DwwR6YH
         +I7wqQhphKSgkl+yEFE6CTlxUlbc5OH1It2JlF/Kb+KE/LNwFbIdeEoqbO++AC+0sLdd
         mnnfaAXL26a0Arrs15PId5FklLjK9OILpCiRtlg3CG9gJhxAqVpJysqhPo0nSTL2oZmV
         Ecv1KRErD4l9bbx3d9AKCB8L+Y3osfuFPj17eVqhkkap5r02rDKb2qqhZCElDzAB7a+I
         pvow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=aw+ABMw4;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id f62-20020a1c3841000000b003b211d11291si481345wma.1.2022.09.19.03.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:16 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDpG-004ai7-Jo; Mon, 19 Sep 2022 10:16:30 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C12E8302DEB;
	Mon, 19 Sep 2022 12:16:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id E6E592BA4903D; Mon, 19 Sep 2022 12:16:21 +0200 (CEST)
Message-ID: <20220919101520.869531945@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:47 +0200
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
Subject: [PATCH v2 08/44] cpuidle,imx6: Push RCU-idle into driver
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=aw+ABMw4;
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

Doing RCU-idle outside the driver, only to then temporarily enable it
again, at least twice, before going idle is daft.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101520.869531945%40infradead.org.
