Return-Path: <kasan-dev+bncBDBK55H2UQKRB3OMQGPAMGQEUOPKHTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F436668004
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:38 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id p13-20020a056512138d00b004cc82055b2fsf5320407lfa.20
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553518; cv=pass;
        d=google.com; s=arc-20160816;
        b=ndc1amFwv5fOyrO5hbyCat5qSr3q4iWd1/VwXc1jfrY9t5vyePVtKi5WMnjiAZQ3nE
         rjCiPR3gyU7G8YsWt9ihQkjYszH+lAQWTiEt/QEwX6OzvOmrWZK/sSqopKOB6rqf9JiU
         33XbPz6xnqqPoAPSDRWHGOv+TaZenp8h1kEY086cgkMibzN+YRp8iQldj0G/G6LMhswZ
         vIZZCy0OTgX92DCfE4zJWmHpyc+nKd1fDE6qTvzHORAOuFUKxCu/FUVl8OoiA8e7UR7B
         cdSZz+sLESAGDXlkZKyhhPIsUGnJPphmHCvWNLqLVUiGVH+peflEMLZ7GE6Q1DgKKv/u
         y0KQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=8Z1qefE1z4gV8EqkfbgN91zGD9Lh6gaXJjCKArwZh+g=;
        b=NkgTm0j7wWccYGAbGJxVUUuM0LxVP6f8wp9DID8mgw8Wk2AkDDqzHlX8WkGxdnLOdW
         jYVoTdwNL/o7AQTSw7gNNMeMuYGBeasJJKgibEfRjru6kamh4H2TWbb7bWC4HLsF6Cxi
         auM0hYpslf8Z/58wCu4W8yt+K06E63/sOpZmpFvQ3Byc1l2TaZjDo+IUDf0qH7qwAyCJ
         XXMW1CwwdIHKUUx1xDllHZ1qmpY9vSNTrWoY0T0k+Ml3jZDAI+YCyXEOeX7zjbcBMHLD
         DXvOisNYdZN3PVQerfz8jWzCr/YYoYwoMf4/+7b1xghdgCVk4UcEf1TQlwBc5nQZGXRA
         h1Dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=UFhO8sQy;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8Z1qefE1z4gV8EqkfbgN91zGD9Lh6gaXJjCKArwZh+g=;
        b=FrtJEi+v5t0knmqvInll9PWp6GdeirIWFgAZseOJcfUaYhynmEZhLjvSA1tM5WXqIL
         MSvHs8+6Nnmx1hiSk/D7z2xY39/XKPzyPsnmuOYJ1NoBWT/tVf6yruX1SBbOaWEYogO1
         TGo8pJ3Idq+Fd12gZC0JSj1x50oit+AeGXxoZy3k3UriPIp7hcRGC5sMVOV+SDtBbFKx
         RHSxJv6khJzd3LxwixxuAN3B+W+z4VX6v96p9Obs37+ewRqBt5F2g+DM62vs02ZA2exc
         5OeIM9tCisItwmcseuSr31SN0q99IGHOlqJL0+P6SmrAmli28YBshMXN+6i43/Y/gwKB
         /U0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8Z1qefE1z4gV8EqkfbgN91zGD9Lh6gaXJjCKArwZh+g=;
        b=DWIpfy0zEKYqYiTdylI5vjZtPq2gCgcWX9gqXN9Gu5ouFM7ix7+p+TJk/3ruAjxmBd
         JZh9MPc4321DGXotkw0EByPqcmJUJLuNYMctQMAi3qgA8B4ztzLXkdbOk5IAU/zOvPI4
         2p3zl6ZMur+PRYfz86NYKaWwVATNCil8drFNLhABalpxYgqEyZBKRIBuIVkY1CPpKlSv
         6q6qCxQYkDZty6w5WpKTQGontYiovJdkwWftkm/LvvrzanKaPLtCj9Se9OFdboSDPIQ1
         K5yB3Cj7o6ZJ+KlxonRvyy2oecQJ7Bu3inlZ0sNXlS00Mbiq4lto83PgqAm+GMFqllEx
         JZJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krY314pj+xJjAl9U4SgYk0kV+ctTGZE6nX8d3kzs75xebqrk7Q9
	ghEWSJAXwRj5bqISUEHoFNs=
X-Google-Smtp-Source: AMrXdXtPtDAzNp7fqfgQkmX8NqFa0PhNsXkbAV/poNpWrymZenRxcqmRc39SNUIAkHZjiCevSI+xbg==
X-Received: by 2002:ac2:46c7:0:b0:4af:ee74:aa5f with SMTP id p7-20020ac246c7000000b004afee74aa5fmr3807781lfo.24.1673553517884;
        Thu, 12 Jan 2023 11:58:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:214f:b0:4c8:8384:83f3 with SMTP id
 s15-20020a056512214f00b004c8838483f3ls1937519lfr.3.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:36 -0800 (PST)
X-Received: by 2002:ac2:5f5b:0:b0:4cc:5908:b9d5 with SMTP id 27-20020ac25f5b000000b004cc5908b9d5mr7624971lfz.12.1673553516672;
        Thu, 12 Jan 2023 11:58:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553516; cv=none;
        d=google.com; s=arc-20160816;
        b=DqHUcCFTbX5S9ni7FNrbNc+OKY25ElMYfPfCDG3yCuJKpVEJsvAByLS6MXmDrIER5q
         u4LIT8wr7VQIHq5zmMLW7Fy9FJeoaYjLKcFCVu+PYqRyoWCQ+2MBaKtNSAkwL/Etm0oc
         kQL3+wLcWtuJtL9zsv1AJSy/0IjwPbIHxH3YUXe08QZFDvre9c1xzB/DPVWqpkxiRFdn
         f7sCt9psq2srYH8ScQWdcx9CvOdUotlKfMKeA2SZ2VmIv1A+sZ9uSvIHe2M8wxlZQ6Ae
         CS6f/Xj6NvJ4jd93d3KUv4APNZRdZltm9/0wdkeA3sxnE0ht+syoLwnBMro2b85rKgd8
         WotA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=ljNIHChdlymEt0s4DtY+Ji5/5ZFr1jFKrzucPLjcAFA=;
        b=TjMzm5lNdI3EVL6PNkP9TZjGXNgPfbKDylhInk+PfXaRuplCpqqqrFkw/RLAaA+txa
         HVqLjFPEmekKaHLTOahLuz+em7PQHHiU8HMea6HqnkEl3/9JgnEcsVy5AZ1tnC4QyYUS
         EEI0aiwvgqrGxP/fy8zaGj1Dam7dLwoss56g19CzSV+rmBj+S6RU20vkgJIpUAQHB/kS
         s6UW89Zr2KAdlV28Gkh+P/D8mOAVMeptJFZmpOf0MgMm4fUR3xDykfyjvh8opodFpSe3
         mSdGc9no0bphMYWh9A+sIfTWEdCStzS7PF1hFh64Et/qsfI6+yAFojcdCDDaCWLa/OTO
         4kTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=UFhO8sQy;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id s5-20020a056512314500b004b59c9b7fbdsi795316lfi.7.2023.01.12.11.58.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:36 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hu-005P6G-06; Thu, 12 Jan 2023 19:57:50 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2E86B303479;
	Thu, 12 Jan 2023 20:57:14 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 68B912CD066DC; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195542.151174682@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:44:00 +0100
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
Subject: [PATCH v3 46/51] arm64,riscv,perf: Remove RCU_NONIDLE() usage
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=UFhO8sQy;
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

The PM notifiers should no longer be ran with RCU disabled (per the
previous patches), as such this hack is no longer required either.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 drivers/perf/arm_pmu.c       |   11 +----------
 drivers/perf/riscv_pmu_sbi.c |    8 +-------
 2 files changed, 2 insertions(+), 17 deletions(-)

--- a/drivers/perf/arm_pmu.c
+++ b/drivers/perf/arm_pmu.c
@@ -762,17 +762,8 @@ static void cpu_pm_pmu_setup(struct arm_
 		case CPU_PM_ENTER_FAILED:
 			 /*
 			  * Restore and enable the counter.
-			  * armpmu_start() indirectly calls
-			  *
-			  * perf_event_update_userpage()
-			  *
-			  * that requires RCU read locking to be functional,
-			  * wrap the call within RCU_NONIDLE to make the
-			  * RCU subsystem aware this cpu is not idle from
-			  * an RCU perspective for the armpmu_start() call
-			  * duration.
 			  */
-			RCU_NONIDLE(armpmu_start(event, PERF_EF_RELOAD));
+			armpmu_start(event, PERF_EF_RELOAD);
 			break;
 		default:
 			break;
--- a/drivers/perf/riscv_pmu_sbi.c
+++ b/drivers/perf/riscv_pmu_sbi.c
@@ -747,14 +747,8 @@ static int riscv_pm_pmu_notify(struct no
 		case CPU_PM_ENTER_FAILED:
 			/*
 			 * Restore and enable the counter.
-			 *
-			 * Requires RCU read locking to be functional,
-			 * wrap the call within RCU_NONIDLE to make the
-			 * RCU subsystem aware this cpu is not idle from
-			 * an RCU perspective for the riscv_pmu_start() call
-			 * duration.
 			 */
-			RCU_NONIDLE(riscv_pmu_start(event, PERF_EF_RELOAD));
+			riscv_pmu_start(event, PERF_EF_RELOAD);
 			break;
 		default:
 			break;


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195542.151174682%40infradead.org.
