Return-Path: <kasan-dev+bncBDBK55H2UQKRB4WMQGPAMGQEUGKNKOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id A8818668017
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:42 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id i7-20020a05600c354700b003d62131fe46sf12971836wmq.5
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553522; cv=pass;
        d=google.com; s=arc-20160816;
        b=h2LFA696gK6eu+EMy+Z/E2temO2QWLwvfwfGq64YqoaZ4l/iIyVMO8yqBALOM/eYzD
         MmxBqBcGIXSDPG/KgsE0K4q7nEdsMJva7BvSYbUjtbnj2C/ROCzbZDnavsNv7wdAaiqC
         s2Z+Nd58VHFQhAL6gpx4MErl9pDyKMnbLMw5WehRoK96w676sdzjLOUW+432bGjA8dIT
         wkQllw34XehmnT4td1zxudnlgTQ3BM0U6I3gs4rOqlGSg8duJNDUatB31+GA+iaDlwVP
         w7cGug6JUxaYaA0Oo1Rx8777YKpdRoU3z6lrF/6UabfzvU85p1TCcRi+cCpzBy3blp3l
         Xtow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=4zvzjYe04ti01R95BFS/vRE9h2louVs7kVCjmom9GoY=;
        b=Hcshn/6UftlOGftCV7YgnoFlm/HNkxb9lAwR1nMUa0u+fJy2aVKXM7tZRkqEbiYh4Q
         okcPfPzC0yhfWl1FqePwoEdCZCzgTHyrz0vfsXQ9qjmdmVGrN1Aj6pPo4b/p3wiOJlrU
         Sii5JPdGgyder4o1tfPx6bs3JGWsStxzPxyW/DoaEK13HhZdsaAhAhqUoYQhvGzzQ+NH
         8aatoiDSVVzdh8ixD9Z8Bv9Sj26F0XSnd4D2XBeefgNDO08jMylxRBH/B0xLvkEvIY4X
         ca8NqR/xVgsyCCsNI6HF3fU8Tzhy/KvfWlDTukUe/F+xdxeNQQl5SUrLuOOlhNLr/XDj
         0bhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=EbqGBmO2;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4zvzjYe04ti01R95BFS/vRE9h2louVs7kVCjmom9GoY=;
        b=mjMauGWTrlNb23kT5bgx8GyDinOpbXvIfccl4dkFKMiXy6j2LceO4rPCb+gYue+TWm
         /DalKxWNLAOJtS5bHt230qoALErNJY1yMrA2De/oKjX97wS/nPzy/tLlfYi2PPOrKcF7
         paNRf+pIJKrYmTdtG+scfH9lh2OLkvSx1QBIsnTc6GKvaOLjc17KxzkyYSvmgfgUoNsD
         e7lyO1YvPk4jCJY4AsXnyXHH7+lW+78kXOD6wIfNjy6yk2O2LputTNpZShOLWzkCctRF
         E7BJevRip3hP/wjeja+CqM6rcdQm7R+hB7YgfJkGSie4CUNHJaX98VYe7wsL5qw+Dkm5
         4dVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4zvzjYe04ti01R95BFS/vRE9h2louVs7kVCjmom9GoY=;
        b=BdCTI9fYawW6jzj4V9DnLOnehQqxYoPOZmxd0lu2pZjooqklTo1pUeidG5p5jMOaVe
         vnwd53qy+edLbq6jPwfHBlj3drEK7SuAEEy+RcG34Xu+OUxJHxKa53SbKNho04BomtVR
         WHgAv6DMfe2LtgmS6RSw+sLcYoAyXHuCpmgJhLcQJIwkS2e70fXRMkf10UjoCC1Z6Rbg
         XGp1x/hRPoY9YI9Op0FaNpUUg8TLiFpDPpklzAaPgYnRX8OMb0Kd6YreL7xNHjxxkCzo
         KpmXBRTkx2e4cR6H+D1OJISH7X25VHXW7p7DyMIrJ56oNV3Q2UCZtogtbPjZZueklKw0
         sCaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kobROxW2kY6B+LNDYMKGo8ifZhI+JS27ov+kxLEQUp+4RHIjsCf
	ILomNiGCnAlgqW3OWMD+ULQ=
X-Google-Smtp-Source: AMrXdXvuafK//r/2I/4Rknt65eQsp5wK6QN3CbF78SJqUXdogM+yknRLOeP86sjRT/4K/iATJ65eIQ==
X-Received: by 2002:a5d:6b0a:0:b0:242:1534:7b57 with SMTP id v10-20020a5d6b0a000000b0024215347b57mr3119500wrw.404.1673553522474;
        Thu, 12 Jan 2023 11:58:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:17d8:b0:3c6:c1ff:1fd with SMTP id
 y24-20020a05600c17d800b003c6c1ff01fdls2949221wmo.2.-pod-canary-gmail; Thu, 12
 Jan 2023 11:58:41 -0800 (PST)
X-Received: by 2002:a05:600c:2844:b0:3da:4e:8dfe with SMTP id r4-20020a05600c284400b003da004e8dfemr7376182wmb.38.1673553521468;
        Thu, 12 Jan 2023 11:58:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553521; cv=none;
        d=google.com; s=arc-20160816;
        b=YJc3Jxz2tZzruUKOOHNGOyCK9P1OJcjuV+a7csHxsO/kM9X9zpaGewnpwBigauWs9E
         e+vKIX0QEUy6/+Sgs+PkXmRYI45WIGzp7y/0p3I8tgzfImLemvhw1ubU98pz8x1QQylE
         zNDwEJCeFQ4XgJpJIGVDJcGikbURsCcUUlyKCdY9a/AELh+Cj2iWzXACHV2VIdUW8SL2
         XemKSHWT+28S5gagPZg0cmuAUksa+j7WdLIjniNacZ6SIARUHO7GsL+KVFkAlI/D6Tkx
         XGsGJH78do8UbkkaamhiBw3vtGnI5jw+u/XqoktLJWnzwRfnFLjXP6nxJo4c24C/zII2
         YZ5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=OSWUMoytbsEQ8xUnxginHGtpoSP0fDdQQe/5yHesCdA=;
        b=QGk9xzeisy7I+fPJ+AKyKcqsW0Ek9guL11Vwc5sRWAOVigmBDeKJCxRLl1D+MvpkMC
         0XdUrcIb+geelGef3MNtLevNhnnylmX9Miv8FZeYJERClfuD6hVgnmBQx9SWmBnT1DQR
         WgV2BOih0QKr6oi43c+usXZWG+sKnXWVqYKkUAf1iOFH6JwxgkVG+mRx9R9FeA4IqdMo
         xg/HjKR2JBZBuq6ColUfQ9kAAE31hFFmztDhely2/Thar7ocL2pYw/FgNc7kkLV/3w7T
         ElxCGuPvCC+4dJPZVCB8lQ7wwAtTqqU5X0yH/Kw5b1KoWvaAHVglRtqy1GUbTuYmvSUW
         4c9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=EbqGBmO2;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id p24-20020a7bcc98000000b003da01357361si350527wma.0.2023.01.12.11.58.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:41 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hD-0045oA-06;
	Thu, 12 Jan 2023 19:57:08 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 133F43033FC;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id B69572CCF1F52; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195539.946630819@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:24 +0100
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
Subject: [PATCH v3 10/51] cpuidle,armada: Push RCU-idle into driver
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=EbqGBmO2;
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
again before going idle is daft.

Notably the cpu_pm_*() calls implicitly re-enable RCU for a bit.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Frederic Weisbecker <frederic@kernel.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 drivers/cpuidle/cpuidle-mvebu-v7.c |    7 +++++++
 1 file changed, 7 insertions(+)

--- a/drivers/cpuidle/cpuidle-mvebu-v7.c
+++ b/drivers/cpuidle/cpuidle-mvebu-v7.c
@@ -36,7 +36,10 @@ static int mvebu_v7_enter_idle(struct cp
 	if (drv->states[index].flags & MVEBU_V7_FLAG_DEEP_IDLE)
 		deepidle = true;
 
+	ct_idle_enter();
 	ret = mvebu_v7_cpu_suspend(deepidle);
+	ct_idle_exit();
+
 	cpu_pm_exit();
 
 	if (ret)
@@ -49,6 +52,7 @@ static struct cpuidle_driver armadaxp_id
 	.name			= "armada_xp_idle",
 	.states[0]		= ARM_CPUIDLE_WFI_STATE,
 	.states[1]		= {
+		.flags			= CPUIDLE_FLAG_RCU_IDLE,
 		.enter			= mvebu_v7_enter_idle,
 		.exit_latency		= 100,
 		.power_usage		= 50,
@@ -57,6 +61,7 @@ static struct cpuidle_driver armadaxp_id
 		.desc			= "CPU power down",
 	},
 	.states[2]		= {
+		.flags			= CPUIDLE_FLAG_RCU_IDLE,
 		.enter			= mvebu_v7_enter_idle,
 		.exit_latency		= 1000,
 		.power_usage		= 5,
@@ -72,6 +77,7 @@ static struct cpuidle_driver armada370_i
 	.name			= "armada_370_idle",
 	.states[0]		= ARM_CPUIDLE_WFI_STATE,
 	.states[1]		= {
+		.flags			= CPUIDLE_FLAG_RCU_IDLE,
 		.enter			= mvebu_v7_enter_idle,
 		.exit_latency		= 100,
 		.power_usage		= 5,
@@ -87,6 +93,7 @@ static struct cpuidle_driver armada38x_i
 	.name			= "armada_38x_idle",
 	.states[0]		= ARM_CPUIDLE_WFI_STATE,
 	.states[1]		= {
+		.flags			= CPUIDLE_FLAG_RCU_IDLE,
 		.enter			= mvebu_v7_enter_idle,
 		.exit_latency		= 10,
 		.power_usage		= 5,


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195539.946630819%40infradead.org.
