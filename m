Return-Path: <kasan-dev+bncBDBK55H2UQKRBL4DUGMQMGQERQV6FBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id A6A615BC651
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:20 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id p4-20020ac24ec4000000b00497accc4516sf9591276lfr.8
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582640; cv=pass;
        d=google.com; s=arc-20160816;
        b=JxVBqzy8NtdXzXKBL3zKJz+Q3SdPQiMWb/EaXMOu+JBJN4j93GDPOnPHXUOHzLUM5h
         Ku26eG8OujK7MZc79FvpFqkXFEDstnGCu8khMW7pmMrk0m6Prfq4wL1FtOVIv5fXJ2xW
         VSj5xY222p4uI3ZMNEQAHD6Wx7J6070cbJpL7p9mfhh3yCb/FH3wCHFI7lBX+2BYA/fm
         5GkGoTpp+gE3eUvApo6FqtBqjV4Czx4GF/ByDWI8Fx2MpKXw+/SHxqTccjCRsBQeNdyC
         Zox+Fe3Lq8uMXagwvxOIN9QnCmLiy7LZ7dgP33KykN7DQKAmmRHT5ouWN4tC64el1q2+
         CUsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=VeUv/kIz7CbRvyYW0lsIiO92bwrZ9fzzmxgW8zWNe3Q=;
        b=um2sSLIAP21vhSagjwiXzKIhWvxW11vjkJYEERAcuYh189Fw3ke2GHOZXhxKOtUlmJ
         lI598vNyppoLsJMcv3ZGjNz2il87VwXqjsXnYOJToadeZzxbFbm7muEOLnEAwZNQIcmq
         7AmuCu0CUPOz4ceU5KNJWzrRKjBG+nA9xPk7igwBt72tjz0hUWhwNg5FYNdXqVGso9+L
         t/qV2wPbS7CBLd1uzU+rQh8Itz2KEwavYE+kELBZp9jAMpXS9rUpCpEJZB4MJLeZr26g
         FswJ92/qxGfvw39uM2ifstuxvq+zh4YOGmhvFPWUaw7L11lVfKLJdrYEosPr72/yiIok
         A7tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=lSdnlbtO;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=VeUv/kIz7CbRvyYW0lsIiO92bwrZ9fzzmxgW8zWNe3Q=;
        b=FP8Xe3AHu/S5coB+0M463/J0rnfYOsZTQzCNdyI9NjJipi2VnTi+Vof/qD85HaUAvs
         U9jB2QQ1POxP+orGY2MNi5CisOWyCQ0DLNzBdvNRy4449hZh+qvmkBuqTBkBaN0fJJ5Z
         q1kXvnLX7izbuKGF75QUhCgAHPX9+3KK55wai7+2OhRVHDz3VjPNcwdwrh1nMmUKaHhX
         B7Ygo//t3KNhoBcqcZubf2IneKDj10zVlLseNHsUJS3OPxBpurdGm2pnDTTD0qEhnel7
         170LWEfI7/SpSk4cHvhdIy61HjWKKD4FCPkQMMno4AC6Kh/hqn0KOUslP9RKxKNAXcpT
         fE5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=VeUv/kIz7CbRvyYW0lsIiO92bwrZ9fzzmxgW8zWNe3Q=;
        b=sE09OeQHxrQ/knACFBF8VI37HZ8v/4/6fRNqoLm2FpLyXVIxkCdNWZXhozZTIzJMux
         TMgOJXSKwnNxX1CugF1OvTP/IKqpPt+9ZrItBbMTIIyRJYQXaue8/uNoeJsm22T482c2
         bv+f4BefbzjgCyY/q2B2/JKDGz+b+QwtrQ3vCpCI9hs7/thnef+5XrMtc/nAjR8SE+dq
         iWLCGMjrCmuUWqWmbWrljR66J5WA46uPPUD2Le8OaCyPxwoSsD7zBvP/uPmLUwQayNqX
         Zew9D3YUdPDWr3EWaqjgfpecubfqCPS0sqTNocy6YBhqp2/sX03kXWtMhHh9klTffyQq
         8GHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1IGtgTryJBWDKqHTkNcjZgj3DVd2guX58/A5Ge1lLq9acH3Q4R
	2hdb34nHwXQoAlMIyDEG1QQ=
X-Google-Smtp-Source: AMsMyM4UiwyX6UX5CXZ49PFl29epAdYKDG/Llx1fMp05+dkPH6UNYXSk//hwXwbE9jlVVqnZvKK1Uw==
X-Received: by 2002:a05:6512:3e29:b0:499:f64a:fa21 with SMTP id i41-20020a0565123e2900b00499f64afa21mr6335303lfv.194.1663582639828;
        Mon, 19 Sep 2022 03:17:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bf1b:0:b0:26c:556a:bf64 with SMTP id c27-20020a2ebf1b000000b0026c556abf64ls108172ljr.7.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:17:18 -0700 (PDT)
X-Received: by 2002:a2e:a785:0:b0:26c:560f:9f6c with SMTP id c5-20020a2ea785000000b0026c560f9f6cmr133214ljf.317.1663582638347;
        Mon, 19 Sep 2022 03:17:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582638; cv=none;
        d=google.com; s=arc-20160816;
        b=QwBYTBBTS9Ehk86mSS0ort0qeXOrU/jxWBn7WD9fmslyl5Ze4sIC73iwbKT5BsjoCh
         rM0RFqSe6MdxtRwrsedG2ja7RhSwyDB9AtwJQHm7oRVvbA4rqZSs7uFUMUREyodeQaqH
         CEvSd7wloLoIw9VNA2OJ9cjJqfH+o0cjW+zrz2hfOYupMGWmm9zjrlsPQuaL/jdQIUiv
         +M6674BbQX3Xm1V4jRoV21IfPE928V7Ln7zhzpK9XVuR7Lj9O+BuIBsppMp0+VohrBvq
         9VSXq4Db9vb+Yb50VKlKMZE+vHHfeAQuZ5q3tzpaveSt7ul2+h6JD3tvkkRUJmxjiVkq
         YVFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=AyMXeQVwfx1/nJp54JFML2b8hK1EwA5OkmJOsxIO+uo=;
        b=Wqr2kehmkGczZUh7tFHFkSLHb9TrPnJB9mKO5jFlAbVs4/ey0Rubtq1+wXQDpJBodj
         Pvg7l3gDxEfIU0wfOxIfh3pQjNrSwFwUPVS8UYuORC8fNqW8ug3lkHTnPuSWXqrACUar
         j0AYttD6eFsTa6PXnaWiJt96H25805DjKlzArsREhwlmFZnDuptZbEdH/LkH4XxeZbCy
         zr7qE+xXgRP9gGVgLOodLBqyh97LEHgXSbmRpz4YUVCHmvyQJA9RYiATTA0C+MA65oE7
         NHqY1IwfW5clBT2JnymS73KcurB8TTsPegNKm20SC7DPT2PnR6FWTtf0fwwMwqOrC8Vj
         dLHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=lSdnlbtO;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id e3-20020a05651c150300b0026c2cb5925esi340158ljf.5.2022.09.19.03.17.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:17 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDpG-004aiA-Uw; Mon, 19 Sep 2022 10:16:31 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id AD88B302D57;
	Mon, 19 Sep 2022 12:16:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id DCCE82BA4903B; Mon, 19 Sep 2022 12:16:21 +0200 (CEST)
Message-ID: <20220919101520.736563806@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:45 +0200
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
Subject: [PATCH v2 06/44] cpuidle,tegra: Push RCU-idle into driver
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=lSdnlbtO;
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
 drivers/cpuidle/cpuidle-tegra.c |   21 ++++++++++++++++-----
 1 file changed, 16 insertions(+), 5 deletions(-)

--- a/drivers/cpuidle/cpuidle-tegra.c
+++ b/drivers/cpuidle/cpuidle-tegra.c
@@ -180,9 +180,11 @@ static int tegra_cpuidle_state_enter(str
 	}
 
 	local_fiq_disable();
-	RCU_NONIDLE(tegra_pm_set_cpu_in_lp2());
+	tegra_pm_set_cpu_in_lp2();
 	cpu_pm_enter();
 
+	ct_idle_enter();
+
 	switch (index) {
 	case TEGRA_C7:
 		err = tegra_cpuidle_c7_enter();
@@ -197,8 +199,10 @@ static int tegra_cpuidle_state_enter(str
 		break;
 	}
 
+	ct_idle_exit();
+
 	cpu_pm_exit();
-	RCU_NONIDLE(tegra_pm_clear_cpu_in_lp2());
+	tegra_pm_clear_cpu_in_lp2();
 	local_fiq_enable();
 
 	return err ?: index;
@@ -226,6 +230,7 @@ static int tegra_cpuidle_enter(struct cp
 			       struct cpuidle_driver *drv,
 			       int index)
 {
+	bool do_rcu = drv->states[index].flags & CPUIDLE_FLAG_RCU_IDLE;
 	unsigned int cpu = cpu_logical_map(dev->cpu);
 	int ret;
 
@@ -233,9 +238,13 @@ static int tegra_cpuidle_enter(struct cp
 	if (dev->states_usage[index].disable)
 		return -1;
 
-	if (index == TEGRA_C1)
+	if (index == TEGRA_C1) {
+		if (do_rcu)
+			ct_idle_enter();
 		ret = arm_cpuidle_simple_enter(dev, drv, index);
-	else
+		if (do_rcu)
+			ct_idle_exit();
+	} else
 		ret = tegra_cpuidle_state_enter(dev, index, cpu);
 
 	if (ret < 0) {
@@ -285,7 +294,8 @@ static struct cpuidle_driver tegra_idle_
 			.exit_latency		= 2000,
 			.target_residency	= 2200,
 			.power_usage		= 100,
-			.flags			= CPUIDLE_FLAG_TIMER_STOP,
+			.flags			= CPUIDLE_FLAG_TIMER_STOP |
+						  CPUIDLE_FLAG_RCU_IDLE,
 			.name			= "C7",
 			.desc			= "CPU core powered off",
 		},
@@ -295,6 +305,7 @@ static struct cpuidle_driver tegra_idle_
 			.target_residency	= 10000,
 			.power_usage		= 0,
 			.flags			= CPUIDLE_FLAG_TIMER_STOP |
+						  CPUIDLE_FLAG_RCU_IDLE   |
 						  CPUIDLE_FLAG_COUPLED,
 			.name			= "CC6",
 			.desc			= "CPU cluster powered off",


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101520.736563806%40infradead.org.
