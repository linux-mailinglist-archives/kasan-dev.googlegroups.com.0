Return-Path: <kasan-dev+bncBDBK55H2UQKRBOEDUGMQMGQEPAMMYLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id D43FB5BC671
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:28 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id i129-20020a1c3b87000000b003b33e6160bdsf4447039wma.7
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582648; cv=pass;
        d=google.com; s=arc-20160816;
        b=uRaun17G5PV65omzssn362QrJgDpOWuDSsW+S6DZKZBlu+4CVp8ICK4m23uDTbqjBH
         gQKjyd5VwPdP1qNPcxn7W5wGLUgztT2YoW46ggs0fBMp18HHJNWru9MM78t9G0AH8wzp
         2R3Y4+m3yr380iFgkWzo46MbZ07rmsD+R2EVYDS7EU81t5uLxeNY/yhjB5fHJDJ0Ijz8
         BuQlLDsTItaK46c/R5w+/rY0tTRMw8vclh92JVlH2Z2KrBzYiCPdRBLOV/OlFV8g4Yh0
         6Xx/u3ZDFSKInMoBmv+5uoCw77wOtDJ7OVapfu79GX+pHipnuBIiWSiU4L3S3ZT819EP
         qAhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=0hUR8FVJK0x+NzR8iBNbU9733BFKdA4dqMSaJx6KK8o=;
        b=r+MCOLQUiVUc5mV3ViIdCSNVSqcmf8Q9JjDEsILUGYSjYqqy9WMpJ5zWXoI1adYqTm
         aBOSo/+bQUSl4u6efaVgovhURkqbaTM1Z396AhdRgDqPOLjWOjBJ/MAoprMDJidDkZMQ
         g1NTAmGUauncyAhCVextqAZEWOx+/zXwL8FLJ5WGsOlYA5l2b0JwAxoe9osx75+TttgE
         4dsuNj+HZi6/nixpPHeighAk2yQPeBbonSfFGSm3kCLGHzePRU0gXvKdX//Mnl4ef9WG
         4HwBJn+2AooxjH7aK0sR+G3LQAkDbBJSJCX70PBYBHsljZRczUmqXzoxcOqr4NXZzI3b
         iTWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=A9Y5adyu;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=0hUR8FVJK0x+NzR8iBNbU9733BFKdA4dqMSaJx6KK8o=;
        b=WntEpFNFvCcgn350wYcEolSJfle2okHFccILH6PIcvps43NJa9gJzfW5N218u2lQ1J
         WGHP/91zXMpKSLrRl/bdhAUhJC6UE8bkBMc3JZ9EseyZxBZtTfv0nPZiVQegNdkmpZ+e
         V1//e3e+0DlvaLcHwmykTk4pf3vjR3KCOF8ooxJoY4MrlCkopO/Xw+al2mhRb/dfITVi
         PNIEi7GZCYnCwILSAmoNm7VZPFXtZANwXeP0Z+xDydfOD7gjOooqFqvVGzG/TGRIsKUQ
         zrsD0sHBduiCNjdwfNI2H0/uYLwN5ljsNBNtdc6zbarjXPXmTrR0RMxImVDZyLyb5iYJ
         pvDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=0hUR8FVJK0x+NzR8iBNbU9733BFKdA4dqMSaJx6KK8o=;
        b=nTGkgF3KWQpxXShRu6J/tE54n/8pS5vQOr/x+UkGA5UG5gmZMByF82/faXiftzvRPj
         3Qf94T3KzUpAvL5rcehTRpYB5mupOmOBTKf04GCGf5RO8gMHr+TRnJHAAvv1ELRKDok2
         jHbEQLzoNrnNFttl0MQGNnTdXh4wb7MGx6yRWrYA6UYLAUUtl3AD1yvQ/DeXhUr7i+s4
         jWFPMTjxW9qHdiFASL0jbMySztFfhBoFQppSQdM2kEmZfNnQzY1XU4p/7y/C4H4U4E+o
         vtqKpDLPem2rRYqXhgukmPhFIMstm8qzF/DqB/AQWDmkVkGxl4MPXi9Uk9tEaIAoyvKw
         pbBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf085Zl+/3oRFNd/J7r4T/BTUFS4Kk/ZoeazzoxSk50Hkpr/saNw
	zNDv1MlJSSTElsnJCXQvG98=
X-Google-Smtp-Source: AMsMyM5JZloEHOyKeFpkp2n5+iBtdhCnNo1EScdH+go8a6plwj8M+aLIFVxx3E2BT5EpQvfUXw5dxA==
X-Received: by 2002:a5d:64c4:0:b0:228:e143:ddb8 with SMTP id f4-20020a5d64c4000000b00228e143ddb8mr9920637wri.148.1663582648584;
        Mon, 19 Sep 2022 03:17:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:255:b0:228:a25b:134a with SMTP id
 m21-20020a056000025500b00228a25b134als7686505wrz.0.-pod-prod-gmail; Mon, 19
 Sep 2022 03:17:27 -0700 (PDT)
X-Received: by 2002:a5d:5110:0:b0:22b:214:38e4 with SMTP id s16-20020a5d5110000000b0022b021438e4mr1792888wrt.219.1663582647371;
        Mon, 19 Sep 2022 03:17:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582647; cv=none;
        d=google.com; s=arc-20160816;
        b=jmUcbEuro0ypZwYLCG5ag+zKAC+Mplgzpe+tBox/eOQXeTAX3Qvn+IC6UdNgITTIj5
         wK01E99O+V9Hw8VUamxRwXvCNe7A8/HK/GY5j/XWeeGUqkdCpwBzLvXAYOu57VrDQvQg
         1wH8oYeryMmDZpNa5ctG6JG6yzQSgdKtBV+IGab2n5gSp3WP3l7kQzP1iVZ2lQqPa+1x
         2n0ZAJxWesEwrRTyeiqB8Vg45cIm/9rE6qMfmOmubLd7negY5hZ1nnX5qU23aYPqlKh8
         y/bbG/pVyPbwX7t574I8ASLENYGZnULG6qOGM0X4bCClc1h22Wfo0neUOuWMZj8TNGm5
         B9HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=nefRY1zld6SB6gly/BgzrvcXEKwr/pOkUZl11QGpgL8=;
        b=EacyFM8qEmQaWXGqx8n7VAkJNV45rRHwlvvreaW40S9+9cE//GM5AjjS977OkbMK/j
         yW7sFx/GU/WH4m0hOaAA9EaxjbGZ7G2yXKU/wNFXv+KAzG+KIWAaQUktmt/ceBhMavnG
         z/V0l/Y8AWPye+nBa08dTCyQ0Xm4atpaIzPNPDC8rgM1BBjdDSC9j+hDhzh6dFVKJCyQ
         kGEJHvMTh6AQe7hGtIBrW8QvQS3aWhNlbAFdV0KkgbYDyLV4ubddn4wC/5/V9DCgDQ7T
         jpZ6r6Psk1PUpf18VpsoU5UI9qKTKjEB3SGH25eM/Ul0FCO4pyKKgjuS9pR1P6jnju8S
         qB3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=A9Y5adyu;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id q25-20020a056000137900b0022a450aa8a8si253832wrz.6.2022.09.19.03.17.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:27 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDpG-004ahx-Fi; Mon, 19 Sep 2022 10:16:30 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id B8FED302D92;
	Mon, 19 Sep 2022 12:16:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id E23492BA4903C; Mon, 19 Sep 2022 12:16:21 +0200 (CEST)
Message-ID: <20220919101520.802976773@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:46 +0200
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
Subject: [PATCH v2 07/44] cpuidle,psci: Push RCU-idle into driver
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=A9Y5adyu;
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
 drivers/cpuidle/cpuidle-psci.c |    9 +++++----
 1 file changed, 5 insertions(+), 4 deletions(-)

--- a/drivers/cpuidle/cpuidle-psci.c
+++ b/drivers/cpuidle/cpuidle-psci.c
@@ -69,12 +69,12 @@ static int __psci_enter_domain_idle_stat
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
 
 	state = psci_get_domain_state();
 	if (!state)
@@ -82,12 +82,12 @@ static int __psci_enter_domain_idle_stat
 
 	ret = psci_cpu_suspend_enter(state) ? -1 : idx;
 
-	ct_irq_enter_irqson();
+	ct_idle_exit();
+
 	if (s2idle)
 		dev_pm_genpd_resume(pd_dev);
 	else
 		pm_runtime_get_sync(pd_dev);
-	ct_irq_exit_irqson();
 
 	cpu_pm_exit();
 
@@ -240,6 +240,7 @@ static int psci_dt_cpu_init_topology(str
 	 * of a shared state for the domain, assumes the domain states are all
 	 * deeper states.
 	 */
+	drv->states[state_count - 1].flags |= CPUIDLE_FLAG_RCU_IDLE;
 	drv->states[state_count - 1].enter = psci_enter_domain_idle_state;
 	drv->states[state_count - 1].enter_s2idle = psci_enter_s2idle_domain_idle_state;
 	psci_cpuidle_use_cpuhp = true;


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101520.802976773%40infradead.org.
