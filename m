Return-Path: <kasan-dev+bncBDBK55H2UQKRBYMDUGMQMGQEDGHNIAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id A06CD5BC6DA
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:09 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id t12-20020adfa2cc000000b0022adcbb248bsf1409454wra.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582689; cv=pass;
        d=google.com; s=arc-20160816;
        b=ojpdMX1D4Ttc5DiEcHmELApTE2R66pBTzAAX+Oh3TJUwAe4FJq0DHUfnAZKE0i4h6/
         ceexXscAzr+Jm2cWH9pihyruYwX1fae3C7Pq4awHT59aQR16OQreOrpKeNt0VnmU0UGs
         kpMvSrdzq+9mCnL7y+sgS7t0fRM9oDaMKjYx5/anr6Mv1byrmOYMGoxx4I0n7+sLaCZj
         B5lh6/Li3Ia5vPKDqQSCU0vRWvO0HXXRmZTTMGvonM2v/Xzn8dPVy3hzt94Qi8AxT9nC
         vZq/jcKDU4wVGkXmQI1YJabpwHGqjlEcXXpckQ7lYq5XRrzaxuDv+V84KZGs75GDo/o4
         Nwow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=YSVEYChRP4FYJdm8FVa5sO6jAXlk4B7M2EO8nDTb2KM=;
        b=roQmVzaHSS3nd5Xf4aW+0yald0Vd0+boIIyaRabAjf1tj+dauFpkl5hAdM3YS0T90B
         rK3FbvY3/i8aVA18pUy8NNOy120XhKBcUgM+P8tSa2XYUhv9tAARbnzW6keJmS3dXi9n
         noQj8hFRFeT0Xt8kkgqe0psYnz/DpydyzifZ73mcQm63QDHMoqK4IppkPwFWXMQ8WLPk
         cw6A/HgktkxKpBXxHQAhVsA9WXmlMUkaPU+auNGnOLS1UUfzaW+BUIyJjPhF2JLFidqK
         3cDFnmfDukVoL0NIq/eGCKMYq5H/I5QXYaDLC/9ZN3WGJnqVAGyT8czbaAewPklP0ipX
         OKTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=F4ZzpLAL;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=YSVEYChRP4FYJdm8FVa5sO6jAXlk4B7M2EO8nDTb2KM=;
        b=kiUedUUnUZOVyw7O8VIMSft/BC7kJ7sTRSyoAn09HOAryJdqrBt5ofZ+QHu5D5O0Vj
         wreGC68JJJiQBwF4oKuAQjITXZFGs1iUfheA1vtcNp++cMETiVfdRpDOyNAv/oZgKdOV
         2VKnGVbfS5lSJjY+1v6dLYdNxQDf422K6b5cxLM1AfuU/HR8XTWb2T0G2q0prIOmeVnU
         YbnkF0t1TW0n6BQc95Rz7dqCUGCm2ubSC6MtrI3JGVjXKWx7zqr4dOKeg/wV9J/Drq0r
         uMyHrFk92fPgnriPQfEmhZYS6iwqF3ffIkrv8hTuGVBEv4+x4WtV2uT3agEnC0/UTk8l
         KBVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=YSVEYChRP4FYJdm8FVa5sO6jAXlk4B7M2EO8nDTb2KM=;
        b=gfw6M27/Egtqtsji2THiuaoznO8W8bG2Urt3OeY8SRXUvxR0htkQRDYAHejH0o8pTO
         dNWb08JHAZ57G6SSUebN32mW5/yF8l4GvPs8QffFFyB65lD52cXETWcKbEJyjBlmvryN
         UsZ2T8qhQffZaKSDVRD8jpSJEHDwoKcna+c7SDZ70950riukabM/IoSp8lNFyiZI9o2o
         dHtjqcevnHifTz3ZL3tU117AnQSfy9QjK19sT/Lgaj1ytufESsNXE4M1xgMEK57nmLtX
         HAmCAVkzYzhQ6wPNlC/YmFuYiTeVZU2Jx2dFkV7k1ywaKDIffN8UlfdVZHlbj0z68ZuT
         XPng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf34BGTLi4pmB0pgzj0C1TUmDwt2lHl/dMu0sTaXLtGYl2xnO1bQ
	2b0FJEM/EfsDSTyYasg9H68=
X-Google-Smtp-Source: AMsMyM6L9MeGQB16Ll0AF0i1tILKa/AH9WD2qkZ2FaTA7T1OjvGD/1WTfjp5bV78OaYlB3ggZNQt/Q==
X-Received: by 2002:a5d:5a9d:0:b0:225:2783:d6f1 with SMTP id bp29-20020a5d5a9d000000b002252783d6f1mr10495499wrb.385.1663582689366;
        Mon, 19 Sep 2022 03:18:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:695:b0:22b:e6:7bce with SMTP id bo21-20020a056000069500b0022b00e67bcels2883629wrb.1.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
X-Received: by 2002:a5d:64cd:0:b0:22a:ba05:8bcd with SMTP id f13-20020a5d64cd000000b0022aba058bcdmr10581562wri.74.1663582688305;
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582688; cv=none;
        d=google.com; s=arc-20160816;
        b=DRApMxV7TtsGbVBuJY58hwGxx9du6TK7e+ynR1Erwj2LTuuy5eFJf53UppPORWcY52
         MaFbSabxYCuNkcirCiY5lSgPLw9jdBDjmyUsHDCPhtLTutyUig8WmbxePKba1jQrnVNW
         R5WwGh6czhgKclmkmHd6sb4UnT1wCqFTrBYqcM0IS+Kw3R+HYesW4ThS33hD7SC1l78V
         mi3NODEJcMGasnMDAwLDjLUIO6PREtV9e2b+O6BmgxoueLP/cn2cjmQCCsIJGPQEtcb5
         jes+GDV0M6yNcoQ44ufTO0njhXByrfOJjyuiOM/zgIDxTFrXVFS6s+Qpu8vookjGFW6h
         shLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=vB057xACRVSJThllhGE8f2SmJ9TT+oL90mm46lxduII=;
        b=qAT+dzOvtizF5APM0r79TXf++kIkCBJhzFy37cP/AnKjm4qBPX7ICoAlGAkKk4FCG6
         f7FXWUtSm2W8cftxkAfmY1atoUXT/00QsdzB6oZ4hJkPn5HLLHNOleSXB0jrtg02z0NB
         BLkIw3nIDoqROgTPbktTywy6aZPVGWFzj8O6u4pofJdZNUppuIePOBgJqBO778zaZbiL
         a9u/9VgD2kSW7FqAjBkvE/13RDYkpXJxwvM+kMgVyZ2q0e/WGFFvz1pK/S0ZJL4vpYOT
         xzVXhlIJHsXheN+ml4iB5eoi5rqVO7k0edhQb8fZ8ki9ljmrv/SYZeSIvfGq1NUQwO03
         asPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=F4ZzpLAL;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id n24-20020a7bcbd8000000b003b4924f599bsi351462wmi.2.2022.09.19.03.18.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDpF-00E292-A2; Mon, 19 Sep 2022 10:17:17 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id E287E302ECC;
	Mon, 19 Sep 2022 12:16:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 0FB662BA49045; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101521.274051658@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:53 +0200
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
Subject: [PATCH v2 14/44] cpuidle,cpu_pm: Remove RCU fiddling from cpu_pm_{enter,exit}()
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=F4ZzpLAL;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

All callers should still have RCU enabled.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Mark Rutland <mark.rutland@arm.com>
---
 kernel/cpu_pm.c |    9 ---------
 1 file changed, 9 deletions(-)

--- a/kernel/cpu_pm.c
+++ b/kernel/cpu_pm.c
@@ -30,16 +30,9 @@ static int cpu_pm_notify(enum cpu_pm_eve
 {
 	int ret;
 
-	/*
-	 * This introduces a RCU read critical section, which could be
-	 * disfunctional in cpu idle. Copy RCU_NONIDLE code to let RCU know
-	 * this.
-	 */
-	ct_irq_enter_irqson();
 	rcu_read_lock();
 	ret = raw_notifier_call_chain(&cpu_pm_notifier.chain, event, NULL);
 	rcu_read_unlock();
-	ct_irq_exit_irqson();
 
 	return notifier_to_errno(ret);
 }
@@ -49,11 +42,9 @@ static int cpu_pm_notify_robust(enum cpu
 	unsigned long flags;
 	int ret;
 
-	ct_irq_enter_irqson();
 	raw_spin_lock_irqsave(&cpu_pm_notifier.lock, flags);
 	ret = raw_notifier_call_chain_robust(&cpu_pm_notifier.chain, event_up, event_down, NULL);
 	raw_spin_unlock_irqrestore(&cpu_pm_notifier.lock, flags);
-	ct_irq_exit_irqson();
 
 	return notifier_to_errno(ret);
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101521.274051658%40infradead.org.
