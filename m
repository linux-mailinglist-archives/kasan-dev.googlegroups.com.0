Return-Path: <kasan-dev+bncBDBK55H2UQKRB2EDUGMQMGQE744X3JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id F31575BC6FC
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:16 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id q16-20020a05651232b000b0049787a1b6b0sf9795096lfe.19
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582696; cv=pass;
        d=google.com; s=arc-20160816;
        b=bFDIe39A3+VYUxYS7PALxcVi1dqdl3cGlCJkqbk8/1Hjjo4YtzBcvPU/u1wO1WQ7MR
         olxqrN04bRmel1qTf3mkKQideYPiTiMMxgmJPHblqIBrt4kEvgfWG1iNKMBsbDUiFlL0
         kNS2N1+h8ePZ+rWtQ8IBtVMfbT8K//eNpUnWntUo3OdE23KQ6NZhSVjwZ8Cp+egO9yWt
         ZRmHpooxRwjpQVOCqqUJ0A1acWfdwf+lMeNzvEf8Q8hrRbEidVU75yUqrBPZHh7EC7U2
         jG5DEmG6xakFKbvvMzqYHs3vtWK8qYvR+A0ikdHijyUHf6kQ3wiwG8WFWdajKPUXbJpd
         VXdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=SEZOsIbZrXBpXN08DM8IpkIhqKpSpEWI1QxWN0aC/KU=;
        b=gZuMxfMgW3PKe80EQ+3cLiseeTNebd1eRbQTH1skt2Qe/A5jNA4sSpXTfynlVpl8PX
         TNjwXLGm2Gu6YrNfqfjj5ts7s92qagVORvmbGJYbFNmmD4X6b29fP6rOzu7qPQ8xZ0h6
         xfZKJ8VMBDc7bul3+p+NjhUd8mFKypKA0EeBv9n7Hj8o/sfKrgcZrd6tPVmLfwNi11Zc
         Xt7A66QrZm7UM76vodo/wm2KJonZB5XtQAbtyjihHEP0dfb6bkXnPcAySvf+LFb1vZZp
         R1IL2Xc7pp6QfWzpCQOYv+WD0sIQz63vhsABzcIpayiOE1yEBMo2fj7t8QquMnFwGBOg
         JEBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=jbOwzdvf;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=SEZOsIbZrXBpXN08DM8IpkIhqKpSpEWI1QxWN0aC/KU=;
        b=HF5VbInQSfZpTWlHtJyPacsbsZEtiWdFxoY1dsQ+fkyb9zGln6spcP1G30pC+kvyYt
         qqiF8kqz4PS8vMpNL8rYSekngFOtAm0WwFl+BRpOHaxAIARTRe7L/qeW/2HgP2ryCfPN
         pYUakrA2j/CobVSwpls4p8E9XvaJzgt5m12k4wv57T7fL7elxAtCCkNZCUAQ8+dAc5xu
         8btumjR3YNGFM+ZMhO/m8ZyR7te0foydVyREySbAmAHWAwdg6w4stV7iafJK/wNL/orp
         gm9lAe28OUGRIiBhczmiSF4BG5p2tXmKHVlyH88lVFP1qRx8DA/1d4G6CBXBjJ47TDdw
         o2EQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=SEZOsIbZrXBpXN08DM8IpkIhqKpSpEWI1QxWN0aC/KU=;
        b=aB9uWn+FQelQUwLsiI/CZaP4kBAWN3TggVgAzkp8XBrtjoI00JK6UmKkJySB4DSrIW
         2bUVeonIrVYbU+2E4RFP+NAZpEJM9K04dI2aVKZqdldCMNxl+aUJThmGthfMrFZpN9FI
         ez9WYjdTQSP53FJPNPNRxk8i+LatPf3M3zYmlyuyLqeipfZZy0KDyk6uJ+YP5Uc/6IZI
         ZZDuRPigz80cBdVPmjX0FcSSBIuM2dNI9+zmyzgJgE8qwqCUoIl0y88zn03SGYecJwVt
         w8jb+h6qRKBKmV528F9cj33GTYEIdCR54JSaQm4r8XOzs2f8VEVlbYq4TwAX5t20QmBa
         ZUaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1pvlm56HRmSiZExBzONLFihnI+cKVZn5mrJGh5dOcM0iea248s
	wEsPYCrt5G8YHvsg9uCL3gI=
X-Google-Smtp-Source: AMsMyM4ThlCaQuJw4TKhuym94io+TaM4ZuqBsrBeqUwDpNdp6EuI9szGlcZeHD1/B0CqWQko1MkQfQ==
X-Received: by 2002:a05:6512:22ce:b0:497:499e:c966 with SMTP id g14-20020a05651222ce00b00497499ec966mr5761004lfu.402.1663582696380;
        Mon, 19 Sep 2022 03:18:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0:b0:49b:8c05:71a5 with SMTP id
 v16-20020a05651203b000b0049b8c0571a5ls556804lfp.0.-pod-prod-gmail; Mon, 19
 Sep 2022 03:18:14 -0700 (PDT)
X-Received: by 2002:ac2:46f9:0:b0:498:f633:8136 with SMTP id q25-20020ac246f9000000b00498f6338136mr6398237lfo.117.1663582694690;
        Mon, 19 Sep 2022 03:18:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582694; cv=none;
        d=google.com; s=arc-20160816;
        b=P8IevUjaBx2NFv6ztcZSQWpSCL1xUcuNkJHyKt89fp9BhMzpARZk4Bd48XESnhaBdP
         igHt7amprL/8Ll+EPjAV+k3zTKB7FFvb9MUhN5RlFuGkkN94NbB7yLpjUz67PhD3Bw3a
         UKTKNsk2nq9KF4agNqjG60dlWfuBn5SB8Zpk7liJPytQob7D0YzUwpfEjzY42mVQObpP
         RjmSXBd1T1sAqKw8wy9JJfFphuxO81hvXTFe9cLxC4gEcpJ3N90KNge37VH1xyvBz81v
         LxRz2b0sRRX+/9Xl/QDdSEagPHtybxtpsbD8q/MKbI+gpQ7E9i9cWvKoRzkXYf8Q1fWs
         p9Cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=d1PXrA0ji5y7WX9aOTLSAuRcBGPwqyEk8vh/reRf4ZE=;
        b=TPnZLkPDR7M/wTu3Lw4Ce7WouNh8BeGwbtoCbimqt6jSsXa/24Kdqk4ePUEsRX706m
         zxe4eY0n+HHR1b1jmcObsH83dZXQXw61aAePPPD1H72V+XM5fQOGVp8qOR3hyu6nBL0p
         sMdnyEJGvh0e5I07MLCAJqsnRgiY9GZIOaXSzYJ9SL5OqMoClUu9qJXGmoGPyyUoegnG
         +ReT+py+aTCsp3XsL6hwtOA3VXFpZ3pSniJMe86Gnq135KvPbYZFcyTfrEMTOLXmLSRj
         uomVqEUiICjdUVeHmasWQlU0bqoU68NDJfy8voX18u4MUR0jDER8YUI+NlWDpK6ln9dx
         AIUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=jbOwzdvf;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id d15-20020a056512368f00b0048b38f379d7si768334lfs.0.2022.09.19.03.18.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:14 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq5-00E2BK-W7; Mon, 19 Sep 2022 10:17:22 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 639E8302F52;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 77FE22BAC75AE; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101522.573936213@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:12 +0200
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
Subject: [PATCH v2 33/44] ftrace: WARN on rcuidle
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=jbOwzdvf;
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

CONFIG_GENERIC_ENTRY disallows any and all tracing when RCU isn't
enabled.

XXX if s390 (the only other GENERIC_ENTRY user as of this writing)
isn't comfortable with this, we could switch to
HAVE_NOINSTR_VALIDATION which is x86_64 only atm.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 include/linux/tracepoint.h |   13 ++++++++++++-
 kernel/trace/trace.c       |    3 +++
 2 files changed, 15 insertions(+), 1 deletion(-)

--- a/include/linux/tracepoint.h
+++ b/include/linux/tracepoint.h
@@ -178,6 +178,16 @@ static inline struct tracepoint *tracepo
 #endif /* CONFIG_HAVE_STATIC_CALL */
 
 /*
+ * CONFIG_GENERIC_ENTRY archs are expected to have sanitized entry and idle
+ * code that disallow any/all tracing/instrumentation when RCU isn't watching.
+ */
+#ifdef CONFIG_GENERIC_ENTRY
+#define RCUIDLE_COND(rcuidle)	(rcuidle)
+#else
+#define RCUIDLE_COND(rcuidle)	(rcuidle && in_nmi())
+#endif
+
+/*
  * it_func[0] is never NULL because there is at least one element in the array
  * when the array itself is non NULL.
  */
@@ -189,7 +199,8 @@ static inline struct tracepoint *tracepo
 			return;						\
 									\
 		/* srcu can't be used from NMI */			\
-		WARN_ON_ONCE(rcuidle && in_nmi());			\
+		if (WARN_ON_ONCE(RCUIDLE_COND(rcuidle)))		\
+			return;						\
 									\
 		/* keep srcu and sched-rcu usage consistent */		\
 		preempt_disable_notrace();				\
--- a/kernel/trace/trace.c
+++ b/kernel/trace/trace.c
@@ -3104,6 +3104,9 @@ void __trace_stack(struct trace_array *t
 		return;
 	}
 
+	if (WARN_ON_ONCE(IS_ENABLED(CONFIG_GENERIC_ENTRY)))
+		return;
+
 	/*
 	 * When an NMI triggers, RCU is enabled via ct_nmi_enter(),
 	 * but if the above rcu_is_watching() failed, then the NMI


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101522.573936213%40infradead.org.
