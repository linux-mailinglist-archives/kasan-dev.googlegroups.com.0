Return-Path: <kasan-dev+bncBDBK55H2UQKRB3OMQGPAMGQEUOPKHTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id B2A1B668003
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:37 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id i7-20020a05600c354700b003d62131fe46sf12971701wmq.5
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553517; cv=pass;
        d=google.com; s=arc-20160816;
        b=khWf1JxOC0DTGYUWzTCmmvjPaCKHIJhRkloXWxh1Rx7cv5gwjUgF16M70Ajq7H8sMz
         nvpAHuXNiOATyk9ZvgKtutKf8WQL4tsa5IyE+ZP3FTdlODv5E9bfDvBweM+Y5Zv5rErg
         9MwJUikG+Wz9IKUtvcJQZhhTA+48jTTiGXWTLyiIQTUG3AFMWIuXq9H9DnExSPBgVMWc
         7oTinWudQK3J3TZn/QE07STtny8b3vI7gBlziNN3wQA0JO0G6W3tKDYc5ISIYfkkDO3L
         TnvjmfCck91MiVHP1MmmUdUGqjV2efQGUyFMAXiLLQ6f8NoLeN5f4QASes5GN/uL1FHz
         bL0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=+mB/pTCKN1lHzqDUYX/sVkDZJBSnC3awPCHPJGcZCTo=;
        b=GB+dP7GOZKLissup2LoyPG76ZXch4hUj42+3iNnv88LldRwSyEmF34mFPESWpI7T2N
         Du4yemQhsV1dAda9MQy0+gXc9YbqIyPhc6f5mdtpMcXEYpPgXG2m0Al3nQ7uuqs/QoUH
         PYyxT+MfQs5V3s/oBVVUB3ZMaUN5zkaRSk03Edm4w5VUA5+lvEMyl6OZIw6uDb9W9kqV
         p/liwFwEU+D1gyxe7rC/CdKHFfkgZz1mdmQvoJ9TkvkMZ8O4pvo/ug5VrJ76W3PZlkwd
         DHyoB0aJ4L3Wj4IOXbqgOPraDzarLR8qY0+My2Fbw2VyA9EYvVIq7CqB4oHMFLE1vmr6
         0CwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=j8TQ8t09;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+mB/pTCKN1lHzqDUYX/sVkDZJBSnC3awPCHPJGcZCTo=;
        b=eE7AwmkwXDlaNeda/DAbQAhu9dR9Zd5/iCFc2Jnx+wjSVbx5COdz7LfvCYqpxIqKt7
         xfEROjspNh8yUtwawwNeAGscEcAaqgHaUGcaQ4DfPWACbuoCIy4a+U2LhSw8ZyzTlRkF
         HCn/vQ9UsDx9K8qVMmU0ucRe9xRa7UMRtR6ZK59p85Zr3XD/y3/WFMRhDbE+UJhjZ8C0
         Yz5Obzl/gIWGsSP0sqRa0gQRIkVRl5NVelxiET8LYtz+biLlLi/yll5rO+TszhWQkAgb
         4QviaXQOvHzFc+46JG7NSxQlAbky4zn73cdYvbOyhLtBqaraW+TKeGieFBsCB2g4uz0f
         g/1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+mB/pTCKN1lHzqDUYX/sVkDZJBSnC3awPCHPJGcZCTo=;
        b=i6wGxUY+ndcUdZu80gLtMoV+HYP75cIvfTLoZwifJBdWsXQTBc/kljoaoNaCL5isdY
         f9wk7EjUFK4zTzowh+Io+GgMu/RUOxw6vwmzVi7yw0HqnN5AUDysqj3QtOJOR0OkySip
         OH8cCERUgdUxEGTBQq16PXHQuQDCkBB9iS+H7jB42gs4jqXP9JKXP2XKr1Nqs6WMcNro
         zTDl7P/86gKy1Xty0zBJq3bbBjVW5y2hjotViRwb5AO3hwLisg4VXCeHszBjQJYcgWpc
         Ht2e8a4HQ0oBu3ggHkjlXxkRqFlnpIbXKufTjcE39u5ddvrMbL9y55ZKmrKTrt2+yOw5
         6G3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kq0D51fnZ11VY7t0irWG3v+Akpyxn/VeRDQCFstNdBVMdMJJEeq
	E+15/JfTo9R0g0qTOpFNqvM=
X-Google-Smtp-Source: AMrXdXtq4QSnpv9osVS7v79l/t+F39HXvdtvhSVbsDsFAnw3B7WxDAFS8L2ecxwTiQfYvbO7qumO9g==
X-Received: by 2002:a5d:5d11:0:b0:242:14bb:439e with SMTP id ch17-20020a5d5d11000000b0024214bb439emr3025721wrb.191.1673553517398;
        Thu, 12 Jan 2023 11:58:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d93:b0:3cf:9be3:73dd with SMTP id
 p19-20020a05600c1d9300b003cf9be373ddls2939680wms.3.-pod-canary-gmail; Thu, 12
 Jan 2023 11:58:36 -0800 (PST)
X-Received: by 2002:a7b:c8ca:0:b0:3cf:728e:c224 with SMTP id f10-20020a7bc8ca000000b003cf728ec224mr57211629wml.6.1673553516268;
        Thu, 12 Jan 2023 11:58:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553516; cv=none;
        d=google.com; s=arc-20160816;
        b=YRdV3KBmoqu1FV0Wr4om8U4dBQM/UpQpy1haWk6N0b6D95Rc210PUzqOdML7Hnv67n
         TFBuL0HVLwoQlggCd+5R7XLU5scOHvXi8i+DCZ7a4iaZzgtkIw8bBHsitFOztKAx7iTA
         Zox4ETM+6CSgk19ltKwPC9Rm9x+cURI+xqgHmsxj6PCJ5aQYhA1bWmZgEEkfooObqcAr
         dvOU4Az2NQ0G9SX26qJYg2VmRNHszqXWL7yRV8tkdCYvxGVedONOQU0qqzCAxtbdWOxr
         Xiy4bscafqbF5hbsiSeVsGtdtPC+zzCiEDLwXDt6jWJINjVXondzVY4wGWocD0c1guwe
         Vvjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=dY+sZF8zXVTImEusizdFam+mvD2uBaZ1sCttd0zpvx8=;
        b=D4GuGlzsMgwIAjx/LJySzItLo6yuLCAf2a3AyBBotk0oxCacDGdec2T9kE/A8n6DtG
         OSx6bzf8e5V7sz9roZoGpecEXDA2eFJEoy/Kfh9Xk3kLLUt9Cxl2WrMita9Fi5UOCYrP
         WW3BmwOMximrLrd9CIO/NVgYujuJYTu1Tr4AVu3STZEupGWtG3g4J0ifB0g2U6ND4M9+
         gSuTzWUpYQymZ72hDz63R0jj6Ee6u0M9E3Q1LXKD8ifUIh7fSfpjedNPTWnBqKUPuZvz
         W1OMa6HlLNbjY7t/f56qySrc9g0+suXLRbywh28Y8tFMvRl3wsfwXAszOg0fUzR6uLml
         sjbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=j8TQ8t09;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id v6-20020a1cf706000000b003d9ae6cfd2esi918078wmh.2.2023.01.12.11.58.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:36 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3he-005Ofx-0r; Thu, 12 Jan 2023 19:57:34 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id CAAF0303455;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 3A2002CCF62BF; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195541.477416709@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:49 +0100
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
 kasan-dev@googlegroups.com
Subject: [PATCH v3 35/51] trace,hardirq: No moar _rcuidle() tracing
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=j8TQ8t09;
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

Robot reported that trace_hardirqs_{on,off}() tickle the forbidden
_rcuidle() tracepoint through local_irq_{en,dis}able().

For 'sane' configs, these calls will only happen with RCU enabled and
as such can use the regular tracepoint. This also means it's possible
to trace them from NMI context again.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 kernel/trace/trace_preemptirq.c |   21 +++++++++++++--------
 1 file changed, 13 insertions(+), 8 deletions(-)

--- a/kernel/trace/trace_preemptirq.c
+++ b/kernel/trace/trace_preemptirq.c
@@ -20,6 +20,15 @@
 static DEFINE_PER_CPU(int, tracing_irq_cpu);
 
 /*
+ * ...
+ */
+#ifdef CONFIG_ARCH_WANTS_NO_INSTR
+#define trace(point)	trace_##point
+#else
+#define trace(point)	if (!in_nmi()) trace_##point##_rcuidle
+#endif
+
+/*
  * Like trace_hardirqs_on() but without the lockdep invocation. This is
  * used in the low level entry code where the ordering vs. RCU is important
  * and lockdep uses a staged approach which splits the lockdep hardirq
@@ -28,8 +37,7 @@ static DEFINE_PER_CPU(int, tracing_irq_c
 void trace_hardirqs_on_prepare(void)
 {
 	if (this_cpu_read(tracing_irq_cpu)) {
-		if (!in_nmi())
-			trace_irq_enable(CALLER_ADDR0, CALLER_ADDR1);
+		trace(irq_enable)(CALLER_ADDR0, CALLER_ADDR1);
 		tracer_hardirqs_on(CALLER_ADDR0, CALLER_ADDR1);
 		this_cpu_write(tracing_irq_cpu, 0);
 	}
@@ -40,8 +48,7 @@ NOKPROBE_SYMBOL(trace_hardirqs_on_prepar
 void trace_hardirqs_on(void)
 {
 	if (this_cpu_read(tracing_irq_cpu)) {
-		if (!in_nmi())
-			trace_irq_enable_rcuidle(CALLER_ADDR0, CALLER_ADDR1);
+		trace(irq_enable)(CALLER_ADDR0, CALLER_ADDR1);
 		tracer_hardirqs_on(CALLER_ADDR0, CALLER_ADDR1);
 		this_cpu_write(tracing_irq_cpu, 0);
 	}
@@ -63,8 +70,7 @@ void trace_hardirqs_off_finish(void)
 	if (!this_cpu_read(tracing_irq_cpu)) {
 		this_cpu_write(tracing_irq_cpu, 1);
 		tracer_hardirqs_off(CALLER_ADDR0, CALLER_ADDR1);
-		if (!in_nmi())
-			trace_irq_disable(CALLER_ADDR0, CALLER_ADDR1);
+		trace(irq_disable)(CALLER_ADDR0, CALLER_ADDR1);
 	}
 
 }
@@ -78,8 +84,7 @@ void trace_hardirqs_off(void)
 	if (!this_cpu_read(tracing_irq_cpu)) {
 		this_cpu_write(tracing_irq_cpu, 1);
 		tracer_hardirqs_off(CALLER_ADDR0, CALLER_ADDR1);
-		if (!in_nmi())
-			trace_irq_disable_rcuidle(CALLER_ADDR0, CALLER_ADDR1);
+		trace(irq_disable)(CALLER_ADDR0, CALLER_ADDR1);
 	}
 }
 EXPORT_SYMBOL(trace_hardirqs_off);


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195541.477416709%40infradead.org.
