Return-Path: <kasan-dev+bncBDBK55H2UQKRB36MQGPAMGQEA3JMCHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 024B666800B
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:40 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id bi18-20020a05600c3d9200b003d991844dbcsf12970151wmb.4
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553519; cv=pass;
        d=google.com; s=arc-20160816;
        b=v7QQh2D7DkamywCZxtMvW9zXZ8JtV28EQayl4txqkjrqScB9EvqguPaNtE/Ak2AcfQ
         fp/CHIVA69nf789p97sJor6voNZlPaUDRKuK30kdOURpTkil4M2QhUMTdH4MNtJPQpEX
         DnhLOb5OBwcVhsHNSZqhlwdRds5G2O7vlZWi4aM9nne19BGL5MIKbkcQMwyJZAmVa4cP
         4FNZUpR0FsFqU4bd0JzD/XMUGnWbSGBFhAF29mhon8xmaIYRYIQmXjENtvDFG+PzSJek
         Q5UfJuAe9t1IHufPD0gPBDNgjGWTvsewYXn0iu+UuPxT2YdU6R7oePdVyIwOSAvVccZ9
         4OWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=VQpAOm92j9D/Uk+vONJ+FDD4L046JW1cLdWiyM1wOW4=;
        b=oQqIlWKQI4HBxyp9gYGsp+3YGjEQPOeWhHJ6NfGOrFC/RHlTnzOT1E17OWV5IMPI5y
         QlxutPMo6IFZLMXbcvXIUGTPPRqPLvMDgHURnc6Jk7B9/0Ce+tlG7g4GrLHiD4VZlkPe
         pw/fRE85hbWpOXBm22DNDYVB1THE0XPBNg8BJLTuqyOZC88peN7vhhwsqiPzoBWtJRWI
         M2evItiYeUX+jUM/ArvBKXPBOoNj/YmX3j7hhMoPBG1LN2drGQ4HEjLrRmQlSSLjU3Jr
         ZSR7QuMJw/n4k4cpMlnpcntQBSQSYf2rbjJe0zokNAleEuKo1aRGTqSyzHFUqVCXMXiJ
         Kz5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=pR2azv2T;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VQpAOm92j9D/Uk+vONJ+FDD4L046JW1cLdWiyM1wOW4=;
        b=ZH64ZiCVR1Zoj+4eE1Dk5vQzF9isqPcoSoUTq48JtTe5GVRhgCTJscYUycE/q67/v5
         sosh6WkqzwfyX1D3J2QnhtSYQqq/vdtT6N29oEIwoOkMuedTfmoQN9I8TfFNI0fzaMoO
         2VCkysH3ZplQp024lhp7yMpwZQwR+GhW7EvUqlnF6LpzWbpPjPRDZOFSEI9irXpoNABR
         5E3r/e73o+5d2BQhls6HunFKin2TiHZrBcNYuT8B9EAx7/yZHKCZ2MzPUHY21Mcd9SXQ
         mtSl82ltY7Bpe0syxviW54YnwW3nQMgCSAtI+CuhppZbNVpESNb8t2OQzW7ipOLGiCNS
         wQ+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VQpAOm92j9D/Uk+vONJ+FDD4L046JW1cLdWiyM1wOW4=;
        b=VR94obgNBkU2TcwV6GWnInEysg4W88BbrbHyZdSloCShjWqohOM8iDnVSFDxOmFw0G
         zgbRJH2tBI+douQVB562WqHTKmbRpFpkgOC2IEqRzkXsLONbLO03bWq2stJCQqBkwL7B
         XLobNrnM2BPfaPEgYTTnZMvbiEhwucvSNpZ2nzLZJ7J3zQ7xC6kbXbZ7ZTU58XhOPF0d
         pgSNywF+UOLWFTUbNqcCDGsK3drM3y3MJh4MnCcYzBzP4bX/bqYY5RY9yzkHV5JzJPBv
         SRseRJyBx11ZxK07Zuww7fI3+80sIAtZvuj1hEb6qS5OnQRJNmkwBhooYVMyzNh9FdjD
         9STQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kp429zlkVtufcfO2noLNaPOL1k5yA6S41wkc32fmhrVn3dVvixA
	HDPt1oXKk5T9uVaFmKYTC88=
X-Google-Smtp-Source: AMrXdXsNi6vhMQ/POlizrIPEu23esXUm8TfZuMnivpsAQfEyT6yUO4ASGHLWXhlEGuQS/R61ag8cwA==
X-Received: by 2002:a5d:62ca:0:b0:2bd:bf71:f9c6 with SMTP id o10-20020a5d62ca000000b002bdbf71f9c6mr429575wrv.624.1673553519601;
        Thu, 12 Jan 2023 11:58:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:250:b0:269:604b:a0dd with SMTP id
 m16-20020a056000025000b00269604ba0ddls1474342wrz.0.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:38 -0800 (PST)
X-Received: by 2002:a5d:5b17:0:b0:26f:42c9:a224 with SMTP id bx23-20020a5d5b17000000b0026f42c9a224mr53738110wrb.63.1673553518548;
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553518; cv=none;
        d=google.com; s=arc-20160816;
        b=Xj+uXgP4IJkNOe9izkbj7+SwfYmG20GnsiTAf9Do4LkoB98X0gOJVZy0vfClrGnqaI
         8gaIKHda6UKqV4+lKm3eldv+A8p7aG7eNyWAFLvtX9ThW2IQ/SKmTz1JVdIa/zNucniD
         l9Q3ANWD0Voe4V94fkdmloBHRzpU1WqjmqysEyhlDN7LssXG66hJpAgYYKVrVeVUEWgz
         eJB9T4QvK8QWmppV9sYsX8506mshzP+B2C/JeUvRbY+CPTAwd69V9NpzMEyUoSO6BLGS
         Ft9UVSRV4ywAwkE73Psqq+qiKp/2jOm9xikMzJ6J6PC6jYcEdFoX1cM3gqAG8Cxixm8k
         GFoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=cMg3ptdf90ideilc5ESAExVXsDzvqUAUHPnoGLTznE4=;
        b=mARI4yZwDdpSXI89j/a1PJZWNyb7LLlLIKQt+KHyXDWsqIxi03F3vXBChIt/85fS3p
         +yFm9j9fvnLnU4jpIktA4LMzm7PXHn1blDA/ZIckQAgHk1uC5jqsgZveid72NrUy5a+7
         2wTZ6DDdXOajqQ0Viiu9HK8S2SZ7/fWJqTl4/zRi7rd14tGwzGkzqK3wCoyRqOkmkheP
         DtSCN8FdmZLnJO9nsmrpfhE8YvWBsEHJ94XGBjBJmEUwCQsDvZqMT4IaDfzR2zgn76iY
         9BvFWvfs2DEmTfd8UglDEMLg5Zf+fsTyRPnslBigk7oAW/TifVqujmSZRpWtp2TL4yBp
         ewEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=pR2azv2T;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id bw27-20020a0560001f9b00b0029c9b8d8aafsi689109wrb.6.2023.01.12.11.58.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:38 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hI-0045pO-1W;
	Thu, 12 Jan 2023 19:57:15 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id BD81830344F;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 31AC02CCF62BB; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195541.355283994@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:47 +0100
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
Subject: [PATCH v3 33/51] trace: Remove trace_hardirqs_{on,off}_caller()
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=pR2azv2T;
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

Per commit 56e62a737028 ("s390: convert to generic entry") the last
and only callers of trace_hardirqs_{on,off}_caller() went away, clean
up.

Cc: Sven Schnelle <svens@linux.ibm.com>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 kernel/trace/trace_preemptirq.c |   29 -----------------------------
 1 file changed, 29 deletions(-)

--- a/kernel/trace/trace_preemptirq.c
+++ b/kernel/trace/trace_preemptirq.c
@@ -84,35 +84,6 @@ void trace_hardirqs_off(void)
 }
 EXPORT_SYMBOL(trace_hardirqs_off);
 NOKPROBE_SYMBOL(trace_hardirqs_off);
-
-__visible void trace_hardirqs_on_caller(unsigned long caller_addr)
-{
-	if (this_cpu_read(tracing_irq_cpu)) {
-		if (!in_nmi())
-			trace_irq_enable_rcuidle(CALLER_ADDR0, caller_addr);
-		tracer_hardirqs_on(CALLER_ADDR0, caller_addr);
-		this_cpu_write(tracing_irq_cpu, 0);
-	}
-
-	lockdep_hardirqs_on_prepare();
-	lockdep_hardirqs_on(caller_addr);
-}
-EXPORT_SYMBOL(trace_hardirqs_on_caller);
-NOKPROBE_SYMBOL(trace_hardirqs_on_caller);
-
-__visible void trace_hardirqs_off_caller(unsigned long caller_addr)
-{
-	lockdep_hardirqs_off(caller_addr);
-
-	if (!this_cpu_read(tracing_irq_cpu)) {
-		this_cpu_write(tracing_irq_cpu, 1);
-		tracer_hardirqs_off(CALLER_ADDR0, caller_addr);
-		if (!in_nmi())
-			trace_irq_disable_rcuidle(CALLER_ADDR0, caller_addr);
-	}
-}
-EXPORT_SYMBOL(trace_hardirqs_off_caller);
-NOKPROBE_SYMBOL(trace_hardirqs_off_caller);
 #endif /* CONFIG_TRACE_IRQFLAGS */
 
 #ifdef CONFIG_TRACE_PREEMPT_TOGGLE


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195541.355283994%40infradead.org.
