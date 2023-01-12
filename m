Return-Path: <kasan-dev+bncBDBK55H2UQKRB2WMQGPAMGQE5YWVWIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C68E667FEF
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:35 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id bp18-20020a056512159200b004b59c4fb76bsf7284225lfb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553515; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uhpv+F0/Hci0IRV4b3oFBG386tS/XY1XkkFciBITQ4mYVTrIanHquU8gK5iBIpJFl0
         htM5gymjgskYnT0QzzmDrra4qdIOMBMOoEDn2RQgLVN4jETLVLTHNA9+tDMJ/Yevnp0e
         EHF/qqeNNC4Aosxwi+1lTb4YKYXS2SXzzTTt2eQiobDI5P1M5jEqHFd74fJAOMDdbEwR
         B3pteAJ/uPMjeLwPF5szHu9E9ideYtZq6qhNK7ziWZhrDv+0whxdfCOLHJCZEEjqX4ae
         DM+XRrjLi7J4NphvbJ2RxJguJ5LuWEl41RQ9McRC29/Ob/fHBsrccie2BhtLYsLOMjZT
         yb0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=xLAOdWISI4SkaXzY+l+g1IeakBOSoUUv4b/e0s7OQT0=;
        b=xMIPVuazjMOparseGxQ7huuq822Ddj5+qVq3zbS93D5mnG/PxmXcap1Zz2PaFCeu0E
         I55QFa+tVYn8a0aTxDjwHwslbU97N8OyrIlmCKE0cyDekOcAm+92cGJeA8J5lWOzQuSm
         LhDacvEgv0cOuQ/K78h4hR0/u29UkxRUUhUv8M8MWv/qcx90ZS/of7GgJ3m3fNmTiwLt
         iyFaLwvhBwnxboZ0shHz3s6IIbIFjTnmXIKaTc78ZjE6D7kzQnoAQP7ACqvXOkj2Crx6
         6YN4KGBLcpZkk9jX5FdwhlKMNwKc/bmfy7TU4Gyb0VprjR9V/Q2/MHrqjTTUn3GWsuDR
         HmUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=h9pA92J6;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xLAOdWISI4SkaXzY+l+g1IeakBOSoUUv4b/e0s7OQT0=;
        b=cdAYrZfzpzxeMmBFXTkNduGrQOVg2kQY8kL6F/+RDdcOWouxAxVNSdBv/aOqXvJBue
         QKmDVcXLOey8/QkvHBT+MMq6+NvFeiBGN7cOL1jD/U/7rcC5R8YflMSggI6KEy1C0ZJt
         a0+dyu5wxjGhQ5yzLS4V8oHReNKc0dnVZopNHWBu3X9QzXoYWyaUvrBz+MCA/Zf4CR8e
         Zq1e13tcz9Zr8MrVI2o12huOE8QGeOe/8fVULhMu+kbcpOjjGiYuimRceZGyY/YWF8PP
         3ZfRFcDSUW1AKZc4cLqeo3tfE46cQ48UWc3JdlRrJiVeMOyA8zI0UoFp0KeNclnL2h0e
         Y2qA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xLAOdWISI4SkaXzY+l+g1IeakBOSoUUv4b/e0s7OQT0=;
        b=ci9DcPeYzM0MCWS3ve+ILpAzUDIW557D1O1uDEhbf+KozjifZxRF/+n8En8DrRUXnv
         FPxKgXBI+qHdJNofzhqlYJ/YraN8Hf/S6DsqCsc6/K4BKxS8TkQLw4hbTBNlVeSNU9p0
         bShJgHplF5y7sZqoZMhU5T9cUmXcpvbuQ3qU5tPJuaDTdeuiAX4WBuR00goTKuMkj06a
         IzKysHmRaOnwrLR3WoAq1IH2DzhR9u31hPriwZ6e4vRFHOU4BpjmqUmd0weTt3IQrncY
         fZiSF3rMJv5pcb7EAsHs1S+RO3eQUU8+bP0vmF75h9rA2dRioFql8eoamV3E3IEjfT88
         Au6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krgYW5FG3S4kgrH96y44hKkiyfbZuoxA5mhz8CKcUxGeJnQiVIG
	nQiSOmc62rST5Ky0OadHfp4=
X-Google-Smtp-Source: AMrXdXvLditbOcUsgYlx54CT37ngLKpYLTDtzWqQBr0nc5Vaybo1g+8cIk8i2OQq9i+oIoSeQh5X4g==
X-Received: by 2002:ac2:54bb:0:b0:4cc:57dd:ad47 with SMTP id w27-20020ac254bb000000b004cc57ddad47mr1815201lfk.366.1673553514853;
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2024:b0:4a2:3951:eac8 with SMTP id
 s4-20020a056512202400b004a23951eac8ls1935348lfs.0.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:33 -0800 (PST)
X-Received: by 2002:ac2:55ab:0:b0:4b4:f19a:5aed with SMTP id y11-20020ac255ab000000b004b4f19a5aedmr22345974lfg.49.1673553513473;
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553513; cv=none;
        d=google.com; s=arc-20160816;
        b=lQRI4CGKfxV8YAK6iSgYatabt8RhP5iJhpdh4y/OARbzqVA/BVny0TwZOzOnL/sIKL
         orrE1vcahymL5DrqKzygtn5isXWxnRr902xNnx/17KRi4gy5tIXiTpXgUL0sOfzcN9sC
         Jpm+400VB508BI6CBIqDNmbTfrd+9QgqLBqiEzcwUGOtc7zXU51Vnk3uHh4ImjMa4tLP
         YI0xyIBxNnNNL34iGihyw8X4qdxN1O/ld5tOJ6Q+V2eL9FQb4vtLFuoM+79+D8ttEaaW
         c5nF1e6jwLal91QlDNly1NrIKotaJ+P9hZbVDENEyCVs6OQuZO3PVgCWYtwmauu0kdCe
         7E3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=BAfnvD9cLrzo61xSnZTsQNCRnrvqWps/XpXHA7FoM0k=;
        b=RkQE0qq6gO+3KcQnO9YFya1a9sGMk+myrygI+9h9tDfwkodlTa8iUYBAp4ELEXsr7w
         p5xBBc+45tuT6TdPyzn+d/M452RnqfyxHna5lerGMiKDIl2G8kzpT8ZWXRuXiKcfUDUi
         Ke9A3uKGpkVzebG5UDhGWHnug1PNeGwscQ6VMe38/mLGct/Icb+J5d+elW/cKESVCl6Z
         I5rfzUpRiknoEw9ftwUqEMGJGIpyFkKOhtGRgFm637EZ/FPzKOSCUvxEw2E5Mpq1J/ce
         Q2744h1DgKki90DlW1QYkOPWR9IYl1VHPU0JX7qu+kU8ekyXrmmJjuBuvBb2jTlHWJSG
         Bgtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=h9pA92J6;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id v9-20020a05651203a900b004cfb4a3fc7esi13612lfp.8.2023.01.12.11.58.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hd-005Oft-Sq; Thu, 12 Jan 2023 19:57:34 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C3470303452;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 364D42CCF62BD; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195541.416110581@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:48 +0100
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
Subject: [PATCH v3 34/51] trace: WARN on rcuidle
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=h9pA92J6;
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

ARCH_WANTS_NO_INSTR (a superset of CONFIG_GENERIC_ENTRY) disallows any
and all tracing when RCU isn't enabled.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 include/linux/tracepoint.h |   15 +++++++++++++--
 kernel/trace/trace.c       |    3 +++
 2 files changed, 16 insertions(+), 2 deletions(-)

--- a/include/linux/tracepoint.h
+++ b/include/linux/tracepoint.h
@@ -178,6 +178,17 @@ static inline struct tracepoint *tracepo
 #endif /* CONFIG_HAVE_STATIC_CALL */
 
 /*
+ * ARCH_WANTS_NO_INSTR archs are expected to have sanitized entry and idle
+ * code that disallow any/all tracing/instrumentation when RCU isn't watching.
+ */
+#ifdef CONFIG_ARCH_WANTS_NO_INSTR
+#define RCUIDLE_COND(rcuidle)	(rcuidle)
+#else
+/* srcu can't be used from NMI */
+#define RCUIDLE_COND(rcuidle)	(rcuidle && in_nmi())
+#endif
+
+/*
  * it_func[0] is never NULL because there is at least one element in the array
  * when the array itself is non NULL.
  */
@@ -188,8 +199,8 @@ static inline struct tracepoint *tracepo
 		if (!(cond))						\
 			return;						\
 									\
-		/* srcu can't be used from NMI */			\
-		WARN_ON_ONCE(rcuidle && in_nmi());			\
+		if (WARN_ON_ONCE(RCUIDLE_COND(rcuidle)))		\
+			return;						\
 									\
 		/* keep srcu and sched-rcu usage consistent */		\
 		preempt_disable_notrace();				\
--- a/kernel/trace/trace.c
+++ b/kernel/trace/trace.c
@@ -3119,6 +3119,9 @@ void __trace_stack(struct trace_array *t
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195541.416110581%40infradead.org.
