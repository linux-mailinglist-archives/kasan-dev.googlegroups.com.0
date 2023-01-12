Return-Path: <kasan-dev+bncBDBK55H2UQKRB26MQGPAMGQEXK2OTRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 85E19667FF7
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:36 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id w2-20020a0565120b0200b004cfd8133992sf58761lfu.11
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553516; cv=pass;
        d=google.com; s=arc-20160816;
        b=a5sNz9ugFbE8cAIMPLhIB0sZoz7B47WAcrApzUGAqNaI8CuDX+n/2QWoc1dbotCoNz
         5UoZl5Epe2TSX7sjkNhyiOhN4xskPzgXM2car9k2Vhu8KkZyQQgMXO/BgqVlWE3wY/LT
         pLm5OkNXOA/IL60I7FrYkFT9VhnbuPlsA7+9Qogrjx3oDf494S+LxvEryl93hjC9nF1y
         7L/HZIYsU7sJPGkrQvbbizC9R7+XMHiVObsfc/P6+VcyyEpzjugdWdtvmdU+VMIG7Rpn
         xq3DlyX24Q9rV/2sra//KS52B7grfZY/KAKMfcpC5xs3JZohNB66H9Lro32Tz+EpIxwg
         mcOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=AyAa1WEVu8b2nJHEKtGiXaa7fmlCFs9ylfNz+P7aet4=;
        b=Hx76H3JMsOYlmzJ5MJXLv7ks5iTWHiO0BsDt/Jo1K8Kzk8xhVn1DXxDXdyVqboFvvD
         YR/piV1Uv/okKHMMgQY6sAwscpjSJXYaMP+rnnPLdUhIJ89+5wL4VRXiCf3eUrVKY8pJ
         UY++Nb3KjrJ3irP9vkSYS4lNIiC0cygeI6ZSZ8E+hdT1lj7rIFEdaToRylWjgDWUTiKN
         2VZ9EK61L/bOwFXV+kDM9cTqXFyj/aLQ7dU0vtPU9nQNDUTsCzhJqmGsrKkNoFCErJyr
         beJPogkgXi7Oc/f8YACW+F6tkLnZvj5qcnhQVsV/60YxXfCWaULenLjnt3fReSQIm2a5
         iaig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=iB4zaU8a;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AyAa1WEVu8b2nJHEKtGiXaa7fmlCFs9ylfNz+P7aet4=;
        b=ccHnxay8x9bEM2N3t7uBg8F7XL3cxerIoqtQCoSaLwFMzqHdJOgZive21Y6KAzNCIo
         Wlf03iXxXmESMZXYhmoneInZ+QDi6G/kCCR7SHnZl6g1NVVoJjsndafro7aXh7ZAQ5cU
         JVS/3MLg4P5geeIOl4Z6wv6lyi2jaXxz3cIIdEKcM9x/Y0TBd50bIQgO8B9bnGSbnf2p
         wzcaZ1Ufg53AMAI5Qnht8MhKjn4J/i9x0QaaxFg4x0/IgF9skm41Z+IaTkJRDvY3I8lY
         xDLRE+N4X0S5mHTj4QKNp3OKtDgc2czPbIsfWtN2GN2B0P+bcmyiWPgr5+etv/B4Kj4E
         loIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AyAa1WEVu8b2nJHEKtGiXaa7fmlCFs9ylfNz+P7aet4=;
        b=zGwQ5LyCQ//oD1a6mPEpnmz1GmDOsNG7/8YWv/p8yW/zBrT1I4ynyikV6dldmSajPz
         WJ/O+zkw1G8cT54XqUxO2+Bm89t+g5xQvkjltRzbifq4tO8eOl+UjT/mtgmxmvBItuh9
         nFM1cB30GBvTNmVpLTlsWqunHD59/X2qhmR+/WEz38dOOD93b8qm4Dn7c9DddiL+VEw7
         O8uBRQsTuklOfwroj+4IYsn1mHOEWOLmY/rtraSG1+Y+a6zUNF49chy/AptybQjG30iT
         d4ljY7BpZJZbcDLGSHD7FvyjA6dCKK/G0+Py9oYnIL81soi8hY/pCJuzP5MExb37J6/K
         jR6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kroUMUiSS2i0ny6wyCHVGFzRmiIxgPmOqzrrVuUre0YxMYmIdt3
	foIXXSdCfOh7IgVj7w3Fd6c=
X-Google-Smtp-Source: AMrXdXttq568s+zoi8oetWLVwu0xVB8CMiz9OGPl2FSO1cjXb3lZSScn+KSlS40IJNO0zOINxYCyiw==
X-Received: by 2002:a05:6512:11f1:b0:4b5:2958:bd06 with SMTP id p17-20020a05651211f100b004b52958bd06mr4015768lfs.26.1673553515893;
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2024:b0:4a2:3951:eac8 with SMTP id
 s4-20020a056512202400b004a23951eac8ls1935397lfs.0.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:34 -0800 (PST)
X-Received: by 2002:a05:6512:2506:b0:4a7:7d62:2808 with SMTP id be6-20020a056512250600b004a77d622808mr22159832lfb.27.1673553514683;
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553514; cv=none;
        d=google.com; s=arc-20160816;
        b=0loZ1tYH78Z535MUUZ0yF+gpeTzB9Rp+IKVbelpANqeN+kKaMxmA1Ur4Zgzb9qkWcT
         QBmWPbGAj0iPiKtJPdUyz1+e/c5TuAuNLdM4vvF8c+zAvmCCAx8SzcqKSi4d0Oc+Gevz
         JZQ6okAAoCQ3aAsRPd1NZWHfDJ8MORdV25Q7871TcecgQw6i35SBVtldh7AlyhAPYfdU
         oYIWi2Yxvl44APevtKPABl651MWX40cxEIV2AMH7VVr/zeZaviPAUKEybezweFhNrO+2
         MF7ut2IsFjwcMpmrMN4RK7/dVEhYJXA06ET/EI524rYqPRi6037IlmYKUlEfZG2vHnu4
         y44w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=iAxp8x4lKKvpjseCn+ZLFQYojoG8LdH6O7HFdGbhL8c=;
        b=DLHqW2SiRc8+Fg9CVGGfpEN8zWTtIIqIz1dieR+W1lz1wACn/xPlrpy2BtCYxOu4u+
         s3nkmw1rIKMG253fCmVRZ4TcsJ5YeXPqXxWuZHePoe9HKXbADjBWidAM5DDE00D/Em2O
         x/pFLiJoRKMDZvnlKbzqd46LKsc2lGVL/ykRo/VxXdU68vwtVdJxzZ7Z03JnxF1rUWm8
         rIkUbNtPGI7g0NIJP+L/p1ZS6OfOYd7wpGqVtAIaUzfkf7PHOblvJosiulanFgw3p6VJ
         WXZDM5HHGO4dEYtUF/AYrp2bV+3jOg5dhRQKy5xZT+XfEe5fRTpn1p/gIxe0ChynT5uz
         W8VA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=iB4zaU8a;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id s4-20020a056512202400b004abdb5d1128si687372lfs.2.2023.01.12.11.58.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hZ-005OdX-4G; Thu, 12 Jan 2023 19:57:29 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2F312303411;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id CBBB02CCF1F6D; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195540.190860672@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:28 +0100
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
 Ulf Hansson <ulf.hansson@linaro.org>,
 "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>
Subject: [PATCH v3 14/51] cpuidle,cpu_pm: Remove RCU fiddling from cpu_pm_{enter,exit}()
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=iB4zaU8a;
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

All callers should still have RCU enabled.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Ulf Hansson <ulf.hansson@linaro.org>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195540.190860672%40infradead.org.
