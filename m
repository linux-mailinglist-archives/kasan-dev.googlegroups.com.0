Return-Path: <kasan-dev+bncBDBK55H2UQKRB4OMQGPAMGQEML4QINI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id C6F5F668014
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:41 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id n9-20020a05600c3b8900b003d9f14e904esf6994166wms.9
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553521; cv=pass;
        d=google.com; s=arc-20160816;
        b=x62siDOA+dpkDiR4tHaOl5TcA4EVsLXycfGmBsEA0sznHjZN5CloW5OKoXpbySc2D0
         fIIF0psSwAnJn5VP1kSZD/CX0dqBLMltbxP5BOyjlQS/HeL1qEZ0CkymI+wxC6J6YNWn
         rYL686G8ajqR1NK4AaTrTITZRCrb839PROjnfktEwA37fXpAH07M2OW5U6P2/TbOj90h
         aifO1ncljONjaA1cEh42BxIkALHSRCaLWtegyr4ol47S9s9jfOWKR9f7DJ8Qvfz5pkia
         MsZ6PMhwHSTt0ieA5Zc/wVPQ+95R6O23nYfU9yEmoY9WYcqqup1Uq2Bwai5RSkEZmEoy
         v6VA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=p5d3DDxvNivajjy5TS55Q3TxTv8Y0L4vGrQpBsy5aJM=;
        b=WdstfidYP7vcpUM9RUa+o5aOm16RYXk3IS4xM/V6MiPqjc1D6he1czVYjxvoIk9vQY
         wgTJ6ZJ8F+9tH2ytxt7xRTuyUKAnEMiaStKgbIZyv1X4ZUBeFwq40/jNV+cv2dY+bcFu
         JaajqUCGFqoxz6Q94eIifjUzAkj6dZi9EMe7xQECtVbQfljPENYa8IZO5YKQsftJkHdR
         PtwzobKfcyfH2Socx62xrxY2ycJjr0UBYW0a2Jq1NJNpkXKR/jiflSqzei9jVIiZQ4Bw
         Ci6FPHlVJZlStOIxsF4xlCoFKCgc6HL45B5j0Zjys63Jo/IwkhEoUqBvV9CSDMZUiOwQ
         rmqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=AsVrq9wT;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=p5d3DDxvNivajjy5TS55Q3TxTv8Y0L4vGrQpBsy5aJM=;
        b=Zx/03xVVvGzNLPlYqLi7G60c9q0JzU5dhS0E0klfIYrDmoXmX7W/xNkgLj6USIH8GU
         9duv9cUCJt9q38S5HsYI4uwbzJEwMGuEO7JgoHyX1cSjkshXjOYxfFeafaoRORACt3LY
         l6CNHOobDvU5iKlvZU1fq5Uxwu9m6xZKl6A8e+xASjSRPFH6oM3deJYzxC9GSeIMyw0I
         K7u66LaT6z3eFpvv9WAgT+cTqx2le1EeSWpnPa99KgEWVzRpEjdD7b9D/mXcUGe2CfHu
         x1d+Ot+1L2Y7LjQ/1C9x4uVeaw+zhB1ixU+Qr926JxWgqM3gf+sqE4/YhWiHHtMGlKnO
         RS5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=p5d3DDxvNivajjy5TS55Q3TxTv8Y0L4vGrQpBsy5aJM=;
        b=5DlGGTOlYc3s09cTs3T0y8Nvnj8kbDHrdlcbesImaI9x5mqoktCAGYU2FlUYpfeMs4
         OlwIn+KnHS9lKYyxKzgayzKxocdCMP+tN6T26UqsyPpbDGw2wk9NNpzfT6I1M3a3Nl5X
         csUoHC0FbAvn8k4jE9nZeAFNRmkHB9R/eueK5Je2pyEMQthtOrEBCfgKNr+rTrAor9Qa
         AVE55wkQDeLQcrBqqe+m4JGZY/kLW8xRAY29YcqE/M2eIgzvoR+m1h/VYwwujCfY8VPj
         iUzeD+71VrqCoWLSzGpePp9eEPd+I1hZFREsNLXzeejQgchRmFkdKwdA/pJAUvs06mFS
         lBXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krnPMi8kX+cTapRU7j6Djt6j9hQ3ZeTsG3/bsScElAeqDswyGYJ
	LAjl/zW+WYS6jW1DFhJBvSM=
X-Google-Smtp-Source: AMrXdXsm3ai1tVrLcm5rO4XJM0bqK97Iboh9247ub+ax/+3XzT9vxLPeyaGSlm6uu20dtJopf9B1IQ==
X-Received: by 2002:adf:f903:0:b0:2a6:4dfb:80b6 with SMTP id b3-20020adff903000000b002a64dfb80b6mr1520172wrr.388.1673553521369;
        Thu, 12 Jan 2023 11:58:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:250:b0:269:604b:a0dd with SMTP id
 m16-20020a056000025000b00269604ba0ddls1474437wrz.0.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:40 -0800 (PST)
X-Received: by 2002:adf:f4c2:0:b0:2bd:c9b5:71c2 with SMTP id h2-20020adff4c2000000b002bdc9b571c2mr3985067wrp.38.1673553520261;
        Thu, 12 Jan 2023 11:58:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553520; cv=none;
        d=google.com; s=arc-20160816;
        b=0roBNgkN46UIu1uIu4uefmcU1gM27K4y359AzFm0ndZ/HbGvksf0sz2BTrkZThn7DB
         /aPDeiXmQX8gHOEkvR4eqkGPYhsk0oNhqfK/pSJMqOe//nBrM0WJdtKm3WFgmw9YcKed
         lFtpCrq87Q0HbZ81+9CfRvYRgJOsLxiid2C3L0376m1HH8Nt0ppJz1Q5YWWr/gdn4Ang
         8wkjIeheTG6BVr6vgtq9vAhKzLav8n4DGtosGvCbG2LwzsrW4FRK+7afD8+k0yD4qf1h
         KT9tYQK9F+GbRon8VeR7h4rkyInxaAvo2I0yALtXb6i+0EzjesiC9cNxP8Pa+UaDwLOn
         p6Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=K+6/dwXz2WKb5RxNLU2q+chP38k8rKZMVN0FbUJ4gys=;
        b=x11ut+SkOt3Y6Iv6fNGBaRCB1yu0Iwg1gYdmw5FXVpA5iW7HqZjWMJ1rHFymaAEBkO
         nkQj5zfH/VddSawUXAfCqeV+rOsfawFTlaO3hUUEnnBHJSdNhXVQDPSDpM5R2O4c9PK+
         vNxbckm55vMBHDTzEHKx9oJZnz5MMqK5xjGgobH7d/gL5DItzSt2KQqIdLDl4zptx0yv
         gKRN7MOdqBbApFAVmDOBy/IznWoOk9325qno3ZfMzWUaQ3JppFGyAi+Q6GxcnGQVuAxx
         xUsItoAjcHtNq80hxYXD/A2bq6wbiNWv2RTerKXF9x78SV651Q/4QJB9ZRCdwI7ORFTq
         GEXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=AsVrq9wT;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id m7-20020a5d56c7000000b0023677081f0esi826742wrw.7.2023.01.12.11.58.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:40 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hC-0045nv-05;
	Thu, 12 Jan 2023 19:57:06 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id B4716300472;
	Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 8D9992CCF1F4A; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195539.392862891@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:15 +0100
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
Subject: [PATCH v3 01/51] x86/perf/amd: Remove tracing from perf_lopwr_cb()
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=AsVrq9wT;
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

The perf_lopwr_cb() is called from the idle routines; there is no RCU
there, we must not enter tracing.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/x86/events/amd/brs.c         |   13 +++++--------
 arch/x86/include/asm/perf_event.h |    2 +-
 2 files changed, 6 insertions(+), 9 deletions(-)

--- a/arch/x86/events/amd/brs.c
+++ b/arch/x86/events/amd/brs.c
@@ -41,18 +41,15 @@ static inline unsigned int brs_to(int id
 	return MSR_AMD_SAMP_BR_FROM + 2 * idx + 1;
 }
 
-static inline void set_debug_extn_cfg(u64 val)
+static __always_inline void set_debug_extn_cfg(u64 val)
 {
 	/* bits[4:3] must always be set to 11b */
-	wrmsrl(MSR_AMD_DBG_EXTN_CFG, val | 3ULL << 3);
+	__wrmsr(MSR_AMD_DBG_EXTN_CFG, val | 3ULL << 3, val >> 32);
 }
 
-static inline u64 get_debug_extn_cfg(void)
+static __always_inline u64 get_debug_extn_cfg(void)
 {
-	u64 val;
-
-	rdmsrl(MSR_AMD_DBG_EXTN_CFG, val);
-	return val;
+	return __rdmsr(MSR_AMD_DBG_EXTN_CFG);
 }
 
 static bool __init amd_brs_detect(void)
@@ -338,7 +335,7 @@ void amd_pmu_brs_sched_task(struct perf_
  * called from ACPI processor_idle.c or acpi_pad.c
  * with interrupts disabled
  */
-void perf_amd_brs_lopwr_cb(bool lopwr_in)
+void noinstr perf_amd_brs_lopwr_cb(bool lopwr_in)
 {
 	struct cpu_hw_events *cpuc = this_cpu_ptr(&cpu_hw_events);
 	union amd_debug_extn_cfg cfg;
--- a/arch/x86/include/asm/perf_event.h
+++ b/arch/x86/include/asm/perf_event.h
@@ -554,7 +554,7 @@ extern void perf_amd_brs_lopwr_cb(bool l
 
 DECLARE_STATIC_CALL(perf_lopwr_cb, perf_amd_brs_lopwr_cb);
 
-static inline void perf_lopwr_cb(bool lopwr_in)
+static __always_inline void perf_lopwr_cb(bool lopwr_in)
 {
 	static_call_mod(perf_lopwr_cb)(lopwr_in);
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195539.392862891%40infradead.org.
