Return-Path: <kasan-dev+bncBDBK55H2UQKRB2EDUGMQMGQE744X3JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 02EF15BC6FD
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:17 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id s5-20020adfa285000000b0022ad5c2771csf2123884wra.18
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582696; cv=pass;
        d=google.com; s=arc-20160816;
        b=w+++ba9QUFO0SGbDqI921p3iJHmm4VsZZ4umALfawE8AASrKC0lbx5satHLlV9XsLX
         cT/Jj6NDfaBOsLgCXaXPbFwFIyfT7JvupM2voPEOEAHW0LD0HQEFgXaHS8EKX0KUzzww
         3Nn/xAG9EeEoTPVlnX0CXbPuWtMbaQ8ISbiYr9nA3mAtLwmWse1WZFW4Sua+dWzrjZX/
         Eh/kERUC9Lu00jtLC/lih7qcSAmue7Pb2YtHHXj2EQuPZRjGsXK/cHsdgThxSpc0aMHY
         Y3ob6OVq7TMUq5QQ9Pk4U54C3iVMBXncbSnj6q1YNTsWMcXUyz4hm3i3x7kFbJv2F8/L
         6rFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=PMyOJyB/TNQNzFd+xO0CLD29uTSnvV2OXYjecwzTgMo=;
        b=W0wBI88fpJzG6/O2HZuBntfG4UIH0++02VqSRpybLVqfwL8+r24FvT7BE2+41UNvEP
         MNubiYmggW76ZXHxoIjg3kzwlRNlGva168AbyhsfdxfAZij6Gzk1b2HirRo+iSXSJhNd
         ++/X/EkTT0PgBgmrayAuG91mZekdc2LDEo/3qHO1Nb2sLRQgL1fGKiVsQM3dLMRFoPIY
         FD1K53d8qp70YmfxGVF+n1AeGAoYVzfgL0rSodO+uPvUTY/FCdDsgYpJmbbOqizhn9TV
         khhcsttm+NavccAIcIDMP3YSGoFZqbVyc4EomqIKO9bpe/RPEardlMVyxE45rHa8HXiX
         LZhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=AlyUL2n2;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=PMyOJyB/TNQNzFd+xO0CLD29uTSnvV2OXYjecwzTgMo=;
        b=WsWBqLEy2XDtklNfCcK8vI/asiJTZI1qb+OprL/PnL37hsUuK4RMVyg4GIPdFoPtrK
         QQ9RlIntRlon9GvsnVkT/w9v68Ax4wwy1nKGQYwMD718rzk3AAyxkTIvvRjySoo06/ex
         GsufjAN5AwmxUQ0sJvBrtocYhi63mGKNYnwN0T1IQycG4zmdnQpMUCdzwuTRQKVDWi+9
         7TsEBHkVUj2UKAY/77aO+BIwIh8R5dROZHvr/JBPccnp0nTsWX0u02dQE0FdjUuhiMt7
         VUq/g0OPlW56nwfXhZTR1hzwBe22azrZp1Zl1pWVMF5NspLzi/AIakyaGKFpsBZzH3qK
         jIWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=PMyOJyB/TNQNzFd+xO0CLD29uTSnvV2OXYjecwzTgMo=;
        b=t0izUeyOQoGpMdzHB09H3N6SbzkNZ0jYAkkVx0ufQ8KTzmT34fV7hgdNRLcR44IMrF
         hSE59yBllVVowW+Be1lL1ZBHQowdvhAuDMEzi39lo4KJ+EvqCwRyj5g76C6C/hG0A9g2
         LNsV6l064UJ0ApXkA+Dh5yCHZmg2NzVceEhyA3rWXX5fVykI9QWM335PFn7WwS+uicFp
         uNUK1QTC+nXRQ3M/cnpvl06TQRwblUAAcUeFIvaU1XfIAgdGOJ5/2Ax1gSERb4YrkQqe
         3cxactTQDCoRKh8Hua9JzGIWzz+nYF9G7XR+eX77Z+PIRWl1mW7TzYLD2I9FgxrMkhPQ
         l+zA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1urcfFl6vHJiwV3zOY+NBKSBPMgwADwv6XuK/jyZaYoMUHsz91
	6U4Pnx2rjK2KtjobwqWjdwY=
X-Google-Smtp-Source: AMsMyM5VBwqp8mEt/bj5xfGqh+E/WbiJJbH1CmriKLut6sXFrsGpxU37y349U4JSjcDlW7JjqcyfEQ==
X-Received: by 2002:a5d:568f:0:b0:22a:e6ca:1bbf with SMTP id f15-20020a5d568f000000b0022ae6ca1bbfmr6710677wrv.427.1663582696701;
        Mon, 19 Sep 2022 03:18:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f615:0:b0:3a6:6268:8eae with SMTP id w21-20020a1cf615000000b003a662688eaels1744466wmc.0.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:18:15 -0700 (PDT)
X-Received: by 2002:a7b:c4cc:0:b0:3b4:757b:492f with SMTP id g12-20020a7bc4cc000000b003b4757b492fmr18812694wmk.74.1663582695668;
        Mon, 19 Sep 2022 03:18:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582695; cv=none;
        d=google.com; s=arc-20160816;
        b=gtO+n/T35i7sUCRoCHI7w2HVCRzPds89B3tPAICfm3d/UvAvMios/PL7UGai+r/eFb
         UE5ohXPc2T4vFWuD0dJi3ipCHs5+4dDtvqfeQWfce1b37cpQsIV/OW2BCttgtfd7rlAx
         KwKPT4fCfd8fd9GiTUcfMCmBFK8BTzqFTrJvSPiKt4juq0MHIyHF/W7qzRC/ca8FDi9/
         UR4EUi3yZF4PVuYaiuZ0Loi+IubY380cmaD1zMTVjtdyUqjF7oHE9pN1Kew7V8DD0vSJ
         PYLKSP6Qg/1anC4jN4filsBi1REKvLv8Jlr5a7Gg/KytdO2AX49vvIe8ymXhKW7Rups/
         VuaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=YOWU43M4IjsvcmJXQwOIFJh+WuCbnSytdcIdnv65DkY=;
        b=Jh//Dx5WtS4mPzHUu4iZMwzQ9uD50rXobxb7I/9DZBcabmv0ITo7lK4yuuF3iLfbb1
         reKj404dNx85KX9Uo9UakHdADvIKnjA4IwQ6Rz0rIy2D/8B3zWwIfVK/cCrv1yDWXbMt
         Ni3InuzdK+wB6+RlEfZZZCISK+X7SqBxgPB/k0JvPfeYyOy4hFbtU4nme0bbobip297d
         Csbgq0S/AkkNQplK1zMZAb17QMFOjIi/n7kaM9nLm9OHKW2BV23GQ9pCy6VMt9o/zjzO
         e/oTvpdDN3Js0t6tYv052UAps9UNMkciAV2UMz05wEVHPC3SLY06clT9ds7+3jxPdcrq
         NP4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=AlyUL2n2;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id n24-20020a7bcbd8000000b003a5ce2af2c7si331999wmi.1.2022.09.19.03.18.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:15 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDpD-00E28u-JK; Mon, 19 Sep 2022 10:17:17 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id E407D3005DD;
	Mon, 19 Sep 2022 12:16:21 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id C4C3D2BA49036; Mon, 19 Sep 2022 12:16:21 +0200 (CEST)
Message-ID: <20220919101520.399971897@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:40 +0200
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
Subject: [PATCH v2 01/44] x86/perf/amd: Remove tracing from perf_lopwr_cb()
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=AlyUL2n2;
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

The perf_lopwr_cb() is called from the idle routines; there is no RCU
there, we must not enter tracing.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101520.399971897%40infradead.org.
