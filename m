Return-Path: <kasan-dev+bncBDBK55H2UQKRBTEDUGMQMGQE7BILAOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F0B95BC685
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:49 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id v7-20020adfa1c7000000b0022ae7d7313esf810470wrv.19
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582669; cv=pass;
        d=google.com; s=arc-20160816;
        b=UJ3eH2gV/I/ngwuT1k//UmxRBoxLEDVOk1NH6H0UmUjrlZXr3YcDit0gTAzYogqo7+
         QRcGM/T38ZHzZep9eGF2jqXbw30nBbAVPCU5qJ0Q1t3xPfvXo7NUAS2vJShvPPBLGbC9
         kRZugEs3BkpKL+pm+3zVOxuwv3nStso7Nv2YCenyhQyHrDrhI1uJ20syzx2MdhemSR9A
         ewjMX8r7yett8mJE+6VrD3v3DKJqC3TDes6kZMJprItiMw6xJHaDOWKtKx6AP8/jdU3b
         0QMcgqjVu8G7vylrdVx6LqjF87z1WxnTC43SwgJwtxRibP+yamAYmbAdBg+B+N08w+Fl
         nAeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=1xX8OaDfJ7Jne280fMFYPsKPoq1o2nbtqj1BHQ8tszQ=;
        b=rk6MVJf7XI4tVoT7hHWc4JZo9LNKzS4Oc3DPfmtIRZcpf86dEWmalfT5DZAuS6OvEs
         R5s9PTOM5E2rQBm5sTQeu7rs6w0ZfgTpawYquYwi2ZVxIVqyIBXTpNEV5IvBnEtIRXQh
         m5gFLP10ENhgCg8aiePoQwGckNQ5je+G/tIMRWeIOFX7OxkINgpb8CX9/boZPW7vnH+C
         Y8AoiIh9U1vEZUqli7nd2ywhML3CFiTeEFa0ykY30WBqCjtDFv1SKFjUjYTY86jsFPIo
         nip86Mcyf8b5p8Tpxqvp5jRGFkA77vrndtdmVT/dmucHmmVfm9CJamuYORJtcgIoQchS
         6zbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=QXbYDlHk;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=1xX8OaDfJ7Jne280fMFYPsKPoq1o2nbtqj1BHQ8tszQ=;
        b=mWU7RVgDF5aYeb2EUoWup++Z8omB95x0EDn4au2q/Wz5uvo9kj2K9DsqIx6FGBlqeY
         jfHzsER+NF0R+zjNc6YZFxFwVZO87neZXV057rxav4kuyCpC0L1prmS1h4Re/UBOKbyC
         kwCoKFDs+P+FEA+itVA1iQPOQJEDKCLLMmEKE7SppgZvHPm5gtbSMlt5PVbPNv6mwQb9
         cVJwPXpAJ/6WmfcyC7kKuWDBotL0QpCdQAvOISxwK2W4Vmj5Se4vr1fGIeRpqWp6iS1Q
         btUhiTLgp5DWcY4DNFigsOYr8JgqKRazRpejk7FnGsgprwKut+7VFnLTtrfWXKKj+m9b
         jL0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=1xX8OaDfJ7Jne280fMFYPsKPoq1o2nbtqj1BHQ8tszQ=;
        b=tzjTWr41sqVzLArP1tBTVeTKqMFFk7TSo5yonujvawIM9TshBmx5VF2P5eUCdJJqyd
         CZbi0ePYyihsfrgWZmA0dqz8tgwJqvSi0pArkTOvnYBOsMBJF3zuDUu4GbVbz05wGjgB
         tA3AmofKKgHvtAqM24yzLd2P8cIzx9XsA4T8yvN7KMHTXG19k3giWrnjjFAtUvknLsI2
         0AY4KKfNIxGA11NSEbAJmJa2zhKSh551Y9lEGcAEozK+OFwiK6vIQj3PBsyxmYzUrGQb
         gT7g3R5LEDCxUwpDvL4s30T6KRsAzypysyuZfIYs9gRze7fcPPjenrftLROQ2MXXRV2I
         dw9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1q/2dEpLudsOIP/DmwADEXZdNrL+w8ZDBo3U7ZO/vQ8bv9ehDB
	hffyy+yZ1G1haBGg5Gjq98E=
X-Google-Smtp-Source: AA6agR4cgm7FyCr0irZgjnhSmJ6UnIREvb6oweW4pmV793iWlFXnMCiBc2n9WCwCANGs248RVYaUlQ==
X-Received: by 2002:a1c:2743:0:b0:3b3:f017:f23a with SMTP id n64-20020a1c2743000000b003b3f017f23amr19514148wmn.137.1663582669208;
        Mon, 19 Sep 2022 03:17:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d19:b0:3a8:3c9f:7e90 with SMTP id
 l25-20020a05600c1d1900b003a83c9f7e90ls2675890wms.1.-pod-canary-gmail; Mon, 19
 Sep 2022 03:17:48 -0700 (PDT)
X-Received: by 2002:a05:600c:4f8e:b0:3b4:ab30:9af4 with SMTP id n14-20020a05600c4f8e00b003b4ab309af4mr12044470wmq.84.1663582668001;
        Mon, 19 Sep 2022 03:17:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582667; cv=none;
        d=google.com; s=arc-20160816;
        b=CwiwU5ZGNnaQBz18IGnAzxoTPkCOjKcrmSekne9AXk41BrB2KOVu9ZlebxNzgq+OdG
         Pw7PI5Lk6QJkCCO8315pBzX3WvON7VG2fk7/hbw5TtObe5HyR6OKD2eYNB/R5cAIwxPP
         uvOzkxDi5X+Z5jWKk0FGMe2PMBFwq3OHPOHhZqMnxEbFRbzNKg9bNNE9cja7vHJ25z0G
         yEgqTJGDPCdzVQAdN5Po6jM6HBcrt4wMqALHwMc4D0IXLXfmYMOrVo903PvttE4N2EWP
         uevD3tnAG97SBlvwB0ExSa2uoAWdpSLcMXw+GafdC2sF8Bn8B1aCFl3L9/to6TwNXcsP
         GCCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=pxqjaMyXYMAIciLaWxKe0qnmRXZim+cyW3iOuZrk594=;
        b=g9fui9BDn7wNkQ7NkN8uT4ZasfIreEcnTPeljNY99WUrO4karb1baqFSzarJjX13au
         TIO5EhDADTdIA7CTVYiBxb3JX/H2vDWB6omxVmEgeOaZq5gtglG1i6ZQ6k5EOQAnZCyL
         yxRdUxCIm81ttakAXtRRmYeDiPr1ZbYrIZHg/053MqgwWCPBopGOEftLPrcx9LZHZbGa
         VqiKafIynZPSBJ6gBAKvqe6AhLdAqYuGqBcom6hHqO2br7pvUwPvNAiIIB9qcj5gig2i
         7vJMOgdrF+ehe2ox0i35GstYn2JIAnKGTxOw5gvy1zv+1ZIEJ+jFO9ylH1GVrRmQXODu
         PRCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=QXbYDlHk;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id c2-20020a05600c0a4200b003a49e4e7e14si453967wmq.0.2022.09.19.03.17.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:47 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq7-004b9h-VI; Mon, 19 Sep 2022 10:17:24 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 4619C302F3A;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 6042A2BA49034; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101522.224759912@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:07 +0200
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
Subject: [PATCH v2 28/44] cpuidle,mwait: Make noinstr clean
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=QXbYDlHk;
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

vmlinux.o: warning: objtool: intel_idle_s2idle+0x6e: call to __monitor.constprop.0() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_irq+0x8c: call to __monitor.constprop.0() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle+0x73: call to __monitor.constprop.0() leaves .noinstr.text section

vmlinux.o: warning: objtool: mwait_idle+0x88: call to clflush() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/x86/include/asm/mwait.h         |   12 ++++++------
 arch/x86/include/asm/special_insns.h |    2 +-
 2 files changed, 7 insertions(+), 7 deletions(-)

--- a/arch/x86/include/asm/mwait.h
+++ b/arch/x86/include/asm/mwait.h
@@ -25,7 +25,7 @@
 #define TPAUSE_C01_STATE		1
 #define TPAUSE_C02_STATE		0
 
-static inline void __monitor(const void *eax, unsigned long ecx,
+static __always_inline void __monitor(const void *eax, unsigned long ecx,
 			     unsigned long edx)
 {
 	/* "monitor %eax, %ecx, %edx;" */
@@ -33,7 +33,7 @@ static inline void __monitor(const void
 		     :: "a" (eax), "c" (ecx), "d"(edx));
 }
 
-static inline void __monitorx(const void *eax, unsigned long ecx,
+static __always_inline void __monitorx(const void *eax, unsigned long ecx,
 			      unsigned long edx)
 {
 	/* "monitorx %eax, %ecx, %edx;" */
@@ -41,7 +41,7 @@ static inline void __monitorx(const void
 		     :: "a" (eax), "c" (ecx), "d"(edx));
 }
 
-static inline void __mwait(unsigned long eax, unsigned long ecx)
+static __always_inline void __mwait(unsigned long eax, unsigned long ecx)
 {
 	mds_idle_clear_cpu_buffers();
 
@@ -76,8 +76,8 @@ static inline void __mwait(unsigned long
  * EAX                     (logical) address to monitor
  * ECX                     #GP if not zero
  */
-static inline void __mwaitx(unsigned long eax, unsigned long ebx,
-			    unsigned long ecx)
+static __always_inline void __mwaitx(unsigned long eax, unsigned long ebx,
+				     unsigned long ecx)
 {
 	/* No MDS buffer clear as this is AMD/HYGON only */
 
@@ -86,7 +86,7 @@ static inline void __mwaitx(unsigned lon
 		     :: "a" (eax), "b" (ebx), "c" (ecx));
 }
 
-static inline void __sti_mwait(unsigned long eax, unsigned long ecx)
+static __always_inline void __sti_mwait(unsigned long eax, unsigned long ecx)
 {
 	mds_idle_clear_cpu_buffers();
 	/* "mwait %eax, %ecx;" */
--- a/arch/x86/include/asm/special_insns.h
+++ b/arch/x86/include/asm/special_insns.h
@@ -196,7 +196,7 @@ static inline void load_gs_index(unsigne
 
 #endif /* CONFIG_PARAVIRT_XXL */
 
-static inline void clflush(volatile void *__p)
+static __always_inline void clflush(volatile void *__p)
 {
 	asm volatile("clflush %0" : "+m" (*(volatile char __force *)__p));
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101522.224759912%40infradead.org.
