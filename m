Return-Path: <kasan-dev+bncBDBK55H2UQKRBYEDUGMQMGQEZVUFEAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 014BF5BC6D4
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:08 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id g8-20020a05600c4ec800b003b4bcbdb63csf4842692wmq.7
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582688; cv=pass;
        d=google.com; s=arc-20160816;
        b=bOWQMirFEvHKkEES1/A599bJMYB6Doh1odgwA9uRpOXoZNu7uGaKH7vAvOjP91l+52
         15dyFh2IaSKA2yLiR7q2yXW+tZjoAcA8YFK9Ezo8ADih3vPJbEcQUD5iCMU8kCa1YuQg
         19xccJbnjWJ99vsf3CUtkl61f4HkPUzuSuQztv7swaNYdq+bbrstVQAWLFsRyrrXCp0X
         RbCshvRR6a3z2odbK1cq29XfYeQYoc5ujQht8zzXhftSF2k+9dudS9WM977xusU1Al4h
         BHNReNPZqv87lVDZUFck6guyfyhi/oCpI8irW/JloRMtnEQt7z1nIeFyHGQapt/yAPrd
         uXPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=sYbfM27xy38bj/aKEFcZP3RSrM3cvNH8C9z2Yj4PfKE=;
        b=EHCXjrngXKtAKBdJEKNGn8kMsxaBbvPp8w/T4KDxYsVqAZuamhOtdxoRQbcJVE7HuD
         VJxLAPr7ukLCHKWcmZB1iVK+YdsSFH48c7F0E+SKGnUnrFkxT3gxuucWEXmjzuA9YoHn
         xh5wfVc1PLPR9c2To+ljUvhQNc/ACkv8VlPwGdPYlH0XRwjAg/uHFFv5nIVhNhxlHkzM
         obXhKsl18+cUkLzdIrHJ/Ox6XvK8uGM6o9J4j78ujwaFUw/MyMhJ1a9MI9jz0FWtruze
         KkyZ4+dI+uM+pPaxbHZKCJLnM/WFYanaW4iMjDaWoXXUldUMPfKRvR7y43BSz2aDlRaP
         V2LA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=buhX52S0;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=sYbfM27xy38bj/aKEFcZP3RSrM3cvNH8C9z2Yj4PfKE=;
        b=I1HD5wCbtdSIIShWEAdXbxybWX5qp25ts9Conqwp0hUL1G2RjbYMytkzwyRARp4b0V
         wi8Bltp2za6XBAY1ioU6nQt1F6GArddb21trb+Wr2OImBYZhyTc4JsA/2eAfELTeWBMv
         DkJlLizymPgnLFxoXEBrTZayJzTl++SIromwC12zx3OCrKU5t4M1IdD5jANEaCByYlrb
         Ykh+rzRC7Jqr1ConZnME93fFMkp4CpOxR0rsGPzD3S2rsm97rEd9FtkZ+6hIr0SazhtR
         ZIRFPGBqHucQDu+jEx31KsQCbaTAgZXcFO/YgukHmt0/lGgbIMaKhvBpeVBH9mtzPHj1
         sYgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=sYbfM27xy38bj/aKEFcZP3RSrM3cvNH8C9z2Yj4PfKE=;
        b=KFVmur7VHUsaoijhQK/U6ps+erfiIoPTsjs2Q4f2BN54bW/f7gNYI8oWuDV7JRfVC6
         y45xaX1gmljFN/4A6sAE+BY+ISiGyeVySQALKzNbTiJtuAM+oeamcL1wS06YDC3ciXCF
         Au3uCL3R0k68X2A6nDcOEH3AlRh/JcnCEEGivdoo745sbEYG51gEJqpmvepX5CQ/LK9t
         uLSj1aIvRmU9v+UrVHbsdayyYS8wcgxxwwcPEOzdR7vma2Fk1eOAVrEat9K5JSSyE97f
         ONMOcvKf1XM/hCC4zcJz/5Up3k1xCh2YbCQAuCrh5Md+r7VQUImvJbblGN6Eqroj6gZZ
         +ZpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1hyUkRqEz6/XcrtrFSh0Y8k1PzsdswN99/4jNmUoErdhLWUICY
	id8AijUtWlCFETqcNur/9lQ=
X-Google-Smtp-Source: AMsMyM7JcB7d7LlnmF9VHs9uSng7FHfnWlLcQbTNwhrJS5i/NvRYhaXhW8ehQWJocnZ2KaXrkN8iUg==
X-Received: by 2002:a05:6000:1842:b0:22a:4d1d:4bd6 with SMTP id c2-20020a056000184200b0022a4d1d4bd6mr10140111wri.603.1663582688486;
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:490a:0:b0:225:6559:3374 with SMTP id x10-20020a5d490a000000b0022565593374ls7610192wrq.2.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
X-Received: by 2002:a5d:59a3:0:b0:22a:fc9b:4358 with SMTP id p3-20020a5d59a3000000b0022afc9b4358mr3285620wrr.4.1663582687411;
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582687; cv=none;
        d=google.com; s=arc-20160816;
        b=a3CQYiotew2H6/5b2yEfTZC1B7qEx4Q5rGIRxntNLJ6o9YC48HvIrNwShujy0xHoYD
         WJYTuNfddS99bKrOvCXRTVbBRp5sxSV983BtSi7WF1qDzuRTSvk1ojjkYJR5SbsosYnF
         GPT8R/bOy3YaazCIKI0zF4oK7V3/Or6MLjxyAALP+UpqKvBoujjIUJmjQ7IP8SP5PxSq
         WMRirBntmd/Sc38ixarTTilSbWPSGH3YlhQ96E0c434FVkSJWpn+sdzf9icJSD8Osx2g
         AgAGWAOpXlT4ZAKk71xxYdOaxOy3+1IKrQidR8U3s/viBuR3x0kdQwHQQtXfX62FCqlq
         b4vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=jlMVapcDkKa+q5r/dVIZrQzWqwQOPh4aNsx9pv05CFo=;
        b=c7OQjMwHj9sjzbeTIl2vc5UmES/ROKk7kTcgZFQskqHiWn1V1EczcVcX6nk0v7oWQn
         b0CaDediLfoX7g/2zPZgP4V/Z/knYvhz4DmAbIZ+2JZ4fewqSEnzoGbC2v7qz08IhKZf
         HKTLKJLVA2hHuhYTrwbOVcBQj1S3HjdAgV298LGjuorK1y+eZX3AAPXcLegUuoLvCZIg
         C8z4XpUKg2Kn6HReeozbY2rjCpMEWrOOENShgwtIZ7zx5gMYNK1JXsmnOyo6FtjET6bj
         PlrITnzSEGLcmHr8DLXYMTC2IAJ0j1tdjI/NeqIxlTe5hGZINl2g+S8jyn46sXmS7v8t
         l37A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=buhX52S0;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 65-20020a1c1944000000b003a5a534292csi295138wmz.3.2022.09.19.03.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq3-00E2Af-Bb; Mon, 19 Sep 2022 10:17:20 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 152C9302EFA;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 29E9C2BA7B0FB; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101521.609602902@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:58 +0200
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
Subject: [PATCH v2 19/44] cpuidle,intel_idle: Fix CPUIDLE_FLAG_INIT_XSTATE
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=buhX52S0;
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

vmlinux.o: warning: objtool: intel_idle_s2idle+0xd5: call to fpu_idle_fpregs() leaves .noinstr.text section
vmlinux.o: warning: objtool: intel_idle_xstate+0x11: call to fpu_idle_fpregs() leaves .noinstr.text section
vmlinux.o: warning: objtool: fpu_idle_fpregs+0x9: call to xfeatures_in_use() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/x86/include/asm/fpu/xcr.h       |    4 ++--
 arch/x86/include/asm/special_insns.h |    2 +-
 arch/x86/kernel/fpu/core.c           |    4 ++--
 3 files changed, 5 insertions(+), 5 deletions(-)

--- a/arch/x86/include/asm/fpu/xcr.h
+++ b/arch/x86/include/asm/fpu/xcr.h
@@ -5,7 +5,7 @@
 #define XCR_XFEATURE_ENABLED_MASK	0x00000000
 #define XCR_XFEATURE_IN_USE_MASK	0x00000001
 
-static inline u64 xgetbv(u32 index)
+static __always_inline u64 xgetbv(u32 index)
 {
 	u32 eax, edx;
 
@@ -27,7 +27,7 @@ static inline void xsetbv(u32 index, u64
  *
  * Callers should check X86_FEATURE_XGETBV1.
  */
-static inline u64 xfeatures_in_use(void)
+static __always_inline u64 xfeatures_in_use(void)
 {
 	return xgetbv(XCR_XFEATURE_IN_USE_MASK);
 }
--- a/arch/x86/include/asm/special_insns.h
+++ b/arch/x86/include/asm/special_insns.h
@@ -295,7 +295,7 @@ static inline int enqcmds(void __iomem *
 	return 0;
 }
 
-static inline void tile_release(void)
+static __always_inline void tile_release(void)
 {
 	/*
 	 * Instruction opcode for TILERELEASE; supported in binutils
--- a/arch/x86/kernel/fpu/core.c
+++ b/arch/x86/kernel/fpu/core.c
@@ -856,12 +856,12 @@ int fpu__exception_code(struct fpu *fpu,
  * Initialize register state that may prevent from entering low-power idle.
  * This function will be invoked from the cpuidle driver only when needed.
  */
-void fpu_idle_fpregs(void)
+noinstr void fpu_idle_fpregs(void)
 {
 	/* Note: AMX_TILE being enabled implies XGETBV1 support */
 	if (cpu_feature_enabled(X86_FEATURE_AMX_TILE) &&
 	    (xfeatures_in_use() & XFEATURE_MASK_XTILE)) {
 		tile_release();
-		fpregs_deactivate(&current->thread.fpu);
+		__this_cpu_write(fpu_fpregs_owner_ctx, NULL);
 	}
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101521.609602902%40infradead.org.
