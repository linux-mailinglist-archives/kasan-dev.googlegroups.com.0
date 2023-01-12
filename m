Return-Path: <kasan-dev+bncBDBK55H2UQKRB4GMQGPAMGQERVECTBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 56F4D668013
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:41 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id bi11-20020a05600c3d8b00b003d9ebf905c9sf7129341wmb.5
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553521; cv=pass;
        d=google.com; s=arc-20160816;
        b=GSqWvVQ61xQEAF5KcVyH4+o81GI8xXALDD73Ja8Y/R6HqstHENLnnMFwZqzJRffWBT
         VgyvOVBmPTfajmaXEaR7Izo7WYCAHZXjF00yNKolWnGxA+mG2PYcx2PhDJkjsz6HA9bV
         HQEfRI47LryAQoI8Q1RYdedI30sWwwHRkuwvxewOXNf2whrtk/e1lia0tg3ui5BJbInm
         9xoOnvz9T5g9IK89w1mRoamppxCmUzGVJYON+93Jvw/ssk8VTV9fvrzHaufoXeg+QML1
         nPtQBZxu8Ey+MHRyTdYxb3Jr78dlONMR6ZL+SNUBULi2y/mCVpXWy2ttrXlFHSDAy6Zg
         6ioQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=rsTNJ1ejqZzVy0ZTSWKyaZEsBoLlpwnKwIZG+8irmE8=;
        b=bYJkQlu92jgvVe7HraafCg4/rDtvv75ziN3CMNm4LmAWnB56YJigQ5b1NmEbw121Em
         qkxWDIafDJxy7n7XPhn/9znpn2FQOr56ukQvMOCbF5rCAPDnou71sDoES2+7udl9jGrc
         dMHtCQDPiDgJPYLVu6k6DFFnDXTyrgqdXhoCYqkSCKQQ6bf6gLyhCtQWnj4BE8CHGLUC
         ZUIWZ1H5Seki6nG6+7kYln4iJpWEbcY3C3R9lie5J5eGHLFsvOUx/PkT6cRtYCmPF4/R
         gfPGWWPKORQP/8ZbEHEwhJT37bZnFwTX5luMQXciSEjVulVzEmqErb8Ilq4xUlPjR9H3
         s7FQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=iJIkTt+7;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rsTNJ1ejqZzVy0ZTSWKyaZEsBoLlpwnKwIZG+8irmE8=;
        b=UM0EtPbHm1heZINJmRDq4lwqcWkKt8nipwYixplcbXw1zWyCg0Kzw6yPr5fvVJwnPU
         t4wWJh1qpXr+x6wV/qr0Dc6vhcDQr07iA9rOoT5Gh5A6Yf+sFq1pszoPMMnz2VML3z5l
         jd4iD8CL1cC6fy5vcyJnEweRX4c6zxlxpdVO7dhxQSM2NE5TvCr/O+IYIfi8rKfASt17
         Vd1sTz4vJVM1RxyrVe76wQ/WxDKsrvOVUOq0jkid8S+q249aHPyGyiaYsIoWzdTHgDVh
         42ad7s5EuVo6xO8Tdf4Q3igTzEItEsfsjs6IH5ulXzyP6sm7BlCXwYC2DUh3XYZ6G1GD
         s4kA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rsTNJ1ejqZzVy0ZTSWKyaZEsBoLlpwnKwIZG+8irmE8=;
        b=WfJLLoSmyvP6HfBANmJ72ZrDrZtJAuRSVKnduDIjWcV5v1lP3/5FKTx8q8KLF4fkhP
         7a8RIyV09Af3U8Q8l9D/aZjlNyiu7U4MMOBzQilbsSZrZkWLnVUZFkN5nZOqNhhbwekV
         qHMmYEuEIQY5HFxMfLHsHfAemI4ibrPaPmfCh1wKiH53KdUQcpxXNq7qgrVC5czMhUVU
         SipS44RHu4Kf65E2PRgLHolDfP5tUYknMH4jBDZbFmsx3oI2OghDDiZTvQlTFOpTGAXs
         FObHrckYrBp2GXTSc9sEfR/3mpkpFl/9umvsKdyOAOtYb42/15s5LBU4SZYXU8a7W0VY
         xx4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koGK2NPT9OXRIkPO9vjsnmwTEiQc9GH3KNyHMdQNp+4l58nhfzQ
	s6yrfAlzBAmXNwyvNHbn1xM=
X-Google-Smtp-Source: AMrXdXu8e7YcdXXGn4v/I3BOqboYSFRgQ/+mSLVmn+h9FQRLWH7PusnzhzpeDpy8LzaIctXBLqR92w==
X-Received: by 2002:a05:600c:4c22:b0:3cf:f2aa:3dc2 with SMTP id d34-20020a05600c4c2200b003cff2aa3dc2mr4163963wmp.175.1673553520913;
        Thu, 12 Jan 2023 11:58:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4081:0:b0:225:6559:3374 with SMTP id o1-20020a5d4081000000b0022565593374ls1472529wrp.2.-pod-prod-gmail;
 Thu, 12 Jan 2023 11:58:39 -0800 (PST)
X-Received: by 2002:a5d:6987:0:b0:2bb:338e:3f2b with SMTP id g7-20020a5d6987000000b002bb338e3f2bmr15303987wru.55.1673553519861;
        Thu, 12 Jan 2023 11:58:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553519; cv=none;
        d=google.com; s=arc-20160816;
        b=TYr6ZkjW6QqNHOAaB9SoN8uMs4JdhfVLWBRl7ZrWBqBNW+KP1p+S4tQnwEraYSKICl
         ig0q0cntTSKunM+YwdcPUA0gOTCDphypctkxX8+9OzbPR7Lr3Pbmu1gSArqzSjRySWB2
         TnFJ5BemWAJzJqrfL+/iMuLS3G0+sQkQDySG0O5f0edJ+V/4OzlC09rh8s+qBvZu9WQw
         rT7uc3go/Yvaj1X8paRiDpEeFsDJjOGYEefu/MqiUbFGtEsynhEkivy6ET9gGG9111mD
         dmLkcejrJg0TanOC8yRFI9D21A3DqqhGg/nBozOemdZbEnwFatemPNg1hw/MWpjQ7jbs
         ptrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=A36GBNDeZcYlVC8rkRiSg7Fkb66ciqPmteGiazOXnKo=;
        b=jAAFD96zdvNRNwQ2T/aFpIBfsLIysKgUzu9OGu8CtulqKr26TdBwhX5g6Ni5HalTxk
         +EKdemQOdRG9iiyVHxaLXaE5GSSFFXpoU+HACECK4bhqfDxsvsWl7TxB6VbchaJzGJ+x
         9vJe4GuvI0kGBnghrZqIpMUJr+o04tbsoff92VXkkGT848ep81O1ee0h9TpW+q+dMsxQ
         0I3WKl1f8oK6bj9XuiPwJcm9L4nYgcEOwLv5DKH5eapjfaJMDeYpo/lwuwdqU/V/5QLl
         viF3i/ruhVjhiqdL16xfeLQ1PUOGAavYywINkiLJ0sFoE8OO17erwd/T7kvuBGpL2n/N
         c30Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=iJIkTt+7;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id bw27-20020a0560001f9b00b0029c9b8d8aafsi689110wrb.6.2023.01.12.11.58.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:39 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hE-0045oX-2P;
	Thu, 12 Jan 2023 19:57:09 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 49A6330341B;
	Thu, 12 Jan 2023 20:57:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id DFC6A2CCF1F66; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112195540.373461409@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:31 +0100
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
Subject: [PATCH v3 17/51] objtool/idle: Validate __cpuidle code as noinstr
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=iJIkTt+7;
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

Idle code is very like entry code in that RCU isn't available. As
such, add a little validation.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Geert Uytterhoeven <geert@linux-m68k.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/alpha/kernel/vmlinux.lds.S      |    1 -
 arch/arc/kernel/vmlinux.lds.S        |    1 -
 arch/arm/include/asm/vmlinux.lds.h   |    1 -
 arch/arm64/kernel/vmlinux.lds.S      |    1 -
 arch/csky/kernel/vmlinux.lds.S       |    1 -
 arch/hexagon/kernel/vmlinux.lds.S    |    1 -
 arch/ia64/kernel/vmlinux.lds.S       |    1 -
 arch/loongarch/kernel/vmlinux.lds.S  |    1 -
 arch/m68k/kernel/vmlinux-nommu.lds   |    1 -
 arch/m68k/kernel/vmlinux-std.lds     |    1 -
 arch/m68k/kernel/vmlinux-sun3.lds    |    1 -
 arch/microblaze/kernel/vmlinux.lds.S |    1 -
 arch/mips/kernel/vmlinux.lds.S       |    1 -
 arch/nios2/kernel/vmlinux.lds.S      |    1 -
 arch/openrisc/kernel/vmlinux.lds.S   |    1 -
 arch/parisc/kernel/vmlinux.lds.S     |    1 -
 arch/powerpc/kernel/vmlinux.lds.S    |    1 -
 arch/riscv/kernel/vmlinux-xip.lds.S  |    1 -
 arch/riscv/kernel/vmlinux.lds.S      |    1 -
 arch/s390/kernel/vmlinux.lds.S       |    1 -
 arch/sh/kernel/vmlinux.lds.S         |    1 -
 arch/sparc/kernel/vmlinux.lds.S      |    1 -
 arch/um/kernel/dyn.lds.S             |    1 -
 arch/um/kernel/uml.lds.S             |    1 -
 arch/x86/include/asm/irqflags.h      |   11 ++++-------
 arch/x86/include/asm/mwait.h         |    2 +-
 arch/x86/kernel/vmlinux.lds.S        |    1 -
 arch/xtensa/kernel/vmlinux.lds.S     |    1 -
 include/asm-generic/vmlinux.lds.h    |    9 +++------
 include/linux/compiler_types.h       |    8 ++++++--
 include/linux/cpu.h                  |    3 ---
 tools/objtool/check.c                |   13 +++++++++++++
 32 files changed, 27 insertions(+), 45 deletions(-)

--- a/arch/alpha/kernel/vmlinux.lds.S
+++ b/arch/alpha/kernel/vmlinux.lds.S
@@ -27,7 +27,6 @@ SECTIONS
 		HEAD_TEXT
 		TEXT_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		*(.fixup)
 		*(.gnu.warning)
--- a/arch/arc/kernel/vmlinux.lds.S
+++ b/arch/arc/kernel/vmlinux.lds.S
@@ -85,7 +85,6 @@ SECTIONS
 		_stext = .;
 		TEXT_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		KPROBES_TEXT
 		IRQENTRY_TEXT
--- a/arch/arm/include/asm/vmlinux.lds.h
+++ b/arch/arm/include/asm/vmlinux.lds.h
@@ -96,7 +96,6 @@
 		SOFTIRQENTRY_TEXT					\
 		TEXT_TEXT						\
 		SCHED_TEXT						\
-		CPUIDLE_TEXT						\
 		LOCK_TEXT						\
 		KPROBES_TEXT						\
 		ARM_STUBS_TEXT						\
--- a/arch/arm64/kernel/vmlinux.lds.S
+++ b/arch/arm64/kernel/vmlinux.lds.S
@@ -175,7 +175,6 @@ SECTIONS
 			ENTRY_TEXT
 			TEXT_TEXT
 			SCHED_TEXT
-			CPUIDLE_TEXT
 			LOCK_TEXT
 			KPROBES_TEXT
 			HYPERVISOR_TEXT
--- a/arch/csky/kernel/vmlinux.lds.S
+++ b/arch/csky/kernel/vmlinux.lds.S
@@ -34,7 +34,6 @@ SECTIONS
 		SOFTIRQENTRY_TEXT
 		TEXT_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		KPROBES_TEXT
 		*(.fixup)
--- a/arch/hexagon/kernel/vmlinux.lds.S
+++ b/arch/hexagon/kernel/vmlinux.lds.S
@@ -41,7 +41,6 @@ SECTIONS
 		IRQENTRY_TEXT
 		SOFTIRQENTRY_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		KPROBES_TEXT
 		*(.fixup)
--- a/arch/ia64/kernel/vmlinux.lds.S
+++ b/arch/ia64/kernel/vmlinux.lds.S
@@ -51,7 +51,6 @@ SECTIONS {
 		__end_ivt_text = .;
 		TEXT_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		KPROBES_TEXT
 		IRQENTRY_TEXT
--- a/arch/loongarch/kernel/vmlinux.lds.S
+++ b/arch/loongarch/kernel/vmlinux.lds.S
@@ -42,7 +42,6 @@ SECTIONS
 	.text : {
 		TEXT_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		KPROBES_TEXT
 		IRQENTRY_TEXT
--- a/arch/m68k/kernel/vmlinux-nommu.lds
+++ b/arch/m68k/kernel/vmlinux-nommu.lds
@@ -48,7 +48,6 @@ SECTIONS {
 		IRQENTRY_TEXT
 		SOFTIRQENTRY_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		*(.fixup)
 		. = ALIGN(16);
--- a/arch/m68k/kernel/vmlinux-std.lds
+++ b/arch/m68k/kernel/vmlinux-std.lds
@@ -19,7 +19,6 @@ SECTIONS
 	IRQENTRY_TEXT
 	SOFTIRQENTRY_TEXT
 	SCHED_TEXT
-	CPUIDLE_TEXT
 	LOCK_TEXT
 	*(.fixup)
 	*(.gnu.warning)
--- a/arch/m68k/kernel/vmlinux-sun3.lds
+++ b/arch/m68k/kernel/vmlinux-sun3.lds
@@ -19,7 +19,6 @@ SECTIONS
 	IRQENTRY_TEXT
 	SOFTIRQENTRY_TEXT
 	SCHED_TEXT
-	CPUIDLE_TEXT
 	LOCK_TEXT
 	*(.fixup)
 	*(.gnu.warning)
--- a/arch/microblaze/kernel/vmlinux.lds.S
+++ b/arch/microblaze/kernel/vmlinux.lds.S
@@ -36,7 +36,6 @@ SECTIONS {
 		EXIT_TEXT
 		EXIT_CALL
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		KPROBES_TEXT
 		IRQENTRY_TEXT
--- a/arch/mips/kernel/vmlinux.lds.S
+++ b/arch/mips/kernel/vmlinux.lds.S
@@ -61,7 +61,6 @@ SECTIONS
 	.text : {
 		TEXT_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		KPROBES_TEXT
 		IRQENTRY_TEXT
--- a/arch/nios2/kernel/vmlinux.lds.S
+++ b/arch/nios2/kernel/vmlinux.lds.S
@@ -24,7 +24,6 @@ SECTIONS
 	.text : {
 		TEXT_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		IRQENTRY_TEXT
 		SOFTIRQENTRY_TEXT
--- a/arch/openrisc/kernel/vmlinux.lds.S
+++ b/arch/openrisc/kernel/vmlinux.lds.S
@@ -52,7 +52,6 @@ SECTIONS
           _stext = .;
 	  TEXT_TEXT
 	  SCHED_TEXT
-	  CPUIDLE_TEXT
 	  LOCK_TEXT
 	  KPROBES_TEXT
 	  IRQENTRY_TEXT
--- a/arch/parisc/kernel/vmlinux.lds.S
+++ b/arch/parisc/kernel/vmlinux.lds.S
@@ -86,7 +86,6 @@ SECTIONS
 		TEXT_TEXT
 		LOCK_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		KPROBES_TEXT
 		IRQENTRY_TEXT
 		SOFTIRQENTRY_TEXT
--- a/arch/powerpc/kernel/vmlinux.lds.S
+++ b/arch/powerpc/kernel/vmlinux.lds.S
@@ -111,7 +111,6 @@ SECTIONS
 #endif
 		NOINSTR_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		KPROBES_TEXT
 		IRQENTRY_TEXT
--- a/arch/riscv/kernel/vmlinux-xip.lds.S
+++ b/arch/riscv/kernel/vmlinux-xip.lds.S
@@ -39,7 +39,6 @@ SECTIONS
 		_stext = .;
 		TEXT_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		KPROBES_TEXT
 		ENTRY_TEXT
--- a/arch/riscv/kernel/vmlinux.lds.S
+++ b/arch/riscv/kernel/vmlinux.lds.S
@@ -42,7 +42,6 @@ SECTIONS
 		_stext = .;
 		TEXT_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		KPROBES_TEXT
 		ENTRY_TEXT
--- a/arch/s390/kernel/vmlinux.lds.S
+++ b/arch/s390/kernel/vmlinux.lds.S
@@ -42,7 +42,6 @@ SECTIONS
 		HEAD_TEXT
 		TEXT_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		KPROBES_TEXT
 		IRQENTRY_TEXT
--- a/arch/sh/kernel/vmlinux.lds.S
+++ b/arch/sh/kernel/vmlinux.lds.S
@@ -29,7 +29,6 @@ SECTIONS
 		HEAD_TEXT
 		TEXT_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		KPROBES_TEXT
 		IRQENTRY_TEXT
--- a/arch/sparc/kernel/vmlinux.lds.S
+++ b/arch/sparc/kernel/vmlinux.lds.S
@@ -50,7 +50,6 @@ SECTIONS
 		HEAD_TEXT
 		TEXT_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		KPROBES_TEXT
 		IRQENTRY_TEXT
--- a/arch/um/kernel/dyn.lds.S
+++ b/arch/um/kernel/dyn.lds.S
@@ -74,7 +74,6 @@ SECTIONS
     _stext = .;
     TEXT_TEXT
     SCHED_TEXT
-    CPUIDLE_TEXT
     LOCK_TEXT
     IRQENTRY_TEXT
     SOFTIRQENTRY_TEXT
--- a/arch/um/kernel/uml.lds.S
+++ b/arch/um/kernel/uml.lds.S
@@ -35,7 +35,6 @@ SECTIONS
     _stext = .;
     TEXT_TEXT
     SCHED_TEXT
-    CPUIDLE_TEXT
     LOCK_TEXT
     IRQENTRY_TEXT
     SOFTIRQENTRY_TEXT
--- a/arch/x86/include/asm/irqflags.h
+++ b/arch/x86/include/asm/irqflags.h
@@ -8,9 +8,6 @@
 
 #include <asm/nospec-branch.h>
 
-/* Provide __cpuidle; we can't safely include <linux/cpu.h> */
-#define __cpuidle __section(".cpuidle.text")
-
 /*
  * Interrupt control:
  */
@@ -45,13 +42,13 @@ static __always_inline void native_irq_e
 	asm volatile("sti": : :"memory");
 }
 
-static inline __cpuidle void native_safe_halt(void)
+static __always_inline void native_safe_halt(void)
 {
 	mds_idle_clear_cpu_buffers();
 	asm volatile("sti; hlt": : :"memory");
 }
 
-static inline __cpuidle void native_halt(void)
+static __always_inline void native_halt(void)
 {
 	mds_idle_clear_cpu_buffers();
 	asm volatile("hlt": : :"memory");
@@ -84,7 +81,7 @@ static __always_inline void arch_local_i
  * Used in the idle loop; sti takes one instruction cycle
  * to complete:
  */
-static inline __cpuidle void arch_safe_halt(void)
+static __always_inline void arch_safe_halt(void)
 {
 	native_safe_halt();
 }
@@ -93,7 +90,7 @@ static inline __cpuidle void arch_safe_h
  * Used when interrupts are already enabled or to
  * shutdown the processor:
  */
-static inline __cpuidle void halt(void)
+static __always_inline void halt(void)
 {
 	native_halt();
 }
--- a/arch/x86/include/asm/mwait.h
+++ b/arch/x86/include/asm/mwait.h
@@ -105,7 +105,7 @@ static inline void __sti_mwait(unsigned
  * New with Core Duo processors, MWAIT can take some hints based on CPU
  * capability.
  */
-static inline void mwait_idle_with_hints(unsigned long eax, unsigned long ecx)
+static __always_inline void mwait_idle_with_hints(unsigned long eax, unsigned long ecx)
 {
 	if (static_cpu_has_bug(X86_BUG_MONITOR) || !current_set_polling_and_test()) {
 		if (static_cpu_has_bug(X86_BUG_CLFLUSH_MONITOR)) {
--- a/arch/x86/kernel/vmlinux.lds.S
+++ b/arch/x86/kernel/vmlinux.lds.S
@@ -129,7 +129,6 @@ SECTIONS
 		HEAD_TEXT
 		TEXT_TEXT
 		SCHED_TEXT
-		CPUIDLE_TEXT
 		LOCK_TEXT
 		KPROBES_TEXT
 		SOFTIRQENTRY_TEXT
--- a/arch/xtensa/kernel/vmlinux.lds.S
+++ b/arch/xtensa/kernel/vmlinux.lds.S
@@ -125,7 +125,6 @@ SECTIONS
     ENTRY_TEXT
     TEXT_TEXT
     SCHED_TEXT
-    CPUIDLE_TEXT
     LOCK_TEXT
     *(.fixup)
   }
--- a/include/asm-generic/vmlinux.lds.h
+++ b/include/asm-generic/vmlinux.lds.h
@@ -580,6 +580,9 @@
 		ALIGN_FUNCTION();					\
 		__noinstr_text_start = .;				\
 		*(.noinstr.text)					\
+		__cpuidle_text_start = .;				\
+		*(.cpuidle.text)					\
+		__cpuidle_text_end = .;					\
 		__noinstr_text_end = .;
 
 /*
@@ -620,12 +623,6 @@
 		*(.spinlock.text)					\
 		__lock_text_end = .;
 
-#define CPUIDLE_TEXT							\
-		ALIGN_FUNCTION();					\
-		__cpuidle_text_start = .;				\
-		*(.cpuidle.text)					\
-		__cpuidle_text_end = .;
-
 #define KPROBES_TEXT							\
 		ALIGN_FUNCTION();					\
 		__kprobes_text_start = .;				\
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -232,11 +232,15 @@ struct ftrace_likely_data {
 #endif
 
 /* Section for code which can't be instrumented at all */
-#define noinstr								\
-	noinline notrace __attribute((__section__(".noinstr.text")))	\
+#define __noinstr_section(section)					\
+	noinline notrace __attribute((__section__(section)))		\
 	__no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
 	__no_sanitize_memory
 
+#define noinstr __noinstr_section(".noinstr.text")
+
+#define __cpuidle __noinstr_section(".cpuidle.text")
+
 #endif /* __KERNEL__ */
 
 #endif /* __ASSEMBLY__ */
--- a/include/linux/cpu.h
+++ b/include/linux/cpu.h
@@ -176,9 +176,6 @@ void __noreturn cpu_startup_entry(enum c
 
 void cpu_idle_poll_ctrl(bool enable);
 
-/* Attach to any functions which should be considered cpuidle. */
-#define __cpuidle	__section(".cpuidle.text")
-
 bool cpu_in_idle(unsigned long pc);
 
 void arch_cpu_idle(void);
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -376,6 +376,7 @@ static int decode_instructions(struct ob
 
 		if (!strcmp(sec->name, ".noinstr.text") ||
 		    !strcmp(sec->name, ".entry.text") ||
+		    !strcmp(sec->name, ".cpuidle.text") ||
 		    !strncmp(sec->name, ".text.__x86.", 12))
 			sec->noinstr = true;
 
@@ -3361,6 +3362,12 @@ static inline bool noinstr_call_dest(str
 		return true;
 
 	/*
+	 * If the symbol is a static_call trampoline, we can't tell.
+	 */
+	if (func->static_call_tramp)
+		return true;
+
+	/*
 	 * The __ubsan_handle_*() calls are like WARN(), they only happen when
 	 * something 'BAD' happened. At the risk of taking the machine down,
 	 * let them proceed to get the message out.
@@ -4155,6 +4162,12 @@ static int validate_noinstr_sections(str
 	if (sec) {
 		warnings += validate_section(file, sec);
 		warnings += validate_unwind_hints(file, sec);
+	}
+
+	sec = find_section_by_name(file->elf, ".cpuidle.text");
+	if (sec) {
+		warnings += validate_section(file, sec);
+		warnings += validate_unwind_hints(file, sec);
 	}
 
 	return warnings;


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195540.373461409%40infradead.org.
