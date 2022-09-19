Return-Path: <kasan-dev+bncBDBK55H2UQKRBLMDUGMQMGQEZB2565A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 14A745BC646
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:18 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id l5-20020adfa385000000b0022a482f8285sf5822771wrb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582637; cv=pass;
        d=google.com; s=arc-20160816;
        b=nNNC7gcsb8h7+GUE4ecASCM38bl+/BMpExGC/0np9Y2bo+j9oowUZlvg5Ad8d3jAAt
         Df1O8c0r5122Z0MwiPKWBE4wbOjsxWW3I1+Hu0CJ3tPhiagVyEPzVwQ39JB+MtUXKip5
         xU+PwFAz60j7pGo1iMAkUA0FkEWqd35waTwT4ugvLzdQeWnoGZL9I5GHTVCEgb+4rDf8
         AgTJOGyOm3HfuNLexXUAGRMjSouCqpC/yrQn2RRMfNUbelzGNIh6/7QL+il9BCr7J+FJ
         e/G1sjVTwryb+TbSKk1kuR+PpJrahSt3H7zlAoDMPdDEUAC7nruZ5fzF5iNO/ID+MAj+
         De2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:user-agent
         :message-id:mime-version:sender:dkim-signature;
        bh=V6Fm4wIIEg3JfzRv3HUfMxBGMgHUFUvjT0fOrjJFIyU=;
        b=g9Z4rX5XSNGy+aHLaUtuP4VcigaXLoVEnyjMzpJe8mgVqzUPR319r6UMyab2gshOf7
         G/+x3Q4Z8kUUTdDpaoxq69Yr7zD/Te6j1etXB842nBMIU669/SbWR5S4jYg4/UCZwYK1
         altMPr33BgYtw88rkitj4EtdfzErnI5AKNQoa9NBOfusVScMkeVo/cSZInVleeifL7ec
         ePDWbCWwD0XlbsJg87YdnF7cxQ5TZdX/28vsdQGY+M1NIWCUCVyGxfkmhG+w/xw4lxKh
         n6EZ8RIKBv4MECqqC5RpA2Au5KgKzoAGlkGn8YYvrZvsi7EZa7l41tiUPQL8T1d6OgE5
         wjQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=cKRL+F30;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:user-agent:message-id
         :mime-version:sender:from:to:cc:subject:date;
        bh=V6Fm4wIIEg3JfzRv3HUfMxBGMgHUFUvjT0fOrjJFIyU=;
        b=G7o1b4pfxUVTTGIRbxPw+yqIo8KjsW6XP2n3zU8TLxqzCSJO8k4LTU3wAbC48s9Jdr
         oO7EWqk5IAcsC5ZkIxwv+Tn3D1dkpw7BTfBArXKU8G/5MmTjLRKcGJgZsLWeL7AEHY+r
         ezL/HqgZpjXhv3HH7j6eHgzRkZJJ6M16qqQkSRmr8ftOp8df6ef6uB/FltEerUTv/1u4
         I4n0aeBAd75yEooK9sb61/8yO2TiI40iABqJ4VIxQ9Buhl6PJ58c3LFHGKB1mPxvW2DZ
         an5ofqYbD0N+Um9qS+qhe0tmqJjU/l9lZgM/lpe3O5ceGGHklYrO0oh2iMFolx4TGPMk
         G9pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:user-agent:message-id:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date;
        bh=V6Fm4wIIEg3JfzRv3HUfMxBGMgHUFUvjT0fOrjJFIyU=;
        b=ryp2je62qndWsCAWSOYYK1pBjEtAxBBDZWayoog064ZvtW663TL6ula1iMA9mUEUmU
         WSZbWAjbTGuVgZw1qd58Y3cS0lMiKWV4Jr18vb1l+0ESjQ+ZEVdtgdfAJrhMf1hVnzZq
         wcZMsOwew0migE+/MHk4tIJPirX6UjKV9qeXCXCJAKJnMhU4E6dmq90aePVIxfLJoBrq
         nsRQV2clOVTR2yr035XAmLNmlos6uUSgFzW2STgPXBoDmsAjnqqMRUWk6fw939oRAqrL
         WrjPL1i/JIPj4IEQQ/MgQozo6U01cQxtrxU6S7Id5lrH2JHcw12HWKtKCq8UjZe0XigT
         OIcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf28yDhvqv/PCgSaibH0zBUojf9/HjPs8S2yTJbZwN4pAbjYGrns
	pW3ecWv4gAW8tgdA+FOOuc4=
X-Google-Smtp-Source: AMsMyM4kHOwAR8vW+8fRsH/BAW7OS+iXaDNTJWx4WHpc0aQK2rCCWB4xB5atr+PIrGv8E0i3MgE8QA==
X-Received: by 2002:a05:6000:1689:b0:22a:a66d:1f37 with SMTP id y9-20020a056000168900b0022aa66d1f37mr10349194wrd.197.1663582637418;
        Mon, 19 Sep 2022 03:17:17 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5123:b0:3b4:76ca:bee3 with SMTP id
 o35-20020a05600c512300b003b476cabee3ls2686424wms.0.-pod-canary-gmail; Mon, 19
 Sep 2022 03:17:16 -0700 (PDT)
X-Received: by 2002:a05:600c:4e89:b0:3b4:8648:c4e1 with SMTP id f9-20020a05600c4e8900b003b48648c4e1mr11841936wmq.26.1663582636058;
        Mon, 19 Sep 2022 03:17:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582636; cv=none;
        d=google.com; s=arc-20160816;
        b=D8oU/WWKj/WMQZkcNh9kL9gREQEMzt/fBxyLZ8NCcAQv32CMFFg06KVi3B2HWeKZFe
         kb7eyZjQFwH0p+x0j+prPFSataBszgKiUj9FJRFcxDom5+YMOeJbuabbJyBWGu4MxxpO
         gjdl5NT2PMMkP0QV+B32xP6yn5ZCO0/eDN6Ng0OIcjfxLmbAjCs4VSNswjq7l7naTxBl
         /IEWlTRFSlJR/uNOL1wZYOoGdz9XXQuctORpydd+MJ6nkNhT+n5Yt5OnzH1aBkdBBlGt
         au7JYVT4fjzyer0rkClzq1qsN/IVsfbHqbG17C+blXsEjdgbBVwHywMUNubu6j9gHRxU
         Skzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:user-agent:message-id:dkim-signature;
        bh=D+MsKiHRvmSvqyjrleqvhdKjdXvjkJhvT05d1tF3TYc=;
        b=UK3uyURfCF3weBct24q8X7VWv6nY0Wvt2BAMl3PRO2cibpsYbRrW+xuw2J104THkwV
         lY/VKOluzSdRreyk3dMHhQe8q9MWFcdp0iRAm8v472Gr5mfwm7ip/CFbXe385g3ll3B0
         Wy+nVTOgY6fY3anKfcvxt6stvIoMwOD5vq60++TMGaIrYGa/2Jhc9LKgSXzEhq8KgZqX
         I5VOBWj178n+jAT7WTdXcoPlkOdmRml6XvvVyVwu5Vuda+0ytqXh6R3GYrbCUqZn413Y
         hs3QVQhSG5DG99R7YqmN2rWxrXt2jEexV82ldbNzUIYBWyqOY23ZHac0vl8gc4MWYMdv
         Guug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=cKRL+F30;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id bz7-20020a056000090700b0022ad6de79d6si354840wrb.3.2022.09.19.03.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:16 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDpG-004ai8-KW; Mon, 19 Sep 2022 10:16:30 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id D928A300074;
	Mon, 19 Sep 2022 12:16:21 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id BF8DF2BA49033; Mon, 19 Sep 2022 12:16:21 +0200 (CEST)
Message-ID: <20220919095939.761690562@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 11:59:39 +0200
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
Subject: [PATCH v2 00/44] cpuidle,rcu: Clean up the mess
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=cKRL+F30;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Content-Type: text/plain; charset="UTF-8"
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

Hi All!

At long last, a respin of the cpuidle vs rcu cleanup patches.

v1: https://lkml.kernel.org/r/20220608142723.103523089@infradead.org

These here patches clean up the mess that is cpuidle vs rcuidle.

At the end of the ride there's only on RCU_NONIDLE user left:

  arch/arm64/kernel/suspend.c:            RCU_NONIDLE(__cpu_suspend_exit());

and 'one' trace_*_rcuidle() user:

  kernel/trace/trace_preemptirq.c:                        trace_irq_enable_rcuidle(CALLER_ADDR0, CALLER_ADDR1);
  kernel/trace/trace_preemptirq.c:                        trace_irq_disable_rcuidle(CALLER_ADDR0, CALLER_ADDR1);
  kernel/trace/trace_preemptirq.c:                        trace_irq_enable_rcuidle(CALLER_ADDR0, caller_addr);
  kernel/trace/trace_preemptirq.c:                        trace_irq_disable_rcuidle(CALLER_ADDR0, caller_addr);
  kernel/trace/trace_preemptirq.c:                trace_preempt_enable_rcuidle(a0, a1);
  kernel/trace/trace_preemptirq.c:                trace_preempt_disable_rcuidle(a0, a1);

However this last is all in deprecated code that should be unused for GENERIC_ENTRY.

I've touched a lot of code that I can't test and I might've broken something by
accident. In particular the whole ARM cpuidle stuff was quite involved.

Please all; have a look where you haven't already.


New since v1:

 - rebase on top of Frederic's rcu-context-tracking rename fest
 - more omap goodness as per the last discusion (thanks Tony!)
 - removed one more RCU_NONIDLE() from arm64/risc-v perf code
 - ubsan/kasan fixes
 - intel_idle module-param for testing
 - a bunch of extra __always_inline, because compilers are silly.

---
 arch/alpha/kernel/process.c               |  1 -
 arch/alpha/kernel/vmlinux.lds.S           |  1 -
 arch/arc/kernel/process.c                 |  3 ++
 arch/arc/kernel/vmlinux.lds.S             |  1 -
 arch/arm/include/asm/vmlinux.lds.h        |  1 -
 arch/arm/kernel/process.c                 |  1 -
 arch/arm/kernel/smp.c                     |  6 +--
 arch/arm/mach-gemini/board-dt.c           |  3 +-
 arch/arm/mach-imx/cpuidle-imx6q.c         |  4 +-
 arch/arm/mach-imx/cpuidle-imx6sx.c        |  5 ++-
 arch/arm/mach-omap2/common.h              |  6 ++-
 arch/arm/mach-omap2/cpuidle34xx.c         | 16 +++++++-
 arch/arm/mach-omap2/cpuidle44xx.c         | 29 +++++++-------
 arch/arm/mach-omap2/omap-mpuss-lowpower.c | 12 +++++-
 arch/arm/mach-omap2/pm.h                  |  2 +-
 arch/arm/mach-omap2/pm24xx.c              | 51 +-----------------------
 arch/arm/mach-omap2/pm34xx.c              | 14 +++++--
 arch/arm/mach-omap2/pm44xx.c              |  2 +-
 arch/arm/mach-omap2/powerdomain.c         | 10 ++---
 arch/arm64/kernel/idle.c                  |  1 -
 arch/arm64/kernel/smp.c                   |  4 +-
 arch/arm64/kernel/vmlinux.lds.S           |  1 -
 arch/csky/kernel/process.c                |  1 -
 arch/csky/kernel/smp.c                    |  2 +-
 arch/csky/kernel/vmlinux.lds.S            |  1 -
 arch/hexagon/kernel/process.c             |  1 -
 arch/hexagon/kernel/vmlinux.lds.S         |  1 -
 arch/ia64/kernel/process.c                |  1 +
 arch/ia64/kernel/vmlinux.lds.S            |  1 -
 arch/loongarch/kernel/idle.c              |  1 +
 arch/loongarch/kernel/vmlinux.lds.S       |  1 -
 arch/m68k/kernel/vmlinux-nommu.lds        |  1 -
 arch/m68k/kernel/vmlinux-std.lds          |  1 -
 arch/m68k/kernel/vmlinux-sun3.lds         |  1 -
 arch/microblaze/kernel/process.c          |  1 -
 arch/microblaze/kernel/vmlinux.lds.S      |  1 -
 arch/mips/kernel/idle.c                   |  8 ++--
 arch/mips/kernel/vmlinux.lds.S            |  1 -
 arch/nios2/kernel/process.c               |  1 -
 arch/nios2/kernel/vmlinux.lds.S           |  1 -
 arch/openrisc/kernel/process.c            |  1 +
 arch/openrisc/kernel/vmlinux.lds.S        |  1 -
 arch/parisc/kernel/process.c              |  2 -
 arch/parisc/kernel/vmlinux.lds.S          |  1 -
 arch/powerpc/kernel/idle.c                |  5 +--
 arch/powerpc/kernel/vmlinux.lds.S         |  1 -
 arch/riscv/kernel/process.c               |  1 -
 arch/riscv/kernel/vmlinux-xip.lds.S       |  1 -
 arch/riscv/kernel/vmlinux.lds.S           |  1 -
 arch/s390/kernel/idle.c                   |  1 -
 arch/s390/kernel/vmlinux.lds.S            |  1 -
 arch/sh/kernel/idle.c                     |  1 +
 arch/sh/kernel/vmlinux.lds.S              |  1 -
 arch/sparc/kernel/leon_pmc.c              |  4 ++
 arch/sparc/kernel/process_32.c            |  1 -
 arch/sparc/kernel/process_64.c            |  3 +-
 arch/sparc/kernel/vmlinux.lds.S           |  1 -
 arch/um/kernel/dyn.lds.S                  |  1 -
 arch/um/kernel/process.c                  |  1 -
 arch/um/kernel/uml.lds.S                  |  1 -
 arch/x86/boot/compressed/vmlinux.lds.S    |  1 +
 arch/x86/coco/tdx/tdcall.S                | 15 +------
 arch/x86/coco/tdx/tdx.c                   | 25 ++++--------
 arch/x86/events/amd/brs.c                 | 13 +++----
 arch/x86/include/asm/fpu/xcr.h            |  4 +-
 arch/x86/include/asm/irqflags.h           | 11 ++----
 arch/x86/include/asm/mwait.h              | 14 +++----
 arch/x86/include/asm/nospec-branch.h      |  2 +-
 arch/x86/include/asm/paravirt.h           |  6 ++-
 arch/x86/include/asm/perf_event.h         |  2 +-
 arch/x86/include/asm/shared/io.h          |  4 +-
 arch/x86/include/asm/shared/tdx.h         |  1 -
 arch/x86/include/asm/special_insns.h      |  8 ++--
 arch/x86/include/asm/xen/hypercall.h      |  2 +-
 arch/x86/kernel/cpu/bugs.c                |  2 +-
 arch/x86/kernel/fpu/core.c                |  4 +-
 arch/x86/kernel/paravirt.c                | 14 ++++++-
 arch/x86/kernel/process.c                 | 65 +++++++++++++++----------------
 arch/x86/kernel/vmlinux.lds.S             |  1 -
 arch/x86/lib/memcpy_64.S                  |  5 +--
 arch/x86/lib/memmove_64.S                 |  4 +-
 arch/x86/lib/memset_64.S                  |  4 +-
 arch/x86/xen/enlighten_pv.c               |  2 +-
 arch/x86/xen/irq.c                        |  2 +-
 arch/xtensa/kernel/process.c              |  1 +
 arch/xtensa/kernel/vmlinux.lds.S          |  1 -
 drivers/acpi/processor_idle.c             | 36 ++++++++++-------
 drivers/base/power/runtime.c              | 24 ++++++------
 drivers/clk/clk.c                         |  8 ++--
 drivers/cpuidle/cpuidle-arm.c             |  1 +
 drivers/cpuidle/cpuidle-big_little.c      |  8 +++-
 drivers/cpuidle/cpuidle-mvebu-v7.c        |  7 ++++
 drivers/cpuidle/cpuidle-psci.c            | 10 +++--
 drivers/cpuidle/cpuidle-qcom-spm.c        |  1 +
 drivers/cpuidle/cpuidle-riscv-sbi.c       | 10 +++--
 drivers/cpuidle/cpuidle-tegra.c           | 21 +++++++---
 drivers/cpuidle/cpuidle.c                 | 21 +++++-----
 drivers/cpuidle/dt_idle_states.c          |  2 +-
 drivers/cpuidle/poll_state.c              | 10 ++++-
 drivers/idle/intel_idle.c                 | 19 +++++----
 drivers/perf/arm_pmu.c                    | 11 +-----
 drivers/perf/riscv_pmu_sbi.c              |  8 +---
 include/asm-generic/vmlinux.lds.h         |  9 ++---
 include/linux/compiler_types.h            |  8 +++-
 include/linux/cpu.h                       |  3 --
 include/linux/cpuidle.h                   | 34 ++++++++++++++++
 include/linux/cpumask.h                   |  4 +-
 include/linux/percpu-defs.h               |  2 +-
 include/linux/sched/idle.h                | 40 ++++++++++++++-----
 include/linux/thread_info.h               | 18 ++++++++-
 include/linux/tracepoint.h                | 13 ++++++-
 kernel/cpu_pm.c                           |  9 -----
 kernel/printk/printk.c                    |  2 +-
 kernel/sched/idle.c                       | 47 +++++++---------------
 kernel/time/tick-broadcast-hrtimer.c      | 29 ++++++--------
 kernel/time/tick-broadcast.c              |  6 ++-
 kernel/trace/trace.c                      |  3 ++
 lib/ubsan.c                               |  5 ++-
 mm/kasan/kasan.h                          |  4 ++
 mm/kasan/shadow.c                         | 38 ++++++++++++++++++
 tools/objtool/check.c                     | 17 ++++++++
 121 files changed, 511 insertions(+), 420 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919095939.761690562%40infradead.org.
