Return-Path: <kasan-dev+bncBDBK55H2UQKRB2WMQGPAMGQE5YWVWIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id AB32D667FF0
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:35 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id x7-20020ac24887000000b004cb10694f9bsf7290550lfc.6
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553515; cv=pass;
        d=google.com; s=arc-20160816;
        b=c1I34h0h0BeE17K7weS2LM45auG9A6XQDWaQojlWXGFYy7bqb0vGUs5NVuGjoH04zL
         bMWpPK6hI9gxpd8MsWvo6lKGExVJiefFT4FrkGlTC0//56FHialYY0JU+KGxXjAlkDZm
         jkvtA8TSyakn65v2gfylSA/S8tE5xDqWBv43GCaNUG8yf0B4Tocf34OBg1kT3Cc/zai9
         JJomxwEuwButPqNtL48WnHkSQIEGq9jO0nQRgdu7Fa04uYzddKsv1AKoAhkvv0P0JTLV
         xSGGT3uVVoZnbD6f4d+MpCf5RC54i735P7GwDT8vbnrfaWxuFl13JK8og1shkkKdWVyS
         x4Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:user-agent
         :message-id:mime-version:sender:dkim-signature;
        bh=Jh1HoGXi9pLJHXybLeW4FocSAG8jZQk+xVSY5vhiY4o=;
        b=evQh49Wlu03e2qgOR1wnvJNobAz+/kxr2rxfNgK4rWj1g48X/wZFt14zZGeDOLJIBJ
         UJrfhLf0xSg9KytQhnWHflOlNza0bCy+nPW6dhaFBWh9m3V0dhm7i7l3AA6O8FRcN+Wh
         9E6jVCd5ZC0wk6g5UqF0jcFndT/HX0fJk5df6NtPZVIogVvG/aqPNqaBMbC3sfAtT5Fc
         oXCyxW9Sbd1CCIFx8+GUm8StuPHpPAVZfBSwaKUp/W1AM7siKiz5yM7930DrUu70r2hE
         zgZhQ3j6Jl8vCg5vEllmdovw0dsm3ttQ17RzGfzT9sf4cLk2lnj15tG+TDyjQ2tppMVI
         srYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=YEW7kFaH;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:user-agent:message-id
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Jh1HoGXi9pLJHXybLeW4FocSAG8jZQk+xVSY5vhiY4o=;
        b=h9FH5KLuJTgXP7Fb4QFy+2HxK4/+W8g+czbbph5uAUaSJIjK5WX8YSzwn7Wh0J005k
         X5rQ3Aerqvbc77eLucAvNKX1U6Rd1ysEHhSHQSver+bzYmqs7wJt0nhcuLIpc5dtuUaD
         9ehKyt/Pb0hZEXv3/wgxb/pci3eYae2fZmWt9my84ozYS+9rSUtq6YhatcEv4B4a8jOK
         /ENEz1rFabgFEuzMlR1EUMah6TyErtuGBzmzBxMyEjXDD8n3C26d1DW7+YVw0IenJaXF
         bF67pyUM6wrw11oP2Eh1pCArThg/PgPh9+kdt7D6aJhxp7jXPNiIPWY1ak3G8M+fBLj2
         8/tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:user-agent:message-id:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Jh1HoGXi9pLJHXybLeW4FocSAG8jZQk+xVSY5vhiY4o=;
        b=xwJA/U2ZhnQfzmZmgYUkR8rdIMMPP5SGOkNAvTWV2arLEcEsG5a8LF7OlTAKkuX54j
         483cGLDnxrUVVdX5ZbhBkKJQysxa96vT6TziM8UQ7sDS6bnpDAzuCqkntuy076pjbGy7
         WvxpCl72zamDElsEI7r7+0cRxWY37idctM9WDHupV9e/9pK4lDAbgUdC0bfmEr7RSMZ7
         5vrHl3t68+4GvXyJeMu1tyVa0fQ/gdltmy69TxAaG7vOCCEPMhukUY9XfmoAFim7gqth
         HUAHZ7tRoyc20jLTlOqKPvJfK93/CnXGC0Sg48A6QUjCDOo+iAttCq0QgffV+JJzsLk2
         kfWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpwCZrOoDddgRcFt8ZoKYEq3ogGserPqhLCWoHWQek4CalqGMr8
	56FcVxFcDT7CnVQTh6WYXcg=
X-Google-Smtp-Source: AMrXdXs8FzrZClpauD9LJw2BjKGGc2xotD2VedGi2B+bBlpMGSPaAnYAB7vxEd124VrfwtTXXdhPKw==
X-Received: by 2002:a05:651c:221e:b0:27f:c88b:5ba4 with SMTP id y30-20020a05651c221e00b0027fc88b5ba4mr2865555ljq.446.1673553514927;
        Thu, 12 Jan 2023 11:58:34 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1182:b0:4b5:3cdf:5a65 with SMTP id
 g2-20020a056512118200b004b53cdf5a65ls1755063lfr.2.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:33 -0800 (PST)
X-Received: by 2002:a05:6512:12c2:b0:4ce:88af:473b with SMTP id p2-20020a05651212c200b004ce88af473bmr489278lfg.54.1673553513475;
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553513; cv=none;
        d=google.com; s=arc-20160816;
        b=ztvmJiIQMb7VlLAi9eIOF60JYi6XEVABMgezI8HHfWnPg9eCD1YlLEglqz8RrbS+16
         OekBntZIyfvy6qSkrHIQ4l3WkoA8FJ92JjGL44pzWV7DzNGJQWPWc/J50QEqzapChooM
         mWu18fwyjsbmUVBWo5eXL9AzsE/dTX8ybR0EQHrkDJmf3VibjhIPn5sMxQ9Zq/Q/KH3b
         u6ykyyFad7gVOMv2OJu1PEgQK1eJSYxcSPNw9e/u3yW9SCRSpEWV3bkoLIFthaq2KVG2
         Xc3v0lQBIYrXYz6wxtbQHZS03ZE2WHk4EriSIQ0pq53av4GVuAu9yPPb3gIGNz5N3IHC
         LyDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:user-agent:message-id:dkim-signature;
        bh=nVA2Mm1l3YORbADd6moHHe8hZRGP2vbv/t+d/ET+JHY=;
        b=TY0xUt2CzduH7nps7X+JPOc78gVeBe/XX+6uAQmIq/Dp9w7LMGMd5CR4DCcVeyONhO
         wg75I7v8o1XHU0YcKmEHf7RBh/JgzP8v5JbULnBE/hYvMtt091ifhM9X8u6+aldqD4Xu
         K1euYFONa12t+W9dsc51LYX/gGs+lKf/1hlSPFEKKZAD4s6+4/mYosAfYlbvoubN2gK7
         eliGFP/e8RUqOkKJbYux5hokSpRgUavlHRk+UW3zsDFIArT/0vvibM2hWWkzsO1jGM0w
         SpXeyXrIp6B5bGDFBR3vGLBR1OHZKuEOsLIPqsRqzcgcgkgKhdsNv6xHL8W9jhIvYeBQ
         jhFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=YEW7kFaH;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id v9-20020a05651203a900b004cfb4a3fc7esi13614lfp.8.2023.01.12.11.58.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hW-005OcE-N8; Thu, 12 Jan 2023 19:57:26 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id A2F1D30012F;
	Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 892382CCF1F46; Thu, 12 Jan 2023 20:57:07 +0100 (CET)
Message-ID: <20230112194314.845371875@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:14 +0100
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
Subject: [PATCH v3 00/51] cpuidle,rcu: Clean up the mess
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=YEW7kFaH;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

The (hopefully) final respin of cpuidle vs rcu cleanup patches. Barring any
objections I'll be queueing these patches in tip/sched/core in the next few
days.

v2: https://lkml.kernel.org/r/20220919095939.761690562@infradead.org

These here patches clean up the mess that is cpuidle vs rcuidle.

At the end of the ride there's only on RCU_NONIDLE user left:

  arch/arm64/kernel/suspend.c:            RCU_NONIDLE(__cpu_suspend_exit());

And I know Mark has been prodding that with something sharp.

The last version was tested by a number of people and I'm hoping to not have
broken anything in the meantime ;-)


Changes since v2:

 - rebased to v6.2-rc3; as available at:
     git://git.kernel.org/pub/scm/linux/kernel/git/peterz/queue.git sched/idle

 - folded: https://lkml.kernel.org/r/Y3UBwYNY15ETUKy9@hirez.programming.kicks-ass.net
   which makes the ARM cpuidle index 0 consistently not use
   CPUIDLE_FLAG_RCU_IDLE, as requested by Ulf.

 - added a few more __always_inline to empty stub functions as found by the
   robot.

 - Used _RET_IP_ instead of _THIS_IP_ in a few placed because of:
   https://github.com/ClangBuiltLinux/linux/issues/263

 - Added new patches to address various robot reports:

     #35:  trace,hardirq: No moar _rcuidle() tracing
     #47:  cpuidle: Ensure ct_cpuidle_enter() is always called from noinstr/__cpuidle
     #48:  cpuidle,arch: Mark all ct_cpuidle_enter() callers __cpuidle
     #49:  cpuidle,arch: Mark all regular cpuidle_state::enter methods __cpuidle
     #50:  cpuidle: Comments about noinstr/__cpuidle
     #51:  context_tracking: Fix noinstr vs KASAN


---
 arch/alpha/kernel/process.c               |  1 -
 arch/alpha/kernel/vmlinux.lds.S           |  1 -
 arch/arc/kernel/process.c                 |  3 ++
 arch/arc/kernel/vmlinux.lds.S             |  1 -
 arch/arm/include/asm/vmlinux.lds.h        |  1 -
 arch/arm/kernel/cpuidle.c                 |  4 +-
 arch/arm/kernel/process.c                 |  1 -
 arch/arm/kernel/smp.c                     |  6 +--
 arch/arm/mach-davinci/cpuidle.c           |  4 +-
 arch/arm/mach-gemini/board-dt.c           |  3 +-
 arch/arm/mach-imx/cpuidle-imx5.c          |  4 +-
 arch/arm/mach-imx/cpuidle-imx6q.c         |  8 ++--
 arch/arm/mach-imx/cpuidle-imx6sl.c        |  4 +-
 arch/arm/mach-imx/cpuidle-imx6sx.c        |  9 ++--
 arch/arm/mach-imx/cpuidle-imx7ulp.c       |  4 +-
 arch/arm/mach-omap2/common.h              |  6 ++-
 arch/arm/mach-omap2/cpuidle34xx.c         | 16 ++++++-
 arch/arm/mach-omap2/cpuidle44xx.c         | 29 +++++++------
 arch/arm/mach-omap2/omap-mpuss-lowpower.c | 12 +++++-
 arch/arm/mach-omap2/pm.h                  |  2 +-
 arch/arm/mach-omap2/pm24xx.c              | 51 +---------------------
 arch/arm/mach-omap2/pm34xx.c              | 14 +++++--
 arch/arm/mach-omap2/pm44xx.c              |  2 +-
 arch/arm/mach-omap2/powerdomain.c         | 10 ++---
 arch/arm/mach-s3c/cpuidle-s3c64xx.c       |  5 +--
 arch/arm64/kernel/cpuidle.c               |  2 +-
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
 arch/mips/kernel/idle.c                   | 14 +++----
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
 arch/x86/coco/tdx/tdx.c                   | 25 ++++-------
 arch/x86/events/amd/brs.c                 | 13 +++---
 arch/x86/include/asm/fpu/xcr.h            |  4 +-
 arch/x86/include/asm/irqflags.h           | 11 ++---
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
 arch/x86/kernel/process.c                 | 65 ++++++++++++++--------------
 arch/x86/kernel/vmlinux.lds.S             |  1 -
 arch/x86/lib/memcpy_64.S                  |  5 +--
 arch/x86/lib/memmove_64.S                 |  4 +-
 arch/x86/lib/memset_64.S                  |  4 +-
 arch/x86/xen/enlighten_pv.c               |  2 +-
 arch/x86/xen/irq.c                        |  2 +-
 arch/xtensa/kernel/process.c              |  1 +
 arch/xtensa/kernel/vmlinux.lds.S          |  1 -
 drivers/acpi/processor_idle.c             | 28 ++++++++-----
 drivers/base/power/runtime.c              | 24 +++++------
 drivers/clk/clk.c                         |  8 ++--
 drivers/cpuidle/cpuidle-arm.c             |  4 +-
 drivers/cpuidle/cpuidle-big_little.c      | 12 ++++--
 drivers/cpuidle/cpuidle-mvebu-v7.c        | 13 ++++--
 drivers/cpuidle/cpuidle-psci.c            | 26 +++++-------
 drivers/cpuidle/cpuidle-qcom-spm.c        |  4 +-
 drivers/cpuidle/cpuidle-riscv-sbi.c       | 19 +++++----
 drivers/cpuidle/cpuidle-tegra.c           | 31 +++++++++-----
 drivers/cpuidle/cpuidle.c                 | 70 ++++++++++++++++++++++---------
 drivers/cpuidle/dt_idle_states.c          |  2 +-
 drivers/cpuidle/poll_state.c              | 10 ++++-
 drivers/idle/intel_idle.c                 | 19 ++++-----
 drivers/perf/arm_pmu.c                    | 11 +----
 drivers/perf/riscv_pmu_sbi.c              |  8 +---
 include/asm-generic/vmlinux.lds.h         |  9 ++--
 include/linux/clockchips.h                |  4 +-
 include/linux/compiler_types.h            | 18 +++++++-
 include/linux/cpu.h                       |  3 --
 include/linux/cpuidle.h                   | 32 ++++++++++++++
 include/linux/cpumask.h                   |  4 +-
 include/linux/percpu-defs.h               |  2 +-
 include/linux/sched/idle.h                | 40 +++++++++++++-----
 include/linux/thread_info.h               | 18 +++++++-
 include/linux/tracepoint.h                | 15 ++++++-
 kernel/context_tracking.c                 | 12 +++---
 kernel/cpu_pm.c                           |  9 ----
 kernel/printk/printk.c                    |  2 +-
 kernel/sched/idle.c                       | 47 ++++++---------------
 kernel/time/tick-broadcast-hrtimer.c      | 29 ++++++-------
 kernel/time/tick-broadcast.c              |  6 ++-
 kernel/trace/trace.c                      |  3 ++
 kernel/trace/trace_preemptirq.c           | 50 ++++++----------------
 lib/ubsan.c                               |  5 ++-
 mm/kasan/kasan.h                          |  4 ++
 mm/kasan/shadow.c                         | 38 +++++++++++++++++
 tools/objtool/check.c                     | 17 ++++++++
 131 files changed, 617 insertions(+), 523 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112194314.845371875%40infradead.org.
