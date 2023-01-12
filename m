Return-Path: <kasan-dev+bncBDBK55H2UQKRB2WMQGPAMGQE5YWVWIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id E2BEC667FF2
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:35 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id b23-20020a05651c033700b0028473c6cc7bsf4014915ljp.6
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553515; cv=pass;
        d=google.com; s=arc-20160816;
        b=r8kqcfVP+7uxWZk5xj7c73ruyzuTZxiJq+42v94JslrCECBwBQk64J6IduiSFY4Ech
         5sc04LdqiB8FloIlaEbDJdqOo3LF1MlErd6lkVpBnxxSypV4HpXtfwILHIOaWLDITdDZ
         NwAtKAOUukEBERrlvTqqzDUeA0gEgk7CLAUCR0bs1SqsYm7BriuRQbNwHhvvlFIaMYue
         gZ5EoaotZ6htvwBGq3q4ub/FG4P9C0bQX+eCHqImsJtOLYpTzTp5fvZIjr8DsEpoRnwr
         7GTc7FUWYVWgie77Z2mh57kRCs2beG16I7KJsdpNEMr4F0qMInNSRkoNqHr28dhe8XMI
         Cg4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=Chd6/ZFriIoMytNExm1dT2G2F1ZvddOMysFyvg07BQ8=;
        b=dHrK4vUmZrWG7dH8nXTAx/AGNzLP1NtcPCy+Ap3OI75P75ev5MMBpwXkuJD+GpzVK7
         I9gPjJ/J/vww6t/2RGXrLNtAWBOMzqTupjUglyLE5POKkd4+nfn2HH1waP1YWFTbfWvA
         NcDWKTDO+YS+HxVGeyNElxvYTuLhlgt69523Vc6DLhEqiSs62k0dCBob7rL4wX9dANvM
         fEnxV/xbdRejqQ4auLjvQo8c6Zg91btXtMSH1gVHM6MkKQ4UgQPBf6e6YzYC7PQdxWMb
         xRq5oMHFtppH5QjbDr/1ihKVhpG1d1/TU8rYgdjCx6/L7bPQZ3h4zRZXjaFdth00X7p5
         PC6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=tOV0YOj5;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Chd6/ZFriIoMytNExm1dT2G2F1ZvddOMysFyvg07BQ8=;
        b=b0LY6BIz0PBJejnK6F/0rJOQalmUpF4hJwQ5GlIt8jTUXyVVFdR/j1ik8O2rZQbjI3
         dBueHARw20Xfk/+Vaf069zK43FjDDLid89ArXDIJV+evuAv3v8R036FMqxkqW671pdCt
         ETaeVsYrNk/Nmq79RGc9pMAFj39yzpxI9+5ITw3Ws+z6qVM5Bs4S4onpD/Rw6iYJSrlE
         zh2CFhGoZcFUn8dXb2LRhVPbbd7js0JtfTGf7vzJbfIVaa+6UgoIxaw0HUu5Kauw7yEx
         0ZPhMXkPTAmnTXa8PqKBPnV66VN+l6KcdglK/46G4XAX5oZcz+B16IK7OFc3az6I0tbi
         4G5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Chd6/ZFriIoMytNExm1dT2G2F1ZvddOMysFyvg07BQ8=;
        b=SL86PvdBeLhsCus0d1YN+DNa73HiuG6PBPFqGJov6OQlYBg0EzXs6STkBr0nxPomyY
         /P295TqHMvViIXC9K5HhV/BWSBPp/fN67NBaSkpNrHd5g7CUgJkPw68yYUK3UbsWyF11
         3B32au4SNlGruxQ/7FKTruEtJdXvaKZmTBidRDJSXlqaya4WgxzY6JdHX6J12Vo1w8Aq
         RE/6BhpReaNJShSm5cHVo6t8pBHc09GllVJlGu5V7Cad45encnpMQVG7OKDcArovwbZz
         vI3SqkFmIWmTSkKTM00aaF5/ITVDcRIstBixikjGkxoHdACXLZJrbo6pk6z2DvxrkOSD
         keuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqqfTexQ6YHnJKmd+LDOTdEIApl9UwF4vx73Oou8T69OaWyq/t8
	fJC1ZtphDRg0um01MfsIwgU=
X-Google-Smtp-Source: AMrXdXtPGJZIUiYZpslZhi31201Y5mFn2s37lv0E70xt9la1P9mMUgcAP2m8aHFzKYkqz//7wyt/Pw==
X-Received: by 2002:a05:6512:128d:b0:4cc:534f:beef with SMTP id u13-20020a056512128d00b004cc534fbeefmr2001433lfs.524.1673553515192;
        Thu, 12 Jan 2023 11:58:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2024:b0:4a2:3951:eac8 with SMTP id
 s4-20020a056512202400b004a23951eac8ls1935360lfs.0.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:34 -0800 (PST)
X-Received: by 2002:a05:6512:2828:b0:4b9:f5e5:8fbc with SMTP id cf40-20020a056512282800b004b9f5e58fbcmr28592885lfb.30.1673553513982;
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553513; cv=none;
        d=google.com; s=arc-20160816;
        b=z3KSUI9riRufDqKPLys/W0ADKjHuWiN22rto69jAlU4J+njLQnw2j1XZ2tEvapL47H
         P4g9O7w/+uI8j/L5ih3yriYg90b4qSM4c2cLYOEU4iIdbhRyXXkx6PQ5Kvl3Ctkb0+qZ
         ggRnCB1r/rSaPt4Oqubkzx/a7b0WLi1+AEfOTa9p79Sximx4cACH/QjjdA0bPtOsQWNp
         5GdMEpIFKnlQPKffuEcDzV5Cbqxz83P+7wimPtx8kxSxEcHxE9n/aOqjcEWYiRTqYvN0
         ehifpJ5mIXuu2KqGdoiJw8hhySsWrY+7TXbZ5cg7hoNJ7SuSXbJGCmv9B+AfF1bdN2m4
         jyrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=TpAs8eQceCyyKKtR//95dieD+m+uPCJ6EEXd6r5ehjs=;
        b=b6rf+C59Y2HYxJTe+kRxCeLlW2ftPt6QB/qLzPrpAiQCiC1MorKl3P3JFz9SelotJ7
         hFY5L6OZZCwUzRtG2zy+Oq8skX9O/kJI9wrGYOsqE738VidS2EZsGTDi31VotJkZ+Ffv
         /3Gb/rH53+j/PHVyE3N1sSpxGfsFoBr9l3iLessUCj2zYNDH66OYTwJC8HmVxL1tXQzO
         WYpOArLObChQjTDWMDo+0izMYx4XOsVOEKIl5fKvWoaL606uVzTZIzWpYVUaLM9EesMB
         ddOQc5wFq/2m+Dcf3r3p1X0A4K4bA+/q+u7fTHWPpOrMA//pwgwgm3HEG3t4qZBbD94m
         sx0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=tOV0YOj5;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id a14-20020ac25e6e000000b004cfe6a1a3e7si4467lfr.13.2023.01.12.11.58.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:33 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pG3hs-005P4Y-56; Thu, 12 Jan 2023 19:57:48 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 25748303474;
	Thu, 12 Jan 2023 20:57:14 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 6405E2CD066D8; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195542.089981974@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:59 +0100
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
Subject: [PATCH v3 45/51] sched: Always inline __this_cpu_preempt_check()
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=tOV0YOj5;
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

vmlinux.o: warning: objtool: in_entry_stack+0x9: call to __this_cpu_preempt_check() leaves .noinstr.text section
vmlinux.o: warning: objtool: default_do_nmi+0x10: call to __this_cpu_preempt_check() leaves .noinstr.text section
vmlinux.o: warning: objtool: fpu_idle_fpregs+0x41: call to __this_cpu_preempt_check() leaves .noinstr.text section
vmlinux.o: warning: objtool: kvm_read_and_reset_apf_flags+0x1: call to __this_cpu_preempt_check() leaves .noinstr.text section
vmlinux.o: warning: objtool: lockdep_hardirqs_on+0xb0: call to __this_cpu_preempt_check() leaves .noinstr.text section
vmlinux.o: warning: objtool: lockdep_hardirqs_off+0xae: call to __this_cpu_preempt_check() leaves .noinstr.text section
vmlinux.o: warning: objtool: irqentry_nmi_enter+0x69: call to __this_cpu_preempt_check() leaves .noinstr.text section
vmlinux.o: warning: objtool: irqentry_nmi_exit+0x32: call to __this_cpu_preempt_check() leaves .noinstr.text section
vmlinux.o: warning: objtool: acpi_processor_ffh_cstate_enter+0x9: call to __this_cpu_preempt_check() leaves .noinstr.text section
vmlinux.o: warning: objtool: acpi_idle_enter+0x43: call to __this_cpu_preempt_check() leaves .noinstr.text section
vmlinux.o: warning: objtool: acpi_idle_enter_s2idle+0x45: call to __this_cpu_preempt_check() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 include/linux/percpu-defs.h |    2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

--- a/include/linux/percpu-defs.h
+++ b/include/linux/percpu-defs.h
@@ -310,7 +310,7 @@ extern void __bad_size_call_parameter(vo
 #ifdef CONFIG_DEBUG_PREEMPT
 extern void __this_cpu_preempt_check(const char *op);
 #else
-static inline void __this_cpu_preempt_check(const char *op) { }
+static __always_inline void __this_cpu_preempt_check(const char *op) { }
 #endif
 
 #define __pcpu_size_call_return(stem, variable)				\


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195542.089981974%40infradead.org.
