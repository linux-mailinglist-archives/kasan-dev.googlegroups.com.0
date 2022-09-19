Return-Path: <kasan-dev+bncBDBK55H2UQKRBYEDUGMQMGQEZVUFEAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id C84FF5BC6DD
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:09 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 6-20020a05651c008600b0026bda5a6db8sf6804898ljq.5
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582689; cv=pass;
        d=google.com; s=arc-20160816;
        b=OjgkDma/dYMcTdtZi0Sue4eC6XsR5kuEFnjdWdcB/ymjRPkKzgQUU1anksGmx5sTmf
         2K04luIef2ojQsw4AbRTLVp3W5K1Scw20OmQ5eyWVTJ27WNLU3wvn9A++y+sn/lyK+eo
         15aiq+ev47JTMCM9FjLYiEcV1AottzdVzItzq9RriA8T5NwHkUMP2Uk8N6nLlsr/5Sax
         hZPl0Nbkxw6sxtGCGHeNl0wqdI1sIW+GBbZlEutTuNvL/+6szUbw0idZnZAlCGE/2ZYp
         aoVBSyBN04glG179dFp8mTFhtDPG03dTnW6+J4hVZjXcdEUTMHly9eYEzW/cFRzouHWa
         T+VA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=HqeghlQ587puiq+JwvCNUzUznuD2s+cZnOumOu8gjPw=;
        b=QR060HhO5oSnI+zgWZscmv955Q+txWQ4/WL3iZ2B9N0pwSp//RDRxTfhaP960/ptS5
         dqZHZq9bp9f02XbVdqr37geJknDlM3AQOfHzwkFLaSxplgp5RZxtSBPvmc/Dj6tCjgnS
         pwHCSQJMrCQsXAgedblHAe+dLjDu0FMJTYqvqj2uYkiJXu+hZQmbhwjZMMw5ZXXHRENv
         2l2O9LOeL6szwm3y+XCmdNRNPuvsfXak1M4RAEiEOwQWyc55QOX7vQICdDSFIbRyGgCD
         5MjK426R+g6bn//HFWKYDoY7H0EWDRkoA7MATxwmtELweutsc7/pvIe8co1vqTvMNWDX
         a73Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=de8Ma0kU;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=HqeghlQ587puiq+JwvCNUzUznuD2s+cZnOumOu8gjPw=;
        b=C4QDUgmwzVK0pvh8HVHgMRcuPV0yMffC8oz+dAzvNl5qIS4kBoa/7OFpwzp+2iZ2m3
         /d9M+tGOm7b+PlANvEHg/Io7fjztZs5YgyjmZIZEKNtpvnVIqg6yLozsrijYPIB1CbKD
         6Bmjr3w5jusJ6ceicLFuq/N19GTeBX1UsYHnKX1ii59+XIugJi/DZ5vU9e8YWejyjuu7
         oOmfcX3+CLOFgeAVghLKd8Zx3zqXJ2oc7r19jqF0fq246B+2sXA1CMFo69sjS4k+ETf2
         QXeHc+A0sXSiiYPaTcfeKoRHurO/oPxeDg6CF9cSv3xFvfr5Y91PRkbDEJo+SrXRZYzd
         Z5pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=HqeghlQ587puiq+JwvCNUzUznuD2s+cZnOumOu8gjPw=;
        b=3u1oMFaTENaZh7skhMU114ZWNOLb3tP+A8NvVFv0Vy/V2lV8zcVH49wtIL5epA+4/A
         pDpVaqiQFJzjqEuv/8+7oP0TpDMcRe9qoxYFfZpgIuaScUxAg6JyFZNp1JdbwK8rEURS
         jSpXrkLGsbebfgxVj1vYvhjKNPN3Mg7ehCG0x5O/o7DZPVwFOLHiT2jfMaMJsaUeGdwj
         A2aeEo1iNloaIUplEKhIX+lB1eorz8o2pSbTys8MriOyMSdJFDk2NKjeVx4cSG7Jy7Z2
         O1qIYiaQbvYg9EJr5bAio3z/HDpUJlfm1aJj5vMaN6nzIQ34yZZXDB5+Rmp0n7wc3Khj
         YGYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2MqVArhCOyMrGXnsBANpe2Z7P0N++OLuXf2D9QQRwQKUmLqJB0
	Wj1xAyYKOVt95DtJ5bwR7B4=
X-Google-Smtp-Source: AMsMyM6sLKfmhNNEOQTShjLnUMYaJvQNTMZx4kF7DpzJ/ekOMKZL+JxR4lfjOUMM0j1OUg/+TPXryg==
X-Received: by 2002:a05:6512:2813:b0:49a:d1ca:6ea0 with SMTP id cf19-20020a056512281300b0049ad1ca6ea0mr6282794lfb.470.1663582688976;
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bf1b:0:b0:26c:556a:bf64 with SMTP id c27-20020a2ebf1b000000b0026c556abf64ls108441ljr.7.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
X-Received: by 2002:a2e:a90d:0:b0:26c:3b4b:731a with SMTP id j13-20020a2ea90d000000b0026c3b4b731amr4517546ljq.83.1663582687738;
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582687; cv=none;
        d=google.com; s=arc-20160816;
        b=q4cqnWRkH4ADmAljO26o2QllwvYHvJCoZs7DhXHcq0XQ7A58Q528HTKOFvn0fp3cyb
         gcpxu0qKtz+uGytMTJhSodqC+bhzNhEoBgtjQKy2DMbVqbFEWKVoGUioxb15s8Gojz3j
         waMrxRY5w6bbfLhS7T7sRios/0F3YKbWZa3BP/QE9prfKKGZhoHdBoXMPW3HbzE2AAbu
         jfDNl4J6wigHqWcbk7QHjePeKHR1MKAny289FrYxa02xELNe6OWjkOdlmSPe4yoPz98v
         tqefSIN7fJ37aHGk5L/hxslS3VzqzL5r0OJCzpeHaW/SFx1/TyiLIDz5n6wXeaxnAfZv
         P3Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=eYoUngVW9N27gIhULqYrRlt6uLJ7xBInAkMSAu6ULjk=;
        b=yPj1pKxbn+pLIQj57q4NohfT0R1jtwaAF+DQzLtsv6nrtWUEzZvQeHRQCjdKZamDSc
         HwlSLHdmypF9triETUFfm9ejiTRnSlC7aqd+VPpzbHvS4CO7IpuENCH/u/hMLAbn3RE5
         /bsL1WxYvM35F0ZMCeKWcF084BA4UXMaZk4bPyPvyrFd6lvGgQNh1ie+cPpRwqwB7kP5
         m4min39PA4LGFc4LW7jVtxvJ6WWNUlsFghBQ+H/Zivcfjog7aUGxc+DjBeLapbK/dQ0H
         gOyuW9Cl/DaoK396mP9SCxn6kWLMm0m6MJfoxPYK911ClHk7Op97UcixFusqV5NKaI3q
         DUIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=de8Ma0kU;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id v9-20020ac258e9000000b0049495f5689asi672006lfo.6.2022.09.19.03.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq8-00E2C4-Kp; Mon, 19 Sep 2022 10:17:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id A2C9D302F82;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id ABA4E2BAC75B6; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101523.244550344@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:22 +0200
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
Subject: [PATCH v2 43/44] sched: Always inline __this_cpu_preempt_check()
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=de8Ma0kU;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101523.244550344%40infradead.org.
