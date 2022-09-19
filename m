Return-Path: <kasan-dev+bncBDBK55H2UQKRBS4DUGMQMGQENF25KNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id B76775BC680
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:47 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id dz21-20020a0564021d5500b0045217702048sf14508392edb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582667; cv=pass;
        d=google.com; s=arc-20160816;
        b=eYngk9YJdHQjgYONbQqF1BfzkTT/zFnSjFwhq5Cz6vug3yt1VgYWyRC9X/tfY9id+y
         7qeB7Qr/X5oJ7nRN+s2Dp0VBjR6QQhP/pOMGs7h+mY+ZSEz+u6y2n0DEMhCM2YwyO3ij
         D/Q6kzF+HYay9qeoBv/fqn0abBS3k5cwUBgR0eFfffIz4EFefALPYJExT/4vgCiIBRT3
         ZFUazNKdgPFSrb6NcXaQaZEz12DylJ85E/zrOy6RvA+hA7JgXv5HE3Umq5pFnIaO+FlQ
         YnvNBNcZBoGxFzKQNz89ZB7Gi91k6wUKapo8zOhPfnBNoixjy21ie6izAWqAb4jDCMt/
         y57Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=A2/wPz3VFahmlYScudQp2t/cUCW32+B/haC/FzItyuE=;
        b=PSSaDvLYrxO7rF2Y/xToYeN3HnHV0ZrBBGoXZgie6zClVAekzA4v148Zkx9qWXX5lc
         eTmB80zk5NFsytK62wHuqys7+2R27A2FTw2T7srDhsxBvn9F0BQucmjOT0LPF6S5ZKsJ
         xEQoI18I1FDJn80U13jSkooplh9OWM/t4dnOnRZfls6SyJD4D/T+TXRmjv7Xa6owWZ9s
         SMpwUNaNk77oNhZ0HibelFAb8WzI4lIzGqta8oiVCPVh0y8Ck1hpzK3ZmD1NQqZntHIH
         zif1DS8nKpMv3J1xDUskHVjpNRkD+u5HHNVwySGTjmKVR2y2zIILGj4pDI/+dpiaqvM8
         BIqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=l6JY0yWl;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=A2/wPz3VFahmlYScudQp2t/cUCW32+B/haC/FzItyuE=;
        b=Q7VuIbk42soI3LvTWWlfE4b5h2f1j05IMsV+3SQjKe2GNHmkkD4Op9qOR/2wtG7RKC
         76w9xVhLFZrk3URDCJk2ixP98LcwyOeV/NZR7NLo/ibZhZnBWTeQGqKs3bSBuWMi/xQ3
         8WwgWpr7+mkiw919ZL+5wQB7cAyXOKzESGkXSQw2GokWP1gP15yZSSElRWEhBKoy+RyM
         hsKC8WdLf+3gXzzoSvgiHaqSx3vhxfXm29mN4w+gn0OyVbvtd5GVhL+UPB5GpsrQSZ21
         eHl7Pa4cASwVYKzH7dLj5vpdksC2lFolJnlNhH5bPzVzBYDhJ+GwUMo1GPSuqgfieIBZ
         UbuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=A2/wPz3VFahmlYScudQp2t/cUCW32+B/haC/FzItyuE=;
        b=Z+uU5Cuw4tjmKPFSLyjT4SbZ8SjgrVYkIxz5Y8P6d7R6cUngPNhmfkEQgRJX7NEJYB
         Fva7Y1bPO1zYy2XvxwlEgUUw1MptoSQFzeDllMtGp0DU9MjcdG8kWPZ2wPQLupm5HC6D
         4XyCv87xn9kquvGhVBRpebjaFjc8bJ1trRH01drpXuRowpAq/vnBHV+8jU3mciFEOKIb
         OxdzVk6aum+lnLAcSSQoNzY6opZR9r9fZUx84/8POZxi0fBfj8Zq5GJ5GlliTxz+uFmr
         PEsuLTAUIVgpHTt2o+OjJtzjjTJ8LcIoiSPvLcm45QZPHv95955GeqmAfux98tDT3y7I
         14dQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0zBEdJnQm5K4A7tl6iaT/qN4x7rGdg1H7F1nPAXE8TgPVsp+BX
	g07RxL5jneJPFcrWM5OtaQg=
X-Google-Smtp-Source: AMsMyM4roJXT73gt8Fc+gaZyr8YurkaePoRk0GVcA9/ulXibbp5IAEIp08eofwfkmutUlIc4Te1Yaw==
X-Received: by 2002:a50:fe91:0:b0:43d:c97d:1b93 with SMTP id d17-20020a50fe91000000b0043dc97d1b93mr15116419edt.67.1663582667507;
        Mon, 19 Sep 2022 03:17:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c083:b0:726:abf9:5f2e with SMTP id
 f3-20020a170906c08300b00726abf95f2els1990898ejz.9.-pod-prod-gmail; Mon, 19
 Sep 2022 03:17:46 -0700 (PDT)
X-Received: by 2002:a17:906:7f03:b0:781:6462:4214 with SMTP id d3-20020a1709067f0300b0078164624214mr2141816ejr.274.1663582666315;
        Mon, 19 Sep 2022 03:17:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582666; cv=none;
        d=google.com; s=arc-20160816;
        b=0aj7z/MRf76eBXSeKBmoJ+ZswuAwPW5gUj6G5EtVFuWr/m/VmqKpf1RCSGs5W48Lim
         1oK8FLOL0+ouWRw+zN9j5t2YsBEptScg+EhPaQhG03rygXSPrIOCm+NLN47HOKjVV37d
         FtsDHGDzmD+p93oqhp24/XcqyYnXFEUr8Dvztdwx9OVJ3jkmehJoRykZjr6hFrw5IMIY
         i8SV6xoedL6NeUHhYD9in7+XDnEc267RaW4VmKwHYdT5xdBPIOLBr6ZaBynb8imttak7
         kKE05DwCFgO/9PfOZfCvPmtTYBv5xwXcICvoVLPCcDm0PpK6MZBUCExf0R8rsX3x8/MD
         fKCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=Vr6T2clVTCKzoOuqPun2LzaBPyz9xLY6Bd2T3LwNb5Y=;
        b=A3ja05cElS7oAI9BlVpb3QXyaCBAB7vLNbRtSik3PM6plIdLK8d69a0/d131FHpmDG
         p+cCMftMmkBDxiY64Py1+qNItDgYEc5ycoU0gcXmN+QtBRe7BViREQYPA1IWXlR+hrFv
         XiTg7NcS0BZSas5oaZUqUowd4OvjWvnHTZV0Yh+gzM5TajbYTER4TgUe4iORagu3OVM6
         4PsHudgpDRNGh9Xgy8cptyQZ9XX4DyxtJuFZ8rkk4eVaN+wxL70IhuPCwApJSe33DQKY
         CmM4SrT37fnUVSsqfZYjPR2ucmT99P4X6rGd6Edz+MEA+GeKm04FV5sg4iAI9tgHHFbf
         eYOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=l6JY0yWl;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id d3-20020a05640208c300b004542c733389si44981edz.5.2022.09.19.03.17.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:46 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq6-004b84-0R; Mon, 19 Sep 2022 10:17:22 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2615A302F1D;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 4AD7D2BA9210F; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101521.953707131@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:03 +0200
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
 kasan-dev@googlegroups.com,
 Marc Zyngier <maz@kernel.org>
Subject: [PATCH v2 24/44] arm64,smp: Remove trace_.*_rcuidle() usage
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=l6JY0yWl;
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

Ever since commit d3afc7f12987 ("arm64: Allow IPIs to be handled as
normal interrupts") this function is called in regular IRQ context.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Acked-by: Marc Zyngier <maz@kernel.org>
---
 arch/arm64/kernel/smp.c |    4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

--- a/arch/arm64/kernel/smp.c
+++ b/arch/arm64/kernel/smp.c
@@ -865,7 +865,7 @@ static void do_handle_IPI(int ipinr)
 	unsigned int cpu = smp_processor_id();
 
 	if ((unsigned)ipinr < NR_IPI)
-		trace_ipi_entry_rcuidle(ipi_types[ipinr]);
+		trace_ipi_entry(ipi_types[ipinr]);
 
 	switch (ipinr) {
 	case IPI_RESCHEDULE:
@@ -914,7 +914,7 @@ static void do_handle_IPI(int ipinr)
 	}
 
 	if ((unsigned)ipinr < NR_IPI)
-		trace_ipi_exit_rcuidle(ipi_types[ipinr]);
+		trace_ipi_exit(ipi_types[ipinr]);
 }
 
 static irqreturn_t ipi_handler(int irq, void *data)


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101521.953707131%40infradead.org.
