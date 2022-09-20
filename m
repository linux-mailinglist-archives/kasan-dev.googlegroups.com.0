Return-Path: <kasan-dev+bncBCBMVA7CUUHRBNXFU2MQMGQE5VTQSOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A8675BE5D2
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 14:31:51 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id q38-20020a056808202600b00350508fd168sf1348175oiw.21
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 05:31:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663677110; cv=pass;
        d=google.com; s=arc-20160816;
        b=lsqGyL+k7P5uNPDwRWla0BH482/NNjAyOLuOMkurxzJM0Z3eoFCPX7MGb+Ao0u9lf7
         9+4EGot5M2s5oxkdExtvSIW2BGz4eKTtikjcWqUBfrkvDaYFnadjfpFcF73+1/QKAHk6
         qb4EDvkYOUcORJQCWFV3G4Gw2jwQ2RpyvAJY0J9xzD56ayFVu07ARHhMCK+WhiVV7pnj
         wNkJaYBlkUDdpOy9fM0i83+odQJfX+6gwwvNiax05hJsHCjKnSWXOG5EHDz8YK36O6t7
         doN8KmT6qsSM7VyetWAJ/Ps+PsDRBFLaBtqC8i7wkKgFOZcsCO4G8zA84GbolUYTPdNw
         Jx1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=CQId3tB1OBnjXK3m0pX9KXVZkCzbpb9bE3jv9ipRJTM=;
        b=Kd0X6fy9BuVGlPI4MWjRSVlDYQ59yom/IzR16bo7LdhN6q64nCD2XhgHaPHiY1VN/V
         S9LUBhwfUi0rbfMBIJHYXEoa4fK9q+9zTGiIU1DtgRhpP3+Sf4wyj8I+BUhhsSkH6T+Z
         cmcaCguTZsPlnM3jSsvmOG/AU1ksJXQZr9o2P/NSVL/uaG6hA5q2V/QuZ4h+9rXD2FRA
         9a51f4V3fMc/GO8XkEatVMrOsjRqS0E0zNhlrZBP/nP8sjLGUKMTVoOxYZS+JlXCaHjf
         fQ2Sk3xYxQ5YEMMZYKQ3FHvUnoXol4+jzOIfLZ4yzS/CyNt5OoCU50z5a9AKhvIu1KXf
         DOuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Q359WuuE;
       spf=pass (google.com: domain of frederic@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=CQId3tB1OBnjXK3m0pX9KXVZkCzbpb9bE3jv9ipRJTM=;
        b=hew662nKCPoL+HIDwWsKL/hhP7YN5y2vcSUtGTpwnAEzPcGtJrr6zHfLKk5KwdGBZ0
         XM/s9JWfDmbghPzhD866xpenKtvXfCXTB9Qi6oJO2EtDs4yiiPYIaK3KWi9bUWMvEUnl
         lQsflz+KsI3sxWTbaAjl8rsScDAQtsW80zrcl0gcOv7ugULzXxh6zaPKpsaPaq+CEVSK
         C8Yu9QbNEYTaB5JgehhQ2yie78cNRg9LB8P8fi9IrklnWf07Qc+FgayRKoxDAA4GhZXX
         DTGuxZl1yGznaxq+g9uY1z6SuTz/hiR7GFApwgnTey8DbBKADk7Qd4VSqFOYDJI4KTNR
         JHvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=CQId3tB1OBnjXK3m0pX9KXVZkCzbpb9bE3jv9ipRJTM=;
        b=yVLxkjsrtkfIBqncFKFronTikrdvqpfI9goN1E6+9O5edhrWuGWUTKiwl+KuN9YiCR
         wdoQvuoJprYYhIcLwkYDKg/5RnDtnWAL8EY9O8G26wGCX1OGc4EWxE03t55fH/UDsKsJ
         GiN+EMXsN0U+qoFkmvJ0yWRMvws57NxmtSEJ4Y+j0zSn+TmZJhZ9QTO7Edv1JFBDm9Q6
         WyXd9MuWDWEmfS7mPPyH1HW/PRU0b0yNHfvRQUCvE+swuG34GMqwYjzzttxGbOtZg50V
         5ZJcYbRSFXk+12/0F6ZyzYoSIDXN9p57qCUglwjBq/09zQsf4s2cnSciS4Odu9Xd7Hcy
         K/2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3juqRRXeN9N2QkdUxd3nqzwxC22g2lxLUHIkN7sv7eui2/KasQ
	3vnO67xXSDyzSRuzQ/DuU1c=
X-Google-Smtp-Source: AMsMyM5yEdgmU39pQ+ZcVOZ+JRnl3jRbV79HJwP9RmOddDv3UlyBkeFXjt11DdoaEhfAmO2h53f+Uw==
X-Received: by 2002:aca:1119:0:b0:34f:d61d:698d with SMTP id 25-20020aca1119000000b0034fd61d698dmr1391037oir.277.1663677110299;
        Tue, 20 Sep 2022 05:31:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9897:b0:127:7af0:8da5 with SMTP id
 eg23-20020a056870989700b001277af08da5ls3856752oab.2.-pod-prod-gmail; Tue, 20
 Sep 2022 05:31:49 -0700 (PDT)
X-Received: by 2002:a05:6870:59d:b0:f3:627:e2b0 with SMTP id m29-20020a056870059d00b000f30627e2b0mr1872905oap.47.1663677109817;
        Tue, 20 Sep 2022 05:31:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663677109; cv=none;
        d=google.com; s=arc-20160816;
        b=gkUSGm7vagXGsL2fMxgji1NBjfi4snSLI1ExeWPHZkudb+NVV56pgHBvOurslwQUVl
         f4lxZ2EUhxzZ4ECERy2uAyaKH0x9r/RMbn9Xl4Oo+SsRHQw7c/55u9lUb99y8LA/lhnM
         fQvlh1IlhaycOrnjVWZcjTKpNpO3llQG8cT5IaADM/HQgtOMDNKlIBLCULD3hvQYjitf
         /OvjAF5ZwLfngiLtj+GCGumWiun4sJMfchNIKc1rehAXWL54mfcv4qj5OcXC8AizI7gI
         pKFtXyF7zf2pmEnywBMuYGnJ55uW7kkyXl90UMPDE7xWGRvOhf+BqYgWZ5prxbZ+nYsR
         EOAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vWsbZvJMm8D44NopgVvqu2acCld1QeyUAITbYqLgkH4=;
        b=Vc49KphYXYiuxLU7b3xipmGshy15gLPUrz/MbJfLHQ2C7+9Goohu1hqDzHYHKx4oWw
         wqidV/RBzUOxyB+Gl32+jVhsvVY4F9Im/JRcv5YLHwHe7nFyiNDa51vDlbLLWa97YBrw
         IRjxxQLGuHkTI5zfRe6F9rxnSctJlKLT/4CnTCbURFMhUdMMI5xwyZHMg5gW4EntrDZY
         a+ZoKqSYBXt/AswAGhlae0V+3TneDztsOKQtx4w7jZO2iCbykCfoiJRmh9mXDCqCPull
         055RwCwtpvKKIBtQG0cSTs9FEIHvD0fER/pOqH5DnXkOS53YqlpOkKA2PjorTmOOZcma
         j+/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Q359WuuE;
       spf=pass (google.com: domain of frederic@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id z42-20020a056870462a00b00101c9597c72si266290oao.1.2022.09.20.05.31.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Sep 2022 05:31:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 25E016233B;
	Tue, 20 Sep 2022 12:31:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 74CCCC433D6;
	Tue, 20 Sep 2022 12:31:47 +0000 (UTC)
Date: Tue, 20 Sep 2022 14:31:45 +0200
From: Frederic Weisbecker <frederic@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru,
	mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk,
	ulli.kroll@googlemail.com, linus.walleij@linaro.org,
	shawnguo@kernel.org, Sascha Hauer <s.hauer@pengutronix.de>,
	kernel@pengutronix.de, festevam@gmail.com, linux-imx@nxp.com,
	tony@atomide.com, khilman@kernel.org, catalin.marinas@arm.com,
	will@kernel.org, guoren@kernel.org, bcain@quicinc.com,
	chenhuacai@kernel.org, kernel@xen0n.name, geert@linux-m68k.org,
	sammy@sammy.net, monstr@monstr.eu, tsbogend@alpha.franken.de,
	dinguyen@kernel.org, jonas@southpole.se,
	stefan.kristiansson@saunalahti.fi, shorne@gmail.com,
	James.Bottomley@HansenPartnership.com, deller@gmx.de,
	mpe@ellerman.id.au, npiggin@gmail.com, christophe.leroy@csgroup.eu,
	paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu,
	hca@linux.ibm.com, gor@linux.ibm.com, agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com, svens@linux.ibm.com,
	ysato@users.sourceforge.jp, dalias@libc.org, davem@davemloft.net,
	richard@nod.at, anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net, tglx@linutronix.de, mingo@redhat.com,
	bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org,
	hpa@zytor.com, acme@kernel.org, mark.rutland@arm.com,
	alexander.shishkin@linux.intel.com, jolsa@kernel.org,
	namhyung@kernel.org, jgross@suse.com, srivatsa@csail.mit.edu,
	amakhalov@vmware.com, pv-drivers@vmware.com,
	boris.ostrovsky@oracle.com, chris@zankel.net, jcmvbkbc@gmail.com,
	rafael@kernel.org, lenb@kernel.org, pavel@ucw.cz,
	gregkh@linuxfoundation.org, mturquette@baylibre.com,
	sboyd@kernel.org, daniel.lezcano@linaro.org, lpieralisi@kernel.org,
	sudeep.holla@arm.com, agross@kernel.org, bjorn.andersson@linaro.org,
	konrad.dybcio@somainline.org, anup@brainfault.org,
	thierry.reding@gmail.com, jonathanh@nvidia.com,
	jacob.jun.pan@linux.intel.com, atishp@atishpatra.org,
	Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com,
	andriy.shevchenko@linux.intel.com, linux@rasmusvillemoes.dk,
	dennis@kernel.org, tj@kernel.org, cl@linux.com, rostedt@goodmis.org,
	pmladek@suse.com, senozhatsky@chromium.org,
	john.ogness@linutronix.de, juri.lelli@redhat.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	bsegall@google.com, mgorman@suse.de, bristot@redhat.com,
	vschneid@redhat.com, fweisbec@gmail.com, ryabinin.a.a@gmail.com,
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
	vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>, jpoimboe@kernel.org,
	linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-snps-arc@lists.infradead.org, linux-omap@vger.kernel.org,
	linux-csky@vger.kernel.org, linux-hexagon@vger.kernel.org,
	linux-ia64@vger.kernel.org, loongarch@lists.linux.dev,
	linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org,
	openrisc@lists.librecores.org, linux-parisc@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org, linux-sh@vger.kernel.org,
	sparclinux@vger.kernel.org, linux-um@lists.infradead.org,
	linux-perf-users@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	linux-xtensa@linux-xtensa.org, linux-acpi@vger.kernel.org,
	linux-pm@vger.kernel.org, linux-clk@vger.kernel.org,
	linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 00/44] cpuidle,rcu: Clean up the mess
Message-ID: <20220920123145.GC72346@lothringen>
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919095939.761690562@infradead.org>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Q359WuuE;       spf=pass
 (google.com: domain of frederic@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=frederic@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Sep 19, 2022 at 11:59:39AM +0200, Peter Zijlstra wrote:
> Hi All!
> 
> At long last, a respin of the cpuidle vs rcu cleanup patches.
> 
> v1: https://lkml.kernel.org/r/20220608142723.103523089@infradead.org
> 
> These here patches clean up the mess that is cpuidle vs rcuidle.
> 
> At the end of the ride there's only on RCU_NONIDLE user left:
> 
>   arch/arm64/kernel/suspend.c:            RCU_NONIDLE(__cpu_suspend_exit());
> 
> and 'one' trace_*_rcuidle() user:
> 
>   kernel/trace/trace_preemptirq.c:                        trace_irq_enable_rcuidle(CALLER_ADDR0, CALLER_ADDR1);
>   kernel/trace/trace_preemptirq.c:                        trace_irq_disable_rcuidle(CALLER_ADDR0, CALLER_ADDR1);
>   kernel/trace/trace_preemptirq.c:                        trace_irq_enable_rcuidle(CALLER_ADDR0, caller_addr);
>   kernel/trace/trace_preemptirq.c:                        trace_irq_disable_rcuidle(CALLER_ADDR0, caller_addr);
>   kernel/trace/trace_preemptirq.c:                trace_preempt_enable_rcuidle(a0, a1);
>   kernel/trace/trace_preemptirq.c:                trace_preempt_disable_rcuidle(a0, a1);
> 
> However this last is all in deprecated code that should be unused for GENERIC_ENTRY.
> 
> I've touched a lot of code that I can't test and I might've broken something by
> accident. In particular the whole ARM cpuidle stuff was quite involved.
> 
> Please all; have a look where you haven't already.
> 
> 
> New since v1:
> 
>  - rebase on top of Frederic's rcu-context-tracking rename fest
>  - more omap goodness as per the last discusion (thanks Tony!)
>  - removed one more RCU_NONIDLE() from arm64/risc-v perf code
>  - ubsan/kasan fixes
>  - intel_idle module-param for testing
>  - a bunch of extra __always_inline, because compilers are silly.

Except for those I have already tagged as Reviewed:

Acked-by: Frederic Weisbecker <frederic@kernel.org>

Thanks for the hard work!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220920123145.GC72346%40lothringen.
