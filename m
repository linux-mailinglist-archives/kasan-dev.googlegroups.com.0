Return-Path: <kasan-dev+bncBCU73AEHRQBBBQXEY6MQMGQEPQZXI7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 38C445EB039
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 20:41:07 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id q22-20020a2eb4b6000000b0026befa4f871sf1891640ljm.18
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 11:41:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664217666; cv=pass;
        d=google.com; s=arc-20160816;
        b=X4QWOwzh1tLYRGw6Vaydx1LfhvrLuLmnASpKQ8RgwwQkxpTTyt9z/Q3qrsd1gQIem7
         rCtKgdJzMvPpIYAd4SxmG8NV/GpDnB39Wli9Ya4hEKt58edV33a0s5r1ahhro8zOI5ni
         pfqgRAmy/20pmbE9ZSOoJT2G09Rl4xAFpU/jlVYmAefJZgDKHbTEseiIYhEMaIv0z158
         0oEPZylQ9hqmT8NMeJJ1OjVDlBur3BS+HN6GR/czKvJ7s5vUkYkSL/OFIz1orNM+gZXR
         JhMrB0t+KdH6ZjlyCRraZXWuItqB6TDMH6DEiw94OqxlpQYK22UpHtv3IzIxu2z9IVGP
         1Wag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=IejfjNobFsvGgGEFefN5EPw9g7ys/7abNs6qbdH5OUo=;
        b=EeGOjjrxymklda4Jf4Fdfz628mYEuRyGF5iroXGhJEalxT31VIN1cl7A0mWfmT4W17
         BIY3ZcAGQBhduoJ3StpiMkP7EfzPtpSbuM5XeUASkhgDsFPApZhoLs1NU/oTwQjvxNj0
         PZ5VfyeHMs0cw+gcodqfT1M0kSU9E+1SKF49jHVWGG/N9s3wDfNhCvUsyewiwrxCCzQB
         /uZ57pa6/YUji6HN18zZ4eLw/DM3rbNB6J/N6csI6s4mazfwHgDxWHuW0RhpxFhzuRvT
         V9defOwZ7kY9DcZkMg9ZlNudZoRCk0Nji/u4gI7dsI1GaxVJtJ8KUwni0yqcn//c3TPA
         MCRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=56q7=z5=goodmis.org=rostedt@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=56q7=Z5=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date;
        bh=IejfjNobFsvGgGEFefN5EPw9g7ys/7abNs6qbdH5OUo=;
        b=V102fOys0WMeM7UuzhL8rj/xlYCZzlMzz+mXdWUcnL9xgF21dl190AgufT9X4UXv3P
         Mf4RMN9g8T7eZVE60ZGPxIWmJaBZXm24hPkNF9uRI8MxI9IYSQTcriYxWGn6HxVTe6Fz
         oDGFlSaV2864HFrWWVto1APCF52W2L6+0/6RjSce0+zQrM+NLvpTq2A+6XBd9hpOF9hc
         qgSgJKk/FBktKjKx9EZys5sB56T0GMIkylhBMEbwZu2T2hWyeKgeo1ctWDGWLQ0d135s
         AxJ4A036a+TMk3SoSjBtX8XMOkId1lLS/Au9aQAAfymbLT/R6DiJjYK2HhVr7FxbC8uH
         W/Uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=IejfjNobFsvGgGEFefN5EPw9g7ys/7abNs6qbdH5OUo=;
        b=uGOd6Mbi4yoBl/nm29TjHIso/L9EMP4r0czM/iWPJHD0g4EsYDS7KVGvdVqbqjO2Ac
         uoiFV9EL3N0MoVfJ3JPVOMlgLVlsP7BgD2FZZOzu9GjdLdJAXyyyP8/B1Ov7YL7ryyRl
         p/qGhYWxZAU8mTDmtYK8Y2RAZj7V4Sbz2p4RvcF1CXPWaBP6DLkp3xCMOItTKeiNcl+l
         xQJJZPzdtKGogOnYabfUp7w8HT9wwgIfHTcD1XWhF2E1WtxCgo6/uWe8AVO9fluLfTy+
         1irqLqhMgPD78Ld2IIklXs7rnIszG7tZXOjin1HsRDNG5CvvpvQAfo+SPRylI9ZnTk9R
         43xA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1zA2LD93swawGN0309ByyVC8q9MkD1KJU+vIAQIvOLbnrht23F
	SB03auKQT8Cn+HVF50APyJI=
X-Google-Smtp-Source: AMsMyM66pRsBmLg2F5kUg+xvsIpSdQWTE95iajXJxNd9ETCZ4e2ng4c1Q0Ome/ZyLfSQLbRwGyZ7Yg==
X-Received: by 2002:a19:6b05:0:b0:49f:53b9:abb0 with SMTP id d5-20020a196b05000000b0049f53b9abb0mr9978220lfa.166.1664217666382;
        Mon, 26 Sep 2022 11:41:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4a74:0:b0:49b:8c05:71a5 with SMTP id q20-20020ac24a74000000b0049b8c0571a5ls403682lfp.0.-pod-prod-gmail;
 Mon, 26 Sep 2022 11:41:05 -0700 (PDT)
X-Received: by 2002:a05:6512:ac6:b0:4a0:2b26:3ab3 with SMTP id n6-20020a0565120ac600b004a02b263ab3mr9707884lfu.154.1664217665124;
        Mon, 26 Sep 2022 11:41:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664217665; cv=none;
        d=google.com; s=arc-20160816;
        b=h0LMMgEml/owVNvXbTtYdizgRCT3U+A03wa5YAHmCj/Dqe9U5XJRDCK7g7W5YBIfiL
         fMh5MIn4o1oaSFzxmo99YhFVSWTNj4spLn9rWtYg+Mwuw3JkjQpQCA5+ULAqki4VSz0N
         uAEhCCSmfxKO5nJRQIUbRE3YoowzBy2XmGLThgFNNHmo+/SSLFShNr1SoRvpGnbfm6WQ
         xoy7/oS9I0ltUbcIas3/MXSivdraif9ZFCvPAUoFXvaZlRfIH8eJoytv//VUGkSr8kLF
         pilxxV4gQKtRazeWwlULNjQWqcnidFVK2HBpJHkAuvj+L9enDpG6l+xvFnlINlVVKNOE
         USmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=itnkyNaxE+RSD3N2sUUnYquTphS8dh+b9w+anwaIZNc=;
        b=zz9ZHpQWeEwFDPC8B6CK3Gl2BtVpnjzfHoQKeuMswa9E3t8lHIl3IR6XGxIEsLwtGg
         jiinDfFB46iPEHyn0waRDqxxb+W7T+PSRZuDHMEiQ0u2ztNYcWeSpjOR/dnveWJ8+IjP
         NUDMBnykDYzdcuXBvq+xMktTIBnWUHYfO1fNSC/wmqMsbMRKshQrZg3PinYiSdgOZi3H
         2uhObuJhJPR36lZJJg9Y3rGy2zL5LztXVeetmAjeTSSc2mCjQcfuvVOWVER9CbYLZ998
         JaIJ0OfXWHeRZGjdT4JLCPAdzvU0BR1CZf7vdAXkE+qhpyW+r7b36zHwct8smUv3Fvum
         /xsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=56q7=z5=goodmis.org=rostedt@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=56q7=Z5=goodmis.org=rostedt@kernel.org"
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id f5-20020a056512360500b0049c8ac119casi680445lfs.5.2022.09.26.11.41.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Sep 2022 11:41:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=56q7=z5=goodmis.org=rostedt@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 6FF91B80D66;
	Mon, 26 Sep 2022 18:41:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B8346C433D7;
	Mon, 26 Sep 2022 18:40:49 +0000 (UTC)
Date: Mon, 26 Sep 2022 14:41:57 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru,
 mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk,
 ulli.kroll@googlemail.com, linus.walleij@linaro.org, shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>, kernel@pengutronix.de,
 festevam@gmail.com, linux-imx@nxp.com, tony@atomide.com,
 khilman@kernel.org, catalin.marinas@arm.com, will@kernel.org,
 guoren@kernel.org, bcain@quicinc.com, chenhuacai@kernel.org,
 kernel@xen0n.name, geert@linux-m68k.org, sammy@sammy.net, monstr@monstr.eu,
 tsbogend@alpha.franken.de, dinguyen@kernel.org, jonas@southpole.se,
 stefan.kristiansson@saunalahti.fi, shorne@gmail.com,
 James.Bottomley@HansenPartnership.com, deller@gmx.de, mpe@ellerman.id.au,
 npiggin@gmail.com, christophe.leroy@csgroup.eu, paul.walmsley@sifive.com,
 palmer@dabbelt.com, aou@eecs.berkeley.edu, hca@linux.ibm.com,
 gor@linux.ibm.com, agordeev@linux.ibm.com, borntraeger@linux.ibm.com,
 svens@linux.ibm.com, ysato@users.sourceforge.jp, dalias@libc.org,
 davem@davemloft.net, richard@nod.at, anton.ivanov@cambridgegreys.com,
 johannes@sipsolutions.net, tglx@linutronix.de, mingo@redhat.com,
 bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org, hpa@zytor.com,
 acme@kernel.org, mark.rutland@arm.com, alexander.shishkin@linux.intel.com,
 jolsa@kernel.org, namhyung@kernel.org, jgross@suse.com,
 srivatsa@csail.mit.edu, amakhalov@vmware.com, pv-drivers@vmware.com,
 boris.ostrovsky@oracle.com, chris@zankel.net, jcmvbkbc@gmail.com,
 rafael@kernel.org, lenb@kernel.org, pavel@ucw.cz,
 gregkh@linuxfoundation.org, mturquette@baylibre.com, sboyd@kernel.org,
 daniel.lezcano@linaro.org, lpieralisi@kernel.org, sudeep.holla@arm.com,
 agross@kernel.org, bjorn.andersson@linaro.org,
 konrad.dybcio@somainline.org, anup@brainfault.org,
 thierry.reding@gmail.com, jonathanh@nvidia.com,
 jacob.jun.pan@linux.intel.com, atishp@atishpatra.org, Arnd Bergmann
 <arnd@arndb.de>, yury.norov@gmail.com, andriy.shevchenko@linux.intel.com,
 linux@rasmusvillemoes.dk, dennis@kernel.org, tj@kernel.org, cl@linux.com,
 pmladek@suse.com, senozhatsky@chromium.org, john.ogness@linutronix.de,
 juri.lelli@redhat.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, bsegall@google.com, mgorman@suse.de,
 bristot@redhat.com, vschneid@redhat.com, fweisbec@gmail.com,
 ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
 dvyukov@google.com, vincenzo.frascino@arm.com, Andrew Morton
 <akpm@linux-foundation.org>, jpoimboe@kernel.org,
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
 virtualization@lists.linux-foundation.org, linux-xtensa@linux-xtensa.org,
 linux-acpi@vger.kernel.org, linux-pm@vger.kernel.org,
 linux-clk@vger.kernel.org, linux-arm-msm@vger.kernel.org,
 linux-tegra@vger.kernel.org, linux-arch@vger.kernel.org,
 kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 33/44] ftrace: WARN on rcuidle
Message-ID: <20220926144157.0406dfbb@gandalf.local.home>
In-Reply-To: <20220919101522.573936213@infradead.org>
References: <20220919095939.761690562@infradead.org>
	<20220919101522.573936213@infradead.org>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=56q7=z5=goodmis.org=rostedt@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=56q7=Z5=goodmis.org=rostedt@kernel.org"
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


Nit, the subject should have "tracing:" an not "ftrace:" as the former
encompasses the tracing infrastructure and the latter is for the function
hook part of that.

On Mon, 19 Sep 2022 12:00:12 +0200
Peter Zijlstra <peterz@infradead.org> wrote:

> CONFIG_GENERIC_ENTRY disallows any and all tracing when RCU isn't
> enabled.
> 
> XXX if s390 (the only other GENERIC_ENTRY user as of this writing)
> isn't comfortable with this, we could switch to
> HAVE_NOINSTR_VALIDATION which is x86_64 only atm.
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> ---
>  include/linux/tracepoint.h |   13 ++++++++++++-
>  kernel/trace/trace.c       |    3 +++
>  2 files changed, 15 insertions(+), 1 deletion(-)
> 
> --- a/include/linux/tracepoint.h
> +++ b/include/linux/tracepoint.h
> @@ -178,6 +178,16 @@ static inline struct tracepoint *tracepo
>  #endif /* CONFIG_HAVE_STATIC_CALL */
>  
>  /*
> + * CONFIG_GENERIC_ENTRY archs are expected to have sanitized entry and idle
> + * code that disallow any/all tracing/instrumentation when RCU isn't watching.
> + */
> +#ifdef CONFIG_GENERIC_ENTRY
> +#define RCUIDLE_COND(rcuidle)	(rcuidle)
> +#else

Should probably move the below comment to here:

 /* srcu can't be used from NMI */

> +#define RCUIDLE_COND(rcuidle)	(rcuidle && in_nmi())
> +#endif
> +
> +/*
>   * it_func[0] is never NULL because there is at least one element in the array
>   * when the array itself is non NULL.
>   */
> @@ -189,7 +199,8 @@ static inline struct tracepoint *tracepo
>  			return;						\
>  									\
>  		/* srcu can't be used from NMI */			\

And remove the above.

-- Steve

> -		WARN_ON_ONCE(rcuidle && in_nmi());			\
> +		if (WARN_ON_ONCE(RCUIDLE_COND(rcuidle)))		\
> +			return;						\
>  									\
>  		/* keep srcu and sched-rcu usage consistent */		\
>  		preempt_disable_notrace();				\
> --- a/kernel/trace/trace.c
> +++ b/kernel/trace/trace.c
> @@ -3104,6 +3104,9 @@ void __trace_stack(struct trace_array *t
>  		return;
>  	}
>  
> +	if (WARN_ON_ONCE(IS_ENABLED(CONFIG_GENERIC_ENTRY)))
> +		return;
> +
>  	/*
>  	 * When an NMI triggers, RCU is enabled via ct_nmi_enter(),
>  	 * but if the above rcu_is_watching() failed, then the NMI
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220926144157.0406dfbb%40gandalf.local.home.
