Return-Path: <kasan-dev+bncBDC4FFVJQ4BRBKGGTCPAMGQE4WCL5HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 709F766D54A
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Jan 2023 05:25:14 +0100 (CET)
Received: by mail-vk1-xa39.google.com with SMTP id b77-20020a1f1b50000000b003bbf35b919bsf8809194vkb.11
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Jan 2023 20:25:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673929513; cv=pass;
        d=google.com; s=arc-20160816;
        b=vIzSNoYGgkxHDfmJ0LvVGt7TYwbJmOadRcK/v26+aAx5fkpEF3dVTZsC9ndyD5k3b5
         gjpGYfF8r7lGIMlYmQk88Xuh21K1MPUu+uXmVWZZmtyXKCVndNS01TICAnt4KnT1AZlM
         QylypMh4EN+4VkqupEfdv0tH/0hhZvaa8/HPt17lCQXUxo1mQJjELpJZktXjw90Tqvr7
         GgJI4EeeXqFEdf2vxHbPnyUf2VKFpU2xGpXzcIvgwdjUfwoQXhSeky2QMm5jq1wAQ70R
         cbNIkDBz9gkXXKZME8RO6GrT4Ry0MeqcZm7wnjOkEMWwAWTRwf3L6yFN5JEeBPqG84Q5
         7J1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=P8l7KPHGt5ERSEYBOEUqbpg4bfO71C+LtXGjnYfEAo4=;
        b=Z4IuMYhA5cQX9ZpYAfc4aF3sjYbvIDTsF23l1Jf8r4+J1kgyP5ir/pbF8UmZLDhgO3
         hcWQQ/2OYJ20H7whaN8b+lhGq423mejiBYGZlVvFBIXWAz1k807FqxCTpKxvzyGCurWs
         TV9hNm1L+sZ/eSna/1OTIFM8KFrBHD2narwaexe12/m51Vp183vG70veOkX0itbzPoOw
         uwvaTBjlfJMS5/H+D/gXp2l7Dl6RiLj/KHONG4q9L4iI/lc3SaJ4B6g1c1FlqfKZrSki
         nCgFccJFHTAd9ZtEwXi5jsM0sosx+RCzSsQssie0dmPfBA2xJzjJW9vVgdByFLAV4i9t
         i/vQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rvDfVQk7;
       spf=pass (google.com: domain of mhiramat@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=mhiramat@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=P8l7KPHGt5ERSEYBOEUqbpg4bfO71C+LtXGjnYfEAo4=;
        b=I8KvnVpyeG99GBhzzTVIngH7XFUPvZJsg9avAMXNr0mhHgbmgx1Q0VbFg953dkOQub
         UUd+67uQ9rAp2Kdb8WonH6NWl1+hBEdhM8R5nKJKgoOgurQNroj//YnKsGC9D58mbQPe
         8cmLcMpuSTmOlVDGJMMVBbDaEs7sKP/bO9IizcapIXLyy89up+c5Z3dPZkeBhY6vTZ81
         Csr3u3mtgnRXegjYQeA3+nmIDcuGHphtWxkGucBSNlxwz1fWJm2g8AUv7oMBJ/W9k5u6
         H9bxzFnFqlN5vRN8PvuRZlIqiInVjqIKylOAztJF3SY9UCpSdk5Oc5KkgHAiV97v+7aa
         AnLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=P8l7KPHGt5ERSEYBOEUqbpg4bfO71C+LtXGjnYfEAo4=;
        b=eETBlLobSU2skQ8XGg6MgXpGa0X/VuDmlKwitzdIxp4QWV/PfYFq5NT013Bqyk6dtp
         cH6UreAiXeBuEw1e3jGBM0w0jZa1v1uCWXEhGDhdYBTpC26JRGFx3H5mmyHvv5Zc+amf
         MTEmC+i3KOd0L6Gvn6Dx3HmMUsKTfsGsNI+HKANHy4o/kfbwF/SALxjNaRgs6aPo4o0T
         rCPHl/uFgJJu+Tf/Xj/G+mOW+8+/NwRJKOxTVVqFIuHMd7ohghVDZ1DqMjkIWO1ZV7Fa
         RjQ7WYIPM8dAohoOUvDzgjzk7ilihL3aY9kPGLJq71yk7h50qOqt26AcTiwpym/Rmrr6
         sZFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2ko1kaVnH5TOEbLQeSV5W8At09fekyjWtdUN2CE7f6k31PWFVvGG
	O8QYN0t58FWBGus2ojXlxAo=
X-Google-Smtp-Source: AMrXdXvcQZtTHNopuk99R7Tbg9H7j9g0dfVK+yRDuokoc0SqJBGtVRWFBRVS8ZyP6K4lv9keDx3hzg==
X-Received: by 2002:a05:6102:2828:b0:3b1:40eb:5957 with SMTP id ba8-20020a056102282800b003b140eb5957mr181501vsb.66.1673929513079;
        Mon, 16 Jan 2023 20:25:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c481:0:b0:3cb:9ab3:81b0 with SMTP id d1-20020a67c481000000b003cb9ab381b0ls4367974vsk.7.-pod-prod-gmail;
 Mon, 16 Jan 2023 20:25:12 -0800 (PST)
X-Received: by 2002:a05:6102:c52:b0:3d3:c4d4:45f5 with SMTP id y18-20020a0561020c5200b003d3c4d445f5mr622466vss.2.1673929512309;
        Mon, 16 Jan 2023 20:25:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673929512; cv=none;
        d=google.com; s=arc-20160816;
        b=tMGzxtuk3hugMrFktoIkf7a2eS0CZ9JhDjuRZolDv2cOFGf931j/qoI3JC1u/Iokt9
         hcY7bRtpKA10mXF6VmyqP3dR/CKccv5GOnE5s+6RGOOQXpCseUwgV8ubTlZu7mLtwhuC
         0CWncsz3mWde8kDbOjVt8PZGEDQ+fcMr3iS+C2PBfobmH2r1+QMbpRMFtATH56b9r3fU
         by3jYHc81x1Ahso2J7X0dbZcr686hG7Y5XgIRaVo6LbOap4g7vK29WtHItId8olOLoM9
         V1jOMMfIKFLgEyzFba2orNiNpLlimLetB2SK197bCkmXj+2/tCNjy5s1XOWbNTmx/lls
         yAXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=cSuIPYyHm9QphoxZwaYLXkJJo2RCcIOu+JwHdiOfIk0=;
        b=kSATN1mjM6+39bHl3+i/eJVkBFFxvweShMUYyh01HR+14TiCAdLa9WIDgGayMb7+dd
         xG9Bf7VHluM9emr/NonYI/Qzv04Q/T5oTMK4mFuwpDZD6qukjsrpb+ZU+AmCb7juMj89
         tQgLXkeJH02tfKA4smrwBOqUBPCN2XObcMEst5bcAjJ54y5DluUkFu390H3AKwBm5Kax
         rgTXpFoGmcYFg9SvGPyW0mvM+CyVq//uTpeYTX1ot8VzDoxXD6K6RUVjcUlFvKk8C2Mv
         LysogeQXEVS+vnsMEPTGFrJolaO3FrPFj0jTOmFzMhh0GUh4oB8ZANwoddmQEEhTHE0P
         CSog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rvDfVQk7;
       spf=pass (google.com: domain of mhiramat@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=mhiramat@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id ay9-20020a056130030900b005e2cbd30052si4140589uab.1.2023.01.16.20.25.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Jan 2023 20:25:12 -0800 (PST)
Received-SPF: pass (google.com: domain of mhiramat@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 7BE61611AF;
	Tue, 17 Jan 2023 04:25:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B0701C433EF;
	Tue, 17 Jan 2023 04:24:47 +0000 (UTC)
Date: Tue, 17 Jan 2023 13:24:46 +0900
From: Masami Hiramatsu (Google) <mhiramat@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru,
 mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk,
 nsekhar@ti.com, brgl@bgdev.pl, ulli.kroll@googlemail.com,
 linus.walleij@linaro.org, shawnguo@kernel.org, Sascha Hauer
 <s.hauer@pengutronix.de>, kernel@pengutronix.de, festevam@gmail.com,
 linux-imx@nxp.com, tony@atomide.com, khilman@kernel.org,
 krzysztof.kozlowski@linaro.org, alim.akhtar@samsung.com,
 catalin.marinas@arm.com, will@kernel.org, guoren@kernel.org,
 bcain@quicinc.com, chenhuacai@kernel.org, kernel@xen0n.name,
 geert@linux-m68k.org, sammy@sammy.net, monstr@monstr.eu,
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
 agross@kernel.org, andersson@kernel.org, konrad.dybcio@linaro.org,
 anup@brainfault.org, thierry.reding@gmail.com, jonathanh@nvidia.com,
 jacob.jun.pan@linux.intel.com, atishp@atishpatra.org, Arnd Bergmann
 <arnd@arndb.de>, yury.norov@gmail.com, andriy.shevchenko@linux.intel.com,
 linux@rasmusvillemoes.dk, dennis@kernel.org, tj@kernel.org, cl@linux.com,
 rostedt@goodmis.org, mhiramat@kernel.org, frederic@kernel.org,
 paulmck@kernel.org, pmladek@suse.com, senozhatsky@chromium.org,
 john.ogness@linutronix.de, juri.lelli@redhat.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com,
 mgorman@suse.de, bristot@redhat.com, vschneid@redhat.com,
 ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
 dvyukov@google.com, vincenzo.frascino@arm.com, Andrew Morton
 <akpm@linux-foundation.org>, jpoimboe@kernel.org,
 linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-snps-arc@lists.infradead.org, linux-omap@vger.kernel.org,
 linux-samsung-soc@vger.kernel.org, linux-csky@vger.kernel.org,
 linux-hexagon@vger.kernel.org, linux-ia64@vger.kernel.org,
 loongarch@lists.linux.dev, linux-m68k@lists.linux-m68k.org,
 linux-mips@vger.kernel.org, openrisc@lists.librecores.org,
 linux-parisc@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-sh@vger.kernel.org, sparclinux@vger.kernel.org,
 linux-um@lists.infradead.org, linux-perf-users@vger.kernel.org,
 virtualization@lists.linux-foundation.org, linux-xtensa@linux-xtensa.org,
 linux-acpi@vger.kernel.org, linux-pm@vger.kernel.org,
 linux-clk@vger.kernel.org, linux-arm-msm@vger.kernel.org,
 linux-tegra@vger.kernel.org, linux-arch@vger.kernel.org,
 linux-mm@kvack.org, linux-trace-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 35/51] trace,hardirq: No moar _rcuidle() tracing
Message-Id: <20230117132446.02ec12e4c10718de27790900@kernel.org>
In-Reply-To: <20230112195541.477416709@infradead.org>
References: <20230112194314.845371875@infradead.org>
	<20230112195541.477416709@infradead.org>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mhiramat@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rvDfVQk7;       spf=pass
 (google.com: domain of mhiramat@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=mhiramat@kernel.org;       dmarc=pass
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

Hi Peter,

On Thu, 12 Jan 2023 20:43:49 +0100
Peter Zijlstra <peterz@infradead.org> wrote:

> Robot reported that trace_hardirqs_{on,off}() tickle the forbidden
> _rcuidle() tracepoint through local_irq_{en,dis}able().
> 
> For 'sane' configs, these calls will only happen with RCU enabled and
> as such can use the regular tracepoint. This also means it's possible
> to trace them from NMI context again.
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>

The code looks good to me. I just have a question about comment.

> ---
>  kernel/trace/trace_preemptirq.c |   21 +++++++++++++--------
>  1 file changed, 13 insertions(+), 8 deletions(-)
> 
> --- a/kernel/trace/trace_preemptirq.c
> +++ b/kernel/trace/trace_preemptirq.c
> @@ -20,6 +20,15 @@
>  static DEFINE_PER_CPU(int, tracing_irq_cpu);
>  
>  /*
> + * ...

Is this intended? Wouldn't you leave any comment here?

Thank you,

> + */
> +#ifdef CONFIG_ARCH_WANTS_NO_INSTR
> +#define trace(point)	trace_##point
> +#else
> +#define trace(point)	if (!in_nmi()) trace_##point##_rcuidle
> +#endif
> +
> +/*
>   * Like trace_hardirqs_on() but without the lockdep invocation. This is
>   * used in the low level entry code where the ordering vs. RCU is important
>   * and lockdep uses a staged approach which splits the lockdep hardirq
> @@ -28,8 +37,7 @@ static DEFINE_PER_CPU(int, tracing_irq_c
>  void trace_hardirqs_on_prepare(void)
>  {
>  	if (this_cpu_read(tracing_irq_cpu)) {
> -		if (!in_nmi())
> -			trace_irq_enable(CALLER_ADDR0, CALLER_ADDR1);
> +		trace(irq_enable)(CALLER_ADDR0, CALLER_ADDR1);
>  		tracer_hardirqs_on(CALLER_ADDR0, CALLER_ADDR1);
>  		this_cpu_write(tracing_irq_cpu, 0);
>  	}
> @@ -40,8 +48,7 @@ NOKPROBE_SYMBOL(trace_hardirqs_on_prepar
>  void trace_hardirqs_on(void)
>  {
>  	if (this_cpu_read(tracing_irq_cpu)) {
> -		if (!in_nmi())
> -			trace_irq_enable_rcuidle(CALLER_ADDR0, CALLER_ADDR1);
> +		trace(irq_enable)(CALLER_ADDR0, CALLER_ADDR1);
>  		tracer_hardirqs_on(CALLER_ADDR0, CALLER_ADDR1);
>  		this_cpu_write(tracing_irq_cpu, 0);
>  	}
> @@ -63,8 +70,7 @@ void trace_hardirqs_off_finish(void)
>  	if (!this_cpu_read(tracing_irq_cpu)) {
>  		this_cpu_write(tracing_irq_cpu, 1);
>  		tracer_hardirqs_off(CALLER_ADDR0, CALLER_ADDR1);
> -		if (!in_nmi())
> -			trace_irq_disable(CALLER_ADDR0, CALLER_ADDR1);
> +		trace(irq_disable)(CALLER_ADDR0, CALLER_ADDR1);
>  	}
>  
>  }
> @@ -78,8 +84,7 @@ void trace_hardirqs_off(void)
>  	if (!this_cpu_read(tracing_irq_cpu)) {
>  		this_cpu_write(tracing_irq_cpu, 1);
>  		tracer_hardirqs_off(CALLER_ADDR0, CALLER_ADDR1);
> -		if (!in_nmi())
> -			trace_irq_disable_rcuidle(CALLER_ADDR0, CALLER_ADDR1);
> +		trace(irq_disable)(CALLER_ADDR0, CALLER_ADDR1);
>  	}
>  }
>  EXPORT_SYMBOL(trace_hardirqs_off);
> 
> 


-- 
Masami Hiramatsu (Google) <mhiramat@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230117132446.02ec12e4c10718de27790900%40kernel.org.
