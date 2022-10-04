Return-Path: <kasan-dev+bncBDF57NG2XIHRBNVI6CMQMGQEGTKMIOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 445D65F4176
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Oct 2022 13:08:40 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-1278be3dc4csf8746453fac.15
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Oct 2022 04:08:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664881718; cv=pass;
        d=google.com; s=arc-20160816;
        b=oOYFvk0dO80vA3uSVvY7zF3r/UmyybUIZzXqH2Vn62VEN84UTk8EwEYyX4Nwc8zEIz
         Af1yOSwlN4l5942CoL4yi5fLTmHBAEGRgXKxL9ZHmQeZaS1bgaYBtOs2tTN0rlASmD5v
         KALre1jdoOq4IrAKuwo2ArMZ+bxQ1OIsDYsiYGUp8BRuKqd7XK9yQEoz8gNzII3HmWwJ
         MTBWOcqBCXJH1inrbLK5Sbzflz71lN0D0WI+4+xS9pcEXElD/M5qXpTa/Te27PZEvRIh
         XJg37HbYrhuOnPHmv95PTbQ0K8UCgNB/dNkyQnh1YuWTtccr18S9fSNjshPRTwWVAX4D
         wD/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=Ab36qGpV93OwHlnX3jqk/5UsCPnrx6igolS1qua4zeI=;
        b=KdTXagZ5RHf8IqXDuugpmtcOHSCjRlA7rEuYDb7f4POjSgqPioqrqkghzCngZvv6YI
         HFnvSz8S4EReZffNMiw//zdQRWpxYKu39SzpdWQ8eJ4TfUEVSqKWqyFtu0/8m25U9o85
         OpNF/kVPAxE/u17Vr+K2zqgMjXtOy0SG9Zu2O/3mtTJNxQAJDy5EPENyYQmeGK+W9RhH
         alLz6N0tNM/rNYlZU9URNBgm5JttvzSuWxI23lej6oJGp9HSfrbViqdBZJWmCDsrU+/T
         13rfcwaS73hYiAddlCdjusjsQL7kQ1qNHx1TDyv4JtNgHpXNhDO4iO8PXVgs7QCQVniv
         umbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=EnhlO7Dc;
       spf=pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=Ab36qGpV93OwHlnX3jqk/5UsCPnrx6igolS1qua4zeI=;
        b=i2z8MrcBdHzBWSIUrozoTtLGcO0jWAnQgiuJv+c8rXlxF0DsY5SJAEbCQXgW2sEZMp
         kvrP/IUpjuBOqvKHhG8b3yeM3dzCiAZ/qRk/u9sAp84mscoqzQ0Cnf5xfw6LAiGWvJWe
         LkAvqoC1MtT67zcFU54hS2WTbY1oJZjpMR2jaQC1JhQNWGb6PYCe258iJvpQtz+0Qh5/
         /ws1CwvJkMKxHXrLpzPD99V9UEoZqHlltfI9Oe9xo5XZT3nEqUjO/nlLvzeo/53TI+n9
         zB8LipKaPqDrDKRiGCCettRZD5hoBUI5adjCE8yiF+aPxGCaGac0bzYpFzs0Brz9j0Cg
         W2rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=Ab36qGpV93OwHlnX3jqk/5UsCPnrx6igolS1qua4zeI=;
        b=tdZ3aQZh+BexjmtXko36n4Rq6oIei3pX0OA3owNSiJk2yq1OwDwm+6JHr0o2W4YX1I
         s25pgzWSHZeDdhZKboa53/DF9tmMhhmhoQLXoi0l8KJbhSvjjyZUnVTG5EUg9o2lvd7K
         E4x6jE4siQCnPlAlMOnHOrG1aqAcBGfyB9HLtw/HQ/sRlGZW/NYvNBNDfGyhle9k+VF7
         F2OX8zz/VwTcJ2naq4YXasu+YZK0qD29ko4Wp9AmQtxGozhkvHTri7a44FNXgjet8SKU
         eU36FMFYmOAiIGCkuwuvM16pv9NSojckUrGe9GtLtA9yMBOZqxUifcVEdPfxcZnGUeoI
         ZJwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2PAT8EzgVd5YqxMD2+xvNLXuQzjIubjsdXlewhVxWLW4m0GmPB
	/xS6KT/kXxp7DUavmwZzDTQ=
X-Google-Smtp-Source: AMsMyM5BdZSfoc98xcbxbwMmGgA/OLMYUc9ESnawefKAdQ4ZZwOdSfLgDscPtWSmGRJmq7X7IEfIwA==
X-Received: by 2002:a05:6830:3115:b0:658:ea61:249c with SMTP id b21-20020a056830311500b00658ea61249cmr9954267ots.225.1664881718693;
        Tue, 04 Oct 2022 04:08:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:307:b0:131:8180:91a with SMTP id
 b7-20020a056871030700b001318180091als4294498oag.8.-pod-prod-gmail; Tue, 04
 Oct 2022 04:08:38 -0700 (PDT)
X-Received: by 2002:a05:6870:601a:b0:132:7b87:1616 with SMTP id t26-20020a056870601a00b001327b871616mr4075432oaa.192.1664881718259;
        Tue, 04 Oct 2022 04:08:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664881718; cv=none;
        d=google.com; s=arc-20160816;
        b=PlWrHs+zWt8iCYWaOmOh25vJgcpsVtSw3RkZoz6vzxZCKN/2NxWPaTHxi/wURZBFRG
         WtxO5zpQjvZZE7dn1duV0BUvXkuzc3epO/bMREz/M54QLcQiid+8ofvSvpOysbAfivFc
         b0FDjOhH+lacsRXZwzWy0nmEy2O5Ne1GDUIqDaR3CLm4o6jstMmRw9o/6AX9yhqpvaBn
         pEKE68hrzOazAP3ByasPiMfLFhXFOEAxh73RsY3ewhIZt7Hryg6Pn7odMEUTUIB5YRUE
         h0AQylrM72iFbKdB+1wc7/Xwk0HXmfYA69Ma+7hLOReVIAG6KMaDTfa9otrgGbYTzlJI
         OqCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Gtwwkxm3K9zy3ub+GhlddjjtZ7fh91sG2Y46OOYgmCM=;
        b=B7GGTG9IPDrhaFG6C573tb9AiWRJ2iwYJZHq8PYcE9+IS6W3fDWqa4W0Gqkzf25gWq
         AKosTXPYwnGsDgR1fmKd5d+xaSOdq6pZYVxj/wlorMP2OHqHvHnrAy2pwbq3Mrf7/y6r
         UWmqZ9ram/QkZtXG7jJVGt0LmBRZhRXWaO6u1JtcNJozvrOzqQJDUm1zMOCAEkRHGXr6
         V7cT+yZ399zYo9FX/2WGcV6Or47IlWt3P7hRZdzLple8735bZ5QhnsIbHH0qcbkzTxSc
         Gizd0wf0h1gh7Jub1xapzQamXpyxEOkPnIoy4nOcKUv4vVmtYG58ISBmqArJtocm4uei
         R0oA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=EnhlO7Dc;
       spf=pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id c37-20020a05687047a500b0011ca4383bd6si729373oaq.4.2022.10.04.04.08.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Oct 2022 04:08:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id bu5-20020a17090aee4500b00202e9ca2182so1225722pjb.0
        for <kasan-dev@googlegroups.com>; Tue, 04 Oct 2022 04:08:38 -0700 (PDT)
X-Received: by 2002:a17:90b:1b06:b0:202:cce0:2148 with SMTP id
 nu6-20020a17090b1b0600b00202cce02148mr17035330pjb.84.1664881717434; Tue, 04
 Oct 2022 04:08:37 -0700 (PDT)
MIME-Version: 1.0
References: <20220919095939.761690562@infradead.org> <20220919101521.886766952@infradead.org>
In-Reply-To: <20220919101521.886766952@infradead.org>
From: Ulf Hansson <ulf.hansson@linaro.org>
Date: Tue, 4 Oct 2022 13:08:00 +0200
Message-ID: <CAPDyKFoMidikoTPe0Xd+wZQdBBJSoy+CZ2ZmJShfLkbGZZRYDQ@mail.gmail.com>
Subject: Re: [PATCH v2 23/44] arm,smp: Remove trace_.*_rcuidle() usage
To: Peter Zijlstra <peterz@infradead.org>
Cc: juri.lelli@redhat.com, rafael@kernel.org, catalin.marinas@arm.com, 
	linus.walleij@linaro.org, bsegall@google.com, guoren@kernel.org, pavel@ucw.cz, 
	agordeev@linux.ibm.com, linux-arch@vger.kernel.org, 
	vincent.guittot@linaro.org, mpe@ellerman.id.au, chenhuacai@kernel.org, 
	christophe.leroy@csgroup.eu, linux-acpi@vger.kernel.org, agross@kernel.org, 
	geert@linux-m68k.org, linux-imx@nxp.com, vgupta@kernel.org, 
	mattst88@gmail.com, mturquette@baylibre.com, sammy@sammy.net, 
	pmladek@suse.com, linux-pm@vger.kernel.org, 
	Sascha Hauer <s.hauer@pengutronix.de>, linux-um@lists.infradead.org, npiggin@gmail.com, 
	tglx@linutronix.de, linux-omap@vger.kernel.org, dietmar.eggemann@arm.com, 
	andreyknvl@gmail.com, gregkh@linuxfoundation.org, 
	linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org, 
	senozhatsky@chromium.org, svens@linux.ibm.com, jolsa@kernel.org, 
	tj@kernel.org, Andrew Morton <akpm@linux-foundation.org>, mark.rutland@arm.com, 
	linux-ia64@vger.kernel.org, dave.hansen@linux.intel.com, 
	virtualization@lists.linux-foundation.org, 
	James.Bottomley@hansenpartnership.com, jcmvbkbc@gmail.com, 
	thierry.reding@gmail.com, kernel@xen0n.name, cl@linux.com, 
	linux-s390@vger.kernel.org, vschneid@redhat.com, john.ogness@linutronix.de, 
	ysato@users.sourceforge.jp, linux-sh@vger.kernel.org, festevam@gmail.com, 
	deller@gmx.de, daniel.lezcano@linaro.org, jonathanh@nvidia.com, 
	dennis@kernel.org, lenb@kernel.org, linux-xtensa@linux-xtensa.org, 
	kernel@pengutronix.de, gor@linux.ibm.com, linux-arm-msm@vger.kernel.org, 
	linux-alpha@vger.kernel.org, linux-m68k@lists.linux-m68k.org, 
	loongarch@lists.linux.dev, shorne@gmail.com, chris@zankel.net, 
	sboyd@kernel.org, dinguyen@kernel.org, bristot@redhat.com, 
	alexander.shishkin@linux.intel.com, fweisbec@gmail.com, lpieralisi@kernel.org, 
	atishp@atishpatra.org, linux@rasmusvillemoes.dk, kasan-dev@googlegroups.com, 
	will@kernel.org, boris.ostrovsky@oracle.com, khilman@kernel.org, 
	linux-csky@vger.kernel.org, pv-drivers@vmware.com, 
	linux-snps-arc@lists.infradead.org, mgorman@suse.de, 
	jacob.jun.pan@linux.intel.com, Arnd Bergmann <arnd@arndb.de>, ulli.kroll@googlemail.com, 
	linux-clk@vger.kernel.org, rostedt@goodmis.org, ink@jurassic.park.msu.ru, 
	bcain@quicinc.com, tsbogend@alpha.franken.de, linux-parisc@vger.kernel.org, 
	ryabinin.a.a@gmail.com, sudeep.holla@arm.com, shawnguo@kernel.org, 
	davem@davemloft.net, dalias@libc.org, tony@atomide.com, amakhalov@vmware.com, 
	konrad.dybcio@somainline.org, bjorn.andersson@linaro.org, glider@google.com, 
	hpa@zytor.com, sparclinux@vger.kernel.org, linux-hexagon@vger.kernel.org, 
	linux-riscv@lists.infradead.org, vincenzo.frascino@arm.com, 
	anton.ivanov@cambridgegreys.com, jonas@southpole.se, yury.norov@gmail.com, 
	richard@nod.at, x86@kernel.org, linux@armlinux.org.uk, mingo@redhat.com, 
	aou@eecs.berkeley.edu, hca@linux.ibm.com, richard.henderson@linaro.org, 
	stefan.kristiansson@saunalahti.fi, openrisc@lists.librecores.org, 
	acme@kernel.org, paul.walmsley@sifive.com, linux-tegra@vger.kernel.org, 
	namhyung@kernel.org, andriy.shevchenko@linux.intel.com, jpoimboe@kernel.org, 
	dvyukov@google.com, jgross@suse.com, monstr@monstr.eu, 
	linux-mips@vger.kernel.org, palmer@dabbelt.com, anup@brainfault.org, 
	bp@alien8.de, johannes@sipsolutions.net, linuxppc-dev@lists.ozlabs.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ulf.hansson@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=EnhlO7Dc;       spf=pass
 (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::1031
 as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Mon, 19 Sept 2022 at 12:18, Peter Zijlstra <peterz@infradead.org> wrote:
>
> None of these functions should ever be ran with RCU disabled anymore.
>
> Specifically, do_handle_IPI() is only called from handle_IPI() which
> explicitly does irq_enter()/irq_exit() which ensures RCU is watching.
>
> The problem with smp_cross_call() was, per commit 7c64cc0531fa ("arm: Use
> _rcuidle for smp_cross_call() tracepoints"), that
> cpuidle_enter_state_coupled() already had RCU disabled, but that's
> long been fixed by commit 1098582a0f6c ("sched,idle,rcu: Push rcu_idle
> deeper into the idle path").
>
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>

FWIW:

Reviewed-by: Ulf Hansson <ulf.hansson@linaro.org>

Kind regards
Uffe

> ---
>  arch/arm/kernel/smp.c |    6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> --- a/arch/arm/kernel/smp.c
> +++ b/arch/arm/kernel/smp.c
> @@ -639,7 +639,7 @@ static void do_handle_IPI(int ipinr)
>         unsigned int cpu = smp_processor_id();
>
>         if ((unsigned)ipinr < NR_IPI)
> -               trace_ipi_entry_rcuidle(ipi_types[ipinr]);
> +               trace_ipi_entry(ipi_types[ipinr]);
>
>         switch (ipinr) {
>         case IPI_WAKEUP:
> @@ -686,7 +686,7 @@ static void do_handle_IPI(int ipinr)
>         }
>
>         if ((unsigned)ipinr < NR_IPI)
> -               trace_ipi_exit_rcuidle(ipi_types[ipinr]);
> +               trace_ipi_exit(ipi_types[ipinr]);
>  }
>
>  /* Legacy version, should go away once all irqchips have been converted */
> @@ -709,7 +709,7 @@ static irqreturn_t ipi_handler(int irq,
>
>  static void smp_cross_call(const struct cpumask *target, unsigned int ipinr)
>  {
> -       trace_ipi_raise_rcuidle(target, ipi_types[ipinr]);
> +       trace_ipi_raise(target, ipi_types[ipinr]);
>         __ipi_send_mask(ipi_desc[ipinr], target);
>  }
>
>
>
> _______________________________________________
> Virtualization mailing list
> Virtualization@lists.linux-foundation.org
> https://lists.linuxfoundation.org/mailman/listinfo/virtualization

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAPDyKFoMidikoTPe0Xd%2BwZQdBBJSoy%2BCZ2ZmJShfLkbGZZRYDQ%40mail.gmail.com.
