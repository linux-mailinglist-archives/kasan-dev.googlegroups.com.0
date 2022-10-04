Return-Path: <kasan-dev+bncBDV37XP3XYDRBPGW6GMQMGQEB4VZ36Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 671FA5F482F
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Oct 2022 19:19:57 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id a13-20020a2ebe8d000000b0026bfc93da46sf4425159ljr.16
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Oct 2022 10:19:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664903996; cv=pass;
        d=google.com; s=arc-20160816;
        b=xh8lhlzoA935KG5OwRN2781y7Dnkb/IiIBfa3uzIqGe86YvQ6sMigBu3TmOJV1Usam
         5FbGXvCR2s6KkE7lCW8xXmzXlIlAZXk0iOQuRGjuoKbaEoRZpI494TrB2l5tI55NlufP
         4DMlhHAjhx2AJkoPrvurtjME6h1Agu8Af1+mTFFJqmDTBAsIX0egYt6AQ8BOKVHBoJqf
         V09UD3kkS8bA2R47wgddl0j3wYkIUgCBGE3jPdt/QK0hcLVDUaC9bgDNmvfZRQnG/dz6
         xa1ymhrd4JBoJ4+G48U3sLtWCudaw5zO0C4FXPVgKZKpvskNbkomCopaxlCRuulYRHIe
         AcSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6RHsZ+/3tc0oRwzCX0/ifUhA/auDZwRTucNL/g2c5sc=;
        b=EhBIqGDka69hFhBJK1iuxJrPaP26K4BgLm7VQ7KLw3bWWSfFBBn5ORyMfSzc012mJN
         M7tFtSimr0zQ9g4auemuQBJJJ23GJykk6ItsYYaiz2NGi4ylgk+33MwGmioak9AomE4F
         +5VPonn07AL0Z77Cg0Jfed178OBBmcMi4FReo++14cqkdywTD0SxiBEAgfP2F0IaMwgJ
         M502Cf6J2ophDVATErFNikx4H3lDaltegtwIpYUM4AAuoiI5fB9oLwX7SHkyAS/OsGJQ
         2+BAKOXu3n59y96P6EYSXez3QhSNeEB3WhgwtiFMMDQ5HdIblajPZVKkKlH5Rvwvkn4e
         xaYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=6RHsZ+/3tc0oRwzCX0/ifUhA/auDZwRTucNL/g2c5sc=;
        b=GI7+BHfjvJZakAhQ5C1qYEO8NgPZSTHUHrdAxKYNcmWutmYdDT55HyN+LDfauC6Lra
         Cd8dRXr2Qgtyr2M0/BggV414voLtseaSyYqcMp6nHw83sO1/K6hqTMEjeO3lXIdW9d0a
         NM1LsXvnibfSbqau8lriZocqq6wIjl9ykZtKlW9vaUvX1msBaNAm5buL3rsi9RjBkqMq
         W33u4G069gJiFe4UFjaF1tadAJui6cNvjxXmk5dCmty7O658Mqv7+bfYo/vRoodR4VR7
         QpewZ2so4xNu0n+DETHFSfqy03ebA7KV6pQ1AbeALEN/wEhrhwpDsK0mJonqELgL0HIX
         zx7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=6RHsZ+/3tc0oRwzCX0/ifUhA/auDZwRTucNL/g2c5sc=;
        b=1bYCcESH6RKuwQKhvTElyMxJx07zGlB0hFXAGs4QSoKZYCkzxryt3pBYUy+y9n6T1x
         kdkyFTlKaGDXgvqG9ZAm25GBlhMv0bO7UN8SB+XUXj8HYQ7xJk5XBRSD9hJ8R5hBwN6+
         6oxc020upMqLWCqcCln/KQ6tFkb9pwVYcCGRzQTUxeBqXwABkUZ0E2fRp/gXdcNWOiDs
         1MLTSZqT2/wfNYP0Bnw/Ox28Uj3l6DeWn4z0Q62DPsS8i6SHKesI2GD5E016Oy2ZPtLy
         91qlK9TGfHiwE8OyfXWjUq2ET3qpmjjSKgrEQRdXbkwQKUV+h7djEYL6ddB5Kzh0Yaux
         g/9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0uZwwVT0OiC1I2/gNFZrpfoliOswZWpvpMhMxk3sIyjiAg2QQI
	FS3PfQNpDU6GyxYmpQnGT9E=
X-Google-Smtp-Source: AMsMyM78S2os+H0S+Xi0GN1RtCFygG3l9XNcHugEexgbSIbfcM+TCoftxxQKsCG2nVED5xjK4HSj3A==
X-Received: by 2002:a05:6512:3996:b0:4a2:1c8c:c9a1 with SMTP id j22-20020a056512399600b004a21c8cc9a1mr6665255lfu.230.1664903996663;
        Tue, 04 Oct 2022 10:19:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f5b:0:b0:4a2:3951:eac8 with SMTP id 27-20020ac25f5b000000b004a23951eac8ls388243lfz.0.-pod-prod-gmail;
 Tue, 04 Oct 2022 10:19:55 -0700 (PDT)
X-Received: by 2002:ac2:5e61:0:b0:4a2:2ab1:4678 with SMTP id a1-20020ac25e61000000b004a22ab14678mr4723380lfr.400.1664903995201;
        Tue, 04 Oct 2022 10:19:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664903995; cv=none;
        d=google.com; s=arc-20160816;
        b=ytTyG8273s7UC7U4aN0zBQMkZ/IaRzjvfeGzudk9cKBz2j3eU8MGipwQ1DYuDlfgce
         SW9CwNcv1mUxNO4OZI6sqSMLzPoVZ8wzbFxdQERS/h+D9hJq8rzxO3sLzvh+drCLD9oh
         uqWa3kPzTjaBHovOeZ+QKvrSxUgNJ7z5UPno8XPRg0zoVM3cTAJUefI1hyrbmDwLyXFN
         cou9u7lSntGK5qxS2u7mNELz7RO7NlEQi8nou+gp1mgaAvIVlX8Tj6ksWfEQnilj8Qdv
         eHnT2+JWSr5KauLPVFPyc3gdtD6xKPffR0F2d4kSZBWE9FqnTOp9wHKuJF9uGQJt7g37
         mQSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=S4F9bNfkzsvmKq+f4o0L/SYkwUhxsczItvqblEm+OiA=;
        b=macnUMLSkc0bSpFuxDYkG3ICskO8+xE81mpo730DDAmLKlIkZ+kltL9FuoRx5iWVsS
         SKM63lq48aum5tX3x8APfMYDiTp4/W32ib37Z7yxleN/8ORh8NvSAaXRtbZM2oaRU8re
         WTjBMUDgfQRagl0gEu68gv6rTM1R5oCRalcfwgfvK/UDw45CppN4eyC1x7lYde4wYyjK
         z9NFNtdSsPKGYdLGxWuPgEpA1g7yPe2M/t9+dKgNP7U6q95HFKxopTprENBsnVJIwk4M
         JCLst06fDopzqLe9CgMCHJuRG8w4mn0+PHI/+Ph8X5c+FsSrWIO2/q7QaWNzLNBrnAsE
         b7Hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id v10-20020a2ea44a000000b0026d92a5f977si451908ljn.1.2022.10.04.10.19.54
        for <kasan-dev@googlegroups.com>;
        Tue, 04 Oct 2022 10:19:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 99510113E;
	Tue,  4 Oct 2022 10:20:00 -0700 (PDT)
Received: from FVFF77S0Q05N.cambridge.arm.com (FVFF77S0Q05N.cambridge.arm.com [10.1.38.139])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2E7683F792;
	Tue,  4 Oct 2022 10:19:38 -0700 (PDT)
Date: Tue, 4 Oct 2022 18:19:33 +0100
From: Mark Rutland <mark.rutland@arm.com>
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
	hpa@zytor.com, acme@kernel.org, alexander.shishkin@linux.intel.com,
	jolsa@kernel.org, namhyung@kernel.org, jgross@suse.com,
	srivatsa@csail.mit.edu, amakhalov@vmware.com, pv-drivers@vmware.com,
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
Subject: Re: [PATCH v2 33/44] ftrace: WARN on rcuidle
Message-ID: <YzxrJYjKxy/vUc5n@FVFF77S0Q05N.cambridge.arm.com>
References: <20220919095939.761690562@infradead.org>
 <20220919101522.573936213@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919101522.573936213@infradead.org>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Sep 19, 2022 at 12:00:12PM +0200, Peter Zijlstra wrote:
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
> +#define RCUIDLE_COND(rcuidle)	(rcuidle && in_nmi())
> +#endif

Could we make this depend on ARCH_WANTS_NO_INSTR instead?

That'll allow arm64 to check this even though we're not using the generic entry
code (and there's lots of work necessary to make that possible...).

Thanks,
Mark.

> +
> +/*
>   * it_func[0] is never NULL because there is at least one element in the array
>   * when the array itself is non NULL.
>   */
> @@ -189,7 +199,8 @@ static inline struct tracepoint *tracepo
>  			return;						\
>  									\
>  		/* srcu can't be used from NMI */			\
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
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzxrJYjKxy/vUc5n%40FVFF77S0Q05N.cambridge.arm.com.
