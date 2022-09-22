Return-Path: <kasan-dev+bncBAABBTHAV2MQMGQEHQJSF3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id B02E55E5785
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Sep 2022 02:46:05 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id s17-20020a056402521100b004511c8d59e3sf5541451edd.11
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Sep 2022 17:46:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663807565; cv=pass;
        d=google.com; s=arc-20160816;
        b=iakRIw/muVVc+bA8UBZvd2/Oic64eaRZBcnQTzmYW0ya/ulN6CO4luxlDV4XzK6w5/
         MLIcx+cfPTY8Qjo3QtLD6BAcbkTf/0CZOAF0fNatnmVpbSQawfnkX9qPY2HS8yxHimLQ
         Fxp7qAx11T5PKQFMpSGMbOXauU4BI/iEXDiRDNasQdzC7q8wxuyHoUMTBOxUZso+PmNx
         nfd30m7RxmiAscH5wKmuNEBGODbvg06g2O6SaUC1vqotcy0uOxpqplh3oL1cL4tVe9pa
         DP1NK2GZ+ER7nMpFyG6qim8CKGkDcld7H6H8ulK6ahy5bhRmiiMUhhPa5FjBR6YNk55B
         DXuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=xN4hj1tikbuNtUjtRqIXnwPpZmnPP5c9ulf4P8ns+Xo=;
        b=hWKHax8JtJGcleFfv8ZDwDA7e8k8st68KRONPQa3+6pUd9U0MjT5HEIanErvpxjaac
         IMRrizQaBWrpHLj7M5lHdaXVhWcl5AEregBaYbtlUH/HtAHpGzbZLvdoSsRwzrT6le/X
         hSAWd1iDC/kW8zzLUg6IhtoCW6naXd6wZQZzyGH80G883A9HcSmuX4NnaWOfircWrOVC
         ICHRaJVo3Q3xT31OVTmFntuG2b97dGRGVWy4QvT+EC3qRFkphyfvGKHKCbTymggl2/1N
         pC7YSuCwHm6XGteLFey2tCYmRy48T0WUA83N0lnIK7OnFq9YfD/Zb0/6TXcicj32ZIHm
         VN4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qaUYBCa8;
       spf=pass (google.com: domain of guoren@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=guoren@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=xN4hj1tikbuNtUjtRqIXnwPpZmnPP5c9ulf4P8ns+Xo=;
        b=OJWbCteCZNUrvttpGszC5JNh2iMW951qaskT3IM5qS6rGGljzn3fF2h8MhmaoAY+lP
         bbBjXQ5YDsm2XycHwzT9cBc1Q3ImIjIMaFUqXFidUajwBJfPF2Bfws5yl03f7SKcPh2x
         dKvANzfPKfFKPq26kZB8qA7Faqu0zYRe9vmf82jX6eKpmOSuYSKFoCSQSrAe/v4uI4Lq
         hDdDyLb3RxyK7xpum852R/fzLMmREGs9RsT25/l+d3OuA0GMbwv5/gDoduSGjFxhgLve
         ZdR90jC6sBgbcrvLTGKr5bOxnNvic1DCDJmZ429apYSGt+VbEty00kTQi+/CQ3mXzl8e
         KyGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=xN4hj1tikbuNtUjtRqIXnwPpZmnPP5c9ulf4P8ns+Xo=;
        b=2yvIcbyF43Va9uwSXwEdbIH2y967GJckwKR3ZjgQgbkFnyPZTPhu+CVvV8el+OcpvR
         Osk1FGH8rORIItmgEqPymTjog6fyg/ie/2YVYubIXGU/73aCnGIpsAAKFWnrJwkTROqc
         QrTpbXFR4VIEM2PnTTk/cokxLKoK1XmLynV6JCJYYHAB/5RX6ELehA3eWMtq1Mu2rJYP
         NRlMAiMmDM8VfJ/RoxJPYgFjcTQGjxso39CqBMIwry0pBe6oD0hYedFx58310b+azVWZ
         VQolIPB1gtSMPJvVSlxDjy5rSM4AwhSxCcSZrsCVWF7G3yffSMjDQQt2G2atdtzu3JYU
         4gGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3q3TTcUUp/+MWZDT67TCbzBksTYn5NVtuuaDfPhiuExuG8tWyg
	RuYVvSSW1it5lkDhtia+Zks=
X-Google-Smtp-Source: AMsMyM7QKTxMonI5gLHvDhsrKacuCd/8HzYRAqXj8l5UPJslf2FB/YJfebsgIYGOrF2TIqU5JDkgGA==
X-Received: by 2002:a17:907:8a01:b0:780:d2b8:61aa with SMTP id sc1-20020a1709078a0100b00780d2b861aamr715999ejc.454.1663807565059;
        Wed, 21 Sep 2022 17:46:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:34cc:b0:44e:93b9:21c8 with SMTP id
 w12-20020a05640234cc00b0044e93b921c8ls3472023edc.1.-pod-prod-gmail; Wed, 21
 Sep 2022 17:46:04 -0700 (PDT)
X-Received: by 2002:a05:6402:518d:b0:451:6655:5fb4 with SMTP id q13-20020a056402518d00b0045166555fb4mr733589edd.150.1663807564314;
        Wed, 21 Sep 2022 17:46:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663807564; cv=none;
        d=google.com; s=arc-20160816;
        b=wnrAyexN85jQMxZOJtYuITWbYrhb8o0BpGhe8lfmIqYgX97B8YUjlLtb6cf3UrRVPm
         w1dkI6ECoT4y5lBT4hTSe8GstaD5m0RxWxN8JVT0VOyZdpDQFKtbJcXcrSv0tzblODgU
         USPUHMSqHzkXDU+qdO60kie1JXuV+tIEXFUKlfcyQb2cfjYWN02SrDd0/LT/QwU27IlI
         Hr7H/W5yRqaB17J7yIhOwJAwCZZxUGmzd9CtFqzQUe8RjphuiwphhahGRGttvFtjLuvo
         XPdjaC/D97Z8EDacEX6HkkGeKA/hJ0L2cSAQPr6eS3kaQzn9I09wb0OGZVKCtltLFhRy
         R8nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rYvuksNDTiBVza6FyeiqYwy5ditZb4hGCy6+ccLqTcY=;
        b=gTIy7C69/1tnuBkajtqT1lbgE2Zvn/uGeDEWo00sqn7ffMoMQuKb/jBoxdxTXvhn7w
         I++Sd9HAohn5x25oub0WJm2aKi19RwrkvUMXspuY6ydHyoiwwWV+esFVIfl6XA2KtVeT
         yQ30++aLH33IcOUKGM1dQK2Lfaix5477X7eyZpxp/Xo8d9nHidqVIpdkyIxR0pNel6ug
         m+wqU8lIYhsDpoDETRaE17yiVXukgxyySjsPjM7NUjhDNmYGFHTzSY6UMiSUr4IMvNea
         YX0PWYhy83n5+CNOwFWAdMtugpwAAgBasmT70DQX4tBXbQo6fEPECEOABC/Yt4ZUzBDC
         Vyeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qaUYBCa8;
       spf=pass (google.com: domain of guoren@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=guoren@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id jx23-20020a170907761700b0077e2b420e6esi177221ejc.0.2022.09.21.17.46.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Sep 2022 17:46:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of guoren@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 12D4FB829CC
	for <kasan-dev@googlegroups.com>; Thu, 22 Sep 2022 00:46:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3E611C4314C
	for <kasan-dev@googlegroups.com>; Thu, 22 Sep 2022 00:46:02 +0000 (UTC)
Received: by mail-oa1-f54.google.com with SMTP id 586e51a60fabf-1278a61bd57so11661837fac.7
        for <kasan-dev@googlegroups.com>; Wed, 21 Sep 2022 17:46:02 -0700 (PDT)
X-Received: by 2002:a05:6870:a78e:b0:12b:542b:e5b2 with SMTP id
 x14-20020a056870a78e00b0012b542be5b2mr6779719oao.112.1663807550798; Wed, 21
 Sep 2022 17:45:50 -0700 (PDT)
MIME-Version: 1.0
References: <20220919095939.761690562@infradead.org> <20220919101520.802976773@infradead.org>
In-Reply-To: <20220919101520.802976773@infradead.org>
From: Guo Ren <guoren@kernel.org>
Date: Thu, 22 Sep 2022 08:45:37 +0800
X-Gmail-Original-Message-ID: <CAJF2gTQxxRQZLV+uJThCZSByUQ0oSoASgwsUggbsR3wHTqrqzg@mail.gmail.com>
Message-ID: <CAJF2gTQxxRQZLV+uJThCZSByUQ0oSoASgwsUggbsR3wHTqrqzg@mail.gmail.com>
Subject: Re: [PATCH v2 07/44] cpuidle,psci: Push RCU-idle into driver
To: Peter Zijlstra <peterz@infradead.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru, mattst88@gmail.com, 
	vgupta@kernel.org, linux@armlinux.org.uk, ulli.kroll@googlemail.com, 
	linus.walleij@linaro.org, shawnguo@kernel.org, 
	Sascha Hauer <s.hauer@pengutronix.de>, kernel@pengutronix.de, festevam@gmail.com, 
	linux-imx@nxp.com, tony@atomide.com, khilman@kernel.org, 
	catalin.marinas@arm.com, will@kernel.org, bcain@quicinc.com, 
	chenhuacai@kernel.org, kernel@xen0n.name, geert@linux-m68k.org, 
	sammy@sammy.net, monstr@monstr.eu, tsbogend@alpha.franken.de, 
	dinguyen@kernel.org, jonas@southpole.se, stefan.kristiansson@saunalahti.fi, 
	shorne@gmail.com, James.Bottomley@hansenpartnership.com, deller@gmx.de, 
	mpe@ellerman.id.au, npiggin@gmail.com, christophe.leroy@csgroup.eu, 
	paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu, 
	hca@linux.ibm.com, gor@linux.ibm.com, agordeev@linux.ibm.com, 
	borntraeger@linux.ibm.com, svens@linux.ibm.com, ysato@users.sourceforge.jp, 
	dalias@libc.org, davem@davemloft.net, richard@nod.at, 
	anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net, 
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	dave.hansen@linux.intel.com, x86@kernel.org, hpa@zytor.com, acme@kernel.org, 
	mark.rutland@arm.com, alexander.shishkin@linux.intel.com, jolsa@kernel.org, 
	namhyung@kernel.org, jgross@suse.com, srivatsa@csail.mit.edu, 
	amakhalov@vmware.com, pv-drivers@vmware.com, boris.ostrovsky@oracle.com, 
	chris@zankel.net, jcmvbkbc@gmail.com, rafael@kernel.org, lenb@kernel.org, 
	pavel@ucw.cz, gregkh@linuxfoundation.org, mturquette@baylibre.com, 
	sboyd@kernel.org, daniel.lezcano@linaro.org, lpieralisi@kernel.org, 
	sudeep.holla@arm.com, agross@kernel.org, bjorn.andersson@linaro.org, 
	konrad.dybcio@somainline.org, anup@brainfault.org, thierry.reding@gmail.com, 
	jonathanh@nvidia.com, jacob.jun.pan@linux.intel.com, atishp@atishpatra.org, 
	Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com, andriy.shevchenko@linux.intel.com, 
	linux@rasmusvillemoes.dk, dennis@kernel.org, tj@kernel.org, cl@linux.com, 
	rostedt@goodmis.org, pmladek@suse.com, senozhatsky@chromium.org, 
	john.ogness@linutronix.de, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, bsegall@google.com, mgorman@suse.de, 
	bristot@redhat.com, vschneid@redhat.com, fweisbec@gmail.com, 
	ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, 
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
	linux-perf-users@vger.kernel.org, virtualization@lists.linux-foundation.org, 
	linux-xtensa@linux-xtensa.org, linux-acpi@vger.kernel.org, 
	linux-pm@vger.kernel.org, linux-clk@vger.kernel.org, 
	linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org, 
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: guoren@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qaUYBCa8;       spf=pass
 (google.com: domain of guoren@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=guoren@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Reviewed-by: Guo Ren <guoren@kernel.org>

On Mon, Sep 19, 2022 at 6:17 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> Doing RCU-idle outside the driver, only to then temporarily enable it
> again, at least twice, before going idle is daft.
>
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> ---
>  drivers/cpuidle/cpuidle-psci.c |    9 +++++----
>  1 file changed, 5 insertions(+), 4 deletions(-)
>
> --- a/drivers/cpuidle/cpuidle-psci.c
> +++ b/drivers/cpuidle/cpuidle-psci.c
> @@ -69,12 +69,12 @@ static int __psci_enter_domain_idle_stat
>                 return -1;
>
>         /* Do runtime PM to manage a hierarchical CPU toplogy. */
> -       ct_irq_enter_irqson();
>         if (s2idle)
>                 dev_pm_genpd_suspend(pd_dev);
>         else
>                 pm_runtime_put_sync_suspend(pd_dev);
> -       ct_irq_exit_irqson();
> +
> +       ct_idle_enter();
>
>         state = psci_get_domain_state();
>         if (!state)
> @@ -82,12 +82,12 @@ static int __psci_enter_domain_idle_stat
>
>         ret = psci_cpu_suspend_enter(state) ? -1 : idx;
>
> -       ct_irq_enter_irqson();
> +       ct_idle_exit();
> +
>         if (s2idle)
>                 dev_pm_genpd_resume(pd_dev);
>         else
>                 pm_runtime_get_sync(pd_dev);
> -       ct_irq_exit_irqson();
>
>         cpu_pm_exit();
>
> @@ -240,6 +240,7 @@ static int psci_dt_cpu_init_topology(str
>          * of a shared state for the domain, assumes the domain states are all
>          * deeper states.
>          */
> +       drv->states[state_count - 1].flags |= CPUIDLE_FLAG_RCU_IDLE;
>         drv->states[state_count - 1].enter = psci_enter_domain_idle_state;
>         drv->states[state_count - 1].enter_s2idle = psci_enter_s2idle_domain_idle_state;
>         psci_cpuidle_use_cpuhp = true;
>
>


-- 
Best Regards
 Guo Ren

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJF2gTQxxRQZLV%2BuJThCZSByUQ0oSoASgwsUggbsR3wHTqrqzg%40mail.gmail.com.
