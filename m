Return-Path: <kasan-dev+bncBDF57NG2XIHRBCNZ6CMQMGQEXGDE3QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D7EE5F4223
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Oct 2022 13:44:11 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-132b6ed45b3sf414488fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Oct 2022 04:44:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664883850; cv=pass;
        d=google.com; s=arc-20160816;
        b=GU/mI55qqJC2SEWxo8TyhRnNJk+rnB+XgsXW3pL4u5bVym7ydo2A6GoC+iveua1MtX
         zOrbcCG9wyC36Br3tLaY9UDLvv6iyQxiDu1/0xa4M0zEIRFPTCvyXKeRGLpZ46EjPHGa
         65i4PvWIofDISk1DJ5RsrpchEBxBa9NDjzmcZS1rmExE5jk6TYaYmtzJzkYt/h2gIwtS
         vM7T2njuYOSrAxIdesyNFjEhTYcoAFacZqRs7TH9al5LkHTZeIfnj5A+i0jhTYSHm1wa
         s2kF2XKnL34amVlmMouhU4FdRDkv9tOtMNWrz7QMP2e417MYUEzcQTSTuin+C54bex/0
         c78w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=3+ycRg7fIhybjllnqjyoLFLr0LpwsWnDV/7+U5krp3M=;
        b=AEWhEbhhGB5XwOXIMFPP4Ve4vPCTKEvAIiROxN755dSMDs43QvdXExSUZxs+E517TN
         LWiAMIhed1eY4cR6F6ppODs4NTcrJ3ZzURNgM8s2x6IS8EvKcvn1xtzmr/s78tWuygjW
         +N1Rh9NpvC/b4QG9IPlwYNkkNXwRFcjeUAFw83sTMOfjk0EWW33vh1ta6k2XZm1fGX1G
         Eavd9jFQQnseQ91kEvknHlyqyROq9KCsGkrTu5MCqexbo+Lzbu+VVt8qj2AVlQBUQIYx
         EbJ8PvcUzxC5Xtesci3fvKu1lnDZcX6UKBk3PO0tkULXjCjuzVLpLytCVYo3Ndy8mzsw
         IiPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="Bo9x/OnI";
       spf=pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=3+ycRg7fIhybjllnqjyoLFLr0LpwsWnDV/7+U5krp3M=;
        b=V2EmiWShHvzNA8ca0PRjEGsBU9gF+1oD44hFsZfSrpKwPqEvuPOH44RDAIf7bQX0B3
         9FDCLH2eEXhnSaGtVtFPs1gkFu8iO1p0YyebWxiQJPAC2ktG2o81odlAdy9jF2WvKLvN
         TmqlENgDDFHn3bJosa6Z5HQPCYpQgGxhyY24BjJSoE09cmls7S362qZjOeEfxE9J7b86
         TgukiRREWxJN4nYfRA4de0NSEF93odEmhYqoe4y8GIr64qE9UomzW7JPLZjKmv4tvqCX
         EfueEqZObLnzqitkzjNjsxHL3mmfQ8/zN3o99+zdPGnPXhIJ2Yh+N+GvzN0PcWEgnvDP
         suBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=3+ycRg7fIhybjllnqjyoLFLr0LpwsWnDV/7+U5krp3M=;
        b=UveBidGXQqBRCLtelqS1AZErb8E/3/xPMR3Fr/iWFXAlFhkja5UPmiUQeoinOMYxCx
         OGYhOLP+Yqjb4ebt55D/l5t+M+rCxRTzRNEGXQ8CTbuarCQoQA7wYlljw2ltGs8vvfpz
         sv7syTzgiWpFoumaJvCf9BCbYypu6LjNL6h1waWsVCyo3cXePA+T67U4gVx5C/dI9Tiw
         yfdJ6pmJ7sAKG9vGQkG1MLmbFiGs1Au3wJw+nDwBw1NkN5N9hUh2XZiaIT+kdaUIJAZP
         sS38KFZVszcLn0ToZM+Wwo9JizfilcWVUYW8dgsCA0IvsHhQhsJg6oMPPVfin2auJSdF
         KkgA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3E84FjZW9w9LLzTYX70VoURju34HBl0cB2ouSnX3KNJ4OtsKX6
	9r5NTSIG3ySxVbvN3pp5t5E=
X-Google-Smtp-Source: AMsMyM6x9h6k1y2JqPClFFYBmiqFV8SFbXyLdVzT0WDSsWsXRohZ/rru41LwUStM/S1p45Ieoz/+fw==
X-Received: by 2002:a05:6870:40cb:b0:131:4fec:3c7d with SMTP id l11-20020a05687040cb00b001314fec3c7dmr7741595oal.147.1664883849949;
        Tue, 04 Oct 2022 04:44:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:6304:b0:639:1b8:ca3a with SMTP id
 cg4-20020a056830630400b0063901b8ca3als2002875otb.9.-pod-prod-gmail; Tue, 04
 Oct 2022 04:44:09 -0700 (PDT)
X-Received: by 2002:a05:6830:160d:b0:655:ca9a:fd3d with SMTP id g13-20020a056830160d00b00655ca9afd3dmr9479393otr.135.1664883849317;
        Tue, 04 Oct 2022 04:44:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664883849; cv=none;
        d=google.com; s=arc-20160816;
        b=qXXA/6vN90NLVhhXKlyJwzEzocOX3SmxC6oHR0P09K6FF7uUBG5MLKpN1F1qRffwJK
         KjzTVTwvAYOmyH+R+I7ZuggguLJ5dTY2QdcVtFkhU45jWhrstx3eLCLxuqYDdbLc3KPn
         BEBgm4g9mHmxzmwR7hN4FaxiDp2PM0ic+FQeJvGYh/+GlLWGoAQiVnHcnpUUHK8IvD0z
         1jvTnB8NAtluU6FzP3D17N2VzlRExx2s3cbXoM8qFaZHgnDSfGmgzodsfct/AEONGj9H
         +RTrCpE/BL77m/7G2oZRRwy/JlxmiCbXymxnf6eoSZFnffVITHeAjHyvY8ntgIBtMz9Z
         uVOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6ZpUfgQM8l58jAA1FLv6FNtqasscnAngw/MWtVrklhs=;
        b=ZbWfypZ6I+7Rh8v4mLXBIaLcK3JWuVimnIpft0ObLxTy2xWWem2+zFL+fYQQuagbpI
         aj8ii6QZfJcyEIw3PizvMRdgmJaMR/oNvGOeweiwD9uXG2MyfbK1b1l8IBPgbqyuSU9v
         BULFsky7BJdxB40sfLBl2KYvRCvZ2EhR3sZxiEvMzKxNBsEMz6DeAajUXzlOXuKgEhzY
         dXwm4uIGueiHvijx/kfHuOXEtYQuvFzVziOBwrgKcB8keyFGANcdiRcr4AsXGqzA86cP
         jjPekPvckXAfz7nEVLses+XaoYPDmBp5BlgfLb2jTLZMkMrpYhkXIqTwFAPa5INfh+lc
         BkIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="Bo9x/OnI";
       spf=pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id bd18-20020a056870d79200b0010c5005e1c8si1116477oab.3.2022.10.04.04.44.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Oct 2022 04:44:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id bh13so12501453pgb.4
        for <kasan-dev@googlegroups.com>; Tue, 04 Oct 2022 04:44:09 -0700 (PDT)
X-Received: by 2002:a63:464d:0:b0:441:5968:cd0e with SMTP id
 v13-20020a63464d000000b004415968cd0emr19098981pgk.595.1664883848385; Tue, 04
 Oct 2022 04:44:08 -0700 (PDT)
MIME-Version: 1.0
References: <20220919095939.761690562@infradead.org> <20220919101521.139727471@infradead.org>
 <CAPDyKFqTWd4W5Ofk76CtC4X43dxBTNHtmY9YzN355-vpviLsPw@mail.gmail.com>
In-Reply-To: <CAPDyKFqTWd4W5Ofk76CtC4X43dxBTNHtmY9YzN355-vpviLsPw@mail.gmail.com>
From: Ulf Hansson <ulf.hansson@linaro.org>
Date: Tue, 4 Oct 2022 13:43:31 +0200
Message-ID: <CAPDyKFqGSt2NFe8aY=6rkp4P-WH7DCO1fmWrcXk4_5XNEvv25w@mail.gmail.com>
Subject: Re: [PATCH v2 12/44] cpuidle,dt: Push RCU-idle into driver
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
 header.i=@linaro.org header.s=google header.b="Bo9x/OnI";       spf=pass
 (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::52f
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

On Tue, 4 Oct 2022 at 13:03, Ulf Hansson <ulf.hansson@linaro.org> wrote:
>
> On Mon, 19 Sept 2022 at 12:18, Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > Doing RCU-idle outside the driver, only to then temporarily enable it
> > again before going idle is daft.
> >
> > Notably: this converts all dt_init_idle_driver() and
> > __CPU_PM_CPU_IDLE_ENTER() users for they are inextrably intertwined.
> >
> > Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
>
> Reviewed-by: Ulf Hansson <ulf.hansson@linaro.org>

This was not (yet) my intention. Please have a look at the comments I
provided below.

Kind regards
Uffe

>
> > ---
> >  arch/arm/mach-omap2/cpuidle34xx.c    |    4 ++--
> >  drivers/acpi/processor_idle.c        |    2 ++
> >  drivers/cpuidle/cpuidle-arm.c        |    1 +
> >  drivers/cpuidle/cpuidle-big_little.c |    8 ++++++--
> >  drivers/cpuidle/cpuidle-psci.c       |    1 +
> >  drivers/cpuidle/cpuidle-qcom-spm.c   |    1 +
> >  drivers/cpuidle/cpuidle-riscv-sbi.c  |    1 +
> >  drivers/cpuidle/dt_idle_states.c     |    2 +-
> >  include/linux/cpuidle.h              |    4 ++++
> >  9 files changed, 19 insertions(+), 5 deletions(-)
> >
> > --- a/drivers/acpi/processor_idle.c
> > +++ b/drivers/acpi/processor_idle.c
> > @@ -1200,6 +1200,8 @@ static int acpi_processor_setup_lpi_stat
> >                 state->target_residency = lpi->min_residency;
> >                 if (lpi->arch_flags)
> >                         state->flags |= CPUIDLE_FLAG_TIMER_STOP;
> > +               if (lpi->entry_method == ACPI_CSTATE_FFH)
> > +                       state->flags |= CPUIDLE_FLAG_RCU_IDLE;
>
> I assume the state index here will never be 0?
>
> If not, it may lead to that acpi_processor_ffh_lpi_enter() may trigger
> CPU_PM_CPU_IDLE_ENTER_PARAM() to call ct_cpuidle_enter|exit() for an
> idle-state that doesn't have the CPUIDLE_FLAG_RCU_IDLE bit set.
>
> >                 state->enter = acpi_idle_lpi_enter;
> >                 drv->safe_state_index = i;
> >         }
> > --- a/drivers/cpuidle/cpuidle-arm.c
> > +++ b/drivers/cpuidle/cpuidle-arm.c
> > @@ -53,6 +53,7 @@ static struct cpuidle_driver arm_idle_dr
> >          * handler for idle state index 0.
> >          */
> >         .states[0] = {
> > +               .flags                  = CPUIDLE_FLAG_RCU_IDLE,
>
> Comparing arm64 and arm32 idle-states/idle-drivers, the $subject
> series ends up setting the CPUIDLE_FLAG_RCU_IDLE for the ARM WFI idle
> state (state zero), but only for the arm64 and psci cases (mostly
> arm64). For arm32 we would need to update the ARM_CPUIDLE_WFI_STATE
> too, as that is what most arm32 idle-drivers are using. My point is,
> the code becomes a bit inconsistent.
>
> Perhaps it's easier to avoid setting the CPUIDLE_FLAG_RCU_IDLE bit for
> all of the ARM WFI idle states, for both arm64 and arm32?
>
> >                 .enter                  = arm_enter_idle_state,
> >                 .exit_latency           = 1,
> >                 .target_residency       = 1,
> > --- a/drivers/cpuidle/cpuidle-big_little.c
> > +++ b/drivers/cpuidle/cpuidle-big_little.c
> > @@ -64,7 +64,8 @@ static struct cpuidle_driver bl_idle_lit
> >                 .enter                  = bl_enter_powerdown,
> >                 .exit_latency           = 700,
> >                 .target_residency       = 2500,
> > -               .flags                  = CPUIDLE_FLAG_TIMER_STOP,
> > +               .flags                  = CPUIDLE_FLAG_TIMER_STOP |
> > +                                         CPUIDLE_FLAG_RCU_IDLE,
> >                 .name                   = "C1",
> >                 .desc                   = "ARM little-cluster power down",
> >         },
> > @@ -85,7 +86,8 @@ static struct cpuidle_driver bl_idle_big
> >                 .enter                  = bl_enter_powerdown,
> >                 .exit_latency           = 500,
> >                 .target_residency       = 2000,
> > -               .flags                  = CPUIDLE_FLAG_TIMER_STOP,
> > +               .flags                  = CPUIDLE_FLAG_TIMER_STOP |
> > +                                         CPUIDLE_FLAG_RCU_IDLE,
> >                 .name                   = "C1",
> >                 .desc                   = "ARM big-cluster power down",
> >         },
> > @@ -124,11 +126,13 @@ static int bl_enter_powerdown(struct cpu
> >                                 struct cpuidle_driver *drv, int idx)
> >  {
> >         cpu_pm_enter();
> > +       ct_idle_enter();
> >
> >         cpu_suspend(0, bl_powerdown_finisher);
> >
> >         /* signals the MCPM core that CPU is out of low power state */
> >         mcpm_cpu_powered_up();
> > +       ct_idle_exit();
> >
> >         cpu_pm_exit();
> >
> > --- a/drivers/cpuidle/cpuidle-psci.c
> > +++ b/drivers/cpuidle/cpuidle-psci.c
> > @@ -357,6 +357,7 @@ static int psci_idle_init_cpu(struct dev
> >          * PSCI idle states relies on architectural WFI to be represented as
> >          * state index 0.
> >          */
> > +       drv->states[0].flags = CPUIDLE_FLAG_RCU_IDLE;
> >         drv->states[0].enter = psci_enter_idle_state;
> >         drv->states[0].exit_latency = 1;
> >         drv->states[0].target_residency = 1;
> > --- a/drivers/cpuidle/cpuidle-qcom-spm.c
> > +++ b/drivers/cpuidle/cpuidle-qcom-spm.c
> > @@ -72,6 +72,7 @@ static struct cpuidle_driver qcom_spm_id
> >         .owner = THIS_MODULE,
> >         .states[0] = {
> >                 .enter                  = spm_enter_idle_state,
> > +               .flags                  = CPUIDLE_FLAG_RCU_IDLE,
> >                 .exit_latency           = 1,
> >                 .target_residency       = 1,
> >                 .power_usage            = UINT_MAX,
> > --- a/drivers/cpuidle/cpuidle-riscv-sbi.c
> > +++ b/drivers/cpuidle/cpuidle-riscv-sbi.c
> > @@ -332,6 +332,7 @@ static int sbi_cpuidle_init_cpu(struct d
> >         drv->cpumask = (struct cpumask *)cpumask_of(cpu);
> >
> >         /* RISC-V architectural WFI to be represented as state index 0. */
> > +       drv->states[0].flags = CPUIDLE_FLAG_RCU_IDLE;
> >         drv->states[0].enter = sbi_cpuidle_enter_state;
> >         drv->states[0].exit_latency = 1;
> >         drv->states[0].target_residency = 1;
> > --- a/drivers/cpuidle/dt_idle_states.c
> > +++ b/drivers/cpuidle/dt_idle_states.c
> > @@ -77,7 +77,7 @@ static int init_state_node(struct cpuidl
> >         if (err)
> >                 desc = state_node->name;
> >
> > -       idle_state->flags = 0;
> > +       idle_state->flags = CPUIDLE_FLAG_RCU_IDLE;
> >         if (of_property_read_bool(state_node, "local-timer-stop"))
> >                 idle_state->flags |= CPUIDLE_FLAG_TIMER_STOP;
> >         /*
> > --- a/include/linux/cpuidle.h
> > +++ b/include/linux/cpuidle.h
> > @@ -282,14 +282,18 @@ extern s64 cpuidle_governor_latency_req(
> >         int __ret = 0;                                                  \
> >                                                                         \
> >         if (!idx) {                                                     \
> > +               ct_idle_enter();                                        \
>
> According to my comment above, we should then drop these calls to
> ct_idle_enter and ct_idle_exit() here. Right?
>
> >                 cpu_do_idle();                                          \
> > +               ct_idle_exit();                                         \
> >                 return idx;                                             \
> >         }                                                               \
> >                                                                         \
> >         if (!is_retention)                                              \
> >                 __ret =  cpu_pm_enter();                                \
> >         if (!__ret) {                                                   \
> > +               ct_idle_enter();                                        \
> >                 __ret = low_level_idle_enter(state);                    \
> > +               ct_idle_exit();                                         \
> >                 if (!is_retention)                                      \
> >                         cpu_pm_exit();                                  \
> >         }                                                               \
> >
>
> Kind regards
> Uffe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAPDyKFqGSt2NFe8aY%3D6rkp4P-WH7DCO1fmWrcXk4_5XNEvv25w%40mail.gmail.com.
