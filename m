Return-Path: <kasan-dev+bncBDF57NG2XIHRBN7G6ONQMGQE3XWTSEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id DDA486340C8
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 17:05:12 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id x10-20020a056e021bca00b00302b6c0a683sf6757429ilv.23
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 08:05:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669133111; cv=pass;
        d=google.com; s=arc-20160816;
        b=NevDwKsrvLAVSfE50NE4msYSe2FSFknQgiFSCVaMflDZicmYQEAQr8S2aOMx3Nfp0N
         xdDP7vilJufvJbPyzUUYXFRCWeguJEr3Mdp38CQqeH+7y1GgoPLSUd0YUgDw+BB/v1xO
         QtfYHesdp/TP3rnvBUuyQJ60u2YovMUZHi/EZx5xa1Mr88IERxlTtd/TNMHV6nH0yxW0
         aBPSwnpy6K/cpnE2n24Gf9ybso7xTDJcu1MFzLT0lFOeycyE+t2sl8FzJ9p90cwFDG9K
         t6b3EgUVJ26ZIE1zZcc5l807ohH6mN08V3Q8Kr68wnl/m6CPyGoum2oaYm3bIAQTUJ9B
         KeAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=1mVkB0uqAcqgqE9pjPkEdYuQhS8HKxS53fuhpeBsJVA=;
        b=PIxpE32ZqU+D/3t2E9pHr6BwspKlMKOfvfIACQYfzCDuYEH7h/El6gfoiradirKnEy
         qQAcWNfsq/KVJYgDdecXuSgmA+erVp6CXIpjnnREkUCiHsWWjTbiq3ViQL3K2rxAWL8O
         jC+VBagVuo/NtvfpprPatJV1rRYell+36XiqEl1Dmvz+UiRr4uXORu0mkaP261Vr1ngs
         g0UGtOD+QFFDVSk+yotZcG8SLiUXVQKvT84lEfgNxbnElEulPBIf/8JSBRF9mIPI3Pmm
         his7pbuCWv9g4YFAyOE8Qk40/qHZ7ys4VnXMuYiBKNGIj/psWJarHltoqg5iRuaFeJiN
         Yc4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=Sxgb7Ndw;
       spf=pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1mVkB0uqAcqgqE9pjPkEdYuQhS8HKxS53fuhpeBsJVA=;
        b=bvMfLZQ53+mn64xWm298UoVgpP8EttfXrkdiXmsozbsPDh6fF7eu1NgGAZrrjhjhgd
         trNWPvvdCWQ78m1LnnNKl0a6aethhZgdju1IZkKqrVpkUOLb+Ad+D714yqdtxtvziANz
         YLgBSgTw07MhfkstsKsEFtAJcjhMGsAfARbcxhWvnj+LzuLt0CyGkKwRaOJiFRZzgHJc
         RTeqLZw7ynyhBqQrEHGdcLEczF7dFq2w1RLXWUFvdLZK+GLgd/1Ds4x/eHG/zSEhj48T
         HgfKwi123orh5GjeY4rETCWv8CtM3LfERMQh5BL3YI6gsWRTGs/Xq0qERDN5/g4FT1Ng
         H4Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1mVkB0uqAcqgqE9pjPkEdYuQhS8HKxS53fuhpeBsJVA=;
        b=0a9xNSX8CLvEo+BYrexKknrPtFMiSWUqx4s2bbQ2iNaKrAhbVt5OSYTFtHqQcJuIKV
         F0Aa4bBYr3Zuq0xj8lFpKPraXXcjVzkbdgjCFsfR8p2gTOZc93aZc5qqgnPfjjim0RNj
         ZszLPHkdiu8bN4ku9KDoe5y5vRaGlTOHQksSR9Rb0BvKEoiQp8hPbWXFftjcDdDMQS3q
         k9RT5P5ofJkYOFi/89Gq/u34dgTkUX/JO8xQG0x8KwYVp0zCTGqiiWFRWqTOsuv8USO0
         WKMNDyVwtDHc8KvICC/dPAWFxWo6Q5BpYFjUTeg+p7lcQuutvdun+FWF4AKBDdFZwy7X
         AHSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkgho6LuCtCvKNog5/prr1TEDEw7eP1sbcoEGPC4Y0tYiwAWc6N
	EEe3Ne/U4t2pVcQi9HpEefo=
X-Google-Smtp-Source: AA0mqf6DmjM4znxhW2mBNDMBs6QuL2BwUHpnG3ef9EXett/I0bjBiyuGTg0DOtuU8M/wozq1hV4w6g==
X-Received: by 2002:a92:d702:0:b0:302:5898:73d1 with SMTP id m2-20020a92d702000000b00302589873d1mr1980310iln.65.1669133111477;
        Tue, 22 Nov 2022 08:05:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:418a:b0:6dd:cccc:38f9 with SMTP id
 bx10-20020a056602418a00b006ddcccc38f9ls1625808iob.3.-pod-prod-gmail; Tue, 22
 Nov 2022 08:05:10 -0800 (PST)
X-Received: by 2002:a6b:c990:0:b0:6dd:807d:89a3 with SMTP id z138-20020a6bc990000000b006dd807d89a3mr2651462iof.33.1669133110879;
        Tue, 22 Nov 2022 08:05:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669133110; cv=none;
        d=google.com; s=arc-20160816;
        b=dnl3/F2hrX/in1H9BSL62cK5ch8PgKWv5CQqX7gzYnUUodhEMh56YGtKWmYZzVO09V
         NGQU02BcYfPFAmtUVKoMIetfQIc21GVNkM81Wht4gD3pzwIvrArNu66c5Ti0Vbkq2AMs
         D2MGvOnyBOEXDXRtUwfoJ31Ez7ruLn6CZRu+S7hJ5hnw7dSFOlquxmEttDxG3+Yx+DTO
         Etqt33xzNNpnjofotM+DjrlFahg+io9hh+3QclNWCw7HsDsXeQN7BAf5rb8/qx6wu1ml
         0Gdsan6rjgtEOL/H1FOAjRVXuhtvldMbDqD+aILX7ywO75CBrrBsyGoisEmi1yUEoJ8y
         qgCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mKqixJN/8zapPMiYOY0ZA2E36N6vIQg16uLiOxlikFI=;
        b=kggeAp+iPurXceW8UzCcKD4PB8sUlpDV2SgymxlK82MKIwFOGuSkwc8a9/ycw8wJwT
         +TpEzBQm73m4LOsnxl4Qs4Bu8xCV2xYRPFP9rHtKfLFYqpq7ZR0bNRT3H97YiH6ToBqu
         WsRNhvhSu1vAE/g8gr6SIKIrr30KnShGOBnrhFBLWunvIBCie5Pm+6r+Mh0WM+ZNQYaU
         v6oty1ZOdTLP5797yr5TKqouy7257Q7p+UJotRQcI66n0jWDmjcmz5ROvvpbeIvYmFmF
         uzOYFrtIsP94F0QpIEGHoUxVDHW2Gj+HTFoTXQabGwSD63g+XUL2cmn/uwW9bAt3eYSH
         TtuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=Sxgb7Ndw;
       spf=pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id i1-20020a02ca01000000b003750f38186bsi855513jak.1.2022.11.22.08.05.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Nov 2022 08:05:10 -0800 (PST)
Received-SPF: pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id g62so14763385pfb.10
        for <kasan-dev@googlegroups.com>; Tue, 22 Nov 2022 08:05:10 -0800 (PST)
X-Received: by 2002:a63:501c:0:b0:477:650a:c29a with SMTP id
 e28-20020a63501c000000b00477650ac29amr3900068pgb.541.1669133109958; Tue, 22
 Nov 2022 08:05:09 -0800 (PST)
MIME-Version: 1.0
References: <20220919095939.761690562@infradead.org> <20220919101521.139727471@infradead.org>
 <CAPDyKFqTWd4W5Ofk76CtC4X43dxBTNHtmY9YzN355-vpviLsPw@mail.gmail.com> <Y3UBwYNY15ETUKy9@hirez.programming.kicks-ass.net>
In-Reply-To: <Y3UBwYNY15ETUKy9@hirez.programming.kicks-ass.net>
From: Ulf Hansson <ulf.hansson@linaro.org>
Date: Tue, 22 Nov 2022 17:04:33 +0100
Message-ID: <CAPDyKFqzmJdVVrcuJ6Hmr5nNgtpd9Oke_exmUKuTGZEb=PjvjQ@mail.gmail.com>
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
 header.i=@linaro.org header.s=google header.b=Sxgb7Ndw;       spf=pass
 (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::429
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

On Wed, 16 Nov 2022 at 16:29, Peter Zijlstra <peterz@infradead.org> wrote:
>
>
> Sorry; things keep getting in the way of finishing this :/
>
> As such, I need a bit of time to get on-track again..
>
> On Tue, Oct 04, 2022 at 01:03:57PM +0200, Ulf Hansson wrote:
>
> > > --- a/drivers/acpi/processor_idle.c
> > > +++ b/drivers/acpi/processor_idle.c
> > > @@ -1200,6 +1200,8 @@ static int acpi_processor_setup_lpi_stat
> > >                 state->target_residency = lpi->min_residency;
> > >                 if (lpi->arch_flags)
> > >                         state->flags |= CPUIDLE_FLAG_TIMER_STOP;
> > > +               if (lpi->entry_method == ACPI_CSTATE_FFH)
> > > +                       state->flags |= CPUIDLE_FLAG_RCU_IDLE;
> >
> > I assume the state index here will never be 0?
> >
> > If not, it may lead to that acpi_processor_ffh_lpi_enter() may trigger
> > CPU_PM_CPU_IDLE_ENTER_PARAM() to call ct_cpuidle_enter|exit() for an
> > idle-state that doesn't have the CPUIDLE_FLAG_RCU_IDLE bit set.
>
> I'm not quite sure I see how. AFAICT this condition above implies
> acpi_processor_ffh_lpi_enter() gets called, no?
>
> Which in turn is an unconditional __CPU_PM_CPU_IDLE_ENTER() user, so
> even if idx==0, it ends up in ct_idle_{enter,exit}().

Seems like I was overlooking something here, you are right, this
shouldn't really be a problem.

>
> >
> > >                 state->enter = acpi_idle_lpi_enter;
> > >                 drv->safe_state_index = i;
> > >         }
> > > --- a/drivers/cpuidle/cpuidle-arm.c
> > > +++ b/drivers/cpuidle/cpuidle-arm.c
> > > @@ -53,6 +53,7 @@ static struct cpuidle_driver arm_idle_dr
> > >          * handler for idle state index 0.
> > >          */
> > >         .states[0] = {
> > > +               .flags                  = CPUIDLE_FLAG_RCU_IDLE,
> >
> > Comparing arm64 and arm32 idle-states/idle-drivers, the $subject
> > series ends up setting the CPUIDLE_FLAG_RCU_IDLE for the ARM WFI idle
> > state (state zero), but only for the arm64 and psci cases (mostly
> > arm64). For arm32 we would need to update the ARM_CPUIDLE_WFI_STATE
> > too, as that is what most arm32 idle-drivers are using. My point is,
> > the code becomes a bit inconsistent.
>
> True.
>
> > Perhaps it's easier to avoid setting the CPUIDLE_FLAG_RCU_IDLE bit for
> > all of the ARM WFI idle states, for both arm64 and arm32?
>
> As per the below?
>
> >
> > >                 .enter                  = arm_enter_idle_state,
> > >                 .exit_latency           = 1,
> > >                 .target_residency       = 1,
>
> > > --- a/include/linux/cpuidle.h
> > > +++ b/include/linux/cpuidle.h
> > > @@ -282,14 +282,18 @@ extern s64 cpuidle_governor_latency_req(
> > >         int __ret = 0;                                                  \
> > >                                                                         \
> > >         if (!idx) {                                                     \
> > > +               ct_idle_enter();                                        \
> >
> > According to my comment above, we should then drop these calls to
> > ct_idle_enter and ct_idle_exit() here. Right?
>
> Yes, if we ensure idx==0 never has RCU_IDLE set then these must be
> removed.
>
> > >                 cpu_do_idle();                                          \
> > > +               ct_idle_exit();                                         \
> > >                 return idx;                                             \
> > >         }                                                               \
> > >                                                                         \
> > >         if (!is_retention)                                              \
> > >                 __ret =  cpu_pm_enter();                                \
> > >         if (!__ret) {                                                   \
> > > +               ct_idle_enter();                                        \
> > >                 __ret = low_level_idle_enter(state);                    \
> > > +               ct_idle_exit();                                         \
> > >                 if (!is_retention)                                      \
> > >                         cpu_pm_exit();                                  \
> > >         }                                                               \
> > >
>
> So the basic premise is that everything that needs RCU inside the idle
> callback must set CPUIDLE_FLAG_RCU_IDLE and by doing that promise to
> call ct_idle_{enter,exit}() themselves.
>
> Setting RCU_IDLE is required when there is RCU usage, however even if
> there is no RCU usage, setting RCU_IDLE is fine, as long as
> ct_idle_{enter,exit}() then get called.

Right, I was thinking that it could make sense to shrink the window
for users getting this wrong. In other words, we shouldn't set the
CPUIDLE_FLAG_RCU_IDLE unless we really need to.

And as I said, consistent behaviour is also nice to have.

>
>
> So does the below (delta) look better to you?

Yes, it does!

Although, one minor comment below.

>
> --- a/drivers/acpi/processor_idle.c
> +++ b/drivers/acpi/processor_idle.c
> @@ -1218,7 +1218,7 @@ static int acpi_processor_setup_lpi_stat
>                 state->target_residency = lpi->min_residency;
>                 if (lpi->arch_flags)
>                         state->flags |= CPUIDLE_FLAG_TIMER_STOP;
> -               if (lpi->entry_method == ACPI_CSTATE_FFH)
> +               if (i != 0 && lpi->entry_method == ACPI_CSTATE_FFH)
>                         state->flags |= CPUIDLE_FLAG_RCU_IDLE;
>                 state->enter = acpi_idle_lpi_enter;
>                 drv->safe_state_index = i;
> --- a/drivers/cpuidle/cpuidle-arm.c
> +++ b/drivers/cpuidle/cpuidle-arm.c
> @@ -53,7 +53,7 @@ static struct cpuidle_driver arm_idle_dr
>          * handler for idle state index 0.
>          */
>         .states[0] = {
> -               .flags                  = CPUIDLE_FLAG_RCU_IDLE,
> +               .flags                  = 0,

Nitpick: I don't think we need to explicitly clear the flag, as it
should already be zeroed by the compiler from its static declaration.
Right?

>                 .enter                  = arm_enter_idle_state,
>                 .exit_latency           = 1,
>                 .target_residency       = 1,
> --- a/drivers/cpuidle/cpuidle-psci.c
> +++ b/drivers/cpuidle/cpuidle-psci.c
> @@ -357,7 +357,7 @@ static int psci_idle_init_cpu(struct dev
>          * PSCI idle states relies on architectural WFI to be represented as
>          * state index 0.
>          */
> -       drv->states[0].flags = CPUIDLE_FLAG_RCU_IDLE;
> +       drv->states[0].flags = 0;
>         drv->states[0].enter = psci_enter_idle_state;
>         drv->states[0].exit_latency = 1;
>         drv->states[0].target_residency = 1;
> --- a/drivers/cpuidle/cpuidle-qcom-spm.c
> +++ b/drivers/cpuidle/cpuidle-qcom-spm.c
> @@ -72,7 +72,7 @@ static struct cpuidle_driver qcom_spm_id
>         .owner = THIS_MODULE,
>         .states[0] = {
>                 .enter                  = spm_enter_idle_state,
> -               .flags                  = CPUIDLE_FLAG_RCU_IDLE,
> +               .flags                  = 0,
>                 .exit_latency           = 1,
>                 .target_residency       = 1,
>                 .power_usage            = UINT_MAX,
> --- a/drivers/cpuidle/cpuidle-riscv-sbi.c
> +++ b/drivers/cpuidle/cpuidle-riscv-sbi.c
> @@ -337,7 +337,7 @@ static int sbi_cpuidle_init_cpu(struct d
>         drv->cpumask = (struct cpumask *)cpumask_of(cpu);
>
>         /* RISC-V architectural WFI to be represented as state index 0. */
> -       drv->states[0].flags = CPUIDLE_FLAG_RCU_IDLE;
> +       drv->states[0].flags = 0;
>         drv->states[0].enter = sbi_cpuidle_enter_state;
>         drv->states[0].exit_latency = 1;
>         drv->states[0].target_residency = 1;
> --- a/include/linux/cpuidle.h
> +++ b/include/linux/cpuidle.h
> @@ -282,9 +282,7 @@ extern s64 cpuidle_governor_latency_req(
>         int __ret = 0;                                                  \
>                                                                         \
>         if (!idx) {                                                     \
> -               ct_idle_enter();                                        \
>                 cpu_do_idle();                                          \
> -               ct_idle_exit();                                         \
>                 return idx;                                             \
>         }                                                               \
>                                                                         \

Kind regards
Uffe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAPDyKFqzmJdVVrcuJ6Hmr5nNgtpd9Oke_exmUKuTGZEb%3DPjvjQ%40mail.gmail.com.
