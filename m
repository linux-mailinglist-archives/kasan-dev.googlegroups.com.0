Return-Path: <kasan-dev+bncBDF57NG2XIHRBRFG6CMQMGQEDPPJJNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E4665F4147
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Oct 2022 13:04:38 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id r12-20020a92cd8c000000b002f9f5baaeeasf3362812ilb.4
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Oct 2022 04:04:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664881477; cv=pass;
        d=google.com; s=arc-20160816;
        b=mKUjWJEHHMeceRoe1PPwi7uWDGEla1C9e9gD6v03GcWKejqOKqb7Lnlq7bIcyTECFB
         kmzrBjnBgWgfDOg+fgXS57qRF6xy4WlhmddA2kVyouVZh6ZBoAzKsa33skpKb1EPs9Gm
         PFKkw0HTQeGOEFxYUjdIChMZ9LYePk+LO6WiGRT/CGYEW4HogFkYVw8nVdZKNsTZy/Cx
         XMcygB04JUj7mDLs3ux96ibnt098KbiKZPAzmPknG9GpubB3mVhqk1Y+Zqgb7jjyAydh
         rtUzWUcJQ0kLFoJYSl1Ix5t3u65ooq7szbl1vunL90NMb66BVZOb9RxLMjCk7YNYy5Gc
         9yig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=ync2AQfjdfIzLfN6acrmzKYfwpJIDs/F+sXlhEnJqj4=;
        b=TWrxnhakqyP2f22yWBNg4C/uP6hEAZ6ApHd4Gwy85s69DUp+lt4xLmlh3gvy7lLFjZ
         s9aCZs41IfQECHZXhz1OtVJbca5os1p1iCkwJSAGjrQaIEKFbTtwrajuWIgh37tH/1Ye
         vRfjbOYOiqC6qJ+bKeQI6fLCrKfEKRQSC4uDg0UhWGwU/jMD7ugHXSQjENKWZ4H3S6mY
         YN90VFvDXbxjouxYHxwCx/by5j52uAEASONMq1p+Sn2qkjBmugLNFuBqvNlaiXdiWU1q
         tg8dz9GXspdTz6Rb1L3w/x9kFsw0ufdGZIeC3z4FhqAKcssVR2Tq6KivhSbaQeKX9fva
         5Pkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="J/vrmB9K";
       spf=pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=ync2AQfjdfIzLfN6acrmzKYfwpJIDs/F+sXlhEnJqj4=;
        b=cD7sO49wGsHtDXXp+fOmzc55h/vWdA4snWHxBJzfImLbTKJRGl6obkupY2KGJRVKRA
         juQSRX1C9yvbqQc5R12Ph1SD/t7Uqk/9EtKFr/wcki6KREJqoUynS2OgJfbgqetl8vx6
         +vNnr8DYsFBjPuR62kDZH/WrLvy7yv3sm1U84OQbIfwWn58inX1953Zh1ZugqzG+VVZC
         5eIg61sur1u14nRNmwqtdipcKFlmF59mG4ttpY4GJ3nUmp4read9v+HEwAqsrbOmxkuw
         KC737MGtgh1+DWSnmUOCWm8XWs15JzeHYtHUD5mAuf0w7gtcB2F0KAVUl+7yIYLZQgwD
         KK+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=ync2AQfjdfIzLfN6acrmzKYfwpJIDs/F+sXlhEnJqj4=;
        b=FbkIwm+9OG/KeTNpzsmwn8zwRRAB97vrYA0PZOoVZOd+UrmZDqo7i1phWFlojSuZWg
         x5T3jTnGhSW6arf/8eDVE8sUKV1N5eXerDdrP61Urfdm3/anQqQACa/QHpmZzT1W48uq
         mp3uy776hX9flyLmW31ekgOGAnlpBDMIPIH6UtyU/KlDQmmBzLWNgSHocYYwiiHgEgbu
         S74W9cXALakx5hUtScjmB9JJfy1wp8slkRzxj+EsKct0mOxobPh3WlO3FuejeA8G200S
         7BEyZ/hU33nebsU+x4aAUlWa1OVqVm90i02uwEqvY3AXrpgOblo0dA0dweh0Ymd4VcMV
         OnIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3jBj4wcWmkY+qAzwvG/qY5Jss2dViPZXR2gAxxiIj6klm3Tnay
	YeOREWm6BLXP+2s4GgzbKnk=
X-Google-Smtp-Source: AMsMyM6ZnsytYTglSnAGf128sUTdO3cVx8qMVbFWxzGr1s+nuuYAI3fsz97fUTjU7P0Qtnfn1FhLug==
X-Received: by 2002:a05:6e02:170b:b0:2f3:3800:aab3 with SMTP id u11-20020a056e02170b00b002f33800aab3mr11730795ill.132.1664881477099;
        Tue, 04 Oct 2022 04:04:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:9581:0:b0:363:5608:799d with SMTP id b1-20020a029581000000b003635608799dls15859jai.7.-pod-prod-gmail;
 Tue, 04 Oct 2022 04:04:36 -0700 (PDT)
X-Received: by 2002:a05:6638:4710:b0:35a:6372:3df0 with SMTP id cs16-20020a056638471000b0035a63723df0mr12368758jab.277.1664881476413;
        Tue, 04 Oct 2022 04:04:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664881476; cv=none;
        d=google.com; s=arc-20160816;
        b=p4/nlIleY6ZwMDbgdZ1PdZj8BF87iV020mUlyLjFAuCMQgnIIlgMdqg6YFxi25FXNL
         +IIAAGBtQcWsoKH9BLKah/h5Hwhu3X2Tz/LDRgBxnKsUWFHoXsMqKh256bJ5qX4QdBaB
         PhIouDVDQL0KahQbApvF9TAFSXvFLz0xk6dwjxqXcyKEI3eogfWS3FziPlT3s0u35Bal
         U+SZcUtUlaKJEJvjMeauZKuSYDq5zDg2ZoLWn0JTAJ8Ss+/vBSEK1xycDJkodamQkfEv
         BQQ+Abzk7tpCLca4l7c++Py+T2goetqZA6PlhBX0WKjKH+kdWXG3AhOB5nKyJNMtckV5
         jzHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+dGyZLAFgGMTjfv/XBtu0TYoOq7FF1Gy12H3Maj7VZQ=;
        b=jfp3IxDsxwLI+HSHVkuSULkEpRu7wZvhKwtfTyYfP4kF0drS5wID8RPJ8oGatGLqtm
         g2RMfuWRM4Hd5HFsy/x/4KnG+L1A3oenS15gVc9vGJrWQXvmtXwUbPFS3fkc1GJhb6UW
         Fel3KukhkkYTnrh1+ls0hJ+TFAUAcjkNegKHStj3MsdUmo+vGqnWYpygq3UBmzBfdXd2
         Irfi9ZHhWd2n+I9KXHIp8hppc4UlOrlymytcI7MV2l1hQNSVnLs2+kn7/od2vf7RoxQQ
         iZPl/jCWJow43RKSqLfL/iRjM/wk6xVExAMqmnZCfson7GkoVJjmQCgZwb/Mas7tV/+9
         xzLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="J/vrmB9K";
       spf=pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id a9-20020a056602208900b00684c9b5bc7asi575049ioa.1.2022.10.04.04.04.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Oct 2022 04:04:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id y136so12833854pfb.3
        for <kasan-dev@googlegroups.com>; Tue, 04 Oct 2022 04:04:36 -0700 (PDT)
X-Received: by 2002:a63:90c1:0:b0:450:75b5:29fe with SMTP id
 a184-20020a6390c1000000b0045075b529femr6949580pge.541.1664881475536; Tue, 04
 Oct 2022 04:04:35 -0700 (PDT)
MIME-Version: 1.0
References: <20220919095939.761690562@infradead.org> <20220919101521.139727471@infradead.org>
In-Reply-To: <20220919101521.139727471@infradead.org>
From: Ulf Hansson <ulf.hansson@linaro.org>
Date: Tue, 4 Oct 2022 13:03:57 +0200
Message-ID: <CAPDyKFqTWd4W5Ofk76CtC4X43dxBTNHtmY9YzN355-vpviLsPw@mail.gmail.com>
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
 header.i=@linaro.org header.s=google header.b="J/vrmB9K";       spf=pass
 (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::431
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
> Doing RCU-idle outside the driver, only to then temporarily enable it
> again before going idle is daft.
>
> Notably: this converts all dt_init_idle_driver() and
> __CPU_PM_CPU_IDLE_ENTER() users for they are inextrably intertwined.
>
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>

Reviewed-by: Ulf Hansson <ulf.hansson@linaro.org>

Kind regards
Uffe

> ---
>  arch/arm/mach-omap2/cpuidle34xx.c    |    4 ++--
>  drivers/acpi/processor_idle.c        |    2 ++
>  drivers/cpuidle/cpuidle-arm.c        |    1 +
>  drivers/cpuidle/cpuidle-big_little.c |    8 ++++++--
>  drivers/cpuidle/cpuidle-psci.c       |    1 +
>  drivers/cpuidle/cpuidle-qcom-spm.c   |    1 +
>  drivers/cpuidle/cpuidle-riscv-sbi.c  |    1 +
>  drivers/cpuidle/dt_idle_states.c     |    2 +-
>  include/linux/cpuidle.h              |    4 ++++
>  9 files changed, 19 insertions(+), 5 deletions(-)
>
> --- a/drivers/acpi/processor_idle.c
> +++ b/drivers/acpi/processor_idle.c
> @@ -1200,6 +1200,8 @@ static int acpi_processor_setup_lpi_stat
>                 state->target_residency = lpi->min_residency;
>                 if (lpi->arch_flags)
>                         state->flags |= CPUIDLE_FLAG_TIMER_STOP;
> +               if (lpi->entry_method == ACPI_CSTATE_FFH)
> +                       state->flags |= CPUIDLE_FLAG_RCU_IDLE;

I assume the state index here will never be 0?

If not, it may lead to that acpi_processor_ffh_lpi_enter() may trigger
CPU_PM_CPU_IDLE_ENTER_PARAM() to call ct_cpuidle_enter|exit() for an
idle-state that doesn't have the CPUIDLE_FLAG_RCU_IDLE bit set.

>                 state->enter = acpi_idle_lpi_enter;
>                 drv->safe_state_index = i;
>         }
> --- a/drivers/cpuidle/cpuidle-arm.c
> +++ b/drivers/cpuidle/cpuidle-arm.c
> @@ -53,6 +53,7 @@ static struct cpuidle_driver arm_idle_dr
>          * handler for idle state index 0.
>          */
>         .states[0] = {
> +               .flags                  = CPUIDLE_FLAG_RCU_IDLE,

Comparing arm64 and arm32 idle-states/idle-drivers, the $subject
series ends up setting the CPUIDLE_FLAG_RCU_IDLE for the ARM WFI idle
state (state zero), but only for the arm64 and psci cases (mostly
arm64). For arm32 we would need to update the ARM_CPUIDLE_WFI_STATE
too, as that is what most arm32 idle-drivers are using. My point is,
the code becomes a bit inconsistent.

Perhaps it's easier to avoid setting the CPUIDLE_FLAG_RCU_IDLE bit for
all of the ARM WFI idle states, for both arm64 and arm32?

>                 .enter                  = arm_enter_idle_state,
>                 .exit_latency           = 1,
>                 .target_residency       = 1,
> --- a/drivers/cpuidle/cpuidle-big_little.c
> +++ b/drivers/cpuidle/cpuidle-big_little.c
> @@ -64,7 +64,8 @@ static struct cpuidle_driver bl_idle_lit
>                 .enter                  = bl_enter_powerdown,
>                 .exit_latency           = 700,
>                 .target_residency       = 2500,
> -               .flags                  = CPUIDLE_FLAG_TIMER_STOP,
> +               .flags                  = CPUIDLE_FLAG_TIMER_STOP |
> +                                         CPUIDLE_FLAG_RCU_IDLE,
>                 .name                   = "C1",
>                 .desc                   = "ARM little-cluster power down",
>         },
> @@ -85,7 +86,8 @@ static struct cpuidle_driver bl_idle_big
>                 .enter                  = bl_enter_powerdown,
>                 .exit_latency           = 500,
>                 .target_residency       = 2000,
> -               .flags                  = CPUIDLE_FLAG_TIMER_STOP,
> +               .flags                  = CPUIDLE_FLAG_TIMER_STOP |
> +                                         CPUIDLE_FLAG_RCU_IDLE,
>                 .name                   = "C1",
>                 .desc                   = "ARM big-cluster power down",
>         },
> @@ -124,11 +126,13 @@ static int bl_enter_powerdown(struct cpu
>                                 struct cpuidle_driver *drv, int idx)
>  {
>         cpu_pm_enter();
> +       ct_idle_enter();
>
>         cpu_suspend(0, bl_powerdown_finisher);
>
>         /* signals the MCPM core that CPU is out of low power state */
>         mcpm_cpu_powered_up();
> +       ct_idle_exit();
>
>         cpu_pm_exit();
>
> --- a/drivers/cpuidle/cpuidle-psci.c
> +++ b/drivers/cpuidle/cpuidle-psci.c
> @@ -357,6 +357,7 @@ static int psci_idle_init_cpu(struct dev
>          * PSCI idle states relies on architectural WFI to be represented as
>          * state index 0.
>          */
> +       drv->states[0].flags = CPUIDLE_FLAG_RCU_IDLE;
>         drv->states[0].enter = psci_enter_idle_state;
>         drv->states[0].exit_latency = 1;
>         drv->states[0].target_residency = 1;
> --- a/drivers/cpuidle/cpuidle-qcom-spm.c
> +++ b/drivers/cpuidle/cpuidle-qcom-spm.c
> @@ -72,6 +72,7 @@ static struct cpuidle_driver qcom_spm_id
>         .owner = THIS_MODULE,
>         .states[0] = {
>                 .enter                  = spm_enter_idle_state,
> +               .flags                  = CPUIDLE_FLAG_RCU_IDLE,
>                 .exit_latency           = 1,
>                 .target_residency       = 1,
>                 .power_usage            = UINT_MAX,
> --- a/drivers/cpuidle/cpuidle-riscv-sbi.c
> +++ b/drivers/cpuidle/cpuidle-riscv-sbi.c
> @@ -332,6 +332,7 @@ static int sbi_cpuidle_init_cpu(struct d
>         drv->cpumask = (struct cpumask *)cpumask_of(cpu);
>
>         /* RISC-V architectural WFI to be represented as state index 0. */
> +       drv->states[0].flags = CPUIDLE_FLAG_RCU_IDLE;
>         drv->states[0].enter = sbi_cpuidle_enter_state;
>         drv->states[0].exit_latency = 1;
>         drv->states[0].target_residency = 1;
> --- a/drivers/cpuidle/dt_idle_states.c
> +++ b/drivers/cpuidle/dt_idle_states.c
> @@ -77,7 +77,7 @@ static int init_state_node(struct cpuidl
>         if (err)
>                 desc = state_node->name;
>
> -       idle_state->flags = 0;
> +       idle_state->flags = CPUIDLE_FLAG_RCU_IDLE;
>         if (of_property_read_bool(state_node, "local-timer-stop"))
>                 idle_state->flags |= CPUIDLE_FLAG_TIMER_STOP;
>         /*
> --- a/include/linux/cpuidle.h
> +++ b/include/linux/cpuidle.h
> @@ -282,14 +282,18 @@ extern s64 cpuidle_governor_latency_req(
>         int __ret = 0;                                                  \
>                                                                         \
>         if (!idx) {                                                     \
> +               ct_idle_enter();                                        \

According to my comment above, we should then drop these calls to
ct_idle_enter and ct_idle_exit() here. Right?

>                 cpu_do_idle();                                          \
> +               ct_idle_exit();                                         \
>                 return idx;                                             \
>         }                                                               \
>                                                                         \
>         if (!is_retention)                                              \
>                 __ret =  cpu_pm_enter();                                \
>         if (!__ret) {                                                   \
> +               ct_idle_enter();                                        \
>                 __ret = low_level_idle_enter(state);                    \
> +               ct_idle_exit();                                         \
>                 if (!is_retention)                                      \
>                         cpu_pm_exit();                                  \
>         }                                                               \
>

Kind regards
Uffe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAPDyKFqTWd4W5Ofk76CtC4X43dxBTNHtmY9YzN355-vpviLsPw%40mail.gmail.com.
