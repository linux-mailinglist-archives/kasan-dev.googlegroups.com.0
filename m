Return-Path: <kasan-dev+bncBDV37XP3XYDRBIHI4GQAMGQE6PMXK3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id E52256C15B0
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Mar 2023 15:56:32 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id t1-20020a7bc3c1000000b003dfe223de49sf8564221wmj.5
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Mar 2023 07:56:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679324192; cv=pass;
        d=google.com; s=arc-20160816;
        b=VSl+5CZ0WSfnMC6G9vuKTchSGTjBD1qfYkQtBftSKFYlQnMGFDCPrNJBYOymrwDrK8
         fxg6t2/QkDebg10mUQ2diqPoRZ1YBnoar3jt3rjElw/9KM1SYYcu+3Ms3mDy92Y3fJPN
         a9OLG7lrDek7yjkQ8sWdwKBWH/0d7GAK/q2GdhSonb2AhOfOeb7skNu98i2uQzku7jQp
         Oy9w5Kfqml60vqxdI6NLKJtT1+3VTZ7uILckXPCIVP/fPTWoNuEZpT7DCgwQQic6bh+3
         Cw1fQ0JmIV733OKz9vWIJ5W8IVcBxvGECW4irYlMN1WjgpZvvPCBT8U3lqrz60HBWdZK
         YbGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Qx8iwugDdqdOLzHll+zkCUxkMBJM0xrL4styYrpluek=;
        b=bvP+ZFf/faWT7d8oBb71XLvPz7Ghg3ypIYU2j36yHNMVwxAcChki9kX3SEw+bz/DHi
         bbDq7BjEDafp+u08TCtpPUPyAzGWfe9Z2omYI4eILXA+xcjI/aEJFgIot0M50Po1FiEh
         QmPobzSaFwHcoycRgej/+RenjXc+APa+XtE8ufNBy46hBJTLPg8kaxpDp7ZieUoKZIt2
         oDBBNrFB5MBrXFDduo8WB1XZQsvqtwk3THHlwh3KG97SKdRxRHlvHSXuZ2KIPSfBLOQH
         ePxx+L364ltJZnOeqf5fRrnp94Hf3Q/gN1y4skj1sRKFzgQM1tL10nIxtIQ+VF5OeqxT
         cLiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679324192;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Qx8iwugDdqdOLzHll+zkCUxkMBJM0xrL4styYrpluek=;
        b=Qu4DrbFCAKjSBNcHtRU5mUC5C8VBLdkhiWB6EIH7nrYukP/A7KopUXgk6iqVHhFjR0
         kxcoRd2vH8I5+UpV2Httu5k5XkbTrSOLDIfaNoUWKDl11wpQosV1PJIuZZ+cNImKaadw
         w8peOiTFLtNPSTFb3lToDAafL4a0laDmfa/McnX+k02hP1vATQ2VoAosGhf2rXstOwwR
         oynLpjwpfNHjNRJ+NoltnslKyYlmCTbPTngkeh+Urd4TWzarQeXxL0UPMK0zBGHTAj/g
         5EKu2y/FBU3oVG/+yhwYNB1kdLeTf/1X0Wil1oXmODPIzP9srRJzro68FBDESMfwzWB3
         QeoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679324192;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Qx8iwugDdqdOLzHll+zkCUxkMBJM0xrL4styYrpluek=;
        b=TJoOBsdV2vLhMEuf9mqfUBKaCn3W5pf4o2eZ+evUH2cNAFf2l7J/SzPm33Y5L/iYWq
         jc83/+Xb1FezDtcN5Jrf6qnABXnkirwUOHLDyl3+IMVcYqQ4lNUEguRVJhW9ApXcfrcu
         z0YCUrpo3vsb9GEfY5RinGH/pxoFYwgipcPZXhXSzsoOUCvfB/5ut93SjlwrZzAbNn3d
         YNHEu9FlHZedgbGQMaRSZNVucHdJe0JmiHI64cz6WE6hvPwDDXvQ9jBg+dkruidj1fHj
         94jn9TbtAT4qRy4VlgGCu34y5tgMvR7sACKe+3FhqmnGblxNKwlCcQDj/ePVUmBFA+Tc
         lWmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUoeP7OEr6fPoy7c7lQPESHkhup+NSRDhOJUaH+szb3/LG35/ik
	AjLbJdbheNpotIqCWNXqBvM=
X-Google-Smtp-Source: AK7set97qvZNubXWiL9IwFHH1xk9TKgytWOf2CD4NlJkI/yzUXoIuphi2qLrQ7wKA3a/4iV3lsvCjw==
X-Received: by 2002:a5d:6405:0:b0:2d1:7ade:aab with SMTP id z5-20020a5d6405000000b002d17ade0aabmr2632914wru.1.1679324192196;
        Mon, 20 Mar 2023 07:56:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6012:b0:3ed:e168:d3 with SMTP id
 az18-20020a05600c601200b003ede16800d3ls2105886wmb.3.-pod-canary-gmail; Mon,
 20 Mar 2023 07:56:30 -0700 (PDT)
X-Received: by 2002:a05:600c:4453:b0:3eb:389d:156c with SMTP id v19-20020a05600c445300b003eb389d156cmr34699835wmn.37.1679324190732;
        Mon, 20 Mar 2023 07:56:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679324190; cv=none;
        d=google.com; s=arc-20160816;
        b=dkNllAIK3cF7TckfSQ5b9AMgHnWOW3LKOFrEgemcJDW+s3SEwm0R0ywdGyLlP2n6+p
         NlFHx+WYMU7x4ArJ5i1VL/iaofN3jS1Zp3FIo+huuQhTkln+wlhYeFC8I8cJ30OF2k/3
         AW26aqZRpnSdj4jF2ei9F1PcCe78pk4b/HVRM6z9FN+rMlLgs23qnzDtnTIxO4wLcgMR
         np7OHSWRP4dVFxg0nXBwBFuIpo4soKlWIRUHlqnrLpZlEdWoF/vytfY+LgrXrCyfS6OO
         JAqguXogUDmMOXvpny+HrQwYmi/84okA0blophPEJbvwloLbkWrDlh7hmieEtZOhY+9r
         H53Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=6uyHtPzbLs9F82J0HVWdgBO/Lsb4YVLVbr58qGA9kOk=;
        b=UsvbhGFfxxI06Qw0+2e8tZXmsmR2WwwttrY05LOEXqiNq6wCcVTE7ddYypFipXpOMR
         GkIlpDmdzdLnyfh44OAknu4HjophsvifGk7pj92jQG8CcJ2VIyil/w3SOBIiNsX/I7SD
         y+gaG9zieUGbcyCZQX3Hmi8RW1S3+cQ/pai9xuxJzDWrJt9WhT2X8KcIQ3cfifpmyN4h
         ASgGJ4UlXB+suZ7zTJopqGf1QQ9F/vvlw4LqDjmETC3P/lo0h14zexKd7+4bptVoUbjN
         0RK7Z12GfheU4Xb3rTCeLX6W5EQo8lzY3wo+grzgbvg0blTiLbENfIcAwMrF6Umgfgp5
         l/AQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id bp11-20020a5d5a8b000000b002c6e883154bsi380499wrb.1.2023.03.20.07.56.30
        for <kasan-dev@googlegroups.com>;
        Mon, 20 Mar 2023 07:56:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8FD62AD7;
	Mon, 20 Mar 2023 07:57:13 -0700 (PDT)
Received: from FVFF77S0Q05N.cambridge.arm.com (FVFF77S0Q05N.cambridge.arm.com [10.1.35.35])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id AAA413F71E;
	Mon, 20 Mar 2023 07:56:26 -0700 (PDT)
Date: Mon, 20 Mar 2023 14:56:20 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Guo Ren <guoren@kernel.org>,
	"Rafael J. Wysocki" <rafael.j.wysocki@intel.com>,
	Kajetan Puchalski <kajetan.puchalski@arm.com>,
	Tony Lindgren <tony@atomide.com>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Ingo Molnar <mingo@kernel.org>, linux@armlinux.org.uk,
	linux-imx@nxp.com, linux-kernel@vger.kernel.org,
	linux-omap@vger.kernel.org, linux-samsung-soc@vger.kernel.org,
	linux-perf-users@vger.kernel.org, linux-pm@vger.kernel.org,
	linux-clk@vger.kernel.org, linux-arm-msm@vger.kernel.org,
	linux-tegra@vger.kernel.org, linux-arch@vger.kernel.org,
	linux-mm@kvack.org, linux-trace-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-renesas-soc@vger.kernel.org
Subject: Re: [PATCH v3 07/51] cpuidle,psci: Push RCU-idle into driver
Message-ID: <ZBh0FPlF1oeqHftc@FVFF77S0Q05N.cambridge.arm.com>
References: <20230112194314.845371875@infradead.org>
 <20230112195539.760296658@infradead.org>
 <ff338b9f-4ab0-741b-26ea-7b7351da156@linux-m68k.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ff338b9f-4ab0-741b-26ea-7b7351da156@linux-m68k.org>
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

Hi Geert,

On Tue, Mar 07, 2023 at 05:40:08PM +0100, Geert Uytterhoeven wrote:
> 	Hoi Peter,
> 
> (reduced the insane CC list)

Helpfully you dropped me from Cc, so I missed this until just now...

> On Thu, 12 Jan 2023, Peter Zijlstra wrote:
> > Doing RCU-idle outside the driver, only to then temporarily enable it
> > again, at least twice, before going idle is daft.
> > 
> > Notably once implicitly through the cpu_pm_*() calls and once
> > explicitly doing ct_irq_*_irqon().
> > 
> > Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> > Reviewed-by: Frederic Weisbecker <frederic@kernel.org>
> > Reviewed-by: Guo Ren <guoren@kernel.org>
> > Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
> > Tested-by: Kajetan Puchalski <kajetan.puchalski@arm.com>
> > Tested-by: Tony Lindgren <tony@atomide.com>
> > Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
> 
> Thanks for your patch, which is now commit e038f7b8028a1d1b ("cpuidle,
> psci: Push RCU-idle into driver") in v6.3-rc1.
> 
> I have bisected a PSCI checker regression on Renesas R-Car Gen3/4 SoCs
> to commit a01353cf1896ea5b ("cpuidle: Fix ct_idle_*() usage") (the 7
> commits before that do not compile):
>
> psci_checker: PSCI checker started using 2 CPUs
> psci_checker: Starting hotplug tests
> psci_checker: Trying to turn off and on again all CPUs
> psci: CPU0 killed (polled 0 ms)
> Detected PIPT I-cache on CPU0
> CPU0: Booted secondary processor 0x0000000000 [0x411fd073]
> psci_checker: Trying to turn off and on again group 0 (CPUs 0-1)
> psci: CPU0 killed (polled 0 ms)
> Detected PIPT I-cache on CPU0
> CPU0: Booted secondary processor 0x0000000000 [0x411fd073]
> psci_checker: Hotplug tests passed OK
> psci_checker: Starting suspend tests (10 cycles per state)
> psci_checker: CPU 0 entering suspend cycles, states 1 through 1
> psci_checker: CPU 1 entering suspend cycles, states 1 through 1
> ------------[ cut here ]------------
> WARNING: CPU: 1 PID: 177 at kernel/context_tracking.c:141 ct_kernel_exit.constprop.0+0xd8/0xf4

So that's:

  WARN_ON_ONCE(IS_ENABLED(CONFIG_RCU_EQS_DEBUG) && !user && !is_idle_task(current));

... and the PSCI checker doens't run in the context of the idle thread, so the
warning is correct, and we're violating the expectation of the context tracking
code.

The PSCI checker is very much a special case, and I'm not sure how we can fix
this without removing the warning in the cases we want it. It'd be nicer if we
could "queue" the idle into the relevant idle thread. :/

I'm very tempted to say we should just rip the checker code out, rather than
contorting the rest of the code to make that work.

Thanks,
Mark.

> Modules linked in:
> CPU: 1 PID: 177 Comm: psci_suspend_te Not tainted 6.2.0-rc1-salvator-x-00052-ga01353cf1896 #1415
> Hardware name: Renesas Salvator-X 2nd version board based on r8a77965 (DT)
> pstate: 604000c5 (nZCv daIF +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
> pc : ct_kernel_exit.constprop.0+0xd8/0xf4
> lr : ct_kernel_exit.constprop.0+0xc8/0xf4
> sp : ffffffc00b73bd30
> x29: ffffffc00b73bd30 x28: ffffff807fbadc90 x27: 0000000000000000
> x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
> x23: ffffff800981e140 x22: 0000000000000001 x21: 0000000000010000
> x20: ffffffc0086be1d8 x19: ffffff807fbac070 x18: 0000000000000000
> x17: ffffff80083d1000 x16: ffffffc00841fff8 x15: ffffffc00b73b990
> x14: ffffffc00895be78 x13: 0000000000000001 x12: 0000000000000000
> x11: 00000000000001aa x10: 00000000ffffffea x9 : 000000000000000f
> x8 : ffffffc00b73bb68 x7 : ffffffc00b73be18 x6 : ffffffc00815ff34
> x5 : ffffffc00a6a0c30 x4 : ffffffc00801ce00 x3 : 0000000000000000
> x2 : ffffffc008dc3070 x1 : ffffffc008dc3078 x0 : 0000000004208040
> Call trace:
>  ct_kernel_exit.constprop.0+0xd8/0xf4
>  ct_idle_enter+0x18/0x20
>  psci_enter_idle_state+0xa4/0xfc
>  suspend_test_thread+0x238/0x2f0
>  kthread+0xd8/0xe8
>  ret_from_fork+0x10/0x20
> irq event stamp: 0
> hardirqs last  enabled at (0): [<0000000000000000>] 0x0
> hardirqs last disabled at (0): [<ffffffc0080798b0>] copy_process+0x608/0x13dc
> softirqs last  enabled at (0): [<ffffffc0080798b0>] copy_process+0x608/0x13dc
> softirqs last disabled at (0): [<0000000000000000>] 0x0
> ---[ end trace 0000000000000000 ]---
> ------------[ cut here ]------------
> WARNING: CPU: 1 PID: 177 at kernel/context_tracking.c:186 ct_kernel_enter.constprop.0+0x78/0xa4
> Modules linked in:
> CPU: 1 PID: 177 Comm: psci_suspend_te Tainted: G        W          6.2.0-rc1-salvator-x-00052-ga01353cf1896 #1415
> Hardware name: Renesas Salvator-X 2nd version board based on r8a77965 (DT)
> pstate: 604000c5 (nZCv daIF +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
> pc : ct_kernel_enter.constprop.0+0x78/0xa4
> lr : ct_kernel_enter.constprop.0+0x68/0xa4
> sp : ffffffc00b73bd30
> x29: ffffffc00b73bd30 x28: ffffff807fbadc90 x27: 0000000000000000
> x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
> x23: ffffff800981e140 x22: 0000000000000001 x21: 00000000ffffffa1
> x20: ffffffc0086be1d8 x19: 00000000000000c0 x18: 0000000000000000
> x17: ffffff80083d1000 x16: ffffffc00841fff8 x15: ffffffc00b73b990
> x14: ffffffc00895be78 x13: ffffff800e325180 x12: ffffffc076de9000
> x11: 0000000034d4d91d x10: 0000000000000008 x9 : 0000000000001000
> x8 : ffffffc008012800 x7 : 0000000000000000 x6 : ffffff807fbac070
> x5 : ffffffc008dc3070 x4 : 0000000000000000 x3 : 000000000001a9fc
> x2 : 0000000000000003 x1 : ffffffc008dc3070 x0 : 0000000004208040
> Call trace:
>  ct_kernel_enter.constprop.0+0x78/0xa4
>  ct_idle_exit+0x18/0x38
>  psci_enter_idle_state+0xdc/0xfc
>  suspend_test_thread+0x238/0x2f0
>  kthread+0xd8/0xe8
>  ret_from_fork+0x10/0x20
> irq event stamp: 0
> hardirqs last  enabled at (0): [<0000000000000000>] 0x0
> hardirqs last disabled at (0): [<ffffffc0080798b0>] copy_process+0x608/0x13dc
> softirqs last  enabled at (0): [<ffffffc0080798b0>] copy_process+0x608/0x13dc
> softirqs last disabled at (0): [<0000000000000000>] 0x0
> ---[ end trace 0000000000000000 ]---
> psci_checker: Failed to suspend CPU 1: error -1 (requested state 1, cycle 0)
> psci_checker: CPU 0 suspend test results: success 0, shallow states 10, errors 0
> mmcblk0rpmb: mmc0:0001 BGSD3R 4.00 MiB, chardev (243:0)
> psci_checker: CPU 1 suspend test results: success 0, shallow states 9, errors 1
> psci_checker: 1 error(s) encountered in suspend tests
> psci_checker: PSCI checker completed
> 
> > ---
> > drivers/cpuidle/cpuidle-psci.c |    9 +++++----
> > 1 file changed, 5 insertions(+), 4 deletions(-)
> > 
> > --- a/drivers/cpuidle/cpuidle-psci.c
> > +++ b/drivers/cpuidle/cpuidle-psci.c
> > @@ -69,12 +69,12 @@ static int __psci_enter_domain_idle_stat
> > 		return -1;
> > 
> > 	/* Do runtime PM to manage a hierarchical CPU toplogy. */
> > -	ct_irq_enter_irqson();
> > 	if (s2idle)
> > 		dev_pm_genpd_suspend(pd_dev);
> > 	else
> > 		pm_runtime_put_sync_suspend(pd_dev);
> > -	ct_irq_exit_irqson();
> > +
> > +	ct_idle_enter();
> > 
> > 	state = psci_get_domain_state();
> > 	if (!state)
> > @@ -82,12 +82,12 @@ static int __psci_enter_domain_idle_stat
> > 
> > 	ret = psci_cpu_suspend_enter(state) ? -1 : idx;
> > 
> > -	ct_irq_enter_irqson();
> > +	ct_idle_exit();
> > +
> > 	if (s2idle)
> > 		dev_pm_genpd_resume(pd_dev);
> > 	else
> > 		pm_runtime_get_sync(pd_dev);
> > -	ct_irq_exit_irqson();
> > 
> > 	cpu_pm_exit();
> > 
> > @@ -240,6 +240,7 @@ static int psci_dt_cpu_init_topology(str
> > 	 * of a shared state for the domain, assumes the domain states are all
> > 	 * deeper states.
> > 	 */
> > +	drv->states[state_count - 1].flags |= CPUIDLE_FLAG_RCU_IDLE;
> > 	drv->states[state_count - 1].enter = psci_enter_domain_idle_state;
> > 	drv->states[state_count - 1].enter_s2idle = psci_enter_s2idle_domain_idle_state;
> > 	psci_cpuidle_use_cpuhp = true;
> 
> Gr{oetje,eeting}s,
> 
> 						Geert
> 
> --
> Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k.org
> 
> In personal conversations with technical people, I call myself a hacker. But
> when I'm talking to journalists I just say "programmer" or something like that.
> 							    -- Linus Torvalds
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZBh0FPlF1oeqHftc%40FVFF77S0Q05N.cambridge.arm.com.
