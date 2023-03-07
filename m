Return-Path: <kasan-dev+bncBCKMP2VK2UCRB6WRTWQAMGQEDL3RL2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 786306AE6E5
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Mar 2023 17:40:27 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id v14-20020a2e9f4e000000b002934fe0289bsf4412298ljk.0
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Mar 2023 08:40:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678207227; cv=pass;
        d=google.com; s=arc-20160816;
        b=auwhUS5VPZEfxocV3DZRasp8VObr5E7+8FhKQ4Y1/wxYtkx6wyv4L3mt8MZAIZPqjD
         +nOGVcpZ66CF01acBQmqK4WENjKw4FuSvjxgLifA/dC1ouxbEI1IEQmDsHlKtFkVog3K
         y25k+XenbqfP/KmFypp3eHR8uqCPav+FPDSJlvKfn3kRMtSBU0TYDY3mgQ13wOw1hKaJ
         B5TwE7l2VgIxR/+HHAjF40UJ4uy/X30X+CsjkkZoVRJ70FSg6jgS3DEDQ4yZ8doSyMuu
         tl14myQzis3eDBHAEvdN1kpF+B66OuIe0D8E3LuhxcFDuH2CbLPhv1P5ZUhM1z9AMqkP
         XJEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:message-id
         :in-reply-to:subject:cc:to:from:date:sender:dkim-signature;
        bh=Pqo0t3Xd9DWBdQKWsOQaU3xp6ewHrSpTw2ikNFpj1TI=;
        b=UHCBvSAdDPJYhK/v4yOs0l/jPvgk3/ST1iWAzUlS4LaeCRyAkxLjI54KFAADWVJL58
         v3rX1Qtv+A0AL+ZnmY0bApDDCdRB1GEhl2Ql4YTDHoGIlynmpALGXSOxPxDMrgxoggd7
         4RZ3FipK/UHF3WiMvT7IEh3GAHmWcGbp/3iepZ7BC+yaw3P1zxGfrvpcnhLVsFCbAWAF
         QKLvQCQq10h0t2CQRT8Z1ABtLWgEmEDFxI1tEGD5qvJEq4GHvHzX6peJK03Hz2uOGu9O
         QWc9m2A1QPYl7Me7or30GdaYj63smGY0JgY1emF0yNS2YrMjy5WGoqRT+XFPNACy2I0m
         fGdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 2a02:1800:110:4::f00:1a is neither permitted nor denied by best guess record for domain of geert@linux-m68k.org) smtp.mailfrom=geert@linux-m68k.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678207227;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:message-id:in-reply-to
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Pqo0t3Xd9DWBdQKWsOQaU3xp6ewHrSpTw2ikNFpj1TI=;
        b=QkYwHPDonw67w/q6cb73uhbOPm5DTM8YlNG2l16hJrSWxrkROk8qslSqLmRnKAFxuJ
         MWnquoILUen2I3/lnLoKbW2YyLslMJORA+KX393sYspuCCnCJuKhB+aAik/0e3/T/XiI
         kuGLOy4FC/mUN6JmMGkntPhZPmvSqiT+5xXnwuiokc7eS4QDaqxRiKbh6iuN9aZ0LFjo
         19R/8SnQev+VtHBsV8hlMkamzZ7zEQMAoFe5cHA6s8RkHUHS162AxCnPb14pxvmOj2Ge
         guCROs84DpY9CWX0stH2y64oiJagNXjG5eJqV1ZYD/Ro3a05Nv2LBnxDRxx9TiB/wtLe
         3dAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678207227;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Pqo0t3Xd9DWBdQKWsOQaU3xp6ewHrSpTw2ikNFpj1TI=;
        b=U+Xu7P/vcLAntdDGdTG7c7+22QuWwGVz617dSJ9RO4RB1puoXngBMsuoRbiHKLozyK
         MrEet+ENjMHXwP3RYNn2f6m71Il7Da+IKMpaawyFLETeajd0vCpm3UrDdluxcg3cySee
         fBbqNnEgf46+dhyhvDtlnNz/GwIy2c30tyW4/L3w4AojpQ5LjKiK4x74GOKsfh4ZoB7z
         mDceOBYq9CStU7FosPZXiDoQ8HrFg6yMZBftY2rGXGt59mVfATQuHXIe17ffh6t9RCMU
         JJ7ZufcMnVHCxPNFnyMLAnqReDx1iJnzXJsTXrMgAMqh1jefV49qcCZTcfyKFVYZVKBA
         +hQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXavTyn0Du892s/N3rXFTfHKOTjCq2rUMqBUsfwIs5IaUHXjcY8
	8gPUtCjCPDsA/GhfG+/V1Bg=
X-Google-Smtp-Source: AK7set/ONBJoAmxcC4Te0R4AmZHLp8X/yDNGX+dpA/bL8Ylwvw9EGwipCLC0If7iHfziMZ0yV+hxEQ==
X-Received: by 2002:ac2:43da:0:b0:4dd:a347:2146 with SMTP id u26-20020ac243da000000b004dda3472146mr4675189lfl.0.1678207226590;
        Tue, 07 Mar 2023 08:40:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:281d:b0:4db:3331:2b29 with SMTP id
 cf29-20020a056512281d00b004db33312b29ls820287lfb.0.-pod-prod-gmail; Tue, 07
 Mar 2023 08:40:24 -0800 (PST)
X-Received: by 2002:ac2:4a8b:0:b0:4e0:c0d0:e209 with SMTP id l11-20020ac24a8b000000b004e0c0d0e209mr4071663lfp.29.1678207224827;
        Tue, 07 Mar 2023 08:40:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678207224; cv=none;
        d=google.com; s=arc-20160816;
        b=wUIHY6uILlQIaVfAtNPQmVAwm5tolfUjxfdghdKLcOkkXg7Mnae/LSTnQmsEdlrnXf
         J08C/AXmstQ06Mo9NfzVnTQotv9YHjTLIi+YmWbxC2K0ueaTvdQxiHsggUyySPS7/rNK
         aKsub16TdIOS9ehl3E2NLdkwkarOWN5EZTbqdZiQ8hYxcmEXx9m3d+wfLoCuUkq8RMa6
         qRBidNSdYyqQRXxCotrKuV0FsKiZzUqZXbz3PJMohVipR1e7imfgkITytC2ojKPfkcGj
         sgYwI1WaMqEPpFDuSVDI660CRWWi0vRFp95FVno1OFxu7gFWqZR5BPE/OLhtXVtSMMgB
         7ayw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date;
        bh=mQoPgOsOdMQXLuw3hPjudPYNz7wYr2Os5a513yqYCuI=;
        b=cPCjLRHTgu1smQGxL+iRK533jvKw4gPuC88dVED9Y0UXMYMo9AHEz90ymuLaC9hxuo
         nxDbEUWUKHH2Wec43w5fRcwLF2n8PK/+vHBUbifiHunPQVH+6nxBkZdQuRZ39iR4vjdJ
         sJ5sQDENFS/p/YX+Q2sdpsUQJa0ifAuPzXew3M+ERJRaAFF1JReCd2yTVeT09ABxc0IQ
         fQ+eqXYFOgN8CPJOMzpe5W/PR2CDakOnvucczv67RqAZCNz5XmB0U/G3+3QH1E24t5o5
         DbRwzmnGIqz2lp1/x90yUP6B1hzZ+m2Hdt/75eESgrg1jNmqVxNOILzI31ho4RShIeqZ
         xTDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 2a02:1800:110:4::f00:1a is neither permitted nor denied by best guess record for domain of geert@linux-m68k.org) smtp.mailfrom=geert@linux-m68k.org
Received: from albert.telenet-ops.be (albert.telenet-ops.be. [2a02:1800:110:4::f00:1a])
        by gmr-mx.google.com with ESMTPS id bp18-20020a056512159200b004dd8416c0d6si641674lfb.0.2023.03.07.08.40.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 07 Mar 2023 08:40:24 -0800 (PST)
Received-SPF: neutral (google.com: 2a02:1800:110:4::f00:1a is neither permitted nor denied by best guess record for domain of geert@linux-m68k.org) client-ip=2a02:1800:110:4::f00:1a;
Received: from ramsan.of.borg ([IPv6:2a02:1810:ac12:ed50:614d:21b0:703:d0f9])
	by albert.telenet-ops.be with bizsmtp
	id VUg82900A3mNwr406Ug80J; Tue, 07 Mar 2023 17:40:24 +0100
Received: from geert (helo=localhost)
	by ramsan.of.borg with local-esmtp (Exim 4.95)
	(envelope-from <geert@linux-m68k.org>)
	id 1pZaMC-00BCRZ-9r;
	Tue, 07 Mar 2023 17:40:08 +0100
Date: Tue, 7 Mar 2023 17:40:08 +0100 (CET)
From: Geert Uytterhoeven <geert@linux-m68k.org>
To: Peter Zijlstra <peterz@infradead.org>
cc: Frederic Weisbecker <frederic@kernel.org>, Guo Ren <guoren@kernel.org>, 
    "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>, 
    Kajetan Puchalski <kajetan.puchalski@arm.com>, 
    Tony Lindgren <tony@atomide.com>, Ulf Hansson <ulf.hansson@linaro.org>, 
    Ingo Molnar <mingo@kernel.org>, linux@armlinux.org.uk, linux-imx@nxp.com, 
    linux-kernel@vger.kernel.org, linux-omap@vger.kernel.org, 
    linux-samsung-soc@vger.kernel.org, linux-perf-users@vger.kernel.org, 
    linux-pm@vger.kernel.org, linux-clk@vger.kernel.org, 
    linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org, 
    linux-arch@vger.kernel.org, linux-mm@kvack.org, 
    linux-trace-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
    linux-renesas-soc@vger.kernel.org
Subject: Re: [PATCH v3 07/51] cpuidle,psci: Push RCU-idle into driver
In-Reply-To: <20230112195539.760296658@infradead.org>
Message-ID: <ff338b9f-4ab0-741b-26ea-7b7351da156@linux-m68k.org>
References: <20230112194314.845371875@infradead.org> <20230112195539.760296658@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 2a02:1800:110:4::f00:1a is neither permitted nor denied by best
 guess record for domain of geert@linux-m68k.org) smtp.mailfrom=geert@linux-m68k.org
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

 	Hoi Peter,

(reduced the insane CC list)

On Thu, 12 Jan 2023, Peter Zijlstra wrote:
> Doing RCU-idle outside the driver, only to then temporarily enable it
> again, at least twice, before going idle is daft.
>
> Notably once implicitly through the cpu_pm_*() calls and once
> explicitly doing ct_irq_*_irqon().
>
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Reviewed-by: Frederic Weisbecker <frederic@kernel.org>
> Reviewed-by: Guo Ren <guoren@kernel.org>
> Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
> Tested-by: Kajetan Puchalski <kajetan.puchalski@arm.com>
> Tested-by: Tony Lindgren <tony@atomide.com>
> Tested-by: Ulf Hansson <ulf.hansson@linaro.org>

Thanks for your patch, which is now commit e038f7b8028a1d1b ("cpuidle,
psci: Push RCU-idle into driver") in v6.3-rc1.

I have bisected a PSCI checker regression on Renesas R-Car Gen3/4 SoCs
to commit a01353cf1896ea5b ("cpuidle: Fix ct_idle_*() usage") (the 7
commits before that do not compile):

psci_checker: PSCI checker started using 2 CPUs
psci_checker: Starting hotplug tests
psci_checker: Trying to turn off and on again all CPUs
psci: CPU0 killed (polled 0 ms)
Detected PIPT I-cache on CPU0
CPU0: Booted secondary processor 0x0000000000 [0x411fd073]
psci_checker: Trying to turn off and on again group 0 (CPUs 0-1)
psci: CPU0 killed (polled 0 ms)
Detected PIPT I-cache on CPU0
CPU0: Booted secondary processor 0x0000000000 [0x411fd073]
psci_checker: Hotplug tests passed OK
psci_checker: Starting suspend tests (10 cycles per state)
psci_checker: CPU 0 entering suspend cycles, states 1 through 1
psci_checker: CPU 1 entering suspend cycles, states 1 through 1
------------[ cut here ]------------
WARNING: CPU: 1 PID: 177 at kernel/context_tracking.c:141 ct_kernel_exit.constprop.0+0xd8/0xf4
Modules linked in:
CPU: 1 PID: 177 Comm: psci_suspend_te Not tainted 6.2.0-rc1-salvator-x-00052-ga01353cf1896 #1415
Hardware name: Renesas Salvator-X 2nd version board based on r8a77965 (DT)
pstate: 604000c5 (nZCv daIF +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : ct_kernel_exit.constprop.0+0xd8/0xf4
lr : ct_kernel_exit.constprop.0+0xc8/0xf4
sp : ffffffc00b73bd30
x29: ffffffc00b73bd30 x28: ffffff807fbadc90 x27: 0000000000000000
x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
x23: ffffff800981e140 x22: 0000000000000001 x21: 0000000000010000
x20: ffffffc0086be1d8 x19: ffffff807fbac070 x18: 0000000000000000
x17: ffffff80083d1000 x16: ffffffc00841fff8 x15: ffffffc00b73b990
x14: ffffffc00895be78 x13: 0000000000000001 x12: 0000000000000000
x11: 00000000000001aa x10: 00000000ffffffea x9 : 000000000000000f
x8 : ffffffc00b73bb68 x7 : ffffffc00b73be18 x6 : ffffffc00815ff34
x5 : ffffffc00a6a0c30 x4 : ffffffc00801ce00 x3 : 0000000000000000
x2 : ffffffc008dc3070 x1 : ffffffc008dc3078 x0 : 0000000004208040
Call trace:
  ct_kernel_exit.constprop.0+0xd8/0xf4
  ct_idle_enter+0x18/0x20
  psci_enter_idle_state+0xa4/0xfc
  suspend_test_thread+0x238/0x2f0
  kthread+0xd8/0xe8
  ret_from_fork+0x10/0x20
irq event stamp: 0
hardirqs last  enabled at (0): [<0000000000000000>] 0x0
hardirqs last disabled at (0): [<ffffffc0080798b0>] copy_process+0x608/0x13dc
softirqs last  enabled at (0): [<ffffffc0080798b0>] copy_process+0x608/0x13dc
softirqs last disabled at (0): [<0000000000000000>] 0x0
---[ end trace 0000000000000000 ]---
------------[ cut here ]------------
WARNING: CPU: 1 PID: 177 at kernel/context_tracking.c:186 ct_kernel_enter.constprop.0+0x78/0xa4
Modules linked in:
CPU: 1 PID: 177 Comm: psci_suspend_te Tainted: G        W          6.2.0-rc1-salvator-x-00052-ga01353cf1896 #1415
Hardware name: Renesas Salvator-X 2nd version board based on r8a77965 (DT)
pstate: 604000c5 (nZCv daIF +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : ct_kernel_enter.constprop.0+0x78/0xa4
lr : ct_kernel_enter.constprop.0+0x68/0xa4
sp : ffffffc00b73bd30
x29: ffffffc00b73bd30 x28: ffffff807fbadc90 x27: 0000000000000000
x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
x23: ffffff800981e140 x22: 0000000000000001 x21: 00000000ffffffa1
x20: ffffffc0086be1d8 x19: 00000000000000c0 x18: 0000000000000000
x17: ffffff80083d1000 x16: ffffffc00841fff8 x15: ffffffc00b73b990
x14: ffffffc00895be78 x13: ffffff800e325180 x12: ffffffc076de9000
x11: 0000000034d4d91d x10: 0000000000000008 x9 : 0000000000001000
x8 : ffffffc008012800 x7 : 0000000000000000 x6 : ffffff807fbac070
x5 : ffffffc008dc3070 x4 : 0000000000000000 x3 : 000000000001a9fc
x2 : 0000000000000003 x1 : ffffffc008dc3070 x0 : 0000000004208040
Call trace:
  ct_kernel_enter.constprop.0+0x78/0xa4
  ct_idle_exit+0x18/0x38
  psci_enter_idle_state+0xdc/0xfc
  suspend_test_thread+0x238/0x2f0
  kthread+0xd8/0xe8
  ret_from_fork+0x10/0x20
irq event stamp: 0
hardirqs last  enabled at (0): [<0000000000000000>] 0x0
hardirqs last disabled at (0): [<ffffffc0080798b0>] copy_process+0x608/0x13dc
softirqs last  enabled at (0): [<ffffffc0080798b0>] copy_process+0x608/0x13dc
softirqs last disabled at (0): [<0000000000000000>] 0x0
---[ end trace 0000000000000000 ]---
psci_checker: Failed to suspend CPU 1: error -1 (requested state 1, cycle 0)
psci_checker: CPU 0 suspend test results: success 0, shallow states 10, errors 0
mmcblk0rpmb: mmc0:0001 BGSD3R 4.00 MiB, chardev (243:0)
psci_checker: CPU 1 suspend test results: success 0, shallow states 9, errors 1
psci_checker: 1 error(s) encountered in suspend tests
psci_checker: PSCI checker completed

> ---
> drivers/cpuidle/cpuidle-psci.c |    9 +++++----
> 1 file changed, 5 insertions(+), 4 deletions(-)
>
> --- a/drivers/cpuidle/cpuidle-psci.c
> +++ b/drivers/cpuidle/cpuidle-psci.c
> @@ -69,12 +69,12 @@ static int __psci_enter_domain_idle_stat
> 		return -1;
>
> 	/* Do runtime PM to manage a hierarchical CPU toplogy. */
> -	ct_irq_enter_irqson();
> 	if (s2idle)
> 		dev_pm_genpd_suspend(pd_dev);
> 	else
> 		pm_runtime_put_sync_suspend(pd_dev);
> -	ct_irq_exit_irqson();
> +
> +	ct_idle_enter();
>
> 	state = psci_get_domain_state();
> 	if (!state)
> @@ -82,12 +82,12 @@ static int __psci_enter_domain_idle_stat
>
> 	ret = psci_cpu_suspend_enter(state) ? -1 : idx;
>
> -	ct_irq_enter_irqson();
> +	ct_idle_exit();
> +
> 	if (s2idle)
> 		dev_pm_genpd_resume(pd_dev);
> 	else
> 		pm_runtime_get_sync(pd_dev);
> -	ct_irq_exit_irqson();
>
> 	cpu_pm_exit();
>
> @@ -240,6 +240,7 @@ static int psci_dt_cpu_init_topology(str
> 	 * of a shared state for the domain, assumes the domain states are all
> 	 * deeper states.
> 	 */
> +	drv->states[state_count - 1].flags |= CPUIDLE_FLAG_RCU_IDLE;
> 	drv->states[state_count - 1].enter = psci_enter_domain_idle_state;
> 	drv->states[state_count - 1].enter_s2idle = psci_enter_s2idle_domain_idle_state;
> 	psci_cpuidle_use_cpuhp = true;

Gr{oetje,eeting}s,

 						Geert

--
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k.org

In personal conversations with technical people, I call myself a hacker. But
when I'm talking to journalists I just say "programmer" or something like that.
 							    -- Linus Torvalds

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ff338b9f-4ab0-741b-26ea-7b7351da156%40linux-m68k.org.
