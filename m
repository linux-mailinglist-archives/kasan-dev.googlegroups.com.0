Return-Path: <kasan-dev+bncBDV37XP3XYDRBBPUZCGAMGQEQX5ZXKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 47FEC4502BC
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 11:44:22 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id q5-20020a5d5745000000b00178abb72486sf3384617wrw.9
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 02:44:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636973062; cv=pass;
        d=google.com; s=arc-20160816;
        b=n3+BM8Y27byq9z8YY4HysluHOaMkJyuHxiQgYXdkttwcWTLhxsrzn4u59rAwePSgJ9
         jeiXseaXOWOcP/e1YITHgh/kYR5LdoRSWGNV9ILaNNnaJwhZ2qD2AKproq/proEQla93
         PEf1hpasUkf+eXB4G9bjsLlJwKeFhjLHut1kGCSgEaDd0iiiZBbRJ+b9c/Ju7kXVatFg
         a9qJOctFlgX7j6XJNa8JuAIpBGxIQ+7eHSsxFxSeCc5HB90W2Kv8Y3gdY/lM3Aw2wGbs
         Ey0bT3wENZmHwyRPxnvLjb9gvibkHjdruzItEYXl5kCEcsYxApcK6/TDGnPUnMGBTSfH
         g0BA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=sYdupvy0vQgPlcatW/t1KFKS2DN02RTmkJhVwk8gneM=;
        b=UvR890A1j0mIEvm/EdWGJglQyJlzT8XiPabwH4gMCScfuQvnRL+kDHZ9Fyy+BUBt/Z
         vYXTvvE793OPgzxWajxdbcb1MJ1N3Nl9yM/YrMvfJtghhsTzp/9ykxEBQUaZZRU5WxNW
         Kb2WAKJmTcDJOYaCLsgUMI0Ci/XCYdD0CEWetjnpJEAchCpUNnKQrbpnY+pOcwZ/k+Ud
         OWoS0emcO4Ksqa/WZedp9/sKgME5g1eolMogwuN1CSgN9K09MC49mFGC/j3Zszx2GgZO
         un4eQXz7W8zwml9uGpO0zB9c5euyIPp1CFhK0N7uiX3536+PdCLYiYbcZVvZzMYndZZK
         vGFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sYdupvy0vQgPlcatW/t1KFKS2DN02RTmkJhVwk8gneM=;
        b=mek/w1E2tjVzNaiBAy3AZdlpnprv4zCgOj+5rOiPXf3oNX6wVBUVlFTDyDNMcn4+9w
         3h6dFMaq07skT+FpqX9rhq5kE9CVoUCRB3W2ryLErUfRrKZiGfG6/Y6w5vSr5SyDr0z2
         zBgnerv2ST7RrdraDjg2a1jukjL/qVlFQpMmVPkdbp/NSMGI50KOc8nDVfqu54GluEVz
         OPm6X0MA/MPzWMTJHcB+Zit1YMossW5Y4jLhTf8QBcOY1kndNRZ9gX0xJRpu6cnPs5U3
         NUFOlFEPjFQcv5UwnDupjQYn/ymuJy0vtvrgDZLKuBExr++VEd+pjnhOsDF4e1rpx9vO
         jJSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sYdupvy0vQgPlcatW/t1KFKS2DN02RTmkJhVwk8gneM=;
        b=V8t9sezGwJJKDF6VXU9SQKufxoz9EixShdpou0Kk+iWhODey3b1KSeHPXcT2o3kPcq
         rMdWO6/MbkATIHtHt2aJDUWY0af90Z+lIRi6SS4YWdkK0TqcH9F6gI7XpIcmpzBrJqNW
         U71evDfRSAKA4a69sKK3qE5QLSMgbacuIZ6ycwNZut5XN67XRbUJ+5zEI0PYTzDiiT/q
         +gi0xZoeiPyoDB+yfQMdeyibML+SS++pYlEHKivbji47EnSN+lcG61qW2zkSeGQflPKK
         NVpZuLwvLPSuQRgqPJNXdB/Lr1mhorK8EXo57CUrER43Y15oBKxWNLabUCqgMeIOjspQ
         uu9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531IVvJYwZG+gSH8N6mkn3axv09W2v8h5eUCgS+LBWl2btP9oynY
	+24BCnp07o8uFym8x5kXqbQ=
X-Google-Smtp-Source: ABdhPJz160g5zae8q7cXWa3voxSrxQMFhQFfshhk/W4cTPkUsX+YwtyQUnDnokK7yBFVE8vHbONdVw==
X-Received: by 2002:a1c:7c19:: with SMTP id x25mr42791417wmc.42.1636973062056;
        Mon, 15 Nov 2021 02:44:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:ed0e:: with SMTP id l14ls6616266wmh.0.gmail; Mon, 15 Nov
 2021 02:44:21 -0800 (PST)
X-Received: by 2002:a1c:9ad4:: with SMTP id c203mr41184412wme.23.1636973061074;
        Mon, 15 Nov 2021 02:44:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636973061; cv=none;
        d=google.com; s=arc-20160816;
        b=YXKq+irOEkd5zo7JME/khJDKJkdrJDDVDtlk7TBtKJAi/vWMd0df0BT++23OfZM8sN
         rpJ19h4v0zFo3BxjuL9QdGHZiElf52h+x4nEexXXF7laS9JT0qfmakeAV5DA6bCd7Y9r
         2YDo5rpyIbI5+uuAHMR8Fk4MUs/6461JN7t+TFikZmDSTOX7mDMHvGb8Wfsb6APE43rk
         dcrjY8wSoKDVECVDgViC6yBALF3ZKOigIyO+JrmHb2f7ShyoOHH7B4/hQpoUEKouahIv
         icqKeIctASnSEKFz6nhJRyLO3HnjHxXn89m5xpiAMHiHsQsfQykBSUvZiyQWmYDvp7W1
         2u/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=g/ENQUWypeWyve1uhT1U3Ej7VVkFkarAYYmThoIHSug=;
        b=XzElOquowAOmF8uvuP60kuuOxYJJ2SS/Nh7wRObMgWmoSlrrfnqaS/3SSZqT0Zg/Bt
         VKq+uXxJcRL29ZmkJThPmzdWWcCcYJfbmIQxLXTbe/sDtUs508OFHudbAbmZujYp4gTW
         vkrjTsGYSiRy6y6hbCT7xT4VqbbaEIkgB7DMDsWY0Xc/Hz08olXjWdq067XZvJoodtMu
         KICTsIdjt+fQ3MeC6FanPfYQOCkuHxvdlfdmWZCkySApiKHJQy+hlH7JsVl9s5tr2Zip
         MHMQUrnkDYcU2UFZqUFZsxrVISJUYVbx6jJuFejx+/lMFX6g7MCqTlcga5JFwQqgBCub
         WQgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id w2si739571wrg.5.2021.11.15.02.44.20
        for <kasan-dev@googlegroups.com>;
        Mon, 15 Nov 2021 02:44:21 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 365081FB;
	Mon, 15 Nov 2021 02:44:20 -0800 (PST)
Received: from FVFF77S0Q05N (unknown [10.57.56.46])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C2E473F70D;
	Mon, 15 Nov 2021 02:44:18 -0800 (PST)
Date: Mon, 15 Nov 2021 10:44:11 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Qian Cai <quic_qiancai@quicinc.com>,
	Valentin Schneider <valentin.schneider@arm.com>
Cc: Will Deacon <will@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Dmitry Vyukov <dvyukov@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: KASAN + CPU soft-hotplug = stack-out-of-bounds at
 cpuinfo_store_cpu
Message-ID: <YZI5+83nxZzo00Dy@FVFF77S0Q05N>
References: <YY9ECKyPtDbD9q8q@qian-HP-Z2-SFF-G5-Workstation>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YY9ECKyPtDbD9q8q@qian-HP-Z2-SFF-G5-Workstation>
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

Hi,

On Fri, Nov 12, 2021 at 11:50:16PM -0500, Qian Cai wrote:
> FYI, running CPU soft-hotplug with KASAN on arm64 defconfig will
> always trigger a stack-out-of-bounds below. I am not right sure where
> exactly KASAN pointed at, so I am just doing the brute-force
> bisect. The progress so far:

From below it looks like this is on linux-next; I can reproduce this on
v5.16-rc1 using your config, when hotplugging CPU0 back in.

We used to have issues with stale poison being left on the stack across a
hotplug, and we fixed that with commit:

  e1b77c92981a5222 ("sched/kasan: remove stale KASAN poison after hotplug")

... but it looks like we no longer call init_idle() for each hotplug since commit:

  f1a0a376ca0c4ef1 ("sched/core: Initialize the idle task with preemption disabled")

... and so don't get the kasan_unpoison_task_stack() call which we want when
bringing up a CPU, which we used to get by way of idle_thread_get() calling init_idle().

Adding a call to kasan_unpoison_task_stack(idle) within bringup_cpu() gets rid
of that, and I reckon we want that explciitly *somewhere* on the CPU bringup
path.

Thanks,
Mark.

> # git bisect log
> git bisect start
> # bad: [e73f0f0ee7541171d89f2e2491130c7771ba58d3] Linux 5.14-rc1
> git bisect bad e73f0f0ee7541171d89f2e2491130c7771ba58d3
> # good: [62fb9874f5da54fdb243003b386128037319b219] Linux 5.13
> git bisect good 62fb9874f5da54fdb243003b386128037319b219
> # bad: [e058a84bfddc42ba356a2316f2cf1141974625c9] Merge tag 'drm-next-2021-07-01' of git://anongit.freedesktop.org/drm/drm
> git bisect bad e058a84bfddc42ba356a2316f2cf1141974625c9
> # bad: [a6eaf3850cb171c328a8b0db6d3c79286a1eba9d] Merge tag 'sched-urgent-2021-06-30' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip
> git bisect bad a6eaf3850cb171c328a8b0db6d3c79286a1eba9d
> # bad: [31e798fd6f0ff0acdc49c1a358b581730936a09a] Merge tag 'media/v5.14-1' of git://git.kernel.org/pub/scm/linux/kernel/git/mchehab/linux-media
> git bisect bad 31e798fd6f0ff0acdc49c1a358b581730936a09a
> 
> I am going to test the "arm64-upstream" merge request next which has
> some interesting arm64/cpuinfo patches.
> 
>  BUG: KASAN: stack-out-of-bounds in vsnprintf
>  Read of size 8 at addr ffff800016297db8 by task swapper/0/0

> 
>  CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.15.0-next-20211110 #157
>  Hardware name: MiTAC RAPTOR EV-883832-X3-0001/RAPTOR, BIOS 1.6 06/28/2020
>  Call trace:
>   dump_backtrace
>   show_stack
>   dump_stack_lvl
>   print_address_description.constprop.0
>   kasan_report
>   __asan_report_load8_noabort
>   vsnprintf
>   vsnprintf at /root/linux-next/lib/vsprintf.c:2807
>   vprintk_store
>   vprintk_store at /root/linux-next/kernel/printk/printk.c:2138 (discriminator 5)
>   vprintk_emit
>   vprintk_emit at /root/linux-next/kernel/printk/printk.c:2232
>   vprintk_default
>   vprintk_default at /root/linux-next/kernel/printk/printk.c:2260
>   vprintk
>   vprintk at /root/linux-next/kernel/printk/printk_safe.c:50
>   _printk
>   printk at /root/linux-next/kernel/printk/printk.c:2264
>   __cpuinfo_store_cpu
>   __cpuinfo_store_cpu at /root/linux-next/arch/arm64/kernel/cpuinfo.c:412
>   cpuinfo_store_cpu
>   cpuinfo_store_cpu at /root/linux-next/arch/arm64/kernel/cpuinfo.c:418
>   secondary_start_kernel
>   secondary_start_kernel at /root/linux-next/arch/arm64/kernel/smp.c:241
>   __secondary_switched
> 
> 
>  addr ffff800016297db8 is located in stack of task swapper/0/0 at offset 136 in frame:
>   _printk
> 
>  this frame has 1 object:
>   [32, 64) 'args'
> 
>  Memory state around the buggy address:
>   ffff800016297c80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>   ffff800016297d00: 00 00 00 00 00 00 f1 f1 f1 f1 00 00 00 00 f3 f3
>  >ffff800016297d80: f3 f3 00 00 00 00 f3 f3 00 00 00 00 00 00 00 00
>                                          ^
>   ffff800016297e00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>   ffff800016297e80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YZI5%2B83nxZzo00Dy%40FVFF77S0Q05N.
