Return-Path: <kasan-dev+bncBDGIV3UHVAGBBCELTOJAMGQEGIR55PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id C9C514EEA65
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Apr 2022 11:27:37 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id h14-20020a056512220e00b0044a1337e409sf994250lfu.12
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Apr 2022 02:27:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648805257; cv=pass;
        d=google.com; s=arc-20160816;
        b=waiRN1jFXTwm4lhUvBBLlqI8Hv/mBR8KJcwZso1ySUo/xSSdwx+9bDHlimH7N84Df0
         EsACiDuP96fFfuR6aTmuZTHlUyZC6pcwdBFA4USHfCamQxarXQfoWSbPXpXPu2Z0g2tw
         XHSOmVfimO0KQy/BUBW25WHLSd7jHkgvIBGsR3FZ7h+wf5NB/mB5PbUZeLMuBBo2rU1S
         ZroDF8aTI1hI7/sMglGuNAesuNaAQhUMQb0NsdI77rj9OXBrbEnN6mhntMyiAFR4QGds
         kC4ABywbG63aL0loXYkpkJKsU6tjWT6UbBmHyD6/qxTHbJDSWyggkpKttXsbUZa5LZEk
         rroQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HjmRoSN0Xqq6YuAQJAo/keT5fLsbBbGAS9Y2m9feies=;
        b=MUXEs2Jx3Ob8Tl3qngEU1VUHdkEJz4R0WVIKTBe4nnPf8p50+3MCpAqZi3J5Z/YvlM
         qTKyng0N5Y3FjqU/MbQMwk7/5gL337CisHjKrbKCAYdk41IAOg1kuvTOlq/Uw8gQHqlV
         Z737UfzB6vyJRDnAiWfYehTruSs/A7H966b8ehsvo0mYdJeNG/9kMLFwx1iS4vr59EoS
         VhjELLlIOVTFYqzVk3jvtWQXmydRwzEpOh9X5iHJuljOiGl7CyoL6ZtHKovRHnkZ1/js
         wXZXKnrMorFHip9jYD2rn//kQfH6fQet9mtz2TH7tQmHC4731JtRq0InlQsdAljsifI0
         4wLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=e9+em635;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=I9QggolM;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HjmRoSN0Xqq6YuAQJAo/keT5fLsbBbGAS9Y2m9feies=;
        b=SprZZsmDB1T5Tktep9HcOef3dncLaPTjBJoIhSHu8+46oZ3VtFISLsjENAaxbz3bUp
         lM5IEY9fc0KzZgHjLyYjnvxizrdywKfN03IX61kuiuokkld0gAZQoCreY0BIoYmiYeUl
         WGs9baPNjzdxsMJVmhxw+3r5fnHwPrGd0aeWUIX5/4Z5i4pQv7UUT/FmOr2KLZMyFeAr
         MUasBgNzFmFJhQOhkQXAfT+o5HHM9JZbaQaemPYdVNk2+BWg86eWXhceFzR+KKg0g5Bp
         7akns/2R1+Xm+WUR1LTYqD8bj4j570EbOAUfBKZXd+upCguQ/RHIgCILQdmhOI3MVxRH
         RArw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HjmRoSN0Xqq6YuAQJAo/keT5fLsbBbGAS9Y2m9feies=;
        b=UqikFSomV/rIl3vvtfikIKZ8swbA9JIzXrO5onM0trXdDD43ZgJpdwjRl5B0gkJInT
         9i6kpgUbM+6IFmt2j/NRdqwiWsDPU9u/bPF20miFyQL10Ceo1P5bh/jWTVhVTyAcXjaR
         1MngfbiyBPmKsyck99L3SWKL1SVuvTLs58/6uOvl/BpTYwsJXH+9Lu0i98oQMjcfoJiW
         K7zmjIxt+Ym5FVfqgat8duRfCXXUKofDKoi5N8cwQIcOV41w+gM26PWDqTdkW5qLQm+r
         f6MF1GrC6YHBCr2N0y/FxwHo2UamTzHPvrkvj+T1xBzvy41RwrAAGSvlnjsAvkLSH8Br
         kqPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533hnilybFXz2D2c0ajfWsKnad0MNt5QwQ9bn2xvkfxtELSMqeWb
	LXZcWAcMlD5KJxpcFPnYIR0=
X-Google-Smtp-Source: ABdhPJz9DM+Go2YSkN6RXqaWBChcjQ7Uf9CyHsjD+pas0DqjFsM0zMoJQF27ySZ/7nzkW1QXSSsKGw==
X-Received: by 2002:a05:6512:128e:b0:44a:4067:9ffe with SMTP id u14-20020a056512128e00b0044a40679ffemr13421293lfs.64.1648805257181;
        Fri, 01 Apr 2022 02:27:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5285:0:b0:44a:94d2:1d8f with SMTP id q5-20020ac25285000000b0044a94d21d8fls339434lfm.0.gmail;
 Fri, 01 Apr 2022 02:27:36 -0700 (PDT)
X-Received: by 2002:a05:6512:132a:b0:44a:8c95:1a58 with SMTP id x42-20020a056512132a00b0044a8c951a58mr13036013lfu.309.1648805256114;
        Fri, 01 Apr 2022 02:27:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648805256; cv=none;
        d=google.com; s=arc-20160816;
        b=sQtasELU6SA3jwBkVltFGstZsi5yrHgyexxRB1Rv6rVCbE9Abe09oExJAvVVo/kNr/
         pinuZRaLDpZoEFSJe7YJzEP9SdFG/xcV6pa5sNJy2KrTEc+6jlbfNz0Vkd+dFVr3znKd
         XPdhCNSJTOCMfptRUeGQJLCk1/6xO3IBor130Ieahc808zIKWs930o84KMJ9a8HHUPns
         W+984y+r8gbIewfE4qw0G0t0td6d93aOA6XZAd5FIEZJD/PV9a4ND+zntS76olnsLrfP
         fFD6hvI6TXs4kYR1q06abO5HBeCB+49gwHocrm7D2JdYMRPUmnVRiYX2Kt8yrfr7HmVK
         +DUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=A0QKk4sUzoou0ZzWNfIYO9gsM92vo3rk5/SdxP8/yFE=;
        b=W8nSHQKaxXsBqlbmpUld2UkMoSaEtWL1RKJYIyhdo9MI2F5ZKSyWjik1m4i/qiv532
         m0aX0fnTyMkDYaOYHsw9nm1PMXbuFWW15txqFBbRM2HeuBL0A9y6L/AegGr30jThEUfi
         Ab8Ei2WtsRfx5gMv8XHr73VmDoANoLj1K86ZVtaB991vYVpTiDB2Wl36g5bwmr9Aj08K
         iYKRrJGsxBZG/B80AOhYD6yd2QQphoAdqysTPmuj6muJwBKxDappU/61nDMD+CQFEY0c
         uuzBHN5KfnElJ7FkdcB+3QxEaK08dlhZ285AuRcRM0kgtyBQDOSw9yRiLjIQACsxLwEx
         RZAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=e9+em635;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=I9QggolM;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id k18-20020a05651c0a1200b0024b02b27c3bsi96706ljq.8.2022.04.01.02.27.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Apr 2022 02:27:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Fri, 1 Apr 2022 11:27:34 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Zqiang <qiang1.zhang@intel.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, akpm@linux-foundation.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-rt-users@vger.kernel.org
Subject: Re: [PATCH] kasan: Fix sleeping function called from invalid context
 in PREEMPT_RT
Message-ID: <YkbFhgN1jZPTMfnS@linutronix.de>
References: <20220401091006.2100058-1-qiang1.zhang@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220401091006.2100058-1-qiang1.zhang@intel.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=e9+em635;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=I9QggolM;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On 2022-04-01 17:10:06 [+0800], Zqiang wrote:
> BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:46
> in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 1, name: swapper/0
> preempt_count: 1, expected: 0
> ...........
> CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.17.1-rt16-yocto-preempt-rt #22
> Hardware name: QEMU Standard PC (Q35 + ICH9, 2009),
> BIOS rel-1.15.0-0-g2dd4b9b3f840-prebuilt.qemu.org 04/01/2014
> Call Trace:
> <TASK>
> dump_stack_lvl+0x60/0x8c
> dump_stack+0x10/0x12
>  __might_resched.cold+0x13b/0x173
> rt_spin_lock+0x5b/0xf0
>  ___cache_free+0xa5/0x180
> qlist_free_all+0x7a/0x160
> per_cpu_remove_cache+0x5f/0x70
> smp_call_function_many_cond+0x4c4/0x4f0
> on_each_cpu_cond_mask+0x49/0xc0
> kasan_quarantine_remove_cache+0x54/0xf0
> kasan_cache_shrink+0x9/0x10
> kmem_cache_shrink+0x13/0x20
> acpi_os_purge_cache+0xe/0x20
> acpi_purge_cached_objects+0x21/0x6d
> acpi_initialize_objects+0x15/0x3b
> acpi_init+0x130/0x5ba
> do_one_initcall+0xe5/0x5b0
> kernel_init_freeable+0x34f/0x3ad
> kernel_init+0x1e/0x140
> ret_from_fork+0x22/0x30
> 
> When the kmem_cache_shrink() be called, the IPI was triggered, the
> ___cache_free() is called in IPI interrupt context, the local lock
> or spin lock will be acquired. on PREEMPT_RT kernel, these lock is
> replaced with sleepbale rt spin lock, so the above problem is triggered.
> fix it by migrating the release action from the IPI interrupt context
> to the task context on RT kernel.

I haven't seen that while playing with kasan. Is this new?
Could we fix in a way that we don't involve freeing memory from in-IRQ?
This could trigger a lockdep splat if the local-lock in SLUB is acquired
from in-IRQ context on !PREEMPT_RT.

> Signed-off-by: Zqiang <qiang1.zhang@intel.com>

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YkbFhgN1jZPTMfnS%40linutronix.de.
