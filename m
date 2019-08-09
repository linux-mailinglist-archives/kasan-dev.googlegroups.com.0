Return-Path: <kasan-dev+bncBDV37XP3XYDRBYMFWXVAKGQEZY66V7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 510AB876BF
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2019 11:54:42 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id m26sf739930wmc.3
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2019 02:54:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565344482; cv=pass;
        d=google.com; s=arc-20160816;
        b=f9vnc3qtH28Tv8Q9DabEiDV52KmhLZmHpeH/kOBbf0xiUi6ElzznVy3xcVM7qw3Gck
         G5iL0GTNs0lbmwqh7CO9dgOqQoPg6IWNuiTnUCG8yCGzeRApsFoOFZygtQN7FYYJlg9Y
         gJoujrdfdx5tl9K5KN1KigOY5nCI+5jj3PGrbtK220X0BRJadT3WYaFCv+LtWkIMnfS7
         Zj5EP4bxIw3rfDdQ0gmNfEvSXBUbWCwOB9URarTwea4csCKFl8FcuFgYE1fJaMMx4Yqi
         iGMwlpZ7Te7VEWMq4j6ykG8I5LGRc+pEQkMIb7ofO/wbaMEDFmK8jxg0HaPk1ZM3O1kN
         FBNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=TYmR3ERnVN7f7tbdXX3/1a2ExP8GMaF2HvfV3QYnAss=;
        b=jZMAvJ40XhWOhHiBnHNOAZ4dmQFzCTsVT29XKpdexnmM1Ew1tSXPZpFHD4YcY2aKGy
         cnKtu7XRotAWgwr1VRqsetqyYjygYsxx7QOtJa2/ntUhLhuX8Fq+myal0ANBgBoMJoM0
         Hu1AFQEqIlBq/0dWOO443DRcDw7CTnrokX9FpXv2M66wCbtpyE7KiejP+DYb3Yw6DcBH
         V1EOv71XimnoUleVnclWtlhDprqHekAFBRhp5zlZOCwHvQP4mqZ/72wJsQWoA83bpVOB
         QypF5EOM/vnlscLMWP8UKGoczDEEnnqRlKEbQZR41jVbD4+ONy/qS24H8nG+KPvJuZLg
         /7vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TYmR3ERnVN7f7tbdXX3/1a2ExP8GMaF2HvfV3QYnAss=;
        b=mUKBmrISg6MwRLv2EO04T+vQk1blzXQKCgf4GAogb87UoFsXxU+j+lyaBLDyKS8InG
         wxeLLe8ZxogC2PXr4jjorUnLDL5KyM/1N7OM0JXeJJhg7fB6GZbarsfZgvQmTx6RHCEM
         OSCkJ/Lnh7hnt46MPgh5fo/lqMYHylxUAfcZBfA1SsCYFUUOe4/6srCOQGZwlS9HG3Ts
         sN17dY3rkJWy9zB4HhES0a7am5NCEzhldoPoDMDslnRJjMldlvmvbFrub/RJFD6GR0c5
         tt9M9E9StAzUbjs3qHBFeHvwAQJ0lq5/NkdwLNYYxcfWMiUKSOHZtfkB9CPbJEmlblxS
         qOLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TYmR3ERnVN7f7tbdXX3/1a2ExP8GMaF2HvfV3QYnAss=;
        b=H9EOEpWcAh9sYpJgWJk3HHmzA5eP/9mYF+XSqy/ONLp/K3sMbCMrb8PWXKb8ez8dIU
         CHzpu8ST0ntsqx15Z8abICR+iVC/jklMPS0KclH9fKealOTOJlL2RCeT9utaha0jkoBS
         CiXy+vwAN24yiwTR4M+eErME7bo9YhBpjwGwFyF707yB7aJVRts6nn5MtjFpDJo9EDJ4
         G0faWppSwTrm2mx7bDEre3bL4plgGMw2SJFrcNzfxXPJ9qq3yTJagNpsSyZD03u6UtcG
         VNZk8LzQZkWCbOANvPFHCuauBqSJe20hMCBbuHdqnKnK7NWznmgUprk4BG06HPAwihtb
         vK1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXWF9mWNkqDsVFGV7eAKv46yoxGVaHcxkiHyRm2lsN9hGHXSD0F
	hLi9NDXrEGUpEz2wH4vPdDA=
X-Google-Smtp-Source: APXvYqz5Kl4Y3grft6/6+VgWJd4dCL8XGEP98Gf7XbOOXv5sEAL9VfuvyddOJezw+VWVTsAAftY5CQ==
X-Received: by 2002:adf:dfc4:: with SMTP id q4mr22299705wrn.54.1565344482028;
        Fri, 09 Aug 2019 02:54:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ea50:: with SMTP id j16ls28258190wrn.9.gmail; Fri, 09
 Aug 2019 02:54:41 -0700 (PDT)
X-Received: by 2002:adf:ec8e:: with SMTP id z14mr23796860wrn.269.1565344481349;
        Fri, 09 Aug 2019 02:54:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565344481; cv=none;
        d=google.com; s=arc-20160816;
        b=ujngrVyaejm1H5t6KBAqEUtaVuBMVPgwjrEkMDq1JMNdP+8cus2pp6DaHWuNCljkBd
         3O3+LcjNb3pfels5nvqsJz4awR6+GIFmbdAmyeKCkJ45KmdGrpb40iG0uZDKIy7ai1MY
         t2V9jxBC8vqi5t7PB8inav75R40/6RmEXLRt0YUnTIyfmcyWnh9QGTJkmQYDvlv3ZKKH
         pfnPrqhoGmh7YGMvAZLQZqqYcmtf0mqMpmzZt0xiPwP9CZKk5rAtJ1zGHJh16xj/Kqwq
         ei0o0qDEbluQ7E05o5ApUCX7ni/uaiIxIs9XJH8Kfnntu6EV+ZgnYFkXQBrBnWvuEZhf
         q82w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=GwruKyw7mHs3C54oT/QuJsxh7Ksfp9svOQkHJNfLpNk=;
        b=H+TXOCd8cQLSDidXEA6LvVuu5K8OvNmnd/2Gaq2WG3hyHDXBfoMR+Rc2CgXQhINGyu
         ahY5ljk6Ty4cWe2eailllH9ZGi0EB/nyZz8RibtBeq7dO87JBwctVDTV8v/+SmtaVwFX
         Rre93d+VXWX6TepQMsIdajXo42Nx8W0NFyVkXhJ9W6+eZhoYcdnv+AWEDRHoMEEcngZU
         Gt34tTgv428pANy9nTvbyiI3y1XhQfDgm91pb7Q61+Uf0X74FHinDWKGdQGlucfmV8n2
         q8Fzz+q8DRqpBT90/a3FTRxes64JJlcpqtN5IpuqAvETAwzNH81WEVJVtHJokfCPH4rd
         MWZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id y4si1914874wrp.0.2019.08.09.02.54.40
        for <kasan-dev@googlegroups.com>;
        Fri, 09 Aug 2019 02:54:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4CFA015A2;
	Fri,  9 Aug 2019 02:54:39 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0F7113F575;
	Fri,  9 Aug 2019 02:54:37 -0700 (PDT)
Date: Fri, 9 Aug 2019 10:54:35 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org,
	aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org,
	linux-kernel@vger.kernel.org, dvyukov@google.com
Subject: Re: [PATCH v3 1/3] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20190809095435.GD48423@lakrids.cambridge.arm.com>
References: <20190731071550.31814-1-dja@axtens.net>
 <20190731071550.31814-2-dja@axtens.net>
 <20190808135037.GA47131@lakrids.cambridge.arm.com>
 <20190808174325.GD47131@lakrids.cambridge.arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190808174325.GD47131@lakrids.cambridge.arm.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Thu, Aug 08, 2019 at 06:43:25PM +0100, Mark Rutland wrote:
> On Thu, Aug 08, 2019 at 02:50:37PM +0100, Mark Rutland wrote:
> > Hi Daniel,
> > 
> > This is looking really good!
> > 
> > I spotted a few more things we need to deal with, so I've suggested some
> > (not even compile-tested) code for that below. Mostly that's just error
> > handling, and using helpers to avoid things getting too verbose.
> 
> FWIW, I had a quick go at that, and I've pushed the (corrected) results
> to my git repo, along with an initial stab at arm64 support (which is
> currently broken):
> 
> https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/log/?h=kasan/vmalloc

I've fixed my arm64 patch now, and that appears to work in basic tests
(example below), so I'll throw my arm64 Syzkaller instance at that today
to shake out anything major that we've missed or that I've botched.

I'm very excited to see this!

Are you happy to pick up my modified patch 1 for v4?

Thanks,
Mark.

# echo STACK_GUARD_PAGE_LEADING > DIRECT 
[  107.453162] lkdtm: Performing direct entry STACK_GUARD_PAGE_LEADING
[  107.454672] lkdtm: attempting bad read from page below current stack
[  107.456672] ==================================================================
[  107.457929] BUG: KASAN: vmalloc-out-of-bounds in lkdtm_STACK_GUARD_PAGE_LEADING+0x88/0xb4
[  107.459398] Read of size 1 at addr ffff20001515ffff by task sh/214
[  107.460864] 
[  107.461271] CPU: 0 PID: 214 Comm: sh Not tainted 5.3.0-rc3-00004-g84f902ca9396-dirty #7
[  107.463101] Hardware name: linux,dummy-virt (DT)
[  107.464407] Call trace:
[  107.464951]  dump_backtrace+0x0/0x1e8
[  107.465781]  show_stack+0x14/0x20
[  107.466824]  dump_stack+0xbc/0xf4
[  107.467780]  print_address_description+0x60/0x33c
[  107.469221]  __kasan_report+0x140/0x1a0
[  107.470388]  kasan_report+0xc/0x18
[  107.471439]  __asan_load1+0x4c/0x58
[  107.472428]  lkdtm_STACK_GUARD_PAGE_LEADING+0x88/0xb4
[  107.473908]  lkdtm_do_action+0x40/0x50
[  107.475255]  direct_entry+0x128/0x1b0
[  107.476348]  full_proxy_write+0x90/0xc8
[  107.477595]  __vfs_write+0x54/0xa8
[  107.478780]  vfs_write+0xd0/0x230
[  107.479762]  ksys_write+0xc4/0x170
[  107.480738]  __arm64_sys_write+0x40/0x50
[  107.481888]  el0_svc_common.constprop.0+0xc0/0x1c0
[  107.483240]  el0_svc_handler+0x34/0x88
[  107.484211]  el0_svc+0x8/0xc
[  107.484996] 
[  107.485429] 
[  107.485895] Memory state around the buggy address:
[  107.487107]  ffff20001515fe80: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
[  107.489162]  ffff20001515ff00: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
[  107.491157] >ffff20001515ff80: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
[  107.493193]                                                                 ^
[  107.494973]  ffff200015160000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[  107.497103]  ffff200015160080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[  107.498795] ==================================================================
[  107.500495] Disabling lock debugging due to kernel taint
[  107.503212] Unable to handle kernel paging request at virtual address ffff20001515ffff
[  107.505177] Mem abort info:
[  107.505797]   ESR = 0x96000007
[  107.506554]   Exception class = DABT (current EL), IL = 32 bits
[  107.508031]   SET = 0, FnV = 0
[  107.508547]   EA = 0, S1PTW = 0
[  107.509125] Data abort info:
[  107.509704]   ISV = 0, ISS = 0x00000007
[  107.510388]   CM = 0, WnR = 0
[  107.511089] swapper pgtable: 4k pages, 48-bit VAs, pgdp=0000000041c65000
[  107.513221] [ffff20001515ffff] pgd=00000000bdfff003, pud=00000000bdffe003, pmd=00000000aa31e003, pte=0000000000000000
[  107.515915] Internal error: Oops: 96000007 [#1] PREEMPT SMP
[  107.517295] Modules linked in:
[  107.518074] CPU: 0 PID: 214 Comm: sh Tainted: G    B             5.3.0-rc3-00004-g84f902ca9396-dirty #7
[  107.520755] Hardware name: linux,dummy-virt (DT)
[  107.522208] pstate: 60400005 (nZCv daif +PAN -UAO)
[  107.523670] pc : lkdtm_STACK_GUARD_PAGE_LEADING+0x88/0xb4
[  107.525176] lr : lkdtm_STACK_GUARD_PAGE_LEADING+0x88/0xb4
[  107.526809] sp : ffff200015167b90
[  107.527856] x29: ffff200015167b90 x28: ffff800002294740 
[  107.529728] x27: 0000000000000000 x26: 0000000000000000 
[  107.531523] x25: ffff200015167df0 x24: ffff2000116e8400 
[  107.533234] x23: ffff200015160000 x22: dfff200000000000 
[  107.534694] x21: ffff040002a2cf7a x20: ffff2000116e9ee0 
[  107.536238] x19: 1fffe40002a2cf7a x18: 0000000000000000 
[  107.537699] x17: 0000000000000000 x16: 0000000000000000 
[  107.539288] x15: 0000000000000000 x14: 0000000000000000 
[  107.540584] x13: 0000000000000000 x12: ffff10000d672bb9 
[  107.541920] x11: 1ffff0000d672bb8 x10: ffff10000d672bb8 
[  107.543438] x9 : 1ffff0000d672bb8 x8 : dfff200000000000 
[  107.545008] x7 : ffff10000d672bb9 x6 : ffff80006b395dc0 
[  107.546570] x5 : 0000000000000001 x4 : dfff200000000000 
[  107.547936] x3 : ffff20001113274c x2 : 0000000000000007 
[  107.549121] x1 : eb957a6c7b3ab400 x0 : 0000000000000000 
[  107.550220] Call trace:
[  107.551017]  lkdtm_STACK_GUARD_PAGE_LEADING+0x88/0xb4
[  107.552288]  lkdtm_do_action+0x40/0x50
[  107.553302]  direct_entry+0x128/0x1b0
[  107.554290]  full_proxy_write+0x90/0xc8
[  107.555332]  __vfs_write+0x54/0xa8
[  107.556278]  vfs_write+0xd0/0x230
[  107.557000]  ksys_write+0xc4/0x170
[  107.557834]  __arm64_sys_write+0x40/0x50
[  107.558980]  el0_svc_common.constprop.0+0xc0/0x1c0
[  107.560111]  el0_svc_handler+0x34/0x88
[  107.560936]  el0_svc+0x8/0xc
[  107.561580] Code: 91140280 97ded9e3 d10006e0 97e4672e (385ff2e1) 
[  107.563208] ---[ end trace 9e69aa587e1dc0cc ]---

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190809095435.GD48423%40lakrids.cambridge.arm.com.
