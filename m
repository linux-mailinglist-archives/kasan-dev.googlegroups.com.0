Return-Path: <kasan-dev+bncBCU4TIPXUUFRBHWJ2SDQMGQESMBPQIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id BE6183CCE3C
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jul 2021 09:07:11 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id gc15-20020a17090b310fb0290173c8985d0dsf10595072pjb.8
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jul 2021 00:07:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626678430; cv=pass;
        d=google.com; s=arc-20160816;
        b=BrUm7hqOwxXCPbEx0gX0EofOA5ZrFK1X/coIO6FHJYHs1O5Us7hy77fkjzMRaP7dnB
         piF7bUmvV2lVCnjWxbJ/+qzNEOGMNKa/v2q1fN+zmwG8fSu4t6ugAv052fCSY1vt2ksV
         5Y3pIaqv9+N2DFZdfJYZ/mlT/aGr00O+6F7rchGKTAZBd9K3V+icTAaDfD02m0HS6CX7
         yCa386fsPBOKo56vLSkUJ9KC+SnY6aQGgN2ubjt4Lhix7r/6JXDXW9MoSdgdZcQBv/Rs
         g6o1cdydf2fILKn/ZX3nt45SK+e37a6t2yB27E24yy3KdKDXjkrF5J05SGf50R0YINq6
         QyKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=M9ImrWCV09W1vrodPmoYKs+wv7BR1hO3rRyjj1swrPI=;
        b=OXE1DY/X/eFAMSTK862Xi6rxOBP9TEqznDCjlH+axgYxL/4nTJt5nl7sXkROjgLrKX
         Fto2SxM6F2/5kxUspaJLkMejuBPiREoaNlIxjJ7VjjXH2yWsTqLnwl3mwK7dFRfolK8n
         fEZWCwkLe9Wy7vZSjb0lh8hfhftbTS+xiELpZyukiMJkHuYYpDvCJkQH7zy5MQ6PoznS
         K5VJRY0hdRABUoECrE8qAkcSjAGX12AE7UakPDvvh2mRwdQ415uzBCGLWzXkfDOlDE4+
         JmuZehDjg4PmhqpvIgBprKAGohEK1RZvQBPoY9eF2cm7mt0Ep9bqBM8KOsrT/7eGi4Wa
         sRxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EQPj1vhw;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M9ImrWCV09W1vrodPmoYKs+wv7BR1hO3rRyjj1swrPI=;
        b=hEXvgW3fsNUcSl4YPHBK1cDXUIEPpI7q6Iqq1w39h6KD60AR55e+ezGt/AndnRvi+P
         vSAp2eq5iy6p6/zOS/mxTFG78ix41KIW5Zq0ZaiAXnLuLum/WukIPOdYaQIRzQOFL3hF
         rx6IyKJQq++ooxNps9jWZWzE17T6Uv3VdVEazLqP7Akdl2PRHBXFUkd9mDSDq2U6t3Y9
         lL0o39VjtH7OwlTUK+eSWaxI5R1xqk0/hb4GCap0p6UKWGo1rxh3CfnMMHCtAq1fEpGE
         NVxDSeoyVU+YD/oD/BoBo0LzMeDZJxf4//ZWjgY8KrJNkZqVmnT/TMvcLzk8l4zL5SgI
         NUFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M9ImrWCV09W1vrodPmoYKs+wv7BR1hO3rRyjj1swrPI=;
        b=k6Iz+TJTZnVDCb7wyindwbRVo8EYIuGNxEDDtpOMYEHJJ5Dz2bHtzeT9fWbvjqVgul
         8EE9/qYrdwf+pvTnEalM3kQWK7I/Cd5k2Jn2yHJI9WmFd27PBhfzvwJSLrlKWQI8gFQc
         qmuEXirFayBr4aerHkbAYCffaDY/dmVCIrxBFw22V0LdfyK81BW9ga9cx8FnmK2hB/pL
         CvmGqq1Ljk+eyEwyCFaIBKRafzjnIN+fqTmXcBVT/dw9R4lSBlrcBK0xmRRpNJY8puNh
         V2JBhYt/JaFNv0bsQiy8TG6wrP73/JXtu3CTOUIXm0qSU822m1fU8V1OhWwVxv61fi1F
         D6ww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531zJ412OxalyJGeFZbRN6AQWmFvTiLHMrva1SAm/ZrvcDDlLl+m
	Gn13iS53oWBFM+oja1h2FeQ=
X-Google-Smtp-Source: ABdhPJw+H2Bslyzd714HKK41WeqXBEe98QmXIK8vdl4k9Yh0R6kGP4JBITPiDCSmRBgbe3srpt5xSQ==
X-Received: by 2002:a17:90a:bd94:: with SMTP id z20mr24047923pjr.214.1626678430540;
        Mon, 19 Jul 2021 00:07:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:968c:: with SMTP id n12ls8607772plp.8.gmail; Mon, 19
 Jul 2021 00:07:10 -0700 (PDT)
X-Received: by 2002:a17:90b:1245:: with SMTP id gx5mr28478685pjb.30.1626678429933;
        Mon, 19 Jul 2021 00:07:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626678429; cv=none;
        d=google.com; s=arc-20160816;
        b=o5T584tE6FucQ4fLe9Fbc6SCu3s9GjJeZfjFeOJRp6XC477LneC8W40MZ7H9SVUAOM
         o9NKTfZqN3Bhp+Ife60cSzT41j5xW2ZYXwTGMig2yLanJTCRyclDSW3pFMwXPO+ASqxf
         wGjydtjxCiQFA6xm6a0GeHvAibPeoKALbiXSWefLzUL7mBdTdJlWll9JCWXZBIWpEome
         ExwSkRFVPoSefYYxuhff26J2bDK9tNgcOVI+Vk2yidHkTXoj2QAsLBQ0FufRPo3h/r49
         d9hm6NIUZSvoSPkWtDAF+mERhHxWZlDQZ1bJWPaLH4YajQ3EFEZ2JO3A+mirQWSLQdfL
         7rFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NcMCIOpU9uiQ2boVXtcFsPn8sAQKxMNfbWoTvfTwKY8=;
        b=byQXY+BwgH7T1Y/GNDd6VTj47U8w637nRWRIOEFs7BCqTTeq5TosFg8WOfPBRjs0+b
         BxBq0yhOnGqwNWxR4GM7fPwsT/ViV1Psv5/6OFYiKGE5AAo9RmsszFPz6kMeTnphTXqQ
         6ZyLRrxEhqXB0FCvo5Gr22YXw6stx5dMdyeuLaiiQ78we6+s5BdHoFQnu6oIIxcvfRAy
         qdHJbyR7TF1lQblPCbWZsBnx+l6NWbRUK5uAQm7UA99fCn8Hbqs1TDJju0fVv+VGCOBq
         wZdOZGgHUJIniSYb891HkKHB0RKOD3lT9h2CqH/vbGfhUR4Brs8Eu+FjpHz7yDCmBVqs
         MtYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EQPj1vhw;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c9si2386617pfr.5.2021.07.19.00.07.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Jul 2021 00:07:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id A03C1611C2
	for <kasan-dev@googlegroups.com>; Mon, 19 Jul 2021 07:07:09 +0000 (UTC)
Received: by mail-ot1-f42.google.com with SMTP id i12-20020a05683033ecb02903346fa0f74dso17230817otu.10
        for <kasan-dev@googlegroups.com>; Mon, 19 Jul 2021 00:07:09 -0700 (PDT)
X-Received: by 2002:a05:6830:2316:: with SMTP id u22mr17824199ote.90.1626678428946;
 Mon, 19 Jul 2021 00:07:08 -0700 (PDT)
MIME-Version: 1.0
References: <CAMj1kXGNKhkwAuEYe1d6L6w7D0OxjgGsiR0i+ZoyZjMVmnjxDA@mail.gmail.com>
 <20210719030932.23384-1-huangshaobo6@huawei.com>
In-Reply-To: <20210719030932.23384-1-huangshaobo6@huawei.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Mon, 19 Jul 2021 09:06:57 +0200
X-Gmail-Original-Message-ID: <CAMj1kXFELSiLXzgJVChstUiDShON+LGZpMUpg1WJoZ0EmZ5pfw@mail.gmail.com>
Message-ID: <CAMj1kXFELSiLXzgJVChstUiDShON+LGZpMUpg1WJoZ0EmZ5pfw@mail.gmail.com>
Subject: Re: [PATCH] ARM: fix panic when kasan and kprobe are enabled
To: Shaobo Huang <huangshaobo6@huawei.com>
Cc: andreyknvl@gmail.com, chenzefeng2@huawei.com, 
	Dmitry Vyukov <dvyukov@google.com>, Florian Fainelli <f.fainelli@gmail.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	kepler.chenxin@huawei.com, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Russell King <linux@armlinux.org.uk>, 
	liucheng32@huawei.com, Abbott Liu <liuwenliang@huawei.com>, nico@marvell.com, 
	Xiaoming Ni <nixiaoming@huawei.com>, qbarnes@gmail.com, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, sagar.abhishek@gmail.com, wuquanming@huawei.com, 
	xiaoqian9@huawei.com, young.liuyang@huawei.com, zengweilin@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=EQPj1vhw;       spf=pass
 (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Mon, 19 Jul 2021 at 05:09, Shaobo Huang <huangshaobo6@huawei.com> wrote:
>
> On Sat, 17 Jul 2021 at 01:01, Ard Biesheuvel <ardb@kernel.org> wrote:
> > On Wed, 14 Jul 2021 at 10:27, Shaobo Huang <huangshaobo6@huawei.com> wrote:
> >>
> >> From: huangshaobo <huangshaobo6@huawei.com>
> >>
> >> arm32 uses software to simulate the instruction replaced
> >> by kprobe. some instructions may be simulated by constructing
> >> assembly functions. therefore, before executing instruction
> >> simulation, it is necessary to construct assembly function
> >> execution environment in C language through binding registers.
> >> after kasan is enabled, the register binding relationship will
> >> be destroyed, resulting in instruction simulation errors and
> >> causing kernel panic.
> >>
> >> the kprobe emulate instruction function is distributed in three
> >> files: actions-common.c actions-arm.c actions-thumb.c, so disable
> >> KASAN when compiling these files.
> >>
> >> for example, use kprobe insert on cap_capable+20 after kasan
> >> enabled, the cap_capable assembly code is as follows:
> >> <cap_capable>:
> >> e92d47f0        push    {r4, r5, r6, r7, r8, r9, sl, lr}
> >> e1a05000        mov     r5, r0
> >> e280006c        add     r0, r0, #108    ; 0x6c
> >> e1a04001        mov     r4, r1
> >> e1a06002        mov     r6, r2
> >> e59fa090        ldr     sl, [pc, #144]  ;
> >> ebfc7bf8        bl      c03aa4b4 <__asan_load4>
> >> e595706c        ldr     r7, [r5, #108]  ; 0x6c
> >> e2859014        add     r9, r5, #20
> >> ......
> >> The emulate_ldr assembly code after enabling kasan is as follows:
> >> c06f1384 <emulate_ldr>:
> >> e92d47f0        push    {r4, r5, r6, r7, r8, r9, sl, lr}
> >> e282803c        add     r8, r2, #60     ; 0x3c
> >> e1a05000        mov     r5, r0
> >> e7e37855        ubfx    r7, r5, #16, #4
> >> e1a00008        mov     r0, r8
> >> e1a09001        mov     r9, r1
> >> e1a04002        mov     r4, r2
> >> ebf35462        bl      c03c6530 <__asan_load4>
> >> e357000f        cmp     r7, #15
> >> e7e36655        ubfx    r6, r5, #12, #4
> >> e205a00f        and     sl, r5, #15
> >> 0a000001        beq     c06f13bc <emulate_ldr+0x38>
> >> e0840107        add     r0, r4, r7, lsl #2
> >> ebf3545c        bl      c03c6530 <__asan_load4>
> >> e084010a        add     r0, r4, sl, lsl #2
> >> ebf3545a        bl      c03c6530 <__asan_load4>
> >> e2890010        add     r0, r9, #16
> >> ebf35458        bl      c03c6530 <__asan_load4>
> >> e5990010        ldr     r0, [r9, #16]
> >> e12fff30        blx     r0
> >> e356000f        cm      r6, #15
> >> 1a000014        bne     c06f1430 <emulate_ldr+0xac>
> >> e1a06000        mov     r6, r0
> >> e2840040        add     r0, r4, #64     ; 0x40
> >> ......
> >>
> >> when running in emulate_ldr to simulate the ldr instruction, panic
> >> occurred, and the log is as follows:
> >> Unable to handle kernel NULL pointer dereference at virtual address
> >> 00000090
> >> pgd = ecb46400
> >> [00000090] *pgd=2e0fa003, *pmd=00000000
> >> Internal error: Oops: 206 [#1] SMP ARM
> >> PC is at cap_capable+0x14/0xb0
> >> LR is at emulate_ldr+0x50/0xc0
> >> psr: 600d0293 sp : ecd63af8  ip : 00000004  fp : c0a7c30c
> >> r10: 00000000  r9 : c30897f4  r8 : ecd63cd4
> >> r7 : 0000000f  r6 : 0000000a  r5 : e59fa090  r4 : ecd63c98
> >> r3 : c06ae294  r2 : 00000000  r1 : b7611300  r0 : bf4ec008
> >> Flags: nZCv  IRQs off  FIQs on  Mode SVC_32  ISA ARM  Segment user
> >> Control: 32c5387d  Table: 2d546400  DAC: 55555555
> >> Process bash (pid: 1643, stack limit = 0xecd60190)
> >> (cap_capable) from (kprobe_handler+0x218/0x340)
> >> (kprobe_handler) from (kprobe_trap_handler+0x24/0x48)
> >> (kprobe_trap_handler) from (do_undefinstr+0x13c/0x364)
> >> (do_undefinstr) from (__und_svc_finish+0x0/0x30)
> >> (__und_svc_finish) from (cap_capable+0x18/0xb0)
> >> (cap_capable) from (cap_vm_enough_memory+0x38/0x48)
> >> (cap_vm_enough_memory) from
> >> (security_vm_enough_memory_mm+0x48/0x6c)
> >> (security_vm_enough_memory_mm) from
> >> (copy_process.constprop.5+0x16b4/0x25c8)
> >> (copy_process.constprop.5) from (_do_fork+0xe8/0x55c)
> >> (_do_fork) from (SyS_clone+0x1c/0x24)
> >> (SyS_clone) from (__sys_trace_return+0x0/0x10)
> >> Code: 0050a0e1 6c0080e2 0140a0e1 0260a0e1 (f801f0e7)
> >>
> >> Fixes: 35aa1df43283 ("ARM kprobes: instruction single-stepping support")
> >> Fixes: 421015713b30 ("ARM: 9017/2: Enable KASan for ARM")
> >> Signed-off-by: huangshaobo <huangshaobo6@huawei.com>
> >> Asked-by: Ard Biesheuvel <ardb@kernel.org>
> >
> > Please don't do this - the maintainer will pick it up when applying,
> > or when you send a new version of the patch, it is OK to add these
> > tags if you have not made any substantial changes.
> >
> > But please do *not* add tags like this on someone else's behalf by
> > replying to the email - and I should also point out that 'asked-by' is
> > bogus.
> >
>
> Hi ardb,
> 1.The original patch you have been asked-by by email before, link: https://lore.kernel.org/linux-arm-kernel/CAMj1kXGqfF68MT4WwrxS0cYiUBb0gODDh-wGZSQcW9vxdfK90A@mail.gmail.com/

No it was not.

It was ACKed by, not ASKed by.

> 2.In addition to adding the asked-by tag, there is no other content modification in this patch
> 3.The patch was reissued because the previous recipient did not include kasan maintainer and reviewers
>

I don't care. Do NOT reply to emails with tags in other people's names.


> thanks,
> ShaoBo Huang
>
> >
> >> ---
> >>  arch/arm/probes/kprobes/Makefile | 3 +++
> >>  1 file changed, 3 insertions(+)
> >>
> >> diff --git a/arch/arm/probes/kprobes/Makefile b/arch/arm/probes/kprobes/Makefile
> >> index 14db56f49f0a..6159010dac4a 100644
> >> --- a/arch/arm/probes/kprobes/Makefile
> >> +++ b/arch/arm/probes/kprobes/Makefile
> >> @@ -1,4 +1,7 @@
> >>  # SPDX-License-Identifier: GPL-2.0
> >> +KASAN_SANITIZE_actions-common.o := n
> >> +KASAN_SANITIZE_actions-arm.o := n
> >> +KASAN_SANITIZE_actions-thumb.o := n
> >>  obj-$(CONFIG_KPROBES)          += core.o actions-common.o checkers-common.o
> >>  obj-$(CONFIG_ARM_KPROBES_TEST) += test-kprobes.o
> >>  test-kprobes-objs              := test-core.o
> >> --
> >> 2.12.3
> >>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXFELSiLXzgJVChstUiDShON%2BLGZpMUpg1WJoZ0EmZ5pfw%40mail.gmail.com.
