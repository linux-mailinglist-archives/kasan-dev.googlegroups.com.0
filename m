Return-Path: <kasan-dev+bncBCU4TIPXUUFRB7G52SDQMGQEOVI5FYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 23C0C3CCED9
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jul 2021 09:51:26 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id z1-20020a4ab8810000b029024abe096a35sf11877561ooo.12
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jul 2021 00:51:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626681085; cv=pass;
        d=google.com; s=arc-20160816;
        b=cWuy/Np+SQXPKw+8zawLf0vKylj/JKdhOKwI6+oX588sVHXsAFk6GmmcS9QNDFT9oT
         s1SPjZli2MPeD/Oqgkp1vM3HQPZxtQg/LovUlrnLWKRgwMvY10k9vsSaSULMjbQ+6Vw4
         nQYm1VOhb4lGyaE7iHjBorbc53c34QuukBm/R/C9dRX2KVGYPqmI//P6RcSH2DBIuZMR
         4+PBuj5qHzHR/86XDLejyEiQmE3OlGE/qzO+QMR9cIE0kDiWvc4Rb8W7Y/79DYTlEzAs
         +UfoG6KgHkpCOx7zFsOXpgwmAnZSfiRDysx6F3SQvPR3oVBPmvhn54EPou37ogjbB81L
         B9ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=/y5mWRoxLp+ugtSFQeyB5zu8Zxm2LUOpE6p3/CVIce8=;
        b=TWhaE+FE2v/o0KC1fA1CYDaCHr4oqNcPyx+j/Ps3S/Yv0i15IzbiYtQnbrANUyw9Gm
         j1WKP3UkEAchyeBwsmm/sSmYZSrn5Kc1zqq3/IrGINH9YIs37PGdJ/tdrQ++NQWkQZGe
         35wrkEevrDngPzmV5SKGKR4huWPnNyva45fKgJ5oYwAH+ZDNFaGJnLs7vp1IBWlbbNFH
         AdxNR3i8Cc5+WLiG0GfL6VfgGNfuhyAQNk3sd9GxUOkbpdyIPJkmikixb84AXxK7Hkbd
         PsmLHyBKxpz1ZiZhcs1sqL+N1/bpJI3NIkFE3uTbo0UDZneJJ1bRBQogg1MrYu1X4QH5
         e70Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PB6wL322;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/y5mWRoxLp+ugtSFQeyB5zu8Zxm2LUOpE6p3/CVIce8=;
        b=imFmlaEQ5apoImu+taQAz6foolCcO6tTghrUw2CdXruSXqDTmph4PdNoF8porh8E/h
         O3rBt0TQjCb1WhZ74tl3u8RdQtxXsc8a528/KpOpH8ql+IRMi+7f5VrluASMEuL8DFCe
         2tl+FZ+KAXftRmHwDENN7om8FCQJyoeYQMhxM74SDpADbJFSedyCykjewOVL0OWX8Hx/
         489Ce9lqdpsPK+rYq6BWz37LksxoLz+SZf9OvgDhTgQa7+twrYmQIDEwlljVJX1VefnX
         elxeNOkJdFMTErzyS6ESQPsp2vb3qHvOwFUGdVdX3JgGlZ64D0ZdP3dPoBmcAeLoYk28
         xKsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/y5mWRoxLp+ugtSFQeyB5zu8Zxm2LUOpE6p3/CVIce8=;
        b=CKE0VtvlYeK9x+pSLjpjpi8XgLUw6Y8YLPGteGpH0fuoZ1Ve4r4Q/zNUlN/RY/C7Tr
         MeHp3QRCqGh/h2Qj7gC1HqTNI9cpqAB4n0YzY7TtBttaw+ETzMmiu8ORIBB0ce5r9sgX
         X0JYAsJn2RTWJ17UVsJEAjKcCDQNB2mcX0MYG+6VhmQOXqGwyRwW6I4OLufPtT1YdkC9
         +Lj6O1O6ewEI4Vr4xgF8GvRbNV1s7PQvBkjltxGSCqDwO+b+m4uJTmzSKTwm5kZVB4Si
         gvg7aaM8yg6pneJF6rnz+Xi3cptoIdmZ5n275KsifFw/RyA936Gme8RmWw/0WGPDMEhM
         EH5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+y4ZrHngUkbV96K+EZQFrFsIm76V+awS0skT04vLOLulYGXOh
	G8HtSRrkFpj5lJ9nFk0489g=
X-Google-Smtp-Source: ABdhPJzRiiYlujMRHYb2AW/xOd5M2McPMQHMTl1Oy1T1j1FDREBbCy31Gmugj+rg+QJaIcwzxrmqdg==
X-Received: by 2002:a9d:3b0:: with SMTP id f45mr18602583otf.5.1626681084892;
        Mon, 19 Jul 2021 00:51:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:49ce:: with SMTP id w197ls3885482oia.8.gmail; Mon, 19
 Jul 2021 00:51:24 -0700 (PDT)
X-Received: by 2002:a05:6808:59:: with SMTP id v25mr16873528oic.98.1626681084425;
        Mon, 19 Jul 2021 00:51:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626681084; cv=none;
        d=google.com; s=arc-20160816;
        b=IEJI6qaDWQHYcRCY5PmTvBrE+nutJqSsPVayqKhatDV5eF+wmh9L5/ivlfGuZYBgZp
         EQujn6EgpT3Nu5LrMb6kFiJi2ll22W5iGy3ugI1Tcap6Na2j5zthV2MkZj6CEl+GPKsm
         FLCRbnLHtZwNVuivI6i+u6SlR+Exn9rY/YeX6fQRcL7T4qfpxB/tSAQy7IAbWBy/lCh/
         We/OFVqEAYgVUrJAqswL65gdCpSYu6XrWSFz+dltV88lgp841oX/3SEY6vw21ciiZrQk
         +X5yKeZCvfQMiNBbcKUrOUScHCIrKRa+hgDJg19ry1d5JnycBCQOer1P50r/jHeFC5oy
         JHhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bzkllqXuelHAoXk+1V/Igf3HjFIAIu3gTMpuwj7ghYw=;
        b=kl5DOXGLz0TJbDjbWGsjdocNrz/znGt2oEWQ/aqAq5u647R7Hgq0QMDg04BZOxc1wi
         ZVw8DaHLKlmyTmA1/mZbEeCW5Nr7zeN51WyoR1bH/g5H/q5fs+q5b5xGIc5P93cbHLJ9
         b7Hfow9J8t/1wvONWdRIyG7av3BS6sGEQrm49Ukpg0AUBscVzugQjhAXBD/tnWwsi+6M
         ywdF3Fz9ZOTRWuMZrzcYRS/YXd252fqjVTmnsN2WhdDp7NLa32ohqAIwWyA+LJFZEaoQ
         PmZdYYGJ8K3NCUFK6v6wdX96EVcPu0pQAVv1x29iuH2LA0JfObvFUkHt5apAksaHWs8b
         oSvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PB6wL322;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h21si2088741oof.2.2021.07.19.00.51.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Jul 2021 00:51:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id A20E56024A
	for <kasan-dev@googlegroups.com>; Mon, 19 Jul 2021 07:51:23 +0000 (UTC)
Received: by mail-ot1-f52.google.com with SMTP id s2-20020a0568301e02b02904ce2c1a843eso6850153otr.13
        for <kasan-dev@googlegroups.com>; Mon, 19 Jul 2021 00:51:23 -0700 (PDT)
X-Received: by 2002:a05:6830:2316:: with SMTP id u22mr17921826ote.90.1626681083016;
 Mon, 19 Jul 2021 00:51:23 -0700 (PDT)
MIME-Version: 1.0
References: <CAMj1kXFELSiLXzgJVChstUiDShON+LGZpMUpg1WJoZ0EmZ5pfw@mail.gmail.com>
 <20210719074538.9112-1-huangshaobo6@huawei.com>
In-Reply-To: <20210719074538.9112-1-huangshaobo6@huawei.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Mon, 19 Jul 2021 09:51:11 +0200
X-Gmail-Original-Message-ID: <CAMj1kXEBbjOOaAjq8SwSM=mxZWyFJ_VwhXF62TfF1T-tA=_2CQ@mail.gmail.com>
Message-ID: <CAMj1kXEBbjOOaAjq8SwSM=mxZWyFJ_VwhXF62TfF1T-tA=_2CQ@mail.gmail.com>
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
 header.i=@kernel.org header.s=k20201202 header.b=PB6wL322;       spf=pass
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

On Mon, 19 Jul 2021 at 09:45, Shaobo Huang <huangshaobo6@huawei.com> wrote:
>
> On Mon, 19 Jul 2021 at 07:06, Ard Biesheuvel <ardb@kernel.org> wrote:
> > On Mon, 19 Jul 2021 at 05:09, Shaobo Huang <huangshaobo6@huawei.com> wrote:
> > >
> > > On Sat, 17 Jul 2021 at 01:01, Ard Biesheuvel <ardb@kernel.org> wrote:
> > > > On Wed, 14 Jul 2021 at 10:27, Shaobo Huang <huangshaobo6@huawei.com> wrote:
> > > >>
> > > >> From: huangshaobo <huangshaobo6@huawei.com>
> > > >>
> > > >> arm32 uses software to simulate the instruction replaced
> > > >> by kprobe. some instructions may be simulated by constructing
> > > >> assembly functions. therefore, before executing instruction
> > > >> simulation, it is necessary to construct assembly function
> > > >> execution environment in C language through binding registers.
> > > >> after kasan is enabled, the register binding relationship will
> > > >> be destroyed, resulting in instruction simulation errors and
> > > >> causing kernel panic.
> > > >>
> > > >> the kprobe emulate instruction function is distributed in three
> > > >> files: actions-common.c actions-arm.c actions-thumb.c, so disable
> > > >> KASAN when compiling these files.
> > > >>
> > > >> for example, use kprobe insert on cap_capable+20 after kasan
> > > >> enabled, the cap_capable assembly code is as follows:
> > > >> <cap_capable>:
> > > >> e92d47f0        push    {r4, r5, r6, r7, r8, r9, sl, lr}
> > > >> e1a05000        mov     r5, r0
> > > >> e280006c        add     r0, r0, #108    ; 0x6c
> > > >> e1a04001        mov     r4, r1
> > > >> e1a06002        mov     r6, r2
> > > >> e59fa090        ldr     sl, [pc, #144]  ;
> > > >> ebfc7bf8        bl      c03aa4b4 <__asan_load4>
> > > >> e595706c        ldr     r7, [r5, #108]  ; 0x6c
> > > >> e2859014        add     r9, r5, #20
> > > >> ......
> > > >> The emulate_ldr assembly code after enabling kasan is as follows:
> > > >> c06f1384 <emulate_ldr>:
> > > >> e92d47f0        push    {r4, r5, r6, r7, r8, r9, sl, lr}
> > > >> e282803c        add     r8, r2, #60     ; 0x3c
> > > >> e1a05000        mov     r5, r0
> > > >> e7e37855        ubfx    r7, r5, #16, #4
> > > >> e1a00008        mov     r0, r8
> > > >> e1a09001        mov     r9, r1
> > > >> e1a04002        mov     r4, r2
> > > >> ebf35462        bl      c03c6530 <__asan_load4>
> > > >> e357000f        cmp     r7, #15
> > > >> e7e36655        ubfx    r6, r5, #12, #4
> > > >> e205a00f        and     sl, r5, #15
> > > >> 0a000001        beq     c06f13bc <emulate_ldr+0x38>
> > > >> e0840107        add     r0, r4, r7, lsl #2
> > > >> ebf3545c        bl      c03c6530 <__asan_load4>
> > > >> e084010a        add     r0, r4, sl, lsl #2
> > > >> ebf3545a        bl      c03c6530 <__asan_load4>
> > > >> e2890010        add     r0, r9, #16
> > > >> ebf35458        bl      c03c6530 <__asan_load4>
> > > >> e5990010        ldr     r0, [r9, #16]
> > > >> e12fff30        blx     r0
> > > >> e356000f        cm      r6, #15
> > > >> 1a000014        bne     c06f1430 <emulate_ldr+0xac>
> > > >> e1a06000        mov     r6, r0
> > > >> e2840040        add     r0, r4, #64     ; 0x40
> > > >> ......
> > > >>
> > > >> when running in emulate_ldr to simulate the ldr instruction, panic
> > > >> occurred, and the log is as follows:
> > > >> Unable to handle kernel NULL pointer dereference at virtual address
> > > >> 00000090
> > > >> pgd = ecb46400
> > > >> [00000090] *pgd=2e0fa003, *pmd=00000000
> > > >> Internal error: Oops: 206 [#1] SMP ARM
> > > >> PC is at cap_capable+0x14/0xb0
> > > >> LR is at emulate_ldr+0x50/0xc0
> > > >> psr: 600d0293 sp : ecd63af8  ip : 00000004  fp : c0a7c30c
> > > >> r10: 00000000  r9 : c30897f4  r8 : ecd63cd4
> > > >> r7 : 0000000f  r6 : 0000000a  r5 : e59fa090  r4 : ecd63c98
> > > >> r3 : c06ae294  r2 : 00000000  r1 : b7611300  r0 : bf4ec008
> > > >> Flags: nZCv  IRQs off  FIQs on  Mode SVC_32  ISA ARM  Segment user
> > > >> Control: 32c5387d  Table: 2d546400  DAC: 55555555
> > > >> Process bash (pid: 1643, stack limit = 0xecd60190)
> > > >> (cap_capable) from (kprobe_handler+0x218/0x340)
> > > >> (kprobe_handler) from (kprobe_trap_handler+0x24/0x48)
> > > >> (kprobe_trap_handler) from (do_undefinstr+0x13c/0x364)
> > > >> (do_undefinstr) from (__und_svc_finish+0x0/0x30)
> > > >> (__und_svc_finish) from (cap_capable+0x18/0xb0)
> > > >> (cap_capable) from (cap_vm_enough_memory+0x38/0x48)
> > > >> (cap_vm_enough_memory) from
> > > >> (security_vm_enough_memory_mm+0x48/0x6c)
> > > >> (security_vm_enough_memory_mm) from
> > > >> (copy_process.constprop.5+0x16b4/0x25c8)
> > > >> (copy_process.constprop.5) from (_do_fork+0xe8/0x55c)
> > > >> (_do_fork) from (SyS_clone+0x1c/0x24)
> > > >> (SyS_clone) from (__sys_trace_return+0x0/0x10)
> > > >> Code: 0050a0e1 6c0080e2 0140a0e1 0260a0e1 (f801f0e7)
> > > >>
> > > >> Fixes: 35aa1df43283 ("ARM kprobes: instruction single-stepping support")
> > > >> Fixes: 421015713b30 ("ARM: 9017/2: Enable KASan for ARM")
> > > >> Signed-off-by: huangshaobo <huangshaobo6@huawei.com>
> > > >> Asked-by: Ard Biesheuvel <ardb@kernel.org>
> > > >
> > > > Please don't do this - the maintainer will pick it up when applying,
> > > > or when you send a new version of the patch, it is OK to add these
> > > > tags if you have not made any substantial changes.
> > > >
> > > > But please do *not* add tags like this on someone else's behalf by
> > > > replying to the email - and I should also point out that 'asked-by' is
> > > > bogus.
> > > >
> > >
> > > Hi ardb,
> > > 1.The original patch you have been asked-by by email before, link: https://lore.kernel.org/linux-arm-kernel/CAMj1kXGqfF68MT4WwrxS0cYiUBb0gODDh-wGZSQcW9vxdfK90A@mail.gmail.com/
> >
> > No it was not.
> >
> > It was ACKed by, not ASKed by.
> >
> > > 2.In addition to adding the asked-by tag, there is no other content modification in this patch
> > > 3.The patch was reissued because the previous recipient did not include kasan maintainer and reviewers
> > >
> >
> > I don't care. Do NOT reply to emails with tags in other people's names.
> >
> Hi ardb,
> Sincerely apologize for my mistake,
> I mistakenly wrote the Acked-by label as Asked-by.
> Do I need to change to Acked-by or remove the label and reissue a patch?
>

You can put this patch into rmk's patch tracker at armlinux.org.uk. In
this case, it is ok to include the tags that were given in reply, ie.,
my acked-by

-- 
Ard.


> >
> > > thanks,
> > > ShaoBo Huang
> > >
> > > >
> > > >> ---
> > > >>  arch/arm/probes/kprobes/Makefile | 3 +++
> > > >>  1 file changed, 3 insertions(+)
> > > >>
> > > >> diff --git a/arch/arm/probes/kprobes/Makefile b/arch/arm/probes/kprobes/Makefile
> > > >> index 14db56f49f0a..6159010dac4a 100644
> > > >> --- a/arch/arm/probes/kprobes/Makefile
> > > >> +++ b/arch/arm/probes/kprobes/Makefile
> > > >> @@ -1,4 +1,7 @@
> > > >>  # SPDX-License-Identifier: GPL-2.0
> > > >> +KASAN_SANITIZE_actions-common.o := n
> > > >> +KASAN_SANITIZE_actions-arm.o := n
> > > >> +KASAN_SANITIZE_actions-thumb.o := n
> > > >>  obj-$(CONFIG_KPROBES)          += core.o actions-common.o checkers-common.o
> > > >>  obj-$(CONFIG_ARM_KPROBES_TEST) += test-kprobes.o
> > > >>  test-kprobes-objs              := test-core.o
> > > >> --
> > > >> 2.12.3
> > > >>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXEBbjOOaAjq8SwSM%3DmxZWyFJ_VwhXF62TfF1T-tA%3D_2CQ%40mail.gmail.com.
