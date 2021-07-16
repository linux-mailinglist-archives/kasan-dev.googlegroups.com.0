Return-Path: <kasan-dev+bncBCU4TIPXUUFRB3XWY2DQMGQEZFCR7KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 366D33CBADF
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 19:01:36 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id y1-20020a655b410000b02902235977d00csf7418965pgr.21
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 10:01:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626454894; cv=pass;
        d=google.com; s=arc-20160816;
        b=LNB6JFUvqS3HYmuHyUO7RUlf8KjS22AjD/JiG98UQQ53nJzn7E3X4Sgi4X+8ZdLqvm
         QZrvDQRxKU64aN8bVJyxt6pygfYDcQNqx5KUn1TT49pYr4wjV2kjSzVhfHpm+Gg3wodo
         mA6YF04r1GicB/ThakAHLQjpmSQdniMx1F/d4BDt8pm4GCMSi3P8S188hDNKj+MjeOkA
         hsQznSzIo1NQfjvgMlvFwdLiuOL5jCsSyDEnTf/oCIu7livFkRKhIw6vEFL/rfhDInPL
         A1V/fvFJ4dIyxaOHk4y2AzyJ09XQqNaWOyKy4yFw//BQkLD4t4Lm5g4jIKmlWK9nrAwT
         5PLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=qOZ4sIqQvsLzUA6CLx5cqxqNDCcg53bGhVAPnWIwRPc=;
        b=cCPvLOjfFoLaVqbgQ7scdLzqf5cXAYKv+z0SvRiU8ki8CyQyxcbnPqErDGXFEil9oC
         7kNMi4+RVxWMGOYHJARRG4ixE89mhdyo37ASAwfnFFSp4sSKXgOpyvDD3l+FPvN6otLS
         yZa6s1YQfOAlPliV5EksG5cbDeYqKJbD8KmkJhTrN/IhF6azXPFJXOSq9aqFmKkhmuVa
         lcd8EnREb3p0HZSHrTsvT1vSlXJ/MKkznICg3sdfpuJm3g4Esr786/wUwpuoKjGw60bt
         W3fsTxvQzKrX8N/mwZcZhSnn/3ebU48ipMwQle1hzlWmGuPoki+rsEFleRKnY7mAhjvY
         4TmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eZPOkDRl;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qOZ4sIqQvsLzUA6CLx5cqxqNDCcg53bGhVAPnWIwRPc=;
        b=YHNrzsPyMEHxHUAAGYdsFYFUd+MSatvqvf0Y2jV6T7f0EehhlHhgOz+WrwvhyNq0b1
         VT0nl1ettDXVrw3cVTHIdEiuCKH+MCzaecDo6+DdMYiQn2jY5sMShpSxAInRvadBy7T3
         kkZeeyEMalmHt1VMctfVYTlV9KxGSKsVjXLINvFCXCVwUcFZt6Wm8wdJa92e5Jt8wT39
         YczFNQ73Ny+X5yVgOVbBhtHlyJurTjJgP+c0X71LNfMbVrYisNCDXucewfkgbwbzLpVR
         CqYwr/AtYc+cTp4LeGaQQra356EmcvD2G9QMmeBrOlqhF3Ln5DdCgXZSe9KMa5eARoUV
         WIYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qOZ4sIqQvsLzUA6CLx5cqxqNDCcg53bGhVAPnWIwRPc=;
        b=LNAIxDh9wl1Xs8021N8zIqkHT2Sr6iVdttgzURcOAaSni7Q1VR+8cz5k+BkwhiGBmW
         Agch5yatS7lWvivaAOsN3e/DRPJwuQXuvjEvp06ow301xZM1ZHAa+hziG6lgFMqTNxTp
         +4xWML7/xFF3jZ2c8ayLV6sInOlGpaZ3M5dCM0ywIEZW6Y7rQSXdDjdDTaw1hiUHL8U+
         M1wOJT0puyaRGCoPMo0cF3F+8bbbWTT3Ry+b+e/S0lnm7vmcubvLMIyTykbNsNsCQj7w
         DyzeZmWR/rt17b/B782YvoiiTLMM1VrY1MLgVyenNcPG833xFwa0zdG8TKpRJgZvuwk6
         s4kg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5302ovOCnZyv8MDPARy9UNgTofjuunbMT/GZM9yRS9EIWRkIVjO7
	evT0lSjTyzl8wOVamDLInwI=
X-Google-Smtp-Source: ABdhPJx79sH8WE2n7Ldy8b4iVFlYHbsMII4a6f8PGHw6ylpiQdUHN4BBGRcmvtkIUx6CF0zdD7BsFA==
X-Received: by 2002:a05:6a00:7d7:b029:32c:b12a:d65d with SMTP id n23-20020a056a0007d7b029032cb12ad65dmr11283551pfu.44.1626454894751;
        Fri, 16 Jul 2021 10:01:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9c9:: with SMTP id 67ls5534201pjo.3.gmail; Fri, 16
 Jul 2021 10:01:34 -0700 (PDT)
X-Received: by 2002:a17:902:e882:b029:12b:1a47:1687 with SMTP id w2-20020a170902e882b029012b1a471687mr8704138plg.2.1626454894026;
        Fri, 16 Jul 2021 10:01:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626454894; cv=none;
        d=google.com; s=arc-20160816;
        b=yZEk5jY5Bg4NNC23swpECaUdhvArJov0ngHsaZkiRcL5UGYtXA1CqvmzDbPGCuqWo1
         Ba1MqXhIyboGsTujksLhQXeEaKYnIa6f3yVFJAnvaaOo9ONHIiG1glUw6Za4Y2cR/MXs
         Vt8/S4UvMgIrhZPyRh56mxbnOJZVKQi2mkLKNvuQyyYQrDavWSCkRUZ3RZs8m20u/bH7
         1ZO5LYTUTZIIDQoVQ4E+59g80YS2EOEjis4JPd/pb9B6m5TZoIpJs+3+okNFLcCUXk/n
         1VPszgIMtaulpZktqRNf+lN1BCmEsDSSZKTZoCEQ6gJEpkfq+Vp/kDgIMNmc1NcgTNFP
         sgeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=f/mrsYzX80btdD1BXA2xrIhCEhflZnZE66tDYLreXaw=;
        b=dfn+j2oC8aBt41ihZqD7+gxPZfCsmFk9569t+uYhQZxq0nXj3cCb91n3yM/fIjIr6O
         jQSzq0F1nZJTkkUp1AOaUzinjxFxSfabPYCPwJW5dbi97rh75ILKup9ExuLZrJ/jaYcI
         QwJtMbJnQi5KaPxLugJ4jr0HIZX7Ef+eWzj6QUjcQ47RdPrX+7+Uw7rJ8XpBq9P5M0Ni
         Sgfai7oRk7TYT0F6kQfuDED3cAaDD86kW8fLsrYUPTy/FjhiDi2d1EqyjfRbVND+0jul
         lzAm6CAROFKN1doOtIk9ACGjn0hioOl8oLAxLnQxtXvBF+VDrWpCbJfICo/p/8i3Dk57
         /pPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eZPOkDRl;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x20si977910pfh.1.2021.07.16.10.01.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 16 Jul 2021 10:01:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id BF391613FB
	for <kasan-dev@googlegroups.com>; Fri, 16 Jul 2021 17:01:33 +0000 (UTC)
Received: by mail-oi1-f174.google.com with SMTP id c197so11582928oib.11
        for <kasan-dev@googlegroups.com>; Fri, 16 Jul 2021 10:01:33 -0700 (PDT)
X-Received: by 2002:aca:5a04:: with SMTP id o4mr8579751oib.33.1626454893040;
 Fri, 16 Jul 2021 10:01:33 -0700 (PDT)
MIME-Version: 1.0
References: <20210708041409.34168-1-huangshaobo6@huawei.com> <20210714082738.2668-1-huangshaobo6@huawei.com>
In-Reply-To: <20210714082738.2668-1-huangshaobo6@huawei.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Fri, 16 Jul 2021 19:01:18 +0200
X-Gmail-Original-Message-ID: <CAMj1kXGNKhkwAuEYe1d6L6w7D0OxjgGsiR0i+ZoyZjMVmnjxDA@mail.gmail.com>
Message-ID: <CAMj1kXGNKhkwAuEYe1d6L6w7D0OxjgGsiR0i+ZoyZjMVmnjxDA@mail.gmail.com>
Subject: Re: [PATCH] ARM: fix panic when kasan and kprobe are enabled
To: Shaobo Huang <huangshaobo6@huawei.com>
Cc: Florian Fainelli <f.fainelli@gmail.com>, nico@marvell.com, qbarnes@gmail.com, 
	sagar.abhishek@gmail.com, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, andreyknvl@gmail.com, 
	Dmitry Vyukov <dvyukov@google.com>, Russell King <linux@armlinux.org.uk>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, wuquanming@huawei.com, 
	young.liuyang@huawei.com, zengweilin@huawei.com, chenzefeng2@huawei.com, 
	kepler.chenxin@huawei.com, liucheng32@huawei.com, 
	Abbott Liu <liuwenliang@huawei.com>, Xiaoming Ni <nixiaoming@huawei.com>, xiaoqian9@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eZPOkDRl;       spf=pass
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

On Wed, 14 Jul 2021 at 10:27, Shaobo Huang <huangshaobo6@huawei.com> wrote:
>
> From: huangshaobo <huangshaobo6@huawei.com>
>
> arm32 uses software to simulate the instruction replaced
> by kprobe. some instructions may be simulated by constructing
> assembly functions. therefore, before executing instruction
> simulation, it is necessary to construct assembly function
> execution environment in C language through binding registers.
> after kasan is enabled, the register binding relationship will
> be destroyed, resulting in instruction simulation errors and
> causing kernel panic.
>
> the kprobe emulate instruction function is distributed in three
> files: actions-common.c actions-arm.c actions-thumb.c, so disable
> KASAN when compiling these files.
>
> for example, use kprobe insert on cap_capable+20 after kasan
> enabled, the cap_capable assembly code is as follows:
> <cap_capable>:
> e92d47f0        push    {r4, r5, r6, r7, r8, r9, sl, lr}
> e1a05000        mov     r5, r0
> e280006c        add     r0, r0, #108    ; 0x6c
> e1a04001        mov     r4, r1
> e1a06002        mov     r6, r2
> e59fa090        ldr     sl, [pc, #144]  ;
> ebfc7bf8        bl      c03aa4b4 <__asan_load4>
> e595706c        ldr     r7, [r5, #108]  ; 0x6c
> e2859014        add     r9, r5, #20
> ......
> The emulate_ldr assembly code after enabling kasan is as follows:
> c06f1384 <emulate_ldr>:
> e92d47f0        push    {r4, r5, r6, r7, r8, r9, sl, lr}
> e282803c        add     r8, r2, #60     ; 0x3c
> e1a05000        mov     r5, r0
> e7e37855        ubfx    r7, r5, #16, #4
> e1a00008        mov     r0, r8
> e1a09001        mov     r9, r1
> e1a04002        mov     r4, r2
> ebf35462        bl      c03c6530 <__asan_load4>
> e357000f        cmp     r7, #15
> e7e36655        ubfx    r6, r5, #12, #4
> e205a00f        and     sl, r5, #15
> 0a000001        beq     c06f13bc <emulate_ldr+0x38>
> e0840107        add     r0, r4, r7, lsl #2
> ebf3545c        bl      c03c6530 <__asan_load4>
> e084010a        add     r0, r4, sl, lsl #2
> ebf3545a        bl      c03c6530 <__asan_load4>
> e2890010        add     r0, r9, #16
> ebf35458        bl      c03c6530 <__asan_load4>
> e5990010        ldr     r0, [r9, #16]
> e12fff30        blx     r0
> e356000f        cm      r6, #15
> 1a000014        bne     c06f1430 <emulate_ldr+0xac>
> e1a06000        mov     r6, r0
> e2840040        add     r0, r4, #64     ; 0x40
> ......
>
> when running in emulate_ldr to simulate the ldr instruction, panic
> occurred, and the log is as follows:
> Unable to handle kernel NULL pointer dereference at virtual address
> 00000090
> pgd = ecb46400
> [00000090] *pgd=2e0fa003, *pmd=00000000
> Internal error: Oops: 206 [#1] SMP ARM
> PC is at cap_capable+0x14/0xb0
> LR is at emulate_ldr+0x50/0xc0
> psr: 600d0293 sp : ecd63af8  ip : 00000004  fp : c0a7c30c
> r10: 00000000  r9 : c30897f4  r8 : ecd63cd4
> r7 : 0000000f  r6 : 0000000a  r5 : e59fa090  r4 : ecd63c98
> r3 : c06ae294  r2 : 00000000  r1 : b7611300  r0 : bf4ec008
> Flags: nZCv  IRQs off  FIQs on  Mode SVC_32  ISA ARM  Segment user
> Control: 32c5387d  Table: 2d546400  DAC: 55555555
> Process bash (pid: 1643, stack limit = 0xecd60190)
> (cap_capable) from (kprobe_handler+0x218/0x340)
> (kprobe_handler) from (kprobe_trap_handler+0x24/0x48)
> (kprobe_trap_handler) from (do_undefinstr+0x13c/0x364)
> (do_undefinstr) from (__und_svc_finish+0x0/0x30)
> (__und_svc_finish) from (cap_capable+0x18/0xb0)
> (cap_capable) from (cap_vm_enough_memory+0x38/0x48)
> (cap_vm_enough_memory) from
> (security_vm_enough_memory_mm+0x48/0x6c)
> (security_vm_enough_memory_mm) from
> (copy_process.constprop.5+0x16b4/0x25c8)
> (copy_process.constprop.5) from (_do_fork+0xe8/0x55c)
> (_do_fork) from (SyS_clone+0x1c/0x24)
> (SyS_clone) from (__sys_trace_return+0x0/0x10)
> Code: 0050a0e1 6c0080e2 0140a0e1 0260a0e1 (f801f0e7)
>
> Fixes: 35aa1df43283 ("ARM kprobes: instruction single-stepping support")
> Fixes: 421015713b30 ("ARM: 9017/2: Enable KASan for ARM")
> Signed-off-by: huangshaobo <huangshaobo6@huawei.com>
> Asked-by: Ard Biesheuvel <ardb@kernel.org>

Please don't do this - the maintainer will pick it up when applying,
or when you send a new version of the patch, it is OK to add these
tags if you have not made any substantial changes.

But please do *not* add tags like this on someone else's behalf by
replying to the email - and I should also point out that 'asked-by' is
bogus.


> ---
>  arch/arm/probes/kprobes/Makefile | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/arch/arm/probes/kprobes/Makefile b/arch/arm/probes/kprobes/Makefile
> index 14db56f49f0a..6159010dac4a 100644
> --- a/arch/arm/probes/kprobes/Makefile
> +++ b/arch/arm/probes/kprobes/Makefile
> @@ -1,4 +1,7 @@
>  # SPDX-License-Identifier: GPL-2.0
> +KASAN_SANITIZE_actions-common.o := n
> +KASAN_SANITIZE_actions-arm.o := n
> +KASAN_SANITIZE_actions-thumb.o := n
>  obj-$(CONFIG_KPROBES)          += core.o actions-common.o checkers-common.o
>  obj-$(CONFIG_ARM_KPROBES_TEST) += test-kprobes.o
>  test-kprobes-objs              := test-core.o
> --
> 2.12.3
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXGNKhkwAuEYe1d6L6w7D0OxjgGsiR0i%2BZoyZjMVmnjxDA%40mail.gmail.com.
