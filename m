Return-Path: <kasan-dev+bncBAABB4GZ2ODQMGQEBN4ML7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B92B3CCC88
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jul 2021 05:09:37 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id i11-20020a056e02004bb029020269661e11sf9618972ilr.13
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Jul 2021 20:09:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626664176; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xb98RHCPdX3vDYoRUUz3LLQLyY7HluLh7+2jxKdtF6e4+TCZJVMfQBTp2RLdlkFDfl
         nNEw0tOVlZi0tz+qIuGPXECXz+Lm4JzElJVr4vHiL8nz+nv61KHj9lgnEYn+jYKEWbvX
         E90aUimm8OtG+afCjbbwsK/W90vlYaG1attpYAt6q79btJ5KAkm7syv6Y6CHckAIC/B/
         2TN/iaiuFA5oipVDzcszQDxeuZa6R54sAx3WNH689WmtAuRGJbNt/OZRG2yogcey3ZCP
         EcokyfnuSu2FZ2ekH2+5VZv35N1metUav9ySwUD+/KK4YyuLQ0/oBUBuHON0JTufHitJ
         AuIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=n/Wdck8AZJEnV+4QrKGrljIxS3Q6pkNAhjA8cVq2cMI=;
        b=fqnWYf0/y1XFWlLUfOzEdm1CXpr0ScgVZ4xPD3OiW2F5dsp7WJlf+d4U169lHof5vy
         aF6Ho4bDRq4n0GjlS+khQs78bXMY5J/8VZHt3H49yBqfskiiqeGVZ13Yl7RLc9+DhqHx
         4QRaTHyHt0Y1CndDrEdQy+/HjRwJB2JR13v6LdrGG3bqmIFowVC3NybaYHtyLUpuZXV5
         7UfoDuOCLir94hFU51QUB3mv4gkkGeCC3KgYPc66ELIDS77pd9H/X+JGB5hBQ75Jx0cy
         wAbwTX1mNm+H3jSSI9cRQZO6Q8cnXjF69vsRjh/IUDj0c0Y4QwWxqjkKT55GPqPMf4wa
         4EoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n/Wdck8AZJEnV+4QrKGrljIxS3Q6pkNAhjA8cVq2cMI=;
        b=pA+ikjFgZb+EA7rvRJWItW27IScm360uMSBa8Fh4Knkg4x0p4sn1ryzas8NfWbcRbd
         fK+cwn/j4NXjO2esIPgQsz7FOjsfq84rlF5UREd8eMbAXTEP+2vtIFJqYuoWHIInLGwa
         o9n06xHbJEyiK/A1KiGWW1dvecX1C2DERWupryu8rXnmuvuwfDDbqum0RrjSF79wTOqp
         VzBotGp5u5fQkdzio9ARAY5Gsf/Re9+8+FXapu7OyLaJHgdVl0lOOUrgLwk2Z0xs/RG3
         T5c+lyLhHVqbQLzwqVIt086m/1JOknxrKtwiPPMRITBoC0zjTBjY9jTUGPy+rDgIG+Pg
         5tJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n/Wdck8AZJEnV+4QrKGrljIxS3Q6pkNAhjA8cVq2cMI=;
        b=kcnMIJ0g/FJjBjDm/y8QrbBGvfZpMnpZXCHKiVfGJu3ZuS9omvqrmUsLSPEU4BCrYj
         nc6pgUY+P4NwGvlnHNpnDrH9ft6Dy2gCZW90wvRAvTCarw9isKxFVmqFKn29qKLU0LQ6
         Fk3Ucc48kNSvNiFDndOpP3me/loppy4CqI0Db7wb3AKTn8YdxugPw86dVXcYiaLshsgi
         L90UcEGhjCKUFKLJoz+vDpHVSLt4SVgMKIeTno+SXTUaPbOmEkoXN4BqwmR1NXWmqBfw
         HGm/67ZIhlHN2+mK0i5q+sTuL+3lYBOl/flS+lmE1O2/p3s/RIJP8JlT6/LJrMphsrv6
         NLhw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Ait7M2XdKDwQgGFNmZJD9AQ87gzmIqg9hXWIfhTQ0g7NGt9Ue
	RtJqSIXqL5m+yQObhVmd2ho=
X-Google-Smtp-Source: ABdhPJwX88i3tusVN6TFPvcjJmZFuKee3OXu/dN+qTCLou3KkBbr+PfKEDs1cZhYFfxzAAYjwTccQA==
X-Received: by 2002:a05:6e02:dc4:: with SMTP id l4mr16047420ilj.94.1626664176334;
        Sun, 18 Jul 2021 20:09:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:c2:: with SMTP id r2ls1874928ilq.3.gmail; Sun, 18
 Jul 2021 20:09:36 -0700 (PDT)
X-Received: by 2002:a92:c748:: with SMTP id y8mr13136142ilp.2.1626664176060;
        Sun, 18 Jul 2021 20:09:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626664176; cv=none;
        d=google.com; s=arc-20160816;
        b=Se9LGkteDKaq33WPOK2QzYhVoNOv7F3l3Kx/7osQVncPho7Pwy8YqhgphKU9TwVlrg
         v3dyBRwcFINbt8RmS7QF0gr7el6GnErQ9hdtv2FaT2lZa/6hc+6fI35V1gtN7SdOKcLV
         3G/Vmebo8EnDBLd0m9zR6/bfK+8Nd+4Xwt3WUvCR53Wyzyax5xiohbIv84LnZK8g11u5
         yxveL2dOlhfHAV9GGWoo3Gk3F4XaR7mxKdg0RT1z/Xjuyj+Wvbn3QZhxZnsHAFy7MWGt
         l+kOi9xLHwRJ3jxhmBPRLVxPKt/zxx33+qLLmTQSx2vObD3qMwcqWJWejTZJp11O+kCC
         uDNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=jy6oud7C8MmsLAdZxe9Zp6LHlsCO9sljS1hqPMOmdJs=;
        b=M5z5X18evf23Q78et8fJeqMm2gj9NSr0gRsQDrCXnP/EZuMO9/2Ns2Jc4OXbfuw2z+
         cj2nbPD3m8JCX11Eh4y9jB/Oah5yh/kXhecClr+IGsblQD+9pFH2+HHyxd/7sd0ScSBQ
         T5ethD6L5o56bS85IejJ2YexkI6tbNUxmFq4L8geTdYs3zpdO2GuAFNYkxE7M1cHi9fx
         PW0WiEfn72FJ/wv1ClflOEulW/hriYLio53oO4yyjfY1EYAjm6yPOuIsRv6BJvK0m4nM
         IhygpIuhRkCpFjD1cTR2wy0G8/x7DgXbshd8e+wH69z7eP5ZE4XUUhpoJ6/5v3GwLgns
         flvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id h1si1180978iow.1.2021.07.18.20.09.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 18 Jul 2021 20:09:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggeme765-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4GSmvR65mfzZqkK;
	Mon, 19 Jul 2021 11:06:11 +0800 (CST)
Received: from DESKTOP-E0KHRBE.china.huawei.com (10.67.103.82) by
 dggeme765-chm.china.huawei.com (10.3.19.111) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256) id
 15.1.2176.2; Mon, 19 Jul 2021 11:09:32 +0800
From: Shaobo Huang <huangshaobo6@huawei.com>
To: <ardb@kernel.org>
CC: <andreyknvl@gmail.com>, <chenzefeng2@huawei.com>, <dvyukov@google.com>,
	<f.fainelli@gmail.com>, <glider@google.com>, <huangshaobo6@huawei.com>,
	<kasan-dev@googlegroups.com>, <kepler.chenxin@huawei.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux@armlinux.org.uk>, <liucheng32@huawei.com>, <liuwenliang@huawei.com>,
	<nico@marvell.com>, <nixiaoming@huawei.com>, <qbarnes@gmail.com>,
	<ryabinin.a.a@gmail.com>, <sagar.abhishek@gmail.com>,
	<wuquanming@huawei.com>, <xiaoqian9@huawei.com>, <young.liuyang@huawei.com>,
	<zengweilin@huawei.com>
Subject: Re: [PATCH] ARM: fix panic when kasan and kprobe are enabled
Date: Mon, 19 Jul 2021 11:09:32 +0800
Message-ID: <20210719030932.23384-1-huangshaobo6@huawei.com>
X-Mailer: git-send-email 2.21.0.windows.1
In-Reply-To: <CAMj1kXGNKhkwAuEYe1d6L6w7D0OxjgGsiR0i+ZoyZjMVmnjxDA@mail.gmail.com>
References: <CAMj1kXGNKhkwAuEYe1d6L6w7D0OxjgGsiR0i+ZoyZjMVmnjxDA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.103.82]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggeme765-chm.china.huawei.com (10.3.19.111)
X-CFilter-Loop: Reflected
X-Original-Sender: huangshaobo6@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

On Sat, 17 Jul 2021 at 01:01, Ard Biesheuvel <ardb@kernel.org> wrote:
> On Wed, 14 Jul 2021 at 10:27, Shaobo Huang <huangshaobo6@huawei.com> wrote:
>>
>> From: huangshaobo <huangshaobo6@huawei.com>
>>
>> arm32 uses software to simulate the instruction replaced
>> by kprobe. some instructions may be simulated by constructing
>> assembly functions. therefore, before executing instruction
>> simulation, it is necessary to construct assembly function
>> execution environment in C language through binding registers.
>> after kasan is enabled, the register binding relationship will
>> be destroyed, resulting in instruction simulation errors and
>> causing kernel panic.
>>
>> the kprobe emulate instruction function is distributed in three
>> files: actions-common.c actions-arm.c actions-thumb.c, so disable
>> KASAN when compiling these files.
>>
>> for example, use kprobe insert on cap_capable+20 after kasan
>> enabled, the cap_capable assembly code is as follows:
>> <cap_capable>:
>> e92d47f0        push    {r4, r5, r6, r7, r8, r9, sl, lr}
>> e1a05000        mov     r5, r0
>> e280006c        add     r0, r0, #108    ; 0x6c
>> e1a04001        mov     r4, r1
>> e1a06002        mov     r6, r2
>> e59fa090        ldr     sl, [pc, #144]  ;
>> ebfc7bf8        bl      c03aa4b4 <__asan_load4>
>> e595706c        ldr     r7, [r5, #108]  ; 0x6c
>> e2859014        add     r9, r5, #20
>> ......
>> The emulate_ldr assembly code after enabling kasan is as follows:
>> c06f1384 <emulate_ldr>:
>> e92d47f0        push    {r4, r5, r6, r7, r8, r9, sl, lr}
>> e282803c        add     r8, r2, #60     ; 0x3c
>> e1a05000        mov     r5, r0
>> e7e37855        ubfx    r7, r5, #16, #4
>> e1a00008        mov     r0, r8
>> e1a09001        mov     r9, r1
>> e1a04002        mov     r4, r2
>> ebf35462        bl      c03c6530 <__asan_load4>
>> e357000f        cmp     r7, #15
>> e7e36655        ubfx    r6, r5, #12, #4
>> e205a00f        and     sl, r5, #15
>> 0a000001        beq     c06f13bc <emulate_ldr+0x38>
>> e0840107        add     r0, r4, r7, lsl #2
>> ebf3545c        bl      c03c6530 <__asan_load4>
>> e084010a        add     r0, r4, sl, lsl #2
>> ebf3545a        bl      c03c6530 <__asan_load4>
>> e2890010        add     r0, r9, #16
>> ebf35458        bl      c03c6530 <__asan_load4>
>> e5990010        ldr     r0, [r9, #16]
>> e12fff30        blx     r0
>> e356000f        cm      r6, #15
>> 1a000014        bne     c06f1430 <emulate_ldr+0xac>
>> e1a06000        mov     r6, r0
>> e2840040        add     r0, r4, #64     ; 0x40
>> ......
>>
>> when running in emulate_ldr to simulate the ldr instruction, panic
>> occurred, and the log is as follows:
>> Unable to handle kernel NULL pointer dereference at virtual address
>> 00000090
>> pgd = ecb46400
>> [00000090] *pgd=2e0fa003, *pmd=00000000
>> Internal error: Oops: 206 [#1] SMP ARM
>> PC is at cap_capable+0x14/0xb0
>> LR is at emulate_ldr+0x50/0xc0
>> psr: 600d0293 sp : ecd63af8  ip : 00000004  fp : c0a7c30c
>> r10: 00000000  r9 : c30897f4  r8 : ecd63cd4
>> r7 : 0000000f  r6 : 0000000a  r5 : e59fa090  r4 : ecd63c98
>> r3 : c06ae294  r2 : 00000000  r1 : b7611300  r0 : bf4ec008
>> Flags: nZCv  IRQs off  FIQs on  Mode SVC_32  ISA ARM  Segment user
>> Control: 32c5387d  Table: 2d546400  DAC: 55555555
>> Process bash (pid: 1643, stack limit = 0xecd60190)
>> (cap_capable) from (kprobe_handler+0x218/0x340)
>> (kprobe_handler) from (kprobe_trap_handler+0x24/0x48)
>> (kprobe_trap_handler) from (do_undefinstr+0x13c/0x364)
>> (do_undefinstr) from (__und_svc_finish+0x0/0x30)
>> (__und_svc_finish) from (cap_capable+0x18/0xb0)
>> (cap_capable) from (cap_vm_enough_memory+0x38/0x48)
>> (cap_vm_enough_memory) from
>> (security_vm_enough_memory_mm+0x48/0x6c)
>> (security_vm_enough_memory_mm) from
>> (copy_process.constprop.5+0x16b4/0x25c8)
>> (copy_process.constprop.5) from (_do_fork+0xe8/0x55c)
>> (_do_fork) from (SyS_clone+0x1c/0x24)
>> (SyS_clone) from (__sys_trace_return+0x0/0x10)
>> Code: 0050a0e1 6c0080e2 0140a0e1 0260a0e1 (f801f0e7)
>>
>> Fixes: 35aa1df43283 ("ARM kprobes: instruction single-stepping support")
>> Fixes: 421015713b30 ("ARM: 9017/2: Enable KASan for ARM")
>> Signed-off-by: huangshaobo <huangshaobo6@huawei.com>
>> Asked-by: Ard Biesheuvel <ardb@kernel.org>
> 
> Please don't do this - the maintainer will pick it up when applying,
> or when you send a new version of the patch, it is OK to add these
> tags if you have not made any substantial changes.
> 
> But please do *not* add tags like this on someone else's behalf by
> replying to the email - and I should also point out that 'asked-by' is
> bogus.
> 

Hi ardb,
1.The original patch you have been asked-by by email before, link: https://lore.kernel.org/linux-arm-kernel/CAMj1kXGqfF68MT4WwrxS0cYiUBb0gODDh-wGZSQcW9vxdfK90A@mail.gmail.com/
2.In addition to adding the asked-by tag, there is no other content modification in this patch
3.The patch was reissued because the previous recipient did not include kasan maintainer and reviewers

thanks,
ShaoBo Huang

>
>> ---
>>  arch/arm/probes/kprobes/Makefile | 3 +++
>>  1 file changed, 3 insertions(+)
>>
>> diff --git a/arch/arm/probes/kprobes/Makefile b/arch/arm/probes/kprobes/Makefile
>> index 14db56f49f0a..6159010dac4a 100644
>> --- a/arch/arm/probes/kprobes/Makefile
>> +++ b/arch/arm/probes/kprobes/Makefile
>> @@ -1,4 +1,7 @@
>>  # SPDX-License-Identifier: GPL-2.0
>> +KASAN_SANITIZE_actions-common.o := n
>> +KASAN_SANITIZE_actions-arm.o := n
>> +KASAN_SANITIZE_actions-thumb.o := n
>>  obj-$(CONFIG_KPROBES)          += core.o actions-common.o checkers-common.o
>>  obj-$(CONFIG_ARM_KPROBES_TEST) += test-kprobes.o
>>  test-kprobes-objs              := test-core.o
>> --
>> 2.12.3
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210719030932.23384-1-huangshaobo6%40huawei.com.
