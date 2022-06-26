Return-Path: <kasan-dev+bncBDFJHU6GRMBBBXWC36KQMGQEUMT5KJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A2F055AED8
	for <lists+kasan-dev@lfdr.de>; Sun, 26 Jun 2022 06:32:31 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id c185-20020a1c35c2000000b0039db3e56c39sf5441348wma.5
        for <lists+kasan-dev@lfdr.de>; Sat, 25 Jun 2022 21:32:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656217950; cv=pass;
        d=google.com; s=arc-20160816;
        b=DoeM9WRRbzn0I5HZDvfKx0R62h4AUbo30R5yjfUbLdgR/wXlmBQS+2RBfwoRHEwDOM
         89eub88aA0nj8J8bd/uFUWDTKNeGiez12dQB2h86XZB+nz8llcexWkz0GNPsC/uoWLDH
         5BWinTB3kcDvOrIuIi6xQrZbCFBmDbw3d1b1oMOZG7MsXW1YO8S5q4aRPZ8kJEuSaVVA
         hIGMV1++C8Il5eaiLoS/QFo+6uhAvCz5OwlFij3gBq5HfOF36VSPPmEH9wpoxDifw6BN
         zopWu7s7FuAC/l9Vg42vwwuedrqG3gmQGxP65euam2LLjiWMaaKFqu5+HzZZaVNQBGU9
         IcXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=i7BSFcvANFfpcfoCvII64/hu23Pk4JIH9ZijmMrQHYA=;
        b=hQxKd6M21lrrjHE53NZK7seHpyldOjUBGnRvPX9HXpwo0Mo4yMOhDGOYOy0RtukfcU
         4RlYs6eKEGZrSnYcvZPUubjmvpbFnE6xsneUtacpxXcp5M40tHeuyFYf1czhOreLMKa3
         Irtq3qE8E5XefVz7h83TQZFVhmVMy/BM3lP5wcAGIkmGTRFMxzz+38l0o1XkXs4JKT1l
         dpgCvAJn/HcbtUPK/SKxYc0+nua1EYrOLwww/GCZhJKWzKf4rCQGsfYT9qyBq5x8t2t0
         Rsv5DPCmDfUQeMXnYGp6+mxYGWJn9N8/Xnyf2bb2kH015xRuucV6u0hmFPpC6XHpW+TU
         bWIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b=VnVmHxRQ;
       spf=neutral (google.com: 2a00:1450:4864:20::435 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i7BSFcvANFfpcfoCvII64/hu23Pk4JIH9ZijmMrQHYA=;
        b=kQacd24lcfAXiERicEtxeJQicQLM/ohUaAZzP2+VIyc1HpO+cNFWAwfa7vV9CxUEJG
         K6Hyfpx3USnSPCLRe2mHciy/aQ4xTMaR4EGsWOaVHsE9PTyxpPe4Xf/NQkp2bhsFemsI
         MT1FlkjRKP7BYsVw5erPn2JSk6Oe9cq7TAPRAUcZrkVSIJnV1aGpNcMbhtmErA7jhEff
         yZy4ZKnTyc2/E3DKtEMqBsOt0ZLB0NLwCgoeK34Y4lBVZ2HTmZg4eH0/lFY+kZtSMjx6
         VLiyfw/TcJE6WSjLYr9eBU1SfCQV96OOQOzNGEDt82lhg5z31X/l7fhbWlrT8tZbh/Ec
         AwfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i7BSFcvANFfpcfoCvII64/hu23Pk4JIH9ZijmMrQHYA=;
        b=JKL+iUNqLSj98k90lKQ6oky2vuz8WXmft8cdhhET5rd/05Hkc7uZamfAhPRZsNu39a
         tE1uqK7YvD9LoWFt1gRpd4iPnKRt3H0AIvLuVKUMwjIQkR2vnXylik10p8TY3d0Xh6j4
         qvzdCnM4pimQT14zK1Ldnue5d6sfOFc89b+cG5gnMb4qD2uE6KL6h1s7LO7jtnRh6V2f
         AhdLPRZyMst8/tGq+2rsad0c0qCLFY+X/TW9yWf/x7G/PKlGS8nLa2Z5ZQx0CdK13ifg
         Zc1Up9y4seNjVI1/LQPqjWmIZ/Nvcy7Fr1dLvatmul23vzLAJ2NUeOjM9fyloroy2Ixn
         J1XA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+cUT28knO+/jxpgqZylkhui02UDIHaz9284x75DfzOcocRIOEp
	yQ8x/MOHZoqJHSIPtTdXsno=
X-Google-Smtp-Source: AGRyM1uX9swwpim2QATAz4TUsdHZxta0Imd642rCWEYVJI/dwcOdq38vbwuAU5Gk0FJYpDBIGCt0/A==
X-Received: by 2002:a05:6000:178c:b0:218:5e44:e9a0 with SMTP id e12-20020a056000178c00b002185e44e9a0mr6815809wrg.76.1656217950660;
        Sat, 25 Jun 2022 21:32:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c23:b0:3a0:48aa:51f2 with SMTP id
 j35-20020a05600c1c2300b003a048aa51f2ls88190wms.0.gmail; Sat, 25 Jun 2022
 21:32:29 -0700 (PDT)
X-Received: by 2002:a1c:cc1a:0:b0:3a0:39b1:3408 with SMTP id h26-20020a1ccc1a000000b003a039b13408mr7578568wmb.157.1656217949669;
        Sat, 25 Jun 2022 21:32:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656217949; cv=none;
        d=google.com; s=arc-20160816;
        b=VIuqcZ51hMKt/SSSaH2TQp2v7/k3C77KKE/61rixWCR4Z5GCb+DHxUSvpondPWJXZD
         3LWoyFr6y2WcSseOnPAP3xKhGgu91d76EQIAFXpb+lsBPhLgOjTl384GJjUvzGr2d0Cv
         uQWO7TmiOOqo+yehhE/wLAz8zyEh93nHYMZ4f3cONOcpmSfbn+yAdDhlYYsbYiEVFYZg
         RerQW6OMPTMpHnB0Y8regmQjAv2z7GrILirVphLK7Q+8a5L2LD9OhCflN4RkvCdwVfjB
         CviV2JFQ9qvX7XeqQQVxR49x+Dj745NnYDz/IrjlHk0vcML7SEnW0lPV+IC47f6wCtlU
         2qPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dgYFMd2AKATEsQVK+8PzanW7bSMhQStpLS8wApMs/kg=;
        b=BpjVef+mGANBn+jLvQBbDQmFoZdtska2sG0zK54cwE+yWEPC6AOB1lhWtbyoqLbWlV
         OW6dRPGpIQpO3s51CQFMqngPnPZY8NB1Ktwsaz4Q9xMt6lPMx6Bi4ootoUpaYHlMfrWV
         DulhfkHkgHNk9Iw9Yyp3QHMDoXLcYCveMWr0laPcV0GE+Er8nHyA61aM7AMW2HgOhXV8
         UkLGjkzB/F+mJVzyLWthuVnS4QUN5emCMvJp7RnQ8MA75gd0EA+TFbt4SZUG82QMWoS8
         zdRDWX8eAhAnTNRExfkfonA83Z5+O+LpWq/gYGiT9Sg/Rmj1J2ZHxXiS40lUGt53plaP
         4UUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b=VnVmHxRQ;
       spf=neutral (google.com: 2a00:1450:4864:20::435 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id w15-20020adff9cf000000b0021b95bcfb2asi272903wrr.0.2022.06.25.21.32.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 25 Jun 2022 21:32:29 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::435 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id q5so3055163wrc.2
        for <kasan-dev@googlegroups.com>; Sat, 25 Jun 2022 21:32:29 -0700 (PDT)
X-Received: by 2002:a5d:6c6b:0:b0:1ea:77ea:dde8 with SMTP id
 r11-20020a5d6c6b000000b001ea77eadde8mr6438147wrz.690.1656217949141; Sat, 25
 Jun 2022 21:32:29 -0700 (PDT)
MIME-Version: 1.0
References: <20220521143456.2759-1-jszhang@kernel.org> <20220521143456.2759-2-jszhang@kernel.org>
In-Reply-To: <20220521143456.2759-2-jszhang@kernel.org>
From: Anup Patel <anup@brainfault.org>
Date: Sun, 26 Jun 2022 10:02:17 +0530
Message-ID: <CAAhSdy2yT26QournxS4Zf6L8oMj5Bs6BEjuW56NHapq=cXOEww@mail.gmail.com>
Subject: Re: [PATCH v4 1/2] riscv: move sbi_init() earlier before jump_label_init()
To: Jisheng Zhang <jszhang@kernel.org>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexandre Ghiti <alexandre.ghiti@canonical.com>, Atish Patra <atishp@rivosinc.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	Sunil V L <sunilvl@ventanamicro.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112
 header.b=VnVmHxRQ;       spf=neutral (google.com: 2a00:1450:4864:20::435 is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
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

On Sat, May 21, 2022 at 8:13 PM Jisheng Zhang <jszhang@kernel.org> wrote:
>
> We call jump_label_init() in setup_arch() is to use static key
> mechanism earlier, but riscv jump label relies on the sbi functions,
> If we enable static key before sbi_init(), the code path looks like:
>   static_branch_enable()
>     ..
>       arch_jump_label_transform()
>         patch_text_nosync()
>           flush_icache_range()
>             flush_icache_all()
>               sbi_remote_fence_i() for CONFIG_RISCV_SBI case
>                 __sbi_rfence()
>
> Since sbi isn't initialized, so NULL deference! Here is a typical
> panic log:
>
> [    0.000000] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
> [    0.000000] Oops [#1]
> [    0.000000] Modules linked in:
> [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 5.18.0-rc7+ #79
> [    0.000000] Hardware name: riscv-virtio,qemu (DT)
> [    0.000000] epc : 0x0
> [    0.000000]  ra : sbi_remote_fence_i+0x1e/0x26
> [    0.000000] epc : 0000000000000000 ra : ffffffff80005826 sp : ffffffff80c03d50
> [    0.000000]  gp : ffffffff80ca6178 tp : ffffffff80c0ad80 t0 : 6200000000000000
> [    0.000000]  t1 : 0000000000000000 t2 : 62203a6b746e6972 s0 : ffffffff80c03d60
> [    0.000000]  s1 : ffffffff80001af6 a0 : 0000000000000000 a1 : 0000000000000000
> [    0.000000]  a2 : 0000000000000000 a3 : 0000000000000000 a4 : 0000000000000000
> [    0.000000]  a5 : 0000000000000000 a6 : 0000000000000000 a7 : 0000000000080200
> [    0.000000]  s2 : ffffffff808b3e48 s3 : ffffffff808bf698 s4 : ffffffff80cb2818
> [    0.000000]  s5 : 0000000000000001 s6 : ffffffff80c9c345 s7 : ffffffff80895aa0
> [    0.000000]  s8 : 0000000000000001 s9 : 000000000000007f s10: 0000000000000000
> [    0.000000]  s11: 0000000000000000 t3 : ffffffff80824d08 t4 : 0000000000000022
> [    0.000000]  t5 : 000000000000003d t6 : 0000000000000000
> [    0.000000] status: 0000000000000100 badaddr: 0000000000000000 cause: 000000000000000c
> [    0.000000] ---[ end trace 0000000000000000 ]---
> [    0.000000] Kernel panic - not syncing: Attempted to kill the idle task!
> [    0.000000] ---[ end Kernel panic - not syncing: Attempted to kill the idle task! ]---
>
> Fix this issue by moving sbi_init() earlier before jump_label_init()
>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>

We are seeing a similar crash when booting kernel via EDK2 with RNG enabled.

Shell> fs0:\Image root=/dev/vda2 rootwait console=ttyS0
earlycon=uart8250,mmio,0x10000000 initrd=\initramfs.cp
EFI stub: Booting Linux Kernel...
EFI stub: Using DTB from configuration table
EFI stub: Exiting boot services...
[    0.000000] Linux version 5.19.0-rc3 (oe-user@oe-host)
(riscv64-unknown-linux-gnu-gcc (Ventana-2022.05.16) 12.1.0, GNU ld
(Ventana-2022.05.16) 2.37.90.20220201) #1 SMP Thu Jun 23 05:33:13 UTC
2022
[    0.000000] OF: fdt: Ignoring memory range 0x80000000 - 0x81200000
[    0.000000] earlycon: uart8250 at MMIO 0x0000000010000000 (options '')
[    0.000000] printk: bootconsole [uart8250] enabled
[    0.000000] efi: EFI v2.70 by EDK II
[    0.000000] efi: RNG=0xff94fd98 MEMRESERVE=0xfe658f18
[    0.000000] efi: seeding entropy pool
[    0.000000] Unable to handle kernel NULL pointer dereference at
virtual address 0000000000000000
[    0.000000] Oops [#1]
[    0.000000] Modules linked in:
[    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 5.19.0-rc3 #1
[    0.000000] epc : 0x0
[    0.000000]  ra : sbi_remote_fence_i+0x1e/0x26
[    0.000000] epc : 0000000000000000 ra : ffffffff800080f8 sp :
ffffffff81203cd0
[    0.000000]  gp : ffffffff812f1d40 tp : ffffffff8120da80 t0 :
0000000000cb8266
[    0.000000]  t1 : 000000006d5e5146 t2 : 0000000058000000 s0 :
ffffffff81203ce0
[    0.000000]  s1 : ffffffff8047586a a0 : 0000000000000000 a1 :
0000000000000000
[    0.000000]  a2 : 0000000000000000 a3 : 0000000000000000 a4 :
0000000000000000
[    0.000000]  a5 : 0000000000000000 a6 : 0000000000000000 a7 :
0000000000000000
[    0.000000]  s2 : ffffffff80dea320 s3 : ffffffff80deabb0 s4 :
ffffffff81353d48
[    0.000000]  s5 : 0000000000000001 s6 : 00000000fffde848 s7 :
0000000000000004
[    0.000000]  s8 : 0000000081021714 s9 : 000000008101e6f0 s10:
00000000fffde780
[    0.000000]  s11: 0000000000000004 t3 : 000000001467a415 t4 :
0000000000000000
[    0.000000]  t5 : 00000000007627e0 t6 : ffffffffbc865574
[    0.000000] status: 0000000200000100 badaddr: 0000000000000000
cause: 000000000000000c
[    0.000000] ---[ end trace 0000000000000000 ]---
[    0.000000] Kernel panic - not syncing: Attempted to kill the idle task!
[    0.000000] ---[ end Kernel panic - not syncing: Attempted to kill
the idle task! ]---

This patch fixes the above crash as well.

Reviewed-by: Anup Patel <anup@brainfault.org>

Thanks,
Anup

> ---
>  arch/riscv/kernel/setup.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
> index 834eb652a7b9..d150cedeb7e0 100644
> --- a/arch/riscv/kernel/setup.c
> +++ b/arch/riscv/kernel/setup.c
> @@ -268,6 +268,7 @@ void __init setup_arch(char **cmdline_p)
>         *cmdline_p = boot_command_line;
>
>         early_ioremap_setup();
> +       sbi_init();
>         jump_label_init();
>         parse_early_param();
>
> @@ -284,7 +285,6 @@ void __init setup_arch(char **cmdline_p)
>         misc_mem_init();
>
>         init_resources();
> -       sbi_init();
>
>  #ifdef CONFIG_KASAN
>         kasan_init();
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy2yT26QournxS4Zf6L8oMj5Bs6BEjuW56NHapq%3DcXOEww%40mail.gmail.com.
