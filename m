Return-Path: <kasan-dev+bncBDFKDBGSFYIJFJPFSUDBUBCTMYEAO@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AAA655B7FE
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 08:47:48 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id q13-20020ab0264d000000b00381d36210c3sf1060132uao.9
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Jun 2022 23:47:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656312466; cv=pass;
        d=google.com; s=arc-20160816;
        b=D44HlKBcui2k7BKnuSimzWGbIsno9WOpWG4JVDLIKfJuDOXnvh1sSEhw6dZGj7ixhX
         PhkxMTfDUnIrNxQ68nrQddptT46/xqJLc2c1O9z1UjYsvOhYeC4HSgU0I96ElE3K9oq9
         IFwDMZS43EFGkk2M/w80OuFhhwAwTuk0weW5KLDcRK0qwsqIP0lTaResW6Buv87NU4ma
         40Lv6Js+yHDHjO0ooV2vy/ktoCAzZkQfSXRzusIPlSXxAl7/IR5oV+7VAy26ItKi/DDo
         bN4hWMmhbdQihvUrzMlKrErTNZOKUEteh0cdXZUt6yLL0JVtyjnu+5M3QDvpbZYxiwjm
         58aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=aaC3cr5DTXcJ437bh8kAXOPMN6JvGvHqoy+tEdfrElw=;
        b=A/EwA7SlnF8u3Dbv0K+0RxqER9DonO+G5XYcNEQc/7cfOrV94oQ99qYhfpCBqGS9qn
         x1h4qelFTTTSAL4Gz44T1SVAl02GHzgQwv+L2nYeORhIBcr96D1zbHpmMN6s5sUC24fY
         T4kSYLWE1QR0FVSdO9qcDevuamXCUqlPsAyq/FQoeG+FoJ0riu4BvcosYTFHTYbyJ3HV
         Af1ZUofZVF3wVJXUi+dlyFWsAvyHCBxln0qLmpFrKwpx9c2CGeMBjhe6dt/e7ohEl2YJ
         61EWchwBtYs/jJcoJKyftOpLjiRB5mV+3U9oNKSjXDspQghvjUjIVj1Fdj1GTmdiJo+v
         zY1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@atishpatra.org header.s=google header.b=RUqSR0Aq;
       spf=pass (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=atishp@atishpatra.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aaC3cr5DTXcJ437bh8kAXOPMN6JvGvHqoy+tEdfrElw=;
        b=kgErq1UlF8D7px1QRUpnm4i4AQ4cM4m2xmj0lJb2a0NWVeGcayDjqxjLbiL/dsqQVj
         XgvmOmPYxkTUiUTKEt+RMlS0KDLZbkl27TyvYFqCJzMO9iecuGxsqGi4gYY6akMGtmu1
         2eKAJZFecsnzcCy21gAJcgICtzxeegvjlrhyQjzsmBEgZ7pcAhzAIfS7zd00km/NBwLk
         b9b/ssU8AF1lCGn2SHdA7CTYtE9IIYKKMHNs2gu9bW2ER80ggAaQOvTcqUnmXC4PO1DK
         q0K+g3Em0uvC3NB7hzOAOl0cIXFaZGzWd0XWjPTfS4rQJ3Krc9TmWxRiEbRibLHBklYC
         3Bvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aaC3cr5DTXcJ437bh8kAXOPMN6JvGvHqoy+tEdfrElw=;
        b=g3IQBFDQnLIGCuDI7rj5d+TpRr8XhBvni3dR18i4BQPLLmiJyr6rMCyrZHvU6QQzcD
         tzszJT9c0G9sSH7cEdXdPtjdDE5ceqgWM28rLgj5xvmsTnwoSybPVd/4APmiB5dg1/x7
         oy1VU/L9XrrCgfGWY0DlvCZprf/KulrUqJRCGDaw+5sTdLa2alsrRaf55MrgYC6+s0lx
         JNZUOtQvpjPcwvzTUX3WuwLExnNYcBi/B5Byb3P2xQqMb9Pn8dc+/nQIyuhj+EQCca99
         35hpmCnzOwXwQAplP+9toOGM4twP9BYUCJsFpT5oEQf1yKp1938iKdsnVkv2/jOEua5d
         /oaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9HBlSUYx34Dg8H17nC0mdmfieeR3rX6tN5Ty90FewdLHgxWiHI
	dt4AoIteHbEMz6/wPRR9jLA=
X-Google-Smtp-Source: AGRyM1uCi8fGITq7ZOGp8OI++xRQb1SrFKCNy+ZrYkZyjHvOnaXOeO94AMaD2lZQNCt+5T+EoMSv6g==
X-Received: by 2002:a1f:cb07:0:b0:36c:6de6:8d3 with SMTP id b7-20020a1fcb07000000b0036c6de608d3mr3624689vkg.25.1656312466669;
        Sun, 26 Jun 2022 23:47:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:f4cd:0:b0:36c:5380:9471 with SMTP id s196-20020a1ff4cd000000b0036c53809471ls1522070vkh.6.gmail;
 Sun, 26 Jun 2022 23:47:46 -0700 (PDT)
X-Received: by 2002:ac5:c205:0:b0:35e:88f6:7338 with SMTP id m5-20020ac5c205000000b0035e88f67338mr3718955vkk.12.1656312465940;
        Sun, 26 Jun 2022 23:47:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656312465; cv=none;
        d=google.com; s=arc-20160816;
        b=mnnOV+TtJEfXUR+xUSFbbSZDVg7SMP215iibogT1psMDZZe5qIx+Bg87dQx6NXeGYG
         6TFnzwsWF7raRLHdrL/FKVoJv65f7xaYG5TWZaXtYdFblNhl6GdhWHwQwcORNUBSVe0Q
         EoemyqBCUQoSCrtXEfTXgNlQOGrQiQNAu6qf7wDiR0QfMBXLR7QR6yDWjNUrVtZlmiAJ
         7oNKC2cbJntnWyec9CULNV5vH75ekulnluML9/euCe92eYIkZQOQUawmAdHLeaSQ/duA
         rRjBmUicgnjMaFE7dTGenPI1guAmMi2W0oP2Fhi34316bXjoRktyXMA9M4eBtGpCM5B1
         DTzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RpPnU8MehDqKJsWHhgDuy79jEz+vPYFTumDLAwjvYYg=;
        b=VkJaKAoyHBTNaxsfo6R6uiEPZtZNuPPpT1BDM+3kg3Djx3wnIkphaQvdTpBXR1+Wfg
         9NKtQwhyPTcf2Zpp4nzROyWQl7jey8xltG8dJL2Ump4H8cbL2Z+6u8gnI9f4oYBXosYS
         xpzAI4T0doyxPnFkW1bzdxLUACi5HQ/XSHydu3ofSysu3RvzWX7+jdViV4/qr29qOBPq
         ttWUw5d/GZz3mJo2+ww6+M52ebqwDPbhzoDb3dcFtyqblKQfkE0UdJKx9VKHoi3lJ17o
         4RO4aH3Gk+Trf0FQjzp/eY82SBTcIFRrZlbLe3Rz6AVdNs9L3KWZg6xVh7SasxAyBXeB
         7yZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@atishpatra.org header.s=google header.b=RUqSR0Aq;
       spf=pass (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=atishp@atishpatra.org
Received: from mail-yw1-x112e.google.com (mail-yw1-x112e.google.com. [2607:f8b0:4864:20::112e])
        by gmr-mx.google.com with ESMTPS id e24-20020a05610211f800b0032cddd78670si325560vsg.2.2022.06.26.23.47.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 26 Jun 2022 23:47:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::112e as permitted sender) client-ip=2607:f8b0:4864:20::112e;
Received: by mail-yw1-x112e.google.com with SMTP id 00721157ae682-3176b6ed923so75551937b3.11
        for <kasan-dev@googlegroups.com>; Sun, 26 Jun 2022 23:47:45 -0700 (PDT)
X-Received: by 2002:a81:6ad7:0:b0:31b:a0f1:c093 with SMTP id
 f206-20020a816ad7000000b0031ba0f1c093mr6336295ywc.400.1656312465509; Sun, 26
 Jun 2022 23:47:45 -0700 (PDT)
MIME-Version: 1.0
References: <20220521143456.2759-1-jszhang@kernel.org> <20220521143456.2759-2-jszhang@kernel.org>
 <CAAhSdy2yT26QournxS4Zf6L8oMj5Bs6BEjuW56NHapq=cXOEww@mail.gmail.com>
In-Reply-To: <CAAhSdy2yT26QournxS4Zf6L8oMj5Bs6BEjuW56NHapq=cXOEww@mail.gmail.com>
From: Atish Patra <atishp@atishpatra.org>
Date: Sun, 26 Jun 2022 23:47:34 -0700
Message-ID: <CAOnJCU+2QXdCkf7g_cnQ+yMoFABc7bfKZ8=5sOJk2uQhS8+Uww@mail.gmail.com>
Subject: Re: [PATCH v4 1/2] riscv: move sbi_init() earlier before jump_label_init()
To: Anup Patel <anup@brainfault.org>
Cc: Jisheng Zhang <jszhang@kernel.org>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexandre Ghiti <alexandre.ghiti@canonical.com>, 
	Atish Patra <atishp@rivosinc.com>, linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Sunil V L <sunilvl@ventanamicro.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: atishp@atishpatra.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@atishpatra.org header.s=google header.b=RUqSR0Aq;       spf=pass
 (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::112e
 as permitted sender) smtp.mailfrom=atishp@atishpatra.org
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

On Sat, Jun 25, 2022 at 9:33 PM Anup Patel <anup@brainfault.org> wrote:
>
> On Sat, May 21, 2022 at 8:13 PM Jisheng Zhang <jszhang@kernel.org> wrote:
> >
> > We call jump_label_init() in setup_arch() is to use static key
> > mechanism earlier, but riscv jump label relies on the sbi functions,
> > If we enable static key before sbi_init(), the code path looks like:
> >   static_branch_enable()
> >     ..
> >       arch_jump_label_transform()
> >         patch_text_nosync()
> >           flush_icache_range()
> >             flush_icache_all()
> >               sbi_remote_fence_i() for CONFIG_RISCV_SBI case
> >                 __sbi_rfence()
> >
> > Since sbi isn't initialized, so NULL deference! Here is a typical
> > panic log:
> >
> > [    0.000000] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
> > [    0.000000] Oops [#1]
> > [    0.000000] Modules linked in:
> > [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 5.18.0-rc7+ #79
> > [    0.000000] Hardware name: riscv-virtio,qemu (DT)
> > [    0.000000] epc : 0x0
> > [    0.000000]  ra : sbi_remote_fence_i+0x1e/0x26
> > [    0.000000] epc : 0000000000000000 ra : ffffffff80005826 sp : ffffffff80c03d50
> > [    0.000000]  gp : ffffffff80ca6178 tp : ffffffff80c0ad80 t0 : 6200000000000000
> > [    0.000000]  t1 : 0000000000000000 t2 : 62203a6b746e6972 s0 : ffffffff80c03d60
> > [    0.000000]  s1 : ffffffff80001af6 a0 : 0000000000000000 a1 : 0000000000000000
> > [    0.000000]  a2 : 0000000000000000 a3 : 0000000000000000 a4 : 0000000000000000
> > [    0.000000]  a5 : 0000000000000000 a6 : 0000000000000000 a7 : 0000000000080200
> > [    0.000000]  s2 : ffffffff808b3e48 s3 : ffffffff808bf698 s4 : ffffffff80cb2818
> > [    0.000000]  s5 : 0000000000000001 s6 : ffffffff80c9c345 s7 : ffffffff80895aa0
> > [    0.000000]  s8 : 0000000000000001 s9 : 000000000000007f s10: 0000000000000000
> > [    0.000000]  s11: 0000000000000000 t3 : ffffffff80824d08 t4 : 0000000000000022
> > [    0.000000]  t5 : 000000000000003d t6 : 0000000000000000
> > [    0.000000] status: 0000000000000100 badaddr: 0000000000000000 cause: 000000000000000c
> > [    0.000000] ---[ end trace 0000000000000000 ]---
> > [    0.000000] Kernel panic - not syncing: Attempted to kill the idle task!
> > [    0.000000] ---[ end Kernel panic - not syncing: Attempted to kill the idle task! ]---
> >
> > Fix this issue by moving sbi_init() earlier before jump_label_init()
> >
> > Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
>
> We are seeing a similar crash when booting kernel via EDK2 with RNG enabled.
>
> Shell> fs0:\Image root=/dev/vda2 rootwait console=ttyS0
> earlycon=uart8250,mmio,0x10000000 initrd=\initramfs.cp
> EFI stub: Booting Linux Kernel...
> EFI stub: Using DTB from configuration table
> EFI stub: Exiting boot services...
> [    0.000000] Linux version 5.19.0-rc3 (oe-user@oe-host)
> (riscv64-unknown-linux-gnu-gcc (Ventana-2022.05.16) 12.1.0, GNU ld
> (Ventana-2022.05.16) 2.37.90.20220201) #1 SMP Thu Jun 23 05:33:13 UTC
> 2022
> [    0.000000] OF: fdt: Ignoring memory range 0x80000000 - 0x81200000
> [    0.000000] earlycon: uart8250 at MMIO 0x0000000010000000 (options '')
> [    0.000000] printk: bootconsole [uart8250] enabled
> [    0.000000] efi: EFI v2.70 by EDK II
> [    0.000000] efi: RNG=0xff94fd98 MEMRESERVE=0xfe658f18
> [    0.000000] efi: seeding entropy pool
> [    0.000000] Unable to handle kernel NULL pointer dereference at
> virtual address 0000000000000000
> [    0.000000] Oops [#1]
> [    0.000000] Modules linked in:
> [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 5.19.0-rc3 #1
> [    0.000000] epc : 0x0
> [    0.000000]  ra : sbi_remote_fence_i+0x1e/0x26
> [    0.000000] epc : 0000000000000000 ra : ffffffff800080f8 sp :
> ffffffff81203cd0
> [    0.000000]  gp : ffffffff812f1d40 tp : ffffffff8120da80 t0 :
> 0000000000cb8266
> [    0.000000]  t1 : 000000006d5e5146 t2 : 0000000058000000 s0 :
> ffffffff81203ce0
> [    0.000000]  s1 : ffffffff8047586a a0 : 0000000000000000 a1 :
> 0000000000000000
> [    0.000000]  a2 : 0000000000000000 a3 : 0000000000000000 a4 :
> 0000000000000000
> [    0.000000]  a5 : 0000000000000000 a6 : 0000000000000000 a7 :
> 0000000000000000
> [    0.000000]  s2 : ffffffff80dea320 s3 : ffffffff80deabb0 s4 :
> ffffffff81353d48
> [    0.000000]  s5 : 0000000000000001 s6 : 00000000fffde848 s7 :
> 0000000000000004
> [    0.000000]  s8 : 0000000081021714 s9 : 000000008101e6f0 s10:
> 00000000fffde780
> [    0.000000]  s11: 0000000000000004 t3 : 000000001467a415 t4 :
> 0000000000000000
> [    0.000000]  t5 : 00000000007627e0 t6 : ffffffffbc865574
> [    0.000000] status: 0000000200000100 badaddr: 0000000000000000
> cause: 000000000000000c
> [    0.000000] ---[ end trace 0000000000000000 ]---
> [    0.000000] Kernel panic - not syncing: Attempted to kill the idle task!
> [    0.000000] ---[ end Kernel panic - not syncing: Attempted to kill
> the idle task! ]---
>
> This patch fixes the above crash as well.
>

Thanks for the confirmation.

> Reviewed-by: Anup Patel <anup@brainfault.org>
>
> Thanks,
> Anup
>
> > ---
> >  arch/riscv/kernel/setup.c | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
> > index 834eb652a7b9..d150cedeb7e0 100644
> > --- a/arch/riscv/kernel/setup.c
> > +++ b/arch/riscv/kernel/setup.c
> > @@ -268,6 +268,7 @@ void __init setup_arch(char **cmdline_p)
> >         *cmdline_p = boot_command_line;
> >
> >         early_ioremap_setup();
> > +       sbi_init();
> >         jump_label_init();
> >         parse_early_param();
> >
> > @@ -284,7 +285,6 @@ void __init setup_arch(char **cmdline_p)
> >         misc_mem_init();
> >
> >         init_resources();
> > -       sbi_init();
> >
> >  #ifdef CONFIG_KASAN
> >         kasan_init();
> > --
> > 2.34.1
> >
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv


Reviewed-by: Atish Patra <atishp@rivosinc.com>

-- 
Regards,
Atish

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOnJCU%2B2QXdCkf7g_cnQ%2ByMoFABc7bfKZ8%3D5sOJk2uQhS8%2BUww%40mail.gmail.com.
