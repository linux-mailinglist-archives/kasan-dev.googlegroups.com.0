Return-Path: <kasan-dev+bncBDFKDBGSFYIPNW5HSQDBUBARESHN2@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E6915301C7
	for <lists+kasan-dev@lfdr.de>; Sun, 22 May 2022 10:02:00 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-f1d49b94d4sf5704202fac.0
        for <lists+kasan-dev@lfdr.de>; Sun, 22 May 2022 01:02:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653206519; cv=pass;
        d=google.com; s=arc-20160816;
        b=FJHIgOQy9P0cgWtzq8J1WsPvXHA9S6TNTG7TxX04Fx+G0QLBsnNP5k4LYWZXuDN7lr
         lq1i5PRDNHjsMKETebkoC3SmDKPveMVxrHp+a/OU4lDAG77gUDTCaKVkM79CC9dKNdlk
         S272O3UOUgXkOGCEUApGOBud5A1xaY/DmBrJYfBSI7a3RqQ7yTpj+J77/QXRs6k2PrTL
         OGrd2smQbBIBN2HB4ME+z5OWSd8zu9I/uuQVuoRDYlcrlf8wMFHIYgWwo44xSbuEkhWe
         N0I34XX+WBt485Oy4198tRbPx9Z0p1Hj041mFQQf3jj6t6g6uHJW15uG4OYa50lod/3S
         TT+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=yDDZowzH7X5dFxiXUu35l1FSCifrHX02zQryvPFhH8E=;
        b=appHR53rjmisaI5sCQQeOI98X3oVJyxg7c8kkdhZ2Pc5tZwNLxqIpVjHrjisX+9rSn
         8aF71Ol5MlkCnFyiHcgkKVeX/l1QL0X5tpBGP6HyNAkZMiD0G9Oh+20Mlwauy4RMwvuO
         4DxL8bkjwg09PgpDbOQrF67CD/oWfde2xauC4bIKpBEYi/A3v4rOQO/2vOCkQL4fTLAN
         OB+82N8yOx22Ma0QJJaJvoaAX0AX58vWpNqxIRBUA6hDA43pD6e7u1KA3BJmpUI9zlh4
         lLzOFHPfBenCQN0qSFrwgYq/2Bp3MfMLYrLMF439QJ5FRj/ZK82jFngyy/OKJ3FRFGZa
         9nYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@atishpatra.org header.s=google header.b=MBJcy6x7;
       spf=pass (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=atishp@atishpatra.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yDDZowzH7X5dFxiXUu35l1FSCifrHX02zQryvPFhH8E=;
        b=POhBGXZEzySxHinsj7TJIyf3fSmkiWw64lYsv3qrzxjdVFfMc8HBFW5AQcg59tdzFL
         nHccT/hu/TXsMES7ZrPTe1YreCXuGUVtoylx9EHs0u/7hK2hgCX/0q0qnrwFGGO7eJUe
         NPHlzOOAvo+h3bC/2u1LJkltAk4BsV47f3aK6vy3o4T9ohGlmYahsHf0bQMipJxAnS2p
         AVcu3j6+Pl/Y9ecSlgCrzazXoMyBFAacnxQdKE8Pp0/ifONrx/CGCJGke+ixIU1cxiTX
         mwqQV3ZEV+cSUQDEmhk7+vIE7/IFvNim+YgsI9YCBYMQCZjulelPG/2pzOUrWTlkcgXZ
         5VTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yDDZowzH7X5dFxiXUu35l1FSCifrHX02zQryvPFhH8E=;
        b=c3DaZjMIGHM0EWDllAliY2lyAbcHhkCQ4lu/s4qLuJjkBillYf1gIlkgOesV3vtFEP
         wcZVRcF9CVMi3giRQp87FoE2YJgRPDh2/b2IRFJkFUVpRz302L7fiDCaBmxhRqVcy3cg
         xLBox7EC66wnifO14DLuCVWedRKsCtoBjxC0tNoaYSWE0uMBxWtWukiNecaRoOBGEeC7
         5kaeKv2Qnb96/GPN/najBKYAP/b+5S4r/ADowNJjjse4Q+42Pl29wn0FFLQ9RHVYE25N
         qrSnz0MT8fvLYga1rLCG0Obd6tNiz6wz64BSLIi1NygMX7UJ/1XBmta61fXV4fhtdKUF
         i+kQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533t5V7dBYWEBtvSGcqv/tLuyiewsM5j+2cXk3ue+WWfUaDimp1s
	Xp0vI9evbhOoAVpOaRfvC/I=
X-Google-Smtp-Source: ABdhPJxGsj/X1IQPRVU9APUcWhLp3mtxe5H0QXdAErKn2Z48zRwc6MJ8IwNttwXSAjKoYZS2crhmYw==
X-Received: by 2002:a05:6871:797:b0:f1:d49b:2f3b with SMTP id o23-20020a056871079700b000f1d49b2f3bmr9150249oap.40.1653206518901;
        Sun, 22 May 2022 01:01:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:4cc:b0:32b:a70:4ae2 with SMTP id
 a12-20020a05680804cc00b0032b0a704ae2ls1765614oie.4.gmail; Sun, 22 May 2022
 01:01:58 -0700 (PDT)
X-Received: by 2002:a05:6808:1392:b0:32a:ebeb:deca with SMTP id c18-20020a056808139200b0032aebebdecamr8086039oiw.26.1653206518470;
        Sun, 22 May 2022 01:01:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653206518; cv=none;
        d=google.com; s=arc-20160816;
        b=oeJjiP/Qf+lmzv1rGT/rgZj//BKePKvLmqppz6Yy+sqIbAE0XNP2MmvWQXsW4DbKg/
         nWfnpvuPYu8+4Tmmiz95umFJ2+hgEsULeBnsNiXAPoM4c/6y7emUOZDeDFez5ls2l+u+
         qCKz/uMc21a7HtD93tgHG4aS63xwlSElPQbdTHjV+1N6665FUpYkyJc5AriFbGZkmibH
         vDXk8/z9lbtFAhYXZOZ6jBns0u5Ud/SmrxDSKW1hZdth0kp2m4Grk3DKsh9CluMH+8XJ
         glc5tC9F9VlyTLhc+v813i/L3BKOhXSN+6w5cFPsJOBDL8OZMfo8t971Xf17fq0/ZNEK
         OY9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iTR4F6Zdd5GmGSK+3VogNeE1cHs24uCXuHYRDacHFH0=;
        b=Pe8MUBD3Kfr9OZQCNEW5aNTLo1b1Xjd6quh+g3yQxAa8SaJ/rFjSte6H9jTX+HtL7U
         D5JTbgdeQk6RboVgYwR9r5Z0VN/vxKgqHBDQaG/+IYtwcDGBJJ2wzSvBf4tAPlCTnkhd
         oPvaEfq4HuPE/3lU2dtV1ygQi7iqBNDNFd08KmjPIUI6mNoN/+iDAoH4KxRoQ/sizPzy
         teJyQomqA4AORiKdXpAC+d9YkwMO6PDdLHIpe3Ir0xQbXMqSXeuXeAxHuQ/TZ56FPnda
         0h0BNV1szr//dBREnAi21a02rS4WkcvthMbVG2vjDt1AeoJPba7x2az/Qd4pLaXcgczP
         Gksg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@atishpatra.org header.s=google header.b=MBJcy6x7;
       spf=pass (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=atishp@atishpatra.org
Received: from mail-yb1-xb2b.google.com (mail-yb1-xb2b.google.com. [2607:f8b0:4864:20::b2b])
        by gmr-mx.google.com with ESMTPS id z11-20020a05683010cb00b0060626ec0327si366931oto.4.2022.05.22.01.01.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 May 2022 01:01:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::b2b as permitted sender) client-ip=2607:f8b0:4864:20::b2b;
Received: by mail-yb1-xb2b.google.com with SMTP id a3so20538375ybg.5
        for <kasan-dev@googlegroups.com>; Sun, 22 May 2022 01:01:58 -0700 (PDT)
X-Received: by 2002:a25:941:0:b0:64d:da87:62ff with SMTP id
 u1-20020a250941000000b0064dda8762ffmr16707944ybm.459.1653206518170; Sun, 22
 May 2022 01:01:58 -0700 (PDT)
MIME-Version: 1.0
References: <20220521143456.2759-1-jszhang@kernel.org> <20220521143456.2759-2-jszhang@kernel.org>
In-Reply-To: <20220521143456.2759-2-jszhang@kernel.org>
From: Atish Patra <atishp@atishpatra.org>
Date: Sun, 22 May 2022 01:01:47 -0700
Message-ID: <CAOnJCU+peNAHCWGvNhHV30h0t9oM5f3f_5=AtbHae=S8SrDAVA@mail.gmail.com>
Subject: Re: [PATCH v4 1/2] riscv: move sbi_init() earlier before jump_label_init()
To: Jisheng Zhang <jszhang@kernel.org>, Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Anup Patel <anup@brainfault.org>, Atish Patra <atishp@rivosinc.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: atishp@atishpatra.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@atishpatra.org header.s=google header.b=MBJcy6x7;       spf=pass
 (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::b2b
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

On Sat, May 21, 2022 at 7:44 AM Jisheng Zhang <jszhang@kernel.org> wrote:
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

@Alexandre Ghiti : Is this the root cause of the panic you were seeing ?

IIRC, you mentioned in your last email that you don't see the issue
anymore. May be you avoided the issue because alternatives usage
was moved but root case remains as it is ?

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
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv



-- 
Regards,
Atish

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOnJCU%2BpeNAHCWGvNhHV30h0t9oM5f3f_5%3DAtbHae%3DS8SrDAVA%40mail.gmail.com.
