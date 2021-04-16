Return-Path: <kasan-dev+bncBDFJHU6GRMBBB6WT4WBQMGQEZM6LBTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EA05361E24
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Apr 2021 12:42:03 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id re9-20020a170906d8c9b029037ca22d6744sf1881281ejb.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Apr 2021 03:42:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618569723; cv=pass;
        d=google.com; s=arc-20160816;
        b=P5yfo9ru6r9zKP1fdaBzWkU1PBBU4DYD9lVemJVIsNHFwxhEBjV5pDFzCTmU/DSc7o
         vactjvYdEuPW9j3vQqEcyzSJ8eaTrHrnD2aUX5kLEYq5JSviLx5CIyNVC7rsCC5/KhiG
         U8gEL5fFG5TtPv7bB+TXdGUU+L5UuaI7PmctxN/WVdANeNdXLCnXFgZdcZDsVwLvCezP
         XPvdd+QgoZ5P/E7guYJoYO/BSNH9rPe7mH7HZca2fU7iZpO1RJ8ZVzx0hNLjuNmBVRWR
         rKcBYAr9ctPfeblWVceAA0lsRAMnQ10x7tfG4sYgpe8Q7zSVe+4uruR2GI8BFXQJFyU5
         31MQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=4atAnqju4GSvYhLI/07yBZAHIMgYETiUZinMa2iHxo8=;
        b=o3hK+CIHnBQp5Jlbuj3Yc6Cfc3sVdiUF9zWLGOz4dPvs7jW1EWclEwa+masTo9Ybqz
         Kxdq16yYu8diMJAzYZ8Vfm6qB+aY0RmEqJQj4I04L2lgjUAPphAtCPkQvwuMmXJVpgqM
         pUxEQ6v2uhuVHTNnVPwm2UkQcGTcZNKEW6927x72FQe6TPBg7lL3zh7ScmSTH2LRX3dw
         gG2nKUsYt/u0D3ypsJ36bLc+8XNKi2uoZzD8SLaAK2zcOLEuqL5zSUv6zaWZxBHSoRuV
         zhV/LZvosJZrjzUkIKVdPFNZs87IDf/3ntZi+nzi/+y/LCyAVkTaNh2h+yfUhXMDef/U
         g2pQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b=o+NE8pGA;
       spf=neutral (google.com: 2a00:1450:4864:20::334 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4atAnqju4GSvYhLI/07yBZAHIMgYETiUZinMa2iHxo8=;
        b=AFZLIWdPA8Q2k3TFhKpnwOlePNsLU+k9qwLdxiiK9JEcn3rzF5kuYwK0yUHhsNnxTM
         HcGpSIUYype0FQer95mjixoopSRx82GXNZBka2VEcpz6L3y2DfKwVcKvfFJyQh79qE/8
         OU8nevAq3mlo+7YyqXPngylQtdES5ZqW4uBLAfFN33164CX74rIYVqmqptwMBtEOJ+Pu
         2oCuC04TqxevM3DH5Ftx1jsn1YAbVn6F6JuJLf5z0/YVR3APuRhYIGccDajypGFyXHpb
         hSNPE8aF9j43mbJLboKQpXxY1YOJLX6BgaJtON9wLTDgFevx5lgSrspbptxJ4bkTsBE/
         yZIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4atAnqju4GSvYhLI/07yBZAHIMgYETiUZinMa2iHxo8=;
        b=hxR3t3N2+rp6WPHTdKI8ct04e2vlg3+X+OWmbpPcY51Y8Vx6LLTNc4FTaShdEuI4Af
         nXy6no48EURSR9GD5x2zVo+JqvR8e3zylT/abw6y7lA8iid0rIoQN+gQpDm/fDTjb3ew
         EIECQ/C2mO+JVmsZYjpRi3l+m+ZrdPrYiHvNh8WQiL1Urvo9SUK4L/xolj1NZNZaxTD5
         Qyl5cTek4iYm2BKSLNelWxNiOyJaWyK/p9SN5QjjDBgGW0x5QW1Lhf3yjvRY1dLZY6zC
         gCMBsX4fv5+jVVriHBc8YYEY/EoUZ38GmV3bu2T2SqN05o+B7fksIrgZjanM2CEUPq6h
         gyvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533CAvOgShUTMSyXCpocJpQAtPraqMUVskVTLVDeeX+szMSJ2htb
	DM5ZSkldCCT4aBGo4wWXPyg=
X-Google-Smtp-Source: ABdhPJyaaVF6xIDJoo8LBg86QKwu6+pPQWq0kgOBdbZ6OMoaru88y/S/xx5eGD9/tJnZo1Gm+4X7Dw==
X-Received: by 2002:a17:906:804b:: with SMTP id x11mr7946570ejw.388.1618569723044;
        Fri, 16 Apr 2021 03:42:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4c2:: with SMTP id n2ls8147831edw.2.gmail; Fri, 16
 Apr 2021 03:42:02 -0700 (PDT)
X-Received: by 2002:a50:ed10:: with SMTP id j16mr9145194eds.29.1618569722094;
        Fri, 16 Apr 2021 03:42:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618569722; cv=none;
        d=google.com; s=arc-20160816;
        b=ffxVbdjRCKPDc3cOBi+k+dgX/yu1i4WUFXscMo8huyVdDR4lw9iqlXYIKZb8dXGhoH
         xlys6lzjOBInT5ym665AYTFgTzscy7wcfdeXNXeVKscPKQpFaXx49+F9OGtYur/eTbSj
         2/6VOqFyCXrZfKmCCQDv9EYndRmX7m6QCJKdUQAGufwlIFPcUMBLDM1+6Ig5lWg1LaPW
         RoFy0W86tlrUcmBHDF1CaV4VOKjyP4EMd8HkuILmy+I0OuoTJOg/gnR1E9iDmoEoZMST
         7GKY1ba31bUIj2HLxxFeQVwSmDXkrJWZ7fxqJXTB5yLo+KDICmlixVsFoay6B4+hSwRt
         btqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zex7i7Gm7ilDvh/qRtb14tTVDUsTiPnIyJ8lJBlTVDY=;
        b=u3CjpTJHt4wDcYug3deL3nq2Tj4cNuTjOALK9rHblR6+EcH6ujpT6gOj1Yi1Qk9IFy
         WJmNwPiJp2rHp3xlsfM8j51ujdheOJPN3n+1HMD2EczyDqFLbRherWgoDRW9y19V5r+D
         r9SaEAScVxDrRHJ1wb4KQr+Wy0ld6GNXV7Tvt7s3TGSk3FAX/Ff1DT2wZ+73hKHtKQ9E
         KDJMq6X445+wK6ppHhcNFvg5hgpzvpgOG3fo3fArhHQKN9jJFzBefNCD+1dUsS8ORS/A
         8dwPjmaC8AbM1pr06GEFJe3ZS6yAH80iDfdgDWVBfOPCA13JQVx5j9Dls54NGA3hakVg
         Dd6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b=o+NE8pGA;
       spf=neutral (google.com: 2a00:1450:4864:20::334 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id co24si112979edb.4.2021.04.16.03.42.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Apr 2021 03:42:02 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::334 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id y204so12649347wmg.2
        for <kasan-dev@googlegroups.com>; Fri, 16 Apr 2021 03:42:02 -0700 (PDT)
X-Received: by 2002:a7b:c348:: with SMTP id l8mr7746989wmj.152.1618569721686;
 Fri, 16 Apr 2021 03:42:01 -0700 (PDT)
MIME-Version: 1.0
References: <20210415110426.2238-1-alex@ghiti.fr>
In-Reply-To: <20210415110426.2238-1-alex@ghiti.fr>
From: Anup Patel <anup@brainfault.org>
Date: Fri, 16 Apr 2021 16:11:50 +0530
Message-ID: <CAAhSdy2pD2q99-g3QSSHbpqw1ZD402fStFmbKNFzht2m=MS8mQ@mail.gmail.com>
Subject: Re: [PATCH] riscv: Protect kernel linear mapping only if
 CONFIG_STRICT_KERNEL_RWX is set
To: Alexandre Ghiti <alex@ghiti.fr>
Cc: Jonathan Corbet <corbet@lwn.net>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Arnd Bergmann <arnd@arndb.de>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, linux-doc@vger.kernel.org, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623
 header.b=o+NE8pGA;       spf=neutral (google.com: 2a00:1450:4864:20::334 is
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

On Thu, Apr 15, 2021 at 4:34 PM Alexandre Ghiti <alex@ghiti.fr> wrote:
>
> If CONFIG_STRICT_KERNEL_RWX is not set, we cannot set different permissions
> to the kernel data and text sections, so make sure it is defined before
> trying to protect the kernel linear mapping.
>
> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>

Maybe you should add "Fixes:" tag in commit tag ?

Otherwise it looks good.

Reviewed-by: Anup Patel <anup@brainfault.org>

Regards,
Anup

> ---
>  arch/riscv/kernel/setup.c | 8 ++++----
>  1 file changed, 4 insertions(+), 4 deletions(-)
>
> diff --git a/arch/riscv/kernel/setup.c b/arch/riscv/kernel/setup.c
> index 626003bb5fca..ab394d173cd4 100644
> --- a/arch/riscv/kernel/setup.c
> +++ b/arch/riscv/kernel/setup.c
> @@ -264,12 +264,12 @@ void __init setup_arch(char **cmdline_p)
>
>         sbi_init();
>
> -       if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX))
> +       if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX)) {
>                 protect_kernel_text_data();
> -
> -#if defined(CONFIG_64BIT) && defined(CONFIG_MMU)
> -       protect_kernel_linear_mapping_text_rodata();
> +#ifdef CONFIG_64BIT
> +               protect_kernel_linear_mapping_text_rodata();
>  #endif
> +       }
>
>  #ifdef CONFIG_SWIOTLB
>         swiotlb_init(1);
> --
> 2.20.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy2pD2q99-g3QSSHbpqw1ZD402fStFmbKNFzht2m%3DMS8mQ%40mail.gmail.com.
