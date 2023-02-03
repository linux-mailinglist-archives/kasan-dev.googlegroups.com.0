Return-Path: <kasan-dev+bncBDFKDBGSFYILF7PSTYDBUBDSBFN2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B34F689160
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Feb 2023 08:58:44 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id l36-20020a056122202400b003e9f114f777sf1890694vkd.10
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 23:58:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675411123; cv=pass;
        d=google.com; s=arc-20160816;
        b=JEqnUQCUFqENGaDwj29p/9+KNhSXggmG0VS0t4cJZGJMmzULO28eiw5YcqnYnUEGZh
         u9BJKC/my6MA5HcfBqDFtqqte7gvnSkxTE4uDDogiRhL8u25MU0qk01W1HtvCkt1rRkk
         uWDLtG1dmAaXQ7lvqbOsX2vyc8Wu8AHtsgBmSXxyn2PtWKRj0pRDI3WOkdcpdWrNdxeP
         /F2ZNRKPwVEB15Mn4zVbONv2bbjovHoBLvX2vs6yWiyA3USqvyKHoEZvuTBx31BBS1/E
         5jdupXozDOKBmPr64nFRAvlwi6WgEJisJGNSIaQJUVfP7vIn0jFOApGbXqiuojMgbPHW
         5N+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=1/XIBQBQSmVvVqgrIJDRJ6DDJPcwJzkVF2+9wu8fX4E=;
        b=JQMduiLKmYGFS0DaLeVlndqKdlbcrH6cT9JAUfgs5xrlXOrEKb+pgpWC0BxFma9buY
         YFKY94JDYxpmCKDbRY+OHRPQadwiEd2msZDxBNwPNzn2kMv6cSiI42KJHNjaMBcNB7l9
         7mfk8JeiUcofFVbVR4w6l0HcIoF8AxhgTT9Yai2jw9Jq/N6d6yP60rNHRcC2nEoupieG
         mC1CZBHuHTghP/YDXTyVlHD2N5P7ZWzf+AkkaGxWrMealz1IxgWs1Q4eobeKyNzkaQtO
         4tPEwBPonTR46M0+A8ZYQnPIq1kxDt82+2hwl20VVgCn0QiXYa3Bsp5wobXjYqH+bOm1
         VO9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@atishpatra.org header.s=google header.b=Sh7tY9cH;
       spf=pass (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=atishp@atishpatra.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1/XIBQBQSmVvVqgrIJDRJ6DDJPcwJzkVF2+9wu8fX4E=;
        b=thu/XzaoL3ET9YVtuWGSv0ya4v/cHAEboV9gE8jT83tS1ofFrpJExfJlxjAP5RmS8f
         IpM1V3PKCVZ8b/u0XQjU9Z+zuFTx+R5vZSHpNtMfp9C7/Z95XXBn1oeZpfBECAL6sk/y
         iLMeHbh5an7/oXODNqUJHWqvnQZHJCaqIyQheHXj20MXZFHgqUyzkVc82x/pIFl+cg4f
         CpYacr23J8CNVf5vsEbOF6Uu582DL38GE6G6ikEnW/CTMlnSgdWcsRJy7R6NFsH9ZYnc
         /U8stUvTZCauzTPrR9X/gdfa4jJ62iM69LtfCzPKLWZ8hxM37okLOjeSl+Efcdwpb2Ha
         p9hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1/XIBQBQSmVvVqgrIJDRJ6DDJPcwJzkVF2+9wu8fX4E=;
        b=f9qKR5YkhfgNdmPH3e30xaiy4XJRrOyGcbXzVSDQEvGzM767dS9oxTu3EOgJOklpKt
         rhfVhCeJ+C4NZw9Oapp6LGU2zdm85xWQ2YARww3phSwofeZBDnrUYzb4NpXKH5ceQLxe
         PmM7KeHtnMYx36Jbdp5Vp7zR/X12o38F4ZwIcI3y5xSMILhNcDw+fAjqRwr1yIX9h9g6
         8ES5Cl+JlAg5Ey46Mgoa2JJbqdppxwYNSanMQLFGc+OcoY8n1bfKDHdHRcOcHgvqoOe6
         Sr6Y0Ja40bQKEu2M9vIqdqrnMJtauARlDRW9Kv0FFPYJj4zaQjCBPISDvCIQcmHRY2QC
         kOhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXmfwVNsVhpWxXdV30XmotHiLAaIWgvG2EeC3oMjIYrRY/r0g6J
	Awi8cKMNpoCWXtr/LxXInp8=
X-Google-Smtp-Source: AK7set+XgciKONF049LhkLRonh9vt+7esEp8C/0h/WLZ4+6/jE6nqICLcUn0f48xsb8Xq+d+oCsAcw==
X-Received: by 2002:a67:cb97:0:b0:3e9:272:76c with SMTP id h23-20020a67cb97000000b003e90272076cmr1574006vsl.64.1675411122896;
        Thu, 02 Feb 2023 23:58:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:bf56:0:b0:3ea:5bfe:4cd1 with SMTP id p83-20020a1fbf56000000b003ea5bfe4cd1ls728478vkf.4.-pod-prod-gmail;
 Thu, 02 Feb 2023 23:58:42 -0800 (PST)
X-Received: by 2002:a1f:f445:0:b0:3e1:56b8:9feb with SMTP id s66-20020a1ff445000000b003e156b89febmr4975600vkh.7.1675411122240;
        Thu, 02 Feb 2023 23:58:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675411122; cv=none;
        d=google.com; s=arc-20160816;
        b=P/RIiZpUDh2WCzVTMTXCBZ5e96wE4CBfsbsfLbNubBvDWYVI0Nbq/6MPwZOhFXDIJp
         796FrMidsTLzckUCT2I5+ZdHGOrXDvTbBFn/NVwApg7c28My0xn+pxdL2ZwpbLbM4KeC
         /uXhgjyfajciKTe6DD1rUcvdV1YKwCgO/bt1w341Nd4nEoGCR2caaNFNyCnkibSGe95P
         lV2MKR6VyESIsVEAFRcpxVNuxkO7kGdC0swS8EXo7njrZo4toBcgm4453SoMjpFEmmTo
         R/lvUGcSG86p/2GlaW599x7VX+vhabDAm+Kzc3eF9b+4V5I8510yOiYOGyeoJf7ea6d6
         2Eng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=i99J2pmlc+pek02YkZ8nESdE1CjXKdwjOkhiDfukAeg=;
        b=SOlch7qIAkULaxQOFo90powmSeHTJNaOySuqk/bVDEs5fBI8e/PBOKujsLzV35uwxu
         fF/sn8zsR3ACuOtamEOX6XvuW8bfKU9tf7BHLCNXaOr1gBdX7I8wGaYvlKdkeAlX2fG3
         KWAX+mTg3tCTDg3+F93Pc2ilw7Axj3MCGimUB6fydPWAOMPFUi2Sq4XyVv69A8cL3UG6
         p6YonUiofUeJMovFrA3G8AufD+L/4AMKdAGxsindJho4R1+HdtqIfQqmag00cDBtD3iw
         EKXmyhGUrpS/AIvA6sTe1ikZAU5PCnqcBVjh4CXFlHVP+TV9W5T4miXDjZ8/dp6UdHZB
         WAsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@atishpatra.org header.s=google header.b=Sh7tY9cH;
       spf=pass (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=atishp@atishpatra.org
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id d27-20020a05612212db00b003e1874cbfc8si132367vkp.4.2023.02.02.23.58.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Feb 2023 23:58:42 -0800 (PST)
Received-SPF: pass (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id e6so4453650plg.12
        for <kasan-dev@googlegroups.com>; Thu, 02 Feb 2023 23:58:42 -0800 (PST)
X-Received: by 2002:a17:902:ecc1:b0:193:794:ba9 with SMTP id
 a1-20020a170902ecc100b0019307940ba9mr2238861plh.22.1675411121784; Thu, 02 Feb
 2023 23:58:41 -0800 (PST)
MIME-Version: 1.0
References: <20230203075232.274282-1-alexghiti@rivosinc.com> <20230203075232.274282-5-alexghiti@rivosinc.com>
In-Reply-To: <20230203075232.274282-5-alexghiti@rivosinc.com>
From: Atish Patra <atishp@atishpatra.org>
Date: Thu, 2 Feb 2023 23:58:30 -0800
Message-ID: <CAOnJCUK==Ma=p0mLLRJBB=3qTyMOTbiDNVYSmXpJr0HCsZ8Kxw@mail.gmail.com>
Subject: Re: [PATCH v4 4/6] riscv: Fix EFI stub usage of KASAN instrumented
 strcmp function
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Ard Biesheuvel <ardb@kernel.org>, Conor Dooley <conor@kernel.org>, linux-riscv@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-efi@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: atishp@atishpatra.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@atishpatra.org header.s=google header.b=Sh7tY9cH;       spf=pass
 (google.com: domain of atishp@atishpatra.org designates 2607:f8b0:4864:20::629
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

On Thu, Feb 2, 2023 at 11:56 PM Alexandre Ghiti <alexghiti@rivosinc.com> wrote:
>
> The EFI stub must not use any KASAN instrumented code as the kernel
> proper did not initialize the thread pointer and the mapping for the
> KASAN shadow region.
>
> Avoid using the generic strcmp function, instead use the one in
> drivers/firmware/efi/libstub/string.c.
>
> Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
> Acked-by: Ard Biesheuvel <ardb@kernel.org>
> ---
>  arch/riscv/kernel/image-vars.h | 2 --
>  1 file changed, 2 deletions(-)
>
> diff --git a/arch/riscv/kernel/image-vars.h b/arch/riscv/kernel/image-vars.h
> index 7e2962ef73f9..15616155008c 100644
> --- a/arch/riscv/kernel/image-vars.h
> +++ b/arch/riscv/kernel/image-vars.h
> @@ -23,8 +23,6 @@
>   * linked at. The routines below are all implemented in assembler in a
>   * position independent manner
>   */
> -__efistub_strcmp               = strcmp;
> -
>  __efistub__start               = _start;
>  __efistub__start_kernel                = _start_kernel;
>  __efistub__end                 = _end;
> --
> 2.37.2
>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOnJCUK%3D%3DMa%3Dp0mLLRJBB%3D3qTyMOTbiDNVYSmXpJr0HCsZ8Kxw%40mail.gmail.com.
