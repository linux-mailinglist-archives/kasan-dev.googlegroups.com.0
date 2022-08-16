Return-Path: <kasan-dev+bncBCU4TIPXUUFRBCG352LQMGQEDNAVMPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 35264595E81
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 16:45:30 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-1048dffc888sf2703843fac.11
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 07:45:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660661128; cv=pass;
        d=google.com; s=arc-20160816;
        b=z3bbarYgyu9os93noS9j3iczcOFGFvoSllyCKwA83HcI7Kws5+S/9VA8uPyEVL9CsH
         5UpGa5lQqrrLl7sUIzuGY4xTm06n4i7JHb5byffcaZHr5oFIrGfzt/ldvQ5yv5WbECBm
         3r0Fso0XMhupC4qzLGv71aHuPaDA1KQXhUaQe6ySgyl7wjOtWN/teaoC8ybIsditjH+/
         0HZ11iQAbeOe8SQ0y15D26MfxI8KSNf6ZmRtV02lhsLt6UvPisZAuoaH0j491xFK6AcZ
         hQBC+z2tTZfsJwgOS1Qztwks6Vn1Fzr1qFKafuYpWHxyrtKC0BvjTvTEWdlH/FFg1hS3
         XjYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=kq/a3Q+GrgP1b1nowus+hDQlyR/Vfs90Re8PQz2wKoo=;
        b=bcUK3+V5vPzdLYNswXm7ILEHym4VYedIh126Pi+AgJszE4uz68eSXTFKD23ioN4aIX
         MFS1BeekcBXaoIQmmnnUq4LSSthxss5LPTDK9kL0+rm+5oXjIlnbyMrPC5c+hM3KIxF/
         JYJn3bqSL+E5y+9qx94UERoAS9gc0WwntZZQ9Xa7aZIBlOZp0aKtmqWY4binshduXvIP
         /LEj6BzeC1mpgDae3BzOrCe/qSQmp17u1HHTHE7EPfI98pv+1hqjfnZTSPLrkRd/TqwC
         qQPxWW0T+yKya+7cHcYAYwp6n6/1y8qNy/QOKFUCYYz/CFwoPtioLOP75mdM6/LFowVI
         moBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=V99ax+ID;
       spf=pass (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc;
        bh=kq/a3Q+GrgP1b1nowus+hDQlyR/Vfs90Re8PQz2wKoo=;
        b=P5KklmSiwvRC+HPg2hKjP5Qi4THjM61vG6sZ4BRqhDrcvEA8p47wfM2cOxosTq9/+A
         svjVskguYDf/NGmKkkmpARVlvclhH7qt0/JR+dxyTbdOLvzp2Blg92ZgSam8ypuo4Flt
         Srzp/2LjcfZgxcI1uePBemqT5jPukVIUtB1koJvEgI6fk0yeFNB2Ya6uVEo/FgB2H7k7
         ap28N+0DXu5Qd+Xr8OOWwu8XOzmUnWuYiitVG13K3M+Y7hVoqETg/gK5qbihefPIK7JY
         3tdCpmx+zLjpp7IkAVNFS+8Nq7qISPwdEhpa6zxvxgnk0pPsZ1utyOz+2Sp2mY9JK8y3
         EHfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc;
        bh=kq/a3Q+GrgP1b1nowus+hDQlyR/Vfs90Re8PQz2wKoo=;
        b=n0Jv2caiOdqajKtCPUdhPkjGO8j5IUOSJetpX4kh6lJSn5OecHT8gwXSFksPLsMW2D
         jzhSMCTBeTPe/aLcnfCrab5g0aN4LWhd0BXaFHIeDcfkrcmBjFwTC/yb3zPReMUQnDxy
         Fa4j+BmjpTk5JpVuBTTg3G40URt6vhJPg5Zq93dblVxPL5UVh+OfxXGrXXhKJy7nkFFw
         neckux8GXbXqEo57MafIXzdq+z0E93B4Z+H2H3P49bx4ftzlHmZG5UKlpg8T3WMlJxxo
         N6+j8GmrSfNXAeN1UllZIibzv6lqJbvnftrfel2GP+WSJw9KHofnOhqLKWBJKut50mMX
         X2gw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0ttoZLizw3Q5xQvy1bdNJC6nPult2Z230TbnVCeDJ59Vc3Ydkw
	0ObdeGN+Xwl02HAu60ZWdZU=
X-Google-Smtp-Source: AA6agR7+fByMgswDF+mdDGqsfd8KtrWT9fKBjVL7/7TbUkzp/5Jku1vEU/JGoEzPv8NPGLIkSkEnjA==
X-Received: by 2002:a05:6808:2d7:b0:344:a080:7e8a with SMTP id a23-20020a05680802d700b00344a0807e8amr4230268oid.10.1660661128717;
        Tue, 16 Aug 2022 07:45:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:20d1:b0:637:18f0:d52 with SMTP id
 z17-20020a05683020d100b0063718f00d52ls2009381otq.8.-pod-prod-gmail; Tue, 16
 Aug 2022 07:45:28 -0700 (PDT)
X-Received: by 2002:a05:6830:58:b0:637:1974:140a with SMTP id d24-20020a056830005800b006371974140amr7841240otp.362.1660661128275;
        Tue, 16 Aug 2022 07:45:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660661128; cv=none;
        d=google.com; s=arc-20160816;
        b=TQaX/w02c8juIjrys00nlZ1bq1L9i0eiNKMFOJ6J9eZz2MyrjFy2W/FFuOjukJTKRl
         FfuV6mCatN7qVxNwVsLgJOchHm+xdgYYrAPw+kYjcADC6csyR8rnJJkWbOH9NIUNrTK4
         KEGgBsYus0YFOLvY0l/yvRsomAOb0wHzw2inUy16Zw4F1cEp+eSc6BRU4nJt7F+Jenzj
         AqIvYO2U3qo+og/JNFDf/2X2GBaErSZRca79y3H6KFM9vbJDDOBfT3QwVXHdsIfYZ5vj
         K7CSwH7bmKhHC6Ikp6j6bFpvpdLmoGHNLiG9mi2RJmxHO4fwqkIhvtDXMxxfxlO1Klb3
         Yrvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oX7Uw1GdRzWPUR63yLpyR3Y8vFILF4KqV1mUqs3+f2U=;
        b=CSNL5OaqJQDBTTfKTFhv96bmRp3wTu/vgo5kTbEoTE02Wg9dhy7V27eT4mqyuAZ3Vk
         8jo9ZSJduUDJ+5qAcjGfjJN7JhJESTXAFJfl3Q+CLnRRsOQ49s+Vy5xCX1v2Hmzb82CB
         REGv01HffZNOS8HGF13A1JNaSNOhSehlQmzDJmwwC6Rpz3F1MrjuwCupOUaKqqSdGITu
         HACNP9Nwxn5ah5AHeySK9irrVXAHo5uqhfRW417ebuER3fYsr9sPmmJViDxG0dMBKBOS
         Poq0zi0U0hFqaFLRqa8lPQkDJKwRVAn3jgJRKJtFal1nQAKymcQ6NsiL4Frkkqs+PsHd
         hDlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=V99ax+ID;
       spf=pass (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id h128-20020acab786000000b00344d0712829si219907oif.5.2022.08.16.07.45.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Aug 2022 07:45:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 07C9B610A5
	for <kasan-dev@googlegroups.com>; Tue, 16 Aug 2022 14:45:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 649B8C43470
	for <kasan-dev@googlegroups.com>; Tue, 16 Aug 2022 14:45:27 +0000 (UTC)
Received: by mail-wr1-f41.google.com with SMTP id p10so12903091wru.8
        for <kasan-dev@googlegroups.com>; Tue, 16 Aug 2022 07:45:27 -0700 (PDT)
X-Received: by 2002:adf:d238:0:b0:21e:c972:7505 with SMTP id
 k24-20020adfd238000000b0021ec9727505mr12174103wrh.536.1660661125577; Tue, 16
 Aug 2022 07:45:25 -0700 (PDT)
MIME-Version: 1.0
References: <20220814152437.2374207-1-sashal@kernel.org> <20220814152437.2374207-54-sashal@kernel.org>
In-Reply-To: <20220814152437.2374207-54-sashal@kernel.org>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Tue, 16 Aug 2022 16:45:14 +0200
X-Gmail-Original-Message-ID: <CAMj1kXEzSwOtMGUi1VMg9xj60sHJ=9GHdjK2LXBXahSPmm56jw@mail.gmail.com>
Message-ID: <CAMj1kXEzSwOtMGUi1VMg9xj60sHJ=9GHdjK2LXBXahSPmm56jw@mail.gmail.com>
Subject: Re: [PATCH AUTOSEL 5.19 54/64] ARM: 9202/1: kasan: support CONFIG_KASAN_VMALLOC
To: Sasha Levin <sashal@kernel.org>
Cc: linux-kernel@vger.kernel.org, stable@vger.kernel.org, 
	Lecopzer Chen <lecopzer.chen@mediatek.com>, Linus Walleij <linus.walleij@linaro.org>, 
	Russell King <rmk+kernel@armlinux.org.uk>, linux@armlinux.org.uk, ryabinin.a.a@gmail.com, 
	matthias.bgg@gmail.com, arnd@arndb.de, rostedt@goodmis.org, 
	nick.hawkins@hpe.com, john@phrozen.org, linux-arm-kernel@lists.infradead.org, 
	kasan-dev@googlegroups.com, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=V99ax+ID;       spf=pass
 (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted
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

On Sun, 14 Aug 2022 at 17:30, Sasha Levin <sashal@kernel.org> wrote:
>
> From: Lecopzer Chen <lecopzer.chen@mediatek.com>
>
> [ Upstream commit 565cbaad83d83e288927b96565211109bc984007 ]
>
> Simply make shadow of vmalloc area mapped on demand.
>
> Since the virtual address of vmalloc for Arm is also between
> MODULE_VADDR and 0x100000000 (ZONE_HIGHMEM), which means the shadow
> address has already included between KASAN_SHADOW_START and
> KASAN_SHADOW_END.
> Thus we need to change nothing for memory map of Arm.
>
> This can fix ARM_MODULE_PLTS with KASan, support KASan for higmem
> and support CONFIG_VMAP_STACK with KASan.
>
> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> Tested-by: Linus Walleij <linus.walleij@linaro.org>
> Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
> Signed-off-by: Russell King (Oracle) <rmk+kernel@armlinux.org.uk>
> Signed-off-by: Sasha Levin <sashal@kernel.org>

This patch does not belong in -stable. It has no fixes: or cc:stable
tags, and the contents are completely inappropriate for backporting
anywhere. In general, I think that no patch that touches arch/arm
(with the exception of DTS updates, perhaps) should ever be backported
unless proposed or acked by the maintainer.

I know I shouldn't ask, but how were these patches build/boot tested?
KAsan is very tricky to get right, especially on 32-bit ARM ...

> ---
>  arch/arm/Kconfig         | 1 +
>  arch/arm/mm/kasan_init.c | 6 +++++-
>  2 files changed, 6 insertions(+), 1 deletion(-)
>
> diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
> index 7630ba9cb6cc..545d2d4a492b 100644
> --- a/arch/arm/Kconfig
> +++ b/arch/arm/Kconfig
> @@ -75,6 +75,7 @@ config ARM
>         select HAVE_ARCH_KFENCE if MMU && !XIP_KERNEL
>         select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
>         select HAVE_ARCH_KASAN if MMU && !XIP_KERNEL
> +       select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
>         select HAVE_ARCH_MMAP_RND_BITS if MMU
>         select HAVE_ARCH_PFN_VALID
>         select HAVE_ARCH_SECCOMP
> diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
> index 5ad0d6c56d56..29caee9c79ce 100644
> --- a/arch/arm/mm/kasan_init.c
> +++ b/arch/arm/mm/kasan_init.c
> @@ -236,7 +236,11 @@ void __init kasan_init(void)
>
>         clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
>
> -       kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
> +       if (!IS_ENABLED(CONFIG_KASAN_VMALLOC))
> +               kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
> +                                           kasan_mem_to_shadow((void *)VMALLOC_END));
> +
> +       kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_END),
>                                     kasan_mem_to_shadow((void *)-1UL) + 1);
>
>         for_each_mem_range(i, &pa_start, &pa_end) {
> --
> 2.35.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXEzSwOtMGUi1VMg9xj60sHJ%3D9GHdjK2LXBXahSPmm56jw%40mail.gmail.com.
