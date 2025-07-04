Return-Path: <kasan-dev+bncBCU4TIPXUUFRBKNST7BQMGQEU6PC35Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 34729AF9455
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Jul 2025 15:37:47 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-235196dfc50sf9983325ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Jul 2025 06:37:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751636266; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZxQQQQ4s0KaXMpswG11WN4V5HgC5mLGLp1m+lUnCmU4wOGL4NKUZzypLI8BpeBS7e1
         P9ftExIAemDrmmoPQeARfYVnrOQ9GQ42En0/heqFM46KU2DowAaGzq/TxntjSRBaEORu
         yXAKMho7UtjUyJxLa6wUiFumjk4zikqC6r0i9dZPKDcJWoWMiU/tKdHbz1a2Tu964xoB
         jdrXYe9TkpMVrHHKmWJSoW7zCdBShvzAoDN/QhH6a8L3ekAZkkZ0QveHtsShpf0/puWG
         0wiBl7eR1xZ3oKxRL+2N5WK1lJZOTiNgq6MbX0cAw/VKT/SeLL96U8QVC97O2mAb9hve
         vaEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rOeYaH1AKumLzGYYgocP+iX1ozQqEAgpTHeVbNJdPR4=;
        fh=aIm0gech3FIei28+J1BuVj+P0Mx8iIDPeeDL+6QbK4w=;
        b=YN7LdnMIc09h0cn8XCB+XCKOEhE6EH2HZ9Sdg1EQp3PRtWYbwMvUDLG2IN3WFO5Chv
         ZaGgwVR9uqtTcNUxtvWDLl/1Awu8xjk0HnLGw7YO/GY0My0kPUiWPA8arncSHlVA0vHm
         xm6mJUqsgQsJzZluDaynw2Y/k7LjCML4pcz5QskKDR9ISx4HMd+7BIfswnVzSOywJoQG
         h5A93pWTljxnAvwjFW1xQ+S0fBMiVIJKlruR5nNzQwJvREnB36nnze9aDkd95RKYf+cp
         q45ij9+6DSvHJ0nSHAnuaC+jx2sr6qduRuVcFnfcygKC9/tLAiUTDl2Nqy+72EUcpl9t
         GWHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OpZqH8sE;
       spf=pass (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751636266; x=1752241066; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rOeYaH1AKumLzGYYgocP+iX1ozQqEAgpTHeVbNJdPR4=;
        b=saqGv4xAiyIbejTOvk3PIQWx1vvdWAv8EqGciRIM2QoA0PPEipeSss4xY8P9/UYWUy
         XrYRnIcf3AnH26D9VHVz/jLY62KFKeYM+ybPnfU/yR44E/xf+1WJQMHUD7F1idbK/jVg
         Q9vXkkZUwjIQC1XdjKUvL+eZRdhRthEq/68FFamqueCL3HLy2RmTZg7+t8bL7WIgh70S
         8V+anze9XqENH5Zwcj259RdCxlmNV2OtjpsyeHJLYvF5/e24mPabH6CMbsxdVFPdnCY4
         +uhVIyAJs283ZlhqDruqbKZ40V+khBzX3Zt8N8r83pJzNi0zQiq78nxFx8Sq2dQILlVb
         n6LA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751636266; x=1752241066;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rOeYaH1AKumLzGYYgocP+iX1ozQqEAgpTHeVbNJdPR4=;
        b=oAFOYwhhBwICPWehGf7tSOfMbkcQHYWFTN/EWAa1H0AG3jzrd27A1lg4AJd1P6QQrx
         IKImwKSu66yG0WnAUHaJQisTpBvgK90AXbTJzh1LGPc2/0vxZBnNsWJCAFp06r+cKb4A
         SLWFmUnUEXhwTRLIIZaSUQVetCXPCrYX36vmUC9QW48n5ben9xuFro9UBWdLCg91N2uu
         S4/m5XmmnzRJfMvlBI6hnnuy8zAHEh4yEW1hfC3vUqoD9pvX4Jl1FgSU/RgQqZBiqj/P
         fgg8AsSc3Vag+NK1g8Wkzz86nVbcbDBoPnbru26AoNQ+9k7hkH0MT85EWRpVLIkKuvuh
         nu6Q==
X-Forwarded-Encrypted: i=2; AJvYcCXuvDVg1cP4yzFkHiSd3ZrsfOlNlNmgnj5M/D47P5BiXHlTSkzGFjmsZvATNaQ8WZ5Ty70rJQ==@lfdr.de
X-Gm-Message-State: AOJu0YwTKir2uA2XwoXcdkpqnDAkcssre0DyUZ+MJzWnk3PDmmvrRZvP
	vEaW7F/rGIQUQ18ihfaWE597TsnuBt1ku3PG3Hf9bH6DS5eosYctQvAW
X-Google-Smtp-Source: AGHT+IHEj7TiDPz56XWMn7s7Mz+S3m2tsMqu9DQFXxVC+OWFM+3hHiVn7E9yCbq4pT55yyUnB5p6ZQ==
X-Received: by 2002:a17:902:f70a:b0:236:10b1:50cb with SMTP id d9443c01a7336-23c8598a1d3mr39961405ad.26.1751636265610;
        Fri, 04 Jul 2025 06:37:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcpaQ2uhtHAnlhCYyHAbsPdr+ADpf/w2LZNL0lNSXF1mQ==
Received: by 2002:a17:903:22d0:b0:232:3488:eba8 with SMTP id
 d9443c01a7336-23c89da42e0ls3259015ad.2.-pod-prod-00-us; Fri, 04 Jul 2025
 06:37:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWNqBhdN2fsE5gTmJP20akqdnAqAdhVqjSkcftOhYwhz78YOxFbYvYJwPhMMOtP3L+cExXW+acleEM=@googlegroups.com
X-Received: by 2002:a17:902:d2c5:b0:236:15b7:62e3 with SMTP id d9443c01a7336-23c858ac240mr41226305ad.9.1751636263812;
        Fri, 04 Jul 2025 06:37:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751636263; cv=none;
        d=google.com; s=arc-20240605;
        b=JlJw4rbxQzCl0ovHSjG8w+poAeg1Ct3gJywx3C24V+s9hT3x7Wcl5JwpKYxnbyodGo
         xqIyDzT4LiylKIF3AMMbmG1M4LDoCLJsH5utuSi5VOuoizh0DbuOzBWsRa/92/JLvG1N
         FMjYnasGT7b8iV6B2TLvZVsC/OgEhr3xr0nLm8FMeqS989F7YYE8ergRRlufUNHWWajZ
         09Vedx9tdYPp8OOYEI0U8uyIWZYDrKCyFztIyd4ykp7C3Hym410adKFCQzjbXo5D1Zye
         Ic9utv5q50yim2s+XdIxFcFgVgUuU+86CYZL/OdBhalfSQyabruJ3RA+bMbtMguWsMLR
         sQWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pjUqkqCowpJ5lnZrv17ukt2R2oRrFdKBckxhi5ciuJg=;
        fh=Xe1ad4nQfTpNWN5I1/2XJ6VerOoeIg61gvaPQih+C5s=;
        b=H4Z/qNCxM0ZT6Da0/DIGKx9a7qL/liL8DTc6KITKF6l2UzqgleRZ2Z2Z+dDPgrCJqf
         peDPLXf/jxgYcu9hl1i3mm1kTGHCRk3v7lL7cdrwfnunnnDZZ339ibewxZo3HU8av69Q
         ek8vqA0jPTXC94c9VUN0QJmTXjJOwWtndc07pnd0CKrcvuiRS9tncdyg/97SfGBEZcwj
         SSSQRtEXf38GqrlmqV0Qe17+kX0LFMNJGdLCLVRyoqjp1ecsOtQioNevTJ4vWOiDDk3n
         NI1lZvda3Ri9AuFRUD7KXgiB7bDtyfYALs7q7a8S1NQXJQqHAPZ2VtVSwmVjDcY4enFA
         sItQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OpZqH8sE;
       spf=pass (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23c84517d29si823115ad.10.2025.07.04.06.37.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Jul 2025 06:37:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 2DC955C5CF1
	for <kasan-dev@googlegroups.com>; Fri,  4 Jul 2025 13:37:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D4817C4CEF1
	for <kasan-dev@googlegroups.com>; Fri,  4 Jul 2025 13:37:42 +0000 (UTC)
Received: by mail-lf1-f53.google.com with SMTP id 2adb3069b0e04-553e5df44f8so894116e87.3
        for <kasan-dev@googlegroups.com>; Fri, 04 Jul 2025 06:37:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVzdFYS2ZN9U/26pb6qIcQWh2gGYobCh9g5axiDKdvL9yduqaCDSZ/LMFYFWnI8djUFnFmB4xE6pZk=@googlegroups.com
X-Received: by 2002:a05:6512:1050:b0:553:252f:addf with SMTP id
 2adb3069b0e04-557a1235e66mr609612e87.10.1751636261192; Fri, 04 Jul 2025
 06:37:41 -0700 (PDT)
MIME-Version: 1.0
References: <20250624-arm_kasan-v1-1-21e80eab3d70@debian.org>
 <aGaxZHLnDQc_kSur@arm.com> <CAMj1kXFadibWLnhFv3cOk-7Ah2MmPz8RqDuQjGr-3gmq+hEnMg@mail.gmail.com>
 <aGfK2N6po39zyVIp@gmail.com> <aGfYL8eXjTA9puQr@willie-the-truck>
In-Reply-To: <aGfYL8eXjTA9puQr@willie-the-truck>
From: "'Ard Biesheuvel' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Jul 2025 15:37:29 +0200
X-Gmail-Original-Message-ID: <CAMj1kXFUjJmJjR3b2S8pZeEheKojJGCYjRWRQDS0EbDYhGEUVw@mail.gmail.com>
X-Gm-Features: Ac12FXxDoYAyne6f9LFfkIyFnAPNWAnIdZPy1iEe6SjskHRpB5hKeukxa0EcUu8
Message-ID: <CAMj1kXFUjJmJjR3b2S8pZeEheKojJGCYjRWRQDS0EbDYhGEUVw@mail.gmail.com>
Subject: Re: [PATCH] arm64: efi: Fix KASAN false positive for EFI runtime stack
To: Will Deacon <will@kernel.org>
Cc: Breno Leitao <leitao@debian.org>, Catalin Marinas <catalin.marinas@arm.com>, usamaarif642@gmail.com, 
	rmikey@meta.com, andreyknvl@gmail.com, kasan-dev@googlegroups.com, 
	linux-efi@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kernel-team@meta.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OpZqH8sE;       spf=pass
 (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Ard Biesheuvel <ardb@kernel.org>
Reply-To: Ard Biesheuvel <ardb@kernel.org>
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

On Fri, 4 Jul 2025 at 15:33, Will Deacon <will@kernel.org> wrote:
>
> On Fri, Jul 04, 2025 at 01:36:40PM +0100, Breno Leitao wrote:
> > On Fri, Jul 04, 2025 at 10:26:37AM +0200, Ard Biesheuvel wrote:
> > > On Thu, 3 Jul 2025 at 18:35, Catalin Marinas <catalin.marinas@arm.com> wrote:
> > > > On Tue, Jun 24, 2025 at 05:55:53AM -0700, Breno Leitao wrote:
> > ...
> > > > >  arch/arm64/kernel/efi.c | 9 ++++++---
> > ...
> > > > >  static bool region_is_misaligned(const efi_memory_desc_t *md)
> > > > >  {
> > > > > @@ -214,9 +215,11 @@ static int __init arm64_efi_rt_init(void)
> > > > >       if (!efi_enabled(EFI_RUNTIME_SERVICES))
> > > > >               return 0;
> > > > >
> > > > > -     p = __vmalloc_node(THREAD_SIZE, THREAD_ALIGN, GFP_KERNEL,
> > > > > -                        NUMA_NO_NODE, &&l);
> > > > > -l:   if (!p) {
> > > > > +     if (!IS_ENABLED(CONFIG_VMAP_STACK))
> > > > > +             return -ENOMEM;
> > > >
> > > > Mark Rutland pointed out in a private chat that this should probably
> > > > clear the EFI_RUNTIME_SERVICES flag as well.
> > > >
> > >
> > > If VMAP_STACK is a hard requirement, should we make CONFIG_EFI depend
> > > on it for arm64?
> >
> > What about if we make CONFIG_EFI select VMAP_STACK? I think it is more
> > straight forward from a configuration perspective.
> >
> > I thought about the following. What do you think?
> >
> >       arm64: EFI selects VMAP_STACK
> >
> >       Modify the ARM64 Kconfig to make the CONFIG_EFI configuration option
> >       automatically select CONFIG_VMAP_STACK.
> >
> >       The motivation is that arm64_efi_rt_init() will fail at runtime if
> >       CONFIG_VMAP_STACK is not set, so the patch ensures that enabling EFI
> >       will always enable VMAP_STACK as well, and avoid having EFI disabled in
> >       case the user didn't set VMAP_STACK.
> >
> >       Suggested-by: Ard Biesheuvel <ardb@kernel.org>
> >       Signed-off-by: Breno Leitao <leitao@debian.org>
> >
> >       diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> >       index 55fc331af3371..cc2585143f511 100644
> >       --- a/arch/arm64/Kconfig
> >       +++ b/arch/arm64/Kconfig
> >       @@ -2437,6 +2437,7 @@ config EFI
> >               select EFI_RUNTIME_WRAPPERS
> >               select EFI_STUB
> >               select EFI_GENERIC_STUB
> >       +       select VMAP_STACK
> >               imply IMA_SECURE_AND_OR_TRUSTED_BOOT
> >               default y
> >               help
>
> I would actually like to select VMAP_STACK unconditionally for arm64.
> Historically, we were held back waiting for all the various KASAN modes
> to support vmalloc properly, but I _think_ that's fixed now...
>
> The VMAP_STACK dependency is:
>
>         depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC
>
> and in arm64 we have:
>
>         select KASAN_VMALLOC if KASAN
>
> so it should be fine to select it afaict.
>

I agree - we have plenty of vmalloc space, and the memory footprint is
the same so we should just turn this on unconditionally.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXFUjJmJjR3b2S8pZeEheKojJGCYjRWRQDS0EbDYhGEUVw%40mail.gmail.com.
