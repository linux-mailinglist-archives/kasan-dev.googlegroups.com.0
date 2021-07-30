Return-Path: <kasan-dev+bncBDYJPJO25UGBBTEASKEAMGQE4BFLLYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 300DB3DC135
	for <lists+kasan-dev@lfdr.de>; Sat, 31 Jul 2021 00:42:21 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id j11-20020a05600c190bb02902190142995dsf3587723wmq.4
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Jul 2021 15:42:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627684941; cv=pass;
        d=google.com; s=arc-20160816;
        b=WhxPPEA42SEKUNA6PhXmktCPigP0jbilU75egD3WA7uzBncwec+8dfUjPQe/PIQagS
         ehTK67bQ8+QFgJ9l72rTvWJm1x7JmgPE0dCasF7S+ZAxVLfKWz2TiwXgfjJlFFcWWNkB
         Zm8Y8/vKypuUJk+/ZQ74JXg/NT+aTLAEIJn3Is5Nm3p4rFHibtddHulQL9DPDajOzgSl
         i4pd6fkY7N1JP7DbgXNBo8ThS8VeBuvzcPLYDIu9G7R6qrLqqJOFQp7bNq9L7jJ8bDZA
         1dhul96fr8wHHrX9+iLKijB7tI2+N8iPFVUwhLRKfVC4RfIIC1ewBWe42ljhSvSsWwJn
         Vtmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8Pn8jHfYFmBZeyIkIzhga5OthrZ8X1AvPK/tujao0g8=;
        b=HNJKanZg9vbcx8yNrJV3JqGYBvVGaVaHRtkiQGK+eY4f/c7K3ygWjxqY2lfr9kFxPD
         s8cdkNpnpi0Lworw4cTwAWO7EeY4MlDdfGDELBoJErQ3m4FNsL6kjp8AvRVETku2bshd
         RGTRV7KXAHfJ7lMnH8KDT6jpbzHwwpKszhMPKxxBdmOr3URNqLCqyc03FDra5tvxFFIt
         AjHUkij1UMuZOqamP+HFZB7/NegQdDVvtsiB8m2DDBb1KQKw8uRobqFrVxtE+pWKFMNS
         kQyiHnL/aadatHeltJzmSYUGSz00zkwhzCH3NDU0Y78ezNzqFJhYEVbWUyYmrg8S4bFy
         Xbmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CamcDOtb;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8Pn8jHfYFmBZeyIkIzhga5OthrZ8X1AvPK/tujao0g8=;
        b=CSJlL8+b0bFJ41hJC5s0LeOH+MfgfMConIPUWatx2eErAJ1SzTSfPVSPzhTbpzmxdT
         s7Ux/ZcCVuPtGGirX56NeePHL1uskKVoj8N3qVADQNg4hLBf4kpM/8y6CL5V/PARPaXH
         R7Cscw4zgmhKVf50OW7X/Wq7zpd6lz7sOTHBYDiZ9UH20UZrM97B3zJDWob/CTxGbxNH
         jxYtst1ueXbADcowcXawZrsnB+CB68tffm1onT+b+htnz1sN+ZX/GZoiloB/Ya9LxR5K
         qsAjoLNyUqtklJ9CQteZtHB3wTIoU10bDo9JGfwIovOAGKv0V8qciY8KB27w1AuzwRob
         ygYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8Pn8jHfYFmBZeyIkIzhga5OthrZ8X1AvPK/tujao0g8=;
        b=ZnJjrweNd40lBECkpu2sLhdWI7nP++cYm2qXH/hDQu6w7P6B4/bw15BhRHdY0hWU89
         dABI3EUVoXLRp0XV7oBKxkC1SGxF03muf8W38KfRAoFOdfmoW5m5l6y5QaQIvjIsQhoZ
         YEYDzOKxTyVCtR4jqc8tOcbOvE9hPSjSbEtQa8VgEYGc3pvtbeT126z+UqW+0MKzPeGM
         4TJeFcpZEjhVJjsjOHyUABJSyHhVzZRiI2dwBbZWS2hOatztGbBoK/OcVq94nY8sJII3
         yfVCDaDkD+UGE2nVWQEn9QjZHEBabsr76mbtpEG673eqi18QE49xhmMzoGGT/KuZHP/U
         IJcQ==
X-Gm-Message-State: AOAM533rMPMrc/OWUUOOg9pi9AQXbTDsoUwoArIkVeoY5Drhqih7KdUT
	P45eA4sl7vMp4uoZKH6Tcbk=
X-Google-Smtp-Source: ABdhPJzHDIl+sjjCqClZjKaNITaD0kmbExhcNx1xigau7lu2J9OvZa2BunqW77SlWlAGwI4AsjNTvg==
X-Received: by 2002:a5d:4207:: with SMTP id n7mr5463439wrq.326.1627684940924;
        Fri, 30 Jul 2021 15:42:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cb09:: with SMTP id u9ls1699347wmj.1.gmail; Fri, 30 Jul
 2021 15:42:20 -0700 (PDT)
X-Received: by 2002:a1c:4e1a:: with SMTP id g26mr5307667wmh.52.1627684940048;
        Fri, 30 Jul 2021 15:42:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627684940; cv=none;
        d=google.com; s=arc-20160816;
        b=h54C9CQMVqMIBhhlxxcuZzYSV3+cur4HfU6jQ2ABPI6aPglYKgQpfppyH3fY7Ro/nZ
         nDZi+TbjNuRGiH5lkq6CT8x/gJzlf8z2seaUEQxdTQvvggHwiGRsgqeWUIfFeuXeeKdA
         OKKk7+/970qVBI4Yfw7qlWE1vQJJbJeeCsX5llFY6l0UXnoL2GA182c/GTPTsWztyMha
         WD0zqVHAMfkKllZFnQN2k0pvWGXz090Q7K09NcSU46Awql4hjODijSgtV8N48b7KQ1Gr
         Nw78bRscDnggS2x2HMBuAGdoPFMgBE7KLfSojJ2ZWElV2rrai8jOFghXFZIsli8mzq0C
         MA5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MvaRlaXK64PpiXVCxXFWPZrJ6CRVJKhlEggaPSUWrrw=;
        b=TqNRYepD+es0VdrYs4cx8iSGo2x8xpEJlwRnyq1vA5R6zAJQxApNpqFRDr8H6OOOE8
         vk0DihjMZlYCn9VtXOv3HSOe8ew1jfuZ39uNLW5tyBhcWCLFoj8ffvtfqV6rnyUkQ+8u
         3ALs6GPr/Zkzxo+fzKLysIURn1dGSpj79mc2cWsX9iSRB5Lu95j65MWE+K7cXOHdZMZZ
         VZV4HEAIinCRFqIWRjoCbZKhPmV8Zc3kli6vlO4F/tNA1QozcZQ+cyvliylWvLHa7NzF
         3H+/oCniMfBQJjjg/x6GWHO6hkZ7wdZEoGYVOKbWuG2dNvko0Jw/6qEKjtUAnYsxAlru
         E67g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CamcDOtb;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x230.google.com (mail-lj1-x230.google.com. [2a00:1450:4864:20::230])
        by gmr-mx.google.com with ESMTPS id u16si183757wrg.5.2021.07.30.15.42.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Jul 2021 15:42:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::230 as permitted sender) client-ip=2a00:1450:4864:20::230;
Received: by mail-lj1-x230.google.com with SMTP id n6so14458880ljp.9
        for <kasan-dev@googlegroups.com>; Fri, 30 Jul 2021 15:42:20 -0700 (PDT)
X-Received: by 2002:a2e:a911:: with SMTP id j17mr3212666ljq.341.1627684939283;
 Fri, 30 Jul 2021 15:42:19 -0700 (PDT)
MIME-Version: 1.0
References: <20210730223815.1382706-1-nathan@kernel.org>
In-Reply-To: <20210730223815.1382706-1-nathan@kernel.org>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Jul 2021 15:42:08 -0700
Message-ID: <CAKwvOdnJ9VMZfZrZprD6k0oWxVJVSNePUM7fbzFTJygXfO24Pw@mail.gmail.com>
Subject: Re: [PATCH] vmlinux.lds.h: Handle clang's module.{c,d}tor sections
To: Nathan Chancellor <nathan@kernel.org>
Cc: Kees Cook <keescook@chromium.org>, Arnd Bergmann <arnd@arndb.de>, 
	Fangrui Song <maskray@google.com>, Marco Elver <elver@google.com>, linux-arch@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	clang-built-linux@googlegroups.com, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CamcDOtb;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::230
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Fri, Jul 30, 2021 at 3:38 PM Nathan Chancellor <nathan@kernel.org> wrote:
>
> A recent change in LLVM causes module_{c,d}tor sections to appear when
> CONFIG_K{A,C}SAN are enabled, which results in orphan section warnings
> because these are not handled anywhere:
>
> ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.asan.module_ctor) is being placed in '.text.asan.module_ctor'
> ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.asan.module_dtor) is being placed in '.text.asan.module_dtor'
> ld.lld: warning: arch/x86/pci/built-in.a(legacy.o):(.text.tsan.module_ctor) is being placed in '.text.tsan.module_ctor'

^ .text.tsan.*

>
> Place them in the TEXT_TEXT section so that these technologies continue
> to work with the newer compiler versions. All of the KASAN and KCSAN
> KUnit tests continue to pass after this change.
>
> Cc: stable@vger.kernel.org
> Link: https://github.com/ClangBuiltLinux/linux/issues/1432
> Link: https://github.com/llvm/llvm-project/commit/7b789562244ee941b7bf2cefeb3fc08a59a01865
> Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> ---
>  include/asm-generic/vmlinux.lds.h | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
> index 17325416e2de..3b79b1e76556 100644
> --- a/include/asm-generic/vmlinux.lds.h
> +++ b/include/asm-generic/vmlinux.lds.h
> @@ -586,6 +586,7 @@
>                 NOINSTR_TEXT                                            \
>                 *(.text..refcount)                                      \
>                 *(.ref.text)                                            \
> +               *(.text.asan .text.asan.*)                              \

Will this match .text.tsan.module_ctor?

Do we want to add these conditionally on
CONFIG_KASAN_GENERIC/CONFIG_KCSAN like we do for SANITIZER_DISCARDS?

>                 TEXT_CFI_JT                                             \
>         MEM_KEEP(init.text*)                                            \
>         MEM_KEEP(exit.text*)                                            \
>
> base-commit: 4669e13cd67f8532be12815ed3d37e775a9bdc16
> --


-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOdnJ9VMZfZrZprD6k0oWxVJVSNePUM7fbzFTJygXfO24Pw%40mail.gmail.com.
