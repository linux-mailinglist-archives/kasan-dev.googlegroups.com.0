Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSUE2X6QKGQE4DIA3GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id C4A672B8121
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 16:48:27 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id l189sf1100777oia.3
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 07:48:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605714506; cv=pass;
        d=google.com; s=arc-20160816;
        b=fSjGePC0z8RybjXUsfGKfvhpkOdc0suZNvIFgzWxGfdTg6vbSkS6QorrPfeM76tD5l
         zHIx951zbIBvRO6Zs284l886Wmn5UI41T1pexaaXxznr2CNjHBpOdsucshmPtovLrK7i
         Yszjxv12Y+uuL/4+lJIckP0Zre1jeGJGmrpY+hLE5P5T6HtbgnipGNIwBbslXR66TFqX
         SrXTHKh1LTKOb0Hda8Wp/4GW0LcleCT0pHFByLrPraCqq0bNoF7xsgSLV0yK2+bMat/X
         72PGi+Zjwxxye16u5He/MfFD8E3pC5ks0SEl8xpd2tFPM4sK3HWpkfWat6TmaRQMtX9e
         nN3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xSaNJxsYtnWsOQ2fLefeBJZjhIFiEFueY/0KpAtepLY=;
        b=vUKrl/n41v+YZAVavqp4wVtuJSAmipWRQvDaPHcuhr/DiNKZMW0SBDssavbSWFarQf
         deTSJ3TYFtVTS+EjuL+Ur44eh9Nr4mR1orN/5D00xf5Sr+U4l7Vr8glfqabAimEDn89t
         gdB1HIgfNQNTYCz8NLaG5Ni7Sa2hgGo8SYyHEqe2yS755JLBi9jCRM6bnBs+gHvQn7gA
         9G9UsAmNQJ+JDGrECgx/5R/qvNS8a3CwKlY34F2d520/gKshugRIsoKidDt7x7zzimsz
         GU0wzMeknn2EF3t25/O5rGPzikwOhYnqVnadr5RmFft03bL7T0B6Vwzm1lJCvwUn9Fp5
         cE8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DjawgnSV;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=xSaNJxsYtnWsOQ2fLefeBJZjhIFiEFueY/0KpAtepLY=;
        b=F0NqPXepEJNm0PHP/pxAQWXm+w2oVcNjUQm13SSDTfZvHDLUe1dEaYwBG+vFaxgp5l
         POpZVerR95zEDULjW+WlOhcNrvZn9Zse7CbYUhiZ3cxtkXXU/ncaD9q1iOBgUmgKSyO6
         /sO8boD1Avh0f/+hhN6RePoFpOshPnpSzLdj0hmVqzaWMQCXmoahVAxTc7BX5THzDWfm
         V6ijWGkXIlTEihIh7QKePcXyYy+JGXDJIcKjGg5FQsujE2pvo14g3xZ+3+fdlEu08Vs6
         UBclJgduWaSRsVz8yNUmEIEWtGceMd7k9daSoAQ0MUQs0Ho04/4HaI4mJoR7sRRJQexw
         T4hA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xSaNJxsYtnWsOQ2fLefeBJZjhIFiEFueY/0KpAtepLY=;
        b=PJfk5lW60Cj0hLrAWTZnsbEMHPu7kiZrudTA4HnOiAVSUAI6Vrx4T0hGZfYpsf5gz0
         Enog5lTMODaJGGR4mUMt3845wYqXd3hhTveJ4hHliyt8muTTPXqtoK2xxhRWDAsNmLPs
         PUUwjI0VAKHHlrjC5I8F3tEtiNlEh9aMzJaG016cWkJ4Uv0XezFnapBHyUj2tMzqjUEc
         qaMf620OdQDrD8AUAwh+/+DUabrs5nfDVlcDq9kgSYHRgW+LA2k8GrhchXqOotmZWO7h
         uFicikduwXd8IPawiEAmUORiFtabwAZgWsgme7GBHFrROisi2VPU5E0SKcnXgd2sR6sP
         ikZQ==
X-Gm-Message-State: AOAM530u63jIr/do5ZzHV2ZUK9thfbe+WgxL40jT0B7zI2W7vsN0Id8h
	SgW8A2C6Uzgq6cYb+04JCeg=
X-Google-Smtp-Source: ABdhPJwkBPCuhPNWdfT5yH65A+qRvtirQTpPiPSWJPc+boRcXgFa9gZQ6wjmh2xDKjxCYDgZed8f1w==
X-Received: by 2002:a9d:190a:: with SMTP id j10mr6812507ota.264.1605714506457;
        Wed, 18 Nov 2020 07:48:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:dd84:: with SMTP id u126ls3678593oig.6.gmail; Wed, 18
 Nov 2020 07:48:26 -0800 (PST)
X-Received: by 2002:aca:e187:: with SMTP id y129mr424081oig.61.1605714506064;
        Wed, 18 Nov 2020 07:48:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605714506; cv=none;
        d=google.com; s=arc-20160816;
        b=jIi2QNm3TyifPzERTo5wNLLRbmVrh4nIyf+zRZJon/yYJgDKXIgni6BX6o9AEoOYx7
         jnn2tvAJh2EV8yeddOacWT7AoSveXKkIOywkqIa2a3psR7yhd0dTxRdSOmFol+8QzdzX
         QDNv+a5WvyumXhSyybpBwWjiccfKVCtG7EbyFSSJ6tKmhbK+LWkzsnYwaRrLu+yWC2eo
         nAPKjHULmudAhL16R5Cx9p6R1EjfoPlIiCH+LBXOTKjnIYiFx6QVBKt98wH/0nQmDVy4
         W0V3hzXQ82rsbJzqJ3HZ+1aDs1oQPjNNGOXYQlce4jEMLLjTllkw59hsayj15ovqzFS3
         2pQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KBY9We200Ww5HcRzOJ8cRuFVemnXKCvdsbdmO5AOcVM=;
        b=eiQBb5chVIV0lqzAwpPmMNSTYgORf/sOuzHgQ6gCWcShqqCzYTiTXlIsarmF7CXy6Y
         Uwc3fdk/lFI1rLlT5Z4LWeaiLhVRzMOTN2nPI3hbHDR24y8FfjYdrPoJDc0kq6OTCBdx
         Ta1ByZF/apGwgUy4kbMqGxbJ+wlDqkdsq7cFY5Z1wncUxqO6SMq9r6BY9KXpy3JUZYfC
         6r6F2U9gpyR9tJppk7YiLSHaUpqAG/TvyjxJH5Ax/VgsXTU3eVeitYWcq0v0xYY5z2BJ
         8aLMmUwuTha8Jn0JyFwsb60WD7V1e7CcSRBv+PqImxmGpxbFL0PwkaLPM94HavwzG6kw
         hRcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DjawgnSV;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id i23si1728203oto.5.2020.11.18.07.48.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Nov 2020 07:48:26 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id r7so2214221qkf.3
        for <kasan-dev@googlegroups.com>; Wed, 18 Nov 2020 07:48:26 -0800 (PST)
X-Received: by 2002:a37:b545:: with SMTP id e66mr5394773qkf.392.1605714505255;
 Wed, 18 Nov 2020 07:48:25 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com> <ba9dc492214fea3a88e05544bb0697b3237e743e.1605305705.git.andreyknvl@google.com>
In-Reply-To: <ba9dc492214fea3a88e05544bb0697b3237e743e.1605305705.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Nov 2020 16:48:14 +0100
Message-ID: <CAG_fn=X4Wpn3oTUwgRPHXnWtBQtmH3VURbzpC5=xiDtzGw2bcg@mail.gmail.com>
Subject: Re: [PATCH mm v10 24/42] arm64: Enable armv8.5-a asm-arch option
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DjawgnSV;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::741 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Nov 13, 2020 at 11:17 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
>
> Hardware tag-based KASAN relies on Memory Tagging Extension (MTE) which
> is an armv8.5-a architecture extension.
>
> Enable the correct asm option when the compiler supports it in order to
> allow the usage of ALTERNATIVE()s with MTE instructions.
>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
> ---
> Change-Id: I172e15e4c189f073e4c14a10276b276092e76536
> ---
>  arch/arm64/Kconfig  | 4 ++++
>  arch/arm64/Makefile | 5 +++++
>  2 files changed, 9 insertions(+)
>
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index c999da4f2bdd..b7d1f1a5705d 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -1591,6 +1591,9 @@ endmenu
>
>  menu "ARMv8.5 architectural features"
>
> +config AS_HAS_ARMV8_5
> +       def_bool $(cc-option,-Wa$(comma)-march=3Darmv8.5-a)
> +
>  config ARM64_BTI
>         bool "Branch Target Identification support"
>         default y
> @@ -1665,6 +1668,7 @@ config ARM64_MTE
>         bool "Memory Tagging Extension support"
>         default y
>         depends on ARM64_AS_HAS_MTE && ARM64_TAGGED_ADDR_ABI
> +       depends on AS_HAS_ARMV8_5
>         select ARCH_USES_HIGH_VMA_FLAGS
>         help
>           Memory Tagging (part of the ARMv8.5 Extensions) provides
> diff --git a/arch/arm64/Makefile b/arch/arm64/Makefile
> index 5789c2d18d43..50ad9cbccb51 100644
> --- a/arch/arm64/Makefile
> +++ b/arch/arm64/Makefile
> @@ -100,6 +100,11 @@ ifeq ($(CONFIG_AS_HAS_ARMV8_4), y)
>  asm-arch :=3D armv8.4-a
>  endif
>
> +ifeq ($(CONFIG_AS_HAS_ARMV8_5), y)
> +# make sure to pass the newest target architecture to -march.
> +asm-arch :=3D armv8.5-a
> +endif
> +
>  ifdef asm-arch
>  KBUILD_CFLAGS  +=3D -Wa,-march=3D$(asm-arch) \
>                    -DARM64_ASM_ARCH=3D'"$(asm-arch)"'
> --
> 2.29.2.299.gdc1121823c-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DX4Wpn3oTUwgRPHXnWtBQtmH3VURbzpC5%3DxiDtzGw2bcg%40mail.gm=
ail.com.
