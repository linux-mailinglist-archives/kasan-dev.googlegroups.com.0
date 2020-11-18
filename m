Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7UL2X6QKGQETQSOCKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 521412B8161
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 17:04:16 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id n10sf1458203plk.14
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 08:04:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605715455; cv=pass;
        d=google.com; s=arc-20160816;
        b=O0TpWTD3x/YNsgtlm2otRz+SbQYhAibGum/l/g96/8gsyhw6GR61twl+X56gqQY24I
         c8aGZ/OOAaqqXbFeKZNntj6UMxjGnTQNx4UXurlegDBQJVu1HOI5Iud25MxTqVNoaITD
         0nQcWDZ/HwLQOa2mUBS7O/2VjAGWTBNkzBsrtNv6pxsKqsl0dt477tZuAdvcdYh7c3Xf
         VZq75ay38BL2wFQV5vc6Rsf6wdRkWKAnCJyRvIszGuuHT53OA42vvyCytQY3eY9oF+Bl
         wUU13MPOB2TvTCjO+zOnhJfrogXYhICa/devu/ehZvhya0zT+PA+ThpvQTWgsYK1J8Xl
         pTJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wtSRGeKUoQZ4xwbjF5khUNqMLdMBjmED2vtzLorXntI=;
        b=HeWZkEhQAtVNIUU7KkZqWot4iVu+nqJTCwEbOb/OaO0JvCv+C7rfoyK39nMaQyrsVn
         a8P5NBGu+I4Y393kyM5O/ro9yGSXpUARANOvoqdeSJR9lLJtSrOIqpplZAfvfZBwemN7
         1Kn6fl4vBZkSt9wIMLvneYCPfyb95zBXFg0AvH7J7Sae2443Jvtndmkd9150FAzqfCfd
         ozXgqP03ASQ0XNItlzFNQkYhVAwV51N9GEQ4F+Jk9MfT5WhCPnl7DtEcG+PoFNQ6Fvt+
         CpwOPejeDIoFJYABvUQGHS73g0eW7Cds9S6BFgQbzBVkoN2S7FIuWKoCAi1BE23SQq7D
         AwPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bkJ9XPUm;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=wtSRGeKUoQZ4xwbjF5khUNqMLdMBjmED2vtzLorXntI=;
        b=agn7gS2xzLt/E5IcDP+DmEGMB5rx+XDEmwcN5Q4mbVGdNFm6Gb9gmaIfOlC9DmNOcP
         a5LGkq0bulSZTH51UVKcGWMRVs/WOadiGeOGgvgmT0xa3UKnpTNJ9klhTqTaJbhbhFVQ
         6BOXK2xG8R5fmz27fPSt72jLnAGwPwzk4+9vRbjR1psMLDxz4LoN++e9Tn629Dvkox2b
         Z+dJvTJ9kb2wxnSNaZmuh659lVvQHuYnMg9SaSlsaGw+RY30x0Hl9cB0ytHXDhKVO3ja
         gROgTucmZrhwuXFcQ2/icskA+kXyikWb8Hj5eD9VnxniuTmyptTFCB4TOo1+NVR8Q8kl
         ebgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wtSRGeKUoQZ4xwbjF5khUNqMLdMBjmED2vtzLorXntI=;
        b=B8jmJXdRHLwsX0iTPcroh162R2l+EeigM2QUQv6aW3WycuTBWjxXNAUCgyxXY+jbxT
         bYaRelCvTENPCVgooz+J1uJbEZ6h5UCmT87nQsiFQDKpdnBIXUvU7wr2Y++5GQovl62X
         vfTMm44D+4ryKH+0v2WNlo/UeKVhZPgb7ZHRVAqQe8r5vyBqClfJ5RFJLvr79gCF96dQ
         ICYPoxm8SKoJtmhXLi18MZpMoCYxap2FMa38Cf+CPSR+/lJXizpzwI+k50OYEMHPy7xN
         SNvaLsLW4q1CqDiPdjbDbbod6wjkh06JBF4ceF57+5BBCO47+0z60jrzkWq0qkAj+B7Q
         L2yg==
X-Gm-Message-State: AOAM531AmqNahfV2mGZXY0+3NWSkyEpPr1/ZIako0zPrY1Q1MVNQo1v7
	veSDRKuYgPegNIxilutHO4E=
X-Google-Smtp-Source: ABdhPJzrbt95SgwOHR3K2tfHKKEcXQ67JdkEButFYuh+fVq2CRM2u7hVrRKyucHhMImZj3g5exJRBQ==
X-Received: by 2002:aa7:9315:0:b029:18b:6372:d43e with SMTP id 21-20020aa793150000b029018b6372d43emr4922651pfj.2.1605715455063;
        Wed, 18 Nov 2020 08:04:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:5909:: with SMTP id f9ls7329170pgu.10.gmail; Wed, 18 Nov
 2020 08:04:14 -0800 (PST)
X-Received: by 2002:a63:2243:: with SMTP id t3mr8990863pgm.447.1605715454375;
        Wed, 18 Nov 2020 08:04:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605715454; cv=none;
        d=google.com; s=arc-20160816;
        b=tjX3uwdSU9uI0eBFvHelFn9mO6WrDR/m6acKGy4FBbNxpS7TFV6uJ2IfYfk0jEEBAM
         PEUl/csaWLLx8goTUIIjza8zaXTbwmK/LS2OWX+GEOKz/YynQi34fz7CjWcC0+uUn2G6
         R0NrgFOqfv7BTTxg69Ivsn/aSNolCPZgWs6aI8giWiPHoOOjAzmyR+W/geKhDBX1vgRw
         eF7TvGoCAY+PnzJGu8z6Nv2cjnWmfZxQzX8+FiWMwL25D7/KTJ2rGgp5doNSe8QXx302
         CostuJqvQiTsWdmbKh0QTJ9ykIlb5DGsRc4eTBzM1vHD2vgxjJVWtTCJHuzHnv7Cngc8
         qPRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=mlFiY9rY2V1HzrQlBE+sq5fSkw65JXH+u+EE2Nk2n44=;
        b=oqRLaqR6B6JUz8b0omCh3B2h+xW1qv65OyobnbXs3+K8q9BUnvor5mwEZxW3jUS4Ae
         F2tsu9CAx7qwKKFhnQOGRQtrhHa7Xux/xqmehYBJtoYvtJgFIAZW7jbCpF9Sun+szqoZ
         lWFBa9LX55wsD5W2EmmLveEEvF7dLdz6ZkmhyJb6EZYBtGlHpM2eq1TCmQhajQzVWibf
         9QQPKmiAcycJGCeDBV3uRW69W6jLbTlyJLBPieOmyI22A43Vptbca2WL9viSC3y0sHHD
         67AxAkHfiQye9TFvITAyYBswWrRjtIqJ+YFUYQTQJ1GQQBr5Lsb121ozVC7nl7obBuoO
         lUWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bkJ9XPUm;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id d2si1819805pfr.4.2020.11.18.08.04.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Nov 2020 08:04:14 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id 199so2233592qkg.9
        for <kasan-dev@googlegroups.com>; Wed, 18 Nov 2020 08:04:14 -0800 (PST)
X-Received: by 2002:a05:620a:f95:: with SMTP id b21mr5514724qkn.403.1605715453444;
 Wed, 18 Nov 2020 08:04:13 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com> <da7fc94554c52c63f957d82e46c5bc8a718b2b96.1605305705.git.andreyknvl@google.com>
In-Reply-To: <da7fc94554c52c63f957d82e46c5bc8a718b2b96.1605305705.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Nov 2020 17:04:02 +0100
Message-ID: <CAG_fn=URYEvbfdZrdpZs8Uv7ui15oeBDNqB2WTXE2erFucQG4w@mail.gmail.com>
Subject: Re: [PATCH mm v10 23/42] kasan: introduce CONFIG_KASAN_HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=bkJ9XPUm;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as
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
> This patch adds a configuration option for a new KASAN mode called
> hardware tag-based KASAN. This mode uses the memory tagging approach
> like the software tag-based mode, but relies on arm64 Memory Tagging
> Extension feature for tag management and access checking.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I246c2def9fffa6563278db1bddfbe742ca7bdefe
> ---
>  lib/Kconfig.kasan | 61 ++++++++++++++++++++++++++++++++++-------------
>  1 file changed, 44 insertions(+), 17 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index c0e9e7874122..f5fa4ba126bf 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -6,7 +6,10 @@ config HAVE_ARCH_KASAN
>  config HAVE_ARCH_KASAN_SW_TAGS
>         bool
>
> -config HAVE_ARCH_KASAN_VMALLOC
> +config HAVE_ARCH_KASAN_HW_TAGS
> +       bool
> +
> +config HAVE_ARCH_KASAN_VMALLOC
>         bool
>
>  config CC_HAS_KASAN_GENERIC
> @@ -15,16 +18,19 @@ config CC_HAS_KASAN_GENERIC
>  config CC_HAS_KASAN_SW_TAGS
>         def_bool $(cc-option, -fsanitize=3Dkernel-hwaddress)
>
> +# This option is only required for software KASAN modes.
> +# Old GCC versions don't have proper support for no_sanitize_address.
> +# See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D89124 for details.
>  config CC_HAS_WORKING_NOSANITIZE_ADDRESS
>         def_bool !CC_IS_GCC || GCC_VERSION >=3D 80300
>
>  menuconfig KASAN
>         bool "KASAN: runtime memory debugger"
> -       depends on (HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
> -                  (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
> +       depends on (((HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
> +                    (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)) &=
& \
> +                   CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
> +                  HAVE_ARCH_KASAN_HW_TAGS
>         depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
> -       depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
> -       select CONSTRUCTORS
>         select STACKDEPOT
>         help
>           Enables KASAN (KernelAddressSANitizer) - runtime memory debugge=
r,
> @@ -37,18 +43,24 @@ choice
>         prompt "KASAN mode"
>         default KASAN_GENERIC
>         help
> -         KASAN has two modes: generic KASAN (similar to userspace ASan,
> -         x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC) and
> -         software tag-based KASAN (a version based on software memory
> -         tagging, arm64 only, similar to userspace HWASan, enabled with
> -         CONFIG_KASAN_SW_TAGS).
> +         KASAN has three modes:
> +         1. generic KASAN (similar to userspace ASan,
> +            x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC),
> +         2. software tag-based KASAN (arm64 only, based on software
> +            memory tagging (similar to userspace HWASan), enabled with
> +            CONFIG_KASAN_SW_TAGS), and
> +         3. hardware tag-based KASAN (arm64 only, based on hardware
> +            memory tagging, enabled with CONFIG_KASAN_HW_TAGS).
> +
> +         All KASAN modes are strictly debugging features.
>
> -         Both generic and tag-based KASAN are strictly debugging feature=
s.
> +         For better error reports enable CONFIG_STACKTRACE.
>
>  config KASAN_GENERIC
>         bool "Generic mode"
>         depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
>         select SLUB_DEBUG if SLUB
> +       select CONSTRUCTORS
>         help
>           Enables generic KASAN mode.
>
> @@ -61,8 +73,6 @@ config KASAN_GENERIC
>           and introduces an overhead of ~x1.5 for the rest of the allocat=
ions.
>           The performance slowdown is ~x3.
>
> -         For better error detection enable CONFIG_STACKTRACE.
> -
>           Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_S=
LAB
>           (the resulting kernel does not boot).
>
> @@ -70,11 +80,15 @@ config KASAN_SW_TAGS
>         bool "Software tag-based mode"
>         depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
>         select SLUB_DEBUG if SLUB
> +       select CONSTRUCTORS
>         help
>           Enables software tag-based KASAN mode.
>
> -         This mode requires Top Byte Ignore support by the CPU and there=
fore
> -         is only supported for arm64. This mode requires Clang.
> +         This mode require software memory tagging support in the form o=
f
> +         HWASan-like compiler instrumentation.
> +
> +         Currently this mode is only implemented for arm64 CPUs and reli=
es on
> +         Top Byte Ignore. This mode requires Clang.
>
>           This mode consumes about 1/16th of available memory at kernel s=
tart
>           and introduces an overhead of ~20% for the rest of the allocati=
ons.
> @@ -82,15 +96,27 @@ config KASAN_SW_TAGS
>           casting and comparison, as it embeds tags into the top byte of =
each
>           pointer.
>
> -         For better error detection enable CONFIG_STACKTRACE.
> -
>           Currently CONFIG_KASAN_SW_TAGS doesn't work with CONFIG_DEBUG_S=
LAB
>           (the resulting kernel does not boot).
>
> +config KASAN_HW_TAGS
> +       bool "Hardware tag-based mode"
> +       depends on HAVE_ARCH_KASAN_HW_TAGS
> +       depends on SLUB
> +       help
> +         Enables hardware tag-based KASAN mode.
> +
> +         This mode requires hardware memory tagging support, and can be =
used
> +         by any architecture that provides it.
> +
> +         Currently this mode is only implemented for arm64 CPUs starting=
 from
> +         ARMv8.5 and relies on Memory Tagging Extension and Top Byte Ign=
ore.
> +
>  endchoice
>
>  choice
>         prompt "Instrumentation type"
> +       depends on KASAN_GENERIC || KASAN_SW_TAGS
>         default KASAN_OUTLINE
>
>  config KASAN_OUTLINE
> @@ -114,6 +140,7 @@ endchoice
>
>  config KASAN_STACK_ENABLE
>         bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !C=
OMPILE_TEST
> +       depends on KASAN_GENERIC || KASAN_SW_TAGS
>         help
>           The LLVM stack address sanitizer has a know problem that
>           causes excessive stack usage in a lot of functions, see
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
kasan-dev/CAG_fn%3DURYEvbfdZrdpZs8Uv7ui15oeBDNqB2WTXE2erFucQG4w%40mail.gmai=
l.com.
