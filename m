Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4X7U2DAMGQE3WUZY3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 434373A9596
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 11:10:12 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id u12-20020a17090abb0cb029016ee12ec9a1sf1314364pjr.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 02:10:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623834611; cv=pass;
        d=google.com; s=arc-20160816;
        b=r3aXyw9hfXuSQvXezFmEi0DeefSmPBxyw3UXPiiTLVDMDmmpjNiYlVjsX13Q59brPH
         eAYLibhoji6Bi5EkXOrOIzon5nrtCsPECkXFv4pLY8tXbex0BTVjhDDV6ei7OMK01I4a
         SEL2okktg9+lp+feeVUkVvxGASWraEq9E2WGdqInPg08Rb1tfcZXqTtLk74iRRxF0h5P
         ontK1WIVsdIBwGeAg67dqaTCjucE6K4ae7MZmT/NuU1MsUH9fnmGv5CocGY2sy2trLOQ
         XGrGfIY0pAqwjWr98DV36rZu49qATM/3cBCS5y86dtj13WJxfGiA38jjJG3+DUYWsObH
         z38Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CIwNXhTw8n/ztAQ+Qjz9j2KaLlSyK3pa+kREwqKM8qM=;
        b=dU6EckhiAZsOBDElBzQe23N9pU+b7OewPCxOz70G3u8k15a9N1Tgn58R0GqiXCm08w
         DjAvnH8Z40tBvDdBaowLgdT0B0WslL7viUb2aXBxjXB9w7dIE1bdllykduU/Dy4+Uvdy
         5ryAIBC0yBb7FSL6ZpU8I9wWUQwuqpLqoS4YFZB2THreW5uDiSYHr62gubF5Zn6mfO4r
         qatnTf1qwYuL4GH/+O6vITHf6ipOrmuKJ9U78mcdPXwjPS75VI88FafA6xMGCpCJHtEI
         r5YDobnwMh/oNe3mui8czsHs3VQK53Aa8hEUl7Ww1tMge/y2csYHfeD/Lwjjj/Tz/HOL
         PoQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qXg9QAKz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CIwNXhTw8n/ztAQ+Qjz9j2KaLlSyK3pa+kREwqKM8qM=;
        b=TNA3aie7X/GX75OYTHdjwoy8ZDXYBBGhyqmfiwclt5MWcb/l8wluT/bsypNT9cCYFX
         LIVEnsbaWxF4XqcetE/3wFDC+WLHK0E/alzJXvuw+RzMzGXdMNX9OOX0vXH+fOrF1zCS
         l1XfAIyyD2rNcuw1sQe8y2WEq6++i2rrBXOAmX2BTDIdvwPBTrHkDfKzelnyb5lhmbPk
         CG429zVB1e0mFcSpPMOet1PyBk5DIUCgaiB1YUIHYz6tndTit4OPEkVU3bHxgX2kGo8D
         18mMqC9tIq7PQ9CXBIeJQE2Tr/7/zcU5YcEeQw93cvqxwSZ5KecwbgrihQLJrwccd1dw
         PXTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CIwNXhTw8n/ztAQ+Qjz9j2KaLlSyK3pa+kREwqKM8qM=;
        b=Skg7REA6adfb+k+hK1OBxJHoqsqHY6WW/gor4FXAIV3F/6p5nX2+eWzfCNGH/+6nxQ
         OsuCw1D9LT2Ela7svYQZ6U6SLaz8VQM2qLeICt3HDdF2JsF0dr1hX/6ndxukElZxZfFL
         ez5wd1b6sxlNs5l3XgUbU6x3FtCk444b/FoB9WyrQq2Fodhpx8xtgja0cRfNA1V45wJc
         U4W7n9PdqHk9a6yUc3WD49151yp4WHEBq2cwOhkegHqBpyPTk9dMGO9z744kU9hKqsKO
         5VDAsFTrp6ruZdLJBN7v0sxoZU0h8+oHqy6OWs/8JLYHxQsbrMq6gZWTop5Ln2VANsAy
         DFIg==
X-Gm-Message-State: AOAM532ODR2soQD3B83PwNdE6UExToMMIiSvTXpX0k8tP8qGwsSEdsv7
	C0X2SRiXQlfec/N7U25Tazo=
X-Google-Smtp-Source: ABdhPJxlBJmlX5JJdmLrrgEkiDhh6oUBaSofpQmxZTmO4Bmfz5X4DCwtEmjiUXAa/jezx9i+RTDueg==
X-Received: by 2002:a17:90b:4b49:: with SMTP id mi9mr9476966pjb.219.1623834611037;
        Wed, 16 Jun 2021 02:10:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:774d:: with SMTP id s74ls755139pfc.11.gmail; Wed, 16 Jun
 2021 02:10:10 -0700 (PDT)
X-Received: by 2002:aa7:8bd9:0:b029:2f2:f491:8836 with SMTP id s25-20020aa78bd90000b02902f2f4918836mr8655350pfd.47.1623834610425;
        Wed, 16 Jun 2021 02:10:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623834610; cv=none;
        d=google.com; s=arc-20160816;
        b=onVatBc00LBAEHs6Zql9vquYferFc99P94WJ+oP111TAufLasrXB6msxdbnNUP5uLX
         QhOp1dege9f+bsU1RLxSR9IKWSvMyXhwxgctmNHZVJDuwzMUIcpmPiAP5veBdc0ZYsR3
         mjj5Rf7vSTLcsi67ub6yNS1LdrdRf1QrhkMFOR8iqRP0ThQNr3bRPM8hbWcgfCjqRlTN
         pDknnnT6G9E9l+hs+tc3b6RT+FvwsV9NviU/4qnnXwwUdfDGcsPZghhBnG13/+p9dGX7
         Df8GdM5nXid5Avt8Rgi6AHqgG0PlENmlk6u+sudXzFz71dv1my58hKtreBa1cXNrEqjN
         +FAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=N0yUvQwf56uXT+DeZe9wCbbuUfkwdrAhTZdP0qYYdjo=;
        b=j0ctHtrYhyjtzkeChvfZgLXFBxw7MdtGv5S3MsciuginNVakhhkGVzDLFDoDyVvqYp
         FuJjndnHhOFJ8Z0cIYYI9/vQLDW2zEZF+UdjjRAPGLEXmNhf8QrvJTDkTkwCaReKPewk
         d/UQZVswfmeUFyLVGtUuDx9xgDhYIyItWtEq5R2IUkSqEnErlTYDrdNKfZaA0pO/LyYv
         sWWLPUV3BiQ8MQ0UUJBJsaN+a0OHCfR4dc8retWPdkq6oYzTfKTQYZKdylCWRtUo+Buk
         4VT5PnqfjAeLaPaJHlm06VXul1H/nQFX0hsQ3ZjpFcPUQNTkodt/LB8vZKN1XTDfy14L
         ayNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qXg9QAKz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id s78si110162pfc.0.2021.06.16.02.10.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jun 2021 02:10:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id b18-20020a0568301052b0290449ba7eff3cso12270otp.7
        for <kasan-dev@googlegroups.com>; Wed, 16 Jun 2021 02:10:10 -0700 (PDT)
X-Received: by 2002:a05:6830:1591:: with SMTP id i17mr517649otr.233.1623834609650;
 Wed, 16 Jun 2021 02:10:09 -0700 (PDT)
MIME-Version: 1.0
References: <20210616080244.51236-1-dja@axtens.net> <20210616080244.51236-2-dja@axtens.net>
In-Reply-To: <20210616080244.51236-2-dja@axtens.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Jun 2021 11:09:57 +0200
Message-ID: <CANpmjNPnRXpmn1fJOMp8pTMvzj-obhoZHN+r8ZQMUS8jEQ3Ozw@mail.gmail.com>
Subject: Re: [PATCH v13 1/3] kasan: allow an architecture to disable inline instrumentation
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	linuxppc-dev@lists.ozlabs.org, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	aneesh.kumar@linux.ibm.com, Balbir Singh <bsingharora@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qXg9QAKz;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 16 Jun 2021 at 10:02, Daniel Axtens <dja@axtens.net> wrote:
>
> For annoying architectural reasons, it's very difficult to support inline
> instrumentation on powerpc64.*
>
> Add a Kconfig flag to allow an arch to disable inline. (It's a bit
> annoying to be 'backwards', but I'm not aware of any way to have
> an arch force a symbol to be 'n', rather than 'y'.)
>
> We also disable stack instrumentation in this case as it does things that
> are functionally equivalent to inline instrumentation, namely adding
> code that touches the shadow directly without going through a C helper.
>
> * on ppc64 atm, the shadow lives in virtual memory and isn't accessible in
> real mode. However, before we turn on virtual memory, we parse the device
> tree to determine which platform and MMU we're running under. That calls
> generic DT code, which is instrumented. Inline instrumentation in DT would
> unconditionally attempt to touch the shadow region, which we won't have
> set up yet, and would crash. We can make outline mode wait for the arch to
> be ready, but we can't change what the compiler inserts for inline mode.
>
> Signed-off-by: Daniel Axtens <dja@axtens.net>

Reviewed-by: Marco Elver <elver@google.com>

Thank you.

> ---
>  lib/Kconfig.kasan | 14 ++++++++++++++
>  1 file changed, 14 insertions(+)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index cffc2ebbf185..cb5e02d09e11 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -12,6 +12,15 @@ config HAVE_ARCH_KASAN_HW_TAGS
>  config HAVE_ARCH_KASAN_VMALLOC
>         bool
>
> +config ARCH_DISABLE_KASAN_INLINE
> +       bool
> +       help
> +         Sometimes an architecture might not be able to support inline
> +         instrumentation but might be able to support outline instrumentation.
> +         This option allows an architecture to prevent inline and stack
> +         instrumentation from being enabled.
> +
> +
>  config CC_HAS_KASAN_GENERIC
>         def_bool $(cc-option, -fsanitize=kernel-address)
>
> @@ -130,6 +139,7 @@ config KASAN_OUTLINE
>
>  config KASAN_INLINE
>         bool "Inline instrumentation"
> +       depends on !ARCH_DISABLE_KASAN_INLINE
>         help
>           Compiler directly inserts code checking shadow memory before
>           memory accesses. This is faster than outline (in some workloads
> @@ -141,6 +151,7 @@ endchoice
>  config KASAN_STACK
>         bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
>         depends on KASAN_GENERIC || KASAN_SW_TAGS
> +       depends on !ARCH_DISABLE_KASAN_INLINE
>         default y if CC_IS_GCC
>         help
>           The LLVM stack address sanitizer has a know problem that
> @@ -154,6 +165,9 @@ config KASAN_STACK
>           but clang users can still enable it for builds without
>           CONFIG_COMPILE_TEST.  On gcc it is assumed to always be safe
>           to use and enabled by default.
> +         If the architecture disables inline instrumentation, this is
> +         also disabled as it adds inline-style instrumentation that
> +         is run unconditionally.
>
>  config KASAN_SW_TAGS_IDENTIFY
>         bool "Enable memory corruption identification"
> --
> 2.30.2
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210616080244.51236-2-dja%40axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPnRXpmn1fJOMp8pTMvzj-obhoZHN%2Br8ZQMUS8jEQ3Ozw%40mail.gmail.com.
