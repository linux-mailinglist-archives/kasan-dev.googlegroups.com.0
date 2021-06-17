Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAHJVODAMGQEEL3JLAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 01B563AACF9
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 09:06:42 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id z17-20020a9d46910000b02903fb81caa138sf3333729ote.18
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 00:06:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623913600; cv=pass;
        d=google.com; s=arc-20160816;
        b=CB57UTY/HWMVGarp0TrMDfX4cVAIV6ymCnl0AM4sOnDSy341yH0yb2bPcTHN/4h8wD
         y4rxq8BY+QZEEefbtCwBYisW6bGMdotc0iQkMYJUZIen5y8kF9rGseRfS1rOb6gu/PJ1
         aiASc6AHrymoTGU+2J4lJDE5/nTF/S+JVYHatbo2FWEpHUfLHcpciZXCEWAnx/OE5BPA
         Ar1m6o83+erviLd3h78mfAxcGPwlvQhz/qwvNAUiJYmg0FM0D76abx1h7V9caOuMLRGF
         hXCRG1W2QYDNxg8SQiN420qVXROH7wGT8lnVKQocrRId4CQ34JkEpaf3GMzw3lJPJnvL
         flRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7ausshOpH+/yiY83WLgnZewJorbMjg3pSNu3p2UPJV0=;
        b=qmcBj5RQbSra8yFVqOIrhmeIMsVC5C2Hsk7Hk8GoGSO0snV7S+8khGiKKbahg1LK/9
         TamZsVHDo7u4KIaUcFwRkTmzJAatMNdHJ8vm++M1zl5UpOesC6ErD4yzkfV+FBfG1hX/
         87Y8mmd11JYKcUD/nXPs6lZ9xiemS+MYkG6QDSiW1a1ixlQzbL9ZlXFNdOdomC35wH05
         99ooq0JJVw7y6fcIP7l/Q9iEB+f9oUd9v1FXj1r9mEaXlDAcnCjFKkdBzdhtMe5DvrN/
         UYFqVefSTUV0nxKjblCmz4mMc8dLy9Eq04Yf7hb50H959DL7jQzAvMYAFEXy935sR6vw
         0lWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TUHB1N3e;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7ausshOpH+/yiY83WLgnZewJorbMjg3pSNu3p2UPJV0=;
        b=Dv//wB6ohmdxLt1pSxFPsXOX1PJOSSQKKGmuBTFXoILj2nWtDu0tLSILw/15omBNSc
         TzvDqAZNuUhEWJl/oLtamEW0I+sDAv6munNBgXbYAOfglYjII9yUYo6PHCDkE8kAPmqG
         mLF39V+w7mMuJYvkoL91Bhg/Hq1WF29lI8OGB+VCiEM0LV+ZRHGAicmN8yuGUVUV+i7K
         cEQzca4gPmZAYdeQxsyPRfgP8HlYtnh5ii6ef4fmVlLFQjOG6Y2miaQuf5adPSw7XQ3u
         koroSsk13WsmX92DhYqGLumPW74W129BXDjxFvLMnN3tneLF6kfPi5QxAi4198qkIAFD
         76bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7ausshOpH+/yiY83WLgnZewJorbMjg3pSNu3p2UPJV0=;
        b=NInt+9ksSpJdGHo/9MbytWFYsH+nNby3KjMGOeZOVT6EnZCIh4lpbt0Nb9bH5p79IE
         FZzDrNdwmZqxpzl1WipBgZHrBDmpURPEfM4CDxbic5DE0yae6K4NQE9EDdzeQLH22iiV
         8jdJEEXSQFsksBibGJDKS3Fku4k98FkJHJ6fCkgy6+n0TyrqwglpM5EsCRUIEDUVElAt
         e7iKDiXyurSJagxMt1KNsrXGAtjfbJOvB2g9KvCJnBQI0cAuS3PkHRFlCCN7VWe5p7DH
         z2u8dJCHToo7qMLBUtSZQvetOK/MDlyL+8No7iyz56NCTRgamgNcU8HPCsOUegO/kVUh
         PKtQ==
X-Gm-Message-State: AOAM530/J3XlcXH4Ckf8hw7wnTXbYMiov5TX/zhMhjqHC4F9T89T0YQS
	5u2HXHTJgB9yJENLFWlGx5s=
X-Google-Smtp-Source: ABdhPJyWve/5lnEDezvzj3vo5tCpNAdhmmVgTpYeDBZYUe94HhDGVKQTEdZjHZTAfs3APFyB4MmJtg==
X-Received: by 2002:a05:6830:1bf7:: with SMTP id k23mr3368752otb.206.1623913600667;
        Thu, 17 Jun 2021 00:06:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5903:: with SMTP id n3ls1599121oib.6.gmail; Thu, 17 Jun
 2021 00:06:40 -0700 (PDT)
X-Received: by 2002:aca:eb8c:: with SMTP id j134mr2285388oih.179.1623913600263;
        Thu, 17 Jun 2021 00:06:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623913600; cv=none;
        d=google.com; s=arc-20160816;
        b=UpbgQw+RI9hOy3GRm3yv5dUSBd/ZgA6L7YHcPKYB4TVcjB41ENOBFZ0FzuMwWdgVni
         YkMzwqNsV2l3RcU4y51zwnNzl7o1GihZ44Z24WpV2uhYotnoTOReoYmVvKdDJmrmrSuW
         R1xZ/7YerZBneyt4PBG97MU64C5QausSn8wZeEVtX0oXzpXkVX4ED9j1r/2if4I6w9zL
         WSpcsjIUgGmBqHelyRifDRECF2ueqWnbrkOZcEM8rXDeAU/sMP+4i9/SZZirygRmJDce
         6ahRJM7Ek1t1sgULUlh28uaULB9Q57qjEuz4dMDq95vgHPvBil89Y+/y2smzNHtgMaE1
         4CRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=x3f7kXNEAio7wn8rN5Q4qZlH4cBywzmH0Nokkyx4dn0=;
        b=bfGsOWq2citVokUG8Iex9R/bg1b1CFNa8z4wBXZiUkWvqo8abLqyiI+GVBOgcYTbPF
         kRR18een7N7URqcIU2Corku0y0Pg0MfzG/iNDa17G7+2xaBd0EdTF9DEuzh0xYRKYivn
         xs34BbasSATVBX+77TgrCTUt+Zz5+ACCX0xMTU4wqUxcLugFr7xBsBULPyK3tOkgntS4
         X2rgi1Zd4wBzhuts7Sb1E3AJOOE7ivJgVxst2hnNy9ilJ2+pvqhvFPQUQpiR0AlA4lzm
         DdjwvDITkmVzVI7B4EfKKCpnYugQ4HPlVPT66tM7h5hJwv4ooyISXW8R2PSTvwtR3gY0
         kVzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TUHB1N3e;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22f.google.com (mail-oi1-x22f.google.com. [2607:f8b0:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id l10si548128otn.5.2021.06.17.00.06.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 00:06:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) client-ip=2607:f8b0:4864:20::22f;
Received: by mail-oi1-x22f.google.com with SMTP id s23so5426366oiw.9
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 00:06:40 -0700 (PDT)
X-Received: by 2002:a05:6808:bd5:: with SMTP id o21mr2268625oik.172.1623913599850;
 Thu, 17 Jun 2021 00:06:39 -0700 (PDT)
MIME-Version: 1.0
References: <20210617063956.94061-1-dja@axtens.net> <20210617063956.94061-2-dja@axtens.net>
In-Reply-To: <20210617063956.94061-2-dja@axtens.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Jun 2021 09:06:28 +0200
Message-ID: <CANpmjNPw2_Av0HVSBMP0nj0a2dwqKxMopWwvsyQF1vv5hN0zzA@mail.gmail.com>
Subject: Re: [PATCH v14 1/4] kasan: allow an architecture to disable inline instrumentation
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	linuxppc-dev@lists.ozlabs.org, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	aneesh.kumar@linux.ibm.com, Balbir Singh <bsingharora@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TUHB1N3e;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as
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

On Thu, 17 Jun 2021 at 08:40, Daniel Axtens <dja@axtens.net> wrote:
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
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210617063956.94061-2-dja%40axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPw2_Av0HVSBMP0nj0a2dwqKxMopWwvsyQF1vv5hN0zzA%40mail.gmail.com.
