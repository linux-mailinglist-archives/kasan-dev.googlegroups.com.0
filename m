Return-Path: <kasan-dev+bncBCCMH5WKTMGRBO73V76QKGQETALVZ5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id BA0EC2AF461
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:05:32 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id v8sf1346330ply.0
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 07:05:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605107131; cv=pass;
        d=google.com; s=arc-20160816;
        b=NRIyesKBBSwMUE3BFQYIDEBgUcnI2ciIzAj+YAJUxY9cHfMEldSfIK8QtO+x1cIr5U
         meXQvw+y/mhEgJgYwyAEwpnUH7ET/3AyyXKTVg8G4X6wNmb7YyOlENmC3z+6nkL3w2Jr
         KoDu3SFMPMJP83JFBRcjQuSPo1W036ZiQU6SHElGKi5b3F6cbmFw70UM739Y0q3348Z0
         OWFRqPq/jS9VIjsuePNV/0tkLXPbKlkmtdJEolJfNrrKIx3RCszswhm4KJIPVXe1CC6I
         AaDjyziRSmaXPYWQoL+/YGSzrYlsQ1tKBD5O8vXyG4wLJZzm54ahr4jd+dzCU5OBCpa6
         hHnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7j8otC/banX5FqQn6Vu12qmChoQN7em0MPqlFVoCtps=;
        b=giyimCXmFzwBdybXUtcH0HZGz2tbj5IAzJWR4NaOhV7js1Pi4YTEq3DFqPHAkcsSLi
         RSK1Xy8Dhm91u7kFqxcxEsl90tfwiknRPnwAUE4EPk0pdzsAfJYhcFDdBU0wvwMvd1x4
         xRK3tO6Zi5+D7XS+enVckhQYTRMm9862S9SAQHvaxrHB5KJ7X53hvxQu8HHsiPUdS/xf
         7itexDLsxgwGfwtc49qnHqz4ow1+3HeBNprjrRMQk71ZMy6izlUVA9AuXQno2BD7rbHp
         LU3ZfnzZVmry2UoM/TfQO2wZlHNPw/WGCBCn6pWa5pl6bDODUM0Ly8bZhrVd6ah3ZUPh
         kL7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UTLVB2hx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=7j8otC/banX5FqQn6Vu12qmChoQN7em0MPqlFVoCtps=;
        b=H9cEev+YHbv/LzE1vHy1xBaPl0g3Qu96+aqUYqz4wJgFpamPIgYnDYDWXPKpWdvbgV
         pMcGoe1tnes1Rdo+Vg3cuahQwlWfhVOMvDY7PRyZv7nE5ebT9o2Pod/26ghzlIZbfLZg
         63SG5hkSODwfQ7wYscRjo1p2fTlIhEGsJaDmdREeCB8RHDzgX+//QopViWOvQ/IH7NpC
         +owpkcSqz+AFdu6bPe9wg8bdE4/kRDZn7QL6sKQYoD4kQKHeuriTZ72CLU8Ey/9zvghm
         PGNSSZVH/vpq6rVGmu0T61Eghh0teD4bw5FtxHo/zfsMlxXe+MEF7A0f2h08HFIQsUdk
         gtdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7j8otC/banX5FqQn6Vu12qmChoQN7em0MPqlFVoCtps=;
        b=rDXHE4fCuND/WVbKsl5Rqf3ZtKFuHBdBycwK1Bbl4FuE9wKiOR6Xv4IdkgiFUk1LvI
         1wn5ufLjUCrCbI2ZXcS8lKBiSLHAFNCdHXyFpX2JiKYCyq0Cu6zFN4U4f1KGBPUNoCqM
         NK14m2gRtbsufCpKAokSJiVi2IxIKUuN69xImcL8VEJpTMsKac6/LZ9qWNMoYHzkuxeB
         MUl+LHplOrG66YTxVc1Mo/wqBPQUa6TeqPvBoe7RSmV2kPlWpkT4ix6Y04+go101qEjY
         omQXVB/62lrUjBqEHO4G7c8FAh/njETWR2gPv6mrCyv45qXLtn9Oaom6maviixIJkrYC
         WWqg==
X-Gm-Message-State: AOAM530rvhtAV2R6Ya8th97DLYpIdxaDiObyYc5Z319y6xLGxkxXt1yd
	Ga+dA0jpHsQvc3mGUBLKuLQ=
X-Google-Smtp-Source: ABdhPJzEtOFNT+CPAzdFQR83KInYBtACrrET9QRdU80RFb1lIah6isEmVajlz9OGyYM2Pn/cUbmTgg==
X-Received: by 2002:a63:1a54:: with SMTP id a20mr22422658pgm.133.1605107131473;
        Wed, 11 Nov 2020 07:05:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:9205:: with SMTP id o5ls6088852pfd.7.gmail; Wed, 11 Nov
 2020 07:05:30 -0800 (PST)
X-Received: by 2002:a63:ef4f:: with SMTP id c15mr22438528pgk.345.1605107130882;
        Wed, 11 Nov 2020 07:05:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605107130; cv=none;
        d=google.com; s=arc-20160816;
        b=UeJb/RebMlb19WwgmdFd3acmiaGdsXq9KvmQGdr5fVTinHigKPutPDWVPkMXR4FVrg
         SZzHL59B6DchTShPsTQvrz1F/GLp3cQc9GPve069ba9zJhEZyymjMX3ZCbqXNXGDhsNG
         Uo4NSNQbaeuNXb0wFm+1CB0au1lKk3PQdJ4C4xUrr3af2V21xbjHx4qvHBEgz4v0jjV7
         CZMxzIMYe+4haQKjU0xGBkwXDLdnR1G3+QEjQ35JIvvTJr2TD5iJg99bsL8Gz0gU9q7h
         0ek+46iahR0lp3mjMXFScNv8PyxvIb3ZGtb/GlgA/46y/nbGOyddTAQ+lz1S0qUFIZwX
         YWTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rVdrwVonW2YmXNPICNMVskHoelIG7HcDSMAakdQ5R6o=;
        b=Fb+NVI21n3IHW2wLGYuA5duMrqGzUllwI+V5MCJhBWqcm5NopJXnAo1Vtt9JwFaepO
         QqNTCD6Jfanyx1y8DrJHwCe2xwd5/JeFpePrYCIhfsxkf0rWcPSV+6jdMOLOoBw/opCL
         +aS6ixzjPebMn3Rmi83IYRreSvorQ8lv6xbv8pUwIynhubceVDG6i3Zc4948/zck2JQx
         CnteXOJBWIIROmqLfpZNv6K3xKLULQh0i2Iz9fsUGAo88wmjEIq7+eDq30rBws6i1lOD
         YiiBksba9RyBtsuH2Tfx1gBVyJooJDYVxGkHqZH7qyaq46TAzrtbnEm53Amh1tyEG4TA
         kY2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UTLVB2hx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id e19si45891pgv.4.2020.11.11.07.05.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 07:05:30 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id j31so1449911qtb.8
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 07:05:30 -0800 (PST)
X-Received: by 2002:ac8:4884:: with SMTP id i4mr24122947qtq.300.1605107129800;
 Wed, 11 Nov 2020 07:05:29 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <8b8345f75fa75638328d684b826b1118e2649e30.1605046192.git.andreyknvl@google.com>
In-Reply-To: <8b8345f75fa75638328d684b826b1118e2649e30.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 16:05:17 +0100
Message-ID: <CAG_fn=UDk95kK-ZsJDe43VUCTUvUmYfFmONKWAAxoXMvoXv6DQ@mail.gmail.com>
Subject: Re: [PATCH v9 18/44] kasan, arm64: rename kasan_init_tags and mark as __init
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UTLVB2hx;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as
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

On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> Rename kasan_init_tags() to kasan_init_sw_tags() as the upcoming hardware
> tag-based KASAN mode will have its own initialization routine.
> Also similarly to kasan_init() mark kasan_init_tags() as __init.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I99aa2f7115d38a34ed85b329dadab6c7d6952416
> ---
>  arch/arm64/kernel/setup.c  | 2 +-
>  arch/arm64/mm/kasan_init.c | 2 +-
>  include/linux/kasan.h      | 4 ++--
>  mm/kasan/sw_tags.c         | 2 +-
>  4 files changed, 5 insertions(+), 5 deletions(-)
>
> diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
> index 133257ffd859..bb79b09f73c8 100644
> --- a/arch/arm64/kernel/setup.c
> +++ b/arch/arm64/kernel/setup.c
> @@ -358,7 +358,7 @@ void __init __no_sanitize_address setup_arch(char **c=
mdline_p)
>         smp_build_mpidr_hash();
>
>         /* Init percpu seeds for random tags after cpus are set up. */
> -       kasan_init_tags();
> +       kasan_init_sw_tags();
>
>  #ifdef CONFIG_ARM64_SW_TTBR0_PAN
>         /*
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index e35ce04beed1..d8e66c78440e 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -283,7 +283,7 @@ void __init kasan_init(void)
>         kasan_init_shadow();
>         kasan_init_depth();
>  #if defined(CONFIG_KASAN_GENERIC)
> -       /* CONFIG_KASAN_SW_TAGS also requires kasan_init_tags(). */
> +       /* CONFIG_KASAN_SW_TAGS also requires kasan_init_sw_tags(). */
>         pr_info("KernelAddressSanitizer initialized\n");
>  #endif
>  }
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 979d598e1c30..1d6ec3325163 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -191,7 +191,7 @@ static inline void kasan_record_aux_stack(void *ptr) =
{}
>
>  #ifdef CONFIG_KASAN_SW_TAGS
>
> -void kasan_init_tags(void);
> +void __init kasan_init_sw_tags(void);
>
>  void *kasan_reset_tag(const void *addr);
>
> @@ -200,7 +200,7 @@ bool kasan_report(unsigned long addr, size_t size,
>
>  #else /* CONFIG_KASAN_SW_TAGS */
>
> -static inline void kasan_init_tags(void) { }
> +static inline void kasan_init_sw_tags(void) { }
>
>  static inline void *kasan_reset_tag(const void *addr)
>  {
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index d25f8641b7cd..b09a2c06abad 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -35,7 +35,7 @@
>
>  static DEFINE_PER_CPU(u32, prng_state);
>
> -void kasan_init_tags(void)
> +void __init kasan_init_sw_tags(void)
>  {
>         int cpu;
>
> --
> 2.29.2.222.g5d2a92d10f8-goog
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
kasan-dev/CAG_fn%3DUDk95kK-ZsJDe43VUCTUvUmYfFmONKWAAxoXMvoXv6DQ%40mail.gmai=
l.com.
