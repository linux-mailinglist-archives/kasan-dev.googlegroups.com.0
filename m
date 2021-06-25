Return-Path: <kasan-dev+bncBDW2JDUY5AORBQOE26DAMGQECKVQQLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B8603B453A
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Jun 2021 16:03:45 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id w10-20020a5d608a0000b0290124b2be1b59sf1889113wrt.20
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Jun 2021 07:03:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624629825; cv=pass;
        d=google.com; s=arc-20160816;
        b=F8PFcGFO3TzZbsbyHvtNp4L69pSol/HQj1Bt6YB2el6oA5vRpI46bAnwQBVdKUbILA
         poo4z273QJ6zJvKnJMRjUm+YENBTEW0e172P8ARymY8e28S9KEtFwLv0FR7pKAKkX453
         DbX7V5wjFnb3T0DzSLFRICJevVkhSYsmptqRp9xF5TwzF0qRQtLcWP+SjiRy5f7zN//k
         ES3GMN+0TmuJ1lUskH6XRAoKOoGE9i+5bkvNgLvGrCYkDYBsfsh/1lRA3qKGsS29BmuJ
         tMV7DsRSrtTthhm0zdicRjhyZtwoeHotVSjCn6Ix+7lm266nGWX08/aGvvKevfv/GZCN
         f08A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=/pHKKby3Lh/MD1Fh9hKWolQUldO3CkGlKMzoo2q1J/4=;
        b=svyie6alE6NDzscfKQusDp5sLcgYOSi9n4A1y/Mx1CBttXJ5RTPANd3LaHbV80b9DX
         N6nk7tfRXlsfd8p2Vo2a+D5xf9JgJpk4aw2mDJaxjov3g3ogqp7fBxPPHUF9HAAhsRyC
         kvYavAQWHUYEYrkMd+Ke9yrMQgpIjr2GH2Qie/WlQ1UVJij/DDmuL3YzfTs1NjOHdii2
         pwAtUczbTKJhFbFPSo3hp5dsgs5bBqMyr0KtUElCNQ+3sRoOStHvQfsFaKVbFC0FXDHi
         V2DF4zQYjMYhh64zF99MLO53letFwlaaCdle3JFMfu0/oYPN4BCuJATHLHC/oRVXSL/E
         WoMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=g2xI4G+Y;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/pHKKby3Lh/MD1Fh9hKWolQUldO3CkGlKMzoo2q1J/4=;
        b=mCWAsrHWWM9FAfqOzbJa+nDXLlVQiCJoOeYsoyx4GLUTY6Tcap0fpG66q79uFaNUTR
         dWxOoumei2BUMWTwFndjUnwYiGyPW7iA9/BfDscSqjhzdV7ooyvGutsIPjcuoGYNWYxL
         Ubixdbp2jJDPINNTN6BVxC75VkGcQ7tRzBVRniQjcvgKt+Z0L8ZVbFxxCGksNfj3NBeQ
         Q63pOjNXBEOlh0IHzveAUK1J4CJibUK8jYzSnBitaE7e8BkL0darCVDmwbT1L+cqusZb
         tOcFLViXQm2yoMdnikBKiiXl0gjKDfNjWF5b+NOo+tuWmRJaXZoAqafrsl3ldBVfZvVT
         zBag==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/pHKKby3Lh/MD1Fh9hKWolQUldO3CkGlKMzoo2q1J/4=;
        b=uY4B//C6AyBD1ZYtLYxaUWUuDjGUMhV4gyZhMarfQxG4AV2QtVHONYNnoAziOi6CpJ
         bPuTxlWndTjk8W/ZAT5CtERv+Q9tIK+GgohVeqor11IbxApgSCq3Vli0S0r5E+OGpJxD
         cs8ARAKOTWWl29OAcIA4PJYK4RRQBodTVm8C/UnDCH2/hkpmqVi00EvDg5/SKw48seS/
         Pz1Af1Y5SekGcjTsgEXXiU1+ua3gRnR4Fm90KmOD18ulVM3RBh9FW8pDf7ajfAwmGMp/
         K8z3OGjBcbNmf0sbPcTgt9oO8fVKocWM/oQE08D4PzEvQTUCIJFP/AjI3u67IlxRMSMj
         Zugw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/pHKKby3Lh/MD1Fh9hKWolQUldO3CkGlKMzoo2q1J/4=;
        b=XOqXmy49Yymz0BROLVXKmW0LwYEHI8BnJ5+Y0CU6T84RUo3+OSEqa3FxSgNqaVVqHm
         OUHIjMkrR4qa0oHDh49eLru9UHZP5BrXhnTG1nXLHuhLBtCUTHV4jj9Nb66V+m0IBVvs
         +XpeS/2haeGokel3z7ojdF89c+QcJ3cCcFGweVgzUas39o2GYJjZ7q0FFO/NIhuIYUSV
         gnJ4zttS6WKKU1SQ2LtTCmmlCmIe2Y/LS3xC+4pRd7tHJVi8k0S6e1kVcJHA+YntkNA+
         jtEU6h7em5VUIbCvhsTlXXGiBcm9N5P++vPuy/om3c+qkKi39/S5c/mtFg1pUb4Ju9mQ
         lZQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530vVXpFASe6Bwnf9uGCmHagmkvr4vX8uhNDa8xpdjzt49bdllvC
	+s9hYKJ489mG17rVDKbXAmA=
X-Google-Smtp-Source: ABdhPJz+QXsoyE28dMFMG6Roqoi+8G+03IQ+NCXi8LNJBdB4Z3N3NZQAcmV4yRgKPxsGe06NdY86RA==
X-Received: by 2002:a5d:5907:: with SMTP id v7mr11342991wrd.342.1624629825159;
        Fri, 25 Jun 2021 07:03:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5106:: with SMTP id o6ls6271437wms.2.canary-gmail;
 Fri, 25 Jun 2021 07:03:44 -0700 (PDT)
X-Received: by 2002:a1c:541d:: with SMTP id i29mr10905572wmb.41.1624629824463;
        Fri, 25 Jun 2021 07:03:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624629824; cv=none;
        d=google.com; s=arc-20160816;
        b=ErCLlx9+qb2P56Jy8YG+++yUU61tXcq1njtlm4PmjsEp99G3k2ALNnq5T1t8S261BI
         OeUEO2FZruosHlL9jxHOZFpb1CqVG5JAQZ+dfMx+jZlLnG/7VIInTom+U3G4qRM63hs7
         Vv+jTpW088z9R1dfC1aVUui64vxmlumKagHs37VBvurhH5qLwkKmXC7e3Rg4yLxKJra7
         rKuZQA93d4Nv12G+75JBua/AR5HxyUX8chQRWRtTXX83lW3HoCGGfGQfBAiPhxKB99ES
         5IPanI0h/EHLJ7W5Gx+TMUobgad7zEqy0JAdkHftYCqR5yS+Zx/jr35OSYI1FA1PjDqP
         Mxqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KCBPWXjUtJqDX481tplGmByedXmi+6SSSYQlopDVlm8=;
        b=PQRwV7fC6KYowgNPeJYBfG4rrXgdDUHf0dUcyWb/bt+JI13b40AgBSzr/kybZEbKuv
         Kq3dNbxKsFcmzOeoS4mvHL7WGvOwXzrQecflKpzq9c05o+7ApUCw4gEYO2etZnoBWa4a
         tpwMzbXZJOmjWqVTa0fyjix+Ybiml6Q4kDIt6jA/BQmwj+SjVr8dditkAt3NH7FZ8s/P
         SjfLNFTHg9VzhlVMtxxud5uAeaLZ8wJ9THOUJdDXYr0xfbndSgVicK1AE0+T40BOrtRj
         SchUNvxMFRyxu7khKGLzBwbHki1z4SSCYDogFk/z/GNh8giszaHBfPeru3b5V0lcvb3U
         GCog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=g2xI4G+Y;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x631.google.com (mail-ej1-x631.google.com. [2a00:1450:4864:20::631])
        by gmr-mx.google.com with ESMTPS id x4si590077wmk.1.2021.06.25.07.03.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Jun 2021 07:03:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::631 as permitted sender) client-ip=2a00:1450:4864:20::631;
Received: by mail-ej1-x631.google.com with SMTP id nb6so15287658ejc.10
        for <kasan-dev@googlegroups.com>; Fri, 25 Jun 2021 07:03:44 -0700 (PDT)
X-Received: by 2002:a17:906:6d16:: with SMTP id m22mr11315367ejr.333.1624629824272;
 Fri, 25 Jun 2021 07:03:44 -0700 (PDT)
MIME-Version: 1.0
References: <20210624112624.31215-1-yee.lee@mediatek.com> <20210624112624.31215-2-yee.lee@mediatek.com>
In-Reply-To: <20210624112624.31215-2-yee.lee@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 25 Jun 2021 17:03:21 +0300
Message-ID: <CA+fCnZe0fng4-53U1=5MiYszCMi97twKut3eQNaNHgPV2HOVug@mail.gmail.com>
Subject: Re: [PATCH v2 1/1] kasan: Add memzero init for unaligned size under
 SLUB debug
To: yee.lee@mediatek.com
Cc: wsd_upstream@mediatek.com, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	"open list:KASAN" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, open list <linux-kernel@vger.kernel.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=g2xI4G+Y;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::631
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Jun 24, 2021 at 2:26 PM <yee.lee@mediatek.com> wrote:
>
> From: Yee Lee <yee.lee@mediatek.com>
>
> Issue: when SLUB debug is on, hwtag kasan_unpoison() would overwrite
> the redzone of object with unaligned size.
>
> An additional memzero_explicit() path is added to replacing init by
> hwtag instruction for those unaligned size at SLUB debug mode.
>
> Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> ---
>  mm/kasan/kasan.h | 6 ++++++
>  1 file changed, 6 insertions(+)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8f450bc28045..d1054f35838f 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -387,6 +387,12 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
>
>         if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
>                 return;
> +#if IS_ENABLED(CONFIG_SLUB_DEBUG)

Is this an issue only with SLUB? SLAB also uses redzones.

> +       if (init && ((unsigned long)size & KASAN_GRANULE_MASK)) {

This needs a comment along the lines of:

/* Explicitly initialize the memory with the precise object size to
avoid overwriting the SLAB redzone. This disables initialization in
the arch code and may thus lead to performance penalty. The penalty is
accepted since SLAB redzones aren't enabled in production builds. */

> +               init = false;
> +               memzero_explicit((void *)addr, size);
> +       }
> +#endif
>         size = round_up(size, KASAN_GRANULE_SIZE);
>
>         hw_set_mem_tag_range((void *)addr, size, tag, init);
> --
> 2.18.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZe0fng4-53U1%3D5MiYszCMi97twKut3eQNaNHgPV2HOVug%40mail.gmail.com.
