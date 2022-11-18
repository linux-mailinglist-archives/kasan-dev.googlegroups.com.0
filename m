Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZPY32NQMGQEVARN2BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id F299362FB38
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 18:09:58 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id om10-20020a17090b3a8a00b002108b078ab1sf6902113pjb.9
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 09:09:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668791397; cv=pass;
        d=google.com; s=arc-20160816;
        b=zK/RHWgBDwHWR8b6DeMCoKkTVJi+xD2jscOY0eywA44o1wojCKDkcVUoR0gc1ocwrF
         HxhaYiW77fSKk6IVEhUwo3T0JUiEybzDYfOYDFswSSiS4BOicDahcKs9MPFRHWxxg3Ox
         1ANH1ergytRo1sq2dkwVfi4mLDT4LA3BwvBV+gcBF5HGNm9rGsFC3MkGZXHpBDvajk+/
         AiEha+r5ZhessYfAO/MDisahIKMBGBwnTZJCNe0eYXjvgkQRzYfIv9xgytt+LkdIUUVC
         wPwPEFA1jqkTyaXoveSQMz+3H5ZIxcQnk2eZQDcI3rwNZGVAXwTl0sMBxbvodMGr2nMv
         K98A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=g+B45gRPqg/dllmY4VmFKmvJ4wg17UG1GP7GTcAcQ1M=;
        b=hN2BaniYhR4ic1tmcRVnq2dSfqS1McXkrjedtfWesiBBdhBFmFLr4K2BhmeYSRMdS3
         St/HROXLoZnY4E4xg5fshQokthidIUKfdb8mML0TDLNc8jMDzztJEjnaWQOwf80mwkUJ
         mbNQkkVW7FiNtoB1ICzYgVRRMXcSr/rMCcO3C8TsmDvpFJWFIREcVjjN2O7SXIWyOOAu
         q9VnNsm0KbATGSQC24Jx8kKReyHeVVEhTUsxYZMf7wxym/ftMHnUjhJcCCkIJfBrHT3+
         pKiAnCTnnIgZflmEVoZH14zrj4UWiXycxhCy+VCbfFhwLvZc6KoAkfkKx5JAK0gLvrDw
         K82Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="PGKf9/dc";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=g+B45gRPqg/dllmY4VmFKmvJ4wg17UG1GP7GTcAcQ1M=;
        b=T/QCFOb2y8P3cwKS0VWJyUOCG3idcOKnsiVBzc0879049sUBolWsdqla4W5nzRi7nO
         8wn3+5+gobxWpVjxwOvren3Te5fpxQu3ABQxy4Nukb4yYuUMOBMy3eO989U6mg8pZIUu
         CQksaBFuGbcGjeEaZvnw+IZOTy9mn6V2IhsLceoDIbjR1+tqO7ITQYKSx7m0NbkBeGwt
         qg2G5M0Sz8f1ZdsFiFOp67RoSDNj+VHZfZ56BHKTYV4IlYRaC9RDKDP3DtXwHRBw9zNF
         62766uiRcMcym2rE56izFxFINJQrvvu4DFuLGiWSVXIylTX82/WEuHZVsYE/OcjiuUOM
         dKBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g+B45gRPqg/dllmY4VmFKmvJ4wg17UG1GP7GTcAcQ1M=;
        b=N8dh0RNGZrhYnYRsJx5YRBIjvX/02ZAhZG9eMe1XUx2+iqVrqn8wxIIXjdRRWR1w8g
         mXvYLMV57OMTfirE+AVfNgi0AD3rVCQ8ldP91Y2AqstOifSa638GqDt2eh8SC7Mzcfg6
         47FfBoYtUJ++125OHYBKrJ/DFcoVEGnI1J49GPoXuJ9UEZG8XS8/Gp5umVcL21lcQbNM
         Sa5wMusZatQyKYnAlBqUveuj6Dx7vjUSJtqVC1q6nimQx7ZIC/vIjMeoaR3KIj1C6pS2
         RxJbn6mGgLII2eyhikcCWItcxiEiBMa85uSDk2dt3cnuon1L+5VUmecYgkTa8OtDh2NA
         0lYQ==
X-Gm-Message-State: ANoB5plIQZQxpDt/OpxIVF00gjkawO+F2H0YKz+kFSEWGHvNy1JI5VOr
	jFyD60/3mfuP3vuMHx+0h8U=
X-Google-Smtp-Source: AA0mqf7D88geCmd4R9Ep5Fi4SS13j2z32g51aVUlGLnmquV681Di7tEAVZAmdcg9yaQbYYTuXesQtQ==
X-Received: by 2002:aa7:9045:0:b0:56c:a321:eecb with SMTP id n5-20020aa79045000000b0056ca321eecbmr8712014pfo.19.1668791397282;
        Fri, 18 Nov 2022 09:09:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6a0a:0:b0:46e:b96a:9961 with SMTP id f10-20020a636a0a000000b0046eb96a9961ls3026828pgc.4.-pod-prod-gmail;
 Fri, 18 Nov 2022 09:09:56 -0800 (PST)
X-Received: by 2002:a62:1a05:0:b0:56c:1277:d056 with SMTP id a5-20020a621a05000000b0056c1277d056mr8629706pfa.23.1668791396450;
        Fri, 18 Nov 2022 09:09:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668791396; cv=none;
        d=google.com; s=arc-20160816;
        b=m3qHzdnl+6aTjRavj6ZPP9Zhz7/17LUs8hLune5fK8Bspp8Zyhb/0WDHKEMNwJsxWJ
         PxqPhdpXzRGpa/OG6hhu0hENLGsGxe1isQ//6PGEKBNAXjWeLf15IVLdPLHeei9ABhJL
         W1mJ/DOGVCTtxY+EFCrvDyXiQChgXKilO5xsVUI14STga+owdhgFCn8nDjqfCQPjE5Lc
         tH6t/cY1jhlM2aVosAJ3pvwnMjmv/j0OWbebvDt2zxHbpKmlMevyWxGbfIKR1387KKgG
         DI5qsgyLvTfPBm1sx8ObnkYAbRgvWg7nQbNpOsYLfXVSOxUJsVGg76ULBjrTl9IJxVvn
         629Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HxawSV9BNIQZeeJx9upRwMR/8ffnB4z3mTZ1jlasJ1Y=;
        b=WbpO/7XRD1fXExpu2ly0vSB9JIjBtv+trttfEqrRvBMxEjZvc0iNnck1cH2hJSxqVD
         HVFN/IvNwbvfvXTkMFHUNYFPV3GDm1u5KwrZ+ucetFv/7htFDYEc5gHvmkEipWlogc3k
         V+p4mzuwU1lxul5nTiO8IPFWydREwFnG8P8oMlltQZI40Z6Kkrmq4xclMhCmAPGQUpMo
         S5TuZM6VJ/7vnWh46inC1v1gtAJOZl48WjUM6vPumsDRrKAK+doR/SVX4EQ6UG+0s9Me
         BfBUdYb4ZU0CyZwzOkjozwH/xjha2vKhbWILeni6OijqW/aIOKDkQ/flXkzoP5k5W0Hr
         I1rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="PGKf9/dc";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id x9-20020a17090a970900b002188bd6aacbsi75391pjo.3.2022.11.18.09.09.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Nov 2022 09:09:56 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-3691e040abaso55305227b3.9
        for <kasan-dev@googlegroups.com>; Fri, 18 Nov 2022 09:09:56 -0800 (PST)
X-Received: by 2002:a81:dd05:0:b0:36e:8228:a127 with SMTP id
 e5-20020a81dd05000000b0036e8228a127mr7429659ywn.299.1668791395464; Fri, 18
 Nov 2022 09:09:55 -0800 (PST)
MIME-Version: 1.0
References: <20221118152216.3914899-1-elver@google.com>
In-Reply-To: <20221118152216.3914899-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Nov 2022 18:09:19 +0100
Message-ID: <CAG_fn=XGY6npNhVwK76zSZzYC61=7-8ag3Jcey4PXa46E1ee-A@mail.gmail.com>
Subject: Re: [PATCH] kfence: fix stack trace pruning
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Feng Tang <feng.tang@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="PGKf9/dc";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1136
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Fri, Nov 18, 2022 at 4:22 PM Marco Elver <elver@google.com> wrote:
>
> Commit b14051352465 ("mm/sl[au]b: generalize kmalloc subsystem")
> refactored large parts of the kmalloc subsystem, resulting in the stack
> trace pruning logic done by KFENCE to no longer work.
>
> While b14051352465 attempted to fix the situation by including
> '__kmem_cache_free' in the list of functions KFENCE should skip through,
> this only works when the compiler actually optimized the tail call from
> kfree() to __kmem_cache_free() into a jump (and thus kfree() _not_
> appearing in the full stack trace to begin with).
>
> In some configurations, the compiler no longer optimizes the tail call
> into a jump, and __kmem_cache_free() appears in the stack trace. This
> means that the pruned stack trace shown by KFENCE would include kfree()
> which is not intended - for example:
>
>  | BUG: KFENCE: invalid free in kfree+0x7c/0x120
>  |
>  | Invalid free of 0xffff8883ed8fefe0 (in kfence-#126):
>  |  kfree+0x7c/0x120
>  |  test_double_free+0x116/0x1a9
>  |  kunit_try_run_case+0x90/0xd0
>  | [...]
>
> Fix it by moving __kmem_cache_free() to the list of functions that may
> be tail called by an allocator entry function, making the pruning logic
> work in both the optimized and unoptimized tail call cases.
>
> Fixes: b14051352465 ("mm/sl[au]b: generalize kmalloc subsystem")
> Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Cc: Feng Tang <feng.tang@intel.com>
> Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  mm/kfence/report.c | 13 +++++++++----
>  1 file changed, 9 insertions(+), 4 deletions(-)
>
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index 7e496856c2eb..46ecea18c4ca 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -75,18 +75,23 @@ static int get_stack_skipnr(const unsigned long stack=
_entries[], int num_entries
>
>                 if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfence_") ||
>                     str_has_prefix(buf, ARCH_FUNC_PREFIX "__kfence_") ||
> +                   str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmem_cache_fr=
ee") ||
>                     !strncmp(buf, ARCH_FUNC_PREFIX "__slab_free", len)) {
>                         /*
> -                        * In case of tail calls from any of the below
> -                        * to any of the above.
> +                        * In case of tail calls from any of the below to=
 any of
> +                        * the above, optimized by the compiler such that=
 the
> +                        * stack trace would omit the initial entry point=
 below.
>                          */
>                         fallback =3D skipnr + 1;
>                 }
>
> -               /* Also the *_bulk() variants by only checking prefixes. =
*/
> +               /*
> +                * The below list should only include the initial entry p=
oints
> +                * into the slab allocators. Includes the *_bulk() varian=
ts by
> +                * checking prefixes.
> +                */
>                 if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfree") ||
>                     str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_free=
") ||
> -                   str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmem_cache_fr=
ee") ||
>                     str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmalloc") ||
>                     str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_allo=
c"))
>                         goto found;
> --
> 2.38.1.584.g0f3c55d4c2-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXGY6npNhVwK76zSZzYC61%3D7-8ag3Jcey4PXa46E1ee-A%40mail.gm=
ail.com.
