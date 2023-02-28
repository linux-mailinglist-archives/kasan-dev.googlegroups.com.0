Return-Path: <kasan-dev+bncBDW2JDUY5AORBFOR7GPQMGQEQUXGHZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id B11AD6A609F
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 21:48:22 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id 65-20020aca0644000000b00383e7adefc0sf3546088oig.11
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 12:48:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677617301; cv=pass;
        d=google.com; s=arc-20160816;
        b=RJzcfQ/7iupuchqgje/0/x3ZN/Szb7wugg9s1ZvQPbukEy1jjaoYMVF98Xy4Sia2e5
         eQhNhQcJ21OAFXjSAAT4lYNAEF8+kwmUjz4N40wd57eHDss0aOKH/gt3aEuw3eQO/FXf
         g2Gke0s8tr6CrfxfaeG67JJagfLxXadn3lZERYicEqDT15oE6DWTXUg4HjoA1PKudZ1H
         nb32u2824+XHjkqaGjK00W9xkxz9d/qVxPy+OMqwzW02ubcnrLyhAbFdRe981ZAWCIGi
         Bj6nm4ITStbded1q+brPPsz/Eb2kKnWrrPtXUSo+QKNuRrBeAHPsuBEL7gHDhsWeauAH
         BYsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=bFuM/Jr4L89sqi/0ntJcIzURNkbHA4ZEkc5goSmAlO0=;
        b=Ap0yFXTIMQjjXMcoitPRZ1ZzTFo4P3NjU16W7QGvOlZiykKpQS2A8n2wkb1m1QigjY
         5s+p/SesOafOWo/UQh4FQwg/vTni44OklR9J/nuURVz1PBlRXVsWCQuHPLW7sPVVBYtd
         QEvEZ8VDXv3DpIXMqAIIE+8gmJw3gRtTvv6SOxL2HAw9DvoBn0puw62BdhcWnJkLKP98
         Fv8MnMDnE3j1fYZofPE6S9ooA6as8gziWgNv4GXmzQvdbnE08U+msn3KYRxc8UCaiFR9
         eYuYuFU5iXyqJwNgeSxTS+US0KWlV0AiJ8kXrAurcEJ/OQ4Qa1R+nNESn3MmJVRy6dOt
         5ing==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=AvBFEisD;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bFuM/Jr4L89sqi/0ntJcIzURNkbHA4ZEkc5goSmAlO0=;
        b=KKgDWwhUCKVWjyFp2bGLAyGpYrysH20tBW3lAXSGJsFq6GwiHxTNeR4lvBBjNlxgg3
         nR3lWd3rfuPpRcUP+QbiZB9YX8gk5C5c3pg/G9OPaPFGZ4XesROlIC6dkAtDIkZtG6Ws
         tH+vJxZMMIQhBibTvCnK80lPiN5QSCuNjazPma6Ea23Jp0NkNp+07cPEXL8I+WGqg9Or
         RBLn9BKqCAawSY6AshvZ5qVFJZp5HqHqP9i3FINPQ5pTnndn8I6cvA3QxHs8aliYYMMM
         jQBQ7unX9S0uj6iEchJtFo1jAvXDKF8jIb3/HAuEo6wSgQNNmfGVvaFDzjSVw/fCXSGf
         2f6A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bFuM/Jr4L89sqi/0ntJcIzURNkbHA4ZEkc5goSmAlO0=;
        b=hWQhM3Jxwq2aer78Rg6C3fdh4YJ3iv6/hm2t1HwV0TOIuySxT3Cy9/KYErpP1rCsKU
         cXO0g4mhcRpz5Bcj+7Wt0BnLFF/qlq3guKFPOeVc1DVaJIjPLGp9i+qQ/rqDA/VSkQ6g
         NwH1njpkJe22JCZPsOZSO6K9OBYwrkp0U6nALewPvbkTqn89GeX13rh3trCXiSPIZPmk
         fvHmlczeRaN7fhiI+b6JGMEFQNPG+VTfjE6+1f+PnZfFLuoDZudspGRU/zJG2oKI/ihI
         5zS8AfQpPOlc38ikRz0WOVfQiNMXRKY0/U+BMHwzEiq4yWUthcOzzRbgITDH4G2n9te4
         jMRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=bFuM/Jr4L89sqi/0ntJcIzURNkbHA4ZEkc5goSmAlO0=;
        b=NTQiTvcZKqzQyoiWRed5tUEKx1rbsmsxsE3vBHtnUVp9Jr2ouOVfGxkly6nfGv/dzA
         ztv7O10Z5gOldaPcKlgVRm98Ijj7huewsKVQcidXXiOsdHtk+1VVJ5KOj46Xp0rmNIpt
         mjvqyDwPX/kO4zTAtXcttDuehwRtlI0Wp/g5sHwDjKTFTA6ECsGB30xGd4qq0baqoEMk
         5PZKMPjbHpTRQcNA753eqTisHOHvvVtcXe7qgnry1pVNW1QgXO5IlUesi0CwuPYsgCeF
         U5OesoLZJtXOxf54kMVDf10MPz3X927OvziQ36UkParzffaRp3ciudPqPWxfrh85VcP3
         ppOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKV/HPHYoug5QEuNwcaJKsI5D1e7VGYTe/HaZ80wCjnX1BIXcJhH
	OORrB5DGafZVMfJ6TRgn6rU=
X-Google-Smtp-Source: AK7set83SGRAmnOqmGypbAzX3iH5aF8uDIF1tm7t/YaGSBaCDWC1F0sHoG5WNCsiriJIcXsMIJOGkw==
X-Received: by 2002:a05:6870:1aa6:b0:172:5195:753 with SMTP id ef38-20020a0568701aa600b0017251950753mr1140317oab.3.1677617301303;
        Tue, 28 Feb 2023 12:48:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:8e06:b0:16e:8811:eaec with SMTP id
 lw6-20020a0568708e0600b0016e8811eaecls5435709oab.4.-pod-prod-gmail; Tue, 28
 Feb 2023 12:48:20 -0800 (PST)
X-Received: by 2002:a05:6871:10f:b0:169:e00f:aa40 with SMTP id y15-20020a056871010f00b00169e00faa40mr2547747oab.41.1677617300853;
        Tue, 28 Feb 2023 12:48:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677617300; cv=none;
        d=google.com; s=arc-20160816;
        b=SizM1ERj6hWXv2nZXPK3Rf31TTvsnrxx3Rknch9exppaXZ1DkcTZSovkNUr/O5qV8E
         iwtZ36t9KfWvX0eqgKcYowQNsP6wQskyAa+aHTk1nmwkDu3fEr4q9v5oiD338v2KJfCS
         cx7oZl7Kmuy/XV8koyicQ+dfmGRHf1PR6qVjsCn8c5o70X9KPFClopUSYTPOAFbsJXXD
         1zS2Oxj9+bR99b65m7x0GxFShQHu86SIgE6vXiwiAyNjtRI9+hEj7F20aWX/1WMyCUFu
         QM2Ttgi5FB8v913MnwUInKcLfms/PnXEA4bZ8hIvGpdTDmEMZxHzapG5XljB1YFseNmC
         qp6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=QjEipJ5COAgM/CUAr8aRHqd6+hTCueASmrwYUwgRgIw=;
        b=nyLlgJRWmN6gsdJTPv6Vdnldy4y7zJUCEPsYA5DCkCGwInlHTU1lGqZ9g3tWU183BS
         f3MbDMbgp/OSci9STzIMQP6wBScvQh+Z7n9zJ6hAureoE2K2HfLVe32Ir25wE8NhKCLR
         8qXDU/5uEgGmQdNJxkaUNr0P7dsuFLM2579+Ws9hjeRzC13mIz/gDpQPLiWQ4DDlHu23
         KkAeuP8cJaI0s/XsIZ1zWOUetusqxykyBXsmKFH/xgz+lw1DFB7J1GJHhtrlQ2sAQvnw
         f3we1J798RA5aGISFH3OYWAcOLT+6vIB2mlZdxtEsEbofZqiFhNNAqEjCOLSUyiPlk9v
         pJYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=AvBFEisD;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id bf11-20020a056820174b00b005176d876205si886524oob.0.2023.02.28.12.48.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Feb 2023 12:48:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 16so6453071pge.11
        for <kasan-dev@googlegroups.com>; Tue, 28 Feb 2023 12:48:20 -0800 (PST)
X-Received: by 2002:a63:7d59:0:b0:502:e6c0:88a4 with SMTP id
 m25-20020a637d59000000b00502e6c088a4mr1324263pgn.5.1677617299741; Tue, 28 Feb
 2023 12:48:19 -0800 (PST)
MIME-Version: 1.0
References: <20230228063240.3613139-1-pcc@google.com> <20230228063240.3613139-3-pcc@google.com>
In-Reply-To: <20230228063240.3613139-3-pcc@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 28 Feb 2023 21:48:08 +0100
Message-ID: <CA+fCnZcDK_zwGDkLC9GmgkQhzXu8yZ8GUghyCR2M7TUdgcGonw@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] kasan: remove PG_skip_kasan_poison flag
To: Peter Collingbourne <pcc@google.com>
Cc: catalin.marinas@arm.com, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=AvBFEisD;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52e
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

On Tue, Feb 28, 2023 at 7:32=E2=80=AFAM Peter Collingbourne <pcc@google.com=
> wrote:
>
> Code inspection reveals that PG_skip_kasan_poison is redundant with
> kasantag, because the former is intended to be set iff the latter is
> the match-all tag. It can also be observed that it's basically pointless
> to poison pages which have kasantag=3D0, because any pages with this tag
> would have been pointed to by pointers with match-all tags, so poisoning
> the pages would have little to no effect in terms of bug detection.
> Therefore, change the condition in should_skip_kasan_poison() to check
> kasantag instead, and remove PG_skip_kasan_poison and associated flags.
>
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Link: https://linux-review.googlesource.com/id/I57f825f2eaeaf7e8389d6cf45=
97c8a5821359838
> ---
> v2:
> - also remove GFP_SKIP_KASAN_POISON and FPI_SKIP_KASAN_POISON
> - rename GFP_SKIP_KASAN_UNPOISON to GFP_SKIP_KASAN
> - update comments
> - simplify control flow by removing reset_tags
>
>  include/linux/gfp_types.h      | 28 +++++-------
>  include/linux/page-flags.h     |  9 ----
>  include/trace/events/mmflags.h | 12 +-----
>  mm/kasan/hw_tags.c             |  2 +-
>  mm/page_alloc.c                | 79 +++++++++++++---------------------
>  mm/vmalloc.c                   |  2 +-
>  6 files changed, 44 insertions(+), 88 deletions(-)
>
> diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
> index 5088637fe5c2..9bd45cdd19ac 100644
> --- a/include/linux/gfp_types.h
> +++ b/include/linux/gfp_types.h
> @@ -47,16 +47,14 @@ typedef unsigned int __bitwise gfp_t;
>  #define ___GFP_ACCOUNT         0x400000u
>  #define ___GFP_ZEROTAGS                0x800000u
>  #ifdef CONFIG_KASAN_HW_TAGS
> -#define ___GFP_SKIP_ZERO               0x1000000u
> -#define ___GFP_SKIP_KASAN_UNPOISON     0x2000000u
> -#define ___GFP_SKIP_KASAN_POISON       0x4000000u
> +#define ___GFP_SKIP_ZERO       0x1000000u
> +#define ___GFP_SKIP_KASAN      0x2000000u
>  #else
> -#define ___GFP_SKIP_ZERO               0
> -#define ___GFP_SKIP_KASAN_UNPOISON     0
> -#define ___GFP_SKIP_KASAN_POISON       0
> +#define ___GFP_SKIP_ZERO       0
> +#define ___GFP_SKIP_KASAN      0
>  #endif
>  #ifdef CONFIG_LOCKDEP
> -#define ___GFP_NOLOCKDEP       0x8000000u
> +#define ___GFP_NOLOCKDEP       0x4000000u
>  #else
>  #define ___GFP_NOLOCKDEP       0
>  #endif
> @@ -234,25 +232,22 @@ typedef unsigned int __bitwise gfp_t;
>   * memory tags at the same time as zeroing memory has minimal additional
>   * performace impact.
>   *
> - * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page alloc=
ation.
> - * Only effective in HW_TAGS mode.
> - *
> - * %__GFP_SKIP_KASAN_POISON makes KASAN skip poisoning on page deallocat=
ion.
> - * Typically, used for userspace pages. Only effective in HW_TAGS mode.
> + * %__GFP_SKIP_KASAN makes KASAN skip unpoisoning on page allocation and
> + * poisoning on page deallocation. Typically used for userspace and vmal=
loc
> + * pages. Only effective in HW_TAGS mode.

This is not entirely correct: for vmalloc pages, this flag doesn't
result in poisoning being skipped, as the memory is unpoisoned and
page tags are assigned by kasan_unpoison_vmalloc.

How about something like this:

%__GFP_SKIP_KASAN makes KASAN skip unpoisoning on page allocation.
Used for userspace and vmalloc pages; the latter are unpoisoned by
kasan_unpoison_vmalloc instead. For userspace pages, results in
poisoning being skipped as well, see should_skip_kasan_poison for
details. Only effective in HW_TAGS mode.

>   */
>  #define __GFP_NOWARN   ((__force gfp_t)___GFP_NOWARN)
>  #define __GFP_COMP     ((__force gfp_t)___GFP_COMP)
>  #define __GFP_ZERO     ((__force gfp_t)___GFP_ZERO)
>  #define __GFP_ZEROTAGS ((__force gfp_t)___GFP_ZEROTAGS)
>  #define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
> -#define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPO=
ISON)
> -#define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POIS=
ON)
> +#define __GFP_SKIP_KASAN ((__force gfp_t)___GFP_SKIP_KASAN)
>
>  /* Disable lockdep for GFP context tracking */
>  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
>
>  /* Room for N __GFP_FOO bits */
> -#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
> +#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
>  #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
>
>  /**
> @@ -335,8 +330,7 @@ typedef unsigned int __bitwise gfp_t;
>  #define GFP_DMA                __GFP_DMA
>  #define GFP_DMA32      __GFP_DMA32
>  #define GFP_HIGHUSER   (GFP_USER | __GFP_HIGHMEM)
> -#define GFP_HIGHUSER_MOVABLE   (GFP_HIGHUSER | __GFP_MOVABLE | \
> -                        __GFP_SKIP_KASAN_POISON | __GFP_SKIP_KASAN_UNPOI=
SON)
> +#define GFP_HIGHUSER_MOVABLE   (GFP_HIGHUSER | __GFP_MOVABLE | __GFP_SKI=
P_KASAN)
>  #define GFP_TRANSHUGE_LIGHT    ((GFP_HIGHUSER_MOVABLE | __GFP_COMP | \
>                          __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAI=
M)
>  #define GFP_TRANSHUGE  (GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM)
> diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
> index a7e3a3405520..74f81a52e7e1 100644
> --- a/include/linux/page-flags.h
> +++ b/include/linux/page-flags.h
> @@ -135,9 +135,6 @@ enum pageflags {
>  #ifdef CONFIG_ARCH_USES_PG_ARCH_X
>         PG_arch_2,
>         PG_arch_3,
> -#endif
> -#ifdef CONFIG_KASAN_HW_TAGS
> -       PG_skip_kasan_poison,
>  #endif
>         __NR_PAGEFLAGS,
>
> @@ -594,12 +591,6 @@ TESTCLEARFLAG(Young, young, PF_ANY)
>  PAGEFLAG(Idle, idle, PF_ANY)
>  #endif
>
> -#ifdef CONFIG_KASAN_HW_TAGS
> -PAGEFLAG(SkipKASanPoison, skip_kasan_poison, PF_HEAD)
> -#else
> -PAGEFLAG_FALSE(SkipKASanPoison, skip_kasan_poison)
> -#endif
> -
>  /*
>   * PageReported() is used to track reported free pages within the Buddy
>   * allocator. We can use the non-atomic version of the test and set
> diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmflag=
s.h
> index 9db52bc4ce19..232bc8efc98e 100644
> --- a/include/trace/events/mmflags.h
> +++ b/include/trace/events/mmflags.h
> @@ -55,8 +55,7 @@
>  #ifdef CONFIG_KASAN_HW_TAGS
>  #define __def_gfpflag_names_kasan ,                    \
>         gfpflag_string(__GFP_SKIP_ZERO),                \
> -       gfpflag_string(__GFP_SKIP_KASAN_POISON),        \
> -       gfpflag_string(__GFP_SKIP_KASAN_UNPOISON)
> +       gfpflag_string(__GFP_SKIP_KASAN)
>  #else
>  #define __def_gfpflag_names_kasan
>  #endif
> @@ -96,12 +95,6 @@
>  #define IF_HAVE_PG_ARCH_X(flag,string)
>  #endif
>
> -#ifdef CONFIG_KASAN_HW_TAGS
> -#define IF_HAVE_PG_SKIP_KASAN_POISON(flag,string) ,{1UL << flag, string}
> -#else
> -#define IF_HAVE_PG_SKIP_KASAN_POISON(flag,string)
> -#endif
> -
>  #define __def_pageflag_names                                           \
>         {1UL << PG_locked,              "locked"        },              \
>         {1UL << PG_waiters,             "waiters"       },              \
> @@ -130,8 +123,7 @@ IF_HAVE_PG_HWPOISON(PG_hwpoison,    "hwpoison"      )=
               \
>  IF_HAVE_PG_IDLE(PG_young,              "young"         )               \
>  IF_HAVE_PG_IDLE(PG_idle,               "idle"          )               \
>  IF_HAVE_PG_ARCH_X(PG_arch_2,           "arch_2"        )               \
> -IF_HAVE_PG_ARCH_X(PG_arch_3,           "arch_3"        )               \
> -IF_HAVE_PG_SKIP_KASAN_POISON(PG_skip_kasan_poison, "skip_kasan_poison")
> +IF_HAVE_PG_ARCH_X(PG_arch_3,           "arch_3"        )
>
>  #define show_page_flags(flags)                                         \
>         (flags) ? __print_flags(flags, "|",                             \
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index d1bcb0205327..bb4f56e5bdec 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -318,7 +318,7 @@ void *__kasan_unpoison_vmalloc(const void *start, uns=
igned long size,
>          * Thus, for VM_ALLOC mappings, hardware tag-based KASAN only tag=
s
>          * the first virtual mapping, which is created by vmalloc().
>          * Tagging the page_alloc memory backing that vmalloc() allocatio=
n is
> -        * skipped, see ___GFP_SKIP_KASAN_UNPOISON.
> +        * skipped, see ___GFP_SKIP_KASAN.
>          *
>          * For non-VM_ALLOC allocations, page_alloc memory is tagged as u=
sual.
>          */
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 7136c36c5d01..960e0edd413d 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -112,17 +112,6 @@ typedef int __bitwise fpi_t;
>   */
>  #define FPI_TO_TAIL            ((__force fpi_t)BIT(1))
>
> -/*
> - * Don't poison memory with KASAN (only for the tag-based modes).
> - * During boot, all non-reserved memblock memory is exposed to page_allo=
c.
> - * Poisoning all that memory lengthens boot time, especially on systems =
with
> - * large amount of RAM. This flag is used to skip that poisoning.
> - * This is only done for the tag-based KASAN modes, as those are able to
> - * detect memory corruptions with the memory tags assigned by default.
> - * All memory allocated normally after boot gets poisoned as usual.
> - */
> -#define FPI_SKIP_KASAN_POISON  ((__force fpi_t)BIT(2))
> -
>  /* prevent >1 _updater_ of zone percpu pageset ->high and ->batch fields=
 */
>  static DEFINE_MUTEX(pcp_batch_high_lock);
>  #define MIN_PERCPU_PAGELIST_HIGH_FRACTION (8)
> @@ -1355,13 +1344,19 @@ static int free_tail_pages_check(struct page *hea=
d_page, struct page *page)
>  /*
>   * Skip KASAN memory poisoning when either:
>   *
> - * 1. Deferred memory initialization has not yet completed,
> - *    see the explanation below.
> - * 2. Skipping poisoning is requested via FPI_SKIP_KASAN_POISON,
> - *    see the comment next to it.
> - * 3. Skipping poisoning is requested via __GFP_SKIP_KASAN_POISON,
> + * 1. For generic KASAN: deferred memory initialization has not yet comp=
leted.
> + *    Tag-based KASAN modes skip pages freed via deferred memory initial=
ization
> + *    using page tags instead (see below).
> + * 2. For tag-based KASAN: the page has a match-all KASAN tag, indicatin=
g

For tag-based KASAN modes: ...

> + *    that error detection is disabled for accesses via the page address=
.
> + *
> + * Pages will have match-all tags in the following circumstances:
> + *
> + * 1. Skipping poisoning is requested via __GFP_SKIP_KASAN,
>   *    see the comment next to it.

According to the vmalloc thing I mentioned above, let's reword this to:

The allocation was not unpoisoned due to __GFP_SKIP_KASAN, with the
exception of pages unpoisoned by kasan_unpoison_vmalloc.

> - * 4. The allocation is excluded from being checked due to sampling,
> + * 2. Pages are being initialized for the first time, including during d=
eferred
> + *    memory init; see the call to page_kasan_tag_reset in __init_single=
_page.

Let's put this item first in the list.

> + * 3. The allocation is excluded from being checked due to sampling,

"is" -> "was" possibly sounds better with "was" in #1.

>   *    see the call to kasan_unpoison_pages.
>   *
>   * Poisoning pages during deferred memory init will greatly lengthen the
> @@ -1377,10 +1372,10 @@ static int free_tail_pages_check(struct page *hea=
d_page, struct page *page)
>   */
>  static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi=
_flags)
>  {
> -       return deferred_pages_enabled() ||
> -              (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
> -               (fpi_flags & FPI_SKIP_KASAN_POISON)) ||
> -              PageSkipKASanPoison(page);
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               return deferred_pages_enabled();
> +
> +       return page_kasan_tag(page) =3D=3D 0xff;
>  }
>
>  static void kernel_init_pages(struct page *page, int numpages)
> @@ -1754,7 +1749,7 @@ void __free_pages_core(struct page *page, unsigned =
int order)
>          * Bypass PCP and place fresh pages right to the tail, primarily
>          * relevant for memory onlining.
>          */
> -       __free_pages_ok(page, order, FPI_TO_TAIL | FPI_SKIP_KASAN_POISON)=
;
> +       __free_pages_ok(page, order, FPI_TO_TAIL);
>  }
>
>  #ifdef CONFIG_NUMA
> @@ -2456,9 +2451,9 @@ static inline bool should_skip_kasan_unpoison(gfp_t=
 flags)
>
>         /*
>          * With hardware tag-based KASAN enabled, skip if this has been
> -        * requested via __GFP_SKIP_KASAN_UNPOISON.
> +        * requested via __GFP_SKIP_KASAN.
>          */
> -       return flags & __GFP_SKIP_KASAN_UNPOISON;
> +       return flags & __GFP_SKIP_KASAN;
>  }
>
>  static inline bool should_skip_init(gfp_t flags)
> @@ -2477,7 +2472,6 @@ inline void post_alloc_hook(struct page *page, unsi=
gned int order,
>         bool init =3D !want_init_on_free() && want_init_on_alloc(gfp_flag=
s) &&
>                         !should_skip_init(gfp_flags);
>         bool zero_tags =3D init && (gfp_flags & __GFP_ZEROTAGS);
> -       bool reset_tags =3D true;
>         int i;
>
>         set_page_private(page, 0);
> @@ -2511,37 +2505,22 @@ inline void post_alloc_hook(struct page *page, un=
signed int order,
>                 /* Take note that memory was initialized by the loop abov=
e. */
>                 init =3D false;
>         }
> -       if (!should_skip_kasan_unpoison(gfp_flags)) {
> -               /* Try unpoisoning (or setting tags) and initializing mem=
ory. */
> -               if (kasan_unpoison_pages(page, order, init)) {
> -                       /* Take note that memory was initialized by KASAN=
. */
> -                       if (kasan_has_integrated_init())
> -                               init =3D false;
> -                       /* Take note that memory tags were set by KASAN. =
*/
> -                       reset_tags =3D false;
> -               } else {
> -                       /*
> -                        * KASAN decided to exclude this allocation from =
being
> -                        * (un)poisoned due to sampling. Make KASAN skip
> -                        * poisoning when the allocation is freed.
> -                        */
> -                       SetPageSkipKASanPoison(page);
> -               }
> -       }
> -       /*
> -        * If memory tags have not been set by KASAN, reset the page tags=
 to
> -        * ensure page_address() dereferencing does not fault.
> -        */
> -       if (reset_tags) {
> +       if (!should_skip_kasan_unpoison(gfp_flags) &&
> +           kasan_unpoison_pages(page, order, init)) {
> +               /* Take note that memory was initialized by KASAN. */
> +               if (kasan_has_integrated_init())
> +                       init =3D false;
> +       } else {
> +               /*
> +                * If memory tags have not been set by KASAN, reset the p=
age
> +                * tags to ensure page_address() dereferencing does not f=
ault.
> +                */
>                 for (i =3D 0; i !=3D 1 << order; ++i)
>                         page_kasan_tag_reset(page + i);
>         }
>         /* If memory is still not initialized, initialize it now. */
>         if (init)
>                 kernel_init_pages(page, 1 << order);
> -       /* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
> -       if (kasan_hw_tags_enabled() && (gfp_flags & __GFP_SKIP_KASAN_POIS=
ON))
> -               SetPageSkipKASanPoison(page);
>
>         set_page_owner(page, order, gfp_flags);
>         page_table_check_alloc(page, order);
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index ef910bf349e1..b0c84847e9b6 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -3170,7 +3170,7 @@ void *__vmalloc_node_range(unsigned long size, unsi=
gned long align,
>                          * pages backing VM_ALLOC mapping. Memory is inst=
ead
>                          * poisoned and zeroed by kasan_unpoison_vmalloc(=
).
>                          */
> -                       gfp_mask |=3D __GFP_SKIP_KASAN_UNPOISON | __GFP_S=
KIP_ZERO;
> +                       gfp_mask |=3D __GFP_SKIP_KASAN | __GFP_SKIP_ZERO;
>                 }
>
>                 /* Take note that the mapping is PAGE_KERNEL. */
> --
> 2.39.2.722.g9855ee24e9-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcDK_zwGDkLC9GmgkQhzXu8yZ8GUghyCR2M7TUdgcGonw%40mail.gmai=
l.com.
