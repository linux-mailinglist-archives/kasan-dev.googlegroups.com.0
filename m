Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6H6U2DAMGQEG3OJB6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 026963A958F
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 11:08:10 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id h10-20020a17090adb8ab029016f0d679be9sf1204694pjv.5
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 02:08:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623834488; cv=pass;
        d=google.com; s=arc-20160816;
        b=BMekNoVYUMDqxhIbSTEerZyT38c9poCy7AKyt5bQGqo8aqi/NofMbfc9DZ/vDINOfa
         AUCBIU4USglIVMrUlYQ20918RKmYaUiSlSlAFeyq3cnyTz3SaVQkkZrqjLnmXZe/EFN8
         LAlNFqu0B/DzBJppOgvIshMU7lBOFAmMotbkCYBrQu+VqArphwITQGy+7tIyVtzOLsqR
         JM/UX1X3i56kwfUz9OyQ63oRonqaynI7bL1BnxygW/OVA5gOm0vI+h5vXmLdyBqn0uT2
         8UCxzbiPjs7entJ+kJe8bNBQmAGnjABiAbqwMgG7B+FsYfx3oD1mXbjFFABqGWZqkZgq
         iUiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oseAZdhblhRewODOr8VxgUbpBrb+2NRy95jXA5zDuk0=;
        b=BR9Mbu+CVnS46mQB1Vwf8leF2ZTt2Z4xK8JAhfTSMWJFVmdSu0nb2Bk6VROjHBuTzm
         6dpYAtxyVq+Cea1a0YYWsEmcCtwCV1Qu9ur61yN+czGLR1WLpdhwXvL8A0Yuy8qtEwj1
         EDtHfzbNx3SLdQMrG+o2I3Mbv2DJbfHjYZqxxaXWwVbs3lD6oLudrEqh82f/+Fp6kkiS
         XFXOFkhrXAj6QXIoL3Vf+Dkr9nJ2D73hsHzA9sgok1wjimy4khYrF5aS4ZFAGEc7Uais
         CryX6OwMGw6zk0rMudt23zD/DvjP6is4v7G9R1+wn8X8I55YxoskYx+sk2uszhmEbmsX
         XSIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lrYME9Lw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oseAZdhblhRewODOr8VxgUbpBrb+2NRy95jXA5zDuk0=;
        b=RPEF9q9w5jVDkj8n2tdPDPiSAH/zmFjdDbA40W/yClDKO0CSpmER1wsB0uUsLFyHNi
         EfBC4LZDSEm+AAztt91c0/+uacxVHsmCxV9uOoXV7IxMEv7YYsNEhnXctdydwcSKXa6H
         F0MYwwvNM0hg1vdQZIwNjtj/KrhPucIDwwHn8Px4pGK+sjPMPEWCQr7zC3TDkE11B9Ec
         6pqQ+jwrscIx2xTl/kQDMH+7hUMu0bjche/4R2WoodMu4c5pkP/p35+FYw1U/RscFMNV
         AKSRQ+dFMlc41CIBPVw27NGAZLSIYu6qNr4pfeY5D6GxdTS0JjJ+qerWxNnyrBzD7q0x
         pzlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oseAZdhblhRewODOr8VxgUbpBrb+2NRy95jXA5zDuk0=;
        b=qclB7Vy1qIHgD2ppnqVq5huUWJIgMuewuSP3U6tmpFODcfCryL6IBkHe95uC1Yfh3O
         9WBL/pkLz6dSAaaGsQRfcHLtFyL0NK3sdZzvIer5b4Pi4ULjwEkkbnggfyu3lCf0laA+
         iS1GUUndLsUyDckaztCbIkuDnXDfGScMZ2t14HOLM5+f3DGJ0aLTSuivE8OAGS463PE4
         LRn+7o1r5jTE6snumV44fWF9dxXWhoVHuK/tP+4SOYQCUr5jnEppNfr+ZEr7fRhCTTlh
         gPTmTN8k+dfChIlmxHomJvJLY0bw9Bz6cLHdg2Vjf6V9I0OKG0ZeSifPoTTmN1O/4SC6
         hWKg==
X-Gm-Message-State: AOAM531NmFkrVW3kzQ9Osb87bR7mkdjFHyFxpvoHszgYmmV60aUx8JTP
	LuN215BpUvdwJxQHNzBXUh4=
X-Google-Smtp-Source: ABdhPJwz7zvbRUnqN/g8ulh8tsmrd6dufXBo0glIL8+UP0vHHzpkya00IEAHTZGvfwtkbY/JYpkwKQ==
X-Received: by 2002:a17:902:d483:b029:115:3e1c:649c with SMTP id c3-20020a170902d483b02901153e1c649cmr8222672plg.44.1623834488672;
        Wed, 16 Jun 2021 02:08:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:414e:: with SMTP id m14ls1075025pjg.3.gmail; Wed, 16
 Jun 2021 02:08:08 -0700 (PDT)
X-Received: by 2002:a17:90a:17c8:: with SMTP id q66mr9813392pja.154.1623834488088;
        Wed, 16 Jun 2021 02:08:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623834488; cv=none;
        d=google.com; s=arc-20160816;
        b=WZaAmy/dgz5GlppSYPUrZL5EYFyFmsaQZ2yIgUMrYLReWchu7jiCuFMB1mb7BeI9jt
         8tPlQSHW66oiYte9HJEhEcLMo91RZpvfNmUOZHSrHti89RiX9FYfjjH10xVE29R+PR+O
         htIv6b0ghwLhsfgt7bvd2H5RSFExtElsJzGlipJCjcE/ygl7PEM5N2FNqCJ9GFL0J9Ax
         5Im9oRN0rUjhhV+Kv5h2m6Xm85NzQPfbFXumovoUU6I3O/NscUh39OYXrD+ArhruujO5
         x66Fn6z/a7rkCefVvxfnxs52L0jR81vB8DDKoYICWml8BXzZTiUtUBYILS2WmWlCLpdP
         DVGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9xuYq+64b5WvG58VNmoINL8JRqUZnuNk7CS6Gt/jkYU=;
        b=gb/u/rVVC9HTZr6hjQZukJd3kL43g1t1P7I7n3oYT5+dtaBaUVauX0INnK7Q74DQHF
         mOVDyGLxAUrBVIL9ygnhr3NfOp5iLPUHXFC8St+tOBPZ2OnZ5utJE5l07lJ3BP+GmE5z
         uSAW+h0aNi2pMRBcURrK7+LO0ST5aCJaVOoAdTPVd6yvIc5cTqLcxYDWwR8XZEhF85iG
         815hSQhHyEzYAd3wNDNwYWvxTQWEyRyA8qv3WTeDoECw6EQXbY/FE4l6JBeY99L6VHIG
         BsA0VUb8dyJSCgiWCllWf/RB3pKcnRBj6zb5XZJtEtt4cSB78jCTAirMRfXf3HKrU98J
         N0KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lrYME9Lw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x331.google.com (mail-ot1-x331.google.com. [2607:f8b0:4864:20::331])
        by gmr-mx.google.com with ESMTPS id a15si168999pgw.2.2021.06.16.02.08.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jun 2021 02:08:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) client-ip=2607:f8b0:4864:20::331;
Received: by mail-ot1-x331.google.com with SMTP id i12-20020a05683033ecb02903346fa0f74dso1787016otu.10
        for <kasan-dev@googlegroups.com>; Wed, 16 Jun 2021 02:08:08 -0700 (PDT)
X-Received: by 2002:a05:6830:1bcb:: with SMTP id v11mr3239145ota.251.1623834487248;
 Wed, 16 Jun 2021 02:08:07 -0700 (PDT)
MIME-Version: 1.0
References: <20210616080244.51236-1-dja@axtens.net> <20210616080244.51236-4-dja@axtens.net>
In-Reply-To: <20210616080244.51236-4-dja@axtens.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Jun 2021 11:07:55 +0200
Message-ID: <CANpmjNN2-nkqaQ8J3nU5QJ4KGkX2mwiNTeTCNPGQYdbb1v2OaA@mail.gmail.com>
Subject: Re: [PATCH v13 3/3] kasan: define and use MAX_PTRS_PER_* for early
 shadow tables
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	linuxppc-dev@lists.ozlabs.org, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	aneesh.kumar@linux.ibm.com, Balbir Singh <bsingharora@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lrYME9Lw;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as
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

On Wed, 16 Jun 2021 at 10:03, Daniel Axtens <dja@axtens.net> wrote:
[...]
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 768d7d342757..fd65f477ac92 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -40,10 +40,22 @@ struct kunit_kasan_expectation {
>  #define PTE_HWTABLE_PTRS 0
>  #endif
>
> +#ifndef MAX_PTRS_PER_PTE
> +#define MAX_PTRS_PER_PTE PTRS_PER_PTE
> +#endif
> +
> +#ifndef MAX_PTRS_PER_PMD
> +#define MAX_PTRS_PER_PMD PTRS_PER_PMD
> +#endif
> +
> +#ifndef MAX_PTRS_PER_PUD
> +#define MAX_PTRS_PER_PUD PTRS_PER_PUD
> +#endif

This is introducing new global constants in a <linux/..> header. It
feels like this should be in <linux/pgtable.h> together with a
comment. Because <linux/kasan.h> is actually included in
<linux/slab.h>, most of the kernel will get these new definitions.
That in itself is fine, but it feels wrong that the KASAN header
introduces these.

Thoughts?

Sorry for only realizing this now.

Thanks,
-- Marco

>  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
> -extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE + PTE_HWTABLE_PTRS];
> -extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
> -extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
> +extern pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE + PTE_HWTABLE_PTRS];
> +extern pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD];
> +extern pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD];
>  extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>
>  int kasan_populate_early_shadow(const void *shadow_start,
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index 348f31d15a97..cc64ed6858c6 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -41,7 +41,7 @@ static inline bool kasan_p4d_table(pgd_t pgd)
>  }
>  #endif
>  #if CONFIG_PGTABLE_LEVELS > 3
> -pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
> +pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD] __page_aligned_bss;
>  static inline bool kasan_pud_table(p4d_t p4d)
>  {
>         return p4d_page(p4d) == virt_to_page(lm_alias(kasan_early_shadow_pud));
> @@ -53,7 +53,7 @@ static inline bool kasan_pud_table(p4d_t p4d)
>  }
>  #endif
>  #if CONFIG_PGTABLE_LEVELS > 2
> -pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
> +pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD] __page_aligned_bss;
>  static inline bool kasan_pmd_table(pud_t pud)
>  {
>         return pud_page(pud) == virt_to_page(lm_alias(kasan_early_shadow_pmd));
> @@ -64,7 +64,7 @@ static inline bool kasan_pmd_table(pud_t pud)
>         return false;
>  }
>  #endif
> -pte_t kasan_early_shadow_pte[PTRS_PER_PTE + PTE_HWTABLE_PTRS]
> +pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE + PTE_HWTABLE_PTRS]
>         __page_aligned_bss;
>
>  static inline bool kasan_pte_table(pmd_t pmd)
> --
> 2.30.2
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210616080244.51236-4-dja%40axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN2-nkqaQ8J3nU5QJ4KGkX2mwiNTeTCNPGQYdbb1v2OaA%40mail.gmail.com.
