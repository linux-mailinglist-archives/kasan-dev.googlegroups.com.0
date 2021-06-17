Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIXKVODAMGQERXBRVOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 9ADF23AAD15
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 09:09:23 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id k193-20020a633dca0000b029021ff326b222sf3183853pga.9
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 00:09:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623913762; cv=pass;
        d=google.com; s=arc-20160816;
        b=TE7tj/l9dMmja8ca/NoQ9jrdmz1wSP6GRyAnz+8wuMWndv+v837A3s+lYSZhgAlPbz
         B9znhCEX2xeBpKSvBGrXBmG4Qn5pR5zMGr0U6cLPpS1awsRK4IomKhaDsYPGtt9uowna
         SZuNX6QPlp4lpGJoTF7a0G4v36yotq3siy7tQuNE+vet3reJcO11QDVakLFQbCInsjBn
         k/UqeHEo+NObGXPyqu5Toqavfnl6osmEixo1MQN3O7oPtJDlhhVAi/yQ8Csm2vBLZT/R
         xCwj4F9mRhVeEKlRyqcFRz0WqIhO4XDrLIsjowKvdd0tDLdYeEVq6W/JFqteEbm9kbKx
         G10A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=q0QdjKroxSld/beQj4LwwasvSg+NuiUSNin1qmqglCw=;
        b=JQmNxetuY1EkdPz0bhQUEnUJZSWuNFzizXvmXjcbKCbGjXYyhD+m8vnV+wmOURwsME
         ZyD1Bh4/B0EvTHuf1131I3jSQN1cp2DELTEQcoUq7nbk/LIXNm82mAXcNPlMgcXmjaed
         qh1fx9y+8BEq2rCXWw7mOFq51ms9EJsIq2MkcBxvXtiJr5L83JDmblFuQEoUEytc87oi
         4ORlqIPmuH2c6ns+b6gktaydwQflrXI3u5br/qLt7+lG6RnoNXp+fyVRc8UB2aE8dRyU
         7KCViI/q1udJh9yHJQMOYyMPswFpqsAmajDiVLvN+MtuRMw/5dK8dZZiNdt00QwnL5j0
         GJzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FQtZTwK4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q0QdjKroxSld/beQj4LwwasvSg+NuiUSNin1qmqglCw=;
        b=XFPWlj5hROdS8vL7Br0rrQnDvg41tnwdszz3IeovHH1QOcMHebYieSP1WvrSayLB8a
         m/Zd9UF5RGIe/5pU9HhKV2HhGOy7KMt8enoGIkaEjqX/ikrosJA+LVaYtieH0Qs4HNI9
         RUjwKNMa1b7IH4tjTzr62b7nM6nSSFec2zTKlPji6uCQ5DytmJrLJG/ZG4Pw7vojRxjC
         HFvoqrs3fDulzr+V6pOORyzU5QOz1i3kY0WkXi8eqlvftrbBZDNzpvfdeEdhWm9foJJx
         PlPfEUHlqrZqkZoY7ipoq4XWf+Y+dNvaYIP2bJvGS0WONJA6OwydR5S7POzXxNTb4KLx
         KOrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q0QdjKroxSld/beQj4LwwasvSg+NuiUSNin1qmqglCw=;
        b=j1l7ovJEDtGFbsZmZi/wRYlL/ANkVpZACuj2ONg3LWPyoZthZzzbqJIDEn4pIHs3Qm
         aL3CI4NeOuVHUx8TSSYGZZzwihJlAsN0PsZTu/MmvICaINtMS4Rq9N7/+qkxAoP7v0L9
         p4OVkMnz3FM3OdbP3og3hDncT2JYt+TkOplnlUgkHhOq4fhoHsCTPAjwdVnXjm3YoSJO
         pe4sLPKyeyWPy97Hj/xLbbVLR7agp1ohfYLDemEwfkE/Qkfs9IqRai5n2GzBp3AqWQDu
         NeNwndkKNoqVSnzjSQK4pLMPHqMaWYhpMq1ys4YTT+rSMljNEa9PEOrrXbeAh/ScDOWi
         omjg==
X-Gm-Message-State: AOAM532kG9fgJE6xdcFmfS+lxVF0bxAx76aYvD4R3V0/ZIKHqdefJn6z
	sKbx2NkuZT6lOZT+9yEgORg=
X-Google-Smtp-Source: ABdhPJxzGQW8OUEwCBR3ecJ5y5pt/haHZeo1BFW591bs9Xw0RajGBnc+71/3P63D0ldctPd64UelXA==
X-Received: by 2002:a17:90a:4414:: with SMTP id s20mr4015803pjg.81.1623913762192;
        Thu, 17 Jun 2021 00:09:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3383:: with SMTP id ke3ls3180057pjb.0.gmail; Thu, 17
 Jun 2021 00:09:21 -0700 (PDT)
X-Received: by 2002:a17:90b:78e:: with SMTP id l14mr4205925pjz.110.1623913761630;
        Thu, 17 Jun 2021 00:09:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623913761; cv=none;
        d=google.com; s=arc-20160816;
        b=zQrFE72wgDcRmSmbtHq6A63pr7LLBXiWrDegZrwhZxX2pLLhqnlIvOTyp3Z4niN+Lc
         F80OBDwfdAE+Z0B5NUJDwqYpSKidJpHdDSkaZ1dKkVmckLMG2bOW1NlGhd338iQqmLgI
         g8SzLpGD5hweCGBIjf3SY6l+tniTGGWPDHA1kofmwaZgFOq9GHP9IUL2CUyxJnu1kwuJ
         hSwf/FQ3Ob8LhozAXomQFs2BX/+R6Ft0SXq81a0znzSI5WCXkzlKyNr5oPFBfVUdru+n
         pThhOOs6cCtkfvipg7YLd7j2IUC4vfAs7NIOtgHiNb0uF2pjzonU9TH+WRCD4ejrzv5Y
         Zfvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Y899QIQlOQvFqET/XGorOZ+F3vK0QdxZBrZzg45qzIs=;
        b=OCv81ksJrIHf4DrLkXvLb+qIz+fqF7irq7kcFGUFCn9lgPvDMgjuqS8fBPZuDVWSoD
         ZtjOxwbH8M/Gr+HY0+njPanJGPKOsOB4jEJfWaNR79eDtjQpa2vCxxm+3eHXQ6CoWV/L
         CtMgjbQXDo+R6mGTDstl5id/FjKcQ4qJzEiJqg9N8hdpgtAspGwRxfWusKzXfbpUGydk
         PfJ9L83A7dcFm0Bw6Yp+noBPFOPv1Ysno55ExYofIIXUmFWFyhERxnV2alH0bVBeIjr8
         wM9eqpkerHOADkBWWwtyoXAFM/mJOIULLTp4XD96jWNYcfCcnXIvBG3NbsIBEKTiCke/
         3vcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FQtZTwK4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x231.google.com (mail-oi1-x231.google.com. [2607:f8b0:4864:20::231])
        by gmr-mx.google.com with ESMTPS id o21si358765pgu.0.2021.06.17.00.09.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 00:09:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) client-ip=2607:f8b0:4864:20::231;
Received: by mail-oi1-x231.google.com with SMTP id c13so5416551oib.13
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 00:09:21 -0700 (PDT)
X-Received: by 2002:a05:6808:bd5:: with SMTP id o21mr2275661oik.172.1623913760824;
 Thu, 17 Jun 2021 00:09:20 -0700 (PDT)
MIME-Version: 1.0
References: <20210617063956.94061-1-dja@axtens.net> <20210617063956.94061-5-dja@axtens.net>
In-Reply-To: <20210617063956.94061-5-dja@axtens.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Jun 2021 09:09:09 +0200
Message-ID: <CANpmjNOoeZqRnqpPGZqiro-ptaV=qKf5dnRYmVcZkRMPq7spig@mail.gmail.com>
Subject: Re: [PATCH v14 4/4] kasan: use MAX_PTRS_PER_* for early shadow tables
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	linuxppc-dev@lists.ozlabs.org, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	aneesh.kumar@linux.ibm.com, Balbir Singh <bsingharora@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FQtZTwK4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as
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
> powerpc has a variable number of PTRS_PER_*, set at runtime based
> on the MMU that the kernel is booted under.
>
> This means the PTRS_PER_* are no longer constants, and therefore
> breaks the build. Switch to using MAX_PTRS_PER_*, which are constant.
>
> Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> Suggested-by: Balbir Singh <bsingharora@gmail.com>
> Reviewed-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> Reviewed-by: Balbir Singh <bsingharora@gmail.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  include/linux/kasan.h | 6 +++---
>  mm/kasan/init.c       | 6 +++---
>  2 files changed, 6 insertions(+), 6 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 768d7d342757..5310e217bd74 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -41,9 +41,9 @@ struct kunit_kasan_expectation {
>  #endif
>
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOoeZqRnqpPGZqiro-ptaV%3DqKf5dnRYmVcZkRMPq7spig%40mail.gmail.com.
