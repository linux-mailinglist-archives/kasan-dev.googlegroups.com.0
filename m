Return-Path: <kasan-dev+bncBDW2JDUY5AORBRGHXSDAMGQED4Z7XFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 175A63ADE1B
	for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 13:17:25 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id s80-20020a1ca9530000b02901cff732fde5sf5404871wme.6
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Jun 2021 04:17:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624187844; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q0s5wKH+fn6T5O8YowYl9fL85+a13hO/l9Tshb0OSHaVgPnHinZTjXaduqQxvhnGOk
         RqfGlGpt5gC3GK67a+nN1oRZeCoBr7rY5zoM0w5Ac7MavAUNDarLjM5iFz35IqTJkpQL
         n7CGGr+TTVi7WzYa/E6RR74wnGdR9y0QTjShnjQxliCdCfGAhExHlmT/bCW0Xup2Ov15
         TCPH8Jz5a0FEPUKL7MCIgPj/7uxLVTiJENDrr3snXuAQBFMNBhcI6raZGxB61yVNsgOI
         YZRMk0MbJeu+F2BEFNcXaVlvKs6j0lStY/sHhzh+hy8tCTeG+KzgjWFA9f8FHMqCB6iI
         1xkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=SQJDiuGw8/LqEtPa7RNsXeAS/3TrQ68ANMYhs6bUuro=;
        b=DfbYs3YpS3TvE1XfszF8EasIn6/r/9AMkgHR82/PdJ8lKSm27vQrJa6ct/DYUrItt5
         EYdoTOafjanLFAZLd9SEXp4mmGi29UFcKGbgReJAgKVcf0DnwBw1O8iCCe5BbcDgYIfA
         yhM1kV9hpTX+I78rjyE9L6jN5IEnKFTY9GV5hzOZtJ6ErB5vmI+4E1xDNhObXTjUg/w6
         NJGIldjnJVWStbnzaVc5/s2bPn0mWAbxDD1xdpFtvklrZ8mPxfDEoKj6wBgtv846y8q/
         Nbg9DLc8ZpMxI2HhrbySx93hugO3n6nDWKNbMZ2E26DYkTv7ktjtoW/KHa9qkQQbkMcX
         Gpfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=WXYG6Cdf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SQJDiuGw8/LqEtPa7RNsXeAS/3TrQ68ANMYhs6bUuro=;
        b=Nmn550VXF7IyBrzN90JBOWlTyhm7S/KLQqAIvyDDax+H8QLeqa7CR5IFoxa7rvFVGE
         yIPFepsw3Yi4Gq+ggFKipUX6n0Zf9tcZ2BOJVDPdLNu7eBWLY0xhQYZD99RILLVufiFA
         w1T/INTV6vcDzWNiXKYn0pSHqq1Eqc1zKmF4ENFAgiLDQIJvOqN96ozcLKTXOTFnlz8x
         p89neT4y7HvQJWfM/02zNziQkUZxaeWjZN2/Ibl1jC3ZlPyTKe6IXS+afBQlnGEV9JpF
         FwBBctYne4w76YNAfYRTIOqfS/p92BwDsrZGTzSF5i+cZ/ux8y5nQgVAEkMAjQ68aoZS
         n90A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SQJDiuGw8/LqEtPa7RNsXeAS/3TrQ68ANMYhs6bUuro=;
        b=len5OuXu/aGVR50NqLpD5O+qc5tlvBgw22D+80lwoxiZgpNNQaW3aMjGhD2lz2eI2h
         eKAYieNgPWExFS2qhQS8W38Qyg1Sccvz65qF/xSb28iV107lkSX4/ME1u+jJq1rijhGN
         GZljjIXkwXllXzggQGh8ihrrQeAjHinL5o9mHFHdScV+cZSxXFFGcdP/8sZBJFCLvbf/
         lCBhVSaeWEc3oiazKVwKsTt2wqbh2YnhBMxRqUJt6FBwqWcPR0nu3X0FudW0R3JbVM5+
         Dll5kQYQjeS4oMR1HjQT+JHl2pPAVhDOV3+43GB+TLhXw4UEYky6WvyyITuJ2TDb1OmO
         OelQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SQJDiuGw8/LqEtPa7RNsXeAS/3TrQ68ANMYhs6bUuro=;
        b=NH0Tv9/dJyZjhJq+t5S2u8zlKiIRwefwYC2O67oLf/T91PrHTSURGIyFJl0henlHbc
         XqayL+qnaGeYea57n2ULnGR587ESqooPiff58NgUardbxcREQBzOq5dlwg1ndA0WJ2Qa
         Yy2EdhzcW1GuH9Lkx0CRGTfGhN6ho9QKrVbRh28cWZcP4WXHUEF3NGuSFxAK7KAHUGqY
         tqJaCO94Ye7vOvTwJxU9fHz4Dz/oiW8PYHmBJkyyd3t5dw6SNAW2veU2pgD0oEp0vlXb
         2fiIirE/WOemztCNzvhfJ8IyMgiEkXPd9rwsRsLc7YVlG0+y6deGEyJRIclyquMM8pOo
         t8vQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533FA1tkxkhsE4srv07qzftdch4OBOK4VlcO2lsHsvlyMfgkno+g
	4VKB2wGxJ+PSZxF9BTNreXM=
X-Google-Smtp-Source: ABdhPJxLphzj1SAckcaOyi9qp1cqXHL7J3ioYXOxv37Aw5Z4sNkQlMe+3Geaf8Zd1qxeFKS9cZ2vCA==
X-Received: by 2002:a5d:65cf:: with SMTP id e15mr23144657wrw.310.1624187844895;
        Sun, 20 Jun 2021 04:17:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5106:: with SMTP id o6ls427976wms.2.canary-gmail;
 Sun, 20 Jun 2021 04:17:24 -0700 (PDT)
X-Received: by 2002:a1c:59c3:: with SMTP id n186mr11977630wmb.48.1624187844100;
        Sun, 20 Jun 2021 04:17:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624187844; cv=none;
        d=google.com; s=arc-20160816;
        b=QdC7NPk2oX3Z+Q9wqKrgRUI8adsh/k/W4Nz1DfJJAf0BdWHpi4YUmHCtEncLKAS+pj
         dRL+WbV7TcGeUHPONoGbt+9ekzyGMCk68gx6m2XuC7kdN8SKgrAYuJmI0VbjQrIgzFLK
         07ASnvytey0yNtgihlb6xn+hjxWenJU+8P3ROHEvI2eg2XQu5BZsnPsGaHsyoF+9vO1k
         Vl4O4Ux3liiX2k9x3H39meKhudPLs2+jFFQHYuiwMmNFdpyYaZUqG0oGbSWamvnhJt/v
         RdIQl97jn6c2pbo77zgFPFCJFISwijx/HfG2e32vb8TPYMKnae1MPCpoiX+IwzBm5KuC
         Ag8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ox6b74Fvc6eYbkVfNLZ3KvjE6zQLqybhjoI+fLMMAAM=;
        b=UfymQOgkOhIvpYNncKY5dTNGiEJOuUF4H7F/RXayWKkmhvQKL5jGyXFsW1Xues7a8f
         we+y3VGzoXk+j4+QMyda3WukE1CAm4iCSZ7gQU9nRE6zCwVVB+1qHAHxKcn532t5UQAw
         fdFpFS/kdB0i+QR0wnUrHd5PAkDpATszqTOqIsmdDTgYEqE3Twmki4jEzhsPAZV/Zov4
         L1z41IvqPizoKuzagIKGhZ/EIZz4tNahy3e6oTGzMFhWGd9UQo8p80p3406SmUxjLjOA
         cZ6q5MwWGL2LgYkqtPl7FxqVWIkiP4zUpmSZyX6AEWOSn7AOTuVEZi/cIxSvvLCLMGDV
         vKaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=WXYG6Cdf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x534.google.com (mail-ed1-x534.google.com. [2a00:1450:4864:20::534])
        by gmr-mx.google.com with ESMTPS id k18si863004wmj.0.2021.06.20.04.17.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 20 Jun 2021 04:17:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::534 as permitted sender) client-ip=2a00:1450:4864:20::534;
Received: by mail-ed1-x534.google.com with SMTP id df12so12445415edb.2
        for <kasan-dev@googlegroups.com>; Sun, 20 Jun 2021 04:17:24 -0700 (PDT)
X-Received: by 2002:a50:fd83:: with SMTP id o3mr12106286edt.95.1624187843896;
 Sun, 20 Jun 2021 04:17:23 -0700 (PDT)
MIME-Version: 1.0
References: <20210617093032.103097-1-dja@axtens.net> <20210617093032.103097-4-dja@axtens.net>
In-Reply-To: <20210617093032.103097-4-dja@axtens.net>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 20 Jun 2021 14:17:04 +0300
Message-ID: <CA+fCnZeJerhmLg_5F_FdVptJC+QqoVa5+pAhqU+nSH1itmhAcQ@mail.gmail.com>
Subject: Re: [PATCH v15 3/4] mm: define default MAX_PTRS_PER_* in include/pgtable.h
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linuxppc-dev@lists.ozlabs.org, christophe.leroy@csgroup.eu, 
	aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=WXYG6Cdf;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::534
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

On Thu, Jun 17, 2021 at 12:30 PM Daniel Axtens <dja@axtens.net> wrote:
>
> Commit c65e774fb3f6 ("x86/mm: Make PGDIR_SHIFT and PTRS_PER_P4D variable")
> made PTRS_PER_P4D variable on x86 and introduced MAX_PTRS_PER_P4D as a
> constant for cases which need a compile-time constant (e.g. fixed-size
> arrays).
>
> powerpc likewise has boot-time selectable MMU features which can cause
> other mm "constants" to vary. For KASAN, we have some static
> PTE/PMD/PUD/P4D arrays so we need compile-time maximums for all these
> constants. Extend the MAX_PTRS_PER_ idiom, and place default definitions
> in include/pgtable.h. These define MAX_PTRS_PER_x to be PTRS_PER_x unless
> an architecture has defined MAX_PTRS_PER_x in its arch headers.
>
> Clean up pgtable-nop4d.h and s390's MAX_PTRS_PER_P4D definitions while
> we're at it: both can just pick up the default now.
>
> Reviewed-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
>
> ---
>
> s390 was compile tested only.
> ---
>  arch/s390/include/asm/pgtable.h     |  2 --
>  include/asm-generic/pgtable-nop4d.h |  1 -
>  include/linux/pgtable.h             | 22 ++++++++++++++++++++++
>  3 files changed, 22 insertions(+), 3 deletions(-)
>
> diff --git a/arch/s390/include/asm/pgtable.h b/arch/s390/include/asm/pgtable.h
> index 7c66ae5d7e32..cf05954ce013 100644
> --- a/arch/s390/include/asm/pgtable.h
> +++ b/arch/s390/include/asm/pgtable.h
> @@ -342,8 +342,6 @@ static inline int is_module_addr(void *addr)
>  #define PTRS_PER_P4D   _CRST_ENTRIES
>  #define PTRS_PER_PGD   _CRST_ENTRIES
>
> -#define MAX_PTRS_PER_P4D       PTRS_PER_P4D
> -
>  /*
>   * Segment table and region3 table entry encoding
>   * (R = read-only, I = invalid, y = young bit):
> diff --git a/include/asm-generic/pgtable-nop4d.h b/include/asm-generic/pgtable-nop4d.h
> index ce2cbb3c380f..2f6b1befb129 100644
> --- a/include/asm-generic/pgtable-nop4d.h
> +++ b/include/asm-generic/pgtable-nop4d.h
> @@ -9,7 +9,6 @@
>  typedef struct { pgd_t pgd; } p4d_t;
>
>  #define P4D_SHIFT              PGDIR_SHIFT
> -#define MAX_PTRS_PER_P4D       1
>  #define PTRS_PER_P4D           1
>  #define P4D_SIZE               (1UL << P4D_SHIFT)
>  #define P4D_MASK               (~(P4D_SIZE-1))
> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> index 9e6f71265f72..69700e3e615f 100644
> --- a/include/linux/pgtable.h
> +++ b/include/linux/pgtable.h
> @@ -1625,4 +1625,26 @@ typedef unsigned int pgtbl_mod_mask;
>  #define pte_leaf_size(x) PAGE_SIZE
>  #endif
>
> +/*
> + * Some architectures have MMUs that are configurable or selectable at boot
> + * time. These lead to variable PTRS_PER_x. For statically allocated arrays it
> + * helps to have a static maximum value.
> + */
> +
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
> +
> +#ifndef MAX_PTRS_PER_P4D
> +#define MAX_PTRS_PER_P4D PTRS_PER_P4D
> +#endif
> +
>  #endif /* _LINUX_PGTABLE_H */
> --
> 2.30.2
>

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeJerhmLg_5F_FdVptJC%2BQqoVa5%2BpAhqU%2BnSH1itmhAcQ%40mail.gmail.com.
