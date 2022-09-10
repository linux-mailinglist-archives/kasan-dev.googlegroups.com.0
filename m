Return-Path: <kasan-dev+bncBDW2JDUY5AORB65U6SMAMGQEXSRUUCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CC8D5B4ACD
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Sep 2022 01:15:09 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id a6-20020a17090abe0600b00200303ba903sf5418172pjs.2
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Sep 2022 16:15:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662851707; cv=pass;
        d=google.com; s=arc-20160816;
        b=z2glhxC7NrianHM8Gex55Qa1tcyXq+DocKiS43z3M2xt+krXDKnApd3VxMA1tkxdLI
         eC6oudqugdZRbSwDELHLtrME2M1lhnuSuFwAUmRxqusspY+Psz5O7EZEBDKJ3KgvetuM
         z2tfpT4AUIAxYP9bH22KpK+iwRK5PSOU/DQ/YFZCuqC/SMet0BOjVYyNTF0qHJo0bf3A
         PKgj0ChRCo7iVyAdKoBy/bzcKnNpgMwfhG3xlntH8fZupQeZNc/0tqYgGNupwufV0f8V
         N0gXjUymmSooWm0aHL1oYrD7wdbN6lpLAfxhR3YD+Cs99BsdA577o3FESGFdmi89i+4E
         529g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=yfRdfGqWdjdWdBoPvTm7As0prjeRDTd3jlLKNdGXxNw=;
        b=uyucJGelytGtrTz/pII38maWHZBhKC/pOxI3eghb9QK7zuVVSEJ2d6ul6VtjFvZQhZ
         ZPTJqinjCvWiSe8l6u6lBprNdRSWjWIxnHTUVRlA1nGLxhDZsVGIKjsDzxbVDpfHU65q
         /D2hhIC0rQBSNmrSz1ZLqdPn+ytOmbPMw6aMcUxsQ2hTnbue9R8gl2LbIVECEsw4xV54
         yY9T/s/nJF9Z59EA0Ww7dJEp2kc3dhKUT5j9+DDXwH+tn9V7ndtXHf1S3SP4ZYO9FDAu
         xWMzfHbeVLTmUjoPkddnfrTsryDBj2pkSpy8zX6E5xW6d+M36mr7MziQ7WegESUDAnya
         Lc6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=iSX3eG5H;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=yfRdfGqWdjdWdBoPvTm7As0prjeRDTd3jlLKNdGXxNw=;
        b=YWRvwzDq5HCD3WKzHAqRjDPD4US3dkf4ia4Vce/7oOkcqwYfbgkBEf/bszMkRrjVbY
         rGHLn3GQAj/6OYB2OALH8IBGKFPDoh9ZSEkn0jLY7+xHxFpJ2K+pBdDcJ7lOm3qbyjDB
         RJ4kC9xRL5SnDOh6eSllelCrJTbnDokzcX4AL5Q5diwDDls9oJHxWLVLzvHizijwIhHZ
         sIkjzGwgCdQUIdcAGIK8gkrAMmS5auulNwPgq4V85brqGCzKrY/KuWR0C4ioYq7CRi7P
         ogUpZP8wBHgTtnUBuw3+9CqyKvcbVRvPRHRau+B6/CuZn+/8zS18okzjHilGFAIXKa8a
         cHFw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=yfRdfGqWdjdWdBoPvTm7As0prjeRDTd3jlLKNdGXxNw=;
        b=P5RPj/PwrfGLvNzPM8Myu0wrpbMjzFFOMpfCw+UPY993uV1efdO3NUoQaZb9hIvyic
         cUsRwfPE5BcPBW1Zz8nAf9eBLZN6H+AuEkN89bdg2p1H5e8d71jOlO7Hbz0CMuBgVN6W
         cjVx/bJKX1BI/TtLYLPWOiyBaZMSQo+EtleIRRVxNgdvBCBSX8VCWBa2uoeTBfZTmTAO
         NPGMa3RHp+kh1rlYlXpbzKRsCc7GcuhBcRNgJQW8dN8aKOWet0cqwiwu8pGQ4k8sGEYT
         DcSPThRH9joejVzo3SC3I6J0CVUdhhXO81AGSlDbrE5uqillS8fZCHTIgWDF7tyCL0Wx
         N9fQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=yfRdfGqWdjdWdBoPvTm7As0prjeRDTd3jlLKNdGXxNw=;
        b=HDWZJe+3HQgqy5KbvoS8rfvsVV5jU6SqXXQiihKmW/ul1d78G3bwbXrW64ubcN5OaF
         VNe9Nofj7SJpZ3YclOqVsr/oZbrURMXuu5lPBkj2SRsFidQLSu/1syz0BXPFk+1NQblt
         m+zOLjAbr3Cpm6XQeLKptpexzat/mwfh1UAJzjGjEpBd6V7KMmSwVE+KNZRLFXymAHBf
         Xm79FVAiixKNyL1GhNZjEUKisUz/NTbSZjtVctth9DZH4Cg/dc0WZBb/8saw48zvAQGZ
         d83+Az/YgviKSoLl9fGi1dVieGLj+qVeXaygIatybJitHheqGbFGA9W9PaogiahZJ9hC
         Cm0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0CJ5agr3QheQyYR0VEX6OJuayoWiG+BM+sQE0iRrX9Lzv4OfAG
	Np6d4UXl6sLj69U6smG4lrU=
X-Google-Smtp-Source: AA6agR4de6YvmBc6CFHRHh+bV3cocaCtSd8fwa73vdHfFhe5GNr9WWrnTsyI6Grguw5CRmQYZoqTUA==
X-Received: by 2002:a05:6a00:b8a:b0:537:f81:203a with SMTP id g10-20020a056a000b8a00b005370f81203amr20685224pfj.80.1662851707529;
        Sat, 10 Sep 2022 16:15:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7610:b0:16c:2ae8:5b94 with SMTP id
 k16-20020a170902761000b0016c2ae85b94ls5236364pll.0.-pod-prod-gmail; Sat, 10
 Sep 2022 16:15:06 -0700 (PDT)
X-Received: by 2002:a17:90b:1c0d:b0:202:61d0:33c with SMTP id oc13-20020a17090b1c0d00b0020261d0033cmr17055246pjb.90.1662851706888;
        Sat, 10 Sep 2022 16:15:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662851706; cv=none;
        d=google.com; s=arc-20160816;
        b=ZelkaBnZ4RLMWI9oBlgWoH1XTDAPWnAua2SvCl14wH9SQ2gHp/cSRWJiFWv23N5NNY
         MGDP1/488Q2yqczdZBfq3CeIDc8GCAVC6g6gHNba4dWnLZKhoCfl0TvUtePz99TRjyvG
         miwts5HvCXbicmswSN5cosi7GPJH+B3PjsGjVm/tO6ooRx1sJnrT2y3AV90/nayh2SX5
         bF8mLLICvj9ChWiJbsoptgFAS1uTX7iZL5wQgvEM1e26sOvN4mRQBv7oF4awwxPvPetR
         eD86at1i/pajoKXX+2oQSPDIo3QrTBHTWIUTbAPPzpAzVPY7tJ8mzPWNMjplwpckUAQf
         uBcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=w2iwfAfjmm20Z/nVGluOZ//otBXBhnUx+0kh6uIL9eU=;
        b=UHzwdghdaLP6a9Q5bVHmT/qd7UH2keq6STsxoQEQjqKNlE7Iwwh3cnfflT6m9rIR+C
         JprwEkli1cOiEwD9Zl3Wk9gSGYxe4jXySxxCY6lKzR1d4RdRKr8B+hGDLI/obmFIQdQo
         wc47Rzo7I7VCLy1umlwLqqtrYfcgoYVUgveOHNATUK18HJQsbFOl0QCO21N52917iz3K
         1cUm6IuXjNE+rIYGyzOiEYhUGmz5piLSg9GnM4MNDwdle0bZtnkFyJhtC4s4F3mt7A84
         GVVCNAZzjy4AoOdTkzOOC0EXX+vZmdhi4x9GIcNv4EbYnKz1mwQb4DLzC0Sw/QOHVPR7
         9t4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=iSX3eG5H;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x82c.google.com (mail-qt1-x82c.google.com. [2607:f8b0:4864:20::82c])
        by gmr-mx.google.com with ESMTPS id ne19-20020a17090b375300b001faab3fc6a0si132871pjb.3.2022.09.10.16.15.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 10 Sep 2022 16:15:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82c as permitted sender) client-ip=2607:f8b0:4864:20::82c;
Received: by mail-qt1-x82c.google.com with SMTP id c11so3848371qtw.8
        for <kasan-dev@googlegroups.com>; Sat, 10 Sep 2022 16:15:06 -0700 (PDT)
X-Received: by 2002:a05:622a:14d1:b0:344:b14a:b22a with SMTP id
 u17-20020a05622a14d100b00344b14ab22amr17595430qtx.203.1662851706097; Sat, 10
 Sep 2022 16:15:06 -0700 (PDT)
MIME-Version: 1.0
References: <20220907071023.3838692-1-feng.tang@intel.com> <20220907071023.3838692-4-feng.tang@intel.com>
In-Reply-To: <20220907071023.3838692-4-feng.tang@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 11 Sep 2022 01:14:55 +0200
Message-ID: <CA+fCnZeT_mYndXDYoi0LHCcDkOK4V1TR_omE6CKdbMf6iDwP+w@mail.gmail.com>
Subject: Re: [PATCH v5 3/4] mm: kasan: Add free_meta size info in struct kasan_cache
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Dave Hansen <dave.hansen@intel.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kernel test robot <oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=iSX3eG5H;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82c
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

On Wed, Sep 7, 2022 at 9:11 AM Feng Tang <feng.tang@intel.com> wrote:
>
> When kasan is enabled for slab/slub, it may save kasan' free_meta
> data in the former part of slab object data area in slab object
> free path, which works fine.
>
> There is ongoing effort to extend slub's debug function which will
> redzone the latter part of kmalloc object area, and when both of
> the debug are enabled, there is possible conflict, especially when
> the kmalloc object has small size, as caught by 0Day bot [1]
>
> For better information for slab/slub, add free_meta's data size
> into 'struct kasan_cache', so that its users can take right action
> to avoid data conflict.
>
> [1]. https://lore.kernel.org/lkml/YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020/
> Reported-by: kernel test robot <oliver.sang@intel.com>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> Acked-by: Dmitry Vyukov <dvyukov@google.com>
> ---
>  include/linux/kasan.h | 2 ++
>  mm/kasan/common.c     | 2 ++
>  2 files changed, 4 insertions(+)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index b092277bf48d..293bdaa0ba09 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -100,6 +100,8 @@ static inline bool kasan_has_integrated_init(void)
>  struct kasan_cache {
>         int alloc_meta_offset;
>         int free_meta_offset;
> +       /* size of free_meta data saved in object's data area */
> +       int free_meta_size_in_object;

I thinks calling this field free_meta_size is clear enough. Thanks!

>         bool is_kmalloc;
>  };
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 69f583855c8b..762ae7a7793e 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -201,6 +201,8 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>                         cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
>                         *size = ok_size;
>                 }
> +       } else {
> +               cache->kasan_info.free_meta_size_in_object = sizeof(struct kasan_free_meta);
>         }
>
>         /* Calculate size with optimal redzone. */
> --
> 2.34.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220907071023.3838692-4-feng.tang%40intel.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeT_mYndXDYoi0LHCcDkOK4V1TR_omE6CKdbMf6iDwP%2Bw%40mail.gmail.com.
