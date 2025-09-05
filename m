Return-Path: <kasan-dev+bncBDEZDPVRZMARBQWX5XCQMGQENW7HLCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 56522B466E4
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Sep 2025 01:01:24 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4b5d58d226csf59340171cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 16:01:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757113283; cv=pass;
        d=google.com; s=arc-20240605;
        b=SJdLN1lUIl75hK6XShaTno3q7QdzpFfzeAqvfPh+8w4qPuSWg4saRmwN3EFjFI8Zj5
         jc4iarfkNW5Ui3poc4kcTdQdTGOW357eV85P/lV2oCYWX3E7fVeBTzlhYxtTEnlxFg48
         vOUaO1i5o30yZI8GxkS1+CBVus617q7uLJG3tvv5K+crhs3b97hGfHmRuki/yCPMw9OT
         ZqE6iAy1hIke6D4w+6hsBNkcv5Kk9xgSuWc9v6PF0VXRY98v+za1Gg1BTb4zjn/SEits
         3tP27exFTv7sd1Hk7sWHWuHlDbCQ4k4da78D43Z3OXAf/ioelzDkQ6B7QFmrLgEYJXBz
         6sCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=TVyz/ZiAAzSoNb1wNfce3wSBQvs99lw9iCsOJegzJpo=;
        fh=oROYc9cs/uOs3A20keHZ38nsiuAPPzBb84rRwOCv11k=;
        b=MwwqhhPtU/isFDx7nKhaXSLrW6eEhA38Ne/toccMNvpAVOWMnXDLJElKgZideifTNu
         aysLKgNkqoU7e6yFDaeUltT+8Kmk9yIo5VhExT82pKDKVS1pBAiVpxDjvUZRmmFI4vqc
         wbZGbJfmyX1E9dEU5/efB6eJwmdflnZoxJSo3WnyLq+RT39bi6DN8qpouwCLOKSwSeUM
         uA1JB5/d4KFAYhmG/+7LWYp13FBiY4ngc0ElxACCVTQzpx1LRaKNHN3y3C7NZZvfaEZ+
         hX2YA6UebhJmsEKAbbkS3rHNU6s2+gm9cgrCJC/2YaJRduyowRXSJeKGsa0CAY7nVn9X
         cvyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FKhh4N0Y;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757113283; x=1757718083; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=TVyz/ZiAAzSoNb1wNfce3wSBQvs99lw9iCsOJegzJpo=;
        b=d+GgFVvcEbirsnRQuD7bjO1g/loePQveOxw0BNOaL1w3SVMwjUFadRdz1ql4mbKHWN
         jMtNgVim1I5Pj07nJVanGWc5YI9pHRf3iV5zpgYoCkuebn2Bm5UKGWgTEUi30Ujg1m37
         yp/91ZU+HBn6S8iDc+Ruk77PWnXSWXubwaz9ilY84k522woDPtj6UTMfLKSi4awj5R94
         AoTdMsO/gaczNF/7RMOwO7E942MprTrvBpgokHSas696sMJwNfD3NY6eVRFvKn02CivF
         y+I7TXiXIHNoC97hoiTVSiSHr5r3tiuHOat13qrd8gObtVI0ZIE9DxVAswDLY+YH0QDd
         QvQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757113283; x=1757718083;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TVyz/ZiAAzSoNb1wNfce3wSBQvs99lw9iCsOJegzJpo=;
        b=AJLQkJ+RVQIzqvCPZ3OT3Wr/Hn4xbGd16c//MrA3P/S7Cy9GFRhb6NkUEJyDM8+E7e
         37IGv2/8qbIMnICe1a9II3t1MchqZ/JWkHWF5nvPuB+isBJG7jz4sdtPBeZKjwhMqDEZ
         wDGmg4GPTL09xbiG4lxdquexneQjPDBku9rcYH4VIM5WRsZVvIOHBkFewjeRMPN+Scr1
         tkTZ/xu8j8EI/opFO9KOqDHD1wmidt4eWKjXd+MYpLynUGP+iVVAfwM9Pnta4GsVqrlU
         KIaUtb+q/H9gXuNKFrt+VoUU2QjkIQI/diX2gBEPsQRwRD79lhxQ7Mz0d5NkhPEahnVb
         4x5A==
X-Forwarded-Encrypted: i=2; AJvYcCVvHDUNxA0o47E4T+JUva+B8Xl8YQ2CIetCkRDyJ3Ar0ogEkC2aImzhWD7JpysKUJeIdiynng==@lfdr.de
X-Gm-Message-State: AOJu0YxUtm73yNo+107dlPOr72J9nrzB5AO1xPwb3bwozuPLdNLaeaYI
	kEGBAlYL1hg+MOqCcwkS24BU3cTE/kcFxaOvZKIwpdPTqIitvyFOL2bn
X-Google-Smtp-Source: AGHT+IHhEYXJht3c84OVpanQ3+PB/k07d8wq3/4zlViMUF6muMdj/qqaki8SUWFV3giqtV0Oimbsqw==
X-Received: by 2002:ac8:5992:0:b0:4b5:f788:423c with SMTP id d75a77b69052e-4b5f84650e7mr3268251cf.65.1757113282699;
        Fri, 05 Sep 2025 16:01:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZepr/JQvUQN6L/pUxRcU5XjcvZNo4ipTVgHFt3ctykkNA==
Received: by 2002:a05:622a:7:b0:4b0:9935:4640 with SMTP id d75a77b69052e-4b5ea8d8ef3ls19970241cf.0.-pod-prod-09-us;
 Fri, 05 Sep 2025 16:01:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWD2f7ULcb7tJ+Zb9Mw5ACL12lnUZONsnbNinnGwD5JmnMc9bg/bCAK4SeZo95xlvZ3hUtSS/30FzU=@googlegroups.com
X-Received: by 2002:ac8:5a45:0:b0:4b0:7950:8cdb with SMTP id d75a77b69052e-4b5f839007emr4291381cf.31.1757113281784;
        Fri, 05 Sep 2025 16:01:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757113281; cv=none;
        d=google.com; s=arc-20240605;
        b=hwk6zyru/ReizYeJMFJtRA47xvHu0Z8zF14tRprmAm9rTWI2rxKAt8gJRbj4qNw89Y
         QaEWUAiwMEAthN6DZQHq57qwGrTFKHC8ZtxiGJNZpMb3DN1tsnB9fYEKtuaug4SwoIav
         K8gaaWrp8mztiiLH2bDFevI9SCn52mLVsodSiJ8LXaSmY8jxOj1QTNIj3Zp4eVJS1HV9
         1KYO3ag987lWxGoy8j1crdGN52alUtbeTkoO2koz6GFaPBT8XU8sVmOgZpThQFpwwcfn
         33O/lwIYFKq32ZrG/3assAWV7hUmumBcTQeSF8reo52tlV/bN2+BI3WmIvRsTbEp9QhO
         sYBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XZoercRzV+9gES767UN4t02R1PKB+nn+QIHkF8YGS5E=;
        fh=vX6gO3pliJpm/AGrWIy9cYz9F3J0yH3JYHwS9n457z8=;
        b=ljRfFC8yww4RDaGXBMUOcJ1QxCiwlhWJv2Xf/QD4dvrY5+81DjLPU1BEtiCfLUuLIg
         OzpZY0A4P2zLulrWP16hfZVZ70N7k0dgIe5XYiivDxZb4Rz9m3mTMWkp/72RkhN+Zsn+
         hKhki03R/a6GZsXdBiBsLS6j/++f37stRhHLfQnckMOIkIIh/2W+pYUWyryHl/nSlQa9
         ozkKM/FlujxkDK2gTTSbGeFbmLVodTGfZ6ktcSzJWlUwwGbSky1LlIU/ZSlCy3tpamMd
         4mg6moDkRbetp9Sv7hRd09gLNwAw4CEbMw4/sucfvwdWsh4UjFkNvgz2m2DbCTdcF3eH
         KlEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FKhh4N0Y;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b48f78b3e5si3431191cf.5.2025.09.05.16.01.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 Sep 2025 16:01:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id CBCC2601AA;
	Fri,  5 Sep 2025 23:01:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A2CEDC4CEF1;
	Fri,  5 Sep 2025 23:01:18 +0000 (UTC)
Date: Fri, 5 Sep 2025 16:00:06 -0700
From: "'Eric Biggers' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
	io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
	kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org, linux-mm@kvack.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v2 19/37] mm/gup: remove record_subpages()
Message-ID: <20250905230006.GA1776@sol>
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-20-david@redhat.com>
 <5090355d-546a-4d06-99e1-064354d156b5@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5090355d-546a-4d06-99e1-064354d156b5@redhat.com>
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=FKhh4N0Y;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Eric Biggers <ebiggers@kernel.org>
Reply-To: Eric Biggers <ebiggers@kernel.org>
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

On Fri, Sep 05, 2025 at 08:41:23AM +0200, David Hildenbrand wrote:
> On 01.09.25 17:03, David Hildenbrand wrote:
> > We can just cleanup the code by calculating the #refs earlier,
> > so we can just inline what remains of record_subpages().
> > 
> > Calculate the number of references/pages ahead of times, and record them
> > only once all our tests passed.
> > 
> > Signed-off-by: David Hildenbrand <david@redhat.com>
> > ---
> >   mm/gup.c | 25 ++++++++-----------------
> >   1 file changed, 8 insertions(+), 17 deletions(-)
> > 
> > diff --git a/mm/gup.c b/mm/gup.c
> > index c10cd969c1a3b..f0f4d1a68e094 100644
> > --- a/mm/gup.c
> > +++ b/mm/gup.c
> > @@ -484,19 +484,6 @@ static inline void mm_set_has_pinned_flag(struct mm_struct *mm)
> >   #ifdef CONFIG_MMU
> >   #ifdef CONFIG_HAVE_GUP_FAST
> > -static int record_subpages(struct page *page, unsigned long sz,
> > -			   unsigned long addr, unsigned long end,
> > -			   struct page **pages)
> > -{
> > -	int nr;
> > -
> > -	page += (addr & (sz - 1)) >> PAGE_SHIFT;
> > -	for (nr = 0; addr != end; nr++, addr += PAGE_SIZE)
> > -		pages[nr] = page++;
> > -
> > -	return nr;
> > -}
> > -
> >   /**
> >    * try_grab_folio_fast() - Attempt to get or pin a folio in fast path.
> >    * @page:  pointer to page to be grabbed
> > @@ -2967,8 +2954,8 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
> >   	if (pmd_special(orig))
> >   		return 0;
> > -	page = pmd_page(orig);
> > -	refs = record_subpages(page, PMD_SIZE, addr, end, pages + *nr);
> > +	refs = (end - addr) >> PAGE_SHIFT;
> > +	page = pmd_page(orig) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
> >   	folio = try_grab_folio_fast(page, refs, flags);
> >   	if (!folio)
> > @@ -2989,6 +2976,8 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
> >   	}
> >   	*nr += refs;
> > +	for (; refs; refs--)
> > +		*(pages++) = page++;
> >   	folio_set_referenced(folio);
> >   	return 1;
> >   }
> > @@ -3007,8 +2996,8 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
> >   	if (pud_special(orig))
> >   		return 0;
> > -	page = pud_page(orig);
> > -	refs = record_subpages(page, PUD_SIZE, addr, end, pages + *nr);
> > +	refs = (end - addr) >> PAGE_SHIFT;
> > +	page = pud_page(orig) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
> >   	folio = try_grab_folio_fast(page, refs, flags);
> >   	if (!folio)
> > @@ -3030,6 +3019,8 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
> >   	}
> >   	*nr += refs;
> > +	for (; refs; refs--)
> > +		*(pages++) = page++;
> >   	folio_set_referenced(folio);
> >   	return 1;
> >   }
> 
> Okay, this code is nasty. We should rework this code to just return the nr and receive a the proper
> pages pointer, getting rid of the "*nr" parameter.
> 
> For the time being, the following should do the trick:
> 
> commit bfd07c995814354f6b66c5b6a72e96a7aa9fb73b (HEAD -> nth_page)
> Author: David Hildenbrand <david@redhat.com>
> Date:   Fri Sep 5 08:38:43 2025 +0200
> 
>     fixup: mm/gup: remove record_subpages()
>     pages is not adjusted by the caller, but idnexed by existing *nr.
>     Signed-off-by: David Hildenbrand <david@redhat.com>
> 
> diff --git a/mm/gup.c b/mm/gup.c
> index 010fe56f6e132..22420f2069ee1 100644
> --- a/mm/gup.c
> +++ b/mm/gup.c
> @@ -2981,6 +2981,7 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
>                 return 0;
>         }
> +       pages += *nr;
>         *nr += refs;
>         for (; refs; refs--)
>                 *(pages++) = page++;
> @@ -3024,6 +3025,7 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
>                 return 0;
>         }
> +       pages += *nr;
>         *nr += refs;
>         for (; refs; refs--)
>                 *(pages++) = page++;

Can this get folded in soon?  This bug is causing crashes in AF_ALG too.

Thanks,

- Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250905230006.GA1776%40sol.
