Return-Path: <kasan-dev+bncBDW7XHEOIAIPPWU7YUDBUBEPEKP4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id A7CC3B30D58
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 06:09:36 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4b10ab0062asf40546961cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 21:09:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755835767; cv=pass;
        d=google.com; s=arc-20240605;
        b=TW7RmTLKYH2jbgkidDgzZH2gqp/glb/k6sgvOMs2dYm10rEyarC1klbSgx5KmXbbP/
         uhLdB/A8vDl8FWXaV5CEMfk7GMt++5Fr0wbJBqYxTbmHNFlMbOggkVgLh9Zgns4N/DLW
         JwcxoDNOgbY2+jtCvvBZhML2cTFry0JsfUIwuRFGjiCaDmL4hSVN/W6ar08lgEy34CC9
         rpYnymXjzHY4pQMnZnt9vAaTVdhOH23/S5CGT7m4yQUUo815eZEtyW2HSgLH65kWQbuv
         jOrQ9ah6i7xTnCdBv2e5hv8Rx2wtO/Ol7NnWX7KY1AhDh7gooiYiHsYbIHsh9uqIh9Ei
         ls+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=B7oZYFRXEnKsw1IpgPylZichP8xBnmZ0lga2kl53nC8=;
        fh=clwT8+KjQxjYJGzmHboPS1ldpxUgDCbZ5MYVXJRSh+Q=;
        b=EebsKea0HEPrYEWI8L1Ll0+ICNA9806kQC++PvH6St6QOjR3xpy80KGjrZxbJqn3R1
         Z0ZHr4rjER4z5diVY8uZzVli/8slexTSjwPvuhVXjjMYNyJ5f8puOItF998jSTncw5Ox
         uw+t2OB89SGuhs32rsan703+MYhbmpT8ZP0LCS2oycc8fQ6XKvEVMoZVQuXHRNv1tvAI
         w0L35PCF3tZ5LcdUVNrK5OLmfiNuRaJY68ac6BlBPYYFy8/Vp3mto2Pt10bEn4aYnAqx
         dr1x/wabE75fod5yDLVyx2i3Pv7XSF5Ae4TzSknF9rv0Z8tORyRU8RwqzXRTuZRuy3Jg
         X3Zw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ekVL8Jce;
       spf=pass (google.com: domain of mpenttil@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=mpenttil@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755835767; x=1756440567; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=B7oZYFRXEnKsw1IpgPylZichP8xBnmZ0lga2kl53nC8=;
        b=hJMb/Ovoj1QA+9cjkSaGpTz5pmaWdbfqStlJVyXwhHip3b3ECgaSa9flUevsiD+JLa
         2TmhwKznq+8kAbLpazhiwzgSKjscrwuakEI5yAr0Gp5rn2o2Cv5JWXm4MUoVclYb30lI
         WEwoyJryluKwgY5AxLxm/MWsTbr+uZsuhL1iogxFPI7cHzh4Kan9M5ayEl1/Uj+hfvDo
         oKCH5xF+v73Y8lgTukJFOo+PQtBp+pTmhC0dpCG/VClqfmiKPbSnkZowYg4ts9X75QxL
         XbO6Q6emxp3mco5Cqoosn5lhg/WnZPE/ha2cejUYSVgFCBvTGr5Fhljy62DIROeFxpFT
         iAVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755835767; x=1756440567;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=B7oZYFRXEnKsw1IpgPylZichP8xBnmZ0lga2kl53nC8=;
        b=DNvI0gaX2ENXGeX1AOMs6iN9xczjCvxNM5lVAML8Ir/obmWu0sq0IQiCX1XHAj9HJR
         EbNcahUpDs4rouCel/ZpabhnFB+JxAJtWJBC8z8bnoh0yar+uLw0raD0ELLhoViEiG/e
         PpCoc81D58HiMSFu6tneRSqMoGUwr/tscgUwpaZFwbnUagsRlC4jJP/1kNvBtBlui+kQ
         2Pe1Ok0kR2CUp30F1oDXWR+JfZnKNLUk3U+TwZRBPOZhsM5ujGG3gGvs7heszL/ejW7E
         VLJ7TpGmm9/ibNyQ7i0p6Ege9OrCUOPGH6O80hTL1TFwyu4cW37dJpmQAHCV2DcGDeDd
         c2pQ==
X-Forwarded-Encrypted: i=2; AJvYcCWNYBw5mR9fy/1EZuzzlk8BasE+xZpvbDbPbeJ6Sb//Jr1Ga0Gy1IAGQho2ETEapXAWnoqqfQ==@lfdr.de
X-Gm-Message-State: AOJu0YxRhs+kmDKZhFseIsPKYb4tn1k9tH2h35quqp9L7/AfFETf7OD8
	9Z9YQLkRhS01eviq0tZ+L2A9T15ObPQmF330iYboX5PQkMxCl+I5o2Tx
X-Google-Smtp-Source: AGHT+IGBOjiNpuhUGgY+YtDLBxjG3fVV6r1GycRbjGtlxH+3qRaqGo3y3/4HHY+WoKiHKgXtzhbJbw==
X-Received: by 2002:a05:622a:82:b0:4b0:7b3a:5301 with SMTP id d75a77b69052e-4b2aaacf118mr17791631cf.46.1755835767258;
        Thu, 21 Aug 2025 21:09:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeAbTyt16WzSEES4H31WDdMPwKptTaypfSAQ1acuME1hg==
Received: by 2002:ac8:5913:0:b0:4b0:774e:d50c with SMTP id d75a77b69052e-4b29daf4952ls24746141cf.2.-pod-prod-09-us;
 Thu, 21 Aug 2025 21:09:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVYbpVeUR3JDrVFaqYWNw9WBD7qHc2FiZa2m3tdFEzC7S94pPBvjunkufvlFcaJrYDG/h2bj61nkcI=@googlegroups.com
X-Received: by 2002:a05:620a:3194:b0:7e9:f820:2b40 with SMTP id af79cd13be357-7ea1107fe48mr188292385a.76.1755835766219;
        Thu, 21 Aug 2025 21:09:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755835766; cv=none;
        d=google.com; s=arc-20240605;
        b=ScLmEaCh6ONCQwBRW/bVTmJVKBET2GODnFQpQ2+b7sbMaivs6F2A4a7N3wZ8vqlu3p
         GKnXw5y5Z3YlmPaKu56yiF6c15Dn6HWJFToZU0JdOIQuT5iLwqFBpKYNI9x6NyAnLGWX
         Smp/ugDjEWAFWHRy/Lo+U2676f4d/PjqkBklHNh1i4gJ7EdL2u/PoTVkQARJs4lh4iGa
         nCr3rw9T3LasoetGrwoPFyDUWWCRVBKYOulUChv9M2Nv3C8a1AejhX22t3cbWfquqv28
         QAlfeCqRyx2vkRF5dYk7ynH/No35100XfDeZY5RZl2KzKFtLyQO1sEJqzYHGUhAkaOXX
         2iHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=wD6Kie9NmTYlBWSYITqg8VmPWCkzgpHh3Jn6J+e3AEM=;
        fh=ZUcBUnTTEoytSX4wuM1cJHJa3wfYxwJs6Q8Micb07BI=;
        b=FcTdUw2sx+JNuc3uqMs3qRiFdeQzha+X1qSUJ9wYCYsEWqfLn1IzlvZ67DhUNMiqNY
         jgmQFCnBAOJcsTDwsMMvKsYRN3qLKqsx30zYdH8j00oGxMWuDlqeQB9RudVTzgOd/itn
         COhqLtbTM5MiiEE0eqoHwcJwUuPi7eri3iUJkHwQ/0klEjh852CiABVTtB1fL6GrhW0n
         +jMXX1RVdxE6yguANyJ19eBKDxgqdyWiaC9t06YiNLXshx5ie5Fp9mrx+3xnO+Bhh6+Q
         cyFYhJuwLgdqjpBMRbYIstJ9D6oBmzbY1qvop4a4E8QMgB51tfArAD2MV4shmG9Nrp7o
         N7vw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ekVL8Jce;
       spf=pass (google.com: domain of mpenttil@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=mpenttil@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e87e1b2e4csi66233485a.4.2025.08.21.21.09.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 21:09:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of mpenttil@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-lj1-f200.google.com (mail-lj1-f200.google.com
 [209.85.208.200]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-561-40sSdPKKNWiQP1LqK-aG_g-1; Fri, 22 Aug 2025 00:09:24 -0400
X-MC-Unique: 40sSdPKKNWiQP1LqK-aG_g-1
X-Mimecast-MFC-AGG-ID: 40sSdPKKNWiQP1LqK-aG_g_1755835762
Received: by mail-lj1-f200.google.com with SMTP id 38308e7fff4ca-333f8ddf072so6799851fa.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 21:09:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXQhGlnE2ATwRjxzltL2GRRBH0H1jIZ4rec2gMjF4pSziLZkGHxbCrGZPs3DuLoNCDDLHm8/hazqz0=@googlegroups.com
X-Gm-Gg: ASbGncvmEWCqlicYynwV88XYrDWTlcNJReUur1PxNWa/+iQP43PkItLQ2dpzTAfmpLf
	wJa3jU1Z2Z+2fJwQvJx/+z8WlSd9sxqrQC/ikpjZ5CT0DXYTa9VyaYPADGhNauPK7hNc68cKL73
	9Imay6IVqBFqYzcrUuJIdKJZ7AlkWl0L0FZi25A6yXxLUsP6dn8vhejeOLDMSXC215bpNjqEOIq
	WTdP6QS+p+qTw/ZjDNYKpI8fXlxwf97Ko/+pII+/raSh8ZPNlr11PJKJMJft+ECDkwBJ0hJgAt1
	OmVoImglRs0sXTFgMf/mDnU4fw3tL2eLuMGsdLy4qFSlYvnlBB01mGClz8AJ3GZhfw==
X-Received: by 2002:a2e:be0c:0:b0:333:b6b0:e665 with SMTP id 38308e7fff4ca-33650fa8605mr4319611fa.30.1755835762129;
        Thu, 21 Aug 2025 21:09:22 -0700 (PDT)
X-Received: by 2002:a2e:be0c:0:b0:333:b6b0:e665 with SMTP id 38308e7fff4ca-33650fa8605mr4319091fa.30.1755835761548;
        Thu, 21 Aug 2025 21:09:21 -0700 (PDT)
Received: from [192.168.1.86] (85-23-48-6.bb.dnainternet.fi. [85.23.48.6])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-3340a41e3cfsm35236551fa.6.2025.08.21.21.09.18
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 21:09:19 -0700 (PDT)
Message-ID: <9156d191-9ec4-4422-bae9-2e8ce66f9d5e@redhat.com>
Date: Fri, 22 Aug 2025 07:09:17 +0300
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 10/35] mm/hugetlb: cleanup
 hugetlb_folio_init_tail_vmemmap()
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
 Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
 Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
 Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>,
 Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev,
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org,
 Zi Yan <ziy@nvidia.com>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-11-david@redhat.com>
From: =?UTF-8?B?J01pa2EgUGVudHRpbMOkJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
In-Reply-To: <20250821200701.1329277-11-david@redhat.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: W8kWX5L_M9FJnN4k6lLatc4JBrlc2XGd4FIRj9I5ZTE_1755835762
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mpenttil@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ekVL8Jce;
       spf=pass (google.com: domain of mpenttil@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=mpenttil@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: =?UTF-8?Q?Mika_Penttil=C3=A4?= <mpenttil@redhat.com>
Reply-To: =?UTF-8?Q?Mika_Penttil=C3=A4?= <mpenttil@redhat.com>
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


On 8/21/25 23:06, David Hildenbrand wrote:

> All pages were already initialized and set to PageReserved() with a
> refcount of 1 by MM init code.

Just to be sure, how is this working with MEMBLOCK_RSRV_NOINIT, where MM is supposed not to
initialize struct pages?

> In fact, by using __init_single_page(), we will be setting the refcount to
> 1 just to freeze it again immediately afterwards.
>
> So drop the __init_single_page() and use __ClearPageReserved() instead.
> Adjust the comments to highlight that we are dealing with an open-coded
> prep_compound_page() variant.
>
> Further, as we can now safely iterate over all pages in a folio, let's
> avoid the page-pfn dance and just iterate the pages directly.
>
> Note that the current code was likely problematic, but we never ran into
> it: prep_compound_tail() would have been called with an offset that might
> exceed a memory section, and prep_compound_tail() would have simply
> added that offset to the page pointer -- which would not have done the
> right thing on sparsemem without vmemmap.
>
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>  mm/hugetlb.c | 21 ++++++++++-----------
>  1 file changed, 10 insertions(+), 11 deletions(-)
>
> diff --git a/mm/hugetlb.c b/mm/hugetlb.c
> index d12a9d5146af4..ae82a845b14ad 100644
> --- a/mm/hugetlb.c
> +++ b/mm/hugetlb.c
> @@ -3235,17 +3235,14 @@ static void __init hugetlb_folio_init_tail_vmemmap(struct folio *folio,
>  					unsigned long start_page_number,
>  					unsigned long end_page_number)
>  {
> -	enum zone_type zone = zone_idx(folio_zone(folio));
> -	int nid = folio_nid(folio);
> -	unsigned long head_pfn = folio_pfn(folio);
> -	unsigned long pfn, end_pfn = head_pfn + end_page_number;
> +	struct page *head_page = folio_page(folio, 0);
> +	struct page *page = folio_page(folio, start_page_number);
> +	unsigned long i;
>  	int ret;
>  
> -	for (pfn = head_pfn + start_page_number; pfn < end_pfn; pfn++) {
> -		struct page *page = pfn_to_page(pfn);
> -
> -		__init_single_page(page, pfn, zone, nid);
> -		prep_compound_tail((struct page *)folio, pfn - head_pfn);
> +	for (i = start_page_number; i < end_page_number; i++, page++) {
> +		__ClearPageReserved(page);
> +		prep_compound_tail(head_page, i);
>  		ret = page_ref_freeze(page, 1);
>  		VM_BUG_ON(!ret);
>  	}
> @@ -3257,12 +3254,14 @@ static void __init hugetlb_folio_init_vmemmap(struct folio *folio,
>  {
>  	int ret;
>  
> -	/* Prepare folio head */
> +	/*
> +	 * This is an open-coded prep_compound_page() whereby we avoid
> +	 * walking pages twice by preparing+freezing them in the same go.
> +	 */
>  	__folio_clear_reserved(folio);
>  	__folio_set_head(folio);
>  	ret = folio_ref_freeze(folio, 1);
>  	VM_BUG_ON(!ret);
> -	/* Initialize the necessary tail struct pages */
>  	hugetlb_folio_init_tail_vmemmap(folio, 1, nr_pages);
>  	prep_compound_head((struct page *)folio, huge_page_order(h));
>  }

--Mika

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9156d191-9ec4-4422-bae9-2e8ce66f9d5e%40redhat.com.
