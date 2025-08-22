Return-Path: <kasan-dev+bncBDZMFEH3WYFBBKEQULCQMGQE2C4KLHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CD7EB31D84
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 17:09:30 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-70a9f562165sf69552906d6.2
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 08:09:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755875369; cv=pass;
        d=google.com; s=arc-20240605;
        b=CSVbhkvZPZ6vTIp6TbtswGxCl1lkcSI8PGkKp9USbivOrDCr1uEugrAoyq0Bj87R5J
         0Dv3/FCf9xabycl+WGQyDUboE+ljyrKlLU3WqsFoxKNRETGdWA+vyanHIRynE+z+LFGW
         KmvPDau7ClGjtKMghrBGfVytXquJQLrZG8tFcuryTxNco8zf22gE8tCK/XlRfZwrNEgy
         GrTBKX/rRkrACbG0SfRJxeCx69xhRwCPK1dSQzwfMOpKlYw9UenqmVUopnUfSqs7qUHD
         /0YLusFy5/DHvQj91FkZh3ibhqI1hYdh/b+S+s6SHspzqdu81dVIMYWpJuFBaIPNBwse
         kFMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=erHUmTK9HMTwi7lRJ0a5ReeF0SxvTrEMvqvst+3NMu8=;
        fh=IS7P3A/rTcARJoVrF7hReA6zSSOngOs5rXuyzG+m16U=;
        b=Uhlwy0sBSXYjpexxWQsdlza5a4Co3eVYljxBObCuZb4NKw8bZKkmJU+XGOoMws6A//
         QwEs9Oo/VkoRoH2MdQSIzlUqXmCLTaclywQfpPmNbpVRPVlgOGMLRo1xaq3AAVYIn9yn
         9Az9zxJhg+dpSqMi4ZMLXwh2eIDnOJ2U1L46CcWBns8v9cQQKYv+6qDG72uXprtkr3FR
         DpZNkBthRW/SlQSByy+pywgNWI/CjQdhWJi8QuNKwpOwLlEycpNevRqcIb5wWp6DeJE1
         M1/i34PyuoXScf1b/PJmJ9Y+HkF7igjnbI3oE71xf3SMSmKld18wqNRs6VyDXKtihFqa
         TxEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Prntf9uZ;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755875369; x=1756480169; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=erHUmTK9HMTwi7lRJ0a5ReeF0SxvTrEMvqvst+3NMu8=;
        b=PCbc+aAd4wnK8rk7r2DjQiLBLFG0rfEzYZNkzT01cojC48r/uYSVl7rTY/F90HT8jl
         sOEMG7Ar8K743kJ5yBN8EqO42BXZwEFBqOcYcVNNXTwuim/bRvPYkGfkVPOeiAO4/uhU
         eWFEAf01l7GotIojmAxKrQvznAMkchYlCJy/08wQT+VkCdKOkGvzUIeL8YNVy6eVHTAA
         BCDD3WJkhiIeBIq3zhTzaVNJ+4anA0RA4GOQJqzLRrSVcsqzzfTlTBxIPI/REY/tvv/o
         DG0M6pLTKyS1hxFnG3lJGxjxhPhHoMXxzggO0iEYG6HKUIiqbF0CrwBuvydJLfEbtnDA
         o1Eg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755875369; x=1756480169;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=erHUmTK9HMTwi7lRJ0a5ReeF0SxvTrEMvqvst+3NMu8=;
        b=oyP6XoPLvX3MKSEMvDEJSLP0r+ahFbLJn3RkWyRLEzGXXHoyUcoPDVhL/QOC4ygzpu
         ZBkcY16utZ8hS4sS6bv07WzUFgsHxfg0CP1BIWJpg6zVz2mQU8qmo++a5XBVbuKIpGOD
         mjCjyfirbj5JUSValsmqvFnRGSjKst2KhiYm53tGdill2LCt5TwAb98sCNhxlS7Kv326
         3tjJBYsh4Q+VPzNAiBYImeH/cQYIEUyCEjBvkMzLn0IzpDw/vQ3v+tAbt5ruMCbm0n8H
         D15dHN4FfhX8wdaVdv8NxvdPRjxW7gq90UWRGfoXEF2TxXv/OdnW+dGQkKbX+aQ8lg9B
         m3wA==
X-Forwarded-Encrypted: i=2; AJvYcCXJ1fCPhb4GZbrcDudykz+W3iEL0aa+NtChGcYP8IvUOzT10xB6zl3rfdcCMACHMGBpOX5S0A==@lfdr.de
X-Gm-Message-State: AOJu0Yxbz8auuN/+trn52CKyqdS21ksPQRX0jW3GHfyrti0FC0JDm0OB
	Q5kZIyS3bK030b44cJFpR49bc8g5bqjYKcApFYTU5EWH8FcUVCNKvrhn
X-Google-Smtp-Source: AGHT+IFL/08thpNFYnepDHySC6uOOVhAI/V4Aa3IFLqf3kP8NM6xpBfOC5No77hgKosQ9+lh40Ex3g==
X-Received: by 2002:ad4:574a:0:b0:70d:8703:1bbd with SMTP id 6a1803df08f44-70d97200ecbmr35403106d6.33.1755875368503;
        Fri, 22 Aug 2025 08:09:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdprhnPecqgQRliAe8S9rjgkO+b9ppBtS/98HYtHdo1gw==
Received: by 2002:ad4:5ce1:0:b0:709:f373:9f9e with SMTP id 6a1803df08f44-70d8584709cls33999326d6.0.-pod-prod-04-us;
 Fri, 22 Aug 2025 08:09:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUBzSS1V8YqPXvNo/sGShuaqu9p+HNmQoed7sQY/F1FzUeOO8iH8gc2T/5zJ2m975GRtGPkXrCMBAs=@googlegroups.com
X-Received: by 2002:a05:6214:400d:b0:70d:6df4:1afd with SMTP id 6a1803df08f44-70d9725e994mr38079966d6.59.1755875365613;
        Fri, 22 Aug 2025 08:09:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755875365; cv=none;
        d=google.com; s=arc-20240605;
        b=XtBd1oV94VMkB6DxQjLbyVEYZoyWZnq4Z5vt5u0r68xjwuYaE00k4UpxLdYULCSSmJ
         U5ZYgcjCB2MD5RwIOL0PPRTiLYLH3TV2DB9S3zYcfuvQPwB9Ye42ZI249qbRzAGyNFXJ
         9EQTvpBBtOWOykaSSqmmLXaTy5cwnuJ10oWIc5i4jwU7yVyHZuCft7i1KBE+evWLuVmy
         SmxSMKjijOqTIfbwVjPf+yXWH91oKl6geb7Xb/Iw0P9Ys2X0n97DMIOWgVSkWJU8ZNR9
         F9GQez83krrbx74O5YjUBmKhhpVVCwdUlQFm5sWczJFdh0wcr06Xb5oZbIlzrcJEszNX
         RUEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vCOsOz88mPScACBG1/CQZuInDpdXn6Z4TRAWSkNAAYc=;
        fh=08YOcola6x+YsEObfrRJABc6QPtq8bv2itfJcuZUlwU=;
        b=GFJijSLdkortgxLHMIJmn+8hMqffpBTBqnaPOgkschYHz4VPEc5lwflJ2faNuKQXuE
         s/CO74OFj5vWMw3k+KPWLiSySDLrVRr2ZGbAV6WJxqi0IhVCToLJPL6LmYfqfAIZUgP/
         ZYZC8o05yj58CSejeF+hUphb8Qcco7L3F1r8nvrgnLd1gYxIZlYEG6eWIr3T/FIutune
         sSplCqgIAzcMRBjeJ6Y/2KCZlSTpGxAsowW3dfex1MIEusun5D3a17YIV6AHK9PdBf+D
         KWlIGMvzHT1aQYjvOAjA4IbqGv5jmhiXxhoAKTKAFFAp3Wnk/pL3yNq8ftPdjUgO4P7J
         Upug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Prntf9uZ;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70da723854csi29866d6.6.2025.08.22.08.09.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Aug 2025 08:09:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id B028D4368F;
	Fri, 22 Aug 2025 15:09:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4DC2FC113D0;
	Fri, 22 Aug 2025 15:09:07 +0000 (UTC)
Date: Fri, 22 Aug 2025 18:09:03 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Huacai Chen <chenhuacai@kernel.org>,
	WANG Xuerui <kernel@xen0n.name>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>, Alexandre Ghiti <alex@ghiti.fr>,
	"David S. Miller" <davem@davemloft.net>,
	Andreas Larsson <andreas@gaisler.com>,
	Alexander Potapenko <glider@google.com>,
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
	Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH RFC 01/35] mm: stop making SPARSEMEM_VMEMMAP
 user-selectable
Message-ID: <aKiID8i6dYrlVi5T@kernel.org>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-2-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250821200701.1329277-2-david@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Prntf9uZ;       spf=pass
 (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Thu, Aug 21, 2025 at 10:06:27PM +0200, David Hildenbrand wrote:
> In an ideal world, we wouldn't have to deal with SPARSEMEM without
> SPARSEMEM_VMEMMAP, but in particular for 32bit SPARSEMEM_VMEMMAP is
> considered too costly and consequently not supported.
> 
> However, if an architecture does support SPARSEMEM with
> SPARSEMEM_VMEMMAP, let's forbid the user to disable VMEMMAP: just
> like we already do for arm64, s390 and x86.
> 
> So if SPARSEMEM_VMEMMAP is supported, don't allow to use SPARSEMEM without
> SPARSEMEM_VMEMMAP.
> 
> This implies that the option to not use SPARSEMEM_VMEMMAP will now be
> gone for loongarch, powerpc, riscv and sparc. All architectures only
> enable SPARSEMEM_VMEMMAP with 64bit support, so there should not really
> be a big downside to using the VMEMMAP (quite the contrary).
> 
> This is a preparation for not supporting
> 
> (1) folio sizes that exceed a single memory section
> (2) CMA allocations of non-contiguous page ranges
> 
> in SPARSEMEM without SPARSEMEM_VMEMMAP configs, whereby we
> want to limit possible impact as much as possible (e.g., gigantic hugetlb
> page allocations suddenly fails).
> 
> Cc: Huacai Chen <chenhuacai@kernel.org>
> Cc: WANG Xuerui <kernel@xen0n.name>
> Cc: Madhavan Srinivasan <maddy@linux.ibm.com>
> Cc: Michael Ellerman <mpe@ellerman.id.au>
> Cc: Nicholas Piggin <npiggin@gmail.com>
> Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
> Cc: Paul Walmsley <paul.walmsley@sifive.com>
> Cc: Palmer Dabbelt <palmer@dabbelt.com>
> Cc: Albert Ou <aou@eecs.berkeley.edu>
> Cc: Alexandre Ghiti <alex@ghiti.fr>
> Cc: "David S. Miller" <davem@davemloft.net>
> Cc: Andreas Larsson <andreas@gaisler.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>

> ---
>  mm/Kconfig | 3 +--
>  1 file changed, 1 insertion(+), 2 deletions(-)
> 
> diff --git a/mm/Kconfig b/mm/Kconfig
> index 4108bcd967848..330d0e698ef96 100644
> --- a/mm/Kconfig
> +++ b/mm/Kconfig
> @@ -439,9 +439,8 @@ config SPARSEMEM_VMEMMAP_ENABLE
>  	bool
>  
>  config SPARSEMEM_VMEMMAP
> -	bool "Sparse Memory virtual memmap"
> +	def_bool y
>  	depends on SPARSEMEM && SPARSEMEM_VMEMMAP_ENABLE
> -	default y
>  	help
>  	  SPARSEMEM_VMEMMAP uses a virtually mapped memmap to optimise
>  	  pfn_to_page and page_to_pfn operations.  This is the most
> -- 
> 2.50.1
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKiID8i6dYrlVi5T%40kernel.org.
