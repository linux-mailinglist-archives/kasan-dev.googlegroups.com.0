Return-Path: <kasan-dev+bncBDZMFEH3WYFBB5EQULCQMGQEMCMFMLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 93F94B31D93
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 17:10:45 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4b109912a9csf79157791cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 08:10:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755875444; cv=pass;
        d=google.com; s=arc-20240605;
        b=V9gJObjyNQDK3t3xW0f6ZKlz8CZ7tU6qsSXnywO0J+A1j+z1M0R16iEupiwf50KACv
         0vzvsmz69vvkCNfzi1oevfRaHvinwbUoprgsLfjDHeAHkTdT0rksTCfYBL/SXplu8SHq
         Y/LTRn2oBUDLoBixpm4FPJZ9/OuHSKYSuwYqiJmz3EvmDnPhi1lU/Da+Ht+iR8LwchtH
         Bc2I/8ckgzC/0hO8Yd2+d4Vy2IWMwKCqENVBrGw/v9K1XeZ+VpjgZV1KXHSwgnrkYY79
         YdPwsME/1+Pe5T9gN43We0FxwJdxvRTWp/qAg15sPuZBkv81j3DNnqlVgbUjjn/rkTUE
         /QNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=8q4qdxhFE/65cVctUGZEDA/anozJn1hzrqXXRvRRemk=;
        fh=W85vCuDv+4eLShPgk7hY4CgUgzLqV8b+6dvRl7oqNak=;
        b=Sq87DMkOlXvkPi09nX7juNE7SI2kum3z6JsFFaoWWS+/9YLnCK8GRMv1FWkc/PD5fI
         drg7RFYaHQz87K87oSWSoTX6N3Nnja2E+RP+NLN0ADJ+e0brB2K/eIOO6VgSK4XzXNls
         jBh6nsL4H6QPs8GknG82oCWLQ3j7Gc5rlTRK48x/az/Gb4h+O14t/2JtDPqTkhUl/5c/
         WkCGJdcBkxz5DOsExKTPL/YMbNGOc6d6Cqd2/hF2rykU/JfRG07WZRINIhclwvvMQJqp
         r1e7gkYVPXFd7ctsug0RmGTt0lJvfgtJ62AY1lyfwcNqAp+3SapJ+ExyzskPItJcAzT7
         YHww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MfKWAMlW;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755875444; x=1756480244; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=8q4qdxhFE/65cVctUGZEDA/anozJn1hzrqXXRvRRemk=;
        b=Dc9E8fJD2ChQZzKEJFac+zdDXsqpe68gb1j4ACFsjeCrFcKSsglZFx3BUCGAKKEET2
         vXL2V/Fhw3/e/oufbVEv4wb8UG2aavbICOJjMSh/eQYhDPrE8UE0YYDPs6NPIdwYL0mK
         IezAFCVKvcvLSZ9sH0h0ajstHiGnI1/+bC/Jh9ryE5RQJhnujWQLSdnqQXTjNyRhbmS6
         xCbpW3lIMzNN9C+3npJwhMI16QhrQHqZp1vxB0pJAJN+G1jN/hk+QylO9cCRY8Acubis
         MZ1yiTI/jCj+9m6LbX+EnVJMTqFTkVgNOsBSvgqPxp6Riz5r//sRrRNNl0cpRq7WRa86
         EL6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755875444; x=1756480244;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8q4qdxhFE/65cVctUGZEDA/anozJn1hzrqXXRvRRemk=;
        b=l1TDdA9zt5G5HcKTmdAAWa0z6eHfQ7goGzYu3zxvdhZb2XRyjVihfPgMct3JlnunXz
         lh0NTxbolsO8/RO5Kye3By3snGGvzVvxg2sxCrPYXeYXZ2wZzNAHS4RuktvuRayPkIS5
         GzdQyZsW7ugjIBLJigKnChvVUx/LGkzHcvLfURGdNiv1iwnjtieiz91+rafgK12hvo/w
         vpY6HBB6P+jGrXE76nxyUb8WPNlZMnD+DtbXpKMMvhH9Y+Tun0LWtxk9dAUPgu4+34Ci
         GXMXYkR2ber813OxW5A4eKlL6qAseQhuBw+U2KKWIvIRpoDBh8FkM8ZOrTjPCy4e7znp
         OKrA==
X-Forwarded-Encrypted: i=2; AJvYcCV3ZjFv2GPNwPpssXz5r9JBzqp+bZZ5PaYMf0tqxJg1jJAZxb3ixR4IJjU+AXeYDvDeY4lGFg==@lfdr.de
X-Gm-Message-State: AOJu0Yy7v2oPCcCNzWPCdsfM+CFvkw5dOAiX1RtHn6GlLOU+srLOynDa
	sev3EoGyEE5qbCfqydajPu6yTLtiwC14+W+rQ6nH42nvTc8M1qyd36e/
X-Google-Smtp-Source: AGHT+IGcrg53KNciYOPAvocun+j35KSHG25vRkHEBFXZ7c+HK7BdzEqbbZWhUuwTQg5mmTCgVJN7WA==
X-Received: by 2002:a05:622a:90b:b0:4b2:8ac4:f073 with SMTP id d75a77b69052e-4b2aab6907fmr42830651cf.69.1755875444296;
        Fri, 22 Aug 2025 08:10:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfnRcPW2SHwbPX8vrSxJ7K2e4cbXibijGaBwPJr/+1Plg==
Received: by 2002:a05:622a:2cf:b0:4ab:9462:5bc0 with SMTP id
 d75a77b69052e-4b29d933133ls38327601cf.2.-pod-prod-06-us; Fri, 22 Aug 2025
 08:10:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVCbEVVUC32ZrqmCuo/+oGBNl5BQE3ec37tGxXWVlkmTqP97VjQP7R6LX3DmtwKWVKwvA0QH6fpaV8=@googlegroups.com
X-Received: by 2002:a05:622a:558a:b0:4b2:97f8:c4bc with SMTP id d75a77b69052e-4b2aab8a7bdmr43253381cf.71.1755875443203;
        Fri, 22 Aug 2025 08:10:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755875443; cv=none;
        d=google.com; s=arc-20240605;
        b=RUmjv1J+cTcT/xYgR9hyzXfOT5xlR8VURhhqPJ9O9wy7BIfUgljL4gQHbjDqYgjr4V
         hznlsJTOmgZHFkoPXlJdayMMjXKfuwNLqjAMYBYHo1XgcCBZbCKJH+6uynWp5pkkvPrC
         43EmtD4gKPt7AOzGY3cm7GnnFUZW40pe3z1iUl5EH4qssmBF//C1KH6HFYoP/U1YyQ83
         niAifKZnQE4NNwdZ+7voohZ7wDrOZdfpjp6n0n9DR9in3Fv229zEoSZNGumWr7bSMOZP
         4zl0gtSZZ/02EKGZA1yIXuvLhQXMbkOFb/99Xz/EUy8tH1ezfUVrUUEYHfR083KynfJd
         5LtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=7oUqMfc5Rr6TMbgE/wenfxbF6AVX4t+wpxIGqlOIW+c=;
        fh=1ebliJjrhNPR1QWtyO3StdoPZWkWGErEcqwtIx3lYzc=;
        b=E4482lezVPzAR2jwMn13LHaKVW8O1l0RiRmxTHKEGmc/tM/vkXtYCyK09vbZkwRW3T
         m+hzWlRnYWQj1o+J49aHcNfk1kUV6SWHe/K9iV/VvzFB36RBl67zxuYWF3P0/mhYWi/m
         r2GIekcS9HusH141AyObqJLCOD418eN+WZlxtmJhL3Jn8wuTHifYGHWytdRKQAyuj6Mh
         aBAQE4u7Ds6zKHrBu/Yaeir15A0IAuQ+DwYxz+MNvDFRzZwZsVTjqPa6YefxUnOwNsHe
         dUv4KrNRl+AjEKYUXT3e5ZD36t7OfPdERd4p4fOOUZiZ8pgttc97Dtih5eyrQ2kb72RG
         i1OA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MfKWAMlW;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b2b8af4d21si99681cf.0.2025.08.22.08.10.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Aug 2025 08:10:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 5905E44023;
	Fri, 22 Aug 2025 15:10:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AA78EC4CEED;
	Fri, 22 Aug 2025 15:10:27 +0000 (UTC)
Date: Fri, 22 Aug 2025 18:10:24 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
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
Subject: Re: [PATCH RFC 02/35] arm64: Kconfig: drop superfluous "select
 SPARSEMEM_VMEMMAP"
Message-ID: <aKiIYJoshnWwrJQ3@kernel.org>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-3-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250821200701.1329277-3-david@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MfKWAMlW;       spf=pass
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

On Thu, Aug 21, 2025 at 10:06:28PM +0200, David Hildenbrand wrote:
> Now handled by the core automatically once SPARSEMEM_VMEMMAP_ENABLE
> is selected.
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>

> ---
>  arch/arm64/Kconfig | 1 -
>  1 file changed, 1 deletion(-)
> 
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index e9bbfacc35a64..b1d1f2ff2493b 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -1570,7 +1570,6 @@ source "kernel/Kconfig.hz"
>  config ARCH_SPARSEMEM_ENABLE
>  	def_bool y
>  	select SPARSEMEM_VMEMMAP_ENABLE
> -	select SPARSEMEM_VMEMMAP
>  
>  config HW_PERF_EVENTS
>  	def_bool y
> -- 
> 2.50.1
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKiIYJoshnWwrJQ3%40kernel.org.
