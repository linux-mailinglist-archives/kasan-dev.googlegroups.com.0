Return-Path: <kasan-dev+bncBC32535MUICBBZV5SHDAMGQEU6A4S3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6550AB555AF
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 19:56:56 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4b62de0167asf56351401cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 10:56:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757699815; cv=pass;
        d=google.com; s=arc-20240605;
        b=UUDAN7ulImJnwYFKGdaXm8fFYOZ7/0hQYCTBXVdm68MgEsWVeGMgD/plkya0Eo1kAq
         mqkh+P5rSoXZh1VGNu0oUzJqyenoT7R68V+Flar8AV2k9YC+zEJqWRRJR9nLcl4YWqZ1
         OW7P0DldyzWFOeBj9MCQjZrvQrfiOEc1TBU79qoQT/P21V5SZYf0A4lgISXu0D0tSH2W
         7L8Jrjzs9eVOaFYthv1RHs+wBpiFnzIt9FcL3mP0247s6s0bUnWNEgq65guzx7jRKe/+
         RhkZL5MgAZYhQA4gVkTl5Ttu1Rc46BLKFXRBbfFnc8qLMVcw7HxEl5TGXYSnc6ucq3SQ
         GyoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=Raq2Li26p7NuRoWliXgSaF9eQFzrEWPeb1cHqv9LaHo=;
        fh=l5ETNzpB8//4J/l0yHvqPsHDscXU2S/HhaWpWzeKCn0=;
        b=QoBcosfA7joMngaTMENk40j2aVMGpe4V2SxnjSGP0uqaWxV8DVJ1MbInBmZ1m+jtGQ
         6Z5477SjxrjOZi+sv9X9sE0V8kzEchZ5lkp1puiDdUHzGocxE0BEamIYbd2SHn9l+nEP
         086ZC8DvoN3D9v6rJFQbrKfmpcBXIra49SFzX6JMC/XPGq5Tt+U0fpnkf0evtofGoRpD
         JmDqRKGLh4tApjCRY1L6woXSMG1ngkvOr0+33D4DAzmjUIQJ/hYeibkZHDyJF4WxUBvN
         py5Nd1iHkDx2iLcuieMB/0gN768YVXdlt2Qb+v5gcFvGQXs19lQyXBpPWvWsdZokOwi+
         Queg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ePRJ6cJT;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757699815; x=1758304615; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Raq2Li26p7NuRoWliXgSaF9eQFzrEWPeb1cHqv9LaHo=;
        b=R7/y2YrFgY27ywBil1qjveMGzyA5GBlNxRhPeivkvg5RArWO8CMD+tmcYp+vNaXk8s
         sRW6qkSVycs0YaCtL2RNV6lOlzruUN9fTqNfKu78xgIstw8R5D0/ZzYxfAMQPRNSmhbU
         D+sZtf/2yanOCHIB97TAcTtBsZgXaqNGbgJIojim2PF5s7O15/P5wdaXDKmuguTc7xml
         5D+27FlV/UUgsbduFEYc0wORqvnez09oSXGMh3JfwQu7ely1KNyEmmmNobXK1Kdt9Jrk
         M/GtiPrEOQMCSFZIT0KMKr/ZAy8xYWjgiwV3p5eN8Pm0GvTbRehbksEaEsdSYUSd+DLZ
         Rknw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757699815; x=1758304615;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Raq2Li26p7NuRoWliXgSaF9eQFzrEWPeb1cHqv9LaHo=;
        b=p+Wo0LLtYUTGJmoyX73ByNlZ0mM0pOcyz9HuM10oxeh0zuM4Ch83wB2ZxgNMYaF5VE
         J5nlt5sMWsMtibpVQQWoHYQCiOlZY4CfZJ4dw7W8e634mzNHfoy51KTybYNdvV7hA+AT
         bLB8W9WGRAwRsgXmQYaB5SVW0eavdmqnUikLOg7UNKfZnsNPGeKpD4ImaduvmZTUKNev
         IaeCDRKxo04K+GZOgcgVjVhx9rK13uSYLGS1o/h1nnZZNBSKQndKP9q43rRU7gQx8w9O
         m0yy7zYqcVK/CrM4Vr5V00bIqFWyjPY1VQEssOjQttJowOt6MnmJRtkJ+FX9x5PrAMrA
         3N/A==
X-Forwarded-Encrypted: i=2; AJvYcCWijA+eCkaXqYWkeWWLSSiY46Rn0A5u7iNO8bC9qe6NTWle8A0d9mu1gHVBpGnR9AMMdemkuA==@lfdr.de
X-Gm-Message-State: AOJu0YxhCuJ8/ox26O1jihrTxlPsZGMce2piLrx7UtL4HxZqDLgEN9Gj
	h49C/rr9dWatGJoDffpm86RxDUTn5WaDB4TVR2eqHQCArKsPHYOBV+WE
X-Google-Smtp-Source: AGHT+IHU/v/H+NjDQzuJKtRZQp20PFsTEXvs/10Y0tOkGHokQGg9tdWUJNGKZRP10bhuk7qZ5ZZp+w==
X-Received: by 2002:ac8:7d4d:0:b0:4b6:2f52:5347 with SMTP id d75a77b69052e-4b77d13b8c6mr51981811cf.84.1757699814850;
        Fri, 12 Sep 2025 10:56:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf68IDYaH2ZVXxIrSDXVnaeTPFb5PtCCd62O735i/wxZQ==
Received: by 2002:a05:622a:4cd:b0:4ab:9462:5bc0 with SMTP id
 d75a77b69052e-4b636cc04b2ls45108971cf.2.-pod-prod-06-us; Fri, 12 Sep 2025
 10:56:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU1bKw5UcXdpTCvmLa245l9yME109d8UBlqCsG9lkGzI5URFIjaB31khT480Jx/iFInSlUT9myYiXs=@googlegroups.com
X-Received: by 2002:a05:622a:10b:b0:4b0:6228:b3e7 with SMTP id d75a77b69052e-4b77d0c8919mr44984441cf.43.1757699814004;
        Fri, 12 Sep 2025 10:56:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757699813; cv=none;
        d=google.com; s=arc-20240605;
        b=kj7e7jIXmXsaneF/uqidLE5mBH6ezeypiNJa7HlfHTHs+NZocXCW7yMfK5qSdekBmO
         p4jkTPEt+Cdo5tl2M5bGhfDeQv6gDHYrYFa+HuhsKPfl8RP+VpGRg9TiUFXjnM+pTZuh
         +O2ZUDDhp1K6KCZCZrJhxkyhvDb1/JBHvsq8HJQuIyKvW9KFVxIID5GcQ4OTm6psREgX
         uURs2rCXVvAg3ZHyKs7DY3FQMH4dd2w3knypx6vlV28uMV9GYIwM/t6jik8oljElFYlZ
         HQ5X3tCm94KV/M4Lv1C6oEaEQHBrBqQNpTW+Z8dtS6aCjaLy1Vino/XE/yrXKTba44d0
         A6WQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=1WFUlnErlcGz3KGoSgWtaZOcBftKtTBkFfUxb/98m8k=;
        fh=4dSWyeCw47J6zXfRaV6OlV2LGn2DkQOceJf+UUWndQo=;
        b=lXm74ZR/CctVwLpcQAVYXLfIZYlFP9m4JeCGt3JdEZFb1G04kAAWBBJ0aDATVT1dMs
         lTbpC5Kq9M5b5/Vg9M1nQ3g8uZthex7TPPPWVjZKEJwdraJf3/jxChgTcw/6Lbs4jjTd
         ue+ikqo3lk2MEniTdTkCiB7SgJxONoE2ehXUjbPPROtENAfY4P9C3AfLVspe4AOqLFKK
         YNgoMAau5NgrDWWoyS0OySXlr1KgNIrCCVhPMHuIraZx0fQb/8Qt5KtVDxT5opTBcjkU
         YU04F+wnOtxhpdp+DY5lCbTXXRoMVEb9ru+FFOcckiC3NHi9wpaY6bJ/Poi+VpXKzOMj
         RDwg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ePRJ6cJT;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b639de813asi2162641cf.5.2025.09.12.10.56.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 10:56:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-632-pWMe4mZnOHWr-aBSH1-ajg-1; Fri, 12 Sep 2025 13:56:52 -0400
X-MC-Unique: pWMe4mZnOHWr-aBSH1-ajg-1
X-Mimecast-MFC-AGG-ID: pWMe4mZnOHWr-aBSH1-ajg_1757699811
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-45dd9a66cfbso19084255e9.1
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 10:56:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVKTmB4bHckoP0//KgbV+94eByw0BoCHXH7bBq7kJARrE6v5T0y6YAFMm1v3ah2oRfzEyv5z2kDMzE=@googlegroups.com
X-Gm-Gg: ASbGncv5FmSS2LqaKueoLSQ9iU/NVy4BoUL3w/WP1fXCZIuJkvpMe1g9GN1ZDb25bch
	kN2Ix+Ldcavs91Kq2wXSCz91kB0p50GqFbQQeHvpGdOdjjsYiXNEYyH6vm0TfhCkhXikXPDJMW1
	yay/gEaoFigz1O0HkkWXldulvxdtRCnmkwbc7QNHyIosMi8dqxvPQ9Qk/7ZMzhTkoCbQg+IZku9
	6BAWo3Usi/EEwtS4QrIhu6tgHIthl3eXg4eXcyiiOqknWvneRWSzmhWaSi8yR296est9AXmkSr8
	+8kW0eA+58QPzCsPzNhKFstOqVqpQxY6KYcHfOFqx+ecPkWWkMdZSY0JP5cPzYKUv5KbigttEwi
	e6MBfEC2xoIiG2/jOBNy0/hNf7+bbl/7xUUlZiz1ZKoHEtdwM323CHCiD4efqCaET1Dc=
X-Received: by 2002:a5d:64e6:0:b0:3cd:6cd:8c2 with SMTP id ffacd0b85a97d-3e765a22c28mr4163094f8f.60.1757699811067;
        Fri, 12 Sep 2025 10:56:51 -0700 (PDT)
X-Received: by 2002:a5d:64e6:0:b0:3cd:6cd:8c2 with SMTP id ffacd0b85a97d-3e765a22c28mr4163028f8f.60.1757699810512;
        Fri, 12 Sep 2025 10:56:50 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f20:da00:b70a:d502:3b51:1f2d? (p200300d82f20da00b70ad5023b511f2d.dip0.t-ipconnect.de. [2003:d8:2f20:da00:b70a:d502:3b51:1f2d])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3e7c778f764sm1719041f8f.57.2025.09.12.10.56.47
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 10:56:49 -0700 (PDT)
Message-ID: <3f11cb3a-7f48-4fb8-a700-228fee3e4627@redhat.com>
Date: Fri, 12 Sep 2025 19:56:46 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 03/16] mm: add vma_desc_size(), vma_desc_pages()
 helpers
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
 Guo Ren <guoren@kernel.org>, Thomas Bogendoerfer
 <tsbogend@alpha.franken.de>, Heiko Carstens <hca@linux.ibm.com>,
 Vasily Gorbik <gor@linux.ibm.com>, Alexander Gordeev
 <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>,
 Sven Schnelle <svens@linux.ibm.com>, "David S . Miller"
 <davem@davemloft.net>, Andreas Larsson <andreas@gaisler.com>,
 Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Dan Williams <dan.j.williams@intel.com>,
 Vishal Verma <vishal.l.verma@intel.com>, Dave Jiang <dave.jiang@intel.com>,
 Nicolas Pitre <nico@fluxnic.net>, Muchun Song <muchun.song@linux.dev>,
 Oscar Salvador <osalvador@suse.de>,
 Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
 Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
 Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
 Reinette Chatre <reinette.chatre@intel.com>,
 Dave Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>,
 Alexander Viro <viro@zeniv.linux.org.uk>,
 Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
 "Liam R . Howlett" <Liam.Howlett@oracle.com>,
 Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
 Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 Hugh Dickins <hughd@google.com>, Baolin Wang
 <baolin.wang@linux.alibaba.com>, Uladzislau Rezki <urezki@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
 sparclinux@vger.kernel.org, nvdimm@lists.linux.dev,
 linux-cxl@vger.kernel.org, linux-mm@kvack.org, ntfs3@lists.linux.dev,
 kexec@lists.infradead.org, kasan-dev@googlegroups.com,
 Jason Gunthorpe <jgg@nvidia.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <5ac75e5ac627c06e62401dfda8c908eadac8dfec.1757534913.git.lorenzo.stoakes@oracle.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <5ac75e5ac627c06e62401dfda8c908eadac8dfec.1757534913.git.lorenzo.stoakes@oracle.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: Q1MU7TiTKhljTYzba98KwjIeJTMT503Y3Xi-C5kYzzs_1757699811
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ePRJ6cJT;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

On 10.09.25 22:21, Lorenzo Stoakes wrote:
> It's useful to be able to determine the size of a VMA descriptor range used
> on f_op->mmap_prepare, expressed both in bytes and pages, so add helpers
> for both and update code that could make use of it to do so.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> ---
>   fs/ntfs3/file.c    |  2 +-
>   include/linux/mm.h | 10 ++++++++++
>   mm/secretmem.c     |  2 +-
>   3 files changed, 12 insertions(+), 2 deletions(-)
> 
> diff --git a/fs/ntfs3/file.c b/fs/ntfs3/file.c
> index c1ece707b195..86eb88f62714 100644
> --- a/fs/ntfs3/file.c
> +++ b/fs/ntfs3/file.c
> @@ -304,7 +304,7 @@ static int ntfs_file_mmap_prepare(struct vm_area_desc *desc)
>   
>   	if (rw) {
>   		u64 to = min_t(loff_t, i_size_read(inode),
> -			       from + desc->end - desc->start);
> +			       from + vma_desc_size(desc));
>   
>   		if (is_sparsed(ni)) {
>   			/* Allocate clusters for rw map. */
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 892fe5dbf9de..0b97589aec6d 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -3572,6 +3572,16 @@ static inline unsigned long vma_pages(const struct vm_area_struct *vma)
>   	return (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
>   }
>   
> +static inline unsigned long vma_desc_size(struct vm_area_desc *desc)
> +{
> +	return desc->end - desc->start;
> +}
> +
> +static inline unsigned long vma_desc_pages(struct vm_area_desc *desc)
> +{
> +	return vma_desc_size(desc) >> PAGE_SHIFT;
> +}

Should parameters in both functions be const * ?

> +
>   /* Look up the first VMA which exactly match the interval vm_start ... vm_end */
>   static inline struct vm_area_struct *find_exact_vma(struct mm_struct *mm,
>   				unsigned long vm_start, unsigned long vm_end)
> diff --git a/mm/secretmem.c b/mm/secretmem.c
> index 60137305bc20..62066ddb1e9c 100644
> --- a/mm/secretmem.c
> +++ b/mm/secretmem.c
> @@ -120,7 +120,7 @@ static int secretmem_release(struct inode *inode, struct file *file)
>   
>   static int secretmem_mmap_prepare(struct vm_area_desc *desc)
>   {
> -	const unsigned long len = desc->end - desc->start;
> +	const unsigned long len = vma_desc_size(desc);
>   
>   	if ((desc->vm_flags & (VM_SHARED | VM_MAYSHARE)) == 0)
>   		return -EINVAL;

Acked-by: David Hildenbrand <david@redhat.com>

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3f11cb3a-7f48-4fb8-a700-228fee3e4627%40redhat.com.
