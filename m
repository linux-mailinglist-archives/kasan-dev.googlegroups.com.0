Return-Path: <kasan-dev+bncBC32535MUICBBZHD7PCQMGQEAWXLX5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 60907B4929B
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 17:10:30 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e931cdd05a8sf5560276276.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 08:10:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757344229; cv=pass;
        d=google.com; s=arc-20240605;
        b=Xa8JbwkXoSPmilthGCi9gteVtIvNnA1lqN0D2izOjEyO1MpDAJBFC/nEwMhYKy0Uw+
         /5pUSND1hT8cBzffMz+enHZP4GKUjaRkKTdDJHCU6VHHy0c+MDMazsoEjYcjYcO06tEz
         dX2gUm9i6fgZqAn9d10lFkn2rdLAeAEZ5DzAMtRJBT2HREjXB1NBzcfjPbnk5CE6WAR4
         nm3KqUnVVaMb1K62WYKKd3zWlIp/x6ceb0klJR5V7faxMv5Fs0OELszSAEeDwzKVlfgF
         HMprmbAyTTyR2/oUyh9U4/92foFA93tAiYTHmb2TK4CkzlZXqJE7tFK7qFuA6wiS7RoJ
         VUvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=HqXd89BgSZPPF5HSZWL3g4VGaAXzXKgEOOQU3NanI0s=;
        fh=z0o/teGGbmsbwfxPgAn2FcuI8/Cg7yBJoR6VH8NQiiA=;
        b=ePLL2TfZ3T1WXOyNHg/ExJ/lSlTQb9Jh3XN6HbkLOACrkLnoHCbHSxOC5uhTlUyn8k
         iUll+aEz5UXp27ny6B3QHW3ugOmp/7voOWJFCar8zeOpPC223CqqUDipuWNzAjPda/nS
         7igWmdoMc1hg7s5xNT6Vsfemayo2eUtu4ODOIS7h8W5W5JZYTkoSyhhsisCgjhp1tP3h
         iCiqL89cKbua6vTg51hGBGWQ9Yh3n5GbXARkq4Bq6mxosCyIy5FHpN60Yx2k3lYeCZ/S
         VgHiO3pgNmRADyKBq3e6+lWjz57A2jRa3VA3JUezjDOU68nAE+2jbop6maysFnfYPUaB
         k+gA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IxlJwd85;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757344229; x=1757949029; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=HqXd89BgSZPPF5HSZWL3g4VGaAXzXKgEOOQU3NanI0s=;
        b=l47FYDTcI9rwDgaePhxitLLbQwGAUDvuqNimgok/iRb3fAHiOVmyS4BEW3TXXgr0Ja
         pA0r7Vq7JzTiwxV+97h26cGQSmnjh7b5QjVdyxIeR1VAabbvWmLixtM4blxne51++a9s
         cHS3EvEjV68wyW0IPgZMHqg22ja/PZtLr+E4kI1PM/zz1LlCZ2Tl53lsh/Wp5jt0FKLd
         wbQYeqBv655Uss46nBIhwOyTjtWh+BY2hjAt6xE+JW9Z0939OmzkTjV+AdZTjvlDthxC
         Ah+ST+eldQHHEK446Qr25iN0QkC1HEcdzAd/Bt0DyZydFV6upNO0JJUV+2+J6etVuQnm
         iPQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757344229; x=1757949029;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=HqXd89BgSZPPF5HSZWL3g4VGaAXzXKgEOOQU3NanI0s=;
        b=mROUVSgpg7BatqM48UG4xDHfqqZZF1TKglv8ENHwR3dvd5hpIpqJaRiKA+IaH5/tzQ
         rAPBdL2s7TGwPDf1joHvGEbOCy7go58r9llyvm+w6t4OOievO73IDJ+Hie3eudYmzMT/
         eX4z2MMy/zac9d2MEZJJqS80Fi3GgzuLLkuM10Dy8ACpiemthtBAZfSvX7pwS22Ja9sb
         CLG7zeFBxA+iThY7e7P9v1zuz83YfZ2kAtrDdo9pYCcwjedF6kvFS3tYWzTIcTQGw3fK
         XiK0pHskpYAl5tdej/D8BzaxerTB4Oo6SPKzq0niomioUBHbFNC+oKZtX8GWeSb5UYdB
         Jx+g==
X-Forwarded-Encrypted: i=2; AJvYcCWlRkaL6tCkoQvDxlt4hUZ6OuX8FZNysvEqAzDA2pD7P9eGD+KWwc301sxWYJDqxMn4GDfK2w==@lfdr.de
X-Gm-Message-State: AOJu0Yz1FIPHBV3CYuxpipU16uggPHDZaKpnAlu1xsNH9688xuWQ5Ny5
	V5F6xdGzT66dfFNgwQoAeeXW4VNerzEJLNhA/Z/nIvi1Q+GH5rVLbDR6
X-Google-Smtp-Source: AGHT+IFFL1X+ac1mnodHU11e8Lru/JkTm3X/qEr1wLyCqnjl3RJ95vllhqgCH20TB2Qd90og5Bhfbw==
X-Received: by 2002:a05:6902:c0c:b0:e98:9627:de25 with SMTP id 3f1490d57ef6-e9f6583cd90mr5814354276.8.1757344228821;
        Mon, 08 Sep 2025 08:10:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7RbG+5gQeNJ87RsTgNSMUEluH7w4zBOROjLzp5GThJAQ==
Received: by 2002:a05:6902:6b04:b0:e96:db47:50f8 with SMTP id
 3f1490d57ef6-e9e06ec00bcls494962276.0.-pod-prod-05-us; Mon, 08 Sep 2025
 08:10:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXtVwlV+YsyhFXk9e6C5HtdlXZIFtyicA1/wfiyC9muVkQp8/ZEcXGayz3S+mzKQAn1RhuygMMFcs0=@googlegroups.com
X-Received: by 2002:a05:6902:1203:b0:ea0:b146:1bd3 with SMTP id 3f1490d57ef6-ea0b1461dd3mr5104365276.18.1757344227740;
        Mon, 08 Sep 2025 08:10:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757344227; cv=none;
        d=google.com; s=arc-20240605;
        b=ZG8FyrvBvVb7z3WNsdfD8eeLziMQaTuIDUPMmBqeWKS0K0PHTn/WLYEzi5blBZrCb8
         QhTFS4deMgPHtKIZcnHXewn/O3IZ2sOzOVz2mFCnvlp5IejLUgzFRRn7fXrW5+OaAsE7
         ZeOElhSVd9CTGu8SQKOV8pPon8EQo4Xb/7oTdVpRZhlPXAdF5ImIIQvhmyjDbtkw2vjV
         E/8qJhkZE0V6pzBP8+lCV0XpQYSAy5OI6DYyeM38Ld4I5GK9C5BlPoNDek99ecwTcPVM
         ntHVYaRlQWgsyv5Lnuisp6lB6PnAfzMhwVrocqQZ9zPnEmJldl8XuDTeIP+NXU4bNTcO
         buIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=MWs38ipt6qYVKPoOaNWVE9IjFwNAzWbj0IVoNQpA9LM=;
        fh=wNadXKMHiVH2Xskcd1SdFQNv91bgLf4snwtYwsYV3lw=;
        b=J6P+AAfUZWZgn/UdyUijRUnH/3uJA+bxczmp+egKUwfB3dcQ6co5zZoH8bMWnc4an6
         WOf0UkdBm2VQH6WdBhTAiGTaDI1v4BngN1SF5D2fuIxBEBljfQbRydcqpTSqitZ1r8Gn
         kxZ/nTnR8jn2QDmTw2PSIv3B3mXvvhm52BPpx3PHhalCwJgE9YF0Gux2JN0NEyBStsYO
         586Y20s/XBEBqKIGXfP8yQoHMWHq7ZABGTRWC/kWQX8Q42k9Q00QIeg0C/Ae0m4aYf2V
         huUUF2WppKM0HVhBE8IPiM13Zl9PrqXTUiz+WDQfwePdcEe7WCw6y//vAqNYzUbxvHY2
         410g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IxlJwd85;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e9ebd304629si377471276.2.2025.09.08.08.10.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 08:10:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-74-OjqrPGrjMA2z4U7lYRDlkw-1; Mon, 08 Sep 2025 11:10:26 -0400
X-MC-Unique: OjqrPGrjMA2z4U7lYRDlkw-1
X-Mimecast-MFC-AGG-ID: OjqrPGrjMA2z4U7lYRDlkw_1757344225
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45dd62a0dd2so17226375e9.1
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 08:10:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVypgZPSAi5S/tJ2NM/7SLcrL3i35fAx0wEXt6mhQfI1ytQJcCv1TyPCMiGhka5sNe9uNZ8f3U5Q9A=@googlegroups.com
X-Gm-Gg: ASbGncv6NhBSzXuUVdiFaed3XdT0r3dD5zn1aVUgH92Qis8gA6g7CELzykqc20u2iKv
	oufhV9/EngvR7RwstAaZ7YghZLRA9SYbDfGIIgnnCWz0CYmciax4UNHxVQMwuk7qlvHS9aXWUwq
	3okrF/qC4usLTzU3z3IXshKCdQVc80hDViUaxc+t19j8gDXxs/g8iXzFH79zQZnhnQZCp7dGCm+
	Gc954wA4VIxA7WEvYK1Y8ROPoxITGbgRXdDeQgWUVejNmsuRy8MKqWPtuPhaWBOf+9pwX8JB5ko
	QnmArsCyiOnqtohCoGNgv1WJCTZFXaW1an4f2xLPfNHfPfMZU+uCqveDFg1+MWPWHE5/5aYkiio
	Pj/DPZnob4Pm27VIzho8nwGgoxFY3kwJxRW02NH9SFdj58l/m8kd8V4mJtar6RU0F
X-Received: by 2002:a05:600d:f:b0:45d:e775:d8b8 with SMTP id 5b1f17b1804b1-45de775e1famr26225235e9.1.1757344224808;
        Mon, 08 Sep 2025 08:10:24 -0700 (PDT)
X-Received: by 2002:a05:600d:f:b0:45d:e775:d8b8 with SMTP id 5b1f17b1804b1-45de775e1famr26224795e9.1.1757344224275;
        Mon, 08 Sep 2025 08:10:24 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f25:700:d846:15f3:6ca0:8029? (p200300d82f250700d84615f36ca08029.dip0.t-ipconnect.de. [2003:d8:2f25:700:d846:15f3:6ca0:8029])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45dddf8c51dsm109133275e9.20.2025.09.08.08.10.21
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 08:10:23 -0700 (PDT)
Message-ID: <076658ac-78bc-4d4b-bf3b-d04cd3f0fa21@redhat.com>
Date: Mon, 8 Sep 2025 17:10:20 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 03/16] mm: add vma_desc_size(), vma_desc_pages() helpers
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
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <d8767cda1afd04133e841a819bcedf1e8dda4436.1757329751.git.lorenzo.stoakes@oracle.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: T1OjWR4OrqziQWuyWKqISHBOkxUKNbXqg0NfSHGvVjY_1757344225
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=IxlJwd85;
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

On 08.09.25 13:10, Lorenzo Stoakes wrote:
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
> index a6bfa46937a8..9d4508b20be3 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -3560,6 +3560,16 @@ static inline unsigned long vma_pages(const struct vm_area_struct *vma)
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

"const struct vm_area_desc *" in both cases?

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

We really want to forbid any private mappings here, independent of cow.

Maybe a is_private_mapping() helper

or a

vma_desc_is_private_mapping()

helper if we really need it

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/076658ac-78bc-4d4b-bf3b-d04cd3f0fa21%40redhat.com.
