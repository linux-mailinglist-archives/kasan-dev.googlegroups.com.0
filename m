Return-Path: <kasan-dev+bncBC32535MUICBBIFMY3CQMGQELMGRJ6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E97DB3BA70
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 13:59:29 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-e96e5521af4sf1999501276.2
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 04:59:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756468768; cv=pass;
        d=google.com; s=arc-20240605;
        b=F3bxNEX05ugNUm/tCnoci/4DQt/e1CnwGGqnNIjAnq1jz2reGHz6pQ36Jj5Q/IFIlV
         IYIyNydk+SH35taUJNbY5en/UYtPO4zaEkq1wxoLo3DkWvo1R/joSRziKj4oRrv5cwLM
         XPm6Bl/twrfl6fD7fCgpwCYHVwTDGMIcDBedbQqq0PGUOXqGQnZOkuVsJLDSn1JvuMCz
         TezUOA/v5P/Q8SMYQrZzcvNZ23KOOY/ItP+V8wNJChZXSiwQRRhyGxPSqO+ISrS5wXzm
         mI9viLLeIRL4zDuzlHWstIV39UUkYmM3a0SVcJ/JyKYiX8lsuT03UzjPqJ13O+e9ed0p
         DiRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=Sm/U7pGFN8ajP8QtYiAwYP5XlaWdXLWgYjR5PUV60Xk=;
        fh=Mebu7csMxfYD8l2Ck0nDPAkyNEjre4zhjSJEa6WEnyA=;
        b=T6BJ2WOff8zW9XOiFo4a0bvTFbrAg4mOK3T40znOMujdH/RfuuDD1OrPiZ+I5hY67x
         59F5zqHYFjlMoaZ8TEkmL4VwMwbMzY7QS4RJscIY0iwuG+m+PY/h0+3AoqDY5UOWfWHl
         8PaS6SQ7bHyKs3MXpzmF1XUKxhc9YGkVSZtkxQUAnqujz9CSIFL1WjBUXTkh9X9FhVf7
         sZja4QR+KVjdgCrzXTBqvo62Wp4mjsRA3d83FfV2hAHf8YzWr6d8nqjFhrp3dYSDUs8l
         bQanDs3RH+KEFV5KMEkH6noMx8Rf1k1zwyxFeNdz9lwEJvq1PCzen7vcC5kup+CkzvAh
         c7Ag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=i3QdRllr;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756468768; x=1757073568; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Sm/U7pGFN8ajP8QtYiAwYP5XlaWdXLWgYjR5PUV60Xk=;
        b=WEIVry0f3v44ftwVdS+CkvBllIQmNx3gKhFTsMKVu5Y56cM0X2L4O7E47yLUb+tkdV
         f8VPoML+q1ue0WyctFuuxuO0ns55w1Bnl+yT/iz+jLp2Sep4tVky74jRcasv1sZqZFzt
         qMiE3aAzR/nQ4/pHnLvzTLjmFm8Pg87Ykum8GFqtXN/F25MzBbQdQUZBt8pyCFX5ed+L
         bsq2sdHTMRkyo8aYyJWBVGiCiGB3pq8YsAstzAYuTjS4NHGDL90zNANHmwlVWCaUNXQE
         hElZQ1uhrVMTIhzGM76fsEq/m2lolIxkCOHt1iWCj4xauRbjxREBHV9nIIPSH/XtYFdw
         LYgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756468768; x=1757073568;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Sm/U7pGFN8ajP8QtYiAwYP5XlaWdXLWgYjR5PUV60Xk=;
        b=Z5vh2S4AuJWZBUVfxVki7WWDP+sUf9J8T9UK2Vqr0B28OGFdbItrcdgXgRiKiJ4dS+
         P5fbfnyvtydZP+JXivzdP83oBZkV1EhQyeYlzu59GwWZ5YDduxuW8TA3ZSi/FGttfZWJ
         urrZFHGCWjCUF5d5JXNvV2aRM9iesXBgk5+sk1rdjuxSYFPqpUxbsS31uaNKX5eyM+mD
         Eha0gyVVT63ek6WDf2m5D2nXDzYexY3o3KarAcrKg/7diOaX9rVdfobMbbPjLelyoiN1
         46C2f1Bxc5OD723rX7+gaEt5OuZ/tzpuS/ojLtikxqn3MU2HdCd3aJZxwC2UKJLJ3nb8
         PY2g==
X-Forwarded-Encrypted: i=2; AJvYcCV6lOrox+9Oie8fRDbm8Pr83vmK1yUeVK1W0/Ef/3+PbAlenRxcVm3b2Ykj2Cqpx3wgh0cAxw==@lfdr.de
X-Gm-Message-State: AOJu0YyomxOroh4rtZMvSEaBeUCQB1x0Q09AsJsj753k/WEqgeZdtUl7
	24VGdz+9EqY/T/8aF4tQ6zmDnDFfR+C1mBwR2M+xbPG/oz3y3d0oaf5Q
X-Google-Smtp-Source: AGHT+IGn129oXCz4OjvLZNiOcgnylHuy16cTXK6ufEx2GSi6/6NQ/VpPd0p12tMUu0UKmRufJ35l3g==
X-Received: by 2002:a05:6902:2a8e:b0:e98:9975:6f0d with SMTP id 3f1490d57ef6-e9899757d51mr1539301276.36.1756468768418;
        Fri, 29 Aug 2025 04:59:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdyneeiUZeCbpv/xnSAY8AVSEK+EnUhwEj/z9U+35w5Nw==
Received: by 2002:a25:aa26:0:b0:e96:f782:76e2 with SMTP id 3f1490d57ef6-e9700f1c3c6ls1704834276.2.-pod-prod-08-us;
 Fri, 29 Aug 2025 04:59:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWb2hPSJWq9HU0AMPb9wCBd9Ks83fq1i6Nj5cPmlfu0gBW4krDhcDa541tq7wkK2CnOWpA1YPj1uv4=@googlegroups.com
X-Received: by 2002:a05:690c:4886:b0:71f:d94a:3feb with SMTP id 00721157ae682-71fdc339daemr318421877b3.24.1756468767539;
        Fri, 29 Aug 2025 04:59:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756468767; cv=none;
        d=google.com; s=arc-20240605;
        b=JB1SDKQAyAKNVyFOOsNw56uMq9lpEBAcpOVglJk+e6DOjl/REOtCX0A18h4lwzIuv8
         XzwT5t2hrUG/l9y9Dy9v69NQAMRgEI1dJmEOvo5zOuJjmxEQaysDEIu0TNMWX5mt2Jbo
         KRjH3Q2dHx46fEwgbuMJgZbNE3EPPbBOEHyooSFNPdjJkIz4JCajcUQz1SjbocfPHIIG
         HIZNnN9eDjuJ6aUscXQ+SWg1lBEGgnBpC4VIIp9fmN/fb0viMtxRf8rkhZreYHOQ106B
         dMI7Sl4hoa730Z1fytbn4PeWzZyyc2SXdVvdijLc7Ql7W8W0hptP5iY7MYBCOYsa2E4u
         x4KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=bF6XoHD5pMX2I9dADLrcLi6kiYTvPDGveY8Ow/uEvrs=;
        fh=HJQsg1q9fGLXGXaB255KUEp6DgVRTJfgELF7jStJyIg=;
        b=DLabqglXmJ+ejGLB7ae2YRDmeUTjE5OsXyJvaPCPwXAgZIUPXanjj1h75DTKKrUTpj
         qm/hAJWQ+cXyyjC20V26xqOP89uoh3+KACfM0JoGy2cUiEygw8PSMCyBmXdQtlWj/RmD
         ULAfyVTjBvSMSjfQF4wQGNAnAcsLqBiSnl5S73eD7yGGplp38qyITM/ADgexJ1W9lhSe
         OxcJDtYqMdZ5vWNAzP4OBkWzsop5M9IvUxUXpIiZSiB9S5SkI7yUt9MIyKFV0Rn5DtYr
         Phy/f94fSvlqtVYUDHMqhEtHc7dSnxF4p48QWNJBGk3QXTQ/VoVm/UJq3nTCKF+BLBsO
         OTJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=i3QdRllr;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-721ce49c4c3si872667b3.2.2025.08.29.04.59.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 04:59:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com
 [209.85.221.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-433-SbJ__1D0NKOYn6RjjcbDrA-1; Fri, 29 Aug 2025 07:59:23 -0400
X-MC-Unique: SbJ__1D0NKOYn6RjjcbDrA-1
X-Mimecast-MFC-AGG-ID: SbJ__1D0NKOYn6RjjcbDrA_1756468763
Received: by mail-wr1-f70.google.com with SMTP id ffacd0b85a97d-3ce7f782622so693066f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 04:59:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXmJXXJLcncgleQqMsqChLWGrsls+fIWDhcgmnHx+ZvHiF1XAtdvyAYSol4HE776QqId+M0LKdM4GY=@googlegroups.com
X-Gm-Gg: ASbGncvqDrvSDRouVWA0oUqyqHupdnhLbnvpvbUkltsGL0OzqGCrahWttwSJ6R0cwbJ
	xWic95MkpK0hgEeZuzcnu2wSpCAK0Ucb9ZqqSCkbn00dMW5nkC7LSa/teHolYQR3H7060dbtDYJ
	qpXgETg6Yz+FfTAeB/2De6q6wzqDS8T53QVfesG2MXXacvPGDa+vC0oU9rEFFyS1KkA4uVNpsnB
	bwt30bFeVw6rqbfnltXQw9I817NhEKOWnlvhIIMhrtZAofUBR8zwDQGXu1aTBv8HrO48im19Jed
	qTzWzPT1Xj7SN3lurYNwM/Kra+xx9sQQ/798uNoVaXpWqYNC7sel7ue1x4VNFtYHtcx//rC1aaL
	YcVRyioGBBmo0oyu6rjjXOUCmn+FJ8D8h0D0xEVcp5nMH6SEC9r6LP+7URFJ0zgo=
X-Received: by 2002:a05:6000:200e:b0:3d0:820:6814 with SMTP id ffacd0b85a97d-3d008206caamr1378546f8f.30.1756468762704;
        Fri, 29 Aug 2025 04:59:22 -0700 (PDT)
X-Received: by 2002:a05:6000:200e:b0:3d0:820:6814 with SMTP id ffacd0b85a97d-3d008206caamr1378503f8f.30.1756468762265;
        Fri, 29 Aug 2025 04:59:22 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1d:100:4f8e:bb13:c3c7:f854? (p200300d82f1d01004f8ebb13c3c7f854.dip0.t-ipconnect.de. [2003:d8:2f1d:100:4f8e:bb13:c3c7:f854])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3d0c344f6casm2018873f8f.36.2025.08.29.04.59.19
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 04:59:21 -0700 (PDT)
Message-ID: <0dcef56e-0ae7-401b-9453-f6dc6a4dcebf@redhat.com>
Date: Fri, 29 Aug 2025 13:59:19 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 13/36] mm/hugetlb: cleanup
 hugetlb_folio_init_tail_vmemmap()
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
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
 linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
 Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>,
 Mike Rapoport <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
 Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
 Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-14-david@redhat.com>
 <cebd5356-0fc6-40aa-9bc6-a3a5ffe918f8@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <cebd5356-0fc6-40aa-9bc6-a3a5ffe918f8@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: EGjECrBxe3LzZp0itN4ZAuXCRbWo_pJJV3pmEqyUspE_1756468763
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=i3QdRllr;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 28.08.25 17:37, Lorenzo Stoakes wrote:
> On Thu, Aug 28, 2025 at 12:01:17AM +0200, David Hildenbrand wrote:
>> We can now safely iterate over all pages in a folio, so no need for the
>> pfn_to_page().
>>
>> Also, as we already force the refcount in __init_single_page() to 1,
> 
> Mega huge nit (ignore if you want), but maybe worth saying 'via
> init_page_count()'.

Will add, thanks!

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0dcef56e-0ae7-401b-9453-f6dc6a4dcebf%40redhat.com.
