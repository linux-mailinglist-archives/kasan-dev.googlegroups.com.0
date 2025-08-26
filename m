Return-Path: <kasan-dev+bncBC32535MUICBBQPDW3CQMGQE435WXKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D3DDB36145
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 15:08:19 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-30cceaaa4c5sf1465272fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 06:08:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756213698; cv=pass;
        d=google.com; s=arc-20240605;
        b=YdD9jZDu+SgFQaybN3hiyQOpMUiH6b9sm4YHgx6/lSpNwg4u88hSGtBoxRTTkk3N/b
         OrWwHuHlH+3e7xAYc9iPimU+8GnUCQP/tKkCGpmfRNCNlkS4uCpMaz+DGt37XRN3BChu
         kwfpaSv9oLSdSRylOOr5VV6M5k4a1Hj/rrBHy2QJ8NxKqANjdapLHWpaLpJ9iG3VJ+e1
         9Vwt8Vs4yKAi7b5pAJeRMpTuqwAAxnJGbtHqivWj89jDEu4TloaVIZruCQVSvTNqCfoC
         BFUwyIehJZvw3stlQLix/tqcH/6ekoxIIhYoj+M5k52yc4vQimEqkyl0FiT14/a9DU0Y
         dYPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=mtYukGPNzlIo4ku/rFXZFS0PWaVlcb0BvSGa/WMQmW0=;
        fh=dN3wp/c1Qx+guBe70CDegDov2zwQB8/zTNXWoafhHWk=;
        b=ZQLEaGphoYrsAXpu7jnhvD77RAPNMOlAwTVhGjHyEYxsFqmmEfEXT7sGSejwHViMfB
         gZn3KT53SXP4Bgp//O1P6TQVxGk62inSu4dfh/owjRoQkV5FBJnE0abBXf9PO8AT6wIv
         4JQN7j1e7w+1gmQjrJIIeBIZRLu8JTe4cbbz0Ezk6OZyiN7OmR1e+3LO69/DjAHWXTqW
         94hAe9fC5oegAjQj1NuZWEPv/Cps8g29IuRnzObT5bVKhDL8qsMwnve/IcU+DrnyzsS1
         1+bO4Ovvupf8pUB9hhTENfENpodOfrh9teHhHi12fIkU6mGvYHu4TAjkko/hjB+iZjMx
         EPVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=EqPZWql6;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756213698; x=1756818498; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=mtYukGPNzlIo4ku/rFXZFS0PWaVlcb0BvSGa/WMQmW0=;
        b=aJNJtlEKLTZDHqOwDRkGrtdIwWeb64oJ3+OGdkx6LNLUdjPCal/k8E9wcELfZ0WLnZ
         oc/MgE427j1m3zCBHipW9VGI9ocZrdLfgMuKeU7t+aqEsPZmcK4MB27PGc/R/AM6i6Xn
         1ArjLxnxbeoGyXFdM7jFmffKXvoL4bzS7+G+PiocSLdkrWiOIQ10prgo3a/o4gWmO9r9
         XibZMoMnFnccAq3NS1kUUqP2hkP8z47OaV6rWYmgQiEUxUBP1cbHn+TtT0ZqKyPonPez
         wQq0GLCOllqNpsWQewlSMJbpm8wIsWNvLxIygMzN39wE0/DQGKtcUnbXEtnhdS4EhRQy
         SyTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756213698; x=1756818498;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=mtYukGPNzlIo4ku/rFXZFS0PWaVlcb0BvSGa/WMQmW0=;
        b=KNmE9eFbfDzhc8DaNyXnoJVKjpAyKY8ji4Nfp13/3Sp7Knh6KTXTkk8krQ9lAPlTR+
         AazETQermbwJIouNMwlXdmyHyBbwZ+8vwmC8xWHD6Yh6URUK5cGlAE1WHlyZUXGeOX0Z
         a8Rm/IJCDb15ZbXfo9j4dmRI7CMX2y+TwL4rnB9/87ZctbSBTt1DCBHbEY1XsRPYJoxs
         H8CgW9XyH5xR6OkABze2IRwBkguHQaRG5DpN64+KEKHHeAH02s00vKnbGbAT54druJNX
         CmMeE21T8bdR8uP7oRAJ2t413sFmZuft5KJ/+9jO0R1jANTSznQsgSehzBQWY3RoK6LL
         cHpg==
X-Forwarded-Encrypted: i=2; AJvYcCXvn2swm52N/6Rb5RbsQDOp63jxlg6ZS1m+DHenvMV2wXyjzj4pJuPxwvvUzZyTDVv+LmdwcQ==@lfdr.de
X-Gm-Message-State: AOJu0YyyJ9/7DV1yylvXS6hCl3oP+A6VQuUuL4zaW6eDbke5a3QaHZe9
	l2nb0rZ6bm3qFnj/JIF+AkOeRNzeEQXsUIHyW7eOR7vQPm50qozZTKy5
X-Google-Smtp-Source: AGHT+IGgHnkmyBRvwf4vJ4cHxn2KNzeVP3UyULbtZpE0URbfKnxFovIqw9tjQIP4psk3eEDJr4aMcg==
X-Received: by 2002:a05:6870:d918:b0:2c2:4e19:1cdf with SMTP id 586e51a60fabf-314dcd1791bmr8041941fac.25.1756213697843;
        Tue, 26 Aug 2025 06:08:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf05uDjK7MInVm9k0x+wT18psOwbDhgq8/psoLKgUivcg==
Received: by 2002:a05:6871:a312:b0:2ef:17ae:f2b0 with SMTP id
 586e51a60fabf-314c1d850c7ls1147113fac.0.-pod-prod-06-us; Tue, 26 Aug 2025
 06:08:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUSavfqYF207XSxNdJB39uTSCkrNEHNYBS/nhLBYUC1aiDfqj7WeoDTQB2e/m/5VDd9/JhL5HmzdlI=@googlegroups.com
X-Received: by 2002:a05:6870:cb83:b0:314:b6a6:686b with SMTP id 586e51a60fabf-314dce1441amr7662826fac.45.1756213695982;
        Tue, 26 Aug 2025 06:08:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756213695; cv=none;
        d=google.com; s=arc-20240605;
        b=aHAx/cQnkxL49OJbpJq7wXTmgMNKXS8KjkDqzI3qeg/MLVF9mSagwcpbtJSR/+Zfup
         BQIgvdTg2q2FAyQPWZ8JefSBENIAuIz3JfqHBg9M3h5C+zyslKB3Q4L/TYG+41rkd5Qg
         cHA7IFt1O+13mEIXHnPVruxGwIBP2ahMyJ2a0x+aktT4kUYzAj0pPpep/5RqN/egzYGw
         PAbwQxQ8JPwKUiInVLHOn0H5y83Lbd/OaWw5J6NxovdaDPMvuNXXisREPj5fXEx/lEjw
         Cq5UI8cDdA1Tpxc/JnCR1gnYkg9ZNZLhtNDyjbhptzDOWqW3SWHgZSf+pzSileJDUuyj
         YL4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=+33Ue2Cu5Y5oxJByCwLn3TsnRWViKb51w/F+XvIasfg=;
        fh=boUZ4M3qyXMR3OzSjxvP8KyqntNXmE2x6ocHVLj1a50=;
        b=fR+TIPD3dzMc2F9fCRr2Ds/fOLxZnz+3tLQtwZ9MS9wLaKz9xDpBmZzzRRe3OKZRbQ
         wxeqJRG3YefypfpIJcujTBXCBl95ad73+xU9f/qgUaEBCEk4MaWsBjS0MsQCdD9ZNn2+
         hBh+Oh+FGvhNCJMasg1VIWeU0CY+hNYDY4WvpJEfRjmJWiD6Elufv9NYn/tiIxJD79Q4
         48YLYVrLJqlBa7IhVrVMIk+gX0xrhxk4QaToI+x/q3V/nYxEtKN4MljnFl7ZtQHBraxO
         YsJZJjwyaqxTbxqkf6rRTllou1NKtq3bSyvVBDlmIT1C/VJvP9KCAswIC+HnaiwMlG1v
         N86Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=EqPZWql6;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-314f7bc3b10si392059fac.3.2025.08.26.06.08.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Aug 2025 06:08:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-580-DwE5UgOGPYKW73Lc5iEM5A-1; Tue, 26 Aug 2025 09:08:14 -0400
X-MC-Unique: DwE5UgOGPYKW73Lc5iEM5A-1
X-Mimecast-MFC-AGG-ID: DwE5UgOGPYKW73Lc5iEM5A_1756213693
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-45a1b0b2b5cso40595065e9.2
        for <kasan-dev@googlegroups.com>; Tue, 26 Aug 2025 06:08:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWE21eU8qIshOwojyrVLcVhywO+FziG9TQseKssmXfs/VnFz7Zq1rCKFwGNPi3vkywei4fKHakC/Uw=@googlegroups.com
X-Gm-Gg: ASbGncvgWc1YEl88y5kk0RugB4sPIC/fkU2mYtLfM3UfixEmouKhdEvnfT36rXFRKVi
	yxDtyLFrNcceKSVPABZz7ZWqqNUkFPFck9eubGbbv0yR5jJ4K7PKVUFAnSX+rYY/SH5LVA5edZ9
	kemTQJbiXWEIzt1N24zenFLIIG2Xg9jmDnkLt9FDXMerKINFX7RJRLtTROeazwoB4YNiGe53eZH
	yTodyGGpl1JGggEKWQza4V53LrlafpOpZlKqKv7dDo/wS98vyZThsBIQXgamkNo77Y2EQoySvcm
	b+tyWSfUbnqlhFrv6U/8/2nWOYMOICDhHm2MPi/EWWZ0/Sz/5o6a5aFRpWxZyKlZZ7fBtf1xRA=
	=
X-Received: by 2002:a05:600c:19cb:b0:458:6733:fb5c with SMTP id 5b1f17b1804b1-45b517d2751mr126239415e9.28.1756213692632;
        Tue, 26 Aug 2025 06:08:12 -0700 (PDT)
X-Received: by 2002:a05:600c:19cb:b0:458:6733:fb5c with SMTP id 5b1f17b1804b1-45b517d2751mr126238015e9.28.1756213691060;
        Tue, 26 Aug 2025 06:08:11 -0700 (PDT)
Received: from ?IPV6:2a09:80c0:192:0:5dac:bf3d:c41:c3e7? ([2a09:80c0:192:0:5dac:bf3d:c41:c3e7])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b57444963sm165603375e9.3.2025.08.26.06.08.09
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 06:08:10 -0700 (PDT)
Message-ID: <ecc599ee-4175-4356-ab66-1d76a75f44f7@redhat.com>
Date: Tue, 26 Aug 2025 15:08:08 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 21/35] mm/cma: refuse handing out non-contiguous page
 ranges
To: Alexandru Elisei <alexandru.elisei@arm.com>
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
 <20250821200701.1329277-22-david@redhat.com> <aK2QZnzS1ErHK5tP@raptor>
 <ad521f4f-47aa-4728-916f-3704bf01f770@redhat.com> <aK2wlGYvCaFQXzBm@raptor>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <aK2wlGYvCaFQXzBm@raptor>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: H2_50mnTUU8BmDSFMj_1TgiaXN03qfX2k9ckNLAA0r8_1756213693
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=EqPZWql6;
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

On 26.08.25 15:03, Alexandru Elisei wrote:
> Hi David,
> 
> On Tue, Aug 26, 2025 at 01:04:33PM +0200, David Hildenbrand wrote:
> ..
>>> Just so I can better understand the problem being fixed, I guess you can have
>>> two consecutive pfns with non-consecutive associated struct page if you have two
>>> adjacent memory sections spanning the same physical memory region, is that
>>> correct?
>>
>> Exactly. Essentially on SPARSEMEM without SPARSEMEM_VMEMMAP it is not
>> guaranteed that
>>
>> 	pfn_to_page(pfn + 1) == pfn_to_page(pfn) + 1
>>
>> when we cross memory section boundaries.
>>
>> It can be the case for early boot memory if we allocated consecutive areas
>> from memblock when allocating the memmap (struct pages) per memory section,
>> but it's not guaranteed.
> 
> Thank you for the explanation, but I'm a bit confused by the last paragraph. I
> think what you're saying is that we can also have the reverse problem, where
> consecutive struct page * represent non-consecutive pfns, because memmap
> allocations happened to return consecutive virtual addresses, is that right?

Exactly, that's something we have to deal with elsewhere [1]. For this 
code, it's not a problem because we always allocate a contiguous PFN range.

> 
> If that's correct, I don't think that's the case for CMA, which deals out
> contiguous physical memory. Or were you just trying to explain the other side of
> the problem, and I'm just overthinking it?

The latter :)

[1] https://lkml.kernel.org/r/20250814064714.56485-2-lizhe.67@bytedance.com

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ecc599ee-4175-4356-ab66-1d76a75f44f7%40redhat.com.
