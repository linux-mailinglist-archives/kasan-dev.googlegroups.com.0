Return-Path: <kasan-dev+bncBC32535MUICBB4FMY3CQMGQEGRNVRCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 38C47B3BA82
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 14:00:50 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-70dd6d25609sf49267886d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 05:00:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756468849; cv=pass;
        d=google.com; s=arc-20240605;
        b=genqbW/LsWpCWHrnwmGDAVL74kiZyxMsZwowz+4Zc3wky6iqZFEHUZeVYX/0zZb0W3
         lZyOiQss72+d5vHy3j+BvoIIUTp8s1APYVJMRI0Czi3OyGgNq8/J/q02uD/FZVGZ5QPF
         l0639axhSZkPNlE047Waoquv907Mf5/Iz3itY5CRt8AOMPN9EIkLxoi0qxTZ75Fc4clS
         8629NKHMzX3jfX+bSNrI07HFbGcuXU/rRqBFUgoFjpzucczSrEZxIyzgXcDG+PAdwEOv
         l7qrRTOUxg/xLFdfRIYcAKb4gvjIExa8jOHrd6RHeIiFj09a2U/qG7mr323InKIa9K/v
         N6GQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=6lCEpK9ZQHxpCdMQSOJkrtCSKKlKaZTFjTO2xY5W7J4=;
        fh=e1P26UhqcM10PDO32uNcFsIi5BvsQrsYZpZYW75OXBM=;
        b=XkBgNqNuH4fxb5S3FpDSvTJ1c/Hk21ZRxQqx6+axZjTr4OSo72+DxsMCDfoC2Kwpc+
         YMAFlecOdC4aWOB/sdBi1C0wmgvm2yrU42UwLkANc/mvPZXW1kLkEUfOXxcmsQBptV/t
         FGS8so5W5EO3dOJ9Sxv9jcf9Xn6byTYStJbb6A1rq6/qkFR5BvnVZIaa76fu6/4dN/+1
         7ARi3vjzZVHCz6ppJYRALi89SU3ywBX4O2GXEVGfLRllH8uque6uzKraMBRFugDSBMgP
         LH/vkKlJUke3GkeCG4+xQnQbbm18lkC45RT4RUbCSnwP2IhQ6lBt3HJV7ChHqczaZ9KO
         z51A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=flnilzGt;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756468849; x=1757073649; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=6lCEpK9ZQHxpCdMQSOJkrtCSKKlKaZTFjTO2xY5W7J4=;
        b=j66aoafuieg9IKs3Jb+OtkcsJIj5AyBCtRj83weNR4M3gmHyjdLkKFcrSCTR9LMdSh
         Do7uWyv7/LPJqVrqf/5CyiLLK+TVb24pgaiXhJFj2TX2Iys6CdtCItDFN/pyNH9t1Zl6
         h3g4d+x67QgOksT/lJvy1xhiRUApoEN59OtNrk8Nz6cr3agloZ1F9J3E5vy2hcRU3MAU
         oFP5Z/8hNJO+QguMIJxpsonCspb+p6oSAFI/rWKFgnoR0bJbBcCk9/0cpVfa9DaK2u6t
         OOOqmv23CIWOP2HGqM5h8WdZxZhNOZyyqt38Qrh76Ocuqj3QACnIaiwDIpZXYOpVk3AL
         RK1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756468849; x=1757073649;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=6lCEpK9ZQHxpCdMQSOJkrtCSKKlKaZTFjTO2xY5W7J4=;
        b=Rbmh0kv3VnbRXtnCIXp2v/02C78eBZ+u88jwmHgOZntINi76hq29r/3LsPY6jV9aWM
         nIV74Pk4unBxZPSbt+zHyDVZCrZIYAHmlpPB3Qj1WySnNGuyfvJthIUOXfNI3AbvYMJN
         h+24Rjl6yrns6YYI36MDFBmDi5zWVlqs4SCDmLV2plbpV/nXywYDuQgoWnCF7o/FSXfO
         ckN11282aasKCkDuRie4ECYQYWFFQaljSwKn79TeTQXIK7O1dnw1hg+zU99HB/A/3uM7
         JSxMzs8q/1D1XQ6sq6ehqfv3b+w2Oo/V3fTeqaBgrkaA6J0Yt7ymOD3dER1wr/MwX1U8
         VafQ==
X-Forwarded-Encrypted: i=2; AJvYcCVFs1lm6IPo14H4EzFjeBG8PMEPBC239CKPNfQ3WV+T44cHL16h4HbJB/0REYhiwGAVAMC/ZQ==@lfdr.de
X-Gm-Message-State: AOJu0YwKQ+sZ4RN5vppyCS2msC8bwYGAIyTNDH45sNIv4GkiWL0tsd0I
	xxWnWivneKBYnemBxQ4ryYDshbnyIeZOIvwK4OBb2gUw/JZ4eH0hqsyS
X-Google-Smtp-Source: AGHT+IE5UdETD1hT5UPv2ZcpLAPxQI7zhvTpN+Z2SxWVIqT9ujdQgqaHwklqN2gUMB+snyAecgY5ZQ==
X-Received: by 2002:a05:6214:20e3:b0:70d:f74a:8f5b with SMTP id 6a1803df08f44-70df74a95f5mr55387106d6.20.1756468848736;
        Fri, 29 Aug 2025 05:00:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe/qRAeB8FJtEsuPuNjPiHw2rpzJ6xp46x9VKuxzXP3zw==
Received: by 2002:a05:6214:5091:b0:70d:9340:2d97 with SMTP id
 6a1803df08f44-70df0355992ls25082206d6.1.-pod-prod-03-us; Fri, 29 Aug 2025
 05:00:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUrAF5yJcORr9a5MKpsw3o5xRBajd/H1JyLZhx221Qeos5mlTdOJAyO6kkSQ/UJXpTp548/78ShD/M=@googlegroups.com
X-Received: by 2002:a05:6122:6112:b0:53f:7828:16c7 with SMTP id 71dfb90a1353d-53f78281ac6mr5899221e0c.15.1756468847034;
        Fri, 29 Aug 2025 05:00:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756468847; cv=none;
        d=google.com; s=arc-20240605;
        b=Iw9IJ49As55xl7gdY9FMfiVbqNEv0RXw1xSz962lDki8JvtdJeKR33NfV0+9e7jOJ+
         cbJ+Nsx5+GXu53jrQnAxoBMJCBH65Tl6nCcBoUm876rokBCGGfd6By95fDTHQST6uEi2
         D/rh7LoS5+DishO55zMe7yoH5g3+JXeqyCx2GRImJVW/1yUq4INUl/gebo2G5M5k1Jw4
         0JhhtLAMyl5r3wHto65zMpE2ClsFyQqkpvEG37P/nUNUtoTx5hlZrqnJYfr7/FlXjBBa
         G4+9bWWc27/kEH4OXjNrEWFcAHj2NR9sME6uYdVW3PJVBLRZq3hZGa0xY3FIMssQco6K
         /N/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=WRODc3MDTNqLHIXQzOQ9QRmb2QGRyzsJAWu0HJ+lHgE=;
        fh=3BNnNpp4VHKIz5kMjUuS0sEWLZwNaO/R40jkBx0F7TY=;
        b=YdHEYG2sx+e9xLlzMSn8xl4UCQJ9MfwtlxdJNguN9yovG/Q6dyTCFwPSO37JK9Z0OQ
         hLvXsYS0T9HXICH9RJoa/NfDm6b+ROgP5iEmoPrpiGeisaitJVSwHRz5T2qc+SMGLdbg
         AM8R5ZEFfo6/f1Uz+jh5kOXvRL8PuoaOut+Qw1VVvu6Hprkc37rn7NK4nxcls1O3Ni6Y
         gH6495Lr53ENZpzbVYYJ3hs+zEjb+Xe7bXvfzynDTLJghcvjjPe7nfZJkiypQk09Qn2a
         IXgTBXgMPqw6xLJf0cFHrO49bBkUh+IiL/i/JgIJfwwIDGRnZokkETUPQUB2RaauDC77
         GnbQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=flnilzGt;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-544912d3088si62252e0c.1.2025.08.29.05.00.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 05:00:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-392-Bho9coPGMMGwGtAfhtzM-w-1; Fri, 29 Aug 2025 08:00:44 -0400
X-MC-Unique: Bho9coPGMMGwGtAfhtzM-w-1
X-Mimecast-MFC-AGG-ID: Bho9coPGMMGwGtAfhtzM-w_1756468843
Received: by mail-wr1-f69.google.com with SMTP id ffacd0b85a97d-3ccfd9063a0so687587f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 05:00:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXUhAd/cp0890gEN2DMVj9ubmU1+JMSoeHmjlYQihPimN1lCShi9LNXDm+yOIEp1K3SndKO5A2EtZw=@googlegroups.com
X-Gm-Gg: ASbGncu2sUBGDaSSFTwyMxKI77FHzQVpZZNXZ/Xp57ztXH6/HQAhZNMOmY65xP3LKqm
	v4NscqFDzrfZgdf+Heg1fiF3AOujw+cm6PVcJAo0wjGsvrxDGwj/gd1WEgnlklOiJqdVyYTq6fY
	ZGfeNkMznypB5gCLqJOBUQREcMS60IctRcfrfKXSMVd8HTW4RguUV5cFeIBe9Hlf7RSd6krR4e/
	XdHrCVZ0A/86F987FnLaSqSGQNknz9OOCJBd7w1CGM0VtzY4UNn6kM1LxAk+qmB52Gq4v6zg+yp
	UNXbjXN/abS+MBScjmUvRR90jParZqYuQCsNiYpPCZO/97sQN+BVryymijSvH1FENemEMbezKi7
	Mzw2Na3L4rDOh2CA3kFR9uVIlRunw4wFPcWWQaowFYM3xhB6WQT3vc8dsb0QLS0c=
X-Received: by 2002:a05:6000:4382:b0:3c8:89e9:6ac0 with SMTP id ffacd0b85a97d-3c889e96e1dmr12052193f8f.3.1756468842727;
        Fri, 29 Aug 2025 05:00:42 -0700 (PDT)
X-Received: by 2002:a05:6000:4382:b0:3c8:89e9:6ac0 with SMTP id ffacd0b85a97d-3c889e96e1dmr12052085f8f.3.1756468841352;
        Fri, 29 Aug 2025 05:00:41 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1d:100:4f8e:bb13:c3c7:f854? (p200300d82f1d01004f8ebb13c3c7f854.dip0.t-ipconnect.de. [2003:d8:2f1d:100:4f8e:bb13:c3c7:f854])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cf270fc0a8sm3118235f8f.7.2025.08.29.05.00.38
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 05:00:39 -0700 (PDT)
Message-ID: <d0b06885-9f04-483f-a7e1-f197c8431491@redhat.com>
Date: Fri, 29 Aug 2025 14:00:37 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 13/36] mm/hugetlb: cleanup
 hugetlb_folio_init_tail_vmemmap()
To: Mike Rapoport <rppt@kernel.org>
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
 Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
 Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
 Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-14-david@redhat.com> <aLADXP89cp6hAq0q@kernel.org>
 <377449bd-3c06-4a09-8647-e41354e64b30@redhat.com>
 <aLAN7xS4WQsN6Hpm@kernel.org>
 <6880f125-803d-4eea-88ac-b67fdcc5995d@redhat.com>
 <aLAVUePBQuz9D89T@kernel.org>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <aLAVUePBQuz9D89T@kernel.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: TvEaVwiLaNSLsRFeW8NHR-0ufqn0yAqXNWI_z-cBArQ_1756468843
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=flnilzGt;
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

On 28.08.25 10:37, Mike Rapoport wrote:
> On Thu, Aug 28, 2025 at 10:18:23AM +0200, David Hildenbrand wrote:
>> On 28.08.25 10:06, Mike Rapoport wrote:
>>> On Thu, Aug 28, 2025 at 09:44:27AM +0200, David Hildenbrand wrote:
>>>> On 28.08.25 09:21, Mike Rapoport wrote:
>>>>> On Thu, Aug 28, 2025 at 12:01:17AM +0200, David Hildenbrand wrote:
>>>>>> +	/*
>>>>>> +	 * We mark all tail pages with memblock_reserved_mark_noinit(),
>>>>>> +	 * so these pages are completely uninitialized.
>>>>>
>>>>>                                 ^ not? ;-)
>>>>
>>>> Can you elaborate?
>>>
>>> Oh, sorry, I misread "uninitialized".
>>> Still, I'd phrase it as
>>>
>>> 	/*
>>> 	 * We marked all tail pages with memblock_reserved_mark_noinit(),
>>> 	 * so we must initialize them here.
>>> 	 */
>>
>> I prefer what I currently have, but thanks for the review.
> 
> No strong feelings, feel free to add
> 
> Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
> 

I now have

"As we marked all tail pages with memblock_reserved_mark_noinit(), we 
must initialize them ourselves here."

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d0b06885-9f04-483f-a7e1-f197c8431491%40redhat.com.
