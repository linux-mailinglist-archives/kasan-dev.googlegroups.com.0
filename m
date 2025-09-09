Return-Path: <kasan-dev+bncBC32535MUICBBRXF77CQMGQEPMERITA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A21CB4A7A6
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 11:26:32 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id 46e09a7af769-7438205f726sf8879694a34.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 02:26:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757409991; cv=pass;
        d=google.com; s=arc-20240605;
        b=cuXp1h0bsecjZXTbAtrqF0r0OaIpISSoa9Z/034QUP5dVjfX6Y9FK6keyyCbEOBTc4
         VnnkcxFL4JmEIB73FkCGRoAt6gg+frLUBoxO20WZ+JpjlQdV1OojUnWw5dqPnWOUsIoM
         Hjl2LhkLeb6HuFk/7q0KCkLCpV/N17/yvRFCrG3L3Ax+qPzCU9z2xSj8ShFnpjJgvXKw
         BqWOzvP7+zYI8BywWRyDy8S3PB3YKt2eh+Yf+W8suKd2i9zVs79YvLB2U/TNwER2pNBW
         nV8OQ06U/wFEU8mrrfNi6jAOEdNX7XOFJ/CFkstoN5YyaVmnvfsfXjVzoAPPF7Kuxc2k
         ZHOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=OC0Ruh1xNnXcI6lhi8ooyZe50pT7b/fVHPCsAY4UM94=;
        fh=Zp2Gkmes9A1hmA2GlHKhDe8SXH3HuWM2MzZsUFziCNM=;
        b=SlDfxdxpaU15XCtn138kWtIut/bQsk7nQ+4kLj+V8Mk+OMVa3Xi487R66Tx8WWx0S3
         I6CIrUjpdr7AY5f08qcw9fTFa61cxvKBfpuVt1Q7SOoBi2sYtMKE8hINshiQgDCan6by
         Pl0N6d57sNrnlMhD1BNC0/fdo0GubKbG4HNOp9Fe4DLT1cqHBvv/xFPeIapOL49M2vEw
         bT/dYXhANY/GTbZGjdPWbAXXzRjyrJQfvWZThvd+wmdQSvv56Edex7LGSunuPS/6W/n/
         H1rDHh660m+NKHzOkmtoaeTdjNxYlKEViTxVEnafuj8lTSgAfJcWAUnTmlpxdE1W6z9d
         HK0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DKcDy4ep;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757409991; x=1758014791; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=OC0Ruh1xNnXcI6lhi8ooyZe50pT7b/fVHPCsAY4UM94=;
        b=Qd32tfGZtpYyhaWKda1ulHpFvIrDBbX8K/BE7QJvRQrESOYj6V1CDSMIadibRBbHGz
         krpsK/ot1mfLfsuXtWAJm2C5y6dTwhiBrXXLGGQs5Fe7jUyO1r2Wt3SUS5ymARMtDVdv
         68pup5XoriJVMpwRyODlrelGUUtzVr+1Qz3H3puJyAaZz3jEdeQe1UD+FN/71nnsGt94
         1EbstFvcppf14xReVqDERPwAovfk8L+jfZ771+4r4IqgPJoVJoTvzFoHkmchZL2GwJSx
         ePXezSCwWeFl7eLu6vNOQ5KWwGR3cJX4PfU8fDfMnzxpA2yFr/cuPMOsLEFCgdgtolLv
         mezQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757409991; x=1758014791;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=OC0Ruh1xNnXcI6lhi8ooyZe50pT7b/fVHPCsAY4UM94=;
        b=ftJxUkHXQc8SkH/zGRzUHO0axVxxT9Nng/tVirhUeOvXhT77imMnRN/5NXs9UyNMPQ
         bUtUzd8yK7omm1//mafapqZYDcMJSSN0vpsT63fmvLD4/bxVhme840lsZfN0+MT4esqU
         9L/XOsIscOMNSEjOcv02dZXER5Zg1ogoMjYlff5MTi7A+G3VunTN2jA9nEpuuPLCSjpX
         lpJpBs7xHKE5BmEhyDNh8KDnW+8ICRjlertQb2dgdjD7AWw1+WeT9x2cz/XeOeNKnz0x
         f8Z4sjrvCULlnMHW5Z2fleTNGj9Eg+foddvuXztyh6Zfj50WPTi/mnXxLLRuRVXYbSnm
         p1mw==
X-Forwarded-Encrypted: i=2; AJvYcCV/vu32hw+vQz+OhaTXex14/hNX+jDBv/cgI72JoI6fD5sNJtPkOhzlqwUnM4MdwtUqxIFSvw==@lfdr.de
X-Gm-Message-State: AOJu0YxjUiXq3jj4Dx/rjblxT2qJM0lhPUBZS7/lFBYN9mN7aU9zs1A8
	b0PSZ75cUKUd0ruCTx3PxrV/M7UegK1OlP5NpHlDK4+bGqwIsrFQaJhe
X-Google-Smtp-Source: AGHT+IGtBNxFmAhj1Od1jeviuueM51vZWQ2K+7u4fNWrKARSeAHU7sb30lS7yYFGAKQOFD0dnb+G7w==
X-Received: by 2002:a05:6830:3914:b0:743:8af2:1af7 with SMTP id 46e09a7af769-74c7529f4a1mr4972553a34.23.1757409990863;
        Tue, 09 Sep 2025 02:26:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeffYNUbi1hq05pPoNOUFVV3xrW+JS2T90njR4YxSNDJg==
Received: by 2002:a05:6820:2acc:b0:621:767d:3486 with SMTP id
 006d021491bc7-621767d3bb8ls976847eaf.2.-pod-prod-05-us; Tue, 09 Sep 2025
 02:26:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUY0HQUe2Vw1dpiCtQEFDpRk2fSwPM9HimFdmlZu6P5g7VkUR+hcf2PSbMYBXu1D4j6pqDSnnk+dJg=@googlegroups.com
X-Received: by 2002:a05:6820:2289:b0:61f:f4fa:6d1 with SMTP id 006d021491bc7-62178a9cffcmr4402824eaf.8.1757409989777;
        Tue, 09 Sep 2025 02:26:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757409989; cv=none;
        d=google.com; s=arc-20240605;
        b=g7rrJRaZUOjzsTclL2DaGHqRF8MbARM2WK6uaWxqG2YMP4ngKsG5j2xHZg+C42TBw+
         ACDazopYuv2kqcYovOM73XFQ5I6IMt9CK6Z3RZrNfWQdNCaaW7vpJAE/uHWfLJJGdwvB
         xyZORKVoYFC8rxbrhIdPbmjU7+qLYtxlrUrZvryhiCBvkb4waGjsJbFUta70+w0f1afc
         MaCfYQn7HRKWcuop4fTvLp0dQi/UIZuLRZL8XLxw+s7pUtRHoeewAMkrKd8AMOlnmSvL
         W34RZJWKfcHx/vuHq8WXW1RNzUKC8W42ROsdeKFuqzk5ryJZvD5qESd4yFjbrQsG3RNl
         giNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=OurCkvo8cRfbGgLYwYff0XkxeLDF9OohYudpKg0Q2Mc=;
        fh=n8vLFgMqCwjjXpxQvHo+13KiejcU1Q0x/70ESTsx+GA=;
        b=erDlCa15oAJUipUsJEK+M2FZYgyE8ML8TYP6z7hRr6w5S42flXv/vA+uS63s445mXA
         D1ncNKdmzFAS3UF4aMVL5uEW8ZSXiDR+gCQyg22p3/IM0ZYvRw/agiJIyjQJ7x/+fWFQ
         ZGLOyDlmCYYz31v0BiBqKdjVXm+/piyAl2pYO6LiowQxe01Z5D1hNnqsnlZ9BFhoCFSG
         8dGbSVR83pa2MKuiZsuFcdzYLbnBQeh0YjgO0cyf2gMTdqWcxR3YA87S2k7SHZVzsbHv
         zrpgYh0lx+p2pLM1GcNbuiqXwI7uEsWvYcgziP4vI8qBqgxr1IrmL4zJ+tLYxvp72HeZ
         rk5Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DKcDy4ep;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-61e78fd172fsi92228eaf.1.2025.09.09.02.26.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 02:26:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-230-FunK6oNCNPWL5jqoIsKGkg-1; Tue, 09 Sep 2025 05:26:27 -0400
X-MC-Unique: FunK6oNCNPWL5jqoIsKGkg-1
X-Mimecast-MFC-AGG-ID: FunK6oNCNPWL5jqoIsKGkg_1757409987
Received: by mail-wr1-f69.google.com with SMTP id ffacd0b85a97d-3e2055ce8b7so1977211f8f.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 02:26:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUE11gYCfJ+QKXV9E+AOm40MiQeEJJjdRGz7AXu/uhDCPpOhy1cvgXwCuUKRuWpdHlXws6yhda5L5E=@googlegroups.com
X-Gm-Gg: ASbGncslFrUxRi+l0Ljr034DW/ESiLAttmfdrZUtEy3EhzwUp8k6S55H1dHTI0Kyjjd
	GYBY55HbneXU0qqojCMfoYWuQFbpOnrcl2R/KwNy3zG0RTGVUWmcBi4bxrFuQpWALwVrYkHQdx9
	dm53jsEoFzrX/VzDyU6r75BHxqRuEP2j0961NzHpd/ta5cZBYR2pciaU1soUNz92PdxLRn2eFrT
	THu/IPxF58WJbKHdRNcwRu8Sf1B41561NUbG9Kbbir3a77YxuprCeBPogHxT4G/r8Zui4SQphVx
	an44xh5gVSuCRyJn7Fs59hS1JlP3V5T+kJR6RkSZUPTYPsctROECRQWFGv16nyJhx4tcbq5x31U
	bcpPzWuwf+rbkwBC3qrRTA15RPbswsF6VGZKGFnWm3Kf7ptCfadQI3+iCShfx1E3VbH4=
X-Received: by 2002:a05:6000:2f81:b0:3c8:d236:26bd with SMTP id ffacd0b85a97d-3e63736f01fmr10702074f8f.11.1757409986542;
        Tue, 09 Sep 2025 02:26:26 -0700 (PDT)
X-Received: by 2002:a05:6000:2f81:b0:3c8:d236:26bd with SMTP id ffacd0b85a97d-3e63736f01fmr10701953f8f.11.1757409985314;
        Tue, 09 Sep 2025 02:26:25 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f23:9c00:d1f6:f7fe:8f14:7e34? (p200300d82f239c00d1f6f7fe8f147e34.dip0.t-ipconnect.de. [2003:d8:2f23:9c00:d1f6:f7fe:8f14:7e34])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3e752238832sm1808267f8f.31.2025.09.09.02.26.22
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 02:26:24 -0700 (PDT)
Message-ID: <e882bb41-f112-4ec3-a611-0b7fcf51d105@redhat.com>
Date: Tue, 9 Sep 2025 11:26:21 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 06/16] mm: introduce the f_op->mmap_complete, mmap_abort
 hooks
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
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
 <ea1a5ab9fff7330b69f0b97c123ec95308818c98.1757329751.git.lorenzo.stoakes@oracle.com>
 <ad69e837-b5c7-4e2d-a268-c63c9b4095cf@redhat.com>
 <c04357f9-795e-4a5d-b762-f140e3d413d8@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <c04357f9-795e-4a5d-b762-f140e3d413d8@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: oqlDxrv2faggadBJS6dgbyFyeUdB63BXnS4kFjk6m3o_1757409987
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=DKcDy4ep;
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

On 09.09.25 11:13, Lorenzo Stoakes wrote:
> On Mon, Sep 08, 2025 at 05:27:37PM +0200, David Hildenbrand wrote:
>> On 08.09.25 13:10, Lorenzo Stoakes wrote:
>>> We have introduced the f_op->mmap_prepare hook to allow for setting up a
>>> VMA far earlier in the process of mapping memory, reducing problematic
>>> error handling paths, but this does not provide what all
>>> drivers/filesystems need.
>>>
>>> In order to supply this, and to be able to move forward with removing
>>> f_op->mmap altogether, introduce f_op->mmap_complete.
>>>
>>> This hook is called once the VMA is fully mapped and everything is done,
>>> however with the mmap write lock and VMA write locks held.
>>>
>>> The hook is then provided with a fully initialised VMA which it can do what
>>> it needs with, though the mmap and VMA write locks must remain held
>>> throughout.
>>>
>>> It is not intended that the VMA be modified at this point, attempts to do
>>> so will end in tears.
>>>
>>> This allows for operations such as pre-population typically via a remap, or
>>> really anything that requires access to the VMA once initialised.
>>>
>>> In addition, a caller may need to take a lock in mmap_prepare, when it is
>>> possible to modify the VMA, and release it on mmap_complete. In order to
>>> handle errors which may arise between the two operations, f_op->mmap_abort
>>> is provided.
>>>
>>> This hook should be used to drop any lock and clean up anything before the
>>> VMA mapping operation is aborted. After this point the VMA will not be
>>> added to any mapping and will not exist.
>>>
>>> We also add a new mmap_context field to the vm_area_desc type which can be
>>> used to pass information pertinent to any locks which are held or any state
>>> which is required for mmap_complete, abort to operate correctly.
>>>
>>> We also update the compatibility layer for nested filesystems which
>>> currently still only specify an f_op->mmap() handler so that it correctly
>>> invokes f_op->mmap_complete as necessary (note that no error can occur
>>> between mmap_prepare and mmap_complete so mmap_abort will never be called
>>> in this case).
>>>
>>> Also update the VMA tests to account for the changes.
>>>
>>> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
>>> ---
>>>    include/linux/fs.h               |  4 ++
>>>    include/linux/mm_types.h         |  5 ++
>>>    mm/util.c                        | 18 +++++--
>>>    mm/vma.c                         | 82 ++++++++++++++++++++++++++++++--
>>>    tools/testing/vma/vma_internal.h | 31 ++++++++++--
>>>    5 files changed, 129 insertions(+), 11 deletions(-)
>>>
>>> diff --git a/include/linux/fs.h b/include/linux/fs.h
>>> index 594bd4d0521e..bb432924993a 100644
>>> --- a/include/linux/fs.h
>>> +++ b/include/linux/fs.h
>>> @@ -2195,6 +2195,10 @@ struct file_operations {
>>>    	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *,
>>>    				unsigned int poll_flags);
>>>    	int (*mmap_prepare)(struct vm_area_desc *);
>>> +	int (*mmap_complete)(struct file *, struct vm_area_struct *,
>>> +			     const void *context);
>>> +	void (*mmap_abort)(const struct file *, const void *vm_private_data,
>>> +			   const void *context);
>>
>> Do we have a description somewhere what these things do, when they are
>> called, and what a driver may be allowed to do with a VMA?
> 
> Yeah there's a doc patch that follows this.

Yeah, spotted that afterwards.

> 
>>
>> In particular, the mmap_complete() looks like another candidate for letting
>> a driver just go crazy on the vma? :)
> 
> Well there's only so much we can do. In an ideal world we'd treat VMAs as
> entirely internal data structures and pass some sort of opaque thing around, but
> we have to keep things real here :)

Right, we'd pass something around that cannot be easily abused (like 
modifying random vma flags in mmap_complete).

So I was wondering if most operations that driver would perform during 
the mmap_complete() could be be abstracted, and only those then be 
called with whatever opaque thing we return here.

But I have no feeling about what crazy things a driver might do. Just 
calling remap_pfn_range() would be easy, for example, and we could 
abstract that.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e882bb41-f112-4ec3-a611-0b7fcf51d105%40redhat.com.
