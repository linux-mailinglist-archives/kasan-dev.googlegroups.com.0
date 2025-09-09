Return-Path: <kasan-dev+bncBC32535MUICBBLXT77CQMGQERZQJSJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id D465EB4A8EF
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 11:55:59 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-72e83eb8cafsf85438636d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 02:55:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757411758; cv=pass;
        d=google.com; s=arc-20240605;
        b=KniiODh/30FuD9y6AuwPmWSQmzMOUgWTl/LKzlzjwC9+6ln/uDjN1JzYUdmyocTBcu
         z8iqa7REBWD8rLyolOcwoYoZMWBNTdrHa/vWvxlNr562KNGTiXO9iIaMAlU6P7GXB+s9
         uAci6ZkHaxqboUyNVj42dpwTlv8bBGxtHV0a+lmwpwSApSWS/FEnzvT2RSUYJbDy5b0/
         W7OMVm8Iignsv2qWtBSZtXKyarRrrtoIZA50EJmqFB+wUALLT0ySCCqE6VGNNhpKGShF
         w9jR8CKj/YjlUMVysqiAX1wsomoy/C2XX+VwmReNkk4oTMCvAWGYKpbJDFGuriyTmSkt
         ojKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=b7U+myKTgxVV1Br9oKe0kGH8VmCMdjEELHizQWPIRoo=;
        fh=JrEh7BIRyPoPLiNkieZ7PbQ1Mla1Qo9TMYN3U7l2Sls=;
        b=CcoBUh54Yr2dR9jlV3pyQ5PhZMhWcJ3u5im0M4okyJm8jU3rWqaKavz5h1IxV47WfJ
         mZ/JdnrqTipXWQZhU8SAIgDfpnXL9OfY7XSqXyyO4y8MGleV1ibHMLiaQ8DbxRfBrWFT
         migHa4ggpKZ22aBT1ZaMMpjfO60VxkbTey7UfsEvqv4xnW7xrloMsaJhlV1dZiPfI9Ga
         4J5sFrB9Qt+kFRT55Vr6FZs3FYfHSzIZcgB8+ck0VYNdYEIPTx6aiHegUvZ16ZXr+deq
         0bdRNMS8UHAeKd2DzsQpSNPglhNl/Xsd9XTLSD6tKhOWL11mWxe3+bmiIFxz7uze0h7M
         tjzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=he7uv1AN;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757411758; x=1758016558; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=b7U+myKTgxVV1Br9oKe0kGH8VmCMdjEELHizQWPIRoo=;
        b=ChKJgNb5aJeKaNrY6zIUykErc488PfTFkZlMmiGLjUdA2uqQIRMnGrpKlusNka+FSg
         I1GaER41yKd3AKzK3vaE95Zm+Q80cV6TKr1amXJpQdfiwpUpn4PPKuwRXxTzsXLQKovq
         404z6rV7YHD9e7bLXb/QCsDb9a5IKRHzpDa/EQcHxztsiO/jhHnQOMRGk8kM6LsTsnPl
         SGuYl6gMO2G82M81E0YY8XTJrljpVp0xxJfHSqMLJzQY8BeF1UTkR/qt8xSmh9DD+TM9
         WW+vKSeNi+/S4khcOA2QE7LD43aI8We/0HH8uJvZ5Gi4aVuK4gZKTIT5CXTPOFnDyyWn
         QK/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757411758; x=1758016558;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=b7U+myKTgxVV1Br9oKe0kGH8VmCMdjEELHizQWPIRoo=;
        b=QOuY+jNYC3TB5fBqT3q4QX/TaXz0zNatx2Ccu5QdLNjvgYnYSIGaiReYvYsqyR1RYf
         5+lm9oaREuoqF/FS9mIfqVddOxl2PezmpIaCzLQRZ2UI9ot04/C0bcChO1x0Qj2tk48f
         ple+dp+q0STp9GnOe+rTgYbthLIT5qVvboo/gTPc/qzJhXh3lSVRgVanyHPB/zdp8uWU
         k8BwZEbarQ0flF1IObMENl1ik7u1L4R6AvIhHggKAjdWbpmyTrX/c//XHLft0w9bXmt8
         ojZpJ99jjqmqmm5cromrRQVoGtMi2TLRWiL5iPLjOiFN9Cx/KSjQRQS2ovoveJ1sVJGZ
         eyrw==
X-Forwarded-Encrypted: i=2; AJvYcCXyav3SoCmJMIkqODLyZiR95ST2vmEc4EajgeiDB3k6YxKMGiarsQfvUZ3ZPJncU96yFrPVGQ==@lfdr.de
X-Gm-Message-State: AOJu0YzM4vN7tHRzQ0QlMh47S8mACTQKynQQqnbAczizqHdto3G8MRb5
	J3oRoc8e+0kpt4QPgf4UKQqwNAcKg14X8+Hlcwm8y18ePIBeDxE4/uZ0
X-Google-Smtp-Source: AGHT+IFMbtGkM7T4V9r6CiUGqX4+OUsQ8u0//ouGFziFczybQEEQMahG/unrOGo24LPkV8cG57dFFA==
X-Received: by 2002:a05:6214:5085:b0:725:7870:6d2a with SMTP id 6a1803df08f44-739256bd41emr137707396d6.25.1757411758638;
        Tue, 09 Sep 2025 02:55:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd75O1y7PMBPUbO7VNv6BVK39enN9ZRldP58brwNvD6iuA==
Received: by 2002:a05:6214:c4b:b0:725:7cef:3097 with SMTP id
 6a1803df08f44-72d1a69be1els56253246d6.0.-pod-prod-03-us; Tue, 09 Sep 2025
 02:55:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXEyQxgEFBAa6yZjoBKrvCIqaLSQRtrKERzmCFju/6Fgo8gHo83ljKCTF7i0foLx/+ve1cfoB3rVI4=@googlegroups.com
X-Received: by 2002:ad4:5d47:0:b0:70d:6de2:50d3 with SMTP id 6a1803df08f44-739435c5a4bmr101157996d6.64.1757411757599;
        Tue, 09 Sep 2025 02:55:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757411757; cv=none;
        d=google.com; s=arc-20240605;
        b=CduGAXuztaIv6FPRqV37ZydTXPzwf+fjZhlZV+uGy7nlMKX9cejIYN8xEzzHsxnkUB
         qwhzQFMkcRdxXGKwV/joV52aIK6pgSpAkSEE0SY5rOccskh2qQjRm8vjoE0A6L6Z4YlO
         9B7M61iOt9u9tSGc1HBFEfm7geHSt6Rwh1mjWMayz0ilab7N+pCLWiXPBIKbWHq6sYCj
         Uz0skLcnfXlEI2dIYYOb3HMh91+jkBCGe/ASVsQieBMZFa5fMYyhb3J3DsdHXoS5KGWF
         NS/EtbNqklz5lx8z/v6xw8YVcCoLb+HCnyQ2kumzv1cCz9hahq4DxYHJoVhc/ssJF2+2
         SkOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=uuhn5XZ+k/yXfBkz6uI/EJtHiraKm76UcsqU/6SM9xI=;
        fh=4GgNF2DPw3opT5UV1L2KNijskcARaNvx0rAxN9NWO4Q=;
        b=cZaqnut5bfVFJGhtCKzKDb/n5r9dGT5Gagu5gzWVzBZML8deZiA4wJJbf2WGMNH7ry
         yaqEUq5jeQzbCFf0XTmUrkBmN5Bo0hZij11Ax0qinxT7fEOrQE4CYetsIGjaN6zdAQjd
         etd6Oi2I/MQcFpPGoVMtKyu84Sz06x/x4EY84KQb05uctUYVwayksnpJi9M/01iChgwz
         hJdeFN+rGXTKBo1Wyz+OGGj59xzDYDvGbQRt1BECn6dMZMLd3uRIO0CUC6rzqPycPTr3
         ZuqK/nTqovJbWYkqLd9etK2t/iLIDXYTtNWiB/JiJV/IQygY91grdUwrUi24GJorx71M
         LEsA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=he7uv1AN;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-75917af7feasi269236d6.7.2025.09.09.02.55.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 02:55:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-497-PegxNMAEP8qWAIX9Z1RbiA-1; Tue, 09 Sep 2025 05:55:55 -0400
X-MC-Unique: PegxNMAEP8qWAIX9Z1RbiA-1
X-Mimecast-MFC-AGG-ID: PegxNMAEP8qWAIX9Z1RbiA_1757411755
Received: by mail-wm1-f69.google.com with SMTP id 5b1f17b1804b1-45cb6d8f42bso52021515e9.2
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 02:55:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVCzJY7dxjD8pcnv67DPadxUR77m5MdCgLtd96Jdxeakg3RUq8AiGEpaU3ZQVefFmJjwma5Z9/1UUc=@googlegroups.com
X-Gm-Gg: ASbGncszDnZvCma24ejCOChEO/VX4qLkV3gM/LnW6u+mQ1GRelurdIbsrGutsFP2xLh
	qVX/Dt5hZLm+s3agycE/ZkEwxhJvBKIXW0ICt3UuLaJDwa+NwMSRMoe+z7IDBbRGYfckzzrtKxH
	g/Of501kf6JtqZ6BQxjBKuRlypIlKSEeHeT6iZUY0CDbJY0RFjrS7iRlJjcoCxS2oT0i7AAu7WU
	TFhqxJ+3xkrV4wO6QrCioc4PdaUlrP9/e6GcD8hiVhjNeRyMolEqBQRGhJOnO+xst+ab5QjAz1F
	IH6rtAtcIVl+X/g4GLfEFO2HaNL/aUNZOSrl1tSVFfu+GbqO4vVSnk/saoCOs9K23OH5zEBpsT0
	EnhebACAhiQ9x5275LIl25c67nQ+O3n8GTTUvKdkMnvQaiwUT+sR+qjh1nHk06T3IoIQ=
X-Received: by 2002:a05:600c:3510:b0:45b:8366:2a1a with SMTP id 5b1f17b1804b1-45ddde829ebmr106120355e9.11.1757411754436;
        Tue, 09 Sep 2025 02:55:54 -0700 (PDT)
X-Received: by 2002:a05:600c:3510:b0:45b:8366:2a1a with SMTP id 5b1f17b1804b1-45ddde829ebmr106119935e9.11.1757411753943;
        Tue, 09 Sep 2025 02:55:53 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f23:9c00:d1f6:f7fe:8f14:7e34? (p200300d82f239c00d1f6f7fe8f147e34.dip0.t-ipconnect.de. [2003:d8:2f23:9c00:d1f6:f7fe:8f14:7e34])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45dd296ed51sm228257165e9.3.2025.09.09.02.55.51
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 02:55:53 -0700 (PDT)
Message-ID: <6ec933b1-b3f7-41c0-95d8-e518bb87375e@redhat.com>
Date: Tue, 9 Sep 2025 11:55:51 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 22/37] mm/cma: refuse handing out non-contiguous page
 ranges
To: linux-kernel@vger.kernel.org, Andrew Morton <akpm@linuxfoundation.org>
Cc: Alexandru Elisei <alexandru.elisei@arm.com>,
 Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Alexander Potapenko <glider@google.com>,
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
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-23-david@redhat.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <20250901150359.867252-23-david@redhat.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: -avQGZMxBVq-bYhdjune11ozmH8GQbxSUBTKhN81vFI_1757411755
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=he7uv1AN;
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

On 01.09.25 17:03, David Hildenbrand wrote:
> Let's disallow handing out PFN ranges with non-contiguous pages, so we
> can remove the nth-page usage in __cma_alloc(), and so any callers don't
> have to worry about that either when wanting to blindly iterate pages.
> 
> This is really only a problem in configs with SPARSEMEM but without
> SPARSEMEM_VMEMMAP, and only when we would cross memory sections in some
> cases.
> 
> Will this cause harm? Probably not, because it's mostly 32bit that does
> not support SPARSEMEM_VMEMMAP. If this ever becomes a problem we could
> look into allocating the memmap for the memory sections spanned by a
> single CMA region in one go from memblock.
> 
> Reviewed-by: Alexandru Elisei <alexandru.elisei@arm.com>
> Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---

@Andrew, the following fixup on top. I'm still cross-compiling it, but
at the time you read this mail my cross compiles should have been done.


 From cbfa2763e1820b917ce3430f45e5f3a55eb2970f Mon Sep 17 00:00:00 2001
From: David Hildenbrand <david@redhat.com>
Date: Tue, 9 Sep 2025 05:50:13 -0400
Subject: [PATCH] fixup: mm/cma: refuse handing out non-contiguous page ranges

Apparently we can have NUMMU configs with SPARSEMEM enabled.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
  mm/util.c | 2 +-
  1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/util.c b/mm/util.c
index 248f877f629b6..6c1d64ed02211 100644
--- a/mm/util.c
+++ b/mm/util.c
@@ -1306,6 +1306,7 @@ unsigned int folio_pte_batch(struct folio *folio, pte_t *ptep, pte_t pte,
  {
  	return folio_pte_batch_flags(folio, NULL, ptep, &pte, max_nr, 0);
  }
+#endif /* CONFIG_MMU */
  
  #if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
  /**
@@ -1342,4 +1343,3 @@ bool page_range_contiguous(const struct page *page, unsigned long nr_pages)
  }
  EXPORT_SYMBOL(page_range_contiguous);
  #endif
-#endif /* CONFIG_MMU */
-- 
2.50.1


-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6ec933b1-b3f7-41c0-95d8-e518bb87375e%40redhat.com.
