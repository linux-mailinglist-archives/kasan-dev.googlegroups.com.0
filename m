Return-Path: <kasan-dev+bncBC32535MUICBBAEST3CQMGQEZJYSCBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id BDDC5B30795
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 23:00:50 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-24457f42254sf31755015ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 14:00:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755810049; cv=pass;
        d=google.com; s=arc-20240605;
        b=WmkhWakgOVVNBSgWz/BCkWDFKbxlVOygYnUtmAgNSI/cUU7y99o7k2r6v0HC8jGrPx
         1tUmsTmUpWpvKYXhxxJaj2v4IndCFNWKsLaPD9ChVZiVNMjxYqodDa4gnVuZeLbG8pZI
         /mrD4x9z2mOjB2UEbXiL2z9XIz4diZL+6BL7hMRvr3fCCVgwRY/MpAzVM8fCaU9f/C31
         tNzafpS/KxivbHV2v1ftQMfVf1LdJQyZ2YVJ3470Z4yg1ZOEGfVeX2wFI4tCxRXOMmd+
         7qfS6XbWE3kc99fA4NHKVFPmyZHw7CmJk57qKe+6UL6XBM+JvgKbUA70LLGiU7pZo8ZM
         CMOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=Hk4iAIehjDp/S9fGdHJHxC31pufJ0D81e6mX/9R6Brs=;
        fh=eqepogYT7gZ+7ziKbBQUupxr6ZXI+zhCPPNUloqlp9g=;
        b=kASY8MvHNMSCW+hwMzjvLYhtZIFA/tTSza4dHIYAdrTPkd/SJQsoHWQQR/vnJwCt9e
         kqj2Ua1X9Q8yT0cix6ae9eJZwIBF0Z23iPGl7RlwB0dIhnta64MLZXApXGdArFFUhHrA
         ahkUJpdcehqPpQG0A2JLE0MwNxfYyT40mOHe7+TMRPHOp4aokPbvHDmVnxcDpSlLNSnP
         FBH8aM9jMGORNuh0mujQoUFa2URw8YDxTD9TW9aVsVY3KeRnUZMHD7xmKfMv7XbTivsh
         gNsaWcmDh58PlMSrK6pverCZDzOihOYScIZ/RY3J+Bh4jE2RhqjzJ8F55x4EOPMivlg3
         R6hA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=f0EYsgAI;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755810049; x=1756414849; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Hk4iAIehjDp/S9fGdHJHxC31pufJ0D81e6mX/9R6Brs=;
        b=Ra5yZ0262kjec829skuV9L/0HGZ3iiz1LrHxuY8oJtU4F1fqFzecBmBA+LW+Y30i7B
         ZoUxawPZzywn1vh7hGoLv/24ZP247TvwKQVrBPfd+oj3El8H2e8UVAWNU31db97qWlJU
         8fDI4CqiMkRonYUoZwoyD8TJdHcqUdGMmEd85JNb3oNXzD1kF6X6BV3DShARcCVTWUc3
         LdQiIzmh+ds5GIthr5cnm57z6MH3UwCQnR8LLCU1CiR4tO32hxWH/Pb2nyJxf8bJBL4Q
         SRpD2QPPux1bCDj5qkOwR4QTfjhxhvR1l/wEX2zPbkUSCJmYRGV/tBJ/BVwWsmwwv4D9
         5Oiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755810049; x=1756414849;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Hk4iAIehjDp/S9fGdHJHxC31pufJ0D81e6mX/9R6Brs=;
        b=wHbtZEO6eVjS2StlCHvraDbjePQbk2kg9CS8C0BsopZgHCr5sQlSpmOiVlHp2w6RDa
         dGiiuWvwhsVV0Qy4kgSf2nEMD+Dh38ShYfI0bqcCrEPui8U4RfVDYJ2O8koAJDyzzrsc
         k9YLQ45IozK6hqLtERw8KDNwiUHWo3rJQXohOTFl3j6Dl+9PHihd0B/jNr8SADWOUORV
         KpqXB4z5KB77ticzuvO5HMH2VdUcPyKWyEgfqpl9Do26/UmBHirmTxq0j/HS0QchXR+N
         6e8+Nj2sRXCmhX1NzUPnGKyHlDa+xPxvv/s5Akt/jSmJL+2UTTaY+qGPjxuTCnABO8MR
         m8Ww==
X-Forwarded-Encrypted: i=2; AJvYcCUSNeh7xmJmSIj+yH+J3XPwU3TcWyWa5RF/YFUabVieH8sdpK12Y+eYh4HXPtu9JLu3a8w6EA==@lfdr.de
X-Gm-Message-State: AOJu0YzttqaXeYDpR1viXV7XHNJGSE6cFezePfczosFULwv2Vn/sFNry
	tBbFsSCuh03F65i/OXrhQsTW85AZOhLvXyq5yXNDy1llFhrLuDailYJ3
X-Google-Smtp-Source: AGHT+IHC4RFDSkK7mvZZRmxCGkSe4yBy5ur2pL2NcgnuUPMLIbNGAjTeLtt4eFT1SacLje78zmmkZA==
X-Received: by 2002:a17:902:db0c:b0:244:6860:2f10 with SMTP id d9443c01a7336-2462edee7bdmr10088775ad.1.1755810049099;
        Thu, 21 Aug 2025 14:00:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfIZKbwp8TmZmmyVyEbkT9xS6wh9eS4jK5khIqnFpwMsA==
Received: by 2002:a17:903:2847:b0:224:781:6f9c with SMTP id
 d9443c01a7336-245fca1f6eels11026305ad.0.-pod-prod-08-us; Thu, 21 Aug 2025
 14:00:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXu2wIswZOS47x1lvuNjx7w8+sqZ7xdv00ZlKxQlYZDYebK4bpAYFesNsKjsCUdSnWg2+954AqTrr8=@googlegroups.com
X-Received: by 2002:a17:903:2f83:b0:240:ce24:20a0 with SMTP id d9443c01a7336-2462edeeb07mr10139555ad.11.1755810047632;
        Thu, 21 Aug 2025 14:00:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755810047; cv=none;
        d=google.com; s=arc-20240605;
        b=jmLjIa8IHOFoCBVgI22yOxX0+FJmQmWIsTEaeylgIiyeyIcaiUz1jX5FxplCa984j7
         KO2BjC9xfUvJpPBqJK4znAFYInV6ckWVPteiJfZjj0o6PDoaKiDVFesruLP9LzRigNdt
         Mtsf+U42l+TBPY7esseVsGSRf31l8IkbbfFodrGz9+zDpZJTShLtOqCMOesg7wTwTq7P
         oPJObaxqkHR5H2QPEKZYI09iXnTp3KiNZfA6Fkgx6ciqtRGmk1sGQvs+yMrf/CkiES5U
         MsZjFb2HCwK2B7ozKdXZeX/qBj1KqPUXZA0VpJWe7dGh6oJvAbssYzhpN7A3iZeKniZG
         fYJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=Cp1mFCWwcTWQzzsUUmh88+YFkDBcq7Y5lQlba0VlHo0=;
        fh=BmdV3yezrahKIutHmiyqm4wEg7SUsSggjXM2g4hZTAs=;
        b=gtvjw7BN5ScIz75VbdyqE2HmkpCWqHbIt7/CwvDN3+0a1ua5WVuFiADcNvbKvmfxKm
         OulBPvYnjagyZuZ6qs5gkdMamdrTdA3OIm9gr8gKLg25cwLs9ZpdErJA0QkKIWjeBEEC
         06NAOij5v3aRc+LfhecrX8DlDnm3AQeMAwcz2o9arFaQrSQuR3jtyLQy3NCwAxI8fU+Q
         +HO3L0lwfqIR4bsmfvbfVK0Gi3npdXvKnmk8xU3l1IZhafoyIA+A4BzEoFX5KGCrZelY
         bjp0dApHSYZBorKn5VPA6o02AeAgCNy9bZLYxQ6l+6z1E8504QE32sy3vgvwJomKj/o3
         OHCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=f0EYsgAI;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-246257b5c09si499595ad.4.2025.08.21.14.00.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 14:00:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-663-SHPJbBoWP_qlJbQZKEo-3w-1; Thu, 21 Aug 2025 17:00:42 -0400
X-MC-Unique: SHPJbBoWP_qlJbQZKEo-3w-1
X-Mimecast-MFC-AGG-ID: SHPJbBoWP_qlJbQZKEo-3w_1755810041
Received: by mail-wr1-f69.google.com with SMTP id ffacd0b85a97d-3b9e4146902so573810f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 14:00:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXPELBK51RRejydXphn67hy2TY923ZmiSmUo+Xf2c3lF8uMTpvDVtb129A47w+IInnuVVpLMnlOTeA=@googlegroups.com
X-Gm-Gg: ASbGncsBaWrHo8KYGm1fNWG17myJhm3kZHgCr4VZ51RHdp/FEGN5VU4YSDyDEq5ln7O
	I3oWsd23+cqwJ1qegrhKyPmzeHilNu3aBtujswl8JOzt4K3wytajH3elYy9ZgdkA0M7X9aInDvp
	wewiX0M2CfWf+5iCvPxhIEyAq+YFo63owWfx5AJ2N0Nd/NX04/S/jz4bj7CJ4uLMyWlVpaY4hHb
	Q7fxk21sRUgyvvjyYS7CTCdPu4ea6aouiCE0TYbW+S08L+jpdLpEZIFCmt5Vnl5oiqUl1EsgMq5
	GnqA01mJRezUCkRPpLLIVHXrqW+NX61CVzdOu6Uz/oBlMNbcKKOGfsT1ia+V58NHRag4e5Yfz0x
	J1UpTX/MTHpCWL0y3hzwJtv5HjIFpBnBLxMZB/R58H+EvBcv/nOvKkJS2VQ1GvA==
X-Received: by 2002:a05:6000:200d:b0:3a5:2465:c0c8 with SMTP id ffacd0b85a97d-3c5daa27e6amr265218f8f.7.1755810041318;
        Thu, 21 Aug 2025 14:00:41 -0700 (PDT)
X-Received: by 2002:a05:6000:200d:b0:3a5:2465:c0c8 with SMTP id ffacd0b85a97d-3c5daa27e6amr265173f8f.7.1755810040805;
        Thu, 21 Aug 2025 14:00:40 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f26:ba00:803:6ec5:9918:6fd? (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3c4ccbf04fasm3476159f8f.7.2025.08.21.14.00.38
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 14:00:40 -0700 (PDT)
Message-ID: <23c6e511-19b2-4662-acfc-18692c899a6c@redhat.com>
Date: Thu, 21 Aug 2025 23:00:37 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 13/35] mm: simplify folio_page() and folio_page_idx()
To: Zi Yan <ziy@nvidia.com>
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
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-14-david@redhat.com>
 <E1AA1AC8-06E4-4896-B62B-F3EA0AE3E09C@nvidia.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <E1AA1AC8-06E4-4896-B62B-F3EA0AE3E09C@nvidia.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: uko9BRwjOGQ6DylAp_7CVQz45b0vvTzDUGwqnQa6YGQ_1755810041
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=f0EYsgAI;
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

On 21.08.25 22:55, Zi Yan wrote:
> On 21 Aug 2025, at 16:06, David Hildenbrand wrote:
> 
>> Now that a single folio/compound page can no longer span memory sections
>> in problematic kernel configurations, we can stop using nth_page().
>>
>> While at it, turn both macros into static inline functions and add
>> kernel doc for folio_page_idx().
>>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
>> ---
>>   include/linux/mm.h         | 16 ++++++++++++++--
>>   include/linux/page-flags.h |  5 ++++-
>>   2 files changed, 18 insertions(+), 3 deletions(-)
>>
>> diff --git a/include/linux/mm.h b/include/linux/mm.h
>> index 48a985e17ef4e..ef360b72cb05c 100644
>> --- a/include/linux/mm.h
>> +++ b/include/linux/mm.h
>> @@ -210,10 +210,8 @@ extern unsigned long sysctl_admin_reserve_kbytes;
>>
>>   #if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
>>   #define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
>> -#define folio_page_idx(folio, p)	(page_to_pfn(p) - folio_pfn(folio))
>>   #else
>>   #define nth_page(page,n) ((page) + (n))
>> -#define folio_page_idx(folio, p)	((p) - &(folio)->page)
>>   #endif
>>
>>   /* to align the pointer to the (next) page boundary */
>> @@ -225,6 +223,20 @@ extern unsigned long sysctl_admin_reserve_kbytes;
>>   /* test whether an address (unsigned long or pointer) is aligned to PAGE_SIZE */
>>   #define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)
>>
>> +/**
>> + * folio_page_idx - Return the number of a page in a folio.
>> + * @folio: The folio.
>> + * @page: The folio page.
>> + *
>> + * This function expects that the page is actually part of the folio.
>> + * The returned number is relative to the start of the folio.
>> + */
>> +static inline unsigned long folio_page_idx(const struct folio *folio,
>> +		const struct page *page)
>> +{
>> +	return page - &folio->page;
>> +}
>> +
>>   static inline struct folio *lru_to_folio(struct list_head *head)
>>   {
>>   	return list_entry((head)->prev, struct folio, lru);
>> diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
>> index d53a86e68c89b..080ad10c0defc 100644
>> --- a/include/linux/page-flags.h
>> +++ b/include/linux/page-flags.h
>> @@ -316,7 +316,10 @@ static __always_inline unsigned long _compound_head(const struct page *page)
>>    * check that the page number lies within @folio; the caller is presumed
>>    * to have a reference to the page.
>>    */
>> -#define folio_page(folio, n)	nth_page(&(folio)->page, n)
>> +static inline struct page *folio_page(struct folio *folio, unsigned long nr)
>> +{
>> +	return &folio->page + nr;
>> +}
> 
> Maybe s/nr/n/ or s/nr/nth/, since it returns the nth page within a folio.

Yeah, it's even called "n" in the kernel docs ...

> 
> Since you have added kernel doc for folio_page_idx(), it does not hurt
> to have something similar for folio_page(). :)

... which we already have! (see above the macro) :)

Thanks!

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/23c6e511-19b2-4662-acfc-18692c899a6c%40redhat.com.
