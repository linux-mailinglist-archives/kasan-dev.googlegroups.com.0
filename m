Return-Path: <kasan-dev+bncBC32535MUICBBG64Y3CQMGQENDC72TI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 36DCAB3BC9B
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 15:41:49 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-7e870646b11sf482055485a.2
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 06:41:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756474908; cv=pass;
        d=google.com; s=arc-20240605;
        b=M180bC25ruPFtOVD/SCI/WQZC2JANyn5s9hMfe5PtGl4ErBvNnIAMX1UrNPv4wT6Ma
         pnnKYNFdFWp+5u/WxVNqEcjMUSyYkpo1dgMxCyAS0Y1OQcakSO9cB9Ks7k8UXXudH/T0
         8dEMjRLFMDJWFMfPkRssQA699HFy3KrNh0Ttn5BNjzbGWiPNLtl6l+Uc6UKUKQHKwXfJ
         kUaWZUZOwUSr36awg7bpGi7gk9ODzqVXZbvQp88jWMSQEGUeBzSxijBdlUw9WQxuLgwi
         JSc2g91XaupszYS5VEWk7PjDO64Z00Qt44lPTe+2oIp+JADzOxjtZaJI2uyz6fqi9GOH
         +pRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=bSAnQ6/KP+/9ixLx0767zS0m0iuUV4hfNU6sY0kt2Uw=;
        fh=JNLT/nqECo2ZUIE1hRis2FvUEAO1t73BTxo9i4GAIJ4=;
        b=JKYcjTSHU0MQTBMKfRpuUFRMhPtjQJYdtluywZSuFuZ4DuLdxXlwV8FfmmpD5rLSAu
         K+llxFolDsPt/08DjcUkNvkVbTahTFM4fD8I8Qr5xBOtOD6NXOq9CZFYtPJru1CNRYpL
         FzVBw2qNTYzaGWVGmG1PEaTRFoFyqnhJxP+EOXweDDnhOianUkiJakiiKtZiQAIKg+Dg
         ViaXp6zOtsKmxoUj2CQJu2mpEhT2etwtrwHu28zeJfHWMbG/RI8xB6ltfVbzanWTL5EA
         f2Tygy7JmO7LDyPFK7lDwUNKdX0Su2MD8Klvrvjrx6TkZjQY4fdNwJ1OMWR1YTOSoIwa
         6F6Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=f98+42k7;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756474908; x=1757079708; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=bSAnQ6/KP+/9ixLx0767zS0m0iuUV4hfNU6sY0kt2Uw=;
        b=ACv+53+APH1MTyZQ9C+rJIeusxCABtkqibvviOynyUVNWrpsDAWk/GU/xaBQhIkLw5
         lx8adp+Vh+O/nn1V/p4puEjLJDQLG4NLNrcG11fFkfeN1sje+qRyKO1XFtW10lPgvqyV
         s18Bjna3C+uR4JHm+a0ULQz8wkpA5kARkd+678B5QhsqK6Cn1GYKN6S/eQja9HEQzG0i
         piqNJCsCv+iEHHMiJ5mIXKV3fgn+GawBT/rYO99z2igyN0hvlu+9hkY98wUiDbfEqvKV
         G23uF3MXev90ST3P6oFyL0Ea6lyoSFPLdLkF5cfJZk258KkoklmKpgxOSM11t4kpJ+vw
         uAOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756474908; x=1757079708;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=bSAnQ6/KP+/9ixLx0767zS0m0iuUV4hfNU6sY0kt2Uw=;
        b=ClqFKvc+k5FhUKIxdBVX36yUSJmlDZifH4oUCOe11lzLQpsKz7PbBh3L0zVWOYcWmh
         4xRFuMewnGi4I3hSPqUVbUJT0NT2nQ1JT+KsgbXpYVhcCt5kamOOz32SHQS/Di/zBJVO
         ZZ+v7UJcGvcdCb3oDwzo0s5Dcsjg3xliaJWArVytuag6VV7g2p285PGX9LZVFhhK0014
         NxhE4tRx7KvEtc0mBV32y9ch0mY6kJbyeHC0QP/aeiBmRPJ4VAdrEH+MB+2BgP3wwbf1
         szh0cyQCWpSl6yf9GGhanHrBIk6EDrCVJ9Wf2EfFWc2ZO9knezUiNThGwfATbmqf9+QF
         vn1A==
X-Forwarded-Encrypted: i=2; AJvYcCXoeJkvizrhw2Tw3NZR1S9FDD9xJOpZEd1zJKgCW5X63M1qXFGj05pPlZqRIbjCTgsQP/fjHg==@lfdr.de
X-Gm-Message-State: AOJu0YyHtNAa8pT+ljUccE6Y4GHKGuC6wmG7J0ATGz0Fs63BXGoVm6dM
	sLmVY9mnTxbzPnCUWUjC3uB6wHRsXSO/PLw/wV854J9FUMR/8rYvCqT/
X-Google-Smtp-Source: AGHT+IHA47tPh+SaqFAdYJfYFzwYDq/QdymrPrTnZ0DOXCUQpVt4RJwx6wAwuxN+cG2GmH2CEUcDmA==
X-Received: by 2002:a05:620a:a80c:b0:7e8:18d5:4b8d with SMTP id af79cd13be357-7ea11096af1mr2799497885a.42.1756474908139;
        Fri, 29 Aug 2025 06:41:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdOvUR7EuKrADDnNYvy33XkLCKHlnNsxbECy8d54Hi71A==
Received: by 2002:a05:622a:188d:b0:4a3:c792:a1c9 with SMTP id
 d75a77b69052e-4b2fe840eb1ls32276581cf.1.-pod-prod-01-us; Fri, 29 Aug 2025
 06:41:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU7cFnOquCxDSDYF5kW+rsRS+ihACdG8Kyz4iQY6twPKFZ8yY8hCxzapO3qTxbj5IF7/xG+p36qyQw=@googlegroups.com
X-Received: by 2002:a05:622a:448:b0:4b2:dedf:449b with SMTP id d75a77b69052e-4b307cfa39fmr58668061cf.52.1756474906718;
        Fri, 29 Aug 2025 06:41:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756474906; cv=none;
        d=google.com; s=arc-20240605;
        b=X+Q0q3pHVINPI44T+eGaZA3eTXhAd6FbQtDqt0Diw4KCxj4jC8JplIBIrIHoF7D42d
         2vQT/bxRAbrTQq1aiGiQ/wc9FNVEa4nBTwLgSOEzfqu8z958wbLbPxOwlkjui/H9RNKX
         5SAeWqVge/AXxBAoPu3ER8EE3aVg9gs/cPG6QfKHf5N2zp1gOUYw+TsLcGuv5oQSZWLA
         MMyWW2vDPmSwjTv/GlCUIIOr2Xf5IeqZFRzgr8bUH6lVsNICmJ/CZLXfeJWnjTUYVGXd
         8brI0Gv09WChGodVBQ1yZ7cwW8s0LjVdYKHwJSLpN43bPnF8Kfj1sIBlms3+p12swl1j
         t41w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=7ZezTDYPV9FY1vYbYIlP1Z79qo+TmLw98Vo74TFiYNA=;
        fh=iybnAc0jEIvMaAoB0NPXT9DCdUn5XGsKWGwYvJYzno8=;
        b=QuAkbSSkpa3u3GvK/fOolTTXgg980r0HnCjf/lagAbE7ODkkYntUz5+nIV/sKTnjq7
         0CMx7T1uPy8uD4AMlZgJbZtGXGELMiC5HTZtisigdQzeoUz8IT/n/9r8y/2UJduf8Tz7
         u0phX6o31LelBr7OeHQ7TIbwKW5UG5KHQxbpMdhqYfDm7g2H/cQtWYSxCq3gvnqpcgpm
         H3yvxpYOJkBnLYv+JpSmE/6T3LlmZwTwPPYPVbUw2/TxlTcvV/e5ZJo68+hm/WQf3H38
         P7BPRR1bpnqC+Qmw9oaR9JZgvjCeTE7CKLaTOhkKpha+o987Ei+6WsEvoQuxdbag0m6m
         42NA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=f98+42k7;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b30b6b4844si945841cf.5.2025.08.29.06.41.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 06:41:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-73--q1FoPFJOcGurp_T4CrC3Q-1; Fri, 29 Aug 2025 09:41:45 -0400
X-MC-Unique: -q1FoPFJOcGurp_T4CrC3Q-1
X-Mimecast-MFC-AGG-ID: -q1FoPFJOcGurp_T4CrC3Q_1756474904
Received: by mail-wm1-f69.google.com with SMTP id 5b1f17b1804b1-45a1ad21752so12836535e9.1
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 06:41:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU//1Mx/bo2mzMJqlAKnVUMRKh/dp/U6yzEDSMnHxDlBOP+WXmiCYdRB6AG9fy9x+ygEUi6Gp5sIqg=@googlegroups.com
X-Gm-Gg: ASbGncvtD2nMScd2PjPPNFEY7C/ZMJ2i/5IyDfID39n6uxRK92jQL8y6MLURO/PPKnx
	O6RnlYSAsyI2P+OYXc6/a3lChohyg/Nb0ichlktInDY27KPsUwtrjH9DBH0CHwUpqwRj5vMcsqv
	Hgm0T/UzYirzCtfZ5mPf3ecu9nha+lil1IkD3QmLE2ATZmCxZlqpr+Sapo+0EEjmxtVYlzC0d0V
	f3HrB/MNNmPKohl6+b0nIwObMhpi+weJISNNAZiTWi+LynkW+zz6zQiI4h/fw0PJgdjd6w8UEnT
	i8AkYiszu2GJyWKkIkNuFGyy2VY1+q1/V7qjmIPPc6HOsGwcin3w9qEtNMdPYIavkHfSQEMJgJx
	sZfX4cDksLbwnzLmZaupFXvqSG/iku8l6+EBCuD2ZKPrMu+4K54muHhxTTgwWNVVt
X-Received: by 2002:a05:600c:8b0a:b0:45b:733b:1feb with SMTP id 5b1f17b1804b1-45b733b214dmr83370855e9.10.1756474903646;
        Fri, 29 Aug 2025 06:41:43 -0700 (PDT)
X-Received: by 2002:a05:600c:8b0a:b0:45b:733b:1feb with SMTP id 5b1f17b1804b1-45b733b214dmr83370155e9.10.1756474903176;
        Fri, 29 Aug 2025 06:41:43 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1d:100:4f8e:bb13:c3c7:f854? (p200300d82f1d01004f8ebb13c3c7f854.dip0.t-ipconnect.de. [2003:d8:2f1d:100:4f8e:bb13:c3c7:f854])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cf3458a67esm3469559f8f.62.2025.08.29.06.41.40
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 06:41:42 -0700 (PDT)
Message-ID: <632fea32-28aa-4993-9eff-99fc291c64f2@redhat.com>
Date: Fri, 29 Aug 2025 15:41:40 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 18/36] mm/gup: drop nth_page() usage within folio when
 recording subpages
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
 <20250827220141.262669-19-david@redhat.com>
 <c0dadc4f-6415-4818-a319-e3e15ff47a24@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <c0dadc4f-6415-4818-a319-e3e15ff47a24@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: 77k85q4FqJvO6kxhB9oXLcFCdN0MvB-qK2D_PeucmNo_1756474904
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=f98+42k7;
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

On 28.08.25 18:37, Lorenzo Stoakes wrote:
> On Thu, Aug 28, 2025 at 12:01:22AM +0200, David Hildenbrand wrote:
>> nth_page() is no longer required when iterating over pages within a
>> single folio, so let's just drop it when recording subpages.
>>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
> 
> This looks correct to me, so notwithtsanding suggestion below, LGTM and:
> 
> Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> 
>> ---
>>   mm/gup.c | 7 +++----
>>   1 file changed, 3 insertions(+), 4 deletions(-)
>>
>> diff --git a/mm/gup.c b/mm/gup.c
>> index b2a78f0291273..89ca0813791ab 100644
>> --- a/mm/gup.c
>> +++ b/mm/gup.c
>> @@ -488,12 +488,11 @@ static int record_subpages(struct page *page, unsigned long sz,
>>   			   unsigned long addr, unsigned long end,
>>   			   struct page **pages)
>>   {
>> -	struct page *start_page;
>>   	int nr;
>>
>> -	start_page = nth_page(page, (addr & (sz - 1)) >> PAGE_SHIFT);
>> +	page += (addr & (sz - 1)) >> PAGE_SHIFT;
>>   	for (nr = 0; addr != end; nr++, addr += PAGE_SIZE)
>> -		pages[nr] = nth_page(start_page, nr);
>> +		pages[nr] = page++;
> 
> 
> This is really nice, but I wonder if (while we're here) we can't be even
> more clear as to what's going on here, e.g.:
> 
> static int record_subpages(struct page *page, unsigned long sz,
> 			   unsigned long addr, unsigned long end,
> 			   struct page **pages)
> {
> 	size_t offset_in_folio = (addr & (sz - 1)) >> PAGE_SHIFT;
> 	struct page *subpage = page + offset_in_folio;
> 
> 	for (; addr != end; addr += PAGE_SIZE)
> 		*pages++ = subpage++;
> 
> 	return nr;
> }
> 
> Or some variant of that with the masking stuff self-documented.

What about the following cleanup on top:


diff --git a/mm/gup.c b/mm/gup.c
index 89ca0813791ab..5a72a135ec70b 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -484,19 +484,6 @@ static inline void mm_set_has_pinned_flag(struct mm_struct *mm)
  #ifdef CONFIG_MMU
  
  #ifdef CONFIG_HAVE_GUP_FAST
-static int record_subpages(struct page *page, unsigned long sz,
-                          unsigned long addr, unsigned long end,
-                          struct page **pages)
-{
-       int nr;
-
-       page += (addr & (sz - 1)) >> PAGE_SHIFT;
-       for (nr = 0; addr != end; nr++, addr += PAGE_SIZE)
-               pages[nr] = page++;
-
-       return nr;
-}
-
  /**
   * try_grab_folio_fast() - Attempt to get or pin a folio in fast path.
   * @page:  pointer to page to be grabbed
@@ -2963,8 +2950,8 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
         if (pmd_special(orig))
                 return 0;
  
-       page = pmd_page(orig);
-       refs = record_subpages(page, PMD_SIZE, addr, end, pages + *nr);
+       refs = (end - addr) >> PAGE_SHIFT;
+       page = pmd_page(orig) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
  
         folio = try_grab_folio_fast(page, refs, flags);
         if (!folio)
@@ -2985,6 +2972,8 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
         }
  
         *nr += refs;
+       for (; refs; refs--)
+               *(pages++) = page++;
         folio_set_referenced(folio);
         return 1;
  }
@@ -3003,8 +2992,8 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
         if (pud_special(orig))
                 return 0;
  
-       page = pud_page(orig);
-       refs = record_subpages(page, PUD_SIZE, addr, end, pages + *nr);
+       refs = (end - addr) >> PAGE_SHIFT;
+       page = pud_page(orig) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
  
         folio = try_grab_folio_fast(page, refs, flags);
         if (!folio)
@@ -3026,6 +3015,8 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
         }
  
         *nr += refs;
+       for (; refs; refs--)
+               *(pages++) = page++;
         folio_set_referenced(folio);
         return 1;
  }


The nice thing is that we only record pages in the array if they actually passed our tests.


-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/632fea32-28aa-4993-9eff-99fc291c64f2%40redhat.com.
