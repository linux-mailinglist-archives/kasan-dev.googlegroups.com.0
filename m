Return-Path: <kasan-dev+bncBC32535MUICBB3NW57CQMGQEAT7GBUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 54747B4699C
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Sep 2025 08:57:51 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-336d4230e67sf8260401fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 23:57:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757141870; cv=pass;
        d=google.com; s=arc-20240605;
        b=b7T1FDuQiVuCfXKLghbvfiiOuyVFdMaCP//4BwUidl0WGQ/Vev2grOmcx5UgBwn9ol
         0iC2YBOs4nGzRO+4IBG60BbdKN4YP8lYUcnwXz8paa0Ba88Gk2m5Ut0tHtq7RF7QMW0l
         Mvvhnk8q6akR0EeMljoXvOapZBW2LdbrI7Khz/w8hLvlUYjiOgHNAk9hui/spWEEPmHd
         Vz1tAAU9DlMzGydwrLCN4DT2QNAz1fa/oJE69Gqg9dvb7qmJm5rQKGl2LDCSvDNhggNm
         1D3yLdYsD1RnoJ677XTYOwynAlq5ha+/6rauRcdMfzA7oAe04WIdWqC/+goH9GRjtnD3
         7wWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=k+5QRMTBRwm9zfF8H/BTFb1tWXGVafygFvYzNZrXTX8=;
        fh=lcLf97ETl+SGcEOeosU6lO7C7ah9yJJbGBjTTdQwrFs=;
        b=D1jJoSZLWCNiEejwKakJmP+8EXkjel52lDM6JQgwYTNnHaayEeSC+LygHx0e4y35mL
         5fOyNNcTswSsOLBGSka0EYd+ngJTCM7syAdQaVLfRLpJ9SDNYQppZmHJJ4z6NiiMEh2r
         ziVhE6N5uYl9VQDz/huuoSCfiIi6T08lAWtD60ToAeyY2V/fA9pivnHIavnWIS+7z/Kv
         xESPtswZNPpxBoL7GfEnP8ZdGGkkBQv5WoN6Yz7IE81A0kAwyrW2gIvGoGQKGGI2C2u7
         cwo5ZfVSjdtgLgO3wnY6swAQSDTtN0wf6zIHgl7z7AY0bVN9oLeh6ngh8WDWI0Y5NY+L
         fcuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IFSh2Efd;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757141870; x=1757746670; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=k+5QRMTBRwm9zfF8H/BTFb1tWXGVafygFvYzNZrXTX8=;
        b=iS3UrZ4J91uCOCvpfz4HRXvw3vbute2ZNAomEG/M2NCt7vdRSXSnlnN6TMCs8oUQBV
         W1JRI5awaceYoTRU+k6e6OnyAApYa5D0LBHNgBB0pRNJfr+nU5PggpmgvzFcWYUxDnZm
         upxShwkiTrXPbbYbTM5PxaVMp/FtX7GU62FHv2ndfzhK8glZnpRjFWPvgYlQddSk4qft
         dwpJT22INVk1ooWNJBt1vea6yffMYfibsinLL9/Q+K6qWNc0C0jZi4HKtxBFJfVxaRKk
         hfjOHbkwl2VS0WVJR5KfXza6q1JWmdQajdtN6Xv0gzItKwJNrAwx9mcBkbNtkWBFq6Io
         RtUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757141870; x=1757746670;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=k+5QRMTBRwm9zfF8H/BTFb1tWXGVafygFvYzNZrXTX8=;
        b=N87xmFueLaUCv199qLV/VPxjd7VYf7lb0+DQNFTy9Mv4c/JyxdSztQIWgtcLg1QSdH
         LNCJ9k45r5cLhZ/6yDLAoXm++2p9kAGd1tfahLLRWrhaWHY4FEfDO6Ha4SuBI1JtB51Z
         O6DJhKNA7Z+6Do+RS1HRwSr3JW3EpbN11cj2VOCGVsssLiEYvXnFtcsPmis//8UO0Luk
         Nlh9ItzoptNi5A0BWWP4jQMG+HjpLo6wqv4lfgMnIlFz7UVhN/L1Q7Flc0NU+XckRi19
         oKkLNrNH52iZ9OYiKL7KVWCRl/SJEc4gmoRhE/nUp9sUhhKWO9gdgwiB+acyA/dLlNcu
         pvSw==
X-Forwarded-Encrypted: i=2; AJvYcCUMsIsT6dBAyvbpqTkZdLAnf6KdLWhlP3HVQCDSVzq1TTICi40hOK51KYWfNyMd1Z/whuKnXQ==@lfdr.de
X-Gm-Message-State: AOJu0YwD/U/JVDnzXSRr/46pBMvS4rL0urzHneizsIeiyo2ZAbksD8Hf
	GTvcGX4lHemP90ZU1i8LXX2SZJ6fA6NcLDbhXVCSabWQK8T1AdmAaDH0
X-Google-Smtp-Source: AGHT+IEyhYwIknUanWzsoynK29Pfbn+8z7cx7DwvE1pWtKMpkktaVIDSZQ9307SU1tYKFFkOMEtLFQ==
X-Received: by 2002:a05:6512:3b0b:b0:55f:4e8a:19ad with SMTP id 2adb3069b0e04-56260a6233fmr337038e87.13.1757141869886;
        Fri, 05 Sep 2025 23:57:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcdglNTQJHfEoJr35ylDRYldGbbVxi9nbtBHAPszb4siQ==
Received: by 2002:ac2:5bdc:0:b0:560:99a2:96c1 with SMTP id 2adb3069b0e04-5615bacb920ls255499e87.1.-pod-prod-03-eu;
 Fri, 05 Sep 2025 23:57:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWlx4bBsr19PSBe/+WDt/ijk5IS0jZg1XwIRBzVhzqfRucjezdCPxsKSMoT3i13xRDVzzHFM6V/VVw=@googlegroups.com
X-Received: by 2002:a05:651c:23d2:20b0:338:735:8a79 with SMTP id 38308e7fff4ca-33b4b230a20mr3355051fa.1.1757141866499;
        Fri, 05 Sep 2025 23:57:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757141866; cv=none;
        d=google.com; s=arc-20240605;
        b=ZBNKV3Lr6RyFRVXgl3nUVQyMzJR982m2TiirJikHsZpeo1F1k20qcS47rZBZUA/B8P
         WWEfqauY/LcwLpfuscrTd3+V4G1VKWcottG0lbcJ2k23Kb5SqI+Id9KNWUQhe0i4ihd0
         7ygXulIdiyJzRm3WopnpS3l/dOujXNk6RzfIaKdYKO+MlrvsToHkn9D8BoKPfxuwyI3W
         QBYBqbB6N0HVOzMFrlb/zMWPHLN4ZFCmJKQOoaCayviurPXDyWtUrrdqXhsewQbjmGRW
         R+L2Z675plFTJNqdh0nYJ2WdK9XugAayo2b9TbmwYvHo+QdRltnIMgcI5Ml7QWLX9j0D
         NdLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=CCJs31gS3SmY6gT03ZW9SqmlSjC26seB+xyCx6US3Ag=;
        fh=C2pFNgB1Ns3QLI07+D4lIW1UnbxiI4PRCG6/9jmnDEY=;
        b=K8eKNjAZyWuQzA5YHd2OcmNfGLMKpyStqYF4WGwHQwKBSq92N30F2fhPeRhu5JVSbL
         arMCZF4SgIaFO21pK9XS6hhO+xU5yY9mLekIRIumaLdvqFvZ5SPDmS1VwSy6QmC+W38W
         zBAbzMIvVWPEkhhZcYa9Hg09qDywcuTzgiIzEDEjtT/Q654j3vT4Dvyr6Oo7FJDLAvkc
         TsvuYKugsLGHc2jECer3JouCel9gXax0KKNWbChHdOdT+JjE5+blplv4T/LUo9P3NCYw
         r9PbNpwwjZwlGVodFJ9itJa8jV8abivMD/CfWx7WNs/QXBVingX9NXZ12tLgttV1s/j8
         PJ3w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IFSh2Efd;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-337f4f75055si1984921fa.4.2025.09.05.23.57.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 Sep 2025 23:57:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-6-_3v02MfLN7qMFArW9T0WmA-1; Sat, 06 Sep 2025 02:57:43 -0400
X-MC-Unique: _3v02MfLN7qMFArW9T0WmA-1
X-Mimecast-MFC-AGG-ID: _3v02MfLN7qMFArW9T0WmA_1757141862
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45dde353979so1323855e9.3
        for <kasan-dev@googlegroups.com>; Fri, 05 Sep 2025 23:57:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV/ZLzAsUP+2zayJytBWy5BMmJBp757yUTeizLL5pX886mfMtMioVM9qdBa9c3y505lBXUd3FvQ/84=@googlegroups.com
X-Gm-Gg: ASbGnctm97QIQ42n4fyLMy5kJVBlAsX5md37cOzAF/ObFHfoo4+iHg/DCjfCfWaJ/45
	GK14t18kFmiYEmwBmrAPtMbPiayvI0YVvSHaeAdMWmE05yRIaNS9eBW2/4qApsDFDtropTwnpaX
	wU5PlF/uG6q6f3N6B7aFxLK0iDUaeFKdcu8/S6eBkGUBt/oHrEoEC0ohR8hruld3gDhABHLPtJe
	iFH+wdqaH/8oJ9dp1Zhob576r4Fv4wNUF046pBqS/ZBbsg3URAht0a3e25YRjPPTl9EhEudOZ1o
	cWlyA5BENeavAQ4fIsldMw4GcVtZA7YWBbJ0gLmNs6ASJZ9sFW5hy0U47YGCF71fMx1WnEqu0zo
	7zsduk3ARyQcyjJOF53dT5wrMoCvsWWZ3Ht8BX5OqxHnyZCYq/nzgoxjbWzKG0SXOv/k=
X-Received: by 2002:a05:600c:a43:b0:45d:d944:e763 with SMTP id 5b1f17b1804b1-45dddef8abemr11582345e9.33.1757141861880;
        Fri, 05 Sep 2025 23:57:41 -0700 (PDT)
X-Received: by 2002:a05:600c:a43:b0:45d:d944:e763 with SMTP id 5b1f17b1804b1-45dddef8abemr11582145e9.33.1757141861401;
        Fri, 05 Sep 2025 23:57:41 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f30:de00:8132:f6dc:cba2:9134? (p200300d82f30de008132f6dccba29134.dip0.t-ipconnect.de. [2003:d8:2f30:de00:8132:f6dc:cba2:9134])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3e740369f1esm87090f8f.11.2025.09.05.23.57.37
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 23:57:40 -0700 (PDT)
Message-ID: <64fe4c61-f9cc-4a5a-9c33-07bd0f089e94@redhat.com>
Date: Sat, 6 Sep 2025 08:57:37 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 19/37] mm/gup: remove record_subpages()
To: Eric Biggers <ebiggers@kernel.org>
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
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-20-david@redhat.com>
 <5090355d-546a-4d06-99e1-064354d156b5@redhat.com> <20250905230006.GA1776@sol>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <20250905230006.GA1776@sol>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: xyYe2Jcrrjr4VBZT1WnoIkA8ZLnUUHf43NVZNAS9hhw_1757141862
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=IFSh2Efd;
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

On 06.09.25 01:00, Eric Biggers wrote:
> On Fri, Sep 05, 2025 at 08:41:23AM +0200, David Hildenbrand wrote:
>> On 01.09.25 17:03, David Hildenbrand wrote:
>>> We can just cleanup the code by calculating the #refs earlier,
>>> so we can just inline what remains of record_subpages().
>>>
>>> Calculate the number of references/pages ahead of times, and record them
>>> only once all our tests passed.
>>>
>>> Signed-off-by: David Hildenbrand <david@redhat.com>
>>> ---
>>>    mm/gup.c | 25 ++++++++-----------------
>>>    1 file changed, 8 insertions(+), 17 deletions(-)
>>>
>>> diff --git a/mm/gup.c b/mm/gup.c
>>> index c10cd969c1a3b..f0f4d1a68e094 100644
>>> --- a/mm/gup.c
>>> +++ b/mm/gup.c
>>> @@ -484,19 +484,6 @@ static inline void mm_set_has_pinned_flag(struct mm_struct *mm)
>>>    #ifdef CONFIG_MMU
>>>    #ifdef CONFIG_HAVE_GUP_FAST
>>> -static int record_subpages(struct page *page, unsigned long sz,
>>> -			   unsigned long addr, unsigned long end,
>>> -			   struct page **pages)
>>> -{
>>> -	int nr;
>>> -
>>> -	page += (addr & (sz - 1)) >> PAGE_SHIFT;
>>> -	for (nr = 0; addr != end; nr++, addr += PAGE_SIZE)
>>> -		pages[nr] = page++;
>>> -
>>> -	return nr;
>>> -}
>>> -
>>>    /**
>>>     * try_grab_folio_fast() - Attempt to get or pin a folio in fast path.
>>>     * @page:  pointer to page to be grabbed
>>> @@ -2967,8 +2954,8 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
>>>    	if (pmd_special(orig))
>>>    		return 0;
>>> -	page = pmd_page(orig);
>>> -	refs = record_subpages(page, PMD_SIZE, addr, end, pages + *nr);
>>> +	refs = (end - addr) >> PAGE_SHIFT;
>>> +	page = pmd_page(orig) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
>>>    	folio = try_grab_folio_fast(page, refs, flags);
>>>    	if (!folio)
>>> @@ -2989,6 +2976,8 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
>>>    	}
>>>    	*nr += refs;
>>> +	for (; refs; refs--)
>>> +		*(pages++) = page++;
>>>    	folio_set_referenced(folio);
>>>    	return 1;
>>>    }
>>> @@ -3007,8 +2996,8 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
>>>    	if (pud_special(orig))
>>>    		return 0;
>>> -	page = pud_page(orig);
>>> -	refs = record_subpages(page, PUD_SIZE, addr, end, pages + *nr);
>>> +	refs = (end - addr) >> PAGE_SHIFT;
>>> +	page = pud_page(orig) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
>>>    	folio = try_grab_folio_fast(page, refs, flags);
>>>    	if (!folio)
>>> @@ -3030,6 +3019,8 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
>>>    	}
>>>    	*nr += refs;
>>> +	for (; refs; refs--)
>>> +		*(pages++) = page++;
>>>    	folio_set_referenced(folio);
>>>    	return 1;
>>>    }
>>
>> Okay, this code is nasty. We should rework this code to just return the nr and receive a the proper
>> pages pointer, getting rid of the "*nr" parameter.
>>
>> For the time being, the following should do the trick:
>>
>> commit bfd07c995814354f6b66c5b6a72e96a7aa9fb73b (HEAD -> nth_page)
>> Author: David Hildenbrand <david@redhat.com>
>> Date:   Fri Sep 5 08:38:43 2025 +0200
>>
>>      fixup: mm/gup: remove record_subpages()
>>      pages is not adjusted by the caller, but idnexed by existing *nr.
>>      Signed-off-by: David Hildenbrand <david@redhat.com>
>>
>> diff --git a/mm/gup.c b/mm/gup.c
>> index 010fe56f6e132..22420f2069ee1 100644
>> --- a/mm/gup.c
>> +++ b/mm/gup.c
>> @@ -2981,6 +2981,7 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
>>                  return 0;
>>          }
>> +       pages += *nr;
>>          *nr += refs;
>>          for (; refs; refs--)
>>                  *(pages++) = page++;
>> @@ -3024,6 +3025,7 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
>>                  return 0;
>>          }
>> +       pages += *nr;
>>          *nr += refs;
>>          for (; refs; refs--)
>>                  *(pages++) = page++;
> 
> Can this get folded in soon?  This bug is causing crashes in AF_ALG too.

Andrew immediately dropped the original patch, so it's gone from 
mm-unstable and should be gone from next soon (today?).

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/64fe4c61-f9cc-4a5a-9c33-07bd0f089e94%40redhat.com.
