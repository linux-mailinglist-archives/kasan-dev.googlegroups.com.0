Return-Path: <kasan-dev+bncBC32535MUICBB5MJ23CQMGQEDIAIRNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 92F90B3E1AD
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 13:35:19 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-55f5f3d9205sf2511745e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 04:35:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756726519; cv=pass;
        d=google.com; s=arc-20240605;
        b=cPMypsX/5kTnQ9D3jM7pJ3jYondV06U+tIk/YHwIeEdfkPJ07gzrjD7Xk+XDKzQKDI
         wEPv7daJqdp9y7it/0ZETUbblOv/+dvz5gQoFbnCRkGAA9rubVf76uB48+CMQJRIaJb9
         WwRvTVES99R91EkBAGhA/tCiTirEMeBfO7sbiFqHTuCc5l9JfcA32eAho+Zi/n7YyDK5
         13FTnn/5WDeMbzbVd6IduUOcOLLYwTTupNyozhd5YkZOJ1G6kS7YYPehNvAFdrRuBgV/
         0nqIar6UMYYfGD0lHLp6FMgpkow8PMzJJSwjEjCsDZJOVWa4gRBLs41f4K2hTMG3olWA
         +cfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=H+9Hpv/mpnJB1WlpJpmA4dKPqwjAm0U3Oa33TNoU25Q=;
        fh=KVWqKCuC6/rX6Ewj4XhXlc/a/YBHpzV2RWiO7QP1do4=;
        b=f/n0e98RgosS2Y7IeW+rGlSmnsLmP2b0kKssjaBPjr8VFkmiVXDX3jAoOa2csl5AID
         WkIe8CrkdzaLc3+Zl9DeAmyuKtcXRy+W68LiK+/VFy/oMDtiu7zAvr//uuHsaR6QQKnJ
         BSgYh/QRJQ10VytvTHa2hcqwImKQaz/VqL5XP/KXcyanOEuo7PzzvwdiFDpUnTSHC3e2
         wXBW5FOYmaV29y47qwJDUt50/EMXf1KthCq/PLxD2FVqcHL29z05kodqbByErewvWAre
         tCTTwBkZZIYj3aRNpPt0pLS59Qwimcjeheqdwd4YejVnGoKUXi1RWAMVWA1fXe7L4nGt
         HcuA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Oi4kPtKW;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756726519; x=1757331319; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=H+9Hpv/mpnJB1WlpJpmA4dKPqwjAm0U3Oa33TNoU25Q=;
        b=g/PyKcyuLuNCtBpIhazmg5jNtkCbN1kJiS3b2WC/RBgAzS/F1cLCFmggLnOSU3HnU3
         5s/fiFIA5t8CCy4KI6dsaNVZKUKZC8e0SssWUvFfGVcsv2i7jdpCSc6Ob98HU1ptTsrS
         pARAtsziWKO3Qli3UJePcwnr2Aqniy2ED0zrrf38Ikgr82sX12ebsvyBRBIHdldnwV5R
         YJx9GeJ2wt9P09MZC1G3+Gjrexe2GJUBrec2vasey0fSOa1HPflXQTG6ebxWqJ5r60OP
         7JOPxSjaQLxvVrQMKmHRtE7UM9+CqosMYh7bcvfYuEsqUVqTaBQ8CA5Yx/Y0mqriqZiQ
         eFiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756726519; x=1757331319;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=H+9Hpv/mpnJB1WlpJpmA4dKPqwjAm0U3Oa33TNoU25Q=;
        b=cfiDQqTFwvNqU73FrGlervV9ZvoZtUnJGxKfiIkhP5h+tUugmDdDNyZmu1tYAbwiGU
         cyNuxXRf0GDYAz+djwfd1gVB1emzFvYK+fW+U61ZMmIMDDGpyT/zmMxxk7xyJRE7kKiU
         Br3OVEzeN/O0Bk9AzBO1Ws68p9vDzUpChIQ4n6CYcHsbm4OXhTD+JBQ1gsmuRfJ7N7La
         OH3z5ppjIdIH74uwb4poFwx/CCmdJSLFSmAHKvUcFYE8huA4no6YnIhlx4Yts5QFZD19
         TbFmOHoNai2u5/Zky6eRi1JPpXZWcVpKIzaTLKlZS9xx69LuCpzRs88LUu9aKCHj8UzS
         snLg==
X-Forwarded-Encrypted: i=2; AJvYcCUhaDkJKxDsc9XcL+RWAN6VOgkPOoOMUUe91zHWLjWyuDJQzESJMwsebHj0GzXOPZ1SiFU1Lg==@lfdr.de
X-Gm-Message-State: AOJu0YxYeKwStZjC/bLtdQGRLeLvgvqK1HgpDZ0dx3CTjkqZrfPrqACw
	phwl7ituIzPQeVJa6wTrV0AdPoS8PuGuHz2Km7XdBNZngJWNNIaWw3+F
X-Google-Smtp-Source: AGHT+IHD9LYrbKaZ1AFsjBe5YskiLFQpvOZ3lmUN04u9hY2PaQ9KV4S+ce8jiqclFxprX/CwgypfnQ==
X-Received: by 2002:a05:6512:12c8:b0:55f:44e8:4741 with SMTP id 2adb3069b0e04-55f708c12f8mr2447230e87.11.1756726518108;
        Mon, 01 Sep 2025 04:35:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfY7Uo7Belf/lEe0Imk7tCZ61H77JtMuHERWtbtCaDlJg==
Received: by 2002:a05:6512:6399:10b0:55f:4af2:a581 with SMTP id
 2adb3069b0e04-55f5dd0b26els488995e87.0.-pod-prod-00-eu; Mon, 01 Sep 2025
 04:35:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWGj58+63PjM0JETsiHn1ErvSI/BpGjK3xuLJ/3XcWA1tj5IZTyqkExNVShHR0imwKHPEloamnSJUQ=@googlegroups.com
X-Received: by 2002:a05:6512:3d8d:b0:55f:3ae4:fe55 with SMTP id 2adb3069b0e04-55f708b1875mr2343893e87.4.1756726512473;
        Mon, 01 Sep 2025 04:35:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756726512; cv=none;
        d=google.com; s=arc-20240605;
        b=QY8S2CQg4iZjVbeJdNAVnYYQWJoodJlUf7mc8SwTlagiiC9UJdG1DkUdAknN/PvrWL
         7aFaUvYmkt0Zl+H/Xhs+vqdqtGVYdgEH7VbcAclMSnpyQqWj3gC6REY5GnAoOtnDNcZo
         WeDSBOddJNjfBpDHNfuto4aUzXGM919D3r9bYwbaVYpUQgiwxx5XkaNpcFLujpimV3vO
         Sbjp7kUauL2LZytnwxrFPRs9xhWPQikrLaYs6EJjsSfC2cOic7YWM/uuCtskEnX7TwYp
         fKFS2t1KDaZzDOhb9zLugCAXArk+Lda1VI6t1Vd6EVQAtLUBs3zbzAVHxbThgtUl/+Jp
         Xrzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=89QceRiDVJR9qzpuoMtjZ42nHjE3zxx93/plzyge73k=;
        fh=OwslRIDaz2pKpxXV2BXZKY6xyyX8Z0saL/Rx6uckNXI=;
        b=Plge4TBRGuRCJ3+vyZL8XSOGOqRJVqRT2Ov6oHFbltycSK2i36GKzKXNg1OSO02h2X
         zuWtaGqzXV8mDpaa0nNmIRZGoILKX/sXQlYggA5mzi4Z1cA7CbgdiClyMhC4pRzt/Fxs
         d6LhN8xNr4piz3PL3LxMxsHSfEBySCUJx6p6ocTyQFZF1H2elvAjWgz+x/PgJX14LUlN
         lOEp9QHFwVPYhiLkc8pRETIdd95gZvhS/Ljj6W6r20KJwHbXkJFtAsoD9xntiKgpimLK
         GTSuLP7jNxdjm6+hHXZKOm3WfrGjZU4xErM16QnqclqtWTmjystZG2Vq+cN77j04aD1K
         sf9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Oi4kPtKW;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55f6764f4e5si199191e87.0.2025.09.01.04.35.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 04:35:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com
 [209.85.221.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-362-NqjiMBWJN7mKuZI449MFTg-1; Mon, 01 Sep 2025 07:35:10 -0400
X-MC-Unique: NqjiMBWJN7mKuZI449MFTg-1
X-Mimecast-MFC-AGG-ID: NqjiMBWJN7mKuZI449MFTg_1756726509
Received: by mail-wr1-f70.google.com with SMTP id ffacd0b85a97d-3d48b45fad0so881953f8f.0
        for <kasan-dev@googlegroups.com>; Mon, 01 Sep 2025 04:35:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVTsa1kTGl/1Jnffb/sL1PmToudGpCIuVhXxarucO2pAGknasrdIBpoEhccUJafEnXjtDpIcaNnw3Q=@googlegroups.com
X-Gm-Gg: ASbGnctVlSwBYaaYpRvoCriSQroq2tTqrIcs4zisZjC1e6JI83RQRfib2l3ZAvIA4f7
	fdT/O1y64wmOHdNlO5m2/FHyY1XFRuxi95eNRdIVsmo0la5ugFBvSAzKBy+OrOXaMqDmgThiSPv
	1axHV8DZ5O4MPEJilFIiPc/LXg98Q5KIfh4tCg4XPd0W7i00JEIwXeqauFEaObN1nv6g07TepST
	3yErRTpAxoYi68s4Iq1sSPVsEt08/p2DoiVTM+1P0hVIL1tX1TRjjBZsT8kt43N+44P7+nuU4hC
	IyLAfB74ak6nV2uAwL8BXTyr3EWF/Tp5/IGHrRkbpin9hK594r21TKXqfx/mFMIFTXRLd9Mbq06
	l6qDsYgppKhoHUMb2AQoppRgZgVnKBqBLl1ljZUUp1LXF5FeCDxyQxHqp+2eAlPsW+rA=
X-Received: by 2002:a5d:5f8c:0:b0:3cf:5f17:f350 with SMTP id ffacd0b85a97d-3d1b16f0165mr6056390f8f.18.1756726508804;
        Mon, 01 Sep 2025 04:35:08 -0700 (PDT)
X-Received: by 2002:a5d:5f8c:0:b0:3cf:5f17:f350 with SMTP id ffacd0b85a97d-3d1b16f0165mr6056350f8f.18.1756726508320;
        Mon, 01 Sep 2025 04:35:08 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f37:2b00:948c:dd9f:29c8:73f4? (p200300d82f372b00948cdd9f29c873f4.dip0.t-ipconnect.de. [2003:d8:2f37:2b00:948c:dd9f:29c8:73f4])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b6f0c6fe5sm233831875e9.5.2025.09.01.04.35.06
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Sep 2025 04:35:07 -0700 (PDT)
Message-ID: <44072455-fc68-430d-ad38-0b9ce6a10b8d@redhat.com>
Date: Mon, 1 Sep 2025 13:35:05 +0200
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
 <632fea32-28aa-4993-9eff-99fc291c64f2@redhat.com>
 <8a26ae97-9a78-4db5-be98-9c1f6e4fb403@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <8a26ae97-9a78-4db5-be98-9c1f6e4fb403@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: OOwJrygS2yXgeZCpPU5Qut-f6uClqabtRQd8358J1ls_1756726509
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Oi4kPtKW;
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

>>
>>
>> The nice thing is that we only record pages in the array if they actually passed our tests.
> 
> Yeah that's nice actually.
> 
> This is fine (not the meme :P)

:D

> 
> So yes let's do this!

That leaves us with the following on top of this patch:

 From 4533c6e3590cab0c53e81045624d5949e0ad9015 Mon Sep 17 00:00:00 2001
From: David Hildenbrand <david@redhat.com>
Date: Fri, 29 Aug 2025 15:41:45 +0200
Subject: [PATCH] mm/gup: remove record_subpages()

We can just cleanup the code by calculating the #refs earlier,
so we can just inline what remains of record_subpages().

Calculate the number of references/pages ahead of times, and record them
only once all our tests passed.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
  mm/gup.c | 25 ++++++++-----------------
  1 file changed, 8 insertions(+), 17 deletions(-)

diff --git a/mm/gup.c b/mm/gup.c
index 89ca0813791ab..5a72a135ec70b 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -484,19 +484,6 @@ static inline void mm_set_has_pinned_flag(struct mm_struct *mm)
  #ifdef CONFIG_MMU
  
  #ifdef CONFIG_HAVE_GUP_FAST
-static int record_subpages(struct page *page, unsigned long sz,
-			   unsigned long addr, unsigned long end,
-			   struct page **pages)
-{
-	int nr;
-
-	page += (addr & (sz - 1)) >> PAGE_SHIFT;
-	for (nr = 0; addr != end; nr++, addr += PAGE_SIZE)
-		pages[nr] = page++;
-
-	return nr;
-}
-
  /**
   * try_grab_folio_fast() - Attempt to get or pin a folio in fast path.
   * @page:  pointer to page to be grabbed
@@ -2963,8 +2950,8 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
  	if (pmd_special(orig))
  		return 0;
  
-	page = pmd_page(orig);
-	refs = record_subpages(page, PMD_SIZE, addr, end, pages + *nr);
+	refs = (end - addr) >> PAGE_SHIFT;
+	page = pmd_page(orig) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
  
  	folio = try_grab_folio_fast(page, refs, flags);
  	if (!folio)
@@ -2985,6 +2972,8 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
  	}
  
  	*nr += refs;
+	for (; refs; refs--)
+		*(pages++) = page++;
  	folio_set_referenced(folio);
  	return 1;
  }
@@ -3003,8 +2992,8 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
  	if (pud_special(orig))
  		return 0;
  
-	page = pud_page(orig);
-	refs = record_subpages(page, PUD_SIZE, addr, end, pages + *nr);
+	refs = (end - addr) >> PAGE_SHIFT;
+	page = pud_page(orig) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
  
  	folio = try_grab_folio_fast(page, refs, flags);
  	if (!folio)
@@ -3026,6 +3015,8 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
  	}
  
  	*nr += refs;
+	for (; refs; refs--)
+		*(pages++) = page++;
  	folio_set_referenced(folio);
  	return 1;
  }
-- 
2.50.1


-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/44072455-fc68-430d-ad38-0b9ce6a10b8d%40redhat.com.
