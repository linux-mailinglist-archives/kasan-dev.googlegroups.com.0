Return-Path: <kasan-dev+bncBC32535MUICBBQEX5PCQMGQEMEYFGSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 2874FB45686
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 13:38:42 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4b3415ddb6asf57579201cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 04:38:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757072321; cv=pass;
        d=google.com; s=arc-20240605;
        b=IX64r6klv1jeWS9Qho+p5VlkdZP8pplwQucmN9raCNPy1zwjT7JBY8jITk9QoH11WX
         RQOl7yVP10IX1QHsDLlCSwpudNh2qzJgW43qMCqeVxaqZ+uH9W9sOikA+2oUJ7G+DBm+
         3j+TIXV4xgYe++pCCueKzKa8XgsWS67j85LyuK0VgmbEBHZNVUW0NTL0xFrWY57HP6xM
         KAyb8J6wnBLXHgqw78N0/wpZ9UzXptc8IF0v9wEVFYAZcTCduuajj/guQpFhKVJKHDO0
         Mp/JYqrG9ANsMIPhaYLqqAywAdbj43fDj2eVgniMH4ObjVhcvwT+EF6Ju1FN3kfrmIUd
         vFRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=rJ47zoSCYHJYZKBMx6ugr/GGkwRrCMFwDJE1TuRKtso=;
        fh=yk2g5owtzp4o35m0eqbcsi0S8NujZkQ8ey3voH/FsNg=;
        b=Xbc+4vegby63vyA3FoUPU8PZ5z6S1zTWKt8L2kg8jk3juuESF2Er2CNz8owZtN2T2E
         3OdCUffqBgdUl+b5W4kjcIy8TRCrBt1eFARVvxPxtja4K1/u+FD4U7R8cIvqE2oigEfR
         mTd1VAzsJQ47F0m29tXXwQS1KjXgbTYB6SflaJRfF3lYIJySNCYA8uznVkpA0c3AwWyD
         kuzouHt0jd/WY7LvwrnuEPGvk4yId2nSWmeONKQmddenzB4CspOd4z/mTarjxrx48U1I
         C9UrY4XD0w6cGsEOiXRQ4xp3bMjxk5v1xlbHR0nu0vIB+edLIrNUjqylrV5xwyyL4vYn
         om0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SAtz4rNY;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757072321; x=1757677121; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=rJ47zoSCYHJYZKBMx6ugr/GGkwRrCMFwDJE1TuRKtso=;
        b=puZvIguUaExMThr4lmRNJEgwSwTlTlXR4GyKNhDkrzd/gvAxFsYsin5NIB9utBpWWU
         4L47jOdCHkGwncWR9I4TtOzArEC6nX+Y2aiECqUuWwMKdFmoB5vg3IDEZhXDtDr8xh3P
         E2cl1BO0qynkmXWC4JGLxnPEbqdYfMirrhx6M88eN82RRGud1k/1GAf7pg51kaF1zr7q
         i+3jdxN4qVY39ZG759yyTvcXU9wNdrXSfFu1pW4U6zYPpVYZEjgyBqurXGtLXqMUeb7+
         CJpa/zHnSYfx+D0OV9lUhfnpWgDCjwIVoHBeAOGxRPXBEOgdwRfQfAx15LJ28vPyAUSZ
         o/ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757072321; x=1757677121;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=rJ47zoSCYHJYZKBMx6ugr/GGkwRrCMFwDJE1TuRKtso=;
        b=PpcL38O+1W5DuMt+LXHfMy54ysz7159f5Lm+OMyRGhTwtNlLishA9YDThEOFbKhDJi
         RVip+jXMV3zC3Jj6wPzLCjYDI0GlA3JVtlXVAyN8AGNX3u3iEK8xTHMCF+XRW+afaggn
         mnMjG+B6D0XtxK0YqEo7b/DlavWSxfviSPqW8aMzHXcun19YeXI/etCm9vxp0FDMGEPI
         jtXJohwzEzItZ4wxGlTno6ZiLkYAWt7vN9NVpG35JJaVmsi3ViJBJNVIRl4xvKTFYqIr
         WkyumxyhJaiwcRdXRRg7oKax+qmi+opTbrDwUdhktERbw8VIBKcpnmHo+08pi8bHafyc
         Gu6A==
X-Forwarded-Encrypted: i=2; AJvYcCVrauvgkqVcuXRytvRb2h8JfLy7z/6CNvdrYmNprtjFDS7rUBcG/2xubCt/zEm53ubKfxffVw==@lfdr.de
X-Gm-Message-State: AOJu0YwKF6BvWukc4jTWmCrn/VOODMiV6rGaXvwhSZmFUnpsEmHT8ESh
	UkdML3BkLf124LDU22w8LgKBL7gVtrH/XShXtKe7Ya0QNwqr/GG0bbWZ
X-Google-Smtp-Source: AGHT+IEwzCgFIPAgMQ+rskQKOPXkk/+X39wKBFXPF/WbnkQGyKVxUVBdN4e61zL445ASacqAA9SbJg==
X-Received: by 2002:a05:622a:1a16:b0:4b4:7b34:1dc4 with SMTP id d75a77b69052e-4b5e7d0bc99mr32016971cf.13.1757072320866;
        Fri, 05 Sep 2025 04:38:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcnOylmEFziEsL1Omf+7gZmanhdVLW44dAxu81/Plo2+Q==
Received: by 2002:ac8:7d50:0:b0:4b4:9807:1037 with SMTP id d75a77b69052e-4b5d70927fals15615481cf.1.-pod-prod-00-us-canary;
 Fri, 05 Sep 2025 04:38:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVwPCQ4vQ8rDaR/a4fqt/NGoWgRQtXrgoY5dAy1Dp6b48KJ3J5Nxi2wGUDUg1DOPj/9xdFpEsOyfzU=@googlegroups.com
X-Received: by 2002:ac8:5e50:0:b0:4b4:3789:53db with SMTP id d75a77b69052e-4b5e7cd3ab3mr42428691cf.2.1757072319603;
        Fri, 05 Sep 2025 04:38:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757072319; cv=none;
        d=google.com; s=arc-20240605;
        b=dnxPGo/oZCO2jIPNKYBzgaAv0hTj/iu28R+LSY/KlmSWMxEoGI2QoF9M5BqRwUhFgw
         WN8OOzNMIrEYy1ybhkPwayJGyvGGzGffv8wUWf+Y1dJluluHEvyLIdoIMvARo+QuJfO4
         1beh6uS2YnSSmtc+SQbTGjDUxZtDPlD9rH2AOaC5oEB7X7Iayag6guEA/qWKdkmVFhMt
         lkH5I+obCtUKu1DE59ZnhDlb0hAU8+BSwS0gf/u07pL1PytSXHGL4m/wa0YhRgndq3U4
         RiPafWJXM+jnDD027h2HgE925ciD4FWlZmE8S5V72LI1LpIQmyy++/t4YrhxBlApa2Dy
         rmxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=luQGhz3W9bQvvWBMkQH/XO40AxL9T26r0ebxy/p3+ys=;
        fh=CVX19caQeXR3ZfZng5mhVxOSCf+F+fDDoOJWxBkMfVY=;
        b=Z9xJ1nGANAEuPlPHhsqy5tXP9EdeS6Wp5YNJYMXAd8MNIl5pj9Q6wnqVrtq2uCmz9W
         KxF8v5bkFYfvqKLyN0EE5LQ+W9OiMExcfHrAsCd4fua2drXlfqAka2vM6HbSfY48lagJ
         UF/23c4zS3APa8WKlIYlzP7RkCQDpevp7b3Cb9EpLrxvhxJ4/L4C/cqpbFXneNSRcjgD
         xft0FpioK6/lw6RtezF6Tkm9yJFB+q0bahihkAKDXGhNcZFe1XWDMgoxe89FD97ZnS4R
         a43ipLTqeM7XdpxMMQWkX59k88SG9f2nvrgU7YQFaKwCYEY9Jy8/ncWXiFwKQidXJ+hb
         75Hw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SAtz4rNY;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b48f78b3e5si2865881cf.5.2025.09.05.04.38.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 Sep 2025 04:38:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-657-5pC2LkKhNyOtqgRGPO5y6A-1; Fri, 05 Sep 2025 07:38:38 -0400
X-MC-Unique: 5pC2LkKhNyOtqgRGPO5y6A-1
X-Mimecast-MFC-AGG-ID: 5pC2LkKhNyOtqgRGPO5y6A_1757072317
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45dd9a66cfbso4118405e9.1
        for <kasan-dev@googlegroups.com>; Fri, 05 Sep 2025 04:38:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXAp1QYxZWu+fuGfH07/uVgOl6QuUlqMKMhPgdqwubU/MnkiS4r4UtG7Zsw0kGtZdMs8ymAxRQH1lI=@googlegroups.com
X-Gm-Gg: ASbGncs8OK0cTMc6ryKp4X+fiZ0SjWtHSqReNhupHveYtsJOy8K2GRb4A8vW/aKKvuA
	XHeDnAh02w+SwaMlDyW5TWLk54+dfasj0BVNgIjzClGURAkZEC8l1ExtFNp+x6akT0VGqzxXXvy
	aFuar0QuXyJtoRpKcKRMcSBF+ZAqSSYIdJta3CtR+CgrISK4Ohz3zy6WzGEfX9mDO/S2n2fepC0
	iw81dxjEdUfwVbLEJR0hm1vCgSMb2mvs3CJphqqmjHsp3DMp9J1HdOapBAgddLvs89IsGTXdP+5
	2fbOeZs5ZfYM9Y+KNGoSyihlvKx1I7x1owS9Ism4AA7EPXLLmOLP1OE2/qrxGphWQbSCSJcYfzs
	9BQZTspNrVx+p4/Ak4VUr0SeL/gnp3z11iYhwAFyL1Zd49KcNHArN3MGf
X-Received: by 2002:a05:6000:1789:b0:3e0:43f0:b7b6 with SMTP id ffacd0b85a97d-3e043f0be07mr5028701f8f.52.1757072316780;
        Fri, 05 Sep 2025 04:38:36 -0700 (PDT)
X-Received: by 2002:a05:6000:1789:b0:3e0:43f0:b7b6 with SMTP id ffacd0b85a97d-3e043f0be07mr5028644f8f.52.1757072316181;
        Fri, 05 Sep 2025 04:38:36 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f4d:e00:298:59cc:2514:52? (p200300d82f4d0e00029859cc25140052.dip0.t-ipconnect.de. [2003:d8:2f4d:e00:298:59cc:2514:52])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45dda2021dfsm19061165e9.24.2025.09.05.04.38.32
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 04:38:34 -0700 (PDT)
Message-ID: <9fe9f8c7-f59d-4a4b-9668-d3cd2c5a5fc9@redhat.com>
Date: Fri, 5 Sep 2025 13:38:32 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 19/37] mm/gup: remove record_subpages()
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
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-20-david@redhat.com>
 <5090355d-546a-4d06-99e1-064354d156b5@redhat.com>
 <b7544f6d-beac-46af-aa43-27da6d96467e@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <b7544f6d-beac-46af-aa43-27da6d96467e@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: ZUAN-X7vCAanYucU7We3rLQ90Lu5ByjGZxLu7i_BuRI_1757072317
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=SAtz4rNY;
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

On 05.09.25 13:34, Lorenzo Stoakes wrote:
> On Fri, Sep 05, 2025 at 08:41:23AM +0200, David Hildenbrand wrote:
>> On 01.09.25 17:03, David Hildenbrand wrote:
>>> We can just cleanup the code by calculating the #refs earlier,
>>> so we can just inline what remains of record_subpages().
>>>
>>> Calculate the number of references/pages ahead of times, and record them
>>> only once all our tests passed.
>>>
>>> Signed-off-by: David Hildenbrand <david@redhat.com>
> 
> So strange I thought I looked at this...!
> 
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
> This looks correct.
> 
> But.
> 
> This is VERY nasty. Before we'd call record_subpages() with pages + *nr, where
> it was clear we were offsetting by this, now we're making things imo way more
> confusing.
> 
> This makes me less in love with this approach to be honest.
> 
> But perhaps it's the least worst thing for now until we can do a bigger
> refactor...
> 
> So since this seems correct to me, and for the sake of moving things forward
> (was this one patch dropped from mm-new or does mm-new just have an old version?
> Confused):
> 
> Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> 
> For this patch obviously with the fix applied.
> 
> But can we PLEASE revisit this :)

Yeah, I already asked someone internally if he would have time to do 
some refactorings in mm/gup.c.

If that won't work out I shall do it at some point (and the same time 
reworking follow_page_mask() to just consume the array as well like gup 
does)

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9fe9f8c7-f59d-4a4b-9668-d3cd2c5a5fc9%40redhat.com.
