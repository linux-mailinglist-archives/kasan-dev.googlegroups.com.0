Return-Path: <kasan-dev+bncBC32535MUICBBDU27LCQMGQELSR3ONQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id ADE02B48630
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 10:00:16 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-72108a28f05sf171909036d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 01:00:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757318415; cv=pass;
        d=google.com; s=arc-20240605;
        b=EvL8bvlI2rP64HKOfAqTi8wuBdnOfKTufoEuvYlC0DgPeVx7QwAfNvilC1VFzCS1vC
         GlITpLbte6mIxSvupylQ56lLNRwBFYaBW28jD+kLisIwWSxpRU3+sFZilSpu1VpXyoNC
         V00A49IlAtMV2u+SuSGQyxbOpKVyGlDpIcQM7wPECJDZn2G4QB96iHpm8RHCs6iHIdpT
         WS4l8flYGcdqJATioXVFmZJNrusz9MKP4Nc4/1IsV57zRk/VVqH7bd9DCC4aGDfqWWWs
         J+JUJms33hYR2Ks9OOr/UyaLtakjXWmUkSmx0/xD5N1DrGLWuF6i+X5vxrHW4N+lyCxq
         3FVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=4GzxmyVdJAD8bgWPI67ydjohT0ulVUKci2ZzeIHiqb0=;
        fh=zmg9Vjbj2NEjlmPIilr1VCBTlcG8fsP4dap0vu/CL68=;
        b=KwitrKAEc2WRJIuG65iDkraRedjqPkA3RvFpeKMLP/FJEKFFXsKGzy2R46xbWR+AAj
         Mo645ZUBkC45rvFUVcK7UHudZl6vko9NRtmtEpCaiLUOle7iFp87iLucK/6ldsb+fn+F
         LVKZAYoxFd3TIiYcvmEk5TeknB+vQfffUI3TPn8QrIaxCDVd169KiI6EXFgjLvbnMVXR
         0vGINsP8pE1xUrRF2SsOUbuXVUq+hJsC7xu/osXURJnTNel7s/b31V+For/I8MnzZLYn
         oiGFRwaHMjdRUmLKn8+Rd5FxvfCwLdxWhCw8LeXS7SLtDqUdP4VkYSHpYE2zUMGSQIGk
         UB7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=JSlQ927H;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757318415; x=1757923215; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=4GzxmyVdJAD8bgWPI67ydjohT0ulVUKci2ZzeIHiqb0=;
        b=MQNRWM+tHBFCYs+iqm9dH1tJEudaPT6EXjUfWUSAs0mHXHH7a2iCBV8/3X2aBGpOgb
         rUeh8HSVdYr8AOoRM7xnMwe9h6HCuQYyq7Aj6z3b5mPkLwhAJTyxuDzqCLtNLkm5IXCe
         ZGt7jLMNOZhxFdaVJF+/27oP8iWxSP9WKgpT5LyubvtULOe7axb11KJLv5GEDXEVK9ve
         cJZejRhzcTUa4YeVf08g0Ngw48ntKyddAULOqc0TPlnVYSWDHnptiLdJ9sq57q0mvy90
         ZKBkfG7m4R8q5LIqIP7g+8tPwooqg5x75fHrNjsdx2HHhJKcOJ5EHKzhoJ2r7mQuR38Q
         bMYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757318415; x=1757923215;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=4GzxmyVdJAD8bgWPI67ydjohT0ulVUKci2ZzeIHiqb0=;
        b=g/h6oM/5axaw1L+H0jPbLWbXyrGuDfLz9xb5EMDvpPUBudMBLnN1IglIzazEbK5qbu
         FZhz2D5SgOXFbKhAbgSOkkD1xYPA79vxIvboveGdw8C5rTpsO791d4CaOqm9pChFsXxD
         p58j+eli/IoeXj/FM2z4qRLGbilCH7lQPaXyigKmJsF4n3/kHYwFAbEm11MRrGsEqsPY
         RZjCoA0X1hC+r3NHpbsgtLf3Jzu3aC3XH2iVhM8SbAjVLoJcsEQjk+2u+BXGVPIjWLwy
         7yq0mHtN8aFA0lulngvnBXHKFNkWmEta0nkT/7G/UY8nZcFAzkPzYgtfoRNM46ZoFzVN
         AsNA==
X-Forwarded-Encrypted: i=2; AJvYcCX4FNxaB0mPKzqRNCOfHJuEtEoB5n8geK2mtGl5JhpAgJCejn4dHewB2vFZnF6dBR34TZaH2g==@lfdr.de
X-Gm-Message-State: AOJu0YyrS34tYfF9CzSQ3QVYEJQ5gACefycKYnzQjZ9ZGnvR7GYNkWnE
	kehPZZSzj/3rKKcg2yhmM0ZTAiHFew+3dARRWMBthnoG+eRj92T0y2k9
X-Google-Smtp-Source: AGHT+IE5L94f7XljnEIUU3oEk3kqgjfop6zR+bHc/18sC08g4l64Yv41kzr7bx9Qfl27RimuAzm/ow==
X-Received: by 2002:a05:6214:2b09:b0:744:be95:5ba with SMTP id 6a1803df08f44-744be9507afmr42359166d6.6.1757318414961;
        Mon, 08 Sep 2025 01:00:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6FsEj9xDzZaNB9wkl+GKbhHlDUWHzrzBUuTz0bYo/M9g==
Received: by 2002:ad4:5f8c:0:b0:70d:ac70:48d7 with SMTP id 6a1803df08f44-72d3ba782b0ls39595146d6.1.-pod-prod-06-us;
 Mon, 08 Sep 2025 01:00:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5pXN50VAT1Hbkvz08d5Wy3JxCQ/lP6ui/I4wzj4qLw0MyZS69HCbh6zcJuEKTkCup+xfMPanCzks=@googlegroups.com
X-Received: by 2002:a05:6122:1e04:b0:545:d756:be7d with SMTP id 71dfb90a1353d-5473cbb0045mr1688205e0c.13.1757318413548;
        Mon, 08 Sep 2025 01:00:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757318413; cv=none;
        d=google.com; s=arc-20240605;
        b=APKwcUk56TKgqB5pzUtZq5mFwgp67ClIc7LAxcocTy4zcjXzZwc8vLgm0SdynCPzjB
         GubD3HuLTwRMb6fN+ou2qTrozu5e3lHiaksVJGfg5NS+ZLErcJIlzgH3vvOZLvRkKh5D
         FeCOcLAkrPoAcnoqoTjkH0ONKHW/V2+PLO/Q/KjxpBwVeinLtL16+aGLgnDse4XW+HTT
         NeNRjaP3AfA+TconAA8zk+MFpm7u4gNAdQAiSjSS8Pjjzyf7vvHkJ4vmT8XoE6ApMZzG
         /Le1i9wToMZ0huJvFpO/R1eAqso2IK+/oagPuBs4T0GSKuwb/ETSfyEO7wpHsLiVoeyz
         Fifg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=6ZtGxzPBBhWZb8TdeGEHePc9lnXNDI+6sWWhJSedy84=;
        fh=2GjwN4wdS18QOb0wsw7UdG8Kz49znVkOX2h6w31zaPk=;
        b=FjdvBba5kK9SrVC2bGFty/ps6Tp2EGV0/2Pm4871PDcc15zZqUiJcaxq59VAKvAo3k
         M4HCzqay3iwQGqlVgZzlOzBe0fMm0Fv1U7AS1jVk3Sf7dvfoXgpwaPzvDLqy1k9hyu/w
         eKUXUhsA9f2Uxk69it2L9sUr3i8rDvht1jro6qNSCJxzYFQkzaWz6924mevQHcNe+feo
         0N/K8le44yyzMc3uFhPsIE1qRutN+BHhYOOcE7tjXwYc4UIU3IxAJKRmb+ISPhy39rc8
         600mHjYxM2VLs8p6pXdL8F2SN04Vu/4AbwU1Chh8ZiQ8tkx9683vCHIohsrMTa+bZS9T
         beeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=JSlQ927H;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-544914717b4si1085216e0c.3.2025.09.08.01.00.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 01:00:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-590-dxjEq0IIPLycZCNnl-Sw9w-1; Mon, 08 Sep 2025 04:00:11 -0400
X-MC-Unique: dxjEq0IIPLycZCNnl-Sw9w-1
X-Mimecast-MFC-AGG-ID: dxjEq0IIPLycZCNnl-Sw9w_1757318409
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45ddbdb92c5so11775465e9.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 01:00:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX209svP9np8Qn8HaVDeKnKpFQ7DpUr5P+jmBXTSsfF8TnIz5dhyDVjnL8Rjhshs6EeopY5ZPWwbgk=@googlegroups.com
X-Gm-Gg: ASbGncvQc+j+E70BjwwmDLB+tIz7tqKn6D7xEbQfoUylUG56fKpYZJ5IyIbqna207GN
	qHdmgqTGSlqG6ahC6ax7tfkt6zXSQHDf5auxxz9ULvSgRlV9hBtWaFT4jes6+zdTFaRhJtN7sVJ
	RMV01b/lbmv9yzdVPm18Ow5+2dlfiMGRdsUG+cdaITrkVdsvVls6cn357sUY0fuC8CH1WixHXjq
	WBxbtvQBzsg3loKgA2mrW/fwoSkfOtW/BXirmraZdsSjupR2mx2CFzO4oNEx9lPTajEkI+eLB5d
	prFolyMlIBvOgfdT98DiVCqdTNv5xtH18lYzWLsP2K54FmJsUVON8olNFKGnT+gO4hnVZ64=
X-Received: by 2002:a05:6000:26cd:b0:3e0:2a95:dc9e with SMTP id ffacd0b85a97d-3e64ce50347mr4840515f8f.57.1757318409123;
        Mon, 08 Sep 2025 01:00:09 -0700 (PDT)
X-Received: by 2002:a05:6000:26cd:b0:3e0:2a95:dc9e with SMTP id ffacd0b85a97d-3e64ce50347mr4840495f8f.57.1757318408663;
        Mon, 08 Sep 2025 01:00:08 -0700 (PDT)
Received: from [192.168.3.141] (p57a1ae98.dip0.t-ipconnect.de. [87.161.174.152])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3e740369f1esm6798834f8f.11.2025.09.08.01.00.06
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 01:00:08 -0700 (PDT)
Message-ID: <28fc8fb3-f16b-4efb-b8e3-24081f035c73@redhat.com>
Date: Mon, 8 Sep 2025 10:00:05 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 19/37] mm/gup: remove record_subpages()
To: John Hubbard <jhubbard@nvidia.com>, linux-kernel@vger.kernel.org
Cc: Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, kasan-dev@googlegroups.com,
 kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
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
 Zi Yan <ziy@nvidia.com>, Aristeu Rozanski <aris@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-20-david@redhat.com>
 <016307ba-427d-4646-8e4d-1ffefd2c1968@nvidia.com>
 <85e760cf-b994-40db-8d13-221feee55c60@redhat.com>
 <0a28adde-acaf-4d55-96ba-c32d6113285f@nvidia.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <0a28adde-acaf-4d55-96ba-c32d6113285f@nvidia.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: iIBljRg2H2zhSiPxyHgCOLBkqvDD5Fe19XLYnzLXpNk_1757318409
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=JSlQ927H;
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

>> Roughly, what I am thinking (limiting it to pte+pmd case) about is the
>> following:
> 
> The code below looks much cleaner, that's great!

Great, I (or Aristeu if he has capacity) will clean this all up soon.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/28fc8fb3-f16b-4efb-b8e3-24081f035c73%40redhat.com.
