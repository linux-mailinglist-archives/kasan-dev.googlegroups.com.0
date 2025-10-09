Return-Path: <kasan-dev+bncBC32535MUICBBTE5T3DQMGQE5BQOF5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B444BC87E9
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:30:38 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-818bf399f8asf27254546d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:30:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760005837; cv=pass;
        d=google.com; s=arc-20240605;
        b=fKcXfnTcIAmovXkuLCP0AK5nA/Pt4QAWPtJK0abD5IOsK7W6Jy4WPZ7NHQ4hEPzMt2
         8RK/hNrcdMzKMpQ+alWQLuDXWKI9nN6++OdGs1wdY8Dks/52lst2sKL/0YLBR4RoJkDA
         K/MuWXs3rJu/Knq+BeRPdXfSWhmzHIVZTGYkqQs1jYLmkNRTZUigqua4p/rbRG3YIGd3
         SIiAawOBBwlpxD4PiNN0agQBvmXolaAuprF1qKZLoWnKpdoh76fCSoq2pcBs36ZekVf+
         0nXkGp6yB4SbyqIibpEFI8v2hBVRKkvV1NTVjpKxmLAZ5zWyaLBdJTGyGgBHV2kiGWgw
         faeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=UGkHcqRpkcf2lUbZejnZrKS3VaCpySeuEjdKsIl0PyE=;
        fh=xmTVhutf7gEXD5G1Qsf+VKQTlOoEBahijVCFqF8VJ4o=;
        b=Bc4ykkZOVel3JHKPmKY1LnOzF+xjUCibX7eisvJ+l7xjNuuApsvSA+fQERBO2wTgcD
         1ksb1GEEiY8JXxfTTdiEbRdh4Eq8qxYVmOtpp5+AkjasV8Vunw5fKhzswBNrgR/fEImE
         H8RezeOoJ/u0svQ1vnlZDnNztR5bXNiqG2hO3+vYHxga/n33yTHDEBg3xYlksV6/28V2
         NXl05JI/qYU6N1GVGoHfFoc6Rli6xZR1oyV43INanncUwhEW/59P0iK9D5kgVCvUaCcZ
         kLlvIN02/YrN51/hkBe/l/Pt1QxqXO/i7Z5uHggtaT6D37iEvErGWVMeC5DkfV3vdMgc
         3rDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QhNlqUuE;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760005837; x=1760610637; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=UGkHcqRpkcf2lUbZejnZrKS3VaCpySeuEjdKsIl0PyE=;
        b=ETEywAPT0MRrnFE9d5oJhy1OgqUk/tWLWD4j10isx+blfDNfThFZkm+UdUm7+p5dhj
         cN6z40AeWpu22BP+o/z90MdNUlcfwFWh5q6nDp0cYyRysS/IDVo+nlXmCaY9IpWoxmLj
         neokVPf8p3xW7aJ47lujEnjVQ75SfR1s05i7ScHuI5LsB4VIs+JIWRD1rqeKqhouY8eC
         ab65iLR8ik7zFuYRvfFoUEY5QREN5382Jx/NZoJCQw7L7RqfBtmMJF0uzZW36UQrIgnQ
         Y5AbgCL7K6bOSyBsHk0KhJS/hn03+bD7d+qC2sjEHPVaqKCVScylWFmmnumQI/9HerCL
         8uKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760005837; x=1760610637;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UGkHcqRpkcf2lUbZejnZrKS3VaCpySeuEjdKsIl0PyE=;
        b=GiCU13p9ixwHPGX+1qWUfpNwViA0V3X2ShPwu0tp5Vl2sjhWmyUucPJ126/lydUTFS
         ePNUYMNoIiNGKPo01FYU0L/TBjc7yFcSEBs4XeX8hbKHLSTJ3OH+89V6pA3GmGKGcHJ7
         GmKPBztfFxgD+7cIAi0ngWWAq6CZAJKb3iQTxyGTWrWdVXNXtGO6O2wxfpONSqup6GUO
         r3KymIekLQzXKg0tfoe8bZ8IIFwd1wRyiD5ky813UANVF9MMNz9oHtHn/1n0T7rvCw2J
         uKFzvD7Z8lBRx2O0+zW3bvjjHe9wwUl1S4xKPcRQJ/XY3hHpGaE9t7ipvbaK5HOe5UnE
         6fTw==
X-Forwarded-Encrypted: i=2; AJvYcCVqqN4fYRZZ5ChuLpuXfV7B6NLF6rwcSumW3jvLIzlDtyKhQY+1IhCibYKIy19EVdMQ7kePOg==@lfdr.de
X-Gm-Message-State: AOJu0YwDa8m3ZxuOyJgKFUWLqGUDwdC0SQWth/4/HVlQnOPlH1yEQgGP
	vqBZTLaFpACBN3zAwnh0ftCt/MbtZhFBUA24JVljZQSDnjdQDgBX0AUC
X-Google-Smtp-Source: AGHT+IFyZXNV63WmoB8MVgcbQ1iqP+6au5LctHvmFkkj8mrMPgWe6jYd4rUiIuTmFGWMfnEBIixXxQ==
X-Received: by 2002:a05:6214:32b:b0:87b:b534:b3a6 with SMTP id 6a1803df08f44-87bb534b737mr24024756d6.1.1760005836859;
        Thu, 09 Oct 2025 03:30:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4IOU4Bdq7qIqMPc3KLwje0MJlnZu1yv69OeAkMUj/a3g=="
Received: by 2002:a05:6214:8103:b0:70d:e7ba:ea21 with SMTP id
 6a1803df08f44-87bb4feb739ls12207066d6.1.-pod-prod-09-us; Thu, 09 Oct 2025
 03:30:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUS5EkrRg9OVGaQsSmcPpnWKjWLIAnG6fO8zrb7ZvRLfN+57UbXQXPItxeCZjM2tV29/0ij2/81dog=@googlegroups.com
X-Received: by 2002:ad4:5ce2:0:b0:86c:a1b1:8485 with SMTP id 6a1803df08f44-87b2ef1e1b8mr95360266d6.38.1760005835805;
        Thu, 09 Oct 2025 03:30:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760005835; cv=none;
        d=google.com; s=arc-20240605;
        b=Hyle4FI6Z9VRN8JTbkWfERkrCkxdxQvJeRVJ1s9++fVGAgZJ07ZeKSVfpn53iSx/G9
         kAvT8x1x/+7xaGzl4/YxdKSksyNCKHhby+AJ6WvNaw3iute0i69vgbudx6EsfEvOZnk5
         BtXwgRPf/zW0lvAZi/UKZ5fOyhR/KI3lU6U2/jsDD85b0rhTXJERyCy/VScXNqncmif4
         09Bu9kUs2v/O8Fv/hvqRWLeu2kkeBckeaACD9SV+D56/FtWs0gbYg/lt+dSQKbVmWSNt
         t7H++YL1k1ovdTbYcE0Hfg0AbXJlme/0zWhwKXPG3+ZYXud8g05PiNtQNceW7F+5Ijh/
         OSuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=5kNnaE3wosVbbZxnmP0sVKpcafEUi286yAMPQXV2QSw=;
        fh=pg7I6DUwBMrV3hNF609JwLLL8Lw5IIjtFi5rTATf4SA=;
        b=YahGieDRIRvaIHiae4lKqWk+QXxB8X77q9aEQQ2jSwoHnVgQ2T6VMuiwXSqnyKBGPN
         Fgg/ki/t3oPMZzZ/XwtDKRNuJz9nZ9ZVYsK7BNmPNBY9T7T00lJElSn7o8vKD10VZqbt
         Tlx3HqYSm5Qa92QoCW+LDtAXsmWowUZPHUt/LkSy8YwwlJw/N1859UomZSrv4VcqcvWG
         9RkGamoJfi5zmC70zTc/fLvxkcAS1DeW7knC4p6Zhvom39kEle2NBl4Q5mpLQLXvWjeD
         zGc28KakUs4zqp+pYsbbcuV6EKLA29lHx9WGTp2jn18uDkkKFy3x44rHv2zj34oSKOgK
         ejgA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QhNlqUuE;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-87ab6c1567csi939826d6.6.2025.10.09.03.30.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:30:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-650-c5YLEl0uOCCBolz1Q9N9vA-1; Thu, 09 Oct 2025 06:30:34 -0400
X-MC-Unique: c5YLEl0uOCCBolz1Q9N9vA-1
X-Mimecast-MFC-AGG-ID: c5YLEl0uOCCBolz1Q9N9vA_1760005833
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-46e2d845ebeso4194465e9.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:30:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU3Sf+Z2VdBvOTQdg56Z/EbbIS3U7Ep4pSueXJ+AUn+5s4iDS11axok/6Y7IoIzWPhmU8HSOe6mHFs=@googlegroups.com
X-Gm-Gg: ASbGncsUYdNGS8tx/77q/2NnlTRrSF/eS1KBrU1nS7s2fKjg6SzAOIzG6/GeKfixraK
	GDtjRzVymFltwzsAVVG7utKGmGbki3KjjjeW9F7MXOWJjWciOr/mEnsA0pWR8eXWbZN1juqtoW8
	JXSbrDah+rqyFDqbLKMuYhHy+pdLaGQydZ4eQ57YEM6x/3LLtLxC2FIxTUiU0pSOqdmLeGaZpVk
	RXaoBwWUtXhybyHG9gjaKH2u1jQEm74m2+/ynivZUJgS9XdBndiv9qxoM49PS8PGzvXcrXLFxI7
	ciL5SK4E0vxSaFmV0k3iggmPOD7rn0lW+mtgl+9W5vAiZ5FQHC8aDcw5m3adLISd50hBkb8WQzJ
	7nz8W7/xm
X-Received: by 2002:a05:600c:8b22:b0:46e:4882:94c7 with SMTP id 5b1f17b1804b1-46fa9b02c6amr45782505e9.28.1760005833112;
        Thu, 09 Oct 2025 03:30:33 -0700 (PDT)
X-Received: by 2002:a05:600c:8b22:b0:46e:4882:94c7 with SMTP id 5b1f17b1804b1-46fa9b02c6amr45781975e9.28.1760005832588;
        Thu, 09 Oct 2025 03:30:32 -0700 (PDT)
Received: from [192.168.3.141] (tmo-083-189.customers.d1-online.com. [80.187.83.189])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-46fab3cc939sm34647705e9.1.2025.10.09.03.30.28
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:30:32 -0700 (PDT)
Message-ID: <7d82cf5e-f60c-4295-9566-c40f6897fce7@redhat.com>
Date: Thu, 9 Oct 2025 12:30:27 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 06/35] mm/page_alloc: reject unreasonable
 folio/compound page sizes in alloc_contig_range_noprof()
To: Balbir Singh <balbirs@nvidia.com>, linux-kernel@vger.kernel.org
Cc: Alexander Potapenko <glider@google.com>,
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
 <20250821200701.1329277-7-david@redhat.com>
 <fa2e262c-d732-48e3-9c59-6ed7c684572c@nvidia.com>
 <5a5013ca-e976-4622-b881-290eb0d78b44@redhat.com>
 <a04d8499-85ad-40b4-8173-dcc81a5a71bf@nvidia.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <a04d8499-85ad-40b4-8173-dcc81a5a71bf@nvidia.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: huevE7nf9YvamQNH3tUTQZ2DnqiAQyQ5FXbSu3GuidY_1760005833
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=QhNlqUuE;
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

On 09.10.25 12:25, Balbir Singh wrote:
> On 10/9/25 17:12, David Hildenbrand wrote:
>> On 09.10.25 06:21, Balbir Singh wrote:
>>> On 8/22/25 06:06, David Hildenbrand wrote:
>>>> Let's reject them early, which in turn makes folio_alloc_gigantic() re=
ject
>>>> them properly.
>>>>
>>>> To avoid converting from order to nr_pages, let's just add MAX_FOLIO_O=
RDER
>>>> and calculate MAX_FOLIO_NR_PAGES based on that.
>>>>
>>>> Signed-off-by: David Hildenbrand <david@redhat.com>
>>>> ---
>>>>  =C2=A0 include/linux/mm.h | 6 ++++--
>>>>  =C2=A0 mm/page_alloc.c=C2=A0=C2=A0=C2=A0 | 5 ++++-
>>>>  =C2=A0 2 files changed, 8 insertions(+), 3 deletions(-)
>>>>
>>>> diff --git a/include/linux/mm.h b/include/linux/mm.h
>>>> index 00c8a54127d37..77737cbf2216a 100644
>>>> --- a/include/linux/mm.h
>>>> +++ b/include/linux/mm.h
>>>> @@ -2055,11 +2055,13 @@ static inline long folio_nr_pages(const struct=
 folio *folio)
>>>>  =C2=A0 =C2=A0 /* Only hugetlbfs can allocate folios larger than MAX_O=
RDER */
>>>>  =C2=A0 #ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
>>>> -#define MAX_FOLIO_NR_PAGES=C2=A0=C2=A0=C2=A0 (1UL << PUD_ORDER)
>>>> +#define MAX_FOLIO_ORDER=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PUD=
_ORDER
>>>
>>> Do we need to check for CONTIG_ALLOC as well with CONFIG_ARCH_HAS_GIGAN=
TIC_PAGE?
>>>
>>
>> I don't think so, can you elaborate?
>>
>=20
> The only way to allocate a gigantic page is to use CMA, IIRC, which is co=
vered by CONTIG_ALLOC

As we are discussing as part of v2 right now, there is the way to just=20
obtain them from memblock during boot.

>=20
>>>>  =C2=A0 #else
>>>> -#define MAX_FOLIO_NR_PAGES=C2=A0=C2=A0=C2=A0 MAX_ORDER_NR_PAGES
>>>> +#define MAX_FOLIO_ORDER=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 MAX=
_PAGE_ORDER
>>>>  =C2=A0 #endif
>>>>  =C2=A0 +#define MAX_FOLIO_NR_PAGES=C2=A0=C2=A0=C2=A0 (1UL << MAX_FOLI=
O_ORDER)
>>>> +
>>>>  =C2=A0 /*
>>>>  =C2=A0=C2=A0 * compound_nr() returns the number of pages in this pote=
ntially compound
>>>>  =C2=A0=C2=A0 * page.=C2=A0 compound_nr() can be called on a tail page=
, and is defined to
>>>> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
>>>> index ca9e6b9633f79..1e6ae4c395b30 100644
>>>> --- a/mm/page_alloc.c
>>>> +++ b/mm/page_alloc.c
>>>> @@ -6833,6 +6833,7 @@ static int __alloc_contig_verify_gfp_mask(gfp_t =
gfp_mask, gfp_t *gfp_cc_mask)
>>>>  =C2=A0 int alloc_contig_range_noprof(unsigned long start, unsigned lo=
ng end,
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 acr_flags_t alloc_flags, gfp_=
t gfp_mask)
>>>>  =C2=A0 {
>>>> +=C2=A0=C2=A0=C2=A0 const unsigned int order =3D ilog2(end - start);
>>>
>>> Do we need a VM_WARN_ON(end < start)?
>>
>> I don't think so.
>>
>=20
> end - start being < 0, completely breaks ilog2. But we would error out be=
cause ilog2 > MAX_FOLIO_ORDER, so we should fine

Right, and if we have code that buggy that does it, it probably=20
shouldn't be our responsibility to sanity check that :)

It would have been completely buggy before this patch.

>=20
>>>
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned long outer_start, outer_end;
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int ret =3D 0;
>>>>  =C2=A0 @@ -6850,6 +6851,9 @@ int alloc_contig_range_noprof(unsigned l=
ong start, unsigned long end,
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 PB_ISOLATE_MODE_CMA_ALLOC :
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 PB_ISOLATE_MODE_OTHER;
>>>>  =C2=A0 +=C2=A0=C2=A0=C2=A0 if (WARN_ON_ONCE((gfp_mask & __GFP_COMP) &=
& order > MAX_FOLIO_ORDER))
>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>>>> +
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 gfp_mask =3D current_gfp_context(gfp_m=
ask);
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (__alloc_contig_verify_gfp_mask(gfp=
_mask, (gfp_t *)&cc.gfp_mask))
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL=
;
>>>> @@ -6947,7 +6951,6 @@ int alloc_contig_range_noprof(unsigned long star=
t, unsigned long end,
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 free_contig_range(end, outer_end - end);
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 } else if (start =3D=3D outer_start &&=
 end =3D=3D outer_end && is_power_of_2(end - start)) {
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct page *h=
ead =3D pfn_to_page(start);
>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int order =3D ilog2(end - =
start);
>>>>  =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 check_n=
ew_pages(head, order);
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 prep_new_page(=
head, order, gfp_mask, 0);
>>>
>>> Acked-by: Balbir Singh <balbirs@nvidia.com>
>>
>> Thanks for the review, but note that this is already upstream.
>>
>=20
> Sorry, this showed up in my updated mm thread and I ended up reviewing it=
, please ignore if it's upstream

I'm happy for any review (better in reply to v2), because any bug caught=20
early is good!


--=20
Cheers

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7=
d82cf5e-f60c-4295-9566-c40f6897fce7%40redhat.com.
