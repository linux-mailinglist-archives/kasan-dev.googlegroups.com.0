Return-Path: <kasan-dev+bncBC32535MUICBBVHKWHCQMGQEPWGMFTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id B8B08B34423
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 16:38:14 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-2464dc09769sf66502705ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 07:38:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756132693; cv=pass;
        d=google.com; s=arc-20240605;
        b=dMHWpZZTkqL8A73rLRqOS36t5V3JMl3nlr3lhSo8u65BHeGQrehm+z+ixg4TR0OajY
         jC9gjxVLE1vNg6+DqAQal9w/ztVmlNTcFmCa0TDeFQWw687kVPIBNF/ya7Im0kqCvOTM
         A6uAGhG8shuknq51FmHPZShYaqH1YWasQf/GxgrlXEDRKCO6flcfkd1mvwaBtXpf3C+U
         t4qvWGXWIWnZds8uEIeuxZrdKTHkgPcZYSfXeBejKQaFuJMcjq3/Wdj2Dk6exSLZnS9o
         Y864G9OtjHk+Nt27wZ4H07iJKEY0ZksTD7flUO3PDwy4CalyTU8GIwV30s+Kymd5su1o
         CkLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=7aOp9HgulXZkjnlrkLRNdD0RmFoPhvzK8TRvOnRA7QQ=;
        fh=3P/BIiiMUxQWJf5YSCcp/h1LmIoNFTOb4HB+gNsqvzg=;
        b=G4Y++OamOIJxVF3c0ThjKYtPoiRum7PTYF0rsa/fFeMKwwMRxmN+b0b8GxtrVannJv
         ZfdEhvKAuz04kttyCtVg9dCMQQpQxRWY84fOS3RN9uEqASMeq5+z17cj/Tq2mV1F7RIq
         6d5LQ67jpZavwZJMCyyVDX682ctSVkPC9nKLtwCrRcoXTH4uRyRWhf9xFXl3iCQ9PU9m
         E3Q2e7kExkgMtZxi2CKM/rxuQmKRAIcx5zUZTQqs7IQPY3/fibzh5aah1YRbwepCtlOO
         LTM3t0W2XjlczhOtvD4XT1AzH/uRHMWUxfsUB8xXKHwP7aRfLieLuGFvaZlcB7TR1m3z
         GQVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="I/u+pstj";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756132693; x=1756737493; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=7aOp9HgulXZkjnlrkLRNdD0RmFoPhvzK8TRvOnRA7QQ=;
        b=MRJ/w/qUf3wbH+gWQxehLCI4EzICXOjE51VthJEePqHeBni8cABvYgFO5u5kLQthvk
         hWf/PaL9RtARbtPSoTFeQB3jbAHuIFHJ7BLlO5LFFB9K5Pq51q4I8PDMZaFQoBSvxdom
         f9Bn7ueO8yEd5Wv05s4wcYETG1TRzPhxSqEULJkcZbgEBhpHXAzji0J4wCzyLqIDYjY+
         7kLiJ22xew+9UgV5oVVw2DvNuXU4IbUrovSr8kKjU9z2sWBdphWDjE/CKLe48+IT8HrZ
         1BHCpPOXa+OWypOEmVhk6vn22q0vZdrUsyMv7LhGDS3ylGPQWGvwg6qNWDG5YJ4Y9szZ
         pIyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756132693; x=1756737493;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7aOp9HgulXZkjnlrkLRNdD0RmFoPhvzK8TRvOnRA7QQ=;
        b=Uia3ya3aCiHgVEE8u0z9avrdmHWZCyAnMbAP+WrynryyhW1gRWaBN+z0er5H24a0NJ
         DRZNox1EthUvNiBUqpljHcfwVHjZs2VYG+tiH3zBom2zE3N7Svfp7JwCRJfpNQxnfOXH
         dKXrhRES3PEVjTO3SSYUh+sXnNBZm+5FJ29TyN5reuKU/V4ctL6k/4889xt3C6XCd966
         K59r+HgwM3XBfASDMCduQkNZSsBkvvemJc88O0Tr8NSsuQy3xXZMp3L8wkSNpHnRm5+2
         H7PF216O5PGyACieITv7LxiLLiOHl8pUJU0J8ky5N1ABK1yEe/mazwPBQ4MM2VMi9fiM
         j4tA==
X-Forwarded-Encrypted: i=2; AJvYcCWBhpuecgmP0cyuyx5/Q92W59olaAroWfw7Vvz7GIeKfKc7MseIb84AACONRQ3WQHH88sjayw==@lfdr.de
X-Gm-Message-State: AOJu0YyzW0Talqop+n2y7RZrIpoHnK2h6ju8YbHeGa+410T83AFrp5T5
	ncuOuRyWVA0tUTouReBw/OnEIJmzNGsd8fg9zl1WLetmxMeKnnHICcnl
X-Google-Smtp-Source: AGHT+IEY4aFMIIZPVwyouzO1DtCP4eN9zahcgCm8MKPyMqL2na+8fgj59YTT/FaFrLqJoafNQYsxog==
X-Received: by 2002:a17:903:38cd:b0:246:644f:5b81 with SMTP id d9443c01a7336-246644f5e62mr114273165ad.32.1756132692596;
        Mon, 25 Aug 2025 07:38:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZea5EerWq89f7WIu0vc9QIuAwOQC4bmhwlpdUopUYwdaQ==
Received: by 2002:a17:90b:1ccf:b0:324:eec4:936 with SMTP id
 98e67ed59e1d1-324eec40a61ls4658244a91.0.-pod-prod-03-us; Mon, 25 Aug 2025
 07:38:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX1wh2zoqCFRkLkJ0S7h1D9tCSBWAwxNBmYrDTK648Ix3pEUD/8C6w/FDTncwwRaa3zv//wzWqJ578=@googlegroups.com
X-Received: by 2002:a17:90a:d18f:b0:321:2407:3cef with SMTP id 98e67ed59e1d1-32515ed6077mr12002531a91.32.1756132690919;
        Mon, 25 Aug 2025 07:38:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756132690; cv=none;
        d=google.com; s=arc-20240605;
        b=aWynf9v9ERbw02vKQM8t2Tm/lJDmLRunp62g3fEpKpoGhC+J0prhYVka+xaKy4j0+i
         0FD2dxeQTjiATbnN31EVU4yzM0Ep9GPksH1hd6bHkOy+QjX8CUr+QvkBAzLEJ/o3qNC/
         q6N4zzihp1qrg9mMiT4F2rOEnJRiqrt5BxMpvoctRcjDAz6ts3+129XmBvWVguqiFATU
         80ZMLvkKwmBrbJyNIWxB9eC9pMMzY67lEuMWcgVr949YUSlAMQW9XtpG57mdLDAyQkxV
         A+KpS2Jbz171VaLFfcbg3oL6YytpdU4/PvNgumlMgvVFCf1S+P4aHERPsWOre0GfBMHG
         9wJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=S1b1Qn5IdFgoYphqgj6hBBswyK4CJqNFMjotKKBhPlQ=;
        fh=V34v4movNNvDn+FuVobYvPcSfsSGHtK4eIlrDgkwVjY=;
        b=ELaT5Vr/QB7TZ8V3n5I+0fxpCBrq+hpfGaRibY7cPqOP1t1bULP+Qk8ckLyJLpYPl+
         kDkI+dHt8y4hyOUJJsMsnvmE4gcMLGQKJbYSH7AbxoonaVeMRrAk3fD5baIdc0W8dj/g
         i36x9JOTq7pSdImL4YnNkr/YLc2fAvjPwwSzIH1tkEtC7FXQFjOYdqaPYu5hUKqt6Qo3
         ZtCTdphvZBbUN94a+fU0t7Lu+ACHlN4LOLCJ1cGmdQ7fLpX9Youp8I3RondiHYUCDT8u
         qo3mGBAsGDoA/AQxO/WaZx5cqPbS2J9KikDtsyR9A83tTKAwJpGaM/w7V+9JudJc/9Kj
         yIdA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="I/u+pstj";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3254ad966a8si282700a91.0.2025.08.25.07.38.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Aug 2025 07:38:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com
 [209.85.221.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-260-kYA7Ox0_M5iFkXv-gDfnyw-1; Mon, 25 Aug 2025 10:38:07 -0400
X-MC-Unique: kYA7Ox0_M5iFkXv-gDfnyw-1
X-Mimecast-MFC-AGG-ID: kYA7Ox0_M5iFkXv-gDfnyw_1756132687
Received: by mail-wr1-f71.google.com with SMTP id ffacd0b85a97d-3c7aa4cf187so963191f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 25 Aug 2025 07:38:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXBraAByEEcMglq1PSnKZLnsMzenXUb7E0LD4zeGDtd9BiL4RjNMyQy5RAwc6/e/+u8new5N9PThi0=@googlegroups.com
X-Gm-Gg: ASbGnctIF3XtaACnfArfoviBA0n7QnvhMkKbB3Cl6FHh0gLm9Xnsb22YArlaKpwsU9l
	s/eZhEQCDFBkhLHpf5FCxlfRxrUFhS2B0Ku8v/bR6HepisEF1+upYJOPVFc+2r92HT0velV2T+m
	oeB+90I4/nj/dt2aDjWxRl/EFbe1RnjAjULmoqwUD59dhEnehoO/jT1wYfPm7RUECaZPY61LHX2
	w345xAKHTdzFBVXGZnp0JWgc+CVCeKkonDkwXpIhBlXb/M568R/6FiaH7WSrMa0QNKiAjPLyytj
	/wOH4ZB0057Q9AOVdReIf6Bi24jyE2RDpalPBwRdDXxCjEoY8/4fX0v7bnsGrexZglYg/zapxSb
	4yqD5b51Y1yBtPPqxANUmxH4TC6IT4w8L1YFZFYnX84Yn9sfkA5JcdY2xNB4V4I+jOQw=
X-Received: by 2002:a05:6000:3113:b0:3c9:f8a:f257 with SMTP id ffacd0b85a97d-3c90f8af5cbmr2996355f8f.50.1756132686354;
        Mon, 25 Aug 2025 07:38:06 -0700 (PDT)
X-Received: by 2002:a05:6000:3113:b0:3c9:f8a:f257 with SMTP id ffacd0b85a97d-3c90f8af5cbmr2996318f8f.50.1756132685799;
        Mon, 25 Aug 2025 07:38:05 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f4f:1300:42f1:98e5:ddf8:3a76? (p200300d82f4f130042f198e5ddf83a76.dip0.t-ipconnect.de. [2003:d8:2f4f:1300:42f1:98e5:ddf8:3a76])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b5744e9b1sm109711045e9.11.2025.08.25.07.38.03
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Aug 2025 07:38:05 -0700 (PDT)
Message-ID: <a72080b4-5156-4add-ac7c-1160b44e0dfe@redhat.com>
Date: Mon, 25 Aug 2025 16:38:03 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 10/35] mm/hugetlb: cleanup
 hugetlb_folio_init_tail_vmemmap()
To: Mike Rapoport <rppt@kernel.org>
Cc: =?UTF-8?Q?Mika_Penttil=C3=A4?= <mpenttil@redhat.com>,
 linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
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
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-11-david@redhat.com>
 <9156d191-9ec4-4422-bae9-2e8ce66f9d5e@redhat.com>
 <7077e09f-6ce9-43ba-8f87-47a290680141@redhat.com>
 <aKmDBobyvEX7ZUWL@kernel.org>
 <a90cf9a3-d662-4239-ad54-7ea917c802a5@redhat.com>
 <aKxz9HLQTflFNYEu@kernel.org>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <aKxz9HLQTflFNYEu@kernel.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: tZagXGJOyFQdp4TKDg5H_XGTK8F43dJtFAIoljdE_b8_1756132687
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="I/u+pstj";
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

On 25.08.25 16:32, Mike Rapoport wrote:
> On Mon, Aug 25, 2025 at 02:48:58PM +0200, David Hildenbrand wrote:
>> On 23.08.25 10:59, Mike Rapoport wrote:
>>> On Fri, Aug 22, 2025 at 08:24:31AM +0200, David Hildenbrand wrote:
>>>> On 22.08.25 06:09, Mika Penttil=C3=A4 wrote:
>>>>>
>>>>> On 8/21/25 23:06, David Hildenbrand wrote:
>>>>>
>>>>>> All pages were already initialized and set to PageReserved() with a
>>>>>> refcount of 1 by MM init code.
>>>>>
>>>>> Just to be sure, how is this working with MEMBLOCK_RSRV_NOINIT, where=
 MM is supposed not to
>>>>> initialize struct pages?
>>>>
>>>> Excellent point, I did not know about that one.
>>>>
>>>> Spotting that we don't do the same for the head page made me assume th=
at
>>>> it's just a misuse of __init_single_page().
>>>>
>>>> But the nasty thing is that we use memblock_reserved_mark_noinit() to =
only
>>>> mark the tail pages ...
>>>
>>> And even nastier thing is that when CONFIG_DEFERRED_STRUCT_PAGE_INIT is
>>> disabled struct pages are initialized regardless of
>>> memblock_reserved_mark_noinit().
>>>
>>> I think this patch should go in before your updates:
>>
>> Shouldn't we fix this in memblock code?
>>
>> Hacking around that in the memblock_reserved_mark_noinit() user sound wr=
ong
>> -- and nothing in the doc of memblock_reserved_mark_noinit() spells that
>> behavior out.
>=20
> We can surely update the docs, but unfortunately I don't see how to avoid
> hacking around it in hugetlb.
> Since it's used to optimise HVO even further to the point hugetlb open
> codes memmap initialization, I think it's fair that it should deal with a=
ll
> possible configurations.

Remind me, why can't we support memblock_reserved_mark_noinit() when=20
CONFIG_DEFERRED_STRUCT_PAGE_INIT is disabled?

--=20
Cheers

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
72080b4-5156-4add-ac7c-1160b44e0dfe%40redhat.com.
