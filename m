Return-Path: <kasan-dev+bncBC32535MUICBBY74TXDQMGQEL42JBMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6543CBC842B
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 11:20:37 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-28d1747f23bsf13027555ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 02:20:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760001635; cv=pass;
        d=google.com; s=arc-20240605;
        b=h9YBGSr8QSiD62kHk+PiCTfcgcLkUJfes4/KxSmTGy7mgSEW4tAzBFmiWd+l9O+79U
         cXDshO5dDC67+kMry/OcPa7us0AHgBRp1USVGjQgV2eU8YUmaW146kYr/hUgLm3Nwedz
         8GaMrxcjyre+bnfhbRTTjMbLapqsCVUpp17WfOX7zIoi2BHemSVGDSq5Lj6mTPd+3QsX
         TfiOvPIAPHBiv64Y+PUS4IXC8YnsVNR2UhVtwQvBCHYcH+YhDI1DnQoNW11rDGE7pKBC
         PU2LZE7CHERf31ldRy2JM9WAZ3IIwDpon1Fl3CollGCM/xbXw52yS3GnSiwRWIeafzzH
         t6mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=Wxm27x9SWToEOcaOJ5R7OEdolUs7bsT8QWKzZ1tI4Gc=;
        fh=6HQzp2CBrxD62ynR8EOlTjO0iZTd0FmRW1voT8TKgKQ=;
        b=AaS6P1hS6L1PP6jeShgdT6yGojldbhfrPyKTwRMOPQt5+2ZuNrOR5FEIOL79mIpg1j
         KmWtTAVSB6ZiysQeoK5J4MWw7We/s1dU0lJ77mHe3bRx4AAkNdacXIK1fh7JyNdE6NG3
         d4zeX08dEcNYkO1DM5VBDUSpQRri2/9Nd3ZkMpYSxQJ65ol95UCX+PD9rEqTwtieb/ZQ
         t+Tgjv2Vi3K7vVbYmf/Q+XnxBKj7ri27psCHAkMXfDL3slka666uLLpOMltiDLk4oa6d
         PgXOPd9Of6tlYuM0YN8bYTUzxVJ0b7vJ8r0x9bh5RdgAVVoU7oI6nX2P1WucBFX4Txj0
         IdRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gk842VPf;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760001635; x=1760606435; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=Wxm27x9SWToEOcaOJ5R7OEdolUs7bsT8QWKzZ1tI4Gc=;
        b=HXtt7S6c2/ZiPSoMgLOuGgiycIGmy1jfBGFNb83Y6kyuQm7gLy0/dFcPxS0jT9AJ4L
         kxxc67iEAafgsL85tJiCDSn8R79ylCvVrVc4L32q+DKYTI7BO0NiOkJxR+kB5qr5v3cJ
         Sjc8zHurXiig3sx6Qp6DaY7278PUbg2XLD7dxqxiYgcn5fhjbxqNrLxIbMdkEOu0/0Bc
         YxLP2d5bB6YJtU00BqgTl8Zw/2uHHnLhwdug25cZeAg6NAAdXCA7+Nfq7WNpBJFK57I3
         IYuo4aGdYMNhDEnn9NhwR1LdPFNv3SrWVD2uSwW/nTsiB/JajtfsUnSCm+h/SotPzmbW
         x5Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760001635; x=1760606435;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Wxm27x9SWToEOcaOJ5R7OEdolUs7bsT8QWKzZ1tI4Gc=;
        b=DeRSgrHsecs9je81C9bq6dnhN8w9jzPxt0qZelitni0kRW4wlyQlioizDtANRwePgY
         YfAeugUjld5SkgQzOuk+6kJgOVe/n4uBdZZ+CNjR5GzZtSsgJ83eFBCxXVEn/3rwGpm1
         SlCnks1ozOCSY/mdnmeMlNDFH1Gfx2oPEdKtDypDxD5TDhdtZA5Q6hxbEq99iqiZWqFO
         NLxcTumUI5qWXMZVZg3ivu0RRMVqjExn0mqM+PuiNwKCxj1Dw6TAtqnzskvjlizrib08
         qEh3y19QkqhVM3tWhGVpWaXnFJEXBVu5TKsxPrQcR/KyvcsNjHW5hqNstie5Acs0xxPp
         ZLkw==
X-Forwarded-Encrypted: i=2; AJvYcCVDqdFqq0eqtqxs/ApQLvTCqfBPuJQuMWo2z8RGfQcQja9zXM0CbXMWUr3Fxd4hwV1X1W/h0Q==@lfdr.de
X-Gm-Message-State: AOJu0Yxtt4ERBsX5GfH63P4LuI48SdIIhMzM+3olF6txGZzqJEnVPkD6
	IRxQpl6EUGb4UA/bUr5hVNkrUVqALA6BgWVpI+Nybba5Di/XIJH9wv5V
X-Google-Smtp-Source: AGHT+IEd57JXYq+8X5ezzTp8Zc76RxkZfwkFdoheJxCnv4z9yCno2mMBbWKLj+FGI8olRJMbaz5gCg==
X-Received: by 2002:a17:902:da8e:b0:26a:589b:cf11 with SMTP id d9443c01a7336-29027402d24mr98105485ad.43.1760001635448;
        Thu, 09 Oct 2025 02:20:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd71kJ+rNd9xmWOeqMqVYhecAHZGbenoEGqUDbxNqHc3rQ=="
Received: by 2002:a17:90a:d790:b0:32e:43aa:41e2 with SMTP id
 98e67ed59e1d1-33b597805f6ls794424a91.0.-pod-prod-02-us; Thu, 09 Oct 2025
 02:20:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUSZY2lKyeAom8Z/zowVgHkInkqlALFETDnghv18ICkeX1IcXxwnwHojX8wlzDcCiQG3xS8shionQE=@googlegroups.com
X-Received: by 2002:a17:903:ac4:b0:266:2e6b:f592 with SMTP id d9443c01a7336-2902739a1b9mr81537105ad.25.1760001633879;
        Thu, 09 Oct 2025 02:20:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760001633; cv=none;
        d=google.com; s=arc-20240605;
        b=IUTD6YtoL66a7D7M7NAsuyTkvvukR5VvTHxrjnIB9GRnKu3g8Gotjqtwj/FF83m3sq
         BS/+W1G+fYVKMCSHIQmmdkVgqlf5+zPCSZwOVbHSLM9YbbTXgwmYqQziNH4YSnSvPTui
         PbvBf0T32vkDaOPGKGKE8P5weMaM/HnrZzPWeOt27WaGZRBAc+W5yb/FyRZT9TF+hSO/
         I3DTsjNRhX9l7hh3cSDtJTRagB6Ws9YZNrWDD6do4LX45EjmpnSC5KFCAPJm8B5h8joW
         70MAhMEyDDd4EN/tSNpZjipT0XtTL4ilVALagCftZBUvirNdy7U7OnrElqR4YvI7EPgz
         Nf3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=nig+QThvSoNq9uOJUVuoYK6Ng7PXDFkVUD8omncLNk0=;
        fh=8vBKoA1TW59GsueZtllHB0YU4hzZuMV4vxaG/64WFG4=;
        b=lMypJaKjlCfXghWU57q0FVkGOGMqPrW1TJ1WfSo1To54+Bk7mr79xpFk3stc3nw/oO
         5OZJsdsjkfQmJTBX+1eaxJvO35iilrhvTyaxFqkEvgsb0L8TAjTOZ7ioqC/d34uRazSa
         tUWZpfXmQiRtCDhJW+jXr2EpMXn9jX9g61rK7Aw3V/470TUaVV3gfiU9HjGodAMklKo4
         +YuRKmdHxZuIzAX9AzphIEriJWjRSUg5yYpWeeyNhW8ter90+QgnCKujt1P7kz5jqZAw
         1Tv/iM1GQIqKxe5fRw/gxFnS/U7ZT1O9KK9hOl2RCkAz32wAisxPOpOEm0Lm5/cLXUMR
         P8XQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gk842VPf;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-290364cac3csi1061225ad.2.2025.10.09.02.20.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 02:20:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-531-8KHXlSzqP_2lN6vIk5dWag-1; Thu, 09 Oct 2025 05:20:31 -0400
X-MC-Unique: 8KHXlSzqP_2lN6vIk5dWag-1
X-Mimecast-MFC-AGG-ID: 8KHXlSzqP_2lN6vIk5dWag_1760001630
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-46e47d14dceso3524875e9.2
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 02:20:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWRU1u1kkU7DhOAseLOqtKg1m5yGRocduNr01vl1TUX5cmLB3Gfo/nTp8GPjRH5pk7HnfGoB2YVfMw=@googlegroups.com
X-Gm-Gg: ASbGncu7ceLkNa/9/dlJxayRBnJ7oWLn5CjoRON3yKYzHrQiuM3ISxPtKNlXd4p96AQ
	hJWBqep+g0U9+GkEI+SECmNOVskSQ5cRKVp+dDDALRk+CHREvQYAA6RJrMytPdFSMZ3y4d5MoSv
	g3SAZ9KXa4qrha523SbFnjMV9SqBuHUFM1zHZ4zmQ4OSwJrcKEPaKCpBlkYuf96qCmJFgOBvfFK
	lMiAyNd+/EZ99ucoD62krJEYhYDhjNYuUl4U9+5gyMkxDarpBp3qed9tzBWp5clUQ/S+33OJS/9
	5NtUv3TZ9VK9KKmBitcuep2nY7nPXXi0IjEAWOt7J7lXzZOZLoRyQ+bUJAAsiLeiHkPAmW5F1dM
	Gv09CMiBS
X-Received: by 2002:a05:600c:4ed4:b0:45d:f88f:9304 with SMTP id 5b1f17b1804b1-46fa9b0e7b3mr48455105e9.30.1760001630390;
        Thu, 09 Oct 2025 02:20:30 -0700 (PDT)
X-Received: by 2002:a05:600c:4ed4:b0:45d:f88f:9304 with SMTP id 5b1f17b1804b1-46fa9b0e7b3mr48454685e9.30.1760001629923;
        Thu, 09 Oct 2025 02:20:29 -0700 (PDT)
Received: from [192.168.3.141] (tmo-083-189.customers.d1-online.com. [80.187.83.189])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-4255d8ab8b0sm33676902f8f.18.2025.10.09.02.20.26
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 02:20:29 -0700 (PDT)
Message-ID: <1db15a30-72d6-4045-8aa1-68bd8411b0ba@redhat.com>
Date: Thu, 9 Oct 2025 11:20:24 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: (bisected) [PATCH v2 08/37] mm/hugetlb: check for unreasonable
 folio sizes when registering hstate
To: Christophe Leroy <christophe.leroy@csgroup.eu>,
 linux-kernel@vger.kernel.org
Cc: Zi Yan <ziy@nvidia.com>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org,
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
 wireguard@lists.zx2c4.com, x86@kernel.org,
 "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-9-david@redhat.com>
 <3e043453-3f27-48ad-b987-cc39f523060a@csgroup.eu>
 <d3fc12d4-0b59-4b1f-bb5c-13189a01e13d@redhat.com>
 <faf62f20-8844-42a0-a7a7-846d8ead0622@csgroup.eu>
 <9361c75a-ab37-4d7f-8680-9833430d93d4@redhat.com>
 <03671aa8-4276-4707-9c75-83c96968cbb2@csgroup.eu>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <03671aa8-4276-4707-9c75-83c96968cbb2@csgroup.eu>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: Dnmbx8q3iJfg5h6nJqbU4PUp02-PEht7ZzsVxjl_4yw_1760001630
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=gk842VPf;
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

On 09.10.25 11:16, Christophe Leroy wrote:
>=20
>=20
> Le 09/10/2025 =C3=A0 10:14, David Hildenbrand a =C3=A9crit=C2=A0:
>> On 09.10.25 10:04, Christophe Leroy wrote:
>>>
>>>
>>> Le 09/10/2025 =C3=A0 09:22, David Hildenbrand a =C3=A9crit=C2=A0:
>>>> On 09.10.25 09:14, Christophe Leroy wrote:
>>>>> Hi David,
>>>>>
>>>>> Le 01/09/2025 =C3=A0 17:03, David Hildenbrand a =C3=A9crit=C2=A0:
>>>>>> diff --git a/mm/hugetlb.c b/mm/hugetlb.c
>>>>>> index 1e777cc51ad04..d3542e92a712e 100644
>>>>>> --- a/mm/hugetlb.c
>>>>>> +++ b/mm/hugetlb.c
>>>>>> @@ -4657,6 +4657,7 @@ static int __init hugetlb_init(void)
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON(sizeof_fiel=
d(struct page, private) *
>>>>>> BITS_PER_BYTE <
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 __NR_HPAGEFLAGS);
>>>>>> +=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON_INVALID(HUGETLB_PAGE_ORDER > MAX_FO=
LIO_ORDER);
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!hugepages_supported=
()) {
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
if (hugetlb_max_hstate || default_hstate_max_huge_pages)
>>>>>> @@ -4740,6 +4741,7 @@ void __init hugetlb_add_hstate(unsigned int
>>>>>> order)
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(hugetlb_max_hstat=
e >=3D HUGE_MAX_HSTATE);
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(order < order_bas=
e_2(__NR_USED_SUBPAGE));
>>>>>> +=C2=A0=C2=A0=C2=A0 WARN_ON(order > MAX_FOLIO_ORDER);
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 h =3D &hstates[hugetlb_m=
ax_hstate++];
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __mutex_init(&h->resize_=
lock, "resize mutex", &h->resize_key);
>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 h->order =3D order;
>>>>
>>>> We end up registering hugetlb folios that are bigger than
>>>> MAX_FOLIO_ORDER. So we have to figure out how a config can trigger tha=
t
>>>> (and if we have to support that).
>>>>
>>>
>>> MAX_FOLIO_ORDER is defined as:
>>>
>>> #ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
>>> #define MAX_FOLIO_ORDER=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PUD_O=
RDER
>>> #else
>>> #define MAX_FOLIO_ORDER=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 MAX_P=
AGE_ORDER
>>> #endif
>>>
>>> MAX_PAGE_ORDER is the limit for dynamic creation of hugepages via
>>> /sys/kernel/mm/hugepages/ but bigger pages can be created at boottime
>>> with kernel boot parameters without CONFIG_ARCH_HAS_GIGANTIC_PAGE:
>>>
>>>  =C2=A0=C2=A0=C2=A0 hugepagesz=3D64m hugepages=3D1 hugepagesz=3D256m hu=
gepages=3D1
>>>
>>> Gives:
>>>
>>> HugeTLB: registered 1.00 GiB page size, pre-allocated 0 pages
>>> HugeTLB: 0 KiB vmemmap can be freed for a 1.00 GiB page
>>> HugeTLB: registered 64.0 MiB page size, pre-allocated 1 pages
>>> HugeTLB: 0 KiB vmemmap can be freed for a 64.0 MiB page
>>> HugeTLB: registered 256 MiB page size, pre-allocated 1 pages
>>> HugeTLB: 0 KiB vmemmap can be freed for a 256 MiB page
>>> HugeTLB: registered 4.00 MiB page size, pre-allocated 0 pages
>>> HugeTLB: 0 KiB vmemmap can be freed for a 4.00 MiB page
>>> HugeTLB: registered 16.0 MiB page size, pre-allocated 0 pages
>>> HugeTLB: 0 KiB vmemmap can be freed for a 16.0 MiB page
>>
>> I think it's a violation of CONFIG_ARCH_HAS_GIGANTIC_PAGE. The existing
>> folio_dump() code would not handle it correctly as well.
>=20
> I'm trying to dig into history and when looking at commit 4eb0716e868e
> ("hugetlb: allow to free gigantic pages regardless of the
> configuration") I understand that CONFIG_ARCH_HAS_GIGANTIC_PAGE is
> needed to be able to allocate gigantic pages at runtime. It is not
> needed to reserve gigantic pages at boottime.
>=20
> What am I missing ?

That CONFIG_ARCH_HAS_GIGANTIC_PAGE has nothing runtime-specific in its name=
.

Can't we just select CONFIG_ARCH_HAS_GIGANTIC_PAGE for the relevant=20
hugetlb config that allows for *gigantic pages*.

--=20
Cheers

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1=
db15a30-72d6-4045-8aa1-68bd8411b0ba%40redhat.com.
