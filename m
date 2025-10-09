Return-Path: <kasan-dev+bncBDLKPY4HVQKBBC73TXDQMGQEYFPE24Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D650BC8401
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 11:17:01 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-336a6070642sf2548701fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 02:17:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760001420; cv=pass;
        d=google.com; s=arc-20240605;
        b=fBdZuhSaLor2x2nGuF9hABQPytFNiiGImGQOEsftn0HED+DrO49rQksg+fkvIiRGrr
         /4e5qQbi2Bz1cbH4nfQ61+AX6guFPXkSCRaFU5cn9kGR0WTCLd2+fEMsBwL39NLeLidH
         ym3vLYNgbRcz6X6JP4M35Q4kNu4wW/VveGGrZaJUTpnBRXm9ndrY4+g6ElEdAaQjssS1
         nRyuIIedMHHeEf7AeY0BFoUdLfDmMgC4NTTIjSHtCoxdZhgb5JmH4fw9ZJ1Zw80exP3r
         YPviYfo6MOGVsQy6zlhFz1ivI71nSO3BlThjgwnv4EEL7OBIFpMRrXvjLest38g1tdPW
         ZGPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=yXPaJb337pAKR+OMLBjeJzv6LrZX/ZAxFr1vMmKlUmE=;
        fh=zjRYs3HB6pKYxC4CXexVz0fcI3uNptP1i1xiO6xGC5M=;
        b=jkcXtxXqZRWjnif3nHS3/k36uF7uT8LtSht3tMdV8yot86rb9CxqqI/lBWignBL5dO
         klEb5qkDsNySFpFjP8coPEpcbpOdCoZ0DIg9gaJb56XCOhEXJNdDy4NCUSusexOw9rRx
         uXbeUvhnIJnawTocMqNpAC11JR21GppuQNpjDFa7FvFNFCdRnbqFNYo2jggI22mJh7KE
         sXpJ6QVhDRxNwC9Xu4l9qsDP6k6n4H6KwP3aBsAR8v9Hun3UYOxoZEScXUNked5lpyfc
         3Obd3AcHgi5FXfaW8lSfFOM4ZaNLt6cseyz4Em9yII7MHWOVX7rmI7k8MmEEvgonCWd7
         tOAQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760001420; x=1760606220; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=yXPaJb337pAKR+OMLBjeJzv6LrZX/ZAxFr1vMmKlUmE=;
        b=uhANMfwub5zJamG/CH3bV408xBboIibqD7sQQb+ZprnFmfjD4Ne6IE/LUezfO6/iOa
         9sJM7kLDz1dZu5gaVpP/ae3/ldc36gDDBD+c7maNSG8YGW0bGNr7lQC5nOTuF7ctuGzu
         Me54sK0HBVLwv3JZ1//UAHz4a0JaderulEIpP4qQQZQYW3RfNNQtFKVBj5pHMCO+QQsr
         DP6wX2ejtDXgl2U2aw8tdeWIgynAZTwGsd9vn0bNNtQj6SJL58zc/ErPEydUb2pb80Yq
         58TENmH/ukK0ayKO+XX9rK7+aDsJszHaRvHdRVbxJXWFWFtJBRZ9ENZzYkP9uL9qPOyp
         ZDkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760001420; x=1760606220;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yXPaJb337pAKR+OMLBjeJzv6LrZX/ZAxFr1vMmKlUmE=;
        b=KTqECHvtb6j6DIYpR8U2eKAGRMSzX0HsyJ0Mw2lHUKdCj2mgSuAEOS3eyyCwU6tYuy
         NMpR645rWartMFhiit51ybVhmH8guZUKZeFpNHBMP/SE69tiy3qv/3FjhZpVbog61UFu
         Pmal+ynx6fCQTpS0+grHQvySYkXuWvAvFtSW5tihS14DbgO7Cq+9qL9BU00PFS8426zb
         iC85yvzzca/oSckxa1Lp3fLAl1Uu2bN895C2fci5mYPSfzF72ybwJ/8sxQqjYMZGtGKN
         iGvIrqHuVuL11bj6RWH5Un4Mk3u2BjzzGY62TlVM3FWrAHqO8XFUEMNL4y7oSaXwkBjf
         PPvA==
X-Forwarded-Encrypted: i=2; AJvYcCUYkgRzaeknGgNO12gC8R9qIQ9h6XpjspE6kJrNa4L4nqD99bC4etjyVAD61G29wQ6qFoCM2g==@lfdr.de
X-Gm-Message-State: AOJu0YyI56tJEa4J4lUBFBPQr+dFWMb/31uwIfpOuyysPJxd6ME6Ytm9
	C9Cm3M8oAZeMRogQ/8T8DKGE8fJiUhBBoXFu2IG4Xc9HIZVyatKkXvUe
X-Google-Smtp-Source: AGHT+IFPoktD4co/mECEMmDcFIcXH6nnQO1cP8GJN9ymsFLFAzYrREEx+9l6A1SzYA4StYba9+ZIuQ==
X-Received: by 2002:a05:651c:b2a:b0:373:a465:294d with SMTP id 38308e7fff4ca-37609cc36d4mr17853351fa.8.1760001419779;
        Thu, 09 Oct 2025 02:16:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6j6DHxSzS+vGQeK0lrQt91iny1Bzzj5PeKl4TaYUyUeA=="
Received: by 2002:a2e:988e:0:b0:372:97a6:f7dc with SMTP id 38308e7fff4ca-3761c94dd53ls1208681fa.2.-pod-prod-07-eu;
 Thu, 09 Oct 2025 02:16:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWt6ArM8N9GrSp4sBF4C1Oeaq2C45uGaHiOXR+BhtEme1CXU5HzQZy8PmDknmyzNU4xn7cBL18mCTA=@googlegroups.com
X-Received: by 2002:a2e:bd0c:0:b0:372:9453:3173 with SMTP id 38308e7fff4ca-37609ea1786mr17610661fa.40.1760001415972;
        Thu, 09 Oct 2025 02:16:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760001415; cv=none;
        d=google.com; s=arc-20240605;
        b=KkJkIm1TpvQqJAH2TC9WG4maqzhfA3/GX+9bKPqnvoXH4OWnKWJ5GFcC9Ct3uyijcO
         zdBoJ8r3hLyw1oe9pt5H/S7tP+TKeUWAy+GSaxKn37edzaIL7T6/klwNtNp3KGQSv5wE
         m0rS6y53oi8nbdmZXn+AgJxCYhEVid+qUk5cEjVvcF7sKHIWMznYjZxm4xsImSK4V3HG
         0LwDqyEYqD/MqkUDn5KtaFRIbOouvfeIYgoXbI/TXtpg0HZ178sq9dOx0ZYVC5YyM4ci
         x2Y7/sY01cb3RiUutm/mG2FrucjDdnC6aVTdNqhYA6GL+WlSLKRY2YwRHSA2bn0aZq39
         f6wA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=SjzO/ywmFDyEDpAIYRGFQ4F67Mu4cfU8z7gpJNsGZLg=;
        fh=7wgiGZD7GN9L56S35I5R8c/eoPZ2zJ2PKdmpqRxCfmQ=;
        b=VkPJb2KI9nmb2Kv01YfBsiqYHnZfgfyibHq4JBcWGI9exaKVYZYlBq0Cu0t/2yBVXd
         34Vg9Dfbrzt2bgX2/9QyBCxG7izU0b5aK51Lyhjf8/FlXXtOyjJ7gPjEujrGJOdNOcK4
         u6JBXcQEwFc2YLd36hOdLeUXICDEz5Gan9AN0IO2V8kiwaSPpVmGvfzK3qRvzlCeyTwS
         ohxsWo/37GDE7tpl2E1hSwHZC/aDcSrGB6gKa5HOGQ6rOLpx5+x6St+MV9m2XwojzlEb
         EJb52RHXKfLB3sr7qdc+1lRajvhIBpLTko5I5ENDKa/AwCjwjQGCnmTkDKxH3fZA3ywz
         /aAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-375f3981890si384331fa.1.2025.10.09.02.16.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 02:16:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub4.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4cj4530nVNz9sSY;
	Thu,  9 Oct 2025 11:16:55 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id 1xW49BLVjvgf; Thu,  9 Oct 2025 11:16:55 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4cj4526L27z9sSX;
	Thu,  9 Oct 2025 11:16:54 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id BC2658B773;
	Thu,  9 Oct 2025 11:16:54 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id ecZHQXz6ERX1; Thu,  9 Oct 2025 11:16:54 +0200 (CEST)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id BE4258B770;
	Thu,  9 Oct 2025 11:16:52 +0200 (CEST)
Message-ID: <03671aa8-4276-4707-9c75-83c96968cbb2@csgroup.eu>
Date: Thu, 9 Oct 2025 11:16:52 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: (bisected) [PATCH v2 08/37] mm/hugetlb: check for unreasonable
 folio sizes when registering hstate
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
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
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: fr-FR
In-Reply-To: <9361c75a-ab37-4d7f-8680-9833430d93d4@redhat.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 09/10/2025 =C3=A0 10:14, David Hildenbrand a =C3=A9crit=C2=A0:
> On 09.10.25 10:04, Christophe Leroy wrote:
>>
>>
>> Le 09/10/2025 =C3=A0 09:22, David Hildenbrand a =C3=A9crit=C2=A0:
>>> On 09.10.25 09:14, Christophe Leroy wrote:
>>>> Hi David,
>>>>
>>>> Le 01/09/2025 =C3=A0 17:03, David Hildenbrand a =C3=A9crit=C2=A0:
>>>>> diff --git a/mm/hugetlb.c b/mm/hugetlb.c
>>>>> index 1e777cc51ad04..d3542e92a712e 100644
>>>>> --- a/mm/hugetlb.c
>>>>> +++ b/mm/hugetlb.c
>>>>> @@ -4657,6 +4657,7 @@ static int __init hugetlb_init(void)
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON(sizeof_field(=
struct page, private) *=20
>>>>> BITS_PER_BYTE <
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 __NR_HPAGEFLAGS);
>>>>> +=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON_INVALID(HUGETLB_PAGE_ORDER > MAX_FOL=
IO_ORDER);
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!hugepages_supported()=
) {
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if=
 (hugetlb_max_hstate || default_hstate_max_huge_pages)
>>>>> @@ -4740,6 +4741,7 @@ void __init hugetlb_add_hstate(unsigned int=20
>>>>> order)
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(hugetlb_max_hstate =
>=3D HUGE_MAX_HSTATE);
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(order < order_base_=
2(__NR_USED_SUBPAGE));
>>>>> +=C2=A0=C2=A0=C2=A0 WARN_ON(order > MAX_FOLIO_ORDER);
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 h =3D &hstates[hugetlb_max=
_hstate++];
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __mutex_init(&h->resize_lo=
ck, "resize mutex", &h->resize_key);
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 h->order =3D order;
>>>
>>> We end up registering hugetlb folios that are bigger than
>>> MAX_FOLIO_ORDER. So we have to figure out how a config can trigger that
>>> (and if we have to support that).
>>>
>>
>> MAX_FOLIO_ORDER is defined as:
>>
>> #ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
>> #define MAX_FOLIO_ORDER=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PUD_OR=
DER
>> #else
>> #define MAX_FOLIO_ORDER=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 MAX_PA=
GE_ORDER
>> #endif
>>
>> MAX_PAGE_ORDER is the limit for dynamic creation of hugepages via
>> /sys/kernel/mm/hugepages/ but bigger pages can be created at boottime
>> with kernel boot parameters without CONFIG_ARCH_HAS_GIGANTIC_PAGE:
>>
>> =C2=A0=C2=A0=C2=A0 hugepagesz=3D64m hugepages=3D1 hugepagesz=3D256m huge=
pages=3D1
>>
>> Gives:
>>
>> HugeTLB: registered 1.00 GiB page size, pre-allocated 0 pages
>> HugeTLB: 0 KiB vmemmap can be freed for a 1.00 GiB page
>> HugeTLB: registered 64.0 MiB page size, pre-allocated 1 pages
>> HugeTLB: 0 KiB vmemmap can be freed for a 64.0 MiB page
>> HugeTLB: registered 256 MiB page size, pre-allocated 1 pages
>> HugeTLB: 0 KiB vmemmap can be freed for a 256 MiB page
>> HugeTLB: registered 4.00 MiB page size, pre-allocated 0 pages
>> HugeTLB: 0 KiB vmemmap can be freed for a 4.00 MiB page
>> HugeTLB: registered 16.0 MiB page size, pre-allocated 0 pages
>> HugeTLB: 0 KiB vmemmap can be freed for a 16.0 MiB page
>=20
> I think it's a violation of CONFIG_ARCH_HAS_GIGANTIC_PAGE. The existing=
=20
> folio_dump() code would not handle it correctly as well.

I'm trying to dig into history and when looking at commit 4eb0716e868e=20
("hugetlb: allow to free gigantic pages regardless of the=20
configuration") I understand that CONFIG_ARCH_HAS_GIGANTIC_PAGE is=20
needed to be able to allocate gigantic pages at runtime. It is not=20
needed to reserve gigantic pages at boottime.

What am I missing ?

>=20
> See how snapshot_page() uses MAX_FOLIO_NR_PAGES.
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0=
3671aa8-4276-4707-9c75-83c96968cbb2%40csgroup.eu.
