Return-Path: <kasan-dev+bncBDLKPY4HVQKBBK6LT3DQMGQEQX24SGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id EDD41BC8F37
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 14:08:12 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-40fd1b17d2bsf482590f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 05:08:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760011692; cv=pass;
        d=google.com; s=arc-20240605;
        b=lfb/GedPf5dwlEhCtcFmV6jnNTYZj/8WIkF6fO8us1S/AY1j6x3n+s70iiMvzeTPE+
         0xY6XnnmOko8aPpa0c8ep1OT6/6qtpbXn2nkfoB2ctqFnVT4eY72RvcGElMS5GMZAjGU
         I7pKM+aZ+ycUIZ8Eg+t6z1OLvaZ1kSzfYX5/ZTOTVoPflIp5bb/eDgkay4k9cR+oup/K
         FWHo4uwNhkBqxoF+D4GIWDA5YlpKYGglcE3cn39JQacd+JnRxl878lQCQdgtpzNHBLOM
         MiHskKPXuSNFvUbDJV1BrEribpm4xyHUefx3g3woRm7BGLGps25M9XLGdFPQ0OE+YewR
         gtTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=eiOjtjYBWNkHxJ/F/dIkh6VhwZbI1hAnP7efmSIacOE=;
        fh=5LjLGuIzBcJR7vQPX0HdRmsoqRIdShSTnTLP6LHOPyc=;
        b=NOc/9E3S6nLmqmG8Vy4Cra0y+WLr7qEkO1P0Pj92qVxNzx8V0442iYw/5nS4rZhVkF
         jMceFhbD+z2OuAmeApVgkOIythcxnJMCKCvGFjL+nKLfIREZV9ysVEenm5kFM34g71RK
         liWBEbPH3JNBJc7VKmOIvjwh78UwlgN++rGYFjEVpkEZMGlfyqeaPjQwczLeS4x736Jw
         p8R7p4TLVpAJmDj4KkqQP+/MTuTbbWgghTYmY7FIkXI4OkIlIH81ujizcScMFzQIL5RA
         RdAujEuoVZgLCd9X6HRhdOMrTYdEOq4RKHwxYt0knS9ATTnW8PyJ3cpEu3A6TDt70u+s
         Mz8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760011692; x=1760616492; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=eiOjtjYBWNkHxJ/F/dIkh6VhwZbI1hAnP7efmSIacOE=;
        b=O1Ti1BGIR40qa4v/+/ZxfwKDk3f+qqNEDdsinho/Q2rb2rndk0+kmhmQJj7fwNDHQu
         DwypuO+cx54KljSAtx17OBzKfUa5lqcz2QL/vdZnPFR7pZ0G1TYJXAqzr0MMJ+pKjCDZ
         qMlPEAdL7QugTAppQx+LI4rgAzeUnmRCyy7EAjF9KTTGaE4ZTd6tu7sHs9eyIGEgWWEK
         fRsdePaOgPwY9a0hKLrEoQRlz8aXpUkd+XsDu+OniHwXowTdDwWOYcyWq7uf3CfB6Xuc
         PFJYi3aCrULX7OnWkqiTnt8wJOhdCbQUqhgLtAK1u/C6xosYwsNaL+v/p/WPb2xmVgYK
         fDIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760011692; x=1760616492;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eiOjtjYBWNkHxJ/F/dIkh6VhwZbI1hAnP7efmSIacOE=;
        b=owqBjtGvoi6diKJTWxLyy8vmGIDfUJyCYvhQUgs5iErndvfHog/Lq0sLDrMsqKG2W3
         ahKavgvjkAqW3e2EFNjU4RYD7kaNRv1GKJKTXfgv+B/5XHlKMmGxiWZlnbB41s9E5oSi
         lly18UKeb056tq7u+MOE/MwjQqFdT8Ki0m1C9DnMHIT5j7Ejix0sdSEvgLiTKkchp2y0
         4iVUlBjHNAW6olpQRZkzv/QUsc8QYxv0KT53fjNvWCHmFKk5C8+4M54Gd7xK/kAi4jAW
         +I7OYMsbDH+kkK7NZ1qVNqFDggxTEELDIS/+EjPHbzgzmiCJx7QSKdnuVkgVbJAOGm++
         7mtA==
X-Forwarded-Encrypted: i=2; AJvYcCU63dtrS2+tT2SuKzaYvzJrAGEX/lJErLFSA5gN8kbdJ8jIMbgESnVrakky9N9CMoS/5nRn8g==@lfdr.de
X-Gm-Message-State: AOJu0YyDSOfgJN6uBwG++cFsxvQRy3O33H5enUAv2BmhHa1VZm6TkxtS
	tehBlFDMBo/p5cVr9eWZjZS+pz7+gwxSiHqY7iH3cPDG7be6IMuUUq0n
X-Google-Smtp-Source: AGHT+IEtPHRJqgqqasSshFzvyTC5XqGfzmNBe0avTtsVS1ziy5Gl7tped/oWmD295jQDD5JRYeezeg==
X-Received: by 2002:a05:6000:1787:b0:425:75a0:36e2 with SMTP id ffacd0b85a97d-42666ab1aabmr3633422f8f.7.1760011692091;
        Thu, 09 Oct 2025 05:08:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4QT9l63ivYFwPxhd5aegdYjhuo+zuVZmiDaesaDvzwOQ=="
Received: by 2002:a05:600c:a40d:b0:46e:1aaa:6933 with SMTP id
 5b1f17b1804b1-46faf64d4a2ls3146455e9.2.-pod-prod-03-eu; Thu, 09 Oct 2025
 05:08:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXhiU4u1Y5kDSi3AxmPrZeUMdAg/97mIZRz0UJ2Q175XfWy9qZbdZdApUgLKw0yWdEy0UdHDIFVuLE=@googlegroups.com
X-Received: by 2002:a05:600c:45c6:b0:46d:ba6d:65bb with SMTP id 5b1f17b1804b1-46fa9b01de9mr58640285e9.31.1760011689038;
        Thu, 09 Oct 2025 05:08:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760011689; cv=none;
        d=google.com; s=arc-20240605;
        b=QxsliyG4Bx4kKBLmZiUn9b69DQ/rZjGCTVqQcz+Al0AAp+loO0mGferc+VW+Z/vlNT
         Gu/8VYEVPOMfuQWklRtY+Iwn4Ggu/G+fYhx5NYZxiDOFvnuZsYL0fzV2aUcex4+9lR12
         sUYwcs7o3w84hO+7i/vfu2r4dBWPOIYRw72HTkzn3tfcOcXr6Qe1Yix4WxBAy3fL1EMd
         568NzFqiBJB/3AblSIMkB20qtTSNG1shmtfIbXOG/VTQQrs8yaCXdFDvKrgynIV3+kK4
         TI43fGhL1+W9ssdl7Jv3IBxleEHS8XqCUm6/thOpNE+ZqdvDfJ9vAex3YbTpy87HrzSn
         XM3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=Mc1TIPZmtb3tKLWmvtpCO9BID0gxh7mz4dL5hPgt17w=;
        fh=7wgiGZD7GN9L56S35I5R8c/eoPZ2zJ2PKdmpqRxCfmQ=;
        b=fhWtt82F1TTUASxFwhzEK3mwYFT6/jTqjLjit5B3eH1Y2gmLV508Ciz0Wy2mEGS6V+
         UBGMYxMlnzwCRYAiqipXW8UyupZhBnZ/zosbft85d1+NgjFd3btRdSyujjinlO5hLPWh
         Jsb417NO7v2asz+NGb+Ov0vib32JgDkUXOT5UqAWpjyRK08mznVMKuMtIi8PdsdUgfaR
         ynmzBLLe/gaOTuALoZEeKTEBgh3pwOMHuwLjArRPYKDjB/soAx/7t9/6+wKfKIWIr8cA
         ywmILp4KB92wakAm61CLhQT3LAeh2Pp6IgwDWYyFqKM0thMnI9WW4mQbUruS5IfQZoer
         215Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-46fb327f546si184785e9.1.2025.10.09.05.08.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 05:08:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub4.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4cj7tc3BBqz9sSy;
	Thu,  9 Oct 2025 14:08:08 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id t-GI2jPxTJia; Thu,  9 Oct 2025 14:08:08 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4cj7tc1MWCz9sSv;
	Thu,  9 Oct 2025 14:08:08 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 08F7B8B76C;
	Thu,  9 Oct 2025 14:08:08 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id dX5DSkuE_w6O; Thu,  9 Oct 2025 14:08:07 +0200 (CEST)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id BC52E8B767;
	Thu,  9 Oct 2025 14:08:05 +0200 (CEST)
Message-ID: <4632e721-0ac8-4d72-a8ed-e6c928eee94d@csgroup.eu>
Date: Thu, 9 Oct 2025 14:08:05 +0200
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
 <03671aa8-4276-4707-9c75-83c96968cbb2@csgroup.eu>
 <1db15a30-72d6-4045-8aa1-68bd8411b0ba@redhat.com>
 <0c730c52-97ee-43ea-9697-ac11d2880ab7@csgroup.eu>
 <543e9440-8ee0-4d9e-9b05-0107032d665b@redhat.com>
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: fr-FR
In-Reply-To: <543e9440-8ee0-4d9e-9b05-0107032d665b@redhat.com>
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



Le 09/10/2025 =C3=A0 12:27, David Hildenbrand a =C3=A9crit=C2=A0:
> On 09.10.25 12:01, Christophe Leroy wrote:
>>
>>
>> Le 09/10/2025 =C3=A0 11:20, David Hildenbrand a =C3=A9crit=C2=A0:
>>> On 09.10.25 11:16, Christophe Leroy wrote:
>>>>
>>>>
>>>> Le 09/10/2025 =C3=A0 10:14, David Hildenbrand a =C3=A9crit=C2=A0:
>>>>> On 09.10.25 10:04, Christophe Leroy wrote:
>>>>>>
>>>>>>
>>>>>> Le 09/10/2025 =C3=A0 09:22, David Hildenbrand a =C3=A9crit=C2=A0:
>>>>>>> On 09.10.25 09:14, Christophe Leroy wrote:
>>>>>>>> Hi David,
>>>>>>>>
>>>>>>>> Le 01/09/2025 =C3=A0 17:03, David Hildenbrand a =C3=A9crit=C2=A0:
>>>>>>>>> diff --git a/mm/hugetlb.c b/mm/hugetlb.c
>>>>>>>>> index 1e777cc51ad04..d3542e92a712e 100644
>>>>>>>>> --- a/mm/hugetlb.c
>>>>>>>>> +++ b/mm/hugetlb.c
>>>>>>>>> @@ -4657,6 +4657,7 @@ static int __init hugetlb_init(void)
>>>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUILD_BUG_=
ON(sizeof_field(struct page, private) *
>>>>>>>>> BITS_PER_BYTE <
>>>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __NR_HPAGEFLAGS);
>>>>>>>>> +=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON_INVALID(HUGETLB_PAGE_ORDER > MAX=
_FOLIO_ORDER);
>>>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!hugep=
ages_supported()) {
>>>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 if (hugetlb_max_hstate ||
>>>>>>>>> default_hstate_max_huge_pages)
>>>>>>>>> @@ -4740,6 +4741,7 @@ void __init hugetlb_add_hstate(unsigned int
>>>>>>>>> order)
>>>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(hug=
etlb_max_hstate >=3D HUGE_MAX_HSTATE);
>>>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(ord=
er < order_base_2(__NR_USED_SUBPAGE));
>>>>>>>>> +=C2=A0=C2=A0=C2=A0 WARN_ON(order > MAX_FOLIO_ORDER);
>>>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 h =3D &hst=
ates[hugetlb_max_hstate++];
>>>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __mutex_in=
it(&h->resize_lock, "resize mutex", &h-
>>>>>>>>>> resize_key);
>>>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 h->order =
=3D order;
>>>>>>>
>>>>>>> We end up registering hugetlb folios that are bigger than
>>>>>>> MAX_FOLIO_ORDER. So we have to figure out how a config can trigger
>>>>>>> that
>>>>>>> (and if we have to support that).
>>>>>>>
>>>>>>
>>>>>> MAX_FOLIO_ORDER is defined as:
>>>>>>
>>>>>> #ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
>>>>>> #define MAX_FOLIO_ORDER=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PU=
D_ORDER
>>>>>> #else
>>>>>> #define MAX_FOLIO_ORDER=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 MA=
X_PAGE_ORDER
>>>>>> #endif
>>>>>>
>>>>>> MAX_PAGE_ORDER is the limit for dynamic creation of hugepages via
>>>>>> /sys/kernel/mm/hugepages/ but bigger pages can be created at boottim=
e
>>>>>> with kernel boot parameters without CONFIG_ARCH_HAS_GIGANTIC_PAGE:
>>>>>>
>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 hugepagesz=3D64m hugepages=3D1 hugepa=
gesz=3D256m hugepages=3D1
>>>>>>
>>>>>> Gives:
>>>>>>
>>>>>> HugeTLB: registered 1.00 GiB page size, pre-allocated 0 pages
>>>>>> HugeTLB: 0 KiB vmemmap can be freed for a 1.00 GiB page
>>>>>> HugeTLB: registered 64.0 MiB page size, pre-allocated 1 pages
>>>>>> HugeTLB: 0 KiB vmemmap can be freed for a 64.0 MiB page
>>>>>> HugeTLB: registered 256 MiB page size, pre-allocated 1 pages
>>>>>> HugeTLB: 0 KiB vmemmap can be freed for a 256 MiB page
>>>>>> HugeTLB: registered 4.00 MiB page size, pre-allocated 0 pages
>>>>>> HugeTLB: 0 KiB vmemmap can be freed for a 4.00 MiB page
>>>>>> HugeTLB: registered 16.0 MiB page size, pre-allocated 0 pages
>>>>>> HugeTLB: 0 KiB vmemmap can be freed for a 16.0 MiB page
>>>>>
>>>>> I think it's a violation of CONFIG_ARCH_HAS_GIGANTIC_PAGE. The=20
>>>>> existing
>>>>> folio_dump() code would not handle it correctly as well.
>>>>
>>>> I'm trying to dig into history and when looking at commit 4eb0716e868e
>>>> ("hugetlb: allow to free gigantic pages regardless of the
>>>> configuration") I understand that CONFIG_ARCH_HAS_GIGANTIC_PAGE is
>>>> needed to be able to allocate gigantic pages at runtime. It is not
>>>> needed to reserve gigantic pages at boottime.
>>>>
>>>> What am I missing ?
>>>
>>> That CONFIG_ARCH_HAS_GIGANTIC_PAGE has nothing runtime-specific in its
>>> name.
>>
>> In its name for sure, but the commit I mention says:
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 On systems without CONTIG_ALLOC activated=
 but that support gigantic
>> pages,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 boottime reserved gigantic pages can not =
be freed at all.=C2=A0 This=20
>> patch
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 simply enables the possibility to hand ba=
ck those pages to memory
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 allocator.
>=20
> Right, I think it was a historical artifact.
>=20
>>
>> And one of the hunks is:
>>
>> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
>> index 7f7fbd8bd9d5b..7a1aa53d188d3 100644
>> --- a/arch/arm64/Kconfig
>> +++ b/arch/arm64/Kconfig
>> @@ -19,7 +19,7 @@ config ARM64
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS_F=
AST_MULTIPLIER
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS_F=
ORTIFY_SOURCE
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS_G=
COV_PROFILE_ALL
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS_GIGANTIC_PAGE if C=
ONTIG_ALLOC
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS_GIGANTIC_PAGE
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS_K=
COV
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS_K=
EEPINITRD
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS_M=
EMBARRIER_SYNC_CORE
>>
>> So I understand from the commit message that it was possible at that
>> time to have gigantic pages without ARCH_HAS_GIGANTIC_PAGE as long as
>> you didn't have to be able to free them during runtime.
>=20
> Yes, I agree.
>=20
>>
>>>
>>> Can't we just select CONFIG_ARCH_HAS_GIGANTIC_PAGE for the relevant
>>> hugetlb config that allows for *gigantic pages*.
>>>
>>
>> We probably can, but I'd really like to understand history and how we
>> ended up in the situation we are now.
>> Because blind fixes often lead to more problems.
>=20
> Yes, let's figure out how to to it cleanly.
>=20
>>
>> If I follow things correctly I see a helper gigantic_page_supported()
>> added by commit 944d9fec8d7a ("hugetlb: add support for gigantic page
>> allocation at runtime").
>>
>> And then commit 461a7184320a ("mm/hugetlb: introduce
>> ARCH_HAS_GIGANTIC_PAGE") is added to wrap gigantic_page_supported()
>>
>> Then commit 4eb0716e868e ("hugetlb: allow to free gigantic pages
>> regardless of the configuration") changed gigantic_page_supported() to
>> gigantic_page_runtime_supported()
>>
>> So where are we now ?
>=20
> In
>=20
> commit fae7d834c43ccdb9fcecaf4d0f33145d884b3e5c
> Author: Matthew Wilcox (Oracle) <willy@infradead.org>
> Date:=C2=A0=C2=A0 Tue Feb 27 19:23:31 2024 +0000
>=20
>  =C2=A0=C2=A0=C2=A0 mm: add __dump_folio()
>=20
>=20
> We started assuming that a folio in the system (boottime, dynamic,=20
> whatever)
> has a maximum of MAX_FOLIO_NR_PAGES.
>=20
> Any other interpretation doesn't make any sense for MAX_FOLIO_NR_PAGES.
>=20
>=20
> So we have two questions:
>=20
> 1) How to teach MAX_FOLIO_NR_PAGES that hugetlb supports gigantic pages
>=20
> 2) How do we handle CONFIG_ARCH_HAS_GIGANTIC_PAGE
>=20
>=20
> We have the following options
>=20
> (A) Rename existing CONFIG_ARCH_HAS_GIGANTIC_PAGE to something else that =
is
> clearer and add a new CONFIG_ARCH_HAS_GIGANTIC_PAGE.
>=20
> (B) Rename existing CONFIG_ARCH_HAS_GIGANTIC_PAGE -> to something else=20
> that is
> clearer and derive somehow else that hugetlb in that config supports=20
> gigantic pages.
>=20
> (c) Just use CONFIG_ARCH_HAS_GIGANTIC_PAGE if hugetlb on an architecture
> supports gigantic pages.
>=20
>=20
> I don't quite see why an architecture should be able to opt in into=20
> dynamically
> allocating+freeing gigantic pages. That's just CONTIG_ALLOC magic and=20
> not some
> arch-specific thing IIRC.
>=20
>=20
> Note that in mm/hugetlb.c it is
>=20
>  =C2=A0=C2=A0=C2=A0=C2=A0#ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
>  =C2=A0=C2=A0=C2=A0=C2=A0#ifdef CONFIG_CONTIG_ALLOC
>=20
> Meaning that at least the allocation side is guarded by CONTIG_ALLOC.

Yes but not the freeing since commit 4eb0716e868e ("hugetlb: allow to=20
free gigantic pages regardless of the configuration")

>=20
> So I think (C) is just the right thing to do.
>=20
> diff --git a/fs/Kconfig b/fs/Kconfig
> index 0bfdaecaa8775..12c11eb9279d3 100644
> --- a/fs/Kconfig
> +++ b/fs/Kconfig
> @@ -283,6 +283,8 @@ config HUGETLB_PMD_PAGE_TABLE_SHARING
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 def_bool HUGETLB_PAGE
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 depends on ARCH_WANT_HUGE_PMD=
_SHARE && SPLIT_PMD_PTLOCKS
>=20
> +# An architecture must select this option if there is any mechanism=20
> (esp. hugetlb)
> +# could obtain gigantic folios.
>  =C2=A0config ARCH_HAS_GIGANTIC_PAGE
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 bool
>=20
>=20

I gave it a try. That's not enough, it fixes the problem for 64 Mbytes=20
pages and 256 Mbytes pages, but not for 1 Gbytes pages.

Max folio is defined by PUD_ORDER, but PUD_SIZE is 256 Mbytes so we need=20
to make MAX_FOLIO larger. Do we change it to P4D_ORDER or is it too much=20
? P4D_SIZE is 128 Gbytes

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
632e721-0ac8-4d72-a8ed-e6c928eee94d%40csgroup.eu.
