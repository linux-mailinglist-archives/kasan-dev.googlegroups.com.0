Return-Path: <kasan-dev+bncBDLKPY4HVQKBB24PT3DQMGQEHXQMQOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id CA4FCBC864D
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:01:16 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-36af4d383fesf3872631fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:01:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760004076; cv=pass;
        d=google.com; s=arc-20240605;
        b=jUyv+LotavkwY1lvYRLnrR6KfMAL3t6hKH3Zu4+lR9AxMDcbGhQku2eKFAOfkknEnX
         gw/69k0HnwAeqzG7zZZZw5h0SuHb1waoviepxfmku319DZVA2pJHGJbx/Hhr3veJe+xb
         J304P/u6K5WaUrCxKMhnEAd62R/lyjY1VH31IKbf+2/6GSsgDJXrJ5RdkbtE9CHk6YDx
         sZlxIxVkI1Nu6QvM1K9QS59gyTSA7NRJtNs4KyZjNZhScg/KQqf4kY4knyoxl3tajli+
         au40yz/cRp4H4VxO603Ojrr1djSzYIIsgrxxQN+9T6tEDaj8hJwC9u+Y/ozGx4NDxcUq
         4uZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=ngHWrtw+vyiKTuJ+Eca4ykwxUDDmGsuP6B13CrN0kdA=;
        fh=7zLA/YATsEYYOIePwnOPihdRkyouJ7RNm3emyLOvUDI=;
        b=HX5te5QGbMDeOFBuiU/OkBMrPNCBLh3f/l/FnalnLOWVoqPR2XL3qEKmq/FJeIiVbA
         CVR6JDUt74tLGArOJOo0E/xReFlGTu59KAwffjw+dQ6fbUOv2KZgErnuCs6ceF9+mNLP
         gPXQ2qaunfrzU4WnQFng9+HD/UW/ESaS0xmXY3bvJNbTurE2qnWMCJEKJwElPuB9DGZH
         t/NYfy95ra4liVvfMzLzoguzlEDoP9ccFq/7v3VSF3006IjxvEOQVqPn+WR1G0CnbzmV
         g/yb8MsL5wh3o+QWpcimtVou9og+EUvZ4g9uyWkfhF9XrTYOvhgEKq72YHMpUYp6hXB7
         ps4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760004076; x=1760608876; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ngHWrtw+vyiKTuJ+Eca4ykwxUDDmGsuP6B13CrN0kdA=;
        b=lRhLhrnaEgEi+TshVXsi7NevF9u4L5wAy2u1MaA/Zs7lL/trf47V/Vb6RTFJPhmaEz
         fdwvAkKrrWT65vpHTTiJZd+2UT7ncFPrIuR7CJk4aB0+rNimyTH1saIuX4C3Z+6TodPm
         VBq8LaCLxTHZzCTnk+sW+3p4CXPZqBWI+CIzlpAcHUo6zRsqxfAQUK5uwyOEaNCHklGP
         JH3Sqv2S2VgzPtMhEU0a6fsa71/BQEhgk9lUrGybMqE3b1a56GttfTT/6ETt5nYN6NZN
         BkRQI6qaAuM4t+iGD8LzgwCyWmn47Aj/Aqkh1mreCC2t7FlTLA1GTMkmUEiDqld/IcnP
         yjmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760004076; x=1760608876;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ngHWrtw+vyiKTuJ+Eca4ykwxUDDmGsuP6B13CrN0kdA=;
        b=i48BoyZGJpgYjkvf5sD/CkdB1J/JY49kmdzIN4H+YWTQ42/SjbZjNvzdtse991RzCi
         3yz/i9bt6JJpbCgKhVUQuKpjKGm4StsS/hEsIkWrfOa00E924zVWPzuJF8hIBVDVj9pn
         LRAJzvfkeL/dRFPnDOqhsHdzcH537SVS0Gh+Yo0ovJu5g6EKTWGBgZeUdiJ3KeXqI0vp
         IR1e1MLZNth935+QvfKLgxpUb5snBq1e+JSnlfh/97yvxtsicP+eXUD5Z0sOqT6J9DgX
         eXFeaQ/apVWcL0PhHXXpO8yFZ0595FczV2qk/ExydGcdViQmS6ZTBZcP56EQuWw+c9+N
         sZEA==
X-Forwarded-Encrypted: i=2; AJvYcCVhRF8ujYsRN5mxm/PlekwQDhSa0Shq8eZIhf6M90LkWVFuhSRmrJIxWRrOEmhBtuP6D7c5MA==@lfdr.de
X-Gm-Message-State: AOJu0Yyl7dYKZx2iYCR4esWDUekd+N3afhTe7mfEtcxur8anhz4NbHPk
	vVBHFrk+vyF/9qSIyEfFYwyLpwzCWHw7jnoE7041ZiY5ohFPM9xqi18G
X-Google-Smtp-Source: AGHT+IHIcwIvUWef+6q7VzZWyaEC+JNX1/7/G87y1nhSVcK6V17nvDrQG/lFYbFyNur/ZO5Bg6MWjw==
X-Received: by 2002:a2e:9a0d:0:b0:373:a3e2:b907 with SMTP id 38308e7fff4ca-37609d3a031mr19775991fa.10.1760004075915;
        Thu, 09 Oct 2025 03:01:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7YjWD8Sf+piWk1uPnlheFoFNrZ49HgQ8RxsjQwYrqvkg=="
Received: by 2002:a05:651c:4385:10b0:332:2df3:1cb6 with SMTP id
 38308e7fff4ca-3761c8fcf01ls1244531fa.2.-pod-prod-02-eu; Thu, 09 Oct 2025
 03:01:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV3dPFAYhA4uFK3NJJFEfynxsaP5Feagp7ixzvgBHD3bGGoLt9PITlwWsS6t75H8TyVE0QrMdZykWw=@googlegroups.com
X-Received: by 2002:a2e:bea5:0:b0:371:a1d1:7fd1 with SMTP id 38308e7fff4ca-37609ed94a3mr17104551fa.37.1760004072848;
        Thu, 09 Oct 2025 03:01:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760004072; cv=none;
        d=google.com; s=arc-20240605;
        b=R2fd8aB6wj9IEjfFOVZVHVYcu0t3DcBROG37Fg8DP2EvUUJrNL9a1JCSjEFZPp1o7m
         QLnmZBLU3Imm6S6UFW5XJfhvtIaaxkix7fo7Yw36vaB6sHGQphAJfQlWj0JAlnkZr9pk
         QXoq1G9UXIPRDynv2bz9R46qMn5Yve+69OxMf0gCNcuUmFvk4CbhwLHzLVEvF+IWmFAs
         qhBu5Y1KmdH5AG9DYHHzBm2Mf5oZxpC5nUearNKei2PsYnnwVv0wJXYARIqS8ayEH39Q
         EZGywjnBTfMUA5/DWdoyI4EFaby5SUS4QJ1gaIdlxUK41equ3JnTW/+qguTET8V2VtxU
         rGcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=Mviit9av+xJ2i1UCKCKoymOIpaOEjjA1p687Sppc3JU=;
        fh=7wgiGZD7GN9L56S35I5R8c/eoPZ2zJ2PKdmpqRxCfmQ=;
        b=CxhJzgNfn4txO1/MZOYir0IypLwrBh5IDC46mDjQDY1N3LPQNJOyS6Viao5wHs7qQ6
         3H/2HBPGuOuwUcHmzBP1ondEg1PStN1vmLnnBilYZEixzRWjitjomkk9ncES9z4TjCXy
         FHaTYhxoaeyPsEKya/sKkDKHGfWo3AIEuOr0qtnS5FM4/k4t9VIRxVYd6JOrTPF1Olx4
         BoFRfqbNQzl6yv8DpYGIR2us3w0riG+nhWGfCnISAVlOQhjhiSCzBwgq5OCozYzLV5QI
         5sB8uFBwVGCzFI2uZUVDo7Ie24CCb9SZ92h9ofJC2O0QhwtnHRf9hNP8Phd7NJ5L+Ueb
         ZDNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-375f3a4eaf6si494061fa.3.2025.10.09.03.01.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:01:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub4.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4cj548110xz9sSL;
	Thu,  9 Oct 2025 12:01:12 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id qOLNCcqM6pFr; Thu,  9 Oct 2025 12:01:12 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4cj5476tjqz9sSC;
	Thu,  9 Oct 2025 12:01:11 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id D06108B76C;
	Thu,  9 Oct 2025 12:01:11 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id MfDghYtIuYkA; Thu,  9 Oct 2025 12:01:11 +0200 (CEST)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 776CE8B767;
	Thu,  9 Oct 2025 12:01:09 +0200 (CEST)
Message-ID: <0c730c52-97ee-43ea-9697-ac11d2880ab7@csgroup.eu>
Date: Thu, 9 Oct 2025 12:01:08 +0200
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
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: fr-FR
In-Reply-To: <1db15a30-72d6-4045-8aa1-68bd8411b0ba@redhat.com>
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



Le 09/10/2025 =C3=A0 11:20, David Hildenbrand a =C3=A9crit=C2=A0:
> On 09.10.25 11:16, Christophe Leroy wrote:
>>
>>
>> Le 09/10/2025 =C3=A0 10:14, David Hildenbrand a =C3=A9crit=C2=A0:
>>> On 09.10.25 10:04, Christophe Leroy wrote:
>>>>
>>>>
>>>> Le 09/10/2025 =C3=A0 09:22, David Hildenbrand a =C3=A9crit=C2=A0:
>>>>> On 09.10.25 09:14, Christophe Leroy wrote:
>>>>>> Hi David,
>>>>>>
>>>>>> Le 01/09/2025 =C3=A0 17:03, David Hildenbrand a =C3=A9crit=C2=A0:
>>>>>>> diff --git a/mm/hugetlb.c b/mm/hugetlb.c
>>>>>>> index 1e777cc51ad04..d3542e92a712e 100644
>>>>>>> --- a/mm/hugetlb.c
>>>>>>> +++ b/mm/hugetlb.c
>>>>>>> @@ -4657,6 +4657,7 @@ static int __init hugetlb_init(void)
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON(sizeo=
f_field(struct page, private) *
>>>>>>> BITS_PER_BYTE <
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __NR_HPAGEFLAGS);
>>>>>>> +=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON_INVALID(HUGETLB_PAGE_ORDER > MAX_F=
OLIO_ORDER);
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!hugepages_sup=
ported()) {
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 if (hugetlb_max_hstate ||=20
>>>>>>> default_hstate_max_huge_pages)
>>>>>>> @@ -4740,6 +4741,7 @@ void __init hugetlb_add_hstate(unsigned int
>>>>>>> order)
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(hugetlb_max=
_hstate >=3D HUGE_MAX_HSTATE);
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(order < ord=
er_base_2(__NR_USED_SUBPAGE));
>>>>>>> +=C2=A0=C2=A0=C2=A0 WARN_ON(order > MAX_FOLIO_ORDER);
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 h =3D &hstates[hug=
etlb_max_hstate++];
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __mutex_init(&h->r=
esize_lock, "resize mutex", &h-=20
>>>>>>> >resize_key);
>>>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 h->order =3D order=
;
>>>>>
>>>>> We end up registering hugetlb folios that are bigger than
>>>>> MAX_FOLIO_ORDER. So we have to figure out how a config can trigger=20
>>>>> that
>>>>> (and if we have to support that).
>>>>>
>>>>
>>>> MAX_FOLIO_ORDER is defined as:
>>>>
>>>> #ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
>>>> #define MAX_FOLIO_ORDER=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PUD_=
ORDER
>>>> #else
>>>> #define MAX_FOLIO_ORDER=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 MAX_=
PAGE_ORDER
>>>> #endif
>>>>
>>>> MAX_PAGE_ORDER is the limit for dynamic creation of hugepages via
>>>> /sys/kernel/mm/hugepages/ but bigger pages can be created at boottime
>>>> with kernel boot parameters without CONFIG_ARCH_HAS_GIGANTIC_PAGE:
>>>>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 hugepagesz=3D64m hugepages=3D1 hugepagesz=3D2=
56m hugepages=3D1
>>>>
>>>> Gives:
>>>>
>>>> HugeTLB: registered 1.00 GiB page size, pre-allocated 0 pages
>>>> HugeTLB: 0 KiB vmemmap can be freed for a 1.00 GiB page
>>>> HugeTLB: registered 64.0 MiB page size, pre-allocated 1 pages
>>>> HugeTLB: 0 KiB vmemmap can be freed for a 64.0 MiB page
>>>> HugeTLB: registered 256 MiB page size, pre-allocated 1 pages
>>>> HugeTLB: 0 KiB vmemmap can be freed for a 256 MiB page
>>>> HugeTLB: registered 4.00 MiB page size, pre-allocated 0 pages
>>>> HugeTLB: 0 KiB vmemmap can be freed for a 4.00 MiB page
>>>> HugeTLB: registered 16.0 MiB page size, pre-allocated 0 pages
>>>> HugeTLB: 0 KiB vmemmap can be freed for a 16.0 MiB page
>>>
>>> I think it's a violation of CONFIG_ARCH_HAS_GIGANTIC_PAGE. The existing
>>> folio_dump() code would not handle it correctly as well.
>>
>> I'm trying to dig into history and when looking at commit 4eb0716e868e
>> ("hugetlb: allow to free gigantic pages regardless of the
>> configuration") I understand that CONFIG_ARCH_HAS_GIGANTIC_PAGE is
>> needed to be able to allocate gigantic pages at runtime. It is not
>> needed to reserve gigantic pages at boottime.
>>
>> What am I missing ?
>=20
> That CONFIG_ARCH_HAS_GIGANTIC_PAGE has nothing runtime-specific in its=20
> name.

In its name for sure, but the commit I mention says:

     On systems without CONTIG_ALLOC activated but that support gigantic=20
pages,
     boottime reserved gigantic pages can not be freed at all.  This patch
     simply enables the possibility to hand back those pages to memory
     allocator.

And one of the hunks is:

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 7f7fbd8bd9d5b..7a1aa53d188d3 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -19,7 +19,7 @@ config ARM64
         select ARCH_HAS_FAST_MULTIPLIER
         select ARCH_HAS_FORTIFY_SOURCE
         select ARCH_HAS_GCOV_PROFILE_ALL
-       select ARCH_HAS_GIGANTIC_PAGE if CONTIG_ALLOC
+       select ARCH_HAS_GIGANTIC_PAGE
         select ARCH_HAS_KCOV
         select ARCH_HAS_KEEPINITRD
         select ARCH_HAS_MEMBARRIER_SYNC_CORE

So I understand from the commit message that it was possible at that=20
time to have gigantic pages without ARCH_HAS_GIGANTIC_PAGE as long as=20
you didn't have to be able to free them during runtime.

>=20
> Can't we just select CONFIG_ARCH_HAS_GIGANTIC_PAGE for the relevant=20
> hugetlb config that allows for *gigantic pages*.
>=20

We probably can, but I'd really like to understand history and how we=20
ended up in the situation we are now.
Because blind fixes often lead to more problems.

If I follow things correctly I see a helper gigantic_page_supported()=20
added by commit 944d9fec8d7a ("hugetlb: add support for gigantic page=20
allocation at runtime").

And then commit 461a7184320a ("mm/hugetlb: introduce=20
ARCH_HAS_GIGANTIC_PAGE") is added to wrap gigantic_page_supported()

Then commit 4eb0716e868e ("hugetlb: allow to free gigantic pages=20
regardless of the configuration") changed gigantic_page_supported() to=20
gigantic_page_runtime_supported()

So where are we now ?

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0=
c730c52-97ee-43ea-9697-ac11d2880ab7%40csgroup.eu.
