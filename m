Return-Path: <kasan-dev+bncBDLKPY4HVQKBBGGZTXDQMGQESBR7HCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 09DC8BC7E6D
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 10:04:43 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-36ac8376b3asf2914661fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 01:04:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759997081; cv=pass;
        d=google.com; s=arc-20240605;
        b=lB6WtNgnxR1jY5D4pX29fsjmclypoeDRUKk2PglOwweE9ke/PFtvG1g4LWoK4OUb8Q
         zkImIHaWLWi+p9XQP/JDskTVSRw9MR8wJblPJNQQNhQaAJA7WHxg71F9MQ/ud+GCEcK6
         bldBpdha5LF7/HToEoyIDqeJpKL7uE//dAK+On9nJ3IsegF5xYuK1kdTvYC/GowugOeF
         Hrp0oqfwZBArwj8aPAVYPxT7WLi800nTICQ11EHzNTuhgSNSd7UOvHrDDnW7eTXKGCBt
         +ToJwwjHne2quAjO1rrAIeHej/qPLLv8zSdfllovsi8hGUoxdgsgKFRX6iupS0yjok+M
         4rcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=Z9cJ1lnQGp6bx+N8TIxb2kQ88UORjcmUiCfRYMScWbg=;
        fh=73RQrvwCP7Y9vfQN2L5vP3r/HqBtFqQ9rN8/VwpRb9I=;
        b=MgDUHq4d/yjlpTBXeuTUOTDP9UZwEXQtNl4r3A/n/APhLoSItzmR19xO5D/mEIR87V
         ePhCKGnt1qKsGvmlwLpFOoP+2rVnWZf8aYwcYArOwPZTktIxWD3tr3F8Tra3qNSumgQl
         OFU3XsKVVF0/qP8ekN2mImfaK93qxxRFWyqVi54xynRvNWOTVXsPoBOtM/3ovigkvChM
         FFf8AIvEfEqh5rIxr19SeakAm6ONpbTRaFtiFWtrt6OaD6fpNJtDvdqmTA82M4wVUKS8
         oziQ7WQ6t1i10N1/IsWGo7LvbSSFwNy4NFsf5v7WVfNa8I9sPTS7nuJYeIvIuyYZ2SoF
         IkAQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759997081; x=1760601881; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Z9cJ1lnQGp6bx+N8TIxb2kQ88UORjcmUiCfRYMScWbg=;
        b=F3I15/pMqwAN4ry5NF70zJsYRK4Q989rTzGDVe6zIVmZq32XkYStEnqh1jCHu16nYe
         QywJPfV3hLcmOFICZbYNBAygjsv6fc2MIrcw4ntNdepKXCBYzIRJChdYBTSlIU+QyfBo
         gc4Fnr1JENv2vo82TyoHl8tgOaJrQYGqv8bGGHTZ71YyFXDna+JIpjYwvv3vzHif73ry
         +gj5Pa11GYCiDwuPrQ2/8zlzUGzPSt2A2QSQdk14yuKhb1gRsmio1tcJwYJAhOpCvS4o
         ikouU/lvdRN/EOqx360y1FvRXaN8W+9Y7X8CMVBotf871W7RRfRwiYh//ZelN+8WpRBJ
         EFxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759997081; x=1760601881;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z9cJ1lnQGp6bx+N8TIxb2kQ88UORjcmUiCfRYMScWbg=;
        b=reGALnHl9BoxDRkG9v5iK/5HUBOEd4UjlRLC9dUcCb2nNFUX+76aoQNxR27BR+t6+x
         WRWg9IhpegPX5fBhtBXAb/fkHAx1jnN8TAziYZmcQ/889X7RxVNYVOGdtdjHNDBMwYxg
         KBd4dwyawkkiW2TjtNh3CcTUPFIVr4sE4/8wtJdfRHwxliLWrCXZGhnF85kXsIrtFS3X
         QebqdElSLf7C6pJrIpuHcVkfrF9RJUbOCDOQuSQgUJ6JaQ2mD0x31yb6eXmzE5B8zlis
         7UxGgUjmhslzVvKZRSjkMTkCB7dBrNqCHJtqti3q3Sz+Op4FRs3lH0PeD81SULL9uHYQ
         cH0Q==
X-Forwarded-Encrypted: i=2; AJvYcCXdr6MW+pnH3Pc3dFgMnazDsKW32zl1DhUGG2T0lqP60RtW8NgOu5VNE64/bB2W4UMpRfHOCA==@lfdr.de
X-Gm-Message-State: AOJu0YzYPLK945zKaOAPHOKYzW36dIjjaj6DGhL7XKt9CVFKBHQuKG2B
	oS+CZWhL4uYfAttnq/Vwu+3HTsdp0F6mh4zxB+fFTN0EjAiXe5lWurVR
X-Google-Smtp-Source: AGHT+IF8WHV6LX+pwrhNaBdy2MF3nh7LmnLJYX95KQi/IkPlbdSc4zmRhfvyZ5AjQwo8U5/w4psf9w==
X-Received: by 2002:a2e:b8d0:0:b0:351:786c:e533 with SMTP id 38308e7fff4ca-37609d67ce3mr18496521fa.15.1759997080871;
        Thu, 09 Oct 2025 01:04:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd61/K8Wc/D/PaBe0V3KEaVIqq2YqEHNUCFwn4NcMGnUFQ=="
Received: by 2002:a2e:83d0:0:b0:363:22ce:bcfc with SMTP id 38308e7fff4ca-3761c93ceb0ls1199101fa.2.-pod-prod-03-eu;
 Thu, 09 Oct 2025 01:04:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVAAJ3U9KvkdudJMHXpOp5zUaRhPOGWyyjF/pZOBO9rCILSJpxmoLkBtobYQvJ0dOM2rkvm5bXJDK0=@googlegroups.com
X-Received: by 2002:a05:651c:2552:10b0:372:9135:be24 with SMTP id 38308e7fff4ca-3761e51ca40mr4164641fa.21.1759997077810;
        Thu, 09 Oct 2025 01:04:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759997077; cv=none;
        d=google.com; s=arc-20240605;
        b=Pjmv6hKOjvQkCldqbLhaOGhGFo274QKybdnT6AaibbKNY+vv+T+hGC/jQB17K4Ci/7
         2X9Go8Jom1dMuQYUuj1lGeKorjwllNRYLD2FnoObSY9OfkcXyeMZQbu8rysyT1689MO8
         XSiVlzTZLntSDHittgG1FZRQbZoCZjBOSh32grJF2PP+Xlk0SdliB1HENmYhQYaGxpHO
         ceJDGRU4Q7e6KOWXWNQt3vg7kh0c6AXxKdJFo5+oH0qFFraneoDHlhdMCM6Yf2b4t5wx
         qZpYen9ToriVlUttC6zQXfAscVgVrMhqClqyyD6q1sU+VNdclp3p5DcMVnXqog0NnoUA
         Z2WA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=Xbw+RhCM/KhKNE+NeIDOVsuF3+v6zQfqYVSxtVn6guE=;
        fh=7wgiGZD7GN9L56S35I5R8c/eoPZ2zJ2PKdmpqRxCfmQ=;
        b=Na2/D5ItF2Ra6MqXVP54K8tGcS0kVVZpck2dMin+NNHHHCQjRgj04earANHaPr8y7D
         u3BqSH9iGiQOzSDNQIXt6CcpBmg9A7hoGIXBUQXaUmib66T68q1uY2gOBT+kE3hqp5zj
         Gbf6zNopb1y9J6IDqc25S/2tI6RiK73dPirmiIoNVb9QrvBPRzWkw1wpzata8da5wbUk
         BQv5IRp1OT1LwL8rt2SZP71DkQ9ORq2+jqrEGa3VjprsFJXiGV3aqZVU4NRDgi/e4iNI
         7LMNMQ0iQ8EvywJZHGq0WhcDil8ppaR5OgdvfUrJo70ncTg7vZI8n49TK5huNFu4dbyo
         RhvA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-375f39814aasi1887741fa.2.2025.10.09.01.04.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 01:04:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub4.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4cj2Td0Mj6z9sSL;
	Thu,  9 Oct 2025 10:04:37 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id qQ36Dhni13kk; Thu,  9 Oct 2025 10:04:36 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4cj2Tc5kJ8z9sSC;
	Thu,  9 Oct 2025 10:04:36 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id A8FDF8B770;
	Thu,  9 Oct 2025 10:04:36 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id CnXkw3FAfnqR; Thu,  9 Oct 2025 10:04:36 +0200 (CEST)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id AE04F8B76D;
	Thu,  9 Oct 2025 10:04:34 +0200 (CEST)
Message-ID: <faf62f20-8844-42a0-a7a7-846d8ead0622@csgroup.eu>
Date: Thu, 9 Oct 2025 10:04:34 +0200
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
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: fr-FR
In-Reply-To: <d3fc12d4-0b59-4b1f-bb5c-13189a01e13d@redhat.com>
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



Le 09/10/2025 =C3=A0 09:22, David Hildenbrand a =C3=A9crit=C2=A0:
> On 09.10.25 09:14, Christophe Leroy wrote:
>> Hi David,
>>
>> Le 01/09/2025 =C3=A0 17:03, David Hildenbrand a =C3=A9crit=C2=A0:
>>> diff --git a/mm/hugetlb.c b/mm/hugetlb.c
>>> index 1e777cc51ad04..d3542e92a712e 100644
>>> --- a/mm/hugetlb.c
>>> +++ b/mm/hugetlb.c
>>> @@ -4657,6 +4657,7 @@ static int __init hugetlb_init(void)
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON(sizeof_field(struct p=
age, private) * BITS_PER_BYTE <
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 __NR_HPAGEFLAGS);
>>> +=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON_INVALID(HUGETLB_PAGE_ORDER > MAX_FOLIO=
_ORDER);
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!hugepages_supported()) {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (hugetl=
b_max_hstate || default_hstate_max_huge_pages)
>>> @@ -4740,6 +4741,7 @@ void __init hugetlb_add_hstate(unsigned int order=
)
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(hugetlb_max_hstate >=3D HUG=
E_MAX_HSTATE);
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(order < order_base_2(__NR_U=
SED_SUBPAGE));
>>> +=C2=A0=C2=A0=C2=A0 WARN_ON(order > MAX_FOLIO_ORDER);
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 h =3D &hstates[hugetlb_max_hstate+=
+];
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __mutex_init(&h->resize_lock, "res=
ize mutex", &h->resize_key);
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 h->order =3D order;
>=20
> We end up registering hugetlb folios that are bigger than=20
> MAX_FOLIO_ORDER. So we have to figure out how a config can trigger that=
=20
> (and if we have to support that).
>=20

MAX_FOLIO_ORDER is defined as:

#ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
#define MAX_FOLIO_ORDER		PUD_ORDER
#else
#define MAX_FOLIO_ORDER		MAX_PAGE_ORDER
#endif

MAX_PAGE_ORDER is the limit for dynamic creation of hugepages via=20
/sys/kernel/mm/hugepages/ but bigger pages can be created at boottime=20
with kernel boot parameters without CONFIG_ARCH_HAS_GIGANTIC_PAGE:

   hugepagesz=3D64m hugepages=3D1 hugepagesz=3D256m hugepages=3D1

Gives:

HugeTLB: registered 1.00 GiB page size, pre-allocated 0 pages
HugeTLB: 0 KiB vmemmap can be freed for a 1.00 GiB page
HugeTLB: registered 64.0 MiB page size, pre-allocated 1 pages
HugeTLB: 0 KiB vmemmap can be freed for a 64.0 MiB page
HugeTLB: registered 256 MiB page size, pre-allocated 1 pages
HugeTLB: 0 KiB vmemmap can be freed for a 256 MiB page
HugeTLB: registered 4.00 MiB page size, pre-allocated 0 pages
HugeTLB: 0 KiB vmemmap can be freed for a 4.00 MiB page
HugeTLB: registered 16.0 MiB page size, pre-allocated 0 pages
HugeTLB: 0 KiB vmemmap can be freed for a 16.0 MiB page


Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f=
af62f20-8844-42a0-a7a7-846d8ead0622%40csgroup.eu.
