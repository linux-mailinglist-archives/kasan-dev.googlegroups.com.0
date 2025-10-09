Return-Path: <kasan-dev+bncBC32535MUICBBEE4T3DQMGQELABRVUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 70FF7BC879C
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:27:30 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-269a2b255aasf23230915ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:27:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760005649; cv=pass;
        d=google.com; s=arc-20240605;
        b=Dez4/l9BtDuML4p+gVNVn2aYIqrhGVx4TP2debh7mp/cNZyZKGeUJdx+tyX5KHVyyp
         OqZg8LfEt9IRRTa/oxdldsDgAJMcZu64YizoYWXXpTi/L72aGtL+dxDKH757Cq/7GZR2
         WdPvTXcVWyZAPyMknrduydDoDcjNfHrmGxb1SXBZE/hjez5bGivH+Fw+ooD8J69Xc1Xn
         pObDfwAivW0oTA09GcsXp2WIT/CKOdfDW+L7TMMw77Jh/WDCX1QEkzL50Dc9TwzBVxQv
         x484dtpjj57Gwt8gF1JNTR2GDzz0/NBjYCAZaAFsOStxQG8yyu7CQbrDNF85k+jRx9Bg
         u0kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=S7SMK7Eojdtn+Nx/EezZL1EdsCGAXq4wpHEWP6euwvI=;
        fh=lzcSjbvvz4hLvRAL3QNwQ7TdX8W3Vw+KXWEo0uVq+gg=;
        b=jA1nUNJYwts1TrweJNaJfyA7VwZ7KAAO2Kanc1czMWqhVqvkWCG4byp9lGu7Pq9xyg
         1jNPqahYd2/AR5WbpI3busPEtULGSyBAjnazk0JR5UMpLs+BE3WWWAF4xRnIKqelxCVx
         /w22I9NqGZXyCbZXX6rEbaDfdJqW9RUlIRy36ndWZ+96yrrFG3eD2YKmiYnoSpal3Qkj
         LrppOllAT856y15mm096Yv6jZDu1LzOmuUVhpyqYH9y1rzWlcpaQzHiuIe0NzVwZmMaP
         qbbuZoQ837ksYdtCcg3mHfJNDpqRGyGhB3NM1F+qSNVac5HPQsa2HNxhtuIbE0QoVB0r
         6ILA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=AmPJ4HRf;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760005649; x=1760610449; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=S7SMK7Eojdtn+Nx/EezZL1EdsCGAXq4wpHEWP6euwvI=;
        b=jvkfD/8RHEH1Ba6BblDQbJYJH28PBKfS7gR9pUlpIveRji0nWpKOUS/ExCFvuKr/J1
         dW4YJT9ilTpFvqs5VLwujS0E97jrbWymL/4v9DAZyoVITduJ5HzmvzXbIDSJEyNO5mbG
         GMQ3N4/5spYICyIlSO+27PKPeNxDnRiuMkr5FM1S32IKSqryHJnWvz6OGBdNXFjWIGSC
         Ag/YXM2pW77/KM0Xk1oWJIXgIqr7Gq2J0kJiqa95teEdETfnm8sVZ5RUcBI0ah8jHAbu
         GJ8RkCQXdrWenu3BRMU3McAet4+THQ8e5CcPtp6jzJNKEDiu1KMCFdr5L9ZDLTEjhQ5Q
         WewQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760005649; x=1760610449;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=S7SMK7Eojdtn+Nx/EezZL1EdsCGAXq4wpHEWP6euwvI=;
        b=YfP3T5qe7SPSXIsmHJAoEjxB7SxXGDIVzF5L/+horjfocnNKee+KiPQeG1vNrUCoGn
         mpcBnPrODrB/kf63fFiU3q2JffdExmdRcw+30cP06RyN73Rh8lHw7PKP84b7ucbvqL94
         1N2dIlvoRXsFbll6VcYJra1pbFmtPSHfVghRK2ULMjgT6jnnO/QKbRxyAJRWzyInyIJE
         8E//LHG6NnTTc1xgtOjCTScip+LtnfhhJCv7DMCuxsCdSjLjIv9c0b7MpTcfJ9TCp4ZZ
         tADvHjNaU/dtDkoi5+L3PToIsHiw4SrPZYx89C1rNYs3cquSYjSLw1QNcp3TzloUsa8C
         mgQQ==
X-Forwarded-Encrypted: i=2; AJvYcCVP39KvDDEj+qV3bsQe2exjX8itOoE/KwD6kavfrCOAwiN7DPdRIKp6F1UXOJxPVGWNmdOJKw==@lfdr.de
X-Gm-Message-State: AOJu0YwWCx76O07YfmECV11PeofPoX4yf/n1yBzZBgYfCooWRkTlPbZa
	sq8PBIneidUKNyHNzlGc9hQtMyJcyngCsIC+1J6PJvZAOcI8JjBnHXDQ
X-Google-Smtp-Source: AGHT+IEkoJhi9zI9sjFRcTRu2L6zhyjJ9uIM+PbqG5J/nxSkyh/a9E4sUHieMzRItPchkVL5BTMyjA==
X-Received: by 2002:a17:903:4b04:b0:28e:80d7:662d with SMTP id d9443c01a7336-2902741e4c2mr76452375ad.58.1760005648499;
        Thu, 09 Oct 2025 03:27:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5JnZBiQJAbSHACjwC8Xx7AA+jhRTWOKIYjkq3KQnPPBw=="
Received: by 2002:a17:902:cccc:b0:248:96db:5c48 with SMTP id
 d9443c01a7336-290358d2292ls8712515ad.2.-pod-prod-06-us; Thu, 09 Oct 2025
 03:27:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWJW5KaH/QksDhm1o40H+hGujIOuDC7RIv1HY7q+BFWBp/MOfXvwpSrAU9qMZ3aixjpOGJ+8/0ahJo=@googlegroups.com
X-Received: by 2002:a17:902:ccc4:b0:24c:e6fa:2a38 with SMTP id d9443c01a7336-2902739ad2emr87961005ad.25.1760005646919;
        Thu, 09 Oct 2025 03:27:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760005646; cv=none;
        d=google.com; s=arc-20240605;
        b=PrulKmWLeHSGUgxf53ln8UC0Fa6+EEoTc1OoxQN7IBPbBOd3x0ztZ8xUS1Gj90e8WR
         0LOo0acldh0RF3R6PD/N2wVHSIJ4YsiafoDII9eUediRBfSmpFpcdZc7IuCqA5tqmPT+
         rbXAhZMyN4gYtPkd8I08LZkogmnl3vek65PhDdduNdiAt7A683ZCDA6UCZ6L3C9W6Uer
         fg3XQpEYEDDptxurmJf7R61gNG12w9KEmSnQFfwADYRpUTd7lcZyUtf53p0ytnGboL1K
         oQD6xED1+FNYqzm+7VFEINK3cSqLlLECvXGpPTyKeSp6ZDubJuZ3hCxNffFUSETlyHY2
         YPfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=PnaMSwBDtuymaXBhgXecb0+EmYLZhk15irlwltuvb1Y=;
        fh=wSUxjKwRzabu5KWrHWDtJQuf0PxT/RfI0rTbo+Ka+jc=;
        b=DZH5HIh9xOfcHhfhQ64wGWMPIbIL6+fdjiH8wj/WQum08fTWGGGoN03a/RAdqjyubc
         GSZ/T3l7VUJ+Z2XVS5/M350YkIhZ/Pu5HHiYog4vAQQsFHzjFvwmTVUXka0oCEHJlGC1
         83I85GPkCe4EEwOSv3ZyRqZiXE9YLNtoNevey7FDVN85goLXPKcLyshMmRWuu7e++Z+1
         Vy3rddPTIW/OSSHPf8zjj856RGE1sAC37i/rQD9j04SbR6+MgeTbmcH5m7hhTFNFxGot
         qxKUvR1+dAcnCs+bMo6di7IH1/IZLNARGZSh6SBQZLxMdz6jqo9Eze5Z0b+JuLzIUzG8
         wZAw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=AmPJ4HRf;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-290364cac3csi1116145ad.2.2025.10.09.03.27.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:27:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f72.google.com (mail-wr1-f72.google.com
 [209.85.221.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-76-o_TiAtevNbe0H0CltLepHA-1; Thu, 09 Oct 2025 06:27:25 -0400
X-MC-Unique: o_TiAtevNbe0H0CltLepHA-1
X-Mimecast-MFC-AGG-ID: o_TiAtevNbe0H0CltLepHA_1760005644
Received: by mail-wr1-f72.google.com with SMTP id ffacd0b85a97d-3ee1365964cso755949f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:27:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXDSIgJAH7Ig8XzEszM1bzYnxMqnub2nfHNt0rTS0RiVstnBDaggofZuLsEOGmbZLKJLmsX9eBmwWw=@googlegroups.com
X-Gm-Gg: ASbGncs8DhMH6AXtcxNqs3sAxrX2/kOf71ly80jrkf7yzjo2r616r7GZ1zJuyVqEiuX
	DDckDS+DdLxpIE73aLnFYHqQR++d2JalE7HRxpC9k7kbv16vwyHe5Djj2pt4i5dEYIlYUGBzlq0
	LVbkl22GPmd+N+IsaPmUfeYYNAPiSyN5wQ5ObLpXiJC9sqi79KCcLn22wkcQZt+Tr3jt6ZQN+Tb
	clu7+44rR+8+R7jRGq4mQ6Cdb4TxoBvyi+F/1OU1Vqb+h02hffER83KAs2PfbioTbwP7sK19nuy
	1Bbeu4yYul9uU23cmjOiIOAqgwuigaTszwhvVZ2eHcF5wV2PtQmPKDj8nBZUNg+oSyb0N1w/gTs
	cHEyOLuW9
X-Received: by 2002:a05:6000:26c9:b0:425:74e1:25f7 with SMTP id ffacd0b85a97d-4266e8e6d0amr4383261f8f.62.1760005643634;
        Thu, 09 Oct 2025 03:27:23 -0700 (PDT)
X-Received: by 2002:a05:6000:26c9:b0:425:74e1:25f7 with SMTP id ffacd0b85a97d-4266e8e6d0amr4383228f8f.62.1760005643040;
        Thu, 09 Oct 2025 03:27:23 -0700 (PDT)
Received: from [192.168.3.141] (tmo-083-189.customers.d1-online.com. [80.187.83.189])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-4255d8ab8fdsm33619939f8f.15.2025.10.09.03.27.18
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:27:22 -0700 (PDT)
Message-ID: <543e9440-8ee0-4d9e-9b05-0107032d665b@redhat.com>
Date: Thu, 9 Oct 2025 12:27:17 +0200
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
 <1db15a30-72d6-4045-8aa1-68bd8411b0ba@redhat.com>
 <0c730c52-97ee-43ea-9697-ac11d2880ab7@csgroup.eu>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <0c730c52-97ee-43ea-9697-ac11d2880ab7@csgroup.eu>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: JMtt8qbNhlyeMGZjw1oltda1x5Qm1T_J0D5Kpbw9ybY_1760005644
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=AmPJ4HRf;
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

On 09.10.25 12:01, Christophe Leroy wrote:
>=20
>=20
> Le 09/10/2025 =C3=A0 11:20, David Hildenbrand a =C3=A9crit=C2=A0:
>> On 09.10.25 11:16, Christophe Leroy wrote:
>>>
>>>
>>> Le 09/10/2025 =C3=A0 10:14, David Hildenbrand a =C3=A9crit=C2=A0:
>>>> On 09.10.25 10:04, Christophe Leroy wrote:
>>>>>
>>>>>
>>>>> Le 09/10/2025 =C3=A0 09:22, David Hildenbrand a =C3=A9crit=C2=A0:
>>>>>> On 09.10.25 09:14, Christophe Leroy wrote:
>>>>>>> Hi David,
>>>>>>>
>>>>>>> Le 01/09/2025 =C3=A0 17:03, David Hildenbrand a =C3=A9crit=C2=A0:
>>>>>>>> diff --git a/mm/hugetlb.c b/mm/hugetlb.c
>>>>>>>> index 1e777cc51ad04..d3542e92a712e 100644
>>>>>>>> --- a/mm/hugetlb.c
>>>>>>>> +++ b/mm/hugetlb.c
>>>>>>>> @@ -4657,6 +4657,7 @@ static int __init hugetlb_init(void)
>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON(siz=
eof_field(struct page, private) *
>>>>>>>> BITS_PER_BYTE <
>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __NR_HPAGEFLAGS);
>>>>>>>> +=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON_INVALID(HUGETLB_PAGE_ORDER > MAX_=
FOLIO_ORDER);
>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!hugepages_s=
upported()) {
>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 if (hugetlb_max_hstate ||
>>>>>>>> default_hstate_max_huge_pages)
>>>>>>>> @@ -4740,6 +4741,7 @@ void __init hugetlb_add_hstate(unsigned int
>>>>>>>> order)
>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(hugetlb_m=
ax_hstate >=3D HUGE_MAX_HSTATE);
>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(order < o=
rder_base_2(__NR_USED_SUBPAGE));
>>>>>>>> +=C2=A0=C2=A0=C2=A0 WARN_ON(order > MAX_FOLIO_ORDER);
>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 h =3D &hstates[h=
ugetlb_max_hstate++];
>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __mutex_init(&h-=
>resize_lock, "resize mutex", &h-
>>>>>>>>> resize_key);
>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 h->order =3D ord=
er;
>>>>>>
>>>>>> We end up registering hugetlb folios that are bigger than
>>>>>> MAX_FOLIO_ORDER. So we have to figure out how a config can trigger
>>>>>> that
>>>>>> (and if we have to support that).
>>>>>>
>>>>>
>>>>> MAX_FOLIO_ORDER is defined as:
>>>>>
>>>>> #ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
>>>>> #define MAX_FOLIO_ORDER=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PUD=
_ORDER
>>>>> #else
>>>>> #define MAX_FOLIO_ORDER=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 MAX=
_PAGE_ORDER
>>>>> #endif
>>>>>
>>>>> MAX_PAGE_ORDER is the limit for dynamic creation of hugepages via
>>>>> /sys/kernel/mm/hugepages/ but bigger pages can be created at boottime
>>>>> with kernel boot parameters without CONFIG_ARCH_HAS_GIGANTIC_PAGE:
>>>>>
>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0 hugepagesz=3D64m hugepages=3D1 hugepagesz=
=3D256m hugepages=3D1
>>>>>
>>>>> Gives:
>>>>>
>>>>> HugeTLB: registered 1.00 GiB page size, pre-allocated 0 pages
>>>>> HugeTLB: 0 KiB vmemmap can be freed for a 1.00 GiB page
>>>>> HugeTLB: registered 64.0 MiB page size, pre-allocated 1 pages
>>>>> HugeTLB: 0 KiB vmemmap can be freed for a 64.0 MiB page
>>>>> HugeTLB: registered 256 MiB page size, pre-allocated 1 pages
>>>>> HugeTLB: 0 KiB vmemmap can be freed for a 256 MiB page
>>>>> HugeTLB: registered 4.00 MiB page size, pre-allocated 0 pages
>>>>> HugeTLB: 0 KiB vmemmap can be freed for a 4.00 MiB page
>>>>> HugeTLB: registered 16.0 MiB page size, pre-allocated 0 pages
>>>>> HugeTLB: 0 KiB vmemmap can be freed for a 16.0 MiB page
>>>>
>>>> I think it's a violation of CONFIG_ARCH_HAS_GIGANTIC_PAGE. The existin=
g
>>>> folio_dump() code would not handle it correctly as well.
>>>
>>> I'm trying to dig into history and when looking at commit 4eb0716e868e
>>> ("hugetlb: allow to free gigantic pages regardless of the
>>> configuration") I understand that CONFIG_ARCH_HAS_GIGANTIC_PAGE is
>>> needed to be able to allocate gigantic pages at runtime. It is not
>>> needed to reserve gigantic pages at boottime.
>>>
>>> What am I missing ?
>>
>> That CONFIG_ARCH_HAS_GIGANTIC_PAGE has nothing runtime-specific in its
>> name.
>=20
> In its name for sure, but the commit I mention says:
>=20
>       On systems without CONTIG_ALLOC activated but that support gigantic
> pages,
>       boottime reserved gigantic pages can not be freed at all.  This pat=
ch
>       simply enables the possibility to hand back those pages to memory
>       allocator.

Right, I think it was a historical artifact.

>=20
> And one of the hunks is:
>=20
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index 7f7fbd8bd9d5b..7a1aa53d188d3 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -19,7 +19,7 @@ config ARM64
>           select ARCH_HAS_FAST_MULTIPLIER
>           select ARCH_HAS_FORTIFY_SOURCE
>           select ARCH_HAS_GCOV_PROFILE_ALL
> -       select ARCH_HAS_GIGANTIC_PAGE if CONTIG_ALLOC
> +       select ARCH_HAS_GIGANTIC_PAGE
>           select ARCH_HAS_KCOV
>           select ARCH_HAS_KEEPINITRD
>           select ARCH_HAS_MEMBARRIER_SYNC_CORE
>=20
> So I understand from the commit message that it was possible at that
> time to have gigantic pages without ARCH_HAS_GIGANTIC_PAGE as long as
> you didn't have to be able to free them during runtime.

Yes, I agree.

>=20
>>
>> Can't we just select CONFIG_ARCH_HAS_GIGANTIC_PAGE for the relevant
>> hugetlb config that allows for *gigantic pages*.
>>
>=20
> We probably can, but I'd really like to understand history and how we
> ended up in the situation we are now.
> Because blind fixes often lead to more problems.

Yes, let's figure out how to to it cleanly.

>=20
> If I follow things correctly I see a helper gigantic_page_supported()
> added by commit 944d9fec8d7a ("hugetlb: add support for gigantic page
> allocation at runtime").
>=20
> And then commit 461a7184320a ("mm/hugetlb: introduce
> ARCH_HAS_GIGANTIC_PAGE") is added to wrap gigantic_page_supported()
>=20
> Then commit 4eb0716e868e ("hugetlb: allow to free gigantic pages
> regardless of the configuration") changed gigantic_page_supported() to
> gigantic_page_runtime_supported()
>=20
> So where are we now ?

In

commit fae7d834c43ccdb9fcecaf4d0f33145d884b3e5c
Author: Matthew Wilcox (Oracle) <willy@infradead.org>
Date:   Tue Feb 27 19:23:31 2024 +0000

     mm: add __dump_folio()


We started assuming that a folio in the system (boottime, dynamic, whatever=
)
has a maximum of MAX_FOLIO_NR_PAGES.

Any other interpretation doesn't make any sense for MAX_FOLIO_NR_PAGES.


So we have two questions:

1) How to teach MAX_FOLIO_NR_PAGES that hugetlb supports gigantic pages

2) How do we handle CONFIG_ARCH_HAS_GIGANTIC_PAGE


We have the following options

(A) Rename existing CONFIG_ARCH_HAS_GIGANTIC_PAGE to something else that is
clearer and add a new CONFIG_ARCH_HAS_GIGANTIC_PAGE.

(B) Rename existing CONFIG_ARCH_HAS_GIGANTIC_PAGE -> to something else that=
 is
clearer and derive somehow else that hugetlb in that config supports gigant=
ic pages.

(c) Just use CONFIG_ARCH_HAS_GIGANTIC_PAGE if hugetlb on an architecture
supports gigantic pages.


I don't quite see why an architecture should be able to opt in into dynamic=
ally
allocating+freeing gigantic pages. That's just CONTIG_ALLOC magic and not s=
ome
arch-specific thing IIRC.


Note that in mm/hugetlb.c it is

	#ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
	#ifdef CONFIG_CONTIG_ALLOC

Meaning that at least the allocation side is guarded by CONTIG_ALLOC.

So I think (C) is just the right thing to do.

diff --git a/fs/Kconfig b/fs/Kconfig
index 0bfdaecaa8775..12c11eb9279d3 100644
--- a/fs/Kconfig
+++ b/fs/Kconfig
@@ -283,6 +283,8 @@ config HUGETLB_PMD_PAGE_TABLE_SHARING
         def_bool HUGETLB_PAGE
         depends on ARCH_WANT_HUGE_PMD_SHARE && SPLIT_PMD_PTLOCKS
 =20
+# An architecture must select this option if there is any mechanism (esp. =
hugetlb)
+# could obtain gigantic folios.
  config ARCH_HAS_GIGANTIC_PAGE
         bool
 =20


--=20
Cheers

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5=
43e9440-8ee0-4d9e-9b05-0107032d665b%40redhat.com.
