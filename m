Return-Path: <kasan-dev+bncBC32535MUICBBEHGT3DQMGQEHWR7X5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 41477BC92E7
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 15:05:22 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-77b73bddbdcsf1253337b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 06:05:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760015121; cv=pass;
        d=google.com; s=arc-20240605;
        b=H1AFbmFjy2nEbiIqhNBwI9zZNb8EoffbbZQyLKyZ9PsduzRZirRAWKdiRoNbAl20SL
         akjrYssZi+0vRAS+gcCUUJpgJ2/v1QjtY6jEV1rj4ZbhrnEqAmKHUfcM/j+AYQ7f/Ymq
         0F3xVsaa7wkukafN6dluiJUEl902Ngl1Jmf4kTJhmlQUaRmO+YWvD6+ls2ZX+mF9Qhjh
         pRAx8+fFMhSU3M5WbZrS2KsdkEdv7Z187aklibo5SOCVtp4GJy1ufffPK5eHNxvYztm3
         iBOEx2EqHSnAYMFVlyh8MK/2zbHFkYvaG+qNlxjLdPESfKS6H5Jx5EIEjmwyOvhMuKjG
         OB3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=uu1tJr9rcmFdmubfMYRwGWi3XBWUEUjbtk7N12VCjDw=;
        fh=4rxSBzNbT6ToaJkPDOiiTFenZXDSTGrjccnOvXH4/sQ=;
        b=FOiwSh4P8OGV5SV058qMh8IEnGQ6VEaYai6lMZf/78ZZkjdN6EUagMk1k6CIaEMgTc
         7TgSIOqM/JoT3IJArE/I5BjE0UhFJwVMuZ4I1mvupMHMXzWrexSN1iLrOvHHClnPMULf
         eEaWP8RCcUwh0/bt5b6io8oMo8Kjr62YUMrFTlF0RqNqUbNlUy7l5utP8hJbvLvljFo7
         RDnfiMQszw9Wo/mRHcVr6H3aH40O57PZy5zR0B5AcbR1WgkuDof3NzJJzwG79KvwUm/s
         OWoIF9YyecSFDtXLSHR4vFacNVh61op7RxsnG2EoKltpyCPM/u3g31zsbVJIepp7VgZ6
         yxow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=YHvPbhWU;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760015121; x=1760619921; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=uu1tJr9rcmFdmubfMYRwGWi3XBWUEUjbtk7N12VCjDw=;
        b=QzcuX5nVPHUtIHeyRVUWfAWDoeAQBX+w3xonQ04Dl6qUavBS5//rJSIuCBh20lcza/
         uosp9z0iwLJvf+R1ApMPOTW7OIEY2P4biqAZ2KYYAJNy/hYz4H+P2o1wpZKB4+DEYZ52
         wWgSXH53dCRpyXCsg+ay7MB8Yh99PWq6UeNq26DG+LDCnLgr6J0uQDVSiuFaF8Vh/wg9
         qF/P87qXPPzNZ4YK7845NXhiN3r/Py1HrkYC34puVpYQkzpR6ecV+aSlcSm/fhpb9nRP
         rWd39GdJ/NFMj930lsCUlbn0wLUVeCd14h1vjmcaaZioNXjApFHimGpxtOMmK4extN5a
         84eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760015121; x=1760619921;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uu1tJr9rcmFdmubfMYRwGWi3XBWUEUjbtk7N12VCjDw=;
        b=arfU1ntwXF80vE9unigH+z8Kb1bw6Ki52GudKMpjHuRoec0O22Soi1PF4t7IvjW4xA
         J5RtYmS4ErAiV09M0szx9361Foop/CtIwxkVKJ6B8kV1uvRGlvaYbdTYc4JSZk0i9fV+
         YAGihL/vudkvUZ0/nGs+abptnp1m25b+DiYPgX7Jk8CsbAEOU82Enp84BbNg5dGksm9o
         f8H64jL5riwTutoXpGqajqdUWwOf2drJFvUBce+J8B5RiZ6GWgkHREYBTUv7Eh4/Ctkj
         RT+HEzeX4JgNCOKu4GAPYiQKHkgpI9+Za4LChXSP/zFgNmd+4IhmZyT+ktqjEsJ/nPVL
         j/KA==
X-Forwarded-Encrypted: i=2; AJvYcCWgy2YTkTSeO5WgvU49CosBSY/XPVwL3hEpwqFctaLG604UmScaHQF8/cNpqKRibjMmslSDJQ==@lfdr.de
X-Gm-Message-State: AOJu0YySXTFEEK2DrBmXuv/Ab2QIpnhRMprBWpGKcdI2WS4zBgACuInJ
	BTma4ljU00faPgM2VZjV17FXKHfYDkORzDPjQE5t1ApGQmQCL5RuEZRP
X-Google-Smtp-Source: AGHT+IG9an7r7rNL7vhovpHtcwrvpe9UdxPYuTYqrHHH62zKHEIjJU8YvRbcUlYKxmPdVUztxXrrhg==
X-Received: by 2002:a05:6a00:a15:b0:76b:ecf2:7ece with SMTP id d2e1a72fcca58-79231df6680mr11835886b3a.12.1760015120348;
        Thu, 09 Oct 2025 06:05:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5hAOVKBAS56mFWvqrfUdHILLC2pKeuQ28nvJ1WoMO9Sw=="
Received: by 2002:a05:6a00:2e9d:b0:76b:ff54:2a0 with SMTP id
 d2e1a72fcca58-7938e7533c6ls977704b3a.2.-pod-prod-00-us-canary; Thu, 09 Oct
 2025 06:05:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXagz7J8nEdoaPLfA0N+CcMeabMq/CTglYE+Sx2OMkJSAwF+f3EVIQY7fNscArMpr9kL82rM8DyUpk=@googlegroups.com
X-Received: by 2002:a05:6a21:9999:b0:2e4:3c9:2ca4 with SMTP id adf61e73a8af0-32d96e5d6b2mr16185309637.16.1760015118398;
        Thu, 09 Oct 2025 06:05:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760015118; cv=none;
        d=google.com; s=arc-20240605;
        b=S1advjmlxj5mP0adnKbRAOVbVwS5MQCX0OmtaiYogjz0j1lrFymX+BDLGgpxjUxUvu
         Wxv9U6WcU7PsaooBJCTIl55HQ4mwArdC22HIGtzcSaZiTlE6FZAQ+oiXDZT6GRBOfOwG
         LIuL4VWE6b9wMCkKE+2Edr0tl2NmlreoU0BK1Tnvz1++cQolArMLjE8YDL5KHDKd9VHJ
         UiUr9qRgS1e8PASLKbQNyeH3dhDAlKiMMnGvgjVFB3lTI8LDv86LbsZEecpF0UiFCiy6
         8SnJa5arQlYH94OP6FyXe1SO/Stf3WCBJwBWwQ4lWuW+QhiDzCNkILZrfYZjDgLijMce
         qAtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=oTHo4iuJRNf/FsWLVapxfI0HO0lapgIr2CMWX1RNMGw=;
        fh=PuMTI5LzEH7ZRtldp1/XTvlDvBiLHBzAfaCkJkkSSTM=;
        b=cHDOLxeJdRdjMzuEf0bB+GIItH7XCvdMB1nSf7S45RKlX9CY5JEV82rkzgIpT924Tk
         8zWHF02z0jEMR5gALfa+DjMf9fL1dfFLICSPyA3gvnztjKo0w7RpF5rWiLWah12dIkaI
         JM1PpK98sYL3PmIJcsmWSTJjTK2qtSfD6q19phHWVnmJCwtS4XVeNcqcKMX25wwijBsr
         8oNdF+b5+j7vzEJErD/celugYnt1ed/SFGIKPNWih3HUN1IsB0Ia0YUFJ/2rpBniHaA2
         /A91p6qSStxJ33fZSkjK5FFstrh810lkz1SRagrF/sc3oEFEjcIao7H2NuQ0XJtcj1L5
         sHiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=YHvPbhWU;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b639612323fsi109873a12.2.2025.10.09.06.05.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 06:05:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-527-ZoTM_mOyNueZFShpqt8gIQ-1; Thu, 09 Oct 2025 09:05:14 -0400
X-MC-Unique: ZoTM_mOyNueZFShpqt8gIQ-1
X-Mimecast-MFC-AGG-ID: ZoTM_mOyNueZFShpqt8gIQ_1760015113
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-46e45899798so7116655e9.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 06:05:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVBWR78PdlcTSVHkQWWCGcAp8oP4off1J44psh4K6tZwq9+Qd0zupS0FKX+1BIeOgpRFDT1J6X25wo=@googlegroups.com
X-Gm-Gg: ASbGncvndp+5CBHLq87Gay/sDp65/Tj2dZzw4KJAHEyAyuHvXeDK6L6fnZcrSSikQRu
	MkpdqbuVQmitREVUn3qQ147uraMpjE53rPUCEmLbds+o7qiGaD9kpVcaGNwvTUsr2Y8n1ZSwdfC
	2uv7bakHCuT6TI+smRx4rhxlosCjoosowlVzIKoyddnGrLxXoSK20/Be2HRBDiGkiSgzNSnflOZ
	ud3Am3Y55nlBLVJQirgYMRLsSdbcl62Vn5NCymG/cOPKkESq5IMkbI2VrBUxcemo0R/osBBaFYU
	gN9vbzXiXZncjaG57PTmR4KlrJa1y4KI4assauOWpR+/1r+5TXyulIVDCdFp9DjVoLAnFcwW6Ox
	l060WGzfh
X-Received: by 2002:a05:600c:83c9:b0:46f:b42e:edd0 with SMTP id 5b1f17b1804b1-46fb42eee2emr2581095e9.41.1760015112978;
        Thu, 09 Oct 2025 06:05:12 -0700 (PDT)
X-Received: by 2002:a05:600c:83c9:b0:46f:b42e:edd0 with SMTP id 5b1f17b1804b1-46fb42eee2emr2580495e9.41.1760015112341;
        Thu, 09 Oct 2025 06:05:12 -0700 (PDT)
Received: from [192.168.3.141] (tmo-083-189.customers.d1-online.com. [80.187.83.189])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-46faf112fdbsm47591035e9.8.2025.10.09.06.05.08
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 06:05:11 -0700 (PDT)
Message-ID: <bce57a83-e7e1-4e3d-85ae-6234a98975ea@redhat.com>
Date: Thu, 9 Oct 2025 15:05:06 +0200
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
 <543e9440-8ee0-4d9e-9b05-0107032d665b@redhat.com>
 <4632e721-0ac8-4d72-a8ed-e6c928eee94d@csgroup.eu>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <4632e721-0ac8-4d72-a8ed-e6c928eee94d@csgroup.eu>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: Pfwuvme7o7bz_N0RejaVpLVwglml5rQyIU8Ybx-4BQM_1760015113
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=YHvPbhWU;
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

On 09.10.25 14:08, Christophe Leroy wrote:
>=20
>=20
> Le 09/10/2025 =C3=A0 12:27, David Hildenbrand a =C3=A9crit=C2=A0:
>> On 09.10.25 12:01, Christophe Leroy wrote:
>>>
>>>
>>> Le 09/10/2025 =C3=A0 11:20, David Hildenbrand a =C3=A9crit=C2=A0:
>>>> On 09.10.25 11:16, Christophe Leroy wrote:
>>>>>
>>>>>
>>>>> Le 09/10/2025 =C3=A0 10:14, David Hildenbrand a =C3=A9crit=C2=A0:
>>>>>> On 09.10.25 10:04, Christophe Leroy wrote:
>>>>>>>
>>>>>>>
>>>>>>> Le 09/10/2025 =C3=A0 09:22, David Hildenbrand a =C3=A9crit=C2=A0:
>>>>>>>> On 09.10.25 09:14, Christophe Leroy wrote:
>>>>>>>>> Hi David,
>>>>>>>>>
>>>>>>>>> Le 01/09/2025 =C3=A0 17:03, David Hildenbrand a =C3=A9crit=C2=A0:
>>>>>>>>>> diff --git a/mm/hugetlb.c b/mm/hugetlb.c
>>>>>>>>>> index 1e777cc51ad04..d3542e92a712e 100644
>>>>>>>>>> --- a/mm/hugetlb.c
>>>>>>>>>> +++ b/mm/hugetlb.c
>>>>>>>>>> @@ -4657,6 +4657,7 @@ static int __init hugetlb_init(void)
>>>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUILD_BU=
G_ON(sizeof_field(struct page, private) *
>>>>>>>>>> BITS_PER_BYTE <
>>>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __NR_HPAGEFLAGS);
>>>>>>>>>> +=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON_INVALID(HUGETLB_PAGE_ORDER > MA=
X_FOLIO_ORDER);
>>>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!hug=
epages_supported()) {
>>>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 if (hugetlb_max_hstate ||
>>>>>>>>>> default_hstate_max_huge_pages)
>>>>>>>>>> @@ -4740,6 +4741,7 @@ void __init hugetlb_add_hstate(unsigned in=
t
>>>>>>>>>> order)
>>>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(h=
ugetlb_max_hstate >=3D HUGE_MAX_HSTATE);
>>>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(o=
rder < order_base_2(__NR_USED_SUBPAGE));
>>>>>>>>>> +=C2=A0=C2=A0=C2=A0 WARN_ON(order > MAX_FOLIO_ORDER);
>>>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 h =3D &h=
states[hugetlb_max_hstate++];
>>>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __mutex_=
init(&h->resize_lock, "resize mutex", &h-
>>>>>>>>>>> resize_key);
>>>>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 h->order=
 =3D order;
>>>>>>>>
>>>>>>>> We end up registering hugetlb folios that are bigger than
>>>>>>>> MAX_FOLIO_ORDER. So we have to figure out how a config can trigger
>>>>>>>> that
>>>>>>>> (and if we have to support that).
>>>>>>>>
>>>>>>>
>>>>>>> MAX_FOLIO_ORDER is defined as:
>>>>>>>
>>>>>>> #ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
>>>>>>> #define MAX_FOLIO_ORDER=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 P=
UD_ORDER
>>>>>>> #else
>>>>>>> #define MAX_FOLIO_ORDER=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 M=
AX_PAGE_ORDER
>>>>>>> #endif
>>>>>>>
>>>>>>> MAX_PAGE_ORDER is the limit for dynamic creation of hugepages via
>>>>>>> /sys/kernel/mm/hugepages/ but bigger pages can be created at bootti=
me
>>>>>>> with kernel boot parameters without CONFIG_ARCH_HAS_GIGANTIC_PAGE:
>>>>>>>
>>>>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 hugepagesz=3D64m hugepages=3D1 huge=
pagesz=3D256m hugepages=3D1
>>>>>>>
>>>>>>> Gives:
>>>>>>>
>>>>>>> HugeTLB: registered 1.00 GiB page size, pre-allocated 0 pages
>>>>>>> HugeTLB: 0 KiB vmemmap can be freed for a 1.00 GiB page
>>>>>>> HugeTLB: registered 64.0 MiB page size, pre-allocated 1 pages
>>>>>>> HugeTLB: 0 KiB vmemmap can be freed for a 64.0 MiB page
>>>>>>> HugeTLB: registered 256 MiB page size, pre-allocated 1 pages
>>>>>>> HugeTLB: 0 KiB vmemmap can be freed for a 256 MiB page
>>>>>>> HugeTLB: registered 4.00 MiB page size, pre-allocated 0 pages
>>>>>>> HugeTLB: 0 KiB vmemmap can be freed for a 4.00 MiB page
>>>>>>> HugeTLB: registered 16.0 MiB page size, pre-allocated 0 pages
>>>>>>> HugeTLB: 0 KiB vmemmap can be freed for a 16.0 MiB page
>>>>>>
>>>>>> I think it's a violation of CONFIG_ARCH_HAS_GIGANTIC_PAGE. The
>>>>>> existing
>>>>>> folio_dump() code would not handle it correctly as well.
>>>>>
>>>>> I'm trying to dig into history and when looking at commit 4eb0716e868=
e
>>>>> ("hugetlb: allow to free gigantic pages regardless of the
>>>>> configuration") I understand that CONFIG_ARCH_HAS_GIGANTIC_PAGE is
>>>>> needed to be able to allocate gigantic pages at runtime. It is not
>>>>> needed to reserve gigantic pages at boottime.
>>>>>
>>>>> What am I missing ?
>>>>
>>>> That CONFIG_ARCH_HAS_GIGANTIC_PAGE has nothing runtime-specific in its
>>>> name.
>>>
>>> In its name for sure, but the commit I mention says:
>>>
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 On systems without CONTIG_ALLOC activat=
ed but that support gigantic
>>> pages,
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 boottime reserved gigantic pages can no=
t be freed at all.=C2=A0 This
>>> patch
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 simply enables the possibility to hand =
back those pages to memory
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 allocator.
>>
>> Right, I think it was a historical artifact.
>>
>>>
>>> And one of the hunks is:
>>>
>>> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
>>> index 7f7fbd8bd9d5b..7a1aa53d188d3 100644
>>> --- a/arch/arm64/Kconfig
>>> +++ b/arch/arm64/Kconfig
>>> @@ -19,7 +19,7 @@ config ARM64
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS=
_FAST_MULTIPLIER
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS=
_FORTIFY_SOURCE
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS=
_GCOV_PROFILE_ALL
>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS_GIGANTIC_PAGE if =
CONTIG_ALLOC
>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS_GIGANTIC_PAGE
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS=
_KCOV
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS=
_KEEPINITRD
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select ARCH_HAS=
_MEMBARRIER_SYNC_CORE
>>>
>>> So I understand from the commit message that it was possible at that
>>> time to have gigantic pages without ARCH_HAS_GIGANTIC_PAGE as long as
>>> you didn't have to be able to free them during runtime.
>>
>> Yes, I agree.
>>
>>>
>>>>
>>>> Can't we just select CONFIG_ARCH_HAS_GIGANTIC_PAGE for the relevant
>>>> hugetlb config that allows for *gigantic pages*.
>>>>
>>>
>>> We probably can, but I'd really like to understand history and how we
>>> ended up in the situation we are now.
>>> Because blind fixes often lead to more problems.
>>
>> Yes, let's figure out how to to it cleanly.
>>
>>>
>>> If I follow things correctly I see a helper gigantic_page_supported()
>>> added by commit 944d9fec8d7a ("hugetlb: add support for gigantic page
>>> allocation at runtime").
>>>
>>> And then commit 461a7184320a ("mm/hugetlb: introduce
>>> ARCH_HAS_GIGANTIC_PAGE") is added to wrap gigantic_page_supported()
>>>
>>> Then commit 4eb0716e868e ("hugetlb: allow to free gigantic pages
>>> regardless of the configuration") changed gigantic_page_supported() to
>>> gigantic_page_runtime_supported()
>>>
>>> So where are we now ?
>>
>> In
>>
>> commit fae7d834c43ccdb9fcecaf4d0f33145d884b3e5c
>> Author: Matthew Wilcox (Oracle) <willy@infradead.org>
>> Date:=C2=A0=C2=A0 Tue Feb 27 19:23:31 2024 +0000
>>
>>   =C2=A0=C2=A0=C2=A0 mm: add __dump_folio()
>>
>>
>> We started assuming that a folio in the system (boottime, dynamic,
>> whatever)
>> has a maximum of MAX_FOLIO_NR_PAGES.
>>
>> Any other interpretation doesn't make any sense for MAX_FOLIO_NR_PAGES.
>>
>>
>> So we have two questions:
>>
>> 1) How to teach MAX_FOLIO_NR_PAGES that hugetlb supports gigantic pages
>>
>> 2) How do we handle CONFIG_ARCH_HAS_GIGANTIC_PAGE
>>
>>
>> We have the following options
>>
>> (A) Rename existing CONFIG_ARCH_HAS_GIGANTIC_PAGE to something else that=
 is
>> clearer and add a new CONFIG_ARCH_HAS_GIGANTIC_PAGE.
>>
>> (B) Rename existing CONFIG_ARCH_HAS_GIGANTIC_PAGE -> to something else
>> that is
>> clearer and derive somehow else that hugetlb in that config supports
>> gigantic pages.
>>
>> (c) Just use CONFIG_ARCH_HAS_GIGANTIC_PAGE if hugetlb on an architecture
>> supports gigantic pages.
>>
>>
>> I don't quite see why an architecture should be able to opt in into
>> dynamically
>> allocating+freeing gigantic pages. That's just CONTIG_ALLOC magic and
>> not some
>> arch-specific thing IIRC.
>>
>>
>> Note that in mm/hugetlb.c it is
>>
>>   =C2=A0=C2=A0=C2=A0=C2=A0#ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
>>   =C2=A0=C2=A0=C2=A0=C2=A0#ifdef CONFIG_CONTIG_ALLOC
>>
>> Meaning that at least the allocation side is guarded by CONTIG_ALLOC.
>=20
> Yes but not the freeing since commit 4eb0716e868e ("hugetlb: allow to
> free gigantic pages regardless of the configuration")

Right, the freeing path is just always around as we no longer depend=20
free_contig_range().

>=20
>>
>> So I think (C) is just the right thing to do.
>>
>> diff --git a/fs/Kconfig b/fs/Kconfig
>> index 0bfdaecaa8775..12c11eb9279d3 100644
>> --- a/fs/Kconfig
>> +++ b/fs/Kconfig
>> @@ -283,6 +283,8 @@ config HUGETLB_PMD_PAGE_TABLE_SHARING
>>   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 def_bool HUGETLB_PAGE
>>   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 depends on ARCH_WANT_HUGE_P=
MD_SHARE && SPLIT_PMD_PTLOCKS
>>
>> +# An architecture must select this option if there is any mechanism
>> (esp. hugetlb)
>> +# could obtain gigantic folios.
>>   =C2=A0config ARCH_HAS_GIGANTIC_PAGE
>>   =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 bool
>>
>>
>=20
> I gave it a try. That's not enough, it fixes the problem for 64 Mbytes
> pages and 256 Mbytes pages, but not for 1 Gbytes pages.

Thanks!

>=20
> Max folio is defined by PUD_ORDER, but PUD_SIZE is 256 Mbytes so we need
> to make MAX_FOLIO larger. Do we change it to P4D_ORDER or is it too much
> ? P4D_SIZE is 128 Gbytes

The exact size doesn't matter, we started with something that soundes=20
reasonable.

I added the comment "There is no real limit on the folio size. We limit=20
them to the maximum we currently expect (e.g., hugetlb, dax)."

We can set it to whatever we would expect for now.

--=20
Cheers

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b=
ce57a83-e7e1-4e3d-85ae-6234a98975ea%40redhat.com.
