Return-Path: <kasan-dev+bncBC32535MUICBBQ5XWHCQMGQEO6ZRIPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 05183B33FE4
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 14:49:09 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-e951acdc109sf5130268276.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 05:49:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756126147; cv=pass;
        d=google.com; s=arc-20240605;
        b=aa+y5xxzKPRrWe8qgYyghZoDyZP4hJO+vfVERkqq/KxNj6bOFkHQXnnOMnO9YaezGk
         c9Ue66JGyCvuCEfWlpm0NnpS22ZmdwSm14PGTS4d7J6/pjEp8TLnSsacZM3D6iVnVWWq
         NyPwaiOz5qwjEkDwtiRpadKbXa77WQgEgcnEvieVaxPOrjuMNAUCUSxEtSJUEeMqz19t
         abF01E+HxBxXlgGhPMgJEmvx0ngwBwnXlYAjtEV8Wzj7OosJ4zL8bCUiP+Zv6dQArtl0
         wvhcX9LCzgDftAyi0O6HcK3hu7WCy9vX/GjaPqDwG/6tfhZePY8a9C1NQG+1swEsNvWj
         Tjdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=7hcL6vUCl+VmT1gZb/w02m7682wKxeVEVOFTwmlzimY=;
        fh=TkUP0bB9VwZSnVWlH62HlMQwutL1I9ohlScEo7fGEcE=;
        b=cTg+i/3L58aFpQdh3xZlAGU5pQuH1QnrZHcY9xk/I6/Z0XwrS67PsPQ9yUUocXTSXU
         xBMML2BkO4cwaSBrizc02Pf7m7Ivrqerq0T2I/cii0g6JlFEGAi+gBbmCz/XGvf8FJcW
         i7St551HRQ4tZVtxmc0Ygw5eqr4h33s6PSy51pae99RuyLA4j97mhggCP2vJNc51nBk6
         yLnyA5MpAoZh4XqHwYQ7HTOs5o1vLlM6nRZY4l6y3xYulbJ4mHvDJ4PzaddBUqxMbDoM
         iwQGxaEbtMf7VBv5c9aAok/phQdxb5qPuq5IDKN2l+R11fKtWygWZZrsNKgxjKItSWHY
         14Og==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BYxI1CvB;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756126147; x=1756730947; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=7hcL6vUCl+VmT1gZb/w02m7682wKxeVEVOFTwmlzimY=;
        b=BeHBXAZGD1xlLjG8iGFxn4QoPZ+fasT2HVFMug9x7IONeaa2rAh7N98PRhQN8CPglG
         lEvaNK+DMOae0NE80FqJZRipq02YAxolSBC/iO7SeCdpL2l4urmXGBB8Hv0f2RZAj75u
         YWyPMcckfaP4uH0ySDR42XziDH7fTCuQDyL6JuDh/hMp4UKx8E9rhaOkfM/A/DY/zwyC
         mfquRdG+GM57SOub2YYZjccdYc6ckDwjfAFVzObySIH6oanm8J+TnUeCqoe+FW3nLZMj
         IFVAZTR1KlbbvkUf24SRFa6RNpMRkbbYGCbBASo4Jl45L8HWrTIeC7eVhCuiGEp9Wgq4
         wnOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756126147; x=1756730947;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7hcL6vUCl+VmT1gZb/w02m7682wKxeVEVOFTwmlzimY=;
        b=lAG/OJWBH9FbsNM5RtyaVcvSLauXF1GyIQbndyJfn1ZKtLi/qBulRSyX/ykS2L18gR
         kAfMwBa8obAjIFri+WVJDbxJ3DhlITustItBsC7zIGgDcTJOglITnn2lx8PLifWzs3of
         QG00yxcmwtgtZeYcoP5LX9whqmmoi/mFMh+T2L5QD/AvbG4MWLEwKgq0FJ2TQXs8jofa
         QTetxEznbYGsL4VVsZeD1iu2pHhI8TjiUoeWeaTzFIH+wRxU+SZ1uW0gZpoUVKu1UKk4
         d0OOq4JLiTLYOU/vz6350FXn8SAYolr1R8Nfg4D3++8t+HsJDjZk23QYS2AZXpEl0tkI
         i3mg==
X-Forwarded-Encrypted: i=2; AJvYcCWy84eLAIxqx5cF2g+7QEF3GWeu1FwfJtSd0r411StbY4Ct2xvbURyG+v7A/dwt3Mo0lwVrAA==@lfdr.de
X-Gm-Message-State: AOJu0YzSsNDXtm6lOU/atpcBI8JODSVy1JFvSu27J2DmhykUgTxuc570
	fQ/SeUXh0PI5p5ldcpNnWlaEkewNPuvipKdpR1tVpYQLVfR+IPjZxwBv
X-Google-Smtp-Source: AGHT+IGgArermw25nRlxcDqNTeuXumFhihGERsThYf6wfAQDfwqLpxJoYZg24ZSVTQ+0li/C+NXhwg==
X-Received: by 2002:a05:6902:4281:b0:e93:3ba9:9e39 with SMTP id 3f1490d57ef6-e951c3aeba7mr13185391276.24.1756126147564;
        Mon, 25 Aug 2025 05:49:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcG4DFzDQ12XzdW3LT5nWwocpMjulWEHQYkKHXhAe2rLQ==
Received: by 2002:a25:c487:0:b0:e93:3895:89bf with SMTP id 3f1490d57ef6-e950467a55els4262626276.1.-pod-prod-08-us;
 Mon, 25 Aug 2025 05:49:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVY9E8C5zHM0pVVcgvwOCIwcJyL3JilJ19gS9lMcwip1TyylXoEyWqiFkFKSXk2VaguB9FJqboZ9dU=@googlegroups.com
X-Received: by 2002:a05:690c:4c05:b0:717:ca51:d781 with SMTP id 00721157ae682-71fdc3085b0mr130312687b3.17.1756126146688;
        Mon, 25 Aug 2025 05:49:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756126146; cv=none;
        d=google.com; s=arc-20240605;
        b=h6GlIWPpNhqTVBXra/lHYZIjkX7OZbxrSr5VDCIxnkXwXIXHL7tXTvQHSHuWZ3LVlB
         YEYjtfOp1Q25rLFyXiB82VnM2Opp7kHw1MuCUejEg7v7c5e2YM/Om6L+IGB0Ayxd2DyE
         oK/iVOZDSMNDrpQ4aFwZqfxFTxXpifASDJxZx5YmtIkjaSLh4KMHNw+RWM/QTyjuUV3+
         KJ4eg6chFvmznP7KJJUlCAiX4K3A6uIwtzXtRKxHlCImOvMHp4P3jn1O9gsKUr3d/aEc
         HSytqgaXvjGtrOXtpsW2UWCvN3Yzq3KGB8KjZ//VfYWVEvNVlM69P5UPMsvP0/uNV2bS
         h3eQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=3vXE/JZQfiOFAY8LityNc5lKOCwFML9m2hfnchuxSjw=;
        fh=QcGCVLiNIASIzJ7tfGnFLBkb+Ra5karzPih2A4wDE8E=;
        b=TmzQ4mOx3LWgH1j9gfeoy4Ih6H+fKnU1A2omrNJkG99auVJYoZ58/C9cVJ0jCyn/xy
         fAfqF7bPHh0L8mL021gf3dwPoc7ZgR3qT1Nfykfpv8Nm55eMxMxmzYDIWmF2QnRepLqr
         lTIbxHFayoE0+E3Q2l1nmPVnCQ5QSY9nlJVNHrs5EUdVayPlD92jENexDfO8WN3Tjov3
         4ymZcpTKSmH/gUBhk8rrLgndv6QgRG/JF5tgJMM6GnX64UCJ3HsnIALhF4P+v04ptlYs
         Ru4LrrkkGAoha7/uZ0Nkc3LWWhBwjUpVgqCDVuFOfurG2iQrYFB6dMzxdFEhcDfzBsr8
         OpnA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BYxI1CvB;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71ff15551cbsi2621817b3.0.2025.08.25.05.49.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Aug 2025 05:49:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-101-Y4gF8-s4ONyOhC-AsHy26g-1; Mon, 25 Aug 2025 08:49:03 -0400
X-MC-Unique: Y4gF8-s4ONyOhC-AsHy26g-1
X-Mimecast-MFC-AGG-ID: Y4gF8-s4ONyOhC-AsHy26g_1756126142
Received: by mail-wm1-f69.google.com with SMTP id 5b1f17b1804b1-45a1b0060bfso28682505e9.0
        for <kasan-dev@googlegroups.com>; Mon, 25 Aug 2025 05:49:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWa3emrk27/TUaGFPfSjdiGYdbGcYEXAhrJBq/jDgLqa/lVoHiXBM0Fy5o6dSf8iwkZFJExlt6vUPg=@googlegroups.com
X-Gm-Gg: ASbGncupIKUr1D6qcwmZ+/3eRM5CKH5QMOjdy10YBG56fYnyvSF5zt5grlbyKJ4KQgw
	pi+MEF5ikgQ9XWkL5pp/VpRxYAx8F2hsLeKk6zYcpl4wVPalleevJjAlfunmLNtdzQh2WbFxTAl
	ZFR4k8DeZ+JDYRFazYYVktmKdBuZyrumpSV+xEkZ7GXVYlu2tg5mwyhph0QCnp4DyDQb5fsCir/
	pBUJLGvUObK5hzXDLw8U79YwjmTZO1qY6O7xcQg7fkpOmYKoqDtf7rNKHLHNnXP9Z0Ww3zsBXcW
	CrCIeDTS+rI9dLVfpGgUXIam8+PWGKgnyU76yrgG01IBpLJZ74tkI4MBvTJGlyQ4kNeMCCymNS4
	RwN2cp1Dy+9lqGF+7JzOLV6GaJgRAG1B5Yr9l1puHtDyLxhsJ/CKqMcD0DjQxlud0UzQ=
X-Received: by 2002:a05:600c:3b0f:b0:43c:fe5e:f03b with SMTP id 5b1f17b1804b1-45b517d4d50mr117582015e9.30.1756126141743;
        Mon, 25 Aug 2025 05:49:01 -0700 (PDT)
X-Received: by 2002:a05:600c:3b0f:b0:43c:fe5e:f03b with SMTP id 5b1f17b1804b1-45b517d4d50mr117581475e9.30.1756126141263;
        Mon, 25 Aug 2025 05:49:01 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f4f:1300:42f1:98e5:ddf8:3a76? (p200300d82f4f130042f198e5ddf83a76.dip0.t-ipconnect.de. [2003:d8:2f4f:1300:42f1:98e5:ddf8:3a76])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3c70ea81d38sm11742640f8f.17.2025.08.25.05.48.59
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Aug 2025 05:49:00 -0700 (PDT)
Message-ID: <a90cf9a3-d662-4239-ad54-7ea917c802a5@redhat.com>
Date: Mon, 25 Aug 2025 14:48:58 +0200
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
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <aKmDBobyvEX7ZUWL@kernel.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: JsFZ71csPLKScYLq5ayfTtQ5wx_FZUn4ylW8zRa96_U_1756126142
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=BYxI1CvB;
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

On 23.08.25 10:59, Mike Rapoport wrote:
> On Fri, Aug 22, 2025 at 08:24:31AM +0200, David Hildenbrand wrote:
>> On 22.08.25 06:09, Mika Penttil=C3=A4 wrote:
>>>
>>> On 8/21/25 23:06, David Hildenbrand wrote:
>>>
>>>> All pages were already initialized and set to PageReserved() with a
>>>> refcount of 1 by MM init code.
>>>
>>> Just to be sure, how is this working with MEMBLOCK_RSRV_NOINIT, where M=
M is supposed not to
>>> initialize struct pages?
>>
>> Excellent point, I did not know about that one.
>>
>> Spotting that we don't do the same for the head page made me assume that
>> it's just a misuse of __init_single_page().
>>
>> But the nasty thing is that we use memblock_reserved_mark_noinit() to on=
ly
>> mark the tail pages ...
>=20
> And even nastier thing is that when CONFIG_DEFERRED_STRUCT_PAGE_INIT is
> disabled struct pages are initialized regardless of
> memblock_reserved_mark_noinit().
>=20
> I think this patch should go in before your updates:

Shouldn't we fix this in memblock code?

Hacking around that in the memblock_reserved_mark_noinit() user sound=20
wrong -- and nothing in the doc of memblock_reserved_mark_noinit()=20
spells that behavior out.

--=20
Cheers

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
90cf9a3-d662-4239-ad54-7ea917c802a5%40redhat.com.
