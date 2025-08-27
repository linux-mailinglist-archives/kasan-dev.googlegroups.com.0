Return-Path: <kasan-dev+bncBCX7HX6VTEARBEVGXPCQMGQE7YCYUPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id AC13BB37F0E
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 11:42:44 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-55f3b9e66fdsf1523687e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 02:42:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756287764; cv=pass;
        d=google.com; s=arc-20240605;
        b=WLlmxDaKyHTmZ2VLQ2IkvfvuVZ7br5Oze5rP9u27+gzWuN/dYTWpfLTPaWdB1nJJ0C
         ND60FIG/BwzdLDJiGUyfb0gxWDIX2h6Yu/oseZwhNVD2Z58xHi9yRyDgZJg5zOWlaK9A
         UDsM4+laz1sJiX6dUy0DggAKc/TD3cN5y7jbyzRSKrrOsy4uOTKE7/a4XzY2b/iqzdfm
         MURUBcIX1bK7RzPa6LDY1Y7uAvKhJj1G4NYnGpC2X10PyaYixi2qFwd90RAB2nCMdA/N
         UL00IiPHq5bbGRZ0kXSTLDyPlDV+QcP8djMcxzZDRNXhS9BiHk5qZhdSKbILIWdj7K68
         V4bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=BpvAIiHW6Ibl2uxJeyEcs437fRUXPi46GCPvA5KHvm8=;
        fh=9CIaU6UkpOm1GG1tEF1k/ln5f4RSWB1wgIdpUwdyAEY=;
        b=FmOl97lLN1K31iVQFgRnjlme0I9s6CLtPD/q+s/WbjgqfIDGcy4gpkbh4S6j2LQ3Ig
         wwvMu+giviNLzxkARM197de8ojJVUVcZVsgRaR0+1O+biyb5THHUWlsBM5WX5kHqFknH
         ZQZ/o+til2eS0Q7HMR28DG7cl+VQhlN1VZb8TKPYz6LuD3c8NwD4aJn+WnEXdi3ww8VQ
         00Jau1/oV6dutdYSai668+rwVJ3R6PcIZshkYUyGsm+ZnR90ilZT3eeM+y/x3karWvD3
         0ULY0ZR9F+3PcpYC0KYK3/cFXa9V54ScLASYL8ptl0Sc4Cn45QgvFSt6F5O4tzMDQexM
         RR0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=D36NEOp6;
       spf=pass (google.com: domain of asml.silence@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=asml.silence@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756287764; x=1756892564; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BpvAIiHW6Ibl2uxJeyEcs437fRUXPi46GCPvA5KHvm8=;
        b=cTLkyl5XlIEj/ljzE5q/m/TxB0j6eUIFyyQL/80tXFvbvo+8+ztHRg92Pjzb1TwXbe
         OfjLwj61sfpZFfLuRlWMEiynLnC8ntqyCV+gVfclsWx/lYJ6pK8cUh+lhNKKXcIUIciK
         N2DEerI5wO+crUjdMqRTnkjV4/HKTF7z0+RpuuGJ1s54jQkQYeFIrbD0fCSVgPWPUPnI
         bInRWApkB1Qwt9aJcHLoODb+gM+gTKGUfgGXjWaKJnmr5PJIG0QROQErxuLzxb5NCXso
         Ef0sboLKYeC//s7zjoPJaSnUZiE3IE4h7R/BW99jGA67fEQAkwKNNSJp0wA1oBayzk4w
         AoWw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756287764; x=1756892564; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=BpvAIiHW6Ibl2uxJeyEcs437fRUXPi46GCPvA5KHvm8=;
        b=A0ofyU/3JYQ9l0YM4DvTIiiNNeZxxEEzszaDIl6Wu5pyJxgWsOpYZ/EFhkO9Zoicpj
         pU4HoXRIWo/ApYcMEKuYBFUveL3E4vbuA1yTUChBURK0S2LqjBJZYs9OjExsg7kiPZ8n
         GG0NYN37Gr6RUvL94DhJcug1DENDbf3Eyhmg2N7YHwVud38DmBzLwvlBeU5Ojqz/1G6F
         zWtjYcdSt1/2o+rkT1u9rFlRuXm+ry3A9IB/znS1ysJY3pUUH/Q1eqI5ryiXGHJQaTKo
         1HY7mDSzChu4jac2rAUZN4+qDDdAhm4wMQ6YoyAmE0qqujLAY6PM0hWYeU3Icmo5lBOw
         yC8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756287764; x=1756892564;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BpvAIiHW6Ibl2uxJeyEcs437fRUXPi46GCPvA5KHvm8=;
        b=r/CbdLdYSeYNWyibjgZhdKBG8Ww3riHXJvCF10EpWRl5eK/DsCm8n2uhO8TnN8OW65
         YyaYVYCJfN1iFU3JqsW8Kjv4FCSZQpr5SmBQ5NFHVX1r44vxVjvxPafKnhX4pIzUdKVh
         mDzrI8kldlTxOHyvVOZJJxhzz/ZZ97JgrcpQw7ZiGJn5auTQmmb0MrHoeuAHZZYqvKN3
         vYqtdG475HCMfYKYRjrDAzS1/d8Chnb6ec3hpnbMwUwvZNg7x05SJ4QtjUdQoPJOhdzV
         ZRhfjpuF7nBzlrrBJn3/SRG+KBvOkNKMPEwR8tDmwhrU54rmvmM6cbYxRey9RccyyUSG
         4fNg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX9OXmGRjG8PPnYilbpC5rEibbNULoB/7Ybzr2Un93I5ky0NlXTANZFca6md1vq0w7AI+XQ6w==@lfdr.de
X-Gm-Message-State: AOJu0YyYyRdfgPAQ7eo4o+osDdAGVQAYsUk3NEdrn8X8dNZOz5+1reDe
	PkpEOUs2CUGRoYoFVYmu0osrQdpRkq/qxN+maO2idtjGuBSZnY1hBKlp
X-Google-Smtp-Source: AGHT+IGwopUlTbhi6T49zLFYM57hVkdxmo26y5qlpBezDksMpW2xoiO1QWgThJlN+n7/Wts8v9XPpg==
X-Received: by 2002:a05:6512:ac9:b0:55f:5685:b5e9 with SMTP id 2adb3069b0e04-55f5685b722mr394109e87.8.1756287763404;
        Wed, 27 Aug 2025 02:42:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe5CP1S4DBMqvXiiH/ot3Xy9XfGCJXcWviRd74Vh9Q8fw==
Received: by 2002:a05:651c:1112:b0:333:cb55:f585 with SMTP id
 38308e7fff4ca-33546c78948ls11975691fa.1.-pod-prod-02-eu; Wed, 27 Aug 2025
 02:42:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXY3mb4YZarzNi5/LwDlKVvf3bj4w6FOb8xAWt7DDwLq9iCPE1bfRo/G0og7R3//tjhoNkVfowj3ug=@googlegroups.com
X-Received: by 2002:a05:651c:23c6:20b0:32a:7826:4d42 with SMTP id 38308e7fff4ca-33650fa8fd0mr34926581fa.31.1756287760173;
        Wed, 27 Aug 2025 02:42:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756287760; cv=none;
        d=google.com; s=arc-20240605;
        b=KFhSoYiFaB8adCb7xd/uuy50SQLT0+0m7RRk7XTu9ei40ORRac4qMxQhXEZbMs9MjM
         52i+4INDatHK5viT06NggigZi5Sne/PQb1mUlnGjqQkpgaxZuosopNhBe/ql19EoDWPO
         z+wT5Rfe6Q+F3bC7w41rEzduUw9LFau1O+P67ZxQebyYwEUVA0OlC0fvJciQL+yGMGpK
         LO7JnU4D68swM7DU16KhGMuWvmtS+ISQkM/XaUjzjONAZH7siVZsNWwTS+/cHboHlUU5
         2wYFogSRZ9Cf2GuFqIyq7aw1P9Hd2gWd1bgNR7eYSgGpQoE4KNcM8DfYFe3uZ9LkmMLM
         mW1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=s4gNirUawo/2N73RGh/VZFmiZovBEw6Zvsz5pkyBSog=;
        fh=k75ZiQeZcUG48nYkAr5GN53TZlXSKvfxW0yGMSBDESU=;
        b=V2Jwndt0EhkXmXLgf3f4ltcvI3G2XpK4/tZawzsFzWC1S0rrhXUpcuYLsdXUCPCqGH
         Gg6G0/QiudDEhRKb0q8ccOWTxEd3OWXtKS69KDlFhQY5nXS8JNmqsc1f8slWqUDtIs4g
         Qqnk2gFs5AnyeHAZmg47nvL0Ewx5/VB9YzJV3bedoD3XCXoWn2UE5Gtq/3Z2oBD4v0yO
         xmJZSDpuJ8r3JvZWiPPAI+Gm2qSL57slnO0vy9hzoH1FVN1HT3wSfIO4MEUPIc3L35YG
         cf62ntIR/Klu8ex8IuF1C25166z5EUWUvG4P4CSVghnOoCb6t0qxuprMSvhh9XyFIxDD
         5fEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=D36NEOp6;
       spf=pass (google.com: domain of asml.silence@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=asml.silence@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3365e20f42asi2528171fa.1.2025.08.27.02.42.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Aug 2025 02:42:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of asml.silence@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-3c84925055aso2676477f8f.2
        for <kasan-dev@googlegroups.com>; Wed, 27 Aug 2025 02:42:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVWUE9Lzn4f3I4wj1WdR5pbWr0O4yXMh47ohrpngW9BnQKXsf26qWiyfR4ycLbA2m8vjav2+O8H/Oc=@googlegroups.com
X-Gm-Gg: ASbGncumwyhZIuAaoWV/QTgkkT4UxEpfVbFTQabUElEIXKnDjdZhisS+/9OygOwUJr+
	JfmVa71VBGbx3MtUeqt1W+hVM5IS4Og2t5b67X/Kcu7F3fEC5OY54iTOqvAbTxyGXjz/BCjE2Ez
	zqbzfPgQ8e8P5qDthQYO1h5XSoiJm2s8awl8oed+UypU0athkkUX+gfyFTk8xHJGjBOv2gBOFkX
	mYWqg9rqBoIZLY8zJzH6uYIsT8FtZxtrQBjslsBXS9Ql1ymygdOmyp8NOsAzaqaUYOjxrXkHoQg
	wWjsVaWPjMFEIBUOiqZbkecq0oWg2AvOsHHqPSZh1Il4YaUYiEc/qmOTP2KP7pGSZyL3INH3Lhr
	dh6VxOJmanc33FeeyK+QEM3uPnJ5ml6N0SdjzcyjIc60bvgGCcbKBeCduhbBVKtSc1w==
X-Received: by 2002:a05:6000:3105:b0:3b8:d672:3cf8 with SMTP id ffacd0b85a97d-3c5dcb10b6amr14770182f8f.43.1756287759105;
        Wed, 27 Aug 2025 02:42:39 -0700 (PDT)
Received: from ?IPV6:2620:10d:c096:325:77fd:1068:74c8:af87? ([2620:10d:c092:600::1:4a1a])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cc4b102889sm3363615f8f.51.2025.08.27.02.42.37
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Aug 2025 02:42:38 -0700 (PDT)
Message-ID: <46d09557-1873-4d97-b073-ce0c7296b954@gmail.com>
Date: Wed, 27 Aug 2025 10:43:59 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 18/35] io_uring/zcrx: remove "struct io_copy_cache"
 and one nth_page() usage
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: Jens Axboe <axboe@kernel.dk>, Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Johannes Weiner <hannes@cmpxchg.org>,
 John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
 kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
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
 <20250821200701.1329277-19-david@redhat.com>
 <b5b08ad3-d8cd-45ff-9767-7cf1b22b5e03@gmail.com>
 <473f3576-ddf3-4388-aeec-d486f639950a@redhat.com>
Content-Language: en-US
From: Pavel Begunkov <asml.silence@gmail.com>
In-Reply-To: <473f3576-ddf3-4388-aeec-d486f639950a@redhat.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: asml.Silence@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=D36NEOp6;       spf=pass
 (google.com: domain of asml.silence@gmail.com designates 2a00:1450:4864:20::431
 as permitted sender) smtp.mailfrom=asml.silence@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On 8/22/25 14:59, David Hildenbrand wrote:
> On 22.08.25 13:32, Pavel Begunkov wrote:
>> On 8/21/25 21:06, David Hildenbrand wrote:
>>> We always provide a single dst page, it's unclear why the io_copy_cache
>>> complexity is required.
>>
>> Because it'll need to be pulled outside the loop to reuse the page for
>> multiple copies, i.e. packing multiple fragments of the same skb into
>> it. Not finished, and currently it's wasting memory.
>=20
> Okay, so what you're saying is that there will be follow-up work that wil=
l actually make this structure useful.

Exactly

>> Why not do as below? Pages there never cross boundaries of their folios.=
 > Do you want it to be taken into the io_uring tree?
>=20
> This should better all go through the MM tree where we actually guarantee=
 contiguous pages within a folio. (see the cover letter)

Makes sense. No objection, hopefully it won't cause too many conflicts.

>> diff --git a/io_uring/zcrx.c b/io_uring/zcrx.c
>> index e5ff49f3425e..18c12f4b56b6 100644
>> --- a/io_uring/zcrx.c
>> +++ b/io_uring/zcrx.c
>> @@ -975,9 +975,9 @@ static ssize_t io_copy_page(struct io_copy_cache *cc=
, struct page *src_page,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (folio_t=
est_partial_kmap(page_folio(dst_page)) ||
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 folio_test_partial_kmap(page_folio(src_page))) {
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dst_=
page =3D nth_page(dst_page, dst_offset / PAGE_SIZE);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dst_=
page +=3D dst_offset / PAGE_SIZE;
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 dst_offset =3D offset_in_page(dst_offset);
>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 src_=
page =3D nth_page(src_page, src_offset / PAGE_SIZE);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 src_=
page +=3D src_offset / PAGE_SIZE;
>=20
> Yeah, I can do that in the next version given that you have plans on exte=
nding that code soon.

If we go with this version:

Reviewed-by: Pavel Begunkov <asml.silence@gmail.com>

--=20
Pavel Begunkov

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
6d09557-1873-4d97-b073-ce0c7296b954%40gmail.com.
