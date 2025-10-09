Return-Path: <kasan-dev+bncBC32535MUICBBVW5TXDQMGQEOCYNMGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 228CFBC7F74
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 10:14:17 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-b5529da7771sf886876a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 01:14:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759997655; cv=pass;
        d=google.com; s=arc-20240605;
        b=DVgc5I55Mwe+YIS2nIBi2UoQkBSlTVqnL7BDFz9+b9a2fLRpgSuv1eCfr2pQy71q08
         yEMpkW0PM/I8HtUu09ZaDhKk0sYjTjeA12x5G8D2jun6FBCEbpbqBeub5ZrDZDWqv/Cx
         PQSD3VpuEHolJ2WFnBmRD89wbia7Tf6Y3Zm2raBsOf+y0nvn3XMw6A45byIQbeiTb7Qm
         sE2HNN9WuDi8jw9XtIJcJpOS68zjoyIxo0b69s+vkhHSPs8m5Lbq0avPCbpX8i6kxv+x
         TY4U5IfexnWCt3scMsEqlghA1LYA89HffuQXLA2rg2Ie+FTMfThcbF/iKtt5sHEys9gd
         EltA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=nFxRIDd/9+Po3v4d4vbHLJkpQ6z/Psj5AV/arY/BEbU=;
        fh=BOyz6zKNFuSymju284Q7+kfY3Lz37sp+2yHEbFEIgmE=;
        b=jqZwNvWqGiDntm4oc+E/XWfjArRpKT305nbffUPFZq04ttkum1HAqrNh+lKCOPr1l5
         H4AZZQj8v6jCj7tb8JwZhHT3lpd4UgmksWdzMKAvcWsSUSTlpv8MvA4C0mrMkl6on89e
         yB9NnboSm1HVo+V56toDihlTGm/UzA2wk65mbrrTEdNTkyAr5xJHwVsYNhlLOqYmO98y
         lVmbLcxyahf8qbjSln3y5pgBot0qwU/kfxlaU6huSg7CNjkiBS/FWEBz0KUGSB0Moq/w
         IIW9g1htCr/MEGaqXR30A5GrTlUuOo2ij/NR/esvlMn+LMI5ZKE9set2bLNTMzRxcb+d
         L2pQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=K7L9V1kj;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759997655; x=1760602455; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=nFxRIDd/9+Po3v4d4vbHLJkpQ6z/Psj5AV/arY/BEbU=;
        b=dcD+9lLeH1dRuStGAcceyt3poRzR4bphM5Hk+yfAJjfqbEXwOp7PKKJpUu0ctbQwjS
         Vkl23oN9q197i9jgPzvg20+zFcvcPFj0Aqypmd1a+5eyl5MvXjma2u0+eOHgQzuw9DR5
         voz+mTs8u4DZFAjfJMApS8/3eHVCRTL4ippREAYY72iXEWsT9ROh13HgwEIlnQCMSoGv
         gmoXRVLSbwdHpngTpBr2PqjlvDY8xD4LpSr9ii9oSTg3DvKZLAB5K9MjCvWMw+viKCjj
         j/GL4yiYU0a5lrQJYyYsLY+nm1scMDw0Ks8tPAt+Fppx32I3mo4m2A6Kv/fCv1pcmY9W
         ETzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759997655; x=1760602455;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nFxRIDd/9+Po3v4d4vbHLJkpQ6z/Psj5AV/arY/BEbU=;
        b=GKLlzYv/QVJzKerHfvcgBw48C8rt43DkAqYBPC4x9gCEcFhyr0BWllbUPz/rDxtX0h
         aET0K1oDTHZ8EXf3BEE1mTGCdmzJKwjSDCZMzVO3I/2nIZU9ycG+ycjeobIYg9S17woj
         R7Awx/dC8RXv9UoX9BXSFeMIUQHuhwDZIl3iHR5QDx8zgx+J3rPmif4HI/99VqS4CFRq
         WH6+iEBE4QLr9j5QnKmz6wE0VDlDRAWC8Ja/8pKQ/FAfP+ozYID/nkzlb+8AbL+DdnMN
         U3dBomRV8jhvAXjaP1Q3EwP/fZahNjQgABPlmtDlxufh0KBy3eC4/eytPPaN79vUfGS0
         Ql+A==
X-Forwarded-Encrypted: i=2; AJvYcCX3JwBz8D9lFCMvVSvRvCrhQD86Jkpuq9W2eKxfMActaryFV4nd9KoLaCfF6cI6bH3C5pAAHA==@lfdr.de
X-Gm-Message-State: AOJu0Yz6o8DvfbG71beC7mEU8BZjA9jr/1FQb1WJIJ8chpDgBBHp8Izi
	F90wuhDOid7IGmgj4eQcnMTpxDWJlgSeLexImYvgVgo87vE+JW/1+Iwo
X-Google-Smtp-Source: AGHT+IG4UjI0FaRXFQmTN8HRJzgyoEeTofg9DPhPSXABTym64iURU168c1RbWxBD4lto6PI0k35C1A==
X-Received: by 2002:a05:6a20:2449:b0:2e3:a914:aab7 with SMTP id adf61e73a8af0-32da8514a1dmr8921103637.47.1759997655098;
        Thu, 09 Oct 2025 01:14:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6Yt+kVFnqAcru7hQpFGrWuN1F/dy3VRMmJfplNb0X0Tw=="
Received: by 2002:a05:6a00:916a:b0:781:605:b96a with SMTP id
 d2e1a72fcca58-794f2e2b975ls948901b3a.1.-pod-prod-04-us; Thu, 09 Oct 2025
 01:14:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX4gocTH3jS+4FXPLHqeMRdEmc318fMfTKz3NAHWUZFWrrkb6e/KMKZ5a0+KTxBQyaDuhd+T84aQ+4=@googlegroups.com
X-Received: by 2002:a05:6a00:92a2:b0:781:1784:6dad with SMTP id d2e1a72fcca58-79387c19ba5mr7518161b3a.24.1759997653448;
        Thu, 09 Oct 2025 01:14:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759997653; cv=none;
        d=google.com; s=arc-20240605;
        b=XEhFBJ6tPPk1hAwoDAEIcbp0CuCuajQJgHxF4kG8AFAj7s3powqKa5JRxstq60Ce41
         dhKFdy52T1TuS2idbzLn7yaak1tUbNEmGiSXpcJvvCS/FHuIDPKQjFwcvMrpnuq9Z/aT
         DDvPXs0z5bkJVlYZ0zqAer4J6FuXrO8FkIakjPMyjLeF9GmfkGQJuBh2ZnUXUmDYkaTW
         lT7gLUgPPbiWOZ5Chj9j5Zbqf/bkHTu9ZIQAK+qfXIhJYg3i2s5gGs+HNYcCeS1hcAHG
         lwn+3SJQk+sHGifrwApRjm4orvSiZ0zkEtv5U2BoQvrMzmqEykzzxSZsfuaG8PXwCpEn
         qlyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=z/B31lhY4bVYeZNnk+dMlfOVrRbTYtHHzwgcdMMaTVE=;
        fh=A+Azb/RX01S5hZJ8kg6xNYzezC9MgU+OMJR2/2HjXRY=;
        b=BfwvdzeJ1pFt88Jvvl1CW5MFJQ6a8nTnaGSHvDuKZFw+wRq7Qvpp3aJMddIh12Bwsc
         aUo1j7SVHPFvOHmKX9QepZZ/mcmoEkPfKJSuGs1B1qk8/T1XmZNhRL4Lp6gHSFuMAPr/
         rjuE+gKckeFldQN9O7WouSQ/utzOdiKo1GJL98Yqssu0PS1Wx1LObgJB7GYWy8vc0GHl
         5PgfDq3+WsiFqUeRdBO2qUI4hQXkmaoV3TzihiIMrLj70/dp9MXjrgucXOdqZiFzrEjI
         dU/V0FnIH/xYbS6iUgmEumuAsqq4QiXqopNcpwNyg+o6iA/LXM/Oy9QbggRZUZygkOJ4
         CfKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=K7L9V1kj;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-794dc061ec2si53867b3a.1.2025.10.09.01.14.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 01:14:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-7-CaqhvvMyNhuQLquWo5cT6g-1; Thu, 09 Oct 2025 04:14:09 -0400
X-MC-Unique: CaqhvvMyNhuQLquWo5cT6g-1
X-Mimecast-MFC-AGG-ID: CaqhvvMyNhuQLquWo5cT6g_1759997648
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-46e407c600eso3959825e9.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 01:14:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWRePryThUb+6JIjpYrpi+bJHY3DG+ERfRJeWSyrM44PWY3ou52vDvag0eyI2yBkP116qwtaG1LPsY=@googlegroups.com
X-Gm-Gg: ASbGncsnMmRTw8NUETA2s2lpMCVqxYTVfmr8g11kWEnidJ9ChDpFJgjLLb5jDOqVb30
	L+KFHL5fganyD7LdDtSB/b4y+5aLV08TO2NVqVSU94kbrJKDqLxc6IZ0X3c+EWBKVlQAzW0fKKR
	OXOVay1WgfOCGnx/UF5XuaERGWD7GltrGa1iz20fz5kKZiKsfssNSrLe90jlERYwKwuEB6pVhzB
	+oRzO/98XyO5ryQ8GglMWGEALGu3hmuBKCg/GvAgY2c1+xEm6F67X85keKg/kMv+gtaWXXPNrvK
	TPCI7bRduXEhUVZh7AOOx4KP5cKwGzn52VYBIPPIjXpSO4RvpT+GzrPeAbxEjZydEegl6XKem1J
	k+SR2GEyO
X-Received: by 2002:a05:600c:4750:b0:45f:28d2:bd38 with SMTP id 5b1f17b1804b1-46fa9af3095mr47092915e9.18.1759997648103;
        Thu, 09 Oct 2025 01:14:08 -0700 (PDT)
X-Received: by 2002:a05:600c:4750:b0:45f:28d2:bd38 with SMTP id 5b1f17b1804b1-46fa9af3095mr47092215e9.18.1759997647608;
        Thu, 09 Oct 2025 01:14:07 -0700 (PDT)
Received: from [192.168.3.141] (tmo-083-189.customers.d1-online.com. [80.187.83.189])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-46fa9d6fb41sm71628175e9.17.2025.10.09.01.14.03
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 01:14:07 -0700 (PDT)
Message-ID: <9361c75a-ab37-4d7f-8680-9833430d93d4@redhat.com>
Date: Thu, 9 Oct 2025 10:14:02 +0200
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
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <faf62f20-8844-42a0-a7a7-846d8ead0622@csgroup.eu>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: iF8XvlXgXAkPMq4Sd7Cp0X5GKQVUokKWs8SdHezKTPE_1759997648
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=K7L9V1kj;
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

On 09.10.25 10:04, Christophe Leroy wrote:
>=20
>=20
> Le 09/10/2025 =C3=A0 09:22, David Hildenbrand a =C3=A9crit=C2=A0:
>> On 09.10.25 09:14, Christophe Leroy wrote:
>>> Hi David,
>>>
>>> Le 01/09/2025 =C3=A0 17:03, David Hildenbrand a =C3=A9crit=C2=A0:
>>>> diff --git a/mm/hugetlb.c b/mm/hugetlb.c
>>>> index 1e777cc51ad04..d3542e92a712e 100644
>>>> --- a/mm/hugetlb.c
>>>> +++ b/mm/hugetlb.c
>>>> @@ -4657,6 +4657,7 @@ static int __init hugetlb_init(void)
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON(sizeof_field(struct=
 page, private) * BITS_PER_BYTE <
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 __NR_HPAGEFLAGS);
>>>> +=C2=A0=C2=A0=C2=A0 BUILD_BUG_ON_INVALID(HUGETLB_PAGE_ORDER > MAX_FOLI=
O_ORDER);
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!hugepages_supported()) {
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (huge=
tlb_max_hstate || default_hstate_max_huge_pages)
>>>> @@ -4740,6 +4741,7 @@ void __init hugetlb_add_hstate(unsigned int orde=
r)
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(hugetlb_max_hstate >=3D H=
UGE_MAX_HSTATE);
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 BUG_ON(order < order_base_2(__NR=
_USED_SUBPAGE));
>>>> +=C2=A0=C2=A0=C2=A0 WARN_ON(order > MAX_FOLIO_ORDER);
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 h =3D &hstates[hugetlb_max_hstat=
e++];
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __mutex_init(&h->resize_lock, "r=
esize mutex", &h->resize_key);
>>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 h->order =3D order;
>>
>> We end up registering hugetlb folios that are bigger than
>> MAX_FOLIO_ORDER. So we have to figure out how a config can trigger that
>> (and if we have to support that).
>>
>=20
> MAX_FOLIO_ORDER is defined as:
>=20
> #ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
> #define MAX_FOLIO_ORDER		PUD_ORDER
> #else
> #define MAX_FOLIO_ORDER		MAX_PAGE_ORDER
> #endif
>=20
> MAX_PAGE_ORDER is the limit for dynamic creation of hugepages via
> /sys/kernel/mm/hugepages/ but bigger pages can be created at boottime
> with kernel boot parameters without CONFIG_ARCH_HAS_GIGANTIC_PAGE:
>=20
>     hugepagesz=3D64m hugepages=3D1 hugepagesz=3D256m hugepages=3D1
>=20
> Gives:
>=20
> HugeTLB: registered 1.00 GiB page size, pre-allocated 0 pages
> HugeTLB: 0 KiB vmemmap can be freed for a 1.00 GiB page
> HugeTLB: registered 64.0 MiB page size, pre-allocated 1 pages
> HugeTLB: 0 KiB vmemmap can be freed for a 64.0 MiB page
> HugeTLB: registered 256 MiB page size, pre-allocated 1 pages
> HugeTLB: 0 KiB vmemmap can be freed for a 256 MiB page
> HugeTLB: registered 4.00 MiB page size, pre-allocated 0 pages
> HugeTLB: 0 KiB vmemmap can be freed for a 4.00 MiB page
> HugeTLB: registered 16.0 MiB page size, pre-allocated 0 pages
> HugeTLB: 0 KiB vmemmap can be freed for a 16.0 MiB page

I think it's a violation of CONFIG_ARCH_HAS_GIGANTIC_PAGE. The existing=20
folio_dump() code would not handle it correctly as well.

See how snapshot_page() uses MAX_FOLIO_NR_PAGES.

--=20
Cheers

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9=
361c75a-ab37-4d7f-8680-9833430d93d4%40redhat.com.
