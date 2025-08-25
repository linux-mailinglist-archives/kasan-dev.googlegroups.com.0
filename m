Return-Path: <kasan-dev+bncBC32535MUICBB5UIWLCQMGQEXERGA6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EB05B34619
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 17:42:48 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id ca18e2360f4ac-886e347d26bsf63615039f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 08:42:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756136566; cv=pass;
        d=google.com; s=arc-20240605;
        b=EguXpGTRFYwPZPBSBjUa0IASNhOvEo07vdrq2KgXhmtuJJ1ueF9r619Do8Lg8t7Em2
         YB0Rp4k0Z1xmmFY/QBhsaRTraKJNJbmhGvpv2lLbsnOYCP4UNrgv8Imv56s2V7kjxvHZ
         +BSMHhIgQ8gksSN2bxn2Nq3Sgi10sit5kJogHekieVG5y9ImDPRYUjvMVf9krSjwJ1tC
         Iq0PJ9qgGDUKuMq0MVbSJvrpYTga60Zu/2MhyWAjNWcOnBrm5Fk/jfS4j0bWfejW/XcY
         0KAuvp7N5B6FdsaYUsgGeTwqsDPVJTQOZA3TQ4fq4tghC+KJMu6pxYsuntKSW5HkqaF7
         tvOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=YB9V66SOAOe8rSJONPIH/cPxqbeEJ1hy+5cjD51DFhg=;
        fh=LQLUEOo1WNfekKy0APR/eziFhrXmhMumdlqCddtAo/A=;
        b=ko33scSUX62stH/48L1a2Fn8S+Fc0UWUCvoI9PboSmGLu53lBrF8s0Pb38Rxh1FI9F
         wE0YvaC7jSKy4Zj5s1fM7KRqnZ+sOkx9UbB46IrAxhFJ2rdX9mJB33yjYnG88Qz4EAOF
         ZeeK6y5IRS44Rvzpt3afFkiXLJRXkxTGO9R2C2u/BcJPaIhQ9abHHHqJEcfWV0MBodgz
         VctoBxTAZDpnjfQN9hx8xTV5QKATxDdOxAf3Acr6O4c3waLmUYD11tHxfvOe8P2OCaNe
         PqRC5qWeCRlMtOiu62lLlj8WvhQLMJIL+TPFPbu/510sUviyQzMDav5HIppIVq3QiDA9
         RUkg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RdtCoIOp;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756136566; x=1756741366; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=YB9V66SOAOe8rSJONPIH/cPxqbeEJ1hy+5cjD51DFhg=;
        b=RxCegbhGBx1NRNS+t5r3r2tZlx7PY73zCMoc6G57G6GiM16i5mKOoO/iN71fKBib3T
         J6595cyRhlBSEL1smAjpZrBkTNOiNcNgGsHy1V2nyIhmpMWHJcse+6hYhV8eepOhWcPu
         MzDCCEJghG3bygilk5I6Zjz+Gk6f8H4o6KCEejeUuzFSvBXiu6xkMED3mqZFrDBokORT
         aoEvqBdcvDBU69lDMIINcMN0KWXYaVvn72/lsZ674H3z2eGWj/C8j+rDxSJpCYnLyY0W
         0S589aFm33xVTQkq13Fvq0y0URUYWoCUSxFc2ES9qgs2gXYpk0NE1Wp52n6NEi4o0utz
         7hrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756136566; x=1756741366;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YB9V66SOAOe8rSJONPIH/cPxqbeEJ1hy+5cjD51DFhg=;
        b=Hon4xcy5kqQRE+FaxCxaC47LMlyQTHYq6CaB78KBuAWpRsZToeTDIzItJbMn5fniBd
         Bz3IItahB5H+7Eu6hqABppXzKL+Hq8ILntlVjXLfA2wVXj6E/BZB257uIlbq2H+2TjQ1
         aDAg4EWReFFodXwp83fmTYEvWUyiAYDWv5DjDslau8m0gpDJRFpjTJQ619fh1/RyvauR
         JP7PV0MjGeBrn8AaxHC5Nu3B6t/85LstoebtTNAMHNOzr0mnMcJsJ59bvKIw3gb2dfWy
         Xp5Qs+VBtguey0/6JgWU3BLHUsNoc9BGarQHmWhrICv1Wrq10G5Meltq3dVTJm7oc+39
         lfZg==
X-Forwarded-Encrypted: i=2; AJvYcCXIPTInbKoYXvsCKC4wrPaUGpRMpk/onNq+zx9daY+V/Gj3NW3+f1Zu/Yy2D8k0OKziwfFE7A==@lfdr.de
X-Gm-Message-State: AOJu0YyQ5LUot7/JgcokuhMj82qRnFWXOiVde2D6Zjq8rU7AXlreimIL
	G+ygTm+CuAZLn49duQ8ZkbcKCZ8wjkVLWvawtNQjPdCRufY8NSglEgYE
X-Google-Smtp-Source: AGHT+IFD8Y3cpFHsOIzuOIFbQxGY5Z9a91gPIu7QkrvPzJGf2vyx+xJ+6jOM5SR0c2sSnUs4WDF69A==
X-Received: by 2002:a05:6e02:1c26:b0:3ec:248b:8766 with SMTP id e9e14a558f8ab-3ee5dbf8296mr835255ab.1.1756136566324;
        Mon, 25 Aug 2025 08:42:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZciCE9CMqQDOzBLTwD6z6eRrXXF35ARyvFg/DkJyKqHPQ==
Received: by 2002:a05:6e02:19ca:b0:3e9:4d50:f845 with SMTP id
 e9e14a558f8ab-3e94d510843ls14481655ab.1.-pod-prod-00-us; Mon, 25 Aug 2025
 08:42:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV6ZALCHUR5imTNNVhKFeBcVftD+8xVbS75UgmVgf8p2k8Vxujr2TdnZU+pqdIYJuwqfng7ehBxEKw=@googlegroups.com
X-Received: by 2002:a92:ca47:0:b0:3e2:9f5c:520f with SMTP id e9e14a558f8ab-3ee5dbf82acmr968585ab.3.1756136563937;
        Mon, 25 Aug 2025 08:42:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756136563; cv=none;
        d=google.com; s=arc-20240605;
        b=RqxF8tVAHuQEiUBXFQdE53/ftuol9yVPYEgICUFtPFOffJau8Jyo8viYkdl5sTw7Cx
         AWu5oO7q/eim+BEZrtcNSgLx88mbbGbZQ+FXnxme/JUNioBfGO+8yENvfjpQ/Z194hjm
         vPwaPCVXFJy5lHCDtynG+FmRgeTDJi0FMrFUNbBbREhrhVoqzF0K7I12O9BGBp/rI2HV
         nZdn8+BiIMBrSptQ8aLCER1+Dq5Vqgnc/seteB9Jx9s7KyaeqbZfLqzly10A/x6ZEkDD
         gcfzhqWNTbuATrfFwI49KfidA0qWU4g2H3USWXQHqimP31kcwk71EXoXH2MW+PjzA7Zs
         tDuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=5rvZAalDayw76mXlaVcK2G8fQoANSfCHvdaqQVOogfc=;
        fh=Rk+Fs2hh3wVXabv/1HytK1hjQ8vRUSespPl7RD/0JLc=;
        b=CpUzQDsPhdff3TdEKXrSgeQ1ZgzRBzKbbiX0nl24ED99qO4fxrUnoaT54pYaWwzG0m
         F8Mu2+5CkPWbTGAyOXXecTgr7XkmJ2JMKiTX53IqnIAG84vjJJ1ZLamuv1fxoNccQJla
         +ygmJw76nvw5UTKtGK994rXKdxWQI5Qq3IsXABiehDhpKph/dxewmVIQnNkoBCv++vy+
         Y+5YocUxXHmMN6R7z1ULLow6EU2HRHNXMNeA9yCvPUd7yhlhHbVDt7tN87/5q2TGK4RY
         Lceu/STHbt3Hbt9I0rhtCXxz4+Azvov2/KyKQD3BV71vUzCubxH8wb3o/PBoTUdwA+Um
         7dIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RdtCoIOp;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3ea492373f6si3248535ab.0.2025.08.25.08.42.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Aug 2025 08:42:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-278-RuXAYR0BNN-TvaY7aV6xQg-1; Mon, 25 Aug 2025 11:42:39 -0400
X-MC-Unique: RuXAYR0BNN-TvaY7aV6xQg-1
X-Mimecast-MFC-AGG-ID: RuXAYR0BNN-TvaY7aV6xQg_1756136558
Received: by mail-wm1-f69.google.com with SMTP id 5b1f17b1804b1-45a1b0bd6a9so24574755e9.2
        for <kasan-dev@googlegroups.com>; Mon, 25 Aug 2025 08:42:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX1+xDmpXN8wvX14Y4Zdr8luqUCInwIUJ1MjctdRrg5zMvQdpCwm+yJAGNeQuIr9WOoZU+n/QwSUd8=@googlegroups.com
X-Gm-Gg: ASbGncu9C2EqhZ1s5E69uuul1+LwVcY50PSnXNQnTNiVRJZ5XOA5Fu8LmrShUhn+I/N
	9BgQ70k3JrO7JvWswn6U6w3rL9y7DC9lt01m3nfmffSYofXG3IFsvFc6uWostGog5JKoJuG2GR6
	xhzf3WWX+4MMl3R1PFmnuj9DH1qPfBnH0Vde4njqKNT0sPPtivR3IfDupZl7ug7bqXME7kOXi7D
	IJU3ljjyQ+FdEb+9tqCUnM39HHS9LQnTX80LJwvS7gRNO6f4OcVsV5Oqhl2NeJqYEB1eK3BIhdW
	IofAzZmIkevLXThdulbgQI21mFM5FYYw+UW6V0gXFUjYB1PjRX8zs6mtJa36AB7l13OtmjDN5+s
	2g0ED4OVtRVtPd5YHYohIzGECPWXzckBB/IXHYmglxeFADtmFK7Le6k0Syu5Y0Stj8fA=
X-Received: by 2002:a05:600c:a344:b0:459:443e:b180 with SMTP id 5b1f17b1804b1-45b51f30f97mr116842535e9.8.1756136557864;
        Mon, 25 Aug 2025 08:42:37 -0700 (PDT)
X-Received: by 2002:a05:600c:a344:b0:459:443e:b180 with SMTP id 5b1f17b1804b1-45b51f30f97mr116841885e9.8.1756136557395;
        Mon, 25 Aug 2025 08:42:37 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f4f:1300:42f1:98e5:ddf8:3a76? (p200300d82f4f130042f198e5ddf83a76.dip0.t-ipconnect.de. [2003:d8:2f4f:1300:42f1:98e5:ddf8:3a76])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b57444958sm113196675e9.2.2025.08.25.08.42.34
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Aug 2025 08:42:36 -0700 (PDT)
Message-ID: <f8140a17-c4ec-489b-b314-d45abe48bf36@redhat.com>
Date: Mon, 25 Aug 2025 17:42:33 +0200
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
 <a90cf9a3-d662-4239-ad54-7ea917c802a5@redhat.com>
 <aKxz9HLQTflFNYEu@kernel.org>
 <a72080b4-5156-4add-ac7c-1160b44e0dfe@redhat.com>
 <aKx6SlYrj_hiPXBB@kernel.org>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <aKx6SlYrj_hiPXBB@kernel.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: pViqQHKbcb7ZCX1TyUI8Fs87yK4O5a8xGwxjV6ajUV0_1756136558
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=RdtCoIOp;
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

On 25.08.25 16:59, Mike Rapoport wrote:
> On Mon, Aug 25, 2025 at 04:38:03PM +0200, David Hildenbrand wrote:
>> On 25.08.25 16:32, Mike Rapoport wrote:
>>> On Mon, Aug 25, 2025 at 02:48:58PM +0200, David Hildenbrand wrote:
>>>> On 23.08.25 10:59, Mike Rapoport wrote:
>>>>> On Fri, Aug 22, 2025 at 08:24:31AM +0200, David Hildenbrand wrote:
>>>>>> On 22.08.25 06:09, Mika Penttil=C3=A4 wrote:
>>>>>>>
>>>>>>> On 8/21/25 23:06, David Hildenbrand wrote:
>>>>>>>
>>>>>>>> All pages were already initialized and set to PageReserved() with =
a
>>>>>>>> refcount of 1 by MM init code.
>>>>>>>
>>>>>>> Just to be sure, how is this working with MEMBLOCK_RSRV_NOINIT, whe=
re MM is supposed not to
>>>>>>> initialize struct pages?
>>>>>>
>>>>>> Excellent point, I did not know about that one.
>>>>>>
>>>>>> Spotting that we don't do the same for the head page made me assume =
that
>>>>>> it's just a misuse of __init_single_page().
>>>>>>
>>>>>> But the nasty thing is that we use memblock_reserved_mark_noinit() t=
o only
>>>>>> mark the tail pages ...
>>>>>
>>>>> And even nastier thing is that when CONFIG_DEFERRED_STRUCT_PAGE_INIT =
is
>>>>> disabled struct pages are initialized regardless of
>>>>> memblock_reserved_mark_noinit().
>>>>>
>>>>> I think this patch should go in before your updates:
>>>>
>>>> Shouldn't we fix this in memblock code?
>>>>
>>>> Hacking around that in the memblock_reserved_mark_noinit() user sound =
wrong
>>>> -- and nothing in the doc of memblock_reserved_mark_noinit() spells th=
at
>>>> behavior out.
>>>
>>> We can surely update the docs, but unfortunately I don't see how to avo=
id
>>> hacking around it in hugetlb.
>>> Since it's used to optimise HVO even further to the point hugetlb open
>>> codes memmap initialization, I think it's fair that it should deal with=
 all
>>> possible configurations.
>>
>> Remind me, why can't we support memblock_reserved_mark_noinit() when
>> CONFIG_DEFERRED_STRUCT_PAGE_INIT is disabled?
>=20
> When CONFIG_DEFERRED_STRUCT_PAGE_INIT is disabled we initialize the entir=
e
> memmap early (setup_arch()->free_area_init()), and we may have a bunch of
> memblock_reserved_mark_noinit() afterwards

Oh, you mean that we get effective memblock modifications after already
initializing the memmap.

That sounds ... interesting :)

So yeah, we have to document this for memblock_reserved_mark_noinit().

Is it also a problem for kexec_handover?

We should do something like:

diff --git a/mm/memblock.c b/mm/memblock.c
index 154f1d73b61f2..ed4c563d72c32 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -1091,13 +1091,16 @@ int __init_memblock memblock_clear_nomap(phys_addr_=
t base, phys_addr_t size)
 =20
  /**
   * memblock_reserved_mark_noinit - Mark a reserved memory region with fla=
g
- * MEMBLOCK_RSRV_NOINIT which results in the struct pages not being initia=
lized
- * for this region.
+ * MEMBLOCK_RSRV_NOINIT which allows for the "struct pages" corresponding
+ * to this region not getting initialized, because the caller will take
+ * care of it.
   * @base: the base phys addr of the region
   * @size: the size of the region
   *
- * struct pages will not be initialized for reserved memory regions marked=
 with
- * %MEMBLOCK_RSRV_NOINIT.
+ * "struct pages" will not be initialized for reserved memory regions mark=
ed
+ * with %MEMBLOCK_RSRV_NOINIT if this function is called before initializa=
tion
+ * code runs. Without CONFIG_DEFERRED_STRUCT_PAGE_INIT, it is more likely
+ * that this function is not effective.
   *
   * Return: 0 on success, -errno on failure.
   */


Optimizing the hugetlb code could be done, but I am not sure how high
the priority is (nobody complained so far about the double init).

--=20
Cheers

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f=
8140a17-c4ec-489b-b314-d45abe48bf36%40redhat.com.
