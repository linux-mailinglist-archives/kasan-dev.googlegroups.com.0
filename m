Return-Path: <kasan-dev+bncBC32535MUICBBKE2UDCQMGQEXYILI6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D676FB30ED3
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 08:24:56 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-70baffc03dbsf39025546d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 23:24:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755843881; cv=pass;
        d=google.com; s=arc-20240605;
        b=FUsSlwcB5M/PJQBYcOs/3UnhFNetDxVvCSk+iT5olPZWSsFxMQAT2gka4gcj8VYRoK
         JU2R6n2tdJxePMxh/Lcq11FPFd19r80fDcelwkZsyhYfbuNLQ0+Ye5Y0yUtxIJLHtGKU
         bTgCay3t2dxYraordtyzADtFbbCOY1ThSysKRwmm0NpFXzGgizC6GXHCTBhrqG1NIIWz
         LhwryC2NbNs8SjCwG11Y32mJlEysliXOgiPU0NihXQ0cNnKQmaB/VFjQpZe8zzNHFpQy
         iDkwhVFX+90lLgZsPzkWS8vJAnGvx2x1BH7pIHCXLtDtPhU4G1jHyHt1wuXXHR7BXlWz
         pUVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=AUv5+vpHcRJxmbR+7chzl7Xg9/v5UWldWroAirFhcZo=;
        fh=mV5t7Jt4sEqyHozWtdoz4c7oLEfVwssGjw3d7uRbTEY=;
        b=cHpRU/5XOMx8rw4yGPTuT0vRsg/FK4fvdnjQ+qQ50Qek0dBhZxXJVcs0SZ2i+TUyl0
         +mx/Vo4GyNVrO7EaMNDpbBYDfuvDyZ5mcJWxSimMSs3bo3ZRk2y+vfrfP/sPaelQtzCY
         HV9DksCI3bhLwi94L+BDHeAkeeG6i5nDZI4m+aRS5S4sejSPlQuitKazD3pEKFq6DKdB
         f4/Nq3F5LJlhF+ORb3/THc5xoBRCZMYOjhsX3zJTuT8+dJ9THiM6CaWYFcvsOBooSj5n
         GLUFKjGOQUn0dn23Ioqo3Ts/UUzDz2yt8WE7auFSpqflL1tkfPn2DPjvdURt18ze1Sq3
         7siw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=XtCiC+Mg;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755843881; x=1756448681; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=AUv5+vpHcRJxmbR+7chzl7Xg9/v5UWldWroAirFhcZo=;
        b=jAZWIMTMu0cWOUVnUHcii4eUvDXelK7CgytTWcVkHWiBiOUfThtxF0opUEvgcQow+3
         oF3+KRrjS6exfUMXkOAy3+qFvliJdMk3kD2iSA+H3MbwCaUeVIY0pgBXj2uR11LqL3Lt
         hAG23C/fgk9wlKXYCqNiFF7QVkNC8FS9LQ3oaoCd6uCYuH7Us75dP2DkPuXcjWjCDbvP
         B2CptR2QloIc3gBloKG1I/a8Z9QM507/kY0hfp4VZhYhxseewJ7/1scKGceGbVJ6g2S0
         PtavyS9y16TgOpMKI2LG/N49XI2xWuomeqB6Jf0WhRtyl5G+bYTQ0wIzMuTQ6wCEHS8f
         zOpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755843881; x=1756448681;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AUv5+vpHcRJxmbR+7chzl7Xg9/v5UWldWroAirFhcZo=;
        b=wZVrJiHkE2cbVylTLzSPDsTt1cSe+Lm2MeR8XMMcqAOCDCIkejX0hCFvMrFFU+cXS1
         AMPydXNMXyYfLRiIhk0cm00TxFvMkejGPKtBURaL152ak7kVObvbFpKYOJr4s6yZp4ac
         BXo+DNb4sG2dTNO0js02XNwcUu1bds+Z1TVUAQlJZnS0zHYp7ER57l+cPnGLBEkQjzOK
         mh9mMHDmFq8KjudDwQna3Me/QfqZDLUgUUnhHO5g8RVMd1oLQV9QOhJ1/8+qxQxiVF6o
         E9t4wUc+vDWmmOZXrD1zFftZAQSY71UCd4AGTz3QTalYdxwlxdMJq/BV8//ta7gPK9lV
         3jfg==
X-Forwarded-Encrypted: i=2; AJvYcCWSpKNOCFeamM8RmxyzG1c5Vb7FBdhOg3gDXIdVIB6ZoYmEXeaGXJk3ZAMwVNm0fTcZfLz1ZA==@lfdr.de
X-Gm-Message-State: AOJu0YzOhw4QuWxO4Vr8m3Klf8qfRR8A/w7EE+p5zDS3UKZbXyraTEBl
	elPqG1EPRylnaeZMWv2obQyHiJd20sAGmB9GmPpQPMgktJdYajvcJBy3
X-Google-Smtp-Source: AGHT+IG91tCbOP1D1Cxo4GpY4ZHylngrYSxgeITNPZpWt66yMmytykN2mri3t10PdVKK/NrqQMjnxA==
X-Received: by 2002:a05:6214:27ef:b0:709:7345:9aa3 with SMTP id 6a1803df08f44-70d982cd4d9mr19063826d6.14.1755843881099;
        Thu, 21 Aug 2025 23:24:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZefO7mD7/h8rCzWYTrQ6SrBMHqEnNVK6i4ybKWbiro1kA==
Received: by 2002:a05:6214:3107:b0:709:642d:1566 with SMTP id
 6a1803df08f44-70d75c0d700ls15041656d6.2.-pod-prod-00-us-canary; Thu, 21 Aug
 2025 23:24:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV0x6vIbTw/LXkVtk69ZAzxEyD5eR4mC7BmwBPJ4HNkiD6ctqFCioqbRcdkcF8sZEoO4ZNJHcsGSQI=@googlegroups.com
X-Received: by 2002:a05:6214:4012:b0:70d:65a:88df with SMTP id 6a1803df08f44-70d893633aamr62757576d6.11.1755843880186;
        Thu, 21 Aug 2025 23:24:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755843880; cv=none;
        d=google.com; s=arc-20240605;
        b=fY2pMlJxcPaUMCRkYExcj0kReu1ryOdaFWuJ/6ZT154HIjXZElb8X0ADT4T8Qi7ihP
         +vrDHoheBAW+7dts+KhtIPepMropbsGZyRe8Am3PO97TnoL3+ZyNcDt23n6JKDZBgjVU
         LKsc2QyXOC6Tsd+41iJU6l26JtVEG29eb3JaMOD0KNtmDnw4NQe625v3zeImQKCWH9H6
         SJ8LViztK2DVUG5DSJMlvV6nAqUmcOnqegIFXPNKcdpmA7lhxk+WyYOWGk3OzuNpKJo6
         b/H8HpLg5EMVCny7WExiVP5wwzy18JiVBMr8C90qbX32Wkh0lY1A0EGu/jm0x4C5gKkY
         lY9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=WiI+ZnCzEnb/n6DQfRPkU+9oejYIM/R2hKOTH1yevco=;
        fh=90y09w3x2Ni1wB4VIAdkJKcnpErvhq4RSSlYWCI5+kQ=;
        b=Z1O1XsqkhO7JNPO4v4EBw9Aoa8Wdpf2gcQ9+75mlydL0nwZTYwgbeqNo/cbM3LYpES
         ig0A89Wvi56iO1ml+wLrV8MEUcalhicS0ObIP5NUizA3yCjn+uXNWrGQHwaNrtduWpKP
         +9tXy1gCPo373iJxaNGre3DwwAq2xCeIqiMaeCwQQXai+4zm1Uv1zEzXvMX4dGlXAoga
         MqKflrOrrY9+5cnT58Jetk2qZpUR52yDSDPjveXys3Cj15/FzJNzLBJt7W6Ov/PoqEKZ
         7XbsrMEhLMj1yjcwciqUR9u2JHObIilGUrj7WixXLxxqbS/430nmYQIQ17vb8xMNJ1SN
         +tRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=XtCiC+Mg;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70d9f80ec00si92606d6.1.2025.08.21.23.24.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 23:24:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com
 [209.85.221.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-304-hmSfUqkjP5yQxVki8J7BQQ-1; Fri, 22 Aug 2025 02:24:36 -0400
X-MC-Unique: hmSfUqkjP5yQxVki8J7BQQ-1
X-Mimecast-MFC-AGG-ID: hmSfUqkjP5yQxVki8J7BQQ_1755843875
Received: by mail-wr1-f70.google.com with SMTP id ffacd0b85a97d-3b9d41b88ffso1025117f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 23:24:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW0N+TvuB11WNbtKJWe+Q/R41WwQwCo+7U7SWiNMjRtcdw5nyO13fZKyyBVzCqp5R3oks4pRZdROe8=@googlegroups.com
X-Gm-Gg: ASbGncvhcl8692hnCzgp9pjS6UrbWbh4FHHYANasB+j+C/gjroHIM8FhDBoAf8wcjOc
	H+N+HLa481bfneZeDUO8LMzP+A/pYmEMXjfFSWeCnS8x0+PuQs+GILR9fuWwDdEaaV4gZ+RwZfu
	cAVZYAmFN1IO6L5E0Z8IWFOfinGvqlTI7M5uR+ZXDKSaBgEK50NG1qsApj7VT8LcvqyxN/F9vNs
	zKWv+Rhp7sv2OUpEGU0Ja7GqioaaFLlvGvTBg6zNQvYtJlsC5rf3mvuCWqrMcwxIxTVad6jM1qg
	H46fZPQGuScptYAzI2ftesf/dzM3KD0DjvSY7xW4WqQ3xDlIGybo4jFLEgcGkgFebj8hbg==
X-Received: by 2002:a05:6000:26c1:b0:3a3:7ba5:93a5 with SMTP id ffacd0b85a97d-3c5daefc4a3mr930339f8f.26.1755843874909;
        Thu, 21 Aug 2025 23:24:34 -0700 (PDT)
X-Received: by 2002:a05:6000:26c1:b0:3a3:7ba5:93a5 with SMTP id ffacd0b85a97d-3c5daefc4a3mr930326f8f.26.1755843874452;
        Thu, 21 Aug 2025 23:24:34 -0700 (PDT)
Received: from [192.168.3.141] (p4ff1f25c.dip0.t-ipconnect.de. [79.241.242.92])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3c6070264fbsm1198544f8f.67.2025.08.21.23.24.32
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 23:24:33 -0700 (PDT)
Message-ID: <7077e09f-6ce9-43ba-8f87-47a290680141@redhat.com>
Date: Fri, 22 Aug 2025 08:24:31 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 10/35] mm/hugetlb: cleanup
 hugetlb_folio_init_tail_vmemmap()
To: =?UTF-8?Q?Mika_Penttil=C3=A4?= <mpenttil@redhat.com>,
 linux-kernel@vger.kernel.org
Cc: Alexander Potapenko <glider@google.com>,
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
 Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
 Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
 Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
 Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>,
 Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev,
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org,
 Zi Yan <ziy@nvidia.com>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-11-david@redhat.com>
 <9156d191-9ec4-4422-bae9-2e8ce66f9d5e@redhat.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <9156d191-9ec4-4422-bae9-2e8ce66f9d5e@redhat.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: PFagsrH-JHQhvNiH9rtgq7rA-dwET80tTSms6YbK3t8_1755843875
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=XtCiC+Mg;
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

On 22.08.25 06:09, Mika Penttil=C3=A4 wrote:
>=20
> On 8/21/25 23:06, David Hildenbrand wrote:
>=20
>> All pages were already initialized and set to PageReserved() with a
>> refcount of 1 by MM init code.
>=20
> Just to be sure, how is this working with MEMBLOCK_RSRV_NOINIT, where MM =
is supposed not to
> initialize struct pages?

Excellent point, I did not know about that one.

Spotting that we don't do the same for the head page made me assume that=20
it's just a misuse of __init_single_page().

But the nasty thing is that we use memblock_reserved_mark_noinit() to=20
only mark the tail pages ...

Let me revert back to __init_single_page() and add a big fat comment why=20
this is required.

Thanks!

--=20
Cheers

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7=
077e09f-6ce9-43ba-8f87-47a290680141%40redhat.com.
