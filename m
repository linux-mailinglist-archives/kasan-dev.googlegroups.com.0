Return-Path: <kasan-dev+bncBC32535MUICBBHPZYXCQMGQEHDIKJ6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7861BB3B841
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 12:10:39 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-70baffc03dbsf42215016d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 03:10:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756462238; cv=pass;
        d=google.com; s=arc-20240605;
        b=OuiidWXUDJHAqSiqIj+hNJLxZJxSQ9flhgxQkNobwKMGdcaMfRqhZ41EjqhItx6uYi
         s5Wq9LgWf1FNmZ1+ipLSPKrwRI3Qs/ssJBaqNNccd4pBwms8ZlyKhfkECkk/yBM7U/iN
         cHrzHFjnzeJsSBWAWwwM/4f7/V5v3PEIXn0azrnwvMOUeuYvlH1tWZ1y8cNEuogmKicU
         4dezz77ix+jHUXOugW61o+iWnhSAJORfXAnW58+OkYGeW4DPvlbXSf4Giz0kM9E11CkX
         UWODs6t3UbixQG3JXAA2kzN8+dvpSHVBLL6Lyu4xOgXvpJ6cXiuQ90mFfZ6bA129miXI
         6d8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=zgUO4FMK1nsMgKgeslfRsSuy0eXj36+Nyg/IwigIN+o=;
        fh=RHLVMvt+t7PFtpssNgdYkyeCM8a193ay4T9XiGLjAIY=;
        b=h8N/YInd/BHUhBPasHra+S39f3LfL0akwr1Eba+Uyw+Hlh0uOfBGSquEggjVp2lpgM
         eq7RQeOPUCa1MZUDIAdQDuShSAQwQT58inDOer59q1HsDDgjqqLlctbNMyuuoQBqD+Di
         fuPzh/cvXrf9T0/t0dipLt/TQaZBxCjEQfMTITjRAbEoxYT8SfkP7XmFVCk+tIlvl8Sh
         gi8qP6E0/l0nDkoZMYhuNKD/xsLGglF5+7pUfoaec2TYKV8DG0ALUlE5ZDi47mJvssYj
         i9OKLxeh6GfKbZC9eNdm+hol8sH7dyWrdHpkD+agxzceK0RN8sOVyhe/P3FrNIttyZ1F
         5Erw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DlCqGzux;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756462238; x=1757067038; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=zgUO4FMK1nsMgKgeslfRsSuy0eXj36+Nyg/IwigIN+o=;
        b=FP1qE3q7AssFW2wj6KIhAmNECS1HvnoHxgD98YfPBmOtA+yNweDDQlN4dVUEuLTHUh
         k/JqiMWnYcJx0gU8nKACgK9vlGs7Uz160ynsQ9+ZoHZ+cPcQONEiC+Lqmgbm4olRiI1f
         Ug11J5mcvRCIF2xJjg2IYDyU1hnhMSpkCRv/GC94slM0ReYS4mfrg5BV2wSrfg8qdx7F
         WtYAnXDKT7rLru+NVTR4tnuFnhH4DnQycX53ad/E90HRP//022I0VHX1Q6J2Rw3yAncx
         ZLNTh3tZZep2zcVYzOh+ZRn4CchD18BgqpKRh6P31bcKr8Rs6pAjV3qV615rEEryQKs2
         8exg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756462238; x=1757067038;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=zgUO4FMK1nsMgKgeslfRsSuy0eXj36+Nyg/IwigIN+o=;
        b=HhgTYYoB8+UMw/UiNUamTu2D/XBQmL8hw4dJrgmK5PAhB5bIfQOiW0KHnPBAcAInJC
         u4grXyZ5CZgAfuZj2XhAl8UtioKTbBn64+MuL5dmlcMPC5f50/JTKEa3cLFung4MWcfn
         A0IhFBkgbG0wSeRN+3D169onxwkMhn+DolwaOlTXrUIWeo7pygeLUoQxkHfcM/JNb6id
         60VorabSJZLgYELy+VY1wCpRKO3rZO1YJ20xQTGF0BEdhi2x+bevvmbzufULKIJh3b9x
         y37/6ovgL93rat9z9MRy7ip6fNh8f0ANiZdSZ1UGhRrpCe1cFoCGNo4beEMPr2ttulEX
         UT+g==
X-Forwarded-Encrypted: i=2; AJvYcCWKfKdDGLkI92G8ZM0c6gM/0Tpi6jFv2NzuBZWR5l6xkuxgEBVsBGx+gmHwiTOXQvAGt44iIg==@lfdr.de
X-Gm-Message-State: AOJu0YwYEQASOiBzv7AclG5Z34yCsLt/KZR4IBSOhYx4eAUw9mM2nht2
	zFWIvwNa0/iMdAwaCeLVRV0LUL3CXz4iH5sOx8O8sh1LFfjWx3S42EaJ
X-Google-Smtp-Source: AGHT+IFx351vCnvGHiS5aPmAkfYDEwJumWkpnaM+rtTLzy67vv6o9RMxZXwwQVOlSVsJNlNeGt3u2w==
X-Received: by 2002:a05:6214:d4e:b0:70d:bb8d:7c39 with SMTP id 6a1803df08f44-70dd59c101fmr145144156d6.19.1756462238036;
        Fri, 29 Aug 2025 03:10:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcKYdrS9cOcJ/VBGVbCNDEZZCMX8+92W0sBOzfXZkHCRA==
Received: by 2002:a05:6214:4e01:b0:70d:b0b8:7a29 with SMTP id
 6a1803df08f44-70defa9760fls13223906d6.0.-pod-prod-00-us-canary; Fri, 29 Aug
 2025 03:10:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXH1zH/ywQTEiQcMjrZyfLAeWYuYmL0sSyErSeQRZyehHcXs0BIw4zaBLj6mG5/iPhZCQXXNCuI9+E=@googlegroups.com
X-Received: by 2002:a05:6122:861b:b0:534:7e7d:e70b with SMTP id 71dfb90a1353d-5438f492a7dmr4648186e0c.2.1756462237073;
        Fri, 29 Aug 2025 03:10:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756462237; cv=none;
        d=google.com; s=arc-20240605;
        b=ZZ8alJJAHb8pJZdOVBpxg6cTjtdtaIXKA86UjjK81Hj326tJawu+eeHfSOWblaPMQp
         erTStvH14LPZu9q4Bk/f68eqSbFSlXxSD2Pc37Kp2SvdAR6DAA/cjqfAblgaH8jlcZof
         Axv40gubZBzfanbdnTwVNJORHSjNsuCpP/KOxQLtz78xiva1eZ0VQ9L69BSstQCP/Q9W
         4boPNILpK64Jzyzq8l6RXIlZwUadubuwx7+IbpKe8EF3FKvYfisAKcrOuOc9EL66ZUYr
         kh3crNo4Ynm5nJJ24cWwspffK0kz5xrr2Hl2bXVVRsl3vcUDftJjradxMVMHl9YFR8H6
         TBSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=utCrFA9SyGV3mLz3PcpHz6c/4tyzaXDXayD3hFRPQRM=;
        fh=AIMs+rPPzy8xV2G6QCBCYommazhB/ILPjbNgpc9eEMg=;
        b=SwqfjpoJ0K9gKlHGJPYWMdW8oSWKGDRrDuuoLi3YIbxL4dBcOOSrW3N3pXFwfvhF3J
         1+BHMgtjQ9T5qo0oHEFZ/cTO2aMLaRlPoHL4w8oEqUp/s9B1Pyb5mHS+/VMBYBNcddXr
         qGGtKZOAcctDDjMIfFGYTDQBxnHncjsFmzwh/h6zX5Q/UiW0it2uCkxjkPOwMFO60+9c
         bEJtmC4ccPESJmk0iLfLIWFr42NQrEC20pHO+UlBbh+Dkd6PpGTGsKUpJBZCXaJc7OXI
         KcLuba4uW1R5nKIOGzahCNWWP/bklRJ+IfShnpDuC/Lk2uLvDVeQf8vyYpvIyr3GpIyH
         qc4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=DlCqGzux;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8943b465463si59174241.0.2025.08.29.03.10.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 03:10:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com
 [209.85.221.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-610-GgmDnGMaNZ6-QvNSdNIPJQ-1; Fri, 29 Aug 2025 06:10:35 -0400
X-MC-Unique: GgmDnGMaNZ6-QvNSdNIPJQ-1
X-Mimecast-MFC-AGG-ID: GgmDnGMaNZ6-QvNSdNIPJQ_1756462234
Received: by mail-wr1-f71.google.com with SMTP id ffacd0b85a97d-3c85ac51732so776972f8f.2
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 03:10:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVz+DUVyu3xsuWf9zXjC/8QuOHku0t8LTkhDcmKRr4jW1IJjfFwevK4aJpBqyl+QKJm1ks9RkOcp5w=@googlegroups.com
X-Gm-Gg: ASbGncuJARlbve21xiEwGFHViyGu66+2BcPYQLAQlzyye8FAOuxVC+PxxkgGHaxkRB8
	0apvwY2c/qmK3g06HWZi++8eWFtu4/Qr33Q97mgo5FGXMdQbJkFceah8bEYZI55vDjZSd57jhhj
	iMwnqs6wPtguVQeHGAkv5FHwutY2KzedfqrWTe+DorTXa2pV7XtdyKPuV+Rmu7xKliFnUF9xcoO
	Q2a1cnVbvVIaqMEuFgJA1pcrQ2Z4fo3LKPLpYH9+4Hgs6NS568lNdKSDdKt8J3JrT6tRzwLvwnA
	bqsqB6s+54GoFfoW4C9571fFyh9FDATSYoYGBoWCyuMgYnPeOWNVpBDRZl6hoT4oKFgjbdbOsco
	V2qxGbzHIvWoBabD5vaNLPi/Drp3zcSMAYJvAyJcZPgFQavzv553IfBrcjWJBu+p5
X-Received: by 2002:a05:6000:4011:b0:3d0:bec0:6c35 with SMTP id ffacd0b85a97d-3d0bec06f52mr1040112f8f.34.1756462234004;
        Fri, 29 Aug 2025 03:10:34 -0700 (PDT)
X-Received: by 2002:a05:6000:4011:b0:3d0:bec0:6c35 with SMTP id ffacd0b85a97d-3d0bec06f52mr1040061f8f.34.1756462233448;
        Fri, 29 Aug 2025 03:10:33 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1d:100:4f8e:bb13:c3c7:f854? (p200300d82f1d01004f8ebb13c3c7f854.dip0.t-ipconnect.de. [2003:d8:2f1d:100:4f8e:bb13:c3c7:f854])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b7e8879cesm31221455e9.12.2025.08.29.03.10.31
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 03:10:32 -0700 (PDT)
Message-ID: <a9b2b570-dc81-43dd-b2f3-a82a8de37705@redhat.com>
Date: Fri, 29 Aug 2025 12:10:30 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 10/36] mm: sanity-check maximum folio size in
 folio_set_order()
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>,
 Alexander Potapenko <glider@google.com>,
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
 linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
 Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>,
 Mike Rapoport <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
 Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
 Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-11-david@redhat.com>
 <f0c6e9f6-df09-4b10-9338-7bfe4aa46601@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <f0c6e9f6-df09-4b10-9338-7bfe4aa46601@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: HCzVwtxbYz0VrmyFDKUCJvWGV49W99pcUtgUhDXLTRE_1756462234
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=DlCqGzux;
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

On 28.08.25 17:00, Lorenzo Stoakes wrote:
> On Thu, Aug 28, 2025 at 12:01:14AM +0200, David Hildenbrand wrote:
>> Let's sanity-check in folio_set_order() whether we would be trying to
>> create a folio with an order that would make it exceed MAX_FOLIO_ORDER.
>>
>> This will enable the check whenever a folio/compound page is initialized
>> through prepare_compound_head() / prepare_compound_page().
> 
> NIT: with CONFIG_DEBUG_VM set :)

Yes, will add that.

> 
>>
>> Reviewed-by: Zi Yan <ziy@nvidia.com>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
> 
> LGTM (apart from nit below), so:
> 
> Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> 
>> ---
>>   mm/internal.h | 1 +
>>   1 file changed, 1 insertion(+)
>>
>> diff --git a/mm/internal.h b/mm/internal.h
>> index 45da9ff5694f6..9b0129531d004 100644
>> --- a/mm/internal.h
>> +++ b/mm/internal.h
>> @@ -755,6 +755,7 @@ static inline void folio_set_order(struct folio *folio, unsigned int order)
>>   {
>>   	if (WARN_ON_ONCE(!order || !folio_test_large(folio)))
>>   		return;
>> +	VM_WARN_ON_ONCE(order > MAX_FOLIO_ORDER);
> 
> Given we have 'full-fat' WARN_ON*()'s above, maybe worth making this one too?

The idea is that if you reach this point here, previous such checks I 
added failed. So this is the safety net, and for that VM_WARN_ON_ONCE() 
is sufficient.

I think we should rather convert the WARN_ON_ONCE to VM_WARN_ON_ONCE() 
at some point, because no sane code should ever trigger that.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a9b2b570-dc81-43dd-b2f3-a82a8de37705%40redhat.com.
