Return-Path: <kasan-dev+bncBC32535MUICBB67EULCQMGQECFDMY7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D410B32201
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 20:10:05 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-314f8825cebsf115794fac.3
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 11:10:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755886204; cv=pass;
        d=google.com; s=arc-20240605;
        b=lO6nS9aY6r5plXxB4NKBScQo7hmk7mW9TWfExkO74FjrtyxMBVjydMZ5sm3/SgR6VY
         6RC1qmWBa5fInuWplJH1bhkSfAs6XMp/mDteRQrjbQfNM9J9OzM/5/0xqeVLrQ8buwif
         7zwED+ygQ+gjocXB197k8rn4XKYwvTKp0DmtnWozuOq3jwBLT1kwKE3kmjtuEHoyIf38
         5NY/jsj7nRH/jrVfjUHmVYaekpdnL5VlB2lglvOB2VNVUYxGJAMfUCTPoiSLOdYJp3Ha
         bHWCWW8WjmslsSNZveMHEqdsz/P4RamY3fRbPkxtKh1NGjYh9ilHS+1lCzASrBfAL35j
         CkkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=d8nr7OceSoW4QDkmm0LlP5Sxaicc+zGQ1fI9FyMtgZE=;
        fh=fmw/DWv5eh6SLJLPjbw2SAa42omcCBFg6uXU78lMsRo=;
        b=IhCRGQBOk34pzX33hZYise1mXTIUkZ00g6XxTkA35viCYyHYNB1vpSUsbIyNL9gr35
         oENKekRP9gyCzmT5wG7pt0gpQRoLJi+JfPGX/AZNuKklkVTTk2FKyHpA7FaRT123LzCB
         N+0DZQZGLelQG6DZX95n/+kOEbN/US3xcirNhfHuiaV6yhQIzPn1f95Z3e5lr/Sstz59
         ED+zUiXUC9F4oTtZwPm0KrIa1CdCsXQy3mFel0nrXcxIzc65cwNIoRDs0DMi+AfFHbXT
         T6zuEKQjOby7SXZgAn9+3WK4o6B4Zh/UGbPn09U+pj98YRvgkQ6QhgOa0lpjsP1tAizc
         NyIA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=JHFX0+qk;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755886204; x=1756491004; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=d8nr7OceSoW4QDkmm0LlP5Sxaicc+zGQ1fI9FyMtgZE=;
        b=RF4t/L24pRVoUNlKM+67haqf8MVyu/R7oav7A/DLwVx8hpR4k9qljmlsMHhufu8Tif
         O79J/mKVUQ/I4lf48zXGjP+6ZOVwE6DYE0Cc3+prL9bS/kwQWc+GkGy8Yoo4rxHzJwnA
         PUmma+JpzmUWLrMH4b/PMzBpD/EA+Lmr9xGfcU8NtgXoqOUdOdqnlf8Ar/Q6IsA3ORtw
         crlxYaV1P5CzGChsHBYBREVKw7EnZmMxa11kQq/zsR8VMHNXC8VHzjH+UusdYrKG4VZT
         D2YSRLl98gypMaQ+PETZ6iAA0KvaV5h1XtnOeaVTzd5t9zFEiT8s6Wl1mja+9oR/ECeK
         J4Ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755886204; x=1756491004;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=d8nr7OceSoW4QDkmm0LlP5Sxaicc+zGQ1fI9FyMtgZE=;
        b=R/zwhtgdEEu5f7N0AvnQZjfwA5j4b/4R5F9SB/oWANZo9zre2cwm9b888sXt6GUvwa
         d12Tbg/Mkm6sjHAze1cdGjDofB9CJSY3WLoPNthJPirZu/qMPqY3ofwmVV68w6TF9u7u
         Sx2MajhfbUGUjQcHiTSU6cv2Y22Rsf2vzwymQ31DPy/34NEMt0aFHfAk6N/7qkAIRlXE
         qohCLI3DZ0Jh0bebV+W2lJfPkbaIAt9F3YtgQH0JylEnL8eTMj3ueaQWK9wWRzEtoMuq
         90jleBAbsFSRBas7uzZPb+Dp+R95MmZ/btZZgZynNLSQlk5f70ucWgeSeMy6iuvgOyD0
         tf1A==
X-Forwarded-Encrypted: i=2; AJvYcCUJNkkVPYj4fjIsgGGrwak9KUgnfQjWpq4jSqpBGJlkW3HYY0tX9bYLLmEYcbXOe6StCxlPEA==@lfdr.de
X-Gm-Message-State: AOJu0YwIUVbZnDCEIg2DoEEWDq7ke34WBTfS3KuwqXIwAdYaSu9AmlRX
	V+7K97/FZQGG6Ca8+gXuaP7hl4xJAAq0wANcbloCL9oEeVD0yS4RA/0Y
X-Google-Smtp-Source: AGHT+IE6UtiM96b7F4BYu3Z26j1CrMyQGPAsaDhDi0SntHw7ZGEZbg8ia8+lCk3AkRNKswP56J10lQ==
X-Received: by 2002:a05:6870:d189:b0:308:fc2b:b7d with SMTP id 586e51a60fabf-314dcee1f5dmr1614737fac.46.1755886203897;
        Fri, 22 Aug 2025 11:10:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf2HtdPsz4JNTxHK2s3EeTHo+3z2Ez78bfm07zrYg7T+Q==
Received: by 2002:a05:6870:ac10:b0:310:db86:8e38 with SMTP id
 586e51a60fabf-314c2326768ls1467856fac.2.-pod-prod-08-us; Fri, 22 Aug 2025
 11:10:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVZ4lFuB2xqKE+uTaKDhsWFc2N2Az6kNzyJlUHZDNgJwunE0r25KDMynFQqs2cApbzBzu4+GQQgbs4=@googlegroups.com
X-Received: by 2002:a05:6830:2aa8:b0:744:f08e:4d2b with SMTP id 46e09a7af769-74500aa8da2mr1878098a34.30.1755886203102;
        Fri, 22 Aug 2025 11:10:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755886203; cv=none;
        d=google.com; s=arc-20240605;
        b=D+oG+83fIqQhwowLO0Ua9QpvdabOZnc7XLDu9qXNcIOePh3sryajm48cDlF/R/vDbv
         D9hHI/dqCC3sN31YR2LRrm/sTbxCfGE0xE1wsPqKRCFaaO9iYytnQA4b3FEgLPAY4fiz
         2KYw7ZVtPcMIzpAAHdWSb4WwGDJNLu3FR7sMjmDzvtGEKs/NgEfD41R7PPDqoTt1U64L
         xXmYhx6qxDCV4BC1KmEyEdAuFq1iL52Mju7/QQfghCvnHi/RcWqeQZIVeotZWf3BtaAH
         czvIjUi9MxucZcj4y4FzJW72r7kqKJusKfNdf0cCR/jJ8Z5nA+zKJT/5Gq/vMlVwi3BJ
         rooQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=4Qgw45kgIvklypQIdjW4WKJClwzbVj1vFIwI4+ABCxY=;
        fh=SHEUo6NhqfGfgVC5nm2ltkL1jef0eOs50UbWe9ntGbQ=;
        b=ipJBTURLv5hFrVaoqpRSLkD6ul15eMxHcxPKq7as/fEpjMROACVBNxwq//AS9mzE10
         I8TSZLKEzn5nB9emOCbKTgc+3gx9KfBCWgmT3ePWFer/h+k0BP9qyfLDbCIBcKGv8IED
         G7IiZQYBkEh/RKR67I0rKcuh31grDTAnhxO2VgnN+dNrouvQQ/PtP1+EUyrC2tMKbPAk
         CFeQjRkDe1mscBBGi2tGqyOdj30MsSEmOlzGrfE47QMxu+MnfV2+8XKm3pFwoFn068VF
         6w4S72duPlkRtAMa3QbcuCdRraGGTt7uWGaZEwqz/eDyCDuLFHJUoh2ZJHb4P9+Oq3n3
         VnIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=JHFX0+qk;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7450e26e811si21169a34.1.2025.08.22.11.10.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Aug 2025 11:10:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-645-VEuwV4f2N2OuwOA2aGxBWw-1; Fri, 22 Aug 2025 14:09:59 -0400
X-MC-Unique: VEuwV4f2N2OuwOA2aGxBWw-1
X-Mimecast-MFC-AGG-ID: VEuwV4f2N2OuwOA2aGxBWw_1755886198
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45a1ba17bbcso12379615e9.0
        for <kasan-dev@googlegroups.com>; Fri, 22 Aug 2025 11:09:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXHXeMjJ6wVxOgoDtYUgY5Asm480FmkfLuQ/IUANuupFrNEaU8Z9Fog5BzTYrdMRUfCgTfgtoHo+uA=@googlegroups.com
X-Gm-Gg: ASbGncuynnaww46IZ+KMkGoNRJXD6DOKB+RmQmoWYCnpsnbEyMEc+GJiXqfX7PvdVGp
	YUNieShuu3nPeQ4wuoGp2hKgN5KK+HmVzj00sbqYvlCi+i1cNZprj4eM/NPJCOpERVwWU/pXWie
	tpDJYMgIfQisDhcdxwW8IIuR0VoNmZCHld7+elPa1poU/WPRLPnsyHziNe48xmALXbZMgotWecq
	tjuLyBtV26OxyNnglSJpMALYn0D5uzwqLwHqCIHA8WX9h2XXUr56k/FvcdM5T8UMZjMstDp0NxL
	YlVXIXgskRCCil6B0KCy3U+b3Z+l4nLYhjsSXsitqHkZFrWh3QA4w626wys33iWfAhh+P/4aayP
	FHcSZDeP566Vesyrm28JLVvm9O03L2mNuJFO3ePL8DxajnNPrM/cygE5H+KCUigMmrkw=
X-Received: by 2002:a05:6000:4011:b0:3a4:f50b:ca2 with SMTP id ffacd0b85a97d-3c5da83bbdfmr2672649f8f.8.1755886197899;
        Fri, 22 Aug 2025 11:09:57 -0700 (PDT)
X-Received: by 2002:a05:6000:4011:b0:3a4:f50b:ca2 with SMTP id ffacd0b85a97d-3c5da83bbdfmr2672603f8f.8.1755886197412;
        Fri, 22 Aug 2025 11:09:57 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f2e:6100:d9da:ae87:764c:a77e? (p200300d82f2e6100d9daae87764ca77e.dip0.t-ipconnect.de. [2003:d8:2f2e:6100:d9da:ae87:764c:a77e])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b5753ac36sm7608875e9.6.2025.08.22.11.09.55
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Aug 2025 11:09:56 -0700 (PDT)
Message-ID: <1a3ca0c5-0720-4882-b425-031297c1abb7@redhat.com>
Date: Fri, 22 Aug 2025 20:09:54 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 09/35] mm/mm_init: make memmap_init_compound() look
 more like prep_compound_page()
To: Mike Rapoport <rppt@kernel.org>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
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
 <20250821200701.1329277-10-david@redhat.com> <aKiMWoZMyXYTAPJj@kernel.org>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 xsFNBFXLn5EBEAC+zYvAFJxCBY9Tr1xZgcESmxVNI/0ffzE/ZQOiHJl6mGkmA1R7/uUpiCjJ
 dBrn+lhhOYjjNefFQou6478faXE6o2AhmebqT4KiQoUQFV4R7y1KMEKoSyy8hQaK1umALTdL
 QZLQMzNE74ap+GDK0wnacPQFpcG1AE9RMq3aeErY5tujekBS32jfC/7AnH7I0v1v1TbbK3Gp
 XNeiN4QroO+5qaSr0ID2sz5jtBLRb15RMre27E1ImpaIv2Jw8NJgW0k/D1RyKCwaTsgRdwuK
 Kx/Y91XuSBdz0uOyU/S8kM1+ag0wvsGlpBVxRR/xw/E8M7TEwuCZQArqqTCmkG6HGcXFT0V9
 PXFNNgV5jXMQRwU0O/ztJIQqsE5LsUomE//bLwzj9IVsaQpKDqW6TAPjcdBDPLHvriq7kGjt
 WhVhdl0qEYB8lkBEU7V2Yb+SYhmhpDrti9Fq1EsmhiHSkxJcGREoMK/63r9WLZYI3+4W2rAc
 UucZa4OT27U5ZISjNg3Ev0rxU5UH2/pT4wJCfxwocmqaRr6UYmrtZmND89X0KigoFD/XSeVv
 jwBRNjPAubK9/k5NoRrYqztM9W6sJqrH8+UWZ1Idd/DdmogJh0gNC0+N42Za9yBRURfIdKSb
 B3JfpUqcWwE7vUaYrHG1nw54pLUoPG6sAA7Mehl3nd4pZUALHwARAQABzSREYXZpZCBIaWxk
 ZW5icmFuZCA8ZGF2aWRAcmVkaGF0LmNvbT7CwZoEEwEIAEQCGwMCF4ACGQEFCwkIBwICIgIG
 FQoJCAsCBBYCAwECHgcWIQQb2cqtc1xMOkYN/MpN3hD3AP+DWgUCaJzangUJJlgIpAAKCRBN
 3hD3AP+DWhAxD/9wcL0A+2rtaAmutaKTfxhTP0b4AAp1r/eLxjrbfbCCmh4pqzBhmSX/4z11
 opn2KqcOsueRF1t2ENLOWzQu3Roiny2HOU7DajqB4dm1BVMaXQya5ae2ghzlJN9SIoopTWlR
 0Af3hPj5E2PYvQhlcqeoehKlBo9rROJv/rjmr2x0yOM8qeTroH/ZzNlCtJ56AsE6Tvl+r7cW
 3x7/Jq5WvWeudKrhFh7/yQ7eRvHCjd9bBrZTlgAfiHmX9AnCCPRPpNGNedV9Yty2Jnxhfmbv
 Pw37LA/jef8zlCDyUh2KCU1xVEOWqg15o1RtTyGV1nXV2O/mfuQJud5vIgzBvHhypc3p6VZJ
 lEf8YmT+Ol5P7SfCs5/uGdWUYQEMqOlg6w9R4Pe8d+mk8KGvfE9/zTwGg0nRgKqlQXrWRERv
 cuEwQbridlPAoQHrFWtwpgYMXx2TaZ3sihcIPo9uU5eBs0rf4mOERY75SK+Ekayv2ucTfjxr
 Kf014py2aoRJHuvy85ee/zIyLmve5hngZTTe3Wg3TInT9UTFzTPhItam6dZ1xqdTGHZYGU0O
 otRHcwLGt470grdiob6PfVTXoHlBvkWRadMhSuG4RORCDpq89vu5QralFNIf3EysNohoFy2A
 LYg2/D53xbU/aa4DDzBb5b1Rkg/udO1gZocVQWrDh6I2K3+cCs7BTQRVy5+RARAA59fefSDR
 9nMGCb9LbMX+TFAoIQo/wgP5XPyzLYakO+94GrgfZjfhdaxPXMsl2+o8jhp/hlIzG56taNdt
 VZtPp3ih1AgbR8rHgXw1xwOpuAd5lE1qNd54ndHuADO9a9A0vPimIes78Hi1/yy+ZEEvRkHk
 /kDa6F3AtTc1m4rbbOk2fiKzzsE9YXweFjQvl9p+AMw6qd/iC4lUk9g0+FQXNdRs+o4o6Qvy
 iOQJfGQ4UcBuOy1IrkJrd8qq5jet1fcM2j4QvsW8CLDWZS1L7kZ5gT5EycMKxUWb8LuRjxzZ
 3QY1aQH2kkzn6acigU3HLtgFyV1gBNV44ehjgvJpRY2cC8VhanTx0dZ9mj1YKIky5N+C0f21
 zvntBqcxV0+3p8MrxRRcgEtDZNav+xAoT3G0W4SahAaUTWXpsZoOecwtxi74CyneQNPTDjNg
 azHmvpdBVEfj7k3p4dmJp5i0U66Onmf6mMFpArvBRSMOKU9DlAzMi4IvhiNWjKVaIE2Se9BY
 FdKVAJaZq85P2y20ZBd08ILnKcj7XKZkLU5FkoA0udEBvQ0f9QLNyyy3DZMCQWcwRuj1m73D
 sq8DEFBdZ5eEkj1dCyx+t/ga6x2rHyc8Sl86oK1tvAkwBNsfKou3v+jP/l14a7DGBvrmlYjO
 59o3t6inu6H7pt7OL6u6BQj7DoMAEQEAAcLBfAQYAQgAJgIbDBYhBBvZyq1zXEw6Rg38yk3e
 EPcA/4NaBQJonNqrBQkmWAihAAoJEE3eEPcA/4NaKtMQALAJ8PzprBEXbXcEXwDKQu+P/vts
 IfUb1UNMfMV76BicGa5NCZnJNQASDP/+bFg6O3gx5NbhHHPeaWz/VxlOmYHokHodOvtL0WCC
 8A5PEP8tOk6029Z+J+xUcMrJClNVFpzVvOpb1lCbhjwAV465Hy+NUSbbUiRxdzNQtLtgZzOV
 Zw7jxUCs4UUZLQTCuBpFgb15bBxYZ/BL9MbzxPxvfUQIPbnzQMcqtpUs21CMK2PdfCh5c4gS
 sDci6D5/ZIBw94UQWmGpM/O1ilGXde2ZzzGYl64glmccD8e87OnEgKnH3FbnJnT4iJchtSvx
 yJNi1+t0+qDti4m88+/9IuPqCKb6Stl+s2dnLtJNrjXBGJtsQG/sRpqsJz5x1/2nPJSRMsx9
 5YfqbdrJSOFXDzZ8/r82HgQEtUvlSXNaXCa95ez0UkOG7+bDm2b3s0XahBQeLVCH0mw3RAQg
 r7xDAYKIrAwfHHmMTnBQDPJwVqxJjVNr7yBic4yfzVWGCGNE4DnOW0vcIeoyhy9vnIa3w1uZ
 3iyY2Nsd7JxfKu1PRhCGwXzRw5TlfEsoRI7V9A8isUCoqE2Dzh3FvYHVeX4Us+bRL/oqareJ
 CIFqgYMyvHj7Q06kTKmauOe4Nf0l0qEkIuIzfoLJ3qr5UyXc2hLtWyT9Ir+lYlX9efqh7mOY
 qIws/H2t
In-Reply-To: <aKiMWoZMyXYTAPJj@kernel.org>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: auewvTJB5IMNa_5elgQdmFfkh5oV6wLfiPOz5GNRWo4_1755886198
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=JHFX0+qk;
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

On 22.08.25 17:27, Mike Rapoport wrote:
> On Thu, Aug 21, 2025 at 10:06:35PM +0200, David Hildenbrand wrote:
>> Grepping for "prep_compound_page" leaves on clueless how devdax gets its
>> compound pages initialized.
>>
>> Let's add a comment that might help finding this open-coded
>> prep_compound_page() initialization more easily.
>>
>> Further, let's be less smart about the ordering of initialization and just
>> perform the prep_compound_head() call after all tail pages were
>> initialized: just like prep_compound_page() does.
>>
>> No need for a lengthy comment then: again, just like prep_compound_page().
>>
>> Note that prep_compound_head() already does initialize stuff in page[2]
>> through prep_compound_head() that successive tail page initialization
>> will overwrite: _deferred_list, and on 32bit _entire_mapcount and
>> _pincount. Very likely 32bit does not apply, and likely nobody ever ends
>> up testing whether the _deferred_list is empty.
>>
>> So it shouldn't be a fix at this point, but certainly something to clean
>> up.
>>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
>> ---
>>   mm/mm_init.c | 13 +++++--------
>>   1 file changed, 5 insertions(+), 8 deletions(-)
>>
>> diff --git a/mm/mm_init.c b/mm/mm_init.c
>> index 5c21b3af216b2..708466c5b2cc9 100644
>> --- a/mm/mm_init.c
>> +++ b/mm/mm_init.c
>> @@ -1091,6 +1091,10 @@ static void __ref memmap_init_compound(struct page *head,
>>   	unsigned long pfn, end_pfn = head_pfn + nr_pages;
>>   	unsigned int order = pgmap->vmemmap_shift;
>>   
>> +	/*
>> +	 * This is an open-coded prep_compound_page() whereby we avoid
>> +	 * walking pages twice by initializing them in the same go.
>> +	 */
> 
> While on it, can you also mention that prep_compound_page() is not used to
> properly set page zone link?

Sure, thanks!

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1a3ca0c5-0720-4882-b425-031297c1abb7%40redhat.com.
