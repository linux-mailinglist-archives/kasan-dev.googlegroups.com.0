Return-Path: <kasan-dev+bncBC32535MUICBBXXYY3CQMGQELOWNYXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 001A7B3BE24
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 16:42:39 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-2445803f0cfsf29091635ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 07:42:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756478558; cv=pass;
        d=google.com; s=arc-20240605;
        b=SPKto8o/nPqaCNlfY2Z3HoCtEwZS/nFJ/PrcNKA17Aq8xNTV3nDAnYufdt+zhR/C/h
         AliG4BNnF/w83yHPpZEBxIdJbMHfkoeZwGE8r5qC84ekjkHlGFb0KCv3rYAo/Ty2RQ+v
         c8U8MBKCikD6F1jr49QroUC1L3UpFKeXAbHBSQw9Qncud0Vu3JyTcSL9kX9HbQklf3SA
         4xKKda/MbNdFVN2UwwdQXc5kDMx/Bo9kaDJLrGwfgpFOV+BM17+sNEovKjXQJugyV1Jn
         BLwnlUJc7lWSpwGuPaWc3oJktRtDDvX1AYROoH4SvXaupHvgcL9Rxqzwuj0aaqKVtnH0
         lUXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=3ZmBvY3+cB6I5GdEM7c+xgCA45jWivaVZqkUB8Zl0y0=;
        fh=7k7lmzZkHHeEqQMLSK8MxEJaNJa68JMgGzybIpW+pkk=;
        b=Ywcfs5bTpwcKAZqVtb5FnED3PKpRLMiwNseH+fhlGLxcFOUIsyLVtVol/Ss9h0Rp6Q
         5/a+0KXb0DunjCVUblAx2s4+S0y8fwgDl4yOc4HogUkXxImi4wb1ON1EYHYKWa0hgTXr
         KrtY+xClROvvc999fuFeAfDGnmP3VnBR9upkSdSutGBvF+abII64TGqgAlABBBPMjQmu
         Ya8W2LET0kfUh0DwVy7NBhXlHnQwTCBBuEvZagpGlCE0DXfXDN41awW5h6UlzByGLV47
         jpSb8xuDrka0OqjQv3UdmSTr39SUXS7lGVsfIf1kcRh4be9/ETPTXIcHMciTtcTh9Ksu
         FzoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ggmBBqWE;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756478558; x=1757083358; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=3ZmBvY3+cB6I5GdEM7c+xgCA45jWivaVZqkUB8Zl0y0=;
        b=ebQX1Uy4b5eKhLXvWQIGNEAeksTHE5EEpxHMD3/2nzeVaQZRJZlVB6wX7M7tK0QABe
         rCkpBZdBT5fTJb1AfdAkRiVC7sKVaDhHuXpa6leGnMH0s2Ot5+er+BpYMxXa7xm1Ke9g
         5AR6Ql0KnpIknrfj0Y7eBtRnYPYWtldjl8kmoUWyW0W0qePzQbtdvA7F5fF1Yn6VUpcU
         x16X6ryoXuj8INROxdt1j1Pn6xbbmoScLXeKpE3gCeJVQ/R+0QpkAR1e4u5NUYpQNa3X
         9cJ++QVdy6lysTubprI6E9Fo4s66W3Dy0JJTF9wKfi00MUCINxObvX80y1s5QQYcvcXN
         ZdZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756478558; x=1757083358;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=3ZmBvY3+cB6I5GdEM7c+xgCA45jWivaVZqkUB8Zl0y0=;
        b=jxBN9zUrK33bPWYnkz4Nj+M4kck1ss4j8GY+u2S6NgRVuXJjbaLxPhbaI4WQTd7W7k
         ndzE+YngKMfyhRvK9K1h79POLPz5yMGgCBWxahpCP1xuLeWnKSRlzVW2JhetRCKjBHqr
         Fc1xXqdAivxDdJN+VNwl7MKwdmL6ZK5+cR06l9vtoCcjT8tich6Cg4zLU2ZjZXYxoS4g
         sd5bqCgxuhH7HvFZA7k7509fLpY8LI8J7q/1eDBgttNtA7lauxfdz6oikVLgjEE/iL45
         vrn9hraseyy3Pf90Gw3lX08yEmJTAEYLaCtHXF+QUFdufmfTIF+VkmTi0O2d320bgSth
         +KAA==
X-Forwarded-Encrypted: i=2; AJvYcCV5AN8OiYHHz4KPQlwu7zr5TuUwhnbbulUfoC3M09F2wxcNjTzsTtdNOk0lRISSQN+quokKow==@lfdr.de
X-Gm-Message-State: AOJu0YzdICJOx08qAchI/Y5iSvgCj2SXLbNi4pmeGloSGuS1xRaiAjWw
	2gUvWwzN40LxUdP+UVkcUtmpu2mfylK4HnCx/CF9n9e0n1hkqxY4biph
X-Google-Smtp-Source: AGHT+IGE1cePjlUKn13Uh7j91LklHjo/cikerTXTWqaekSPLx24ew/0q5WK7QK7QraYa9gyANd7e7A==
X-Received: by 2002:a17:903:fa5:b0:246:b56f:7ec2 with SMTP id d9443c01a7336-246b56f7f2cmr224315885ad.51.1756478558358;
        Fri, 29 Aug 2025 07:42:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZesV63vHb+umUcndf26f2MtAbmv5ByVu6BUzxZ5sMJqQg==
Received: by 2002:a17:903:1385:b0:248:9d52:852 with SMTP id
 d9443c01a7336-248d4e3e14als14347825ad.2.-pod-prod-01-us; Fri, 29 Aug 2025
 07:42:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU1jFY/LGQL911W1QPNBVBYEamffBdxTfEFxyk/tIdeZqtje/4sCDGLc5D+yOlQk78v7k0S3nF/zzA=@googlegroups.com
X-Received: by 2002:a17:903:3d0c:b0:248:f55d:447a with SMTP id d9443c01a7336-248f55d44bfmr80353785ad.3.1756478557042;
        Fri, 29 Aug 2025 07:42:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756478557; cv=none;
        d=google.com; s=arc-20240605;
        b=jODHXbpggyP5fLRnTEUcX/csnWokWLGwVAtw2oY+3apBzt/cHujr95XKp6sI4fxTkH
         mHkYztXweTXLFBNICp6+e1w/cBU1G05tXMwTk+LdSznHFW3Bf1J7+ks1A60Tvo3eaNFD
         Ohio3WL5YspifWz/svElVOg4tm5jfudOFyYa5cATAgylM7t5Sav04Sg733GrwJbMNFX/
         YreaUp1K/vnW9TNF/sNxp8uFwIjd2F25gjzmPWMfbmgpTcOSlikgrkpch95B+EWwdL+z
         6zBIzlGOWeK4B3BI2ASf7WQcSoTn2C0ezAhAiHD2uzhVJA+IJpUlQyLuoM+E8qRcSy0T
         xlXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=ReHesm1JzI77Ttn1crqpxEHfJBy9ITN9OqG2sWgOwWM=;
        fh=pJqoX/eavNfqm4e4hMA/l7AV2IXYGccSpUjgv2hvbZA=;
        b=R5jA7d/833IGLBPafE/SN0BYg1Sq1XzK25xFdQ1CCL9KVqMvfP/QLyaYkmsnvEAjhr
         TMtpYmGrKxrTnmvqk3ktDYGoB2WEWLnNQG9n+vc6ba2VZSgZTXjCtZSd265cxDGuLH/n
         TcTYpLc3h8B1J+ppMkdxnCnF4PiDOlTv9pz3iXrigXN2/zNUq9WpRtQ9479R6fKC4uvD
         f1upIl6RO1aBl9FF1MmIRpN9nFRjBWeXZLaWYFYyQqtIt5Sf82j4DxQN+FeehMzn99ZK
         Y9WPtGI0MwskY9Dusrzll/irstmvGF1y1OHv2kyQDneb5OZrMW1ySUJYeaSyl+AMiJ4P
         Eoiw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ggmBBqWE;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-249055cc501si923275ad.3.2025.08.29.07.42.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 07:42:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-66-ttcpl5XTO6GWWkkxuk0wRA-1; Fri, 29 Aug 2025 10:42:34 -0400
X-MC-Unique: ttcpl5XTO6GWWkkxuk0wRA-1
X-Mimecast-MFC-AGG-ID: ttcpl5XTO6GWWkkxuk0wRA_1756478554
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45b7f0d1449so5191305e9.0
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 07:42:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUIUBgEcNZ/2gFmBoe5pBejS291NMoYfpZh/K+FZtlgE51lV+MrIka09MzOxvUiBNSXlizeCadHSlk=@googlegroups.com
X-Gm-Gg: ASbGncuurIg7aP0LE7Wtnu+NAU4r/PZqsjE60Q8PCfs8RaOpp440MTryV+GucMxXEXa
	HD3IlTQEE6Lkvd11WkcRdPSyD3iuu+cUi6+/BRsD+MqAnfYvt3v9ghEvykPi3UY+pit3CCb9H/i
	8ySzW+tuGO1mX5D19cdDhesbIPoAweAhicnEhB8MG/vbyI3wAxjdpnPCzCUf/0Dc5NFyr3en1zH
	nF0PnJBhmRfh96+Zg2F6WMfDFsGmsQQ+na6QB1JZ6XNsVjDH1pYznoFox4dz3F9IaxMZe5mzLj2
	QXwOZhmiaEvr4qzvx4L3Ig6hD7P3uCmbpFFoYcWB055qQBD+CoxVlLeiIJs/GBpbsA7xvYUM4eH
	jpkUj10gNmwxQitqyYb2vsET8SXoPfvSZvdeDeu2qDpeetTeKMxTIqeOPS+ig05fe
X-Received: by 2002:a05:600c:a47:b0:456:1824:4808 with SMTP id 5b1f17b1804b1-45b517cfe66mr203887925e9.32.1756478553434;
        Fri, 29 Aug 2025 07:42:33 -0700 (PDT)
X-Received: by 2002:a05:600c:a47:b0:456:1824:4808 with SMTP id 5b1f17b1804b1-45b517cfe66mr203887385e9.32.1756478552938;
        Fri, 29 Aug 2025 07:42:32 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1d:100:4f8e:bb13:c3c7:f854? (p200300d82f1d01004f8ebb13c3c7f854.dip0.t-ipconnect.de. [2003:d8:2f1d:100:4f8e:bb13:c3c7:f854])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b7e89920dsm46578795e9.16.2025.08.29.07.42.30
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 07:42:32 -0700 (PDT)
Message-ID: <7cd5f8c9-9bd3-40ed-a3df-a359dcfe1567@redhat.com>
Date: Fri, 29 Aug 2025 16:42:30 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 36/36] mm: remove nth_page()
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
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
 linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
 Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>,
 Mike Rapoport <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
 Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
 Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-37-david@redhat.com>
 <18c6a175-507f-464c-b776-67d346863ddf@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <18c6a175-507f-464c-b776-67d346863ddf@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: cw9RtCfGD9Il5UQrVBCTzulvPNE33q0zKuinaQmbXCQ_1756478554
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ggmBBqWE;
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

On 28.08.25 20:25, Lorenzo Stoakes wrote:
> On Thu, Aug 28, 2025 at 12:01:40AM +0200, David Hildenbrand wrote:
>> Now that all users are gone, let's remove it.
>>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
> 
> HAPPY DAYYS!!!!
> 
> Happy to have reached this bit, great work! :)

I was just as happy when I made it to the end of this series :)

Thanks for all the review!!

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7cd5f8c9-9bd3-40ed-a3df-a359dcfe1567%40redhat.com.
