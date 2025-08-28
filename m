Return-Path: <kasan-dev+bncBC32535MUICBBWMSYDCQMGQE72K2GNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FE12B395D6
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 09:46:35 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-61bf9ab032fsf371833eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:46:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756367194; cv=pass;
        d=google.com; s=arc-20240605;
        b=doDJ32bLHF7mjQLw2jCo+RAw6w0x38H3y6tOHoQPCa5Qz7uWQJgEpjhKC28g4m71Cg
         xkTy6Hnr43Snh81fY61vRVTxT7y8C/ZpRvmSp8tZ0wIaUy5nd/kkPjaiWklibNleCZr7
         Pnb+l8pK37sWkvxtj6S5DBkgT2wVYZdl51nYJUlstBlIGQ077pmB6hefndH2QKlZObMp
         IH4GdhCVBjSAEMhMmz/0ZGSBpDtJgiyVX3YkHuCzbUQMMQSX3ge8b+JbLyCLRmylvE18
         6Oz/jDMu0XjVCyaHzZQXzG5iVAE4PS4Xa+SAYQSWw7EpP9S9jROxY5tZ2/h8o7nqauyJ
         xnNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=OfdzZ2qo1cXEcTngeVWcCDC5aRF0m7yGUVuY19Ht6pc=;
        fh=dsIwpZ0+Q1qlzjhS3w4NnMmnYOgMhjnJYU+WUJwKOLY=;
        b=TKqc6f8hscLnmkGN57nVNRLbqzNrLsKuW5GslI2WB80YlY+TczXgRE50tdU9NyJgib
         5ALOivIZtNV7oRzhnZ7lft5JOxnerrkwKlrWpQULoFahpHewktYsa7iHFbFnz9UKXpLr
         1Ef3UU7hCUtViWBDtN3KfRGB7zyO3dALQBt2BuExn7QNurbAQaYiBgMM+MtJ4XJjK2YG
         4ai1YFZInj2W5RsJXAM50EWczYdRMOYSxYMxpK7XMZpdVZdbDpCrc/QlLriwKHqj4o1V
         W0jwdyCm8N/0Gwqb2Kkr845unR6CnaBANEdDr9sSDqvalEvGiTc8v1xIY1F2ztZyXLAQ
         98gQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="eHAsVJf/";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756367194; x=1756971994; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=OfdzZ2qo1cXEcTngeVWcCDC5aRF0m7yGUVuY19Ht6pc=;
        b=C/vU7/Q34MvHe2CmqPXqGTrWfz5ADooCAJve5F/H24rCUkkzaKdkFiRjLbd3JWHA2y
         MBdrPyVGuW6fZuMJC3/D79B8pNK0BJDNpZR20GrVvwi8sbMkKAqQqIh6au9LQ1cAzxBQ
         ZBfIDuiA1UPHJSLrm3G16HoL78GOnD6/FqD8KSesaQl2RtelXH0Mo1PwVzAYGo5eJ3rY
         Utphr/ybrPhmZywirEQTzXbZ9sqE2etjWJ316qMi6kZiynVZhg7oDrDWYffmoZslv7El
         gqgAPKAt/DWds50SKd4eqC7U1SY48ehkU4w/J3ih6bv+3tkNQzHAlJCPT5yZD20sFcCu
         KtSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756367194; x=1756971994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=OfdzZ2qo1cXEcTngeVWcCDC5aRF0m7yGUVuY19Ht6pc=;
        b=bPrXgA4V8gABgCDSjuh/QMJOmmgK7K1SpPot6o/dwfB1CX3XpsNy9+dxbluEck+yQC
         FSWBBzZ+wLgYZGhGQa3XZMYJ+qBOpCQz+YbRjxklgQeNcuUPUdEhytRDNfdGDgMo2mUa
         kh1+4vKbml7OYcdF6FxSz3iknnHrYcv4EJ0ZhWnO7Xcz8MCbA0lODah/eB6Jy1IvyN0J
         UyJ4jExtg5wKS7n3C0GGsXAZSFZT4OP5TSkDZA8lCj7NnIaxhAYDg/9PFxXelXt0auS+
         EbLYmLdjTCJ0pJZk/r6yPcDXQc/B5KntTB1+FVJkxHKrbXArvPIacvBLgv3oW6vYTDsk
         PRhQ==
X-Forwarded-Encrypted: i=2; AJvYcCV8FIEHzDNfPNO50Q+aX+uWIQb18ssYY2DZQXbnGnFnC9Lv14a/hz/2UTq57fk8QYTCGS+cWg==@lfdr.de
X-Gm-Message-State: AOJu0YyyPHHjjiS1JVsjdaomLADHlpV9eHv+Zd5x0/AFMTYv+CrqGvlN
	1zDp9QrTEULm+ptjV1iWARjXw6I4ZXh48wJCVI4axzp24Hy0fGH0EObc
X-Google-Smtp-Source: AGHT+IFKD0U59dfFY2hIzeJirboFZhskFLML6kbsxGwcfKwZcz9W9jxD5qNvP9rg4JdHWZUMY/nRWQ==
X-Received: by 2002:a05:6820:611:b0:61e:6dc:d085 with SMTP id 006d021491bc7-61e06dce3f3mr2394931eaf.1.1756367193719;
        Thu, 28 Aug 2025 00:46:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf0w2IAomMM5Ui/DbYCtK9bbJku/qhBSXMaaUVS+0tsdg==
Received: by 2002:a05:6820:4408:b0:61d:cf72:9730 with SMTP id
 006d021491bc7-61e1248901als117430eaf.0.-pod-prod-09-us; Thu, 28 Aug 2025
 00:46:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUNXwMftksL2mciZUk7tbMsXZASkZq9vQEI+QxE2XAavt6CWc9KaB21sP5owsUvYGKtsONEgMk322I=@googlegroups.com
X-Received: by 2002:a05:6808:6a8e:b0:437:d966:be22 with SMTP id 5614622812f47-437d966c349mr1109364b6e.36.1756367192915;
        Thu, 28 Aug 2025 00:46:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756367192; cv=none;
        d=google.com; s=arc-20240605;
        b=caHPSflqLE4F9KhJtB4Yhgg7clcIDsnRo1bU7e/2gvhwNl1cmeU5eTQj886ggQUSGx
         GkMNQbCbanb2diw0luVw3w/3sowzVRGsREEMA1UHtU9hBYVKHPw5JVUn6yp1Q/T83Z1Q
         ukAWlUA4mpJbil1greaQQoErKDCujfCf7F+syudIl38nfgLnUpZDJorynm5fLYktJwgn
         eu+HO6fdMygGw8ZxNP+7S6EP6D5rqD+c8WQl7/W39bLxZDSdIKNSyPYod1lgOE0qxrAM
         YsPJ6bPixVc5YBd1XabrM9IB5wqbpP9UaZAFAmtZlZ6NGs4Qm6nNrcEMsaVUBUEW+mX2
         xkJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=QIPVhNdDqwyEUU2mMSzlYSdtbuVp92JbzlpYQuyYJ0w=;
        fh=Cx9OrAnwQemQRWsXzlQEAPVRq68AiXvleUYdHV4yMoU=;
        b=Jfc6JbVhI9OB7c59ufMpXnUhVraFskgUmuqy/8RnjIAdJWbr87QD+M1xhopdAA3Jxf
         7RCK4oYrTkZWzjaNfK7GUukVWrfGWbhWApVq6Gc3tt9YcUA3yqJkAzkmh0vgWKkP/1/C
         mUjcgxbpiIgemGbUzXXhhBPV+dMp0RJTvDJJFjPiWujS6P0ggycIVWx7ntq9jQXSypc+
         Sb0M3hin3/9nr4mjHaIdVT36qZv5VT+06jhEqnihCrYA+IRdDDil65lp7IMSOng+u/D0
         WXJCNCnitOAXGacInzDmSMwm5xoqentXXjhhIV9pz+H5b8zgffcfOkpjXzCmEaUtDpa5
         iBTQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="eHAsVJf/";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-437963df630si457479b6e.0.2025.08.28.00.46.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 00:46:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com
 [209.85.221.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-605-F-2xUJjbNraksuL8nlOejQ-1; Thu, 28 Aug 2025 03:46:30 -0400
X-MC-Unique: F-2xUJjbNraksuL8nlOejQ-1
X-Mimecast-MFC-AGG-ID: F-2xUJjbNraksuL8nlOejQ_1756367190
Received: by mail-wr1-f71.google.com with SMTP id ffacd0b85a97d-3c8bc2914a9so285081f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 28 Aug 2025 00:46:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVpa5Ijwmu4nHCcfcfbrQTkLNqlmYzosUBP/4cxHwiNm65Yhc45WlB6odxC96kynlM1FIyAF39HHYU=@googlegroups.com
X-Gm-Gg: ASbGnctKETG1Hga1SVpowBZXqIUSZpF8RQ8D2XHbFXC5rg00eooOv/9riexJRigB16q
	IMk+2uJ5BlLr+620NXm1TZgI/k7VRUsAYPqA9IDpI1nxRgm2BveezsloaWj9fIQ1TCcNjNuhnUF
	ZZNPbtAUrQq7urbJVmY/IdGG4zqzLd+lD64Vgf09h7dxIkwPkuBaMeqo2zZm9zrKKoeNrFgMaSw
	HPexZN3HOcyBFZj2bPG8FmoA5ZdkBKyEehtsYJh+aagDBag2RRNzSQmkxAHbnPXK3RMoHmbpOh6
	GpHR73I3ql22+6uwzDuzKytJAPj0uD/ZdBka1Z4Z4X79caM7SsouXcNIxb2tPgnmbflEu//boYw
	0ZH0PpKj5t5Fv5xZxy9p3CRgWQolrjThKi6BMDTy6E/vuETOCV7Po+Og5/LgvLQFB/jg=
X-Received: by 2002:a05:6000:18ad:b0:3b7:948a:1361 with SMTP id ffacd0b85a97d-3c5da741330mr15989030f8f.6.1756367189564;
        Thu, 28 Aug 2025 00:46:29 -0700 (PDT)
X-Received: by 2002:a05:6000:18ad:b0:3b7:948a:1361 with SMTP id ffacd0b85a97d-3c5da741330mr15989008f8f.6.1756367189132;
        Thu, 28 Aug 2025 00:46:29 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f28:c100:2225:10aa:f247:7b85? (p200300d82f28c100222510aaf2477b85.dip0.t-ipconnect.de. [2003:d8:2f28:c100:2225:10aa:f247:7b85])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b6b1cdf05sm35411485e9.1.2025.08.28.00.46.26
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Aug 2025 00:46:28 -0700 (PDT)
Message-ID: <0e1c0fe1-4dd1-46dc-8ce8-a6bf6e4c3e80@redhat.com>
Date: Thu, 28 Aug 2025 09:46:25 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 12/36] mm: simplify folio_page() and folio_page_idx()
To: Wei Yang <richard.weiyang@gmail.com>
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
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
 Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
 Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
 Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>,
 Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev,
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-13-david@redhat.com>
 <20250828074356.3xiuqugokg36yuxw@master>
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
In-Reply-To: <20250828074356.3xiuqugokg36yuxw@master>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: mqXyM41DDi5uidN3v6NdgS4BuMaw_Zta6BkS0g2WNbc_1756367190
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="eHAsVJf/";
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

> 
> Curious about why it is in page-flags.h. It seems not related to page-flags.

Likely because we have the page_folio() in there as well.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0e1c0fe1-4dd1-46dc-8ce8-a6bf6e4c3e80%40redhat.com.
