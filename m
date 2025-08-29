Return-Path: <kasan-dev+bncBC32535MUICBBA6TY3CQMGQEVKYNTRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id A98F4B3BC64
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 15:22:13 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-3275d1275d1sf616316a91.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 06:22:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756473732; cv=pass;
        d=google.com; s=arc-20240605;
        b=XBeRc5rfh+ARreuQmuvYUfG1oJOcNyOV98xNk/iIQczXo1xhPJLn0Y5honWQCdXecB
         KjJyZ+3a/m3gvOQhdQ4azw8z4ybqhk+rBicV44jp4o8LQDM+BnDZTXhtFh7SOQ6jjnyD
         5lGCHYdQLM0lbw1nk8giKT9Sxe4C5aOwMuoF5Li8nxhPDO/QmkLe0SZeJCLZBCvy/xuk
         opvo1FZQZmSVdnl05kdEWEbcN/ofQMQT7Lb6wnok/c6kMEDGIJgbV1Ly8MpjLJNFG67L
         yyI/gZhB7CJZ0RMB/RjEAH+9e4nUP8o6j/hudbE7ars21cFnvHKwBImtl97y51PFYxiY
         zlcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=SZy1HSBm875BBvUkqP6bXlK4qpxwmftPOV2KBWXhuok=;
        fh=Fy/Iw5ph7RNsJIdcPag6/4lk9OJYCfLwT8WnHyJWkVk=;
        b=Uc99etiMJQ5Ur2DuY0KQfAnX12bCcf6Tc8PIgrkxq2e4R0gZwNYNEpbpg47a6l5pv9
         Tiulc8M6Ky1FDvBQkEE5iMzsxfaPMpQoe3tdE2ZRIOYPXxDzSq0q9EJ0NXZKNz1mqudX
         fgTJ/C3OPQkEOox5xTCv5TwpwKwHBZM9iO8RYTfbVNddbS0lXum+jMYSY7VNyRujDmXy
         TggXCRI3kP74oJDJRMpRR8Aokid1IYnu59VJ+UR/aJpPn7uvhl6ABu5v8wbYoXY7MFo4
         u5u6QGY4phzELD5MWBlqkt44ArBwcPnmNKuEWH+rfNFpRK5Y89sF+eOWmEUkPGExrzRt
         OjJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UuLQ56t9;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756473732; x=1757078532; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=SZy1HSBm875BBvUkqP6bXlK4qpxwmftPOV2KBWXhuok=;
        b=i6T7tSB08f8z7T6tmoXWg+cJxNqL70EUMpHU1d6tVKgEA9tbOJOcpXya2x+WbpnPFJ
         JJJogMGfMOtDFhUJtmmJirIklbfmQpSrEgwql33/M24kHIq4hGunKi9WrDjIGet7w2gM
         qeJKLp9Wer8Xo7V7uQFONSy4UZVpqitgXxm2Uxjsl+e0Bb1VJAicOBLFRfNUl3EDsT7O
         +eh1jeEuug8FR0Su3P/TIV5yd/d74Pm2TDJ/af+g6N0o3lzQo/t82g/8fd8pa6t5zqON
         HAcPodOkrlgZ5Bie9T7Gm2pZst/uK8hUoSq6ZsAuxI2lSuhralMAm9jkrb8uzb8pa1yv
         o5cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756473732; x=1757078532;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=SZy1HSBm875BBvUkqP6bXlK4qpxwmftPOV2KBWXhuok=;
        b=X15vIbrkzrop1abX8uK1w3Kxw/FSZHyTd94QA9Xttg8W7QSmOyH2igsBDLgkS/I9EB
         KpV3qEBb8HURPMil1ctHc4Djj3gHwBX+TNVECWeI2/zGHqrHjC4wIp//xyEpqj0VhS/1
         efWAnYIUdtTlH+boQu/7zxwVB77kS3BhyEQOTgZOhuIf1U1BjbqVDvTrqOr42ofzS3lk
         gjGfwk2JkmAs7b21wR6OBe6Hu4Qc2utP7tke9ZlWeYIe3qNotzL8nS8yF0V7+1F2YFoK
         b/Sg2//8LvQTqtAvaqZf9QQ4V+1IlEQttyrjsDPdG3aZqEcApVZna3c4srUsFzsT6m4C
         KK0A==
X-Forwarded-Encrypted: i=2; AJvYcCW601qqSXskXQ13UurLp6Hw69hYJQ70WBIa8VVJjmliTdz8dLBEc5qweKgvZHJawL9e+GfF/w==@lfdr.de
X-Gm-Message-State: AOJu0YwlUtJx/qpRHhuhz0R69+LT5zPB+NPEV6aW9KgrsEhHZLj0yixg
	J5xpf0GUv5NEKjQDKUWorrIF2cSqOUJeJcJjGoBe6MD4K3NVRMnQGgkA
X-Google-Smtp-Source: AGHT+IE/vY/mT4HrattWdeQgtV26VFLuSA+nfKBTdB13PVFcKBYXZhfZRkRH9GpNfmxEnbq3PfFK+g==
X-Received: by 2002:a17:90b:1d92:b0:327:e34e:eb01 with SMTP id 98e67ed59e1d1-327f5b87d56mr1098981a91.1.1756473731625;
        Fri, 29 Aug 2025 06:22:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf8w0RVifxBMiw4oKYdErMc9Q62NEPw3hMZT1qYtkb0ng==
Received: by 2002:a17:90b:278d:b0:324:e4c7:f1a2 with SMTP id
 98e67ed59e1d1-327aacedf42ls2420634a91.2.-pod-prod-06-us; Fri, 29 Aug 2025
 06:22:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU5nEb1km5W1aCbWHTwgvLUVehZOcF0QL58AKg3CB2c9U70L/oWkAig1GAtJRKFfZ7zkGIbKZLCOF0=@googlegroups.com
X-Received: by 2002:a17:90b:2ecb:b0:327:e34e:eb16 with SMTP id 98e67ed59e1d1-327e34eed17mr3554188a91.1.1756473730054;
        Fri, 29 Aug 2025 06:22:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756473729; cv=none;
        d=google.com; s=arc-20240605;
        b=RdeQSJt4OkU1CiIlnKk6cSr5AilssM0S5tWJOxCd8CGJCHjWcrJcBwe+GP7e70Gdl/
         7UdNPyw7bJodCSAt6k+6ghQm4DMi9xauWBLcAcivpWRbj6Imii9hCHN3Prdy30li7d/g
         6IugA3ZwKthcR+77srfnJoeMhX6pws/wzCIN536Zh5zPpuhHgIo9buwkSlUUt5E72rM2
         v9bzwJDPLGF5nry9DlLGXsuOCg47UCyA2bgHFkLuXa+LKze/o15uyAuC6wnQZum2rR5s
         vUrO3ffa8jipEQRy9V96UJeSCHNcHG1N9mPURXaTZv2Q61mCULDs2eWbrHMxKTjdbLVD
         Jmww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=aggFKTWIoz3JmsTS53UGUQwfpKwPCT7EHzMCjR4W6Kc=;
        fh=lPi0aPKP3zL7Z7ptgwj+byKaTGXHC9uF0CtSsI9FPmU=;
        b=OJjNj890pW5Dmd6QfkYgw3XNKgbvApnalRazPBtYAleSKWUYoRIqb2liCmOsAfLk6m
         yHzIeGP2L05d0ZChwdpuHJSexS2sHskPW2NjHUUg3J8xgEDo9bFZeI1Ll39zMO0otSUM
         HlMtdpFVGVz92aQ2cFtooRRfnQ1lFfdIAXALfLhDPfOBRk7RZQQdD3//IHwdmCOtijXm
         2SKSGhfaQFMgb9vQXgvQXt905P5NG5uTWDouzxBufZRWlkDRMvf8gs6UN26z+CaqNd1c
         A3M6CFS2HKN8xROUwkSL3tHrjQn4TQbKW4DsLXwcPAkSTucRTJknLtJyJX9rwzJBxfZB
         uH1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UuLQ56t9;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-327414fc119si331440a91.0.2025.08.29.06.22.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 06:22:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-183-xIMUYa1hP028szUEsJKlGg-1; Fri, 29 Aug 2025 09:22:06 -0400
X-MC-Unique: xIMUYa1hP028szUEsJKlGg-1
X-Mimecast-MFC-AGG-ID: xIMUYa1hP028szUEsJKlGg_1756473726
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45b612dbc28so14837685e9.0
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 06:22:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVgOXAFLvkjH8fNIB/pajUENViItqZNPWYUe0ctYEsMH6DawLyX1ruXW/AqQnb8kE+ypma97zWIFbI=@googlegroups.com
X-Gm-Gg: ASbGncuXH3Vj70z0YiZ8pqefZXtbYWfr0Qibruv/Vc/yOPCwYETwySI7sm6dPFjx1D8
	7MLVBzy5jwsDZmK05VSP/cR8BHFfiynPg5LjhiUzvbSpICfN2Gdfzx2HAwTfNkC0FCQsRvZgQ8T
	ihry5Lxv2voDJPL+BuGyg6jKngOgW/IzGzRU1xxllZrbkQ7uaCQ2TFRp5r5WMfaSb4qUW/QskMj
	uXHYW81WnfSIRpwoz45Bg+/Wu1E8XvQKvnns2FL5JTTFI5/Q4ygo0KZSPXf+Y0/QPevi8uY3dzQ
	wY3jRmp0qXmnzO/OkYXLpw6cTnpobGQP62NB9cTRc+eBtgfn60Ly5qWmVbEGM7VgvMjJeovd06O
	dAB7rwCwSxzzW+hVnvNqxz/K0byClDJCts+KGOoaO3fpGa3JJVIAWDpPWcuxHaBpd
X-Received: by 2002:a05:6000:2c0f:b0:3ca:a190:c473 with SMTP id ffacd0b85a97d-3caa190c6ecmr9849853f8f.4.1756473725461;
        Fri, 29 Aug 2025 06:22:05 -0700 (PDT)
X-Received: by 2002:a05:6000:2c0f:b0:3ca:a190:c473 with SMTP id ffacd0b85a97d-3caa190c6ecmr9849784f8f.4.1756473724881;
        Fri, 29 Aug 2025 06:22:04 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1d:100:4f8e:bb13:c3c7:f854? (p200300d82f1d01004f8ebb13c3c7f854.dip0.t-ipconnect.de. [2003:d8:2f1d:100:4f8e:bb13:c3c7:f854])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cf33add483sm3368560f8f.37.2025.08.29.06.22.02
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 06:22:04 -0700 (PDT)
Message-ID: <f7f9f535-0bbe-413a-84e4-fcb17a502a40@redhat.com>
Date: Fri, 29 Aug 2025 15:22:01 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 16/36] fs: hugetlbfs: cleanup folio in
 adjust_range_hwpoison()
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
 <20250827220141.262669-17-david@redhat.com>
 <71cf3600-d9cf-4d16-951c-44582b46c0fa@lucifer.local>
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
In-Reply-To: <71cf3600-d9cf-4d16-951c-44582b46c0fa@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: 40G1UvRC6mpr6MtF8pZrMaa6vaoKrsLjAFPHow-WZTw_1756473726
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=UuLQ56t9;
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
> Lord above.
> 
> Also semantics of 'if bytes == 0, then check first page anyway' which you do
> capture.

Yeah, I think bytes == 0 would not make any sense, though. Staring 
briefly at the single caller, that seems to be the case (bytes != 0).

> 
> OK think I have convinced myself this is right, so hopefully no deeply subtle
> off-by-one issues here :P
> 
> Anyway, LGTM, so:
> 
> Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> 
>> ---
>>   fs/hugetlbfs/inode.c | 33 +++++++++++----------------------
>>   1 file changed, 11 insertions(+), 22 deletions(-)
>>
>> diff --git a/fs/hugetlbfs/inode.c b/fs/hugetlbfs/inode.c
>> index c5a46d10afaa0..6ca1f6b45c1e5 100644
>> --- a/fs/hugetlbfs/inode.c
>> +++ b/fs/hugetlbfs/inode.c
>> @@ -198,31 +198,20 @@ hugetlb_get_unmapped_area(struct file *file, unsigned long addr,
>>   static size_t adjust_range_hwpoison(struct folio *folio, size_t offset,
>>   		size_t bytes)
>>   {
>> -	struct page *page;
>> -	size_t n = 0;
>> -	size_t res = 0;
>> -
>> -	/* First page to start the loop. */
>> -	page = folio_page(folio, offset / PAGE_SIZE);
>> -	offset %= PAGE_SIZE;
>> -	while (1) {
>> -		if (is_raw_hwpoison_page_in_hugepage(page))
>> -			break;
>> +	struct page *page = folio_page(folio, offset / PAGE_SIZE);
>> +	size_t safe_bytes;
>> +
>> +	if (is_raw_hwpoison_page_in_hugepage(page))
>> +		return 0;
>> +	/* Safe to read the remaining bytes in this page. */
>> +	safe_bytes = PAGE_SIZE - (offset % PAGE_SIZE);
>> +	page++;
>>
>> -		/* Safe to read n bytes without touching HWPOISON subpage. */
>> -		n = min(bytes, (size_t)PAGE_SIZE - offset);
>> -		res += n;
>> -		bytes -= n;
>> -		if (!bytes || !n)
>> +	for (; safe_bytes < bytes; safe_bytes += PAGE_SIZE, page++)
> 
> OK this is quite subtle - so if safe_bytes == bytes, this means we've confirmed
> that all requested bytes are safe.
> 
> So offset=0, bytes = 4096 would fail this (as safe_bytes == 4096).
> 
> Maybe worth putting something like:
> 
> 	/*
> 	 * Now we check page-by-page in the folio to see if any bytes we don't
> 	 * yet know to be safe are contained within posioned pages or not.
> 	 */
> 
> Above the loop. Or something like this.

"Check each remaining page as long as we are not done yet."

> 
>> +		if (is_raw_hwpoison_page_in_hugepage(page))
>>   			break;
>> -		offset += n;
>> -		if (offset == PAGE_SIZE) {
>> -			page++;
>> -			offset = 0;
>> -		}
>> -	}
>>
>> -	return res;
>> +	return min(safe_bytes, bytes);
> 
> Yeah given above analysis this seems correct.
> 
> You must have torn your hair out over this :)

I could resist the urge to clean that up, yes.

I'll also drop the "The implementation borrows the iteration logic from 
copy_page_to_iter*." part, because I suspect this comment no longer 
makes sense.

Thanks!

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f7f9f535-0bbe-413a-84e4-fcb17a502a40%40redhat.com.
