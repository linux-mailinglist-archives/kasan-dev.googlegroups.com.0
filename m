Return-Path: <kasan-dev+bncBC32535MUICBB55GT3CQMGQEQNHJ4HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id E5D94B30891
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 23:45:28 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-32515a033a6sf288363a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 14:45:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755812727; cv=pass;
        d=google.com; s=arc-20240605;
        b=k7YPGafv3bze9HKVHz8/o2B84oJfswyu9LlacyJi0aoxXJlDMf4aBT6gbRr7Ax1FQY
         IZn9hx6MTaL2Fk4JzpfGnFhsbOjqjD7FtOt5ROHlKQNLAjoTnsZC6M6tJyQ6PB8yAZUT
         ansppKF3Cav3FnKhy+8395ZEq7w/KrCMNNWia3/0La/VAJMHP4cRXxtQYd8z1/ppPYT6
         zpMW+f72zjyyER8M0+lq5+D6ptFDaNIU9TYSy71YqiOrXsYjdkIDDjrANQhLSyTKDKIM
         OgAw8peM507exbQ7Zif5S1r0fAW6zb8L3nsnfuKoraDvQaLJFbwr/o2cZC9LM1Ud8Uf0
         md9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:references:cc:to:from:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=7XzYsyPp6mwCLdW3qCX8S6CfBFvwoGtGYIG7X68faSE=;
        fh=TZKVrLknWOowy5XWM1Ivvj0GiW1WpbZkxLZMzPa8VwY=;
        b=Ypm8hXxgMaGs613eCEL8CfVstAT0rKx4JShhsKzOs64aw3J6TyQBypwpatZfKoxGiy
         4+LIHsmRRj8QtrkV/fVPPH5c2LQzhPdRSy6yIn3KFcf27l9sA+ei0ImMQ0ewn37iFjHq
         repYJP3dz1Ftu0CH8EjkJjgSfBcw5H34upWO0FfoOT5INc6T6xBx/iMw4O4asJDQlZsK
         krteQJT8Y7d5LHu0QEGgEP0EGoC5g28Lho3OC/HI5SxaXxUBRZhKCfiTX+LrnCaUKerD
         Xk4b8M3kdmKfDWpkKTJDeBI53lWKLOl+RcooByGkYcOjk4LKx4z8oUfyHL3KtuV5FSyU
         mMkg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dRqQIkhv;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755812727; x=1756417527; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:references:cc:to:from
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=7XzYsyPp6mwCLdW3qCX8S6CfBFvwoGtGYIG7X68faSE=;
        b=PQFBvLK5KSwT7AGqvFSZaE9P588Q8Y+097BmHKTKR9DInOg7E06aBjWNISoTTS0aY3
         /lILAftADOHsvCeLdnE0qfC+Kg9WIxYnkWKGaBiwGWAna/b8S6+OG/sFEYh94n6e1JQR
         qtIPocunVGo0w3DemA0PqRlwEBPYu+E1gevb/JY5ebIV8U++FPZMHmMIdo10/aIqsXZn
         ub7pnbV9ROwrUh+Wgm5Zmt4H6FgKT0y/vlYcl6KpLg8iNum+DlQxPxbph/83s2LGDr73
         ZHO5P2HMdZsDpoARczr8oKjk8Syvl/76ZeYBVNAMnsND1R4q6xV7/F6fRkM1DhkPaArG
         TJbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755812727; x=1756417527;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:references:cc:to:from
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=7XzYsyPp6mwCLdW3qCX8S6CfBFvwoGtGYIG7X68faSE=;
        b=Kq+IiBwkYNYGXlG9U4iZaWvor6OJ1jAEla+BkDQ8HWUme1M/XjDjYJ+nvdsbbkiSdt
         Xuf9QKskEXTvQsW3ERgeGt61uNZmTMbUn6etUJ0zQpjdZr6nGUDGsmay3zpH4R+pRitf
         x/3M2cI9iScOx1E1nRkR736uu6MjEYG4iS1XHACT5l+2PzYlJpYRP4zGqGCREe+n8xwo
         Xl5zreggAyl7ktpdVsxnplNfscgYVPg+RphnyMO6X/CjE16REsW28WNJI9OV/uvnRa/I
         IAHBKQZXFkqQ+LE6+gbNqB1Zkeix2RvM51zsBpEQJXIcakS153pwJdwIvPldmn4g++8k
         OJAQ==
X-Forwarded-Encrypted: i=2; AJvYcCWBpbHK9q/HueJLCS0Nbql/oYfYm7Zl2bKNgs+QEadgvlc2jpWPti+CqvoA5Ecc5si1H8929w==@lfdr.de
X-Gm-Message-State: AOJu0YxeipZLRD3lyDJtSCIet4iMVHIC1Ity54QpHa0OzTm8/AoWiGkX
	wqqwqsU216IUnghN94wnMXe91ev9kecKQGxKPlV42N33w3SEbKqbUPgW
X-Google-Smtp-Source: AGHT+IF8jxD3Cyym7uYwgMfYzMH/QErw3gxuK40mMiFQJchSYihuIPrMnmqCXsb57oWZ7RAwXHpfug==
X-Received: by 2002:a17:90a:ec84:b0:31e:e88b:ee0d with SMTP id 98e67ed59e1d1-32515e456c6mr1219948a91.9.1755812727427;
        Thu, 21 Aug 2025 14:45:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcRIbG8apfwLk5Fw6BttnlBiuG2zVAcX0fzqcMDS83NWQ==
Received: by 2002:a17:90b:3c11:b0:321:6ddc:3398 with SMTP id
 98e67ed59e1d1-324eb802e1als1695107a91.2.-pod-prod-05-us; Thu, 21 Aug 2025
 14:45:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW3Qif1t3/956QbnZY/EV2Rvz9MMnKIxBvB8YrVG6uH+rnlbpd18w9prijef6CMXIg92BF7xAyE97U=@googlegroups.com
X-Received: by 2002:a17:90b:2785:b0:31f:9114:ead8 with SMTP id 98e67ed59e1d1-32515e2d5a0mr1370719a91.6.1755812725848;
        Thu, 21 Aug 2025 14:45:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755812725; cv=none;
        d=google.com; s=arc-20240605;
        b=HZcC1wqMuuN8DV0AbmdXuaPzyzhRWwXlEJfcm7hEM0i8+Ema8nFrbJ9DxZAUeYrexW
         WCE5vFJ9VnVqr3n/wOW7XqutrUS4vLXKgopZh7wiuCe975vp5b7uv4RVvQvW/G+Xc9Uz
         p0WgJiEFgk9VqYc7GO2F2Gb6Wr8fBC/Fvnq9ek06Xtheif+fGbO0IPDiYfkYgPK7jhmj
         zebQej0n4kXFeoN1++7pWad4Bg1PuvuuNDqnM8F+6SUA9aN7XtCPFRKM2PDneyL3Yt2l
         GppaJQf4SfK2OHIbGgGpU0r3zWUyhhntdFVC8qgQt49H+eFD733+P43sTUV5azoAU7G7
         lkhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :references:cc:to:from:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=xgU+Z5k4KPqEraeKDWCOzJcpc8HGVmW4oZxLQRmx6Ws=;
        fh=XIXEdbiqNuy3IKmmbqujaBUin/FPfSYefoOCl1pz8As=;
        b=TcQFtnzz/m921JmYdbzsf09Ap23rqfkRi0TdIvexIxEwV3hAIyBSY0Fzo3/t+CS4bU
         kT5n7m9VVhAaUTR82Bmh0oMnAVOdSgjZah0ReGN/GphFA6hDLAIfdWAiCAw9lmrDANIs
         224UEjwgAeFAw9y3el/+aBlMVK8Ij8xkbz5+1WX/VyOVHbDxyXDyUziWoLI8j5h+rwL6
         7F6W1ei+vSQBRINnx9OE0yEtd1W9xTAbiN849genIPiIw5l5boi27X3aNKYlCP9WWuwG
         E5sCX5VeHx364uMRmGzTjpDPy7itabJ1dFAtC2y7SuCcBTiY9GL9Sc0Q7co0Cq8QWNH9
         ymWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dRqQIkhv;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-325138fbac6si47256a91.2.2025.08.21.14.45.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 14:45:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f72.google.com (mail-wr1-f72.google.com
 [209.85.221.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-349-qMDUufH3N_yDlQvARGvTsQ-1; Thu, 21 Aug 2025 17:45:23 -0400
X-MC-Unique: qMDUufH3N_yDlQvARGvTsQ-1
X-Mimecast-MFC-AGG-ID: qMDUufH3N_yDlQvARGvTsQ_1755812722
Received: by mail-wr1-f72.google.com with SMTP id ffacd0b85a97d-3b9e4117542so652275f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 14:45:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUhVls0UBT0z71mw22No55oH8nrv5a+Zirzu6qJ4XeaN3eyrs2ZWy3338gYeHwjzs2G5lbhx+sOAgE=@googlegroups.com
X-Gm-Gg: ASbGncsQ143bLhgNUKMO4/w6pmVMieys0qnc1ZgkEo8MWY3zC1r3V0E3dHq4ONJo0BP
	jmxKt9FmGA6llFGEAhNvHcbbzfcdUHuHpAX/vlmx5QM3+feCzqRz6yqrIKXzkIBnk8OPPeQCAg/
	lRTVlDsO1Zxra1bIL4wc1Ovn4Z6I3tQFtgElVL79ZZ8u0iA+9Ra0VXGcb/MOABUhyop8T9PYHOP
	JA8eEhMiJx0cFYtAvxZ03ZOj5cUlk54A83/XEU11kt9qiONOJEOe6TdyCNS6aJf6Ckzf28ElAQB
	ytdrS8qI3/AehOtCnJPwi3NUxumZUhaszhQOSQllBMqY3J++2Gjx+piTIl2y6KuQlwQgKvAoISi
	yLNJzYWGBa1l54JR/uO5jU9r9k+I0Du+pJY8A0TVhx07pLGH7RC1Q6P+jXiyJbQ==
X-Received: by 2002:a05:6000:2902:b0:3b8:f925:8d4 with SMTP id ffacd0b85a97d-3c5db2da00amr300079f8f.26.1755812721893;
        Thu, 21 Aug 2025 14:45:21 -0700 (PDT)
X-Received: by 2002:a05:6000:2902:b0:3b8:f925:8d4 with SMTP id ffacd0b85a97d-3c5db2da00amr300045f8f.26.1755812721421;
        Thu, 21 Aug 2025 14:45:21 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f26:ba00:803:6ec5:9918:6fd? (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b4e25da97sm22067085e9.1.2025.08.21.14.45.19
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 14:45:20 -0700 (PDT)
Message-ID: <b09b7ef4-5b06-4bb8-9be3-1194e3904c92@redhat.com>
Date: Thu, 21 Aug 2025 23:45:18 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 33/35] kfence: drop nth_page() usage
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, Brendan Jackman <jackmanb@google.com>,
 Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
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
 Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>,
 Mike Rapoport <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
 Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
 Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-34-david@redhat.com>
 <1a13a5cb-4312-4c01-827b-fa8a029df0f1@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <1a13a5cb-4312-4c01-827b-fa8a029df0f1@redhat.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: NdpFA4OCqb-aIqfeE7pnmQud_KJf0Ch9Vd3y5FSnwyU_1755812722
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=dRqQIkhv;
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

On 21.08.25 22:32, David Hildenbrand wrote:
> On 21.08.25 22:06, David Hildenbrand wrote:
>> We want to get rid of nth_page(), and kfence init code is the last user.
>>
>> Unfortunately, we might actually walk a PFN range where the pages are
>> not contiguous, because we might be allocating an area from memblock
>> that could span memory sections in problematic kernel configs (SPARSEMEM
>> without SPARSEMEM_VMEMMAP).
>>
>> We could check whether the page range is contiguous
>> using page_range_contiguous() and failing kfence init, or making kfence
>> incompatible these problemtic kernel configs.
>>
>> Let's keep it simple and simply use pfn_to_page() by iterating PFNs.
>>
> 
> Fortunately this series is RFC due to lack of detailed testing :P
> 
> Something gives me a NULL-pointer pointer here (maybe the virt_to_phys()).
> 
> Will look into that tomorrow.

Okay, easy: relying on i but not updating it /me facepalm

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b09b7ef4-5b06-4bb8-9be3-1194e3904c92%40redhat.com.
