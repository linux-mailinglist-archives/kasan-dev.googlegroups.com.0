Return-Path: <kasan-dev+bncBC32535MUICBBQ5NY3CQMGQESLTKRCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 01412B3BA97
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 14:02:13 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-315babce805sf793265fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 05:02:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756468931; cv=pass;
        d=google.com; s=arc-20240605;
        b=gkDwTrAdg9FNvRztzvm/9KiC5YKBCHyFO1JCi+0Ja3Qi0yqyrYcCno/jiwh5DVYi3I
         zInpEjp3LnIHobNxwRJoqLEIH4XltMWmrIiOV1Uy9u8HIhj0tqPkrqK/ndK7JpKu72b1
         VIdNZlf1upOgy5ha8TMaQz25s//CfBPYzwp9Wpg3pxGFf4JoUE7rjTD4eJYuek1s7QUl
         HWbCYU8yYgNyPkqoMYUk1bDwK+89MmYCm7BqXqBo2+MnM08xb3Qkp77o9sI7Ng05LXsl
         9IOynZCxbL46xusgN1ZsWlWE4PK4Y4HErFRXeRs2bQUDr9Qfkfe6xHhNAePvB6ZckCqq
         ob8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=Mi0XhxuMHsI66qcK6s2aQ2uo9+u3QnKPLT7RAZEq/F4=;
        fh=3Qe/VY7LpdBf0JWBH/C+mQh5IDQhI4BUZGGLBJGlHJQ=;
        b=fmxJLVRRaw5kBgJyhhJJVVkqnvE8v33EtDXzC7+kK5v8QsGEdlIvZkfYmx5Y5+SLE/
         Biyd8cYjV7kM/A+yvhkcPFn8WrQGCYh6Fg2kvoDDO3J7YbCsSz9+RFECYm7+CzlZLnSc
         0bHs+UsTv6uROUux2BFRtUEbLtr3BFAQ0lycKHc5WtKssPmtn0uSMIREnOYNSKHXP+vy
         ROHUgqroGginEXZT7Ngg37zytKhtGajajSjYjHPnU6kBrFJqYg7ogsbKZLptpk8FVA95
         /vXJ2q5kHubL717AO4GVUCex6lyLELNFr2X9KppENOXHIiLUdyYsBT3LyBcRsAfqq89e
         ZOTA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UYXmXfHF;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756468931; x=1757073731; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Mi0XhxuMHsI66qcK6s2aQ2uo9+u3QnKPLT7RAZEq/F4=;
        b=coJ4KQzEYTRk7j7555LOVpaWxRNLDM4aH3AgOfgUPk/gCPF4Cel+RgpqFZ/X4Opw/+
         lQ9HSDq/+c+8rOZ85pyYvV69E3Q3Z8FlNuxpvCBT3xp8s4GJ8K77UnqkkKbMwfF7a5rA
         8GhzG4QXr08dmaOf0dpOWnTIHmi7LKVM6+h0WWrQGf0Qn5AfkghAv9tNvgbjSs0SZ+Ah
         5N8esOtDJzmf8vgfkUm9Tqkcxvhc1b476l4symYHQFE9sZlnqxyVEytt7AarBSRZDQ1M
         5+b362PIhEtmwJ9KAUOopneGa2w9s/kNz2M4e1/ZvZ7z6+h3tu71FEFqiSUxdpVZZXWo
         k6Pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756468931; x=1757073731;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Mi0XhxuMHsI66qcK6s2aQ2uo9+u3QnKPLT7RAZEq/F4=;
        b=ZnHsEl72wT0WL4iV+hOfVK69/UOD8qQE7i/C3hCGuvojEwVD8Hxe1E19EjJszJyhZI
         PQNWUaeLAV69Oq/hBStmDXryWYtIe3t1AlShwGBUWlEHbPu1WEJ7cyIk5U0lNME5X++k
         ecwOh8HUZC2xYWDz3z/1kuaYSZDjcBouzv5Nr3gRFixYqSib5A5vm2XDjHRp5Qoyrkar
         RD/g2YZCeL62eIyc3UhY7LwoyGaLjOEOD+zaBB1Dn4WEniYlHSRLudNJkKP1z73SOnhH
         O08X3/ZPNdnl5zbs7RCXe054M9ywmr8FJAGWw4SAZ21tc9S85l6XBdq6Q9it2OBVUhhL
         5keA==
X-Forwarded-Encrypted: i=2; AJvYcCV6xpsvqPFzZSMeFKu4FqVcfB4lah86deijkKGpWlbNVBB75gRIZ2snTkkEKVu1f48+28q0qw==@lfdr.de
X-Gm-Message-State: AOJu0Yyw20Lf0BTj1s/GZytTjSQPGaJhICD5qOeDwzn2UblynTn3mi9p
	gV9Axk0yUUykZzLP5HguTO34sunlvsTXR6fQGHnSi0+dJctsVpjHlKth
X-Google-Smtp-Source: AGHT+IFT2SQ5OQ2lfkCEqT+x0wGGh6RYBD6nYLLhH9oBsmhMDK+tvVFIh+8lH7zm8xbp/dcl5LnwCQ==
X-Received: by 2002:a05:6870:aa08:b0:30b:ca29:cf8d with SMTP id 586e51a60fabf-314dced5eacmr13762443fac.35.1756468931404;
        Fri, 29 Aug 2025 05:02:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfB1pqJ9FTF0fbtXKAVXOSKNnLCwiVWgD8/klwY6snbkQ==
Received: by 2002:a05:6871:a1f9:b0:30b:af41:d3a3 with SMTP id
 586e51a60fabf-31595ff10e8ls571506fac.1.-pod-prod-09-us; Fri, 29 Aug 2025
 05:02:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWNlqDf7faKNKgNAzbqW4PpgJSZy3x4luiczMtbCWFN93lYEKAAfLgiNQv7MgI/4I27l18yhRwMfNg=@googlegroups.com
X-Received: by 2002:a05:6871:538c:b0:314:9684:fe0f with SMTP id 586e51a60fabf-314dcf189f0mr11938368fac.42.1756468930401;
        Fri, 29 Aug 2025 05:02:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756468930; cv=none;
        d=google.com; s=arc-20240605;
        b=Jr/9ga+NL0EOxYY1z+a4pnFODEpBeuDy89zzdEuXuAKXCoD13uj0Q8t7q78bfv0rz0
         7pzIwYFSzZ1D4XgCv7E+PMo6iB6ToQH/Z7R5UFJ0SswvT+qBECYiBGxzFfvkZKI1ZKfB
         LRTf9uAfNvLR/dutDlXkHx9StBBkcVhrqBkzpA1SKu88wGaJJyINo+5mwfFZy2nieWrm
         sC+1HvlvZ0EEy3wAaHKqt+FFrtlVATd5PtOVPaMVUKJgsL8IpIrY+6kN+TWzZCU24c27
         10eWwOX9zQEloufwxkrv/VGhq24Ub2PDYDPThCuCp+/QNXPYvhVet8ayjXvbamm/yt2o
         ZuGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=ZYQANwx9dP2TniNNzJzejSk0KLOlcIb4cHUahyjX99U=;
        fh=9TcPyssQd0eVnCg+8ASuAbjCtzj8DgqZuanR+oGS26A=;
        b=KsECKh1+1v+Y6LGi5u8IKCJfB6JbHhpcMvpU/0aFDqhCCXkRRCBQxnwX5JZjpN/1QY
         NQOZleZe3ghdb0D3We73gOIKu50ehCXmklhZLmrzDuA2WiI5c8N85oVzTGXTZSoQu0Xb
         NVGu3FjPZYsq3SzVaJa5FiOBSla50negf6lXaB8U8IrBe6ret1y0rxlOGYS1s2Nr0gg2
         UQKCxKT7JtYMhyH4+upyup1epJT6jNZCux8obutD6bECewqctJRUrTP+PJN658LCu0Ok
         vK11WYxLsR0T+Qeh4Ugv+oiJltTfw37NcvAqLE5G/gsuUUIDu8MyuiwweeYdFGuh+wB1
         6Kow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=UYXmXfHF;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-315afdefa46si116280fac.3.2025.08.29.05.02.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 05:02:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com
 [209.85.221.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-457-8YXzEoI8Mx6SiGKXsi15_w-1; Fri, 29 Aug 2025 08:02:08 -0400
X-MC-Unique: 8YXzEoI8Mx6SiGKXsi15_w-1
X-Mimecast-MFC-AGG-ID: 8YXzEoI8Mx6SiGKXsi15_w_1756468927
Received: by mail-wr1-f71.google.com with SMTP id ffacd0b85a97d-3cf12498799so477230f8f.2
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 05:02:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXmiIpcEiVwr0Wv1kYvg668xxWKeY96rpHqinF40jbasJen4uriox8OGQtrhTwpfDGuaxqc2xXmNV8=@googlegroups.com
X-Gm-Gg: ASbGncsBd2CE/3wyfgXTIB8nYyI7e8aZba5IPc3zYxfUGlLbZsWHW8YFnrWTIWvfcxd
	HUhzlf1cNbdFgDJGVLAJKbytetkzGkvxnEAlWaxR8l8ou6H1/1AehXSEY5ZWAqqUisu5m2yPaRe
	KTkiFr1DNo6FrLfNc9WV/5KLwAFhX+VK639sByqNff5rVgo8tpNhCp5PbcBJIaiIigwvoC2Zy5g
	z0aBN3/18rb+rxJ8LG/Lu9puy8w/3qwL64eHXkGjAILpwvbFtovJLJf72YqDpnWODK52WJG88RD
	kv6cYUVECQP5MDJFhE9oV4jOFl8275JdMdObO4IkJ/YMnNOW3BhpATV2w170owHKcGFjopEb/N1
	btL213QBaYlWel9EIZ2f0+5DTplzYx082z7vUXDaoFrgvDRjWe2btal8XRyk8sbo=
X-Received: by 2002:a5d:64ce:0:b0:3b7:7377:84c5 with SMTP id ffacd0b85a97d-3c5d7cb4888mr17563656f8f.0.1756468927148;
        Fri, 29 Aug 2025 05:02:07 -0700 (PDT)
X-Received: by 2002:a5d:64ce:0:b0:3b7:7377:84c5 with SMTP id ffacd0b85a97d-3c5d7cb4888mr17563581f8f.0.1756468926590;
        Fri, 29 Aug 2025 05:02:06 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1d:100:4f8e:bb13:c3c7:f854? (p200300d82f1d01004f8ebb13c3c7f854.dip0.t-ipconnect.de. [2003:d8:2f1d:100:4f8e:bb13:c3c7:f854])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cf33fb96ecsm3144067f8f.45.2025.08.29.05.02.02
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 05:02:06 -0700 (PDT)
Message-ID: <d2bc788e-abea-4453-86fa-daa68e280d52@redhat.com>
Date: Fri, 29 Aug 2025 14:02:02 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 15/36] fs: hugetlbfs: remove nth_page() usage within
 folio in adjust_range_hwpoison()
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
 <20250827220141.262669-16-david@redhat.com>
 <1d74a0e2-51ff-462f-8f3c-75639fd21221@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <1d74a0e2-51ff-462f-8f3c-75639fd21221@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: E8DNFWgu9KelqiR0B7LBK_R0yb4YCl4m7B95KYmCHxA_1756468927
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=UYXmXfHF;
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

On 28.08.25 17:45, Lorenzo Stoakes wrote:
> On Thu, Aug 28, 2025 at 12:01:19AM +0200, David Hildenbrand wrote:
>> The nth_page() is not really required anymore, so let's remove it.
>> While at it, cleanup and simplify the code a bit.
> 
> Hm Not sure which bit is the cleanup? Was there meant to be more here or?

Thanks, leftover from the pre-split of this patch!

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d2bc788e-abea-4453-86fa-daa68e280d52%40redhat.com.
