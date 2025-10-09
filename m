Return-Path: <kasan-dev+bncBC32535MUICBBMOFTXDQMGQEXLNFX6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id B9D92BC7AD5
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 09:22:27 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-643abf559edsf1020643eaf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 00:22:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759994546; cv=pass;
        d=google.com; s=arc-20240605;
        b=NnKDx/HBxSmXDeSpruW2K/rntTaSNTWDRN6QltJJQFgqgcvctggxYs18vcgLZEnMH2
         9Y9UB6yyNwgBdg7tMgsoNsEAaaAa5L5+J/MbAG5SJ1bhohK2gDxBDXKB8854RAKN3mYI
         t/VA1QGYNMwZkIGXEVnyVI0rcsubmRrs+yb5JeWEjqoxIwWlSjBf2rjjpGoj6zV6XhA4
         YcsnReDm7OYAQFOh5UOerJfNxmHoUqe+Q36ownn7qdWE1q6m+DVZD/FvtVrzmeSSZJEe
         5msYHkfCVYINrpprebstEhUtnwhMS0Ss8RdvzO0xeg3c34/5hBk5nWEFU0u/qO3cVoQ4
         m5IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=4BHTBAoDXaIWDOtAgu1wbzQrOYEBC4XhwBLtVP24Ins=;
        fh=b/87t63/e1z8xitvzMKr02bL8tsi5+keUSs1SioxTkY=;
        b=jEIaTZinq4bfLMxKPbCwz4EWD0WKATtMnn3pwKDijoRqZ+FvGzCmIZxTFTQV/03IQ7
         g7EvJzWZI2BX0069ZHo5+lcjde290884TVBdw9JzuPkf8sx7JQwzFv60cGbOnZLI3VcD
         zEoSu9OUHktVCX79Tj5auoRNgdULe7rvXjmopQR/YxNYVpV6fPiembLNZQxF0nedekZ5
         +04SzJIRkoC+SX7170HuPDywnLkyI7mjiZIyzkpTftBevzAwFE5LkWb9iAiOR3tlwcbV
         4FxYRIen1Fjo2ZMtPvJlytrUxwfXaCXs9wjRa5DfUfqPCp1stuTZZ6wHP6Zhrvr/tyo8
         eiUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fcjEUCxZ;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759994546; x=1760599346; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=4BHTBAoDXaIWDOtAgu1wbzQrOYEBC4XhwBLtVP24Ins=;
        b=oidtOxbx/TvdVpZZvn6GwrkphbU/C0peWZihAqIHLiLF+AqtQuy2Vy+iupxiGjeRqw
         LGI5IPHHlW11zt6P215ej1E3I9GcE6AzvuSgHFv2XvrKEwPeHxrjdm0Xbx4N+g89/0Dx
         PuAXXDselXNRwDEEzjFn83UXWMmwNYBzDde8EhqeZ3d08ng3GiDSV2jDPCwigGt+2hnY
         pKG/2q9jSbveilUi6I0IrDlIJ8S4WuHyVMm5VZ+B753piCUGrAdyFNxujaE7+ya+adQl
         d0p+AZ5RbD+6PUfJvMlTapNIpdSoHJlGy0RlTZ/+lLvu7pYnhqOKYduoEw/W4gTs+5UR
         oUkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759994546; x=1760599346;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4BHTBAoDXaIWDOtAgu1wbzQrOYEBC4XhwBLtVP24Ins=;
        b=N+vJRj8IoCX3+eEH55uoJQWzcbt7q8Pd/78vaXJPsbWWkMpahAwXzGv4S6p9+YcsSG
         8MA1xD4mJCyE0It0OspKj3Ycg3XdqYx4P3eUo90YgihGmgivTu9966o3SHrrBpXASEKW
         UrNAXXS+xCpnWACI0tpfSSBUZBuq1BrtVFZDO1gJmn2oWGY71RC9DhU2qwj0cOb/U3x/
         DRcQClSNAXxP33lgPsEl7+1jxqH9ywZwUoPKz+1vZRtKgLAW1bsU+/CLYeLbveTox1bG
         OBcSDtmwRpzJqtAWw66cqAjnmkcPLQSJk12SPGl41Z0QF0BGvjKXRq+f8OguuJ9XUsce
         RV4Q==
X-Forwarded-Encrypted: i=2; AJvYcCV0yq1HNDZWSKssEWo/li5rlpKAkGEBVNpu+iM62bfG1Ig/ZDR7xtlWREncubHYU1jQUDRjRA==@lfdr.de
X-Gm-Message-State: AOJu0YytshcEs5VVVUSLH4zHPk0MQau5CIKDsNM7Ztq9JoXOxiVm6c3N
	hHwKr+7M737SOqKCNizfsJoEqA6v4bToDc/tQt9a7EtCyacLk+j7L4Ll
X-Google-Smtp-Source: AGHT+IHhkw40j7cuXHFdTmJByK5tRq3cW5Pdc4JPgmbrk3yDWJ6GwO7cJk42TrToSD4x3eLrkPfE5A==
X-Received: by 2002:a05:6820:839b:b0:64e:6fdd:165d with SMTP id 006d021491bc7-64fffe369bdmr2856846eaf.3.1759994546137;
        Thu, 09 Oct 2025 00:22:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd75AP7FxWWfH68JB7TfmIJjvI4IRB9DV2vfDNJEGowySQ=="
Received: by 2002:a05:6820:640c:b0:62e:5dca:2198 with SMTP id
 006d021491bc7-6500ee09eb5ls125134eaf.1.-pod-prod-01-us; Thu, 09 Oct 2025
 00:22:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVQityCrxpkRtm2cSCJAn+fkJxqaVJnK9hTP1w7mfe3teoWL0Ax8Ouj2gtRPTVFH6YBD0mfSi0eqgA=@googlegroups.com
X-Received: by 2002:a05:6830:83bc:b0:7ae:dbc5:4705 with SMTP id 46e09a7af769-7c0df7c2f7emr3933631a34.27.1759994544823;
        Thu, 09 Oct 2025 00:22:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759994544; cv=none;
        d=google.com; s=arc-20240605;
        b=Dbvgs8w4CnHoqOGamJnW/7orO4UNAblzOABDxThJ7MfFp1BlfwGNhG9uNdXCuyzxxX
         UaYETCD8Ps8B480D4IBRWRgnh7/47GtUlk6BF1rKaZycFNfO0ZOOMjRX8bAysUL9oMbB
         JISMhljdDTZEkMyxlGvDnC3NI2BG3hwM82y3QWLCKBodUDO27HRSLxxAtO2FMkbHowU0
         zUpQy9kB6dZcLvVzOD4SijcCP4dSCotZRGohB+/si6oKF+QbfXCXq1+WdR04GUHfhNcR
         DLX0nzpZ30DKhmbazF5TGq/hIbqywBOUElmnn5x0IfPWgJEH1NhxiARoXYM8NmguYGt5
         1CrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=NR0GPPrQth8s1EL9fLV4+qP3WUCAWdzIUfVSZ9j+y5w=;
        fh=kNlWBLFrz8n+lSFtE6B9mZwXwg//3yq/JKUYYKv+QfA=;
        b=ioC7YKzNxp7AsEWQVEczQpCYDLhGdAAy5US2Mn8z/KsfePcVYzrsMC4TuyX7YXiEYE
         mK00qnW+ZJj3GIooVHJxhtfmNkU1kUDjnEg8qorEv8fv3b0O3d9Lb80Yn2cSQu0lbrGT
         bwDn/32AivfxzjDkjNc98120kWVfCR693gx1OC00MEuekDcqxdIAGGsx/AeQJi7saVUo
         Np5M8SM9UO0Kj7I9nHlSNsDlOXdhlmoaMFr4nwfHFV0MrhGRsAgXbIQVDC+3ocyB8O85
         MyreFggezVCPFJjSl5TUCZdRltzY5T0Ph67AJrZWB17+TQIZ/YCjumK0VlgWq7uoPQrq
         0AaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fcjEUCxZ;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7c06be0892asi62482a34.5.2025.10.09.00.22.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 00:22:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com
 [209.85.221.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-474-Etj_ftfROGG7s6y2ZIkmrg-1; Thu, 09 Oct 2025 03:22:22 -0400
X-MC-Unique: Etj_ftfROGG7s6y2ZIkmrg-1
X-Mimecast-MFC-AGG-ID: Etj_ftfROGG7s6y2ZIkmrg_1759994541
Received: by mail-wr1-f71.google.com with SMTP id ffacd0b85a97d-3ed9557f976so531313f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 00:22:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXWJkZE1htL15kYKg25IYpldFp8fOslUiKk5l1+t828Mg7PHd1yjHwZKjE4aSDocWbfFpXLwryethE=@googlegroups.com
X-Gm-Gg: ASbGncvGceIjWaXWexkuXjcrq0e3+KGCiwDBilRMmx+0hVZBwyds23BhqitFfk/6ogY
	SSKZL3RPdnza2IMY8/olHQYgIq8vNnXyjtiXiBVnH+iIJwmjvS4QlXKy3XpygeSIErS0cChVeDw
	DysS+be3DZ/VAV6iPpf4uz3O8LMXm/VF3GihamLjOW9czgLOmGA8yjpOdzd7WDqdR24zTveXKyU
	TP9dzyeCaIvo8ZKxy1M3wMgjYwPlBX3EKgDeZfLLiLuw/QEKJUMt8X8QdKGqZobblcEYkmfDE4p
	pidnIOHOIU8esLyIv1zXtAvyqSWBD5A99Vcq0oN12QQy1kPTK4WAeQgFUv5IqUuIp9Awzlzwofe
	zWxnhwL/P
X-Received: by 2002:a5d:5f84:0:b0:3ee:1578:3181 with SMTP id ffacd0b85a97d-4266e8de444mr4275645f8f.49.1759994540848;
        Thu, 09 Oct 2025 00:22:20 -0700 (PDT)
X-Received: by 2002:a5d:5f84:0:b0:3ee:1578:3181 with SMTP id ffacd0b85a97d-4266e8de444mr4275568f8f.49.1759994540323;
        Thu, 09 Oct 2025 00:22:20 -0700 (PDT)
Received: from [192.168.3.141] (tmo-083-189.customers.d1-online.com. [80.187.83.189])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-46fa9d62890sm68237045e9.14.2025.10.09.00.22.15
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 00:22:19 -0700 (PDT)
Message-ID: <d3fc12d4-0b59-4b1f-bb5c-13189a01e13d@redhat.com>
Date: Thu, 9 Oct 2025 09:22:14 +0200
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
In-Reply-To: <3e043453-3f27-48ad-b987-cc39f523060a@csgroup.eu>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: T6WsNAsenJqt4ieeAi9tNOi-bsOaunUAbo3gWZchC0E_1759994541
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=fcjEUCxZ;
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

On 09.10.25 09:14, Christophe Leroy wrote:
> Hi David,
>=20
> Le 01/09/2025 =C3=A0 17:03, David Hildenbrand a =C3=A9crit=C2=A0:
>> Let's check that no hstate that corresponds to an unreasonable folio siz=
e
>> is registered by an architecture. If we were to succeed registering, we
>> could later try allocating an unsupported gigantic folio size.
>>
>> Further, let's add a BUILD_BUG_ON() for checking that HUGETLB_PAGE_ORDER
>> is sane at build time. As HUGETLB_PAGE_ORDER is dynamic on powerpc, we h=
ave
>> to use a BUILD_BUG_ON_INVALID() to make it compile.
>>
>> No existing kernel configuration should be able to trigger this check:
>> either SPARSEMEM without SPARSEMEM_VMEMMAP cannot be configured or
>> gigantic folios will not exceed a memory section (the case on sparse).
>>
>> Reviewed-by: Zi Yan <ziy@nvidia.com>
>> Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
>> Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>
>> Signed-off-by: David Hildenbrand <david@redhat.com>
>=20
> I get following warning on powerpc with linus tree, bisected to commit
> 7b4f21f5e038 ("mm/hugetlb: check for unreasonable folio sizes when
> registering hstate")

Do you have the kernel config around? Is it 32bit?

That would be helpful.

[...]

>> ---
>>    mm/hugetlb.c | 2 ++
>>    1 file changed, 2 insertions(+)
>>
>> diff --git a/mm/hugetlb.c b/mm/hugetlb.c
>> index 1e777cc51ad04..d3542e92a712e 100644
>> --- a/mm/hugetlb.c
>> +++ b/mm/hugetlb.c
>> @@ -4657,6 +4657,7 @@ static int __init hugetlb_init(void)
>>   =20
>>    	BUILD_BUG_ON(sizeof_field(struct page, private) * BITS_PER_BYTE <
>>    			__NR_HPAGEFLAGS);
>> +	BUILD_BUG_ON_INVALID(HUGETLB_PAGE_ORDER > MAX_FOLIO_ORDER);
>>   =20
>>    	if (!hugepages_supported()) {
>>    		if (hugetlb_max_hstate || default_hstate_max_huge_pages)
>> @@ -4740,6 +4741,7 @@ void __init hugetlb_add_hstate(unsigned int order)
>>    	}
>>    	BUG_ON(hugetlb_max_hstate >=3D HUGE_MAX_HSTATE);
>>    	BUG_ON(order < order_base_2(__NR_USED_SUBPAGE));
>> +	WARN_ON(order > MAX_FOLIO_ORDER);
>>    	h =3D &hstates[hugetlb_max_hstate++];
>>    	__mutex_init(&h->resize_lock, "resize mutex", &h->resize_key);
>>    	h->order =3D order;

We end up registering hugetlb folios that are bigger than=20
MAX_FOLIO_ORDER. So we have to figure out how a config can trigger that=20
(and if we have to support that).

--=20
Cheers

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d=
3fc12d4-0b59-4b1f-bb5c-13189a01e13d%40redhat.com.
