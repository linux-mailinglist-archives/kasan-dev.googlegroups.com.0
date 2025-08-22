Return-Path: <kasan-dev+bncBC32535MUICBBZPPUHCQMGQEOL7NVZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 07E4DB31A79
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 16:00:07 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4b109c7e901sf47312111cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 07:00:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755871205; cv=pass;
        d=google.com; s=arc-20240605;
        b=QKOxbeO9J7TQFQK5U6JSPZIlkHFWXLxbFzl8mMcvuHTHQftj8mu3VS45MOGLgNYu3C
         gOvG4uSFMrbelbzOy2UfXgnKzoL+r3Y3P/ikKa1cvY16T7h9toQmsuPj84tdGgM2vALV
         6J2X6j8NwGxmrxpjWrHJOdk9Jrf7GcVWV3OnF0KJRNqRm13HmJWS5B0y/z1/kevqbe9n
         njh/X7kbKAYNq9597U0AmdtaYny8TOh9zcAL+sRmC+Q+0/RiDaicZ2mGBI7wJ2Y4ZL6n
         Cglh/pN3jLmwabkU3CxtRnNEs+qyGViaenLJFL3GoKG6Y9Q6mnJyALHi2yDkzFN/2X1u
         XepQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=tla5/4XF5YAVWRrtkyMPhr3Gz/GJTdj9wknpsJFdEO0=;
        fh=V3AIdiAr3+D/bS4BKPGj84T+9w0KtQcsrCpZD4kHOJU=;
        b=At2W1k24Gp6+TDJMGLuJMn59Qgs/w4S+rvkPqkmPaGdUlXirrR0b0328ZlCfNy+95T
         cUXDqOmYUgATPJDkWjosdX2Nt/BPN4FATdomJnEN8pcX+4xtIj8xXrCxfcWGmyFMAyCc
         9zYTH04pwygQNiaY3r6g0aiJnaGj3OS2wfmOVd9vuqYehp5TFEeayUuNbnC6eiKronc1
         c68/GxjCtNg2Pyi/4pmbXiJKwsDT/+7PGs2wtjQAj0dxmkchjISqVtyi4CfFP6XpwxVu
         +FsMM/sEMzW4bLcjYh2p8RPn3Fq0mc2XXQwYZqicW6KnlbIVleaHy8zJhOd/iFC6qIFO
         vmlw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=S2RDm1yB;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755871205; x=1756476005; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=tla5/4XF5YAVWRrtkyMPhr3Gz/GJTdj9wknpsJFdEO0=;
        b=cBGQaSGUp0Ydx3XxZfSQHxSGuwkLkQvqT8Ja3QAsxzeUtC/pkcmc3da1E8OKFJjSy8
         CtjxKGcSIeGEJLIACA6JF0P0A/3+XpH/aVP/lq7tGugXhqB/hnsqiMHvqzTJ5B2v0Osx
         M6YGCJFkPSN6GJVQQ5LlbI2P2e0zznekSGfAveaNa3hjWf4PIwsFIK+sUnQVbbqc9mAe
         IJ4anIE8o+E6rPukQIdIKI/GL8sb2dsbKtzxZCoqu9fv10AEkCfaJN3oDcPHYMc6y6Vh
         /oY05lwPRDIvVHmj5XT0RBjq4TYfWpXUka7EgyEn7zYid2CIixsOyxlXyOKZbprE+Un+
         6FCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755871205; x=1756476005;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=tla5/4XF5YAVWRrtkyMPhr3Gz/GJTdj9wknpsJFdEO0=;
        b=tHRnNV8/H/Cossg3nOIoF7XDnJc3PqKkAn5bgdQodNya5WhOXP+9cMKUouRBYN4vdY
         VGhxfzd0EG9IqQB6689KTpjWm7dKQ5tcf2/pNGzEhgVBE7YRQ9CgZli/YJbblkTUsDTE
         N+UbdT+waMCslC0uGcc/+0k1z4lNcvuzAz7czb7f2jQJp83x0Us6FV8T/jxE1/kMQlwC
         BiXckjbf/OEu/5YO8lqJS3AWQiFkLmHKSfbUHjQ5+JxiHA9rRVIEm7IaUWX08KZXrmkO
         Kqp+G08n0dA4vMQfBe3AKcAIi7HPxo8m7mo0CcLE8/6zjxfrayh8lwYE/LYiAoEeabA8
         u2yw==
X-Forwarded-Encrypted: i=2; AJvYcCVjw1JJCeUtU0FtG+5TCILvuTgBXsxVrutW/HqMlX6iizsm9KtmsqmPuMO1rFw5+z8z75VTwQ==@lfdr.de
X-Gm-Message-State: AOJu0YwYuz51/6+5jwOoZLOdV57DlngBIwrfO3l+5EpeCEWvTsVnbNaO
	6rN2ZeqbnW9TmOd8LqeuHhCMJkzftEPOsczfZ8NguHG7SDe9F3fIFA+D
X-Google-Smtp-Source: AGHT+IH7+Sm6HPWsS1VZ6vNjZsepwN1Ctr/+eBRDM3Pte81C4sKFad45P40gxzMHPswF9Cx7cpWTDQ==
X-Received: by 2002:ac8:5810:0:b0:4b2:89c9:1552 with SMTP id d75a77b69052e-4b2aaa57116mr34552411cf.8.1755871205256;
        Fri, 22 Aug 2025 07:00:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcwFfEh0lPXPJLCLgDz0lX+UnLGEdYwVHA5KEqlSZGaLA==
Received: by 2002:a05:622a:1445:b0:4b0:7bac:ac35 with SMTP id
 d75a77b69052e-4b29daa4c0als35481641cf.1.-pod-prod-05-us; Fri, 22 Aug 2025
 07:00:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW7932sUbn/zvA4Q+0tzpw8k77qURkgKHUmQPCrADZGOvQEcflrHe+JL8g0s7xYd/2kyiYSyOdJZIw=@googlegroups.com
X-Received: by 2002:a05:6122:21a0:b0:53c:6d68:1cc8 with SMTP id 71dfb90a1353d-53c8a40bab4mr867925e0c.14.1755871204195;
        Fri, 22 Aug 2025 07:00:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755871204; cv=none;
        d=google.com; s=arc-20240605;
        b=MyWa+FSoSph93P4CH/oLuwbWp6gWvPrB76GK0zPbdKA+jLU7a4RzEQn6OqUpPSnjOH
         DihmKyTEUK70GXRYEscg2aZaMlgwIxurJvdLx8Xn5O5hNKCxfGVh0IXfjUNF9Uz59Bqb
         lbFzoh0G01t2uJdiDvgECAF0OPT2WqmsIp5oh3LEEM1UoRnkSU4dqOSgMnKzJLLQhx0Z
         HT4KnNumEySdk4ttZxz1seAL32pRxqBwk5zWF7+StoLtGcrAALJ9rWxJ85heBjRWlcr8
         8rXODhJ1LQJReAaPd6hMGZOzqUpyyS9As8w53gE0yQIzp/tZa3R0CzKhbMSqE5EhcuxG
         JdFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=K6aDoQ2nZkjhSfUgeR22UAGAXQBWHHuCN2RUasZyd3Q=;
        fh=q3D7WgIlHI93mcGR+fChW2sZsvVg7ZRqgDUOzj2WI+E=;
        b=VIcbmDpDp0M9ml15nQXy6/XI8uyjt1GMPCpOIlQkm5L66hZmsZ+nBq4NT4mO/w88s0
         8PWMcWBWEtZ7GR2sOpQ8TwtqQ1HzLnW4hkwhXehvYMr9OQsGd83ofQShoOUyIiRb1yEI
         dPSIVbA42YDkyDRNDI+VYKodgpdy05wsNTYofpwIrrf5L/jib3EFCXegko4ABvrhem8p
         Yxcn9A4kK0uGNBt0QZHFtaN89MMC7geqTCVcgCVZj+iZZGQGIDG2rMSRKdFyvTlzi38Q
         78XYaQtd7iQRGOx9LLNJOuC2YMrxqTDnnziiesr7qIK03CWFvVSV3RmKSN7GX2upuDgS
         YIMA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=S2RDm1yB;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-53b2bf2af08si789629e0c.3.2025.08.22.07.00.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Aug 2025 07:00:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-299-aejz3198O5-Bogb9aov_RQ-1; Fri, 22 Aug 2025 10:00:01 -0400
X-MC-Unique: aejz3198O5-Bogb9aov_RQ-1
X-Mimecast-MFC-AGG-ID: aejz3198O5-Bogb9aov_RQ_1755871201
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-45a256a20fcso12451385e9.2
        for <kasan-dev@googlegroups.com>; Fri, 22 Aug 2025 07:00:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUwO81D3oxW5vh6De+itMl+C7gn2x6qv2pjn/LABmCHlF3vSkYkCId5anC2ljCIJHVD7tQPr92nMns=@googlegroups.com
X-Gm-Gg: ASbGncsf+8g82VZGg8/4zfyXONvUFjOiGlMSx0Qy0p1qeeAcZuuWh4Fpuv4ryvrXt4d
	y6eRLZ6dUHcj/skYIJTTTKrfxaEhsBcfKyI9zfptTNmB9td17lFh4nRnkiez64/mvO+Jcj8dtP+
	bJhxo5+kWIB6Bguj5UYgdJzUsAWDedTCU5nnpzROqlTie5m4jrxx6CngICxpHRMqk82/1EGFVYe
	quQkOfmMmQhpWvKPm+DWD02FqsQKHQbf0FPyBvmge9LnR4OZrL7AIhnbgYApdPG5qujTqGSEn6C
	Wotq9JiMJmF6s33BMHd7kthHwkpMWwhJYPa+bMQDlwD7Kz59L31HjiRkisa8IiJxTiGK7iAbx4S
	9Kh2thYmYtRqnMbP1WXJU/ErBmSqBjwzhv6U2D4q9cpJHnaj2I21TQFMQDaoYtyqRDNA=
X-Received: by 2002:a05:600c:1554:b0:459:e06b:afb4 with SMTP id 5b1f17b1804b1-45b5179b4fcmr28181545e9.4.1755871200651;
        Fri, 22 Aug 2025 07:00:00 -0700 (PDT)
X-Received: by 2002:a05:600c:1554:b0:459:e06b:afb4 with SMTP id 5b1f17b1804b1-45b5179b4fcmr28181195e9.4.1755871200176;
        Fri, 22 Aug 2025 07:00:00 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f2e:6100:d9da:ae87:764c:a77e? (p200300d82f2e6100d9daae87764ca77e.dip0.t-ipconnect.de. [2003:d8:2f2e:6100:d9da:ae87:764c:a77e])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b57498d9csm82525e9.22.2025.08.22.06.59.57
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Aug 2025 06:59:59 -0700 (PDT)
Message-ID: <473f3576-ddf3-4388-aeec-d486f639950a@redhat.com>
Date: Fri, 22 Aug 2025 15:59:57 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 18/35] io_uring/zcrx: remove "struct io_copy_cache"
 and one nth_page() usage
To: Pavel Begunkov <asml.silence@gmail.com>, linux-kernel@vger.kernel.org
Cc: Jens Axboe <axboe@kernel.dk>, Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Johannes Weiner <hannes@cmpxchg.org>,
 John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
 kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
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
 <20250821200701.1329277-19-david@redhat.com>
 <b5b08ad3-d8cd-45ff-9767-7cf1b22b5e03@gmail.com>
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
In-Reply-To: <b5b08ad3-d8cd-45ff-9767-7cf1b22b5e03@gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: 3eMJXzgsRnAT6UORoDugPQEbcrrkbN0bB3saTfhpL5Y_1755871201
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=S2RDm1yB;
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

On 22.08.25 13:32, Pavel Begunkov wrote:
> On 8/21/25 21:06, David Hildenbrand wrote:
>> We always provide a single dst page, it's unclear why the io_copy_cache
>> complexity is required.
> 
> Because it'll need to be pulled outside the loop to reuse the page for
> multiple copies, i.e. packing multiple fragments of the same skb into
> it. Not finished, and currently it's wasting memory.

Okay, so what you're saying is that there will be follow-up work that 
will actually make this structure useful.

> 
> Why not do as below? Pages there never cross boundaries of their folios. > Do you want it to be taken into the io_uring tree?

This should better all go through the MM tree where we actually 
guarantee contiguous pages within a folio. (see the cover letter)

> 
> diff --git a/io_uring/zcrx.c b/io_uring/zcrx.c
> index e5ff49f3425e..18c12f4b56b6 100644
> --- a/io_uring/zcrx.c
> +++ b/io_uring/zcrx.c
> @@ -975,9 +975,9 @@ static ssize_t io_copy_page(struct io_copy_cache *cc, struct page *src_page,
>    
>    		if (folio_test_partial_kmap(page_folio(dst_page)) ||
>    		    folio_test_partial_kmap(page_folio(src_page))) {
> -			dst_page = nth_page(dst_page, dst_offset / PAGE_SIZE);
> +			dst_page += dst_offset / PAGE_SIZE;
>    			dst_offset = offset_in_page(dst_offset);
> -			src_page = nth_page(src_page, src_offset / PAGE_SIZE);
> +			src_page += src_offset / PAGE_SIZE;

Yeah, I can do that in the next version given that you have plans on 
extending that code soon.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/473f3576-ddf3-4388-aeec-d486f639950a%40redhat.com.
