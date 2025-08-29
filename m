Return-Path: <kasan-dev+bncBC32535MUICBB6HXYXCQMGQE6LOYBWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id CE197B3B827
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 12:07:54 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-244582e9d17sf5367685ad.3
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 03:07:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756462073; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZAMz3JtnrzyR1EswfAPZxkrSacN7ROjMnEHUEvSqU1qaq5kg6Y0qUjuLsdI99b5sHA
         qDYAK2Q38yQnK5sYlpKcCL2hGUi/BPFHJHHGX9wbLIf8LR8QWppD0EtLaoScj3h9lLDj
         Ii6VRGnQa76LXNy+5nGqu3597Nt5euQKSewTAMvDBuJxkLfnqT8Ps4WTqiWYlQHfDFl3
         cuzfd7vn7+94Pb6pVzz2hPiiUWomi/NOcbtdkAug2jd/yXec1+W0zhJ8YvMQoKHteeIO
         SkQUzy4+sTDf9d2gvkDlyWoRfDeDN5MB4EWnKI8VTpNUBoksGy7PkpLgbBUkf2bXL0Yh
         cxrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=pstfK3vBWNUYkMo6WInAcl2MiHDvRhoRj0VqfbLbRdw=;
        fh=GMM7M3Bj5bGJJeKnRq7bDvLMZVB2dii2axMHdQyeMho=;
        b=cI6jzNk2OmTi+j13GZsfH57Y3gBxSvYHpvN8q+0i29DknX3U1TqvY2U4QnPDCZrUNK
         buc4fFJtJtD06cKKywURSvs2o828Ol15wVmWVjEKWrLgQJnKynXqrkbCZRojjE5/CDLa
         L6zjfgQ3BJGX+QFwkb7rvRJChVbJ1aYWvuypdxHuv3aExWB0tinL07VUOAjNBSgnTDtO
         qdA6dJUpGhc3BJXezglIu10ygVCuNEZx05V05A4g2N6X5mWqFkXlu/C3rd2gtyoXcRj/
         +pAeQ1PBjsgnMJxkpviKPdsuDeRza2Sn6JveA99KntQZ3sUYNwQ0zzFX/1n942Ge2x+l
         M6Qg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gY0jiPmV;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756462073; x=1757066873; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=pstfK3vBWNUYkMo6WInAcl2MiHDvRhoRj0VqfbLbRdw=;
        b=sDoNdHnxOZ934FyxjjKXHBEb6N8/L708exEre51+oMvrRmhlBT3RkhrDb6/q2hCwPG
         aVj3LFBRg7k6zsTNqC+loNwxG1j6qcw++iGu3UDxOqK8Hm/X6roOb3mn4z54c/Z2/nbY
         pLYoZIxOpNLQjO8q/yX0XJBa0/Atl9CeS+bE6evXin0GnR28y/ObbYU6Wvi0PvhBdPnu
         iw9HXw3x/05oOoW9VGtcIE5CnWdjCIj0vslgwR/tVBNmc2dldbSogcvsyUxjBLc5MS3T
         T5esZr5c6nehyk9eGrsj1E+lZ9Q4EBJE3Gf72IyaQddADW0yGTbP8DDtoFNcu0BwrJ3H
         PBxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756462073; x=1757066873;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=pstfK3vBWNUYkMo6WInAcl2MiHDvRhoRj0VqfbLbRdw=;
        b=Gg6wrKaConJMFkisTtzUD54acuzDN0CKECQlZIwhYHLwu7fdlUBlOPhrQbV4dAQdEL
         0XJhCWEUvGzEmPLodh0yLhomNdyTd2ay4P0CpZGudsVqtNQYJH7xTssZTjoPe3cqGg4R
         vfuYqNq+DRlGxj1clwJQHyUNpXAtYFCFfn33IyqEAd6TJypvOnUNfGL6kJgrpVSMINJ4
         Gb7z53mcuiX7l3mtaOFSe1W4PwJi+0mUC78Jl1Ll8y2vLWjk5MmExitjEiT1FmMAKU5X
         qFNONNAbDaL51aea3CjHb7rK/MAes/3Rf7rbNA9llxKPDIIDB0fQsnGNcjVwE5MNQN49
         ohdQ==
X-Forwarded-Encrypted: i=2; AJvYcCWT0IXfOBrJIPO+8mc9E9h8M2o9mN98qe3zfIQuS4Dl2R/hqS6CZ9xIa0lJmsND0Ov0H7qBfQ==@lfdr.de
X-Gm-Message-State: AOJu0YyMlXXnAAid2pvZyZ3ldPhLDr1Qf5po4oL4ZImBP66DBHCh2/Fg
	I7178Se20aZkAx2Zwmm2E3eHNUF33e9Mgq90GPoyjZe3poFulOwzg0c0
X-Google-Smtp-Source: AGHT+IGVs8gOSljvew02sjJJCSLB22oc89xnCtBrvrdZutN4UbSAHGBuhElFLK6IAXt8pZeg1Y5NwA==
X-Received: by 2002:a17:902:dac7:b0:248:bf0a:a127 with SMTP id d9443c01a7336-2491e3e2d9fmr6518095ad.1.1756462073042;
        Fri, 29 Aug 2025 03:07:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZetEiZrHV18eM6Cqqtm7gxl81aHxVqo+9LvDktBxPgJhA==
Received: by 2002:a17:903:88d:b0:246:8165:f6a4 with SMTP id
 d9443c01a7336-248d4e34f49ls7163265ad.2.-pod-prod-00-us; Fri, 29 Aug 2025
 03:07:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXF4Au4Sdp5/viTJsZ/HdbC+1Ok8Y7ziB9TCaDq21yFKiD+ZurVu7JVbkSn86kP6DASkLRBe18XPqo=@googlegroups.com
X-Received: by 2002:a17:902:d48b:b0:248:c928:c373 with SMTP id d9443c01a7336-248c928c696mr102984735ad.8.1756462071652;
        Fri, 29 Aug 2025 03:07:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756462071; cv=none;
        d=google.com; s=arc-20240605;
        b=YpW2YayOjRnCbM4jjoXJgqxURWPGXRbM8fUORW5M4o13QLPN6aasX+tSp5P8rXkGPz
         abmZLklSjv7RWRXrc/X1fstUq70Z3jIsl3P10Uk/oD9MJ1uZeJxB+pAzqwH7ZTeHLAK3
         Ay8Fr9VikNGeAIG76vqPf8T8r6KtW4pafNybqB1OcBkRKd+CMV23xm+FWAN9ucpewqXv
         khT+3vFbW110ZRgwWZTUwNoGS9VLJmH4P+4JfG5IYeEMu4N/YjR48r10uFa4pdoxx6eT
         Ovkmpr64VAvdwORfcuKyGLIO2GjE1nJhBus/lqUtU3HCnVzhtNN9mBKKEg59bDZ8/zzH
         Pi/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=R/nFDMhWq8V1oJTJ8TEj89R3ylFApbzlPBSZ+h+c35U=;
        fh=odD01y/0GCnlQF2cRVoiyg3qhwEqNK2Y4HEs8ULycH0=;
        b=Y3WL5AQAnFL0gUkT0n9UIfdp1VglpBhrDm4L2dFrVfTAQrvlew3QMV86PvKK1Vr1ps
         2tKDSeX5wy559tgUDLtDKHhcwC7GP9PQ/Rv29uxwKgNpASNFeWDvtp3Pd/BrYeDVJK0T
         tvPeT34snqMdGEIawOZb3No6i82O18n03G9/2HcuR7SJD1qHwV26t8vu79VE1/UzByn/
         dAPgJpPJmVEs1/sT3e2J+8yRTknZeq1PPoEAAH5tYOSDA/yRKlOOuLMiOJpk17B8BjhN
         tvDp31wMzp+l0qo7htNjf33ql2Ympnzoq1uItWhTWgZhUoWYRSrNOImX5axNMJ9Ia0oC
         xpJA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gY0jiPmV;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2490371aadasi895805ad.1.2025.08.29.03.07.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 03:07:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-641-WeToc5mCOqGlbGYRoRahHQ-1; Fri, 29 Aug 2025 06:07:49 -0400
X-MC-Unique: WeToc5mCOqGlbGYRoRahHQ-1
X-Mimecast-MFC-AGG-ID: WeToc5mCOqGlbGYRoRahHQ_1756462068
Received: by mail-wm1-f69.google.com with SMTP id 5b1f17b1804b1-45a15f10f31so20269755e9.0
        for <kasan-dev@googlegroups.com>; Fri, 29 Aug 2025 03:07:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUoImNwqjiEuWEsEXCGrKc0nitIWsv9nUq505aoJGcOGQU7WFJ+z2q8P7G/hpFunFgiRk6ezskzKb4=@googlegroups.com
X-Gm-Gg: ASbGncuOmaLEKOm3gS/xZZ9QiUo9rYSZQXipcfisvlq4rE26OX5/HbM+wFeG7HwP/n8
	2DNg9g5hCAmiLy3ay0E66RKGBt3NiQXJ35Kuzuzfdlg3NH6lSgujx4JMIDvK9Gg+5vO2R/uU3XE
	7w7h7gOkvEoiG6XV4NZyp2rluiUyUfFme7Sac5byw39732ku5rwMd1rlK3p0lY8s8DlP0L4t53V
	rIuL1NKuQ/lR4wbSh/bqmI6l7VylPCLEBy54Gp54ac9Vz47z/OVshQEyCVdiXvyloyv+2kWj1hB
	zVLPg5bRmB4xq9c97y1Y4+THbWXFndJYKGVnk0im5M+3YiyKOD50acJtlxqPS63Ae/EKSRoWoY7
	cyaW6c5FziKCb4oI+AFuQsyeReujclAD7q6EM4QDRrU7saE7LmLM+2my1hz4tPvIb
X-Received: by 2002:a05:6000:1786:b0:3ce:bf23:3c15 with SMTP id ffacd0b85a97d-3cebf2345e6mr2871179f8f.26.1756462068007;
        Fri, 29 Aug 2025 03:07:48 -0700 (PDT)
X-Received: by 2002:a05:6000:1786:b0:3ce:bf23:3c15 with SMTP id ffacd0b85a97d-3cebf2345e6mr2871142f8f.26.1756462067529;
        Fri, 29 Aug 2025 03:07:47 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f1d:100:4f8e:bb13:c3c7:f854? (p200300d82f1d01004f8ebb13c3c7f854.dip0.t-ipconnect.de. [2003:d8:2f1d:100:4f8e:bb13:c3c7:f854])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3cf33add7f2sm2910573f8f.32.2025.08.29.03.07.45
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Aug 2025 03:07:47 -0700 (PDT)
Message-ID: <5f6e49fa-4c1c-4ece-ba67-0e140e2685da@redhat.com>
Date: Fri, 29 Aug 2025 12:07:44 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 08/36] mm/hugetlb: check for unreasonable folio sizes
 when registering hstate
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
 <20250827220141.262669-9-david@redhat.com>
 <fa3425dd-df25-4a0b-a27e-614c81d301c4@lucifer.local>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <fa3425dd-df25-4a0b-a27e-614c81d301c4@lucifer.local>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: GGQNKb4gI0boA4w2PfHj1IpxPhBU7ZfrTbT4TDCqXAQ_1756462068
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=gY0jiPmV;
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

On 28.08.25 16:45, Lorenzo Stoakes wrote:
> On Thu, Aug 28, 2025 at 12:01:12AM +0200, David Hildenbrand wrote:
>> Let's check that no hstate that corresponds to an unreasonable folio size
>> is registered by an architecture. If we were to succeed registering, we
>> could later try allocating an unsupported gigantic folio size.
>>
>> Further, let's add a BUILD_BUG_ON() for checking that HUGETLB_PAGE_ORDER
>> is sane at build time. As HUGETLB_PAGE_ORDER is dynamic on powerpc, we have
>> to use a BUILD_BUG_ON_INVALID() to make it compile.
>>
>> No existing kernel configuration should be able to trigger this check:
>> either SPARSEMEM without SPARSEMEM_VMEMMAP cannot be configured or
>> gigantic folios will not exceed a memory section (the case on sparse).
> 
> I am guessing it's implicit that MAX_FOLIO_ORDER <= section size?

Yes, we have a build-time bug that somewhere.

-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5f6e49fa-4c1c-4ece-ba67-0e140e2685da%40redhat.com.
