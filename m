Return-Path: <kasan-dev+bncBC32535MUICBBJXZTXCQMGQEBF4NJ4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 002E2B30392
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:09 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-3232669f95esf1445109a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806887; cv=pass;
        d=google.com; s=arc-20240605;
        b=CQsFB7oT2V5vzP6EG/3kRlYmBS+47Wop9ahyJUgYNqDaurjz9S7r+jq90ubUNylmyo
         TZ8dN4YoesIwg9VHR9ljxrFnV+Q+1V2P6FQ0KmKcdXDvWpAhueGDGgmuzx6CP5vTf7Fs
         4Kf5vQh0Czi0Iam3DdBHJMBc5RaFlT9aro7EmToKkj4T3YrsKmFFm+IOOnqUZRfOrl/u
         uHngSjYiQCYyIlC/FpfUA85uJujin0NvQisY7EKc5DGpWeHGXwb64qPQ0t8+Bul9dT+0
         jCSdk9SwwctsWjSZUd/0dUtg80f9e/NYpHLrfXLVGz4MA/lWhPgotBKVVy5cj0IvSpBy
         52LQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Z1FALCFjr/8G4WiFe/WJHQaqsReRP8OaXYX9AB0YQv0=;
        fh=kVb0NXVayneqK5RbuI+oFxmew1DuCaXKX1zF5ziQSew=;
        b=kDy7/wx3Mgin38XjZxzX5b+nnMmBnchCIcZKQYPgyAXrSa6tuMo3WB3aJ0netnaTYM
         OXsjxxOIzW23cZFN99qQnCnhkcP9dEuTtkFxXdQEeWQ3u7lp+HI3tpPMespV7pYKEj7K
         9oWqTlid139Xd+9eCDpm/zuXok8S8EQhjZHmi/8HCcqcs9CTh3/O9klS5SO2ulLMtY3u
         ig7pbfo27S8KMvC7/n4CAnN26u6blnfAkTGbRymssCaZg7uVopHWL2PgzN9CcpRJGWSA
         6/QNlD4c45kwyPC/nDwigBV5xIq+tfq3mzvWNereU+tx510tkkdpXaqTTNwM5Mk+2HTR
         Jx7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="iLJCde/Y";
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806887; x=1756411687; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Z1FALCFjr/8G4WiFe/WJHQaqsReRP8OaXYX9AB0YQv0=;
        b=M64FJfYRona/Wkyy9SeejsDzwFyCT5k9/0GM84F9CUJdDvoBsSAv3C37Vs4iTliqhf
         Xyrx76DIkGR3qUVMNswJQf9o9HX3bpH9DVnTbXVVRh343/p0auzGHsxJwLw/FiUtRcrQ
         LYVLirWHk58geN/an6X4nHTxDPKMjUfZ6KeyqgfAbENhdHLLpELWytoj0x23beQjTdxP
         JkQXP4Mjw73G0p+3MB0k0LkZdmGfr69c9JqFsII1RZaqUApN/D3HlyQSKtRuWPNe++4N
         S6Z8RM26y9NouzWWfi27xDQ60KsG5oog+WeSKwxCzDkxEtY5BCjPUpVEom4d62+r7Q/o
         Ks6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806887; x=1756411687;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z1FALCFjr/8G4WiFe/WJHQaqsReRP8OaXYX9AB0YQv0=;
        b=VrHAciaBv2glo3f+W3CI/e4Mg1Vemx6vScm4XHQjSugM2A8w+tSmbz5rdRvEMIZvCO
         2YSTCf8E029UIOil89SmeNEdhhqo6PBF2O42aIUtKCP/4MkLG/rQxfKZMZD/ZV+2BQRj
         dDwiAEmzQdbfBlIRf5NbVW4IUaUhzYXMUfU4Qy4qtU3xlwhiIOgh+T11nKt+I5vAeG22
         9cuA7mYyzWOdz7Jb4XU/jfcmJi13DpQT+fOPjSLSSaInxO1PDvxqngMPUzedJhYDujsp
         Z04tbgbVfJcW+cZJhmlSGbZftpbJ083Rt4VH9Aul1iSHN2pvS4PSqNnEM04kxdRvNL7P
         zwLg==
X-Forwarded-Encrypted: i=2; AJvYcCVxKqYPbo7LroCSKIe7imrrp07bu6sRVSyAxId0oXH5J2EVKAw/C258koWUxamM2RJgdy3viA==@lfdr.de
X-Gm-Message-State: AOJu0YxFXkSTyWyxBHINfwt6hWIOmZTt9ckitK0whtA5Ug5BWX5j1CkT
	gMiobTs3tSnCY6lLoMblr/GCPFBm6RxzpnEiNf6PxSNqr+f0tjY6dtvS
X-Google-Smtp-Source: AGHT+IEIazpR0ky2LE2+af7tr2P6yVoJSTpn03tyu13ix4cwDFjbAM6ewLxoBThag5KMZqTY8jFOyw==
X-Received: by 2002:a17:90b:3d87:b0:311:ed2:b758 with SMTP id 98e67ed59e1d1-32515edd782mr705750a91.3.1755806887048;
        Thu, 21 Aug 2025 13:08:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfhjzJacHR766vnR6nI4YWsVucfhAI5F2VEFTxw9z/h9A==
Received: by 2002:a17:90b:2292:b0:313:9f92:9c2e with SMTP id
 98e67ed59e1d1-324eb8538f0ls1065050a91.2.-pod-prod-01-us; Thu, 21 Aug 2025
 13:08:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUo2WCQresHnGY1t5kmk+OPQnvAcyb8+cWyeQ5PNcKgLSrWRJd+tlApTtA9WroLrFcuE0jsqeD11tQ=@googlegroups.com
X-Received: by 2002:a17:90b:1350:b0:31e:c95a:cef8 with SMTP id 98e67ed59e1d1-32517d1dd42mr823338a91.32.1755806885451;
        Thu, 21 Aug 2025 13:08:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806885; cv=none;
        d=google.com; s=arc-20240605;
        b=OdmFsFIT7aT7PQSVzOlPtvLxBCm8Fl1M5WqYn0nY9vUgVBbAt2ZCLe9jiOI6t/AARf
         un0WAkGDQ67a+rXtbutwmV8iUAQKHHTmqbf8XVlzMjCOL7137aMeqFRuVNXf+H9FVtoh
         GOREH9Xgc/N6yAB43pxJn4JpqqWpz7rKdXVyaHrZ9QnoRg5txNFBkRj5e4zGxG+tDakd
         HJ+QukSJborTyy3K/L0YgPytxWlshDtOVrh9agyyyA8ML1yo1lV6WecjU1T0nm7ruaJJ
         IeYVTNvhZWaHCAHs21co1AGlYH/yt+nL7kjhoW3SHX5Isg614Js/Zi7Lcv4SUkcT6LxD
         TxCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=w6VkvDa+3msZeC5nA9B9+aDln+Mg2ABReefULBX94/4=;
        fh=S3N5+m+kSkgQZ/XEer13rF6U4F6h+RqCoKYcTSaF68U=;
        b=P5IGnCPOVG3XxPatxll/xqug8dyylyxoyD9+jCSJ/wspiOAB48FgBXWdiJa2KViT3d
         s4pxqdWiFBTcIF7/K5HSJKikh/OwYhJRlyvlbkTdiZFl/H8Zl/g/d5AjKsoeAYhEF3n2
         snUJDkJw0t4AIKVle/+o43doIxsHnuDZu2mg9Z/teggw69M4JcMOJLdx1o/KhT0E1V1I
         KeTeqDrsj1KcDpJIbMFlALTgrgsrAqJ0SRHtojumUJOSa4D87708r728iCmjd9k04E/m
         sKSV2QyMEf5UgDmHNF136d95dYbdHKIm9VBig7vhxxzDs1rl1DUHpnk6IUb7WYMm3420
         JOeA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="iLJCde/Y";
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3251390caa0si35086a91.3.2025.08.21.13.08.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-263-lEVhW24APVWaJHhosFiRuQ-1; Thu, 21 Aug 2025 16:08:01 -0400
X-MC-Unique: lEVhW24APVWaJHhosFiRuQ-1
X-Mimecast-MFC-AGG-ID: lEVhW24APVWaJHhosFiRuQ_1755806880
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-45a15f10f31so14273525e9.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXi3P6qKj4gePyFitOehn+47ssZ+B6OH0eohkYP5C1alWt1m1tKg1S5pu9rt/Zz7Z/sLv+XejGhY2A=@googlegroups.com
X-Gm-Gg: ASbGncsoroMs8ezFN7iEpEKRz4KeUeG0dx172Aj+OYb5SlJJilLsKE1K5Yv05b1uAaF
	srL8WT3SP3yghcoQzps0fKmGSJffEyFqWpygjbJluT3kFq5ZzvSUq9F9Yf59OhDTAXozJYjEnHI
	Hj3IPKttBJ+jlXy24/77eBuMVRxYJ31gh/UIWMaqEr9IuEZUnYXiudLkmGZ2tFXMLM6HvU6XvJf
	hQ+L4aJwD5IiFwvaYvMcELkUjMfap8F75PKeKt3V88eQ8n/FoKLhABabnTGDgM8Pxu/kCW5WRFP
	X/2bdBPyAkLtqwxH/8laB8qBhOElIyYpcxyLw81F9/P598poENO0i0nLUuXCrJjAexBDZUdbE/y
	uw7yQQoIfoU86expBT50Bow==
X-Received: by 2002:a05:600c:1c87:b0:456:942:b162 with SMTP id 5b1f17b1804b1-45b51792539mr3328745e9.11.1755806880051;
        Thu, 21 Aug 2025 13:08:00 -0700 (PDT)
X-Received: by 2002:a05:600c:1c87:b0:456:942:b162 with SMTP id 5b1f17b1804b1-45b51792539mr3328365e9.11.1755806879543;
        Thu, 21 Aug 2025 13:07:59 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c07778939bsm12219075f8f.46.2025.08.21.13.07.57
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:59 -0700 (PDT)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Jens Axboe <axboe@kernel.dk>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>,
	Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org,
	iommu@lists.linux.dev,
	io-uring@vger.kernel.org,
	Jason Gunthorpe <jgg@nvidia.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com,
	linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org,
	linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org,
	linux-mm@kvack.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>,
	Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com,
	x86@kernel.org,
	Zi Yan <ziy@nvidia.com>
Subject: [PATCH RFC 19/35] io_uring/zcrx: remove nth_page() usage within folio
Date: Thu, 21 Aug 2025 22:06:45 +0200
Message-ID: <20250821200701.1329277-20-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: dUwDxlZxwFy4VE-onK94wHcJRF3tC-ZYR_55MSvfBYY_1755806880
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="iLJCde/Y";
       spf=pass (google.com: domain of dhildenb@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
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

Within a folio/compound page, nth_page() is no longer required.
Given that we call folio_test_partial_kmap()+kmap_local_page(), the code
would already be problematic if the src_pages would span multiple folios.

So let's just assume that all src pages belong to a single
folio/compound page and can be iterated ordinarily.

Cc: Jens Axboe <axboe@kernel.dk>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 io_uring/zcrx.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/io_uring/zcrx.c b/io_uring/zcrx.c
index f29b2a4867516..107b2a1b31c1c 100644
--- a/io_uring/zcrx.c
+++ b/io_uring/zcrx.c
@@ -966,7 +966,7 @@ static ssize_t io_copy_page(struct page *dst_page, struct page *src_page,
 		size_t n = len;
 
 		if (folio_test_partial_kmap(page_folio(src_page))) {
-			src_page = nth_page(src_page, src_offset / PAGE_SIZE);
+			src_page += src_offset / PAGE_SIZE;
 			src_offset = offset_in_page(src_offset);
 			n = min(PAGE_SIZE - src_offset, PAGE_SIZE - dst_offset);
 			n = min(n, len);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-20-david%40redhat.com.
