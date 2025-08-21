Return-Path: <kasan-dev+bncBC32535MUICBBU7ZTXCQMGQEB2FNV6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id EDAB6B303DB
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:52 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-244581c62fasf18115725ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806931; cv=pass;
        d=google.com; s=arc-20240605;
        b=a/+UY/AiL55J8fIzZtLIUb88dTP2fBccRoOgrzBScctNHnKiQ6k1WxoFG09SsuixjZ
         8nfecbkOCRMenfCTC8YmyqHJwXpdGYTWOSxss3pWCJvglO//Wt1MlsKhx1Xg5wEiVw0W
         i1Lpuqy2Ta701RbWImJX/akLNx1cqkscI9l5gzi2O+N5V8g+ZV3vApmEuyT9y8whWt83
         G370a//sc+FDDjSLeL24rwzJ8QIDhMOGCvwsLwJ9RXASCA49UCBOe0hptqVwEPs0RMK9
         TuiYRoRW3XMr4ihyGZUoAo232prb9sD26FsQhpDZvYoAjQ1VJ6MmiUOq06TP7j7LMuXk
         dAEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=vcsJQYZh+hr32G5UovLuqJQxsbNAKugwNgT2nDkaY4I=;
        fh=L9nAgOrrEwHkXhnOtm31RonZXD2p5Jdn4oUS3keWr1I=;
        b=KIrAiu8m6SRlXSusyAA+QIFYNLiTYQpgtFadjPjbZm6vpmGEJUermDUiU+Bs2gn++E
         opOQ353uFEarlAkYhnVys+IE8sSMAnT5YffBync9dEf5TZv1ioK3k375qZi/t/kA6eS5
         agj1dmFVRMmKDuqu0KnCxSTlnGAyuWRC3edlKkIfYNYrepIz2lPWoWMaoTnXRbnJOq86
         klN3Z0yidOJ5uHlDYKMb3i/hwbwjgYzS6tAuq1v8CThPBCkW6WL7mQGW8hCsHmCSaJwF
         FKUjLxpaiqo566Yv6wcGto92u8d9MUddGIECMGq3jSvIaxv+Y52CmCbFI67o8ZLfSBpA
         XogQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=E+EKZVNo;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806931; x=1756411731; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vcsJQYZh+hr32G5UovLuqJQxsbNAKugwNgT2nDkaY4I=;
        b=SX+XYzTpYIbWn2yzD2NNSChSr06wGJeWX0sd8nEmBOSU7ahEySo8JTKJa7/iWkkWov
         m8imv6FcJ64p0s+c6XJluGdghnyujU5CP0NtJF3L8FTmANrB/AGD8hSE5u63JZKn7Vot
         O5erzxdJZFpR3J2yNseqeS2vsc79iGk+2keOwZMAAcD0JAhNuU7363EYUSIrcihw3JWs
         i0gVOWEMtb88dDc7858fqTtKAsY5JpabMkMOA8s8lC7jbWsFaPf8Uq6qOi/wgFtRb1TJ
         WXzvXI+fGe3e7cZ2sDB7rWHoyc298IUu75lb8vu0+CxnBRjQaHZoarAgPoYw2FvFdzDN
         m0aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806931; x=1756411731;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vcsJQYZh+hr32G5UovLuqJQxsbNAKugwNgT2nDkaY4I=;
        b=cYFUwsniAXnIGxhM5cnbBu85IVQtkfCY8+nRfozFW+Lo8afyCSnQh5LZ1Y7b44KFfe
         4O98NtQZ4/OGmY0NV8/hDwk0irTf+qXpp565Kb7UUvEYK8PVUWnHgrJ8unxZRm7rxf+0
         ITgjfVxQfHCF9Y23ExTiW0TjQlXb6Ugzvpm1EAtG467mVMh/8iAQuXEB4gBifbsqd58C
         uq2o8FAEf8r2HSfMfhMTSDRucR/DgRegZISyLngiKMP6myculVqir8Vy/qd9bHDD5k/h
         pv3wVUQqbnD27qfu2TwWYcf4dqBL0Op8+sO49ofkgEdHGFYpElxnRO4WGr/cFzPScWNJ
         kHjQ==
X-Forwarded-Encrypted: i=2; AJvYcCUx/oqQkgg0pV7XfqWLlGGz2BdJnHjhicxO/8KKOtM7HTEBrPwPlsBgytnEp1psUFSxnfEueQ==@lfdr.de
X-Gm-Message-State: AOJu0Yywm+d84Osmhi/HZKiG3cxVK9nnHcFXoppfDbcrroiSHQIWWDAh
	8xSTZ+6Kthhu7vdoU5KXPD9XlNpLk5URkeUwQ8u/5ibghCaA/8dqEjNo
X-Google-Smtp-Source: AGHT+IFK7OW09MBrfioNWYkwbs+wNp8P6QMKu9BusFZgeq7kkazqblXaLzcDJkROMSNFPGS/M0F5ng==
X-Received: by 2002:a17:903:2a8b:b0:246:3964:63dc with SMTP id d9443c01a7336-2463964650fmr1021795ad.47.1755806931333;
        Thu, 21 Aug 2025 13:08:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdsL/vhRTG9h0Ox9N5lhl4sH+QQyNbqjPxwryFfKU8L0A==
Received: by 2002:a17:903:120a:b0:237:e87c:ecee with SMTP id
 d9443c01a7336-245fcb7f08bls14025135ad.1.-pod-prod-02-us; Thu, 21 Aug 2025
 13:08:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWChMOzbUhDgAcDmUZsQLy+BTUBDuAt/XclW7Oe4IF0BPm7KG6oiKyvTvJYz9lKIZE3Aa+p5AYivDE=@googlegroups.com
X-Received: by 2002:a17:903:22c7:b0:246:570:2d93 with SMTP id d9443c01a7336-2462efd234amr7243125ad.59.1755806929119;
        Thu, 21 Aug 2025 13:08:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806929; cv=none;
        d=google.com; s=arc-20240605;
        b=QlalYG1W44+aswXNeL/VjTm/alGWppo1YaJOXXqtzSeJDLxRuKXw1nSPJtLmi2HyWC
         iHrnbAi3iDS8SWnSI+EdzK+G/qYnh8g1fRC4C/t5PK0rGI0hM8NnW6gPZ+Y9KmR9Ze4z
         Iee+kh8JFKHs2FOZ0lNibtOO07UgQLD1zdwJItZqQbLmoyIAM4rvLW/U3t0/JYWVkvYW
         t+7/TFFlZ6ikXVzs/ZAKshMvp8tuj9FfN2YlaKGXkzftLIV8uimHkSndtNGQOzfovHoI
         gJtNT+u5yjxTARg2yL7vkJOPlxH3wJ8jqxOKzP+3MvtDx8ytniZCV5xsoqyWx8HMXZhy
         uzNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8aQmj/0+AYT4mPx/DatgQPPbmq0Lkvm9KCqKkKCdC9Q=;
        fh=1Ed1dP9/EWSABdVOtp/1C5msy4YsyOZqsDWuutmFI14=;
        b=MczgT1xNg7Fv7E1LuDjKlEBxr7qbPqUHWufL9UyT06BtdGVHE5Ir3C4BfNVrZpOvw+
         p/L5OobzDPkrdf6bPkxbUKmCVZrGJgXHL9wkzwCIm2gEPU1FKs/ikhgnLxZmrEF/9mUf
         CUz5Y1sbqPL6l3+yHMXS1npthQzuGav2z/qqVl+3ZlmUIBN2Ivp8vDBOFCHdnIS/8DAj
         +LYeomFK/jHsiFBHvGSaiiCLBt+mVZxizFgrhxPQqgm7w6xfaXwZh+pDWgFRqX0BUS+6
         DZDxKxLi3KAv/SczB52ja4v84M4sdatdteDcoXSSMex7YCBOGCrgToUW4fJE6ZtzfnYj
         CsOQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=E+EKZVNo;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-324f80d9c15si84107a91.1.2025.08.21.13.08.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-311-JlNnBMUwNVChAwFznqP0kg-1; Thu, 21 Aug 2025 16:08:46 -0400
X-MC-Unique: JlNnBMUwNVChAwFznqP0kg-1
X-Mimecast-MFC-AGG-ID: JlNnBMUwNVChAwFznqP0kg_1755806926
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-45a1b0071c1so6423065e9.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXKomKLnxQ2+JMgz/LZRf+tJIA7VeDJ2SBWXBYNU5yDEZ27ETH1BziWKcxv5cYm5LKoiKjj/9Jdmdg=@googlegroups.com
X-Gm-Gg: ASbGncvm/FDcR0339B8wHe2Zs1uXqKUiIHySQHZZ92E9jixnTD8b29D6A+zJQfA8CX9
	SrpcMqXCWlCrWmesmi+of83GRgPWBpwbH4ZMlciKTTdYodQ0v47SCZWoNOSD3jn1ge6zK+DfPPO
	ZYP2Z52ykA7mIZfM9PwsExo/fsTL8wjHFH8r4OMJ2lnqw0ErO0ovF2ibyVqgTfhR3OTBYKOWcK/
	f1pQvRe3CeWngeyEuiO20T3Y/ShNdWbXf7BZccmNKLF1InBZuiXgd7SxnBIDkxAU9dM8GjjygJZ
	qlaj+KDelFOT4SclPaH9yJshYDcy1nkz8ufjAPVdP8K6U4mTuU9F9vuy0D20aqsOUXG+LxUguEi
	63BIHcTIFyKOjrhI66xLHrA==
X-Received: by 2002:a05:600c:3b25:b0:459:da89:b06 with SMTP id 5b1f17b1804b1-45b517b008dmr3774515e9.16.1755806925544;
        Thu, 21 Aug 2025 13:08:45 -0700 (PDT)
X-Received: by 2002:a05:600c:3b25:b0:459:da89:b06 with SMTP id 5b1f17b1804b1-45b517b008dmr3774035e9.16.1755806925116;
        Thu, 21 Aug 2025 13:08:45 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-45b50e0a479sm8895255e9.21.2025.08.21.13.08.43
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:08:44 -0700 (PDT)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
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
	Jens Axboe <axboe@kernel.dk>,
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
Subject: [PATCH RFC 35/35] mm: remove nth_page()
Date: Thu, 21 Aug 2025 22:07:01 +0200
Message-ID: <20250821200701.1329277-36-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: LewXs8BuzSQliLXriVvzYHEPhwkZ5RBI5dgRvhGjyIk_1755806926
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=E+EKZVNo;
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

Now that all users are gone, let's remove it.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/mm.h                   | 2 --
 tools/testing/scatterlist/linux/mm.h | 1 -
 2 files changed, 3 deletions(-)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index f59ad1f9fc792..3ded0db8322f7 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -210,9 +210,7 @@ extern unsigned long sysctl_admin_reserve_kbytes;
 
 #if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
 bool page_range_contiguous(const struct page *page, unsigned long nr_pages);
-#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
 #else
-#define nth_page(page,n) ((page) + (n))
 static inline bool page_range_contiguous(const struct page *page,
 		unsigned long nr_pages)
 {
diff --git a/tools/testing/scatterlist/linux/mm.h b/tools/testing/scatterlist/linux/mm.h
index 5bd9e6e806254..121ae78d6e885 100644
--- a/tools/testing/scatterlist/linux/mm.h
+++ b/tools/testing/scatterlist/linux/mm.h
@@ -51,7 +51,6 @@ static inline unsigned long page_to_phys(struct page *page)
 
 #define page_to_pfn(page) ((unsigned long)(page) / PAGE_SIZE)
 #define pfn_to_page(pfn) (void *)((pfn) * PAGE_SIZE)
-#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
 
 #define __min(t1, t2, min1, min2, x, y) ({              \
 	t1 min1 = (x);                                  \
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-36-david%40redhat.com.
