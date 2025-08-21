Return-Path: <kasan-dev+bncBC32535MUICBBEXZTXCQMGQEUBITH7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id B7D9CB30385
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:07:47 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-70ba7aa11c2sf30774626d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:07:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806866; cv=pass;
        d=google.com; s=arc-20240605;
        b=aDLMFyc62oOccRxn+dcMop2ZSOXqNBtgIGDDM2WDuthaY3VJQAO5uvKWYhEjimJWOV
         MHASR6swEIC4wZNw4Xk9C307WrOxLEmUO4ToJPy6SoUQQ3lUvaKUihE1o0AbgaA6XrvS
         57ZJ1xU05WdYTeB1b4JKprxk+9QDOU8HxOFXAFd88OwDLmKwPh3H3hJMW16PL4euuLqO
         idGXzRq5TrBHHFzWTWkaxxg7voM1R6wXQIYNDsA4994Aivi/q4gC2WM90O1Sepy3XKBv
         oRzcceZhRKyxpPTjkXeBnVdDEBBDbjSt7KkQthxAV2JWAGTDvjo6VvYufHaqt5txUQuC
         DfbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=NcoHdEI9e5px+xxmF5cFRYX3XvlqkqK/4llHWNnuYzA=;
        fh=4hyqFjvmipvl6tKVePRvQp0jPC11kARNIFndwTGSeJ4=;
        b=TtP7WOK0n4d8N70HjeJNtDJFMupuU6QOjesUUZbex8Pm3w97R3G05hd8LMUZatRIE5
         uh7gkPAbvdtt5FBKtUYk+tFMOoSPpwnT0grD3BIeuBeDEdQmSp//ZuOjEQEQ6BVCY3c1
         UDMpaaaxl3mkoxoHRDTuMq26T2sz1MiyRe5cVQTbDjdTHzCpvyr6Uo4juskblPHip+1k
         97VMd7E8DnieU3ZZL9nl/78c8acZNIcE+EBIejaGYWMdleVSzWUsm/EZWFiAk7sz/NJR
         bQeOYM8mL381pqEJeZ84zwAUoVE3rs0LtilW4/4q32BezVFacWlFOjK9m6iJx7sXwFXt
         8Tng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=avYwfnmW;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806866; x=1756411666; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NcoHdEI9e5px+xxmF5cFRYX3XvlqkqK/4llHWNnuYzA=;
        b=ASaXw2oOY3Hj+bWIhp2kY8994V6CHsiwJwZtrUJvJ4cLx7y1Wu4SXgKSawEyy9TOuS
         tDyvBw06EmVCovcWmZywj4RdzJTqcLcmLmTXNB0s3iOpz6nal1E//vFlV8ZbpOASNbvB
         bW5nVaDRpa0rL4F742dLKr73A950xeACuez445C4Vw4EFPyi2rkcvHlUBJNYs+v2LkDv
         HiUSPrTHihcoJ+j04/sOnGd0Wdbn12Hv2uAM/LFDxh4FEcbHqLFLDZDgyUZVyR876V1K
         JQL0OXp/he2oyPJ8wpPGLsQdMaW3NzOBS4iRSYCYLLSFDLknvBiMnuXxpaRp3pr6d7z7
         ZpaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806866; x=1756411666;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NcoHdEI9e5px+xxmF5cFRYX3XvlqkqK/4llHWNnuYzA=;
        b=R2BgmFlptaMcCj6uhRTYjTPdKoxHBWKHAPXpaLsJNo6nRRPb/kOFiqRl1CW6E3qRB7
         9w2GniH2gW+r7XfyJsNJDsS4lQJUWhbTCW0ue90vjm8/N0ne69djtHRIcDojnSut7hW0
         FV0RiQf16O2DJ1DCus8jh5WXCegXNRHMuVleV63saspRVlK8lZxPqn2bTBYwxHRZ9Zae
         8jQLZSu/YLdDcnePkNXrsZHc0cjTM/8HL3vTVMQc63eWbnen2F5xLkuZOgk/azNfiFId
         uJASMsTpzsseaM2HGhakgZ5WZuvSuf8llBB1gR3pbnVRfn5H5ZYZBY6qz+R8e2Odcma1
         GZFg==
X-Forwarded-Encrypted: i=2; AJvYcCVfNXkJcW3v9AqNhSowAVJIo5+DT/+KBJqcM1Q2ucVPX1ck/7Dk5uIqy/BJlunaV8wKHquWtg==@lfdr.de
X-Gm-Message-State: AOJu0Yyx5qUiyMjlisIxLdyP94Vuesl0fDBUPWSjWzMCOtEhmM2DfFNR
	bSK1SmLxPODPcV9LlNMPobcFFnUnvJ2SvyryVUUCr2TneSEaE6AhTHcy
X-Google-Smtp-Source: AGHT+IFmrrzmMiGVcETTGkeoAiW1frwDNleP86bM5tTSI8LHLNIwDlfwZdqXQPnZhiHOkvmBFVnYrw==
X-Received: by 2002:ad4:5de2:0:b0:704:c686:3f54 with SMTP id 6a1803df08f44-70d970d57aamr10669396d6.15.1755806866323;
        Thu, 21 Aug 2025 13:07:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe7h8NSH7ZS9WBqOevXObLqjW3YQFXYR9tvOrY6TxaMhA==
Received: by 2002:a0c:f097:0:10b0:707:4335:5f7 with SMTP id
 6a1803df08f44-70d85a03de8ls12841266d6.0.-pod-prod-09-us; Thu, 21 Aug 2025
 13:07:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV3F23SZ1HvsFAdJmSj0R77gu54SvOGBV95MgQLM7dZ2pHFA9gU9BM2TZ7JegsUH4EGtHMbYxodalQ=@googlegroups.com
X-Received: by 2002:ad4:5ae2:0:b0:6fb:59de:f8ab with SMTP id 6a1803df08f44-70d970a53ffmr10620606d6.10.1755806865347;
        Thu, 21 Aug 2025 13:07:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806865; cv=none;
        d=google.com; s=arc-20240605;
        b=W3lB8+s5L17Xhtj89eoE9xtNuR0xQ7IAwKd8h0hTWgr3Yu71Txy03GMia2QHu3HjHI
         AovRxCr9lQSAK0TEDiH2WU+/WCjqBRFLrsD0TRVsrQlZ27HxaiPFEd6SkWmQqNolEVwg
         MEGukth/CVxK3PKV+IUDxo4gmDIP+Xphgv0Saq5I9VjIxXa0jMGz9369YcI0XhytLCQT
         oAwc24jx7l/QC52DXgmnjlS1NAkpgzAC2G/YjRd5nXrtAbBA0oj+og3I9M54CAWKV+9b
         3M9u311W+6Ax8WNK8bDexxYry2yEYPCVe+Yy45u2f45LcItlZPpxmlMeQW/wuLdBJJ4u
         xfNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=S+ehuLujhp6/6Ui8/ETipqTmnVB5w2txW2o3jJCUzuY=;
        fh=AgR6cfrukWIlx0p1FYwwjozqu3DN8psjukUNzkSUMHE=;
        b=chpPOo1LVOx6ZaH9Vd/jSg1nCUGx4p7kq99Xw59a1YEVHL2oj4B7aIgPPluus0iWgP
         C2mPQVQpqH3Xt4Iolo2u/dfXWNNaayVYVTBrSY+irLiQXdF8kRjpqYRI7dUGdZDd5f+u
         NtW1GHjietUAZRDWqSTB8Vxr2NRgFmoh1afhoAcpeLqUp7a0lQZP/t81FqVc+46Rvmqg
         jBXenYw/dpexEDM/95RsuyK4OLVHL2x8YfUWZ4nehfXypqH1cwAOC60zMn5sj/DVcUMu
         gMaEtwUeJyNfsTQnohBIFB3DaFKyCsGhpRm1WAnt/ciTHLrAkp807z+kLDOoglUnL9do
         kWFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=avYwfnmW;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70d70191d93si399326d6.2.2025.08.21.13.07.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-586-WPosvfoHOsCwuVYrna7ixQ-1; Thu, 21 Aug 2025 16:07:41 -0400
X-MC-Unique: WPosvfoHOsCwuVYrna7ixQ-1
X-Mimecast-MFC-AGG-ID: WPosvfoHOsCwuVYrna7ixQ_1755806861
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-45a1b00149cso6294495e9.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWXpeTDFrjgaxsO3ju35ht+QfnKHnEzVBRoyKVX56NM7TKXm55GfnJRwIlr+2ST23aYxxDzBUY/VvM=@googlegroups.com
X-Gm-Gg: ASbGnctW0QGt3wv33bVgZJDR7MeyvsSF7WjyMAvPdynFDQpKmMN1FLgNiz1Y7NJUfft
	3EaSXgDsqybq6i7DQBoh5wgDiT9ojb7Mif2SEWHE8nYj4OHbn03N/pHVkzpeLyaWbJZCEBd1/4Y
	KrxVx4Mu6JtWVVyuCif7JtnoyP1ywT82aPxzNmIratxu2qV0RLbSuKCoWypQ4RVSeP0ZvyyYRp0
	Ai201vqI62IhSgRL5jjwpjYzsqWk/XY8IugjwvtXwd1v3j21i+7bMjWZ4EyJU/njGOie8RiNNrU
	JxP/vqdEKX6/VzbRAJ8k+qBQ2H1ZKHmtu1al+zyfGGto8xE3cJOyk4kfno6eraM9vMDlWhBmrj4
	yTdvfSC9thTCi0O0JK/wvpw==
X-Received: by 2002:a05:600c:19cd:b0:458:be62:dcd3 with SMTP id 5b1f17b1804b1-45b517c2fc0mr3573015e9.17.1755806860556;
        Thu, 21 Aug 2025 13:07:40 -0700 (PDT)
X-Received: by 2002:a05:600c:19cd:b0:458:be62:dcd3 with SMTP id 5b1f17b1804b1-45b517c2fc0mr3572545e9.17.1755806860106;
        Thu, 21 Aug 2025 13:07:40 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-45b50e3a52bsm8600375e9.21.2025.08.21.13.07.38
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:39 -0700 (PDT)
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
Subject: [PATCH RFC 12/35] mm: limit folio/compound page sizes in problematic kernel configs
Date: Thu, 21 Aug 2025 22:06:38 +0200
Message-ID: <20250821200701.1329277-13-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: F7A3PTrFe_u4LzGaHXuRf3_-RVJybwWFaCivyeyoT5w_1755806861
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=avYwfnmW;
       spf=pass (google.com: domain of dhildenb@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
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

Let's limit the maximum folio size in problematic kernel config where
the memmap is allocated per memory section (SPARSEMEM without
SPARSEMEM_VMEMMAP) to a single memory section.

Currently, only a single architectures supports ARCH_HAS_GIGANTIC_PAGE
but not SPARSEMEM_VMEMMAP: sh.

Fortunately, the biggest hugetlb size sh supports is 64 MiB
(HUGETLB_PAGE_SIZE_64MB) and the section size is at least 64 MiB
(SECTION_SIZE_BITS == 26), so their use case is not degraded.

As folios and memory sections are naturally aligned to their order-2 size
in memory, consequently a single folio can no longer span multiple memory
sections on these problematic kernel configs.

nth_page() is no longer required when operating within a single compound
page / folio.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/mm.h | 22 ++++++++++++++++++----
 1 file changed, 18 insertions(+), 4 deletions(-)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index 77737cbf2216a..48a985e17ef4e 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -2053,11 +2053,25 @@ static inline long folio_nr_pages(const struct folio *folio)
 	return folio_large_nr_pages(folio);
 }
 
-/* Only hugetlbfs can allocate folios larger than MAX_ORDER */
-#ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
-#define MAX_FOLIO_ORDER		PUD_ORDER
-#else
+#if !defined(CONFIG_ARCH_HAS_GIGANTIC_PAGE)
+/*
+ * We don't expect any folios that exceed buddy sizes (and consequently
+ * memory sections).
+ */
 #define MAX_FOLIO_ORDER		MAX_PAGE_ORDER
+#elif defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
+/*
+ * Only pages within a single memory section are guaranteed to be
+ * contiguous. By limiting folios to a single memory section, all folio
+ * pages are guaranteed to be contiguous.
+ */
+#define MAX_FOLIO_ORDER		PFN_SECTION_SHIFT
+#else
+/*
+ * There is no real limit on the folio size. We limit them to the maximum we
+ * currently expect.
+ */
+#define MAX_FOLIO_ORDER		PUD_ORDER
 #endif
 
 #define MAX_FOLIO_NR_PAGES	(1UL << MAX_FOLIO_ORDER)
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-13-david%40redhat.com.
