Return-Path: <kasan-dev+bncBC32535MUICBBPXN23CQMGQE25OHJWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 24725B3E874
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:07:44 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-61d2d2b792asf1617402a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:07:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739263; cv=pass;
        d=google.com; s=arc-20240605;
        b=Zuu0XQ3jB0oilrsAgtH/BzxyqLHEy4NDHXmwx2TS2OX6qed0IAUfQGobRxQMoyKKP7
         2bL9oGJTpKJ64dFNHiOTFoUMrHPQ0VOp/tgHTfj/Nh93SoHf1lzlpKkfMkk9EjztrKH7
         greZSExF9HUvQ8hQza67c5Aww2BmfiRw3WbYaw6MlbGjJLLcoEGWP6jgqvdTjHYYN+0n
         KGWKY6wK544BdVX2xv0F+DcEwcXGwYbdohoXrhQ4U9SA+43mWBJs+YBXgtHy/k35JhAV
         /z5PvpiL3LU4TQqnWrooI1Mf/eB/RCrQET1snnu/oVKu8D95i0RPMUCGEW7G1U52/F08
         DFNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=jUfskquC0xDiliSGtN6wF/CZWkIR93t8iCdt2t3yTHg=;
        fh=1WmDF9KWODzCEo5hGBMiv8IUx1xWNSw5Sq7FEs6dpTw=;
        b=Cr59ayTGfa1xYIraPL5syM3wg+7JsLrHpiWphlE9gnwzwwY0aHBS6cZkL5ZuyMcxum
         4aloLtT78D8q0Q8K8pJKsxWag+DkTPlpEhLFyiSSRw4JFOGjl3LINTJbD6oG9yS+f6wM
         8pO1RO38PHAnwWAxN4NgiW7U2KwEudTDTlvrH0koxx1yzfzVwpheckB0j7Q/R05tbm/I
         tTksMivyhJhEF9W4XK4xUrxSRr4g5CSTgn5WKqzy6p6bRpPZCp++FCLx2kHJZHDJN2wV
         cMecP8hizb13PrPFGkyVCVzLDPDF425jDNBLnPZ16TZYL5lZTpg7bbvErl+YKqBRxm1L
         +m3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=AAcxLvWo;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739263; x=1757344063; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=jUfskquC0xDiliSGtN6wF/CZWkIR93t8iCdt2t3yTHg=;
        b=FYwJvx5l96kOM4NrO8Oz6laxZrVzUmPLnOctIJ9LyMbPOPRIgMRRWcR8CiMM7CgB4S
         ip455UsPFK3faq+1qk6DMaZWmNeo9ANoGZ1sXtsw5YcLPTpAjOcSfOEbyBinXWXxG2c7
         mg6BliUDDd9sive3uahnJdlv/GqIlzZLtMgKsu4j1GlcoZnJ74xXDa6AM3lPxWKzl8Dh
         gUoqOx/E41xAvyYhQpY8/pLhQBzlU7++Zb9S5jPhqnnktm3rBE2AtLl0ijFOWLgffJcB
         8lT3EiZUTsasbpTs6Uyd6CYDK0FxALuwsqiURYlqL+/ASDF4SFBZUvx+yrW4RULVfl3r
         MOaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739263; x=1757344063;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jUfskquC0xDiliSGtN6wF/CZWkIR93t8iCdt2t3yTHg=;
        b=s3fii7QL8dilYq9VLILkdweWSeAYXAh66L4hIVw29pwdKJBB8jGE55fPlJmHpYLTNu
         /6UIgInmvTsBFzxIpKvVQVneQGXLDIZnKxQU+w+vnu86T+XG/fhoN9XUgSPTCmPwNGcC
         7KDPfdHkZ3Uv2qZgOJydfBCc19kiv3aiFPsXmakMoYsCg+y8k/ba34tXQV1mfCJJolRn
         a30tj6+1UP1XHVpHR+8Gi8VAx0MxQTYeQ42HizlZXR0hJnB0AzhdWj+eDyXVmE0Sv6oH
         jf+renix3k6ZeF2OQBMB1FOPlcmP62AxLXoid+A2fU7Qt1FOaqn/wjdzsoSi8y6VnxVL
         L7NQ==
X-Forwarded-Encrypted: i=2; AJvYcCXWMw7tPuCxpmqsfG9vkp66LeyvC0wcbDxt7mcYGRdmIpZT0wvOhysWU28Wflbgo1NG8fYDrA==@lfdr.de
X-Gm-Message-State: AOJu0YwFcDFpGTBIaJ7Y6qoJToLwos0SgD5ncWw51WPVKal5/otLunib
	QfQ7oKSJxeKYB/GEs+EqB6gbTTwVTlx7mEW0dNmtRNqQMJ2EkGJ6ZK10
X-Google-Smtp-Source: AGHT+IFQ47r6mWT1WrIGJRYi0PRfOwZiEy0lpiVFk1flOtCJQgc8LZvXR0M2p/nfQh9Qk7xyqpV/sQ==
X-Received: by 2002:a05:6402:4306:b0:61c:948e:59cd with SMTP id 4fb4d7f45d1cf-61d26d84f73mr7800311a12.24.1756739263122;
        Mon, 01 Sep 2025 08:07:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf5OFofGmuagvc1AkS2Du+rpSE9vqodxuXXsxv1+MwIEQ==
Received: by 2002:a50:c30d:0:b0:61a:170c:1804 with SMTP id 4fb4d7f45d1cf-61cd3f77485ls3358271a12.2.-pod-prod-06-eu;
 Mon, 01 Sep 2025 08:07:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWmPZcnoIxXG1HFoNIH1BxkNYa/l9P+wPzrpyHanEBzgtYNZYcpKsmpvHuhLTAuOxWknE3A5XxlZvs=@googlegroups.com
X-Received: by 2002:a17:907:7245:b0:afe:7d3b:8463 with SMTP id a640c23a62f3a-b01f20bc431mr833081066b.62.1756739260175;
        Mon, 01 Sep 2025 08:07:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739260; cv=none;
        d=google.com; s=arc-20240605;
        b=hBM6r3UGn6itkw3u9tT6qWyU/pQNV+ujR9blwLEzixnFIGpfYNRwJUoRoGtNwDfcbH
         wUrf8Ts1yB6IL8/QrVCkEOY9OkFY5t4GzGg7JPvbJU+WgcaFpwfIGZHurb4coiMp/Vw7
         3gQ2unviTHitijXuRyLB9+nMg9rL+Zx5BjL3RFzEicISHJ4rBb7hPq+4GqCsS6YrFWCa
         CXM9YVBYlp1L/x0sCplDGjN3Jpp9BCjJqaqrPM9nlvpsS4ACuLl553DUpziD234eWzrC
         qbIC3UfhhHTEvwb1HijB+OYwh39PIdcFadC7GY9wV5m9160KTUkDftuWG96cbAoH6HPe
         TVGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1uoE6NXhltHN+7rLv53vXfhLviFP/GMqcI5NGlTVFxQ=;
        fh=HZd3WqDCB2w+hFqNxcu9K3GcyUiUuKc4ovslYdzTWiE=;
        b=S0aRpMDI+5CsigLv0gCNGqtpEk/U/x6YPrmx4oYl60CyVwPyRm571jib7oodK8Ysds
         5c6YaQsjQxJGjVVFBBPcxAlzMimamEDxBKVcIjaMdah8+mlj4Mn8XXNB7NgwafTQW4RF
         RvXx4XIG7d4j+8oY+MNH9XF10mflFphnMNOrh3JSk0XBZgG5p+N4z5c9wsWr7FRHzMHm
         6H+Sty/+63VYjHOfoq47wSW+p3CHjAbIFz3zblb2gXe2Cozk3YREbuV1tCbkJYEIQUad
         2UWJ7hzsP406xeq6GKy2HvyA/IQTq+JI/PNXmjcBY43yIS7J5Gvs/U6dhy1+KAOAqxXE
         BSBA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=AAcxLvWo;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-aff0d8f06a3si12493266b.2.2025.09.01.08.07.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:07:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-458-Vu95gNDhN86FCvXuoQpXFg-1; Mon,
 01 Sep 2025 11:07:34 -0400
X-MC-Unique: Vu95gNDhN86FCvXuoQpXFg-1
X-Mimecast-MFC-AGG-ID: Vu95gNDhN86FCvXuoQpXFg_1756739249
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 609CF195608B;
	Mon,  1 Sep 2025 15:07:29 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 9DFF318003FC;
	Mon,  1 Sep 2025 15:07:15 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Zi Yan <ziy@nvidia.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
	Wei Yang <richard.weiyang@gmail.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
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
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>,
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
	x86@kernel.org
Subject: [PATCH v2 11/37] mm: limit folio/compound page sizes in problematic kernel configs
Date: Mon,  1 Sep 2025 17:03:32 +0200
Message-ID: <20250901150359.867252-12-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=AAcxLvWo;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
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

Reviewed-by: Zi Yan <ziy@nvidia.com>
Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
Reviewed-by: Wei Yang <richard.weiyang@gmail.com>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/mm.h | 22 ++++++++++++++++++----
 1 file changed, 18 insertions(+), 4 deletions(-)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index 77737cbf2216a..2dee79fa2efcf 100644
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
+ * currently expect (e.g., hugetlb, dax).
+ */
+#define MAX_FOLIO_ORDER		PUD_ORDER
 #endif
 
 #define MAX_FOLIO_NR_PAGES	(1UL << MAX_FOLIO_ORDER)
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-12-david%40redhat.com.
