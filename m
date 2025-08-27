Return-Path: <kasan-dev+bncBC32535MUICBB74BX3CQMGQEC4AV6AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E559B38C3F
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:04:49 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-b474b68cff7sf245672a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:04:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332287; cv=pass;
        d=google.com; s=arc-20240605;
        b=fTSGsQQ0rqG+pYu3ZHewyKwyJzngT2Ts0Hp9VoU1XpldrUFVyTCMYjdJgvyuqyd3zq
         aJWBdS4xpFuvlQNmnNd48u7H6AudHA0kuMSN4b4/l1FbyOwwwmcCvChXXmbR8qj8d0BY
         qCYoz7a9pTn/aPfPg8cQ2LG08IMj4yQGONWEi1Sfk8gY8z1GKv4NOYH3g0eyWh9scwRY
         3Q+/qcUtZEeOWC+BRlDw2oZHS40/b++9s9f2mLclFV5QS1+5VFJN5vrMzEw2Q/S4xChL
         kPPHpFBRlLxHrghpEyCZcF/g0TdH+XUiR29C+cgaf34pJsAnv0GDT5+wAGqSrRuzfxS0
         lNJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=yE/1gqP9l/DOdYDF2EpOMSrNfuNrs/S1fVsc2fakHlI=;
        fh=Sed9BI6Th+1aYPotVhPzP6rD9DODAX/qz8EmdSaNDac=;
        b=DCKsMdKhHpMBEJk1Dbbtqbyq4Kn+7GCTHwwLr8k253CxCadTb9ub8znssTQ+ebZOe3
         3juZC/yeVgWZLLhCnba2hC1ik8Jrun9LQRAE634co0LQGKCqNaW8i/P4AJlCbtbAvgjF
         GRDR/ELmRzCJJabLr4/xk2ggOP7Hh9lQwvPETsy7RDGKxPpQplxzCdvGNpfmCNanvVLj
         UYlk/o1crPue7Pr6Uxzk1G+CvNd6l/6Lx9S0RltArGHD1FKQC8kSE7gSptwcJFPNRTr0
         kslvcNChdgls71A2B3sVJungKdsRTjgR7ooI8U4pZK09kdYXIFIrqIh9e3OQlQ9zxPMT
         i5WQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=cOFZHkFk;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332287; x=1756937087; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=yE/1gqP9l/DOdYDF2EpOMSrNfuNrs/S1fVsc2fakHlI=;
        b=GHsvXuKni/RhNMx1MRY0erJuAQqzaq3StHPAdXSRZxHAGlvroz8w72I8ePk0ZGPuSp
         O6WsGtwj7i7MXcxnrPNF04M90M5q7CtTxOoKdWsyKRUXXowfb4yAkzbmlewQ42lZg94A
         GIR6awKdXixD9FX63pyKnne+PhV5080FwjBF+RcyI7DU7M0qmYkVTlxIujz4VcAiUMCn
         bl1WSOf3zF3gW5F9m5X2yDVoi+92OGy6qwy4hxZWveiVgoAl2P8Y+R+jYgyPmK25fTEa
         tVEp0M6B152fGXOud2v9iLBMgp2jKkwmfmZKA2sQHeF5CvQ3z49hyhTmFufgcPg9Z/uL
         TSMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332287; x=1756937087;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yE/1gqP9l/DOdYDF2EpOMSrNfuNrs/S1fVsc2fakHlI=;
        b=QK+chbTUfKdLDljbabes6VK8AusspWGMV5eCru31r+2lg+Prc8/vpTHePlNfoBDMYM
         i+ZAjdlkbWqI04CdzCg+gutRc/M4hJRY1A8TUEBBT9mInBNOCsIYBQO9yMUM4VGnKX1Q
         aCa5L/2VfczOM2BJIiOAz7OuOt0uMQ2rfpwa7OYCK2d6OYDpOgG/E/N9DCaLqMszgsVz
         orZo+h6QqE2wwaNMHiIrr2GmGC+e9obYPAiCMf1k4VhI0KvBMExWleNyRjXB0nbbSwvJ
         nQ0Qn7PnFz9J4U8y8FqxA/ePJtDjwrnJCehy9J4lbDJZPrUwkdzv6m6suS68NtJCR9yr
         aSBw==
X-Forwarded-Encrypted: i=2; AJvYcCVCmcw00uFCGupdHfL8YDIpOiBY0Bb4XUkix/JXIv8mHhJ/ilOsODf7LdnqXcs1lps/LAClcg==@lfdr.de
X-Gm-Message-State: AOJu0Yy6EW6vvOpmm+Pjb5byxUZYknLvgLC2Cbzuri1p3ffTNfYCL5hc
	HxZffKCKDbTkqn5DbN0zUzD+gcEXc6r9B+MDDtWWfBW+/NHJoXlWQybH
X-Google-Smtp-Source: AGHT+IFS1acy15cDhzvuVbsJ5z4rBR/G4AdxiYBCkfhc2aXGM0jthKC5nzhl6ydb8WZzjNM0Pz7XSQ==
X-Received: by 2002:a17:902:ec88:b0:234:bca7:2920 with SMTP id d9443c01a7336-2462ee59196mr331421065ad.24.1756332287494;
        Wed, 27 Aug 2025 15:04:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcPDHHjcHL3n3DzYxb+/JcJvPVKYUaVU1P7XQJ/ijfduw==
Received: by 2002:a17:902:f9c4:b0:246:7333:30d1 with SMTP id
 d9443c01a7336-248d4e86a5fls1054945ad.2.-pod-prod-07-us; Wed, 27 Aug 2025
 15:04:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWatW+Ux0n9abHCAkAZcgTBSGQkxZGx6abXVf8QZkE7msZdIAjT6SPUlyJEofP73PAI+5+Lknik4Nk=@googlegroups.com
X-Received: by 2002:a17:902:d509:b0:246:7a43:3f66 with SMTP id d9443c01a7336-2467a437649mr237738385ad.7.1756332286116;
        Wed, 27 Aug 2025 15:04:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332286; cv=none;
        d=google.com; s=arc-20240605;
        b=fU3OipNzfLN11qzp0a2nyB/YXRpIV3S+sIkoybp9RUWynf9msWfcSKyhmcna1Pddcr
         z3qfOVEGG9U1rfJTZPXMa+/wI0/yR4MoTiX7SAHyIY0Ov36F4Vc397DVxwXFQ3X8RCzQ
         UNb2KiwLwVs5oB9zmuN5LCW+C0SJnMHd6A/5ZybWfvODNhQZWFbIlNsAvRY5fFVKuGn3
         k+dDbXAJs8yXLVo83t3enf6ruBOD6sbDjOiskm9UdzH+gIimJC/r7l3ledBi93o5A4mR
         N5RsWAQ0yA8fLose/GUFy538tAHP4f1DMXud7XYwGz/XFtuFkqAN0kfYdoU99egktklI
         0JLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=IPdRkz39C6GEGewoqOPx6e5B77yZ10PZ9TzgCgWDUu8=;
        fh=b8pL5mxsrifaEynZEGzAqvQF5L+S8U+H1jEuAVk/IKA=;
        b=e7EgZX6brRWPEo1ppKgtOKMmxUMJyI/7A+SteJTdsh1B7x5weJRrmFMq3bykhQ4xMb
         6uSFHBGQ0cEb4IDqo/DfeIg6/utt9ktKuAEdsv4Yqnob3NZbQZZN/yjap7sTXCH56yf0
         zORikEYLpndksKs3BqqfbxSHU3xdjTjcIGkbyNLYfaMEdYlhBb+uLMg0U0oKFCEU3wg8
         Xzv6xYEKwlQIozK16mTyM7udFwuBBuHBgys/IBa5/F9O/Mg0XHqtNFLHS1f8z+BwYiv8
         5GKb9kver2cR6yYjCgW5qqGKc5MCODociOi7c6/KQesWMqLmPVAkkEEt9/FXU4aqLuGP
         rlaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=cOFZHkFk;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-327415067d9si290313a91.0.2025.08.27.15.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:04:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-140-ejq5WAESPvyYJNhJ8vcpMw-1; Wed,
 27 Aug 2025 18:04:41 -0400
X-MC-Unique: ejq5WAESPvyYJNhJ8vcpMw-1
X-Mimecast-MFC-AGG-ID: ejq5WAESPvyYJNhJ8vcpMw_1756332276
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 3C407195608E;
	Wed, 27 Aug 2025 22:04:36 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 9EB3E30001A1;
	Wed, 27 Aug 2025 22:04:20 +0000 (UTC)
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
Subject: [PATCH v1 08/36] mm/hugetlb: check for unreasonable folio sizes when registering hstate
Date: Thu, 28 Aug 2025 00:01:12 +0200
Message-ID: <20250827220141.262669-9-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=cOFZHkFk;
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

Let's check that no hstate that corresponds to an unreasonable folio size
is registered by an architecture. If we were to succeed registering, we
could later try allocating an unsupported gigantic folio size.

Further, let's add a BUILD_BUG_ON() for checking that HUGETLB_PAGE_ORDER
is sane at build time. As HUGETLB_PAGE_ORDER is dynamic on powerpc, we have
to use a BUILD_BUG_ON_INVALID() to make it compile.

No existing kernel configuration should be able to trigger this check:
either SPARSEMEM without SPARSEMEM_VMEMMAP cannot be configured or
gigantic folios will not exceed a memory section (the case on sparse).

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/hugetlb.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index 572b6f7772841..4a97e4f14c0dc 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -4657,6 +4657,7 @@ static int __init hugetlb_init(void)
 
 	BUILD_BUG_ON(sizeof_field(struct page, private) * BITS_PER_BYTE <
 			__NR_HPAGEFLAGS);
+	BUILD_BUG_ON_INVALID(HUGETLB_PAGE_ORDER > MAX_FOLIO_ORDER);
 
 	if (!hugepages_supported()) {
 		if (hugetlb_max_hstate || default_hstate_max_huge_pages)
@@ -4740,6 +4741,7 @@ void __init hugetlb_add_hstate(unsigned int order)
 	}
 	BUG_ON(hugetlb_max_hstate >= HUGE_MAX_HSTATE);
 	BUG_ON(order < order_base_2(__NR_USED_SUBPAGE));
+	WARN_ON(order > MAX_FOLIO_ORDER);
 	h = &hstates[hugetlb_max_hstate++];
 	__mutex_init(&h->resize_lock, "resize mutex", &h->resize_key);
 	h->order = order;
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-9-david%40redhat.com.
