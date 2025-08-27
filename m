Return-Path: <kasan-dev+bncBC32535MUICBBP4FX3CQMGQE4D7P3UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CD29B38D33
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:12:37 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-70de47323ddsf10671186d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:12:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332736; cv=pass;
        d=google.com; s=arc-20240605;
        b=TlgwTx/pJprEzBiXrObkIH/5QiuWlc5MKQwozQFlIL469csTzEF1N0rLyxfprakFh4
         Xqv+TsAjDPqVpTVDQbJZtPVRl12nLr708eqNJOteSnGz9DCLYJwsqj27nlnEAiuioOXT
         M3+qiL1GuNTKrA9jQ9Vc2XXpL0Q4W3UVeW3ywjQP6Cq4cr8DxNRGUjaGeNIaa5eLPl4x
         BhQsoOJW2gzlrrWvR+k3Wyfaqcg3JZOrW9bRQbaVQw8g5kpTn9jRqcKWX0jhMG4Yivo+
         iwO0nKR7FWX1BAOxQFqsjdLri+0zueME8Ha/qSufAJysUyvPl+rZmCLqZOYlQb2+/lcw
         zMbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=kTXF/O5B9LYuBE/mWS4XbTj56GupWpryfhWOjIFKdoY=;
        fh=w3YfYc3Bc+u8d4zXS4xVAv2yJ9Z4pu/9PbGl13iCz8o=;
        b=hLE/7nK7sgbvvjeWrlV8l614uAlGJ8eXR5A2jKdD825NPyY05i2+uh/l3QxTWNUTfX
         U2hIwtzQXVZ/b2uQwUUchOlkTPV97IUA4RRx8i4BHWKGjPYhzjoKlRxpO9dRBAuSsKU8
         gjqx7c2hMQOQqilHVUcWdCjUbh/4A7QHesFJnoCgcoAoM3RahJdoNFH9ue6KPVkG/zE/
         wVU4Rq5B0FJT0WLWRJQCB+xJ0PKDa4PJ/wmgqQIqSzQZKC5HbMtUccomqSE1WGBQYYBX
         R9/QnMIHY3WUJLMv4vLZPI22ynaTW1gcCAikLtwB7IcyoCPw3HlYYyB2e33CNrM/o6xy
         WBbA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=P3OXT2Gy;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332736; x=1756937536; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kTXF/O5B9LYuBE/mWS4XbTj56GupWpryfhWOjIFKdoY=;
        b=XTxs6UvjbI3XSetQHmnEmmAa2SpflfMvZKo3NcNhBELKnOudK7cDhCWncdUz26otT2
         7KGLrw9dnwcyTCYKp0x9nz7C6lvKPP9bumYyzVil8qHAOyfpxOkXnFlA8Ir+xz4ubynq
         GKz4EbLUQleLLb82/0VHUfct9tymTvPQzRUsS5gEa0KlqnXjOdsCWqv0nWvlj7nza4DM
         VFu55l0N1LJz7EZqr11GDcWSj1NNL40SMCfjMvBG8jJ1G4mKPR3FaWkB5sj0mzs5SQ2m
         lh2R29GCY9I2uV6SqpQItKJxEqeHrMIWjHX/TVn5v/52ugi8fFvxm3GSpG9FB9uSn5fq
         F91Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332736; x=1756937536;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kTXF/O5B9LYuBE/mWS4XbTj56GupWpryfhWOjIFKdoY=;
        b=vnzcD0qrvVcSe9gqZmMFYsq/tp1fYfQJ+LEGrS20N24njNt/oSqBxv17B89qlbDTQv
         mJ6sAR2XA0JpJQ/3iAUGaD6xMsODyFsxLI3U/s1oxtlAGYfgvT3df87nn/mURQq/m8Mw
         QU5rAb05UCvo4iFByLLAWfQGY5Fl9G6i9HCPE5LNZAtItwI3YW2He3Rd7+HMfqNXpGDl
         t5PCAJ0BYFbpBr+Dtq7/UZTvIAAKsEv/eQ4MtjJ7dpJpaMGO9WDfiM0n5zj6zkZN86nU
         0KlGKdhdaVnwgXzwxI+g11FmfqQ5Vwv2pDFUTUDToshc6SsPYgwUIK8J22yCXGG8k9Fm
         we8g==
X-Forwarded-Encrypted: i=2; AJvYcCUjMLj0wszeqat/ZvbV69lpXhqsWOlTZBcLR1x/6qkZOOPV7OLYLnsb0yu/kG6gLrPUjomeqw==@lfdr.de
X-Gm-Message-State: AOJu0YymgOEoHd6F42rb4n8W/H+PQXh9wobTJeHL7EXIjO1LowBYKfkI
	/M9a1/l7W4XbK3wNwAbHEHZokmFbEg7+DSCaWD9QHWljaOtwTwQ8LJUO
X-Google-Smtp-Source: AGHT+IFC9r1XTDTehS00HTOH/RSDUijZOzfZAdMhHDnLLtOhNozZ1viIOymc0YbBCr8cm/5U4LFyxA==
X-Received: by 2002:a05:6214:e69:b0:70d:afde:8784 with SMTP id 6a1803df08f44-70dafde8dc9mr169119836d6.26.1756332735948;
        Wed, 27 Aug 2025 15:12:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZftzfU3PB0qTk3vnjl8gZikk0OJxnGe7oc+RBEV2VUYFg==
Received: by 2002:a05:6214:3016:b0:709:f373:9f9e with SMTP id
 6a1803df08f44-70df009ec34ls2575976d6.0.-pod-prod-04-us; Wed, 27 Aug 2025
 15:12:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVHXclrlJBoQWWKx5N3EAJCX2+thjNeIMCTk6B/aHG3JwjfPUCwiduWEXl4kbqo4cE/l8QzkLnlCso=@googlegroups.com
X-Received: by 2002:a05:6214:4116:b0:70d:d36b:a7a1 with SMTP id 6a1803df08f44-70dd36ba8e8mr87113836d6.2.1756332735182;
        Wed, 27 Aug 2025 15:12:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332735; cv=none;
        d=google.com; s=arc-20240605;
        b=H4/tnuA+Bb/6M6/rkhhNLIDLv1r81b9ahEe/qYzIx8jqg/M40hLVHai+1BT8A3GNzl
         n9/fiP/weUld3JLEB6ibiaFH7EBlfS7jnsTsynGV1fUQO77zaxaPt2pE3WcYKsVEqt5I
         3nxXnqI3m8M9vHU+QWxEexDa5Z8fhhWPg5j3Z1HAc0DRnNAsrpft4INc4csASY9HMP1Y
         MMsQdUJaRdfkQW6/U3uL0v+03hbqsQ6RMuVt8A+H2pCfV5rYdT5ybVr2x+bQj1HiwDok
         P1kZyvljI9l+rGy0AeHHvbaA3j6ysNMRTz5JCYhCTHzpvJ2Alfwpx+G1feg/ruqOkj9l
         Gsrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Z7iPpUiW3LrFM0W3XrB+Z82uodwKTsefoCzXwhLbLUo=;
        fh=b8pL5mxsrifaEynZEGzAqvQF5L+S8U+H1jEuAVk/IKA=;
        b=QH9mG9cipjbBjNPOAomGvhlRRvqo3M0u2xwGRNna1msVxMQ41lxg5m4jxSAEQeRlKx
         xEKjuPmD6xOVn9/vwBYP8rPbc5pr+/d2I6IJ3/eVz5SgtVfQpI9V6v54GzGOVsZMuKSP
         TCiB+0OdARl4Wo6I8aygVYTz2Ph43T1bMJnuRd1sGLvPxzXNoqF3ERADEh84lYoSc9Ji
         SkucGG6MRiY6FvyqDadK/w5kxyuUfOH9h/iyy3B6CDa3CwPKJA39o3sjfMNSY2Iii4AA
         /f9pgfz2CJ+iPMnnNTMxjawSG8MEFQaM7nbpMUMI5E3TianspxDYWOEVH60OV6xhQN9J
         c74w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=P3OXT2Gy;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70da71ee876si4883276d6.3.2025.08.27.15.12.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:12:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-636-ShHxITs4Pxeui_5CEKaCgA-1; Wed,
 27 Aug 2025 18:12:10 -0400
X-MC-Unique: ShHxITs4Pxeui_5CEKaCgA-1
X-Mimecast-MFC-AGG-ID: ShHxITs4Pxeui_5CEKaCgA_1756332725
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 8CFA218004D4;
	Wed, 27 Aug 2025 22:12:05 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 7D11F30001A5;
	Wed, 27 Aug 2025 22:11:48 +0000 (UTC)
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
Subject: [PATCH v1 35/36] block: update comment of "struct bio_vec" regarding nth_page()
Date: Thu, 28 Aug 2025 00:01:39 +0200
Message-ID: <20250827220141.262669-36-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=P3OXT2Gy;
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

Ever since commit 858c708d9efb ("block: move the bi_size update out of
__bio_try_merge_page"), page_is_mergeable() no longer exists, and the
logic in bvec_try_merge_page() is now a simple page pointer
comparison.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/bvec.h | 7 ++-----
 1 file changed, 2 insertions(+), 5 deletions(-)

diff --git a/include/linux/bvec.h b/include/linux/bvec.h
index 0a80e1f9aa201..3fc0efa0825b1 100644
--- a/include/linux/bvec.h
+++ b/include/linux/bvec.h
@@ -22,11 +22,8 @@ struct page;
  * @bv_len:    Number of bytes in the address range.
  * @bv_offset: Start of the address range relative to the start of @bv_page.
  *
- * The following holds for a bvec if n * PAGE_SIZE < bv_offset + bv_len:
- *
- *   nth_page(@bv_page, n) == @bv_page + n
- *
- * This holds because page_is_mergeable() checks the above property.
+ * All pages within a bio_vec starting from @bv_page are contiguous and
+ * can simply be iterated (see bvec_advance()).
  */
 struct bio_vec {
 	struct page	*bv_page;
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-36-david%40redhat.com.
