Return-Path: <kasan-dev+bncBC32535MUICBB4PO23CQMGQEBPNWCTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id D8A7BB3E8C1
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:10:47 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-70dd6d25992sf86767076d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:10:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739441; cv=pass;
        d=google.com; s=arc-20240605;
        b=gCLHhDFH9FvX0x7fbIBMLK6C28/ERwGoZrCD58C+jQqgRmDDUMfjKCFk+RmWW229Mm
         6KMR0rG/gPXXQlj+7Z3FLikcTqbo34+BOHGIE29SAmKWZu8JuQNLeseMclA99g1/OM8c
         mVDE6Dt9upEh97ifPe/Pl3M5RwNMh9mx0oROrFtWgDwuTim1JJdm1WBRMSFUxbup1i9d
         lfNjZCgX+cRuO0lpKaxbBFY4cCFHFG/rQTl2NXUAB47x5pgKBjQOPM1c/dlFHePElS4u
         M2DFJh1bYf4+MZuyt4sP7QLGsMG0iJxSuOLaG3PJrsBXL/7BLHfevrqkcZp3/VCRfAdh
         HVkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=da95YTGOei4ppVIqCn1YlYSZBOAIKnZFDASKAiS9vXc=;
        fh=vTx6PkxTf/FscQP26xC7pX65zVXJxXMrB8px8AOgiE0=;
        b=ZsoQKW5yrM/e1nMETle3hGMdi7ci836xJsfr4fyFGh1LptuaWbZQDkOm4xMXK4eMHP
         zPVvPgpl90o5/pEmohjM9zXQeAjlj+Lf4K5B5GTfnfYouhV4HfXvxnTczQoV9evnrWZ7
         6oR86KQvLcyXObp853xFVu0PAeVK165XH9e+Vg+VF4eAnwAY4/DKAZZjO8o7NIMcKb9+
         4R/mBhpDhOEWg3GTg75Xcdu8ttgsy9W17FJn6Or0piVsLg5DUIU+VGqts2qzHi/2dHzL
         /6DZfnrN9YZ5mxTN5dq4Q1CsVtieMjUsEcE2HjwHrd/L/IiAuvziwSxbYC/JTetdc0Id
         iStA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=LlLksyJM;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739441; x=1757344241; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=da95YTGOei4ppVIqCn1YlYSZBOAIKnZFDASKAiS9vXc=;
        b=vzO7kTm5nvHGIxRpDZtUi078QpDKX3HDVM+biTPkduGRyXkadMa1yAYtVANmW145zN
         TPW18CXBmsrc6tjt5kNIQuq2B/80vSTmzJkFKh6jH4DRL2+gkBkoGCWuVE4/Rx7Aewgz
         WZvHSzO/+m3+2Rt/rXQ8JXimNS+xH84lIHc0tKrDPefOVXRU3S2XSYTNRlpKb8z/kVZq
         ycR8+qgnq7cU5VtvFxPWkN9C665AFhAsYxsU1FB2w9jwlTduzbEn6hyZ3KKKdjv9NO1d
         Qb+En/FOJJQWU9CR6t/QYGmq5Q1CAi9AvmRptA34JCetsvXjgJDHpJ4pp9M4+20GsjxJ
         zt6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739441; x=1757344241;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=da95YTGOei4ppVIqCn1YlYSZBOAIKnZFDASKAiS9vXc=;
        b=ARL0oxHNCr6SNjTZPYa6X39YpDGBoI4zEARs9BTN+IhhCMB7bLeRWVh9hcEaQ7A1ZE
         uqmrE6sZDvYnVl3MvAsPl9pRHQKaBbB+Mx6ubhaqIxTeD6MV2+1aUiMgVmeANWS4Lf6t
         7KPrfwsRxNXb8ZgDAb+k7wxl7GR7JTi4e3upF5E/TUFohHZJdYfGTsGOeSVc62eq1eve
         ybE7LZI5YYx3JbBbYVtrp+5nbCouwZpas6pZc0uSfMe9oJp/P6NvHgUqd/qQSITclO61
         MGdTZlMrNe15145KY8K9lkVXqtgycgEwmU+MahnsTVNzSLGAaVuoPSRRbrK7yrvlbCm7
         AbGA==
X-Forwarded-Encrypted: i=2; AJvYcCWr4LOH5xAYrb3GAM64TI2/4EQXBVa5eBFNWXB9rJoWVpx6H4N8fFU/pInh9dDu7pwSncYvuA==@lfdr.de
X-Gm-Message-State: AOJu0Yw6+57r2q2Oh/0opdPGOVZIKzZUPb1dNSJy3N0neAc1NUmJdCnG
	ao1DUpIlpuNITZNpfTuWO/JJzT8PWigQy+xW6xn+3KYpG4Y0IpmhvqNj
X-Google-Smtp-Source: AGHT+IGxq9MhWLMITWuTbCboKxnwWqIxUgQb+v4U/FbbgxVEYajMKY8TOYHFcVCHzK+fIK4o/1q+lQ==
X-Received: by 2002:a05:6214:f09:b0:70d:f9d0:de72 with SMTP id 6a1803df08f44-70fac940a7dmr86551306d6.61.1756739441357;
        Mon, 01 Sep 2025 08:10:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdB0GVHVnu44C/u7DLALMf+o3IzSF0nkRNRoISYJ/yaFg==
Received: by 2002:ad4:5d69:0:b0:707:6c93:e847 with SMTP id 6a1803df08f44-714cecde8f5ls25074006d6.2.-pod-prod-07-us;
 Mon, 01 Sep 2025 08:10:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2kootEjpGsdzJquV3hgvUIw6xj4LNYswERTNpejIvlom1YfGEjHDDOpLyAE0csinG4eVYJglVgGw=@googlegroups.com
X-Received: by 2002:a05:6122:90b:b0:542:97fa:2b17 with SMTP id 71dfb90a1353d-544a02492b5mr2445610e0c.9.1756739440090;
        Mon, 01 Sep 2025 08:10:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739440; cv=none;
        d=google.com; s=arc-20240605;
        b=lt82fu5KUgkwcAj+LoQ+HMpb2wGeJRp0/7lmqvkGIpIW4UdrjXhXy3ckkf8RSS2Im3
         JbL3bnOGYQplwk3DWw2UlVUO9wlWj1+2QG6vzQdxcuNopRYyVgZ8D8ti/ZdOSrRQ8OxU
         2XmpWbd4+7+qbJc0N4qBPpchYFkI/zR8fEFEDyiep6aC0haMKHMmqJfx0VtR1dZ6h5zF
         aPoWcPQrYBPHH2xLz66lKvgRdMeAVqgInwVD2cfJHv6pD+ZUOsMKoPMrpFe9RI8AUus3
         /cwEgrzUXqq3JZpelEw0YtXUp8XPECVnY8vNd54s35HeN3gosxyVqL18qYP4ik1R4sH/
         A4cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fIzsdHZ3fBP51ER2numDMmmgvS6jLZjlCpLLEi+lFJs=;
        fh=+tnz5ic8pEoOAAu+mvcoby0ONgE28khcaSl2YlsL+cc=;
        b=ig30hIfxBHGTkPmf3gBO2nfJNC93E9G1q1PPqxqsABRWjS+R5iKtKLyuwwvwcNOkDY
         cI7tMY8CibnUevoY3rUWSQAs7jrgl+ZAYI2THHwDG0AtRkXacqWPIUV1bTXUQBp3Jfrn
         XUDK4uyyogQBrN1VQrhkccohsTQmaYBpOIBWVjqBE6rCs0r6OvcPsxriS9ajri6aTouu
         B2Kz7LoKXssGn9+ueQ03ObvA9pJlGM0BbA8X4Q0D7fmsZOZZTe5Zuant9OYI6RHPeHA3
         DPrBiwfcb1i1VCQaQd5UPTXV/bmm8UX3HMXMHOlIkk+YEX+QuKmVMQAROlVdnV8Gyb9Z
         cUIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=LlLksyJM;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-544b333f42csi129655e0c.2.2025.09.01.08.10.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:10:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-326-b49aMdn1OuiZpoH1EqfeVQ-1; Mon,
 01 Sep 2025 11:10:36 -0400
X-MC-Unique: b49aMdn1OuiZpoH1EqfeVQ-1
X-Mimecast-MFC-AGG-ID: b49aMdn1OuiZpoH1EqfeVQ_1756739429
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id D9D7819560BF;
	Mon,  1 Sep 2025 15:10:28 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 4F426180028F;
	Mon,  1 Sep 2025 15:10:14 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Robin Murphy <robin.murphy@arm.com>,
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
	Marco Elver <elver@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com,
	x86@kernel.org,
	Zi Yan <ziy@nvidia.com>
Subject: [PATCH v2 23/37] dma-remap: drop nth_page() in dma_common_contiguous_remap()
Date: Mon,  1 Sep 2025 17:03:44 +0200
Message-ID: <20250901150359.867252-24-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=LlLksyJM;
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

dma_common_contiguous_remap() is used to remap an "allocated contiguous
region". Within a single allocation, there is no need to use nth_page()
anymore.

Neither the buddy, nor hugetlb, nor CMA will hand out problematic page
ranges.

Acked-by: Marek Szyprowski <m.szyprowski@samsung.com>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Robin Murphy <robin.murphy@arm.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 kernel/dma/remap.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/dma/remap.c b/kernel/dma/remap.c
index 9e2afad1c6152..b7c1c0c92d0c8 100644
--- a/kernel/dma/remap.c
+++ b/kernel/dma/remap.c
@@ -49,7 +49,7 @@ void *dma_common_contiguous_remap(struct page *page, size_t size,
 	if (!pages)
 		return NULL;
 	for (i = 0; i < count; i++)
-		pages[i] = nth_page(page, i);
+		pages[i] = page++;
 	vaddr = vmap(pages, count, VM_DMA_COHERENT, prot);
 	kvfree(pages);
 
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-24-david%40redhat.com.
