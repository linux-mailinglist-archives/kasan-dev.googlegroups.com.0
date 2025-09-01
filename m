Return-Path: <kasan-dev+bncBC32535MUICBBBXO23CQMGQE2E2CINY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 930FDB3E898
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:08:59 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3f46ca1f136sf26517855ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:08:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739334; cv=pass;
        d=google.com; s=arc-20240605;
        b=HyyvmYwtStd9XUASEgV59GfJW2NbZZFHNQr2WhBP0tJRPQxB8hw8RCEoy/2V6cYW6P
         G404SYhbtNRPq2mKa8mPQ6uc/+Nfk5hjHGFe1X+E/tAqNT5jsYvbLgij888pl6nVypwr
         FKfOIkfNQqvg6/2Tbd2c52TeykbuemHw7fvZaAtPoljUuEztQ2MooUHp9N6DeO+QaE3I
         UPbeCNTJIHC4jho2mOdT0AQom5oRxd99aUaWtW/k8Q3gRGZokti8KdJX1iGfILg3wqQ1
         zDr/0fQO6yEaDlJdq0/Ps3rcXwVLE7f1H/qUizCrmK2rIIaMBi3c6Xswa6QAsvkn1UGM
         icBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=xNfgvI8ubv22NQVDJdXMfhQvuOvtQ27wKYjMQvQXDy0=;
        fh=aa2W5cz3qroEEfT4qhAc89nS7NBSBEpld4hXOvT9oyI=;
        b=CrKmB1qLW2qgY/G7eLSn5bVN30NF8WridmTzQJwW3Ei2XbAkZDDR1tHpQvBVV8nzXv
         pmmD9qUTkHedIr71u/Mpr/v1L+v+rkrOQQkV+UL2faoCRt5LAfOj5be1cq/Ql66gBguN
         a/ImTgZuYb88sUl9hHQQk3TF9LGILGYz00iu3yacw57Dvj3lQ+i9Murcf3u7nfPAMNVv
         ySMIb/8jwVsStSTfiAtsiygn8ArcdOz55IgwlAu0/HA7Uv2smuBj+/Nbt9a+Tiou2Hc+
         YxzVOMLUC2UWtDkJ9iJ3ypqffhU5gkEn/CZBQ1B5h2i5lb5bgwpjBAjUp0MBTe0cQ8gN
         n4uw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="OAG/+N5Q";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739334; x=1757344134; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xNfgvI8ubv22NQVDJdXMfhQvuOvtQ27wKYjMQvQXDy0=;
        b=qOm3Y+V1KMrSC4g9Yw6T8RrRB8phSaOag5rDzv25TIvCyJOKnZ3CRl0NRhx+rCNhrM
         W1l1jw3uhfN3BO1JJC2XOTpfW8OkGL8i2LmBjoGu7pNvjHo7Z/AB9y11X1tCoZSfSh7z
         GOha2YVRXY7DYfrLsNKAryImDpPxzumDmuG0V5gEmoANZGyg4GXzIvlTr7w/H0XhbvY0
         n8vVoX08zrN5HwmWPcYGT/yHRDRbtT7b1OT7PNz13RgH5f3wnS4Z2eMky4tYm3lHwl7L
         Ke/r2ZPZZvXDDyro2iIZbD59e4x3QnqDJafkLOaixEhaSrlRmh2KA6OdMXc9dQ/lIZDP
         Hb3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739334; x=1757344134;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xNfgvI8ubv22NQVDJdXMfhQvuOvtQ27wKYjMQvQXDy0=;
        b=HVYtbHnMI+c/766x3seVX0LrxhoDa2lPUPyZLTAOUI6TmJsu7s35XFHiw++GkvnGFX
         khjFTNigbF+uZLks9LyAliltTBxvBWGLiS2IGfhE1kTahbiLJw1u3qTIL5RVY3X+GF4L
         swohk52FSXiwj+O5/bGEb2B9F2ZOMsbqhgpmLpKO5Z10TC8dseH9ysaUAA1YTxjHm+CN
         SFbkmzY1L3ala0+jzRrBOUMx/sRWjBF4/Ziqn9AJu/vY+tJyWiARtedG5GWVFVv0WzIr
         JEBdRTlJOLlGIIAojktIDGyKBY6LLhEOu5/Nuh2YXx8l60yEyUPv/Q9uYCWYxVhvP00B
         ufbA==
X-Forwarded-Encrypted: i=2; AJvYcCUQc8f1wgKYgIgUfojoasHFoXYinIMa8rAr7Fw4dgO7oHvZ+Bfw+qBEEATP6hlTBtU94j22pQ==@lfdr.de
X-Gm-Message-State: AOJu0YyWNOeSgJiotrf0TL4bffo1Os7qNrqkFkUJnbhy7s3Fs/U+fHaa
	ia1b0oUNOxS2ALbNTlSNxB7iVeddxOl5tpbozcr6ofQymohAjlsLGDY6
X-Google-Smtp-Source: AGHT+IFTQmKXPc5fTFc3wUzhkoLMHAjuMOcYzHhIfnG9tqV+W8rG0ykcfsKuB0W8ZGNSiVgAvz7qKw==
X-Received: by 2002:a92:cd8b:0:b0:3f2:4d3d:ded8 with SMTP id e9e14a558f8ab-3f401fcf5ccmr149740555ab.15.1756739334346;
        Mon, 01 Sep 2025 08:08:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd+YhEo994uKi7pDTRWWkFRdMIwhBJKgMXII4wMGUPN7A==
Received: by 2002:a05:6e02:23c9:b0:3e6:6922:1bc1 with SMTP id
 e9e14a558f8ab-3f13a3fe6fbls31557925ab.2.-pod-prod-07-us; Mon, 01 Sep 2025
 08:08:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXePuY2O/ZN9Pul0xKo91YOTg8fL15oWvYmJOdAqcdnszEwP7uOmuR3qCZSX4eDByaX20NyGlKCB1w=@googlegroups.com
X-Received: by 2002:a05:6e02:b49:b0:3f0:62bf:f1a with SMTP id e9e14a558f8ab-3f402ab65a3mr183795185ab.29.1756739333096;
        Mon, 01 Sep 2025 08:08:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739333; cv=none;
        d=google.com; s=arc-20240605;
        b=UnWMr2nOiW7Fx0JCT69LGdN0MhfEsCWjS6ZI2ogoBYLA8Fpjz4YSQHPD2TMApHY/Gx
         d4CT6xM8xEiagZAQ06169foxShDUwt17Ql0zofJdiLCmH/2Ip1E8V7z+Q+bouUR0SO5k
         /LyMgtLUkF56+jjOCsUei0jEDc485BvA2jVnuaTmWNGkytX4SlljQegk5+ud++NXz8g9
         LPUzFFLMUFN1zocoyOX9q4z+r1Fh+ucrVAjzu+nAgPAPrKKkFOctDMZP2rUCnoAwpXgC
         o/vkNmmbg8uQa1m8JuyKwCcQLR3kOMAUNHedMw1CfhjbYcmNkK+I+AoYDSfn5mIfJudI
         gWRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=h1YA5SEzriG6DwRMDjDKDzhTIS6PJdzeBsQAf3ehrUM=;
        fh=Le5UCAyHFARpvd5xG7qbGRmMIMGH6cdg0dbHcRTfhZI=;
        b=B+uAnzd/M9AVyNbYXfzIub0tnQnl/YB9d47mkt0jccUNVczn5CSYFZ7invx9TerjkI
         ypgylQkySTWYAZwpL99S6uPFlg8aCNRDcrshGHyaSbLZEWzcWC2ynxdeKZYSzlWvIraY
         K0ciTtPz44fjQ/2knHU6OoREVGMxvQLGIFGOZjP4DJTnMNN6+8TZ9TAn7FSqwqMCBft3
         Z+H2k3XpG3H73GWzMtuekJSYOEiKUei6z0can6z8lW94MlfBP57a/19TG2wG+7oKlhBr
         hoPzX1jOqgvh0AaXZU+pULCTmzFBPpUXnrcXmcKJjELemeqUL8UbGNBKrxycqHMVW7em
         AFaQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="OAG/+N5Q";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50d8ec80f62si199332173.0.2025.09.01.08.08.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:08:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-155-r4d3g8gTOkynYA1ac-wgQg-1; Mon,
 01 Sep 2025 11:08:49 -0400
X-MC-Unique: r4d3g8gTOkynYA1ac-wgQg-1
X-Mimecast-MFC-AGG-ID: r4d3g8gTOkynYA1ac-wgQg_1756739323
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-02.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id B11E01956089;
	Mon,  1 Sep 2025 15:08:43 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id D5D1C18003FC;
	Mon,  1 Sep 2025 15:08:29 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Zi Yan <ziy@nvidia.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
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
	x86@kernel.org
Subject: [PATCH v2 16/37] fs: hugetlbfs: cleanup folio in adjust_range_hwpoison()
Date: Mon,  1 Sep 2025 17:03:37 +0200
Message-ID: <20250901150359.867252-17-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="OAG/+N5Q";
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

Let's cleanup and simplify the function a bit.

Reviewed-by: Zi Yan <ziy@nvidia.com>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 fs/hugetlbfs/inode.c | 36 ++++++++++++------------------------
 1 file changed, 12 insertions(+), 24 deletions(-)

diff --git a/fs/hugetlbfs/inode.c b/fs/hugetlbfs/inode.c
index c5a46d10afaa0..3cfdf4091001f 100644
--- a/fs/hugetlbfs/inode.c
+++ b/fs/hugetlbfs/inode.c
@@ -192,37 +192,25 @@ hugetlb_get_unmapped_area(struct file *file, unsigned long addr,
  * Someone wants to read @bytes from a HWPOISON hugetlb @folio from @offset.
  * Returns the maximum number of bytes one can read without touching the 1st raw
  * HWPOISON page.
- *
- * The implementation borrows the iteration logic from copy_page_to_iter*.
  */
 static size_t adjust_range_hwpoison(struct folio *folio, size_t offset,
 		size_t bytes)
 {
-	struct page *page;
-	size_t n = 0;
-	size_t res = 0;
-
-	/* First page to start the loop. */
-	page = folio_page(folio, offset / PAGE_SIZE);
-	offset %= PAGE_SIZE;
-	while (1) {
-		if (is_raw_hwpoison_page_in_hugepage(page))
-			break;
+	struct page *page = folio_page(folio, offset / PAGE_SIZE);
+	size_t safe_bytes;
+
+	if (is_raw_hwpoison_page_in_hugepage(page))
+		return 0;
+	/* Safe to read the remaining bytes in this page. */
+	safe_bytes = PAGE_SIZE - (offset % PAGE_SIZE);
+	page++;
 
-		/* Safe to read n bytes without touching HWPOISON subpage. */
-		n = min(bytes, (size_t)PAGE_SIZE - offset);
-		res += n;
-		bytes -= n;
-		if (!bytes || !n)
+	/* Check each remaining page as long as we are not done yet. */
+	for (; safe_bytes < bytes; safe_bytes += PAGE_SIZE, page++)
+		if (is_raw_hwpoison_page_in_hugepage(page))
 			break;
-		offset += n;
-		if (offset == PAGE_SIZE) {
-			page++;
-			offset = 0;
-		}
-	}
 
-	return res;
+	return min(safe_bytes, bytes);
 }
 
 /*
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-17-david%40redhat.com.
