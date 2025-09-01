Return-Path: <kasan-dev+bncBC32535MUICBB7HO23CQMGQE2LCCXRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id A6A13B3E8C2
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:10:53 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e96e47cc603sf3283469276.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:10:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739452; cv=pass;
        d=google.com; s=arc-20240605;
        b=iCLfVER0r3KeHJ+IctR+jRnyj4ldFGAN1oNmZ1tyfpAHt4RAAOuqYOwOseT26pHnbd
         +22NlsJjk96XkdziwpdaFComj42iGVZt6jh2TcKpN5cDyFAuG1ZLVW2R7pQXhY86qebt
         +fE+F/pN19aAy/yNE8PGLec6uaiy6cgfI+OpF8VxrwVeb/E07tg65KrzTDP+LXlskIzl
         vB2lq82TpsCQwz0LPujK9M5Pf6L7futnPE1OpGfKBDKXdLpWfeuemkNALjL9q9/msZlD
         9IAt+L8zTC5Rn3GE4i2flg6OA6RHv4cfxIKvVF9HoX41OklP+Ri62q3pgNBDtwj2a7EO
         jSAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=fKv8oUiVvNu2gltyJgdiFRsy0uoDFCOH5yTEvVBfIWk=;
        fh=4muUOA2IrEdAKWgpJhw7+dECEhD/TIAIG8nE2rCsTB0=;
        b=dxuwJCJBvrU2TMDCcWdfdrKxY6WSbJD+SZNpCGTZ7MYRzSBiA291AjVvvay//EO0/B
         LgXs9sFCAxdX05tzhcZoi/u/San5mhDgNqehrGrJ3mUZfLOM/nwkjiVhRzO51UxuFMiA
         S19GBhnH29ZLaGfuMN02P42XWPouQpahDq3I+3o0XSzIHw1HWbROqdpiHO4ZzuUpBIBt
         ClZ1JEvNp9xfM8WOJdjIpxyKxYUlvVoHOWPsmyk6q/ZLze4Xvky47/9y7IYy9QrTg/r0
         2m0+8g4s/uoX+qTh01PPE7HMwnlwwE60svCLyQkwu4GnY0kaIAsxS+NzvgKbIXjqgHlX
         GtqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QPmeg1IA;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739452; x=1757344252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fKv8oUiVvNu2gltyJgdiFRsy0uoDFCOH5yTEvVBfIWk=;
        b=ZISB/3ovcbMRUk0+oDK/K0Rq/0BSd49f8KXoJVHApCbh6EZf2MFD1Pkbi2rDbKwcuP
         qmt0n547KYgUWs+ov/lLZk9ADQu7b6/tie2l22GNPw2w41acgdokR80l1Slhmqk7EWTd
         u4MQwVwCBNE5BdG20OVtzGz34qSbjpLKyahS1g26xPgz2IlH5raImrhMpn3hBhMa3BjI
         Yys7YH1S3HhJmeSO3jydzo4whVgjXPw1yx44aat6DKQkQ9UFa8NaCJ7F3eGWETjAVZ1k
         TgD6LRM+r2hPjX4PL+J7kV4f8G/yWqvAJ9kfsgQO9pSghodopmhsyfTmGbWHX0BFooHX
         iW1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739452; x=1757344252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fKv8oUiVvNu2gltyJgdiFRsy0uoDFCOH5yTEvVBfIWk=;
        b=k7BhNuK/CvUwD6xNUym0qSa/dPp8dqJnCoyC4JGulR1JWvGIEYAcgaJN0FJq3vlNin
         6dDFrpKciiMEeOrAVYLZ5j3Nzkt4bwrnXjrNN9Z2a5ixZP8lL1jIl05QMYfJmm06lE8A
         ZdFWFUOCtQarpDk0YRBHyelSvepP1dvic2ITWZBkMsQuf1u1Jy/79wATgOf0VllzdjqC
         /OfsW+3BNjxJjZJHAebVuLwVi5DAwaD//ithg+M8qjxbPM9LRb5kyQiv9rjK12f4sWGz
         puTYdxKQNAuhwD2beTkRZ7oXcD6MiW8JcATquvZWk+a09LWLozSs9p0yUs0vY55tN2ud
         EwJg==
X-Forwarded-Encrypted: i=2; AJvYcCUT8DCW8jQ3mfh2ZlNevuJTF3NXI4aYv9xknglnL7DOA9Xy+bJCz2LxjwRZeVyrAu6HaeXqwg==@lfdr.de
X-Gm-Message-State: AOJu0Yx/gMaSsVm2Tid5IjjEZOe+Rqqv9C4jpOtJBWt32c+39NtI4YXl
	SE5Ly2ziCmenjWWEmaG9ZLjmzF73Bx2LGmUkxF+WAzafpIOqMWANEWWR
X-Google-Smtp-Source: AGHT+IEq2qBaYmodiXrZP6TXUUbMvGA2nqbDv7GIrWooizckoQBeoZ59qiDO7SD3F9GAl3eJ3PtFrw==
X-Received: by 2002:a05:6902:4a82:b0:e98:a36a:7633 with SMTP id 3f1490d57ef6-e98a575c57emr6461719276.1.1756739452401;
        Mon, 01 Sep 2025 08:10:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc21wbE2DlpuxLAdqxRtG1oXJnuMarZ+CWvrC4Kf6I5jA==
Received: by 2002:a05:6902:b20:b0:e96:c61f:e271 with SMTP id
 3f1490d57ef6-e97010faccfls4085975276.2.-pod-prod-09-us; Mon, 01 Sep 2025
 08:10:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU4HqkP/K64TluzxTiZvZ765ybH7B7eXDdMqSnk/yI1yuSMt5RCsxbXWsT9kbX4oqnSGOSNoFiGOFA=@googlegroups.com
X-Received: by 2002:a05:6902:6285:b0:e95:2a4e:6e26 with SMTP id 3f1490d57ef6-e98a58629fdmr6663326276.52.1756739451494;
        Mon, 01 Sep 2025 08:10:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739451; cv=none;
        d=google.com; s=arc-20240605;
        b=eqkETqwNgjyVFniXLuYkKq9g3g8tlnUCZOuY+kGd+CFnNXrKWFvD5sz0t12w0JpntV
         ZIUpZ0DIF2BtFaqxdWH49x9HlgBhtAtyd6UrlojmcPEBSHXAgVkkD3v20/rYtMDB7REH
         QR/xxOTBx7epU5lOO4mRI7i47E+Dsyb5fYAE5wqKAo0/YRID3JtOAEtlW4YnLSK7qNIJ
         jDcVr4QUZqdSTocJx3ufMHZJkY64IDNSTAv4ARMPQqR819AsBtBVc55BZzF0NqYkjcVH
         GjBY+J3IYTx49WH9LBWHgf9lTA7PlMsqgACo+6NK1ZoSngiEwyY1LFzxa4U/HwzpzVe9
         lJhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=i06htfFlQWUPNnzacoxmjdCfJTHM/jIyMh7+2RAfHF4=;
        fh=tM06cyeXLFemUFoHs/WW1UEaPU7kuVLZTw6c8GNrwSI=;
        b=L4g6fIvbQQnyBPsAh1hPe4+5zgOjKxsyMpTZSzzfewBLaIQizL91EMC0NLe2rwHxb/
         Uk9ulWhlaF13e9s2fi1rXKLivRqK/qPXp0swYwc2WfK1ZVmSV+4OZkPEKMQ859klWHhS
         n/arEsy8PSiAYnowSLRnWdM38vwr0F55bj4CNzuJxkRGbq3/5uA+xvWP2TYwJ22L0tch
         UU/kgAsE0hoeSv7YMNyf/x3FJ1Hd0FWMA2FZCPZIbEFmLjHcK5/Ze7zz5Tg7XF7xfDco
         Y5S4+pTp9OGyHt4NAx4SgBJcdxZQYq9qDtEBGproqLlasX+e0L+kCF+McNMBIN/GY9IC
         vh3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QPmeg1IA;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e98ac525de2si215531276.2.2025.09.01.08.10.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:10:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-137-mPsifsa5O0-R1fp0Ep7F3g-1; Mon,
 01 Sep 2025 11:10:49 -0400
X-MC-Unique: mPsifsa5O0-R1fp0Ep7F3g-1
X-Mimecast-MFC-AGG-ID: mPsifsa5O0-R1fp0Ep7F3g_1756739444
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 6F20F19560B2;
	Mon,  1 Sep 2025 15:10:44 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 6AB8A1800280;
	Mon,  1 Sep 2025 15:10:29 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
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
Subject: [PATCH v2 24/37] scatterlist: disallow non-contigous page ranges in a single SG entry
Date: Mon,  1 Sep 2025 17:03:45 +0200
Message-ID: <20250901150359.867252-25-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=QPmeg1IA;
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

The expectation is that there is currently no user that would pass in
non-contigous page ranges: no allocator, not even VMA, will hand these
out.

The only problematic part would be if someone would provide a range
obtained directly from memblock, or manually merge problematic ranges.
If we find such cases, we should fix them to create separate
SG entries.

Let's check in sg_set_page() that this is really the case. No need to
check in sg_set_folio(), as pages in a folio are guaranteed to be
contiguous. As sg_set_page() gets inlined into modules, we have to
export the page_range_contiguous() helper -- use EXPORT_SYMBOL, there is
nothing special about this helper such that we would want to enforce
GPL-only modules.

We can now drop the nth_page() usage in sg_page_iter_page().

Acked-by: Marek Szyprowski <m.szyprowski@samsung.com>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/scatterlist.h | 3 ++-
 mm/util.c                   | 1 +
 2 files changed, 3 insertions(+), 1 deletion(-)

diff --git a/include/linux/scatterlist.h b/include/linux/scatterlist.h
index 6f8a4965f9b98..29f6ceb98d74b 100644
--- a/include/linux/scatterlist.h
+++ b/include/linux/scatterlist.h
@@ -158,6 +158,7 @@ static inline void sg_assign_page(struct scatterlist *sg, struct page *page)
 static inline void sg_set_page(struct scatterlist *sg, struct page *page,
 			       unsigned int len, unsigned int offset)
 {
+	VM_WARN_ON_ONCE(!page_range_contiguous(page, ALIGN(len + offset, PAGE_SIZE) / PAGE_SIZE));
 	sg_assign_page(sg, page);
 	sg->offset = offset;
 	sg->length = len;
@@ -600,7 +601,7 @@ void __sg_page_iter_start(struct sg_page_iter *piter,
  */
 static inline struct page *sg_page_iter_page(struct sg_page_iter *piter)
 {
-	return nth_page(sg_page(piter->sg), piter->sg_pgoffset);
+	return sg_page(piter->sg) + piter->sg_pgoffset;
 }
 
 /**
diff --git a/mm/util.c b/mm/util.c
index fbdb73aaf35fe..bb4b47cd67091 100644
--- a/mm/util.c
+++ b/mm/util.c
@@ -1314,5 +1314,6 @@ bool page_range_contiguous(const struct page *page, unsigned long nr_pages)
 			return false;
 	return true;
 }
+EXPORT_SYMBOL(page_range_contiguous);
 #endif
 #endif /* CONFIG_MMU */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-25-david%40redhat.com.
