Return-Path: <kasan-dev+bncBC32535MUICBBKXZTXCQMGQE4CRNQIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id E9BD7B3039E
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:11 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-70a928da763sf29445626d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806891; cv=pass;
        d=google.com; s=arc-20240605;
        b=UOEIRKM1oNOuttTD4TTmGkswwWU4qVQ0JK8vzy4ZvxyVkcf8Evi63dANODOtsCnRXk
         UC9ZWek0l1xPF4QcdDwANDm1nkTIKfpPbuiE6dWLsr7NGL3QTVzRsJtmKoo30dNMswCU
         rXtHqtk5rXQTZaVTgV43DPp5h4RmYYbALsJu0g7ivvYXXZm0CAv/ivio5xkKcrL1cvR+
         0RfyzbC+gPoifEfAS8OV4DSQYPYcmwXIHOqxTEAHbYUTKcZ6Yw9I2vsOtK4h+lq2yZNG
         D6IvNeb34XloP4XYf7q0nu5z0V1dN1vfgSK2aBIEfKCeHuSDwthUJ+wqBTXceh4Hy+Rz
         hyUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=5jIdbJqyRzpk8XxPob5EqIGbeGOmKrDVXSEABdwXhoY=;
        fh=tkyRfPsGvKdPMUixEnlx+H5z+sGoRgENe7jzbtDhu0s=;
        b=gOK9n1LjMlyqoJmw33oOcTmwMts2wPUmOYx50LblRMO4QMYGFD2lBpXiOfmnJwLFzG
         xsJcJeAaZgFVQiTfUoTaXyoEuS+7IYxrBzf8+9viWOGACWAQmNToyjlxIpypvMNIaTVP
         5ym7g53O+1JewEWz2Q9qj0jK4FJNf28eKq46LI5vLNBBCcPwkocA8mWFh98RUiqnsmP3
         MEkOiLRTIJrdy1CSclubOWHAuguOcSXMlfXJ69rL61g0CqdCi1W0ml8kGS1bslKp00kA
         VKk7lULkABXzVtRHeV+1eP4U2yHY8B4Sk6CRcR6Hf+4H5DzN+bWgTivAWWLUT+Y1uuA3
         mj6Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=AGznkjss;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806891; x=1756411691; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=5jIdbJqyRzpk8XxPob5EqIGbeGOmKrDVXSEABdwXhoY=;
        b=Di4a9JSGCHt2tBtV6dR6YvjSyJdSnDjQAjjJ/GANsSvoKSUglbCHhVEmBOb8hg9K/R
         gnsg8AvOqV10HQcVJB1KuYuNuxR0tMgwdvEShl8jQG5XCTkz5FJ07NsIT1JETzMEFd1+
         IDZHROB4Tl91ai40ljTHMKTsvmIKIFGd1jnP+bAp6VW26ZTalHzws/KHOwO4Xc2pj1T7
         3ol1oJnRqGTjhVY99C8+xty+HaABnPcx287QBkt+1rc0baOIEV9DE09FuOPmg6kEXwpd
         FCz3/OABpJ0HnW1XLM0yRXOs+mM56grVJpacR3YGQ7hBXSG/FSszmLR/ggmsnrP0Inwi
         lCKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806891; x=1756411691;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5jIdbJqyRzpk8XxPob5EqIGbeGOmKrDVXSEABdwXhoY=;
        b=c8qxEfWdrnQFiD0n0ZP3oD175uqC9j6lB/UWz+upz4bjFYnK9hs7gyqlgBLOKBPaWa
         g6OB7l4h4anEeHSO1ZrMjjkj4ZH4Tqtat11FSW87UmQNwENz7Oat8giyto0ev8yr+4BZ
         TF0BPEbnGxWgpPxeQHVaGcAOrkpersSZ9RRTSNeVGsT6SXgMVbBsB1zQjAMkdo4J37pQ
         8WS6V3mWhHC3q2LQbKgmAqcvBHykaYgUGpXrhaqPtfLKeJi1hWJuHLgKTBcQUtUZMbVe
         cjHS2EVus9xEaQTeZroUaNN9wbzxS54z+706X/xoeSwW3iYOx92/myqglR+23EBECy56
         aa7A==
X-Forwarded-Encrypted: i=2; AJvYcCWYao6Ezw4mWDsyGy/WGyMPGLS83tmwiEo4uLCcnBrjlhgT6wXZpQKgeVJ6ih/5t8cWW+uWKg==@lfdr.de
X-Gm-Message-State: AOJu0YxLXYsV4+45TNOJyfLeez7kfXVJ9Tbp2wYOqR13xOiOv5f7BhyJ
	ZV5JLYRpw8WsiL2CdfeETG5C1PdhfDggd9vU50RSttwll8DRaSXNg+Qs
X-Google-Smtp-Source: AGHT+IFcU/Z7uHngpQUlom901bbOQqdd8UekYn8folMqWCeWI+33W/JWxPWxJzzN7AErODh+8t1GWA==
X-Received: by 2002:a05:6214:2587:b0:70d:8715:2875 with SMTP id 6a1803df08f44-70d971f271bmr8523126d6.40.1755806890749;
        Thu, 21 Aug 2025 13:08:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe4QAk4B6GkbuLmLJq2/WSIHJKNLHBc5DXe0SSmBQPlFA==
Received: by 2002:a05:6214:d66:b0:709:289d:3157 with SMTP id
 6a1803df08f44-70d85939c75ls20265176d6.0.-pod-prod-07-us; Thu, 21 Aug 2025
 13:08:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWpv+Q+VsZYa1S0WriGwlH6FToPslCFAO8vO/HsJ6R5dueR/z8lNSYP8n2xvDY+nnLygIHOC67SseQ=@googlegroups.com
X-Received: by 2002:a05:6122:20ab:b0:53c:6d68:1e8f with SMTP id 71dfb90a1353d-53c8a440fa2mr227863e0c.14.1755806889156;
        Thu, 21 Aug 2025 13:08:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806889; cv=none;
        d=google.com; s=arc-20240605;
        b=CzNrRaZBe7h89RdQv+nAo8IdUZWUJ+8HYoIVaMdgZpIylsTwB0ne/V+z2AZTgfye05
         dWQB4HLgIvfM755hBcLG9e07Cn5+vrTmjALgUc/BeJoo+e1JzroRByaKbG6cBU4pI432
         JIq9m//xcWVPn6Wq5Lf5Wrvd5nxu6NbXP2Z40WXFspOiaUCGeSLCpo/7di/B3vzBT4tG
         Rv5ZcNozLvJmhz94IGWbi6PMPSj/Rn6k+JU+A168i40GUESeBg72pzQ/mcHSLfVkwG5N
         AjMkksCcwEWz2aRUulpdvrXEmPKnxu6cEfloK+N/7LY7mUXT+SteGhgLlj8MZjBNJqf9
         TABQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OlD9YGSFbsAaeSHrs+lmfmp3eNVZAqkWDWaUN3GbxpI=;
        fh=0/vSla1cSauH8q3Jgy4S3Wf8lhvtGChU4GWn/cL/jcQ=;
        b=AT06ePytd+OT8kyX2S/EMCZSSwUsfqP5veR4w56TBxATNYOSgpr3LEsjoxtJc8y71n
         dsiQYu5hcuJY2gcbvZZGfmdAkTPYLLegWMqufWbvRyq8PYhiURzG03EpZ458JwuvS6yo
         zO+FbwNb1yyq6wQr0QZP00cX+Z/souC1GNbf5msgbTTBF3zJ27wR7hcWD5JCxKeC9Vle
         gOlW/BnGLyn4sEnMb6+DrY6rIlTYtKPbq60+HuZHdKjWTkDyk6RAOtufM2uRmXOk2prO
         xgbTRJshdNznYtQupBNJyt01Y16PTZmmhnWol1fVItwb2YxBdnNzteUWdHQjFk7/+ROP
         pyxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=AGznkjss;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-53b2bb63059si715268e0c.0.2025.08.21.13.08.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-169-L1fKODk6M6Cernc04X1ZRg-1; Thu, 21 Aug 2025 16:08:07 -0400
X-MC-Unique: L1fKODk6M6Cernc04X1ZRg-1
X-Mimecast-MFC-AGG-ID: L1fKODk6M6Cernc04X1ZRg_1755806886
Received: by mail-wr1-f69.google.com with SMTP id ffacd0b85a97d-3b9d41bd50aso995793f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUhVVB1hF8pmH/JjxBHH18MixrYTR+ehtCU7BT8KELjhIfXXySy5+aAZxmb3p5Arm3ZSkUVxxvxMkk=@googlegroups.com
X-Gm-Gg: ASbGncu0FDnVdzDdQG4Q2uFyEuM6l8pkHDDgLeeohxBd71+UI1sXfwNGYg7/+HEAWEo
	lI8qd+2kusaLSAzwQ7aurrf438dYGP7OZNJSXnDko7383L/bEI9nkDhOpPX4uGaDRxUtYazmz4A
	fPDqgiH63IEKPkm6OzR/aU6T80LGFwn6PB8b10Bjy7e7BRlJSMIy3vFTekSgwdRAzBdgZRNjLgn
	kzPaJU9ZXaqyP+7G0rJtP9GfiYvt0gOspZmHHVlGP0V35EGqzVIQFGH6bS3YwUhf1Q1d36/1EXa
	iMIIFiasBEAEboWZ491eHEF3+gHQ8d1X609FSuxpYj8pRz/+vYWoTAKDC/05VSVxLx56O1TJ3Sl
	zNwZn2RDUynEfgioiROenHA==
X-Received: by 2002:a5d:5849:0:b0:3b7:94c6:7c9 with SMTP id ffacd0b85a97d-3c5db4ca226mr187830f8f.27.1755806886218;
        Thu, 21 Aug 2025 13:08:06 -0700 (PDT)
X-Received: by 2002:a5d:5849:0:b0:3b7:94c6:7c9 with SMTP id ffacd0b85a97d-3c5db4ca226mr187788f8f.27.1755806885705;
        Thu, 21 Aug 2025 13:08:05 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c077789d1dsm12697993f8f.49.2025.08.21.13.08.03
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:08:05 -0700 (PDT)
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
Subject: [PATCH RFC 21/35] mm/cma: refuse handing out non-contiguous page ranges
Date: Thu, 21 Aug 2025 22:06:47 +0200
Message-ID: <20250821200701.1329277-22-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: TPWx-35IA-foEokILe69dwrwXbfzlqTLLiCYv-TMH4U_1755806886
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=AGznkjss;
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

Let's disallow handing out PFN ranges with non-contiguous pages, so we
can remove the nth-page usage in __cma_alloc(), and so any callers don't
have to worry about that either when wanting to blindly iterate pages.

This is really only a problem in configs with SPARSEMEM but without
SPARSEMEM_VMEMMAP, and only when we would cross memory sections in some
cases.

Will this cause harm? Probably not, because it's mostly 32bit that does
not support SPARSEMEM_VMEMMAP. If this ever becomes a problem we could
look into allocating the memmap for the memory sections spanned by a
single CMA region in one go from memblock.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/mm.h |  6 ++++++
 mm/cma.c           | 36 +++++++++++++++++++++++-------------
 mm/util.c          | 33 +++++++++++++++++++++++++++++++++
 3 files changed, 62 insertions(+), 13 deletions(-)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index ef360b72cb05c..f59ad1f9fc792 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -209,9 +209,15 @@ extern unsigned long sysctl_user_reserve_kbytes;
 extern unsigned long sysctl_admin_reserve_kbytes;
 
 #if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
+bool page_range_contiguous(const struct page *page, unsigned long nr_pages);
 #define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
 #else
 #define nth_page(page,n) ((page) + (n))
+static inline bool page_range_contiguous(const struct page *page,
+		unsigned long nr_pages)
+{
+	return true;
+}
 #endif
 
 /* to align the pointer to the (next) page boundary */
diff --git a/mm/cma.c b/mm/cma.c
index 2ffa4befb99ab..1119fa2830008 100644
--- a/mm/cma.c
+++ b/mm/cma.c
@@ -780,10 +780,8 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
 				unsigned long count, unsigned int align,
 				struct page **pagep, gfp_t gfp)
 {
-	unsigned long mask, offset;
-	unsigned long pfn = -1;
-	unsigned long start = 0;
 	unsigned long bitmap_maxno, bitmap_no, bitmap_count;
+	unsigned long start, pfn, mask, offset;
 	int ret = -EBUSY;
 	struct page *page = NULL;
 
@@ -795,7 +793,7 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
 	if (bitmap_count > bitmap_maxno)
 		goto out;
 
-	for (;;) {
+	for (start = 0; ; start = bitmap_no + mask + 1) {
 		spin_lock_irq(&cma->lock);
 		/*
 		 * If the request is larger than the available number
@@ -812,6 +810,22 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
 			spin_unlock_irq(&cma->lock);
 			break;
 		}
+
+		pfn = cmr->base_pfn + (bitmap_no << cma->order_per_bit);
+		page = pfn_to_page(pfn);
+
+		/*
+		 * Do not hand out page ranges that are not contiguous, so
+		 * callers can just iterate the pages without having to worry
+		 * about these corner cases.
+		 */
+		if (!page_range_contiguous(page, count)) {
+			spin_unlock_irq(&cma->lock);
+			pr_warn_ratelimited("%s: %s: skipping incompatible area [0x%lx-0x%lx]",
+					    __func__, cma->name, pfn, pfn + count - 1);
+			continue;
+		}
+
 		bitmap_set(cmr->bitmap, bitmap_no, bitmap_count);
 		cma->available_count -= count;
 		/*
@@ -821,29 +835,25 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
 		 */
 		spin_unlock_irq(&cma->lock);
 
-		pfn = cmr->base_pfn + (bitmap_no << cma->order_per_bit);
 		mutex_lock(&cma->alloc_mutex);
 		ret = alloc_contig_range(pfn, pfn + count, ACR_FLAGS_CMA, gfp);
 		mutex_unlock(&cma->alloc_mutex);
-		if (ret == 0) {
-			page = pfn_to_page(pfn);
+		if (!ret)
 			break;
-		}
 
 		cma_clear_bitmap(cma, cmr, pfn, count);
 		if (ret != -EBUSY)
 			break;
 
 		pr_debug("%s(): memory range at pfn 0x%lx %p is busy, retrying\n",
-			 __func__, pfn, pfn_to_page(pfn));
+			 __func__, pfn, page);
 
 		trace_cma_alloc_busy_retry(cma->name, pfn, pfn_to_page(pfn),
 					   count, align);
-		/* try again with a bit different memory target */
-		start = bitmap_no + mask + 1;
 	}
 out:
-	*pagep = page;
+	if (!ret)
+		*pagep = page;
 	return ret;
 }
 
@@ -882,7 +892,7 @@ static struct page *__cma_alloc(struct cma *cma, unsigned long count,
 	 */
 	if (page) {
 		for (i = 0; i < count; i++)
-			page_kasan_tag_reset(nth_page(page, i));
+			page_kasan_tag_reset(page + i);
 	}
 
 	if (ret && !(gfp & __GFP_NOWARN)) {
diff --git a/mm/util.c b/mm/util.c
index d235b74f7aff7..0bf349b19b652 100644
--- a/mm/util.c
+++ b/mm/util.c
@@ -1280,4 +1280,37 @@ unsigned int folio_pte_batch(struct folio *folio, pte_t *ptep, pte_t pte,
 {
 	return folio_pte_batch_flags(folio, NULL, ptep, &pte, max_nr, 0);
 }
+
+#if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
+/**
+ * page_range_contiguous - test whether the page range is contiguous
+ * @page: the start of the page range.
+ * @nr_pages: the number of pages in the range.
+ *
+ * Test whether the page range is contiguous, such that they can be iterated
+ * naively, corresponding to iterating a contiguous PFN range.
+ *
+ * This function should primarily only be used for debug checks, or when
+ * working with page ranges that are not naturally contiguous (e.g., pages
+ * within a folio are).
+ *
+ * Returns true if contiguous, otherwise false.
+ */
+bool page_range_contiguous(const struct page *page, unsigned long nr_pages)
+{
+	const unsigned long start_pfn = page_to_pfn(page);
+	const unsigned long end_pfn = start_pfn + nr_pages;
+	unsigned long pfn;
+
+	/*
+	 * The memmap is allocated per memory section. We need to check
+	 * each involved memory section once.
+	 */
+	for (pfn = ALIGN(start_pfn, PAGES_PER_SECTION);
+	     pfn < end_pfn; pfn += PAGES_PER_SECTION)
+		if (unlikely(page + (pfn - start_pfn) != pfn_to_page(pfn)))
+			return false;
+	return true;
+}
+#endif
 #endif /* CONFIG_MMU */
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-22-david%40redhat.com.
