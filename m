Return-Path: <kasan-dev+bncBC32535MUICBBI7ZTXCQMGQEFHBNVVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 96840B3038D
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:09 +0200 (CEST)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-71e7d652a65sf17083677b3.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806883; cv=pass;
        d=google.com; s=arc-20240605;
        b=auf4odSCpx3mg5dhSZxqMku8sskWpXW7Dyhhi+9WmhJMG2Y+I/MLlRfS3/MF/7bNVw
         BE/ZM6BdD5ZeaR/qcB81W2Zf8G9H4VlyFuW6ERlFqNveqJCii0tpWJyCUXb7HQLWjqcl
         +V0V0ndq3tjWwIW4IJUR1IqWGY7ty5xvRXYHPn2COXxAwah4lmIfGEhpwQQApzGj6UfU
         VnfzDf48tIL9X4UG2/xAJpS4mBU5CI4Q7pyWsH88RO+D/gkPcNo3ALY59vWD5uhgxP3z
         FMdzppx/eAFnnKoHNqadUQ0rPISU+qWzgr9ox6QMa7bSa7ifn/7JDBY74iyhWNZhJAxt
         BTTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=r9M4UpegE/SJyZ4YoAcs89uXl9EXJiAcaKRViZNaCdk=;
        fh=pvXZJkvKW1b6ML9lHbWcDiMLIOiQdHG6LbpzMuPKS7U=;
        b=A9Dcgr7IdXRDpu56LWA5wvZ09HAdsBggkRautpaI4WmBPe+H/u1bLbe+PGQ9D/9iNa
         QhKyozQatm/R5jGS0Oadca95vOSlIJCi+2TqnIVVtgd79bKerzhc88x+PAQCWTM8raMJ
         l44t+PpMxpB4d0JV+u2jxMJSOOyw1Tv4GT0ghpxapP1nyjhlc3ZsMWHaq5mG+gXVsyUg
         /6os8BOiPm0msejwGeXOKSIdo5Sd7wpNwA5n9L0Gs7OkO8DOnCoBO6NpcVmf88jLiMPn
         BPSK/cHm5QXwYbyj+SUhamWOxsyJ3X8F246sNeALRKTh9zQyJ4QxAZ10SkmFnbxxxpNb
         LxVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fa7yDWEK;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806883; x=1756411683; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=r9M4UpegE/SJyZ4YoAcs89uXl9EXJiAcaKRViZNaCdk=;
        b=lXQ0z04p1nV8CBU/4n4LQMesmhquNDCuhx/MHPOcbVHLe2yqU/7l43A4YHcoF48XGp
         pW2Bzcz1yHtPuImVyBvQ/CMWtrfgHqWQWwWtTOP4PAPJeQd9i3RScdaATB2NPMbb0bY/
         pLL+0pKw37CIk050R901F4sHKdjeRNLeHMdEIGjX6CK59Sj1VF4XvBOz5lsvPdSiCS/n
         7Ebsz9CteaOBt8LihILChKFYEUY4HSgORcobgfmaVLvwtBE8BrRZfpt+RWy+AVa8OCXg
         UxfQUeVfvV20PyoCOU4M22vjzVDcMfHm09wOz8HMDbT7cU+X1WYY//8+604vi4ggffI3
         Gf6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806883; x=1756411683;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r9M4UpegE/SJyZ4YoAcs89uXl9EXJiAcaKRViZNaCdk=;
        b=Hf6KWa4Ekx/AuRoD5lEX8T5z81OLFvELcQYOb9B2+I9iFPK2mCgA076m7kHECW86C6
         aGCCndAe/b2ncQbhTAZsx7aUbZbiMoxtoDc1SRhDpVIZAsRBREwHXnc3S2u/+kKqXL6O
         6dh7flMJPi3Hs/nZsvR4xnen+GuAqAihifNk3Ry65PtwQTTyqJAf9KGSzG9bCZI0b9iI
         BMhztV5Bx7I+T42zS/llbrX4/gc6ubfTRK0m8U3alCZsUcteEoEPz9CWNvH+m2OR2dI2
         oT8Ky1Ifrxei9FoBhC72J7yOqFRiyrmq7my7IZJyrdxfCzylj5m4T1HMtgki6DA4TuOG
         WmWg==
X-Forwarded-Encrypted: i=2; AJvYcCXJwxiz4ywsnBi1JNR51boY2Gt8W/EC37d0EbShs5VzsS5exr3Sn10zSagejn7DhvUDLvbGSg==@lfdr.de
X-Gm-Message-State: AOJu0Yz0IrxzeyVgBhGEMXKgvKcAdBZ/8Py0J+m22Dk5WDXQ9yOqwcs9
	l/mM+SQZ60V5fwRhQWKasfoUIAnMYn+vbPojgZV461cDL3AcZDfvgkEg
X-Google-Smtp-Source: AGHT+IHnCD6EDdaJSdILXYCiQHWwHmw/edT5yiRD/udDVfhaxVDRw9xp5oSulwgt6r52JxvHDFuK3Q==
X-Received: by 2002:a05:6902:e0b:b0:e94:e1e5:37f7 with SMTP id 3f1490d57ef6-e951c3ffb8fmr899568276.53.1755806883338;
        Thu, 21 Aug 2025 13:08:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdsxdnbKCwx9a8UEUif5gFSqQgIFgbKirIWhaawODc1iw==
Received: by 2002:a25:aaf2:0:b0:e95:1bb9:4d90 with SMTP id 3f1490d57ef6-e951bb956e6ls272152276.0.-pod-prod-01-us;
 Thu, 21 Aug 2025 13:08:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXL8M8Q34jxlVYYeHfMhD4/n4QBFQLBgj8rlg6b1fdfPH+qTLEbO/CaZefBtF/TMvZarKnL5B50opQ=@googlegroups.com
X-Received: by 2002:a05:690c:63c7:b0:71f:afcb:a0c9 with SMTP id 00721157ae682-71fdc4153bamr6681727b3.36.1755806882387;
        Thu, 21 Aug 2025 13:08:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806882; cv=none;
        d=google.com; s=arc-20240605;
        b=lV+gXM/9b9KNh2Cij5OBoiMmujw4TtDEysoTHlE1Ht3adwoCMUAdzPU66C+VQ8siSI
         CQcffoknhrPd1KFglncHlw4q8unwu5hQBXHMUbxhinCJKcJqcEmPLHojuKh1Qto3o83v
         uWOyYvGYvEl09vLqS1GEtZu4wJUJnpGUyWq8MbjLuaYilKVO/HvCmDPOPvREMpsEm5ic
         9txf8TkU2htDom1ut8AifG8r3qHeWJRqK9pJ890ciRgW/t6UhnwK3/Q+AmoQuXGrWhaf
         0nOwY4LQ6kYOzCWBOJc7MLZsLyllgoPbPdoGK7FDV5+Iaj+3wOWLjAphjGYZkWN4TnHj
         oamA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hICKs+PYshPEfoclHwqOXtWPheskj6p8LyRcJkrFnX4=;
        fh=IVz1LgN35oSs4cFagNyANODYwm6Hpje2rNVfFk6+QaQ=;
        b=Ab06mdSadWLb5EgeRnJ7WRAc8GfGEKD/6XYZoo45RzaZEKoH5cZohvVzNqri59ki7h
         b8kR1b+LMBnuAVFAvzS5dvcY7PxPOJT8UivJdYpg1yfNU7UlAIOx0nk1mXZ0XUtQ6Lux
         hZ78/NJdydxgyjNb9r+WMfbNx/wXbMqfun3aeZI03RfkUH1aIb9XdNR6tA/gcFNxyvUS
         D1TjNNZlvQK3cpIssza0dqjKvEjj8bTSSIcQIfEnLC7TAMH0p4xh5Qfwji0Sg5BnSjwE
         ag0rGun1F9k0lR9DqbWrTmF2XsWJCLeWKOikC+gOsQ3Z2xBcZjnfLjH9ZQkOm+8YJg+s
         oYNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fa7yDWEK;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-5f52aeb2dadsi6855d50.0.2025.08.21.13.08.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com
 [209.85.221.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-134-_KsY2KGkPn6j6VXg1yuqtA-1; Thu, 21 Aug 2025 16:07:59 -0400
X-MC-Unique: _KsY2KGkPn6j6VXg1yuqtA-1
X-Mimecast-MFC-AGG-ID: _KsY2KGkPn6j6VXg1yuqtA_1755806878
Received: by mail-wr1-f70.google.com with SMTP id ffacd0b85a97d-3b9e41475edso915378f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXkn/FYXSKU/nUV3RlECT0S/mEX0rerCp4JpOoFa2yF5F2okZ2hJcgVLgpkIf3jwqjn5bFODEtUrWg=@googlegroups.com
X-Gm-Gg: ASbGncsOiht69pXXtbHMBMhTFAtm+nomqWQjy7C5ftoIEbeoQKIKXNdVERu/FMIVRbm
	XLVKhnYhAXMVpAK2NGxvXOY3udOyGryWzQrnOnxslSx/baaG3dDSAl5r6+pU1yl14hoDem94JvN
	fa21N5P7fOAvzyZHiME9L5xhwihecyDxibUYtDCKnHK2XM9eIsUr1O1YDPDcPSuwGHJTVVD8Hby
	n8TKutn/7SscW1J2tNLRAfQbGZsnZijBvwud7Dt6Sj9rolEyx5nDJA4yrZuRKFXlTLb33SEnGNn
	r+XP+vwmiCowEcmQDwMqk7M9KPfFztXZIqT2zZHgIYUayKcviBfPwND8wCM6d8+yAIk+tZbnk3h
	iUCmMWsXCo+5M1WmLKHoZwQ==
X-Received: by 2002:a05:6000:1789:b0:3b4:9721:2b2b with SMTP id ffacd0b85a97d-3c5dac17062mr195822f8f.12.1755806877251;
        Thu, 21 Aug 2025 13:07:57 -0700 (PDT)
X-Received: by 2002:a05:6000:1789:b0:3b4:9721:2b2b with SMTP id ffacd0b85a97d-3c5dac17062mr195797f8f.12.1755806876810;
        Thu, 21 Aug 2025 13:07:56 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c4f77e968esm2903478f8f.21.2025.08.21.13.07.54
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:56 -0700 (PDT)
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
Subject: [PATCH RFC 18/35] io_uring/zcrx: remove "struct io_copy_cache" and one nth_page() usage
Date: Thu, 21 Aug 2025 22:06:44 +0200
Message-ID: <20250821200701.1329277-19-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: EpvHK_G_fZMvOziCqJgh38r06OTVTeHdn2UHu6AlDZA_1755806878
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=fa7yDWEK;
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

We always provide a single dst page, it's unclear why the io_copy_cache
complexity is required.

So let's simplify and get rid of "struct io_copy_cache", simply working on
the single page.

... which immediately allows us for dropping one "nth_page" usage,
because it's really just a single page.

Cc: Jens Axboe <axboe@kernel.dk>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 io_uring/zcrx.c | 32 +++++++-------------------------
 1 file changed, 7 insertions(+), 25 deletions(-)

diff --git a/io_uring/zcrx.c b/io_uring/zcrx.c
index e5ff49f3425e0..f29b2a4867516 100644
--- a/io_uring/zcrx.c
+++ b/io_uring/zcrx.c
@@ -954,29 +954,18 @@ static struct net_iov *io_zcrx_alloc_fallback(struct io_zcrx_area *area)
 	return niov;
 }
 
-struct io_copy_cache {
-	struct page		*page;
-	unsigned long		offset;
-	size_t			size;
-};
-
-static ssize_t io_copy_page(struct io_copy_cache *cc, struct page *src_page,
+static ssize_t io_copy_page(struct page *dst_page, struct page *src_page,
 			    unsigned int src_offset, size_t len)
 {
-	size_t copied = 0;
+	size_t dst_offset = 0;
 
-	len = min(len, cc->size);
+	len = min(len, PAGE_SIZE);
 
 	while (len) {
 		void *src_addr, *dst_addr;
-		struct page *dst_page = cc->page;
-		unsigned dst_offset = cc->offset;
 		size_t n = len;
 
-		if (folio_test_partial_kmap(page_folio(dst_page)) ||
-		    folio_test_partial_kmap(page_folio(src_page))) {
-			dst_page = nth_page(dst_page, dst_offset / PAGE_SIZE);
-			dst_offset = offset_in_page(dst_offset);
+		if (folio_test_partial_kmap(page_folio(src_page))) {
 			src_page = nth_page(src_page, src_offset / PAGE_SIZE);
 			src_offset = offset_in_page(src_offset);
 			n = min(PAGE_SIZE - src_offset, PAGE_SIZE - dst_offset);
@@ -991,12 +980,10 @@ static ssize_t io_copy_page(struct io_copy_cache *cc, struct page *src_page,
 		kunmap_local(src_addr);
 		kunmap_local(dst_addr);
 
-		cc->size -= n;
-		cc->offset += n;
+		dst_offset += n;
 		len -= n;
-		copied += n;
 	}
-	return copied;
+	return dst_offset;
 }
 
 static ssize_t io_zcrx_copy_chunk(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
@@ -1011,7 +998,6 @@ static ssize_t io_zcrx_copy_chunk(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
 		return -EFAULT;
 
 	while (len) {
-		struct io_copy_cache cc;
 		struct net_iov *niov;
 		size_t n;
 
@@ -1021,11 +1007,7 @@ static ssize_t io_zcrx_copy_chunk(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
 			break;
 		}
 
-		cc.page = io_zcrx_iov_page(niov);
-		cc.offset = 0;
-		cc.size = PAGE_SIZE;
-
-		n = io_copy_page(&cc, src_page, src_offset, len);
+		n = io_copy_page(io_zcrx_iov_page(niov), src_page, src_offset, len);
 
 		if (!io_zcrx_queue_cqe(req, niov, ifq, 0, n)) {
 			io_zcrx_return_niov(niov);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-19-david%40redhat.com.
