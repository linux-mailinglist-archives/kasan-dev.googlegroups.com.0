Return-Path: <kasan-dev+bncBC32535MUICBBEECX3CQMGQEOD6N7BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A5E6B38C43
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:05:06 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-b47156acca5sf198340a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:05:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332305; cv=pass;
        d=google.com; s=arc-20240605;
        b=ien46etA+gVKOJ2If5xtlnZoqnGvhtQJ0lolljz8gJFE5sPDSptoZoNHzjBImj6vzO
         BulkdzqWXiBSrMFkmlLr6vsUMBuR9OZAhS9v4Z/rrFfvOCI910x4hX5oYKnWE6gwGVg6
         yDDYYJw25fEeFFQertD3+vgbQSTg4uLcIrr8fQw5sLBSB0QtexZWKG0N2B9RnxR/cgdV
         +e3F5ReNfy6cTjLsv2TDZuGZcxWwEHejS6p3/E+0VvYgoVW3TM36M5nUOL9ZDW9akeiK
         jRTkOL7p+pxnYSAFt6jx8QAOyYLYumxFBmsR+Bb0MnpIQF3cIL8c5Zx48S+eBJOIXECt
         lwDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=o87Aocs3EO3vNnKcGdJKN1yvhtHND1lRDoCbSyrap28=;
        fh=p+pDcM106zcrKyw9hb36mjA5cTgbHbvr5n5PBacrDKc=;
        b=QgXSSwsV1YQndow4hCP0+Tea66DWR2rxJ4D3YwNx/dc23opP5ROBgx9CPE+G+QCGXS
         z3agO+hS8hR5Sy73JYFF2o7sFJEmORMivV/6MgPco/516ZR2opr3Sc9ycqjJPfXDMUir
         sVUKbSBm173NGZGKfVRh+z8HK66MunOhMA+rgdGNHf2NtzKmFBZna+TrsLwABAjlw6F3
         PlEjSAIhe8LO2H1ahCxS0x/cnQ1ATwfSWza1emcxCnhen3+NITapFSlsVsSVU85m8gMh
         O3rfg4pFQGdoNgTFSOU6ACAr/1Pf7YaexHu2P9IlG5kLKeMJX8JJ4Q61vk40l/P7B67Z
         6tXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZO8ARR7i;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332305; x=1756937105; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=o87Aocs3EO3vNnKcGdJKN1yvhtHND1lRDoCbSyrap28=;
        b=pOpzM8QjmfLHhTcwq1r3O2MNGh93gzGNyCqzh+tZurNEmEQFWH4b05+BgtANMXEuyO
         VKX5YNBxBnrvxU4FbjXcY3/6O+MI0sI0fTUU41zvHy1n86ohbQzu9TIS/JUsVbevcZna
         fP3+kQXtZcj/JaGd4L5nPaiEM2AAfcXVmVzgbGrzQpINqkDBTQs9FD50uduvJcgwLGsI
         nOclcr2CITSWQBDnxTre+rygJSomGRZbZGOYrreHLifJcY33m1YBUwQaZg/52zMaoVNd
         6V24FMsc4HEti7vYPflswp1YlAnF2+OMpHQ+pLeTmslsv/WF5OsfrqC9+N8jGrFnuVhd
         7Vaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332305; x=1756937105;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=o87Aocs3EO3vNnKcGdJKN1yvhtHND1lRDoCbSyrap28=;
        b=F6KLjAqLZnSdTtUdPRskrvR7FNiErRpBU5iHHjCeHtpM9Cw8n0bKy0mulVvHBUo8+H
         gvIjsHGZ1BiqlKRjeRmxOevFkbjvmjFqVdDi1Oi09KTcydhIQHejXEuGHFcA1ywAxqIs
         vtr4YjEChnzwUT2p5MMhtcMUQm6rv1qa2XYEdaBRIP1j27KwZAaGlMQHjvlhL9Z/yJ+0
         LcCwxN7yhksjGLghyHwbAE7GVF5TUWs3p3YGD7r7QGFJ46HJJ/wvbletDAH+eYxNLQ5l
         knb+shDSfCLPikiq7i9A7lRk75xRgleha5GQWMJP5Zvvn+Vc9pE2H4y1NHGlypMbOHcN
         bPaw==
X-Forwarded-Encrypted: i=2; AJvYcCXfjLroNAqc/G8K+iI9RTtpYj/J8RTecdCOlej4uw1WsWDUYySxtw53zZAoR3auUQNCv8YttA==@lfdr.de
X-Gm-Message-State: AOJu0YzdszRYGKQnx52BgWiktewcQVKjfJGdQwmSrlHw2TYUGZzwxX/H
	Qsm0vFF9S+lxSLKqBEgjxlZMFOA+oIwgCigXCRhABwh/YIhG7w4FJ73K
X-Google-Smtp-Source: AGHT+IG4BkT35ecbUVTEDwruto0my6mvZzhI5ZonLNy8p2m7vNhZdNi3eYnIoFqfSFzpn+sGN95bOQ==
X-Received: by 2002:a05:6a21:9987:b0:243:78a:82d1 with SMTP id adf61e73a8af0-2438facc6a1mr9508052637.30.1756332304677;
        Wed, 27 Aug 2025 15:05:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdUpELX1MMdEc+Ddk8kPosg0Lfqoigg8gIGzPyZ8sRGtA==
Received: by 2002:a17:90b:534b:b0:324:fbc0:d169 with SMTP id
 98e67ed59e1d1-327aa822c92ls105937a91.2.-pod-prod-00-us-canary; Wed, 27 Aug
 2025 15:05:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUIvKQAiC6hMwF9ZyogRiW+31IOJ+gJaabEFmnBl0zAaj0EmZhuqa0xQGLRvriSOONUm6ms/avZZAA=@googlegroups.com
X-Received: by 2002:a17:902:db01:b0:231:9817:6ec1 with SMTP id d9443c01a7336-248753a26eemr87987125ad.17.1756332303288;
        Wed, 27 Aug 2025 15:05:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332303; cv=none;
        d=google.com; s=arc-20240605;
        b=DJ/rVLGMceq3eQlD6DvcI1SIpH+xo+D3YbAN/idTPD6Ldf7Y9RRZkWJo3OmkYBOzH2
         UM4Fe1bf2U29wraycQH8zW6Zf18WiIreWbGh9Ojd3CtzWAUTSPC410ikUqrw44HGB95w
         9H5ociWuCDXk1cCI+fBzgq5rhtDEyu0SycIYMQVByiztGC6YTV34pAPPzaQabT5pWNs/
         l1VxfgUD2z+dwim3wLnyN0gX/KE5m4MvrJpAiFl80Jw9Ll799hcKhJFr2DoL9ROndwQB
         +m1nQqOF9tH2AW8FtOjlNTojygit3YR/wztfpYn04/oDLV4i8I2XyDvVp6fywFHuIMEh
         LAvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sdduxfP9sOW11CIIetzrq/g2aOdRCb5eN+kQk0XudUI=;
        fh=4DF1q/SpyHIHI3rGSRtJnOwU9P9Lsfa9ROxihRpIPuU=;
        b=bWJpDsbE6euV43l4CQ9zuFCtvzTO4BWNTcdl45MfcpVEoeck+68tshr2bHZ4GVzrI8
         U15THbU47x+iMOfC6mh7K5q58+BDxUgxa7oE9RJ3Vw03z8aW/S5RPkPcpxQEaWAm31lB
         mf9jFzfJmX7HLbt6NYetbUbKByn7HropMOPNQUype6z+54ESCmhgUSDI/2Whe2grYu41
         GYm/7iV6iZNhe3crELlIqg24l7hW8OdgKWaG4I3y4/kKMKiMW6PmAl4QJeczCS+yYx7T
         7j7se+NekKWV5QrBmYELIO1BHrNuTM1eFTL4TvV61tIwBVSrddu3pIlCiW8Z1wzDfX2+
         +VaQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZO8ARR7i;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2466884ab84si5428285ad.3.2025.08.27.15.05.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:05:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-417-EpEDj_iqOtyJ7pKJWv6ETA-1; Wed,
 27 Aug 2025 18:04:58 -0400
X-MC-Unique: EpEDj_iqOtyJ7pKJWv6ETA-1
X-Mimecast-MFC-AGG-ID: EpEDj_iqOtyJ7pKJWv6ETA_1756332292
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 995B919541AC;
	Wed, 27 Aug 2025 22:04:52 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id CAF5B30001A1;
	Wed, 27 Aug 2025 22:04:36 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
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
Subject: [PATCH v1 09/36] mm/mm_init: make memmap_init_compound() look more like prep_compound_page()
Date: Thu, 28 Aug 2025 00:01:13 +0200
Message-ID: <20250827220141.262669-10-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ZO8ARR7i;
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

Grepping for "prep_compound_page" leaves on clueless how devdax gets its
compound pages initialized.

Let's add a comment that might help finding this open-coded
prep_compound_page() initialization more easily.

Further, let's be less smart about the ordering of initialization and just
perform the prep_compound_head() call after all tail pages were
initialized: just like prep_compound_page() does.

No need for a comment to describe the initialization order: again,
just like prep_compound_page().

Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/mm_init.c | 15 +++++++--------
 1 file changed, 7 insertions(+), 8 deletions(-)

diff --git a/mm/mm_init.c b/mm/mm_init.c
index 5c21b3af216b2..df614556741a4 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -1091,6 +1091,12 @@ static void __ref memmap_init_compound(struct page *head,
 	unsigned long pfn, end_pfn = head_pfn + nr_pages;
 	unsigned int order = pgmap->vmemmap_shift;
 
+	/*
+	 * We have to initialize the pages, including setting up page links.
+	 * prep_compound_page() does not take care of that, so instead we
+	 * open-code prep_compound_page() so we can take care of initializing
+	 * the pages in the same go.
+	 */
 	__SetPageHead(head);
 	for (pfn = head_pfn + 1; pfn < end_pfn; pfn++) {
 		struct page *page = pfn_to_page(pfn);
@@ -1098,15 +1104,8 @@ static void __ref memmap_init_compound(struct page *head,
 		__init_zone_device_page(page, pfn, zone_idx, nid, pgmap);
 		prep_compound_tail(head, pfn - head_pfn);
 		set_page_count(page, 0);
-
-		/*
-		 * The first tail page stores important compound page info.
-		 * Call prep_compound_head() after the first tail page has
-		 * been initialized, to not have the data overwritten.
-		 */
-		if (pfn == head_pfn + 1)
-			prep_compound_head(head, order);
 	}
+	prep_compound_head(head, order);
 }
 
 void __ref memmap_init_zone_device(struct zone *zone,
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-10-david%40redhat.com.
