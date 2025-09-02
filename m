Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBHEI3TCQMGQEDQDFHCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A431B407B1
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 16:50:05 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-70deedd1deasf92775526d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 07:50:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756824604; cv=pass;
        d=google.com; s=arc-20240605;
        b=BlkLJOg3P1xIR6fIGibQpaVjChUVIqcI6Alh/ay7i88H965Szqi1moAWitSEFGDjB6
         KvJP7SOBRr2SRIVJyf3yuUvGHa+sGiKOXSJjIZCH3lNQzm32Z5ZI0TTVjL4lsNLM0SL/
         27x4UvhoEWAYss9sFhwqQJqTVIVUcMA421C2vxiqY+p0AezGv9Y5+xaixeCHrRfMw9R6
         Dvd9ZGCBtLd4tPc/n0IY6BMJm+ji1OqYkFHLscd8MyKpDbHl2dhq4ifi0B1h6UG0wcJ8
         4YsnO4wYAMJudOFyTeoqcUbcjMLeYT3UQKFFolZflBWwrjd7GdkRILRKBmz+fnbH2Fbb
         75QA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=vN8XaLxRZ/OaTegNxMnoO1+KiT/204vhJHg9AqypaO4=;
        fh=Jf0xCqTlRjK28/wXxqkzKYfeZIpSEL43QLXRsqLI688=;
        b=h8PCfn5b0e2F8Qr4DuP9FEGNQx2fRVCpz3fGzb/ivFgCt+jdRiV0UyNmOeagWjge7l
         rbvRk7vIDTkE1HBk+zvwgfBmnP9IG+Opx2AO6Z2BvFxuM/4qSUoLGhjrAzJCJoC4e3hw
         ea9cHhDsx8IhGxlph2VfDqc9HjtnpoZ1Cyc9Wcw0yFYjH6Bq142+4/j9f9pha0nTpJeQ
         x8ld0sYSHanFgRdHpHzU93/5p9kd/+hjWix52dvUuZnt3SpGh11VOar9DxPQxb84CcAd
         CxEF4Y1M1USy7WXCqfI+6jYNW8/U6bG6Bjpz3b3xNlar+WFnDX7aRKABdpCaLzNO5/fi
         xp/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lkdauzdp;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756824604; x=1757429404; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vN8XaLxRZ/OaTegNxMnoO1+KiT/204vhJHg9AqypaO4=;
        b=IOV1MbrlRlxqGNmre1lDKPaQJST3R7EKvWO3ZxQNvyJTWjeeuA9nXccpC+VH6QT6re
         +g8e5E4geTvDvE8nYaCUFUeBEvemSOvJqhEFvglCHraFSemdUVXhfjvxWbIBsMMrDD58
         9QMg4WjxQAptTIiYdw4x57HY26QBzlY8XHQk5uFjzLiwW0AtBEF6tvJlWmgLf64udFRi
         gYvKKg6xVAWxUtvOEIMR02OKftRsHjNQx1YdTrfsG5XWGLvh2/UnDvEuoews/q1EwYia
         +DLqVe+IE/jmaxDaUHkgTcYJqY+ElbEvbAntJxOUiUk9H0vOJDrrAyoWbwGN20hOZ3PI
         fHkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756824604; x=1757429404;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vN8XaLxRZ/OaTegNxMnoO1+KiT/204vhJHg9AqypaO4=;
        b=djqXbjVpf3JvpjAA8WUrI/tjbZnjYPGSZ1JkcXwE4tK8CNxxpbg091jV6jnyN7f2Jf
         HgdIyB19cUvys2H1+yydL2BcDoEgRQF8HkC1IQ0zeU0YX8vu41SGCk2bSScNETKVWh6K
         OsRbAfaMb01jPsumPmYMPhX40TMpLBrFmajr847XrUJpvMG3T/odgDgO/Gu+YMnTEUcR
         ruFgEXY7Q6P+Cu48lfnQsAC834M5zjHB4W4GxfUCXBphyWCycsWi8dBkHojPKkeCtVYW
         qYKQqK8W9JGcydla9uCqUHZ7Uf8J+5OOuA1zQY8PWVMnAuqoKD66YsEatJGdtZZB0xAX
         htGg==
X-Forwarded-Encrypted: i=2; AJvYcCU7fcEO/dmtNhWwW038T6+uzUHIkeyL1mckdMDZunn6WBJMz3tZ1XGKDF/I/HbHrQWORtjleQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxt2NG4/sLIW/Js6f78t+ARqpE/H54gi6YZEkveY0FD/FRBITwj
	S48o91kp543SMS2BQbQbn5DQlPc3q3GothRXQhUigeSbXNjTIlFGD7J3
X-Google-Smtp-Source: AGHT+IH8NXLWgEmMmyj1paoO1jTicDxhozMJ4VJH4dSFlXyKpmIMJh2xYXBDRBp1nXd2AqV0nLP06g==
X-Received: by 2002:a0c:aa07:0:b0:712:9051:c001 with SMTP id 6a1803df08f44-7129051c60emr72349676d6.12.1756824604256;
        Tue, 02 Sep 2025 07:50:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeYS7K8urefvcjOzPC/+QOizra2q2tnTBYa+BUyuvM0Ag==
Received: by 2002:a05:6214:301b:b0:70d:e7ba:ea21 with SMTP id
 6a1803df08f44-70df04b1e47ls88038926d6.1.-pod-prod-09-us; Tue, 02 Sep 2025
 07:50:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVA/yr5XnIw9qAvzbcEHMUti9XHbeTPnhE754f3pWPg68OG6YSjat4AiwjNA+Q/tTBof7TU8YVWSjU=@googlegroups.com
X-Received: by 2002:a05:620a:4085:b0:7f9:d31c:784 with SMTP id af79cd13be357-7ff2b0d980amr1314532685a.51.1756824603055;
        Tue, 02 Sep 2025 07:50:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756824603; cv=none;
        d=google.com; s=arc-20240605;
        b=FxAwHX3PqImtU36zrSu/jmvlJSfo0Ld04ieIHsHxCP9ciY/dCVX30wGs9EM0b6aCyl
         8U+CDAPe1hWu/3LZZiH4O0XYEQkrAudtGsuE8iZt45yl9dxA4KotN6Fd0vfTAoD6SWvn
         P6J9BTi9LkPrlxQavQHwZ1KfZIeg9xcoR09YvBUPzL7JRh3H56roUwQfQAgh23brAk4j
         PewGqvAbVCYfxXTw6yp6opSERAg/qJwgdiNQm7p0gYK7EjH5bfLPf/gE6daqowk/tU1H
         V/co/hCH2ZG4K9UaxVHjuSqQIeN88jtGXozpCQ30x0+TEsQphYLN1xFIs/smZlbdkR+j
         /gTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gBN6TymVGMKhXDzN9igdXoFGYHBR48aWHHpqoRKUgm4=;
        fh=ShBgXETKwNBX30wdInl0EHoVoSAuG18ihnf6j2gSbWU=;
        b=ZoSsQU2wn0vDtGbeM9fKvWjNLzKeqbxUzettMVPW2sJxRHjgelXJ/M6kjsKXVkk5mL
         d/NATaJqjgDE8VwVGg9a1ly8FwgIPIfcMLbyYdKAvhYAqsLMvkeJ5ejoY5VgKVVDtwkA
         ThK8MnYm8BmjBJopeZudpMpgaFT2Kwr/wE7TWVWN9NCRW91T1XVbWyzqJ5sHewnmtDAk
         /rU40JZKa+JJKcyl5hcOr9SbBZ2WoEpiNl3MNP+hcE7n9F16k/V6Eh2+lHT5jaJP5DN0
         tl+tC05NIddvlEhL1sIyWtTb3rQBuivs6vdwHR9wnkv7qnN1rGqYl7xdQQ0i00EBsdKF
         MJfA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lkdauzdp;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8069bf66e25si7952485a.5.2025.09.02.07.50.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 07:50:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 4A6A641B36;
	Tue,  2 Sep 2025 14:50:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C5010C4CEF5;
	Tue,  2 Sep 2025 14:50:00 +0000 (UTC)
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Leon Romanovsky <leonro@nvidia.com>,
	Jason Gunthorpe <jgg@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>,
	Danilo Krummrich <dakr@kernel.org>,
	David Hildenbrand <david@redhat.com>,
	iommu@lists.linux.dev,
	Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>,
	Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com,
	Keith Busch <kbusch@kernel.org>,
	linux-block@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-nvme@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>,
	rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev,
	Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Subject: [PATCH v5 14/16] block-dma: migrate to dma_map_phys instead of map_page
Date: Tue,  2 Sep 2025 17:48:51 +0300
Message-ID: <b6356fbc547963548f2d4f035fb2e85f9d83ff99.1756822782.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756822782.git.leon@kernel.org>
References: <cover.1756822782.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lkdauzdp;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Leon Romanovsky <leon@kernel.org>
Reply-To: Leon Romanovsky <leon@kernel.org>
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

From: Leon Romanovsky <leonro@nvidia.com>

After introduction of dma_map_phys(), there is no need to convert
from physical address to struct page in order to map page. So let's
use it directly.

Reviewed-by: Keith Busch <kbusch@kernel.org>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 block/blk-mq-dma.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/block/blk-mq-dma.c b/block/blk-mq-dma.c
index ad283017caef..37e2142be4f7 100644
--- a/block/blk-mq-dma.c
+++ b/block/blk-mq-dma.c
@@ -87,8 +87,8 @@ static bool blk_dma_map_bus(struct blk_dma_iter *iter, struct phys_vec *vec)
 static bool blk_dma_map_direct(struct request *req, struct device *dma_dev,
 		struct blk_dma_iter *iter, struct phys_vec *vec)
 {
-	iter->addr = dma_map_page(dma_dev, phys_to_page(vec->paddr),
-			offset_in_page(vec->paddr), vec->len, rq_dma_dir(req));
+	iter->addr = dma_map_phys(dma_dev, vec->paddr, vec->len,
+			rq_dma_dir(req), 0);
 	if (dma_mapping_error(dma_dev, iter->addr)) {
 		iter->status = BLK_STS_RESOURCE;
 		return false;
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b6356fbc547963548f2d4f035fb2e85f9d83ff99.1756822782.git.leon%40kernel.org.
