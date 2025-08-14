Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBGXO63CAMGQELIBSBBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 30065B26213
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:14:52 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-30cceb36c8asf1307282fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 03:14:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755166491; cv=pass;
        d=google.com; s=arc-20240605;
        b=cSmMMd/SyoJXOB7uXWg6C19NbCg2BIZAVlHzGbKnCtuEIHNwtW+4n/ir0ww+AqUwPY
         tj/oz1EFjH662/BkkQNLVEpTU8NAjt+5E0m+leBezMNls1eu31O6+Ixh93xbIesM9Ohb
         mvZw6253TknUg6ZYFcbigcof6PtgE/sAn8ocJZ6rTXLaJNfyvluh5thdzV6EVn7QWhcT
         jRj+L8hV3xtW59XQeG+orUYa6uun50AcHQctIpUXsdkwJvvqwE3eIaiS4z7XHtRtP539
         4tfiG3QMc7JyFrnEdjSF9zQiS+ATAimXibnWIOToDWAMuOaAZ21S0gq+ZZe1Qb6jvkM0
         7RUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=uchFWEk/xLgAI5ndHTScHY7LW3Yo3fY7w+uMeKxlD6I=;
        fh=ieUmEof8JTVpil/Bw1yIM9UrPQkZ1pPdQ8CFl3mwhTs=;
        b=SaLrqJUi0JzcZRWrU59qnwADySPZWx3g70sRz46jjaEQi8iZuywoOMy06geCv6nO+G
         AB0/e218F4AoWG7lNwlRY+TI3IAMWKuHya67coGnZ5IApzHVISihN7Wrx1AZWrVgRTWQ
         ILc2/ZqzszoYjENxMTn/gpZts3XPDV24GYHVB0mLgetQ+Yi2bWk+553vJQzWwkJ6ew/f
         H9hg5CZJ5vGvcihr2M3WcZ/xyDFWE5NwbVqriYLEJufih3dwSZ29wojcsJ4ikRCCkXDY
         r/y30eh7iMFAKvsvL+DjcB/Phk9mOX/D/hgB1S3oIvNx+QF9JeJeIhmYG6oUdzwiktAH
         +4VQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Yjr61GWr;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755166491; x=1755771291; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=uchFWEk/xLgAI5ndHTScHY7LW3Yo3fY7w+uMeKxlD6I=;
        b=JZbDSdEuoO+l0CZcIs9G/E6owbJEtLq3No7bjkN8rwrGOYRoUEO3EU1asmNVt56VjY
         r6H6fehNrxet3yriaWYK9Sl99AQD/XIAhTqAZ8ZOYtB7gwW458eaahXuwErsjsY5kXVZ
         TACUa1s3Al3vqlhAXpw8oNuhkAm9SRQMPXXk2sLBI145moA5F4eW96oMKjIdaqJsdvfr
         xJ+TTjozo1qa/VijweeQan1H5XQpv6rLgULXXh6sCuC74b41Wl9eJcNiIUkPz3MJr47j
         YNGi3fz09eo7sklDk2ZZVn6Qe51HKKxbM0inq4p2oERlpCphPWLEm4RPGKdYgqjFZS0M
         PDfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755166491; x=1755771291;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uchFWEk/xLgAI5ndHTScHY7LW3Yo3fY7w+uMeKxlD6I=;
        b=eBdk4HCb+/M/4aH+I9OHEtwXmb9skeJOEW0Iel/wFtRp1ijYIBSJwqQ7KZnXYHrrMX
         vRqGKOh2h7QGwUDSxau38ms5fM1mwlwMlR+DwuQWpqSg8imySyBQCSk5y+5vEvoGrLDh
         JUIv9gVX+Vvvdzcm1Kjh0ZoBMjf6yaqDvXk0oREcXAR/Dg8o2ZI43Yge8VxTRuCLhd4Z
         NChgx+oiwHFcQJn2cMKDoWjKLX4cgElGdRrLZ9L8W+PzyDXY4GnJMnCcPYfQmLCg+uEo
         uguJKR6RYmvGwg7J+ZTkczuMUnhxrgMrx1dqNATId2i7J/RKLfG99yS4VClnbjbzZQSx
         JgFA==
X-Forwarded-Encrypted: i=2; AJvYcCWmEDs3iPx1DasBsyE3B3RF1OmL4Hk8i/qZWgnRO5x2dGvEcWopc2fV4JWZl06YwMAa698wwg==@lfdr.de
X-Gm-Message-State: AOJu0YwCq+17O0Ctb8gzsPrjIR0fXYmdak7x+jY9EGPlWFJuvlsAWnZG
	uspuAkIcASmswAJTgqgFYzFk88dxeC2Vd7QwCPtO3kkIk6sYT7L++dm7
X-Google-Smtp-Source: AGHT+IGF95AfcYxnk2EJenCAvtIQQMrbcxH1vJ400d7dyyZvjJWn4nEo74r+7aHaiA1z1zJ1/6DSnA==
X-Received: by 2002:a05:6870:c0c4:b0:29e:27b6:bea5 with SMTP id 586e51a60fabf-30cd130fb9bmr1529995fac.25.1755166490948;
        Thu, 14 Aug 2025 03:14:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfxPSFWKgFZwmQOJSmTSazxvMrf4tXjqbzAgUemydoE0Q==
Received: by 2002:a05:6870:d152:b0:30b:c2b3:2130 with SMTP id
 586e51a60fabf-30cceb68b39ls448433fac.1.-pod-prod-05-us; Thu, 14 Aug 2025
 03:14:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUh241IcWim66MjaBrXdPYPBpgQPqO3aS23hOxMD58GTUXZXr1LdFD1DEHgWs6kXIGWI07i5xufwdE=@googlegroups.com
X-Received: by 2002:a05:6870:d29a:b0:301:2bc7:61e7 with SMTP id 586e51a60fabf-30cd136490dmr1524738fac.26.1755166490183;
        Thu, 14 Aug 2025 03:14:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755166490; cv=none;
        d=google.com; s=arc-20240605;
        b=gVbuGdz0zwXTuMDb+Y6GdhpiIi1kpaeqr5puHDWN9StjTy00FDqX7nd0vq16Dyekb/
         c2dkh1rMNfjSNezxwmBE4PrY+CV8OQF6GJmjpG+oyQiUxBH4SAkUS31BJA61mpCgsTc0
         QGbSvUw7PlklFoCNGE+yZZBJw4NXkuzA+Ek/Tbu41yjzE8TZLEwyTK41EqicN8EYjf7t
         CcwUrtvuN1r3rN+SZIs5LTTiRKNGH2jOs8apCvHZ5kRMq2V8OKiHiF9G9gFLqOGgWIQG
         PG551ocCrpzhNdC1bT5ERHDGiKu9LVOhLuZ83ywZXdJHKfLhm1EN2FGj2AK69y2LI2mX
         C6lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XPxNQF8Cx+yhCu6yL4faxmro9U88DCzv8Ndb1qLzzQ0=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=lmbkapB2tyR5kNwCoAQzDOXKI4vHcHaeRtWDEaE59/0tz3yIHLIBByvcjk+UYhy2KH
         RQTvvynhQlHPF5VKs4PWGELZ0N2nRNfPqiEZmcy2N+6YhRaE4iLcXrWDherwQjDfRIuI
         8NAbaDfmCy9zeAAJat0H09EzDutUuMXkNwmjaNOz+FO5T+YhKjxWglNt+uf3VA3eInvt
         NKxz+9hZVG9MK2tWgmFI41gVYhXRAMXIrNyJCPlLvn/iQzV6spDvHYd1Y3pNHuQsR39g
         5MuAEZAt5kcYFMxzBmbAYn9gidG1NPsgCM2zW7v6k3Rq3lrgCzpnGMsSl5x8RyXmqQPt
         lRIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Yjr61GWr;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-30cd009662esi90994fac.4.2025.08.14.03.14.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 03:14:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 8F9236020A;
	Thu, 14 Aug 2025 10:14:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4BB3EC4CEED;
	Thu, 14 Aug 2025 10:14:48 +0000 (UTC)
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
Subject: [PATCH v2 14/16] block-dma: migrate to dma_map_phys instead of map_page
Date: Thu, 14 Aug 2025 13:13:32 +0300
Message-ID: <a48cbbc074bf11c92b29b547e44f495a4504ae9f.1755153054.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755153054.git.leon@kernel.org>
References: <cover.1755153054.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Yjr61GWr;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a48cbbc074bf11c92b29b547e44f495a4504ae9f.1755153054.git.leon%40kernel.org.
