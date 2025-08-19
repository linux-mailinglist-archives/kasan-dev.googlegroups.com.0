Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBI7NSLCQMGQEIRZCLIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AFA2B2CAEB
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:38:45 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-30cceb74bb1sf4676301fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:38:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625124; cv=pass;
        d=google.com; s=arc-20240605;
        b=B0sFloy7fRokC8AhWOhjXFtgtKKtHuGI9ELqv+GcMFG2kVEyaUH9fP/0uNuoF5kG/5
         dmgJYHx8urT6HFDA4/NSwyZp0zszoaPKzkznktBxtW/kATfIWU2QJ6ujXs820M4o1wmv
         GO7lI9JdB2btIocOET4cdSv3RG8Wo79HtWv8yGUlEs5TC1jbFEaZl2rma6TTT/2yyK5j
         0XjPr3aN9EpazTZQ/YkrR+nquYMJ0Fe3dYgIjrhyv/ZIAobz4+yNb/A4YR/T+YVai79m
         uZyW/x1Hkcydj2G2dR1nMIwuioxZ3B41V1XofIHOKb6440LRxfGAel0yAQIrH8dEBz11
         CP7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=59QbwFUWO7w4TTo5j+hc8wCIKhSlZQvrcinz31ZJnnM=;
        fh=fg+5vDeFBT3pnGwj1MEsWZExThkkx6XZ4LxMrTJuhXU=;
        b=VS70abA/a3idE2guPREMZRff4DcDLPTkJtyLvqVSdlQfmS4acxgEFdyW9jauNruIwM
         qD7tYcaf4ElwyltO6s73nUIHDgbKBwoRTvW797t62FANtIw8qSl34n3FE0IkSKI12EVS
         2YMgxhy3Emy9FZYkAisekaDco98WtnJXUtArIxEv5DBAGZlr24yv9eekOW2KLC00KYf2
         X3w7MHPE5Ti7EcvOuliNKlD8sKurju3FFS0UaBjcsg+snLgwKhBUlyvEtMkZypgOu1RS
         lgLxtdESeMd0gjgvCepG3PN3M0cWpXTonh9daxtgO5hdUKYPnmPIDAI+B8foELwLSioY
         +5Sg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QF95AAuh;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625124; x=1756229924; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=59QbwFUWO7w4TTo5j+hc8wCIKhSlZQvrcinz31ZJnnM=;
        b=gbdgJpq2oDReJhk0bRDkaPDdO4o1a5FZrdWFnGzaddnyMiQ4nylNbB2LLSaB52ynwg
         7ujs9J3z8CRCiedyWAXbJuTse8PTvGlftMca22adVlCcbRrXjiArhO/EzD8Q7w1zVEVE
         Ul9bUzUbiTZjFS9kXV10JRbsX7TKgmD3GCtruNM5uwJiQtuWROSxY05kaoLXIWjRPemo
         woyn8R/3vPn96JPqQbnHQygzWqBC5X6NQ6Bu7jGxb9tUSSBTpHXWmGPUTJhGQ9HgqbuZ
         cEXGLLnjVYfqunYn+S183GuODLyJiq9oCIWStdHav0o2TkC9q5zbkwJSFLGfz44R2KiN
         Gjww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625124; x=1756229924;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=59QbwFUWO7w4TTo5j+hc8wCIKhSlZQvrcinz31ZJnnM=;
        b=msNjf5wj3+Qa3qaN7BPdnuXD7Qq0/dbF5boD0aw/sQ7CsTswjrB7KW2zoFGtQ1VX2A
         3bx8lZEkO3qvGR42ffTos/DgWNSWo2HQrdyDAae5fEqT6HoXEYkGRxMFSIO2TEnx/WEK
         TjiqQ7ui0s/6X7U0+cnTQ4O7h0eCwppqbpvFXavzMcvkZwJdYCGj8X6wbw0Fn67teeUZ
         QroOSFgip7MSygi2emIBZuHTT8NbONWTi9DZ2hqur5tSStDUpgElPTkU0u6vLqJc7NGH
         p5qN0m5ZunRbBm5ow/Dgw8dgHHcTRIk94rh5mlkpMBSg5R6FKzcUvcJ20SFn7P+X0nrI
         Ws7w==
X-Forwarded-Encrypted: i=2; AJvYcCXrgFoqZXnre4a0ksBicMIsZa5IhymtUUsVM1VbYCAS6dKOep/DPHk5o2xWW4RaQGyY5Jc3Sg==@lfdr.de
X-Gm-Message-State: AOJu0Yxhcw4NQLUk/7wCtCSajSm2m6+N0EfY7XIkvGuWYnysoSwWQTMA
	G0iPNSB6tMw8Ea7v9ahPmCqStKi78BDB8V3YY3roSC210o3sbk/RdbAr
X-Google-Smtp-Source: AGHT+IETfGQp2sGMaF46g4q2DMYXjqhn0dt7tNpA0dW/iL9JuajplhuVxPltn16n6rWsffQUL0Go2w==
X-Received: by 2002:a05:6871:28a1:b0:2ff:8852:da88 with SMTP id 586e51a60fabf-3110c25306amr2288867fac.18.1755625124058;
        Tue, 19 Aug 2025 10:38:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdhGq1YrzhF5BFkELYlvuxQirA4w6FPYVM0sILYrbKE3A==
Received: by 2002:a05:6871:8403:b0:310:fb62:9051 with SMTP id
 586e51a60fabf-310fb629560ls553677fac.0.-pod-prod-02-us; Tue, 19 Aug 2025
 10:38:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU0QcAyByKvwUp7GF9QCr7tP2Rzj4uCAtguEAlq+n3IOMeH88BcvT9Pg1G9iUpait+JyENm0jCAHVE=@googlegroups.com
X-Received: by 2002:a05:6871:878b:b0:2e8:f5d4:6077 with SMTP id 586e51a60fabf-3110c3844c1mr2202087fac.38.1755625123208;
        Tue, 19 Aug 2025 10:38:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625123; cv=none;
        d=google.com; s=arc-20240605;
        b=Uu77vB67pq//JdAZukN4mUDmqX5ADYmHDK3FFldqtPdW0kNXnd3yPZ8EoU8p4O6qrr
         L4haR94OYvEobNRUOFQB4kX9bAyX/tP/ln8D/hXRJdpbMoepJTnTpxSJ5kwnZJD5T/xD
         iQOZjNvcGnHxiN7eLsVd8Hxgtn9EeDr55T/3dZEMrxbrKL6+duxajS2qS547O/gkitKE
         g+xZtGsCyuCk6GjyGwCwqdZjXLkKFDty+7lQpnb+fTP2X08wYvLS54naUzzBClNwdMJM
         g0zEMjzQGyyjwJkHPhGg7Gbnh2fSjaG2pHfnN4jEstyCNjx6kbCRNn0Um3KVo/lgFfpi
         OP0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XPxNQF8Cx+yhCu6yL4faxmro9U88DCzv8Ndb1qLzzQ0=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=NShQqdtzval2UAsSf0Gcb6CMIyxIk0smE+VwQ6LIpKexIiBJLX3qiBqdigsnAjFhMe
         8R6fH4oJ17JwBfCgxzHzMA06U934X0qe7L2Hhfw7LskovLoVX8KPfodRYfCi0/PZlTx0
         fPSF93djuYZboO0yqCQ0dZYf/EcTX6qNLTulohDaRIcb9PK63X8TFX2Xc+Aci7wQ0wlr
         EeKPbtPsscwPEAoTWZlK+GQSXsWnSa1MS4nnPV8hlf2szisIMVpknGPxsgz62/TJsteM
         Et96VcBkdqO/hwsWvX711LjAkTnZAFCkfnyq1b3ejYqrxIQA2GWkKDRVOlBS4a8Hu0sm
         sBqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QF95AAuh;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-310abaf7bb2si570217fac.3.2025.08.19.10.38.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:38:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 7DFD3613EF;
	Tue, 19 Aug 2025 17:38:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E7E8DC113D0;
	Tue, 19 Aug 2025 17:38:40 +0000 (UTC)
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
Subject: [PATCH v4 14/16] block-dma: migrate to dma_map_phys instead of map_page
Date: Tue, 19 Aug 2025 20:36:58 +0300
Message-ID: <22b824931bc8ba090979ab902e4c1c2ec8327b65.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QF95AAuh;       spf=pass
 (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/22b824931bc8ba090979ab902e4c1c2ec8327b65.1755624249.git.leon%40kernel.org.
