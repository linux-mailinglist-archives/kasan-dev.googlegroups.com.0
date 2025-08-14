Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBBPO63CAMGQE4ESBVLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id BBC4CB26209
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:14:30 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3e56ffdf1casf21646495ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 03:14:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755166469; cv=pass;
        d=google.com; s=arc-20240605;
        b=BOMwMiaW6QRKcO+TKgEm8s+LAY0gRcG4yP5jHV6yY+VLYm3jFdenBHnaFdk9oUHrJx
         Zc8uYKZhVT5IhknkgTauVJCAWqwGwaxWvWM+L08NAVnZKyxhmqYRNQl4gUnp/8qOz1IZ
         tWBALjlBQ5r0erEFzAV6OioBkCwcK/HWNlRA2Cvnk6hBshl2SjI0A/Rn8oGUd4t69dS5
         5OBV4NSWkkN6PG/njsP5f/Qe0Mu72jYoZZCHWg+okD0H1aL+TcDehFcdl1UEuJ7Yanad
         G3Q24cL2o+qMneqvjmo9cMkNgWZt9vDKP4B+DtsTRxy7TSXzLV0Q1gbElr4SxuIGYoUI
         jl7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=T5xNoZpddfQhcbGq4rl6V3F4q7tM2ZIrxKlE8VWh1eE=;
        fh=YcaDBwGgd/PgfkwmO/EUI20DL1wpPYLs5DvnP5UBemw=;
        b=OOxAVZHhDmqzk2gSN9nfWsmrz4vgGyKa0hGrmvUOyjddIynhKSFzXZwtcEVre4VHlv
         M6WpHaGJIieVgxOzkY5DrlTIutUoRuIWY1YFBynR4ZUY+d6rRzgFAvMsHKbKzRvbpoyX
         jWkxfJuLi3bZPL+6E6L0Ruz8ix3RnFozXIEmZrYrMPsA2ZLiJI2seJ+GxbEKDUZol9DZ
         lD7FuKZ6ys+Fehm0GwPKtPe8SZpd+0gT9wIxkQ6Hz7kApPNCYyr7QTQF4H+YzWHQ0r2o
         atzEYG9y1lDuaII0hE1HAPnotEAAMsrzG6LgXwvLwuZRGnHZIZDClYk7pnZXKoX2CmOf
         SnRQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eJTkq+GT;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755166469; x=1755771269; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=T5xNoZpddfQhcbGq4rl6V3F4q7tM2ZIrxKlE8VWh1eE=;
        b=bWOde2Tf2hH5B9thcMHwokAgdcvg0YbNhncDRM/dPa9ecB3jsiNDPZVms3NmxNP41B
         wAeoNzsk5RsFjprW8DLMbY/fsSVApR6bxWBicPpm8q57imKRI1glR6BZeSzJu1vj/m1M
         llhlDzQQU0BwBUvu8/5xLesLMJ3AslsW7g9Qf/bWXheYTQdtMv80xCyZ68Xgd7Rh07YR
         IXCTGCqV1/E2TdoZDMzgBEFD6rbCpVeJDyewaKtcO78lAQLruJ+D0YFO6NCyqglTJ3Ia
         dpUrVURoxehCLHrHpzzSMfRZ6O074PIOfyYfML8KmMm4sDd6/SAtG1JVQv1Nt1f5NT5u
         wTOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755166469; x=1755771269;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=T5xNoZpddfQhcbGq4rl6V3F4q7tM2ZIrxKlE8VWh1eE=;
        b=pbG7Z2Up/QawRcBUtbbBITje4vgCmWPFx7xb9XVVsqIHuk3HAYiUxb5FKpNBO2AqV0
         xFpR3lWqdPFwao3c6J1KRbLFggPhvH5qi9LJZPq2d41PBOSSJXbL8DrnKhTcpUH0hW3Z
         l8vicCSei8o+YVO4HiYUI2mrujRe2FUuA5SoUXK0p3Kp4U3BZdVKFpvHfzHlziYLi5Ob
         nGRLgdVHXS46Eox73l3sa3K4S5QM7ZNRmaM+nXDBPdQOyUgg3/I4YiAv5+bAuLlTZZa0
         2HYf4KG9JnjLtvXklBLa7mvu01QsdGDAIicb8i2KpDU2qP7mWEnHOVkqsShbuPJhvXHt
         Xwcg==
X-Forwarded-Encrypted: i=2; AJvYcCVgeICcbmRJ8TZEAAErhAovl2FlUfRp4suCTyPgjE4wV81Hd6z4UkDOneiHgF/s1nV1rXPXdg==@lfdr.de
X-Gm-Message-State: AOJu0YyX5t+9U9OTtrf78TksaM7BCOKn7EVBpc+aY3pk4qOtfaNRYfR1
	dwhHBVvD0zlKOgJ6Fgi4iFnIToQFD7Da11Jli+NWdVvsBZuUMFR7Q9bu
X-Google-Smtp-Source: AGHT+IE1yrqC0nEDrxOcEq5ZglZeoUl7iKamyONCgjJOED3/iXbLa6MCNmxpOdMux3ukRbX1W7F6xg==
X-Received: by 2002:a05:6e02:3e05:b0:3e5:5937:e576 with SMTP id e9e14a558f8ab-3e570914fa0mr40396315ab.13.1755166469422;
        Thu, 14 Aug 2025 03:14:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZep7Njt8rj/x5HKs1trt66eTay4PTemknwfKoK20MNgfg==
Received: by 2002:a05:6e02:1253:b0:3e5:50da:c386 with SMTP id
 e9e14a558f8ab-3e56fbbfb85ls6755015ab.2.-pod-prod-05-us; Thu, 14 Aug 2025
 03:14:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW62jfe2UAi33AB25epB2AS3DNJo+/V7An8nfwdoSlW/Lk/toHnQbjFI9Y6t1wYYfkPm2fogb5NGj0=@googlegroups.com
X-Received: by 2002:a05:6e02:216a:b0:3e5:3ef0:b0e5 with SMTP id e9e14a558f8ab-3e57080bbd3mr42432365ab.7.1755166468228;
        Thu, 14 Aug 2025 03:14:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755166468; cv=none;
        d=google.com; s=arc-20240605;
        b=ANo9Sft4rWQm/3HanALCu70PACs+cUb1eW0bzCLU7pYut0HK0GCsv0ShULVyeJQNNk
         Cs30c89VSezIbJiR/n9QGTk2ud9Wm9ajIRNafryzvL1IDynGRiiXXqkwtvm6BkTOEEC2
         I594GT8q5pzVvx3XgP4iM51IeZzD0rJiCaxyLrFvwRDewV3bSyBlbR7oscTe5cKoSYXI
         IizYcFrVd537xWM6UY5GNOZM7o0YAB8LIU/jj08EEcnim5AE4srLR/zacp31o2RglRgC
         4Aq/Upoi4/Qw2hHw93NcZLsKyPDsZRT1/fvl3GkCVmZ1Byb9b4aG7gOPHOHZ2QAeyi04
         8PQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Py7VOBxcd4HwAc7HHDB+PTMRXMSLHO8b88vcAnVEU6A=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=GaWACV9+UgU3UAh00KCXMYPJyc+aMqWv5+NhtW3eXTYtOQjHr8DnoJ7yibml/rYfZt
         eikRa0qovfV2GypTMNwvZbjnRLEujdvo/pylicAj7FVeRbwcFyJ0Q6KXISDk93JMdQij
         Nt07om5LrBiALZ2KTy8NCYy6eE0yEUBmA8e+7BxloAD90vXHTUAIc1V2ukbKb/p+l7gC
         h9JF1BlwV253MZdkNg55toQPIR+5njvV1H2CPSbFmCa/Szwh2URb52CNG36IelLvyFXV
         +6tZWnsceMSQGPNBd39Gu2m4zUJEoRWHA8si1VwpAvoeqlgJF5f2gKrzScRdRzZwIvys
         HbZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eJTkq+GT;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50ae972f695si635277173.0.2025.08.14.03.14.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 03:14:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 9834F6020A;
	Thu, 14 Aug 2025 10:14:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2BAE6C4CEEF;
	Thu, 14 Aug 2025 10:14:26 +0000 (UTC)
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
Subject: [PATCH v2 10/16] xen: swiotlb: Open code map_resource callback
Date: Thu, 14 Aug 2025 13:13:28 +0300
Message-ID: <972e4cd98b0d3683e02d06b7a35a2c1d76a226e4.1755153054.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755153054.git.leon@kernel.org>
References: <cover.1755153054.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eJTkq+GT;       spf=pass
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

General dma_direct_map_resource() is going to be removed
in next patch, so simply open-code it in xen driver.

Reviewed-by: Juergen Gross <jgross@suse.com>
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 drivers/xen/swiotlb-xen.c | 21 ++++++++++++++++++++-
 1 file changed, 20 insertions(+), 1 deletion(-)

diff --git a/drivers/xen/swiotlb-xen.c b/drivers/xen/swiotlb-xen.c
index da1a7d3d377c..dd7747a2de87 100644
--- a/drivers/xen/swiotlb-xen.c
+++ b/drivers/xen/swiotlb-xen.c
@@ -392,6 +392,25 @@ xen_swiotlb_sync_sg_for_device(struct device *dev, struct scatterlist *sgl,
 	}
 }
 
+static dma_addr_t xen_swiotlb_direct_map_resource(struct device *dev,
+						  phys_addr_t paddr,
+						  size_t size,
+						  enum dma_data_direction dir,
+						  unsigned long attrs)
+{
+	dma_addr_t dma_addr = paddr;
+
+	if (unlikely(!dma_capable(dev, dma_addr, size, false))) {
+		dev_err_once(dev,
+			     "DMA addr %pad+%zu overflow (mask %llx, bus limit %llx).\n",
+			     &dma_addr, size, *dev->dma_mask, dev->bus_dma_limit);
+		WARN_ON_ONCE(1);
+		return DMA_MAPPING_ERROR;
+	}
+
+	return dma_addr;
+}
+
 /*
  * Return whether the given device DMA address mask can be supported
  * properly.  For example, if your device can only drive the low 24-bits
@@ -426,5 +445,5 @@ const struct dma_map_ops xen_swiotlb_dma_ops = {
 	.alloc_pages_op = dma_common_alloc_pages,
 	.free_pages = dma_common_free_pages,
 	.max_mapping_size = swiotlb_max_mapping_size,
-	.map_resource = dma_direct_map_resource,
+	.map_resource = xen_swiotlb_direct_map_resource,
 };
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/972e4cd98b0d3683e02d06b7a35a2c1d76a226e4.1755153054.git.leon%40kernel.org.
