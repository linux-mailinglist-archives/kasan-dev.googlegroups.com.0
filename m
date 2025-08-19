Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB3PMSLCQMGQER3SN6XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id DE661B2CACE
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:37:50 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id af79cd13be357-7e87069677csf1598038185a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:37:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625069; cv=pass;
        d=google.com; s=arc-20240605;
        b=ESjEvYr+FVb1583dV2pduB69ZNhbYssurn+e/0tJ+1EKuB5GhpSfc5Q8HhNvTxHght
         4tRSixFcgt67fHXNd1HgiIpKi2u2ngh/u1boG+gLTkTaP6gznqCzHWaZc25qK0s7PalY
         4yJoT9yybKEy1V2IAWDEwVDL2/ECY5HKMSd2iFhnJ1b+mvAWatWYVpcbRkxAFH7HoBXT
         CRkj/VZ1umWQ8Mhec/lJ9mXnNk+X0D6GEjCOlK3h9qrVtOioHnUnk5yb1naAKDOiyfDG
         Oiamr8IlKYNvWUPTXAjTcvfpH/B13D+/Ppy/bOoZzt1tlgHEJyxvw/GesmafXq6QbOaV
         mULw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=TPcC8cHqaOQ0eXI/8O0C+4eWjgt6G9nZK44KjCfSRyE=;
        fh=HeYw+p0bHRi+dNXsz2z7h/lgmRPFosCrnJauM1zpOxI=;
        b=dXk5VoPxYUXXqqdUgaQpGi4eZ1ZR/k1P1A1dHT77BaoaN87GM5fnyKwkBuIsIWv/KR
         Zrfiqm7D7YujSJQxfAS9Rq5neQy8RxZYvOkDacMM4kTmf2E2LwmHgFiU6MOU92Y+9mPB
         CGpihnUxPPNkYo+91LBTYwxEWo1jZha8hDl9zhVZFjphaulSUBMvpNNDotmhxvCTZKgX
         xSm5clyKrIv2LX4KvjJXI1tcEJUrgprgWepsSfDiweeudE4vL1xDfVIPodjh192ic4s1
         zNoZD22SwJCGyeAsGwt/7CpI3tTen9IE4D6aOpSKColUlRb9cB7CyfQsmjxEA2ZKSh2J
         Ca+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OoY3cFH2;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625069; x=1756229869; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=TPcC8cHqaOQ0eXI/8O0C+4eWjgt6G9nZK44KjCfSRyE=;
        b=Ik/PO2O1O+yBYS9yAyrRvSall2ml9sCtnf1KbdOdl65CW5Umj0itMZg5kxKV1F5m7D
         OpmpwsHrHbF5TJNOCnxNwQEkZdnEt0OJe7jKW+gRBPFt+axn4bzWER7uJRJ0GtubNgjB
         xOmFowuRALkHXK3B5AoMdLMb6KrlnGOjOm67XJ3EX8pFeKBkTgHUXUC/q1PeoksrYLGN
         PGZuddpo9NZ2713BQTYJmRSrpm7sb8O2VO8Lpc3FPvS93mWNdjh9owxVR2w5VYztCpSb
         kPIRCFi7xbuFiKK5CN42bCDjLXysyk70GnbG14YiLSmTr76gOtHVSr8Y21WTHtHAhrIb
         sRJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625069; x=1756229869;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TPcC8cHqaOQ0eXI/8O0C+4eWjgt6G9nZK44KjCfSRyE=;
        b=kU/P4MfWztjjiFSqtks3CHWGsB6Ap9X+8Jx4FyF0Ns9PyAPIPlNWO9SmKIKQMh2bMI
         qcoOckNXQ73kyri8BkBB0Lrr/t9IS53p6awJJjpV7yyGs6tNcI93GgSvngr5aWn/Jxqv
         qt1+9fXYaeUpoqHFiK3RNS3B7xghUNvFeLc3M7NMzbA9GbuAWiT7PNwVcUmKk/iwGN4z
         lsfITOrTMgP8jGQZUoik5/pTIEXsmqIAZdxVuMy8m5o9AmJBMfBvFNELYrKxujL0PEd3
         EFfYzhBVuH+OlwNbYUC7HbMmnFyoFGzw9ZLD7r9bko3FvamVafDqvHrAibg4t6qlbF2R
         NnlA==
X-Forwarded-Encrypted: i=2; AJvYcCWDoCo0mUcDV8sa8wLaMlJk/HQgyVfTBdsHancXpAanD4a1bZ3aRelWCsYmulW2GRJlhVFY6Q==@lfdr.de
X-Gm-Message-State: AOJu0YyTVMTemjfeBU+C8/fiSqVQmo92X1UpDsPcLNLOn57goaFe3W08
	aC5Txk7TKa9zH68hSfDecRN3OiYZMAIy1r+gOZcJPermEgdXuQdg5VGg
X-Google-Smtp-Source: AGHT+IFFmjFp+FYpptREdLpUf6KiQPV6NrLjB59WMzA0fQgZ0HEXbRwTgfDJ+vmnp5lpSuwLDKmbyw==
X-Received: by 2002:a05:6214:e49:b0:70d:6df3:9a74 with SMTP id 6a1803df08f44-70d6df39c3amr26411246d6.52.1755625069251;
        Tue, 19 Aug 2025 10:37:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdEX5YDr5sx0rCvHsFxLyC0vX4HFri6D9rONa+Eqfpo/Q==
Received: by 2002:a05:6214:d83:b0:707:6c93:e847 with SMTP id
 6a1803df08f44-70ab7a9f0e9ls103796966d6.2.-pod-prod-07-us; Tue, 19 Aug 2025
 10:37:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVXO6TwxBBknrL42Hi7M+h2p3SwUn1kdx+NrOSliXoTQEeguhUcHkPsHHlTteQtPfPU3/y/tJBxPOc=@googlegroups.com
X-Received: by 2002:a05:6102:b0b:b0:519:534a:6c45 with SMTP id ada2fe7eead31-51a517c83e4mr11384137.31.1755625068445;
        Tue, 19 Aug 2025 10:37:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625068; cv=none;
        d=google.com; s=arc-20240605;
        b=AcrTHw1+OHlP93CqbUw8ttum6V7lFj8Z0bfw3iDbUXtPGhKcD8ozwu5i7rjzOBX1yo
         eAKtA/t0eDZa8ThBrmlAELMyS+lrF+D0vfROqzNTDTZJtjT1q7YyEIJxi76PzHU3ya9w
         WkuW6rEmIcfhNFZ7w0o63i3r+pby7gnt+YCZf1IgTQxx+ldpyhOATKAjy5Vaad6M7zm3
         F2CYJ4JRa80Y4ifvlA4LGhPymfvosjmJDD4kqfJRAKAX2+vE3y4fRWBd3Djm4RTXD9Uw
         AFfGOWZCB9aVEGJya2WoFk3AG4oL78avvhF7n5GVB4rMck//NTXTl7w5sOdOAFXyuJor
         j7zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AxToNPSfI6WM9a997+Z4VoIL+Khe9+Ojk4pU73w2JVQ=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=EErkdEN9RTnaGhsXBad98IMPWhEBgqEjsvVzyGNrydMKK3GFTc0sSVSOoPO5yhsnkl
         +yIIlZy8GJepTp6Gfl3yJfYVeYutbF+A6mJHzVl9fxskpJM1kFLyzjD6pJJOG/V4/622
         yHMZVoMlgyZ0+hwtXxzOk1lHF4qgTPiLG7NWQt5FsRMwJofIGhSuQgXw7/X5XxK7CT4P
         bun0LeWZbOfFCWfC/sYi0xmglKvJVNjylbmELc1ordneG06TbHaq2tkNSX9+FPLj4grE
         osYvjrSX0Xx1WPcBoc2i5hd/h01LeDpcHMwSDK/P1eNn/7FpyYyYzdKC/YmA2Oh1iCo8
         UeRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OoY3cFH2;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-890277e552csi450887241.1.2025.08.19.10.37.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:37:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 68ED361428;
	Tue, 19 Aug 2025 17:37:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 20E31C4CEF4;
	Tue, 19 Aug 2025 17:37:46 +0000 (UTC)
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
Subject: [PATCH v4 04/16] dma-mapping: rename trace_dma_*map_page to trace_dma_*map_phys
Date: Tue, 19 Aug 2025 20:36:48 +0300
Message-ID: <d7c9b5bedd4bacd78490799917948192dd537ca7.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OoY3cFH2;       spf=pass
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

As a preparation for following map_page -> map_phys API conversion,
let's rename trace_dma_*map_page() to be trace_dma_*map_phys().

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 include/trace/events/dma.h | 4 ++--
 kernel/dma/mapping.c       | 4 ++--
 2 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/include/trace/events/dma.h b/include/trace/events/dma.h
index ee90d6f1dcf3..84416c7d6bfa 100644
--- a/include/trace/events/dma.h
+++ b/include/trace/events/dma.h
@@ -72,7 +72,7 @@ DEFINE_EVENT(dma_map, name, \
 		 size_t size, enum dma_data_direction dir, unsigned long attrs), \
 	TP_ARGS(dev, phys_addr, dma_addr, size, dir, attrs))
 
-DEFINE_MAP_EVENT(dma_map_page);
+DEFINE_MAP_EVENT(dma_map_phys);
 DEFINE_MAP_EVENT(dma_map_resource);
 
 DECLARE_EVENT_CLASS(dma_unmap,
@@ -110,7 +110,7 @@ DEFINE_EVENT(dma_unmap, name, \
 		 enum dma_data_direction dir, unsigned long attrs), \
 	TP_ARGS(dev, addr, size, dir, attrs))
 
-DEFINE_UNMAP_EVENT(dma_unmap_page);
+DEFINE_UNMAP_EVENT(dma_unmap_phys);
 DEFINE_UNMAP_EVENT(dma_unmap_resource);
 
 DECLARE_EVENT_CLASS(dma_alloc_class,
diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 4c1dfbabb8ae..fe1f0da6dc50 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -173,7 +173,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 	else
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
 	kmsan_handle_dma(page, offset, size, dir);
-	trace_dma_map_page(dev, phys, addr, size, dir, attrs);
+	trace_dma_map_phys(dev, phys, addr, size, dir, attrs);
 	debug_dma_map_phys(dev, phys, size, dir, addr, attrs);
 
 	return addr;
@@ -193,7 +193,7 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 		iommu_dma_unmap_page(dev, addr, size, dir, attrs);
 	else
 		ops->unmap_page(dev, addr, size, dir, attrs);
-	trace_dma_unmap_page(dev, addr, size, dir, attrs);
+	trace_dma_unmap_phys(dev, addr, size, dir, attrs);
 	debug_dma_unmap_phys(dev, addr, size, dir);
 }
 EXPORT_SYMBOL(dma_unmap_page_attrs);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d7c9b5bedd4bacd78490799917948192dd537ca7.1755624249.git.leon%40kernel.org.
