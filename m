Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB3HN63CAMGQEHNUDWZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id D5118B261F5
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 12:14:05 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4b109bf1f37sf17508611cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 03:14:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755166445; cv=pass;
        d=google.com; s=arc-20240605;
        b=I40gFt/YDyt8SqGEKEjkkA4zaMvZBYLI7vi6nqxiEgZ5riYgSwENms/sl2abE35W/a
         /k72MsUsqS6+1XhbwJjbsjgPLkikuEOAoPo0PvaVnJ1AsiXDuokQAXaaun/lqbRBr69S
         15ViuUZxVmDHEUS4Ge1uEcGE9Yai+H52OjnqftvAUk0JJk9fwUtY5nW3BdLSi4phYnZZ
         Nhj9vhVpS8Dy4NRdYe9s38p6YFmPIORPdQ2aDrLW8ZJMTx/7ZYv1+RxTp3EeDuGBbuF8
         Pg/B9gZ47E1NRc8CWehKhEshB+wJ/DJlyqI0Ov8VaM6ARrFcjupl4Hoyn0i5xPBTKXvN
         kfjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=HAR+O0bKr7GHlusJdNGyHbwXsZ0ZYerrVcagJm01S00=;
        fh=g8o4dDKmggef5V7wXFMEZ+LcVXxueKDwDpIEMfrZ20g=;
        b=cfeRpsTQimU5rVowHxrFDay3YcgLUTF8O/6w27Bmi/OS+mzUz5F1wL547uqfjCxbJu
         kjnH6ctK4qoqSQhBRd5TgM3ji75C6ee4YkVw4lRvYHWTT7BYkrV6+fXe8OyIW7oGwUNS
         G/m3gxdgMhPDjLBvrCArLAeK2NbSkrsFxTejPZO6whs6mm4Ve5hf0aUfG407Z1WxjC1C
         6LQCSv1txp+mf756O6pX/F1q1/8iOh2XfhIC38VqyqYsPET1quNEs7O1QQR0luPXS0CY
         NibgfCVS2hF44U2K1bd1w+Op60buPrCJkX3CxIe9p5U3VOZrogfFHUoBt1uKAuZUiBou
         4Etg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BGe4vleQ;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755166445; x=1755771245; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=HAR+O0bKr7GHlusJdNGyHbwXsZ0ZYerrVcagJm01S00=;
        b=iFyjjwVpll9I1zNZbU7WplPDGlcLOOjUkCtFPE1PblmyOkravpzZvny3qg9mT5SSOG
         rR5IwofVtzF5T+AWg1kL1Gm2VWh6oQiuGtLrxPZxzalmgF3QJ1A2TzpSt/7BcTXgIemw
         gW8wR36w/JS704ktuCTJTmxj2VoDlsra4A2T0H5rNZLaIhbITSClDBMeWL5ZzM7Kq5G6
         gskKfdla9Tfj2HuFSy79RdnKDNUXViYse3E08qrdGtTvZt9tSDFf0rbl7Z9eyU1zUyPp
         z3yna7UbyjiqGfJOEVG/VUgNkuLZDDjmhjF8car/jMVa40rm1xH1XXPl8uwEHcHRI8rM
         8MqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755166445; x=1755771245;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HAR+O0bKr7GHlusJdNGyHbwXsZ0ZYerrVcagJm01S00=;
        b=CTHxEkYj6gifjMVQLgiBWEZ1v4QSv1PC24GBcG0KMCZM4lOzwqh/FMfRmH2voikYJj
         /S6W99bbxtWXc+anKnW7QuiWaox3VfYrjvDD72SyvQ6WtrIXdNWPjSIWgVL4mFkH4U9D
         /VMKLTpMv2WHkboXJST26mmRKTAyGoaWSY44OM3A90uwMGn1P7q49Ydj9In1SeUxw3Sw
         6NjTdFfmLGlr1VkIi+QSn5W7h4cNedqv2PLd7mTpRvg9QNOs/IdmHjnJk6JEdPOMex6Q
         Eq/ZC+eElYhdvxfVyYvzO3Ld06BV7d5prKJ6dlYGOG9DCVmYH/U3XF5VP1e+riaA0gCt
         kTVg==
X-Forwarded-Encrypted: i=2; AJvYcCWy6datIxX2kfvwQQZEQEcjydSAICdYcuLxKtD7rPpfErwy4y5BmxZ/qP1wsKzfirYP9keOSw==@lfdr.de
X-Gm-Message-State: AOJu0YxmJcaZyoA+/DnuN8/YENzLtFEG/e0zZAhKrKOxnqFlMiEF2gXX
	/kTJrEu1k/8zReF+tssnHBAGMpUr3BYoOJw43fjjOTpCnU4Yb/C8hTCz
X-Google-Smtp-Source: AGHT+IFkPSBMErxLiFSTCTDDhxziO5SSoeSgiklFXPIu4mfdOwPB5XAfEfjq7k7fRm3T2IYR4UM8ww==
X-Received: by 2002:ac8:59d3:0:b0:4b0:b7ce:90b4 with SMTP id d75a77b69052e-4b10aab6dbamr32478831cf.44.1755166444604;
        Thu, 14 Aug 2025 03:14:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeUJksO+3gpbM9GXJ3xUx/qDd/1r62bMZzGEhNmvrQDOQ==
Received: by 2002:a05:6214:f21:b0:707:1963:15ba with SMTP id
 6a1803df08f44-70aae13c32dls10072066d6.2.-pod-prod-02-us; Thu, 14 Aug 2025
 03:14:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVr2H3rVGpNputy2Y8KT7ATcLVeKpjVZKkWj07Gr2eA/82zaFKE83HMB0gIpw2usZukPuFCOow0fE4=@googlegroups.com
X-Received: by 2002:a05:620a:691a:b0:7e3:4413:e494 with SMTP id af79cd13be357-7e8706c74famr392167285a.60.1755166443810;
        Thu, 14 Aug 2025 03:14:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755166443; cv=none;
        d=google.com; s=arc-20240605;
        b=POJ73F8xv4Di8jcBqK8DpsVdqEXGFysMQoZWtBLwvJsaQTR9KaRPXD0eLVaPYzRcsM
         IycrvamU+8/GZxiwSY/frwYyWDQ9DL2gylZeB/X4X62vjtjZrzd9HFvNGT7GfSwpXfVp
         L9gU+or0KoaKW+0DugaB5yNSUb9oduELAxTgzp6C2P1LmYFzhnVXU6bP9CGA6R1oK1iA
         xbYKoKojVemTo67KI2BVvSxgmU8IG8+RCCBI99GaQ2Xf3MMnVh+0DGBz1W/XMQCUiBIF
         HjTNGEeRZwMgy4pw50/2Yl0m2iAwFgfsMpTs1Praa9hDsBsVFxbBjq/mfufN8+SaET0S
         i9KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AxToNPSfI6WM9a997+Z4VoIL+Khe9+Ojk4pU73w2JVQ=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=NqoKRq/sf13FvWvFQgHcMEXdOXpRiJ7pdivREVnr/Lz5xZW9w3v23Gme1nvnQsLTuG
         zZoCsJhymXNo4aAc7Mo5jNjV/lfAHzc9Nzi7Q5bhZHmJ2sdOrM0Ud08PtZ11HgNoPUCy
         ohUfzX1SeZ3UbRGXxcAfXoWCqMNqCCP4M2dk2ruFXFeDilfPBJgDCVkwSwYhrutar7eG
         ffT8S59hw0CTxYKrkeKFiyLbzN8fjR0rtOPNrDeCjIXQfaCnLoC6rBNbXFhU4hTMhFXE
         YXoxV3or7CrOZ03xqics8Ptg2ARgPaHL8eHm1yy6w5t+f3CzJ5H1YsH0lcKtMOXdDfR+
         lDcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BGe4vleQ;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e7fe360ea4si114313485a.1.2025.08.14.03.14.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 03:14:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 6E0926020E;
	Thu, 14 Aug 2025 10:14:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0F402C4CEEF;
	Thu, 14 Aug 2025 10:14:02 +0000 (UTC)
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
Subject: [PATCH v2 04/16] dma-mapping: rename trace_dma_*map_page to trace_dma_*map_phys
Date: Thu, 14 Aug 2025 13:13:22 +0300
Message-ID: <18459094e29f22a137a9a77c614bcef07963f769.1755153054.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755153054.git.leon@kernel.org>
References: <cover.1755153054.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BGe4vleQ;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/18459094e29f22a137a9a77c614bcef07963f769.1755153054.git.leon%40kernel.org.
