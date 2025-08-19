Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBBPNSLCQMGQEAHMFM2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6037DB2CADC
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 19:38:15 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-30cce87c38dsf2542607fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 10:38:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755625094; cv=pass;
        d=google.com; s=arc-20240605;
        b=iblNxjNkH+PP9I5G/+uVPDBakvzyglaMYr6U+oI5V1IDZsx/4kolZdO0nre8/KN0uV
         DfVXaSxmsYjjyGRQDee9e9CvwiVyaB9D2fUmyfW9H+CdxFUs7xd7n/TEyfGN+fAAgbfQ
         +IbVorqpTBD6Qn5XLpqo2LNi5hncmOhkVz/rIMhRttnQ4FqKskCX583bNipA4KISAH2+
         V8zKqbvKmOoALhdNfm5CJ0yESCy+jSXweRAocolak8lZPmljY9wG3Zbfn01LazzktI1v
         YGUH8exe8oELV85OzclzSWftlP7vA9TyfRF7efwM4BRaRYyLQxRmxkdcd1xpXwbWAXdZ
         8Jug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=8AQHSqTNW/lIy0PM14jcu4mYCcPtouR+UWNq/cS9A7A=;
        fh=i4z7Xnam/CBUzLcgVqgDZVKCTo7nGodEJTm3XnHN7nY=;
        b=V8ovX3f3QfyQlFm0NoLRF0tuVcjN+rvjy2EYr+hizfq3ZXbqIUv5X9XVL9NhAU98Ly
         ddhw/XA1cQgXf3zmXIADpRgzKTnk0jCzGDLE7Gz7LKR7M/UDj/i0YQRYN4L7F3zi9jad
         9R9HV+TpikwpVbY7Pn09r7QvEIz3SZ63iTr9r7mnPEjgfm1OvkOPDP4vk4cGxE08xNy6
         1/sebItYvn0CUPemNWcETmR1NvbkcpdTfJa9xRlucCuEx8+5VUwqE8elF9t+sqr9iUWN
         9MI3sGDmPfDsm6BBBTGyaVjZPKkFDq0kgkPCuwzfEGs6mKo61n+mTBiPFnnKC20yhOZs
         yNyA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=f0VJAtsV;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755625094; x=1756229894; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=8AQHSqTNW/lIy0PM14jcu4mYCcPtouR+UWNq/cS9A7A=;
        b=u923eMiFjtbm6VoaPHvTNCRpKzDqYM1oWNOhgCQI0MUtAs9AhIj21awlpbE7OTk5Ds
         3jqCsqDn1jRRNfw3X5JRYQO0Ed2MytdRFED0XD8Kp0Ux4VxaZgPCAcnZHNxsWX3DaKJJ
         ThNrExin/bxL7kshLfC6oru269uRAOOdSfdzUm43DK1gbX1Wn9tB98gO9+PAbm2uGtF0
         SAfqmfShpSDrua8hGu1SLRuXi1tlxesDWdLvoS5YHeNoCOorj+jbhKkYHyu6oe2fpz8y
         qed/gWk5/gKAgIOxCISr5HPJBTihFkrcIJetoOzQyN4KUrjzkqi5Hs6oZNimKu+2T7Wz
         A4Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755625094; x=1756229894;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8AQHSqTNW/lIy0PM14jcu4mYCcPtouR+UWNq/cS9A7A=;
        b=dI/2TqKMNAt68kBHeTnnafX44nWO3l1jbCHhZD25/B90inlT1Tac0WGun8xOig/iEr
         tD1smI25IUuShRiBcToeQRZW+ZHnQw89eotnFWRSwdChlKHWtozH5EVMFsq+Zi6DpzB5
         5bJnOBjuA5uhG0RN/m+P/9bVBDhdJrJY61Yv6iLp72L1ZoWnkSLH1zOnC2Y0AjdLMKdi
         NmrCGqVtbpG0SXk5UnvF+2CIkaHNM/Op/Z5vzU941y1q3cCtZYnAkk0k3BvzgupwwwMu
         UhDV+mBqEE9W12/5oHbx91L7id4jmlYa8poS4UbAfcb/3tQtMqAWACxrMIKH08K3nkBr
         NVoA==
X-Forwarded-Encrypted: i=2; AJvYcCXcQV/LGmMCQzsnXgy8f+FthHU05RZFbJMVIMQXvERcbX+S+bejSDBgiDc7NvdtUB1IunMH4w==@lfdr.de
X-Gm-Message-State: AOJu0Ywj0LBJix0FqKlR8wQMYhnee74rR2ifOXi8G9dxdAnpuOGEHuNX
	XhMDE/y58duWa9aBI0eWGFgAkokgKhAiuOEUQS7RuGioFNkJ0fAeOHKp
X-Google-Smtp-Source: AGHT+IHdD5JWAkqJgeb9v94ZTQ7pIRpBj8tV7hp1cUeNR96lU0Jr55EIVoX3PsQJ1sccGjHS4XOdNA==
X-Received: by 2002:a05:6870:cb92:b0:2c2:2f08:5e5b with SMTP id 586e51a60fabf-3110c269fe2mr2481180fac.13.1755625093983;
        Tue, 19 Aug 2025 10:38:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe+GwIWWetPGCY/nMbkIKv32ccdKUTwsRN3jFHBbCcAcA==
Received: by 2002:a05:6870:d249:b0:30b:76e3:703 with SMTP id
 586e51a60fabf-30cceb87e88ls2308329fac.2.-pod-prod-06-us; Tue, 19 Aug 2025
 10:38:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWBySlYeA61EGOE+2su/d2FNpdGPLVnJi5Zhfxe9F6sd62IZW1W+SOc6girNJyTx4B5vLMuMWMK5Sc=@googlegroups.com
X-Received: by 2002:a05:6808:6f82:b0:430:6126:e49b with SMTP id 5614622812f47-436cdc8e59fmr2676430b6e.17.1755625092171;
        Tue, 19 Aug 2025 10:38:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755625092; cv=none;
        d=google.com; s=arc-20240605;
        b=JXbRtm7o0TIo3V8cGyLsHnud8+rytoknIMqIr97hThNETaCgh97z/ps746JcdWeRJp
         aSiCCpG+Ze0EkFTASdhuoOcHZksEsp0/Fl9GT6zXVyfEQg+clAEBNZ0faBcQ9RI4dUnZ
         kvkDuAS8MV72sD5sQ9jVUpM7h6Qu1fB3wrGEbtINLW+t7SpxbuXyVswIoaa8EvRjeBsx
         d4uVRDjXzq2tQgYaQjCnFkOI/prhD0L5fxSlqpfSWhNzqW66r3iHe/aM0kFanyp8FOw+
         pe++3Ku7ozcsH1DJwHcfRt6DOyFYBL0JAgUQyzCsFScVD1VrOad5y/5iocuw0fVl+WYz
         X7dA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eUWODOYu7xl20YNi/5H7WavDXD5EiHAIElpuMjzztLk=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=cjHOogI0PBMIrX2FakkAtcu/lBemFWmba8dnvgkd1NCoP1u91vw+ibvSRFmAgxZu0f
         J3YiRoIP8HRnW0SLGqyJ/E9RX3nK1imNYfTZRYamaVt2UsDIQ1VdVaxEl+d+gMfHaTcf
         Y4XDm8J1P9mTCt23LIqszwChOey6fRBp7Ka1JR+JbeXNcc3Y4frLZpzWc/SzCpAsFlMW
         6VdKNKx7rmHVdhht1AdSF/9S9zV5nNJFudckN/W+gImFn2q7NezqvgRq+/OsVEqlcfKW
         mzBWQJhIirv/ZzfY35X63MdulC1k9z/1DZVB4PwEMnGGHgxfKQw93tiUf//TQF8T1TYI
         9/6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=f0VJAtsV;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-435ed00e54asi336607b6e.0.2025.08.19.10.38.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 10:38:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 7FC7261429;
	Tue, 19 Aug 2025 17:38:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E0661C4CEF4;
	Tue, 19 Aug 2025 17:38:09 +0000 (UTC)
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
Subject: [PATCH v4 09/16] dma-mapping: handle MMIO flow in dma_map|unmap_page
Date: Tue, 19 Aug 2025 20:36:53 +0300
Message-ID: <ba5b6525bb8d49ca356a299aa63b0a495d3c74ca.1755624249.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755624249.git.leon@kernel.org>
References: <cover.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=f0VJAtsV;       spf=pass
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

Extend base DMA page API to handle MMIO flow and follow
existing dma_map_resource() implementation to rely on dma_map_direct()
only to take DMA direct path.

Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 kernel/dma/mapping.c | 26 +++++++++++++++++++++-----
 1 file changed, 21 insertions(+), 5 deletions(-)

diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
index 891e1fc3e582..fdabfdaeff1d 100644
--- a/kernel/dma/mapping.c
+++ b/kernel/dma/mapping.c
@@ -158,6 +158,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 {
 	const struct dma_map_ops *ops = get_dma_ops(dev);
 	phys_addr_t phys = page_to_phys(page) + offset;
+	bool is_mmio = attrs & DMA_ATTR_MMIO;
 	dma_addr_t addr;
 
 	BUG_ON(!valid_dma_direction(dir));
@@ -166,14 +167,25 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
 		return DMA_MAPPING_ERROR;
 
 	if (dma_map_direct(dev, ops) ||
-	    arch_dma_map_phys_direct(dev, phys + size))
+	    (!is_mmio && arch_dma_map_phys_direct(dev, phys + size)))
 		addr = dma_direct_map_phys(dev, phys, size, dir, attrs);
 	else if (use_dma_iommu(dev))
 		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
-	else
+	else if (is_mmio) {
+		if (!ops->map_resource)
+			return DMA_MAPPING_ERROR;
+
+		addr = ops->map_resource(dev, phys, size, dir, attrs);
+	} else {
+		/*
+		 * The dma_ops API contract for ops->map_page() requires
+		 * kmappable memory, while ops->map_resource() does not.
+		 */
 		addr = ops->map_page(dev, page, offset, size, dir, attrs);
+	}
 
-	kmsan_handle_dma(phys, size, dir);
+	if (!is_mmio)
+		kmsan_handle_dma(phys, size, dir);
 	trace_dma_map_phys(dev, phys, addr, size, dir, attrs);
 	debug_dma_map_phys(dev, phys, size, dir, addr, attrs);
 
@@ -185,14 +197,18 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
 		enum dma_data_direction dir, unsigned long attrs)
 {
 	const struct dma_map_ops *ops = get_dma_ops(dev);
+	bool is_mmio = attrs & DMA_ATTR_MMIO;
 
 	BUG_ON(!valid_dma_direction(dir));
 	if (dma_map_direct(dev, ops) ||
-	    arch_dma_unmap_phys_direct(dev, addr + size))
+	    (!is_mmio && arch_dma_unmap_phys_direct(dev, addr + size)))
 		dma_direct_unmap_phys(dev, addr, size, dir, attrs);
 	else if (use_dma_iommu(dev))
 		iommu_dma_unmap_phys(dev, addr, size, dir, attrs);
-	else
+	else if (is_mmio) {
+		if (ops->unmap_resource)
+			ops->unmap_resource(dev, addr, size, dir, attrs);
+	} else
 		ops->unmap_page(dev, addr, size, dir, attrs);
 	trace_dma_unmap_phys(dev, addr, size, dir, attrs);
 	debug_dma_unmap_phys(dev, addr, size, dir);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ba5b6525bb8d49ca356a299aa63b0a495d3c74ca.1755624249.git.leon%40kernel.org.
