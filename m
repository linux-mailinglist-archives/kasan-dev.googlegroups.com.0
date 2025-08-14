Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB66F7DCAMGQEJWID5DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 0200DB26E1B
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:55:18 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-74382041788sf407959a34.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:55:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755194108; cv=pass;
        d=google.com; s=arc-20240605;
        b=OzFItJWzRmpLxHz5UN0KqXqU1EmheRKBwKz4hgLYnvi6Kr4o1CZ53kvjSckYgBuy82
         lf+HAap5YwI2N/mXjNaKEchmVEJQZgzgtdzZUgGu1dCfjovVTbk/G1BGaptgBmI54wRE
         wzchoZKbSMkq4l7kvewnpd/IAA3Z0P+apyHzObger2npFYecMt5B2caglJndA0VnYULp
         BVtOWnBcRA+1UXa9ezCH02htALF0bTsPKmYUMsOOdJDhzC6FTVBdE21R+9Zkh54JurSO
         +n3I+QbOyvU1yOXNB8Tu64HOcOvkTlAeo6d0kh9tYJsgxdNyhXY7w3taUnsO+za04zxd
         A9LA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=jfeUXrninxQ3sxHhUuQfrorivrAQp7pjBC8SyXnLJzQ=;
        fh=EOmAQ1QjX2emyq7pQfMfZYpAcRukQIae7RnQhdopc8U=;
        b=JyQ2+U1VQRVdB5eEvbYkmdpuOsxpmKtHoBmVvsCnwYa6UDQkUl0+E7EZZspvSu0WKd
         eK7fmDWO0gYe+99Q+1o2XAyNFaozbIgqc8k6l7KoUOQHi65J2ICsc0vJEjXy3jtGXS9J
         vLDT0evqAUr1m+y1Vtd/5bWjGsGHC2DExfFB3EDnUZrS9tufYXjoP8n48G5snFEMhGUA
         qw2edcuCE8BfhLU7sGESHGjutNpMG4yz4vsdv6vekXVGP9ywPiqLA/LTc6GewJCsor2j
         GaEiOAqEkSih2TTpS8++a4acFN499+IQfMOC2ZWpq1T11oaAOql1LFIQElhK6fTGi/pz
         lUpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MsbLK5kT;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755194108; x=1755798908; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=jfeUXrninxQ3sxHhUuQfrorivrAQp7pjBC8SyXnLJzQ=;
        b=YOogrW7mFnhZFXiyCBf4ZcoW8nYxgiQAhzM28qSjmHkHIniipIWbPcV9xpy1Ljobiv
         PgM9d864lc2FRvEG9RyZEQb6CXwQaK0aC1CJWzHafx70CvKlKFApDrkisNNcHWnCLEuu
         OEztsJq5YurZDh900I7X10wffNZr5s1pz0q0pXlcuNNZGCPrTmJm9zhmZ4/BTN/ifNOH
         szG5PeOUKS6s8ISaTQKlW3cIzIdip/vPeUhPfPOzr9/CKgs+Q/XqS5NxnzGS0AhN9ulU
         aG5DFmdqtDtxdxRv/ULd6pmy9f4hVXv1qGBs55DWq/3E6xhR2p/p2WOPqAD1VxbvK7IL
         pr9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755194108; x=1755798908;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jfeUXrninxQ3sxHhUuQfrorivrAQp7pjBC8SyXnLJzQ=;
        b=P0V9eZoWevDU24fnu+A1AxJuvFrpTSAM7LllKc8HEme7Ppl583Q0XAspuWdSv5RBiA
         8zTZfnUOH8d1T4Z7z5BIdNwi8gbiTfgVvevfGBvGC1LdmE9ktrUIPakOe1qPQI6wWKTM
         zniFWmpAPobqxsM18r+zHnxflfT/xNfnCpd3cSAcuF3j5dgpyJjhHIaqRHpmv+hfzwB1
         y7wFv6KahRD8qCOtFcijPrj8/y/DlO5nLd0cpN/33zIwk0WisZBjzJ1HXumT8auwYsrF
         7lEZ1khi7fhuLc4ON9MI5/Gr94rBj4vljkBV85ly0Cps19rh31Je0w0j/br2E92n7MRy
         tmbw==
X-Forwarded-Encrypted: i=2; AJvYcCUFPBUKbPrC0aHoOiwfR2wygArse2ylLJ1/XEBRZo8eXbIr7rlMfAdhQsKlW/ArSgKxOmpUZA==@lfdr.de
X-Gm-Message-State: AOJu0YwBAvGmuiTtHI10X+Ke/M/emz1ZiAnb3+C/rvH39Qhs1m239n4G
	HJnKStrt8qUZW9hcYeXTiZ4hrIadx6GSu6qU6Dok0cAXtt88r2tzfMA4
X-Google-Smtp-Source: AGHT+IGWWBzRnDys1uQd+AbOxuWQ79ctm2SrfWWSszHLwotn3p06XBxThXgoRConb/X/Vzv/1ze9jA==
X-Received: by 2002:a05:6830:3202:b0:741:7902:8b41 with SMTP id 46e09a7af769-74382bf31bamr1749174a34.22.1755194108055;
        Thu, 14 Aug 2025 10:55:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcT3V84D/BSTWzG5gdhCwms6P79efG/3Ieymv2Zs/4duw==
Received: by 2002:a05:6820:a01:b0:611:9e19:22fd with SMTP id
 006d021491bc7-61bd49afdd1ls242472eaf.2.-pod-prod-06-us; Thu, 14 Aug 2025
 10:55:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWOvIKrnrWpwmETSw8Qa+363M6MB2MFvrrBTJq+VOyyPbC7YRd7slGPh2CDfivmvoAYstFmO32qKa8=@googlegroups.com
X-Received: by 2002:a05:6830:3482:b0:727:345d:3b83 with SMTP id 46e09a7af769-74382c0108dmr2574239a34.23.1755194107119;
        Thu, 14 Aug 2025 10:55:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755194107; cv=none;
        d=google.com; s=arc-20240605;
        b=NfDPC8DiRyeIcDsGJKhVh6aK7z7kscRKQhjIzD0PrlRRLFCGUOv88IlvN37pPEovL+
         np0zc5Pl5hsFNrH/qw6GJvnEBSKtQyoPLF0+nH/I+VIREB1gbhVO2lC6DP+Qx/zupz09
         JjGMIk5sJE3QqoFB5J2PVKWZOWNriIofqtqugU2B9LjNasrU9ZUu8U/rditZS+CsvZ9K
         CJI5zVYpNzHs74iWU5pizRrZwOpjsrO5gaAQA0cdl4OXh7DQLcbc3w7DtX22HMc6C/Ev
         5jaKIG2xQbegcn4+8RW4mfVcPzGinG6Ie+GuKRyi0+j8QKwYSW1r7JWLcXSZmJh3cIiU
         IFqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XPxNQF8Cx+yhCu6yL4faxmro9U88DCzv8Ndb1qLzzQ0=;
        fh=7V/4mfmIBPVtH5Gsq5s7pcGHGm3ouCqKnRMFyJrAs8U=;
        b=Rzyrp6MwOrGFIt6xRiBvGx9//QeyabFyGwoWYu1yPv7qNSvd3ErGn1b5kE53w/3IFc
         m8qjZtxFLSJ1ADsbP7J6haJKB+Nf64C6wdJCUvJdcob7SkWUpSnH+FyrPYXve6cRCUx3
         nZLYVjtEq2RO60CKwiTsJ8EfAK6IwyRFE02UhV5MiBj87JSF1BB8Dc4t+hM6je6lro47
         jbRNWmHFZLh1MSkvaSWkRtE971Y1ZZq2nJi4NAKaFN8i205lorQD6abEygWfHWV+JYZa
         /Uf2fgypBs1TVHZDrPr+7YCj+PWA0I7k3ZAtWIK0vVnSE7vf1yWImmV1Y7YbyLNW7EgX
         wgtA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MsbLK5kT;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-61b7c9a44e7si149058eaf.2.2025.08.14.10.55.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:55:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id CB8B25C720C;
	Thu, 14 Aug 2025 17:55:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B3833C4CEED;
	Thu, 14 Aug 2025 17:55:05 +0000 (UTC)
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
Subject: [PATCH v3 14/16] block-dma: migrate to dma_map_phys instead of map_page
Date: Thu, 14 Aug 2025 20:54:05 +0300
Message-ID: <d05ac5a700b008577a5740c99fc1ccd24c8e1359.1755193625.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755193625.git.leon@kernel.org>
References: <cover.1755193625.git.leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MsbLK5kT;       spf=pass
 (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d05ac5a700b008577a5740c99fc1ccd24c8e1359.1755193625.git.leon%40kernel.org.
