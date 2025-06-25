Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBVXO57BAMGQE5I6IKDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id D8BF5AE843C
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 15:19:22 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-b34abbcdcf3sf951196a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 06:19:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750857558; cv=pass;
        d=google.com; s=arc-20240605;
        b=AASg6+8p6HthJ+3CRFqswt8tmPuVDnd0AZ/R+LbhhV5Ko+zy5q3oHigKtFkfKzpd9+
         akdNR9Hu3Yj9qmKGbQYxFOluS/c8OQEI1zMTrcJmmTXCvwJXrHfNd+qBi2ZkuaWMwcF0
         vNMke1WeM1x5FAGT8eycdNyLCt0dmj8N2i0xBcgXMJk8YwgUfbQt0U/K+ahu4ilKyFnl
         IuvPhUiWBdPzPp2JjN/cOg774hchgE0guQ2SDfR4c/J5RP1rC3n7W2qX7qvZU2Bh67BD
         UAwCpUaSy5fGhTBDEF+u9pzKnaY8iPz2GcNr7GoBJpFNXLZ5I+ZAxZ/b9cLN4PncTvVF
         zmeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=K2BPy9fvNheWLPkbDQ91LVevX7Y8NaNB0ktrsh6l7f8=;
        fh=RiFLMnQg0ZTF7xeJJAre6QUgDx6t6pUy6dvuNoTE40M=;
        b=gzRxM9xE8JeaF9oA95ImilvZRUzzSqioOHer6wZSdEKbOpM34fvOpfCP+qbiPKbhBt
         LLfNqSO53HaZynlXBdafwOypoP5+/umAAi1qRQvDpGQLxJOz8TcVr5FRPQ42cA54u+Mw
         ZchjO3K8mqt6/RfprNkPcy+1u5khdSxV8AfJyIn9Py//q9tZqELwn6UVS5KgDoKhy5LP
         /h5I6DJrVTZnwXxcUL7Y2qvZv9HAsnJQHliQUyy0kkg2jDLUSnySrmFz7GEuo43aGwpl
         MQDZbpSv9/5HelPx7daR8OSlK7HlQrZYkG5Xba3Y5Dis1WeHkOKZ4tApy/aJPlbFCTBa
         O+oQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=l10zw3Wd;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750857558; x=1751462358; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=K2BPy9fvNheWLPkbDQ91LVevX7Y8NaNB0ktrsh6l7f8=;
        b=YnNkGowoe23MyUw3OLQBroXt1DQ43I8tm3c1BPjJ/U844irJvw9d+THUSpoYFiUAgY
         LFgbmKUEM3NIutKL65DKum0nqO52kPFw8l9H4ZH082f7nwChBZPAEydqbBOB72XCAKAB
         W11XDAXRkQ5Tkv1UKZg4Q+2fN9CSJRl+xsdlacq7GMv/jvOy1evMJDdc0r8Ll9DJN3q/
         5TgV2H2FCQmxYgF79Yddg/iVyECflm8VYV4iNy1rrCsKOmiGMbPwWmytKP3bJkncAIzs
         YwTHXHDzw6q5200KrnvqlXJ9XMM5iBznj2dvgRvR3qPHYKJ/AauCCMxbtjPZelwt9n7x
         +saA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750857558; x=1751462358;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=K2BPy9fvNheWLPkbDQ91LVevX7Y8NaNB0ktrsh6l7f8=;
        b=hyDdORd4+ETfnS4LqTFUgaZsWCNFFI23nijzW5kS76GHsJusyX/bdf+PaMAREcxW5q
         itPqRc3oK6bwO+HDHDhrk0squLt86OAtyuWffe7rxFIqf1Rpl5hbR/3zkgJVVLKXSoCw
         l1SeWMF7vSW5PWY0AmAdC3dfXCGNKWxRJ9LJh+2HuCJktMkVrl67rIU03EtJR9PCTNJa
         YrzO2n3vraidWszDWLhGE+R6L9KQKxNnMpjlIGmu0jXX6xbdvG4cuu3yDXHbJLAYXIRZ
         i1XaRQgpVktOCmfilk8c2b1xTlfa4JmteMl9cmxl2OwQskuaL3FW8m+bwFkW4p9dIdl8
         09AQ==
X-Forwarded-Encrypted: i=2; AJvYcCWkHYcjh0F6NhDofY6qkT8WrFImBdriBBdner8Lz7ALQ4r0kL1Oy/L8c8i+L2ARlxo9PjTlcw==@lfdr.de
X-Gm-Message-State: AOJu0Yw+u0ZetQsVGTGW+D5cmIrbERhSglVk6bPoFyclYCy0Vw9n6HfH
	tJmdmZLCGpxdaD9sl+RmGZkchC5AuX1Wed/IsY+K+aC37sEU+kB8p14h
X-Google-Smtp-Source: AGHT+IGndMBzuTGvOFNdtZdfxJETipevpN5i56wf5MRRLwUDdl2R0ihTL9XwgPNmfNmGg3ruCRBHLQ==
X-Received: by 2002:a17:902:c94e:b0:234:f825:b2c3 with SMTP id d9443c01a7336-238245822afmr56014835ad.17.1750857558326;
        Wed, 25 Jun 2025 06:19:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdHX2m8bwNqjBK/ERHTJWE0GFj2q8EZtNlWyIZ8inpSZw==
Received: by 2002:a17:903:40cf:b0:234:b428:baa0 with SMTP id
 d9443c01a7336-237cd3c4fe2ls53423365ad.2.-pod-prod-01-us; Wed, 25 Jun 2025
 06:19:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXvfiTthuUoltu5tH834upO52/ccRX6+aJTTEbL4kMSdDyRGa09qtdnvWeKH8s2fthXAZy9kUatkLs=@googlegroups.com
X-Received: by 2002:a17:903:15c8:b0:233:d1e6:4d12 with SMTP id d9443c01a7336-23824575e9dmr42284845ad.13.1750857556635;
        Wed, 25 Jun 2025 06:19:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750857556; cv=none;
        d=google.com; s=arc-20240605;
        b=iayLD89nxPtdG2k1UgmZaNn0yVXyurYftmaCQ5Hn5dTfTm2CBs8YkKrz016B9JD8MH
         qwZ8VDPw3369MPYeRwxgv+KbHI+RSV+ifc4/nri+2FpiWJSkc+nbANYNOAPq6BpVSInS
         5wVdcX3z7rMFGJf99bzCxGL/XAnxRPU6b7+nkzX46fsSmirq4dkdaXr4Nw0qd30/t23M
         5j0YRP2k1i8BFI9vwan1Wtx/Qi2287NxsPkFVaf1j6g46hyJ7jX+0fq10TTv9yTOwge6
         huHe0ECg2StZrpdTGbOYn2cLgtYFnupkcUHFxGQwp0TDR6WaTAbg5CBRhojRQZxKlWXq
         AR7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=CP2stCY7T0xSEqK1gjrxM6I4ViVfNBXb5kLK+aDHiy4=;
        fh=2YwhH7Yqke+JtVc+ekpbE7Kc843L6a/jLCo+pjWIHyg=;
        b=gldRSQe6ZqYlce+JkwDiv6f/rzkzzomLd9bdRgDXJbOo6Y4Iq0iMX80PpRVxdJbJZh
         woDN3yBJlh0jzy8IzlhTDPceyresmk2rXwSpdvI+4OFwmFsCRVMZIvHoAXNpqSybNNAG
         EHdIdcVidR8ADAShdN1AIeF1b8rCZzs5W12W5go7XvxyGzJmYdRobHO8taqoB7DtR+OD
         PVh4DDX/HqwbIe39ztfv+4cHa65QAWk6qivtVbdAbd8t+h9NlUZ3CWtiR20F74W3IUp/
         ZB+TO4/eenTOSC6j94+gpbDnDC8SVMzo8PKAsvXyi8bA3XsVqwYDxgTeczniJ1YXCIao
         IYrw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=l10zw3Wd;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b31f11e186bsi719432a12.4.2025.06.25.06.19.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 06:19:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id A1C12A5260A;
	Wed, 25 Jun 2025 13:19:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 82CB0C4CEEF;
	Wed, 25 Jun 2025 13:19:13 +0000 (UTC)
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Christoph Hellwig <hch@lst.de>,
	Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Robin Murphy <robin.murphy@arm.com>,
	Joerg Roedel <joro@8bytes.org>,
	Will Deacon <will@kernel.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	=?UTF-8?q?Eugenio=20P=C3=A9rez?= <eperezma@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?UTF-8?q?J=C3=A9r=C3=B4me=20Glisse?= <jglisse@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	iommu@lists.linux.dev,
	virtualization@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: [PATCH 0/8] dma-mapping: migrate to physical address-based API
Date: Wed, 25 Jun 2025 16:18:57 +0300
Message-ID: <cover.1750854543.git.leon@kernel.org>
X-Mailer: git-send-email 2.49.0
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=l10zw3Wd;       spf=pass
 (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted
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

This series refactors the DMA mapping to use physical addresses
as the primary interface instead of page+offset parameters. This
change aligns the DMA API with the underlying hardware reality where
DMA operations work with physical addresses, not page structures.

The series consists of 8 patches that progressively convert the DMA
mapping infrastructure from page-based to physical address-based APIs:

The series maintains backward compatibility by keeping the old
page-based API as wrapper functions around the new physical
address-based implementations.

Thanks

Leon Romanovsky (8):
  dma-debug: refactor to use physical addresses for page mapping
  dma-mapping: rename trace_dma_*map_page to trace_dma_*map_phys
  iommu/dma: rename iommu_dma_*map_page to iommu_dma_*map_phys
  dma-mapping: convert dma_direct_*map_page to be phys_addr_t based
  kmsan: convert kmsan_handle_dma to use physical addresses
  dma-mapping: fail early if physical address is mapped through platform
    callback
  dma-mapping: export new dma_*map_phys() interface
  mm/hmm: migrate to physical address-based DMA mapping API

 Documentation/core-api/dma-api.rst |  4 +-
 arch/powerpc/kernel/dma-iommu.c    |  4 +-
 drivers/iommu/dma-iommu.c          | 14 +++----
 drivers/virtio/virtio_ring.c       |  4 +-
 include/linux/dma-map-ops.h        |  8 ++--
 include/linux/dma-mapping.h        | 13 ++++++
 include/linux/iommu-dma.h          |  7 ++--
 include/linux/kmsan.h              | 12 +++---
 include/trace/events/dma.h         |  4 +-
 kernel/dma/debug.c                 | 28 ++++++++-----
 kernel/dma/debug.h                 | 16 ++++---
 kernel/dma/direct.c                |  6 +--
 kernel/dma/direct.h                | 13 +++---
 kernel/dma/mapping.c               | 67 +++++++++++++++++++++---------
 kernel/dma/ops_helpers.c           |  6 +--
 mm/hmm.c                           |  8 ++--
 mm/kmsan/hooks.c                   | 36 ++++++++++++----
 tools/virtio/linux/kmsan.h         |  2 +-
 18 files changed, 159 insertions(+), 93 deletions(-)

-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1750854543.git.leon%40kernel.org.
