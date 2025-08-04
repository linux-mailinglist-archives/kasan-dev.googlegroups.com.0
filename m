Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBY6VYLCAMGQEJOO5MPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id E1CE1B1A19A
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 14:43:16 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-70732006280sf59622236d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 05:43:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754311395; cv=pass;
        d=google.com; s=arc-20240605;
        b=JVaBVQn+VSGYpExaOF2bCYU2mNZgdPPol0xkI4AKnW/6kmZRKgqI6AuQTO+9Cu3d+z
         u3a1R2fcqg61bnkw09oUBoZuU6TfNBxL7UHjjqTAc+zWcUSeQBWvRZ4rMF1fw6G4PLPy
         b16dKZnzGLU2zrmcLNbJh4K3HBWTI1L29ySCBd346E/ZH4sujzyqzAyM+oILZBIQyXRP
         hgjNtPpa9mkmlIRqEvl5Uz8u9n2scOy0VvpiYaK5aS+8T4HHQDeipWwomSW4yHRJ8f5T
         54qdN2/G1CLevuMkz6yj5NSkbdlC3Pbzzb4ooyX7h6l7TMJtXn7Wy5bj9NMKn+PoMkm3
         AG5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=KaDQjB6IDNxAG5aycoE0R4hOHcaUpR5snwuk1OUQU4U=;
        fh=6bfHA6m7wMgNKZzGx6f2glaA5hMcLVLIRATO3cwsvm8=;
        b=KdBLUoe+AItf5cNfOEyuiPs5w9tWJKuKjuNlMjTWI3iPlE794SAa0nL6lh4pEW4emE
         baP3UJyxZYwCAiIpAeGYXd5TaGvYcmn+09jvTPtMa2qiTiie+/v4jcdyxyhMDnjWdiL3
         mWvwT550nSiAnYbV0p/ZoouIVUwUX94aQBWZwNlnENGorSqJbg7rhte09jKRAUmzuBD/
         lcNNwrRnGAtygtDVieUy71zHxC7wG4HRQT4+6G3qwbFzmZ1+OwvAiymkpjCCvPmrHv5d
         +Y/M8PRCukoUl/+aGojwQKODiLjLgrkCvoYl2604rJtuDwhP1iWjudXXpoHhV9J/zC1m
         FA/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ea6NngjA;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754311395; x=1754916195; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KaDQjB6IDNxAG5aycoE0R4hOHcaUpR5snwuk1OUQU4U=;
        b=jnAQlmYsOaNpygWooetDvj4IibFoXqc5r6j34hRJ5EfizFy0dwjih+Sv6/Z4w2mwa/
         XDlvQ2xBQKNRX6l+V+OBpeV19r5vQKurOb+iBNIfLT1jirMxr1KpEe4iiO6x7LEaZq2v
         /EL7RIYbjxfjqrQxKzlI9u+OuUXgeEov6lELltPSDUFR+LYjm+IACfcNSj0ziatMNDw4
         YxNiEwnrQKqnspR5TSs9yMkL5pI1kBglquRn7tHTf04ge0orA76/ug6GIsujtt56c7OC
         MT+tQfVVnK8oGRgxi2mAlna3ddtLEBPx9mq0C2bNotC0Yu3qutrF4Txa4P+zrSMuVR04
         UqAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754311395; x=1754916195;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KaDQjB6IDNxAG5aycoE0R4hOHcaUpR5snwuk1OUQU4U=;
        b=Ul3Q+DlpQer212hBkg1DvDVbpOvN4imHW8K9g4rm03FmW4ukph4OM6u9EXMrsPJjPf
         Drfst8khvYxRLRFSDVb0XufVgnv5coJhCg6fQWWpvkEmdwxRlRRfxfSo/FUc18diPQF1
         HRfaED1g4g22ajJ8tM0Gg4bhRfKmAhB8WeFiximmn9rCc1xD5fIeAh551VzOL6+9Iba6
         ZF1c7pP/r03Mo7dEOeLiTKhm7Dd5fVhU51mYO2zy5RXJzFooKYDh0zMOocqviDD92RT8
         XtD5aB/xUg3zMM0Ue2vsjcGM2g6cXH1qMYg6ebnAcy4bGVGVYou+iK5Tou3KA6lyaAPS
         ZIEA==
X-Forwarded-Encrypted: i=2; AJvYcCUqXaZtAgVbqeH95jirCqtLqn3fJXo/BqkicZtAKaEx1P6YfUFcmJKpKck/KiGKm3B5mg8Twg==@lfdr.de
X-Gm-Message-State: AOJu0Yy9v9Iv/aZghO+9tSL4LBBjYFv4irwyJZbNAcNeCDsh78TGfgZR
	fqdmUI/REbKUP0/XeBidUCtOjJpBoYpiPCJ9gafjXOTDvxLDlYF3Kbi5
X-Google-Smtp-Source: AGHT+IGWJevdYRpix3JV4CEMXD9WGi6Lhr6xqXFE+JQACgjx5mHBiewihBtU4MgCOqffy7uN8LQ5tg==
X-Received: by 2002:a05:6214:dab:b0:705:816:6179 with SMTP id 6a1803df08f44-709362d810cmr130648476d6.38.1754311395409;
        Mon, 04 Aug 2025 05:43:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcti9NZxkDXLcrA5Ahip+rqh0imNfXf99Mr9nDshE0WFA==
Received: by 2002:a05:6214:2126:b0:6fa:c0b0:1fa7 with SMTP id
 6a1803df08f44-70778b0526fls85077586d6.1.-pod-prod-07-us; Mon, 04 Aug 2025
 05:43:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWcaUHJgsd0PUd8d5sg7a7AsmSle8vOWs6o9nxXX08xPgQgkzRc1IRmxFfoEjSHgFHcc2uiSoWqwiE=@googlegroups.com
X-Received: by 2002:a05:6214:494:b0:709:2483:bbfe with SMTP id 6a1803df08f44-70936232acbmr122853066d6.29.1754311394294;
        Mon, 04 Aug 2025 05:43:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754311394; cv=none;
        d=google.com; s=arc-20240605;
        b=cgGTv95G9hfW7pI5Iq1d9UHZlEHR7e6nlThclRvNdiuT8d95omNK5OtxRuI8aZ8wsv
         aKmx8W94vq7MSJHoq4vwlSWIweadBI6oSsJJqeTJ4Y1G8R7B7WyCwrd2bNWD6lQ6dUyr
         oc21BGBgR3NbYLK6SFlEAU2RqU/RcFDlro5v74hiIqEpkAOvIZsmY1dypXdvW1oCUykj
         +m7jPDQa05HBhlyCamTNtLdtQVzGzz/w5VjaubkC7JKuo6opNv8yDMW7WUZP1ZgiG5f6
         bH736WUzD1Wvq4dOGvsCusuVrRvA1jBurKurhsephn2CDKS+AO8Y/5+6/AQNJQ8r57Bl
         /c0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=9mBSq747xnxKM4OSX34hdNxsM5vfVfa6L4EsHB97MsM=;
        fh=iu7vSg1EzzlrRbrwbQPzfF0RoV1Uw6GXAom/pnqIJaQ=;
        b=dfZmyzvwIG7J3ewNDVXxTSFq5UyyHxPEms2zmKy4Dd29eaRXuLZQTNwyYU9aJBDfI7
         Rivmg6WD3vf9GOjMa+povLij69FHGO/coZQ2fFBPi7omz2rsWid+ZKeE3TdVqmZC1hkp
         XtRArOVLFHWeKNB87vhuPWLcFpnrEfj907BhiU9VHclXWDWKLZETDy5qfhmsHSagy54E
         d/VW+i8WZGBkbkaxTscz8wZbArB8n+1e4s+gV/qT32gEC8yq0sRSmuUHjaWZsXGQRE4s
         h3sc1UHS/yiFZcitL55/KmmnLrCzXVxJREHP5BkG04ejWOuoJYJ7LIL4ZxXp5eF9349I
         aprA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ea6NngjA;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7077c636180si3194496d6.1.2025.08.04.05.43.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 05:43:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 030FAA55811;
	Mon,  4 Aug 2025 12:43:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 73ED3C4CEE7;
	Mon,  4 Aug 2025 12:43:12 +0000 (UTC)
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Jason Gunthorpe <jgg@nvidia.com>,
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
Subject: [PATCH v1 00/16] dma-mapping: migrate to physical address-based API
Date: Mon,  4 Aug 2025 15:42:34 +0300
Message-ID: <cover.1754292567.git.leon@kernel.org>
X-Mailer: git-send-email 2.50.1
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Ea6NngjA;       spf=pass
 (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as
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

Changelog:
v1:
 * Added new DMA_ATTR_MMIO attribute to indicate
   PCI_P2PDMA_MAP_THRU_HOST_BRIDGE path.
 * Rewrote dma_map_* functions to use thus new attribute
v0: https://lore.kernel.org/all/cover.1750854543.git.leon@kernel.org/
------------------------------------------------------------------------

This series refactors the DMA mapping to use physical addresses
as the primary interface instead of page+offset parameters. This
change aligns the DMA API with the underlying hardware reality where
DMA operations work with physical addresses, not page structures.

The series maintains export symbol backward compatibility by keeping
the old page-based API as wrapper functions around the new physical
address-based implementations.

Thanks

Leon Romanovsky (16):
  dma-mapping: introduce new DMA attribute to indicate MMIO memory
  iommu/dma: handle MMIO path in dma_iova_link
  dma-debug: refactor to use physical addresses for page mapping
  dma-mapping: rename trace_dma_*map_page to trace_dma_*map_phys
  iommu/dma: rename iommu_dma_*map_page to iommu_dma_*map_phys
  iommu/dma: extend iommu_dma_*map_phys API to handle MMIO memory
  dma-mapping: convert dma_direct_*map_page to be phys_addr_t based
  kmsan: convert kmsan_handle_dma to use physical addresses
  dma-mapping: handle MMIO flow in dma_map|unmap_page
  xen: swiotlb: Open code map_resource callback
  dma-mapping: export new dma_*map_phys() interface
  mm/hmm: migrate to physical address-based DMA mapping API
  mm/hmm: properly take MMIO path
  block-dma: migrate to dma_map_phys instead of map_page
  block-dma: properly take MMIO path
  nvme-pci: unmap MMIO pages with appropriate interface

 Documentation/core-api/dma-api.rst        |   4 +-
 Documentation/core-api/dma-attributes.rst |   7 ++
 arch/powerpc/kernel/dma-iommu.c           |   4 +-
 block/blk-mq-dma.c                        |  15 ++-
 drivers/iommu/dma-iommu.c                 |  69 +++++++------
 drivers/nvme/host/pci.c                   |  18 +++-
 drivers/virtio/virtio_ring.c              |   4 +-
 drivers/xen/swiotlb-xen.c                 |  21 +++-
 include/linux/blk-mq-dma.h                |   6 +-
 include/linux/blk_types.h                 |   2 +
 include/linux/dma-direct.h                |   2 -
 include/linux/dma-map-ops.h               |   8 +-
 include/linux/dma-mapping.h               |  27 +++++
 include/linux/iommu-dma.h                 |  11 +--
 include/linux/kmsan.h                     |  12 ++-
 include/trace/events/dma.h                |   9 +-
 kernel/dma/debug.c                        |  71 ++++---------
 kernel/dma/debug.h                        |  37 ++-----
 kernel/dma/direct.c                       |  22 +----
 kernel/dma/direct.h                       |  50 ++++++----
 kernel/dma/mapping.c                      | 115 +++++++++++++---------
 kernel/dma/ops_helpers.c                  |   6 +-
 mm/hmm.c                                  |  19 ++--
 mm/kmsan/hooks.c                          |  36 +++++--
 rust/kernel/dma.rs                        |   3 +
 tools/virtio/linux/kmsan.h                |   2 +-
 26 files changed, 320 insertions(+), 260 deletions(-)

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1754292567.git.leon%40kernel.org.
