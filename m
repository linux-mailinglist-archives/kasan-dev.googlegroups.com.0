Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBFU4XPDAMGQE66WQNCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A8B4B8CC3F
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Sep 2025 17:54:00 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-e94dfb23622sf4555088276.3
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Sep 2025 08:54:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758383639; cv=pass;
        d=google.com; s=arc-20240605;
        b=e80QlXKJzLhOmc3UqVh0/xMcMiepwgbQkrUOZhgANwGCCcl5c1fEwEsLejGXp2KpxA
         /5tLSswOnHNs67NBW8L3pqJmvtXuXEuyv+XNQTVIEgTH3RE+mWHUuiygV7a2PHvxSAlU
         dqRQ5GcKf2BJ5SjWfETIQZH+lt1SAl96ffdxZAELf3ItElqWzU1aduXw587aMy4j9UmU
         NnvT6ASU4TFjj4pdV6tVkDqBlFUpba5z2gs9Hd/ZFnyJPVLSFi2RKfCLiDhkvqcwp62i
         bmN5bYOEpI0PA96ETsLiFN2zeyUR1rK2t8C/qRwaqUb3D9O8fNs4csztxS96k/tRWlIx
         XSLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=dNxRIa0MeA5LvvQkTfPjEqbnHOcRkhcKyO/cdMc8MKA=;
        fh=5/DiP3/zFYxatfUZOxJLjE4z/4NGHCf9W12zc0uAlYU=;
        b=d/L9POGzScMlx9mTk73tckhncuefOorxpMPKMjYDmYmZXz44bWS1trCG2a1APT97ha
         qnCGYfoUY23erLnlqALe8p7/NR6+osnn87fzMEzBo52YLxVdIqPS4NzVXQDkLWCkYQnY
         CEQZDPv+cuXkLdJTjj+l1o+asNx+T7pr+sj6GsThfqOWaS0o/iCCJ6lqJFvFuBTv+5lA
         JoT0CxbJrcfIbEOzK5e9JkGmUyiplMrAUExOqaZCdXATP1rHpQM7bQE7Kvfj+ii5uQHs
         sL9SfPEo6Yzl0jL4D8pFxzcy4sYBHl3oYObd/vrPQQOrVDGFcRhnJkYBLFwF0M+Ztgo5
         clSw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qbW+7cTt;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758383639; x=1758988439; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=dNxRIa0MeA5LvvQkTfPjEqbnHOcRkhcKyO/cdMc8MKA=;
        b=AjL3DBC/tn2KOWTU1hgU3xi7X0H86PZnf0zeyMq0QETGF+bk7ZldW9cXXup8LISujE
         vbG26cCagyWwz1zRxvwY1GwtL4oPk00rRi+0K2l7JXWS6X6FeNH9X8IgWCtL4bIBeWIh
         K7yZmMSCLeioGdy1IIwYJJUvesnZdaZvyakZFA5V/hfjsTEtCgTGIr+JNr/a1P+fZXPb
         TWtISaZZHuZY+efMvuM3xABTpMg6mjH3S53W1nboiPu9hQ9j8YQRsHzxYas2iNMVdhIA
         4uGJn9+jZIa5C/gA8V7/uWeW5er7br/3ynBuBMWkY4aepDSGveG9QGDPz8155SWIZVrL
         moCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758383639; x=1758988439;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dNxRIa0MeA5LvvQkTfPjEqbnHOcRkhcKyO/cdMc8MKA=;
        b=qTx/UJKKMFx83FkRibk/ng5g8Ml7VLD6f0aVxCXbGP7v6dc01gGA2lvWDXFAjE15Cv
         aelLDSyN4QNlXWCcQGDT2Zo2KrgyCvrElyV6fL3BjW4+ZcvtY0FBje7NgjGqpt08fN+H
         lbwCXGUU30fFXwrhiwUWG+pa9arrZD6/U0plKu9qDdv/9zJcEHBecet/JN3spKnl8fQL
         4/339c/4a+LNwc5zU4Cfh/IOdgr5cxSKTa8DKrSsfQS1C5u4tfJXbguvcZMD6/lbEerH
         EoBfGg8MMctxvDx24pd5MunD6EvQWGK6CfY8jmdA0qBKIxKmOCh7r6gpSFmV6OV6cd8P
         ClrQ==
X-Forwarded-Encrypted: i=2; AJvYcCUUbnXXXIq4+YK2ufChEGYe59YPCCr/gSIHfd3hZ8SmXhHTYObMuFT1oFAIsbum89YMvLy4nQ==@lfdr.de
X-Gm-Message-State: AOJu0YyhttTusPbnxouZEtLSQ7z3a6AdtwOMBdwmUIqD4KKZqDZFluPR
	5AFYswNm7E7CN+n9VVmUpEqL24vkLfVtN9hQifLrXd7Zb8FU9GR/pC7F
X-Google-Smtp-Source: AGHT+IE8JaeIzT6wkiocTvGnjW0wMRNpK1ir46ypn94K3QqMTjL8onYGTpjkI5o4jzzdiUft2RGAiA==
X-Received: by 2002:a05:6902:6081:b0:e9f:bf6a:29ab with SMTP id 3f1490d57ef6-ea89cd1d48fmr7033979276.16.1758383638956;
        Sat, 20 Sep 2025 08:53:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5f1tJUWQGgz+WCbT6t0PIkoORicL8LWutXmtErXixtgg==
Received: by 2002:a25:5846:0:b0:ea4:5263:8f0b with SMTP id 3f1490d57ef6-ea5d12266dels1458926276.2.-pod-prod-04-us;
 Sat, 20 Sep 2025 08:53:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvxdLNRGyEjD0wMt/WN3cfv8UlDr/7iptL1a+T1u65dBe+aCOXhIUn4UKLkqHywTU5Qoy8TCjEb0E=@googlegroups.com
X-Received: by 2002:a05:6902:f85:b0:ea5:ceda:8e87 with SMTP id 3f1490d57ef6-ea89d99c362mr6099646276.23.1758383638039;
        Sat, 20 Sep 2025 08:53:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758383638; cv=none;
        d=google.com; s=arc-20240605;
        b=CZKH4KmgLnxTsLBfvl51kwpJ+FkAEuFdNGVjY3nYqX/a735/jIyQx2/i8GW/BlyIoh
         dQRxoAvgyTRUyXsHH3Kh8lQrIdS4WKiBVoTzSiJq8CK7PQZ2y+4gcP6OAPZNLm3Ngeq+
         sVFrN5Sx7iCb9FPlBJpnO1G5NuAApWHJ+2hwz0rePre53tDJ1e///KaR+f2YLgIZbEPl
         BdWb7g/UmkJ6B3tRgZWnYS7Kt2ai2gcmJe39vtjLee0JkjlsBBgMEON+hvvyxBypHtER
         QR+Y818iNcCGhUzV1NrBCjldh8JuqF5pVbjovToNNve2neMlIlkaXEIZi/nkbRHSVYak
         E9xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=06Hpa/1OvoT0TpifdUKNOv9vBuePkD3RG427WbWRUJY=;
        fh=55lTKMfWY7miVUmGk8ojnCN7+aXwTCfYFQdm0/5N4ZU=;
        b=X+VjxF5Jw9xlfhNa1Dp9wLjEfAD9JOb7ITlpnzBEXPWqVR8xX1GcrundGKdwvsbrJq
         EMyxEXzYV0J5/VIErIJecsDAQVGa4dEi/34jYQrlVp/e6SyOggTEn81PR3+RPipFPYUK
         KmIkq1Nanb9A9ZQKMdGMIh3YZ6/ZbqbdB/RsTMMsTBHXp+J4qa46nT2KyvAGRowSibhl
         HOuaWYT2nfKqQRNtC7RhG6dTcUFBvK4MIwD/sGu9/MWZiLfY3WntQPE/40TF6ayLOXyR
         LiDyZpSEHmfUeSDMd3NQ9DILQBqi8wiz7ysUKLS48MCckY67JJr4vUVzWdStI7FLZ++W
         KiUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qbW+7cTt;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-ea5ce7250b6si382626276.1.2025.09.20.08.53.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 20 Sep 2025 08:53:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 48CFD6014D;
	Sat, 20 Sep 2025 15:53:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 60277C4CEEB;
	Sat, 20 Sep 2025 15:53:56 +0000 (UTC)
Date: Sat, 20 Sep 2025 18:53:52 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Keith Busch <kbusch@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Jason Gunthorpe <jgg@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	David Hildenbrand <david@redhat.com>, iommu@lists.linux.dev,
	Jason Wang <jasowang@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joerg Roedel <joro@8bytes.org>, Jonathan Corbet <corbet@lwn.net>,
	Juergen Gross <jgross@suse.com>, kasan-dev@googlegroups.com,
	linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Subject: Re: [PATCH v6 00/16] dma-mapping: migrate to physical address-based
 API
Message-ID: <20250920155352.GH10800@unreal>
References: <CGME20250909132821eucas1p1051ce9e0270ddbf520e105c913fa8db6@eucas1p1.samsung.com>
 <cover.1757423202.git.leonro@nvidia.com>
 <0db9bce5-40df-4cf5-85ab-f032c67d5c71@samsung.com>
 <20250912090327.GU341237@unreal>
 <aM1_9cS_LGl4GFC5@kbusch-mbp>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aM1_9cS_LGl4GFC5@kbusch-mbp>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qbW+7cTt;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Leon Romanovsky <leon@kernel.org>
Reply-To: Leon Romanovsky <leon@kernel.org>
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

On Fri, Sep 19, 2025 at 10:08:21AM -0600, Keith Busch wrote:
> On Fri, Sep 12, 2025 at 12:03:27PM +0300, Leon Romanovsky wrote:
> > On Fri, Sep 12, 2025 at 12:25:38AM +0200, Marek Szyprowski wrote:
> > > >
> > > > This series does the core code and modern flows. A followup series
> > > > will give the same treatment to the legacy dma_ops implementation.
> > > 
> > > Applied patches 1-13 into dma-mapping-for-next branch. Let's check if it 
> > > works fine in linux-next.
> > 
> > Thanks a lot.
> 
> Just fyi, when dma debug is enabled, we're seeing this new warning
> below. I have not had a chance to look into it yet, so I'm just
> reporting the observation.

Did you apply all patches or only Marek's branch?
I don't get this warning when I run my NVMe tests on current dmabuf-vfio branch.

Thanks

> 
>  DMA-API: nvme 0006:01:00.0: cacheline tracking EEXIST, overlapping mappings aren't supported
>  WARNING: kernel/dma/debug.c:598 at add_dma_entry+0x26c/0x328, CPU#1: (udev-worker)/773
>  Modules linked in: acpi_power_meter(E) loop(E) efivarfs(E) autofs4(E)
>  CPU: 1 UID: 0 PID: 773 Comm: (udev-worker) Tainted: G            E    N  6.17.0-rc6-next-20250918-debug #6 PREEMPT(none)
>  Tainted: [E]=UNSIGNED_MODULE, [N]=TEST
>  pstate: 63400009 (nZCv daif +PAN -UAO +TCO +DIT -SSBS BTYPE=--)
>  pc : add_dma_entry+0x26c/0x328
>  lr : add_dma_entry+0x26c/0x328
>  sp : ffff80009fe0f460
>  x29: ffff80009fe0f470 x28: 0000000000000001 x27: 0000000000000001
>  x26: ffff8000835d7f38 x25: ffff8000835d7000 x24: ffff8000835d7e60
>  x23: 0000000000000000 x22: 0000000006e2cc00 x21: 0000000000000000
>  x20: ffff800082e8f218 x19: ffff0000a908ff80 x18: 00000000ffffffff
>  x17: ffff8000801972a0 x16: ffff800080197054 x15: 0000000000000000
>  x14: 0000000000000000 x13: 0000000000000004 x12: 0000000000020006
>  x11: 0000000030e4ef9f x10: ffff800083443358 x9 : ffff80008019499c
>  x8 : 00000000fffeffff x7 : ffff800083443358 x6 : 0000000000000000
>  x5 : 00000000000bfff4 x4 : 0000000000000000 x3 : ffff0000bb005ac0
>  x2 : 0000000000000000 x1 : 0000000000000000 x0 : ffff0000bb005ac0
>  Call trace:
>   add_dma_entry+0x26c/0x328 (P)
>   debug_dma_map_phys+0xc4/0xf0
>   dma_map_phys+0xe0/0x410
>   dma_map_page_attrs+0x94/0xf8
>   blk_dma_map_direct.isra.0+0x64/0xb8
>   blk_rq_dma_map_iter_next+0x6c/0xc8
>   nvme_prep_rq+0x894/0xa98
>   nvme_queue_rqs+0xb0/0x1a0
>   blk_mq_dispatch_queue_requests+0x268/0x3b8
>   blk_mq_flush_plug_list+0x90/0x188
>   __blk_flush_plug+0x104/0x170
>   blk_finish_plug+0x38/0x50
>   read_pages+0x1a4/0x3b8
>   page_cache_ra_unbounded+0x1a0/0x400
>   force_page_cache_ra+0xa8/0xd8
>   page_cache_sync_ra+0xa0/0x3f8
>   filemap_get_pages+0x104/0x950
>   filemap_read+0xf4/0x498
>   blkdev_read_iter+0x88/0x180
>   vfs_read+0x214/0x310
>   ksys_read+0x70/0x110
>   __arm64_sys_read+0x20/0x30
>   invoke_syscall+0x4c/0x118
>   el0_svc_common.constprop.0+0xc4/0xf0
>   do_el0_svc+0x24/0x38
>   el0_svc+0x1a0/0x340
>   el0t_64_sync_handler+0x98/0xe0
>   el0t_64_sync+0x17c/0x180
>  ---[ end trace 0000000000000000 ]---
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250920155352.GH10800%40unreal.
