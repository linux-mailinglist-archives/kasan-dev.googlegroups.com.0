Return-Path: <kasan-dev+bncBD56ZXUYQUBRB677WXDAMGQEEGF2JIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id D1C7AB8A80E
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 18:08:29 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id 5614622812f47-43b330c6e05sf1445959b6e.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 09:08:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758298108; cv=pass;
        d=google.com; s=arc-20240605;
        b=kUkQz/FC4E95TPxJBG7ghCp1NIrqRMKJOtE4fRSoGq0CzeANRj/hFK2Fe3gWRCmT8Y
         rjbZUJInXfBKtNHhTisXkQXjUfI5Mi840H3umLIoZKRl3J9kTezq6Ewq8cqi0CCsXYq7
         gmcUYzJC5Y6z2IJVWRsLMso5UVoiGcc0mnUAjVwNHYsmI09zh2Qqx4b8zqG69DanIczw
         pg+HjJSvK0vRZRZz7IgcXPKdrchqQYdjFCDOQkhnuu8oXtfuf+wtErs/PUE3ZeKklBz5
         Ip3QiN/WX+8m13yBMSHJ8BB58astgBG/PwUx5DeaoZn0HPr98sbat8O5HKRvoXgbNG1+
         urxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Odm7qgVbfJOkxDXAoBUYIOBE4YeoaY6LH9Dxnpp8tvc=;
        fh=dqMA2QaxFY8K6oyp1Zbylj50EDYf1ZkpgOXtIuSyYIs=;
        b=H2oouseh8t0JCjI9yefQaKDiOh1VP6LGR4w7EFdQ9oG45r+udKp9VS1Wfhaq30wsIo
         P4ebxrc743D1CcDb3Ie8tgQs+APl3wL3DCRf6Iv3n/Tk2yxMNaIntAxJEPyhq9LiE+FU
         W0aW35jRWu+2waCjyDUe6c3/hn7Up/htPvxeKrk6kWnrStmkgyzBXHJ6AN0fxjf7N1Qc
         wbvNUtK+Fwh6gAkZV0/Z4lu8/WwIlR2bMP5YfJg9aCVnGZVvpSA5xe24j2DKOsWfReQM
         2Scd0/BziJIVvqBLjMKCap/aBrPYA1MMESP+UZYXigpYRTwkeAw7HRolWc9ENNk6ldvS
         z+WQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gxcwNWOd;
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758298108; x=1758902908; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Odm7qgVbfJOkxDXAoBUYIOBE4YeoaY6LH9Dxnpp8tvc=;
        b=jV2e8hjp0YnzcXvxZVEQhu2zB3uIaQREe94Ve8hvhotg9osakF6OxqynfvBvumD3IG
         +A0M8AeHyg2JFkohtnOv31L8BmJz0LNaW7xs9RvLXw+J9wk4erIpO1dNza/fAHfcrZu4
         zMc/Sv+Jam0DNjfpUb1EzL+5gZO93wgiWkOiy7gi7zlthl3zTl7UlBfLOJPZNI4Gzka1
         P1ogF4e+VGCGvnyXUUVZyf4Hx1ple+B3oC30nzHyiAgByFdWCgoERRQ4eQFsaJ83st/F
         gCKwxDHtLr2fhDc2GkjgzdmqKas50TRu94k8CQMvGXnD1YhZw4Q4x983i7VCxBYOJjOq
         +xCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758298108; x=1758902908;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Odm7qgVbfJOkxDXAoBUYIOBE4YeoaY6LH9Dxnpp8tvc=;
        b=H+PRsktmTiw+L5idkvtviDxr2dFICY7G41tyv2fj1dztHaPeemykCLpdKx+1bckTU4
         YUz+dCBk9ZjlsnSep1M3jrAu1rH4UZ9bnZtiLrPr0PmXWJKMSjpDQ0ugyT74D8qk2jym
         CzMc/SHh9HAqiwCOjla302M0RbpWGLRnOJU4drGdnO8+Mzw1HyXQgqIqYGRlxjDGSCgK
         ttV/st6DGNzBBLJDJoe7P6XyunARwLpJYvDgpkKJx8w2mUV+09F6pHOyt3lyn+WQlY+t
         +3mjHEYAPmgvnGAr9KWoc+P/MF/lMrdpZRXBv+Dwi9PeuIwx7RbCeTiQBJ3gT513YGUd
         ytKA==
X-Forwarded-Encrypted: i=2; AJvYcCXVBXnXCwhErPm8lb+Uu5SldBxDIJLf0XkyejXgl40FTmfrkZ1t70elwJ9vDLEeFD09wIcA+w==@lfdr.de
X-Gm-Message-State: AOJu0Yxr3bZ82hhD9x8r1D9jPhJbAB8bAxYKMhDzgZzrZTBqZ6RS8ONw
	bDjCoW43megm9dy6XccntPyvQpjqDqs40ZkSTaN0ugiPmV2zbIW1HezS
X-Google-Smtp-Source: AGHT+IEEjXBLen83h05E1S2dwK2zkxGUD2M99IaEgwjbTODI/o0KZLA2JIqkslPwQhdVLdTEljW3Mg==
X-Received: by 2002:a05:6808:2228:b0:438:2440:a594 with SMTP id 5614622812f47-43d6c2ccaf5mr1166585b6e.47.1758298108186;
        Fri, 19 Sep 2025 09:08:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd54XSql57EyzcgAvjV9h/bqybeJMQGj0QJl7CgGHUAaUQ==
Received: by 2002:a05:6820:2adc:b0:621:a2f1:abe6 with SMTP id
 006d021491bc7-625df6d3a26ls557095eaf.2.-pod-prod-08-us; Fri, 19 Sep 2025
 09:08:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUWXDvjNNbaOGYF48x2ROUo7x2LB3smoo1K8u+5z0bAVbAD54l3+FBysSbEHFgbZPcXb3iY+ue/14A=@googlegroups.com
X-Received: by 2002:a05:6830:4392:b0:746:d70f:d4ea with SMTP id 46e09a7af769-76f82661af0mr2139701a34.34.1758298106211;
        Fri, 19 Sep 2025 09:08:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758298106; cv=none;
        d=google.com; s=arc-20240605;
        b=Lk+hNFQwCmpedi71hpA6hQ1j5plSRp6INExgYgd8kQpUPkQe5MdPuojWHPDfLsiblo
         YuIfbmlUgLxKAZjfg0541+srXjvIMWYTb+jJYMBkQUrKBgaQPDKmF0DgmCzrKUS6T1X1
         /zYMx9+jaaXZkmJItj5nzMOKEOAFVRkLrFac+cNdWpRWtN2V66wLzhEiZPq+yEftIXP4
         UZbHY/JPsWU244wbV+Ukh2mJVQYKQW0yW/8/p+X2vkQ8GWQAflNq8WznffDOA/OCJR4W
         RvZdQjPQ5vbiLlLDGWrEBSINe+9bGjluDrsArv6awY67/Bndps7s8wEiKr5+eV5BRjvL
         Gsng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=93+iChQy8k9w2vSLxjsMF2tpsbL6StUGENS3z0mFMo0=;
        fh=/pP+JCOVj5Up2vjyxsdjqDSC1OMjCf55UJSgs32bCfc=;
        b=dFE5zk9Q3lmxD3JF1FSimKTrBao4HO4PB3H4A8y4SQNVcYAfFNvCM0b/cRITQIE/gG
         kwNeQ5VbrC462B0oA2BtsdDQt2GhtJt4NvmL/usxO4P5a8JJmR0Z4gHnV16oMR1spXPk
         J2iF40phyp1X7e4G+AQlb4TaxXNgsz+JqfRP4AZ7VFOkAnysfvqMHq8qQJsz2SYS711s
         2bK5AL8cbsM+N443l18RSmpAPqcWdnJ6hKNKcBghT+qY8ENbXAURNMcYot1jDneu1xPx
         o0TCfCL4kTLFkAUa8NrJ4PliImxMfWTdMvY7wXLyNW+pkyQ0AjwTAPOzfMGI+FITDMaV
         AVmA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gxcwNWOd;
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7692c348adesi252662a34.4.2025.09.19.09.08.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Sep 2025 09:08:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 581BF60140;
	Fri, 19 Sep 2025 16:08:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 76C8EC4CEF0;
	Fri, 19 Sep 2025 16:08:23 +0000 (UTC)
Date: Fri, 19 Sep 2025 10:08:21 -0600
From: "'Keith Busch' via kasan-dev" <kasan-dev@googlegroups.com>
To: Leon Romanovsky <leon@kernel.org>
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
Message-ID: <aM1_9cS_LGl4GFC5@kbusch-mbp>
References: <CGME20250909132821eucas1p1051ce9e0270ddbf520e105c913fa8db6@eucas1p1.samsung.com>
 <cover.1757423202.git.leonro@nvidia.com>
 <0db9bce5-40df-4cf5-85ab-f032c67d5c71@samsung.com>
 <20250912090327.GU341237@unreal>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250912090327.GU341237@unreal>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gxcwNWOd;       spf=pass
 (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kbusch@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Keith Busch <kbusch@kernel.org>
Reply-To: Keith Busch <kbusch@kernel.org>
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

On Fri, Sep 12, 2025 at 12:03:27PM +0300, Leon Romanovsky wrote:
> On Fri, Sep 12, 2025 at 12:25:38AM +0200, Marek Szyprowski wrote:
> > >
> > > This series does the core code and modern flows. A followup series
> > > will give the same treatment to the legacy dma_ops implementation.
> > 
> > Applied patches 1-13 into dma-mapping-for-next branch. Let's check if it 
> > works fine in linux-next.
> 
> Thanks a lot.

Just fyi, when dma debug is enabled, we're seeing this new warning
below. I have not had a chance to look into it yet, so I'm just
reporting the observation.

 DMA-API: nvme 0006:01:00.0: cacheline tracking EEXIST, overlapping mappings aren't supported
 WARNING: kernel/dma/debug.c:598 at add_dma_entry+0x26c/0x328, CPU#1: (udev-worker)/773
 Modules linked in: acpi_power_meter(E) loop(E) efivarfs(E) autofs4(E)
 CPU: 1 UID: 0 PID: 773 Comm: (udev-worker) Tainted: G            E    N  6.17.0-rc6-next-20250918-debug #6 PREEMPT(none)
 Tainted: [E]=UNSIGNED_MODULE, [N]=TEST
 pstate: 63400009 (nZCv daif +PAN -UAO +TCO +DIT -SSBS BTYPE=--)
 pc : add_dma_entry+0x26c/0x328
 lr : add_dma_entry+0x26c/0x328
 sp : ffff80009fe0f460
 x29: ffff80009fe0f470 x28: 0000000000000001 x27: 0000000000000001
 x26: ffff8000835d7f38 x25: ffff8000835d7000 x24: ffff8000835d7e60
 x23: 0000000000000000 x22: 0000000006e2cc00 x21: 0000000000000000
 x20: ffff800082e8f218 x19: ffff0000a908ff80 x18: 00000000ffffffff
 x17: ffff8000801972a0 x16: ffff800080197054 x15: 0000000000000000
 x14: 0000000000000000 x13: 0000000000000004 x12: 0000000000020006
 x11: 0000000030e4ef9f x10: ffff800083443358 x9 : ffff80008019499c
 x8 : 00000000fffeffff x7 : ffff800083443358 x6 : 0000000000000000
 x5 : 00000000000bfff4 x4 : 0000000000000000 x3 : ffff0000bb005ac0
 x2 : 0000000000000000 x1 : 0000000000000000 x0 : ffff0000bb005ac0
 Call trace:
  add_dma_entry+0x26c/0x328 (P)
  debug_dma_map_phys+0xc4/0xf0
  dma_map_phys+0xe0/0x410
  dma_map_page_attrs+0x94/0xf8
  blk_dma_map_direct.isra.0+0x64/0xb8
  blk_rq_dma_map_iter_next+0x6c/0xc8
  nvme_prep_rq+0x894/0xa98
  nvme_queue_rqs+0xb0/0x1a0
  blk_mq_dispatch_queue_requests+0x268/0x3b8
  blk_mq_flush_plug_list+0x90/0x188
  __blk_flush_plug+0x104/0x170
  blk_finish_plug+0x38/0x50
  read_pages+0x1a4/0x3b8
  page_cache_ra_unbounded+0x1a0/0x400
  force_page_cache_ra+0xa8/0xd8
  page_cache_sync_ra+0xa0/0x3f8
  filemap_get_pages+0x104/0x950
  filemap_read+0xf4/0x498
  blkdev_read_iter+0x88/0x180
  vfs_read+0x214/0x310
  ksys_read+0x70/0x110
  __arm64_sys_read+0x20/0x30
  invoke_syscall+0x4c/0x118
  el0_svc_common.constprop.0+0xc4/0xf0
  do_el0_svc+0x24/0x38
  el0_svc+0x1a0/0x340
  el0t_64_sync_handler+0x98/0xe0
  el0t_64_sync+0x17c/0x180
 ---[ end trace 0000000000000000 ]---

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aM1_9cS_LGl4GFC5%40kbusch-mbp.
