Return-Path: <kasan-dev+bncBD56ZXUYQUBRBJUWXXDAMGQEQBFM27I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F695B8D2BC
	for <lists+kasan-dev@lfdr.de>; Sun, 21 Sep 2025 02:47:37 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-76e2ea9366asf2874375b3a.2
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Sep 2025 17:47:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758415655; cv=pass;
        d=google.com; s=arc-20240605;
        b=NZ0saz+zpBBS/M1mvrNMQSBbp7LfhwQiNWl3v4acmxyBGUf4MXHcodqdTl+lkFKuor
         GFo465/EKMAdynkURK9Lv/EtRtgclbMpbUCnVhLZ/Dy51NRDFsuHqDjmpzFRzaXwkQ3N
         tXTw7iO56fSm6eGtuTJtfX5Vci4bUoui0cvSZNRj0VRpWATIC7bhZ1sUtM1UK5v8xQBv
         btveucqXrmq/juzedz7+Yi71nvDDfeh7sLZ8RhcpqszwhkW56By/wZgrTRL5Xg7+V4d9
         lfKgolb2adtYpeSR4WTf88ZkQwwS2bK2sl32QcCkJ0HpWUF3U5hTq1U/YLB5+uRBVzEd
         4frQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=/Y7rdIz04XxxBj4K7NUCWJJ4fNKLCyOA6IF60xCDKn8=;
        fh=dW19neXzn6NSrBWPnGW3tPev7ZDOzRYStYmcD10SSpc=;
        b=NquTG9F65dArgNtBQbK5Pj+5RtJVkFn8J3NoQl+cm0VGEyq8pskPS3a4IXwSHk6cHd
         7HNBqYAUe5iiAZYJqKfUyunQQhV/POLqVfRgIO0VQhA70NuzEsqG5E7jZmnr/FrtAG+L
         IbCUm69QnIMKVsRumx80MS7oSJyhdz5Xfv9DZI/VfdWdZdTiYHbTUR8WGpmBUuSqmxqf
         H2MTkoZHhRE9LatcMPXDzvSzLckhHvHIctJM1dEtRHqnSVSNviPgfmKoBOHUMBLsk6mx
         nHc4ZOeokJC9aZ5ffljm1XIExwnIdv04sS9cdl5V+EgMp2kClWjwYoSwjTSTOytJPOCE
         mpbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fLUxwzDv;
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758415655; x=1759020455; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=/Y7rdIz04XxxBj4K7NUCWJJ4fNKLCyOA6IF60xCDKn8=;
        b=HDVIq+6vGBv2hBs1t5tZpM9oQvkeW52E36KkjpUITFoSpZQ6GfodOny3Gio3LSBywX
         Q8AeUvGqh5UPKeEFLUwhwns/vuxPjNlcBpRYYxr/V/RhsV79eDgS3CbDfp253VR+Coik
         YWTKqHgIrPJgxjGHDkMQWf9GkIXIEU7E8+8ctKgLMV3Hb3IrTZ+QjnEL1Yd1C6TxhLBd
         EL132xfWKXvaDm3LfoT2de1th874w0VcPsVE64Ofabv1YObLgY4p3sbcpz2QErsYYukB
         +hlXmGY5FVTCdOaP+LYcICtm8/8YrEm/Fvp0KjIIBES0KZX/c1BND3MTXTsEZ36mDY3k
         0MjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758415655; x=1759020455;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/Y7rdIz04XxxBj4K7NUCWJJ4fNKLCyOA6IF60xCDKn8=;
        b=Kr9LP9kwuVNXZ1BK7Ltt/RbAOL4fuz58AXxJ+yyPS1GuoN3ls4eQbnjUIJo4aVKSyf
         73k743gp5jBwaEgxCXvH1l44vdmq+aNiVi69irbIaOMUHl/XlFGG2Ph7QVrvab8OXVWa
         iKQg27JkH5xXn3SzC7hgPpAnH3mK0x5zTZJET38z1WHLImRJtAfbjNbIAlqISfrAPl6S
         JCwjh+1JiXHFU1kKQMNTf+XGxI1o1e1dk8tgdymU4aSxHlU9Ru3wNil09/Fu60eTB4ji
         kn2wlwbwpfDLeYu1memjm2ne43W1p04p2tPpza/d+CQSkQ8wmf86xoyWYR89El6ia2+Q
         ++fg==
X-Forwarded-Encrypted: i=2; AJvYcCU5CDc9kiCFmDUlqH9E/ijsRy2jcWJhqtl2dNAP+C4CQAm1PIZEMiprKlyNfEGFST03p/Q8Wg==@lfdr.de
X-Gm-Message-State: AOJu0YwZAi0nYnZ6G25G7u3rDbZDymc+0N+674XhDm6BK9/l+KfnnX1X
	SY/ezf7wBseV3GM9FuEq0OuigJftRv2wWSxpd2Gqhterty4df95J412Q
X-Google-Smtp-Source: AGHT+IEKancQlnZB88BU0ZZIMhFyrx5SI1q9k6nFW398sQbT+VbIZ2lsOkyRC+NPtxdIYEMGEZVPyw==
X-Received: by 2002:a05:6a20:6a06:b0:249:3006:7567 with SMTP id adf61e73a8af0-2926dcb8673mr10939639637.35.1758415655299;
        Sat, 20 Sep 2025 17:47:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4wtWsmet5OxcmvGRjHA/fi/GNdyIREIrhm5Qur3ctwSg==
Received: by 2002:a17:90a:296:b0:32e:a8ab:b267 with SMTP id
 98e67ed59e1d1-330651fc422ls2187088a91.1.-pod-prod-09-us; Sat, 20 Sep 2025
 17:47:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVRMROyfYTrMMEKhctnYjqWnhETUR0tdUshQMcv/7UEHulCOpnKu2bprTkIOn7LRQZgKEm+yf1XaY0=@googlegroups.com
X-Received: by 2002:a17:90a:dc08:b0:32e:87fa:d975 with SMTP id 98e67ed59e1d1-33098386c09mr8364698a91.34.1758415653804;
        Sat, 20 Sep 2025 17:47:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758415653; cv=none;
        d=google.com; s=arc-20240605;
        b=NicqhFaw8xODqmfgekK4/whkoHWlQCUFyhKyD5SeTPxSQiutoHyEXdf077ArtiNF8+
         x2/wk3Pw53hT5+pX4RhRNgQfzKq7YL1vdciiuPSIUsyGFDUCzsCrv+mGVhVHf1QcaMt+
         se0t5Xg3uuNAjh+4KczEJydsyZZox7FghT3yjYQ6qHuAGbVjgBPpAt5hNQENQ8z8ISFJ
         Slwn9oGEqq7J7HNis5/unjc9azjMp7ecWWls32psrBsMftZegWPsPLq/bT/kozEwk21X
         jgklJTD//H7PgLINJvaN5v7xCxlRMQAsQmhWmt6d7eJQxOD0ZUACH1qf15KPwNZcYTVy
         7ntQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xtIvv4lw44pUlJuaLKbzEHjJi6xJvnBBYTGn1zOuzT8=;
        fh=/pP+JCOVj5Up2vjyxsdjqDSC1OMjCf55UJSgs32bCfc=;
        b=eod73d81CBNMI8VIS9Q6K/bzPFMVXhP6VncFt/zGrbdN3XMzsRhrUUiQ5ATNaBJZy3
         YNeaeVIDVbgJWd/bMyafBFHX2h7CwAHXq+yUVgVu35qwSVVqcEEV/y2/zK2XLYTYeP0R
         Dsxbn5UmcnQNFzR27S7P1CTFg+nZJV22RSzDUnzLNOnla4Qae4HpSl9ueloqLDjG1C8g
         ytKiSJUES4XvpMJTWi48+nUcdXNEpU8PkCQrzS3USeLDdBElxwe1id2UjpBpX/T4Dk9v
         93boL/AXwXM7ze7xxX09ot3ku8UxLKvqLVKiYfAGzLLsW6aZSank6/XDknR2hRZWzc4Y
         jZNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fLUxwzDv;
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3306070f7d4si382387a91.2.2025.09.20.17.47.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 20 Sep 2025 17:47:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 70099600AC;
	Sun, 21 Sep 2025 00:47:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5F266C4CEEB;
	Sun, 21 Sep 2025 00:47:29 +0000 (UTC)
Date: Sat, 20 Sep 2025 18:47:27 -0600
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
Message-ID: <aM9LH6WSeOPGeleY@kbusch-mbp>
References: <CGME20250909132821eucas1p1051ce9e0270ddbf520e105c913fa8db6@eucas1p1.samsung.com>
 <cover.1757423202.git.leonro@nvidia.com>
 <0db9bce5-40df-4cf5-85ab-f032c67d5c71@samsung.com>
 <20250912090327.GU341237@unreal>
 <aM1_9cS_LGl4GFC5@kbusch-mbp>
 <20250920155352.GH10800@unreal>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250920155352.GH10800@unreal>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fLUxwzDv;       spf=pass
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

On Sat, Sep 20, 2025 at 06:53:52PM +0300, Leon Romanovsky wrote:
> On Fri, Sep 19, 2025 at 10:08:21AM -0600, Keith Busch wrote:
> > On Fri, Sep 12, 2025 at 12:03:27PM +0300, Leon Romanovsky wrote:
> > > On Fri, Sep 12, 2025 at 12:25:38AM +0200, Marek Szyprowski wrote:
> > > > >
> > > > > This series does the core code and modern flows. A followup series
> > > > > will give the same treatment to the legacy dma_ops implementation.
> > > > 
> > > > Applied patches 1-13 into dma-mapping-for-next branch. Let's check if it 
> > > > works fine in linux-next.
> > > 
> > > Thanks a lot.
> > 
> > Just fyi, when dma debug is enabled, we're seeing this new warning
> > below. I have not had a chance to look into it yet, so I'm just
> > reporting the observation.
> 
> Did you apply all patches or only Marek's branch?
> I don't get this warning when I run my NVMe tests on current dmabuf-vfio branch.

This was the snapshot of linux-next from the 20250918 tag. It doesn't
have the full patchset applied.

One other thing to note, this was runing on arm64 platform using smmu
configured with 64k pages. If your iommu granule is 4k instead, we
wouldn't use the blk_dma_map_direct path.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aM9LH6WSeOPGeleY%40kbusch-mbp.
