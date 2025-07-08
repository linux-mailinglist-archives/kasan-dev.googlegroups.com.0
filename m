Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBPPUWPBQMGQECCSOORA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DE9CAFC914
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jul 2025 13:00:15 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3df4d2a8b5esf40555455ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Jul 2025 04:00:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751972414; cv=pass;
        d=google.com; s=arc-20240605;
        b=lcoN89t2jZDz4ok0te1UJkJYHf1t+KHqEbUpzT65OLf1jExbmZL79y8emDKmfCyNwJ
         AY1jNnzC0U/kDwvVZk9SbwaL7TOk0XCwUdo886oXXv4Iaafo4DuQjganAyQQBkCEvBfX
         LV5ZEUsrsmxApUBWHN+xk92A7G56E7taJitr/mBVrpy7kvJXaCR0robAmXo13rtM5Moy
         FzANxlSvQ/ZxxdB0p12YolCOPCACWyjy10I7ERqqk0iVW9LG+kOPLKi9j2r70QjqsmMI
         sJJ/fszdra+P+A2GDD7SYi0UqoTAW9fFgqjfBPO12xxELjhdwFSm6MKDkQh1394XGtnF
         PQnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=owcne7Q3WvrN1KHdRZL1bve9sNlZHzcb1EbH1DNQOpE=;
        fh=F3REDqAoA39N6R/UTs5QDtbCjV7hsjxSgIadYuNVeho=;
        b=hmwTrra3mngdQAZB2tDgcTgv0I+bSlxsuYmir+fEyW09w5Vae5JualzoXQIqb/EMHJ
         1awAxgw/hmVWgUKdaq+ywFAi/fKZmY95fLwU/qFw0MbBtBCYVNYBZ+o76bGo0NXtXLfM
         1Y2hjLgGUbbDQdMamAGJXE1Lb9Hl5T4zP4+6dX6gFcaGBsQ7pR4T/3dzsKNUyXQhgYTD
         i0JVFSnykm5E1PdsjuR6jl6+d3OVschWG3GrsuAgrtR6WjSceSFS5M7/zaQr8tNBjBk7
         IjqIBPp9gQfLZpWfo8CLg8hnB21YzIcifWbu6H7en/qwLyY9reQq0TvPm4ZeUnidh6WJ
         u8ag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uN8tyuqT;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751972414; x=1752577214; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=owcne7Q3WvrN1KHdRZL1bve9sNlZHzcb1EbH1DNQOpE=;
        b=btS5Ts9TDTEXP3oI6EGgKdKNyEEGFqENqIWBARHoKSQOTtX60fXY4csUDsYG0or0aB
         uu5Kgw6/yJTy4SgxqJK2eT7QI0Blse3ddZwrBf6IzOZDrizpPj2F1YO2qzqnjThU6hDv
         1BjahflRz1WoPQr6YDOVjLkUDfbHIualzk5MKZ7/nwy0pmMyDKuXdxBqjZ/j/HZ79/0G
         BhcgzXKXrQzBspgkYLMe6w4bjKUYQaSGLNoYyU4+0Sam4EYXPRfCHoeuwSE9iUfSF3X1
         WKdxMoOW6Mc5+oNEhH0kT+/S7Q5e8CgiI0sxlDB+IWCMMDIHs29CwqCCI8zCIpHUqNtz
         fWRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751972414; x=1752577214;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=owcne7Q3WvrN1KHdRZL1bve9sNlZHzcb1EbH1DNQOpE=;
        b=JKESEtshoLNFjIGiLNq7Zt2+dhYgsBnHUz7r1tosmkpXI3nYc0Jiziy1VaZsDQun+H
         fe+39E5LebhgCG9/26gDi/JhIzWQjSvSry/8g5T5bF6afENgrJlkwi7oBYKtPyY0bH32
         6mhVCv5jIJbX8qjOQaEZu+KF3U3LD6+yMmNdNLPOSB3NRE9GmQ9dqTJFnAMKOZehlMNV
         9dp4nAPBXnw//64fb3xixyJNpvmL/GGBlNsaceM+oKErgQejiKD8nOh6FIAadHC19saT
         I+kFKXciNzkWJ5WsPtGO8etbqSTaxm7sKCFKIcDmnS+KAtuuaIyqPM+Jaqwcd2TvnhCq
         3fWA==
X-Forwarded-Encrypted: i=2; AJvYcCXxJQTHMYaxQoOwhCtpSjS1rBsYYkp1ODHumhe4/29DkzhGKET5e2UrEKdR1GDDZwD0k+aaDA==@lfdr.de
X-Gm-Message-State: AOJu0Yxmfc+FVJmzqcsZc7NL+AKxHRuWJauUWZ8Q9qkXT7Ub8bfIdNWg
	NQXn5HSmsuQ9sojhDPbBT/G+MnLPiSl2agSXLt+kjxwz4aZhkkkUfvR9
X-Google-Smtp-Source: AGHT+IHZMxUpuB27lcDwsM0XhaLLnTxbiJJquGp4aDVmPpSjVpTYG4CaRLJ2akVZCiYFd0kUGHi3/Q==
X-Received: by 2002:a05:6e02:3a03:b0:3df:4024:9402 with SMTP id e9e14a558f8ab-3e136f062c4mr152841635ab.8.1751972413745;
        Tue, 08 Jul 2025 04:00:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc4mwTPPLAjUHJ8PsSqxsrIfu1m3/EFKdz5JJtxjbFl4A==
Received: by 2002:a05:6e02:5e86:b0:3d1:9c39:8f7e with SMTP id
 e9e14a558f8ab-3e1391d7869ls26103785ab.2.-pod-prod-07-us; Tue, 08 Jul 2025
 04:00:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW8B0bJXOF7J+b7RUC7v7U6Bc4n+sPk2h7j3iRUGM580MA0FEaTPeZnFIXiJ8t9CqXmzNsDa7kh+rY=@googlegroups.com
X-Received: by 2002:a05:6e02:4419:20b0:3e1:5f8b:c0c1 with SMTP id e9e14a558f8ab-3e15f8bc62amr2453275ab.20.1751972412288;
        Tue, 08 Jul 2025 04:00:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751972412; cv=none;
        d=google.com; s=arc-20240605;
        b=lnfVnKXERe5RYqpsFzLrNVve4jOTr7+cEVUUVnAo3ZOP4pbD7jdcP74fXmAZqZNi5v
         8en31b7Scf7VMMtNJl9aoxv3GYnnr1T6zFm1PhpbR5q1r2TtDyPkDcPkL1V+Jeo14HPE
         Vn4+WuY/3D15MNQrWCvXilDpA26zp/nQkF0got4ielOpZ7dOTWssV33aQ1YUAlx5BhdL
         aYGbLcHi5Je1b4NornUZUyJN9gCnnBevNXlDCKPIfJSw90y7t3NA94UwrIecTOh9X7Yx
         XW5T6DfLmGKpNVztVPnkGeRW2fF6H2AQEt6da/UT2kUMcIZrPah8cPQ7cMT/qpg02vDH
         HDzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5KW2QIC6jmGHY1Ben2OZlkSykbNXUJ+rne80QQUMlFA=;
        fh=grh+l/l01Tfuw88bd6pzQP8VTuOQOiDQnVZvsS9R1x4=;
        b=hqYDJBTnzz92OD9HQMPlF+jjlKUFH6mkbT7L/pehPp7GQnjU3FN/AZ7Op14oiMe8vf
         nrbkYIQKkKIDNKEDkyh3yydQh3zyYh10bU4xfXm4B/VqmkWyu2k6NKtRa9osi1lX+Ffd
         QHIYMZIyDAW/ibAaocZS4Tt+aiZMSGKKSqGlP7aHR9VVyaGplliVYzpMmF8r/ISxkh9c
         4sUwyU0eWkzpulAnK0x8FLjQlHh/NvfSBNx+kPYiHcdq6zcpaB2XPy+KNPEfNwIDtSLi
         rZHhy+LwS9fVhTKhEy7a62FIRpiyaL8st4JI7fNes+iKGjSOkXpEwgFZS1XgbNUs4jF4
         HZ8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uN8tyuqT;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e0f343ee48si3653865ab.1.2025.07.08.04.00.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Jul 2025 04:00:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id D46E15C5ADD;
	Tue,  8 Jul 2025 11:00:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 91044C4CEED;
	Tue,  8 Jul 2025 11:00:10 +0000 (UTC)
Date: Tue, 8 Jul 2025 14:00:07 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Christoph Hellwig <hch@lst.de>, Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Robin Murphy <robin.murphy@arm.com>, Joerg Roedel <joro@8bytes.org>,
	Will Deacon <will@kernel.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	Eugenio =?iso-8859-1?Q?P=E9rez?= <eperezma@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?iso-8859-1?B?Suly9G1l?= Glisse <jglisse@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, iommu@lists.linux.dev,
	virtualization@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org, linux-mm@kvack.org,
	Jason Gunthorpe <jgg@ziepe.ca>
Subject: Re: [PATCH 0/8] dma-mapping: migrate to physical address-based API
Message-ID: <20250708110007.GF592765@unreal>
References: <CGME20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf@eucas1p2.samsung.com>
 <cover.1750854543.git.leon@kernel.org>
 <35df6f2a-0010-41fe-b490-f52693fe4778@samsung.com>
 <20250627170213.GL17401@unreal>
 <20250630133839.GA26981@lst.de>
 <69b177dc-c149-40d3-bbde-3f6bad0efd0e@samsung.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <69b177dc-c149-40d3-bbde-3f6bad0efd0e@samsung.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uN8tyuqT;       spf=pass
 (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

On Tue, Jul 08, 2025 at 12:27:09PM +0200, Marek Szyprowski wrote:
> On 30.06.2025 15:38, Christoph Hellwig wrote:
> > On Fri, Jun 27, 2025 at 08:02:13PM +0300, Leon Romanovsky wrote:
> >>> Thanks for this rework! I assume that the next step is to add map_phys
> >>> callback also to the dma_map_ops and teach various dma-mapping providers
> >>> to use it to avoid more phys-to-page-to-phys conversions.
> >> Probably Christoph will say yes, however I personally don't see any
> >> benefit in this. Maybe I wrong here, but all existing .map_page()
> >> implementation platforms don't support p2p anyway. They won't benefit
> >> from this such conversion.
> > I think that conversion should eventually happen, and rather sooner than
> > later.
> 
> Agreed.
> 
> Applied patches 1-7 to my dma-mapping-next branch. Let me know if one 
> needs a stable branch with it.

Thanks a lot, I don't think that stable branch is needed. Realistically
speaking, my VFIO DMA work won't be merged this cycle, We are in -rc5,
it is complete rewrite from RFC version and touches pci-p2p code (to
remove dependency on struct page) in addition to VFIO, so it will take
time.

Regarding, last patch (hmm), it will be great if you can take it.
We didn't touch anything in hmm.c this cycle and have no plans to send PR.
It can safely go through your tree.

> 
> Leon, it would be great if You could also prepare an incremental patch 
> adding map_phys callback to the dma_maps_ops, so the individual 
> arch-specific dma-mapping providers can be then converted (or simplified 
> in many cases) too.

Sure, will do.

> 
> Best regards
> -- 
> Marek Szyprowski, PhD
> Samsung R&D Institute Poland
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250708110007.GF592765%40unreal.
