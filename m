Return-Path: <kasan-dev+bncBD56ZXUYQUBRBZWOZPDAMGQEXTMRD5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 203ADB97321
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 20:31:05 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id 41be03b00d2f7-b549a25ade1sf7433709a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 11:31:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758652263; cv=pass;
        d=google.com; s=arc-20240605;
        b=MlfGAMH+XaeISE3TTnHaiskDJBVHq/FnJUpJv9QR0se4P3eecxAlmc1WWwJfa29tpO
         Mx9uQZxfr/47Gao1MbH3K2DheIL9wx17q2k+31ojI323G8spmpP3tvrmguRZOF2QUUg0
         XdoVY+VihuVnnpksvhJkjWmNbsIEmHOqUGmf0ewiqQQFpPGSMqThS1WVzXmrYIe1ise+
         Om1Zx3C/IHCaph59kS/hFZKCIZ3FePSgCWduZ4er9Tc8pEcfpDW0uft/hQ0++p3/66FY
         C++GIMhV6N+/vFM2n1DKE3Md25+3JZhjpbNoWrBWyNve3kXfvfhwabZHHoDqiuIu1JJ4
         n50g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=47CdwBLrqbCa7UbGvgiSvRocN2S3jjjGAMidoWP94zc=;
        fh=3dS7N+oztq0b9n4XXCN6yWPu5iAC9FDRIBifU62qlrY=;
        b=O64j0SmShnH5n3GIk31u5b05qUzks5cpeL1bKG2v6lrLjVnBRwZ6eaK3xcGr/58MuO
         wWUhLkXtD03lyt/yxHeUst2ZYMs/b7hIJoDqwNyvvu/Ej5OVFQYZGVmXCDeY57qFSHYu
         xuNgAHhDoYDnOFYCxdG5/KP/ulqgSJvYj2y1nDulOHFGhvLE7FPhZDBPxhtKaIZyXr+Y
         XXmDdbP8I+tg7+TbrEG+qMrLl9kO94g0abA9IZPZgu6EaAXoP/HSO0Lk/eOEg85bxsnY
         ITQ9XNHmW1O3fQhYh9sv8iaJ1zk+Xjxmz6TYceGayBXV0PpHAC/CpFRgv1YvIoKSZWrh
         GW9A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=S4ZXIaWM;
       spf=pass (google.com: domain of kbusch@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758652263; x=1759257063; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=47CdwBLrqbCa7UbGvgiSvRocN2S3jjjGAMidoWP94zc=;
        b=d4gXT3wIwx2GxuN2KIxYDwSCoAnSiaqqc34r7n1kETsFgIUKdjmhpcf95M303Bg3fq
         66WDWCjPB11PfLpUxVOmQU6hePjYF1GLRpul0BYJyugFiX+vSw33IC3zPFOcPOTHb3IR
         MIgYW9BFmZ8NaKXibvAzCrl6vgUYDV2EmEvCtPzExMnsm22iBJ6dZm4MZcP4DyP6GaHs
         HCADjHZsFXtYjH6JvfZlERB5kCud7J+D8pdFUPhWGAvN00aBA7bIlq5+BRnG3g01X6c8
         fbB6oLlAzQ7gvEUER212snBTZWSilzwS8IMpYdhvAaLpQ3s1UoW6jDbEtebcTKJK243g
         ejOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758652263; x=1759257063;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=47CdwBLrqbCa7UbGvgiSvRocN2S3jjjGAMidoWP94zc=;
        b=axJYLaEMe2q0e9gKR7D7FAQFQ8eM0hD6s03b5xkhBKDsA0tyuc+JpS+ijF6+LPp6eU
         KVOxGpTiMRHauI9aJerv82QY5G25AOxLD2Xyp5KGkxg42VgjQvaXmQzduvUqddIGEIsx
         6ju27eXGVXkoVPCkfV3e3J0wMnsbUU7h1lF4vQOMSh86KDvpRz73zTSewjAZAu5eWFeU
         aNH5JKuKEXxZXnnymk1SIXCmGmyEyG5nWGZO9q5Wm8RKzS+ikeo4EXjUnlx8H0kgQBSp
         9Rq6fS8nYyFvrSXT1RaVSt+h1T3aBQEP1zADBKSReZqBNwPWASqg1a8hmy34h9Hk+GcW
         6WGQ==
X-Forwarded-Encrypted: i=2; AJvYcCW1jNveP+MbVB1wwueT5xTwPZ5pO8Ynbv6DLgEqlGmPKRTmrNK2Q5t1tYstP2N0zuv3Us+NhA==@lfdr.de
X-Gm-Message-State: AOJu0YxDV/IxiJ9O2BQ8siEcZUzKPGOQSa5NC3QtXhahxjknt7zECgOs
	dq1U4ad3aSOdaxNBJutz1NlGhSL5oB0XTlRXAxHr4iJpk0CTYZNnUUuy
X-Google-Smtp-Source: AGHT+IEU0yFwHbTG4T8zEu1RZhzfWY2fbkj86wc6dFcYxGbMYWjcJVSuZEiL2mFibdIE/yeme0fCsw==
X-Received: by 2002:a05:6a20:7289:b0:252:3c5e:45c7 with SMTP id adf61e73a8af0-2d00675b36fmr5379658637.17.1758652263363;
        Tue, 23 Sep 2025 11:31:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd68y2a6blQo8Ny13jyIuONFeydeUyM3MKxf0lwoZGF1YQ==
Received: by 2002:a05:6a00:a449:b0:77f:33ea:9853 with SMTP id
 d2e1a72fcca58-77f33eaa262ls2134675b3a.1.-pod-prod-03-us; Tue, 23 Sep 2025
 11:31:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXfqW+2JD1cuYN1oNkjRPVYs7W5L450whoeGcBbQPtmQDQiMrJBwFIcNrhiY2Dde37RkWqBq6vqtUQ=@googlegroups.com
X-Received: by 2002:a05:6a00:988:b0:77f:156d:f5b1 with SMTP id d2e1a72fcca58-77f53ab2d5bmr4531205b3a.26.1758652259887;
        Tue, 23 Sep 2025 11:30:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758652259; cv=none;
        d=google.com; s=arc-20240605;
        b=klbHTSDiMRVpPHKOXx6MRfxHc+ZDIlt6zIBohOlzR8ygDScJn4Y/BBZ9xJ6OsEJ7Gk
         /m8y7EHDac2rNGGUSE+lLHQr95bErPKwTvQUmMJwGzrKCZeE8C/SVJUY0uSjvRoCud/V
         /Z0KfuUQ3DW2bwNflNL1p68SgqbAttaYQvC5dnY3eeEXHX86GhCKPh98Clu1iQOkDRuG
         1ifOd2aNiHyIyvNXh2TJCQcdF8c8t7Hr1tmf13nAZuv1hRfUBci74AR+/OBEUkx8n0bP
         KiQc5YmDIvq8ksxsDoO//n42WTqjmaRMVLf9PuQLZ2mxytYeBj9NQg982A80BkafqEab
         ZMmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=f74v45qTfX4rd0AIVdvbIhhb3jagTfRC+ZZltoOMjTc=;
        fh=wB5rWgJB0RNxJt9sN6dF69FyVhDpMnk+gJOyItA08gE=;
        b=hKkaqBvH0m5IgQl6ilRpSTaBkXzN5eUYanQTBhr8wgypU0qZA2SISVMJJI1wxfXhxw
         RKqSpizz/r+XJ+4Dw+yoT5pfn0zGp5wvMjJDRdlQa3hE04Oz4EU2UAIQF7HGpe1gJfVe
         Fnxx6Rl30glKNhyCQaTSZLUNba5WUu/BO3dNwhDcnwMiz/U7SMYDqM9Ot88rWJ++8wqH
         15eJVtLENn6FfdrM2BliTFHV+n1YnLGL6V2kTsfeFnu58vSD1KnGGSfw5zZSK9K0DQxF
         ADnMK5LWlZI8/jUUbc5DO0GkDHWNgTAfm6n1dQ0d+BFTLTdw220nvqXArWISiFL80wWk
         hGbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=S4ZXIaWM;
       spf=pass (google.com: domain of kbusch@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77f43239352si202933b3a.5.2025.09.23.11.30.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Sep 2025 11:30:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6BC3A4393E;
	Tue, 23 Sep 2025 18:30:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AB030C4CEF5;
	Tue, 23 Sep 2025 18:30:57 +0000 (UTC)
Date: Tue, 23 Sep 2025 12:30:55 -0600
From: "'Keith Busch' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>
Cc: Leon Romanovsky <leon@kernel.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
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
Message-ID: <aNLnXwAJveHIqfz0@kbusch-mbp>
References: <CGME20250909132821eucas1p1051ce9e0270ddbf520e105c913fa8db6@eucas1p1.samsung.com>
 <cover.1757423202.git.leonro@nvidia.com>
 <0db9bce5-40df-4cf5-85ab-f032c67d5c71@samsung.com>
 <20250912090327.GU341237@unreal>
 <aM1_9cS_LGl4GFC5@kbusch-mbp>
 <20250920155352.GH10800@unreal>
 <aM9LH6WSeOPGeleY@kbusch-mbp>
 <20250923170936.GA2614310@nvidia.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250923170936.GA2614310@nvidia.com>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=S4ZXIaWM;       spf=pass
 (google.com: domain of kbusch@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=kbusch@kernel.org;       dmarc=pass
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

On Tue, Sep 23, 2025 at 02:09:36PM -0300, Jason Gunthorpe wrote:
> On Sat, Sep 20, 2025 at 06:47:27PM -0600, Keith Busch wrote:
> > 
> > One other thing to note, this was runing on arm64 platform using smmu
> > configured with 64k pages. If your iommu granule is 4k instead, we
> > wouldn't use the blk_dma_map_direct path.
> 
> I spent some time looking to see if I could guess what this is and
> came up empty. It seems most likely we are leaking a dma mapping
> tracking somehow? The DMA API side is pretty simple here though..

Yeah, nothing stood out to me here either.
 
> Not sure the 64k/4k itself is a cause, but triggering the non-iova
> flow is probably the issue.
> 
> Can you check the output of this debugfs:

I don't have a system in this state at the moment, so we checked
previous logs on machines running older kernels. It's extermely
uncommon, but this error was happening prior to this series, so I don't
think this introduced any new problem here. I'll keeping looking, but I
don't think we'll make much progress if I can't find a more reliable
reproducer.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aNLnXwAJveHIqfz0%40kbusch-mbp.
