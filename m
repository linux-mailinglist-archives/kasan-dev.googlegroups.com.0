Return-Path: <kasan-dev+bncBD56ZXUYQUBRB24BSPCQMGQEIWDU5FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id D7C1FB2CBC5
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 20:22:53 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4b10946ab41sf4641461cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 11:22:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755627756; cv=pass;
        d=google.com; s=arc-20240605;
        b=SWcsA7LN6fcn6JxnHZzPbX+pMlbnIeuZw2z0lTJ1vF3TFK+foZUea5PWX4aMSWC7Bj
         tTPFbfrP5bxD51famkI1dWccXwh/nwxUKHAveYgZOjaDWZGWrImsshKuJQlCdIghzw65
         hYcwj4ydrEvcaWWSApfTvS7I76qJrsWqsw4RxJZibgRwCyZxzkwLOxUmDYWSWLSt0wVv
         pZcToVhdSZj8ws1OdbdtKZYQS3HNrhYd4J2Ywrbs4xe/fiCsj6GZ97uwvtfPSlNguZNt
         iQSjkUe4OC9C27wMtI3NDXp1f88VPs5fgtgdGtAcYluWT4dXh23EBLds29itDfsaFN3A
         H49w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=KS/d0Er9NnCc0+5V4VtwVqbQWKuRGvHPnFDyN/bcSGg=;
        fh=NLkSOf4sbbpgHIP4AgltcjgJNp0tZ9r+dpvtnbw25T0=;
        b=Ky/E+uleDwmzhh6z9cOMJxCx7AwOkzOwRWBWJdzJUu3/Yd4vQTiaDyEW/r6XF9YytE
         5dEMu8LDSd9f6XXmre0igjw2Pp8BQXmtaSciYMEYx0UmYKEH3FAKvRE1nVkk9gINv0nM
         r+r2FQSxTm90arrXHQZqmeQl+bKg5XAGCTzb1B11Oa9HUn/euOT6q2WIOT4mtO/q66K8
         8sk6mP2Gz3/YNnLs0C3zDN91c3pGAYpSeXzgOzaxgdVFJif5DchEjlruaOLlbcdtvheE
         OUOcYruEudXOkBHIgzOTvbML+eACQG15C8xuYa5qZZHfxIdY2jonaCKLItsiF0m7T4rQ
         wklw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="alN6/hwH";
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755627756; x=1756232556; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=KS/d0Er9NnCc0+5V4VtwVqbQWKuRGvHPnFDyN/bcSGg=;
        b=ey2E/XiBDM4yC9nTQk/bqwG9tyx/IKrYei8Ii7qg2Qo9xxoGwSmK2FtywitUWAmXaD
         HrSnmGfywfPYNg4NSUszi5rOM46i5oRyQkS0VLkBv8AQAzxwBTvGA+jM5g11qyiSIhHh
         vuUgkeJIhjGayFuryl3KEAVqUc88LWRmGXgZoQsnF5e5kYVoNis47gery1uIWEyZNokb
         TfeushIrPoq81ZPErtSNPXqok0mkYbUu3tGVPb6G4osgF/NVQLRFSVXrBWxH0+9DIROz
         8mR6PvvnbB/FKvxbQQQR4PPHKwkCQDM8UWqgp6Kk4HgC1bdjq6q9ym5JljJ15vaLs7hP
         2QIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755627756; x=1756232556;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KS/d0Er9NnCc0+5V4VtwVqbQWKuRGvHPnFDyN/bcSGg=;
        b=ZEjAwVSzOs6pJ31nRzW3nk5xMTed5pPtAhaD7zF9qH9ATOZbtW1YVaGkGgT/XHplD0
         cXZS0gA1MSVPBgphwMide4K3GLutov4r/BNz4Qz32aYEYqDbHeiXfOY1REEck+PliPay
         ZZBQcI0+BLBqnvmb+EAu5eBN9K5rPvSSI3/nGqnfSfr3mnwhorCeHDBeztYBHOUWTS/8
         Nk7z+4sMQep+pbU3Oz6OFwahf3TM/JWW6pKEsVAJzjLIoSIYvdZf3J2ij7sw1U+4lkNE
         sR+LqFnBS2OV0GnFCaHkkM0s6x4W0g3BajShPQwyRp+sAwXPeLIW8OW/Uy4K14WUUseV
         j+nw==
X-Forwarded-Encrypted: i=2; AJvYcCXAkOJWPjwwwvWflX+bJZ8ov8wvrBiK14CHhDHZGrtHZZkIajAry/ku+mfTdYmOtqgxpBVgUA==@lfdr.de
X-Gm-Message-State: AOJu0YwzDX7ERqe656FdfhTzNG9mxGNTXc5FKWC/HYWjE6+dR3L8eqjv
	46f8MIUAPxki6sWFGnWDrjrI8YSTy84FKimrytPG90vPysjTkKQ9gtVU
X-Google-Smtp-Source: AGHT+IEHBBiIplSM9S28+LrPzi0ll/9i8s9gChXKjkP7T8OHEkggr5N8t4b+yihtX1q1CTBHFVKIMg==
X-Received: by 2002:a05:622a:1f0d:b0:4b2:90a3:6235 with SMTP id d75a77b69052e-4b290a36293mr6726241cf.1.1755627755909;
        Tue, 19 Aug 2025 11:22:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdIrtVDOdDMmm9iYJcdDMFjNgaA3SwSp5J8X7MvyHi6XA==
Received: by 2002:a05:622a:1789:b0:4b0:6adb:de19 with SMTP id
 d75a77b69052e-4b290c2c484ls1712491cf.0.-pod-prod-00-us; Tue, 19 Aug 2025
 11:22:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV2cJofqqptQLnhuUTBCzNTou7ouLhAmm39wLmx/rxehMs4vhYkONY4Dp6mGSDlcaRvZ/azKMKZJuQ=@googlegroups.com
X-Received: by 2002:ac8:7f47:0:b0:4b1:22af:3984 with SMTP id d75a77b69052e-4b28dff0a6cmr21020311cf.16.1755627755003;
        Tue, 19 Aug 2025 11:22:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755627754; cv=none;
        d=google.com; s=arc-20240605;
        b=ODcxFKmMWKanCbNQB4IkxJCj+LOcueVPYi/AdVP/GOkm9Hd/RGTCN9aP4Q4XMV7KxJ
         Nlzwo8GLCfpXCC6VXtu6mAxmhM4RbCl7ZMvMyp1lN0dYgoylRfGuykWvLYTA4WUVerR+
         0XOcZUGn6zZ+YJh5Q64g08sj+Eda0Ig3GFMUkePidHDbBL5fMZbRC8/CO5Yt80lHBwqW
         HhBXl2zhH02mAjOr2BbFfHk1LIcGxuu+tR/Q18RSDNqcnSUZI/3Nu4D7ye6GriaD9CCu
         gzAozI6qWbPyHPbUzMPiB6lOu+YCgw/LECxGWxNyRRsjqw61h8A852hIynvkZRgRd+Xf
         AOuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=rPawf4MAOK3K2lEjypEKyp/U3T0IFN68PxzTHE3J6/E=;
        fh=j6sgmjYfcl3NT0NcHnADy1HyK+NYf98K9zJ9uHWD/qk=;
        b=SVtKZ6+HxfZXqehN10qOursisPyuHYmWXw4eE/v1ONOPI1IQGRkU8j8dqiNkXEdrtr
         6bcRvAYo4ycHtishBgGvv0LqSU03unHu4vIVWoUTi9htuIxKE7xMALtpXwN5MlqRmpWM
         8mFk+xw2A1yU7JL8y+/wVVpGcg8BOQ8Z13jNzA6uswO3+q5ebi48tEB1D4peBFl99yE+
         i/0T45K2og419zOqDmLxf+6dPan2Lsdon12JzESeAN4ddBOi+RRUqqv2M4oPOc+YlFXb
         374Bm6lX1ifUqqn/Yg+lKxFqVzu5i2Z7AyDdDBHDh+GbwGGKOCncRtdndXNpBN6/3SWP
         DDvQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="alN6/hwH";
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e87e1dcbe1si49536685a.5.2025.08.19.11.22.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 11:22:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 594E960209;
	Tue, 19 Aug 2025 18:22:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8557CC4CEF1;
	Tue, 19 Aug 2025 18:22:32 +0000 (UTC)
Date: Tue, 19 Aug 2025 12:22:30 -0600
From: "'Keith Busch' via kasan-dev" <kasan-dev@googlegroups.com>
To: Leon Romanovsky <leon@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Leon Romanovsky <leonro@nvidia.com>,
	Jason Gunthorpe <jgg@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, linux-block@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-nvme@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org, linux-trace-kernel@vger.kernel.org,
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
Subject: Re: [PATCH v4 11/16] dma-mapping: export new dma_*map_phys()
 interface
Message-ID: <aKTA5i1IZquRBolf@kbusch-mbp>
References: <cover.1755624249.git.leon@kernel.org>
 <bb979e4620b3bdf2878e29b998d982185beefee0.1755624249.git.leon@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bb979e4620b3bdf2878e29b998d982185beefee0.1755624249.git.leon@kernel.org>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="alN6/hwH";       spf=pass
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

On Tue, Aug 19, 2025 at 08:36:55PM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
> 
> Introduce new DMA mapping functions dma_map_phys() and dma_unmap_phys()
> that operate directly on physical addresses instead of page+offset
> parameters. This provides a more efficient interface for drivers that
> already have physical addresses available.
> 
> The new functions are implemented as the primary mapping layer, with
> the existing dma_map_page_attrs()/dma_map_resource() and
> dma_unmap_page_attrs()/dma_unmap_resource() functions converted to simple
> wrappers around the phys-based implementations.
> 
> In case dma_map_page_attrs(), the struct page is converted to physical
> address with help of page_to_phys() function and dma_map_resource()
> provides physical address as is together with addition of DMA_ATTR_MMIO
> attribute.
> 
> The old page-based API is preserved in mapping.c to ensure that existing
> code won't be affected by changing EXPORT_SYMBOL to EXPORT_SYMBOL_GPL
> variant for dma_*map_phys().

Looks good.

Reviewed-by: Keith Busch <kbusch@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKTA5i1IZquRBolf%40kbusch-mbp.
