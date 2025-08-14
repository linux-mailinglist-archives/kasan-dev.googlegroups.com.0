Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBIWK67CAMGQE7OJRC3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E371B26757
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 15:31:16 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-30ccebc5babsf563345fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 06:31:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755178275; cv=pass;
        d=google.com; s=arc-20240605;
        b=S1NDzIwmPsf6hQ5gJAaiVGj86fa/55g0LQtvF+4aa94CuBlsq81GH0fmB97W8mP4wj
         zJ+46tK8GOUZVyxPXst+v2smGAZocUtQO/EE2jvVTGoNPTKhOunHXQ6IIHd6wEerTK0Z
         47gEDMn5eAfmze9DubYGMW016sNsv6XzB00f8DSHiLGfb23nl+m7cvVphgKSeojc4lpI
         jBgf0+PqWr/bTSPAEcF0U76JvK21dToVhUJ7BGC0zBmt1uvNpMqAUx1w8bIckXWonWMr
         n1aQ3xF/U0C/6/oaRgRJ+3q5G0lgbX3lpcbn5uD8rAP3s/Lr1EFs6fJKcRIvRnb2X1ps
         M93Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=adXDAVxfy2rk43shU/8mCzFDv0TebN0OZL0lDBudRKo=;
        fh=iNKUof2/d/3CeJMFLcDqmTp6gDcJYPIxkZQM3DvLG2U=;
        b=VAMgG8/eyFr06mJxTiTo2u3RvCQjXKk1EbT6KdUgx5WYBbAw37DQZ2XO7EiEExEAaS
         prxKnqKgrTneEITKGSzUo3yD0RdeV3H/J45C3VcDuI531VnEloMznOJaHftEUQEwL13d
         sUUrBwED32UbrzvRbrpbs93diqL5wHQVjQ7wXJo7lU3Vt5YeUumaUsZ1glNaBc1BIqz3
         Rj4qT7v5ibW6+JPvxHUBJ8et1T4Gnu2lmOa6ULkgfrFh4+cekKVfkqvXzUwSJJpDEdRp
         vkkpoy4I0Ie0+yV4aFbYD0/d9l5LWW0ecZzZbju/Mxtj2R9/GU1BjgwFj7p2wh4I+zR2
         xmgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XqHxW8YW;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755178275; x=1755783075; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=adXDAVxfy2rk43shU/8mCzFDv0TebN0OZL0lDBudRKo=;
        b=RyfdK+lUBynfcb4Z5qfgdJ9uqo628ZPXN9sBcZWwnYl8L0cKV1RyH19ZhElzWZ60al
         TCW+CLD/7/QwPihmuf1j7QdvBvdCq0/69C0Z2qT1aeKZR20e/GuzB0sfJ8tRuAXgt75p
         ltUP2uwGwZdlVSI1mXHikIcqZzg1hTzeXWlSkaH6EjrP1HbtsOqRARm+OXKKCqzc1AUD
         uhyaQTbjAYmpDf3N14OOUlsJE5MKLvybbnqVaj3e18BDz81NA3I+YyC1UzTbeaZIc3QC
         KkUTWVZ20k6FRPE+jUUfjauAqTjGOSUE+G/zRUAxwyC6Bp+c+DKhdkqwAv+I/3/yUiLW
         ojUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755178275; x=1755783075;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=adXDAVxfy2rk43shU/8mCzFDv0TebN0OZL0lDBudRKo=;
        b=cdHH4ngnUtR0cSOTlg7XL5Eqe/L4nOzvV3/dWXAZa2oWryuudsgEdH4Uf/59gGXsIc
         QO68u12MdYTTkq/6hNdaWiYnVCn1owkf0N2EFM36u6YyikpecVpFCeAEiTMUW/8w2JuA
         NvfJdz6tubMf0uRMGsw5yaTT8/+CpyV2vX6ruX93Wkz8zTpju4SXccl7mnq5Wm0wxNJD
         Fw91UJPF+ll2I3q8EF1JVn7Of+krp6S6RMvkPInsUNa7CttQ0Q1Wu2ZHZ5hhnutKHbjm
         p2MUMLALdAYYVshWw22rk96wafE3+7zGLH5+72IiE8VP2BMZEsSsWWJuxMRBBB9YUC71
         rCuA==
X-Forwarded-Encrypted: i=2; AJvYcCXw046AgsHOEpBxCdpHN774tNIz+6PHDqW1DeCl2OAjQzIY1APbmS6z1EMDtOAegXDqPS6E5Q==@lfdr.de
X-Gm-Message-State: AOJu0YwK+4KUsJnmm5/17eSB6e+NDNnnSFfnm91ycPGusBYubL2QuSYa
	Sgd0aK3j0MWyUYdAwdHhoAt+l7sj9fMU0N89MxHZOz/2CjfMrhIDlZFX
X-Google-Smtp-Source: AGHT+IEVUir5+Ld9iTmxqeqaO6pVZHBzRTNSH/HlStCpvl50F47xTo9bEqn5KynibKoCWgY7hwmXNQ==
X-Received: by 2002:a05:6871:694:b0:30b:8cb9:e70d with SMTP id 586e51a60fabf-30cd0da6d6dmr1976638fac.4.1755178274453;
        Thu, 14 Aug 2025 06:31:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZescyfMkXbon45PgaT3j82BWS9lAxEunnyueB+qUtj81A==
Received: by 2002:a05:6870:d249:b0:30b:76e3:703 with SMTP id
 586e51a60fabf-30cceb87e88ls369540fac.2.-pod-prod-06-us; Thu, 14 Aug 2025
 06:31:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZcvkN43P2HNPjysvkXlCp+E7BeLTlKT9ByCa8jswo6ikaxyqvSj7B6YB3CkR5PvPsDwaXkfo9FCA=@googlegroups.com
X-Received: by 2002:a05:6808:1a11:b0:40a:a408:a32a with SMTP id 5614622812f47-435df7c3061mr1726460b6e.19.1755178273253;
        Thu, 14 Aug 2025 06:31:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755178273; cv=none;
        d=google.com; s=arc-20240605;
        b=W+60KKwt6McIjaDC0kIjBJD5LrVvwjzhJ6drf9s0LXteOOXb9Ht80lZ89+gG12qEHp
         V/3pDpIvvT/Y6IaoAtYGG/yszKzHZK91lTSR+tM/z0hEZLhp+Sh6l92M0bdXyByE5uKr
         rQ/swwcgdmmDj0/IC8RjghKh8waOHNgC1rgzilLtBgt8ZlKTNd1ZVVdMlC8aIDnilkKs
         jTssutDCcL0tXnbw0f8/P7jxYD1n90r1md0Bli9W0tQyMlEj3SQDOXYFdZhYuuTwUHDg
         cZmlEtGv12LAaPEnjcdvbDdIFq7sLxKU/ZeH1S4DdFzIeIMhzEioXDfk0rZ0pLmrUUa3
         qONw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=/aVLEAIiIUq96sEpteKq4xn0CYp2Pr/HhvYRjdNe/U0=;
        fh=Em3yvq2zMsfyYtekL77bXM163wy++1f+rgqYXqx5CqE=;
        b=NzVxUvL5qloTzBj7XNQ61z26JvBxMehTA0A2ejuRiD9O6ydIf8x+62zRg+nO9x1JMS
         QsPHK9ghqykBtyxgrCmh9bpeZulePwjzMUPvjA7UrIvkfJzH7qs9sE81l0616K0RM6Dm
         X63HMECX4qyaNTlsr96NfsicM4nae5/jd+qFetPSZUirvceauhNJYkb/hvWxZBEoKWeP
         zDSKKd3MHq9sVQf3YAY3Q1RgnjN3w6v2P5zxdMvif+sAJggVKLCeNGF64MbbSoVh2XeM
         HfIBWvqsKR+SfY7T2D/Mtw3j/yJC9xHYwPQSsKw64q9bbcD8jyRa5DtRAz+uVMFQkyyP
         bXFQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XqHxW8YW;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-435ce755d81si235848b6e.1.2025.08.14.06.31.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 06:31:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 766E96111F;
	Thu, 14 Aug 2025 13:31:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 02E81C4CEF1;
	Thu, 14 Aug 2025 13:31:11 +0000 (UTC)
Date: Thu, 14 Aug 2025 16:31:06 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, Keith Busch <kbusch@kernel.org>,
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
Subject: Re: [PATCH v1 08/16] kmsan: convert kmsan_handle_dma to use physical
 addresses
Message-ID: <20250814133106.GE310013@unreal>
References: <cover.1754292567.git.leon@kernel.org>
 <5b40377b621e49ff4107fa10646c828ccc94e53e.1754292567.git.leon@kernel.org>
 <20250807122115.GH184255@nvidia.com>
 <20250813150718.GB310013@unreal>
 <20250814121316.GC699432@nvidia.com>
 <20250814123506.GD310013@unreal>
 <20250814124448.GE699432@nvidia.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250814124448.GE699432@nvidia.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XqHxW8YW;       spf=pass
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

On Thu, Aug 14, 2025 at 09:44:48AM -0300, Jason Gunthorpe wrote:
> On Thu, Aug 14, 2025 at 03:35:06PM +0300, Leon Romanovsky wrote:
> > > Then check attrs here, not pfn_valid.
> > 
> > attrs are not available in kmsan_handle_dma(). I can add it if you prefer.
> 
> That makes more sense to the overall design. The comments I gave
> before were driving at a promise to never try to touch a struct page
> for ATTR_MMIO and think this should be comphrensive to never touching
> a struct page even if pfnvalid.
> 
> > > > So let's keep this patch as is.
> > > 
> > > Still need to fix the remarks you clipped, do not check PageHighMem
> > > just call kmap_local_pfn(). All thie PageHighMem stuff is new to this
> > > patch and should not be here, it is the wrong way to use highmem.
> > 
> > Sure, thanks
> 
> I am wondering if there is some reason it was written like this in the
> first place. Maybe we can't even do kmap here.. So perhaps if there is
> not a strong reason to change it just continue to check pagehighmem
> and fail.
> 
> if (!(attrs & ATTR_MMIO) && PageHighMem(phys_to_page(phys)))
>    return;

Does this version good enough? There is no need to call to
kmap_local_pfn() if we prevent PageHighMem pages.

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index eab7912a3bf0..d9cf70f4159c 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -337,13 +337,13 @@ static void kmsan_handle_dma_page(const void *addr, size_t size,

 /* Helper function to handle DMA data transfers. */
 void kmsan_handle_dma(phys_addr_t phys, size_t size,
-                     enum dma_data_direction dir)
+                     enum dma_data_direction dir, unsigned long attrs)
 {
        u64 page_offset, to_go, addr;
        struct page *page;
        void *kaddr;

-       if (!pfn_valid(PHYS_PFN(phys)))
+       if ((attrs & ATTR_MMIO) || PageHighMem(phys_to_page(phys)))
                return;

        page = phys_to_page(phys);
@@ -357,19 +357,12 @@ void kmsan_handle_dma(phys_addr_t phys, size_t size,
        while (size > 0) {
                to_go = min(PAGE_SIZE - page_offset, (u64)size);

-               if (PageHighMem(page))
-                       /* Handle highmem pages using kmap */
-                       kaddr = kmap_local_page(page);
-               else
-                       /* Lowmem pages can be accessed directly */
-                       kaddr = page_address(page);
+               /* Lowmem pages can be accessed directly */
+               kaddr = page_address(page);

                addr = (u64)kaddr + page_offset;
                kmsan_handle_dma_page((void *)addr, to_go, dir);

-               if (PageHighMem(page))
-                       kunmap_local(page);
-
                phys += to_go;
                size -= to_go;

(END)


> 
> Jason
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250814133106.GE310013%40unreal.
