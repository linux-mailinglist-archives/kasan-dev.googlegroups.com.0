Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB6PR3LCQMGQE2OQT7PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DC78B3FA59
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 11:29:31 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-30cce50fe7dsf1934278fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 02:29:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756805369; cv=pass;
        d=google.com; s=arc-20240605;
        b=blufMwH04rZ2IIwDhB6So/QyaGTld681VTJJJw6iST2a+mCQRKJoSpfeOEUDsEpv/v
         PUfUAEnbzsLT6rlooBDpMvbpT3WkcgHFcOUE5PaOEwfb4BelNQ4Bsq/Qf+sG9ztPP/xl
         S+MsjDhDDRwGE2LOPGpL4tw1jfttf0cQdvCSMajFnqHcNayMIwRiqwDENTMuHvIMVWGX
         aQVZoB488u97elBkQ5pWE8PntuVyZpOb56uHa3HUrzZRMarjbT4xjE19e8bUaiXG3Ikj
         IEnMQNiESPtSBxkb6+3xku0AzH3432Q5Ajx+GGLnhbBCV7qjc9cXMS7nwSEGgmlQXYYD
         w7xQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=V4dEaLMLmm1p9ijlD5Xyj8Jfp+ATk0FyHEa5k2D47RU=;
        fh=HLma4/YKVcS8GDa7baymbMHpxNq2w75QZccqJMsTNWM=;
        b=feH9KM+mc77eKImgRXDYBq3dTWN8FjS8J7Xbtas1jDglpJRrOa887G00jKV49qKt8T
         1XEa5T27IhSGUN55xmj41XTdPgApMLhUMJz5xXGrk/H04rR1JGz2oHL+Npq8/HD1TJlX
         0AA4O3OZeD004ar1yI1W6uS2kWVhmEOo7MEeYJwcNN/rZAUvpx4f9OvV6UWGK6Bwonwo
         YaLZ/lTlJ3yWUtZohIwhxUJWSpQwJW1j/gB91IYKQ/da4f1YCgrpxhsOQVvIoihHudJd
         UYPWcrGjUBDSFhCNYoIOCk173XFkcu3SSlGslPsc7jGZXIGlKq9ePioZB91qA1eDZIpg
         d6lg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=u+YP0LKc;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756805369; x=1757410169; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=V4dEaLMLmm1p9ijlD5Xyj8Jfp+ATk0FyHEa5k2D47RU=;
        b=DiehTHMaCsYc9ZJoQV27VXnS3iuryvbldy3BiZUTayUq0qlDtqyWbmtJPzE6skkbMb
         widavoA7k4HlaYTFhBTpQfbJtTmS13nw0PRmPSmvjiF/MDgdEK95wmdFOv3e9x5LfMQD
         YA3byA07Az/FEda2nTR68YdG0jT6VzQgj7D/TxPgrmNejGhSmKSTunCR+F+Giq3figiA
         zWDfs/Taea8yKmo/MYh4zYV+8rBaFgV3ldi7wGcM7D8qAvla3qlvLUD1DX8QynEO3eAW
         OXkhxoV+jREMODXKh1bu/kQfFLIurW0H6IoLBzwTPzQnmrPINlyBmkU/ZiMTnArNKMax
         tkWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756805369; x=1757410169;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=V4dEaLMLmm1p9ijlD5Xyj8Jfp+ATk0FyHEa5k2D47RU=;
        b=UrSyuYyeJdtBbYwJaP8WrGs9PuAjbiDweSDWHEw4EeE0GNSvVqC7v+g1bwmLKvGrU1
         ffa5tjt4h27pRq9lhEegtjNu3Yx5Ltq2d2H2Ib46DUmkakzeZIxFzsA9n1J6eMKqbfDU
         MfEejKFrrGab+OIWOHE1vSkNBY3eS4z52Uu1c3EHIg87xJMf+r4t39GaxJpf779HJGZU
         J/OJAFToOLKKja45+TZedPoYgbN0bD2Tq4EFVJ2G/jaMLDxfSr2q9+ZlkaWsQT5M4pCl
         ETbHtDm8FCHxtMiJLY+OfVML/bNNFjChBX7kC0ZmDdRItPsFicpllu3iWDrSy9irvaDF
         MsUQ==
X-Forwarded-Encrypted: i=2; AJvYcCVtSog9NKYSdHtTZvdqBwZ1r1sRcsNnCy0fZaMm8pnRkzTM7Elpz39++MWiE4WBdgYZ5b0RDA==@lfdr.de
X-Gm-Message-State: AOJu0YxEiuoQZECunncOcXz89CdmGu7IqjZatLNENlGOC8Bp4XO42QgX
	mNqJ4vLZIL0n0Uu93c8tVHZX0KF4itYdkVo43SMREiBJnWnJtSkYCoEn
X-Google-Smtp-Source: AGHT+IESKCoFGfriSVtP21ZIvlVAJkg92+kBXKbNjMi4uHFx2iMIrx4bfAP+YIpwhWdOL96pTjyHpg==
X-Received: by 2002:a05:6870:e40d:b0:315:c0bc:4bb8 with SMTP id 586e51a60fabf-3196307efd6mr5528538fac.2.1756805369398;
        Tue, 02 Sep 2025 02:29:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeYkrEhMmOofOtd3fI4cyAWPu4rmfTpp2DBxzE2ayWvVA==
Received: by 2002:a05:6870:d2ca:b0:319:bdd4:d1c3 with SMTP id
 586e51a60fabf-319bdd4d38fls161683fac.2.-pod-prod-06-us; Tue, 02 Sep 2025
 02:29:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW2/hhLLySWkApvwuv2IyY2lNsFlWOQKQqrRn0xjXOo7wU3RC8P5wk3FcUMZQFfNR1fvo2sD2rA5uQ=@googlegroups.com
X-Received: by 2002:a05:6808:8219:b0:434:97b:5eb9 with SMTP id 5614622812f47-437f7d74afbmr4270283b6e.28.1756805368371;
        Tue, 02 Sep 2025 02:29:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756805368; cv=none;
        d=google.com; s=arc-20240605;
        b=LuGN/Q/XWm8us2K6aIu8SiLVXPqTyR9rQNQv6jc8+eQzBzUbXMS/fEI7CsM63DXs/l
         wEhTJ3sHs3c5XNGpxF6kVk91CREJA4fGxbTVio8PZsEEmP3Qk2svHjhDzNu9zE23m1P2
         tf/RXNqON9dOT8ZcSFXJ51vHpFx0i4w9yKQWBqZa9P4oGTK9CYnF5DZzZIosRezgF9DC
         ruTD41DygExQIk3r7s0/Lvni1vjgBT2NHRYAQw0YtEWdjyuCbJ0Icmyd9jE3FQFWriOL
         ACb3/cFkIMFsp1rAtrCxrbyIclBGq0TnEA15j3qEFt0KYpyhMQ7IlHm/5CH7Ixa+5gpL
         mwrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=RUP9TtL1xAhoFb9CaSEK22nm8Sa8vb9894tliSqEP4U=;
        fh=Qbhj/Lb0zMeSZJx28wGbbfuSxMTYtwB8DLS29eHDHp8=;
        b=Ic7fus95sk+QhkVqwwPchJ1AQndPpfgsTc6v2KmaQlFuwyvWYHSl+9fFXxhDM3Clt/
         Vp+ssR3Xa+AlE0Y2uNhXV11Ad9oxZLRnIiOJDYzrSnu772oUMaWUpl53FvUP3OmKQV6H
         qenfOcFURtyobDXPrd/6rSBTHhogi2e0upX07WyxbYeKkSAwaK+6afQGIEaUxa4nYt15
         VINFlInWFO3e37QZxKWFilUGwDUHvhShRpba6l8l5bQBm4Qs8ZOPu5eC2q/TsAdL1tfS
         AwNxuu+Vu1qMNQMuhUhtiBEcG+28Mpip+M8bGsWLyk0hzg8dK9fRxqSI9JjL+tP8A49l
         FI1g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=u+YP0LKc;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-4380007f816si192286b6e.5.2025.09.02.02.29.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 02:29:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6678F43E7E;
	Tue,  2 Sep 2025 09:29:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 793FEC4CEED;
	Tue,  2 Sep 2025 09:29:26 +0000 (UTC)
Date: Tue, 2 Sep 2025 12:29:20 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Abdiel Janulgue <abdiel.janulgue@gmail.com>,
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
Subject: Re: [PATCH v4 00/16] dma-mapping: migrate to physical address-based
 API
Message-ID: <20250902092920.GE10073@unreal>
References: <cover.1755624249.git.leon@kernel.org>
 <CGME20250828115738eucas1p24f3c17326b318c95a5569a2c9651ff92@eucas1p2.samsung.com>
 <20250828115729.GA10073@unreal>
 <26bd901a-0812-492d-9736-4a7bb2e6d6b4@samsung.com>
 <20250901222302.GA186519@nvidia.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20250901222302.GA186519@nvidia.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=u+YP0LKc;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted
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

On Mon, Sep 01, 2025 at 07:23:02PM -0300, Jason Gunthorpe wrote:
> On Mon, Sep 01, 2025 at 11:47:59PM +0200, Marek Szyprowski wrote:
> > I would like to=C2=A0give those patches a try in linux-next, but in mea=
ntime=20
> > I tested it on my test farm and found a regression in dma_map_resource(=
)=20
> > handling. Namely the dma_map_resource() is no longer possible with size=
=20
> > not aligned to kmalloc()'ed buffer, as dma_direct_map_phys() calls=20
> > dma_kmalloc_needs_bounce(),
>=20
> Hmm, it's this bit:
>=20
> 	capable =3D dma_capable(dev, dma_addr, size, !(attrs & DMA_ATTR_MMIO));
> 	if (unlikely(!capable) || dma_kmalloc_needs_bounce(dev, size, dir)) {
> 		if (is_swiotlb_active(dev) && !(attrs & DMA_ATTR_MMIO))
> 			return swiotlb_map(dev, phys, size, dir, attrs);
>=20
> 		goto err_overflow;
> 	}
>=20
> We shouldn't be checking dma_kmalloc_needs_bounce() on mmio as there
> is no cache flushing so the "dma safe alignment" for non-coherent DMA
> does not apply.
>=20
> Like you say looks good to me, and more of the surrouding code can be
> pulled in too, no sense in repeating the boolean logic:
>=20
> 	if (attrs & DMA_ATTR_MMIO) {
> 		dma_addr =3D phys;
> 		if (unlikely(!dma_capable(dev, dma_addr, size, false)))
> 			goto err_overflow;
> 	} else {
> 		dma_addr =3D phys_to_dma(dev, phys);
> 		if (unlikely(!dma_capable(dev, dma_addr, size, true)) ||

I tried to reuse same code as much as possible :(

> 		    dma_kmalloc_needs_bounce(dev, size, dir)) {
> 			if (is_swiotlb_active(dev))
> 				return swiotlb_map(dev, phys, size, dir, attrs);
>=20
> 			goto err_overflow;
> 		}
> 		if (!dev_is_dma_coherent(dev) &&
> 		    !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
> 			arch_sync_dma_for_device(phys, size, dir);
> 	}

Like Jason wrote, but in diff format:

diff --git a/kernel/dma/direct.h b/kernel/dma/direct.h
index 92dbadcd3b2f..3f4792910604 100644
--- a/kernel/dma/direct.h
+++ b/kernel/dma/direct.h
@@ -85,7 +85,6 @@ static inline dma_addr_t dma_direct_map_phys(struct devic=
e *dev,
                unsigned long attrs)
 {
        dma_addr_t dma_addr;
-       bool capable;

        if (is_swiotlb_force_bounce(dev)) {
                if (attrs & DMA_ATTR_MMIO)
@@ -94,17 +93,19 @@ static inline dma_addr_t dma_direct_map_phys(struct dev=
ice *dev,
                return swiotlb_map(dev, phys, size, dir, attrs);
        }

-       if (attrs & DMA_ATTR_MMIO)
+       if (attrs & DMA_ATTR_MMIO) {
                dma_addr =3D phys;
-       else
+               if (unlikely(dma_capable(dev, dma_addr, size, false)))
+                       goto err_overflow;
+       } else {
                dma_addr =3D phys_to_dma(dev, phys);
+               if (unlikely(!dma_capable(dev, dma_addr, size, true)) ||
+                   dma_kmalloc_needs_bounce(dev, size, dir)) {
+                       if (is_swiotlb_active(dev))
+                               return swiotlb_map(dev, phys, size, dir, at=
trs);

-       capable =3D dma_capable(dev, dma_addr, size, !(attrs & DMA_ATTR_MMI=
O));
-       if (unlikely(!capable) || dma_kmalloc_needs_bounce(dev, size, dir))=
 {
-               if (is_swiotlb_active(dev) && !(attrs & DMA_ATTR_MMIO))
-                       return swiotlb_map(dev, phys, size, dir, attrs);
-
-               goto err_overflow;
+                       goto err_overflow;
+               }
        }

        if (!dev_is_dma_coherent(dev) &&


I created new tag with fixed code.
https://git.kernel.org/pub/scm/linux/kernel/git/leon/linux-rdma.git/tag/?h=
=3Ddma-phys-Sep-2

Thanks

>=20
> Jason

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250902092920.GE10073%40unreal.
