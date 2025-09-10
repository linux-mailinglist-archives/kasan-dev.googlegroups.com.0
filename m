Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBAMYQTDAMGQEUG7CCCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 4358BB50D2B
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:26:27 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4b60d5eca3asf86008861cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:26:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757481986; cv=pass;
        d=google.com; s=arc-20240605;
        b=aeNxDplQD5vjY5mTvYLdZiNnVRrPZVlOelHwIQM8jB71SNgdZ94ZJXsDxsTIEnT8WN
         Mv+fQ8/uVCoy3E+Rotu3hs9QD8IxULuZ1cmvaBZyHLggFGdDUkgx+UHdlZIMPadJ9HKx
         YwbYXa3I19jFQY8NHhCRse7dQaT0rs0TETeqrn3HTJ81Ws2MoJJ/uvO6JBSiU1Rsdb24
         GFe55rPXVktBaqbfG+rnkdwkTof5LP+7linEjPL9vNNdBUoPAft0kgDUbvJBqnh7kqEH
         Ly8hlHclhfU8MrULoS8JL9U+4Y7L7ChgVl6yLWnFrSDnEDdj3P2SxYVdKmM8OH+Zd5fG
         k19Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Di6r5RxR7Lldvq4H1oM5xlXLaiEJw64toeaxbGL0u6M=;
        fh=8aMjlmBN3MGijelzWHLc0IpzahsZ18cRg8fTjdV9yKA=;
        b=bdoAOJKWRRhwJpl6QUbKUcX8C0R/1pRusqxSoL/gtltk1/cYV0hwmaEW7AE4GetzJ7
         Y2ECJ8zXHmuEEcf+I53zb/8Hz/k8Ic9wABV6Vs10ih9v6XlREhwoC0kvaQFkJ2IO+Bvx
         FaC7Iacxothk9bJ15LFypsOmhq7R/Og483lYPb3wzGuT3HidDaN1oRU0zimYyGErhqBG
         tLkvJA/LGF+4GZp+G3HOTo2xN05Dni3Wdn9m81gITI8gse3apB+Skd7kK2NxXPunBXai
         Dosc/19j00Pg1TMhRqvNAMc4wFsHbkj6loZPt2tVlVDK9/r3YNR0bz0aKKBSyOYYFaFs
         nO2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=W3++ctIi;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757481986; x=1758086786; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Di6r5RxR7Lldvq4H1oM5xlXLaiEJw64toeaxbGL0u6M=;
        b=OI8jlLVP/OIC+w+lAFEW17JfJBKW5ZeNELvxTXuC6TsmPwrLx1xQFSYUhzwJkvtoJu
         V2r2EfZd66MXX31onG4GrzLpDGgl/n2VqtJ07aANMvxwz8DaRYemC5OrosA4LIzlJD1+
         03IRwi038wgiiEbMqjr14M3+63nzwGuzCxs4Tw2xpHC14cRz2aSuQAzV0CMMMq/9ZWJG
         7jMyblurHmZB+AT+WWPAB6pUkTHtq5QC+qxpfUAdBWcSVJIysJRv5ZnqrCrLxkqgR12I
         7QXFlCUfBtNlW8f3y2SNSkaLa5gKBeiTbcQMYTiCyL44psFaqG8KXxfOQf7hahOBcE7f
         XQ/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757481986; x=1758086786;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Di6r5RxR7Lldvq4H1oM5xlXLaiEJw64toeaxbGL0u6M=;
        b=fUXtzc+CnVOzRaZp6kIVYNvMcAUFwPeVT8mxUk1Q4D/FbSDYx9Y2dYqE3tKBj2l5ds
         3UsdH/Bd287XItFjGe+akz08diEq/EdpUlti9hpGFzI9xBcQ7UlxyWKb/MTXaz7dz0sd
         rrRVZMdL8LPppHmpTO1UroNDouM+FyJH3fy/tXIJ6ri6UZ+Zrmr5RF1jVj0JHxvoW5ca
         4yuv5qCzNU81jgGpNrSNw3TU85Kyu69aXhcHfQYS1SBWdyHIIXbx7WfEU1PrYj+c+bQQ
         +EGJ9I6ypHkD8DRQJ7jFXcNmge1gMh943jcN1KeJPsMWcbeMUW4U54+rnTadOWvoiBCp
         Akug==
X-Forwarded-Encrypted: i=2; AJvYcCVR97L2Iu1SPREQbgKI40OwB5iwjkixdwg927J+qadEh29P+cUDH17zqhO5asUX2V3YSXWJ6A==@lfdr.de
X-Gm-Message-State: AOJu0Yw7V0v/hYuLqfaCTAYqjSofPtFzEOlOXempQxwvq61ZLvRWopIO
	SQfeUMocnlzdoHYX8AHSJIJ4EFA9jlB/cj9SKOuJX65lLE/jS4IOM2KK
X-Google-Smtp-Source: AGHT+IGDtj82/TR9N/yek5zciOzY0srl11y705dNz6H7jQT+XFTn8XZejdISa9VwjtOSapxushRP7w==
X-Received: by 2002:a05:622a:164a:b0:4b4:8f35:c902 with SMTP id d75a77b69052e-4b5f8386268mr153366581cf.4.1757481986013;
        Tue, 09 Sep 2025 22:26:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6QarylVFONLdpv9AZgivd+bld7Ug2j49jPHivs5d4vOA==
Received: by 2002:a05:6214:21ef:b0:70d:b7b1:9efb with SMTP id
 6a1803df08f44-72d3934765als78815286d6.1.-pod-prod-07-us; Tue, 09 Sep 2025
 22:26:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXi55ESr4p0KR+h+d/a0fxGfWgmTCuuGgbASvnngcthLsk+Va0YmtEMsx3jsxJS33qlYYCdg0Klt3o=@googlegroups.com
X-Received: by 2002:a05:620a:1918:b0:7e2:3a27:a120 with SMTP id af79cd13be357-813c235f189mr1721319385a.54.1757481984663;
        Tue, 09 Sep 2025 22:26:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757481984; cv=none;
        d=google.com; s=arc-20240605;
        b=A9PhMsLhl3Yf9XAeiUbacbQ96wI3nL4NFdRI9RXCVmtAxHahgLjtYFgJv9XoxsjydO
         tZ5SP+6sxANlD0O3RI/abvuZnhyRF5cJVG+w4JcmfhvACTqO46LdIkBuDOemR00Vf4Z0
         peILypj5FMwLoRZhFyo1ffqQw/aQuMhjzo/kGWjrxHeHOIJ2ZIxN+uhcaMeqg9PhcqxI
         glu0yEzUEOYwCoOV4u+8PonEMq3Uf1ThIrh/VEZwZ9DL+HZRweORfJdJbpPicBWslpiY
         TutcpYjwcLiZbMPLYIbffBxjsoA4UN5s9lpTAdIjzsVF1POrHTaZcOyOFbhblPLL31sa
         dxTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=nCgLh808zcItteVMXL9jaLEwx6dqzX8VyNuK8FSQYGc=;
        fh=0KZfjkVFrBJ1A8P/k5PTY2PAUr+/l0FquzWeYmXM7tg=;
        b=K9y+zFz+kMZgCapknEUqVrO3SBLR/D16VdwuyjTGTWlJFS9V3CVGXwRAgiAW3A1wSf
         pn7AmME7gCQl/+JrtTfjCmjeFoeI/Qo/b5jSCy+hdqYTvaehEnCbcsWYZbhJ8AITKttm
         xY/fTWp0x0qCXOxe4hk3v6jCtqoqA6STnrXUR+QoalBLXYLtFnqnzLugn7nm2uoDHvft
         r8BWbnrhHwFpK+6NwB7CTVOnUcWSB5cIuKX6uNYOXsXHrkvGbvDkL9d/l6aj5H7Gfcno
         lZgbBWL2qZINk0gaeCnvFQVScv2aTVjywEUjltbVPn8Bc6xJkNOrR2Ghbp9V9lyU6M8/
         Jb6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=W3++ctIi;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-720b23a4713si7457226d6.5.2025.09.09.22.26.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:26:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id AFB3041752;
	Wed, 10 Sep 2025 05:26:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DF34CC4CEF0;
	Wed, 10 Sep 2025 05:26:22 +0000 (UTC)
Date: Wed, 10 Sep 2025 08:26:18 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Jason Gunthorpe <jgg@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	David Hildenbrand <david@redhat.com>, iommu@lists.linux.dev,
	Jason Wang <jasowang@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joerg Roedel <joro@8bytes.org>, Jonathan Corbet <corbet@lwn.net>,
	Juergen Gross <jgross@suse.com>, kasan-dev@googlegroups.com,
	Keith Busch <kbusch@kernel.org>, linux-block@vger.kernel.org,
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
Subject: Re: [PATCH v6 03/16] dma-debug: refactor to use physical addresses
 for page mapping
Message-ID: <20250910052618.GH341237@unreal>
References: <cover.1757423202.git.leonro@nvidia.com>
 <56d1a6769b68dfcbf8b26a75a7329aeb8e3c3b6a.1757423202.git.leonro@nvidia.com>
 <20250909193748.GG341237@unreal>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250909193748.GG341237@unreal>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=W3++ctIi;       spf=pass
 (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass
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

On Tue, Sep 09, 2025 at 10:37:48PM +0300, Leon Romanovsky wrote:
> On Tue, Sep 09, 2025 at 04:27:31PM +0300, Leon Romanovsky wrote:
> > From: Leon Romanovsky <leonro@nvidia.com>
> 
> <...>
> 
> >  include/linux/page-flags.h         |  1 +
> 
> <...>
> 
> > --- a/include/linux/page-flags.h
> > +++ b/include/linux/page-flags.h
> > @@ -614,6 +614,7 @@ FOLIO_FLAG(dropbehind, FOLIO_HEAD_PAGE)
> >   * available at this point.
> >   */
> >  #define PageHighMem(__p) is_highmem_idx(page_zonenum(__p))
> > +#define PhysHighMem(__p) (PageHighMem(phys_to_page(__p)))
> 
> This was a not so great idea to add PhysHighMem() because of "else"
> below which unfolds to maze of macros and automatically generated
> functions with "static inline int Page##uname ..." signature.
> 
> >  #define folio_test_highmem(__f)	is_highmem_idx(folio_zonenum(__f))
> >  #else
> >  PAGEFLAG_FALSE(HighMem, highmem)

After sleeping over it, the following hunk will help:

diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
index dfbc4ba86bba2..2a1f346178024 100644
--- a/include/linux/page-flags.h
+++ b/include/linux/page-flags.h
@@ -614,11 +614,11 @@ FOLIO_FLAG(dropbehind, FOLIO_HEAD_PAGE)
  * available at this point.
  */
 #define PageHighMem(__p) is_highmem_idx(page_zonenum(__p))
-#define PhysHighMem(__p) (PageHighMem(phys_to_page(__p)))
 #define folio_test_highmem(__f)        is_highmem_idx(folio_zonenum(__f))
 #else
 PAGEFLAG_FALSE(HighMem, highmem)
 #endif
+#define PhysHighMem(__p) (PageHighMem(phys_to_page(__p)))

 /* Does kmap_local_folio() only allow access to one page of the folio? */
 #ifdef CONFIG_DEBUG_KMAP_LOCAL_FORCE_MAP


> 
> Thanks
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910052618.GH341237%40unreal.
