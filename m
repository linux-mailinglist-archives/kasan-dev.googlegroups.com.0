Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBKGRT3DAMGQEQ26LA3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D46EB56FC9
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 07:48:27 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-24457f59889sf39931385ad.0
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Sep 2025 22:48:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757915305; cv=pass;
        d=google.com; s=arc-20240605;
        b=EJr9Z6+VnKoQLSkIaMWNl/+iIFWNmvpHRP1oeSWTp2LjVdm5NI658/DqlKjQ27JqgW
         xJKv1a/LikJq+a8oZPE1fU31dZ3gwuR7nV4W+/H0iA2TF3AiaIJNFmxJ6P/jQGx/XNIC
         uaMPpM/8DYbK5lJkByDqL19Fu3AryJVIGJNbH43tieYCkIPkQkyRbjK/INM40pKGLLIz
         S6NQz3dJNELdOID62oV2rifi5WOth35XG7pHW4OzmRdXaCJlFo/Qkb5GqM1wE9WA9vxW
         +3GUowyCvj3GlYLUOkV4TKj+w9nVGYgWdx/P451d7/Vaz3pnRUo4gBpqyojTz9HHJbn4
         rTRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=DmPrGnpdnkZh1xivPY4SW5R6dYaNFBsgR+M9DBeW9Ek=;
        fh=fVZHtAd0rvu18ur3JaCPHsoRS8L61L98+yhl7HEbBSc=;
        b=OeRo7jus1jUWEt32Ac8rywRVy30rl2HYdr63o3Ac2gByZ9JP1oDzE8p9JijLcXD77b
         rySY2jx3htFDAEXABGPb1qg5ochxns55hPqk3suhzTlgoayddIyc4I6mQ8CrXLNnwHh0
         5R2z2Es5gzzn3Ul5n2N1ZVO9+PCP98UuWKiNhysSFGJz377N1BnssSXMjijDkm2Ajys6
         tZgNfrGMX5SMJwaLZJXnzoZeoHPR9L6Kr6JY2x85ggrjq/cAxBWZRwisi4QWvemdZTlh
         R4f7Z5GE/e460uftHhhQ83tIAeE0bUd3FI8wlIiXboz/IxcSSRSuU1RXA51kFX6KNizv
         AgWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LY4R44OP;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757915305; x=1758520105; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=DmPrGnpdnkZh1xivPY4SW5R6dYaNFBsgR+M9DBeW9Ek=;
        b=Xj0a5/97r+C91XzoQCBYG0ciRbK476nnipXk9NJFz0bNqnQRRt6BuMZFJfxrQg/UdZ
         711OvjkWMGdujEcEOMscXUJ8/mAbBoKrOVpPrKWg9kHSx9aU3nv6FwoAJxjqPrM/dzvi
         KfCQi1pc4u5gWwSBiaQ8YljTQs+9jVlCw52Xe15HR30cgzMzrUJhSU0MUngQ87lsm50x
         uTFS5c5DI51nPTBXZ0rVfaa9gwl8fP8/p7xM8AtTPxpm39CWOvIqG1xQAbJtl/nJpeT/
         gt90k7qeNI9okshSODllvrITBrHkPhvh54Qeo3mR0BTrSka1otfg7YJccfahObDV8it2
         b4Ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757915305; x=1758520105;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DmPrGnpdnkZh1xivPY4SW5R6dYaNFBsgR+M9DBeW9Ek=;
        b=L0s+drn90K+6ONSx0A0aBErJcajlCSNStpqjBJGz9/BwpW/zv2T7FQRIS05v1z8CXL
         oIUpDmurA3w0YjmclsmvImvOgGQyV74+gkHNKT3kDgaW7olFhaOb3TOaw4M03dxFvQHg
         vaHUC4iyvp8UmbRM44Or+X/hzFlQbXvLGA1ih/a7H3n4Lv5kyFEkaSeuYpwHPlq2kUUC
         2gSsj0C0CRTzGzCRvkxiVY7CZMFkqWVHLXgRxrCmKqxG/bLSTB7pMp2PZzx7xvWmUu+F
         fWVjBD+6YtJepbGj0UDVqD0wtDtYa+1/cS0lMsxawsVuLCzESvyPRM0oJERZRq4VGJzM
         Jlkg==
X-Forwarded-Encrypted: i=2; AJvYcCXa0jaWbqdwcEQy7FS8GYxkd04qcRFcsBbH19nXYT8hT8ZoisQdI7MtpLeDHlkJXwdiiSeDQg==@lfdr.de
X-Gm-Message-State: AOJu0YwW82RLP9OTJ1Dw0LJhCFjVnZzQvKYmAyMeHqXA12FQkscHWfQM
	xyzDo8HnpgubNkLqzLQy4OMcKbgfEyq8hxmBB8+P6qdOgO3GkQq2eFMH
X-Google-Smtp-Source: AGHT+IE9fngXhb9p7QCnZhDBEI5PwC+KSKzRzHSyfxMiFZkqQXkB6FlSlsBc5Men59KmReeRwWVw9A==
X-Received: by 2002:a17:902:d2c8:b0:266:2e6b:f592 with SMTP id d9443c01a7336-2662e6bf791mr28835065ad.25.1757915305191;
        Sun, 14 Sep 2025 22:48:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5SLFlk4qYxJMDgbroCKIftchaEOLjOjUsa5tTgSzweng==
Received: by 2002:a17:902:d50d:b0:246:570:cbdd with SMTP id
 d9443c01a7336-25beddd8445ls41187445ad.2.-pod-prod-02-us; Sun, 14 Sep 2025
 22:48:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUG44B6yMa8sMm5z23/IvCjUaGSEI/3TfBCypacJpHNUrYMlw0Puk6sxuCYXwNB5WytZuCNfAwkFtU=@googlegroups.com
X-Received: by 2002:a17:902:ec8e:b0:25d:d848:1cca with SMTP id d9443c01a7336-25dd8481fbdmr141944535ad.35.1757915303436;
        Sun, 14 Sep 2025 22:48:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757915303; cv=none;
        d=google.com; s=arc-20240605;
        b=UzPVhFrCZpDEyfpUKubuIQWH8FSH6mSzqGk5xNyrj0DiVQrSXptChXETUOr+C50uo5
         95jpJpntEOD4JyzltQEpjEZaw0c78kdxmINm7Pa1TehTzNRF8kn3gQOCHzNNEWHQ6BJs
         7hDyO047QcAwsUu7BcR/xNN1q/S5pY66ijarDpYrfQbvzPruW2hSkPstPCs5KK1uvz6j
         45ie5yrMr51sr//OHeTZt/0dAxo7j00TlFkMH5K08QEyR3r8Qn2KznquRg522NT+oM8p
         BZxsx7IHMm6DRCfqAzLRvJzneolKyZjqw0xg0NEcmsfKmVC0986O85hJ9ayJno0lUEB0
         GZ8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JXL3zMOfk7HJmj1hH5tcjC1ukwS1rzTdhMLd/yhlMo8=;
        fh=0KZfjkVFrBJ1A8P/k5PTY2PAUr+/l0FquzWeYmXM7tg=;
        b=MDR9wjhumHVhc8LbaRLtpx7nPpSQx8J3qk31nLJ1gvWpRlAG60iYI7DLxKi+tPa7nH
         7HbYIo7h0aZkOA8V8aVS1eiz+imr25IWrfpxImWKPmr4jHlRYwDbbF9xERvql22WvNrN
         J0L0P8VFgQIpN0Arafs6UE36xsovP30pNK85sBLAkY1ChdfuFYXX1nKShkCyTSEnPz+R
         TUAyIJ6ivfFCZhbjs6DHxd+wY2cY1WrURvWOfzxOHA5fb2nb4qwAzIUcgM16N2L6eyJB
         uhwD5W3LGdtaZkB7wOuTkCkmhg4Zgp12EF93Xw+FHTFi2pWlFzE4ZSWqCTpkkvvm/7lY
         V8iw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LY4R44OP;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-25f31869f46si2207695ad.5.2025.09.14.22.48.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 14 Sep 2025 22:48:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 05E2143F68;
	Mon, 15 Sep 2025 05:48:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E1FCDC4CEF1;
	Mon, 15 Sep 2025 05:48:21 +0000 (UTC)
Date: Fri, 12 Sep 2025 12:03:27 +0300
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
Subject: Re: [PATCH v6 00/16] dma-mapping: migrate to physical address-based
 API
Message-ID: <20250912090327.GU341237@unreal>
References: <CGME20250909132821eucas1p1051ce9e0270ddbf520e105c913fa8db6@eucas1p1.samsung.com>
 <cover.1757423202.git.leonro@nvidia.com>
 <0db9bce5-40df-4cf5-85ab-f032c67d5c71@samsung.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0db9bce5-40df-4cf5-85ab-f032c67d5c71@samsung.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LY4R44OP;       spf=pass
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

On Fri, Sep 12, 2025 at 12:25:38AM +0200, Marek Szyprowski wrote:
> On 09.09.2025 15:27, Leon Romanovsky wrote:
> > From: Leon Romanovsky <leonro@nvidia.com>
> >
> > Changelog:
> > v6:
> >   * Based on "dma-debug: don't enforce dma mapping check on noncoherent
> >     allocations" patch.
> >   * Removed some unused variables from kmsan conversion.
> >   * Fixed missed ! in dma check.
> > v5: https://lore.kernel.org/all/cover.1756822782.git.leon@kernel.org
> >   * Added Jason's and Keith's Reviewed-by tags
> >   * Fixed DMA_ATTR_MMIO check in dma_direct_map_phys
> >   * Jason's cleanup suggestions
> > v4: https://lore.kernel.org/all/cover.1755624249.git.leon@kernel.org/
> >   * Fixed kbuild error with mismatch in kmsan function declaration due to
> >     rebase error.
> > v3: https://lore.kernel.org/all/cover.1755193625.git.leon@kernel.org
> >   * Fixed typo in "cacheable" word
> >   * Simplified kmsan patch a lot to be simple argument refactoring
> > v2: https://lore.kernel.org/all/cover.1755153054.git.leon@kernel.org
> >   * Used commit messages and cover letter from Jason
> >   * Moved setting IOMMU_MMIO flag to dma_info_to_prot function
> >   * Micro-optimized the code
> >   * Rebased code on v6.17-rc1
> > v1: https://lore.kernel.org/all/cover.1754292567.git.leon@kernel.org
> >   * Added new DMA_ATTR_MMIO attribute to indicate
> >     PCI_P2PDMA_MAP_THRU_HOST_BRIDGE path.
> >   * Rewrote dma_map_* functions to use thus new attribute
> > v0: https://lore.kernel.org/all/cover.1750854543.git.leon@kernel.org/
> > ------------------------------------------------------------------------
> >
> > This series refactors the DMA mapping to use physical addresses
> > as the primary interface instead of page+offset parameters. This
> > change aligns the DMA API with the underlying hardware reality where
> > DMA operations work with physical addresses, not page structures.
> >
> > The series maintains export symbol backward compatibility by keeping
> > the old page-based API as wrapper functions around the new physical
> > address-based implementations.
> >
> > This series refactors the DMA mapping API to provide a phys_addr_t
> > based, and struct-page free, external API that can handle all the
> > mapping cases we want in modern systems:
> >
> >   - struct page based cacheable DRAM
> >   - struct page MEMORY_DEVICE_PCI_P2PDMA PCI peer to peer non-cacheable
> >     MMIO
> >   - struct page-less PCI peer to peer non-cacheable MMIO
> >   - struct page-less "resource" MMIO
> >
> > Overall this gets much closer to Matthew's long term wish for
> > struct-pageless IO to cacheable DRAM. The remaining primary work would
> > be in the mm side to allow kmap_local_pfn()/phys_to_virt() to work on
> > phys_addr_t without a struct page.
> >
> > The general design is to remove struct page usage entirely from the
> > DMA API inner layers. For flows that need to have a KVA for the
> > physical address they can use kmap_local_pfn() or phys_to_virt(). This
> > isolates the struct page requirements to MM code only. Long term all
> > removals of struct page usage are supporting Matthew's memdesc
> > project which seeks to substantially transform how struct page works.
> >
> > Instead make the DMA API internals work on phys_addr_t. Internally
> > there are still dedicated 'page' and 'resource' flows, except they are
> > now distinguished by a new DMA_ATTR_MMIO instead of by callchain. Both
> > flows use the same phys_addr_t.
> >
> > When DMA_ATTR_MMIO is specified things work similar to the existing
> > 'resource' flow. kmap_local_pfn(), phys_to_virt(), phys_to_page(),
> > pfn_valid(), etc are never called on the phys_addr_t. This requires
> > rejecting any configuration that would need swiotlb. CPU cache
> > flushing is not required, and avoided, as ATTR_MMIO also indicates the
> > address have no cacheable mappings. This effectively removes any
> > DMA API side requirement to have struct page when DMA_ATTR_MMIO is
> > used.
> >
> > In the !DMA_ATTR_MMIO mode things work similarly to the 'page' flow,
> > except on the common path of no cache flush, no swiotlb it never
> > touches a struct page. When cache flushing or swiotlb copying
> > kmap_local_pfn()/phys_to_virt() are used to get a KVA for CPU
> > usage. This was already the case on the unmap side, now the map side
> > is symmetric.
> >
> > Callers are adjusted to set DMA_ATTR_MMIO. Existing 'resource' users
> > must set it. The existing struct page based MEMORY_DEVICE_PCI_P2PDMA
> > path must also set it. This corrects some existing bugs where iommu
> > mappings for P2P MMIO were improperly marked IOMMU_CACHE.
> >
> > Since ATTR_MMIO is made to work with all the existing DMA map entry
> > points, particularly dma_iova_link(), this finally allows a way to use
> > the new DMA API to map PCI P2P MMIO without creating struct page. The
> > VFIO DMABUF series demonstrates how this works. This is intended to
> > replace the incorrect driver use of dma_map_resource() on PCI BAR
> > addresses.
> >
> > This series does the core code and modern flows. A followup series
> > will give the same treatment to the legacy dma_ops implementation.
> 
> Applied patches 1-13 into dma-mapping-for-next branch. Let's check if it 
> works fine in linux-next.

Thanks a lot.

> 
> Best regards
> -- 
> Marek Szyprowski, PhD
> Samsung R&D Institute Poland
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912090327.GU341237%40unreal.
