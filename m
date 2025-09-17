Return-Path: <kasan-dev+bncBCT4XGV33UIBBN5VVTDAMGQEHWYCFIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 90605B81C42
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 22:32:04 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-26776d064e7sf2260665ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 13:32:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758141112; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZtTZZNHcs4RGtUINwjGiQaCOyhoZwHNM1Ji43afWRHLBMswF5S2280yQ2qIDu4Oww9
         L9sQiXXeCX0DrVwzPPAkAdc/k8vE6tUKY+P+ZGWQL23mrRWk2JPwso1aSVzQh064AcCT
         VX+VOnDv+WDGLe3fYeHgauOTG/ELHulbLwE/7Ucjaq8n8IvdMcWGvRNFseK1tKLI6YvP
         BcinDU4N0YQGmVA3v5pZZlnwwcjnZSJjHnJdCdo+ZWH+L7MAnyY+XoANe2IVnZW7I9AB
         4kWClHxBPzl9ttXrnYsGqi6pIeBPmXYTaB+D3xHc8TiQOtOwmZfj7ft4wjAqCYNLMlJ/
         7lrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=DRghNf00pv9/k9uifGaiPXF8fx2CXLfh0OJqO0AzCyE=;
        fh=8PpxGX6JLhb+ffk+UCg9oM9G3YSonvYc+HyAS4Ynvls=;
        b=X6uAkpRPmm1bxdbO3CbaLlmsYvbrnaA2WeHDr8eQelpBcnFAcobKzfunWh2BNO5nMA
         0aNzpqJH8y9M5TIPGE2fe5i/e0+dPrHY1Iloq2fpeXs/wETjIHaXcm7d9qa5wFlVmyI+
         a9ZjTTixbp+tk/fFF4nB8vNftm8cbDG3uOAJHQ/mH2dhxV/vJbieX+A2SrAQywgLUO1c
         jV79TEWxvip6OY7E/R2xWFLFpw3VbF+poQaiTBcjUgkHo0p0d62z2tigBobOhz3D8y6G
         xogM2xKWs78SrPPZaTaHDpcGExaqRFGT8mPeITm8aEGUjE342ekiJRqTdv7EZp0LveKL
         CGTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=IBy1LxKv;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758141112; x=1758745912; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DRghNf00pv9/k9uifGaiPXF8fx2CXLfh0OJqO0AzCyE=;
        b=P5xYbMDIgqckVttWJEEB5hrKc6KwptBGns8b2iKgyFl/eFr+4P5SXnF6TpZJ6sGOHW
         Uh79o8a0BTX19/c/3YpHWxVvMedVi6TSOxTh5CRNcFgOfeaEcen2i6Rgk+o0H5DzIp2K
         G+Ab8dMJqUF46mFdeEzqOpEFP/YAxZ7EXsvrr67JV9qwjk7ecgfS3P9sNXaotmwu/ZGb
         6iQ0R31TtP4EMPRKDp9NZ2mQYY8wtVeIZ26RZl+2vJRRsi4iL1mP5IFiCtDZsJDBOXv2
         N4nwZdIsJG44rNA3XrLLi/dDXia7fI7lX0bD7NkSP/VtIPPj+JrVghpzZQ3AN4R2LWD5
         x9sQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758141112; x=1758745912;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DRghNf00pv9/k9uifGaiPXF8fx2CXLfh0OJqO0AzCyE=;
        b=Vh9+k8k3tM279rXbaFxWBNNbvJgKJhrGdTHK+DGlZ+KmfWBTCh7EuDRs+qMU9ZV0nd
         khujAidLouX393/FWy8MoCs0Ha7OLMnxDCS9IbY5dxX6H8+N10Clg+mVGLbJTEvj4CUr
         qA1eh2sB89URMQCVtV23dIL7mJt1+TuK5WHfE9hwF7WLRIYW8EgzwQOPcBFQm6vNn3nJ
         H0+MaiNCG8fDzW4NygDCrSbi6qrMVlbETZjwkm/MOIkN5s0RMqL93XwhYDUIJ47cluOh
         D2frSB6IIrIVVB9kpHONhVNndWRZYFDC0ABgnNASmYGi2VqstvT71x7OLEF9Cj2BvnsT
         vAJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVjTbsvRIz2gnzZ2bj4zKboJbOpLCDyeBKthqe0vv+LaXsVsrZFpLzD8CSCNZ/04M+q//NIUA==@lfdr.de
X-Gm-Message-State: AOJu0YyMVYh/hN3xo0XNO2IQK2rBA+jMyMUSd7+DTsRZUaX5ca5tNPJo
	gJ+I53baqzVWDXkmbGa1iAUi0hFP7p6mLAaSgLwG3tbZzKqlaxYnlnrs
X-Google-Smtp-Source: AGHT+IF7BVgcnTg+f/G062TcpFbyJiz71Wh4L/8rgr2PaoBHNxpG5uRiEH9mDzMTRwFR8bidlfjAsQ==
X-Received: by 2002:a17:902:e94e:b0:266:9407:4a5 with SMTP id d9443c01a7336-26813cfa50bmr39312865ad.50.1758141111698;
        Wed, 17 Sep 2025 13:31:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6Cy/9lFgrEoWInLMmeHH5rhPjwRHCWA3p39nfd3F2sCg==
Received: by 2002:a17:903:848:b0:24c:c1b8:a9b5 with SMTP id
 d9443c01a7336-26983fcd4d7ls547385ad.0.-pod-prod-07-us; Wed, 17 Sep 2025
 13:31:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+cqJj0AtdUvs4SHg4o0x+8us8knPGq/4g4zsdodS2fUpy5NF1brNNVCDvrn3zx0L4Uy9bDnM8yA0=@googlegroups.com
X-Received: by 2002:a17:902:e882:b0:267:95ad:8cb8 with SMTP id d9443c01a7336-26813be8412mr41841885ad.44.1758141110090;
        Wed, 17 Sep 2025 13:31:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758141110; cv=none;
        d=google.com; s=arc-20240605;
        b=YawgcLoPJXbWujcTGPqdQ3cl/iEFEaxGUsOVNC+mNTW+EX3jOnlkdc7N+QzlXL+2+O
         JdKAw809PxcL3CeFM6ErRayt2c41SrpSrkjlMu6YLKdb1+aQOdhfGgflBo8+u3H790eI
         hZodtjR4qIygCzWbnoZlTb2y5hZ8Hri5TWkzPuIPENwN9s0nep4KK7nA72B+ur7FU1Kb
         E3ySYRqurP3zprdNjzMHIrNVHEnxMDnn0lp14S8ffC5vvOgOHeLxGlEoXUeXl1CqRzP8
         A9S7hu5xxT6JLULXt2Kgtebt5lY5zicfcLW/3B1m2PdRaiHLoY7xZcMaF3SgNzNPUYGt
         EioA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Xlobmp3U3nJ5hLlB38ePRBjirbU86UFdACM2UMQ2d8U=;
        fh=Q8MWn8ZajgPukYf5a0QIENRpjsGF1RqFrFgPgdw4SbA=;
        b=cImeBWeTbW9SYR/GFTW1a+gQu0pby5U25gAA6IXO4DuhN08tPGyDImJGPpcd9B0/Lb
         01mdLL0M9ewMSyFcOxXRlbF995SDbwe+y8wfXD+jGydUus3jYsZrsIm8xy8QD8VQQCpi
         9RnSp7fI7v5oaJsnJN/Ea9raJCyrVJ1yXbBeAL0w+Gwznt3rXPcwfJzyz623zVuQQ27b
         qQ8OP3JP8SF7/hpccNO7ovRilMs0SeF/r9Qo056yqpnj+xKhgugWg7kTYWd4xXLp/F+N
         uVNTXqWgAbo2aOcEZOorPfymuQWWQV+iNLjT6jqraDZSQnlQJFs70/+qGpj4bD6OLP2r
         UgDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=IBy1LxKv;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2697f738ebfsi321375ad.0.2025.09.17.13.31.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 13:31:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id A5D6444589;
	Wed, 17 Sep 2025 20:31:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3CB4AC4CEF7;
	Wed, 17 Sep 2025 20:31:47 +0000 (UTC)
Date: Wed, 17 Sep 2025 13:31:46 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
 Guo Ren <guoren@kernel.org>, Thomas Bogendoerfer
 <tsbogend@alpha.franken.de>, Heiko Carstens <hca@linux.ibm.com>, Vasily
 Gorbik <gor@linux.ibm.com>, Alexander Gordeev <agordeev@linux.ibm.com>,
 Christian Borntraeger <borntraeger@linux.ibm.com>, Sven Schnelle
 <svens@linux.ibm.com>, "David S . Miller" <davem@davemloft.net>, Andreas
 Larsson <andreas@gaisler.com>, Arnd Bergmann <arnd@arndb.de>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>, Dan Williams
 <dan.j.williams@intel.com>, Vishal Verma <vishal.l.verma@intel.com>, Dave
 Jiang <dave.jiang@intel.com>, Nicolas Pitre <nico@fluxnic.net>, Muchun Song
 <muchun.song@linux.dev>, Oscar Salvador <osalvador@suse.de>, David
 Hildenbrand <david@redhat.com>, Konstantin Komarov
 <almaz.alexandrovich@paragon-software.com>, Baoquan He <bhe@redhat.com>,
 Vivek Goyal <vgoyal@redhat.com>, Dave Young <dyoung@redhat.com>, Tony Luck
 <tony.luck@intel.com>, Reinette Chatre <reinette.chatre@intel.com>, Dave
 Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>, Alexander
 Viro <viro@zeniv.linux.org.uk>, Christian Brauner <brauner@kernel.org>, Jan
 Kara <jack@suse.cz>, "Liam R . Howlett" <Liam.Howlett@oracle.com>,
 Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren
 Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, Hugh
 Dickins <hughd@google.com>, Baolin Wang <baolin.wang@linux.alibaba.com>,
 Uladzislau Rezki <urezki@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Jann Horn <jannh@google.com>,
 Pedro Falcato <pfalcato@suse.de>, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-csky@vger.kernel.org, linux-mips@vger.kernel.org,
 linux-s390@vger.kernel.org, sparclinux@vger.kernel.org,
 nvdimm@lists.linux.dev, linux-cxl@vger.kernel.org, linux-mm@kvack.org,
 ntfs3@lists.linux.dev, kexec@lists.infradead.org,
 kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>,
 iommu@lists.linux.dev, Kevin Tian <kevin.tian@intel.com>, Will Deacon
 <will@kernel.org>, Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v4 00/14] expand mmap_prepare functionality, port more
 users
Message-Id: <20250917133146.cc7ea49dc2ec8093ab938a57@linux-foundation.org>
In-Reply-To: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=IBy1LxKv;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 17 Sep 2025 20:11:02 +0100 Lorenzo Stoakes <lorenzo.stoakes@oracle.com> wrote:

> Since commit c84bf6dd2b83 ("mm: introduce new .mmap_prepare() file
> callback"), The f_op->mmap hook has been deprecated in favour of
> f_op->mmap_prepare.
> 
> This was introduced in order to make it possible for us to eventually
> eliminate the f_op->mmap hook which is highly problematic as it allows
> drivers and filesystems raw access to a VMA which is not yet correctly
> initialised.
> 
> This hook also introduced complexity for the memory mapping operation, as
> we must correctly unwind what we do should an error arises.
> 
> Overall this interface being so open has caused significant problems for
> us, including security issues, it is important for us to simply eliminate
> this as a source of problems.
> 
> Therefore this series continues what was established by extending the
> functionality further to permit more drivers and filesystems to use
> mmap_prepare.

Thanks, I updated mm.git's mm-new branch to this version.

> v4:
> * Dropped accidentally still-included reference to mmap_abort() in the
>   commit message for the patch in which remap_pfn_range_[prepare,
>   complete]() are introduced as per Jason.
> * Avoided set_vma boolean parameter in remap_pfn_range_internal() as per
>   Jason.
> * Further refactored remap_pfn_range() et al. as per Jason - couldn't make
>   IS_ENABLED() work nicely, as have to declare remap_pfn_range_track()
>   otherwise, so did least-nasty thing.
> * Abstracted I/O remap on PFN calculation as suggested by Jason, however do
>   this more generally across io_remap_pfn_range() as a whole, before
>   introducing prepare/complete variants.
> * Made [io_]remap_pfn_range_[prepare, complete]() internal-only as per
>   Pedro.
> * Renamed [__]compat_vma_prepare to [__]compat_vma as per Jason.
> * Dropped duplicated debug check in mmap_action_complete() as per Jason.
> * Added MMAP_IO_REMAP_PFN action type as per Jason.
> * Various small refactorings as suggested by Jason.
> * Shared code between mmu and nommu mmap_action_complete() as per Jason.
> * Add missing return in kdoc for shmem_zero_setup().
> * Separate out introduction of shmem_zero_setup_desc() into another patch
>   as per Jason.
> * Looked into Jason's request re: using shmem_zero_setup_desc() in vma.c -
>   It isn't really worthwhile for now as we'd have to set VMA fields from
>   the desc after the fields were already set from the map, though once we
>   convert all callers to mmap_prepare we can look at this again.
> * Fixed bug with char mem driver not correctly setting MAP_PRIVATE
>   /dev/zero anonymous (with vma->vm_file still set), use success hook
>   instead.
> * Renamed mmap_prepare_zero to mmap_zero_prepare to be consistent with
>   mmap_mem_prepare.

For those following along at home, here's the overall v3->v4 diff. 
It's quite substantial...


--- a/arch/csky/include/asm/pgtable.h~b
+++ a/arch/csky/include/asm/pgtable.h
@@ -263,12 +263,6 @@ void update_mmu_cache_range(struct vm_fa
 #define update_mmu_cache(vma, addr, ptep) \
 	update_mmu_cache_range(NULL, vma, addr, ptep, 1)
 
-#define io_remap_pfn_range(vma, vaddr, pfn, size, prot) \
-	remap_pfn_range(vma, vaddr, pfn, size, prot)
-
-/* default io_remap_pfn_range_prepare can be used. */
-
-#define io_remap_pfn_range_complete(vma, addr, pfn, size, prot) \
-	remap_pfn_range_complete(vma, addr, pfn, size, prot)
+#define io_remap_pfn_range_pfn(pfn, size) (pfn)
 
 #endif /* __ASM_CSKY_PGTABLE_H */
--- a/arch/mips/alchemy/common/setup.c~b
+++ a/arch/mips/alchemy/common/setup.c
@@ -94,34 +94,13 @@ phys_addr_t fixup_bigphys_addr(phys_addr
 	return phys_addr;
 }
 
-static unsigned long calc_pfn(unsigned long pfn, unsigned long size)
+static inline unsigned long io_remap_pfn_range_pfn(unsigned long pfn,
+		unsigned long size)
 {
 	phys_addr_t phys_addr = fixup_bigphys_addr(pfn << PAGE_SHIFT, size);
 
 	return phys_addr >> PAGE_SHIFT;
 }
-
-int io_remap_pfn_range(struct vm_area_struct *vma, unsigned long vaddr,
-		unsigned long pfn, unsigned long size, pgprot_t prot)
-{
-	return remap_pfn_range(vma, vaddr, calc_pfn(pfn, size), size, prot);
-}
-EXPORT_SYMBOL(io_remap_pfn_range);
-
-void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
-			       unsigned long size)
-{
-	remap_pfn_range_prepare(desc, calc_pfn(pfn, size));
-}
-EXPORT_SYMBOL(io_remap_pfn_range_prepare);
-
-int io_remap_pfn_range_complete(struct vm_area_struct *vma,
-		unsigned long addr, unsigned long pfn, unsigned long size,
-		pgprot_t prot)
-{
-	return remap_pfn_range_complete(vma, addr, calc_pfn(pfn, size),
-			size, prot);
-}
-EXPORT_SYMBOL(io_remap_pfn_range_complete);
+EXPORT_SYMBOL(io_remap_pfn_range_pfn);
 
 #endif /* CONFIG_MIPS_FIXUP_BIGPHYS_ADDR */
--- a/arch/mips/include/asm/pgtable.h~b
+++ a/arch/mips/include/asm/pgtable.h
@@ -604,19 +604,8 @@ static inline void update_mmu_cache_pmd(
  */
 #ifdef CONFIG_MIPS_FIXUP_BIGPHYS_ADDR
 phys_addr_t fixup_bigphys_addr(phys_addr_t addr, phys_addr_t size);
-int io_remap_pfn_range(struct vm_area_struct *vma, unsigned long vaddr,
-		unsigned long pfn, unsigned long size, pgprot_t prot);
-#define io_remap_pfn_range io_remap_pfn_range
-
-void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
-		unsigned long size);
-#define io_remap_pfn_range_prepare io_remap_pfn_range_prepare
-
-int io_remap_pfn_range_complete(struct vm_area_struct *vma,
-		unsigned long addr, unsigned long pfn, unsigned long size,
-		pgprot_t prot);
-#define io_remap_pfn_range_complete io_remap_pfn_range_complete
-
+unsigned long io_remap_pfn_range_pfn(unsigned long pfn, unsigned long size);
+#define io_remap_pfn_range_pfn io_remap_pfn_range_pfn
 #else
 #define fixup_bigphys_addr(addr, size)	(addr)
 #endif /* CONFIG_MIPS_FIXUP_BIGPHYS_ADDR */
--- a/arch/sparc/include/asm/pgtable_32.h~b
+++ a/arch/sparc/include/asm/pgtable_32.h
@@ -395,13 +395,8 @@ __get_iospace (unsigned long addr)
 #define GET_IOSPACE(pfn)		(pfn >> (BITS_PER_LONG - 4))
 #define GET_PFN(pfn)			(pfn & 0x0fffffffUL)
 
-int remap_pfn_range(struct vm_area_struct *, unsigned long, unsigned long,
-		    unsigned long, pgprot_t);
-void remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn);
-int remap_pfn_range_complete(struct vm_area_struct *vma, unsigned long addr,
-		unsigned long pfn, unsigned long size, pgprot_t pgprot);
-
-static inline unsigned long calc_io_remap_pfn(unsigned long pfn)
+static inline unsigned long io_remap_pfn_range_pfn(unsigned long pfn,
+		unsigned long size)
 {
 	unsigned long long offset, space, phys_base;
 
@@ -411,30 +406,7 @@ static inline unsigned long calc_io_rema
 
 	return phys_base >> PAGE_SHIFT;
 }
-
-static inline int io_remap_pfn_range(struct vm_area_struct *vma,
-				     unsigned long from, unsigned long pfn,
-				     unsigned long size, pgprot_t prot)
-{
-	return remap_pfn_range(vma, from, calc_io_remap_pfn(pfn), size, prot);
-}
-#define io_remap_pfn_range io_remap_pfn_range
-
-static inline void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
-		unsigned long size)
-{
-	remap_pfn_range_prepare(desc, calc_io_remap_pfn(pfn));
-}
-#define io_remap_pfn_range_prepare io_remap_pfn_range_prepare
-
-static inline int io_remap_pfn_range_complete(struct vm_area_struct *vma,
-		unsigned long addr, unsigned long pfn, unsigned long size,
-		pgprot_t prot)
-{
-	return remap_pfn_range_complete(vma, addr, calc_io_remap_pfn(pfn),
-			size, prot);
-}
-#define io_remap_pfn_range_complete io_remap_pfn_range_complete
+#define io_remap_pfn_range_pfn io_remap_pfn_range_pfn
 
 #define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
 #define ptep_set_access_flags(__vma, __address, __ptep, __entry, __dirty) \
--- a/arch/sparc/include/asm/pgtable_64.h~b
+++ a/arch/sparc/include/asm/pgtable_64.h
@@ -1048,12 +1048,6 @@ int page_in_phys_avail(unsigned long pad
 #define GET_IOSPACE(pfn)		(pfn >> (BITS_PER_LONG - 4))
 #define GET_PFN(pfn)			(pfn & 0x0fffffffffffffffUL)
 
-int remap_pfn_range(struct vm_area_struct *, unsigned long, unsigned long,
-		    unsigned long, pgprot_t);
-void remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn);
-int remap_pfn_range_complete(struct vm_area_struct *vma, unsigned long addr,
-		unsigned long pfn, unsigned long size, pgprot_t pgprot);
-
 void adi_restore_tags(struct mm_struct *mm, struct vm_area_struct *vma,
 		      unsigned long addr, pte_t pte);
 
@@ -1087,7 +1081,8 @@ static inline int arch_unmap_one(struct
 	return 0;
 }
 
-static inline unsigned long calc_io_remap_pfn(unsigned long pfn)
+static inline unsigned long io_remap_pfn_range_pfn(unsigned long pfn,
+		unsigned long size)
 {
 	unsigned long offset = GET_PFN(pfn) << PAGE_SHIFT;
 	int space = GET_IOSPACE(pfn);
@@ -1097,30 +1092,7 @@ static inline unsigned long calc_io_rema
 
 	return phys_base >> PAGE_SHIFT;
 }
-
-static inline int io_remap_pfn_range(struct vm_area_struct *vma,
-				     unsigned long from, unsigned long pfn,
-				     unsigned long size, pgprot_t prot)
-{
-	return remap_pfn_range(vma, from, calc_io_remap_pfn(pfn), size, prot);
-}
-#define io_remap_pfn_range io_remap_pfn_range
-
-static inline void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
-	unsigned long size)
-{
-	return remap_pfn_range_prepare(desc, calc_io_remap_pfn(pfn));
-}
-#define io_remap_pfn_range_prepare io_remap_pfn_range_prepare
-
-static inline int io_remap_pfn_range_complete(struct vm_area_struct *vma,
-		unsigned long addr, unsigned long pfn, unsigned long size,
-		pgprot_t prot)
-{
-	return remap_pfn_range_complete(vma, addr, calc_io_remap_pfn(pfn),
-					size, prot);
-}
-#define io_remap_pfn_range_complete io_remap_pfn_range_complete
+#define io_remap_pfn_range_pfn io_remap_pfn_range_pfn
 
 static inline unsigned long __untagged_addr(unsigned long start)
 {
--- a/drivers/char/mem.c~b
+++ a/drivers/char/mem.c
@@ -504,18 +504,26 @@ static ssize_t read_zero(struct file *fi
 	return cleared;
 }
 
-static int mmap_prepare_zero(struct vm_area_desc *desc)
+static int mmap_zero_private_success(const struct vm_area_struct *vma)
+{
+	/*
+	 * This is a highly unique situation where we mark a MAP_PRIVATE mapping
+	 * of /dev/zero anonymous, despite it not being.
+	 */
+	vma_set_anonymous((struct vm_area_struct *)vma);
+
+	return 0;
+}
+
+static int mmap_zero_prepare(struct vm_area_desc *desc)
 {
 #ifndef CONFIG_MMU
 	return -ENOSYS;
 #endif
 	if (desc->vm_flags & VM_SHARED)
 		return shmem_zero_setup_desc(desc);
-	/*
-	 * This is a highly unique situation where we mark a MAP_PRIVATE mapping
-	 * of /dev/zero anonymous, despite it not being.
-	 */
-	desc->vm_ops = NULL;
+
+	desc->action.success_hook = mmap_zero_private_success;
 	return 0;
 }
 
@@ -533,7 +541,7 @@ static unsigned long get_unmapped_area_z
 {
 	if (flags & MAP_SHARED) {
 		/*
-		 * mmap_prepare_zero() will call shmem_zero_setup() to create a
+		 * mmap_zero_prepare() will call shmem_zero_setup() to create a
 		 * file, so use shmem's get_unmapped_area in case it can be
 		 * huge; and pass NULL for file as in mmap.c's
 		 * get_unmapped_area(), so as not to confuse shmem with our
@@ -676,7 +684,7 @@ static const struct file_operations zero
 	.write_iter	= write_iter_zero,
 	.splice_read	= copy_splice_read,
 	.splice_write	= splice_write_zero,
-	.mmap_prepare	= mmap_prepare_zero,
+	.mmap_prepare	= mmap_zero_prepare,
 	.get_unmapped_area = get_unmapped_area_zero,
 #ifndef CONFIG_MMU
 	.mmap_capabilities = zero_mmap_capabilities,
--- a/include/linux/fs.h~b
+++ a/include/linux/fs.h
@@ -2279,14 +2279,14 @@ static inline bool can_mmap_file(struct
 	return true;
 }
 
-int __compat_vma_mmap_prepare(const struct file_operations *f_op,
+int __compat_vma_mmap(const struct file_operations *f_op,
 		struct file *file, struct vm_area_struct *vma);
-int compat_vma_mmap_prepare(struct file *file, struct vm_area_struct *vma);
+int compat_vma_mmap(struct file *file, struct vm_area_struct *vma);
 
 static inline int vfs_mmap(struct file *file, struct vm_area_struct *vma)
 {
 	if (file->f_op->mmap_prepare)
-		return compat_vma_mmap_prepare(file, vma);
+		return compat_vma_mmap(file, vma);
 
 	return file->f_op->mmap(file, vma);
 }
--- a/include/linux/mm.h~b
+++ a/include/linux/mm.h
@@ -3650,7 +3650,7 @@ static inline void mmap_action_ioremap(s
 				       unsigned long size)
 {
 	mmap_action_remap(desc, start, start_pfn, size);
-	desc->action.remap.is_io_remap = true;
+	desc->action.type = MMAP_IO_REMAP_PFN;
 }
 
 /**
@@ -3713,9 +3713,6 @@ struct vm_area_struct *find_extend_vma_l
 		unsigned long addr);
 int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
 		    unsigned long pfn, unsigned long size, pgprot_t pgprot);
-void remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn);
-int remap_pfn_range_complete(struct vm_area_struct *vma, unsigned long addr,
-		unsigned long pfn, unsigned long size, pgprot_t pgprot);
 
 int vm_insert_page(struct vm_area_struct *, unsigned long addr, struct page *);
 int vm_insert_pages(struct vm_area_struct *vma, unsigned long addr,
@@ -3749,32 +3746,34 @@ static inline vm_fault_t vmf_insert_page
 	return VM_FAULT_NOPAGE;
 }
 
-#ifndef io_remap_pfn_range
-static inline int io_remap_pfn_range(struct vm_area_struct *vma,
-				     unsigned long addr, unsigned long pfn,
-				     unsigned long size, pgprot_t prot)
+#ifdef io_remap_pfn_range_pfn
+static inline unsigned long io_remap_pfn_range_prot(pgprot_t prot)
 {
-	return remap_pfn_range(vma, addr, pfn, size, pgprot_decrypted(prot));
+	/* We do not decrypt if arch customises PFN. */
+	return prot;
+}
+#else
+static inline unsigned long io_remap_pfn_range_pfn(unsigned long pfn,
+		unsigned long size)
+{
+	return pfn;
 }
-#endif
 
-#ifndef io_remap_pfn_range_prepare
-static inline void io_remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn,
-	unsigned long size)
+static inline pgprot_t io_remap_pfn_range_prot(pgprot_t prot)
 {
-	return remap_pfn_range_prepare(desc, pfn);
+	return pgprot_decrypted(prot);
 }
 #endif
 
-#ifndef io_remap_pfn_range_complete
-static inline int io_remap_pfn_range_complete(struct vm_area_struct *vma,
-		unsigned long addr, unsigned long pfn, unsigned long size,
-		pgprot_t prot)
+static inline int io_remap_pfn_range(struct vm_area_struct *vma,
+				     unsigned long addr, unsigned long orig_pfn,
+				     unsigned long size, pgprot_t orig_prot)
 {
-	return remap_pfn_range_complete(vma, addr, pfn, size,
-			pgprot_decrypted(prot));
+	const unsigned long pfn = io_remap_pfn_range_pfn(orig_pfn, size);
+	const pgprot_t prot = io_remap_pfn_range_prot(orig_prot);
+
+	return remap_pfn_range(vma, addr, pfn, size, prot);
 }
-#endif
 
 static inline vm_fault_t vmf_error(int err)
 {
--- a/include/linux/mm_types.h~b
+++ a/include/linux/mm_types.h
@@ -777,6 +777,7 @@ struct pfnmap_track_ctx {
 enum mmap_action_type {
 	MMAP_NOTHING,		/* Mapping is complete, no further action. */
 	MMAP_REMAP_PFN,		/* Remap PFN range. */
+	MMAP_IO_REMAP_PFN,	/* I/O remap PFN range. */
 };
 
 /*
@@ -791,7 +792,6 @@ struct mmap_action {
 			unsigned long start_pfn;
 			unsigned long size;
 			pgprot_t pgprot;
-			bool is_io_remap;
 		} remap;
 	};
 	enum mmap_action_type type;
--- a/mm/internal.h~b
+++ a/mm/internal.h
@@ -1653,4 +1653,26 @@ static inline bool reclaim_pt_is_enabled
 void dup_mm_exe_file(struct mm_struct *mm, struct mm_struct *oldmm);
 int dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm);
 
+void remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn);
+int remap_pfn_range_complete(struct vm_area_struct *vma, unsigned long addr,
+		unsigned long pfn, unsigned long size, pgprot_t pgprot);
+
+static inline void io_remap_pfn_range_prepare(struct vm_area_desc *desc,
+		unsigned long orig_pfn, unsigned long size)
+{
+	const unsigned long pfn = io_remap_pfn_range_pfn(orig_pfn, size);
+
+	return remap_pfn_range_prepare(desc, pfn);
+}
+
+static inline int io_remap_pfn_range_complete(struct vm_area_struct *vma,
+		unsigned long addr, unsigned long orig_pfn, unsigned long size,
+		pgprot_t orig_prot)
+{
+	const unsigned long pfn = io_remap_pfn_range_pfn(orig_pfn, size);
+	const pgprot_t prot = io_remap_pfn_range_prot(orig_prot);
+
+	return remap_pfn_range_complete(vma, addr, pfn, size, prot);
+}
+
 #endif	/* __MM_INTERNAL_H */
--- a/mm/memory.c~b
+++ a/mm/memory.c
@@ -2919,7 +2919,7 @@ static int get_remap_pgoff(vm_flags_t vm
 }
 
 static int remap_pfn_range_internal(struct vm_area_struct *vma, unsigned long addr,
-		unsigned long pfn, unsigned long size, pgprot_t prot, bool set_vma)
+		unsigned long pfn, unsigned long size, pgprot_t prot)
 {
 	pgd_t *pgd;
 	unsigned long next;
@@ -2930,16 +2930,7 @@ static int remap_pfn_range_internal(stru
 	if (WARN_ON_ONCE(!PAGE_ALIGNED(addr)))
 		return -EINVAL;
 
-	if (set_vma) {
-		err = get_remap_pgoff(vma->vm_flags, addr, end,
-				      vma->vm_start, vma->vm_end,
-				      pfn, &vma->vm_pgoff);
-		if (err)
-			return err;
-		vm_flags_set(vma, VM_REMAP_FLAGS);
-	} else {
-		VM_WARN_ON_ONCE((vma->vm_flags & VM_REMAP_FLAGS) != VM_REMAP_FLAGS);
-	}
+	VM_WARN_ON_ONCE((vma->vm_flags & VM_REMAP_FLAGS) != VM_REMAP_FLAGS);
 
 	BUG_ON(addr >= end);
 	pfn -= addr >> PAGE_SHIFT;
@@ -2961,9 +2952,9 @@ static int remap_pfn_range_internal(stru
  * must have pre-validated the caching bits of the pgprot_t.
  */
 static int remap_pfn_range_notrack(struct vm_area_struct *vma, unsigned long addr,
-		unsigned long pfn, unsigned long size, pgprot_t prot, bool set_vma)
+		unsigned long pfn, unsigned long size, pgprot_t prot)
 {
-	int error = remap_pfn_range_internal(vma, addr, pfn, size, prot, set_vma);
+	int error = remap_pfn_range_internal(vma, addr, pfn, size, prot);
 	if (!error)
 		return 0;
 
@@ -2976,18 +2967,6 @@ static int remap_pfn_range_notrack(struc
 	return error;
 }
 
-void remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn)
-{
-	/*
-	 * We set addr=VMA start, end=VMA end here, so this won't fail, but we
-	 * check it again on complete and will fail there if specified addr is
-	 * invalid.
-	 */
-	get_remap_pgoff(desc->vm_flags, desc->start, desc->end,
-			desc->start, desc->end, pfn, &desc->pgoff);
-	desc->vm_flags |= VM_REMAP_FLAGS;
-}
-
 #ifdef __HAVE_PFNMAP_TRACKING
 static inline struct pfnmap_track_ctx *pfnmap_track_ctx_alloc(unsigned long pfn,
 		unsigned long size, pgprot_t *prot)
@@ -3018,7 +2997,7 @@ void pfnmap_track_ctx_release(struct kre
 }
 
 static int remap_pfn_range_track(struct vm_area_struct *vma, unsigned long addr,
-		unsigned long pfn, unsigned long size, pgprot_t prot, bool set_vma)
+		unsigned long pfn, unsigned long size, pgprot_t prot)
 {
 	struct pfnmap_track_ctx *ctx = NULL;
 	int err;
@@ -3044,7 +3023,7 @@ static int remap_pfn_range_track(struct
 		return -EINVAL;
 	}
 
-	err = remap_pfn_range_notrack(vma, addr, pfn, size, prot, set_vma);
+	err = remap_pfn_range_notrack(vma, addr, pfn, size, prot);
 	if (ctx) {
 		if (err)
 			kref_put(&ctx->kref, pfnmap_track_ctx_release);
@@ -3054,6 +3033,47 @@ static int remap_pfn_range_track(struct
 	return err;
 }
 
+static int do_remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
+		unsigned long pfn, unsigned long size, pgprot_t prot)
+{
+	return remap_pfn_range_track(vma, addr, pfn, size, prot);
+}
+#else
+static int do_remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
+		unsigned long pfn, unsigned long size, pgprot_t prot)
+{
+	return remap_pfn_range_notrack(vma, addr, pfn, size, prot);
+}
+#endif
+
+void remap_pfn_range_prepare(struct vm_area_desc *desc, unsigned long pfn)
+{
+	/*
+	 * We set addr=VMA start, end=VMA end here, so this won't fail, but we
+	 * check it again on complete and will fail there if specified addr is
+	 * invalid.
+	 */
+	get_remap_pgoff(desc->vm_flags, desc->start, desc->end,
+			desc->start, desc->end, pfn, &desc->pgoff);
+	desc->vm_flags |= VM_REMAP_FLAGS;
+}
+
+static int remap_pfn_range_prepare_vma(struct vm_area_struct *vma, unsigned long addr,
+		unsigned long pfn, unsigned long size)
+{
+	unsigned long end = addr + PAGE_ALIGN(size);
+	int err;
+
+	err = get_remap_pgoff(vma->vm_flags, addr, end,
+			      vma->vm_start, vma->vm_end,
+			      pfn, &vma->vm_pgoff);
+	if (err)
+		return err;
+
+	vm_flags_set(vma, VM_REMAP_FLAGS);
+	return 0;
+}
+
 /**
  * remap_pfn_range - remap kernel memory to userspace
  * @vma: user vma to map to
@@ -3069,32 +3089,21 @@ static int remap_pfn_range_track(struct
 int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
 		    unsigned long pfn, unsigned long size, pgprot_t prot)
 {
-	return remap_pfn_range_track(vma, addr, pfn, size, prot,
-				     /* set_vma = */true);
-}
+	int err;
 
-int remap_pfn_range_complete(struct vm_area_struct *vma, unsigned long addr,
-		unsigned long pfn, unsigned long size, pgprot_t prot)
-{
-	/* With set_vma = false, the VMA will not be modified. */
-	return remap_pfn_range_track(vma, addr, pfn, size, prot,
-				     /* set_vma = */false);
-}
-#else
-int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
-		    unsigned long pfn, unsigned long size, pgprot_t prot)
-{
-	return remap_pfn_range_notrack(vma, addr, pfn, size, prot, /* set_vma = */true);
+	err = remap_pfn_range_prepare_vma(vma, addr, pfn, size);
+	if (err)
+		return err;
+
+	return do_remap_pfn_range(vma, addr, pfn, size, prot);
 }
+EXPORT_SYMBOL(remap_pfn_range);
 
 int remap_pfn_range_complete(struct vm_area_struct *vma, unsigned long addr,
-			     unsigned long pfn, unsigned long size, pgprot_t prot)
+		unsigned long pfn, unsigned long size, pgprot_t prot)
 {
-	return remap_pfn_range_notrack(vma, addr, pfn, size, prot,
-				       /* set_vma = */false);
+	return do_remap_pfn_range(vma, addr, pfn, size, prot);
 }
-#endif
-EXPORT_SYMBOL(remap_pfn_range);
 
 /**
  * vm_iomap_memory - remap memory to userspace
--- a/mm/shmem.c~b
+++ a/mm/shmem.c
@@ -5908,6 +5908,7 @@ static struct file *__shmem_zero_setup(u
 /**
  * shmem_zero_setup - setup a shared anonymous mapping
  * @vma: the vma to be mmapped is prepared by do_mmap
+ * Returns: 0 on success, or error
  */
 int shmem_zero_setup(struct vm_area_struct *vma)
 {
--- a/mm/util.c~b
+++ a/mm/util.c
@@ -1134,7 +1134,7 @@ EXPORT_SYMBOL(flush_dcache_folio);
 #endif
 
 /**
- * __compat_vma_mmap_prepare() - See description for compat_vma_mmap_prepare()
+ * __compat_vma_mmap() - See description for compat_vma_mmap()
  * for details. This is the same operation, only with a specific file operations
  * struct which may or may not be the same as vma->vm_file->f_op.
  * @f_op: The file operations whose .mmap_prepare() hook is specified.
@@ -1142,7 +1142,7 @@ EXPORT_SYMBOL(flush_dcache_folio);
  * @vma: The VMA to apply the .mmap_prepare() hook to.
  * Returns: 0 on success or error.
  */
-int __compat_vma_mmap_prepare(const struct file_operations *f_op,
+int __compat_vma_mmap(const struct file_operations *f_op,
 		struct file *file, struct vm_area_struct *vma)
 {
 	struct vm_area_desc desc = {
@@ -1168,11 +1168,11 @@ int __compat_vma_mmap_prepare(const stru
 	set_vma_from_desc(vma, &desc);
 	return mmap_action_complete(&desc.action, vma);
 }
-EXPORT_SYMBOL(__compat_vma_mmap_prepare);
+EXPORT_SYMBOL(__compat_vma_mmap);
 
 /**
- * compat_vma_mmap_prepare() - Apply the file's .mmap_prepare() hook to an
- * existing VMA.
+ * compat_vma_mmap() - Apply the file's .mmap_prepare() hook to an
+ * existing VMA and execute any requested actions.
  * @file: The file which possesss an f_op->mmap_prepare() hook.
  * @vma: The VMA to apply the .mmap_prepare() hook to.
  *
@@ -1187,7 +1187,7 @@ EXPORT_SYMBOL(__compat_vma_mmap_prepare)
  * .mmap_prepare() hook, as we are in a different context when we invoke the
  * .mmap() hook, already having a VMA to deal with.
  *
- * compat_vma_mmap_prepare() is a compatibility function that takes VMA state,
+ * compat_vma_mmap() is a compatibility function that takes VMA state,
  * establishes a struct vm_area_desc descriptor, passes to the underlying
  * .mmap_prepare() hook and applies any changes performed by it.
  *
@@ -1196,11 +1196,11 @@ EXPORT_SYMBOL(__compat_vma_mmap_prepare)
  *
  * Returns: 0 on success or error.
  */
-int compat_vma_mmap_prepare(struct file *file, struct vm_area_struct *vma)
+int compat_vma_mmap(struct file *file, struct vm_area_struct *vma)
 {
-	return __compat_vma_mmap_prepare(file->f_op, file, vma);
+	return __compat_vma_mmap(file->f_op, file, vma);
 }
-EXPORT_SYMBOL(compat_vma_mmap_prepare);
+EXPORT_SYMBOL(compat_vma_mmap);
 
 static void set_ps_flags(struct page_snapshot *ps, const struct folio *folio,
 			 const struct page *page)
@@ -1282,6 +1282,35 @@ again:
 	}
 }
 
+static int mmap_action_finish(struct mmap_action *action,
+		const struct vm_area_struct *vma, int err)
+{
+	/*
+	 * If an error occurs, unmap the VMA altogether and return an error. We
+	 * only clear the newly allocated VMA, since this function is only
+	 * invoked if we do NOT merge, so we only clean up the VMA we created.
+	 */
+	if (err) {
+		const size_t len = vma_pages(vma) << PAGE_SHIFT;
+
+		do_munmap(current->mm, vma->vm_start, len, NULL);
+
+		if (action->error_hook) {
+			/* We may want to filter the error. */
+			err = action->error_hook(err);
+
+			/* The caller should not clear the error. */
+			VM_WARN_ON_ONCE(!err);
+		}
+		return err;
+	}
+
+	if (action->success_hook)
+		return action->success_hook(vma);
+
+	return 0;
+}
+
 #ifdef CONFIG_MMU
 /**
  * mmap_action_prepare - Perform preparatory setup for an VMA descriptor
@@ -1296,11 +1325,11 @@ void mmap_action_prepare(struct mmap_act
 	case MMAP_NOTHING:
 		break;
 	case MMAP_REMAP_PFN:
-		if (action->remap.is_io_remap)
-			io_remap_pfn_range_prepare(desc, action->remap.start_pfn,
-				action->remap.size);
-		else
-			remap_pfn_range_prepare(desc, action->remap.start_pfn);
+		remap_pfn_range_prepare(desc, action->remap.start_pfn);
+		break;
+	case MMAP_IO_REMAP_PFN:
+		io_remap_pfn_range_prepare(desc, action->remap.start_pfn,
+					   action->remap.size);
 		break;
 	}
 }
@@ -1324,44 +1353,18 @@ int mmap_action_complete(struct mmap_act
 	case MMAP_NOTHING:
 		break;
 	case MMAP_REMAP_PFN:
-		VM_WARN_ON_ONCE((vma->vm_flags & VM_REMAP_FLAGS) !=
-				VM_REMAP_FLAGS);
-
-		if (action->remap.is_io_remap)
-			err = io_remap_pfn_range_complete(vma, action->remap.start,
+		err = remap_pfn_range_complete(vma, action->remap.start,
 				action->remap.start_pfn, action->remap.size,
 				action->remap.pgprot);
-		else
-			err = remap_pfn_range_complete(vma, action->remap.start,
+		break;
+	case MMAP_IO_REMAP_PFN:
+		err = io_remap_pfn_range_complete(vma, action->remap.start,
 				action->remap.start_pfn, action->remap.size,
 				action->remap.pgprot);
 		break;
 	}
 
-	/*
-	 * If an error occurs, unmap the VMA altogether and return an error. We
-	 * only clear the newly allocated VMA, since this function is only
-	 * invoked if we do NOT merge, so we only clean up the VMA we created.
-	 */
-	if (err) {
-		const size_t len = vma_pages(vma) << PAGE_SHIFT;
-
-		do_munmap(current->mm, vma->vm_start, len, NULL);
-
-		if (action->error_hook) {
-			/* We may want to filter the error. */
-			err = action->error_hook(err);
-
-			/* The caller should not clear the error. */
-			VM_WARN_ON_ONCE(!err);
-		}
-		return err;
-	}
-
-	if (action->success_hook)
-		err = action->success_hook(vma);
-
-	return err;
+	return mmap_action_finish(action, vma, err);
 }
 EXPORT_SYMBOL(mmap_action_complete);
 #else
@@ -1372,6 +1375,7 @@ void mmap_action_prepare(struct mmap_act
 	case MMAP_NOTHING:
 		break;
 	case MMAP_REMAP_PFN:
+	case MMAP_IO_REMAP_PFN:
 		WARN_ON_ONCE(1); /* nommu cannot handle these. */
 		break;
 	}
@@ -1381,41 +1385,17 @@ EXPORT_SYMBOL(mmap_action_prepare);
 int mmap_action_complete(struct mmap_action *action,
 			struct vm_area_struct *vma)
 {
-	int err = 0;
-
 	switch (action->type) {
 	case MMAP_NOTHING:
 		break;
 	case MMAP_REMAP_PFN:
+	case MMAP_IO_REMAP_PFN:
 		WARN_ON_ONCE(1); /* nommu cannot handle this. */
 
 		break;
 	}
 
-	/*
-	 * If an error occurs, unmap the VMA altogether and return an error. We
-	 * only clear the newly allocated VMA, since this function is only
-	 * invoked if we do NOT merge, so we only clean up the VMA we created.
-	 */
-	if (err) {
-		const size_t len = vma_pages(vma) << PAGE_SHIFT;
-
-		do_munmap(current->mm, vma->vm_start, len, NULL);
-
-		if (action->error_hook) {
-			/* We may want to filter the error. */
-			err = action->error_hook(err);
-
-			/* The caller should not clear the error. */
-			VM_WARN_ON_ONCE(!err);
-		}
-		return err;
-	}
-
-	if (action->success_hook)
-		err = action->success_hook(vma);
-
-	return 0;
+	return mmap_action_finish(action, vma, /* err = */0);
 }
 EXPORT_SYMBOL(mmap_action_complete);
 #endif
--- a/tools/testing/vma/vma_internal.h~b
+++ a/tools/testing/vma/vma_internal.h
@@ -293,7 +293,6 @@ struct mmap_action {
 			unsigned long start_pfn;
 			unsigned long size;
 			pgprot_t pgprot;
-			bool is_io_remap;
 		} remap;
 	};
 	enum mmap_action_type type;
@@ -1524,7 +1523,7 @@ static inline int mmap_action_complete(s
 	return 0;
 }
 
-static inline int __compat_vma_mmap_prepare(const struct file_operations *f_op,
+static inline int __compat_vma_mmap(const struct file_operations *f_op,
 		struct file *file, struct vm_area_struct *vma)
 {
 	struct vm_area_desc desc = {
@@ -1551,10 +1550,10 @@ static inline int __compat_vma_mmap_prep
 	return mmap_action_complete(&desc.action, vma);
 }
 
-static inline int compat_vma_mmap_prepare(struct file *file,
+static inline int compat_vma_mmap(struct file *file,
 		struct vm_area_struct *vma)
 {
-	return __compat_vma_mmap_prepare(file->f_op, file, vma);
+	return __compat_vma_mmap(file->f_op, file, vma);
 }
 
 /* Did the driver provide valid mmap hook configuration? */
@@ -1575,7 +1574,7 @@ static inline bool can_mmap_file(struct
 static inline int vfs_mmap(struct file *file, struct vm_area_struct *vma)
 {
 	if (file->f_op->mmap_prepare)
-		return compat_vma_mmap_prepare(file, vma);
+		return compat_vma_mmap(file, vma);
 
 	return file->f_op->mmap(file, vma);
 }
_

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250917133146.cc7ea49dc2ec8093ab938a57%40linux-foundation.org.
