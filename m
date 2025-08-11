Return-Path: <kasan-dev+bncBDZMFEH3WYFBBIGL43CAMGQE2WONUSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 8791DB2016C
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 10:11:14 +0200 (CEST)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-711136ed77fsf57414537b3.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 01:11:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754899873; cv=pass;
        d=google.com; s=arc-20240605;
        b=CgeHzTJ8zzGlE/XBieE6tYEFjWfLt3AVWWTj3rCkLIOOKMNtTSFZ6TSQcCo1vZb9Wr
         Fn+tQWwKSApx0l5btdTXEYexjg+HLKuoqdXQ7U9NwZVP1rwqsN1tD9Tz6IA7hS9HgsK6
         zto5nuUcgFK5KBsOoHzT0FPvxRHbaRG3vkN/RCglCjhe41jhNxTSUTmFurNHWU1oD2rp
         7qdfhT9xBSp906e+cOYdrXTu/+lTB2L7Na1OWf03l6d0jsvmXpIb3p1oT/yPDzGMzCfj
         0WeQQw42q0QEow/uCWffXhAPinny5umsH2qwib/b0C8KdHfJ6a9qVPLmVT2Jqrr05hoa
         xb8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=dx5IdvRFavjqmhxtOxMnVYxKiFkwCw6nZfaMJItgMS0=;
        fh=Ily0hk/b8nZsP6X/xk//l8wfIz76TPmG9zN2NsyrAEw=;
        b=hFhsk+bpY/E9aIeMxOGkxpwECI3f0av5zPkeLa+9xQNkuQ+5LFUCw/eNhAsCS4Y5rt
         s5OLCMebK0GBz5ehF5H3x0VEXa3kBilRyX3mg8SvXvLPWN4o6xmZv280Gm9vF19fvoff
         Dt7a/XGxn0vDV6xgVIyt4Foz+y71UuaPnrP6L75TJLERzNnFUQUpoySjtjEN6xiIOOy1
         J1otgRtOhydbBq3QOK8x+eJdunW8ioWgieGNMF83ebEDQsHHYZXvoCxekNGDiK/T7qVn
         dAHKp6e072H95vsggVzk+b5yTXBoX+ouupPbWv2Zm9cASzraq9xXIu+eMk04AnWGfKWZ
         cSCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=n2nv20t+;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754899873; x=1755504673; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=dx5IdvRFavjqmhxtOxMnVYxKiFkwCw6nZfaMJItgMS0=;
        b=aZeJaLhVzOFD3uDwgAALA+AG6Pvqs81IWeBYwO3u01aZ1GU8UkNoGmJRO/gGC627j/
         HYIIYwbSiUqVdMWMMI23EQR3WjEk/NAWLMt/b2MftGRC/DIYtdIswHQeI2WN574uSUSu
         hLrxRn0xv0dUrxH999QhI2WXYvztBhCnl2WCq44cQ3BeDHzI3HL6pM+obd7x8MjNVru0
         QGhTTHdiIuldsAJO/0BR/fXdZzizEgDQiGSxb8l/5boa9+0fMFOczUukMaZFFkkaKqlP
         LEdad/b36vL7i+mbfVrFNnCogsM032BQegw/d980eYJ3RH6UU7Px3Y9mj1d0yTD8nzg+
         53cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754899873; x=1755504673;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dx5IdvRFavjqmhxtOxMnVYxKiFkwCw6nZfaMJItgMS0=;
        b=YLpe7Mm12lIgMbigu1+ogrFlgmRsxEB5Kf1rfLAR56s/5s5ohhYu5+su2J9cEIHezy
         j0sXqp7+ZjEavuVVwvZZ9HByFryTJvAxFq5ZPR/oj0xOXAXOZGjSJbiBhNNeefePMJ0p
         1QoIB6/hPqiuhoDxf9chU+6kvZXVD+HFUyGPQRvq+W8oD6zppxj8SIlJWtltmtMazsqC
         J2bGwcMLIki7t/ObAEtTBZ3bQK4QqN+XxoY97Gnx+CAQJsSVP/AEv3XZcgh5vIz5jS/m
         9fZ4JadhrtTs9ipF6ghnQUo04LnbWWhXOLQnkC9dslb8UDBt6/vXX04tkG16LivudmJa
         hYfQ==
X-Forwarded-Encrypted: i=2; AJvYcCUBkyG+hacvYir832tTbAGyQRoqSZ5hGCuKCEichdCuYVBjbS5soMFcoSUvEYaDnttLuOEBhw==@lfdr.de
X-Gm-Message-State: AOJu0YwwVPiwzODVt2pOb6cRTpKa5gOyqrgX/uvK0vtjhNBXb2sUaI/Z
	NMktAx7OPbtFxxCU6y72g+y3Vhqp3hpcNlp5nMvNkWeXa33qmCdYb/8Q
X-Google-Smtp-Source: AGHT+IGjKLM8vwDSbbcnFVaO2sDT2NC8mp99X1OVOybK+ETdpfOxfep/BwxiezeUDEg6RkwlRhAkPA==
X-Received: by 2002:a05:6902:6c0b:b0:e8e:2535:5ce with SMTP id 3f1490d57ef6-e904b658476mr13062886276.34.1754899872906;
        Mon, 11 Aug 2025 01:11:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc16ajBWhfiaq+Ne5iF5kx0UiOL3Rq0H8TQZVy7p7mxag==
Received: by 2002:a25:ec0b:0:b0:e90:47aa:a04c with SMTP id 3f1490d57ef6-e91729233edls197177276.1.-pod-prod-07-us;
 Mon, 11 Aug 2025 01:11:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXjC7V4SENIPxmFMfHQtaTwwY4xbiJnsjKXrMmu3xL5Ae4mpXkxW0wHJz/vomoxIhQpvX1V1LVwV9E=@googlegroups.com
X-Received: by 2002:a05:6902:26c9:b0:e90:3cfb:2b20 with SMTP id 3f1490d57ef6-e904b5501b5mr12903933276.10.1754899871486;
        Mon, 11 Aug 2025 01:11:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754899871; cv=none;
        d=google.com; s=arc-20240605;
        b=Y+DxoYmCZfeMahdehWHeh5xDtfPF9QS1uRHELPh1BS0ore/QcAZWk7v0D/3mAM1aZ3
         IiA3NQYc/gLJu9X1ZjDpeL+rF0DVoPJiadm7G3KoK4ZRLo2fcjb4EWPvlYY2oHUPZKVz
         0vIvJrNEOlEVpeJxQZaGUhURYNGvW2dOZD0sx4pYSv19axLvp5hmPFRXe//TQ+Enp2jw
         Xp1icfuG8TH62a1bW/ql1BbrT74vMlaFCBItMjayiTFSmJfOch+6hII5IfG/FobyiZLa
         MeC8YIMnC/eKo5rkM9XD9fXZ0KeBFYhHnuo23vTjgPwpSci5UnQmQWSD++Ni/np7D/q1
         qI0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ikirbhZh3RT0runx5vWzABxjEiE566Wspw/E/T7F2Pk=;
        fh=gnVSzXXSy4qK///OqQITMo9DTimSoa5cYZv+8GlStL8=;
        b=XQipuRsHQSqoLUIklSZPrN1/ejKhdqz66RYFvZRe5lwCnXGCVT5RvR+i61koESowQA
         KxKsatEKMArBWAgKnuwJN1pc3nL6sf2ggDU1QBWUr4gvNad2UFWrbnflQZeVhab9/QBM
         I8GngFk88tx/BdHBe9cGmy0R9IwJYq0QpY3QXuQkPwaNEM7x+R9Sx6qiKAkfAbd8S6Di
         DyMMh75P50TXuip9kkQnJNjnxr2kE7HSNjrQEP0Hme4pdWGjoBksbVJ746q/dsFgsQrc
         LIVkuNHue9zf1p6S5lCcBnqghC5lX9HqOiQSxfvmHQbRh8l3MJE+XCzSBVe0dGyyGcAa
         rO7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=n2nv20t+;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e8fd37f8435si88841276.2.2025.08.11.01.11.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Aug 2025 01:11:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id D2CD45C5E02;
	Mon, 11 Aug 2025 08:11:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id ED3FBC4CEED;
	Mon, 11 Aug 2025 08:10:58 +0000 (UTC)
Date: Mon, 11 Aug 2025 11:10:55 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Dennis Zhou <dennis@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, x86@kernel.org,
	Borislav Petkov <bp@alien8.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Andy Lutomirski <luto@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Tejun Heo <tj@kernel.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Christoph Lameter <cl@gentwo.org>,
	David Hildenbrand <david@redhat.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	"H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com,
	Ard Biesheuvel <ardb@kernel.org>, linux-kernel@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Thomas Huth <thuth@redhat.com>, John Hubbard <jhubbard@nvidia.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Michal Hocko <mhocko@suse.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, linux-mm@kvack.org,
	"Kirill A. Shutemov" <kas@kernel.org>,
	Oscar Salvador <osalvador@suse.de>, Jane Chu <jane.chu@oracle.com>,
	Gwan-gyeong Mun <gwan-gyeong.mun@intel.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@linux.ibm.com>,
	Joerg Roedel <joro@8bytes.org>,
	Alistair Popple <apopple@nvidia.com>,
	Joao Martins <joao.m.martins@oracle.com>,
	linux-arch@vger.kernel.org, stable@vger.kernel.org
Subject: Re: [PATCH V4 mm-hotfixes 2/3] mm: introduce and use
 {pgd,p4d}_populate_kernel()
Message-ID: <aJmlj3bG6qb60Me0@kernel.org>
References: <20250811053420.10721-1-harry.yoo@oracle.com>
 <20250811053420.10721-3-harry.yoo@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250811053420.10721-3-harry.yoo@oracle.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=n2nv20t+;       spf=pass
 (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Mon, Aug 11, 2025 at 02:34:19PM +0900, Harry Yoo wrote:
> Introduce and use {pgd,p4d}_populate_kernel() in core MM code when
> populating PGD and P4D entries for the kernel address space.
> These helpers ensure proper synchronization of page tables when
> updating the kernel portion of top-level page tables.
> 
> Until now, the kernel has relied on each architecture to handle
> synchronization of top-level page tables in an ad-hoc manner.
> For example, see commit 9b861528a801 ("x86-64, mem: Update all PGDs for
> direct mapping and vmemmap mapping changes").
> 
> However, this approach has proven fragile for following reasons:
> 
>   1) It is easy to forget to perform the necessary page table
>      synchronization when introducing new changes.
>      For instance, commit 4917f55b4ef9 ("mm/sparse-vmemmap: improve memory
>      savings for compound devmaps") overlooked the need to synchronize
>      page tables for the vmemmap area.
> 
>   2) It is also easy to overlook that the vmemmap and direct mapping areas
>      must not be accessed before explicit page table synchronization.
>      For example, commit 8d400913c231 ("x86/vmemmap: handle unpopulated
>      sub-pmd ranges")) caused crashes by accessing the vmemmap area
>      before calling sync_global_pgds().
> 
> To address this, as suggested by Dave Hansen, introduce _kernel() variants
> of the page table population helpers, which invoke architecture-specific
> hooks to properly synchronize page tables. These are introduced in a new
> header file, include/linux/pgalloc.h, so they can be called from common code.
> 
> They reuse existing infrastructure for vmalloc and ioremap.
> Synchronization requirements are determined by ARCH_PAGE_TABLE_SYNC_MASK,
> and the actual synchronization is performed by arch_sync_kernel_mappings().
> 
> This change currently targets only x86_64, so only PGD and P4D level
> helpers are introduced. In theory, PUD and PMD level helpers can be added
> later if needed by other architectures.
> 
> Currently this is a no-op, since no architecture sets
> PGTBL_{PGD,P4D}_MODIFIED in ARCH_PAGE_TABLE_SYNC_MASK.
> 
> Cc: <stable@vger.kernel.org>
> Fixes: 8d400913c231 ("x86/vmemmap: handle unpopulated sub-pmd ranges")
> Suggested-by: Dave Hansen <dave.hansen@linux.intel.com>
> Signed-off-by: Harry Yoo <harry.yoo@oracle.com>

Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>

> ---
>  include/linux/pgalloc.h | 24 ++++++++++++++++++++++++
>  include/linux/pgtable.h |  4 ++--
>  mm/kasan/init.c         | 12 ++++++------
>  mm/percpu.c             |  6 +++---
>  mm/sparse-vmemmap.c     |  6 +++---
>  5 files changed, 38 insertions(+), 14 deletions(-)
>  create mode 100644 include/linux/pgalloc.h
> 
> diff --git a/include/linux/pgalloc.h b/include/linux/pgalloc.h
> new file mode 100644
> index 000000000000..290ab864320f
> --- /dev/null
> +++ b/include/linux/pgalloc.h
> @@ -0,0 +1,24 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef _LINUX_PGALLOC_H
> +#define _LINUX_PGALLOC_H
> +
> +#include <linux/pgtable.h>
> +#include <asm/pgalloc.h>
> +
> +static inline void pgd_populate_kernel(unsigned long addr, pgd_t *pgd,
> +				       p4d_t *p4d)
> +{
> +	pgd_populate(&init_mm, pgd, p4d);
> +	if (ARCH_PAGE_TABLE_SYNC_MASK & PGTBL_PGD_MODIFIED)
> +		arch_sync_kernel_mappings(addr, addr);
> +}
> +
> +static inline void p4d_populate_kernel(unsigned long addr, p4d_t *p4d,
> +				       pud_t *pud)
> +{
> +	p4d_populate(&init_mm, p4d, pud);
> +	if (ARCH_PAGE_TABLE_SYNC_MASK & PGTBL_P4D_MODIFIED)
> +		arch_sync_kernel_mappings(addr, addr);
> +}
> +
> +#endif /* _LINUX_PGALLOC_H */
> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> index ba699df6ef69..0cf5c6c3e483 100644
> --- a/include/linux/pgtable.h
> +++ b/include/linux/pgtable.h
> @@ -1469,8 +1469,8 @@ static inline void modify_prot_commit_ptes(struct vm_area_struct *vma, unsigned
>  
>  /*
>   * Architectures can set this mask to a combination of PGTBL_P?D_MODIFIED values
> - * and let generic vmalloc and ioremap code know when arch_sync_kernel_mappings()
> - * needs to be called.
> + * and let generic vmalloc, ioremap and page table update code know when
> + * arch_sync_kernel_mappings() needs to be called.
>   */
>  #ifndef ARCH_PAGE_TABLE_SYNC_MASK
>  #define ARCH_PAGE_TABLE_SYNC_MASK 0
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index ced6b29fcf76..8fce3370c84e 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -13,9 +13,9 @@
>  #include <linux/mm.h>
>  #include <linux/pfn.h>
>  #include <linux/slab.h>
> +#include <linux/pgalloc.h>
>  
>  #include <asm/page.h>
> -#include <asm/pgalloc.h>
>  
>  #include "kasan.h"
>  
> @@ -191,7 +191,7 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
>  			pud_t *pud;
>  			pmd_t *pmd;
>  
> -			p4d_populate(&init_mm, p4d,
> +			p4d_populate_kernel(addr, p4d,
>  					lm_alias(kasan_early_shadow_pud));
>  			pud = pud_offset(p4d, addr);
>  			pud_populate(&init_mm, pud,
> @@ -212,7 +212,7 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
>  			} else {
>  				p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
>  				pud_init(p);
> -				p4d_populate(&init_mm, p4d, p);
> +				p4d_populate_kernel(addr, p4d, p);
>  			}
>  		}
>  		zero_pud_populate(p4d, addr, next);
> @@ -251,10 +251,10 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
>  			 * puds,pmds, so pgd_populate(), pud_populate()
>  			 * is noops.
>  			 */
> -			pgd_populate(&init_mm, pgd,
> +			pgd_populate_kernel(addr, pgd,
>  					lm_alias(kasan_early_shadow_p4d));
>  			p4d = p4d_offset(pgd, addr);
> -			p4d_populate(&init_mm, p4d,
> +			p4d_populate_kernel(addr, p4d,
>  					lm_alias(kasan_early_shadow_pud));
>  			pud = pud_offset(p4d, addr);
>  			pud_populate(&init_mm, pud,
> @@ -273,7 +273,7 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
>  				if (!p)
>  					return -ENOMEM;
>  			} else {
> -				pgd_populate(&init_mm, pgd,
> +				pgd_populate_kernel(addr, pgd,
>  					early_alloc(PAGE_SIZE, NUMA_NO_NODE));
>  			}
>  		}
> diff --git a/mm/percpu.c b/mm/percpu.c
> index d9cbaee92b60..a56f35dcc417 100644
> --- a/mm/percpu.c
> +++ b/mm/percpu.c
> @@ -3108,7 +3108,7 @@ int __init pcpu_embed_first_chunk(size_t reserved_size, size_t dyn_size,
>  #endif /* BUILD_EMBED_FIRST_CHUNK */
>  
>  #ifdef BUILD_PAGE_FIRST_CHUNK
> -#include <asm/pgalloc.h>
> +#include <linux/pgalloc.h>
>  
>  #ifndef P4D_TABLE_SIZE
>  #define P4D_TABLE_SIZE PAGE_SIZE
> @@ -3134,13 +3134,13 @@ void __init __weak pcpu_populate_pte(unsigned long addr)
>  
>  	if (pgd_none(*pgd)) {
>  		p4d = memblock_alloc_or_panic(P4D_TABLE_SIZE, P4D_TABLE_SIZE);
> -		pgd_populate(&init_mm, pgd, p4d);
> +		pgd_populate_kernel(addr, pgd, p4d);
>  	}
>  
>  	p4d = p4d_offset(pgd, addr);
>  	if (p4d_none(*p4d)) {
>  		pud = memblock_alloc_or_panic(PUD_TABLE_SIZE, PUD_TABLE_SIZE);
> -		p4d_populate(&init_mm, p4d, pud);
> +		p4d_populate_kernel(addr, p4d, pud);
>  	}
>  
>  	pud = pud_offset(p4d, addr);
> diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
> index 41aa0493eb03..dbd8daccade2 100644
> --- a/mm/sparse-vmemmap.c
> +++ b/mm/sparse-vmemmap.c
> @@ -27,9 +27,9 @@
>  #include <linux/spinlock.h>
>  #include <linux/vmalloc.h>
>  #include <linux/sched.h>
> +#include <linux/pgalloc.h>
>  
>  #include <asm/dma.h>
> -#include <asm/pgalloc.h>
>  #include <asm/tlbflush.h>
>  
>  #include "hugetlb_vmemmap.h"
> @@ -229,7 +229,7 @@ p4d_t * __meminit vmemmap_p4d_populate(pgd_t *pgd, unsigned long addr, int node)
>  		if (!p)
>  			return NULL;
>  		pud_init(p);
> -		p4d_populate(&init_mm, p4d, p);
> +		p4d_populate_kernel(addr, p4d, p);
>  	}
>  	return p4d;
>  }
> @@ -241,7 +241,7 @@ pgd_t * __meminit vmemmap_pgd_populate(unsigned long addr, int node)
>  		void *p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
>  		if (!p)
>  			return NULL;
> -		pgd_populate(&init_mm, pgd, p);
> +		pgd_populate_kernel(addr, pgd, p);
>  	}
>  	return pgd;
>  }
> -- 
> 2.43.0
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJmlj3bG6qb60Me0%40kernel.org.
