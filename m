Return-Path: <kasan-dev+bncBDZMFEH3WYFBBMOM43CAMGQE44T3SSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 46772B2017A
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 10:13:39 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-70771983a52sf88318536d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 01:13:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754900018; cv=pass;
        d=google.com; s=arc-20240605;
        b=RATZMkQzxFuJ9a8UODGC7rQQ4ogKkNNpK7pxY1ZWJqZB+h8ZgT6y8m2goyjyM5Qi60
         RcHwIfhg1YZWjW/AMZlqD1nxV5OITPrN4NsXwpOwpWnJT+wixNUVw6V1Wfb4NdPKMSan
         s1vnwSP4O0QGv0swKPT6TSeRAAYwDrv5YNnHX69Rtx047YGzMB2oLtyRWzWbHFbmTk3H
         5TyBiLkH5b1saT+LgRfyuwGGRbP/aHuZHjdjJuURvRKzISzMfIX/1LE54agwZkjgQx4J
         FlQOGT2ijJkiqZKH3tLSlf4fH8oJnxFRSznve9SIYAoLuisrwCrdX65riv+1eGAd2fVj
         Lfww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=DSUtjvMdd67AOm9Rf8Ap2duee1DHFmndONIXX5bf2vI=;
        fh=y9sTyj6zDi15WYdsxDSHKHCBycj6wuYg7gVoItJcO7I=;
        b=F1RuP1J/nwlffOCloYoU0e02x3XUJgj+qJkvBVeljZtAOw7fogTLm21bu/nSDTt780
         H2M1su2ON5GHjC6Mdv7So9LjN8DO4HVefbtnzWvTBDpDTASRr3rpYunZ5ZvkUiQQHJWX
         0yJ/7DjV1msAvdsEsQjpQ8m7VEiQIxqaVreiiABmsksEbCRDhfNKUWmNXz8eqQJeBWq4
         E9lzwV/2w6LyVsf2HN/dJia2RxEhS0/s/TOsO+FgK8oJj4FASwY7uzlMc0x9zb4hSa32
         4dDAcwpCbrEj3TxNX+tdaobYP7dYqDIcCEMOAUSIbEFNRjBA9jleoo3d6s2/tB/aOAup
         /nBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NabTfTob;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754900018; x=1755504818; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=DSUtjvMdd67AOm9Rf8Ap2duee1DHFmndONIXX5bf2vI=;
        b=T4cP0NZw1anqTM7cGpe3ybRlY3xuuWACbhZ580vGhhEfabwzNjIE6nvsdf57c0aBXg
         oOnsNWU/b7KrlX/TG6hE34SHpTI9yVrnNuUg6kpWK0XPptH8Ym1Tb1iWAU1TU2CGNxQv
         VlXMv5P2mb+o4TjUlrwU569NBIpNaqIEILDqMfBgeXMtMo3aABMfIIwUffpMPiSh7LEk
         IhcnjPavBAXAGtZKVwj6UtQIjp2VMP7+75IHfibLiIm67GHR9e2QftuHNBkN0flmlMy3
         k1yJgOMd9bqN3+bX5eaxY7iUPnA05VjLrfCzLSf6cmkrbhjVI3jGaUfRJTGusoLEQ7Xz
         TfxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754900018; x=1755504818;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DSUtjvMdd67AOm9Rf8Ap2duee1DHFmndONIXX5bf2vI=;
        b=BbiAPOw7qp3a3HjekreouOXFkELL8zBQPR7mvU2qq7BDwZb5Wasuq01cBD6adet8F8
         GnY6WLW9Pe1QkU4rmMoannApjXrNgv/emxfje9oRrkJcpe344fiNnYl0Z9huOeM5mmgr
         U5BsO7X8YxBrJO6Q94BWuzR+c4q2mDvd0vDDS6tAC+ZTk9LrjLQ5b7q9MmyGHp/+IprV
         FxyRFdQxv+TAEJ7Tz+c0ZOCPA0F3gMlxkd74LxBfduT8LZYikmJyuGvFMNupg7a0bLou
         e/uJ0n/bQ7IA/+YBXyDjTRoTLl3yJH4xZmMEtEjxoGI1g1D5RC2tfoNEd5T8sbC1fi6N
         n+aQ==
X-Forwarded-Encrypted: i=2; AJvYcCVSWus+XnaVb78ruEK3acxLR6AAIFMPuI8H0qmoV1+KxHATsQL6p5RMTHAqEYSWXibpsbjWLg==@lfdr.de
X-Gm-Message-State: AOJu0YxQadaAN+4/qqHmUUyAbiKSWVwbzgJUlX5q0dGRUhCrFEv8AT3C
	oorebzfvTeUG0xeLsU6zciLvVio2rbtdt6sgjvI983Fxux9lD8XSWICq
X-Google-Smtp-Source: AGHT+IEOQHTvbVCeXGU2KkuWj4Zwb+/RDOdEO9782pU2cUnvL7m8kfh9hI7WVvS4BVfOSq28Zg7jnQ==
X-Received: by 2002:a05:6214:623:b0:707:7090:5400 with SMTP id 6a1803df08f44-7099a3021abmr143744676d6.17.1754900018055;
        Mon, 11 Aug 2025 01:13:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZceEiClJRAnDUWrOIpuZWGx9oLsxkLVgruXoWwN5XxLAA==
Received: by 2002:a05:6214:4015:b0:707:56ac:be47 with SMTP id
 6a1803df08f44-709880b9e29ls61485496d6.0.-pod-prod-01-us; Mon, 11 Aug 2025
 01:13:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXkAVEauq+8cLjWWsnyeZu05m51+7T7RrBDQ2b71J/8v/HbvATKSSx3kCHmGCntFGkwOcPlkZFSSfc=@googlegroups.com
X-Received: by 2002:a05:6102:5985:b0:4e7:bf03:cd79 with SMTP id ada2fe7eead31-5060d29f617mr3932969137.5.1754900017000;
        Mon, 11 Aug 2025 01:13:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754900016; cv=none;
        d=google.com; s=arc-20240605;
        b=Zjcpn5fb1+TDKS8gxEom6FmWozCvwRJbSMlEiEZ/DkihHa7LZ3tJ+I4lgQldVFoNvu
         SSEv6Ep+CPfTt2e5luFqpikV3E06ewfA4gUbij3UEe45ogtqsStfXOj1O0hZJ8BnnU2+
         YOgojRQgXxBQsF0i8/daiYwYPAwFUnIzOUwvcImURBq4e/N24xWaACgUeilxoKvTB1+L
         x7C18PjgOnOzdJ45WaX33y4sX/k9xhVa4Il39xCLN+F3gtODFIX8XoFKXlyjTCb0/7TS
         0bWaZs28h3Y7kiFbHfI1dhEkWWyzvGdE+u/tus6jWOwt0o8BzTS6nBISTQ1h7et47d60
         joMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=f3sDw793CPWAS611HTtLYr5SWDtvHzlJoLtJhvY+jFs=;
        fh=gnVSzXXSy4qK///OqQITMo9DTimSoa5cYZv+8GlStL8=;
        b=XnsdAob8vNk/4rZmcLM++CZ3xjPveKKIM0bPpWgXotQqrjMy+peE9rtgkRE1nNe7HB
         +/ZaCV6QAm+qtTEpngwluYrBXiAEHQK9RK+m28nMGKPbOMGcR1f7M9FgHi7rcItmEdx4
         0yiW0Ws0YeupUEpEwpfd+Jt65s8kqtfaVwIdsoEB4YTX7AP1PSRS9sLX3Dp197WnAyb1
         9a9nwJwntjg47cw+HFRL1iRG5IJKr90SXSQUnizVnReN93W7N1VA9yrGV+VxcaXGvyCM
         XLh2INvhPPRCeAP3tl4bfqiVZz+HZHzoupZTWsoXMJvWK4qfb/h04eR3FdhAwkfGD4Tp
         bOsA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NabTfTob;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-539b01ae82bsi388311e0c.2.2025.08.11.01.13.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Aug 2025 01:13:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 1ADCA601D1;
	Mon, 11 Aug 2025 08:13:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C3FDBC4CEED;
	Mon, 11 Aug 2025 08:13:22 +0000 (UTC)
Date: Mon, 11 Aug 2025 11:13:19 +0300
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
Subject: Re: [PATCH V4 mm-hotfixes 3/3] x86/mm/64: define
 ARCH_PAGE_TABLE_SYNC_MASK and arch_sync_kernel_mappings()
Message-ID: <aJmmH40sV0Ig8YFr@kernel.org>
References: <20250811053420.10721-1-harry.yoo@oracle.com>
 <20250811053420.10721-4-harry.yoo@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250811053420.10721-4-harry.yoo@oracle.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NabTfTob;       spf=pass
 (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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

On Mon, Aug 11, 2025 at 02:34:20PM +0900, Harry Yoo wrote:
> Define ARCH_PAGE_TABLE_SYNC_MASK and arch_sync_kernel_mappings() to ensure
> page tables are properly synchronized when calling p*d_populate_kernel().
> It is inteneded to synchronize page tables via pgd_pouplate_kernel() when
> 5-level paging is in use and via p4d_pouplate_kernel() when 4-level paging
> is used.
> 
> This fixes intermittent boot failures on systems using 4-level paging
> and a large amount of persistent memory:
> 
>   BUG: unable to handle page fault for address: ffffe70000000034
>   #PF: supervisor write access in kernel mode
>   #PF: error_code(0x0002) - not-present page
>   PGD 0 P4D 0
>   Oops: 0002 [#1] SMP NOPTI
>   RIP: 0010:__init_single_page+0x9/0x6d
>   Call Trace:
>    <TASK>
>    __init_zone_device_page+0x17/0x5d
>    memmap_init_zone_device+0x154/0x1bb
>    pagemap_range+0x2e0/0x40f
>    memremap_pages+0x10b/0x2f0
>    devm_memremap_pages+0x1e/0x60
>    dev_dax_probe+0xce/0x2ec [device_dax]
>    dax_bus_probe+0x6d/0xc9
>    [... snip ...]
>    </TASK>
> 
> It also fixes a crash in vmemmap_set_pmd() caused by accessing vmemmap
> before sync_global_pgds() [1]:
> 
>   BUG: unable to handle page fault for address: ffffeb3ff1200000
>   #PF: supervisor write access in kernel mode
>   #PF: error_code(0x0002) - not-present page
>   PGD 0 P4D 0
>   Oops: Oops: 0002 [#1] PREEMPT SMP NOPTI
>   Tainted: [W]=WARN
>   RIP: 0010:vmemmap_set_pmd+0xff/0x230
>    <TASK>
>    vmemmap_populate_hugepages+0x176/0x180
>    vmemmap_populate+0x34/0x80
>    __populate_section_memmap+0x41/0x90
>    sparse_add_section+0x121/0x3e0
>    __add_pages+0xba/0x150
>    add_pages+0x1d/0x70
>    memremap_pages+0x3dc/0x810
>    devm_memremap_pages+0x1c/0x60
>    xe_devm_add+0x8b/0x100 [xe]
>    xe_tile_init_noalloc+0x6a/0x70 [xe]
>    xe_device_probe+0x48c/0x740 [xe]
>    [... snip ...]
> 
> Cc: <stable@vger.kernel.org>
> Fixes: 8d400913c231 ("x86/vmemmap: handle unpopulated sub-pmd ranges")
> Closes: https://lore.kernel.org/linux-mm/20250311114420.240341-1-gwan-gyeong.mun@intel.com [1]
> Suggested-by: Dave Hansen <dave.hansen@linux.intel.com>
> Signed-off-by: Harry Yoo <harry.yoo@oracle.com>

Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>

> ---
>  arch/x86/include/asm/pgtable_64_types.h | 3 +++
>  arch/x86/mm/init_64.c                   | 5 +++++
>  2 files changed, 8 insertions(+)
> 
> diff --git a/arch/x86/include/asm/pgtable_64_types.h b/arch/x86/include/asm/pgtable_64_types.h
> index 4604f924d8b8..7eb61ef6a185 100644
> --- a/arch/x86/include/asm/pgtable_64_types.h
> +++ b/arch/x86/include/asm/pgtable_64_types.h
> @@ -36,6 +36,9 @@ static inline bool pgtable_l5_enabled(void)
>  #define pgtable_l5_enabled() cpu_feature_enabled(X86_FEATURE_LA57)
>  #endif /* USE_EARLY_PGTABLE_L5 */
>  
> +#define ARCH_PAGE_TABLE_SYNC_MASK \
> +	(pgtable_l5_enabled() ? PGTBL_PGD_MODIFIED : PGTBL_P4D_MODIFIED)
> +
>  extern unsigned int pgdir_shift;
>  extern unsigned int ptrs_per_p4d;
>  
> diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
> index 76e33bd7c556..a78b498c0dc3 100644
> --- a/arch/x86/mm/init_64.c
> +++ b/arch/x86/mm/init_64.c
> @@ -223,6 +223,11 @@ static void sync_global_pgds(unsigned long start, unsigned long end)
>  		sync_global_pgds_l4(start, end);
>  }
>  
> +void arch_sync_kernel_mappings(unsigned long start, unsigned long end)
> +{
> +	sync_global_pgds(start, end);
> +}
> +
>  /*
>   * NOTE: This function is marked __ref because it calls __init function
>   * (alloc_bootmem_pages). It's safe to do it ONLY when after_bootmem == 0.
> -- 
> 2.43.0
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJmmH40sV0Ig8YFr%40kernel.org.
