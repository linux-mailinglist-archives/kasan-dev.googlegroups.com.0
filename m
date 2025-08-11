Return-Path: <kasan-dev+bncBDZMFEH3WYFBB4GI43CAMGQEEPBPXSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F26AB2014B
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 10:06:11 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-76bd2543889sf5788366b3a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 01:06:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754899569; cv=pass;
        d=google.com; s=arc-20240605;
        b=F2DxH1Fy/kbBgDgOxy072ffdHf0n4ireB+8mI2gyCfXuVjCK5+s+mjWycjwY2J1Cmr
         doCKTDq1gDLRSr49h6Y6dvNejhKPDtO0IChmgC+dKzm3SyxblFSVaZEogUy34Pd5jw+I
         tHei0T2BgwMvZgm4z2MDQgsut9ceRvN+ItrESgVjoufrryesNL4neWJFFmETPHwJyek5
         CA2Tbw88QsWwZRInv64e1Wi/kSGYDFxv8MD71XkpUWPRK+txBVR8pmQcR6u+KbtTjLYg
         C3mDwQiCVdeYQUmO+/4UlKu5VIqrH48kw+0mZfkPOkzslNxzg4GZD1WCG0P+QayXdDJh
         Na0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=VSSdwURSwinlSGnVH1C3EOvTLIGmEJ2TCltH3utojNw=;
        fh=gDIK7+IMCph76p1omDc+0u3tWvHQxiM1Z0QYoUlEzNI=;
        b=PoLBCkbk3i+BUvg+RDmmPNa5GAYY7QdOacQb2YSBEyeHmYYb23xZ7fMWMNNFEU//VY
         Qpkg4N1Eq94qSzOBF+vfgieB1IEnd1xkmyeS/sP5Tx2uUQVmhclI9lYqju3+nWyh0HcF
         bQF17SbNTrZcx778h8W56auCgF4m3JrmSx5qr+boC5bbEk1HUlQpN1xUL9+saT4gY01o
         LDa6Xv6mNcMwiqT8jpaokdHi2QjcabvtSKkNWFz3mZO+Fr1vEgcvrtjIeG6K58Teo9wD
         M68YnCr/3fSGkLsJGJtWzvkYP8C1WcpPZmMlHmnExx6cnGOw6ZiHRx/3+ovkLvmAoUwF
         Vb+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="FyessW4/";
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754899569; x=1755504369; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=VSSdwURSwinlSGnVH1C3EOvTLIGmEJ2TCltH3utojNw=;
        b=Gnd89jHVOiRxjl0CUWPf384mqVMDAjLjOv0nZC56lgx2IpIul2g67uBS569+Cuphfj
         vUpZYIDlEhae7lw+ZLouTO5oueb6UQpiabGi7YB7T7SRtKjmM8kp8mEaEBdUyCpWA0hX
         ifWf36vh6eGaAkzF+fDVVthMXcJTbqVoYIBenL1ddCM28ksfo3To+sBWwMSzLRPhJYVt
         ozcsjBOzh7bhJVH5JsK0rDLa71By0E77KSvOdrQkWHIC3rNjx+moY6+GsvzxlvzxDArV
         gQQWSOrx0bfwOdmGvlJMl+FGHunUDEmjRzQRJvxhQyWM1e4c1aiyrcOZZvWG/VSXvkaL
         mW2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754899569; x=1755504369;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VSSdwURSwinlSGnVH1C3EOvTLIGmEJ2TCltH3utojNw=;
        b=WceVcgX87icFPMwzi1lrekGSmZ7Siewjg8rcnSdAm4BXC2tDmwOL9c016vPUHRaTDT
         d9ZDi+P4EFvO1dbMLFMjrefxO5g7WzUmvSXSpQVl+CMM5fHctUD7L/pn/CnycVCUyu1x
         TFQ9LBQHcPW84EP6FTUEs2lcjxQ8Tw+I7ZCrqHJ3gYF+CT6Xy/AVzYgsKgPDvghmSk+6
         Ulp1r36+VbZILC26QdzM0n+UobpIeyD4457k8Qun/bBSkm5puvDHXNEdKbBgeDSMm7sb
         XHcg10EnUIOB01ziJYHo4XSnprJDin/QLF5+/5fM9Kz5eFZfrSnX7zx8HEMWo45iVI2U
         v9wg==
X-Forwarded-Encrypted: i=2; AJvYcCXNzepoKvfP1dgTcD7he4NlS+qgcMglldSr6EgQ46z94U0tJWHecG/sB4XzOf5O0VvLQOnzfA==@lfdr.de
X-Gm-Message-State: AOJu0YzMRniODSwT0oN/MhFBsgv9sJj+cUoGqf/yNWV04qGWy3Q4zOZr
	hfBAMk5kn5jvsue50Tm1WBMjvDJQrzihrmzXpcmWzwIdFr2tZpdh3Td6
X-Google-Smtp-Source: AGHT+IHAk1sG0N36NVUXBMxb9NZOgzbh75CWbxGQfHuuJNeJtxCegb7wAwoj9eeUN2p9R301fsxx5w==
X-Received: by 2002:a05:6a00:1409:b0:76b:f7af:c47d with SMTP id d2e1a72fcca58-76c460aa949mr15917460b3a.4.1754899569040;
        Mon, 11 Aug 2025 01:06:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfbPkNKNlNXtR1Ou575OxiZUYSCtKsaxQK3/8b2V8BnbA==
Received: by 2002:a05:6a00:2493:b0:730:8b18:e9ff with SMTP id
 d2e1a72fcca58-76c36d44eb1ls3859302b3a.0.-pod-prod-06-us; Mon, 11 Aug 2025
 01:06:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXBoq9ZL08FuKOmn8wfrX689rdCpcNuxrD5l6ihg111HgpRbezGcstuuP6T+TPdHiFkL30hEYXRsRg=@googlegroups.com
X-Received: by 2002:a05:6a00:1409:b0:76b:f7af:c47d with SMTP id d2e1a72fcca58-76c460aa949mr15917371b3a.4.1754899567650;
        Mon, 11 Aug 2025 01:06:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754899567; cv=none;
        d=google.com; s=arc-20240605;
        b=dZQL9jxUIW3BrR8iPB0MoQ8JRB/rzOog+tCis1NK2O1wnNdZZiqLYI7sFJrbRQcmW8
         kmc8YEHQCxNUp6HaVJLIqEI2CYN5eoSPJJZGm795iZXvga3NY1wJWkW1f0B2ZWB12+JF
         Iof2F5ZHARU+poPNqE8yrqudJnWh7BuhhG1NquTo4NBX71FqwlwnNsdvuJi8UeGXCcCx
         FgCCL+15a8mwIaw9Dc2INglQsYYShuBvilpTd+kHC5t23KP/FMx4aBRsIsMG12lu6n2B
         QPXfk6wUHMWAgYmM6hXMrgfNHiBoBbrw6EzbBaNltKG438eyfg30pIu9qha+rHsGlCUt
         rQpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=wkhwaYsOlNpQnkvKInIJcg+qBvI8c4bNMxUHogr91So=;
        fh=gnVSzXXSy4qK///OqQITMo9DTimSoa5cYZv+8GlStL8=;
        b=GpeKqSe2W+UDjU4wyVi4PPv3E1tkqIPzV6qEr5DjMJ7ffgE2Jnl9rLATtF6el9HFxk
         6cpxDtt6rYy5bTyt2HxL3neSjuy9LaJLmPzbBvUf0JG55jj/JLaYPj1O/JB1CF6sHETm
         ALpYiEhCsv5oaCtGZxeRCB226nhFZpClOH9KkcTg3sVZi58FHnP9gBEOid1hrrE0udb3
         r3An9ajh+dY5FzMJ0hFO203tYGAYm7o8tpp1DVg4iqKvsR1PGm8sQ/AUdnjybbDKxmSG
         d5NKIWvDJ1gw981iZlflO9cpQ9inL0qtKz6DzTGx6YWvMcX6nvLCY4h18Zqtm/7hMsbP
         57xA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="FyessW4/";
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76bccffbb17si496563b3a.3.2025.08.11.01.06.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Aug 2025 01:06:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id D57F4A56AA5;
	Mon, 11 Aug 2025 08:06:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 75C29C4CEED;
	Mon, 11 Aug 2025 08:05:54 +0000 (UTC)
Date: Mon, 11 Aug 2025 11:05:51 +0300
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
Subject: Re: [PATCH V4 mm-hotfixes 1/3] mm: move page table sync declarations
 to linux/pgtable.h
Message-ID: <aJmkX3JBhH3F0PEC@kernel.org>
References: <20250811053420.10721-1-harry.yoo@oracle.com>
 <20250811053420.10721-2-harry.yoo@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250811053420.10721-2-harry.yoo@oracle.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="FyessW4/";       spf=pass
 (google.com: domain of rppt@kernel.org designates 2604:1380:45d1:ec00::3 as
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

On Mon, Aug 11, 2025 at 02:34:18PM +0900, Harry Yoo wrote:
> Move ARCH_PAGE_TABLE_SYNC_MASK and arch_sync_kernel_mappings() to
> linux/pgtable.h so that they can be used outside of vmalloc and ioremap.
> 
> Cc: <stable@vger.kernel.org>
> Fixes: 8d400913c231 ("x86/vmemmap: handle unpopulated sub-pmd ranges")
> Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
> ---
>  include/linux/pgtable.h | 16 ++++++++++++++++
>  include/linux/vmalloc.h | 16 ----------------
>  2 files changed, 16 insertions(+), 16 deletions(-)
> 
> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> index 4c035637eeb7..ba699df6ef69 100644
> --- a/include/linux/pgtable.h
> +++ b/include/linux/pgtable.h
> @@ -1467,6 +1467,22 @@ static inline void modify_prot_commit_ptes(struct vm_area_struct *vma, unsigned
>  }
>  #endif
>  
> +/*
> + * Architectures can set this mask to a combination of PGTBL_P?D_MODIFIED values
> + * and let generic vmalloc and ioremap code know when arch_sync_kernel_mappings()

If ARCH_PAGE_TABLE_SYNC_MASK can be used outside vmalloc(), the comment
needs an update, maybe

... and let the generic code that modifies kernel page tables

Other than that

Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>

> + * needs to be called.
> + */
> +#ifndef ARCH_PAGE_TABLE_SYNC_MASK
> +#define ARCH_PAGE_TABLE_SYNC_MASK 0
> +#endif
> +
> +/*
> + * There is no default implementation for arch_sync_kernel_mappings(). It is
> + * relied upon the compiler to optimize calls out if ARCH_PAGE_TABLE_SYNC_MASK
> + * is 0.
> + */
> +void arch_sync_kernel_mappings(unsigned long start, unsigned long end);
> +
>  #endif /* CONFIG_MMU */
>  
>  /*
> diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
> index fdc9aeb74a44..2759dac6be44 100644
> --- a/include/linux/vmalloc.h
> +++ b/include/linux/vmalloc.h
> @@ -219,22 +219,6 @@ extern int remap_vmalloc_range(struct vm_area_struct *vma, void *addr,
>  int vmap_pages_range(unsigned long addr, unsigned long end, pgprot_t prot,
>  		     struct page **pages, unsigned int page_shift);
>  
> -/*
> - * Architectures can set this mask to a combination of PGTBL_P?D_MODIFIED values
> - * and let generic vmalloc and ioremap code know when arch_sync_kernel_mappings()
> - * needs to be called.
> - */
> -#ifndef ARCH_PAGE_TABLE_SYNC_MASK
> -#define ARCH_PAGE_TABLE_SYNC_MASK 0
> -#endif
> -
> -/*
> - * There is no default implementation for arch_sync_kernel_mappings(). It is
> - * relied upon the compiler to optimize calls out if ARCH_PAGE_TABLE_SYNC_MASK
> - * is 0.
> - */
> -void arch_sync_kernel_mappings(unsigned long start, unsigned long end);
> -
>  /*
>   *	Lowlevel-APIs (not for driver use!)
>   */
> -- 
> 2.43.0
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJmkX3JBhH3F0PEC%40kernel.org.
