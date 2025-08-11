Return-Path: <kasan-dev+bncBDZMFEH3WYFBBWW643CAMGQE5JCBBRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EE8DB20250
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 10:52:43 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3e3ef736a78sf93185745ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 01:52:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754902362; cv=pass;
        d=google.com; s=arc-20240605;
        b=FHCltwlI/f3fwS+Qa+ugwqIivpzr0qfSQNqNWvMjzFlvISU3mgcrwKsukBQfbp9quF
         pggzk1bJ/jJ42Jcg6lOwiLqyapWmGyE38cM7dNb1es3vJdWdTGwLZlN5iryGKaMS5Cgr
         uoOjVQN/xxsOiJ87eOdWorWi9gPFRnyXvaMptLSrbIA11BJHE5sBJ8H5kFVjDjkgT8Qd
         K6KDxnulx0nZGZ2PlQC7UqxGeazDcPnjn+yl5FCBryuGbqnjpLVHwsAXthVICQwI5Iim
         NpTHieb2A43Y6qJXUGoLG2GcBe1nUWbOAiXr+IoksPaMw/FH/6+wj8LmosdqEyJdq36h
         7dCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=vpTFOClDZGjLok6xrSGhPgiSTKNaszuJ2GE0jsfLFxI=;
        fh=gyiXIvvEBA7xRhwyQ0zHsnJ9gE48sAIfHX6yvBiuKto=;
        b=aJfWLU9vG0m6QvAT3Im20TFZsUUYt2IOt5sEH1ARN9vXf2E+/9zonbUy8DoABoUO1y
         4WY4yvd0wVxq5euuF8c3o2Yz9EnH+Q9c136GjnHWmattouMqfwz16fGpJikjZ8O8TFxM
         Blqmw6MBIQtdBhOWPs+vK88OgTHrm4KqIWLRh5B69fgrZPYznPDYyz4C99tLeFKsmNjr
         O1JnhQiKmX0GYUAycKSF3yxl6zNJVmEdkb+yecJtJFN2j6QLub6b9mKdmUZuwRROLDMX
         mjz7CSAcpcs9kiqtGRvnUd5bFKv8diedBPsneP7O85HrGR6W+JYJzF+XjwHYWcpwX/EC
         KMJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fKswWXSD;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754902362; x=1755507162; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=vpTFOClDZGjLok6xrSGhPgiSTKNaszuJ2GE0jsfLFxI=;
        b=J+7EsSzAZHCxYvhn71qJNWKwvxem4Za6hygnOe1qeYkv/aVb3uHYYj30HuCaIKVA3A
         DrzmlNuGHJlmkFt6R9mIgR3NmPUjiOZTDVWiKH9qLnk6HZqhPSIRHe+xnbNchkKTm1Yv
         v3MvG3zasa4gbAlMpFz3RHUpTtybxGCrveuauSS7aDEbGAXtMBAICZGiz1MAMIYoMNbq
         esdGL540DQO+Z2NzQBZb6hjDgFeGjV8niE/GTs+1Xhl2L4D4i3dNVcaSHf9OodaSRvcB
         IUSiYhvodNDBtFO4btA+PBuVXy3ZIt/3i+QCpJQ2V/ze7XfmahNU/I/BqVi5sZiefjmh
         093g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754902362; x=1755507162;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vpTFOClDZGjLok6xrSGhPgiSTKNaszuJ2GE0jsfLFxI=;
        b=wluwuLmnbegXOhESx/RqLmrregIkPY4OHINedzvlY/ZyouvHWf4VyXWLllE7XVh/mv
         ne9YakHRfELg/o3Q/NbHk/qBs9PF+NOHyYio2+VC7nGKE0IQfZCutior9IzONRrbKTw2
         jxGlzZLWzDBPAYuSrWh0N0qWX69PpAXfT3VEK/ULQ+uMfLP2POP1+tQMOVZFS8ST8hZJ
         WPASEcl+jQNttY7V1ImWl3086W7YQAnYJJ1xeOx6lQs0cmeDSrU/tYnqE5wYOqdYnFPR
         CqT6spfqRCmQjUWPWQgT5yWar8hWWig4yAapduHu+Nq6dywDb55W23a0iwlb0qyTHhza
         Tq0g==
X-Forwarded-Encrypted: i=2; AJvYcCXymzMIgFYr3z2gMaXHchWsECjHGDRUMS8pR8kvDwptGEmaU24l+pYIs1rw78lVXtO8pkUepw==@lfdr.de
X-Gm-Message-State: AOJu0YyulMCoFNm0BMfeovXVjB+E72PPHyyzKFq0xeKbODSuE6fniKbf
	w80yVKbp7DPBh6F6N4m0neNrDOw14/tGfprpyn41+suwQ8C8g8SvTSDt
X-Google-Smtp-Source: AGHT+IHtk7K+RDpUyzBL3VM9+AbsTMUivvvc6GPanw36c8pOyzURYe0dVd4+6OLQiUuSSRjWO/MfrA==
X-Received: by 2002:a05:6e02:3e02:b0:3e5:4bc5:539a with SMTP id e9e14a558f8ab-3e54bc55c78mr71277245ab.19.1754902362237;
        Mon, 11 Aug 2025 01:52:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZekB8YZJXaXHttgxRoTQKIbJKomJw/dY4/2eiUGOBmu2w==
Received: by 2002:a05:6e02:470e:b0:3e3:fb9d:321 with SMTP id
 e9e14a558f8ab-3e524940cc4ls37745565ab.0.-pod-prod-05-us; Mon, 11 Aug 2025
 01:52:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXaZiWJebnqGFcvD3a+hT5v58uWZJc0DlsGt1o2D8n9HkpqqBnRw/JWZ2bn80bsehDPvr5nxHO74ew=@googlegroups.com
X-Received: by 2002:a05:6e02:144f:b0:3e5:42ec:1352 with SMTP id e9e14a558f8ab-3e542ec19bcmr115287455ab.4.1754902361324;
        Mon, 11 Aug 2025 01:52:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754902361; cv=none;
        d=google.com; s=arc-20240605;
        b=N//V6KgKxpK+O6vk5TyYffbZrPLAk+R9QMwlpWHW4U5US7cUUApNB4bhRNCM4Ti3cI
         ZsGqKeN8kblqQwCEiLHEepVlO0u/PSithYfF++9L6uRlt+jc9pjeynYxb2de2GdIhVnF
         9XOw7IgLa3l6cZUo3JcTvO+jjHcUlXZPPuvb8E135u02QQgVYlGEsV7cgeATk5kQ7jfg
         5LTIhrHJCVxt6C3YZU9J8F3iY454Gs7DMQhbsVCEFQzvNtpXDfstKBb0At+Uz8PQ0TLl
         sFLpig67QW44JfF7y2HrBxnWISY6yaaPrfikUXZ+0yh7WT6UO1xs45+raKvKKhQQd7aR
         D2gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Oe2VKxHHBnv9GjgWLsKN6Ezb3lZiI1aA5YJ7TN1WMOM=;
        fh=gnVSzXXSy4qK///OqQITMo9DTimSoa5cYZv+8GlStL8=;
        b=Ed0C9fHDirsmWwl+snG5QsnDknO7zJWtuQUR2aiBwDxuzf9XB4inefcDl8ZoSyJ1Te
         XDDowED9B+oAzrP4IL2FLCe8CHkFMqyshu/w3LSzbbGEf+in5uZolQOplgP3krhDuuDW
         CnDe/AhcVEsBNrXEm525mXeb7DqoEM8IMxPBxs0nVoxre1LgmU07yZh70Uf36ZfBUzog
         0w3IkMGgt13TCqtBoy0AVTjRqddqr0B88iu0G4S/oXhBEzPq6nUJeUTGc0FdEXwd3a0g
         o0LqS4xf+ICrJjvSazGm+N04b8ImSi4ns4pAIH+zPBZLdfIvId7A7llZ05w0J/A46ryN
         I7GA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fKswWXSD;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50ae99c28d4si363860173.1.2025.08.11.01.52.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Aug 2025 01:52:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 7F54861133;
	Mon, 11 Aug 2025 08:52:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8B104C4CEED;
	Mon, 11 Aug 2025 08:52:27 +0000 (UTC)
Date: Mon, 11 Aug 2025 11:52:23 +0300
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
Message-ID: <aJmvR5mRJ2htKoss@kernel.org>
References: <20250811053420.10721-1-harry.yoo@oracle.com>
 <20250811053420.10721-2-harry.yoo@oracle.com>
 <aJmkX3JBhH3F0PEC@kernel.org>
 <aJmrpaeKKeNCV3G_@hyeyoo>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aJmrpaeKKeNCV3G_@hyeyoo>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fKswWXSD;       spf=pass
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

On Mon, Aug 11, 2025 at 05:36:53PM +0900, Harry Yoo wrote:
> On Mon, Aug 11, 2025 at 11:05:51AM +0300, Mike Rapoport wrote:
> > On Mon, Aug 11, 2025 at 02:34:18PM +0900, Harry Yoo wrote:
> > > Move ARCH_PAGE_TABLE_SYNC_MASK and arch_sync_kernel_mappings() to
> > > linux/pgtable.h so that they can be used outside of vmalloc and ioremap.
> > > 
> > > Cc: <stable@vger.kernel.org>
> > > Fixes: 8d400913c231 ("x86/vmemmap: handle unpopulated sub-pmd ranges")
> > > Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
> > > ---
> > >  include/linux/pgtable.h | 16 ++++++++++++++++
> > >  include/linux/vmalloc.h | 16 ----------------
> > >  2 files changed, 16 insertions(+), 16 deletions(-)
> > > 
> > > diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> > > index 4c035637eeb7..ba699df6ef69 100644
> > > --- a/include/linux/pgtable.h
> > > +++ b/include/linux/pgtable.h
> > > @@ -1467,6 +1467,22 @@ static inline void modify_prot_commit_ptes(struct vm_area_struct *vma, unsigned
> > >  }
> > >  #endif
> > >  
> > > +/*
> > > + * Architectures can set this mask to a combination of PGTBL_P?D_MODIFIED values
> > > + * and let generic vmalloc and ioremap code know when arch_sync_kernel_mappings()
> > 
> > If ARCH_PAGE_TABLE_SYNC_MASK can be used outside vmalloc(), the comment
> > needs an update, maybe
> > 
> > ... and let the generic code that modifies kernel page tables
> 
> Right, and patch 2 updates the comment as it uses it outside vmalloc():
> 
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
> 
> Or if you think "page table update code" is unclear, please let me know.

It's fine :)
 
> > Other than that
> > 
> > Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
> 
> Thanks a lot for all the reviews, Mike!
> 
> -- 
> Cheers,
> Harry / Hyeonggon

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJmvR5mRJ2htKoss%40kernel.org.
