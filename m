Return-Path: <kasan-dev+bncBDK7LR5URMGRBRHL43CAMGQE4R3PS7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id DE617B20318
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 11:20:06 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-55baf24e02esf3164636e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 02:20:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754904006; cv=pass;
        d=google.com; s=arc-20240605;
        b=dSlRyOvZjS6FbRQp8JqEa8gf6bJ3KO4FAxnjzZhhoUSJUZsgcMwXAI6GiZF7wKxHBh
         luCNYm3gri3xh3WlKoWCPtJtas1+Ad6UA+Br2V3EsITASNncN5vXTlGkdYQuWHScVf3F
         zHLRaT24gU/tQixEE51xI6uX7ZMMdyYrk7Px9a1gEy9j0jPSIg0G+g4wbKGbI9g5e1pg
         TaBRMoUDU5aFgBANqGb8SCzBQRRSo6D4nLjnPQbLj41caIQ3NoP7XE5Qh7jx3I/h4Nff
         vkFABf5FroBQ90roYymgdOkaQuRoqqXubmmNObpo18a0FtvVKrVvQ1d6DrBq+sYOG3m1
         hcnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=kiPh+LjayQ/Jv75Erj/5+H1b/3JT3F/s2256falAC8o=;
        fh=hJWJfmrDig0C8iq6o3ET/ldJ8tLrPGJKc9YJrsZxjrw=;
        b=H/MtllRklTE9kB5qCyESIVOgdmNOzoUIOiQ06RkVcyi3P3I+3wZpftU3M5Z09IIsy3
         VFk++1aCj77PtoqDaAmwFzxWWY5eFoUBHhRtSoZHSMpw9ZEA7U8UIWQrMoG9ZUT4+Ari
         u5T/lhuEtITg5XUpOSE6TVIKLQtKTSLSHahGWPMJ6ntndQbjxQJDQ87BYNuL5PzHCeNy
         zCkqniDkjEknqHNvHALmBklrs7hqTZ8TLDYpZgjpdqXVUkqASMITMSb9LuQXz+IFiX9j
         oIhX4VcWZkPqaIZ92l1weR7NzhcQDBgdaGEhhgs/vScO7X7gRy1ocuMTdYUWlV0yOWaX
         z4sA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EXjlMeYB;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754904006; x=1755508806; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kiPh+LjayQ/Jv75Erj/5+H1b/3JT3F/s2256falAC8o=;
        b=P3J8rBpjFtrxXRqAfg/mij71WDv+eCtO4NVbZgcQVBs3thzObt8FlT2Pw9ZqddORps
         c1Rn0Hp4QS/gowczl0ZCoqSlQCl1afZ1jlQkM94EUU/8BZPTh80ovdu5jwIZcA6UcR9m
         cMoARnuzeX8c8EplI/LVNO0sigtvWO1PLBshcDa+1JR8oL+zElro6nWHIccNMROGcROC
         KobAi5lL+5EjAey3Hb9nqT/c5YSkhe1AJCShW9RtTTUjZLvJRWQLRN9FWu8Qd/fVI706
         Bfk6Ej1cNbuKj6t+HKPT0tgWUsbAk/9jjfWTc76Zt+GomO8MDcK1pisu6pVfN8OEuTIZ
         KL9g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754904006; x=1755508806; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=kiPh+LjayQ/Jv75Erj/5+H1b/3JT3F/s2256falAC8o=;
        b=Vx8CEImK/1Mi+UP9rsSPoas1F2JHe49QmbQIjmadLwLfOY0Ii6AEpHGOtbRAfJ4xoF
         dhbsMlJDP0M+xtYR3kor3+1lcocyNIFEzzgEA63i1fCvMPpaFrM/8rDS8l2IJVoy61+z
         HoDs2iwoYAz/zqJcqtwnJDQ5Qqk978P/jQ7TFUnPSpjVEevclE7Le4VxaPBg9f/XrXaA
         2O/lj7zjI70Mx/IHctdFeH5xeQdYlhz6bpvE3tNnGS8y6JEWNv68iO9Lpdmj3OUQ9RPY
         vlHSddu083pqKpCZSzAwdQNaD/PNOJwfXQQp3vLXN5i+NojYdx2xNb+NmUQqV7GqXLwo
         dZWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754904006; x=1755508806;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kiPh+LjayQ/Jv75Erj/5+H1b/3JT3F/s2256falAC8o=;
        b=mAIgpOMzJXpHaIFhb1oVBKVcYPwcYKpU75+MfX+9TSWnVs8O6fHmZ/7L51wT92N7tq
         C0nkw7krYdhx9kIIiiSwiHjOJvf6dyzFVhgfqCdZNAOk/nbHV5RVDy67ZlZc1DRt+St7
         DlJSaB3vV+5VHZ1ly87zTMhJjDMRY2h+J3xVJhOqSr/8eUckIMaVXovcXJWJnUn3V2Zv
         kwnGZGjznFWwFfBEitelnuVIwArGnroaee0CA4squhQgLCqGHuswXbmR7Dkt3eqGfNoV
         UXV5pKIev8GHg/gtxTHcXMPOs22yGK+aZDucsjnXfrw56XF6Cxxl74GdikOmUxP1aE3h
         gQtg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWs7ysPkR77cRs1XdZ+ch1wbIQ0Csc2wfZLTEuNFp4K5GcNk8Ea8Dtejlvjl2l888AbA7Vq4Q==@lfdr.de
X-Gm-Message-State: AOJu0YxjSa1gIAiWsvB17Z81sQmwjQTYI+KeYoygv49WzREv3p24HAJe
	rgLF4GUJo5gN2cHrZZ4yPLbPm1JNN28zQgUtgEFugLJY0yktCOP2HAKJ
X-Google-Smtp-Source: AGHT+IHY/+i2Vv5MWnN5uwgQ+eixJRkMAdf7YcPvLEOnWezpC5i/Y2kzUwP0AY676is/OBkfCq0Shg==
X-Received: by 2002:a05:6512:3d03:b0:55b:8767:1b08 with SMTP id 2adb3069b0e04-55cc0077afcmr2889180e87.10.1754904005492;
        Mon, 11 Aug 2025 02:20:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcnI+oFWplbCSABx+59HebiSLcCApxZ2Zpg+01iV4DG0w==
Received: by 2002:a05:6512:2399:b0:553:214d:2e12 with SMTP id
 2adb3069b0e04-55cb5fbf6fals1406960e87.0.-pod-prod-08-eu; Mon, 11 Aug 2025
 02:20:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXFr20APjh5poQy0klfLlOA3sV/ivqzqTGTikTqVypRIQzDSDwnD2UdMEiOUC1Kxle0FU5a02YDh6Y=@googlegroups.com
X-Received: by 2002:a05:6512:3e1f:b0:553:3407:eee0 with SMTP id 2adb3069b0e04-55cc0078ba4mr3541206e87.4.1754904002561;
        Mon, 11 Aug 2025 02:20:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754904002; cv=none;
        d=google.com; s=arc-20240605;
        b=gu+f3mfMe/5Uvqur4xgijWOXCVFoRK3j0PwOa/66Kv0HbHavLEZoN6KjhIpIErXt5H
         mIVed8tcpTJ7ChnlRxTfHI1v/OSPkM8HvVldof8yzS0VWHhpqd+pgBAR5t+n77+sPw/5
         9habPHviBoCl7JRhpeY06Dp/D57Zd/ynNsgjpduuNkk1xyZWPDuglMM3O1UIwgstn+9k
         077ORQx7/npngVlHWxMFexz/g+qrJAB9C0CyEPbgvZoc0Or5anL2TlwgKpzlVtGrEnHX
         bEIRD3uzISLt6+rCx5gLTQzsgY0scGuI87INEDH+3rnH939/EWXX2hPUNSW+xrWqq4kq
         ZBIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=fLY040Of3yhdDWokuw+L+nE0pmeX/ImH14JZx346nu0=;
        fh=LtZn+iwPyWRXrsS4SqWhS9f0IgSG4O6fLxCbysJ7KiA=;
        b=e1kBBw1UxxyeE/pFOUVQ+z49DqL0C4Q1Ig6MSQZ9fLVjdRN88s6r+CsekXmHWix1MA
         3ZZ0k0tf51os2QlEv7CpZQHa41W/FN5c189fHYmkFOonLxduod5j71zZ3Akgft/8g/Ns
         o9Im3DJuogbHzPRxOqKzCI9hl+kFsI111FGpZBecm3TOk9ehbY/mHFfIqsv6PUsGIp+4
         LgyFc/dRg90GLpOx/ZiDv3nyyvDBoykYimdo53ii5q7rHJafbs1Tliw6NQWb3tuY0VI+
         G9PKwTtpSa8nzO/dJBm72ZSEuSm/8ZYRJxC9BnpfGP2nqCa0wforeM8HaaIT5/9bhIwz
         n0ZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EXjlMeYB;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b887deca0si574394e87.2.2025.08.11.02.20.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Aug 2025 02:20:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id 2adb3069b0e04-54b10594812so4836055e87.1
        for <kasan-dev@googlegroups.com>; Mon, 11 Aug 2025 02:20:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUAQ44o0Txv1vFSBwTyAgdo1JwKVyvG+Fo/GD6leW15hAA5hzVClfnBxc5odjKGkbXsx/fM6oGYfD0=@googlegroups.com
X-Gm-Gg: ASbGnctP4Dx4SwSWrZ9ZgxUOLkf+e3hfcElaHedqtXQoO8OqLrPc5MsBly41YfT16PB
	453VhmqT3eoTa3iQELCVb3eguvcBKeqFd6edCJmGKHKxK2HDW3GW6ikVa+Zc7egdzA4MU3QJlNs
	/iQbxHgZbb6KwAAmwqwBHhk+6z6BTlns0hl5D9tKhpyhcxYNlZ5hAO37LMw7d+oY8k3g3IZTU/I
	ioGDbbbGYRLOrhnvqWJFCii+fzbx+5kqQ4PFNX0hGdoy5Pf9iVOwRW46dp7esCmu3QgG+FIMwJc
	pbu+0w/DhCy1NiMthAFBsm6ZXdjv2DaklXUq1PfBdASgwZXB7+6Ih2e2lJOoz5WdGzce7HXquT3
	0UItJRfw1dtRBU49Xrx1eZ7j09nvqhmlCjT833Vpt6+ZZRks18Q==
X-Received: by 2002:a05:6512:10d6:b0:55c:ad2a:aa7c with SMTP id 2adb3069b0e04-55cc0094c9cmr3053586e87.22.1754904001692;
        Mon, 11 Aug 2025 02:20:01 -0700 (PDT)
Received: from pc636 (host-95-203-26-173.mobileonline.telia.com. [95.203.26.173])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55cce15c650sm806954e87.103.2025.08.11.02.19.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Aug 2025 02:20:01 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Mon, 11 Aug 2025 11:19:57 +0200
To: Mike Rapoport <rppt@kernel.org>, Harry Yoo <harry.yoo@oracle.com>
Cc: Harry Yoo <harry.yoo@oracle.com>, Dennis Zhou <dennis@kernel.org>,
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
Message-ID: <aJm1vQ2D1YOhipos@pc636>
References: <20250811053420.10721-1-harry.yoo@oracle.com>
 <20250811053420.10721-2-harry.yoo@oracle.com>
 <aJmkX3JBhH3F0PEC@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aJmkX3JBhH3F0PEC@kernel.org>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=EXjlMeYB;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::131 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Aug 11, 2025 at 11:05:51AM +0300, Mike Rapoport wrote:
> On Mon, Aug 11, 2025 at 02:34:18PM +0900, Harry Yoo wrote:
> > Move ARCH_PAGE_TABLE_SYNC_MASK and arch_sync_kernel_mappings() to
> > linux/pgtable.h so that they can be used outside of vmalloc and ioremap.
> > 
> > Cc: <stable@vger.kernel.org>
> > Fixes: 8d400913c231 ("x86/vmemmap: handle unpopulated sub-pmd ranges")
> > Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
> > ---
> >  include/linux/pgtable.h | 16 ++++++++++++++++
> >  include/linux/vmalloc.h | 16 ----------------
> >  2 files changed, 16 insertions(+), 16 deletions(-)
> > 
> > diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> > index 4c035637eeb7..ba699df6ef69 100644
> > --- a/include/linux/pgtable.h
> > +++ b/include/linux/pgtable.h
> > @@ -1467,6 +1467,22 @@ static inline void modify_prot_commit_ptes(struct vm_area_struct *vma, unsigned
> >  }
> >  #endif
> >  
> > +/*
> > + * Architectures can set this mask to a combination of PGTBL_P?D_MODIFIED values
> > + * and let generic vmalloc and ioremap code know when arch_sync_kernel_mappings()
> 
> If ARCH_PAGE_TABLE_SYNC_MASK can be used outside vmalloc(), the comment
> needs an update, maybe
> 
> ... and let the generic code that modifies kernel page tables
> 
> Other than that
> 
> Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
> 
> > + * needs to be called.
> > + */
> > +#ifndef ARCH_PAGE_TABLE_SYNC_MASK
> > +#define ARCH_PAGE_TABLE_SYNC_MASK 0
> > +#endif
> > +
> > +/*
> > + * There is no default implementation for arch_sync_kernel_mappings(). It is
> > + * relied upon the compiler to optimize calls out if ARCH_PAGE_TABLE_SYNC_MASK
> > + * is 0.
> > + */
> > +void arch_sync_kernel_mappings(unsigned long start, unsigned long end);
> > +
> >  #endif /* CONFIG_MMU */
> >  
> >  /*
> > diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
> > index fdc9aeb74a44..2759dac6be44 100644
> > --- a/include/linux/vmalloc.h
> > +++ b/include/linux/vmalloc.h
> > @@ -219,22 +219,6 @@ extern int remap_vmalloc_range(struct vm_area_struct *vma, void *addr,
> >  int vmap_pages_range(unsigned long addr, unsigned long end, pgprot_t prot,
> >  		     struct page **pages, unsigned int page_shift);
> >  
> > -/*
> > - * Architectures can set this mask to a combination of PGTBL_P?D_MODIFIED values
> > - * and let generic vmalloc and ioremap code know when arch_sync_kernel_mappings()
> > - * needs to be called.
> > - */
> > -#ifndef ARCH_PAGE_TABLE_SYNC_MASK
> > -#define ARCH_PAGE_TABLE_SYNC_MASK 0
> > -#endif
> > -
> > -/*
> > - * There is no default implementation for arch_sync_kernel_mappings(). It is
> > - * relied upon the compiler to optimize calls out if ARCH_PAGE_TABLE_SYNC_MASK
> > - * is 0.
> > - */
> > -void arch_sync_kernel_mappings(unsigned long start, unsigned long end);
> > -
> >  /*
> >   *	Lowlevel-APIs (not for driver use!)
> >   */
> > -- 
> > 2.43.0
> > 
> 
LGTM,

Reviewed-by: "Uladzislau Rezki (Sony)" <urezki@gmail.com>

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJm1vQ2D1YOhipos%40pc636.
