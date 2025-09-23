Return-Path: <kasan-dev+bncBCT4XGV33UIBBVU4ZTDAMGQEDFZTXRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id D4BDAB978E7
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 23:17:11 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-817ecd47971sf68394885a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 14:17:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758662231; cv=pass;
        d=google.com; s=arc-20240605;
        b=cQwWY+jOWRxm8vHhhkncOZBZORfEA6AZ/kWXKkJEZby/IwDubm6+xzLbFhrnctrJ9U
         mpGu2vFKmYb+Js+3Cv9rzBmCkIshqReXR+CvNHHir7OJcFDhPbgkuHnF6DtU7Swk5CWc
         8gxaOzu25O56aNmmzKpowGEiPl2QSjzPtBpfrm9wNkkywRyb89DVvruMmGho5jzpd9tQ
         MJ0JMIHSZtVGpIgMdWOAsho5iIq93X1MLo/NrvG1c2omptHKRMpNvskUzmFxoBjcpXss
         5zV3PfjHXHHUfoEBpMxLrQLuQuvW1l/Z7IUGpJ3lD+JL8YB7tYySJzECrrfb1fej9SKt
         Fs9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=deiabbmXyvrg29b4dvPOFw+zEqXRGQKwEIO9NvFEg+8=;
        fh=9AvfIzRR/jh3xylSpC988f6sQapo27RUF/l3oUrE368=;
        b=Rt9FzXhkkQixzp4mAl8b7NdGWerkIeeVB9IGo9gOu5Qg2mgBMo1qyCEDoZkKNyO5DW
         oz3TeSwdnkTSHPsXhFY0Sz1FPkBMerz3cj4R2m0XmONq+LDR8YM2xAR+tossOijEF2Ts
         OtG3jIyyb1rXXF/cvMxPRoeqE/VE82BVVse2dQXr1hmJIH0G5U+YOpllrHa7i4kRBHbN
         /TsKKZnNhORS/GnUyFebfrA46/z3Uz0PzoT1abPiKkBnU8U+osj/uwz1IoBWLGvW7Te7
         m8HbyIKQN42AMd6Oefjuj24Aohuz6/dCzD20kf3mjjUOy1CzChaAvs7cQeRyxsTrBYpQ
         ob5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=YQt4yJD4;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758662231; x=1759267031; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=deiabbmXyvrg29b4dvPOFw+zEqXRGQKwEIO9NvFEg+8=;
        b=UquTb8/Ex7su2C9dmex+w1wTRF/mFeVfpfPHGKAVyUx5s6BDbZ+idzKwo0M+YEcUQz
         bnyFx0bbtwipYftfJqQVZeaT0GSe5it0/g3Jfpm6cFUXfiYG27VhZgK6m1ycKGkHdoCO
         D3Uby0OMkAOnKqWqRzg/yETyqD5rpu6mpKkntXOBwHN8zUfWpRWRhkh9XAI1SWbUlG1U
         sNmMP9aOWOJDhV+7W6M5EEPsirqbdsMYT7/aDfutjLKWcp1A31e3OCBwxBeL3u2vPnZ4
         buEHVFpUSSHy86iW1cCZNb4MpBFMne5YSyQtx/NSTs9RUh8GppvYW7TgRq6vr5om7rxz
         rMjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758662231; x=1759267031;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=deiabbmXyvrg29b4dvPOFw+zEqXRGQKwEIO9NvFEg+8=;
        b=BFIbAk3bLHpNKGNo45jgLL20AUbKm0Ecn2XjK3iWdX2Qrl1C0dU93lAPgQ0NA5LW4O
         xB6DFE+dYPs8iXqx9OFn/wzKN5YHLz5Kqb7BaN+mK57otZpDC1xmChU6EoWK041I0YLK
         Sb9rzOr9Js6GyS6F6GFUsTVBb0zguqZEFsI+JoVK8MsrFrbMZ/Dg5AT6FdRqTa+d9Ziz
         qkvQFeGMi3WHFAuu1DHHogeRSPqJ5yF8MR5lYfsAaMUInWBc0kZlpxyOCaUIYgPUaZkk
         CZwt+y2rw8zmE8vu1b5snRrc5LVebK0TYHF4Lx8d0+YAbWpPZtAuAH8xjgNN62Pdzous
         zgmQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUHbrLsIWEGtCnR8qHcYnk4MNbq4wGn/L4xPH/YKz0HgVdECqtGRWWftp5qd+JGd0uKlyhqmg==@lfdr.de
X-Gm-Message-State: AOJu0Yx9bZXOZmEPlWHCeTvEE/T8mjpYYLVCCW0kJrBzwlgv38RTFVvu
	guwpwJBHUvv2Ma3nn8hYjb6ZeFNqXf/2UaiLQz8w5oO1splVExpSjlEb
X-Google-Smtp-Source: AGHT+IFT3WrHY5q4FzUp9YaZxZCpHhSs56H/PYkz6m+iue26JaXwTUy36MrCljfsvqhSDOcx/LAdTA==
X-Received: by 2002:a05:620a:7003:b0:815:9d71:62be with SMTP id af79cd13be357-856e7680d09mr13484185a.32.1758662230737;
        Tue, 23 Sep 2025 14:17:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd52k2UW/VKvXaGMbMt/UnJOv0LETpt3mCIGQckM/r7XSA=="
Received: by 2002:ac8:5d03:0:b0:4b0:7a8b:b32a with SMTP id d75a77b69052e-4d7a4de7951ls2331571cf.2.-pod-prod-00-us-canary;
 Tue, 23 Sep 2025 14:17:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVi0DW4slW0pJp+hA9VSxfVF4DClNTbHR26lX+E63xp9xypTBY60mcUddAW/jq3vua7/tQsIsD8owk=@googlegroups.com
X-Received: by 2002:a05:620a:4048:b0:7e7:fd49:b0c7 with SMTP id af79cd13be357-856e41c8165mr13575185a.7.1758662228204;
        Tue, 23 Sep 2025 14:17:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758662228; cv=none;
        d=google.com; s=arc-20240605;
        b=kFwPeIzROU72hvLhRNym8BFg+hpiXbE9KWqi8TRtOnc+i6yBxJvefjlHdRX4N5KO2h
         m1vTxtoGT9jsKtJOJeAeCWcFk+MQXD3ENZzkHbA82ZCgiuIzyaDfYeP74tYQ8MRhJ70P
         MIPvVm/K/FBXYZDjZUjc5ZfiPBQg1trIOzqPDUh3NOdPRF70r0zMKMabsL9LO5xRf2Bp
         s3cP5fNxfirIoIwLpxsMth+sFd10WnlZv+dKd/1UYPUw+4PiLwVqLybhNUgG8bOQdEQY
         EtT67D3tgoozMrjQlC77ZEsNWNloKM+Z96hLpIYb/mm0mDIOgdHaDpwHj4YOWHyOwCkE
         PmXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Yje1Tz9SaEGw6dlz8jsIVamZUDeUt5rPgw2qC2XPSGI=;
        fh=iJfG4RqYWLg+le4xWqpAUTs1f4sjIaWpNoE211v+nxY=;
        b=g7leJRyVijPkMP5HCQCfsyJpWgSjdQK2NA2ys6MXahkjaPqE/6XuRUV2a+b0+jBv5+
         uHEEEdF5RIalX5H7t0KHzfp97XTvLxBeMBmEBLgEbtNSlkODWwjr4IC6oCk1JxTrVcIP
         F8GlBPS+HkKxcGi14qCVsDT5L6d/6AMhfIvUH8LLf9OO++v+jkUXLWMjEcFeUs8ZCOaO
         lsoJ5LBWH/F18ppnjl95+rt5H8RaKzjfCI7YGE/Zjz/9tixwiNbF4u12WT34LQMZcq1u
         kaShxf3wZDuhs1B8r4360wOWG9fflhmd1zaDj9cy9AHYfOmF59K3ykkzMtS1gATuMJqO
         nPUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=YQt4yJD4;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8363066c299si32899185a.6.2025.09.23.14.17.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Sep 2025 14:17:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 61BEB42B86;
	Tue, 23 Sep 2025 21:17:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 51CB1C4CEF5;
	Tue, 23 Sep 2025 21:17:05 +0000 (UTC)
Date: Tue, 23 Sep 2025 14:17:04 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Sumanth Korikkar <sumanthk@linux.ibm.com>
Cc: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, Jonathan Corbet
 <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>, Guo Ren
 <guoren@kernel.org>, Thomas Bogendoerfer <tsbogend@alpha.franken.de>, Heiko
 Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, Alexander
 Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger
 <borntraeger@linux.ibm.com>, Sven Schnelle <svens@linux.ibm.com>,
 "David S . Miller" <davem@davemloft.net>, Andreas Larsson
 <andreas@gaisler.com>, Arnd Bergmann <arnd@arndb.de>, Greg Kroah-Hartman
 <gregkh@linuxfoundation.org>, Dan Williams <dan.j.williams@intel.com>,
 Vishal Verma <vishal.l.verma@intel.com>, Dave Jiang <dave.jiang@intel.com>,
 Nicolas Pitre <nico@fluxnic.net>, Muchun Song <muchun.song@linux.dev>,
 Oscar Salvador <osalvador@suse.de>, David Hildenbrand <david@redhat.com>,
 Konstantin Komarov <almaz.alexandrovich@paragon-software.com>, Baoquan He
 <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>, Dave Young
 <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>, Reinette Chatre
 <reinette.chatre@intel.com>, Dave Martin <Dave.Martin@arm.com>, James Morse
 <james.morse@arm.com>, Alexander Viro <viro@zeniv.linux.org.uk>, Christian
 Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>, "Liam R . Howlett"
 <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport
 <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko
 <mhocko@suse.com>, Hugh Dickins <hughd@google.com>, Baolin Wang
 <baolin.wang@linux.alibaba.com>, Uladzislau Rezki <urezki@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Jann Horn <jannh@google.com>, Pedro Falcato
 <pfalcato@suse.de>, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-csky@vger.kernel.org, linux-mips@vger.kernel.org,
 linux-s390@vger.kernel.org, sparclinux@vger.kernel.org,
 nvdimm@lists.linux.dev, linux-cxl@vger.kernel.org, linux-mm@kvack.org,
 ntfs3@lists.linux.dev, kexec@lists.infradead.org,
 kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>,
 iommu@lists.linux.dev, Kevin Tian <kevin.tian@intel.com>, Will Deacon
 <will@kernel.org>, Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v4 11/14] mm/hugetlbfs: update hugetlbfs to use
 mmap_prepare
Message-Id: <20250923141704.90fba5bdf8c790e0496e6ac1@linux-foundation.org>
In-Reply-To: <aNKJ6b7kmT_u0A4c@li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
	<e5532a0aff1991a1b5435dcb358b7d35abc80f3b.1758135681.git.lorenzo.stoakes@oracle.com>
	<aNKJ6b7kmT_u0A4c@li-2b55cdcc-350b-11b2-a85c-a78bff51fc11.ibm.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=YQt4yJD4;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 23 Sep 2025 13:52:09 +0200 Sumanth Korikkar <sumanthk@linux.ibm.com> wrote:

> > --- a/fs/hugetlbfs/inode.c
> > +++ b/fs/hugetlbfs/inode.c
> > @@ -96,8 +96,15 @@ static const struct fs_parameter_spec hugetlb_fs_parameters[] = {
> >  #define PGOFF_LOFFT_MAX \
> >  	(((1UL << (PAGE_SHIFT + 1)) - 1) <<  (BITS_PER_LONG - (PAGE_SHIFT + 1)))
> >  
> > -static int hugetlbfs_file_mmap(struct file *file, struct vm_area_struct *vma)
> > +static int hugetlb_file_mmap_prepare_success(const struct vm_area_struct *vma)
> >  {
> > +	/* Unfortunate we have to reassign vma->vm_private_data. */
> > +	return hugetlb_vma_lock_alloc((struct vm_area_struct *)vma);
> > +}
> 
> Hi Lorenzo,
> 
> The following tests causes the kernel to enter a blocked state,
> suggesting an issue related to locking order. I was able to reproduce
> this behavior in certain test runs.

Thanks.  I pulled this series out of mm.git's mm-stable branch, put it
back into mm-unstable.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923141704.90fba5bdf8c790e0496e6ac1%40linux-foundation.org.
