Return-Path: <kasan-dev+bncBDW2JDUY5AORBPHM72GAMGQEL525NBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DF5F45DE73
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Nov 2021 17:13:49 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id w5-20020a25ac05000000b005c55592df4dsf6803147ybi.12
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Nov 2021 08:13:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637856828; cv=pass;
        d=google.com; s=arc-20160816;
        b=rPeeM+oePo4SYDJCL/HVlnVZH8pbGdVf8qB5bhEFh52cl8IgP207rsPz2hWh/bqMXB
         fN/ulcOONfywRLr2XlwWY7OByrcW9YQ3yBbJXNcNcAOmSi6C9iabaIsO0IwUoECN3uLN
         mZcsV3Ibx3dsLp6bjMLwcMn77XRzeRVoQTQGIOcVNTWEr5ljCCd+mHY7Qzu7P4yEfCfR
         9gzdtTSIQVJuCdvZdyoV1+lmeNYwRAiSu5O8GCR9pgq0xcf+WdROmcMkE0Wtkc0j1zrV
         rqyIz2y/lbvyYIvTITCVahurz3FVPAm/0RKmCW5Cm38u+o2d35iY29hzOZ7udmJFCAP/
         5irA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=g4yoXY8ouBTci9bDFAxmUE/5xYX4O2iERnF1kxgojW8=;
        b=IZFu6Z1Za+O5Exku5IBmQ2syTRYyMjmNYR4MoFVoq3sTmHo6YtAg1xBgWIFJWtVwZk
         3WCCeey8yaidgznBD7SqDmhW+6uGZV94bCEeVTmiEWNN56JI0kWpLM0i4lIHjgyHhQIe
         YjVp7UZnwcNsdgepkqcurHvwNlONvH30eJIpuq9Vfcjjt8DnNHztz4YQpzuX1u8ji5it
         QUdw6UQmPJR6mhdIckgp/MfeRNP7Y8pTvCxSbkL5H5rktQsxKhM7YR/ypX7XN0qZhznn
         Sj1n7YXS4qOFgymUu/qShTIkQpD/jfjXqm2idWTsYgLAER9oWIC0rsna8o7N4Frhwagg
         dN5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Q5LblFsq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g4yoXY8ouBTci9bDFAxmUE/5xYX4O2iERnF1kxgojW8=;
        b=NkcI51xc6ek0IIWiCt/5y/EHXm/YUtgYA6y0o0ogogcUk0kCI4fKKySe1PrvT8RbZf
         OzXR6rootBbp5G39qC0zmT8VM7Xr0QZ1F2YTy8AwibyB9KJJvw3TCLNW8t14cpLsX/F7
         KxZjxDjeHQR5m3wOhGmJtY8/k4ZHqI3Nd6PBM8EGVW40FxEPhcR81wHZhUExQ38kCTbN
         krpEhUXBgTiIV3C+0oqGMeswmgnfnVbWILU7ByRUiotrBxouQOn4zjT7EzXM//IPhkXD
         Ws3vf8VbE6W5BhHEUEi0DTi89jTRcTF/8lEGbqlAJ/kdPmQukElz3jD4W8Tc3ehU7Mj3
         xRbw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g4yoXY8ouBTci9bDFAxmUE/5xYX4O2iERnF1kxgojW8=;
        b=J2lxaUYywJCIyddwEOjNwAGQMAhDP4DJMorpU9THWgWYIHAYDGyOnoa4IG2xKugc5Y
         RmX0NAncu/KbpMdcqUmPLfgX/u1KjS8LE5WW2fNNWW06bZZf/V1xXJfVmlo8UHsUm+Hv
         ztIPwomctyuy7WvkbrzyYCNVdAfBZYJh3nr5EygaCKzvCF+ERgw2zCxLaaMI1M7PsNZU
         cGs6WusJTcfDpOElyBHD4z+TlD7B3R+Tb8zjDkMPAMFRXGnA3rKIu0E9KUZqBk7wF+86
         5iV+VDMbKyLKwmtuGZrPEc0E/xrt4ESOrl+dSn9n+66ql1JGjv5/rZz1pXHPfTP7Ircc
         Kfjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g4yoXY8ouBTci9bDFAxmUE/5xYX4O2iERnF1kxgojW8=;
        b=mlVhQKguNaPYwNXlq1RV4tmhn7ahEqVPVz0hg1kUxgIZJB/ye9ZLhDT8ya7pImyZk3
         oeVg/UBf1HAZFSZvztYoi9RyhiKIzb+whSesy4779ZTr517HHtHzybTHDmh4tQjbQUNf
         eWu9B2AxpiO6+hS4PEXxGPJxdXWxq4Hd9LRgBWUQSmh4bduIL6z5vl3TKeeSGkpFBBCc
         dlA1Ptt5HauVMOFYA7EwFpXktOdzT31Eevt6zsTmlkdjbHIt439waVb0hRekrkbl9S9l
         iZ3ijZ8pXf2xC8doSMbi7zEdxFWomQt/Y0Cr4LM/BZFmgSkeAY5G8Yvd0Moot/CwaZ1y
         DheA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ICUALJJfWYjKdRTVXGmaPZEJET2X5oXCuSAHUXh6/EpDFzRsE
	Ow9NdOCGxEnqUDvF4NHAJ+Y=
X-Google-Smtp-Source: ABdhPJybosdDYJApgp54/hF8qWIVzJlFMeV6pQ4zL6orROw17vPIIVMpOMeR1ThZsya61GXaxKUFIw==
X-Received: by 2002:a25:c046:: with SMTP id c67mr7809101ybf.135.1637856828352;
        Thu, 25 Nov 2021 08:13:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ac09:: with SMTP id w9ls2231950ybi.5.gmail; Thu, 25 Nov
 2021 08:13:47 -0800 (PST)
X-Received: by 2002:a5b:8c4:: with SMTP id w4mr7794813ybq.333.1637856827756;
        Thu, 25 Nov 2021 08:13:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637856827; cv=none;
        d=google.com; s=arc-20160816;
        b=TKE9lD4IU1Px8Gzmpp47BftOaDuEuiLpabbWG/JR/yTqbi+1qIxWmgGjIK3X5cE/Bw
         bB8hQqSqZIAp/FFonpHpiks5P+rILe/WOaq2ri5dak8NGbpn4lsTCUgzalEvvEo1jSNy
         +si0tYIE4pH/B7uTaklml8XMmO0Jq4zdUzzm7LeZdK9S05rSEe29vbDoE0u8hBeQzJn6
         LghU8gczSLku/LmFAaBEWanWGyR3gnHlFh9kFmQ+gJDn45FrZT64Y+ntQn/pQjfRdZlQ
         IFx/62PeKiUvUzoG9IJc7lFuxKYVfbCViQ8dmd9TEj+ZCTfxVzK/RW+0oeAemkbAhk2N
         q2uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dLhxroQIXOo3AV01Fb+l/j0FVm/nZtdr4Hd5UI0PqAM=;
        b=i5jJtkHUwszNUSNi1LSKiZlUVccEPub2r0fxrgAfEY7KEjrOPbwRg7SnuEe98oZB17
         j4g3uhEvc36KKWdZQHgtgUnw9HXPlhdDRWMrHzGPUkwO0YFhpBgjZk3Fja+iQ2fzGOEW
         O2X/726FsC5zutCNpikvg01XAEj/gJk7V3/qH3MnCgRj4xQDETGMnT/yMjH+3VAEQXQS
         JFD/f8BmJw2uUaJHWBL8rJpU889UMgy9uk+/AvayD1wMJ4hq5BWCAAfZUdqwByq9BGLa
         3S6dNXbwC25nUaH9BC1Id4sac23D8YdE+jU05gHxyhItHVzrd7a+9BWf0ob+uXDODDNi
         jERQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Q5LblFsq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd33.google.com (mail-io1-xd33.google.com. [2607:f8b0:4864:20::d33])
        by gmr-mx.google.com with ESMTPS id w6si269506ybt.0.2021.11.25.08.13.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Nov 2021 08:13:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) client-ip=2607:f8b0:4864:20::d33;
Received: by mail-io1-xd33.google.com with SMTP id k21so8152735ioh.4
        for <kasan-dev@googlegroups.com>; Thu, 25 Nov 2021 08:13:47 -0800 (PST)
X-Received: by 2002:a05:6602:2d04:: with SMTP id c4mr27017706iow.56.1637856827487;
 Thu, 25 Nov 2021 08:13:47 -0800 (PST)
MIME-Version: 1.0
References: <20211118054426.4123-1-Kuan-Ying.Lee@mediatek.com> <754511d9a0368065768cc3ad8037184d62c3fbd1.camel@mediatek.com>
In-Reply-To: <754511d9a0368065768cc3ad8037184d62c3fbd1.camel@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 25 Nov 2021 17:13:36 +0100
Message-ID: <CA+fCnZchvHjU9G_SSf_M2--jHPqEa6PEr3u_5q-wJWvZK4N2pA@mail.gmail.com>
Subject: Re: [PATCH] kmemleak: fix kmemleak false positive report with HW
 tag-based kasan enable
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Matthias Brugger <matthias.bgg@gmail.com>, 
	=?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?= <chinwen.chang@mediatek.com>, 
	=?UTF-8?B?TmljaG9sYXMgVGFuZyAo6YSt56em6LydKQ==?= <nicholas.tang@mediatek.com>, 
	=?UTF-8?B?SmFtZXMgSHN1ICjlvpDmhbbolrAp?= <James.Hsu@mediatek.com>, 
	=?UTF-8?B?WWVlIExlZSAo5p2O5bu66Kq8KQ==?= <Yee.Lee@mediatek.com>, 
	"linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Q5LblFsq;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Nov 18, 2021 at 10:20 AM Kuan-Ying Lee
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> +Cc kasan group
>
> On Thu, 2021-11-18 at 13:44 +0800, Kuan-Ying Lee wrote:
> > With HW tag-based kasan enable, We will get the warning
> > when we free object whose address starts with 0xFF.
> >
> > It is because kmemleak rbtree stores tagged object and
> > this freeing object's tag does not match with rbtree object.
> >
> > In the example below, kmemleak rbtree stores the tagged object in
> > the kmalloc(), and kfree() gets the pointer with 0xFF tag.
> >
> > Call sequence:
> > ptr = kmalloc(size, GFP_KERNEL);
> > page = virt_to_page(ptr);
> > kfree(page_address(page));
> > ptr = kmalloc(size, GFP_KERNEL);
> >
> > Call sequence like that may cause the warning as following:
> > 1) Freeing unknown object:
> > In kfree(), we will get free unknown object warning in
> > kmemleak_free().
> > Because object(0xFx) in kmemleak rbtree and pointer(0xFF) in kfree()
> > have
> > different tag.
> >
> > 2) Overlap existing:
> > When we allocate that object with the same hw-tag again, we will
> > find the overlap in the kmemleak rbtree and kmemleak thread will
> > be killed.
> >
> > [  116.685312] kmemleak: Freeing unknown object at 0xffff000003f88000
> > [  116.686422] CPU: 5 PID: 177 Comm: cat Not tainted 5.16.0-rc1-dirty
> > #21
> > [  116.687067] Hardware name: linux,dummy-virt (DT)
> > [  116.687496] Call trace:
> > [  116.687792]  dump_backtrace+0x0/0x1ac
> > [  116.688255]  show_stack+0x1c/0x30
> > [  116.688663]  dump_stack_lvl+0x68/0x84
> > [  116.689096]  dump_stack+0x1c/0x38
> > [  116.689499]  kmemleak_free+0x6c/0x70
> > [  116.689919]  slab_free_freelist_hook+0x104/0x200
> > [  116.690420]  kmem_cache_free+0xa8/0x3d4
> > [  116.690845]  test_version_show+0x270/0x3a0
> > [  116.691344]  module_attr_show+0x28/0x40
> > [  116.691789]  sysfs_kf_seq_show+0xb0/0x130
> > [  116.692245]  kernfs_seq_show+0x30/0x40
> > [  116.692678]  seq_read_iter+0x1bc/0x4b0
> > [  116.692678]  seq_read_iter+0x1bc/0x4b0
> > [  116.693114]  kernfs_fop_read_iter+0x144/0x1c0
> > [  116.693586]  generic_file_splice_read+0xd0/0x184
> > [  116.694078]  do_splice_to+0x90/0xe0
> > [  116.694498]  splice_direct_to_actor+0xb8/0x250
> > [  116.694975]  do_splice_direct+0x88/0xd4
> > [  116.695409]  do_sendfile+0x2b0/0x344
> > [  116.695829]  __arm64_sys_sendfile64+0x164/0x16c
> > [  116.696306]  invoke_syscall+0x48/0x114
> > [  116.696735]  el0_svc_common.constprop.0+0x44/0xec
> > [  116.697263]  do_el0_svc+0x74/0x90
> > [  116.697665]  el0_svc+0x20/0x80
> > [  116.698261]  el0t_64_sync_handler+0x1a8/0x1b0
> > [  116.698695]  el0t_64_sync+0x1ac/0x1b0
> > ...
> > [  117.520301] kmemleak: Cannot insert 0xf2ff000003f88000 into the
> > object search tree (overlaps existing)
> > [  117.521118] CPU: 5 PID: 178 Comm: cat Not tainted 5.16.0-rc1-dirty
> > #21
> > [  117.521827] Hardware name: linux,dummy-virt (DT)
> > [  117.522287] Call trace:
> > [  117.522586]  dump_backtrace+0x0/0x1ac
> > [  117.523053]  show_stack+0x1c/0x30
> > [  117.523578]  dump_stack_lvl+0x68/0x84
> > [  117.524039]  dump_stack+0x1c/0x38
> > [  117.524472]  create_object.isra.0+0x2d8/0x2fc
> > [  117.524975]  kmemleak_alloc+0x34/0x40
> > [  117.525416]  kmem_cache_alloc+0x23c/0x2f0
> > [  117.525914]  test_version_show+0x1fc/0x3a0
> > [  117.526379]  module_attr_show+0x28/0x40
> > [  117.526827]  sysfs_kf_seq_show+0xb0/0x130
> > [  117.527363]  kernfs_seq_show+0x30/0x40
> > [  117.527848]  seq_read_iter+0x1bc/0x4b0
> > [  117.528320]  kernfs_fop_read_iter+0x144/0x1c0
> > [  117.528809]  generic_file_splice_read+0xd0/0x184
> > [  117.529316]  do_splice_to+0x90/0xe0
> > [  117.529734]  splice_direct_to_actor+0xb8/0x250
> > [  117.530227]  do_splice_direct+0x88/0xd4
> > [  117.530686]  do_sendfile+0x2b0/0x344
> > [  117.531154]  __arm64_sys_sendfile64+0x164/0x16c
> > [  117.531673]  invoke_syscall+0x48/0x114
> > [  117.532111]  el0_svc_common.constprop.0+0x44/0xec
> > [  117.532621]  do_el0_svc+0x74/0x90
> > [  117.533048]  el0_svc+0x20/0x80
> > [  117.533461]  el0t_64_sync_handler+0x1a8/0x1b0
> > [  117.533950]  el0t_64_sync+0x1ac/0x1b0
> > [  117.534625] kmemleak: Kernel memory leak detector disabled
> > [  117.535201] kmemleak: Object 0xf2ff000003f88000 (size 128):
> > [  117.535761] kmemleak:   comm "cat", pid 177, jiffies 4294921177
> > [  117.536339] kmemleak:   min_count = 1
> > [  117.536718] kmemleak:   count = 0
> > [  117.537068] kmemleak:   flags = 0x1
> > [  117.537429] kmemleak:   checksum = 0
> > [  117.537806] kmemleak:   backtrace:
> > [  117.538211]      kmem_cache_alloc+0x23c/0x2f0
> > [  117.538924]      test_version_show+0x1fc/0x3a0
> > [  117.539393]      module_attr_show+0x28/0x40
> > [  117.539844]      sysfs_kf_seq_show+0xb0/0x130
> > [  117.540304]      kernfs_seq_show+0x30/0x40
> > [  117.540750]      seq_read_iter+0x1bc/0x4b0
> > [  117.541206]      kernfs_fop_read_iter+0x144/0x1c0
> > [  117.541687]      generic_file_splice_read+0xd0/0x184
> > [  117.542182]      do_splice_to+0x90/0xe0
> > [  117.542611]      splice_direct_to_actor+0xb8/0x250
> > [  117.543097]      do_splice_direct+0x88/0xd4
> > [  117.543544]      do_sendfile+0x2b0/0x344
> > [  117.543983]      __arm64_sys_sendfile64+0x164/0x16c
> > [  117.544471]      invoke_syscall+0x48/0x114
> > [  117.544917]      el0_svc_common.constprop.0+0x44/0xec
> > [  117.545416]      do_el0_svc+0x74/0x90
> > [  117.554100] kmemleak: Automatic memory scanning thread ended
> >
> > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > ---
> >  mm/kmemleak.c | 17 ++++++++++++-----
> >  1 file changed, 12 insertions(+), 5 deletions(-)
> >
> > diff --git a/mm/kmemleak.c b/mm/kmemleak.c
> > index b57383c17cf6..fa12e2e08cdc 100644
> > --- a/mm/kmemleak.c
> > +++ b/mm/kmemleak.c
> > @@ -381,15 +381,20 @@ static void dump_object_info(struct
> > kmemleak_object *object)
> >  static struct kmemleak_object *lookup_object(unsigned long ptr, int
> > alias)
> >  {
> >       struct rb_node *rb = object_tree_root.rb_node;
> > +     unsigned long untagged_ptr = (unsigned
> > long)kasan_reset_tag((void *)ptr);
> >
> >       while (rb) {
> >               struct kmemleak_object *object =
> >                       rb_entry(rb, struct kmemleak_object, rb_node);
> > -             if (ptr < object->pointer)
> > +             unsigned long untagged_objp;
> > +
> > +             untagged_objp = (unsigned long)kasan_reset_tag((void
> > *)object->pointer);

The two lines above can be squashed together.

> > +
> > +             if (untagged_ptr < untagged_objp)
> >                       rb = object->rb_node.rb_left;
> > -             else if (object->pointer + object->size <= ptr)
> > +             else if (untagged_objp + object->size <= untagged_ptr)
> >                       rb = object->rb_node.rb_right;
> > -             else if (object->pointer == ptr || alias)
> > +             else if (untagged_objp == untagged_ptr || alias)
> >                       return object;
> >               else {
> >                       kmemleak_warn("Found object by alias at
> > 0x%08lx\n",
> > @@ -576,6 +581,7 @@ static struct kmemleak_object
> > *create_object(unsigned long ptr, size_t size,
> >       struct kmemleak_object *object, *parent;
> >       struct rb_node **link, *rb_parent;
> >       unsigned long untagged_ptr;
> > +     unsigned long untagged_objp;
> >
> >       object = mem_pool_alloc(gfp);
> >       if (!object) {
> > @@ -629,9 +635,10 @@ static struct kmemleak_object
> > *create_object(unsigned long ptr, size_t size,
> >       while (*link) {
> >               rb_parent = *link;
> >               parent = rb_entry(rb_parent, struct kmemleak_object,
> > rb_node);
> > -             if (ptr + size <= parent->pointer)
> > +             untagged_objp = (unsigned long)kasan_reset_tag((void
> > *)parent->pointer);
> > +             if (untagged_ptr + size <= untagged_objp)
> >                       link = &parent->rb_node.rb_left;
> > -             else if (parent->pointer + parent->size <= ptr)
> > +             else if (untagged_objp + parent->size <= untagged_ptr)
> >                       link = &parent->rb_node.rb_right;
> >               else {
> >                       kmemleak_stop("Cannot insert 0x%lx into the
> > object search tree (overlaps existing)\n",
> > --
> > 2.18.0
> >
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/754511d9a0368065768cc3ad8037184d62c3fbd1.camel%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZchvHjU9G_SSf_M2--jHPqEa6PEr3u_5q-wJWvZK4N2pA%40mail.gmail.com.
