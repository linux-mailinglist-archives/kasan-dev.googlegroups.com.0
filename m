Return-Path: <kasan-dev+bncBDW2JDUY5AORBB7D32GAMGQEYAV4B6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 4321345706F
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 15:15:37 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id y1-20020a0568302a0100b0056cc948b120sf5977673otu.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 06:15:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637331336; cv=pass;
        d=google.com; s=arc-20160816;
        b=ByJYKkHy1xi6Xa3Eq9jVIjMffr0cPwNzJxeM1vd+b+Ssq+MU2+YS1R3HqfG5dwW5IZ
         top+S3Roa3vfKOB8w51TjWvdgoot2ysz6JFK/F9tCbSDvjgtpyRZxN0BtsuUvUCjCAMy
         IASSIDFGk9EeQNMZ1yxxTcTHpWNIAcOQZUQqBVn8FB/VW1Sxv79AHq1TF2qhyJUBBBQl
         D9HVnwICAEk+kGT3TWJ4mjFbfFUu3dQb94uzc4OMEn0A/kVGXSNqjeZQCiOUP1MKJP9g
         es+8N3NxZWKAMkV/Jtuk8WIuxEPyl4AcDnEWePHl2HA6geynUFupjTLTvokUPXaLr2Hk
         aP4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=ueDaLiBP+OkMBmCUvao2+IL2CwnFVkN8EtpDp/lLy5Y=;
        b=P0CDJpi633DPHThAe3KMrd2iCHKKCPS6Fcn6s3a1tWH7NB6FNM/72tslfk/Z9d158W
         8xXZhG5Zuf4fQhv0xBVAJQfASCVMZe5sAZ4LmxZNtArdDb5X3jRiZkY2X+KlARo8azmp
         0q0gW0UOpWp2bV2/ffR8REu2zKDOZ3vz3UkB6aSC8OXdAygOTJwP8JCeMxRlwFdd84Bz
         JCdG4HOeU+jVR6XRyJrL2on2v410PKekqCQUSmIEdH6DN8yej3PPwpGcGc+6bUyIU/uR
         qVcCunKAde/WGuUmp/1rFFw6jqszrzmZi4WVUBiECsJBIYZjTGkcoLi7F1ezelMYL5u6
         WHlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=TL+kYVRg;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ueDaLiBP+OkMBmCUvao2+IL2CwnFVkN8EtpDp/lLy5Y=;
        b=YSX9qfqePQgpPJihThsh0xwtbw7sg4+eWnt8lWROH3nME45IOCbZDAejhG5X46b3B/
         ZCLF7zMcSDAqg7rfdjAOUrAmIDt5c3+wpIbYFinFleJj0EaVmd/gvsovgCoAXvv2D6l8
         AsXQS5bK2IHcddnTawXv15Xd9pJ5Nq7gu7dSJgw70QvoE58zWVeI1QPP98HZ3e//Kx0M
         ELPnHgAIh2J9AS2sxNDTuzGtVn0T2MkFKM1rxNX8UK4sgbHwm7XVVNhv2FTdp7eoUPil
         q4C3uDHop1Mf7pMNk57Cn28Dw8QXkOqoDsCUk0worsgegm6d/VShS4sV1pKFqsx6lFxi
         yG5w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ueDaLiBP+OkMBmCUvao2+IL2CwnFVkN8EtpDp/lLy5Y=;
        b=Qt7G0/+6FJHMbkny3BFJkvzbfR1YcUKdBT3vdCp6kFH8/7JaYKf1yzKK7CrolFYHhl
         xL6VBnB4x6DLhQNyb2GKSOrlglitnyejdPFclnTijjOSt0mlgoDhrXqfoHqvjpfpHCXp
         2ZgwqrNhLuNbyK3ngrThP6neaqoutafPQ/cmvXSNDFJQtVr4vgF7VVNuOipUNEcEAXEu
         qk02wNccQlYPRAKPQpEOUSyQYdDA8cNvS0/66WH6cYtxAWD0eegCtMMkxwlUijvTMcnD
         1ivhdDNsAkgwoU/k80N1XgK6oqlZjpfuk/bT4HgJqleH5ZtblqaPTi7UPzpzr1lVNL3N
         5CKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ueDaLiBP+OkMBmCUvao2+IL2CwnFVkN8EtpDp/lLy5Y=;
        b=xQ+naWNOe9DVKVu21Ssuia08Do12ie+pPpA8Txdl+pWtAXRbXbSMixfxIFjkSzMMEJ
         VJ0vDpQSvIDwPuiMPZIdiSRDEv3yzsQNoLCrQGY7fFg242ZRFfqB6NzHplSsbYPeND+G
         5pemHB350tUBXvuUXaf2qCRM/i+7ELX5TvpWw8DLNSjVFkqH36RUwnskwWUN6dkAanaU
         AMPTgXhi1dcvsU5ZhD6lZzfPnudfcfNcUB36Ctat10ErhPs05sUreGFz3M70PizggF0X
         vRffw8Hm7YnBKzLFWcLyn5sGxMxuSEJ2fvE75qnvI23EetpKkLxpSPzN6FoLaQ69J+8+
         LYkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ej88LUVXCNM6+zY4lX6o6QokcSGxU3fgl8IzgYXNVJDWfyayv
	HvOSbS3zUFnonLU24wd7Nr8=
X-Google-Smtp-Source: ABdhPJy/pxMEt5k0bPl5ZW/eGCzaD+qcZLZ7/zrltoY6S3o3uPuo3XGeDHfq4Q64XEDUgbPa+YhKdg==
X-Received: by 2002:a9d:7ccb:: with SMTP id r11mr4961802otn.122.1637331336009;
        Fri, 19 Nov 2021 06:15:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c284:: with SMTP id s126ls1375447oif.10.gmail; Fri, 19
 Nov 2021 06:15:35 -0800 (PST)
X-Received: by 2002:a05:6808:e90:: with SMTP id k16mr5219891oil.166.1637331335532;
        Fri, 19 Nov 2021 06:15:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637331335; cv=none;
        d=google.com; s=arc-20160816;
        b=Als0/oAZW4MFa+lwh8zeM4Hhq+ZecwjyJhFmNDZMnZ8wzbTvnLUooIfGf09XBTpWNG
         lhTavyZFL0g7XQ9lT94pKcq7aWAqjvl+dUqZkY6I8mHecaJU1TSA4oWMaNRY7NJG/pPc
         HFUP9+0q0POG+f2G/Uqlu+fdtHUXmgVS6KuFRXSUFez5MYXkJSpTZBRzKxGgq0N7B/At
         SgWHU4DFM2E4WxRO7WUj0usurfR0DrrEqJIf7+sXszlY1X6tB75uWMyhucS9yZZhuSYv
         jTGlSEJ8YUfiRFj9KzVT2W6Dp92js5dhDQdicwi6Rbm0KUHaPs73EJ15Y4fcN6FdQF8a
         xk5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0C7ROqxCmjaAbgYP83xHwXpa8YBysEBDejrqcdYrWb4=;
        b=hvNLyUYDuduzetpPsEKG7dFuw6ThB5UgsDij5VgbtA20Lh0CdmPPkC9ka8PkqKmXOo
         i0tGlTar8rIijgO7L4dXYcEx0+P/UsraHYEezdv0PlUdTuKsrsQFSoR4qn69ywtMMPz6
         lOYAhC/kodnvYCGYPeaE9Ln+JeUBUHDXbAz36UTk/cRa6f2neDwyifFa8OwkqZGaiZeg
         Vv9twRIHFt9RLhGEoxpRSwe83B3pgYw/pr3Iikv2qLfONCav+i2GhGT6T3Z5a6u/m2vB
         yMWr89YxL8qPdtxZIzVMqqJlzh/OoiHcltOthmcMbKMsUxnUEVJZsAcRWGJvQW7JCM1/
         NOrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=TL+kYVRg;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2a.google.com (mail-io1-xd2a.google.com. [2607:f8b0:4864:20::d2a])
        by gmr-mx.google.com with ESMTPS id w29si278113oth.3.2021.11.19.06.15.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Nov 2021 06:15:35 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2a as permitted sender) client-ip=2607:f8b0:4864:20::d2a;
Received: by mail-io1-xd2a.google.com with SMTP id k21so12925909ioh.4
        for <kasan-dev@googlegroups.com>; Fri, 19 Nov 2021 06:15:35 -0800 (PST)
X-Received: by 2002:a05:6638:2257:: with SMTP id m23mr28073982jas.17.1637331335309;
 Fri, 19 Nov 2021 06:15:35 -0800 (PST)
MIME-Version: 1.0
References: <20211118054426.4123-1-Kuan-Ying.Lee@mediatek.com> <754511d9a0368065768cc3ad8037184d62c3fbd1.camel@mediatek.com>
In-Reply-To: <754511d9a0368065768cc3ad8037184d62c3fbd1.camel@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 19 Nov 2021 15:15:24 +0100
Message-ID: <CA+fCnZddknY6XLychkAUkf9eYvEW4z9Oyr8cZb2QfBMDkJ23zg@mail.gmail.com>
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
 header.i=@gmail.com header.s=20210112 header.b=TL+kYVRg;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2a
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

How is this call sequence valid? page_address returns the address of
the start of the page, while kmalloced object could have been located
in the middle of it.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZddknY6XLychkAUkf9eYvEW4z9Oyr8cZb2QfBMDkJ23zg%40mail.gmail.com.
