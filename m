Return-Path: <kasan-dev+bncBDY7XDHKR4OBB7X532GAMGQE24QULZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D729457175
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 16:13:03 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id i5-20020ac85c05000000b002ae12b76e64sf7094933qti.6
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 07:13:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637334782; cv=pass;
        d=google.com; s=arc-20160816;
        b=ixa3R5nN1Bw4lcoGfJpN0dVDblBWJ+zx9/dP3i83GQQsv2rdvABccNeOL0K/Q9Tqzv
         ZAESXuDoTCyfgoeURDC+ynunVgwDlndtTFcFrFXa59TTHIqcfQqRdcGT7Yuy0bzLb4YH
         hXG+vNk5VjRjzvYpExgSoB0P34ictbA7Kj6z2HsygiWmaElhbscM+pyh//G2tDV4PucE
         xq4snYoSz6lS30VkevbFybdrPZpHGn4oo+duwr5dCKVQolukohzszb2J7qlQCuHFr9c9
         a6BSazNUkqy9SBQOI0pNGHa1XkcAfIkhhW+nzupX1SIN+7BSGHCXtF2c/tn3t1pulcGU
         IFJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=CX7ppC12/GCEttMKPJMOCNdmnKWB9Sm2OLk1Jn9ZrYI=;
        b=Y7sSWlE8az5poWsEcvFvIKuuCfzLrduEs++UV0FBLsfTAjBc8+YnjZT14cNWPeUUrC
         0ILaoxJhAcybuJl9gMaZh/Bi0GINqpbuVoO8Kx69yaXkKK23/BhJrODqJaVRasInc4P/
         vs1gAEd/dnMt2lcKY59l9POOYTNyr1+tiTsyTolhFMATY9FctxlqspQg//MzHq7xhAVt
         Q5c/4Uq4dz4mRiPs2+lQ3TdX5slybj48uANV8g4OdnlSFZHpH4snRwkl/SGRNQlpEQ5f
         gttI0waj+yCIgHrg1JF2j6bTkhu2OAPOB+j9BKwm0T5Y1R9bMJZzyH5PZe5mi6opQlIc
         tfRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CX7ppC12/GCEttMKPJMOCNdmnKWB9Sm2OLk1Jn9ZrYI=;
        b=a5NTCTg43PTSIxOyXPNQsOeNTPOSDkgaVnlS1TErSs9u/Id0KtRJ66JfsUnzX/NyPC
         jAbP+NcbL2/jzwR7PFuUu2aXKHsNQ/Lakq49Jxx6m59KaZpunj4Dx3P5aiRyGwj+Au5/
         3DlD0n155OxIFHD5qfGVFbE/jTlyh79CR9O5V1WQN4cJMWS4NUVhjXYraTpF9MzwIcby
         rrEOHmayD5hLbuGarrSLr31OH8MKPzixE4xlyWiwJbIHKdv982EnBlilYa3/xrZ/7sze
         XN+wbspEGu6FLDJuI8fSHwee2dysB0F+ske4Muvkqr1o2jamghgq2nR3wmXbjGnIPwBr
         j8eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CX7ppC12/GCEttMKPJMOCNdmnKWB9Sm2OLk1Jn9ZrYI=;
        b=MRjp4xpPer/6gCQ7PGuD4hDUBwvRKLFRZse6yNOJjTGcLmyp00TWzpTXvcv8lf0R5s
         Ds+TjApDq4gHXS5WjodxLy2IVvSM8LXOwUexs1kuwfVap3kAQ6AAJXcrmxVgUQ28pV5R
         dKwX6EIT2QHGm92xg4jNyoPK618cAju3ZukEnCXGTR5VHeqSLPmwJhrYPk83KuQ3xGED
         9rPxLpI2cujrmJDMP5hcTPctUabJ5NTu9b2M8vArvLb1SmCU1ZVplN9RUYNuRlb5RiMt
         WuN0Z3EgDq2ilLEqznrzo+158duvh2OEV+oCZ9rdv0fRQqTjvsn3VD8H13c6ktnTFZN8
         EYSQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531MR62zOaCh3+vRR/9nGjFsYlnh4aIo/qfB0Rcf5KgIjrf0Gmqz
	zZ2AHPMnl4ORBX+OD2uo+W4=
X-Google-Smtp-Source: ABdhPJwBm0ephlQ7afQZnVm95l9nrH/r90Yye4J866sKqcgRHGywGFD3ydNWcZERJADwZMfOQqU4iA==
X-Received: by 2002:a05:620a:bd6:: with SMTP id s22mr29385867qki.306.1637334782088;
        Fri, 19 Nov 2021 07:13:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1866:: with SMTP id eh6ls27780qvb.1.gmail; Fri, 19
 Nov 2021 07:13:01 -0800 (PST)
X-Received: by 2002:a05:6214:501b:: with SMTP id jo27mr75488761qvb.64.1637334781673;
        Fri, 19 Nov 2021 07:13:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637334781; cv=none;
        d=google.com; s=arc-20160816;
        b=qYTtqMpx8Jal0aPoXgXQPl7Cv+Ia4ABBApiIajVeTqm6IneQfOu4kf2A9mxiTZFw4x
         OfkJC+4FduOcusZDZmXzDdz9TBbAX/HNNVYJA2/v95S82UxFMZb03INqsnYUlWCmC0+R
         pbIBBmEgRtbKli1cEMPotlVZr/eSVW50gvHVQoavS8yWXoVp8+Us3Zw6slF1Vd1RvRDf
         xlZEw/eN9sp/9n50n4M0y1Zfn593+IBlaGVzK1a8C9YfLIepzkBBcIpf9k560TSLHey6
         MD18uf57Yip8Hvcs7D2UD22qV5voMqYnzqcPlPGMXGqIumFqQo107m9QBsG7HSvsnhSV
         AYww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=rur3k8TXjDWQ5SsranouqxH9DaqYe8Cx54WbyA/Yy+Y=;
        b=oyjrK5hAnQm40MOeDi6JggRGxvMp3gq0XiSJSApJQy3ybpk4OWTswqTPddiEBI4yeY
         uVnqe15IzupDL/ONSw/UU5F68YKuXSy7D9HO0d/Z6D0bqjappVbMUkAmyqq6dWmiRSAN
         JpeHHLbsvJ9GLZXirQTCNyCDoLsILhi1fFwjujsl/fCrCORmpt+G2B2uaHUevcvDcV0T
         dsqLIZix1QtsJBjgzfflkauZL8c5bpZ+LPnnqkBhIYM8BHkP5cuoz1F8LtO9olDsOa3g
         hQuY8UcTXYAivzE2hOG0guwIw8ekGFs0HMjsxm8mqJlP2CkCr+rxd9mVmQ/Hx17a7mP/
         +a3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id u2si20736qkp.6.2021.11.19.07.13.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Nov 2021 07:13:01 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 0aeac716630e475c87c099b9aa70375d-20211119
X-UUID: 0aeac716630e475c87c099b9aa70375d-20211119
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1689223143; Fri, 19 Nov 2021 23:12:57 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 15.2.792.15; Fri, 19 Nov 2021 23:12:56 +0800
Received: from mtksdccf07 (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 19 Nov 2021 23:12:55 +0800
Message-ID: <c5cfd0c41dee93cd923762a6e0d61baea52cec8d.camel@mediatek.com>
Subject: Re: [PATCH] kmemleak: fix kmemleak false positive report with HW
 tag-based kasan enable
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Catalin Marinas <catalin.marinas@arm.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>,
	Chinwen Chang =?UTF-8?Q?=28=E5=BC=B5=E9=8C=A6=E6=96=87=29?=
	<chinwen.chang@mediatek.com>, Nicholas Tang
 =?UTF-8?Q?=28=E9=84=AD=E7=A7=A6=E8=BC=9D=29?= <nicholas.tang@mediatek.com>,
	James Hsu =?UTF-8?Q?=28=E5=BE=90=E6=85=B6=E8=96=B0=29?=
	<James.Hsu@mediatek.com>, Yee Lee
 =?UTF-8?Q?=28=E6=9D=8E=E5=BB=BA=E8=AA=BC=29?= <Yee.Lee@mediatek.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "linux-mediatek@lists.infradead.org"
	<linux-mediatek@lists.infradead.org>, kasan-dev <kasan-dev@googlegroups.com>,
	<kuan-ying.lee@mediatek.com>
Date: Fri, 19 Nov 2021 23:12:55 +0800
In-Reply-To: <CA+fCnZddknY6XLychkAUkf9eYvEW4z9Oyr8cZb2QfBMDkJ23zg@mail.gmail.com>
References: <20211118054426.4123-1-Kuan-Ying.Lee@mediatek.com>
	 <754511d9a0368065768cc3ad8037184d62c3fbd1.camel@mediatek.com>
	 <CA+fCnZddknY6XLychkAUkf9eYvEW4z9Oyr8cZb2QfBMDkJ23zg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Fri, 2021-11-19 at 22:15 +0800, Andrey Konovalov wrote:
> On Thu, Nov 18, 2021 at 10:20 AM Kuan-Ying Lee
> <Kuan-Ying.Lee@mediatek.com> wrote:
> > 
> > +Cc kasan group
> > 
> > On Thu, 2021-11-18 at 13:44 +0800, Kuan-Ying Lee wrote:
> > > With HW tag-based kasan enable, We will get the warning
> > > when we free object whose address starts with 0xFF.
> > > 
> > > It is because kmemleak rbtree stores tagged object and
> > > this freeing object's tag does not match with rbtree object.
> > > 
> > > In the example below, kmemleak rbtree stores the tagged object in
> > > the kmalloc(), and kfree() gets the pointer with 0xFF tag.
> > > 
> > > Call sequence:
> > > ptr = kmalloc(size, GFP_KERNEL);
> > > page = virt_to_page(ptr);
> > > kfree(page_address(page));
> > > ptr = kmalloc(size, GFP_KERNEL);
> 
> How is this call sequence valid? page_address returns the address of
> the start of the page, while kmalloced object could have been located
> in the middle of it.

Thanks for pointing out. I miss the offset.

It should be listed as below.

ptr = kmalloc(size, GFP_KERNEL);
page = virt_to_page(ptr);
offset = offset_in_page(ptr);
kfree(page_address(page) + offset);
ptr = kmalloc(size, GFP_KERNEL);

> 
> > > 
> > > Call sequence like that may cause the warning as following:
> > > 1) Freeing unknown object:
> > > In kfree(), we will get free unknown object warning in
> > > kmemleak_free().
> > > Because object(0xFx) in kmemleak rbtree and pointer(0xFF) in
> > > kfree()
> > > have
> > > different tag.
> > > 
> > > 2) Overlap existing:
> > > When we allocate that object with the same hw-tag again, we will
> > > find the overlap in the kmemleak rbtree and kmemleak thread will
> > > be killed.
> > > 
> > > [  116.685312] kmemleak: Freeing unknown object at
> > > 0xffff000003f88000
> > > [  116.686422] CPU: 5 PID: 177 Comm: cat Not tainted 5.16.0-rc1-
> > > dirty
> > > #21
> > > [  116.687067] Hardware name: linux,dummy-virt (DT)
> > > [  116.687496] Call trace:
> > > [  116.687792]  dump_backtrace+0x0/0x1ac
> > > [  116.688255]  show_stack+0x1c/0x30
> > > [  116.688663]  dump_stack_lvl+0x68/0x84
> > > [  116.689096]  dump_stack+0x1c/0x38
> > > [  116.689499]  kmemleak_free+0x6c/0x70
> > > [  116.689919]  slab_free_freelist_hook+0x104/0x200
> > > [  116.690420]  kmem_cache_free+0xa8/0x3d4
> > > [  116.690845]  test_version_show+0x270/0x3a0
> > > [  116.691344]  module_attr_show+0x28/0x40
> > > [  116.691789]  sysfs_kf_seq_show+0xb0/0x130
> > > [  116.692245]  kernfs_seq_show+0x30/0x40
> > > [  116.692678]  seq_read_iter+0x1bc/0x4b0
> > > [  116.692678]  seq_read_iter+0x1bc/0x4b0
> > > [  116.693114]  kernfs_fop_read_iter+0x144/0x1c0
> > > [  116.693586]  generic_file_splice_read+0xd0/0x184
> > > [  116.694078]  do_splice_to+0x90/0xe0
> > > [  116.694498]  splice_direct_to_actor+0xb8/0x250
> > > [  116.694975]  do_splice_direct+0x88/0xd4
> > > [  116.695409]  do_sendfile+0x2b0/0x344
> > > [  116.695829]  __arm64_sys_sendfile64+0x164/0x16c
> > > [  116.696306]  invoke_syscall+0x48/0x114
> > > [  116.696735]  el0_svc_common.constprop.0+0x44/0xec
> > > [  116.697263]  do_el0_svc+0x74/0x90
> > > [  116.697665]  el0_svc+0x20/0x80
> > > [  116.698261]  el0t_64_sync_handler+0x1a8/0x1b0
> > > [  116.698695]  el0t_64_sync+0x1ac/0x1b0
> > > ...
> > > [  117.520301] kmemleak: Cannot insert 0xf2ff000003f88000 into
> > > the
> > > object search tree (overlaps existing)
> > > [  117.521118] CPU: 5 PID: 178 Comm: cat Not tainted 5.16.0-rc1-
> > > dirty
> > > #21
> > > [  117.521827] Hardware name: linux,dummy-virt (DT)
> > > [  117.522287] Call trace:
> > > [  117.522586]  dump_backtrace+0x0/0x1ac
> > > [  117.523053]  show_stack+0x1c/0x30
> > > [  117.523578]  dump_stack_lvl+0x68/0x84
> > > [  117.524039]  dump_stack+0x1c/0x38
> > > [  117.524472]  create_object.isra.0+0x2d8/0x2fc
> > > [  117.524975]  kmemleak_alloc+0x34/0x40
> > > [  117.525416]  kmem_cache_alloc+0x23c/0x2f0
> > > [  117.525914]  test_version_show+0x1fc/0x3a0
> > > [  117.526379]  module_attr_show+0x28/0x40
> > > [  117.526827]  sysfs_kf_seq_show+0xb0/0x130
> > > [  117.527363]  kernfs_seq_show+0x30/0x40
> > > [  117.527848]  seq_read_iter+0x1bc/0x4b0
> > > [  117.528320]  kernfs_fop_read_iter+0x144/0x1c0
> > > [  117.528809]  generic_file_splice_read+0xd0/0x184
> > > [  117.529316]  do_splice_to+0x90/0xe0
> > > [  117.529734]  splice_direct_to_actor+0xb8/0x250
> > > [  117.530227]  do_splice_direct+0x88/0xd4
> > > [  117.530686]  do_sendfile+0x2b0/0x344
> > > [  117.531154]  __arm64_sys_sendfile64+0x164/0x16c
> > > [  117.531673]  invoke_syscall+0x48/0x114
> > > [  117.532111]  el0_svc_common.constprop.0+0x44/0xec
> > > [  117.532621]  do_el0_svc+0x74/0x90
> > > [  117.533048]  el0_svc+0x20/0x80
> > > [  117.533461]  el0t_64_sync_handler+0x1a8/0x1b0
> > > [  117.533950]  el0t_64_sync+0x1ac/0x1b0
> > > [  117.534625] kmemleak: Kernel memory leak detector disabled
> > > [  117.535201] kmemleak: Object 0xf2ff000003f88000 (size 128):
> > > [  117.535761] kmemleak:   comm "cat", pid 177, jiffies
> > > 4294921177
> > > [  117.536339] kmemleak:   min_count = 1
> > > [  117.536718] kmemleak:   count = 0
> > > [  117.537068] kmemleak:   flags = 0x1
> > > [  117.537429] kmemleak:   checksum = 0
> > > [  117.537806] kmemleak:   backtrace:
> > > [  117.538211]      kmem_cache_alloc+0x23c/0x2f0
> > > [  117.538924]      test_version_show+0x1fc/0x3a0
> > > [  117.539393]      module_attr_show+0x28/0x40
> > > [  117.539844]      sysfs_kf_seq_show+0xb0/0x130
> > > [  117.540304]      kernfs_seq_show+0x30/0x40
> > > [  117.540750]      seq_read_iter+0x1bc/0x4b0
> > > [  117.541206]      kernfs_fop_read_iter+0x144/0x1c0
> > > [  117.541687]      generic_file_splice_read+0xd0/0x184
> > > [  117.542182]      do_splice_to+0x90/0xe0
> > > [  117.542611]      splice_direct_to_actor+0xb8/0x250
> > > [  117.543097]      do_splice_direct+0x88/0xd4
> > > [  117.543544]      do_sendfile+0x2b0/0x344
> > > [  117.543983]      __arm64_sys_sendfile64+0x164/0x16c
> > > [  117.544471]      invoke_syscall+0x48/0x114
> > > [  117.544917]      el0_svc_common.constprop.0+0x44/0xec
> > > [  117.545416]      do_el0_svc+0x74/0x90
> > > [  117.554100] kmemleak: Automatic memory scanning thread ended
> > > 
> > > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > > ---
> > >  mm/kmemleak.c | 17 ++++++++++++-----
> > >  1 file changed, 12 insertions(+), 5 deletions(-)
> > > 
> > > diff --git a/mm/kmemleak.c b/mm/kmemleak.c
> > > index b57383c17cf6..fa12e2e08cdc 100644
> > > --- a/mm/kmemleak.c
> > > +++ b/mm/kmemleak.c
> > > @@ -381,15 +381,20 @@ static void dump_object_info(struct
> > > kmemleak_object *object)
> > >  static struct kmemleak_object *lookup_object(unsigned long ptr,
> > > int
> > > alias)
> > >  {
> > >       struct rb_node *rb = object_tree_root.rb_node;
> > > +     unsigned long untagged_ptr = (unsigned
> > > long)kasan_reset_tag((void *)ptr);
> > > 
> > >       while (rb) {
> > >               struct kmemleak_object *object =
> > >                       rb_entry(rb, struct kmemleak_object,
> > > rb_node);
> > > -             if (ptr < object->pointer)
> > > +             unsigned long untagged_objp;
> > > +
> > > +             untagged_objp = (unsigned
> > > long)kasan_reset_tag((void
> > > *)object->pointer);
> > > +
> > > +             if (untagged_ptr < untagged_objp)
> > >                       rb = object->rb_node.rb_left;
> > > -             else if (object->pointer + object->size <= ptr)
> > > +             else if (untagged_objp + object->size <=
> > > untagged_ptr)
> > >                       rb = object->rb_node.rb_right;
> > > -             else if (object->pointer == ptr || alias)
> > > +             else if (untagged_objp == untagged_ptr || alias)
> > >                       return object;
> > >               else {
> > >                       kmemleak_warn("Found object by alias at
> > > 0x%08lx\n",
> > > @@ -576,6 +581,7 @@ static struct kmemleak_object
> > > *create_object(unsigned long ptr, size_t size,
> > >       struct kmemleak_object *object, *parent;
> > >       struct rb_node **link, *rb_parent;
> > >       unsigned long untagged_ptr;
> > > +     unsigned long untagged_objp;
> > > 
> > >       object = mem_pool_alloc(gfp);
> > >       if (!object) {
> > > @@ -629,9 +635,10 @@ static struct kmemleak_object
> > > *create_object(unsigned long ptr, size_t size,
> > >       while (*link) {
> > >               rb_parent = *link;
> > >               parent = rb_entry(rb_parent, struct
> > > kmemleak_object,
> > > rb_node);
> > > -             if (ptr + size <= parent->pointer)
> > > +             untagged_objp = (unsigned
> > > long)kasan_reset_tag((void
> > > *)parent->pointer);
> > > +             if (untagged_ptr + size <= untagged_objp)
> > >                       link = &parent->rb_node.rb_left;
> > > -             else if (parent->pointer + parent->size <= ptr)
> > > +             else if (untagged_objp + parent->size <=
> > > untagged_ptr)
> > >                       link = &parent->rb_node.rb_right;
> > >               else {
> > >                       kmemleak_stop("Cannot insert 0x%lx into the
> > > object search tree (overlaps existing)\n",
> > > --
> > > 2.18.0
> > > 
> > 
> > --
> > You received this message because you are subscribed to the Google
> > Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it,
> > send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit 
> > https://urldefense.com/v3/__https://groups.google.com/d/msgid/kasan-dev/754511d9a0368065768cc3ad8037184d62c3fbd1.camel*40mediatek.com__;JQ!!CTRNKA9wMg0ARbw!y7gGU0PsiMId4XiGTZzBUUL_WtWQ24nnTQtGbFrZ46wqfwk8ZeYCVP2pYmNFHrAUGOKr1g$
> >  .

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c5cfd0c41dee93cd923762a6e0d61baea52cec8d.camel%40mediatek.com.
