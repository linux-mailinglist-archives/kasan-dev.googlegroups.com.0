Return-Path: <kasan-dev+bncBAABBQNPQSJQMGQEISLCIAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 53D9E509AD1
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 10:37:24 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id n9-20020a056602340900b006572c443316sf1805007ioz.23
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 01:37:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650530243; cv=pass;
        d=google.com; s=arc-20160816;
        b=nQjKIC303dW31vZAsaPAJUUeupH6r6tnvpjIBzoCwkhZPIBNYl8DyWWPnEtzQdyyqm
         Iyi1rbYPfReelqwC9OWdyMf8KJ+Vr9Ga2gjMiKDhjdxSr+UEIRrXCVqW5229FP/blmYV
         z1PGHxVlrBVvjO1zJmW87Zr6/PBvrA2meWfGP4YfbaUG1QxZNAWtn5EVxJAtuzT2r4pE
         YGAwDz6u7yQFa2xid557vIB80rCWhE98+cUbDvcvg4gDlHjCkXNhKADkHUIXiuPS+xlq
         wqDkWhelLtC7CIWFzphsV2Fa3KUac8G7XyoU/zsOs0rti2yPKwiG8uD3ikUjmmzneOTb
         Q2gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=JuNVVzb97iYeQQ30Fwnofv4e9BQfnCdDQKGBAOojI00=;
        b=VhFygmd0KDg3kgfBPg4uNo7IdcMS1+KQ42fcRcbrRrkGIIhTnpiVL38qUlzG0dursV
         MIngUoeliPxYeK2NI6AukmBssOE67UDaaWy2H+LiZQIaVM+Eybr5NFTDdi0N5c+eiJWX
         /9qC0qY4JCWTh8KcBdMYD+GCtV8NvMQAtQlmz85FaC0TNYjVonk6m5SZkvIVDwifWc46
         OTr+yjc9bREZWIl4IUzhPDCsfVYJhG0cRJ7KHkbEICDlSQ5u7OPwjb9zuKZMMLtLpHco
         BbzTVvfFBamVoUfo5bnllIt45eTolyE0Vw+QKjReBBVywq6rtLCaCrs3E239G3+p9WpR
         5kSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JuNVVzb97iYeQQ30Fwnofv4e9BQfnCdDQKGBAOojI00=;
        b=UNxa4VVvUHp7QhT7qU788of5O5zKFI/AmTK4pS0SHoFUgTmMAtmYEgH+dki7RT88ni
         MvGyafwRj0OOZ+95qYD0KWpT5n+G+ggVWrFhT3eHAOz5eFlUVW1wWsI7J2wheIFCaXZj
         zgITVjpspveUxEBJ2WWXlKM2BdMItwn25vNrVScyl1t434K9VmgHC3sKMqzTEmKu3Vmy
         7iXb916KsJH+TwvntG9rBwRkVrZXFmIVwn/71WOD+9G5fS353WkDMvZ3+/x0x3UhSChI
         viFxlcJxyakuSxXkZ3sJ5Bagy8MuH/K4qWqNo/AzQZrk8J/Ht5I6SVM0qZCd3ppVeahg
         q5dA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JuNVVzb97iYeQQ30Fwnofv4e9BQfnCdDQKGBAOojI00=;
        b=t9xxm/hKrvFWpCG4b1kC0bE3U970bsMoOrZkOtGPi8vMW4edGB1V2ifsUD8kLzMYCS
         teCOjhv2a4VCIS/rq/DkaigYxAECY5p5PRU0Y1EEoNiduyeC7Ky+Wp5xXGQvE81zxAbp
         IgTuRw4s251FBqkz7DTv4Dc0liN/Fckg8zLCjV8EWfGX5SC0vfWqpoMfSVydo0ktxbSG
         wz3TgGjYzbzEheGwRaV51KPMwFYt6yXHtU3wASDuynd6XAeUNe33ePokSDMJY73JHPgi
         cbXh6reM+sZ4gBPEWPCd2m49KKfHJ+XVyFBkxZcB74gO5w6PMGScSYT6ITTC8TY9yYvU
         7z2Q==
X-Gm-Message-State: AOAM532gT1X2u+wOwvsehE+XTaJEQywwiwvhykhr7twsgU5nt/C+PfX2
	ms+yUo8KyMnOfRRVjGl1TEI=
X-Google-Smtp-Source: ABdhPJzO8WGdaoNtIJyedSEixAchJjQEfYXWFKO4NjogZItlnufumcnaONlqp7ZOd1PrUIxKmccsZg==
X-Received: by 2002:a02:11c8:0:b0:328:8f79:557c with SMTP id 191-20020a0211c8000000b003288f79557cmr7741142jaf.265.1650530241343;
        Thu, 21 Apr 2022 01:37:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:334a:0:b0:326:6590:f908 with SMTP id k10-20020a02334a000000b003266590f908ls1335427jak.8.gmail;
 Thu, 21 Apr 2022 01:37:21 -0700 (PDT)
X-Received: by 2002:a05:6638:1384:b0:32a:9e39:a194 with SMTP id w4-20020a056638138400b0032a9e39a194mr864027jad.164.1650530240875;
        Thu, 21 Apr 2022 01:37:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650530240; cv=none;
        d=google.com; s=arc-20160816;
        b=urMpfAzl0M4IszeqURg0OkRPd9jAwfJ65qN58mL20dz5vMW8NR4VLWj3ikLp69cf0Z
         EWKIDDZ2Y5k3c7JXYg1H/fRr5cl2Sl//eEe/AJcq2QHl1cyp1Uj3guNcEFkxzKmzeG2o
         gZEY194xZEMvRHDlGdVBeKLWvNwioYpssfQMSSLZ2N14SLleDwY8Jj8q/CNqn/dEL8nQ
         OIpC9+fK+MaonkXtPYxencFwwhdRsQQ2spew4ZsLKgpdY1iWvjStQWbgFfTAho1a95yS
         Iia4NPJ5n+yt9BLD3vZQPwNzoqVmAclUlC1DJjXvx8uqMOeBFAGb90iW6jsdZ6zi/P6O
         SZ2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=NDsYuH7QcewgUmcYPV1ZoeEsSIlM/ZiHSiSZm9ExmRg=;
        b=yphto4PoGSq/kfncccKUaYPtMsZ+ZW+kDGx1nvpKj9X6/Iv8zSxyocHWPEKGv91UVI
         CwrualQVih0rNBTpHC39dQSGeT8tKU3TMTvmDVHuE5pDnSLTKygtI4WiyLd4BOc2m8sy
         odJR6+ul3ObQOVzD1W11NytOkEG0atWq6Lzy4QIOdFYvDc9pRxfgwwONwmt/BhnYdIjc
         O+7CKH4b+atOao5sRE0Td3xuvOZeQ+bnBqxEp62YRbm9HWIs1MiYInV+ZIYUZ9PRvrNb
         SSFTB0k14ItqVteeD33dgoI1A/XcWEXjiQmAGLx82bjwrN/AT2sJjZrthLcnnyw9dBWD
         vc0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id u15-20020a0282cf000000b0032660e40516si193000jag.2.2022.04.21.01.37.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Apr 2022 01:37:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from kwepemi500025.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4KkW9w1CZrzhXdc;
	Thu, 21 Apr 2022 16:37:08 +0800 (CST)
Received: from kwepemm600020.china.huawei.com (7.193.23.147) by
 kwepemi500025.china.huawei.com (7.221.188.170) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Thu, 21 Apr 2022 16:37:17 +0800
Received: from DESKTOP-E0KHRBE.china.huawei.com (10.67.111.5) by
 kwepemm600020.china.huawei.com (7.193.23.147) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.24; Thu, 21 Apr 2022 16:37:16 +0800
From: "'Shaobo Huang' via kasan-dev" <kasan-dev@googlegroups.com>
To: <elver@google.com>
CC: <akpm@linux-foundation.org>, <chenzefeng2@huawei.com>,
	<dvyukov@google.com>, <glider@google.com>, <huangshaobo6@huawei.com>,
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <nixiaoming@huawei.com>, <wangbing6@huawei.com>,
	<wangfangpeng1@huawei.com>, <young.liuyang@huawei.com>,
	<zengweilin@huawei.com>, <zhongjubin@huawei.com>
Subject: Re: [PATCH] kfence: check kfence canary in panic and reboot
Date: Thu, 21 Apr 2022 16:37:15 +0800
Message-ID: <20220421083715.45380-1-huangshaobo6@huawei.com>
X-Mailer: git-send-email 2.21.0.windows.1
In-Reply-To: <Yl/qa2w3q9kyXcQl@elver.google.com>
References: <Yl/qa2w3q9kyXcQl@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.111.5]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 kwepemm600020.china.huawei.com (7.193.23.147)
X-CFilter-Loop: Reflected
X-Original-Sender: huangshaobo6@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of huangshaobo6@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=huangshaobo6@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Shaobo Huang <huangshaobo6@huawei.com>
Reply-To: Shaobo Huang <huangshaobo6@huawei.com>
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

On Wed, 20 Apr 2022 13:11:39 +0200, Marco Elver wrote:
> On Wed, Apr 20, 2022 at 06:49PM +0800, Shaobo Huang wrote:
> > From: huangshaobo <huangshaobo6@huawei.com>
> > 
> > when writing out of bounds to the red zone, it can only be detected at
> > kfree. However, there were many scenarios before kfree that caused this
> > out-of-bounds write to not be detected. Therefore, it is necessary to
> > provide a method for actively detecting out-of-bounds writing to the red
> > zone, so that users can actively detect, and can be detected in the
> > system reboot or panic.
> > 
> > for example, if the application memory is out of bounds and written to
> > the red zone in the kfence object, the system suddenly panics, and the
> following log can be seen during system reset:
> 
> Interesting idea - however, when KFENCE is deployed to a fleet, the same
> bug will eventually manifest as an OOB that hits a guard page (because
> random placement), and produce the normal out-of-bounds message.
> 
> Have you found new bugs this way?

We haven't found bugs in this way yet, but we have proved that this way works through injection tests.

> But doing this check on panic doesn't seem to hurt. But please see
> comments below.
> 
> > BUG: KFENCE: memory corruption in atomic_notifier_call_chain+0x49/0x70
> > 
> > Corrupted memory at 0x(____ptrval____) [ ! ] (in kfence-#59):
> >  atomic_notifier_call_chain+0x49/0x70
> >  panic+0x134/0x278
> >  sysrq_handle_crash+0x11/0x20
> >  __handle_sysrq+0x99/0x160
> >  write_sysrq_trigger+0x26/0x30
> >  proc_reg_write+0x51/0x70
> >  vfs_write+0xb6/0x290
> >  ksys_write+0x9c/0xd0
> >  __do_fast_syscall_32+0x67/0xe0
> >  do_fast_syscall_32+0x2f/0x70
> >  entry_SYSCALL_compat_after_hwframe+0x45/0x4d
> > 
> > kfence-#59: 0x(____ptrval____)-0x(____ptrval____),size=100,cache=kmalloc-128
> >  allocated by task 77 on cpu 0 at 28.018073s:
> >  0xffffffffc007703d
> >  do_one_initcall+0x3c/0x1e0
> >  do_init_module+0x46/0x1d8
> >  load_module+0x2397/0x2860
> >  __do_sys_init_module+0x160/0x190
> >  __do_fast_syscall_32+0x67/0xe0
> >  do_fast_syscall_32+0x2f/0x70
> >  entry_SYSCALL_compat_after_hwframe+0x45/0x4d
> 
> Is this a real bug? Or one you injected?

one injected, construct red zone oob, echo c > /proc/sysrq-trigger to trigger panic.
The call stack example here will be deleted later.

> > Suggested-by: chenzefeng <chenzefeng2@huawei.com>
> > Signed-off-by: huangshaobo <huangshaobo6@huawei.com>
> > ---
> >  mm/kfence/core.c | 28 ++++++++++++++++++++++++++++
> >  1 file changed, 28 insertions(+)
> > 
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > index 9b2b5f56f4ae..85cc3ca4b71c 100644
> > --- a/mm/kfence/core.c
> > +++ b/mm/kfence/core.c
> > @@ -29,6 +29,9 @@
> >  #include <linux/slab.h>
> >  #include <linux/spinlock.h>
> >  #include <linux/string.h>
> > +#include <linux/notifier.h>
> > +#include <linux/reboot.h>
> +#include <linux/panic_notifier.h>
> >  
> >  #include <asm/kfence.h>
> >  
> > @@ -716,6 +719,29 @@ static const struct file_operations objects_fops = {
> >  	.release = seq_release,
> >  };
> >  
> > +static void kfence_check_all_canary(void)
> > +{
> > +	int i;
> > +
> > +	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
> > +		struct kfence_metadata *meta = &kfence_metadata[i];
> > +
> > +		if (meta->state == KFENCE_OBJECT_ALLOCATED)
> > +			for_each_canary(meta, check_canary_byte);
> > +	}
> > +}
> > +
> > +static int kfence_check_canary_callback(struct notifier_block *nb,
> > +					unsigned long reason, void *arg)
> > +{
> > +	kfence_check_all_canary();
> > +	return NOTIFY_OK;
> > +}
> > +
> > +static struct notifier_block kfence_check_canary_notifier = {
> > +	.notifier_call = kfence_check_canary_callback,
> > +};
> 
> Sorry to be pedantic, but this is a pretty random place to put this
> code. Can you put it after the debugfs section, perhaps with:
> 
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -748,6 +748,10 @@ static int __init kfence_debugfs_init(void)
>  
>  late_initcall(kfence_debugfs_init);
>  
> +/* === Reboot Notifier ====================================================== */
> +
> +< your code here >
> +
>  /* === Allocation Gate Timer ================================================ */
>  
>  static struct delayed_work kfence_timer;

thanks for your suggestion, I will modify it according to your suggestions later.

> >  static int __init kfence_debugfs_init(void)
> >  {
> >  	struct dentry *kfence_dir = debugfs_create_dir("kfence", NULL);
> > @@ -806,6 +832,8 @@ static void kfence_init_enable(void)
> >  
> >  	WRITE_ONCE(kfence_enabled, true);
> >  	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
> > +	register_reboot_notifier(&kfence_check_canary_notifier);
> > +	atomic_notifier_chain_register(&panic_notifier_list, &kfence_check_canary_notifier);
> 
> Executing this on panic is reasonable. However,
> register_reboot_notifier() tells me this is being executed on *every*
> reboot (not just panic). I think that's not what we want, because that
> may increase reboot latency depending on how many KFENCE objects we
> have. Is it possible to *only* do the check on panic?

if oob occurs before reboot, reboot can also detect it, if not, the detection will be missing in this scenario.
reboot and panic are two scenarios of system reset, so I think both scenarios need to be added.
 
> Thanks,
> -- Marco

thanks,
ShaoBo Huang

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220421083715.45380-1-huangshaobo6%40huawei.com.
