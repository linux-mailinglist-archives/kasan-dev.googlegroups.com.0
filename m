Return-Path: <kasan-dev+bncBDDL3KWR4EBRBMOMRGBAMGQEWHP2M7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id EF78032F0D8
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 18:11:14 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id r18sf1435398pfc.17
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 09:11:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614964273; cv=pass;
        d=google.com; s=arc-20160816;
        b=tfyCl6yIt0GCQIns1MRLbC78dfCORVwbvfMmr8tXobiUnGtnnqV0buD4XKSaEAWxsI
         5WxzeBFYFGAYDfQomMgfw4jCQD7xmJj3OyQxHsyD1aR8Hc2GGEMtbaGd8Ib351/3pmDR
         QrpPYq8VnY6qj3gRVBLCL7tBqqlVenbdr6qD3hGcNac/5A1sw/deouf+mgxp6Hxm4qZP
         Mj1MblThhhc8cWim7Ea0K8hF/5DXsxuGtG03aLKxVXiEpGq9r7Njxd+PlaiK8hwHwYwI
         OQFTPV4YhnN7OqHMT47vnrUMFMKOwYn6ig/1FvcjKImw0SGSl72R6EKvY9KiIm9wZ8Ly
         bj+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=G3WsKNC4fzreWLUsOXTsTg7F9LEM1y4Q7moZDb/8D0I=;
        b=KstW7pVXCnlwl7hhFQX/u9aVTrnrHuWGBBhYCHLjQsWDwNLvCyUnk7pnUrmcDItYLR
         nC6wOMuM/nd01eKbjR4jCbvU33ZVFbHdUaOrRYOgvV3MLslYme3BKnp9KOxLPkvYQZ4v
         KFrFBmvB07N9Df5wifO1medwiqkaJivLHLbWI2If1ChAcNllJB5li/o0q+9Va4AVpp6e
         Sr6W7o5nWvM9IrMcZvZcjqoSF2NydaVIXqhfKlWg1XWoqhXjEUAqGRpq7QSufFRc/aIj
         z45mGlQUvmDG6XHyBo34gxrChg34fConIESnlttRIFCWl9Is6VGJ/n6rXOo1QkhiMf5A
         52xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=G3WsKNC4fzreWLUsOXTsTg7F9LEM1y4Q7moZDb/8D0I=;
        b=bMM15dG/yzKPlcRmMWloZfpUKrVmRF7Doaqb8sN4zG8PJ3ONbFGGmLMXXWXkPvaBU8
         DMg35iKOokIPuaYQCrQZGGVQTh4b6HDOezxVcN5xmvMW2OakALLU2zQGRgamlGGIjXnf
         4XVpWOAIoC/yp4ppfb2YJTuCUnbrh7XTAQJajuh4wC4aes+Pf4JfLBOGVJ0PBvTOXa7N
         zAaOpXoXWp7QrQnOGuwOp9TTy213yUo/mGag4MpTKgPfGLUycNo24xgvFELt/DbhZ9yX
         VgxSIgY1QldsEW3sH55Ns5hBmZQ0eUrYSUsNmM2fWGS/bo4Gkr7Ge1Ntbh80WK4SAW9n
         lrrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :mime-version:content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G3WsKNC4fzreWLUsOXTsTg7F9LEM1y4Q7moZDb/8D0I=;
        b=mPWFt3WA0evBVFwabh1PnuCrjkrSoRIkfoRaF9qqU4lEwEzeKZGgPZWFS6a8L0GQPQ
         RSO+MCWahftuvVd8po4ns6Zou1zuzRpG2iFb41n/x4dCp3DxiKWX/BIf3IO+VHh3Bg7n
         zJZmr02D0YZsT/k6jbEoEK8Jd711zcUW4I8ykEUy+L0tUHeJ+VLTxtyps0HSFi4ud52Q
         g1eMVNJQFI8wxHGsv3Q+0DWlTtTbvO2wjPPE86A+JlKKJW4bMul6tqeJay83tF4fuSDB
         6yF8ubFPKq2wQ0mpQDjchV1whqsGVngYS26l7MQ5m/pxFzaaCpoakASYov+TGS7gxHzv
         MNlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Ps3m5vXWvBjVePR3cme9oQzk8EuDWd+sGKi+Emz3BFbukP04b
	XjT9e7NQjUKORoYi/i2TOuU=
X-Google-Smtp-Source: ABdhPJzXPf+RQRVP+2rGA8KnEuUZAiC05p03iWkaxEkR/vHEDfLm8U4L8CZKV/msL34EoFr3T0E8pg==
X-Received: by 2002:a17:90b:108f:: with SMTP id gj15mr11464126pjb.177.1614964273689;
        Fri, 05 Mar 2021 09:11:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1914:: with SMTP id z20ls661636pgl.0.gmail; Fri, 05 Mar
 2021 09:11:12 -0800 (PST)
X-Received: by 2002:a05:6a00:1385:b029:1be:ac19:3a9d with SMTP id t5-20020a056a001385b02901beac193a9dmr9739046pfg.65.1614964272798;
        Fri, 05 Mar 2021 09:11:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614964272; cv=none;
        d=google.com; s=arc-20160816;
        b=1G8rX8nod1dpYPMVXiXgAhXPEZxt3ousbZAPlo/r/1+SFDeafanzpIxPQhNdIACHBq
         Xu4fYy+JlZUdnrl7Y0bObrVOwITw6IUyNmtjzGliicYqUJZGLedg+Pp9BqJg8t4c8lMw
         K6HDtLwdDTfB+vcZnVjrMgXzE3rQaKZ/PgriGptShxiYAviDptCbeep3ZgpJem6PSrGr
         8CcctOgkfp7RPJjEVXNMDAFMMGzU2gMCG95krQcWLql+VEj20u0YgnewsFc4rYlv1qyL
         k0qtRQ+ttgRY5R3QtkRTh/wm7NqQ7xLYELNgcncYkbH3uL7Gkxw2o0b5spY1wzVOVSOc
         A8rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:message-id:subject:cc
         :to:from:date;
        bh=LECtyvmaVBbti5zvMrHo1EQhAyLp7O/xTYdGGCMN3L0=;
        b=krzs3Xd8mkXkt7Va1ToomnQ2gTzTjhwaSieQQW3rQpmCifvk7A1zAfKQ0FXYD0w4IX
         DSFjKJxYunT9+OMnsI2pbrBDNcaehJfrIzOW7Y4lUGQ1P2I/LGoVzGZXISWIyehI3rOm
         l8SjV+leukPqsRsDt0EAJFcgB8tlQIDPF6s+TGu8IR4Zac9tkX+dxkdH8rTLAiIAK11y
         +O2yR9gokcUv0JyW5xyyxxfUh8XfMMILmQ+em03kPKy94IvJxf9/2bDDa9UhyRhRKwtT
         QIaJhYzZ7Z0haz1KLzA65aZN2SGSSukCg9eDxSB3boVkvoEpfDofp2BchPI6CzraipSC
         E6/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k21si254596pfa.5.2021.03.05.09.11.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Mar 2021 09:11:12 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 75B666509A;
	Fri,  5 Mar 2021 17:11:11 +0000 (UTC)
Date: Fri, 5 Mar 2021 17:11:08 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>
Subject: arm64 KASAN_HW_TAGS panic on non-MTE hardware on 5.12-rc1
Message-ID: <20210305171108.GD23855@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

Hi Andrey,

Enabling CONFIG_KASAN_HW_TAGS and running the resulting kernel on
non-MTE hardware panics with an undefined STG instruction from
mte_set_mem_tag_range():

./scripts/faddr2line vmlinux kasan_unpoison_task_stack+0x18/0x40
kasan_unpoison_task_stack+0x18/0x40:
mte_set_mem_tag_range at arch/arm64/include/asm/mte-kasan.h:71
(inlined by) mte_set_mem_tag_range at arch/arm64/include/asm/mte-kasan.h:56
(inlined by) kasan_unpoison at mm/kasan/kasan.h:363
(inlined by) kasan_unpoison_task_stack at mm/kasan/common.c:72

The full trace:

------------[ cut here ]------------
kernel BUG at arch/arm64/kernel/traps.c:406!
Internal error: Oops - BUG: 0 [#1] PREEMPT SMP
Modules linked in:
CPU: 0 PID: 0 Comm: swapper Not tainted 5.12.0-rc1-00002-ge76afd1d69f3-dirty #2
pstate: 00000085 (nzcv daIf -PAN -UAO -TCO BTYPE=--)
pc : do_undefinstr+0x2c8/0x2e8
lr : do_undefinstr+0x2d4/0x2e8
sp : ffffc07baeaa3cf0
x29: ffffc07baeaa3cf0 x28: ffffc07baeab3280 
x27: ffffc07baeaa9a00 x26: ffffc07baeaa7000 
x25: ffffc07baeab3964 x24: ffffc07baeaa9c00 
x23: 0000000040000085 x22: ffffc07baed7f0e0 
x21: 00000000d9200800 x20: ffffc07baeab3280 
x19: ffffc07baeaa3d80 x18: 0000000000000200 
x17: 000000000000000b x16: 0000000000007fff 
x15: 00000000ffffffff x14: 0000000000000000 
x13: 0000000000000048 x12: ffffc07baeab3280 
x11: ffff64d0ffc00294 x10: 0000000000000000 
x9 : 0000000000000000 x8 : 00000000389fd980 
x7 : ffff64d0ffbde5b8 x6 : 0000000000000000 
x5 : ffff64d0ffb99880 x4 : ffffc07baeab5710 
x3 : ffffc07baed7f0f0 x2 : 0000000000000000 
x1 : ffffc07baeab3280 x0 : 0000000040000085 
Call trace:
 do_undefinstr+0x2c8/0x2e8
 el1_undef+0x30/0x50
 el1_sync_handler+0x8c/0xc8
 el1_sync+0x70/0x100
 kasan_unpoison_task_stack+0x18/0x40
 sched_init+0x390/0x3f0
 start_kernel+0x2cc/0x540
 0x0
Code: 17ffff8a f9401bf7 17ffffc8 f9001bf7 (d4210000) 
random: get_random_bytes called from print_oops_end_marker+0x2c/0x68 with crng_init=0
---[ end trace c881f708bdfe36c8 ]---

If MTE is not available, I thought we should not end up calling the MTE
backend but it seems that kasan expects the backend to skip the
undefined instructions.

Does kasan fall back to sw_tags if hw_tags are not available or it just
disables kasan altogether?

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210305171108.GD23855%40arm.com.
