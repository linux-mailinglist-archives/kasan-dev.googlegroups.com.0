Return-Path: <kasan-dev+bncBAABBWNKUOHQMGQEYME4PLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E6BAD494610
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jan 2022 04:22:02 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id jn6-20020ad45de6000000b004146a2f1f97sf4858076qvb.19
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jan 2022 19:22:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642648922; cv=pass;
        d=google.com; s=arc-20160816;
        b=kmNMPyJZZVvs6K0YeKm/AzjI5abTwUynTXdd3fRr3wyRZfXy0wo0O+3Lj6iMXzt/OP
         rCbxH6CTcjpTOhcepW/qbNAyfy8I+h0oKAIjPrxXXD1iOfrKqFeIRyPTqmlCYryR2HlO
         AC8wpzlzwrID+m5LD0KcM9eDbdIaK5nU8r8/KsYNSPs7Y87K1S/0CQyxyBQOGDCgFjfK
         j6eFMMKmGEZSpWS4f69b1waxY9RHEWXixgsLWvPrZNEYXDRGxJAM13DDOIQe7KgPuCOa
         K/yN7EYW8OUIDFmGfukoT0XF+Z8N1eyOoCHKwV/L4S+9W3ouTszI5dLzQ8zhBBDP3nv8
         TrIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :references:message-id:date:subject:cc:to:from:dkim-signature;
        bh=DNCgSQcZni6n+gE185FXkQF4wbxilr1Z6Jc3Qf/WQVM=;
        b=Ok+kMzhrT3XbiMTYdiJDeyIGiC8GhKqafWsrjfwvRSfiTX8FQZrjmTDT4jhZcwyffF
         93MtvVaytg8kHc2UZCqIsdrsBgZ9xbeIB68oiDftgAnoJi1q1QhtAIU3729GmmLB18V+
         Obc/D1/e3/abq7CTe3ZR4wIyUJcRKs1W1f/6/cZRrtmtaj7MmWHjodWYHBB15md3N/vJ
         BZ3y/n7TFOHhtBWq4qmoSI0Da48bBpTUq1AlVJmV5JimRk6yg4Bk0B9oyqJqegSAdiUO
         uPMK6AeWk16Vr5v2PQXOC1uIaCjjqw/MnKtFP/K4F9HXcnPywpox5eiXh0AQnef0oNwx
         ly/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of chenjingwen6@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=chenjingwen6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:references:in-reply-to
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DNCgSQcZni6n+gE185FXkQF4wbxilr1Z6Jc3Qf/WQVM=;
        b=VnNvETUkw1Q44KefGb6RMidNONRd+nhNLOjnEuREELlY2quwPh6shCQY4W9Bw+FUSG
         kr/de63th5UP1nZxf2W37XVK996ijOVhy/ZKUaPYmCZgEXu4G75n2iyjx2DXL1qw/jrG
         dEGDZCP1Q83Rq45UVDNnJR/4IbIDlUAGnAwqrUPgkB73nQW0cou6nr2Rr66WT8dQZGrY
         bvSKqQWTvsm1bbbk8G3EWnE+aR2bCpuaaD1lMuCJBTy88Qa4jRyRaJBaDDclSsmqntfO
         tjnbllUoXk2jCWquJJvRk0H9KbrTwVbwyu3roRRGB6FF+fzknx6P2dtwiklNIkJ9WJN+
         RQHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:references
         :in-reply-to:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DNCgSQcZni6n+gE185FXkQF4wbxilr1Z6Jc3Qf/WQVM=;
        b=hLAw6SUtXU5NNoWJsrTXh6SJVlXD2b6ON3aqMpGzqNL2IKGwckT81hsmzbClwxtoer
         Mhlx//je7cW4RMQr1l8BGZt2iuMTm1iZEY8axdXpHxoa6jbt1b1EkHDetrQdjGLjQwQn
         hCTkHpC8c6eniETZK9bCsIoFdNTl2vKxyVkHbNTQiyz1qclyX88nyFFZx3fncH62arew
         HlRtOz9zKDiNghmnf/Uv9NoxREMl6hPKuC6Q6KqDUi3Jb/YKJmVw0HH4Rcw/iKrCyvdN
         ak7zaJr00sHnb3Yo9Qdg6BZa4o03G8YJrxZn0i1VetUPEa283riglI+Y1Ui3c9QHeZxl
         32wA==
X-Gm-Message-State: AOAM533ZiTrlnrIRq0iT1Z9bACB8752xUZObYYsGCSScMj6S6FdUJ2Pz
	hDPx9qGLAhnN6ShmgqBz0hg=
X-Google-Smtp-Source: ABdhPJww+bJsQ3fM1Vt9ocAHctaD+zYBKd0/wpPEqOz1aSvjx3qEByK0wH4mGlFIpiHDeINNwqcsXA==
X-Received: by 2002:a05:6214:27c9:: with SMTP id ge9mr2130362qvb.111.1642648921989;
        Wed, 19 Jan 2022 19:22:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:75c6:: with SMTP id z6ls2199028qtq.10.gmail; Wed, 19 Jan
 2022 19:22:01 -0800 (PST)
X-Received: by 2002:ac8:7202:: with SMTP id a2mr22965980qtp.268.1642648921535;
        Wed, 19 Jan 2022 19:22:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642648921; cv=none;
        d=google.com; s=arc-20160816;
        b=LKPeOCo2V+m0HuYbrmT5BWxmV611CpgvX/KA52Z8nzPCgdAYBTYc5MTxiyfdpGwfx6
         kWqzuT6JBcOizA7IEaXiTxUXRPyDcv2MNoMiCSaGpzZfh2VDVXwbxmmz+sXPo9SnIEB3
         V1ylHsXZkskJRtEXCNmPz18MsEGHa5VHuxfbCBGGT8tnMdeZLAHfKwJ6PMG6TCUeOTSY
         UWpI5w9PFoqHjB0b70bTG3WqOQucRLarQvzPPJQiERYFsGyQApDlY2pOXOsoTMMY4VyE
         8ozhHzu7JtQlfKEIVQaTjpgyUT5zQAGeGxDT8jilwEqFtVv/DmKbfyiZYFzbZjqms58l
         NFXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:in-reply-to:references:message-id:date:subject:cc:to
         :from;
        bh=TZBTicc1x1PAGfueQcjFZhQGV49zGpdbNLJLJB1CVjA=;
        b=fROnEa4E+FbyM4twtJb+nMWEHiSxqRFTL2WSROEuRC+zf1GQytsuNNhNw0XIFFVQUH
         pVALB400I++A5IYerlHh1q3w/LD+aUnGPUSjwkhSMUL9g60Gg9NJfnGUodsJDCXzRYKs
         hEHMS75Z1uu2IBpCrlU+vguqRaM3cRTksx7qwiYXyqR/BIHPHm/FcD4G+PZraYWWyUgC
         40GcdmhF5XSSYdeP6l1FPlTTfyYnFNdMXEgAGmkOkAwHGd6hx+tJEhY+TicOYhkhlqSX
         n+tFWkdfipNhwAHd5EumAdQLua2K6lXFAY3stWukJv4x5bWJz3JQIJOJ3QRrL+4lGWA9
         aQrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of chenjingwen6@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=chenjingwen6@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id w22si74887qtk.1.2022.01.19.19.22.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jan 2022 19:22:01 -0800 (PST)
Received-SPF: pass (google.com: domain of chenjingwen6@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggpeml500024.china.huawei.com (unknown [172.30.72.55])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4JfSTP23HczccbR;
	Thu, 20 Jan 2022 11:21:13 +0800 (CST)
Received: from dggpeml500017.china.huawei.com (7.185.36.243) by
 dggpeml500024.china.huawei.com (7.185.36.10) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Thu, 20 Jan 2022 11:21:58 +0800
Received: from linux-suspe12sp5.huawei.com (10.67.133.83) by
 dggpeml500017.china.huawei.com (7.185.36.243) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Thu, 20 Jan 2022 11:21:57 +0800
From: "'ChenJingwen' via kasan-dev" <kasan-dev@googlegroups.com>
To: <chenjingwen6@huawei.com>
CC: <benh@kernel.crashing.org>, <christophe.leroy@c-s.fr>,
	<kasan-dev@googlegroups.com>, <linuxppc-dev@lists.ozlabs.org>,
	<mpe@ellerman.id.au>, <paulus@samba.org>
Subject: Re: [PATCH] powerpc/kasan: Fix early region not updated correctly
Date: Thu, 20 Jan 2022 11:21:57 +0800
Message-ID: <20220120032157.31174-1-chenjingwen6@huawei.com>
X-Mailer: git-send-email 2.12.3
References: <20211229035226.59159-1-chenjingwen6@huawei.com>
In-Reply-To: 20211229035226.59159-1-chenjingwen6@huawei.com
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.133.83]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 dggpeml500017.china.huawei.com (7.185.36.243)
X-CFilter-Loop: Reflected
X-Original-Sender: chenjingwen6@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of chenjingwen6@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=chenjingwen6@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: ChenJingwen <chenjingwen6@huawei.com>
Reply-To: ChenJingwen <chenjingwen6@huawei.com>
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

From: Chen Jingwen <chenjingwen6@huawei.com>

Hi, It can be reproduced with the following kernel configs.
make corenet32_smp_defconfig

CONFIG_PPC_QEMU_E500=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_OUTLINE=y
# CONFIG_KASAN_INLINE is not set
CONFIG_KASAN_STACK=y
CONFIG_KASAN_VMALLOC=y

And boot the kernel with the rootfs created by buildroot-2021.08.1
qemu-system-ppc -M ppce500 -cpu e500mc -m 256 -kernel /code/linux/vmlinux \
-drive file=output/images/rootfs.ext2,if=virtio,format=raw \
-append "console=ttyS0 rootwait root=/dev/vda" -serial mon:stdio -nographic

Could you help review this patch?
I will add the necessary info if any is needed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220120032157.31174-1-chenjingwen6%40huawei.com.
