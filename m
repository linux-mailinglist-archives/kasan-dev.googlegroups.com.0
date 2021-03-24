Return-Path: <kasan-dev+bncBCN7B3VUS4CRBDXV5KBAMGQERPM3BTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id E93DB347057
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 05:05:35 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id x8sf867644ybo.6
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 21:05:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616558735; cv=pass;
        d=google.com; s=arc-20160816;
        b=IUasAbuA7v54fKen7XIH5F+C06FE/OyZ6h4ZP3qYqnNqKk51mU6wVr3jozy91pW4ZV
         8Fq+EjCoAfvGDyylOxr3pUEcW6quG89h0BpO+ZJ4DeJ+D4rckBRKXwMTGN6kUeUZifdd
         i2ayXa60PSqjx5yXZdDphTbY8jYpNpgkSxpuHUEN3vNXoWRmNGkIkQWPnyqeDG1uQXhS
         LE80AZ8sdqU7ThT+bmxYUeaLddlCegdj5aIQsCKJI6IBJM2FRfp1Sok/uI35zFJ0hUtq
         ValQky8k/I1zKJzG/Iq6PwGx6qbUWifzOYR8XCPnJoudA/3DIm5O5asR6WR2D4OXbDvr
         uRJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=RP9BvO9nplQapGOA+cmMuq5hvCcBuBN7s9dsaIieZcY=;
        b=Kl5Fe0TyKzsJ0mNoNkiBOYRCAdNVqY8ZmfXPYaWs0dE99viQZ4ykfvYp0HuFjKkyWF
         eiOUzy7ONJOx/Pq0Xbjz0rwIokUc33LWj1pR+ODBPIiK/jr1phjdQisEQ2MUH847GpHp
         aySl3qIIPf/8IQhQxYBS96ppeI+VUszL6tVMo7CmQxUO41D5hdUnH4yHbQK4tvCHMRmD
         8aOyYrsoJlJr0rcDXfCtcM9Fv0Or7dxFiYsvsMm5FSxetHxFP2yeIhAUNF5uteQd0i2z
         itnkC7TlJsEfsjLPormycekGZ0WkxAvFJdB64XoXzJLoGQGSDyvKhKddx877AooldeOc
         e58Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RP9BvO9nplQapGOA+cmMuq5hvCcBuBN7s9dsaIieZcY=;
        b=FARCGlaSgFOBvlvyIU+6iJpymJX63boVFSNrY8udLWi7B1A+spjJ4yakaGYBg3Esqp
         BlGBQLMpgtptzE1qxjYOX2Cy818jp8ckhgpwZTeEmSCrcjUx0Ow57mHJZddwrwgWwgly
         QeeNugFlU9QoMytkIp3r77u7RbSrHIIAAwVtLOGrd+bX1DZXUq1rFigIZyQvIB5liNAU
         0fetYWF/AVs8geF6eQ/UI+t2QzXxcILkv+agTn7XAERE+pENEtUi2ss7ISBJD1B9pghH
         /W/WFDd0huyZje6yG4VKMreMf+JvmcVmDTQ0F1/bFI2zPDIe7VL90jAMRMW9i7Vii0OE
         WdaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RP9BvO9nplQapGOA+cmMuq5hvCcBuBN7s9dsaIieZcY=;
        b=ulq9LU7MoKqESlAoyX8/18H5+hmupN8c/gVzVVLHd1T0mnuYfjuwfNGpebUSEWLmGa
         nQ1RdkHonCt+Kz51sc9ucHP3F/xUGLnAB1Jw65GmF4daU3+wMLJ6FFiDcY7HivqKVuRN
         dwCxFJU5YcrmQFhiIh5jM1jphSFk7unLdhZO4PwbpC8dZm6diKW9eiTFuTYqVFowhzkK
         KsDb1GHjJOlpuKmERtJavlg/shKYjc1SHeVoHhcC3Hf17GrIGDjao0Cwj90fzB+pj0aW
         GHcEq7EKSGWhT8voVXtH0e+aoywOQlmfmMEzAU4x1cdHluc2/2yjKrCPD6MX3qrIm0G6
         EmKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532G7yKOj43StIPkx4KAi0TpDXu2GTJTrbYIB711qZwUsUHOzkRq
	X1GBLvirFff+3BtxY/l45MY=
X-Google-Smtp-Source: ABdhPJwqNapU8Bb6672iJOg2nzfZk1Ij0d1KQIUuYLEHdPBvQgE/nHNOdZcqOKGp3m5QA+CWY6DNZQ==
X-Received: by 2002:a25:8b86:: with SMTP id j6mr1871503ybl.470.1616558735006;
        Tue, 23 Mar 2021 21:05:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d306:: with SMTP id e6ls412231ybf.11.gmail; Tue, 23 Mar
 2021 21:05:34 -0700 (PDT)
X-Received: by 2002:a25:bd45:: with SMTP id p5mr2171413ybm.355.1616558734469;
        Tue, 23 Mar 2021 21:05:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616558734; cv=none;
        d=google.com; s=arc-20160816;
        b=mSAkf9WRVJm5YXWj2ajuUrz81JaAs8T6uV4MxWsmazppNUpif4XtpsURtAsSxHyxDK
         oUxSxMxYvvUuzBLgPdPvj/emCqIXRtxyDTlFytpQ/mF82aKsT9EjUUAauAm42ZlFma0l
         OXaIp+P/jo8h403EqJsGpjOe5zpPFzkm5njjvN/RoMtqPzH62DtLkJUqviMBRgVBj4KP
         dw6liwvbM1pohpbh1j12scfFjI+hHVF9Flqb3uShh1p/SRNl/yBRN+glI6bKUSKKM6DC
         ZuAX6d9Ixh8W2hN8nzrII4kI93AisdZGgYFOPy2rHYKfBzkMZJOTUwazUUHog0RBb6vU
         B1LQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=FtFy96pgpKwPlrdtcvvbb6bhjCfesSe/pP0XW88Guzc=;
        b=M5bNv+Kexjpq8NeSzLTs2tknfvTWCXNn+XIUvgKKwmGdixJD7xedc5vOQAfj2PpljQ
         Eh5avv2Q8/NwMVNQfjVahSQzU93df2g41UB/T8XPBOxFDssb5zYh7SmMHWhy2dJK35YK
         rC2ah7HJmXcXuUR/M82Bsp8nvZXr0eRIKUTr5z07bcJLRw9CsbbXdUcQltUtr2dpfLBT
         bkJ7OJet6W8aRQSsrm//A9LQpv5rLi1Gl4FdkE1FVxTit43oNU8s76Ms2KJMlJvnId0p
         N/nN6uTHXwmN1lQJUKaVT/l4PbOMEvpD7agKKZ+rNEEft4mLMSAgN8WysaCRWPsxi3Sp
         +K4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id t17si76599ybl.2.2021.03.23.21.05.33
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Mar 2021 21:05:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: eb711cfae5c642b1902f3ad106b7ca61-20210324
X-UUID: eb711cfae5c642b1902f3ad106b7ca61-20210324
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1831448406; Wed, 24 Mar 2021 12:05:28 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs05n1.mediatek.inc (172.21.101.15) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 24 Mar 2021 12:05:27 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 24 Mar 2021 12:05:27 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <catalin.marinas@arm.com>, <will@kernel.org>
CC: <ryabinin.a.a@gmail.com>, <glider@google.com>, <andreyknvl@gmail.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>,
	<tyhicks@linux.microsoft.com>, <maz@kernel.org>, <rppt@kernel.org>,
	<linux@roeck-us.net>, <gustavoars@kernel.org>, <yj.chiang@mediatek.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH v4 0/5] arm64: kasan: support CONFIG_KASAN_VMALLOC
Date: Wed, 24 Mar 2021 12:05:17 +0800
Message-ID: <20210324040522.15548-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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


Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
("kasan: support backing vmalloc space with real shadow memory")

Acroding to how x86 ported it [1], they early allocated p4d and pgd,
but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
by not to populate the vmalloc area except for kimg address.

  -----------  vmalloc_shadow_start
 |           |
 |           | 
 |           | <= non-mapping
 |           |
 |           |
 |-----------|
 |///////////|<- kimage shadow with page table mapping.
 |-----------|
 |           |
 |           | <= non-mapping
 |           |
 ------------- vmalloc_shadow_end
 |00000000000|
 |00000000000| <= Zero shadow
 |00000000000|
 ------------- KASAN_SHADOW_END


Test environment:
    4G and 8G Qemu virt, 
    39-bit VA + 4k PAGE_SIZE with 3-level page table,
    test by lib/test_kasan.ko and lib/test_kasan_module.ko

It works with Kaslr and CONFIG_RANDOMIZE_MODULE_REGION_FULL
and randomize module region inside vmalloc area.

Also work on VMAP_STACK, thanks Ard for testing it.


[1]: commit 0609ae011deb41c ("x86/kasan: support KASAN_VMALLOC")


---
Thanks Will Deacon, Ard Biesheuvel and Andrey Konovalov
for reviewing and suggestion.

v4:
	1. rebase on 5.12-rc4
	2. tweak commit message

v3:
rebase on 5.11-rc6
	1. remove always true condition in kasan_init() and remove unsed
	   vmalloc_shadow_start.
	2. select KASAN_VMALLOC if KANSAN_GENERIC is enabled
	   for VMAP_STACK.
	3. tweak commit message

v2:
	1. kasan_init.c tweak indent
	2. change Kconfig depends only on HAVE_ARCH_KASAN
	3. support randomized module region.



v3:
https://lore.kernel.org/lkml/20210206083552.24394-1-lecopzer.chen@mediatek.com/
v2:
https://lkml.org/lkml/2021/1/9/49
v1:
https://lore.kernel.org/lkml/20210103171137.153834-1-lecopzer@gmail.com/
---
Lecopzer Chen (5):
  arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
  arm64: kasan: abstract _text and _end to KERNEL_START/END
  arm64: Kconfig: support CONFIG_KASAN_VMALLOC
  arm64: kaslr: support randomized module area with KASAN_VMALLOC
  arm64: Kconfig: select KASAN_VMALLOC if KANSAN_GENERIC is enabled

 arch/arm64/Kconfig         |  2 ++
 arch/arm64/kernel/kaslr.c  | 18 ++++++++++--------
 arch/arm64/kernel/module.c | 16 +++++++++-------
 arch/arm64/mm/kasan_init.c | 24 ++++++++++++++++--------
 4 files changed, 37 insertions(+), 23 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324040522.15548-1-lecopzer.chen%40mediatek.com.
