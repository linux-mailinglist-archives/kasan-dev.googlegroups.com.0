Return-Path: <kasan-dev+bncBAABBU6PUCAAMGQEA2SLBGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 3319B2FD050
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jan 2021 13:53:41 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id w13sf18352958pgr.13
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jan 2021 04:53:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611147219; cv=pass;
        d=google.com; s=arc-20160816;
        b=nKZuVd+uRTTijX0WPsdUYIe+ReLhjL35Kon4H6HHJgEFl3t1ryUBuAKIiY6F/gNM2o
         PcemKdaNu4YWok1pe4k7qi1WMRGqPEAQ6kCb5o1CvFf4X366HBM0xNwnRjUWcSlZ8GLx
         kMO7D14ocpd59Es7q0UZdpIEjHFMTZmK9kX99esQnt1/hhPmTtjn40t6pJU7U0m9gpuW
         udPCqq9qQYjXVsHzvE+k5VTK8DnieT0MPvKoB4bgDN7ouUDAMeePSMy5Nwf8vx/IYxmd
         n3QdulUPmtS6O5ospgX8piJkHfUDVUyYPBGnK6FKiVpn6HSbkeSmYpVidKTo8OPviJmz
         42Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=Ao0QGAIJCGAoIYFWG+sUkI1/HnW5CHHLSab8EO6rjyM=;
        b=dNpesSpj7+R7YI3W2X5uAcT7rCJHjOAkZe5YuLE1Nw//Bsc6yDJvWpQTgC1DnrvJNJ
         sVdqhAArKT1ukPKZ3U/RG2myK/2XTUzw8hlkeZ0Hz/9cfyL2pBeYmCScdmPWOuyX6qsk
         U+R8FFJ/9TR1mMfnuVquGSKqboHLiNAV1Cfp388CBG1Or64MWK0aPwaFTPHlsJU9D8yK
         7rKZvqUQsW2rE+VBUhk8A6YEGSr2+p6983q31DSMJH6mMl4ssu1z34OdRNkOB2gPwXZk
         G4Fr2IQJX1MYPWQgxCRZ3c9GUewkTmv8kW5kjIRLP01Zgle8cHHrRBcmafh35VnsMk/O
         UnQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b=kXA+RBCW;
       spf=pass (google.com: domain of carver4lio@163.com designates 220.181.12.18 as permitted sender) smtp.mailfrom=carver4lio@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ao0QGAIJCGAoIYFWG+sUkI1/HnW5CHHLSab8EO6rjyM=;
        b=J9Ni/WOcqIAQRi14kQpNEsQ2JhEgom0tVRb1XyxjIjnwjawUGxZbCuT/d6oIFlcP4p
         2T+ELxrIaOFGd9uFQYZ13Z4xiOqRwC48zFW5fBwT+ahm/2rUYZ0RaM6aMY8NgIF7Fr0k
         Q7clXqjfMy9FNK4FwroPmx8mH5JegD9UP1T074hnJgsnWf1mRnjuIyPCHWPVdtPKOjs+
         R443WwZkkEolnSFanhK3Ty9H6lKxCeXoXCHkZ/3IsEDEW5FisQ2flTzd6yMxzA81hXLl
         n8RmA2v1/u/rGh38nDDdhYc8UoGVE7KyGvoAPu5/NWioCoJWqPJeK2GDmE7WFJxm+H6M
         9dSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ao0QGAIJCGAoIYFWG+sUkI1/HnW5CHHLSab8EO6rjyM=;
        b=QHgYWSIkDtjGkW2oHb/qud/GBOEHRXQ9lnRtC/1Wqdgpr2xskjme84gEJgWwncEJ9M
         ymdJIftkuGx36nRA1OJlEN+Dx9DhxjEoBRUJWLGE0FJXyI4tX2Axv4At/xP3XV2GPigy
         YLbiS5T9tUy0ow9PShmrldo6twE6LEMP3foWflE4PyDnqNrGMfe9ivBUMIOKBxZfiMlP
         zS7PNeooiQ7eM0gCRSJD6ib2dEiAN3fNnOR/FWlAqvPkcPLWcVHdy7wsOmq6WyenVK9h
         avgZTz8Tb0CeIAgZTfvKPUWDwJSJbRM5P1tYYXhYH491ayuFXSMcz/UcBvyKhrdPoqTt
         UM5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5335UPlByotSf9KXMXZYnzfhh1/RWBHvWCBnFj+ebxPDCCd3sBoQ
	tvn8Am1sRf1eeIbWPDAu9Tc=
X-Google-Smtp-Source: ABdhPJzUMGPZvkwcseahY/cbmpyYTI8gW632eyrqYN3cPdScjt/pfbp60lYyUINZPlYSgdVyL4QB7Q==
X-Received: by 2002:a17:90b:3886:: with SMTP id mu6mr5455366pjb.153.1611147219600;
        Wed, 20 Jan 2021 04:53:39 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:378a:: with SMTP id mz10ls1953428pjb.2.gmail; Wed,
 20 Jan 2021 04:53:39 -0800 (PST)
X-Received: by 2002:a17:902:834a:b029:de:343e:adb0 with SMTP id z10-20020a170902834ab02900de343eadb0mr9862962pln.28.1611147219158;
        Wed, 20 Jan 2021 04:53:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611147219; cv=none;
        d=google.com; s=arc-20160816;
        b=TbZx+VsnpJGDR5qdolR4nxkzHG4zhyAZ2qFlVGgcHJEvSML5qnqYl43DBPSq6qtNR0
         CTuNVUAFU+FY7wqclWZb7diBkBW7OCvhJT9QUgFGfxyskETYskunp7Sm2+oEwHA+NG9w
         xBMK0QklOlgq4cV47EPMsVLZf7vZ8Ewzsny0kjSzRKTVsddBRkmDXjpo/zy8vr5wMBtN
         xeHsAcClin/6x4UxyiGEsuqDGE66AxMrOJQQS3xx0myLHQ6dqIjvrR3WjuGC36aGgCw4
         t3iwaMeE/yKQcDWS9ZcoCRojRZRsnMD9+p3i3aqdg2/kgbMkErAHp4Hr13/D0A46sXjo
         ri5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=WcGGIHmekyaog93XsEBBCUmq5nOTA4s3EjGiGY44s40=;
        b=K9W7W6YET957fgwlkFEXuP5YnacOlPS3j/m+Hflzu7hgLfaDFcA2mD466UJjFsonau
         EtSJi5iOyS4BWBO/uXcVqV9ZNML6rRWUHlMzoXqp/J9R0CLDAGZ+LnIAwjvrXQevV8rA
         m4uvqf5nZPKz3YsIi4ayC0e+6OccEwHZEQXkb+mSYytmKqa1vVjoLzBgbwj5BTntylgF
         zRIVGqoqwxy7j/QnAXur+K+G9fhvCg1ThOtc7WtGxRR4e1F+rgBizAUNhUSNXPJvlLi0
         tQeS+bHb6nTJKSXSHMaXFK8s8XLdoldsLOUXVfHref4WdxRjODNBCAJrq6q/u3RkQ3vB
         IxAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b=kXA+RBCW;
       spf=pass (google.com: domain of carver4lio@163.com designates 220.181.12.18 as permitted sender) smtp.mailfrom=carver4lio@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
Received: from m12-18.163.com (m12-18.163.com. [220.181.12.18])
        by gmr-mx.google.com with ESMTPS id r142si120951pfr.0.2021.01.20.04.53.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Jan 2021 04:53:39 -0800 (PST)
Received-SPF: pass (google.com: domain of carver4lio@163.com designates 220.181.12.18 as permitted sender) client-ip=220.181.12.18;
Received: from localhost.localdomain (unknown [223.87.231.20])
	by smtp14 (Coremail) with SMTP id EsCowAAHDwNlJwhgl1Z_QA--.23708S2;
	Wed, 20 Jan 2021 20:51:50 +0800 (CST)
From: Hailong liu <carver4lio@163.com>
To: Russell King <linux@armlinux.org.uk>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Mike Rapoport <rppt@kernel.org>,
	Linus Walleij <linus.walleij@linaro.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Hailong Liu <liu.hailong6@zte.com.cn>
Subject: [RESEND PATCH v2] arm/mm/ptdump:Add address markers for KASAN regions
Date: Wed, 20 Jan 2021 20:50:10 +0800
Message-Id: <20210120125010.10896-1-carver4lio@163.com>
X-Mailer: git-send-email 2.17.1
X-CM-TRANSID: EsCowAAHDwNlJwhgl1Z_QA--.23708S2
X-Coremail-Antispam: 1Uf129KBjvJXoW7ur1kXF4fCFWxAw1DJFWkWFg_yoW8Ww4kpr
	nxAry3urWrA3W7XayjkrsrtryYkr4DZa9rZr42gw4YyFy5AFyIqF4IkaySy3y2qFWrJw4r
	uFnayryYqF4DJw7anT9S1TB71UUUUUDqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDUYxBIdaVFxhVjvjDU0xZFpf9x07jTSoXUUUUU=
X-Originating-IP: [223.87.231.20]
X-CM-SenderInfo: xfdu4v3uuox0i6rwjhhfrp/xtbCCw4gnV3Le2RxvgAAs+
X-Original-Sender: carver4lio@163.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@163.com header.s=s110527 header.b=kXA+RBCW;       spf=pass
 (google.com: domain of carver4lio@163.com designates 220.181.12.18 as
 permitted sender) smtp.mailfrom=carver4lio@163.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=163.com
Content-Type: text/plain; charset="UTF-8"
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

From: Hailong Liu <liu.hailong6@zte.com.cn>

ARM has recently supported KASAN, so I think that it's time to add KASAN
regions for PTDUMP on ARM.

I have tested this patch with QEMU + vexpress-a15. Both CONFIG_ARM_LPAE
and no CONFIG_ARM_LPAE.

The result after patching looks like this:
 ---[ Kasan shadow start ]---
 0x6ee00000-0x7af00000         193M     RW NX SHD MEM/CACHED/WBWA
 0x7b000000-0x7f000000          64M     ro NX SHD MEM/CACHED/WBWA
 ---[ Kasan shadow end ]---
 ---[ Modules ]---
 ---[ Kernel Mapping ]---
	......
 ---[ vmalloc() Area ]---
	......
 ---[ vmalloc() End ]---
 ---[ Fixmap Area ]---
 ---[ Vectors ]---
 	......
 ---[ Vectors End ]---

v2:
- fix the puzzling subject and the description due to my
carelessness.

Signed-off-by: Hailong Liu <liu.hailong6@zte.com.cn>
---
 arch/arm/mm/dump.c | 9 ++++++++-
 1 file changed, 8 insertions(+), 1 deletion(-)

diff --git a/arch/arm/mm/dump.c b/arch/arm/mm/dump.c
index c18d23a5e5f1..93ff0097f00b 100644
--- a/arch/arm/mm/dump.c
+++ b/arch/arm/mm/dump.c
@@ -19,6 +19,10 @@
 #include <asm/ptdump.h>
 
 static struct addr_marker address_markers[] = {
+#ifdef CONFIG_KASAN
+	{ KASAN_SHADOW_START,	"Kasan shadow start"},
+	{ KASAN_SHADOW_END,	"Kasan shadow end"},
+#endif
 	{ MODULES_VADDR,	"Modules" },
 	{ PAGE_OFFSET,		"Kernel Mapping" },
 	{ 0,			"vmalloc() Area" },
@@ -429,8 +433,11 @@ static void ptdump_initialize(void)
 				if (pg_level[i].bits[j].nx_bit)
 					pg_level[i].nx_bit = &pg_level[i].bits[j];
 			}
-
+#ifdef CONFIG_KASAN
+	address_markers[4].start_address = VMALLOC_START;
+#else
 	address_markers[2].start_address = VMALLOC_START;
+#endif
 }
 
 static struct ptdump_info kernel_ptdump_info = {
-- 
2.17.1


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210120125010.10896-1-carver4lio%40163.com.
