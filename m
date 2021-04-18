Return-Path: <kasan-dev+bncBC447XVYUEMRB7VP6CBQMGQE35Y5EYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 44A633634D8
	for <lists+kasan-dev@lfdr.de>; Sun, 18 Apr 2021 13:29:03 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id a14-20020a2e7f0e0000b02900b9011db00csf4971108ljd.8
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Apr 2021 04:29:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618745342; cv=pass;
        d=google.com; s=arc-20160816;
        b=lObNZFxZixiXWeoXPak8CfC7JTVurxQByq47pbboveFreRDQBNWgdnbo2w7ENgFKBv
         29Q37vzuujmMlow/RKxGGvur3KZ6vjZlB5uv0Z1I/ob/idnpbeO9VSIKQIR6mcFWwP6X
         z+Bb7Anm+t4vtdtz70wfFAjq3rUJBs2KHSvW8WW4k/H7O0NtDyODrfFqjv8BZoZbcCy1
         7nLvrRBc0pAV2AUB2u1jCSbAt2ZHjj8ss2fTlPVmK2H4k23neHY6QSkPZVFKPrBBGJM4
         5b8EQ2nUkYPqWm9zxXRR7CkHMAxvis7HkhUCDnvkxxn3IkCrZaUySStYcG5IkM181BMZ
         lZEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=SPlRCvVyRm6fXb8Y8BkDdYBtLbpww3jwCaYe/6IOJsM=;
        b=q6d9XtvS7xmVSiUndan3gjM2AOypLvkMKIGATef1bBzsZwaEDChUxXa5R8FIkRDd7d
         y91It33yyakklek4DW6oXA/MXYJ38wR3eJrFyy1mh0lka6OP8MFMnuyMTpQIOYLb1sOF
         u/6KzAXveR9YrB6BOJnbk9CUWxLaOfHvyPcgIiu1GrXckGEV77+R7aRqNE2OGLkFFQnW
         K8gD8CwDQgbSjcr1IxHlWNN6tf8K/6A1A9WzFCVIpcMX0DYT8V44Er5r5CFKldb1ZRpm
         zUU3Q4BFWtuYHfF4rLNO8vIK6POljzNOciSkgQ4o6tR2AJY9ExhwI46RXwwuDdxGPyVt
         Cm2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SPlRCvVyRm6fXb8Y8BkDdYBtLbpww3jwCaYe/6IOJsM=;
        b=Nl5Rxuh36GMMgjh4NVrbo2CFk7GVj54B1eka6a5krpDmtaVUmQLZmems6xgK76ZUD6
         9Wo4zXRsYja7lctxP2KCS3RjfE/+Rd2vcjw2shv1LrQ0oc33tj+/VVbEq+GPF+2STtwa
         sElx0zj0EExFg6ozLoVcU84nl/X48f2C8e0jFpC1K6Xz3v8DNnrkSMB1vZMdzpakq6rN
         bmQART5nJbjmh3UWaVOoVktZsOb8fOBD6GFUg6zz3ivvQ/r48ZSEvGuI+3TX7ZliP+lG
         KCmInuMG9ZNKDlnnEj0DoO6N6TXF3GCjzxbPr8f862R+eYv0nwI+iUDJeu2ogj4OxlUZ
         dwOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SPlRCvVyRm6fXb8Y8BkDdYBtLbpww3jwCaYe/6IOJsM=;
        b=GopNeU8T/6mpdNLSdb9wPNVRxFUlvT/esoi2qNvxiyXI/CxxEbwYn764gWMS8HK298
         ixKhwQmXT2RukOxDOPK8PXartpdq7Y1d7mI3XNURu9gzKAjtAIFeLP8tunFopAKkONgN
         UepZGM7BMKO8YSnGXopy2q13EVQs3WvjdIWr3wu2ccNnei5VHu92Fqe8DcVQ0j4T/hh8
         KpIsk1qQ3czZjD96RJALSspvetYdudnk+4j1WKKIu4SbKv4OdE1RU/TpOLowNQ2wtAp4
         29A676MSROXmuJHH87o+lfrYpYkbxiqXWxUsNIUREGDzg2AYwK9Lmj1GOwP+F44S+Zte
         wyFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533YDdzSjDvOvk6mLg2N4KhNe7ekejE9/vRm6QzIxlqOi98irdvP
	p8zasLI4YNCZeVjH/g+NTUQ=
X-Google-Smtp-Source: ABdhPJyEoM4YHzPOISKFvAbFkEvBE/BGwaUY5QrLpHNRCIgm9PjtRwPKF0SiRsAAjYdWU5kjifQqYA==
X-Received: by 2002:a05:6512:3194:: with SMTP id i20mr9435252lfe.266.1618745342767;
        Sun, 18 Apr 2021 04:29:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b95:: with SMTP id g21ls6278614lfv.1.gmail; Sun,
 18 Apr 2021 04:29:01 -0700 (PDT)
X-Received: by 2002:a19:6446:: with SMTP id b6mr8965574lfj.98.1618745341716;
        Sun, 18 Apr 2021 04:29:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618745341; cv=none;
        d=google.com; s=arc-20160816;
        b=gRfTOBo7mYTUR9GpYQK3OCAwCds5MWOLnIgGsZhmtMd3WvjzVHJBGIrp3KKNc8ZlEc
         vju19E+gvye2RB1otBPIl0vMkrhHfcLjTXziZiZDsKSp8cjsOMZQtkxpV4oUsqh7dcgH
         39LiDPnkl0ejC9qYU4Fsc/IbQDwcgsMpz239VOJRjipLU46c9RGtveUdl3ozN8LlTWdK
         jjvsuWVelqAqRLVan7gFtVyY0a7Tcv3/payoBUjq4zRJBhrrM7+lcTgHKoPpRKz4LIJJ
         GaVwjWkcnSlJo7vfnu7pJUMn0ozP+JCP0ltUaMJqqTFSMvWukcidwKC4Qx1TpmdGX4i3
         oPXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=9e0Dh+gsBlpwN6nZZnwDrLbnEg5H80vgwABnfJ7+VYw=;
        b=gS96Wxiu/mWv1r0de2nbvYRYUyh41ipJ9YVu4QfVlhkM9ni1NPuvlcz7I0vrmpPugp
         ORekAChXYotdV8N8V5ktRR/KPaL+qiUf2rr+ccHdoAcEBXmzquYTniuG8JGRl8x2VImC
         GerJGzO9PGpBQHqxL3HRfbBy2NRx7Cb/xtKK9+VZK+q2JqhbaLxQ0JNVo/6FNE9Ascxl
         hI6KC1Jx7SFN2kBNxGgLHBN720i6On55Du09mqskrQ0FiwE4yVNMcPD7Lz1zsS7yJn5p
         ahm9B2XodrZj/la1JOOVRSksWplxg3FmV/FdpzSDodSV0HsRPrJEFUPvOUl2UJJj/xiS
         +OEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay1-d.mail.gandi.net (relay1-d.mail.gandi.net. [217.70.183.193])
        by gmr-mx.google.com with ESMTPS id b12si367347lfv.7.2021.04.18.04.29.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 18 Apr 2021 04:29:01 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.193;
X-Originating-IP: 2.7.49.219
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay1-d.mail.gandi.net (Postfix) with ESMTPSA id 782E0240002;
	Sun, 18 Apr 2021 11:28:57 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alex@ghiti.fr>
Subject: [PATCH] riscv: Remove 32b kernel mapping from page table dump
Date: Sun, 18 Apr 2021 07:28:56 -0400
Message-Id: <20210418112856.15078-1-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.193 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

The 32b kernel mapping lies in the linear mapping, there is no point in
printing its address in page table dump, so remove this leftover that
comes from moving the kernel mapping outside the linear mapping for 64b
kernel.

Fixes: e9efb21fe352 ("riscv: Prepare ptdump for vm layout dynamic addresses")
Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
---
 arch/riscv/mm/ptdump.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/arch/riscv/mm/ptdump.c b/arch/riscv/mm/ptdump.c
index 0aba4421115c..a4ed4bdbbfde 100644
--- a/arch/riscv/mm/ptdump.c
+++ b/arch/riscv/mm/ptdump.c
@@ -76,8 +76,8 @@ enum address_markers_idx {
 	PAGE_OFFSET_NR,
 #ifdef CONFIG_64BIT
 	MODULES_MAPPING_NR,
-#endif
 	KERNEL_MAPPING_NR,
+#endif
 	END_OF_SPACE_NR
 };
 
@@ -99,8 +99,8 @@ static struct addr_marker address_markers[] = {
 	{0, "Linear mapping"},
 #ifdef CONFIG_64BIT
 	{0, "Modules mapping"},
-#endif
 	{0, "Kernel mapping (kernel, BPF)"},
+#endif
 	{-1, NULL},
 };
 
@@ -379,8 +379,8 @@ static int ptdump_init(void)
 	address_markers[PAGE_OFFSET_NR].start_address = PAGE_OFFSET;
 #ifdef CONFIG_64BIT
 	address_markers[MODULES_MAPPING_NR].start_address = MODULES_VADDR;
-#endif
 	address_markers[KERNEL_MAPPING_NR].start_address = kernel_virt_addr;
+#endif
 
 	kernel_ptd_info.base_addr = KERN_VIRT_START;
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210418112856.15078-1-alex%40ghiti.fr.
