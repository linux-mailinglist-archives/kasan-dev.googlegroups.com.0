Return-Path: <kasan-dev+bncBDN6TT4BRQPRBDM23CEQMGQEX4ARERI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-f57.google.com (mail-io1-f57.google.com [209.85.166.57])
	by mail.lfdr.de (Postfix) with ESMTPS id C1711401B54
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Sep 2021 14:43:58 +0200 (CEST)
Received: by mail-io1-f57.google.com with SMTP id i26-20020a5e851a000000b005bb55343e9bsf4991228ioj.7
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Sep 2021 05:43:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1630932237; cv=pass;
        d=google.com; s=arc-20160816;
        b=eMHpgkpQ0sVF0CcbToppgbPOYQUpsH+uX6fQVBSEFPR0wrFpIVgbNFPpl0nSmHHonr
         s9eyXE4pqesU4/E/BIsWVG62WQqE5xyEvwoPXlGzCNlrbk4VhK6corkb8dTAoaiMrxLR
         dGVhGCtomSdxMBGk5yYlakXTf+V44NoC6aWpDioslW8T5lctJlOzEwi2oZ+BrS7jtopG
         37rD/oCERLCXV+D9gNHxGRiMogTU9Wo78gSf81mZPrFXuyEa/qephXD0TDQELl5LNRrT
         WL6cSf6WrBLrIU80iJm+xulKR8KrDEYDmYjMQ1bZqpP5JplNpZFpUTJeHsYgprh6MNor
         Jp9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:cms-type:date:message-id
         :in-reply-to:cc:to:from:sender:reply-to:subject:mime-version
         :dkim-filter;
        bh=aGpmLzivUALa1fl8SkAUpZ45XYZwCZywmI7t8yneryc=;
        b=mcvs4Qc/fowj4ajwXxrNcSp34vqSJkSh9gY00/A/BCLhjTT+E3ShHoyVBMH54di3Ju
         J5RnysmJOSPXi1Bq+7bWsZL/Y6qfW0rhghPOyfPsuhQN+WB/JxVoQ9C8ezipj2Kyddyy
         w7wHSL7LylenCDzrEPSt8D79zcgO5PxieRV9sguieH0p6uoGTSHOj8jupSqwengULa2j
         VnXgEgPTwBIh87qHLCxM+extL7V0XQdHmePWguwSFL+ZrAyLcy9HrgizVk0IK0eDdUtF
         1sDCnXCVJze2nP335XTC6W0Mi5+qkjGxtEUmmCWBxb4OpT22U6hmK4kBlWp62wAu9vou
         oFzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b="sgVa/UyR";
       spf=pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.33 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:dkim-filter:mime-version:subject:reply-to:sender
         :from:to:cc:in-reply-to:message-id:date:cms-type:references
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aGpmLzivUALa1fl8SkAUpZ45XYZwCZywmI7t8yneryc=;
        b=Jf4jnQYQheIdXcdTSYrfSbBAfpXBhK24XJv/itUkPFJNBQVxYKi5uEeoc1ixZiB7og
         jM0h9b7VSjcENVqu/LR9fiaUyM6W5nabbC3ssFocxhjJfXNHJZCpC1AdKYxWDNGCgIbC
         fHkWEYhXQVX5eui6vl2OpnlqJNR9c7LQmbHKmy5enKjJxvG5hIs6VM9keX5KF+sAORJ7
         5Ka9AW8L+PY2z00QBbiIMSaayHeKSN9H2g1KidaTvS6cdD/bSlDndzYPlDGpW5V7pJZe
         67i4nTeegsAxuLUiVdtUj5jcGgUrOyVqR7zjKcH6/eKn7PAjq6pgUykesVNGPdEJxuPH
         ATLg==
X-Gm-Message-State: AOAM5329q4WZhzjFrhw62Fx7HAxHE1Xjuo8jBxTQCdw8NBTLbnkVrm+K
	LECTmdvZ/RaFVL9eDESt3Lc=
X-Google-Smtp-Source: ABdhPJw5Qa8xD8mdp8B+glO1ZGD2DJC9cF9Lav8DECGH07P5grOX39bgTI9dvstOZONLMbG/qcEB7A==
X-Received: by 2002:a92:d0cc:: with SMTP id y12mr8395736ila.38.1630932237371;
        Mon, 06 Sep 2021 05:43:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d70b:: with SMTP id m11ls953539iln.1.gmail; Mon, 06 Sep
 2021 05:43:56 -0700 (PDT)
X-Received: by 2002:a05:6e02:1ca6:: with SMTP id x6mr8182449ill.86.1630932236565;
        Mon, 06 Sep 2021 05:43:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1630932236; cv=none;
        d=google.com; s=arc-20160816;
        b=w9PnlTjIu6tYMLPFwcs8A8677zFcad5kNUmAtcA7b6Fj4pFtC4mW0HJ1bMzeNpBgao
         NsdtajO4HUEzraMu6YxIXg2RPR6ryqciaAyfKg1J1oGnVLMbrYtP2UjOY/DVAPELItlA
         86jPrTwXwXKMBBhn6E6ugi5ow93Y8S2R3T2P66DBJa03/4Z/fiYo5rGelSsEVUojvOL1
         lG4L+pmG7cTpzuTMPA1SACyg1MPtaXLU6xG4rT8uwHRe6JOYBPdZWo+dxkvzaDK2Anb+
         2oJCVih+Ytbj/L897tDbUSAqYHUYI8EfeNmpt4BgjhRzA+Dnba9bTBbJnIs2smz/ZSnL
         LBMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:cms-type:content-transfer-encoding:date:message-id
         :in-reply-to:cc:to:from:sender:reply-to:subject:mime-version
         :dkim-signature:dkim-filter;
        bh=EFp0m3tslH5KjpSoT1hMcrA4KY3cyIg9bqTxXSjX/RA=;
        b=B/vf7Ml7V4azjEF1ri7hbbJpgeEdMmnXfM3VC2I1fhEl+0blJw+xbDNH+kEFRKx/98
         eSIOJfgmwyNiItn/ECH7LBTsl22SxwvZuKcJfFcS5tXegYMuAuOi8IPAWIaF4nT6o6n6
         WmhUcG37DKNxUjE4Sjw9iq1fvzC9udH8BUTNDj7h3x6hYX8IF2cw8vXPc6j5G2pzE/vk
         vW37T+DKda18lTO8D6lPcDu2AlnV/XhJK43yetGccs2GFds/f5oLh0AVt+u/rX5JPlAM
         lVRRBTe+Xahklm+tA0/k1sZixcCdIN06HfpTyEmgr5aNVRl20UhRhxGLt0GBX93eG0Ap
         ryGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b="sgVa/UyR";
       spf=pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.33 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout3.samsung.com (mailout3.samsung.com. [203.254.224.33])
        by gmr-mx.google.com with ESMTPS id y129si432621iof.3.2021.09.06.05.43.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 06 Sep 2021 05:43:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.33 as permitted sender) client-ip=203.254.224.33;
Received: from epcas5p2.samsung.com (unknown [182.195.41.40])
	by mailout3.samsung.com (KnoxPortal) with ESMTP id 20210906124353epoutp03b15726c78c944732e6589036f5326c46~iPDnDNTsJ0205802058epoutp03X
	for <kasan-dev@googlegroups.com>; Mon,  6 Sep 2021 12:43:53 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout3.samsung.com 20210906124353epoutp03b15726c78c944732e6589036f5326c46~iPDnDNTsJ0205802058epoutp03X
Received: from epsmges5p3new.samsung.com (unknown [182.195.42.75]) by
	epcas5p4.samsung.com (KnoxPortal) with ESMTP id
	20210906124352epcas5p415d157ca83aad931d48291f6992220f5~iPDl82cyn1714217142epcas5p43;
	Mon,  6 Sep 2021 12:43:52 +0000 (GMT)
X-AuditID: b6c32a4b-23bff700000095ca-5b-61360d082cab
Received: from epcas5p1.samsung.com ( [182.195.41.39]) by
	epsmges5p3new.samsung.com (Symantec Messaging Gateway) with SMTP id
	28.55.38346.80D06316; Mon,  6 Sep 2021 21:43:52 +0900 (KST)
Mime-Version: 1.0
Subject: RE: [PATCH 1/1] exception/stackdepot: add irqentry section in case
 of STACKDEPOT
Reply-To: maninder1.s@samsung.com
Sender: Maninder Singh <maninder1.s@samsung.com>
From: Maninder Singh <maninder1.s@samsung.com>
To: Maninder Singh <maninder1.s@samsung.com>, "linux@armlinux.org.uk"
	<linux@armlinux.org.uk>, "catalin.marinas@arm.com"
	<catalin.marinas@arm.com>, "will@kernel.org" <will@kernel.org>,
	"mark.rutland@arm.com" <mark.rutland@arm.com>, "joey.gouly@arm.com"
	<joey.gouly@arm.com>, "maz@kernel.org" <maz@kernel.org>, "pcc@google.com"
	<pcc@google.com>, "amit.kachhap@arm.com" <amit.kachhap@arm.com>,
	"ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>, "dvyukov@google.com"
	<dvyukov@google.com>, "akpm@linux-foundation.org"
	<akpm@linux-foundation.org>
CC: "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, Vaneet Narang <v.narang@samsung.com>, AMIT
	SAHRAWAT <a.sahrawat@samsung.com>
X-Priority: 3
X-Content-Kind-Code: NORMAL
In-Reply-To: <1629270943-9304-1-git-send-email-maninder1.s@samsung.com>
X-Drm-Type: N,general
X-Msg-Generator: Mail
X-Msg-Type: PERSONAL
X-Reply-Demand: N
Message-ID: <20210906124351epcms5p6020fbfe5f885f1e8834a72784b28d434@epcms5p6>
Date: Mon, 06 Sep 2021 18:13:51 +0530
X-CMS-MailID: 20210906124351epcms5p6020fbfe5f885f1e8834a72784b28d434
Content-Type: text/plain; charset="UTF-8"
CMS-TYPE: 105P
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFjrFKsWRmVeSWpSXmKPExsWy7bCmui4Hr1miwcGZ8hYXd6dazFm/hs1i
	yocdrBbvl/UwWkx42MZu8aW5jclixbP7TBabHl9jtbi8aw6bxaGpexktDs9vY7FYev0ik8XO
	OSdZLfrvXGezOL51C7PFoZNzGS1a7pg6CHqsmbeG0ePytYvMHjtn3WX3WLCp1GPPxJNsHptW
	dbJ5nJjxm8Vj85J6j74tqxg9Pm+SC+CK4rJJSc3JLEst0rdL4Mp4OamLvaBNuOLlNY8GxhkC
	XYycHBICJhJ35q9j7WLk4hAS2M0oMeldE1MXIwcHr4CgxN8dwiA1wgLREhvOXmMHsYUEFCUu
	zFjDCFIiLGAg8WurBkiYTUBPYtWuPSwgY0QE1rJIzH69C8xhFljIJLHswSxmiGW8EjPan7JA
	2NIS25dvZQSxOQXcJU4fW8gKEReVuLn6LTuM/f7YfEYIW0Si9d5ZqDmCEg9+7oaKy0is3twL
	tkxCoJtRYv27vVDODEaJnkfToDrMJdYvWQU2lVfAV2Ljv9lgV7AIqEpcf/GPHeQdCQEXia2T
	REHCzALyEtvfzmEGCTMLaEqs36UPEeaT6P39hAnmlx3zYGxViZabG1hh/vr88SMLxEQPiSVr
	FSBh28co8WHGKeYJjPKzEME7C8myWQjLFjAyr2KUTC0ozk1PLTYtMM5LLdcrTswtLs1L10vO
	z93ECE5uWt47GB89+KB3iJGJg/EQowQHs5IIb7SzUaIQb0piZVVqUX58UWlOavEhRmkOFiVx
	Xt1XMolCAumJJanZqakFqUUwWSYOTqkGpnnGOzm1lnjrv1e3ET18XOHtVd3XXGwVx7iMPRZu
	8U8we78/miW0a5dlzO3EebsWvbizfub01RuvrAvaeiFev3CWWiCf72xxdoXnv6afWXqs88qk
	3S/OMAhLOph2XJFedfWZn8zeZPm/app6IVIpX0okdcXNLycc+v1ValOAZqh56xoegy3PzaM/
	zloVvSVu/WG/kuUi8+r0/ZjO7/yf/v38jddBe/8n1q0XXOLjFbimI+KMiK7fX3uJdJUM9YCS
	2riZYQIXNBYdNlK3zT+f0Rf/qKzhimV8ruhs8bTdklN0AwrfyS6aNP1x0Debp5/X/gipzW5n
	V3zoFMcaypDNpdNhKf21UlUq96fbI9VaJZbijERDLeai4kQAQrbsb90DAAA=
X-CMS-RootMailID: 20210818071602epcas5p4fecf459638312c95c5d5aaa29e7e983a
References: <1629270943-9304-1-git-send-email-maninder1.s@samsung.com>
	<CGME20210818071602epcas5p4fecf459638312c95c5d5aaa29e7e983a@epcms5p6>
X-Original-Sender: maninder1.s@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b="sgVa/UyR";
       spf=pass (google.com: domain of maninder1.s@samsung.com designates
 203.254.224.33 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
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


Hi,

Any inputs on this?

>As of now if CONFIG_FUNCTION_GRAPH_TRACER is disabled some functions
>like gic_handle_irq will not be added in irqentry text section.
> 
>which leads to adding more stacks in stackdepot as frames below IRQ
>will not be filtered with filter_irq_stack() function.
> 
>checked with debug interface for satckdepot:
>https://lkml.org/lkml/2017/11/22/242
> 
>e.g. (ARM)
>stack count 23188 backtrace
> prep_new_page+0x14c/0x160
> get_page_from_freelist+0x1258/0x1350
>...
> __handle_domain_irq+0x1ac/0x4ac
> gic_handle_irq+0x44/0x80
> __irq_svc+0x5c/0x98
> __slab_alloc.constprop.0+0x84/0xac
> __kmalloc+0x31c/0x340
> sf_malloc+0x14/0x18
> 
>and for same _irq_svc there were 25000 calls which was causing
>memory pressure of 2MB more on satckdepot, which will keep increasing.
> 
>Before patch memory consumption on ARM target after 2 hours:
>Memory consumed by Stackdepot:3600 KB
> 
>After change:
>============
>Memory consumed by Stackdepot:1744 KB
> 
> prep_new_page+0x14c/0x160
> get_page_from_freelist+0x2e4/0x1350
>...
> __handle_domain_irq+0x1ac/0x4ac
> gic_handle_irq+0x44/0x80
> 
>^^^^^ no frames below this.
> 
>Signed-off-by: Maninder Singh <maninder1.s@samsung.com>
>Signed-off-by: Vaneet Narang <v.narang@samsung.com>
>---
> arch/arm/include/asm/exception.h   | 2 +-
> arch/arm64/include/asm/exception.h | 2 +-
> 2 files changed, 2 insertions(+), 2 deletions(-)
> 
>diff --git a/arch/arm/include/asm/exception.h b/arch/arm/include/asm/exception.h
>index 58e039a851af..3f4534cccc0f 100644
>--- a/arch/arm/include/asm/exception.h
>+++ b/arch/arm/include/asm/exception.h
>@@ -10,7 +10,7 @@
> 
> #include <linux/interrupt.h>
> 
>-#ifdef CONFIG_FUNCTION_GRAPH_TRACER
>+#if defined(CONFIG_FUNCTION_GRAPH_TRACER) || defined(CONFIG_STACKDEPOT)
> #define __exception_irq_entry        __irq_entry
> #else
> #define __exception_irq_entry
>diff --git a/arch/arm64/include/asm/exception.h b/arch/arm64/include/asm/exception.h
>index 339477dca551..ef2581b63405 100644
>--- a/arch/arm64/include/asm/exception.h
>+++ b/arch/arm64/include/asm/exception.h
>@@ -13,7 +13,7 @@
> 
> #include <linux/interrupt.h>
> 
>-#ifdef CONFIG_FUNCTION_GRAPH_TRACER
>+#if defined(CONFIG_FUNCTION_GRAPH_TRACER) || defined(CONFIG_STACKDEPOT)
> #define __exception_irq_entry        __irq_entry
> #else
> #define __exception_irq_entry        __kprobes
>-- 

 
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210906124351epcms5p6020fbfe5f885f1e8834a72784b28d434%40epcms5p6.
