Return-Path: <kasan-dev+bncBCN7B3VUS4CRBFPV5KBAMGQEM5XHPEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E11D34705C
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 05:05:42 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id l63sf453418qtd.23
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 21:05:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616558741; cv=pass;
        d=google.com; s=arc-20160816;
        b=I9Cw0bkdc4IxNYNzNLqVxYKlDL/VZHw/svKsOZnKNYahJW9LoJrAqzWWGpuwtc8/IP
         pHxXqsPjCxWVcBlCOA0sw/Zi0Bpklc/Pfc7u9jdqgg/5mn8vE2LZXJFPWR8Sh0IUgvg3
         xIIglZXXebgz+fZYeNnzg8hv+u6YaiTmnzaS5eVbW4wxS0jDEnPnR3NSg6IPWXDVULef
         j8u2f5sf7vwj3ZyY1oZnLIZ8aGsM7jzsboJKmODVOWDz47rvgPaoT+Ei6gc70Ex9JqaN
         EMYsIxv15W0gdTAnTMlBkeuhOkBe2AdAIVsMyOsEU/e5K45/bQcBHSUVFB3n/kVU6S2z
         BOjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SoKlgneADWPyY46tGL9/Xv4L4ujHcVadK6X4NtvKfUs=;
        b=vGCbGsdqC72s8xKyvZG5CeRlJjjhOJD3WHqIcfs65aiEhvj2kUMNhQ28Nzw8el+2hY
         WYDDZ2V1O9kcrHkcg1aHH5IiNynRodfcOMaHyEI4sU0Yf7fqL+8M85HMVz3cNx9vfrXf
         9e1Q2wNQge0HzEIRrk+jQkV/ZmOA23jVHoHXyNtld/6XH2x0n3UzJelg679c0lb6FXzh
         joFgJ82h/nyRzBRSUiDkG8zzveVg/7avA3nXHy6ZjHwFEPcRXdrv4g1EmR8kHTniy2u2
         fB/SnGD0vIzR3FesJhycJP0Q2GHu0Gv2yqLwbN9Ma2xCtEg/EHplA07PRPn7aUMH/v6i
         Mbww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SoKlgneADWPyY46tGL9/Xv4L4ujHcVadK6X4NtvKfUs=;
        b=HlcV1kiOz+ME+wzqTiSHgx4Tbgy5xPE0pv+TjKSmONMh7GuPNRRMHNPsrtTPZ+I1Cg
         UyQfFKfXSInYsxTjUWDmTwooHHRTnVA0DrEgHnPLiCqWrAOggqI7p43rYc4yGy+ygYwj
         hTFr4xjstU8gufzHuo0q1AgLJyA8vBAl0lqv9q1x6JcDobnk3uwA/nV/teJe+bXvf3Vx
         p8xefviXk1hy8qOXcYcLXl2uydV8tj5Bqg0zQbaXXANaTsUTT2mY1Mg+UUjINErQll/1
         asFJZ7JC61l4natIVWaDt5Z5O/mHqxkGctuceMbyLpAmsHNiory3gFLL+fHQYMfprT18
         b4eg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SoKlgneADWPyY46tGL9/Xv4L4ujHcVadK6X4NtvKfUs=;
        b=D05kaUg0GW1eP1oTEI4tGa8hkKkgxnu55DW1vrFHiYiNTxCWqSbSRp7Hql9cBCsyii
         j+LxfRL3s9hjglTIa54CSlcPL1kTOgPsk/kLfRGxrA7udj+4Cum0M+HDkMICcVUeqYW+
         kmSki+277jN4Gg2fx7G0dpHiOKdOHi9A4YCnm2JfwBt81mfnYq/L8hyjIRSAmu6imKh2
         /qW/OkYcpZuTiQC/T4WRKQjreNN4jMdImZuNbi7cMtyb0WcXu5kWy9ajr3zjIHv4bmPu
         HG5aYRKlXHz00ra1y1Z/oyVB90TeaYi0VDHtGLLYuQ77fVegC72rscz/+r3ng+rsry8F
         TQRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533jFMILbPqQmiIrPr45ebbkayKvFxrJCX85SCUCGKNIxAKR+39W
	ac8wuoprg1gZS8RteEu4O40=
X-Google-Smtp-Source: ABdhPJxB4vI9gnFq6WS/AFOHs7aovHItjU1VygwgeaylGeWXcrWmc0Ai9gu2vHw5LIEDJQWbrDmLrA==
X-Received: by 2002:a37:2795:: with SMTP id n143mr1290934qkn.292.1616558741314;
        Tue, 23 Mar 2021 21:05:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:4455:: with SMTP id w21ls452503qkp.7.gmail; Tue, 23
 Mar 2021 21:05:40 -0700 (PDT)
X-Received: by 2002:a37:a0ca:: with SMTP id j193mr1311811qke.242.1616558740879;
        Tue, 23 Mar 2021 21:05:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616558740; cv=none;
        d=google.com; s=arc-20160816;
        b=G6c/GveHFiTKLxpi14PpIHIVRtkoOBh4zZp1OQmMx0qjGUfrufXHT9z0gXO5LMU/rC
         CQtxH+xnZ6HDUOmFXLLTSSqg5heGi3OwhfduvdjtPa/YqzEK3DUAzoC6Rg3YSqSBQMc8
         6DzRltZlaU8U+tddr58xQlXtyY5K3HhAidHYp28K0OyiDkGsPPvRyE1vvJDcyV0WX83W
         2jCse2VFaDathITrqEV+AJAueWEQVZnqVPw75nqbbH5FcYguytPDZcPtOmIwwXhq8GYx
         Qn5TZZxaq7zuKJwz0LfFkW4fTJ8JCTLB3VVD2GyLi1o/4dFvDWtrO7VYE2I34PJXRAv5
         wPpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=jSA8u/XdlzgiyDM6T56sL9revISGzQ4wwNouayQ6oF4=;
        b=giB6DGJLAV0M+50uhzCm8XoA0++YODUMwPIZxCq6iVL+3STpj/fHmmfi6XEa812osx
         u7POCl2YtBbsDXBQlXdBYNpU43lTQtoRFLnxflvof0q021DrumXwLjzQhCoqGm0AqKPu
         ZZ1npXcGjfu+FmMzO0tUV1YMje7UZAbxL4i/8Boh6sPhRTpvc/zHTpQbum6wkfOvkhaQ
         +SmGqX8F+Sttc2t2aUdEAbi/DLW0hj/S2mxC+Nwpb66Pt1nVT46GmkwZB5YXl9NtnmCP
         Gljsw1y6LMgMDfrpB6yIIKb6Wd3FgsRpyknpfBcAijTKianGS8S7x91NBb9W4WtJutdA
         lAXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id k7si64346qtu.2.2021.03.23.21.05.39
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Mar 2021 21:05:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: e34170eaa28946bdbf56de68a9d3745c-20210324
X-UUID: e34170eaa28946bdbf56de68a9d3745c-20210324
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 979377580; Wed, 24 Mar 2021 12:05:35 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 24 Mar 2021 12:05:33 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 24 Mar 2021 12:05:33 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <catalin.marinas@arm.com>, <will@kernel.org>
CC: <ryabinin.a.a@gmail.com>, <glider@google.com>, <andreyknvl@gmail.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>,
	<tyhicks@linux.microsoft.com>, <maz@kernel.org>, <rppt@kernel.org>,
	<linux@roeck-us.net>, <gustavoars@kernel.org>, <yj.chiang@mediatek.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH v4 5/5] arm64: Kconfig: select KASAN_VMALLOC if KANSAN_GENERIC is enabled
Date: Wed, 24 Mar 2021 12:05:22 +0800
Message-ID: <20210324040522.15548-6-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210324040522.15548-1-lecopzer.chen@mediatek.com>
References: <20210324040522.15548-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: A3457C077D10D4C7DD6B3D9223F0B41AFC95665282A9E44F390A034C7FB65A4C2000:8
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

Before this patch, someone who wants to use VMAP_STACK when
KASAN_GENERIC enabled must explicitly select KASAN_VMALLOC.

From Will's suggestion [1]:
  > I would _really_ like to move to VMAP stack unconditionally, and
  > that would effectively force KASAN_VMALLOC to be set if KASAN is in use

Because VMAP_STACK now depends on either HW_TAGS or KASAN_VMALLOC if
KASAN enabled, in order to make VMAP_STACK selected unconditionally,
we bind KANSAN_GENERIC and KASAN_VMALLOC together.

Note that SW_TAGS supports neither VMAP_STACK nor KASAN_VMALLOC now,
so this is the first step to make VMAP_STACK selected unconditionally.

Bind KANSAN_GENERIC and KASAN_VMALLOC together is supposed to cost more
memory at runtime, thus the alternative is using SW_TAGS KASAN instead.

[1]: https://lore.kernel.org/lkml/20210204150100.GE20815@willie-the-truck/

Suggested-by: Will Deacon <will@kernel.org>
Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 3e54fa938234..07762359d741 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -195,6 +195,7 @@ config ARM64
 	select IOMMU_DMA if IOMMU_SUPPORT
 	select IRQ_DOMAIN
 	select IRQ_FORCED_THREADING
+	select KASAN_VMALLOC if KASAN_GENERIC
 	select MODULES_USE_ELF_RELA
 	select NEED_DMA_MAP_STATE
 	select NEED_SG_DMA_LENGTH
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324040522.15548-6-lecopzer.chen%40mediatek.com.
