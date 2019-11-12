Return-Path: <kasan-dev+bncBAABBM5NVHXAKGQE3EGSETY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id AF257F88DB
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Nov 2019 07:52:36 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id 49sf710441uad.20
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Nov 2019 22:52:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573541555; cv=pass;
        d=google.com; s=arc-20160816;
        b=BF85jf7AiWlqXs0Yj/ZBEuKs29zkmbCFxNRKml+79S5hruH8xNk0mrYRX6Yfkz0V/V
         0vZyRPI6fPmKYq79Pl6mnVbZr514jPocm9AhzmHd7pV3si9/M4pVyO8JCk0giLMppcua
         /BmsIi7Z4BYnNbY4uNeBtj+Twk+VrAj2IQvD8szLbrsCFR80KhATMwQNRdg+wlUOEuTz
         4Nnd4qSivNpleG98zzq8n3No5i5lj3oQS9hoJqLzPl7nEJwIArTs/lCKvtsQRzA82iDT
         8D8THDu123pb/fVrFum3Obkj8mlHUIm+UKqY0aH557jo47L+Km7vn2iVU5LUCzXCyOqy
         c+Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=3oIrF4JJ+kkNNWIfR7ufMpudk8LEIuF12gx82VlFKU4=;
        b=ZINsYcmaVF5SmNfwqLQLS7+z7SX103JrPa+Gi9Ayi+MsFmhVNQzb/bP1m7Dk95FlYC
         rzXoSmxi4xErvzGWupnyjIUWTXFksUrc5KW9GQOWFN5Oh3btaosrb7TYAcihKJRJimff
         QbjYA37dI6fc8DIb1wr8jRPoyycLKFM22Jjff+Lq2EOnCQCeab46+G7cE7gsLQmLVKqR
         cj88i/IfwQIWQ+QVGSRgTAFn5m+AwghoSOdAIRMdAsmh6MnvYFfjBe3jAwpy67ctcxKe
         iWOfmvXloVgDAFbY98nHyNjWBf2Squ1fB/AeBxrZCLugKPIr0FddN/UCv7brf9C2JUcz
         oaDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="SkP0IbH/";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3oIrF4JJ+kkNNWIfR7ufMpudk8LEIuF12gx82VlFKU4=;
        b=GC1QENbtTb2OBcbQV1ToF7TgFmTYw9/Jj2/KTbvTO/WUp4Y+Lrp7Rv+PgJ5oF+XQ7w
         2Lxb95yTpx01PCI2ljBYUNsha+0InElYe6vK4o1QivQGwXaZQ1ks+1TlieWndBcW0zx8
         GA5UcaX2vNSDFg4X1u/U6eioKU87IHtRrlsAlA36TuM55i/lXX2OAKq9b08C0WGPp5dC
         eU2makTjTkq0rl0hN76YT96iGZ/+u1wiMPEwWiwuITP9aR3DwrC8mR94LoGY8WHGostU
         3gOxNHhxb79MqY5T2dIDRR2it0dAX2faWxXCHJBew9nSZN/N5eUEBJ/JgCUPAQwxZzz6
         W7Ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3oIrF4JJ+kkNNWIfR7ufMpudk8LEIuF12gx82VlFKU4=;
        b=DvrJO4YsTevtIYAOUy5L348DY3csyZoXij5bTYqEOcDHce9Dvg+EO/Bupm4Y2Jo+am
         JnFCRQCJcIklMWhbsFyVDOIQ1dpsBq/+h63+Y8GHbvpoa4+DeBG8MWkRHwywG+cGCh+7
         NMBuIuvYNrvPdAsGM5Do9FpyiBhwhsTduC7EbSxOQJkJ0TUBAGbFI2WWn6zMKm9xflFU
         vZW9JMQth5fjqFYWVO5fia6MJ+l5fq5BTE8R2jKE+oTxaDi/4choTPqx09EpwMbk3CXB
         Tr/+Ol6wByL1FlUtQdsJiGQXLdlwFdL78V1rryK6iN2ve6Q6LMOuGlANSwfA3pXBm2Vh
         MEiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWGY2ziQdqhpGyfC5nIy0+GLQGXNSxKD+1E+Cm4y1X/FI/LUc3t
	5ow6hHXFbSB2z0r8edGngbs=
X-Google-Smtp-Source: APXvYqwAUg57ukr7d8TlyDVDk2XSfJwKgfmATVj4JARZABfIbaPr/pRiWE4C6gaw8u88C1JVGlAzsw==
X-Received: by 2002:a05:6102:2145:: with SMTP id h5mr849223vsg.144.1573541555521;
        Mon, 11 Nov 2019 22:52:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:cdc7:: with SMTP id u7ls53411vkn.13.gmail; Mon, 11 Nov
 2019 22:52:35 -0800 (PST)
X-Received: by 2002:a1f:2b0f:: with SMTP id r15mr20190384vkr.91.1573541555218;
        Mon, 11 Nov 2019 22:52:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573541555; cv=none;
        d=google.com; s=arc-20160816;
        b=GULOovu3Wn4rYODjbCVqvPdN3IH5UgwwGnZt5AUBTFthl2YK8l4giKbEbe/r9YgOAK
         i1P4kdRFXsFJX52wuDOMSK72bu3xIVnHWGNx/GbzAl+nrnJqOkGXiUF9Pjv1kmLuG/9t
         amUjED4au0cDXrPgiLrhyMlwrS9MJ8/eWeiMDtExQZvmEs8Vp4pvtb6ifLZTuBHkppLA
         /kpJ6a5t+cdovpDoSYS8TQOHHTtIlqgEDg2mLDA6YOaO72PJu0Mce/3UQ2m708H75wls
         5ZJ8dW/NNS64j29XArWob57A7szIY5B1VxftjKpm9RBzYXlY6q4Ll76tDjLQL/OpDeg0
         8cYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=wdSA5MhsOB9Ng3BYMmOZcpPo2w0m19TKE7PUEysk4/I=;
        b=AelrcHXdOPsmSOxGlXWlJPqwzXPfLdvvNuCpZBZ5dE+SD5zeej/KCIHRUV5zBQSREQ
         XVzez5cYVfC4a8EpDaA0eteEp0iIuBDdCMSwFET06p97pXfAN2Kov89IMpQzYUS3S/wJ
         Qzh7dV4Ac+w1idDb0Z0mY0J6KV8nSjCpbOrAd+vqEy/RnA7uZYegXqWyG+PNIMIX1IRG
         hUu1HRETit0vlu7/E5j44v+qXVUEGMkcJidny+j6UO1lZr+KT8UTwJe+LEUqyLlrbY3m
         yJp2M8nPh2PPIJ8ssd/sRSxAAozMn1SPnpR7louUlO3y7tRiOoqTsX/qpazImLn+rlnU
         bwaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="SkP0IbH/";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id p21si903386vsf.2.2019.11.11.22.52.34
        for <kasan-dev@googlegroups.com>;
        Mon, 11 Nov 2019 22:52:34 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 76bf00009fdb47c4a0739cb4a74a6ebf-20191112
X-UUID: 76bf00009fdb47c4a0739cb4a74a6ebf-20191112
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 139208525; Tue, 12 Nov 2019 14:52:28 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 12 Nov 2019 14:52:25 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 12 Nov 2019 14:52:26 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v4 0/2] fix the missing underflow in memory operation function
Date: Tue, 12 Nov 2019 14:52:25 +0800
Message-ID: <20191112065225.6971-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="SkP0IbH/";       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
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

The patchsets help to produce KASAN report when size is negative numbers
in memory operation function. It is helpful for programmer to solve the 
undefined behavior issue. Patch 1 based on Dmitry's review and
suggestion, patch 2 is a test in order to verify the patch 1. 

[1]https://bugzilla.kernel.org/show_bug.cgi?id=199341 
[2]https://lore.kernel.org/linux-arm-kernel/20190927034338.15813-1-walter-zh.wu@mediatek.com/ 

Walter Wu (2): 
kasan: detect negative size in memory operation function 
kasan: add test for invalid size in memmove
---
Changes in v2:
fix the indentation, thanks for the reminder Matthew.

Changes in v3:
Add a confition for memory operation function, need to
avoid the false alarm when KASAN un-initialized.

Changes in v4:
modify negative size condition
modify comments
modify the fixed code about early stages of boot
---
 include/linux/kasan.h     |  2 +-
 lib/test_kasan.c          | 18 ------------------
 mm/kasan/common.c         | 25 +++++++------------------
 mm/kasan/generic.c        |  9 ++++-----
 mm/kasan/generic_report.c | 11 -----------
 mm/kasan/kasan.h          |  2 +-
 mm/kasan/report.c         |  5 ++++-
 mm/kasan/tags.c           |  9 ++++-----
 mm/kasan/tags_report.c    | 11 -----------
 9 files changed, 21 insertions(+), 71 deletions(-)

-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191112065225.6971-1-walter-zh.wu%40mediatek.com.
