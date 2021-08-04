Return-Path: <kasan-dev+bncBDY7XDHKR4OBB75SVGEAMGQEEOPYNMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 203233DFDB5
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Aug 2021 11:10:24 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id b190-20020a3767c70000b02903ca0967b842sf103139qkc.9
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Aug 2021 02:10:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628068223; cv=pass;
        d=google.com; s=arc-20160816;
        b=bcWrdGU1eP5+B40zwRyjRY8Go9LIByAAp2I0XxUq0roszc8Oj3FsHGCxxXW+jgoPsB
         Evgz02KYJRYrV21EipFG369lS3AYWzdPGpLNQY/a9RFy1Io0z6b2oHk1a1QZsuazkW8H
         MHPdsvVIujHqfZfTnc0hYkZrtu41zcdRvLk1vsIDl6OzgyiMbqtDfRqCIMqzMliOieWx
         JY+dRr0bzHQBz26gvr8DDwovl/h4J3aDGP75KL2muPhKmNbc1FKtKXXWnqp3lNp2i4py
         /GLQuAtTGepmqlYMTMS5BTfhoXXmPqU2GWTc7vGjthC9IDc7Zi4h9QK178qawkqwrS7K
         9FFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=MifrnkX5ulK6seNIrIxTkkhjnbQ5XUyEHkFDyq7RqEM=;
        b=u7yfvXvpP/TlRx+23/oBKxRmq6+bZC/wiAhBDsaP9+Pzkm0f7dkAxbLbZSgve1ZRLi
         /dg6qayBGmsY2uHcDNYTQ6dSeVN173SnjiT/wYxADQ/JU9kQoi8ICbc+Fr/ih8MzQyam
         8XWvnjDML6XYs0vykQaxQQk3WthrRKPvR1Vvav+NhgjHtkVrVupSGQCC2UnF14p6Yg+i
         /ASlPnJIRqjRodIZUaJ3XElE5IphK+B+nM/UD8m7FYCeKmSFYI8e2t7blBlGv8kix8pa
         EVanPzehYyi+jeGK32Cqp3SSUl7U4faAyntETUTg0lh47JzKOOazXJ0PNi3a84pysLwu
         fzZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MifrnkX5ulK6seNIrIxTkkhjnbQ5XUyEHkFDyq7RqEM=;
        b=PnTyPU9R8/MM1ItTJbVTSj9GtfkkNJZW0bYOiByUqYD0OMcdkBenvlNbs41jlXdpPJ
         YzRtJEwpXQxNpAtxnfsitCxktS1CAUyXg3pvrFWiFH2SyIbJbv/yn8cysOIV+2uTXkVg
         Ld76tL4OrE0Wlb1UIBxeLq8YXpfCRw7Zbwm2O7s22JXCEe6fmDoeIpAWv1WQGWVWJZ0v
         K6sJkRe6HvGNXha8wZdslGVQ5bXdeH6xg2PAvE0GAkqo/3UT4m8p5iyOrU5+Bj+1b3k5
         PgV99xU6LTHnOTenW3opEolecsExaUJRORpIQNimHyttlDam1deyxDcHJ5biX8pHbztt
         GUJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MifrnkX5ulK6seNIrIxTkkhjnbQ5XUyEHkFDyq7RqEM=;
        b=uCVptx4whYdUnoaecFLq4xVhdxhRC2k/SiPE6e1EJdw8gRAdUTChnIV9mJpta34lpz
         uwxyXdccRucvFQoKdpXRDnHlKkep8ZEbhiNWZ5ai4vxeCA8kc9wGCDmjz5j1zIWPunU0
         CmcQpRHgtuZ6r5PxS3teEP+VY90MVj7xH56k0qnFSGy89+QEEBnvfE+XyYhHJkprW/Ep
         nylnz2MZfxZxj8AWsrIRW9ZXcKIMPRtTboxfS6YjmYWkdSDS6QGn1uVj6H7Qwz/ILyiK
         JoV5XgrptSPQZ7fo68rih+Vil16Tm2b3kqA/lJdpK1pHEft5ESUZ/KKLduj5/08i3SO2
         gwEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531B0eJgfNv0LXZK799P7P9aNCF7vmGpFh+Vi11o8uqq8g1q+Dem
	GJBRhfSQg9qCOmzzyzFEAx0=
X-Google-Smtp-Source: ABdhPJwr/lMw0kkoAmptBBiiw+hcgh7VmXGmOf1qPInSUfsq10NfyDHEaXdGxzxsW3BjmMYMVsMdQw==
X-Received: by 2002:a05:622a:16:: with SMTP id x22mr22264372qtw.140.1628068223205;
        Wed, 04 Aug 2021 02:10:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:240d:: with SMTP id d13ls1119418qkn.1.gmail; Wed,
 04 Aug 2021 02:10:22 -0700 (PDT)
X-Received: by 2002:a37:9cf:: with SMTP id 198mr25083218qkj.60.1628068222788;
        Wed, 04 Aug 2021 02:10:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628068222; cv=none;
        d=google.com; s=arc-20160816;
        b=mGG0923wXrvLDxDWwLVzT/i+IqY2GCtFTsLP9ZeopLuRr0ONKLeSZtxqoROH3wJ8Xo
         UqpMWhpkUErp0XNGCE6XseOCQVQFjrvyLY6arkAon90+/Yp7exhItedlZI/SaI4JANtb
         mwqcUP5rnMNMnsEK0vd5oEmwoPlsydq+ZvlEYXXLPei7z6t3tR1Iu3dJ/O0RBFRBewdb
         OZ6zyGhVxcn6tTt0sKAb0L+JkaGV9Ui926WvE3AwNqynZ79mJBP+5o8vrlnGdidB3MSk
         a77wgXM8H/mUGL7MTZl7l8lnkDQ/FZGeP+WLwgFSF7BqpGV1Y9Gu31VY+2KU0Wvzuart
         cdWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=5dKoKDhhjhDSGyfHWIa+WMFbSRbE1O37zbFp8C9LpeQ=;
        b=DZx09SOAFgnhhIO3r25xKvJht83iMeqhuQ8FbOal8Zirz/kb5k7b0O38btqoLFycY3
         BjqbIVTSMOS6OWYlo40Ed8c4p4A9oSiqmlgKGxSdtCYIW7jP9JWOawagP0i5vOFPvtZU
         z8fYjQxUIHd+Q8FEgDLDXBDFIJaLKKp4RSRPeGI67Hgfpdfk+RZ/48EjFhhBGbccad0t
         WEKwLAKIJzJ91KSot7OxACFlLkH+fwy5hBEtIvgDtOw4peLsYgPKwgWFHxSN0aHYZPSt
         /DbWIZMc8Kwj/CUOAt9p870YFk8kbFeM8LyMiZAdrsGVU15XHso/20RvheGAjbx4ohAr
         0VZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id v31si61988qtc.4.2021.08.04.02.10.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Aug 2021 02:10:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 37b1258cb2234a309df1b9ba8a8e64aa-20210804
X-UUID: 37b1258cb2234a309df1b9ba8a8e64aa-20210804
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 21374007; Wed, 04 Aug 2021 17:10:17 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs02n2.mediatek.inc (172.21.101.101) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 4 Aug 2021 17:10:15 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 4 Aug 2021 17:10:15 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang
	<andrew.yang@mediatek.com>, Andrey Konovalov <andreyknvl@gmail.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>,
	Chinwen Chang <chinwen.chang@mediatek.com>, Andrew Morton
	<akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v3 0/2] kasan: reset tag when accessing invalid metadata
Date: Wed, 4 Aug 2021 17:09:55 +0800
Message-ID: <20210804090957.12393-1-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
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

With hardware tag-based kasan enabled, we reset the tag
when we access metadata to avoid from false alarm.

Changes since v3:
 - Remove inappropriate suggested-by

Changes since v2:
 - Refine the commit message in detail.
 - Thanks Andrey's explanation about false alarm
   of kmemleak.

Kuan-Ying Lee (2):
  kasan, kmemleak: reset tags when scanning block
  kasan, slub: reset tag when printing address

 mm/kmemleak.c | 6 +++---
 mm/slub.c     | 4 ++--
 2 files changed, 5 insertions(+), 5 deletions(-)

-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210804090957.12393-1-Kuan-Ying.Lee%40mediatek.com.
