Return-Path: <kasan-dev+bncBDGPTM5BQUDRBNPOYP4QKGQEDM5PHQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 83192240281
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 09:28:54 +0200 (CEST)
Received: by mail-vs1-xe3d.google.com with SMTP id f17sf1973956vsq.17
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 00:28:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597044533; cv=pass;
        d=google.com; s=arc-20160816;
        b=vX7QUM6DIa/5U133hRZ2ALJUQwFIioUUKQ7y60aGznff/4kBleFu4ii1eeD+Pa3C0p
         qW+fmzn/OXjGH8s55ip5518AqmKypizf3Z3B8In+b3UzEkJyR42ejQjoLd+NAJFdcDMK
         jYjnQ47VfZ9P3Vu4qiZww063dpJiu8ZBWZEoJcDjLGbJAwbFLUmqJV6FRmBFZPW1MW7i
         Q2YOfj+bsmtg1GlEupjPK1Oo9ClnIHEQYUXBGW09ADKv3zycUpwrNRRYW+hXJiXsRlF0
         mAwB6FMM8MhdRwziY8o5qHVCaXAXX8U5yNcSYTiJ7u/QknOidVhuDgKFxtkkvTsaddfM
         PxYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=AOA0q04sNHh5ip3sq9mRWrxoULQmn4+A0QdEE4k3Scs=;
        b=plv+PdQKwepVyajsXP71/REXf/KL9imgM2tOgiB5ES27WbNfOyqjQTKS503HQt9sXV
         J16Zkczl6yCo/ckC0ACyFWoDO/QqdnOymS8u2M2zDZsNje9XFQVmyEWIi/L9E6mT5nT8
         Yfwpi2rd87E6oqM7AWK0kBL17odo75Y47vDno10Apc4/1jDzsuU/v/9lxfRClicYprIn
         qLvw+41tiL452+Wrhg9HIbWl4fF1eRatUM7CKNOQOS0iLUlwE4L5Z+LkO0XeEaeSYYEE
         oD4Jif1H4Bq6pweE0GsQ/ooRDAlf9UTB5ibGxDDGGtcKB+BzKxrtHbe5+hxhCUbdytWJ
         jFeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=qLCWArRY;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AOA0q04sNHh5ip3sq9mRWrxoULQmn4+A0QdEE4k3Scs=;
        b=G02d3v/xeUDKgKspTQS51O5ePlf/Y4vA99uvmYpR0m4A29WaGs5UlmpU1fvsltX5Ma
         i+V+OjYVT2deRepX+RCTdiTWYYQflAfiSagrlaau2X2OpUR8phh/urgIMJvNBbtvUWez
         o5cctEs32fXTSv5sR7vcOGY2tbIdz5+1oY2J/G5gW4tjXE35zhLTSk9m/PyXVR2wi+ZT
         glgFQpyNRwCn94JMjwqkI79xag7aeqIgXjTuOADJc5BjJbvRwvY6dPIxlGfQUxWE8hAX
         QLv3pmmiFLYXI8tBM8JW4WcQ53uvfbWNlojiFmTdLNrMC/w7a4dG3ISqR6L5Xl4Ilc3P
         rpeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AOA0q04sNHh5ip3sq9mRWrxoULQmn4+A0QdEE4k3Scs=;
        b=gvjBswY0sHXWeNxSUsq/AalWtfZYeCP2QDLwbTRx9OYykaKNAl/dKNvCrD74BatjjO
         yx4Nesth7wuLWCMyTQpGYVwysKs3wr24bh0UnE91tiKnI2ep+ssU0BmoY6BZxWFwkCz5
         XzAXuQrtm144NiWuL1ixuXFYke+mg5pbVpaHA3hRYQOG60RnFf6aDRQZSl67XwTs1dt/
         S9Wt7ECn62ztjHhrwWmZnpKLx2P6YA0yzkoMkWWfyP4VhGWsp9bn+htaxUy67EAlkOev
         2REvJedvX5of8hiE4I8BVEDyhhkoINJmL20sSquj2TMkxBNtw0IYXsj6rEfxhU7+iHlM
         nHDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532/rJ6pvwF0yRxWqGntvAYZxrE/azcGMd44/49o9CD59FiR18mT
	Y+4glVH7cRrYpvt46KlpDKE=
X-Google-Smtp-Source: ABdhPJxNgtCzsMe3AdYpkzrKToO+ZdSfpuwRavew4TPH6a3Eee4WQZBF0/G+dIFip3d0EgKUCXZOPw==
X-Received: by 2002:ac5:c8a7:: with SMTP id o7mr19285675vkl.29.1597044533576;
        Mon, 10 Aug 2020 00:28:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3cc:: with SMTP id n12ls1388272vsq.8.gmail; Mon, 10
 Aug 2020 00:28:53 -0700 (PDT)
X-Received: by 2002:a05:6102:51b:: with SMTP id l27mr9925146vsa.149.1597044533271;
        Mon, 10 Aug 2020 00:28:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597044533; cv=none;
        d=google.com; s=arc-20160816;
        b=u3iylwAF8Aa/iijXVrFJPHD4y/g9vMk1BgraNHvWPtFtsEPl9vHbFSfxyKk5K1ip7W
         El63JdMIanMNT++OxHjBRUQOFTwApeDxQTrdze8KXGWKrx306HW//4DGPpcY4x5Uxgkc
         Ut0ZBZJie57/ceqNZP4TWaSceQvINe7hloIhsO1hNm4jYSMibp1AoGPrU0rJzjAJVvMs
         OMPWRiJ2SLEVOuT9NOusd5VMZjM/ByHH/Oeqs2EjKfrPSQLzBCZVf+WHCaG1CXpjdsy3
         Q1hd8SfNadnoYCsBvhptGtkQ9EQPn0zYVYns2VS/yv2efz41Yfc79wj5RTQqY4zymkID
         Q+ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=fNYSYPr/EUtrb5AE0HZcFt+MO/QDfADl7kGfo3uCntY=;
        b=TO+tKssZbCCRgg9cK8B4B9q/HG8PmtIuND4YpfUpDrBqpe0rRg1FqD8kGeY4BMGzLz
         OHhDh8guZnk0sswEbx6nTubn61XLrHzlBzHneEaqvf3gER+NqCXZscNM+ljpZ9QSMZQN
         IEDmCJONy18qK/gYif2fX2zoOQhC9GBKencI5s7aC6Bu9gUn1O6dRzmQUoV3C3EBRqUk
         qR6DpBCFXzr6wqQ2h4dD9MENOimTFdZsqkbaL7uA6sHGioSYvE+2r0z9sH1TStocz31x
         aAGZBDUQl3q8xLXMaWIkBB0mnX8nNcnT/GCSDcU5ZVa7DNhiyJkGivP5IJv/CxvRj102
         Fa7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=qLCWArRY;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id u18si1058302vsq.0.2020.08.10.00.28.52
        for <kasan-dev@googlegroups.com>;
        Mon, 10 Aug 2020 00:28:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 664afc6c40cf4209a5f22d6ad54708c7-20200810
X-UUID: 664afc6c40cf4209a5f22d6ad54708c7-20200810
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1679514413; Mon, 10 Aug 2020 15:28:49 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 10 Aug 2020 15:28:48 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 10 Aug 2020 15:28:46 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Jonathan Corbet <corbet@lwn.net>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH 5/5] kasan: update documentation for generic KASAN
Date: Mon, 10 Aug 2020 15:28:47 +0800
Message-ID: <20200810072847.921-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=qLCWArRY;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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

Generic KASAN support to record the last two timer and workqueue
stacks and print them in KASAN report. So that need to update
documentation.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Jonathan Corbet <corbet@lwn.net>
---
 Documentation/dev-tools/kasan.rst | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index fede42e6536b..5a4c5da8bda8 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -193,8 +193,8 @@ function calls GCC directly inserts the code to check the shadow memory.
 This option significantly enlarges kernel but it gives x1.1-x2 performance
 boost over outline instrumented kernel.
 
-Generic KASAN prints up to 2 call_rcu() call stacks in reports, the last one
-and the second to last.
+Generic KASAN prints up to 2 call_rcu() call stacks, timer queueing stacks,
+and workqueue queueing stacks in reports, the last one and the second to last.
 
 Software tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200810072847.921-1-walter-zh.wu%40mediatek.com.
