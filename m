Return-Path: <kasan-dev+bncBDGPTM5BQUDRBYVWWD5QKGQEBYH3NGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5ECDD276786
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 06:06:59 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id w3sf1568577iou.9
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Sep 2020 21:06:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600920418; cv=pass;
        d=google.com; s=arc-20160816;
        b=k7nx00VBftwK+awgLtc5q68obtuMAwyIted0CyQ9Nd0LZUEEwEHKg2p/EB+T9bNzRn
         kZY+6boB4y+1rbqHP3VCBSSkxQqkhqTqHCNFTjHoGLb/OF+Jx4lJVpmSrNjvSQ+qKj2W
         Qi4zNL7Ns12q4FMCbNq6vFr2tUWTDC5z5NslAwcC8m0BfSyNvOZukMVmqw6Pxn3jHJ9z
         fwNwBmKH8qjEAsIoIONAOzjb8Sly0wU+SSRK8kgAGaLyJxb8YVdEsbY6KpyCqpMK6PMw
         yUAHEJxHzGF87x0ge+DTj50mkoDJeNhPvTIoGfLVrh/FwVgQpgai+a+gH/h+68Etn3Q6
         wO/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=wXKuc4Tgp7+PQipP2KoYmE2rxpbgqErVVXm1WkixBaQ=;
        b=Ani42X0QHqcT932mNxMVthHG7AC9p/1og18el/0wGig3I5oc7ymMHdVbJomRF+1m5Q
         rxCkdzkdAmQmMn304+TnW+/7R87QCYZzGJawhsWyQjnNk4Og6azwp3ZgAiwgQnMx2E23
         uE7nS5/5GAcTc7VPtrLQwlNYYOsL/qeFofjTy2J373MMaOUIhmPQK1S82cgIv4NQ3v7Y
         UK5meN4g4hVM3gQtlslF/oCVXzFXJA4BbfXj6hAFs6K7lMt7dzhWHSXyXPpNHycX1/rm
         Z0ncJHRclyd1xAEJWRnJpcASv8tgzTEe5UP8Nsz8OglDzxapmkp4z77a0Hx22Ftn32or
         3U9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ZWXXixq7;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wXKuc4Tgp7+PQipP2KoYmE2rxpbgqErVVXm1WkixBaQ=;
        b=r9nx3MoUFb+JXKYDVmtrj1DDHFVwpTiYTRT2rEd8Zr0Cpi/f0m3thUqzsp4k+avHEe
         /vANRtMksEpAF7f9WnxXTbw6KeilYEo/DhgtEzI0MbdqjLmUUJfwbQYQPxmw4sNXL9Vl
         elMYOXRUVtPSNyad2R/PgmvOFv1t26pUnphdXvG8tnyMUVdmAWQ1zkaGMDh8eYKiCJTa
         eWsYfjmETN6bZCOX4nRI+iiUyG4fJSD8wmAK2/x61A9cHByH9l7KxnBOiMNFxn08YvWR
         vQlRk9O7rsji7RjVIL1zUe9A/G+bt3KNKL7A76ursQd926SACqxkNCWuw8IWzXjtsrDe
         fU/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wXKuc4Tgp7+PQipP2KoYmE2rxpbgqErVVXm1WkixBaQ=;
        b=KjyjukWDZAER6aUNNePxkCsx+HYfm4wBAHLFvsspt12ipJiEFLUiDHWpWq8WNpgaBQ
         d7HAoNnX8n0I3cG4YL/V8H1ASn8IgfE9e7AqG1hwiProUVJm67TATuDaUJ0lMOeUgBCO
         OJCFlHYZjQfwuXMV/duKxUn0P1+dh+ksjusRScypUn8xFXOMzhjYK7XAgM5oY7A51gHM
         jb6gw4bgCUStPQdAvVY2Ad4v2Lu+eZU/4tAQhyMIMZZGUfyrkx1dDC0kUdTY6UQeA2hL
         MpF/A1N7dPK7/JaJL/es195uZHOHeWIJWn8FEA/EqI6WRj0JFFJqnm/+XIvUutAw/W1j
         DvTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530PDpLgJr8liTZCXxi5IefQWkKpqCVEz6pE2x8zeGW0LohN6mRZ
	8qhIErAjUFoKOFajUGiiCpk=
X-Google-Smtp-Source: ABdhPJzU+aN0pxLLNgrXO/T1xCjaP889/hhsoeOha0kUAQCn1YKlM+qreQNwQj9GJMPDf0GofsIPPA==
X-Received: by 2002:a92:d14b:: with SMTP id t11mr2388537ilg.75.1600920418349;
        Wed, 23 Sep 2020 21:06:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1307:: with SMTP id r7ls238053jad.7.gmail; Wed, 23
 Sep 2020 21:06:57 -0700 (PDT)
X-Received: by 2002:a05:6638:d4e:: with SMTP id d14mr2089765jak.107.1600920417890;
        Wed, 23 Sep 2020 21:06:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600920417; cv=none;
        d=google.com; s=arc-20160816;
        b=WqOg2DUlBjaf2cIC/eq9oyux/tHeKXpI7T+jk88UFCMxg+Ep5804bCa9tVDQxzj/SF
         tcMFZbsruB6RcAb5I38Knced0LTmOTX1niZBRbCFdLptV0jCthFmc6hHOv6lsVn9OA+A
         BxaBOOIEClB8bbZZvNUx9ZfeGYZVaqKxPL+BkwzAW0pHiWId9YElw00bftv/eTGud2q6
         czs9k6LFzdL9YfezgzZZaLpDowWzVa1t+IbSXyc/ZBCS/YPQRRWJysGWWBS7DfUeasre
         j3gSIGt9AlD4WQDbrx0ePROr++A0d13HQMEsDJ1kGXh439le7QCwzhDCTC1lwKLDrSh5
         MmXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=kgEyV8GPi8LIdYi4bGI7Bw0WJs3ADwMNIObdnpyN9FA=;
        b=kPKk8S0E+DYx8fP8FsvZdRX2iDj78R/xOxRwoCxWU2ubuJCTDftgnjmA7lQju5PlqG
         vW6kvVsjZr75wzf0IhDdJsi1NNsKyhhhPRlubJ82vX/vPzJ7a7xf3EjmtElEzA8nm4YU
         tXhUxxcQI43NQKq1bBvsiR2ImqTJytHdppC9dTnk4If30nA9TEunXnR6R8gyi9f7E4pZ
         jvA22dC8wRuEAHZDwPlrVMJGoDTPyBQw0HIHZBZXXV2D8a3y0YDDDcGMb5e3XjQNYzbH
         0va91mWu8lOWEJPuhjGfmRgZRgf0pDIqYGpAxXZVdHjV6qtkg77BVjJtCup1+l/qI6Bs
         ET1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ZWXXixq7;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id k18si119799ion.4.2020.09.23.21.06.57
        for <kasan-dev@googlegroups.com>;
        Wed, 23 Sep 2020 21:06:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: b2f4419533d24dd5a6cdbfe760e02c2e-20200924
X-UUID: b2f4419533d24dd5a6cdbfe760e02c2e-20200924
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1917049134; Thu, 24 Sep 2020 12:06:52 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 24 Sep 2020 12:06:49 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 24 Sep 2020 12:06:49 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>, Jonathan Corbet
	<corbet@lwn.net>, Marco Elver <elver@google.com>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v4 6/6] kasan: update documentation for generic kasan
Date: Thu, 24 Sep 2020 12:06:49 +0800
Message-ID: <20200924040650.31221-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: CD7E561389D179394336201CEA174E7F8D7E06FE8F5E04C5B1D4AD0B5E80F0E02000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=ZWXXixq7;       spf=pass
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

Generic KASAN also supports to record the last two timer and workqueue
stacks and print them in KASAN report. So that need to update
documentation.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Acked-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Jonathan Corbet <corbet@lwn.net>
---

v3:
- Thanks for Marco suggestion

---
 Documentation/dev-tools/kasan.rst | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 38fd5681fade..698ccb65e634 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -190,8 +190,9 @@ function calls GCC directly inserts the code to check the shadow memory.
 This option significantly enlarges kernel but it gives x1.1-x2 performance
 boost over outline instrumented kernel.
 
-Generic KASAN prints up to 2 call_rcu() call stacks in reports, the last one
-and the second to last.
+Generic KASAN also reports the last 2 call stacks to creation of work that
+potentially has access to an object. Call stacks for the following are shown:
+call_rcu(), timer and workqueue queuing.
 
 Software tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200924040650.31221-1-walter-zh.wu%40mediatek.com.
