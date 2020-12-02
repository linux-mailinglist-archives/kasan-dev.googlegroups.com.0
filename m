Return-Path: <kasan-dev+bncBAABB7UPTX7AKGQEQM6GLKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id A87AF2CB5F4
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Dec 2020 08:53:35 +0100 (CET)
Received: by mail-vs1-xe3d.google.com with SMTP id 1sf151626vsj.21
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 23:53:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606895614; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rsi42GJfhNBaBH1OYdn+orr920v7m+MgWG0u4MiWOIdMMjyfXbDKc42nQhuiPiY5Ne
         ClqRQ+XhQvhxqHoTy/CE9+urVjRomKLWA6QyScuGJEQ7B116lPgt58Cz6RxQKLCzJYOP
         KdpCX/NaPiA51IMNcD2m6lu4Dn8F/mZDzeAnMe7m3+cFCzHyeV/QQPEyhqv7H4olAHhI
         vKgX6z2DIaeynDsR0/Ykg7biK5oj0fV8rxmPuQZ4JPo7XSDr7I9II+SqHWg90cqsoI4e
         q6IUYL7PuJY3y3mAZMZnUPl/2ddO4xI3350n5KkvNyfkKPcl+VYOLwp1v4CUq70sD713
         s28g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=wr5+E9akyc1WEjo30LtFiqUX2oLe2XQ0MxI1KHXePPI=;
        b=ZnrFhuO0f9g6IPC1vlHDoAxmnCjJyZ+VE/a9Tmn/CDA3pdswF+fJX8dNk0SyeZL0zD
         nq2Yj8mMSb+gGWEwNekggH1QmDIZliI96MeENyC5/+jGaLE5FdHGC/FOIZ4x7Y1S1ypj
         Hf6kbBJ5VYaWUviMswKRsaRiFOqFGBKKv8wa+zLrpyjLt+DHU4cGdt/0AHX+u665SQlv
         10P5PEcLmq7QUuHdFD1D02/EHSS7BgFPNPqnH82waMD77NnV0YcyGD66GTIb5bfAYQOh
         77zKkB364y/oVZ/TytXR0BpAqzIwGpPgdkrsZeNpFoAEjyckmnsnebZHHqFRiYYwTmLY
         Tgfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wr5+E9akyc1WEjo30LtFiqUX2oLe2XQ0MxI1KHXePPI=;
        b=U/7JrBsBeFBR5gCj6PaTc/uh1hn+8pk5zhncKce+kVxKts6zOIzL/UlijXLQ9PJUDM
         AmJs4UgnVT2FkxCeswZw+sSo7BSVTc8yZW6qFhwRXsgkTdoLoTfCh4o72s5mK2vHWVLP
         3xdMugbdJJlP52yVuJVGD1YSSANSV0YSTKuDb1Z7lBZ7Ac10vlb9fv+EYYjDUJ46VA12
         PSx9sKf3st8/JlrVUI3FKzTXL2+ZoNEWgfVZABdlV4AI0Aa+ZlpTHmKtsIt3XldbJ9rt
         c1OAmZtF3jVWBdAACkqB3ofQeQvbfuVpzNVsuhFRC7I84oClv8maKKGJV4GIWzaggAmz
         0r7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wr5+E9akyc1WEjo30LtFiqUX2oLe2XQ0MxI1KHXePPI=;
        b=MhL9xUMUXdWrj9ewVLqjlgSzx3okJQkDIlPm+rOmwLZxPdwQaJC8TKo0ptrfzsTcX0
         XTc5pbuTpl7/hmB/dXykyoL1bYT3Kbe0QvaCu4jycPUVl+DfWuRd6b5fxSVThDRaKZjg
         hb5mZuIqezvgQDJa6PLA9FVHG0itlpaItTI+HTWB2Xoh7Y3R4sha96LfJ9CWZ+cH3pkh
         muuq1exwHUxlpGI7c/dbC52R3bY1QcPtlNyj7eeBq6U40M77bA76YG/spmzQDvEls4ju
         INSXz0ifpl4KYVO5YY/YVj8KE4EEfh2VweKDIsqXo9+gwtI3uAwQaiw/yZXv+IdQxdIk
         GHjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531i2kj+1q9LD6Vere2aTKKqnK3jPu/BN0ajJ6tTDycx2vXmlYks
	gs+BtZBYKh9Zc5Alt6UaSKA=
X-Google-Smtp-Source: ABdhPJy8kLgWhPlWmdQdjJgq824V9+gaL+y200p3gknM6XtYQLwPYflp2IG6BYkRbK8mlRImKPTD0A==
X-Received: by 2002:ab0:7653:: with SMTP id s19mr963167uaq.14.1606895614597;
        Tue, 01 Dec 2020 23:53:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e985:: with SMTP id b5ls104849vso.11.gmail; Tue, 01 Dec
 2020 23:53:34 -0800 (PST)
X-Received: by 2002:a67:2783:: with SMTP id n125mr765343vsn.47.1606895614155;
        Tue, 01 Dec 2020 23:53:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606895614; cv=none;
        d=google.com; s=arc-20160816;
        b=xyjnrpmZD6YczON8vNUWweU8VeMZZgkI16ifCNMFsxTwS8nyd5Tcpj2904B9LNzu0t
         qqSkeU8CSHddAWCG7rdQ/OiDFH2NskGIJtjoZTtidukZHj+xGSIxAcIq39MNT9C+dTFf
         x6kabjuXFZ6OJcXJ8DDUDhli1W+ZLtUy4a7wgSsRqI/Es9AFu+Uvbx97NdD1h6uNvlq+
         j1l8yKZ3rRH3l7T8rxWMiPR21BhKKv0QeuyaMOWpBInewsR+Xf7QGy08nfimyFUM7inj
         CDE7pgAcvNOFfzddwTOVwgCKdujtFGlf0ao0axagWlGHiqKLLvPddBQW9k70M7cc2rJb
         FFAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=LTS3UJhcwXD+TROxnovUioNWm4vo44yj75DE78ydZpk=;
        b=VJGuAD1/t+sUPi/bcPIyNGHBBM+UyWZaQlJD8uGLSaFtf1Byo/Cqp+j6d2fuAa77cy
         ixhSLH/jkUDT/v75YntDkNwISg2SZktpqUncXAuMRkUgsI1IGaUFfJ1Xzjq/8dWIRuuL
         9ke2wasigdRvoXuO2hVq2LTGyyAhi17uk0Ud7YS8pXDV8I3Tp7NlZHG+bAYsxMetW5gU
         z56uG0hnBeyCIFag9XJqYGhtb8q13mV0HIMtuzomE3I9Skm8dDTm//rpCe04NAmBIQsP
         9volobEix6eCZJAyO8fg3BtEA+OdSJvnciHkMRFvqdpaAnw7/xdPkPYCOC/rGPr0J/pn
         n2kA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id q6si60563vsl.0.2020.12.01.23.53.33
        for <kasan-dev@googlegroups.com>;
        Tue, 01 Dec 2020 23:53:33 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: a885dc096bc1489ea0ccbfb7beaf2d2e-20201202
X-UUID: a885dc096bc1489ea0ccbfb7beaf2d2e-20201202
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 775296454; Wed, 02 Dec 2020 15:53:29 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs08n1.mediatek.inc (172.21.101.55) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 2 Dec 2020 15:53:27 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 2 Dec 2020 15:53:27 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>,
	Nicholas Tang <nicholas.tang@mediatek.com>, Miles Chen
	<miles.chen@mediatek.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>, Kuan-Ying
 Lee <Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v3 0/1] Fix object remain in offline per-cpu quarantine
Date: Wed, 2 Dec 2020 15:53:04 +0800
Message-ID: <1606895585-17382-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 1.9.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: kuan-ying.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
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

This patch fixes object remain in the offline per-cpu quarantine as
describe below.

Free objects will get into per-cpu quarantine if enable generic KASAN.
If a cpu is offline and users use kmem_cache_destroy, kernel will detect
objects still remain in the offline per-cpu quarantine and report error.

Register a cpu hotplug function to remove all objects in the offline
per-cpu quarantine when cpu is going offline. Set a per-cpu variable
to indicate this cpu is offline.

Changes since v3:
 - Add a barrier to ensure the ordering
 - Rename the init function

Changes since v2:
 - Thanks for Dmitry suggestion
 - Remove unnecessary code
 - Put offline variable into cpu_quarantine
 - Use single qlist_free_all call instead of iteration over all slabs
 - Add bug reporter in commit message

Kuan-Ying Lee (1):
  kasan: fix object remain in offline per-cpu quarantine

 mm/kasan/quarantine.c | 40 ++++++++++++++++++++++++++++++++++++++++
 1 file changed, 40 insertions(+)

-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1606895585-17382-1-git-send-email-Kuan-Ying.Lee%40mediatek.com.
