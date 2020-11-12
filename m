Return-Path: <kasan-dev+bncBAABBOFKWP6QKGQE5WCBC4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id B72882AFF9B
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 07:24:57 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id m76sf3603901qke.3
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 22:24:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605162296; cv=pass;
        d=google.com; s=arc-20160816;
        b=NJL1JMgYqhcvtynSky/ADWqs+23+u4MNP5GMlbfWMMLPVi2IX5tCJeh5zULlMQ1IMg
         1uHKZRU4cRzEvAX4JKyiCYA30NUKb9iEKuT5PCZyaYvYj9GGMsYhH9mCuB/orGskhpg8
         cwypiRB02GGyjRgatQo4nfVeX4cxUOdbjBtutFjbfXG56h7fogK6800fYnpTbsC/G0ln
         kVXguLz92/Lm5E1hQMDNmwMQUZc6sqbxM6VH+2cvRxZIfZYfgjNgyT2YVEeNua/wK69q
         7Dhoi6Ll2NJLiONNvt9zzuF5TH+oJb3Da+mpy/QbMngcZcT28PdJek+ohfgfpkekv2f9
         /4UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=/06uS+He4D4paWtdH3kUts2B3NFIq4SvXGzzSZ1SGEQ=;
        b=BwgnpJ6PE5CMZc1pZDY5xGxLvBY8nje902FJqmLHfWXhrn+VbUGho7pBkCSo0Pupbn
         Y3GELn/hLO4nCx//v9Jt+dMzHGV2AAGFpaSWe+aATFtV5ayz/8Ccp+fYjVaMcj0i21zG
         9JfWhy5AB9X5XIMBwk5nbJdtSK8077rucYWp/rAalwah1wk9auImCGuBXcZZ+GPRUPMB
         RKHi5VyRGsRsuyNDlRXpBINNmOyVmowY1tIb1xcCvuZ4xCMqHAw/kwqub+RTHTpCcnFN
         PG6SR500D9wDtUoSzSbYas7VuXLe5jGEWPrfuoFTAsf03bFMYnf929mVyt5FaTlvKu3u
         Xa+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/06uS+He4D4paWtdH3kUts2B3NFIq4SvXGzzSZ1SGEQ=;
        b=p/kB1qqauLWQKTr4HjyMj4DFXg6l2RXDKriFUA4w9htXIBfetC8AZrVyS2VdhviMLy
         97wnRH5gOHsC1Gss7eCtBSo7T9aAkqZDn+FrYQSkgp0Zyrb3k9NV1Fpltqs5F3HPVGx3
         RSi0o+cU9R8Itj9v77rg8uESrZ+L+WD/j6zLneXoLl8SszMhutzj1n4xu/ZJoA9o9vrj
         84YlZysiSmradY4DM3Cp7y5yONQNjHRdm2ZvkmJPUp/C7GbuHQzBzBWwWfxraCXmh9Iz
         oZISFdkpXq/mUldxbArQWizQa3oU7TUFB1EOpp6VFAntDJ7IwtUopQYCxtNnz2lFp2Mg
         biwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/06uS+He4D4paWtdH3kUts2B3NFIq4SvXGzzSZ1SGEQ=;
        b=NMabKSa2DWHUitu36Q3ZCs3zPh2aobwJN2Q7O3w0zVNPpXZx8gjQzujXDx3DDnvT4F
         +5WQwtWdDn2SXOYX1pN2uOea9+3II26+huXqbR1BL4K777TAKjqGUR7YS6zQe0QNSbwz
         c045lUe/4gaS905ekZ8wQaIuLe/5q7K8t9ZkxH5BptFpVVYOB39b97PinA034HoKR1+z
         sDH6hEKAlGpYlzVLKvtSuLK20ZQ+iwnp77cf1YUCzO+SGv5cy21lphPHcdMJuSnCENrR
         EEM6nuFOe6jGjqBH141Njk4QZvmURGtqdxvLmk3qAIRjP2f2TGFYXThNEPh77qs2rvar
         3kPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533cNyQ/b9wRc239YFZ1cDcJrGi32FTHSiSHOaTEfWJm5lVAK9cu
	eu3z0UypJlxs0AezpirGOLw=
X-Google-Smtp-Source: ABdhPJxfSTx3GE69kknDA9ohawR/eAd0bsikN1uQcy3dETtJUGLqum8kGcmfaVXQSzfNaZLZPz/Ngw==
X-Received: by 2002:ac8:6898:: with SMTP id m24mr27613856qtq.157.1605162296541;
        Wed, 11 Nov 2020 22:24:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:584e:: with SMTP id h14ls649747qth.2.gmail; Wed, 11 Nov
 2020 22:24:56 -0800 (PST)
X-Received: by 2002:ac8:65d5:: with SMTP id t21mr16597559qto.365.1605162296025;
        Wed, 11 Nov 2020 22:24:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605162296; cv=none;
        d=google.com; s=arc-20160816;
        b=HdNvnZMQVU1aTdE1lqY4FuFuDc7XZnlYsZY6cDbvTaYO8hQVb8OWm7e2cIzRNHLw+7
         8RTO71QbZDXfm6KL2335CjZ/IZ2xrF+rxAZwiH1K9JoyJroAzopAFQx3iNw2NQM7DsgL
         r3yM59J45Y2IUYqGStRqhvBCu119IyHsuGme7IZmMWvkQqkPCGlE2a9xcaQf/HoQsF6B
         6ZiMtj7Y9Bi6E3BUGEtdzxCo5kPs5NK0IADoxdGtsRF838CYHc7h96RZsKcdNJGk6vsa
         tAr0+ZqiR+yJl/xhHmkHRadVMLklJwr22NnmoCaGyOs/3cZE4ZzNKGT+1xkRINy+FQd1
         GMsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=gJbzxYcbFuEmceJX85c/AxjD+0HdLDfYZ6K+NhsBTqw=;
        b=EtmY4E40x4y/GASM/O09ztccMd/1YRE3pUoGKUE172GLggZmyd7BtA7s4l48/+IR4y
         VLRafGUPKB3EfRhAs/diFt3jISKXyjG/xIDVPT12MwNwYO/qBYzKinLW4ed4jZPaPPm4
         pgIL/ES0AMnC5l/c5pr26RMnbHD8XeLgNosmjzgnykoAsLbwNmyKo7HZvJlSzZGXY/1I
         jQ2wxz8xrSZ95ZfmvVihd3SMApSCG6UMdMKTRgFUhqYjprxhBoVbvfbFBF1yOQWqvU8W
         anjWvu+/F3o47oxgCOUK2BfXjgBlolIQr5iMgi0fKelRckMMizjZXH6xoz3YTbiYI7yh
         ftgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id h1si359634qkg.5.2020.11.11.22.24.55
        for <kasan-dev@googlegroups.com>;
        Wed, 11 Nov 2020 22:24:55 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 0fca04583e6f4935af9d2e5f172a45c4-20201112
X-UUID: 0fca04583e6f4935af9d2e5f172a45c4-20201112
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 542004095; Thu, 12 Nov 2020 14:24:49 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 12 Nov 2020 14:24:47 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 12 Nov 2020 14:24:47 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>,
	<miles.chen@mediatek.com>, <nicholas.tang@mediatek.com>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH 0/1] Fix objects remain in the offline per-cpu quarantine
Date: Thu, 12 Nov 2020 14:24:11 +0800
Message-ID: <1605162252-23886-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
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

Kuan-Ying Lee (1):
  kasan: fix object remain in offline per-cpu quarantine

 mm/kasan/quarantine.c | 59 +++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 57 insertions(+), 2 deletions(-)

-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1605162252-23886-1-git-send-email-Kuan-Ying.Lee%40mediatek.com.
