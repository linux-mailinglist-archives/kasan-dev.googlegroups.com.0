Return-Path: <kasan-dev+bncBAABBA5ZZD6QKGQEDAONRSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CAB62B3D23
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 07:30:28 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id 204sf7777686oid.21
        for <lists+kasan-dev@lfdr.de>; Sun, 15 Nov 2020 22:30:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605508227; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kh/FmuhaedX14MxbUCp+uQTmOfuBout1mwxchNiQ5q6qosldJKAP1pgr9H3LLVhh0X
         hOsZp5iU43SQUCu8MEpfr/6WuyCCDyaPOs83zacTEk5/aHO8y4BkhxwxryD15ATTzpkL
         90G5IlSyAiJ4oGLpPPRXCT/j+V5+auZRJ/Xs64B4L6yps2/8LL1eROECgxAW8lA59hqq
         HkXcqJ7ymuEQakl/INUhfd6Qww1JF1m7FdMz/Cg1NNrL1e37Esj+tgUoY1caoM2unBIP
         cm40m4HnsN859LzSjsX17Mtnb4SZZdYNZ7gjXTr6lBT579yV6kRQtjbktJFdehpIFC2q
         ZJLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=9tfQAnVAHfnac9t18F0Ki7vqSN0SUEaBs8FAQoEiNeM=;
        b=e3Yr6AZXAqjYJ56oxnZGusYNQSQhimoifxUmgPVNWCTqPR25vaaAhNk5maXz2X1crD
         LRtagKI7jjYF2z4PnkxXxHlGq+OTl0Rl7DvCeYtOnl63QQkIMOXhAcCSK9aTfaPASJVY
         VseplToc+P9E+++qEIGQyIDD/44khJ8AfoQS3JPT0frerZOKk4NYkXu8q/cZwPocwbrj
         N1tHB9vvWycwWkMMNlLwuRj/k2zcs42OTSyb7gK6B10mwp05Mqkpo/TwOZSK2hKrQIaG
         R5KuqQjgH1jF344oeZ6mMRA7DpfkcHzDgQqktQ0LMnO+sWGydmnXoLeSOiPM6742hcvT
         X9GQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9tfQAnVAHfnac9t18F0Ki7vqSN0SUEaBs8FAQoEiNeM=;
        b=nT7IqgNZAYPivprq6JEJq2JYUT7lrvTrRUe6Gr8QL708Bx+DQlhDM61NyM4IsvLLIx
         FHS5+L5lVuGnOwwmp6NgTlT1zlsNCjH+v5d8TQQGX1Q/vbtqjtN6SqmPBx76J3LO/tCC
         7Jzlr3yh98ncqCcXRhC8sZCrLrb7GStbbtnM5gW4FqlulMmd+MM17hBOZgZHsErnNOJj
         A5AmUJU2MDA7OkauVPtZyajBUJl/smgw8VJwga/yZaehAuo6IyYUWqbqAP/ITYQqWnnQ
         SRXaGUtMXkve8vrXdSFQmwC9fZQ9bCsba9CmWXcV4RsYSj1oL+zLUT9Z5ye9SiuxMDUf
         KgEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9tfQAnVAHfnac9t18F0Ki7vqSN0SUEaBs8FAQoEiNeM=;
        b=bJiwS0Tl29+CFddYp+5Mc98q099eEcA3DvWwIKZUti2CNNtgiLnXk0tyOJQVmp7YSS
         lL1b40MgtgkU+8dMIGtFrDSB5/5msB3/4993G10wCve23vt06CljMR8sR+uJpBZZwe8g
         +V1sRXwKH+1lJlPcbLrEcOY2h+zEmgGiEOVC5MF6M7qYKzF3CI26faz7C0/23q+YvdyX
         9TZiI4NKzg7arRGb15It/zdPO6sUJYLlfn6Jx12jUqP/oc4OOFm/n19zE5BWHdXVGeZC
         aStJTBkVcQxP7qKW/dDo0Dd9LYTipyz4nxtxa5VlQCxA/vwaMlKXi71rcw1B5ltII48W
         hL2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530uoO4LlY5uHOb4kwdxu5eb3UPe+N57y57BKhLTPGmWxQBdGXhx
	hoWdUIOyn/zYUgRErCcG/50=
X-Google-Smtp-Source: ABdhPJxCnxrDi2MFiqp8OgMR3HZcKEihYt6QxHXZdyvrd/NN/NdzGL+V3+7cxTeLkkZMsb5ld2da+g==
X-Received: by 2002:a9d:3cf:: with SMTP id f73mr9309357otf.118.1605508227564;
        Sun, 15 Nov 2020 22:30:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:130e:: with SMTP id p14ls3024611otq.10.gmail; Sun,
 15 Nov 2020 22:30:27 -0800 (PST)
X-Received: by 2002:a05:6830:19f4:: with SMTP id t20mr9663435ott.239.1605508227237;
        Sun, 15 Nov 2020 22:30:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605508227; cv=none;
        d=google.com; s=arc-20160816;
        b=dRSkcDrrhBFw9LmWsTMzOnBolgAX0ilNIy6LDJ6ta987WL6vehUVOJ81v0uorNGYac
         BRff1kZ5q4cfvJrIS6VC36UxDnrcyvUUbt6nw4T75VdcPgkvaYOkUtU4qSYHJoHSqbUR
         eQ/WA06LU1UR3n144FLEVq5wQ6y+rE94CwthGs9AwB26CjN7lHOghYOmE44RwYl57WCU
         IQcyGiTuIgmr+luKb7Emtzj+8dyyW7h5r3OasUkKlNXakmkunNRCz5cW3G26+Ewer+wa
         Vrf5UL+OVIemWVlcK7lOgjTQ1xnAjO7UUZXBJRCkQXtKYD6q7Ih5wXSmEKxWkzkXt3EP
         1cgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=dGKqQGTsHliY3FZsBlGIbzNAwCXc9W3VOgntOqA5xBk=;
        b=G9rxRb3lHW+Mz40uKLJMfMKb3R4qV09Oeffd77SCXvh/DBRBu0bIlhi4JvkYnfFD15
         1YpbW59+6EzVRGe2Ld1iYtG4AED3rgnS9uCl0cub0Rby5UiTDfnBV9oSrZ7AhQmtWgwT
         fKndZ/YGP+EH8qaqefyRjArR7I6jnFRBzwbUhnxxk7R5y+XEk+ltpBYOsyYBf0DXy1zr
         wDJTfDCcIn3524r2E02iZwnpSCHaT9LaImvPYsyoLPtnUcUZ6x/n25/Ylb8JZoWyXEgj
         JijCq9O8p3r0/IV+OJSwrcTH1DJNaE5vSv4K4tPfw6JSA8nvXecJMgtJHrSSPBKVjgya
         tbcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id b4si16317ots.4.2020.11.15.22.30.26
        for <kasan-dev@googlegroups.com>;
        Sun, 15 Nov 2020 22:30:26 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 41ff020b6eec4a2580c9b73b5e5d3933-20201116
X-UUID: 41ff020b6eec4a2580c9b73b5e5d3933-20201116
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1805354627; Mon, 16 Nov 2020 14:30:21 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 16 Nov 2020 14:29:31 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 16 Nov 2020 14:29:31 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <nicholas.tang@mediatek.com>,
	<miles.chen@mediatek.com>, <guangye.yang@mediatek.com>,
	<wsd_upstream@mediatek.com>, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v2 0/1] Fix object remain in offline per-cpu quarantine
Date: Mon, 16 Nov 2020 14:29:27 +0800
Message-ID: <1605508168-7418-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 1.9.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 75B8CD20D38641DB5CDC7A8379557EE33EB44A40F207B979FD7759BFA4468E852000:8
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

Changes since v2:
 - Thanks for Dmitry suggestion
 - Remove unnecessary code
 - Put offline variable into cpu_quarantine
 - Use single qlist_free_all call instead of iteration over all slabs
 - Add bug reporter in commit message

Kuan-Ying Lee (1):
  kasan: fix object remain in offline per-cpu quarantine

 mm/kasan/quarantine.c | 35 +++++++++++++++++++++++++++++++++++
 1 file changed, 35 insertions(+)

-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1605508168-7418-1-git-send-email-Kuan-Ying.Lee%40mediatek.com.
