Return-Path: <kasan-dev+bncBDGPTM5BQUDRB5PKYP4QKGQEZRQ5IFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D47924025A
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 09:21:26 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id d30sf6736662qve.5
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 00:21:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597044085; cv=pass;
        d=google.com; s=arc-20160816;
        b=WiK5FC/NVPbFbjCD/rqK5GvSxrudKhUMsDAQqAl0wXIlW3fXmdIQDBDUQq4T4wym3D
         KawVYvYwNJxgPvgHACEMc2YPQ0Fakei9rOt8F7tclMvQ+xgc+YSNjNY8WCOW1INYoPO5
         BotdxLK3hwLn/EgJ/Kq/ldhZLrZ/7jNRuoXS/Jexl6EdH6vyDY4JCbfNnnE4jQegC7sc
         hWGbDVrBGyA7uy6K/cIbgFkrH/QcovAXhJe6FCQT7hi4Mth7uFR7iC06usUxUm8OQyAq
         kjZYE5GpxrOMjwBXgbgT1vkb8NibhvJljEoO4kyhWP9DDKN33kqphtqW+cHXqgE3duXc
         4+Jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=dghv0D07ynuMeUMJbjOnKbMQ/gTfZCXkJHTvmmNJmoQ=;
        b=mOrzCE2829ssATpracy55l0pTyr5Z+CZOQdLphUpQe13R1k/flVy0JIhcYcRpr5X6o
         w5gZ0boSBleL3pOAIUIKaYdNZSTEHJ6cCRv05Peb5T4ZnupCbdVoWi4pOTr8OKpZR3td
         TfxSF4R76ktSNBCXxK/SpIrZ+tmGJbjzUlwpLkAHw8R8OOpdHnWl2i4WtQtyOCezeqER
         cM/heHt7AbRh0/ijDGqthP5BX4ll8cu8EzBrkQfMdzUPPSxRs1uDBYhQQvBdidreYu8a
         dwd5iAjj94oN3y/BAfXIRXEF3qmYaanAX+Fkx+SG2SprP/qWBOD1mXnn4YCDmaWd9PNu
         PqKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=SMQ+HDqc;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dghv0D07ynuMeUMJbjOnKbMQ/gTfZCXkJHTvmmNJmoQ=;
        b=j+JM1MtHM7ByYvSylBeQJW+XardYCMUDp8tLBMVSd2cN/nCoYEc9mXgjt+ofM+/z97
         e2Y5oqJc2qbjaize3gfEMmglI1NNjhsaEIBT9kJXUzhefnjXoaIOTZAt3WJ1DDXOMq9k
         hTc8zmPXXRxZsq+JBC2C796vh5yiamTiY5AQGN3f/httlgPBGEBAmDDCZfkkbCUCPZVW
         1GlfNJIcg/AwGFyErFf7fupNUL6pT2jgi1HXhzcpKZzA8XP3Wn2xH7wS/DI4KRPcAXpN
         Gvgm3k5QCbOtmsmJOO4fjATVTVMJBfgI7/h4Mm8OoQ0DifdWWES61j7h5pL7UCoah6e1
         zBqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dghv0D07ynuMeUMJbjOnKbMQ/gTfZCXkJHTvmmNJmoQ=;
        b=SUOnLfkGr6Q0YcV1qlfZ8zODC0j4CoyPgrEinHtVMS9cK7TNWCQNGhcpOjdH8X47I4
         SXUSW9Go8n6rDluqxBdYqYODsVNJtX1FsAQCb25nofLUwT7G+Y81INfg9DFReMJexO7d
         PcvWSmUnCe2xSqpJ7X/+HoQOZ3fze+9Gi+v6BRZM8D7I9GQMUUdbN+1aO+Us9MhxLKk0
         G4om+12G92uVFz4HKoI21H6/FGAekUHRQTiI7/dnEo7whF5FQdT69L2naBFJo+ao06lk
         vaf63+NxY1Os5lvq9m/E6ioIhQRUNNWRKdhVtpCesmHfpRwYnayofyKWz1eqQhw49lyW
         taaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533vHETbSRC4F2Y0Qj2hWOLh8+9+12BkcvcN9alnuvvHbEqgNrGG
	XHaXLpNNCWT0i7BizD3rOFw=
X-Google-Smtp-Source: ABdhPJztYEZwK7/KI3nrPJv9H3M6me7J7v8Aw6tmBt2F9ASbCKjpsUyfUsy6LhyGyaSlVd/rfXCfsQ==
X-Received: by 2002:a37:7407:: with SMTP id p7mr24821770qkc.350.1597044085205;
        Mon, 10 Aug 2020 00:21:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:7d2:: with SMTP id bb18ls4094696qvb.6.gmail; Mon,
 10 Aug 2020 00:21:24 -0700 (PDT)
X-Received: by 2002:a0c:d64b:: with SMTP id e11mr20245121qvj.169.1597044084912;
        Mon, 10 Aug 2020 00:21:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597044084; cv=none;
        d=google.com; s=arc-20160816;
        b=W0ezmRPm/xFwb5YWla6ObyYiTjIrwUMP+i8ezOBRgsS1l4E/puC+Rmf/5hRZNAhoHd
         leD9021DcDrlE8/xjH2Az7yIgvHjBx7rciNw6YZTR2rZrZBeacEgIeXt0DhT38rot70z
         zOKwbKRx+dvPLMQJwbAdL2uL6lUZnkNkRMdEQMA9BU9LTOxrGNp0hFLZFMePrZ8385nn
         tnV2I5zpvB/bV0pobywS373EVNLsk4GEKZckL8+Fw+WPCfXYzCQkUc/1UyxxkxGeTqU+
         QKrjo8wK4tuXl+XtXsmORMFp3CPHAxc093adHkdmogH1ekc1jqyzYJ8O8eR7zBvoalAY
         TepA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=8hb1XmCOYYfoHO2INc2JsSa/wZHmidgJRDdB3egeX9U=;
        b=dj0hXIPOOfhHJcPpQlPqdXrKTNzAYpbtV+eegWUJBuylRttbFYq2z5r3wDZ4PXGMeR
         dNBzvKwLB9lFmf+pezH/Syx+yhZ/eAtevqm6OYbFC6LrxSXOthqtUhbkvq9/QO4AwibR
         TFg4cheutYfo9r1QvdpaG5XAtWfrNuhmFtcqj5mjsKD2W8+oMNU8UWCuacSpCqpE5aQ+
         vnst1HZwrzvI+/27RZVwplr5uJwt27Mhma1R1XVfgddCEY0yMTq2BPEM7SsAuUETrOGB
         a8GW8zkTUPI+kEHnL/1f9j1zHdGOH4PRH32Mdg24JL9ZJXWK2Cs24RonpN2hd10MQ8HD
         aebA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=SMQ+HDqc;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id m13si831789qtn.0.2020.08.10.00.21.23
        for <kasan-dev@googlegroups.com>;
        Mon, 10 Aug 2020 00:21:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 9ef467e8e3c44a80abe745e271563427-20200810
X-UUID: 9ef467e8e3c44a80abe745e271563427-20200810
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1691687393; Mon, 10 Aug 2020 15:21:18 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 10 Aug 2020 15:21:15 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 10 Aug 2020 15:21:15 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, John Stultz <john.stultz@linaro.org>, Stephen Boyd
	<sboyd@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, Tejun Heo
	<tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH 0/5] kasan: add workqueue and timer stack for generic KASAN
Date: Mon, 10 Aug 2020 15:21:15 +0800
Message-ID: <20200810072115.429-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=SMQ+HDqc;       spf=pass
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

Syzbot reports many UAF issues for workqueue or timer, see [1] and [2].
In some of these access/allocation happened in process_one_work(),
we see the free stack is useless in KASAN report, it doesn't help
programmers to solve UAF on workqueue. The same may stand for times.

This patchset improves KASAN reports by making them to have workqueue
queueing stack and timer queueing stack information. It is useful for
programmers to solve use-after-free or double-free memory issue.

Generic KASAN will record the last two workqueue and timer stacks,
print them in KASAN report. It is only suitable for generic KASAN.

In order to print the last two workqueue and timer stacks, so that
we add new members in struct kasan_alloc_meta.
- two workqueue queueing work stacks, total size is 8 bytes.
- two timer queueing stacks, total size is 8 bytes.

Orignial struct kasan_alloc_meta size is 16 bytes. After add new
members, then the struct kasan_alloc_meta total size is 32 bytes,
It is a good number of alignment. Let it get better memory consumption.

[1]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22+process_one_work
[2]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22%20expire_timers
[3]https://bugzilla.kernel.org/show_bug.cgi?id=198437

Walter Wu (5):
timer: kasan: record and print timer stack
workqueue: kasan: record and print workqueue stack
lib/test_kasan.c: add timer test case
lib/test_kasan.c: add workqueue test case
kasan: update documentation for generic kasan

Documentation/dev-tools/kasan.rst |  4 ++--
include/linux/kasan.h             |  4 ++++
kernel/time/timer.c               |  2 ++
kernel/workqueue.c                |  3 +++
lib/test_kasan.c                  | 54 ++++++++++++++++++++++++++++++++++++++++++++++++++++++
mm/kasan/generic.c                | 42 ++++++++++++++++++++++++++++++++++++++++++
mm/kasan/kasan.h                  |  6 +++++-
mm/kasan/report.c                 | 22 ++++++++++++++++++++++
8 files changed, 134 insertions(+), 3 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200810072115.429-1-walter-zh.wu%40mediatek.com.
