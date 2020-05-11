Return-Path: <kasan-dev+bncBDGPTM5BQUDRBSHO4L2QKGQENUPBRRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id CF24D1CCFAF
	for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 04:24:09 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id c13sf6222105plq.22
        for <lists+kasan-dev@lfdr.de>; Sun, 10 May 2020 19:24:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589163848; cv=pass;
        d=google.com; s=arc-20160816;
        b=kM7BZTMmPhd5EFunTGx2zeE3tIP3YJ+7GFP+FWNHf+ovWLbmensK0BCrh333Ft1lCV
         gCGHKQvdloDkZxlLU74PtOxtKj5L81gbPMxmi/quuxFhYB3KhDn84iVdPeeXsvhnm5Gf
         P1qHQl9IQRd/ma1n+vWCCsvrSd9qZrY1vcQ/W6oU2xcyJWmpdnN4MCtFW/RSgwQRWNBl
         yLZWDRO2ybpCwW2KZ1oheFCELX5Os7Ewi62pMYish/C4T63+nosHZJg+VQph7/g1UPCI
         BEWqMOOrVJ+xnJM0VLLuFFVrcp30TFSTUeEjNkn89zcQTpWJorCiUfjKO9D004uVBca7
         4a7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=kkxh0by7DIXftBumMlOX/AA6zhNg6XzNFAGJO4mn0qU=;
        b=h6cTWh/dPiiPNFa3UCtd9IyZYr3WT95tNQGNgIAMg6b9FzjZHsOPfnopltIs7lAD55
         +fN9QsS4d5psWyVR48Ch27TffduzrPitHK8AN0KWImiCE7p5r6ACxOUr4cLk26G1Boza
         qdb0TGEYsyDqnQeozhqAG0x3iqhSHQRIjZNwMLhzdohVuwSFvDkWPCEUt0zcibzUzTSX
         XA0BiK6aX9JhDkrkOx7IpjJRb16Pbms1ZPynlfVV8vXp9fmKKeFlgR6e2ADVeBORrGKl
         FvOkkC8q+4S9Q6DN3EVvyeT+fr2DDrqAMftKHerQOJzgUckMkdyObJpTwShvYAh2MbTM
         JuaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=vAnu9TQ3;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kkxh0by7DIXftBumMlOX/AA6zhNg6XzNFAGJO4mn0qU=;
        b=tGxdsFZTxHKbQc0WpQzCrPXY7j5VHLTS7OdHSeRiXJN4msfCp+r3cNQhjht1RKnE9W
         NJaoWSR8lgAB/nw0w20TpglctVBZNnGKydtwpELllSYZIJ/qUoJbF2/x8KkTYnLYeYlD
         ZgFFKPa+fDSZBb3QKP00bX9gogsyPhkUa0NbEjZzO3pPIXJbepFFltrWtBLjBRD7ohmF
         Z2m7QzCVbiExKRHgMlp+9SLpmgaYaSK4saokNMYgmh+RWa5QxTjNn2ENE1Zhwlds2X/W
         ChNGjQdjsu9/tx/YZm1bVmPm1NDeAAiwVINqNBxhyt1yNHwe8ORSAZuSS3Xqpex0t5bl
         Ugeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kkxh0by7DIXftBumMlOX/AA6zhNg6XzNFAGJO4mn0qU=;
        b=sWgJCgnt/UYwB3XO8shDDZlXMd+Uv0ONMWnqZw7yQzMRiY4NbpVEHtFjoOCDO4NsOj
         Ex1fnttkcds7TTEruXt6idaNzzsdOK5cZtvbguHSMGOt/AWwOGkc9ZtZCG8QKShVP9Rh
         e5ij/Tk0eDzeV/QAB3x0DULt1baL7N3tPFkxUKHhPMOaHZqqryJF7YfDUOzkZFdx+dQC
         8iQa+Wsv6Cpdz0yxKAMwoDcYVVVfq/SgbgYio/BlrLQOdoO/2w9V3hs4+UZWDUchItd4
         P+dqznbTfF9jqzXmx0+AsrZtC8UboxRg2I0UX3VfFeaIe6ORVgb8+ASuXOKzBjuRg1g2
         RzKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZvJyqwNh4DP4TvJeMxN3FWdmWkc67K0QUxw7oEdOIagVPx9jvF
	43ZBYLk0F4h06M+p8ZRphAY=
X-Google-Smtp-Source: APiQypICWyIpxALJplwt6Rm5kzqf8NuE0IUFjsF3F0PR6Nw2ZM9APAyj4A9QQJfibHJC0jYsCTC3FQ==
X-Received: by 2002:a17:902:bf41:: with SMTP id u1mr13340025pls.195.1589163848289;
        Sun, 10 May 2020 19:24:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8c82:: with SMTP id t2ls4326940plo.5.gmail; Sun, 10
 May 2020 19:24:08 -0700 (PDT)
X-Received: by 2002:a17:90a:2e82:: with SMTP id r2mr20019926pjd.128.1589163847877;
        Sun, 10 May 2020 19:24:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589163847; cv=none;
        d=google.com; s=arc-20160816;
        b=VQu2TEQxWd7yNrzQ+0trUgg+ZDqUrjCDWNYcvOBFiS4WzoxI+IqU7SyKneEPVze6Yp
         Keo5DkbgslPRs8dOileWOCbRGmwfrLWZczgTMq7cTUfU7DRuZIt8WojIV506Dw3jDHef
         piWgpszx6qBHvfYvGCfMVmvIc8a08ZJ6wOPezE7HSxtJCRg7Tk6H630i+QLCyxcOHV43
         0NZweFPRYRG5iup1eTHn8TF6y/+YjJW4WvjvVCNQj2kyPpDEsU6XAQAKfVhT3JCnD8Gk
         xyITpDwaHnzxOwFrgxzyubn7KieXGQ2HK3DXiOZFj4H9Vgwcrjn8yyQ0U/UsTbaoOTAh
         BtyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=fxR+3x6dfchTUCq1rEZKfrKVHn0oaDflYS25MJ56o6M=;
        b=MwNl/l00YBBdtPJ6riKWX1O8DPU1tyeQQGQ2IPjoXisIGsR5G/cpYWP/VU7WbJKuct
         rcoqKpRnCTLK9vB3Rv1Ghs1MBiBEccKU6IWYT98C9vnDBCjdS0aG75wAm2MKwEf22S1r
         pldByAeblLIBmH0EdYo4ijPSnVxhMCC9teCO0JpRZTrvRXfHkbyR4HzjaKssDDX4giCK
         W8RVqz4mTuQ/kVA61xEmytxzAWEl6OA3BZyfPWS5ggZ+SuwPU3tKDmcIPOLjvHyY154v
         /GqNwqJg5sv94IQM7lDeBAERylPcYqeJGU6sYKixuL7x8yZrpU3ouzMK+W1juG3bI45s
         0FAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=vAnu9TQ3;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id s65si781584pfc.3.2020.05.10.19.24.07
        for <kasan-dev@googlegroups.com>;
        Sun, 10 May 2020 19:24:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: e8a9aa12e5eb4e27a98022774341eb60-20200511
X-UUID: e8a9aa12e5eb4e27a98022774341eb60-20200511
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 510547924; Mon, 11 May 2020 10:24:03 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 11 May 2020 10:24:00 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 11 May 2020 10:24:00 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, Josh
 Triplett <josh@joshtriplett.org>, Mathieu Desnoyers
	<mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>,
	Joel Fernandes <joel@joelfernandes.org>, Andrew Morton
	<akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v2 0/3] kasan: memorize and print call_rcu stack
Date: Mon, 11 May 2020 10:23:59 +0800
Message-ID: <20200511022359.15063-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: B313EB8E7A005151BC9122FE7936DF9B364C35100A83A879C7D0BF8EF3E92D172000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=vAnu9TQ3;       spf=pass
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

This patchset improves KASAN reports by making them to have
call_rcu() call stack information. It is useful for programmers
to solve use-after-free or double-free memory issue.

The KASAN report was as follows(cleaned up slightly):

BUG: KASAN: use-after-free in kasan_rcu_reclaim+0x58/0x60

Freed by task 0:
 save_stack+0x24/0x50
 __kasan_slab_free+0x110/0x178
 kasan_slab_free+0x10/0x18
 kfree+0x98/0x270
 kasan_rcu_reclaim+0x1c/0x60
 rcu_core+0x8b4/0x10f8
 rcu_core_si+0xc/0x18
 efi_header_end+0x238/0xa6c

First call_rcu() call stack:
 save_stack+0x24/0x50
 kasan_record_callrcu+0xc8/0xd8
 call_rcu+0x190/0x580
 kasan_rcu_uaf+0x1d8/0x278

Last call_rcu() call stack:
(stack is not available)

Generic KASAN will record first and last call_rcu() call stack
and print two call_rcu() call stack in KASAN report.

This feature doesn't increase the cost of memory consumption. It is
only suitable for generic KASAN.

[1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
[2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ

Changes since v2:
- remove new config option, default enable it in generic KASAN
- test this feature in SLAB/SLUB, it is pass.
- modify macro to be more clearly
- modify documentation

Walter Wu (3):
rcu/kasan: record and print call_rcu() call stack
kasan: record and print the free track
kasan: update documentation for generic kasan

Documentation/dev-tools/kasan.rst |  6 ++++++
include/linux/kasan.h             |  2 ++
kernel/rcu/tree.c                 |  4 ++++
lib/Kconfig.kasan                 |  2 ++
mm/kasan/common.c                 | 26 ++++----------------------
mm/kasan/generic.c                | 50 ++++++++++++++++++++++++++++++++++++++++++++++++++
mm/kasan/kasan.h                  | 23 +++++++++++++++++++++++
mm/kasan/report.c                 | 47 +++++++++++++++++++++--------------------------
mm/kasan/tags.c                   | 37 +++++++++++++++++++++++++++++++++++++
9 files changed, 149 insertions(+), 48 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200511022359.15063-1-walter-zh.wu%40mediatek.com.
