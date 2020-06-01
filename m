Return-Path: <kasan-dev+bncBDGPTM5BQUDRB2M22L3AKGQEWXOQ6FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B82E1E9CE8
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jun 2020 07:08:59 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id w65sf8027044ilk.14
        for <lists+kasan-dev@lfdr.de>; Sun, 31 May 2020 22:08:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590988138; cv=pass;
        d=google.com; s=arc-20160816;
        b=xlbxUS3Q5ldD4booX2niC5pnqgUx/SMSA5EUHSaD6NVo45C52FChvH/1ytai06ZYz8
         8IqFKBDp1xUn2giB4OUqoQx5qqqCtkbxlqt08FwIyht5qyLb1DchW2FdscP8q3Ku6B9l
         De+G03deAMeITJtPxVp4mXiZOiVXB/cLZgDwCxrHSHYmdn9nIkMLYDz9RVrrIoTG2YZC
         uL/AtLoEJP5/orv/gJDq7v1JdequuQOzI0vvr1Xj7dHMgIK/FJ001tzORf0kILEdg7Ma
         BjBh4WV00NHMy5CcLZvIpM3PQceHL2I8nChRNCQ74TxVbJ7wxkQLRSJY9mKrE3eADroq
         Xrcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=hEo/jiG/eJbR7be22ALSQB4404+86X/mo+wIQaZt0dU=;
        b=nOYqKtAqiGHbnY4Z7G9H/wnuaAUce/B6+4cClEbW1h7QBHPjNs/pKkRwwGWvJ667Ys
         q6aK2WArEPv0mv5dRbhGddzV0uee6c77j1aZSxFUnCqFMi7IQn6NjEMdDBwCfJ5k3qmK
         Dnz2+RWqvFK5dnQjy57QZhEh2lCpDUWcFw38BFOaPTY2U0pyhgdx9uke5DcQJV6ynMVw
         eY+xEWkbG9247AwXXVHdaMHiqHvhnxR13gD+MX9oT/26XhkOka+6q1iH5Q/bkLLNrbXc
         /ZGFZJf/g4cOAROqeSao8yDA6AedoPDHFk7/Mzy/9UxBjhGYd6DPHdbhNSrdOvzecWsU
         Mh9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=t28cMnF3;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hEo/jiG/eJbR7be22ALSQB4404+86X/mo+wIQaZt0dU=;
        b=sAGnEFEJeTnfSGq6m9leFDwpTrzypQMnVMNEn+I+nrRRDFsFDfBJiVF5LkHaM30mx+
         OM8wJLhAwop1DJgyvp7UgxGTYMm1eVfYGf/WJ/kp54rmtkM+slIvfJBzoDdODVU2KWVj
         7r8Rn7Mvfai9G7PwGne0vBWCBuMZOj2n7BYltkJRBGIVNySFSl1bPiwVOSUsLlnymVq0
         GzRK6tXDrmoQ9Hif4m+KOPyl37SRyDqVcIm7aOwHKbfzTM8/daOf3RzNN96mCYMam7Im
         E0sSVQf6aSAH0gQdhmza5obdHajxlTqoSt8XRF6KvuSXcHIIKGNN54DQyGtNdYsopTNq
         iPHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hEo/jiG/eJbR7be22ALSQB4404+86X/mo+wIQaZt0dU=;
        b=svOkOSmAltdW9Fv9dHlTA+/TNyRP34thfVjDcLS68063VxEYAzHAfTpvMEgo5j/JgI
         NVaByn4lFzb+ohJEbluXQ342K/pKmCplIEq0k8VbaU6ysUSrWYUEJKUkuBIFspbhEk+4
         Bq3DPQEvD1vHLKhS8r2/bWxlKihyKFy+l6IHdNe8aFgD9JRD+iV6FlfwRxU2lSrcu9qo
         B/K/tsk+5GNdFDuI9YCklanNIJvBFzTuOqUet29vn5wgHc/BiuhTIKTbB4oNimYlskkT
         0zUm4g8V0cQNH+hJnul6FstpP55iTWcZtqxM0HC/iP3HVk5aSgD3Zb6159ztcWSpaMa5
         5SBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xNgB+jlT1KhQUp4uXaBTmWUgutylDDbDGdhWl+FHSr4aPXjY0
	wv0xWUlRh7+BrGq099tsUb0=
X-Google-Smtp-Source: ABdhPJydaPLUQfffLiVYckqTH3dLqJUQU0z6ZG8oqhGgiRa/22cGr+3DjCD9PvD+JyEb7wCTfmhGCA==
X-Received: by 2002:a02:2c6:: with SMTP id 189mr20087389jau.115.1590988137170;
        Sun, 31 May 2020 22:08:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:3001:: with SMTP id x1ls3269250ile.6.gmail; Sun, 31 May
 2020 22:08:56 -0700 (PDT)
X-Received: by 2002:a05:6e02:dc8:: with SMTP id l8mr3294868ilj.88.1590988136748;
        Sun, 31 May 2020 22:08:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590988136; cv=none;
        d=google.com; s=arc-20160816;
        b=uP7U8VdSyF9Rn6rYze5IHUy5fOvwHuOIxleQWs8wscHzx182naLx4J0YHQvVnVTug9
         Gh5GPLQ5zWqLg96qF6fNh4kpixd4sPlmVK3PhML27IjhXH2VKbkkBSIxAXTNYsRJV28I
         ttmAO+DEai735NYy4cGWF4UoX29n57o1aTDi1ezw/f4g9khZ9VGIZhZ8vrLOzJzueEfN
         e+H6colwBhu+X1OqMAqPTRru30PZ5OwqIMfXmTbAPap5M1j5uo/p2BhHqTLKZv1Mr0gz
         /yxWKpXR3ZYgBW8gRr8hI0A52Hr0er7x4Y5u+uIlla6OOBBE9sd3nwbhidAJpU6oMCbs
         JKYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=BjrBbuCItqpm1repRmaWQetZfuTVq1NPzMTTrAPlriY=;
        b=bJm6eQzgGHFeeV5ldyyvW4rD4ZggqbWcmQoti16R1C1BGPFy96q05MKZB0zR+fnBC7
         +ia4lJFSovsTMqZrEBfTbofzQTW7bQWh5CK0MiORnfMEK1QSYcFlH8+QKZztbkYhc03E
         kvxH4HT5YdgYZvmXHF1hbweCgxcZc8Vv7eh99nzV0nsPvJRhtxSu3AtlfnzxkhHbs/Zx
         QYEcOEMB+6PxkSOPENWAiFJ6LoAntnE/4F59eFBm7EeIr4Jb2GLAw4aMmfIE7FHFc8wN
         uG9LDxq8DPIChOKVp1XlK7pg6RzGsbgowC9a8aL7ktPdxApIEaGZnE/7KYENPOOU1p57
         OGZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=t28cMnF3;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id k16si493497iov.2.2020.05.31.22.08.56
        for <kasan-dev@googlegroups.com>;
        Sun, 31 May 2020 22:08:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: cc27831c42c04c5c9464f3d2821bec67-20200601
X-UUID: cc27831c42c04c5c9464f3d2821bec67-20200601
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1622336591; Mon, 01 Jun 2020 13:08:51 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 1 Jun 2020 13:08:43 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 1 Jun 2020 13:08:42 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, Josh
 Triplett <josh@joshtriplett.org>, Mathieu Desnoyers
	<mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>,
	Joel Fernandes <joel@joelfernandes.org>, Andrew Morton
	<akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v7 0/4] kasan: memorize and print call_rcu stack
Date: Mon, 1 Jun 2020 13:08:47 +0800
Message-ID: <20200601050847.1096-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: C727DCCAB018333AAFDF619F9CBED0C6C0C9C294D74ECB3B9AE5B3304687462E2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=t28cMnF3;       spf=pass
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

This patchset improves KASAN reports by making them to have
call_rcu() call stack information. It is useful for programmers
to solve use-after-free or double-free memory issue.

The KASAN report was as follows(cleaned up slightly):

BUG: KASAN: use-after-free in kasan_rcu_reclaim+0x58/0x60

Freed by task 0:
 kasan_save_stack+0x24/0x50
 kasan_set_track+0x24/0x38
 kasan_set_free_info+0x18/0x20
 __kasan_slab_free+0x10c/0x170
 kasan_slab_free+0x10/0x18
 kfree+0x98/0x270
 kasan_rcu_reclaim+0x1c/0x60

Last call_rcu():
 kasan_save_stack+0x24/0x50
 kasan_record_aux_stack+0xbc/0xd0
 call_rcu+0x8c/0x580
 kasan_rcu_uaf+0xf4/0xf8

Generic KASAN will record the last two call_rcu() call stacks and
print up to 2 call_rcu() call stacks in KASAN report. it is only
suitable for generic KASAN.

This feature considers the size of struct kasan_alloc_meta and
kasan_free_meta, we try to optimize the structure layout and size
, lets it get better memory consumption.

[1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
[2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ

Changes since v1:
- remove new config option, default enable it in generic KASAN
- test this feature in SLAB/SLUB, it is pass.
- modify macro to be more clearly
- modify documentation

Changes since v2:
- change recording from first/last to the last two call stacks
- move free track into kasan free meta
- init slab_free_meta on object slot creation
- modify documentation

Changes since v3:
- change variable name to be more clearly
- remove the redundant condition
- remove init free meta-data and increasing object condition

Changes since v4:
- add a macro KASAN_KMALLOC_FREETRACK in order to check whether
  print free stack
- change printing message
- remove descriptions in Kocong.kasan

Changes since v5:
- reuse print_stack() in print_track()

Changes since v6:
- fix typo
- renamed the variable name in testcase

Walter Wu (4):
rcu: kasan: record and print call_rcu() call stack
kasan: record and print the free track
kasan: add tests for call_rcu stack recording
kasan: update documentation for generic kasan

Documentation/dev-tools/kasan.rst |  3 +++
include/linux/kasan.h             |  2 ++
kernel/rcu/tree.c                 |  2 ++
lib/test_kasan.c                  | 30 ++++++++++++++++++++++++++++++
mm/kasan/common.c                 | 26 ++++----------------------
mm/kasan/generic.c                | 43 +++++++++++++++++++++++++++++++++++++++++++
mm/kasan/generic_report.c         |  1 +
mm/kasan/kasan.h                  | 23 +++++++++++++++++++++--
mm/kasan/quarantine.c             |  1 +
mm/kasan/report.c                 | 54 +++++++++++++++++++++++++++---------------------------
mm/kasan/tags.c                   | 37 +++++++++++++++++++++++++++++++++++++
11 files changed, 171 insertions(+), 51 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200601050847.1096-1-walter-zh.wu%40mediatek.com.
