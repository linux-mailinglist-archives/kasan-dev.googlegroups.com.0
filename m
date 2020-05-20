Return-Path: <kasan-dev+bncBDGPTM5BQUDRB7WGST3AKGQE62K74EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 158461DB350
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 14:33:04 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id o89sf2693399pjo.3
        for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 05:33:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589977982; cv=pass;
        d=google.com; s=arc-20160816;
        b=lpTK3V09qNHj7F/0HFP5OQNM93Z/yF7UtvtQyZYTBEtGKrt+3EKQCm6zlkGaz0D7N6
         M0x4UJAl93wSSKtrExGMoCwhfne2b3DxnIUQl5ygvmEOWyBMy6SWZD0WcNLE+xwehF8B
         zUqsWjxVvtgdqNG4qFoQRbI5cs26SiBBKSaYDgkvQoRs2Gb36gT9VTGyFkcm8mOLqlb6
         r8iaFfnbOerK6/C+lux7tXze4jeaYVXMEH0g7/IQR/A7Uao8NABZ1x2h8VRwuz+HNSOq
         RZ5MHg9ala1/KfGSW8icMB9eY1EW/btgi8VfQlRkuUTjwXBu6UxXbMb4XDpaFE2UyBoY
         bnPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=1F6ZrfA/YQkxahmuGF1dNl1dNj15nLGevyG9OAyywmo=;
        b=wSwAdtOdu9+z0TfIszA8VQXCtIMj7i4rQmYp9axTUiMBwz8XL8PU5IasIRqQ8fmgES
         7GGpe6tzUVGlruV6pk96leh1ltfeKjUReyMvPkj5IwAJKrO69nqXaEcoc4QGCT+c/0PY
         emniiSPaAI9jiABz2H1qDTYCsiXW1zwVHs+gbWjlayQVdTp/YkI5ZzQPPiQZ9F3/Ss29
         a9bZUSLcyAYSJg8qeqrTmGbxaSrlk2s/ovrPWZkAb0X16KoQssUiu3AlnUXkObmjy5fd
         RLsLDgXt0TdNfaRiA58SXKja90dCvD99eLeuVhZIlnF7UgJoRN7HNbYHAEyepA6ngPCv
         oXfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=kbDEy74i;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1F6ZrfA/YQkxahmuGF1dNl1dNj15nLGevyG9OAyywmo=;
        b=JM2k8kfnzjNP4hOyLABVCcYxpRWSJpe8U8KSEWusdkYpCSs5p6Aiv9y7FBsAlkTMch
         pKpsC2u7RfG+wErTgzj83xOeR3zz5QA4jfTpF+4jd3TytRYbqRWb2IfIDT4vhWmQmEct
         zKk/QZyTR+aO8RUhfcjcXSqOBZ01vwFjjvg/4BY10i7jRElC+T+hzpYZu2WmKBjoVVxD
         YmohgHEM7+QR3DQ2VstaHtlbL6jddHZ/AYtiynA67e0ogRPMEgz+hq9buFJaxfgw0J5c
         fyYbwb9IzjMSSMo+aAw8xin4wJALL229OkY8inaugkI6QDxMScIzIdtkPxY90rZ608pw
         vpXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1F6ZrfA/YQkxahmuGF1dNl1dNj15nLGevyG9OAyywmo=;
        b=kWRw5yMBzMzHKSB0CDne8df9NotT7MX48vWPLOj7HhhJ1xqha1QLhCnF8nqR17igNT
         H4C5Sc7j3h4DE2WBKZsTPQJpiy5DeVoDMYzcpFmDGaIQiGdNvEfHoxPhRe7qek5xl+P3
         vvM7oovrX8UW/7gfwgEklA6x1TWrdpRJSY7jwqrwE0mscNUZZ0xBDxWhAeIAyLYBwyz3
         9NvM4015JXqsIwBRdWofauwnHvW5vBOqsI8RkJ+9Iza5lvxmVNNBxGXEJPt5ypiEcYCS
         2u547AMHoezHM5KiQt1SNBBLY4qp6V7iuD3TAPRg/COJbpNCnVFShdl84TF4Ma203OVm
         gwhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532mx8xYakbYHWez5fe3B2htxyV+epiLRrldmZXNo1bqg7KGlDMt
	1Qz/JHC20wbHk+SCihO1zgc=
X-Google-Smtp-Source: ABdhPJwhvzpnvgH0jm6kl4qypsKw6lfc0gwQj169Ps7j2tXcCbkTke0Zv/Hex1dTMPdlWsSxEpyL7A==
X-Received: by 2002:a63:d547:: with SMTP id v7mr3843368pgi.413.1589977982719;
        Wed, 20 May 2020 05:33:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5457:: with SMTP id e23ls855171pgm.4.gmail; Wed, 20 May
 2020 05:33:02 -0700 (PDT)
X-Received: by 2002:a63:c601:: with SMTP id w1mr4019197pgg.263.1589977982271;
        Wed, 20 May 2020 05:33:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589977982; cv=none;
        d=google.com; s=arc-20160816;
        b=V5uCVzL4AMyor4SIWo3ogJjfkSthmwon7nnA7OHdrXHaFD+YRhWwBPAR2dB8G5r9sH
         nNZGYbgcyH7fCMS8u47Pid/wDGLIQKZ+axI6Q8Qsvc+HvxN7aJbEyqIYCcZ83ZDAp0ef
         Bq6zibwyoopv28iIePq9KPuGfdQoWWMrpplcS3RsoaRiAYNUqjWfGEAlhGxb0GCK03XX
         vZqL2Q+6XG1jljWQy+fT/YXHL0oMwjB/WrCQyw7HBkYC3eLogH+tXayv6fCI5hYWsmff
         B0MUKcDrN13O2uUPvmnLzGN9lqxuMQYYvMWZFtimrQkgWX4UGtIzt6oM8zT8H4dwlu3Y
         TIOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=BeLeJJH5ofgcw6vUjWiYK26OxvqDsbWroYEUdxA+t8A=;
        b=mwjVAvrqZOMuPXMk8b9UOAGeRfAMfREuPs/LKZ3OghLTsOmEWLxfvnOL1sh8Kj71MH
         EQg2uApH0qyBf88J10NxEnNt2e82mHTOVxS8zjlHAvgAvrMZFv3VlybJUWSQMXKtIuzt
         Hfh2jY9mOd4+D7YRwoW1QerguK/ZRwZ0lipW8ipSNYQKns1ll1eNz7azK+uPb5e5JiJS
         tvhB7O7i9olbdNlq8uvx3nnWQlWLC2Oqc0Db9ikXJ5LtgrQI67tQ1SGH7KaYv4jvgVVn
         U7tx95KmmXIvD2DjIojowcMG/9Qkuy3SMVWfxrU7GX2w9OIrCX1/CZT08bdyKBSk9IYH
         WEEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=kbDEy74i;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id e17si175328pjp.3.2020.05.20.05.33.01
        for <kasan-dev@googlegroups.com>;
        Wed, 20 May 2020 05:33:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 6e711db97bcf455184bca1c019ad3e79-20200520
X-UUID: 6e711db97bcf455184bca1c019ad3e79-20200520
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 185924271; Wed, 20 May 2020 20:32:58 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs06n2.mediatek.inc (172.21.101.130) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 20 May 2020 20:32:55 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 20 May 2020 20:32:55 +0800
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
Subject: [PATCH v5 0/4] kasan: memorize and print call_rcu stack
Date: Wed, 20 May 2020 20:32:55 +0800
Message-ID: <20200520123255.3839-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: DF741B473EA238CE2AE57D1C416BCAEDDD57C2833C3B4D2DA18BAD5A08D8623E2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=kbDEy74i;       spf=pass
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
 kasan_save_stack+0x24/0x50
 kasan_set_track+0x24/0x38
 kasan_set_free_info+0x18/0x20
 __kasan_slab_free+0x10c/0x170
 kasan_slab_free+0x10/0x18
 kfree+0x98/0x270
 kasan_rcu_reclaim+0x1c/0x60

Last one call_rcu() call stack:
 kasan_save_stack+0x24/0x50
 kasan_record_aux_stack+0xbc/0xd0
 call_rcu+0x8c/0x580
 kasan_rcu_uaf+0xf4/0xf8

Generic KASAN will record the last two call_rcu() call stacks and
print up to 2 call_rcu() call stacks in KASAN report. it is only
suitable for generic KASAN.

This feature considers the size of struct kasan_alloc_meta and
kasan_free_meta, we try to optimize the structure layout and size
, let it get better memory consumption.

[1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
[2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ

Changes since v2:
- remove new config option, default enable it in generic KASAN
- test this feature in SLAB/SLUB, it is pass.
- modify macro to be more clearly
- modify documentation

Changes since v3:
- change recording from first/last to the last two call stacks
- move free track into kasan free meta
- init slab_free_meta on object slot creation
- modify documentation

Changes since v4:
- change variable name to be more clearly
- remove the redundant condition
- remove init free meta-data and increasing object condition

Changes since v5:
- add a macro KASAN_KMALLOC_FREETRACK in order to check whether
  print free stack
- change printing message
- remove descriptions in Kocong.kasan

Walter Wu (4):
rcu/kasan: record and print call_rcu() call stack
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
mm/kasan/report.c                 | 50 ++++++++++++++++++++++++++++----------------------
mm/kasan/tags.c                   | 37 +++++++++++++++++++++++++++++++++++++
11 files changed, 172 insertions(+), 46 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200520123255.3839-1-walter-zh.wu%40mediatek.com.
