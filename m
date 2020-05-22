Return-Path: <kasan-dev+bncBDGPTM5BQUDRBNXDTT3AKGQEBN7UQ3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CBB21DDCD7
	for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 03:58:16 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id a69sf7559674pje.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 18:58:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590112694; cv=pass;
        d=google.com; s=arc-20160816;
        b=btQiOqdt0nYlSKVF87UbjC6QrZvZecrQuwlbgVxc6dM1cpqL5fy3gQgsYe0JahkXpS
         Chmt6SCfIQ1uQAOV99yFF3R1ZxeVwioxZb2OoONNWDInRWwfE30T9Pp3/be0PmcNS1nT
         nH8Kdd8cC1EHL3f+kgafccOHEqNDDXZfTPP74F7Mw2Y18PxTKDdtrYUMvbvcOvL4QLa/
         OjTLJ5NfrrEBVtP7gRTvjM6wYl0aAD+TxVly35Hv/2m6/rS5ofoVOvq7uiGlArGDtqTC
         56Ac98SQnuAbe3UsYoHtSLBcnngBJgbFApoyLQvrzGyYCVa1Bubx/nbxETxIU4y7LMt7
         VVfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=gDMYwMu6qG3oeMmrYmzUs2z+zvRo6V/Ki4ULfEp6kNE=;
        b=OE66h+s7OkhLmj7HwSgsSpq1fedC08bF04BlWRJCdt/c2l8K9xFwue7f3o5EO6j4+R
         VAOzSmeAuGBqZZtzd3fmoWqQ+Hg3BZhRk2EBvUkqW6JU+oBI78xz1f3LEoypuPbqqoMQ
         q27Uq56+oiI4mly8DZC/keeZcaW0imwfZPjyjkEYTEca1f8/xC+uAUF/UzZVkEfBOALm
         RLFXWgq7/1PgijGZPeOAoMl5BCSJBvKU32va0NatoSnd/tMMuQ7hr7ZpmDhxFkQ7ZXvn
         tkfzpA0QkOIDibpPhKHQIVk7UseG4n/b5c+Klbj7IFvH+jdQJOnLzj0pLnwl7oCEUax3
         IRsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=cvdLQwfP;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gDMYwMu6qG3oeMmrYmzUs2z+zvRo6V/Ki4ULfEp6kNE=;
        b=h+g+SBfUVe3zyL56im5BF7Exg8elL/+JDMd3fBbQwyigciwyM80GMIZdNEAF+qrp9A
         6GcOETUK4e/Cnz4pRiIRBPcp8CdiM1tfFKoO9xHolgL4AXNVzsNTLR1taxcf2Eu6cKoJ
         mWdOMfO6QmKQ/nfO33p0KSBg5ga7mEPAL2bzF0CpHy78eZKEFutjOV3veGuVoJ1dvRW/
         X4CRs+Le9TKchbKUTXJ8fPBfbHHMA2SRymZuXVX447IRo8d8UDBUPcrd5Fig+EW1NrWT
         Xphna0KjkgWij9rpF48Y5MV9Vl7Dq99Bh6ctn1t2R4ybep6VxoO8UT00fI5q976k7w+W
         rWAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gDMYwMu6qG3oeMmrYmzUs2z+zvRo6V/Ki4ULfEp6kNE=;
        b=ibnrXc8XhtqTyVM4CLRfiCUqYxNvhjmtMtCwVwfY+km/qb5iHeGA1cTWFM6HTrbVQ8
         qC6wfSVaLXNrCzdE2cNyhw6Qo21aI7+diEyLEfOIbwnw2zniijvPcEWxQWVdFh/SyPOv
         tsRbqgo9ejbGRs2uPvwhk/5U+SW+kbAX+R90zDe5K88YR/0K5oEBbzf0nSNxbRf11yDX
         Wql2wmkcUyVgGBo2XoLzg7AXjefIE1s1x7+N/xf0bjMRMIo7vdpm6k0wvfRC7GfPhJRa
         GPc9CPxnSC2RGlMwjlW+reCLiK4qvtMrp96jZcwMfWkHdxOdUstST8UomVl4m+ez6xam
         owvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530p61Q+QUf4CePDMtfytnasHYT1FekrY+5ybqoqMjAXzwExpzAB
	8ZqyGsLmS2GzJOXgCYqpAhk=
X-Google-Smtp-Source: ABdhPJyNV6nfnr3IbRanMZ62JiJgA8MaND9JqVcDv3jlM+drtCNg6QN44LwwGCQEzeoUCKdgouaezg==
X-Received: by 2002:a63:3587:: with SMTP id c129mr11878946pga.190.1590112694482;
        Thu, 21 May 2020 18:58:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1d93:: with SMTP id d141ls145682pfd.1.gmail; Thu, 21 May
 2020 18:58:14 -0700 (PDT)
X-Received: by 2002:aa7:829a:: with SMTP id s26mr1661216pfm.40.1590112694064;
        Thu, 21 May 2020 18:58:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590112694; cv=none;
        d=google.com; s=arc-20160816;
        b=vnf34I4jJYXbKsWpRpOzK3PShOjDTgJKFQaDbD9hQMjxMyUAxRCNuedMNsOP73s2oT
         vpd9GulR6aWUReSgO1jfdBJFbJyWcMc+Tve6LphhWRRnB5EoyS0LcHDXIrubCpi5bqFu
         7ZW9DERH05GCcV/f6M+lI/y9Buwf8gY2FeJ7eMwZPOYmFJXSN/J/JiNkHFgzW08qaPVE
         Q0DzGYDolgbYXoejZ5SWfUE1OZhs5HS2hWsXMIvfcy7PwHzq76cuKQib9eUY2L4bRqjS
         bk4LY5bPfiyEtsVQqtMmzZ/FU1tEF2MMTxERUhXyr+dYt15vNyHM7UDqFP8VfKmaeXLO
         uw4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Xb9E+XZkPSEUYQhPO9o49Hp+qlF6ImWZr8Z4BQKjcUw=;
        b=n6zUzQ08Nxk3les5g3xOgn548jM2TZQ0bLhtQA95gTpN+OnbamvQsrcbUgtPfSPcd7
         Sm6pdSbWtqJNqt/FzkU7F9vw8RZvQlBTYVWh3Yf9bFH6M7TvW2bvQFVyr94YhDI75fHC
         wAAMAJrKnQMw7zkCw+3fBXBUiZm3q7fCMXtksFb5NLDEde0F+JcCz/+/PTKH9Cr0CCV/
         +DForkDCLPVxtNiDiV5sFi2dIQeAhdDpYLSW2Gp17gI6SlgMDrnYgcCwZHEYwJ/EHlO3
         M32VDNLmJw8U2U7Pe/ruqjFCgm2B54jypRl9AYDEjzq7uhqFEIdLQdd6x8y41aiUP9HR
         /o0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=cvdLQwfP;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id g6si505067pjl.1.2020.05.21.18.58.13
        for <kasan-dev@googlegroups.com>;
        Thu, 21 May 2020 18:58:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 5e4ea46496fb4a92a0a23d7d4553f0ee-20200522
X-UUID: 5e4ea46496fb4a92a0a23d7d4553f0ee-20200522
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 884651903; Fri, 22 May 2020 09:58:11 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs06n2.mediatek.inc (172.21.101.130) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Fri, 22 May 2020 09:58:07 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 22 May 2020 09:58:08 +0800
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
Subject: [PATCH v6 0/4] kasan: memorize and print call_rcu stack
Date: Fri, 22 May 2020 09:57:57 +0800
Message-ID: <20200522015757.22267-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 4A07CD0C78D35F1D1A3F7B59AA5C56C5D75035B244EFFD9341CF91B3C9B466812000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=cvdLQwfP;       spf=pass
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

Changes since v6:
- reuse print_stack() in print_track()

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
mm/kasan/report.c                 | 54 +++++++++++++++++++++++++++---------------------------
mm/kasan/tags.c                   | 37 +++++++++++++++++++++++++++++++++++++
11 files changed, 171 insertions(+), 51 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200522015757.22267-1-walter-zh.wu%40mediatek.com.
