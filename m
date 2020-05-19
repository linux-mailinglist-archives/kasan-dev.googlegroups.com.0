Return-Path: <kasan-dev+bncBDGPTM5BQUDRBJEGRX3AKGQEQSI42HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 743811D8D8A
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 04:23:33 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id v17sf9231915qtp.15
        for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 19:23:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589855012; cv=pass;
        d=google.com; s=arc-20160816;
        b=YoealslnTS8hPBcBjVeUTDz6ACmeONVUsKzLukP/q3RzpEuA4COZ8e/PSxUYFctcbB
         lP99IIB2n1+ytPcTi1IfxQ1JO0C87/FAyNSRFWPy5rMx4lMC+9LWHZGNsnTD7RMohlHt
         IsxbBCSZr4nKGSWX3eqRPghUYm714Qe0XFYNdDySGJnXa2s3Bu8QGqHPea049hlL6RjG
         rCkhsmcJacOLzBOndUoVbgQgtqbrjDTyyBcNfXP2mgNTEGv54niSt3ySMoKNMjCk3o+A
         gguVO5Oehu5veT5VKW8RSEz5nP+oR3hRieadbXsmkv6Nx4WjPy55fOkVnKcdWIu67Q18
         idfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=NujO9ltWalDwkBN065Jr7qOULxYF2QItXIazPUk/rAE=;
        b=coKMkoprcJUr8EdTlwFdluKiXX2iiFH2RNHzUhFRTJfxqtmfan2s/OeaBv75xl+93M
         5iHnS/lZRGpqRXQw25E4g59EziqhP34AF5ui29yxf7uJDbj3amdDMVTM6gZCVNK3LLGR
         DwmXYIJCeQREwd9UFN+A3jOStzuaZykFnXEYBAKxFFNLAGdQWKjSLoYZ4ZolUg1na3zT
         ahVmFZX++9cBLHcIdqsdaovag34gsXbgtnw0zZFa9FteKQdNRpbgUoHNFviddvfkoaz8
         4rlCXAwYKt36Nr7ekIB7hEPvEsNxKXD7lnD5a8cePc2n42Mr8AA825Iwsz6VZ8vPf6pC
         wqYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=bo4ndfY0;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NujO9ltWalDwkBN065Jr7qOULxYF2QItXIazPUk/rAE=;
        b=VfWoesRQ6LhkKbeNPFXw1vFcJDWrRI0nteuoYCeeCD0jSPWW944I3/Ph4Za6s2HL8s
         OUVqeDIY8ufxD8MLRdZ55HVq7g3ExPZdvG/aimytoxuqejphqwlAas7Qb4MK7Pmxn1OG
         Xg9L4C6dVQTfZCRbliRw2EBcJ7EYnhqYTcRXSPKRdh+9MfGm6KMg5RBQnbN4XlKmQ+2V
         UKcs2XwPKxF4GIrtQzu/1rsjsdDzWdGe5TAhvyHsKiWUIlZGom3QZoVj8BjGcbPVf2VA
         iDWvJnsHF/8GOu60Cm1V4LMrcO7kk4N7GNrFuc1a+fwZ4GLFiwVBVjuyyjA0i7S6Jlv4
         zYog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NujO9ltWalDwkBN065Jr7qOULxYF2QItXIazPUk/rAE=;
        b=GtgCdkNfkOgPifOq09AkiMzieCxNjjBmgC4Cj4a6mvAM9B5Dm/eU5YiEP2zcjrc6BV
         vigVQ4WSS61PPrbQeBzzYVsYoI8a8CcPtshabqo9ODXhcOPPMFzbYX/MO/a4OJmIORGT
         6JS8bFo2x7W0gNNCqJQLoEYG82coX5mSQr3MkZ+ZdPE6wOG6D/KkGKPHv8wfpjyWq9Hx
         jtWCj3WzkKogHhhauDLfC9v9UpptmwkIARTQrg0Hwo9KXemk+hBF0yiSdLjr/uubie93
         uo5qMlcnEnkM29kxlUhNg2AHR/olCxYjuuLSZ8zy4BGcFlkjQmgowO2DCsVVxJeDwnei
         hSIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532rmA6mNRP14y54lIsuMv2i3eeUmHfioIwigtcekYh0YD8rHhHf
	PomMinbqDxOPCREY5jnU30g=
X-Google-Smtp-Source: ABdhPJytSupTG7jvKndhsalPNYaUnjsGSydqCY6Mbp6YOSOS3g69NlehJ4R7owurHnleVCEbozw3Mw==
X-Received: by 2002:ac8:5045:: with SMTP id h5mr18737297qtm.259.1589855012518;
        Mon, 18 May 2020 19:23:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5584:: with SMTP id e4ls2716771qvx.3.gmail; Mon, 18 May
 2020 19:23:32 -0700 (PDT)
X-Received: by 2002:ad4:5553:: with SMTP id v19mr18434186qvy.77.1589855012100;
        Mon, 18 May 2020 19:23:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589855012; cv=none;
        d=google.com; s=arc-20160816;
        b=DT4IqMeB/24ga5qOSR1mhjxZQZWFeJt8/p/a2OJmMjLQ4/KqWguM7ECzZX1IUQo9ME
         tEVANMB9nsZjhrVC4CAK33LTi4NQ7SpOKc7EYB+rMqy2H7ST7mAefRlfhDrNmXXaVe/Q
         3I+/gieGUK9vVzRt8BJw4qGQ1935kJ5S1402/p9SAWBepsohkab+SRgCRhTfSWTdyj+M
         1mJh5b5sXlqLLFZ6iZHR9y+yoqFABjwQg3BSsZRY2IrF7s0J3pUivgLe2Ur+LXD7Ww8z
         RR96g5flWMMqTK9OHt2YaxAsnLUr7E5pVsiHbxCB0OydkeSnbXWoXicFT/hCZe5uuaQZ
         3o4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=pahJ2L0gjM1kDa0csOJAjHWKOME8knEXrsVPb3ccsfw=;
        b=g1N4ozBvQTsoE/joOlHW+xwPbh2QnIFzvJadSHBxQh7jTunqPMQG+2TbPsvrqM5hDY
         1ZxdvhgS6aNR7HG1oRlSXs0AugeZ0a1Sd4VVtqpeucYsm/3pBHQhQ163YrzbReBoUFud
         bUsOP+qOe2UpkO19rKpWkSrf8s7mBUbbB2pULbUKfaEkZ1YXAns2GtQT9PDBJtcjSObl
         cBOiQijNdQVHMhA0WsZ+aksB3BWYBKbucvKkHHPI8So9ZaPpO2YCSeRQCdn6E/dc66D0
         r3MUsn8UDNxaMYcO37YJOorWz4VV32yd72Dmezzy4XOQovYrZvODD6WMaZ1VoNwOv40k
         Sz8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=bo4ndfY0;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id g126si738307qkb.0.2020.05.18.19.23.30
        for <kasan-dev@googlegroups.com>;
        Mon, 18 May 2020 19:23:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 1287ad98d3fb47f4bb82707ef0185cdb-20200519
X-UUID: 1287ad98d3fb47f4bb82707ef0185cdb-20200519
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1620647460; Tue, 19 May 2020 10:23:25 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 19 May 2020 10:23:24 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 19 May 2020 10:23:24 +0800
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
Subject: [PATCH v4 0/4] kasan: memorize and print call_rcu stack
Date: Tue, 19 May 2020 10:23:22 +0800
Message-ID: <20200519022322.24053-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=bo4ndfY0;       spf=pass
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

Walter Wu (4):
rcu/kasan: record and print call_rcu() call stack
kasan: record and print the free track
kasan: add tests for call_rcu stack recording
kasan: update documentation for generic kasan

Documentation/dev-tools/kasan.rst |  3 +++
include/linux/kasan.h             |  2 ++
kernel/rcu/tree.c                 |  2 ++
lib/Kconfig.kasan                 |  2 ++
lib/test_kasan.c                  | 30 ++++++++++++++++++++++++++++++
mm/kasan/common.c                 | 26 ++++----------------------
mm/kasan/generic.c                | 37 +++++++++++++++++++++++++++++++++++++
mm/kasan/kasan.h                  | 17 +++++++++++++++++
mm/kasan/report.c                 | 36 ++++++++++++++++++++----------------
mm/kasan/tags.c                   | 37 +++++++++++++++++++++++++++++++++++++
10 files changed, 154 insertions(+), 38 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200519022322.24053-1-walter-zh.wu%40mediatek.com.
