Return-Path: <kasan-dev+bncBDGPTM5BQUDRBRMRZH2QKGQEAQHUBBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E9E571C6757
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 07:19:02 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id l4sf449059oog.15
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 22:19:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588742341; cv=pass;
        d=google.com; s=arc-20160816;
        b=YIUhvCk4KI+29a+wXfBDy4VwcQ7t12vHmIpOHnUn/QCErwLrd6wsCETW5KylIrqrF2
         5kZgzi9N+ninpPWkGHw2npWcb3f3wJ5e7AeLdng/AjnrRHWpVTgvOwW3PKRtbBK6YUed
         njlMkeIDs3WxnpbpJtpYvLD5eN3IGEKhPI0llaucezC72El3SGFa0GQokQwPa6+bRWyC
         oKcgPgPpTu2GejnBOoQtezu8W993d5Geg9QTly9+2MH2MFN4wkJfu3K4SxHCwX/rERp8
         ns3IJOuPfT5811lIbj1vKdvojrokMSBeSk8FbwnB18Cs7r801tuFN130Z5kh30LHyXDJ
         P7qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=co3cJSIxhWIf0cmOpEXaId1XCn+MDu4gtbvyehmX8J4=;
        b=qkhWT2QdBRTOwAWI6615Fro4rwUJ3gAWnYcHKHlu3B811KWoZZ/8R3WSmS8PAivEdh
         udLUdQhA80U2df9NWQy42fxYZIZLk8JISL827w87QKFVhgv4xxgKX12E0Xa8U9bqRwU2
         E4kY+Fw3cSEeBETjkwU/L3MBpQXNDNF6xI+3XeG/SkURbYXvkksg8DuV0bz2qoXsdb6N
         JxE1Ytt0ut0rH7sEIuGsUVptRBEiL6lIQtNWFB88nvS3XcHwzpT74PPUUBkRIy0NQeCK
         VGzTWeL7gH4YBvpxkfaDozCR2jWikedsVHnPe/ct/VFEDkwQznIFp0qW7DhcrMi5F6X2
         7kpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=cfZMNlqW;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=co3cJSIxhWIf0cmOpEXaId1XCn+MDu4gtbvyehmX8J4=;
        b=TdGohOL9CG2+tVa9lmNtegvosSW4r2lThH99M9BsiqNtk4Xnxi3kUxj3MyIZ2+Cgs9
         SHmjtcyQZ/eVsh05aPjsm3j5ym4mPP+sfpK+YcJmv0RiRRDc129nt3+J1orpKnF0meAx
         QE4Skl4smotZUsF2EwgNxV82aG43TRUZZrJN7AEqKpNJQiZym4LLSdZLnF6LXlpt+yDI
         hGOG0V4lB29UwfYt1RcHYv0ant7KCm46s43jE14iCrCg65Yd18eeKbJwN6PYhGbUBkUk
         rPwZd45WJA3gBmcFYqxjmJxootybrUd/V7FFi1tKi7z4HZgAo5TbyIUFZspBFInJE/1l
         YpWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=co3cJSIxhWIf0cmOpEXaId1XCn+MDu4gtbvyehmX8J4=;
        b=tz4nKe/SHwzx8hODNPClJFghxzEXYA9DL2td4XEy4xoo7DhD/bkszjuHFSki9/sXsW
         V9T8//5saAS/ZAqxdnAmRdakV3hNcdzecV3bPVVPsJ1PDRi7IiQBJ7ipqHyYI0WJLW3u
         sU+SWZzvPD25qOxC9/i3Vsl6crjzOvHxKpi+l9G+krSHpuQsBxM0fMxyoCpcbSla2lBu
         r3UH4NwI9YQjKLhBu7gPHB6Rnu9QpCWhycPgvzqeCJkR3XpOSfXDWaUjsikaTObEV7rM
         6Ujy2us5flJSECFzxiUIzAjWDcutBIX3GZ0rKg5p/UhM73gmJtbjBNod+keKqfEbyiJM
         gNqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZzrJowBCii79H+MRaHOy7lVpZ+nuyL2C2atmONTGQ46ouqMHKx
	yJ3bSGXK7thpNDlq5mujQ3U=
X-Google-Smtp-Source: APiQypJljJ+BBqTWguuPQzyEgAzlBR4sVJgQ+4jZg3fLRdABgtXpZkhswcv5n6qJUjbSG3kSP2lJ7w==
X-Received: by 2002:aca:5008:: with SMTP id e8mr1467598oib.140.1588742341556;
        Tue, 05 May 2020 22:19:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c648:: with SMTP id w69ls253486oif.7.gmail; Tue, 05 May
 2020 22:19:01 -0700 (PDT)
X-Received: by 2002:a54:4396:: with SMTP id u22mr442210oiv.154.1588742341273;
        Tue, 05 May 2020 22:19:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588742341; cv=none;
        d=google.com; s=arc-20160816;
        b=VI10mIT6feQgqknYTKZ3PojTLXC7Ar0GHwBFaOTtYKLNx/TlnxUZKEsqF+BSX10/jA
         EWIvVp476GgCSa0UuyP6t0qgPsl0SgfCr6BSQLNSpDj82lW5li2BeH6aa1PF7cPVEvuT
         IEt9/QTtjKsUo5RL0fbnc/uT92qRpDltFKcPkufEiMwX97HuplxKKfxRHZtPZ524DUTq
         qxZ8r1PrNfkzZbAdvHn1eAp75CWLtnS2/pFFCEnweCz6sKRCRC7YDodGB52CyEgW8WHT
         FPrxhSN1IpP+tEEelaUKV4xNtI2YZaLGhK0FYS3d8r24qR1fvf/fcCbSQfYYMptcLkcq
         5EKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=uJZg8sC2cd+BcgzYcwDrLwJbXHxd7+JuJtTz708pa/0=;
        b=n9aSWkH+nQGjQYyUJBsVd5VzwAk3E+vDUlEFf6g9IFPjWDbWj7a4qp4KvOrYP3ZWkE
         gqDoZpRGPsgvqXHrut0jI/FH4LhrZJZxlKObiRgyzOhLiMjtmacv7ncSmmON/b4hF94f
         egQCpRZapyO6jK7eCZYEPEzokeupkE/SdPHSrirJObCNTVuSvHcnLf1KuOFnRMX6karV
         Vt+PxUHUA9ZjLKSIFZvaxOFSUSbZzop1adGP2TPSeLQsJMCbpmSqzpzHaRrAvYjHlA4V
         EQRjWJIYNDT9TQ4SqrdXA5upnU88NWp7w3rC7wPrtBbT/ugVEL7e2XvcDoeosBHQRCm7
         dYPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=cfZMNlqW;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id s69si71259oih.3.2020.05.05.22.19.00
        for <kasan-dev@googlegroups.com>;
        Tue, 05 May 2020 22:19:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 86d09f1015a844cb9f53b78527a4df92-20200506
X-UUID: 86d09f1015a844cb9f53b78527a4df92-20200506
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1650363527; Wed, 06 May 2020 13:18:57 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 6 May 2020 13:18:55 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 6 May 2020 13:18:54 +0800
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
Subject: [PATCH 0/3] kasan: memorize and print call_rcu stack
Date: Wed, 6 May 2020 13:18:53 +0800
Message-ID: <20200506051853.14380-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=cfZMNlqW;       spf=pass
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
call_rcu() call stack information. It is helpful for programmers
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


Add new CONFIG option to record first and last call_rcu() call stack
and KASAN report prints two call_rcu() call stack.

This option doesn't increase the cost of memory consumption. It is
only suitable for generic KASAN.

[1]https://bugzilla.kernel.org/show_bug.cgi?id=198437

Walter Wu (3):
rcu/kasan: record and print call_rcu() call stack
kasan: record and print the free track
kasan: add KASAN_RCU_STACK_RECORD documentation

Documentation/dev-tools/kasan.rst | 21 +++++++++++++++++++++
include/linux/kasan.h             |  7 +++++++
kernel/rcu/tree.c                 |  5 +++++
lib/Kconfig.kasan                 | 11 +++++++++++
mm/kasan/common.c                 | 31 +++++++++++++++++++++++++++++++
mm/kasan/kasan.h                  | 12 ++++++++++++
mm/kasan/report.c                 | 53 ++++++++++++++++++++++++++++++++++++++++++++++-------
7 files changed, 133 insertions(+), 7 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200506051853.14380-1-walter-zh.wu%40mediatek.com.
