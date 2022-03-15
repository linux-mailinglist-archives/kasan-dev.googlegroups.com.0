Return-Path: <kasan-dev+bncBCN7B3VUS4CRBE5MYGIQMGQE2RO4OCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 83FC14D96FB
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Mar 2022 10:02:12 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id 207-20020a3703d8000000b0067b14f0844dsf13762726qkd.22
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Mar 2022 02:02:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1647334931; cv=pass;
        d=google.com; s=arc-20160816;
        b=JDw+w3Q3ClXhd1I/m0Ee2DJiE5o9dRKDTmUJeVlPRLNcEhg/iNza7OzkNe+E6PMvNj
         2XpHqn1RAqC0sfr1q4emUwPly1CejNq4ahj1GJbdu7wFXjjfrenAbxsv0pc/U69G+h96
         WQUbAdPaCXWpXxXi4L/zgmT2i0ggiVypq1rLXMR+AH83gnm2Gj+bbsZ9vjizE3fz/dtU
         co8JuzS1yDBJ8QqOXeX8eKXIY+AnwEvoQt81T6H6gOn05LMZDlhs3MGGU5q56k13LKJg
         Y3Gm2PKTR91VIrKNvn5rd7sw0Db+ihfrikqspcTiJhMfBZlh0qU4hVASJASRpkRmlgTY
         GAMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=DIkQZ1H3fyMQFEe2lFmLfBuZeZKW5h7U51kFfH65Yxk=;
        b=r4UT0A4vj7CNbQigker0O7R6WQ1IWpFKabxlcyJZ6D+BadeW32uilFdXLUjbeJty0m
         gfTPnD18hhds89tfR0N4sRio9Yq/OCPXTHW0QsItQwNajG/m1vSQ4ytp6lJhUeCmZYJr
         5oyTF7wz+RyCpwSh1CgSy10mI3E9pz7KPUiREyaYiPsXjMdHBUkt6WSo7TrTJpFcBuMI
         aDGQvDvGQZzC4pNPCxUYfY0YWSG+0r8RJh181bg3njPhwXs4fCLKUj5Qu+nDkSnPtwC9
         aGNvi/lX6aks9M6UyfTZOvqJCIE6ca+qpc/PKD3PrvSolnMKxQj5sj14gFZhIDq8Xell
         tsJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=DIkQZ1H3fyMQFEe2lFmLfBuZeZKW5h7U51kFfH65Yxk=;
        b=CQ+0F8gk8lZSrAUb/8g2H5mFx+/eOb2hvHk6G8H75Ya4iJlWFnMADu26mQ23G5h5Nr
         el50IANFFR2gCHcFHkGZuQgqZ+c17jwW+fdadxLZi4CSz/T/mLXaLgFVSIcWkehkAux9
         tivCc3GxJOmwpfpsevyqO2kWh+tU6YRzarBCftPqq0Ep05/P2BZR5OfjOVeHfRAnkPAJ
         mjkornkhO9atSwIELy3EB2B+/B+HWSd6cdqtkKya0XWuBljQlWthmHRMLee68YU8R0Pn
         Im6lXUqVKNiy/czaf0w1jHr9CZv9wGRpExmc/vv0bd80LAiZQd2dCJcUtvqHcWZ/Sy32
         OBoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DIkQZ1H3fyMQFEe2lFmLfBuZeZKW5h7U51kFfH65Yxk=;
        b=FrTE/C5MZLE/kqRqNx9k0KoXnn7hZIpUWMn9FMEg4e/QtNQCw2RRiHMkkdkZaFhBJz
         U0IMuQYqAwxbgWXUYOQ/Lc9R8aE6dYo8NTTmOxQYUh86uukTvizMIVyc8bOAQirE7wjr
         tiSsiSZltSuadtqJl1EYPeFbD5xOVeFsgQ+XB2hIYsx6F7aYTpBNMLpVLVyzS0gu6aPj
         1umWlTAYQGf9Woh46QCB+VAUaaYzmBEfto2AOM9CtjnTxhrGua5AM4uN3i6pwwlgxTa0
         eG6ODvVv+CCxKjrCyGdUye4iLWGQxHGyHoXrHxk6MFk3vnRpu5JqLDjC/+HuV9sdgnOE
         6URg==
X-Gm-Message-State: AOAM530L+NbDBdj/2WgfLksfBmle551eFoUM3aI5TlkBF3WhD4IpTbel
	TuUv9/EDDrSas5u5ZUJigdU=
X-Google-Smtp-Source: ABdhPJwTEJ3S8ZEPcgsyWnlZ30E/Q2jbEZ8KR3N0U3+LOC9qcEOzc/bhXqJHDK7cZbJ0X46kD8fLtg==
X-Received: by 2002:a05:6214:1c5:b0:42c:1227:c542 with SMTP id c5-20020a05621401c500b0042c1227c542mr20949501qvt.11.1647334931321;
        Tue, 15 Mar 2022 02:02:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5745:0:b0:435:33cc:9ec0 with SMTP id q5-20020ad45745000000b0043533cc9ec0ls4932720qvx.6.gmail;
 Tue, 15 Mar 2022 02:02:10 -0700 (PDT)
X-Received: by 2002:ad4:5c6a:0:b0:440:c74a:20e with SMTP id i10-20020ad45c6a000000b00440c74a020emr1249288qvh.129.1647334930772;
        Tue, 15 Mar 2022 02:02:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1647334930; cv=none;
        d=google.com; s=arc-20160816;
        b=R2e0G5gscfentN848YnulahYulBkLtILcOg+Edo8MIlv0aWAb8AYPv9E58RqwwVyok
         5oVfbeh/bQDKGD5o/JlfTFYfq5wmPptizBufjFctjH/mkvVgkFv4zGIufwwWa4YYPzr7
         iD2yj6ToH6uULqBQTTNYcTPzEBzh1xHSxuSdEdXOr4NZNTQA8q/cLyHBWo0KLtfdZWJp
         mcc7Tir8PtYroUcbAOlLKr15ZMHDKMuI+XxHucen7Y5uk7m79a/oIwpDNS9tWt1YoOY/
         k8hivEYt6XrYvkzQvkZHa/A4ISssy7PK7AhdWwVUH6xTTT5fyRu+vgLqo9BNrm0DAGo5
         rREw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=IqmS0UfL+pq7UoP4HCaZEH1BRTsnBL3JU+RVP8Ofs98=;
        b=oM9155CxPeotCRPcebQBuePBredurwn3jWGZbLS3QP+SAf0LBlyY3C987wEpIO1UyU
         ffXB4OphArNO9WVd5Lwu1WiZ267Zzaip9h/4Kk574YMWQydNhDP3ZVWmnK2xFsQ+6zkQ
         gESO0P1oKFtf24Bpt6zPRDyZqUwvsNYyx6Nytbt6wH8A3cGl5pKCvmDHGfKxanMa6cb4
         Xr/y2e/GPHLHk5D4vHOtKqx9y/ZoT/jMMVdqRbVUZTXwJa2qCstC1DjQ69L0aPT2M7+l
         fx3GGVnqxrW6ip0ojVJ6zl/IrA+RXHOHcxXqhzrtFBmBzZqIXGYXEPye6nV0MLGx5exv
         HS6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id x18-20020ac87012000000b002e1b3636527si750759qtm.4.2022.03.15.02.02.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 15 Mar 2022 02:02:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 54457aaeeeae4d3aad0dffd452a40eb0-20220315
X-UUID: 54457aaeeeae4d3aad0dffd452a40eb0-20220315
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 914556803; Tue, 15 Mar 2022 17:02:04 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 15 Mar 2022 17:02:02 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 15 Mar 2022 17:02:02 +0800
From: "'Lecopzer Chen' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-kernel@vger.kernel.org>, <linux@armlinux.org.uk>
CC: <lecopzer.chen@mediatek.com>, <andreyknvl@gmail.com>,
	<anshuman.khandual@arm.com>, <ardb@kernel.org>, <arnd@arndb.de>,
	<dvyukov@google.com>, <geert+renesas@glider.be>, <glider@google.com>,
	<kasan-dev@googlegroups.com>, <linus.walleij@linaro.org>,
	<linux-arm-kernel@lists.infradead.org>, <lukas.bulwahn@gmail.com>,
	<mark.rutland@arm.com>, <masahiroy@kernel.org>, <matthias.bgg@gmail.com>,
	<rmk+kernel@armlinux.org.uk>, <ryabinin.a.a@gmail.com>,
	<yj.chiang@mediatek.com>
Subject: [PATCH v4 0/2] arm: kasan: support CONFIG_KASAN_VMALLOC
Date: Tue, 15 Mar 2022 17:01:55 +0800
Message-ID: <20220315090157.27001-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Lecopzer Chen <lecopzer.chen@mediatek.com>
Reply-To: Lecopzer Chen <lecopzer.chen@mediatek.com>
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


Since the framework of KASAN_VMALLOC is well-developed,
It's easy to support for ARM that simply not to map shadow of VMALLOC
area on kasan_init.

Since the virtual address of vmalloc for Arm is also between
MODULE_VADDR and 0x100000000 (ZONE_HIGHMEM), which means the shadow
address has already included between KASAN_SHADOW_START and
KASAN_SHADOW_END.
Thus we need to change nothing for memory map of Arm.

This can fix ARM_MODULE_PLTS with KASan, support KASan for higmem
and support CONFIG_VMAP_STACK with KASan.
    

Test on
1. Qemu with memory 2G and vmalloc=500M for 3G/1G mapping.
2. Qemu with memory 2G and vmalloc=500M for 3G/1G mapping + LPAE.
3. Qemu with memory 2G and vmalloc=500M for 2G/2G mapping.

v4:
    rebase on 5.17-rc8.
    remove simple doc for "arm: kasan: support CONFIG_KASAN_VMALLOC"
    rewrite the description for VMAP_STACK

v3:
    rebase on 5.17-rc5.
    Add simple doc for "arm: kasan: support CONFIG_KASAN_VMALLOC"
    Tweak commit message.

https://lore.kernel.org/lkml/20220227134726.27584-1-lecopzer.chen@mediatek.com/

v2:
    rebase on 5.17-rc3


Lecopzer Chen (2):
  arm: kasan: support CONFIG_KASAN_VMALLOC
  arm: kconfig: fix MODULE_PLTS for KASAN with KASAN_VMALLOC

 arch/arm/Kconfig         | 2 ++
 arch/arm/mm/kasan_init.c | 6 +++++-
 2 files changed, 7 insertions(+), 1 deletion(-)

-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220315090157.27001-1-lecopzer.chen%40mediatek.com.
