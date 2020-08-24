Return-Path: <kasan-dev+bncBDGPTM5BQUDRB4HNRX5AKGQE2K4BIGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CF2B824F3BB
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 10:14:41 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id z2sf4999439ooi.18
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 01:14:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598256880; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pb0Mh51PL16Lki/N/Utpw/czFAEtnIdKXX91btZfyU6fNOdFMz2GoOz1DF/D3OVqxC
         9ur4XNfH+aVaaBTlG+EGB3J/ww4OzJFeq6haJ28Gvr1FPV/bSOZj98nzPVRBE7TNuOwK
         11FHcsGq4KiBl9hKQmaJsdr3FdoE0rv1L/ZZPas28ilFT8dVun+iDkRaR2CEqxTmpqFV
         q33p+7K9/TAhOEnNf3CfFou067Gzo2mbsRD65cA2dPP1A6doD6qiR5CbX+hDk46pASNi
         AD87N3DspYWUMo2se90F8Y2bnb7fzmubqNHLs+CSnYuEf1LGCAw0aYJBT13F627l2cH/
         uBfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=klAjKa+Vy8Btqz0R9bpFewXIHBmE4NwXpaFoOXIr8jg=;
        b=ZrTVRPMmBvcd1xMZuJT4XmZK1IGYjcP9RJltPr+rNaEWS0dR2mnnzxSLgbl5FtpoZi
         tulJFYqdkurE52TbtQ6O+o8VborACwoBqbe0B3eFgRdVesWUvOJ6E7VCkbmGaiMiSO7m
         /mIXkdxlgM41Tzn+c3oXaXW87DQwKI9Wbkt4Ng+bZEm7RvlSWu3xVKEAZ0sMdfmYhOVJ
         zUgWtCiA74wn+nWRr5xF+J3IxqSN/02rFGh9YyM/usXQI7yeLADmJq3ixyleywEZ2cxb
         2bsdyN9+cSuNo2EIScMC0QwC5ZfjKcgbaZxSWP0exoQoKIq0oPBapKlwcQ0hR4eSdoiC
         PDrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=aFxz1yah;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=klAjKa+Vy8Btqz0R9bpFewXIHBmE4NwXpaFoOXIr8jg=;
        b=KG7wx3I6PFpY5KSpUvbYjFjzR1qtk1s1nGl727d3ISj0Yv5ueAEzON2C4sYn8zvCTz
         Bmo9c+3Qj3lZKmesJz7LrAV0738xiJ1pOXwHaeHD7HORzdZU/hbwG98wqPDmm9DJ/Qny
         ncGLrOOyPMNwZhkLUwr0y0Lj+27NDQmnQKVh4JDXQC1pyLmz1isSrGDS21QO1kcg0nFZ
         YQkxF9ZkfuJ8aJfcriolxk/jRJG4lgCi2F27u7vfaDExbu8cxBG9aKC7u5hEzmI6tLXZ
         reeqaLCSI0Ftqq+1hkBeCUtOneOtuZOY0gvhmggeAIMp5OvcgJSA5WuaBhXM6m0bqW60
         fl1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=klAjKa+Vy8Btqz0R9bpFewXIHBmE4NwXpaFoOXIr8jg=;
        b=DnjvgR3ZvgAKzABbkPaiiQ1cdyyX0Bnp+dMXaDaG9GO25Ey7aBIeFlKiBJ40hkKf25
         FFWGQCZG/Rk4+wNJ+tff1UtsyXPA2EOR3hN93BsEvtDk1TOvV1khPvOF60ekhMrq849R
         4Q5wrkO6x95j2hJjuDjLa8KYDzTP3Nak+4XYDLaEf87GZ/raFhWrtxXQskvIu45ZZEin
         qnBw9x0C8Q9c/2tMrKlpjytG9XslO9dInaSkiuTJbVqxC+ebtxoSYV+RAAJ+1PGYTySO
         TbDfEGSRngMgXC9U3J1M9BkN0FNHTvoex62hODmN497Xz2fQ/GGX8KHtbmdtIPaGzBm7
         ke4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qAMjLyKmYoO+Z4dRxqeid8XJjWhENgp98WP0OXqWdEbtvP4KY
	cyXU49H6WnmMRKk0T8K4DNA=
X-Google-Smtp-Source: ABdhPJwrmiTOunW8+UGNvy2xYuE9diYx4nnrGyaHp42M0/HxpKXKIOpLuAGUBrONEOLTnWY21BYG4A==
X-Received: by 2002:a9d:6f07:: with SMTP id n7mr2694287otq.164.1598256880541;
        Mon, 24 Aug 2020 01:14:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f11:: with SMTP id u17ls1034841otg.9.gmail; Mon,
 24 Aug 2020 01:14:40 -0700 (PDT)
X-Received: by 2002:a9d:5186:: with SMTP id y6mr2995918otg.230.1598256880155;
        Mon, 24 Aug 2020 01:14:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598256880; cv=none;
        d=google.com; s=arc-20160816;
        b=FQxpEWaNo5SkIF4d1QZ7po9fc7NCo05lX96Js2y4xQZhZRUxi+WSilQ7bCAzKnS83k
         ENn/nmUlWM2XVbO86PCQ8opJDVvYKE61Wm/q2TI4K05zNOEV3I6EMieQTKucmz9e8Mwj
         yTKYmlK7+o7Cj5a6W6vYdGn4c6McNNVfBYEDW6ml6WYD2y+8DDejVDgKIcspI0nwOGit
         eStc+iggIqSre4iIQ07N2Ln4pBLfAvPaI7nFtUFEGBHhNrb1GuipxG8dMp/b3BJhLJqc
         6CPScJLw1O0ydLkhFZpEuhMk55i5OzOhGzrzCr1NwNeCpLnb5nnpt+f9l6atGQ6nCSma
         X46Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=fp5BvuMv6aQW1kwsMMF3iiFeaB50z+78RNwBXksdEww=;
        b=MlzgpGAtWAgkmUWBHiYAvMwsWeAoq24dzyWSZH/RC3fCoY0JhKCTYjhho5sm7+U3hu
         rZjyVMZ2OXhAYRUYt1fCLuA5RI5/KYyQwv2y5WOj7EQRmUJLZVSS9Yyh+MwzR50h0lpv
         /m+VSE9KAK4RKfy+rGwtOg6Lz0Z5X+ao+1Lvn/rPObCw+yy3pDWh7NcadUE21RRTdYqw
         jB69LpUu3bt0H8a8eFPGGkkp4cKzvaFZU23kahzpLSIvrmgLxZaj/8R6OIsNtuy7IUBQ
         gIAkaGcCY32YIS1kF5Bm0F0Mli9wrDHo277o3LYZkNFWrJu2xLVj8KHx1q0FN+i7Uarq
         QpEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=aFxz1yah;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id c199si409405oob.1.2020.08.24.01.14.39
        for <kasan-dev@googlegroups.com>;
        Mon, 24 Aug 2020 01:14:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 3df8a9808a0645cbb9ff4172bda44e44-20200824
X-UUID: 3df8a9808a0645cbb9ff4172bda44e44-20200824
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2082476556; Mon, 24 Aug 2020 16:14:36 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 24 Aug 2020 16:14:33 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 24 Aug 2020 16:14:33 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Jonathan Corbet <corbet@lwn.net>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v2 6/6] kasan: update documentation for generic kasan
Date: Mon, 24 Aug 2020 16:14:33 +0800
Message-ID: <20200824081433.25198-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=aFxz1yah;       spf=pass
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

Generic KASAN support to record the last two timer and workqueue
stacks and print them in KASAN report. So that need to update
documentation.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Jonathan Corbet <corbet@lwn.net>
---
 Documentation/dev-tools/kasan.rst | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index fede42e6536b..5a4c5da8bda8 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -193,8 +193,8 @@ function calls GCC directly inserts the code to check the shadow memory.
 This option significantly enlarges kernel but it gives x1.1-x2 performance
 boost over outline instrumented kernel.
 
-Generic KASAN prints up to 2 call_rcu() call stacks in reports, the last one
-and the second to last.
+Generic KASAN prints up to 2 call_rcu() call stacks, timer queueing stacks,
+or workqueue queueing stacks in reports, the last one and the second to last.
 
 Software tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200824081433.25198-1-walter-zh.wu%40mediatek.com.
