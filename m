Return-Path: <kasan-dev+bncBDY7XDHKR4OBBZ7Z3ODAMGQEIC73CJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id ECDF93B4DE6
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Jun 2021 12:09:44 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id eb2-20020ad44e420000b029025a58adfc6bsf12030402qvb.9
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Jun 2021 03:09:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624702184; cv=pass;
        d=google.com; s=arc-20160816;
        b=hEK2P2aenx7TgpTs+kxAkXjByG4KmvAA4PCFJ9X7S+1sYQvXrmlYbO/h3oMS9nui50
         RsFlPANaTQeS8RjSvVaDxGTPL7cUSKAprnHVEc3jnmJ6dJ1hZ12ip9j/Br/hXzGJN9p1
         /OMwcbvTSdvW7ROrd9LlIomnAM1WIjfk2lm4Rg1SBJ16mKqE7oPz3gvFNEb5swNwld8x
         ivknJ0tb8JiVWjp6HialmJHgod50i6AnFkNMYlDBFpdrSYC6PSlyWV+JledAnmSaprtr
         naIrzPKmv6ydydh0YAwp1PbR3r4hQPbkqwfZxpBpA9tymF4L9k8brC4BgcPvN5v0mJ0h
         gywg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=sXJmOtYb/O2IrKKNc84U0aOUJC8fl9UzKejqe8zqKds=;
        b=uXKsjz1zOyHGeG/fNtuN9ZZzLkSutwoej5AgfyGmwJSWG/GBXJ2RaZp5CGGeAeXqoK
         mmyAE2ELa4Zbd8w5z/gQY4nNfSpQ/xNNALx6bnt2zhwW/rNDnmMWP+i5vccJfBoSlsQg
         Ezn1pL8h0BRK9TqUnJ+Xuh3kISTCV6oZVaDnoVHuExiVJXnLnvbJt5O+8/GmdOcMZIuJ
         9as5OEamd6U8Qd1a2XVWznVsV9mRFCP9VGyXcynKsxqh6alWMz9o1BK8KIKVkCzWiz5I
         hD1ZHSIIG4VoRO7xKRNdrkZPaaJJgBHzGGhOXKmB8sprK3NPZWZnW7TSLQ7TfLR8A1g6
         iX8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sXJmOtYb/O2IrKKNc84U0aOUJC8fl9UzKejqe8zqKds=;
        b=orRXF6ksimIvoSZbiIVWYdMc+5uNBJ5Fj1JoptWOGKlhgePP3B57Szg72R+Axbs4Nm
         TIwWBLvTpE4foTd+uOAkEVX08XUpMcn5n5wJ+TCH3zzdMKCWoYM8oo3qTYBrLlVV3swi
         cu3u/ZeOmwrmpRInaxwZdBx0GpdOxkApuDrFeHxNEvKtrHxhUpjIPr0g/BLqgKZAFlE6
         yMHv5jy1QnCDJcgRTCoak3byf8mNjrEh9VpTTDbfJVeLxk9DdMi4b9h3tf8rPk3XT33i
         5FhYI5oSAv3D0Y8hQYm7NiGH8E8TUfAaxZC7Q7mp8rrDkxTREuQM8yeo8lIKMmeM04PG
         MHHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sXJmOtYb/O2IrKKNc84U0aOUJC8fl9UzKejqe8zqKds=;
        b=lH70ZmznKTS6YkrnVSdcKHGQ8tt0A1NLHp6yNZp8A+ZxUtah74hbGDHdNOoLNwlDoK
         DF10W0T6w80raTNmRvopc0xNBWIfwXnEEyYq4NDLbuOskxJ+h+HvwxrEu8nbFL7iD9TX
         fSajqhH4vV3rvo2OhoKWfkcCvSd8lm280qhdLpe+anZ6IhwrMFX3No8YGfCKQdXpDAuX
         DPBUD6PmdmRckTnMc8G8lGRS8udfLyAtXyH2rRnbwO2To76ohZRxS09w9qzn4r1/2+Ft
         F0olRZR1/wqjec5upl9e479eaw0ugHORzweCfcn6uCYNOupeREXkLHAQ6erd3i///yk0
         kPyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531QP//HVq8ObdOeA5VQeP9GjGJy/YStIfHJ7C80gp0RjGLmE/cL
	GtgiH4HL6Qdgfz12ycHoH20=
X-Google-Smtp-Source: ABdhPJwCZHWxQtEL2idX5Es1JBVKiMpbmWb9N5SpEAppIl+xmk4l36ApVQFbaTSpUGLnssbbhWjCNg==
X-Received: by 2002:a05:6214:17c1:: with SMTP id cu1mr326132qvb.27.1624702183923;
        Sat, 26 Jun 2021 03:09:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:ea15:: with SMTP id f21ls7848294qkg.7.gmail; Sat, 26 Jun
 2021 03:09:43 -0700 (PDT)
X-Received: by 2002:a05:620a:12ec:: with SMTP id f12mr15562669qkl.246.1624702183362;
        Sat, 26 Jun 2021 03:09:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624702183; cv=none;
        d=google.com; s=arc-20160816;
        b=BS6pEOWmpebqtjCESTH3hmc2ACO4KhKgxLLTs9TKTpc6RuzXp6ZzRFsd1VBxuf10+R
         otbQQ2+IeBp+7o1uGH64CUagkn5CzsC9zRL6c+WMOg5ygwf1E34gaT+x987PeL4Q6aM8
         Eudd58KTw+MLOXbKzETTnuk8Z3MVVW6ERZxU5p9kM+D0agl6T+E+9UXXgGeXI+zlgJL3
         DTrr3n/M+yMkOmZsl4r16o98Kz283UUSmyzHrSIMetOKBrpYyH/MQyYDl2XCF+DoEEg0
         QOJ9WdrbUQCUzhBU/McPPDpHPTDCpBMgBE63Z/+gmMQqdsGgHns6GdOVK91Lzu9PD1Lh
         g6Ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=Vxc84V9Pij+OTEl5t579raBxpqqVtlQNdnoyWEjhAIo=;
        b=ahAroPNi6953txxp08DmyF+G2PECEAig02gdVO28o9qt6+2XpnNLgo8nPFTmZ6WZZ5
         wIz+dNjnfHkVmsJRSo25vNmDtUbVWe2/otWogG9+ILV3jy3NFiBWiZcwzg7vk59O/Cyc
         Hw0SfH5gUN6eWR+SkinnLQs4p014aWgXj6nWQihqkBgsI612MkC2EfEW4YcAGyuW+/Eo
         pfaSEISnLwEoHlT6FxJTDYJQA/Dqr1a43RiCeJFNOihJCFAg7JoW50I6mHb5ybsvx4C9
         QBou4J6oOirsS4Vg5aVzesIikFoO+pKbZ/PDq3YHak+voBBGvtbYSCw0D25bUm+ArpeZ
         YLmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id v14si477515qtp.2.2021.06.26.03.09.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 26 Jun 2021 03:09:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 6ddb299865154c4a94ca2d424c352079-20210626
X-UUID: 6ddb299865154c4a94ca2d424c352079-20210626
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 609472269; Sat, 26 Jun 2021 18:09:35 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sat, 26 Jun 2021 18:09:33 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 26 Jun 2021 18:09:33 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver
	<elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>,
	<chinwen.chang@mediatek.com>, <nicholas.tang@mediatek.com>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v4 0/3] kasan: add memory corruption identification support for hw tag-based kasan
Date: Sat, 26 Jun 2021 18:09:28 +0800
Message-ID: <20210626100931.22794-1-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
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

Add memory corruption identification for hardware tag-based KASAN mode.

Changes since v4:
 - Change report_tags.h to report_tags.c
 - Refine the commit message
 - Test lib/test_kasan module with SW_TAGS mode
 - Test lib/test_kasan module with HW_TAGS mode
 - Rebase to latest linux-next

Changes since v3:
 - Preserve Copyright from hw_tags.c/sw_tags.c and
   report_sw_tags.c/report_hw_tags.c
 - Make non-trivial change in kasan sw tag-based mode

Changes since v2:
 - Thanks for Marco's Suggestion
 - Rename the CONFIG_KASAN_SW_TAGS_IDENTIFY
 - Integrate tag-based kasan common part
 - Rebase to latest linux-next

Kuan-Ying Lee (3):
  kasan: rename CONFIG_KASAN_SW_TAGS_IDENTIFY to
    CONFIG_KASAN_TAGS_IDENTIFY
  kasan: integrate the common part of two KASAN tag-based modes
  kasan: add memory corruption identification support for hardware
    tag-based mode

 lib/Kconfig.kasan         |  4 +--
 mm/kasan/Makefile         |  4 +--
 mm/kasan/hw_tags.c        | 22 ---------------
 mm/kasan/kasan.h          |  4 +--
 mm/kasan/report_hw_tags.c |  5 ----
 mm/kasan/report_sw_tags.c | 43 ----------------------------
 mm/kasan/report_tags.c    | 51 +++++++++++++++++++++++++++++++++
 mm/kasan/sw_tags.c        | 41 ---------------------------
 mm/kasan/tags.c           | 59 +++++++++++++++++++++++++++++++++++++++
 9 files changed, 116 insertions(+), 117 deletions(-)
 create mode 100644 mm/kasan/report_tags.c
 create mode 100644 mm/kasan/tags.c

-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210626100931.22794-1-Kuan-Ying.Lee%40mediatek.com.
