Return-Path: <kasan-dev+bncBDY7XDHKR4OBB4E4VGEAMGQEBOQUQEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 053213DFCB2
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Aug 2021 10:23:15 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id p7-20020a170902b087b029012c2879a885sf1591809plr.6
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Aug 2021 01:23:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628065393; cv=pass;
        d=google.com; s=arc-20160816;
        b=NQfGBbyBVUR92KLxOOD83sEnxfAQ5JBoouWNWl3DIf+F+RCWv1LfNW0vhXqklpDJNS
         tbElt3blJ84Ke1iSwGbuKwo1gbTTYv91YT6l7Vxz7isjANQK/wZQJle/Mx2eCCVm0M4W
         3TWzCGplsgeKG9Sbgf+IYTbNV0wUau9+RcslKB0Q2ipGOh/BibA5oNd8SDeniEkLSZaL
         zZG1MDDgn76sKGb8+vc+T/EMpnDg9rUJnNN4TABY9HoX0Oh2DM7O6+dOhzrtGxcJsxB3
         tmpD4Ftq4f2aFSlL5lpI5J2zze7RFEAdppL0aughEPeSkTb42VYfzVI3hgvAXInn7d6g
         sreA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=rSU6F3Zn0FpPfolO3GujRHaalMQuQMnjRCbjFvaFCt8=;
        b=OrvRRU+7cbdBvU8IB2zaojkNM1/4qjofk0e54OKSosSqHCFUPq+eVq9PW82N6RfdNc
         eK5jYfxH5LX/BUBiTnPN5hjyn3Duh43zmmUnNxeiwmHvWWCnqsLUL213LkzF+jk144vu
         mzh7db3+mIPxsCfZAKp2CaA2rWEOoHKCIdI+W3Imknql1hBrgYcbqUHY2KySVwvSRsTO
         pNXxBfx5OM0VwB2v+C1hoSDguPKdneB6wmnho8yNU5TJoSGgyYVqg16v+oFk705IPF4x
         q2CQNl1LVynfw7DBaJhXCD4WN2XG41ZJ99iW04onV98jI656zPzwiJO/xXDfGTVpsThP
         y14w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rSU6F3Zn0FpPfolO3GujRHaalMQuQMnjRCbjFvaFCt8=;
        b=PcHpEnhs6wEaPyrN+sXu1w4TFcYuKF/GQDI0gKgY6hVbb2ytqnXXq3V+7gO2J0niEd
         8q+7RCVn2ltGguWPzv/rR+NZkeIqxQObHAxamlFiwWyMld6tspwiONnk/yzQzmG9OZEN
         /HLRgHqDuGFgsp/TkVXeQV4SmpRJr4jeUN/+GCIX0BRGhTXUnpPLGzppCi+VyW6igmDn
         iXxQSAFtmtGeEVqrytfqSj4HpKwzEKmfpk/yIrqtZydIbXhSzJtiB+xOLx0IEQTlU0oa
         JQGdYQvTRupmScB+FnjPzkRjvEhlWdVkpsax0/D8+R4uTq2GJQbVTdJg1V0YloYS1OT6
         wuDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rSU6F3Zn0FpPfolO3GujRHaalMQuQMnjRCbjFvaFCt8=;
        b=joQHOkhsKrbJd6kjqkxsxmBKmJxlBopUsS/LV5eZZ0x3ZLLmy3RIwKML+gSTTahMyI
         RVCqAR8qAPYgf8oHJfXOLOsI9+JZ+Q0JVMQ5OmuhxFDueH0hEKPdaKB6Qjr6IKpzii33
         0pFKtCdZKuLux1fi81P0Tk104tCoZ/w+FFrrcgaGgBZoD21Gjo6lQrpdRXE0hnszp2z0
         7G+xlki3LIVYP13c3b3y/uWC9j63SxSDGUYmDMzgCc1XCOX3V9rWvp38DMFgjVDyhzkB
         oe2CErVEQ0weUPW8c7fdDw/zftJIYFu2sIBmYPbrsnAt+UA0saaMEK7WZ2o9ZHlT2SEc
         ppBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ND4szDjoySNbwirm58oejohkTkEYYwRS7KWPNWa8sjLPAsw9F
	lOL3DpENuKYaGjk18V8BNYo=
X-Google-Smtp-Source: ABdhPJxt/76UP6RVpjk7Dn5DtWQQP00Qjz7CILaN2sxvEh3pUO06q6ck1wUzz+D8z4Ruvr8BZ+/9Gw==
X-Received: by 2002:a05:6a00:d50:b029:3c5:72a7:bb05 with SMTP id n16-20020a056a000d50b02903c572a7bb05mr1401660pfv.26.1628065393012;
        Wed, 04 Aug 2021 01:23:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:656:: with SMTP id 83ls748881pgg.9.gmail; Wed, 04 Aug
 2021 01:23:12 -0700 (PDT)
X-Received: by 2002:a62:878c:0:b029:3c5:f729:ef00 with SMTP id i134-20020a62878c0000b02903c5f729ef00mr328065pfe.43.1628065392368;
        Wed, 04 Aug 2021 01:23:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628065392; cv=none;
        d=google.com; s=arc-20160816;
        b=TS5wU0/FhCEbeF2rIDKVvxyB3nY2eG3Ldb5U61FONgEIj0sraOn0FeKuQcPTfHnm8o
         crr8dt1KBrsho0MXgf3FjdTAlCidRy31f1GKzxDWjILsULEdCOKhQAOg5mUTehJS5DO7
         g/kAFdW+6O320+si7ke/ECla0hfJPMW2Qjpar3/oS+W71mJ307xJnkNH8nexHcy70JdY
         PK2lCRmwdFv1iU8sGPT1h94g5iFk/sW/kgcV+td9mQ7AjE2WcQKhXbFUqcoaAPzMz94e
         qMljT5BgMrnhJbwjn0afMp63zOuWwlf5KXdPWcbYz4a0jyaaH9XFO0BbigP062xZq3ji
         SSmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=KFq2ECQdILbEnKxwBoUtMxJ1+JK9utaMzIzLVOAgFHM=;
        b=xijMlnPjn2pIkk11MYASe9BrzRoaMjJn3yWDtGHlGZEcv0jrEqhexO5jrLBQq2M6WU
         fmSfBXBSA3fsvXhtNFalEL0MM9ypFCaI8FCYCVjHIOCVPoN0AP68NvbVj4Rl5ILiG5QY
         hb/y0HLtjx3JhNOhmbsa0nr+4PolgDD0bJaXlamU9/HSncTJ40R9CIPE2UwcBXA4ills
         edK/JYWHIVNIC5F5DDPCA/Owy2+vypyk8VxUwJjIMbGGcEAETgIouEbgrn8WymPTvaOJ
         rtHnUoqy9E36VIqAcrmOILc2XUshqpwaB+CBpswXoW23yClYUiqo05AVX9XhYtmCB9FE
         /Vaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id e1si263812pjs.3.2021.08.04.01.23.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Aug 2021 01:23:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 9748f6851311479fac11afc7ca83a48e-20210804
X-UUID: 9748f6851311479fac11afc7ca83a48e-20210804
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1817066279; Wed, 04 Aug 2021 16:23:08 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs02n2.mediatek.inc (172.21.101.101) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 4 Aug 2021 16:23:07 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 4 Aug 2021 16:23:07 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang
	<andrew.tang@mediatek.com>, Andrey Konovalov <andreyknvl@gmail.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>,
	Chinwen Chang <chinwen.chang@mediatek.com>, Andrew Morton
	<akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, Kuan-Ying Lee
	<Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v2 0/2] kasan: reset tag when accessing invalid data
Date: Wed, 4 Aug 2021 16:22:28 +0800
Message-ID: <20210804082230.10837-1-Kuan-Ying.Lee@mediatek.com>
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

With hardware tag-based kasan enabled, we reset the tag
when we access metadata to avoid from false alarm.

Changes since v2:
 - Refine the commit message in detail.
 - Thanks Andrey's explanation about false alarm
   of kmemleak.

Kuan-Ying Lee (2):
  kasan, kmemleak: reset tags when scanning block
  kasan, slub: reset tag when printing address

 mm/kmemleak.c | 6 +++---
 mm/slub.c     | 4 ++--
 2 files changed, 5 insertions(+), 5 deletions(-)

-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210804082230.10837-1-Kuan-Ying.Lee%40mediatek.com.
