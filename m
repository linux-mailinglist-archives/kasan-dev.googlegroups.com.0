Return-Path: <kasan-dev+bncBCN7B3VUS4CRBDNIUSJQMGQEB5WG6CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id AD2DE511499
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 11:59:42 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id b13-20020ac85bcd000000b002f37fbd3c01sf758200qtb.17
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 02:59:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651053581; cv=pass;
        d=google.com; s=arc-20160816;
        b=bsl+LctVPFpCwVjJQQxgB6jvFYPKihgSvC1MeNdNWIQxbovIIAurhBC97IEu+ik41V
         OWRbGlgmd3HfcVwXjyYqtNzeiNPcr2yP83hQoH7nJF0j0c82926lUGgPqlsL6MMu9ldI
         79NQyoTQ/ufYm5KjNFm3LwKh861C6E5PiHt3TdkdQu7PotKMG4KXXYE4PeVXclHat1xY
         yuvEtKKz1Fbzaz5CwR555V0I6y56aN+PGFxaVpA1lamerwrqO84I2DJVmevslohfvpnR
         MXNO1BEujk1G72qOYHTcvCJ1i9J/1ALkEd6DYy1xsw3xSd15P/vvM8ys8igW4Ebx6DEx
         PTrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=qpMt2z0CSnL80qFGoUAazYt6CimrHgE3g8bKKxlgFI8=;
        b=j6c5MwNX+joa5a6BeQosaSEB7W2u9qHASgUUEjsHVHvDUVaPJcN4k495FJWcmXro/W
         OHUsjJkX86l3/WjeAkeno25BZxSzJNbXlQfO4XrZ/VXoD559IX0839idR2Oyp3tMav0/
         ajVptYktkr6mTldfBneU3+BHz/YYbJTHHQoUV8cSOuBvrTbSlivPnDw47Y1ncIu2/d94
         TgpTxrAdzUT1MSUqZncZ+iU4+G+HTqy8hRbHpUnOwAKl0OM+OWZOcuyRHZqDPAvBXxNs
         gq362eGgp00MiBWKBrH7n0H0pNAGMUNJaaNkMO1VAVRHwFIohHTknwWlCEZk7WIQxAGo
         ryuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=qpMt2z0CSnL80qFGoUAazYt6CimrHgE3g8bKKxlgFI8=;
        b=Edo5wKjHq6+C2tmafiEzhlXQEVQjAu1K3GdSNq5R7L4tVrad01poqsyza+mxMQF8Qf
         /UBCgkp2aihUhoYC1A5xyr3CrtwRQFe+lIdRKklS5QblbvBzdyhfNSMx0cgIIbw6V632
         r9ncWo2T0MdmR1RI+SBDWUnN7Alr2oddmRqjA4aCvGe+jP0SkgdAN5QWCR6E4EIiWyXL
         zLcQ7DCkhGxX5rY7JZ3BL10siHydhoZel/RJvyt+y1DQTS3N/g8LOV6KwGgfYwRkjXkL
         hhyUlcFEYaUvFMZwDRFrjvyE04fkz4d5DnU7FwyCjDWZ80d/AI7UoPzcQHHxmnBc70XV
         tTGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qpMt2z0CSnL80qFGoUAazYt6CimrHgE3g8bKKxlgFI8=;
        b=sYwmiRVZDPhbQGd4BF/FO7UniM4ml/HhdDY2923fmzS3kp9lTd2T/bVI/EHaDnUF/U
         a3LIKD8Pb25b8MzfQe+nwUiwgwNPABAc0Aarv8mJaG3T/DvNsVLa89u9kDJGmgasS11L
         FmmUFmA3Kh0P7fFDI0RlDFrLZ3hMdY4IB95rj6GIhFzs6rpoufgDUrn5EvF9TmjdmEOA
         nC8tUMdTPNECJQiTffVjGcZ2sllr6IdH0a/9x2jWoF75UN2oHVXjz7IbKONph77kJCOb
         LtLmOZV1nIeAxc50edy3iVBhX/Fk8T/n2E7/rGr4oVDkTBm2VoYg0gFDv781mjRtAWnF
         zbjQ==
X-Gm-Message-State: AOAM533gNpx7p91zkyWHdWycx/lX1WgfxXqBorC8IhRTg0kHYA2T4a1O
	1eIO1uWLGBI9JIUCp12/Trc=
X-Google-Smtp-Source: ABdhPJxHAYTqgZ7s5M4BMCuMxALIb+TcMpVs9bzuIq/qZg0UE593umwNxetpwgdjBsnybLbhNmO+mw==
X-Received: by 2002:ac8:5a96:0:b0:2f3:6fff:261e with SMTP id c22-20020ac85a96000000b002f36fff261emr7548638qtc.3.1651053581627;
        Wed, 27 Apr 2022 02:59:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:151:b0:2f1:fed1:9962 with SMTP id
 v17-20020a05622a015100b002f1fed19962ls2887263qtw.11.gmail; Wed, 27 Apr 2022
 02:59:41 -0700 (PDT)
X-Received: by 2002:a05:622a:110:b0:2f3:66b9:c616 with SMTP id u16-20020a05622a011000b002f366b9c616mr10233298qtw.149.1651053581090;
        Wed, 27 Apr 2022 02:59:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651053581; cv=none;
        d=google.com; s=arc-20160816;
        b=uJXsPoFynvrOMAYgSLuHSEJQIgvOZa47SfUJzCcQwoMAz7lZ1Y8vz7FXy3ySrDlTVI
         kXUraRJmWh1HoBuG7TnH95p4tX4Ap5Hb9o/E8ERFVQj//hX6DLLuTNK1aeGFDY69C+Dh
         5JAGNEnB7uQ9Qpo/uHXeJ/NLF8fCzRorHG29qmsFadAN3OqB0sma7v0jQFw0LPfuskiv
         SDb6+NJbC64xoBsR52lUvA6Fa7hevuKul/aDwEfd1frvQV+qdntIB8W2UBS76GfjDIjP
         zkraeey6HWdpP/+KP4+8rY69YG7gP+civjpF1N0d0QCwQ/WZxcNpqoASyyNvkQfskV4N
         mMEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=YasnZWB/S9kp2uHJl4L3glk6G5P8haLeuYhco/2bOxE=;
        b=Akb/rKDveq+itlO2vRjaHVtSCUix0+vloPOw3ni7GnR/QKWdcgyvKlhrknMEuyfp9J
         cQ48UV4CZ1cuazLs0Up7pjZXiUFVYAWhb/krK3u3kGBRBmCxlQx6ke1UrGB03aq3eCy/
         ZANINGYQE2xdTXBy2ogDwTIPkwoRrExslM31kh8va4AJnDqS7LTmsOmSY22hy4GjThVk
         gp1+ZFjIyeFLaizqvPJN/Lbo02WpJ5Tsp9rwut30kvCptmbqvs62GM01xq3LhE7wcj9R
         pXw8ZoZk3IhamEITMkL8+A4AURXV7svElTYdX/zdFLM9jFAlm0eG/GD3pJ4d5W+wIjG3
         jJTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id 79-20020a370752000000b0069f92e9a004si35006qkh.3.2022.04.27.02.59.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Apr 2022 02:59:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: eefbb75b7eb649d4803ab8ec1db8a0af-20220427
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.4,REQID:89c744a2-ae14-4fa2-8bfd-c801bfa8a180,OB:0,LO
	B:0,IP:0,URL:0,TC:0,Content:0,EDM:0,RT:0,SF:95,FILE:0,RULE:Release_Ham,ACT
	ION:release,TS:95
X-CID-INFO: VERSION:1.1.4,REQID:89c744a2-ae14-4fa2-8bfd-c801bfa8a180,OB:0,LOB:
	0,IP:0,URL:0,TC:0,Content:0,EDM:0,RT:0,SF:95,FILE:0,RULE:Spam_GS981B3D,ACT
	ION:quarantine,TS:95
X-CID-META: VersionHash:faefae9,CLOUDID:6d5bacc6-85ee-4ac1-ac05-bd3f1e72e732,C
	OID:febf3ac4902a,Recheck:0,SF:28|17|19|48,TC:nil,Content:0,EDM:-3,File:nil
	,QS:0,BEC:nil
X-UUID: eefbb75b7eb649d4803ab8ec1db8a0af-20220427
Received: from mtkmbs10n2.mediatek.inc [(172.21.101.183)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1096876898; Wed, 27 Apr 2022 17:59:33 +0800
Received: from mtkexhb02.mediatek.inc (172.21.101.103) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id 15.2.792.3;
 Wed, 27 Apr 2022 17:59:32 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by mtkexhb02.mediatek.inc
 (172.21.101.103) with Microsoft SMTP Server (TLS) id 15.0.1497.2; Wed, 27 Apr
 2022 17:59:32 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 27 Apr 2022 17:59:31 +0800
From: "'Lecopzer Chen' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linus.walleij@linaro.org>, <linux@armlinux.org.uk>
CC: <lecopzer.chen@mediatek.com>, <andreyknvl@gmail.com>,
	<anshuman.khandual@arm.com>, <ardb@kernel.org>, <arnd@arndb.de>,
	<dvyukov@google.com>, <geert+renesas@glider.be>, <glider@google.com>,
	<kasan-dev@googlegroups.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <lukas.bulwahn@gmail.com>,
	<mark.rutland@arm.com>, <masahiroy@kernel.org>, <matthias.bgg@gmail.com>,
	<rmk+kernel@armlinux.org.uk>, <ryabinin.a.a@gmail.com>,
	<yj.chiang@mediatek.com>
Subject: [PATCH v5 0/2] arm: kasan: support CONFIG_KASAN_VMALLOC
Date: Wed, 27 Apr 2022 17:59:14 +0800
Message-ID: <20220427095916.17515-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
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


v5:
    rebase on 5.18-rc4
    
v4:
    rebase on 5.17-rc8.
    remove simple doc for "arm: kasan: support CONFIG_KASAN_VMALLOC"
    rewrite the description for VMAP_STACK

https://lore.kernel.org/lkml/20220315090157.27001-1-lecopzer.chen@mediatek.com/

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220427095916.17515-1-lecopzer.chen%40mediatek.com.
