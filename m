Return-Path: <kasan-dev+bncBCJZ5QGEQAFBB44ZVKMAMGQEHJOSIKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id E2E545A3A17
	for <lists+kasan-dev@lfdr.de>; Sat, 27 Aug 2022 23:30:27 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id ay21-20020a05600c1e1500b003a6271a9718sf2761908wmb.0
        for <lists+kasan-dev@lfdr.de>; Sat, 27 Aug 2022 14:30:27 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1661635827; cv=pass;
        d=google.com; s=arc-20160816;
        b=lQ3HX9SVowSKrDwUeYyUdheq8brqekuNAyKdBxAjYvj30wGnXj8mKFEG75shXLWopG
         tpD0Y1aQekSPwnT7jtRoQvvoW+Rk12RJeTolm4tNIgs3uOch7nH+sleErA2gp9dUt8us
         +70qbpSbM/tFThs7GGohPeLCqeX9wQS5CuSZLAn4CjD12WIliFt2OnMDZGw7yfBPPfCL
         xCtV7sT99YTXo6w2CQzmp+J9XTASOr2wnXhIqRG3XxZqAr0UzBz/j2cr2jaZO4rvX3xe
         q9N0mOY021C/rMN0pVlk0gufRB5Xw8+2j9/OiMPoBz6dAWJJIg6SPjxFh5z/FvIZITb0
         nCQA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=zk13a2wDxPbPwS6F9muX+U0Rh+2AIy5htDo1pByYht4=;
        b=svktKTzqy9fMFfgzmm/bdk1NRkPD0DsMZGwbSCP16Dszvn57/Om0s16CibwkpzeuH0
         61pKGDXl3CS/V0Swq61+X7/DMVdes/v938NA8gHQlNikF9s80McrklrdSUnoO++d+nCc
         AKARTbk++0yj7dcBXT2VvoMU1w2WtE5CT0FDiscQSbHLyEPkRSoWkzIz+2P2Bm4gBuf1
         XmY6JZDRjpLUJgIcRAd1yK1vtSF4OOKbLlXp8HwWDQ8PH4CDM5M+3f7GEOtziIt3mhJC
         p7+jMn8gbnLpMAiXkHSSIIoOExTRZVUvfXK995mdhXVLwvDjN9OjNWZ+pvB1HKeUWhvt
         KmSQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com header.b=T40zAiOB;
       arc=pass (i=1 spf=pass spfdomain=nokia.com dmarc=pass fromdomain=nokia.com);
       spf=pass (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.21.90 as permitted sender) smtp.mailfrom=alexander.sverdlin@nokia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nokia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc;
        bh=zk13a2wDxPbPwS6F9muX+U0Rh+2AIy5htDo1pByYht4=;
        b=e3pC1Z47/3Lv9xfS3f1tKxk/27arweh4oo52gmgCTE3h8Hn/UV2pFaICQVERMZ10zq
         FIh/aPVZSh9c5Vke8Qh/+1Vs3LHMNIFAg4Hb8Ej86H6OXBu3uu+MeGvVjxxm7v2NznQG
         UBJR5Ayi9Pqm2Z7RHE11OISoYWuSvjZjeJLXH5nfMEf7pG4MPA37bQfERrAru0geqx0a
         ohAnI58T8ZGhBguuNhOdwuiKvQQO28nBTT4UGaclZOdvrf6PDHqfokp+M3pw0O4U7jUl
         AQ9a2HFpwxCTDmbu8/bWQUrfkTKvSMW0N0XS6sDji++gGGJqc48l/ekoWgn86K4Uw6v4
         N1ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc;
        bh=zk13a2wDxPbPwS6F9muX+U0Rh+2AIy5htDo1pByYht4=;
        b=Sx66GT5YSgOHQYiIweJqk9vwBs315kq0hyaazPGOOCWxA9Bi+bi0pOle47ZOpCJs6G
         61su1kCNZ+0zAU6HsKL3fEegVzgb6Si4zice/6dhnL6T5g1pDJ+DwKFLxFabJ8C8Wyun
         7Ivvct1r1wc/NyFOaXnOS5w4IlIdiauAWTymRYLZcb89462vc8Zrgnc/uc7D5+9KmEOA
         QZWavrliMViUIpwadXt+A70/xOlt+R2Eubtsq51sbEBz0ClLGpZ7Qy93PeZVCNYe6pnq
         Ppfedw8ARfeoYdkLla0Zv/k5vKnzWSnyFnJ7R2Af1+elT2Nr36EtImIS0JeJj1DCpKS3
         KCfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1y+Mk3U81G/uTCW2JMnIZcvuHryb9dxRjK0tPG4DamU9RIApUw
	wa7uN1f9sVxXVY3AiU2G4a0=
X-Google-Smtp-Source: AA6agR4QyZrPgarhHQnwRolBYkSYf9dXrB/Z0gSMN1Eb3Elyavj8Ct4vU7IQvt3wxcsd4WGtBquW5g==
X-Received: by 2002:a05:600c:22d2:b0:3a8:3e8c:d914 with SMTP id 18-20020a05600c22d200b003a83e8cd914mr1665673wmg.128.1661635827512;
        Sat, 27 Aug 2022 14:30:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:251:b0:221:24a2:5cf with SMTP id
 m17-20020a056000025100b0022124a205cfls4443781wrz.0.-pod-prod-gmail; Sat, 27
 Aug 2022 14:30:26 -0700 (PDT)
X-Received: by 2002:a05:6000:144a:b0:220:7181:9283 with SMTP id v10-20020a056000144a00b0022071819283mr2703054wrx.158.1661635826282;
        Sat, 27 Aug 2022 14:30:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661635826; cv=pass;
        d=google.com; s=arc-20160816;
        b=q4ZoJxXxAKRX9ROWMpfFBSRchmCIzkSW+YbAddnUeVQW09VOQWs+WwiLnNPwcKOGBf
         JGcbRIJSAqxZF60lgjt6Pj6FMusAan54Ba+mwFbT/oa/7yxEw2XhYy0jZ3OeEzdy0WRe
         qfYtkyPhYvOGOMHtMNLYbA2dPofcJkjfzN4ftrxTANQ1lRS33MKnl+44KwXJ8ETVUXo8
         2nqb6K4/Pqi9CI/iqDo8T6jkCgrKwqJw/jVWGbp3akgCrDVnCKzVBLgtWh/FVBrbl8Iu
         aF+vFmPhRkg8c0IENrK78er41rsX9l+Yz6bPdxOyAeXdtlmLrwfknj5H6RvS848GCzDO
         jUoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=MGMuUvhSvZXy/S8vAKI2Tadnp4vXnJRLcr1jsXKOf6A=;
        b=pZINxs7QqxpbY+8DPwArxlD2yG0JA8Tdo0AkiS+SxhsoKNOwqxIA/gEkOOLVQPNoTX
         /IQGIkEmQfateVb3TnwpVAhlSIWu567dVZvY6V5XIiF5l3tudkHGjgu6SfuQmpXqAnfy
         ek1cMQAwQTTgmmAIXw1VByKlz4w2cVYKE+DrkbG19wQC3gpEtYKd8BYEGrUEooKAlg6K
         e+9+Wq0kikBz00lORnFz8k2dP3JJP5MOeROnNcVzbszCVh1yRL8LnxQaoyLmzQ7f78ta
         eq7NB1/2GNEUUFg15Kl9CFqh89JgdPdCpft8j+P1EEI6cqFwhPsYRxSdmIiEX7OJMmpR
         7WyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com header.b=T40zAiOB;
       arc=pass (i=1 spf=pass spfdomain=nokia.com dmarc=pass fromdomain=nokia.com);
       spf=pass (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.21.90 as permitted sender) smtp.mailfrom=alexander.sverdlin@nokia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nokia.com
Received: from EUR05-VI1-obe.outbound.protection.outlook.com (mail-vi1eur05on2090.outbound.protection.outlook.com. [40.107.21.90])
        by gmr-mx.google.com with ESMTPS id bu25-20020a056000079900b00226d0b6b95dsi97967wrb.1.2022.08.27.14.30.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 27 Aug 2022 14:30:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.21.90 as permitted sender) client-ip=40.107.21.90;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=DVtXWPFGPaNKqJztl6Su8HFX4ye7Yi0MCfpBpIIUe5k8axa2uWs1yL5JVsnmmvWeVHR//E1RswO5FAV1b27D30LN0UA0fIh/ox6cFKBmasLYtPACfC/yLDCvsSso523Gv48f0O3Z/ZyZnKLgoQkCbnNOuIJ0AIovIapQ9+TNd8I30s/pVZLkDAWrH1XvXMvyVbRz7XjDsoMg1Cujj8E6xXcx4rZhUl+mrLwJftmNuchNLlQtfgJrHx+l9IHAs8f/H92PWdYvqOHS63cHAXm5FRI2PtQvyX0cMCBQ3vFLu8qYam/vP3/lMOMMQKyICXIPqvprccIpFHGZq2oSgdA9EA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=MGMuUvhSvZXy/S8vAKI2Tadnp4vXnJRLcr1jsXKOf6A=;
 b=NOC2e0LNlISMG4VnshmmoxGQpNe7M3AAegz3VFRKq0KBwPOjnwQuon3ntkczlzlE51MvQYkC2nE4NRjJ7KTbtDDVylRltmIKmqa24pjKjXauStmvBcO3nGIcYGlb5tQ4I4cV4WwX0JwxTmeWmC9Tt0+ThChcJNmbo4BujzC/hqTj9e18yrfcnFgMXwepkFHUyR0CrEKsA6zGXZxFP8viDjYTkjfej7m8ZPcD8ge7HJ6rVTOrOSC/spQNEB85lrgTPy5YaAXNNxKxVlFY3FM3l/ABLHNdadSvz0o5enNwh4gM2TZmSZFJg6nR+qBjXfZ8oKSkoUqrMEOVJA9OS79s7A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass (sender ip is
 131.228.2.8) smtp.rcpttodomain=vger.kernel.org smtp.mailfrom=nokia.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=nokia.com;
 dkim=none (message not signed); arc=none
Received: from AM5PR1001CA0044.EURPRD10.PROD.OUTLOOK.COM
 (2603:10a6:206:15::21) by HE1PR0701MB2570.eurprd07.prod.outlook.com
 (2603:10a6:3:96::18) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5588.7; Sat, 27 Aug
 2022 21:30:23 +0000
Received: from AM7EUR03FT038.eop-EUR03.prod.protection.outlook.com
 (2603:10a6:206:15:cafe::f4) by AM5PR1001CA0044.outlook.office365.com
 (2603:10a6:206:15::21) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5566.15 via Frontend
 Transport; Sat, 27 Aug 2022 21:30:23 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 131.228.2.8)
 smtp.mailfrom=nokia.com; dkim=none (message not signed)
 header.d=none;dmarc=pass action=none header.from=nokia.com;
Received-SPF: Pass (protection.outlook.com: domain of nokia.com designates
 131.228.2.8 as permitted sender) receiver=protection.outlook.com;
 client-ip=131.228.2.8; helo=fihe3nok0734.emea.nsn-net.net; pr=C
Received: from fihe3nok0734.emea.nsn-net.net (131.228.2.8) by
 AM7EUR03FT038.mail.protection.outlook.com (100.127.140.120) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.5566.15 via Frontend Transport; Sat, 27 Aug 2022 21:30:23 +0000
Received: from ulegcparamis.emea.nsn-net.net (ulegcparamis.emea.nsn-net.net [10.151.74.146])
	by fihe3nok0734.emea.nsn-net.net (GMO) with ESMTP id 27RLUHQc017485;
	Sat, 27 Aug 2022 21:30:17 GMT
From: Alexander A Sverdlin <alexander.sverdlin@nokia.com>
To: kasan-dev@googlegroups.com
Cc: Alexander Sverdlin <alexander.sverdlin@nokia.com>,
        Lecopzer Chen <lecopzer.chen@mediatek.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Russell King <linux@armlinux.org.uk>,
        linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org
Subject: [PATCH] ARM: kasan: Only map modules if CONFIG_KASAN_VMALLOC=n
Date: Sat, 27 Aug 2022 23:30:09 +0200
Message-Id: <20220827213009.44316-1-alexander.sverdlin@nokia.com>
X-Mailer: git-send-email 2.10.2
X-EOPAttributedMessage: 0
X-MS-PublicTrafficType: Email
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MS-Office365-Filtering-Correlation-Id: da3dcd54-f34a-4876-bc5d-08da887359bb
X-MS-TrafficTypeDiagnostic: HE1PR0701MB2570:EE_
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: CcJepoL4qGlxn0XxEwVyt/uDEhisBp5N6qDF7IWb1yaLIjMbsYMGjuL7SEdcw/fKa/i4lOOoAFDEfLTbmZMhM59yJYrOEQZyogRCtAeuF/HinbVi/8TZogc+3s7tDHE7d69ZB4BD/fp1xUzzozwo3P35qfDYhJSiYbDfm09+LyNl0hnFb/6lloJS3ldqUgQ/vUsyDBUuEZ6dMekEScDCfAkMmcwo5yUIWoL8vPnVpgwLsiTvb/cVz3N0SQPBOmxgJk8bRyphYAX09XKc0OEZw54n+kqewOnOd2rmDgyfFPfD0YOJwg8WuV/nN+QQW7weeuF/lfIsAVYNShGW3EWbnsMB8ifbq7FVjzhpXFwioAU0SOKH8RGgcrNioL450zfbxy/EcSv1pWNZMKumn+YiVZPVHe/CS++QeaAG0Vc4udTXj0s8mN36O7Fn4mNxDNxYd0onihYQHsvz+fY3gy9UBKQzbsvGYn2npFumRg8r1iYyRxnCTFUAJV9qJeIPWEqiup+piGMRr9PNKQKNWf/IfGoPy86DF1CzaRLR94C8ZDaPMsjgdxIaFP0S8g8nejeaY40hPU4ERv2CXmM1xhfGz+qpNRRwHaRWvCEFAG+jzaG4l2UE5thklDL6zHrXUAWiimvkpJyeOhtmnL3FJHKM1W5tPDNvJWMVVpltX3xghyvQuFGugQDompS1jQ4z4lNDxlqoR/28I9cZKWMY4r5gfBmGsweUrdQTz8evicZ0SR+iXDRhos2fcMKG75GCh9GhlymhPMRw92d9BG4dzWlr8+0Zl2uPPHZVIEqwR40ZS6HNE3iXBfw1aaMXqJE+tJBOMd00gGZyGtCNKLsueaq85I6N/Yo5kqf9WocBXL5gM/A=
X-Forefront-Antispam-Report: CIP:131.228.2.8;CTRY:FI;LANG:en;SCL:1;SRV:;IPV:CAL;SFV:NSPM;H:fihe3nok0734.emea.nsn-net.net;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230016)(4636009)(39860400002)(346002)(136003)(396003)(376002)(36840700001)(46966006)(40470700004)(6916009)(6666004)(41300700001)(54906003)(316002)(82310400005)(478600001)(45080400002)(86362001)(26005)(82740400003)(36860700001)(40460700003)(82960400001)(356005)(2616005)(1076003)(83380400001)(336012)(186003)(81166007)(47076005)(36756003)(7416002)(40480700001)(2906002)(8936002)(4326008)(5660300002)(8676002)(70206006)(70586007)(36900700001);DIR:OUT;SFP:1102;
X-OriginatorOrg: nokia.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Aug 2022 21:30:23.3813
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: da3dcd54-f34a-4876-bc5d-08da887359bb
X-MS-Exchange-CrossTenant-Id: 5d471751-9675-428d-917b-70f44f9630b0
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=5d471751-9675-428d-917b-70f44f9630b0;Ip=[131.228.2.8];Helo=[fihe3nok0734.emea.nsn-net.net]
X-MS-Exchange-CrossTenant-AuthSource: AM7EUR03FT038.eop-EUR03.prod.protection.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: HE1PR0701MB2570
X-Original-Sender: alexander.sverdlin@nokia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com
 header.b=T40zAiOB;       arc=pass (i=1 spf=pass spfdomain=nokia.com
 dmarc=pass fromdomain=nokia.com);       spf=pass (google.com: domain of
 alexander.sverdlin@nokia.com designates 40.107.21.90 as permitted sender)
 smtp.mailfrom=alexander.sverdlin@nokia.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=nokia.com
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

From: Alexander Sverdlin <alexander.sverdlin@nokia.com>

In case CONFIG_KASAN_VMALLOC=y kasan_populate_vmalloc() allocates the
shadow pages dynamically. But even worse is that kasan_release_vmalloc()
releases them, which is not compatible with create_mapping() of
MODULES_VADDR..MODULES_END range:

BUG: Bad page state in process kworker/9:1  pfn:2068b
page:e5e06160 refcount:0 mapcount:0 mapping:00000000 index:0x0
flags: 0x1000(reserved)
raw: 00001000 e5e06164 e5e06164 00000000 00000000 00000000 ffffffff 00000000
page dumped because: PAGE_FLAGS_CHECK_AT_FREE flag(s) set
bad because of flags: 0x1000(reserved)
Modules linked in: ip_tables
CPU: 9 PID: 154 Comm: kworker/9:1 Not tainted 5.4.188-... #1
Hardware name: LSI Axxia AXM55XX
Workqueue: events do_free_init
unwind_backtrace
show_stack
dump_stack
bad_page
free_pcp_prepare
free_unref_page
kasan_depopulate_vmalloc_pte
__apply_to_page_range
apply_to_existing_page_range
kasan_release_vmalloc
__purge_vmap_area_lazy
_vm_unmap_aliases.part.0
__vunmap
do_free_init
process_one_work
worker_thread
kthread

Signed-off-by: Alexander Sverdlin <alexander.sverdlin@nokia.com>
---
 arch/arm/mm/kasan_init.c | 6 ++++--
 1 file changed, 4 insertions(+), 2 deletions(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 29caee9c79ce3..64790661bdc40 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -268,12 +268,14 @@ void __init kasan_init(void)
 
 	/*
 	 * 1. The module global variables are in MODULES_VADDR ~ MODULES_END,
-	 *    so we need to map this area.
+	 *    so we need to map this area if CONFIG_KASAN_VMALLOC=n.
 	 * 2. PKMAP_BASE ~ PKMAP_BASE+PMD_SIZE's shadow and MODULES_VADDR
 	 *    ~ MODULES_END's shadow is in the same PMD_SIZE, so we can't
 	 *    use kasan_populate_zero_shadow.
 	 */
-	create_mapping((void *)MODULES_VADDR, (void *)(PKMAP_BASE + PMD_SIZE));
+	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC) && IS_ENABLED(CONFIG_MODULES))
+		create_mapping((void *)MODULES_VADDR, (void *)(MODULES_END));
+	create_mapping((void *)PKMAP_BASE, (void *)(PKMAP_BASE + PMD_SIZE));
 
 	/*
 	 * KAsan may reuse the contents of kasan_early_shadow_pte directly, so
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220827213009.44316-1-alexander.sverdlin%40nokia.com.
