Return-Path: <kasan-dev+bncBAABBZXI5GVAMGQEYIJUIFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 31D007F08E5
	for <lists+kasan-dev@lfdr.de>; Sun, 19 Nov 2023 21:47:36 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id ca18e2360f4ac-7b0a341eb53sf34850739f.1
        for <lists+kasan-dev@lfdr.de>; Sun, 19 Nov 2023 12:47:36 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1700426854; cv=pass;
        d=google.com; s=arc-20160816;
        b=iZ17WRAZ+eNCzhBD+p4BAbNQuDVwKOPEnm5LT8CX8HLgkWEAQN8gf7m7THPtReNrAK
         e4CORsqECZn20LGo/JzT/YslNVh03sZ39yXBzNZIOBgVjZyugUYRnyefWJ23EfgT+1PB
         TJ14LywJABcUXy0QjsAcqvFoF/vTKcAVz5DbD35bZPWX/b8jCXKSJAoahVlIiB1U66/H
         V4Y9qilkSG4VBKl+HCrRfyxG4v8L+Gf77k0ZpQA9X8V4N3w0YnqI4jdpO30nuP2Ye8z+
         Xdlf8N15gv9QGFS48TzbSuQV/XmWN7qEIiRhDk7k1ffCXAn2t9tCMjgoceSVxIuqbO9U
         RBoQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=UrqY2fqJx0dtoCQTIgl8qXV5M5X8QFaJlTEOTbWZnpc=;
        fh=2KNG8pWZM1FFLpB08HYKQidB7bFxhRhLQxHWPZMWwTQ=;
        b=iawlW1QxmR4TsIpPupjdlENIq/B+AickqUXmSAdwEQHfltqZrPTNSpqgmO5Lo1agP9
         pdU71wlvSMr9e95q+sVbmpPg4djG5WIO+gsc4fL0Mc9DgIG7Zsx86I5P5wBrqkSUPo7H
         AbX2O3hmnkhUojLZjkuORbS26+/Qr/3iJGMhBGbTZ9OQISGUFWRreyeV3N1GYs+xgW9x
         3RNkc5jYQGuYftjDZBHk63iTPRwWO+0lPnzOxORadsxVltteqUQloem54XV8/wvrG/30
         pYmcQMMRc1ko3CzqaQS5cvOGahEHrlaxPIbaurQkv5bus4rRYF2vyzJtdEm0qxKn4mV3
         V5Lw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=pz4rspAq;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe13::813 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700426854; x=1701031654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UrqY2fqJx0dtoCQTIgl8qXV5M5X8QFaJlTEOTbWZnpc=;
        b=Lr/XkSjc+ul3xn/609t2fbmxQeYXtzxYc6eEPcf8ApGmObUDfDGNJxmDrGlxb+kqw7
         VgP9Bk5H0QyVIUos+L2yrc9XkU0K0EGIh6hFEB2ACFMjd61zs0O25FTTwDuUveZFChVv
         4BisLAdEknlcvi8o+YbudWyQ/rBKD8b2NFCd4O5lqr5lXZZ1rV83cko5IxapKe1XNM7h
         pgSY/o/CpfzUg0w1IGiZQm/TIZXvgmSNhFiLnZK46yoqA8grFht2BLjeNRr+4RjC/jkW
         hsWzONzPLyD7NPEBOhUFVN8/X1ylNT+7D9+sK+uXKy2LPwa8A62jVE2vuGHNyzcUqyXt
         KaZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700426854; x=1701031654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UrqY2fqJx0dtoCQTIgl8qXV5M5X8QFaJlTEOTbWZnpc=;
        b=Ea2HR24j9QIN3Lo1uOKnDAJtpI58t7u08eQUgknt5EdFBoJX/0tJfN/P9u9q5VwR97
         pS/t+wMSHNZcStCYBpufCneZsgKoCtdaCOdcN+gTYfTxgIJtGTAk6AIiXQ2dMmlcRvdw
         SJA68dgBhRVkDKQX8A05GI44VPVbeoKjxi5YVlx0f4+vJZcJUenlSlaykudJy0ME6TDo
         AEu3eJqUpRo8IyeqU8HPUn/psUkp2Lucy1Ab+PR9GY87cvFvtVQzAcJoo773Thvo6WW1
         JQbwcbKQfMNJIEfbiI6Y89QRBOz5HMzgn7feZNoRW5dCHveQ7Sg/XI1lIuDK9RkZGOpC
         QkRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy6gxCxq7TOy+friPZ6kJLkifByeEt+/bQ6EL5CLpzBSPFZD4NF
	Mj+OVGLh/TdlAjdqDesJAeA=
X-Google-Smtp-Source: AGHT+IE8u3yly/SwKJiTvifLnUMr9dPMOij47mRQezH2bIBkHmO7M7CTYTAl2CQjfvs7PPTv5tI2Aw==
X-Received: by 2002:a92:ddc9:0:b0:359:6d7d:d2c1 with SMTP id d9-20020a92ddc9000000b003596d7dd2c1mr4674629ilr.0.1700426854396;
        Sun, 19 Nov 2023 12:47:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2182:b0:352:6621:64a9 with SMTP id
 j2-20020a056e02218200b00352662164a9ls777708ila.0.-pod-prod-01-us; Sun, 19 Nov
 2023 12:47:33 -0800 (PST)
X-Received: by 2002:a05:6602:1a86:b0:7a9:4207:289d with SMTP id bn6-20020a0566021a8600b007a94207289dmr8808281iob.10.1700426853797;
        Sun, 19 Nov 2023 12:47:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700426853; cv=pass;
        d=google.com; s=arc-20160816;
        b=WQNr5jCez9vn2I9ZoDAgXt6YHsobPQqWOcGBs0AzGGisGttfq0YhqAAWubrev6BFL5
         /Xp3zWfjuLuUub2B5jDZdll/Puc/pRoAVYaqVG47A3HbRKXu4e/uZRHeGT1vcvFHa/+0
         9PwBPrmiCl3SY0MVxsaJV/+triqXBQpYV16j51k9XpHY2sU0aetBlPPiJg+bNfLYLq1Y
         SKWt5WIGIkAOOkibzWEGxx4/QJ/C/Fm7NwHFtDJfvIKytsm5nDDtdJWfbKkA1B/26TY5
         tX/8uPFCl4KGCKpCVMdO5sRLHIsColrQBBQACGeybfwLBY/xXQSS8zXGHH2M/aRNV37b
         g+iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=YsUMSVOnhh1wXQpueuIRtJL4hWzd409vv6M7e5vGF54=;
        fh=2KNG8pWZM1FFLpB08HYKQidB7bFxhRhLQxHWPZMWwTQ=;
        b=0GinYKycZRGunOPuMXRr2lNodM4xdfDmZY+pV0b1Poko21cngsvpKeW49nm28Y8WKw
         AmDqU+3bpHx+3VzWymb5j1IMEXautrR+wFtdloI9oQ2lzl8JLTWWoO/i1tz+XEmFw09l
         XBWM0B9EBFC3j6adr8ueEWzBUzCheEAZW7uhmPrsJx6QKFuutrzICuSRhKtQ8CpCs1ch
         Fsw1loM/6hA8dtc9yrhNEK7+1nw6LHam6Jsbul0AI+ZbFdoSyRyIxbWSR/K2jMfPX2Lh
         bs6sHg/xt0Ga68iPN4aotdPAdN6X3UoYGQHMiLFbxk/wJvIRBdtz28k57uew9nnOzNNg
         k+Zg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=pz4rspAq;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe13::813 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR02-AM0-obe.outbound.protection.outlook.com (mail-am0eur02olkn20813.outbound.protection.outlook.com. [2a01:111:f400:fe13::813])
        by gmr-mx.google.com with ESMTPS id bz7-20020a0566023a8700b0079f9c4f99absi406486iob.2.2023.11.19.12.47.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 19 Nov 2023 12:47:33 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe13::813 as permitted sender) client-ip=2a01:111:f400:fe13::813;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=dZ6TCziyavlHj10hJp3W403mcCfqTNy7a/oRAmRuTjcTCqBlgdPQxqz0r2xzu9CmSveK8D/+Kj/MiIhJuFuWvN7s2WXmYJxPoF6igf0UbhBFIjxgZb3M0JNJ7shhsjXPJHGqi3ZFUX1/DRNkujwQtTNQ3Mn4tjSOBAEEwkuBiMQbgZYPt5JOqzfkgA0CNUNLxzrZGJXE60B05vh9VRFEakZ83fWjht6IFcuaa0PpYLr8IA6biLXwXqERAWWQQ5W6imE/qWqyXA58Hff/NQGCrXWC8J1sPEc9ZtxQclEu5MSjS+17eISuqDYGR12NwkKaymDmxRx+biUOM1ykbN8PLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=YsUMSVOnhh1wXQpueuIRtJL4hWzd409vv6M7e5vGF54=;
 b=nuHGYU23NVh3g1EOwNmddWjVH/BxBIzZROjT8n1gt3kQfuz2K9MVi+WBDuyeP6EbbrsYIt/QN7DFwYHSw+pRp5xw2vNbME00xvTKd81kdmYU78kz8gUAN7BA3j4mbFm6e6bH7X7uEFUXhm9ZFkU6w2P5NOiX8Pkxh1z7nkKVcRnydZOCxYzRDqox/YYIxGJtWeklTqEsM5ochyHPM0Qrs3/Hfjxp9p4mMVyEKVsJfGuR6r6VNDpG9WFFJ7YJCi9G9qy3/g1qhyWGcWqn2qy3jEmR2p45ApMjhp6FV4XkC6egPUQhuxoGYLinIGefSN6S9dG12LE0NQmwgYk1WQGSAg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by DB9P193MB1354.EURP193.PROD.OUTLOOK.COM (2603:10a6:10:2a0::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7002.26; Sun, 19 Nov
 2023 20:47:31 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4%4]) with mapi id 15.20.7002.027; Sun, 19 Nov 2023
 20:47:31 +0000
From: Juntong Deng <juntong.deng@outlook.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	linux-kernel-mentees@lists.linuxfoundation.org
Subject: [PATCH] kasan: Improve free meta storage in Generic KASAN
Date: Mon, 20 Nov 2023 04:46:29 +0800
Message-ID: <VI1P193MB0752DE2CCD9046B5FED0AA8E99B5A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
X-Mailer: git-send-email 2.39.2
Content-Type: text/plain; charset="UTF-8"
X-TMN: [SDLZg+o5aRh8rljxMKf9GYjanOwFCPPo]
X-ClientProxiedBy: LO4P123CA0068.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:153::19) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <20231119204629.50560-1-juntong.deng@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|DB9P193MB1354:EE_
X-MS-Office365-Filtering-Correlation-Id: 3cb3973d-d264-4571-b623-08dbe940c005
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: ioV3GNxZUGwzbi/BEEUl0gzZWb9LAeS7OutWNDIxlenq3o4+taZRHbmYYqT9lA111nA581bCHKFdi3hJ5jJOcY8VGH+KvPFmgjoz5gN7Qa+pDLY5fPC9iEuhQqgpDgE33Y/eRVYvX1OxV80rjtUbFEuuyq4SBeqPeFbmjiCfB/v5X5LjqhNrr1NBJe8SP9ee+EBM0WXnbkP8zZUMj3Pae9zo8En389hsT7Cv2rjiAixev33SGRet1dqkONR/jDBJH8eAiPdKpl5fO7UqKQmMQ4Tcwkh2lT6ogcb6onhmAWf12M20FeXcrVhEnGahSn4+ylcIshP1ChryAMRmhxSjqP1mg0qzHMErnIxQ6pbzQkGy1MAlwW2R7AM5TjXSlGA5DHeoFapaz677/nxbsvCQnjAjaNJvHzGICk30lI9am/115hXWVAsUvEjVLPah71sGGxX9rWLGb4kIw7S0N1qQ1FlRTEYrXuv0QSD9hzUz5hUAnhOgp5SWN51lURZPlgSK4QNqiExaSV9qGpi5292pjBTIBwPcVBoVE1crzgT5BMxJu19AI0QQWYeBB8/3BC79
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?WjmwsBQ18Spe/TmVvGEh0LyWLWl7JE5KdCho1V6eRVQEYgxzcRzHOfLNdUJt?=
 =?us-ascii?Q?r1xS4KkuybMzQbfcYDZTvxuP3wDETcFdYm4KTHzRTlXDDjFwUMuVSpw3mBJq?=
 =?us-ascii?Q?WyFAPkRnpq3CHVcK+zOgmj+rlSNlORuCG+8ZrTfL0+mWA6SMtWvOjHG1YVAk?=
 =?us-ascii?Q?0UKJpgAc0Bg2pNgJOpLq4STi9vWdvxyoTtkaZtE04qdz/W5KhB87DoaHvhcf?=
 =?us-ascii?Q?DQyovu5ZueTokgf1ZTDMVWJJ8lo7QrUZ3f29WQvU2r6DnMVoXpwruY+z7tDS?=
 =?us-ascii?Q?zQctzF1NX2/17wdr4/p0tRW48Fgxmh6wArQEFtVTkG+R1gl88jnFNlEp1uvA?=
 =?us-ascii?Q?VCXc+aCk5hHX8qy//6RPDOXBcQVAqBpivwHM2FMVCroRFlmyEQMCb+nuXFMc?=
 =?us-ascii?Q?9rnUPlrG29X73ws5CGwzn6GMEugOPuP13LXfSzcMglsoC1a5VF+uKSAedw5U?=
 =?us-ascii?Q?SMbRuZKpv/Of7r/32eRPuvCyt14c1LQysfafyc4oOW5bfhI5lPlLHN3f82Ak?=
 =?us-ascii?Q?18C73l+2CJr89GjhhOdOWEIlgHjrFAMXlkPZrmbDzooEIvjULtRH1mS6U2iq?=
 =?us-ascii?Q?xLYSWI2d8AJQeHJ5krlqf7bbNMAb2E6HB8LH4nvzSQdzOwsMITJ5u0cXHbs0?=
 =?us-ascii?Q?f4WlNPHebjAC4sIDDCBd1OMcrxXITY+tIyqJn1Ojc0YmAisbNwBF/PpyPvH8?=
 =?us-ascii?Q?LiafAvn/Y4EAm1qsx10KB8eg0UAy0I8St38raLXXQhin8T4OVXUbYajfVD3/?=
 =?us-ascii?Q?9+buoiKQiSrv88icdTt6PeIBmLZiO/biNSnt4D01VDIoxYjG4wNkHkRR3hlh?=
 =?us-ascii?Q?e47nTKsaDSOBFbpRxLevrFwoRKGk8NQsSp5yHSH+z/A9G+h61RufRRmVjbx3?=
 =?us-ascii?Q?fr91wfWeXKPx6lMBlpoWJuSZk0wIUAEo1evGTJ3tGAryvAlz5r87VwVWxxmF?=
 =?us-ascii?Q?+WK/RMFj9NK4WLFXdowOK/4/7f/kriC0LZFaBGFzPirHkngrHXQngy90MjvE?=
 =?us-ascii?Q?MS1BsBu8+2BlVb1iGaD8duWZVgYc9f0ws+SFXaE3FIwlBOUaTOV76lfp5yrM?=
 =?us-ascii?Q?Fdgdlf+GIkT8uf+g8P2td6LTPlDe6u56MPP6es17rx2P+Gwnf596/SFVWl8k?=
 =?us-ascii?Q?iAgt0IL1jed095pyu/QQYhe6qz698RlKE0e/eaNHkpdI9BkJg+Ej+wJEdiMp?=
 =?us-ascii?Q?ix+fxUJ+xUnDf25WxHunaDJaKI9+uiTwILa9ZQuW48q8+xNdNil/CKvMULQ?=
 =?us-ascii?Q?=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 3cb3973d-d264-4571-b623-08dbe940c005
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 19 Nov 2023 20:47:31.5305
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DB9P193MB1354
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=pz4rspAq;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:fe13::813 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
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

Currently free meta can only be stored in object if the object is
not smaller than free meta.

After the improvement, even when the object is smaller than free meta,
it is still possible to store part of the free meta in the object,
reducing the increased size of the redzone.

Example:

free meta size: 16 bytes
alloc meta size: 16 bytes
object size: 8 bytes
optimal redzone size (object_size <= 64): 16 bytes

Before improvement:
actual redzone size = alloc meta size + free meta size = 32 bytes

After improvement:
actual redzone size = alloc meta size + (free meta size - object size)
                    = 24 bytes

Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
---
 mm/kasan/generic.c | 30 ++++++++++++++++++++----------
 1 file changed, 20 insertions(+), 10 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 4d837ab83f08..286b80661a80 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -361,6 +361,8 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 {
 	unsigned int ok_size;
 	unsigned int optimal_size;
+	unsigned int rem_free_meta_size;
+	unsigned int orig_alloc_meta_offset;
 
 	if (!kasan_requires_meta())
 		return;
@@ -394,6 +396,9 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 		/* Continue, since free meta might still fit. */
 	}
 
+	ok_size = *size;
+	orig_alloc_meta_offset = cache->kasan_info.alloc_meta_offset;
+
 	/*
 	 * Add free meta into redzone when it's not possible to store
 	 * it in the object. This is the case when:
@@ -401,21 +406,26 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	 *    be touched after it was freed, or
 	 * 2. Object has a constructor, which means it's expected to
 	 *    retain its content until the next allocation, or
-	 * 3. Object is too small.
 	 * Otherwise cache->kasan_info.free_meta_offset = 0 is implied.
+	 * Even if the object is smaller than free meta, it is still
+	 * possible to store part of the free meta in the object.
 	 */
-	if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor ||
-	    cache->object_size < sizeof(struct kasan_free_meta)) {
-		ok_size = *size;
-
+	if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor) {
 		cache->kasan_info.free_meta_offset = *size;
 		*size += sizeof(struct kasan_free_meta);
+	} else if (cache->object_size < sizeof(struct kasan_free_meta)) {
+		rem_free_meta_size = sizeof(struct kasan_free_meta) -
+								cache->object_size;
+		*size += rem_free_meta_size;
+		if (cache->kasan_info.alloc_meta_offset != 0)
+			cache->kasan_info.alloc_meta_offset += rem_free_meta_size;
+	}
 
-		/* If free meta doesn't fit, don't add it. */
-		if (*size > KMALLOC_MAX_SIZE) {
-			cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
-			*size = ok_size;
-		}
+	/* If free meta doesn't fit, don't add it. */
+	if (*size > KMALLOC_MAX_SIZE) {
+		cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
+		cache->kasan_info.alloc_meta_offset = orig_alloc_meta_offset;
+		*size = ok_size;
 	}
 
 	/* Calculate size with optimal redzone. */
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/VI1P193MB0752DE2CCD9046B5FED0AA8E99B5A%40VI1P193MB0752.EURP193.PROD.OUTLOOK.COM.
