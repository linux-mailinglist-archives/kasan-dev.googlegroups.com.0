Return-Path: <kasan-dev+bncBAABBRWI6SVAMGQETCOUOXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id BFC917F3877
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 22:42:31 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-41cd5077ffesf102391cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 13:42:31 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1700602950; cv=pass;
        d=google.com; s=arc-20160816;
        b=bmaUoE/yv1lG2QIpb0ObH+apBnpgjfzsufuel//pHMVSs6rflvlSagPK+xQis8eyiq
         CDk8tA38l2rdCD9E551B4kjxI5naXJnevwPBtdKxWVfgUC6M5MQuUAoQjfyArriwpHxz
         pQc8zQv6/qQXPbh92Hz4jJmrKlJKDJdzAC7KrYYkU9ByA7dqJtQxyjvVHprDiRjO6lZM
         oG0kqElSt9vRtmuz/6jbhQjqlP4CDos5uiyWtYwghOqI6KtMGZWMszkKvHpaPzxQSjER
         XOVevMareVaO//faj4ag9cmt2oExZsP3cD4nmkl9lmeVSBomMYS2Kyhalltwy+KR5Z0t
         nhNA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=cUOVwsSD9cb3L52PU16h1gtOwhOdXrBQhNdFP8C61ts=;
        fh=2KNG8pWZM1FFLpB08HYKQidB7bFxhRhLQxHWPZMWwTQ=;
        b=s+/FF41RnznLVN5P8BLjwu/AuDBAJAwJyzOTwfjmJg6ZPXlo19PYptS7W+IwCTQ9jO
         VHq84iRQT5Ryhf+ZXnE/uvVL+3oHv5XzMhNpPmgj3gzjLtoeI3MrEaMgsrB27Hk420ZX
         EC0UuhfsVHhIMYTGfCiLz+16o1URDEHjUSuxZu5UwaYfFvxGQPuVvJQVZ1RFU7hFdgct
         5Ct4xXxfWMvKbWQuojJiTjPO0k+456XcxefI+6o3Ye6MU5t3BRCIW1Sx9iVhmzJmcUr4
         mQzO4AMKB/z3Rq32vKV6OFXNnDQ48VNzGLv32DbG2nuA8ZHWbF32cXSB6u6l7jJEnuD8
         aDFg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=kfT4MzbL;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7e1b::801 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700602950; x=1701207750; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cUOVwsSD9cb3L52PU16h1gtOwhOdXrBQhNdFP8C61ts=;
        b=o/rVWK0SgRtDdrcly3OlooQ9okqZFmKkdstI5Awm8XSA2JkzJ4KCOou7Ixw4mUpzz/
         M7ditICMSdkvpLNBerBedl2vuUZIFfcUY7B5TDPH7x4AxQTgj8CcvEHT8jt4IlyY96hN
         +FV2tNqEjRTfp4aqbkGT156/p9rnp19agnzZBWKvlZ9er3DcuHmCIvc/z4iB0OpLTTZ7
         D+qgCpjOhSSeHdHFSinuhnaEPrfc94oondw6WU8hArH2k5VyonEOTEVU6tRKXTcBF9HE
         ERh2ApX2bVYp827o1+aUKg39N/YuBiGdf56OJvbabpIgfCCJhU3QovQP0dqoKU/IFi/5
         owKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700602950; x=1701207750;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cUOVwsSD9cb3L52PU16h1gtOwhOdXrBQhNdFP8C61ts=;
        b=Ikf80kYzyD6Z2uYPwFRStivm9yKRagWGtIy3qc8HRTQOJSXITZpUS5Xb3v9So+Pc5b
         4EYAirxvobk+hBQn2AmIAaR81p+Vnr0dMmXfC7kNroyPBWCGTogZFTLIEiMW6cf0/6Zm
         ebAPy0aTp8XzvzrZofeTT7t6IeEUy7wchEAWOrsax7tumMdxIp3uvz+dbprZ53p8g7lM
         2q1zPd8/eUewSYSXsttaA5J7/Nkz9Y0PTwul7awAccj/I4tuU0DlMCfbfIWoT1uR0AmH
         zn7sHJTwx3xZHngDs0YyhO4J/EkbcjiQ1n5WpQ64E4X30Gm9+rXeoKiqgBaIyew9ow4e
         Y64A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxhgiapZt2Nx6krZ2WJJZrYw6lbEcz+kYEIQCfIPwlHpgZofLdz
	/iRlmtk+5dwqn7VsxwBbeOs=
X-Google-Smtp-Source: AGHT+IEBZtG1gOwtUv2+i2HkcQEpeGfs7tISRCvQxfa7tH6r1JlukMzPMX9qGX5XIdB36/HTXzi/Gw==
X-Received: by 2002:ac8:7e95:0:b0:421:c39c:3eb2 with SMTP id w21-20020ac87e95000000b00421c39c3eb2mr11439qtj.3.1700602950513;
        Tue, 21 Nov 2023 13:42:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:20c:b0:41c:b879:6082 with SMTP id
 b12-20020a05622a020c00b0041cb8796082ls583373qtx.2.-pod-prod-09-us; Tue, 21
 Nov 2023 13:42:29 -0800 (PST)
X-Received: by 2002:a05:620a:880c:b0:77b:9360:8839 with SMTP id qj12-20020a05620a880c00b0077b93608839mr280004qkn.68.1700602949543;
        Tue, 21 Nov 2023 13:42:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700602949; cv=pass;
        d=google.com; s=arc-20160816;
        b=eRWX1Boa38uPUQ3UYlHjJTdxLPomy3+FNCHjSCpOlCskJvOPygziqy6NYfeoRIeNm3
         sS6dcZ16lKVsJtYml4z2lTflkX2+qeoLKzVzTXa02ldHSvPV/nsywZuGMGXZLhq33wbu
         auYc4gomHBBogvHck7F9Q7vtiGjywGCAfGVqD0/j8BVVOrvvAt2iqOxgjRaN7qpWI7Ka
         kbJtq1s8ksO4Jt1uXvBFRiINW3sHU+CUsn4cYG04lPRNBXbDBZgiEtyopewJ0bMJzEaz
         bX9l64+M/qwisPOru8d2laoPHHPSAWYepctBkO7V1+XOe60bolLo6Msmp0XfBVoLWNcK
         QTVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=29jcc8/33Wt3un8RLmiE4c7QrGd7B8cnl+cNOftp/PY=;
        fh=2KNG8pWZM1FFLpB08HYKQidB7bFxhRhLQxHWPZMWwTQ=;
        b=BN+y9WFwZzvb7hoHXmQP4gQBNoTsc3vhAvI+EJ9tgqvvhnFdVeTt9ZpSloZk65/5be
         P9wq/2a/5aHYeELKSTfCvuA/bTT+smToOvGx53x/ueA1ZLsg/BmUL6dRMKPWvHfUXg8T
         /22C7o/Wrxo+RRng+cO3goqbzniWnyfwtyRlnPi5A12M5cEfBoNontyRLLqiRtRfOwAE
         2D3D0OJ8ErsmNJJnJrCA4LFabSwgjvsFHhgt3f/7JHBdq5tB758AlqruIZcsLUmRlJY6
         VLyQVpTvc1oVOqwFQ8o9FLcHHMRY8AutwnJxhpMLLp4tWhvjPj0JsRnchAYFQjIIraNT
         0vAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=kfT4MzbL;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7e1b::801 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR05-AM6-obe.outbound.protection.outlook.com (mail-am6eur05olkn20801.outbound.protection.outlook.com. [2a01:111:f400:7e1b::801])
        by gmr-mx.google.com with ESMTPS id c10-20020a05620a268a00b0076709fdb678si739456qkp.4.2023.11.21.13.42.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 13:42:29 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7e1b::801 as permitted sender) client-ip=2a01:111:f400:7e1b::801;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=V7DdMUeaeXMK7dydA1E2tkw6tj05plq38ElmULzPln/FGbGMgkXeHFF2MWYxm1HkLbOP+lwHKXw0E8i/y9na+pmnDdUBNcTV9Na9+iOs8Ctdll+Tc1VEmgTydFRWDbFm18TE4hvQ196avKNdaKHTDT0DQMXrxPNdGM43DVs6W+nCXV+B2rWiNasq7i+VHSInFyTQ8mH8U4+trrJvjl2MOaKblkIOPSAMYeyAq6UwEYT9UTXZ2qlyspxOf6HZ53ghh9dk0LcQw51Y2MMaZngUbHl3Dl1SMVwN1ox1E6wsMN/ZtMk9I/s4V79CkQ3glJ9UQK1a0WwC3CEl0d3OpH1uaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=29jcc8/33Wt3un8RLmiE4c7QrGd7B8cnl+cNOftp/PY=;
 b=TABwSwKo5RzKQ3H++98WCVJswhlmyKKvfa10bA4xZMWJbbbkmat6E4HQYNK7f/uUwNYhZhDXnGgwMFxvn/gYWwSLXb9u88i4vNQa8YJxzT1V3H/Q1w5ClW7N8GO7/O0slwlkpmBkba02ntX1Uzdzz4nZTbNMKNWVf5+6vFXqLW658vWw8lljKPVgHbqBSNcrsmONRb9gP+uy1IwgXCLJpmy7YyK49sCVNcZrUbeDM/gdOgsL/oK979SUbnwm7NYB5cQjMxA+LahX6o3LmpUIHYDkqyZm8NSkiAppDKwSnlSkEs1G8HH4rZ1ybKLOIdLDTqcFx2Ye9uL7FVyQgr1CYQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by PAXP193MB1503.EURP193.PROD.OUTLOOK.COM (2603:10a6:102:13f::24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7002.28; Tue, 21 Nov
 2023 21:42:27 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4%4]) with mapi id 15.20.7002.028; Tue, 21 Nov 2023
 21:42:27 +0000
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
Subject: [PATCH v2] kasan: Improve free meta storage in Generic KASAN
Date: Wed, 22 Nov 2023 05:41:26 +0800
Message-ID: <VI1P193MB0752C0ADCF4F90AE8368C0B399BBA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
X-Mailer: git-send-email 2.39.2
Content-Type: text/plain; charset="UTF-8"
X-TMN: [aBStXIVnfS+GP4EU6rrNTwppYbpfxVCc]
X-ClientProxiedBy: LO4P123CA0568.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:276::18) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <20231121214126.53528-1-juntong.deng@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|PAXP193MB1503:EE_
X-MS-Office365-Filtering-Correlation-Id: 690f3537-efd0-4c59-dea4-08dbeadac14b
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: 3HPfTPT0ur8NWreQU5zYm+w3m1DIR2Z8jGAxOyYCSUQTSp3oNWFyMlfM+Ns6If44pkzMEdD/lxL0f1BMomF+VLxZJqmvFo31wufUahRDJEpJKMdB6+FHNW3fiAj9JIJUPiGn9OJJMljkIdkaRvfrCjVZrUdMprhusgseI8X2LB+gWq69da16eiktbL4sQcYOisCVcnDzXMpECjqCxZCKBvrLCZqEv8DR/JUhBe43CezOdRwgolzHnyNNZlKs32lYJgUK/9jIfxCBgF/ui0rdei6uk/5MtwsZ8iQG8KwUr73+6GMKOzV7yAIRMmywoAkmef3kuz4sVmxWbWoPuvraY6f2KsVQJdlWtjGecuS/NSn/ae4K06FxnHjQyvd1a3+Vwh7Eg5hv8ztaAa+R+9NEGXWrID9vsuNk7KpIVqKJRkDO0nxOeMsRibgVN7fJTmLrU0JU6EG0hw1b6XjSQDYAAyUT8/Fpb7cQ/5OQn+uVXgu6MoNamFxX1qnFnY7DhoCbYSAv7eKdcWHSMf9JpiBTb+UABRie4DR+WEM/x7JHKEQI2nnYKYSYLFr6l8kZXDWq
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?RJ32V+mru7FobK8CEA2A+P1u2wj/tbSLUNbI1AHLGDTvqnldw2ByW3zf+xy0?=
 =?us-ascii?Q?uoMn3vy1Fl00gTgrz1FrSap+SXToLJLKuFb2IiOSpN6sf3Laur8X+Jh2+AX+?=
 =?us-ascii?Q?QZ4cO3lKobuG23zsJBjm6wz6LsudtacvSvebbcVXZAF61lNRiZ1ngRAlZ8rn?=
 =?us-ascii?Q?BZ0ZhpDB75bmvcrTR+IneRpNK7MT4CqQCtOViBjHWj9CVbwtgHI7PfTFzy82?=
 =?us-ascii?Q?4/VijxQcdhPer/qnizDcW63JQvl/fSYNXCEtu2gY/drowxYZdelWVa9PfFAW?=
 =?us-ascii?Q?3GQyhw4KT056qnkFULxEqkTqMClu7mtR4Ker2/bjP0+fVB6caOuUSuNZ8NCj?=
 =?us-ascii?Q?SZrgGaxgVRC8HknbzSx97EmVULeQDVgGvkFh0tQHytH99Ffe3AdfEptUauML?=
 =?us-ascii?Q?0NQqLEizi64rcPfKv/whS6rqDpmiT8Fnk4Et03ph3+OxrUwsyGqa5e6ksYYE?=
 =?us-ascii?Q?fz8tsIc+31Wp6K64Hh6/q5si/tn+fpTK0qFep4H3afm2vFCMJSN7vJqtFcTT?=
 =?us-ascii?Q?hA2yFp1zJctpPT7gviu9h6bxYuTJCBSZwiUcV4QyAxsiMW/p1DrgEaDHGwlh?=
 =?us-ascii?Q?SdrFzUq+JdraEwtJTbBubOY4vSpsq/kUs0DBnDHMH7u1V+0wgr+gMea+6VTP?=
 =?us-ascii?Q?YwHqkbLS/Rb7kxho2iuJ3SJWMoyvuC7Fcg/Ctkc8xdYvc2Zfe0O7yaqI2TUq?=
 =?us-ascii?Q?0zs1+stTqyXW3KymMjqi0DNqWAxFl6pc2OkFF8svjJBhx/g2bT7QtzqVXJyQ?=
 =?us-ascii?Q?/MzX3IbchXPB7kxvxROApLZPb52wMzipg6crM8I8QYxWzNOqvpet5zTTDRYq?=
 =?us-ascii?Q?YIQcgWXUoyviC08qyf3Dzn6WbUb6csqQwG3YAFUsIf7H577rmmkddnLrbJm4?=
 =?us-ascii?Q?ArfPKscqVm6NOK3xnXW81EewoPSbKuN2JrHGHsriuSsDcI2R6HgeWVP+Ey+J?=
 =?us-ascii?Q?pWAuS0LA2W+pt78zIav/Y5zE7aEDXTBH5x/tIp3OCTdbIOjloz6qSVdZ8eEe?=
 =?us-ascii?Q?EtkHAwZCYEegLGmchkVVafM/jFtUBwBLi7azGQOl3rLgUtLt6fFdVPzK216v?=
 =?us-ascii?Q?SxBf1K2RuIG/BHmq5cC9ZML9xjT6/48Bt0kLK720t/RRzNXWTITiM43lfIDJ?=
 =?us-ascii?Q?+DuVLp++g2HAxn/EB3oO5rUoQEQi4g06N8MLIjoHUNw/zCweDMnMcRQDfhUW?=
 =?us-ascii?Q?GgAqs6U6Yq4Gd9Vvf8WWa6zY1i0f/kd6Nz82FGmlyzwy938ijvxNmeMMGAw?=
 =?us-ascii?Q?=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 690f3537-efd0-4c59-dea4-08dbeadac14b
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Nov 2023 21:42:27.8261
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PAXP193MB1503
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=kfT4MzbL;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:7e1b::801 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
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
V1 -> V2: Make kasan_metadata_size() adapt to the improved
free meta storage

 mm/kasan/generic.c | 50 +++++++++++++++++++++++++++++++---------------
 1 file changed, 34 insertions(+), 16 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 4d837ab83f08..802c738738d7 100644
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
@@ -464,12 +474,20 @@ size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
 	if (in_object)
 		return (info->free_meta_offset ?
 			0 : sizeof(struct kasan_free_meta));
-	else
-		return (info->alloc_meta_offset ?
-			sizeof(struct kasan_alloc_meta) : 0) +
-			((info->free_meta_offset &&
-			info->free_meta_offset != KASAN_NO_FREE_META) ?
-			sizeof(struct kasan_free_meta) : 0);
+	else {
+		size_t alloc_meta_size = info->alloc_meta_offset ?
+								sizeof(struct kasan_alloc_meta) : 0;
+		size_t free_meta_size = 0;
+
+		if (info->free_meta_offset != KASAN_NO_FREE_META) {
+			if (info->free_meta_offset)
+				free_meta_size = sizeof(struct kasan_free_meta);
+			else if (cache->object_size < sizeof(struct kasan_free_meta))
+				free_meta_size = sizeof(struct kasan_free_meta) -
+									cache->object_size;
+		}
+		return alloc_meta_size + free_meta_size;
+	}
 }
 
 static void __kasan_record_aux_stack(void *addr, bool can_alloc)
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/VI1P193MB0752C0ADCF4F90AE8368C0B399BBA%40VI1P193MB0752.EURP193.PROD.OUTLOOK.COM.
