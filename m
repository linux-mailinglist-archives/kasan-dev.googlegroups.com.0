Return-Path: <kasan-dev+bncBDBLJCHX2YFBBLOQSGPQMGQEATG3TRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id D34D668FDEF
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Feb 2023 04:27:41 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id iz20-20020a05600c555400b003dc53fcc88fsf373870wmb.2
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 19:27:41 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1675913261; cv=pass;
        d=google.com; s=arc-20160816;
        b=K9U6EKk5+3DqR8JZQwnpiB+aVZGOudTsv8w7cXbStYvTTFjnPeGOP/nEgHojdWRxDV
         zrNANQur6oOcIQR8EDdNHeTslkdrWAwPCieyMXJRPecNfDt9mj1Q1shbcQo3Q6hyA9+l
         hv2IhxVTwS9rX65hOfIE9d3paQbKn/ifViBgF0ao4lbY652UJqncY5qX3unRCTVmF6R1
         YUc/ETVTmxCtXeXhjyRpQEGuF8UquTikCrZpMKTQYN4pp6IqE7/LqWuKgENyUvCsFeF9
         UN6WkecBC1lyhwPlsGQSpANqk6i1JjZaxIlWHm87wX2JRBkqbddJI8Wz6tca0hwF7T5w
         MwQg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=47IEItZLzbKwAGOXkaEDxVnHO7Uw6C2yqOzlDyrvAzU=;
        b=LDcuP7Oj4g5n4cmgZ1vYOyIjxmjfrfx1DPZne03TkZYe99v4bSFwVbQKv/gV1btFbD
         t2SRK79VIE9FMCUOXBIPQ2JaPw8qhZmUvOT67FjrIH8JMEITXxU5uX1jwghiiHWDe1tj
         XIXBKkSjKG+XxiwQkfFEbXb2Y8DqaGCSPvqYFE5K461Rci9ZnjR3K4SrXwolt0RNSnbB
         zN3pCHQm1CFknSfZuuN9rH2yT1ZwoeIk1VXJAXr4vc9lfd/QOqRVSk2WnhH5QzKxBJC4
         v0zVdP+wRh7zwMM72q003cyehIqWYje6a2sg5hH7X2UnVJw27t8vFMlHvLl5NvAIuGJ/
         AF1A==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@zeku.com header.s=selector1 header.b=IJkFn9sK;
       arc=pass (i=1 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);
       spf=pass (google.com: domain of ouyangweizhao@zeku.com designates 2a01:111:f400:feae::70c as permitted sender) smtp.mailfrom=ouyangweizhao@zeku.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=47IEItZLzbKwAGOXkaEDxVnHO7Uw6C2yqOzlDyrvAzU=;
        b=aDgH3QYZRzu0IkZ1AGCa0T8GrbkuYYHnOlwwGxujkQl8PyK8gRXxYiAByONkUfNB8P
         owcHDRR7P+8rX9lDJFNH8TgtVv94nqrVGW4BnSvz+7jUeC7Hd8OY1iJLnJ2f9zID0UyG
         S6XVJzCexXTtKctgiUHcJnukihg9i1NsPkpf2JN88GdONaoFy4irtxj+7Qm4DPNOlMJm
         dgysYjAO44zZOVfnpaLRO9RKJo2rIy/yPPL26ws/KK8OlFKRRC7ZI3bgYF8EwDyYhML0
         USwVPKBd8HNKlmx8EWRjgZQ788vMBX0R4gTVEGRtc+pDDOuBMwOLW75iLZvUVwdsf5xs
         xS0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=47IEItZLzbKwAGOXkaEDxVnHO7Uw6C2yqOzlDyrvAzU=;
        b=nehBLgaJd6jrmDYSrS7Yrxvaw+FI8rX1HRnJPzU75o2WGQ8PfF8AI3OFHKxt2QjwgN
         qCQF1a00st758hPuL5XCHWl62XVxX0gCOna2PWrK3IuBH9Ry5k9bdt2MgjsBwqkOxFrh
         BZEj+b8WLSguf6TG5ydodcJ1eWPrxgDthHZsnXhc5rDv3iRNJy9+Nehzq4p2GSkIYga3
         rr+8PsgsSrBYVTPFoY0n/+hCmYTYClEdSLNDsNYJK70gy3T6+CEGulXr1thQN1o7psNf
         Wne0uFlhiIVzL2Byenr97bLkHAnQ1n50Ng2KowmWcX/1JOVUTbAJg4sBz0SmoIfXKQtJ
         LYUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKU8WzGiuaZ4VGYyIuronMCenJLa2LfO7x59VAEyHHnfsUkYmo9k
	WmFS/sTcuFes+63O5XLuGy8=
X-Google-Smtp-Source: AK7set9gIHZw3sGRwbe3ziJrbVcuVulJYJ1UJA5c1CvLptLvhs8TqCkCoeuu72EFFSWjBsi/kghypA==
X-Received: by 2002:a05:600c:3b0f:b0:3dc:51e5:45d3 with SMTP id m15-20020a05600c3b0f00b003dc51e545d3mr325334wms.138.1675913261422;
        Wed, 08 Feb 2023 19:27:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d06:b0:3cf:72dc:df8 with SMTP id
 l6-20020a05600c1d0600b003cf72dc0df8ls1999343wms.0.-pod-canary-gmail; Wed, 08
 Feb 2023 19:27:40 -0800 (PST)
X-Received: by 2002:a05:600c:4a90:b0:3e0:ffd4:bfb2 with SMTP id b16-20020a05600c4a9000b003e0ffd4bfb2mr4751031wmp.4.1675913260184;
        Wed, 08 Feb 2023 19:27:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675913260; cv=pass;
        d=google.com; s=arc-20160816;
        b=nLhLJpECSjZFuloofZiYoyPjqx91f2EVE/8s1hpRfsAcYjQ474qsWzzCIGouRl5vxM
         xirtJSxNygXKCfJ1j1ArSUfh8PCODx9Ca4kCERoJckmy0bzAb/tE3SwTevtLCNBcDCpn
         L9DDvmFItWbMdKTE/AjAj7Wf919WVWLsq5Jmj9shq+sNB1wiU8RY35d3oyNd2MAucfws
         nfDqUz8MuaYht+a8nyxdqZw/4iyTOGGKd4CZ7Ke0DD5fI9RWnxJ2R9R/IWPan/yId7dm
         xp//jAZig2U2gtqhdeU7lWRsSOEP4WgvxlBBTHVls7anc5CRaj0x37rU23qK0gvWoumG
         oyNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=CMsTfoXAVz7HPkrgNVxHHrE4a/fTKMFzP3+DIvN2VEI=;
        b=ljPfUfFWmvattPKsGXhocD4xypNmZcMgU2RLguflNgg3pH71kIVKuEI2lKV3o1IZlM
         HbgP75A7gYgcGY8OFIs9h2zhPjoU5DbQaL/Gi128y6XD9eJiB3YLltyyS3WbTw1F543v
         p3Yw6vR56H7ob9Ks4w5NAeK1R+UhxjNA2uuZffcoCMN98Y/sZiSBOgOIV/t2O3SK1Lux
         Hc/ssbFFoEXNiaG/c+Od1M33uJmoT4ZMGixx8EwmElTWPHV97PhiIKCjAUcm9Gdg6MlR
         LoNBI/Q1Rqo/AAJwxxcRmLQcxwjbMp23a4Im7HMFc1v8al/YF1wmQGxwT3l2cmCMlwbb
         7sqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zeku.com header.s=selector1 header.b=IJkFn9sK;
       arc=pass (i=1 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);
       spf=pass (google.com: domain of ouyangweizhao@zeku.com designates 2a01:111:f400:feae::70c as permitted sender) smtp.mailfrom=ouyangweizhao@zeku.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeku.com
Received: from APC01-PSA-obe.outbound.protection.outlook.com (mail-psaapc01on2070c.outbound.protection.outlook.com. [2a01:111:f400:feae::70c])
        by gmr-mx.google.com with ESMTPS id gw7-20020a05600c850700b003dfd8e47092si36064wmb.0.2023.02.08.19.27.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Feb 2023 19:27:40 -0800 (PST)
Received-SPF: pass (google.com: domain of ouyangweizhao@zeku.com designates 2a01:111:f400:feae::70c as permitted sender) client-ip=2a01:111:f400:feae::70c;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=j1sv53BuXfi62XjcaFBJDDvBM0U/wdOiZNHF9LOjdc5w9wdL9D378SNbTljqLzgFstQFJrX4Jk1ZrkyWkodqMQxd1JLksjfWq/KFedt5VMI/D3Q+XFKq7Fry/2+/D+aHoZ9sj34XoCvsBeOeE13E7bkAroMinYEvjbSXck241yT4NhEHP8sBQrPP4YSvtqhUV6VxW+ma/xT9C01gsU/D+SZ6/Vl/GEtBGeOOvxaUdi2sbHQnEHS6lhp6TecAQsoFBTU8UubLzPUzE2fzkavUruUNXNSI8m/rdHq2d4eyDK7hH+siGUaRwSCidOglFNs71jpne1p4x7fb17+vV1KQSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=CMsTfoXAVz7HPkrgNVxHHrE4a/fTKMFzP3+DIvN2VEI=;
 b=XtnV/vTnrzZDVHRbMCNSvQ0qJ8DZcyEgl58FvxVQ3DPZlLQ8Cn6bRGl8ZZsdiAOj42tPNtc6dlUtoSGk4QZQxEn/XCQ+OnL8PJ0dFqRCjs5+1Ou1pMStiAn6Z9T6/ZZ5c2uClSWPmMC+U4vnoV0erlLN6U6t8/9fC+A+Zqf941YuNxxYtKGAaVp/OR00tbcOwB8jyoGsYb0Z6ymCpkCH00uUOScTf1GuBIl8tFD6P4Y2aoMm73N+kWN8z6s/M3atLvcvjRts294pgW9Hv2q7+Qf7UhfZP4F+yZnRtqxilIUtbThdtChjI+vJ2fKc15ZHEqCFQa8oVmCt4J8busF/TQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass (sender ip is
 103.192.253.182) smtp.rcpttodomain=gmail.com smtp.mailfrom=zeku.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=zeku.com;
 dkim=none (message not signed); arc=none
Received: from SG2PR02CA0051.apcprd02.prod.outlook.com (2603:1096:4:54::15) by
 SG2PR02MB4347.apcprd02.prod.outlook.com (2603:1096:0:5::12) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.6086.17; Thu, 9 Feb 2023 03:27:35 +0000
Received: from SG2APC01FT0026.eop-APC01.prod.protection.outlook.com
 (2603:1096:4:54:cafe::d0) by SG2PR02CA0051.outlook.office365.com
 (2603:1096:4:54::15) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6086.18 via Frontend
 Transport; Thu, 9 Feb 2023 03:27:35 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 103.192.253.182)
 smtp.mailfrom=zeku.com; dkim=none (message not signed)
 header.d=none;dmarc=pass action=none header.from=zeku.com;
Received-SPF: Pass (protection.outlook.com: domain of zeku.com designates
 103.192.253.182 as permitted sender) receiver=protection.outlook.com;
 client-ip=103.192.253.182; helo=sh-exhtc2.internal.zeku.com; pr=C
Received: from sh-exhtc2.internal.zeku.com (103.192.253.182) by
 SG2APC01FT0026.mail.protection.outlook.com (10.13.37.85) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.20.6086.17 via Frontend Transport; Thu, 9 Feb 2023 03:27:34 +0000
Received: from sh-exhtc3.internal.zeku.com (10.123.154.250) by
 sh-exhtc2.internal.zeku.com (10.123.21.106) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.12; Thu, 9 Feb 2023 11:27:34 +0800
Received: from sh-exhtc1.internal.zeku.com (10.123.21.105) by
 sh-exhtc3.internal.zeku.com (10.123.154.250) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.2.986.5;
 Thu, 9 Feb 2023 11:27:33 +0800
Received: from localhost.localdomain (10.123.154.19) by
 sh-exhtc1.internal.zeku.com (10.123.21.105) with Microsoft SMTP Server id
 15.1.2375.12 via Frontend Transport; Thu, 9 Feb 2023 11:27:33 +0800
From: Weizhao Ouyang <ouyangweizhao@zeku.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, "Andrew
 Morton" <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, Weizhao Ouyang <o451686892@gmail.com>, "Shuai
 Yuan" <yuanshuai@zeku.com>, Weizhao Ouyang <ouyangweizhao@zeku.com>, Peng Ren
	<renlipeng@zeku.com>
Subject: [PATCH v2] kasan: fix deadlock in start_report()
Date: Thu, 9 Feb 2023 11:11:59 +0800
Message-ID: <20230209031159.2337445-1-ouyangweizhao@zeku.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-EOPAttributedMessage: 0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: SG2APC01FT0026:EE_|SG2PR02MB4347:EE_
X-MS-Office365-Filtering-Correlation-Id: 5e1cfa4d-addf-44e7-25ac-08db0a4d961e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: YPH2u0bp0ju5wCWJXcCtE/QYoZuaJu1/882wCqkNyaVht3NOrkfzFtc6hg5shXdZfVptF8XNfGh2h/I/VW/4LvIlKbKGCxeTVv6ucePatHtEpibCwdBvVohRDUd8LjHbhaMfPGZwRhUnhdzvljpqoYfjcZhJzxuKZLKNAt3xPZDp/8b25MRSjgOolpqWLTDDfi2b+E0Aue8OI06zykg+DSa6QiTJUaOp07I/Zktwv3rTBzQyD+gY2KJ7pmWe4/Odtj727BKp1FCC8MkWlOHNXNk16HOKi8lQaxu3HZzgwmpX79Claz0FD19ZSUjmqxi1fFRYWqXoafMiVfIqFJI2KjmIXcuU7UdEniQzHs7rxf35mufs8gig6AAPbUdm9pEcNn2aHq1cGkCpML6cUl0fHaxrciDo88ql7jyr34vfo67D/Tc/40Mx9Vsh3cRzWvHkhN1moBiH8m6RWG/DTldJiNt5k7tjmgZEgosMyfc4XMrBdlqUtA8FMFJC0jv1qi8zXUv7ptrHpMz0x6/rS63MWijiDihuL8P5KDjy9Nq/HqLa9KhRlHCLpvfmfemLJzxccsnS27j8t447DgZQTt7RnyHFVB6J+KlrsExxJojKvqdO5jESPXPfBzm9rXvPwej35IWxI+zXsb3Rv7OaU+EGW+1PezKq3egxmNeFTNEZN7mtIeXQBmkKLdj9ya0TGeat
X-Forefront-Antispam-Report: CIP:103.192.253.182;CTRY:CN;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:sh-exhtc2.internal.zeku.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230025)(4636009)(346002)(396003)(376002)(39850400004)(136003)(451199018)(36840700001)(46966006)(70206006)(4326008)(70586007)(8676002)(336012)(36860700001)(316002)(83380400001)(110136005)(54906003)(86362001)(426003)(5660300002)(7416002)(81166007)(356005)(478600001)(1076003)(186003)(26005)(36756003)(6666004)(107886003)(2906002)(47076005)(82310400005)(41300700001)(8936002)(82740400003)(2616005)(40480700001)(36900700001);DIR:OUT;SFP:1102;
X-OriginatorOrg: zeku.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Feb 2023 03:27:34.8968
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 5e1cfa4d-addf-44e7-25ac-08db0a4d961e
X-MS-Exchange-CrossTenant-Id: 171aedba-f024-43df-bc82-290d40e185ac
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=171aedba-f024-43df-bc82-290d40e185ac;Ip=[103.192.253.182];Helo=[sh-exhtc2.internal.zeku.com]
X-MS-Exchange-CrossTenant-AuthSource: SG2APC01FT0026.eop-APC01.prod.protection.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SG2PR02MB4347
X-Original-Sender: ouyangweizhao@zeku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zeku.com header.s=selector1 header.b=IJkFn9sK;       arc=pass (i=1
 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);       spf=pass
 (google.com: domain of ouyangweizhao@zeku.com designates 2a01:111:f400:feae::70c
 as permitted sender) smtp.mailfrom=ouyangweizhao@zeku.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=zeku.com
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

From: Weizhao Ouyang <o451686892@gmail.com>

From: Shuai Yuan <yuanshuai@zeku.com>

Calling start_report() again between start_report() and end_report()
will result in a race issue for the report_lock. In extreme cases this
problem arose in Kunit tests in the hardware tag-based Kasan mode.

For example, when an invalid memory release problem is found,
kasan_report_invalid_free() will print error log, but if an MTE exception
is raised during the output log, the kasan_report() is called, resulting
in a deadlock problem. The kasan_depth not protect it in hardware
tag-based Kasan mode.

Signed-off-by: Shuai Yuan <yuanshuai@zeku.com>
Reviewed-by: Weizhao Ouyang <ouyangweizhao@zeku.com>
Reviewed-by: Peng Ren <renlipeng@zeku.com>
---
Changes in v2:
-- remove redundant log

 mm/kasan/report.c | 25 ++++++++++++++++++++-----
 1 file changed, 20 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 22598b20c7b7..aa39aa8b1855 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -166,7 +166,7 @@ static inline void fail_non_kasan_kunit_test(void) { }
 
 static DEFINE_SPINLOCK(report_lock);
 
-static void start_report(unsigned long *flags, bool sync)
+static bool start_report(unsigned long *flags, bool sync)
 {
 	fail_non_kasan_kunit_test();
 	/* Respect the /proc/sys/kernel/traceoff_on_warning interface. */
@@ -175,8 +175,13 @@ static void start_report(unsigned long *flags, bool sync)
 	lockdep_off();
 	/* Make sure we don't end up in loop. */
 	kasan_disable_current();
-	spin_lock_irqsave(&report_lock, *flags);
+	if (!spin_trylock_irqsave(&report_lock, *flags)) {
+		lockdep_on();
+		kasan_enable_current();
+		return false;
+	}
 	pr_err("==================================================================\n");
+	return true;
 }
 
 static void end_report(unsigned long *flags, void *addr)
@@ -468,7 +473,10 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
 	if (unlikely(!report_enabled()))
 		return;
 
-	start_report(&flags, true);
+	if (!start_report(&flags, true)) {
+		pr_err("%s: report ignore\n", __func__);
+		return;
+	}
 
 	memset(&info, 0, sizeof(info));
 	info.type = type;
@@ -503,7 +511,11 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 		goto out;
 	}
 
-	start_report(&irq_flags, true);
+	if (!start_report(&irq_flags, true)) {
+		ret = false;
+		pr_err("%s: report ignore\n", __func__);
+		goto out;
+	}
 
 	memset(&info, 0, sizeof(info));
 	info.type = KASAN_REPORT_ACCESS;
@@ -536,7 +548,10 @@ void kasan_report_async(void)
 	if (unlikely(!report_enabled()))
 		return;
 
-	start_report(&flags, false);
+	if (!start_report(&flags, false)) {
+		pr_err("%s: report ignore\n", __func__);
+		return;
+	}
 	pr_err("BUG: KASAN: invalid-access\n");
 	pr_err("Asynchronous fault: no details available\n");
 	pr_err("\n");
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230209031159.2337445-1-ouyangweizhao%40zeku.com.
