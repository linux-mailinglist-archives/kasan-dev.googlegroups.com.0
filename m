Return-Path: <kasan-dev+bncBAABBZ4LR6VQMGQEKZF6VSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AA257F95C8
	for <lists+kasan-dev@lfdr.de>; Sun, 26 Nov 2023 23:25:45 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-1fa2e488bb2sf1485379fac.2
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Nov 2023 14:25:45 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1701037544; cv=pass;
        d=google.com; s=arc-20160816;
        b=PgYYV7iIle7QkdIVPkrCix39SDvC0t37VrXQrtqL2I0NiRgrl22oUPgG+S0noZJcvv
         cpUkH5KdtY7gj0vfzJD7kQpfxqC+/lGPJWYdO33IdL4kP3NUuA8FCejZpuaiU2SUbaxL
         ELFepPZxKyeCTIE5ZTNTp15i4iGguzdQUJnuEjjJhU/4sKSOW3J6b9QaGW0r+vzruh6J
         7NYTxOm967yr5SnElrSlfhLvoCIrOxoz7cEk4+AGDD6DSIjMBek93nlssWWC999xJxsY
         wkrjv/yMXcKKgDSRhfuvpMq0BaNa5SO9ZNUflBAVc6SbnVaIxnMpVccwM6otPhsF9a4+
         GA5Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=1en022+34/rn9N6e8A6/TgK4GtJD4ORdqfGOfHDNVR8=;
        fh=2KNG8pWZM1FFLpB08HYKQidB7bFxhRhLQxHWPZMWwTQ=;
        b=abgmEtKywVBGPypcNII6SpdmK48NddHKiZGahFDKnWQG2rPTCH1GGQNSXA5stwe4q+
         lpkg3wULA+M5Vn0hEwejY75cEIDo3wqvVCnW15RUYGzcDpCP0IWSR4bAjC4VSCnTIaTN
         6qw7FR9lDMAB39WHty4FKrLrDunG9XkcLFgk99aZ9iOoqJ2ChFA0ykBzvcHq8KtaygJk
         urw0u9gyvud2PWHsx6xVYq/hQHoDqQatheC5SS/QUc9/2eJPHcp6JAXwHzPtGvtqOS1y
         KZt5SxBr4XEeHtSDHS0/KBxGFdDDm5mtlhJDOhxOgM/vMFIHYzeCIcW+gykHst6xvTM/
         PITQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=mCE6IjEH;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7e1b::80e as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701037544; x=1701642344; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1en022+34/rn9N6e8A6/TgK4GtJD4ORdqfGOfHDNVR8=;
        b=loh5jZqkgi2dUcQvjFZH2JsHrUWf4yXASgsLYFWiuQePDkpcSMUs5Unthr5WSaWPuc
         VevQFwPFgPRSoSy0cubm7jCbLPU1EJPPNz3b8GGukekW8OLnf/MA0FR0VV4J96XHiTXo
         jb9ICeaOylJ+X1Pkze8KrOg7sh45IPbUS4lp7BFRNQaq3XSIj+P0hthHURcnfgbXV4v1
         VUwrACa7FQrh2aElhsIlvWZ1B1JOLNVAvRFnwWiqm8ifmFgjD2s8aynm1fmwi3NILfmm
         0kF74xMLNNGVyzGznrdFtGjqhCfGrbh6SI9nYOCX8tGQdWTunc3+B55dVCB6I4orZcUh
         2+IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701037544; x=1701642344;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1en022+34/rn9N6e8A6/TgK4GtJD4ORdqfGOfHDNVR8=;
        b=kPV+plvFLOIWLCFtSXzlSXKoHvTpmngyR1r8EEtViibBEfveS/MYmVpP/cBsLXevME
         xMn/pzgAmHqf5IrpUjgnXhieHQesQXmYLUSGP1NVou55WQWzB+ibAffkg/lKqpP/f2e3
         6cHIxgaQYp75Gh89scXgVzsBRfTHABupvH+fcwh7T05aeaEwk58gbAkilOx/AkTlyTWY
         lN7fbVIXuUPc5SgGlk9oaUvRz4OXy/WuZxmQn4+0hRjp/OvAIXOic9r4JPa5iEq3oMTW
         B06gjx9+Fc6RM/pzd1N1+xhbc0bGeY7RToq6+0ALIHCteIONVvMiYimSIlEMPWu6fTjg
         RR0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyfG3ZWgBPvQq3Adhr9B93/YNXAQf5D5WlpYUJsiIPDg4oD9Wnk
	Z4UNfc0mrIT3QIl1fOTNCzg=
X-Google-Smtp-Source: AGHT+IFObEW3ADg1mQoT4KCcp4E9tl1cM/aYVqfSW1X5qaKCk+SG1h6ypkI9c09/1afh7BJBQL6UUQ==
X-Received: by 2002:a05:6871:818a:b0:1f9:5caf:24ee with SMTP id so10-20020a056871818a00b001f95caf24eemr11709876oab.12.1701037543989;
        Sun, 26 Nov 2023 14:25:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:8181:b0:1fa:2fe2:bdc8 with SMTP id
 k1-20020a056870818100b001fa2fe2bdc8ls1114484oae.2.-pod-prod-08-us; Sun, 26
 Nov 2023 14:25:43 -0800 (PST)
X-Received: by 2002:a05:6870:d1c3:b0:1fa:1ce9:7d45 with SMTP id b3-20020a056870d1c300b001fa1ce97d45mr8646101oac.47.1701037543424;
        Sun, 26 Nov 2023 14:25:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701037543; cv=pass;
        d=google.com; s=arc-20160816;
        b=d5dSyYXPybqdNHW78wecr1oG2ALrqWPEcZMqzBWGu9Ub43yMidkHZArZZHevdwD6T/
         IjVo8t/PsG4814lQoZCMc+QQzKVBx3KUyylDdzPHyvHybU0j90TK5Aa1GUBXIliJXeSh
         CVCHhwT1PYzzQNcfyQYvBw76y3wqtIrgxL8wK6u4CGRad66fp4121Kmn1H3KqDUvid2H
         MaBq8YyqCVfKrOWSsu5sxN3w1BeSNignl6aY69EeUxW7XvY75SDFHFQ7IBUbpw1ljPly
         cwuUk4KGTWU3oK7MAs7N3qwsGXd/QpdPGV6OEPeoak1fVqqIJLuaMHXCFLk1ZNcAm/he
         QEXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=LTe9aM+fjlA10OQyyR23o+HAgb9+PrgvP0lWfd0cnBs=;
        fh=2KNG8pWZM1FFLpB08HYKQidB7bFxhRhLQxHWPZMWwTQ=;
        b=Uop8ZLyW2EtwTBhj6aznjIT2JgWiYDZ5CWkdJnq2DGtB5Pzlsugd2a1sOqbBW6hDhQ
         6awhouIePLcA37KSnr9igMXSeWlNiw/XuhVXELw4gd1sCDSgwwj88fwste4wIONPjjBA
         6ysAQvg6JiHe1zPC1SiRT9JsVTybuhEjSIo3McL+bzOuPIH4H2wHdYTwFjN/fZD3YUyS
         n3d6lpE++wpMuYXY25tWEchP8Rob0I384vXbglw4KsbqojeQePLFIbXMMP10KOw779o1
         i+HtBSXTypIW05NfwKHY7TAWEg+KdjNTf1QH0fwO+0dYm9IAHGS9uEuWR6/0nx65M5kW
         0M0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=mCE6IjEH;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7e1b::80e as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR05-AM6-obe.outbound.protection.outlook.com (mail-am6eur05olkn2080e.outbound.protection.outlook.com. [2a01:111:f400:7e1b::80e])
        by gmr-mx.google.com with ESMTPS id ay14-20020a05622a228e00b00423977fa478si1080772qtb.3.2023.11.26.14.25.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 26 Nov 2023 14:25:43 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:7e1b::80e as permitted sender) client-ip=2a01:111:f400:7e1b::80e;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=FVcvMsTouluahEAm4FzQy8CraUxrYn/ki09Pt1u+KlGSQcLHu4GVyIPrd57xUD1/UrLbV0KcMYEBi7LttVnfEoUn1toVser+4rZesL4tTmZvcnAsbGDpkGLKy6+yejVaT395yObuDh6l7yEvgTTfcaPuD9CTmVb2pEI5qyVnJd3F5+oFXw5oC0JC6UlN0/RHm+shvqHeqiNKoRZSdhpkD7oR6uCiktWC1H2lWAM0x0YGyy/DSbf4iPhm6GDd0O7+cAXDLmlkp7HVUrPAipsXgB6/mf31eU8Qr+jcF1dnMTFwwBYOvF45tyrhHpEFofhPUMuebkSsORdzGzE4HD3LtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=LTe9aM+fjlA10OQyyR23o+HAgb9+PrgvP0lWfd0cnBs=;
 b=TQdjje/eJK36mvH3u/t+8Ly1gOixfVxT75g8J4eK79yswauXTIJjDIjbsvriQd2QRgsKGWKOo/35kS7KNZLCeSHc0thJECEREKnv7Oujg6ie04PrgKK4RC/dOE3nSizRruFM+7zWnxeoQkALHSsnd0Zj81o3EgV8/azs0dUHiugV4uaOUKOpP1ZWsOVF6h8SEWWJm+KjAPl1/jsE60Vn77ZM7B3csiRrQPXYCRx9NOiKHZzsFJ9/9ha1kAmPF26Rl4oG1c5XJhrdDYtuCV76drqIF7kh7beXhovWEdVGBr3SukymQfmnUOQ6U2QK1o5ougXYNcz5ZvH/t2daSK0z3w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by DB8P193MB0695.EURP193.PROD.OUTLOOK.COM (2603:10a6:10:147::24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7025.27; Sun, 26 Nov
 2023 22:25:41 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4%5]) with mapi id 15.20.7025.022; Sun, 26 Nov 2023
 22:25:41 +0000
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
Subject: [PATCH v2] kasan: Record and report more information
Date: Sun, 26 Nov 2023 22:24:25 +0000
Message-ID: <VI1P193MB07529BC28E5B333A8526BEBD99BEA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
X-Mailer: git-send-email 2.39.2
Content-Type: text/plain; charset="UTF-8"
X-TMN: [d8Q4vUfspLfUTUoWHZPUFBITuUhW/iON]
X-ClientProxiedBy: LO4P123CA0548.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:319::11) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <20231126222425.226688-1-juntong.deng@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|DB8P193MB0695:EE_
X-MS-Office365-Filtering-Correlation-Id: 3e4979fd-c456-419c-2b6c-08dbeece9f63
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: OdVvgAvvhIFsvk3ATaW8y0ZbpBNnoh7e5x2pVRAMszxr/j2S159JPq8RKRQKlR58Ezd88+fpsoFhJmKca4KDLErjCvmDbNucy4rC9JlCFzqvN3vTBRZ3D5/nzxEnqbKyfKHhQu+o9yb+J6UNfW1sl7j1zbCIEDw/2wUf47sG0oolXOKLOKdn4dlfl2yB3rdTaWof+WWGzWhRQrPtbpD0DR3K0z/no5Me8dVu0/wDHTnAbY9dwdmF4rbdBsZyeiFQrjv/KkbAtUlv+o2cP4Xrr6R1VJGIeocuB5N/8P2IA1WzbgH018N52yz0s65ngbscQ80uuow+0PsKd9rU1//KZfIZ8wlSj78XSYgSyBbanp+7HYOpWGUritGlJrjIQVlgQg8ZTlgdIwGQifZoBCpcyjjAC2gnvDfi8xq3REQ+08Xj1jJQmZ4sUrSdkXQFhV/2PSnZBFIGdZWBiMMwD4PqkCzJ617Lq9cKtTaOZKQyyStWdDMgZQaNiat+yMGalkECtuSMBA/eybca30gpK37zjAKOgZkOcRURM4u99VotbmCCk5aKQGBpnIGDb5e3keBC
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?zNBDu8AR2FX1v2zMUIUNaqLfbqbgqSzzvGl8OfNw203MkwK3UCqpyr2k2B7Y?=
 =?us-ascii?Q?rbVh1z0xctZh1cFL4M5+qatTxa9++yeQo7I6pyvagpZ+1+WgJeIl1nMeqtkP?=
 =?us-ascii?Q?tBFWkjo2vglDuVqPkt/U92/oBCXRRLAqjuAw72I9yJMflOKNHKopKYzWZbGr?=
 =?us-ascii?Q?VKFgo4/owwDIU3LzwLOxVT8O2ULXRZxBF1tepJ4YsvOpTnKCYWMT3BXxvVh8?=
 =?us-ascii?Q?Nref59mBYdOwxGLs5iaUwGqd26Pfo4wlRBPwKLCyOpspM7i4Syh4+2PX6KOw?=
 =?us-ascii?Q?3O+HZE2IiU8agBg1cpAEEfFbR6Ha3KGRJySOSDUrMFAhWboeitbbYaqlAqIq?=
 =?us-ascii?Q?n3VHrHglx7btkO11GddyOhxa3BQGUyqwQ/jtNIcx2IuqGWCykEoWClSLg/Ah?=
 =?us-ascii?Q?TZVaAdYSTiZo6GlzouMbEIsiXkygx6FKnzkrxytPB0g0zaRsK9gIvyi17u0H?=
 =?us-ascii?Q?oeFKWDc9JKirMqTzXhQUgeLITA1b3pV9Ga0G5wHLucalWHuySy2RiivLauCZ?=
 =?us-ascii?Q?+r9kJoSCKHe8Egnopa7ZdVXxXXGEGn9+etG3V3YDuUFyx9dhQ7TPYvE0TcnS?=
 =?us-ascii?Q?bInog0ka7eXvE2vQysrRRPfA8gwsPEZUy4zRjWORw//IYYn78iG3Gqv6IuZH?=
 =?us-ascii?Q?h4MW0qlfDqaiK0bHM0FTrV76kS7ZV4IQ85IdaGw3n92avAYcnnYjsOkIlbIY?=
 =?us-ascii?Q?hND9iO1Qhqofwy959BmPHf//xGEZLfl4TosIV+//n/pyBAsxZShLJVL53pyd?=
 =?us-ascii?Q?ZMONE4fUTQR5HZceaIBpYja2GK/LK3l93rSnEcLm8EidtTL923PfYMy4bBYw?=
 =?us-ascii?Q?JWzdSzc/SxFgaXJQpZ7plQWTR+IThnfEJ1ZTWCe75ChakLRt7ieFDnl5tZUw?=
 =?us-ascii?Q?ME4SwCRcM2RWV3DPauF6QC8y7NcDMwcSt0TcubYmc4qd8ggwulYkCsTuEp0T?=
 =?us-ascii?Q?ky0JcD9AqldaQkl5lUYlvdUXMoxkcGCFDG0FXi+6MBCf/9bWxio67VPs62Ue?=
 =?us-ascii?Q?3IANx0XEY5cfnuR9JqU7shsqJGj7CX2pJLEMrDWDFxJ9IJ0LIcFzYEda5TeY?=
 =?us-ascii?Q?ipCtJ2htIgt+borC4Gl7wy4nRPj3z23bV94V3dBrjD146ps/0ymw1oewVTFu?=
 =?us-ascii?Q?zECYx78VXZJLxjonuc3yfJAHY0wxuduWVoLoFileTZ20rnnMYUeHaZ9HqWnn?=
 =?us-ascii?Q?8hWVSJS/qqFiX2dVdqYxsJ8JDGJ0fD3+bkeBOJDeBliJc+IQCvo2rtfC5s4?=
 =?us-ascii?Q?=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 3e4979fd-c456-419c-2b6c-08dbeece9f63
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 26 Nov 2023 22:25:41.1630
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DB8P193MB0695
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=mCE6IjEH;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:7e1b::80e as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
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

Record and report more information to help us find the cause of the
bug and to help us correlate the error with other system events.

This patch adds recording and showing CPU number and timestamp at
allocation and free (controlled by CONFIG_KASAN_EXTRA_INFO). The
timestamps in the report use the same format and source as printk.

Error occurrence timestamp is already implicit in the printk log,
and CPU number is already shown by dump_stack_lvl, so there is no
need to add it.

In order to record CPU number and timestamp at allocation and free,
corresponding members need to be added to the relevant data structures,
which will lead to increased memory consumption.

In Generic KASAN, members are added to struct kasan_track. Since in
most cases, alloc meta is stored in the redzone and free meta is
stored in the object or the redzone, memory consumption will not
increase much.

In SW_TAGS KASAN and HW_TAGS KASAN, members are added to
struct kasan_stack_ring_entry. Memory consumption increases as the
size of struct kasan_stack_ring_entry increases (this part of the
memory is allocated by memblock), but since this is configurable,
it is up to the user to choose.

Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
---
V1 -> V2: Use bit field to reduce memory consumption. Add more detailed
config help. Cancel printing of redundant error occurrence timestamp.

 lib/Kconfig.kasan      | 21 +++++++++++++++++++++
 mm/kasan/common.c      | 10 ++++++++++
 mm/kasan/kasan.h       | 10 ++++++++++
 mm/kasan/report.c      |  6 ++++++
 mm/kasan/report_tags.c | 16 ++++++++++++++++
 mm/kasan/tags.c        | 17 +++++++++++++++++
 6 files changed, 80 insertions(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 935eda08b1e1..8653f5c38be7 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -207,4 +207,25 @@ config KASAN_MODULE_TEST
 	  A part of the KASAN test suite that is not integrated with KUnit.
 	  Incompatible with Hardware Tag-Based KASAN.
 
+config KASAN_EXTRA_INFO
+	bool "Record and report more information"
+	depends on KASAN
+	help
+	  Record and report more information to help us find the cause of the
+	  bug and to help us correlate the error with other system events.
+
+	  Currently, the CPU number and timestamp are additionally
+	  recorded for each heap block at allocation and free time, and
+	  8 bytes will be added to each metadata structure that records
+	  allocation or free information.
+
+	  In Generic KASAN, each kmalloc-8 and kmalloc-16 object will add
+	  16 bytes of additional memory consumption, and each kmalloc-32
+	  object will add 8 bytes of additional memory consumption, not
+	  affecting other larger objects.
+
+	  In SW_TAGS KASAN and HW_TAGS KASAN, depending on the stack_ring_size
+	  boot parameter, it will add 8 * stack_ring_size bytes of additional
+	  memory consumption.
+
 endif # KASAN
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index b5d8bd26fced..2f0884c762b7 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -20,6 +20,7 @@
 #include <linux/module.h>
 #include <linux/printk.h>
 #include <linux/sched.h>
+#include <linux/sched/clock.h>
 #include <linux/sched/task_stack.h>
 #include <linux/slab.h>
 #include <linux/stackdepot.h>
@@ -49,6 +50,15 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags)
 
 void kasan_set_track(struct kasan_track *track, gfp_t flags)
 {
+#ifdef CONFIG_KASAN_EXTRA_INFO
+	u32 cpu = raw_smp_processor_id();
+	u64 ts_nsec = local_clock();
+	unsigned long rem_usec = do_div(ts_nsec, NSEC_PER_SEC) / 1000;
+
+	track->cpu = cpu;
+	track->ts_sec = ts_nsec;
+	track->ts_usec = rem_usec;
+#endif /* CONFIG_KASAN_EXTRA_INFO */
 	track->pid = current->pid;
 	track->stack = kasan_save_stack(flags,
 			STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index b29d46b83d1f..2a37baa4ce2f 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -187,6 +187,11 @@ static inline bool kasan_requires_meta(void)
 struct kasan_track {
 	u32 pid;
 	depot_stack_handle_t stack;
+#ifdef CONFIG_KASAN_EXTRA_INFO
+	u64 cpu:20;
+	u64 ts_sec:22;
+	u64 ts_usec:22;
+#endif /* CONFIG_KASAN_EXTRA_INFO */
 };
 
 enum kasan_report_type {
@@ -278,6 +283,11 @@ struct kasan_stack_ring_entry {
 	u32 pid;
 	depot_stack_handle_t stack;
 	bool is_free;
+#ifdef CONFIG_KASAN_EXTRA_INFO
+	u64 cpu:20;
+	u64 ts_sec:22;
+	u64 ts_usec:22;
+#endif /* CONFIG_KASAN_EXTRA_INFO */
 };
 
 struct kasan_stack_ring {
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index e77facb62900..8cd8f6e5cf24 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -262,7 +262,13 @@ static void print_error_description(struct kasan_report_info *info)
 
 static void print_track(struct kasan_track *track, const char *prefix)
 {
+#ifdef CONFIG_KASAN_EXTRA_INFO
+	pr_err("%s by task %u on cpu %d at %u.%06us:\n",
+			prefix, track->pid, track->cpu,
+			track->ts_sec, track->ts_usec);
+#else
 	pr_err("%s by task %u:\n", prefix, track->pid);
+#endif /* CONFIG_KASAN_EXTRA_INFO */
 	if (track->stack)
 		stack_depot_print(track->stack);
 	else
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 55154743f915..bf895b1d2dc2 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -27,6 +27,16 @@ static const char *get_common_bug_type(struct kasan_report_info *info)
 	return "invalid-access";
 }
 
+#ifdef CONFIG_KASAN_EXTRA_INFO
+static void kasan_complete_extra_report_info(struct kasan_track *track,
+					 struct kasan_stack_ring_entry *entry)
+{
+	track->cpu = entry->cpu;
+	track->ts_sec = entry->ts_sec;
+	track->ts_usec = entry->ts_usec;
+}
+#endif /* CONFIG_KASAN_EXTRA_INFO */
+
 void kasan_complete_mode_report_info(struct kasan_report_info *info)
 {
 	unsigned long flags;
@@ -73,6 +83,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 
 			info->free_track.pid = entry->pid;
 			info->free_track.stack = entry->stack;
+#ifdef CONFIG_KASAN_EXTRA_INFO
+			kasan_complete_extra_report_info(&info->free_track, entry);
+#endif /* CONFIG_KASAN_EXTRA_INFO */
 			free_found = true;
 
 			/*
@@ -88,6 +101,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 
 			info->alloc_track.pid = entry->pid;
 			info->alloc_track.stack = entry->stack;
+#ifdef CONFIG_KASAN_EXTRA_INFO
+			kasan_complete_extra_report_info(&info->alloc_track, entry);
+#endif /* CONFIG_KASAN_EXTRA_INFO */
 			alloc_found = true;
 
 			/*
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 739ae997463d..c172e115b9bb 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -13,6 +13,7 @@
 #include <linux/memblock.h>
 #include <linux/memory.h>
 #include <linux/mm.h>
+#include <linux/sched/clock.h>
 #include <linux/stackdepot.h>
 #include <linux/static_key.h>
 #include <linux/string.h>
@@ -93,6 +94,19 @@ void __init kasan_init_tags(void)
 	}
 }
 
+#ifdef CONFIG_KASAN_EXTRA_INFO
+static void save_extra_info(struct kasan_stack_ring_entry *entry)
+{
+	u32 cpu = raw_smp_processor_id();
+	u64 ts_nsec = local_clock();
+	unsigned long rem_usec = do_div(ts_nsec, NSEC_PER_SEC) / 1000;
+
+	entry->cpu = cpu;
+	entry->ts_sec = ts_nsec;
+	entry->ts_usec = rem_usec;
+}
+#endif /* CONFIG_KASAN_EXTRA_INFO */
+
 static void save_stack_info(struct kmem_cache *cache, void *object,
 			gfp_t gfp_flags, bool is_free)
 {
@@ -128,6 +142,9 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
 	entry->pid = current->pid;
 	entry->stack = stack;
 	entry->is_free = is_free;
+#ifdef CONFIG_KASAN_EXTRA_INFO
+	save_extra_info(entry);
+#endif /* CONFIG_KASAN_EXTRA_INFO */
 
 	entry->ptr = object;
 
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/VI1P193MB07529BC28E5B333A8526BEBD99BEA%40VI1P193MB0752.EURP193.PROD.OUTLOOK.COM.
