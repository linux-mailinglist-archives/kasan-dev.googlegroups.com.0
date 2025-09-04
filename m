Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBO4H4XCQMGQEVFTVVDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id B01E5B43476
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Sep 2025 09:46:04 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4b29cdc7417sf14491881cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Sep 2025 00:46:04 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1756971963; cv=pass;
        d=google.com; s=arc-20240605;
        b=A4ZF4Z5LeacbGojgQU+QmYU+IYg1r7WUO951Ea0YQZ4+S97cJfwn3nLxAws1zbPg7T
         sgEShp/FE7MoGxalseFHDPrHOCYWkTfher7RyuePI9ul+dIYrh/iWcQRS4lrmJMsV6MT
         Nj9yGeLJbRegJJES/ZJ7OKo4sYHOSDWMWkzbdH92659ttFIMOC/ziAC3Dso5mr6Rt9h1
         zW6DAdVe26ZIQBDMBfok+JSU58nnzHeV91TAuDoHT3Wuf5pjkOWYWWsFluAONHfaPPi5
         hysYk1nBg3SxFL09rrp5xg5+shP7zAL7kfWi9kbLcKGaHLHJw57xM8WMzANwwnSb72oa
         i74g==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=NVPjuTmOtggfgpgibUC2W8/m076YQUJqQJHcaEE9cBM=;
        fh=9jNKeBJiKY0k+FHJbG1ixTFamhL/0T8u/pFtoGI16aI=;
        b=WKATwYm73sUx9mq5kAizNrtkvcWrV2TKG9PXT+KgTbyqbscQHts/oyq5pmU9+LNiVl
         4W7Y513nXMSmeZbkNSSIcrWlmP3jO/1GId7ZemYoorhThqS7WtkMZYgd7oehDm5DK0da
         n8UufmrcMLhvsHTBDqW+ZYKHMPpjCc/kmMAmWHP9ObRkqDybTF98UdV0cftdA3k/pMJ5
         VPu78Cj1g0GqlmWYUkNBGfdupd+HWQ4+4oBDLK1G1a0U9fiSm5EcOk7exHaspAxtjssp
         WO43kruTJCcqbxdCPuRaSuRyRUUwOsQ87ORMoKa10u52pxETHTXQ3EXdV1OrOPBamWJF
         LW9A==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=pSGA9Gc+;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=pSGA9Gc+;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756971963; x=1757576763; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NVPjuTmOtggfgpgibUC2W8/m076YQUJqQJHcaEE9cBM=;
        b=lSaR1f7oVisuj1ze8nzkY7wmhSb48AqYodrAOYe+z1hXleAMLmnupy1vd65e3C2k3S
         jUYFobGLppTciDMlehMEnvnSn64UQDYU0ENuEVcYVtZWN8RAznU2KNqHiOD0EMag8pqf
         EtF3l/LMO943aoiCURGFJirdgeh1tKfv6Qgw6sWvzFenjmvkSn9YmIYqL5bN+z71htVl
         F5sJeaks2dyFKYSetdHC8DKULmje6OgQgxVXNhzkDxDbWzzfhWhrFvfzQSObTPHj2z3K
         rMN7eAdunyd1JbEkKqeWP9uDrNnFr/bw3vdiortGOMPMs8VM4qxaR0U0w3jOLmQO48Ao
         N2EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756971963; x=1757576763;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NVPjuTmOtggfgpgibUC2W8/m076YQUJqQJHcaEE9cBM=;
        b=VJTAhdBBo38gQ/nizu8oiVHP/TWIdUwSFL4sJsJQd8oe6Dw2T6SB8pNdjzkCjPu/Oy
         A9wLY9IGWcPKjjPeKorNV4VuZ6OeYfP72G4L6Uk+Fh8WHwqNutPzFz4+IaihJReLByCc
         YxE/jfWIoGQtYBCwWuH2H38TUfMj1J+Z6l6Tpeb+558OKJvsxGfjCG5Aj+VOaHxwBlt2
         cGxiH3h1oI2lQ3GAcZQv7Vkuo3/edRbyBG470HtmZ8vqdq2B3QmZT1alZlL/eg2ZORcm
         jbaBC7KZzIKwWUaa/nhEp2CPJzs6D4UYZaFyCxJ1MpJVxHKmfrSLYLrw05YCFdI7jdI8
         o/ZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCX75xyz1WZUzfa5Ju6nK20R0pJLlL8EEbJ+xHUykTiU5Sy8iKiK98pxHu3cWlGd4wDB2/XgOg==@lfdr.de
X-Gm-Message-State: AOJu0Yzif1rXyy41awLWmV5/E4PsYPR2k68bp84x2bC6TU0KSl1hiirL
	KqEq7A8EXEC3E3ZpXgwfUwq+cT0D6d/eD1wZFrZcvnN1iswFhkkiG0za
X-Google-Smtp-Source: AGHT+IG3oubCy6SVQRqi4eVuQHK3Bt1yTtz2mImJa2922Q/B2Pw/cR6/AvXrVugPSy2hZy7CDoT9uA==
X-Received: by 2002:ac8:5a0c:0:b0:4b4:7b4d:2801 with SMTP id d75a77b69052e-4b47b4d29f0mr80171221cf.68.1756971963253;
        Thu, 04 Sep 2025 00:46:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfOIaMQa6RhR/G7rXclSkzrOynmyZ+qU6k/T86rAcvR7g==
Received: by 2002:ac8:7f09:0:b0:4ab:8dcf:6968 with SMTP id d75a77b69052e-4b2fe847e53ls139266001cf.1.-pod-prod-09-us;
 Thu, 04 Sep 2025 00:46:02 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCVrFu3wGCepTsZhC9756YsSPhNajqE+2/UqBbRtkggdjyUkX4D6g9au4gYWO3sTv1OD1I6xms0MGFo=@googlegroups.com
X-Received: by 2002:a05:620a:7009:b0:7f9:b87f:212c with SMTP id af79cd13be357-7ff27936f75mr1895687985a.20.1756971962366;
        Thu, 04 Sep 2025 00:46:02 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756971962; cv=pass;
        d=google.com; s=arc-20240605;
        b=IKQzfM9E3JpSSYlJN55SHuTDoO567Ob4jPOtAIdUefUyXkqZEFjF9TeD7jMFF/n1x0
         VIoP23XMToDqD8a58UXDozA677GVn8GjlxhCpr81CgL2StlnV6X3ANb4qy5h3pL8xEw8
         8LawX8WZx3IkrfGFUv1kq69DnDGitJhLZcn4EVhZ53nirdl7hBWgGgHK8CUagAlu3sBz
         sWqCuM4ex8ND0uZiLa18m6W+cKCC/GmhKXWFGPXG27lXb7Zmvq/18jZivg/WkCENdrmn
         iDdaIXVyNHD6yzs7Bxg7L/YRMgSlA9kXp9IibdtnshUsa/Sws5H7ig5jY3nsZl3uBcHQ
         gChQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=Bb8OyJNWkXoWbomOVdkD8jSMhnArCsbleFsCSjAudQY=;
        fh=ufqDvzVfba2dkpl8jTip/BMio/P94U1NAsuX93cABCQ=;
        b=A9d0yld1Cu3d4y8zRZkoCVt9ePO2/OJPyx/FJKRrOjXVLDIZ3GWfwzbM6ljtHgR4/f
         vbO9X/GMbWQQknD6cBEZWNZYK3FqdrDGgBstwMMckzOqWZX/v/yb2DS19IrB+5LJXSRY
         /7v4T+LiFcHVap7KIF614BRmwsw8xL1zSqToafIPox7lj18fLZdIhI6AJHIFO5gHqWcD
         Z5MalYTC9Wsi33O5PLQYNtSvHLeFhJbVO+/b1v0sNCKP449VkuIuRg6+Pllbds/Q/cFs
         rbTJsFv2aH6PkzkesmU+3C5mXHILANoOi+M2yMdXkB/bGSl4YGGu3IFdcVoMRwH9Kn6C
         bLWA==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=pSGA9Gc+;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=pSGA9Gc+;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from PA4PR04CU001.outbound.protection.outlook.com (mail-francecentralazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c20a::7])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-80aa93f27cdsi15172685a.4.2025.09.04.00.46.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Sep 2025 00:46:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) client-ip=2a01:111:f403:c20a::7;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=Lq63AZHxRRs2Xjxr8wLTLMz8kD+QJ9KIhW8mptN2HFBZhCJdXA+Gauvdt6GGHMzIDwxo1/t4DL2kLYsxAAGVFgg+cMhab9tD202E7z/jWml8KjaIsePh3eNTgQLFKJf+coZynswFJuVkLYnNrt3DKy/O3+yyqW61ia7YV59fkWfLoRayDuDmjptcg9BkZ1187dYvfxp8KVwxeK84pMjXDkkFN/dVBPv4/Y65jrsYej23FU9OQMvv4JEfduqPZuMGeEBq6qxDWBdIoy3vvC06KtvwEkeDCnaAbeiwmMYPr3DAV0OZRHAmuUstM5+ZDg7dd8Yspv51JIPwU2DDQ6FNYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Bb8OyJNWkXoWbomOVdkD8jSMhnArCsbleFsCSjAudQY=;
 b=vcPQDTEWLQeV9qcl7fUJ+j/mH52ofOJutYyn+MVAH2Bjd5++6nTuortcCi84HHHEN9ADO9Y84Wz7DhVGu2STsyBgT9saaUKH2uZ+LqI73eFJ89U9R8XUnvDWxX9xQEoP3h8i54rlgykCyLDbqZMssEG4GprWAoJrGyp8et/A3YtCcHcu8KIRjEaTW59tu5xs5ohmOR9qVppfARX1HZFeZ4kX7tT6uzqAuCvP8m9hPamNx025QkmooSPthG/YzQRoKvuqd44VQ3rlpMEWAhnQH1vejDMF7xcqQZiGr4vFuknfxJmUkDsb+upEaqAIosYWxdB6jHmOom4yhfBCVGS+pg==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=gmail.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from PR1P264CA0027.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:19f::14)
 by GV1PR08MB11089.eurprd08.prod.outlook.com (2603:10a6:150:1ef::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.27; Thu, 4 Sep
 2025 07:45:59 +0000
Received: from AM4PEPF00025F9C.EURPRD83.prod.outlook.com
 (2603:10a6:102:19f:cafe::a3) by PR1P264CA0027.outlook.office365.com
 (2603:10a6:102:19f::14) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9094.18 via Frontend Transport; Thu,
 4 Sep 2025 07:45:59 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AM4PEPF00025F9C.mail.protection.outlook.com (10.167.16.11) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9115.0
 via Frontend Transport; Thu, 4 Sep 2025 07:45:57 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=NjdIG4GHK3agalbYIS5iOoSZAL0xg5ea6QGk6OEYef0+azbls06ELGmxxd4dn455fIVeT7p4jAaLYDopfQJzaolc80sDAo3IKdai7LF8hVqxivGTdObOIR0G18HPpl4jqqYRL3ig8FPGdwQWzJ1mdWpRb0maBk3IOv+0p/TjBAjpHCtnGuT8E9GQWlId+wYFPOlcy34ISrq5lRm2Q7NaRGZoRdJwNIS4pWY7xWd2+pVZIQbwe2e5Ft5VKRbvJlSU9PW4wZxeK5Kla90SYDGFvw0AcXUNlO3RZkoEuOCGKPVoMtbyZpht8I8jDTCNSb+oXTDJc4Vm9sYok4DEDnV35g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Bb8OyJNWkXoWbomOVdkD8jSMhnArCsbleFsCSjAudQY=;
 b=OFUY3q+fSqzvWftgKcbXVOjvdxlf4+4cIzjHKMBXYKb1QthDyaO7q5NIYbaQPc3NN032f/iB2C0vzD/EoT94XHxJUEzzLTxLX5Q5FNtnFsLvponOdQ8z7Oj6ECuzB7I4zviTMdvRDQE85WOb5BdqNepGM+Tv05SPx18siiSa9ACdVHYYP7vW136PSWs7OawDnpTR6lYLI+7rOjCSntS3Wq7babvS6Fy0DRYVPGP8UZPiJ4e+dJAUwovYqcK6D/jmkKRyPgsCksNb991xEMMFv0q2pA99U8aRpsDxwXNsNr5h6MnxML9wow3up3ZRyUhxsciIfpP0+zRMXrF5006SIg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by PAXPR08MB7393.eurprd08.prod.outlook.com
 (2603:10a6:102:2bd::13) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.27; Thu, 4 Sep
 2025 07:45:24 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.9094.017; Thu, 4 Sep 2025
 07:45:22 +0000
Date: Thu, 4 Sep 2025 08:45:18 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com,
	vincenzo.frascino@arm.com, corbet@lwn.net, catalin.marinas@arm.com,
	will@kernel.org, akpm@linux-foundation.org,
	scott@os.amperecomputing.com, jhubbard@nvidia.com,
	pankaj.gupta@amd.com, leitao@debian.org, kaleshsingh@google.com,
	maz@kernel.org, broonie@kernel.org, oliver.upton@linux.dev,
	james.morse@arm.com, ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v6 2/2] kasan: apply write-only mode in kasan kunit
 testcases
Message-ID: <aLlDjmQF0DSOqILw@e129823.arm.com>
References: <20250901104623.402172-1-yeoreum.yun@arm.com>
 <20250901104623.402172-3-yeoreum.yun@arm.com>
 <CA+fCnZeyKuet2XY9=jOdiK4Z6f4_=Xb5ZBzBaDL-2gFPv9yJ5A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZeyKuet2XY9=jOdiK4Z6f4_=Xb5ZBzBaDL-2gFPv9yJ5A@mail.gmail.com>
X-ClientProxiedBy: LO4P302CA0043.GBRP302.PROD.OUTLOOK.COM
 (2603:10a6:600:317::16) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|PAXPR08MB7393:EE_|AM4PEPF00025F9C:EE_|GV1PR08MB11089:EE_
X-MS-Office365-Filtering-Correlation-Id: 8f6bceba-7f59-48df-93b5-08ddeb8715c2
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|376014|1800799024|7416014|366016|7053199007;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?5tpcSuMHSDR338XvUmkG5hqIm81h55AwZOp3g7/jivJPT1M+h2+KZcSy/9ug?=
 =?us-ascii?Q?QiABnMsCAa5+WSECX6hhiCmLm8gUR/bqTlef/+47tGw0+RwLKUiQjTUbHWjS?=
 =?us-ascii?Q?rlfjxve6YHV0Sozehhg5di2HUR0TCBOuApP7FAO3jatSRCy500I5jVQs84bv?=
 =?us-ascii?Q?/zODw055eoK8Qq4/Dm8lviOry3jW5r93h1jSFeTSOW1SQsQL53pCYHb2NsXp?=
 =?us-ascii?Q?hT+fL3pDi5X/IM0gnCwfkyJzVqJBuVqmu38xK484zyUshe9UOfDSM8ScULSZ?=
 =?us-ascii?Q?Okq8Tb3YW+r4x1uCdEqfmbrAWjwRiiijudGtpOBs9kwE7GhLdTPiIdERLoN0?=
 =?us-ascii?Q?jHac0WyPT4MTJLq1V4ZdP9pbZ6QcZquZGIDKxVrBJTxJLP9hSxDD4gusM+IE?=
 =?us-ascii?Q?2dnrYAUOAsBlkDEQ2o9YE/fLD8ieKOuEO6YqWafu6uJSltHZBzA9sDQmtmhX?=
 =?us-ascii?Q?AXn/+0syQeBF2pE0HEQ9qV1zPabPGZtgK+z9SKtLdZsq9k0cf510VZL2W4T9?=
 =?us-ascii?Q?66ujplk/mSJtfbnCS3rkjcegB+bENqLW3vHemRnGFeaREZOEqEZncPFtW6Pt?=
 =?us-ascii?Q?pbXYzvW1H/o60lc6/Zir3CIkb0BZEuWRyNbNA0tp0y1DSthji7Unab09jQiD?=
 =?us-ascii?Q?3lfoTNu4liaBMlhkQeCgPKLw53MhHI4C2KR6WLAv4vkom8RB8ZShX1w1L6td?=
 =?us-ascii?Q?+IIc8t23a4We5FFhWga9Ll0ztd+vajJIocVHUIp0NPfRv7TtKLjUhI9qg6+t?=
 =?us-ascii?Q?kOYU022UNpeTAycYngfSVxTUBrH4CKynaV4dVDhTZeM/sBLnnr+OLRNeMzg5?=
 =?us-ascii?Q?LYkv1vDWSWcGK3SE2fciR1MOpmuEpo88rrfzB8Who9auTd723Sxn9YJh+vZg?=
 =?us-ascii?Q?nVMNXIPlw0Mo5/mDIfgwyAjyno9OyXa5WUJ8oR0ANsnGc3nqxo07xmFe7ZiE?=
 =?us-ascii?Q?kwzoq9s0VfbgDHsXktO0oTZsiw1I808nmBqn+XMp+wXouIBjGds66bjh0m0z?=
 =?us-ascii?Q?7gR00TdWTZi6fENJpPob050k4lVK1E4v2vHV1MQSPOIEDFRgEiolEYtAfdKz?=
 =?us-ascii?Q?swnNDC+jgiyMKMkgvwU545b2gzzhCr6jGZpcvWbNA6AWWY1Ld0AJvyh9cnhp?=
 =?us-ascii?Q?gnPA8hfS5Zf90Dj7qle9+6N34qgLnt5ShNgaLa0vnJsnvfwBx86N2GBq8rPh?=
 =?us-ascii?Q?nFuKApwaphiQ5qovNpigSnJgU6m9tsfVnPA2zWIFbcM034HKRp4OSsuCgd5L?=
 =?us-ascii?Q?WLfIt6iszu1Kp4oPOPGP6Rzz/BqEVgUf91DC1GXOOw3fkEodN0AnsjiiXLxM?=
 =?us-ascii?Q?CIbtzFTUTRmHurLpGcctAt0I2T92hZdf5PvZG8igdpq6rQip+P8LXBRkwsNo?=
 =?us-ascii?Q?94MUfSlnU9ZzYiWtJfqHxn25SQs2vrw6o6oyAt2lwZkVQIR+aL0+kNjyj5x3?=
 =?us-ascii?Q?zsU1LVT7/sM=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(1800799024)(7416014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PAXPR08MB7393
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AM4PEPF00025F9C.EURPRD83.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: b9ea77e3-b520-44e1-547f-08ddeb8700e3
X-Microsoft-Antispam: BCL:0;ARA:13230040|35042699022|1800799024|82310400026|36860700013|376014|7416014|14060799003|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?wGbFgm/vmMXJjg0nb5oYdTlZShtxSzz01dwTjMsOnh3/I+vREKaMRb7qGInO?=
 =?us-ascii?Q?3iYddgW3DDafXUnomGe/xkJe4iJfmhFWByNcGh1t9LcBerpC0Ok2ix/ABsnk?=
 =?us-ascii?Q?HYBqJr5n9C2K4WdfvzWiYev28u2wBDkbGxxik44XXEvJprnpKJ0MhLc9ovkk?=
 =?us-ascii?Q?0bFHS5f5shGQv1TAqVjjHlGhA6bhdNKtphmSH5ScNEp2zNi9ofBjXJbLQMPE?=
 =?us-ascii?Q?l1EIXrS64CX4VlvcoWgc3sdGlffmyljf5guvOip8V+Xmnwa8LWY8u6rnJaPe?=
 =?us-ascii?Q?WL6nDyIKYb2NOSUjdPWf/QjW8AHMgKvYqWCcekoCbZ3CUF+1IHwTEHIFPBnq?=
 =?us-ascii?Q?GEdC1OMinG6oWCIK8f2/UJg1f0xxsbUHxuJmz0CyGvyVDLsHQXVsg6eP33AT?=
 =?us-ascii?Q?iaQHDjKyfotBC2uxgaoCkuGG9R1LNbvehqqu8e6O26i/N0YaiFzkXe91zGkN?=
 =?us-ascii?Q?E5C99mm+o6bmSbiuCVp2q6Sd28nU34u7rOoHgWRptHnth8rLGiJ8BLFN1QAE?=
 =?us-ascii?Q?lMMpAeuKQp11Iq6WAa8RY2cI3szf9WhwqC3EoQF1CjN/qtHy2mMElwQxsYw0?=
 =?us-ascii?Q?2FllUncuozlBc62UJ58oVA/Twxuxqe6wM93eU1TH8cTPUQqK0crs8p+F1ncq?=
 =?us-ascii?Q?QPQPNgmk64PDKDWOqpmKlx0WSFIaHRp1vQbpIgE2NFGE3A0aj0F4Au5HtLMl?=
 =?us-ascii?Q?pLjApHF47P2SVZDSBTxRXEjxX/Rrp1YaAFTr/pGPGDIyoUlIi/9d5DlBhebJ?=
 =?us-ascii?Q?vPsRCCHFmSZN0htNBuqjWdY4S3BeUZNqje87tbL6XAA/QP0MtlXSgVYbcR9R?=
 =?us-ascii?Q?2vkyDEsJ6MDUJGrEJOgsQYmv75l5ovWohFf95Z24TV5gn2H223fLshmdoUG4?=
 =?us-ascii?Q?FsQ4ttcSWylN2fNKDmuotU84e0yqQ8g7wwO1j9xLFuoOQ27Hv12CT7XTdXy7?=
 =?us-ascii?Q?wbjgAGY7jHy/7F14UWMe0FxisJABLysYZW6y+LRwObKO3NTUfLeLe0buvkQg?=
 =?us-ascii?Q?7mSNOAgtikhPzKOWr6eBxzxb3+7ZUlGRaU6PIAy5Qx8gHfu5vHOy79nTivlv?=
 =?us-ascii?Q?0VWzal8FmBhLLeq4fMeet6BrfAV7HXhEHxdXjs1fHxTgZD7O7JqHiytoNWnQ?=
 =?us-ascii?Q?8apj+yyP4bpXIhGR9mfsWJl2CYkSYMXL17xZqm4fsJu50MPIv0SYpdek08ak?=
 =?us-ascii?Q?anzfoOUOLQWgRjwBn9x4enYqglxGq9QYuzLFaQhiOZx1Vm46Kq/YcQizDJyU?=
 =?us-ascii?Q?aH9iVVnuLXyHF081E6rWmYX/SWusCpxS+Suo7deeRysmIlrufdFl1bGqTeP9?=
 =?us-ascii?Q?OoLdwlNkLsDPC1eQLOSN3tOxhw7HWKxm8proMkQXVsDKtIIlZ3q3Q4F4635H?=
 =?us-ascii?Q?ypRZ3QsRfAohcac0mQ9GrrUqfrpg9SEGrjvtN5dwEXDAIxasTQxjQt3y4E75?=
 =?us-ascii?Q?F3p7H39apXDA6afq2z5t6th+KEnNPbKc8vjI2SNy7oTa4WO+0lOwPfjnVlOd?=
 =?us-ascii?Q?QzXvz4WGMjaZoBx/5eCobu8kcuiZMIwkCNu+?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(35042699022)(1800799024)(82310400026)(36860700013)(376014)(7416014)(14060799003)(7053199007);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 04 Sep 2025 07:45:57.3702
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 8f6bceba-7f59-48df-93b5-08ddeb8715c2
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AM4PEPF00025F9C.EURPRD83.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: GV1PR08MB11089
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=pSGA9Gc+;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=pSGA9Gc+;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender)
 smtp.mailfrom=YeoReum.Yun@arm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Andrey,

[...]
> >  /**
> > - * KUNIT_EXPECT_KASAN_FAIL - check that the executed expression produces a
> > - * KASAN report; causes a KUnit test failure otherwise.
> > + * KUNIT_EXPECT_KASAN_RESULT - check that the executed expression
> > + * causes a KUnit test failure when the result is different from @fail.
>
> What I meant here was:
>
> KUNIT_EXPECT_KASAN_RESULT - checks whether the executed expression
> produces a KASAN report; causes a KUnit test failure when the result
> is different from @fail.

This is much clear. I'll modified the comment this again.

[...]

> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks :)

--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLlDjmQF0DSOqILw%40e129823.arm.com.
