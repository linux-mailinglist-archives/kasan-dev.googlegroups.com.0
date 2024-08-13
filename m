Return-Path: <kasan-dev+bncBDGLD4FWX4ERBY7G562QMGQEZDQU5JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 64AF09510D1
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:59:33 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4531a85d3e8sf39815801cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 16:59:33 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1723593572; cv=pass;
        d=google.com; s=arc-20160816;
        b=ENkqkZKwt6vaf4gC4eYg25YjJrsmsHvP9HDdDEkNDrTrDcivyfHlL1UpLE6c0FmM6D
         ultUC+ZJi/K1hog0NzHY9R0buwrDCLV+geHM4vzvO7ZzWVPUCwvLDC7255CYS6NFm60z
         mK9Fdg98jbqRPe01MhJ4y66K/pR2nUC/FnY2I6W4ljozdaC0/fMBY+bgiSPhlSfUjPb6
         5icUGSwDoErzcoRL+ouoBwpHL44w9Y0sKMMAK7xe1arYYUUZzQDrLhu60awmllKOV9Wl
         Az8hskoboUW3QQ6NvZ/VdvkdkPveGjf2+UgoaGmW+qUuBekzOKyuu2e6ofcMiip1jeMV
         E8sw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:content-id
         :wdcipoutbound:content-language:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:dkim-signature;
        bh=xNLJQO/kOsRAk04ioT3wy3wpwMRy0GoEcHhj/3iA4s0=;
        fh=p0tkCr5RwEBST6lZAXmTg+qvfkbi+ZVNrueXvciqAQI=;
        b=M7FOKx/n5U0eoGcWJZ6OcT7szGNeT6j+8D5gIAzbOrfROUIDOjbe055SgOM2UX8ILI
         MJoZpxq+JkDNWZTrmH/SBcI9dlcYaJ5BgOQLI0000xvv8iwIVo9AdVSK44kDa5eTcjVC
         G9ewTx4SqJ5MI/evBQwn31PkujX4JIQGLjwuLxvyCU2V2PCaA3p/dP24ocSPtj1KW6YU
         p59/QSMgXngsNbDP2PKWtQNg1R6ysFAcmxJZYUm8Za9yttMdE6oTXj18FwVdW2Yyu/e2
         Bk13zOYIBMkvau28EL1HVcRQcylV2VFMkdNb1ggocwFuLiBymTwgnOiu+w/mCnffZMlV
         b45A==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@wdc.com header.s=dkim.wdc.com header.b=Sn4V7nVG;
       dkim=pass header.i=@sharedspace.onmicrosoft.com header.s=selector2-sharedspace-onmicrosoft-com header.b="FZ163j7/";
       arc=pass (i=1 spf=pass spfdomain=wdc.com dkim=pass dkdomain=wdc.com dmarc=pass fromdomain=wdc.com);
       spf=pass (google.com: domain of prvs=9484972d9=shinichiro.kawasaki@wdc.com designates 216.71.153.144 as permitted sender) smtp.mailfrom="prvs=9484972d9=shinichiro.kawasaki@wdc.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=wdc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723593572; x=1724198372; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-id:wdcipoutbound:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=xNLJQO/kOsRAk04ioT3wy3wpwMRy0GoEcHhj/3iA4s0=;
        b=lqhswaKG68D4S/R+PxIIKP60bYt+Nq4LsOAzkWNeLb1Svtjmi4cQGgiarGAPw4g4q3
         XseyZITSB7TirKKe6CBCxlDLDap6Uai/k3P4VODSfOdLF1EpY0nyVyQAEa/JGhaPZ2P1
         D9vm1d12Udrp90esEG3km3aueg8bWBtknWZUa+90zgZVT7iv6UqFeJb55bLFr8T5OPmz
         VJ9acdqB1nI0qmFjI4yLBm5ddzDDAevcpqq7lINblrWr0vUF39LbpREWggbVI2gaRbU7
         pxAE+b7fxsLyB40XPdlts890zy23bPlRVVj1UPOGfrUSZwi6y0VZwFtjX5Cvr4l6RJk8
         vbhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723593572; x=1724198372;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-id:wdcipoutbound:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xNLJQO/kOsRAk04ioT3wy3wpwMRy0GoEcHhj/3iA4s0=;
        b=dwo92EEnrRf5ljC7LM5y2EbQ3PR1KSwKOhIyFavTyckJ4ak1xXeuXXqolRmYleQ2QG
         idm0YhiZYYkYw7sPrPNbGfhPBMi6+fK0Rlqqnfj0H1066FTW3UHxOCJSrh8ofR9ZWqGv
         uoTFNR8zkz8awg1q5GveUQu7XrIr+R2hf2iAKCdKGFnNdvde264xCRO6MYAoTn0RzhDt
         LL3NeiVSciWJZf3UKUEmHCSpSmWrORDDrgNFQwUrSMRpAExgSF5o5VYCcCSBjgG+ZnHb
         TJIlQir0B2VxYAuUZRK/jmC+NUQLJetO4r6mZTngNA/EXVUdmUqWo6zSfXBHKCBI+FTo
         ZfNg==
X-Forwarded-Encrypted: i=3; AJvYcCVLbIKupPdM0D3S5JC7B8kciLp9h7oZNn3ht2httY8sKvetpq3I75+AcO1lk3fu18anGjzk0ZyO2i5qD7wcm54AUPuZSEbgtA==
X-Gm-Message-State: AOJu0YxynolCg4ygwJx8Qjd4xmwDR3Tlubk/M3fvpNSAG+3Ukl7RM0a0
	0DurBsSY7fDbJjtDPJPHQ74iSz90sJdojuc6npjBN2ejfZz5GyYA
X-Google-Smtp-Source: AGHT+IH+kuvuybEjWYYom1HgUKjNaSeu0NjtxYnBk9FYFMqvlSIw+Xg/IqIOaTf0xUgWqmbOBnDuHg==
X-Received: by 2002:a05:622a:2613:b0:451:d859:2042 with SMTP id d75a77b69052e-4535bbdad7emr16253291cf.56.1723593571817;
        Tue, 13 Aug 2024 16:59:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7f05:0:b0:447:e749:8f3f with SMTP id d75a77b69052e-451d12d9da9ls77786101cf.1.-pod-prod-08-us;
 Tue, 13 Aug 2024 16:59:31 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCW4T2GS2W+pRrRoz41iMi5LBPAkWEIoBhryGknvH0PugHo0s6WMNajxa1W7K9oUWNPbLwzqC2z76JPch7hhIiQin+4cunt7cxG3pw==
X-Received: by 2002:a05:622a:1f0a:b0:453:1e6b:79c1 with SMTP id d75a77b69052e-4535bbdd5d1mr11947301cf.58.1723593570893;
        Tue, 13 Aug 2024 16:59:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723593570; cv=pass;
        d=google.com; s=arc-20160816;
        b=D9btZFDxLYuyYbji+8h6pf+AGpkfOQYbExayeWy4rwCX7EMQVTq0yertD0F1jiLThN
         jVqjNMS+fU3qYARW+T/984RJkok9DU2X0K9pASvGPDfYvkivTiVJIdi2sJtpc5HvztCd
         4HOj1nF9Gi4Fwp2tYp1g8Cu69ugCCjVIJPFaIbmTcR/UUO2d66A4Uul8g5A5PJLF4nzx
         pCIx2Ne4XMXz1UUZ/hrLU1WG2LBdPf4WDk1BTkEiefwZp1Huy4zgi2uMJvQ9/RKgDhs7
         ornJOBIp2pJDtO7i8eWsxy6rnjR/1SJnt7xwj2zbPeMbfmmSIz1buCAxFA3ulCYJvMOJ
         YYew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:wdcipoutbound
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature
         :dkim-signature;
        bh=yQpOJsvupl4FpFbGdgNcXFgvKedkhniNcvGPFzLWjDM=;
        fh=mMvgyET6K+TK8b4q+njXrVQfXHOUxGyHNtliy8cgRo0=;
        b=asI5eCOAua1xDV9Qb1v4xKy6l8+yFpkUb05s+xpz2z1VFNSClDETifFVjStjLvZyYi
         KqqKF97mgxy7q0AkTkfGhB3gV+56XQtEYwFBbiVVHjfKUAN5575Rs+nIk34pLJAO0ocO
         afzmnuVKT4oUwSeg+FF4FVEgsKTY42xDmfybSjqcvH5PR8NCHLUA4p1X0BfD8esY/KJp
         Pe+ua/ZiaxrongtSzWWZ6hYEl0ehL0g8C6jg/I7hhh0oCAuK/IvG4w9IzwYvpSa5579u
         XrlkmjAn1Gwnb4/CD3qaZBvF+MwBlisbL6m8BpS5RTAVg4OImTLZoIAhM9k5PPPQtfi4
         8J7w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@wdc.com header.s=dkim.wdc.com header.b=Sn4V7nVG;
       dkim=pass header.i=@sharedspace.onmicrosoft.com header.s=selector2-sharedspace-onmicrosoft-com header.b="FZ163j7/";
       arc=pass (i=1 spf=pass spfdomain=wdc.com dkim=pass dkdomain=wdc.com dmarc=pass fromdomain=wdc.com);
       spf=pass (google.com: domain of prvs=9484972d9=shinichiro.kawasaki@wdc.com designates 216.71.153.144 as permitted sender) smtp.mailfrom="prvs=9484972d9=shinichiro.kawasaki@wdc.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=wdc.com
Received: from esa5.hgst.iphmx.com (esa5.hgst.iphmx.com. [216.71.153.144])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4535cbdb006si256321cf.0.2024.08.13.16.59.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 13 Aug 2024 16:59:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=9484972d9=shinichiro.kawasaki@wdc.com designates 216.71.153.144 as permitted sender) client-ip=216.71.153.144;
X-CSE-ConnectionGUID: GLQjJo8cSlyAUBPIy2G9rQ==
X-CSE-MsgGUID: nw7+L3r1RNC6otRr+QUN8A==
X-IronPort-AV: E=Sophos;i="6.09,287,1716220800"; 
   d="scan'208";a="25202873"
Received: from mail-co1nam11lp2175.outbound.protection.outlook.com (HELO NAM11-CO1-obe.outbound.protection.outlook.com) ([104.47.56.175])
  by ob1.hgst.iphmx.com with ESMTP; 14 Aug 2024 07:59:28 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=PfN4rn4PRCZ21EL1u+RWZg6BmhDbo5FLSvpVy9lZ0fRZ1eBLWMffTgyhToVYNRfwCszPvPNgEsO9B4E8kAJhzFh69JzAU+p6NfCiDKcbiRUuEoAmHT3zkb81psQixOsUKrIt+xBk/0gdqJoE/uU/R0mDaUp1YCFfzDY+rteLI9pNqmUQqlt5VfmlEUB0E/PhxL+tEEYmFG2Gs3cJfnzNf17zoBoR0fgg467u3JdfKuoyqYDmmTKwCWo9ugIJvjSHfwzhkyeWm21q2kLbLUG6+D55VJPFiv80ZVsq82g+RFqOsRonZOs+dMcvAC+kMtAUuBv2Mg3ma+JJ087cNtEnVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=yQpOJsvupl4FpFbGdgNcXFgvKedkhniNcvGPFzLWjDM=;
 b=hwwS01kjyAbpnforwfSdbweD2kBUXDVM8q8yb91NYc5rGbUy7DahRf/vmY9HT1nkc5DFAh2BHlSPm9k4Lgtyb0jgljfw3IpDAkiGFCsu9nkFmgbfxbh3drFZynMP+ACRbk4TNIACj1FR5Z4wVSDFy6rxt9AEIjqbMkGVxqnnv5c3RpxD7aVg0ne88th+/egJrITYjbDNNOWBaE8UjpTDgiFQPx735+4qL4jahJ80xoj4CKxD1TgpFCWJLcqkqkFX/a9e7mdTE3/iSsg6Wi+p8Rn/5KpBZfd7KfwaWUDYpmhgWjfpQokNAOHob7snZARcJag08nhAIYM7y37iwIArEA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=wdc.com; dmarc=pass action=none header.from=wdc.com; dkim=pass
 header.d=wdc.com; arc=none
Received: from DM8PR04MB8037.namprd04.prod.outlook.com (2603:10b6:8:f::6) by
 BY5PR04MB6534.namprd04.prod.outlook.com (2603:10b6:a03:1d4::24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7849.22; Tue, 13 Aug
 2024 23:59:26 +0000
Received: from DM8PR04MB8037.namprd04.prod.outlook.com
 ([fe80::b27f:cdfa:851:e89a]) by DM8PR04MB8037.namprd04.prod.outlook.com
 ([fe80::b27f:cdfa:851:e89a%4]) with mapi id 15.20.7849.021; Tue, 13 Aug 2024
 23:59:26 +0000
From: "'Shinichiro Kawasaki' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jann Horn <jannh@google.com>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew
 Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, Pekka
 Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo
 Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, Roman
 Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Marco Elver <elver@google.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	David Sterba <dsterba@suse.cz>,
	"syzbot+263726e59eab6b442723@syzkaller.appspotmail.com"
	<syzbot+263726e59eab6b442723@syzkaller.appspotmail.com>
Subject: Re: [PATCH v8 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
Thread-Topic: [PATCH v8 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
Thread-Index: AQHa7V+aNJWuNJQxqEGdTCA84xSRzLIlQTyAgACdqoA=
Date: Tue, 13 Aug 2024 23:59:26 +0000
Message-ID: <5qdsfymdkyqhc57ww64mphrshgq4ioelbtg3ojwpicmyzwjydw@kgzio5qsmnng>
References: <20240809-kasan-tsbrcu-v8-0-aef4593f9532@google.com>
 <20240809-kasan-tsbrcu-v8-2-aef4593f9532@google.com>
 <vltpi3jesch5tgwutyot7xkggkl3pyem7eqbzobx4ptqkiyr47@vpbo2bgdtldm>
 <CAG48ez2DUgxh3f4N=i60TfHBSTbh2HPMbA8DcBo2g7HSepnzzg@mail.gmail.com>
In-Reply-To: <CAG48ez2DUgxh3f4N=i60TfHBSTbh2HPMbA8DcBo2g7HSepnzzg@mail.gmail.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: DM8PR04MB8037:EE_|BY5PR04MB6534:EE_
x-ms-office365-filtering-correlation-id: 8116a057-4fa4-4ed0-cb70-08dcbbf3f669
wdcipoutbound: EOP-TRUE
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024|38070700018;
x-microsoft-antispam-message-info: =?us-ascii?Q?X84IYnn1a93VnN7ivtwtZE9y98b0K0PycZgowcPuNRWGBHBC5SntMRAM1h/b?=
 =?us-ascii?Q?yy7hbxW2Z7orz8eMm2v+W+oAnXosjG+fWXDeQpYg/HKvPF27ZSz0g4nP9ZvC?=
 =?us-ascii?Q?W9E+1SZ3BG8VUgYqatGzVrMkTr8+4CfZbazQ0PPd/A4A0EtnBOlJqYUjMAnX?=
 =?us-ascii?Q?1cdhZd5++Z93/zirOoD44CvOIyeCKNQP0JFLRQHngNmpS8w9EnkbnMzkbv3Y?=
 =?us-ascii?Q?0AlLp/Z6XUCvc+5Zw8ngJM8/3H6sVBvMZp1OAEyx622nHdRJqXXHLHISLz+K?=
 =?us-ascii?Q?beUs0sWNLf2Lq62jgSV/Tg7nKOclWSc0q9VM8Py9gzcGaECBIrUejvN4RQlo?=
 =?us-ascii?Q?604mpIHNh4kRDRZ2R39bYhotyr64EwYmluSwk0iPGhM9WE4RAiFag8B8s9tq?=
 =?us-ascii?Q?GT1a5awsyXJ4bFxcMzudp5CQfro+FaghRVjNeFkAsQr3llMQycmqLG/lHUFI?=
 =?us-ascii?Q?lo2G9Totv6PgeV0iUApYUhOvkCe+FM6ONTkl7WiKeP/suH6oQJnkE96HKafr?=
 =?us-ascii?Q?CnCCbZd2YQkLLyP9G33KalVB02E5rdE0awC4EbOfQBM3hJnUK8f/kdnQOrEE?=
 =?us-ascii?Q?2cI5NBQmt3lvIjFRUe0yqqBAYlhcSBQFsGi9+mOuHHstOtDMIQXpRy4h/SzJ?=
 =?us-ascii?Q?69hkxyeOBZKpz6+hc2J4l/10h+7D52YBEuChV+OWtWRqpBid0dppFrYHoh/b?=
 =?us-ascii?Q?gt2bxQDRqSKKJUU6K5Y5Zkq4VQFmD0nwz1e25863nCvfDllT/LfX4iGJCZj7?=
 =?us-ascii?Q?6pO5Ax/hk9/ufwpgYO+Xiq1t5DyDiZ8nBeJEBX3H91b6CwWNMR6XjmwM9BZW?=
 =?us-ascii?Q?Zawenng+xvFH+Oh5+f2Lupew72FcV0EZMYcFC4yKtHQ/rAJ78dc9Wj3rmaHE?=
 =?us-ascii?Q?s8RPEeaOZvr4x539Cv6wgaJvyaERcZ8KcUulpC/HW1qtFljp11L7oPY+wUyh?=
 =?us-ascii?Q?bhWCJGH4/FiJza4YZbMSVj9eHvVJD4JF9hdkK9aWVbMstJJVqXGdyxGafOL2?=
 =?us-ascii?Q?eT3JifemJuwhE5ZIRhToIqcoMr5vG9imbOyQ/6vUEelWQUY/ZhXNxmqjkemH?=
 =?us-ascii?Q?zcjtU+/jdUIYWAPq+C98TbIeGnBMuP8AbHIVTDyTCPQsBjVi6PTKSxHQvs6k?=
 =?us-ascii?Q?NFz04stwm8bfvWNHA4ah/WDg/04dC1qfy/ocGguTgDJ8CV7nnziSABe4Nvcx?=
 =?us-ascii?Q?Y9Gwpp+P70uXb2+LAnZpMpMRwtMyNVP88To+jcsLPXyuaTci52E4JcXjo6y1?=
 =?us-ascii?Q?eFi0qMx4g5cjf7/bNrw76DI+R8CJaqVgqy2mIqqw4Tg/d94NaZrHzjtSR6iq?=
 =?us-ascii?Q?ASkbBbtiPsrBuXM9MVQyPWCF?=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM8PR04MB8037.namprd04.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024)(38070700018);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?us-ascii?Q?ahnxXEywiQRqmct6W93Ue+r8VSfYpdlvL9J7epMuhzWfPa5wIOZJbsFVvKsu?=
 =?us-ascii?Q?xbsFGD072Ee14HLZh0/Q4c+Fn3Pkc1a2QULm+v5vr4rQw9RmVQ+sNN+F3+pO?=
 =?us-ascii?Q?iDzNsP8OE7C+CA8WzPyQn8EC71kQqMoAqGtBAjNyhAvLqnkytwDdHI0xCvbw?=
 =?us-ascii?Q?LsBBSbQxQs3Oxlmj/yEC1z4yYTkXLvdD6dryP4WFovjjBLqdZU592HGNdn/o?=
 =?us-ascii?Q?9HTc+tjDbzixg2nDze/UWHJPZQoU6Udgi5vgqUoCOd51qb28Kj9CsdHXd7jT?=
 =?us-ascii?Q?+53ZHksEsgLdltd4B6wWREm0mfP0lphXhGW7jz5DTkyaCJ2iB/eXETNknDZj?=
 =?us-ascii?Q?xSz4wucmaoMtJmSDaOtc2x9DJUCEXCO0954nuspy8yihr6v62i7KouthzATa?=
 =?us-ascii?Q?DHh8E4gUSgyFfZhj4W7SA38GRqb8A45+oOcMrJzlxFEfZlfPBjUFcKaMM4ml?=
 =?us-ascii?Q?CyLMWaTFJBurro+eJB/ouCCW0Z5FPF+MqvgJHEw1wrAPTBWoQunmf9fJ7hvu?=
 =?us-ascii?Q?h+aAtHmU9BlPGN15oVUpzLiP6ScVv80z9ZcyLGA5hEaxElEtm5NHeRs12SAp?=
 =?us-ascii?Q?/jeYN19GCQvB/+DH3AiMySJzRZPGshxcIjJR0Q4XY3pvFAgyYpZi4kArWraP?=
 =?us-ascii?Q?+K/pVR5WhXZWs9yFGfUmS0JEg2cIeDwySpxdS1GR3AI4jGu4hRtDAP9JCYVH?=
 =?us-ascii?Q?0HWhjly/ZHhWQnaHixA2d7J4ORWaa8Fzr51bGIK6Daw3ZURkjWJAz38EoFnI?=
 =?us-ascii?Q?tTtv/3zA9wfhuDdfnuWTjmoSEKz4hywEMe8AfovsXG4Kcap37QT15rbFDyg8?=
 =?us-ascii?Q?r72zVu3ouFtRKp+98azcY9/Yx9oav9BuSC+dF/KhCZUGVg8U3LC9Tg9+tXeD?=
 =?us-ascii?Q?3sLCl9Oqzr7/dU0awZ7fLsljDNvzUxgqPtcsfiSN/jIQjuAtRX/8loL4fii7?=
 =?us-ascii?Q?WTI4QU1fNEHkMS+Er1lh9OoMOtsboPAzD5wsUOpYN/qYGu/LB4jgg0qtGmA7?=
 =?us-ascii?Q?wLR1JABKW71NTKW5z4lihOirI2ZCJsDKBbH6kdAZEOovIZCZNZkXdm1qK/K+?=
 =?us-ascii?Q?xzRtXKIo57LLRWS1aeXq1Pchu+h3mLreTzQnL/cNPzXVxnDbe3oAsGPpzbFP?=
 =?us-ascii?Q?ryA/5x8qeY9ovOr7DBNXnRy2UkyJxBqgeKOowzNpYaN1R2RCsJ5KacczZPyx?=
 =?us-ascii?Q?Hn9VVspK1t8JOyP9M5ukTJQps9yWcsTZ4Q9qjVYvD+uaTj3nRAWZvQ0/olR/?=
 =?us-ascii?Q?gl2/1CSR7eCh7borl0C4kp8f6vNjB89yot5CvNEmlG3RGbHeu1SsK15mv0v8?=
 =?us-ascii?Q?826qutUY/pHh+B5uTb2aG99OoswEoRtkuNGqAlDHy9vgoUynoOWnTZf6qqLY?=
 =?us-ascii?Q?PhKqRVRg++KVXILiG/KxDSp8LHiP96A7g2A3/GudMNDEjgCAC09uS0F5Xy8B?=
 =?us-ascii?Q?uuwOdQeILdrFbyTxzf21qqIb8tVhBWRfMZ6OBDg3jLhSyppBpSMk5cKU/bTJ?=
 =?us-ascii?Q?ZgcDJFzTXH93o1SYjweA6L26PmGA4tkz3M9oqnyKvjI3GvPneQGXOyMktw6Q?=
 =?us-ascii?Q?aMvg9vWn0lTiyl6WujU3ouQInDZKQuKMRvXVS07bGaxHfLfakE3G+WxOl8Rr?=
 =?us-ascii?Q?T9nUottsiZYTPgmBvTM3cIM=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <10172981F48E2B4997229FB7B3BE49F8@namprd04.prod.outlook.com>
MIME-Version: 1.0
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: BxCFubE5eSj/EOFTWOiYSnVJDM0Pc1WdpOKWYaj5JlPy0OMG9X3DfKmCSnwAmNMJdcINT+hfT4/8wP4psz/P26PbG3s3MgX3Qnla2FmWodtOJ46dtIYDMngqPo6uip99JT8ATs/fbTdtxrFRjG0Mo1Qo7CSLYM91Qny6laO3vl7+hz0nsxdxAjBZitYV3hySUGFINAcfPHIh3oWUUbq2AsOXrlnxp01wMOyJ+1aXe0ESydoRdgiQRLIcX1iAN6GJTuW11niSXfTrfiKbpNFbMKOx8cqniFmc5d5mMrZrzR97j6TWbndqKke8MXHgaL7Ox68tcq3K4T7Z3p9yWmIC431TJu9iGwH9Ohm8X0NuBNo+OSpIB0mwhDbDS1Dm5FX6J6cabRlc80eUs8jbwKNZ3o+wsoumCCbB7dXHdM+sIadIeZMoEPbsmW7iEqjuK7HnPsh/vVD4hBz7py6odAgLdcc9FLz24sxn3LuLZi5zTBXp4M7AGKavUs+24F/UN4oWO1s3C3+Qlf4H30BJ+YxyUkvdmc/3gm5BZc2E5E7oCMcRJ62NiqLzkzyLiiWYdqwn+KzXxmaRpzuFykMEV9jVao4FwlKEisXhK1+zoFL9mi+naToE3NaNHFL+83RmPwMR
X-OriginatorOrg: wdc.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: DM8PR04MB8037.namprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 8116a057-4fa4-4ed0-cb70-08dcbbf3f669
X-MS-Exchange-CrossTenant-originalarrivaltime: 13 Aug 2024 23:59:26.4781
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: b61c8803-16f3-4c35-9b17-6f65f441df86
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: vMq/J//wboYQz9bU4a6wmJ68TTp+nJKKP5DUCitRs0lCEaPlQ3i53ezs+uPr9AU5FvnmRmZcgvmTXuzXtktfzVB3Bqcd+cYUrp37/x2PJtw=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BY5PR04MB6534
X-Original-Sender: shinichiro.kawasaki@wdc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@wdc.com header.s=dkim.wdc.com header.b=Sn4V7nVG;       dkim=pass
 header.i=@sharedspace.onmicrosoft.com header.s=selector2-sharedspace-onmicrosoft-com
 header.b="FZ163j7/";       arc=pass (i=1 spf=pass spfdomain=wdc.com dkim=pass
 dkdomain=wdc.com dmarc=pass fromdomain=wdc.com);       spf=pass (google.com:
 domain of prvs=9484972d9=shinichiro.kawasaki@wdc.com designates
 216.71.153.144 as permitted sender) smtp.mailfrom="prvs=9484972d9=shinichiro.kawasaki@wdc.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=wdc.com
X-Original-From: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>
Reply-To: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>
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

On Aug 13, 2024 / 16:35, Jann Horn wrote:
[...]
> In the version you tested
> (https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next-history.git/tree/mm/slub.c?h=next-20240808#n4550),
> I made a mistake and wrote "if (WARN_ON(is_kfence_address(rcu_head)))"
> instead of "if (WARN_ON(is_kfence_address(object)))". That issue was
> fixed in v6 of the series after syzbot and the Intel test bot ran into
> the same issue.

Ah, I overlooked that 'rcu_head' has changed to 'object'... I should have
checked the patch change history. Good to know that the WARN is already fixed.
Thank you for the clarification.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5qdsfymdkyqhc57ww64mphrshgq4ioelbtg3ojwpicmyzwjydw%40kgzio5qsmnng.
