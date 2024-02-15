Return-Path: <kasan-dev+bncBAABBZWGXGXAMGQEHOLO5UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id DCD40856D80
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 20:17:59 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-5621580fca5sf1637803a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 11:17:59 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708024679; cv=pass;
        d=google.com; s=arc-20160816;
        b=UVphlaydf+PuBFgfneyFXAdbyGJJzj2JCoeu+8J5JxTQL9+S0nFHNnuzGSgE9S3Wt2
         ZNmneu/owROCxOFi+yfxXSo6l4zTiLJG1U+PkOKJLQPwrwPH6oZgsCIJPpDoQ0XsRbPC
         xP80Zn379BE5BZBTh2JZ7gWvL2puUj6WZ4lSzvuxQBqtXa+Ykq7mUebfqzwDfVUwuSTB
         ND0Pw1R1bY/OyxTGrpYaV87IMqScmOBpdEvjoNUZJ4ii/7KmermcwyBcU7ROdMoHWbge
         iS/DLlPX5e543mzgL4EraCrfUVELdR5fuvtw4yz0R4GiCWK1dxd79W1hOHKlfc9A35z4
         kBhQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=FHI+P2lJCff8x0Ahl+Xd/P0vcyT3IPo1vzs7/WCuD/8=;
        fh=gSzMsClIRgeiVa+ZUS+TdROwW5IqNRiz/qBobXDJYpY=;
        b=CsII2zwYqu/vtmMAkGZb+h3Tc7BBzDw07f2BGjXL5LjwgSnjhcj7YqD1MGIBNTRBQy
         sf3eXzkM6NESjxVLr7aXhwb78oJheT5ZLJWks/PGSaqaMenmI2DdBI6Op4nEBifznQxI
         eH4nsrKNiWSVdougmHWumpRhYJjHiNHt25x/wFPcNldLBhvOOgsD1MVboGUrzH/NrNoN
         KjHRoQ29+b4FsEvBv/V8mNjeGABu84ioKmj27RSXgCCPJ+cGV/yVRSFTxt7HcQhiVGMq
         DoyBHldhy4jm3crf4TDdFXJh2Bjx8IroaM6OFSY7JhZVCp3GMaECP2uzgrsUepVrBW4j
         PFAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=D3+5OjrM;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f403:2e0f::801 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708024679; x=1708629479; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FHI+P2lJCff8x0Ahl+Xd/P0vcyT3IPo1vzs7/WCuD/8=;
        b=Zc78gTYroT5VZFmRousdbiXkcbO8fr983PKyEd7Wxxw1YA+Pv7XdF/wDoSTihyUWSx
         hXqaEDnP/lrddIb2RG8f7IsgST741o7GAEmSpzBZJH5hztkR+hFXbLcp9RmEoMli386G
         SIxt9v2CHLjFm0eCK6nPXy78rVOxIj9SfGsxe3E+z6CODgtwQLUI3kZwVVuaSeIYHX/R
         BQpBKAzKKyS4Cgqu97Xw3or2TEmLHpDKwKRcxP2LTrSwxCEPkjB4K4UwPYm4/Rcxd1s9
         U70bC26P07kWz6Vu0VEpXXvNtsZ8UkDHPdPcNDYTmLFNJcvxF8CH8Uge1ZM13fyaBaLT
         AvZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708024679; x=1708629479;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FHI+P2lJCff8x0Ahl+Xd/P0vcyT3IPo1vzs7/WCuD/8=;
        b=S1zOgBmDBJGddYl+uPnQa2rgHzlgEVpIUoTb1pCWIqUj3b71PWqnCCZC0s0Ram5ViX
         7gVj5AFyFL5Bo57NGKyNKX5/oWmeypv0ZwwOJlOyFGO52UALjeNQSjfZDuo3a/9JmGvi
         Swx1RcV9bqVxKiqGy3bC+W+jc6/SNuK74Wpu0eGf7NFxVouI78fyBEMTdTV2qcZHHFFI
         4z84ynp4/21EmKYFIT6USjzwolsS0c30nUa/9z+lNY2Qlox4son7IpVyxU0nIP9Z676Y
         73Z2rST0qp/iGKjCb5hCUVpuPf4mB80wMlRnP+MvGjZbG61/3UEPzFuvH4u0zfYusvQs
         V4XQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCXGSyAIFMN0OKmKCMNYaI5E0HyGpF+Ynfu8VVkw8s3ahy5qjBMhlrOE4aBURC6pEgTtaxSg+BfB0T45yVCKRipQiQiyT7OxQg==
X-Gm-Message-State: AOJu0Ywn3ATy4vSmnEO7fw9ISA6ekvVcaN2hQzWTQXqJCJFrfDD9CtAX
	3TRwNFMfDPRZ9YrHrJIksKXUkXSFVQLuxkdHOGP/+8yMzmTKRBOF
X-Google-Smtp-Source: AGHT+IGA/RRlmfZae6WiucZo9BNl9bI2sJO3VMkNgvNT9Z7EOvzRNLhSgkmgP5W1BqIegyY8+wE1pQ==
X-Received: by 2002:a05:6402:2405:b0:563:c2e5:5289 with SMTP id t5-20020a056402240500b00563c2e55289mr1867394eda.13.1708024679143;
        Thu, 15 Feb 2024 11:17:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4490:b0:561:63b4:b06a with SMTP id
 er16-20020a056402449000b0056163b4b06als35856edb.2.-pod-prod-00-eu; Thu, 15
 Feb 2024 11:17:57 -0800 (PST)
X-Received: by 2002:a17:906:280c:b0:a3c:2f68:54a9 with SMTP id r12-20020a170906280c00b00a3c2f6854a9mr2647715ejc.3.1708024677350;
        Thu, 15 Feb 2024 11:17:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708024677; cv=pass;
        d=google.com; s=arc-20160816;
        b=UquEAp8lrBufGRwpQDNaQDik042gtP6GSyapFBRqlLt9EtAJx2sKSZfrH159lD/xDp
         V67abbhL8wXpSIPKdVVgt+uP4rPz32xsAzJJDKLsoqr8IYcJODtiO55765l9i4BJXSu1
         PBc6uJqP/tJfmibH82WYgjT37/kpjMEOfDJ7cHZv9D8DaEvz6pGy5cZjm6vANHAZdMlU
         BPpgR5eqhSUbegCuIQ0qsAFPZTYTdIiDl9zBWgd3eeP+oULUgj/S/4U27tXIg8G9yQ7w
         YISGBv01HemHJESFa2edRqZ77q4WJkYBj/6CyOyVtt/i0SB+h7v+7fw6IC31vqIjO+/Y
         6NkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=clT4qt/TkJCdoqftxMl/h4sVvqEPAyVqVotivf4wvKU=;
        fh=gs3koJsRte1hkBBOJcSQX014JRME+LB8R7AyE3W7NUk=;
        b=aPMOfqaYsxPgtVVFolu8wi475fNeKJ6tPBWvF2+KVS5nXbAM0VtqyTtRWMhJwDxZ96
         qlvyE8ZT0fi24jZkrFr1zTjAlVOG9njvmiolRvlBDo9Hc29VA48hGFxAlOeISz9AUh3R
         l/7ed48zSUL1EvpE8iqYkLTlc9/PsDzxINQ+1RpgSCsU0jUQD8phUWue1iWqugZD6czO
         nxDX48tGqFHLniS4Vr134xKaPkxlWZF1r3AfpG5VVwUWKPpu2jzG4zrmeDMVCj5Tr5Jy
         k1+gD1Yowh7j5UHU/zIgCDE7aga4EHFpWFyl5NpEF39NNSZ48meitn2pLyR/VUx4tB5H
         6bzw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=D3+5OjrM;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f403:2e0f::801 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR04-HE1-obe.outbound.protection.outlook.com (mail-he1eur04olkn20801.outbound.protection.outlook.com. [2a01:111:f403:2e0f::801])
        by gmr-mx.google.com with ESMTPS id v3-20020a1709064e8300b00a3d6acddb2bsi80329eju.0.2024.02.15.11.17.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 15 Feb 2024 11:17:57 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f403:2e0f::801 as permitted sender) client-ip=2a01:111:f403:2e0f::801;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=So/jpOxhMeScO/KXLoov5jwTmvJbhylZlZB9ngcCE9VCwQcrA37sBii+C9Hk2GRPsXY38YV8ZeOjblNzra/0y/y5+32GW9zUZxrBC4/a654fUDP1GIa0zw/jJOy6B3yDZzPHq/RH2zI2TlYwyCgabLWsM+Yl1NVa7SAMyt9EcsLL1ovvmEz9p3+grXeH+lZTRvCX8V80DpVa9Q57H4kKKoo4nF6A167l7K+xgLhiqQIY0CZ6bSUHa+gVJyLoVZQ2/bHOyKLt51/7r77/ZtwNc6ONncdHTWP0n+nJMCE53W5xC3u8yJGLgOiCHSt94mYlhBuJ+dmyC2lvBc+BXfsCOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=clT4qt/TkJCdoqftxMl/h4sVvqEPAyVqVotivf4wvKU=;
 b=DZU50yl+2GfvXdUBZ3IJJxpC6qQwHAo5nGPG4PFfbyQYoOUS7zvDLAMrbl953MD8T6SoU9dXMXjEMv0R0VOGcRiLFvDFsTuHm/a8bcT39zJLPAevZF8btD5oQIRoMcl/g2IQ+B5G6LwiusiuLlNoO4zW1j2Wfz6E3Xb3+cCp/2lQE46p4NzhfIsrwWAuWJ3TnP33EswRzaSWRTUw5m5gZq9EZNeEo6vEpFWEM/lf7WC+FSZpEqUlqmpQrANuQ4KzCy9seB2hbZrDrvdGI1dEYYH9LkE8bQn1PCHUYgPosYSKbYmLY9Ch1UUGuBif6yyzI1WtLsDnwE1ys2iyqvjevg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from AM6PR03MB5848.eurprd03.prod.outlook.com (2603:10a6:20b:e4::10)
 by AS8PR03MB7064.eurprd03.prod.outlook.com (2603:10a6:20b:29e::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7270.39; Thu, 15 Feb
 2024 19:17:55 +0000
Received: from AM6PR03MB5848.eurprd03.prod.outlook.com
 ([fe80::58d5:77b7:b985:3a18]) by AM6PR03MB5848.eurprd03.prod.outlook.com
 ([fe80::58d5:77b7:b985:3a18%7]) with mapi id 15.20.7292.029; Thu, 15 Feb 2024
 19:17:55 +0000
From: Juntong Deng <juntong.deng@outlook.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	corbet@lwn.net
Cc: kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2] kasan: Add documentation for CONFIG_KASAN_EXTRA_INFO
Date: Thu, 15 Feb 2024 19:17:23 +0000
Message-ID: <AM6PR03MB5848C52B871DA67455F0B2F2994D2@AM6PR03MB5848.eurprd03.prod.outlook.com>
X-Mailer: git-send-email 2.39.2
Content-Type: text/plain; charset="UTF-8"
X-TMN: [7syb3p4o9NNOOt1pBPNJaw1LkI/E6JzT]
X-ClientProxiedBy: LO4P123CA0627.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:294::15) To AM6PR03MB5848.eurprd03.prod.outlook.com
 (2603:10a6:20b:e4::10)
X-Microsoft-Original-Message-ID: <20240215191723.35167-1-juntong.deng@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: AM6PR03MB5848:EE_|AS8PR03MB7064:EE_
X-MS-Office365-Filtering-Correlation-Id: b05df645-6d42-4c76-dd4e-08dc2e5ad044
X-MS-Exchange-SLBlob-MailProps: AlkLxVwsndmQJIsjirGokQVJ/lfvIDvZhrdTXLfBIxJFaJ+fkGENmPRMB/mYs8cowYRFp059SXgeymq7Ik6IUT4lbkOPrdRgOSqODAdpsDcWKhe5Fh5aRCPhY/icX48ePMLqki3vSrRuyH28r1mO0e/4SPzYJQL5TJt8vwxUnGg1oczeL6R8RkO7JjY2OODFEFtCJQO+m6eVl0sg6nf/gUBiYReETGebCEvJHQA1khRmIXSIFFq6qxPhsDU0oWhMAbFkLwa6c4X45YZRDSWALQfysRUlUZ306c1qSVaPslyz2u8YVJlH2C8oqXkXgKiPj3UgwwoZW0T8/k2SsqVNpF6vRXNRthgXcB4IR8AteQO7/jBqHFkSHf9ozfyD24RmeFBhOxMc7QWC3oGoiEFMiusHnuuEzGaEix9EsC08GMoaCZnWO9IAVOahWYqZ5jCBjEieBx9wwa7AlGl3a1F5ura5+l1JcA0csW3A3xXY5v7tNwXNlnw32+bJm5tvnuQh45brPfIOuRrsWgmNbPiEtUIrarDvAxte4NaegSHyysyywIz8WiqCPkmBFSXBy89Yw6zA8dJxTJFHOgj/a9zD17gdJkORm7HhrF+NVe9eJ+dtPfPvJU2zv8fHPI3l+61CNzrbIAjvQ6RdFq3qiLUQLubNDKfM+rqmfnjGYOr7ngl8CxSz0/F2v4eECIa6e19TCljpkYVDubSi+GM0Q3XNoiu5yTpRHdenj1ybn7RMMJ31ftccoDleDY04O+++YE2ofmgLG+r5US3NM87J+brTKCTT7QlAplEB
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: YlTMErR6FDS9R1TOkNZ05GXB5XPOMaA/aDbNITeg+lqN1FnXf/HolqilEcUmoGedWhmbWYVNUI+yH83t8qaBXI/9x7frtGPuRqr6pp4Ppx/yCSRgMSBqWupGXV9ygQ89rlM+fcNqvhVFnKSXm0xB3sxcEfmT4yy9ufV/jYz+is2SyAVO8O75xoQOdjG4eMRJpq+SffaRIGRfMcCuqgYQMp9WWDuTp2yc2k0aza0sOE3WN8Oy+coTDCZ5RNd36EqMNft8eGXjpRiO2M7i6597WfgT31unf1HUbDeUoE1fe0pavvkTNsVvhDRl5F/czGcEYtWTDJFor4viOat67UtdqIBdRLXnT7fTEes8xAzZj9Bz4PFPO+4pE0UZavxmwLZBOfKxj1etyVqaNkAH45XuSs3DsdqfsEQ3tfgId9jmcFfeh7KQ5hNyboOTpQnPxZyY9sqf+IvNoEuCd7wvl+9QXh+PVgJ29boPTTyfzXcTD5PJVdYG68RtvAc8BPrYWoDSOsGFZD3PLknbZVcY4MJq0Qb2npLnFIIwI81Rpo8waX2VnS//lGa38GRkq0/WKf6v
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?9OzFaSswNo9G2D9txM7B7QtFuiUyLmwpsarR9TUcZ5sWYm4k0c8E4Ei9rd9S?=
 =?us-ascii?Q?nImPZ6P8zyKMykAG82p6NUnVmXfYhLzjElaU4swMWXkvCi8Pqpi9H5zJiqCJ?=
 =?us-ascii?Q?kAEU8pHQewJAsYWGf23YM9muhjt4DybOkrNSlev3WhUlR7YtnxV3yZ+JHI4B?=
 =?us-ascii?Q?XkQevuTjSz8zlvYw37Y518rAc345YrhLdn6si+W2atzRPPFSdcl0EqnEwqm5?=
 =?us-ascii?Q?JLs5QL1s27YoQvxDVGGvcj69Z4a2luZwmbXAcohAulmBtphQF881geD76VfD?=
 =?us-ascii?Q?Jqan/qQIuyOgRwvHboi03QddzQIt9eaC8t38eVTcaRZqZlPB1VgfDiKQrkoI?=
 =?us-ascii?Q?GEGrvV/E8XtKms+9gf12hf+6Z6wtma50m1fYJUZ7yjT++aVmuV/YQ1KAeG3A?=
 =?us-ascii?Q?s2AxAoX08OpQTn8K1WZmdKEIh6qVI0RT7oAfeS60iCGkcoLSOMoGPfbcza28?=
 =?us-ascii?Q?FK7HPI2W3oJqMnNYFHpFD/BUv/yUGTyFUz0UI+2p7NtOuSff8aH/I80OD9Ja?=
 =?us-ascii?Q?5GmEJLITPj3/wKnrrV3lylQ8mP089Ty0fVCBlLhrl83FXg/bP5egvyStYVkU?=
 =?us-ascii?Q?/SevW3p3hGA8Lf3Ew5eZU+nBu5i/JGIDmXtYGTbb3mjKbNvqezZyUQvwT4Z/?=
 =?us-ascii?Q?+fomMAiG+2pBfEJTZHw6D/bgnQHvK/AqB6RgCMgT6T+vLAGhHrEEfObmy+Px?=
 =?us-ascii?Q?yiw3q4uVMp0Uo9DcK4dpyrJSfGZO9Ztyedpovi/NSYtt7xUyRG+MiaDGKwa5?=
 =?us-ascii?Q?N6MQk+3n8tW2hyCrzcOdswZQWoexkPZ6Vh7KRG1WY8//jQMD6IydITBKsbCi?=
 =?us-ascii?Q?wYY24wcfalMZiIEplYD/WRcBQyqHefGvpOtAO9hSlet6qdAbo8zHAcnLlds7?=
 =?us-ascii?Q?FxmQ51YHqiMbbitH3ZRcLSOG2yy6TBEhUC6tfyvjjjN+spckjgbT2N4EJShL?=
 =?us-ascii?Q?fHw7yicnfBBkuZy/51/mPs7e7vE8VPbTqCEzplMOrZanxGs2FNs430Brmy3U?=
 =?us-ascii?Q?KJuURtKXNLSnmOgeQqUl5vD4eQEdA0AuMChjaipcO+qFXcwCOQ04IWRTCfHb?=
 =?us-ascii?Q?cblMck3Z3dPwAojTFXaIaSsc3GbF+RTQR9kQJc54hMJxq+9pERofF5PYXf2w?=
 =?us-ascii?Q?/1wqCaCaI9yMHqxajTiNSh2g0iXX0F5MTQrzhFbYVzrqvXRe1dGAPzEomtt9?=
 =?us-ascii?Q?FWygJWoM1+NRXu90FoasO9m4R/R9bpSyCs9MsXuuCZnsvGgW7CwJwgGCgZwA?=
 =?us-ascii?Q?DDmiEQl2X9o2qp96r2ko?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b05df645-6d42-4c76-dd4e-08dc2e5ad044
X-MS-Exchange-CrossTenant-AuthSource: AM6PR03MB5848.eurprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Feb 2024 19:17:55.8135
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AS8PR03MB7064
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=D3+5OjrM;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f403:2e0f::801 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
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

This patch adds CONFIG_KASAN_EXTRA_INFO introduction information to
KASAN documentation.

Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
---
V1 -> V2: Fix run-on sentence.

 Documentation/dev-tools/kasan.rst | 21 +++++++++++++++++++++
 1 file changed, 21 insertions(+)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index a5a6dbe9029f..d7de44f5339d 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -277,6 +277,27 @@ traces point to places in code that interacted with the object but that are not
 directly present in the bad access stack trace. Currently, this includes
 call_rcu() and workqueue queuing.
 
+CONFIG_KASAN_EXTRA_INFO
+~~~~~~~~~~~~~~~~~~~~~~~
+
+Enabling CONFIG_KASAN_EXTRA_INFO allows KASAN to record and report more
+information. The extra information currently supported is the CPU number and
+timestamp at allocation and free. More information can help find the cause of
+the bug and correlate the error with other system events, at the cost of using
+extra memory to record more information (more cost details in the help text of
+CONFIG_KASAN_EXTRA_INFO).
+
+Here is the report with CONFIG_KASAN_EXTRA_INFO enabled (only the
+different parts are shown)::
+
+    ==================================================================
+    ...
+    Allocated by task 134 on cpu 5 at 229.133855s:
+    ...
+    Freed by task 136 on cpu 3 at 230.199335s:
+    ...
+    ==================================================================
+
 Implementation details
 ----------------------
 
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/AM6PR03MB5848C52B871DA67455F0B2F2994D2%40AM6PR03MB5848.eurprd03.prod.outlook.com.
