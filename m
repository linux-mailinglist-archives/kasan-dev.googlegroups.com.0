Return-Path: <kasan-dev+bncBAABBPNVXGXAMGQEA6SXLDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id C1853856CE5
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 19:41:02 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-5620a2d150fsf558627a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 10:41:02 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708022462; cv=pass;
        d=google.com; s=arc-20160816;
        b=vpb06QacCT5s0fGa8KUROkPBvHFAH7JE3qEOcODQiuBdiALs1r5L6+Ayl01BdJtuuj
         QSbCCnr6T+amX4uUFF1mXkvu1Cv9zZfFg608Ea4fnHh0TYjhv/dJz7Q8vKphB66SnOSB
         wAmUbZbJdlh1NK6gA1o46kGDPC6huRu39mmBDo+t8lRL3uBgEoA2XoUwVU2Mi/t6NHSw
         eZTTFqw5kXV2x6h5q40sUOEd21SL1upamsxwlkAGrEhP45Em0Mlld8FlVMXzPHxJ4Z1v
         HkR5ReaWgJdd7Ve7Nn6A/uEbhbR5I2nvz5cOAfZB2J5DPhH6LF6A9y6HrXpGmbWgP2eR
         nHDw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=A81PDHVdCgBfDkv78YzqOxgNq0bKmapmSJVa8f/8oys=;
        fh=CdaZJ5c6r/uODdn1WVy2YNgH+R9w1px1ZnhzCMTSofQ=;
        b=SS5fj3wf1Nj6q4N4wCSqU3lJLJe0yyL0fTBpZL69L25SpCE2PEMDR1kz6uCY0C3ssT
         s8z1yWqEdthKz7S/I+dlOtjJIbXbDs2SS9RIlistFwPKEIl5yBcZkVJ78Ttm256A2mAk
         Ag1/jt/DsZUk8cm8auDDDTOl9njj+tGbWVq9gYBw/fUZ+BdOawbTI94O8YZ7f9o7Lg5B
         Mv/Hc+u1V0Bx4dJ2m1u8W+D+YE9AOE3w9dBKtr6HzTjTelPArz6943HIm3rGMuYGoV6y
         teJUXRI9ECZ0FRRgWnDuH4JZTgXUBV+gvtpM4LJJ+VVoay+DEuIRAjJlIxkSxT3cVSJY
         l0VA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=Hmq+H0X+;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f403:2e06::801 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708022462; x=1708627262; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=A81PDHVdCgBfDkv78YzqOxgNq0bKmapmSJVa8f/8oys=;
        b=ugmuYBy93MBBiNUeqvokyMBjfEHXIBTjDeogFNwD9QI9kzlJ/f3+S5nNav8Nv13wbS
         XXxMortv6mZ0RgHt/rmNSOfatfxCPTlnUXx5Y6HXLIlilWe1/3m1k6+3a7URmw4PvkPu
         uBJ1JUsAFTSR0HXrUXuC8h2Nr2cPYeJ+NUeH1XhjceM6yt3I9ML+TtLBrGqbJ2Dfd8L2
         m+s5hE/Dv4w+F6+zBl6M1bHj8plDGkRfpi+UX4aJBd0fdbzKGe0rtOmaHkVapEnxlZ2R
         2KqCbTeM2+v4iR8SP/XrFm3T+IiGd8/oPecEt/ZBqMjNSIR1yI4RpffZnuefZsdf0ja6
         Rcdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708022462; x=1708627262;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=A81PDHVdCgBfDkv78YzqOxgNq0bKmapmSJVa8f/8oys=;
        b=NkcGg2hWFkleBus5fNVZsDdG6R1PsIsfJKvB8Xe1zIz5814Pfo53BGqSHxa34/NIUj
         Wyc4RehsH+hH1SCJWXn7j/Lb9hmGMkf0vGNdgH45t7EYIAAs9A6tx59EeZvv44Fjj0Ur
         G7VxoqzBtvKLFq6DUIEFmiG5j50GQwbDQFX0RFQS174Pc5q+G3EHSRon1kYcoio4oYZR
         iXgp28mlVmVs0UWto/IXW/tKAzaJXnu7QsnMC2oc6PMRZetRtr0fOxUKKDD996sYej+5
         hsZaoym1Q+d9WCZy8AqGqnOBWDZerxkpSxMOEdrYTCA/C/vhOpPwCwo3ouz0764hAnuO
         1a5Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCWKOwgxUnHvhbEGIa4UMa6E1hGyE0URpkh1tKYFURK3WQkML8ncq98DPVSEU5vypJMYaQ3Wh7zxgiATTA3NCl6vcEx8QbkIuQ==
X-Gm-Message-State: AOJu0YyNWOcZ+YSe8fVj47+/Xy8hX3OarfRFrbrchkCZSIRmej9wcX/y
	UA6qHawknz/m3AGrNKo66OJlLUlR0MmuovfAzHLhOdMIFGQhcSbY
X-Google-Smtp-Source: AGHT+IEJpVcxlubPPQUHk4zizigdyaSOblazZriT4yVqnEWhcDlwdg+DiiXtJvSVWPAhsukZh40thw==
X-Received: by 2002:aa7:c517:0:b0:561:c29b:9023 with SMTP id o23-20020aa7c517000000b00561c29b9023mr1858062edq.14.1708022462055;
        Thu, 15 Feb 2024 10:41:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3811:b0:561:6437:6010 with SMTP id
 es17-20020a056402381100b0056164376010ls26578edb.1.-pod-prod-05-eu; Thu, 15
 Feb 2024 10:41:00 -0800 (PST)
X-Received: by 2002:a17:906:cd1a:b0:a3c:cebc:9e0e with SMTP id oz26-20020a170906cd1a00b00a3ccebc9e0emr1838070ejb.66.1708022460580;
        Thu, 15 Feb 2024 10:41:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708022460; cv=pass;
        d=google.com; s=arc-20160816;
        b=oAoeZrD3eiCGqQdUXqslqHAA5fQYqK42vm1ZNFKya+lMCSTyxFX0P6jR1h2D59i2/F
         JPh3hbgkzV6FP3GAXg6bbQNNBonhwPdjQoO6NZap1E7QCVxeu4CimkllwuCpQZsRrg1c
         Wdu/nUdZ2V0vtbZ/0BVdZHdzESmbsw4leD7+m+yH0NEBeSQ9o9b0QFLEK0YYjq3KVBPB
         K1BTWOzQ5dtAzUumF5+gCOR3gwoFDh32nA07lBJGzCmxhGhmnB1xcRi2zDrqb8WQmY/G
         U2U6Lq4+J7GdOEz1gtDyzDyFoi19DRuTsRl3Tnb7JsU+hxT4TPUtgTfHLXKBD2gTsk3S
         YZwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=LYW4I0don8z51CznFCHHe6TYcm1wKugg5YALpmmzYBI=;
        fh=g7k4qO4EmKpubxkW/49ITrMO3BPdfOcN7/w3hRNmBjE=;
        b=c7n4jUI0eDRAujZekmN5EPfsZP+HKPPClxqKpUZ1/oDet1F5wXjb/51J89XAx9Tjkd
         Aub+gUaPSqUwZe/DMnSWP3xXoM57DrGsDRD/d/yKq1O+e+tAckU7yawRccv52l2pyknR
         cYW+94xtiPcr/iIhofkWPTBpq/YYaZ7CP5IRdLvOaCVaD3/ha3BARvprZDYAtKVgkCLX
         pYic7TE9ab88QxNTG5cZy9IjgrIjQEIM/BXjGah886ktL+bmNk0g1GrTf7wpEws20Ik5
         r9IWW11yK6ZKn7NYxgpcvxdsLih5v3D8Pai1rLnwJxBhNr5kRttLw6brcXUAi4AYV0Cb
         Julg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=Hmq+H0X+;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f403:2e06::801 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR02-AM0-obe.outbound.protection.outlook.com (mail-am0eur02olkn20801.outbound.protection.outlook.com. [2a01:111:f403:2e06::801])
        by gmr-mx.google.com with ESMTPS id ji12-20020a170907980c00b00a3cffbbb483si88572ejc.2.2024.02.15.10.41.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 15 Feb 2024 10:41:00 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f403:2e06::801 as permitted sender) client-ip=2a01:111:f403:2e06::801;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=gJMvMjqd2/ohZoEACnti4aGag+61ou2KGF/EwhgXXZbZsRzTcBJUCvJC1uuRFXmgNQjGvK7ryCcjUyNBxRvO4NYmH0EQFhsJ6a8LHAeyhlPF9HrjlPA8cneB/lj4uuOtVt+W0xJRAdYg2eWy41T93OIBosmHVNvoSPdrAGxEyYhn3TK1gUfqQ61DEnc5fJLE5iAc0ovL1Oc8P/OCUG64j/eucXgenUEQxvm3GY/kUNmm4++fPnFDbZfS7KUyA+vL1BloLo7JorivEd2zxZlsO6WufnEgtH2wWrnZJYcyTyQqgDWVVTX7TJTZ39+8GMJvVO9AdnQIt8pIkm42QKJ0aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=LYW4I0don8z51CznFCHHe6TYcm1wKugg5YALpmmzYBI=;
 b=bZ5BClNP4mB/sobKLPEO2b65wkau1IiaTYwvSC6hi1dCYKWJO425dZvjOqtGu4ywjhdNqztpHb5+0iVUNTji4gDaah2qxT8S7RUjIUPFKxgon47tdNYsboCLJfVTk2bhxULU5uHO1Lj4GZavt+OSpbBdtwkOvl5DbX0E6xXiADW2322AF9HNumbwaOk5tgHiJwtUhk915WMZrQSIFDAd55+IdfwXGVI+4ooYH7IZPKrH7sL+gU2rp7TNSEpNEE0x4Ad+s7SgtYd77w0gNCFEFaqJO/yjoPWU+u7RQVmPwxbh0JwYtFip56TE8xj/t2/N3z/Dheu/VQHt6bMf8KeMSg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from AM6PR03MB5848.eurprd03.prod.outlook.com (2603:10a6:20b:e4::10)
 by GV2PR03MB9548.eurprd03.prod.outlook.com (2603:10a6:150:da::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7270.39; Thu, 15 Feb
 2024 18:40:58 +0000
Received: from AM6PR03MB5848.eurprd03.prod.outlook.com
 ([fe80::58d5:77b7:b985:3a18]) by AM6PR03MB5848.eurprd03.prod.outlook.com
 ([fe80::58d5:77b7:b985:3a18%7]) with mapi id 15.20.7292.029; Thu, 15 Feb 2024
 18:40:58 +0000
From: Juntong Deng <juntong.deng@outlook.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kasan: Increase the number of bits to shift when recording extra timestamps
Date: Thu, 15 Feb 2024 18:39:55 +0000
Message-ID: <AM6PR03MB58481629F2F28CE007412139994D2@AM6PR03MB5848.eurprd03.prod.outlook.com>
X-Mailer: git-send-email 2.39.2
Content-Type: text/plain; charset="UTF-8"
X-TMN: [n6tJOoOusIshE8sJ2Vr9yx60s3p7dhzo]
X-ClientProxiedBy: LNXP123CA0021.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:d2::33) To AM6PR03MB5848.eurprd03.prod.outlook.com
 (2603:10a6:20b:e4::10)
X-Microsoft-Original-Message-ID: <20240215183955.32394-1-juntong.deng@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: AM6PR03MB5848:EE_|GV2PR03MB9548:EE_
X-MS-Office365-Filtering-Correlation-Id: 38063376-af7a-40da-8cf3-08dc2e55a63d
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: MYYb+XUcsI6NGGwiZQpbILR/QrTa1z7Uf9+PEVU/g3KMkwlxd+7ySnYh+cgnquol7AE1ZTwyO735Pqcf0A77AGZYJRco3Yx/kXPFlo81uSxn2Cc0+yBpfwkDwCC/BituJZUdD2JcjabOQLEt0CzL7RxvB8Ph1wu5cY0gXT0Xw9JD/mM2Z3zk3WTK9/5qoInAx6Iju4n6WljTKXej1hK6vwdcu0yIlUKibpqHQi8wmEKxTnQ5IX00M6OZsm7lwUdefJfCHwnHb8ecVmjQCXxfVctcmtgtphZsF/O0AbVm3M4uUMeL1IrjN27uCZFo3r8oMGCT7LgjepF5aT1xC49MBpRI3WqEABBphWYwXDjM0l6yzk4O0Pjjycdk4PbDPXKkJ+zNpq0jbOtEZxsF3f+iiR1i4n4bfujiKcMEvrUgPhL/6BNzXIVeQYIVBA6uvtlrrJNKHBFk3KijIxlbDEN4TkKx7eYPOQO+TTg5zQRDy1H+RBGl6+jINhZL9s2bja2vHNh9j27PGiswByhjSUed0SygTNjLrzcO7PjuX83ioe3UAEWP2axC1MyG76bOqoJW
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?pLEqswMD/ICnBQjxx3WYFJHb3Fiyu7WNJeAOmS6L4/ff0Pvrdmkk57J341Hs?=
 =?us-ascii?Q?BTccEIJ/2eGKzHdt5AEmpu+BIYcDlirfN+oWPhc4U/ukS/29Qh5txm3/5cPr?=
 =?us-ascii?Q?ebRj1pu0m6nXqEMU7LObTaJqzR/rvXdyCV/c1UbLXnZnwZy8z8vswvNuHp+J?=
 =?us-ascii?Q?Mz2IApF1kj5M2UpkZK7cobA2XKtEDZkWpo8PngKS+tqwPqZoydtBS6dj/PLW?=
 =?us-ascii?Q?jD6U6x1TlKpsOVOQoAffCa+EXskmIy/d/uhVARhzYVz2CEUFsEEzaiK2QhLX?=
 =?us-ascii?Q?48NGAafvDp2UtDYPDeLKOFwwfE2b9pGZFw3DjX+UFN5N+0VLD3ekTFKzNRbZ?=
 =?us-ascii?Q?LFuQOlL8RZhDt32qVODz+X1N7MTgjC4CpCULQYp8GaXTw1Yme13v5yTCnsF5?=
 =?us-ascii?Q?PZi3B5RrKm7umFX8lGPMqAxjHtZHGukGpBzVYCwXz81r9UDbJ7BbX8xiipK9?=
 =?us-ascii?Q?t110dAgu5khqfos9RPgwcwAez+UICIkdNd2N/CjLIkJw2EVTLH3/tZr6b8i6?=
 =?us-ascii?Q?WzwgldXsPALJv1Wk5GWKHklMPCU97tOmGT5jxQKfsJ27B4h38tu4VhPYlCRU?=
 =?us-ascii?Q?4HGt/LN6JaEcWh1m2Pa+92A6kKd86hmajaCd+1oS/FiDkduJ5aECvjIPkB7l?=
 =?us-ascii?Q?m5THTDW7ssSEBBUt0hXxobyieniWk2hweF88ue4Fm/iaTIP1azPAPqL7OZLy?=
 =?us-ascii?Q?30+5Q75i3SXgMLweRS9Oy9ZbM8ZbH13xd3AHdKMRHiyj56v3OpfIQ7236IwH?=
 =?us-ascii?Q?d+tZxXYhjVQ/VFhtT7EgOPWtygw15px6RWWr3EtRdg1WB3rHrbf4vmc705rX?=
 =?us-ascii?Q?w32wFSG4oscW+zCL0b3ibJbifj/x1ZwoBRGIAppBS/ZODnfU56w2Iykn4nKJ?=
 =?us-ascii?Q?dzR7tpzE21LH9vIpvxYrh1ipeXTumJxFniQ3gqoCZ+eNIGh3oyUVXLapCol+?=
 =?us-ascii?Q?ZiZnSKSxF5v2TD3DvWRqQ7r2XOuNDk6oOBcoVGH0J19TLWDYso5uMKVpCzy/?=
 =?us-ascii?Q?r76wDvb2VVOwkKJtJtKaVnNcW7HhBcrSeU0hnmoC+2sWRcoFhBQcUqpuiHQQ?=
 =?us-ascii?Q?1x1i82Kjn+TnBfRQ+5K6dK+gEyECw2E553v5d+aSvxm8+ZTC24ul5TFfbi3j?=
 =?us-ascii?Q?AE317nrUonKmi3ULnit+IzyloBuTw3h/4+pnjFLkllWshvz4dtsNJPi8UjhE?=
 =?us-ascii?Q?1QufIGGuFd8a97d1CKe4g2vriYNyAlJ3YFr4I1hXqt8TnROZiwn4dO7NgrkU?=
 =?us-ascii?Q?9LrvsfTREm7O+bchpDn7?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 38063376-af7a-40da-8cf3-08dc2e55a63d
X-MS-Exchange-CrossTenant-AuthSource: AM6PR03MB5848.eurprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Feb 2024 18:40:57.8922
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: GV2PR03MB9548
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=Hmq+H0X+;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f403:2e06::801 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
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

Fix the mistake before, I thought printk only display 99999 seconds
at max, but actually printk can display larger number of seconds.

So increase the number of bits to shift when recording the extra
timestamp (44 bits), without affecting the precision, shift it right by
9 bits, discarding all bits that do not affect the microsecond part
(nanoseconds will not be shown).

Currently the maximum time that can be displayed is 9007199.254740s,
because

11111111111111111111111111111111111111111111 (44 bits) << 9
= 11111111111111111111111111111111111111111111000000000
= 9007199.254740

Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
---
 mm/kasan/common.c | 2 +-
 mm/kasan/report.c | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6ca63e8dda74..e7c9a4dc89f8 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -55,7 +55,7 @@ void kasan_set_track(struct kasan_track *track, depot_stack_handle_t stack)
 	u64 ts_nsec = local_clock();
 
 	track->cpu = cpu;
-	track->timestamp = ts_nsec >> 3;
+	track->timestamp = ts_nsec >> 9;
 #endif /* CONFIG_KASAN_EXTRA_INFO */
 	track->pid = current->pid;
 	track->stack = stack;
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 7afa4feb03e1..b48c768acc84 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -267,7 +267,7 @@ static void print_track(struct kasan_track *track, const char *prefix)
 	u64 ts_nsec = track->timestamp;
 	unsigned long rem_usec;
 
-	ts_nsec <<= 3;
+	ts_nsec <<= 9;
 	rem_usec = do_div(ts_nsec, NSEC_PER_SEC) / 1000;
 
 	pr_err("%s by task %u on cpu %d at %lu.%06lus:\n",
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/AM6PR03MB58481629F2F28CE007412139994D2%40AM6PR03MB5848.eurprd03.prod.outlook.com.
