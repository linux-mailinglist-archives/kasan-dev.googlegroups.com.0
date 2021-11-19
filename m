Return-Path: <kasan-dev+bncBDAL5AMDVMDBBIMR32GAMGQEAILFENA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 14559456E24
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 12:21:06 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 187-20020a1c02c4000000b003335872db8dsf3415220wmc.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 03:21:06 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1637320865; cv=pass;
        d=google.com; s=arc-20160816;
        b=HV7xwNu0Tm0CR7RLZi8kudkd8pT7clCxUCOi+eRHUKHgT7r+46m8Givs/DUskuaZdg
         v0fAHcf3qZ3n+vARpPnaN5RvlltNfVeJHSiqOG/6uyv2ni3J8bbb5oV60+DBK/MExl2A
         NeadlXigbJ9KerM2tpXCR0QWSNxmjZXbO0XMh3rH2Xjs6gWhBTXfxH5LQwvIrWKEPS6R
         fDwW8B0nfdCuidWY+gBxyIn6nBmcTkQAJCmtzC83ZCgqTtKHigZKuKKEFKqiGzttUKci
         sAsTYw34V2MF39asrj9ncArDhG1dx6ClkHRVNyL1w/aHL+UfaoxXmoSgDawWf6I//A4R
         K4pA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :cc:to:from:sender:dkim-signature;
        bh=8CZ6XLPwVH9lh5Uicxalyq8r0SH0mlmBwWHya6bKsFU=;
        b=AH8xmtjFnMpRshU1YKHqY94tKdLW5upeQZeoDqEdbLDXH5yVEdDh5rEh0iMHoP18RH
         qo/pXsSVwu7Gqwl7xni5Pjg/cv1B2Kstq9a1n1jhj0FXpVwqHDIM/pyZyzjm6oSM/0F8
         4nNtInqvwC4J59kFMuAtMWvWFX7CnsFK3AyQpXJ0hgB9tzlxGBKNP2en9UMHGGuc6wVs
         SpwLAOqgQ7RmW4fWgHm65VyjmbWtIWzD5c729fIZi/PxZB+7W/pLyqzMQYQNEaMcbTel
         MNA6TpRjLsEmZ/y7F+4ZxGfK8y04fUYO+b3L8X/GAa1nraofzXou90XOuftHw82hOnDA
         y8hQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@qti.qualcomm.com header.s=qccesdkim1 header.b=yED9UPF2;
       arc=pass (i=1 spf=pass spfdomain=qti.qualcomm.com dkim=pass dkdomain=qti.qualcomm.com dmarc=pass fromdomain=qti.qualcomm.com);
       spf=pass (google.com: domain of jiangenj@qti.qualcomm.com designates 216.71.140.77 as permitted sender) smtp.mailfrom=jiangenj@qti.qualcomm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=qti.qualcomm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :accept-language:content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8CZ6XLPwVH9lh5Uicxalyq8r0SH0mlmBwWHya6bKsFU=;
        b=qgLAqOffV6ftf5QNVMX/3e9XBVxnGcFa4gzNsSviwiov9nPpf4WFCH4ehz8e4ZNOoE
         CZPv6Kwm72W6fDiFjD5Ubgm2qxHZNEoCiKrE4r7S5zgvAzqI6ZIi0NzSZMav7KkZ7NfD
         2KKGIENigzcV8Ncd8+lp+5PEBPHF69QIG+1Tb+Sdr8uAX9nDXLzdW9TKUkieNLDVjmOE
         lU+2AV1RKk7OWDunM1jQ2ekVNk/kvAW7oN1KXrx5t0Xk4mftjReWR3BHJEEwdg6YPqjP
         JrzxxD2oyxTCHtJ6udoXgVUBA2fA3mDBLTJxwLaqjtjNhs0gNg27sAVtZzKsQOd5qWFg
         gMCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:accept-language:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8CZ6XLPwVH9lh5Uicxalyq8r0SH0mlmBwWHya6bKsFU=;
        b=uFTZYXMldhD64U38hYpJQikC3Qav8nDfUcNzouzJeET9oo26B/zd3nF5spBjE1cRuq
         o30vvsWcOFBpATgmjCqMdzl2DuFqremzf0WIfVKNP8MGf3TNsYUzctb+NeublGbG+vYF
         6f4SsxrRn+3+VmNE/B+Z7QVcRSKo6xJ7rHNWu4NYe6pvKLEQUuNgQ2KbsSwYwmAdW22n
         vh55RTLM2J4G5HMzSAObQk4ykWjBlpC/YL0cy9TLz3U4505lWqff8jz9ZsfT+TeguRSW
         CglAEvia0k7cNtbrOGlSYHhnwBOJJ9M5hk1PyTzUzN+57xeREDrhKHG2+vr9/A7fVf9L
         xxbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531z2jC5ZJP2Nj5NVoBdAuR7sGYgvx1Xd7Hou2iS2KHshBE4EARY
	XJ2y3THqkfpbDmnCjaa2HIM=
X-Google-Smtp-Source: ABdhPJxYZD3OvYIY96sasDH5SDJR41TCs3Vr30Ums2Jm3E4gbz8T+q6CNBwhyqFYLHkVGtSucWgYfA==
X-Received: by 2002:a1c:9dc6:: with SMTP id g189mr5702357wme.87.1637320865817;
        Fri, 19 Nov 2021 03:21:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:416:: with SMTP id 22ls6911475wme.0.canary-gmail; Fri,
 19 Nov 2021 03:21:04 -0800 (PST)
X-Received: by 2002:a1c:a710:: with SMTP id q16mr5989652wme.138.1637320864919;
        Fri, 19 Nov 2021 03:21:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637320864; cv=pass;
        d=google.com; s=arc-20160816;
        b=KN4gXsebv0LL5cEhmj+1RueY0Zql9Rr2fqNKnl+kEQJQiU68xKQRQGwBuSwro4GPFN
         1sXzwOsEqEMpHYY5ihMhpSMIxgyr4aLTo4ebEh1oVI2f7qCKQEdkVs561BCKc3GJNQa8
         d2dEQRdkYT690+m5fZUnuC/sWrnKW5zXji8MH6j9aKnaOADroPGqSFw4KChpUQoYDyLM
         rf3eQokI3pW1LgYT/ViEKrqLTlBYCdGQhrdKuOmMXpcnS/5t5oKT6Y2dHX6sF8iRyjiT
         tZovcrFBjUDcOfvAiawlgPtnan1kt8O6wz9izgwm8dL3XuhURPC8008drTJdwsOXnii/
         +8qA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :cc:to:from:dkim-signature;
        bh=zfGvPXpDm44g/oRu7pmKzij6Wad4Vk4MxBLABd5rBGE=;
        b=zxU9lHbaPScarVvTJOEvzbfJkY1xlSitTxze+3dB+nnJvm3rl7Hze9MknBL/UhIor7
         Hkto5i/qS56MidVYQQWPQeSW4EEokzHDjLwIs3cbJSea7r/GnxmNsnEzZtsAaRG7v/b0
         EnE/lAEyGnZ9XVz+VU7uEKPeIog+C+tmfvfpOqsIICGBGTep7PX+mCF48c9ufnSLsLf3
         4EYbbYKXILWC2VGP6aLkpswQ2zOFQz7FRqmGxmKAM2fjowLGf37WwrfjkbKi7GRbd5el
         zfySQ4vOIx46EQwCOdXQfH5RrqDm0qV5gF2m63Xvara+duHVoz60J9P8PQwkhyWgqwIf
         wsfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@qti.qualcomm.com header.s=qccesdkim1 header.b=yED9UPF2;
       arc=pass (i=1 spf=pass spfdomain=qti.qualcomm.com dkim=pass dkdomain=qti.qualcomm.com dmarc=pass fromdomain=qti.qualcomm.com);
       spf=pass (google.com: domain of jiangenj@qti.qualcomm.com designates 216.71.140.77 as permitted sender) smtp.mailfrom=jiangenj@qti.qualcomm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=qti.qualcomm.com
Received: from esa.hc3962-90.iphmx.com (esa.hc3962-90.iphmx.com. [216.71.140.77])
        by gmr-mx.google.com with ESMTPS id a1si172987wrv.4.2021.11.19.03.21.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Nov 2021 03:21:04 -0800 (PST)
Received-SPF: pass (google.com: domain of jiangenj@qti.qualcomm.com designates 216.71.140.77 as permitted sender) client-ip=216.71.140.77;
Received: from mail-co1nam11lp2168.outbound.protection.outlook.com (HELO NAM11-CO1-obe.outbound.protection.outlook.com) ([104.47.56.168])
  by ob1.hc3962-90.iphmx.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 19 Nov 2021 11:21:02 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=eClSXIvypYlAT38uORz0PJ8WwMhDhZOWlCH9gakeTfD6/vrL3woIBL6/IHdbMFTUkqrQX59gENQsOfj7XOxbvMLkbpwbYaQvB0mmtSvD7UKZAnrK1BCaFqDlDDk5DlxrJh9GgZ/cvpmtlwj74dsW0FsOBiz4OwXKNVKQS/88PM/i7WbkKz/jHUrv3fXN8POY8elhupZgb/U4ijfrP9JXVm/lx0zKr73lAELUMyo6iW6jxjcqATM+zOeKWpaQPgXU6sChPoHw8V3V1yTIHtTH2fTBJKZ0N1t7F1LqVV0uaMMqPI4htpCohHE8jYIGTbqgpdKfw9Gb1txOdZjI1EgOGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=zfGvPXpDm44g/oRu7pmKzij6Wad4Vk4MxBLABd5rBGE=;
 b=Yd9Dkjzo9zHEVL2ThyuVjitDdBtaxN019Nyw3vQ7ky4cfphroNGj8Qunp7Ax7eHICZpc8X3oiPym1OfSEBzkRFfBoHcfM0Tz7N0ACHNbkHDYYam0Eq1gD3p1BB38u4m0Z8uI+d0AfmufKGC/3EZ9Cp5misKkW/ZCnOvsdGtjBf5XSrK+L08B81JfdefSrVqw7U4/xlpEm0gHhjVJPUsWPZMCA3Zd1IaKbu3GJQm1BMiKDO0fkGOy7L0s2D+Gv+Fhg/wLtmFMfFmBcu4WxsOUme9tj27wwidC9ys9cT7cFGPBImun73LYMTLchO8efb8xwK0FK7wuJTy0JNbVKlRcqw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=qti.qualcomm.com; dmarc=pass action=none
 header.from=qti.qualcomm.com; dkim=pass header.d=qti.qualcomm.com; arc=none
Received: from DM8PR02MB8247.namprd02.prod.outlook.com (2603:10b6:8:d::19) by
 DM6PR02MB4379.namprd02.prod.outlook.com (2603:10b6:5:2d::19) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.4713.21; Fri, 19 Nov 2021 11:20:59 +0000
Received: from DM8PR02MB8247.namprd02.prod.outlook.com
 ([fe80::7049:5fd3:2061:c1f3]) by DM8PR02MB8247.namprd02.prod.outlook.com
 ([fe80::7049:5fd3:2061:c1f3%9]) with mapi id 15.20.4713.022; Fri, 19 Nov 2021
 11:20:59 +0000
From: "JianGen Jiao (Joey)" <jiangenj@qti.qualcomm.com>
To: Dmitry Vyukov <dvyukov@google.com>, "JianGen Jiao (QUIC)"
	<quic_jiangenj@quicinc.com>
CC: "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, LKML
	<linux-kernel@vger.kernel.org>, Alexander Lochmann
	<info@alexander-lochmann.de>, "Likai Ding (QUIC)" <quic_likaid@quicinc.com>
Subject: Recall: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
Thread-Topic: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
Thread-Index: AQHX3TeHWEZhC3t63U2kVih2i1ADAg==
X-CallingTelephoneNumber: IPM.Note
X-VoiceMessageDuration: 35
X-FaxNumberOfPages: 0
Date: Fri, 19 Nov 2021 11:20:59 +0000
Message-ID: <DM8PR02MB824702D8ADBA2D3C3BD83C6EF89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 7f117a25-8713-4d38-b6e0-08d9ab4ea9a7
x-ms-traffictypediagnostic: DM6PR02MB4379:
x-ld-processed: 98e9ba89-e1a1-4e38-9007-8bdabc25de1d,ExtAddr
x-microsoft-antispam-prvs: <DM6PR02MB437955AECE6D7486952534D6F89C9@DM6PR02MB4379.namprd02.prod.outlook.com>
x-ms-oob-tlc-oobclassifiers: OLM:4502;
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: bT3U0qVGmXEdu7Lx7nvjr/LSE3JJgwvBgxmRUWw4LGAVHo8jZDU5GT1HqwenkaDvJZ3jiXTxqSmEaXG9MLsrYdctnz7srDJIQ1T6ACmHlmf3zc7XdTm4sqinZHTZXjLjrnc+WaxFvUyUWrMlZ9whZNvTh4wOlb0cfL9ZeY6oK8gTjpXZn2Cr+ofDqrJ47TpLqZlN++qMzNxxobdYv1NS3I3VNuC0wYkisKVOu/0g9l5N43D7Xzbbk44zJilW3jOLXd0gKY9Vd6tBk5wQADpx2TYpFdAjXJRRYGlWDtRftDpElVn+RLAF01Z0G/PEYHd0XYq5xZ8vqx0UuWKIElL3hqEGCjFAdOmoukRQf8rIc5Wq6B6PHpZIhcm3Fqev20fEcun4U5ShdT/MVhe/tYAv29abCpJaTwpsfixaWgFE+3fLr9H/SUXlAwVR+QdAVeZ3Ejya77iGUGi5iKfShPovcfwWt0Q+IC53O/xp/xfDrGHOsSqkAbgHPoUvHgsysN0884VzaOa8GS/KUodigq9Ll4jI6F4ldmNiD1m9TUERMt8oT0oblJwT09pJjb6qWID4Sh8TMJYVrOSu42jTXG9ZxHQqeIWNGdweLaNbIPlPu0/3H9e4wNBuYG3DfF2GkpFxoJ9CpVZDH5xFiTkzK+tE6J+SmH1okVGE5wbjAdAlwtyTdsmR2NuXuppj9BY2IP9HbUnTl1c2zMYWYC53qdkZpQ==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM8PR02MB8247.namprd02.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(366004)(52536014)(186003)(7696005)(107886003)(83380400001)(5660300002)(54906003)(4326008)(110136005)(122000001)(8676002)(8936002)(38070700005)(9686003)(86362001)(55016002)(71200400001)(6506007)(76116006)(64756008)(33656002)(316002)(66556008)(508600001)(66946007)(66476007)(26005)(66446008)(558084003)(38100700002)(2906002);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?us-ascii?Q?OWh9yDybstAErY1ryxYxbvQCsmLa/+TQcLbStNO/uvGFHsB3eqnQwupCyn3G?=
 =?us-ascii?Q?bizqsaTK8j4TCKskAwoE/u7tBoQ6dooqrvOr8t3uU5FNvjuyrE55JHrqCbsT?=
 =?us-ascii?Q?d45fJgxAaFgFerF2kX7sAkuM7aeLAN2wZtjaBfF529hSyrFscBBTJCuDyW7+?=
 =?us-ascii?Q?V9U9gXztkbp7+CfsQmUMNadK/lJ+6Xag6JJr5Ws5pCxCtyGqMGy97XFcHLA9?=
 =?us-ascii?Q?7t2XMBlO9IobmDEQlRtQXwX7uJxLRluuSvG+7/eSYWwvPvYA2smNm1cwfxeD?=
 =?us-ascii?Q?o5e+YxCDwOFccoteYoZ4FxBh58tK3cd9tg03CYW/gy6QVA4bpii0c00kPFmJ?=
 =?us-ascii?Q?jRjUpls0jq3XsvcrwqHE0nU0fpbZMC6wulMFv9VrXNMOa/mmfQuf31UytTSn?=
 =?us-ascii?Q?LUkCYXq+gc7lPi+w3DyAbOgpEoag7Gq+tvUhM2r+AkvWESAqyeccJP7FBqNr?=
 =?us-ascii?Q?XJF6/FJttFSK03qQaqi25neupVGBk13e83JZTIe+sisEWIyThgEi7RtXEydl?=
 =?us-ascii?Q?MbyqWvoRWg1aIm6YXbxnvBEGQK7qO5edKNOQGil7dLDUPeuphYHim1Az9CU0?=
 =?us-ascii?Q?h7RjR9E8PrmCgkBN2XpcSILYdfavJXwJrpP/zxWtflTrNdGbKqmnATTPryxt?=
 =?us-ascii?Q?9FhFKHJcV4eGZQk3au8laEHwF2pT+zA/sNgKMsRuUwG2EH8MdWSNb+Kxi7Zx?=
 =?us-ascii?Q?uJ1wA1YOxqsKJGkC4y2mAOaFshmWMwASts+FIS1I+/wjAJg7Bk5FSrbQTkWX?=
 =?us-ascii?Q?FWqd63PFWuQug+ZrUa1fBCKk1jaBXE3ntzjOKpW9OhLlR5B/cn6VbRbYMRdg?=
 =?us-ascii?Q?4eaWvN9bGusKrkX2CTEE7jt3GgROOlQvXoQbTTG6vMnF3x/nXqRDJgqoaU0+?=
 =?us-ascii?Q?nDxnw1K0yH7lsQDEgxwVS7oQpq71cMwvKuk9ZCxst4rzsizXmzwlNcjrMkxl?=
 =?us-ascii?Q?rJo0sGS9y7oeQNZVoVRIadmV6DX2R4akkyYAwASl76VosDl5riIZ6zM9dQR+?=
 =?us-ascii?Q?PoXph6MYLOBzKpjq68A9CBXNt1PhFVBLHUkbj4vXnH2FQH+9DPR280FEYcXZ?=
 =?us-ascii?Q?aVu+nD33nZb/drlWcDEQ5Dsff+avY4p/bx1O3rL8TnBm+iuRngOXAoEX0a+p?=
 =?us-ascii?Q?k82LD1BunVmxBlqSlwdR4dKAgcnhE4zU6TJuLphWykP0GICe8fGqRVME4WwD?=
 =?us-ascii?Q?6/NyRAUTwFMvTJnLgz52feyGZp8/rVQja+X8ZAW2jl61v340zuQioHWFYjHJ?=
 =?us-ascii?Q?esuMVkO1ZOTvbZ04l+8pLKJrnnKc/LBk2+Z4jpON9rkhUGf+6I7H+e93nXCU?=
 =?us-ascii?Q?gA/ykCKOqmH/aEMKrcFe6gW3EMIAxKwfJgATh5BQbWclafTqJ1NiahLHQVQf?=
 =?us-ascii?Q?NUCEfxGNT844v5tmtLXETL5EjJXelH9YxPrU2eMKATcD263NQPf4VQjB54fA?=
 =?us-ascii?Q?Sl2qxwd3mX6NedRP05VJsJLFsryoPOZNG24yjSEbaGonj9C6O54bsKWq6vh5?=
 =?us-ascii?Q?NeEnZ58rb0StnEojtXqNStDBeJMF/zHlapPP2u9EJ2rj/98r4MV2AG7ds10w?=
 =?us-ascii?Q?lHxI+pcpKgbzHR5sjlp/wzn80gb5cxX6ijMDYowt3ETW7nmxDk/+9sB3lW8X?=
 =?us-ascii?Q?PA2X6sNRTrYU7FFTK7aBG113Gnp2e5FVqcUbnY2lnAuQa+xxcPPc8jVM+7qe?=
 =?us-ascii?Q?qQ8YhQ=3D=3D?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-OriginatorOrg: qti.qualcomm.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: DM8PR02MB8247.namprd02.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 7f117a25-8713-4d38-b6e0-08d9ab4ea9a7
X-MS-Exchange-CrossTenant-originalarrivaltime: 19 Nov 2021 11:20:59.1018
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 98e9ba89-e1a1-4e38-9007-8bdabc25de1d
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: NAerHZgDD6EPDQk3DF/EpXU0Lea9/fYy/CMkqK1Lhhs4TSti9qPqab/gr5nM7TkN/3sfTHF+w1sj/zJYJOWNEIWXkvFHhCY8zlNmad10eYE=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR02MB4379
X-Original-Sender: jiangenj@qti.qualcomm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@qti.qualcomm.com header.s=qccesdkim1 header.b=yED9UPF2;
       arc=pass (i=1 spf=pass spfdomain=qti.qualcomm.com dkim=pass
 dkdomain=qti.qualcomm.com dmarc=pass fromdomain=qti.qualcomm.com);
       spf=pass (google.com: domain of jiangenj@qti.qualcomm.com designates
 216.71.140.77 as permitted sender) smtp.mailfrom=jiangenj@qti.qualcomm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=qti.qualcomm.com
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

JianGen Jiao (Joey) would like to recall the message, "[PATCH] kcov: add KCOV_PC_RANGE to limit pc range".

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/DM8PR02MB824702D8ADBA2D3C3BD83C6EF89C9%40DM8PR02MB8247.namprd02.prod.outlook.com.
