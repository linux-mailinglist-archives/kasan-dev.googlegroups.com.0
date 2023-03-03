Return-Path: <kasan-dev+bncBCINXLESYINBBAE6Q6QAMGQE6UXGOZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B6E06A9576
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Mar 2023 11:42:09 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id e17-20020a05600c219100b003e21fa60ec1sf827931wme.2
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Mar 2023 02:42:09 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1677840129; cv=pass;
        d=google.com; s=arc-20160816;
        b=VwzPQnf3FcT0SYY6JGKCO1IhW+A/Pk9yi9UauPdP4iCtTUgm2DoQJOkzBfn38IaCal
         WLU1DQYLguyjBPyZcDstuxSPkEu/eNG8I4WKubVhZDxMCFdQ6uRBUcuu3DpPfDL/hkQx
         P1sgcJqp2Y3DKofrw02uash2drRDrRVccIJhqvmandPhWvuGrHGhvjQ9Gji2AYoEhNHX
         4xFzxkSVRreu+tPaMKx5UgDdoSEAZ4iRnK3OhIKV85vGU6Qovv/hDa4HYrn7mAkDp5sS
         5K2YIRMzH0GlO/z3wo/ndjFNyWiOl7iPQQirZrVg6JmmhbLEvJf8eDAc7bAill/dUPbs
         WHtg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=SRGl0J1XLK0egXcAsMIpznfeM/k53ZlB/JNmr7eHTAo=;
        b=rLT2ztrz75kjy8eh7u93Yb7k0p+PG2UiICLMAMllHep/1UUpp154ryX4VMwlQQS8ne
         cQ3iV3r+A4mKd3eUWl97QM7MJx2KTSvEKeqqovp8P9mu21qybvl3dmx++8HCMBqyPAo7
         roxIvgrcbtqHXLxx/Gk+F5q0FxCTcofAOnbNUN4SN4oCeXowce9ytqUxO6dk79DJCnCX
         /XfteF4VuxLxquV2jK8t3bIkpWV0sKJIYLww6gee3C5Dw765gp8Mw9HSJgri1ATRAAxN
         xB1i5gKdsLz8yGzuVmI+ZEk8+CAxyYWxnX94d48WWWtXWPE3oIaUvApPmvk92dK0SgAM
         LG4Q==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@zeku.com header.s=selector1 header.b=ta2Rk1WQ;
       arc=pass (i=1 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);
       spf=pass (google.com: domain of yuanshuai@zeku.com designates 2a01:111:f403:704b::72a as permitted sender) smtp.mailfrom=yuanshuai@zeku.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeku.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1677840129;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SRGl0J1XLK0egXcAsMIpznfeM/k53ZlB/JNmr7eHTAo=;
        b=K0Lyjx5CV9pKuXNmzpT8U5ymThkXLVhn6P0BOIFytUbD4tPRIGHiJYzBGk1vqhx61X
         XHD4Nauu5yHFcfjnJFS6ufJERuUOtrDTLgYUmpxQY142pINQaQs6QqROGwQp1wHZHIVj
         MOABhxbhAovVqpbF8j6WTpBXgUn6yblFmGKXkNSesQJcM4CasMBNkY0oyjnDs0bRzOSz
         VqTCQdW+QqGRfhqRgNmODwGy3pBzpi2CmpntW06qACaQrQp6rhLLYuCWkLuT/THOGTEx
         V8Rs4XvFX+WKej4b33B2o6l8GD611/a79h2DXYIbCcISISS0O/tbf6T8VAUMHh4nIbfL
         OKRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1677840129;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=SRGl0J1XLK0egXcAsMIpznfeM/k53ZlB/JNmr7eHTAo=;
        b=5w3pFYoA7cO3KzMNxX1QsEjvIZKhJ5tkzKndHaBTFDuWrPw4LCp64BHCfQx1gng+FS
         R9Mh4qjP8wz5QkV2qnN3+bzkrm5M2/UNf34rCp0IptuqM+IMWxNrzjs0Qdfr4uzed+uD
         jn4sgej8w+PjjaXrMpCDyZ5K//WbhRtWiIAzEOuLzbRi4L9yX8YfYVNGI2Q/vP4ka6G1
         8725A0JKczJOzzESMVhaq2P01ujfGZH5IKTyuDYBacKVN0pLSF25NXtnN0vyEmtaMjJD
         n4RGgsQgOX+g9XPo+pQm+bDkfxumejy1SUbh7XIzNpzAJZmw5ZO8FH6ZJy55Ckozfi7B
         nGeg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWFf6kIRv0Ng890SmqpdWk1pvZdSEyfNFD9BU+a9MurZZBgtMyl
	xZTODgGptHQsqehorzL/aH4=
X-Google-Smtp-Source: AK7set+xQdN5kvePUC5awq0ILFvuzJ6qyvo+6ZPsCxM5bhenF93v3RLBWJ4ZM3CrWum0RjE13Ag7ug==
X-Received: by 2002:a5d:69c8:0:b0:2c8:f4a:59f8 with SMTP id s8-20020a5d69c8000000b002c80f4a59f8mr357123wrw.3.1677840128737;
        Fri, 03 Mar 2023 02:42:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3ca8:b0:3cf:72dc:df8 with SMTP id
 bg40-20020a05600c3ca800b003cf72dc0df8ls2952525wmb.0.-pod-canary-gmail; Fri,
 03 Mar 2023 02:42:07 -0800 (PST)
X-Received: by 2002:a05:600c:34d2:b0:3ea:c100:f5e7 with SMTP id d18-20020a05600c34d200b003eac100f5e7mr1116972wmq.39.1677840127465;
        Fri, 03 Mar 2023 02:42:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677840127; cv=pass;
        d=google.com; s=arc-20160816;
        b=t+A3YdYqlZi9Bv189yRHUqVtCbnyhZnWLBFcH5+OoJQyvdnwdHc/lDwU/cDTCWISb/
         ifibU0ouFap/GK9al9+q+q3iRI1dq+5q4ALz3ZtChHe4BZ21otA6ubxl1l3cpADpxis2
         Uks7ROw4s5o6qsHou9ztkTRJJ+Wcj9LunF2wdocmlhN8XXct7WHOlzwYwb2RDgsSyXEt
         Codigc9q7SJYYRy/b/1tCKQnCwuANn3WHT3kUoMUDhRnmMgpFX2KBXeubGhFTkhqNP1J
         PqeovWIw+EDbfuY8VUi8GZhx/JE/6P2SWzR6KeaN+ww771OcavbtcX11INIBywOOetk2
         IWPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=X6hkccg2J+hl9gIRA7Mt1Zdg4oRxJZj7piHMtYfiq/Q=;
        b=MZGK4cH3HYQWDH+4NGOQCYDDHrUxcmcrOmjbbpxZS/gUE+g/5YwBX6xy+cL71/tq2l
         0A68T1/Rpx1+XwFn3JnToQNECwlPPnIhXy3Rgi4eepfD+GTWCQ+lhLwZkHXCpvMgoC+l
         aFNaSXZwGBZsNPtZITmctxZZvNuMpxp2eSzOT7ExrmAG6LlDQ3wIN4jqN2sef0+xI+9w
         hjcQ+s1Xb7A4LYqJrCyrWr6HKTwf6zochFCd3kJmMNaBd5eme1piNb3+cVF+z8gEkqj8
         /HVT7KJkGztbrVnoGYZ1iZPltrVb94vg2zY9yWU1YcABuZLnnbAAqwpvPNjz+KERcG7a
         631Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zeku.com header.s=selector1 header.b=ta2Rk1WQ;
       arc=pass (i=1 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);
       spf=pass (google.com: domain of yuanshuai@zeku.com designates 2a01:111:f403:704b::72a as permitted sender) smtp.mailfrom=yuanshuai@zeku.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zeku.com
Received: from APC01-TYZ-obe.outbound.protection.outlook.com (mail-tyzapc01on2072a.outbound.protection.outlook.com. [2a01:111:f403:704b::72a])
        by gmr-mx.google.com with ESMTPS id bn3-20020a056000060300b002c59bef13d2si73174wrb.8.2023.03.03.02.42.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 Mar 2023 02:42:07 -0800 (PST)
Received-SPF: pass (google.com: domain of yuanshuai@zeku.com designates 2a01:111:f403:704b::72a as permitted sender) client-ip=2a01:111:f403:704b::72a;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=PrJdTlNI/TmX1beozvz6zUz4M4A48H1FhA1OZuAXlMYE7UMAQlrtik+0Lve65t4LgcuL7kA1GhqwAifmdt9gv/A93U6A6Z/UO2NLRlk7A/jhQrpZ1NscRHrvgGWMT1IWe4gvWyP/CcxVxUXB1fbmCIrLMKcDu71VDMeTCYpPafp+IvNEZcNypEk83Qqj0z6sn3ZnDL1OkPYC3az59Dd78Iu1sfUx8Es23FQD7rZhaKQzO9NV1HmPYvnrJCt6OhbvzBsnDTB6eJ5wJerFeA4Owjl1OJGEGoKGcYlHih1cpIZ/W7IA8kD4FY9e7+cH46D75GVt/yUrnPA37VYFpVsSYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=X6hkccg2J+hl9gIRA7Mt1Zdg4oRxJZj7piHMtYfiq/Q=;
 b=fGFNDgzvsMccioAf5g6mkePy8ZfUwSFm0NM+RloxGU1pkBvACuC9su2LdBkBzzF1ddSaSd6YPnbVvbg23AZUrsgfnJ+bjABubxmYgRAv5jWRRcKFHPLjjVgQkBTfKeT0lvmyNVFGeovUcS4qaZcng1lpL/jAH+6ze+knZLhk3eajklzVtS0PZvSzpERkiTOaOSAzePtLAfwSjoOYU23aLU8QjPe36m+TbUHDXQciBtSvZcMYZDbLIuDbtt+ikvykx//QtPZgSxhj5w5WHkvY6m8n/FhZ6R6rwsUmixy0OLnwXXe3HObYpD8GIxs7YfzUscAJMbwtw6pL/oQHg05Wag==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass (sender ip is
 103.192.253.182) smtp.rcpttodomain=arm.com smtp.mailfrom=zeku.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=zeku.com; dkim=none (message
 not signed); arc=none
Received: from SL2PR03CA0005.apcprd03.prod.outlook.com (2603:1096:100:55::17)
 by SEZPR02MB5888.apcprd02.prod.outlook.com (2603:1096:101:74::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6156.18; Fri, 3 Mar
 2023 10:42:02 +0000
Received: from PSAAPC01FT056.eop-APC01.prod.protection.outlook.com
 (2603:1096:100:55:cafe::6a) by SL2PR03CA0005.outlook.office365.com
 (2603:1096:100:55::17) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6178.10 via Frontend
 Transport; Fri, 3 Mar 2023 10:42:01 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 103.192.253.182)
 smtp.mailfrom=zeku.com; dkim=none (message not signed)
 header.d=none;dmarc=pass action=none header.from=zeku.com;
Received-SPF: Pass (protection.outlook.com: domain of zeku.com designates
 103.192.253.182 as permitted sender) receiver=protection.outlook.com;
 client-ip=103.192.253.182; helo=sh-exhtc2.internal.zeku.com; pr=C
Received: from sh-exhtc2.internal.zeku.com (103.192.253.182) by
 PSAAPC01FT056.mail.protection.outlook.com (10.13.38.168) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.20.6156.21 via Frontend Transport; Fri, 3 Mar 2023 10:42:00 +0000
Received: from sh-exhtc1.internal.zeku.com (10.123.21.105) by
 sh-exhtc2.internal.zeku.com (10.123.21.106) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.12; Fri, 3 Mar 2023 18:41:59 +0800
Received: from sh-exhtc4.internal.zeku.com (10.123.154.251) by
 sh-exhtc1.internal.zeku.com (10.123.21.105) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.12; Fri, 3 Mar 2023 18:41:59 +0800
Received: from sh-exhtc4.internal.zeku.com ([fe80::b447:eb25:37fd:3fd8]) by
 sh-exhtc4.internal.zeku.com ([fe80::b447:eb25:37fd:3fd8%3]) with mapi id
 15.02.0986.005; Fri, 3 Mar 2023 18:41:59 +0800
From: =?utf-8?B?6KKB5biFKFNodWFpIFl1YW4p?= <yuanshuai@zeku.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Andrey Konovalov
	<andreyknvl@gmail.com>
CC: Dmitry Vyukov <dvyukov@google.com>,
	=?utf-8?B?5qyn6Ziz54Kc6ZKKKFdlaXpoYW8gT3V5YW5nKQ==?=
	<ouyangweizhao@zeku.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander
 Potapenko <glider@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Weizhao Ouyang
	<o451686892@gmail.com>, =?utf-8?B?5Lu756uL6bmPKFBlbmcgUmVuKQ==?=
	<renlipeng@zeku.com>, "Peter Collingbourne" <pcc@google.com>
Subject: RE: [PATCH v2] kasan: fix deadlock in start_report()
Thread-Topic: [PATCH v2] kasan: fix deadlock in start_report()
Thread-Index: AQHZPDZzScKWhyj5L0eV70o/eMb/rq7FygeAgACH4+D//5aGAIAAy+8AgAC6aDCACH5tEIARtn+AgAJ7vQCAAF9zAIABQRKAgAMl3+A=
Date: Fri, 3 Mar 2023 10:41:59 +0000
Message-ID: <942d0845b3ac42f284ac6c790d65b095@zeku.com>
References: <20230209031159.2337445-1-ouyangweizhao@zeku.com>
 <CACT4Y+Zrz4KOU82jjEperYOM0sEp6TCmgse4XVMPkwAkS+dXrA@mail.gmail.com>
 <93b94f59016145adbb1e01311a1103f8@zeku.com>
 <CACT4Y+a=BaMNUf=_suQ5or9=ZksX2ht9gX8=XBSDEgHogyy3mg@mail.gmail.com>
 <CA+fCnZf3k-rsaOeti0Q7rqkmvsqDb2XxgxOq6V5Gqp6FGLH7Yg@mail.gmail.com>
 <b058a424e46d4f94a1f2fdc61292606b@zeku.com>
 <2b57491a9fab4ce9a643bd0922e03e73@zeku.com>
 <CA+fCnZcirNwdA=oaLLiDN+NxBPNcA75agPV1sRsKuZ0Wz6w_hQ@mail.gmail.com>
 <Y/4nJEHeUAEBsj6y@arm.com>
 <CA+fCnZcFaOAGYic-x7848TMom2Rt5-Bm5SpYd-uxdT3im8PHvg@mail.gmail.com>
 <Y/+Ei5boQh+TFj7Q@arm.com>
In-Reply-To: <Y/+Ei5boQh+TFj7Q@arm.com>
Accept-Language: zh-CN, en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [10.122.89.15]
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-EOPAttributedMessage: 0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PSAAPC01FT056:EE_|SEZPR02MB5888:EE_
X-MS-Office365-Filtering-Correlation-Id: 63f2b70e-2e6b-4ad7-f539-08db1bd3eb8b
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: TFTPp4LceXDjjXT8/gSO3QNbmLUHtDGhilU6ODwH02bVrlQFEN/yceIzjCsRw2wOphpZOCIhG3UThI/rxPRYT1yLKNei9X35ZCWJlGnQXFfq95fr7BhiFhumksVUTf9MlIWdutZxd3r2T9MINlc7oGBEiHgA3MCBdkxrPI5/zrX7o5de7enWccLDPup1FUHTeUJnJsvG4srnRAgqPeAnyy3tI7S/BXow5wXaJYopbP6bkucLYZJKfCLJNmd1EiO9MpL1PwFVlTFnKHz6Y52kn/OvKASHsJFi+q3DDSPPldVO89dvt1+N5V4TkrA4zUWp+EJYphFjpp7oCVQehLLT/oCXpbMtahWGE4bG1T0JTAa0/fOAiZ61c1GI4AYUjXix8wZ/9OaOp0f8wJZDcpGbAUxf7NXRLzzGSfbqVshsj2XsM5bqfjsglwaF3qxBvKHF+2bThJGxA8Cqgqy93AeCkSvVQfYzAr+sIJnD2h34GruBFALVM6UF7ADu+b4eSh6hBAiLSlz6iawo1Ato0GdPDs71W90040ZxM42l0C9yUOhZL/WSawdIgN32IF5YS87q1gKd9TXsMfm1t9kXA4CdoxNjANedgWVdmJsEWq5WX4onteabmveWwJmIJorSCaabDwFUPEpsOi5hzfJgV3gt/64x/U/G8iJAUrWN946XVWRa7UxPz/LGKnpLmNcrhp8KOsTcGbajT12sMun7tAEOuQ==
X-Forefront-Antispam-Report: CIP:103.192.253.182;CTRY:CN;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:sh-exhtc2.internal.zeku.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230025)(4636009)(346002)(376002)(136003)(396003)(39850400004)(451199018)(36840700001)(46966006)(83380400001)(66899018)(36860700001)(426003)(47076005)(36756003)(85182001)(24736004)(5660300002)(7416002)(81166007)(8936002)(82740400003)(86362001)(356005)(40480700001)(82310400005)(186003)(108616005)(336012)(478600001)(26005)(2616005)(7696005)(70586007)(8676002)(316002)(70206006)(2906002)(54906003)(4326008)(110136005)(41300700001)(36900700001);DIR:OUT;SFP:1102;
X-OriginatorOrg: zeku.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 03 Mar 2023 10:42:00.4893
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 63f2b70e-2e6b-4ad7-f539-08db1bd3eb8b
X-MS-Exchange-CrossTenant-Id: 171aedba-f024-43df-bc82-290d40e185ac
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=171aedba-f024-43df-bc82-290d40e185ac;Ip=[103.192.253.182];Helo=[sh-exhtc2.internal.zeku.com]
X-MS-Exchange-CrossTenant-AuthSource: PSAAPC01FT056.eop-APC01.prod.protection.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SEZPR02MB5888
X-Original-Sender: yuanshuai@zeku.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zeku.com header.s=selector1 header.b=ta2Rk1WQ;       arc=pass (i=1
 spf=pass spfdomain=zeku.com dmarc=pass fromdomain=zeku.com);       spf=pass
 (google.com: domain of yuanshuai@zeku.com designates 2a01:111:f403:704b::72a
 as permitted sender) smtp.mailfrom=yuanshuai@zeku.com;       dmarc=pass
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

> On Tue, Feb 28, 2023 at 10:50:46PM +0100, Andrey Konovalov wrote:
> > On Tue, Feb 28, 2023 at 5:09=E2=80=AFPM Catalin Marinas <catalin.marina=
s@arm.com>
> >
> > Right, but here we don't want to re-enable MTE after a fault, we want
> > to suppress faults when printing an error report.
> >
> > > IIUC, the problem is that the kernel already got an MTE fault, so at
> > > that point the error is not really recoverable.
> >
> > No, the problem is with the following sequence of events:
> >
> > 1. KASAN detects a memory corruption and starts printing a report
> > _without getting an MTE fault_. This happens when e.g. KASAN sees a
> > free of an invalid address.
> >
> > 2. During error reporting, an MTE fault is triggered by the error
> > reporting code. E.g. while collecting information about the accessed
> > slab object.
> >
> > 3. KASAN tries to print another report while printing a report and
> > goes into a deadlock.
> >
> > If we could avoid MTE faults being triggered during error reporting,
> > this would solve the problem.
>
> Ah, I get it now. So we just want to avoid triggering a benign MTE fault.
>
> > > If we want to avoid a
> > > fault in the first place, we could do something like
> > > __uaccess_enable_tco() (Vincenzo has some patches to generalise
> > > these
> > > routines)
> >
> > Ah, this looks exactly like what we need. Adding
> > __uaccess_en/disable_tco to kasan_report_invalid_free solves the
> > problem.
> >
> > Do you think it would be possible to expose these routines to KASAN?
>
> Yes. I'm including Vincenzo's patch below (part of fixing some potential
> strscpy() faults with its unaligned accesses eager reading; we'll get to =
posting
> that eventually). You can add some arch_kasan_enable/disable() macros on
> top and feel free to include the patch below.

I have initially verified the following code on kernel version 5.15 and it =
is valid.
Although not using the latest interface, there is no fundamental difference=
.
I think this change should also apply to the latest kernel code.

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 1f96a72c7edd..73b7fc532d81 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -28,7 +28,9 @@
 #include <trace/events/error_report.h>

 #include <asm/sections.h>
-
+#ifdef CONFIG_KASAN_HW_TAGS
+#include <asm/uaccess.h>
+#endif
 #include <kunit/test.h>

 #include "kasan.h"
@@ -107,6 +109,10 @@ static void start_report(unsigned long *flags)
  */
 kasan_disable_current();
 spin_lock_irqsave(&report_lock, *flags);
+#ifdef CONFIG_KASAN_HW_TAGS
+if (kasan_hw_tags_enabled())
+__uaccess_enable_tco();
+#endif
 pr_err("=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D\n");
 }

@@ -116,6 +122,10 @@ static void end_report(unsigned long *flags, unsigned =
long addr)
 trace_error_report_end(ERROR_DETECTOR_KASAN, addr);
pr_err("=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D\n");
 add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
+#ifdef CONFIG_KASAN_HW_TAGS
+if (kasan_hw_tags_enabled())
+__uaccess_disable_tco();
+#endif
spin_unlock_irqrestore(&report_lock, *flags);
 if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags)) {
 /*

> Now, I wonder whether we should link those into kasan_disable_current().
> These functions only deal with the depth for KASAN_SW_TAGS but it would
> make sense for KASAN_HW_TAGS to enable tag-check-override so that we
> don't need to bother with a match-all tags on pointer dereferencing.

ZEKU
=E4=BF=A1=E6=81=AF=E5=AE=89=E5=85=A8=E5=A3=B0=E6=98=8E=EF=BC=9A=E6=9C=AC=E9=
=82=AE=E4=BB=B6=E5=8C=85=E5=90=AB=E4=BF=A1=E6=81=AF=E5=BD=92=E5=8F=91=E4=BB=
=B6=E4=BA=BA=E6=89=80=E5=9C=A8=E7=BB=84=E7=BB=87ZEKU=E6=89=80=E6=9C=89=E3=
=80=82 =E7=A6=81=E6=AD=A2=E4=BB=BB=E4=BD=95=E4=BA=BA=E5=9C=A8=E6=9C=AA=E7=
=BB=8F=E6=8E=88=E6=9D=83=E7=9A=84=E6=83=85=E5=86=B5=E4=B8=8B=E4=BB=A5=E4=BB=
=BB=E4=BD=95=E5=BD=A2=E5=BC=8F=EF=BC=88=E5=8C=85=E6=8B=AC=E4=BD=86=E4=B8=8D=
=E9=99=90=E4=BA=8E=E5=85=A8=E9=83=A8=E6=88=96=E9=83=A8=E5=88=86=E6=8A=AB=E9=
=9C=B2=E3=80=81=E5=A4=8D=E5=88=B6=E6=88=96=E4=BC=A0=E6=92=AD=EF=BC=89=E4=BD=
=BF=E7=94=A8=E5=8C=85=E5=90=AB=E7=9A=84=E4=BF=A1=E6=81=AF=E3=80=82=E8=8B=A5=
=E6=82=A8=E9=94=99=E6=94=B6=E4=BA=86=E6=9C=AC=E9=82=AE=E4=BB=B6=EF=BC=8C=E8=
=AF=B7=E7=AB=8B=E5=8D=B3=E7=94=B5=E8=AF=9D=E6=88=96=E9=82=AE=E4=BB=B6=E9=80=
=9A=E7=9F=A5=E5=8F=91=E4=BB=B6=E4=BA=BA=EF=BC=8C=E5=B9=B6=E5=88=A0=E9=99=A4=
=E6=9C=AC=E9=82=AE=E4=BB=B6=E5=8F=8A=E9=99=84=E4=BB=B6=E3=80=82
Information Security Notice: The information contained in this mail is sole=
ly property of the sender's organization ZEKU. Any use of the information c=
ontained herein in any way (including, but not limited to, total or partial=
 disclosure, reproduction, or dissemination) by persons other than the inte=
nded recipient(s) is prohibited. If you receive this email in error, please=
 notify the sender by phone or email immediately and delete it.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/942d0845b3ac42f284ac6c790d65b095%40zeku.com.
