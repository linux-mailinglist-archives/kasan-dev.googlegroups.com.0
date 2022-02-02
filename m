Return-Path: <kasan-dev+bncBDLKPY4HVQKBBDUJ5GHQMGQE2EYJSUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 18BDF4A6D16
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Feb 2022 09:45:03 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id ay8-20020a05600c1e0800b00350de81da56sf4358469wmb.9
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Feb 2022 00:45:03 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1643791502; cv=pass;
        d=google.com; s=arc-20160816;
        b=aLAILHaPL+siSukrTStKQVGiYF5wlLUcBXk1zYLPBE2pfnLCX7+ETnJ7BicQgQhl38
         biglZDeBtCVK06xObplOvx77zH9oHLhicQhmsbDVyWSqeNYJ/FpT5nXs7AlHVH8oADuh
         YlyrHcFCjfYoo5CBKh4jk7iHqAJdSYt6X4zIC/jQLqRcgGPS+gBH//RzZbC+ofG3tVgs
         zznsXB9ryN60LmzPicV31tIhiJq1qhoF/ZPhGyQ/N7RYhmaP5c+jg6Xit2aChJ683cDx
         ymsIK4Bj0ivnF7L77V6sVnkd7lH+pqnI46+kmp9/PPF+wFOx9SSoKmJXTsbGl3p9GUKT
         k72Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=YSS5QYuUDtJLmtFRtQb/5oOVWom13WO+2kq8q3+U+Ok=;
        b=DR0rd+9YM2NKKyTXyDf84Vk79RL/OwxZF4IQKwWCMmUjD65ssnFQSiSdGafDBVbJG4
         PcbmQsKaphcN1Ns+AVE+MjlbASJeVzjk5Th8wCuj6c/z9Up+M6q44LWDlHWhmFqc9ivX
         bZDlp6L5Q4VlmR1Nkq7m16zsvNjKVcQ9QTxAI/V9P5xeXEiBHT4Pk2pSjp8NMaby66k1
         qoeksfoh47Sz9YYKV7hFzmDRzgH3nv4CQeVJlFEGz7HnpN0BkY0RPfJcyg+S9TZTZsLH
         mua0oDfg2QNTKzO4mavgYtXQfhpn+OoCFAFRGTZCrSluTByCGUXfOUogRmSXy3hZH/kw
         iC6w==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       arc=pass (i=1);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::62b as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YSS5QYuUDtJLmtFRtQb/5oOVWom13WO+2kq8q3+U+Ok=;
        b=Heyt1BDnS3UxUjO3w0VaNGeLmVQDwpjbh+zPVcUDUA1UNU6HH2OtIgDezTphWk3p9h
         ckGnRrHGovY6Ws4fLgwq3kURBx6Q3rQP3Veva9QsPKFZ6TNAU5U0RlZdS74Va2ugMDzT
         XIT+S3axcw35D/UdQ/Qjhc0TEdkuZ5DV05ctH6zUUpStoZoYq2D49W0+smItm6zPtBf/
         J+VMsXKWXzy23lY6qfoKMjp3sYRAnJYHvxHB/2U4NUyunW0RDVohgZVEVmSdTZeH5WoS
         S4ucY34/HLvOoy5Lh+hwaJvGcISHTtPZ3Ena2sXdC0oIDoFFjrL5OeCMQJhASeWOJIdF
         RiMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YSS5QYuUDtJLmtFRtQb/5oOVWom13WO+2kq8q3+U+Ok=;
        b=jcyKVXpU2IhjOXN4xmEJVkPD2RZaszQqQSHPtoJvYs5UcXH9u+Wt76sqmuGcdMcGkc
         kuKa8d0JEJt8pONtWzQVTojO5zlBuAkihO9/be3u8g9KU7aB4FT0kQ4qR2xOuJcH5Hgg
         im+Fx4CmUFJVEMjPGjsLJcZ7cs3c/zZE3d7Ir/Q55y61AK0Hw+bra0UgnOXw4ND/aNDk
         HWHeS05AbwpRnpVwURkGlwqiHWTtKdaobPGGpqO+zeo8Fyzz5ktR3dD0sBQtK3NZMH0Z
         L4zb/esCf283rilXDyig+fEcTVjDxNW4Llm31KWMIJWg7digrdKo729rkCpgjeBuxNHn
         WbZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531n/dXqUvfKEP0mFGlIRlMKlAR2tJPPZo3WSfLlPSnItjBr2LX1
	mmskml1UFHdgUgA+gl6tyd4=
X-Google-Smtp-Source: ABdhPJzas5Fd2IxiTyNq6YBJ6zlsuA+fHG+DomVE/ooLNWqBeQDsFfw7VIaiFzwIrLYYIjWuaqww4w==
X-Received: by 2002:a1c:f702:: with SMTP id v2mr5054825wmh.155.1643791502852;
        Wed, 02 Feb 2022 00:45:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f792:: with SMTP id q18ls332981wrp.1.gmail; Wed, 02 Feb
 2022 00:45:02 -0800 (PST)
X-Received: by 2002:a5d:53cf:: with SMTP id a15mr23550998wrw.677.1643791502010;
        Wed, 02 Feb 2022 00:45:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643791502; cv=pass;
        d=google.com; s=arc-20160816;
        b=FgNb4tdm1BLlzgY8CdBqvmfRwRCZdsKfFbIqGbvS8IlK4t+B9HoIsa0/chCKNoCtZc
         IlSrcX6Zsq8R6ZQuFdPqL5AeysYUttQXcwHLJcIhUXk0MeA3NEzSH/HpREHLnU6+mPgL
         lJuolojX/zmNG9uIrja+kn+6kyEZr/inB40xLOkAUPgF47myx16NEfORnFg0BMUgQnE+
         w7qOX1oisz5jDYK8cBmdn0trgtE1zXnOkSTfZ4qR+g2Da9gpQ+YJKBuaJRE1azHLN98L
         JxarisZNBiclOzW/wiG8FlQ7tDo7T3VBFol/CJKarrIckKqDhKWqALUD7OJkBZzy9cJe
         rg2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=V5HZpJSMefTe1BknEmToruAT0+zCkQH76HIrX9oj8dk=;
        b=03c+uNRuSJJk0XbNatSUiboT0YhLFnIWoxojdXoMoxNL4vGyeZ43Ekp7Kki2B2H9uY
         cQXCnnOHK1THjDyfqE0UcwGon0D4bBFvEkWZZ7npbKiY8e6t9/UkMsCBW4pDRI56t3+8
         de3vbv0DtdSv3sivEcajaDbIqWy+LYDXTlL3jB0mzXhq9/CzpV9bwm6pb/K89LndaNhG
         h1tAm910RfwpdOS7r92EUItxhAtgZeAR4eKL5N7heBpb5r+AC8j5XbRIiGPCVskEFecd
         OgWkhGemcg4ZDuHpTMacbzG7+3rMcJ1upccMG2EQvoEnCvi52mnj5WBwmwx7qTZrDKhn
         XPMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       arc=pass (i=1);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::62b as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-mr2fra01on062b.outbound.protection.outlook.com. [2a01:111:f400:7e19::62b])
        by gmr-mx.google.com with ESMTPS id v5si206600wme.4.2022.02.02.00.45.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 02 Feb 2022 00:45:02 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::62b as permitted sender) client-ip=2a01:111:f400:7e19::62b;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=iiIl7g7LGIKvIAlzXpBc86Xg2w8mGn8WHt7bjSDNLN1tfbvhSAmTNFPmttTja4malMfufV5CLos83wAUImpKgYursPI8lT/rV0Bh7LIS5chnpQFkFhnksPg9rn8ts0a+T9jFduDyDbPhWcoJWekwIe6MkEX+eDErJPafaGXlt+eiF9pimWj4CXzhH9DXMkBNTB290Da0vpm+F+siMXb+B/vzpWF51RuscNX5aZ3yP7B2R1RUqLh4DKffJNpIYVXdOOUYuPVNXQfPbxINQ3kfOpSbdOZUkFFUrWTna2Yy7mm8W3/wPPdbMFE/COXLm4fxzJOtA+P+mieY5o+WJMqVJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=V5HZpJSMefTe1BknEmToruAT0+zCkQH76HIrX9oj8dk=;
 b=XaaoJU1+naNIhEpapL851xHOp/d5j5AHQLLPj10FR7qNCPjBKmqeMOrgLdCZ/2AYHvzC+90nCs5yNQP3HxXLLwnPy98thE3r+urGC4VcjT19g6hPYjONAe8jk6zmKK9+hPC7Damp3o0qjBy5/5owlezN/6OBEyr2IwU2WVj+G9sPkHSdsZZnU01S4hW53gQtPw8MWO/5l6FMteUk7TtJNjGa3KcE8aHDtnuc2aR09ZC9Ch7Mp8z1g/VawZ5IKBxvaD4/2xB3OYaiCVNjR4KuZvjEfXrpYKWwz4Y8d5NtOdO8RiBlUPk+J5C76+u3I0wHlaWbkFETBcVsjRXMaTo3iA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by MR1P264MB4276.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:42::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4951.11; Wed, 2 Feb
 2022 08:45:01 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c9a2:1db0:5469:54e1]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c9a2:1db0:5469:54e1%9]) with mapi id 15.20.4951.012; Wed, 2 Feb 2022
 08:45:00 +0000
From: Christophe Leroy <christophe.leroy@csgroup.eu>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>
CC: Christophe Leroy <christophe.leroy@csgroup.eu>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "linux-hardening@vger.kernel.org"
	<linux-hardening@vger.kernel.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>
Subject: [PATCH 3/4] powerpc/ptdump: Use kasan_pXX_table()
Thread-Topic: [PATCH 3/4] powerpc/ptdump: Use kasan_pXX_table()
Thread-Index: AQHYGBEqqckPpaTFM0exPARyP+NQmw==
Date: Wed, 2 Feb 2022 08:45:00 +0000
Message-ID: <976e4678182a5e47311d6200ad8c93bb20c85f64.1643791473.git.christophe.leroy@csgroup.eu>
References: <a480ac6f31eece520564afd0230c277c78169aa5.1643791473.git.christophe.leroy@csgroup.eu>
In-Reply-To: <a480ac6f31eece520564afd0230c277c78169aa5.1643791473.git.christophe.leroy@csgroup.eu>
Accept-Language: fr-FR, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 1b3eafa6-bf37-41ac-fb6f-08d9e6284cb6
x-ms-traffictypediagnostic: MR1P264MB4276:EE_
x-microsoft-antispam-prvs: <MR1P264MB4276618EDC7ADEA2EDF1D0B5ED279@MR1P264MB4276.FRAP264.PROD.OUTLOOK.COM>
x-ms-oob-tlc-oobclassifiers: OLM:5516;
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: E6FRJOEuOEjUES9MLd01MlGvCM/vE7amPAQcuk05qxrYNwo2HKfp/8GcQA//y1eqSY8nJRbuNpHGFtqVQ1avLgWSGZ+fhm3xPebblK5kSVpLDHiFWEl7GJK07po+m7vNHVFxHgJdmYEYZN5t8faFIZ1TDGcGyYx8Pop/mkWUQ0aJAuTmBsqpnLxC+N4mamCkbvKvu/zp1DqrToZLI6VdZlroYklqEoDIhXtjUgByxgPn5CN3Fd7jJmPMut6IPEQg8KuGbcM014hAH62ZhZSBDCzQ6xK0U2j+R8VPu1yxgHuylb38g5cwBNCGPZR1tUmLuFAXJMkeinUPwYvWnr59UKqFWhK/97Jsn1mcJdAaj7bA5ry/jN3LwA9QLQbAx55L/mhFM7Aq9nz3Eb1TJ4SzJ6G2TCU4a2IcTRXl1VphpflL/F4EAZYLXXx2IZ/oDTv2NSuq7+rVExq6abw12TLAg7cCviNJRgv2JDpjPyFTWfWs9Qc7RXiRGrLm1nytLbT1RJFFuO0aeydC1sYyFWjB54rLZqyvfCP7TUBsPw1BVuntUdlErFU8X+vSkPmzvPdEPCKuzQXl30wBNcqP1kOsouv4XEzT/LjdL1c9O0bpyspajI4NQRMg25pvyZ8CVs/18qL/E7st+iZBrlmwxcy8+tssQAzLCwASYWlNlkCDvMp2PDReX5bAkLt4mhx3oqTy34wI+S8qvwzXL1xb4mW8+g==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230001)(4636009)(366004)(54906003)(38100700002)(86362001)(122000001)(110136005)(44832011)(316002)(38070700005)(83380400001)(6512007)(6506007)(76116006)(66946007)(66446008)(71200400001)(26005)(6486002)(2616005)(508600001)(186003)(2906002)(4326008)(8676002)(5660300002)(91956017)(66476007)(8936002)(64756008)(36756003)(66556008);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?iso-8859-1?Q?OwPGI3hMnsa5tPcA1C5LzIfqVM9LmpPIfw+Kkkddsqmyju1gWjjuJDbAYN?=
 =?iso-8859-1?Q?PRRrIGz8kR46KAyqG2DEBVuyje1SSDleDbWZeeIWnsVvnFq83QJXhpfBmq?=
 =?iso-8859-1?Q?Qq1d85z49Kw5wcDPHdxD5jjy+LNP/IGpwGnD77qwHhfRvrTBG6uTbO7fZw?=
 =?iso-8859-1?Q?qTlZ3Af3jW22JkKbfQAvsWZO6qc/geBDkaETQWiei8/vRf20RP1zyGTVnA?=
 =?iso-8859-1?Q?FPirZPuDoK3dzrKD0LMy0RGK8yn83zPmZY2n7Q7ukG4VQ8aFo5NP4iRuiL?=
 =?iso-8859-1?Q?cTye9m58iVFnn0wXCxGKgFGf/UNj6wTVEKNhFSopAQpRgD4m8uzjoMoE25?=
 =?iso-8859-1?Q?bYiEi1lux/A26rE1covCwy8gbKzA/ATHX9+xVuyZOjYgl4O3xKGLdNXlup?=
 =?iso-8859-1?Q?Zng4Z1+2VR8OxxVk74Sbo1M7Fbvb9xyfmlGWHm8pjbv80bac/IfZVRK5VU?=
 =?iso-8859-1?Q?a3gwVF1ZHRJrR52pcuh78HTja7YK2GOB6cAVTjDpWRXNYDlckmDjmPUQIS?=
 =?iso-8859-1?Q?4MlxNC2qX06Ul2kI12Hut+dhWLXN/j1DfrAbu3farsOuG8l5bX9EeWJXtG?=
 =?iso-8859-1?Q?N2RHKyPFqKAfcGPQCbOP0K+LDrRshGilWFOI5Gw4DCQGxdHm2Xcs7/AQZU?=
 =?iso-8859-1?Q?AG5BVT3Yla99sWlQbWLI0bLVVv6FrcFVVArZw9dP8Wwu/hyfHlPN5onmLn?=
 =?iso-8859-1?Q?vlGKHtk+a7S48dGw2AH4mwMcLylDf3pSJ2srQg/0/r5PRqox7cERmbguQB?=
 =?iso-8859-1?Q?G8cKwGkA2gLcGl9Du+ZjRm/jP+J8c8TAWNOrmFCFvHvkvSoNiDKB+QDBsL?=
 =?iso-8859-1?Q?EKM13NYjDO9x98e78JE3izZZ2qGvUUtaJhq32V4JABaWI+S54/iZCAUCsM?=
 =?iso-8859-1?Q?MHs7aacAfP2+9tWMts387n4kWvrF7cAt8iFfW9r4ZoYjZuwjSolIW7CY4Z?=
 =?iso-8859-1?Q?Sqi8yg80x0qWeRkRku8FW01ov53BJEvg45aN5u8e7YBWKgIuyKMOL1zD6R?=
 =?iso-8859-1?Q?sWWUELkSr/GZgSO8GLHd0Ij4j0lkBGHkj4e8tS8Ljex/IGdRI+FKR13QX8?=
 =?iso-8859-1?Q?HBznfQSH6rRl811NzMIGKMrL/lXQVTfrAIyxQiJn1wlKeicS0yeEcSqPvy?=
 =?iso-8859-1?Q?2gCCzYxUpcFfaywuZfrtyq7r67MJ6zQ7Iev++oe1tF84o8vrL2TwwocyOt?=
 =?iso-8859-1?Q?Lt8KwCtsdw5vaJU/dXEBLUOm5HunehxFSi5vk9GCvOr48GJm8dofd0lJza?=
 =?iso-8859-1?Q?OmTdqz2ytXFYvYrSmxOntdDvU6e1AXVja9IhvSgOR0daK8jZqp+u8LV3fG?=
 =?iso-8859-1?Q?2lWGOpSWwA14yZ1rMRLVvdZGGzxBFcADsom2gT3fjd/VpwVL+Yyj5FcwxP?=
 =?iso-8859-1?Q?UDOtA+gpqXpHTwuqWcOQ96kE20bthNgJ9MSk0HMYPjArRufzfr4yTrqi1K?=
 =?iso-8859-1?Q?HJ10zC1FNv/ByjxlVC4cx1g9j+X7bzax3e4WJL47gO4JdDprZwv7lWYwA3?=
 =?iso-8859-1?Q?GCNCqwDiWps4sRuOMiZRdx/+C+61n6epG8soBFpk3NSueSuV5u+0wZ8xxN?=
 =?iso-8859-1?Q?sqbWU4FFRZv+fLkkurruoYyOxjrjniWDri3nTMFuJc5z/60OZaakJR7y1A?=
 =?iso-8859-1?Q?Php4RW78mgZFuTLDU5wR5USaArVnVL7h91XwzXYiVUiBmYKPPKOUQtjbCH?=
 =?iso-8859-1?Q?+4HgUE+uo82Bn1jz4aQy5hTt5odR910rm1rLENSQMUVHHZoEK9KTHDcsQE?=
 =?iso-8859-1?Q?+GNwc268oyDDBL+T9lhAPoiWg=3D?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 1b3eafa6-bf37-41ac-fb6f-08d9e6284cb6
X-MS-Exchange-CrossTenant-originalarrivaltime: 02 Feb 2022 08:45:00.8995
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: wICNpzSWfgL3v5YZGctUQ0j4c1YaIkBLpA+5hZyK8y/uvowCvzmLFvjrC+OSRPWzR0ECNpIiP0GJHh7ji4VZxdCyBGNftcOhS3b9vAxSZ0k=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MR1P264MB4276
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       arc=pass (i=1);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates
 2a01:111:f400:7e19::62b as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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

Instead of opencoding, use the new kasan_pXX_table() helpers.

Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
---
 mm/ptdump.c | 23 ++++++-----------------
 1 file changed, 6 insertions(+), 17 deletions(-)

diff --git a/mm/ptdump.c b/mm/ptdump.c
index da751448d0e4..bb6782de8203 100644
--- a/mm/ptdump.c
+++ b/mm/ptdump.c
@@ -4,7 +4,6 @@
 #include <linux/ptdump.h>
 #include <linux/kasan.h>
 
-#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 /*
  * This is an optimization for KASAN=y case. Since all kasan page tables
  * eventually point to the kasan_early_shadow_page we could call note_page()
@@ -15,15 +14,16 @@
 static inline int note_kasan_page_table(struct mm_walk *walk,
 					unsigned long addr)
 {
+#ifdef CONFIG_KASAN_SOFTWARE
 	struct ptdump_state *st = walk->private;
 
 	st->note_page(st, addr, 4, pte_val(kasan_early_shadow_pte[0]));
 
 	walk->action = ACTION_CONTINUE;
+#endif
 
 	return 0;
 }
-#endif
 
 static int ptdump_pgd_entry(pgd_t *pgd, unsigned long addr,
 			    unsigned long next, struct mm_walk *walk)
@@ -31,11 +31,8 @@ static int ptdump_pgd_entry(pgd_t *pgd, unsigned long addr,
 	struct ptdump_state *st = walk->private;
 	pgd_t val = READ_ONCE(*pgd);
 
-#if CONFIG_PGTABLE_LEVELS > 4 && \
-		(defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS))
-	if (pgd_page(val) == virt_to_page(lm_alias(kasan_early_shadow_p4d)))
+	if (kasan_p4d_table(val))
 		return note_kasan_page_table(walk, addr);
-#endif
 
 	if (st->effective_prot)
 		st->effective_prot(st, 0, pgd_val(val));
@@ -52,11 +49,8 @@ static int ptdump_p4d_entry(p4d_t *p4d, unsigned long addr,
 	struct ptdump_state *st = walk->private;
 	p4d_t val = READ_ONCE(*p4d);
 
-#if CONFIG_PGTABLE_LEVELS > 3 && \
-		(defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS))
-	if (p4d_page(val) == virt_to_page(lm_alias(kasan_early_shadow_pud)))
+	if (kasan_pud_table(val))
 		return note_kasan_page_table(walk, addr);
-#endif
 
 	if (st->effective_prot)
 		st->effective_prot(st, 1, p4d_val(val));
@@ -73,11 +67,8 @@ static int ptdump_pud_entry(pud_t *pud, unsigned long addr,
 	struct ptdump_state *st = walk->private;
 	pud_t val = READ_ONCE(*pud);
 
-#if CONFIG_PGTABLE_LEVELS > 2 && \
-		(defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS))
-	if (pud_page(val) == virt_to_page(lm_alias(kasan_early_shadow_pmd)))
+	if (kasan_pmd_table(val))
 		return note_kasan_page_table(walk, addr);
-#endif
 
 	if (st->effective_prot)
 		st->effective_prot(st, 2, pud_val(val));
@@ -94,10 +85,8 @@ static int ptdump_pmd_entry(pmd_t *pmd, unsigned long addr,
 	struct ptdump_state *st = walk->private;
 	pmd_t val = READ_ONCE(*pmd);
 
-#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
-	if (pmd_page(val) == virt_to_page(lm_alias(kasan_early_shadow_pte)))
+	if (kasan_pte_table(val))
 		return note_kasan_page_table(walk, addr);
-#endif
 
 	if (st->effective_prot)
 		st->effective_prot(st, 3, pmd_val(val));
-- 
2.33.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/976e4678182a5e47311d6200ad8c93bb20c85f64.1643791473.git.christophe.leroy%40csgroup.eu.
