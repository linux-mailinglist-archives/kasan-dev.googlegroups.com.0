Return-Path: <kasan-dev+bncBDLKPY4HVQKBBJMS2GXAMGQEIK55XUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id B8E9485B2FD
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 07:39:34 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-50e55470b49sf6745086e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Feb 2024 22:39:34 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708411174; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vc+DfUi2nh1xLRdlEP5xptJwDQgfdIxiGme59B5aNlH7GcYryd5N7iL5NdFeu6QWyy
         uqmZB6RGa+e33mbrjqBDCUrXLq12kTbPONli6KbdVzw0yexarUAWw/22gnCKCUk8f4d9
         9ACfwqlQ4tGdDo2ohNJTW7HLwSFlqQ1thu/WQncYDd4YqEoeBiW3SCI1c00X6NDNvpyu
         cF/k71yAlwXo4CrttLLCe+3f4Ra9AF8qgT/wGmIjujLD3dI3UvXk/suAd9iFH99Hszku
         2YLSnalYwI2rJllrpxurJlRiNxN/6C9++6LaHoQwQPYiLoUyuIMtTGIiNk33z+qbbSb/
         xfzQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=ZaS/8LcsCNXHoH4IoQg6FfbBDRxkLc9ufRMu2e202L8=;
        fh=lcvcBpec75Gyk0UK91eaMelY5a6rJ2Nj0XGZo2cxXVE=;
        b=0pEn46CD/BvXXdweMmnWJnzASRi2CU4hGM2+KtYFHFo4otwLV8nk4EkXUN4UwENM3e
         LYWSCIP6IsbeTu7JWvdx9HR5RQ6xlS+oind7hbcR9Ia9OUJ/HYwgZahnecwVUFVR7Nvp
         zySY1CNvbp1Qg+04n12TK9Y29ZN0BD65wh+vlOqWWH0PRNwHCUYeIDYl4dt/gGtc4jK+
         Pxtbw40KLywZiLgcafT3iONyhA03g3pXT3+vgluFPzQqvVsXNSq5GgQ9C9bdVYdL4U1F
         a/1Vig4lPl28GCQXFr/0pwyJRIiJpGwGbv6pQRXQ/+g5eyDJvGDYoA0Uhw6RRRELyRNI
         cdoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=MOjZEVxM;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261d::700 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708411174; x=1709015974; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZaS/8LcsCNXHoH4IoQg6FfbBDRxkLc9ufRMu2e202L8=;
        b=WgiLm3FxFglu9IJJ7pPGGEzYGpOulo0QG3hXOC1yrK8y+Zl7MNjBAgC6qNzSihIBJY
         nxPtnawavu987zoiSX1syQCk6pSBywBInCxCR18qZYPxqvUujHcwsmySnivkE32FE27T
         S9en7DRS53A92lmuqEhyrGeF5m9HrE5WFPjui9ywkkcZpknXxFUI4KfOdKRPeioe7Pdd
         bnGGY7Bq1SKxeEzPI7vKnl9dtBgeJy634sQYndEVBXFK+rpN4Ir7SuuS6NEOz/susMfT
         AdH0PRDxO1hpvi1oDBH32lUgjgDaDRXH9cM+l0PfgmUxLJ/cg+XNDXMx2O/Qll8vTwVj
         zmMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708411174; x=1709015974;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=ZaS/8LcsCNXHoH4IoQg6FfbBDRxkLc9ufRMu2e202L8=;
        b=KAIt4If0VQveTSqvxQ/gNUCOPC8TMOxpZiL0zZ6rRTvd739WSnZZs/MO3x1I1WCyUv
         o/fk/EPmkMfHdBSWSWyK6C5sLX+SIcZEMvAsc4DTkBrQxgMaMl14cKstZwexjuRf0JNR
         qVEvq0CyMpVoiJzi21W/6JK2UK/H+Yao3AHjILlQ+9K6uV4aSSD8svjKKn29stV4uabV
         f5r4sMYxeCYoMbm04qvuoS6DYiOU7/REBHHAwxYJjLjTDWZtWlD06PNoyJoS0OTJWzaa
         YwtrB5XpA5jyoV+JU6vxn/Tt+vTOETw02Jg0kK0fnNHL/F8hn+ZDmKWLaZb8l0TN06Xt
         nbEg==
X-Forwarded-Encrypted: i=3; AJvYcCXsvDNdQ3Ily5A8a8YzyYBoJxFWa9ow31XprPzZCfQHvnGcF3ucLprvvfySUNLND8WlHBFTmN/lqjawx+wr3pdFWw2pkpnqog==
X-Gm-Message-State: AOJu0YziljvGkRL4uTc349msMAVlzl6E9ZWrwZcd4E5fL714o9St9Icq
	FXy9QYqfBNdKtYQF7wD9QMjpDYi7yWKGqqZznAiDZrU4NohqQOEr
X-Google-Smtp-Source: AGHT+IEfgwt7tr9jNu819q1WljMGP8mnZ1XoGfwVtsQmT2uF0/Pc6U5ajFF/3WGfUnyYoJ/VNzRbtA==
X-Received: by 2002:a05:6512:1385:b0:512:b438:baba with SMTP id fc5-20020a056512138500b00512b438babamr2982295lfb.28.1708411173510;
        Mon, 19 Feb 2024 22:39:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b9e:b0:511:623f:a563 with SMTP id
 b30-20020a0565120b9e00b00511623fa563ls780532lfv.0.-pod-prod-06-eu; Mon, 19
 Feb 2024 22:39:31 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXeEp/UTtXeSxX23fUxGxCCEWsZ/uMSxmckP27nqyLd6vkk/a6sXIqxce7Lyb1+rsgo/oo0ZUgYf+GeNjZuMEn8f+KcCouA0NqePg==
X-Received: by 2002:a19:9157:0:b0:512:a4ce:abb1 with SMTP id y23-20020a199157000000b00512a4ceabb1mr4783788lfj.32.1708411171566;
        Mon, 19 Feb 2024 22:39:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708411171; cv=pass;
        d=google.com; s=arc-20160816;
        b=KrM0tbV3gsfql9m4yJKsAkbLsCIN/+MJ4mksfmZQ6RzX+1A6bcW1jGV8GnKYsM25h1
         JpPk8wsthgJHkLo8zDgZIt9oHkpatvjttAm7WrmE8FTp6UTIx/ShKjdyB9BNGUeNWlB3
         aylrWA32xE7d+/foiGhUDbmRnVsh+1XuuVsDBKaagqJqcfLEcbhLtCvqOoDMxPkWz3+K
         uqyldtmnicBClf6shD9W7jOL33pocOVcbTydnXHLbVngEZQm7CENkTSGDTd7kugyoqU+
         LNFoO1bZGUyXUttCDDHOhH6yrc5Awy7LJtfvh0bjkJBiPXx8ia8x//Qq37s1A+qgYint
         laNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=R2nM8YqQTUwDz5bAB2sJ7xFHqoayx/n0l0EAcd2yvg4=;
        fh=RrZ19OfX14okVFSSNQSI4Ydw+VahiAISsipj6KSVYuQ=;
        b=ZF3KTAhYdSWcl6+iBmHcXetw6/jYJurAraEY/T9uw3gUoM1IbDsRoQL4GGMQHd1vgH
         oek+UwVo89IamqXEbwfSQ5o/rCJtlrDLxemrBTe90Ksj3mwJJa+kvbyscFJjdoyslInD
         L0iM7ed9wnVsZzUh2j3fwjA3ZiAWXlQin2Zrx+W6IE1icVjXLlxxP40Ur/p6fdrYwR5I
         +eiToFmtayiSh29oYsdM+PKx73GW8vKgXGYeiK7w9Ktvz4jt7MAmWo3TaJ5p86Lv9zCL
         DprL/86MHnxv+Ixvzv4zWLOou44tGKnYyjR8RI4uR24Hc0eQH33b0Tl0pGCXuV+qS5mU
         ORnA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=MOjZEVxM;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261d::700 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from FRA01-PR2-obe.outbound.protection.outlook.com (mail-pr2fra01on20700.outbound.protection.outlook.com. [2a01:111:f403:261d::700])
        by gmr-mx.google.com with ESMTPS id y9-20020a05600c364900b00411fc619abfsi411168wmq.1.2024.02.19.22.39.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Feb 2024 22:39:31 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f403:261d::700 as permitted sender) client-ip=2a01:111:f403:261d::700;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=eXKdLTcaHydqNCJOYf+/DlgAVgA3fEMJR7QX8msWf+tRpyW1ld1TtbTlE6lH7kGX98Ogiyf7gb97uWmQPzpeUXVpzxzrP2PelKFsx+AKywNXYprlATnsTARQhKfprZrsERHK9vRlZj8zGsyvrDiZ0fVPwjq/YZ5k/4UCYiYxMexvBWNE/LIf/TKTzLZ7JGk2dfK/qJ9/POVs6xr7z0tNmOIoJlo0MXwLqobZf0aHv5l46sfaM4MfY/YXb4Cg8gKKzs0lWUWGOTXN8HywJx5pvfgewjF8hjlTaoKsYjRxTtQuG5Eaha5aeD3SsOQcQW5Zdq4x05iARKawUnLHqxUhDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=R2nM8YqQTUwDz5bAB2sJ7xFHqoayx/n0l0EAcd2yvg4=;
 b=fBqCBPtGcX+wXlQh/e0dJvfLy98rnTyCL4Mf5dGdTGnvtFHh7AWAUakFCZmyvYY1neO/cA91I9cvfhwUUYRuDAjQkPPeEUvZBrN+MROEhpQDlJuXSGRH/qRfx2onSLTEbS48nEgsRRv/lH31d5zCQxktu3c6Dr4TAg6LryqE7PW3LlaqGLMeggyuLpK3/d/QRKLglQjovXkACGpFAA6v2bgMOCS1WG7rgJ4ssymydAumAySIoLo6q5nEgmwcJNfyKgtZnegFQrhgauK21aGYIeh9fF2XaqdcTw+f1IHxreyRsFFSL1r4jTl5z7+WD7DXaVu9DFr4H+Zgz7eI7POvTw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by MR1P264MB1793.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:10::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7292.39; Tue, 20 Feb
 2024 06:39:29 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::64a9:9a73:652c:1589]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::64a9:9a73:652c:1589%7]) with mapi id 15.20.7292.036; Tue, 20 Feb 2024
 06:39:29 +0000
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
To: Nicholas Miehlbradt <nicholas@linux.ibm.com>, "glider@google.com"
	<glider@google.com>, "elver@google.com" <elver@google.com>,
	"dvyukov@google.com" <dvyukov@google.com>, "akpm@linux-foundation.org"
	<akpm@linux-foundation.org>, "mpe@ellerman.id.au" <mpe@ellerman.id.au>,
	"npiggin@gmail.com" <npiggin@gmail.com>
CC: "linux-mm@kvack.org" <linux-mm@kvack.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "iii@linux.ibm.com" <iii@linux.ibm.com>,
	"linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 00/13] kmsan: Enable on powerpc
Thread-Topic: [PATCH 00/13] kmsan: Enable on powerpc
Thread-Index: AQHaLlJJUsT14twO30yc2wWFVbaBWrETMnUA
Date: Tue, 20 Feb 2024 06:39:29 +0000
Message-ID: <7233932b-ef98-480b-9d47-702315fa9875@csgroup.eu>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
In-Reply-To: <20231214055539.9420-1-nicholas@linux.ibm.com>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla Thunderbird
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|MR1P264MB1793:EE_
x-ms-office365-filtering-correlation-id: 3db0ae37-f262-4404-5fe3-08dc31deb0a9
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: H2WGzcvg2MAS9W3dIfP6iJmWKnv3O717ACrjAwWgP/CA+az5gvUgq9Q1djnV6pcBKnx2wtZK4yqSWrLpD9VtRjHVWBIZMCSVBoT8KAPMP5Jl96XqYeALKqEPq9ByIvwi8NOhq975scZr5DXKSXqk8wDc1uziHsuz8wBLlq+3SOJd7YlFxaz5uCWE1eY2a1SkSNth/j4IHY5JeGSzyhpncx5hq6xC008RP3UP+nq0X4jV23i1MXZdH3mUu76/4pkgAdQ4fr99b5PcQ2fsP+Cd1nh47cSLDWY4kHzfC5ZXK24a9a4DWBON5E+PcjNN8CHDNn4iB6YLdzz8NWtCtbnZrFHFm32zRtzu0vpv42bRT4s05Hir2HDDzz5snYNUR5xodEoITwApQtRwXFR83+lm9mHrlE5MmER4k+L7pJumSe0PspU9VzSYJCQF6Adkn4XZx4o4KYq8y86tfJFZvN8tRGvPVpZCW+iGpdImyVAcWNpko25sawN7Vtij9zI5n4dHhOwMZ2LzxKPd/8NZJrxW8dAQSeb1GXgqKaJqbwJ1zSu5F3V5ApxExx4oaQIUJ4MEZvARmHZHiilFY+oM7aPCRHENH4r+1PGQy4b73ykvZuQ=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230031)(230273577357003)(38070700009);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?aGh0ellzYVJIcEhVeUpHT0VTeDJndUFwYmtKREhFWWVjUEpDUTdTWCtReUhG?=
 =?utf-8?B?ZjlrajF1aTMzVEVBS1BsRW5tYUNWUUQ3RjYvYVdHSWFIRFBpbDdhY3NiNEtY?=
 =?utf-8?B?TXhrTlBER1VrZGR3RXRkSnlJZ2RhanJzRmd3eFhySThObkxML1NXdHE3bHN1?=
 =?utf-8?B?bmthMUhPWHppOE9LUlZGU3M3Z2lNL3lLQWE5L3hOOHZnOUtlZkdzc0tDcWFC?=
 =?utf-8?B?OWtmS3ZRVS9RYmtBRmhPaUlkQjRlVzhsYnk4aGhtRDJTYXhSdis5T0RLLzF3?=
 =?utf-8?B?dHduNzlyRVV5a2MyVTZLRmNEWk1JSGRGTjJrYjlVMXZBRHpTVm45UmtNUXF4?=
 =?utf-8?B?V1lOeVhUdGVCbm9mTWZpZHlKQmFDenZBc1lXc2UzbDQrRjMyOCtXaTVNN1ls?=
 =?utf-8?B?WEhyNm1rZXl4a1NYL2E4a1ZOSEtnVXlkUExJejNmRGNGK3dTR0FUOUlmSDBO?=
 =?utf-8?B?QUVWVXdDT2pSKzhQMnZNVDZXWFRkVjVzdDNTbEpSbXdSYlNWU3hESHE2cFZC?=
 =?utf-8?B?NWpDeFo1Y1BFUmt5aWc2clV2L21DNHpkNGtwcG55NytGWUwvZk9QL2I5Zmc5?=
 =?utf-8?B?NUNSQ3d2RmFBZmRlekMyK2lnLy9sUThnMkVxTEVqTHV5T09zKzdIbTVoVFgw?=
 =?utf-8?B?MWpNTlpoUFNxNE1jL0ZvMkVJTnNsQmxLbDExVDRaNjNMbW45cDNMc1lRWnVx?=
 =?utf-8?B?cHl6K2pnN3RYMlhyVXdUck5sUXRXNHJHelhRZGlycitZaUtibGVlQ2Z1UXk1?=
 =?utf-8?B?YStNTHloQzAyZmZiZXpnZUwxTmMzZHdyNWdGbmlwbU8zelN0VHhnS0J4blRi?=
 =?utf-8?B?RnQrS1ZSZFAvVkh1R24vY1ZGMGtsN3hKMnU0SFgrVXhKV1RqLzJhNnRyR2Ns?=
 =?utf-8?B?c0txRWJpTEV6SmVERnF4VFRxR3h6SDFyUXA1ZXppMFpGKytHaEFCaHpVaDlH?=
 =?utf-8?B?V0F4ZDdCQXVxUGRhellJYXVMS0FkcDlRWlVkbUoyaVpiSkptL3p5b09MVmZX?=
 =?utf-8?B?TW1FdmVySHBRc0QzUHBpcS9vcURNMkV3V2d2WWtoUWNtdm5Bd2txZzlhQ05v?=
 =?utf-8?B?d3Npcnl4eElXd2g0T3RTSVVMenFxYUJNRkhLbFp4Y0RhSms0bFBDM2dLL2lr?=
 =?utf-8?B?czlxYVk3c1JRcmNBcktMZ0ZHWHIyR0J3eGdyMjBwWE9BcWo4akpVVWxnRmZk?=
 =?utf-8?B?Q2NZZWhWK1VWL2Mzclc5R25yMGllRStINGJMdDIxRTF1aktjT24yNjFRYkJW?=
 =?utf-8?B?NzVydXhBaWc4dURoNnREd2EzOFNta0xkTHVVb0FZTmtIV3RUMHZ4V1dRUFZu?=
 =?utf-8?B?Mkk4U0g3K0RyTnVUaTJvaWpWd3lyYms5SjhEVG5PNGtmQjJnalhRenBpMTJv?=
 =?utf-8?B?V0lPb2FJbUJ2Um8zSk4zNzhrUDJLcHJBMSttYWF5c0hVbE1ST2RBMUMxL0JR?=
 =?utf-8?B?c2J0MTdsOG9FUFNnSkk4REpVMlRSUGxXOEx2d3JQc0lTRm4yaGtqL1ZSRGN1?=
 =?utf-8?B?YTMwOWNRVlBwc3l2TmdWRDh3eTlBS1FBUGFpNjZESzB2MUlUUkxoSnJicXpH?=
 =?utf-8?B?clpLSXB3RU5yYncycElhaloxVTJMV2lGbDc4V1JrQ3dwbjZVVUlVTEV4SVNF?=
 =?utf-8?B?NzNhb1YwL2dnV3RzcjdEb2NhL1kxaFhLUFJGWTZNSjVkL0VDRHRVSng1SlY1?=
 =?utf-8?B?Syt6SEhyekYxc1E2dUVQN24zZGVZM3NaMmcxQ2U0MTNJd2xFdzFRWnMxMjdp?=
 =?utf-8?B?OWRNamRMdWVlRTd5NnpYUzNKOUpwOExlM2Nha3EvZXBnR2czNFhwZzh4cFZw?=
 =?utf-8?B?UUozWlN5WVUwMWFPUTI5WWk4OUZpUTAvVGJoZUtiQjBVbXhKZ21CbFg1VkRu?=
 =?utf-8?B?eW5pWlo0SkFqRGFOazJBUGtxKzZvZHgwOHh6MlRXTGxBT1lDWlZ3UEt4ZmE4?=
 =?utf-8?B?cTFVOVZ1aFBOY2tWOVlCR0hTUkNLbENvdUhwaEZLYjN5c0dxODlrYkVTTmZ3?=
 =?utf-8?B?NEVQKzlOejNOOHZHN3hocTVURmlpaXM1UFNPaXJFaS8xc0t4K09kOWxWcUZS?=
 =?utf-8?B?M2RGUXNxeTlxaTRCNk1tdTQyWW1WQlR1Wm15dzRobTB5UTVtbzQ2RTlzSVlF?=
 =?utf-8?Q?fGCsF/6KG9VNj1wU3rp967ohs?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <AA422DBD7C262C4F8EAEFE9E04243EF8@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 3db0ae37-f262-4404-5fe3-08dc31deb0a9
X-MS-Exchange-CrossTenant-originalarrivaltime: 20 Feb 2024 06:39:29.5899
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: Oe+DWXsFsnQf3jvCWjpo3PDrojRajT6JWCKzHEjd6LAZ/W2fGupOWG26fPYsX0ZnuiuafAa1Yj26iDlvlHYd/NC1os9Arf58Cg/1hmRa/jY=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MR1P264MB1793
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector2 header.b=MOjZEVxM;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 2a01:111:f403:261d::700 as permitted
 sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 14/12/2023 =C3=A0 06:55, Nicholas Miehlbradt a =C3=A9crit=C2=A0:
> This series provides the minimal support for Kernal Memory Sanitizer on
> powerpc pseries le guests. Kernal Memory Sanitizer is a tool which detect=
s
> uses of uninitialized memory. Currently KMSAN is clang only.
>=20
> The clang support for powerpc has not yet been merged, the pull request c=
an
> be found here [1].

As clang doesn't support it yet, it is probably prematurate to merge=20
that in the kernel.

I have open https://github.com/linuxppc/issues/issues/475 to follow through

In the meantime I flag this series as "change requested" for a revisit=20
it when time comes

Christophe

>=20
> In addition to this series, there are a number of changes required in
> generic kmsan code. These changes are already on mailing lists as part of
> the series implementing KMSAN for s390 [2]. This series is intended to be
> rebased on top of the s390 series.
>=20
> In addition, I found a bug in the rtc driver used on powerpc. I have sent
> a fix to this in a seperate series [3].
>=20
> With this series and the two series mentioned above, I can successfully
> boot pseries le defconfig without KMSAN warnings. I have not tested other
> powerpc platforms.
>=20
> [1] https://github.com/llvm/llvm-project/pull/73611
> [2] https://lore.kernel.org/linux-mm/20231121220155.1217090-1-iii@linux.i=
bm.com/
> [3] https://lore.kernel.org/linux-rtc/20231129073647.2624497-1-nicholas@l=
inux.ibm.com/
>=20
> Nicholas Miehlbradt (13):
>    kmsan: Export kmsan_handle_dma
>    hvc: Fix use of uninitialized array in udbg_hvc_putc
>    powerpc: Disable KMSAN santitization for prom_init, vdso and purgatory
>    powerpc: Disable CONFIG_DCACHE_WORD_ACCESS when KMSAN is enabled
>    powerpc: Unpoison buffers populated by hcalls
>    powerpc/pseries/nvram: Unpoison buffer populated by rtas_call
>    powerpc/kprobes: Unpoison instruction in kprobe struct
>    powerpc: Unpoison pt_regs
>    powerpc: Disable KMSAN checks on functions which walk the stack
>    powerpc: Define KMSAN metadata address ranges for vmalloc and ioremap
>    powerpc: Implement architecture specific KMSAN interface
>    powerpc/string: Add KMSAN support
>    powerpc: Enable KMSAN on powerpc
>=20
>   arch/powerpc/Kconfig                          |  3 +-
>   arch/powerpc/include/asm/book3s/64/pgtable.h  | 42 +++++++++++++++
>   arch/powerpc/include/asm/interrupt.h          |  2 +
>   arch/powerpc/include/asm/kmsan.h              | 51 +++++++++++++++++++
>   arch/powerpc/include/asm/string.h             | 18 ++++++-
>   arch/powerpc/kernel/Makefile                  |  2 +
>   arch/powerpc/kernel/irq_64.c                  |  2 +
>   arch/powerpc/kernel/kprobes.c                 |  2 +
>   arch/powerpc/kernel/module.c                  |  2 +-
>   arch/powerpc/kernel/process.c                 |  6 +--
>   arch/powerpc/kernel/stacktrace.c              | 10 ++--
>   arch/powerpc/kernel/vdso/Makefile             |  1 +
>   arch/powerpc/lib/Makefile                     |  2 +
>   arch/powerpc/lib/mem_64.S                     |  5 +-
>   arch/powerpc/lib/memcpy_64.S                  |  2 +
>   arch/powerpc/perf/callchain.c                 |  2 +-
>   arch/powerpc/platforms/pseries/hvconsole.c    |  2 +
>   arch/powerpc/platforms/pseries/nvram.c        |  4 ++
>   arch/powerpc/purgatory/Makefile               |  1 +
>   arch/powerpc/sysdev/xive/spapr.c              |  3 ++
>   drivers/tty/hvc/hvc_vio.c                     |  2 +-
>   mm/kmsan/hooks.c                              |  1 +
>   .../selftests/powerpc/copyloops/asm/kmsan.h   |  0
>   .../powerpc/copyloops/linux/export.h          |  1 +
>   24 files changed, 152 insertions(+), 14 deletions(-)
>   create mode 100644 arch/powerpc/include/asm/kmsan.h
>   create mode 100644 tools/testing/selftests/powerpc/copyloops/asm/kmsan.=
h
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/7233932b-ef98-480b-9d47-702315fa9875%40csgroup.eu.
