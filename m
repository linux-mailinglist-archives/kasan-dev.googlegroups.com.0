Return-Path: <kasan-dev+bncBDLKPY4HVQKBBL4Q5OVQMGQEAXD3ZGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 8546C812B76
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 10:17:36 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-35f77a6e63csf11324915ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 01:17:36 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1702545455; cv=pass;
        d=google.com; s=arc-20160816;
        b=bl2IhXJS1K4ROaUYyQe0Acrf1lcvvAVZ4t4YEiYQvvK4vilHsrDWk68L8KRRFWdnSo
         myhdGBdBRsQkRukDasaKn77vYxR/LeLpXPDWKIP55JiPp9zCd/6WaVUgdTeFMAO776Hn
         FLnLxlO5P7OoOjVzYWRPzdVd/e2/qOxwdFuJPACUaJvRZXLeTXo72wrecxeHdwOKJ2mj
         bSpi4aIbXR0W3R1WJakxnVc2ok/Xx6RP3scXo2vv22Xl1HjA8XLtWBqrTnAUqy0YFEsi
         WiiewXXN4hWlg/amVIFoOtJclBJrdCCp0D9Eq6/FOd+7ZDNDc/NtLBuPEjQNQ8mnKxOG
         qYwQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=QB+FtsYXm0sy5mrn6T2fViJaJHFX/e8IxF0hwgd9Wgw=;
        fh=RrZ19OfX14okVFSSNQSI4Ydw+VahiAISsipj6KSVYuQ=;
        b=q2cl6la9hKFjNgdKB/JcZA3JW4IUuTRN4TaERFvjtELCTs4H390IDg2xSsv13z+xbX
         iNIDcH4oUqTSRgJtMvDkxCj3W35iDyTFiPkaLT9ptut5x+qy8cBxQpRdkpWvUAWpuAJ7
         YdgcbRdaspA1s0vHIsaid3cuRM3HjXmmHEEY/fl8YsK5uQTRCFA0IqG6KOYMmwBg9nHq
         1/QcItwXhzmp/Lt37iDZ/NqRYoG4EGRATemHfcWP8ThYmLQij+YXaXfIOG417T4Gk/RL
         LO83FV/sj7hLIMvMyde7y8zear8LooYnkVnLUQDTHuCaAlhFD0BYTNoX5OWcRSSpz1SN
         Dg2g==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=eh6+iWfp;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e18::600 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702545455; x=1703150255; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QB+FtsYXm0sy5mrn6T2fViJaJHFX/e8IxF0hwgd9Wgw=;
        b=udikqKQW7tl+gjlgM6hGXokdSEqptN7485IxiUiGrZzEUkJu3GT9FuyG0ual/4nP38
         AOK3iYRJ3824O66HO/+R9PhhmdPN4iSiQXTZLZXZwoh4xhEpiBlCUWRpD2SRvJ4S23gv
         GFxAOBsBCV9tmgCYcVQ/Wnq980TrrvUf236wtCo8hJ56yS93wc/7sTYbKRmVDBV57V98
         Y9Qx3JeTkzizQuacCVHUDC7X8/IQ588NVGwjQduZWEspVta/eWKcJ+2/lUpvJezax/w0
         JJvn9O4THW2LOdW2Wmg4xB5gvK1JUxM9rsN8OU8K9wfa23Xf+gFhO0lyIK7GfIhX1av/
         +uUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702545455; x=1703150255;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=QB+FtsYXm0sy5mrn6T2fViJaJHFX/e8IxF0hwgd9Wgw=;
        b=GR5lxOLI7X24HGEn1amsWHwLtBtDhe7eEjwSCJaLBRfP7GBPGF8neBgkE4q8V5Gkcr
         +UZWr4CeNLcecd1PzK8Ej0sA5GDVRV9576kwzqVcSdVRaKMs0lF4rgsmsY+nU33M311+
         ddI80YUyqOJ9r4ZqbYddIrSZRBh7eoyX+KxbazDj5kCFRn9dDIlcabvF9SkkHl88adr6
         uL1mFksWlwZHW9wpwHEfULtRBLk6S8agLGiXO6iBTNqVZuHSoviHxAuUUkmkVoe/rJX0
         f6B2yPgqUn/ePUIa1eA5xK1C3mYlygf8vR+yGBrRKzE+8xSoj+Ydml8i8gLUVx1a2XO4
         DAlA==
X-Gm-Message-State: AOJu0YwEFB0YGJFFCgt9k5uyz/s5X55rPSMy1QNeeGSa7H+3+RL68Och
	cENvnaGhTyMHpc/XwvySj/I=
X-Google-Smtp-Source: AGHT+IFBWbvTgf1vzlodDXZe4z/0r9TZPMDe9EjTlqY9HnnlKqFGngpDMF96bCyoAJctxUh7umu+Ww==
X-Received: by 2002:a05:6e02:190b:b0:35d:6b73:e9d5 with SMTP id w11-20020a056e02190b00b0035d6b73e9d5mr16325749ilu.42.1702545455413;
        Thu, 14 Dec 2023 01:17:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:174a:b0:35e:7419:87c with SMTP id
 y10-20020a056e02174a00b0035e7419087cls3751934ill.0.-pod-prod-07-us; Thu, 14
 Dec 2023 01:17:34 -0800 (PST)
X-Received: by 2002:a05:6e02:2144:b0:35d:59a2:68f6 with SMTP id d4-20020a056e02214400b0035d59a268f6mr14918569ilv.35.1702545454678;
        Thu, 14 Dec 2023 01:17:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702545454; cv=pass;
        d=google.com; s=arc-20160816;
        b=Oh/136pLUNgW25n0OPEROPFiyzvAYZvNULQHpDb1JPYoSIJsqBx0IqL7+gpghAVlWr
         X00W36ziHoU7ULTcX51tAuedDePFZ21DqXk+ED7CMr/HhSQOme183GpTDA5355GfZfKG
         4h39McWYVz/Ck3Ha7mxAgaFFCPG4LT/Q7aZiilEInjd/dDduIYfiSuPEDw1kyweHzfb0
         Xm9OqUmQ9jlGiEKD+z7yoEZa/ipY7VFojniXqPOCuCFQQ7YwqwEDNeA5OyBdfhFsj/le
         Q9AzdPMxuNy4ZNWegfCWfozdmtx3qMqDpbqjZiLhzAj873WWK51kEQp0BdfSFlntTiZ5
         E2jQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=XIKDqZdgU3TnD42f8D3u4+T2RkWLA7v2bkjMWiGL5TQ=;
        fh=RrZ19OfX14okVFSSNQSI4Ydw+VahiAISsipj6KSVYuQ=;
        b=undiGVVRrKlg9kmfoxnYNPG2OIOMma8VQORZosF8r5+g5rHRlh6sn7u6rG6m6eYjxB
         eJNnbFflTzlTqgv0VcSUNzBkO4nJ/aPeZRzIFgbKFusgQfISdi6ZLSNPsLVDPtYEbEIq
         B/sHBcr7pUj/EnjclI9uorpjP3sRMHg2URHUD3icJGxcqRk2NOw5aepPmMJG7MzfHiHG
         3xPpH8/l3Sq1qAxp+0VLYt+F0tLu1xMBNyFcW33eOZrDqsnhoRix+S3EjETd8gQWvNDL
         Bx2JlYJVP9cGWlU2RhfrYf2pmaBDOBpbQCX4fesi9lqf7zO8gjwj8bIRQ8oaR3WgCAaO
         Jafg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=eh6+iWfp;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e18::600 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from FRA01-PR2-obe.outbound.protection.outlook.com (mail-pr2fra01on20600.outbound.protection.outlook.com. [2a01:111:f400:7e18::600])
        by gmr-mx.google.com with ESMTPS id x18-20020a92de12000000b0035e6c380435si1019181ilm.1.2023.12.14.01.17.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Dec 2023 01:17:34 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e18::600 as permitted sender) client-ip=2a01:111:f400:7e18::600;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=GZTj6/MUOQ99bkaB3/vsFArYzAjRY+fsWFg3gMMK3KoL2/vfpfeKUHVF6g1k1exsOAiYp0B+gquOC50EU+VrHBhdq3ziZMwm5yTcP8OyRXNFy5yavPyIo0K6JSmQAwKuSciiLLFaeklSEqkrUyFRL7rqaXdgif4W6hUwRTrSPuWr4uXdwr29m/H5T1GN6A5Zm89u0mDnG5PHG6FcSMhUNpKjJ+2ZRyP7T3ou2wiO96t+tRNs3gZ6PQNYrwEpyEv+/TIeUeDwWwDTHF7ZdcLzjdWq3j2HnX1P+pIiGVsCdx+mGzsULTTz5vxZK/qCTOz910N2N1sN+uZQ8SmwxJfSkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=XIKDqZdgU3TnD42f8D3u4+T2RkWLA7v2bkjMWiGL5TQ=;
 b=dDDTdGrBDO78aEdwI3M4Rvhj8wB1dKn5BfdFD6GFhNTwEEggzzkoYYj94GtvlR4j7Z44bkHDUzlZZXO8eaTQTlNZyKl1iP7J2OMcpTQzsFu47MkFn5R54b+A8F/6Sjzq0N3uheUmUHzEAAMt6vLBFieLKKundo4lc8Pr1l4Ac/1QgrZFJziJ50/X+3UjoV2diDmuKizTXm6VnBUJgcTlIkPmbZ1jME3wThmIVynTlYwRaEIqHS7UPgz/xco8U+bAfbBiLTlJm3aD9pjl6xVSvQP8f6xjaaf0jAzSpwoTBUqSsE8YyWkSmBZZWPw7THoWAxUyIFSLf+aPjbu/wZg5PA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by MR1P264MB1892.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:2::9) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.7091.28; Thu, 14 Dec 2023 09:17:30 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::f788:32b4:1c5e:f264]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::f788:32b4:1c5e:f264%7]) with mapi id 15.20.7091.028; Thu, 14 Dec 2023
 09:17:30 +0000
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
Subject: Re: [PATCH 10/13] powerpc: Define KMSAN metadata address ranges for
 vmalloc and ioremap
Thread-Topic: [PATCH 10/13] powerpc: Define KMSAN metadata address ranges for
 vmalloc and ioremap
Thread-Index: AQHaLlJRjUyjraQgMkSxQbOtue9pZ7CogBOA
Date: Thu, 14 Dec 2023 09:17:30 +0000
Message-ID: <d24c430a-bde5-4432-8550-57de33cb203c@csgroup.eu>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
 <20231214055539.9420-11-nicholas@linux.ibm.com>
In-Reply-To: <20231214055539.9420-11-nicholas@linux.ibm.com>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla Thunderbird
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|MR1P264MB1892:EE_
x-ms-office365-filtering-correlation-id: cad02949-1d7b-425c-6e1e-08dbfc857fd8
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: UA9+4vAZVV0X/rFOh1R6VKwXTT6oEBYb138+/w5QJzmQ/okNi5J4pXhYEL2D4inOGVYkroLN7IvRsYJ4191rmHzX4VYxu8fzAg75nxZGVoIdjDlg4UqhcVKpsneES3DC4d0Wx55XC3mkbIWi7SP4rI3M4pZe7ungVEIg/uxn5MmuPXCinQKWEEouxq8gH739tdDCl4WKAnFx/2loIVXQLE3UbYSDXewRxEONM9Zz+DUtVLraFq4yQHnSqH14DZS+brdjsf6i12gtgtAY5NesjThxFtd/2rWMyVSbIsKRi4jxp8MnZMO7P+Me74J/fFVYBKb4mM45B4GR7pjyhWck7P6AiKZpZXGaETSYTdodArhj57XJoIkdMidIwq/Dnx4U+8Zu/hQOH0rGET61qjGIVz8Bsi3L/f9ssauJAA4fHrvIpEIOAW1/GNysIa8OLPbRFb4wX2m+Lks4YCShPCGZEpMfhkM9gHQ1RkyrcAsjnrhx19nI9I3LkGKELhUfvSvKC9Cwv46xrfM+ZbZQmiyBauDTuuvjsk1MJuI+G4E9GP6ZTS6FvwPpLYxFwNMb/9NLcQpH2aIM0i6iEulJ3QnYFLIsBFkohhJF6spe03Qa94lEcyqwBtI8DiOkXclyGC2RyHw6UlvTbd4z/VfpdKLyArfKNKgQ6ljKrA1lnq12d1bOT2VB6Jexlqj38RdTZJEt
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230031)(376002)(396003)(39850400004)(366004)(346002)(136003)(230922051799003)(451199024)(64100799003)(1800799012)(186009)(8936002)(8676002)(44832011)(76116006)(54906003)(316002)(66446008)(64756008)(4326008)(110136005)(66556008)(66476007)(66946007)(91956017)(36756003)(122000001)(86362001)(38100700002)(31686004)(31696002)(38070700009)(83380400001)(478600001)(71200400001)(6486002)(6512007)(6506007)(41300700001)(5660300002)(2616005)(26005)(66574015)(2906002)(7416002)(43740500002)(45980500001);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?ZGFQOUUrRC9HVXEvVkNCUXZKbklMbVpJcndTVXQ5WnB3K0tMWEFQbHpvdXNr?=
 =?utf-8?B?OEhQQUtjemp6aDZiYXBxc25oVmNneXF4Q1MrZXc0cmpJNCtSWkZicDY2WWl6?=
 =?utf-8?B?ck8vRTdmRFRWSU16Nlp6NVloOWlqZXErQVd5V1kvQ2tNcWd4YzNGMW4vTWtG?=
 =?utf-8?B?MVBvTmFLNmZRWlI0UXc5VWw1TDhCdEtUd2lJWFo1NWN5RDQybHFPcUtiMU4z?=
 =?utf-8?B?cVErNmt4M05ZRVJEamZTQTNsMFZtNzZiU2pQeXNXZTJJOXN3TWlCN0wyYVJq?=
 =?utf-8?B?dmJSR3AvTEdtTDdVVk51amtkam5KazBwK1EweUVIeVpncldSSUdpeE9MeFBD?=
 =?utf-8?B?YlJrRDVFZWxnNjRHUzFqUXlNQkZuMFJRRTVyZ1Z6a2NDcnNUdkxsRDJiSDJV?=
 =?utf-8?B?eE1LRXREMmdFaHJ3elV0UHo2ZUlVYmgxMFhvdS8vU1BmMUVFYlJCTnRPRGRa?=
 =?utf-8?B?TnVqa2o1V3RjNzZORFlJYzBmZ3pRVlpzdE0xSmEzZ0JNbEM5Yzd2ZnBRREF3?=
 =?utf-8?B?dWRleFU5aGNWdVd3WGdRSi9xT1ZVVkQ4aXRkeFU5cGJseHJqMjBFVHVTVHV0?=
 =?utf-8?B?TXBlRkFkbm1RK3dsaW1wS2hrR1lPZXlna1RscEZFZFJta3F1akY4b1hHc2tm?=
 =?utf-8?B?OHBCVG5td3lnMWJTejRMNlVQVzRiUGYzbVVEV0Z5d1N1c1Jhcmx4blVYS0dq?=
 =?utf-8?B?dkRzUW90RU8rTEM1NEJwRGs1ckE3VHlhVTM4cHZqa1FSY0FPeTJJWnpHYWlK?=
 =?utf-8?B?a0plZ1BiYjlSMmlTNkdiNE4zWld5cWw5SmtseEIzSHJ4a0NQcGRzSnVGUUdY?=
 =?utf-8?B?eUFMUGprNkFLTjVnNERKZmZFNUlXU1Q3Rm0zZEFUV1EwVUdWb0h3UHBVeDBV?=
 =?utf-8?B?L2YzTndHRFZZSkpzRGxHVjc1YVo5V1VIVDdydEpPendHRVQrOCt4aDhYYmto?=
 =?utf-8?B?YmtTaW02WEVzbVJLTmdvZ2VtK2JvZjI3bFR1RlB2TVZVbVZsNTM0dmdqa1N4?=
 =?utf-8?B?dHpPSFloREV1bEducVFUN1h2b2REcjdBY1FHU2YwaXhzd3AzZU5tWlFjN0Zz?=
 =?utf-8?B?Nk9LWnM1YzU4WU5QaFhXSjd0U1U5RFRCQmpVNEprc3htTlEzTXpxSDVTelFo?=
 =?utf-8?B?eElKTXhqNmhTb1psWmtPSm0vTkNkSWRTcE52ME03VDc4dkFicThVUjJvT3JJ?=
 =?utf-8?B?a2NSTTQ4dEMrcE5GQzhjNm5zbFRkS1FEVEJkb3gweTFwVzNNSnA4RG13NDBl?=
 =?utf-8?B?UVMrdGJBdWxKY0g3Q1U2ZmI1KzRuUTRpam5UVG83ZDQyQVBUVkRTYUtiT0Jz?=
 =?utf-8?B?bFFidVpzVWVSN3N2U2FFYVVIYVZVeXVjWVVzc3V6d3dVajY5SExqZURqbUJW?=
 =?utf-8?B?Ni9WcHBQM3EzUHo1dWxLK1lGeVZmMjV1STB1NjliZ05kN2prTGpNZ2h5WUMz?=
 =?utf-8?B?S2pvNldIMkQxaGJFR2JadnQ4eVRnOTg4KzlKQ1BEK3B6T25VL21xRVlkMGxL?=
 =?utf-8?B?Q2xJOGNmczNDM0ErSWNsdjBCY2Zwa3kyRVpDYThqUkhJMThnajJmOEFzbFVG?=
 =?utf-8?B?aGttS2h3K0JiSGxva1N6SkRHV0I3WVNZSk4yNWVEbnhMdG92VHpyR2hvaTJa?=
 =?utf-8?B?RUpBeWR3aGRuaElzMlJEZ2tXMmRwbUlHRkw4UTV1ZGtad2o0YkpYMUJYRkx3?=
 =?utf-8?B?MldRaE1EWDBjYWJZNytxZjQycVRwbHlMU0VtbEV5L1ZKcFVGR1FmYjVjQUli?=
 =?utf-8?B?dXl5azJrbllNTVNPNDRWVDBWN1RzVCtxSFpJVHN5RURuckxjZ1dSQ3lxbmZ6?=
 =?utf-8?B?ZFFDTWZmMzZ0bEhFbDBkL3JucXNjbTV3M1ZTSXJmSFhkdjhHWVNmYjY3ci9R?=
 =?utf-8?B?MHVqMXZLVUNUdFdVV2VjY0NPaFZKdkM3NzNvbXd1VklOeVdJendTeHFwM2RQ?=
 =?utf-8?B?UEdQTXJERjdYc2dJSkhTZ0duOXVpTW9jOGxxV0ZSaXRQQWU1Slh3OURQT1ZF?=
 =?utf-8?B?azJuczZ2YTRlVmJRcEVKRk1CYlF5K2JzYXoxWlRUTXIrb3R4cVd2aDZPc1ZO?=
 =?utf-8?B?bkZxdG9YYkt0WFdUcndZVk5hd0pBNHBrcXg4bmt3a0FwVFBraERYamUrVGZR?=
 =?utf-8?B?aTRpYzRNaWtmTEhhaHc5NjFWcWJ4cktiTWZSd3hOOXh4Y3hjcHFWcU9aK0pk?=
 =?utf-8?B?UFE9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <BC26EA0A44A03B4CA90E9F8ABFD12A41@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: cad02949-1d7b-425c-6e1e-08dbfc857fd8
X-MS-Exchange-CrossTenant-originalarrivaltime: 14 Dec 2023 09:17:30.8172
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: 3xNoqweeUHKpPL8MEI56uGUkauN+qbVG6NBCu6qj2wzbie5o0aD7CdjbbBck1anijvFthcjhzbGZenPSPJa98hDYLtydezsdeK5KQABOuIQ=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MR1P264MB1892
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector2 header.b=eh6+iWfp;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 2a01:111:f400:7e18::600 as permitted
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
> Splits the vmalloc region into four. The first quarter is the new
> vmalloc region, the second is used to store shadow metadata and the
> third is used to store origin metadata. The fourth quarter is unused.
>=20
> Do the same for the ioremap region.
>=20
> Module data is stored in the vmalloc region so alias the modules
> metadata addresses to the respective vmalloc metadata addresses. Define
> MODULES_VADDR and MODULES_END to the start and end of the vmalloc
> region.
>=20
> Since MODULES_VADDR was previously only defined on ppc32 targets checks
> for if this macro is defined need to be updated to include
> defined(CONFIG_PPC32).

Why ?

In your case MODULES_VADDR is above PAGE_OFFSET so there should be no=20
difference.

Christophe

>=20
> Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
> ---
>   arch/powerpc/include/asm/book3s/64/pgtable.h | 42 ++++++++++++++++++++
>   arch/powerpc/kernel/module.c                 |  2 +-
>   2 files changed, 43 insertions(+), 1 deletion(-)
>=20
> diff --git a/arch/powerpc/include/asm/book3s/64/pgtable.h b/arch/powerpc/=
include/asm/book3s/64/pgtable.h
> index cb77eddca54b..b3a02b8d96e3 100644
> --- a/arch/powerpc/include/asm/book3s/64/pgtable.h
> +++ b/arch/powerpc/include/asm/book3s/64/pgtable.h
> @@ -249,7 +249,38 @@ enum pgtable_index {
>   extern unsigned long __vmalloc_start;
>   extern unsigned long __vmalloc_end;
>   #define VMALLOC_START	__vmalloc_start
> +
> +#ifndef CONFIG_KMSAN
>   #define VMALLOC_END	__vmalloc_end
> +#else
> +/*
> + * In KMSAN builds vmalloc area is four times smaller, and the remaining=
 3/4
> + * are used to keep the metadata for virtual pages. The memory formerly
> + * belonging to vmalloc area is now laid out as follows:
> + *
> + * 1st quarter: VMALLOC_START to VMALLOC_END - new vmalloc area
> + * 2nd quarter: KMSAN_VMALLOC_SHADOW_START to
> + *              KMSAN_VMALLOC_SHADOW_START+VMALLOC_LEN - vmalloc area sh=
adow
> + * 3rd quarter: KMSAN_VMALLOC_ORIGIN_START to
> + *              KMSAN_VMALLOC_ORIGIN_START+VMALLOC_LEN - vmalloc area or=
igins
> + * 4th quarter: unused
> + */
> +#define VMALLOC_LEN ((__vmalloc_end - __vmalloc_start) >> 2)
> +#define VMALLOC_END (VMALLOC_START + VMALLOC_LEN)
> +
> +#define KMSAN_VMALLOC_SHADOW_START VMALLOC_END
> +#define KMSAN_VMALLOC_ORIGIN_START (VMALLOC_END + VMALLOC_LEN)
> +
> +/*
> + * Module metadata is stored in the corresponding vmalloc metadata regio=
ns
> + */
> +#define KMSAN_MODULES_SHADOW_START	KMSAN_VMALLOC_SHADOW_START
> +#define KMSAN_MODULES_ORIGIN_START	KMSAN_VMALLOC_ORIGIN_START
> +#endif /* CONFIG_KMSAN */
> +
> +#define MODULES_VADDR VMALLOC_START
> +#define MODULES_END VMALLOC_END
> +#define MODULES_LEN		(MODULES_END - MODULES_VADDR)
>  =20
>   static inline unsigned int ioremap_max_order(void)
>   {
> @@ -264,7 +295,18 @@ extern unsigned long __kernel_io_start;
>   extern unsigned long __kernel_io_end;
>   #define KERN_VIRT_START __kernel_virt_start
>   #define KERN_IO_START  __kernel_io_start
> +#ifndef CONFIG_KMSAN
>   #define KERN_IO_END __kernel_io_end
> +#else
> +/*
> + * In KMSAN builds IO space is 4 times smaller, the remaining space is u=
sed to
> + * store metadata. See comment for vmalloc regions above.
> + */
> +#define KERN_IO_LEN             ((__kernel_io_end - __kernel_io_start) >=
> 2)
> +#define KERN_IO_END             (KERN_IO_START + KERN_IO_LEN)
> +#define KERN_IO_SHADOW_START    KERN_IO_END
> +#define KERN_IO_ORIGIN_START    (KERN_IO_SHADOW_START + KERN_IO_LEN)
> +#endif /* !CONFIG_KMSAN */
>  =20
>   extern struct page *vmemmap;
>   extern unsigned long pci_io_base;
> diff --git a/arch/powerpc/kernel/module.c b/arch/powerpc/kernel/module.c
> index f6d6ae0a1692..5043b959ad4d 100644
> --- a/arch/powerpc/kernel/module.c
> +++ b/arch/powerpc/kernel/module.c
> @@ -107,7 +107,7 @@ __module_alloc(unsigned long size, unsigned long star=
t, unsigned long end, bool
>  =20
>   void *module_alloc(unsigned long size)
>   {
> -#ifdef MODULES_VADDR
> +#if defined(MODULES_VADDR) && defined(CONFIG_PPC32)
>   	unsigned long limit =3D (unsigned long)_etext - SZ_32M;
>   	void *ptr =3D NULL;
>  =20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/d24c430a-bde5-4432-8550-57de33cb203c%40csgroup.eu.
