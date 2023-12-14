Return-Path: <kasan-dev+bncBDLKPY4HVQKBBS4R5OVQMGQEJ5MUNWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id E8B33812B80
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 10:20:12 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1d364251d75sf1959135ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 01:20:12 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1702545611; cv=pass;
        d=google.com; s=arc-20160816;
        b=o3T/xFPW2TJrUqU/uGR9qBL9Vl5DBqEgtbj+295a9oEwj/2j5t272ZSiMj2U4xzdXk
         IlT6h8x5VROqW4udA0U/NKkKzJfx1No0c5LP9lxg1LuEBoDbE4lUiiDX9QzGJjm/0KLy
         9OakB/SDzFuGAkw/wIB0VBRlt6BeByMAQytgv7Hl1+/47vfklaRB5Ntp6CKZ7zBxfomW
         MnirPHhzujaTVZjjKg/4NVM813uR6Z7e0FPsogOkcMtIXrRVlPe6TfaMPeo6M9vAQZyS
         hIm1Gs1jcP6wqkluvuzRd4DXFfcZY93JP0a31XL5+If5CVsUVUX8o2vaYO+iWoVbDOus
         qdgQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=iHdfERro1EkMZN3VLprHvms2lEAqQTN0Man5VlM7oNg=;
        fh=RrZ19OfX14okVFSSNQSI4Ydw+VahiAISsipj6KSVYuQ=;
        b=f0P9r0IsXonSBnIDtjcsxWi6qEm6icldwHdKBLnF4GPQoBmpAuzgBR76oH2zEAE9xJ
         tWWgrwe6HimN6u0/A9rdKtdhOJ1ltyxZHuqjmmoRq9blKBVNdf+L3xw7+VZkdsjIMzEO
         BmyQQWL9L5aYBu8tU0JcLyPmdNyubHVzS1j4/CPUfg46oi3ItjrydQmVtYyimHk7cykR
         RahXxL9JwLKn+WRK18Az55SXy1BM6Z69Gl+n2ELT6+8RtYPWr+NiQ881Nbtpb5a8U+2d
         bOu6Ys3HhTdIVB3R28JuctHWL7U2Z/wfYvwIfKJzkwwTqnkrq9x2e2U+Qc2SQ60xSFsE
         VaYA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=WnwLfpPO;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e18::626 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702545611; x=1703150411; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iHdfERro1EkMZN3VLprHvms2lEAqQTN0Man5VlM7oNg=;
        b=pa6r3pJHch3rMJByY8Jz4dI/4ZropHPn3h7Z438uG1BZWslTHeNAKpxgidLbjrVCch
         gjlJPmOAM/AzhaIoH4dOV/z+0U4I20t44gnoaku5plF4olaQ7q54yAMpX8/Y62d5S8Je
         qJsgNiE6Wvw1d8jsRO6/+Xy3ynKMCcpoy+igCAcBvAjHdIerfWk5gkYvelICsFYmTutj
         ANOKM4CjR5/W5bhT3uJ6csbCsod+ZQsW61tgWrpKkSonStDnVaUlmMxJNwCUZb1yzhYN
         lBxBp8+TfmKkFNi04EgzE9H43HC01R80C5+RdQ+24OnI3+XTLXC1Oj4fyMGH7Uizr43s
         cRcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702545611; x=1703150411;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=iHdfERro1EkMZN3VLprHvms2lEAqQTN0Man5VlM7oNg=;
        b=hX7sqiq9x8biOcPPK93QMWouCsWQTLzwWtobTYLGshqD3QkGRbk8xeorYclYy8pR3g
         AXmuwHS7syk4S+2L7kZU6FWB2EY/QIwB0UPVjXsdAT65ZlyNW9HdBUZ+0nXDM4NTXo6W
         fhzbssr60WvedAyFCl817d3VcWWEXKUKO0Jkm8bVx5q7vpTDrxUYz2Qt7cnS+qOqusol
         sV+s/rrn5bmvkgCoL31XNnZcrm5Dc9o/D66qqfn5BIKGDqyCTs2Pa6wMR+sVXUZo/015
         1WZG1xa90DJge5mv46SaDTYsl531EgQJb9PjQZNaoKK7KIxt6U5MW3RjxGpVsEK+AwLh
         Sn8g==
X-Gm-Message-State: AOJu0Yzvgf+mz9H9W+JSVY0J4t2Myr9q0f98lIcfBHF/0qbirrBS0/J2
	8PvFS3PY7/NhoCgZOO9dJtA=
X-Google-Smtp-Source: AGHT+IHRDg7WDsod5kBeMzJJ7yyEz0n8Wbx0SMKyCp8ld11J8HWZZ6TaIHosQ6a9f2aFf/hd36JQ+A==
X-Received: by 2002:a17:902:e80e:b0:1d3:39f7:ed7 with SMTP id u14-20020a170902e80e00b001d339f70ed7mr755585plg.3.1702545611197;
        Thu, 14 Dec 2023 01:20:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2444:b0:1d0:54ae:202e with SMTP id
 l4-20020a170903244400b001d054ae202els1764652pls.1.-pod-prod-06-us; Thu, 14
 Dec 2023 01:20:10 -0800 (PST)
X-Received: by 2002:a17:902:d4ca:b0:1d3:45c8:bc12 with SMTP id o10-20020a170902d4ca00b001d345c8bc12mr3828965plg.38.1702545610027;
        Thu, 14 Dec 2023 01:20:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702545610; cv=pass;
        d=google.com; s=arc-20160816;
        b=g3oC3IJ1pbQ0kbhS/tnMElDd7eaJOenLtBCgbARuWsMpxQc8Gu2eNfL7ds1yX+ceH/
         bPkOAVaqyti6VZG4prcUZUKVPl1rSYO4gWeBGTsoqAZcHxf4Rs1ep/4iegPB9zGoK8NB
         /tYis4OHdO3iI4RKFw7UPRwXR0cX15c/IMSUdpLFNI0Mxg+9jgD/4yBcbaUpSiC32Jii
         C7bYKXEWSlN8Lc8z4wuXHwxTNw3G0DmcS4RHWf6DdBrUcQ18pQc3T0vx18wSF4AwvSSt
         dzim3toT+KTxPTlopDH+9/Waj8cOh63lNq840mFUtGMRrRDCiaPGdqdKPGPme3xXFlPK
         TzxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=Fkqx4aPyZqrVhO9pnGAMQGFu3sqVyRKxctUP8Rrl7fQ=;
        fh=RrZ19OfX14okVFSSNQSI4Ydw+VahiAISsipj6KSVYuQ=;
        b=Wu3Lnzke9RdHVJZo2zlgHshPQ6h9qD3DhOCwCUuYIsRQm3Lp0cxjgwrRfukOJOhgdd
         ZP4/xibmmcthZgAJQSC5lvbCkXD7YS08WR5YZtw1HyOTH+ZlfCW/B2JmYyQIcHEzIvkX
         uuqKxO5MqhD62KSUJvsr8QWTeVZGQRQEQhjlGPM/wZh80yV6DcVMLwAqhYwig6DEtCDW
         PyG3jNnUw2E9TvGeDUT4c0x1sbJt2TWv3TibRROsqcyL6A+N9ANPXvnkp1oLSj7ulRyT
         UT0JON1IDeYRIBpjrX5XXWBixzKRmLQ0880AYgM89FWdkv7kfLR7aCsMPlwfgOz1SI9E
         auzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=WnwLfpPO;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e18::626 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from FRA01-PR2-obe.outbound.protection.outlook.com (mail-pr2fra01on20626.outbound.protection.outlook.com. [2a01:111:f400:7e18::626])
        by gmr-mx.google.com with ESMTPS id f8-20020a170902ce8800b001d3555be8b4si170064plg.4.2023.12.14.01.20.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Dec 2023 01:20:10 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e18::626 as permitted sender) client-ip=2a01:111:f400:7e18::626;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Afycax50xjGPNepJ+6M6erP16Pj93cM6eFE+S/c691+MbkcCfmOJ2FLL1VgQ9QX9AnnH5eeoBTQM1DNbRyse0wDdgowzXW2V7474Y2K/SGpCyX085UtrkeyGrGJvJ3f3PdgObXJbtEHufKXNunQd2Fa12GDxwHOgRuL43OkTfqh3rOCs5/+e8zvER3ADp4cym0snOjzkygrSkOYde5pxMuiUJ8BvsM6h7P02dM416yJ1hDWpofthwC8a/AenUuLM+dNVvwkDpiAHMlbV2fRO4p+sNI/WbjgJQX9uTUWQ0cM2CK74DilfbsQkQN3Rpng0dnFLbi8PYFGZxvw/XPIygg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Fkqx4aPyZqrVhO9pnGAMQGFu3sqVyRKxctUP8Rrl7fQ=;
 b=HokpYlC/jBy/5vSZr1EXbWCxTdZqzFAkMEyy47I5t8wc8IexsP62mhfBBnXbHUUx8/oAgy8JMv6nQOsaZC+8O2CuSzqFYOGRJ6O5AE7BlchEPnk4ZPxW5unWt4LqrjTbta6qF6L+L0JjSWdlJvu0EQPqnlLFVR4ChUfdFw3Vj2Ay272uO5463Pop8Pf+hViuVVTPB9J7TmpHXF4t8j3D4DMnkblsFsGW3YznisCriHuWKMue1yZ9ntYwWE476uQ7WOF5Z6DRoGOgYWmQ9+RKed0neIoNDpc+BhibPqbL0ylXJhuXYrCZX3OvpwxTOTxZhGAIbK2pXXMYFNelF04tew==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by PR1P264MB3344.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:1b::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7091.28; Thu, 14 Dec
 2023 09:20:06 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::f788:32b4:1c5e:f264]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::f788:32b4:1c5e:f264%7]) with mapi id 15.20.7091.028; Thu, 14 Dec 2023
 09:20:06 +0000
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
Subject: Re: [PATCH 11/13] powerpc: Implement architecture specific KMSAN
 interface
Thread-Topic: [PATCH 11/13] powerpc: Implement architecture specific KMSAN
 interface
Thread-Index: AQHaLlJRapjZClFrTEO0LVVzss3B4LCogMwA
Date: Thu, 14 Dec 2023 09:20:06 +0000
Message-ID: <f75e5273-6c5f-4b47-ae2c-3cd21a0b5289@csgroup.eu>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
 <20231214055539.9420-12-nicholas@linux.ibm.com>
In-Reply-To: <20231214055539.9420-12-nicholas@linux.ibm.com>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla Thunderbird
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|PR1P264MB3344:EE_
x-ms-office365-filtering-correlation-id: 15e6f427-e304-451b-dec2-08dbfc85dc5d
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: RLcd+lcQLsOiDW0R2Of+mKInZiIVMWixg1WKw75tHjdHXx7hDFh+mBVnFksGmibLOLn11Pi0lRKLLn2xF95vURQfZJHOx5hNg5ICfHBh/8CC3gYRjpNiXiQbMIAW0kEZIgXETPN6S2KWN+iZiedO4840uKYMFIy6Ne6ULP5aTij44Om4vZrdYSL+azhjRh0OkX4PYMMykAK2binzk45yntdGkvAbGU3zlye6tuHzySQ0+i5e5OyXiWqNzf1SgMPnM5TnUjGmEoXCYukqgvdHUqXzCRlvu9Mm9uoAU8Asr9RLyfqb/OtH08u1K4mn+dzN7ZU2uMHwwVkl8Y02g0jjDWjcPPb1Lly9PVcHDTD+yQ9TKQZ2JQ6wwZtvVULHotj6q2lPlm3KNHHUDGJFTKz4UARKgpXfnBBZQFWvwtewsbsvnkzFbfn7A0j8GXMeGPTDVudydTVqtctjGd/2tlWNRbVFfJPCpRFTiaPvQBy+KgzXfH1jqTlLB7WeQp0i0VEAU2V2kMh8RExmJT8ERBrSW8VZnlOh5+AP/joF5v5DV/wRrpD48aYZ6faosFvm9BhcW15Dlfg+ndEhwqcCaD7XjCTLqNEOHWqqAMatnEaQdLGNeMCfwZ2nB2GFB5qp+P34CKn6NsM2XcU4y7M4WoirirBMCHGDg73iXQF3x6jNyWGGwl6qy96+l2Wbvngv0Jad
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230031)(39850400004)(376002)(136003)(396003)(366004)(346002)(230922051799003)(451199024)(64100799003)(1800799012)(186009)(8676002)(44832011)(8936002)(316002)(54906003)(66446008)(64756008)(4326008)(66556008)(66476007)(66946007)(76116006)(110136005)(91956017)(36756003)(122000001)(31696002)(86362001)(38100700002)(31686004)(38070700009)(478600001)(71200400001)(83380400001)(6486002)(6512007)(6506007)(41300700001)(5660300002)(2616005)(26005)(66574015)(2906002)(7416002)(43740500002)(45980500001);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?Q2RwOWJES21QRVNWZG9ER0JuSXpya3cyUmxlVEZRZldSUWtYYTlJZEtuUm5J?=
 =?utf-8?B?emRmWkpRcnF3dkdzVUkvMWtXZ3ljaWVmdG5FTk9NWERJRGRQc0lYUVBZUFNP?=
 =?utf-8?B?bEM3YXhidDVHNFNVcGFoREJEb1JSdUFYcXg1TFY4OFVRbjF2cGVCNEN5MWRw?=
 =?utf-8?B?R3ZFRldNcldqSGxnSVgrbFkwR2ZDc1hEVHd4SnhITXFaS2o3VDV3cDdBdTRQ?=
 =?utf-8?B?ZTBaSVc3VVVpMy9OcUtpdy8xNURrYVJ6eitTRjBPWVVUNGhaajE2bnBJWm5Z?=
 =?utf-8?B?U0RSVTVPMjJmUmdBdEpBOUxjdGU0bGdpbDBCUm1SQVFJRERVdGVuQTZLU3VX?=
 =?utf-8?B?RUVVeUx4aG16WXA4SUdxYjQvR2dKNFVOL0JCY2tjWUo2WUQ3eVpIUGxuR05J?=
 =?utf-8?B?TmE4VC94cEs3Q2xhdlM3RkhYZXlQZUNSZCtYdUZma0ZTMFcrai8zOEhkTW1D?=
 =?utf-8?B?N24vNUhRcVN0MjdBcXRhRVRPWTd2M3Q2Q1NQQjc2YUVPaHpzbElBQU5iang4?=
 =?utf-8?B?WjVxa3oraXZ6YUJFNUNtRkhVMVNjR29KVDhuNnJZQ0hrUktOUExMaHZxSmZZ?=
 =?utf-8?B?aTVuUVF6ZGk0bjJYS0JOUzdiZDVpMUtDVmJpbWRsZkwrOGhhdC9maHZuTXRS?=
 =?utf-8?B?ZnZmUEJ2ZmRLQmNrRmhkalV1clFVeUNHMkM1TXRoeHlaSFJ1bEJoQ0czVWJF?=
 =?utf-8?B?cTlrWEtPd1E2QVpmdHV0aWhVMTN2TWJaZWdpNmJONDRSQVdLSFM5bTRiRW9w?=
 =?utf-8?B?WW9wdkttRlhZTHhmbHZKVXZvbjk5ZlhFdHVmZ2Q5cVI0c1pPM1NDc3BjeVM3?=
 =?utf-8?B?TjhZN2doVXpIVE80QW02M0RUNmk5Y3U0S1hMVTdJREgwenYvb1RaNDI4Q1hB?=
 =?utf-8?B?dmhzcUtjYXNkRXJGNlRmN1Vpa0NOd1hveW1FN3FsWmVXQUdGS1NnMXV6MnlE?=
 =?utf-8?B?NmJXM0xVbU5IdHlSeHBTTXhVTmtBNG5lL01xV0xSaE4yMTVvUFlCZFVJTzlk?=
 =?utf-8?B?cGIyYXlhN0tWaVRKaFg3VXNmMDE2allFQ1hDRkZUKzJNcXpMdlBXelQraHdI?=
 =?utf-8?B?SUFVaEZTMW5UQUJXK2wrdksrWVZLendaR2swdlRYNGVNMUl3WjVGS0J1dTZx?=
 =?utf-8?B?RWgvWXpIaGVpV29NblMzLzh4MmxCRTR4cCswU1pKM015RFpiUTMyc2xNbUZW?=
 =?utf-8?B?aUIyTGJ1eEl6U1ZCVy9CUFd1RE9GTTB4YzE3UU1TS3UzTXVxcGhFa01DRk9R?=
 =?utf-8?B?UURlL2NKM1RXYmxPNTlONVNicDlvZ0E3S2hwWXl4Zm4wcVJLeHlLUlJxWGhG?=
 =?utf-8?B?OU5yUWkzcWl4T2FjejIzQ0E2MVRqL2ZVdC9ET0I1S2cvNUlkVUJjRGdUTjB5?=
 =?utf-8?B?TTJqVVRmYkhibEJSZEc1a1EwUkxFV3J0MHZpdlhWMmVncXpDNjN2N3FrbjRk?=
 =?utf-8?B?SFA1UDJQQUZJQkxNQ0JWUEUrT0lNTDJPaWlkWElybE8zNzV6d0dBS3JhV2Vr?=
 =?utf-8?B?SldtbllHYlpBSXkrZS9KeEpxUXNQVDNzaXRXb1pYb2F3TFlrbDJ2blBVUitq?=
 =?utf-8?B?bjNrMEtsZmFhcHNCT2poYXJOOTlNOVFyUVhGTlY1TXlaQUVkaTRDRExNTTNi?=
 =?utf-8?B?MUlHQXJpQXFFYVJoa05kVnFQY3JUZXlPc3B2ZUczUmxtdHJQU1BZcEFOdFZx?=
 =?utf-8?B?NG9rOGtLQmZWK01wYSthVUFtZGNlMXJGY2hPL2VBS3BVVkVrOHBZd2sxZG01?=
 =?utf-8?B?MEh4RUd5cm5WQkNUcnc4WjRNbGU2MW5IS2xnUTFYVjVWT1FISjFVbnczMy9G?=
 =?utf-8?B?WWtQaTV6KzJqclN2ZGo0TXZVQjJYUlJINWJhN0xWVUpETDdqODMzVkxOODdW?=
 =?utf-8?B?bUwxYnEvWTF6djBrUzBhOGNoeU1DcHJiZGFqZDd1akxNS2ZCeURHbFJuUXZK?=
 =?utf-8?B?UW43VUZmdDBvc3NQS1lXb3pyK3NseUtWaURUQWpjSmF2UTdwZHFyTm8zdXI1?=
 =?utf-8?B?dHhUVWRJOVFIa1ZBVmZvL3hUOTkyM0hKdFhCUlVzcWM1VnUvTEhSMDB2K0kw?=
 =?utf-8?B?bjdIczFXQmYxSmhJbGpWcDYwMFdqNVEvSGVoS2IrMjlLWmJPYWNJTVBZcUJI?=
 =?utf-8?Q?Y10rsH/N4ROU9eeNaps6+diY1?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <ED20B952632B2E4987B5228C12A31EAB@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 15e6f427-e304-451b-dec2-08dbfc85dc5d
X-MS-Exchange-CrossTenant-originalarrivaltime: 14 Dec 2023 09:20:06.0620
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: XR0YNE1DvcPoq6I2MRdrBNIwlF2/aoghjxcplejDYD+mUSqARu9WGSBDtweNGApFad+ij9adw+F3cvLy1ooBuNilsi5h61kZ9OSkyhL3Q9U=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PR1P264MB3344
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector2 header.b=WnwLfpPO;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 2a01:111:f400:7e18::626 as permitted
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
> arch_kmsan_get_meta_or_null finds the metadata addresses for addresses
> in the ioremap region which is mapped separately on powerpc.
>=20
> kmsan_vir_addr_valid is the same as virt_addr_valid except excludes the
> check that addr is less than high_memory since this function can be
> called on addresses higher than this.
>=20
> Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
> ---
>   arch/powerpc/include/asm/kmsan.h | 44 ++++++++++++++++++++++++++++++++
>   1 file changed, 44 insertions(+)
>   create mode 100644 arch/powerpc/include/asm/kmsan.h
>=20
> diff --git a/arch/powerpc/include/asm/kmsan.h b/arch/powerpc/include/asm/=
kmsan.h
> new file mode 100644
> index 000000000000..bc84f6ff2ee9
> --- /dev/null
> +++ b/arch/powerpc/include/asm/kmsan.h
> @@ -0,0 +1,44 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * powerpc KMSAN support.
> + *
> + */
> +
> +#ifndef _ASM_POWERPC_KMSAN_H
> +#define _ASM_POWERPC_KMSAN_H
> +
> +#ifndef __ASSEMBLY__
> +#ifndef MODULE
> +
> +#include <linux/mmzone.h>
> +#include <asm/page.h>
> +#include <asm/book3s/64/pgtable.h>
> +
> +/*
> + * Functions below are declared in the header to make sure they are inli=
ned.
> + * They all are called from kmsan_get_metadata() for every memory access=
 in
> + * the kernel, so speed is important here.
> + */
> +
> +/*
> + * No powerpc specific metadata locations
> + */
> +static inline void *arch_kmsan_get_meta_or_null(void *addr, bool is_orig=
in)
> +{
> +	unsigned long addr64 =3D (unsigned long)addr, off;

Missing blank line.

> +	if (KERN_IO_START <=3D addr64 && addr64 < KERN_IO_END) {

off is only used in that block so it should be declared here, can be=20
done as a single line (followed by a blank line too):

	unsigned long off =3D addr64 - KERN_IO_START;

> +		off =3D addr64 - KERN_IO_START;
> +		return (void *)off + (is_origin ? KERN_IO_ORIGIN_START : KERN_IO_SHADO=
W_START);
> +	} else {
> +		return 0;
> +	}
> +}
> +
> +static inline bool kmsan_virt_addr_valid(void *addr)
> +{
> +	return (unsigned long)addr >=3D PAGE_OFFSET && pfn_valid(virt_to_pfn(ad=
dr));
> +}
> +
> +#endif /* !MODULE */
> +#endif /* !__ASSEMBLY__ */
> +#endif /* _ASM_POWERPC_KMSAN_H */

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f75e5273-6c5f-4b47-ae2c-3cd21a0b5289%40csgroup.eu.
