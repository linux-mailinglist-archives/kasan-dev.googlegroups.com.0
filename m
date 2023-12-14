Return-Path: <kasan-dev+bncBDLKPY4HVQKBBAUV5OVQMGQE4TLKANA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DD04812B98
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 10:27:32 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-6c337ce11cesf9725388b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 01:27:32 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1702546051; cv=pass;
        d=google.com; s=arc-20160816;
        b=S/xwi1ymynoiXCAu2T1dOVukNjuw47GCeQJSwUQNorHjt1lHWXMj9gvZzx2jXQ4Cz0
         BHshfq9tT1dUB3bD8a022Ct5dtc7oXrVv/LMAicBll3YjXWk7JOKWyUQ8+Uc5oWzv+NE
         HMeIwV+1V74LdzqzB7g54mOR6Reo2EdzdwNy9GH0uCpeiMh5bySId2mHJQ2Aci6/1QJW
         nEtDok9nT2C4j/nv1vkf/v/l4cKfot9MfwyqzSiCGbMn4SEJaXHR4WHWJVbBKFWoZNOF
         mppoT109LYegZ04B4bl9n6wlVK1QFoVt4WIKNeoGHD4wIbE26LmDredxRhSHVWgry4h8
         xKGg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=6b+fBwPqAMIqfOQF43fMsXBEltp57dxk04wXrKxG4Wg=;
        fh=RrZ19OfX14okVFSSNQSI4Ydw+VahiAISsipj6KSVYuQ=;
        b=oBwF3dZPQFBXrMLlNbMCs89h18vpfs1R03ohusER+IHDEiVIZb/+6dYqAbvsevARfR
         l/pKm+8STHJNl0f35r2JQTLmuH9XmbR8okUFNi6pGPvLpP4j5FafnotVZfV6RAqY+zlz
         ic/liTHqCxoDJcv+geSVPT/FpmquRdAJuiRXXFELwjsh6XXx/ni803OVhoJONEXYxcBD
         fy9D0N6mI6ZqQd1XZB3JMX3gwodTpQXhLxPaMzKSB7Wy34pzWlLDk/u3pXjY8rs8cy7v
         mRUOzQ1xL3NZL1LsA5c7PK+ZZzQsnH9y6m8HeR5QCmAx0PXE8caqGQHHUZ6fiMqVos8b
         D/ZQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=MkLdPBCa;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::61d as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702546051; x=1703150851; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6b+fBwPqAMIqfOQF43fMsXBEltp57dxk04wXrKxG4Wg=;
        b=iRGgfTkQbVt1JtUQ7PPX1bSp3G857g1G3ZzndHvhuewuyNWKJKJGICGoOHmMJKEYhI
         uJj6/iJkuh+27lqCk1Fa3/ALg6t8bMR79uZaaXLV95gdnxZwvUgx/IFN8RPUoKA/SjK8
         UNdDsU8QT+dDoBW83QqqKSiula0+V4kKuLeFoKYkcQxMb9iDRBiNGFECnrNYZZp/25u+
         4ONdTS32jSpCrdDHDslTe6W6GPzEN0nIcb4fzTWEd/yr/d7cS/mRWlLMz469eYEJefyS
         DIVzYENYDfV38iRP0dhwJF07XqpuDMpA9Bds+zTW4WcUD+7XfLQQiJgr2jN2fnUPS/zW
         +11A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702546051; x=1703150851;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=6b+fBwPqAMIqfOQF43fMsXBEltp57dxk04wXrKxG4Wg=;
        b=PNmnelmzcwtv6ffLGpzNM6IgXeKBwBUmIHKEu8A+yx5/1qOt+zM+DLhRw1sunpeMpt
         5j5PGboMAnIBL1MSkwc35uUYe19ZMWTamJTw/mICZxdrRc217LdOGQezzoWoEvCgEzK5
         gQYAXFy3btL+BWwdWQfg5OSkPJQekZj58rfEnxSi8ZfbQdw85Ocw/H+yTNTEBaIYWBcB
         KfArYsw+ylGkTaekluxcZjn3YtIM8nuzdo4qdFWEHfFGG4j1ef/CgF6kS5Qn9u9toSK2
         p5M3zK94ll2lJ9WCYRqO5eLKTZuhshCyCJGH93BKrjah3/dqyYY8f/e2uhL2HKz031O3
         x5xw==
X-Gm-Message-State: AOJu0Yz6bcVwizjDNjJYHpUIQTA818BgCEGglyoARhERKbaw7gQ1cO1i
	WOE2P4t96c3GABvmFOPdEUg=
X-Google-Smtp-Source: AGHT+IGXEX93NfRD5w7ze8VZYA3RTcLMYcTlfu0ASdYcb8jsGCkJ9C6K4uLYhIj/5QpMSR0e2Uwr3g==
X-Received: by 2002:a05:6a20:13cc:b0:18f:fcc5:4c64 with SMTP id ho12-20020a056a2013cc00b0018ffcc54c64mr10175163pzc.67.1702546050783;
        Thu, 14 Dec 2023 01:27:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:6d27:b0:28b:308:2733 with SMTP id
 z36-20020a17090a6d2700b0028b03082733ls860531pjj.0.-pod-prod-06-us; Thu, 14
 Dec 2023 01:27:30 -0800 (PST)
X-Received: by 2002:a17:902:7e82:b0:1d0:9416:efb7 with SMTP id z2-20020a1709027e8200b001d09416efb7mr9065002pla.108.1702546049680;
        Thu, 14 Dec 2023 01:27:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702546049; cv=pass;
        d=google.com; s=arc-20160816;
        b=Olc1ZU/fzy3AK/wZhrYKK5Vf+kXoE8ZqBvNZRZEZXGl7CJSt8qH/8ReIvQor3Revqe
         9G1Jm5sXF5tE8rZCLKZaESvb/1Fn74yHxz6m85uvZPPU++nc/oIXUCGcHEiSdWYdtwFw
         KERN1vGBSfywhhorGTDn+O1Devh56XVYssYinifCVFU9PGNUyxjMIpdbuvfOqgg1mZJe
         mNy7A9hUfvE1hLRmaTL014UWj07D4+UCAq2vIpU4qX2dqvqvgDiWfQ0tjNZ5cn+DSYR/
         TIMKbZOstJMurvTmjJxKjTLmJokISNQAL2IzE8IUU/FN4dzMgfg+wWj9aKhksHbTVAza
         W+MA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=jq6dUynZLM/DYs1PNsFstHof4JImW6mSe1PVvXI3EJ0=;
        fh=RrZ19OfX14okVFSSNQSI4Ydw+VahiAISsipj6KSVYuQ=;
        b=UlABmh7J/9TyNDIkYHqZfRC9xAD6NyioFVUMQxT9S+NzwdQfCdMItZN91trusRbo9N
         VOF6y78NC39aNOxWOUvnC4KSYY6+B42Nn4AhkG3bG1EqvCCUBj2wh+d/ZwxcQPXoCMwS
         ljpII1zfDbYefqaPJd6BnN5j+Mrtp9DMOWd7thErRbLCstQ/IwkeJrM1mr+tAqkN8KN7
         jvIh/W64C0aVF/thJnOWq6P9WVVg1AJb/AzvIYEf2kB0/2VcGX+DCmDBvY/C6LsVoC5t
         iQ7rjg92Re+nwjZbqqztOh0wdiEvl9Mq+WH2UXfcgcEEuFlj4unaWsZrrrN9bspKT85m
         X7Og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=MkLdPBCa;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::61d as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-mr2fra01on2061d.outbound.protection.outlook.com. [2a01:111:f400:7e19::61d])
        by gmr-mx.google.com with ESMTPS id y9-20020a17090264c900b001d345bd5d20si402518pli.6.2023.12.14.01.27.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Dec 2023 01:27:29 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::61d as permitted sender) client-ip=2a01:111:f400:7e19::61d;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=fbHrzHCC79E2++YWFTyK8F3KVY0+2p50SLNR85qV04Dx5V/QTJzK+V8yhxERpVUl0RLGB+mJbadFZBh4Gr383zqraGhz7IRWDzTz6YVUOeNu+cRN0Y/g3gC0EEdCxQwdXq0qNxdd2GFOcLhJoDDUQFM1z5Q0sLa6ogHu652hp1TfQaiqnyCw2tvjQnKJr1PNBlwcgI86YpI8X9FBaIuq5ugqt2effrnhcc2TAwfCj4cJFEs+R/OIw8ocued6lMvMyjWGGMAoesCdeV8TOg+NRYo1zNSf4HzYrvAtYvh95rPOSQ71oSgH7GJsXv3jOEqxi7WJARf2w+yKhZwubfTQkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=jq6dUynZLM/DYs1PNsFstHof4JImW6mSe1PVvXI3EJ0=;
 b=R2WQkutVOz7ZEq7M+H14o/5ZW2F+JWkpm6G2hGGUq/xvI/gUisCdjsLaOhDOJrQ6F9snp1bpox3NQCU7ctl8+fyw1lla6ag11NEq1VhkT3qNL757ieVopDJUVe0R/0hSWIQFcrty1LLyBdoISgI6oc3GgVeuDn8YOJOfB/OBdFxDn954ghFo5onbRjNcLA+hvtwu3SdH3f1lG5/1etx+FYdzoYFPfINx6JTjH7eo6o5e/+y1ODKA4VQ19y8ww89DD5DmZfB0jyo6UDRf5CUh+y8r32EE4iPys7/E8MOIrQN+moup/aDupxjvy5RNIP0Br35my5CPXmIhBdOnxCnCGQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by PR1P264MB3294.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:1c::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7068.33; Thu, 14 Dec
 2023 09:27:23 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::f788:32b4:1c5e:f264]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::f788:32b4:1c5e:f264%7]) with mapi id 15.20.7091.028; Thu, 14 Dec 2023
 09:27:22 +0000
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
Subject: Re: [PATCH 13/13] powerpc: Enable KMSAN on powerpc
Thread-Topic: [PATCH 13/13] powerpc: Enable KMSAN on powerpc
Thread-Index: AQHaLlJKFt27m+mMQUKs0pZ7BCJjwLCogtWA
Date: Thu, 14 Dec 2023 09:27:22 +0000
Message-ID: <e51947db-747b-4b97-afee-198934c16ee6@csgroup.eu>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
 <20231214055539.9420-14-nicholas@linux.ibm.com>
In-Reply-To: <20231214055539.9420-14-nicholas@linux.ibm.com>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla Thunderbird
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|PR1P264MB3294:EE_
x-ms-office365-filtering-correlation-id: 09574041-9e0e-4b22-617a-08dbfc86e0c0
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 5dPPt/UKh03RLfEWhAoaFRJ2eXewupvP/1lpy7xVrHAiJFMdgKfAmBTL+ReG4DqfB6UFEsspswdnMjLhOniAMgXDg0FogHJt+BsaeO8UpcmJvrOLSeDXySNN9gLSS7fhKxGPx3XwDCdz7NSaI0M3NuyVtZ2ZaYX8Ej9qCbekYnQ+rQWNZLepsaA01qmrHE8yQuhmhS1zAgdX09Z4Q56AAidkaLl1DwRS/50/+s6qUoIAnMA8W9GNDVaYawWq6QjVdiL6f9uOrvt5LQiWYoQ9LEXI97+JYHi/L6E82qRQey04x0XZDO+kCdKnTPBzs1wnKh1IfXEzyidCkA5xUrGJxV1lugHFr3OLeZsaKMeOf351TeOcStb7RF7uFwGrabhFbDSsUpMstHvPNS7KC3+6F3yJANFUUOoojmLG4/u9E1HzIKUY59L+K0C5B0bWzDjyws5UmvK3V6oCGcFCbAJbKODKzM/y5zXmAEz2+iglpuspEtc1OhlCHiKiienBZOCArNqYUGtp+Fk3o8L78bqa3mm/oKZn5omhCXwZWb7N8820DIXuXpVap+yy5eW8xyqY7lqf/on/gg801zbO9ys2fknWA1BDTHidK/MNe87Gg+i3Q/I0OOOyI6opkZjn3UQG2+KIjzQrUBNYCTVejmFOd5+ruWqqmE4dElyAaZq0FGV/MBoFCjFl758tyNFX8nEg
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230031)(366004)(376002)(346002)(136003)(39850400004)(396003)(230922051799003)(1800799012)(451199024)(64100799003)(186009)(31686004)(6486002)(478600001)(6512007)(26005)(71200400001)(6506007)(2616005)(122000001)(38100700002)(38070700009)(31696002)(86362001)(36756003)(44832011)(91956017)(76116006)(64756008)(66556008)(54906003)(66446008)(2906002)(66476007)(41300700001)(4744005)(7416002)(316002)(66946007)(5660300002)(4326008)(8676002)(110136005)(8936002)(43740500002)(45980500001);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?TkxNeUo0YW5xUTFlZGdrVllQSVVVSFdkTHB5VnlaU3huekxMQ2oxNzR5dkVX?=
 =?utf-8?B?QlpEVkVHNUVuZ0oyOEc0bWVIbUpTWUREaitKT01GUW00b0I1Q1JZeWptS2dE?=
 =?utf-8?B?RXZzT2ljMHRpV3ExbHBBQXJyUjhEOTVwK3lTbFlObkRJQlhhZkZLZS9LY3Nr?=
 =?utf-8?B?Q2d1MGg1bWYwVFpJcnBZaVkvZ1BrdWxJcmZRK1V4emdsREtMamdNSndEUDZx?=
 =?utf-8?B?Tm1nT1JmVVFFVkY5R2p3NjRGZHJJUlhsZWErYWZ5L1FEOHdURHIwbVk0SlNW?=
 =?utf-8?B?NVZzR3hKZ2k5ZVE3NEZ0SFppSEZVcWVGNWk4UTBwbW5GOFIvNXhWMXhVUFB5?=
 =?utf-8?B?TWNjZDh5aDFUT3RxN2toTHhMcE1qc0dIdUlIUzNIWENteU5odzhwVXJkYXA2?=
 =?utf-8?B?ZktPeTJnVERFSjBQMCtKMisyQmprUmlITU1OMWRXTWtYTFpxM1R6QjVaTENT?=
 =?utf-8?B?WFN2UjdEWWtZKzNNZnRlYlJBTEdSUURTajVzd0hJSTRnT2NLY3dUek5oWGEy?=
 =?utf-8?B?cU1sUVk5THhUYzNmajRxcGJXSlo5VEd3cUVrcjVIV2NqdmdybndJTkM0RXBy?=
 =?utf-8?B?b1ZhVTNjKzJDaFd5RzFVd3RUT1lpZ0I5VnFaVzBwNnUwaVNCaC9aeS9wN1Va?=
 =?utf-8?B?WDN4N0VkNmhpcWR2OW1BYWxnc0Q1ZGFVMnpyLzVLRDNOYzFveE1FQ0x4TDBm?=
 =?utf-8?B?SUdHditlWVZwZktwcmZtUThsOEl2VkZTNHlWNXpQWkpFaHpvKzBBT2UzUElm?=
 =?utf-8?B?VXA4ckN2ZGxTSmFUekM2cWRMT0czaUEzc2pyV2tKaGdKSnl5OGFHNytzTFph?=
 =?utf-8?B?WnNqNWRqWlpUSVFsTVRkaFI3Vm1TOFQrNFVPaCtmZDl6eU1QdjdXQmJ1TGU5?=
 =?utf-8?B?UkNudEM5V01vRkJnQ29WcnRRalNkUFUrY0haeTU4WTM2aS9KdGROeEIzTUZP?=
 =?utf-8?B?VTZEdDFPbk5WUUJmMWFCNTZjOVpjWEdjZjFSN2ZKWUNRZjdEckNJZmZBK2xY?=
 =?utf-8?B?eDZtWGFuQ3FrV2lzamg5Qmx6R0dQT0V5WjF6MzA0cDVCK05IL2QrbkF2eHRX?=
 =?utf-8?B?RXlhUGJPdjhIYTltMGpsT0pCSmNxYkRsenFocnZuSTU0TlZJaWxXcWZZQ05w?=
 =?utf-8?B?czdvZHpUS21sekRyL1FaOVI1anM2Tk53enRCbWtZR0U2bWZHWnhDdUhLR3BG?=
 =?utf-8?B?WXhDNlpWWEFJSmkyNnRSQzFDZzFFT2FWdnFEVmM0S2V5YVRaV0hFblNncXFX?=
 =?utf-8?B?dk1LQnlRd1ZPalVZMDl5TWZ0eDBTR0s3TFJlRjc2QXpGZ2tXaW1RQnRRcVo2?=
 =?utf-8?B?WllFOXkzMno3bi8yZW9tb1NGTFFEeTlwNFFGUnRBUlJ4dlpOWk5aVklJUUph?=
 =?utf-8?B?TVVxY3Q4c2NCM1Axb3g1UDdZSlFjUHBlTjVOQ3lJUEpFK1ZmeXAyVGxFNVl4?=
 =?utf-8?B?ZCtvbHpsSU1XN0tob3NHNjdyUnhMWTI5cm84RlpOY0JkOWhXeWlveE9zcTlL?=
 =?utf-8?B?MTl4aWlIc2cwWWNZelpDSjZlOVMyeGZ2TXpyaE5QRjA1ZmJNYUdxVXVVczU0?=
 =?utf-8?B?Syt4TVg3N3BzZ3Y3aVVySVJzYk9qZVhyMFJJSzNySGdRN2NIY05sRnNOcEdG?=
 =?utf-8?B?UzBiQUVXZkxhRkNKUW1UYUplanVJSjNoOFJicnB3UGYzQXNNQ0ljRmIvcnUx?=
 =?utf-8?B?azZCdmRtNHczSFg3VUlsNXE3bE9sanlNcWFPdVZVVDVRYmY0OHFXZmFtbDhY?=
 =?utf-8?B?S0FtNzNjeDlHeGVNcXNyS3V1Ymt1MG5BbFd1NjhlYUJQcG12UFlnUDVMcmFU?=
 =?utf-8?B?VUlUMUdaM2lNZ0NOVUViVHVYdVhMbEdrVkx5YVJFOHNiUUdLcDJpTjRKU3px?=
 =?utf-8?B?cWtkVjZDTjJ6TjRjaEdkd09tbHhYNENzVytzeDUwaDVnVXRac3ViZDNZeWd5?=
 =?utf-8?B?WVhuNTlRQk5GRVg0U2NvWC9ISVNvb1NJWU5HbzdWU1hLUE1YQ3hmdS93UWRx?=
 =?utf-8?B?Z2wvSkU2dk9TYjU0Qmpadjd6QlhYdTZHUEZyQU5RY3FoKzBseExtTHd6U3Fh?=
 =?utf-8?B?M3JEK3RucVd6SkZLRDBnSFhyeTNWSkJCeEdaTHpUSjlZdXRwUVN0SFdaQlk3?=
 =?utf-8?Q?IC6w+JnbvRbD8QAKZEDniq1ZG?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <7FBB2617CD3A1B44B9387CBEA20E848C@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 09574041-9e0e-4b22-617a-08dbfc86e0c0
X-MS-Exchange-CrossTenant-originalarrivaltime: 14 Dec 2023 09:27:22.8953
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: FM+VNAw/ny2SPc6CJfGyuQIUUMHZiInZbcbmN+GzRRScCgbp8wGtiPDZ1v72vQ0PVS9LZVQMCU3v6Jk0Po7sQrXiK74DLQwoLI7Xc/akl1o=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PR1P264MB3294
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector2 header.b=MkLdPBCa;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::61d as permitted
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
> Enable KMSAN in the Kconfig.
>=20
> Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
> ---
>   arch/powerpc/Kconfig | 1 +
>   1 file changed, 1 insertion(+)
>=20
> diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
> index e33e3250c478..71cc7d2a0a72 100644
> --- a/arch/powerpc/Kconfig
> +++ b/arch/powerpc/Kconfig
> @@ -217,6 +217,7 @@ config PPC
>   	select HAVE_ARCH_KASAN_VMALLOC		if HAVE_ARCH_KASAN
>   	select HAVE_ARCH_KCSAN
>   	select HAVE_ARCH_KFENCE			if ARCH_SUPPORTS_DEBUG_PAGEALLOC
> +        select HAVE_ARCH_KMSAN                  if PPC64

You said in cover letter you are doing it for "pseries le guests".

Will it also work on BE and also on nohash/64 ?

>   	select HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
>   	select HAVE_ARCH_WITHIN_STACK_FRAMES
>   	select HAVE_ARCH_KGDB

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e51947db-747b-4b97-afee-198934c16ee6%40csgroup.eu.
