Return-Path: <kasan-dev+bncBDLKPY4HVQKBBPMI5OVQMGQENFQFCPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D925812AE7
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 10:00:46 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-35f7f9c298dsf4290775ab.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 01:00:46 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1702544445; cv=pass;
        d=google.com; s=arc-20160816;
        b=ESLH4SPYVHd7LokNkR1E1V7pHWXqii/Hsn0Hb+wbiBumiN43pFjSpb45XelQ7XQT/U
         mFcBkGZfvu695jE4hvy+CovSNne+FFRHH/2tXA4vx2FUpKsuBOoZe6sQ8HlJiRuVqM6p
         1HDyhrmPyStW7BePPZt5ZnPOv+bGDPREEbtAs978rhk3L40sm+ZtTQa4qkeuL+S4jzSS
         SrYrMv3oBkA0GrVY642uGpvOizxbL5MyzJuoHqOPwey7P4NPb//5IiR/aONksDdvQlde
         SPAQEybAjwnWP6GCayIym9XjcUyeGLsQx7OK80yUsaQuXGBcEl3XD97vtkb8mxyokeQ3
         N/JQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=4mCWSIJ3fPzWyROt84PPBs/H9YzsNU3Eo0CZANTKJ6M=;
        fh=RrZ19OfX14okVFSSNQSI4Ydw+VahiAISsipj6KSVYuQ=;
        b=b46KSXULYoqy9kaAw2DcXUkD0QylGUpp74m9wyPr8xbvUIzjnGsYwqz7mxfk83+l85
         my+koGr8yuCHAdyK7To02jNmwJuP4YfNoFoQfx8Q4ARMy7dfh59jWC/tfM1j2AlSDZR0
         VNbvV9UTpF/yGt7qrD7VARBRETbGIecs4ZQKSDWhJ3NmhSEncpRf+TKHmjh9c+33ueyN
         bZpAl/72QNwi08gdUNCC0cpqWiYUyDuvTs9P0dJRjslwD78UXM+t5Cvyg2ND4S746/+F
         i/pf5en80ji5WoQXm3tpi9RO3puodzqOFGFP5d2owN0J3QieVi3EMgkcYWAggRwQhdQR
         iQjw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=RTNUIvLX;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e18::619 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702544445; x=1703149245; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4mCWSIJ3fPzWyROt84PPBs/H9YzsNU3Eo0CZANTKJ6M=;
        b=M+pFOIJvbmc2d9xmbdiKm5i0jd2Cc1RUVdshxese0fQ3cn0vSdjGOLnIDMF+wBMHgA
         KgUNPiPMJRiBVsQwgzsmXmEWMeLnhfLYhUjM9tuhZ9maFkxo2AjISv9gFK1wtSmoQFM2
         S1INX+PDO/JLJLdlyzsMKtJDCBHJo078x6Ek9NdhceNRC6Rq9JC4pVKNfWpMdAn+rJkU
         D0zine8vRPk3a24P0+w+g4N3tLBI6Sv4iVG8ggkr4aKz6aKnPb8FOvwxzSItNJaV52Cb
         Ktt7ukswIUeyEPVdHuRklFbj8I8sAbTayZKqxeAwoW0H51HWIlDV5RasaEMH0h3YxRa0
         IT9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702544445; x=1703149245;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=4mCWSIJ3fPzWyROt84PPBs/H9YzsNU3Eo0CZANTKJ6M=;
        b=J6jXPB1o3yWY2QLmQ114oRW8WPSQ+nnYdUZv1l/ZOfj8gSAFlFbtoM+PcPoSpMV3/M
         ZkLkn1iI0bre1xclK5l7CYgEFeKgLW5qD6fbTnjjAzVHq5ICIhYxFkkQS7khUiFSFIZ7
         q13BI7tP6/xJL/dwMd2/DU1tHWppMTmKPpncPE2QgOMG6JhYps1i1dzdhZ2SyTtZDF9B
         OjHcdJt4D/eEocgOjFcRr3ZFtvgrE4bWfGwLOnAuIxbtZ+Oh+ZExl48WIBIjcyI0TYgA
         sFL3Mb9zVO52nJc2PFx1IdY9F8Ta8MNZPilt3ocsaWujyonJaQ+QYIUWPo1WT7NCtTz6
         KdTw==
X-Gm-Message-State: AOJu0Yz6MAN9Gnb+xhr/0HSXHsMt30GGp/vxRFsPZltTl8NV5w30WT/F
	gXIC9qGyn2Mk5tubFi0WA+A=
X-Google-Smtp-Source: AGHT+IEbhSyjQXgoACjhWggBlaOxshVVTuzz4E3Zw6pnp+yBqST9MfbJL+vkZ7r8yDCOvBxZhobCww==
X-Received: by 2002:a05:6e02:3881:b0:35f:7e26:96e3 with SMTP id cn1-20020a056e02388100b0035f7e2696e3mr980802ilb.49.1702544445367;
        Thu, 14 Dec 2023 01:00:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3886:b0:35f:6a09:c1ec with SMTP id
 cn6-20020a056e02388600b0035f6a09c1ecls656924ilb.2.-pod-prod-08-us; Thu, 14
 Dec 2023 01:00:44 -0800 (PST)
X-Received: by 2002:a6b:7b01:0:b0:7b7:13a5:386a with SMTP id l1-20020a6b7b01000000b007b713a5386amr9255320iop.6.1702544444422;
        Thu, 14 Dec 2023 01:00:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702544444; cv=pass;
        d=google.com; s=arc-20160816;
        b=E8pJTSC4LxRZN6qSD0RkWANpHq0I6RdHJyhvx/YjgzJqyqIqc99vD2xxGiScsbyB/m
         p0FWLU3CTS3TGQWQFACFs/RWgaxFRUpiXsy/0m2fqr8lniX5v3KM/7BpZ5iLENk9V3uz
         8IGAyu5gXSiL7Tf70zLoMGdw7A8mckgU5Kq2WACiwF4HuyAo68wtxusPvYunGN28lQju
         s3xFiPSiBjIDNfkN9xBOjHeiKTEMxcF6sFEOZI3rUfotDdZeBOZpdDGEAFwweEFBVNUL
         HVLjMEMU528mRMPgM36ziJw8AlzWxvGQlowviqxha1AclqYZHEJk/2DJ4W6reVLKDURT
         +/Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=bvwfZpKPULduv5ChTs6A0rFOcJeHTuqax18gvWYt014=;
        fh=RrZ19OfX14okVFSSNQSI4Ydw+VahiAISsipj6KSVYuQ=;
        b=ZGu51ROcumtjYfKTb3wzowtDB8NedZIYqXhLkvQHmp6TMst42N135QnvUubJBnoUzt
         yXXVCnV2/FWfmSB9WSm2/1cWgfxfQEnaUd9z2LWMEKvO8a65xlmiApn9NJAC2RTQh3oN
         Rgmr74xv7HIW6Qh9YzgPfrPFKHVKtErJamDJw6Tn6EqSbWWzFHfsy80t1WVIjDfr49RU
         rzaPW18Z3JLbvxNTqs+2gxJyeYdpUlzF5tikJzIleNcZ+PPz8BAaESy7T62G3p6sKIRW
         neDdxeX2R1bKrOFnNoTXST0l7oW+jIj0vjzr/xAQJm5YOzfnara9o5Oxhh3cJsCjE4c1
         5OuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=RTNUIvLX;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e18::619 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from FRA01-PR2-obe.outbound.protection.outlook.com (mail-pr2fra01on20619.outbound.protection.outlook.com. [2a01:111:f400:7e18::619])
        by gmr-mx.google.com with ESMTPS id j15-20020a056638148f00b0046b11d71dc0si4651jak.0.2023.12.14.01.00.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Dec 2023 01:00:44 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e18::619 as permitted sender) client-ip=2a01:111:f400:7e18::619;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=etKgXqIrs828EemeJ7MKDpHZa2tXtBfwC4C6/Z44PFT5vcIS5g91oggrOhgQEWo7e9VSg36XpUMWNgnqOfRTtL9pqnjAkboLDdfoBDAhBJSo/zB59h0120RFL2T/9ikDyXCZ1jyYD340kfQpxWLcAVrbQfW18Ku1DvfGcsSk5H9I7VEaSk2/3VusLUIPZyIOtyJJeELCIc4sAd78azRRuiWkCTl0L/t5udfIHGF+9hdnLrszdb0kLC2+3xnZIme6a3stljD+3cH7PbeNtPo4Z4pjtsDANIhfasI2DTOUMAnv47YqU9OrA9wwCqCpMdyOozVTvbVtkStE/4C3DfocVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=bvwfZpKPULduv5ChTs6A0rFOcJeHTuqax18gvWYt014=;
 b=iyh4t1JaNZ2QR18o/bgORlbuZQPgZLc5SlHh1TkuU8JkiD/x/QPbk0zpL23SlsD6rda94G5MTdoMu0AZAAu9iH0YKAldPEYwtkyggdX60yHnpFZ59d+BeRu/u+xEb5srSLQKFoAdcVEG/IsDAuxY0ZM1HmvhUGWaSQ9dL50obFDao1oQBiMnDWGvOuMeeDMdRatkq4EKxWz+aC0ogt5I+lXdr4BjgM8588MdzXtuFFkEgkA8XfjC8A0bMApCKvRvp/aLWaK7Xbaa3uPUEo3+8QGKQCunG7Katdl8fptqKDiOFWMJU+qmIvYpK/f13uw+SAMSCjALEz7dh2hA/piQ6g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by MRZP264MB2040.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:a::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7091.28; Thu, 14 Dec
 2023 09:00:41 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::f788:32b4:1c5e:f264]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::f788:32b4:1c5e:f264%7]) with mapi id 15.20.7091.028; Thu, 14 Dec 2023
 09:00:41 +0000
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
Subject: Re: [PATCH 09/13] powerpc: Disable KMSAN checks on functions which
 walk the stack
Thread-Topic: [PATCH 09/13] powerpc: Disable KMSAN checks on functions which
 walk the stack
Thread-Index: AQHaLlJJWEBA6253AEOXkBRrg23pE7Coe1+A
Date: Thu, 14 Dec 2023 09:00:40 +0000
Message-ID: <e70b4365-cb0c-4565-b7b1-ac25be85c5a6@csgroup.eu>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
 <20231214055539.9420-10-nicholas@linux.ibm.com>
In-Reply-To: <20231214055539.9420-10-nicholas@linux.ibm.com>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla Thunderbird
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|MRZP264MB2040:EE_
x-ms-office365-filtering-correlation-id: c1251bf7-fc1c-451e-543f-08dbfc8325ef
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 3f7/Yi7RPHzUMpDtpGdZzX5uoy2pC+xhn3ewHOSSrotK12c9s+piuMH7lrPgkKsyG3z0LAmGzu8kqEayNqTl77flkxbmt92gb7ZTgIhh2W+z2ImgfUfUgI/RCxm0U7E+IjRBp1BcDUP6BHHNPFhdu1Mof3YaEraAGeXet2qfMjBAIdygAMaRC8ld3zL/QKTZbgvcmZJ3YcxKXm4BxN6Z97D14T1jEUc0HeRpN+PBiODbuf+FyRb8vGP11r2xxlVbOMeqnrASejmUfSKJ2wDJLoJhL3RJSQLWdarbQJOxA3m/ppOpZ+PWstS8Y+wtiFMZWRnxgQUSi2ZzrbxoiGQ8n1y84MPtH2YmZjSIy8E5f/I9JJf2jppBxStfI6a4KRICaR+DDkQsZfZr7g5HfAwxGxPOh4oXzEj9QK6XVybSV3i0EEIF6WI6rPyEVJr8glYQx7kzkLURBnNl+SECFFUUIlUHsT0g1q8+0qZ43apEOEdfRevehmGQp8UN/QIH5/d1ym2bXHCLRYG8wnxFmiaCaHdMP3XGeRXsm/HeE0a6akLoSBECwVMvBM9yZTrT1yZD8fj8LF4c8jsu2EkPdffPSFipTKEBBWHwHfVvydgVDXBBz6FUxvAH39E8N+4wfieqK7yVwEl/cA7waD9q1GyWaKHsaIk/BbHN2RmLf3m0Lf4=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230031)(366004)(396003)(346002)(136003)(376002)(39850400004)(230922051799003)(451199024)(64100799003)(1800799012)(186009)(7416002)(2906002)(31696002)(6486002)(478600001)(41300700001)(38070700009)(31686004)(122000001)(86362001)(5660300002)(44832011)(4326008)(91956017)(110136005)(76116006)(64756008)(66446008)(66476007)(66556008)(66946007)(316002)(54906003)(83380400001)(26005)(2616005)(71200400001)(8936002)(6506007)(6512007)(8676002)(36756003)(38100700002)(45980500001)(43740500002);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?YllFcXUwZ1J6cGU3ZmRFczBTb3p3bzEyNXZuWFNsS2pmU3pQWnhER2piQmtj?=
 =?utf-8?B?aVVBbzFuRmR3T2ZYWmx1NzFRTDgvRjBtMkl5bkkxRFJNQmw4TU9hYVVFN2di?=
 =?utf-8?B?WUlwaDYwcGFLZVB6cit2SjBpOURBNm1Oa3pPSnN3UUtjWCtuUTNCQjR2TkNk?=
 =?utf-8?B?cTBNd3B0aENCRmJBSjN1dHBjNUtuTjlYNUlVR2Q4ckRTS2IrYWZtWm1JcWp4?=
 =?utf-8?B?dm8yMUppWFlJWVNSeUoxeXd1SStiNmlwd0JoNWw1akt2S2IvQjVLNWVONU90?=
 =?utf-8?B?UmdsMStIN2lKTDNPNVljQ3JpTURnWGkxVW44bGFydnQ2UitSbzFWY1Z4Ry9L?=
 =?utf-8?B?OW51Q1N5QVdmNmZhYWZlSkxuSENEYmhaTHVQT0FybVF0SXQyaWhmTGVvQUd1?=
 =?utf-8?B?a3hpT2k5czdHYmY2bDRsOG5tT0M4eHV3Q0ptM0pmZjd4RjY5c1YyM0VTU284?=
 =?utf-8?B?RFZ0SjRZekgxemVFVnZpcVI3K01yQWRaRXFWVWRRZENxK21mUHkrQk5iaGg5?=
 =?utf-8?B?b3lpYzFWV21RblRobzNFRVlvWmlzNUJvb2NjOVdtYlBEL05GYzhodjA0d3Bn?=
 =?utf-8?B?bXZGdW0yMkVsWmxJSWVPZE94Qm5aYS9PbjJHMXlvOG54bjd1R1BuUTVKZGhV?=
 =?utf-8?B?amMwNTFocE4rVWpxREI1dUVMTEFrODhVZ0ZrZ0dyVk9HMjNDaUUwRnFjRlhl?=
 =?utf-8?B?bjdKZ09UN2tON1pFMWltdzRGTTJWRlVCT1VlZUVnY29lREpzQ2dGV0NySUpk?=
 =?utf-8?B?Y2FUenB6NEJYOC8wTDdEWEVJdXR6M0Zxb2dUSnZGMGNsOE81ZHNrNS9wZ3dv?=
 =?utf-8?B?MTF6UnBNQWZEbTNtQjlqUVJYWGcwbk9uckRVaHUxUG84Y3dOZ1QvTXFHb2NJ?=
 =?utf-8?B?RWdvMUFLT21QOVNQTEhEUFZlc0lqSy9TWFNmV3VsM3FTY0h4R3lUSFBoMkpa?=
 =?utf-8?B?SlA5Rjg4cU9tUUptZURzUWRCdEFpOFRyZk80NW80aVFWb2dQT1dybGYvVEdP?=
 =?utf-8?B?by8xN1liMjR3YWJDVkNDbTZuU1BHVFYvQ0o3UmQyRzEvMDZRc1E5aEYzOHBi?=
 =?utf-8?B?ams3bXN2andkckU3Qm1JWU9UMWJ2U0s2RXU1em9ULzYvNEpwbFZXR0JSWmIy?=
 =?utf-8?B?K1dGRHkrVkdsaXY4SUt0dUZLWlFMRjlCaFFuajlhbEozVE9qSnExR00xU01t?=
 =?utf-8?B?SHF1bXZNTjB5TTB4OGZwZXhIOER3QWh1L21XbWNCZjcwK1FrVFNIaEt0L3gr?=
 =?utf-8?B?SGVBd1huOXRKQlMrMmZjNFV3MXQ2Rk5zSEtZNnN5dDVFM1hjUHJpdnJUcWxF?=
 =?utf-8?B?cXhJbG1XOE44RmlkazVaRXJxT0hsdmdHYS9wTUZ5VG9NVGRva3gyU0h3Rjk3?=
 =?utf-8?B?eEZRQ2tkRFdDSHFsK0VtZG9KemFKVFlUWjdhRDh2NGM4TXlQdmkvQmExazdX?=
 =?utf-8?B?aEdoK3lBdkh6Y2VhZGhRNCtadzMzampaNXFRRktzTTBwK1Q0bGVINU56S0Nv?=
 =?utf-8?B?cXgwTXhMc2tJa0JhMEYvVCt1SThnRmx5dXFlelp3Tm91d2FEWTNCNTJ0ODFj?=
 =?utf-8?B?SlhLeHNmNnpvZkMwRHFsU0ZEd3MyZnJwWnhaaXRPUmxLZUVDK1ZFaE03UlFB?=
 =?utf-8?B?MGsyMjN4NjE1eXRrNlhEeUVET0JuSmdCT3RQZzZTN01vYmQyL29Zc1cyODNp?=
 =?utf-8?B?dkZkcmhHblk1QWlBWU1LaDEvTUZzN0VGeGJld0FHdmZHWTdvc3p2SHpNblNN?=
 =?utf-8?B?Vzk5L2FaQVFRRi9ranhKblZmL1NRa3BjK05LWXJpVjNvM3dRRkFCY0czTFcw?=
 =?utf-8?B?cTNSb2NXS05tSXBJa3owN3drbGN0UElqYmJSaCtqMFByaU9uUTFUN3Zqd2NJ?=
 =?utf-8?B?OHNIejNjYzVTNXZ0NUVxQ1NxUmNjZEUwTG9DQjR4TFp4aVBoaER2WXlkODFE?=
 =?utf-8?B?SEJkdXEyY0ZHVWdNZDdkUk9QNzhUSk5RV2JOUzExSE1mc3hOcEV4a1BBN1JP?=
 =?utf-8?B?VGcrQzN4bkpaRWE3YnRobVhmMC8wK2xIanc1c21oVU42VWNtZkJGZkxId01W?=
 =?utf-8?B?cjIrR3k5TFRuZ0dmU3VxWS9sbktwZHp5WXoyV0xsN3BiMVMxRVVWVnFQMXh6?=
 =?utf-8?B?M2dIM0dUUmN5dVNVaUVxQXNJRVAxNGVyM3ZiVUh0OEZFZzAweHN2RnFtSFZo?=
 =?utf-8?B?K0E9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <A61D03C90DADE7469E4CB76013F56659@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: c1251bf7-fc1c-451e-543f-08dbfc8325ef
X-MS-Exchange-CrossTenant-originalarrivaltime: 14 Dec 2023 09:00:40.9865
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: XyMlTIS1uMIGhd9PlKLKgo5/wiwepjfQfa94qryJyap/JfzhCdWGcDJ38noyGT13CkI13bn4fU5p6PohJB1dOLHKqjTkEeNk51R8cQYb8LI=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MRZP264MB2040
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector2 header.b=RTNUIvLX;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 2a01:111:f400:7e18::619 as permitted
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
> Functions which walk the stack read parts of the stack which cannot be
> instrumented by KMSAN e.g. the backchain. Disable KMSAN sanitization of
> these functions to prevent false positives.

Do other architectures have to do it as well ?

I don't see it for show_stack(), is that a specific need for powerpc ?

>=20
> Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
> ---
>   arch/powerpc/kernel/process.c    |  6 +++---
>   arch/powerpc/kernel/stacktrace.c | 10 ++++++----
>   arch/powerpc/perf/callchain.c    |  2 +-
>   3 files changed, 10 insertions(+), 8 deletions(-)
>=20
> diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.=
c
> index 392404688cec..3dc88143c3b2 100644
> --- a/arch/powerpc/kernel/process.c
> +++ b/arch/powerpc/kernel/process.c
> @@ -2276,9 +2276,9 @@ static bool empty_user_regs(struct pt_regs *regs, s=
truct task_struct *tsk)
>  =20
>   static int kstack_depth_to_print =3D CONFIG_PRINT_STACK_DEPTH;
>  =20
> -void __no_sanitize_address show_stack(struct task_struct *tsk,
> -				      unsigned long *stack,
> -				      const char *loglvl)
> +void __no_sanitize_address __no_kmsan_checks show_stack(struct task_stru=
ct *tsk,
> +							unsigned long *stack,
> +							const char *loglvl)
>   {
>   	unsigned long sp, ip, lr, newsp;
>   	int count =3D 0;
> diff --git a/arch/powerpc/kernel/stacktrace.c b/arch/powerpc/kernel/stack=
trace.c
> index e6a958a5da27..369b8b2a1bcd 100644
> --- a/arch/powerpc/kernel/stacktrace.c
> +++ b/arch/powerpc/kernel/stacktrace.c
> @@ -24,8 +24,9 @@
>  =20
>   #include <asm/paca.h>
>  =20
> -void __no_sanitize_address arch_stack_walk(stack_trace_consume_fn consum=
e_entry, void *cookie,
> -					   struct task_struct *task, struct pt_regs *regs)
> +void __no_sanitize_address __no_kmsan_checks
> +	arch_stack_walk(stack_trace_consume_fn consume_entry, void *cookie,
> +			struct task_struct *task, struct pt_regs *regs)
>   {
>   	unsigned long sp;
>  =20
> @@ -62,8 +63,9 @@ void __no_sanitize_address arch_stack_walk(stack_trace_=
consume_fn consume_entry,
>    *
>    * If the task is not 'current', the caller *must* ensure the task is i=
nactive.
>    */
> -int __no_sanitize_address arch_stack_walk_reliable(stack_trace_consume_f=
n consume_entry,
> -						   void *cookie, struct task_struct *task)
> +int __no_sanitize_address __no_kmsan_checks
> +	arch_stack_walk_reliable(stack_trace_consume_fn consume_entry, void *co=
okie,
> +				 struct task_struct *task)
>   {
>   	unsigned long sp;
>   	unsigned long newsp;
> diff --git a/arch/powerpc/perf/callchain.c b/arch/powerpc/perf/callchain.=
c
> index 6b4434dd0ff3..c7610b38e9b8 100644
> --- a/arch/powerpc/perf/callchain.c
> +++ b/arch/powerpc/perf/callchain.c
> @@ -40,7 +40,7 @@ static int valid_next_sp(unsigned long sp, unsigned lon=
g prev_sp)
>   	return 0;
>   }
>  =20
> -void __no_sanitize_address
> +void __no_sanitize_address __no_kmsan_checks
>   perf_callchain_kernel(struct perf_callchain_entry_ctx *entry, struct pt=
_regs *regs)
>   {
>   	unsigned long sp, next_sp;

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e70b4365-cb0c-4565-b7b1-ac25be85c5a6%40csgroup.eu.
