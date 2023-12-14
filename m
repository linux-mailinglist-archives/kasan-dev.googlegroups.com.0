Return-Path: <kasan-dev+bncBDLKPY4HVQKBBHEU5OVQMGQETGQJAWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 61CC9812B90
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 10:25:50 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5915b261837sf1287215eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 01:25:50 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1702545949; cv=pass;
        d=google.com; s=arc-20160816;
        b=y9pQX6wlcvY+cnyVxUtvyP8T2m+U6LBigsNv0RHSoetAxnUgRIZMpZ6u1pMmO/IZvs
         tJYmqXTWGGR4RoR1+/GRVfKtOApktOGwd+aplYm+Pv2GvjfeBP0qFDm2SNGc/Q/qRoeD
         luFSzvVpBT0R8RN8qRjnCu1/LXsCXGLEnooI/7h8jL355JXs6mO5jVRRaxU2I3gZjpPs
         pqcoYQuNufblTwEocNhDz9Qe7ZpsKgFWdvENRRqySy88QtKXLile1r/q85yr998zDgR0
         21rxzg5nZsQMPdeUJdWkgXy1M2XyGwMv0cic0NXEctGbghYafhY015tCZjBo9zmygRsK
         gQpg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=kqjNFlBV94T9Y141AI7EIUcVMtJh3dgKR8QGWt3lfdc=;
        fh=RrZ19OfX14okVFSSNQSI4Ydw+VahiAISsipj6KSVYuQ=;
        b=qmuyGnjSxigVAO5qhMcmI83IagPvh9DLCrwBaEjC2+1px6MAkgzTBO5egCzY/nyDme
         DZJt1Q1srcAjDzoYQJuY8We28t0tyNymgQe//DbtbAEXZV1TC7eViWtxScYXc8Q2NV0r
         tPwi1OE62SKz1OjqZ6a/yVIxMkvTsWEzzdPWlwgH7V2gO7lhokTefUvTlXlAF7Qlm54q
         SDTBARL3R6a5t7Lm9/X0ccFH7IMAMkHo2wlKv0v+ooxIUAN97p5taadWSPXIrm9wvKMJ
         bMf7ybflNNqIfwlSyDRz4ChaujJRkpUonm9PkIKfx3g8xk+sBsd58hbzIZG4Ni91euly
         DLyQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=UsGmsXSd;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::60d as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702545949; x=1703150749; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kqjNFlBV94T9Y141AI7EIUcVMtJh3dgKR8QGWt3lfdc=;
        b=qI4eL538AhCzPHRrpox8N6Kszi7AlZzo1GtQSqTgM+AzVhFMFGuBFoi4hI/8AXQkWk
         CUm3DnW6bDMk4lOhDKO4uEW8uTmBFPNNI/dlAHHy+nY9no9kSbc2llQ6+v5m940rvG86
         UmmIFnIz+PvLjSR+ZxhCEOrXG45f8Um83BRbguRkPmxpG3sqbNR8XQrOLqIgn0PmdRmJ
         cuVNxTsUiwTSAkFNXU4jr6HXrA12GCgpO5sUe9bj6zSfdximk5T9npV37XuQhhsUNoJD
         3goB8QtEiOPKiyKXpJxNfWGF+pt2AykQv9lIgm4Yjim9bv8lzBsUAkmyfX3lnx/S6FGi
         gwOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702545949; x=1703150749;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=kqjNFlBV94T9Y141AI7EIUcVMtJh3dgKR8QGWt3lfdc=;
        b=oxnh9oUZZqwjFmOZQfdFnCmcnF07nCfNFJ9RtOfNzWEZubH4VCzNQgoZFRUbY7NbtN
         J+/TZEhEZn8xtiUefkhhdigi5XjOcxc3zYCLeuPwVPkVXnXipoJY0Irm6QNNiTNEn95l
         21NY73c1anE0c4J/Zf+/g+CIpu4WiF/SyhId82cuxJpvKI5+XTuIyLVHIK6fKA58qPlr
         0M9k48P8f3pcdSeb6N4YwmhA08ifnxdvLlrYVY9Ib4mITGQSnCqDSnWMoNSFPBtQ95Ar
         2Lk6ECU2ftLUjlrNTuNZaVstLcnpM5zISUCaq3uPwBDExxSnhT4dcsaiJYCPghVMd+kR
         syUg==
X-Gm-Message-State: AOJu0YyFxjdvExLtTdHAfealRnhQ13kJj8v+GrmxJ/knkyYv5e0zr6D/
	SyLxhZrrqCllQKlqMjPxXDY=
X-Google-Smtp-Source: AGHT+IEqIGBfQrGohRsNl2eYo9bi+j+s2hh6u4xkl/mZdGaY+7vZbk8sBU1wnGArKBm5kmRyrPoJEQ==
X-Received: by 2002:a05:6870:d0ca:b0:1ff:2d17:5ce4 with SMTP id k10-20020a056870d0ca00b001ff2d175ce4mr11846055oaa.40.1702545949006;
        Thu, 14 Dec 2023 01:25:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:49c9:b0:203:1826:df23 with SMTP id
 ty9-20020a05687149c900b002031826df23ls25421oab.2.-pod-prod-08-us; Thu, 14 Dec
 2023 01:25:48 -0800 (PST)
X-Received: by 2002:a05:6870:799:b0:1fb:75b:99c7 with SMTP id en25-20020a056870079900b001fb075b99c7mr11487599oab.118.1702545948415;
        Thu, 14 Dec 2023 01:25:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702545948; cv=pass;
        d=google.com; s=arc-20160816;
        b=vkLL2E+pjrTvAmlHQso8YepyYGog29juMT1ku6guEGtfyuFUXOyKxN0TpHUut4PBHk
         M85qie6Mn271c5kuT9f1967lm4XT2Z764Lxb+If5xcaR+v6LcFaOjpzxUOV8KFlgNifZ
         QTKusvB8O0jxrKeLIg6glL67jslg2iU606HieqQ6l7m8Tq5KFKa9LFq3SN+B7WW3IM4k
         rQAneB4ZFkMtNwpJBMTQOGwakJjt+FJNtabKRm7LcxaNotkrXWnNJkTvyYBj88GM2uZN
         icgwK3YjeSfn9WEYPd7f0c8+wQVYzsSKa3lKd7XRufMu+KIbKiDJpXtRyr3TAtUQiiI3
         Ei/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=B+gsJ/8AQtYkTRB1aLs7FPjM3Zb3btcBLD+D1Kuh8+4=;
        fh=RrZ19OfX14okVFSSNQSI4Ydw+VahiAISsipj6KSVYuQ=;
        b=JldVj0ly+mbKfa/La+b9Q68MrUUZeYOnRlU/cNtpOL4rTLicpZb38x20Pz6xqCtOy8
         G9EWEsaNCX6Ae0Lsqq/4AVCvlZXVz4CsYqgXqTDxN0sfny386PUEFud6Kbe9YoxKZ19v
         MdlGPsKHR8enyuCExNCRAHCc26BAU1xbOLZdO6H6HqxxUgRs4d7avYbg93lmyC3JpxO2
         /nIJ+FXgw8Ch0vwC2OYVLsebTPuRoEBN1qz3caZ42HTXR4gP1J5Tz0pRSi10bv9yFw/4
         mCk6sSP+FO1jP4WCHQn8gBTs9uB5JhoItrLOPpGoS+jtDFjWhl9kFOs9dRp+WdxDupww
         3NYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=UsGmsXSd;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::60d as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-mr2fra01on2060d.outbound.protection.outlook.com. [2a01:111:f400:7e19::60d])
        by gmr-mx.google.com with ESMTPS id hx10-20020a056871530a00b001fb179a3c63si1598411oac.3.2023.12.14.01.25.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Dec 2023 01:25:48 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::60d as permitted sender) client-ip=2a01:111:f400:7e19::60d;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=oQSh8nQABCK8b9tmUQddQfkKwWPsOTDpaMygcX8zMTz9Hu6GhhMs1GIm2Roq6M8wLvPZP0VT3h1jI+LOyXBNtcd6yzHAuDdukVjYIE1q1TLJum2FlPyGtAQADByW1Ld/HOpM0RYnLjbUFdXw6jgnl5C+xusPx9jBkC9uL0WPXx/gCbFtYLDqdw2EPfLDsnUzFb+wc5s2ENFuMF/ZO/Oo457LAOrJIOoa5wzrXLGAlQnoISQ+aOg1Zj9cdhyFtqLCUMw18INM8fKELKDWBtbSuWt/O80OtFbK9C+D0Aq3u1NcwnDxNXQ4UWXkSYc/6iKj8F6xa/C8xOSChzjb9r9KVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=B+gsJ/8AQtYkTRB1aLs7FPjM3Zb3btcBLD+D1Kuh8+4=;
 b=fLJ5+WzmQ3jo6ipZn4V+a+bj6uM4B9ibC5PCD2eAOzNMOA9Qux/YqQy2ZMBkcDX4o2Qz8bX9F1W/9h/kGeItgJx/N3xbJBH9SajiX7KQCLkOrSVbu5f18WE8jVCZ01TJYWRb1SRwB60GqR1jtA7Le9EXUykXY1yFlttV/cGsPpdsaSzZBrC73Mn3f9RBGe8u93g9kOvnr+3Sx7jqUta6bC79kGfLYdNTwqjxlcAihh/Iw3sFKKzRt2NvEbrSyqtC82l2s4GrKxjHUyw75jc1j7lKMhHNgmm8qh48hINFkbdTxZjR9ZQGv6wmGfUuT+nUnj8zj1fOq75COcqm30dmkQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by MR1P264MB2883.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:38::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7091.28; Thu, 14 Dec
 2023 09:25:44 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::f788:32b4:1c5e:f264]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::f788:32b4:1c5e:f264%7]) with mapi id 15.20.7091.028; Thu, 14 Dec 2023
 09:25:44 +0000
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
Subject: Re: [PATCH 12/13] powerpc/string: Add KMSAN support
Thread-Topic: [PATCH 12/13] powerpc/string: Add KMSAN support
Thread-Index: AQHaLlJMXQiYw0la3UuI69TOhUcnGLCogl8A
Date: Thu, 14 Dec 2023 09:25:44 +0000
Message-ID: <2f35548a-bdbd-4c37-8f60-cebeb381a7af@csgroup.eu>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
 <20231214055539.9420-13-nicholas@linux.ibm.com>
In-Reply-To: <20231214055539.9420-13-nicholas@linux.ibm.com>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla Thunderbird
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|MR1P264MB2883:EE_
x-ms-office365-filtering-correlation-id: 45f7172d-b4a8-4bd8-bacd-08dbfc86a5e1
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: ZPz5W+Wg8XDAjZqT4gqRh4zSK+EZIigHDHZqaRSKKMTc+Wc0qXDJLWxVcncKb0/jEcSkhr+F/NC4K5hjGXABwrytSmqaUA6IN9A6N95SXr6ZigFcyFGdwG2Uec5SNz79GF7wR0rimIFseKK+saVRqFXoxL/CL/tJtzh+PIfzQ+TnaWsyqCCL8hckX+nAR94MTS4navwR9aPYuYm+hKuIDfLPV33DJbQQIFr5I8mPt8hkMOr0cDYZC6SY2P7XlbXIaq+ROSp+dIM/woh2jgaXcjcd8PJKvM9GS08u/hCHLFcZE/p5a2BbH0JOGXX9EAwyP6OUt7lyjyGnnRhC/zXjh2Nn/xSbSc8A2q/tciaKdQ5LsBtO1NlwdlRMrvTgTBi6yEGQMEXi4jXcadHCwrYaFfXytby6zeXbjDyeYF1LIASzJ7MmzHfLw9+aL0HcWxR70xKjjd9huqlOH2+6OIsqqlCitJ+7+ZTqOD3a86RACKPxBPriaWWprWI61Znf2JmeP5FPSQB/LVdENUmUwZcbWN4EIu3Sc7l9hU7JO/9ucUwQjCGlW99VmtMeU40nmnw+EZz15TEreYWCcOEDkSJnk0fK1iQ1jFhyLMYyLqsBsExKI0+3tEEqZhtMtZ6mkDpVmFQ8D8gHXrRXgoG60X/LfyUgvRc0BB65Ib5U3FZX4TJ3ntS7waBln8y9QNDgCMGT
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230031)(366004)(346002)(396003)(136003)(376002)(39850400004)(230922051799003)(451199024)(64100799003)(1800799012)(186009)(2906002)(7416002)(31696002)(6486002)(478600001)(41300700001)(38070700009)(31686004)(122000001)(86362001)(5660300002)(44832011)(4326008)(91956017)(110136005)(76116006)(64756008)(66446008)(66476007)(66556008)(66946007)(54906003)(316002)(83380400001)(2616005)(26005)(71200400001)(8936002)(6506007)(6512007)(8676002)(36756003)(38100700002)(45980500001)(43740500002);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?WVQrRDl2Q1pwZGoxaW1Ud0NISFY2THppR2M5WldGeU03cTJxQThURDgxQ3hv?=
 =?utf-8?B?NDZFRG1jS3JoZ1RUcG1mOENhVTg3ZGsrSzAzNkdCeng3dXE2THJzNEhCY0NR?=
 =?utf-8?B?Z0F4NTRYMmM5eXlUK1lwQlhVYS9kR1gzbVpzUGFHcmhHSTdncHZrbzRxb1Rz?=
 =?utf-8?B?UHV4NXgrTGorWnRYWHRyeGJJMlN0cFhiQklQYnZVTzdiYjlMTFJzZTF0cWFr?=
 =?utf-8?B?N3VKQzlSZHNrb09ucHh4R2pEVGtoV2dLbmZHZmVadWgreXp1bGZ6dUMrSU4x?=
 =?utf-8?B?WGRSU0xmL3N3TjZGVVM0TkxjeGIyZVhBUHF6Wk1Ud3JwNC9KSjNXV25MMjZ5?=
 =?utf-8?B?bVFNTHVmZkJlOHZSV2VWbHIxOXZoVmxZc3RiQ3F2QVBkYStoWEoycGRHaEdJ?=
 =?utf-8?B?ckYybXdSL3d6VW5hbnQ5ekVyTU9kaTlaaHdhWkNzK0NEa2d6Q1lNNWZNNGp3?=
 =?utf-8?B?RGFGcDdxTEdPVEp2Zm54eU1oZ3JuaUtIZHlPOVk2WDkyeWZzMmhTdkdCb1ZD?=
 =?utf-8?B?NmRYM0lOcXptajhodFVvdDhWQmxaMnZzREJHR0VRZkxIWjlBTnRNdmltT0Zx?=
 =?utf-8?B?L0VhaERIMEp1N09OM2w2N1dhdHFRRmFpRFhDMmg3ZkwrYkI3QmtzS3VuSWZQ?=
 =?utf-8?B?a0tNTjBJazBqcEtScFRhL2wwMTJ1SktZdDcxa2hOMXgyT1ZaUG1EQmVQUHpV?=
 =?utf-8?B?eUt1NnVWaDhKSWhHUFVieXZGejh3ak0xRjRJUEZqTWoyS1hZOW1OZVdMTVNo?=
 =?utf-8?B?NmRJWjhDczh6eEhUU1Nic0xYKzRPb0dRNHp0bytsQlZvcm5hd2l5TUhiR2l5?=
 =?utf-8?B?dVpaRnRpSG1KVllhNWVIZTRGcmZRbHRvNHNpcFRraEJyMVg2dEsra0t1aXJK?=
 =?utf-8?B?S1A3Vk9sTGpQc0NyWVArME1Xc1ZzNXR1N3hlTjNqc2dnOTVDb3BVemZLTHZH?=
 =?utf-8?B?cjcyZmlONDlydkV5djlFRmxKc2lINlpiSTE2eGl1aEk3TFlNN29kVHNjaEJn?=
 =?utf-8?B?anIzSnRiZS9iQzZQNTkyL041aDgxa05vQkZEcHdqSG1NN0hyUjJ5QnpxMHBq?=
 =?utf-8?B?YU1rbmVRanVVZERQUlIxU3ZGazBPNkVzS1VOK2YxNWFFNm5ldUVjZ3dZNHk4?=
 =?utf-8?B?ZEswUC9wb2RkSE5OUU52L0ZCbHE5dHFwSUp3cElobmFsQ3c4Ry9DZU5IaGFu?=
 =?utf-8?B?cVpHdTJLbzVTL2tCNmttMk1meXRhbExsM1FvSE4wY2piMXFhNFMyK2o3ZWE1?=
 =?utf-8?B?VDhRU0dralBXeEpzQzVTRkU1Q0hhb0N0aFByaWY2azFRb09ydDRBQmxyb1E3?=
 =?utf-8?B?ME90dXRNb0tRN05GUHRLbTZvZExRa1lkSnFQT0d5VTVPdEFhQ2ZjeWo3SXNj?=
 =?utf-8?B?ZnMvUzZWRzc5bEpEcUViYjlIOGJtT29uVTBpY3BHREFVdXZzTFVCYjZrSDRC?=
 =?utf-8?B?WFczR1RHQXBnVDlKKzZCWVZoZXJnZHlOMXdoUEh2NExtWW0zb1lYRkU2cDlV?=
 =?utf-8?B?Q1lYQldoMzgxZEJJTjdubFhWditXc1QycHlib3lTZkdPZkErSUkvbXR1Slg1?=
 =?utf-8?B?d2dMYUFHbU5acW9lQ2RGeUNSRmZZcEhHQ09KREo2NXl2OTc4N1phdHNsNE9W?=
 =?utf-8?B?SHhKT1ZucENTaVNVcU54N1I3eHJHQ0IrQUxMaFQwZzhUSDZ3NkJEUTRTQ2hE?=
 =?utf-8?B?Ui9KWGZLUHB4L0ZQRHArRGNYcngxNHZBUUptWU1kaTB1aU83amtjNkhBbnR6?=
 =?utf-8?B?R0RlWXVUYTR6ZHdlMEV1ZHVSa2hEbzJNZlRFZmtPZ3c3MUtINmZFZjZ3Rk10?=
 =?utf-8?B?cExSeWtKTnZ6K3dBT2lMaVl1VUlwYVU0bURmUUxmSE1ub1plbDFEY3FlRmNk?=
 =?utf-8?B?Vm1BTHRMV2tERHpyUGNZblVVMDNvbm1JMUI0ZnNxQ2srVWdoOUVUK25DZzlG?=
 =?utf-8?B?dEJPUTVHaUpBQkI5UUs1RTNQcmdSZHQ4VzlOcUEveVczL3NCWHV5T1VNWEJP?=
 =?utf-8?B?SmVkcEdWU2dNVGRxd05vbk5JVDJpU0MwbU0wSzNBaVk1T3VnOENUa0QxOGJj?=
 =?utf-8?B?eHlnMlp5eFkzTHRyTDQrRDY4aXhtTmhvVnBuYWZEcjJta0QyL0JtWlZMVFVJ?=
 =?utf-8?Q?NJwN7WFJ74W6vn7zMAuT63htC?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <0730C0C4D0B03A4BA2046162E794992C@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 45f7172d-b4a8-4bd8-bacd-08dbfc86a5e1
X-MS-Exchange-CrossTenant-originalarrivaltime: 14 Dec 2023 09:25:44.1557
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: FeNrZKKdFTrPa51ADkiK/FX6XuH13bjP5yzaUj6sk+20SX58uWu0MLrddRiLy8LAPsVT4fAcJLHrxN+TbveXtOuJFcaVydxdhzK21Ks0Cuw=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MR1P264MB2883
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector2 header.b=UsGmsXSd;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::60d as permitted
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
> KMSAN expects functions __mem{set,cpy,move} so add aliases pointing to
> the respective functions.
>=20
> Disable use of architecture specific memset{16,32,64} to ensure that
> metadata is correctly updated and strn{cpy,cmp} and mem{chr,cmp} which
> are implemented in assembly and therefore cannot be instrumented to
> propagate/check metadata.
>=20
> Alias calls to mem{set,cpy,move} to __msan_mem{set,cpy,move} in
> instrumented code to correctly propagate metadata.
>=20
> Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
> ---
>   arch/powerpc/include/asm/kmsan.h               |  7 +++++++
>   arch/powerpc/include/asm/string.h              | 18 ++++++++++++++++--
>   arch/powerpc/lib/Makefile                      |  2 ++
>   arch/powerpc/lib/mem_64.S                      |  5 ++++-
>   arch/powerpc/lib/memcpy_64.S                   |  2 ++
>   .../selftests/powerpc/copyloops/asm/kmsan.h    |  0
>   .../selftests/powerpc/copyloops/linux/export.h |  1 +
>   7 files changed, 32 insertions(+), 3 deletions(-)
>   create mode 100644 tools/testing/selftests/powerpc/copyloops/asm/kmsan.=
h
>=20
> diff --git a/arch/powerpc/include/asm/kmsan.h b/arch/powerpc/include/asm/=
kmsan.h
> index bc84f6ff2ee9..fc59dc24e170 100644
> --- a/arch/powerpc/include/asm/kmsan.h
> +++ b/arch/powerpc/include/asm/kmsan.h
> @@ -7,6 +7,13 @@
>   #ifndef _ASM_POWERPC_KMSAN_H
>   #define _ASM_POWERPC_KMSAN_H
>  =20
> +#ifdef CONFIG_KMSAN
> +#define EXPORT_SYMBOL_KMSAN(fn) SYM_FUNC_ALIAS(__##fn, fn) \
> +				EXPORT_SYMBOL(__##fn)
> +#else
> +#define EXPORT_SYMBOL_KMSAN(fn)
> +#endif
> +
>   #ifndef __ASSEMBLY__
>   #ifndef MODULE
>  =20
> diff --git a/arch/powerpc/include/asm/string.h b/arch/powerpc/include/asm=
/string.h
> index 60ba22770f51..412626ce619b 100644
> --- a/arch/powerpc/include/asm/string.h
> +++ b/arch/powerpc/include/asm/string.h
> @@ -4,7 +4,7 @@
>  =20
>   #ifdef __KERNEL__
>  =20
> -#ifndef CONFIG_KASAN
> +#if !defined(CONFIG_KASAN) && !defined(CONFIG_KMSAN)
>   #define __HAVE_ARCH_STRNCPY
>   #define __HAVE_ARCH_STRNCMP
>   #define __HAVE_ARCH_MEMCHR
> @@ -56,8 +56,22 @@ void *__memmove(void *to, const void *from, __kernel_s=
ize_t n);
>   #endif /* CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX */
>   #endif /* CONFIG_KASAN */
>  =20
> +#ifdef CONFIG_KMSAN
> +
> +void *__memset(void *s, int c, __kernel_size_t count);
> +void *__memcpy(void *to, const void *from, __kernel_size_t n);
> +void *__memmove(void *to, const void *from, __kernel_size_t n);
> +

The same is done for KASAN, can't you reuse it ?

> +#ifdef __SANITIZE_MEMORY__
> +#include <linux/kmsan_string.h>
> +#define memset __msan_memset
> +#define memcpy __msan_memcpy
> +#define memmove __msan_memmove
> +#endif

Will that work as you wish ?
What about the calls to memset() or memcpy() emited directly by GCC ?

> +#endif /* CONFIG_KMSAN */
> +
>   #ifdef CONFIG_PPC64
> -#ifndef CONFIG_KASAN
> +#if !defined(CONFIG_KASAN) && !defined(CONFIG_KMSAN)
>   #define __HAVE_ARCH_MEMSET32
>   #define __HAVE_ARCH_MEMSET64
>  =20
> diff --git a/arch/powerpc/lib/Makefile b/arch/powerpc/lib/Makefile
> index 51ad0397c17a..fc3ea3eebbd6 100644
> --- a/arch/powerpc/lib/Makefile
> +++ b/arch/powerpc/lib/Makefile
> @@ -32,9 +32,11 @@ obj-y +=3D code-patching.o feature-fixups.o pmem.o
>   obj-$(CONFIG_CODE_PATCHING_SELFTEST) +=3D test-code-patching.o
>  =20
>   ifndef CONFIG_KASAN
> +ifndef CONFIG_KMSAN
>   obj-y	+=3D	string.o memcmp_$(BITS).o
>   obj-$(CONFIG_PPC32)	+=3D strlen_32.o
>   endif
> +endif
>  =20
>   obj-$(CONFIG_PPC32)	+=3D div64.o copy_32.o crtsavres.o
>  =20
> diff --git a/arch/powerpc/lib/mem_64.S b/arch/powerpc/lib/mem_64.S
> index 6fd06cd20faa..a55f2fac49b3 100644
> --- a/arch/powerpc/lib/mem_64.S
> +++ b/arch/powerpc/lib/mem_64.S
> @@ -9,8 +9,9 @@
>   #include <asm/errno.h>
>   #include <asm/ppc_asm.h>
>   #include <asm/kasan.h>
> +#include <asm/kmsan.h>
>  =20
> -#ifndef CONFIG_KASAN
> +#if !defined(CONFIG_KASAN) && !defined(CONFIG_KMSAN)
>   _GLOBAL(__memset16)
>   	rlwimi	r4,r4,16,0,15
>   	/* fall through */
> @@ -96,6 +97,7 @@ _GLOBAL_KASAN(memset)
>   	blr
>   EXPORT_SYMBOL(memset)
>   EXPORT_SYMBOL_KASAN(memset)
> +EXPORT_SYMBOL_KMSAN(memset)
>  =20
>   _GLOBAL_TOC_KASAN(memmove)
>   	cmplw	0,r3,r4
> @@ -140,3 +142,4 @@ _GLOBAL(backwards_memcpy)
>   	b	1b
>   EXPORT_SYMBOL(memmove)
>   EXPORT_SYMBOL_KASAN(memmove)
> +EXPORT_SYMBOL_KMSAN(memmove)
> diff --git a/arch/powerpc/lib/memcpy_64.S b/arch/powerpc/lib/memcpy_64.S
> index b5a67e20143f..1657861618cc 100644
> --- a/arch/powerpc/lib/memcpy_64.S
> +++ b/arch/powerpc/lib/memcpy_64.S
> @@ -8,6 +8,7 @@
>   #include <asm/asm-compat.h>
>   #include <asm/feature-fixups.h>
>   #include <asm/kasan.h>
> +#include <asm/kmsan.h>
>  =20
>   #ifndef SELFTEST_CASE
>   /* For big-endian, 0 =3D=3D most CPUs, 1 =3D=3D POWER6, 2 =3D=3D Cell *=
/
> @@ -228,3 +229,4 @@ END_FTR_SECTION_IFCLR(CPU_FTR_UNALIGNED_LD_STD)
>   #endif
>   EXPORT_SYMBOL(memcpy)
>   EXPORT_SYMBOL_KASAN(memcpy)
> +EXPORT_SYMBOL_KMSAN(memcpy)
> diff --git a/tools/testing/selftests/powerpc/copyloops/asm/kmsan.h b/tool=
s/testing/selftests/powerpc/copyloops/asm/kmsan.h
> new file mode 100644
> index 000000000000..e69de29bb2d1
> diff --git a/tools/testing/selftests/powerpc/copyloops/linux/export.h b/t=
ools/testing/selftests/powerpc/copyloops/linux/export.h
> index e6b80d5fbd14..6379624bbf9b 100644
> --- a/tools/testing/selftests/powerpc/copyloops/linux/export.h
> +++ b/tools/testing/selftests/powerpc/copyloops/linux/export.h
> @@ -2,3 +2,4 @@
>   #define EXPORT_SYMBOL(x)
>   #define EXPORT_SYMBOL_GPL(x)
>   #define EXPORT_SYMBOL_KASAN(x)
> +#define EXPORT_SYMBOL_KMSAN(x)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2f35548a-bdbd-4c37-8f60-cebeb381a7af%40csgroup.eu.
