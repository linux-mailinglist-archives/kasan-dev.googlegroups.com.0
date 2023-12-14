Return-Path: <kasan-dev+bncBDLKPY4HVQKBBZH75KVQMGQEG6EYRUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 08042812A91
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 09:42:14 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-6d265c1d8e8sf166716b3a.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:42:13 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1702543332; cv=pass;
        d=google.com; s=arc-20160816;
        b=sCGXAs6/UjIX7iLsq7Chw2ldezq0XwUTugaQH1oLK9faE2GygnWPiAw/NZmtiQ6m2q
         /fArxWKRcU+AFO1nnB6QY826a6PtnlzmRzasfHqwrr+hxWH2ac5WavPE0/luDNUOrtrH
         akoMTLK5NfsB7hwBykufwUSVArdRVpEK2TAS7SYt7+ML1LqvaJlLHRSRKW8kXIjgksu/
         cDIt6ip0prJai+Vl2XUYCURGAfSnMMC/+AiwWdbrxMzACJlkO71EZn/w+WpTjwh5v93x
         ra+UlIKX0mpgiWkFqzwM+gkrLt6+Dco+Ug6wpQo9FSibG+HlOIRi8RSBkgXo+X1943or
         9yqQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=29pKOkiHHoNAvfeb7s5QiXRCcdZChjaDdzvbkZqKJ1Q=;
        fh=RrZ19OfX14okVFSSNQSI4Ydw+VahiAISsipj6KSVYuQ=;
        b=AWmTS4jD8lNJEyDUvlzOStlly4JOk3NvKpseIUHIH5yfvDZlsn7kl9IU59/BPeWF1X
         Cb1uTVFsEAirhdDE8Cr9cyhpR8Xe2iVCjy9xzQc7YAsQh/CmnKuVdjI7mkgGMZ7NXYSB
         b6dNJ706W2k44BlVcn2V3PWMGtuJx1sJqqEvX2xjFpMSXsGdQCr/RlO2bZ35MMIcG8kX
         JjVyHQHzQvJM59sT0l128L49yfRdVSfaQUEgb44RVqPFEf5MqPhUxZaanjt3X0ekpjaN
         +Bi1uP1+tIF1ri/4u/et7tVdQA8MLUvZ+c0a7Co8wY7GOcpwW5BXgec2fekzS5a1JEZ+
         rv6g==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=XXmxVduq;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::615 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702543332; x=1703148132; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=29pKOkiHHoNAvfeb7s5QiXRCcdZChjaDdzvbkZqKJ1Q=;
        b=ZONzfr12/pKR2GYvTgge39OYBZ6DQWWCaxQsJG5ZWOmOuxyjiVNtpj3S6yS4BcQt/7
         GxEBFiqrSJksi942UidsEaonIMfk6y1V0vMk4v7mPcMImVp1lY8z8OzvxSuxpTzIjOOc
         AS2tY/7A0vnFhouTGCwfucwy/Hnv2TcvRt+t1t0GlEo7/VGZiMbl9CEg+0gnUAmCxBlf
         GgXUa5b745NPIexbch14zXYcRg50Hk9b2BXV0yqgC3reC3DPEPHkwxReJ2OsaUgtEX8r
         iXJon52SNE+0vOdir2CKUOA108HI71xrOxdB6GxLUcPbV7q7hFcYpcDuwrjXvZxXpZ6i
         VIWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702543332; x=1703148132;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=29pKOkiHHoNAvfeb7s5QiXRCcdZChjaDdzvbkZqKJ1Q=;
        b=p+qeXQqqy4dkfTPwNToEKAwDaIAbCAUigEj26uWiwjO4aflDVcXhcoL7eG8ry3E3D0
         yxShI1Do0EMyQ7ZzL1lYaWJa89ma21CEBTr8ZzTxSS54UArPKGqp0KPWj5aFr7q0kNAF
         S3EeFVel3JnzyYSVvs7KjPsZslEfnbO5ngTwwB+ojHB48t7TKnMOr1diMOUrU1LxXcCp
         pPft5t6YLvS7QPW+o6wC8YMapE4B/iVGQIJT7iz1wWaCdwcRm3kxGeY/FyLRu61aVPNa
         pRH6zHzufkhtK7Hi8b3IpoWwHujwF2U60GPtODx1VRdYU+PnZ1MAKepkGbecEmvTddK5
         JW5Q==
X-Gm-Message-State: AOJu0YydxJ6ZyjrUUOvNLM5VNmk2R+XvG8Co+NTk/7tn5raDBS04AMuk
	ALp/4CgFrrKUh8UGdoKe8H4=
X-Google-Smtp-Source: AGHT+IFeePAna023cAgusMFI8m7DHMKXi72K5HSkjhf3gTs4AOPm8oT6cZH7Ty7/ggmNdAuTxjMx2w==
X-Received: by 2002:a05:6a00:2451:b0:6ce:4010:d206 with SMTP id d17-20020a056a00245100b006ce4010d206mr4738484pfj.20.1702543332315;
        Thu, 14 Dec 2023 00:42:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:b8e:b0:6cb:76bd:cb70 with SMTP id
 g14-20020a056a000b8e00b006cb76bdcb70ls3633021pfj.0.-pod-prod-01-us; Thu, 14
 Dec 2023 00:42:11 -0800 (PST)
X-Received: by 2002:a05:6a20:9782:b0:187:dd5f:93b9 with SMTP id hx2-20020a056a20978200b00187dd5f93b9mr4134258pzc.14.1702543331304;
        Thu, 14 Dec 2023 00:42:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702543331; cv=pass;
        d=google.com; s=arc-20160816;
        b=ERvnTSt9HWKd6bUJiLbMidfsqI5PKniZW59ws86NL58K+SCsdCbirk9BjyI2tQCtbg
         vSippbBEHnalTbvHXd72ccGmEQWYdXlqgd+wjRcgIiyROWvrvPR7SLCDvhWaGYi5ueBR
         FzTt7XOS7uxLQaAAGFJnm6O38Sy31EKW2T5+3+V1icXTE99J21DYETz5J49iqGYHteVm
         fN0ybEBYh+qns14hoUV3HUXfCNThV79FZi8xU1V7r+IfWMiErcUfKyQDr1JFVBRDwwV2
         9kyC8mLMSWDTcBDmWl5fmdCaQqf+yJTutMgDIwKSwIdMVSKK/LwOvdgCdJMXkNuFQFZG
         s11Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=bOBftX54unTZAXgBMVOuXlqf2REtbmWB6W31i13K4dw=;
        fh=RrZ19OfX14okVFSSNQSI4Ydw+VahiAISsipj6KSVYuQ=;
        b=tUBJ67PIXrNKFn0rSli3ZstW0WdN0g42176Q1dxAthThso7MG37LdEF2a7AhZrzQgZ
         jbZiNmQgI3QMHn4JPkfDKjmwoOYfbQCVnPVYbdcXOBHSwQGSgfUQbCG87GQuCJrIoaM9
         MLh6P1Lcjjk0HJuPZyS6tu6HId8GqdvnogaKc8SWW6z8IQTZAzVF+Ud8TLBoHkk8aLdx
         Z60REaC8t9vpA8wVOG9XB9PBYQ3eQoWu4de4cb9J4dq++8Ny0Cm6xZP2C1ka7mXH3i1S
         ZyoimqCttbL+OUwiZnomezkYfAJvoTFSVSHanTVRBc/iax7gfyGZyJLIG9BV6MT2fe94
         Xkdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector2 header.b=XXmxVduq;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::615 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-mr2fra01on20615.outbound.protection.outlook.com. [2a01:111:f400:7e19::615])
        by gmr-mx.google.com with ESMTPS id j4-20020a17090276c400b001d0855af27csi818728plt.1.2023.12.14.00.42.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Dec 2023 00:42:11 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::615 as permitted sender) client-ip=2a01:111:f400:7e19::615;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=VY6pXp+aeWgWZcwlr3YqGidrjA4WPdg9hOMf/gqBIJkjEUMUS/joOPEqo7Smk8j0i6RdDZlOifUP1lBb4QDrRrVIBJq8yZnh6yAMoA692K8dqj2frx5ZfaBovNOabJDnVlZerSGcIKu4eXvXCm1t5CBOwGkVhhY7IC9PjpQbvcNDwKLUEb5GBP20FYItvRj0dL1EHOxDWkLRnuJBudPT1gBiTlIKj59wfHFSRCHVlfTi+de9r8OXaDlD/GRFpft+wjOlvvkaBMUaiU5RBEmGs5fjqL8iJi64LaFZuFvqyz51hbi/rqiqPkBTda7HjOa0A6tVjKPV7K4t9UdxeDwxBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=bOBftX54unTZAXgBMVOuXlqf2REtbmWB6W31i13K4dw=;
 b=CsFvUu+uv2ANJnOirAt5UMbuJOkeJO151iwS42erqSfZD2YM7H/Tp8xSFNGdX6ESDbGtp1E0zFtaUqziUt1Y+qSbosmNEh8+unKnNVDusK4z8VZk9bG2M2vGbNMpah0PQLuzg9N5/e71zDuoT5UXlelIYvO7Ht/DSkSvzBUxczTHqvga+mS+oHGMVxxLdOyGE4b430MLr984HUXdTCArnrR7TlsZjYVokTBVdX+XINQqaEvy5RPrxlz9dz5wpfR6mtqFw9X2nvbDCtvfLaGlBg1oJz20xpl2UIpgDy1+oUogExVMIqXLGle02QNUERrEcem7gJ4n6aWpEtVUKIvEXQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by PR0P264MB3353.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:110::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7091.28; Thu, 14 Dec
 2023 08:42:07 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::f788:32b4:1c5e:f264]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::f788:32b4:1c5e:f264%7]) with mapi id 15.20.7091.028; Thu, 14 Dec 2023
 08:42:06 +0000
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
Subject: Re: [PATCH 04/13] powerpc: Disable CONFIG_DCACHE_WORD_ACCESS when
 KMSAN is enabled
Thread-Topic: [PATCH 04/13] powerpc: Disable CONFIG_DCACHE_WORD_ACCESS when
 KMSAN is enabled
Thread-Index: AQHaLlJI6LSmE5V5qk+oa6hKFZGaxrCodi+A
Date: Thu, 14 Dec 2023 08:42:06 +0000
Message-ID: <1f3b22d4-00b3-4ff9-b29b-a901c03988e3@csgroup.eu>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
 <20231214055539.9420-5-nicholas@linux.ibm.com>
In-Reply-To: <20231214055539.9420-5-nicholas@linux.ibm.com>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla Thunderbird
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|PR0P264MB3353:EE_
x-ms-office365-filtering-correlation-id: a0787351-02a9-4ed7-fcde-08dbfc808de3
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: x0Bc7+krDRkjLqVAe63sv0nmryxan3HPJ7h5tjy0pCIL3fm76ZJ0MD7LWzzvDLY8oe+L5Hz+gzRt+JbtUOeQYEuo/e8BdqYCHACA67U46xHvfPOgesBuW9Cxm/r8kVVH9V6XwPr8sH2JWZ9D6P55mNZUbBLOXBDV3RCWZU6kF6lmQzd+SXPnroXHkv7MqPM4uayOQNelHKe3Dl4qQv+FS0MmCemOy4NHEI6rXs8qKQugRRIibng/jJ7oaIBtFMF5sHZnEuBVHqyrouEKddBHqIvSg7titK6doOxm1t74FS5B8W3u4uJv1vy0Qzjhorh3YfyGU9dJJ5z4mCRnTA5m68hOPTQ6CAvJZrxpdDLEu9WxINWLnQm0ivCYemn8iOv3s13UczPbDrM91wy3JvyNzkdHfejwPD0KrmqTWQ/tLrA8mohF96WpBPucpiOxZshFzSzZkBcnO65ie3Hux42f/bfEVM7nDbQibkzPTB8V13lzDDpf4FX9xdK6UGEoqWAildtve/jX0nDKkUA63kbaZTojyl02SCVX56S1Nch4LPV774OnMp842NIZt63ahG7jwkbw49Y2u/+xc4+kRs5Ngrr4bXOr9o+MWPl+uVgdKP0cTcn7y1TlwjKwN5paIIkuLk5ZoXszWlMuTNFgKXgMBRY62w9iu1DcDkMg5Q6Fz3Srd6LZFE9rAxnoGRGJWcGd
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230031)(396003)(136003)(366004)(376002)(39850400004)(346002)(230922051799003)(451199024)(64100799003)(186009)(1800799012)(31686004)(26005)(66574015)(6506007)(2616005)(36756003)(38070700009)(31696002)(86362001)(38100700002)(122000001)(6512007)(4326008)(83380400001)(5660300002)(44832011)(7416002)(71200400001)(76116006)(91956017)(2906002)(66946007)(110136005)(8936002)(64756008)(54906003)(66556008)(66476007)(66446008)(316002)(41300700001)(8676002)(478600001)(6486002)(43740500002)(45980500001);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?d1c2N0tWSW1CME53TFRKQVB1bXk5YXpiYmZEbzg4SGYzZTR4TTJtU3N3TXpT?=
 =?utf-8?B?SmkrdXZza2VFU0JzclJRUHU2cTlYNWZpVmFYNlN4bWtaZGF6MEtaQnlDSS9k?=
 =?utf-8?B?MHo3d1V0SGJ0c3RLNUtYdFpvaU45dmd2UUNzVW1MSjRMMGtFcFAybythQWxa?=
 =?utf-8?B?RHUwckdQZ1k3NC9VaGhSeEhCZzNKZTNJZTZTYlJseFM1MFJLL2RhblJ3VG1h?=
 =?utf-8?B?dkI1WXprb08zN3NBMU1NV2ZLbjE3b0ZIZGRxaGpkNU8zNnVvaU5CVUUrRlZG?=
 =?utf-8?B?QURQUkI1UU9xaVJ0NmdmaWFFb1FwRVFaSUZrZEttbnFTQTZzRFJ1WFVwZEZX?=
 =?utf-8?B?L0V2KzM3QTIxNWUyK1pZb3RPK3BFYjFSdTcwMStkVnVyTjgwRVNZMXdhV2ho?=
 =?utf-8?B?MDJPWkk4Vm5FOEpOT1kvQnZQT3ZSRE9Ca0pYSFFGa0c4M1l0SkVFL0hPMTN3?=
 =?utf-8?B?WUJYbmgzdGFWMnljUXJtTThTSDIrZ2h3RWY2aDFmZ011RkFRTEh2dndkaUc3?=
 =?utf-8?B?eUZqMHR5N0FHem12RUZ5a2VzM2FpOEVkcnVwcEVyUG5jTDRJSm1TOU84L0xG?=
 =?utf-8?B?YlpsT2RWUndkNERFNXM0STdEY0xoTkswaTVUUTZOcWVrMGMyM2N4bTA2NmRa?=
 =?utf-8?B?MENnZEl5Nk9TODFwVVdacEJDWHdBOUJrYlJoZm04OTI5K01GekVVNGxiYTF5?=
 =?utf-8?B?RG9iR0tzaFZCelAyTjc5WlNuYlVaa2o2Zncxenk4SzRJRGUvZDFMSGZFSTQ5?=
 =?utf-8?B?OEpIZ0tXNS9LcnRWTitBaXZtUExLRm9wdkltU0J4QW5CcGxLZ3psc1V5SVRl?=
 =?utf-8?B?MEJLVHhhUUE5cm5FSXVFb2FicXlrVlRNODJLM0FERU9JRDM2cis5dXNQOHRX?=
 =?utf-8?B?WVdMa2lnbTZBR0VKU25CUG5XN0grUFk3V1pwNVFrOWNaY2oyUDlLeDI5dmJY?=
 =?utf-8?B?OUFJWW53QVN3Z2NnOTFvQnVkNnNEMU1kZmpvNXdJR3Bwais2ZWdrMkFmMVVi?=
 =?utf-8?B?L1lBNFhDSTR6T1EramNBS3puMk1qZWNsQlBmYklzZHdhck5UYWVrS2Y0UHcz?=
 =?utf-8?B?dDB2Uk9PZ3l2WnprZlFJcm9jd2FpSmRWV3ZDSmZaQTA5aThpYlEyOE80Q0VS?=
 =?utf-8?B?dnFhdVdBQjVpTjV3bDZ0d2tJUi91aktYQm5CK3F2bDRVVmQ0V3VLcWRjWmQx?=
 =?utf-8?B?bDlNazNVYzByTVlKbXRXcExaMDRjc1dMTE1STmh3cktVL0tyMlYzSE95RHVk?=
 =?utf-8?B?cFA4VFNjL2lQaUwxeFdPYzhsN1kwNHFWUkQyU3RnMGFJM3VGbWZGR2h2RmVa?=
 =?utf-8?B?amZLbGJyWjNQS3l1OEZWK0tMRVpPaDBUOHpPL0l2QUpDOVJjOFc1QW5VOW84?=
 =?utf-8?B?SU9UREtXM05CeWV3ZWt0R0hEYUJobTBZVXllK25UYXZVb0lzeGVtZVg3a3hS?=
 =?utf-8?B?Z0syb1hiY05LdU5Oa2ZvKzBuTE9yRnNTV3JpLyt3T3U4Q0ZqNnNPUHhldWxI?=
 =?utf-8?B?TmREVWV6aWxUV3d5RzNEaG1wZzcyZmlkVU5FaE0zNUNhMFBsdmtBU2UrbTQ3?=
 =?utf-8?B?VklUaGVrRGxFbFErMzdsUlpSUW1pWnhYWkdWSThJNDZtd1JpY0doU1pmSEpF?=
 =?utf-8?B?R29yNm1RbWRyYS9jK2diVS9LeFZyMGY0OHlHUTFra2FLY2dIRXBJd0w1SVg3?=
 =?utf-8?B?U01pSjdkQUtOeTYyVkM2NlVaWWR6L09GZGZOWlF4WlRLL0tiZGo1WlVrQ05R?=
 =?utf-8?B?RUwyS0hORmo4OTc5UGFvUlFkNFpsbkFCRGhqVjZSSjVKSXpOUEt4UW45TUxh?=
 =?utf-8?B?UEorY2k3eHZkSzk4RDJxVEkrZUhSczk5S3dqakpHdTh3Mmt2UVlxaU82T291?=
 =?utf-8?B?d1p4REp3VTdtUUQ1ZlRXQ1A5T3d2RGp2dW1lTHE0UFhFUVo2czU3K0NYd1N0?=
 =?utf-8?B?cDlpbUFsOHp4STlYYjYyVkdNM1ZjMU01RDkxQ0F6TDMyUTNMc21DdGNQcVBt?=
 =?utf-8?B?YWpmTmNvQy9oN28rb2FFTDFSK203RjBDNDZoNU1rZDc2L3VRbys5ZkRIVU9t?=
 =?utf-8?B?cnRDenR2bTkrejB1MEJ6OWUyL2tNa3NNNmFFR1lyWWppL29xRTV4bDB5Z0p6?=
 =?utf-8?B?bElQNW82eWVXck5yKzgvZlJMOFpaSS84R2NzVU5qdWxqMEI5ZnF4ZVpCdHl1?=
 =?utf-8?B?RGc9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <A7DE56272EF88841A21E4624DEEC8060@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: a0787351-02a9-4ed7-fcde-08dbfc808de3
X-MS-Exchange-CrossTenant-originalarrivaltime: 14 Dec 2023 08:42:06.8995
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: LqglYRFHhNzM5li4Bb6jl8ocPxE4K4R/Zmqolu4NZi5FfObH/QgjVGfeqvTifWDbRoSrVGxqCNsILT7LwPPc8po47O65WWdcmnNQVFhixqw=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PR0P264MB3353
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector2 header.b=XXmxVduq;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::615 as permitted
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
> Word sized accesses may read uninitialized data when optimizing loads.
> Disable this optimization when KMSAN is enabled to prevent false
> positives.
>=20
> Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
> ---
>   arch/powerpc/Kconfig | 2 +-
>   1 file changed, 1 insertion(+), 1 deletion(-)
>=20
> diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
> index 6f105ee4f3cf..e33e3250c478 100644
> --- a/arch/powerpc/Kconfig
> +++ b/arch/powerpc/Kconfig
> @@ -182,7 +182,7 @@ config PPC
>   	select BUILDTIME_TABLE_SORT
>   	select CLONE_BACKWARDS
>   	select CPUMASK_OFFSTACK			if NR_CPUS >=3D 8192
> -	select DCACHE_WORD_ACCESS		if PPC64 && CPU_LITTLE_ENDIAN
> +	select DCACHE_WORD_ACCESS		if PPC64 && CPU_LITTLE_ENDIAN && !KMSAN
>   	select DMA_OPS_BYPASS			if PPC64
>   	select DMA_OPS				if PPC64
>   	select DYNAMIC_FTRACE			if FUNCTION_TRACER


Seems like all archs do this. Maybe a better approach would be to define=20
a HAVE_DCACHE_WORD_ACCESS that is selected by arches, and then the core=20
part select DCACHE_WORD_ACCESS when HAVE_DCACHE_WORD_ACCESS && !KMSAN

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1f3b22d4-00b3-4ff9-b29b-a901c03988e3%40csgroup.eu.
