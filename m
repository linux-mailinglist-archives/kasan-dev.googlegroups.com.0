Return-Path: <kasan-dev+bncBAABBJHZ3DGAMGQEO7JVWTY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id peA3F6c8lmkycwIAu9opvQ
	(envelope-from <kasan-dev+bncBAABBJHZ3DGAMGQEO7JVWTY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Feb 2026 23:26:47 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id B9BF015A9E8
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Feb 2026 23:26:46 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-2aae3810558sf2600145ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Feb 2026 14:26:46 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1771453605; cv=pass;
        d=google.com; s=arc-20240605;
        b=EtAp1U8UtS1xW3509PI4l9z2nZeWo4QeW1xFMPjop4yscs+5vZhIsygiksr7ou07fF
         kPaJ1jzujlbz6nQY7AYeVJNv1QRVOd9W6W1M7VWvBnIyoPXGEnOb8bWKHGrIHvAGf7oU
         kzXOWlZvXsDDY7ZL7oO6fxZ0SSsLbWYmuZPB6o77XS2j4SDXasduFFIP40S3joPCf8WB
         Y3NIG28k7wfc3noJOwITYPptp8Ebndx4x6s8ckNAXl63sw2XEpEfqqcpgnyulcFe8/QU
         nJPaZc+/JK9taJGmFwymBBwcDaJw3dhBWkF2k1fpZecJG2+1GDXjS12xW8VfycrtSAo3
         npvA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :to:from:sender:dkim-signature;
        bh=AwvjeRHTo5SxO4yfzWqyN3BGdJksET8+B3Kj3wtAQmM=;
        fh=x94x59ar2pu3+fY5QDPdyBephtPhah1z0kK54Wvue1k=;
        b=SzBSqsbZM2XNLvXmCTo0KWHK9BkVju1DanooFbXtXJA3aRTm3+bkXbR0ZjqKTzyLIq
         7cgfblOtaED6SJ+Xc1bEsRrrlwp2yW2UJ971B0UelFWUQfeJ/MYxu2poepHyGp4oSCbh
         TX6DgpcpXizL7qnfqNfUe39ze3q0+3+PdpVpt38T36b+lDNF1hkv3sgjGZP7ReOkJLOq
         y5wD56mBjwUXu21ogUwxKvqEdfHgsgzY6UOytLRkNx49Ru45WyLmwwl/CkmPbhFOzD9f
         r6Y9OHpHbbllj/+uIq/KuZ8I9qG3+RTI5EvJ2SFNTzDOeWiFOyuQV2GzwtUtK2XycY7k
         LJkg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@hotmail.com header.s=selector1 header.b=ujUAp9bs;
       arc=pass (i=1);
       spf=pass (google.com: domain of whitsejaneth806@hotmail.com designates 2a01:111:f403:d200::1 as permitted sender) smtp.mailfrom=whitsejaneth806@hotmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771453605; x=1772058405; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-language:accept-language
         :message-id:date:thread-index:thread-topic:subject:to:from:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AwvjeRHTo5SxO4yfzWqyN3BGdJksET8+B3Kj3wtAQmM=;
        b=GpJeAigD51dEweyUzccz7VtZaYGQ34h2sF6m0d4v3qbXb1FWEtPRy8Dsv+/G6GGm/H
         rl6evzV5arADw+FqdlmmdKoLT0QALBmNEnaDIQY3aBn+s4jyJLDlCHuq3GkEHoe9wktZ
         0k+HrEFzZy30PtlSw+ZvaG+ZCgv9s2MuEcGAw23tt1g06IKxq/X9kSeQwR8FDAh4OKM+
         Vs4zzXTIhO+WyQjc06EIKufwBiYc34nkzBnUP1Askog01cUe4Y+F4be4y2b2pLyAQziD
         SqpDe/h6OYWGWlKzahXdhPHcwLBG9Qqp4qW9m0xtZYM0jHwhN8hBmX4M1jzIH7caRuyD
         PhMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771453605; x=1772058405;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:message-id:date:thread-index
         :thread-topic:subject:to:from:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AwvjeRHTo5SxO4yfzWqyN3BGdJksET8+B3Kj3wtAQmM=;
        b=AFuESufuG7JpCgwpUdoThzQVgHAl1aEjSpguPd3vX79aHH+X/jWrvXM/+iHfMe37tc
         MmifdzeYhS25qnZx03ynW7vS2RSWiWI5LCvgHrv5imlEOfBrqf0inM0TneOSAH0Fa1zN
         KRApb0hwXiGoIAYY6OKAdFe908EjIqG24hyo5O+AGmHOIZJAO3vX35ww+xJQJn3wGBy0
         javJf2jZCP4BIQxdQcDFsCtqVVG1i9F1v+sJzTGSU8CE4eqwxY6zNudCdtF9CF2WcCOT
         0A2vCk5PDVjYXR0qVhY/PdLpgXWPf+O7T7hvILEZjRFqJQTIZzC25NR5UhJY9GLZr5qe
         AxtA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCVPrt5e/ykF10cd0onHxV7mJivOa8nauuhIqlITMeNBQYWluJnFkumjqJJyDHo9N8yiOuQx3Q==@lfdr.de
X-Gm-Message-State: AOJu0Ywo89GKApT6OkValamd3ojV3MtTI6LGOWmFn6zpKKZTQSfs89r0
	M/J5UoTy+MjKyovjQ8D/UK4cnCV732w24NbFzLl9ll1wOl4j+WRA0AkV
X-Received: by 2002:a17:903:190d:b0:29e:c2de:4ad with SMTP id d9443c01a7336-2ad5b03d9eamr5799995ad.24.1771453604513;
        Wed, 18 Feb 2026 14:26:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FUhtAudESwLozRdkBWRJncPRSF9Rtmq+9W+wpsckTcMw=="
Received: by 2002:a17:902:8304:b0:295:68e4:74d5 with SMTP id
 d9443c01a7336-2ab3c2e0f96ls48159735ad.1.-pod-prod-01-us; Wed, 18 Feb 2026
 14:26:43 -0800 (PST)
X-Received: by 2002:a17:903:8c3:b0:2aa:e3da:52b5 with SMTP id d9443c01a7336-2ad5aed3f6amr4881415ad.9.1771453602908;
        Wed, 18 Feb 2026 14:26:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771453602; cv=pass;
        d=google.com; s=arc-20240605;
        b=GiKM8whvWVT+5sqtRVpCe4s2JZjG2/XI6JCnVJlZ/jPEqKk8TewkEDO0zGbFTWCfYf
         sx2bULZ3X5KHIwONKJijkGR3uLJ/5kOt8E2V3ctqlCvY48KNKjY55O/aPXUolfM+XeZR
         6ficpAfK824ZzpQlVTRVWLu7rLq+2rXvaDNezM4mJ/FjalUlvwiXVp7fCnaBw/4+kk1B
         ZiIu8QF97jDwGiNYaI5mj+IgkWmW6ICPK+DGItcf8YGiEfem/0mSfrEAA67UlMZMj/DB
         27QfxGGnId9QPLuFv1Q1VlK5I54a2EEd4WxTd6x3VulJeqvD2wSFIcQxTVnqVwHVyaL8
         EO+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-language:accept-language:message-id:date
         :disposition-notification-to:thread-index:thread-topic:subject:to
         :from:dkim-signature;
        bh=3vGaa027YKW/DmsKd6N0UQkMmVNxSySLl73hH+QLoJU=;
        fh=RYEHzHU/HAyeZBCO4E+IbnoHdOzcm1YWiVKtSJ7fCDU=;
        b=C2u4TPfYkQAR80pH2ZcHvyTbXjbu7SLMjomt4ClA2IecOxqZv/mIDkwjGPbVHaeYmz
         SoqkyPOKniN9NE9nH2Se+8y4aayWKaZszAYgQNZ8d2dNIgNIOS0PvQQMQaPNQKKZOXqw
         OJSRDQAkb6bL/+hem9k9bUDLxd752rh8OEJlPnjdcOP1tkuZa2XmcJJegvanAxSsu9V0
         cAHFps5AmN28tbteqpnKMiMcTav5itg/0hkM6VCwps5HxEMsdwsML9f2kb/dsmc2y4WK
         kTKd7KDx/nPpQEFw1vLD88x6J8oxLwfKJ4GcJ+CEq+3fXNyzsNqOlewHXZ0ezwUE3zuv
         rK/Q==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@hotmail.com header.s=selector1 header.b=ujUAp9bs;
       arc=pass (i=1);
       spf=pass (google.com: domain of whitsejaneth806@hotmail.com designates 2a01:111:f403:d200::1 as permitted sender) smtp.mailfrom=whitsejaneth806@hotmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hotmail.com
Received: from DU2PR03CU002.outbound.protection.outlook.com (mail-northeuropeazolkn190110001.outbound.protection.outlook.com. [2a01:111:f403:d200::1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2ad1a9ccd54si4785255ad.6.2026.02.18.14.26.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Feb 2026 14:26:42 -0800 (PST)
Received-SPF: pass (google.com: domain of whitsejaneth806@hotmail.com designates 2a01:111:f403:d200::1 as permitted sender) client-ip=2a01:111:f403:d200::1;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=SLIBPAyVQG5uRrJ8DMe51TzzDCYYYKaexDvfbsqIKTIA3FYmKdE2WiYykPh4W2yrXC399F5vixiIPgenTi2vxSrINCKwOSbZskdlNvXqG/YZr9eWm+KJEWlZ1S1iHd4ZwSwboA+5oR3+2kSU32Wjp9MOboUvQd5rlbq5MUWe1duZNDKLl1DXsP/xjVNJrxSeGAfigM2Odi6deT/hvVhw9j/TXrmz33PQlZN+dBKORe1PbuPzRW2ZS3nsI/TBCS+8pYKWOuRp2CCafdJvAxiQsiIjx/Z59CCCyuywquFRkEXcEjq4DajGLTctlAsY6uqR0G/R8QTNTMccV0Wz+6rHMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=3vGaa027YKW/DmsKd6N0UQkMmVNxSySLl73hH+QLoJU=;
 b=qN2qPYZG8OwyQaQfwGvHm7+16oMENrTXFwJKCDmJn/XX5WVcDl5kaVFFZMsTYAPLWTgPQlvWPUqtYSyict8cdGyj5Zs0zv03akUYSxuSLWTzUZbpSFpLkho5u9N8Ls8SORoUzGY+nFJ7LRkxxwh1i+Q/p5ccXvF7Kqw+rTWBRC+cLH8jWoXYawxEx9ZkQ6eKkPURIkctzYscpa6c/yipcETrKVqvknlC0SMOvzUgshWZb5IzSMHEcU0BC99vjK3SIIU2xnkZgzbExF3sOm8lR+xppSRkfPCEiGUValcX+FIt5JqI/o//HLGrEE+++8lmIfQa7wao1YmSc+Cx6CEtXA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from PAWP192MB2179.EURP192.PROD.OUTLOOK.COM (2603:10a6:102:358::13)
 by VI6PPFA9EBEF71C.EURP192.PROD.OUTLOOK.COM (2603:10a6:808:1::21b) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9611.10; Wed, 18 Feb
 2026 22:26:40 +0000
Received: from PAWP192MB2179.EURP192.PROD.OUTLOOK.COM
 ([fe80::474:8ab3:b947:5f2e]) by PAWP192MB2179.EURP192.PROD.OUTLOOK.COM
 ([fe80::474:8ab3:b947:5f2e%3]) with mapi id 15.20.9632.010; Wed, 18 Feb 2026
 22:26:40 +0000
From: Janeth Whitsett <whitsejaneth806@hotmail.com>
To: "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Piano to a Music Lover: Baby Grand Piano
Thread-Topic: Piano to a Music Lover: Baby Grand Piano
Thread-Index: AdyhJZ5KW6fqLqd1ThKBpAVCeIcSOQ==
Date: Wed, 18 Feb 2026 22:26:27 +0000
Message-ID: <PAWP192MB2179CD9E5CEC9853A58DE0E6F96AA@PAWP192MB2179.EURP192.PROD.OUTLOOK.COM>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PAWP192MB2179:EE_|VI6PPFA9EBEF71C:EE_
x-ms-office365-filtering-correlation-id: 1f0797e2-ed2a-453a-1fa6-08de6f3cc982
x-ms-exchange-slblob-mailprops: CLk2x5OX5VYv3c8Emt0jD2wdZaenNeU3FKdbLTNc4Xy5xX9aLTLlP7yLn+xWd/0hTm1SaIrgKZa3TlkcSN8QaARcIUX/234NHdmtEUb4Rs5tRXiujS8jBLAETAb8OL519/uWJMbg5HaED2GCGGYbK1z+uOVl+HiuS8dTD6nBCDQAN5hatflVG6ib9c8tXUs9qXgzeQvGg2IuF8ThW1Q/FHKOEuXYiRKJzDfnT6irDqgLM0rueqRSvmkeqN0YStERLBRuOPPXJDqHgfUPwHhrDxc1uxoEvQuSxmwjSRzcxdAkjE38h4lmA7gbgFBZql6cQTW6ZIc33n9sgR/s0BXXQQSd4ox/wKNxnC3+6KhUU1WQ9M0kcOIoT6AXDc+u7Q2F8uSL/cVXeiVV5E9YkYsB+RCY0GCgG5srRTa21asRRoYLSSrk6+mfAQgg64ns60HsXfCesFkBJxu1/HE2YYpRgybJePOqAQ4al/Eq8tDHih9aMPE9kwRVWxQX8faEdonBNrKQ072ryPZV3F5IeTC/cghZEHO5OWlrM15n9q0+3wfTC4Ega9LuQCCyJGSJTFhcX/+qZQxSrwj6SHBgbebLQoYI+ii5XJ4z9evicc+kc+1NK9GeF4XiN+lJhY4JLV66C/+z0V851B8NugtSjI0MIujVeY6hyiKX/CmXx10osO5IJF053QF7k7hOTA26HEYmcsOu9JXzQu6GHWeodvZgAQ==
x-microsoft-antispam: BCL:0;ARA:14566002|39105399006|8062599012|13091999003|31061999003|20031999003|12121999013|19110799012|15080799012|8060799015|461199028|40105399003|3412199025|440099028|19111999003|102099032;
x-microsoft-antispam-message-info: =?us-ascii?Q?BPMB4GOtSOeuUDiiAknyzKPQWBFocbgmF59xG04qwz4KezX7zoqbJ8aqMpXE?=
 =?us-ascii?Q?v6Pg8znsblokIh5RV3YWJHcUISqdk1H/1QcuyvyYKQn4Kc13FZ9nvEpL7EJ4?=
 =?us-ascii?Q?RVN7r027rkrM6WqqyuT1ONAd7esiM66Z1YN+iM2gGOXr0cunWtMDgdfrolKf?=
 =?us-ascii?Q?cQCiHOCTOlrfSMgWoMO5JEemXM9QCbAIVzbxb80ePK+g92v5y0nGHwHQRR//?=
 =?us-ascii?Q?zc55LhM12ikcStXtDu9kH01cNZdUUXq2Z4Wwx/uSZRx6apRGQu9Ny45MpXBp?=
 =?us-ascii?Q?f5+XksNbRcYCDnUHzqZCI+hqW6o+bT3Q/REMg88e3pYIanCcrsytkDXOd/9V?=
 =?us-ascii?Q?1YgQfnRdgqvjWdmEmFL0hyS9/GGX6vTou/InRvAl0uvDQcUJhRuaVyHaoL8Q?=
 =?us-ascii?Q?7LE9t8/hYLBUNHusRGgKQcBJQuSpU6CYmHllO0ABU/iup2syd3lQWag5r9SI?=
 =?us-ascii?Q?qZAqBu1zU5gPwzQD9l2MY48rmFZv2kcc4PzWNxakxl/KsHByxQgiVgSscjTx?=
 =?us-ascii?Q?cl6uc7SlC6Fn+zpzG0pWh1kIaM2Qcw41xjOUDyWsF2QWvG/6xR3f2GfbN/rx?=
 =?us-ascii?Q?VQGxjWBl0/yS52NvPLqfOv9zPkZZkcdFc6nk6D3iCekMzPjrimwkCyrdu86N?=
 =?us-ascii?Q?ruL6tXe07YThVIr2dDwULPCCXuq0B7wOJdNj/kVnzg4kSuT9Bp/bW0hrm97t?=
 =?us-ascii?Q?qQtGZyK3o5MrOIaoMTnmocx9YvZ9j3nLpk5zUeHG6PTxTafBe29Gin5oMMm8?=
 =?us-ascii?Q?u832HixGH+TlhNgIPQsqV9GISLZ49KZz8h0b6P8K7rXxsW7oVjMi+TH+Uqms?=
 =?us-ascii?Q?OGXoUIH7FofavvcCgRRYkWcHn1i/+c1/Kk2IQoqxXS2NUVUKNZhfnaRceP2y?=
 =?us-ascii?Q?QkjN9OuKDmpj8BIz1ECGf8ItcepUXw3rwQCzvn8vIgoKC0WaxKwB+cfq9XVT?=
 =?us-ascii?Q?VTTxmSpi0CImdf/xFmwUfrdennyhYCr+yY0kRlBUt50revLtUF2OArbeCkQZ?=
 =?us-ascii?Q?YZxakKZdnnvC7rpYgngYOHEhteNrYrNzO/cCqxjM8QJWx7H51Nj6w0/1xgZh?=
 =?us-ascii?Q?DZfXdxyB9vTEAaVQWpNyQU+ac7NyxpRQ4FOFRn5BoFhCe13qCwjzr3VDn2JY?=
 =?us-ascii?Q?pgPY+lTJh4pYGH/eMtdrNsCxQuOOQrnwS4K/j34VMj2W9b0aDoAY2Hfm0vjX?=
 =?us-ascii?Q?ZWvS6+ZPn1S91RZQRADtPfXLYxOI7FYHwr9SmNAinTDYSPO9eMt5+Vd6Exh5?=
 =?us-ascii?Q?ady8YhP4eY7nQJ7uZAiZb1CFnyqxaqPydhTRlTHL4KaU1ictXejkXpH8ijcw?=
 =?us-ascii?Q?NQuP/mpdCKorrBPJYVUUZdix?=
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?us-ascii?Q?TOmiaq+bhlBHwLpXpMfSi2GoqwomBtkR/0PcT9Lk1qFAfYmr6H5AE9bm1JO7?=
 =?us-ascii?Q?/65UX3NykQOcdbHHpMI+AQBi1X9yx2csW7viZbf69HA1oRJPlSivgf4pCTHo?=
 =?us-ascii?Q?rj7QOkrr2gJnoflc3QK2tW2bfoKyICbNZGDTtqpPT6R+PSDGgz82WSaW6zAw?=
 =?us-ascii?Q?WWxeiZusAXRPC4OVPZenWi8SIvm8BhSxUryRuKYUy3TWbf/yp4rHAHP7QIep?=
 =?us-ascii?Q?MwkX93p0t1Hbro6L6GecCZ1c6SAHzUr4JrtLTr2JG4ii6jM8uMfjtyMC6o61?=
 =?us-ascii?Q?VmXTViMY0O8geNPqAXNoY+w2Jdqq2DK5KOmPb/+asQ4BGOBdn3rwckKDeP0f?=
 =?us-ascii?Q?vcEPNKnCx8PiFdjKohEHb6HUZvJZqpoVlBZ5Gbg9+UnrGBUyEcNbw0PHscCX?=
 =?us-ascii?Q?bfsbIqQwNti4kGL4R+1/zLb/Mt6dq1WMVkC6wZjRoayBI0xouoXWJQpzfPD6?=
 =?us-ascii?Q?knNU5qJbrvldxds8mMMM6rA1F5+9knLrgM0W8WfFUgIP+KUhqgvEclmK0HQC?=
 =?us-ascii?Q?QKsFxa0E/ufuV1wMxsOxixrEADHoL9IqIBAm7RZ4vnmx0owflXCOK6Z+pcRb?=
 =?us-ascii?Q?dmGW5/tGynArXKgoK6Nkwcnh5iEK75J6+mC2ABMVlLNa7tiri2XnXg2Sq7fp?=
 =?us-ascii?Q?bg5R4NTph/Q4FLKQm8oiWrOea88+xhMWDTge5sbgXuT43inDUdEWyODL+Qp+?=
 =?us-ascii?Q?LHccf6plEmwJUB2Br1jwwbrG5b/Cf0rzl1aC9agmDiuijYZoqIRbgDFBwzcf?=
 =?us-ascii?Q?Ot8YNrwnKujeTaBeD1NlOE9Fdl1xyuokb6f5+KYlzbLY4YwIG88bghYgW8rP?=
 =?us-ascii?Q?FrY3mJYjlBciWq35yFF8n2kO1BW9oW6mcDH7tUXdlL4CTbuqegim1IJXoJH5?=
 =?us-ascii?Q?/+Y+0ZBSzXzW9AdmEuWNuKyobQSPJ6WthiIj5NNkHSR+FAU6Gym5jrwk+CY0?=
 =?us-ascii?Q?QEj6aPi/oIt+XaN8EOEPvafYHhkgp/IRgD8fhS3SOv5TPd0NWc05MttIw9NE?=
 =?us-ascii?Q?aBAaGwhzM5PxBLfzyxeD6XakwoSQU3g7IiWMl/DoTeAr7C6Jd30GAY07hM74?=
 =?us-ascii?Q?qYCEO4Iyc41yuO1hdfMG35pcEK3FhKMimldO16wF2tRaEtpq8rerKd8X7o2n?=
 =?us-ascii?Q?K/F70UT8/YeeF+yiar+Tl5lOOMZafl165OcKH8y0ZeBAjlqTdwC4AXBowNjd?=
 =?us-ascii?Q?LSD9JyHvhBca+L+MwNnvxd3TOfnhBxZbW2AyFU0is/SwlXHZCK8jTsC/tGUE?=
 =?us-ascii?Q?gESmUpN1y1oXu97wmKLg6Een6VrA98phoEZsm/UoytTqt/RjKuDcMGSS2gHv?=
 =?us-ascii?Q?rbMmrkAU0EW9ssBWSGseyMKNuiZ8C1HkjN0ByPECgCmRrOg2XU5XpeGDIyH+?=
 =?us-ascii?Q?m9MqKi4x0ynSeS8pmIiQ4/T4dNVh?=
Content-Type: multipart/alternative;
	boundary="_000_PAWP192MB2179CD9E5CEC9853A58DE0E6F96AAPAWP192MB2179EURP_"
MIME-Version: 1.0
X-OriginatorOrg: sct-15-20-9412-4-msonline-outlook-ce714.templateTenant
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PAWP192MB2179.EURP192.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-Network-Message-Id: 1f0797e2-ed2a-453a-1fa6-08de6f3cc982
X-MS-Exchange-CrossTenant-originalarrivaltime: 18 Feb 2026 22:26:27.9729
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-rms-persistedconsumerorg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: VI6PPFA9EBEF71C
X-Original-Sender: whitsejaneth806@hotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@hotmail.com header.s=selector1 header.b=ujUAp9bs;       arc=pass
 (i=1);       spf=pass (google.com: domain of whitsejaneth806@hotmail.com
 designates 2a01:111:f403:d200::1 as permitted sender) smtp.mailfrom=whitsejaneth806@hotmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hotmail.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.61 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	URI_COUNT_ODD(1.00)[3];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	DMARC_POLICY_SOFTFAIL(0.10)[hotmail.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	MIME_GOOD(-0.10)[multipart/alternative,text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_ONE(0.00)[1];
	TAGGED_FROM(0.00)[bncBAABBJHZ3DGAMGQEO7JVWTY];
	FREEMAIL_FROM(0.00)[hotmail.com];
	MIME_TRACE(0.00)[0:+,1:+,2:~];
	TO_DN_EQ_ADDR_ALL(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[whitsejaneth806@hotmail.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	NEURAL_SPAM(0.00)[0.164];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: B9BF015A9E8
X-Rspamd-Action: no action

--_000_PAWP192MB2179CD9E5CEC9853A58DE0E6F96AAPAWP192MB2179EURP_
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi Kasandev,

Trust you're doing fine. I wanted to check in regarding the message I sent =
earlier about the Yamaha piano that belonged to my friend's late husband. I=
t's a special piece with a lot of meaning, and she'd be so happy if it went=
 to someone who truly appreciates music.

Please let me know if you're interested or know someone who might be.

I'd be grateful for any thoughts or connections you might have.

Sincerely yours,
Ms. Whitsett

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/P=
AWP192MB2179CD9E5CEC9853A58DE0E6F96AA%40PAWP192MB2179.EURP192.PROD.OUTLOOK.=
COM.

--_000_PAWP192MB2179CD9E5CEC9853A58DE0E6F96AAPAWP192MB2179EURP_
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2//EN">
<html>
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Dus-ascii"=
>
<meta name=3D"Generator" content=3D"MS Exchange Server version 16.0.19628.2=
0204">
<title></title>
</head>
<body>
<!-- Converted from text/rtf format -->
<p><font face=3D"Aptos">Hi Kasandev,</font> </p>
<p><font face=3D"Aptos">Trust you're doing fine. I wanted to check in regar=
ding the message I sent earlier about the Yamaha piano that belonged to my =
friend&#8217;s late husband. It&#8217;s a special piece with a lot of meani=
ng, and she&#8217;d be so happy if it went to someone
 who truly appreciates music.</font></p>
<p><font face=3D"Aptos">Please let me know if you&#8217;re interested or kn=
ow someone who might be.</font>
</p>
<p><font face=3D"Aptos">I&#8217;d be grateful for any thoughts or connectio=
ns you might have.</font>
</p>
<p><font face=3D"Aptos">Sincerely yours,</font> <br>
<font face=3D"Aptos">Ms. Whitsett</font> </p>
</body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/PAWP192MB2179CD9E5CEC9853A58DE0E6F96AA%40PAWP192MB2179.EURP192.PR=
OD.OUTLOOK.COM?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/PAWP192MB2179CD9E5CEC9853A58DE0E6F96AA%40PAWP192MB2=
179.EURP192.PROD.OUTLOOK.COM</a>.<br />

--_000_PAWP192MB2179CD9E5CEC9853A58DE0E6F96AAPAWP192MB2179EURP_--
