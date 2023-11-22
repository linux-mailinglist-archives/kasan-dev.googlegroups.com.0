Return-Path: <kasan-dev+bncBAABB3EU66VAMGQEU253OBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id 718707F41B0
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 10:31:25 +0100 (CET)
Received: by mail-ua1-x93e.google.com with SMTP id a1e0cc1a2514c-7c43ef4b8a5sf130804241.2
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 01:31:25 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1700645484; cv=pass;
        d=google.com; s=arc-20160816;
        b=t7k8YxXZuZRv66Dq8ASTc4aPwvEl9miyCP9M63qMeUnDMgYjgOk/zzUvf4YqF6ljgw
         jy+Rom8eAS0M2MZfyIHSo/mHXHDtYo3AkagHdvjghr1qwez38QHOc3vKH72gKWZCmh2d
         I3ObGy0FtWqbu0xnybk1iGO627imlYY2Dow9nRlN5wJ/UjmkfreqV/2T4iiRocM51xAA
         7WTNNymTqFTFHUs3VRaSbD/6kco6MTDYhvsUphIOoKBZoFGHobCZ3SQImMzY9+6/QDA2
         fmAbvKHP1VlMJB8GOiS93Yp6mcTDuMsyQdVu1Ron+L6/V7wB9vIZPWNSZfQYkh0dT63Z
         tGhA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:date:message-id:sender:dkim-signature;
        bh=Ky08No/vIYSjc1pO99yElDShGiBC5ptZwwlkAAjQNRw=;
        fh=s0/lp7F24HpsT408w1znVuowr7gz8VUTtsMZNZU0Sj0=;
        b=eTBi9giAEZht7e0HqEoRIKIDS91Msh1zkQ2ixslKxnMLcOFq7ZmktNWuX0A1mAW6al
         i4xO6CM8xKbBG6U1JHbgjQjrAuHYEYZij+6dK3HNjpYBOcrxDOlfLI70iDqFaoTExhjA
         +/3knSzeasxuhCDUsnGxAvgEX9hNT+vKIXIrYZtDUvup/LhuD0/Xolkhm/WTDdNPes54
         xUr5mceyYzvqXZfqe6Gfe6CO6T8bWsjbIFryyIQqg0TT1GbQ3W9JJDCSCJD0f1U8NZ3w
         nZLF5/MVI1AiZgGrU/7a4ssMboauLiZ1x4+eaXmGtQ5c3NW25/DmTBMX44FojXcHg43w
         fxZQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=em30Hzhq;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe1b::803 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700645484; x=1701250284; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:date
         :message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ky08No/vIYSjc1pO99yElDShGiBC5ptZwwlkAAjQNRw=;
        b=jMJ6QoBb/MmdTVIxtc1+YDF+FwaLKIP7BFYi8bXTvS02IK4/3G6BfEsr8y7vKUYyA/
         j94/Cusa592nr0msQtw9yB2kbJsv1nF/49CWA5V3cYhkMk6REAw36AkbvPa11pg06rku
         JS7Rkb9b6pBxoHefgr5l3KizNnqniavMg5al8mHDqgJcyiOZ1ZRLNrLQuVd/Gt+uoXkb
         5FQzorXRMI9Ft0g10U657KhuFG2m7VX5YN0p0+CED3UFvTTfWn7psI9/U7aybbmlxjO+
         TfO59LBIP2CFknZEMXaHZ5j/rPQMOj7hO1p829O7tI9l6KcsXLwHscFgvxrizwpnvJBH
         UM6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700645484; x=1701250284;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Ky08No/vIYSjc1pO99yElDShGiBC5ptZwwlkAAjQNRw=;
        b=YjI90EUPYUko9hKxVuge3P3DhsvcLOTgr4bRb0JscmsaIQMrKlYNRcjsc9r19SUC8z
         N7eyj5wLrfnxt+Y0+HSskgoIKPb8D1FtMfNxX3wSWEv8yqXvCeNjeOL2c1Z0P7zjkenR
         SHg0Hj9gHtQsE+fxMe1lQto/5nEm6TbOAHH7WBvIScf8cYTDSPWgwF6fBPTq+Me27X0G
         nKcO9GKy8BPHf1aThOronYUKhKxYQEXN1O7QeSjlAEVmq1tV5/NlFYgSPgOuWhaIQI++
         WIPlxRatRplMUlEj+jjl8t9BB5XAOAPdpUt4A4NavIhFDZCGHsiwdzzU/9/XUkpxcojg
         6miA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwSc/UoN6lO1fi+CXHG89cY2NkJDegUXpIeHDxuJW5EsEuW5Yfk
	pFBRe6hZKKm9TYIIpZXyGiPHYg==
X-Google-Smtp-Source: AGHT+IES34PqPdzRI01p4K6ZIoMedAj9ZADk/D4ay/jow13Umw1Z1QrzGS42nlfaLdx6ekf8uhflMQ==
X-Received: by 2002:a05:6102:4754:b0:45f:3a78:ca20 with SMTP id ej20-20020a056102475400b0045f3a78ca20mr2032906vsb.0.1700645484274;
        Wed, 22 Nov 2023 01:31:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:14f2:b0:677:fbda:b41f with SMTP id
 k18-20020a05621414f200b00677fbdab41fls4262037qvw.2.-pod-prod-07-us; Wed, 22
 Nov 2023 01:31:23 -0800 (PST)
X-Received: by 2002:a05:6102:30ba:b0:462:8f47:cf9b with SMTP id y26-20020a05610230ba00b004628f47cf9bmr1960475vsd.16.1700645483592;
        Wed, 22 Nov 2023 01:31:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700645483; cv=pass;
        d=google.com; s=arc-20160816;
        b=u0Xvj5Yihl0iEA9+OlrxAGoEUuaszMMky341EKhh//FuBhnLeYPiXckvq6KjAIdox6
         NZ4J5XPuRollfoaTfn5t/gR3Q0HiHjN6A0wvBlSxPvqy7XxzfmH+paSfnYxo/+boeW8B
         vn653dDMNaYFmj/OdJSXw80yYOJbqbZrbtX65BunER8teRomCDRYZlwuK7LIYNpRt83Y
         w9r5zpT9sqrNF3CTh+rr8VGM2iiTGAQBaFyljglVRafmk9RLqEbNN5tC7SPF+lpivtVv
         CSfW3WXrJBrAnYvo1TH1Jz7fHvh4fnmGNu/9pma87mjeBR2/utY5POsmntITtNyNb4c4
         tSCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:subject:user-agent:date:message-id:dkim-signature;
        bh=wPIXkEm/xEsL/EC11qE51rwRVlS83/az6sa636j1GNM=;
        fh=s0/lp7F24HpsT408w1znVuowr7gz8VUTtsMZNZU0Sj0=;
        b=dWjxmdehBYjwBj4PaF8GAWsqcWrRveUAKez4SFK5lipwCencPSepzADflxcGyL/XH2
         37NWBNTEpa1iqzEoMoNs5JPq+B49p1EbaRYf59MdwYVFOCGjlhDEBDlK1AzvqeOTRkip
         ZcdiFGYmbFThF5TegibI0yNB8GrF2C5GH5mFU5c5iwPI2kI7gIOrycCiOCwWGn72P0pc
         Vvj1ceDh0WtLeGXywfjlNbG6WYGGJYWZLbTCm9zsS5sShiuGuasg02xA7/A55xUR5Cij
         QmVQ55KjTZfWgM0cg9wFkKzo/GlkOVBe4cKGMFJSAvpZW4eDWKlnGy4+loB7TZRPpeVJ
         d4WQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=em30Hzhq;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe1b::803 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR03-VI1-obe.outbound.protection.outlook.com (mail-vi1eur03olkn20803.outbound.protection.outlook.com. [2a01:111:f400:fe1b::803])
        by gmr-mx.google.com with ESMTPS id d11-20020a056102148b00b004508d6fcf6csi1766516vsv.1.2023.11.22.01.31.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Nov 2023 01:31:23 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe1b::803 as permitted sender) client-ip=2a01:111:f400:fe1b::803;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=NEQqjBNwXXNk8cH9xEXrxxRWWAI3rxzi/XcLe+EzUIWBxuE3AF49xLz3Gs0X3NHYssje17diUSgYC50jLfpthE6FN8MUP99rtYFJCMwY+oqcPN2fFe++fFd33tLZz0UCorkMyQ5mtvd3o7LY6rzSrCwBPscTbjtfa9fPLA9FpSVJ50V/fAbsgmphMRnrrD5lv/+hyCXUT6W9kpTtFjoNu+AwwYfIE6AjOZgGVBg42gGUAvMTOuCk+Zo73kC5OOQ/jt2SaTPOU0b9N1hnfR32G2tNNPMeWbt4YjRY9L/QIfBs7XBW14AYBgxbCqzYgJSNmc/BBSG8IQPQh1sLIwrUSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=wPIXkEm/xEsL/EC11qE51rwRVlS83/az6sa636j1GNM=;
 b=d8PqnLIMu5/U1EnensTO4OJdCrlloK0ZgdPYA0L16BvdtkICsOgbddfaAeVyd4mrv3bItXQsgJLolasWEwrPTV6u0GjYmWPYKWaAQC+xENaNG6Vii3XfcVSYzylrwhVR6U8tuYV7DR5b1U7RUoH2ffv2nfz4WvlacElMUntIqx6PxNkHWu32H87DP0dZusI5FtSHtImwm9RuGFUXl5D8VnTakRgyO6Sh63KqMTKA3SyisaEcR8c4V6Pktl1H6vAHZe8hoWW3l5sjXNXevQCI5KikD204cagONn0sp2AIqcxnSz/cKo/TfnTEcAkhFMFbXxBOlXBsiQKDacXC4LPA8g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by GV1P193MB2406.EURP193.PROD.OUTLOOK.COM (2603:10a6:150:1e::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7025.18; Wed, 22 Nov
 2023 09:31:20 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4%4]) with mapi id 15.20.7002.028; Wed, 22 Nov 2023
 09:31:20 +0000
Message-ID: <VI1P193MB0752C8CE08222B9EA4D744F399BAA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
Date: Wed, 22 Nov 2023 17:31:19 +0800
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] kasan: Improve free meta storage in Generic KASAN
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-kernel-mentees@lists.linuxfoundation.org
References: <VI1P193MB0752C0ADCF4F90AE8368C0B399BBA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CA+fCnZfBM=UU0AyArERNMxBMeaPvbV-e6uyQDpwgqA5c6_f_DQ@mail.gmail.com>
From: Juntong Deng <juntong.deng@outlook.com>
In-Reply-To: <CA+fCnZfBM=UU0AyArERNMxBMeaPvbV-e6uyQDpwgqA5c6_f_DQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-TMN: [844qAesJ/jBR/CvE/c8M7SmratwBpcuW]
X-ClientProxiedBy: LNXP265CA0022.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:5e::34) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <63744528-8fc5-4986-b74d-070297b1e6d1@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|GV1P193MB2406:EE_
X-MS-Office365-Filtering-Correlation-Id: 0a11d2a1-5303-459c-428d-08dbeb3dc8dd
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: 6xGYvrNnRYLRQZ8Cy3YybntJqRVSQSEt7ju4AFjBwvCW0cgwMHhGcsdlK0Dvu7csLsEM2H1zD+pfk3dwWAHOGVQC7Er+npznRRV48l4d0PjRj/WngNwzWW6WKHqs7144HNxbiJqB+v8XHbeJvv9f1cOjq6jsm6zjvQhY5ul9q3TLpgKQMrb3vPnkpjGz8YDjQ7cIWAcPMuLBBay6NbDP4efo1aZ8Hm7XTsH6HdabbDogkZna/NPGkvZHKrGAjJjhVnEqX9l4xPw60ZAe9MCBcEwTCtkvJNsjD0A3Kp8wz3CE+FM/+ctejUeMWYKF1sD2NcT8Sm7ICKyovRGlTADztv9yqQq8WQRXdhvjyOb04mKctZa69FOz7sCYSSgpam67OcsQu1Wc++9c52k3VSB87gYvbhVtjIaHEN5AwWTLqqciOBo829WawseUBHbL1+7ODvqW5pZoyEhwuhdPMHboOo9biVUXiSW/yaUYXiTwqwgFRShRvzaaB/bIj3WRzTPmwePBA98IJI1yXkr3SAJQsUHuBfFVZ/tbTqaslh3L+5/diF/WsQ1nhm5bHhy5Kj8D
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?R3g1enY3cUdHR2xiMDBWd3dXaUxKTW4xejlISlpSVjVETk0yL2pYbDdiNWps?=
 =?utf-8?B?eUJXaXpEdWJZVUJhYTdncXhzeEZOWVFIaDkrWlMwcVljT1lMNWFUb3lFVjZk?=
 =?utf-8?B?dlBIT0ViWDh6UlJSUlZIMWIrVnpqSkxXZzhFSnR4OWpITExML2pvbXJPd3Rz?=
 =?utf-8?B?djV0UW52Z2FxbExUNVVHWUxSS3ZJcEVWT1ZSQ0Q2aVBENnVlZ0NWZG00MGlm?=
 =?utf-8?B?ZVk5OE9sSHJKd2Q2TkRGYlJIbXk4dS8rY2pDRlRzck5NaVMzbDhDZWs3M2ty?=
 =?utf-8?B?MGN0dDFET3RRNllFZUlvS1dnTGJzWnQ5SHNLN1lRUnVKa1RsTmRFNVpaS2kr?=
 =?utf-8?B?RHBVV284NUxzZlpqRHZibWVNbHlJYzNVRitZbDN4QTVNQkJpVFBValJwS1FO?=
 =?utf-8?B?TGJaUEhyd3Q4OXJhUUh0c2dJMnpCOWZ0a280akV3NmczSHk3UlliTFBPbHVz?=
 =?utf-8?B?KzR1YjVZNkJkTWlRS0IwRy9KK2ttQS9aZThtZVBBWWdSL1JvcmRIU2FNODlV?=
 =?utf-8?B?amhlV2M2dm5zaXh1VGpRVzVEOWJpV3A2UExpR05uN2J6c0xDc0NxSDlZdW5O?=
 =?utf-8?B?dXYxNXZwcFkvUmJwanJReHJrTDZCOG9RbGVDQjNXa2YrNUE4Tjl1K3NsVFNV?=
 =?utf-8?B?QnVqaXVpaFdacmtjZWoxd0phQUxWWHh6SWNrRXpnMWZGLzdtRy92aEMweXoy?=
 =?utf-8?B?aDlkMFBjakh0a1R1bXA2amxjWFM5d1Bna2M2dVkvdGIvTklUSkVucHhHd0kw?=
 =?utf-8?B?dElrbDRONUhCSkZtYU9vaWJVRzNTenN4aW5UN2hPKzVYVk5wT2NCVGNIN21J?=
 =?utf-8?B?ZFBBM09GZVpDT2lwWnE5ekJTdmdLdjFQU1EySmtiYlFTcEIycEFKZFMrbUs2?=
 =?utf-8?B?RmFyVFQ2clBVSEtBdWpTUnduaGJseE9xQ3pFSEpMWFZrZjQ1aHlwZkZQTFNK?=
 =?utf-8?B?ZHFMNTg1bGIvN0hPYkoxb2lMNk9DUWFSTko0NU9mZzdMOFRvVXJoUXQwZC8w?=
 =?utf-8?B?dk80ZkowTDVmUDdCQ3d1djh2L3RWL0loZUhLMjBSdlA4ZmpQODNTMGEwcnpl?=
 =?utf-8?B?cTVyWjdRUllGYlNabHpvL2hJNnZJRmV0SWRhZy9HRWdEQmRncWQ1R01LV3Bk?=
 =?utf-8?B?Z0JYZVhPZzNsTlN5cEdtY0RTUFQ0a0FFSkF4NDMzVWQ5Q28ycmcrRGl2cFdr?=
 =?utf-8?B?N1BLcllVelNSSytkYzNJc3V2Nlc1VnJ3SFNnbjhVWU14TDUreW1oSTA3bWVU?=
 =?utf-8?B?OWlMVFoweGp6OXJGRGdlM3lhNkFlK3pnWDZFQ00rK3pXQlBtN3NsMnRBbDdl?=
 =?utf-8?B?cUJPUHZCU0c4cUlXODU5aGVXbkxqWXgwcmpmODYzRlV3OGhPT2JkemtpZkJ2?=
 =?utf-8?B?bEQ2bU9yZzRTZi9qTUJtSlViRERjbnptRk5yUzFKejZvbTI0NTdtR3gvZTUv?=
 =?utf-8?B?bURJWUJJK0RVZjlZR0hPbE1kMkNJZFlMdmJXOGRmRkUxU1JmU01wVHJxNzdW?=
 =?utf-8?B?b09SeG4yOVBycWRxajhpWXJ4U09nckhkMXBxL2dBSWlTQjg3R0IzVHdKYy9C?=
 =?utf-8?B?b1M4RFZGekJ0bVlLUWlWcDM5YmNWb2RKTUlwWjJnemxRWGNvM1B2ak04NWxM?=
 =?utf-8?Q?tdANndwOI6dSfmdu9BBJbehA2xgif2b9EeC+6qIruuV4=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 0a11d2a1-5303-459c-428d-08dbeb3dc8dd
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Nov 2023 09:31:20.5028
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: GV1P193MB2406
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=em30Hzhq;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:fe1b::803 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
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

On 2023/11/22 10:27, Andrey Konovalov wrote:
> On Tue, Nov 21, 2023 at 10:42=E2=80=AFPM Juntong Deng <juntong.deng@outlo=
ok.com> wrote:
>>
>> Currently free meta can only be stored in object if the object is
>> not smaller than free meta.
>>
>> After the improvement, even when the object is smaller than free meta,
>> it is still possible to store part of the free meta in the object,
>> reducing the increased size of the redzone.
>>
>> Example:
>>
>> free meta size: 16 bytes
>> alloc meta size: 16 bytes
>> object size: 8 bytes
>> optimal redzone size (object_size <=3D 64): 16 bytes
>>
>> Before improvement:
>> actual redzone size =3D alloc meta size + free meta size =3D 32 bytes
>>
>> After improvement:
>> actual redzone size =3D alloc meta size + (free meta size - object size)
>>                      =3D 24 bytes
>>
>> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
>> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
>=20
> I think this change as is does not work well with slub_debug.
>=20
> slub_debug puts its metadata (redzone, tracks, and orig_size) right
> after the object (see calculate_sizes and the comment before
> check_pad_bytes). With the current code, KASAN's free meta either fits
> within the object or is placed after the slub_debug metadata and
> everything works well. With this change, KASAN's free meta tail goes
> right past object_size, overlaps with the slub_debug metadata, and
> thus can corrupt it.
>=20
> Thus, to make this patch work properly, we need to carefully think
> about all metadatas layout and teach slub_debug that KASAN's free meta
> can go past object_size. Possibly, adjusting s->inuse by the size of
> KASAN's metas (along with moving kasan_cache_create and fixing up
> set_orig_size) would be enough. But I'm not familiar with the
> slub_debug code enough to be sure.
>=20
> If you decide to proceed with improving this change, I've left some
> comments for the current code below.
>=20
> Thank you!
>=20


I delved into the memory layout of SLUB_DEBUG today.

I think a better option would be to let the free meta not pass through
the object when SLUB_DEBUG is enabled.

In other words, the free meta continues to be stored according to the
previous method when SLUB_DEBUG is enabled.

Even if we teach SLUB_DEBUG that KASAN's free meta may pass through the
object and move SLUB_DEBUG's metadata backward, it still destroys the
original design intent of SLUB_DEBUG.

Because SLUB_DEBUG checks for out-of-bounds by filling the redzones
on both sides of the object with magic number, if SLUB_DEBUG's redzones
move backward, leaving a gap, that will break the out-of-bounds
checking.

I will send patch V3 to fix this issue.


>> ---
>> V1 -> V2: Make kasan_metadata_size() adapt to the improved
>> free meta storage
>>
>>   mm/kasan/generic.c | 50 +++++++++++++++++++++++++++++++---------------
>>   1 file changed, 34 insertions(+), 16 deletions(-)
>>
>> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
>> index 4d837ab83f08..802c738738d7 100644
>> --- a/mm/kasan/generic.c
>> +++ b/mm/kasan/generic.c
>> @@ -361,6 +361,8 @@ void kasan_cache_create(struct kmem_cache *cache, un=
signed int *size,
>>   {
>>          unsigned int ok_size;
>>          unsigned int optimal_size;
>> +       unsigned int rem_free_meta_size;
>> +       unsigned int orig_alloc_meta_offset;
>>
>>          if (!kasan_requires_meta())
>>                  return;
>> @@ -394,6 +396,9 @@ void kasan_cache_create(struct kmem_cache *cache, un=
signed int *size,
>>                  /* Continue, since free meta might still fit. */
>>          }
>>
>> +       ok_size =3D *size;
>> +       orig_alloc_meta_offset =3D cache->kasan_info.alloc_meta_offset;
>> +
>>          /*
>>           * Add free meta into redzone when it's not possible to store
>>           * it in the object. This is the case when:
>> @@ -401,21 +406,26 @@ void kasan_cache_create(struct kmem_cache *cache, =
unsigned int *size,
>>           *    be touched after it was freed, or
>>           * 2. Object has a constructor, which means it's expected to
>>           *    retain its content until the next allocation, or
>=20
> Please drop "or" on the line above.
>=20
>> -        * 3. Object is too small.
>>           * Otherwise cache->kasan_info.free_meta_offset =3D 0 is implie=
d.
>> +        * Even if the object is smaller than free meta, it is still
>> +        * possible to store part of the free meta in the object.
>>           */
>> -       if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor ||
>> -           cache->object_size < sizeof(struct kasan_free_meta)) {
>> -               ok_size =3D *size;
>> -
>> +       if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor) {
>>                  cache->kasan_info.free_meta_offset =3D *size;
>>                  *size +=3D sizeof(struct kasan_free_meta);
>> +       } else if (cache->object_size < sizeof(struct kasan_free_meta)) =
{
>> +               rem_free_meta_size =3D sizeof(struct kasan_free_meta) -
>> +                                                               cache->o=
bject_size;
>> +               *size +=3D rem_free_meta_size;
>> +               if (cache->kasan_info.alloc_meta_offset !=3D 0)
>> +                       cache->kasan_info.alloc_meta_offset +=3D rem_fre=
e_meta_size;
>> +       }
>>
>> -               /* If free meta doesn't fit, don't add it. */
>> -               if (*size > KMALLOC_MAX_SIZE) {
>> -                       cache->kasan_info.free_meta_offset =3D KASAN_NO_=
FREE_META;
>> -                       *size =3D ok_size;
>> -               }
>> +       /* If free meta doesn't fit, don't add it. */
>> +       if (*size > KMALLOC_MAX_SIZE) {
>> +               cache->kasan_info.free_meta_offset =3D KASAN_NO_FREE_MET=
A;
>> +               cache->kasan_info.alloc_meta_offset =3D orig_alloc_meta_=
offset;
>> +               *size =3D ok_size;
>>          }
>>
>>          /* Calculate size with optimal redzone. */
>> @@ -464,12 +474,20 @@ size_t kasan_metadata_size(struct kmem_cache *cach=
e, bool in_object)
>>          if (in_object)
>>                  return (info->free_meta_offset ?
>>                          0 : sizeof(struct kasan_free_meta));
>=20
> This needs to be changed as well to something like min(cache->object,
> sizeof(struct kasan_free_meta)). However, with the slub_debug
> conflicts I mentioned above, we might need to change this to something
> else.
>=20
>=20
>=20
>> -       else
>> -               return (info->alloc_meta_offset ?
>> -                       sizeof(struct kasan_alloc_meta) : 0) +
>> -                       ((info->free_meta_offset &&
>> -                       info->free_meta_offset !=3D KASAN_NO_FREE_META) =
?
>> -                       sizeof(struct kasan_free_meta) : 0);
>> +       else {
>> +               size_t alloc_meta_size =3D info->alloc_meta_offset ?
>> +                                                               sizeof(s=
truct kasan_alloc_meta) : 0;
>> +               size_t free_meta_size =3D 0;
>> +
>> +               if (info->free_meta_offset !=3D KASAN_NO_FREE_META) {
>> +                       if (info->free_meta_offset)
>> +                               free_meta_size =3D sizeof(struct kasan_f=
ree_meta);
>> +                       else if (cache->object_size < sizeof(struct kasa=
n_free_meta))
>> +                               free_meta_size =3D sizeof(struct kasan_f=
ree_meta) -
>> +                                                                       =
cache->object_size;
>> +               }
>> +               return alloc_meta_size + free_meta_size;
>> +       }
>>   }
>>
>>   static void __kasan_record_aux_stack(void *addr, bool can_alloc)
>> --
>> 2.39.2

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/VI1P193MB0752C8CE08222B9EA4D744F399BAA%40VI1P193MB0752.EURP193.PR=
OD.OUTLOOK.COM.
