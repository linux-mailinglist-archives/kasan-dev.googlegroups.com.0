Return-Path: <kasan-dev+bncBCWJVL6L2QLBB6VVUSKAMGQEZWMPF3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 207C952FE72
	for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 19:01:47 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id n3-20020ac242c3000000b00473d8af3a0csf5836862lfl.21
        for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 10:01:47 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1653152506; cv=pass;
        d=google.com; s=arc-20160816;
        b=JmSW77gR19PmFtbtStC2ao0ZdtejI6Z4eUXdMGiR6+PNFqBP57gElBtyMq10R8zXaL
         tS4l4fotVrnWTPM9oRChgYdMfsi6HXNr92ZA0DC9WxZcmNO7Egzf3Ly5QufsIGPwfkNT
         FS5AQy/YWjlyzs8rBWddrQMxdCK0ht8U7TYeTIwIgtbPQJa3z8AK62gLeivSY+n9Kydw
         vHlzpbJ1YNUKYbxWfqCR5YCNLEFbvL7Nv7i8CzkeZh4L1ZP+IVHRTzCvKsqmOSx8/2uq
         /qHmWrT0g2W1GgNMGqBnnSnxJar3EKqaq1ZipbRd6E7koQZT/sDuMocaIN2Ji/a4br5O
         OBFw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:suggested_attachment_session_id
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender
         :dkim-signature;
        bh=uGH5p+FBLYDw6pknTUdIsbqVOHrJmuoZfpPNA6Bc/kE=;
        b=DAleKX9X6Xs/mePQLMf5L2dHW2vMfpUNY6mJk1n9NbfIxHRjCZVv8SKpHHKFFgcXeQ
         mmMbQziBywdTCuF4KyvjDdAughbQxzkSUlFsl3LTTqHk+HS6ZnnAQzGHlv7fc2uOmlva
         5BE6Gkqan4eH/66jRXS+J9QXQWve1/SRhUUiwfkSdpmKa3BaXmK+x4h4z/YzziZUB0E6
         AJbFQ58EiyvjGQoDcgTWjy08bhmpKMDF3lRv5h0kgsByYIU/i/SmQ5lpc5ao9RpCM3Fp
         gxyR8D+aD93jYMuCwvV35x8eeqtL3UJX028dEYes5IiI2/cWYvqgbIFZvyEsU7BWmsQO
         jm2Q==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@purdue0.onmicrosoft.com header.s=selector2-purdue0-onmicrosoft-com header.b=Sc8yrzLr;
       arc=pass (i=1 spf=pass spfdomain=purdue.edu dkim=pass dkdomain=purdue.edu dmarc=pass fromdomain=purdue.edu);
       spf=pass (google.com: domain of liu3101@purdue.edu designates 2a01:111:f400:7e8d::71a as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=purdue.edu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :suggested_attachment_session_id:content-transfer-encoding
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uGH5p+FBLYDw6pknTUdIsbqVOHrJmuoZfpPNA6Bc/kE=;
        b=h0p3wTinGD5puDh9MbY2d3djiCIs7KiAIpHTywlRQ3bEnBL84c8gyiy8Xiy+jYwhtT
         1rPoU1420w9qHGV0DqhBomC38iX1PSqhIUxHIndq6uTx4kiOwuYYPEWTem8bpsGA8W4V
         Mh/FX3qmmeZ4P1uK4ttSPxS6mWcGGRihkkGBk6V8QQm/QQ8srZfecTsgcCReDJkvpJlK
         9iOMsxsQqoAtOcdE96KONkBZEfR7x8cmOv2f/VKkrJ1zTrrhLtO8z6CxLDxTEBgSFtNK
         7fYOlENCjUeKOuanm/tbSDWMFxIS4MwcQsC0YF8vsx+RZ5so46bHStIEP1LZ/yZ3EJ51
         JtBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:suggested_attachment_session_id
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uGH5p+FBLYDw6pknTUdIsbqVOHrJmuoZfpPNA6Bc/kE=;
        b=M5el02nPrao1gDmTItTtGBj4Ju+ewMJnqx+B90aKPP4uM+7Mq3gvaH2bPnTwt9+I4e
         QXyXkBpEn3ry680QZiJkD4AVhabPcz7u1kLnLqTL8y8mXAVOb80zzTqYPVTw2kfWY3AX
         pLYPNTo7TY+j6JNRLvyaYCUpLs/5LUREEIxcmE02iE8T5ktcPrPio4wt7/E7Kg7tTURG
         RTXM3fF5sl3MR9y0VzPun+yz6qCCeOdaDjjehij2HSbsexdJKlOy20NrX/vQ6rgOqqHi
         cwmFGTNi2sAgmC7SeWZ1TnJiiV05SfF8iRRZa2o8SRy+9USUHYBQfgmui+/fiyl7j35n
         YreA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530TG/J35VzRKK+bHE+vSl66T7QVT0y0IYu0YcZfexJfea+rZ5O1
	AOUhjM6bPuXc3T+bE37lI8s=
X-Google-Smtp-Source: ABdhPJwrfNkpVmXIDPQynXyE2rrP8QXjtOdZpHuMTkc5sAP3zdlW2LMNQ8B/BdJZ44jbw8sk55Vd0A==
X-Received: by 2002:a05:6512:3048:b0:473:a3d4:5252 with SMTP id b8-20020a056512304800b00473a3d45252mr10555383lfb.50.1653152506349;
        Sat, 21 May 2022 10:01:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als3677638lfa.2.gmail; Sat, 21 May 2022
 10:01:45 -0700 (PDT)
X-Received: by 2002:ac2:4154:0:b0:477:d389:ba5e with SMTP id c20-20020ac24154000000b00477d389ba5emr7388088lfi.162.1653152505093;
        Sat, 21 May 2022 10:01:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653152505; cv=pass;
        d=google.com; s=arc-20160816;
        b=q6ox/Wsp0eJyHOJ6cNhRG0YBw5LXIFJCjpT0Z8ZO1gk7ri4B3STwBzH+1CYg+VbIlS
         hvcnDTCkoHn6RXpxrC+OXX8/CXTcB3dfu+3aKwYEAzoaGC6t31Juh9MRZ5N+/65/jcsL
         LlO75mpplWq3ietrfyNXDJf9SRh9WjyFE87bxHOfqM4lNENo7dTtMk9j2aNiPNQWvylF
         BAA3aYDinjibtc06oOHPPiq9NWwgk4/Hrw/Je6gndBwfOsk/z85AUIpRxP8jjXsLUZWb
         Mfgvmq88A6763hFh0AoLA/00R12TwD2P8uMGkn3JAx2JW69eWinh4n5wqM/DAkIRxequ
         1u8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding
         :suggested_attachment_session_id:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:dkim-signature;
        bh=Ol7Mn0Vq4w/YCICoTGWRHFxDsjM656lYWP822BoEoSg=;
        b=cEDBvM8Hpfz8V3lndI8bw7uz9lyEYcHQoO77AweFTSW0C+LLaLgmkBuRWhcjMvidxK
         511gJI6DgnrEIJDhwp3Lj6LDaY0FhLkuHTZOjHTmtwOQGcQ4foktdoJD9AQN3PPqxZ0n
         5MznNF1sK9z0wqzT06DKiEB9n6Nu0sEcIC/LdMOT4JPnYNCwh5ASX4C+gwNo2ZIh7FjF
         LbDSi+CYVUokA6v3md8hMlMfobeQZTSWLackT0bQJhIvTrb5+pr9LinomI78EILrSItN
         LZpLN4nke4groZLcQN7NCb7BRx5lTJByXtnfmQmfcFVC1vqN+29NkHOd1QrbH/HE6B/+
         0lFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purdue0.onmicrosoft.com header.s=selector2-purdue0-onmicrosoft-com header.b=Sc8yrzLr;
       arc=pass (i=1 spf=pass spfdomain=purdue.edu dkim=pass dkdomain=purdue.edu dmarc=pass fromdomain=purdue.edu);
       spf=pass (google.com: domain of liu3101@purdue.edu designates 2a01:111:f400:7e8d::71a as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=purdue.edu
Received: from NAM04-BN8-obe.outbound.protection.outlook.com (mail-bn8nam08on2071a.outbound.protection.outlook.com. [2a01:111:f400:7e8d::71a])
        by gmr-mx.google.com with ESMTPS id b23-20020a2e9897000000b00250a0b5e050si275194ljj.4.2022.05.21.10.01.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 21 May 2022 10:01:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of liu3101@purdue.edu designates 2a01:111:f400:7e8d::71a as permitted sender) client-ip=2a01:111:f400:7e8d::71a;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=aH/f1q8wriR/0U9z5D4u0iimK7EBGjIERK+erZxZ7FnpskpeXuqqeggtTAWfK+526zxfs5HwPPZTdN89CevGTLz+Pw+86WC7sV4Zeox5iXxveiuZj/iFEp9qUFmZYsqCbolBnhqCzC0/X07tv2LTJ2zwhxbVt2MmXwfTOnyTHfRp4NWGRXMf5oZpbQs+nrJGdp1eKRmFaOB0/ClYBT9pesQ05TsReR9raAgMurpyIQTtfO3zy5xQjVVrl+RG9FjyKDKkB6a2GVIk37IxzLvKqO0RS32QR52EXKi2dJ7XSMe53kskZC+qUlQb89XaAkoIt5dEov7LYQrNMOpvXKWE+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Ol7Mn0Vq4w/YCICoTGWRHFxDsjM656lYWP822BoEoSg=;
 b=SqOjZW56ul/TTVA15NE5In/rT33jkYb4T3QXGH/J1DwnzQRYrz8jw4k771qhu35UuXc6Rc+t9hIujj53hQNljQmVMoK4mTFq5l9vM6KS8Xq4VzWAcnvcSsqSV/TCYvm9EinjeesjjxoTyqhRUEvEKX0eZ2ltZjWqdF8iHXbbR4Shu3/WmP30XWZdw4pWoB6daMtT7mzERA6bCDNi/ukuVzY2cDg1exhRKZlCAJKlwghq2PqO4zKT09mt1yWozdMKsWNHNiMJQXPhYgjTCsvp1pP/t9WTXRlbBrscMRkUQzdj+SJfaCWBlGdGYZo9VhgyVDc9qxfGpqaxk5LzmDoIFQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=purdue.edu; dmarc=pass action=none header.from=purdue.edu;
 dkim=pass header.d=purdue.edu; arc=none
Received: from MWHPR2201MB1072.namprd22.prod.outlook.com
 (2603:10b6:301:33::18) by CY4PR22MB0088.namprd22.prod.outlook.com
 (2603:10b6:903:15::22) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5273.21; Sat, 21 May
 2022 17:01:42 +0000
Received: from MWHPR2201MB1072.namprd22.prod.outlook.com
 ([fe80::a9e9:b100:2a55:23aa]) by MWHPR2201MB1072.namprd22.prod.outlook.com
 ([fe80::a9e9:b100:2a55:23aa%3]) with mapi id 15.20.5273.017; Sat, 21 May 2022
 17:01:41 +0000
From: "Liu, Congyu" <liu3101@purdue.edu>
To: Dmitry Vyukov <dvyukov@google.com>
CC: "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] kcov: fix race caused by unblocked interrupt
Thread-Topic: [PATCH] kcov: fix race caused by unblocked interrupt
Thread-Index: AQHYajHoHiVYwAN8JUi5UTY5PvyBWK0kVeGAgAAA0wCABFjck4AAWi6AgACIm5Y=
Date: Sat, 21 May 2022 17:01:41 +0000
Message-ID: <MWHPR2201MB10723CCBB4869738E4BDFC36D0D29@MWHPR2201MB1072.namprd22.prod.outlook.com>
References: <20220517210532.1506591-1-liu3101@purdue.edu>
 <CACT4Y+Z+HtUttrd+btEWLj5Nut4Gv++gzCOL3aDjvRTNtMDEvg@mail.gmail.com>
 <CACT4Y+bAGVLU5QEUeQEHth6SZDOSzy0CRKEJQioC0oKHSPaAbA@mail.gmail.com>
 <MWHPR2201MB10724669E6D80EDFDB749478D0D29@MWHPR2201MB1072.namprd22.prod.outlook.com>
 <CACT4Y+bXyiwEznZkAH5vRNd6YK3gi4aCncQLYt3iMWy43+T4EQ@mail.gmail.com>
In-Reply-To: <CACT4Y+bXyiwEznZkAH5vRNd6YK3gi4aCncQLYt3iMWy43+T4EQ@mail.gmail.com>
Accept-Language: en-US, zh-CN
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
suggested_attachment_session_id: 27f1dff5-781b-b168-e29a-e2c58d0d881b
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 9745fced-50d0-4071-269c-08da3b4b93f5
x-ms-traffictypediagnostic: CY4PR22MB0088:EE_
x-microsoft-antispam-prvs: <CY4PR22MB008866C8B7893983057461AAD0D29@CY4PR22MB0088.namprd22.prod.outlook.com>
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: t4tQ9ITxJOfLmOqly2Nx9QqXTlYEiyfcgGOQDYfAfPsyMM13NZXx8h7NGXj6QILbcM4CMoMPq8NsE7NR5W11lhAnqVELniFgPQMCgHIl08qpVjDyoKTYmw6/B1stnPn68REXRwQWoXa+3KT6Uu5YCqsJgB7D/mDQxQn6WA240jHTvFM1h1ZK4c44ZDr57XBN4yGcuTjOnw9fP8IJUsj3rpqqX+HF9GKrAJWT5LZ59gc3PVERrYr8fsW7b//5g0C4uIjB79x0NRfgOwKbNYSs9K+6WTiOp+0CQco1AR40+Xx2WvmTSlWswU35W0AIycOuXglaLcbmrZWHbi0Mcnq9k5Q9cPOS30nuFQhw+i6O1qf1pewAHstjfqVXboTAOndqD3o7pfEP/VNMqil/s7kPnZFSqt4WHfEWM8sJeAqDSPKfobRc5uP8hL/efEeUTMoWnT2Ci32fO39w7ej9sXdWCfmaiWw4smXxis33O1mmo6MvjSjNeQys3JSdpRk3v1y9FJWQX71BxIRLaimPLsOJFRbaWfkyQEmXxS5g71GJUnyolJEER2x0iE9oNH1zY+Sq974Jothv+XmA/WBz9+EM3pxZVMdoNXi4BshL9K4hmlIveqTozdFGNxrv9e325we086FL2Dp5H/80GOXhbnVaHRqtYbv9vY/E+7bs4Uawab+Mt71TSMhDaEPYu465ZyuO2EQpgO9XIMS7q9pkIQv+vtivElg1jBKvVnor2uI51sitocMhQQq6RSmz8jsHxnzdL7REs0NwFya+OHatDvPhjjJ8hLiemO3smrNfY90OM+Q=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MWHPR2201MB1072.namprd22.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230001)(4636009)(366004)(64756008)(66476007)(66556008)(66446008)(66946007)(76116006)(8676002)(83380400001)(8936002)(91956017)(52536014)(2906002)(4326008)(33656002)(5660300002)(186003)(122000001)(71200400001)(75432002)(9686003)(53546011)(7696005)(54906003)(38070700005)(38100700002)(786003)(316002)(86362001)(6506007)(6916009)(55016003)(966005)(508600001)(26005);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?iso-8859-1?Q?xPl3QfnTB5+6IlBSxZOhtoXghoiynDX3rvo66N3xU6rC3jcrpGGatFz7VV?=
 =?iso-8859-1?Q?320OS9pi56k5BrmuIQu7RRwBHaBRaDtGkn30iUJnVVJEF9bJFF4kefqGQ6?=
 =?iso-8859-1?Q?PL9MH9miOcimk4Flb6LWFv2D3dP2jaMoi3v4G8g5ikZN95xJMswfotH+Av?=
 =?iso-8859-1?Q?l+Ir0trTwG2ovi4hILSSQn6LLSfLcQoe9ryBx9GK566v/m3uNgGFA3ECGZ?=
 =?iso-8859-1?Q?g9Q2tCC/+vguXeZiO8TMAFAhRK+utxGPOqQz3LyfanjG1eqbCGJiRiz6Nu?=
 =?iso-8859-1?Q?hqCI/SCdTkzuyoHMmbieJM8G0TNvwyRab0OyPUIEp/4M55w9NOmCOTqAMp?=
 =?iso-8859-1?Q?UAoaWd1dOM/KXLUQRIVVmkwbC4rjYTYDeb7mW4EuWeDJbURnqJ3jgwBE/8?=
 =?iso-8859-1?Q?ZB4ZEOHNDIQOppkRMzXzWVSVd4sW7DszaBuEmB9zL4pkSdWXDHa5XtzPaY?=
 =?iso-8859-1?Q?BYkQtdv6oDqfFhIj2UU/Dy7nWbFPbhdcAsbKD5qudaUUE1VYdA52vwCOcL?=
 =?iso-8859-1?Q?uzTLi8gHBeSFFU45HQ2jMpDEEufm5z6MCBVs8hXDv576s7g1ZKY7vYD1iX?=
 =?iso-8859-1?Q?7Vsb+tYxZ5Gt2Lr7Htl+Q45tmq7J4e01P6XbXpoTjO3oovkekC9ccrSri5?=
 =?iso-8859-1?Q?8wznbHQEVFaC9M+1cUImujLl5pNYVawO9gS6wtn/uovBnW5+vYXu7BcICT?=
 =?iso-8859-1?Q?eQCtJlKkPXPwrY/EIOZUSvUlt7Ld0r1c/6nSqIjy3ABGFE/qn6KYfsoJv+?=
 =?iso-8859-1?Q?2Md5v7Eg0Z+nHXk9maJHrPBo0t2gxQ4cB/Obk2UgQKI7b8lZVpGalCYIii?=
 =?iso-8859-1?Q?8db37T9JmVqLM4apMnE0rslf8t9CgfOu003TEYFmT2U6wsUfW828hI2BH2?=
 =?iso-8859-1?Q?PFh1vylcgS6QLkw9EVHSeJAh+LO44tFHFldNQpH+wpWyrRasCh4KFTviKn?=
 =?iso-8859-1?Q?r5FPn7/FOegsa9IyT9rolAceIfGzTBqJMInr0UmtTO3ie1w9irLTr7CP1V?=
 =?iso-8859-1?Q?9UpY7NdW3csCMBR30mwfVoVv24mZwaa8rYAhqtHuG60LVk/Ic1mpPvHC/R?=
 =?iso-8859-1?Q?FfvfEEUeN3AlIxbsoq5W3aaUVeinomKgo1JfGfKZ2sIHK7y7o+SyNjoOlG?=
 =?iso-8859-1?Q?AqbVVC1jf18eDWX34O+S9qyNi74zaRdlbA7CPPD4ItV9IbvUZToZb4QEie?=
 =?iso-8859-1?Q?0HoC4lummF83a1U08jjYRcqcpEAIxM9TpcRIuG0tn4UtWfeOJpVjsZiWiT?=
 =?iso-8859-1?Q?XMwzzpzHNxvc4lhwd+zVfWdZfpuOkYtHYP7JxeJJSUXT0Ydmju6KZl9fub?=
 =?iso-8859-1?Q?JWPjbSdQi0PmkAhQR5p+8FBk+7zRH+31kGrNpk643kWqzadXAgvNEmTG8o?=
 =?iso-8859-1?Q?0LuCzDPBsrdijFnCbyKbXSaLEiOFN44KenkNtGY3vBR1JHrNIqlUnZu9NM?=
 =?iso-8859-1?Q?w8dUW4EBDRa+JZ9675shTfHVxjsroWSNbItxlaS2UdWXNxTWSZCrflvSyI?=
 =?iso-8859-1?Q?dm0E77mxQQQBxH2S0MntdGgpaXGsNpYOs6w8O78HJqN6Hfn0HXmokwnP9E?=
 =?iso-8859-1?Q?XQHHR2oK8zAIvAAjLFmWE52OyZYetRGh36SJEI5pFRo/WHcQ6vSu/8zaOV?=
 =?iso-8859-1?Q?Oxhx/6m2cC4tP3gtaWZECrONenhKl27wbfDOnw6hj4HsDBPPeRuGrLkDJw?=
 =?iso-8859-1?Q?tmDa6s6mGl9P8/KrmMv+Hg5UsjckcW4kswneRqog0/h2v+c1Ym0l7DO2RS?=
 =?iso-8859-1?Q?zbn8R5+dI8uXzdPjiPThoWUukradMk+Wk4pc6B80O9/346?=
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: purdue.edu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MWHPR2201MB1072.namprd22.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 9745fced-50d0-4071-269c-08da3b4b93f5
X-MS-Exchange-CrossTenant-originalarrivaltime: 21 May 2022 17:01:41.7093
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 4130bd39-7c53-419c-b1e5-8758d6d63f21
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: 6EMUhxYqlyCUA88nNNYRcuP36RFm+hVB6zoBeRsS7U/ar3ZJxSMOCwi+d4qYh/KdDZ0JqGsnnkY3NEftrd6a4A==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY4PR22MB0088
X-Original-Sender: liu3101@purdue.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purdue0.onmicrosoft.com header.s=selector2-purdue0-onmicrosoft-com
 header.b=Sc8yrzLr;       arc=pass (i=1 spf=pass spfdomain=purdue.edu
 dkim=pass dkdomain=purdue.edu dmarc=pass fromdomain=purdue.edu);
       spf=pass (google.com: domain of liu3101@purdue.edu designates
 2a01:111:f400:7e8d::71a as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=purdue.edu
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

I just collected some call stacks when `__sanitizer_cov_trace_pc` is recurs=
ively invoked by checking `kcov_writing` flag.

Here are some examples:

__sanitizer_cov_trace_pc+0xe4/0x100
trace_hardirqs_off_finish+0x21f/0x270
irqentry_enter+0x2b/0x50
sysvec_apic_timer_interrupt+0xb/0xc0
asm_sysvec_apic_timer_interrupt+0x12/0x20
__sanitizer_cov_trace_pc+0x91/0x100
file_update_time+0x68/0x520
pipe_write+0x1279/0x1ac0
new_sync_write+0x421/0x650
vfs_write+0x7ae/0xa60
ksys_write+0x1ee/0x250
do_syscall_64+0x3a/0xb0
entry_SYSCALL_64_after_hwframe+0x44/0xae

__sanitizer_cov_trace_pc+0xe4/0x100
_find_first_zero_bit+0x52/0xb0
__lock_acquire+0x1ac2/0x4f70
lock_acquire+0x1ab/0x4f0
_raw_spin_lock+0x2a/0x40
rcu_note_context_switch+0x299/0x16e0
__schedule+0x1fd/0x2320
preempt_schedule_irq+0x4e/0x90
irqentry_exit+0x31/0x80
asm_sysvec_apic_timer_interrupt+0x12/0x20
__sanitizer_cov_trace_pc+0x75/0x100
xas_descend+0x16b/0x340
xas_load+0xe5/0x140
pagecache_get_page+0x179/0x18d0
__find_get_block+0x478/0xd00
__getblk_gfp+0x32/0xb40
ext4_getblk+0x1cf/0x680
ext4_bread_batch+0x80/0x5a0
__ext4_find_entry+0x460/0xfc0
ext4_lookup+0x4fc/0x730
__lookup_hash+0x117/0x180
filename_create+0x186/0x490
unix_bind+0x322/0xbc0
__sys_bind+0x20c/0x260
__x64_sys_bind+0x6e/0xb0
do_syscall_64+0x3a/0xb0
entry_SYSCALL_64_after_hwframe+0x44/0xae


__sanitizer_cov_trace_pc+0xe4/0x100
prandom_u32+0xd/0x460
trace_hardirqs_off_finish+0x60/0x270
irqentry_enter+0x2b/0x50
sysvec_apic_timer_interrupt+0xb/0xc0
asm_sysvec_apic_timer_interrupt+0x12/0x20
__sanitizer_cov_trace_pc+0x9a/0x100
__es_remove_extent+0x726/0x15e0
ext4_es_insert_delayed_block+0x216/0x580
ext4_da_get_block_prep+0x88f/0x1180
__block_write_begin_int+0x3ef/0x1630
block_page_mkwrite+0x223/0x310
ext4_page_mkwrite+0xbf7/0x1a30
do_page_mkwrite+0x1a7/0x530
__handle_mm_fault+0x2c71/0x5240
handle_mm_fault+0x1bc/0x7b0
do_user_addr_fault+0x59b/0x1200
exc_page_fault+0x9e/0x170
asm_exc_page_fault+0x1e/0x30

Looks like `asm_sysvec_apic_timer_interrupt` is culprit.

________________________________________
From: Dmitry Vyukov <dvyukov@google.com>
Sent: Saturday, May 21, 2022 4:45
To: Liu, Congyu
Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; linux-kernel@vger.ker=
nel.org
Subject: Re: [PATCH] kcov: fix race caused by unblocked interrupt

On Sat, 21 May 2022 at 05:59, Liu, Congyu <liu3101@purdue.edu> wrote:
>
> Hi Dmitry,
>
> Sorry for the late reply. I did some experiments and hopefully they could=
 be helpful.
>
> To get the PC of the code that tampered with the buffer, I added some cod=
e between `area[pos] =3D ip;` and `WRITE_ONCE(area[0], pos);`: First, some =
code to delay for a while (e.g. for loop to write something). Then read `ar=
ea[0]` and compare it with `pos`. If they are different, then `area[pos]` i=
s tampered. A mask is then added to `area[pos]` so I can identify and retri=
eve it later.
>
> In this way, I ran some test cases then get a list of PCs that tampered w=
ith the kcov buffer, e.g., ./include/linux/rcupdate.h:rcu_read_lock, arch/x=
86/include/asm/current.h:get_current, include/sound/pcm.h:hw_is_interval, n=
et/core/neighbour.c:neigh_flush_dev, net/ipv6/addrconf.c:__ipv6_dev_get_sad=
dr, mm/mempolicy.c:__get_vma_policy...... It seems that they are not from t=
he early interrupt code. Do you think they should not be instrumented?

Humm... these look strange. They don't look like early interrupt code,
but they also don't look like interrupt code at all. E.g.
neigh_flush_dev looks like a very high level function that takes some
mutexes:
https://elixir.bootlin.com/linux/v5.18-rc7/source/net/core/neighbour.c#L320

It seems that there is something happening that we don't understand.

Please try to set t->kcov_writing around the task access, and then if
you see it recursively already set print the current pc/stack trace.
That should give better visibility into what code enters kcov
recursively.

If you are using syzkaller tools, you can run syz-execprog with -cover
flag on some log file, or run some program undef kcovtrace:
https://github.com/google/syzkaller/blob/master/tools/kcovtrace/kcovtrace.c



> I think reordering `area[pos] =3D ip;` and `WRITE_ONCE(area[0], pos);` is=
 also a smart solution since PC will be written to buffer only after the bu=
ffer is reserved.
>
> Thanks,
> Congyu
>
> ________________________________________
> From: Dmitry Vyukov <dvyukov@google.com>
> Sent: Wednesday, May 18, 2022 4:59
> To: Liu, Congyu
> Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; linux-kernel@vger.k=
ernel.org
> Subject: Re: [PATCH] kcov: fix race caused by unblocked interrupt
>
> On Wed, 18 May 2022 at 10:56, Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Tue, 17 May 2022 at 23:05, Congyu Liu <liu3101@purdue.edu> wrote:
> > >
> > > Some code runs in interrupts cannot be blocked by `in_task()` check.
> > > In some unfortunate interleavings, such interrupt is raised during
> > > serializing trace data and the incoming nested trace functionn could
> > > lead to loss of previous trace data. For instance, in
> > > `__sanitizer_cov_trace_pc`, if such interrupt is raised between
> > > `area[pos] =3D ip;` and `WRITE_ONCE(area[0], pos);`, then trace data =
in
> > > `area[pos]` could be replaced.
> > >
> > > The fix is done by adding a flag indicating if the trace buffer is be=
ing
> > > updated. No modification to trace buffer is allowed when the flag is =
set.
> >
> > Hi Congyu,
> >
> > What is that interrupt code? What interrupts PCs do you see in the trac=
e.
> > I would assume such early interrupt code should be in asm and/or not
> > instrumented. The presence of instrumented traced interrupt code is
> > problematic for other reasons (add random stray coverage to the
> > trace). So if we make it not traced, it would resolve both problems at
> > once and without the fast path overhead that this change adds.
>
> Also thinking if reordering `area[pos] =3D ip;` and `WRITE_ONCE(area[0], =
pos);`
> will resolve the problem without adding fast path overhead.
> However, not instrumenting early interrupt code still looks more preferab=
le.
>
>
>  > Signed-off-by: Congyu Liu <liu3101@purdue.edu>
> > > ---
> > >  include/linux/sched.h |  3 +++
> > >  kernel/kcov.c         | 16 ++++++++++++++++
> > >  2 files changed, 19 insertions(+)
> > >
> > > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > > index a8911b1f35aa..d06cedd9595f 100644
> > > --- a/include/linux/sched.h
> > > +++ b/include/linux/sched.h
> > > @@ -1408,6 +1408,9 @@ struct task_struct {
> > >
> > >         /* Collect coverage from softirq context: */
> > >         unsigned int                    kcov_softirq;
> > > +
> > > +       /* Flag of if KCOV area is being written: */
> > > +       bool                            kcov_writing;
> > >  #endif
> > >
> > >  #ifdef CONFIG_MEMCG
> > > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > > index b3732b210593..a595a8ad5d8a 100644
> > > --- a/kernel/kcov.c
> > > +++ b/kernel/kcov.c
> > > @@ -165,6 +165,8 @@ static notrace bool check_kcov_mode(enum kcov_mod=
e needed_mode, struct task_stru
> > >          */
> > >         if (!in_task() && !(in_serving_softirq() && t->kcov_softirq))
> > >                 return false;
> > > +       if (READ_ONCE(t->kcov_writing))
> > > +               return false;
> > >         mode =3D READ_ONCE(t->kcov_mode);
> > >         /*
> > >          * There is some code that runs in interrupts but for which
> > > @@ -201,12 +203,19 @@ void notrace __sanitizer_cov_trace_pc(void)
> > >                 return;
> > >
> > >         area =3D t->kcov_area;
> > > +
> > > +       /* Prevent race from unblocked interrupt. */
> > > +       WRITE_ONCE(t->kcov_writing, true);
> > > +       barrier();
> > > +
> > >         /* The first 64-bit word is the number of subsequent PCs. */
> > >         pos =3D READ_ONCE(area[0]) + 1;
> > >         if (likely(pos < t->kcov_size)) {
> > >                 area[pos] =3D ip;
> > >                 WRITE_ONCE(area[0], pos);
> > >         }
> > > +       barrier();
> > > +       WRITE_ONCE(t->kcov_writing, false);
> > >  }
> > >  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> > >
> > > @@ -230,6 +239,10 @@ static void notrace write_comp_data(u64 type, u6=
4 arg1, u64 arg2, u64 ip)
> > >         area =3D (u64 *)t->kcov_area;
> > >         max_pos =3D t->kcov_size * sizeof(unsigned long);
> > >
> > > +       /* Prevent race from unblocked interrupt. */
> > > +       WRITE_ONCE(t->kcov_writing, true);
> > > +       barrier();
> > > +
> > >         count =3D READ_ONCE(area[0]);
> > >
> > >         /* Every record is KCOV_WORDS_PER_CMP 64-bit words. */
> > > @@ -242,6 +255,8 @@ static void notrace write_comp_data(u64 type, u64=
 arg1, u64 arg2, u64 ip)
> > >                 area[start_index + 3] =3D ip;
> > >                 WRITE_ONCE(area[0], count + 1);
> > >         }
> > > +       barrier();
> > > +       WRITE_ONCE(t->kcov_writing, false);
> > >  }
> > >
> > >  void notrace __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2)
> > > @@ -335,6 +350,7 @@ static void kcov_start(struct task_struct *t, str=
uct kcov *kcov,
> > >         t->kcov_size =3D size;
> > >         t->kcov_area =3D area;
> > >         t->kcov_sequence =3D sequence;
> > > +       t->kcov_writing =3D false;
> > >         /* See comment in check_kcov_mode(). */
> > >         barrier();
> > >         WRITE_ONCE(t->kcov_mode, mode);
> > > --
> > > 2.34.1
> > >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/MWHPR2201MB10723CCBB4869738E4BDFC36D0D29%40MWHPR2201MB1072.namprd=
22.prod.outlook.com.
