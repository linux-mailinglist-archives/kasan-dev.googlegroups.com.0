Return-Path: <kasan-dev+bncBCWJVL6L2QLBBJWHUGKAMGQE6R7P7KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id CB03652F833
	for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 05:59:34 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id v124-20020a1cac82000000b003948b870a8dsf7123705wme.2
        for <lists+kasan-dev@lfdr.de>; Fri, 20 May 2022 20:59:34 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1653105574; cv=pass;
        d=google.com; s=arc-20160816;
        b=vnw1bSqcQOlUFg42pc8YHLfw3b6MO9adjk/b0kU7xh1hHeu76e4mL/cj/64DYnM3Ch
         M8cUICPqJYFz0tRGfdlmEllRxSlzF79Pxf37quEu5GM3vO9al+r0mIhb4QZYVU1DOvu0
         ho0WccoSbEF4Fz6U/AiJeJwEgvVUhhRL488cytGeJQfmuEQqDx+RCi5cYfYUurqyjhzB
         sABWYI4ljImYVUTIT3Y9jETPniFQhVoBwGGbbbr9G46tRPXdbp3rt31j+5XEJFYZrUPe
         U+oeYgihsA6B5kiiavKbEDFmCrOdfGkzCanV9mjTjkkO4zv/+kUJKa6zevooVYtTWj6C
         oDAQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:suggested_attachment_session_id
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender
         :dkim-signature;
        bh=3L6dbwqz5NXSrNSs5S9/96HYMqYwLhHA1P+4mlWhz4c=;
        b=pRi7gp358xiLpFkpqS6XLZ3D11LvXm8oliWjy8ObNtS9T6DoxhQk4VBXGUOrcMoQXE
         827EZDxgJGMxDDZnWFa6b7RgJ08QsrMmy/fg3cNcGLnG8IBZwopIB6T5L0U49SG0dc2+
         5qXAP3vNDSo+nR6bkSY5h2vxQ1xm8/OW1fczQyq4mmc7XK/ZjZQ61YU84P0wijQAGoXa
         3T0fhBU387gPSdIMHAaEWHU7JPs3exgrmroccGCBvLs3BaSOgNX9tl2gvUZ6GX9BT8yy
         JOBbsUoJIy6K8pPKdlXI1DfyzM8VuKHqAIhKI2mczESuFFyJkJj3fNEcslNblYoieakb
         W1LQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@purdue0.onmicrosoft.com header.s=selector2-purdue0-onmicrosoft-com header.b=sup8Q42P;
       arc=pass (i=1 spf=pass spfdomain=purdue.edu dkim=pass dkdomain=purdue.edu dmarc=pass fromdomain=purdue.edu);
       spf=pass (google.com: domain of liu3101@purdue.edu designates 2a01:111:f400:7eab::725 as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=purdue.edu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :suggested_attachment_session_id:content-transfer-encoding
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3L6dbwqz5NXSrNSs5S9/96HYMqYwLhHA1P+4mlWhz4c=;
        b=AOc/ODkn2e3Rvjl0vacK08JihbYNy1TTa2OjAxA1BSMD27KcUTZ9u8Rof3QXQfFNVC
         jg758KTZhpstEAaB9MaEBMDWvFRXHi11xz1bk4HiKS29IEGbgY1tvUXjmi/9sRrg0zEb
         4/INlzCen3hQ0gDzpb7XycgFemwpegSGDIb2ZDt39AWbNfu+enuNfWd0ds5aMfVoRyQN
         MKf0vPyYRxAK1LXBlzOIZYdEzzi9jLgIlZY3N7FeLCsEuHLS3AETI9RL4rbwjrLcUMSa
         5h2G7HkO0nnVUnzldSFKX7SZXFserpeb5xerQqPdlwiz7VIiTmCd4cxD/x8G2ZSiPv7a
         Nzeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:suggested_attachment_session_id
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3L6dbwqz5NXSrNSs5S9/96HYMqYwLhHA1P+4mlWhz4c=;
        b=TSHtPJWOFAysSYbIDjUEc1h57yPdI0/ICUpW/vHgVju8EXytt3i3TL+afDxQsYJHhQ
         LzbTkTmI8LVVA6RrKdxzMRCVbdkILlKM71kga339xX+Wi7B3k4TM0ikM+5Z+KsNA79rv
         eBQFHZ0U/44FbKelQg+lOBy/ECv1lopJOiln6vapDw5l/e7dcnfBxe8v+sP/b+1NGvGu
         MdDkehm1wIp8kGH96nVAl+G28O4Px60Ji0PGP/ekja3vKwrLwY4/sIygPkHCaD96wAlZ
         lc8BNJd1sjj/2QnpA2ju1YRxheMc7wfAt8v47qi/MjreXgef4p+KV7C/LwB+pfHuqcbH
         92QA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/PIoDlRH80T5Bm57IFchAXVO98xB5NAwR1GaqK6IxSExBlhRA
	+XluROELhoQ6Mzlf++iHHo8=
X-Google-Smtp-Source: ABdhPJxnaY3gdjiKwOLbhEWjyeGDOUFCLq23QLWa5avyOD20P6mPREDB92ch4NwTS9ODeYlL7NoEiw==
X-Received: by 2002:a5d:4b92:0:b0:20e:5d73:7546 with SMTP id b18-20020a5d4b92000000b0020e5d737546mr10930934wrt.322.1653105574260;
        Fri, 20 May 2022 20:59:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1e0b:b0:20e:7a8a:8c81 with SMTP id
 bj11-20020a0560001e0b00b0020e7a8a8c81ls4458138wrb.1.gmail; Fri, 20 May 2022
 20:59:33 -0700 (PDT)
X-Received: by 2002:a05:6000:18a2:b0:20e:6698:924 with SMTP id b2-20020a05600018a200b0020e66980924mr10370708wri.385.1653105573299;
        Fri, 20 May 2022 20:59:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653105573; cv=pass;
        d=google.com; s=arc-20160816;
        b=mbZmYi2GT4QBT5eyBZD7JRAstxRE3Q/pDhhL7Lf3tZQVsD5qLg6p6E2ZuKj//83Mu9
         l4skTOvsUGQINgwaU46mHZp+c2tLe9feIZb5mHUkuZjLX2KcB54K4Y1mKc1DcHuYo2Ng
         6Z+DxpVxmALh5MFrzi2PRogRvqILfXY9jchzglQECnObE1veLinuD9lSQ1N6sgVbSJeG
         m7M5SysMq01nmEup5Hw12dTdyrqoR/K5kRGxJdVDwAfOcWUwWwXCWVlu/jeDwxSqcwCQ
         sJqnBTolFy//iuceV+vBFgBxN6PTLa0FQ4YjCSVviJlL9oqaL5JkCOjCHjj9LgbClA69
         YNjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding
         :suggested_attachment_session_id:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:dkim-signature;
        bh=f1fk+VS7vZY/YdCR5d8x3fPkjxvFwwedu3VhuJfmTPY=;
        b=CpDyhFzhERSB3uxcCvddjG4Ph0F88KGNRCNOVnek4Op3W1EFpPDTqHqwPfgj/y2Lnt
         XHivLubb3LhXo+42ETU0R9Jt1mvI+oblnJ7AiqiMylhuuM48pE4OcE7u1kNfMtp5bj5F
         YxFuMnDdntoXaWw4s1El4AXFNGGWiCHhd0GpzUURsohwJBvwSK14VYbpAD6yCadI/DDM
         3drCVerMEwa+9EJo/ykntaw1lBrXHvUzxP5H6Rfq1lh8NC+dpdr10v35UcQD4wB8P+UN
         +LgBSOtnvWxbxM3o6mZi2ONbFkytrpqMOxmA/Hujh+QqRXwrnSLlBMa5i8wE6UbSzVRz
         ry2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purdue0.onmicrosoft.com header.s=selector2-purdue0-onmicrosoft-com header.b=sup8Q42P;
       arc=pass (i=1 spf=pass spfdomain=purdue.edu dkim=pass dkdomain=purdue.edu dmarc=pass fromdomain=purdue.edu);
       spf=pass (google.com: domain of liu3101@purdue.edu designates 2a01:111:f400:7eab::725 as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=purdue.edu
Received: from NAM11-CO1-obe.outbound.protection.outlook.com (mail-co1nam11on20725.outbound.protection.outlook.com. [2a01:111:f400:7eab::725])
        by gmr-mx.google.com with ESMTPS id 190-20020a1c19c7000000b00396f5233248si209428wmz.0.2022.05.20.20.59.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 20 May 2022 20:59:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of liu3101@purdue.edu designates 2a01:111:f400:7eab::725 as permitted sender) client-ip=2a01:111:f400:7eab::725;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Vs7CqCHh+gMM4HXAhIaxRCEXBNjz5JF/+6yt6RDqxWc4/F811OmR2O2T0yIxtsV18j9Vm487lAY4vj6aoZXkKjN013m2Tu8LiqdraFRGu2/yKLiiDAfZUMC7C3n9cSRIK1DUdpMCopXkKATPaREIstgLdScELaE9BZzCX77v7NnQi8ZQp8N7oHFrrXMwOHRvRnOXr33u+6vS+vqLiiJyFMA5fVrFA1U4Qz575rYdOliTRJrfZRuytCzbjZisG0q3JjF3vEyrRqY9/QnLZCIOeyJSp0uJOkgS8n1tqs2YaWaxGYu37//Ekbe4AfV7hXcRuWcmZ5Yy7n2IfTVgUZcMIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=f1fk+VS7vZY/YdCR5d8x3fPkjxvFwwedu3VhuJfmTPY=;
 b=C0hLIpo98YWbCteTIJ4jdzJZIKEUGrIxgcWSAUtxvyDNqo+EpuvXERzY72GfMfvTuOC5cEXVauiS2eBLokV0bSiZ9v1AEb6dd4tZYG20DbXOUcpuwNVRVjqpDi9vmGVy9pgoeKdl+XkpCV0gt7Y/wyFNLkhUgX1qJ83yQtttmoChbSC+kiQIkCpUntIElC0MF6SGKp4UOtEOmL4tvLZcqBSRPjQ3kwTw0bZIGvzWwiL/+rDO4jMkiN0YQfk5HP7ojWt9fOkXrzLDNmb4ISwBI4Gz0NoH6d9yTiBLHH3mPa1szwklEPspMZ+qGoS3Zrn6qypBi5w5x8zl+sjjz7C39w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=purdue.edu; dmarc=pass action=none header.from=purdue.edu;
 dkim=pass header.d=purdue.edu; arc=none
Received: from MWHPR2201MB1072.namprd22.prod.outlook.com
 (2603:10b6:301:33::18) by DM6PR22MB1899.namprd22.prod.outlook.com
 (2603:10b6:5:22c::15) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5273.19; Sat, 21 May
 2022 03:59:29 +0000
Received: from MWHPR2201MB1072.namprd22.prod.outlook.com
 ([fe80::a9e9:b100:2a55:23aa]) by MWHPR2201MB1072.namprd22.prod.outlook.com
 ([fe80::a9e9:b100:2a55:23aa%3]) with mapi id 15.20.5273.017; Sat, 21 May 2022
 03:59:28 +0000
From: "Liu, Congyu" <liu3101@purdue.edu>
To: Dmitry Vyukov <dvyukov@google.com>
CC: "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] kcov: fix race caused by unblocked interrupt
Thread-Topic: [PATCH] kcov: fix race caused by unblocked interrupt
Thread-Index: AQHYajHoHiVYwAN8JUi5UTY5PvyBWK0kVeGAgAAA0wCABFjckw==
Date: Sat, 21 May 2022 03:59:28 +0000
Message-ID: <MWHPR2201MB10724669E6D80EDFDB749478D0D29@MWHPR2201MB1072.namprd22.prod.outlook.com>
References: <20220517210532.1506591-1-liu3101@purdue.edu>
 <CACT4Y+Z+HtUttrd+btEWLj5Nut4Gv++gzCOL3aDjvRTNtMDEvg@mail.gmail.com>
 <CACT4Y+bAGVLU5QEUeQEHth6SZDOSzy0CRKEJQioC0oKHSPaAbA@mail.gmail.com>
In-Reply-To: <CACT4Y+bAGVLU5QEUeQEHth6SZDOSzy0CRKEJQioC0oKHSPaAbA@mail.gmail.com>
Accept-Language: en-US, zh-CN
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
suggested_attachment_session_id: 23f74e33-808c-ea5a-2a90-797ae0dfa15e
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: f96429ef-c813-4230-ebb5-08da3ade4dc4
x-ms-traffictypediagnostic: DM6PR22MB1899:EE_
x-microsoft-antispam-prvs: <DM6PR22MB1899890D9DD90900E8573DB2D0D29@DM6PR22MB1899.namprd22.prod.outlook.com>
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: Q5zgBk3YBdJUEggLAhIqdhAXIJlh+cf/kFaLXCmYFNFpfD1db6tKWUuXhpZSSQ1qyTaUxtO2szaBqG5YNfaRlueDf9vEthdwgSC5G66buPLFgLUz8Y3YhkxfafEjc5oW2idS+EvJ6lwvhps4Doljx0rhsmQGZuPKTWYeJkIA1BW+W7W3DvqIOp17yp7vD2y2BRFFm+aP9zxREmXyZTAlsnBSx1U9cxklJcMN4wWmSdl6fHL6d6fT5HYWQAC9O88TQls1kgduGnHS2Mqs2nAAM+ZqCTHcflk0EiAHJICg5sokVI1tgmGiRR6dvOchdC21oYPmVxAgRAbaNNboQeZq9swoEjpWFcqLgDwcbQI3ossuJZ0/taMPqT0FIrLsKFob8CbyNPvHDFdHjFQ4O35qojcM0VI3ogweXQwTtIgrTl1hv472HJGJR712lp1nHHz2PIz8PuVDbUPKJ+pRBNNQcONmH409cc6zN0hZZ0VLyi6RkgpyM+1U/1AKyfF76/pgRHYtv5tguT/HSUPzbGm1i5imT2Wupeu2KgI/rVNUvA/pjS399aWVKFjSsHKmHmFcvxbE8KoC003+aOoYPxFTvzlgwxb2FxwCQ6Uf1L/rUnoTCDUnYeqBJ2ajfO1YMEGdnWv0J4v8E03PCnFzca7oEKIU8MXAuku4O9nOoBwM6sCRvGkCQF55CTQVgUbf7kwdmOuUgJHGVSBwMVwlGuaOzg==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MWHPR2201MB1072.namprd22.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230001)(4636009)(366004)(8676002)(64756008)(66556008)(71200400001)(66446008)(66476007)(66946007)(4326008)(6916009)(786003)(316002)(76116006)(54906003)(53546011)(86362001)(7696005)(9686003)(6506007)(26005)(33656002)(55016003)(91956017)(508600001)(122000001)(52536014)(186003)(83380400001)(8936002)(38070700005)(38100700002)(2906002)(75432002)(5660300002);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?us-ascii?Q?y/vqZzgxopixNtScHkiH+lxeTTk7e58D5t6dE/Q9B6F1luBc6o7GyTuydFJA?=
 =?us-ascii?Q?RwDUPx7il9LwABQAvG3BgqbyWTBVmOL7YleT4CVgxC7I+CDKKu7BwJ3SwTmN?=
 =?us-ascii?Q?dXoXHeu66AOsQbMPdMBNhFD+RtW6miKJ1BD52JY/RwXAMFw78VyTeqTyd7lA?=
 =?us-ascii?Q?PFs9U+jRXu4TRbrBhQ8PcupjgMHI3XzBxBzuivjGz5FcxYo1yVLaEhLMK8zA?=
 =?us-ascii?Q?BD+PRM00gJCgF+cy8Za6CqLKGd0RP/Pa/rMlMqHs0SSPxwMxVIaPz76jSGV3?=
 =?us-ascii?Q?k0QmALdlLzyqY1/CgDPYINUmQgA2e3I9kkCZ5Galfh7NjBOGs/ZFeCu8u63p?=
 =?us-ascii?Q?gouHLJRhrY7guX9/4vQt7yYMMnQTH7gq1jv51ykBpYYXUNEcWTABlQpFPG1A?=
 =?us-ascii?Q?1N4OFicfg9Lv/GPcWkf/DLlnfdiGyZgR5G7eBKlEu+cPzhmV850s5r+WyNdr?=
 =?us-ascii?Q?MsoNVezU73nq57EPIUPURtN3Avc2iyorBBGce0k1TmnLdIf62NUmaEI4sHJb?=
 =?us-ascii?Q?+8S7Ft2rHnNIMj3rzFQJV7MFzZMV4SpWJxCsq1r1NKxnO6dOM5GVlJCpjHIg?=
 =?us-ascii?Q?RIMxNqchCDiQrWShz1yJCWGFI4cLo1aveV3xlZL9N6NFCmRz4r7WDmQBWUQA?=
 =?us-ascii?Q?Ax0Qx30Acg5ijF1NifPLkdSGwtDcuv+Ssxj1GGebSirHLv+EIuKjs2lYF8q3?=
 =?us-ascii?Q?unnTJBFHP49OVfgqSFIXNR4CKADoIAL9yQDVzDiwV1zwr5ZnQHCt26B88P0E?=
 =?us-ascii?Q?S1CoGZu72tkboeNJn6TqZjW4udGrlAMaMcf9BK1YJkqEkenVu5AHloibbSAF?=
 =?us-ascii?Q?TqS2P3rrR9F1waUMZiMhRYrJXETSf7l+rEeHSeMS/lAmfQmaj8Ne0KwlVpiE?=
 =?us-ascii?Q?wRbPcaN+Ess0qL+68+Rd270nfMf6ts7/cvIAJNOZ585SQREtpbbwBzM0cquq?=
 =?us-ascii?Q?rhmFQ927L9/pQ0ucpTP0D5psADjuAZaRYsfXdTZy4g12j44Xs7E7KnFJpilm?=
 =?us-ascii?Q?sEj6x7QCFGwgj9SN/69ek4XoZ3O9EyX4AbjomntknPitRt7lpmdI2zpKhSt+?=
 =?us-ascii?Q?njmZALVlHtMfl1G3kop7msfph4AEJ1CiqA8UVdC3fK+VWPPUIOXZ/7z7o0ua?=
 =?us-ascii?Q?tBRsSaP93Y1cWb1ScXiiY/D3PB7JqaFR05TYuvv87uQLjA8oY2NCTBQlIKc7?=
 =?us-ascii?Q?Y/ZqwF8FGmt4XArkf2/9RC8YNwU3SIxouw22YTWMlBLB4wyoMDgXwjOSUcj5?=
 =?us-ascii?Q?3BCAp6ssBnKGqPGDVhLXUMXXE47FC6E49Hq8nRwOhXuxN7xrkXx9RU40+A9q?=
 =?us-ascii?Q?tOfNhYsppYW3O4+OAFyUBSY3ORliHEql73pBfuDt4EZxD0HpJnCx2XxQIyEA?=
 =?us-ascii?Q?j5/0UB6VmS4n1lI+kWwf22uwgpjWRAuLXRh0TIpWYJ6Or+jJ+TJXurgix5JH?=
 =?us-ascii?Q?+1QMpnYO+U4tdjDt7cCyVZynAhZoTfoSsiQW1upFSpZPKe7oVcTloSJ0BFLn?=
 =?us-ascii?Q?XP39AW6FFS1QZnsjYmOq1qw+lYnjNo1JG8R8O4c4YspM1+xOEK+vu6XkjbWY?=
 =?us-ascii?Q?Y4mDQsXSaCIfojQstLHTqg8LwmgzpX7A9CX8eSM01qA5ccCOg5IpNE32y4mw?=
 =?us-ascii?Q?pk2zGbddJiM9Z141CiPHUamlBGjsn5xxGfCRjArfC9bsh3wWrg+dVzpvRHDb?=
 =?us-ascii?Q?DzWStGMtVS8qEQWMrU1Bne/JdSvlerl5oIjnTfF6cA+F0+KD?=
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: purdue.edu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MWHPR2201MB1072.namprd22.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: f96429ef-c813-4230-ebb5-08da3ade4dc4
X-MS-Exchange-CrossTenant-originalarrivaltime: 21 May 2022 03:59:28.7935
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 4130bd39-7c53-419c-b1e5-8758d6d63f21
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: prKMpB+k3U2XJlXWBz6S0pToymLrjM7/U36C9lTWdD0UqhDK2j/LbUz0tG0XAPD9P86HjHWagegdoNzMD8mPeA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR22MB1899
X-Original-Sender: liu3101@purdue.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purdue0.onmicrosoft.com header.s=selector2-purdue0-onmicrosoft-com
 header.b=sup8Q42P;       arc=pass (i=1 spf=pass spfdomain=purdue.edu
 dkim=pass dkdomain=purdue.edu dmarc=pass fromdomain=purdue.edu);
       spf=pass (google.com: domain of liu3101@purdue.edu designates
 2a01:111:f400:7eab::725 as permitted sender) smtp.mailfrom=liu3101@purdue.edu;
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

Hi Dmitry,

Sorry for the late reply. I did some experiments and hopefully they could b=
e helpful.

To get the PC of the code that tampered with the buffer, I added some code =
between `area[pos] =3D ip;` and `WRITE_ONCE(area[0], pos);`: First, some co=
de to delay for a while (e.g. for loop to write something). Then read `area=
[0]` and compare it with `pos`. If they are different, then `area[pos]` is =
tampered. A mask is then added to `area[pos]` so I can identify and retriev=
e it later.

In this way, I ran some test cases then get a list of PCs that tampered wit=
h the kcov buffer, e.g., ./include/linux/rcupdate.h:rcu_read_lock, arch/x86=
/include/asm/current.h:get_current, include/sound/pcm.h:hw_is_interval, net=
/core/neighbour.c:neigh_flush_dev, net/ipv6/addrconf.c:__ipv6_dev_get_saddr=
, mm/mempolicy.c:__get_vma_policy...... It seems that they are not from the=
 early interrupt code. Do you think they should not be instrumented?

I think reordering `area[pos] =3D ip;` and `WRITE_ONCE(area[0], pos);` is a=
lso a smart solution since PC will be written to buffer only after the buff=
er is reserved.

Thanks,
Congyu

________________________________________
From: Dmitry Vyukov <dvyukov@google.com>
Sent: Wednesday, May 18, 2022 4:59
To: Liu, Congyu
Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; linux-kernel@vger.ker=
nel.org
Subject: Re: [PATCH] kcov: fix race caused by unblocked interrupt

On Wed, 18 May 2022 at 10:56, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, 17 May 2022 at 23:05, Congyu Liu <liu3101@purdue.edu> wrote:
> >
> > Some code runs in interrupts cannot be blocked by `in_task()` check.
> > In some unfortunate interleavings, such interrupt is raised during
> > serializing trace data and the incoming nested trace functionn could
> > lead to loss of previous trace data. For instance, in
> > `__sanitizer_cov_trace_pc`, if such interrupt is raised between
> > `area[pos] =3D ip;` and `WRITE_ONCE(area[0], pos);`, then trace data in
> > `area[pos]` could be replaced.
> >
> > The fix is done by adding a flag indicating if the trace buffer is bein=
g
> > updated. No modification to trace buffer is allowed when the flag is se=
t.
>
> Hi Congyu,
>
> What is that interrupt code? What interrupts PCs do you see in the trace.
> I would assume such early interrupt code should be in asm and/or not
> instrumented. The presence of instrumented traced interrupt code is
> problematic for other reasons (add random stray coverage to the
> trace). So if we make it not traced, it would resolve both problems at
> once and without the fast path overhead that this change adds.

Also thinking if reordering `area[pos] =3D ip;` and `WRITE_ONCE(area[0], po=
s);`
will resolve the problem without adding fast path overhead.
However, not instrumenting early interrupt code still looks more preferable=
.


 > Signed-off-by: Congyu Liu <liu3101@purdue.edu>
> > ---
> >  include/linux/sched.h |  3 +++
> >  kernel/kcov.c         | 16 ++++++++++++++++
> >  2 files changed, 19 insertions(+)
> >
> > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > index a8911b1f35aa..d06cedd9595f 100644
> > --- a/include/linux/sched.h
> > +++ b/include/linux/sched.h
> > @@ -1408,6 +1408,9 @@ struct task_struct {
> >
> >         /* Collect coverage from softirq context: */
> >         unsigned int                    kcov_softirq;
> > +
> > +       /* Flag of if KCOV area is being written: */
> > +       bool                            kcov_writing;
> >  #endif
> >
> >  #ifdef CONFIG_MEMCG
> > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > index b3732b210593..a595a8ad5d8a 100644
> > --- a/kernel/kcov.c
> > +++ b/kernel/kcov.c
> > @@ -165,6 +165,8 @@ static notrace bool check_kcov_mode(enum kcov_mode =
needed_mode, struct task_stru
> >          */
> >         if (!in_task() && !(in_serving_softirq() && t->kcov_softirq))
> >                 return false;
> > +       if (READ_ONCE(t->kcov_writing))
> > +               return false;
> >         mode =3D READ_ONCE(t->kcov_mode);
> >         /*
> >          * There is some code that runs in interrupts but for which
> > @@ -201,12 +203,19 @@ void notrace __sanitizer_cov_trace_pc(void)
> >                 return;
> >
> >         area =3D t->kcov_area;
> > +
> > +       /* Prevent race from unblocked interrupt. */
> > +       WRITE_ONCE(t->kcov_writing, true);
> > +       barrier();
> > +
> >         /* The first 64-bit word is the number of subsequent PCs. */
> >         pos =3D READ_ONCE(area[0]) + 1;
> >         if (likely(pos < t->kcov_size)) {
> >                 area[pos] =3D ip;
> >                 WRITE_ONCE(area[0], pos);
> >         }
> > +       barrier();
> > +       WRITE_ONCE(t->kcov_writing, false);
> >  }
> >  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> >
> > @@ -230,6 +239,10 @@ static void notrace write_comp_data(u64 type, u64 =
arg1, u64 arg2, u64 ip)
> >         area =3D (u64 *)t->kcov_area;
> >         max_pos =3D t->kcov_size * sizeof(unsigned long);
> >
> > +       /* Prevent race from unblocked interrupt. */
> > +       WRITE_ONCE(t->kcov_writing, true);
> > +       barrier();
> > +
> >         count =3D READ_ONCE(area[0]);
> >
> >         /* Every record is KCOV_WORDS_PER_CMP 64-bit words. */
> > @@ -242,6 +255,8 @@ static void notrace write_comp_data(u64 type, u64 a=
rg1, u64 arg2, u64 ip)
> >                 area[start_index + 3] =3D ip;
> >                 WRITE_ONCE(area[0], count + 1);
> >         }
> > +       barrier();
> > +       WRITE_ONCE(t->kcov_writing, false);
> >  }
> >
> >  void notrace __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2)
> > @@ -335,6 +350,7 @@ static void kcov_start(struct task_struct *t, struc=
t kcov *kcov,
> >         t->kcov_size =3D size;
> >         t->kcov_area =3D area;
> >         t->kcov_sequence =3D sequence;
> > +       t->kcov_writing =3D false;
> >         /* See comment in check_kcov_mode(). */
> >         barrier();
> >         WRITE_ONCE(t->kcov_mode, mode);
> > --
> > 2.34.1
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/MWHPR2201MB10724669E6D80EDFDB749478D0D29%40MWHPR2201MB1072.namprd=
22.prod.outlook.com.
