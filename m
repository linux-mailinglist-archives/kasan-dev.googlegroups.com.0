Return-Path: <kasan-dev+bncBDLKPY4HVQKBBFEJ5GHQMGQEY333UII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 20C9A4A6D19
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Feb 2022 09:45:09 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id m3-20020a7bcb83000000b0034f75d92f27sf2188877wmi.2
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Feb 2022 00:45:09 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1643791509; cv=pass;
        d=google.com; s=arc-20160816;
        b=KxLYQP8ep6qqdbIkPkc37VUtMYU1dHh4dJq1YjwSQJwzLPSpyvbfr46YeuRhg22CCS
         qmYjtHDQT7+U0jVEt+UCpo8HQA4KUtkNc5hvIWtyVG+lYpsFkMbQlWGIoG7G+8NkMj/V
         aNcgRnLfgnz8KJ45aHOMRAgsLUseXYaZ/i/3lqFsHJK4VxqxBqfawmiKWjH7P9Tx1EXZ
         gB+mMz9or2rzqYaqOOWytg4UAWHaXEn5Q51mmuOjLx8Soq2GJGDfr0ZLIFNTcdrW382V
         oH6BsvK0TdL47vZI0nFO95YdwQbrAvKMX0WfTaOIe8cP9WQ4C88CjsmfvPhaH6iX3ELE
         TsEQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=S06UOHqruqqVbNthqOr/5U6PXk40jSsE22JOoLG648A=;
        b=cwoa0H5bmMsFT/XnLg3OamAKX/tVuDj4qD3ooDedVOrtJp/JKgYaooj99CqB776WjN
         HITO6iHyhM8tLPAXWxmuVr8WTuwP4Gvu+g7JDnbntuds3NbEyq4QaZY2vmiowfPckklU
         w8sEWd5LN51GZ3jZLd/spaUBN3oPFH5Hxew13KCjy5YQOD2sCuK3J/VSjK9Kiu4AHU4x
         eF4LYrmayuEZz0Ea/8QgDuleOZnZT2/VkQaFCEZ5+bj3qepVNqxtYLIktjW9gN7z8xAy
         g0SZi0IO0Kh2DkBJGKZLYyS/NCoTf8zbxaRDhv7RyDB1rQXJ5ZIC7uTdCShEIAhXhJbk
         qQCA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       arc=pass (i=1);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::619 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S06UOHqruqqVbNthqOr/5U6PXk40jSsE22JOoLG648A=;
        b=e59vnxVb8OewSxIenBlmQUYxbPh7PMpIzfTOst+CYaB/57dM6c39TW3Wp80VjGdoVH
         8Wl163RnQ5Ppi0VBcWbzzf+OgcDu+PykOCkzRPKDUFutbT43BsBfKqIAw3YktSJ+Tomk
         hrUSDgpmEDgnFwIpwT44IygV1+erTX/7TkhwPyM9gqWqDirPwQfXqkhBXEwcJhUGx3ps
         qcdB2DsbZL7da/Vy1Xi+b9o0VsMeFACn/1TC9J/SPhvm/P8RuytvYpBt+1plFfH1upOw
         PA51bBMy7qoyhT8HklWgyHOV2O/LD3G+i/biX65Z7LPhS2BbFJfbNAqCRHdg+g9zGGaZ
         jI2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S06UOHqruqqVbNthqOr/5U6PXk40jSsE22JOoLG648A=;
        b=g1A6aH3hZJqXk7/zMrpw9BkikLeVH8Lnpm+4Z8c3tCRo0T8yPcon3gkHCPwy/OcU+i
         VZBc/VFlx41TodDTqvrua4KnMKHyOekee+W3PpA1VQPGADDWMnPe3B3puWYoreJNpn98
         tvz8e3e8/VjLHDSMKDiwARHLAZY98rwUwRHbnmIvPZKmJpZ0JONXN989AhCo3DRmForr
         3wG5Wm0JuqfADDGh12h/KYCaCmC0i7pFFs7izVefdATmE6eGJ6aVLkyFxOPPHe1XKL7R
         UZ/OyCO5bP8ziIDkWtO9Wzcubn4/tiqq+q91wzJvIyrfbuZ9oWceS3+ex7pxF514/Lyj
         8KmQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532/BZqgUW+DWZPPCBccRY941sl9qUv8xesJubr+gkxZjp7oZfsK
	jjAaDjvWE538AeHyRsE8AGw=
X-Google-Smtp-Source: ABdhPJykczNkm6k7N4Jx5z58Ge4KhEtkR5FWWxuuPOXmdaF56wVRZSd0gdnrkcmkzT9HCgy1ye+Nqg==
X-Received: by 2002:a1c:7410:: with SMTP id p16mr5070153wmc.16.1643791508781;
        Wed, 02 Feb 2022 00:45:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:3c8:: with SMTP id b8ls334361wrg.0.gmail; Wed, 02
 Feb 2022 00:45:08 -0800 (PST)
X-Received: by 2002:adf:d090:: with SMTP id y16mr23589489wrh.18.1643791507938;
        Wed, 02 Feb 2022 00:45:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643791507; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZVL6XV9xaZlVF7rJcg/NrCaYnCUosWab5xIcryTElSt/knPZF2l1s26CnYNpMYnp/k
         JOAobFJ3Z9jlFpdoMzbZQ88HrDcw+pBwCor+AsgSsV2nqlFVBXZXxn1fOwkN6nSZb/ue
         BYCfF3mgSGe3Hkxj3Ews+8z5ehqo56mKoHnBzOCUAmM2aV99sB80Xkk8ph/s5N/w+TtS
         8HvnT5yVQTurAQUoLs3g2m4DA9yL9MhevT7gok12DVkhCucmjLLQe5hjMgioOEyXYdkU
         0fm2pFVwLn/jraaHJAJ1CGcBUA1p/3ie8Q9y03JBN/JcnWRYi8695lJ/hJX3mv7IziHV
         3LDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=dHXMQs7YgD3Yni5ZkwlbHjK3NnL1xtKJYyaAF37axAM=;
        b=utwZ5yw86kCx1odDh/6gZRDaRg7yvt07f/D+nZk35Yl86GS/2i6JWdrNxbE+3TqCmC
         +IhqkSrluXcrPUN5eh99o+y4yFJ5PHLQaRpdOWUNCfUS+mIl133dtY5mXC4BPT/0eh3E
         A+etRHKMYr55vZScq23O4zz0AYMVaWyI/nkeDyr0nYW/GisG5PIpqJlVgcf0rhNApOSC
         Zoc2BZFHO5xE4mC+QUuBROpez3QVpiqYqEISdVc/55rzC0BiT16gH1iYgSre1R9TDWTn
         dWNT62ww4sKzH1eC8B1qNp3VPgQ3S6WcI0m7J1YCOuBSE+8NuYUVpErhjFwRf8otXuTc
         m+TA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       arc=pass (i=1);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::619 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from FRA01-MR2-obe.outbound.protection.outlook.com (mail-mr2fra01on0619.outbound.protection.outlook.com. [2a01:111:f400:7e19::619])
        by gmr-mx.google.com with ESMTPS id p4si175329wmg.1.2022.02.02.00.45.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 02 Feb 2022 00:45:07 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e19::619 as permitted sender) client-ip=2a01:111:f400:7e19::619;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=hguDEE+NBXdcyPFFzb1mLGthJrIPbWO2736/inkZtOYcJO3riOMekimiHyfxMMczBu4gCZ0vUJ9SR3yl5WLhTZbCEia3aBgRfTeJhcI8e1WwfqJCo4446q/ceBi9IKfMagiRGU+CdPckxO+uCGojIHjGJaD5/XOuTOo43Lc5DEHEuihdEqhO2viDV8v77asUbYlTwmBoBOPW8xAe9oSm+CE7fZiBTRbRbbmSxTw4FtA7KAUjMxEVgmCz2WjEfUpazfdZXqwmTUSqclymo3owePfUFfewwSZppqiBqD7ebDC8bjv8q6VirzfjflPjswGygJEfispn7wIBLsjlVlTy9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=dHXMQs7YgD3Yni5ZkwlbHjK3NnL1xtKJYyaAF37axAM=;
 b=Nwhc9D1o3NSsLT+diQRgH4sMHDA/1SvZssW5OJsDdNQE4UFxxuFlAfYvO0s6gfs1AYqqE7e8xHBXuXdKFanZNze4qdFHryODFQCT2qXRugeoxl83tIWcwea+I9EgbxiLdgTI1e4/Ts5UV4azYp5+2wzAgSG3TO1vEQ5f46NjgYIBpqwProK+/CwKL7rC78INBW5LVOHD36wgjOXmzlWXtegdHeD+3LwkObA8dRHm5Zh4e+NJuRFrnzrD7T1VJfXlR8fgrBNAXFRFTRNZD+t9lb4NAhauPg9EnL9kpaaOxu970/DZN2msjZLCDUY8Kh5LskFLLpc0WU7uPykfS5jZsg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by PAZP264MB2847.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:1e7::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4951.12; Wed, 2 Feb
 2022 08:45:06 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c9a2:1db0:5469:54e1]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c9a2:1db0:5469:54e1%9]) with mapi id 15.20.4951.012; Wed, 2 Feb 2022
 08:45:06 +0000
From: Christophe Leroy <christophe.leroy@csgroup.eu>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>
CC: Christophe Leroy <christophe.leroy@csgroup.eu>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "linux-hardening@vger.kernel.org"
	<linux-hardening@vger.kernel.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>
Subject: [PATCH 4/4] [RFC] risc/kasan: Use kasan_pXX_table()
Thread-Topic: [PATCH 4/4] [RFC] risc/kasan: Use kasan_pXX_table()
Thread-Index: AQHYGBEtLm+UnIWHmE22p3QOjbJy3A==
Date: Wed, 2 Feb 2022 08:45:06 +0000
Message-ID: <1f88cb32e438f9f29f45ae56849ac3fd94ec8a54.1643791473.git.christophe.leroy@csgroup.eu>
References: <a480ac6f31eece520564afd0230c277c78169aa5.1643791473.git.christophe.leroy@csgroup.eu>
In-Reply-To: <a480ac6f31eece520564afd0230c277c78169aa5.1643791473.git.christophe.leroy@csgroup.eu>
Accept-Language: fr-FR, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 8abdb104-f1be-40e2-ac9c-08d9e6285011
x-ms-traffictypediagnostic: PAZP264MB2847:EE_
x-microsoft-antispam-prvs: <PAZP264MB284799D6FAD065F0EF65E501ED279@PAZP264MB2847.FRAP264.PROD.OUTLOOK.COM>
x-ms-oob-tlc-oobclassifiers: OLM:1060;
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 7UMAg4phz99NXiCxFdFCNZQ0UP8jTsRbYId8UMRzwIr0vnmCDToHiDgP+2/S6+1k51Oh8m78PyvftHYLNjyilGdQfHyEiqfxZBJBK3dp6HcdkX2Hy8VB6ajx3rfxszUTe3c4eRhWJmNFOtLoFwR4/wP6ZwgZSijtuMJgnHeVYtspPJFBOgYjr7i92H2QnGp3D6LvGEtidUmoqEx9vHrJ+hdb/oiz4JyvaNWT6Gekl33DsPRlM8I9OB8JlJL8eaEustkQt88bfA/IiW5bABRKVwccrSbhp+s+6NbWiYsZcOij7TvqEgj0IF9ljujBgldwa3ujZd8T5PLYjWBqg724oN5fVrGhDg+k/odtEZUtoV/prmU7tO8G9Wqt5ZexRu8Ud/fBA3Ch6FXgx8uwl/Nn6kweKcy7UKuvvB5qb3BdQwms2GzooXP3uCjiCXvsvVIFrDFFMEfIKw8PNCf8Pj6B7MWUJ3H/szn1UZCK+u+w0nZw8BsTBAsm1e3HhqqRmyQCfHLubbmw9m0DB/y1BlYlAvX8FIgRFI9bKCOFjbg/n9b1bdECeMnTDZjd30ljKAvc4ZiysHGmiDgmsyIWbthYHOAg7MYNU9a3f7rsp8JyqBvNaLdCnr11JmD6DF6cPfNOQSdH17hdeQYVF6sv3bu7oFqgsh+tHcgfDFOCnwra5bXbBYYqPYDpYmDKRjHB8iM7yOyQiA4sbZHlMDx4Bpb0Ew==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230001)(4636009)(366004)(71200400001)(122000001)(6486002)(508600001)(110136005)(316002)(38100700002)(38070700005)(54906003)(2906002)(36756003)(91956017)(86362001)(66946007)(8936002)(186003)(44832011)(76116006)(4326008)(26005)(8676002)(83380400001)(7416002)(66446008)(66556008)(64756008)(66476007)(6506007)(6512007)(5660300002)(2616005);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?iso-8859-1?Q?mjSK8srJ0AIT8N6GgQdIXJ4Jkf6F/GdAbS+jeXMKvlB7qaGuZT3fvEXrNz?=
 =?iso-8859-1?Q?T7bBHnez+dpM1Y6zWC0EgvPUCZj86pcRiH6E49rwipKp3oUcQP+izehIwS?=
 =?iso-8859-1?Q?Se844yqPKKcxVONQgnsLirWWPHzeT72B3FmrYP/lJyRx2RxtUPOFqgWImQ?=
 =?iso-8859-1?Q?26XTjeT9gwbPgzV0cBMfB+NfaqfDaDD7SPoNc5OG6opbdEg/P6MKqeRn2o?=
 =?iso-8859-1?Q?tPXCVULUjKmH7o0hH67CzTfGJrWKOH/+eTsaz2jNbFACu8LixzWtsMMEOv?=
 =?iso-8859-1?Q?7vQVKcwQJpLnOVGpD8h4QDQWi6Bx3M9fXGxTgbi1ndMJeUyfG7b2ImAQFh?=
 =?iso-8859-1?Q?AKtrWeoIQpd+t6Kyo0c8x0v26i1tate2diuTFhutI9E/2IJVJfZYDNyJS/?=
 =?iso-8859-1?Q?aSUH8eS4t2XLS0/v/T9EYCLZ4Nm1WUdw7oyir82EVIC0fThvy7rijB1Mh4?=
 =?iso-8859-1?Q?tWhvPg898/RvVZSnz0CIjDCct5N9Qn/RhqU/dNt3rHSiCKbBzkyiAZgtDK?=
 =?iso-8859-1?Q?EQNhyw6NLlaXBfzQzbYkVf61y88onDnrQwei2pG0JL/ITtd8Uqwy2H+84L?=
 =?iso-8859-1?Q?P3UZ1E/cWpUcfALutHQnI3OT2kHwy4dji0DaSjNkj+iP5nG240iRzdhNWx?=
 =?iso-8859-1?Q?Tn7QZwqLWhu4vdEF4m0eQWf94Qa0EAv24n+ggMlTezTwAkb0q2jZO1edGK?=
 =?iso-8859-1?Q?Q2mU16JJNwEFCoGid0NPkCElplV7/0FuWJlfU1r6DctuvV4q5KMF//jsxs?=
 =?iso-8859-1?Q?QDfoYiD+pw7v2TQSal9mXu5d22LE8oARcEUaINtK1tne65BuDxo9eNMaR2?=
 =?iso-8859-1?Q?t01CYM1rlC0/Bm6mwo6Vy0IitLEFn1QGOIoa88QSNDjScpqVnruADp/miH?=
 =?iso-8859-1?Q?MZ/9QZ8yk/8mTzsMCcMeSEECflCjqahmWwhO7FOjqu14clDlif2jvqYv65?=
 =?iso-8859-1?Q?NissGGh0dnknyqHH7pCKvjVKHax4NbTAwC2iorNAKS0Eld2UIWtr8rrd1E?=
 =?iso-8859-1?Q?VqVNdO2P9PFEzqg6cUlJPTF9xy5kkJqnD9ajyVZMyGJBq9uI5nd67AsivL?=
 =?iso-8859-1?Q?6u2HjNC9Cli89edAky9l+ZXr9ZnjRPM2eV2IZI00p03n054QVJCH0fUwOW?=
 =?iso-8859-1?Q?4kIZGa3VWaEk3q61vfaXxkxsZWxpbccJguw2zmjFGm+kPmPxaGYVzrhMcR?=
 =?iso-8859-1?Q?dk63mjK6cE3GR01s6LzSCoTgR9PU4mhZPKXGQ82XsiGkXjle7ueGuT1yO9?=
 =?iso-8859-1?Q?M4LtG3k+Oi6+p2eMepoP4GnqxZsDKL8LPFkVHea5E384l9kXImGklO3X/P?=
 =?iso-8859-1?Q?0wWMr6mJ3sz+mGO1ThYvAo8GJt3XX7DHPWnPapsDueLwMm/lkt8YR2jsFz?=
 =?iso-8859-1?Q?nNCGgyOWrNi9GaFdYPXRPToeVAh561aFgZ2ccN/mfHdxiVAl7Om7/w10kl?=
 =?iso-8859-1?Q?Cxx4aIoraZo997vOSeq7SIunYxrL4E8k2zZntgkMmOGkQ2fZwUCqapMYiC?=
 =?iso-8859-1?Q?0/NJZuqjTazrGeOxT1Rlme4auSRj65Krr2diSuyu/hg5Slvo4AAqSSWL6s?=
 =?iso-8859-1?Q?kU2hlthrJ/Bclv88nu2OARaGBi14kAFuGHnFa7REL2BdDllJb3HSv98Tqm?=
 =?iso-8859-1?Q?L7K3FfvaL5tMA2uGtIgajyHjIrfF3xut6/fq6tj/9DNQZOJ7Q54iyuLRZS?=
 =?iso-8859-1?Q?8U5DIBgUFknVGYstxjjsXh2YioNTY/HXWkPQmbtlTz0pb2VtNTUpU68MgX?=
 =?iso-8859-1?Q?mpXDee7YoHw6jB0V+gppuEzzI=3D?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 8abdb104-f1be-40e2-ac9c-08d9e6285011
X-MS-Exchange-CrossTenant-originalarrivaltime: 02 Feb 2022 08:45:06.5583
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: P0GK3+tjOPSeDDsCpCjgY1LTh99wdJ21CbYbSKxHfQb6o9zJrr5DLPJpdt1Ktx1UZKBBYG/BcWD9t3yTJvTanV1KhfpPlkI1CZeVLDn33L0=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PAZP264MB2847
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       arc=pass (i=1);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates
 2a01:111:f400:7e19::619 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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

Instead of opencoding, use the new kasan_pXX_table() helpers.

Add kasan_pgd_next_table() to make things similar to other
levels.

Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Paul Walmsley <paul.walmsley@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>
Cc: Albert Ou <aou@eecs.berkeley.edu>
---
Sent as an RFC as I don't have any risc setup to test it.
---
 arch/riscv/mm/kasan_init.c | 27 +++++++++++++--------------
 1 file changed, 13 insertions(+), 14 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index f61f7ca6fe0f..f82d8b73f518 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -61,13 +61,10 @@ static void __init kasan_populate_pmd(pud_t *pud, unsigned long vaddr, unsigned
 	pmd_t *pmdp, *base_pmd;
 	unsigned long next;
 
-	if (pud_none(*pud)) {
+	if (pud_none(*pud) || kasan_pmd_table(*pud))
 		base_pmd = memblock_alloc(PTRS_PER_PMD * sizeof(pmd_t), PAGE_SIZE);
-	} else {
+	else
 		base_pmd = (pmd_t *)pud_pgtable(*pud);
-		if (base_pmd == lm_alias(kasan_early_shadow_pmd))
-			base_pmd = memblock_alloc(PTRS_PER_PMD * sizeof(pmd_t), PAGE_SIZE);
-	}
 
 	pmdp = base_pmd + pmd_index(vaddr);
 
@@ -112,9 +109,10 @@ static void __init kasan_populate_pud(pgd_t *pgd,
 		 */
 		base_pud = pt_ops.get_pud_virt(pfn_to_phys(_pgd_pfn(*pgd)));
 	} else {
-		base_pud = (pud_t *)pgd_page_vaddr(*pgd);
-		if (base_pud == lm_alias(kasan_early_shadow_pud))
+		if (kasan_pud_table(*pgd))
 			base_pud = memblock_alloc(PTRS_PER_PUD * sizeof(pud_t), PAGE_SIZE);
+		else
+			base_pud = (pud_t *)pgd_page_vaddr(*pgd);
 	}
 
 	pudp = base_pud + pud_index(vaddr);
@@ -157,6 +155,11 @@ static void __init kasan_populate_pud(pgd_t *pgd,
 			kasan_populate_pud(pgdp, vaddr, next, early) :		\
 			kasan_populate_pmd((pud_t *)pgdp, vaddr, next))
 
+static inline bool kasan_pgd_next_table(pgd_t pgd)
+{
+	return pgd_page(pgd) == virt_to_page(lm_alias(kasan_early_shadow_pgd_next));
+}
+
 static void __init kasan_populate_pgd(pgd_t *pgdp,
 				      unsigned long vaddr, unsigned long end,
 				      bool early)
@@ -172,8 +175,7 @@ static void __init kasan_populate_pgd(pgd_t *pgdp,
 				phys_addr = __pa((uintptr_t)kasan_early_shadow_pgd_next);
 				set_pgd(pgdp, pfn_pgd(PFN_DOWN(phys_addr), PAGE_TABLE));
 				continue;
-			} else if (pgd_page_vaddr(*pgdp) ==
-				   (unsigned long)lm_alias(kasan_early_shadow_pgd_next)) {
+			} else if (kasan_pgd_next_table(*pgdp)) {
 				/*
 				 * pgdp can't be none since kasan_early_init
 				 * initialized all KASAN shadow region with
@@ -251,7 +253,6 @@ static void __init kasan_shallow_populate_pud(pgd_t *pgdp,
 	unsigned long next;
 	pud_t *pudp, *base_pud;
 	pmd_t *base_pmd;
-	bool is_kasan_pmd;
 
 	base_pud = (pud_t *)pgd_page_vaddr(*pgdp);
 	pudp = base_pud + pud_index(vaddr);
@@ -262,9 +263,8 @@ static void __init kasan_shallow_populate_pud(pgd_t *pgdp,
 
 	do {
 		next = pud_addr_end(vaddr, end);
-		is_kasan_pmd = (pud_pgtable(*pudp) == lm_alias(kasan_early_shadow_pmd));
 
-		if (is_kasan_pmd) {
+		if (kasan_pmd_table(*pudp)) {
 			base_pmd = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
 			set_pud(pudp, pfn_pud(PFN_DOWN(__pa(base_pmd)), PAGE_TABLE));
 		}
@@ -280,8 +280,7 @@ static void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned long
 
 	do {
 		next = pgd_addr_end(vaddr, end);
-		is_kasan_pgd_next = (pgd_page_vaddr(*pgd_k) ==
-				     (unsigned long)lm_alias(kasan_early_shadow_pgd_next));
+		is_kasan_pgd_next = kasan_pgd_next_table(*pgd_k);
 
 		if (is_kasan_pgd_next) {
 			p = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
-- 
2.33.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1f88cb32e438f9f29f45ae56849ac3fd94ec8a54.1643791473.git.christophe.leroy%40csgroup.eu.
