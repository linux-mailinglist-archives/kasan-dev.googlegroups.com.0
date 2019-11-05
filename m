Return-Path: <kasan-dev+bncBAABBVN4QXXAKGQE5KY2TUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id B9320EFC76
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2019 12:34:45 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id s15sf14568648edj.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2019 03:34:45 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1572953685; cv=pass;
        d=google.com; s=arc-20160816;
        b=xvm9xjHMJkHx28rGzwTpqmjqT0Idesvh+eYuzu9/+giFawWH7RMNQ6KUe3sMG2bgvG
         MaduDT3kptlKcD4JOrlfHJ8NlljAjy+3c8xxpK99vPk7CO1B+nfX4QJQM68TT5wwPbPN
         Z0UvSCVay2WZglfC23wl++HbvW6kqZg7ctHfbiDSmLFnaj9I306oGz3g3PwXFTvamHGS
         edX/cjSadu9iJMhP1zuguQfQNzNKWjWvtF/TFoWjx9cqMGxe3U5p0RzRvqP1DnPJYx7g
         MM//swMhR9zqT+zkdPx3/FoQo+/sNFe5PmOBN1p3naK0lxeDLsBbn+Yo9pzdnbgQ0AbM
         oWuA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer
         :original-authentication-results:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=+vXF1gN4ZEUPdEWloj8CjkbmHqlV9mPW89nWuFyj3u8=;
        b=WnbgAqoafHzcpoe6basj6zWeMuI3daR+1TYRK4uwLbiyJku9Uxjnvtr4gmUWvk5Fdr
         ihCNah6c5hv9JWRJ23B9HIGbowUo6KFY3Hasoxc1ZCdqOMdZyq0LrTQEIBToZJJ0yAEy
         +oCprFp4BWaLS1aa3wg5lTubZ0OW+9kUibJhwf+DodN7wy6Q/jbSnJJuGb/r67QWLmgK
         Cldt9Yjp7WtGNc96XcmX9vw27rSmwHkTisk2X5A/N0ENxUoFgLMDiXLJ6HdMIwLzBQI8
         me2Lr+LKt1vXdoyy10oeCVV3NdwW/3GyyiS4oaz6TZz8ToZNIXI5YNKP84I+81KDoWZf
         W4Kg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=0+BTvi77;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=0+BTvi77;
       arc=pass (i=1 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of matthew.malcomson@arm.com designates 40.107.1.74 as permitted sender) smtp.mailfrom=Matthew.Malcomson@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :mime-version:original-authentication-results:nodisclaimer
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+vXF1gN4ZEUPdEWloj8CjkbmHqlV9mPW89nWuFyj3u8=;
        b=nsN8zoCws2r6dBE5q2BKzFnZbIg1e+qbibSNPy/D4G1EyknX1O6PakFzgFdsuOMz+X
         khUSeCUGIB6bNZaUEl4PjfvnuhOxkVbWvR+BTHcKQJSnpbl8EFl3nWQ7PxAjhU1/mkQa
         KIdn9buVPt7PzB3YoDN8oyBPbbpDGOBE8Yxrbwdf6ATnxQ0yMXhHgkJprPj0ApR1IkoZ
         aePiWaS1VEnGoKA7ss2TMjgAlSWPGLT5KhtPAetNyYnIEIR6zwaheIFc1ORi0W4kQoR6
         +AVIbnQZkX35BnUPtPGXion9PnL4sewAJvZxBvNTps6KHBSyj3c+GpOnXUUAK9sPDAL8
         989g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:mime-version:original-authentication-results
         :nodisclaimer:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+vXF1gN4ZEUPdEWloj8CjkbmHqlV9mPW89nWuFyj3u8=;
        b=NkOapl0JdGvnJ15H5wb2T0a+Hjw2lTzgXIo5kZ+db23+i11wwxh8qWkuHts+r23SrS
         2kopUATj1HvZRNkXRVPaIaEnI4Z2UqUgInclFFrK10dyAA1Im+bg21oXFG87QvI8fuve
         TumJsFoqM4CtvwnzY14F3Rajenu8VNQsU8XGmqTWeHnOpRQoMl1/IhMaiGMVN30BwlBK
         zCCfSzAyLi3nlhyuSREc6B5DmTjgnPos0QIm55ldr5h3GYpHnqGc2m3i4nCyyOxyIqSc
         YB6qCqkYelIafob7/V7ZToJ7A2zKKl6MywImgaHA28K0xlM/hhJljVc5dEmMMbbLYpwm
         q06A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW8Qq9PFChIr5qhqh4z9wNjpJblK+KaB6r79pE8VCvoOVQkeKpx
	cnq7a4KfUHLjlXJFwgAjGe4=
X-Google-Smtp-Source: APXvYqzi8+y1U06CaNh4vUzqYHV7HhFsHhJATdlIHV5fw2HWgARFAGGM5p6z7QqE0wLKsfDIv6PPGA==
X-Received: by 2002:a05:6402:2042:: with SMTP id bc2mr31832231edb.167.1572953685320;
        Tue, 05 Nov 2019 03:34:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:b54b:: with SMTP id z11ls5194568edd.6.gmail; Tue, 05 Nov
 2019 03:34:44 -0800 (PST)
X-Received: by 2002:aa7:df8c:: with SMTP id b12mr25319551edy.166.1572953684887;
        Tue, 05 Nov 2019 03:34:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572953684; cv=pass;
        d=google.com; s=arc-20160816;
        b=CLnvovDGUrc74J6rBzSiIcaTxY4HEgGBYRVqMGbZHYsq6jML48cNg4v2PLu0Xi7aGb
         sHZwFzA36OIaJYhgmYcSzEv6nvTFXLc1ryPwJmV/IIOfZsWBev/YsKceuMxTnIzjGv1n
         RgfNyyBNmGhI5HzOvpzym7R1Bw0y8+rnOjqarOPYX78vR+J/vLMBLeBLUy0nxKlY17Z0
         e2blwkdckZ9fci3fNFaYvPZCervTD0R7oU3xjCS/pfs45WUVudD3vSLkLbBurdctjTVq
         2HCsVbSdBbCIkMqk5RoirJB3mBzc9C2kllygBz6qKD0lLuuoMhwkrXX9ZEcbiCs98BIe
         t0vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=nodisclaimer:original-authentication-results:mime-version
         :authentication-results-original:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:dkim-signature:dkim-signature;
        bh=hAvysLsCR0pV6cIPJFIjbdghqlDo4rRVCJ8QoyUoprY=;
        b=Bes+Z3sbF3U9eJ8/cCH6zm5ZV9guLJ4LJckgaiDx041DLM5g/aaJCT9jwbOB4C1CuF
         6g8ax9I2nM48qqDprph5EiPKDycshkKQcZIZ/yd7Atk4NcPfZeNfe6p788NH5Mkmb6yL
         7QSPoMmcF20PSaiaKwNjFudqDieHRZ9ObLANKJu+TeDiRDwwqZ/nOf9QZqaNzfr4d0hB
         XH5hWSflDELyo+AzdG+00R3vhCATe3pTMh/Qokvg5CFKZd6YnRyYS75k5de4SprB8qYt
         X9MFDXb1G7b4rpyYZfXxmMsLeEXlwjCI0lMgzBz1+rNSMmWUTCHevIWVt3OsgN2TGve7
         US+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=0+BTvi77;
       dkim=pass header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com header.b=0+BTvi77;
       arc=pass (i=1 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of matthew.malcomson@arm.com designates 40.107.1.74 as permitted sender) smtp.mailfrom=Matthew.Malcomson@arm.com
Received: from EUR02-HE1-obe.outbound.protection.outlook.com (mail-eopbgr10074.outbound.protection.outlook.com. [40.107.1.74])
        by gmr-mx.google.com with ESMTPS id a15si743521ejj.0.2019.11.05.03.34.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 05 Nov 2019 03:34:44 -0800 (PST)
Received-SPF: pass (google.com: domain of matthew.malcomson@arm.com designates 40.107.1.74 as permitted sender) client-ip=40.107.1.74;
Received: from AM6PR08CA0028.eurprd08.prod.outlook.com (2603:10a6:20b:c0::16)
 by HE1PR0802MB2139.eurprd08.prod.outlook.com (2603:10a6:3:c3::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.2408.24; Tue, 5 Nov
 2019 11:34:42 +0000
Received: from VE1EUR03FT021.eop-EUR03.prod.protection.outlook.com
 (2a01:111:f400:7e09::202) by AM6PR08CA0028.outlook.office365.com
 (2603:10a6:20b:c0::16) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.2408.24 via Frontend
 Transport; Tue, 5 Nov 2019 11:34:42 +0000
Received-SPF: Fail (protection.outlook.com: domain of arm.com does not
 designate 63.35.35.123 as permitted sender) receiver=protection.outlook.com;
 client-ip=63.35.35.123; helo=64aa7808-outbound-1.mta.getcheckrecipient.com;
Received: from 64aa7808-outbound-1.mta.getcheckrecipient.com (63.35.35.123) by
 VE1EUR03FT021.mail.protection.outlook.com (10.152.18.117) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.2387.20 via Frontend Transport; Tue, 5 Nov 2019 11:34:42 +0000
Received: ("Tessian outbound 6481c7fa5a3c:v33"); Tue, 05 Nov 2019 11:34:40 +0000
X-CheckRecipientChecked: true
X-CR-MTA-CID: 0dd5eab63dc3235c
X-CR-MTA-TID: 64aa7808
Received: from df8669d8ea0a.1 (cr-mta-lb-1.cr-mta-net [104.47.14.55])
	by 64aa7808-outbound-1.mta.getcheckrecipient.com id 7A59C7D4-D73F-40CD-A359-0C48A11C1FE9.1;
	Tue, 05 Nov 2019 11:34:35 +0000
Received: from EUR04-VI1-obe.outbound.protection.outlook.com (mail-vi1eur04lp2055.outbound.protection.outlook.com [104.47.14.55])
    by 64aa7808-outbound-1.mta.getcheckrecipient.com with ESMTPS id df8669d8ea0a.1
    (version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384);
    Tue, 05 Nov 2019 11:34:35 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=g5zE2x2z3XjQA5LBO1B3vnsgjI8ZzAzDhBtio41d2YYo0Lh8bkSIl3+LcXMmF/i2BH43hEIEOirddVwVfU7UjGcq1bnolOU1Oyf2RhxTuFXmJtJfyaVJRJJXdHgipC64N0WHObqY2qrKm/YkAg+nDjroAMDTanG+aAjZDjRm1qodUzuXD537SPMrNL1s/CsvshRsKqWkXpOGNHF2mNXrlV/7eCCyltCQR+w2WkgPKoDh/FD5GkF0Cg76VXLcb5N8xhdJ+jjEkUbiYvFQdjj6CT3yE9jb0pNOXHcS7KMmd4CtJqnQLgQaebEpnCgPFTrzgZT0G7iUWzj5yH0Qe3+few==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=hAvysLsCR0pV6cIPJFIjbdghqlDo4rRVCJ8QoyUoprY=;
 b=DDSDaY3Cd6+nHCi564ND+VHQHfjega+LG8sWIDYAf57TfXFspHeReD3piSsl/uMTdbI/7ENvbAHg/spB82YB2XJsagL1GPL9wLsMphUPDVlV3wvD+02mf/9JM6RGHfceu2ApLexZIXvs9IQNFDSbn7EDoIFrcyeTbkoL6yQbV2CpsvpKnSVDYt0gWGaIRHqukPceNfN/bpmmNrYETWYYcaG7eI+VNQpkjFXpOdv1bUus8MjdRN697pfg188LzO5j9GzyCv8a6NoC5rTXFoZdEhi2WdweJ7wNbxVCW9B9AaMio70zifFAGM0L+Ze8KTzLE+6Bb/U/2UOvcyvs8ITUbg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Received: from HE1PR0802MB2251.eurprd08.prod.outlook.com (10.172.131.21) by
 HE1PR0802MB2313.eurprd08.prod.outlook.com (10.172.127.146) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.2408.24; Tue, 5 Nov 2019 11:34:32 +0000
Received: from HE1PR0802MB2251.eurprd08.prod.outlook.com
 ([fe80::e120:9a38:bcf4:6075]) by HE1PR0802MB2251.eurprd08.prod.outlook.com
 ([fe80::e120:9a38:bcf4:6075%5]) with mapi id 15.20.2408.024; Tue, 5 Nov 2019
 11:34:32 +0000
From: Matthew Malcomson <Matthew.Malcomson@arm.com>
To: "gcc-patches@gcc.gnu.org" <gcc-patches@gcc.gnu.org>
CC: nd <nd@arm.com>, "kcc@google.com" <kcc@google.com>, "dvyukov@google.com"
	<dvyukov@google.com>, Martin Liska <mliska@suse.cz>, Richard Earnshaw
	<Richard.Earnshaw@arm.com>, Kyrylo Tkachov <Kyrylo.Tkachov@arm.com>,
	"dodji@redhat.com" <dodji@redhat.com>, "jakub@redhat.com" <jakub@redhat.com>,
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Konovalov
	<andreyknvl@google.com>, Dmitry Vyukov <dvyukov@google.com>
Subject: [PATCH 13/X] [libsanitizer][options] Add hwasan flags and argument
 parsing
Thread-Topic: [PATCH 13/X] [libsanitizer][options] Add hwasan flags and
 argument parsing
Thread-Index: AQHVk8z+/6P4LKLAqkOSZsJwRpLgNg==
Date: Tue, 5 Nov 2019 11:34:32 +0000
Message-ID: <HE1PR0802MB2251783050BA897E608882ACE07E0@HE1PR0802MB2251.eurprd08.prod.outlook.com>
References: <157295142743.27946.1142544630216676787.scripted-patch-series@arm.com>
In-Reply-To: <157295142743.27946.1142544630216676787.scripted-patch-series@arm.com>
Accept-Language: en-GB, en-US
Content-Language: en-US
X-MS-Has-Attach: yes
X-MS-TNEF-Correlator: 
x-clientproxiedby: LO2P265CA0474.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:a2::30) To HE1PR0802MB2251.eurprd08.prod.outlook.com
 (2603:10a6:3:cc::21)
x-ms-exchange-messagesentrepresentingtype: 1
x-originating-ip: [217.140.106.49]
x-ms-publictraffictype: Email
X-MS-Office365-Filtering-HT: Tenant
X-MS-Office365-Filtering-Correlation-Id: 010027d7-0af2-4d7d-3622-08d761e42699
X-MS-TrafficTypeDiagnostic: HE1PR0802MB2313:|HE1PR0802MB2313:|HE1PR0802MB2139:
X-MS-Exchange-PUrlCount: 3
x-ms-exchange-transport-forked: True
X-Microsoft-Antispam-PRVS: <HE1PR0802MB2139C45ADEBE37917054CBF8E07E0@HE1PR0802MB2139.eurprd08.prod.outlook.com>
x-checkrecipientrouted: true
x-ms-oob-tlc-oobclassifiers: OLM:5516;OLM:5516;
x-forefront-prvs: 0212BDE3BE
X-Forefront-Antispam-Report-Untrusted: SFV:NSPM;SFS:(10009020)(4636009)(1496009)(376002)(136003)(396003)(366004)(39860400002)(346002)(54534003)(189003)(199004)(11346002)(446003)(66616009)(5660300002)(26005)(102836004)(7696005)(2501003)(6506007)(7736002)(8676002)(81156014)(81166006)(33656002)(478600001)(74316002)(2906002)(76176011)(186003)(386003)(99936001)(8936002)(14454004)(2351001)(44832011)(486006)(476003)(66476007)(316002)(52116002)(71190400001)(966005)(30864003)(6116002)(25786009)(3846002)(305945005)(54906003)(86362001)(66066001)(6306002)(9686003)(6436002)(5024004)(5640700003)(4326008)(55016002)(99286004)(14444005)(66446008)(71200400001)(66556008)(52536014)(66946007)(64756008)(256004)(6916009)(579004);DIR:OUT;SFP:1101;SCL:1;SRVR:HE1PR0802MB2313;H:HE1PR0802MB2251.eurprd08.prod.outlook.com;FPR:;SPF:None;LANG:en;PTR:InfoNoRecords;MX:1;A:1;
received-spf: None (protection.outlook.com: arm.com does not designate
 permitted sender hosts)
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam-Untrusted: BCL:0;
X-Microsoft-Antispam-Message-Info-Original: PyClyW5VDsAnKvDOGuI92P5ZzCG2ipLSkyMitSPU84orMSmpomGcH3v48P5FrZLZyvyGpQRw5CYGQvwfaNzNTX4BdRbe2TQou5lGmCLxKdK8OkCanHvau4wWsn94jl1I82nIt+OAdNtAOtH7PSTv4/lnxtBZYy/+9k0nhQbvQOJjKhFFOERttrfj3KWDucERFxOGSvbbZhUbfhmj1pXybRY0kluqlTcr51bPDaNOE2nKHdf72aB+DZUiEOp/CBOphBtgS5BeQLTUoGAyXxSKpPbf7w2gpLzDUCZ2aa8Q57hebRmLxRCMjSDWUbloaJvvQJLN47Ke5YJ3rGPBGTkpYWKBnyhpAjICfyJCapSCvROqKd1jHwyUftyzbxVbm7cuwPNfRQg1f2TFMb+J3RSs44H+aSqWk10jjHt1SNYPVJlET3kvsl0jRrg6F9yZ82j/fFkZiXFLMWJE2WNbpKvKE+DcsNPkPOtCQh/uHK1CayQ=
Content-Type: multipart/mixed;
	boundary="_002_HE1PR0802MB2251783050BA897E608882ACE07E0HE1PR0802MB2251_"
MIME-Version: 1.0
X-MS-Exchange-Transport-CrossTenantHeadersStamped: HE1PR0802MB2313
Original-Authentication-Results: spf=none (sender IP is )
 smtp.mailfrom=Matthew.Malcomson@arm.com;
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: VE1EUR03FT021.eop-EUR03.prod.protection.outlook.com
X-Forefront-Antispam-Report: CIP:63.35.35.123;IPV:CAL;SCL:-1;CTRY:IE;EFV:NLI;SFV:NSPM;SFS:(10009020)(4636009)(346002)(136003)(39860400002)(376002)(396003)(1110001)(339900001)(189003)(199004)(54534003)(25786009)(102836004)(14454004)(8936002)(107886003)(70206006)(52536014)(81156014)(66066001)(4326008)(6862004)(30864003)(235185007)(81166006)(99286004)(66616009)(86362001)(356004)(5660300002)(70586007)(71190400001)(7736002)(11346002)(2906002)(74316002)(76130400001)(476003)(99936001)(486006)(305945005)(126002)(446003)(478600001)(105606002)(316002)(2351001)(26826003)(966005)(16586007)(26005)(8676002)(336012)(22756006)(186003)(33656002)(568964002)(54906003)(6116002)(3846002)(2501003)(2476003)(5024004)(14444005)(6506007)(5640700003)(55016002)(6306002)(7696005)(386003)(36906005)(45080400002)(76176011)(9686003);DIR:OUT;SFP:1101;SCL:1;SRVR:HE1PR0802MB2139;H:64aa7808-outbound-1.mta.getcheckrecipient.com;FPR:;SPF:Fail;LANG:en;PTR:ec2-63-35-35-123.eu-west-1.compute.amazonaws.com;MX:1;A:1;
X-MS-Office365-Filtering-Correlation-Id-Prvs: 63da0fe7-4c8b-4144-5f40-08d761e4209c
NoDisclaimer: True
X-Forefront-PRVS: 0212BDE3BE
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: eN65rZgqda8U8HZrP9qCF/R9/E8sFvUkoZbOXQt7gTgguIIxLLnRg/wNSElRck+1gtmHPlWHZ04NaRg5qL7U1BH70LdFidc/wapPHM/VS6qWhpBSK4I02TJJjrrT8MlFsuiCcnnlkQAhVTnUr3YRDjihz7AmKYZFAea771ZFuQ7k2ROe1Dm/OCXq1djSWqfu0NAysQl8YjFpuxmbx324v5ztS8rsh5KCl276hvWGy8S/lUQLHnKBnzYvgu1LQq6QRRrY58ht3/CkSRvRj+1qF+gs18wu1oWVJeuHEyQq87kDiWjVcFgu7/LxiSYtwZcFdirzpn70Dmq6tJTl1KLjNTKqKW6x/2HiZY/7Y4Fb8UnUdnNpYSBivEWaPCY3TdCfEJtvpUHkeWHix478ozzRTCqWS329fa3Gn9d5eUHi0DwGiKhj5GZzx8dsBM7YywvNjG87Ces0VV93AvOC7dfjfuY+Mqmhy2doCqkLjQjiyME=
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 05 Nov 2019 11:34:42.3156
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 010027d7-0af2-4d7d-3622-08d761e42699
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[63.35.35.123];Helo=[64aa7808-outbound-1.mta.getcheckrecipient.com]
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: HE1PR0802MB2139
X-Original-Sender: matthew.malcomson@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@armh.onmicrosoft.com header.s=selector2-armh-onmicrosoft-com
 header.b=0+BTvi77;       dkim=pass header.i=@armh.onmicrosoft.com
 header.s=selector2-armh-onmicrosoft-com header.b=0+BTvi77;       arc=pass
 (i=1 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 matthew.malcomson@arm.com designates 40.107.1.74 as permitted sender) smtp.mailfrom=Matthew.Malcomson@arm.com
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

--_002_HE1PR0802MB2251783050BA897E608882ACE07E0HE1PR0802MB2251_
Content-Type: text/plain; charset="UTF-8"
Content-ID: <A45E38CE2106C74C81BBD2422E96F541@eurprd08.prod.outlook.com>
Content-Transfer-Encoding: quoted-printable

These flags can't be used at the same time as any of the other
sanitizers.
We add an equivalent flag to -static-libasan in -static-libhwasan to
ensure static linking.

The -fsanitize=3Dkernel-hwaddress option is for compiling targeting the
kernel.  This flag has defaults that allow compiling KASAN with tags as
it is currently implemented.
These defaults are that we do not sanitize variables on the stack and
always recover from a detected bug.
Stack tagging in the kernel is a future aim, stack instrumentation has
not yet been enabled for the kernel for clang either
(https://lists.infradead.org/pipermail/linux-arm-kernel/2019-October/687121=
.html).

We introduce a backend hook `targetm.memtag.can_tag_addresses` that
indicates to the mid-end whether a target has a feature like AArch64 TBI
where the top byte of an address is ignored.
Without this feature hwasan sanitization is not done.

NOTE:
------
I have defined a new macro of __SANITIZE_HWADDRESS__ that gets
automatically defined when compiling with hwasan.  This is analogous to
__SANITIZE_ADDRESS__ which is defined when compiling with asan.

Users in the kernel have expressed an interest in using
__SANITIZE_ADDRESS__ for both
(https://lists.infradead.org/pipermail/linux-arm-kernel/2019-October/690703=
.html).

One approach to do this could be to define __SANITIZE_ADDRESS__ with
different values depending on whether we are compiling with hwasan or
asan.

Using __SANITIZE_ADDRESS__ for both means that code like the kernel
which wants to treat the two sanitizers as alternate implementations of
the same thing gets that automatically.

My preference is to use __SANITIZE_HWADDRESS__ since that means any
existing code will not be predicated on this (and hence I guess less
surprises), but would appreciate feedback on this given the point above.
------

gcc/ChangeLog:

2019-11-05  Matthew Malcomson  <matthew.malcomson@arm.com>

	* asan.c (memory_tagging_p): New.
	* asan.h (memory_tagging_p): New.
	* common.opt (flag_sanitize_recover): Default for kernel
	hwaddress.
	(static-libhwasan): New cli option.
	* config/aarch64/aarch64.c (aarch64_can_tag_addresses): New.
	(TARGET_MEMTAG_CAN_TAG_ADDRESSES): New.
	* config/gnu-user.h (LIBHWASAN_EARLY_SPEC): hwasan equivalent of
	asan command line flags.
	* cppbuiltin.c (define_builtin_macros_for_compilation_flags):
	Add hwasan equivalent of __SANITIZE_ADDRESS__.
	* doc/tm.texi: Document new hook.
	* doc/tm.texi.in: Document new hook.
	* flag-types.h (enum sanitize_code): New sanitizer values.
	* gcc.c (STATIC_LIBHWASAN_LIBS): New macro.
	(LIBHWASAN_SPEC): New macro.
	(LIBHWASAN_EARLY_SPEC): New macro.
	(SANITIZER_EARLY_SPEC): Update to include hwasan.
	(SANITIZER_SPEC): Update to include hwasan.
	(sanitize_spec_function): Use hwasan options.
	* opts.c (finish_options): Describe conflicts between address
	sanitizers.
	(sanitizer_opts): Introduce new sanitizer flags.
	(common_handle_option): Add defaults for kernel sanitizer.
	* params.def (PARAM_HWASAN_RANDOM_FRAME_TAG): New.
	(PARAM_HWASAN_STACK): New.
	* params.h (HWASAN_STACK): New.
	(HWASAN_RANDOM_FRAME_TAG): New.
	* target.def (HOOK_PREFIX): Add new hook.
	* targhooks.c (default_memtag_can_tag_addresses): New.
	* toplev.c (process_options): Ensure hwasan only on TBI
	architectures.

gcc/c-family/ChangeLog:

2019-11-05  Matthew Malcomson  <matthew.malcomson@arm.com>

	* c-attribs.c (handle_no_sanitize_hwaddress_attribute): New
	attribute.



###############     Attachment also inlined for ease of reply    ##########=
#####


diff --git a/gcc/c-family/c-attribs.c b/gcc/c-family/c-attribs.c
index 6500b998321419a1d8d57062534206c5909adb7a..2de94815f91da5a0fd06c30d004=
4f866084121b8 100644
--- a/gcc/c-family/c-attribs.c
+++ b/gcc/c-family/c-attribs.c
@@ -54,6 +54,8 @@ static tree handle_cold_attribute (tree *, tree, tree, in=
t, bool *);
 static tree handle_no_sanitize_attribute (tree *, tree, tree, int, bool *)=
;
 static tree handle_no_sanitize_address_attribute (tree *, tree, tree,
 						  int, bool *);
+static tree handle_no_sanitize_hwaddress_attribute (tree *, tree, tree,
+						    int, bool *);
 static tree handle_no_sanitize_thread_attribute (tree *, tree, tree,
 						 int, bool *);
 static tree handle_no_address_safety_analysis_attribute (tree *, tree, tre=
e,
@@ -410,6 +412,8 @@ const struct attribute_spec c_common_attribute_table[] =
=3D
 			      handle_no_sanitize_attribute, NULL },
   { "no_sanitize_address",    0, 0, true, false, false, false,
 			      handle_no_sanitize_address_attribute, NULL },
+  { "no_sanitize_hwaddress",    0, 0, true, false, false, false,
+			      handle_no_sanitize_hwaddress_attribute, NULL },
   { "no_sanitize_thread",     0, 0, true, false, false, false,
 			      handle_no_sanitize_thread_attribute, NULL },
   { "no_sanitize_undefined",  0, 0, true, false, false, false,
@@ -929,6 +933,22 @@ handle_no_sanitize_address_attribute (tree *node, tree=
 name, tree, int,
   return NULL_TREE;
 }
=20
+/* Handle a "no_sanitize_hwaddress" attribute; arguments as in
+   struct attribute_spec.handler.  */
+
+static tree
+handle_no_sanitize_hwaddress_attribute (tree *node, tree name, tree, int,
+				      bool *no_add_attrs)
+{
+  *no_add_attrs =3D true;
+  if (TREE_CODE (*node) !=3D FUNCTION_DECL)
+    warning (OPT_Wattributes, "%qE attribute ignored", name);
+  else
+    add_no_sanitize_value (*node, SANITIZE_HWADDRESS);
+
+  return NULL_TREE;
+}
+
 /* Handle a "no_sanitize_thread" attribute; arguments as in
    struct attribute_spec.handler.  */
=20
diff --git a/gcc/common.opt b/gcc/common.opt
index 1b9e0f3c8025a3b439f766edcd81db462973037b..d8ba9556801e5afc479c33ba359=
125d6354ca862 100644
--- a/gcc/common.opt
+++ b/gcc/common.opt
@@ -215,7 +215,7 @@ unsigned int flag_sanitize
=20
 ; What sanitizers should recover from errors
 Variable
-unsigned int flag_sanitize_recover =3D (SANITIZE_UNDEFINED | SANITIZE_UNDE=
FINED_NONDEFAULT | SANITIZE_KERNEL_ADDRESS) & ~(SANITIZE_UNREACHABLE | SANI=
TIZE_RETURN)
+unsigned int flag_sanitize_recover =3D (SANITIZE_UNDEFINED | SANITIZE_UNDE=
FINED_NONDEFAULT | SANITIZE_KERNEL_ADDRESS | SANITIZE_KERNEL_HWADDRESS) & ~=
(SANITIZE_UNREACHABLE | SANITIZE_RETURN)
=20
 ; What the coverage sanitizers should instrument
 Variable
@@ -3289,6 +3289,9 @@ Driver
 static-libasan
 Driver
=20
+static-libhwasan
+Driver
+
 static-libtsan
 Driver
=20
diff --git a/gcc/config/aarch64/aarch64.c b/gcc/config/aarch64/aarch64.c
index 232317d4a5a4a16529f573eef5a8d7a068068207..c556bcd1c37c3c4fdd9a829a28e=
e4ff56819b89e 100644
--- a/gcc/config/aarch64/aarch64.c
+++ b/gcc/config/aarch64/aarch64.c
@@ -20272,6 +20272,15 @@ aarch64_stack_protect_guard (void)
   return NULL_TREE;
 }
=20
+/* Implement TARGET_MEMTAG_CAN_TAG_ADDRESSES.  Here we tell the rest of th=
e
+   compiler that we automatically ignore the top byte of our pointers, whi=
ch
+   allows using -fsanitize=3Dhwaddress.  */
+bool
+aarch64_can_tag_addresses ()
+{
+  return true;
+}
+
 /* Implement TARGET_ASM_FILE_END for AArch64.  This adds the AArch64 GNU N=
OTE
    section at the end if needed.  */
 #define GNU_PROPERTY_AARCH64_FEATURE_1_AND	0xc0000000
@@ -20839,6 +20848,9 @@ aarch64_libgcc_floating_mode_supported_p
 #undef TARGET_GET_MULTILIB_ABI_NAME
 #define TARGET_GET_MULTILIB_ABI_NAME aarch64_get_multilib_abi_name
=20
+#undef TARGET_MEMTAG_CAN_TAG_ADDRESSES
+#define TARGET_MEMTAG_CAN_TAG_ADDRESSES aarch64_can_tag_addresses
+
 #if CHECKING_P
 #undef TARGET_RUN_TARGET_SELFTESTS
 #define TARGET_RUN_TARGET_SELFTESTS selftest::aarch64_run_selftests
diff --git a/gcc/config/gnu-user.h b/gcc/config/gnu-user.h
index 95a3c29f7cee86336f958bef1d7fe56b82e05e6c..90b1fa91742c6a7d76aa6c7e931=
f8014fc4fff0c 100644
--- a/gcc/config/gnu-user.h
+++ b/gcc/config/gnu-user.h
@@ -129,14 +129,18 @@ see the files COPYING3 and COPYING.RUNTIME respective=
ly.  If not, see
 /* Link -lasan early on the command line.  For -static-libasan, don't link
    it for -shared link, the executable should be compiled with -static-lib=
asan
    in that case, and for executable link with --{,no-}whole-archive around
-   it to force everything into the executable.  And similarly for -ltsan
-   and -llsan.  */
+   it to force everything into the executable.  And similarly for -ltsan,
+   -lhwasan, and -llsan.  */
 #if defined(HAVE_LD_STATIC_DYNAMIC)
 #undef LIBASAN_EARLY_SPEC
 #define LIBASAN_EARLY_SPEC "%{!shared:libasan_preinit%O%s} " \
   "%{static-libasan:%{!shared:" \
   LD_STATIC_OPTION " --whole-archive -lasan --no-whole-archive " \
   LD_DYNAMIC_OPTION "}}%{!static-libasan:-lasan}"
+#undef LIBHWASAN_EARLY_SPEC
+#define LIBHWASAN_EARLY_SPEC "%{static-libhwasan:%{!shared:" \
+  LD_STATIC_OPTION " --whole-archive -lhwasan --no-whole-archive " \
+  LD_DYNAMIC_OPTION "}}%{!static-libhwasan:-lhwasan}"
 #undef LIBTSAN_EARLY_SPEC
 #define LIBTSAN_EARLY_SPEC "%{!shared:libtsan_preinit%O%s} " \
   "%{static-libtsan:%{!shared:" \
diff --git a/gcc/cppbuiltin.c b/gcc/cppbuiltin.c
index 60e5bedc3665a25fa51c2eca00547f12a9953778..e8d0bedfc2eb22d1e72e7e48751=
55202c8389a38 100644
--- a/gcc/cppbuiltin.c
+++ b/gcc/cppbuiltin.c
@@ -93,6 +93,9 @@ define_builtin_macros_for_compilation_flags (cpp_reader *=
pfile)
   if (flag_sanitize & SANITIZE_ADDRESS)
     cpp_define (pfile, "__SANITIZE_ADDRESS__");
=20
+  if (flag_sanitize & SANITIZE_HWADDRESS)
+    cpp_define (pfile, "__SANITIZE_HWADDRESS__");
+
   if (flag_sanitize & SANITIZE_THREAD)
     cpp_define (pfile, "__SANITIZE_THREAD__");
=20
diff --git a/gcc/doc/tm.texi b/gcc/doc/tm.texi
index 0250cf58e72b4df8fec19cfb4399ed0e2594342b..bf53df715391128d6fbe9be4e77=
906650309ab2e 100644
--- a/gcc/doc/tm.texi
+++ b/gcc/doc/tm.texi
@@ -2972,6 +2972,10 @@ This hook defines the machine mode to use for the bo=
olean result of  conditional
 A target hook which lets a backend compute the set of pressure classes to =
 be used by those optimization passes which take register pressure into  ac=
count, as opposed to letting IRA compute them.  It returns the number of  r=
egister classes stored in the array @var{pressure_classes}.
 @end deftypefn
=20
+@deftypefn {Target Hook} bool TARGET_MEMTAG_CAN_TAG_ADDRESSES ()
+True if backend architecture naturally supports ignoring the top byte of p=
ointers.  This feature means that -fsanitize=3Dhwaddress can work.
+@end deftypefn
+
 @node Stack and Calling
 @section Stack Layout and Calling Conventions
 @cindex calling conventions
diff --git a/gcc/doc/tm.texi.in b/gcc/doc/tm.texi.in
index 0b77dd8eb46dc53fc585d7b3eac9805c6ed79951..005cef05999d7c334f16ffa3689=
03c3b66806231 100644
--- a/gcc/doc/tm.texi.in
+++ b/gcc/doc/tm.texi.in
@@ -2374,6 +2374,8 @@ in the reload pass.
=20
 @hook TARGET_COMPUTE_PRESSURE_CLASSES
=20
+@hook TARGET_MEMTAG_CAN_TAG_ADDRESSES
+
 @node Stack and Calling
 @section Stack Layout and Calling Conventions
 @cindex calling conventions
diff --git a/gcc/flag-types.h b/gcc/flag-types.h
index a2103282d469db31ad157a87572068d943061c8c..57d8ff9a1a010409d966230140d=
f1017bc3584a8 100644
--- a/gcc/flag-types.h
+++ b/gcc/flag-types.h
@@ -256,6 +256,9 @@ enum sanitize_code {
   SANITIZE_BUILTIN =3D 1UL << 25,
   SANITIZE_POINTER_COMPARE =3D 1UL << 26,
   SANITIZE_POINTER_SUBTRACT =3D 1UL << 27,
+  SANITIZE_HWADDRESS =3D 1UL << 28,
+  SANITIZE_USER_HWADDRESS =3D 1UL << 29,
+  SANITIZE_KERNEL_HWADDRESS =3D 1UL << 30,
   SANITIZE_SHIFT =3D SANITIZE_SHIFT_BASE | SANITIZE_SHIFT_EXPONENT,
   SANITIZE_UNDEFINED =3D SANITIZE_SHIFT | SANITIZE_DIVIDE | SANITIZE_UNREA=
CHABLE
 		       | SANITIZE_VLA | SANITIZE_NULL | SANITIZE_RETURN
diff --git a/gcc/gcc.c b/gcc/gcc.c
index 1216cdd505a18152dc1d3eee5f37755a396761f1..cf1bd9de660f32f060b9277f89a=
562873a48684a 100644
--- a/gcc/gcc.c
+++ b/gcc/gcc.c
@@ -708,6 +708,24 @@ proper position among the other output files.  */
 #define LIBASAN_EARLY_SPEC ""
 #endif
=20
+#ifndef LIBHWASAN_SPEC
+#define STATIC_LIBHWASAN_LIBS \
+  " %{static-libhwasan|static:%:include(libsanitizer.spec)%(link_libhwasan=
)}"
+#ifdef LIBHWASAN_EARLY_SPEC
+#define LIBHWASAN_SPEC STATIC_LIBHWASAN_LIBS
+#elif defined(HAVE_LD_STATIC_DYNAMIC)
+#define LIBHWASAN_SPEC "%{static-libhwasan:" LD_STATIC_OPTION \
+		     "} -lhwasan %{static-libhwasan:" LD_DYNAMIC_OPTION "}" \
+		     STATIC_LIBHWASAN_LIBS
+#else
+#define LIBHWASAN_SPEC "-lhwasan" STATIC_LIBHWASAN_LIBS
+#endif
+#endif
+
+#ifndef LIBHWASAN_EARLY_SPEC
+#define LIBHWASAN_EARLY_SPEC ""
+#endif
+
 #ifndef LIBTSAN_SPEC
 #define STATIC_LIBTSAN_LIBS \
   " %{static-libtsan|static:%:include(libsanitizer.spec)%(link_libtsan)}"
@@ -982,6 +1000,7 @@ proper position among the other output files.  */
 #ifndef SANITIZER_EARLY_SPEC
 #define SANITIZER_EARLY_SPEC "\
 %{!nostdlib:%{!r:%{!nodefaultlibs:%{%:sanitize(address):" LIBASAN_EARLY_SP=
EC "} \
+    %{%:sanitize(hwaddress):" LIBHWASAN_EARLY_SPEC "} \
     %{%:sanitize(thread):" LIBTSAN_EARLY_SPEC "} \
     %{%:sanitize(leak):" LIBLSAN_EARLY_SPEC "}}}}"
 #endif
@@ -991,6 +1010,8 @@ proper position among the other output files.  */
 #define SANITIZER_SPEC "\
 %{!nostdlib:%{!r:%{!nodefaultlibs:%{%:sanitize(address):" LIBASAN_SPEC "\
     %{static:%ecannot specify -static with -fsanitize=3Daddress}}\
+    %{%:sanitize(hwaddress):" LIBHWASAN_SPEC "\
+	%{static:%ecannot specify -static with -fsanitize=3Dhwaddress}}\
     %{%:sanitize(thread):" LIBTSAN_SPEC "\
     %{static:%ecannot specify -static with -fsanitize=3Dthread}}\
     %{%:sanitize(undefined):" LIBUBSAN_SPEC "}\
@@ -9434,8 +9455,12 @@ sanitize_spec_function (int argc, const char **argv)
=20
   if (strcmp (argv[0], "address") =3D=3D 0)
     return (flag_sanitize & SANITIZE_USER_ADDRESS) ? "" : NULL;
+  if (strcmp (argv[0], "hwaddress") =3D=3D 0)
+    return (flag_sanitize & SANITIZE_USER_HWADDRESS) ? "" : NULL;
   if (strcmp (argv[0], "kernel-address") =3D=3D 0)
     return (flag_sanitize & SANITIZE_KERNEL_ADDRESS) ? "" : NULL;
+  if (strcmp (argv[0], "kernel-hwaddress") =3D=3D 0)
+    return (flag_sanitize & SANITIZE_KERNEL_HWADDRESS) ? "" : NULL;
   if (strcmp (argv[0], "thread") =3D=3D 0)
     return (flag_sanitize & SANITIZE_THREAD) ? "" : NULL;
   if (strcmp (argv[0], "undefined") =3D=3D 0)
diff --git a/gcc/opts.c b/gcc/opts.c
index efd75aade6c879f330db1aa7b8ef6b9100862c04..88a94286e71f61f2dce907018e5=
185f63a830804 100644
--- a/gcc/opts.c
+++ b/gcc/opts.c
@@ -1160,6 +1160,13 @@ finish_options (struct gcc_options *opts, struct gcc=
_options *opts_set,
 		  "%<-fsanitize=3Daddress%> or %<-fsanitize=3Dkernel-address%>");
     }
=20
+  /* Userspace and kernel HWasan conflict with each other.  */
+  if ((opts->x_flag_sanitize & SANITIZE_USER_HWADDRESS)
+      && (opts->x_flag_sanitize & SANITIZE_KERNEL_HWADDRESS))
+    error_at (loc,
+	      "%<-fsanitize=3Dhwaddress%> is incompatible with "
+	      "%<-fsanitize=3Dkernel-hwaddress%>");
+
   /* Userspace and kernel ASan conflict with each other.  */
   if ((opts->x_flag_sanitize & SANITIZE_USER_ADDRESS)
       && (opts->x_flag_sanitize & SANITIZE_KERNEL_ADDRESS))
@@ -1179,6 +1186,20 @@ finish_options (struct gcc_options *opts, struct gcc=
_options *opts_set,
     error_at (loc,
 	      "%<-fsanitize=3Dleak%> is incompatible with %<-fsanitize=3Dthread%>=
");
=20
+  /* HWASan and ASan conflict with each other.  */
+  if ((opts->x_flag_sanitize & SANITIZE_ADDRESS)
+      && (opts->x_flag_sanitize & SANITIZE_HWADDRESS))
+    error_at (loc,
+	      "%<-fsanitize=3Dhwaddress%> is incompatible with both "
+	      "%<-fsanitize=3Daddress%> and %<-fsanitize=3Dkernel-address%>");
+
+  /* HWASan conflicts with TSan.  */
+  if ((opts->x_flag_sanitize & SANITIZE_HWADDRESS)
+      && (opts->x_flag_sanitize & SANITIZE_THREAD))
+    error_at (loc,
+	      "%<-fsanitize=3Dhwaddress%> is incompatible with "
+	      "%<-fsanitize=3Dthread%>");
+
   /* Check error recovery for -fsanitize-recover option.  */
   for (int i =3D 0; sanitizer_opts[i].name !=3D NULL; ++i)
     if ((opts->x_flag_sanitize_recover & sanitizer_opts[i].flag)
@@ -1198,7 +1219,8 @@ finish_options (struct gcc_options *opts, struct gcc_=
options *opts_set,
=20
   /* Enable -fsanitize-address-use-after-scope if address sanitizer is
      enabled.  */
-  if ((opts->x_flag_sanitize & SANITIZE_USER_ADDRESS)
+  if (((opts->x_flag_sanitize & SANITIZE_USER_ADDRESS)
+       || (opts->x_flag_sanitize & SANITIZE_USER_HWADDRESS))
       && !opts_set->x_flag_sanitize_address_use_after_scope)
     opts->x_flag_sanitize_address_use_after_scope =3D true;
=20
@@ -1827,8 +1849,13 @@ const struct sanitizer_opts_s sanitizer_opts[] =3D
 #define SANITIZER_OPT(name, flags, recover) \
     { #name, flags, sizeof #name - 1, recover }
   SANITIZER_OPT (address, (SANITIZE_ADDRESS | SANITIZE_USER_ADDRESS), true=
),
+  SANITIZER_OPT (hwaddress, (SANITIZE_HWADDRESS | SANITIZE_USER_HWADDRESS)=
,
+		 true),
   SANITIZER_OPT (kernel-address, (SANITIZE_ADDRESS | SANITIZE_KERNEL_ADDRE=
SS),
 		 true),
+  SANITIZER_OPT (kernel-hwaddress,
+		 (SANITIZE_HWADDRESS | SANITIZE_KERNEL_HWADDRESS),
+		 true),
   SANITIZER_OPT (pointer-compare, SANITIZE_POINTER_COMPARE, true),
   SANITIZER_OPT (pointer-subtract, SANITIZE_POINTER_SUBTRACT, true),
   SANITIZER_OPT (thread, SANITIZE_THREAD, false),
@@ -2363,6 +2390,14 @@ common_handle_option (struct gcc_options *opts,
 				 opts->x_param_values,
 				 opts_set->x_param_values);
 	}
+      if (opts->x_flag_sanitize & SANITIZE_KERNEL_HWADDRESS)
+	{
+	  maybe_set_param_value (PARAM_HWASAN_STACK, 0, opts->x_param_values,
+				 opts_set->x_param_values);
+	  maybe_set_param_value (PARAM_HWASAN_RANDOM_FRAME_TAG, 0,
+				 opts->x_param_values,
+				 opts_set->x_param_values);
+	}
       break;
=20
     case OPT_fsanitize_recover_:
diff --git a/gcc/params.def b/gcc/params.def
index 5fe33976b37bb0763986040f66a9c28681363535..a4b3f02b60898f54aeec40238ad=
417e423f56e01 100644
--- a/gcc/params.def
+++ b/gcc/params.def
@@ -1299,6 +1299,17 @@ DEFPARAM (PARAM_USE_AFTER_SCOPE_DIRECT_EMISSION_THRE=
SHOLD,
 	 "smaller or equal to this number.",
 	 256, 0, INT_MAX)
=20
+/* HWAsan stands for HardwareAddressSanitizer: https://github.com/google/s=
anitizers.  */
+DEFPARAM (PARAM_HWASAN_RANDOM_FRAME_TAG,
+	  "hwasan-random-frame-tag",
+	  "Use random base tag for each frame, as opposed to base always zero.",
+	  1, 0, 1)
+
+DEFPARAM (PARAM_HWASAN_STACK,
+	  "hwasan-stack",
+	  "Enable hwasan stack protection.",
+	  1, 0, 1)
+
 DEFPARAM (PARAM_UNINIT_CONTROL_DEP_ATTEMPTS,
 	  "uninit-control-dep-attempts",
 	  "Maximum number of nested calls to search for control dependencies "
diff --git a/gcc/params.h b/gcc/params.h
index 26f1236aa65422f66939ef2a4c38958bdc984aee..ad40bd0b5d3b217e6d0dc531fce=
04faba97b5f60 100644
--- a/gcc/params.h
+++ b/gcc/params.h
@@ -252,5 +252,9 @@ extern void init_param_values (int *params);
   PARAM_VALUE (PARAM_ASAN_INSTRUMENTATION_WITH_CALL_THRESHOLD)
 #define ASAN_PARAM_USE_AFTER_SCOPE_DIRECT_EMISSION_THRESHOLD \
   ((unsigned) PARAM_VALUE (PARAM_USE_AFTER_SCOPE_DIRECT_EMISSION_THRESHOLD=
))
+#define HWASAN_STACK \
+  PARAM_VALUE (PARAM_HWASAN_STACK)
+#define HWASAN_RANDOM_FRAME_TAG \
+  PARAM_VALUE (PARAM_HWASAN_RANDOM_FRAME_TAG)
=20
 #endif /* ! GCC_PARAMS_H */
diff --git a/gcc/target.def b/gcc/target.def
index 01609136848fc157a47a93a0267c03524fe9383e..0ade31accab25bf121f135cbf02=
c6adfcd6e1476 100644
--- a/gcc/target.def
+++ b/gcc/target.def
@@ -6706,6 +6706,17 @@ DEFHOOK
 HOOK_VECTOR_END (mode_switching)
=20
 #undef HOOK_PREFIX
+#define HOOK_PREFIX "TARGET_MEMTAG_"
+HOOK_VECTOR (TARGET_MEMTAG_, memtag)
+
+DEFHOOK
+(can_tag_addresses,
+ "True if backend architecture naturally supports ignoring the top byte of=
\
+ pointers.  This feature means that -fsanitize=3Dhwaddress can work.",
+ bool, (), default_memtag_can_tag_addresses)
+
+HOOK_VECTOR_END (memtag)
+#undef HOOK_PREFIX
 #define HOOK_PREFIX "TARGET_"
=20
 #define DEF_TARGET_INSN(NAME, PROTO) \
diff --git a/gcc/targhooks.h b/gcc/targhooks.h
index 5aba67660f85406b9fd475e75a3cc65b0d1952f5..463c27c7d7b550bf63630f21026=
81b37ffd265cb 100644
--- a/gcc/targhooks.h
+++ b/gcc/targhooks.h
@@ -284,4 +284,5 @@ extern rtx default_speculation_safe_value (machine_mode=
, rtx, rtx, rtx);
 extern void default_remove_extra_call_preserved_regs (rtx_insn *,
 						      HARD_REG_SET *);
=20
+extern bool default_memtag_can_tag_addresses ();
 #endif /* GCC_TARGHOOKS_H */
diff --git a/gcc/targhooks.c b/gcc/targhooks.c
index ed77afb1da57e59bc0725dc0d6fac477391bae03..d7dd07db65c8248c2f170466db2=
1449a56713d69 100644
--- a/gcc/targhooks.c
+++ b/gcc/targhooks.c
@@ -2368,4 +2368,10 @@ default_remove_extra_call_preserved_regs (rtx_insn *=
, HARD_REG_SET *)
 {
 }
=20
+bool
+default_memtag_can_tag_addresses ()
+{
+  return false;
+}
+
 #include "gt-targhooks.h"
diff --git a/gcc/toplev.c b/gcc/toplev.c
index d741a66f3857a60bcdb6f5c1b60e781ff311aad4..3920ef5c40f27b27a449dc6bf1d=
a795f0d40e77b 100644
--- a/gcc/toplev.c
+++ b/gcc/toplev.c
@@ -1752,6 +1752,16 @@ process_options (void)
       flag_sanitize &=3D ~SANITIZE_ADDRESS;
     }
=20
+  /* HWAsan requires top byte ignore feature in the backend.  */
+  if (flag_sanitize & SANITIZE_HWADDRESS
+      && ! targetm.memtag.can_tag_addresses ())
+    {
+      warning_at (UNKNOWN_LOCATION, 0,
+		  "%<-fsanitize=3Dhwaddress%> can not be implemented on "
+		  "a backend that does not ignore the top byte of a pointer");
+      flag_sanitize &=3D ~SANITIZE_HWADDRESS;
+    }
+
  /* Do not use IPA optimizations for register allocation if profiler is ac=
tive
     or patchable function entries are inserted for run-time instrumentatio=
n
     or port does not emit prologue and epilogue as RTL.  */

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/HE1PR0802MB2251783050BA897E608882ACE07E0%40HE1PR0802MB2251.eurprd=
08.prod.outlook.com.

--_002_HE1PR0802MB2251783050BA897E608882ACE07E0HE1PR0802MB2251_
Content-Type: text/plain; name="hwasan-patch13.patch"
Content-Description: hwasan-patch13.patch
Content-Disposition: attachment; filename="hwasan-patch13.patch"; size=17711;
	creation-date="Tue, 05 Nov 2019 11:34:32 GMT";
	modification-date="Tue, 05 Nov 2019 11:34:32 GMT"
Content-ID: <A62AEAD8E906334D957E222143AA1D41@eurprd08.prod.outlook.com>
Content-Transfer-Encoding: base64

ZGlmZiAtLWdpdCBhL2djYy9jLWZhbWlseS9jLWF0dHJpYnMuYyBiL2djYy9jLWZhbWlseS9jLWF0
dHJpYnMuYwppbmRleCA2NTAwYjk5ODMyMTQxOWExZDhkNTcwNjI1MzQyMDZjNTkwOWFkYjdhLi4y
ZGU5NDgxNWY5MWRhNWEwZmQwNmMzMGQwMDQ0Zjg2NjA4NDEyMWI4IDEwMDY0NAotLS0gYS9nY2Mv
Yy1mYW1pbHkvYy1hdHRyaWJzLmMKKysrIGIvZ2NjL2MtZmFtaWx5L2MtYXR0cmlicy5jCkBAIC01
NCw2ICs1NCw4IEBAIHN0YXRpYyB0cmVlIGhhbmRsZV9jb2xkX2F0dHJpYnV0ZSAodHJlZSAqLCB0
cmVlLCB0cmVlLCBpbnQsIGJvb2wgKik7CiBzdGF0aWMgdHJlZSBoYW5kbGVfbm9fc2FuaXRpemVf
YXR0cmlidXRlICh0cmVlICosIHRyZWUsIHRyZWUsIGludCwgYm9vbCAqKTsKIHN0YXRpYyB0cmVl
IGhhbmRsZV9ub19zYW5pdGl6ZV9hZGRyZXNzX2F0dHJpYnV0ZSAodHJlZSAqLCB0cmVlLCB0cmVl
LAogCQkJCQkJICBpbnQsIGJvb2wgKik7CitzdGF0aWMgdHJlZSBoYW5kbGVfbm9fc2FuaXRpemVf
aHdhZGRyZXNzX2F0dHJpYnV0ZSAodHJlZSAqLCB0cmVlLCB0cmVlLAorCQkJCQkJICAgIGludCwg
Ym9vbCAqKTsKIHN0YXRpYyB0cmVlIGhhbmRsZV9ub19zYW5pdGl6ZV90aHJlYWRfYXR0cmlidXRl
ICh0cmVlICosIHRyZWUsIHRyZWUsCiAJCQkJCQkgaW50LCBib29sICopOwogc3RhdGljIHRyZWUg
aGFuZGxlX25vX2FkZHJlc3Nfc2FmZXR5X2FuYWx5c2lzX2F0dHJpYnV0ZSAodHJlZSAqLCB0cmVl
LCB0cmVlLApAQCAtNDEwLDYgKzQxMiw4IEBAIGNvbnN0IHN0cnVjdCBhdHRyaWJ1dGVfc3BlYyBj
X2NvbW1vbl9hdHRyaWJ1dGVfdGFibGVbXSA9CiAJCQkgICAgICBoYW5kbGVfbm9fc2FuaXRpemVf
YXR0cmlidXRlLCBOVUxMIH0sCiAgIHsgIm5vX3Nhbml0aXplX2FkZHJlc3MiLCAgICAwLCAwLCB0
cnVlLCBmYWxzZSwgZmFsc2UsIGZhbHNlLAogCQkJICAgICAgaGFuZGxlX25vX3Nhbml0aXplX2Fk
ZHJlc3NfYXR0cmlidXRlLCBOVUxMIH0sCisgIHsgIm5vX3Nhbml0aXplX2h3YWRkcmVzcyIsICAg
IDAsIDAsIHRydWUsIGZhbHNlLCBmYWxzZSwgZmFsc2UsCisJCQkgICAgICBoYW5kbGVfbm9fc2Fu
aXRpemVfaHdhZGRyZXNzX2F0dHJpYnV0ZSwgTlVMTCB9LAogICB7ICJub19zYW5pdGl6ZV90aHJl
YWQiLCAgICAgMCwgMCwgdHJ1ZSwgZmFsc2UsIGZhbHNlLCBmYWxzZSwKIAkJCSAgICAgIGhhbmRs
ZV9ub19zYW5pdGl6ZV90aHJlYWRfYXR0cmlidXRlLCBOVUxMIH0sCiAgIHsgIm5vX3Nhbml0aXpl
X3VuZGVmaW5lZCIsICAwLCAwLCB0cnVlLCBmYWxzZSwgZmFsc2UsIGZhbHNlLApAQCAtOTI5LDYg
KzkzMywyMiBAQCBoYW5kbGVfbm9fc2FuaXRpemVfYWRkcmVzc19hdHRyaWJ1dGUgKHRyZWUgKm5v
ZGUsIHRyZWUgbmFtZSwgdHJlZSwgaW50LAogICByZXR1cm4gTlVMTF9UUkVFOwogfQogCisvKiBI
YW5kbGUgYSAibm9fc2FuaXRpemVfaHdhZGRyZXNzIiBhdHRyaWJ1dGU7IGFyZ3VtZW50cyBhcyBp
bgorICAgc3RydWN0IGF0dHJpYnV0ZV9zcGVjLmhhbmRsZXIuICAqLworCitzdGF0aWMgdHJlZQor
aGFuZGxlX25vX3Nhbml0aXplX2h3YWRkcmVzc19hdHRyaWJ1dGUgKHRyZWUgKm5vZGUsIHRyZWUg
bmFtZSwgdHJlZSwgaW50LAorCQkJCSAgICAgIGJvb2wgKm5vX2FkZF9hdHRycykKK3sKKyAgKm5v
X2FkZF9hdHRycyA9IHRydWU7CisgIGlmIChUUkVFX0NPREUgKCpub2RlKSAhPSBGVU5DVElPTl9E
RUNMKQorICAgIHdhcm5pbmcgKE9QVF9XYXR0cmlidXRlcywgIiVxRSBhdHRyaWJ1dGUgaWdub3Jl
ZCIsIG5hbWUpOworICBlbHNlCisgICAgYWRkX25vX3Nhbml0aXplX3ZhbHVlICgqbm9kZSwgU0FO
SVRJWkVfSFdBRERSRVNTKTsKKworICByZXR1cm4gTlVMTF9UUkVFOworfQorCiAvKiBIYW5kbGUg
YSAibm9fc2FuaXRpemVfdGhyZWFkIiBhdHRyaWJ1dGU7IGFyZ3VtZW50cyBhcyBpbgogICAgc3Ry
dWN0IGF0dHJpYnV0ZV9zcGVjLmhhbmRsZXIuICAqLwogCmRpZmYgLS1naXQgYS9nY2MvY29tbW9u
Lm9wdCBiL2djYy9jb21tb24ub3B0CmluZGV4IDFiOWUwZjNjODAyNWEzYjQzOWY3NjZlZGNkODFk
YjQ2Mjk3MzAzN2IuLmQ4YmE5NTU2ODAxZTVhZmM0NzljMzNiYTM1OTEyNWQ2MzU0Y2E4NjIgMTAw
NjQ0Ci0tLSBhL2djYy9jb21tb24ub3B0CisrKyBiL2djYy9jb21tb24ub3B0CkBAIC0yMTUsNyAr
MjE1LDcgQEAgdW5zaWduZWQgaW50IGZsYWdfc2FuaXRpemUKIAogOyBXaGF0IHNhbml0aXplcnMg
c2hvdWxkIHJlY292ZXIgZnJvbSBlcnJvcnMKIFZhcmlhYmxlCi11bnNpZ25lZCBpbnQgZmxhZ19z
YW5pdGl6ZV9yZWNvdmVyID0gKFNBTklUSVpFX1VOREVGSU5FRCB8IFNBTklUSVpFX1VOREVGSU5F
RF9OT05ERUZBVUxUIHwgU0FOSVRJWkVfS0VSTkVMX0FERFJFU1MpICYgfihTQU5JVElaRV9VTlJF
QUNIQUJMRSB8IFNBTklUSVpFX1JFVFVSTikKK3Vuc2lnbmVkIGludCBmbGFnX3Nhbml0aXplX3Jl
Y292ZXIgPSAoU0FOSVRJWkVfVU5ERUZJTkVEIHwgU0FOSVRJWkVfVU5ERUZJTkVEX05PTkRFRkFV
TFQgfCBTQU5JVElaRV9LRVJORUxfQUREUkVTUyB8IFNBTklUSVpFX0tFUk5FTF9IV0FERFJFU1Mp
ICYgfihTQU5JVElaRV9VTlJFQUNIQUJMRSB8IFNBTklUSVpFX1JFVFVSTikKIAogOyBXaGF0IHRo
ZSBjb3ZlcmFnZSBzYW5pdGl6ZXJzIHNob3VsZCBpbnN0cnVtZW50CiBWYXJpYWJsZQpAQCAtMzI4
OSw2ICszMjg5LDkgQEAgRHJpdmVyCiBzdGF0aWMtbGliYXNhbgogRHJpdmVyCiAKK3N0YXRpYy1s
aWJod2FzYW4KK0RyaXZlcgorCiBzdGF0aWMtbGlidHNhbgogRHJpdmVyCiAKZGlmZiAtLWdpdCBh
L2djYy9jb25maWcvYWFyY2g2NC9hYXJjaDY0LmMgYi9nY2MvY29uZmlnL2FhcmNoNjQvYWFyY2g2
NC5jCmluZGV4IDIzMjMxN2Q0YTVhNGExNjUyOWY1NzNlZWY1YThkN2EwNjgwNjgyMDcuLmM1NTZi
Y2QxYzM3YzNjNGZkZDlhODI5YTI4ZWU0ZmY1NjgxOWI4OWUgMTAwNjQ0Ci0tLSBhL2djYy9jb25m
aWcvYWFyY2g2NC9hYXJjaDY0LmMKKysrIGIvZ2NjL2NvbmZpZy9hYXJjaDY0L2FhcmNoNjQuYwpA
QCAtMjAyNzIsNiArMjAyNzIsMTUgQEAgYWFyY2g2NF9zdGFja19wcm90ZWN0X2d1YXJkICh2b2lk
KQogICByZXR1cm4gTlVMTF9UUkVFOwogfQogCisvKiBJbXBsZW1lbnQgVEFSR0VUX01FTVRBR19D
QU5fVEFHX0FERFJFU1NFUy4gIEhlcmUgd2UgdGVsbCB0aGUgcmVzdCBvZiB0aGUKKyAgIGNvbXBp
bGVyIHRoYXQgd2UgYXV0b21hdGljYWxseSBpZ25vcmUgdGhlIHRvcCBieXRlIG9mIG91ciBwb2lu
dGVycywgd2hpY2gKKyAgIGFsbG93cyB1c2luZyAtZnNhbml0aXplPWh3YWRkcmVzcy4gICovCiti
b29sCithYXJjaDY0X2Nhbl90YWdfYWRkcmVzc2VzICgpCit7CisgIHJldHVybiB0cnVlOworfQor
CiAvKiBJbXBsZW1lbnQgVEFSR0VUX0FTTV9GSUxFX0VORCBmb3IgQUFyY2g2NC4gIFRoaXMgYWRk
cyB0aGUgQUFyY2g2NCBHTlUgTk9URQogICAgc2VjdGlvbiBhdCB0aGUgZW5kIGlmIG5lZWRlZC4g
ICovCiAjZGVmaW5lIEdOVV9QUk9QRVJUWV9BQVJDSDY0X0ZFQVRVUkVfMV9BTkQJMHhjMDAwMDAw
MApAQCAtMjA4MzksNiArMjA4NDgsOSBAQCBhYXJjaDY0X2xpYmdjY19mbG9hdGluZ19tb2RlX3N1
cHBvcnRlZF9wCiAjdW5kZWYgVEFSR0VUX0dFVF9NVUxUSUxJQl9BQklfTkFNRQogI2RlZmluZSBU
QVJHRVRfR0VUX01VTFRJTElCX0FCSV9OQU1FIGFhcmNoNjRfZ2V0X211bHRpbGliX2FiaV9uYW1l
CiAKKyN1bmRlZiBUQVJHRVRfTUVNVEFHX0NBTl9UQUdfQUREUkVTU0VTCisjZGVmaW5lIFRBUkdF
VF9NRU1UQUdfQ0FOX1RBR19BRERSRVNTRVMgYWFyY2g2NF9jYW5fdGFnX2FkZHJlc3NlcworCiAj
aWYgQ0hFQ0tJTkdfUAogI3VuZGVmIFRBUkdFVF9SVU5fVEFSR0VUX1NFTEZURVNUUwogI2RlZmlu
ZSBUQVJHRVRfUlVOX1RBUkdFVF9TRUxGVEVTVFMgc2VsZnRlc3Q6OmFhcmNoNjRfcnVuX3NlbGZ0
ZXN0cwpkaWZmIC0tZ2l0IGEvZ2NjL2NvbmZpZy9nbnUtdXNlci5oIGIvZ2NjL2NvbmZpZy9nbnUt
dXNlci5oCmluZGV4IDk1YTNjMjlmN2NlZTg2MzM2Zjk1OGJlZjFkN2ZlNTZiODJlMDVlNmMuLjkw
YjFmYTkxNzQyYzZhN2Q3NmFhNmM3ZTkzMWY4MDE0ZmM0ZmZmMGMgMTAwNjQ0Ci0tLSBhL2djYy9j
b25maWcvZ251LXVzZXIuaAorKysgYi9nY2MvY29uZmlnL2dudS11c2VyLmgKQEAgLTEyOSwxNCAr
MTI5LDE4IEBAIHNlZSB0aGUgZmlsZXMgQ09QWUlORzMgYW5kIENPUFlJTkcuUlVOVElNRSByZXNw
ZWN0aXZlbHkuICBJZiBub3QsIHNlZQogLyogTGluayAtbGFzYW4gZWFybHkgb24gdGhlIGNvbW1h
bmQgbGluZS4gIEZvciAtc3RhdGljLWxpYmFzYW4sIGRvbid0IGxpbmsKICAgIGl0IGZvciAtc2hh
cmVkIGxpbmssIHRoZSBleGVjdXRhYmxlIHNob3VsZCBiZSBjb21waWxlZCB3aXRoIC1zdGF0aWMt
bGliYXNhbgogICAgaW4gdGhhdCBjYXNlLCBhbmQgZm9yIGV4ZWN1dGFibGUgbGluayB3aXRoIC0t
eyxuby19d2hvbGUtYXJjaGl2ZSBhcm91bmQKLSAgIGl0IHRvIGZvcmNlIGV2ZXJ5dGhpbmcgaW50
byB0aGUgZXhlY3V0YWJsZS4gIEFuZCBzaW1pbGFybHkgZm9yIC1sdHNhbgotICAgYW5kIC1sbHNh
bi4gICovCisgICBpdCB0byBmb3JjZSBldmVyeXRoaW5nIGludG8gdGhlIGV4ZWN1dGFibGUuICBB
bmQgc2ltaWxhcmx5IGZvciAtbHRzYW4sCisgICAtbGh3YXNhbiwgYW5kIC1sbHNhbi4gICovCiAj
aWYgZGVmaW5lZChIQVZFX0xEX1NUQVRJQ19EWU5BTUlDKQogI3VuZGVmIExJQkFTQU5fRUFSTFlf
U1BFQwogI2RlZmluZSBMSUJBU0FOX0VBUkxZX1NQRUMgIiV7IXNoYXJlZDpsaWJhc2FuX3ByZWlu
aXQlTyVzfSAiIFwKICAgIiV7c3RhdGljLWxpYmFzYW46JXshc2hhcmVkOiIgXAogICBMRF9TVEFU
SUNfT1BUSU9OICIgLS13aG9sZS1hcmNoaXZlIC1sYXNhbiAtLW5vLXdob2xlLWFyY2hpdmUgIiBc
CiAgIExEX0RZTkFNSUNfT1BUSU9OICJ9fSV7IXN0YXRpYy1saWJhc2FuOi1sYXNhbn0iCisjdW5k
ZWYgTElCSFdBU0FOX0VBUkxZX1NQRUMKKyNkZWZpbmUgTElCSFdBU0FOX0VBUkxZX1NQRUMgIiV7
c3RhdGljLWxpYmh3YXNhbjoleyFzaGFyZWQ6IiBcCisgIExEX1NUQVRJQ19PUFRJT04gIiAtLXdo
b2xlLWFyY2hpdmUgLWxod2FzYW4gLS1uby13aG9sZS1hcmNoaXZlICIgXAorICBMRF9EWU5BTUlD
X09QVElPTiAifX0leyFzdGF0aWMtbGliaHdhc2FuOi1saHdhc2FufSIKICN1bmRlZiBMSUJUU0FO
X0VBUkxZX1NQRUMKICNkZWZpbmUgTElCVFNBTl9FQVJMWV9TUEVDICIleyFzaGFyZWQ6bGlidHNh
bl9wcmVpbml0JU8lc30gIiBcCiAgICIle3N0YXRpYy1saWJ0c2FuOiV7IXNoYXJlZDoiIFwKZGlm
ZiAtLWdpdCBhL2djYy9jcHBidWlsdGluLmMgYi9nY2MvY3BwYnVpbHRpbi5jCmluZGV4IDYwZTVi
ZWRjMzY2NWEyNWZhNTFjMmVjYTAwNTQ3ZjEyYTk5NTM3NzguLmU4ZDBiZWRmYzJlYjIyZDFlNzJl
N2U0ODc1MTU1MjAyYzgzODlhMzggMTAwNjQ0Ci0tLSBhL2djYy9jcHBidWlsdGluLmMKKysrIGIv
Z2NjL2NwcGJ1aWx0aW4uYwpAQCAtOTMsNiArOTMsOSBAQCBkZWZpbmVfYnVpbHRpbl9tYWNyb3Nf
Zm9yX2NvbXBpbGF0aW9uX2ZsYWdzIChjcHBfcmVhZGVyICpwZmlsZSkKICAgaWYgKGZsYWdfc2Fu
aXRpemUgJiBTQU5JVElaRV9BRERSRVNTKQogICAgIGNwcF9kZWZpbmUgKHBmaWxlLCAiX19TQU5J
VElaRV9BRERSRVNTX18iKTsKIAorICBpZiAoZmxhZ19zYW5pdGl6ZSAmIFNBTklUSVpFX0hXQURE
UkVTUykKKyAgICBjcHBfZGVmaW5lIChwZmlsZSwgIl9fU0FOSVRJWkVfSFdBRERSRVNTX18iKTsK
KwogICBpZiAoZmxhZ19zYW5pdGl6ZSAmIFNBTklUSVpFX1RIUkVBRCkKICAgICBjcHBfZGVmaW5l
IChwZmlsZSwgIl9fU0FOSVRJWkVfVEhSRUFEX18iKTsKIApkaWZmIC0tZ2l0IGEvZ2NjL2RvYy90
bS50ZXhpIGIvZ2NjL2RvYy90bS50ZXhpCmluZGV4IDAyNTBjZjU4ZTcyYjRkZjhmZWMxOWNmYjQz
OTllZDBlMjU5NDM0MmIuLmJmNTNkZjcxNTM5MTEyOGQ2ZmJlOWJlNGU3NzkwNjY1MDMwOWFiMmUg
MTAwNjQ0Ci0tLSBhL2djYy9kb2MvdG0udGV4aQorKysgYi9nY2MvZG9jL3RtLnRleGkKQEAgLTI5
NzIsNiArMjk3MiwxMCBAQCBUaGlzIGhvb2sgZGVmaW5lcyB0aGUgbWFjaGluZSBtb2RlIHRvIHVz
ZSBmb3IgdGhlIGJvb2xlYW4gcmVzdWx0IG9mICBjb25kaXRpb25hbAogQSB0YXJnZXQgaG9vayB3
aGljaCBsZXRzIGEgYmFja2VuZCBjb21wdXRlIHRoZSBzZXQgb2YgcHJlc3N1cmUgY2xhc3NlcyB0
byAgYmUgdXNlZCBieSB0aG9zZSBvcHRpbWl6YXRpb24gcGFzc2VzIHdoaWNoIHRha2UgcmVnaXN0
ZXIgcHJlc3N1cmUgaW50byAgYWNjb3VudCwgYXMgb3Bwb3NlZCB0byBsZXR0aW5nIElSQSBjb21w
dXRlIHRoZW0uICBJdCByZXR1cm5zIHRoZSBudW1iZXIgb2YgIHJlZ2lzdGVyIGNsYXNzZXMgc3Rv
cmVkIGluIHRoZSBhcnJheSBAdmFye3ByZXNzdXJlX2NsYXNzZXN9LgogQGVuZCBkZWZ0eXBlZm4K
IAorQGRlZnR5cGVmbiB7VGFyZ2V0IEhvb2t9IGJvb2wgVEFSR0VUX01FTVRBR19DQU5fVEFHX0FE
RFJFU1NFUyAoKQorVHJ1ZSBpZiBiYWNrZW5kIGFyY2hpdGVjdHVyZSBuYXR1cmFsbHkgc3VwcG9y
dHMgaWdub3JpbmcgdGhlIHRvcCBieXRlIG9mIHBvaW50ZXJzLiAgVGhpcyBmZWF0dXJlIG1lYW5z
IHRoYXQgLWZzYW5pdGl6ZT1od2FkZHJlc3MgY2FuIHdvcmsuCitAZW5kIGRlZnR5cGVmbgorCiBA
bm9kZSBTdGFjayBhbmQgQ2FsbGluZwogQHNlY3Rpb24gU3RhY2sgTGF5b3V0IGFuZCBDYWxsaW5n
IENvbnZlbnRpb25zCiBAY2luZGV4IGNhbGxpbmcgY29udmVudGlvbnMKZGlmZiAtLWdpdCBhL2dj
Yy9kb2MvdG0udGV4aS5pbiBiL2djYy9kb2MvdG0udGV4aS5pbgppbmRleCAwYjc3ZGQ4ZWI0NmRj
NTNmYzU4NWQ3YjNlYWM5ODA1YzZlZDc5OTUxLi4wMDVjZWYwNTk5OWQ3YzMzNGYxNmZmYTM2ODkw
M2MzYjY2ODA2MjMxIDEwMDY0NAotLS0gYS9nY2MvZG9jL3RtLnRleGkuaW4KKysrIGIvZ2NjL2Rv
Yy90bS50ZXhpLmluCkBAIC0yMzc0LDYgKzIzNzQsOCBAQCBpbiB0aGUgcmVsb2FkIHBhc3MuCiAK
IEBob29rIFRBUkdFVF9DT01QVVRFX1BSRVNTVVJFX0NMQVNTRVMKIAorQGhvb2sgVEFSR0VUX01F
TVRBR19DQU5fVEFHX0FERFJFU1NFUworCiBAbm9kZSBTdGFjayBhbmQgQ2FsbGluZwogQHNlY3Rp
b24gU3RhY2sgTGF5b3V0IGFuZCBDYWxsaW5nIENvbnZlbnRpb25zCiBAY2luZGV4IGNhbGxpbmcg
Y29udmVudGlvbnMKZGlmZiAtLWdpdCBhL2djYy9mbGFnLXR5cGVzLmggYi9nY2MvZmxhZy10eXBl
cy5oCmluZGV4IGEyMTAzMjgyZDQ2OWRiMzFhZDE1N2E4NzU3MjA2OGQ5NDMwNjFjOGMuLjU3ZDhm
ZjlhMWEwMTA0MDlkOTY2MjMwMTQwZGYxMDE3YmMzNTg0YTggMTAwNjQ0Ci0tLSBhL2djYy9mbGFn
LXR5cGVzLmgKKysrIGIvZ2NjL2ZsYWctdHlwZXMuaApAQCAtMjU2LDYgKzI1Niw5IEBAIGVudW0g
c2FuaXRpemVfY29kZSB7CiAgIFNBTklUSVpFX0JVSUxUSU4gPSAxVUwgPDwgMjUsCiAgIFNBTklU
SVpFX1BPSU5URVJfQ09NUEFSRSA9IDFVTCA8PCAyNiwKICAgU0FOSVRJWkVfUE9JTlRFUl9TVUJU
UkFDVCA9IDFVTCA8PCAyNywKKyAgU0FOSVRJWkVfSFdBRERSRVNTID0gMVVMIDw8IDI4LAorICBT
QU5JVElaRV9VU0VSX0hXQUREUkVTUyA9IDFVTCA8PCAyOSwKKyAgU0FOSVRJWkVfS0VSTkVMX0hX
QUREUkVTUyA9IDFVTCA8PCAzMCwKICAgU0FOSVRJWkVfU0hJRlQgPSBTQU5JVElaRV9TSElGVF9C
QVNFIHwgU0FOSVRJWkVfU0hJRlRfRVhQT05FTlQsCiAgIFNBTklUSVpFX1VOREVGSU5FRCA9IFNB
TklUSVpFX1NISUZUIHwgU0FOSVRJWkVfRElWSURFIHwgU0FOSVRJWkVfVU5SRUFDSEFCTEUKIAkJ
ICAgICAgIHwgU0FOSVRJWkVfVkxBIHwgU0FOSVRJWkVfTlVMTCB8IFNBTklUSVpFX1JFVFVSTgpk
aWZmIC0tZ2l0IGEvZ2NjL2djYy5jIGIvZ2NjL2djYy5jCmluZGV4IDEyMTZjZGQ1MDVhMTgxNTJk
YzFkM2VlZTVmMzc3NTVhMzk2NzYxZjEuLmNmMWJkOWRlNjYwZjMyZjA2MGI5Mjc3Zjg5YTU2Mjg3
M2E0ODY4NGEgMTAwNjQ0Ci0tLSBhL2djYy9nY2MuYworKysgYi9nY2MvZ2NjLmMKQEAgLTcwOCw2
ICs3MDgsMjQgQEAgcHJvcGVyIHBvc2l0aW9uIGFtb25nIHRoZSBvdGhlciBvdXRwdXQgZmlsZXMu
ICAqLwogI2RlZmluZSBMSUJBU0FOX0VBUkxZX1NQRUMgIiIKICNlbmRpZgogCisjaWZuZGVmIExJ
QkhXQVNBTl9TUEVDCisjZGVmaW5lIFNUQVRJQ19MSUJIV0FTQU5fTElCUyBcCisgICIgJXtzdGF0
aWMtbGliaHdhc2FufHN0YXRpYzolOmluY2x1ZGUobGlic2FuaXRpemVyLnNwZWMpJShsaW5rX2xp
Ymh3YXNhbil9IgorI2lmZGVmIExJQkhXQVNBTl9FQVJMWV9TUEVDCisjZGVmaW5lIExJQkhXQVNB
Tl9TUEVDIFNUQVRJQ19MSUJIV0FTQU5fTElCUworI2VsaWYgZGVmaW5lZChIQVZFX0xEX1NUQVRJ
Q19EWU5BTUlDKQorI2RlZmluZSBMSUJIV0FTQU5fU1BFQyAiJXtzdGF0aWMtbGliaHdhc2FuOiIg
TERfU1RBVElDX09QVElPTiBcCisJCSAgICAgIn0gLWxod2FzYW4gJXtzdGF0aWMtbGliaHdhc2Fu
OiIgTERfRFlOQU1JQ19PUFRJT04gIn0iIFwKKwkJICAgICBTVEFUSUNfTElCSFdBU0FOX0xJQlMK
KyNlbHNlCisjZGVmaW5lIExJQkhXQVNBTl9TUEVDICItbGh3YXNhbiIgU1RBVElDX0xJQkhXQVNB
Tl9MSUJTCisjZW5kaWYKKyNlbmRpZgorCisjaWZuZGVmIExJQkhXQVNBTl9FQVJMWV9TUEVDCisj
ZGVmaW5lIExJQkhXQVNBTl9FQVJMWV9TUEVDICIiCisjZW5kaWYKKwogI2lmbmRlZiBMSUJUU0FO
X1NQRUMKICNkZWZpbmUgU1RBVElDX0xJQlRTQU5fTElCUyBcCiAgICIgJXtzdGF0aWMtbGlidHNh
bnxzdGF0aWM6JTppbmNsdWRlKGxpYnNhbml0aXplci5zcGVjKSUobGlua19saWJ0c2FuKX0iCkBA
IC05ODIsNiArMTAwMCw3IEBAIHByb3BlciBwb3NpdGlvbiBhbW9uZyB0aGUgb3RoZXIgb3V0cHV0
IGZpbGVzLiAgKi8KICNpZm5kZWYgU0FOSVRJWkVSX0VBUkxZX1NQRUMKICNkZWZpbmUgU0FOSVRJ
WkVSX0VBUkxZX1NQRUMgIlwKICV7IW5vc3RkbGliOiV7IXI6JXshbm9kZWZhdWx0bGliczoleyU6
c2FuaXRpemUoYWRkcmVzcyk6IiBMSUJBU0FOX0VBUkxZX1NQRUMgIn0gXAorICAgICV7JTpzYW5p
dGl6ZShod2FkZHJlc3MpOiIgTElCSFdBU0FOX0VBUkxZX1NQRUMgIn0gXAogICAgICV7JTpzYW5p
dGl6ZSh0aHJlYWQpOiIgTElCVFNBTl9FQVJMWV9TUEVDICJ9IFwKICAgICAleyU6c2FuaXRpemUo
bGVhayk6IiBMSUJMU0FOX0VBUkxZX1NQRUMgIn19fX0iCiAjZW5kaWYKQEAgLTk5MSw2ICsxMDEw
LDggQEAgcHJvcGVyIHBvc2l0aW9uIGFtb25nIHRoZSBvdGhlciBvdXRwdXQgZmlsZXMuICAqLwog
I2RlZmluZSBTQU5JVElaRVJfU1BFQyAiXAogJXshbm9zdGRsaWI6JXshcjoleyFub2RlZmF1bHRs
aWJzOiV7JTpzYW5pdGl6ZShhZGRyZXNzKToiIExJQkFTQU5fU1BFQyAiXAogICAgICV7c3RhdGlj
OiVlY2Fubm90IHNwZWNpZnkgLXN0YXRpYyB3aXRoIC1mc2FuaXRpemU9YWRkcmVzc319XAorICAg
ICV7JTpzYW5pdGl6ZShod2FkZHJlc3MpOiIgTElCSFdBU0FOX1NQRUMgIlwKKwkle3N0YXRpYzol
ZWNhbm5vdCBzcGVjaWZ5IC1zdGF0aWMgd2l0aCAtZnNhbml0aXplPWh3YWRkcmVzc319XAogICAg
ICV7JTpzYW5pdGl6ZSh0aHJlYWQpOiIgTElCVFNBTl9TUEVDICJcCiAgICAgJXtzdGF0aWM6JWVj
YW5ub3Qgc3BlY2lmeSAtc3RhdGljIHdpdGggLWZzYW5pdGl6ZT10aHJlYWR9fVwKICAgICAleyU6
c2FuaXRpemUodW5kZWZpbmVkKToiIExJQlVCU0FOX1NQRUMgIn1cCkBAIC05NDM0LDggKzk0NTUs
MTIgQEAgc2FuaXRpemVfc3BlY19mdW5jdGlvbiAoaW50IGFyZ2MsIGNvbnN0IGNoYXIgKiphcmd2
KQogCiAgIGlmIChzdHJjbXAgKGFyZ3ZbMF0sICJhZGRyZXNzIikgPT0gMCkKICAgICByZXR1cm4g
KGZsYWdfc2FuaXRpemUgJiBTQU5JVElaRV9VU0VSX0FERFJFU1MpID8gIiIgOiBOVUxMOworICBp
ZiAoc3RyY21wIChhcmd2WzBdLCAiaHdhZGRyZXNzIikgPT0gMCkKKyAgICByZXR1cm4gKGZsYWdf
c2FuaXRpemUgJiBTQU5JVElaRV9VU0VSX0hXQUREUkVTUykgPyAiIiA6IE5VTEw7CiAgIGlmIChz
dHJjbXAgKGFyZ3ZbMF0sICJrZXJuZWwtYWRkcmVzcyIpID09IDApCiAgICAgcmV0dXJuIChmbGFn
X3Nhbml0aXplICYgU0FOSVRJWkVfS0VSTkVMX0FERFJFU1MpID8gIiIgOiBOVUxMOworICBpZiAo
c3RyY21wIChhcmd2WzBdLCAia2VybmVsLWh3YWRkcmVzcyIpID09IDApCisgICAgcmV0dXJuIChm
bGFnX3Nhbml0aXplICYgU0FOSVRJWkVfS0VSTkVMX0hXQUREUkVTUykgPyAiIiA6IE5VTEw7CiAg
IGlmIChzdHJjbXAgKGFyZ3ZbMF0sICJ0aHJlYWQiKSA9PSAwKQogICAgIHJldHVybiAoZmxhZ19z
YW5pdGl6ZSAmIFNBTklUSVpFX1RIUkVBRCkgPyAiIiA6IE5VTEw7CiAgIGlmIChzdHJjbXAgKGFy
Z3ZbMF0sICJ1bmRlZmluZWQiKSA9PSAwKQpkaWZmIC0tZ2l0IGEvZ2NjL29wdHMuYyBiL2djYy9v
cHRzLmMKaW5kZXggZWZkNzVhYWRlNmM4NzlmMzMwZGIxYWE3YjhlZjZiOTEwMDg2MmMwNC4uODhh
OTQyODZlNzFmNjFmMmRjZTkwNzAxOGU1MTg1ZjYzYTgzMDgwNCAxMDA2NDQKLS0tIGEvZ2NjL29w
dHMuYworKysgYi9nY2Mvb3B0cy5jCkBAIC0xMTYwLDYgKzExNjAsMTMgQEAgZmluaXNoX29wdGlv
bnMgKHN0cnVjdCBnY2Nfb3B0aW9ucyAqb3B0cywgc3RydWN0IGdjY19vcHRpb25zICpvcHRzX3Nl
dCwKIAkJICAiJTwtZnNhbml0aXplPWFkZHJlc3MlPiBvciAlPC1mc2FuaXRpemU9a2VybmVsLWFk
ZHJlc3MlPiIpOwogICAgIH0KIAorICAvKiBVc2Vyc3BhY2UgYW5kIGtlcm5lbCBIV2FzYW4gY29u
ZmxpY3Qgd2l0aCBlYWNoIG90aGVyLiAgKi8KKyAgaWYgKChvcHRzLT54X2ZsYWdfc2FuaXRpemUg
JiBTQU5JVElaRV9VU0VSX0hXQUREUkVTUykKKyAgICAgICYmIChvcHRzLT54X2ZsYWdfc2FuaXRp
emUgJiBTQU5JVElaRV9LRVJORUxfSFdBRERSRVNTKSkKKyAgICBlcnJvcl9hdCAobG9jLAorCSAg
ICAgICIlPC1mc2FuaXRpemU9aHdhZGRyZXNzJT4gaXMgaW5jb21wYXRpYmxlIHdpdGggIgorCSAg
ICAgICIlPC1mc2FuaXRpemU9a2VybmVsLWh3YWRkcmVzcyU+Iik7CisKICAgLyogVXNlcnNwYWNl
IGFuZCBrZXJuZWwgQVNhbiBjb25mbGljdCB3aXRoIGVhY2ggb3RoZXIuICAqLwogICBpZiAoKG9w
dHMtPnhfZmxhZ19zYW5pdGl6ZSAmIFNBTklUSVpFX1VTRVJfQUREUkVTUykKICAgICAgICYmIChv
cHRzLT54X2ZsYWdfc2FuaXRpemUgJiBTQU5JVElaRV9LRVJORUxfQUREUkVTUykpCkBAIC0xMTc5
LDYgKzExODYsMjAgQEAgZmluaXNoX29wdGlvbnMgKHN0cnVjdCBnY2Nfb3B0aW9ucyAqb3B0cywg
c3RydWN0IGdjY19vcHRpb25zICpvcHRzX3NldCwKICAgICBlcnJvcl9hdCAobG9jLAogCSAgICAg
ICIlPC1mc2FuaXRpemU9bGVhayU+IGlzIGluY29tcGF0aWJsZSB3aXRoICU8LWZzYW5pdGl6ZT10
aHJlYWQlPiIpOwogCisgIC8qIEhXQVNhbiBhbmQgQVNhbiBjb25mbGljdCB3aXRoIGVhY2ggb3Ro
ZXIuICAqLworICBpZiAoKG9wdHMtPnhfZmxhZ19zYW5pdGl6ZSAmIFNBTklUSVpFX0FERFJFU1Mp
CisgICAgICAmJiAob3B0cy0+eF9mbGFnX3Nhbml0aXplICYgU0FOSVRJWkVfSFdBRERSRVNTKSkK
KyAgICBlcnJvcl9hdCAobG9jLAorCSAgICAgICIlPC1mc2FuaXRpemU9aHdhZGRyZXNzJT4gaXMg
aW5jb21wYXRpYmxlIHdpdGggYm90aCAiCisJICAgICAgIiU8LWZzYW5pdGl6ZT1hZGRyZXNzJT4g
YW5kICU8LWZzYW5pdGl6ZT1rZXJuZWwtYWRkcmVzcyU+Iik7CisKKyAgLyogSFdBU2FuIGNvbmZs
aWN0cyB3aXRoIFRTYW4uICAqLworICBpZiAoKG9wdHMtPnhfZmxhZ19zYW5pdGl6ZSAmIFNBTklU
SVpFX0hXQUREUkVTUykKKyAgICAgICYmIChvcHRzLT54X2ZsYWdfc2FuaXRpemUgJiBTQU5JVEla
RV9USFJFQUQpKQorICAgIGVycm9yX2F0IChsb2MsCisJICAgICAgIiU8LWZzYW5pdGl6ZT1od2Fk
ZHJlc3MlPiBpcyBpbmNvbXBhdGlibGUgd2l0aCAiCisJICAgICAgIiU8LWZzYW5pdGl6ZT10aHJl
YWQlPiIpOworCiAgIC8qIENoZWNrIGVycm9yIHJlY292ZXJ5IGZvciAtZnNhbml0aXplLXJlY292
ZXIgb3B0aW9uLiAgKi8KICAgZm9yIChpbnQgaSA9IDA7IHNhbml0aXplcl9vcHRzW2ldLm5hbWUg
IT0gTlVMTDsgKytpKQogICAgIGlmICgob3B0cy0+eF9mbGFnX3Nhbml0aXplX3JlY292ZXIgJiBz
YW5pdGl6ZXJfb3B0c1tpXS5mbGFnKQpAQCAtMTE5OCw3ICsxMjE5LDggQEAgZmluaXNoX29wdGlv
bnMgKHN0cnVjdCBnY2Nfb3B0aW9ucyAqb3B0cywgc3RydWN0IGdjY19vcHRpb25zICpvcHRzX3Nl
dCwKIAogICAvKiBFbmFibGUgLWZzYW5pdGl6ZS1hZGRyZXNzLXVzZS1hZnRlci1zY29wZSBpZiBh
ZGRyZXNzIHNhbml0aXplciBpcwogICAgICBlbmFibGVkLiAgKi8KLSAgaWYgKChvcHRzLT54X2Zs
YWdfc2FuaXRpemUgJiBTQU5JVElaRV9VU0VSX0FERFJFU1MpCisgIGlmICgoKG9wdHMtPnhfZmxh
Z19zYW5pdGl6ZSAmIFNBTklUSVpFX1VTRVJfQUREUkVTUykKKyAgICAgICB8fCAob3B0cy0+eF9m
bGFnX3Nhbml0aXplICYgU0FOSVRJWkVfVVNFUl9IV0FERFJFU1MpKQogICAgICAgJiYgIW9wdHNf
c2V0LT54X2ZsYWdfc2FuaXRpemVfYWRkcmVzc191c2VfYWZ0ZXJfc2NvcGUpCiAgICAgb3B0cy0+
eF9mbGFnX3Nhbml0aXplX2FkZHJlc3NfdXNlX2FmdGVyX3Njb3BlID0gdHJ1ZTsKIApAQCAtMTgy
Nyw4ICsxODQ5LDEzIEBAIGNvbnN0IHN0cnVjdCBzYW5pdGl6ZXJfb3B0c19zIHNhbml0aXplcl9v
cHRzW10gPQogI2RlZmluZSBTQU5JVElaRVJfT1BUKG5hbWUsIGZsYWdzLCByZWNvdmVyKSBcCiAg
ICAgeyAjbmFtZSwgZmxhZ3MsIHNpemVvZiAjbmFtZSAtIDEsIHJlY292ZXIgfQogICBTQU5JVEla
RVJfT1BUIChhZGRyZXNzLCAoU0FOSVRJWkVfQUREUkVTUyB8IFNBTklUSVpFX1VTRVJfQUREUkVT
UyksIHRydWUpLAorICBTQU5JVElaRVJfT1BUIChod2FkZHJlc3MsIChTQU5JVElaRV9IV0FERFJF
U1MgfCBTQU5JVElaRV9VU0VSX0hXQUREUkVTUyksCisJCSB0cnVlKSwKICAgU0FOSVRJWkVSX09Q
VCAoa2VybmVsLWFkZHJlc3MsIChTQU5JVElaRV9BRERSRVNTIHwgU0FOSVRJWkVfS0VSTkVMX0FE
RFJFU1MpLAogCQkgdHJ1ZSksCisgIFNBTklUSVpFUl9PUFQgKGtlcm5lbC1od2FkZHJlc3MsCisJ
CSAoU0FOSVRJWkVfSFdBRERSRVNTIHwgU0FOSVRJWkVfS0VSTkVMX0hXQUREUkVTUyksCisJCSB0
cnVlKSwKICAgU0FOSVRJWkVSX09QVCAocG9pbnRlci1jb21wYXJlLCBTQU5JVElaRV9QT0lOVEVS
X0NPTVBBUkUsIHRydWUpLAogICBTQU5JVElaRVJfT1BUIChwb2ludGVyLXN1YnRyYWN0LCBTQU5J
VElaRV9QT0lOVEVSX1NVQlRSQUNULCB0cnVlKSwKICAgU0FOSVRJWkVSX09QVCAodGhyZWFkLCBT
QU5JVElaRV9USFJFQUQsIGZhbHNlKSwKQEAgLTIzNjMsNiArMjM5MCwxNCBAQCBjb21tb25faGFu
ZGxlX29wdGlvbiAoc3RydWN0IGdjY19vcHRpb25zICpvcHRzLAogCQkJCSBvcHRzLT54X3BhcmFt
X3ZhbHVlcywKIAkJCQkgb3B0c19zZXQtPnhfcGFyYW1fdmFsdWVzKTsKIAl9CisgICAgICBpZiAo
b3B0cy0+eF9mbGFnX3Nhbml0aXplICYgU0FOSVRJWkVfS0VSTkVMX0hXQUREUkVTUykKKwl7CisJ
ICBtYXliZV9zZXRfcGFyYW1fdmFsdWUgKFBBUkFNX0hXQVNBTl9TVEFDSywgMCwgb3B0cy0+eF9w
YXJhbV92YWx1ZXMsCisJCQkJIG9wdHNfc2V0LT54X3BhcmFtX3ZhbHVlcyk7CisJICBtYXliZV9z
ZXRfcGFyYW1fdmFsdWUgKFBBUkFNX0hXQVNBTl9SQU5ET01fRlJBTUVfVEFHLCAwLAorCQkJCSBv
cHRzLT54X3BhcmFtX3ZhbHVlcywKKwkJCQkgb3B0c19zZXQtPnhfcGFyYW1fdmFsdWVzKTsKKwl9
CiAgICAgICBicmVhazsKIAogICAgIGNhc2UgT1BUX2ZzYW5pdGl6ZV9yZWNvdmVyXzoKZGlmZiAt
LWdpdCBhL2djYy9wYXJhbXMuZGVmIGIvZ2NjL3BhcmFtcy5kZWYKaW5kZXggNWZlMzM5NzZiMzdi
YjA3NjM5ODYwNDBmNjZhOWMyODY4MTM2MzUzNS4uYTRiM2YwMmI2MDg5OGY1NGFlZWM0MDIzOGFk
NDE3ZTQyM2Y1NmUwMSAxMDA2NDQKLS0tIGEvZ2NjL3BhcmFtcy5kZWYKKysrIGIvZ2NjL3BhcmFt
cy5kZWYKQEAgLTEyOTksNiArMTI5OSwxNyBAQCBERUZQQVJBTSAoUEFSQU1fVVNFX0FGVEVSX1ND
T1BFX0RJUkVDVF9FTUlTU0lPTl9USFJFU0hPTEQsCiAJICJzbWFsbGVyIG9yIGVxdWFsIHRvIHRo
aXMgbnVtYmVyLiIsCiAJIDI1NiwgMCwgSU5UX01BWCkKIAorLyogSFdBc2FuIHN0YW5kcyBmb3Ig
SGFyZHdhcmVBZGRyZXNzU2FuaXRpemVyOiBodHRwczovL2dpdGh1Yi5jb20vZ29vZ2xlL3Nhbml0
aXplcnMuICAqLworREVGUEFSQU0gKFBBUkFNX0hXQVNBTl9SQU5ET01fRlJBTUVfVEFHLAorCSAg
Imh3YXNhbi1yYW5kb20tZnJhbWUtdGFnIiwKKwkgICJVc2UgcmFuZG9tIGJhc2UgdGFnIGZvciBl
YWNoIGZyYW1lLCBhcyBvcHBvc2VkIHRvIGJhc2UgYWx3YXlzIHplcm8uIiwKKwkgIDEsIDAsIDEp
CisKK0RFRlBBUkFNIChQQVJBTV9IV0FTQU5fU1RBQ0ssCisJICAiaHdhc2FuLXN0YWNrIiwKKwkg
ICJFbmFibGUgaHdhc2FuIHN0YWNrIHByb3RlY3Rpb24uIiwKKwkgIDEsIDAsIDEpCisKIERFRlBB
UkFNIChQQVJBTV9VTklOSVRfQ09OVFJPTF9ERVBfQVRURU1QVFMsCiAJICAidW5pbml0LWNvbnRy
b2wtZGVwLWF0dGVtcHRzIiwKIAkgICJNYXhpbXVtIG51bWJlciBvZiBuZXN0ZWQgY2FsbHMgdG8g
c2VhcmNoIGZvciBjb250cm9sIGRlcGVuZGVuY2llcyAiCmRpZmYgLS1naXQgYS9nY2MvcGFyYW1z
LmggYi9nY2MvcGFyYW1zLmgKaW5kZXggMjZmMTIzNmFhNjU0MjJmNjY5MzllZjJhNGMzODk1OGJk
Yzk4NGFlZS4uYWQ0MGJkMGI1ZDNiMjE3ZTZkMGRjNTMxZmNlMDRmYWJhOTdiNWY2MCAxMDA2NDQK
LS0tIGEvZ2NjL3BhcmFtcy5oCisrKyBiL2djYy9wYXJhbXMuaApAQCAtMjUyLDUgKzI1Miw5IEBA
IGV4dGVybiB2b2lkIGluaXRfcGFyYW1fdmFsdWVzIChpbnQgKnBhcmFtcyk7CiAgIFBBUkFNX1ZB
TFVFIChQQVJBTV9BU0FOX0lOU1RSVU1FTlRBVElPTl9XSVRIX0NBTExfVEhSRVNIT0xEKQogI2Rl
ZmluZSBBU0FOX1BBUkFNX1VTRV9BRlRFUl9TQ09QRV9ESVJFQ1RfRU1JU1NJT05fVEhSRVNIT0xE
IFwKICAgKCh1bnNpZ25lZCkgUEFSQU1fVkFMVUUgKFBBUkFNX1VTRV9BRlRFUl9TQ09QRV9ESVJF
Q1RfRU1JU1NJT05fVEhSRVNIT0xEKSkKKyNkZWZpbmUgSFdBU0FOX1NUQUNLIFwKKyAgUEFSQU1f
VkFMVUUgKFBBUkFNX0hXQVNBTl9TVEFDSykKKyNkZWZpbmUgSFdBU0FOX1JBTkRPTV9GUkFNRV9U
QUcgXAorICBQQVJBTV9WQUxVRSAoUEFSQU1fSFdBU0FOX1JBTkRPTV9GUkFNRV9UQUcpCiAKICNl
bmRpZiAvKiAhIEdDQ19QQVJBTVNfSCAqLwpkaWZmIC0tZ2l0IGEvZ2NjL3RhcmdldC5kZWYgYi9n
Y2MvdGFyZ2V0LmRlZgppbmRleCAwMTYwOTEzNjg0OGZjMTU3YTQ3YTkzYTAyNjdjMDM1MjRmZTkz
ODNlLi4wYWRlMzFhY2NhYjI1YmYxMjFmMTM1Y2JmMDJjNmFkZmNkNmUxNDc2IDEwMDY0NAotLS0g
YS9nY2MvdGFyZ2V0LmRlZgorKysgYi9nY2MvdGFyZ2V0LmRlZgpAQCAtNjcwNiw2ICs2NzA2LDE3
IEBAIERFRkhPT0sKIEhPT0tfVkVDVE9SX0VORCAobW9kZV9zd2l0Y2hpbmcpCiAKICN1bmRlZiBI
T09LX1BSRUZJWAorI2RlZmluZSBIT09LX1BSRUZJWCAiVEFSR0VUX01FTVRBR18iCitIT09LX1ZF
Q1RPUiAoVEFSR0VUX01FTVRBR18sIG1lbXRhZykKKworREVGSE9PSworKGNhbl90YWdfYWRkcmVz
c2VzLAorICJUcnVlIGlmIGJhY2tlbmQgYXJjaGl0ZWN0dXJlIG5hdHVyYWxseSBzdXBwb3J0cyBp
Z25vcmluZyB0aGUgdG9wIGJ5dGUgb2ZcCisgcG9pbnRlcnMuICBUaGlzIGZlYXR1cmUgbWVhbnMg
dGhhdCAtZnNhbml0aXplPWh3YWRkcmVzcyBjYW4gd29yay4iLAorIGJvb2wsICgpLCBkZWZhdWx0
X21lbXRhZ19jYW5fdGFnX2FkZHJlc3NlcykKKworSE9PS19WRUNUT1JfRU5EIChtZW10YWcpCisj
dW5kZWYgSE9PS19QUkVGSVgKICNkZWZpbmUgSE9PS19QUkVGSVggIlRBUkdFVF8iCiAKICNkZWZp
bmUgREVGX1RBUkdFVF9JTlNOKE5BTUUsIFBST1RPKSBcCmRpZmYgLS1naXQgYS9nY2MvdGFyZ2hv
b2tzLmggYi9nY2MvdGFyZ2hvb2tzLmgKaW5kZXggNWFiYTY3NjYwZjg1NDA2YjlmZDQ3NWU3NWEz
Y2M2NWIwZDE5NTJmNS4uNDYzYzI3YzdkN2I1NTBiZjYzNjMwZjIxMDI2ODFiMzdmZmQyNjVjYiAx
MDA2NDQKLS0tIGEvZ2NjL3Rhcmdob29rcy5oCisrKyBiL2djYy90YXJnaG9va3MuaApAQCAtMjg0
LDQgKzI4NCw1IEBAIGV4dGVybiBydHggZGVmYXVsdF9zcGVjdWxhdGlvbl9zYWZlX3ZhbHVlICht
YWNoaW5lX21vZGUsIHJ0eCwgcnR4LCBydHgpOwogZXh0ZXJuIHZvaWQgZGVmYXVsdF9yZW1vdmVf
ZXh0cmFfY2FsbF9wcmVzZXJ2ZWRfcmVncyAocnR4X2luc24gKiwKIAkJCQkJCSAgICAgIEhBUkRf
UkVHX1NFVCAqKTsKIAorZXh0ZXJuIGJvb2wgZGVmYXVsdF9tZW10YWdfY2FuX3RhZ19hZGRyZXNz
ZXMgKCk7CiAjZW5kaWYgLyogR0NDX1RBUkdIT09LU19IICovCmRpZmYgLS1naXQgYS9nY2MvdGFy
Z2hvb2tzLmMgYi9nY2MvdGFyZ2hvb2tzLmMKaW5kZXggZWQ3N2FmYjFkYTU3ZTU5YmMwNzI1ZGMw
ZDZmYWM0NzczOTFiYWUwMy4uZDdkZDA3ZGI2NWM4MjQ4YzJmMTcwNDY2ZGIyMTQ0OWE1NjcxM2Q2
OSAxMDA2NDQKLS0tIGEvZ2NjL3Rhcmdob29rcy5jCisrKyBiL2djYy90YXJnaG9va3MuYwpAQCAt
MjM2OCw0ICsyMzY4LDEwIEBAIGRlZmF1bHRfcmVtb3ZlX2V4dHJhX2NhbGxfcHJlc2VydmVkX3Jl
Z3MgKHJ0eF9pbnNuICosIEhBUkRfUkVHX1NFVCAqKQogewogfQogCitib29sCitkZWZhdWx0X21l
bXRhZ19jYW5fdGFnX2FkZHJlc3NlcyAoKQoreworICByZXR1cm4gZmFsc2U7Cit9CisKICNpbmNs
dWRlICJndC10YXJnaG9va3MuaCIKZGlmZiAtLWdpdCBhL2djYy90b3BsZXYuYyBiL2djYy90b3Bs
ZXYuYwppbmRleCBkNzQxYTY2ZjM4NTdhNjBiY2RiNmY1YzFiNjBlNzgxZmYzMTFhYWQ0Li4zOTIw
ZWY1YzQwZjI3YjI3YTQ0OWRjNmJmMWRhNzk1ZjBkNDBlNzdiIDEwMDY0NAotLS0gYS9nY2MvdG9w
bGV2LmMKKysrIGIvZ2NjL3RvcGxldi5jCkBAIC0xNzUyLDYgKzE3NTIsMTYgQEAgcHJvY2Vzc19v
cHRpb25zICh2b2lkKQogICAgICAgZmxhZ19zYW5pdGl6ZSAmPSB+U0FOSVRJWkVfQUREUkVTUzsK
ICAgICB9CiAKKyAgLyogSFdBc2FuIHJlcXVpcmVzIHRvcCBieXRlIGlnbm9yZSBmZWF0dXJlIGlu
IHRoZSBiYWNrZW5kLiAgKi8KKyAgaWYgKGZsYWdfc2FuaXRpemUgJiBTQU5JVElaRV9IV0FERFJF
U1MKKyAgICAgICYmICEgdGFyZ2V0bS5tZW10YWcuY2FuX3RhZ19hZGRyZXNzZXMgKCkpCisgICAg
eworICAgICAgd2FybmluZ19hdCAoVU5LTk9XTl9MT0NBVElPTiwgMCwKKwkJICAiJTwtZnNhbml0
aXplPWh3YWRkcmVzcyU+IGNhbiBub3QgYmUgaW1wbGVtZW50ZWQgb24gIgorCQkgICJhIGJhY2tl
bmQgdGhhdCBkb2VzIG5vdCBpZ25vcmUgdGhlIHRvcCBieXRlIG9mIGEgcG9pbnRlciIpOworICAg
ICAgZmxhZ19zYW5pdGl6ZSAmPSB+U0FOSVRJWkVfSFdBRERSRVNTOworICAgIH0KKwogIC8qIERv
IG5vdCB1c2UgSVBBIG9wdGltaXphdGlvbnMgZm9yIHJlZ2lzdGVyIGFsbG9jYXRpb24gaWYgcHJv
ZmlsZXIgaXMgYWN0aXZlCiAgICAgb3IgcGF0Y2hhYmxlIGZ1bmN0aW9uIGVudHJpZXMgYXJlIGlu
c2VydGVkIGZvciBydW4tdGltZSBpbnN0cnVtZW50YXRpb24KICAgICBvciBwb3J0IGRvZXMgbm90
IGVtaXQgcHJvbG9ndWUgYW5kIGVwaWxvZ3VlIGFzIFJUTC4gICovCgo=

--_002_HE1PR0802MB2251783050BA897E608882ACE07E0HE1PR0802MB2251_--
