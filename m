Return-Path: <kasan-dev+bncBDY7XDHKR4OBB6F752OQMGQEUIAVV4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 2164F661E25
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Jan 2023 06:02:50 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id h7-20020a17090a710700b00225b277a376sf2424475pjk.0
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Jan 2023 21:02:50 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1673240568; cv=pass;
        d=google.com; s=arc-20160816;
        b=EWmqWfXkrgnrW2v2bYEZUhSlP3kxzfqkPeSaE7QeUvjUp1e4+qxC1zLlFpaBU3Hf14
         mD5HEYi2ncfpqt9IAlsfpuj2KPx3ixmZVKteDt/+BXH77WlzyI/H53EuhCuNKjgN/5Hi
         v0ytZ4sboDMWU8yFBcZeCM7YQ0NBB1AOnTywKeuNOarMIZZbg2LSO33/vqGTC7V2iQMj
         qvW3ta448C35X3JA3YoG1cQ3qivX+Svr4vun7Saw5Q+i9r1334/BFRkn4mGioXPlTF3h
         M3wvA/U0rXWVTrxpAnCKGBzme6TvDU2Th9EFIhqF7sPSLmAMpqz/RBbF2IxT3JfKdkbR
         /eGA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:content-id
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=CPBfTAZyJGWfR9x8mjqatZgFkmnuqQKRNBWASY+JqEs=;
        b=qhaXYpCC/HiDShmQs9RyguAFY+XksYgkfarRAaf8fcgeB0mqegnMVJ/abnwCyqFACK
         C+nrv9WsjqPD+CjgJqULyVOV0DGudSVgNQDY4yUrwmgVMEF3P4K0XqMuTUetUAJzZoND
         XVIalcY2OXFuPN3DfPHjcnYt0nQXQb7dUTEY3vqeenQpyzFUSBSf2CjJcBsnETMm5B5i
         4ePh58cGEc0OeV4af7F/W69fU7tS6SDiHhAfmOw5ofNRcprQj0CrbSqOLV7syo3mxVjs
         bUaB7sWhpiMhAZzxmq0UEjcJ0yBYXFXLrJsftsTRzFxrVKQmzCWoN/t6aE44yjnpoyE7
         oodQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=CJOzQHq3;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b="K/nnx14k";
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-id:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from:from
         :to:cc:subject:date:message-id:reply-to;
        bh=CPBfTAZyJGWfR9x8mjqatZgFkmnuqQKRNBWASY+JqEs=;
        b=DQEk3sR0J6sdBA/iZbM3RmaUA7pASv8kG3FjKJ/YN72n3XvCQomDeI1qthLzyPfCOU
         TfBm+4JiuQAu7/k0SR1leYiF7CoEX/LAf9cz7APDKZCqvo4oL7d6X1eM4V4fDJ+AQD/S
         x8FoCz29UGDStFvy+55LrMqKcC2xt+yAmuoKJFwSrNg4kMR+aSe0LV6l9Gf9UV5Xyjjh
         SuJVnyZqM5ttkHWFH98V8ZVf+/a0WPOnmXMBF2tqdUhT2b/1rNUm8yR/NgildqQ3HNqc
         awgII+M1Q7sv8ZmiQHGV4wr/ucJiI+L/E/hoTuwWxRyw90QDYB1aXX4c/CAncu/aO0Bf
         ojEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-id:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=CPBfTAZyJGWfR9x8mjqatZgFkmnuqQKRNBWASY+JqEs=;
        b=shrjXxiWSktjeFzhPt9q56rc7Ge4wNrTn4mcR5eTMJqx6v6m60xNjxQrDRMCG3ChDQ
         ByC0+6BqJsj/aVszf6lhhk8A7lLwjMFL4PntAXp0egRK/2dSpIYveKMRjXqHk/oUTIaq
         9TrABYVca8J8qoAIxbD1mLn9yZw4Fr7V0TggU1BGXLCxEwZy8geEVHKf2m+AAcaLtoAG
         0liNkCUbrzLF/6zEkMonnJTf9oyDGlu3AIEms4FFSwavxcAfIAKaXffT8FMtmueOtNS6
         AW4+Uhvz1siL7nixlqWzu25o0SYcmH5sWCew9IFmqKfGwTCuCSHeNlnGoKThmuVnwpH+
         DYcQ==
X-Gm-Message-State: AFqh2krsSK79rz3R5vB+6ulofxoNPnZGXE6Z+nQrkT1JDO0wQ09vpTA7
	Er85K0lvWFwdqt3yvkuu904=
X-Google-Smtp-Source: AMrXdXupSUHK42cflCYVoIPQ5a3QMYqXoXEbxJtMLKn7xR0FHajz6mtMgNaclxMrT409GolBpTglIg==
X-Received: by 2002:aa7:973d:0:b0:582:197f:580f with SMTP id k29-20020aa7973d000000b00582197f580fmr2809947pfg.2.1673240568272;
        Sun, 08 Jan 2023 21:02:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ee53:b0:188:b504:8ce4 with SMTP id
 19-20020a170902ee5300b00188b5048ce4ls4550728plo.7.-pod-prod-gmail; Sun, 08
 Jan 2023 21:02:47 -0800 (PST)
X-Received: by 2002:a05:6a20:a687:b0:af:7cf6:1d4b with SMTP id ba7-20020a056a20a68700b000af7cf61d4bmr81168500pzb.23.1673240567473;
        Sun, 08 Jan 2023 21:02:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673240567; cv=pass;
        d=google.com; s=arc-20160816;
        b=OxTiDpDuQxIMVcKBj4HL6rgNBrGQJk4cyMl67rDp2Sqhz3Fk2wGaylHai9KC0G44I8
         PYqBpQEpSrGNvsKp/RKkUTz1wtz5JfszPvZqj4CA3/P4WxZL3aYWxdsHBjPGmBFA3zYV
         XByF7EmMccefT6EtNQhxajrJO+wRic11eD/LyLT9NB/H+qWLP+sfrDqdJDE5FPQIHKOa
         xAQ7u4XTqWSDf74OB0AG3ooeUtCAnDO0yWgsiWr4aU7qAPW9/RodyFO9ETElB79u/hoy
         0l8IAcL5gFFPcK67NLENRkXx5c/zss/1YTFeLtM2bdn74nXHEdbYx9VirgEuzwCmzUnf
         /swg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=kFi4/MFIgI/0LmaYm1LqCv7qDrMYCq2P+g4CFiHgHAQ=;
        b=TxvBDyMovZRagbH/7xlhg4DebIhgqK3z7x08CkPVw4xCyhlsAx1kmcU3OuO79y7sfL
         Zh4ol2He/W1z+ZmYLXcX/2HYFgKQJR08O3+AgYDpJH1C44aepAriCQFUQVxz2ZI4Q2ln
         KHWgrfzUKGPtn+w5ySadiVztnIgADB7NQan3DbhjARvFl/99Vdcet209xYGOfOIrsKKd
         QD6ujP4YAjW6W6C4fZ7+9tOP2RskJe6klI3Yqj0olxyCL13EBkCA9XJL7v6/Tsg7EkGC
         gwEL2qvo9ND5yxllnqkUW8I3ln2SqeQ8mM6HId5ozG4EbbHlC0GSs/lTD5HpSFu8GK7/
         4sqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=CJOzQHq3;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b="K/nnx14k";
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id q19-20020a656a93000000b004a3ed20c3c0si450804pgu.3.2023.01.08.21.02.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 08 Jan 2023 21:02:47 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 59a81ed02ff743478f3fb8c28e5ff2eb-20230109
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.17,REQID:f335b2f0-c516-4e4c-8d86-5a19c698c9ae,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:-5,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:-5
X-CID-INFO: VERSION:1.1.17,REQID:f335b2f0-c516-4e4c-8d86-5a19c698c9ae,IP:0,URL
	:0,TC:0,Content:0,EDM:0,RT:0,SF:-5,FILE:0,BULK:0,RULE:Release_Ham,ACTION:r
	elease,TS:-5
X-CID-META: VersionHash:543e81c,CLOUDID:e9daaa8b-8530-4eff-9f77-222cf6e2895b,B
	ulkID:2301091302433IZZU6AN,BulkQuantity:0,Recheck:0,SF:17|19|102,TC:nil,Co
	ntent:0,EDM:-3,IP:nil,URL:0,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,O
	SA:0
X-CID-BVR: 0,NGT
X-UUID: 59a81ed02ff743478f3fb8c28e5ff2eb-20230109
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1266390611; Mon, 09 Jan 2023 13:02:42 +0800
Received: from mtkmbs10n2.mediatek.inc (172.21.101.183) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.792.3;
 Mon, 9 Jan 2023 13:02:40 +0800
Received: from APC01-SG2-obe.outbound.protection.outlook.com (172.21.101.239)
 by mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server id
 15.2.792.3 via Frontend Transport; Mon, 9 Jan 2023 13:02:40 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=aMlsujdZOrUTvN90e5V8ScWAFzwMicDQREX11vcbbdHn7Bs6dpgPL/7RWGmIbAPwT3UerV3LwyiH+MBSxKFqwE+jfWZ4Um2G11vYVxLr69SE6lYZ69Xd5wpFV/zXRNmW/4O9W1u//dyG4Ll3UKNPY+ShxLCkjrnbGL9pndMj8D9YBOMgYy0hFrbpK7y/Z7xFVivJFvYcLbqEsUPUBGhEuWOqI/Es2rQDCyuzjPo4yejLQfBKg/u/NpE5hQEjmUSCHGgozxYIPWIQdGDFgNGHUakzI3oS4vaoOkEW+Zh10JGdBdnsA0P8HH3fYPAlUygr/nGKB90RSrMvYvsZi7rTwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=kFi4/MFIgI/0LmaYm1LqCv7qDrMYCq2P+g4CFiHgHAQ=;
 b=odF2HJZeYIT2CPx5btxRMOKZEUhu0E+j6aK2FHEpuIU9CAxJ9oqVF9ekSDiKmiA+jTJuSz348piEbEhZZjAamIid8thIKAfVRjZter4yEZPldkc22ntbkIWZ4WxYlfFBZ+pMbC0G2ILLnubgxhlVfggBP4liI0/E1EIpcYeZ92k/qzQAg65Uag0oyakWLHH80PiUQYjyK2PEE+Xgxg970fS6+POSrHvuQZ+gU6F7gMvPNU4glYPH1Y6Z9ZnJUNpPsZ0oGQe88I98FLxnuUuI2FK4MtcXLwlu8Qur0KKGs6cfSqENonyv/ULEw6xUcfMPAV5sO6GWD7qPonkmbwLvsg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com (2603:1096:301:b4::11)
 by KL1PR0302MB5411.apcprd03.prod.outlook.com (2603:1096:820:4f::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5986.18; Mon, 9 Jan
 2023 05:02:38 +0000
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::c43a:ce45:4a27:bd80]) by PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::c43a:ce45:4a27:bd80%9]) with mapi id 15.20.5986.018; Mon, 9 Jan 2023
 05:02:38 +0000
From: =?UTF-8?B?J0t1YW4tWWluZyBMZWUgKOadjuWGoOepjiknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
To: "andreyknvl@gmail.com" <andreyknvl@gmail.com>
CC: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>,
	=?utf-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	=?utf-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
	<chinwen.chang@mediatek.com>, "dvyukov@google.com" <dvyukov@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	"ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "vincenzo.frascino@arm.com"
	<vincenzo.frascino@arm.com>, "glider@google.com" <glider@google.com>,
	"matthias.bgg@gmail.com" <matthias.bgg@gmail.com>
Subject: Re: [PATCH] kasan: infer the requested size by scanning shadow memory
Thread-Topic: [PATCH] kasan: infer the requested size by scanning shadow
 memory
Thread-Index: AQHZH0jgINbB3ihm8EOrOsTiVH1z6q6NgimAgAgOdIA=
Date: Mon, 9 Jan 2023 05:02:38 +0000
Message-ID: <dbaeb044c547ddb908bffdce4d2dfa0936805ef7.camel@mediatek.com>
References: <20230103075603.12294-1-Kuan-Ying.Lee@mediatek.com>
	 <CA+fCnZdk0HoWx6XCbTsiNhyR2Z_7zv5JUdgNs8Q_tV4GRkkmCg@mail.gmail.com>
In-Reply-To: <CA+fCnZdk0HoWx6XCbTsiNhyR2Z_7zv5JUdgNs8Q_tV4GRkkmCg@mail.gmail.com>
Accept-Language: zh-TW, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-mailer: Evolution 3.28.5-0ubuntu0.18.04.2
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PUZPR03MB5964:EE_|KL1PR0302MB5411:EE_
x-ms-office365-filtering-correlation-id: 48b3be3f-62eb-4c79-824b-08daf1febac8
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: Nm3AFYYtf5/KWln8Hj8jyZgVhLaTUM0/eQI/rS+ZW69qbMZBkVvPJ4XC7FA9egQ18kXoZZzylYmjHWxm4StyRupFt0cSLgAhcCT5Wmzfss1MsgcZ+wRAPZMDNX58zoZVZn4Uy659SLl//iLmqeCqN8BjsZIUsH1MR7tTgz5PAULZwwQAAfaILtV28YVH1ucvwI4jEUyQf5bTQtPoOmWR+mIiZZzZK9hiIUJFmCl1+60R4B7p3JAw82prTOy7LXUYqcocx7HFNVlVLmCbQKPDrTmXLDpBgcbydfI/BgmqGIbdQqBZDU0ObwOwVgH1+k18nAAD6U3wq+CahlBoV+NJm+yK9KJUcqLdvWja5IVRWdQXK99pgBCQrNFh9BSOhCmWiUPmG7OJ4JEDPKjv45im9ivDQt0CPyz8qZ0ENIwVPjJwdSmNc6Jjik7MPDeGDUf+0e1CVnITjTxbEvbSPxR3uTE0n9b2Db9O4zb/oyAFoJnguKhEm6rP7P9Iy1atq7V4DYxz7t/K5yct5phcWkUc2bljHE7+S0hXI8OZP4/6HsLdKZMi9jKqbowYJ48vf1hA0q2yFIZbYJn323Lv+4bQBbNWUAl5UdJVNHfKMp/1nY7slW6ryGiub+HnaNaHr5aWicrVE3XEHKHNM+9qrVd70UgGelJJv5p9X5LG2u5T+Aeioqnc4xFmr8jfmp2MyTzHjd+YGApKfK1iRUhahxkQPk0H5JAIWYESyL8E815PHeds6W181xJMofTu7tPrgXWB
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PUZPR03MB5964.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(4636009)(346002)(136003)(366004)(376002)(396003)(39860400002)(451199015)(2906002)(8936002)(7416002)(85182001)(5660300002)(36756003)(41300700001)(64756008)(91956017)(8676002)(66446008)(66946007)(66476007)(76116006)(66556008)(316002)(71200400001)(54906003)(4326008)(6486002)(478600001)(26005)(53546011)(6506007)(186003)(6512007)(2616005)(6916009)(86362001)(83380400001)(38070700005)(122000001)(38100700002)(99106002)(505234007);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?ME55cWFCTk5zQW9JS1dqdnQ2SFBGQnpocE1sUVEwQUt4VHMzNUlPWHlOMENM?=
 =?utf-8?B?a25IRjFDNWZCOWRhSWFMOWhGdi9HUFJJRmRmMjdQTExtTXZYd3hNQjVmZytN?=
 =?utf-8?B?aFlvN0ZZTExuZWxVQlBLemdmMHJrWU9SY2s2NS8wc0o0bGFnSXNwdWRKYW1F?=
 =?utf-8?B?S29pdXdvWmNnS0dXOUV2SGhqeUZVMHVNZXh0eXBFUXA0ZFlOZjRuTVY1Tnc2?=
 =?utf-8?B?NC9lbmwvVm1hbzdPRkUyY1FIdHQ0SEtuMVpnWHNIbEJHclBhSVpLUDZTM3NB?=
 =?utf-8?B?R0tXc0VNR2wrak5XcU5Td28zangzRHJyU2cwRS9pd2pIVWtSVVVwb01yazBF?=
 =?utf-8?B?d2RJcjFZekZHT3FCR05vejR6NWRmekdZNjJGNFVieXJrYlBPTTdjVzFjditU?=
 =?utf-8?B?Y05HMXhmb0xReTMrQ0c3VTVaU20wSDRmbm1WQStNQ2hUNG93WnJ5b1lvenFy?=
 =?utf-8?B?UUp4MzBxWS9vMnZzcWpTYlZCdG45ZHkwK1pUZGhBQnhiaUUyZzlQejE5eVh4?=
 =?utf-8?B?RHVLM0lZTzRRSDFucEFFUlg5OVVFZWE1M3JFVWdFVmErNXp5Nm1xejYwMDE1?=
 =?utf-8?B?d0grT2pTZ0FWQkNJTm5jY2w0azJsZ2Z4VTVXdkxDL2JmZlFhVzN5UHRLbGRE?=
 =?utf-8?B?NXpYTHFIa1luVkk5UnZaZlNMbGV4K1lSK1lWbmxRTXcxcHZBU3dtckVFSU44?=
 =?utf-8?B?RGFsNFA1V21zR2hLc1dUNTd0Q0N1Q3FLcnpHc2paRnZtTzBOazlRMUorOVNp?=
 =?utf-8?B?cjFySHZLNk9yaG9XNGVEcFdXRGFrK0lJWkppMVdYOGtUZjdrUXVkWCtzSlZF?=
 =?utf-8?B?OUwxbG8rcjUxUXdkVHRyOTVYWE0xUE0zSEhaSDkvMmpYUEQzRUpjVmR3ZExt?=
 =?utf-8?B?RlB5YlNON2RiZG16aWtNeGtVaCs4ZG9YZ0tEYURydjlYSkJEeWhIUkdCMExt?=
 =?utf-8?B?MEc0amN3Q3pTWDkxOU9IMThVVnpLdkRuTFFObytQeUE5T1VXNHQ3V1FYczRV?=
 =?utf-8?B?bnFEeTNDL0JGRzNGc0xEM0xpcUxqWFM2eENpNnBuN0tmL2k3eU5QL3JoNTJw?=
 =?utf-8?B?NVFGZFE5Vi8vR2ZJcmw1d0xycVVGV0FkbUdMQmo3OUlER2F5dXN2SkJZTDRx?=
 =?utf-8?B?YndsZmpXRE1xNjJrK0RSZXdUaHQ2dHlPcnRYNlc3Q2dCMklLOW1JTnlpbEZU?=
 =?utf-8?B?Z1NGM2EzdUx6SmtrbklpWDZjblJPUHlLT2trOHpsWFZ0aGszOVFNTE5hRTFV?=
 =?utf-8?B?eDVUSnBPYjFyNlJGUUxHSGczeUd3V0NhY096Z0MrTzkxVFBEMFhXQzNmUUZY?=
 =?utf-8?B?dDkxcUxndTR4QkVaUC9PWHJvZGo0czFkb3hHTTg0TW5sS2x3MFE0VE5FQmdT?=
 =?utf-8?B?UEdoWU5wcHpMKzFaQS9sVVZkdUFxdDR2bUxpNUtJaStmL09WK2oyNUJUMFo1?=
 =?utf-8?B?Ykg2Rm82dWV1UUlvcG5WaHk3Y3JpTmhhTC82NVd4YS83dXdZcWxuVW0wa3Jw?=
 =?utf-8?B?eTVNTGpuN3phc09Hc3IrYkFqV3p6bFF0REtyeFN4M0hlZE4xdmR0QXpWNWxR?=
 =?utf-8?B?M2d5a295NkRFTFBoTTJLd21kTzZ6MFRSRG54NmRqKzhoVG9Ydm1BTm5FaTE2?=
 =?utf-8?B?NmdFWDdLZ1ZEaGUrczd5MTVpdVV5bEk3RG11TXBRYm5CclJrL2Jhc1ZhMDhE?=
 =?utf-8?B?WUNCMlJKSmt0OTVkVlQvNERCK0tBQVMrYk1lOTNXNXVaTnFMMWcwTFJNZGlR?=
 =?utf-8?B?ZXU3RWVHZnlUQXRyUTJQdFJaZk00Y09ZSEhXemxwakxBalNsN0N2MVBPdEdi?=
 =?utf-8?B?TlpvemxETFA4YWo2S1pVQm1YeXNMdUEvcFhDaFZoNGFMd1hDZTlaYVlRQ0NM?=
 =?utf-8?B?bGhsbkMwWGFYT3lZSnBoY0xNdi90elBnb2VTQURlMGpST3VKNkdDTzUraW9Y?=
 =?utf-8?B?UWVudzhqZUZ2ZytzT00xRFZvS0doVUZIL1JHZE5UV1NWaHBKZFloeGZlOXJ6?=
 =?utf-8?B?QWFjbm9QVVptN1YzbFRJbG5IbjdrdFUvVUhzbUpjcTNyaHQ5WDhUSjE5UVdG?=
 =?utf-8?B?UnZtb0huWlk3OFpML3REcm5YZndWVXJsc21GV3FBbzAzN2djTzdaQmlDVFRy?=
 =?utf-8?B?d1Nzb2VDNldzRlZlMVR4cHprRmNNS2g0UjFMRGcreVVOZFludVVoeVIvZWxG?=
 =?utf-8?B?NFE9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <F4E8FD454221D24EAD5D3D500652D74D@apcprd03.prod.outlook.com>
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PUZPR03MB5964.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 48b3be3f-62eb-4c79-824b-08daf1febac8
X-MS-Exchange-CrossTenant-originalarrivaltime: 09 Jan 2023 05:02:38.3411
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: SaoeGTbDqefBp55mGeogXMq4Kgp+AdFA5J73SXJsEhDQHX5ORVEfLKurzPX4+TCtjZbAWIaLOofXfZG8q14aldn1jeuM74t35zBilsfPbR4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: KL1PR0302MB5411
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=CJOzQHq3;       dkim=pass
 header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com
 header.b="K/nnx14k";       arc=pass (i=1 spf=pass spfdomain=mediatek.com
 dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates
 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: =?utf-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
	<Kuan-Ying.Lee@mediatek.com>
Reply-To: =?utf-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
	<Kuan-Ying.Lee@mediatek.com>
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

On Wed, 2023-01-04 at 03:00 +0100, Andrey Konovalov wrote:
> On Tue, Jan 3, 2023 at 8:56 AM Kuan-Ying Lee <
> Kuan-Ying.Lee@mediatek.com> wrote:
> > 
> > We scan the shadow memory to infer the requested size instead of
> > printing cache->object_size directly.
> > 
> > This patch will fix the confusing generic kasan report like below.
> > [1]
> > Report shows "cache kmalloc-192 of size 192", but user
> > actually kmalloc(184).
> > 
> > ==================================================================
> > BUG: KASAN: slab-out-of-bounds in _find_next_bit+0x143/0x160
> > lib/find_bit.c:109
> > Read of size 8 at addr ffff8880175766b8 by task kworker/1:1/26
> > ...
> > The buggy address belongs to the object at ffff888017576600
> >  which belongs to the cache kmalloc-192 of size 192
> > The buggy address is located 184 bytes inside of
> >  192-byte region [ffff888017576600, ffff8880175766c0)
> > ...
> > Memory state around the buggy address:
> >  ffff888017576580: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
> >  ffff888017576600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> > > ffff888017576680: 00 00 00 00 00 00 00 fc fc fc fc fc fc fc fc fc
> > 
> >                                         ^
> >  ffff888017576700: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> >  ffff888017576780: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> > ==================================================================
> > 
> > After this patch, report will show "cache kmalloc-192 of size 184".
> 
> I think this introduces more confusion. kmalloc-192 cache doesn't
> have
> the size of 184.
> 
> Let's leave the first two lines as is, and instead change the second
> two lines to:
> 
> The buggy address is located 0 bytes to the right of
>  requested 184-byte region [ffff888017576600, ffff8880175766c0)

Did you mean region [ffff888017576600, ffff8880175766b8)?

> 
> This specifically points out an out-of-bounds access.
> 
> Note the added "requested". Alternatively, we could say "allocated".
> 
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -340,8 +340,13 @@ static inline void
> > kasan_print_address_stack_frame(const void *addr) { }
> > 
> >  #ifdef CONFIG_KASAN_GENERIC
> >  void kasan_print_aux_stacks(struct kmem_cache *cache, const void
> > *object);
> > +int kasan_get_alloc_size(void *object_addr, struct kmem_cache
> > *cache);
> >  #else
> >  static inline void kasan_print_aux_stacks(struct kmem_cache
> > *cache, const void *object) { }
> > +static inline int kasan_get_alloc_size(void *object_addr, struct
> > kmem_cache *cache)
> > +{
> > +       return cache->object_size;
> 
> Please implement similar shadow/tag walking for the tag-based modes.
> Even though we can only deduce the requested size with the
> granularity
> of 16 bytes, it still makes sense.

Will do in v2.

> 
> It makes sense to also use the word "allocated" instead of
> "requested"
> for these modes, as the size is not deduced precisely.
> 
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -236,12 +236,13 @@ static void describe_object_addr(const void
> > *addr, struct kmem_cache *cache,
> >  {
> >         unsigned long access_addr = (unsigned long)addr;
> >         unsigned long object_addr = (unsigned long)object;
> > +       int real_size = kasan_get_alloc_size((void *)object_addr,
> > cache);
> 
> Please add another field to the mode-specific section of the
> kasan_report_info structure, fill it in complete_report_info, and use
> it here. See kasan_find_first_bad_addr as a reference.

Got it. Will do in v2.

> 
> Thanks for working on this!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dbaeb044c547ddb908bffdce4d2dfa0936805ef7.camel%40mediatek.com.
