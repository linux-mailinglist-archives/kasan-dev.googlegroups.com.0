Return-Path: <kasan-dev+bncBDY7XDHKR4OBBBMF6KPAMGQERIVALVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D373688E1B
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Feb 2023 04:41:59 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id g1-20020a92cda1000000b0030c45d93884sf2580311ild.16
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 19:41:59 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1675395718; cv=pass;
        d=google.com; s=arc-20160816;
        b=yITmkSRTLgPM2Yls7p1ZXJUI0zoGf2mOxHYw/M05g/OGErgQydJn3pVk74Q8j3owrB
         GPIrP7BEgJvCiudjM0QsUnGv47yiBvWl7FqfNFGovctpG/qd9/5kRhGme5pgbzSEyMBj
         5+BTXWoUrqhCfqwbdI8aOxzXAKo5tTWvlfj5rY8vCfnHTzDu0pURDBSMf40s0GiBNV8Z
         H9Bs12+c1FhR9Y4HdcWJTqGVLgQhj23TEv/3VF7bvPUJdp+cklgR8Dz2B94pUyFs2OHT
         xh/aWa08V2Q2U+IG9IXwbATH1V7h8zvlmovfrlODTQQlEPlKamyGzvI8PwGUlIc1KeUJ
         q87A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=1lTzS0E2r52x44kwcbW2ia/bZTfDofP6Zc4Ge+wRvUY=;
        b=uNmU7ZitOyb9qheVE1yO2qfD9tdGipf5nJm2WnJJ9HC3DshVxtsfXpgiPXnhBbyfKf
         1Pr2V58+aE+gsLQUl+Fiv0FOhmHX2Z2jyQU+Knthen9mqFR6+WIBfk5CupyMNJZfpiid
         4Q81YE+IccKipDN5Wo9vJznFt6rOBH0xy4tuRMwSBbxeJtrNhhGn5mPhEfKjv+kqbyjP
         GA8hHaJFMAftJzAzAxvepnaQlBZvzCohpIV7DPOig0QkKWKptE1naKVaSWGPEnKfceyZ
         044ss+A5JJoANaY/mNfvDayefqsvQ3Ffi+hnItb+Xf9Oi06/nq9Ohi9BWNujVYsZkIme
         knkw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=nFS2vn0d;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b=l9Muaewa;
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1lTzS0E2r52x44kwcbW2ia/bZTfDofP6Zc4Ge+wRvUY=;
        b=EiE3rw3UT4tNIwYLBG54xPK+IYcQa7I0M89tvOQ7LuIX7QnGMdPBnR7HUsE7XBGwlq
         AHAW/b+BwadxSaWLkZ/FvFTPD/iwrHIJV8Ng3szaH7SpyDkaTOrtrApANczmcrdm03bp
         sm82ITOicuR+ejfo92bWkd8TdQKNXnn81O6K9ZOZSNzQ5+SwJJncS5FDY9gyTASt5Np4
         OYHWdH4mFqnsl7068cSgPC1t3ujMrJaNS2SdByM4qaObcFHO3nNFl1UU8+liGA+Pd+t7
         7T8AlpuWGlU664TSRQiWXQfpq8//k4FqlKQJB90OUzHUGZjjB4ArIEY5jvpl1BHF2urZ
         DT8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1lTzS0E2r52x44kwcbW2ia/bZTfDofP6Zc4Ge+wRvUY=;
        b=u2IkszQNgQ5MvFmD6fAIr3rsR00P+z9r/NYAfZNe/AoBvBQQnKcwnUK8wDQ07dwiQf
         OY1QQ6bryMacqkO9qW/pzV69o1hrnBBnRHhEER702D/zuLSyUem7Ijm+jVv+fQxapdKP
         yNnvqE13edr9Tnr9UDLyrz5JvRvqt7FAK9XqqwPx4t81PocVS6g+eNYkyT/L6MNKZrJy
         89SB6/qY+8RxI5USm/qybf//Sq/QqEsPzAg0JilHcyxDfiF+36s1dRRhCpxHAeaEsSCm
         B1tz0HF3ucFhEY/XzAo1K3zRKP4MHnPzqiUG0993eqZdHh+bDOs1BywYb8FTENhNRH8V
         n1ag==
X-Gm-Message-State: AO0yUKVKAJSlZ9yTsaHcHXrMbmANXn5FfqnvZyLZJwxMwS3J9gVKLCwr
	3f0TknMpLA3iV/E3Og1MfRY=
X-Google-Smtp-Source: AK7set8fW/VIJi0zAN2ChTpTKoZo8L38uYp2n3v2XYs4m8Qt2rnS0RM0Hh2DrjdS3Y6dw+U9IY+lXQ==
X-Received: by 2002:a92:7005:0:b0:310:a063:fa82 with SMTP id l5-20020a927005000000b00310a063fa82mr1834915ilc.81.1675395717716;
        Thu, 02 Feb 2023 19:41:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1145:b0:30f:4f58:8670 with SMTP id
 o5-20020a056e02114500b0030f4f588670ls1288004ill.10.-pod-prod-gmail; Thu, 02
 Feb 2023 19:41:57 -0800 (PST)
X-Received: by 2002:a05:6e02:1c45:b0:310:aff3:4cf5 with SMTP id d5-20020a056e021c4500b00310aff34cf5mr7942548ilg.7.1675395717179;
        Thu, 02 Feb 2023 19:41:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675395717; cv=pass;
        d=google.com; s=arc-20160816;
        b=rNJn9yYy1p8hv3GSPMBA5VuuHO0UdlMLz0U2LcbzMkJ8YSs/VYYwlDRyx6r2MXnjFH
         A58pK8apSvv0uCr6/EAt6ec6cLCDmMIdmOXDjMTOxsgVBGyvs8ZibPuuOeZb4u0at3+j
         LObeOfYVUQNxIC+74f8JnGdJDHTjPTSZ4JwC63pqFPaPfPrF32lgQWh8tJFNwsLvhzg+
         qJOEptbQIiVccGNxem4lfLpnIkrnDmPgqcJF6yeSAj0zNd2Jn0QnTOAfxjTOYm3LRzxY
         ThJi1sqpvG3i3xnIeo5COLTMg+DGm6fHu0WYsEP3F4dUVZx/8cIP/Pdbokfjbk2ka2oF
         GI7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=IgxKKp2xi0WhbzPu2Hs4N7mDId9KxTjCg/ML+lb2h+U=;
        b=B+oIhAOZxtNHnRq5XM859IMqpXliSPx507syTzUdqIxduIAx7J6mT8mRCHuEhffWKj
         pm5mzGJ0iMSbhwapI5oDR6fAxlT1P8wDLlt+X1qlQt91aA35oJNXzUfnW5N0z5roJEzx
         r/jWwQVivxF7ETIkMf9KZoXBFttr2U8BShs6SQzTJMgiJxoICQf5LIWgqrYvWzLrnW6t
         lrqZPdwe4fRmm7iZtCGj/Lpp0ticub3LXhkk4yoHAoY6oRuljD7Ov2R82qqQyFdwv09t
         +U931zoxgxUFhQ8YW5o3b1IzJ4B+qVuHVZg1mmbsxy1A1pzSkkr3PtCjMS96P4Fht/fQ
         MlMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=nFS2vn0d;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b=l9Muaewa;
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id l6-20020a056e020dc600b0030d87b97b25si99450ilj.4.2023.02.02.19.41.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Feb 2023 19:41:56 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: b17f8cc2a37411eda06fc9ecc4dadd91-20230203
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.18,REQID:dd9f8391-508f-431b-897f-8126e84103cb,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:3ca2d6b,CLOUDID:4cf22956-dd49-462e-a4be-2143a3ddc739,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0
X-CID-BVR: 0,NGT
X-UUID: b17f8cc2a37411eda06fc9ecc4dadd91-20230203
Received: from mtkmbs13n2.mediatek.inc [(172.21.101.108)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1707689750; Fri, 03 Feb 2023 11:41:50 +0800
Received: from mtkmbs10n2.mediatek.inc (172.21.101.183) by
 mtkmbs11n2.mediatek.inc (172.21.101.187) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.792.15; Fri, 3 Feb 2023 11:41:49 +0800
Received: from APC01-PSA-obe.outbound.protection.outlook.com (172.21.101.239)
 by mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server id
 15.2.792.3 via Frontend Transport; Fri, 3 Feb 2023 11:41:49 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=LJ4/Z7kZ6ynvK6lABBZ5SrKcq+Of9yzKY6+p4HzYhgXAlTbwDQElBPIAEmuvBcVZlAyxM555KrLtfmeNckxUpj8O9FiJR3niuh2fBjD5DMWO4OrqsGnB0j9LDRILc/G6xo4kRqPiDuhLgeKqmhTVQI/E6l8TRtG0/HpgNdnTi/d1XrtNuMlBsZD3t3dHzzs49mzTPFU6uK2BIRKqnfLjCx+wUPV6CwsVJweCGn4tZxanT5EXpU/8J3CFFz5jiN86mR6rOqXq7SD4GTA7h153FfolHkStHSZiVsLzNoqQUmq0vr0uQoh0rp9v/9nO/jY11w/yWueLhETntnkqnoT+Qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=IgxKKp2xi0WhbzPu2Hs4N7mDId9KxTjCg/ML+lb2h+U=;
 b=Y9409/1wHHm3q1PnMZoUEiij9tQS+kVzGK+znxGl+C9kjdoAFhUoXXld+9EjycX0I8Rta/7zZQGJmfTZ9GOEgCXIY7m2BGcyXOvuNVNzR2faBaHqpKbaBOc/ckLOHgHItsKC6ct4zDnDouQgS/D9/JbQ+jegB/USlOuzjDN+oB0AjQ3YenmE3BwWMb6zehNy9TKkqxEoVo+ZM2mVUr4TbXrBfet6uvi38YdYZ5GxD9aOOP8IuBwfW6zk/Yz2pc0tqv9749ztGJc3kDwNw/7z7ArSQqHJY78I+8fq5joJerGVigvx6BSLtoOPw2/dNcmNLg5rJR4fB9H6MNLRgCpirg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com (2603:1096:301:b4::11)
 by PSAPR03MB5253.apcprd03.prod.outlook.com (2603:1096:301:17::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6064.28; Fri, 3 Feb
 2023 03:41:45 +0000
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::c43a:ce45:4a27:bd80]) by PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::c43a:ce45:4a27:bd80%7]) with mapi id 15.20.6064.028; Fri, 3 Feb 2023
 03:41:45 +0000
From: =?UTF-8?B?J0t1YW4tWWluZyBMZWUgKOadjuWGoOepjiknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
To: "andreyknvl@gmail.com" <andreyknvl@gmail.com>
CC: =?utf-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	=?utf-8?B?R3Vhbmd5ZSBZYW5nICjmnajlhYnkuJop?= <guangye.yang@mediatek.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "catalin.marinas@arm.com"
	<catalin.marinas@arm.com>, "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "pcc@google.com" <pcc@google.com>,
	"vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>, "will@kernel.org"
	<will@kernel.org>
Subject: Re: [PATCH v2 0/4] kasan: Fix ordering between MTE tag colouring and
 page->flags
Thread-Topic: [PATCH v2 0/4] kasan: Fix ordering between MTE tag colouring and
 page->flags
Thread-Index: AQHYfN3UQ2ZS5zhImUiCo/W/1QNefK68k6aAgAB+/YCAAPZ+gA==
Date: Fri, 3 Feb 2023 03:41:45 +0000
Message-ID: <eeceea66a86037c4ca2b8e0d663d5451becd60ea.camel@mediatek.com>
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
	 <66cc7277b0e9778ba33e8b22a4a51c19a50fe6f0.camel@mediatek.com>
	 <CA+fCnZfu7SdVWr9O=NxOptuBg0eHqE526ijA4PAQgiAEYfux6A@mail.gmail.com>
In-Reply-To: <CA+fCnZfu7SdVWr9O=NxOptuBg0eHqE526ijA4PAQgiAEYfux6A@mail.gmail.com>
Accept-Language: zh-TW, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-mailer: Evolution 3.28.5-0ubuntu0.18.04.2
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PUZPR03MB5964:EE_|PSAPR03MB5253:EE_
x-ms-office365-filtering-correlation-id: e824cfc3-e89d-4ab1-30bd-08db05989277
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: B9DaR/TQaaDCqJM8zo4CX2M+jP5dCkz/rB2/fqmy50ZOQVFGdVVTVIO6uoe/hwCrVtRsMiDpH3oZYmdu+dEAHXL8wnvn03NKjGeTwmUASKphQKNa9hw2Wpd8x6CpeE/MXW0rzguqg9pjaSf89wozq8ByaMP9Fo4DzCWRSoJ9E5SxIC/ZJv483dxIUTBKv4c42hzNSTvf1iUBVucwIhu6CxVAR0HPHNKvXSTjgcVBwOnajoa7VfuZH7coDZ47aRI2hfS02s7B8+C1yW4gD1HOn7ayqPZbDKq3rAs+el9OqxOrlW4Llxv0AS0ELQkZFkRRcC78Ej3vot1/YNjKMuF7YEvdbCiuQB5v2BB8M0NkYqpqWL3m88Y3UnrCVBNOSYHOE2lbPr3+PJxpvw2g6GBXL+w3VctscoSA4xDv7n7Pp+EbqkeG338YzD2Pcs8cpSpY7xS/8V3jCqbP9yWdpo2HiLjzAqwCvDLZ0T8hWJixO4hZwOgHq+Fb6qD4aHRK+OwYAiv6aO9fBWsAN/SXzm+CSOByu2Hf4xJiK+sr8wMx64CA9+yZ0GRLJsYhIpcEW83d4ljtBk/v6cwhCqRuc3Vpej0ENHTsstjNOpcOaTZMNgWxPpCdPKn9PabBalkg8/jZF3+9fEOPk7tVxBa9dEFNd9FQa2G2w5cPpNf/8gBVJGsX5fjzqOOFq748BftwOCWI3iSTM27ZDist855IUnvOigHnxc/QX1SCDVc+B/0AJ+v1/dQH7l6Jyaj3qHFL4IzQydExsQvt8XcteDEsXxiDR+GAo4uvOWsaSiT9SQVnciJlljau7HZsr/y/xcJ8VGpEQfwN+ifawOO9Td7TLgafnQFEZHbSWhuTyIsoW1nPYys=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PUZPR03MB5964.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230025)(4636009)(136003)(396003)(346002)(366004)(376002)(39860400002)(451199018)(64756008)(4326008)(8676002)(6916009)(66556008)(66476007)(66946007)(76116006)(66446008)(54906003)(5660300002)(8936002)(91956017)(316002)(41300700001)(2906002)(966005)(6486002)(478600001)(186003)(71200400001)(6512007)(53546011)(6506007)(36756003)(26005)(85182001)(2616005)(83380400001)(38100700002)(86362001)(122000001)(38070700005)(99106002);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?dzBhdVJCK0ZyZGFsL1l4S1YyWTczSm9aSVlkUXp2dXJ3VzVlZEppSGczLzlj?=
 =?utf-8?B?Vngva3kvbHEweGpYZktZTXNOcmVCKzd5RVM4RVF5bGhMTWZ2YUNrK1E1UmE2?=
 =?utf-8?B?cndJTE4xcnd2dEl5REQwZUI3QU53R0FrR3V6dE1wQXo5RGkyeFkxTDFpaXlB?=
 =?utf-8?B?emNNeUExZDh3ZjVuT3c4ZXZKYzdvcksrTDZnckwrNHRyZDZBemJkcWdzVVli?=
 =?utf-8?B?RXRlTUVTU1p6WDZVTG11bFdIdmJncXJJRVZ4SkxNUHRmdTV5Y1RYcEs1bWV2?=
 =?utf-8?B?aFpBR1lES0RXOFV6ZC8rVEk3MGtuZGRvRFhCUDNvQ2xtb3VER3hIeXd0bW1i?=
 =?utf-8?B?Wk5OajZXdnJoaXgzS1NTS05USlh0YVMrTzVJcFZscjhRWEV0ZXlaVWZwTkxw?=
 =?utf-8?B?Q2JDMWdzYitYSGpIOG9HbEpMeG1CYkpPYU1EVHBwS2h1cHhBcHBIK2YyR0V4?=
 =?utf-8?B?VjArSysvdkpncWI3azBpdmlNdEpzbjErQnI5RkgwYTRvM0l0cVVhOS9GL2VH?=
 =?utf-8?B?MVhpWWVoa0R1M0podml2MjZwakhMdFdBUk8ySkgzbFFNWUdQbjJtZ0RuZWRJ?=
 =?utf-8?B?Vkd4WWVOU25vVWFNSVJZVkhjSUN4dXNkTk5kVmFTaWtFV05pRk0wUTBYZ3VR?=
 =?utf-8?B?MEpGaWxuclZleEFXMkpJT28yODczVnZCbzNtTHYxNnJyNC8yZDVxaSt4U0xB?=
 =?utf-8?B?S1JIcFNwMm1OYlFzR0F0ZXNyeW0wWnJ0S0U2YXlHbnNNSnViSXI2K2ZUNFZP?=
 =?utf-8?B?ellOMDJteXJSQnRLNU9hNThzbEN6dmVmZmc4NzVNNmwwblBNYWhFdXVvSWVp?=
 =?utf-8?B?UVJ2d052d3F1bEpuOWRvcEJibFdRdExqbnlBNDgybWo4aTdoSDZ6ZXpxcnhw?=
 =?utf-8?B?NFFSNnRYdkRnZnM5NjdGT0paQzBaVlJKNE43aFBUZ3FuckhPczd6TXZYZXZR?=
 =?utf-8?B?K1k0NGl6dzU3c1dkUEFrOFgxQnhZUFJMRndrWjBzWlg3VjlYazFNUkFlMys2?=
 =?utf-8?B?UGFGenFFZkR5d3Zsa25rOEVYbTlJSDdkMklVSHZWUGpVZCtWK3FENUhPSzZQ?=
 =?utf-8?B?TGo5anlOVHRPTnU1dmQ1TnNsUTNqR2dzMHk1UjJTYlpSc1Jqd2JRZGpxZVhl?=
 =?utf-8?B?L2o4WDBvNHVDeXJRWmhXYkNmS0ZRV1lMMEFlVVIyMjZENk1RMTY1OHRDa3lL?=
 =?utf-8?B?RzVFakNxa01KbWVmeSt3VUJETnRiL2NrLzdlS0NIcUExazJOdWVpampmM0I5?=
 =?utf-8?B?bVI0ZzgrKzdPTlVNNmE1VnpIQ3JaM1E2eFdSR1pod3VYemcvcmNiYmhyOWI2?=
 =?utf-8?B?K2RYSWZHRU5EWWMrSW1uRjMwb0VIRWd4U00vNGVqN0diUjJFWTV3SllpZk1F?=
 =?utf-8?B?N1k0NXVUYjkydWpaN2o4aHh0cEFBWDArazNwZ1JOUFBXUi9LY21sVitFYVVh?=
 =?utf-8?B?MEVGaDF2NlRza3ZYbUd3M0dsU0VsRDJ3N0xpeW1iTFRHUEhmWEtRQjYzTzEz?=
 =?utf-8?B?ZGNoSTZWWURSaklGRWJOL3BwQ2I2ZlZpRDB0WnptWU5nYTdUVWxDa2RIU2lW?=
 =?utf-8?B?Qy9OWXFVSisyL094V3FzZ0RZckFFdDc3a2pJZEM3NmxoUkZmS0lsWjlXM09W?=
 =?utf-8?B?Rzh0eFpNZENDSVFCSmxiUDdFa2JqZmdFK1BEZk9WSnpFc0YvekppcXNkS0Zl?=
 =?utf-8?B?WVZGYktIVjFsSlorSjJzNEFGdVhXSnNSUTdrRzM4QlRPSjJBckJGYjNOWFNF?=
 =?utf-8?B?Vm0wMjM0bXR0VStXeGp1bDd1RHpUTnBKdng0L3YxZlNqMllZYVErbHBBV3pV?=
 =?utf-8?B?Z0FzTXZ4cnJadUp3MEgyZnBpR1h6djVIRTk4Tk9vY1F5TVdySUJkbmVyckJ4?=
 =?utf-8?B?RzQ0d3N6ZnRBTFR1Y0dUNXBrSnZUZlVNUzZsYlNTbmx3QVlZUWIrSGpQL3dj?=
 =?utf-8?B?M0h0enNIbngzNXl1ckt1MXJRRTdZdGdTZ0FXMEFVcE9KMDZuQk5aWlN1R3NB?=
 =?utf-8?B?MkpES2FYYzYzZ0xQNGIralllNlQ0WkhLR0RwdlpTcHNzQ2Q1OERIZlR1ZTEv?=
 =?utf-8?B?T2FBdTB3WURETDN6L29sdjlzM2pjUnN5c1lwRmZaeEtSR1RGNWhRWTdrNU9r?=
 =?utf-8?B?VVQwcCszMU1Pd09TQldGTlRMVC9hNFdaK0s2cFY3SUJYZktjbGpsbmxYdEtT?=
 =?utf-8?B?bXc9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <B5ADBFCA1435C74CB9C2609869F0FC5F@apcprd03.prod.outlook.com>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PUZPR03MB5964.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: e824cfc3-e89d-4ab1-30bd-08db05989277
X-MS-Exchange-CrossTenant-originalarrivaltime: 03 Feb 2023 03:41:45.3041
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: MWkYsWSfOdX5XHnuQvzGvouxKHeXbHBjz2s3AEWkfmRUpqCvq1YjKdcDy49mPk527TNE87RVB7obryvHUJPEAFgeyduLJtoQVFCnuziXZLk=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PSAPR03MB5253
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=nFS2vn0d;       dkim=pass
 header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com
 header.b=l9Muaewa;       arc=pass (i=1 spf=pass spfdomain=mediatek.com
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

On Thu, 2023-02-02 at 13:59 +0100, Andrey Konovalov wrote:
> On Thu, Feb 2, 2023 at 6:25 AM Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=E7=A9=8E=
)
> <Kuan-Ying.Lee@mediatek.com> wrote:
> >=20
> > On Fri, 2022-06-10 at 16:21 +0100, Catalin Marinas wrote:
> > > Hi,
> > >=20
> > > That's a second attempt on fixing the race race between setting
> > > the
> > > allocation (in-memory) tags in a page and the corresponding
> > > logical
> > > tag
> > > in page->flags. Initial version here:
> > >=20
> > >=20
> >=20
> >=20
https://lore.kernel.org/r/20220517180945.756303-1-catalin.marinas@arm.com
> > >=20
> > > This new series does not introduce any new GFP flags but instead
> > > always
> > > skips unpoisoning of the user pages (we already skip the
> > > poisoning on
> > > free). Any unpoisoned page will have the page->flags tag reset.
> > >=20
> > > For the background:
> > >=20
> > > On a system with MTE and KASAN_HW_TAGS enabled, when a page is
> > > allocated
> > > kasan_unpoison_pages() sets a random tag and saves it in page-
> > > >flags
> > > so
> > > that page_to_virt() re-creates the correct tagged pointer. We
> > > need to
> > > ensure that the in-memory tags are visible before setting the
> > > page->flags:
> > >=20
> > > P0 (__kasan_unpoison_range):    P1 (access via virt_to_page):
> > >   Wtags=3Dx                         Rflags=3Dx
> > >     |                               |
> > >     | DMB                           | address dependency
> > >     V                               V
> > >   Wflags=3Dx                        Rtags=3Dx
> > >=20
> > > The first patch changes the order of page unpoisoning with the
> > > tag
> > > storing in page->flags. page_kasan_tag_set() has the right
> > > barriers
> > > through try_cmpxchg().
> > >=20
> > > If a page is mapped in user-space with PROT_MTE, the architecture
> > > code
> > > will set the allocation tag to 0 and a subsequent page_to_virt()
> > > dereference will fault. We currently try to fix this by resetting
> > > the
> > > tag in page->flags so that it is 0xff (match-all, not faulting).
> > > However, setting the tags and flags can race with another CPU
> > > reading
> > > the flags (page_to_virt()) and barriers can't help, e.g.:
> > >=20
> > > P0 (mte_sync_page_tags):        P1 (memcpy from virt_to_page):
> > >                                   Rflags!=3D0xff
> > >   Wflags=3D0xff
> > >   DMB (doesn't help)
> > >   Wtags=3D0
> > >                                   Rtags=3D0   // fault
> > >=20
> > > Since clearing the flags in the arch code doesn't work, to do
> > > this at
> > > page allocation time when __GFP_SKIP_KASAN_UNPOISON is passed.
> > >=20
> > > Thanks.
> > >=20
> > > Catalin Marinas (4):
> > >   mm: kasan: Ensure the tags are visible before the tag in page-
> > > > flags
> > >=20
> > >   mm: kasan: Skip unpoisoning of user pages
> > >   mm: kasan: Skip page unpoisoning only if
> > > __GFP_SKIP_KASAN_UNPOISON
> > >   arm64: kasan: Revert "arm64: mte: reset the page tag in page-
> > > > flags"
> > >=20
> > >  arch/arm64/kernel/hibernate.c |  5 -----
> > >  arch/arm64/kernel/mte.c       |  9 ---------
> > >  arch/arm64/mm/copypage.c      |  9 ---------
> > >  arch/arm64/mm/fault.c         |  1 -
> > >  arch/arm64/mm/mteswap.c       |  9 ---------
> > >  include/linux/gfp.h           |  2 +-
> > >  mm/kasan/common.c             |  3 ++-
> > >  mm/page_alloc.c               | 19 ++++++++++---------
> > >  8 files changed, 13 insertions(+), 44 deletions(-)
> > >=20
> >=20
> > Hi kasan maintainers,
> >=20
> > We hit the following issue on the android-6.1 devices with MTE and
> > HW
> > tag kasan enabled.
> >=20
> > I observe that the anon flag doesn't have skip_kasan_poison and
> > skip_kasan_unpoison flag and kasantag is weird.
> >=20
> > AFAIK, kasantag of anon flag needs to be 0x0.
> >=20
> > [   71.953938] [T1403598] FramePolicy:
> > [name:report&]=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > =3D=3D=3D=3D
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D
> > [   71.955305] [T1403598] FramePolicy: [name:report&]BUG: KASAN:
> > invalid-access in copy_page+0x10/0xd0
> > [   71.956476] [T1403598] FramePolicy: [name:report&]Read at addr
> > f0ffff81332a8000 by task FramePolicy/3598
> > [   71.957673] [T1403598] FramePolicy:
> > [name:report_hw_tags&]Pointer
> > tag: [f0], memory tag: [ff]
> > [   71.958746] [T1403598] FramePolicy: [name:report&]
> > [   71.959354] [T1403598] FramePolicy: CPU: 4 PID: 3598 Comm:
> > FramePolicy Tainted: G S      W  OE      6.1.0-mainline-android14-
> > 0-
> > ga8a53f83b9e4 #1
> > [   71.960978] [T1403598] FramePolicy: Hardware name: MT6985(ENG)
> > (DT)
> > [   71.961767] [T1403598] FramePolicy: Call trace:
> > [   71.962338] [T1403598] FramePolicy:  dump_backtrace+0x108/0x158
> > [   71.963097] [T1403598] FramePolicy:  show_stack+0x20/0x48
> > [   71.963782] [T1403598] FramePolicy:  dump_stack_lvl+0x6c/0x88
> > [   71.964512] [T1403598] FramePolicy:  print_report+0x2cc/0xa64
> > [   71.965263] [T1403598] FramePolicy:  kasan_report+0xb8/0x138
> > [   71.965986] [T1403598]
> > FramePolicy:  __do_kernel_fault+0xd4/0x248
> > [   71.966782] [T1403598] FramePolicy:  do_bad_area+0x38/0xe8
> > [   71.967484] [T1403598]
> > FramePolicy:  do_tag_check_fault+0x24/0x38
> > [   71.968261] [T1403598] FramePolicy:  do_mem_abort+0x48/0xb0
> > [   71.968973] [T1403598] FramePolicy:  el1_abort+0x44/0x68
> > [   71.969646] [T1403598]
> > FramePolicy:  el1h_64_sync_handler+0x68/0xb8
> > [   71.970440] [T1403598] FramePolicy:  el1h_64_sync+0x68/0x6c
> > [   71.971146] [T1403598] FramePolicy:  copy_page+0x10/0xd0
> > [   71.971824] [T1403598]
> > FramePolicy:  copy_user_highpage+0x20/0x40
> > [   71.972603] [T1403598] FramePolicy:  wp_page_copy+0xd0/0x9f8
> > [   71.973344] [T1403598] FramePolicy:  do_wp_page+0x374/0x3b0
> > [   71.974056] [T1403598]
> > FramePolicy:  handle_mm_fault+0x3ec/0x119c
> > [   71.974833] [T1403598] FramePolicy:  do_page_fault+0x344/0x4ac
> > [   71.975583] [T1403598] FramePolicy:  do_mem_abort+0x48/0xb0
> > [   71.976294] [T1403598] FramePolicy:  el0_da+0x4c/0xe0
> > [   71.976934] [T1403598]
> > FramePolicy:  el0t_64_sync_handler+0xd4/0xfc
> > [   71.977725] [T1403598] FramePolicy:  el0t_64_sync+0x1a0/0x1a4
> > [   71.978451] [T1403598] FramePolicy: [name:report&]
> > [   71.979057] [T1403598] FramePolicy: [name:report&]The buggy
> > address
> > belongs to the physical page:
> > [   71.980173] [T1403598] FramePolicy:
> > [name:debug&]page:fffffffe04ccaa00 refcount:14 mapcount:13
> > mapping:0000000000000000 index:0x7884c74 pfn:0x1732a8
> > [   71.981849] [T1403598] FramePolicy:
> > [name:debug&]memcg:faffff80c0241000
> > [   71.982680] [T1403598] FramePolicy: [name:debug&]anon flags:
> > 0x43c000000048003e(referenced|uptodate|dirty|lru|active|swapbacked|
> > arch
> > _2|zone=3D1|kasantag=3D0xf)
> > [   71.984446] [T1403598] FramePolicy: raw: 43c000000048003e
> > fffffffe04b99648 fffffffe04cca308 f2ffff8103390831
> > [   71.985684] [T1403598] FramePolicy: raw: 0000000007884c74
> > 0000000000000000 0000000e0000000c faffff80c0241000
> > [   71.986919] [T1403598] FramePolicy: [name:debug&]page dumped
> > because: kasan: bad access detected
> > [   71.988022] [T1403598] FramePolicy: [name:report&]
> > [   71.988624] [T1403598] FramePolicy: [name:report&]Memory state
> > around the buggy address:
> > [   71.989641] [T1403598] FramePolicy:  ffffff81332a7e00: fe fe fe
> > fe
> > fe fe fe fe fe fe fe fe fe fe fe fe
> > [   71.990811] [T1403598] FramePolicy:  ffffff81332a7f00: fe fe fe
> > fe
> > fe fe fe fe fe fe fe fe fe fe fe fe
> > [   71.991982] [T1403598] FramePolicy: >ffffff81332a8000: ff ff ff
> > ff
> > f0 f0 fc fc fc fc fc fc fc f0 f0 f3
> > [   71.993149] [T1403598] FramePolicy:
> > [name:report&]                   ^
> > [   71.993972] [T1403598] FramePolicy:  ffffff81332a8100: f3 f3 f3
> > f3
> > f3 f3 f0 f0 f8 f8 f8 f8 f8 f8 f8 f0
> > [   71.995141] [T1403598] FramePolicy:  ffffff81332a8200: f0 fb fb
> > fb
> > fb fb fb fb f0 f0 fe fe fe fe fe fe
> > [   71.996332] [T1403598] FramePolicy:
> > [name:report&]=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > =3D=3D=3D=3D
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D
> >=20
> > Originally, I suspect that some userspace pages have been migrated
> > so
> > the page->flags will be lost and page->flags is re-generated by
> > alloc_pages().
>=20
> Hi Kuan-Ying,
>=20
> There recently was a similar crash due to incorrectly implemented
> sampling.
>=20
> Do you have the following patch in your tree?
>=20
>=20
https://urldefense.com/v3/__https://android.googlesource.com/kernel/common/=
*/9f7f5a25f335e6e1484695da9180281a728db7e2__;Kw!!CTRNKA9wMg0ARbw!hUjRlXirPM=
SusdIWe0RIPt0PNqIHYDCJyd7GSd4o-TgLMP0CKRUkjElH-jcvtaz42-sgE2U58964rCCbuNTJE=
5Jx$=C2=A0
> =20
>=20
> If not, please sync your 6.1 tree with the Android common kernel.
> Hopefully this will fix the issue.
>=20
> Thanks!

Hi Andrey,

Thanks for your advice.

I saw this patch is to fix ("kasan: allow sampling page_alloc
allocations for HW_TAGS").

But our 6.1 tree doesn't have following two commits now.
("FROMGIT: kasan: allow sampling page_alloc allocations for HW_TAGS")
(FROMLIST: kasan: reset page tags properly with sampling)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/eeceea66a86037c4ca2b8e0d663d5451becd60ea.camel%40mediatek.com.
