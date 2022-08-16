Return-Path: <kasan-dev+bncBD4L7DEGYINBB3XN5WLQMGQEYRWCA4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id B8D525958FD
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 12:52:34 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id s22-20020a056a00195600b0052ece6c829fsf3612472pfk.6
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 03:52:34 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:from:to:cc;
        bh=0Vs4ygJai81RJdpnL04My+sfuNc/s41xe9rrIJbf1Iw=;
        b=Hk/Y9+VVePGTtkqhilAZ7Qph27OUVgFiCself+AexuC8t7/fVI75QYFQkHUqoc9hSy
         thc9YvjkrGXJeXlUG0Pdx60ee0R2nYXGRoH6jkOIRSPKMmPO1QIAitVt9RIfN946jIT9
         wjQ4Bx44Ib/pt+5A6xOF1zY3agjJ2fR4VTPM4QZBZbJtrEYCQ2Z71/sClinkR4kwWWdM
         lNf5mBFkOtqB2PkUI1aH0PyDxft/u1thTyD+KFRTICCuEs72MSLCj16ruI202ao53z/+
         rzdfKWoos/EqzR+fQjmU1h/dkVgHPIbKqszmrHaT0IidlFkvrPR8BUfFkl4AyWO+D6+2
         bEzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:x-gm-message-state:from:to:cc;
        bh=0Vs4ygJai81RJdpnL04My+sfuNc/s41xe9rrIJbf1Iw=;
        b=Y+g8FYlbCLO+r/DI3v0MiEi+DBwSMKCxq9O+HuaT93WvKXleXjVbjy5KFMx3HnwiWp
         u1GIDcYIn/WzafWugdVrdT2iSK92sYp0LTdjLL/SNAOJxrohPyDZyX4TWDozB2TNAN15
         6VL+2KW+hBUgN7STkdOveUrBzMtvEmKxxCX/37qCRX4TflE3sXnK05XKDb0yTQmLemiw
         xwJ1Nii8sBXUnq6Tt8Z4hvgD2XRwEK6wuOlmlk/TglxG+W2+sjSbTkFaYk8nUBhuwXOP
         jds8wSaTnkPbDVp3pXQJuxYJsBsKA1AiIteLNIa4CRc0Q0MlKylYljgET0mck/T9yZis
         amxQ==
X-Gm-Message-State: ACgBeo0LGC6WKlV+g4ChiZtodIK/k/t20QSdPjxzWGgRP4pmCQ/6wBvG
	gDxQ82boP74NdKHAHAFKHJA=
X-Google-Smtp-Source: AA6agR7lGWubHYJwiMRe7SjNI0a9URuBl2HvBeOoBLwrpOLvDiEPo8XXNxKHXVYD2YbXhwnj9XeYtQ==
X-Received: by 2002:a17:90b:4a4e:b0:1f5:431c:54f8 with SMTP id lb14-20020a17090b4a4e00b001f5431c54f8mr33569741pjb.161.1660647150885;
        Tue, 16 Aug 2022 03:52:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2a0c:0:b0:41a:63e8:2535 with SMTP id q12-20020a632a0c000000b0041a63e82535ls6254060pgq.2.-pod-prod-gmail;
 Tue, 16 Aug 2022 03:52:30 -0700 (PDT)
X-Received: by 2002:a05:6a00:14c4:b0:52e:6b0f:209b with SMTP id w4-20020a056a0014c400b0052e6b0f209bmr20218398pfu.36.1660647150076;
        Tue, 16 Aug 2022 03:52:30 -0700 (PDT)
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id z13-20020a17090ad78d00b001ef94afbc2esi93018pju.2.2022.08.16.03.52.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Aug 2022 03:52:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 05e67bf02bb94abd8e14d7eb3085b398-20220816
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.10,REQID:86879b7d-5548-413f-a741-7d3ac7a12332,OB:0,L
	OB:0,IP:0,URL:0,TC:0,Content:0,EDM:0,RT:0,SF:1,FILE:0,BULK:0,RULE:Release_
	Ham,ACTION:release,TS:1
X-CID-INFO: VERSION:1.1.10,REQID:86879b7d-5548-413f-a741-7d3ac7a12332,OB:0,LOB
	:0,IP:0,URL:0,TC:0,Content:0,EDM:0,RT:0,SF:1,FILE:0,BULK:0,RULE:Release_Ha
	m,ACTION:release,TS:1
X-CID-META: VersionHash:84eae18,CLOUDID:afeef7ae-9535-44a6-aa9b-7f62b79b6ff6,C
	OID:IGNORED,Recheck:0,SF:17|19,TC:nil,Content:0,EDM:-3,IP:nil,URL:1,File:n
	il,Bulk:nil,QS:nil,BEC:nil,COL:0
X-UUID: 05e67bf02bb94abd8e14d7eb3085b398-20220816
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw02.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 576619076; Tue, 16 Aug 2022 18:52:25 +0800
Received: from mtkmbs10n1.mediatek.inc (172.21.101.34) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.792.3;
 Tue, 16 Aug 2022 18:52:24 +0800
Received: from APC01-PSA-obe.outbound.protection.outlook.com (172.21.101.239)
 by mtkmbs10n1.mediatek.com (172.21.101.34) with Microsoft SMTP Server id
 15.2.792.15 via Frontend Transport; Tue, 16 Aug 2022 18:52:23 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=D8aHUsyGXU7Gwrj7OxD7iQLvPrqjBXRHFg8ntYHvMb/hYVguDnhPQrF84NIVYA2MSs2mT3OvQTZePbbl00m6vanrHuEn9ESSSBbbq+7o5sHTWezMaXwORWzhWKnJMMqKbRLictplC3Z/5P24lKCwrap8qLtJjy++42jebbgPHKMM1bFjFvI3xdIgy123KIloG6uW5bfgcJYZ9G4sTsFHXZsgy2BByXnYqfDks4TggfVac87obofBa07+3DS1UtifEBHgSS9TEUFikfenCHuv6FLCcs9zn9LqF8ii5ptFT0mQZhc/Da5QOxrxipsRtCh7xAi46hcpcdmpE8T+u4fsjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=A1veVDmax2abyme5cUHqGNqbq5GtFJMgpm8rVCbw+Go=;
 b=GgTrBshe55q82IYRtGkB7FYuNJA5/6BE3gUoVn6DdGk23wPT4/vfQOD1qZi4Mor5a6qOrRvRkF1llugNm9NdBzx2HYGp8ujUac+BbDyF2ytUIWv2Lr6Z7AP0uA97RUApaRgr+D8uWjjv9ZRJA//y8h+1ZvGSGMtrWhi7fWJSuYolzlC2Upj1qI1G7SFj1hXC6sPYnxAgMojjPEm4R+QlRuBuEmZyPDFIZ22mAQbKY/uSzBGVbPgL2hHvBAiN5Hc+6LUv9aHlFdM0f4ImKTqKLUDSXQgJHvVcyFuNHXjgODD154MdtW2M3tPwh/AVjf0YLxxPLI8LtoHrueVfDpuSnA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from SI2PR03MB5753.apcprd03.prod.outlook.com (2603:1096:4:153::11)
 by SI2PR03MB5690.apcprd03.prod.outlook.com (2603:1096:4:15d::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5546.14; Tue, 16 Aug
 2022 10:52:20 +0000
Received: from SI2PR03MB5753.apcprd03.prod.outlook.com
 ([fe80::b455:bbf8:c815:f2eb]) by SI2PR03MB5753.apcprd03.prod.outlook.com
 ([fe80::b455:bbf8:c815:f2eb%4]) with mapi id 15.20.5546.015; Tue, 16 Aug 2022
 10:52:20 +0000
From: =?UTF-8?B?J1llZSBMZWUgKOadjuW7uuiqvCknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>, Will Deacon <will@kernel.org>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>
CC: Max Schulze <max.schulze@online.de>,
	"linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "catalin.marinas@arm.com"
	<catalin.marinas@arm.com>, "naush@raspberrypi.com" <naush@raspberrypi.com>,
	"glider@google.com" <glider@google.com>, "dvyukov@google.com"
	<dvyukov@google.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>
Subject: RE: kmemleak: Cannot insert 0xffffff806e24f000 into the object search
 tree (overlaps existing) [RPi CM4]
Thread-Topic: kmemleak: Cannot insert 0xffffff806e24f000 into the object
 search tree (overlaps existing) [RPi CM4]
Thread-Index: AQHYsL7XJSggUk+jtUKo5xgcYfZ5Sq2xMNKA
Date: Tue, 16 Aug 2022 10:52:19 +0000
Message-ID: <SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9@SI2PR03MB5753.apcprd03.prod.outlook.com>
References: <b33b33bc-2d06-1bcd-2df7-43678962b728@online.de>
 <20220815124705.GA9950@willie-the-truck>
 <CANpmjNPrDW5FRf3PdzAUsjEtHgaWVTJ2CNr0=e732fEUf4FTmQ@mail.gmail.com>
In-Reply-To: <CANpmjNPrDW5FRf3PdzAUsjEtHgaWVTJ2CNr0=e732fEUf4FTmQ@mail.gmail.com>
Accept-Language: en-US
Content-Language: zh-TW
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 3e9bc31a-6916-4cdc-5911-08da7f756499
x-ms-traffictypediagnostic: SI2PR03MB5690:EE_
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: NRe7g0IgNfVUHs8ncKY6EC80/gTCddkOpmP2zgYQdlwW1KzKbrUpxn0Xp4ie5CQBE5G3YJ0nvY7TBngDLHt1GHP4u/m25LxoVrGGBJxvsQmP/Sv9l2M5S727/Y81Xm5+hNPfJmzLP+DRGk4Rad3Vucr2GObFJYrs5mGw9zkRfIJBK59ZMMFXX64wrfYq6/xNN28H/td7yf00LGxGueJ9pnfmi1e0T38t133xQvA0nNV5mB1TuMn/Q3zgUOyHABfX1Dj752WwLL3na+6KrERPdYeDBUpTm4IIuSJz50LhgEq6sVmAEPxEwuSELyAxqJTDcetZH/7AAmt87Cl3U2e76XIHbbkR/xhdPlht7oXUWY8tY33yke0ehlKR4/aRLKb6mtynSS0NflUX2rmBM/Tuj3vAhj717f3oj9IgIF2NIquB1cpImC1kprgLDaw3jE1MPt6sLTyjc4/PApOlLeaMT/Dzs3AjId9T6B9/Y+4phaASvS15+PcRx83Ks+urK9Y8hIBASTGAsvb5db3sERGVhzs5FcQ+WeuwwZ/sCn8Z+30OObGwshvMVRXvr9imkOZR/voxCiUGQ8lC2krSPvU0gYcjdFSnkQD7KQEp1ykZI9d2mg73fj+JFYJamkbe1iFyrtm8n5QWnv6pZbV3YlgbkA2RwBflhl+5+cb6v+InJTqEPqCpwEp6xjV33gFNOlz9HaHF8REE8bNyxdqSA4z8dXFskDBofM0OKofZZ/ApCBUo6P8eS0LsVHZn8aOu82JyBWrppHkxNvAZpUjfO8nYc3G8eHMX+El6CF7G9vNNgYFGsKQOaHYNzcH1olHP733v5iTGX7ST+Cv+i/bm18Gx4MhhCl9MFe2rchBLD8DqwhNXJaDG9MhEv+l3fUxcXZWf
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:SI2PR03MB5753.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(4636009)(396003)(39860400002)(136003)(366004)(346002)(376002)(38100700002)(8676002)(478600001)(966005)(26005)(9686003)(6506007)(66446008)(7696005)(53546011)(41300700001)(66476007)(66556008)(316002)(54906003)(186003)(83380400001)(64756008)(4326008)(76116006)(8936002)(66946007)(110136005)(7416002)(2906002)(55016003)(38070700005)(52536014)(5660300002)(71200400001)(85182001)(86362001)(122000001)(33656002);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?dGNsVWRzaG9wallaMHgrZWprYnNJKzFYQWJlYVU0Si9hSkJKU1Uxa2NmaHF6?=
 =?utf-8?B?citqeStzNHNZZDRtQjhvb3NYUGxwZjFoYWY5NU9zQVlTVWJXdDJ2QmVabzJI?=
 =?utf-8?B?TFNTK3lXOGZuMGJ3aktHcy9KRTVpc3Bid3p2K2dmV1M5UElYakxDbzBidkc1?=
 =?utf-8?B?TmJaQXhIcS96bWVYancyL2VyVG9XTHphS25qMnhLeDBXNDVPUFdEV0VzZzlM?=
 =?utf-8?B?TzZHOCtqMmlIUkJZNXAvSlp2UFVVekMvblZ3T0lZQjdQajI0WCtvMm1aT2ZP?=
 =?utf-8?B?WkpnWTJlaFJacXQ0dTF2Y2NTWVhKOGtuUFUxaTZjSG5tK3RlNUViQXNzcG9l?=
 =?utf-8?B?VGk1aGplaUpnUE1kTkNqblBYOFhWWUdJWnRZWU5OSi9WejdjUDY1Z002bG1z?=
 =?utf-8?B?Szh6d3dDT1NhWW83TVNLdmFrQUJicWhJanNoZXRSaFlLUFk5UEZYNmtnenBu?=
 =?utf-8?B?OHNkWWVzN0QvaUhhREx2dHlFZEVoeEpxRE40d0x6S2RIV2ZtN2FtcHlCeER1?=
 =?utf-8?B?cEZaRGVnZDdNTTJYaGZvbGJLK0F4a3VNSEUxK2M3K3phMDR0bDZKRlhkajNo?=
 =?utf-8?B?VGJBdVdnOVNnbXpCWTdYM1Y3ZFVBcVliWlgxSXNzcUdjNkJUbkh1ZWJNcFEy?=
 =?utf-8?B?NVpEUURJWEpPbHlkSWorWWYxcitFU2xZdDRiVEhTbjlvb3NBT21GUjV1R29t?=
 =?utf-8?B?NVBxRUlFMEVLS3A3aDFmdmZkOTNwMTIzMjVPZG5rN05oRXlxb1NxbXg2b2c3?=
 =?utf-8?B?Z1hIbU9BSWRQT3pJTHdocWUzN0lWNkxLUjY2K1h3bWR2YjlVeTZJRnBSd0Fk?=
 =?utf-8?B?OXQrRllhVVlTdmh3RWJLQTJHamJ3dFlPeDZKdVorZE96YjU3d01XYjFIN3NS?=
 =?utf-8?B?VFVVWU45NkhGclBEMEhZbzNRL2J2ZlNoa2xUU1AxdzdoSUwzVnlrWjN0ZmVw?=
 =?utf-8?B?SnFjQno4TGNGdFNnRjdWaW1kYXJRd1RZb3Y2cmp3cUt4SXNEK0Mwc0FteEs4?=
 =?utf-8?B?dXVvOTUvUldvRElXM1NvcGU5eXlXNmNJUXMzY1RUdDJYVm5wM0R5a3ZScWd3?=
 =?utf-8?B?dFI5VTVQTzByZ2t3NUtoNFhOVE9zSFd6cllEU1JlR1VKbHdtVnBURm1rZVB6?=
 =?utf-8?B?ZllUQ1pXbGN0TURXdkRZSjhseUFvOFN5S0dlN1NrUDg3UUlDL2x2MUxHSGVw?=
 =?utf-8?B?cmRKVU5pdGpvK2FtaGVWU2o3RzZGT2RDVlNxUUEvU3ltOWREQ3BJNjNFS2ln?=
 =?utf-8?B?S1dZSThUTXpJbzlpdTg4RXFXYzhSWWIxTXIycWo2MDZWb2ZoT1lOK1dPRmlk?=
 =?utf-8?B?Y1lwOGpTSm5UMG5Bc1pldWtmemwreFRRcVlHQkVsSlJvUnRNUXB4OE1xdVdT?=
 =?utf-8?B?UVFjRDhyNURHb0l3RE5PaDFBOXk2YzU1UkNZaXpac1BCVXNsSzduVlpqampr?=
 =?utf-8?B?dVkvWXpHckxDMjd1RVFwc2dzbE03cmI3M0V3dXZsVm9aWlJtQnkrMkJzNy8z?=
 =?utf-8?B?bGtFaUhuRnpXV0VjNVBYNHpjNXppWkdzRGlNV3NNR2VaazhJVm5wa3ZMNU9k?=
 =?utf-8?B?WUgzYXNubVl6bmpiVHljTVljMlJzRVV3ZVVQd0pOZjRxSjQxSGY3bGlPODgy?=
 =?utf-8?B?Q0dtaW1FVjN1OHJ1Y1JVcC9VbytXTzVjVlB1Si9Zdyt4OFcxRE56bmVnM3l1?=
 =?utf-8?B?VHZzNDFoWERzd2NZZ1lTOGhmcjY0RnI1bXdYdWhFeEpRMFRoeUlqbDhBYUxP?=
 =?utf-8?B?bFpGQjdVdGRaZS8vajhtNWNWa3poQjJwckN0cmovTVFyWTA4Skx5aGhybC9Z?=
 =?utf-8?B?Wk96VGo0TWMxSGNFTUh6RElCenMwR015ZENMSmFBYTdQU2tteDFsUE1iYUs5?=
 =?utf-8?B?NHlrYzBxZDhubmN0eUk3TnZxaHQ3WHQrSHlQOTNBU1ExS08rVHRYWmxFaDB1?=
 =?utf-8?B?UUx3bGRwUWpZL3VSNWwySU5CUndxYWozV0lqamo3VXZubGM2TFFlYVk1WTd4?=
 =?utf-8?B?QlNJb2hMcFFxSG1BZllKYWQxbnFGU00xdW96VnVsL09hWDBnU2VaQjBHOUFx?=
 =?utf-8?B?K2xDRTkzSDFKVm0wSWR4TVJ0WnBuYkJOWWw5azJqZllnMGU0T2xsL2J1Tzhz?=
 =?utf-8?Q?1HGQgf83xpZ+m1hEZineu47DP?=
Content-Transfer-Encoding: base64
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: SI2PR03MB5753.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 3e9bc31a-6916-4cdc-5911-08da7f756499
X-MS-Exchange-CrossTenant-originalarrivaltime: 16 Aug 2022 10:52:20.1550
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: HRE9ss1YNU1DjmZzeu+SwLM304BTIWUCQeny1OSSItWfKK9jA9oU2FQFTTaLo1+o1gADML//T4TIhYs0ffcFOg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SI2PR03MB5690
Content-Type: multipart/alternative;
	boundary="__=_Part_Boundary_001_122232010.1314762188"
X-Original-Sender: yee.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="Gok8/mJs";       dkim=neutral
 (body hash did not verify) header.i=@mediateko365.onmicrosoft.com
 header.s=selector2-mediateko365-onmicrosoft-com header.b=FrLw8ZOy;
       arc=fail (body hash mismatch);       spf=pass (google.com: domain of
 yee.lee@mediatek.com designates 210.61.82.184 as permitted sender)
 smtp.mailfrom=yee.lee@mediatek.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: =?utf-8?B?WWVlIExlZSAo5p2O5bu66Kq8KQ==?= <Yee.Lee@mediatek.com>
Reply-To: =?utf-8?B?WWVlIExlZSAo5p2O5bu66Kq8KQ==?= <Yee.Lee@mediatek.com>
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

--__=_Part_Boundary_001_122232010.1314762188
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<pre>

The&#32;kfence&#32;patch(07313a2b29ed)&#32;is&#32;based&#32;on&#32;the&#32;=
prior&#32;changes&#32;in&#32;kmemleak(0c24e061196c2&#32;,&#32;merged&#32;in=
&#32;v6.0-rc1),&#32;but&#32;it&#32;shows&#32;up&#32;earlier&#32;in&#32;v5.1=
9.&#32;

@akpm
Andrew,&#32;sorry&#32;that&#32;the&#32;short&#32;fix&#32;tag&#32;caused&#32=
;confusing.&#32;Can&#32;we&#32;pull&#32;out&#32;the&#32;patch(07313a2b29e)&=
#32;in&#32;v5.19.x&#63;

Kfence:&#32;(07313a2b29ed)&#32;https://github.com/torvalds/linux/commit/073=
13a2b29ed1079eaa7722624544b97b3ead84b
Kmemleak:&#32;(0c24e061196c2)&#32;https://github.com/torvalds/linux/commit/=
0c24e061196c21d53328d60f4ad0e5a2b3183343


The&#32;overlapping&#32;happened&#32;as&#32;kfence&#32;pool&#32;occupied&#3=
2;the&#32;virtual&#32;address&#32;which&#32;supposed&#32;to&#32;be&#32;avai=
lable&#32;for&#32;later&#32;object&#32;allocations.&#32;With&#32;the&#32;ch=
anges&#32;in&#32;kmemleak,&#32;the&#32;pool&#32;won&#39;t&#32;be&#32;record=
ed&#32;in&#32;VA.

The&#32;pool&#39;s&#32;kmemleak&#32;object&#32;is&#32;created&#32;from&#32;=
memblock_alloc&#32;and&#32;can&#32;be&#32;freed&#32;as&#32;calling&#32;memb=
lock_free.&#32;
If&#32;there&#32;is&#32;no&#32;more&#32;operating&#32;on&#32;its&#32;PA,&#3=
2;we&#32;can&#32;just&#32;ignore&#32;it&#32;not&#32;removing&#32;it.


Best&#32;Regards,
Yee

-----Original&#32;Message-----
From:&#32;Marco&#32;Elver&#32;&lt;elver@google.com&gt;&#32;
Sent:&#32;Monday,&#32;August&#32;15,&#32;2022&#32;11:50&#32;PM
To:&#32;Will&#32;Deacon&#32;&lt;will@kernel.org&gt;;&#32;Yee&#32;Lee&#32;(&=
#26446;&#24314;&#35516;)&#32;&lt;Yee.Lee@mediatek.com&gt;
Cc:&#32;Max&#32;Schulze&#32;&lt;max.schulze@online.de&gt;;&#32;linux-arm-ke=
rnel@lists.infradead.org;&#32;catalin.marinas@arm.com;&#32;naush@raspberryp=
i.com;&#32;glider@google.com;&#32;dvyukov@google.com;&#32;kasan-dev@googleg=
roups.com
Subject:&#32;Re:&#32;kmemleak:&#32;Cannot&#32;insert&#32;0xffffff806e24f000=
&#32;into&#32;the&#32;object&#32;search&#32;tree&#32;(overlaps&#32;existing=
)&#32;[RPi&#32;CM4]

On&#32;Mon,&#32;15&#32;Aug&#32;2022&#32;at&#32;14:47,&#32;Will&#32;Deacon&#=
32;&lt;will@kernel.org&gt;&#32;wrote:
&gt;
&gt;&#32;[+kfence&#32;folks&#32;as&#32;kfence_alloc_pool()&#32;is&#32;start=
ing&#32;the&#32;stacktrace]
&gt;
&gt;&#32;On&#32;Mon,&#32;Aug&#32;15,&#32;2022&#32;at&#32;11:52:05AM&#32;+02=
00,&#32;Max&#32;Schulze&#32;wrote:
&gt;&#32;&gt;&#32;Hello,
&gt;&#32;&gt;
&gt;&#32;&gt;&#32;I&#32;get&#32;these&#32;messages&#32;when&#32;booting&#32=
;5.19.0&#32;on&#32;RaspberryPi&#32;CM4.
&gt;&#32;&gt;
&gt;&#32;&gt;&#32;Full&#32;boot&#32;log&#32;is&#32;at&#32;
&gt;&#32;&gt;&#32;https://urldefense.com/v3/__https://pastebin.ubuntu.com/p=
/mVhgBwxqPj
&gt;&#32;&gt;&#32;/__;!!CTRNKA9wMg0ARbw!zoc_1ye57MyrB-45TNoz5wwiQLHWrXAblWZ=
LGm1RPhPaTX
&gt;&#32;&gt;&#32;6WWyI6wxHFOOrUwzw&#36;
&gt;&#32;&gt;
&gt;&#32;&gt;&#32;Anyone&#32;seen&#32;this&#63;&#32;What&#32;can&#32;I&#32;=
do&#32;&#63;

I&#32;think&#32;the&#32;kmemleak_ignore_phys()&#32;in&#32;[1]&#32;is&#32;wr=
ong.&#32;It&#32;probably&#32;wants&#32;to&#32;be&#32;a&#32;kmemleak_free_pa=
rt_phys().

[1]&#32;https://urldefense.com/v3/__https://git.kernel.org/pub/scm/linux/ke=
rnel/git/torvalds/linux.git/commit/mm/kfence&#63;h=3Dv5.19&amp;id=3D07313a2=
b29ed1079eaa7722624544b97b3ead84b__;!!CTRNKA9wMg0ARbw!zoc_1ye57MyrB-45TNoz5=
wwiQLHWrXAblWZLGm1RPhPaTX6WWyI6wxHFQ-Ttpzo&#36;&#32;

+Cc&#32;Yee

</pre><!--type:text--><!--{--><pre>************* MEDIATEK Confidentiality N=
otice
 ********************
The information contained in this e-mail message (including any=20
attachments) may be confidential, proprietary, privileged, or otherwise
exempt from disclosure under applicable laws. It is intended to be=20
conveyed only to the designated recipient(s). Any use, dissemination,=20
distribution, printing, retaining or copying of this e-mail (including its=
=20
attachments) by unintended recipient(s) is strictly prohibited and may=20
be unlawful. If you are not an intended recipient of this e-mail, or believ=
e
=20
that you have received this e-mail in error, please notify the sender=20
immediately (by replying to this e-mail), delete any and all copies of=20
this e-mail (including any attachments) from your system, and do not
disclose the content of this e-mail to any other person. Thank you!
</pre><!--}-->

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9%40SI2PR03MB5753=
.apcprd03.prod.outlook.com?utm_medium=3Demail&utm_source=3Dfooter">https://=
groups.google.com/d/msgid/kasan-dev/SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9%=
40SI2PR03MB5753.apcprd03.prod.outlook.com</a>.<br />

--__=_Part_Boundary_001_122232010.1314762188
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable


The kfence patch(07313a2b29ed) is based on the prior changes in kmemleak(0c=
24e061196c2 , merged in v6.0-rc1), but it shows up earlier in v5.19.=20

@akpm
Andrew, sorry that the short fix tag caused confusing. Can we pull out the =
patch(07313a2b29e) in v5.19.x?

Kfence: (07313a2b29ed) https://github.com/torvalds/linux/commit/07313a2b29e=
d1079eaa7722624544b97b3ead84b
Kmemleak: (0c24e061196c2) https://github.com/torvalds/linux/commit/0c24e061=
196c21d53328d60f4ad0e5a2b3183343


The overlapping happened as kfence pool occupied the virtual address which =
supposed to be available for later object allocations. With the changes in =
kmemleak, the pool won't be recorded in VA.

The pool's kmemleak object is created from memblock_alloc and can be freed =
as calling memblock_free.=20
If there is no more operating on its PA, we can just ignore it not removing=
 it.


Best Regards,
Yee

-----Original Message-----
From: Marco Elver <elver@google.com>=20
Sent: Monday, August 15, 2022 11:50 PM
To: Will Deacon <will@kernel.org>; Yee Lee (=E6=9D=8E=E5=BB=BA=E8=AA=BC) <Y=
ee.Lee@mediatek.com>
Cc: Max Schulze <max.schulze@online.de>; linux-arm-kernel@lists.infradead.o=
rg; catalin.marinas@arm.com; naush@raspberrypi.com; glider@google.com; dvyu=
kov@google.com; kasan-dev@googlegroups.com
Subject: Re: kmemleak: Cannot insert 0xffffff806e24f000 into the object sea=
rch tree (overlaps existing) [RPi CM4]

On Mon, 15 Aug 2022 at 14:47, Will Deacon <will@kernel.org> wrote:
>
> [+kfence folks as kfence_alloc_pool() is starting the stacktrace]
>
> On Mon, Aug 15, 2022 at 11:52:05AM +0200, Max Schulze wrote:
> > Hello,
> >
> > I get these messages when booting 5.19.0 on RaspberryPi CM4.
> >
> > Full boot log is at=20
> > https://urldefense.com/v3/__https://pastebin.ubuntu.com/p/mVhgBwxqPj
> > /__;!!CTRNKA9wMg0ARbw!zoc_1ye57MyrB-45TNoz5wwiQLHWrXAblWZLGm1RPhPaTX
> > 6WWyI6wxHFOOrUwzw$
> >
> > Anyone seen this? What can I do ?

I think the kmemleak_ignore_phys() in [1] is wrong. It probably wants to be=
 a kmemleak_free_part_phys().

[1] https://urldefense.com/v3/__https://git.kernel.org/pub/scm/linux/kernel=
/git/torvalds/linux.git/commit/mm/kfence?h=3Dv5.19&id=3D07313a2b29ed1079eaa=
7722624544b97b3ead84b__;!!CTRNKA9wMg0ARbw!zoc_1ye57MyrB-45TNoz5wwiQLHWrXAbl=
WZLGm1RPhPaTX6WWyI6wxHFQ-Ttpzo$=20

+Cc Yee

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9%40SI2PR03MB5753.apcprd03.p=
rod.outlook.com.

--__=_Part_Boundary_001_122232010.1314762188--

