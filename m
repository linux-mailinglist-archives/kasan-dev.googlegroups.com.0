Return-Path: <kasan-dev+bncBDY7XDHKR4OBB3FN3KTQMGQEWZX5YWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id C1A5E792010
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Sep 2023 04:48:13 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4120b583ab4sf16362431cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Sep 2023 19:48:13 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1693882092; cv=pass;
        d=google.com; s=arc-20160816;
        b=0GyhIDDvfXQOZtOzZAcK56a0JeL5uxIXKccxsvwB9VGarmZp7yF0OOB9+JRovBMPeT
         qid8O5mgn3TXUJ9zsViuMUILRtSQY04HHV0rtu+WuTO+L+0tchfsglQ6EXdN0BVnbxAi
         NPa/Znts3vNRdNjOuZ0SxoX1J2OFih05VoG6lKQ/6Yvr3nHkBHIu2BLTGJP2VBfeSdey
         vLaPBHrEljLjbaw/dlX0uo5a4uEQxR04xFxEcZFZKQK1lrf6IzGfQlVOc9JEvVDE3O7J
         TDwXEWaR96AqXlpbkKEh1sy2IhmtCh6pW6J4qFwxm/XtOOIMz/NHGnbzJO/nMhM2faZB
         oM4w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=sNHyETVdSxiZZaYgwlTJ1PU5HYjO1j9/Zge84b3DH0M=;
        fh=lDlZ9LCEypStzcVBdMqTs29Dcpc1rGWguN1A40gH4bs=;
        b=jtEN2PyplWuFnijvIk5id7bCMHUWKHLoMz64xfiMDoiYO58pxsVBaEBgblZECG3y6h
         UJD1rrne6ffe2ZbfmrwGNcKVFdJ+NiWmkNSpxCKKEp7///ZP5K0bG7y5lE7Fv3WJh8g0
         eIVE5+DdJG96mIFTzU9Z04IBq0d5T/1ywSVLnzjAE4yPNyBft3kRpm8vEOEmlQqWkyJE
         CFce8/sVXzvBTCCRHdJ9XxwDFuhb6nfSyQMhU4SeKb9HELZ5T6rKDLa9zAyp4t5/72cF
         6GFrsF0yfnqMxv4reMAv/W/gpr7o6kYTaLAr1DbB18zjC12xeTxhShgJG67tB38IRxOE
         Zp3g==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Nchoh89v;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b="HGGPbO/B";
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693882092; x=1694486892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sNHyETVdSxiZZaYgwlTJ1PU5HYjO1j9/Zge84b3DH0M=;
        b=RNxFG1P9PztraLb7y6ctXoOTUVuwV2Mb4gALnJldFYlmz6bl0w3VrS3hG3KMtQ7IZz
         /DzHnw1p0GjOUiHfXuyk19FNCnYFPIj9CMl9SeZaMJFpcSEDlUrls2grBRFHUU1xik9/
         SVcwULFZ6dUEBdQiK8I3r2a5UIcU9WSorwVg2Y2um8qGUMIyuql1G+xawDLYLUAFm3qf
         dbIo6wQwe0pkZPrFHlfbrN2S9F67qCsfM8/IK8mbaC3jsgk1F7I44YynRMlMCdHtxtmx
         TXuyTMxAuKNPtWG78K7Eni0oWNmgFCZHqtjs1wUoKgtPYH9XVgfZEDDqAya24uVFPugU
         GJ0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693882092; x=1694486892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=sNHyETVdSxiZZaYgwlTJ1PU5HYjO1j9/Zge84b3DH0M=;
        b=W6cBY6YeRCHPBmyPl2CpTjztxAVddx1JlQCEVydbEpiBKkpDw73kJ8v4PAqtkDlDEI
         L5ijeqvXnDt/M3z1kETWPJ7Y/QTUctDkm74283oAR6a0WnuROvVOaNxord1QkKNyiIEy
         32Xbkeo7be4hgkMl4QV2Tri2CKh8Q5AAsPGtA3/TJEPvuk3WzIjptmK+U1siaJwjftCE
         7mBQ6y5D+4W/0qKGg7qYkyxvvv8EiVkDz8k1N8eEsFAxebOXF/nQYJVJRKs1Vm2etyFX
         4JQz6wP0hIYemntrBu2kcdsmzh//NGoYKIix/xxjKppcAcVgTRs6xO+gp03ZtQFD/1n+
         VE5A==
X-Gm-Message-State: AOJu0YzDSUtsvyHjWtIcjtXjMINYJFBJ9DxWlig/HVfesEQtcepyeLWI
	gC4M5jf6E4NO0Ht4zO6V1bo=
X-Google-Smtp-Source: AGHT+IE3TKbiYfyWWjbSvq5a1/yr/s/fZhvcY0NqY03zjL5o1Y0gz+k6+P0kdyvu2VmYjUZ5ffXShg==
X-Received: by 2002:ac8:7fc2:0:b0:40f:5510:d74d with SMTP id b2-20020ac87fc2000000b0040f5510d74dmr14313993qtk.13.1693882092341;
        Mon, 04 Sep 2023 19:48:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:53c2:0:b0:40f:e8cc:ced0 with SMTP id c2-20020ac853c2000000b0040fe8ccced0ls4687633qtq.1.-pod-prod-08-us;
 Mon, 04 Sep 2023 19:48:11 -0700 (PDT)
X-Received: by 2002:a05:620a:450e:b0:767:d0c:9ec1 with SMTP id t14-20020a05620a450e00b007670d0c9ec1mr14118197qkp.59.1693882091553;
        Mon, 04 Sep 2023 19:48:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693882091; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZalbliHFGaOfih2sJBdN2pNQwYeG4tsOnuUh3rDx8kAnfJz2qemp1/8mYmCbYCFiFE
         WfQCVbRee1Tjx5Fxlc0wWRYczxVDPMxD81DnbvSbJ7IQ/LKj5xRkWyfUfbchT5q8SF6V
         VEzXycElE+RVJpeuTLh2B8eKJIqwF2IqulgFyo6HUwbgvpckzIhk+F11Zpvb+/yWAq2x
         t8Gx3AM5fEkUha9Q2BkKU308gfGQentLG947bmdtl7z9hxL6tsyvy4KlzBNmKPSNGnSV
         OSDzYFhLRLu+L6p8jTe74s02DaGSF3/zCVgRwLJWJk/q0xpAtfdAbGpAdKKq7n2w3R3T
         QsXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=RiyUfq/oUZ79cTfk7WJKn1P8+JzVxNpoaqbAsyXxo9Y=;
        fh=lDlZ9LCEypStzcVBdMqTs29Dcpc1rGWguN1A40gH4bs=;
        b=l3UveGNWu0Fyivs2kmtvmRdIcWnCvZxyBYvBE4+sM69qmNQLI7W6+Qf1oYtn7r61Bg
         ux83iYVlo17oXhIySiSKfdxZeulvMM5BQHOjBoj3HLI+Gkv0UHRtPw1PAFo6Dq+Laz51
         8LMUhYGaBZB4vB+LEIWGDlNInrQai3FdznqXZBIEInPWnpou57AC/uD22G/ajAru4Hkf
         ee0xdGjBbQkVCRENORZ8n4EAENGucoeGPKxR4gArAOpdzAyyRngecoyhVWrHVpe+CH6V
         yP00dsnWGOo+8Aj37ZRh3+aXYnNGPs323jJ0DSDU256bWiNz3oGu979KAOuVQ355Tblg
         iLPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Nchoh89v;
       dkim=pass header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com header.b="HGGPbO/B";
       arc=pass (i=1 spf=pass spfdomain=mediatek.com dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id qd15-20020a05620a658f00b0076d9b7f6888si1036124qkn.5.2023.09.04.19.48.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Sep 2023 19:48:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: a27325344b9611ee8051498923ad61e6-20230905
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.31,REQID:7c23d6a1-511f-4214-bdf5-149e40bde4df,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:0ad78a4,CLOUDID:cb1750ef-9a6e-4c39-b73e-f2bc08ca3dc5,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:0,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES:1,SPR:NO,
	DKR:0,DKP:0,BRR:0,BRE:0
X-CID-BVR: 0,NGT
X-CID-BAS: 0,NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR
X-UUID: a27325344b9611ee8051498923ad61e6-20230905
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 2035160323; Tue, 05 Sep 2023 10:48:03 +0800
Received: from mtkmbs10n1.mediatek.inc (172.21.101.34) by
 MTKMBS14N1.mediatek.inc (172.21.101.75) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Tue, 5 Sep 2023 10:48:03 +0800
Received: from APC01-PSA-obe.outbound.protection.outlook.com (172.21.101.237)
 by mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Tue, 5 Sep 2023 10:48:03 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=KyMpstS7Qt+O3biljYWOEAYq2wgNmzwimOT7/CNW7mu9wkUTQLHB5roGIL1YPsyWemrJjacWf00x+co6awYEg3kl8VOPfuIN/Dx22qaIkpiZnuyJgGe8WrF2ZQVS6q3Dp8Mfdv2HwLuWC6f2RPjezdW+kIXmTAF/JL2n/z/vEK6ddeMzoYENdhzGIre3EoMjXKZvka6pJqanTHNkelino4katyc1/xlsV4xWhj1ZvOGmvdATm/It6f9eX5a65QvxoyhiRiaeu9We5qcydl5cjMDmVGik+sakbdd/z4OWhh1juwFl7gd2GYPTQEXD0En9H+XkcU4vY5N+8GPcan4C3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=RiyUfq/oUZ79cTfk7WJKn1P8+JzVxNpoaqbAsyXxo9Y=;
 b=cmnbeW0x1TCiv5P8jHTnVzmmNEOR/l6AlSUacPey8fLdcS1g2eYXxur3B/3TvC9/O1ACaNe9XZqZHU0+DQR4n3RUCH/1pObmaORcN3SqpI+UGifibgcxnlxqayyR313GeCihenLYlqR0ZHOFV9uOosb68eilUfjEURE8FGQz+5jRatM+x3RdkF/TSYV2HahnqaBxW4ThbFBYgqh1DpWhKnYNre1YScf0t1BAp1Q1fkzp0aUDr+pR4wi7EIYdbzCvdIi8knYOUeUZh6wlZmdeX/3IwldqICS7J7QsbKLCRmaom1JrHs5Pkdos6AG8QcEywyuudvkXzcVzNC3CABcCMA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com (2603:1096:301:b4::11)
 by TYUPR03MB7229.apcprd03.prod.outlook.com (2603:1096:400:358::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6745.30; Tue, 5 Sep
 2023 02:48:00 +0000
Received: from PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::4731:7196:588d:ba27]) by PUZPR03MB5964.apcprd03.prod.outlook.com
 ([fe80::4731:7196:588d:ba27%3]) with mapi id 15.20.6745.030; Tue, 5 Sep 2023
 02:48:00 +0000
From: =?UTF-8?B?J0t1YW4tWWluZyBMZWUgKOadjuWGoOepjiknIHZpYSBrYXNhbi1kZXY=?= <kasan-dev@googlegroups.com>
To: "andreyknvl@gmail.com" <andreyknvl@gmail.com>, "vbabka@suse.cz"
	<vbabka@suse.cz>
CC: "andreyknvl@google.com" <andreyknvl@google.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "dvyukov@google.com" <dvyukov@google.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	=?utf-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
	<Kuan-Ying.Lee@mediatek.com>, "elver@google.com" <elver@google.com>,
	"eugenis@google.com" <eugenis@google.com>, "andrey.konovalov@linux.dev"
	<andrey.konovalov@linux.dev>, "glider@google.com" <glider@google.com>
Subject: Re: [PATCH 00/15] stackdepot: allow evicting stack traces
Thread-Topic: [PATCH 00/15] stackdepot: allow evicting stack traces
Thread-Index: AQHZ36GyQqx7aOyG9USa8MVVyLP1i7ALh3kA
Date: Tue, 5 Sep 2023 02:48:00 +0000
Message-ID: <3a372d658246c5dd1ab1d95f4b601267b0fb154e.camel@mediatek.com>
References: <cover.1693328501.git.andreyknvl@google.com>
	 <3948766e-5ebd-5e13-3c0d-f5e30c3ed724@suse.cz>
	 <CA+fCnZdRkJTG0Z1t00YGuzH4AFAicGUVyxFc63djewRz0vj=pQ@mail.gmail.com>
In-Reply-To: <CA+fCnZdRkJTG0Z1t00YGuzH4AFAicGUVyxFc63djewRz0vj=pQ@mail.gmail.com>
Accept-Language: zh-TW, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-mailer: Evolution 3.28.5-0ubuntu0.18.04.2
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PUZPR03MB5964:EE_|TYUPR03MB7229:EE_
x-ms-office365-filtering-correlation-id: 96642851-7d91-48e4-29e6-08dbadba84c0
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: IycZlfgoamv48mUkpEjk6olPhogpqj+ZSgAuecJokpaNr/nBG6X/xtAbF5QVOAeIdD5CQyb5RHY1q2vaTwI2f8WtvRvBBkd6mk7f0SK2jwOSbFZq4wnvXCCfmNVuIzOVZZw9Fbh1BIT0Id2xr3lNqbQ3Gt8U6URi0UAG9+WOPD89g8MqSUBPtGiKw4RJZiXQ8q8MysFlbXsYRyNaA/anb0ZnfpLPIfvTwUDcbH+PnmuOvqGHNjiOrpFnvFfYxm1Al4RijHhIZ+UE2lAUchSrGD72YHhDPKiKJ3NDS14VPrOmadFR0HQAa9ir5JIYjcUfxgYUzGudDgMASf5FCEyEjP7AKey6y946aZOgtXdmnwIqqLIvZo7af9GVu9T/OvtmnHDl3HMpbW/STUUUQ3p+2LdmYR/FnQ8T4jl4aUH7TOfpl+pMWdKeLy5ygOKQWuRYNqP1/oYVVsTVajYDgwcUuA1bppjTyN9H8l4Dh7KftZ8DC6KymIvZ/NygHu2TUo3kamfbgSKtA3sXnuV9HgsTWTER3Ee2MpQVjJD6WYQXG9ae+bun1Cqx1odTkQkpOakZN97qBRUz8XpmzLyfhUBgepsChZBBDorTyR5zGGKoO8QctFwOKlhnLp0w7TZfeoFh0AWVLXTFh9gD50OZx8tbb5ZKD1PcIa8ABScsPlko4OWy2k9eWIwTym1jVxTbTl+0
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PUZPR03MB5964.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(366004)(39860400002)(346002)(376002)(136003)(396003)(451199024)(186009)(1800799009)(38100700002)(122000001)(38070700005)(83380400001)(41300700001)(5660300002)(85182001)(36756003)(7416002)(86362001)(66556008)(66946007)(66446008)(66476007)(76116006)(26005)(64756008)(71200400001)(478600001)(2616005)(110136005)(91956017)(8936002)(53546011)(8676002)(4326008)(316002)(6512007)(6486002)(54906003)(2906002)(6506007)(99106002);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?b2p4UVpIcStRZEtQUnhWZ21iUzUxeStEYW5rMmJVdTNOR1FlekU3aTBmNTlE?=
 =?utf-8?B?UVBaenVJdkt1TDJrM0JETUZmQzR0REtjUkszd05wWndaeTh0Y25RL28vVnpJ?=
 =?utf-8?B?Z1VKdXkyZm5TTW5zZ01vbDRvNVdpc2RMYm1HQ3VjV3kwQVZMMGVOU2R3ZmRW?=
 =?utf-8?B?eW94dWZ3Wk43c1AwZXNQN0VzZWRDczVkOTM2cFBZeUhIcVhvNmdSdHBoakpN?=
 =?utf-8?B?UU42UnExMGl0dzJlVGFrbXlZS0JWcFRwODNqTWMzNGZlWkpJRVQrdGNIdWhr?=
 =?utf-8?B?UGphNDVZRyttNjhWR1EwSnU1cngyZGxxTWptdkQrem8xL3BvcCtkTFdyaUt6?=
 =?utf-8?B?OUluNUNnOGQxeENiTTlHMjlDajIxUldXdXFWVXRYYUt3UTVuM0IrVnQ1eWhk?=
 =?utf-8?B?WTNhSGJ2cU5MT2djcnIvVXJ6cEpkdzdGK2k2Znp0Yy8zbXJadVVEdURPWFho?=
 =?utf-8?B?byt5dEU1cU04OVk1b3FjdDhaSzdDYlFKUmgzVXRJNkJrQ2lUbm96T2dPZlpH?=
 =?utf-8?B?WmNWbzUxOFdoOG9EeGRBV1ZhT2RmZXFmaCtoays0ZHFUQmlPRVc2aWkvQ0w0?=
 =?utf-8?B?T2hBMy9tZE5WUCtUWXZQZ3ZHbFpYaGZFQUFDR2Y2bjcxVXNKL21IRmtwKzhT?=
 =?utf-8?B?ZGJUSmdYSGM5cEdPYlFlbzlzY092TG1kM1dON1BpK1NjTGhhUG5SWlFsbUs2?=
 =?utf-8?B?RVIwNDAzVzl5ZUxBY1Vha2o1VmhTbWpGaUQ1VmU4SVRtWkdGSWc4TERpM3o3?=
 =?utf-8?B?Wk1ZK3pjOXUzMSs0Rm12bXhkYVh4NDVhUU82QnVOS0IvejdmcTZKd0JPbWxM?=
 =?utf-8?B?bFVkVE5XRmIxQ3JXRG9SWVFmZHVZNUdWT0ZXTzk4YStjQ1BRZk9BZURTV2ZE?=
 =?utf-8?B?RUo3VUtmb2xEODFCeVFKb014T25OUnBFVXNKRjA0YzRNMFNPeFRESDVHblRj?=
 =?utf-8?B?aWFqQlFDVGxheUQ1R2s2dEt3a0tpZ2FlcVZkbmRZYTZVWUk3TmJFMFFsMHZD?=
 =?utf-8?B?bHAvcjYwOTZ3VnZKSWFlc2ZXZit0WURuSWxiUk5LWUJoalJ2SW5CdTEvb3I1?=
 =?utf-8?B?NzRNVHVpZmFrSU9mWm5OOVQ1ZEd5ZFhTZGc5YWl2cEM2bkFRR3lXWVgrUlhB?=
 =?utf-8?B?eEU3bW1hMjllQlVhenpFRTRNcWc0SWVud2Q1WlM3d2VXWWhNUTlPTXE2RUEz?=
 =?utf-8?B?bjlNUzRYem0yRWpORXoyK0JHRlZ0WFFabjRDUnRMYUtUbWdCVXNKcnJNYk9C?=
 =?utf-8?B?dnNQRVpnMUtXSXdtTm0rU2swRlJkNG83cTljRDhvZlVqWlk0Rlh4UWFONVcz?=
 =?utf-8?B?cGc0b1kwT1lVM2Z5OUdZQmxyUm1EVXlpV3lFUjF0OWhyVEh2UG1xZkczbFBB?=
 =?utf-8?B?REFvdVhPa0FDd256K2lFT1NqeENrbzc0cmpESElCRTUyMGlLa0pZWW13OENX?=
 =?utf-8?B?dUpuTlg2bDBPemNGQjR3eU4vUEdrV1B1UzFVODdVZHNUcnNJRnIzSkJCTUsy?=
 =?utf-8?B?UUQrVXZvMFI5d0lFLy82SnNoVWlLTi8yVnpKckpnb0F5OUlyU0RZa1IxSitY?=
 =?utf-8?B?TjZjdTh0SXdkdUlNelc2dTJJN1d2UlByOG9iQ0lING9oeGtPcVRlN3plZlhw?=
 =?utf-8?B?VWU0NzR3NHJUakhyRkxDMGhNckVtRS9zbTkzQUJqeVlKYW96ZG8vRVdwU3p1?=
 =?utf-8?B?ZlBOaS9URThtbS9GTHpOLzRjVVQzOFREUkRtL3Q1RXU0cFM3bUw1S0gvNitl?=
 =?utf-8?B?UWJxbXk2dEpXS21tSUNPQVpPUXNSdzh5OVd6MzAvQVVWbUIwNUIxdWVKa2k1?=
 =?utf-8?B?OTRjREJyb0tsaDZRSVZFOFdzZnZ4VnU4U2t0cjVuNnVUbjkxV0p6aU9maFBk?=
 =?utf-8?B?SG8zeHZvczg0eU5vZVcrMlJadkt6QllkUzEvUXpqZTVQazYxRThZMzU4VXBq?=
 =?utf-8?B?S0hXZFBhUDIvd0FQTU9RN1o4STdTa3VhOE1NdzJkcWVrMnFNWXIzVm9MQzdU?=
 =?utf-8?B?TElaTkREYTh3eTlaSVAyRUR3ditBNVdyZ0ZwdWtPTzdja2Q3aVhmdG5kcDFi?=
 =?utf-8?B?M29sZ1k0bmVoS3FPOEZHUUtqKzBXY0xqelRlMFRSUXBLeEhDUkVEMXc1ZXlZ?=
 =?utf-8?B?QWQrNGJSMTczTitsenIzb0FGMHZLNXErMlJlSEo0L3ZNU1pBdU5Dc3Nyekd3?=
 =?utf-8?B?Tnc9PQ==?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <088D6DD7BED7F647B8EA131597FD3C9F@apcprd03.prod.outlook.com>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PUZPR03MB5964.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 96642851-7d91-48e4-29e6-08dbadba84c0
X-MS-Exchange-CrossTenant-originalarrivaltime: 05 Sep 2023 02:48:00.5550
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: kFo75OqRqbYuegaMszafx4hSmeJUKm/Ja65nyskvj1I1Rj8ON742XIsBnUxHUGTD5ssKA2a8LKkdJdNtLPcnF1IPNB72tExKAcOhoYD9OqM=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: TYUPR03MB7229
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=Nchoh89v;       dkim=pass
 header.i=@mediateko365.onmicrosoft.com header.s=selector2-mediateko365-onmicrosoft-com
 header.b="HGGPbO/B";       arc=pass (i=1 spf=pass spfdomain=mediatek.com
 dkim=pass dkdomain=mediatek.com dmarc=pass fromdomain=mediatek.com);
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates
 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
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

On Mon, 2023-09-04 at 20:45 +0200, Andrey Konovalov wrote:
> On Wed, Aug 30, 2023 at 9:46=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz>
> wrote:
> >=20
> > I wonder if there's also another thing to consider for the future:
> >=20
> > 3. With the number of stackdepot users increasing, each having
> > their
> > distinct set of stacks from others, would it make sense to create
> > separate
> > "storage instance" for each user instead of putting everything in a
> > single
> > shared one?
>=20
> This shouldn't be hard to implement. However, do you see any
> particular use cases for this?
>=20
> One thing that comes to mind is that the users will then be able to
> create/destroy stack depot instances when required. But I don't know
> if any of the users need this: so far they all seem to require stack
> depot throughout the whole lifetime of the system.
>=20
Maybe we can use evition in page_owner and slub_debug
(SLAB_STORE_USER).

After we update page_owner->handle, we could evict the previous
handle?

> > In any case, evicting support is a good development, thanks!
>=20
> Thank you!
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/3a372d658246c5dd1ab1d95f4b601267b0fb154e.camel%40mediatek.com.
