Return-Path: <kasan-dev+bncBAABBQGRR2QQMGQEPWE53KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id C4A566CD062
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 04:56:01 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id bp16-20020a056808239000b00384dfa31ab8sf3090668oib.2
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 19:56:01 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680058560;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=0EsgOqTntxVoU7ZwgremzQvQyJA1B5wKwhIfw67KW48=;
        b=deawtzVuU6x2+Zk27S5+ZHerLzxwm1jY1qnAglZmV0Wp6mo1IzQaGm9+1VM/Jy9aQz
         Nq+Ue9HU7PVF8632ZhKsuVLZwmATQea3fPxrmq9CODegXs4ehsaKnTyhcctGqn6Ojdqj
         TQTKrUrK1BjyOORlojMMNf09uOFkQH4oo0gaGpAlNZw47paodHC4qLjIAhWOnWH33e85
         MSmuIFEr5SSKsSg6h6zug8cR1db2aAhVQTDoNGsCQsl+h7sloDjJnzeFMT+3ZGXDDcug
         f6PmkUK8SZwL42eSkOf0ntQ2GQSjdWCZSjczKGbsbwYYw5hk131ZDimQOVQ3DWpOg9/Z
         ZjWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680058560;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :cc:to:from:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0EsgOqTntxVoU7ZwgremzQvQyJA1B5wKwhIfw67KW48=;
        b=d1djrvp2qCq+MpbfYcI/auBV+uspZkalGTb3kCs1A6XnOPQ4fFT3+AYBLIDLXd2AAI
         QuEX9tnSQ4hQtGLDNtellbpZUoqCR0SaMzQrlmdglDjcATN7hppvzW2vKozmTZySj4Bp
         UZyn/ec2pCtbkDO5GeTdz/5nBXXy8dvN3xSX9n/C3tYbGovpniV07Id3JhsnZuVnPiYZ
         AKf5g61lbe69B8ol2ZB+4NzynXFOZQzULmS7PdwvQk4YjmcQpK6mAVqr0Bq5zKjGuVwT
         jUy6dDxUu6dlpqz/faJ+LRevJp+77ZMzCRmlF17O/vvaWtQYvxEYC0nnJa1SQ3P0+H9B
         7KLw==
X-Gm-Message-State: AO0yUKUTjNcGqhTrlDbhhtyfZyBUvV/q+AWWIH77dLnoH8jirutRw38F
	Jn5Oh5CqdHsB2V1PnSzaoto=
X-Google-Smtp-Source: AK7set8jGGOmQvf4t2zG37n5ArboUM5A5IJ73Xb54goNYFWylYLXxv7j4NTDoxVAZuDLOnn9We8ZaA==
X-Received: by 2002:a05:6870:c81b:b0:177:7dc2:6f2a with SMTP id ee27-20020a056870c81b00b001777dc26f2amr4395329oab.10.1680058560340;
        Tue, 28 Mar 2023 19:56:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d108:0:b0:53b:545d:9cb2 with SMTP id k8-20020a4ad108000000b0053b545d9cb2ls582747oor.6.-pod-prod-gmail;
 Tue, 28 Mar 2023 19:56:00 -0700 (PDT)
X-Received: by 2002:a4a:494a:0:b0:525:b0c8:4d4e with SMTP id z71-20020a4a494a000000b00525b0c84d4emr8879573ooa.0.1680058559923;
        Tue, 28 Mar 2023 19:55:59 -0700 (PDT)
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id h7-20020a4ab447000000b00525240a102asi772196ooo.1.2023.03.28.19.55.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Mar 2023 19:55:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of qun-wei.lin@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 38e0de7ccddd11eda9a90f0bb45854f4-20230329
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.22,REQID:f8f468ce-6dc1-4c07-843e-5f8ba3681711,IP:0,U
	RL:0,TC:0,Content:-20,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTIO
	N:release,TS:-20
X-CID-META: VersionHash:120426c,CLOUDID:f602adb4-beed-4dfc-bd9c-e1b22fa6ccc4,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:102,TC:nil,Content:1,EDM:-3,IP:nil,U
	RL:11|1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-UUID: 38e0de7ccddd11eda9a90f0bb45854f4-20230329
Received: from mtkmbs11n2.mediatek.inc [(172.21.101.187)] by mailgw01.mediatek.com
	(envelope-from <qun-wei.lin@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1609519517; Wed, 29 Mar 2023 10:55:54 +0800
Received: from mtkmbs10n2.mediatek.inc (172.21.101.183) by
 mtkmbs13n2.mediatek.inc (172.21.101.108) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.25; Wed, 29 Mar 2023 10:55:53 +0800
Received: from APC01-PSA-obe.outbound.protection.outlook.com (172.21.101.239)
 by mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server id
 15.2.1118.25 via Frontend Transport; Wed, 29 Mar 2023 10:55:53 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=MVKOErt37BQNM9lBGfzAcW99kTZ2+AN8pKnasSnEW8/VD79PUJg+vXtHj5e0vWSSgrTqMVpGi+X2OixzCCtm3Udq5Hkr9AFF1ho94atPdkTy6YAL+yqq/PZiAQidcJ0IpA+Sa9R5ovOvEOj9cRQ/0fVH7qn7UttvDQD/1IU8vXb2phIxaVksMDvM5MG/TFdZ2Pa/j0RfQmhrAw5j7kQEKSApkmrhicNWF6ojZSUtfvfXksiNn5ojI2ecjevrdBM0umS6WLjfMBp86+axPDEAj23GPHHayyoPHFywqXL6YUSpdAwI2jlhDl8UcOo/LiFA9Kv91TEkFwJKp/UWr/8uVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=C2883PnuNPpCTsPs9t8wQt7THVcXcbjvh2GOL3JE5K4=;
 b=ErO3QqMaciq/oiEaKcLchYFkiNwIvG0tJNcG57RjuQLO5cKta8ZH2BFtVwNBZ9+1TN0eY6UoWeD0+EQCmp71rsZ59K/cmo5tDaWEIQtbnFCiF8SoGpAbY2bBbxC9XoBkyflu5WvqszCEHPCDnq6P1Pt+6T+j+cBslrUwu+aJIe0hiOav20avaQ4JwLLuEju/M6j4DKa1VGHvVCJxShVHx0q7uNWoHQ0wFLpAoDa7eIDwnFZ6SChB9BUnGGECBApH8S7qAb1ESF/XQ+BpYMOUut5d4APBbVy6qqu7rzd07Gmz5xoqGcvI9/IoGnt+WsfeSCY9FyLK+jyKMkuauOdGWg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=mediatek.com; dmarc=pass action=none header.from=mediatek.com;
 dkim=pass header.d=mediatek.com; arc=none
Received: from PSAPR03MB5542.apcprd03.prod.outlook.com (2603:1096:301:4e::12)
 by PSAPR03MB5526.apcprd03.prod.outlook.com (2603:1096:301:92::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6222.35; Wed, 29 Mar
 2023 02:55:50 +0000
Received: from PSAPR03MB5542.apcprd03.prod.outlook.com
 ([fe80::4e8a:b69:30c5:9cf5]) by PSAPR03MB5542.apcprd03.prod.outlook.com
 ([fe80::4e8a:b69:30c5:9cf5%4]) with mapi id 15.20.6222.034; Wed, 29 Mar 2023
 02:55:50 +0000
From: =?UTF-8?B?J1F1bi13ZWkgTGluICjmnpfnvqTltLQpJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "linux-mm@kvack.org"
	<linux-mm@kvack.org>
CC: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"surenb@google.com" <surenb@google.com>, "david@redhat.com"
	<david@redhat.com>, =?utf-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
	<chinwen.chang@mediatek.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>,
	=?utf-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
	<Kuan-Ying.Lee@mediatek.com>, =?utf-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?=
	<casper.li@mediatek.com>, "catalin.marinas@arm.com"
	<catalin.marinas@arm.com>, "gregkh@linuxfoundation.org"
	<gregkh@linuxfoundation.org>
Subject: [BUG] Usersapce MTE error with allocation tag 0 when low on memory
Thread-Topic: [BUG] Usersapce MTE error with allocation tag 0 when low on
 memory
Thread-Index: AQHZYen3s5qS35hNike4zSKmU9bvyQ==
Date: Wed, 29 Mar 2023 02:55:49 +0000
Message-ID: <5050805753ac469e8d727c797c2218a9d780d434.camel@mediatek.com>
Accept-Language: zh-TW, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PSAPR03MB5542:EE_|PSAPR03MB5526:EE_
x-ms-office365-filtering-correlation-id: 8fa764cd-2032-4d50-c7c1-08db30011a74
x-ld-processed: a7687ede-7a6b-4ef6-bace-642f677fbe31,ExtAddr
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 8RMoye2HNdHoo3TbC4UDLCrr5zAtANZ+gDTc1bYgzgoLquvY1fNbwjOUCbDQRSjf1qloHKJ0mE9qFnQZy0sDlFSlOjbMYk1Nc/jCuQ8tbvWAwJc068I2wCf+kN2n2UsqB7BOEotlxdgsj+T2/jfeBvDe9sXJm57lIw3Wxv1UZwgdGA9kFakblrZUFmSVGeXharPbWoLIGQ+QDe3PYxoaeG6+Lpl6wRqaZKeIJ7Zu1W9zpIGO4NiT19KJS4PzFINpfjpzoSUV3Ij6JcBb5GSQYY9XzdNeFJdB90eZAoxenYHBTLe2IVP/IUE0KDJGNbEOAxuPQJBeiBIQMozUAuxqUA4XQvasJbzdn8B/1nGliQHa02kLgPivfUwbvBsPeIBIAeVWDGu86IindHlj9dPXevpCjp03qEMM1VyVP6EPsiHqXzQpC8qseIK5GacQ+rl4euByKWO4UQhTYyWkSrDQqT73qYbgKz7KDjn2L3OHv2A688v/r9qLCYbaBlTgcga+F5sZOgDTukE6vFXUtslToRh2JeiC0QrBCOv5yPWlLz4tigNFcJ6KsCC4PiAG8ehZW67Er1xMlLAQVL22D6DsJucOAE92lnBSog0rYSR7fKA=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PSAPR03MB5542.apcprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230028)(4636009)(376002)(366004)(136003)(396003)(39860400002)(346002)(451199021)(5660300002)(41300700001)(66446008)(66476007)(66556008)(64756008)(4326008)(66946007)(8676002)(91956017)(76116006)(8936002)(6486002)(54906003)(110136005)(316002)(2906002)(38100700002)(85182001)(36756003)(966005)(478600001)(71200400001)(83380400001)(186003)(86362001)(38070700005)(2616005)(26005)(6506007)(6512007)(122000001);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?K1V1dmR4ZFJSakFnSEhNbUcwNVJVWmljMjVoOTNFOFpRZXlHY05leWJzdFp4?=
 =?utf-8?B?WjYvUjRsOTNGNW01ME5mKzhnbVRSdTRlVmdVejV3VW9RdCtBZlo1dDUxQ0Ux?=
 =?utf-8?B?VDBZRTI0eGJyTlRXNGZHSmJLWWFuWGRZdnZiTVBUbzhzWjRwTEdkbWNBd29l?=
 =?utf-8?B?V0FBVFVTcDN0ck1FUkszckJ2N05HemR6dnczQlNzTUhiSmpQWk4xMHFSSEx3?=
 =?utf-8?B?T00xYzZFMnplQkFsVERHVlQ4Tklnb1JpbzVUM1JNUlFkdzBjWld3aFBvbEZ2?=
 =?utf-8?B?NUFNM0hBRGpTaTh4SVhUT3FzT1R6a09Ca1cyMmtCbmloVHl6RGNWQUJDRGUr?=
 =?utf-8?B?NCtsclFmV3J6RHRWZ0ZmSlFtU08yTHgvc2RMeTNCUHdTT1I0SUVYUG52VWFJ?=
 =?utf-8?B?VUk0YytCdVRQc3RZK09nbE5kMVRCV01PYzRCSXZPYjdtK0dLQUY3VkxtSWxB?=
 =?utf-8?B?UVNCRmpTSFFUeVdKclNPOGpnQlZBS3h3UGdXY3ZlaGlyM25Dd0h2ZnNzVU5k?=
 =?utf-8?B?RlVqYlZETXE0eXVQaWdpS1BHNnJiOEF2Q2hFM3N2cDRLcWRwRnNxamlLL1FQ?=
 =?utf-8?B?ZFVYUWFiYlo5MEJ4RXdwSTR3OU5iNFJ2UkVJeC9MRjZkVmdmTlVjQStibWJL?=
 =?utf-8?B?azE5aEx4b29vTzNyMFFXTmQ1VnRRbk1hSFBZOEhZWXZiNFhEdWdDNGIvTUpM?=
 =?utf-8?B?UVBPYk10RjUxYmZVTFg3WmVvdmVXaXI4Z013SmlpaC9ldTR3Yy9tYy9NL0Vv?=
 =?utf-8?B?cEhZeEREQkdBUWp1cWVCcFNxb0E4ZGdGQzdZK3lwc3ZpcVIwcFFDaWxZUUNi?=
 =?utf-8?B?bkgrdUJLMjNzZC9EMlFFZFk4VEl3Zi96VXM2VkZZSERDOHRsTVBLZVlRWHdJ?=
 =?utf-8?B?akRMOTZmK2JZekR4T2s2WnJoYW5tMkwxLytvVlF2Q0l4NkUxM2ZWMUYxa3dN?=
 =?utf-8?B?YnFZUzlnancwb3RDN1JTK2duNU4xZTBkV0JMTzRoQ0FINyszV0EvTUZ1aFVr?=
 =?utf-8?B?TERuZ2dOY1NVTDYyNkFVSFkvemIyUy9aVDJYU0NWbloxcWlIbmZSUGc5RUN0?=
 =?utf-8?B?eGZ3WHZiWnRreXcrUkx0cnVUOU1xR2RiMTIza2UyOFFja3hCNUlPZHYrMFhv?=
 =?utf-8?B?SVBJWDI2Wk5xNGxJcHNHcG42SCtVSnhiQXdpODR3TDA2RFFVUHd2TEVxbXQ5?=
 =?utf-8?B?TVdrWnVPWDZSQzlickRqOXRzR3VTVmNCbWlmNnFJNHlGUHFqL2JXQ0hJLzNU?=
 =?utf-8?B?TlVDTEhUYjVia1dBOGZoMHBIWjMwQWIxTy9TTkZES29ZRkZxdS96ZGs0S0Fh?=
 =?utf-8?B?SXE2UDJCbDlPWXdUUzQ0WDFMczhZUzJGZmo2ZFpyZVJHekJmbGRpaW1xak9L?=
 =?utf-8?B?QmYzL1dIVk1jZzcveXlDUlBWMTI1S094TlQvckpJRXIzTGdFZnBVRm1iTkNt?=
 =?utf-8?B?UFBaWjFDVDVXb1Q0T1hDakZMZDlraGpNRTFFNE5wcGVEMGUzUWQ1YWJGZ2ll?=
 =?utf-8?B?dWxyRHZwVWVLSlFsQU8yQmVYSlZIRkE4cUxwWVJuVkxQOXV4TWZGMUNseXV6?=
 =?utf-8?B?Sk05Ukk0cWhKWGkwRkVLZjlML1hBdlQvdDAwOWVvQTk3VTJZcUd6L0EzWEVN?=
 =?utf-8?B?YXI0dWVGeG50d0FFY0ZlTXNhWmVrYWpwOGZvRnptSGhRMjk3eVVlSjk4L0xz?=
 =?utf-8?B?K3ZxVld2bDdwcmI4NWViaWxuV3JtTi81RzltckxMcnZHa2hmaFlpQUhqV2dF?=
 =?utf-8?B?dXJsK1J6Z1lveXpVMTdZeFQ1aWE5bHZKcXhEeWdJNGpXNlR4c1ZEMVZJTWpT?=
 =?utf-8?B?MDlYVXpDS0JFSzlKSklSajlLdWsyZExjMGRuaWxwaithUStKblhRUlVYcjRy?=
 =?utf-8?B?ZlZZUWFqRmlZUlJzNXFJTk51VWl0bEJDTEcwdEJzSFh3bGZuTjdMb0Y4MEt3?=
 =?utf-8?B?Tyt6eDIyWUgrWkRSWjl3WFNxRFZYY1FJN1VFaXN0Q1JTSWRwU003UGJ3QkRW?=
 =?utf-8?B?Q25QS0kxOHJLSDFLUzIzdHFZN3RQMENMNi92QjhBZ1RicVlrelFNQTVMTHRi?=
 =?utf-8?B?bTlGTXBzLytPeU9GV2tIdnEzTDRKOHN3aEkzd3VLOU9PWWlrWlFRYlk5VVZ2?=
 =?utf-8?B?a3RRem5DWDVZYUE0c0xuaElUc1pIblo5bHdZWFp5cjc5L1hLS29UT2hROTUz?=
 =?utf-8?B?bFE9PQ==?=
Content-ID: <1871495C4C0AC842800F4BA76501EDE5@apcprd03.prod.outlook.com>
Content-Transfer-Encoding: base64
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PSAPR03MB5542.apcprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 8fa764cd-2032-4d50-c7c1-08db30011a74
X-MS-Exchange-CrossTenant-originalarrivaltime: 29 Mar 2023 02:55:49.9718
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: a7687ede-7a6b-4ef6-bace-642f677fbe31
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: vnJPk6L4ikuldB/a261Y6+PoSQu9pMCrX/9PforaLernbFYp6vhKLCw00K3+TC5bZ8Pmrv4Ixd0dMU2c6ZZsYYhLUdwBNRGIf+6pCpYn81E=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PSAPR03MB5526
Content-Type: multipart/alternative;
	boundary="__=_Part_Boundary_004_2090201843.1939580327"
X-Original-Sender: qun-wei.lin@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=GSwZvRNC;       dkim=neutral
 (body hash did not verify) header.i=@mediateko365.onmicrosoft.com
 header.s=selector2-mediateko365-onmicrosoft-com header.b=JoYL0ICG;
       arc=fail (body hash mismatch);       spf=pass (google.com: domain of
 qun-wei.lin@mediatek.com designates 60.244.123.138 as permitted sender)
 smtp.mailfrom=qun-wei.lin@mediatek.com;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: =?utf-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>
Reply-To: =?utf-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>
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

--__=_Part_Boundary_004_2090201843.1939580327
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<pre>
Hi,

We&#32;meet&#32;the&#32;mass&#32;MTE&#32;errors&#32;happened&#32;in&#32;And=
roid&#32;T&#32;with&#32;kernel-6.1.

When&#32;the&#32;system&#32;is&#32;under&#32;memory&#32;pressure,&#32;the&#=
32;MTE&#32;often&#32;triggers&#32;some
error&#32;reporting&#32;in&#32;userspace.

Like&#32;the&#32;tombstone&#32;below,&#32;there&#32;are&#32;many&#32;report=
s&#32;with&#32;the&#32;acllocation
tags&#32;of&#32;0:

Build&#32;fingerprint:
&#39;alps/vext_k6897v1_64/k6897v1_64:13/TP1A.220624.014/mp2ofp23:userdebug/
dev-keys&#39;
Revision:&#32;&#39;0&#39;
ABI:&#32;&#39;arm64&#39;
Timestamp:&#32;2023-03-14&#32;06:39:40.344251744+0800
Process&#32;uptime:&#32;0s
Cmdline:&#32;/vendor/bin/hw/camerahalserver
pid:&#32;988,&#32;tid:&#32;1395,&#32;name:&#32;binder:988_3&#32;&#32;&gt;&g=
t;&gt;
/vendor/bin/hw/camerahalserver&#32;&lt;&lt;&lt;
uid:&#32;1047
tagged_addr_ctrl:&#32;000000000007fff3&#32;(PR_TAGGED_ADDR_ENABLE,
PR_MTE_TCF_SYNC,&#32;mask&#32;0xfffe)
signal&#32;11&#32;(SIGSEGV),&#32;code&#32;9&#32;(SEGV_MTESERR),&#32;fault&#=
32;addr
0x0d000075f1d8d7f0
&#32;&#32;&#32;&#32;x0&#32;&#32;00000075018d3fb0&#32;&#32;x1&#32;&#32;00000=
000c0306201&#32;&#32;x2&#32;&#32;00000075018d3ae8&#32;&#32;x
3&#32;&#32;000000000000720c
&#32;&#32;&#32;&#32;x4&#32;&#32;0000000000000000&#32;&#32;x5&#32;&#32;00000=
00000000000&#32;&#32;x6&#32;&#32;00000642000004fe&#32;&#32;x
7&#32;&#32;0000054600000630
&#32;&#32;&#32;&#32;x8&#32;&#32;00000000fffffff2&#32;&#32;x9&#32;&#32;b34a1=
094e7e33c3f&#32;&#32;x10
00000075018d3a80&#32;&#32;x11&#32;00000075018d3a50
&#32;&#32;&#32;&#32;x12&#32;ffffff80ffffffd0&#32;&#32;x13&#32;0000061e00000=
72c&#32;&#32;x14
0000000000000004&#32;&#32;x15&#32;0000000000000000
&#32;&#32;&#32;&#32;x16&#32;00000077f2dfcd78&#32;&#32;x17&#32;00000077da3a8=
ff0&#32;&#32;x18
00000075011bc000&#32;&#32;x19&#32;0d000075f1d8d898
&#32;&#32;&#32;&#32;x20&#32;0d000075f1d8d7f0&#32;&#32;x21&#32;0d000075f1d8d=
910&#32;&#32;x22
0000000000000000&#32;&#32;x23&#32;00000000fffffff7
&#32;&#32;&#32;&#32;x24&#32;00000075018d4000&#32;&#32;x25&#32;0000000000000=
000&#32;&#32;x26
00000075018d3ff8&#32;&#32;x27&#32;00000000000fc000
&#32;&#32;&#32;&#32;x28&#32;00000000000fe000&#32;&#32;x29&#32;00000075018d3=
b20
&#32;&#32;&#32;&#32;lr&#32;&#32;00000077f2d9f164&#32;&#32;sp&#32;&#32;00000=
075018d3ad0&#32;&#32;pc&#32;&#32;00000077f2d9f134&#32;&#32;p
st&#32;0000000080001000

backtrace:
&#32;&#32;&#32;&#32;&#32;&#32;#00&#32;pc&#32;000000000005d134&#32;&#32;/sys=
tem/lib64/libbinder.so
(android::IPCThreadState::talkWithDriver(bool)+244)&#32;(BuildId:
8b5612259e4a42521c430456ec5939c7)
&#32;&#32;&#32;&#32;&#32;&#32;#01&#32;pc&#32;000000000005d448&#32;&#32;/sys=
tem/lib64/libbinder.so
(android::IPCThreadState::getAndExecuteCommand()+24)&#32;(BuildId:
8b5612259e4a42521c430456ec5939c7)
&#32;&#32;&#32;&#32;&#32;&#32;#02&#32;pc&#32;000000000005dd64&#32;&#32;/sys=
tem/lib64/libbinder.so
(android::IPCThreadState::joinThreadPool(bool)+68)&#32;(BuildId:
8b5612259e4a42521c430456ec5939c7)
&#32;&#32;&#32;&#32;&#32;&#32;#03&#32;pc&#32;000000000008dba8&#32;&#32;/sys=
tem/lib64/libbinder.so
(android::PoolThread::threadLoop()+24)&#32;(BuildId:
8b5612259e4a42521c430456ec5939c7)
&#32;&#32;&#32;&#32;&#32;&#32;#04&#32;pc&#32;0000000000013440&#32;&#32;/sys=
tem/lib64/libutils.so
(android::Thread::_threadLoop(void*)+416)&#32;(BuildId:
10aac5d4a671e4110bc00c9b69d83d8a)
&#32;&#32;&#32;&#32;&#32;&#32;#05&#32;pc
00000000000c14cc&#32;&#32;/apex/com.android.runtime/lib64/bionic/libc.so
(__pthread_start(void*)+204)&#32;(BuildId:
718ecc04753b519b0f6289a7a2fcf117)
&#32;&#32;&#32;&#32;&#32;&#32;#06&#32;pc
0000000000054930&#32;&#32;/apex/com.android.runtime/lib64/bionic/libc.so
(__start_thread+64)&#32;(BuildId:&#32;718ecc04753b519b0f6289a7a2fcf117)

Memory&#32;tags&#32;around&#32;the&#32;fault&#32;address&#32;(0xd000075f1d8=
d7f0),&#32;one&#32;tag&#32;per
16&#32;bytes:
&#32;&#32;&#32;&#32;&#32;&#32;0x75f1d8cf00:&#32;0&#32;&#32;0&#32;&#32;0&#32=
;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#=
32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0
&#32;&#32;&#32;&#32;&#32;&#32;0x75f1d8d000:&#32;0&#32;&#32;0&#32;&#32;0&#32=
;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#=
32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0
&#32;&#32;&#32;&#32;&#32;&#32;0x75f1d8d100:&#32;0&#32;&#32;0&#32;&#32;0&#32=
;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#=
32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0
&#32;&#32;&#32;&#32;&#32;&#32;0x75f1d8d200:&#32;0&#32;&#32;0&#32;&#32;0&#32=
;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#=
32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0
&#32;&#32;&#32;&#32;&#32;&#32;0x75f1d8d300:&#32;0&#32;&#32;0&#32;&#32;0&#32=
;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#=
32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0
&#32;&#32;&#32;&#32;&#32;&#32;0x75f1d8d400:&#32;0&#32;&#32;0&#32;&#32;0&#32=
;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#=
32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0
&#32;&#32;&#32;&#32;&#32;&#32;0x75f1d8d500:&#32;0&#32;&#32;0&#32;&#32;0&#32=
;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#=
32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0
&#32;&#32;&#32;&#32;&#32;&#32;0x75f1d8d600:&#32;0&#32;&#32;0&#32;&#32;0&#32=
;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#=
32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0
&#32;&#32;&#32;&#32;=3D&gt;0x75f1d8d700:&#32;0&#32;&#32;0&#32;&#32;0&#32;&#=
32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;=
&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;[0]
&#32;&#32;&#32;&#32;&#32;&#32;0x75f1d8d800:&#32;0&#32;&#32;0&#32;&#32;0&#32=
;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#=
32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0
&#32;&#32;&#32;&#32;&#32;&#32;0x75f1d8d900:&#32;0&#32;&#32;0&#32;&#32;0&#32=
;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#=
32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0
&#32;&#32;&#32;&#32;&#32;&#32;0x75f1d8da00:&#32;0&#32;&#32;0&#32;&#32;0&#32=
;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#=
32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0
&#32;&#32;&#32;&#32;&#32;&#32;0x75f1d8db00:&#32;0&#32;&#32;0&#32;&#32;0&#32=
;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#=
32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0
&#32;&#32;&#32;&#32;&#32;&#32;0x75f1d8dc00:&#32;0&#32;&#32;0&#32;&#32;0&#32=
;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#=
32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0
&#32;&#32;&#32;&#32;&#32;&#32;0x75f1d8dd00:&#32;0&#32;&#32;0&#32;&#32;0&#32=
;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#=
32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0
&#32;&#32;&#32;&#32;&#32;&#32;0x75f1d8de00:&#32;0&#32;&#32;0&#32;&#32;0&#32=
;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#=
32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0&#32;&#32;0

Also&#32;happens&#32;in&#32;coredump.

This&#32;problem&#32;only&#32;occurs&#32;when&#32;ZRAM&#32;is&#32;enabled,&=
#32;so&#32;we&#32;think&#32;there&#32;are
some&#32;issues&#32;regarding&#32;swap&#32;in/out.

Having&#32;compared&#32;the&#32;differences&#32;between&#32;Kernel-5.15&#32=
;and&#32;Kernel-6.1,
We&#32;found&#32;the&#32;order&#32;of&#32;swap_free()&#32;and&#32;set_pte_a=
t()&#32;is&#32;changed&#32;in
do_swap_page().

When&#32;fault&#32;in,&#32;do_swap_page()&#32;will&#32;call&#32;swap_free()=
&#32;first:
do_swap_page()&#32;-&gt;&#32;swap_free()&#32;-&gt;&#32;__swap_entry_free()&=
#32;-&gt;
free_swap_slot()&#32;-&gt;&#32;swapcache_free_entries()&#32;-&gt;&#32;swap_=
entry_free()&#32;-&gt;
swap_range_free()&#32;-&gt;&#32;arch_swap_invalidate_page()&#32;-&gt;
mte_invalidate_tags_area()&#32;-&gt;&#32;&#32;mte_invalidate_tags()&#32;-&g=
t;&#32;xa_erase()

and&#32;then&#32;call&#32;set_pte_at():
do_swap_page()&#32;-&gt;&#32;set_pte_at()&#32;-&gt;&#32;__set_pte_at()&#32;=
-&gt;&#32;mte_sync_tags()&#32;-&gt;
mte_sync_page_tags()&#32;-&gt;&#32;mte_restore_tags()&#32;-&gt;&#32;xa_load=
()

This&#32;means&#32;that&#32;the&#32;swap&#32;slot&#32;is&#32;invalidated&#3=
2;before&#32;pte&#32;mapping,&#32;and
this&#32;will&#32;cause&#32;the&#32;mte&#32;tag&#32;in&#32;XArray&#32;to&#3=
2;be&#32;released&#32;before&#32;tag
restore.

After&#32;I&#32;moved&#32;swap_free()&#32;to&#32;the&#32;next&#32;line&#32;=
of&#32;set_pte_at(),&#32;the&#32;problem
is&#32;disappeared.

We&#32;suspect&#32;that&#32;the&#32;following&#32;patches,&#32;which&#32;ha=
ve&#32;changed&#32;the&#32;order,&#32;do
not&#32;consider&#32;the&#32;mte&#32;tag&#32;restoring&#32;in&#32;page&#32;=
fault&#32;flow:
https://lore.kernel.org/all/20220131162940.210846-5-david@redhat.com/

Any&#32;suggestion&#32;is&#32;appreciated.

Thank&#32;you.

</pre><!--type:text--><!--{--><pre>************* MEDIATEK Confidentiality N=
otice ********************
The information contained in this e-mail message (including any=20
attachments) may be confidential, proprietary, privileged, or otherwise
exempt from disclosure under applicable laws. It is intended to be=20
conveyed only to the designated recipient(s). Any use, dissemination,=20
distribution, printing, retaining or copying of this e-mail (including its=
=20
attachments) by unintended recipient(s) is strictly prohibited and may=20
be unlawful. If you are not an intended recipient of this e-mail, or believ=
e=20
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
om/d/msgid/kasan-dev/5050805753ac469e8d727c797c2218a9d780d434.camel%40media=
tek.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/5050805753ac469e8d727c797c2218a9d780d434.camel%40mediatek.=
com</a>.<br />

--__=_Part_Boundary_004_2090201843.1939580327
Content-Type: text/plain; charset="UTF-8"

Hi,

We meet the mass MTE errors happened in Android T with kernel-6.1.

When the system is under memory pressure, the MTE often triggers some
error reporting in userspace.

Like the tombstone below, there are many reports with the acllocation
tags of 0:

Build fingerprint:
'alps/vext_k6897v1_64/k6897v1_64:13/TP1A.220624.014/mp2ofp23:userdebug/
dev-keys'
Revision: '0'
ABI: 'arm64'
Timestamp: 2023-03-14 06:39:40.344251744+0800
Process uptime: 0s
Cmdline: /vendor/bin/hw/camerahalserver
pid: 988, tid: 1395, name: binder:988_3  >>>
/vendor/bin/hw/camerahalserver <<<
uid: 1047
tagged_addr_ctrl: 000000000007fff3 (PR_TAGGED_ADDR_ENABLE,
PR_MTE_TCF_SYNC, mask 0xfffe)
signal 11 (SIGSEGV), code 9 (SEGV_MTESERR), fault addr
0x0d000075f1d8d7f0
    x0  00000075018d3fb0  x1  00000000c0306201  x2  00000075018d3ae8  x
3  000000000000720c
    x4  0000000000000000  x5  0000000000000000  x6  00000642000004fe  x
7  0000054600000630
    x8  00000000fffffff2  x9  b34a1094e7e33c3f  x10
00000075018d3a80  x11 00000075018d3a50
    x12 ffffff80ffffffd0  x13 0000061e0000072c  x14
0000000000000004  x15 0000000000000000
    x16 00000077f2dfcd78  x17 00000077da3a8ff0  x18
00000075011bc000  x19 0d000075f1d8d898
    x20 0d000075f1d8d7f0  x21 0d000075f1d8d910  x22
0000000000000000  x23 00000000fffffff7
    x24 00000075018d4000  x25 0000000000000000  x26
00000075018d3ff8  x27 00000000000fc000
    x28 00000000000fe000  x29 00000075018d3b20
    lr  00000077f2d9f164  sp  00000075018d3ad0  pc  00000077f2d9f134  p
st 0000000080001000

backtrace:
      #00 pc 000000000005d134  /system/lib64/libbinder.so
(android::IPCThreadState::talkWithDriver(bool)+244) (BuildId:
8b5612259e4a42521c430456ec5939c7)
      #01 pc 000000000005d448  /system/lib64/libbinder.so
(android::IPCThreadState::getAndExecuteCommand()+24) (BuildId:
8b5612259e4a42521c430456ec5939c7)
      #02 pc 000000000005dd64  /system/lib64/libbinder.so
(android::IPCThreadState::joinThreadPool(bool)+68) (BuildId:
8b5612259e4a42521c430456ec5939c7)
      #03 pc 000000000008dba8  /system/lib64/libbinder.so
(android::PoolThread::threadLoop()+24) (BuildId:
8b5612259e4a42521c430456ec5939c7)
      #04 pc 0000000000013440  /system/lib64/libutils.so
(android::Thread::_threadLoop(void*)+416) (BuildId:
10aac5d4a671e4110bc00c9b69d83d8a)
      #05 pc
00000000000c14cc  /apex/com.android.runtime/lib64/bionic/libc.so
(__pthread_start(void*)+204) (BuildId:
718ecc04753b519b0f6289a7a2fcf117)
      #06 pc
0000000000054930  /apex/com.android.runtime/lib64/bionic/libc.so
(__start_thread+64) (BuildId: 718ecc04753b519b0f6289a7a2fcf117)

Memory tags around the fault address (0xd000075f1d8d7f0), one tag per
16 bytes:
      0x75f1d8cf00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
      0x75f1d8d000: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
      0x75f1d8d100: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
      0x75f1d8d200: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
      0x75f1d8d300: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
      0x75f1d8d400: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
      0x75f1d8d500: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
      0x75f1d8d600: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
    =>0x75f1d8d700: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0 [0]
      0x75f1d8d800: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
      0x75f1d8d900: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
      0x75f1d8da00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
      0x75f1d8db00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
      0x75f1d8dc00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
      0x75f1d8dd00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
      0x75f1d8de00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0

Also happens in coredump.

This problem only occurs when ZRAM is enabled, so we think there are
some issues regarding swap in/out.

Having compared the differences between Kernel-5.15 and Kernel-6.1,
We found the order of swap_free() and set_pte_at() is changed in
do_swap_page().

When fault in, do_swap_page() will call swap_free() first:
do_swap_page() -> swap_free() -> __swap_entry_free() ->
free_swap_slot() -> swapcache_free_entries() -> swap_entry_free() ->
swap_range_free() -> arch_swap_invalidate_page() ->
mte_invalidate_tags_area() ->  mte_invalidate_tags() -> xa_erase()

and then call set_pte_at():
do_swap_page() -> set_pte_at() -> __set_pte_at() -> mte_sync_tags() ->
mte_sync_page_tags() -> mte_restore_tags() -> xa_load()

This means that the swap slot is invalidated before pte mapping, and
this will cause the mte tag in XArray to be released before tag
restore.

After I moved swap_free() to the next line of set_pte_at(), the problem
is disappeared.

We suspect that the following patches, which have changed the order, do
not consider the mte tag restoring in page fault flow:
https://lore.kernel.org/all/20220131162940.210846-5-david@redhat.com/

Any suggestion is appreciated.

Thank you.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5050805753ac469e8d727c797c2218a9d780d434.camel%40mediatek.com.

--__=_Part_Boundary_004_2090201843.1939580327--

