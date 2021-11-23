Return-Path: <kasan-dev+bncBCLMXXWM5YBBB3N26GGAMGQEH32JPFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 146BA459A6E
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Nov 2021 04:18:06 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id j25-20020a05600c1c1900b00332372c252dsf799653wms.1
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Nov 2021 19:18:06 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1637637485; cv=pass;
        d=google.com; s=arc-20160816;
        b=Aq7eDJBShfsPmzHQkBz+iGJbA2VyuTCfH+gvOeSmjMooXiMOPdpZfpqQo5L6a93/fN
         TDprl6IDxM1QshgqsaD7Hbw/+PdUWLm4z8woq9+LIvie1UmfZjDpynbdwK+Poc2Yf/Hf
         +kDhnt9HfeKdO/oe01p6hMhTEVRmvIf+0d2045ECfLFEtGSRKpjaBiBHEIn0FX47dZe9
         modiSFCxLZ/zankInUG6b2rk/oFubkhj9FHsK+rnFSRhfgIIdyzbizblIA1lCSh88hXB
         Z6JoQYbhPfPt9j9CDI6DwM239/diDHkZP3K7/25/gwSeZFpQ8BF6kj6Wv5aO2gFbo8Mo
         Qfjg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=YLWCzp9pip+rVTVMWTI2IwH/y1nJNqGunyA7Gx7CMjo=;
        b=QurITXqKTo/PjwuGZ/GuZZrqHdSBTCo95myGR7hl7UtoVmKyeZmtDx62Bg25863Qfw
         ctGZaMG0YByCYVYd3Hk4mh90hu3ECOvtrQdIegmK/M6gi8ilwSMSx58FfIrP9FpknGau
         ceVkkAtdI8aEAC6Mvg4uF2eGWg1FvcSK8hTWETNMbf7aJBEQVGB+5mIRuaR0q20mMHJb
         w094LQRaFXqYtFBnqFpk69nAKSVGuAjaQg7XahFX6UgkamansI4vlykYSjd0K5ntWKC3
         HO4V23Ulx/mR2GOTL/1CewrLFje5EwjNtT7/HqjHsGdNSMiQdW0TtSMaPMdt6pZ7+vG6
         rdEA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qccesdkim1 header.b=NmuVer7n;
       arc=pass (i=1 spf=pass spfdomain=quicinc.com dkim=pass dkdomain=quicinc.com dmarc=pass fromdomain=quicinc.com);
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 216.71.140.77 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YLWCzp9pip+rVTVMWTI2IwH/y1nJNqGunyA7Gx7CMjo=;
        b=jJU6RGNOnBL5jg/PPDTaRO2TwLuyDQLmN4JBVQpOa2shLP2InrzJIGzh81Nj6/qeZ4
         foxFu2CNarxVzlexUxJqWQGgsYhf430GHUfv9mDoDbqfQ1o2Uhxu2lOY/T7adqlselG8
         L1nv6NpeQc0pIxEM9xdHqpVQoi2HZWJNaPANMPPivCa2eZMHS066+VRN5XCozYXoAvkW
         S6BZW1EX0FCu9IP7L+hBwpp55A4WHaroDK6PQwALxB/eSFcmiWOFsgmcLQmz6LRE6NoK
         oWASVMvhBN5v/B6BwE4oxYoy1gYOJBNLGdED/HPrNKqORwW0uEaTibQwogH25QMyb4ay
         AqqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YLWCzp9pip+rVTVMWTI2IwH/y1nJNqGunyA7Gx7CMjo=;
        b=5R8lzos09q1EC/pQmPeWXXyR7fsWwtp0DJ6u1Nh2GraVMao4dpWqR36HCtN1uqxPKZ
         aW2sXkWxHI9ZydOQZQhUvnbwQb/xKgDmfRXYk4Qmi0HFLvbM8WPh4DupDPS79lfuK+zB
         TeCl4Qo3URuBXESHzrwdbFUJOk86RTXpn4lzi/oXGABqoyL99yk35p2KeoqGC9s8m1ae
         CkKG/zok+xfGchQ+duzGUsNEhUga/Fol4b9I0qRFh6QOx43Zs1jbUswN2fILCCoR+1TV
         4Loy5q6JIyyVJSttVmrS53oYsnbTFaVzIbyiyWcU4m1I5XA+ayV/wo25BHYZRVk8RTi7
         qpUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533F53TZI+lr0VZmd7iu/9d3dS5pUyDH6666dWzbZICfcfnz4l4L
	L7FcFGB99flWwbQJ6Gkgc1g=
X-Google-Smtp-Source: ABdhPJzZMKY4/k06mwFMdia/YHCJH41U4rmMtG6XSlUnJnrNM+Ofrh2l6R8KmkA/4ihjUX+73Bz1vw==
X-Received: by 2002:a1c:9dc7:: with SMTP id g190mr2954244wme.130.1637637485804;
        Mon, 22 Nov 2021 19:18:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:416:: with SMTP id 22ls12168792wme.0.canary-gmail; Mon,
 22 Nov 2021 19:18:04 -0800 (PST)
X-Received: by 2002:a7b:c756:: with SMTP id w22mr3046098wmk.34.1637637484860;
        Mon, 22 Nov 2021 19:18:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637637484; cv=pass;
        d=google.com; s=arc-20160816;
        b=WwVwizfTOWJcwRCZYZq40m7O2i5DulRYmJRZULO1EhWiFrWipEEoppzW5jAtw8XNJr
         nYf30a3OV7dHj/0eGHpp2j+pAVcJi8YRdnhvpR6E4ZAggCt0DFKeuIxsQsDyk8xbZQsd
         iSzOSFKv2aFEupRLPrGcMP4F8NQ53gLa3Z1WEI2HWzmGXTwEjB/1h6gzOQLcToUcOLEy
         a8lVaR7R8GReeFMFNGCba+fyd6h/JCGI6aUH66wFrWXHaAm9mvp3M1nwGl2gHbiFp25n
         vpCTUsyXGI1KRCPJTL7LHa9pwlMkxmRK/DGAwPYvNFm/hH3Mr7ksWngKXk8d9fYfPXj+
         kEAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=YyGNWRsS5B922rHSr4/4OE41VHmDjsX0GzYlikHOwn4=;
        b=pvuasDYM39QoayorCWG8U0jJAXMxDDreH53F9JDqTYCvpnBZO5RZejv2nwp06ufmh2
         Mlz72vXjXz73npWgcI7kovBCukrjqknRS03GKefcUte3djgdV0BW2CFHrqTHPsiGVvx9
         TQElhYFAfUzncDSZwoYwIlPhGBNDY8gcZVBCP8RW5TQSJ8P3tOsHc0d01YAjOk6yJBxh
         MyVE4DPLhd/fPLUQfS+Ct2GbjSaatAaKkbHmTFEyGfQ0gUvDkedktvKoccXq8vW5VWQw
         kzx3UvywUf8cF7t8Ugg5cSt/zX+TpAREmi2PSNDOt8JYTb+hPwb8gaIsvvHcJFpMU51Y
         nMHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qccesdkim1 header.b=NmuVer7n;
       arc=pass (i=1 spf=pass spfdomain=quicinc.com dkim=pass dkdomain=quicinc.com dmarc=pass fromdomain=quicinc.com);
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 216.71.140.77 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from esa.hc3962-90.iphmx.com (esa.hc3962-90.iphmx.com. [216.71.140.77])
        by gmr-mx.google.com with ESMTPS id s138si45246wme.1.2021.11.22.19.18.03
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Nov 2021 19:18:04 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 216.71.140.77 as permitted sender) client-ip=216.71.140.77;
Received: from mail-mw2nam12lp2045.outbound.protection.outlook.com (HELO NAM12-MW2-obe.outbound.protection.outlook.com) ([104.47.66.45])
  by ob1.hc3962-90.iphmx.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 23 Nov 2021 03:18:01 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Kas9YL/0YT/y5B6pu0f1/S5B5TK5PmLDid3N0vvcXZF464+DI1xgAoKuUN1rixFDk6M1yx5Xxy6S0w3Q1CQEGdG5bBnJARqVVQxsMtvRYW6c25T7jANjloIeYpUwnpJJavPhZaUM+ZLvHVuZ8Gmxa1niU5Kguc3twe1PsiJwMOlSnIswKq5a1ux/yREpd5Ij4kB5T/7QJ7MQPl9SWDzwMn2wCOpW3YGLkpnraw8VGzFi3WucVIwlszZ5EX29oi+GL80ppSPgPVdBlffoc4FZrrrtNiZq8vUuiylZue0xQf/M59FWY5QeHS1BSg1kC5SJTthtFkfsQDixXeOW1d/VMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=YyGNWRsS5B922rHSr4/4OE41VHmDjsX0GzYlikHOwn4=;
 b=iw+j7+F+HV/IMciOwkD/FGoBUZr6d5UeU4chMxjZ3bRLkq4HYduLQA3xCZxjuj3Dn2y3gxT0+rnRoJHc0k1V/YBDXxCXHoRH097rGf8R0zvlI5aFxNru5tSe9vUCWgmLsDnYi2ceVZLBEQpH7kpsMTZSeQzlEX8TJl7toyXyzWmecbKEYkHoIutyt8jwgjUichg9Ky9kJSslwW6kkwQvBI/XuW4n9E4yPrsOR8H84H2IXXnHJ8qnojIGLqcjHc+ZgSx+VtXNQaAy3DNn1MFhnisfi1kaUQNWfHuCSdIx6hz+3bSmDFoyGABR70z1uM2PIdUNFP5MdZfXeyhyy6ot8g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=quicinc.com; dmarc=pass action=none header.from=quicinc.com;
 dkim=pass header.d=quicinc.com; arc=none
Received: from DM8PR02MB8247.namprd02.prod.outlook.com (2603:10b6:8:d::19) by
 DM6PR02MB5946.namprd02.prod.outlook.com (2603:10b6:5:154::22) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.4713.22; Tue, 23 Nov 2021 03:17:59 +0000
Received: from DM8PR02MB8247.namprd02.prod.outlook.com
 ([fe80::1584:d2b2:1ef7:6fb0]) by DM8PR02MB8247.namprd02.prod.outlook.com
 ([fe80::1584:d2b2:1ef7:6fb0%5]) with mapi id 15.20.4713.025; Tue, 23 Nov 2021
 03:17:59 +0000
From: "JianGen Jiao (QUIC)" <quic_jiangenj@quicinc.com>
To: "JianGen Jiao (QUIC)" <quic_jiangenj@quicinc.com>, Kaipeng Zeng
	<kaipeng94@gmail.com>, Dmitry Vyukov <dvyukov@google.com>
CC: syzkaller <syzkaller@googlegroups.com>, "andreyknvl@gmail.com"
	<andreyknvl@gmail.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, Alexander
 Lochmann <info@alexander-lochmann.de>, "Likai Ding (QUIC)"
	<quic_likaid@quicinc.com>, Hangbin Liu <liuhangbin@gmail.com>
Subject: RE: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
Thread-Topic: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
Thread-Index: AQHX23vD2nRqghWy5Eq5zUX4/l1PcKwJUjYAgAC3OuCAAKLFAIAAC+bwgAAaW4CAAANPgIAED+WAgAAEWYCAAZBvUA==
Date: Tue, 23 Nov 2021 03:17:58 +0000
Message-ID: <DM8PR02MB82473E366FA560E2FF214EF8F8609@DM8PR02MB8247.namprd02.prod.outlook.com>
References: <1637130234-57238-1-git-send-email-quic_jiangenj@quicinc.com>
 <CACT4Y+YwNawV9H7uFMVSCA5WB-Dkyu9TX+rMM3FR6gNGkKFPqw@mail.gmail.com>
 <DM8PR02MB8247720860A08914CAA41D42F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
 <CACT4Y+a07DxQdYFY6uc5Y4GhTUbcnETij6gg3y+JRDvtwSmK5g@mail.gmail.com>
 <DM8PR02MB8247A19843220E03B34BA440F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
 <CACT4Y+Y36wgP_xjYVQApNLdMOFTr2-KCHc=AipcZyZiAhwf1Nw@mail.gmail.com>
 <CACT4Y+YF4Ngm6em_Sn2p+N0x1L+O8A=BEVTNhd00LmSZ+aH1iQ@mail.gmail.com>
 <CAHk8ZdsPDDshy2EVtdGs=rjVOEWDctcNo2H+B5=d4GRcpQunog@mail.gmail.com>
 <062ffa8658124e089f17d73c2f523afb@quicinc.com>
In-Reply-To: <062ffa8658124e089f17d73c2f523afb@quicinc.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-messagesentrepresentingtype: 1
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 6a0255f2-2ddd-4cd3-4c63-08d9ae2fd9e6
x-ms-traffictypediagnostic: DM6PR02MB5946:
x-ld-processed: 98e9ba89-e1a1-4e38-9007-8bdabc25de1d,ExtAddr
x-microsoft-antispam-prvs: <DM6PR02MB5946A74ABE9DD46BBB9AA56F84609@DM6PR02MB5946.namprd02.prod.outlook.com>
x-ms-oob-tlc-oobclassifiers: OLM:9508;
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: qE9usOE/8OdAJiM7QZjHMXLMgn3T1ZG3b0Xt1yydqgyQ9sckaPrn1j3tPwaB1fjXxoxDLDiV+6BUU4crAvF2tpUmXj2EA0jXvKsuDFwAbo0dVa/cgPYaqxwzKE4KZuLwewq2XHRrjJTe23z+A8wuxIOK/xlSO5otyOuLb17XbJsu7PPAFVaNohMEIEUVkTW0b2EoExEedaZEfnYqmBjRHJ9O5PaT6DgJ0sJV9vtSL2DUsZgNYBsSxrzTbqXlxdohh1FpIoObMIKEcOeEYBPy8JhIyJArP8G6i9b9PTyvVO3hS7kfZUs7nb0ncXKCC89Lqm+einBGXbjvXGBFOPVTKsZS+QF4z/Dndfw+XQQ2BJ365ArZ56edmPKjOubZ2VbygTn3gwHWf+3Llm00X3euZCtOpoGmN48pjrQdI1UJTsDBRgRv1sdPBOIpqF83b8xCsKxeurXL0531GzRkg0jR11FwxUDrtaFYOelKvt9tBo4nd4zykOvpz1GePEEvVQ5CmoUnOKZVPTgeYpd5UPgnipRQIXicLqIf5WhQrd1q+gIMPewPTaFi0yAI30LmrBVXS9oELHBiEEB22x2JUFaDdq3RNASwHmrkYV4fZCTMIsiVY5moG/H0QKdBTyGJ7X5qxG5S3wj3MekPLfptw+PYwVpRC+c7wo7bOWIwsqTA7bUdZdZ+4UfoXAlTQz2UJordYrp8h8ykgIldThdowdxq7AyHvUdAj6DeJ1v/FQ+g0FYwyfotvN9DXEr5hOgvalSAW5faW4lcaJmSSj0r7Cqe3X7u4BqKKszK7FneD7n+06Q=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM8PR02MB8247.namprd02.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(366004)(6506007)(54906003)(53546011)(110136005)(38070700005)(4326008)(8936002)(316002)(66446008)(122000001)(55016003)(8676002)(508600001)(186003)(26005)(966005)(71200400001)(64756008)(7696005)(76116006)(66476007)(66556008)(66946007)(2906002)(38100700002)(9686003)(33656002)(52536014)(30864003)(83380400001)(86362001)(5660300002);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?bnFVR3Q4ZDRxVHZOMlVOTmlxWVl2U0JEWWpPbjFVTG9RczUva0kvZjhDV3Jo?=
 =?utf-8?B?WHFBNVFSTlp3UXVuWlY4R2ZIYlZDOTNWdFZ4Q0tHbkIvWWo1QytUK1VWYncx?=
 =?utf-8?B?L2tvVUdlUGdNUDBFN2Y2d3hrdHhxZmxCajAyQ04xd3NzdXg0cUhVSnNvMGNp?=
 =?utf-8?B?ZHl6SmsxejFKNngxSkl4eS9BR05ZNTZHUXdENlIzLzMrazdKaVBFZG4rc2ty?=
 =?utf-8?B?Q0NKUlNPdEhlakppd0JkQnVzVE1JZ2ExeklEdkpBenFhcVg0RFNFTWwxL2Ni?=
 =?utf-8?B?YnRYZ3Y5Y2VLR3FQdVdGZWV5MEZnOVBZMWJNQTVHalJuSDdQT3YxaHdsOWpt?=
 =?utf-8?B?ZmxrdHEwWjdVTVZ6SlR2THoyb0VqTERMUW9GY0pXWmVFS1VWcGhHcnRDRUl0?=
 =?utf-8?B?TVFUQ2FucUl3cHh4eHlTWXVLZHZjbWY4aVM0SUVRdTFVQXliQ1hIVXoySGVV?=
 =?utf-8?B?eHVUMnlreUdGTVBxUEw3VGd4LzUrVmk5cmx2cFAyeEJpMnNoRHBTYkdJeEdp?=
 =?utf-8?B?M2p0N3VKbDVsWWRkSkNOK3RCZ2RxQ0FxZ0tqWWtQNUl1aUFhazlWRitvd0E2?=
 =?utf-8?B?VkxWQXJTUVlidzUxZHhXalJlTXowV2N2MVhJRXhOVUU4MHM5MjAwNEQyZ1Zy?=
 =?utf-8?B?Q1JxeTRLb0V5TGV1ekVPUVJsems2cDFaYXZGNGJjVUF0VVBZUUVYQ3o0cytC?=
 =?utf-8?B?Z0dTRDlZTVI2eTZhYlFJUFJKZTRORUxOMzdlL3JiNDhJTHZ4dFlqN3BGYkFp?=
 =?utf-8?B?THFCVXhqbjZrUE1BUXM0T0xkUGdMeHdvbEFYNTJCZENvNVZ5RG5nL3F0NHRm?=
 =?utf-8?B?c3hPc3AzVGhoTEJGTkRVREFBNEZWZk1oRWgwcEtlbFEza0pCaW9BbmczZUFX?=
 =?utf-8?B?TlFDTGhXbXhjOTZvOGY2cFB0bkNWcExZbnl5K1RkWUlOMFJGck1jWXpsemJM?=
 =?utf-8?B?SHZwZ0ZpU21CbW1yUE1BT1U2NGtpbDBtNzlmdWtpT1hnSTdSS0h6dUtibmZO?=
 =?utf-8?B?T09DaVFaSWNEeG54cHhQaENsaWptV3UvbFlrSjdYWE5tc1puNGFNZ0pZR2Rx?=
 =?utf-8?B?ODl5UDYxbUdUemNQMkNENmVRWEJSclBIbnM0MyszcjIweXVHbXROUVJTQmhL?=
 =?utf-8?B?Nmg1NHpKN01LQWxSY3BIcDhuQ1pZZUdDbzR4WlBRVW5iM0MwRGRlZi9WUVhy?=
 =?utf-8?B?bkNIMXZuSDNtdEo2YkcvdkhLemZwYUlqMjlaNzV0aUtYVWcyNXRqYVhCY2Zh?=
 =?utf-8?B?Wm5OOUFiTm5ZREpWdit3endFQzRjckhyY0NRcWtNbE5lTWdqNXVvYjlZeGJO?=
 =?utf-8?B?RDFpN2htc1VsdVRDbk9XNytjRlFWaEFISmRRbzVrYndiWWZnb2pIcUpYT1BB?=
 =?utf-8?B?SEwwcUhDTkZnUGh0KzVKV0UwNXo5bU43VTA1V0R2ZkpTaCtRd0c1MGRVenc5?=
 =?utf-8?B?YzBPQ2dCdFhwOWlyTVNlVU0vN1plVWNhRENreGdWcmxlMHUycTVITVZ0T1ZJ?=
 =?utf-8?B?eUtBaldQMm41U0oxQitVVE9jdzUvY3B2WkRUekh1YUxicXQwdXI1UGU5V0Uy?=
 =?utf-8?B?ZUs1WnFBaWRmWVYzYWZycm9WR1lOWTU2L1oxcld2dVZEQ09FSWQ0K2xSSEtB?=
 =?utf-8?B?SzlBMkkyME5SbTZuMGJNL0swbVpQZVVwS3pXRmx3T29SRGg1cWxoT0h6Y0tL?=
 =?utf-8?B?TjVYaSttWDkwUkk2YXU2TFhvZjhXaE5EaHJ1NWdRdnR4L0FGNlllN2Y0dnBV?=
 =?utf-8?B?V1A1R3BKWWFoanBSdG5DbE1Hb205ajlWRktUR0tTU2VyVjlOQXRDUGdiQ04v?=
 =?utf-8?B?L2pKdGo3a0VueWZNcXdCV0pUL1NjdUZZS1BmeFZTQyswMktVMkkzN21zRnJH?=
 =?utf-8?B?K0tCTGdGSUk3SmJuczBkSndBazNDWlFWTU81VnFBWVZKUmhseWFZdThEbmw3?=
 =?utf-8?B?UHZhVStxMDR2b092MmVUY1d0Z3F0ekhaL01iOWRreStwMTJKTE91SC9nUWlI?=
 =?utf-8?B?TW45ZGZ4VzZnY2xFMkNSRWJIZ2ZRZ3RyNXdUQm1wdjRsL0NmYjBmR2swa2lw?=
 =?utf-8?B?bDczZUQyK2lmQVh3cG5OYUxJYjBFSDFKSndMNENsZVpSRlZ6enA2aS9uQ0JL?=
 =?utf-8?B?WUJBa1NnVTVjUjE3Wkl1NDRUc21YREQ4UWJWVDdvQnlWZ0tnOFZONngrcDBW?=
 =?utf-8?B?SW5oNmRBdnhkN3RPK1RjbG5LVVh1T2tyN0MrNDhaQ0pVY2xyQjBxK0ZPTHU3?=
 =?utf-8?B?aHlBWHV5RUp2MDAxWUFxaFNDZ3dBPT0=?=
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: quicinc.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: DM8PR02MB8247.namprd02.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 6a0255f2-2ddd-4cd3-4c63-08d9ae2fd9e6
X-MS-Exchange-CrossTenant-originalarrivaltime: 23 Nov 2021 03:17:59.0507
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 98e9ba89-e1a1-4e38-9007-8bdabc25de1d
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: YjxldXE1Js74ZsBI7Gzj4ZWYCuA/LJIe8hw+dxTHdxJCVFIrgYEJbii/wxQU1X+Zbt7GJvoSopdstPb6VugtP2tLbYAzxOLdeWGLxajnGNI=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR02MB5946
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qccesdkim1 header.b=NmuVer7n;       arc=pass
 (i=1 spf=pass spfdomain=quicinc.com dkim=pass dkdomain=quicinc.com dmarc=pass
 fromdomain=quicinc.com);       spf=pass (google.com: domain of
 quic_jiangenj@quicinc.com designates 216.71.140.77 as permitted sender)
 smtp.mailfrom=quic_jiangenj@quicinc.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=quicinc.com
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
Based on these info, any further comment and next action?

# Summary
* shouldn't filter inside kernel which will loose edge info (Kaipeng).
* filter start, end should be enough (Kaipeng).
* put edge info into kernel? (Kaipeng) __sanitizer_cov_trace_pc_guard might=
 be an option? But it will loose PC info for /cover page (perhaps needs gco=
v), also not feasible to filter out pc guard value. (Joey)
* eBPF is for read-only purpose, not suitable to overcome kcov->area overfl=
ow (Joey).
* PC RANGE (start, end) can be used together with current cover filter (sta=
rt, start+size) in syzkaller to fuzzing file or module interested (Joey).
* KCOV uniq PC is for another purpose (dropping edge info) even it also ove=
rcomes kcov->area overflow (Joey).

THX
Joey

-----Original Message-----
From: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>=20
Sent: Monday, November 22, 2021 11:25 AM
To: Kaipeng Zeng <kaipeng94@gmail.com>; Dmitry Vyukov <dvyukov@google.com>
Cc: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>; syzkaller <syzkaller@g=
ooglegroups.com>; andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML <l=
inux-kernel@vger.kernel.org>; Alexander Lochmann <info@alexander-lochmann.d=
e>; Likai Ding (QUIC) <quic_likaid@quicinc.com>; Hangbin Liu <liuhangbin@gm=
ail.com>
Subject: RE: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range

Hi Kaipeng,
> BTW, our coverage filter is for Linux/amd64 only. Seems the author needs =
a coverage filter on arm.

Let you know that cov filer for arm[64] is available too in syzkaller back =
months.

-----Original Message-----
From: Kaipeng Zeng <kaipeng94@gmail.com>=20
Sent: Monday, November 22, 2021 11:09 AM
To: Dmitry Vyukov <dvyukov@google.com>
Cc: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>; syzkaller <syzkaller@g=
ooglegroups.com>; andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML <l=
inux-kernel@vger.kernel.org>; Alexander Lochmann <info@alexander-lochmann.d=
e>; Likai Ding (QUIC) <quic_likaid@quicinc.com>; Hangbin Liu <liuhangbin@gm=
ail.com>
Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range

WARNING: This email originated from outside of Qualcomm. Please be wary of =
any links or attachments, and do not enable macros.

Hi Dmitry,

On Fri, Nov 19, 2021 at 9:07 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Fri, 19 Nov 2021 at 13:55, Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > +Kaipeng, Hangbin who contributed the coverage filter to syzkaller.
> > This is a discussion about adding a similar filter to the kernel.=20
> > You can see whole discussion here:
> > https://groups.google.com/g/kasan-dev/c/TQmYUdUC08Y
>
> Joey, what do you think in general about passing a filter bitmap to the k=
ernel?
>
> Since the bitmap is large, it can make sense to reuse it across=20
> different KCOV instances.
> I am thinking about something along the following lines:
>
> kcov_fd =3D open("/debugfs/kcov");
> filter_fd =3D ioctl(kcov_fd, KCOV_CREATE_FILTER, &{... some args=20
> specifying start/end ...}); filter =3D mmap(..., filter_fd); ... write=20
> to the filter ...
>
> ...
> kcov_fd2 =3D open("/debugfs/kcov");
> ioctl(kcov_fd2, KCOV_ATTACH_FILTER, filter_fd); ioctl(kcov_fd2,=20
> KCOV_ENABLE);
>
>
> This would allow us to create 2 filters:
> 1. One the interesting subsystems
> 2. Second only for yet uncovered PCs in the interesting subsystems=20
> (updated as we discover more coverage)
>
> During fuzzing we attach the second filter to KCOV.
> But when we want to obtain full program coverage, we attach the first one=
.
>
> The filters (bitmaps) are reused across all threads in all executor=20
> processes (so that we have only 2 filters globally per VM).
>

I think implementing such a filter in kernel would be harmful to syzkaller =
fuzzing:
1. Both two bitmaps would impede syzkaller from getting backward and forwar=
d edge between interesting and uninteresting code.
Currently, syzkaller uses edge but not coverage to decide if the prog shoul=
d be collected to the corpus. And the second bitmap actually destroys the C=
FG in the interesting subsystem.
It's impossible that syzkaller restores such information by analyzing the f=
iltered coverage. While syzkaller coverage filter doesn't have this problem=
.
2. The First bitmap would impede syzkaller from getting full coverage of th=
e whole kernel. So that it would be hard to analyze how the kernel path get=
s into the interesting subsystem.
It's OK if the syscall description is completed. But, we always need to do =
such analysis if we try to improve syscall descriptions.
3. Coverage of prog would be imcompleted.

It seems the only reason to introduce in-kernel coverage filter is to defen=
se KCOV area overflow. Do nothing in improving the fuzzing loop.
It is reasonable that a fuzzer should collect full information as feedback,=
 then analyze and decide how to use that information and which to drop.
In the other hand, kernel should try its best to send more information to f=
uzzer. Only if the memory is not enough to store such information.
Doing such in-kernel filtering would be reasonable.

An alternative choice is doing edge analyzing in kernel also, but KCOV woul=
d be more and more restricted and limited.

So, I think the pc_range is enough for defense KCOV area overflow. And keep=
 it from the syzkaller fuzzing loop. But not implement such bitmap into ker=
nel.
Coverage filter in syzkaller would be more flexible. A user could effective=
ly fuzz their objective subsystems and easier to customize fuzzing loop.

BTW, our coverage filter is for Linux/amd64 only. Seems the author needs a =
coverage filter on arm.


> KCOV_CREATE_FILTER could also accept how many bytes each bit=20
> represents (that scaling factor, as hardcoding 4, 8, 16 may be bad for=20
> a stable kernel interface).
>
> But I am still not sure how to support both the main kernel and=20
> modules. We could allow setting up multiple filters for different PC=20
> ranges. Or may be just 2 (one for kernel and one for modules range).
> Or maybe 1 bitmap can cover both kernel and modules?
>
> Thoughts?
>
>
> > On Fri, 19 Nov 2021 at 12:21, JianGen Jiao (QUIC)=20
> > <quic_jiangenj@quicinc.com> wrote:
> > >
> > > Yes, on x86_64, module address space is after kernel. But like below =
on arm64, it's different.
> > >
> > > # grep stext /proc/kallsyms
> > > ffffffc010010000 T _stext
> > > # cat /proc/modules |sort -k 6 | tail -2
> > > Some_module_1 552960 0 - Live 0xffffffc00ca05000 (O)
> > > Some_module_1 360448 0 - Live 0xffffffc00cb8f000 (O) # cat=20
> > > /proc/modules |sort -k 6 | head -2
> > > Some_module_3 16384 1 - Live 0xffffffc009430000
> > >
> > > -----Original Message-----
> > > From: Dmitry Vyukov <dvyukov@google.com>
> > > Sent: Friday, November 19, 2021 6:38 PM
> > > To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> > > Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML=20
> > > <linux-kernel@vger.kernel.org>; Alexander Lochmann=20
> > > <info@alexander-lochmann.de>; Likai Ding (QUIC)=20
> > > <quic_likaid@quicinc.com>
> > > Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
> > >
> > > WARNING: This email originated from outside of Qualcomm. Please be wa=
ry of any links or attachments, and do not enable macros.
> > >
> > > On Fri, 19 Nov 2021 at 04:17, JianGen Jiao (QUIC) <quic_jiangenj@quic=
inc.com> wrote:
> > > >
> > > > Hi Dmitry,
> > > > I'm using the start, end pc from cover filter, which currently is t=
he fast way compared to the big bitmap passing from syzkaller solution, as =
I only set the cover filter to dirs/files I care about.
> > >
> > > I see.
> > > But if we are unlucky and our functions of interest are at the very l=
ow and high addresses, start/end will cover almost all kernel code...
> > >
> > > > I checked
> > > > https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCAA
> > > > AJ, The bitmap seems not the same as syzkaller one, which one=20
> > > > will be used finally?
> > >
> > > I don't know yet. We need to decide.
> > > In syzkaller we are more flexible and can change code faster, while k=
ernel interfaces are stable and need to be kept forever. So I think we need=
 to concentrate more on the good kernel interface and then support it in sy=
zkaller.
> > >
> > > > ``` Alexander's one
> > > > + pos =3D (ip - canonicalize_ip((unsigned long)&_stext)) / 4; idx=
=20
> > > > + =3D pos % BITS_PER_LONG; pos /=3D BITS_PER_LONG; if (likely(pos <
> > > > + t->kcov_size)) WRITE_ONCE(area[pos], READ_ONCE(area[pos]) | 1L=20
> > > > + t-><<
> > > > + idx);
> > > > ```
> > > > Pc offset is divided by 4 and start is _stext. But for some arch, p=
c is less than _stext.
> > >
> > > You mean that modules can have PC < _stext?
> > >
> > > > ``` https://github.com/google/syzkaller/blob/master/syz-manager/cov=
filter.go#L139-L154
> > > >         data :=3D make([]byte, 8+((size>>4)/8+1))
> > > >         order :=3D binary.ByteOrder(binary.BigEndian)
> > > >         if target.LittleEndian {
> > > >                 order =3D binary.LittleEndian
> > > >         }
> > > >         order.PutUint32(data, start)
> > > >         order.PutUint32(data[4:], size)
> > > >
> > > >         bitmap :=3D data[8:]
> > > >         for pc :=3D range pcs {
> > > >                 // The lowest 4-bit is dropped.
> > > >                 pc =3D uint32(backend.NextInstructionPC(target, uin=
t64(pc)))
> > > >                 pc =3D (pc - start) >> 4
> > > >                 bitmap[pc/8] |=3D (1 << (pc % 8))
> > > >         }
> > > >         return data
> > > > ```
> > > > Pc offset is divided by 16 and start is cover filter start pc.
> > > >
> > > > I think divided by 8 is more reasonable? Because there is at least =
one instruction before each __sanitizer_cov_trace_pc call.
> > > > 0000000000000160 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
> > > > 0000000000000168 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
> > > >
> > > > I think we still need my patch because we still need a way to keep =
the trace_pc call and post-filter in syzkaller doesn't solve trace_pc dropp=
ing, right?
> > >
> > > Yes, the in-kernel filter solves the problem of trace capacity/overfl=
ows.
> > >
> > >
> > > > But for sure I can use the bitmap from syzkaller.
> > > >
> > > > THX
> > > > Joey
> > > > -----Original Message-----
> > > > From: Dmitry Vyukov <dvyukov@google.com>
> > > > Sent: Thursday, November 18, 2021 10:00 PM
> > > > To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> > > > Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML=20
> > > > <linux-kernel@vger.kernel.org>; Alexander Lochmann=20
> > > > <info@alexander-lochmann.de>
> > > > Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
> > > >
> > > > WARNING: This email originated from outside of Qualcomm. Please be =
wary of any links or attachments, and do not enable macros.
> > > >
> > > > ,On Wed, 17 Nov 2021 at 07:24, Joey Jiao <quic_jiangenj@quicinc.com=
> wrote:
> > > > >
> > > > > Sometimes we only interested in the pcs within some range,=20
> > > > > while there are cases these pcs are dropped by kernel due to=20
> > > > > `pos >=3D
> > > > > t->kcov_size`, and by increasing the map area size doesn't help.
> > > > >
> > > > > To avoid disabling KCOV for these not intereseted pcs during=20
> > > > > build time, adding this new KCOV_PC_RANGE cmd.
> > > >
> > > > Hi Joey,
> > > >
> > > > How do you use this? I am concerned that a single range of PCs is t=
oo restrictive. I can only see how this can work for single module (continu=
ous in memory) or a single function. But for anything else (something in th=
e main kernel, or several modules), it won't work as PCs are not continuous=
.
> > > >
> > > > Maybe we should use a compressed bitmap of interesting PCs? It allo=
ws to support all cases and we already have it in syz-executor, then syz-ex=
ecutor could simply pass the bitmap to the kernel rather than post-filter.
> > > > It's also overlaps with the KCOV_MODE_UNIQUE mode that +Alexander p=
roposed here:
> > > > https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCAA
> > > > AJ It would be reasonable if kernel uses the same bitmap format=20
> > > > for these
> > > > 2 features.
> > > >
> > > >
> > > >
> > > > > An example usage is to use together syzkaller's cov filter.
> > > > >
> > > > > Change-Id: I954f6efe1bca604f5ce31f8f2b6f689e34a2981d
> > > > > Signed-off-by: Joey Jiao <quic_jiangenj@quicinc.com>
> > > > > ---
> > > > >  Documentation/dev-tools/kcov.rst | 10 ++++++++++
> > > > >  include/uapi/linux/kcov.h        |  7 +++++++
> > > > >  kernel/kcov.c                    | 18 ++++++++++++++++++
> > > > >  3 files changed, 35 insertions(+)
> > > > >
> > > > > diff --git a/Documentation/dev-tools/kcov.rst
> > > > > b/Documentation/dev-tools/kcov.rst
> > > > > index d83c9ab..fbcd422 100644
> > > > > --- a/Documentation/dev-tools/kcov.rst
> > > > > +++ b/Documentation/dev-tools/kcov.rst
> > > > > @@ -52,9 +52,15 @@ program using kcov:
> > > > >      #include <fcntl.h>
> > > > >      #include <linux/types.h>
> > > > >
> > > > > +    struct kcov_pc_range {
> > > > > +      uint32 start;
> > > > > +      uint32 end;
> > > > > +    };
> > > > > +
> > > > >      #define KCOV_INIT_TRACE                    _IOR('c', 1, unsi=
gned long)
> > > > >      #define KCOV_ENABLE                        _IO('c', 100)
> > > > >      #define KCOV_DISABLE                       _IO('c', 101)
> > > > > +    #define KCOV_TRACE_RANGE                   _IOW('c', 103, st=
ruct kcov_pc_range)
> > > > >      #define COVER_SIZE                 (64<<10)
> > > > >
> > > > >      #define KCOV_TRACE_PC  0
> > > > > @@ -64,6 +70,8 @@ program using kcov:
> > > > >      {
> > > > >         int fd;
> > > > >         unsigned long *cover, n, i;
> > > > > +        /* Change start and/or end to your interested pc range. =
*/
> > > > > +        struct kcov_pc_range pc_range =3D {.start =3D 0, .end =
=3D=20
> > > > > + (uint32)(~((uint32)0))};
> > > > >
> > > > >         /* A single fd descriptor allows coverage collection on a=
 single
> > > > >          * thread.
> > > > > @@ -79,6 +87,8 @@ program using kcov:
> > > > >                                      PROT_READ | PROT_WRITE, MAP_=
SHARED, fd, 0);
> > > > >         if ((void*)cover =3D=3D MAP_FAILED)
> > > > >                 perror("mmap"), exit(1);
> > > > > +        if (ioctl(fd, KCOV_PC_RANGE, pc_range))
> > > > > +               dprintf(2, "ignore KCOV_PC_RANGE error.\n");
> > > > >         /* Enable coverage collection on the current thread. */
> > > > >         if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC))
> > > > >                 perror("ioctl"), exit(1); diff --git=20
> > > > > a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h index=20
> > > > > 1d0350e..353ff0a 100644
> > > > > --- a/include/uapi/linux/kcov.h
> > > > > +++ b/include/uapi/linux/kcov.h
> > > > > @@ -16,12 +16,19 @@ struct kcov_remote_arg {
> > > > >         __aligned_u64   handles[0];
> > > > >  };
> > > > >
> > > > > +#define PC_RANGE_MASK ((__u32)(~((u32) 0))) struct kcov_pc_range=
 {
> > > > > +       __u32           start;          /* start pc & 0xFFFFFFFF =
*/
> > > > > +       __u32           end;            /* end pc & 0xFFFFFFFF */
> > > > > +};
> > > > > +
> > > > >  #define KCOV_REMOTE_MAX_HANDLES                0x100
> > > > >
> > > > >  #define KCOV_INIT_TRACE                        _IOR('c', 1, unsi=
gned long)
> > > > >  #define KCOV_ENABLE                    _IO('c', 100)
> > > > >  #define KCOV_DISABLE                   _IO('c', 101)
> > > > >  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, struct kco=
v_remote_arg)
> > > > > +#define KCOV_PC_RANGE                  _IOW('c', 103, struct kco=
v_pc_range)
> > > > >
> > > > >  enum {
> > > > >         /*
> > > > > diff --git a/kernel/kcov.c b/kernel/kcov.c index=20
> > > > > 36ca640..59550450
> > > > > 100644
> > > > > --- a/kernel/kcov.c
> > > > > +++ b/kernel/kcov.c
> > > > > @@ -36,6 +36,7 @@
> > > > >   *  - initial state after open()
> > > > >   *  - then there must be a single ioctl(KCOV_INIT_TRACE) call
> > > > >   *  - then, mmap() call (several calls are allowed but not=20
> > > > > useful)
> > > > > + *  - then, optional to set trace pc range
> > > > >   *  - then, ioctl(KCOV_ENABLE, arg), where arg is
> > > > >   *     KCOV_TRACE_PC - to trace only the PCs
> > > > >   *     or
> > > > > @@ -69,6 +70,8 @@ struct kcov {
> > > > >          * kcov_remote_stop(), see the comment there.
> > > > >          */
> > > > >         int                     sequence;
> > > > > +       /* u32 Trace PC range from start to end. */
> > > > > +       struct kcov_pc_range    pc_range;
> > > > >  };
> > > > >
> > > > >  struct kcov_remote_area {
> > > > > @@ -192,6 +195,7 @@ static notrace unsigned long=20
> > > > > canonicalize_ip(unsigned long ip)  void notrace
> > > > > __sanitizer_cov_trace_pc(void)  {
> > > > >         struct task_struct *t;
> > > > > +       struct kcov_pc_range pc_range;
> > > > >         unsigned long *area;
> > > > >         unsigned long ip =3D canonicalize_ip(_RET_IP_);
> > > > >         unsigned long pos;
> > > > > @@ -199,6 +203,11 @@ void notrace __sanitizer_cov_trace_pc(void)
> > > > >         t =3D current;
> > > > >         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> > > > >                 return;
> > > > > +       pc_range =3D t->kcov->pc_range;
> > > > > +       if (pc_range.start < pc_range.end &&
> > > > > +               ((ip & PC_RANGE_MASK) < pc_range.start ||
> > > > > +               (ip & PC_RANGE_MASK) > pc_range.end))
> > > > > +               return;
> > > > >
> > > > >         area =3D t->kcov_area;
> > > > >         /* The first 64-bit word is the number of subsequent=20
> > > > > PCs. */ @@ -568,6 +577,7 @@ static int kcov_ioctl_locked(struct k=
cov *kcov, unsigned int cmd,
> > > > >         int mode, i;
> > > > >         struct kcov_remote_arg *remote_arg;
> > > > >         struct kcov_remote *remote;
> > > > > +       struct kcov_pc_range *pc_range;
> > > > >         unsigned long flags;
> > > > >
> > > > >         switch (cmd) {
> > > > > @@ -589,6 +599,14 @@ static int kcov_ioctl_locked(struct kcov *kc=
ov, unsigned int cmd,
> > > > >                 kcov->size =3D size;
> > > > >                 kcov->mode =3D KCOV_MODE_INIT;
> > > > >                 return 0;
> > > > > +       case KCOV_PC_RANGE:
> > > > > +               /* Limit trace pc range. */
> > > > > +               pc_range =3D (struct kcov_pc_range *)arg;
> > > > > +               if (copy_from_user(&kcov->pc_range, pc_range, siz=
eof(kcov->pc_range)))
> > > > > +                       return -EINVAL;
> > > > > +               if (kcov->pc_range.start >=3D kcov->pc_range.end)
> > > > > +                       return -EINVAL;
> > > > > +               return 0;
> > > > >         case KCOV_ENABLE:
> > > > >                 /*
> > > > >                  * Enable coverage for the current task.
> > > > > --
> > > > > 2.7.4

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/DM8PR02MB82473E366FA560E2FF214EF8F8609%40DM8PR02MB8247.namprd02.p=
rod.outlook.com.
