Return-Path: <kasan-dev+bncBCPZ5EGB2AHRBW4UZL6QKGQE5I2K5BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 894FB2B45A5
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 15:19:08 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id u28sf10201676qtv.20
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 06:19:08 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1605536347; cv=pass;
        d=google.com; s=arc-20160816;
        b=oFXFzHtp54TXHVwVujuGT/4t9ICR2QTjK1YEBwud9jq1W5Yzadcrrf4SI1gt5P0ul+
         dlGpP3xqNSA3Ve6y0RzzxbwanLR+w8z72Q+xK5uiFawJkOs/OmK43LFqFNByS5BcO5rr
         dyAZr1mZ58CpXiZHEp1AHfGczaOaHnNdbudeqrohdcBVQupufbCjRC5Tnts4sEuvOkF/
         N5kJ4Suu3NbZ8DYzRQAwgqveGSotycRE3guFKOHVZTpyFT/pek81dySPvNIdBQGZo6VX
         fed1elcw92XQrOeCSU3ZCavhL+pXLFJRVcJuLHY1pYJZrXzGXrRXrxzE261Bk0bUaamV
         zY8w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=9I6hGwfbdwNO9oBReB9qELb//JsRbhFRKMui2ppXb74=;
        b=mx8QoMAxi6MKQJkNzAO14BV6CDKI9ZoW35RRofNCgtocomoS6q5PnbF1ZRlllF+erf
         BDF86FrHLf5cPMKIxfE+DJMrFZRmyIVBNmPIKEch+N6FKBAWLBNLP0Fr00balmq2dtn/
         Ax15CuEVlErg+7VKYXaQF5LEs1HmOQ4Np2KlH+mdxCVQDmDwNDBbBtbTZ/kmtRsL+Vi1
         nJgao4jJCDFLUwg4+mz/POtFZURhBZ6c5m7h1hc3cdxVMZzqW/XqG7w8CmeH3xY7SA+9
         aqeZ+brvrldzKqtd3eC8YikmCKSa9LDaGoi6iTztt2Q1lyM8jipnM2fSshjMlTQmjHNs
         WSsA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@psu.edu header.s=selector1 header.b=Dkhjakbe;
       arc=pass (i=1 spf=pass spfdomain=psu.edu dkim=pass dkdomain=psu.edu dmarc=pass fromdomain=psu.edu);
       spf=pass (google.com: domain of yxc431@psu.edu designates 40.107.92.134 as permitted sender) smtp.mailfrom=yxc431@psu.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=psu.edu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9I6hGwfbdwNO9oBReB9qELb//JsRbhFRKMui2ppXb74=;
        b=ZjnjgCphpI+sE5wrD69oXrfuQJ5/PaURz31KuuG88XrwR8QQb6b36Lq/ZjuZ71VyL1
         EyJGQye01VZ5PxTGzM+lGsZYtQ22Ayj6Wt3BSJ4DNi3nyuxEvUuFCpwobVIkvMT7WEL/
         5JOBR2mgUONss9WfJAiB6xKMqCBIMdNZIPwTdPH47xWS4SFs5+Tyk/ugeUVKNQQAdeli
         07uvkjb4BPRpf8RAt0lZ9d+DlwE3G8UmNZSIC/pDVDAYGdY1sSy7MI8ay1qaEcKS8ODO
         ArSwoUpxirPauG01ltjIBGGjFXcDHpl9vvYSTyG69sgo0IcaqK7iFS7TuWWbzbHXG7n1
         aMxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9I6hGwfbdwNO9oBReB9qELb//JsRbhFRKMui2ppXb74=;
        b=YkqaOXmhXu/r+bzlcAK7r76v3Hm5i5TO6Pt9pJCmokV91wmahs30a+mcRJV2hShhaY
         PWbdj6zAYyAfn9msn+77PBhgEF2okJLfPiiJvv1wYaen4CV09737jDs/MtHwQ3DYVBMs
         C/fmfPTgNRmPY4ZKxKkqkkmMlNMrNDJzi43+juCMVJLtwBzWkeOTUa4+N7vvTwsuFnBP
         1ts2UZXlf68bwo8hmndhwEbdjyF8cut+nMrJS00kfU0w8Hx3ccpd6a/JVEDfWcgtj4a4
         pmDTlJeMaZseYtmoelzkkcz0/u4Up423Ds5act9sF85cDIuGj0toISOJ41OqV+CrrP50
         FWYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530GGIh4M0hoAIdUmrz17eHpqcJZZ8my2sW7B12uMtm2YzOEc8e6
	A5+g1jpVJrvceGRW4auul9U=
X-Google-Smtp-Source: ABdhPJxi7HfYSQlRa/La2M6NmfmRwUpHi73izE2f9br4oo0wUUkaUHS8sHRR1UZ8IvImfXnOX0O4vg==
X-Received: by 2002:a05:620a:22e6:: with SMTP id p6mr14829420qki.174.1605536347195;
        Mon, 16 Nov 2020 06:19:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:708e:: with SMTP id y14ls3110515qto.9.gmail; Mon, 16 Nov
 2020 06:19:06 -0800 (PST)
X-Received: by 2002:ac8:13cb:: with SMTP id i11mr14285599qtj.390.1605536346723;
        Mon, 16 Nov 2020 06:19:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605536346; cv=pass;
        d=google.com; s=arc-20160816;
        b=BiIHbKfN9ICSWExXK7i8mt7vUhCh9emOPEgXNsQ5Pzwfd0Q2fEPJ9WV8S1JV/C0Av5
         /YZelBy98BqH+vpPcHLzJlZxyEbUDgQr9fiW30nWQ5EC2JpkiTEaDhHsO3S23WR2sR2f
         9I/lb7GLQRn12gC5n9K2K+oBbs1ES8ukkAdS9dfDrMRnOqss4729Q1JXl4EgwFet/+Tn
         Y/5l0JM3qIqFdp+710FVPiLtXqMZRDIAnCeLfwnzVScTnyLEWFkD/yEGefygi00Dxupu
         kdlKn6bqu4RE80MITlygLLT3IC/JYbr0thfiwzD9OyMetXincCoGMPq8S98q6O4wgPUE
         KuBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:dkim-signature;
        bh=SqJAelGGQeTJ4dm7KcOvdgwaMfMtsN+MS+A81W5PNJU=;
        b=IdzRKdlthrB6LG2i8efjx4/VeOS4PSamoEDNeCKsOah8sP9L5XU73ywNPKDLEZmEX0
         s7shK8M641BIQ2ey4j79/SZy6Sv2f4I4vWu0OSf928i0Qbtysq851XAoJ432GpXPDe8r
         0TmG60/aAZWY7Khk8Caa+rQfIw+XMxBOlIoMym5zp3u1uif+gsrF59vLxY4x15NJ4gVP
         ibG8J6vr7M43M8TiVCyVuHZH2WW2/72uMvhbtj9fdkbjw2Kv/Vbfhho+0hZpGAfFhAAQ
         fVHSdvQVtHWw5Ez2ZX4KcxFBor0knKz+y9sGi8XWV6cQjdimWYalzP6f/O3+ECJAf+Kc
         koAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@psu.edu header.s=selector1 header.b=Dkhjakbe;
       arc=pass (i=1 spf=pass spfdomain=psu.edu dkim=pass dkdomain=psu.edu dmarc=pass fromdomain=psu.edu);
       spf=pass (google.com: domain of yxc431@psu.edu designates 40.107.92.134 as permitted sender) smtp.mailfrom=yxc431@psu.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=psu.edu
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (mail-bn7nam10on2134.outbound.protection.outlook.com. [40.107.92.134])
        by gmr-mx.google.com with ESMTPS id p51si1067416qtc.4.2020.11.16.06.19.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Nov 2020 06:19:06 -0800 (PST)
Received-SPF: pass (google.com: domain of yxc431@psu.edu designates 40.107.92.134 as permitted sender) client-ip=40.107.92.134;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=H9hSZ786kUS3/nYDGPKAtEVWtgSs16LDSBqIpbJ7k1f0uAx1vSZrK40nI/0JcnzrcLzNM/t6ACKVlv0IWpOXZOXX4IfmPksj2q9Oiv/+NNEkzQIdSqhgSXvld3/Z9KmTfk6HSpz8XKs065y/qF2Sw3sA+RGxewzaLnwnfpRazqvt+uczhgwlSPc8aJiykVfjWz8UMYcx6QuLufBiInA0FUhE6Lb/0nR3BZk9C9CNxdJDWU+DVQCytVUoBkSjDPpR6g1otNvFHWmMRDRoRC1sIKewTrp0R41Tijd7oHQRSwl7l2N0t5Y5g2ihLg8wd7q2JZWe1lUPuHXZ4KNY3CpT7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=SqJAelGGQeTJ4dm7KcOvdgwaMfMtsN+MS+A81W5PNJU=;
 b=lowTH0ngXnqKdsCrK8ptGUNj5njMw3LBvy/BYwZHU9TYWlzQB2Z066XRjk0BuN7lPjzwFs3rPnRLlzlXVlkYXCXxznpQVLhNybTNCaHFaD4KC7Xgg/i+t699gJ2IB+YRsXu6M1A+LVTbvz4KoaiM0jyo83o0/UrLvpnTa9gYxFsAFz0544yjlpErrRjZad3j86ia18cDl95dRUNRNfMx0eYUXeTatImz/YUXKGIPvPt+BjpxFE/SaZwsia9W9svWz5FqnGuebFtyWOIaz65vij6UGLfimSEvkwJ53vQZsXIvudhwTYKJfb8Ct88tfYOUmgtQwvb1N2Viw7LhY8Q5kA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=psu.edu; dmarc=pass action=none header.from=psu.edu; dkim=pass
 header.d=psu.edu; arc=none
Received: from DM5PR02MB3211.namprd02.prod.outlook.com (2603:10b6:4:6b::24) by
 DM5PR02MB3703.namprd02.prod.outlook.com (2603:10b6:4:b5::17) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.3541.21; Mon, 16 Nov 2020 14:19:05 +0000
Received: from DM5PR02MB3211.namprd02.prod.outlook.com
 ([fe80::64d9:4c21:1d6c:5359]) by DM5PR02MB3211.namprd02.prod.outlook.com
 ([fe80::64d9:4c21:1d6c:5359%7]) with mapi id 15.20.3541.025; Mon, 16 Nov 2020
 14:19:05 +0000
From: "Chen, Yueqi" <yxc431@psu.edu>
To: Marco Elver <elver@google.com>
CC: "mingo@kernel.org" <mingo@kernel.org>, kasan-dev
	<kasan-dev@googlegroups.com>
Subject: Re: Questions about providing generic wrappers of KASAN and KCSAN
Thread-Topic: Questions about providing generic wrappers of KASAN and KCSAN
Thread-Index: AQHWtw418g5z8WoLLkmWzLfSDi8UeanBh76AgAlL+KQ=
Date: Mon, 16 Nov 2020 14:19:05 +0000
Message-ID: <DM5PR02MB3211D24303BB7B0CFF1E993182E30@DM5PR02MB3211.namprd02.prod.outlook.com>
References: <DM5PR02MB32115A1568F018C726BAB62982E90@DM5PR02MB3211.namprd02.prod.outlook.com>,<CANpmjNMS_stvBiTFw4CR3oSgg9W_Pxinn8omkYX24TOETybFdA@mail.gmail.com>
In-Reply-To: <CANpmjNMS_stvBiTFw4CR3oSgg9W_Pxinn8omkYX24TOETybFdA@mail.gmail.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [67.22.19.206]
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: 543d5a9f-6735-438c-63e0-08d88a3a936b
x-ms-traffictypediagnostic: DM5PR02MB3703:
x-microsoft-antispam-prvs: <DM5PR02MB3703F9EEBD6B32F9E112C0E582E30@DM5PR02MB3703.namprd02.prod.outlook.com>
x-ms-oob-tlc-oobclassifiers: OLM:9508;
x-ms-exchange-senderadcheck: 1
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: XXTN9TBnXmaL7kVDK98kuxtAE28S5eQ11JU4EnfUUmDs+ZDN0S2BFbkeT458c3HFr8Xm1NZbRl5/7yMpQt+x+8gqPCqQ3dL5RzCWQL2tpp1wacrykGqGX4glcoHWNcPy46M86RrFGB4W45V6hVnL0JaD044sFStDaG1/kB6HbBx/kBrRNENXYwESOVERbKLW6RE4YOCeyOtrTT62SZybWs5/EoghTn+c5ZZxpd0fv2SkpUk9UMYeGPvs4k0AEcwQD6JC0v0z2qdcNLh7hDRu9XcANx/xo3MNJKwP3MZdJ7imPvBKVvDRdpMDVfO7iEQOCahFy6Ea4M6qLqY0ISxuYbpeKBhhSjaXp6gLugHu746rPYZr18KYBAPZg50uvQ9mLZY6dIqL/p+7ycddI/zDTRfaxVkwxljVCc9jtMAcd46beJKAP6VhkCtRI/9gls1tGcTirTyO89VoYmtOIbkwfyd9AqKIsacmYObwsQh1ck0=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM5PR02MB3211.namprd02.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(136003)(39860400002)(346002)(396003)(376002)(366004)(66946007)(4326008)(2906002)(66476007)(64756008)(33656002)(66556008)(8676002)(66446008)(966005)(6916009)(76116006)(45080400002)(166002)(478600001)(53546011)(9686003)(316002)(54906003)(26005)(75432002)(786003)(5660300002)(8936002)(55016002)(52536014)(71200400001)(19627405001)(83380400001)(186003)(7696005)(86362001)(6506007)(41533002)(82582004);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata: ns/NikrTaYcDdLkT/yDM0/Eb69ZjJynlgHtVwRQHzD4bUFt4sb5sq1gjLzyboLHcCMThBl2NFkIFmbLJFqcO0/1f+L+gAVGz5OPkI4w+Ue7szjZcRDOSDtT6Vo3GFSp39jq8kVVBsTnRWPWoPGOdUwtOLdWMj+c9zNWdppD8REHSnwzcPGPRhx5YAlwb5pkc+1FlFhCq/l2b/fvAAALq9DtmuzacS0RGtiNzn30csccHnmJLiMyXbElAHXlQy9WeuO3E4WqPrPptHLm4os12+3vXZMw681k/MuRVQtWB4I8gzriZZ5nVk7rqs8dgHsY1MrOw1t2YjmASl/QKMy6H9h+vnD3l9llmxvJIliKDEowehKPzlsz+4tsgLG80Z3LAsnC4Wie17B3/dOUsTh5W5wH0SiAAjjnk5nv6g3B4foaLLWZUVhsAv0Vkj8yFGXOK5HybT4UccC2LsjLmAdhWcp3ZGGr2LAR7MBJWtSqA1id3vsE0tsfIf9vtNWtlqNvxg11LsnaZbBdPhaF3NZpvC9agN/PqtQsa2WGNEayYvyPV77YxwryMP801QrFjMKDy2reNragOfEBYF1g5MvJI8Xf7jVib+y7H4BBzR50lefQ4eUkrfAldA+9kSRNvVT32UUbEGXJYmKj1db6mM8oQFQ==
x-ms-exchange-transport-forked: True
Content-Type: multipart/alternative;
	boundary="_000_DM5PR02MB3211D24303BB7B0CFF1E993182E30DM5PR02MB3211namp_"
MIME-Version: 1.0
X-OriginatorOrg: psu.edu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: DM5PR02MB3211.namprd02.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 543d5a9f-6735-438c-63e0-08d88a3a936b
X-MS-Exchange-CrossTenant-originalarrivaltime: 16 Nov 2020 14:19:05.7880
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 7cf48d45-3ddb-4389-a9c1-c115526eb52e
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: hVkcNiUhSGFS7s3yiXjyLDth6ingdymqooeRswQpdpZogHYGiq4ScqiHE2+fOY+X
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM5PR02MB3703
X-Original-Sender: yxc431@psu.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@psu.edu header.s=selector1 header.b=Dkhjakbe;       arc=pass (i=1
 spf=pass spfdomain=psu.edu dkim=pass dkdomain=psu.edu dmarc=pass
 fromdomain=psu.edu);       spf=pass (google.com: domain of yxc431@psu.edu
 designates 40.107.92.134 as permitted sender) smtp.mailfrom=yxc431@psu.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=psu.edu
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

--_000_DM5PR02MB3211D24303BB7B0CFF1E993182E30DM5PR02MB3211namp_
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi Marco,

Thank you for your response and insight.
I am recently considering to re-design a sanitizer to have three in one.
Probably I need to think it twice.

All the best,
Yueqi
________________________________
From: Marco Elver <elver@google.com>
Sent: Tuesday, November 10, 2020 11:02 AM
To: Chen, Yueqi <yxc431@psu.edu>
Cc: mingo@kernel.org <mingo@kernel.org>; kasan-dev <kasan-dev@googlegroups.=
com>
Subject: Re: Questions about providing generic wrappers of KASAN and KCSAN

[+Cc kasan-dev]

On Tue, 10 Nov 2020 at 04:14, Chen, Yueqi <yxc431@psu.edu> wrote:
>
> Hi Marco and Ingo,
>
> Hope this email finds you well.
>
> My name is Yueqi Chen, a Ph.D. student from Pennsylvania State University=
.
> I am writing to ask questions regarding the commit https://nam01.safelink=
s.protection.outlook.com/?url=3Dhttps%3A%2F%2Fgit.kernel.org%2Fpub%2Fscm%2F=
linux%2Fkernel%2Fgit%2Ftip%2Ftip.git%2Fcommit%2F%3Fid%3D36e4d4dd4fc4f1d99e7=
966a460a2b12ce438abc2&amp;data=3D04%7C01%7Cyxc431%40psu.edu%7C25b98718db4b4=
78bac5508d885921812%7C7cf48d453ddb4389a9c1c115526eb52e%7C0%7C0%7C6374062098=
05326584%7CUnknown%7CTWFpbGZsb3d8eyJWIjoiMC4wLjAwMDAiLCJQIjoiV2luMzIiLCJBTi=
I6Ik1haWwiLCJXVCI6Mn0%3D%7C1000&amp;sdata=3D6TlmyePbpZnfvXY3YnkXoIj9Q6VI0bz=
nHCr5oVVIIc8%3D&amp;reserved=3D0
>
> As described, this commit unifies KASAN and KCSAN instrumentation, and pr=
obably in the future, KMSAN is also included.

That instrumentation is only for explicit instrumentation. For those
it's quite easy to combine as the type of accesses can be generalized,
but when it comes to the instrumentation that the compilers insert
things look *very* different.

> I wonder do you have any plans to re-design the three sanitizers into one=
 sanitizer.

No, we do not.

> By re-design, I mean brand-new shadow memory, brand-new instrumentation, =
and etc.
> Do you think this re-design is helpful in terms of reducing uncertainty, =
facilitating reproduction, and so on?

Each sanitizer works very differently, and e.g. KCSAN relies on
soft-watchpoints (and not shadow memory!). The latest KASAN
(AddressSanitizer) compiler instrumentation normally uses inline
instrumentation for performance, and not function-based hooks unlike
KCSAN.

While theoretically possible, the complexity and performance would
both suffer immensely. Some past discussion:
https://nam01.safelinks.protection.outlook.com/?url=3Dhttps%3A%2F%2Flkml.ke=
rnel.org%2Fr%2FCANpmjNPiKg%2B%2B%3DQHUjD87dqiBU1pHHfZmGLAh1gOZ%2B4JKAQ4SAQ%=
40mail.gmail.com&amp;data=3D04%7C01%7Cyxc431%40psu.edu%7C25b98718db4b478bac=
5508d885921812%7C7cf48d453ddb4389a9c1c115526eb52e%7C0%7C0%7C637406209805326=
584%7CUnknown%7CTWFpbGZsb3d8eyJWIjoiMC4wLjAwMDAiLCJQIjoiV2luMzIiLCJBTiI6Ik1=
haWwiLCJXVCI6Mn0%3D%7C1000&amp;sdata=3DnLBG%2F%2B5AE1C04De2XzMR9QHZ2bqVfL7D=
U0hSnJciQTU%3D&amp;reserved=3D0

Getting things like this to work in kernel space is much harder, and
before you look at the kernel, try to think if what you'd want works
in user space. There I think any real-world benefits are also
diminished by complexity and resulting poor performance.

-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/DM5PR02MB3211D24303BB7B0CFF1E993182E30%40DM5PR02MB3211.namprd02.p=
rod.outlook.com.

--_000_DM5PR02MB3211D24303BB7B0CFF1E993182E30DM5PR02MB3211namp_
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Dus-ascii"=
>
<style type=3D"text/css" style=3D"display:none;"> P {margin-top:0;margin-bo=
ttom:0;} </style>
</head>
<body dir=3D"ltr">
<div style=3D"font-family: Tahoma, Geneva, sans-serif; font-size: 12pt; col=
or: rgb(0, 0, 0);">
Hi Marco,</div>
<div style=3D"font-family: Tahoma, Geneva, sans-serif; font-size: 12pt; col=
or: rgb(0, 0, 0);">
<br>
</div>
<div style=3D"font-family: Tahoma, Geneva, sans-serif; font-size: 12pt; col=
or: rgb(0, 0, 0);">
Thank you for your response and insight.</div>
<div style=3D"font-family: Tahoma, Geneva, sans-serif; font-size: 12pt; col=
or: rgb(0, 0, 0);">
I am recently considering to re-design a sanitizer to have three in one.</d=
iv>
<div style=3D"font-family: Tahoma, Geneva, sans-serif; font-size: 12pt; col=
or: rgb(0, 0, 0);">
Probably I need to think it twice.&nbsp;</div>
<div style=3D"font-family: Tahoma, Geneva, sans-serif; font-size: 12pt; col=
or: rgb(0, 0, 0);">
<br>
</div>
<div style=3D"font-family: Tahoma, Geneva, sans-serif; font-size: 12pt; col=
or: rgb(0, 0, 0);">
All the best,</div>
<div style=3D"font-family: Tahoma, Geneva, sans-serif; font-size: 12pt; col=
or: rgb(0, 0, 0);">
Yueqi</div>
<div id=3D"appendonsend"></div>
<hr style=3D"display:inline-block;width:98%" tabindex=3D"-1">
<div id=3D"divRplyFwdMsg" dir=3D"ltr"><font face=3D"Calibri, sans-serif" st=
yle=3D"font-size:11pt" color=3D"#000000"><b>From:</b> Marco Elver &lt;elver=
@google.com&gt;<br>
<b>Sent:</b> Tuesday, November 10, 2020 11:02 AM<br>
<b>To:</b> Chen, Yueqi &lt;yxc431@psu.edu&gt;<br>
<b>Cc:</b> mingo@kernel.org &lt;mingo@kernel.org&gt;; kasan-dev &lt;kasan-d=
ev@googlegroups.com&gt;<br>
<b>Subject:</b> Re: Questions about providing generic wrappers of KASAN and=
 KCSAN</font>
<div>&nbsp;</div>
</div>
<div class=3D"BodyFragment"><font size=3D"2"><span style=3D"font-size:11pt;=
">
<div class=3D"PlainText">[+Cc kasan-dev]<br>
<br>
On Tue, 10 Nov 2020 at 04:14, Chen, Yueqi &lt;yxc431@psu.edu&gt; wrote:<br>
&gt;<br>
&gt; Hi Marco and Ingo,<br>
&gt;<br>
&gt; Hope this email finds you well.<br>
&gt;<br>
&gt; My name is Yueqi Chen, a Ph.D. student from Pennsylvania State Univers=
ity.<br>
&gt; I am writing to ask questions regarding the commit <a href=3D"https://=
nam01.safelinks.protection.outlook.com/?url=3Dhttps%3A%2F%2Fgit.kernel.org%=
2Fpub%2Fscm%2Flinux%2Fkernel%2Fgit%2Ftip%2Ftip.git%2Fcommit%2F%3Fid%3D36e4d=
4dd4fc4f1d99e7966a460a2b12ce438abc2&amp;amp;data=3D04%7C01%7Cyxc431%40psu.e=
du%7C25b98718db4b478bac5508d885921812%7C7cf48d453ddb4389a9c1c115526eb52e%7C=
0%7C0%7C637406209805326584%7CUnknown%7CTWFpbGZsb3d8eyJWIjoiMC4wLjAwMDAiLCJQ=
IjoiV2luMzIiLCJBTiI6Ik1haWwiLCJXVCI6Mn0%3D%7C1000&amp;amp;sdata=3D6TlmyePbp=
ZnfvXY3YnkXoIj9Q6VI0bznHCr5oVVIIc8%3D&amp;amp;reserved=3D0">
https://nam01.safelinks.protection.outlook.com/?url=3Dhttps%3A%2F%2Fgit.ker=
nel.org%2Fpub%2Fscm%2Flinux%2Fkernel%2Fgit%2Ftip%2Ftip.git%2Fcommit%2F%3Fid=
%3D36e4d4dd4fc4f1d99e7966a460a2b12ce438abc2&amp;amp;data=3D04%7C01%7Cyxc431=
%40psu.edu%7C25b98718db4b478bac5508d885921812%7C7cf48d453ddb4389a9c1c115526=
eb52e%7C0%7C0%7C637406209805326584%7CUnknown%7CTWFpbGZsb3d8eyJWIjoiMC4wLjAw=
MDAiLCJQIjoiV2luMzIiLCJBTiI6Ik1haWwiLCJXVCI6Mn0%3D%7C1000&amp;amp;sdata=3D6=
TlmyePbpZnfvXY3YnkXoIj9Q6VI0bznHCr5oVVIIc8%3D&amp;amp;reserved=3D0</a><br>
&gt;<br>
&gt; As described, this commit unifies KASAN and KCSAN instrumentation, and=
 probably in the future, KMSAN is also included.<br>
<br>
That instrumentation is only for explicit instrumentation. For those<br>
it's quite easy to combine as the type of accesses can be generalized,<br>
but when it comes to the instrumentation that the compilers insert<br>
things look *very* different.<br>
<br>
&gt; I wonder do you have any plans to re-design the three sanitizers into =
one sanitizer.<br>
<br>
No, we do not.<br>
<br>
&gt; By re-design, I mean brand-new shadow memory, brand-new instrumentatio=
n, and etc.<br>
&gt; Do you think this re-design is helpful in terms of reducing uncertaint=
y, facilitating reproduction, and so on?<br>
<br>
Each sanitizer works very differently, and e.g. KCSAN relies on<br>
soft-watchpoints (and not shadow memory!). The latest KASAN<br>
(AddressSanitizer) compiler instrumentation normally uses inline<br>
instrumentation for performance, and not function-based hooks unlike<br>
KCSAN.<br>
<br>
While theoretically possible, the complexity and performance would<br>
both suffer immensely. Some past discussion:<br>
<a href=3D"https://nam01.safelinks.protection.outlook.com/?url=3Dhttps%3A%2=
F%2Flkml.kernel.org%2Fr%2FCANpmjNPiKg%2B%2B%3DQHUjD87dqiBU1pHHfZmGLAh1gOZ%2=
B4JKAQ4SAQ%40mail.gmail.com&amp;amp;data=3D04%7C01%7Cyxc431%40psu.edu%7C25b=
98718db4b478bac5508d885921812%7C7cf48d453ddb4389a9c1c115526eb52e%7C0%7C0%7C=
637406209805326584%7CUnknown%7CTWFpbGZsb3d8eyJWIjoiMC4wLjAwMDAiLCJQIjoiV2lu=
MzIiLCJBTiI6Ik1haWwiLCJXVCI6Mn0%3D%7C1000&amp;amp;sdata=3DnLBG%2F%2B5AE1C04=
De2XzMR9QHZ2bqVfL7DU0hSnJciQTU%3D&amp;amp;reserved=3D0">https://nam01.safel=
inks.protection.outlook.com/?url=3Dhttps%3A%2F%2Flkml.kernel.org%2Fr%2FCANp=
mjNPiKg%2B%2B%3DQHUjD87dqiBU1pHHfZmGLAh1gOZ%2B4JKAQ4SAQ%40mail.gmail.com&am=
p;amp;data=3D04%7C01%7Cyxc431%40psu.edu%7C25b98718db4b478bac5508d885921812%=
7C7cf48d453ddb4389a9c1c115526eb52e%7C0%7C0%7C637406209805326584%7CUnknown%7=
CTWFpbGZsb3d8eyJWIjoiMC4wLjAwMDAiLCJQIjoiV2luMzIiLCJBTiI6Ik1haWwiLCJXVCI6Mn=
0%3D%7C1000&amp;amp;sdata=3DnLBG%2F%2B5AE1C04De2XzMR9QHZ2bqVfL7DU0hSnJciQTU=
%3D&amp;amp;reserved=3D0</a><br>
<br>
Getting things like this to work in kernel space is much harder, and<br>
before you look at the kernel, try to think if what you'd want works<br>
in user space. There I think any real-world benefits are also<br>
diminished by complexity and resulting poor performance.<br>
<br>
-- Marco<br>
</div>
</span></font></div>
</body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/DM5PR02MB3211D24303BB7B0CFF1E993182E30%40DM5PR02MB3211=
.namprd02.prod.outlook.com?utm_medium=3Demail&utm_source=3Dfooter">https://=
groups.google.com/d/msgid/kasan-dev/DM5PR02MB3211D24303BB7B0CFF1E993182E30%=
40DM5PR02MB3211.namprd02.prod.outlook.com</a>.<br />

--_000_DM5PR02MB3211D24303BB7B0CFF1E993182E30DM5PR02MB3211namp_--
