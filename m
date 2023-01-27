Return-Path: <kasan-dev+bncBAABB7ORZSPAMGQEREDHKGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 052EE67DB3E
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jan 2023 02:29:35 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id k3-20020a05651239c300b004cca10c5ae6sf1431922lfu.9
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jan 2023 17:29:34 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1674782974; cv=pass;
        d=google.com; s=arc-20160816;
        b=IJhb/CtS365sd0wxeyTM2Aon3ujhHziJPirIctbE0o2Da3oTa9fp+AZ540vbyqxzH2
         dTSbgDtDzxGPkmOJYfZAQXFcgJKucRa4kyKQqHfk4JTRkvLeS0lNFOMP8JvGJAYkF2lf
         6VwJNZhZVS2WhU96RJf1ot0F5XjpWNZ1eZSsA15bSfS1M5k8s4VJAj+wYgL7bikjAeT2
         AjL8niW6gO1HfMnwPjk+CycLAh0N5KhuetAJJBtjmlFsh7nik/qjY7Zhunl+0gZSTRYr
         rw7O742gu+mA4A+0yGSdU0+vge4MI2yzxIWX4h/mP4R0iPH8SP6Ex7yvAOUrk1jCHuHs
         czjQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:msip_labels
         :content-language:accept-language:message-id:date:thread-index
         :thread-topic:subject:from:sender:dkim-signature;
        bh=GDFqEg/dk0DO/y9i4049z7RLaEJPin6zVoFTHDte81M=;
        b=AalamGSkWS3ABDdzNJcyZYMWMrCUpdiI0rcPTyAkSvLv6nGBoPr/TkrLcH6aeCkw8C
         gND/zT2gWCsc6wuE9OhzTKt6TolUP/Qlri4SRDwMb8xUb11ZeqsHhV62XXPDfdiX5f42
         xoMVvWnXnreMEtsyfDVgFLP6mnHklbPm1HeAIgd8dYHVlHu7K3UFrG2wD4Q4W7D79Fy2
         4f8IC8FPe9vJohjK8XWKtZ09zdu70NlEAQ7ylcMd3p3DZ2dKwgaR64l6FgyEgfCYm+2g
         K7pSUC8UiMoCFZWWQNvAEKR+RLIOK3fP7Nr/vK2f8/C8ZMzQUmufM+XJnMGTtV72ghU1
         wdAQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@hotmail.com header.s=selector1 header.b=GnlqVC8+;
       arc=pass (i=1);
       spf=pass (google.com: domain of poostinffo74@hotmail.com designates 2a01:111:f400:7eaf::801 as permitted sender) smtp.mailfrom=poostinffo74@hotmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:msip_labels:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GDFqEg/dk0DO/y9i4049z7RLaEJPin6zVoFTHDte81M=;
        b=q75OAeiSt2NKBD0TX3X/wENrQn5vFAzsd2XHip93WN2QFmBZy4O6eDbdr/Xz/RIkK2
         V+/7bva4A1DIb75ymkUhhJClYjUCVhZK2RyOlmw5BJVzwBMg3ZcPIj7f0tKXhNDac9+n
         Nxmm2HrfymX6GrjF0Hkv06fWeeG3AZnPyUa4MlsATpDs2ESYlXqEGiBos1XQ+Z+VLNTk
         uwK5P5egziNhmrNF67vmJP6w3tFsQUvkaNqjFdOACWbIic1f2yMO4n8eGatvRlj8eG/X
         GY74nbVWLGn0gryC1wsdNoK4y2KBp2TUjqa19rgfaz3aqkMranM356bDRF7DAKIAfrke
         1t/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :msip_labels:content-language:accept-language:message-id:date
         :thread-index:thread-topic:subject:from:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GDFqEg/dk0DO/y9i4049z7RLaEJPin6zVoFTHDte81M=;
        b=Ig4dlOfLP3wdzYMpM3WnNCWywwSCHkVX3EPU8WBvqjiuSSqhp0ZgSvsaGShkYwrOlK
         kM8Nh+q/pu5T2maqYZx+OUkThrgGdFHCaWXz9p05NmWwDrHEU/A67kZzdtJyZ22J7yT7
         zZAhXF+xeT9/1h2P0xwBKBCrMd9b4rt1fXmXjyk9tdMlSB6F8CXopRT1rumonPbEyVGY
         eJ4zVeSKHd1MUN+5GCA3QUIwNjacUZwGR7SX54cP22ntkEgL0Vf6eB+321R8TNBEHaNV
         YQjB5fRZscjROAEijM2M1fJB2J/itWhdNyCVDKjHl+b5DuTrYFJX9NeM+E+0JOat1EY4
         yX2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koiTNbeVwJ5u0vhxsYEt5TSYpZ7pWajzkfRLNaSFPyYV1VZBYut
	J8d5OkzNsgnw7phG8uRFbBE=
X-Google-Smtp-Source: AMrXdXu70+3Zs1EWhtIj3KqD+haqUcj5V/aoD52zBDyCmbaGqblyRK6QaWSzGw9V5qNlsWP/LlyOHg==
X-Received: by 2002:a05:651c:1253:b0:28a:a1d3:572f with SMTP id h19-20020a05651c125300b0028aa1d3572fmr2254884ljh.20.1674782974163;
        Thu, 26 Jan 2023 17:29:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1146:b0:4cf:ff9f:bbfd with SMTP id
 m6-20020a056512114600b004cfff9fbbfdls2539483lfg.1.-pod-prod-gmail; Thu, 26
 Jan 2023 17:29:33 -0800 (PST)
X-Received: by 2002:a05:6512:2254:b0:4d5:a689:c899 with SMTP id i20-20020a056512225400b004d5a689c899mr9451385lfu.56.1674782972903;
        Thu, 26 Jan 2023 17:29:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674782972; cv=pass;
        d=google.com; s=arc-20160816;
        b=EkGlMRDnK89W9/jYyXfTKvF2dXjUavx8aggcz8YkJz9BW4ms+XKJeARp9aCfPZ1mcJ
         4CxtbL6pFU6puyjrcGehujFsQvkzQFreemgl+jkWhGPk4rVhwbTq9vu7T6t/l8mVRUlh
         BBtLh0eG0yP8/5IMthSeIQI7flEi1aFgCj5ltMC4t/9xtcHjQKrytIxrT5PgbDIWVZSo
         N0+R5M8Am450NeQISArRLYwXOUVI+kwaG2mDv4EH5jsoxTldW4jlBvnro1GnIJzW7he3
         4jAgAIl0gify1Th0H1ATVuPTA7yv6zDNKz/xL2pFtMH63SR/m+I0SYOWoLVazFRX9GD0
         4seg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:msip_labels:content-language:accept-language
         :message-id:date:thread-index:thread-topic:subject:from
         :dkim-signature;
        bh=uietF1nJiDK358xnMmaO0FMPeGinKDZzHc7VFQhg6OA=;
        b=HnDXJtvunwfVc8KddfFtXcazFdmxbRPGVMs+yk3LeHFtpIxjFxUbAxR+R/8NYWwwPJ
         MUexWcGPqiQ4G3hZ7it+mbMsusLCkFc7b4o02exvBXCQoXv2XOLG0MAC9R81ci1v87Ri
         yICJYnN0FPN5dB0pn6S8qj9KSDjTcuo5McRaIaRZmxRStHepJg5H3YeRo2I+cUzQtKPN
         eSp9ODJRmTUSCXpT5xZj6of2MNg0d+EgE5YDAZUiT0tZ/PREz28AirrG21Bmse+ZAd2t
         t2A2HKrwTSgf9BSiGfrP26gRUnUZrHNS2uUSGGt4U5+XUWcO5F1FWn4fjrbwvlZ/8FWV
         cOaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@hotmail.com header.s=selector1 header.b=GnlqVC8+;
       arc=pass (i=1);
       spf=pass (google.com: domain of poostinffo74@hotmail.com designates 2a01:111:f400:7eaf::801 as permitted sender) smtp.mailfrom=poostinffo74@hotmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hotmail.com
Received: from EUR03-AM7-obe.outbound.protection.outlook.com (mail-am7eur03olkn20801.outbound.protection.outlook.com. [2a01:111:f400:7eaf::801])
        by gmr-mx.google.com with ESMTPS id h6-20020ac25966000000b004d5786b729esi169961lfp.9.2023.01.26.17.29.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 26 Jan 2023 17:29:32 -0800 (PST)
Received-SPF: pass (google.com: domain of poostinffo74@hotmail.com designates 2a01:111:f400:7eaf::801 as permitted sender) client-ip=2a01:111:f400:7eaf::801;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=DltL1u9b45lpvnuVhvjYTYDRrEeoigyL0+5710kpfEnv43bqk/ap/r/5px/LBAYvlHOp3CWgVk/jglMSdXSeJIyoTED69u/tUw9LISrFz1uPPrJsSVA/RgSnDakSs1dPioJjUKecDzbnXqLVxNRMtoFbrPXMqPVjGTAN4yOYJ9p731lyoDqKfB5S1CaH6UZkHwQs6Yveo0wkIxAN5FdoByY7Y80tLtBnJE270A6uGlf1jwOuB6sQfpwwxjk4vnrKI62swdf1wuQWod76YOEyGd4oOJKCMIrNNbDFeW0hgYLasnXRL0SrQQRLLz2HqndJLK6aptKjXfF6p4CrfqWsow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=uietF1nJiDK358xnMmaO0FMPeGinKDZzHc7VFQhg6OA=;
 b=gxEpjtqKXIYN7scpWPT/A9LpAalKmGG/Uz8S7oZX7xyMgdhjVqtOUeYEiP2sIw10bnsVH3BxhHpyoTZ8sBL+h0hMjpNToK12GJ7Qy2VjGcZK70Wpkj6Z2e84Ou5IPM3NEOSUDC8RkYVEl1mFSa2HwSN5JOp/7pzJu046Fy6WtCFqkeR94+HNl0I6oGLvERXENzxvREzETxvpLJMdiRb1yojIGI/fS6/i5h3vyzCHPjcRz66m7m0oKdptaCtRmRDTClTB/5CkSAwRfEPPBtlDLix7uLpCSEbo0eHAY+ss9wX+zj38edKNavRpn7skW1aoE24zq+p7BsqcOq7Zq80KPw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from PAXPR04MB8318.eurprd04.prod.outlook.com (2603:10a6:102:1c0::7)
 by AM7PR04MB6822.eurprd04.prod.outlook.com (2603:10a6:20b:108::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6043.22; Fri, 27 Jan
 2023 01:29:31 +0000
Received: from PAXPR04MB8318.eurprd04.prod.outlook.com
 ([fe80::723d:f89:5f0a:e35a]) by PAXPR04MB8318.eurprd04.prod.outlook.com
 ([fe80::723d:f89:5f0a:e35a%6]) with mapi id 15.20.6043.022; Fri, 27 Jan 2023
 01:29:31 +0000
From: info you <poostinffo74@hotmail.com>
Subject: LinkedIn
Thread-Topic: LinkedIn
Thread-Index: AQHZMe7OiuTuxZSKCUK78iOVkjBIVQ==
Date: Fri, 27 Jan 2023 01:29:31 +0000
Message-ID: <PAXPR04MB8318E437ED9EB082367FC5CED3CC9@PAXPR04MB8318.eurprd04.prod.outlook.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
msip_labels: 
x-tmn: [FuKJQI+1pl0BcBappuH62X/r0E+zJdvU]
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PAXPR04MB8318:EE_|AM7PR04MB6822:EE_
x-ms-office365-filtering-correlation-id: 7f21f268-f9d1-4ecb-b7ae-08db0005f085
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: B2wxP+6vntX2QeNMUkKy96xLFWUrr0peaje7ud2dC0RnXv8dyYwH7cEpovKwo50LPzt+UnzdPqbvSZgFrggNdsSavfBYTmYdjDP6qb/kclvzrXeq8UKKNaIqeINoh+cDF3BaTngvAufrtLHpNNRI0KKmoMRwVWFwGrPj/ECAZtjh0DilovQtX80hPh48VRlZGUV+xh0bsku/y9FsDRmxg2obNyrYlQ4/i6XAMC1bFzD1wbthAh2Wi76bmn58VWTMR17SeB+7WFV946Hocyagq57m6GQfz8x0HmYnRzW70X0t5sAvFuAMox2gudDuWV6+sGv0i78hMZV1tvhcdLVp58B/WlEoh51oX07sTX3ZnqAt2ItJb0+ue1MN8XQeHDp7KMMcOLuv0DsTbxpBMsAGnGf28Fc3LsU6cE4KwP2kswL70UXBeonKDm5S8NVGTTKPtr3eA4AAYZQMEj2cQmfu7TXWjEJhjNSb/dnMpCPLK7QSs4DMww7FWERRHIcFRZnWsl8eXPbiSuhGgyJGGElzvzrwB3yMcRMhKNmyOfYAC7ctH9uhiK8p1FAZtuq5wn9ngp1/ZEoJN8uPslsuq6hn1tElrkCI4cbYXpPfCAZiqBM=
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?iso-8859-1?Q?OlNwNF8g5xmV82P5Pu9RC64tlcFKvV6cQt7NW/XJrldqYhSpzuygsvMOTi?=
 =?iso-8859-1?Q?Hak1RZlzmtnCUlw/HT2LtFylVTcc1qs/psk/ARNoOMyRW0FqKfLc1rl/C0?=
 =?iso-8859-1?Q?ZWcCR9JlIG2uzlbxvlz924zI/QqkIkgd/4FWEE3nD6gl8SOYuZB+9agRAL?=
 =?iso-8859-1?Q?LUuWMBt20oxIVRhwaaNZd8/VuPMCBp30Jnj+uKcG7ndAKDL1uShyz/k4tq?=
 =?iso-8859-1?Q?8Bl6WDo5z1OHZ/0TpycBD35g7JDVQV/fW6KytfTdJpfe0fRcZrJCHOG0Fb?=
 =?iso-8859-1?Q?1UB+BDIbxhc8piJGB2NRocyi8MnlPKVtwXwV1yF4ocquipvxPnLFl1AqGG?=
 =?iso-8859-1?Q?7Guf3LTlyABEiFkpNiVo88a6JSdCxpNtX7lfuW/HyuBdIxoFH7em/s9kdL?=
 =?iso-8859-1?Q?JA23pwHgFcwOAAKcX6bZPb6nYq4kSaa2/x9ioBdlQMbaRheuqafPIqgX2B?=
 =?iso-8859-1?Q?Uptd2EBP0cDRtvDnHHzS/A+O3Nq0xHu93RreZExsS/4eRXZ1GIUMgwjTV9?=
 =?iso-8859-1?Q?eMsXtt2ciOHJbHTB6lq6O0EtG3mmxky8AwzG2L2tj2Rm609LADSech1tEj?=
 =?iso-8859-1?Q?aY61TkgqVMq0ckZGx8puzs34H/V6VuJKMhdWdXXHUE4zGLgKc0vlwv7knI?=
 =?iso-8859-1?Q?q2bTROL4LHvfR1PDZN5o37S7P4YNUA5KhmTvxK2sIgFhcSIZ8x6ed8ZkiU?=
 =?iso-8859-1?Q?5/vXHtZu/LTgwHYpsZJsfaVQPGPbnkTDSQq203XhmMSRXDog5ApMpl61yZ?=
 =?iso-8859-1?Q?P2Cv0+fmB6VnlPV7aKLvkbQG3Hit2asgJ30nuv4ndlim71Xt4TLIB9yeuW?=
 =?iso-8859-1?Q?eXEvktICkcg3urFt1Sh9JLh8wpakYtNo5TIY3NK44RfyJBLvE/Bpa2hSrF?=
 =?iso-8859-1?Q?2rnd1vy3TFa/5mkchGcG/6xWsZGqZRcBOImbSZqQMKCLcL7rOKvP7YCBqr?=
 =?iso-8859-1?Q?A6d8teChWeGgul1ggX0CRJAwqmK35h/oOAnrj7IgQFCWv0CTCHKksFlBiA?=
 =?iso-8859-1?Q?wx7I4Fpi6lwDOpsExRSqrEfMqNB1fUxh0PwL+v6z9IZq7/zrDzzBheVUCY?=
 =?iso-8859-1?Q?EkWbWDOFwF3yRe/LuxDkCsACDW16tJBsT9fSY6tkssf/jt8QllYUeJVvdB?=
 =?iso-8859-1?Q?8WtyY5TvmyKzvbVjjstd3Kf+NM7imEkLdMUcqiLtP7+JdzJ/rk02dsyG32?=
 =?iso-8859-1?Q?zYot5Ixob66paL3R7hdXJhWNlJ4pBqPFPv1maeczsh5wO7hNZKGm/RJymm?=
 =?iso-8859-1?Q?gOSb/g6yPCNk9VWYd68o+0WTsckNU8bMKrVTHxTerGkxhO6M+2FdWv6zKT?=
 =?iso-8859-1?Q?sPitzz3Fbsb7/2B9xBXahImZDA=3D=3D?=
Content-Type: multipart/alternative;
	boundary="_000_PAXPR04MB8318E437ED9EB082367FC5CED3CC9PAXPR04MB8318eurp_"
MIME-Version: 1.0
X-OriginatorOrg: sct-15-20-4755-11-msonline-outlook-03a34.templateTenant
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PAXPR04MB8318.eurprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-Network-Message-Id: 7f21f268-f9d1-4ecb-b7ae-08db0005f085
X-MS-Exchange-CrossTenant-originalarrivaltime: 27 Jan 2023 01:29:31.2564
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-rms-persistedconsumerorg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM7PR04MB6822
X-Original-Sender: poostinffo74@hotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@hotmail.com header.s=selector1 header.b=GnlqVC8+;       arc=pass
 (i=1);       spf=pass (google.com: domain of poostinffo74@hotmail.com
 designates 2a01:111:f400:7eaf::801 as permitted sender) smtp.mailfrom=poostinffo74@hotmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hotmail.com
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

--_000_PAXPR04MB8318E437ED9EB082367FC5CED3CC9PAXPR04MB8318eurp_
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Bitte ist das Ihre pers=C3=B6nliche E-Mail?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/PAXPR04MB8318E437ED9EB082367FC5CED3CC9%40PAXPR04MB8318.eurprd04.p=
rod.outlook.com.

--_000_PAXPR04MB8318E437ED9EB082367FC5CED3CC9PAXPR04MB8318eurp_
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Diso-8859-=
1">
<style type=3D"text/css" style=3D"display:none;"> P {margin-top:0;margin-bo=
ttom:0;} </style>
</head>
<body dir=3D"ltr">
<div style=3D"font-family: Calibri, Arial, Helvetica, sans-serif; font-size=
: 12pt; color: rgb(0, 0, 0); background-color: rgb(255, 255, 255);" class=
=3D"elementToProof ContentPasted0">
Bitte ist das Ihre pers=C3=B6nliche E-Mail? <br class=3D"ContentPasted0">
<br>
</div>
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
om/d/msgid/kasan-dev/PAXPR04MB8318E437ED9EB082367FC5CED3CC9%40PAXPR04MB8318=
.eurprd04.prod.outlook.com?utm_medium=3Demail&utm_source=3Dfooter">https://=
groups.google.com/d/msgid/kasan-dev/PAXPR04MB8318E437ED9EB082367FC5CED3CC9%=
40PAXPR04MB8318.eurprd04.prod.outlook.com</a>.<br />

--_000_PAXPR04MB8318E437ED9EB082367FC5CED3CC9PAXPR04MB8318eurp_--
