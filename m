Return-Path: <kasan-dev+bncBD653A6W2MGBBDEC7OTQMGQEN5L75BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A2D279A463
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 09:26:06 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-31fb093a53asf135488f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 00:26:06 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1694417166; cv=pass;
        d=google.com; s=arc-20160816;
        b=fssnqREQmuHxhCEHzTA/f1v+ekyGmStxtdJTi03Kx2FDWyWhmUYcLbG0Ym4qM2q/+S
         WLGs4lT/6HK5K07nTLDNmDTJQaYqnodd0KAmafs/bo0RC0qYeEpiugau1iSAjmhxloG+
         3Z+nwCHm0D0uJIWHUld33bhur9mmoO1Rzg5hTE5As6MfiqW2Ckb1gjLEB+AFcDF5FNgZ
         ELGOTibn2s5d2dowIOxItbdFrGHTjzR0Y4XcogvXQkmTKN9hEjN4MD4Gz5qpjYFTxAX/
         EZrUgL1jyziBgutbzohm/JUO17iMOFMsE4XM06pmzjN9gj2fxka37kRkYyIqykwLmIh+
         MeQw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=AG3ucvTtq4dKMDl30dP/BZBdV7SawzY5dv0MRP3uL5Q=;
        fh=cStHs8nurMcRrD0GCje1aqtL62RajPtE5HeoLS0mlRk=;
        b=ToLecTns4jwZHfk3La5A3phmwdYnNBPrZ8FfUgY3yG/QzOxmbshu6zlxsHDZKAYKXO
         iUM/XeJMLNLpaReKcDOxmScIPwVc2iKBasBUKRajbM7HkURhf4q9LRdxq7i2mR/eegrn
         jXF8K5ZoABCXDg0yFSOiIWFYmxoToW5SAPCXghNPsEOrl3Vz25KqlCrC43FwRD7kz3r5
         nWOe1u4kY8GYdPS/vOvtB9O+OQGxajuTCWnXlE4aA6jjg1xQIuRVFd0QXTa4Oo/lK92t
         sxwBW3cD7vrp2cJddBeYbuPrK9/F42Kh7+lL5C/LsZNAYTCO2O4rVLQ/OyLmdR7u5g53
         1NEw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b=BfW0YSO8;
       dkim=pass header.i=@axis.com header.s=selector1 header.b=fP+UeHy3;
       arc=pass (i=1 spf=pass spfdomain=axis.com dkim=pass dkdomain=axis.com dmarc=pass fromdomain=axis.com);
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.18 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694417166; x=1695021966; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding:content-id
         :user-agent:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AG3ucvTtq4dKMDl30dP/BZBdV7SawzY5dv0MRP3uL5Q=;
        b=ZnvftWvP1yNjc45SMQl5sOuwkJd1IgNnykvP2p4Mx9vEiwOzmZUA8qiQv+PlgwebvZ
         ScVf5dlHu3Y+J0ft3cI9Xsu4EE9XZC6m0XYuvu2t1rnljQrL6b7vzmlFDNemlsri+u4p
         pITrtaO3c7zJTCTwxKHxxSLW38Q1d9zZvojUJ6SsK+UcZCmUXeNSmNgUlHSScXWeK3Dj
         8tQ8Yl6LUFFZGD7EpQr+ZassS96P+75o9muFm7A9xfArtulKqJyjVS0GSP54iYmkPDhi
         7h5qyF4tlr3kvD4ptCXNjDFTGIcC0ZLu06XngY3c+FwJuXH1BDCptYCWpEdcFZ7DZI3C
         mCkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694417166; x=1695021966;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AG3ucvTtq4dKMDl30dP/BZBdV7SawzY5dv0MRP3uL5Q=;
        b=lLY0QtF6EpvkXbqjh+zaJvArM9IQti+h4lgzgOCG0SVyQOxlmuUNrAvzx4oG6bT7bD
         N45V7Jwrni+Ja2YFqxEO7dGSNUBiPZwgk+gxyjj33G3UqvOHZyS920oNkNWj4NxXYw30
         GcZxmNBYL7Qgo4i6nid2FQZMrI9YPX9wlsRcTycA0MXPT3/3VvoXZrJc2baEcnbzPVdz
         ju/AroKoBZ9RhIdkzbIb/1o2ymAiidiQ2nGAnSss4Dk+rL3UTF7x1QIwS7emCffPAjJj
         ZKE0+nA/nXYaBDuJUdHJ5glVLncx3XhW+UJH1dZnv0x3loZwu+Ub1S2j8Izibfll0xEj
         Ppng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzBISGhS1z9ykAjcQ+ZJ5XFcSW7qdkdRnSJmb+6YrMVow4CzSQ9
	VCdvUoYLTn0wedLwn0e0bLk=
X-Google-Smtp-Source: AGHT+IGuCEak8GVFB/ctfV4DDOF7h0nDAWB7oERUeinIjjycSvurT3YCpC2cLW3DDinbB1PDc85srg==
X-Received: by 2002:a5d:6309:0:b0:319:7295:311 with SMTP id i9-20020a5d6309000000b0031972950311mr6783434wru.10.1694417165194;
        Mon, 11 Sep 2023 00:26:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:624b:0:b0:313:e6b1:8d51 with SMTP id m11-20020a5d624b000000b00313e6b18d51ls987511wrv.0.-pod-prod-02-eu;
 Mon, 11 Sep 2023 00:26:03 -0700 (PDT)
X-Received: by 2002:a05:6000:12c8:b0:319:6b6c:dd01 with SMTP id l8-20020a05600012c800b003196b6cdd01mr6902930wrx.17.1694417163471;
        Mon, 11 Sep 2023 00:26:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694417163; cv=pass;
        d=google.com; s=arc-20160816;
        b=eQp2bpj7vMiPvg1mMAJr1Mv+OOUnQJOq0ZqZCjQDIFq3PnM4pnjWyQCXq+9/BhBCPH
         qzYpb8JKoqldJt8fKjEf9AtZs2chRanSco3UrKPZqqlcJ6t19oGyiEEGJj+05bcQEZFi
         fAaCXSOny7HY4Wkru+EUCv7jAwvUh2kjSTYaxYfRhvo97Zz71q++6+8Bq6aJ9mO/9aAQ
         lMo3fcBJtawlJeSDByFhe+wa9KFkm3EqyXjdb9bKOor0h8cncWUE8CO5WU/EqI+Tq2un
         OnDkoszzq0RxQuncaZyz7thI8rRbY5KWXujESemXs0WrMdOtoDh6G7BUqAREIYC+m4wE
         zO0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature
         :dkim-signature;
        bh=SRzgu3whToxQprH/a+lTsuIbz30UkQmXZTNxXmYZvVs=;
        fh=cStHs8nurMcRrD0GCje1aqtL62RajPtE5HeoLS0mlRk=;
        b=U5U9pHkZTf2Iqx/SppzQoMa9Uyk9DkimrMhyXN3lLCv8qtypueHqbo5nZAc48l7ycC
         T4EF4OmiF9KtOcpwKmFaDNaWFo1GkWWbYzyrg+tVQjDtbHLRWeDRpA44T9mMWbNbdi9Q
         in+PYCRzvRMz3DknYWZEnE0IDmFDxsW6SPMoaHJ7Vo4lW9Iul4ttfmJSvlXFc9NJZlMO
         Vn0visa01tXqmDpPgN1/zKvlKmuB50BVIC6lCSm7aO5QcH7zaLCPkzsTWORupi2y1Wba
         O7qS2ZtqZHp0Ur7OVAyLkcqIDUKfP+K18VSOj93m5QSjZOrzJmRgc/xz+aN7eF4420zs
         LkIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b=BfW0YSO8;
       dkim=pass header.i=@axis.com header.s=selector1 header.b=fP+UeHy3;
       arc=pass (i=1 spf=pass spfdomain=axis.com dkim=pass dkdomain=axis.com dmarc=pass fromdomain=axis.com);
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.18 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
Received: from smtp2.axis.com (smtp2.axis.com. [195.60.68.18])
        by gmr-mx.google.com with ESMTPS id ba17-20020a0560001c1100b0031c3528356asi489654wrb.2.2023.09.11.00.26.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Sep 2023 00:26:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.18 as permitted sender) client-ip=195.60.68.18;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=mnoaSvjRyeKvacG4VRoaGx18DA7PH4rPnICobChmYN3mj1UCGef88l1oePMsZp9VvGFRazqsDHsnEkXFsppWaDrY6SGLNItSYINjT+NsrJrXbT5StjGXn2Z0bCA1u7Rudvxn4YxdwmXDP1M97nxe+OrDpMJiNfy0hCT3m58PxQkTFrAkR+QarbTw1QvR4gDwNeV9T7iplqniyrbXbrQ2KDfMXz8nNzodseMU2iCaY0IW+YkQgmvQfvNdgijbvwnKpcs+EO1kEcI9637t0bARc6BjhYN8S9J/foqEv//0qZeiLm9DhGHAEV+SC5etwZNF0kCsPTxtK8PQWpdmg0XTVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=SRzgu3whToxQprH/a+lTsuIbz30UkQmXZTNxXmYZvVs=;
 b=YmqzomdOdNcxQWuepWN3wCjQ8Q6iaxuxJaPXPvhMMmW02PPnMTq4f9e7Yyy5GvvLkX3O4SwctDRpzjEJF/my8SEjpKjYXDoMeJQDqDukLzlNN6/UviDqpoZLD+FfMYOgL1g09Sb5oPeJEShhdavMaBSro7EDylrZJKYR1Mhp1l27nMFydAOXESu+umivW2sQ9nArI+KpXmkTgxLl70RyeagfksGVV9zNRRoRmSF0wwIqbwPo6uXmmP8/WG9oElxyCuF+lrTBJABUz91JoEckOQm8Q+tMTgr5keDbegRl8dPhZ6Jz45ySD1AxYSct7hoQstZhD+8Wh4/N8oZZXaKIkw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=axis.com; dmarc=pass action=none header.from=axis.com;
 dkim=pass header.d=axis.com; arc=none
From: Vincent Whitchurch <Vincent.Whitchurch@axis.com>
To: Vincent Whitchurch <Vincent.Whitchurch@axis.com>, "davidgow@google.com"
	<davidgow@google.com>, "x86@kernel.org" <x86@kernel.org>
CC: "dave.hansen@linux.intel.com" <dave.hansen@linux.intel.com>, kernel
	<kernel@axis.com>, "rafael.j.wysocki@intel.com" <rafael.j.wysocki@intel.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"johannes@sipsolutions.net" <johannes@sipsolutions.net>, "mingo@redhat.com"
	<mingo@redhat.com>, "linux-um@lists.infradead.org"
	<linux-um@lists.infradead.org>, "tglx@linutronix.de" <tglx@linutronix.de>,
	"andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	"anton.ivanov@cambridgegreys.com" <anton.ivanov@cambridgegreys.com>,
	"dvyukov@google.com" <dvyukov@google.com>, "richard@nod.at" <richard@nod.at>,
	"hpa@zytor.com" <hpa@zytor.com>, "peterz@infradead.org"
	<peterz@infradead.org>, "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"frederic@kernel.org" <frederic@kernel.org>, "bp@alien8.de" <bp@alien8.de>,
	"glider@google.com" <glider@google.com>, "vincenzo.frascino@arm.com"
	<vincenzo.frascino@arm.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>
Subject: Re: [PATCH] x86: Fix build of UML with KASAN
Thread-Topic: [PATCH] x86: Fix build of UML with KASAN
Thread-Index: AQHZmsQx3HM02RYVik+aPUiiZcEw2q+Dtz2AgJIVpwA=
Date: Mon, 11 Sep 2023 07:26:00 +0000
Message-ID: <f11475f922994b88f5adb14d23240716e16d5303.camel@axis.com>
References: <20230609-uml-kasan-v1-1-5fac8d409d4f@axis.com>
	 <CABVgOS=X1=NC9ad+WV4spFFh4MBHLodhcyQ=Ks=6-FpXrbRTdA@mail.gmail.com>
In-Reply-To: <CABVgOS=X1=NC9ad+WV4spFFh4MBHLodhcyQ=Ks=6-FpXrbRTdA@mail.gmail.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Evolution 3.38.3-1+deb11u1
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PAWPR02MB10280:EE_|AM9PR02MB7025:EE_
x-ms-office365-filtering-correlation-id: 61b264f8-e9cc-43c1-9cdd-08dbb2985982
x-ld-processed: 78703d3c-b907-432f-b066-88f7af9ca3af,ExtAddr
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: tyQAgTc/SJWWnEdiM6MxNgWcSn26rIicqz1SSz9xYWyimt94Pt3US0vk8+nfCLFupmXeOL1C5E3cp4lPVg4uipeguvZs8WxEb31aiH85K3rHDe/5VppS/8CFnlurEKzYkkgIV1VQP/9hl0ZjYg+xfJfccnC5OkAj2Q4Cw+urxiJ7NDtTdrumRqkTKjOWx5wEGS4HCRrg/BoBIXwWxPfAwCEAkz1GYzjGj9hXGV3PT0oLaeRNY1LPfHpzoEJkxM/q9l/9Wm7UvvXOIwlJRJMoT5Rs3/CwYQkuveCDv2OQ0kFK6aoHruhBerjbOregT6dNde74iAWzdKeaK7CRgqF2W+V0uy6UKRwCdSXAwcmk+Vv2RfIVr2mkY3qcc/LlLNnlZ6bKY0miC+NsXLz6RwnU41yf5Ms3e5Bnsr9Oet2a1x5XPP1uUrq6kaSeXFYU/gEZ4ZlLh3bwBthNy4TGTZ8V/NDbZBWUEv1PEasxU3fTuuoBL+eLDsAuRkjBTZh2uSKIkke07A7phpYRW1sPIqeq9C9b1f9CM7ople/OgiMjy7FpGVFiTcLLfLOUPTPy6O9fctIA3mtL+67glWWBKy/qJzeu3sc7bwhY9qKL5rUsH6VScHzXQgzxjMHNiFkoeihu
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PAWPR02MB10280.eurprd02.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(366004)(346002)(396003)(136003)(376002)(39850400004)(451199024)(1800799009)(186009)(6512007)(36756003)(2906002)(7416002)(5660300002)(316002)(4326008)(8936002)(54906003)(8676002)(41300700001)(64756008)(66946007)(66446008)(76116006)(66476007)(66556008)(6506007)(478600001)(71200400001)(2616005)(38070700005)(122000001)(86362001)(38100700002)(110136005)(91956017)(26005)(6486002);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?d3JqMjZsZkVhZ1F2cGE1OTRzVkk2cXQ1Q2VEV0pwd2p2TGdZU0lFRzBXVnhp?=
 =?utf-8?B?RTZ1SjV5UkdLd2tSbUw0akZ1RWFXNlMwd21La2Z3cktZc3R6SStmZFUxekNh?=
 =?utf-8?B?YnpPbi9PTTF6VGNPN0VmeGg0K0diQTB3T2dpK3VJZEFEZFh5dUNaRzlzamdD?=
 =?utf-8?B?ZVJHc2tWd2RSWUhhOEQrVGlkdTRNTnE5NkpYTmROdThDVElxRUdXNnN1eEt0?=
 =?utf-8?B?UkhLbFV5d2VMclB5bHNaM25xWU0zTDJMajE4WFBMQXNVbEZkV3V4R1g4eFo5?=
 =?utf-8?B?dVBaeGN5WnpGbXd1QzJnVWNvMjJ4Q2MwMFlUTkhpVE9kaG4yeXMyUGdyY2tm?=
 =?utf-8?B?Nmt2dlluT2YrcE9jS2xrMHZ3RFB4dHY2VkVONXBxZFJtTXl0WWZIOGFGNTlW?=
 =?utf-8?B?UC9HdndXeTBINjdHajQyT0RaWFRHbU1JeXFTL01hc1FtVCtGZXRkamVlc1NM?=
 =?utf-8?B?Ukt6N2ZhdVZTdnpFUjVYRjNYa0dScVhkUjVmTGZiZEdTdnBFbDJxUGZnU3R0?=
 =?utf-8?B?OExreENhY2x3M25acWE2WWZxMFZ6U29CZWx2eStLbWFwMHI0SnpUTlBnSWcr?=
 =?utf-8?B?ZmtjY2h6OWViMm1yK1JZNldCdjZneEhnTmdtZEhYaGZZa3FwV09wenkvVGdX?=
 =?utf-8?B?YU85QW96WGlvdUV4UEErcHZvTXN1eWRSeGgwRjFvUGVSdUkyWitLTmFKd1hL?=
 =?utf-8?B?czV6Nm1KU2IvUUlITm5KQWROVDhtclFrcXlvUFBtQkVObEt5eHhSV08rMG96?=
 =?utf-8?B?WjltY0FCOHRGSmVJai8va1NoOFgyelhiV0lrTnVnL1Btb1NlSkUrU3llTHBx?=
 =?utf-8?B?bDNENUpKK25NT1lma2hBL0Q3MGVoOHBEU3FuMnVQL3haU1MzemJ2V3h4STZR?=
 =?utf-8?B?a3B4MFJaOVNwMzExaEJhU1lqc0pOWlhoZTNzUnpOWmdJbEtrNW1rUHZVTW9s?=
 =?utf-8?B?ZEhqSzBCaGZYNjA4K1AxRFFYZUxsL1NGTFQ2c3lsOFNkdHFsQlBxcVZCZTNS?=
 =?utf-8?B?T2hJNDRUbEVJaE84RU1HR2JCdldZWnEzT1FtRUZPM0RrZCtrYXdEMlhhZ3U2?=
 =?utf-8?B?bjZFVGVpMk9jNEpRM0tXa2U5MDdnTVRIYTltbjMzd21aWG9SSXc4QWQ0aG1n?=
 =?utf-8?B?cXVJbUw2bDBSenY2czNReFo5WTBGZVg3ZzA3ZVR2QzNuZjZzYW1qSWZESTRP?=
 =?utf-8?B?R2ZGcHRIem9ObHA1empnYTRDMHdqNHFMRjhRSy91OUxaVU9OK2JTN2ZRZXEy?=
 =?utf-8?B?a1gyUU1WeTk2WERYY01pVzRXeGM5YzhkamY4QnZUOVY0a0lQU3ZROVB6eTlO?=
 =?utf-8?B?aXRpREJlbzJHbXdaWXR2endjY25YLzc0dEQyUDF0YlBlSXlBbHJGM2FOSmg5?=
 =?utf-8?B?UEhOMGlnMW0xQkwzd3dqYTdrVVRRSzM1V0hDdk0wTXJINm4rOWNrTmhPM1Bq?=
 =?utf-8?B?em1QMG1lVitycS9YcHppVk9UQVg4bVZPRk5xZFdIZFMrZ1U2TTZQZzlzamVp?=
 =?utf-8?B?eDNVbGFUMUNjckIrU3d3VUxidVg1VmcvV1U1aGFCNzFXTnVnR2lCRFpEZkdC?=
 =?utf-8?B?dGluUVplOHJRNk1FS1lUSGJManBXVEs5eG50cWRRcE9VeTRORTJ5ZlZaU0pF?=
 =?utf-8?B?Y3hITDBDKzVXdTgyNmJPeWZONFpLQ21xZ3JhNmJUbW1keS9WSFVqZ3lUNW0r?=
 =?utf-8?B?WUpVTXBWUHplR2E4VC8vb0loYjlVYWpqZlFsd1hjek9JVzd6dWNhbHpZVU91?=
 =?utf-8?B?SzFxM2FoUFhvQUt2SW12NlNzcEtqTmNwcklvK1pOSk5aeUJFN29ac3ZyZHdo?=
 =?utf-8?B?dStGaFRZUTZ1c2p4WFRpdGp0T1NSbkZxcjNOUnhVZ0R5NWlhSDlLNCtCalRi?=
 =?utf-8?B?Y3lMZ2JrcVptTml4NG9tVWFTSGdERitDTytCSmM5dWQ3L1RRa2hKWnpzNGdV?=
 =?utf-8?B?RUpPU1RPMzFZUml6MWsxektCcWhITURqOEQyZHJQUjVZbytxQUN6aklBRmNW?=
 =?utf-8?B?TEk2eFpCYzBpYW5lenJlb2lpcXY5TkFpM2ptWlZZQjZGV1RRbkF5V3lRMWJV?=
 =?utf-8?B?bjhhN1lqMTBkTkFRZklOc1hvcSt3Z0FsSmlyV0Nnb01LcVJDUnYxZ2NtNWl0?=
 =?utf-8?Q?IaYY0EkAbJsqQAXQk9ioyi+oa?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <6BCC8F6AFFCD484EBD9947AC06F8E329@eurprd02.prod.outlook.com>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PAWPR02MB10280.eurprd02.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 61b264f8-e9cc-43c1-9cdd-08dbb2985982
X-MS-Exchange-CrossTenant-originalarrivaltime: 11 Sep 2023 07:26:00.9245
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 78703d3c-b907-432f-b066-88f7af9ca3af
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: nk5dOdAUwE3/0v3eSZfZkE4BOvIGu949nbgvPrlgP3LAcKFNLQ1Re3CyskuBXV1H
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM9PR02MB7025
X-Original-Sender: vincent.whitchurch@axis.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@axis.com header.s=axis-central1 header.b=BfW0YSO8;
       dkim=pass header.i=@axis.com header.s=selector1 header.b=fP+UeHy3;
       arc=pass (i=1 spf=pass spfdomain=axis.com dkim=pass dkdomain=axis.com
 dmarc=pass fromdomain=axis.com);       spf=pass (google.com: domain of
 vincent.whitchurch@axis.com designates 195.60.68.18 as permitted sender)
 smtp.mailfrom=Vincent.Whitchurch@axis.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=axis.com
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

On Sat, 2023-06-10 at 16:34 +0800, David Gow wrote:
> On Fri, 9 Jun 2023 at 19:19, Vincent Whitchurch
> <vincent.whitchurch@axis.com> wrote:
> >=20
> > Building UML with KASAN fails since commit 69d4c0d32186 ("entry, kasan,
> > x86: Disallow overriding mem*() functions") with the following errors:
> >=20
> > =C2=A0$ tools/testing/kunit/kunit.py run --kconfig_add CONFIG_KASAN=3Dy
> > =C2=A0...
> > =C2=A0ld: mm/kasan/shadow.o: in function `memset':
> > =C2=A0shadow.c:(.text+0x40): multiple definition of `memset';
> > =C2=A0arch/x86/lib/memset_64.o:(.noinstr.text+0x0): first defined here
> > =C2=A0ld: mm/kasan/shadow.o: in function `memmove':
> > =C2=A0shadow.c:(.text+0x90): multiple definition of `memmove';
> > =C2=A0arch/x86/lib/memmove_64.o:(.noinstr.text+0x0): first defined here
> > =C2=A0ld: mm/kasan/shadow.o: in function `memcpy':
> > =C2=A0shadow.c:(.text+0x110): multiple definition of `memcpy';
> > =C2=A0arch/x86/lib/memcpy_64.o:(.noinstr.text+0x0): first defined here
> >=20
> > If I'm reading that commit right, the !GENERIC_ENTRY case is still
> > supposed to be allowed to override the mem*() functions, so use weak
> > aliases in that case.
> >=20
> > Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() fun=
ctions")
> > Signed-off-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
> > ---
>=20
> Thanks: I stumbled into this the other day and ran out of time to debug i=
t.
>=20
> I've tested that it works here.
>=20
> Tested-by: David Gow <davidgow@google.com>

Thanks.  Perhaps someone could pick this up?  It's been a few months,
and the build problem is still present on v6.6-rc1.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f11475f922994b88f5adb14d23240716e16d5303.camel%40axis.com.
