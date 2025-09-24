Return-Path: <kasan-dev+bncBDM2745SWEORB35HZ7DAMGQE3XXKFWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F5B5B998FC
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:20:17 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4b31bea5896sf64455021cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:20:17 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758712816; cv=pass;
        d=google.com; s=arc-20240605;
        b=EE10nF+8Ka6i20ZRDCGmMbMrS2lgmNrTBi34prJUPK7bFw7elspnzgc5S0zBKzrjoG
         9sERh9q00YLhC+ncCtgSLRNUnuHpGlu5U1hWq0NKLDHqw5TEO5X//nF5vT4ABBVuKgnP
         v4s+EMWkcmSCOA0m6TVGE1M8wL1bc/he3EtEqthlUSeSJRB4Qlyo+lohdVsnCQmhUNzx
         qme1at9+HwGO1lOWZDN+lhsFbcuhYd46V9LBcR/5FnQ9YLFEUDGFZDOkpkZ5HRMgZNoD
         atbkBrWd4Bxc/R89l6jh8vV6YYidFWMFJhNWEX1p5damSpJlWmaBD+CbVhNAogOHu4We
         F/bg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:msip_labels
         :content-language:accept-language:message-id:date:thread-index
         :thread-topic:subject:to:from:sender:dkim-signature;
        bh=MoQgKAd+DPaqNW92LTebLAFJJZbl9j8VfO5U12qMwQ4=;
        fh=0CZ6KaAMTanT51lUJSQJ03z6ccuRdgz7EItrM17b6Ck=;
        b=ASqC12xKfXwJnw0xDJlZg97BDeMDkkV4E5hx3JoLOztCgko8G1x4x6hCgA+trPW2zl
         MOUbfcjQweqIhTA6olC6ozljPkco2oLLmV4Gy+YGT3fXoy7t6NKuOsUyi9WI5ZY8BGmj
         k+QUypn2Q34vxO65NXAzuIikxEWRYIUYCIH0WUQVAm5NGUJ+/ZC7Ka0/y1WpAXi5kTF2
         nCOj+VqPhtSfcp+epHlmYIztjWSPmW3OIgK6eP1TqvAr6kgCb+WkwYaGw46tDjhFPKCW
         rt5NhGuH/CJ63JRkYgJZMkJscq1WbU+4OtdMOVj0V47eAFyqkEoly5AbLPbtoDbHViwM
         YrVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=riNpH9Vq;
       arc=pass (i=1);
       spf=pass (google.com: domain of https.www.benjamin.digitalmarketingservices@outlook.com designates 2a01:111:f403:d405::2 as permitted sender) smtp.mailfrom=https.www.benjamin.digitalmarketingservices@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758712816; x=1759317616; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:msip_labels:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MoQgKAd+DPaqNW92LTebLAFJJZbl9j8VfO5U12qMwQ4=;
        b=qSzawFgF53uV1O7D1PeIdO8b/ypc/Jih4VAgBFIMBeaMLkY7rVmQKeDv4qvDu0KwJH
         e4GFaSHTw1h69l1f66u7Dk7DJnZVASh/sRrj0N00TRk+ISsKQVhy1HF/icLxU23INfnm
         SQ8dPy00SIIQXEp6uHtofMlXIMKDUbbJn5lB+peE5pixzy1q3MOY10oFUeVN5tVfhg59
         mKhvDJvCaajc3iShU2dbn8Z2cXNgLuea8AZD19zy3Z9bfG5IYQk2+36VfQgL/bDN48wa
         OCcD9KJYgYmOKtHX6cgeSUcNANEJbZps/TeXww5wpFH3y6CWG/OtiUVZAWjkGoMmcaT9
         nBLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758712816; x=1759317616;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :msip_labels:content-language:accept-language:message-id:date
         :thread-index:thread-topic:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MoQgKAd+DPaqNW92LTebLAFJJZbl9j8VfO5U12qMwQ4=;
        b=s+DHH0XEsbptzqM+2t9V3Hqv8OI+nvNdm03SIzcOlgNb9zzyb7w++/iwpELMj8gutx
         XQmB1Y5FlAjNdnbGjbDhGC/XMQoJHa4SHNUHjQhY9nbs9xeH3RYcHnIQtPASUZhXbsmI
         W/CbslVXDv3Z7ZFLsekxOklincW7A9NSlSUgmHl3EkWb86PPKjMPrVkGqqc23Fk/Guoo
         svIJcvSuW/0Uj25VG7cnRWPWq6Zcrgd5fW2iroAfQKKxc3r9br5htSuowKonLao7fZpg
         ZeunWvpqiH2MUCI1hfyEuXPHIhUurf58ZB+kbC3CtUmhfB32rB73VKF5VH7RjdH1PsvW
         noWg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCUTUBnwhFrKuvOZ21hGSgNGtoMeB/jAIhXxAT2RsuoBFS/MiYOaJG+DxBfGqQp5P3vj4U8LrQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywiw5RtIIxu/G1M+2ELfGfTA43XfXAzsW3fTQptObattLahXxBb
	BCpQpDMx2vksc3u/dWKPR31KYIWK+YzD98FG1YJX1igvRW3eHpSlTNWP
X-Google-Smtp-Source: AGHT+IGQi0wK8hiNpCxR1kYwhBQRPYiIz7a6F2I52cik7+4998wg0ZK82sjRpSxtJIgibKrtr8rfxQ==
X-Received: by 2002:ad4:5c8d:0:b0:79c:6f51:7f6f with SMTP id 6a1803df08f44-7e71265c001mr69497786d6.55.1758712815876;
        Wed, 24 Sep 2025 04:20:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6rWHxhHUnR+yvnjZm1+1AlrMw8vQBNAVPBDolzHPjbEQ==
Received: by 2002:ad4:5962:0:b0:783:6e2:3e57 with SMTP id 6a1803df08f44-7933ea75357ls28533896d6.0.-pod-prod-08-us;
 Wed, 24 Sep 2025 04:20:15 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWJ6+WtmDjayLglPem+GsUCv+MOpZwx1zsGGE57i/heMsc4gq7IKuHEUqH+ZAD1Nnf2OR7Cg7LHXSg=@googlegroups.com
X-Received: by 2002:a05:6122:31a9:b0:54a:9fe8:1717 with SMTP id 71dfb90a1353d-54bcb1bb614mr1892495e0c.9.1758712814892;
        Wed, 24 Sep 2025 04:20:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758712814; cv=pass;
        d=google.com; s=arc-20240605;
        b=W3Hod8Uy+9qemvLlTGkZt+q1dF1qgP+E05hqX2v81/Y7FKvb3w4pm1ANk6B9IgWpRl
         HT2lJbOV4Ff3FR/k+lFoQcIKJ6SISuQTolIUnG2+Z+u1rAvSaulb+6BljOU+CCf7D1rI
         qsSkO2vofguKDt6Gc0h82CgVcgoKFdlkqomacQjC4OaNBoUNxjVH/2zhByoueY9u2E00
         R2KVFNNp8K35mAgN0fDBh4mLjhsXarEalGUNwaADGNfOj05BCbK9wkKexbf9gZD3VcbT
         64kgzb29GSagZ/8+h+0ICkbdgIe1S9HeltDmJ4OijxOEnrVYjufQXFmFW32mDCLnkNDU
         tTrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:msip_labels:content-language:accept-language
         :message-id:date:thread-index:thread-topic:subject:to:from
         :dkim-signature;
        bh=nBjmsMg/M4y0LNbGjumZeJbaJ7mkvTNAAlIPBeArQj8=;
        fh=KQ8HRf2InxjJNwyO0eF7Ei4ZzU4tJFmoyJnczlYz83o=;
        b=f8YKBDyWhOLWA0m9PcXkdXJWrgGRSC+ZbFOaZvhaXIIKDPuK/a7AsOO56rgCu7JebP
         dCJtJbP2wLR0Piaxm5TmpW2S5UaQb56+msQXvC5FAKb/KjXnQtqB/Qdb4R+emfI6J7ka
         GsoFhzmqlx5tOi+fFkn+XUgPctfocSTwCHCpNVEmzY7RPy80qqhGtoiWvoQtpK7HwYq/
         7a14Q+j3ekhDR4fSXrjq4S44mTtG3fhIFiax5kkASgw3h5zk75Af/2vdAzDPMz9Qan5R
         xjDI3dAFAYRntV47v9VksZRr/ZED8bwTUSdfPMJCgwEn5YIRmz1wUgsx5CbBx/7UZWqI
         qvPQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=riNpH9Vq;
       arc=pass (i=1);
       spf=pass (google.com: domain of https.www.benjamin.digitalmarketingservices@outlook.com designates 2a01:111:f403:d405::2 as permitted sender) smtp.mailfrom=https.www.benjamin.digitalmarketingservices@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from TYPPR03CU001.outbound.protection.outlook.com (mail-japaneastazolkn190120002.outbound.protection.outlook.com. [2a01:111:f403:d405::2])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-54bda6a4f19si83360e0c.5.2025.09.24.04.20.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 04:20:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of https.www.benjamin.digitalmarketingservices@outlook.com designates 2a01:111:f403:d405::2 as permitted sender) client-ip=2a01:111:f403:d405::2;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=lZhymIw/SCgGNQ8+ey0I9GxG//P2gWVnMPL+4lD0yR37D4bCRaYBRYnj9bAo1roauosWmjtcZmd7cbZLYS3Is/9dikRvrQgSFuoMZLtJrVYJJpncSqGupegsJmX17YEaZ8nhM9hzUJZVKdI9JgqQn0s7ry+pHnn4UBdr2QqOoGxbovCwqR0bpDtZukkiEbTW2im8OVqjJoJQn+FHTK+cVO9Y+qr7gf8MTpgIac6j/2+gNY/bPcRi/AoGY4B3xspvp6KICJubLciBGeoIOzvGAg/RoDfCiascYfZI63/L/ioNCGXHPS0OoxkJln2oZbjfYqso3tiyShtXasPRptNgww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=nBjmsMg/M4y0LNbGjumZeJbaJ7mkvTNAAlIPBeArQj8=;
 b=O7KhfJ7LLv2AY2fYkerBqRvTIzu879mD8kHM6kxgKI0WpBpBuTQgBJdTPkN4bvz+7YfEDj42kN8BSYIJCsnxpgivBIBAK+qeSecuUqBHEymr8WX87nUAbFP0+9HGMhdjHJS1OwjBod3X7ZUlRtwBSeZBvRF2VtAMyVH1ezeEYTOQq5tJdqhpDSdXnIOFXN4xOMTgzEKaZK+f0M0h8yd+m8PcV8+Qs7G9vN5owyipvjHR1mTMv0+XN/l3U8Jkfrs+oeE1y8AhUl2vHWcO1piHwYa7bKtAz+96uKG88p/nQPO3qClRR8sapGcJ1tpxlmYs1ZMldemgl+/g1z7844qiBg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from TY0PR0101MB4727.apcprd01.prod.exchangelabs.com
 (2603:1096:400:265::11) by TY0PR0101MB4334.apcprd01.prod.exchangelabs.com
 (2603:1096:400:1b2::9) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9137.19; Wed, 24 Sep
 2025 11:19:37 +0000
Received: from TY0PR0101MB4727.apcprd01.prod.exchangelabs.com
 ([fe80::82fd:5f9d:37b2:467a]) by
 TY0PR0101MB4727.apcprd01.prod.exchangelabs.com
 ([fe80::82fd:5f9d:37b2:467a%3]) with mapi id 15.20.9160.008; Wed, 24 Sep 2025
 11:19:37 +0000
From: Benjamin DigitalMarketingServices
	<https.www.Benjamin.DigitalMarketingServices@outlook.com>
To: Benjamin DigitalMarketingServices
	<https.www.benjamin.digitalmarketingservices@outlook.com>
Subject: Re: Yes...
Thread-Topic: Yes...
Thread-Index: AQHcLUTJlRWjiFy8nEuH88kurGvcyg==
Date: Wed, 24 Sep 2025 11:19:36 +0000
Message-ID: <TY0PR0101MB4727B80F5D83C58A4E9CBFCEF61CA@TY0PR0101MB4727.apcprd01.prod.exchangelabs.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
msip_labels: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: TY0PR0101MB4727:EE_|TY0PR0101MB4334:EE_
x-ms-office365-filtering-correlation-id: d1bed334-9e7b-4df2-9896-08ddfb5c3ebc
x-microsoft-antispam: BCL:0;ARA:14566002|8062599012|31061999003|461199028|5062599005|8060799015|19110799012|15080799012|15030799006|40105399003|440099028|39145399003|4302099013|3412199025|39105399003|34005399003|41105399003|102099032|10035399007|1602099012|1710799026;
x-microsoft-antispam-message-info: =?iso-8859-1?Q?wLvD+kpotWumv8UpgK6o0ELRGYaIXyI2/6jCqbOITY05bk6k+DFcY4oyTG?=
 =?iso-8859-1?Q?r5YXj5WT4wI1wgIsq7zyaX3J8aGGdsLSKjJrvZZOso8Xx2lFutoBMCOYhI?=
 =?iso-8859-1?Q?Lnvyliz9TttQXPHDAwED9QdT7EtcQyeGOr63Z3fPXWExSOkvRPqOyXrUun?=
 =?iso-8859-1?Q?CCFEjDpZ06ePAX9pPyMrDGsbln/oDAPb1WuQDWXEwx+sNHxic22mv6Myvq?=
 =?iso-8859-1?Q?XCjGrnKZodtyR4ePsSXMGSL3Fg9isnLqDQFPO2gRQKxVGBxJmPiw7UQ06k?=
 =?iso-8859-1?Q?4yWpY51m7JTo3EJUwdH6j+hHPFQLP2bXDV90C5jHX+WYFGWAWWIhkXOlf7?=
 =?iso-8859-1?Q?b7gQ8am144ovf/nsSVJSAPyJSFasvcxfNrk1RZJ7kIRU5Ee2v4oBu3W8wS?=
 =?iso-8859-1?Q?Ps8x3q4VG1nvVoaJ107M24xvdmfPRQcrZQLB/IbS+fEnkQBs3Clogyw/XR?=
 =?iso-8859-1?Q?1Mi4SrM19FjA8jnXiAC7IAmYcoJ28UjKOVObon6VL90BQz4BAETsd8iW45?=
 =?iso-8859-1?Q?/f59Y2F+Lcox4JEDwiI/oFi5017bVAj9Xd51mORzc9bm0CEnNcdkg0HkeO?=
 =?iso-8859-1?Q?7m2+6IYq5dto2EzOPVYF6HkdDPBAvF1Otd2uQcEPurzL6rrR2oceY4+qZr?=
 =?iso-8859-1?Q?bYbh0d+IgmDTu+H/op/MHW0K48QujIQxZ8fci2M7+S9UEmKL444JMz7KmP?=
 =?iso-8859-1?Q?zqBR1SF75Wp6x/8O4RijYN7FXfgNPq+KM7BHkHbneiwtJOqmm5ndWwasFR?=
 =?iso-8859-1?Q?Q+ap2s7tI6KMLLAH34ToLL+g+tmjUoghRjICutcUrnErF5p6uKDvcTFf3I?=
 =?iso-8859-1?Q?r7gyce7HzzzRcZaNkCm6OYjed/CkzrAHeRZVMpKLLpzq4xRQRnyNya0gjs?=
 =?iso-8859-1?Q?kQSyytGaR5zz/CNrIk1F8sp6vLRNrlwIRbBSS+9XjfmLACJUTkq2ncX58V?=
 =?iso-8859-1?Q?qgBWFx9/I+l1zMfxyABm/wsvaTeT5NIhMLmQFSuMKkGwQhaEOYdk53bd1m?=
 =?iso-8859-1?Q?Dfo5YgmHIX6yX4/HWuwlBgJ20Awg73uL6zcLnPo/Xhi0X9yOqNqaj7yZ+T?=
 =?iso-8859-1?Q?g5xiialgGL9j5spGH1YUWooBaWDSBlGisuxwrzoO2uqwNPPclTUjo+2NkC?=
 =?iso-8859-1?Q?e0w9mtPJoWnCeJznHg2ebCa5LDTwBkIZs1yOpwAeGE6gnEYzLulq2iQvgN?=
 =?iso-8859-1?Q?x+VYHSGiJ8QQ6kIneS0kBg648meiiUD9s68YqHXRMce0va8MUt+bn+tTnc?=
 =?iso-8859-1?Q?HzluHMOmjO8PRi2T93LuZJjGwlm6+ZjuQihEU6kOGXnP4pCU5KCBfmE6FJ?=
 =?iso-8859-1?Q?7+covaZ9DqywGbGRZQRCHiIKUmF5fJkaYKvQILZUS77DOOSpSlS0B+qkfG?=
 =?iso-8859-1?Q?+tSJkKQxKxVhFdSg92wrPU61NZOy0WNBuYu48Lw6KKcltWhbfiEnfqO7Iv?=
 =?iso-8859-1?Q?iOJUQh9sU9OyL7mR2NlentqVkcdQdt3O/9hi7OY5SUWMmcYyme1qtyS8Dy?=
 =?iso-8859-1?Q?YplpflOn8snn1FwalhADsn?=
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?iso-8859-1?Q?biYWpOPtqYNtFMQRRq2UxUKQb2+DO1+wyZC/6aRM2scHYYH5pfIEmCjMga?=
 =?iso-8859-1?Q?PkxlWThCPPYlLB7qmz97wCynPIGHJZ4cQZUJ5kXho4ow0XIqBZzcaJFNep?=
 =?iso-8859-1?Q?FLESgVZ/Tvb7TESjUY48k6mTohGBo20PvFatD8uUWPgkSspwkEA28yQoZF?=
 =?iso-8859-1?Q?NLjA4mXwmEDsGee2NikgOBKrWOov5qahSTtt2V+u2n9qgEIhz8pePrTqbF?=
 =?iso-8859-1?Q?ByPrvdhmKbu6/nBnDIXakBly12zAJm1UggAIj+mdsYpKAt7y6tq9Fpi/cw?=
 =?iso-8859-1?Q?aoiuEoHJ3wX2Hr5LSUbvBxPry3bo4ALO3B07SyJxEQ5Ip3CJFe2PgkwCq/?=
 =?iso-8859-1?Q?D6700pSTwfsHv9ohTgN9aGyq6JFLD5FtMV1v6XlJC0yLWwEFI0xCsED4NB?=
 =?iso-8859-1?Q?vE+2woOHwVrsbxdU6sXUL6X0fNoYbWosphzQL9r1lDmXPdtYyHii4VcxaG?=
 =?iso-8859-1?Q?rDdI6v+FnVaPXwx62lr9c3Ef4X6kNcM80Mm/omQfbfmxnybEw8XElAr2tT?=
 =?iso-8859-1?Q?G1gRDI/qC8p2ZJVcBR37JqMyCx84VgppY+2wi+gV/YufHo/5lcaL9dP4Hu?=
 =?iso-8859-1?Q?p2TUoauBWDf5NpmmW4V74Y91MnBae9fE7l2yhTvwOJNOxGhQx/V87u83uy?=
 =?iso-8859-1?Q?hB2IaYwW0vYmc6Otn/k27iD2AouiF3NJuT3S/Z188xbfWGureNScH0BsIL?=
 =?iso-8859-1?Q?Swp9vCVVVy4x4fNf3kRi07uA8F4pl7DBOiRgnnaZV/AjWnGmVVxaG9xm/k?=
 =?iso-8859-1?Q?tF9ly1E3Z1ReDTloTkit5cJBxnEQsWzFAtxejf2bCsNv1F/+3XuU/o1Vju?=
 =?iso-8859-1?Q?Yblk1289LUk75ySil2AF6hGlfV3ltPyUH4if4JgUWSADdhREtB5ti2lXEB?=
 =?iso-8859-1?Q?we4vm3mJX0UktSoMWFTkxATLfWoxJdaopTtT4kEYzzxpYwhSiwlA6ZFaw8?=
 =?iso-8859-1?Q?ZuCSyxZBy5hXc0HocngetwgNn0R3nVEhg7VnE3fIjuzhYijGVfPxbwD0Fg?=
 =?iso-8859-1?Q?5jjVDffEGZXe+AVEqA99yuh827b0KzN/PRMFVvv04XgGyb7QmEvfzS7eF2?=
 =?iso-8859-1?Q?SDwZnp8lNZHmn51uAd92t5jycnKlT2U38O3h9uG8nDO5aL1i9BG2+A9qih?=
 =?iso-8859-1?Q?2LL7X/s1EzY5AOGHdHo3tLM2nFpuIVSyMoYp38Z8VDy/nmZ/kZX4QxYtar?=
 =?iso-8859-1?Q?yg3rk0WIppIGU7GsqknICzHIJLf+T1QfcTaMX+l55OTV9KtUsHe2CzfGsF?=
 =?iso-8859-1?Q?mYRNpfSOMZOlhss1kfpJJlAi1wHDLE2Nn0pM7mvDPNSEzas3S/6kKYHTNY?=
 =?iso-8859-1?Q?b81ZTkDuXld7pOWQdxo2F5uF6obc7C/1hQloukSgf9ugjDGwpi1Vu0skE3?=
 =?iso-8859-1?Q?LwR4y6Yc2u+HdI0DdYMfCUayrx5KQbuVOl+qZ15ZDN67nW4j+MnfL1V6ZW?=
 =?iso-8859-1?Q?8d8xpqj7+m1JULGh?=
Content-Type: multipart/alternative;
	boundary="_000_TY0PR0101MB4727B80F5D83C58A4E9CBFCEF61CATY0PR0101MB4727_"
MIME-Version: 1.0
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: TY0PR0101MB4727.apcprd01.prod.exchangelabs.com
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-Network-Message-Id: d1bed334-9e7b-4df2-9896-08ddfb5c3ebc
X-MS-Exchange-CrossTenant-originalarrivaltime: 24 Sep 2025 11:19:36.4393
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-rms-persistedconsumerorg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: TY0PR0101MB4334
X-Original-Sender: https.www.benjamin.digitalmarketingservices@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=riNpH9Vq;       arc=pass
 (i=1);       spf=pass (google.com: domain of https.www.benjamin.digitalmarketingservices@outlook.com
 designates 2a01:111:f403:d405::2 as permitted sender) smtp.mailfrom=https.www.benjamin.digitalmarketingservices@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
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

--_000_TY0PR0101MB4727B80F5D83C58A4E9CBFCEF61CATY0PR0101MB4727_
Content-Type: text/plain; charset="UTF-8"

Hello

Quick follow up. Can I send the errors? Just reply Yes, or Sure.

Thank you

________________________________
From: Benjamin DigitalMarketingServices
Sent: Tuesday, September 9, 2025 10:56 AM
To: Benjamin DigitalMarketingServices <https.www.benjamin.digitalmarketingservices@outlook.com>
Subject: Re: Yes..

Hi,

I found your details on Google,   and I have looked at your website.

I would like to send you the errors of this business website!

If you were on page #1, you'd get so many new customers every day.

May I send you a price list & report ? if interested

Regards,

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/TY0PR0101MB4727B80F5D83C58A4E9CBFCEF61CA%40TY0PR0101MB4727.apcprd01.prod.exchangelabs.com.

--_000_TY0PR0101MB4727B80F5D83C58A4E9CBFCEF61CATY0PR0101MB4727_
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
<div style=3D"font-family: Aptos, Aptos_EmbeddedFont, Aptos_MSFontService, =
Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb(0, 0, 0);" clas=
s=3D"elementToProof">
Hello</div>
<div style=3D"font-family: Aptos, Aptos_EmbeddedFont, Aptos_MSFontService, =
Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb(0, 0, 0);" clas=
s=3D"elementToProof">
<br>
</div>
<div style=3D"font-family: Aptos, Aptos_EmbeddedFont, Aptos_MSFontService, =
Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb(0, 0, 0);" clas=
s=3D"elementToProof">
Quick follow up. Can I send the errors? Just reply Yes, or Sure.</div>
<div style=3D"font-family: Aptos, Aptos_EmbeddedFont, Aptos_MSFontService, =
Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb(0, 0, 0);" clas=
s=3D"elementToProof">
<br>
</div>
<div style=3D"font-family: Aptos, Aptos_EmbeddedFont, Aptos_MSFontService, =
Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb(0, 0, 0);" clas=
s=3D"elementToProof">
Thank you</div>
<div style=3D"font-family: Aptos, Aptos_EmbeddedFont, Aptos_MSFontService, =
Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb(0, 0, 0);" clas=
s=3D"elementToProof">
<br>
</div>
<hr style=3D"display: inline-block; width: 98%;">
<div class=3D"elementToProof" id=3D"divRplyFwdMsg">
<div style=3D"direction: ltr; font-family: Calibri, sans-serif; font-size: =
11pt; color: rgb(0, 0, 0);" class=3D"elementToProof">
<b>From:</b>&nbsp;Benjamin DigitalMarketingServices<br>
<b>Sent:</b>&nbsp;Tuesday, September 9, 2025 10:56 AM<br>
<b>To:</b>&nbsp;Benjamin DigitalMarketingServices &lt;https.www.benjamin.di=
gitalmarketingservices@outlook.com&gt;<br>
<b>Subject:</b>&nbsp;Re: Yes..</div>
<div style=3D"direction: ltr; font-family: Aptos, Aptos_EmbeddedFont, Aptos=
_MSFontService, Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb=
(0, 0, 0);" class=3D"elementToProof">
&nbsp;</div>
</div>
<div style=3D"direction: ltr; font-family: Aptos, Aptos_EmbeddedFont, Aptos=
_MSFontService, Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb=
(0, 0, 0);" class=3D"elementToProof">
Hi,</div>
<div style=3D"direction: ltr; font-family: Aptos, Aptos_EmbeddedFont, Aptos=
_MSFontService, Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb=
(0, 0, 0);" class=3D"elementToProof">
<br>
</div>
<div style=3D"direction: ltr; font-family: Aptos, Aptos_EmbeddedFont, Aptos=
_MSFontService, Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb=
(0, 0, 0);" class=3D"elementToProof">
I found your details on Google, &nbsp; and I have looked at your website.</=
div>
<div style=3D"direction: ltr; font-family: Aptos, Aptos_EmbeddedFont, Aptos=
_MSFontService, Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb=
(0, 0, 0);" class=3D"elementToProof">
<br>
</div>
<div style=3D"direction: ltr; font-family: Aptos, Aptos_EmbeddedFont, Aptos=
_MSFontService, Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb=
(0, 0, 0);" class=3D"elementToProof">
I would like to send you the errors of this business website!</div>
<div style=3D"direction: ltr; font-family: Aptos, Aptos_EmbeddedFont, Aptos=
_MSFontService, Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb=
(0, 0, 0);" class=3D"elementToProof">
<br>
</div>
<div style=3D"direction: ltr; font-family: Aptos, Aptos_EmbeddedFont, Aptos=
_MSFontService, Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb=
(0, 0, 0);" class=3D"elementToProof">
If you were on page #1, you'd get so many new customers every day.</div>
<div style=3D"direction: ltr; font-family: Aptos, Aptos_EmbeddedFont, Aptos=
_MSFontService, Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb=
(0, 0, 0);" class=3D"elementToProof">
<br>
</div>
<div style=3D"direction: ltr; font-family: Aptos, Aptos_EmbeddedFont, Aptos=
_MSFontService, Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb=
(0, 0, 0);" class=3D"elementToProof">
May I send you a price list &amp; report ? if interested</div>
<div style=3D"direction: ltr; font-family: Aptos, Aptos_EmbeddedFont, Aptos=
_MSFontService, Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb=
(0, 0, 0);" class=3D"elementToProof">
<br>
</div>
<div style=3D"direction: ltr; font-family: Aptos, Aptos_EmbeddedFont, Aptos=
_MSFontService, Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb=
(0, 0, 0);" class=3D"elementToProof">
Regards,</div>
<div style=3D"font-family: Aptos, Aptos_EmbeddedFont, Aptos_MSFontService, =
Calibri, Helvetica, sans-serif; font-size: 12pt; color: rgb(0, 0, 0);" clas=
s=3D"elementToProof">
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
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/TY0PR0101MB4727B80F5D83C58A4E9CBFCEF61CA%40TY0PR0101MB4727.apcprd=
01.prod.exchangelabs.com?utm_medium=3Demail&utm_source=3Dfooter">https://gr=
oups.google.com/d/msgid/kasan-dev/TY0PR0101MB4727B80F5D83C58A4E9CBFCEF61CA%=
40TY0PR0101MB4727.apcprd01.prod.exchangelabs.com</a>.<br />

--_000_TY0PR0101MB4727B80F5D83C58A4E9CBFCEF61CATY0PR0101MB4727_--
