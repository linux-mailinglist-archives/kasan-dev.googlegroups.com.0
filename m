Return-Path: <kasan-dev+bncBCP7BJMSVEBBBYU5QODAMGQENTJ5HPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id CE7303A171B
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Jun 2021 16:23:32 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id n62-20020a4a53410000b0290246a4799849sf15010890oob.8
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jun 2021 07:23:32 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1623248611; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ehg2yXOqsj6uvDVeyEb8LkOtXrfw5/pm6ZDAB0IBryfJrJBg3Dm9sHONgbFg21Cim5
         IwClXIjJ6IcqIfA2GpaRORhLiRYaeiGeDAHTuMhuPrzK9Py69Y0COq6jmH92WcK7W2cy
         J6hzCsgH4htd4X8QYhh/V6oDHtkrRBlX6tmtN0wGzLV0d0R7ZDIzG6a+dQlvk+EQJpHw
         b569Bcbq/c8360CAbAG3sHhygzIqgrTrTIhILZ+pNlD8Kge8kDP6aRRDtGMlG3e7kpp9
         8hPpYfs2aswyha3GtjV8DzFpWX95PLMslMSaPplPd/mLqwmc9RgSmbod5/lIWaKxAjfm
         2Ddg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :to:from:sender:dkim-signature;
        bh=KRfdPY4XUBPrZDxuTPjch1J2LOc7YIp07d800JrmaUc=;
        b=kgnGmlG46j6iIO6tGvl6oXTLBet4Xs6ope5dEya5xMQkY6HKG0D06jvvJ6zAEAyMfy
         JvhhOyzDB84f6aeaUAcHWGoUe1gfDtTSpQHHVSMzBVeISj9i7L80xU0nXBLMJHDGlkud
         rCZ0CfH3LRcm4QSV4DfxSTsX0MsvjOfyfmSkTK2kL35hEiuj1M7G0GU7JSGDxMUgu80f
         3nIczr4hv72sqfd/5U39q8CwClrav45PFgYQmJGugV8WMndywAwx8CWalCLQVgq/Fh2U
         Rf2E4Bqx8cNWOx/hddZChiz0aFYM22iYWEwicFhtOVqbp7kEDxz43fwn2do6OlNIcPo5
         0v1Q==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=iXFNqiMa;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of soberl@nvidia.com designates 40.107.236.55 as permitted sender) smtp.mailfrom=soberl@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:thread-topic:thread-index:date:message-id
         :accept-language:content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KRfdPY4XUBPrZDxuTPjch1J2LOc7YIp07d800JrmaUc=;
        b=Th1E5no4eHz5ZHkRIJv8V2Iyz4wlCnGYMAtWlmbkIyCOKSaYFvaEOA5s/K7rUhLSff
         Kwzb0UBM5mTLecFhqHb04Bg/vQFWS5Vj0W+kxaON6GWmpG4YmwalghkLM/fgjjjHQpbS
         Jfw012ipY4eIUgS3KLVfNH/pZLl6Iryde2scIddXu5XGOsur14ir+aQtRbwLYWrwMkVD
         NgiQp5AKrFjPqK7Fe9XbgD0eRVuNkMMwumNGFCWZ5Dt1iKvRisluEaQYYwjdVeY5FJtr
         nWzZoRZqjIWHVKJso86iLvErFZsOFsVvW4TzFwyww3Cewj0XHpulQZDTaDmf2qLd/Rzg
         sXoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:thread-topic:thread-index
         :date:message-id:accept-language:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KRfdPY4XUBPrZDxuTPjch1J2LOc7YIp07d800JrmaUc=;
        b=hj94byYftV6d5O2QG/vD92X6pos6D1FWJ0gJMNZ7ue+eMiuGG/FU52PWZ9nnx1CH+8
         jQgSoGsUUBzoYV+ntrYseuKvOWkDT6J1FOaqZUH680gyRVWs49Dn/YHrQodM0B2v0XIG
         t6WJq4+7V6fnTLCB1URxA39XIo7U6L9YHYJDrWW/LEZo3z+hrAlZMTsWTEzUXUNSD/K8
         UhoEVoiu/3FposaC8jA9ZQN3E5PlfsKYcbet3Sjw/61UEx340D4YEs8xvo3NXb6PnEK5
         VjD7mBigr3O8FzBgeMgA8jSS83k58y1GdjRgZQV5QEOSXXo3c4ge3aJnJat2i9xh6kUs
         dliQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53037dbu0Xy3dqu2839X6DlyXCRND2o1trpYRE/x7c8WQhMDUWXG
	UxQ7iAcgtwNx2OYyrEWIVxE=
X-Google-Smtp-Source: ABdhPJyMAMaQc9D15TVkockYFEYmy2+OwwRamJhv/U7Zb1tqRH3Ibu+pAdZ7pYBySCB3yOw0iB/ITg==
X-Received: by 2002:a4a:d052:: with SMTP id x18mr127554oor.21.1623248610919;
        Wed, 09 Jun 2021 07:23:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:bd6:: with SMTP id o22ls782972oik.1.gmail; Wed, 09
 Jun 2021 07:23:30 -0700 (PDT)
X-Received: by 2002:aca:53ca:: with SMTP id h193mr6472429oib.69.1623248610450;
        Wed, 09 Jun 2021 07:23:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623248610; cv=pass;
        d=google.com; s=arc-20160816;
        b=Aj8xGzwa/4uoYRVJlkoeT06tEewDxG6ewiwxCwHXsmIOdAY7sBqpS5lxtlp7hzFzef
         5fgatfpkecE7t6/mkvPUZ4qLgDlVgnIb5VYdLIz+8u1XlY57Ibv4LCKkSaBKPocHjuCY
         9Elhbg62E7ejruKJJkkysTFqu+jZHaAQ0qyaha708hCvs4MwJvjnd8GLW++yk51DVB9f
         gbspqo9cA0RMX3GCt6mk2ajRfS/5q4xrbh4vTCogce+gy7EVya+BWqPmW72Zb+TW3Dhg
         5okt6vo6gDBXZfm5K0v17kfjTGZd0dGBQuhoquMXMjNsY/IEobQQp3P0ln1CpbcW/and
         IkXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:accept-language:message-id:date
         :thread-index:thread-topic:subject:to:from:dkim-signature;
        bh=a6wvC7g6DZIhPSF+V9GwwFa8l/KiojCnIRiohsVzZUQ=;
        b=bExUlv4kRjxoBwMyR7FNahicP0jnxbgNpXowztV38PE6QvZGfChZnU51vfDVUpB3ek
         tTVl6Jlrd1FYQ7Dex4Msq5hMQQoTtd69hD1tN86uxtOrY6kqQCB7Bv2r1vtBow1vXVM7
         SBrhpriwDRORaKgO1hX3nqj12QWyxhyacubNLe4IMr2Ug3olmSgxN0vp1TMKQulF7HrV
         W5KAhFgkqKmFgHy3lb262SJGTxzTfTyPh1UZKEkqkCHeIdiT8uXgMmO/LaqNstZXpInU
         rpmrkemgyZe34BouILJ4riA9qCGoupVnoN5zKMdfsZhW9r3vcmnLTAypOXjAFePm/Jhl
         XXng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=iXFNqiMa;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of soberl@nvidia.com designates 40.107.236.55 as permitted sender) smtp.mailfrom=soberl@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
Received: from NAM11-BN8-obe.outbound.protection.outlook.com (mail-bn8nam11on2055.outbound.protection.outlook.com. [40.107.236.55])
        by gmr-mx.google.com with ESMTPS id a25si2499585otp.1.2021.06.09.07.23.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 09 Jun 2021 07:23:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of soberl@nvidia.com designates 40.107.236.55 as permitted sender) client-ip=40.107.236.55;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=iayGscPtwtYU27+xLUldBpy3QoZZh9/cY9HkSyJ9tQFPubD2bF2R5HRXxRHr27qxLWPG1FdxDxjI/rGX7xHSRg/q/pE2gppQ2xJdZIbZ5KMkz/aqcZNVkCyKTr/tBXsndgmNaPJRKANSHbY4D5PkWCFNnhGQ4CuKrG5TaGrj81rtAlBZIvSlD5Qw7SmBlPE99MqD+d1kvRfEkp/8RXoMDUEggvKRQ58eVohVFy4O5umAIFLOlZoPxXTL2hTi71KIhi0bgKJ09S+3Y7UllsYNtYAfsmpWGnb4HG9QuRCK0WtIERB7hmw9QyhQbI90MDNTjuYeVXMJF+0lrRcEvacrsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=a6wvC7g6DZIhPSF+V9GwwFa8l/KiojCnIRiohsVzZUQ=;
 b=KvyZfteFjkPw/oLiXH6I1ub9783MlNxUFIdR1/ydSQIsHgbPIq5X6xrvAvK2SMQyljz+puxDkhoTCNelkrOgkupWU4oVYv5w06YaacRscjmK17O8SHBxGYlnCYpSzLn2r4YNLvfvlu+62UbFsKkxpgPUdQ/9qY/G5+uVEdoZprRLchAMwgTP7PfFQIbuDxWxQQ8LwXS0vQI8aBRIYJy1Alc1NkORj5buaL5/cHOOM28tDOFkk2SQeMS+Q6zGMJB7Gz3Rv6O4UUuUtDFPOmSgK2xq1DdEK/b2Ui2295sD2/e8IvgRUBQfbdRdcI0c8x1wzgCEMxDQ/A89d7L8VVuRig==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from DM8PR12MB5416.namprd12.prod.outlook.com (2603:10b6:8:28::18) by
 DM8PR12MB5464.namprd12.prod.outlook.com (2603:10b6:8:3d::13) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.4195.24; Wed, 9 Jun 2021 14:23:29 +0000
Received: from DM8PR12MB5416.namprd12.prod.outlook.com
 ([fe80::b1f4:1cc4:5634:3803]) by DM8PR12MB5416.namprd12.prod.outlook.com
 ([fe80::b1f4:1cc4:5634:3803%8]) with mapi id 15.20.4195.030; Wed, 9 Jun 2021
 14:23:29 +0000
From: Sober Liu <soberl@nvidia.com>
To: "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Question about KHWASAN for global variables
Thread-Topic: Question about KHWASAN for global variables
Thread-Index: AdddORCE41vfWG3DRxWVahYduXzsrg==
Date: Wed, 9 Jun 2021 14:23:29 +0000
Message-ID: <DM8PR12MB5416B119812D7B939F9AC9CBAD369@DM8PR12MB5416.namprd12.prod.outlook.com>
Accept-Language: zh-CN, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [43.254.66.34]
x-ms-publictraffictype: Email
x-ms-office365-filtering-correlation-id: b9a19b41-214b-4a1b-9905-08d92b522711
x-ms-traffictypediagnostic: DM8PR12MB5464:
x-microsoft-antispam-prvs: <DM8PR12MB5464CFF1379CA1C28D93F34EAD369@DM8PR12MB5464.namprd12.prod.outlook.com>
x-ms-oob-tlc-oobclassifiers: OLM:5797;
x-ms-exchange-senderadcheck: 1
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: xs2TtFrIEexdoMMwpEmkrtwYjl9ZRh1Y1fe7XDG2C+55NtyhL2n9TQbKvRNB19guPycpDC3ypm6ArRrbTdcth8XcNE/Cq1a4O97UVulYn8pwK2uot4AYN2TRsXnTy6j6xCJfPdG/UC5NBui8Aiz9sbmyJZgun6x9duAvrWn65n0EBbzWozoUmD82bjrFbwAvNRJXo1nGhu4EC2ONoPPeUtG+UscwMhSv+rE5endTUhUt8iL3N5LK21Nw+8D3JhrjvVOn4wVaUQ7wHqrBEvpZmSE3mXHI5F8qOF1bEwbdkivKA+MglzkF3g4Abnb9WVO5bYr1f0cCqB2Oyz1cyOHEFdEVZ9QHJU0zb7RXK1PAq4HLuLgvOtplJskFfLvWanFBgOg8PtKhSwPJGJJXF2z6AqW7ZLdopi48ySmH0ZJgkyOUJZt8Ayx5ONMgogBDNFgNL9T5i7P4E4rFD3FGtvUsyp4G9p6ZxeM1AQV1YlrYU1WTdBaXE/kstI/0C/+XstYF6/9aeJSduE7v/glw22+zXxDc8oko1Fpjb+6RDLovVPeJdNttS/22/GgWb9f9Aqcm/H8YU1qjbLevrIQBCLs3bofHLv4C+pNbXI9tPiBM9bKAZDNQdrlpQmTNXkckfWOoiXZpPD33eLt+H3mxOy9apgaxH0Qm9fzuUwF7wp7zoGavJ1LLlx6+n9zjtaw497lZYeVq+pWooimnhXOFcVrItyVy+UtKUZux4MiwiUmmegk=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM8PR12MB5416.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(396003)(136003)(346002)(376002)(366004)(39860400002)(478600001)(2906002)(6506007)(5660300002)(4744005)(8676002)(86362001)(6916009)(26005)(966005)(83380400001)(166002)(7696005)(52536014)(316002)(9326002)(186003)(76116006)(9686003)(55016002)(33656002)(66556008)(66446008)(64756008)(66476007)(71200400001)(66946007)(122000001)(38100700002)(8936002);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?us-ascii?Q?72tnD1MyjGo6ORK4o0mK3nWsqJ7Ztocm6evRH4N16sXx3haXF201we062HPc?=
 =?us-ascii?Q?BI+ZiyMcHySYr02FapmfvMclkOH8ZMcfespynOKOMlH8zoUi/FyKwiAAoAuE?=
 =?us-ascii?Q?Bfy6NwBvxR5DtsK/4ja4V0eC9hmZHWwpMXlLbtMHyAfhExKQCezPn4JLY3Yq?=
 =?us-ascii?Q?d+m6EwtTUymCvtMgDYWyQuwtIQxmtX4iyHwDx30P+sD5GIxi6Fl40kI3bbmL?=
 =?us-ascii?Q?aBzTUIbppmOuBuk0gmKH66Lx3LyjoAPTu33Dov6Jl7tNe3qH8NMXRIU1+9j7?=
 =?us-ascii?Q?SYVhhLjMdFl24GE7dWZobBA5XfND+DX1vFh/EaOFyhRf5t5arw7vjvGHAOHH?=
 =?us-ascii?Q?Wlu6N+z11yp5Sp/5VmMa+mR05OpnWxsmia8u3NtAKRFhlyaSBG3knume5zYO?=
 =?us-ascii?Q?0pmvve6vFpGVuMeMCr9c7sKIBktvKsCK27vMgGsyMBGbHl1U18gPrvPHhO30?=
 =?us-ascii?Q?y9jDcAtkfh6lZ5f1sYjqLLhUt0HIMHGVHQuASQcA7OgmtEuKYeZYx1CZe1QK?=
 =?us-ascii?Q?TYHRG7/M53MoXcluVetFKoo3ZC2cIOq0eGRawaS/Zz3Xal2iqGgFh0C7Ou9g?=
 =?us-ascii?Q?9/riSqPhh9NTGljpDzPkjUUP40w0jpljufMw1Vz8IMW8akEzYR6dWzC1U+Nk?=
 =?us-ascii?Q?6nYV0MYUi8MtvNbvlq/fGDtjoi1Db8WmW0+aOFtcvKqiolWQtgh7agQB5kcz?=
 =?us-ascii?Q?1MFK0OdooKX9mnU7Yvb1mktXq3Zcpqh9rMk1gQDQHiP0hGTYvROSPYaag+XI?=
 =?us-ascii?Q?NVuuPls8BI19EfKLq/BoX7bINmfTCxb9dKaqLLM3JloiWxnCXwkcLkYD0HoQ?=
 =?us-ascii?Q?RIow/zHFpqdFjIDQh5J4Mw/QjChMr51GLv8rfxE1a2Cq4BcxVLEoBTIBkcb9?=
 =?us-ascii?Q?WPR2Phc7tEdajeu2UKF2a7yKXIgrnHkch0pNezU9hUYMLR2CLyczHY5xHpY2?=
 =?us-ascii?Q?hp5NpwIWzJx6Qub11kcLIcPUv1+29Pne1R+KRRdT2mXNlGmbuXfh1Vg9f9J4?=
 =?us-ascii?Q?b7JenDMJwaxe5RLXkQYtsn8C3y4yC9sUhIpIJEtjx/oB4C5/p9xhgpYTZEAe?=
 =?us-ascii?Q?VM6S5Y84/jIdA9t/ynIzTd+n5F17O32vefH/6HgabPxkNR2cT7o5EzQeks6A?=
 =?us-ascii?Q?OqBt0vRjDxXhJfhkNwTfttqFnKcaVlvi6TSNmlpxB4aKcSP4emb0txXWzIXh?=
 =?us-ascii?Q?WS6RlR5JBV/6+utOWnv7kFwWbYi7DTlaO4qddNvQ9vig82yLYultB7lDQc47?=
 =?us-ascii?Q?KuU/uj0aPG5KWmiOJESa4CE3Umb2N/F1/4448SAfVt7OHj+7QoVXN/gz7+fe?=
 =?us-ascii?Q?f8U=3D?=
x-ms-exchange-transport-forked: True
Content-Type: multipart/alternative;
	boundary="_000_DM8PR12MB5416B119812D7B939F9AC9CBAD369DM8PR12MB5416namp_"
MIME-Version: 1.0
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: DM8PR12MB5416.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b9a19b41-214b-4a1b-9905-08d92b522711
X-MS-Exchange-CrossTenant-originalarrivaltime: 09 Jun 2021 14:23:29.0979
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: Nx2LaneHJV8uNDYl6RQLv8VJq1Y3tI5LIWASI6ylF9PuWC5XrZz4rdRgE7Q7qyN8l99Wg8cYLQGXeOlp9JDSag==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM8PR12MB5464
X-Original-Sender: soberl@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=iXFNqiMa;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of
 soberl@nvidia.com designates 40.107.236.55 as permitted sender)
 smtp.mailfrom=soberl@nvidia.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
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

--_000_DM8PR12MB5416B119812D7B939F9AC9CBAD369DM8PR12MB5416namp_
Content-Type: text/plain; charset="UTF-8"

Hi,
Sorry to interrupt. And hope this email group is suitable for this question.
I am confused by whether global variables are supported by KHWASAN or not in GCC.

From https://bugzilla.kernel.org/show_bug.cgi?id=203493 (for KASAN with sw-tag), it tells LLVM doesn't, and GCC does.
While for gcc/asan.c, both its GCC submit log and comments mention that  "HWASAN does not tag globals".
I also tried to make a comparison here: https://godbolt.org/z/Pqvdaj3ao. Looks like GCC doesn't generates tagging infra for global registering.

Could anyone help to confirm that?

Thanks and best regards.
Soberl.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/DM8PR12MB5416B119812D7B939F9AC9CBAD369%40DM8PR12MB5416.namprd12.prod.outlook.com.

--_000_DM8PR12MB5416B119812D7B939F9AC9CBAD369DM8PR12MB5416namp_
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html xmlns:v=3D"urn:schemas-microsoft-com:vml" xmlns:o=3D"urn:schemas-micr=
osoft-com:office:office" xmlns:w=3D"urn:schemas-microsoft-com:office:word" =
xmlns:m=3D"http://schemas.microsoft.com/office/2004/12/omml" xmlns=3D"http:=
//www.w3.org/TR/REC-html40">
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Dus-ascii"=
>
<meta name=3D"Generator" content=3D"Microsoft Word 15 (filtered medium)">
<style><!--
/* Font Definitions */
@font-face
	{font-family:"Cambria Math";
	panose-1:2 4 5 3 5 4 6 3 2 4;}
@font-face
	{font-family:Calibri;
	panose-1:2 15 5 2 2 2 4 3 2 4;}
/* Style Definitions */
p.MsoNormal, li.MsoNormal, div.MsoNormal
	{margin:0cm;
	margin-bottom:.0001pt;
	font-size:11.0pt;
	font-family:"Calibri",sans-serif;}
a:link, span.MsoHyperlink
	{mso-style-priority:99;
	color:#0563C1;
	text-decoration:underline;}
span.EmailStyle17
	{mso-style-type:personal-compose;
	font-family:"Calibri",sans-serif;
	color:windowtext;}
.MsoChpDefault
	{mso-style-type:export-only;
	font-family:"Calibri",sans-serif;}
@page WordSection1
	{size:612.0pt 792.0pt;
	margin:72.0pt 90.0pt 72.0pt 90.0pt;}
div.WordSection1
	{page:WordSection1;}
--></style><!--[if gte mso 9]><xml>
<o:shapedefaults v:ext=3D"edit" spidmax=3D"1026" />
</xml><![endif]--><!--[if gte mso 9]><xml>
<o:shapelayout v:ext=3D"edit">
<o:idmap v:ext=3D"edit" data=3D"1" />
</o:shapelayout></xml><![endif]-->
</head>
<body lang=3D"EN-US" link=3D"#0563C1" vlink=3D"#954F72">
<div class=3D"WordSection1">
<p class=3D"MsoNormal">Hi,<o:p></o:p></p>
<p class=3D"MsoNormal">Sorry to interrupt. And hope this email group is sui=
table for this question.
<o:p></o:p></p>
<p class=3D"MsoNormal">I am confused by whether global variables are suppor=
ted by KHWASAN or not in GCC.
<o:p></o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal">From <a href=3D"https://bugzilla.kernel.org/show_bug=
.cgi?id=3D203493">
https://bugzilla.kernel.org/show_bug.cgi?id=3D203493</a> (for KASAN with sw=
-tag), it tells LLVM doesn&#8217;t, and GCC does.<o:p></o:p></p>
<p class=3D"MsoNormal">While for gcc/asan.c, both its GCC submit log and co=
mments mention that &nbsp;&#8220;HWASAN does not tag globals&#8221;.<o:p></=
o:p></p>
<p class=3D"MsoNormal">I also tried to make a comparison here: <a href=3D"h=
ttps://godbolt.org/z/Pqvdaj3ao">
https://godbolt.org/z/Pqvdaj3ao</a>. Looks like GCC doesn&#8217;t generates=
 tagging infra for global registering.
<o:p></o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal">Could anyone help to confirm that?<o:p></o:p></p>
<p class=3D"MsoNormal"><o:p>&nbsp;</o:p></p>
<p class=3D"MsoNormal">Thanks and best regards.<o:p></o:p></p>
<p class=3D"MsoNormal">Soberl.<o:p></o:p></p>
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
om/d/msgid/kasan-dev/DM8PR12MB5416B119812D7B939F9AC9CBAD369%40DM8PR12MB5416=
.namprd12.prod.outlook.com?utm_medium=3Demail&utm_source=3Dfooter">https://=
groups.google.com/d/msgid/kasan-dev/DM8PR12MB5416B119812D7B939F9AC9CBAD369%=
40DM8PR12MB5416.namprd12.prod.outlook.com</a>.<br />

--_000_DM8PR12MB5416B119812D7B939F9AC9CBAD369DM8PR12MB5416namp_--
