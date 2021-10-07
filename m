Return-Path: <kasan-dev+bncBDRYTJUOSUERBXP27WFAMGQE5RZ3X7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 9898F42602A
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Oct 2021 01:06:05 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id o2-20020a5d4a82000000b00160c6b7622asf5750033wrq.12
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 16:06:05 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1633647965; cv=pass;
        d=google.com; s=arc-20160816;
        b=zPDrLiuKB5g1+kaFu6Khg7FuAgqfZXnunF0NtTN17BrZdIZDlzMEJwcjuC1gnozgwv
         4AzkfjXMrwm+hTo9A/LDMg7yxqftaf/ZcuSCnbgTKGPFLkoJKn5CuLMXdQHy1MEDjznn
         d7tQfqWU/zMdMLKkaZGuxtY6J3Ii8foOiuAKbci5Em9EQUtWn7WYIiFLSyLU8L+/zp6U
         mjgdiGIx2UAYZsfMkf1vcKX6wJ7qlp/rppb9JCw0w0lrRF62CxKz2ZAoY1y2Vbm3fHT9
         wvMuUP8U20igozoClVcc7Wgo9R48HB3Sl7R3vwkS26oOnSiiApU9gEG/aPSA1woGmEbL
         uELw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=wmUC/ZBrts+zQUtQVkJW8VlTUixsTe2IYzyoiS2uRKw=;
        b=L1rfz35x84dAry0sRhbnSPCdvUA1NNHeCm572FagpyOkR72NMl8vSvlBHadE+2+gQ+
         QZQUTwKejcPANh8/8VlakDxBu6eXjrcikq9SFtkc8976yOY6cG8BYKRORvWc+Jjm2s0y
         Ly6moJEbIfP5YosVgY26wswvsz0LzgiyztuTMCyJpkJ+Mhsr5rjFegm6Pd0XOtsVNeXO
         4BWXBD5yhy9InYaCsuwFe6hdJo5cYL6s8I8Zj1KwKBOoXUc7Dm/OhmcAc5cKTDGrhsH3
         SKXmZS/Mri3t9Y2I1Ciec1CVHZysrugca1d79HAuI3zQjXUmEr4nLzJmvXTELs4C4C8u
         SRCQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=UzmnwL2t;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 40.107.10.118 as permitted sender) smtp.mailfrom=gary@garyguo.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wmUC/ZBrts+zQUtQVkJW8VlTUixsTe2IYzyoiS2uRKw=;
        b=FUz6pTM+sZ6XPiXwq42JvpKGbJdd35X7lEvT1OaRP6rvNJ/yj8JSdKsHAC4vRrGf8u
         1PuK+kmY2UPsnu56U/GbY8W0X9iagmP/p6klopdTfjjTRFRG+REcAp+AlExL5G+UsaZJ
         2TBP+YCse+/rjXNYykvu7fv/DY3oKU90st03wsIw/7uZTBSMzAOAC0KU8faWOGHjzL7g
         XdDXWdRwxuTGIrrW0UxEtTOQyJf604iJABJe7i9Yb7VmYSNbgGCQNQtWiYAs5QYT4asD
         ADHHP0q9tQjTAjHWGpyDzKOACqpOYiKpHvSSbRAQ15h089y+ua24EwCHhDPKqH+rqs0q
         LUSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wmUC/ZBrts+zQUtQVkJW8VlTUixsTe2IYzyoiS2uRKw=;
        b=p7PvPBG0ymNy8kirtIEu7XTXcl7UvYXMa8stqtmjZei1Pg8fwDBb38k6NjI3/5GUVq
         2iqf9zfpcVO+SreeZ6voMrNu3Vca5faK4NW7YVtGBXGSDI5aN1kYnRo4zrg9b0k5W6br
         10dL/8vGG5m+1teLN0MNMBBT32Xrbg4QNO6A2LrRlISlE395DmeiOkh6SB7V52AhILWN
         RHEHnszM3HPquMPrPpJGDmFUbqFVoCs9MQVB7x0kXAQNh5BBo+4CKVU+LH+fRppBoMOQ
         tnsPY/IeiFIHHKEPS1c96In/0qpVsNwQJQxL9Esng9PV8TIS3+YuyRJ2AHA/QUTL2LYH
         ZV9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ydJYrQMlKTGDrYIn2TyU4C3kEDhwQmdnXwaqHvzQOxFHhm72/
	VMlajpqp3uzOPybHjmFOx7U=
X-Google-Smtp-Source: ABdhPJxlf1cmzAs8B6q6HwiPdoy+PxSpj6ai6RGIdMX4Ptrq0zGQjnK+KvN9A0osgMW4mV+3jxk3Rg==
X-Received: by 2002:a5d:6d8e:: with SMTP id l14mr8781797wrs.44.1633647965384;
        Thu, 07 Oct 2021 16:06:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b8f:: with SMTP id n15ls2934237wms.1.canary-gmail;
 Thu, 07 Oct 2021 16:06:04 -0700 (PDT)
X-Received: by 2002:a1c:98d7:: with SMTP id a206mr19148753wme.68.1633647964391;
        Thu, 07 Oct 2021 16:06:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633647964; cv=pass;
        d=google.com; s=arc-20160816;
        b=MTFybz7+TPec6UQY2izJMwa4Vz4SJ/2JFF0nXNH2dFvwH95DpfUPZT35b+hSo93iUj
         upCYCSBMpfpaX4q467CVaJcwTTsnXeCaagEh5xuZ4ZokLZZmk/V8TuxAsYS08kiTXyKh
         79SrF2aXKxt53Ld+7D1G9RYhzyGlGDE7fHC0pOYDCw3IeErB6uKf65ABBsolrLAEIcS4
         dJfdnv1nxTlpUhlR6camMBFqkKELmhOe/1Rgo+UsBZL/rImHnDBNpFdAF1sStFSbRZNE
         aTvda3ZvDgiB1+rrL+1KKPY21BRyvyApY+Jluavxp5gZB7LhqBhjzXjP6dGbri/1ahSX
         pEQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=hJMBNx0B4rWO3WrispxtgACcdMNGWEFkOPJO8ka0Q8Y=;
        b=Ru38bmBwet/pcE0bsVKr6H5U1lhfprSy9hBIDZyxvhEReIE6Ko8PIjHvtQ7NYNBiGp
         BG+sqNEGedfIoIseiRucI7s+BKUbKwRSRTEf8hjnIPILDEliVVPig5gJTGG0U+JudkSw
         apxMNu3enFCoTj5k6AB8AwOuH58VuKKgEvI2e8pP9oQ/AW299EDH1aVUl78a+nnR+qHu
         GLbT4myQa6ZHV5HzNrU5RinQmka9nNSVJRljCV1+qOR+8fwHhJXUid8wWRjfwCZ6RmOI
         5+IsGhUeTySNgfRAoxwfidVxAoTn+PkVTJPu6ElEPbv+vw7CYNQVjxoXgR8sUSA7RC0w
         8Krg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=UzmnwL2t;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 40.107.10.118 as permitted sender) smtp.mailfrom=gary@garyguo.net
Received: from GBR01-LO2-obe.outbound.protection.outlook.com (mail-eopbgr100118.outbound.protection.outlook.com. [40.107.10.118])
        by gmr-mx.google.com with ESMTPS id a11si31690wrh.5.2021.10.07.16.06.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Oct 2021 16:06:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of gary@garyguo.net designates 40.107.10.118 as permitted sender) client-ip=40.107.10.118;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=H1mNlM5hzrXPcbUpQqWQo5GtReWSFm173cYfDM3JYGX7yBEobPZLjWMq9B1uzJ7zYSNVZ+AMIbZ/1IpKAehHb+d1pLOMUDIn6PGW+feRzwbe9gt30rlL/nabg5YFEoUyfQsSUeEZzB1zrhrTvAgsS9XJpb7pQhobiwByXvKHfYjvjCewl//viAZizgqVa+6bU+tzKqlN6hNSWfyhyHz1YZtRcOo55Zd6qhpAV8ElfmUE1uv5YBqT4nRQvy8VgEeQ27tUOBj4vEq69jgMVwdX6GwwryxNStDtJK7Qf/WfLd0Ntu5VU714Vem9+rbt4qcuJYLSli8FLO3TZiKMmwRvGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=hJMBNx0B4rWO3WrispxtgACcdMNGWEFkOPJO8ka0Q8Y=;
 b=Qb0fs271ewUhz36NRiFPPu9AstAWi1wXULX24pcnGMqBpsmtDgtm4IxPgRH3u+a/SdDSRSlMOEk2EltboFbhpkZFFNXaL+RyGYBJWhFGkAULbreQoXyY/tJpis4yQhP1u/r0mhdscpMe3WAmz+n/7KokK62WoI1q8vawoZHzgvaAiinpjG7bBee0RZjmieaIyIsZ07nlCHyP5ZvZvrQuyqVcvKc68jRAkVlZgmCLuhtfBTuBacjjiCrOpYM46YRbvS+e8Yi48uqh1RX3UF1ZRDLTV9Bq9tu0a6sw6euIKs7MXUOFRLlUsEFgOMpzW1yczhYuavdcj+3xJboyxWBZtg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=garyguo.net; dmarc=pass action=none header.from=garyguo.net;
 dkim=pass header.d=garyguo.net; arc=none
Received: from LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:253::10)
 by LO0P265MB5310.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:280::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4566.22; Thu, 7 Oct
 2021 23:06:03 +0000
Received: from LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM
 ([fe80::35d4:eb8e:ecdc:cc89]) by LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM
 ([fe80::35d4:eb8e:ecdc:cc89%5]) with mapi id 15.20.4587.020; Thu, 7 Oct 2021
 23:06:03 +0000
Date: Fri, 8 Oct 2021 00:06:01 +0100
From: Gary Guo <gary@garyguo.net>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, Marco Elver
 <elver@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev
 <kasan-dev@googlegroups.com>, rust-for-linux
 <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211008000601.00000ba1@garyguo.net>
In-Reply-To: <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
	<YV8A5iQczHApZlD6@boqun-archlinux>
	<CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
	<CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
	<20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1>
	<20211007224247.000073c5@garyguo.net>
	<20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; i686-w64-mingw32)
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO4P123CA0462.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:1aa::17) To LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:253::10)
MIME-Version: 1.0
Received: from localhost (2001:470:6972:501:7558:fc3c:561c:bc74) by LO4P123CA0462.GBRP123.PROD.OUTLOOK.COM (2603:10a6:600:1aa::17) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4587.18 via Frontend Transport; Thu, 7 Oct 2021 23:06:02 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 3d84e12e-2971-4a03-653b-08d989e708f7
X-MS-TrafficTypeDiagnostic: LO0P265MB5310:
X-Microsoft-Antispam-PRVS: <LO0P265MB5310B5E5D6EFE8130031A0ACD6B19@LO0P265MB5310.GBRP265.PROD.OUTLOOK.COM>
X-MS-Oob-TLC-OOBClassifiers: OLM:10000;
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: FV4sZwzBE4SOEDEDCR8CNmgt5SuoKvipXgF0u/IUAAbSvI+CcVhFZJWv5VGs9SmmVfc3MydXWbskAlMNZY5R63XwO3rCFXAowJBeAbdrA6Af/gDNB6zdeHfT+5xyhvq60pBCHy4l+wERluP/1aw5axLz2dL+3zwO+Ax/69YFPh+h2GVaXdJ7XB344nIWWvm9F9p5DFFhSpnTKOg/iybQMX+M2u+Jxw9GRTyvqCkndhZHoul2M9lW62zx9aa+F0KuFNnyvEyp6jGBKAESNPMZw4GF3DTD7hll3/MPOtipW/bAyxW+eSBAKNuME+XjAZ4yTT68xxK4PhgnFKNf6060P9153a9RCdUcs/Qhh1DofSTraJgUHWnRvChEADpDl/K8MyoGlaRM0gR2D6U3hdhCzIGp7Y5vQk2Q/EUdc7twoV2xUy0swfhr7DTyMiZi/dWhcJnaukZDNH/JvVXbj64FR0Wx4zjsMmv7kiOGKU6af+QW0kmX+6Hx7SRF03e7wD7SwJkHcGk9R7P0tunW+lM40KM8WCBc30lGP2cRUIP7L7Rjq/fM9x/po5UPYMZ93NtCByGdj8VX/NQU7zpSHg17EExgBjoRWzmAefnIe090DfEgCbcyMyLIaO6VKRkCbXkzXloW4IaYypGiueOVDet1Zg==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(346002)(376002)(396003)(39830400003)(136003)(366004)(1076003)(316002)(66476007)(6486002)(508600001)(38100700002)(186003)(36756003)(8936002)(52116002)(6916009)(86362001)(66946007)(5660300002)(54906003)(66556008)(6496006)(2906002)(4326008)(8676002)(2616005);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?pE8FNPWkaynwb54j3Smf5xfPU2VQInyPqYgpg1pCybInUI1EjnPdoy0l9hsn?=
 =?us-ascii?Q?6/AjwD68yduqx7O0Bnu3pZ816EcEs04E4sn/hG63RB9hzNbvFyeaZtIPl0xK?=
 =?us-ascii?Q?I15rBvTDVCm93t1gtFDUd7P0aPySlv0t22N7KFA9JLHgWXnjeAuVYqdwrTEG?=
 =?us-ascii?Q?NksIejKokeRywCJ1PcVAmxtVHoz3WSu7eYvBAIPjlQfYHsGQj4P2ZSDdsXOf?=
 =?us-ascii?Q?jQPqRtMJCauPLcvGPN1up4c7sR0tc9w5NL5OaF5v7wgpJ/KwRLVGEOQUR1Ni?=
 =?us-ascii?Q?Cn5rHJE+BmOO6VtwCs4Dv1ycYNWYPMtCaM9Nk9n14DATYIcTt8p1MUGtzgVD?=
 =?us-ascii?Q?hGAgXWBOiq5fibC52RkhYGydzqXIWIEp0uSdZ/0g6V41mC71LeGZ8hjAeqVI?=
 =?us-ascii?Q?XQwMkD+fAgPNoviHCuYIO0MeDN9pVkoZRvxihZATOUxAx7LmwcXRf2f09kGL?=
 =?us-ascii?Q?GMGx3j7t89gQmiCanwsSUL0PGaxxi1XXE8+aKJPxqNQ4W2qO/WbxRtSeu9er?=
 =?us-ascii?Q?8ANRfitAiX5YLrNkR5WswJMJAe3GcYVjnSHZApCaqJhxMwoxBr4vGnXRdT4S?=
 =?us-ascii?Q?VUvvXFRhLJn7R8HXl5EoU1bTwBlrwzYjfbTPfa33lQtPol6lvuwc4V4z+Ecg?=
 =?us-ascii?Q?G5jN85nut9X6x6dvxeBaCJfEYOUe84pt1KncBEJ0ErLoO6qwLBojJEkOeI7f?=
 =?us-ascii?Q?biLbgFeW4jW2bFae5JCfhE8aeqZqXje2OuQVZhV3yF+XmcEzRvt9EXXu1SNw?=
 =?us-ascii?Q?RcfKD+69QxvEcTyjdXuJ913K2otri67aem0NZ3ihAWHmGKzN38A4T2HZkrgc?=
 =?us-ascii?Q?/a8xA7GPcYVeeyNe/HgZUNVn/bw4Tq60qX9900n66AF9NpLcDhRnjyBk2WDt?=
 =?us-ascii?Q?8JHB76VIOS2N/DLLTRqHC1UwaqNyQ3F6gBIInxn2ulfS1G3I4EMcM2nq0VNa?=
 =?us-ascii?Q?9RXgikkgaTTs8lnG0hOMYF/XifAQv7brW00yxaQZi8xs1lSTArz0tTseBQ/K?=
 =?us-ascii?Q?FbCShYT0ZdtTrN50YKO3QVjkCw2cJNJtSrcD4YO6X2KLK2BmgiAqR9GphEcO?=
 =?us-ascii?Q?ig5uQ85qUkuypFAsBV05uHUja6vmVynkXJ8KQ0Rv3XLKYUb4m8yuKwcPN1GE?=
 =?us-ascii?Q?NtB5QfYRxUJNMlW3geexmKGTx0qIP4PBWm8d4CKB9EZf91n14ZkdNh118EBp?=
 =?us-ascii?Q?3TLyGPtXk41XXK8GPXmZ3CgqAGHURZOkfCiJ00HeTJ2fOBmc0rNC9u8zAx7v?=
 =?us-ascii?Q?zrOHGucMeXtq97kahyzS6ELketCMslQ8JnFGdxEF4DU/M5b97l5NXLiG1h0w?=
 =?us-ascii?Q?61b35DDWhpKoJ2VD0NRtpA4LJunn1SESE2NLAVxBSJsFDpDlx2hMC3K0RGnT?=
 =?us-ascii?Q?xDcGlzPe181CZ4Gf2zAt6757/Zh/?=
X-OriginatorOrg: garyguo.net
X-MS-Exchange-CrossTenant-Network-Message-Id: 3d84e12e-2971-4a03-653b-08d989e708f7
X-MS-Exchange-CrossTenant-AuthSource: LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Oct 2021 23:06:03.1523
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: bbc898ad-b10f-4e10-8552-d9377b823d45
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 7T3HunlmJaG9PIt2tAuG4d1OYqxVdlL9/KxFOjkAfmX0j6UFikdFU8nDMKYsf6LPiXwqSKV22sjf+fdpPQqalw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LO0P265MB5310
X-Original-Sender: gary@garyguo.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@garyguo.net header.s=selector1 header.b=UzmnwL2t;       arc=pass
 (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass
 fromdomain=garyguo.net);       spf=pass (google.com: domain of
 gary@garyguo.net designates 40.107.10.118 as permitted sender) smtp.mailfrom=gary@garyguo.net
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

On Thu, 7 Oct 2021 15:30:10 -0700
"Paul E. McKenney" <paulmck@kernel.org> wrote:

> For C/C++, I would have written "translation unit".  But my guess is
> that "Rust module" would work better.
> 
> Thoughts?

Module is not a translation unit in Rust, it is more like C++
namespaces. The translation unit equivalent in Rust is crate.

> And the definition of a module is constrained to be contained within a
> given translation unit, correct?

Correct.

> But what prevents unsafe Rust code in one translation unit from
> violating the assumptions of safe Rust code in another translation
> unit, Rust modules notwithstanding?  Especially if that unsafe code
> contains a bug?

Unsafe code obviously can do all sorts of crazy things and hence
they're unsafe :)

However your article is talking about "safe code can violate unsafe
code's assumptions" and this would only apply if they are in the same
Rust module.

When one writes a safe abstraction using unsafe code they need to prove
that the usage is correct. Most properties used to construct such a
proof would be a local type invariant (like `ptr` being a valid,
non-null pointer in `File` example).

Sometimes the code may rely on invariants of a foreign type that it
depends on (e.g. If I have a `ptr: NonNull<bindings::file>` then I
would expect `ptr.as_ptr()` to be non-null, and `as_ptr` is indeed
implemented in Rust's libcore as safe code. But safe code of a
*downstream* crate cannot violate upstream unsafe code's assumption.

> 
> Finally, are you arguing that LTO cannot under any circumstances
> inflict a bug in Rust unsafe code on Rust safe code in some other
> translation unit? Or just that if there are no bugs in Rust code
> (either safe or unsafe), that LTO cannot possibly introduce any?

I don't see why LTO is significant in the argument. Doing LTO or not
wouldn't change the number of bugs. It could make a bug more or less
visible, but buggy code remains buggy and bug-free code remains
bug-free.

If I have expose a safe `invoke_ub` function in a translation unit that
internally causes UB using unsafe code, and have another
all-safe-code crate calling it, then the whole program has UB
regardless LTO is enabled or not.

- Gary

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211008000601.00000ba1%40garyguo.net.
