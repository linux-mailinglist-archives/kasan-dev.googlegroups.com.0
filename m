Return-Path: <kasan-dev+bncBDD3TG4G74HRBKFFWGCQMGQE7ZFDWZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C17938F784
	for <lists+kasan-dev@lfdr.de>; Tue, 25 May 2021 03:28:09 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id p6-20020a92d6860000b02901bb4be9e3c1sf33451228iln.11
        for <lists+kasan-dev@lfdr.de>; Mon, 24 May 2021 18:28:09 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1621906088; cv=pass;
        d=google.com; s=arc-20160816;
        b=CZi4oJ4Mm+6wwqhs5ea3+a6vUtPwoRi6EtWcQJzQ+NK0JacTtlymMdN/K6bAv0g6M+
         DfItFXy5Jlot1nM5+h/ZuNtAgMyAZ8ffMFBj5Shzj+CCketna6nIW1fnf7M5i9FXynqA
         bTWwcpq4uGZEIogF6MFkKC/1b36UiHGiKN5rJTYkL91fi2bcW3DCwdWT9EKhgUGT1tSE
         vATdbc9meh9JrUfnWYsj7q6rhNCCrpmtMO4cY0a1s2wcFHQ6/IrhrKM8fgzEksftldJN
         5uwXxfSlP9fxEM7e9akWTypx6eYPB2OT/3kE/qozHY02DJ70D5YBgxhRYJKzEc7we3lX
         jyFQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=eGkZZ6kZN0S1RIJ0SRuO/S4UdSINRV5aT5lFKA5PBno=;
        b=guzhZZ4Xc9+X0fquh6L5N5bheR1KFzY4HUuhbcSkZ9J4m2jAqC60W98kHKgmrW03Yz
         fmCqBILH/4LOK8QYPdg1Z8LFrisbn4aZVwI+bM7ELEI7zD7QVItdrQVAVQ1/nLeVQmPC
         nLGrmT3M6VyH/qQ1KAskVZBx4zoknBCZjE4JnKl6HaffjaNavcAMEWq70Rm2UHq/EGM6
         CMQX1ajVn+9E+rCtZbEEu5XisNi2b1Urg339ls67X5h24Em+LKBBwgnNsfeRUSrnQg7B
         NPseV+Awzwun4Sd44gfhEd9+WwZUC2pbwtrcuPiZuY2sMxBJ5iDuhQ6OaZrMkkoK2/1D
         F2BQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com header.b=EQSaIxkg;
       arc=pass (i=1 spf=pass spfdomain=synaptics.com dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.223.83 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=synaptics.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eGkZZ6kZN0S1RIJ0SRuO/S4UdSINRV5aT5lFKA5PBno=;
        b=izOq2NG2RRGaBKXSZkKgvF/rAlzKzlsvCrwBMsnjcVLoiFe4WxqEbOCiprGr62zYdH
         3N8RT90oWXZalUGNzEL0AReW5N8W+GLHo3lNwnZVA2qCen0JGbfU58CkfywySfSxNO70
         7u0EkdYFrLWLmjIvVAUcN2EkUXegt7IcQ3gaDKc/GQszXNfwQTtpm2bakkprV5WJuaB6
         7tMu/BgnO/1RBWtokYTvKfMtOWGUAmI16YvYnyGBGf2bvMFG/J4pTakk8PIx0gE9pY+m
         xC5edgq778c91G/tfY/LKM7uGHuZeW93iTB/nDfvknW10clB5Xbn7iejzgBGRmtqPxs/
         ZFpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eGkZZ6kZN0S1RIJ0SRuO/S4UdSINRV5aT5lFKA5PBno=;
        b=qLoLif1iflwDtKy6IN7kaDe+y2mzUJuPRJRhSA1UMKrmutJXANXNOz/noz8P1wubcW
         uqpF1HvL+j+VUC/jdsJ1XrFDaIBIwVYAVWbixeokQCo+x/TkXfEkIXA+BV6ysUrb0DPC
         o4V1J2ArzODphmVuXzdsgrw51Njy6r1Z3EcTkUvx45MLwu7KtFTlsgAv6gF/DOwFw2Iu
         noTnRbVjOSUGW2OFYTWpyV3NS/NEfbF1q27aMXwA/OvNPvZN1rKhvw5q7mywSYGSqx6E
         f0cu498yXkAaoNs/gq1WsO23Pf2lmiNsOxnx/O0TpsM0B2pBUMDvFXudwYJM9Qu7Qo4Y
         D7fQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530e9RStHDNLCYqVyg5UAKE7/EehM6erkinLfWIx6aeRZoBqQmkf
	wQ1ax+1huaAHRHquO51EnzI=
X-Google-Smtp-Source: ABdhPJzjwLzz/PCchaOZe4/WbBKAW+rXZFi9ax9szTgno2tUYSXO50mjk9v7QC32aY3KvxdoaTEUJw==
X-Received: by 2002:a05:6602:1584:: with SMTP id e4mr16625630iow.4.1621906088081;
        Mon, 24 May 2021 18:28:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:b2a:: with SMTP id e10ls3680148ilu.8.gmail; Mon, 24
 May 2021 18:28:07 -0700 (PDT)
X-Received: by 2002:a05:6e02:54d:: with SMTP id i13mr18762443ils.26.1621906087577;
        Mon, 24 May 2021 18:28:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621906087; cv=pass;
        d=google.com; s=arc-20160816;
        b=xmwXSLo8JFLlCKUyf5qhMRBZ6TGeJztR8Y+SthYbIpHRGVKSwn6I/41kv6C7c9VBlC
         iJagbaSXKdajexLghZro4rdKvBzJ8Qp7MRXtxo/L19PUQfRXtrrk3SLq4wDwX01HIiRY
         ZfPJ3NAvOVrdYhcHtIVsqWqHGRjnyR4/ZgYv6UXaOe6RLvupXTy4YU4F4+DSfoAjFnAu
         hjldM5ox9x7SbeM8IAQV0ezoBkRQj1zMF/2+uNovycap4peSgyUlaJC61SCl+nWcXXAH
         HXAd1lf1Yj3Nw3PmQf1BD3GF1kdh2k2TNDhYuhgYryBkkZrMqEpHo/O7YWJiwQUD8TDa
         UuxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=EqrytqCe282xbtigViVX7Y9Z520SvyeWoOFsNY/EEfM=;
        b=fgFCg/8adX1J1gXGk4AZkLh9fyOsyL/5/Ge2qo44sFlLupWlusSRU9f7RfCVKNd1Io
         SoO7CNfLAc8RJZo4JX9ksdjbNHHGtSCG4Mo9Bw0A3oqRvGe1NDkzEp4UQ3b1PjEUxiZz
         7SMMnJRa13iVLk0fxILj7Lan8oHijKhDDampUbwRuLN1pJ1ODdywUXD9q+zZLjFrpr0T
         VSdHix9TIXtD0JctWX5sLreDTx7YXFneLWnsv+34XTomMennTIdHd4Lj+YQwsHLqsS6i
         xe7YpuDMFuGQ3qMF2DlVMVIquUPLiQBbQpw2D7adv2VyKtKkX70XScDQEMxn2S6tC6pN
         uBlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com header.b=EQSaIxkg;
       arc=pass (i=1 spf=pass spfdomain=synaptics.com dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.223.83 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=synaptics.com
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (mail-dm6nam11on2083.outbound.protection.outlook.com. [40.107.223.83])
        by gmr-mx.google.com with ESMTPS id r20si2524116ilj.3.2021.05.24.18.28.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 May 2021 18:28:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.223.83 as permitted sender) client-ip=40.107.223.83;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=nl8d8vitGEkaoTznOlTP7B6OmuiaZvRCDnSuvfcC6jKfwoAYzq0zLWHptcTpZr8FmhA61sJC1I2hVHfZh/rB3D4xiQu+bLQDF0SAvRNOEaZpZ1z0oL5vJY68qqD9nOeBp/chlN0tDF/FB300VpQyQQcGEytT9SXKw71dQOZ4bxLvctj5ZjMpp5hNT5f/GJGNzQbJhLCNRrYkJfxe6tIJ2dYjJnSxWWfUPmkTVJrFWtuFKgJdL9Xz16c2xyYY2RJt8uE2AzGxXZjhLuhk7cq4JoUbxKraf3yGhPkCVBpSwM5k/luc9uhbR42jc7zO9g527e+4FHwjgXaGJaaq6NzqNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=EqrytqCe282xbtigViVX7Y9Z520SvyeWoOFsNY/EEfM=;
 b=cxNRdJivl+yUfyk201lEnNSe59A5HhLxjexKf9hOaAPHngDzL7kQf9EmtzqrIxnbfoJFA8mkWnIpmuw08CsS8zEso9s3+RQRnx4x+p+5sZ5lpEPZQ+JZ3VveypJl2TdX/g2gkFklIo06S9pKvd5CcRoPLGH2G9f5p66iOq/5Ff+KSGNomGf6HyDwm4FK4ltFgOYd1JugyM1lp14vRUoNzFzP5fQExrqmXK1S0AdlV2B5sOpH430AkAVFfEyCacAjPZeRmjmUpk2jaLurF5NKATxJio3MNkXRqq6BHYsYk7KtL8m9twKCMJfjyAo8gUJbAwcPeebbfVrDMQ/H6BoVHA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=synaptics.com; dmarc=pass action=none
 header.from=synaptics.com; dkim=pass header.d=synaptics.com; arc=none
Received: from BN9PR03MB6058.namprd03.prod.outlook.com (2603:10b6:408:137::15)
 by BN8PR03MB4690.namprd03.prod.outlook.com (2603:10b6:408:99::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4150.27; Tue, 25 May
 2021 01:28:04 +0000
Received: from BN9PR03MB6058.namprd03.prod.outlook.com
 ([fe80::308b:9168:78:9791]) by BN9PR03MB6058.namprd03.prod.outlook.com
 ([fe80::308b:9168:78:9791%4]) with mapi id 15.20.4150.027; Tue, 25 May 2021
 01:28:04 +0000
Date: Tue, 25 May 2021 09:27:49 +0800
From: Jisheng Zhang <Jisheng.Zhang@synaptics.com>
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
 <will@kernel.org>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, Linux ARM
 <linux-arm-kernel@lists.infradead.org>, LKML
 <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Linux Memory Management List <linux-mm@kvack.org>
Subject: Re: [PATCH 1/2] kfence: allow providing __kfence_pool in arch
 specific way
Message-ID: <20210525092749.3ceac5ad@xhacker.debian>
In-Reply-To: <CANpmjNOVikz=u90-xQKzWGxbH_ov5R_EkuG6ZLqVAkjkgw8Z2Q@mail.gmail.com>
References: <20210524172433.015b3b6b@xhacker.debian>
	<20210524172529.3d23c3e7@xhacker.debian>
	<CANpmjNOVikz=u90-xQKzWGxbH_ov5R_EkuG6ZLqVAkjkgw8Z2Q@mail.gmail.com>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [192.147.44.204]
X-ClientProxiedBy: BYAPR11CA0055.namprd11.prod.outlook.com
 (2603:10b6:a03:80::32) To BN9PR03MB6058.namprd03.prod.outlook.com
 (2603:10b6:408:137::15)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from xhacker.debian (192.147.44.204) by BYAPR11CA0055.namprd11.prod.outlook.com (2603:10b6:a03:80::32) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4150.23 via Frontend Transport; Tue, 25 May 2021 01:28:00 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 5e2d6f26-0532-4395-8717-08d91f1c577f
X-MS-TrafficTypeDiagnostic: BN8PR03MB4690:
X-Microsoft-Antispam-PRVS: <BN8PR03MB469080361A7DDEAF90E8D5B2ED259@BN8PR03MB4690.namprd03.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:8882;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: dvMenRLpvjweu9NQBIVtMsl93iSJEI9w2uY+sn4DltbfqqpVuyDrWEOAsDDK9n04mJY5cSvOD22vDwSyVww5WvMxHyE6k0HM6Go5BdZH+VUcWEAdLL++Bke+4tz+uWal5ZBYHi4fvYwasv/hKn7e3h8oVe0Q19lWuo/7nJsylOM8b/eW5RN7DWncheS+6V1DUBweJcnZQQEfwOzvN+I8euZroO+lOebkA8Y6YD7dbYfJfd869KnnoXlCQxeNtB1y0MfY22luK7V9aw2K7gZvDPcn3NOGf3jkFuK7QatfUwffSscRysUE9NyrvFUsI62Kq7XSEEC/IlR/SLxDe/YGifpTRcjOOnxKktMDcCXKuufIzUCUn8dLzTr74uynyGMOHFpv0DohrEEN3auFMxeHp+BAbr543kM4colMDBx95nMKHTh0mWFPn0VMTQSQ+gsdqmZ70p47IP6XHiErHqD1xSBunkcMWZG3iDr841STxYgNiLYZIaf/6QWhSH79hEEwT/1TyN37Eja/Tg6T4Yqswns8TFn8nUYTjIBiq1jX9UmOK1j4q9iixqg0gVXTkELqBl2Q1fYe1TtWKn6z76rqUUBVpHgZ2GNI1I7UzqrIIRRK45wSa7sOA657rjzWDybGbr4tZSf42x3/AlV3cJ3G2rgyeakBMtAB3ognXne9xk8=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BN9PR03MB6058.namprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(396003)(346002)(39850400004)(366004)(376002)(136003)(2906002)(38100700002)(5660300002)(1076003)(6916009)(9686003)(38350700002)(478600001)(86362001)(956004)(7416002)(6666004)(316002)(54906003)(8676002)(26005)(83380400001)(66556008)(6506007)(7696005)(4326008)(186003)(55016002)(16526019)(8936002)(66476007)(66946007)(52116002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?us-ascii?Q?4CGw4K5CBWjv+igeDThnZmmhu4ylDASbWaEn5NSfzhiSSbD6KL0dJcyt3e+C?=
 =?us-ascii?Q?hF0D0CeTfudkYpak9xu9AfRomd+9rmQIwhq+aobkg/+CvjeugBmKkWV09PYv?=
 =?us-ascii?Q?EUGtyjOByhPyDTltUmrJsTJrF4K8mWKhpneaUT83OOt+N6WqWiJTspkOiQOb?=
 =?us-ascii?Q?EjSX8Ufftt1DQC/UUhFg0+/rW9nFs9/Oj9CxBLj00nBeK5kq0UXHegy70D5P?=
 =?us-ascii?Q?NZCdOSsd8UV/D+3x2SvayzW0HU3oItccPdzBJjr2f1zwg84r7R3BO0h9/6wy?=
 =?us-ascii?Q?MZrh+Qcqn0LKK7BaKx6IpSjKV/6Xu24Fxwt8fwWC3AOcFR+HoSYqJCwXCWnQ?=
 =?us-ascii?Q?8G+dxBwPi3a6Y3S7i5ZfEg74E3mRLdVN7hoQgXKrZD9poY5+7NfL44hAGved?=
 =?us-ascii?Q?CnPxY5TTPeSzV2uxllWV4FW9b2rjJ72/NKqhyzD5jEjtj1nxL5AF+dDoBCC+?=
 =?us-ascii?Q?Zys6GXjiykv3aqDjJUZHt+DZRFarT8BoiEXxVQkLKNsPRsDlvwa9bk1x6qDG?=
 =?us-ascii?Q?2IsfhJCD6jYEfIO+xxRrlxzPcFRrBIyxgMCzZPee0FxgYNNf1z8hGrVs96KH?=
 =?us-ascii?Q?v5L6SnsrgHFDUo5XP9u1eRPmBMtI4S8hg3V5cnEHV1TZonHXZ0SIpFVjJMz0?=
 =?us-ascii?Q?pnpwufZfYkdsswRzCqZp8cqd7vy/+6bjTqTlpncRGqcdKvxsiv/NuZ1tZ8fV?=
 =?us-ascii?Q?v8jThqTDCIexiXLvcYGrR6wHLUfZS7WEveHv7M442ycjszuhdlWyUKiukT4M?=
 =?us-ascii?Q?nSFKOPgjsiC+wxUagZzDxrIU9orz/uZx4QbTZj7/HRTw2ur2Ng/8l8mdH6uR?=
 =?us-ascii?Q?i0Cl5n7o6WpGe+fWaCb5hDbRg4zmWIvOOigIogPUhCLy7/EEhDS+EqO2Wjm0?=
 =?us-ascii?Q?piQuZ6c9ko0Mp6DlkqJ1OdVxokPm6Y4EibLyL+BHUGJBXJyW1keb/zJEVnQO?=
 =?us-ascii?Q?DoQqgjf3POuSFE2zs8W9ZYo1MJzAVbrkHi6hLXeDXAW9uRH857LHRpwFT+Vm?=
 =?us-ascii?Q?N3RPyECJdLIo93vv4GmtaktMPSw3764ETSEM42RG1tjyWn3rRrj6OQ3mi+II?=
 =?us-ascii?Q?/DaoTJ//AEf+AcoXmHKZF+hSLE+aPOhxX7/rQp6RZzctObn+3rWhjcQhhLMG?=
 =?us-ascii?Q?8/PW9Btu4xtpvGMv93ocIByfE6UqOIwkFOeqmrtjn3UgEBvCl24+woZe5S4D?=
 =?us-ascii?Q?g5TChSDG/2Y1Nvl/X2c/d+kF9pQ/XqikBMpeyivhuSUAOd00e+yGItqWgISm?=
 =?us-ascii?Q?76090+n7xrTiJrZ8ghBZNUhP3DD/jMwsAFQr3CFlPIwpu78olsTJgnSHfFnL?=
 =?us-ascii?Q?QHH7mf8i8pH4w7NySotKCxsG?=
X-OriginatorOrg: synaptics.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 5e2d6f26-0532-4395-8717-08d91f1c577f
X-MS-Exchange-CrossTenant-AuthSource: BN9PR03MB6058.namprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 25 May 2021 01:28:03.9098
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 335d1fbc-2124-4173-9863-17e7051a2a0e
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: y3/+E/SGXChjpx2+IPUGm+kXfI01Gp2IMaOuX3raL0cjBHJ1sBzqoKHuH+tU4jSMXhStmH35MvOTVbflmYP4IA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BN8PR03MB4690
X-Original-Sender: Jisheng.Zhang@synaptics.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com
 header.b=EQSaIxkg;       arc=pass (i=1 spf=pass spfdomain=synaptics.com
 dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates
 40.107.223.83 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=synaptics.com
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

On Mon, 24 May 2021 12:36:34 +0200
Marco Elver <elver@google.com> wrote:

> 
> 
> On Mon, 24 May 2021 at 11:26, Jisheng Zhang <Jisheng.Zhang@synaptics.com> wrote:
> > Some architectures may want to allocate the __kfence_pool differently
> > for example, allocate the __kfence_pool earlier before paging_init().
> > We also delay the memset() to kfence_init_pool().
> >
> > Signed-off-by: Jisheng Zhang <Jisheng.Zhang@synaptics.com>
> > ---
> >  mm/kfence/core.c | 6 ++++--
> >  1 file changed, 4 insertions(+), 2 deletions(-)
> >
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > index e18fbbd5d9b4..65f0210edb65 100644
> > --- a/mm/kfence/core.c
> > +++ b/mm/kfence/core.c
> > @@ -430,6 +430,8 @@ static bool __init kfence_init_pool(void)
> >         if (!__kfence_pool)
> >                 return false;
> >
> > +       memset(__kfence_pool, 0, KFENCE_POOL_SIZE);
> > +  
> 
> Use memzero_explicit().
> 
> Also, for the arm64 case, is delaying the zeroing relevant? You still
> call kfence_alloc_pool() in patch 2/2, and zeroing it on
> memblock_alloc() is not wrong, correct?

memblock_alloc() returns virtual address which can't be used before paging_init()
so I delayed the memset to kfence_init_pool.

> 
> Essentially if there's not going to be any benefit to us doing the
> zeroing ourselves, I'd simply leave it as-is and keep using
> memblock_alloc(). And if there's some odd architecture that doesn't
> even want to use kfence_alloc_pool(), they could just zero the memory
> themselves. But we really should use kfence_alloc_pool(), because
> otherwise it'll just become unmaintainable if on changes to
> kfence_alloc_pool() we have to go and find other special architectures
> that don't use it and adjust them, too.
> 
> Thanks,
> -- Marco
> 
> >         if (!arch_kfence_init_pool())
> >                 goto err;
> >
> > @@ -645,10 +647,10 @@ static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);
> >
> >  void __init kfence_alloc_pool(void)
> >  {
> > -       if (!kfence_sample_interval)
> > +       if (!kfence_sample_interval || __kfence_pool)
> >                 return;
> >
> > -       __kfence_pool = memblock_alloc(KFENCE_POOL_SIZE, PAGE_SIZE);
> > +       __kfence_pool = memblock_alloc_raw(KFENCE_POOL_SIZE, PAGE_SIZE);
> >
> >         if (!__kfence_pool)
> >                 pr_err("failed to allocate pool\n");
> > --
> > 2.31.0
> >  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210525092749.3ceac5ad%40xhacker.debian.
