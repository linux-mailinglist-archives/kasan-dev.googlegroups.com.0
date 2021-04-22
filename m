Return-Path: <kasan-dev+bncBCZLRWEX3ECRB57BQSCAMGQEOR7W4IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id A11B1367C05
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 10:16:56 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id b203-20020a1fb2d40000b02901c9714c9241sf7588100vkf.19
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 01:16:56 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1619079415; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z3X1ynnG0t76GtX8XvDzBD8/1ayA566FUZostWoeJUXnsTasrn/OQlAB3PCrmVeGmb
         UiXNsAKykoQQJkJ2frPYLgcO+R4LIXmiMj7xanYBErx5D0it+mPxKJGQVMZ+1WxhMPZa
         io4Z+p7KyGWauD+ERbykO/CJ8FWzmJZ66NOiUneIfc3CQnHSq5m/WphuZR+r6rEGlAFO
         wMwsiD493pGrQPQNwXaj7fnjLCprvS9h9fYqCFw8uoALyvx1IZ2AlesVNhQJmYJIzUrY
         R2ftev/DoPF/WcudStJQ7MAcJzO9Eq5vr6fCDCAyAxuHRG9JUeCoT0Sj251xp4B2wOPP
         b46Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=dnEqHznXnr/ia51B9KEcYrLPJkAGYkfVOv4xYVZPfOs=;
        b=lDovl3t9RP5rK2Lyr4rcU1ruNlf1fqjs69FAFHaunrOr9qOOhTB8+JJ/Itv1OaEOHK
         oYYOlx6mZzb/OG6jKO1OR5rNEA9xa6lAak11TeMYNdQ+x7bT6Fnv40Ub5cg7hY+1hv3X
         c6c9TsEiwCel4z3hv3mPkZ8ZusQvw78HwWSeayFnAuCALJ5EpLx5aThJIXTckc405rZv
         IOWevoSVSs2LM0Ip94vTYkLpBtjwWcXZuIB5p/l7pvh8ckoMfoDq+qIk/O4VcOf97mFl
         ESzYXHvH9C0hIRpgp+/jOfT1UwBtoFmAYPWjJOHNRRaPifIvf75Jct46b7kFkUy6YgRi
         WW0w==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=eUWZMqLe;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jonathanh@nvidia.com designates 40.107.223.55 as permitted sender) smtp.mailfrom=jonathanh@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dnEqHznXnr/ia51B9KEcYrLPJkAGYkfVOv4xYVZPfOs=;
        b=Ov+1ata9QTQoyIscrdGXaDr/ga7TBUxhTyRGz2MD0yZ6TxASm5ZDGGWVRl4uNF5UFX
         TYqMV2fMjbE6bXgZC6XQDO1UAGO+47M/Nrs+Rr7FanaQvAmWb3ZA+ql/VNt9RJ+Be2MB
         sXLcAhY+8ztPXlcn4xqvNinM7T89/Yo1SxpatzYzAPBB+oWLFxjSCtOa6Rh2MB0QIAeC
         2z6IP4b3orr0RWoK4LW+nU6CleyCf4WshizBJlGrD/xr7Aw3hRyqOpujWH1JD2W+piSV
         rv46eNvA4U34Y8QLxWAxI/brK0cukTpwBJC9kuHnKHSLpnaivW2N6Xlcc2kF5bYJYrDX
         4uSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dnEqHznXnr/ia51B9KEcYrLPJkAGYkfVOv4xYVZPfOs=;
        b=sQAIAS2xebUFDg6rj7NWEnrif0Pn7pNJb2tjW4RabXK8h61HdI5h+zE/IN3/T0E2tG
         Mv8xB+CSbuE5yQCge7EKTby0V2oknmMsMu7mtLf9wxySojbuJSh/Q6NOw7iREg90nKW8
         x0bc9Ig7VzKIn55+7yU4ePFAE9VCEjTX6r03jHeMeg13SGDegqE6rZ2LY2w65xTLm8Oh
         9mAAFA7MdtzfLhuGjQuW7iu1FtSXODV5BNuDXtCTpD70KsMB1lhPHBVZ/MMUZuBqUu3T
         SVVdXHTmUPXeN8Tw/EuTat15RXCYm22D+6wsJuW1gYlYt21CYMhF4nRt5PPoArf6Jd7g
         Ob8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5307gd+JiuIJ5j6Nff7D1lzrW+dTsizdrXhzscpAWBvmSd9IJ6Sd
	zU2SkUWpLsPQX3gM+agiHdQ=
X-Google-Smtp-Source: ABdhPJx1gl8ATzsHBTl8eaMNx5YGZLT8VZy0lT1p7AIPCr5T1PaIrVOP4ru92s2abgUA/+1jVkWdyw==
X-Received: by 2002:ac5:cde5:: with SMTP id v5mr1539612vkn.16.1619079415656;
        Thu, 22 Apr 2021 01:16:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c0d0:: with SMTP id b16ls369864vkk.3.gmail; Thu, 22 Apr
 2021 01:16:55 -0700 (PDT)
X-Received: by 2002:a1f:aa43:: with SMTP id t64mr1438936vke.22.1619079415095;
        Thu, 22 Apr 2021 01:16:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619079415; cv=pass;
        d=google.com; s=arc-20160816;
        b=daJ7myXzi/g43dwff+jGjl7Xl4flpoTBFkUUy+ONbO56nzY7iZvjKJ9oQMgBZOyuNF
         oFFQI3yfpbUKQtaTjMAGgkNHutzyW6reTb8LzTDRDX2LUjUI5AbU6FmIsyhxHYoCBiQm
         bGN1N3WQVtTY5AcIaIFVYfgJmr4SbM1Sxjq3vcDJYTywjCnmrNxXBmi/MnC3JLEYj1HP
         1r9XhiUtu7W0kSaor5d4GvbwYRpDy+NZnxymq+6e4ko2hfig7kQuyP9UrfX91ARacBF2
         5wbR2T+ds6Kom25N2I4d5gZBXlfSxBN4iJH5sGxD3BQqX7cOsil7OacTH0oSD2FTdRti
         6rVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=oq+qBPcPbTa5KykEfFLD4bbBZ35fuqzptm5NfiJmyi0=;
        b=OtFo68nhu3pccXAPcpFRNUO3+P6VVzfY5ylmx6YbOtC/zVqyRtLLVfoTBPqRR7w4ud
         igi1fWPtnnfzbnABO4W45S7+lo9B/hzmFIqtL3bhK/2NG7rLhJ6t2j5LurWUgOzl9/l4
         lhEBZxyzD4ABzyFYG0dm+RO8wAh0HO6jGXDNaVvJO2xMlfnAl+hG4UaAaixnceGAKtP3
         Z2Tm8EAxldF6/zF58S+N7EilHk7ygx30OQlkiOLcc1YHk+UOAmTutwSgnZnF0q/ExRFj
         /r2+qn4AxJgfWCWeRwq9oKTAS8iT2OYB27KiIpjg0aK5V9DQLwXBvxww2oSORof42FuZ
         D2hw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=eUWZMqLe;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jonathanh@nvidia.com designates 40.107.223.55 as permitted sender) smtp.mailfrom=jonathanh@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (mail-dm6nam11on2055.outbound.protection.outlook.com. [40.107.223.55])
        by gmr-mx.google.com with ESMTPS id a6si304057vkh.0.2021.04.22.01.16.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Apr 2021 01:16:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of jonathanh@nvidia.com designates 40.107.223.55 as permitted sender) client-ip=40.107.223.55;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=PbupAbkt1Y9WuGT9qOJS7lZlDGvSwcHclZd6M3Qsahz7bUbAVBnLNMKzyIucGnZYQ5jXz3VLB3ZaCwf+C0vbCCppTgPmePr4yfqlJQ9nNLi9SjfrQG4w6rOuuEzC/fuCpZwK/VIC+gpk0TABd07VSuDvz1Ga7OCNj/K9cUIOPmHt96i23hwxoAmOQljZ+/MG/yvdfqEbR2g903z9ePcUq3dWtNXOaEe+tbR+L1G7t4zkKHM5maTumj09xmXldxHd1JLJ4WEBYU3u7nTbmwd9xcbLgK8jOm0chq/6akis88YmNxZbe4kx2tcuH6kcPGYm/OriwndVmdkwr1PJGJIdiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=oq+qBPcPbTa5KykEfFLD4bbBZ35fuqzptm5NfiJmyi0=;
 b=WJtHEV2gau9O6MMfO6vZe3xIPTv9EFvOgZD5UOIFU1ijBy4fNpWLo1fpTWrNcBF39jEsogAeH1OyjWAZjNJxGMrvoIrzRACiV0Rw7Ih/uQagG0aDdcCcfm2J3jklqopMnu6cmTThY140FEDW9pOf/BISYP8GhxbXkz1JyU3i/yVCUQHgrMYUE14rvPbnIdmHFDM23mcpu55f/SbmaWWpacm+bcBK/MNvkKXXCm9ZMW1RNGOLlFuJm0ibsy6bEuDJ02KZbvN1q+2JpFTsJ84DF0Q9/S5d4ajQlKeG9V5zKXFDm9oqgWBWE9OFnRROpRhLGJ2bkutigzXVP+Rw0EUOMA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass (sender ip is
 216.228.112.34) smtp.rcpttodomain=google.com smtp.mailfrom=nvidia.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=nvidia.com;
 dkim=none (message not signed); arc=none
Received: from MW4PR04CA0260.namprd04.prod.outlook.com (2603:10b6:303:88::25)
 by MN2PR12MB3758.namprd12.prod.outlook.com (2603:10b6:208:169::28) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4065.21; Thu, 22 Apr
 2021 08:16:53 +0000
Received: from CO1NAM11FT066.eop-nam11.prod.protection.outlook.com
 (2603:10b6:303:88:cafe::5b) by MW4PR04CA0260.outlook.office365.com
 (2603:10b6:303:88::25) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4065.21 via Frontend
 Transport; Thu, 22 Apr 2021 08:16:52 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 216.228.112.34)
 smtp.mailfrom=nvidia.com; google.com; dkim=none (message not signed)
 header.d=none;google.com; dmarc=pass action=none header.from=nvidia.com;
Received-SPF: Pass (protection.outlook.com: domain of nvidia.com designates
 216.228.112.34 as permitted sender) receiver=protection.outlook.com;
 client-ip=216.228.112.34; helo=mail.nvidia.com;
Received: from mail.nvidia.com (216.228.112.34) by
 CO1NAM11FT066.mail.protection.outlook.com (10.13.175.18) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 15.20.4065.21 via Frontend Transport; Thu, 22 Apr 2021 08:16:52 +0000
Received: from [10.26.49.10] (172.20.145.6) by HQMAIL107.nvidia.com
 (172.20.187.13) with Microsoft SMTP Server (TLS) id 15.0.1497.2; Thu, 22 Apr
 2021 08:16:45 +0000
Subject: Re: [PATCH v4 05/10] signal: Introduce TRAP_PERF si_code and si_perf
 to siginfo
To: Marco Elver <elver@google.com>, Marek Szyprowski
	<m.szyprowski@samsung.com>
CC: Peter Zijlstra <peterz@infradead.org>, Alexander Shishkin
	<alexander.shishkin@linux.intel.com>, Arnaldo Carvalho de Melo
	<acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa
	<jolsa@redhat.com>, Mark Rutland <mark.rutland@arm.com>, Namhyung Kim
	<namhyung@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, Alexander
 Potapenko <glider@google.com>, Al Viro <viro@zeniv.linux.org.uk>, Arnd
 Bergmann <arnd@arndb.de>, Christian Brauner <christian@brauner.io>, Dmitry
 Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, Jens Axboe
	<axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>, Peter Collingbourne
	<pcc@google.com>, Ian Rogers <irogers@google.com>, Oleg Nesterov
	<oleg@redhat.com>, kasan-dev <kasan-dev@googlegroups.com>, linux-arch
	<linux-arch@vger.kernel.org>, linux-fsdevel <linux-fsdevel@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>, the arch/x86 maintainers
	<x86@kernel.org>, "open list:KERNEL SELFTEST FRAMEWORK"
	<linux-kselftest@vger.kernel.org>, Geert Uytterhoeven <geert@linux-m68k.org>,
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, <linux-tegra@vger.kernel.org>
References: <CANpmjNM8wEJngK=J8Lt9npkZgrSWoRsqkdajErWEoY_=M1GW5A@mail.gmail.com>
 <43f8a3bf-34c5-0fc9-c335-7f92eaf23022@samsung.com>
 <dccaa337-f3e5-08e4-fe40-a603811bb13e@samsung.com>
 <CANpmjNP6-yKpxHqYFiA8Up-ujBQaeP7xyq1BrsV-NqMjJ-uHAQ@mail.gmail.com>
 <740077ce-efe1-b171-f807-bc5fd95a32ba@samsung.com>
 <f114ff4a-6612-0935-12ac-0e2ac18d896c@samsung.com>
 <CANpmjNM6bQpc49teN-9qQhCXoJXaek5stFGR2kPwDroSFBc0fw@mail.gmail.com>
 <cf6ed5cd-3202-65ce-86bc-6f1eba1b7d17@samsung.com>
 <CANpmjNPr_JtRC762ap8PQVmsFNY5YhHvOk0wNcPHq=ZQt-qxYg@mail.gmail.com>
 <YIBSg7Vi+U383dT7@elver.google.com>
 <CGME20210421182355eucas1p23b419002936ab5f1ffc25652135cc152@eucas1p2.samsung.com>
 <YIBtr2w/8KhOoiUA@elver.google.com>
 <dd99b921-3d79-a21f-8942-40fa5bf53190@samsung.com>
 <CANpmjNPbMOUd_Wh5aHGdH8WLrYpyBFUpwx6g3Kj2D6eevvaU8w@mail.gmail.com>
From: Jon Hunter <jonathanh@nvidia.com>
Message-ID: <e590c4f6-ad6a-26a4-4f5f-9e6e63bfb15a@nvidia.com>
Date: Thu, 22 Apr 2021 09:16:43 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <CANpmjNPbMOUd_Wh5aHGdH8WLrYpyBFUpwx6g3Kj2D6eevvaU8w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Originating-IP: [172.20.145.6]
X-ClientProxiedBy: HQMAIL111.nvidia.com (172.20.187.18) To
 HQMAIL107.nvidia.com (172.20.187.13)
X-EOPAttributedMessage: 0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 46b2d5bf-fba0-49a2-bcdb-08d90566fc25
X-MS-TrafficTypeDiagnostic: MN2PR12MB3758:
X-Microsoft-Antispam-PRVS: <MN2PR12MB3758BFD9334AFFC08B699A0CD9469@MN2PR12MB3758.namprd12.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:10000;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: nm5s+WgV7SQ8bBFfG1OlcKc4uJ8eghCmgsLVl90qOnH7vUoHUilS0KzakTQwzcepwt5ugpt55utCYrfBj/1Y8caAsOpqtF69hgQuFqbtkvXXOoya/gjp0VR9Fo72P5iNhXMqxGRTxi1vMLXtzxHYHkEe1oYToKMVExl8kCZAS/efyxYO4RqumzkN63dp6N6q/3Nnc2eE2VpdOylZJBnrDiJLIfNi6R30GodaE/UWY+yj5X9BT3Cv2slDjMSwsmlHZzcbR5nQ7ho6/Kn80NllfSBWVDBHRoCzj288AvgQ4gYaguKF+ZLmNnCHH9a++5d8vW892rLv6M3lLCcgQW/Vyas7DEUncHc6sn80YYBmOptNvwE3cGVDiz1aOxlW4LIif6T7WAs0gVO0cdawLjcuoHoyRXYyKQi+/BZ8CnCbwnO0P9VTHIP5ho9Wse+2lZWZRHEo38NOS+ImQI2Lzvk8fucnoYyypZbvGDXXEGtyIxkIIxTfqhC6TUveqoAs56j3HJ6m6sX+p1i3i1Rq9eCNKoLnanjUOiI3kZYQnU+sJnaiV790TwJy9J32EWuEi1reqf6a75CIfZjGHyTLx6qG8OeTCPCwpP0c/DCbqckI8BiIg6eueATDXyqg9ZNiL0B9k5qFe4SIhmZVFM27OV2a+JRGqiCqxNZHKYRIldNIXqgwf/kwdmwB7o5iHPYbp82L/VcQRak5K6V9BjLh/WrokNpemkKLx6wZgu/V0DHHTNbRd4UNxygJytVEFq98zeiFd9J+ns7urgpbOaX7dOyhEg==
X-Forefront-Antispam-Report: CIP:216.228.112.34;CTRY:US;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:mail.nvidia.com;PTR:schybrid03.nvidia.com;CAT:NONE;SFS:(4636009)(39860400002)(376002)(136003)(396003)(346002)(46966006)(36840700001)(5660300002)(86362001)(31686004)(7406005)(36906005)(7416002)(316002)(82310400003)(7636003)(82740400003)(83380400001)(31696002)(70586007)(70206006)(356005)(186003)(426003)(36756003)(8676002)(4326008)(47076005)(16526019)(966005)(36860700001)(53546011)(110136005)(478600001)(2906002)(54906003)(16576012)(2616005)(8936002)(26005)(336012)(43740500002);DIR:OUT;SFP:1101;
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Apr 2021 08:16:52.3701
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 46b2d5bf-fba0-49a2-bcdb-08d90566fc25
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=43083d15-7273-40c1-b7db-39efd9ccc17a;Ip=[216.228.112.34];Helo=[mail.nvidia.com]
X-MS-Exchange-CrossTenant-AuthSource: CO1NAM11FT066.eop-nam11.prod.protection.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN2PR12MB3758
X-Original-Sender: jonathanh@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=eUWZMqLe;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jonathanh@nvidia.com designates
 40.107.223.55 as permitted sender) smtp.mailfrom=jonathanh@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
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


On 22/04/2021 07:47, Marco Elver wrote:
> On Thu, 22 Apr 2021 at 08:12, Marek Szyprowski <m.szyprowski@samsung.com> wrote:
> [...]
>>> So I think we just have to settle on 'unsigned long' here. On many
>>> architectures, like 32-bit Arm, the alignment of a structure is that of
>>> its largest member. This means that there is no portable way to add
>>> 64-bit integers to siginfo_t on 32-bit architectures.
>>>
>>> In the case of the si_perf field, word size is sufficient since the data
>>> it contains is user-defined. On 32-bit architectures, any excess bits of
>>> perf_event_attr::sig_data will therefore be truncated when copying into
>>> si_perf.
>>>
>>> Feel free to test the below if you have time, but the below lets me boot
>>> 32-bit arm which previously timed out. It also passes all the
>>> static_asserts() I added (will send those as separate patches).
>>>
>>> Once I'm convinced this passes all others tests too, I'll send a patch.
>>
>> This fixes the issue I've observed on my test systems. Feel free to add:
>>
>> Reported-by: Marek Szyprowski <m.szyprowski@samsung.com>
>>
>> Tested-by: Marek Szyprowski <m.szyprowski@samsung.com>
> 
> Thank you for testing! It's been sent:
> https://lkml.kernel.org/r/20210422064437.3577327-1-elver@google.com


Thanks! This fixes the problem for Tegra as well. I have responded to
the above patch with my tested-by.

Cheers
Jon

-- 
nvpublic

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e590c4f6-ad6a-26a4-4f5f-9e6e63bfb15a%40nvidia.com.
