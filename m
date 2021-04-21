Return-Path: <kasan-dev+bncBCZLRWEX3ECRBMH7QCCAMGQEYILYIXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id A70E4366EC3
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 17:07:29 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id x9-20020a056a000bc9b02902599e77f7afsf8142818pfu.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 08:07:29 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1619017648; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZKo2nLxE1t64TMIUu4Y+wX/nXNPq7WITW/cEaiDSXb8sND+ztRg0En2zoAloixjBPg
         WDP7qx5wrTk90CqLPf7/xDc363Lej/obwwwXCsgO26PxgyK7CPPQ/B3FmYPywxIa8vjr
         VWYAsGeGLWPGgwbFXvvZrFDXTADpHWjmNNgxx/aFIDTjU6WS2YWIUaUZCTaMhWnAmLu5
         apv330b/UnmyF+QQgwGeivwGGw6HrL33uvbxA9BBm3gUR8PUiHKENwxK8ZgQnH97o9Qp
         mq3GcPRssG0uHVDY13J9O8Br9/Ln4tZmc0JMDS5oFzUIlVDRf6V1j9xjqjehz/2nMAQO
         Hj7Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=fpj/WvYgq4kAasDMsU+l4YTFBY4RfG9FlP0YTtXKth4=;
        b=jDoYpOnaD30gFwlvwU3fwp4CtcQLKGReTQC6ZiumCP4K7aIiOM6wWTgiJC+ylMOSzH
         +VCow1yUSZFTll9SmnQO3ecE7LlrFMfVK2758CB3kTlGsoKdEi0XT9t/KmJ8Fy9RuQTH
         MZAeKeUP5Ej/irtTNBvkgN5Ht80B+t9oxcGPFrb6GCp79S4tf2Kht/lLXU8L+DsCceAI
         AdHqu2earA67hY0Cjzi0DuhC7FJa7rehFsRSt2QURhCr6iTxAOHHt0NuZURh7u7fyXES
         gJf+UqPwDXyUBt1uCcSKvpXcjmE0W6IOfjkTIwTUq4PYBpkt5NJwQtILUr8CzBJcOgP3
         IwTA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=QvibK0bQ;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jonathanh@nvidia.com designates 40.107.75.75 as permitted sender) smtp.mailfrom=jonathanh@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fpj/WvYgq4kAasDMsU+l4YTFBY4RfG9FlP0YTtXKth4=;
        b=g8QWrEyp/j+vn9MB3Rx7CfJ2IikQoB+8TuyR2XPiKaY/zO4b6QZTpbA78VfyTl3/R/
         05INKJHM1BHgVbLppkbGr5LhdD6T+a3aeleuJsFWn/zw0dfIyedICAMF0+LHXyxSp1ph
         RkwAOKBERsq/OZ9s6olC0N43JUts6MG6upe9mIDuTA/6ymiix5wKzpcAOqJY4glJ9wVv
         sUd8jAxZihFMHMfKF6tvfI16Sp1hgMn6z7gRrijNFAEWpy5SbUTlLxTNHPx84j0Q9BSe
         kHMoRpuQpVdKu+6QNt/JSdbBIkYjlu8Bo1en0PEGz1cYQrhPF+62PJudOepA2NhUr2Am
         rDxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fpj/WvYgq4kAasDMsU+l4YTFBY4RfG9FlP0YTtXKth4=;
        b=jtDRCjlg1ot9lg1FjNjIQG325xMilwn/0DMcnHYt/SqgFKUgHPXLz592z9LhHSw5Ux
         uNVbOZ/+ummeLZ60+8UbR/LuhZc9Z0I8qfIjRnMTBFSTpqDy4ip7yO53EmAfR3QZI3ip
         AANjA5MR3TGY0PCx6Etgue5QCQF1IduI1lF6BZXv/G2x/RpmeYTx5pO77YCvZRAKjA4u
         KMT2zlnDrcTi+OTp2+uJvoH53h2dhAxIgXaaI9DCtw5EB2tRj6G0uyhGWCWLSZTZfCre
         OtjOSKMtqpDfJ/gJZW0qKVL0lzM8sI417tJRlNM8Iau+xxu+b5wWCewjpIfTQnGegiUi
         OHdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+0d/iA6pAZfodewNf8Tm7SzNsq4+SxogOljkyXm+otAA+ljN5
	u49THto/hR5x7mcCJY/7TWo=
X-Google-Smtp-Source: ABdhPJwuzXWo/hsPTvnGN4LPY1b48HyeTMQaiTi7FzKV1R1incDMBQ0mZxpk3rD7gvFDpTq001coXg==
X-Received: by 2002:a17:90b:249:: with SMTP id fz9mr11330977pjb.167.1619017648330;
        Wed, 21 Apr 2021 08:07:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:79d5:: with SMTP id u204ls981399pfc.9.gmail; Wed, 21 Apr
 2021 08:07:27 -0700 (PDT)
X-Received: by 2002:a63:5322:: with SMTP id h34mr22575653pgb.182.1619017647680;
        Wed, 21 Apr 2021 08:07:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619017647; cv=pass;
        d=google.com; s=arc-20160816;
        b=KyEQjJCRyLNmCEfikrbQSyRlXflqWLRt4Z9WqfS5yJd+b/XFH7nz5oKPrsw73VX+gO
         aEhe4O2NRUiFUK86I372N1OWusT8zfh2xl7b1Gtw5vlaGKo3P9GtdoMtmvz9lxhwn/9Q
         6DDbk94ee0zkCyk2nonmx3QCSy4smpGDrked5oyoaL6gDVzq9jwxMnv9OTzbQkW4ryuN
         H6Cy18knuU+rChjv3e/yu19mq8iyWC5TV5IHlIY5Jq1awnegT7WNZg9KcQjpmPwVEerD
         NfiSFrpl/vBACrFlkxXNfNUq11VeCcwmG75X49+XSpReGv69gzkY/1AQysq4AwKdlPsX
         bMCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=1Hz6XlcExdhxkeP7H5H8MIczXGLVYlD+EsooV8ep78o=;
        b=IyokKmxZ/vDRhG/VLNveRLwgWOt3JBd9IdKMc6/tGxEdjQa/a6AuxBJFpmhRVrmFJk
         Yo6Aa6svYknJ4/iH6rkkK2wD2uhbhTBZ+Wya778MV3ENOUcSBIshtjIv9WMbfb6SmDFt
         +WGLnz9KwxTCQiPcGWdzS8Md4rK7YSaO23iB09Zdjmy7lTeNVidRH0cf4pZiXmDrBfmB
         lGZBFf2M2+5qOe92PX7pOzVoSqHcKfA7xbUuLIlJdxl2sA0qPHuq3HQ0KJswxu3QhH76
         00VO7d0/uQUbtr8w02Btfv62lgKP4BIFYqAICU0qi3R0cIu2HkevV624qP8W1z9Yw0Uw
         9nng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=QvibK0bQ;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jonathanh@nvidia.com designates 40.107.75.75 as permitted sender) smtp.mailfrom=jonathanh@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
Received: from NAM02-BL2-obe.outbound.protection.outlook.com (mail-eopbgr750075.outbound.protection.outlook.com. [40.107.75.75])
        by gmr-mx.google.com with ESMTPS id p18si231901pgi.3.2021.04.21.08.07.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Apr 2021 08:07:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of jonathanh@nvidia.com designates 40.107.75.75 as permitted sender) client-ip=40.107.75.75;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=hodxI244DlnMlsd4U7em2E++AiS1m5luIMEOIhwG5G3yolHZZtucz9uQsDHVP8A/36AB4soPVuud29QDAAzzfVIw3GyyaTKZxEHhexKusp22nvl1RsNg8cH8E4iGQpEHshvXDaNg0qd61blzxUBB19lGFzAZBG1oUUbeJYJ17RoONA9HHetrQxAG3zE4v2/y3Hv1sKPHy+cm4FpzbQofE7Emoj5k4Uhwpgyz/nK+YhWe5nyAz1emiwfhzg0fz6kCj3PRG7cj1tjDvUKfT1yeh7f9GVccaf2DEj8BRqltxhapJjH1d43m8q3R3ydSjScJqxNYHoI5xY5Cji6WMJosWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=1Hz6XlcExdhxkeP7H5H8MIczXGLVYlD+EsooV8ep78o=;
 b=eeYhHVsgU+bG1hn4SwPDoTtS8xJ3vZubaljUxum792+0CTqoS1k1kkyF8bxX6nTNr6zioxh34UfA4UxlNmOM8QCXer9csIA+Z8cWNkMZld9sR7nHjIB8Aljg9eNn5OLrAZC4ULn9Vha4fiB65TJ3gMwlJr/Op4CdxnmUs46DrC26LDqATimykoEGjl27rP+U3ZRF90+nZdSmfTBCt8sE31v1U/ry0AeA5+Cye504g15gPytn7v+9GXxNkSE84hEA9BnGdc6RL56iw9jyeshdeC4XzJD+EC2ezbAyLLjxRg0uAvRybIDFPUq92L5/xZHhEgX+1BpUjHVUlyLRRkG1pg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass (sender ip is
 216.228.112.34) smtp.rcpttodomain=google.com smtp.mailfrom=nvidia.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=nvidia.com;
 dkim=none (message not signed); arc=none
Received: from MWHPR20CA0048.namprd20.prod.outlook.com (2603:10b6:300:ed::34)
 by MWHPR12MB1519.namprd12.prod.outlook.com (2603:10b6:301:d::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4065.21; Wed, 21 Apr
 2021 15:07:25 +0000
Received: from CO1NAM11FT052.eop-nam11.prod.protection.outlook.com
 (2603:10b6:300:ed:cafe::1e) by MWHPR20CA0048.outlook.office365.com
 (2603:10b6:300:ed::34) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4065.20 via Frontend
 Transport; Wed, 21 Apr 2021 15:07:25 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 216.228.112.34)
 smtp.mailfrom=nvidia.com; google.com; dkim=none (message not signed)
 header.d=none;google.com; dmarc=pass action=none header.from=nvidia.com;
Received-SPF: Pass (protection.outlook.com: domain of nvidia.com designates
 216.228.112.34 as permitted sender) receiver=protection.outlook.com;
 client-ip=216.228.112.34; helo=mail.nvidia.com;
Received: from mail.nvidia.com (216.228.112.34) by
 CO1NAM11FT052.mail.protection.outlook.com (10.13.174.225) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 15.20.4065.21 via Frontend Transport; Wed, 21 Apr 2021 15:07:25 +0000
Received: from [10.26.49.10] (172.20.145.6) by HQMAIL107.nvidia.com
 (172.20.187.13) with Microsoft SMTP Server (TLS) id 15.0.1497.2; Wed, 21 Apr
 2021 15:07:15 +0000
Subject: Re: [PATCH v4 05/10] signal: Introduce TRAP_PERF si_code and si_perf
 to siginfo
To: Marco Elver <elver@google.com>, <peterz@infradead.org>,
	<alexander.shishkin@linux.intel.com>, <acme@kernel.org>, <mingo@redhat.com>,
	<jolsa@redhat.com>, <mark.rutland@arm.com>, <namhyung@kernel.org>,
	<tglx@linutronix.de>
CC: <glider@google.com>, <viro@zeniv.linux.org.uk>, <arnd@arndb.de>,
	<christian@brauner.io>, <dvyukov@google.com>, <jannh@google.com>,
	<axboe@kernel.dk>, <mascasa@google.com>, <pcc@google.com>,
	<irogers@google.com>, <oleg@redhat.com>, <kasan-dev@googlegroups.com>,
	<linux-arch@vger.kernel.org>, <linux-fsdevel@vger.kernel.org>,
	<linux-kernel@vger.kernel.org>, <x86@kernel.org>,
	<linux-kselftest@vger.kernel.org>, Geert Uytterhoeven <geert@linux-m68k.org>,
	linux-tegra <linux-tegra@vger.kernel.org>
References: <20210408103605.1676875-1-elver@google.com>
 <20210408103605.1676875-6-elver@google.com>
From: Jon Hunter <jonathanh@nvidia.com>
Message-ID: <81254854-aa22-fab1-fc6f-22716b7c2732@nvidia.com>
Date: Wed, 21 Apr 2021 16:07:13 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <20210408103605.1676875-6-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Originating-IP: [172.20.145.6]
X-ClientProxiedBy: HQMAIL111.nvidia.com (172.20.187.18) To
 HQMAIL107.nvidia.com (172.20.187.13)
X-EOPAttributedMessage: 0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: ec883513-a740-4be9-fa1c-08d904d72c58
X-MS-TrafficTypeDiagnostic: MWHPR12MB1519:
X-Microsoft-Antispam-PRVS: <MWHPR12MB1519E77813E2DDEDC4D904C5D9479@MWHPR12MB1519.namprd12.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:1148;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: ZoEHylcQurSelIXMAse60Pl6Vp6bWaXID/qD8iT4o2P7RDDj09dep7ybG0PGNTIPZtrO9bL8NPbghZ0enkUWyMBZHN91/+9n3JH8RjMdG0FpCQpYFunme/rAmMpWYWbpFgSVoLlp38AdziHzW+l++RuDY6RB+1NZNDrETm9xjiQskn+FvWbBj8tGw+awC08bZivrPCGC+N4yeGJ0nRtHW/jK7VZEd96vE1vusNKT2fFsXrIAvJ5+0hgJzCt0s3ethMw3JY+W2fpjSfxvUVI+XaNFFVZDHe/AgqpzSx/ujjyxX/hlP63lBz5WH84Y7nSKUF0hs0gksFl/oK/JeQjbNcPz4L97lbwW0md54jS6PlF1dc6X9gWV37D5ZBiS4RgxK4w4M05sU5b7Ve7RHZJeZHBUPvhHkmIAycLfi1SgP/yQ1kpZrDowPsp1LLvwso8WrtKUV29Z9oqHLO7JxPgKj5QoTeTDn8uDOdSLg3K+WSFpuul4IJcOPqfOEO2NLp6sR4jA50jUqBjNH8Zxf4rmb1BfuK9k7bzCnZCYm6JrX0qniphrEWqL2Jx8x2P307T3VACyCC7uL7hB2PIvqZ5G1OBZS4Iwykgb5GmrN8QtBtfXFC8J8oFbjpD3ZRqB7I/9wvT/Uqb9mnWRd+KMA/RWz0FsB6iAcEGpucyOox29HCw9x+jUK8+bKTotOMsG5PpWmaPK07XaTUFrDE7s6zKwqg==
X-Forefront-Antispam-Report: CIP:216.228.112.34;CTRY:US;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:mail.nvidia.com;PTR:schybrid03.nvidia.com;CAT:NONE;SFS:(4636009)(39860400002)(136003)(396003)(346002)(376002)(46966006)(36840700001)(5660300002)(53546011)(4326008)(316002)(36860700001)(82740400003)(4744005)(82310400003)(47076005)(86362001)(2616005)(7636003)(31696002)(478600001)(2906002)(70206006)(83380400001)(7416002)(8676002)(36756003)(356005)(8936002)(31686004)(70586007)(16526019)(426003)(26005)(16576012)(36906005)(110136005)(186003)(336012)(54906003)(43740500002)(2101003);DIR:OUT;SFP:1101;
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Apr 2021 15:07:25.7014
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: ec883513-a740-4be9-fa1c-08d904d72c58
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=43083d15-7273-40c1-b7db-39efd9ccc17a;Ip=[216.228.112.34];Helo=[mail.nvidia.com]
X-MS-Exchange-CrossTenant-AuthSource: CO1NAM11FT052.eop-nam11.prod.protection.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MWHPR12MB1519
X-Original-Sender: jonathanh@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=QvibK0bQ;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jonathanh@nvidia.com designates
 40.107.75.75 as permitted sender) smtp.mailfrom=jonathanh@nvidia.com;
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

Hello!

On 08/04/2021 11:36, Marco Elver wrote:
> Introduces the TRAP_PERF si_code, and associated siginfo_t field
> si_perf. These will be used by the perf event subsystem to send signals
> (if requested) to the task where an event occurred.
> 
> Acked-by: Geert Uytterhoeven <geert@linux-m68k.org> # m68k
> Acked-by: Arnd Bergmann <arnd@arndb.de> # asm-generic
> Signed-off-by: Marco Elver <elver@google.com>


Since next-20210420 I have noticed a boot regression on all 32-bit Tegra
that we are testing. Bisect is pointing to this commit and reverting
this patch and patch 6/10 does resolve the issue.

Interestingly there is no apparent crash, but these systems just appear
to hang silently after mounting the rootfs. If anyone has any thoughts
let me know!

Thanks
Jon

-- 
nvpublic

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/81254854-aa22-fab1-fc6f-22716b7c2732%40nvidia.com.
