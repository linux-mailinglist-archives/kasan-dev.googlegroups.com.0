Return-Path: <kasan-dev+bncBCX7RK77SEDBBYF54SAQMGQE4DUHKWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EDE432655C
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Feb 2021 17:16:34 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id f127sf10341826ybf.12
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Feb 2021 08:16:34 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1614356193; cv=pass;
        d=google.com; s=arc-20160816;
        b=BfUy1ZddUrvQB4v9z5d0Xeq2SdMQHaqXgZcKZ+gl+Oot1zUMFwdakiRNOF5t2YPcjb
         46gh44NPdDhOt4oHF0oLqtfaptERhxDnen87AnCToovmRu5wN7ZXO4DvN4mY/SEIG6vp
         1JXfd9JSuNB9+c2Gy9MtYgvrX4YRlk6ss0kgf/kYo/2dSUiJdJvI/DljVZozewO9SK8E
         dl4ZReiqdiU93Zc/YmMHBT8ZdezTZRUeDhq4jkw6S6fUS/NU98AcMJf22Bu2bQJzNbTJ
         5yByiYyvS/KVJ+pejXw8B9gHTb2l4sXVYKHLiR4rGYHtzVh0RIi/gkXlx8EAvVEzbcWV
         TOBg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :content-transfer-encoding:in-reply-to:user-agent:date:message-id
         :organization:from:references:cc:to:subject:sender:dkim-signature;
        bh=NPVosWx2Z5W+rQVbybocp2qTywHvJcOUxooZ/aMPH8A=;
        b=WoxaG9jADorbwSQQufiwXdlpiTpGrrSZwj3LgSH2s2bFMNiZPZsB3Ds/UoCJ15ho6X
         tUAsuF5qHnk9HhAghoLKf069l/mniNeJIwDtkV0x8737nuRnp85CGU+fSLn11xwD2oda
         f2LVRtk587NwfocjChIfNEZ+NvKiIAr4TZF9bVPoPFKgVm6ohfe8PIsMjJ+h/0ArEqnr
         k0HziEajspjqgd56J5kCX9Sr5qM7Z9On2GCxKtJCgD0A4GfxwxAIxtNI552WuRBkcybf
         awyE9/wiCvvOyKKHzSl4SxIt6ZiGZUVkGmm0J2r5Gw++vCRtqV5dq0O3In3t22ttbI1O
         uNgQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=zdRF4AwQ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=uoy5zmjF;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:in-reply-to:content-transfer-encoding:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NPVosWx2Z5W+rQVbybocp2qTywHvJcOUxooZ/aMPH8A=;
        b=F3RcKvBCcBXOOwvfk6MyFxi5qTZRsf1SJbWAxp79KVknTqdLNzjNoXMU7JuMuZpsTY
         7gpJ5o2ylFsETz/wOWHIT/3YIWhRYiOIkykO32ior9QLUciBeMNnCbFYYOz1ouf7tREG
         J8HnobxRnEfHIyaS9lzj46tKd93/p6bi1Us53do+W8bylgZbf0ZFlgdVrnlY99IlqTWk
         AiRUE1wGlwNyTFBzFMrYBgzTGJ7u4EJA2UbEzX76AVXWhiRnlOpEkSz+lQPRYCbQ8Ih2
         sm60kUO8TfJRgmdoFggJDJfDzBwLIfFJwHBXnkLHJbNCTS+Tqswjff12MbePfnVjy5kH
         Mlhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:in-reply-to
         :content-transfer-encoding:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NPVosWx2Z5W+rQVbybocp2qTywHvJcOUxooZ/aMPH8A=;
        b=QsOiFy7JS7Zjpt/R/j1tVIb2xgTR31mw7AMI5SJYHsZenALCk2h7ig7ZmJSWet4ncS
         UDg3tiElX60s1RkwS9yRcZjx5vRJjvFgPJRDdYEe7aboMFtfNJDzxA+YON0gtY3rhA43
         +1KIeHjwDhfyB8WVOlm8zmV54/vQoiITPT9/UgOdrF53ebg56LNtiSl3z6HcLDhTCrJl
         4QnIjuBVIjwkoAvV4C9S0vhGaXsYzkszNxesxRmGe8yZdwZz/PIhODMPDNiQf4oOmSib
         NR0EA/Jqxo2TDzKISfTwrzsG2QH/nhF1ldGWJrV/Xoi1LRjxB7PUGDN/i8cljZdYsOZA
         GQGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ueU2syQuhnsDKXkV2qex6QSx/o+CBCgdu5XjFUec1swCKWzHq
	hO3T6IF84CuJvdPhGFxiIN8=
X-Google-Smtp-Source: ABdhPJwUqN+HP4NgAGKUweaGkNydqHkHn6y0mKcK3RxfmgyVqAK4nVJZirgn4R/gRgph3sCoCzMX7A==
X-Received: by 2002:a25:db07:: with SMTP id g7mr5317934ybf.304.1614356192941;
        Fri, 26 Feb 2021 08:16:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:820b:: with SMTP id q11ls2491280ybk.5.gmail; Fri, 26 Feb
 2021 08:16:32 -0800 (PST)
X-Received: by 2002:a25:c749:: with SMTP id w70mr5273010ybe.393.1614356192449;
        Fri, 26 Feb 2021 08:16:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614356192; cv=pass;
        d=google.com; s=arc-20160816;
        b=vjQnSVCkcxkutd8jA40GMHdZpgotNA2wLXzLo2NnRQcjGaGLovtFW1s5hNti4tKEL4
         PzeFg2jgUGWFLSR7tBrUY0RiAqzP7wevGvXOpIMKpyOwxaiXm++zeZJGGTNWhGDHI18S
         QTcg0RNNkr+OBWISH7h+gZOmYGm1rLvbp6OtF8tzgiR5ninJBKDKIH+hqPYHf8rXnuNt
         M19K70Y/yBQKTzlrg+YBH/GVOdIFPZY8BeZrBWIrC9oruUWoZMPQi1CaDziozJaxWlu7
         MaB1hGhcJtT6LLOAcU2a5BOcm+O3lYAjN+T9XyIreOeQsupEgFyr7tLwdzxfXKD+qZG6
         4nBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:content-transfer-encoding:in-reply-to
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature:dkim-signature;
        bh=Ytf7G45iE6sxoo7dwT+4e9DlgHaCOdX1M6yCeo1GVEo=;
        b=R6z3DcV69n3jDodQwHf3zS/oqkJvcBEeIU8jeE6egdsvDg/w8jQr+dRO00BbQIs/U6
         uQjfdsaeqL4/s0Iu+RKFGv9OHrYZq1VE1tX0L5HN21yc3FkZD9FyAJSMd2WJGf08ssMi
         E7Vr5bBsZuK354OTJtc7BKWhJmQT9hd/bNF8o/rcUI9cbhHWvVrYc6juxoevZpywpueX
         HPsKrAH0gNx8vdbej9fYU6dU6sOewHUf4ayzZhiiXnU/BZ62oNhvwXCXf/CZ6WQ62e0K
         v2Jf9CJTspLBoXukcGLdeOUMi2iyrUo6tzuN03+q9xCyL9N3y1vtB0Op0arF/3CfCPTg
         IqzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=zdRF4AwQ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=uoy5zmjF;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from aserp2120.oracle.com (aserp2120.oracle.com. [141.146.126.78])
        by gmr-mx.google.com with ESMTPS id s44si769746ybi.3.2021.02.26.08.16.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 26 Feb 2021 08:16:32 -0800 (PST)
Received-SPF: pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.78 as permitted sender) client-ip=141.146.126.78;
Received: from pps.filterd (aserp2120.oracle.com [127.0.0.1])
	by aserp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11QGASm5058543;
	Fri, 26 Feb 2021 16:16:15 GMT
Received: from aserp3020.oracle.com (aserp3020.oracle.com [141.146.126.70])
	by aserp2120.oracle.com with ESMTP id 36xqkfa1s9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 26 Feb 2021 16:16:15 +0000
Received: from pps.filterd (aserp3020.oracle.com [127.0.0.1])
	by aserp3020.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11QGAkCc129740;
	Fri, 26 Feb 2021 16:16:14 GMT
Received: from nam12-mw2-obe.outbound.protection.outlook.com (mail-mw2nam12lp2043.outbound.protection.outlook.com [104.47.66.43])
	by aserp3020.oracle.com with ESMTP id 36ucb3kggd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 26 Feb 2021 16:16:14 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=IgABS4BnLQxr8gTonILQuSPBg3E90F0fG7ywbVG89QuI7LHMN4MTJl0/cvC/ZzfnX6cPIdzOE+aUFfGYtRp+A3RnFekPtZdIX7cmQPgL3u63HrS+A4Mj0UVLspiEZCP46w0uQ/sAy9MH2szqxPG4e4B537EkbI29QUTSz8iq+ws+Sz9o0CO2NKyQAX+SHynx4eEKt484eAyXZgtYPu9PTbRT5xzyVCUP/Mo0YZPzjdyWez2K9IUo/taXJ+hszvvqXGvCtOmGTIfEl473qpD68PFjpuHmqLsOebQ+LKFOkvtJ4A7GHASfPfMO5KXx07fodllNIqom0vkBTJjYTG5yjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=Ytf7G45iE6sxoo7dwT+4e9DlgHaCOdX1M6yCeo1GVEo=;
 b=alXobR5KwBgyz+UlEAq+oPfh7R1T+L/cnM+qcJyQ1svB7LRqDBNjW3jBMhIoaqfF3BjUVvdiqYvNhgoaqPwHPn1I3VxjQdj2i1qUwa14rakJqYC8OYAvxrPwE67YyH5eMPaToER/gs9lP1SKmL44D0wm1LZAJ1Cuy+lsHbgsj6kfWPxXrJGX2J+vWjrZztUkiIh6TCATJ0hDlyBAehnMTObugjwb2LJc0VpfR3uElQHa+ju0kUT6KBrP6ieuzS5LeNcaTUMd5wsEy4GPfWB74IaeyvVzw8cBm68okQDjoRNsclu/8d23R4vNAG+siAWDCTvsi4gPhRnWNJD/dT/rZA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM6PR10MB3851.namprd10.prod.outlook.com (2603:10b6:5:1fb::17)
 by DS7PR10MB5087.namprd10.prod.outlook.com (2603:10b6:5:3b0::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3890.19; Fri, 26 Feb
 2021 16:16:12 +0000
Received: from DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da]) by DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da%3]) with mapi id 15.20.3890.023; Fri, 26 Feb 2021
 16:16:12 +0000
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
To: Mike Rapoport <rppt@linux.ibm.com>
Cc: David Hildenbrand <david@redhat.com>,
        Andrey Konovalov <andreyknvl@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Catalin Marinas <catalin.marinas@arm.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Konrad Rzeszutek Wilk
 <konrad@darnok.org>,
        Will Deacon <will.deacon@arm.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>,
        Evgenii Stepanov <eugenis@google.com>,
        Branislav Rankov <Branislav.Rankov@arm.com>,
        Kevin Brodsky <kevin.brodsky@arm.com>,
        Christoph Hellwig
 <hch@infradead.org>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Linux ARM <linux-arm-kernel@lists.infradead.org>,
        Linux Memory Management List <linux-mm@kvack.org>,
        LKML <linux-kernel@vger.kernel.org>,
        Dhaval Giani <dhaval.giani@oracle.com>
References: <450a9895-a2b4-d11b-97ca-1bd33d5308d4@oracle.com>
 <20210224103754.GA1854360@linux.ibm.com>
 <9b7251d1-7b90-db4f-fa5e-80165e1cbb4b@oracle.com>
 <20210225085300.GB1854360@linux.ibm.com>
 <9973d0e2-e28b-3f8a-5f5d-9d142080d141@oracle.com>
 <20210225145700.GC1854360@linux.ibm.com>
 <bb444ddb-d60d-114f-c2fe-64e5fb34102d@oracle.com>
 <20210225160706.GD1854360@linux.ibm.com>
 <6000e7fd-bf8b-b9b0-066d-23661da8a51d@oracle.com>
 <dc5e007c-9223-b03b-1c58-28d2712ec352@oracle.com>
 <20210226111730.GL1854360@linux.ibm.com>
From: George Kennedy <george.kennedy@oracle.com>
Organization: Oracle Corporation
Message-ID: <e9e2f1a3-80f2-1b3e-6ffd-8004fe41c485@oracle.com>
Date: Fri, 26 Feb 2021 11:16:06 -0500
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.6.1
In-Reply-To: <20210226111730.GL1854360@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [108.20.187.119]
X-ClientProxiedBy: BYAPR07CA0010.namprd07.prod.outlook.com
 (2603:10b6:a02:bc::23) To DM6PR10MB3851.namprd10.prod.outlook.com
 (2603:10b6:5:1fb::17)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from [192.168.1.222] (108.20.187.119) by BYAPR07CA0010.namprd07.prod.outlook.com (2603:10b6:a02:bc::23) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3890.19 via Frontend Transport; Fri, 26 Feb 2021 16:16:08 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 64ad95ca-dd20-47b0-23a7-08d8da71d57f
X-MS-TrafficTypeDiagnostic: DS7PR10MB5087:
X-MS-Exchange-Transport-Forked: True
X-Microsoft-Antispam-PRVS: <DS7PR10MB5087821B223FADE776AFEFEBE69D9@DS7PR10MB5087.namprd10.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:1923;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: JAbwhjO0HPMCqOsv/9NL07qjE82pjwWC/cLxc3K+bx5/bJE3vZM/wipzV3albqOzK/Q/l3/Ekzq5aMp7gh4nSc/IyTZdrHl/kJyO/pg6Jr5ULGDv7H7/syqVGKuXLKMLREoeHbdAdnDLse7fHrwZJP2lPtqH6M59LCPcl/kBVt8Tmxvnnj6C7Go0ujE6zwyUhLMqSjVm3rLtApAF22PHYgXoBSq+nnC6gXN9EGAov6vr+P7tblmkDrD4Z5FCVQxYWnfjUsgZDCQMxFM9M++zEITCKLcMMcWUWFkqzCp+4blrdzsdqZC9CLqgfBboU2w+nSc3Tf3G0wERsQWjsqRL0WvWXUTIwgYlDzEFA6AX28VgsP7U99EnnK/huoe4TRjlBJ1LnYegCrM+ka7qd/DA3/XsTtwo+hj6gV62/VPxYxjgr/cwgUWJ2aiA2JLZ0VszEZqzWokQjJY3nfX9+VvQaow/CKyzyGP7qwMMw66mHCb9SGilgQVYRnNdrGR3NQt4Xa84MwYBpbum0/5fLjjCZtAE4cW6qCqL1Na5mR2pGHHN1Zw6pj0DYIDIgb5dhJxa5fsJv0T+TZoJOxNi2V58J4P81Wp81+lkNVJcjGlb7xEAMHk0weEW+xmr7YqUS1E+
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR10MB3851.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(39860400002)(396003)(136003)(346002)(366004)(376002)(8676002)(54906003)(6916009)(44832011)(66476007)(26005)(316002)(478600001)(36756003)(107886003)(7416002)(6486002)(66946007)(53546011)(66556008)(186003)(2616005)(16526019)(86362001)(2906002)(36916002)(8936002)(4326008)(16576012)(31686004)(83380400001)(5660300002)(31696002)(956004)(21314003)(45980500001)(43740500002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?utf-8?B?L0wvTm9TaWFvTFJQRFRxNm5rKzBwd1BIUWNWdzFGYmVRbW0vTzdXU2JsYkJv?=
 =?utf-8?B?YUZXSHdKblVUYnVLWmhaMENNWmIwOEdVMDlMR1RLaG9QeHNHaUh1dEp0STNy?=
 =?utf-8?B?U3g3UTNUd0VXZkZRNzlMMzdJS0JxV1IzbEVMbndvS3Rmam9Ib2IvNlg5d0Iy?=
 =?utf-8?B?bGVob0VBZVlNcVpDSEh0K2lZQjhLUlZqd1ZIdTBLdVBxdzJxbTBMSnlxdlZP?=
 =?utf-8?B?dWZ5SUtyZEZVRHJRZVBUSFIzVjNleTZWNXZtR3hUOG5MU1cxM0lPUHIzL3ZZ?=
 =?utf-8?B?WW9MRGJ5amR5Y2VYU1AwNGl5V1NiQnNwRHlOZFVESmRHekJVdmJmSTM5bWVC?=
 =?utf-8?B?bkJ4US9LQnIzNDF3Vk43QUd6Y1pCbytnT3h4NnRaS296WnZEQVdCRmhzMjZG?=
 =?utf-8?B?NlNlVW1KYXY1Nm10dnBtUVJCSnM3TnUzcE0wRnNvZUVjUG5oaVpmaVE3MXFK?=
 =?utf-8?B?YnJHdEpTZFNLcjY5aUxRMWE3MVJrdUJDR05zRWoyL3RWRHQ3UkYxVE5IZmFM?=
 =?utf-8?B?c1lXQUIrRjdFbDhNb20rdUhHb2UyQ25CWWFNUE1NOElwZmNTbklCZHlibGV5?=
 =?utf-8?B?OU1zTnlUVTNhejE3eG5BR1NZbnlLM21sRVRUYUZHMTVsR3hOeXJ2SDJOZU8z?=
 =?utf-8?B?NUxmbzl2VU1Ta1BFbnR0MHM0bGN3b3dHSzBKOUJSQ2hWb3Y2dlJOa3R2MjNx?=
 =?utf-8?B?Y25xcnBZSU1xMElsaEVWUzFaTWMvaE40TkFvd1liWTc3U0ZQNmdvdTQ2bjZJ?=
 =?utf-8?B?UCt0RTF5L0o3WWg2dnNHVUNVQ05nMkh4ODcxcmI1Ly8zSXdKYWU3WVIweERL?=
 =?utf-8?B?U2dmS1ljd0FrNjBuMTBGbDdNd3FaOGtIb0E1MkwxaWI2Sy9oTUM1ZGhTejhW?=
 =?utf-8?B?T2JJaC9FK3ZDZjc5dnhoamdEMXF2YzdwQmY4WUtpTE5qOEdCZERtNGx3S2hJ?=
 =?utf-8?B?MzlqRkhFZ1BVdVd5eUJ1dTlNQTFKMTI4Tm9uRDlISUQ2eFlEWUk2VWRsVyt0?=
 =?utf-8?B?QVl3VUp0bVJyN3lmOHZPN0VVc0NrdWtJaEtYY2ppRVZ0aTV5dUMvY1JINmpC?=
 =?utf-8?B?N3YwZ1hIVG1QYTZBN05vUUpJekZ0QVhlTzMvZFNCNUNOSXhIYmd6N283VHBK?=
 =?utf-8?B?Vmt3MkR0QWVwZVBWeDRHUjhSNlpkbVF0eVdtR2JzeHh0Rm53b29Ta3hUNjJK?=
 =?utf-8?B?RTF2VDdjU3l6THIvdWFrTElCUWRxNEdJdGFTMnVzZmM4ajJNS3NLclhkNDVp?=
 =?utf-8?B?ZUovQVg5dHkrT2ZDdDZYRG5uR2R2MHBiYXVBUWhZWFpDd2xDSm9DSmZCUEN6?=
 =?utf-8?B?VG5NMFR2V3BtdDNEWVFCUXovNVZsMmlsVUhzZXhmOHpVcTNaS3d0c2czUFVT?=
 =?utf-8?B?VHE5aHdNRHBoOUdTeEJ3WW9HQlgxYXJJRU1Sb096MGFrU1pMQXpTeHk5Tzgy?=
 =?utf-8?B?aWVvaFRNQ0hCTGJMZWpRWXd6akN5VENzQ3Eyb3hDZ3hGVHhFNlVpK3B1TmZu?=
 =?utf-8?B?WlNoTW8yQkMrTnJVQjZPenF3ZGdYRkVseWd6dE9iYVR5MklyWm0vRHBhQ0tp?=
 =?utf-8?B?bFZ2RG1zWkszUkd6VDFlQkNLTkR6QnlxbUphNEpBcDZTenp6VDNjRVNNRU9W?=
 =?utf-8?B?VnRlSm5seGh5RDRUOElBSHl2ZFRFM3djUWdaVUF0SldTcmpBVlNhc3NKeVBS?=
 =?utf-8?B?eG9Lb09PN2R1T3hIY1UyQUdmYTVqalU0bC9qNmc3NTIrdzlPWjJzWnZrb0xH?=
 =?utf-8?Q?oGVDi7w/QSoW1feaUhoMjnOj1zhe/rxVJmBrNxI?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 64ad95ca-dd20-47b0-23a7-08d8da71d57f
X-MS-Exchange-CrossTenant-AuthSource: DM6PR10MB3851.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 26 Feb 2021 16:16:12.3392
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: vjb0xyEnwgv4JGvzVuCXxdIDMR7odNFnr011BzuqNiL3rzC/GN+qQUWU/DXI+SVCFE2zUth/zTwfBxFv8CmWp4Sc2ycR7gIp+nS0V6VKlR0=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR10MB5087
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9907 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 suspectscore=0
 malwarescore=0 mlxlogscore=999 adultscore=0 bulkscore=0 mlxscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102260122
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9907 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 lowpriorityscore=0 clxscore=1015
 malwarescore=0 suspectscore=0 impostorscore=0 phishscore=0 mlxscore=0
 spamscore=0 mlxlogscore=999 bulkscore=0 priorityscore=1501 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2102260122
X-Original-Sender: george.kennedy@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=zdRF4AwQ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=uoy5zmjF;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates
 141.146.126.78 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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

Hi Mike,

On 2/26/2021 6:17 AM, Mike Rapoport wrote:
> Hi George,
>
> On Thu, Feb 25, 2021 at 08:19:18PM -0500, George Kennedy wrote:
>> Mike,
>>
>> To get rid of the 0x00000000BE453000 hardcoding, I added the following p=
atch
>> to your above patch to get the iBFT table "address" to use with
>> memblock_reserve():
>>
>> diff --git a/drivers/acpi/acpica/tbfind.c b/drivers/acpi/acpica/tbfind.c
>> index 56d81e4..4bc7bf3 100644
>> --- a/drivers/acpi/acpica/tbfind.c
>> +++ b/drivers/acpi/acpica/tbfind.c
>> @@ -120,3 +120,34 @@
>>  =C2=A0=C2=A0=C2=A0=C2=A0 (void)acpi_ut_release_mutex(ACPI_MTX_TABLES);
>>  =C2=A0=C2=A0=C2=A0=C2=A0 return_ACPI_STATUS(status);
>>  =C2=A0}
>> +
>> +acpi_physical_address
>> +acpi_tb_find_table_address(char *signature)
>> +{
>> +=C2=A0=C2=A0=C2=A0 acpi_physical_address address =3D 0;
>> +=C2=A0=C2=A0=C2=A0 struct acpi_table_desc *table_desc;
>> +=C2=A0=C2=A0=C2=A0 int i;
>> +
>> +=C2=A0=C2=A0=C2=A0 ACPI_FUNCTION_TRACE(tb_find_table_address);
>> +
>> +printk(KERN_ERR "XXX acpi_tb_find_table_address: signature=3D%s\n",
>> signature);
>> +
>> +=C2=A0=C2=A0=C2=A0 (void)acpi_ut_acquire_mutex(ACPI_MTX_TABLES);
>> +=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < acpi_gbl_root_table_list.current_t=
able_count; ++i) {
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 if (memcmp(&(acpi_gbl_root_table_=
list.tables[i].signature),
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0 s=
ignature, ACPI_NAMESEG_SIZE)) {
>> +
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 /* Not the req=
uested table */
>> +
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 continue;
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 }
>> +
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 /* Table with matching signature =
has been found */
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 table_desc =3D &acpi_gbl_root_tab=
le_list.tables[i];
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 address =3D table_desc->address;
>> +=C2=A0=C2=A0=C2=A0 }
>> +
>> +=C2=A0=C2=A0=C2=A0 (void)acpi_ut_release_mutex(ACPI_MTX_TABLES);
>> +printk(KERN_ERR "XXX acpi_tb_find_table_address(EXIT): address=3D%llx\n=
",
>> address);
>> +=C2=A0=C2=A0=C2=A0 return address;
>> +}
>> diff --git a/drivers/firmware/iscsi_ibft_find.c
>> b/drivers/firmware/iscsi_ibft_find.c
>> index 95fc1a6..0de70b4 100644
>> --- a/drivers/firmware/iscsi_ibft_find.c
>> +++ b/drivers/firmware/iscsi_ibft_find.c
>> @@ -28,6 +28,8 @@
>>
>>  =C2=A0#include <asm/mmzone.h>
>>
>> +extern acpi_physical_address acpi_tb_find_table_address(char *signature=
);
>> +
>>  =C2=A0/*
>>  =C2=A0 * Physical location of iSCSI Boot Format Table.
>>  =C2=A0 */
>> @@ -116,24 +118,32 @@ void __init reserve_ibft_region(void)
>>  =C2=A0{
>>  =C2=A0=C2=A0=C2=A0=C2=A0 struct acpi_table_ibft *table;
>>  =C2=A0=C2=A0=C2=A0=C2=A0 unsigned long size;
>> +=C2=A0=C2=A0=C2=A0 acpi_physical_address address;
>>
>>  =C2=A0=C2=A0=C2=A0=C2=A0 table =3D find_ibft();
>>  =C2=A0=C2=A0=C2=A0=C2=A0 if (!table)
>>  =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;
>>
>>  =C2=A0=C2=A0=C2=A0=C2=A0 size =3D PAGE_ALIGN(table->header.length);
>> +=C2=A0=C2=A0=C2=A0 address =3D acpi_tb_find_table_address(table->header=
.signature);
>>  =C2=A0#if 0
>>  =C2=A0printk(KERN_ERR "XXX reserve_ibft_region: table=3D%llx,
>> virt_to_phys(table)=3D%llx, size=3D%lx\n",
>>  =C2=A0=C2=A0=C2=A0=C2=A0 (u64)table, virt_to_phys(table), size);
>>  =C2=A0=C2=A0=C2=A0=C2=A0 memblock_reserve(virt_to_phys(table), size);
>>  =C2=A0#else
>> -printk(KERN_ERR "XXX reserve_ibft_region: table=3D%llx, 0x00000000BE453=
000,
>> size=3D%lx\n",
>> -=C2=A0=C2=A0=C2=A0 (u64)table, size);
>> -=C2=A0=C2=A0=C2=A0 memblock_reserve(0x00000000BE453000, size);
>> +printk(KERN_ERR "XXX reserve_ibft_region: table=3D%llx, address=3D%llx,
>> size=3D%lx\n",
>> +=C2=A0=C2=A0=C2=A0 (u64)table, address, size);
>> +=C2=A0=C2=A0=C2=A0 if (address)
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 memblock_reserve(address, size);
>> +=C2=A0=C2=A0=C2=A0 else
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 printk(KERN_ERR "%s: Can't find t=
able address\n", __func__);
>>  =C2=A0#endif
>>
>> -=C2=A0=C2=A0=C2=A0 if (efi_enabled(EFI_BOOT))
>> +=C2=A0=C2=A0=C2=A0 if (efi_enabled(EFI_BOOT)) {
>> +printk(KERN_ERR "XXX reserve_ibft_region: calling acpi_put_table(%llx)\=
n",
>> (u64)&table->header);
>>  =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 acpi_put_table(&table->head=
er);
>> -=C2=A0=C2=A0=C2=A0 else
>> +=C2=A0=C2=A0=C2=A0 } else {
>>  =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 ibft_addr =3D table;
>> +printk(KERN_ERR "XXX reserve_ibft_region: ibft_addr=3D%llx\n",
>> (u64)ibft_addr);
>> +=C2=A0=C2=A0=C2=A0 }
>>  =C2=A0}
>>
>> Debug from the above:
>> [=C2=A0=C2=A0=C2=A0 0.050646] ACPI: Early table checksum verification di=
sabled
>> [=C2=A0=C2=A0=C2=A0 0.051778] ACPI: RSDP 0x00000000BFBFA014 000024 (v02 =
BOCHS )
>> [=C2=A0=C2=A0=C2=A0 0.052922] ACPI: XSDT 0x00000000BFBF90E8 00004C (v01 =
BOCHS BXPCFACP
>> 00000001=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
>> [=C2=A0=C2=A0=C2=A0 0.054623] ACPI: FACP 0x00000000BFBF5000 000074 (v01 =
BOCHS BXPCFACP
>> 00000001 BXPC 00000001)
>> [=C2=A0=C2=A0=C2=A0 0.056326] ACPI: DSDT 0x00000000BFBF6000 00238D (v01 =
BOCHS BXPCDSDT
>> 00000001 BXPC 00000001)
>> [=C2=A0=C2=A0=C2=A0 0.058016] ACPI: FACS 0x00000000BFBFD000 000040
>> [=C2=A0=C2=A0=C2=A0 0.058940] ACPI: APIC 0x00000000BFBF4000 000090 (v01 =
BOCHS BXPCAPIC
>> 00000001 BXPC 00000001)
>> [=C2=A0=C2=A0=C2=A0 0.060627] ACPI: HPET 0x00000000BFBF3000 000038 (v01 =
BOCHS BXPCHPET
>> 00000001 BXPC 00000001)
>> [=C2=A0=C2=A0=C2=A0 0.062304] ACPI: BGRT 0x00000000BE49B000 000038 (v01 =
INTEL EDK2
>> 00000002=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
>> [=C2=A0=C2=A0=C2=A0 0.063987] ACPI: iBFT 0x00000000BE453000 000800 (v01 =
BOCHS BXPCFACP
>> 00000000=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 00000000)
>> [=C2=A0=C2=A0=C2=A0 0.065683] XXX acpi_tb_find_table_address: signature=
=3DiBFT
>> [=C2=A0=C2=A0=C2=A0 0.066754] XXX acpi_tb_find_table_address(EXIT): addr=
ess=3Dbe453000
>> [=C2=A0=C2=A0=C2=A0 0.067959] XXX reserve_ibft_region: table=3Dfffffffff=
f240000,
>> address=3Dbe453000, size=3D1000
>> [=C2=A0=C2=A0=C2=A0 0.069534] XXX reserve_ibft_region: calling
>> acpi_put_table(ffffffffff240000)
>>
>> Not sure if it's the right thing to do, but added
>> "acpi_tb_find_table_address()" to return the physical address of a table=
 to
>> use with memblock_reserve().
>>
>> virt_to_phys(table) does not seem to return the physical address for the
>> iBFT table (it would be nice if struct acpi_table_header also had a
>> "address" element for the physical address of the table).
> virt_to_phys() does not work that early because then it is mapped with
> early_memremap()  which uses different virtual to physical scheme.
>
> I'd say that acpi_tb_find_table_address() makes sense if we'd like to
> reserve ACPI tables outside of drivers/acpi.
>
> But probably we should simply reserve all the tables during
> acpi_table_init() so that any table that firmware put in the normal memor=
y
> will be surely reserved.
>  =20
>> Ran 10 successful boots with the above without failure.
> That's good news indeed :)

Wondering if we could do something like this instead (trying to keep=20
changes minimal). Just do the memblock_reserve() for all the standard=20
tables.

diff --git a/drivers/acpi/acpica/tbinstal.c b/drivers/acpi/acpica/tbinstal.=
c
index 0bb15ad..830f82c 100644
--- a/drivers/acpi/acpica/tbinstal.c
+++ b/drivers/acpi/acpica/tbinstal.c
@@ -7,6 +7,7 @@
 =C2=A0 *
***************************************************************************=
**/

+#include <linux/memblock.h>
 =C2=A0#include <acpi/acpi.h>
 =C2=A0#include "accommon.h"
 =C2=A0#include "actables.h"
@@ -14,6 +15,23 @@
 =C2=A0#define _COMPONENT=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 ACPI_TABLES
 =C2=A0ACPI_MODULE_NAME("tbinstal")

+void
+acpi_tb_reserve_standard_table(acpi_physical_address address,
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0 stru=
ct acpi_table_header *header)
+{
+=C2=A0=C2=A0=C2=A0 struct acpi_table_header local_header;
+
+=C2=A0=C2=A0=C2=A0 if ((ACPI_COMPARE_NAMESEG(header->signature, ACPI_SIG_F=
ACS)) ||
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 (ACPI_VALIDATE_RSDP_SIG(header->sign=
ature))) {
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;
+=C2=A0=C2=A0=C2=A0 }
+=C2=A0=C2=A0=C2=A0 /* Standard ACPI table with full common header */
+
+=C2=A0=C2=A0=C2=A0 memcpy(&local_header, header, sizeof(struct acpi_table_=
header));
+
+=C2=A0=C2=A0=C2=A0 memblock_reserve(address, PAGE_ALIGN(local_header.lengt=
h));
+}
+
 =C2=A0/*******************************************************************=
************
 =C2=A0 *
 =C2=A0 * FUNCTION:=C2=A0=C2=A0=C2=A0 acpi_tb_install_table_with_override
@@ -58,6 +76,9 @@
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 new_table_desc->flags,
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 new_table_desc->pointer);

+=C2=A0=C2=A0=C2=A0 acpi_tb_reserve_standard_table(new_table_desc->address,
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=
=A0 =C2=A0=C2=A0 new_table_desc->pointer);
+
 =C2=A0=C2=A0=C2=A0=C2=A0 acpi_tb_print_table_header(new_table_desc->addres=
s,
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 =C2=A0=C2=A0 new_table_desc->pointer);

There should be no harm in doing the memblock_reserve() for all the=20
standard tables, right?

Ran 10 boots with the above without failure.

George
>> George
>>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e9e2f1a3-80f2-1b3e-6ffd-8004fe41c485%40oracle.com.
