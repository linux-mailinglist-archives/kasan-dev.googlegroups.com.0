Return-Path: <kasan-dev+bncBCX7RK77SEDBB4MH2WAQMGQEF7SWBXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 422F8323034
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 19:05:39 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id y15sf10152736pgk.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 10:05:39 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1614103538; cv=pass;
        d=google.com; s=arc-20160816;
        b=FWVM/eZDHp9UzGoXQGCZPtREvS/TjKi5heDPKpoM01O1kyPxxFs3qOi6XaZOtc+g63
         A/EnDSSWV67aeKDH8bX3e3nTVFttuZ8m/AzBRxbicttiuq+35BrLQ9H+3WN8mrT1/wVn
         tFU7CyTs2lAOmMAnm3lO1zHUACfJwFOow5+l+5EvQkq6Svrlv3oiO/Y2IRZRasml+UpC
         kKmy+tJBOVF8liZ2/A3yLah/fHWLjDXuf4EqYpcjHZJL1apZjJL2PG9INVJT+UOHJfcq
         rwgraJibP2fqzWfF507+H9W1NwqULuFoDUXaCQgsTPmQniPZiiAYtMEn1PydmkRG2KYo
         hYGw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :content-transfer-encoding:in-reply-to:user-agent:date:message-id
         :organization:from:references:cc:to:subject:sender:dkim-signature;
        bh=nBS2YFloms1YZi0FKsARkIe3AlrsFe2QPf3uq/thmew=;
        b=mCjx/lxbC+7ids/jzWe01UjXRxyunnLx+o517gaBAFOrZ4hcgHWjm2C72bPsMFtE6Y
         ua+c2QjMrckqMWSWJbHjr0B3Mnp+eA++0sGayY3K4gY14olWvXfNoWiZEXYWGDbRPfYO
         UYRUAxtEveuT276KBSM3jZ9c2J0f7jJKq0CY6rB8mjeVlpMaXcMtnl8V2tBa4Pr3cZ6E
         uc206vTbp787sWVaWVHBaTFnmvc+qth2QnkmiP/C77w1TPOm+DouY0h+LBWAgFTkJx5O
         Yj9US70bxI/wYjJ4N6p7KX1ij2iVMNjwkA+y0P2jePLbMDXI9PiMm0QWTyicMEnML1vx
         lH1w==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=oFxyAcOu;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=WST7pqIW;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:in-reply-to:content-transfer-encoding:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nBS2YFloms1YZi0FKsARkIe3AlrsFe2QPf3uq/thmew=;
        b=Ivj+boi/rocLZ2yoXBfyCZWTAR+T4I+F5ESQ0eNTgIlapUY/z4tcCMDCAGNO1VUP56
         dKCjx+m2BCbhOVFcWybs5WOX3oy7BbHTVp6pS/EHn0YTQLpUAN2S6PnjigsISYOrM7ph
         XWOVAUGVgVJAG94zbTCmuPirWHRYUuxFEhDAQ9eW+E6ODVT1kBt+3ZO+hrHkGAze6Bkj
         ZOUU/Vce2/SDuAZ6OVQEZM+74oWi/PNr9VnzUKB+cpta6mRJ3a2pZ841W3vo8WQnKskB
         IgicxmWS57/6U7eJmlRj+l9Cta+N0GD6zinu/0HYJQydkcft7Pg5/yxUXxJwLkDnEiaj
         66Yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:in-reply-to
         :content-transfer-encoding:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nBS2YFloms1YZi0FKsARkIe3AlrsFe2QPf3uq/thmew=;
        b=lVIFZIVnh7NB7tJJnoARh3qmYKvryA2lwYx1+zzyk5cIQGaa5VKM8OZqEV9H1d4LTC
         za8xDgx40AdsTXoAD3mli9Kmepaz4Af8fgaqoGBXekv3yiWUbkbBk9ZXSudYmMxZxDMW
         hc4j72/aIJgTLIH3CKerRBIKEJSVSpgNnEfnf+oQBKOLTS1TNErZD/+gltgc4GT4Grxw
         I78u2vREaeaeTFu8friUi4gkw5Flvw2ExA2MGzVwvpegl9OXB8mQGxgJcsVBEpdWn5RE
         d8wICynfZrqWrmpjv8/kzpcIeL4f7GpuZNWBQgYFqr9fUcP6+lBXx1DuMRqQHPju5iC/
         G/xA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533SMrqZnfz5jfCGcoe1MMOr4/LGoA2+ithMuGVIps/CXg4Asojp
	JKs3XjoPFWajYlkOz1N/qqk=
X-Google-Smtp-Source: ABdhPJw0QtUo7MfDub/LW4bdiFvY7Cp85rwqDs8UvxiqpZjaYrqGcPKTF88taTSejCAYj0VAvKn9kg==
X-Received: by 2002:a65:4c08:: with SMTP id u8mr24777443pgq.203.1614103538003;
        Tue, 23 Feb 2021 10:05:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4c89:: with SMTP id m9ls7659420pgt.8.gmail; Tue, 23 Feb
 2021 10:05:37 -0800 (PST)
X-Received: by 2002:a63:4761:: with SMTP id w33mr25357485pgk.118.1614103537387;
        Tue, 23 Feb 2021 10:05:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614103537; cv=pass;
        d=google.com; s=arc-20160816;
        b=s20zdfvrwQyH5Go0HoHvYN6BwfhRxmexoBk9Sxqf1O4e1hPqE/Kr3Xw1Pn9FhM79jj
         B6ZpJmEUJyM5UO2+QFijO5qpEEuxa/3gClYQG2qqGY/7UYXBqcGBpFt8ahFMgj4P8lqu
         Fy+pZVa90XgNceewqN8fPsiC4i4oNGcqjEEIAHYameWGErm+fl+ZnGxvzZaLFwFjIGGh
         GrUqVH1LS6D6ExEWk4YUbha+gXmSFj/jrcpaB2o9RMEvjMrFe19uAI0FPRhMoUNahgEb
         yIeLtdeiwyWUNXLc9fhZkRtK8z9YFZ5t4GcabjYprX5e9oL8tCcylCcM08MQjxQ8EvNk
         LOHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:content-transfer-encoding:in-reply-to
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature:dkim-signature;
        bh=s3qhbGpMsBLVh/dROWQDr5uTQcl6wUEYNO6AnHU0k7s=;
        b=OVb9CGO62bnWgCA3N4PS9WtlkaEtHmbAthbKeJcnR8ZDAoFFF6HAcVwG1BbrRg2LXz
         1L0GbpJMH94pzKjmb2vXzrfa6KLlKcvI+WsYwQq3VD/Xbos2jflE1ohohcIatvwwsSBI
         W4CDl/TBozWMK3GdDUSBoaZo3R9THy840NZXTgO48PI9TGKryHF4uKqdVNkcPGI78dcj
         wGAocgayiHhNCHXCGXG11j0g/X2rIdYABDPihwhqg5utqqs83Fy6hGAX95hhnof4uEXr
         8oGKQEeFqOY6VXwMqKsVx+K1//fjKBa3MGaX2ijbDM7aofH+NpUa2Madmo2St5wPPptP
         asFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=oFxyAcOu;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=WST7pqIW;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2120.oracle.com (userp2120.oracle.com. [156.151.31.85])
        by gmr-mx.google.com with ESMTPS id k6si572045pgt.2.2021.02.23.10.05.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Feb 2021 10:05:37 -0800 (PST)
Received-SPF: pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.85 as permitted sender) client-ip=156.151.31.85;
Received: from pps.filterd (userp2120.oracle.com [127.0.0.1])
	by userp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11NI4Xps024361;
	Tue, 23 Feb 2021 18:05:19 GMT
Received: from aserp3020.oracle.com (aserp3020.oracle.com [141.146.126.70])
	by userp2120.oracle.com with ESMTP id 36ugq3f6ts-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 23 Feb 2021 18:05:19 +0000
Received: from pps.filterd (aserp3020.oracle.com [127.0.0.1])
	by aserp3020.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11NI0aOW110349;
	Tue, 23 Feb 2021 18:05:18 GMT
Received: from nam11-dm6-obe.outbound.protection.outlook.com (mail-dm6nam11lp2173.outbound.protection.outlook.com [104.47.57.173])
	by aserp3020.oracle.com with ESMTP id 36ucayqh6d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 23 Feb 2021 18:05:18 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=BSnn7OBkfX1IMdwjqN904aWincpC8K1Lm1tkFOZ6qcE2IyTzYZbT1AMPED4lmIE4vKmfxcHePLmGLpB9M2BOzLLhHJJWmOgyITHsU4g/mwVdLcsmxUyEe89u+a4iPPoTSSTH5uNDTxta6wavcgXhARoSTqb8BZ2Q55vEN8mgDBb+08+xQIrWcPPfXP1oH90SpvtUONe4bicemW3yJkkXO3xb2xwcIquhpCzHvwAzcWw3o7wffEpM3+48w/89EtSZcJ49gfJgWk/FFOwxDB2MRGEtwqeeYH7/Cc6cDzhCfCsAisRh/BKqMdthV3Xd+TVojxCki5o2ESfXJuM2cqD4IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=s3qhbGpMsBLVh/dROWQDr5uTQcl6wUEYNO6AnHU0k7s=;
 b=G9Bj9rvPgcse2xUZYwj+8zyJyUQig1W0iLxFoICK93hRiPYqTuSoxNunR9ty4yuEl72ina2THPzR+7HY+evtVvVj24jTQuJOm9yFW/Z2nGiLYLtD2I+G+au8SgHofCujS1nYCwPPPTLQe+SNjQsLCB0i65c5+H6NqGNIClb6gLbDeF6D2NhBjAiL1RqvM7qF9hPtfB8Yftx6iGg5aKwDxqkZe52EjDk6vdMzbn9BfLiig/xHNcapCwGNSa7z4RrA1vXud0OWpbMrpnKO17Z/OyfNoKmn1UtPhj2qf/3d4nrGqaD01JQJcF4WyaC+dQqJY9dE3tJbrN0PAS43tEfufA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM6PR10MB3851.namprd10.prod.outlook.com (2603:10b6:5:1fb::17)
 by DM6PR10MB3595.namprd10.prod.outlook.com (2603:10b6:5:17f::32) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3868.32; Tue, 23 Feb
 2021 18:05:13 +0000
Received: from DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da]) by DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da%3]) with mapi id 15.20.3868.033; Tue, 23 Feb 2021
 18:05:13 +0000
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
References: <c7166cae-bf89-8bdd-5849-72b5949fc6cc@oracle.com>
 <797fae72-e3ea-c0b0-036a-9283fa7f2317@oracle.com>
 <1ac78f02-d0af-c3ff-cc5e-72d6b074fc43@redhat.com>
 <bd7510b5-d325-b516-81a8-fbdc81a27138@oracle.com>
 <56c97056-6d8b-db0e-e303-421ee625abe3@redhat.com>
 <cb8564e8-3535-826b-2d42-b273a0d793fb@oracle.com>
 <20210222215502.GB1741768@linux.ibm.com>
 <9773282a-2854-25a4-9faa-9da5dd34e371@oracle.com>
 <20210223103321.GD1741768@linux.ibm.com>
 <3ef9892f-d657-207f-d4cf-111f98dcb55c@oracle.com>
 <20210223154758.GF1741768@linux.ibm.com>
From: George Kennedy <george.kennedy@oracle.com>
Organization: Oracle Corporation
Message-ID: <3a56ba38-ce91-63a6-b57c-f1726aa1b76e@oracle.com>
Date: Tue, 23 Feb 2021 13:05:05 -0500
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
In-Reply-To: <20210223154758.GF1741768@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [108.20.187.119]
X-ClientProxiedBy: SJ0PR05CA0019.namprd05.prod.outlook.com
 (2603:10b6:a03:33b::24) To DM6PR10MB3851.namprd10.prod.outlook.com
 (2603:10b6:5:1fb::17)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from [192.168.1.246] (108.20.187.119) by SJ0PR05CA0019.namprd05.prod.outlook.com (2603:10b6:a03:33b::24) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3890.11 via Frontend Transport; Tue, 23 Feb 2021 18:05:09 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: cb59a264-b97d-41e3-3736-08d8d8259116
X-MS-TrafficTypeDiagnostic: DM6PR10MB3595:
X-MS-Exchange-Transport-Forked: True
X-Microsoft-Antispam-PRVS: <DM6PR10MB35958451603B6C5B974399C4E6809@DM6PR10MB3595.namprd10.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:7691;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: Lfi1BWxg3j1BTJe6B/gMF2jVlcXEVQdFzCoW4mOXnx6ajuzoeN9cDLHXz+iixO0qHNxVvcuZoWkz7LV6xcC2Zy6xHJG/hpnNq4IaiSV5cyOj1fd64u9H89ZAyWrGJp8j0N/xJgbMXEzyD4OZ7kFZtdjuUXnGxkUYtqnMo1BTLW8/nS4e3sIa1F/5s1OyWWAGVZgfeDQKhonr33KZUQ+XZQV8CYVSSqUAJHOxhtDmiIjl94okSNxWk7/RkbANSfbFxERHqtOTKbCIMaUBHihh8PYgCmiS+sYbBhAUVaj4q6VfLwS3hLzFEKRMluacUHETgRMkBjx02BGdvbj9IsbqHQhvTI5QUeBdAbxOAafSvse52Sp31qnxMGonJ2h8qrrsDqS8Yewpshw1XHjqYjkp+hz1IOUakQwCuOTbYXnLqAgnXVWaa7jwJm7sFyjUZ/ub9ZKYF1WaIRHxMuk2of2UndNen0wgL6v9dPOuUzR1lV6caigugAn5o7zu5OHlcYnR9O3OQFcCJ4IYMwxZqeb/0DjYPDUgPhAgbKgz5w5tcRf6RFPA7CYX3R68rOVWWPNuz8OhhjxwKZyIg0agoN6f2ZGti5uJc5eehqOZOobUosPRpaWxVBMoBD/5FxUBanmP
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR10MB3851.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(396003)(346002)(39860400002)(366004)(136003)(376002)(8936002)(31696002)(478600001)(6666004)(16526019)(26005)(6916009)(6486002)(83380400001)(8676002)(16576012)(186003)(2906002)(36916002)(316002)(44832011)(31686004)(66476007)(66946007)(54906003)(4326008)(66556008)(107886003)(7416002)(5660300002)(86362001)(2616005)(53546011)(956004)(36756003)(21314003)(43740500002)(45980500001);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?utf-8?B?clFvSnAzYXF3bHhnNDl1cVBLUm15QUEwTUxKN2hheTE4Q0hUK3h4NU5iTmtz?=
 =?utf-8?B?MjF5TFlWWjNHTkd0TVE4cmpuaHZtTHlMREMyV0NVZExkcjdIVFJjVXc2b0dL?=
 =?utf-8?B?bEtlQVdsZ1dYcnpsYkhTZTczc0h0d0MzWk9OZmpPVGM4TG42TVFld3RJd0pB?=
 =?utf-8?B?bFR1UldpQW50RzlZeVc2dE9NOTZ4SlhHVkw5VXE1VmIxV3ZHMnNNeXVaTG9C?=
 =?utf-8?B?RHcrZWFRYTc2dzBaNTVkM3NObEpJSGxLUmR0NmZRcG14NEFBNE12TFFhZWF2?=
 =?utf-8?B?blZVenR5ekhKY3g1VGpndTBXdDVZczhwUFBtLzlHcllGUkNGcDZoZk5aQ3dO?=
 =?utf-8?B?WGZ5U0U2VjlPd0Y2bG9lbzVjdmNhMTd6MldtNWZ1WUk5ZjBWRWtqdVJ4M3dz?=
 =?utf-8?B?MXRCRUVINE9Bc2FJdFJobHBqTTlCOXlpK2xMYUpLeUE0VFlNbktxU1RQRmxO?=
 =?utf-8?B?RmNjVTRNcG1Oa3NCZmtLMXJYbTFyQ0dPM3ptM3Q1RkNWcUJibjhjK1R4TVFE?=
 =?utf-8?B?WmxORTB1a1h0LzZLSmU4RzVUYmNsUThlM3AraUJ4cUVGbjRPekJIaFhNSEFF?=
 =?utf-8?B?eFA2TUV1N3BlL1NPTzJsNFNXckwrdEdUT2lHREdReks4T3phQXJpUFpRTmdC?=
 =?utf-8?B?UjV3REQveUJZODlYUzJGN0UyTDlyOUh6R3h3ZE5BUlY1UkxNSldsTE83VVM1?=
 =?utf-8?B?MkRlVk1ub1M0QlM1TE1TZGhxMHh2Ujl1MjZBQ01YUGl5SlBxYWl0OFdOYTJz?=
 =?utf-8?B?UXZ3a0FWa2JGNXF4NDh0Zy9RYmQrVHdTdENSRTNPWFIzT1ZPbzN1bCtvQ0kv?=
 =?utf-8?B?VnppVlpGTmJjcFdzRXBMWHhnWHRvQWQ5YVMvckNTc3FHWEc4dWpRc3JFQzZI?=
 =?utf-8?B?ZDJmeGZJUmFLWm9ReTlnMmg1NGF3d2F4VzRJeFMzWGVyd0U5aEQvbjBlRXBS?=
 =?utf-8?B?VTRwUFdldnVDcnRJU0NUcnNiRXAyUG80VDZFTUYrQ0t1T2NrSnhqUVVXTERR?=
 =?utf-8?B?dFI5a3VXV1dNWWJDSE40czJyRk5mTEprL3V5SzVnTm8rRjdhTGQxTFY5Rkow?=
 =?utf-8?B?L2d0ekQwNTc4a0NlNkJoRStqZ216VnY3K3Iyb3c0RHVqTG5lVFFRampnZE9i?=
 =?utf-8?B?ckdQeHBhamNaVGFiTllWN2RscVVCUjBpVTZyRnN0dCsyeFNTN3FHUXl0c1VV?=
 =?utf-8?B?ajlLczB6Z0Z4OWN1aGJ2UFEzTzFtNXBXa1JCZGo4N1BSd3dxVGkrTW1PL0o0?=
 =?utf-8?B?bHJ1cWVHd28yUXJaSHJtOWxYSW9id1hnYkRjMkNoSUFmdSs0WkdLd3JGQnpE?=
 =?utf-8?B?S29TN1MzQWNDZk4rZE5mc29MTE9WaFVxQlA1NlRTQjlDdXpYT2l4SHZKQys3?=
 =?utf-8?B?a0dueUNYRDZLSTFKU1EyZVhHTWE5ZXU0N3J6YjlweE1zeHh5WWlWMmptQnY1?=
 =?utf-8?B?RlFGbnZOSDljM0xrMmxCTzFGMlFrbDRnVG91QTFURTllY1FFSGxGaFMwb3Fp?=
 =?utf-8?B?L2duMGpUa1p5VWZBalM2Z2RDRmp2eFF0N3Noc25XcnkvWjZ4dDJ4U05Qakx1?=
 =?utf-8?B?eG9vbDE2OXl4TDV4S0xJM0VDbllhMCtxUFloZnY3dGlkcmQ1eDIyY1lHbk1H?=
 =?utf-8?B?c0hCeW9RTTdBL2RuRFVueEpFRnRMTjFRZE5Qd0doelFFbUo0cXhKZTNCNlBG?=
 =?utf-8?B?SFVOVjlrL0FHS1RCUWRjMGwva2ZaUzF4aklNOTEzTEdlZGE1SzNHVlMvRzRU?=
 =?utf-8?Q?vtJuDAAfLw2ORQZjxXJRIuvRUpbrG0VhRrvGEuz?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: cb59a264-b97d-41e3-3736-08d8d8259116
X-MS-Exchange-CrossTenant-AuthSource: DM6PR10MB3851.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 23 Feb 2021 18:05:13.6824
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: P3fTODYUWTFeKCIPr5bpKk0ymWCVRzCl4DR82Xo4UQRKUJfQm3EjDJcLBrjbn14KdE3GLK9UrWZQjC7ACUhxzfqyAJ82b6fqi1JBQ38f79w=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR10MB3595
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9904 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 suspectscore=0
 malwarescore=0 mlxlogscore=999 adultscore=0 bulkscore=0 mlxscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102230151
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9904 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 phishscore=0
 malwarescore=0 spamscore=0 mlxscore=0 suspectscore=0 priorityscore=1501
 clxscore=1015 impostorscore=0 lowpriorityscore=0 mlxlogscore=999
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102230152
X-Original-Sender: george.kennedy@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=oFxyAcOu;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=WST7pqIW;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates
 156.151.31.85 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
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



On 2/23/2021 10:47 AM, Mike Rapoport wrote:
> Hi George,
>
> On Tue, Feb 23, 2021 at 09:35:32AM -0500, George Kennedy wrote:
>> On 2/23/2021 5:33 AM, Mike Rapoport wrote:
>>> (re-added CC)
>>>
>>> On Mon, Feb 22, 2021 at 08:24:59PM -0500, George Kennedy wrote:
>>>> On 2/22/2021 4:55 PM, Mike Rapoport wrote:
>>>>> On Mon, Feb 22, 2021 at 01:42:56PM -0500, George Kennedy wrote:
>>>>>> On 2/22/2021 11:13 AM, David Hildenbrand wrote:
>>>>>>> On 22.02.21 16:13, George Kennedy wrote:
>>>>>>>
>>>>>>> The PFN 0xbe453 looks a little strange, though. Do we expect ACPI t=
ables
>>>>>>> close to 3 GiB ? No idea. Could it be that you are trying to map a =
wrong
>>>>>>> table? Just a guess.
>>>>>>>
>>>>>>>> What would be=C2=A0 the correct way to reserve the page so that th=
e above
>>>>>>>> would not be hit?
>>>>>>> I would have assumed that if this is a binary blob, that someone (w=
hich
>>>>>>> I think would be acpi code) reserved via memblock_reserve() early d=
uring
>>>>>>> boot.
>>>>>>>
>>>>>>> E.g., see drivers/acpi/tables.c:acpi_table_upgrade()->memblock_rese=
rve().
>>>>>> acpi_table_upgrade() gets called, but bails out before memblock_rese=
rve() is
>>>>>> called. Thus, it appears no pages are getting reserved.
>>>>> acpi_table_upgrade() does not actually reserve memory but rather open
>>>>> codes memblock allocation with memblock_find_in_range() +
>>>>> memblock_reserve(), so it does not seem related anyway.
>>>>>
>>>>> Do you have by chance a full boot log handy?
>>>> Hello Mike,
>>>>
>>>> Are you after the console output? See attached.
>>>>
>>>> It includes my patch to set PG_Reserved along with the dump_page() deb=
ug
>>>> that David asked for - see: "page:"
>>> So, iBFT is indeed at pfn 0xbe453:
>>>
>>> [    0.077698] ACPI: iBFT 0x00000000BE453000 000800 (v01 BOCHS  BXPCFAC=
P 00000000      00000000)
>>> and it's in E820_TYPE_RAM region rather than in ACPI data:
>>>
>>> [    0.000000] BIOS-e820: [mem 0x0000000000810000-0x00000000008fffff] A=
CPI NVS
>>> [    0.000000] BIOS-e820: [mem 0x0000000000900000-0x00000000be49afff] u=
sable
>>> [    0.000000] BIOS-e820: [mem 0x00000000be49b000-0x00000000be49bfff] A=
CPI data
>>>
>>> I could not find anywhere in x86 setup or in ACPI tables parsing the co=
de
>>> that reserves this memory or any other ACPI data for that matter. It co=
uld
>>> be that I've missed some copying of the data to statically allocated
>>> initial_tables, but AFAICS any ACPI data that was not marked as such in
>>> e820 tables by BIOS resides in memory that is considered as free.
>>>
>> Close...
>>
>> Applied the patch, see "[=C2=A0=C2=A0 30.136157] iBFT detected.", but no=
w hit the
>> following (missing iounmap()? see full console output attached):
>>
>> diff --git a/drivers/firmware/iscsi_ibft_find.c
>> b/drivers/firmware/iscsi_ibft_find.c
>> index 64bb945..2e5e040 100644
>> --- a/drivers/firmware/iscsi_ibft_find.c
>> +++ b/drivers/firmware/iscsi_ibft_find.c
>> @@ -80,6 +80,21 @@ static int __init find_ibft_in_mem(void)
>>  =C2=A0done:
>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return len;
>>  =C2=A0}
>> +
>> +static void __init acpi_find_ibft_region(void)
>> +{
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int i;
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct acpi_table_header *table =
=3D NULL;
>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (acpi_disabled)
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 return;
>> +
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < ARRAY_SIZE(ibft_=
signs) && !ibft_addr; i++) {
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 acpi_get_table(ibft_signs[i].sign, 0, &table);
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 ibft_addr =3D (struct acpi_table_ibft *)table;
> Can you try adding
>
> 	acpi_put_table(table);
>
> here?
Mike,

It now crashes here:

[=C2=A0=C2=A0=C2=A0 0.051019] ACPI: Early table checksum verification disab=
led
[=C2=A0=C2=A0=C2=A0 0.056721] ACPI: RSDP 0x00000000BFBFA014 000024 (v02 BOC=
HS )
[=C2=A0=C2=A0=C2=A0 0.057874] ACPI: XSDT 0x00000000BFBF90E8 00004C (v01 BOC=
HS BXPCFACP=20
00000001=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
[=C2=A0=C2=A0=C2=A0 0.059590] ACPI: FACP 0x00000000BFBF5000 000074 (v01 BOC=
HS BXPCFACP=20
00000001 BXPC 00000001)
[=C2=A0=C2=A0=C2=A0 0.061306] ACPI: DSDT 0x00000000BFBF6000 00238D (v01 BOC=
HS BXPCDSDT=20
00000001 BXPC 00000001)
[=C2=A0=C2=A0=C2=A0 0.063006] ACPI: FACS 0x00000000BFBFD000 000040
[=C2=A0=C2=A0=C2=A0 0.063938] ACPI: APIC 0x00000000BFBF4000 000090 (v01 BOC=
HS BXPCAPIC=20
00000001 BXPC 00000001)
[=C2=A0=C2=A0=C2=A0 0.065638] ACPI: HPET 0x00000000BFBF3000 000038 (v01 BOC=
HS BXPCHPET=20
00000001 BXPC 00000001)
[=C2=A0=C2=A0=C2=A0 0.067335] ACPI: BGRT 0x00000000BE49B000 000038 (v01 INT=
EL EDK2=C2=A0=C2=A0=C2=A0=C2=A0=20
00000002=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
[=C2=A0=C2=A0=C2=A0 0.069030] ACPI: iBFT 0x00000000BE453000 000800 (v01 BOC=
HS BXPCFACP=20
00000000=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 00000000)
[=C2=A0=C2=A0=C2=A0 0.070734] XXX acpi_find_ibft_region:
[=C2=A0=C2=A0=C2=A0 0.071468] XXX iBFT, status=3D0
[=C2=A0=C2=A0=C2=A0 0.072073] XXX about to call acpi_put_table()...=20
ibft_addr=3Dffffffffff240000
[=C2=A0=C2=A0=C2=A0 0.073449] XXX acpi_find_ibft_region(EXIT):
PANIC: early exception 0x0e IP 10:ffffffff9259f439 error 0 cr2=20
0xffffffffff240004
[=C2=A0=C2=A0=C2=A0 0.075711] CPU: 0 PID: 0 Comm: swapper Not tainted 5.11.=
0-34a2105 #8
[=C2=A0=C2=A0=C2=A0 0.076983] Hardware name: QEMU Standard PC (i440FX + PII=
X, 1996),=20
BIOS 0.0.0 02/06/2015
[=C2=A0=C2=A0=C2=A0 0.078579] RIP: 0010:find_ibft_region+0x470/0x577
[=C2=A0=C2=A0=C2=A0 0.079541] Code: f1 40 0f 9e c6 84 c9 0f 95 c1 40 84 ce =
75 11 83 e0=20
07 38 c2 0f 9e c1 84 d2 0f 95 c0 84 c1 74 0a be 04 00 00 00 e8 37 f8 5f=20
ef <8b> 5b 04 4c 89 fa b8 ff ff 37 00 48 c1 ea 03 48 c1 e0 2a 81 c3 ff
[=C2=A0=C2=A0=C2=A0 0.083207] RSP: 0000:ffffffff8fe07ca8 EFLAGS: 00010046 O=
RIG_RAX:=20
0000000000000000
[=C2=A0=C2=A0=C2=A0 0.084709] RAX: 0000000000000000 RBX: ffffffffff240000 R=
CX:=20
ffffffff815fcf01
[=C2=A0=C2=A0=C2=A0 0.086109] RDX: dffffc0000000000 RSI: 0000000000000001 R=
DI:=20
ffffffffff240004
[=C2=A0=C2=A0=C2=A0 0.087509] RBP: ffffffff8fe07d60 R08: fffffbfff1fc0f21 R=
09:=20
fffffbfff1fc0f21
[=C2=A0=C2=A0=C2=A0 0.088911] R10: ffffffff8fe07907 R11: fffffbfff1fc0f20 R=
12:=20
ffffffff8fe07d38
[=C2=A0=C2=A0=C2=A0 0.090310] R13: 0000000000000001 R14: 0000000000000001 R=
15:=20
ffffffff8fe07e80
[=C2=A0=C2=A0=C2=A0 0.091716] FS:=C2=A0 0000000000000000(0000) GS:ffffffff9=
2409000(0000)=20
knlGS:0000000000000000
[=C2=A0=C2=A0=C2=A0 0.093304] CS:=C2=A0 0010 DS: 0000 ES: 0000 CR0: 0000000=
080050033
[=C2=A0=C2=A0=C2=A0 0.094435] CR2: ffffffffff240004 CR3: 0000000027630000 C=
R4:=20
00000000000006a0
[=C2=A0=C2=A0=C2=A0 0.095843] Call Trace:
[=C2=A0=C2=A0=C2=A0 0.096345]=C2=A0 ? acpi_table_init+0x3eb/0x428
[=C2=A0=C2=A0=C2=A0 0.097164]=C2=A0 ? dmi_id_init+0x871/0x871
[=C2=A0=C2=A0=C2=A0 0.097912]=C2=A0 ? early_memunmap+0x22/0x27
[=C2=A0=C2=A0=C2=A0 0.098683]=C2=A0 ? smp_scan_config+0x20e/0x230
[=C2=A0=C2=A0=C2=A0 0.099500]=C2=A0 setup_arch+0xd3e/0x181d
[=C2=A0=C2=A0=C2=A0 0.100221]=C2=A0 ? reserve_standard_io_resources+0x3e/0x=
3e
[=C2=A0=C2=A0=C2=A0 0.101265]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
[=C2=A0=C2=A0=C2=A0 0.102203]=C2=A0 ? vprintk_func+0xe9/0x200
[=C2=A0=C2=A0=C2=A0 0.102953]=C2=A0 ? printk+0xac/0xd4
[=C2=A0=C2=A0=C2=A0 0.103589]=C2=A0 ? record_print_text.cold.38+0x16/0x16
[=C2=A0=C2=A0=C2=A0 0.104540]=C2=A0 ? write_comp_data+0x2f/0x90
[=C2=A0=C2=A0=C2=A0 0.105325]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
[=C2=A0=C2=A0=C2=A0 0.106262]=C2=A0 start_kernel+0x6c/0x474
[=C2=A0=C2=A0=C2=A0 0.106981]=C2=A0 x86_64_start_reservations+0x37/0x39
[=C2=A0=C2=A0=C2=A0 0.107902]=C2=A0 x86_64_start_kernel+0x7b/0x7e
[=C2=A0=C2=A0=C2=A0 0.108722]=C2=A0 secondary_startup_64_no_verify+0xb0/0xb=
b


Added debug to dump out the ibft_addr:

[root@gkennedy-20210107-1202 linux-upwork]# git diff
diff --git a/drivers/firmware/iscsi_ibft_find.c=20
b/drivers/firmware/iscsi_ibft_find.c
index 2e5e040..a246373 100644
--- a/drivers/firmware/iscsi_ibft_find.c
+++ b/drivers/firmware/iscsi_ibft_find.c
@@ -83,16 +83,22 @@ static int __init find_ibft_in_mem(void)

 =C2=A0static void __init acpi_find_ibft_region(void)
 =C2=A0{
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int i;
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int i, status;
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct acpi_table_header *table=
 =3D NULL;
-
+printk(KERN_ERR "XXX acpi_find_ibft_region:\n");
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (acpi_disabled)
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 return;

 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < ARRAY_SIZE(ib=
ft_signs) && !ibft_addr; i++) {
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 acpi_get_table(ibft_signs[i].sign, 0, &table);
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 ibft_addr =3D (struct acpi_table_ibft *)table;
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 status =3D acpi_get_table(ibft_signs[i].sign, 0, &table);
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 printk(KERN_ERR "XXX %s, status=3D%x\n",=20
ibft_signs[i].sign, status);
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 if (ACPI_SUCCESS(status)) {
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ibft_addr =3D =
(struct acpi_table_ibft *)table;
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 printk(KERN_ER=
R "XXX about to call=20
acpi_put_table()... ibft_addr=3D%llx\n", (u64)ibft_addr);
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 acpi_put_table=
(table);
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 }
 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
+printk(KERN_ERR "XXX acpi_find_ibft_region(EXIT):\n");
 =C2=A0}

 =C2=A0/*
(END)

George
>
>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>> +}
>> +

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/3a56ba38-ce91-63a6-b57c-f1726aa1b76e%40oracle.com.
