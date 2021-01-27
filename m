Return-Path: <kasan-dev+bncBCX7RK77SEDBBIENY6AAMGQE3JO2IZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2736C3064A4
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 21:01:40 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id v1sf2191267qvb.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 12:01:40 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1611777696; cv=pass;
        d=google.com; s=arc-20160816;
        b=UFsZUhwh49aNdfCO8ojniJmdT+zMZYQBmmv6qtH7NYmW3qOOGV+8vW2hJ1l8A60Phf
         wa9OBmisQR+CbpivSbo9aXxuPLzK9Gifivs4TfCwt99EuZn55zMA4l0MPxLysHO9c1OV
         hxXirHkdGCqOtZwxHRZqO/ZGBQJCIPsrjSylrF7ZlEsDLDc3OIu3Zu5WGpUIA6wgU9nH
         shkAIjA4jXKd5oj/8HTvqXwA1fUbWM7G84frZOduIf34pJk+cYcUFm23rQcmtF40yFOV
         Qr4MqoaSBsf/hXnfV4+XtJ1m9ISXnYXFnIIFwVYWJxUmu7fuaZuVsPX+H2R0Cp8FNo57
         Tn6A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :in-reply-to:user-agent:date:message-id:organization:from:references
         :cc:to:subject:sender:dkim-signature;
        bh=aKZ3oosCun8BSuKpCnK6BXMEAp1HOZv7f6K9DxEgHjo=;
        b=qfcZ7TVC/ut9CjGq7Gz/FBuWC+u16A8+xUtAmbmiE92431jzPxCuyO4cnQ34WAmMda
         cq2pn7rvdbod3xd3FBUdR3y88vgPsqwAl45OfE7upagqdi8s94URdS1ZXkCdUWXAApsX
         qswYcPcsMlsOF/vpOaYWer4uq99YWVLJ6RmcgDIa39+Bwy9jdjMM4ekHqVuZeuiF7ntw
         98D0nT1AxWCfRDq2W7K9BfxkbmX4cr79d3bu4t7X0Crqz3BdvfNUFMeAUwk4/0IDyyTU
         7iGxcJuBOS5xvMNl4oFz9g1k1HwCSMRxycafk+Ra2qXtTRjkb2QLqc5BNPQrNBxT7TDz
         iyOw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=dZpt7M9l;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=emkDelFy;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:in-reply-to:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aKZ3oosCun8BSuKpCnK6BXMEAp1HOZv7f6K9DxEgHjo=;
        b=MESMUeSv4aC1iqmP6eL3KMXqohjEpu2lIaZZaDX+L86VA/mrALCcpHi2qJkKT69whu
         QALhGmNE6dEy2arTNakvOcrAElTVjWEGg4HU1DjtNA4w7o4aNIuBkILkhcDv+R7uon9J
         kwHHecek991n4R5cC2hv7zUg/QVUXe0M9wOsh5eUtEjeTihgOh/1okkbOH8XoEf8SAm/
         HH7m2CeewCMSKVQsg+gI1LXWjsqaIMUZbdKwbgKxmoMnbcHa2+fK/2HtEuxfFFV30DmO
         IM7BmKhEnksUPwoWWjrVpriL6YJsGNz0YGYK8E0vKtZq7XSpk4mZgNP3FMdhPGVFPlit
         uUDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:in-reply-to
         :content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aKZ3oosCun8BSuKpCnK6BXMEAp1HOZv7f6K9DxEgHjo=;
        b=m5O5kH3jfr39oVrFBADnuEa7nrHI3d2FMwjfjQhO2d9N+QtXOrJFtHyi58VQrvHQlF
         RzTi0o/KGJ+s54HaopFM3QFGNxcrQC3lhpq7aha52k3JMTRFJ2ZRqIlS4iaD4T3PfVBi
         4+rXGtmts0aQvS222YSUauJ6NG+WEhBZmjKWuDNgN1XfrkwnR38omMAWA68GCn+ptXj0
         fc1GV5GEzLAXZyAgF3JSGpok/pM9t4meVkMJNsiv05SSn8iLx/t/yHbB4cQoS7Bx0iUE
         Rm7cQZKyU3v0DSlQSvYIJxOASX52M1jHR0x4YsvHUlbZNvDrziZaoeE6urfX4UuiBB/Q
         qCKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530MTJVBVnFbd9VA46BpzTzvwEvyygJTr+TpZmZsD/tRG6DXPLK0
	HELTuxLfuUjjgc40UVZvnTY=
X-Google-Smtp-Source: ABdhPJx0MGn4wiEbuHgFMrBC2F40DYKyqns5ITWs/p9qJUkpn5Dzt3XI/ROmeZQaFLNJbXhs4wOQiw==
X-Received: by 2002:ac8:a0e:: with SMTP id b14mr11373119qti.84.1611777696684;
        Wed, 27 Jan 2021 12:01:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:c001:: with SMTP id u1ls1615292qkk.1.gmail; Wed, 27 Jan
 2021 12:01:36 -0800 (PST)
X-Received: by 2002:a05:620a:209c:: with SMTP id e28mr3937425qka.188.1611777695667;
        Wed, 27 Jan 2021 12:01:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611777695; cv=pass;
        d=google.com; s=arc-20160816;
        b=dFZTNhzX4cDNfsEXvaJRcmuWHeDcVEjb62X3dqpUGeK6MzkNTTb/YRPMvt/KdKGWY+
         /taHyzey2OpXAoy6862L1HtauULtWEqDr8RuLrtSBVdc7Ngu97grcwRcFTHowxQ5EX9A
         Zu1BABlc/G3bz7jl9tQ2HYQJVsYedDK6EAWXwJair+SmfZmtwZ9LXvMWGxQn6mykxaZU
         5CkC4ltqP2ISObt1uNBUFubruUX36hTRt/XbnbCagSnU5KJSERdkwghgwQcal97ikx6e
         bJfUIamcv6hpxTjRtnyGP9XzgiucPgt5iJ4GriWbj5ybaBPYlQWig0RbKvJ8tcCXegep
         tmIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:in-reply-to:user-agent:date
         :message-id:organization:from:references:cc:to:subject
         :dkim-signature:dkim-signature;
        bh=WUDQnGcxmZTwS/XgNtXHzTspYjekv/e6KgC+UgsYtQs=;
        b=L9v/5FyU7SEhUgOxY/9RpX5LSPViL8dVs2RB+c1ABEN+yawoAkXG2TjU3TPg6nV2KQ
         lHxYfZt49QpAuayZFPLpiUaf373j6k6in51qmFcsR1NJ4CBURxda/C1IWtdmY8+813wm
         7C5Fb+lVr2aOn0bNFM2YL1syetrgHuPCxnOHeGyaKIOUe9MG2Bkb0TtM0s/jL8pZLvok
         RNQokIOCfmQsmhcNRwBuzp/53luiTjGAHUj5xWGzIQNvDXPTHbwv13ZBC34TpI2HnrAN
         o1hYxJKPBwqA+GBu/mCAcG5V2PubRgJH2/RpDWk9fzJAAPO2Mpjvtu11Qt2aQ1xulELO
         Wo7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=dZpt7M9l;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=emkDelFy;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from aserp2120.oracle.com (aserp2120.oracle.com. [141.146.126.78])
        by gmr-mx.google.com with ESMTPS id j40si279611qtk.2.2021.01.27.12.01.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Jan 2021 12:01:35 -0800 (PST)
Received-SPF: pass (google.com: domain of george.kennedy@oracle.com designates 141.146.126.78 as permitted sender) client-ip=141.146.126.78;
Received: from pps.filterd (aserp2120.oracle.com [127.0.0.1])
	by aserp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 10RJsbMp008569;
	Wed, 27 Jan 2021 20:01:32 GMT
Received: from aserp3020.oracle.com (aserp3020.oracle.com [141.146.126.70])
	by aserp2120.oracle.com with ESMTP id 368brkrxn6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 27 Jan 2021 20:01:32 +0000
Received: from pps.filterd (aserp3020.oracle.com [127.0.0.1])
	by aserp3020.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 10RK0c6d125666;
	Wed, 27 Jan 2021 20:01:32 GMT
Received: from nam12-bn8-obe.outbound.protection.outlook.com (mail-bn8nam12lp2170.outbound.protection.outlook.com [104.47.55.170])
	by aserp3020.oracle.com with ESMTP id 368wq0pqqa-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 27 Jan 2021 20:01:31 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=XE+18DRXfUbXfXyey7FhBa8iuscYJavJCLwozKn6hsEsjWH6gFgZbgzW2KO4t9NGbs7VP9T8yi+AAinpfEEIm6vmIwxpi2b3HWSOIQetwZjWplmLYCKZGvLPUDi0nIdcfDbLZVfMT0k0XDCEcW0pvE4BM8qE4QG5WHWwhxqUvfTaglnIPlyC3bi2mStEXT41/kWyrEE8tOwjTaNvktCmNXtYP0ik4lIfzrnIJTbpI/6neFPpS5ZROLOFuLlvR82lcVR8sskfufr+dMFiCZFbxlTWZKfFmSu4q2WHRLoDF4gAgIXowmgUp8qV6cdlDKbYVWAvnQ7KPVeWZe4d/Lg+QA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=WUDQnGcxmZTwS/XgNtXHzTspYjekv/e6KgC+UgsYtQs=;
 b=idPIeEqAh9NEiqaMqgdDUVAT1kVhvn/LgcF941GyOyW00mAIDaKhRXEsQcYV1rL5QPT/R4rPqyWIlb/SJLJH2af4SU7cbr/whtoRpAr7fQo9e7hYtslJ9ilCLHY5AueE/lamg2diwd3zVgx7Gwdp342QbetWd+pSFW1Z9Q3Uml/KgGF84937jm0lL3+MjSz1aXRtJJrDGpsbkYu+kiwejHVXd2iFDN8kgWATUl3U0Prpf+vx3QX5IhoJ+VXJP0w/z+M63sjTCwBXwGFK6aRV37PmWKipMZEoMTxF3SwNFRszD/+JDFtb1m3ICLkPFA1bQs/MurG3swMFgIvEjM5FOQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM6PR10MB3851.namprd10.prod.outlook.com (2603:10b6:5:1fb::17)
 by DM6PR10MB4250.namprd10.prod.outlook.com (2603:10b6:5:212::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3805.16; Wed, 27 Jan
 2021 20:01:29 +0000
Received: from DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::4d1e:6f06:cff0:364f]) by DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::4d1e:6f06:cff0:364f%6]) with mapi id 15.20.3784.019; Wed, 27 Jan 2021
 20:01:29 +0000
Subject: Re: [PATCH 1/1] iscsi_ibft: KASAN false positive failure occurs in
 ibft_init()
To: Dmitry Vyukov <dvyukov@google.com>,
        Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>, pjones@redhat.com,
        konrad@kernel.org, LKML <linux-kernel@vger.kernel.org>
References: <1611684201-16262-1-git-send-email-george.kennedy@oracle.com>
 <YBG0glwiK1wyJTeN@Konrads-MacBook-Pro.local>
 <CACT4Y+a48smtXc6qJy9Wthwuqjk2gh6o7BK1tfWW46g7D_r-Lg@mail.gmail.com>
From: George Kennedy <george.kennedy@oracle.com>
Organization: Oracle Corporation
Message-ID: <cc712c9c-7786-bb26-7082-04e564df98aa@oracle.com>
Date: Wed, 27 Jan 2021 15:01:27 -0500
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.6.1
In-Reply-To: <CACT4Y+a48smtXc6qJy9Wthwuqjk2gh6o7BK1tfWW46g7D_r-Lg@mail.gmail.com>
Content-Type: multipart/alternative;
 boundary="------------5A39CAAFC3726DB12D456DCE"
Content-Language: en-US
X-Originating-IP: [108.20.187.119]
X-ClientProxiedBy: CH2PR05CA0004.namprd05.prod.outlook.com (2603:10b6:610::17)
 To DM6PR10MB3851.namprd10.prod.outlook.com (2603:10b6:5:1fb::17)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from [192.168.1.246] (108.20.187.119) by CH2PR05CA0004.namprd05.prod.outlook.com (2603:10b6:610::17) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3805.6 via Frontend Transport; Wed, 27 Jan 2021 20:01:28 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 08b048d5-9542-4861-6189-08d8c2fe5605
X-MS-TrafficTypeDiagnostic: DM6PR10MB4250:
X-MS-Exchange-Transport-Forked: True
X-Microsoft-Antispam-PRVS: <DM6PR10MB4250E866BAF82D2AAC36CC44E6BB9@DM6PR10MB4250.namprd10.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:10000;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: s6HgyC1Dnd8NeZpkg7iJg4ODI+4Woihw7I5+oR3rYdG+xjNNlqXPq3Msnb3N5CZf2Dn/gzSzmKJVQOMVdRYT3LRQRF1zDQpmaOqjzwPq6blEfuRhWqAjwsmFGCT+RKK2DtbWBySF/ZMc6oZkS37oUtkPF8Rkd5vxtLU+vXO7babhOd+ChZMMMh028Pne0oueCiRkysCZLPm/aiDFuucsAV6R1co3fz5b+ueeA+9p3sTdbLtB48FUThmP/L++WLLJs4cDJZNkBzogQx88qoFIEuN3uq9hqqVrwTMZGVu1RRqss++79SyWLR6qwzQ2ztuAQw0DX8Xlwr2JVS+G0Gm6Xt5kkLmuiOb6zGtWG2K5iTGStsSaHGtwR2+yJs2VsJY6FoCXuKw7fW8Q1GXmNCPw0u9ZD/SQZJqGSKBdH8IdnHLYzm5QNNp1ifi5dNujYi3H+Cf6Ox32rQy0EjVwOWF4JQa4hFkhJ8GPDm5EyWwxb/zs9H6XJueHM7sz8qwi0/1BS8iwedw2gl+SL5rUS6ycJfPvr/4zAIuaJFcKM/0/vOG1QDQJaNZzrKFAVcmksYsMQhqZy2tg7hSvzVugCUw5K4tvGfZX8/l7xc5/KF8L7vo=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR10MB3851.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(346002)(136003)(376002)(396003)(366004)(39860400002)(44832011)(8936002)(26005)(66476007)(2616005)(36916002)(186003)(8676002)(316002)(956004)(478600001)(53546011)(6636002)(2906002)(30864003)(66946007)(5660300002)(66556008)(6486002)(4326008)(36756003)(16526019)(110136005)(31696002)(31686004)(83380400001)(54906003)(86362001)(16576012)(33964004)(45980500001)(43740500002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?utf-8?B?aW5LaExTbHAyakQ2SVZLUXp5L0pHd3VnVGxOYXJHRGtVZDQ2bEEvS1IwR3Fw?=
 =?utf-8?B?RkRzR3I4Q1BaQVpGeTVBZ3JCTjlnSHU5bDJpSWNUVGQyT3BVVHVHdmhPZENm?=
 =?utf-8?B?NXlFbU9vM3dxcmVESFRNc29ZVEtmb2xDbWhESEVLdG5uZUptZ3pQWVZEakcr?=
 =?utf-8?B?bGg5QXRNb2RCcFh1OFVyT2g5dC85bW1uV1JaV3poU25kWjdCWDhkOVliMUg1?=
 =?utf-8?B?emdOUlRVMzVXRUsxdlhoeGFmQm1xbVdHQ1Njb3QwbnJHVGo4R1pBTUpidy9k?=
 =?utf-8?B?NnFQcFVpQUN6VFFhaldML0hIbHNXRXVIbnoyanR3ckJhb3ppM2RscHVMRW83?=
 =?utf-8?B?R0xwTXJqUGN6Zkl0MVdwR0ZrRUVmTW00QktoMHhwNCtVb1Y4YnQrNkVJZVUx?=
 =?utf-8?B?ZFpOUkF4Z092RDRkTG9rL0duRzAwc1hQVHhMRlVpTWZxNnd4SFdQczV4enY5?=
 =?utf-8?B?N2hIY25zRG01SmFVUVFwOGFPUTlXelczdjlBeklQbFdHb3YxSW5iK2xQd1Q3?=
 =?utf-8?B?YVp6TGhxUCtJNk94N3dvMjhmeGZZbnRBcG5kZklGai9jWE1ETjhpU2MwNmVt?=
 =?utf-8?B?RkpMR20yUHJpeVRVZ0xLZGpBR1ZPV2l0UVRIbTVIcTVITnpzTnVXcHl3bXVl?=
 =?utf-8?B?b2JQUVJBY3FIbzMvek9IaDhqMEEzTEFSMnVNNVNsSkNUMCtwbzY3VGpQMFNN?=
 =?utf-8?B?cWtuN3ZsREJ0RWtrZVAxcHdXT2FwQjBGVm0rMUNOOTNtd1FQMUNSbTJieUt0?=
 =?utf-8?B?dDZKei9TTElsQUZEdjJLU0EvMlJ4YUtzZ2FZLzFKZThvTXd2TkxNYWVmcktL?=
 =?utf-8?B?bnVtcWdTcndpWHBlNTJFemRyTTd5VEJ5cVBqOWl3YURldVdlUDdSRkp3MDZS?=
 =?utf-8?B?UHdCSFBPck1May9PRkwvV2tuUzBqekhUeHZxam9LVVlBY2dUdVpqRjQ0L0gw?=
 =?utf-8?B?dFA5djg2ck10ZEpSbUdGNWxoOXpqQ1hvU0JGWkhxd2tSZU5ta1QzV0JwUlQ1?=
 =?utf-8?B?RmQ3MHVCUUdIbit3MnpWUllpZGlLQVEzNXdRRWYvdVhIdjI3SFpGTnN1aUd6?=
 =?utf-8?B?Y3drSXc4bStQSkRRWEZobURxa21CK3g3cFVyamc2TWl0SE5JVmYzbnNyNjZJ?=
 =?utf-8?B?dVpNL2VjWFJ0dFpaL1pCZktEcGVxU3RhcEh2cGU3TjBjektnMXYrUmUwYzBx?=
 =?utf-8?B?WWk4dklkc0ZCNUdMa3hGV3NaVjgybFpCNFRQazlXWHFBK1ZxQ3V4bkQxYkYx?=
 =?utf-8?B?QThNS250YnNUZ1VEMTdoL3pqTG9PSllUZEpZd21LdHBOMytrZjV0S2pqcjFF?=
 =?utf-8?B?ajY2eVRxY2RHejE5L25meFRDZysva3hHK1lNWEN1OFVHUHpzUFRYTytoMXhH?=
 =?utf-8?B?U3A2RjduTm5qa2xrWnVQek5NcTQ4SEVJRjI2SjJ0N05FREp1SEtUMVdJdUVM?=
 =?utf-8?Q?YtDOmwPB?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 08b048d5-9542-4861-6189-08d8c2fe5605
X-MS-Exchange-CrossTenant-AuthSource: DM6PR10MB3851.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Jan 2021 20:01:29.6878
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: EWH1LPgbNDtGJZXkATDj4kmQzlYgTUjfrhiHF+nUxWEFtyfnEXIo2zvAFaowe3oKDxhvYQbY7WmPJjqKm6c0KGbZpMKLkd/ht8iONWSCrOg=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR10MB4250
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9877 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 mlxscore=0 spamscore=0
 adultscore=0 bulkscore=0 phishscore=0 suspectscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2101270100
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9877 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 impostorscore=0
 phishscore=0 bulkscore=0 priorityscore=1501 mlxlogscore=999
 lowpriorityscore=0 spamscore=0 mlxscore=0 suspectscore=0 malwarescore=0
 clxscore=1011 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2101270099
X-Original-Sender: george.kennedy@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=dZpt7M9l;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=emkDelFy;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

--------------5A39CAAFC3726DB12D456DCE
Content-Type: text/plain; charset="UTF-8"; format=flowed

Hi Dmitry,

On 1/27/2021 1:48 PM, Dmitry Vyukov wrote:
> On Wed, Jan 27, 2021 at 7:44 PM Konrad Rzeszutek Wilk
> <konrad.wilk@oracle.com> wrote:
>> On Tue, Jan 26, 2021 at 01:03:21PM -0500, George Kennedy wrote:
>>> During boot of kernel with CONFIG_KASAN the following KASAN false
>>> positive failure will occur when ibft_init() reads the
>>> ACPI iBFT table: BUG: KASAN: use-after-free in ibft_init
>>>
>>> The ACPI iBFT table is not allocated, and the iscsi driver uses
>>> a pointer to it to calculate checksum, etc. KASAN complains
>>> about this pointer with use-after-free, which this is not.
>>>
>> Andrey, Alexander, Dmitry,
>>
>> I think this is the right way for this, but was wondering if you have
>> other suggestions?
>>
>> Thanks!
> Hi George, Konrad,
>
> Please provide a sample KASAN report and kernel version to match line numbers.

5.4.17-2102.200.0.0.20210106_0000

[   24.413536] iBFT detected.
[   24.414074]
==================================================================
[   24.407342] BUG: KASAN: use-after-free in ibft_init+0x134/0xb8b
[   24.407342] Read of size 4 at addr ffff8880be452004 by task swapper/0/1
[   24.407342]
[   24.407342] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5.4.17-2102.200.0.0.20210106_0000.syzk #1
[   24.407342] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 0.0.0 02/06/2015
[   24.407342] Call Trace:
[   24.407342]  dump_stack+0xd4/0x119
[   24.407342]  ? ibft_init+0x134/0xb8b
[   24.407342]  print_address_description.constprop.6+0x20/0x220
[   24.407342]  ? ibft_init+0x134/0xb8b
[   24.407342]  ? ibft_init+0x134/0xb8b
[   24.407342]  __kasan_report.cold.9+0x37/0x77
[   24.407342]  ? ibft_init+0x134/0xb8b
[   24.407342]  kasan_report+0x14/0x1b
[   24.407342]  __asan_report_load_n_noabort+0xf/0x11
[   24.407342]  ibft_init+0x134/0xb8b
[   24.407342]  ? dmi_sysfs_init+0x1a5/0x1a5
[   24.407342]  ? dmi_walk+0x72/0x89
[   24.407342]  ? ibft_check_initiator_for+0x159/0x159
[   24.407342]  ? rvt_init_port+0x110/0x101
[   24.407342]  ? ibft_check_initiator_for+0x159/0x159
[   24.407342]  do_one_initcall+0xc3/0x44d
[   24.407342]  ? perf_trace_initcall_level+0x410/0x405
[   24.407342]  kernel_init_freeable+0x551/0x673
[   24.407342]  ? start_kernel+0x94b/0x94b
[   24.407342]  ? __sanitizer_cov_trace_const_cmp1+0x1a/0x1c
[   24.407342]  ? __kasan_check_write+0x14/0x16
[   24.407342]  ? rest_init+0xe6/0xe6
[   24.407342]  kernel_init+0x16/0x1bd
[   24.407342]  ? rest_init+0xe6/0xe6
[   24.407342]  ret_from_fork+0x2b/0x36
[   24.407342]
[   24.407342] The buggy address belongs to the page:
[   24.407342] page:ffffea0002f91480 refcount:0 mapcount:0 mapping:0000000000000000 index:0x1
[   24.407342] flags: 0xfffffc0000000()
[   24.407342] raw: 000fffffc0000000 ffffea0002fca588 ffffea0002fb1a88 0000000000000000
[   24.407342] raw: 0000000000000001 0000000000000000 00000000ffffffff 0000000000000000
[   24.407342] page dumped because: kasan: bad access detected
[   24.407342]
[   24.407342] Memory state around the buggy address:
[   24.407342]  ffff8880be451f00: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
[   24.407342]  ffff8880be451f80: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
[   24.407342] >ffff8880be452000: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
[   24.407342]                    ^
[   24.407342]  ffff8880be452080: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
[   24.407342]  ffff8880be452100: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
[   24.407342]
==================================================================
[   24.407342] Disabling lock debugging due to kernel taint
[   24.451021] Kernel panic - not syncing: panic_on_warn set ...
[   24.452002] CPU: 1 PID: 1 Comm: swapper/0 Tainted: G    B 5.4.17-2102.200.0.0.20210106_0000.syzk #1
[   24.452002] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 0.0.0 02/06/2015
[   24.452002] Call Trace:
[   24.452002]  dump_stack+0xd4/0x119
[   24.452002]  ? ibft_init+0x102/0xb8b
[   24.452002]  panic+0x28f/0x6e0
[   24.452002]  ? __warn_printk+0xe0/0xe0
[   24.452002]  ? ibft_init+0x134/0xb8b
[   24.452002]  ? add_taint+0x68/0xb3
[   24.452002]  ? add_taint+0x68/0xb3
[   24.452002]  ? ibft_init+0x134/0xb8b
[   24.452002]  ? ibft_init+0x134/0xb8b
[   24.452002]  end_report+0x4c/0x54
[   24.452002]  __kasan_report.cold.9+0x55/0x77
[   24.452002]  ? ibft_init+0x134/0xb8b
[   24.452002]  kasan_report+0x14/0x1b
[   24.452002]  __asan_report_load_n_noabort+0xf/0x11
[   24.452002]  ibft_init+0x134/0xb8b
[   24.452002]  ? dmi_sysfs_init+0x1a5/0x1a5
[   24.452002]  ? dmi_walk+0x72/0x89
[   24.452002]  ? ibft_check_initiator_for+0x159/0x159
[   24.452002]  ? rvt_init_port+0x110/0x101
[   24.452002]  ? ibft_check_initiator_for+0x159/0x159
[   24.452002]  do_one_initcall+0xc3/0x44d
[   24.452002]  ? perf_trace_initcall_level+0x410/0x405
[   24.452002]  kernel_init_freeable+0x551/0x673
[   24.452002]  ? start_kernel+0x94b/0x94b
[   24.452002]  ? __sanitizer_cov_trace_const_cmp1+0x1a/0x1c
[   24.452002]  ? __kasan_check_write+0x14/0x16
[   24.452002]  ? rest_init+0xe6/0xe6
[   24.452002]  kernel_init+0x16/0x1bd
[   24.452002]  ? rest_init+0xe6/0xe6
[   24.452002]  ret_from_fork+0x2b/0x36
[   24.452002] Dumping ftrace buffer:
[   24.452002] ---------------------------------
[   24.452002] swapper/-1         1.... 24564337us : rdmaip_init: 2924: rdmaip_init: Active Bonding is DISABLED
[   24.452002] ---------------------------------
[   24.452002] Kernel Offset: disabled
[   24.452002] Rebooting in 1 seconds..

//
> Why does KASAN think the address is freed? For that to happen that
> memory should have been freed. I don't remember any similar false
> positives from KASAN, so this looks a bit suspicious.

I'm not sure why KASAN thinks the address is freed. There are other 
modules where KASAN/KCOV is disabled on boot.
Could this be for a similar reason?

Thank you,
George
>
>
>>> Signed-off-by: George Kennedy <george.kennedy@oracle.com>
>>> ---
>>>   drivers/firmware/Makefile | 3 +++
>>>   1 file changed, 3 insertions(+)
>>>
>>> diff --git a/drivers/firmware/Makefile b/drivers/firmware/Makefile
>>> index 5e013b6..30ddab5 100644
>>> --- a/drivers/firmware/Makefile
>>> +++ b/drivers/firmware/Makefile
>>> @@ -14,6 +14,9 @@ obj-$(CONFIG_INTEL_STRATIX10_SERVICE) += stratix10-svc.o
>>>   obj-$(CONFIG_INTEL_STRATIX10_RSU)     += stratix10-rsu.o
>>>   obj-$(CONFIG_ISCSI_IBFT_FIND)        += iscsi_ibft_find.o
>>>   obj-$(CONFIG_ISCSI_IBFT)     += iscsi_ibft.o
>>> +KASAN_SANITIZE_iscsi_ibft.o := n
>>> +KCOV_INSTRUMENT_iscsi_ibft.o := n
>>> +
>>>   obj-$(CONFIG_FIRMWARE_MEMMAP)        += memmap.o
>>>   obj-$(CONFIG_RASPBERRYPI_FIRMWARE) += raspberrypi.o
>>>   obj-$(CONFIG_FW_CFG_SYSFS)   += qemu_fw_cfg.o
>>> --
>>> 1.8.3.1
>>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cc712c9c-7786-bb26-7082-04e564df98aa%40oracle.com.

--------------5A39CAAFC3726DB12D456DCE
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html><head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Dutf-8">
  </head>
  <body>
    Hi Dmitry,<br>
    <br>
    <div class=3D"moz-cite-prefix">On 1/27/2021 1:48 PM, Dmitry Vyukov
      wrote:<br>
    </div>
    <blockquote type=3D"cite" cite=3D"mid:CACT4Y+a48smtXc6qJy9Wthwuqjk2gh6o=
7BK1tfWW46g7D_r-Lg@mail.gmail.com">
      <pre class=3D"moz-quote-pre" wrap=3D"">On Wed, Jan 27, 2021 at 7:44 P=
M Konrad Rzeszutek Wilk
<a class=3D"moz-txt-link-rfc2396E" href=3D"mailto:konrad.wilk@oracle.com">&=
lt;konrad.wilk@oracle.com&gt;</a> wrote:
</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">
On Tue, Jan 26, 2021 at 01:03:21PM -0500, George Kennedy wrote:
</pre>
        <blockquote type=3D"cite">
          <pre class=3D"moz-quote-pre" wrap=3D"">During boot of kernel with=
 CONFIG_KASAN the following KASAN false
positive failure will occur when ibft_init() reads the
ACPI iBFT table: BUG: KASAN: use-after-free in ibft_init

The ACPI iBFT table is not allocated, and the iscsi driver uses
a pointer to it to calculate checksum, etc. KASAN complains
about this pointer with use-after-free, which this is not.

</pre>
        </blockquote>
        <pre class=3D"moz-quote-pre" wrap=3D"">
Andrey, Alexander, Dmitry,

I think this is the right way for this, but was wondering if you have
other suggestions?

Thanks!
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">
Hi George, Konrad,

Please provide a sample KASAN report and kernel version to match line numbe=
rs.</pre>
    </blockquote>
    <pre>5.4.17-2102.200.0.0.20210106_0000

[   24.413536] iBFT detected.
[   24.414074]
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   24.407342] BUG: KASAN: use-after-free in ibft_init+0x134/0xb8b
[   24.407342] Read of size 4 at addr ffff8880be452004 by task swapper/0/1
[   24.407342]
[   24.407342] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5.4.17-2102.200.0.=
0.20210106_0000.syzk #1
[   24.407342] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS =
0.0.0 02/06/2015
[   24.407342] Call Trace:
[   24.407342]  dump_stack+0xd4/0x119
[   24.407342]  ? ibft_init+0x134/0xb8b
[   24.407342]  print_address_description.constprop.6+0x20/0x220
[   24.407342]  ? ibft_init+0x134/0xb8b
[   24.407342]  ? ibft_init+0x134/0xb8b
[   24.407342]  __kasan_report.cold.9+0x37/0x77
[   24.407342]  ? ibft_init+0x134/0xb8b
[   24.407342]  kasan_report+0x14/0x1b
[   24.407342]  __asan_report_load_n_noabort+0xf/0x11
[   24.407342]  ibft_init+0x134/0xb8b
[   24.407342]  ? dmi_sysfs_init+0x1a5/0x1a5
[   24.407342]  ? dmi_walk+0x72/0x89
[   24.407342]  ? ibft_check_initiator_for+0x159/0x159
[   24.407342]  ? rvt_init_port+0x110/0x101
[   24.407342]  ? ibft_check_initiator_for+0x159/0x159
[   24.407342]  do_one_initcall+0xc3/0x44d
[   24.407342]  ? perf_trace_initcall_level+0x410/0x405
[   24.407342]  kernel_init_freeable+0x551/0x673
[   24.407342]  ? start_kernel+0x94b/0x94b
[   24.407342]  ? __sanitizer_cov_trace_const_cmp1+0x1a/0x1c
[   24.407342]  ? __kasan_check_write+0x14/0x16
[   24.407342]  ? rest_init+0xe6/0xe6
[   24.407342]  kernel_init+0x16/0x1bd
[   24.407342]  ? rest_init+0xe6/0xe6
[   24.407342]  ret_from_fork+0x2b/0x36
[   24.407342]
[   24.407342] The buggy address belongs to the page:
[   24.407342] page:ffffea0002f91480 refcount:0 mapcount:0 mapping:00000000=
00000000 index:0x1
[   24.407342] flags: 0xfffffc0000000()
[   24.407342] raw: 000fffffc0000000 ffffea0002fca588 ffffea0002fb1a88 0000=
000000000000
[   24.407342] raw: 0000000000000001 0000000000000000 00000000ffffffff 0000=
000000000000
[   24.407342] page dumped because: kasan: bad access detected
[   24.407342]
[   24.407342] Memory state around the buggy address:
[   24.407342]  ffff8880be451f00: ff ff ff ff ff ff ff ff ff ff ff ff ff ff=
 ff ff
[   24.407342]  ffff8880be451f80: ff ff ff ff ff ff ff ff ff ff ff ff ff ff=
 ff ff
[   24.407342] &gt;ffff8880be452000: ff ff ff ff ff ff ff ff ff ff ff ff ff=
 ff ff ff
[   24.407342]                    ^
[   24.407342]  ffff8880be452080: ff ff ff ff ff ff ff ff ff ff ff ff ff ff=
 ff ff
[   24.407342]  ffff8880be452100: ff ff ff ff ff ff ff ff ff ff ff ff ff ff=
 ff ff
[   24.407342]
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   24.407342] Disabling lock debugging due to kernel taint
[   24.451021] Kernel panic - not syncing: panic_on_warn set ...
[   24.452002] CPU: 1 PID: 1 Comm: swapper/0 Tainted: G    B 5.4.17-2102.20=
0.0.0.20210106_0000.syzk #1
[   24.452002] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS =
0.0.0 02/06/2015
[   24.452002] Call Trace:
[   24.452002]  dump_stack+0xd4/0x119
[   24.452002]  ? ibft_init+0x102/0xb8b
[   24.452002]  panic+0x28f/0x6e0
[   24.452002]  ? __warn_printk+0xe0/0xe0
[   24.452002]  ? ibft_init+0x134/0xb8b
[   24.452002]  ? add_taint+0x68/0xb3
[   24.452002]  ? add_taint+0x68/0xb3
[   24.452002]  ? ibft_init+0x134/0xb8b
[   24.452002]  ? ibft_init+0x134/0xb8b
[   24.452002]  end_report+0x4c/0x54
[   24.452002]  __kasan_report.cold.9+0x55/0x77
[   24.452002]  ? ibft_init+0x134/0xb8b
[   24.452002]  kasan_report+0x14/0x1b
[   24.452002]  __asan_report_load_n_noabort+0xf/0x11
[   24.452002]  ibft_init+0x134/0xb8b
[   24.452002]  ? dmi_sysfs_init+0x1a5/0x1a5
[   24.452002]  ? dmi_walk+0x72/0x89
[   24.452002]  ? ibft_check_initiator_for+0x159/0x159
[   24.452002]  ? rvt_init_port+0x110/0x101
[   24.452002]  ? ibft_check_initiator_for+0x159/0x159
[   24.452002]  do_one_initcall+0xc3/0x44d
[   24.452002]  ? perf_trace_initcall_level+0x410/0x405
[   24.452002]  kernel_init_freeable+0x551/0x673
[   24.452002]  ? start_kernel+0x94b/0x94b
[   24.452002]  ? __sanitizer_cov_trace_const_cmp1+0x1a/0x1c
[   24.452002]  ? __kasan_check_write+0x14/0x16
[   24.452002]  ? rest_init+0xe6/0xe6
[   24.452002]  kernel_init+0x16/0x1bd
[   24.452002]  ? rest_init+0xe6/0xe6
[   24.452002]  ret_from_fork+0x2b/0x36
[   24.452002] Dumping ftrace buffer:
[   24.452002] ---------------------------------
[   24.452002] swapper/-1         1.... 24564337us : rdmaip_init: 2924: rdm=
aip_init: Active Bonding is DISABLED
[   24.452002] ---------------------------------
[   24.452002] Kernel Offset: disabled
[   24.452002] Rebooting in 1 seconds..

</pre>
    <i><span id=3D"mainframespan"></span></i>
    <blockquote type=3D"cite" cite=3D"mid:CACT4Y+a48smtXc6qJy9Wthwuqjk2gh6o=
7BK1tfWW46g7D_r-Lg@mail.gmail.com">
      <pre class=3D"moz-quote-pre" wrap=3D"">
Why does KASAN think the address is freed? For that to happen that
memory should have been freed. I don't remember any similar false
positives from KASAN, so this looks a bit suspicious.</pre>
    </blockquote>
    <br>
    I'm not sure why KASAN thinks the address is freed. There are other
    modules where KASAN/KCOV is disabled on boot.<br>
    Could this be for a similar reason?<br>
    <br>
    Thank you,<br>
    George<br>
    <blockquote type=3D"cite" cite=3D"mid:CACT4Y+a48smtXc6qJy9Wthwuqjk2gh6o=
7BK1tfWW46g7D_r-Lg@mail.gmail.com">
      <pre class=3D"moz-quote-pre" wrap=3D"">


</pre>
      <blockquote type=3D"cite">
        <blockquote type=3D"cite">
          <pre class=3D"moz-quote-pre" wrap=3D"">Signed-off-by: George Kenn=
edy <a class=3D"moz-txt-link-rfc2396E" href=3D"mailto:george.kennedy@oracle=
.com">&lt;george.kennedy@oracle.com&gt;</a>
---
 drivers/firmware/Makefile | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/drivers/firmware/Makefile b/drivers/firmware/Makefile
index 5e013b6..30ddab5 100644
--- a/drivers/firmware/Makefile
+++ b/drivers/firmware/Makefile
@@ -14,6 +14,9 @@ obj-$(CONFIG_INTEL_STRATIX10_SERVICE) +=3D stratix10-svc.=
o
 obj-$(CONFIG_INTEL_STRATIX10_RSU)     +=3D stratix10-rsu.o
 obj-$(CONFIG_ISCSI_IBFT_FIND)        +=3D iscsi_ibft_find.o
 obj-$(CONFIG_ISCSI_IBFT)     +=3D iscsi_ibft.o
+KASAN_SANITIZE_iscsi_ibft.o :=3D n
+KCOV_INSTRUMENT_iscsi_ibft.o :=3D n
+
 obj-$(CONFIG_FIRMWARE_MEMMAP)        +=3D memmap.o
 obj-$(CONFIG_RASPBERRYPI_FIRMWARE) +=3D raspberrypi.o
 obj-$(CONFIG_FW_CFG_SYSFS)   +=3D qemu_fw_cfg.o
--
1.8.3.1

</pre>
        </blockquote>
      </blockquote>
    </blockquote>
    <br>
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
om/d/msgid/kasan-dev/cc712c9c-7786-bb26-7082-04e564df98aa%40oracle.com?utm_=
medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan=
-dev/cc712c9c-7786-bb26-7082-04e564df98aa%40oracle.com</a>.<br />

--------------5A39CAAFC3726DB12D456DCE--
