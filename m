Return-Path: <kasan-dev+bncBCWK3NXC5AIBBJ5UT2CQMGQE7H4Z7FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 85AE238C5BF
	for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 13:31:52 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id u7-20020a259b470000b02904dca50820c2sf26687552ybo.11
        for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 04:31:52 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1621596711; cv=pass;
        d=google.com; s=arc-20160816;
        b=CzDEsZX+1htvMxvvu36q4iXzHWrG+aKm5MEiYMADKr1tJ+WSncM9LyehZBYFteGscE
         eTKX6Z8I+6aIURuX7QPo+MddeDDiLqO0oUNO2T2Qdi1H1AMLKzBGOc8qp/JaHAqzDSQX
         ApnK1kjxjL881CZ7afA8pc8D9qjCtgepX5tmy1xqoOH7rD2jz8fuky5kDBtK7YZ1wR87
         K22GVOImN9WCMfREjURSs/q9nXiPg2tpCVOrHoXRQGZf0uCNcd8FEACXpW44ByDRFsEU
         pP8GkAXnC2VOxxB3KkmPUAU9coCCZBnHVGXbqTxWkOFydGio6QFWbog4wY/32lQDRwNk
         /jvQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :in-reply-to:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=ug+cmQ0eyJNKc1CDliG74fhdigEW/xkTQGtpkHV37hc=;
        b=DkaswOhSLqTag+SJRmPNjgbl6dLRzljxzvzmdU6F2owZlzsExvdDn/KctqanZUojcV
         FunYvd0GTb9yqp7uBoH02itgypZynxtfIH52nIuVIcihTbpoewk1cVmYca+xg85UeJAk
         gD2IcuuPYDKg3L4PC+kigR/OwHhBhOmRv3rJKPxHIYAvS9B0w092Zaq0zecbgj5X6MdQ
         AskzZZFKYB2avXly7XpTHI3zdb19u/pldjgeaby2pg7f4qxJAXP3jqSxalS+TrWS3aXi
         5haI12q0mtkkl/TNVq3b9nyi+5bYafdvsI4piVzDR/d4qVFtyxec4fbyeA1HqqX2AYL2
         uf4w==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=IsYNCOiH;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=xhSxXriD;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of vegard.nossum@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=vegard.nossum@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :in-reply-to:content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ug+cmQ0eyJNKc1CDliG74fhdigEW/xkTQGtpkHV37hc=;
        b=BoZt9DCD+jPJ6B1h9MUZ7W2yeE8h0M2ontAHXXqYgEGf3i5VBemVYx4B5bTTPKkBrO
         Ou5IUt4u7D3L52vQqcGrbLJhdt5nQLUMYdv1so38/ftbyJJjVITfhQTsgaJ7j/DuQBqB
         2arggje1uCBxvZgo6O4/iTnQlFsBir4axl/2/yDt8FCtboPYgWRnH0ojohT4stkXaryk
         QqYRvtIbGTMwqiGgeC5JkS+TUl15A1m9TNJ9BwuL6cMcA1GGVUt8wu/pecAta6i6VnuO
         Y3NLy2htxSyLO9u/MoYL4a1kwhkQdMyycAKwhYpTK6oAjguleLU3Rd7MXYcK6tAIOGQw
         CWoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:in-reply-to:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ug+cmQ0eyJNKc1CDliG74fhdigEW/xkTQGtpkHV37hc=;
        b=kf7n3M/sB1uJciX21GkZ/xuj0/FfeuiUd9AaXdE0w41awJNlgylvMYpptLE7ZKNQjc
         mxUyagP9c0kyZWiIMX8uU8QlgbeMIAZFKJAE1cvGxixUthRE2b6J3jRlO+ffqR3wNZSF
         EOJp6ZTQvCB49XwxEJyFHlDA7B4B9iA8Z+dAnRTMk6/93rsNhDl6+FTqjoKV0nNDAV/l
         TsHOcZ06sQjNQHYDDDEMykskjxj2Cmpi6CTWKxXQ6qqa+NdPEu4r7pODoMKE1l6NJQ7g
         LDGPKShJvD/OYOfZXSiUzjb/GWeKWpAh9kdl9KetFtX9NHb1MlY5ZiWz8bA7AEC4T+CP
         LENQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/kuQ33Tdn3KYVedaaI3wFJpMmPXG4YAwf+UsK1KdIL2NaNDHV
	DZhSGY/2P1t2aBxpl+rlVF4=
X-Google-Smtp-Source: ABdhPJxCJsC+r5sxxuUpRngnF23Y8WiMT/maYqoFbHHC82DMcpduZyNhy5eOU8x4xaeKjZ5Aj3ERhw==
X-Received: by 2002:a25:8442:: with SMTP id r2mr13710732ybm.492.1621596711597;
        Fri, 21 May 2021 04:31:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7808:: with SMTP id t8ls3172395ybc.3.gmail; Fri, 21 May
 2021 04:31:51 -0700 (PDT)
X-Received: by 2002:a5b:ac9:: with SMTP id a9mr15428455ybr.304.1621596711126;
        Fri, 21 May 2021 04:31:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621596711; cv=pass;
        d=google.com; s=arc-20160816;
        b=lPgwDqHv9rJ8ixHXHVVZ3JYUssWx8wuX+5j2jtDao27UR5Mfy5mQq2BdV40tXAO38G
         L3FCuykhEsQ4+0laWMFWXV9Dz0qDy4pSEuTjj+05qaR6jCo/do699EcJmtPOg17KiI3m
         pwcgaKxyz7kY6pD/qYa7lDGjxP79TDHMiMM94X2AEIBKoLriNWrVH4qAeYWfMxIwDFxy
         UpsLeGqB4SqdH4y9Cqn8SbiSh47doWY74YSBN4wBmxbIspFXMnEUVrA7oTsmCuKwK29x
         876PykAn0PqKoUdtKYm4N4Ny8xneWvxOy0vbKuXI6DKptGPW0EnT5pJq445aQU0RaDDg
         Mc7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:in-reply-to:user-agent:date
         :message-id:from:references:cc:to:subject:dkim-signature
         :dkim-signature;
        bh=PGVn+kQXwcxp243fSrlSlaeSAuWWi3PjSiIhlHMqgFw=;
        b=aQNpNdQYhFQ52FMrkVz0njhCHWN17oCIbiem5m9hVADd8+ZJD6woKbdVfSTlLC6QHC
         gVN41J60+ok6Ad5hR6+/XyvRnmc7rsOl+l8+1iWrok4SdVmD8Px6Qm8VI0uRljQ/heAY
         GgxJLDNuR+ovOvt6dOjskFxbFxPJk8699GaNx6Lo4fdtzVaVyuGrIBbxCcIHoAykjRg/
         +Q3BgptIfpwuV5XKoRvnH+/hRUeJ3VAxM/QaD1h6kt9FrbGXANygeEbbmto+H1gRMMTD
         Nb7Uj+Gtoeaa76WIoyPzaoQC8gzdeq7H6GMCw85+31fAnHPGzA7GKjSEoWPJvnbwDmnr
         Pwnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=IsYNCOiH;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=xhSxXriD;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of vegard.nossum@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=vegard.nossum@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2120.oracle.com (userp2120.oracle.com. [156.151.31.85])
        by gmr-mx.google.com with ESMTPS id x5si536484ybs.5.2021.05.21.04.31.50
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 May 2021 04:31:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of vegard.nossum@oracle.com designates 156.151.31.85 as permitted sender) client-ip=156.151.31.85;
Received: from pps.filterd (userp2120.oracle.com [127.0.0.1])
	by userp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 14LBPO5D131457;
	Fri, 21 May 2021 11:31:48 GMT
Received: from aserp3030.oracle.com (aserp3030.oracle.com [141.146.126.71])
	by userp2120.oracle.com with ESMTP id 38j6xnqc3u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 May 2021 11:31:48 +0000
Received: from pps.filterd (aserp3030.oracle.com [127.0.0.1])
	by aserp3030.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 14LBPV01083872;
	Fri, 21 May 2021 11:31:47 GMT
Received: from nam11-bn8-obe.outbound.protection.outlook.com (mail-bn8nam11lp2177.outbound.protection.outlook.com [104.47.58.177])
	by aserp3030.oracle.com with ESMTP id 38meehq2q8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 May 2021 11:31:47 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=jwDAt0MpN7wgaPU6wzgV3oyyFkzYGPS1cPLnMzPR2DbENacItn+XrFVZQWxRv27bSZKdOrMeKB3hvXY3rcgvomBS3ROO+dWvS6GvJ4p3a0sALqNEdk2ctg1K6Qtc/UzjBKOl6wWVR7tQ6y3uNSqoPuSakHsF8jAULALvWGGFgAGub25l07h4/5RgxKhFflzNMcqV7qzWxUuz9/MUPeQXBuKVJsk082C0/pgGEkKnv10uaooz6FyqawAGdVlo9QHsyv/Mo5gkcnF8ronqANLF8eiCmDsJEDp2V6MvE7evNamPO6eWbcWOejeTQvawawHg1afhR3TRGH0g1V9IFyh9eA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=PGVn+kQXwcxp243fSrlSlaeSAuWWi3PjSiIhlHMqgFw=;
 b=OQTFr7dN6C15p/M4KLgTmY2wD1ABiu3j+8EXuTUStrh3Knohu3v3yN6pfYUYtE8klg5+bMGydoczkyiSR/TRdgAUSifNrAot+FYU9QWvAu2PAc6BkJDM64nwHBbCpgA46RVRYOHJtmE/zimd0CSV+K4o5uTnJCt9oVZvXj0c6JXxa4KzWvRm8dQEPvSEr+U5vQYks/i52cO+6NynNWl3ajWh3oYSAhoB345NcEO2XslFbH7fZ2h4Xb6q0iPqpX8K0CG7WH00VUMdSoCZnZGwTOKN47mYGxZ7NlK6SdU17nQB8ujKJ078IP47q2+NPLBZrz4gGKC+2aBNbIlJP3yL2Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CY4PR1001MB2133.namprd10.prod.outlook.com
 (2603:10b6:910:43::27) by CY4PR1001MB2405.namprd10.prod.outlook.com
 (2603:10b6:910:3f::33) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4129.26; Fri, 21 May
 2021 11:31:45 +0000
Received: from CY4PR1001MB2133.namprd10.prod.outlook.com
 ([fe80::40a:b796:4a86:d0cc]) by CY4PR1001MB2133.namprd10.prod.outlook.com
 ([fe80::40a:b796:4a86:d0cc%3]) with mapi id 15.20.4129.034; Fri, 21 May 2021
 11:31:45 +0000
Subject: Re: "Learning-based Controlled Concurrency Testing"
To: Dmitry Vyukov <dvyukov@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
        syzkaller <syzkaller@googlegroups.com>, Marco Elver <elver@google.com>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Mathias Payer <mathias.payer@nebelwelt.net>
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
 <5650d220-9ca6-c456-ada3-f64a03007c26@oracle.com>
 <CACT4Y+Z9DuS6aKQdTb1mD6sVbnz_KPFeRK01zmutM1bmG9zSVQ@mail.gmail.com>
From: Vegard Nossum <vegard.nossum@oracle.com>
Message-ID: <51ff62a6-68e1-ea01-5303-07e820ae599d@oracle.com>
Date: Fri, 21 May 2021 13:31:37 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
In-Reply-To: <CACT4Y+Z9DuS6aKQdTb1mD6sVbnz_KPFeRK01zmutM1bmG9zSVQ@mail.gmail.com>
Content-Type: multipart/mixed;
 boundary="------------6174A7DE53AD28E0CAD20CA2"
Content-Language: en-US
X-Originating-IP: [86.217.245.67]
X-ClientProxiedBy: MR2P264CA0030.FRAP264.PROD.OUTLOOK.COM (2603:10a6:500::18)
 To CY4PR1001MB2133.namprd10.prod.outlook.com (2603:10b6:910:43::27)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from [192.168.1.13] (86.217.245.67) by MR2P264CA0030.FRAP264.PROD.OUTLOOK.COM (2603:10a6:500::18) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4150.23 via Frontend Transport; Fri, 21 May 2021 11:31:43 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 526ebdd3-0b46-4cc3-f0ff-08d91c4c034d
X-MS-TrafficTypeDiagnostic: CY4PR1001MB2405:
X-Microsoft-Antispam-PRVS: <CY4PR1001MB24051F245A3FC986A561EA0497299@CY4PR1001MB2405.namprd10.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:4941;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: dsutYJEnl4HtFrIsdNMEtnqdDtzoGAzsEDwtGGsVwn6yXdL3K8EABZH1cq8y2RW3EV7/t5XhziFBB7OMvsJ9UGgDf/hWjDYsEPPH8kgRbfcC7dOMMxH6gilWQ6BEs6nlPfjPRpaZKxPfeCyBpL6I1QEVyKtSCI3dP+fQCcIJaMjMXsgLR7h/x4Al/cw9ivNUoay/DLZeUEdYR0jp/4OMTRDBuf0062F5LFtB84kPVLkC/RIrc80q7JbPef+yEu14Bg5+zJtXiW3DQUvecVhig8mOfYmIpiB8rKnJdkKnB/dKNm/1ZrTIfHFWlDHRtjtgtvaZ6zGShjHhIXMc2YP9bUoEzi7SBciS8dDhED8S1xFSr0Kiw3AvEOZKfQ3EKync6r+pBdTAuLCGX9b6KXFmMPx+Hzi/1k1F6K6qqFmXzJIi3kPw51Whk30M+5yBW2zxvxlbGiLl9H+nfHAh21czt4r+2j0npxshP4XR7YjW7y/Tbddm5/KDDZLz6eB46BB4aJMeyYIbGtADIFN+I3yFcjdGGVzZsX5seYlJOPVmDDLej8ifL9YXeza1kDz2++OGSZsk6FpOcEE/zuE0uY5Z7bUdK8MF794mTSBE+jNsW79+JmhXO9cbysheHk9OBSxCY1vz8KRKotcFvH/nTsMutE6bWw8Duy7Q2vesQwF/UPY3OVxTPhyoCzyi6Nf47nU3Ph7khvQbN3H0jAVU3ZDOrBBx9I002x9LxgtcbvT4eg70yWLWU7LhSZap7l2L3pxr9m8wn/sjoQgHaWTnCTbHaxHdI2FGRPMalYenaN3zo201U1uUXUKhS2O2kH+p9r4WkcB0uh0d0+QOtsuizjz3DQ==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CY4PR1001MB2133.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(136003)(346002)(366004)(39860400002)(376002)(396003)(66616009)(66556008)(66946007)(66476007)(52116002)(186003)(16526019)(33964004)(26005)(4326008)(2906002)(16576012)(316002)(956004)(478600001)(53546011)(5660300002)(6486002)(44832011)(6916009)(54906003)(235185007)(966005)(6666004)(83380400001)(38350700002)(38100700002)(36756003)(31696002)(31686004)(2616005)(8676002)(86362001)(8936002)(45980500001)(43740500002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: ODciO/MnVUfCKm+fapUUfwl6nzSsLTrk0oaHz/XwOUkcGySqq5cSiWowvIhfKrU+N7zPZg5TU3Vg+ffHAnOO4wGzuWUw04cBH5Uv/HMr1AaASPmTW/hFAxmYqW6uNNsQ3f5lELaIlimxX0kIdiTG3GpuwfQJmbVglCGx+qhfzGF4zpYDNTUnwx2ChXnOhqV//GMQ1qlNo8swxzdklarLRE+c4mWYY5qUkT6iIg0q/PIn4vsp17vNo2U6OEF59nqSzWk4xLj+udhhbpV8gZJwrWb/UoliiYIULpf6jTDAKxjoBGD860ZtcMksWkCC4qCftNicNaPx79oisgSiO3wZensNq23RUxvpGhT2LJ3zTkkChU9aF6WDlozlp4tTWpgj3FmC183SRFMp05+b40wSUX1RdSD1LQNZF4JR7MDmNYC1sI8N248RC5Aj1sh4A5J+TKuY47rVxoZsUwtTev66mWMRjZLGjNPdXLjh9V69Ybe4UTFtKJOmsURPxia70VBP/8IufH46o0Xc/QmO3QJKZ3pQ+iLFBOPQ+yE7OzJivLjH+cBnndQ+UL1soxn2phm+vGLV29D10Yfc/8Cmrk74MqkVJYzfptmNqx0LEG4htTNRHx4rhreWqBkuwhMUHu+EDJveXV9jrIAO6/cfGXKrD1YkIq9wpPPYoKe1DkF4e8nyrA5WIXAz9ftSU9SOkTPQm3AAW5vWAw/SrTCTD5bBrxolzL+wbOz6dRIA9WftvCAz3pcJ4ott/g0L0ReMltbb
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 526ebdd3-0b46-4cc3-f0ff-08d91c4c034d
X-MS-Exchange-CrossTenant-AuthSource: CY4PR1001MB2133.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 May 2021 11:31:45.3424
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: vlmZwv0/CjeKgasdPRywNucr38GNTLoTygmnguIAWo9B7CZg8f2i+cjcZ6j6+CLIUwkT7is9PTCvuWXg0WSv0c2PsIFouU39Lv3SchzUq5c=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY4PR1001MB2405
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9990 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 mlxlogscore=999 adultscore=0
 phishscore=0 malwarescore=0 bulkscore=0 spamscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2104190000
 definitions=main-2105210071
X-Proofpoint-GUID: DO2TV76pInX3kQ_l4tCfA5K5AJgTPFK1
X-Proofpoint-ORIG-GUID: DO2TV76pInX3kQ_l4tCfA5K5AJgTPFK1
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9990 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 impostorscore=0 mlxscore=0
 mlxlogscore=999 adultscore=0 malwarescore=0 priorityscore=1501
 phishscore=0 suspectscore=0 lowpriorityscore=0 bulkscore=0 clxscore=1011
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2104190000 definitions=main-2105210071
X-Original-Sender: vegard.nossum@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=IsYNCOiH;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=xhSxXriD;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of vegard.nossum@oracle.com designates
 156.151.31.85 as permitted sender) smtp.mailfrom=vegard.nossum@oracle.com;
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

--------------6174A7DE53AD28E0CAD20CA2
Content-Type: text/plain; charset="UTF-8"; format=flowed

On 2021-05-19 09:19, Dmitry Vyukov wrote:
> On Mon, May 17, 2021 at 8:15 PM Vegard Nossum <vegard.nossum@oracle.com> wrote:
>> On 2021-05-17 18:44, Paul E. McKenney wrote:
>> Somewhat tangential in the context of the paper posted (and probably
>> less clever), and not based on state... but how about a new gcc plugin
>> that records which struct members are being accessed? You could for
>> example hash struct name + member name into a single number that can be
>> recorded AFL-style in a fixed-size bitmap or kcov-style...
>>
>> The fundamental idea is to just ignore everything about locking and
>> concurrent accesses -- if you have the data above you'll know which
>> independent test cases are likely to *try* accessing the same data (but
>> from different code paths), so if there's a race somewhere it might be
>> triggered more easily if they're run concurrently.
> 
> Hi Vegard,
> 
> Interesting idea.
> Also +Mathias who was interested in dependency analysis between syscalls.
> 
> A similar analysis can be done statically as well... I can't make up
> my mind which one would be better... both have pros and cons...
> 
> However, again, I think we are missing some lower hanging fruit here.
> The current collide mode is super dumb and simple, I added it very
> early to trigger at least some races. It turned out to be efficient
> enough for now to never get back to it. The tracking issues for better
> collider with some ideas is:
> https://github.com/google/syzkaller/issues/612
> I think we need to implement it before we do anything more fancy. Just
> because we need an engine that could accept and act on the signal you
> describe. That engine is indepent of the actual signal we use to
> determine related syscalls, and it's useful on its own. And we have
> some easy to extract dependency information already in syscall
> descriptions in the form of /resources/. Namely, if we have 2 syscalls
> operating on, say, SCTP sockets, that's a pretty good signal that they
> are related and may operate on the same data.
> Once we have it, we could plug in more elaborate dynamic analysis info
> that will give a much higher quality signal regarding the relation of
> 2 exact syscall invocations in the exact program.

I understand what you wrote about improving the collider support, but
unfortunately I don't think my Go skills are sufficient to make a
contribution on the syzkaller side here...

However, I was too curious to stop myself, so I went ahead and
implemented a gcc plugin for collecting struct member derefs + a kcov
mode, see the attachment. It seems to work here but I'm probably missing
some subtler cases in the gcc code (e.g. anonymous structs).

I'll play a bit with this, and the plugin is there in case somebody does
end up doing something on the syzkaller side :-)


Vegard

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/51ff62a6-68e1-ea01-5303-07e820ae599d%40oracle.com.

--------------6174A7DE53AD28E0CAD20CA2
Content-Type: text/x-patch; charset=UTF-8;
 name="0001-kcov-add-dereference-tracing-mode.patch"
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment;
 filename="0001-kcov-add-dereference-tracing-mode.patch"

From c2118d72cbda89a6a39ef1bc7c837c1599d4fe9b Mon Sep 17 00:00:00 2001
From: Vegard Nossum <vegard.nossum@oracle.com>
Date: Fri, 21 May 2021 11:26:03 +0200
Subject: [PATCH] kcov: add dereference tracing mode

So far just a sketch, proper changelog TBD.

Example user program (can be run as init):

	#include <stdio.h>
	#include <stddef.h>
	#include <stdint.h>
	#include <stdlib.h>
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <sys/ioctl.h>
	#include <sys/mman.h>
	#include <unistd.h>
	#include <fcntl.h>

	#if 1 // init
	#include <sys/mount.h>
	#include <errno.h>
	#include <error.h>
	#endif

	#define KCOV_INIT_TRACE			_IOR('c', 1, unsigned long)
	#define KCOV_ENABLE			_IO('c', 100)
	#define KCOV_DISABLE			_IO('c', 101)
	#define COVER_SIZE			512 // 1 page

	#define KCOV_TRACE_PC  0
	#define KCOV_TRACE_CMP 1
	#define KCOV_TRACE_DEREF 2

	int main(int argc, char **argv)
	{
	    uint64_t type, arg1, arg2, is_const, size;
	    unsigned long n, i;

	#if 1 // init
	    mkdir("/sys", 0755);
	    if (mount("nodev", "/sys", "sysfs", 0, "") == -1)
		error(EXIT_FAILURE, errno, "mount(/sys)");

	    if (mount("nodev", "/sys/kernel/debug", "debugfs", 0, "") == -1)
		error(EXIT_FAILURE, errno, "mount(/sys/kernel/debug)");
	#endif

	    int fd = open("/sys/kernel/debug/kcov", O_RDWR);
	    if (fd == -1)
		perror("open"), exit(1);

	    if (ioctl(fd, KCOV_INIT_TRACE, COVER_SIZE))
		perror("ioctl"), exit(1);

	    uint64_t *cover = (uint64_t *) mmap(NULL, COVER_SIZE * sizeof(unsigned long),
		PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	    if ((void*)cover == MAP_FAILED)
		perror("mmap"), exit(1);

	    if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_DEREF))
		perror("ioctl"), exit(1);

	    // just do something...
	    char buf[1024];
	    read(open("/sys/kernel/slab/kmalloc-32/order", O_RDONLY), buf, sizeof(buf));

	    if (ioctl(fd, KCOV_DISABLE, 0))
		perror("ioctl"), exit(1);

	    for (i = 0; i < COVER_SIZE; i++)
		printf("%08lx", cover[i]);
	    printf("\n");

	    /* Free resources. */
	    if (munmap(cover, COVER_SIZE * sizeof(unsigned long)))
		perror("munmap"), exit(1);

	    if (close(fd))
		perror("close"), exit(1);

	    return 0;
	}

Signed-off-by: Vegard Nossum <vegard.nossum@oracle.com>
---
 include/linux/kcov.h                      |   2 +
 include/uapi/linux/kcov.h                 |   2 +
 kernel/kcov.c                             |  41 +++-
 lib/Kconfig.debug                         |   7 +
 scripts/Makefile.gcc-plugins              |   2 +
 scripts/Makefile.kcov                     |   1 +
 scripts/gcc-plugins/Kconfig               |   6 +
 scripts/gcc-plugins/sancov_deref_plugin.c | 221 ++++++++++++++++++++++
 8 files changed, 277 insertions(+), 5 deletions(-)
 create mode 100644 scripts/gcc-plugins/sancov_deref_plugin.c

diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index 55dc338f6bcdd..3d1f359437a38 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -21,6 +21,8 @@ enum kcov_mode {
 	KCOV_MODE_TRACE_PC = 2,
 	/* Collecting comparison operands mode. */
 	KCOV_MODE_TRACE_CMP = 3,
+	/* Collecting dereferences mode. */
+	KCOV_MODE_TRACE_DEREF = 4,
 };
 
 #define KCOV_IN_CTXSW	(1 << 30)
diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
index 1d0350e44ae34..25c4f2a58a867 100644
--- a/include/uapi/linux/kcov.h
+++ b/include/uapi/linux/kcov.h
@@ -35,6 +35,8 @@ enum {
 	KCOV_TRACE_PC = 0,
 	/* Collecting comparison operands mode. */
 	KCOV_TRACE_CMP = 1,
+	/* Collecting dereferences mode. */
+	KCOV_TRACE_DEREF = 2,
 };
 
 /*
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 80bfe71bbe13e..121e31a6f64cf 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -40,6 +40,8 @@
  *	KCOV_TRACE_PC - to trace only the PCs
  *	or
  *	KCOV_TRACE_CMP - to trace only the comparison operands
+ *	or
+ *	KCOV_TRACE_DEREF - to trace struct dereferences
  *  - then, ioctl(KCOV_DISABLE) to disable the task.
  * Enabling/disabling ioctls can be repeated (only one task a time allowed).
  */
@@ -322,6 +324,31 @@ void notrace __sanitizer_cov_trace_switch(u64 val, u64 *cases)
 EXPORT_SYMBOL(__sanitizer_cov_trace_switch);
 #endif /* ifdef CONFIG_KCOV_ENABLE_COMPARISONS */
 
+#ifdef CONFIG_KCOV_ENABLE_DEREFERENCES
+void notrace __sanitizer_cov_trace_deref(u32 hash)
+{
+	struct task_struct *t;
+	u64 *area;
+	unsigned long mask;
+
+	t = current;
+	if (!check_kcov_mode(KCOV_MODE_TRACE_DEREF, t))
+		return;
+
+	// TODO: precompute this
+	area = t->kcov_area;
+	mask = rounddown_pow_of_two(t->kcov_size) - 1;
+
+	// TODO: racy without atomic/{READ,WRITE}_ONCE?
+	area[BIT_WORD(hash) & mask] |= BIT_MASK(hash);
+}
+EXPORT_SYMBOL(__sanitizer_cov_trace_deref);
+#endif /* ifdef KCOV_ENABLE_DEREFERENCES */
+
+void notrace __sanitizer_cov_trace_(u64 val, u64 *cases)
+{
+}
+
 static void kcov_start(struct task_struct *t, struct kcov *kcov,
 			unsigned int size, void *area, enum kcov_mode mode,
 			int sequence)
@@ -516,11 +543,9 @@ static int kcov_get_mode(unsigned long arg)
 	if (arg == KCOV_TRACE_PC)
 		return KCOV_MODE_TRACE_PC;
 	else if (arg == KCOV_TRACE_CMP)
-#ifdef CONFIG_KCOV_ENABLE_COMPARISONS
-		return KCOV_MODE_TRACE_CMP;
-#else
-		return -ENOTSUPP;
-#endif
+		return IS_ENABLED(CONFIG_KCOV_ENABLE_COMPARISONS) ? KCOV_MODE_TRACE_CMP : -ENOTSUPP;
+	else if (arg == KCOV_TRACE_DEREF)
+		return IS_ENABLED(CONFIG_KCOV_ENABLE_DEREFERENCES) ? KCOV_MODE_TRACE_DEREF : -ENOTSUPP;
 	else
 		return -EINVAL;
 }
@@ -922,6 +947,9 @@ static void kcov_move_area(enum kcov_mode mode, void *dst_area,
 		BUILD_BUG_ON(!is_power_of_2(KCOV_WORDS_PER_CMP));
 		entry_size_log = __ilog2_u64(sizeof(u64) * KCOV_WORDS_PER_CMP);
 		break;
+	case KCOV_MODE_TRACE_DEREF:
+		// TODO
+		break;
 	default:
 		WARN_ON(1);
 		return;
@@ -946,6 +974,9 @@ static void kcov_move_area(enum kcov_mode mode, void *dst_area,
 	case KCOV_MODE_TRACE_CMP:
 		WRITE_ONCE(*(u64 *)dst_area, dst_len + entries_moved);
 		break;
+	case KCOV_MODE_TRACE_DEREF:
+		// TODO
+		break;
 	default:
 		break;
 	}
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 678c13967580e..2cc3af7544367 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -2007,6 +2007,13 @@ config KCOV_ENABLE_COMPARISONS
 	  These operands can be used by fuzzing engines to improve the quality
 	  of fuzzing coverage.
 
+config KCOV_ENABLE_DEREFERENCES
+	bool "Enable dereference collection by KCOV"
+	depends on KCOV
+	select GCC_PLUGIN_SANCOV_DEREF
+	help
+	  Blaargh.
+
 config KCOV_INSTRUMENT_ALL
 	bool "Instrument all code by default"
 	depends on KCOV
diff --git a/scripts/Makefile.gcc-plugins b/scripts/Makefile.gcc-plugins
index 952e46876329a..93d8aafed01c1 100644
--- a/scripts/Makefile.gcc-plugins
+++ b/scripts/Makefile.gcc-plugins
@@ -11,6 +11,7 @@ endif
 export DISABLE_LATENT_ENTROPY_PLUGIN
 
 gcc-plugin-$(CONFIG_GCC_PLUGIN_SANCOV)		+= sancov_plugin.so
+gcc-plugin-$(CONFIG_GCC_PLUGIN_SANCOV_DEREF)	+= sancov_deref_plugin.so
 
 gcc-plugin-$(CONFIG_GCC_PLUGIN_STRUCTLEAK)	+= structleak_plugin.so
 gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STRUCTLEAK_VERBOSE)	\
@@ -51,6 +52,7 @@ export DISABLE_ARM_SSP_PER_TASK_PLUGIN
 GCC_PLUGINS_CFLAGS := $(strip $(addprefix -fplugin=$(objtree)/scripts/gcc-plugins/, $(gcc-plugin-y)) $(gcc-plugin-cflags-y))
 # The sancov_plugin.so is included via CFLAGS_KCOV, so it is removed here.
 GCC_PLUGINS_CFLAGS := $(filter-out %/sancov_plugin.so, $(GCC_PLUGINS_CFLAGS))
+GCC_PLUGINS_CFLAGS := $(filter-out %/sancov_deref_plugin.so, $(GCC_PLUGINS_CFLAGS))
 export GCC_PLUGINS_CFLAGS
 
 # Add the flags to the build!
diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
index 67e8cfe3474b7..1aeda23124dca 100644
--- a/scripts/Makefile.kcov
+++ b/scripts/Makefile.kcov
@@ -2,5 +2,6 @@
 kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)	+= -fsanitize-coverage=trace-pc
 kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)	+= -fsanitize-coverage=trace-cmp
 kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)		+= -fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so
+kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV_DEREF)	+= -fplugin=$(objtree)/scripts/gcc-plugins/sancov_deref_plugin.so
 
 export CFLAGS_KCOV := $(kcov-flags-y)
diff --git a/scripts/gcc-plugins/Kconfig b/scripts/gcc-plugins/Kconfig
index ab9eb4cbe33a6..eec1a1fa1f42d 100644
--- a/scripts/gcc-plugins/Kconfig
+++ b/scripts/gcc-plugins/Kconfig
@@ -43,6 +43,12 @@ config GCC_PLUGIN_SANCOV
 	  gcc-4.5 on). It is based on the commit "Add fuzzing coverage support"
 	  by Dmitry Vyukov <dvyukov@google.com>.
 
+config GCC_PLUGIN_SANCOV_DEREF
+	bool
+	help
+	  This plugin inserts a __sanitizer_cov_trace_deref() call whenever a
+	  struct is dereferenced.
+
 config GCC_PLUGIN_LATENT_ENTROPY
 	bool "Generate some entropy during boot and runtime"
 	help
diff --git a/scripts/gcc-plugins/sancov_deref_plugin.c b/scripts/gcc-plugins/sancov_deref_plugin.c
new file mode 100644
index 0000000000000..d613fe9d008fd
--- /dev/null
+++ b/scripts/gcc-plugins/sancov_deref_plugin.c
@@ -0,0 +1,221 @@
+/*
+ * Copyright (c) 2021, Oracle and/or its affiliates.
+ * Author: Vegard Nossum <vegard.nossum@oracle.com>
+ *
+ * Based on:
+ *
+ * sancov_plugin
+ * Copyright 2011-2016 by Emese Revfy <re.emese@gmail.com>
+ * Licensed under the GPL v2, or (at your option) v3
+ *
+ * randomize_layout_plugin
+ * Copyright 2014-2016 by Open Source Security, Inc., Brad Spengler <spender@grsecurity.net>
+ *                   and PaX Team <pageexec@freemail.hu>
+ * Licensed under the GPL v2
+ */
+
+#include "gcc-common.h"
+
+#define ORIG_TYPE_NAME(node) \
+	(TYPE_NAME(TYPE_MAIN_VARIANT(node)) != NULL_TREE ? ((const unsigned char *)IDENTIFIER_POINTER(TYPE_NAME(TYPE_MAIN_VARIANT(node)))) : (const unsigned char *)"anonymous")
+
+__visible int plugin_is_GPL_compatible;
+
+tree sancov_deref_fndecl;
+
+static struct plugin_info sancov_deref_plugin_info = {
+	.version	= "20210519",
+	.help		= "sancov_deref plugin\n",
+};
+
+/*
+ * Hashing helpers adapted from old Linux dcache.h and include/linux/hash.h
+ */
+
+static inline unsigned long
+partial_name_hash(unsigned long c, unsigned long prevhash)
+{
+	return (prevhash + (c << 4) + (c >> 4)) * 11;
+}
+
+static inline unsigned long
+name_hash(const char *name, unsigned long prevhash)
+{
+	unsigned long hash = prevhash;
+	unsigned int len = strlen(name);
+	while (len--)
+		hash = partial_name_hash(*name++, hash);
+	return hash;
+}
+
+#define GOLDEN_RATIO_64 0x61C8864680B583EBull
+
+static inline unsigned long
+end_name_hash(unsigned long prevhash)
+{
+	return (prevhash * GOLDEN_RATIO_64) >> 32;
+}
+
+static unsigned int sancov_deref_execute(void)
+{
+	basic_block bb;
+
+	if (!strcmp(DECL_NAME_POINTER(current_function_decl), DECL_NAME_POINTER(sancov_deref_fndecl)))
+		return 0;
+
+	FOR_EACH_BB_FN(bb, cfun) {
+		gimple_stmt_iterator gsi;
+
+		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
+			gimple stmt;
+			const_tree rhs1;
+			const_tree rhs1_arg0;
+			const_tree rhs1_arg0_type;
+			const_tree rhs1_arg0_type_name;
+			const_tree rhs1_arg1;
+			const char *struct_name;
+			const char *member_name;
+			gcall *gcall;
+
+			stmt = gsi_stmt(gsi);
+			if (gimple_code(stmt) != GIMPLE_ASSIGN)
+				continue;
+
+			rhs1 = gimple_assign_rhs1(stmt);
+			if (TREE_CODE(rhs1) != COMPONENT_REF)
+				continue;
+
+			rhs1_arg0 = TREE_OPERAND(rhs1, 0);
+			if (TREE_CODE(rhs1_arg0) != MEM_REF)
+				continue;
+
+			rhs1_arg0_type = TREE_TYPE(rhs1_arg0);
+			if (TREE_CODE(rhs1_arg0_type) != RECORD_TYPE)
+				continue;
+
+			rhs1_arg1 = TREE_OPERAND(rhs1, 1);
+			if (TREE_CODE(rhs1_arg1) != FIELD_DECL)
+				continue;
+
+			rhs1_arg0_type_name = TYPE_NAME(rhs1_arg0_type);
+			if (rhs1_arg0_type_name == NULL_TREE) {
+				// why?
+				//debug_tree(rhs1_arg0_type_name);
+				continue;
+			}
+
+			if (TREE_CODE(rhs1_arg0_type_name) == TYPE_DECL) {
+				// even with this check, we sometimes crash in DECL_ORIGINAL_TYPE() below. why??
+				//debug_tree(rhs1_arg0_type_name);
+				continue;
+
+				rhs1_arg0_type = DECL_ORIGINAL_TYPE(rhs1_arg0_type_name);
+				rhs1_arg0_type_name = TYPE_NAME(rhs1_arg0_type);
+			}
+
+			if (TREE_CODE(rhs1_arg0_type_name) != IDENTIFIER_NODE) {
+				// why?
+				//debug_tree(rhs1_arg0_type_name);
+				continue;
+			}
+
+			struct_name = TYPE_NAME_POINTER(rhs1_arg0_type);
+			member_name = DECL_NAME_POINTER(rhs1_arg1);
+
+			// TODO: skip tracing some incredibly common dereferences
+			// that do nothing in terms of coverage, like list_head::next
+
+			// random seed
+			unsigned long hash = 0x177e3471c15cd026UL;
+			hash = name_hash(struct_name, hash);
+			hash = name_hash("::", hash);
+			hash = name_hash(member_name, hash);
+			hash = end_name_hash(hash);
+
+			//fprintf(stderr, "@@@ %lx %s::%s\n", hash, struct_name, member_name);
+
+			gcall = as_a_gcall(gimple_build_call(sancov_deref_fndecl, 1, build_int_cstu(uint32_type_node, hash)));
+			gimple_set_location(gcall, gimple_location(stmt));
+			gsi_insert_before(&gsi, gcall, GSI_SAME_STMT);
+		}
+
+	}
+
+	return 0;
+}
+
+#define PASS_NAME sancov_deref
+
+#define NO_GATE
+#define TODO_FLAGS_FINISH TODO_dump_func | TODO_verify_stmts | TODO_update_ssa_no_phi | TODO_verify_flow
+
+#include "gcc-generate-gimple-pass.h"
+
+static void sancov_deref_start_unit(void __unused *gcc_data, void __unused *user_data)
+{
+	tree leaf_attr, nothrow_attr;
+	tree BT_FN_VOID = build_function_type_list(void_type_node, NULL_TREE);
+
+	sancov_deref_fndecl = build_fn_decl("__sanitizer_cov_trace_deref", BT_FN_VOID);
+
+	DECL_ASSEMBLER_NAME(sancov_deref_fndecl);
+	TREE_PUBLIC(sancov_deref_fndecl) = 1;
+	DECL_EXTERNAL(sancov_deref_fndecl) = 1;
+	DECL_ARTIFICIAL(sancov_deref_fndecl) = 1;
+	DECL_PRESERVE_P(sancov_deref_fndecl) = 1;
+	DECL_UNINLINABLE(sancov_deref_fndecl) = 1;
+	TREE_USED(sancov_deref_fndecl) = 1;
+
+	nothrow_attr = tree_cons(get_identifier("nothrow"), NULL, NULL);
+	decl_attributes(&sancov_deref_fndecl, nothrow_attr, 0);
+	gcc_assert(TREE_NOTHROW(sancov_deref_fndecl));
+	leaf_attr = tree_cons(get_identifier("leaf"), NULL, NULL);
+	decl_attributes(&sancov_deref_fndecl, leaf_attr, 0);
+}
+
+__visible int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
+{
+	int i;
+	const char * const plugin_name = plugin_info->base_name;
+	const int argc = plugin_info->argc;
+	const struct plugin_argument * const argv = plugin_info->argv;
+	bool enable = true;
+
+	static const struct ggc_root_tab gt_ggc_r_gt_sancov_deref[] = {
+		{
+			.base = &sancov_deref_fndecl,
+			.nelt = 1,
+			.stride = sizeof(sancov_deref_fndecl),
+			.cb = &gt_ggc_mx_tree_node,
+			.pchw = &gt_pch_nx_tree_node
+		},
+		LAST_GGC_ROOT_TAB
+	};
+
+	/* BBs can be split afterwards?? */
+	PASS_INFO(sancov_deref, "asan", 0, PASS_POS_INSERT_BEFORE);
+
+	if (!plugin_default_version_check(version, &gcc_version)) {
+		error(G_("incompatible gcc/plugin versions"));
+		return 1;
+	}
+
+	for (i = 0; i < argc; ++i) {
+		if (!strcmp(argv[i].key, "no-sancov-deref")) {
+			enable = false;
+			continue;
+		}
+		error(G_("unknown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
+	}
+
+	register_callback(plugin_name, PLUGIN_INFO, NULL, &sancov_deref_plugin_info);
+
+	if (!enable)
+		return 0;
+
+	register_callback(plugin_name, PLUGIN_START_UNIT, &sancov_deref_start_unit, NULL);
+	register_callback(plugin_name, PLUGIN_REGISTER_GGC_ROOTS, NULL, (void *)&gt_ggc_r_gt_sancov_deref);
+	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &sancov_deref_pass_info);
+
+	return 0;
+}
-- 
2.23.0.718.g5ad94255a8


--------------6174A7DE53AD28E0CAD20CA2--
