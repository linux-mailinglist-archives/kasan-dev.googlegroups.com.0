Return-Path: <kasan-dev+bncBAABB4FX2SLQMGQETHGU54A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 848B858FEDB
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 17:10:41 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id bt7-20020a056902136700b006777a976adfsf14878530ybb.20
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 08:10:41 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1660230640; cv=pass;
        d=google.com; s=arc-20160816;
        b=oQxUb0KoQKrsq0PkYOfAfRlzSoYq9VxeBqhW4tXuj6fLSdUxOxtby0T0lhJgNOG//r
         69XdRQts01IS/TFymDVrShWhT11zgK8Bb44HSskuj+zyYc87tqmaOfySYeCjIdOMEzmk
         m96HrN7bfcbYuolps8/12ejswrSRYqo4uUB33lf0y2ehW5m/gXd2YoteAGyJ1Gc14vVs
         u5GxIpS3CZVA4s+KBm1+YGXl0YcbEBI3qoHfBNUF136d5ZOaLR2mndjhyvOwEKKGsg8U
         kHuPZ8N5zaUDGXy6pKhd5eySqxtpLjR1XeM/tIiepl0vkQLVlK6TmJmXLRST457YDo1J
         bg/Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:date
         :message-id:sender:dkim-signature;
        bh=PtXFEhB8jeQRhkyAwNrNUG1CAAf0VmSzOjMdXPAZrUA=;
        b=SOH3QRW4m2QrMdoC/4QfDn7GB8m1T+ZHCfMsCgy2KER0md33tjyaFe+jLJPaC1Q7ge
         L/IBSEvgf/GlDCL2CetYXMZ3keBUoNOigkCRUV2SMGvgHkKOoQonHmk3taIvgQF8rD11
         0BwcTDYkh3C6grOQIKNpvQhvqUF1PK1IZk+bWKIDTm6oGFnhHIF2O9WVPaeorIM95CUY
         ThCp0i9v558zD90xvNjlzO0GUEeDe3vEwV2VYVjza2XDFcDTReb/l44bfTJHuE0Dcl0s
         piITPwON7lw4KTSc6L0Ffu3JeE8XwDOtEDTwBWweOQ5M+L1lANclSU4GnIHWsAJSBhXb
         HS/g==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2022-7-12 header.b=hzLLEcJk;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=WvDFCRRz;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of imran.f.khan@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=imran.f.khan@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:date:message-id:sender:from:to
         :cc;
        bh=PtXFEhB8jeQRhkyAwNrNUG1CAAf0VmSzOjMdXPAZrUA=;
        b=nGL98ulEztwl0O2G83L1PQzEmhXo9IFHq2yRVO8z9KHBBzpwbgLkEI3dJsEPRYADMy
         iZDzJVJNx2A2cKgwlNdR/m6ZyJa2h7Y7BMtS39z+irOy9SDHMSvINuvAPoAN8p0NEAIO
         9IaRKA0QdRopJ4tRnKtH0yhaa7RYZRRTYofQcXNX5k5CSMrDoXIwrzmU3GqHd+14UhIZ
         dMwi8vQp5r5moUTkULz46oIvbB81lqAM709bDqpEpvpuBA8gwLg6Wjb8cPs9mfBhuh9y
         XwURNmAcjYOYTir/ZzlbnV/5kTr/dznyV5H0bx4tHfZ6DYKFvjZp1+0aiMEy6SsDMGJ6
         Hquw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:date:message-id:x-gm-message-state:sender:from:to:cc;
        bh=PtXFEhB8jeQRhkyAwNrNUG1CAAf0VmSzOjMdXPAZrUA=;
        b=IzZMltNk8mwPZjRjgAzo11nBtb/jMEk+eFfdHVpXCU+V1X2qOD6jt3EmGRVCmHJFGY
         SUKUc5n4Arr+kSieg0xtQ2B3nFxvRevrl5xOIwXAtdlQsHWYBjN4QgRyL4j9AtlNjp2Z
         RDVPzYbnZFDfiZdUzuZvKe0A93eg1kJKTa4O4+OGXfieqCz5chl+MW2yK/Gk8LTDGMUe
         MK8kTP/1FOButqkAoCFdQs2+HbK2LpRji4y522uG0+vFSxUer/h9bPK/hu/TTclKzxvr
         m6fqacolo9loLbfUX/TyMXa1KyLJGxmJ+ERmN1Oe4pnohdLblro551YY/V/1fu5yuWVu
         x+0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2og/chVpddEGhDPHzZ1nqniLLdBoNg1CaKZyVbxqKrvZVxwezQ
	iLWiGeWBpdne2SS5b+9viLU=
X-Google-Smtp-Source: AA6agR5pDVGGbu5YHM6QRHeBrn300qedYrHepxHFr8hur7s1AMjRfULfrIxjqqMuyl1j535f+/wDWg==
X-Received: by 2002:a81:c30a:0:b0:328:4a6c:bc89 with SMTP id r10-20020a81c30a000000b003284a6cbc89mr33240948ywk.29.1660230640186;
        Thu, 11 Aug 2022 08:10:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:d454:0:b0:31f:56e8:aa58 with SMTP id w81-20020a0dd454000000b0031f56e8aa58ls1195092ywd.9.-pod-prod-gmail;
 Thu, 11 Aug 2022 08:10:39 -0700 (PDT)
X-Received: by 2002:a81:7756:0:b0:328:2dde:3336 with SMTP id s83-20020a817756000000b003282dde3336mr34729605ywc.81.1660230639651;
        Thu, 11 Aug 2022 08:10:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660230639; cv=pass;
        d=google.com; s=arc-20160816;
        b=I+OzeENvETah+WZ3/wlTTqF7dPzfs2OKMrjwVz7vavxF+FIfzZ11M8fm3bwtGsD91x
         aEsaphoOXYo3QsypZnSEggZ/K35WEOa5d5p5eeblWKmAXrMzjv2cRj0QW0rp79awPvjn
         M2FkMHf3mIRM8wY1mkllQFkcOF2KuXPPvpOc9CVpbV54Mbehw1+90NDaNEeJHDyrZZ7z
         rFqXqH2Dn6N76b5Z9CKFEVNry+tNyLWhquAnmL+QAmAA3R4cOyS3u3iOu98g8X6z9a5i
         oWhHBfhj5FoqjjM2+XjzFX2LDX3rpQyUgupaQaifhptMh4oo91a66I/Q4nC1QehcWp8s
         pPlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:content-language:subject:user-agent:date:message-id
         :dkim-signature:dkim-signature;
        bh=yPZI13DPAP3gB4/lrzo4c8VA5C0qzZ9dMTuHeJ1EfwI=;
        b=Uh4epEfS6UtK5hTRSOoDM4S9PdRCPDxgXle4D+nlMXBrIYteKjlcDdPxjrvsIMjAYQ
         /+gq9tuPEzpiha3vvOVIiBA0JzPAywF8ADruQu/JVFcCs9zUvMPquc6e1BEQftTerrQt
         5/ZfqRtvNRA6HOIAFF7WxPNe8Y9UDM6BNtKrky6u/6ntHQgBpD42E/5bgbwexPihc5Di
         Wq3+yQ0FavL1kMQ+77vliDE1bnRCDPZ9SeB+hX6Uv+ecizqtwuJYOKzNAOE4zHY2AZth
         FSAvveuXFKTvCSDmuznXXhD8DCGD3vePTJARLLXYKplqDftmc7rkZZZPMxKGVri4wKNP
         d9dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2022-7-12 header.b=hzLLEcJk;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=WvDFCRRz;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of imran.f.khan@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=imran.f.khan@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id i85-20020a25d158000000b0067a69dcb59bsi1052851ybg.2.2022.08.11.08.10.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Aug 2022 08:10:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of imran.f.khan@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.17.1.5/8.17.1.5) with ESMTP id 27BE8uGt030054;
	Thu, 11 Aug 2022 15:10:37 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 3huwqj4xqf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 11 Aug 2022 15:10:36 +0000
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.17.1.5/8.17.1.5) with ESMTP id 27BF0L9v005096;
	Thu, 11 Aug 2022 15:10:35 GMT
Received: from nam12-mw2-obe.outbound.protection.outlook.com (mail-mw2nam12lp2049.outbound.protection.outlook.com [104.47.66.49])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 3huwqjq5f6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 11 Aug 2022 15:10:35 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=YcWZfoZVYagTaniNWfJk8gAUU0/inhjhRjMn2MKjt3iqHORZ8FYyZhXX///lt32keBSw7FvY870RLpsBP52uPqnfdJenWBcY7GWEzml+3OkDWRAeqgLftzU7Zc4SvSQEfouKHV++849w/LaA37se+BnDjWOQEGPE1NvFJlY6M93A6B1fIVcN7YJzQNOopo2GojPAab3THlPZrBXq4NDNMOhDqOVKMwkM8LRvUGgzxu56h/D0sfUETuHZeFPQu+rLjD3WOG35lPKuxDWLK5X7kPi+P0EOLm7QmIYIw2+06sc+NOXeP4ft4I5drg4NmfatBggzIpj0B/nulns54tGNGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=yPZI13DPAP3gB4/lrzo4c8VA5C0qzZ9dMTuHeJ1EfwI=;
 b=KTkHwwY77v5NzL8IpEnb9EgT/5TZqnexaUn9GdEJ1Z8K28FI6ny/QRAyW2XcuTjz80M3g8/yvsh3zthvw2ijZe3yV6NkPM8Uinn1DLmuoIkKQzpPhfLhe3yWP84iHrj9CCf/9Ujj6VxZxPthzqC6fdJ44xiVr0BnfquF36z1dFjfxQYVHjQpNcjqRuPxDjQEdGmsPBQtVu/3maUBODg7cXsOtKlJtyc9/5G1tKRZTfmst380xDSMcMIOolmP7ZplclEONP6fWyfpJWCWLx9AmnLpNOpLKXjL3DeRBptARfJnO2/cQIFUvYERKvezqE8WTAmq36ug0yup//u2hkDXWg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CO1PR10MB4468.namprd10.prod.outlook.com (2603:10b6:303:6c::24)
 by BN6PR1001MB2322.namprd10.prod.outlook.com (2603:10b6:405:30::30) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5525.11; Thu, 11 Aug
 2022 15:10:30 +0000
Received: from CO1PR10MB4468.namprd10.prod.outlook.com
 ([fe80::c504:bfd6:7940:544f]) by CO1PR10MB4468.namprd10.prod.outlook.com
 ([fe80::c504:bfd6:7940:544f%5]) with mapi id 15.20.5525.011; Thu, 11 Aug 2022
 15:10:30 +0000
Message-ID: <26acafb0-9528-9b29-0b5d-738890853fca@oracle.com>
Date: Fri, 12 Aug 2022 01:10:15 +1000
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0)
 Gecko/20100101 Thunderbird/91.12.0
Subject: Re: [PATCH v2] Introduce sysfs interface to disable kfence for
 selected slabs.
Content-Language: en-US
To: Marco Elver <elver@google.com>, vbabka@suse.cz
Cc: glider@google.com, dvyukov@google.com, cl@linux.com, penberg@kernel.org,
        rientjes@google.com, iamjoonsoo.kim@lge.com, akpm@linux-foundation.org,
        roman.gushchin@linux.dev, 42.hyeyoo@gmail.com,
        linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
        linux-mm@kvack.org
References: <20220811085938.2506536-1-imran.f.khan@oracle.com>
 <d3cd0f34-b30b-9a1d-8715-439ffb818539@suse.cz>
 <CANpmjNMYwxbkOc+LxLfZ--163yfXpQj69oOfEFkSwq7JZurbdA@mail.gmail.com>
 <6b41bb2c-6305-2bf4-1949-84ba08fdbd72@suse.cz>
 <CANpmjNNC3F88_Jr24DuFyubvQR2Huz6i3BGXgDgi5o_Gs0Znmg@mail.gmail.com>
From: Imran Khan <imran.f.khan@oracle.com>
In-Reply-To: <CANpmjNNC3F88_Jr24DuFyubvQR2Huz6i3BGXgDgi5o_Gs0Znmg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: TYCPR01CA0020.jpnprd01.prod.outlook.com (2603:1096:405::32)
 To CO1PR10MB4468.namprd10.prod.outlook.com (2603:10b6:303:6c::24)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: a7027164-195e-4823-538c-08da7baba12d
X-MS-TrafficTypeDiagnostic: BN6PR1001MB2322:EE_
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: jy+cxEB7H5snvz2cnHnum4ka5nDyzjhu1gEA9x8AiOfowVX0CWLKkJxxvXYq7zSRJ8OxQqV4N9HGHY8IWY7uAGc4P9nCd3DeYKboFqMgiuQRsaSnAIBL+KvEzsz2xRVV+QMpsCMvBnh8ftY+ytY0mNZH9D79XMCS9zqsYAh/YRupwzi3y5GXtMwk54xfMGxgnSQ79zdQhgctjt1Ke36esAycqvX8od6jo41daNWDE56Tbc7//8LsTBA4TI80pJUdgfmLRJpMemaz3peSZDiQXOpZNEc1/ez/XdSu3auuexvtDgE7EBJmJfLPxhH2z1ll3/iLSz0voF4ATnlNKXuN6JzMlbZgIJ4xbwC5VYJEpPZeWYyRjmbpCPUNh7m7E5RnWa9pE78kbE2NHliLjuwAeN4XCkImlcXhWBuQVPe509w06XgEdn42uGiZzTtTs7PX8LJGm99KRESY8YH0YnAu09YGE4as4Bp5PBPJRBo3OjQfhZKgk/l58jNBFCOvZeAk59pGZNGml15M7oFg4VHN6mvEZdkMipR9QYCFf3lQvihbzbtKPoeVjwVY/FKvehwtX7PasTIBUpKl41kHgYtw96aF5GSik4KhfuX/YDJt7massH5MlajD5TzcAfvNUgnVwkGnA8sl1QWMBNFF9uEeyvZkzPvwAGmisoryJd+tpm9wBFjy4qRMwwgI/Ws/KL3mBu0um+fYlXIzcA/5apYsm8sUuc1f8W5ixX958cJteS0Yfc2zWOvwtBVpDjrRIfAACSASFLuKa6JKnLNyxHggokY6LoDm1NaK9vByGffg0KvejbTF/1UUJD2eCPOhvTB+mLYJ9fNeFH/aPgYJpraxf8VkYhFW9nSuS8SlyGNzV6U=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CO1PR10MB4468.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(396003)(136003)(376002)(39860400002)(346002)(366004)(478600001)(2906002)(966005)(6486002)(53546011)(8936002)(7416002)(5660300002)(41300700001)(26005)(6512007)(31696002)(6506007)(86362001)(6666004)(38100700002)(83380400001)(2616005)(186003)(8676002)(4326008)(66476007)(66556008)(36756003)(31686004)(66946007)(316002)(45980500001)(43740500002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?VnlNa1RLVkNtR2JRbk04RTNTU1EzbGQ3SWhRTFFDOTY1Wm9qYzc2N2lQWUpQ?=
 =?utf-8?B?ejVibmN6eVFTeGRCQTk3MU1pc1FlV2EycXNWdlNiKzd1OGVXZ1R2d1R6b09x?=
 =?utf-8?B?bEtJSHFKYXkzSW9RM3JoelpjUWZQRXFEK0dlNnhuV2txdU5ENzRmbkFuTWJ4?=
 =?utf-8?B?Z2oyZTFwaEJWQmZ0Vko1QmJBeG84a21XZ0p1SXhRN0NjVjJWa3VGbUV1MUVi?=
 =?utf-8?B?WjBBd0FCQ1RWL1kzUDVtanljSEM1S0tsa0c5Q1B2MHNrZnY1RUMxQmM5dWxV?=
 =?utf-8?B?clh1dWdKZG8vcmQ4UmgyTXQ2dXFoaVVuUjdNNDdrc1AybTZ1UmlhdlZLRlBr?=
 =?utf-8?B?STdjbnNUL2x0YnU1cDR3WE5VamF3ZW5tOWoySGZmay8vUmdzSEtDY3dCcDZk?=
 =?utf-8?B?NW5BTC9BRkEvQXdacFFOL2RYVDVWWkUzczZUVWo1ajUwY05BTDNoTXRwejJT?=
 =?utf-8?B?OERORGRxMXNmU3QvTkttM21WUUFZZFg0RHRFVEc2UFZDMS9XNnJWbURQOENG?=
 =?utf-8?B?b1ZXanpvRlVyMU9qTlRUcHJic3AxYXI2RDVtdlRZN0JiVDhuYXB6TTVMYzJB?=
 =?utf-8?B?T29NbkxobWxCRnoyUVlzWmh4SXFNT2F2SCs1Z0lqQ0dUNE9Qa3VHTXpVc3Ny?=
 =?utf-8?B?d2ovaG5IZXFZU01FNVFicWdPcFdFVWFnZXc2NUIvRDRCRW5TR3l0cUNMYm0x?=
 =?utf-8?B?bldVTnkrTjZSSkF5SC9RUE14a2Uzcy82dnNYL2ZRVkg4bkx6TWhOcDRiS2JH?=
 =?utf-8?B?cnUrRytOSTBLYmNIVS9KV0lmR2s3ak9zcDRweFdrZWFmd28za25LejFNZUhY?=
 =?utf-8?B?N2RrcERsVlBKU1lHbS84QXpNUm40SUloTkhjWFNlRkMrZ3ZUYXpqczYxbjdQ?=
 =?utf-8?B?bjkycGFDRWtma3RWQWRVaEh0czlZb1UyVFZvbWxkTmVkMnYwV2VqSXV1L1Rh?=
 =?utf-8?B?NTdVMGtQQ0hXWTJZMFd0cytDMWtkU1F0R1dFNGNKTktBbWUyakxFa2Q4NUVa?=
 =?utf-8?B?NFlnbGMvQ2I5aDRFRCsvbG1zVG53eXB3U0luQnNwU3RLbGx1aXFncmpicXBm?=
 =?utf-8?B?SjVkcFVteVN3dWh2L0k0S2lFOVdlcmc1SEMydWY3YVVYWFc5Q1daWVowa0hD?=
 =?utf-8?B?dXJxcStUai9HRUo1bXhKcXJhM1JVWmVPLzgxckM1aHlaNi9ZN1NGR0NMMi9k?=
 =?utf-8?B?VEZVTFVoTi84RjdaNE9neDU5Vi9GdHJucHZ5a3ZKRkFqaVlmc2F2enQveFll?=
 =?utf-8?B?cnArZll5bzhtZVo2dEg0Q29mVGI1WTB3WExtVnpoM1UyVWZLWDJpQkIwdmZM?=
 =?utf-8?B?TElMaSt5VllJOUZCRXU4d3dVQmNCNlJabjAvb05QKzU1aWhIWkdRMzdwbkQz?=
 =?utf-8?B?dnBUaW1vM2FXeWw1SGd3RW5CeGQvWU5XMm5kT2hVeUdPS21FOXkySXUwNk85?=
 =?utf-8?B?NmZFOVkyYXVSc0dKa3FoaHBQNmRmc0dSNXRtYmZHOGZicFZNd1RjVks3RCtM?=
 =?utf-8?B?ZnIrcTV2Sm53LzBIczRiSVAwSHZMMXlrTlowNGozeHZSdVYrSmQrMDhYOFBp?=
 =?utf-8?B?Tk40TjkxVTgvcTFnOGFpalR6Y3VCZGNCZTI1VERTd1hBMFlHY1Vpa1A1a2Nq?=
 =?utf-8?B?ZWNDbnl6Y1pFNjI5VkJlSHZzb1NzRWIxbjl1NkVMd2p5cjBKN0plZGFzSlI2?=
 =?utf-8?B?VHFJbGhyR0M5OTBpZzFVK3BjTUlWRCtVNVZydWxVWFh5cno2WGFlTDQxUk5x?=
 =?utf-8?B?OW42RDF4RDZDMUxSdEdHV2lNTFR2TG52WjdoMFRRVHp5OGJzVTM2b3hkN056?=
 =?utf-8?B?dThVd1FWTytnOFVGbnNIZGlKNlIwNzJHeXdxUkxIUHFVNEJUaFk3c1JGcmpx?=
 =?utf-8?B?ZjB2VFVramJ3dWRGTWoyOFdFU242ZXZJSW9DWm9jVmlPNzc1MEpCSVNrazRr?=
 =?utf-8?B?RXpqb0lCZVU3MzdVTWZ1RW9FRk9qWkFNVFE3alFkOWxIZVB1TEk2czlZc0dp?=
 =?utf-8?B?VjZjS3dBNDZJd0hROEZZM0hsVVFnZGFqdDZiV0J6RjV6K2lMZjh2aFFVaWtB?=
 =?utf-8?B?eHpCUk9TQTgwQTNCeUdhZ29zSjV5YU9rZ2MxWHY3SGJ4R0Fhc0pJUFZoZnJh?=
 =?utf-8?Q?daFKRA41a45EZi05W4Ec7f51w?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: =?utf-8?B?U1JCSU9hZ0g4aUV5bndWYU9hZmlXaEJmRjhNc25pZGFyQlluN2VNemZmUUNK?=
 =?utf-8?B?TzhwSE9wa1dacmtHT1BCU2lVMkhJUzhkTkFvVzNOUzczS08zN3hFVjdURHVH?=
 =?utf-8?B?WnpuelB0STJtdEtRL1pJYUJPdGZzZ2U3YStLcWlla3N5czU2TXpRaERmRHp1?=
 =?utf-8?B?M0RHMlo2WW9LVFlvMXhXUWgzWmdUQTdCdHd2QkVQTzgzR1JRTjVHeXJVelEr?=
 =?utf-8?B?eTRXeTBySE92cXhEYnJTWmdWc2xUcjhyVlVRTzEwMXZFSjVKQjVHVUdKNlM3?=
 =?utf-8?B?Y0h3ZE5EOVdpZTIycUNiK2FQS0JOTGZuc3RaZkJYaDZUa001NzJqVUxDUit6?=
 =?utf-8?B?UzZXTm1ocm5STDdEeHVHTW5mRmVwbWtCTEFsSlEraHd1aC8wRWZMWVYxYkRa?=
 =?utf-8?B?eWpZUUp4bXM2Z3dpN1ZJbzV1aTljM2hiNW1GRHdXYTJDUmxXUzEzYkZ0L1Ja?=
 =?utf-8?B?bkYvcXVEcTBibTdEUGx6ajBvWjU0dVJmcnQybkVZcnJQazkrQVhSTm4zRGVq?=
 =?utf-8?B?QW1NdVliWFRMSnEvd2RldkhzaDFOc0MzN01DQy9lc0Q5Y2plTjJXK1gyTi9w?=
 =?utf-8?B?dzJNcHVsbGF5TjVXTjB4Z0RBbzJTZmdnelJnckxzaG1pdjYrcWMxeTRKS2Vj?=
 =?utf-8?B?RGt5S1AyT25jS3FJeGNuZkZZRXNlM0JDZm5YSFErV3lwL1JMZ0dnQ2prNEtR?=
 =?utf-8?B?andwVzNEQ3J6TmFyMHh1MG5iRFo3Q1d2TllhV3JpeFJFblloTlRGanFyTWtD?=
 =?utf-8?B?emo3VW5jNFNSSGVsUGpYSXoyS2hNYTRTTyt1MkUwaXRJWm4rWEZkeFRIc2pv?=
 =?utf-8?B?K3RoRHBCNlh5V2RqS2NJWFM4L0phOHd2UitZdVRyeWFSZFFUR2NGend0RXVD?=
 =?utf-8?B?WGJZb0xvc0JYSmlSZE1NSDVRdUplRDkwb3pwRGhZQ1pqbWZhWkplREhzbTA4?=
 =?utf-8?B?U28yNDNyWTkzOUttTGRmNzNGYVpYR2V6WWxrQ2xZZUxqeWtVcDdlNzB3VytH?=
 =?utf-8?B?U28zS2dqa3NKNktaelVHY1FkYmsrcVE3QVZWQ25WallIVXRySUxWWklaQTE0?=
 =?utf-8?B?QnFISkdwNndIVlFBK3owQnprd1E1eDJjZFRDN1lTNFVKQWd6Sk9NVVFRbkRL?=
 =?utf-8?B?TlVna3FaeWdzUDZscHRFYjduRC9DL09TQit1Q2RKam1xNUQyU01COWZZZkgx?=
 =?utf-8?B?L09NZCtsM3dvNi91bkpNNTB6c0NWUmdHaDA5TWpKLzBsTm9aY05TY3pabCtt?=
 =?utf-8?B?RDdXakhORlFnVGpGdldKNFc1ZVNrb2ZwakFLeGFybzB0L25GSkIwaVVNcDll?=
 =?utf-8?B?SnpQQU5MMWRIQTBVTCt5anU2cnBuRVllQzFUQmRFT0J3UGFNeURod3VPQUhY?=
 =?utf-8?B?cWpkdmF3VGJERDRtZnRKeWdxOFB5RXpycFpxL1NQSHJoRlFxRENYYUhLV3Fl?=
 =?utf-8?B?MzJoYy83Z0dLVHg0Tm45Tjl1L1J2QUtuNHlER2hKU0RZeVBsV2V4d3lEUmIy?=
 =?utf-8?B?ZjFTaGdpV3pOWlVsL3hVTXJUQm92Zll5OExNMkxjS2Y5azlSN3NEVUdLaEd0?=
 =?utf-8?B?Q0ZFazIvUkg1UzB1UTRNYXU5eFVtR29nU2ZqQ2wwREFQUTZuNkk4dmZRbnVB?=
 =?utf-8?B?djJVcCsvSVo2czh5MW5UbmxOZ2FTVm1XdEczN3MzcFpCd1Y3WVIySFhnTTlD?=
 =?utf-8?B?R1FTWkVldHhCVlpaVzUvRG9mN1hWR0VjUVlvNUo3Vk4zSVVwTWU5a25HTUNP?=
 =?utf-8?B?VS9GT21YN2ZKWGpiaHNlZG9kL1k0TlZIVGhGOGxkV0VCcm45dy8zdVIxeDhn?=
 =?utf-8?B?bjUrcTIxWVVqTVNVb0pEODRHeHIrN0lrTjZSaCt3MlBlcVhkeXlxd0dxS2Rw?=
 =?utf-8?B?NXFKYS9wYVRMOGtpRmZFdlZEQnZGb25pa1dpZHh1ejk2emV1Z256OTZXY1JJ?=
 =?utf-8?Q?KNDAMD8X3gs=3D?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a7027164-195e-4823-538c-08da7baba12d
X-MS-Exchange-CrossTenant-AuthSource: CO1PR10MB4468.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Aug 2022 15:10:30.2728
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: wgOnqYasYz0wPHcvTHr6IUok940cLZr4sQM0A9x3N869EcDQ8xeS/o/Gm2+JsL46qn8w3L/Nwbd0llbC6JBR2Q==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BN6PR1001MB2322
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.883,Hydra:6.0.517,FMLib:17.11.122.1
 definitions=2022-08-11_11,2022-08-11_01,2022-06-22_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 phishscore=0
 spamscore=0 bulkscore=0 adultscore=0 malwarescore=0 mlxscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2207270000 definitions=main-2208110051
X-Proofpoint-ORIG-GUID: cRHO22u6pzprGzjtwenQfz3Em_4qzlDQ
X-Proofpoint-GUID: cRHO22u6pzprGzjtwenQfz3Em_4qzlDQ
X-Original-Sender: imran.f.khan@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2022-7-12 header.b=hzLLEcJk;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=WvDFCRRz;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of imran.f.khan@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=imran.f.khan@oracle.com;
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

Hello Marco,

On 11/8/22 11:21 pm, Marco Elver wrote:
> On Thu, 11 Aug 2022 at 12:07, <vbabka@suse.cz> wrote:
> [...]
>>> new flag SLAB_SKIP_KFENCE, it also can serve a dual purpose, where
>>> someone might want to explicitly opt out by default and pass it to
>>> kmem_cache_create() (for whatever reason; not that we'd encourage
>>> that).
>>
>> Right, not be able to do that would be a downside (although it should be
>> possible even with opt-in to add an opt-out cache flag that would just make
>> sure the opt-in flag is not set even if eligible by global defaults).
> 
> True, but I'd avoid all this unnecessary complexity if possible.
> 
>>> I feel that the real use cases for selectively enabling caches for
>>> KFENCE are very narrow, and a design that introduces lots of
>>> complexity elsewhere, just to support this feature cannot be justified
>>> (which is why I suggested the simpler design here back in
>>> https://urldefense.com/v3/__https://lore.kernel.org/lkml/CANpmjNNmD9z7oRqSaP72m90kWL7jYH*cxNAZEGpJP8oLrDV-vw@mail.gmail.com/__;Kw!!ACWV5N9M2RV99hQ!Oh4PBJ1NoN9mEgqGqdaNcWuKtJiC6TS_rIbALuqZadQoo93jpVJaFFmXUpOTuzRUdCwcRJWE6uJ4pe0$ 
>>> )
>>
>> I don't mind strongly either way, just a suggestion to consider.
> 
> While switching the semantics of the flag from opt-out to opt-in is
> just as valid, I'm more comfortable with the opt-out flag: the rest of
> the logic can stay the same, and we're aware of the fact that changing
> cache coverage by KFENCE shouldn't be something that needs to be done
> manually.
> 
> My main point is that opting out or in to only a few select caches
> should be a rarely used feature, and accordingly it should be as
> simple as possible. Honestly, I still don't quite see the point of it,
> and my solution would be to just increase the KFENCE pool, increase
> sample rate, or decrease the "skip covered threshold%". But in the
> case described by Imran, perhaps a running machine is having trouble
> and limiting the caches to be analyzed by KFENCE might be worthwhile
> if a more aggressive configuration doesn't yield anything (and then
> there's of course KASAN, but I recognize it's not always possible to
> switch kernel and run the same workload with it).
> 
> The use case for the proposed change is definitely when an admin or
> kernel dev is starting to debug a problem. KFENCE wasn't designed for
> that (vs. deployment at scale, discovery of bugs). As such I'm having
> a hard time admitting how useful this feature will really be, but
> given the current implementation is simple, having it might actually
> help a few people.
> 
> Imran, just to make sure my assumptions here are right, have you had
> success debugging an issue in this way? Can you elaborate on what
> "certain debugging scenarios" you mean (admin debugging something, or
> a kernel dev, production fleet, or test machine)?
> 

I have not used kfence in this way because as of now we don't have such newer
kernels in production fleet but I can cite a couple of instances where using
slub_debug for few selected slabs helped me in locating the issue on a
production system where KASAN or even full slub_debug were not feasible.
Apologies in advance if I am elaborating more than you asked for :).

In one case a freed struct mutex was being used later on and by that time same
address had been given to a kmalloc-32 object. The issue was appearing more
frequently if one would enforce some cgroup memory limitation resulting in fork
of a task exiting prematurely. From the vmcore we could see that mutex or more
specifically task_struct.futex_exit_mutex was in bad shape and eventually using
slub_debug for kmalloc-32 pointed to issue.

Another case involved a mem_cgroup corruption which was causing system crash but
was giving list corruption warnings beforehand. Since list corruption warnings
were coming from cgroup subsystem, corresponding objects were in doubt.
Enabling slub_debug for kmalloc-4k helped in locating the actual corruption.

Admittedly both of the above issues were result of backporting mistakes but
nonetheless they happened in production systems where very few debugging options
were available.

By "certain debugging scenarios" I meant such cases where some initial data
(from production fleet) like vmcore or kernel debug messages can give some
pointer towards which slab objects could be wrong and then we would use this
feature (along with further tuning like increasing sampling frequency, pool size
if needed/possible) to pinpoint the actual issue. The idea is that limiting
KFENCE to few slabs will increase the probablity of catching the issue even if
we are not able to tweak pool size.

Please let me know if it sounds reasonable or if I missed something from your
query.

Thanks,
-- Imran

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/26acafb0-9528-9b29-0b5d-738890853fca%40oracle.com.
