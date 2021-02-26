Return-Path: <kasan-dev+bncBCX7RK77SEDBBM4Z4GAQMGQEIIDPXKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EB40325B33
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Feb 2021 02:19:49 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id o4sf5237313pjp.3
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 17:19:49 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1614302388; cv=pass;
        d=google.com; s=arc-20160816;
        b=QiAG6Mwd7nh3tc8XWHxR5txwoRJ1HsWRlLs5asTzf5OHnuZV8ITQovmvT6aQpegNlG
         YHoWwYQMvVs6U+ZzZqOvpjAm5tOgZGBFyqfyrZOEHV+xTCwp2ESH05Nqe8AlW4N+HtaJ
         T3NjswIKF6RO9bMU24vuA2nhXdILVNyVI751dxpthA21AnO2mFmdzAKUElKaQ+CwgCa/
         LzFPcfePiUWY+MBK9uA1JQHfAd/L9LX9sba/hJAfYPa7oOZMytyLosckXHMJlbUKpY2R
         52A+t57bPDdnQkUDxgdPpiB02W2xWwbvUXxPCNVEhbFv9/7k0w1b6gVcXcumMwyIAyuo
         MFrQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :content-transfer-encoding:in-reply-to:user-agent:date:message-id
         :organization:references:cc:to:from:subject:sender:dkim-signature;
        bh=otHTweD5queWhCHvhezVCjS3gqQYS3pF0gZVG0Xuq2s=;
        b=vFrXWQ+Z+GYJ/BomPuYCzzFoPcJN22DBTxb8xt/dHHTzhKt9J9A7RAiCy/XJPUXCyP
         1oSb3agUFjCKZ17UvokfIveAFs7SgyqunBT5+8zPR/wkc6eHdMywaK//CMYFR4owb2aY
         C8H6DgV/KCCzD+v7FBLEocANRFuKwgzWhjNZnQ/BUzVURuuo/cYi1erQdSRjWEvaNEOo
         bMvTf+Qi5u/dfzkEu/Jej2k8kWLvss6Vh2iUqu7ibafrdsq4meqmpq3bq+6PUN/FVGtP
         ragI/WIxOsGojaIZwu9yNynDD2xSgGx9KsC0qGMQ87gJfwOOn8W13LLHDd0fETiXwA+q
         vouA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=QkZpA3su;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=zqZTggRc;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:organization:message-id:date
         :user-agent:in-reply-to:content-transfer-encoding:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=otHTweD5queWhCHvhezVCjS3gqQYS3pF0gZVG0Xuq2s=;
        b=h6DLbbAeEVc6Ug6y9H7r8pVWsdBIen8Ld+Ghe6BMkz9FhsG3rECryAtqqC8WHGkiYB
         8Ygnzl7kfmY3zfjgDqbX2iTRFAuDeUIkNiU9Xe0SJLOwruGjwa4wtBGkT1YtM2r8ycJj
         2MpfD0XCfVGXOVoI/nUEINhcAgzGY1TCQyQH1S5VxS/HpY9TH2vwUsX0BJO+Wu7mW8XY
         oKL0PfJ9p/dI7hRtaRAiuYEVACU58KYwzUkj4Kl13pfHCqplDYc7jyJoz7zUEYsxNfYr
         UCfYpU0vc+PfuSmXrU2wFO0YV89O6gJflD4ybHtzjzM1mlw0ovkrVCnwbG8VE9Nauhph
         qeRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references
         :organization:message-id:date:user-agent:in-reply-to
         :content-transfer-encoding:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=otHTweD5queWhCHvhezVCjS3gqQYS3pF0gZVG0Xuq2s=;
        b=clUpfDs9PyzinA7SuDh+hyRJ2croUWQdUbqvjKp4Rqb8ol1iNT8cX8zGb/6DKDsQRn
         In8mcf1fpCurer3Bxdoszyx/f3wQ734JvHvNYyqCRoOyU3M8kgzALMWgXPFmr09jMT80
         OK2aB7aHKhCDEEgO1aePR+XFSL/kyU+nV51riaX8CCQmbuEMm9C0FZg0Wr3qprQ2WK6G
         DeMjQpQlzggIF7+40fmOJsy03JRhIWe/6bw2SdImQU9kl0vb/UJuqNNgM0sOVJifTCvI
         ojgC40kSq1XpCfkp7ye6aG/sfVgPYLH/ALMnyiMbvPmYe0Jit2updxzrdxkSUQM9J1O+
         W3yg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XPmBqdPCCQ5czZJqDbQ5T7k2DLixFd2nP+P4TuQYsJZcKC7mP
	x54aNa+VL/688szyol6MT8E=
X-Google-Smtp-Source: ABdhPJyAK6r39Hj2209fA6k714TG+hHv/exEw/c/MogXZXIhPek/4YsTD7n+KQ4b45Z9tJOzd85law==
X-Received: by 2002:a63:fa05:: with SMTP id y5mr668166pgh.154.1614302387812;
        Thu, 25 Feb 2021 17:19:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:511a:: with SMTP id f26ls2886954pgb.9.gmail; Thu, 25 Feb
 2021 17:19:47 -0800 (PST)
X-Received: by 2002:a05:6a00:158b:b029:1d1:f9c9:84ca with SMTP id u11-20020a056a00158bb02901d1f9c984camr548959pfk.46.1614302386905;
        Thu, 25 Feb 2021 17:19:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614302386; cv=pass;
        d=google.com; s=arc-20160816;
        b=FVaJup/2Qls89epfOiRfin3v6TbCotX/xR9nMLycrT692s6babUbpuypUUOrVwK7iD
         Ut6z/gpfN/u1PETnd6jAtqumwwcaR8A3WOQFrelZzKjg+2gscOuD/if6EzRE70RSQU29
         nZjlv4skjZCdX1UONGkj1lHNuzNlAv85jV3c68bxOVmFPvWqBDi1xc8PhmhgNCtTJyGS
         tFrKNi1j1O0+WjXuFG6+CdF7ZhA0YUbFL+o1i03ilcIzZ3sb084jPiK6J65tHd6KbPUc
         RV6QAH9XcbJQn+Ha1iGYT1GgWFsmXjgZEVJapyillJDDT/vp18ggmRWI8Hdn8uoWsgw7
         B1pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:content-transfer-encoding:in-reply-to
         :user-agent:date:message-id:organization:references:cc:to:from
         :subject:dkim-signature:dkim-signature;
        bh=Mz6hGcrX5xJivaMDtBIIyfPQPRBG6AMkc8dbN5v9mtk=;
        b=YNiJKYre6HpiOUcCDyqZQWBJ5/IOv7M3LC9uV//XVaIRwG8Eu2tOece4uv3+pTqW26
         Anff3BGhk2opMIpTI8bzWQvONGju2bagInbAdXDWZG1buBdKUDmZIKEohjP1Pgnp+iDd
         wfySBunhqUuwIWo64RTFrsJ8qQjK6+NM/b9Mv0sMpYpfroDKH4cNPUHnEE2Sncq/uYYm
         CtGny8+x8jwTd8knfW9y/vk29h7y4DlEygzQhc0E36kjYEcGfTu8bH7xdFxu5G7XcSOU
         mu0RM1vpw/OahwIDZe92pK1gUkt/s4R0dhq+WoqZuxHexqSBB5WIQQmZBty6J8kSW9dU
         Eszw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=QkZpA3su;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=zqZTggRc;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2130.oracle.com (userp2130.oracle.com. [156.151.31.86])
        by gmr-mx.google.com with ESMTPS id a2si17449pjd.2.2021.02.25.17.19.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Feb 2021 17:19:46 -0800 (PST)
Received-SPF: pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.86 as permitted sender) client-ip=156.151.31.86;
Received: from pps.filterd (userp2130.oracle.com [127.0.0.1])
	by userp2130.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11Q1JR4t133938;
	Fri, 26 Feb 2021 01:19:27 GMT
Received: from aserp3020.oracle.com (aserp3020.oracle.com [141.146.126.70])
	by userp2130.oracle.com with ESMTP id 36tsur8f41-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 26 Feb 2021 01:19:27 +0000
Received: from pps.filterd (aserp3020.oracle.com [127.0.0.1])
	by aserp3020.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11Q1EjAX011242;
	Fri, 26 Feb 2021 01:19:26 GMT
Received: from nam10-mw2-obe.outbound.protection.outlook.com (mail-mw2nam10lp2104.outbound.protection.outlook.com [104.47.55.104])
	by aserp3020.oracle.com with ESMTP id 36ucb2sq0h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 26 Feb 2021 01:19:26 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=iUDmSOch1IGoMwKFEcid9pLetfaDk9vdrqNS59B7o4IfodsvGHVBpXvS2G9YgjprHX4Zcjt4sFPSElo+BRHayyQCWDn/1FDkmdTj5BJr86R8cxot4Po2FvZ1vI9x2Wb8rZstzca2i1oqskI5V4VWxglcWgiN5msjE77qSuQ2lx0sVafNWM08pkaMpPyZg6JyDFezi4IsXlIFTFrjlPIrdJ8r8R/jBgmC/8HXHp3/AkvrlDY/IJQG9VxdjJ1SQnGNz3fHGk618J2XJlXfIpeWX7wrHJ0AqDjeQ0ygOOS6DRMjzEkKj9aajuNCYmTkX48OVYM7Va05OpllG2LZvAa8Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=Mz6hGcrX5xJivaMDtBIIyfPQPRBG6AMkc8dbN5v9mtk=;
 b=D8rGshVdWJrKMH1Bgb2qbzUcUpaji+nC498UTaGr62G8d6FyZUThQeiHG3A/z44MOMEhHQsl3a6et0LptUkuycEy0C0iDIMuPFmkKrcoHSTvLQm13lL3dpZf+r4Iy7M5Vi0Ga/lKYKDy8I2h5RIE5+33zZB+22N1+IAvHWoQZ0O3tF1NCXnRu7YcXEZZRMwZxKaGPr9grV1niJl+WmmY0XmLDuZx5kMCSoJohl87EOmtPVCFRkSFFdgLLErqMSrj8eIm5K5r0VX2IUo/3m8REyKYtTfM1bI/r2OlYhHZMeNQ8K1UTbipZZ40S7va33tiyVBuCRhuFWM822uR8zJ3jg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM6PR10MB3851.namprd10.prod.outlook.com (2603:10b6:5:1fb::17)
 by DM6PR10MB3116.namprd10.prod.outlook.com (2603:10b6:5:1ab::24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3868.32; Fri, 26 Feb
 2021 01:19:23 +0000
Received: from DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da]) by DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da%3]) with mapi id 15.20.3868.034; Fri, 26 Feb 2021
 01:19:23 +0000
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
From: George Kennedy <george.kennedy@oracle.com>
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
References: <20210223200914.GH1741768@linux.ibm.com>
 <af06267d-00cd-d4e0-1985-b06ce7c993a3@oracle.com>
 <20210223213237.GI1741768@linux.ibm.com>
 <450a9895-a2b4-d11b-97ca-1bd33d5308d4@oracle.com>
 <20210224103754.GA1854360@linux.ibm.com>
 <9b7251d1-7b90-db4f-fa5e-80165e1cbb4b@oracle.com>
 <20210225085300.GB1854360@linux.ibm.com>
 <9973d0e2-e28b-3f8a-5f5d-9d142080d141@oracle.com>
 <20210225145700.GC1854360@linux.ibm.com>
 <bb444ddb-d60d-114f-c2fe-64e5fb34102d@oracle.com>
 <20210225160706.GD1854360@linux.ibm.com>
 <6000e7fd-bf8b-b9b0-066d-23661da8a51d@oracle.com>
Organization: Oracle Corporation
Message-ID: <dc5e007c-9223-b03b-1c58-28d2712ec352@oracle.com>
Date: Thu, 25 Feb 2021 20:19:18 -0500
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
In-Reply-To: <6000e7fd-bf8b-b9b0-066d-23661da8a51d@oracle.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [108.20.187.119]
X-ClientProxiedBy: BY5PR13CA0022.namprd13.prod.outlook.com
 (2603:10b6:a03:180::35) To DM6PR10MB3851.namprd10.prod.outlook.com
 (2603:10b6:5:1fb::17)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from [192.168.1.246] (108.20.187.119) by BY5PR13CA0022.namprd13.prod.outlook.com (2603:10b6:a03:180::35) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3912.9 via Frontend Transport; Fri, 26 Feb 2021 01:19:20 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 678ef2f2-8871-47f8-00a0-08d8d9f48cea
X-MS-TrafficTypeDiagnostic: DM6PR10MB3116:
X-MS-Exchange-Transport-Forked: True
X-Microsoft-Antispam-PRVS: <DM6PR10MB3116AE3CFC6A4562A4ACB578E69D9@DM6PR10MB3116.namprd10.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:2089;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: w0ZL6EM5Q7RxspN5TF6QKFcMWM3XrzDGemAqAcdcCGQ848BGqMhjda8m7ogK9zFrbfRknP3J+2zpbI74ERWKeEcnjt3H4lwbVI3lTYyk2lBxHy1iGE4UfN3BsNT8tooL0xwc1X6ppsbqjpoQ2ro5rzFY0wbhuxJTfHM19rQvMGuuDqNkKEX8DvPzOKmOpsCAe1qxOdB/KRXR/IBvgXapmqrVaP1ZmXv87D2RVYh9Pm8bNy3wVdG/HQcse+zQPRSWDmZSwE1JN2SC6XSykkZw5bEryzfgz9O0MuJvizNiaDyCh9ACTxUWwsqTa4mLYdxwCQtqDka0cTzC/fB+/X/MtNiRopXoqY9iMhKUG8Iho0ffPWvn4B7CdXM9LNHmUeewRpIWdhldPHltiSEL9AUXji+2tYFWn9XDNkuQla6orptbthpTQwA5TzIXnJOmf3NSB3GLP9j+ZKgFVOKYGX499PPsN2FVZRIJT8TMvG+04Fu5LvDhjBeoQ90NRpkMlDh9jVbFwtzqsPAVZDGHk9yhVnbIsmhyk5u/niOviyG1IigCwBIGwIt2MY7CJgkpxafrfGM1cSlr/xz+/Z2iNZYGqZQ9q+hqHogkXAUN3JJtLyBuaY4jry2Lns03IHrFUk2C
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR10MB3851.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(346002)(136003)(366004)(396003)(376002)(39860400002)(30864003)(6486002)(83380400001)(478600001)(31686004)(54906003)(316002)(44832011)(31696002)(36756003)(7416002)(6916009)(86362001)(53546011)(16576012)(66556008)(5660300002)(956004)(2906002)(16526019)(2616005)(107886003)(26005)(36916002)(8676002)(66476007)(8936002)(186003)(66946007)(4326008)(21314003)(45980500001)(43740500002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?utf-8?B?Wm1nTU9FT0g0WE9sVFozTUdDaERMZk1UZEpZSHNQQkgvTlpVWWhJeE44cVVY?=
 =?utf-8?B?bmIzakxidDBYcFB0dkV6OWp2K0prMmtJVVNFS3RFeElnYUFkSXpSdnZMVnpq?=
 =?utf-8?B?Rzg5Z1FUSXdRVFhISmRzZDBGYW54L21SQTY1UUhDdXp6OFcwc0xIaERWT2lw?=
 =?utf-8?B?V09qcEY4V3Bzci9BVDBPcXBBOERZb3haTE5PWGJ5UVE5TkFFb2s3VXhWQ3Nl?=
 =?utf-8?B?cE1YcEoyWVBvZU1xVWt5RFJpZ0Q5OWtUR3Y3Ynpyc2tBeGNmRklObTh2TGhv?=
 =?utf-8?B?T3UyWkV1eThYbHhPUm4zWUZUaThYUlFWaU5YYUh4N1FJVFZwNm9OZGZTM05M?=
 =?utf-8?B?Rzd5amFoT2x1QW8xaG1KVGIrVGp5aVVrN1liMVpNb0lFZVNOSVh3c1pUaEJU?=
 =?utf-8?B?bUJFU25qQld2dFdMSlFJOGk0Y1lHc1lxdkptVmJqOHB6OE96R25YdE5wUXBM?=
 =?utf-8?B?dnoyREQzcStwWWRsWVRjdXl4NXpFanVzSUFmMFJFeWFCckdGNnB2UlNySVRP?=
 =?utf-8?B?aGJ1UTZCL1dwRGtvRHY3Vk9tNE1CcnV6RngyQzR6b1VZamdCVWxPZ3FsUVF0?=
 =?utf-8?B?MXJSalczVnYraGJ1bXl0QWVKakwvT0pEcnJOSDBjMmxtbHFDYlVxRndIVU01?=
 =?utf-8?B?dmRJZWg1ek43NUtpVUQ1a09wd0pTdUpQZ0l5ZkNpMVJENVJIVUgvejJLV3lo?=
 =?utf-8?B?QXRCUFZUNGRJSHY5M0lyL0pzY1ZiWHVPSEhDbG51OTZRbTZhQWNrRVVVMVlq?=
 =?utf-8?B?eDRVanl6c3A1ZTFpMFE0UTJrdmcrMVAyVDN1MTlQRUtzYklBb2xlR3dLaXhY?=
 =?utf-8?B?N1RHSS9BVmZYUmJIV0ltay9oYmR0Wi9oQWNmVS91Z0JSNDI3NDRLc1Y5TEs4?=
 =?utf-8?B?bU5FQ0FZQW0wMFJLMkdaK3F0NklraWtvWGlhcDR4WkdwZ0JZUkFkTE5kdHFP?=
 =?utf-8?B?bHgxaTZGUk1nUU04R0l4dkRrSVh0N0d6TWUraFdVS0FaKzV3Wjh6K3FuWlJt?=
 =?utf-8?B?Q21tNFA1cGVLdld6UjZNazVwNy9SaEtCUEtXSEpNeGlMdisyUDhMcmNWMUpJ?=
 =?utf-8?B?VFhzWkFZeFVjakZ4Y05LcWx3SnZxb2JhVnZTeFZCYkhXOHI1dWJsZDFvSk8w?=
 =?utf-8?B?cWNEOGFjRVFFV2JJbXFJL3YwUStZY2tDYTBlVGVrRktHQXRQdHRwQ1lyc0d3?=
 =?utf-8?B?NDBoL1dEcnJ0Vjg2VDd5NHJrUGhrTjdMekQ5bVc0MmFEVjVvdE8rK1FWMkhN?=
 =?utf-8?B?Tlh3NGxvVzB6NjczNnlSbmVjeDBDcHBPSlJzQWRySlpMK05jU2NXZjJibEhS?=
 =?utf-8?B?TnJhamlaTTBiUnY0cGFlWjdJZnYvYkcvK2pPYVE2cDQxLzJ0TmN3ZGx3c3Z3?=
 =?utf-8?B?dGxDVjZBV1NrNkU3azBwOW1wTFQveCt3d3ZmTS9odjZKSWdLY1pQVUhNTTRr?=
 =?utf-8?B?OUdtWVRxblQrc2JnOEpacytDMStNZ1lxb1dSNnJPTGtqR1dtQnIvMmRVTFla?=
 =?utf-8?B?S2xaWElFQXZBMWIvMnlnL1FaTUZiR0l6elVMNFNUdWpYeEZCcnZ5NEVMVk1v?=
 =?utf-8?B?OHRPVk8xNUEvVHRoSW9PUTZjZGxjcGh2OWc5TlVWTGU3ZGFuU2NsdjN0bk1i?=
 =?utf-8?B?Umw0K01NNDhWWXFsTDdNN1ZxNkY3SnAwZzYzQTMxVUkwUXk4RmpnMDdTTGZr?=
 =?utf-8?B?cGFZNUt3c0NuZGVaSFVvVTE1SUF1SzNKeFVSSHRPVFV3Y2NMWjNNdmxBUnFo?=
 =?utf-8?Q?+lUgeHWEGwg5leZ4FnfubjMumYiGgiR56pRul+y?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 678ef2f2-8871-47f8-00a0-08d8d9f48cea
X-MS-Exchange-CrossTenant-AuthSource: DM6PR10MB3851.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 26 Feb 2021 01:19:23.6236
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: jXckyj3gMOhq3di/2bzsIH2M8AP5+C6FJahZ35YVYP7Se3tYXJrC6+hgq3+2Ebt5cbAVmK/BCRk+jGfnjyTdwHlK6KrFK5fAvJCucWGgUt8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR10MB3116
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9906 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 suspectscore=0
 malwarescore=0 mlxlogscore=999 adultscore=0 bulkscore=0 mlxscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102260006
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9906 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 spamscore=0
 priorityscore=1501 impostorscore=0 bulkscore=0 mlxscore=0 malwarescore=0
 clxscore=1015 phishscore=0 mlxlogscore=999 lowpriorityscore=0 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2102260007
X-Original-Sender: george.kennedy@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=QkZpA3su;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=zqZTggRc;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates
 156.151.31.86 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
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



On 2/25/2021 12:33 PM, George Kennedy wrote:
>
>
> On 2/25/2021 11:07 AM, Mike Rapoport wrote:
>> On Thu, Feb 25, 2021 at 10:22:44AM -0500, George Kennedy wrote:
>>>>>>> On 2/24/2021 5:37 AM, Mike Rapoport wrote:
>>> Applied just your latest patch, but same failure.
>>>
>>> I thought there was an earlier comment (which I can't find now) that=20
>>> stated
>>> that memblock_reserve() wouldn't reserve the page, which is what's=20
>>> needed
>>> here.
>> Actually, I think that memblock_reserve() should be just fine, but it=20
>> seems
>> I'm missing something in address calculation each time.
>>
>> What would happen if you stuck
>>
>> =C2=A0=C2=A0=C2=A0=C2=A0memblock_reserve(0xbe453000, PAGE_SIZE);
>>
>> say, at the beginning of find_ibft_region()?
>
> Good news Mike!
>
> The above hack in yesterday's last patch works - 10 successful=20
> reboots. See: "BE453" below for the hack.
>
> I'll modify the patch to use "table_desc->address" instead, which is=20
> the physical address of the table.
>
> diff --git a/arch/x86/kernel/acpi/boot.c b/arch/x86/kernel/acpi/boot.c
> index 7bdc023..c118dd5 100644
> --- a/arch/x86/kernel/acpi/boot.c
> +++ b/arch/x86/kernel/acpi/boot.c
> @@ -1551,6 +1551,7 @@ void __init acpi_boot_table_init(void)
> =C2=A0=C2=A0=C2=A0=C2=A0 if (acpi_disabled)
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;
>
> +#if 0
> =C2=A0=C2=A0=C2=A0=C2=A0 /*
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0* Initialize the ACPI boot-time table pars=
er.
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0*/
> @@ -1558,6 +1559,7 @@ void __init acpi_boot_table_init(void)
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 disable_acpi();
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;
> =C2=A0=C2=A0=C2=A0=C2=A0 }
> +#endif
>
> =C2=A0=C2=A0=C2=A0=C2=A0 acpi_table_parse(ACPI_SIG_BOOT, acpi_parse_sbf);
>
> diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
> index 740f3bdb..b045ab2 100644
> --- a/arch/x86/kernel/setup.c
> +++ b/arch/x86/kernel/setup.c
> @@ -571,16 +571,6 @@ void __init reserve_standard_io_resources(void)
>
> =C2=A0}
>
> -static __init void reserve_ibft_region(void)
> -{
> -=C2=A0=C2=A0=C2=A0 unsigned long addr, size =3D 0;
> -
> -=C2=A0=C2=A0=C2=A0 addr =3D find_ibft_region(&size);
> -
> -=C2=A0=C2=A0=C2=A0 if (size)
> -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 memblock_reserve(addr, size);
> -}
> -
> =C2=A0static bool __init snb_gfx_workaround_needed(void)
> =C2=A0{
> =C2=A0#ifdef CONFIG_PCI
> @@ -1033,6 +1023,12 @@ void __init setup_arch(char **cmdline_p)
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0*/
> =C2=A0=C2=A0=C2=A0=C2=A0 find_smp_config();
>
> +=C2=A0=C2=A0=C2=A0 /*
> +=C2=A0=C2=A0=C2=A0 =C2=A0* Initialize the ACPI boot-time table parser.
> +=C2=A0=C2=A0=C2=A0 =C2=A0*/
> +=C2=A0=C2=A0=C2=A0 if (acpi_table_init())
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 disable_acpi();
> +
> =C2=A0=C2=A0=C2=A0=C2=A0 reserve_ibft_region();
>
> =C2=A0=C2=A0=C2=A0=C2=A0 early_alloc_pgt_buf();
> diff --git a/drivers/firmware/iscsi_ibft_find.c=20
> b/drivers/firmware/iscsi_ibft_find.c
> index 64bb945..95fc1a6 100644
> --- a/drivers/firmware/iscsi_ibft_find.c
> +++ b/drivers/firmware/iscsi_ibft_find.c
> @@ -47,7 +47,25 @@
> =C2=A0#define VGA_MEM 0xA0000 /* VGA buffer */
> =C2=A0#define VGA_SIZE 0x20000 /* 128kB */
>
> -static int __init find_ibft_in_mem(void)
> +static void __init *acpi_find_ibft_region(void)
> +{
> +=C2=A0=C2=A0=C2=A0 int i;
> +=C2=A0=C2=A0=C2=A0 struct acpi_table_header *table =3D NULL;
> +=C2=A0=C2=A0=C2=A0 acpi_status status;
> +
> +=C2=A0=C2=A0=C2=A0 if (acpi_disabled)
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return NULL;
> +
> +=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < ARRAY_SIZE(ibft_signs) && !ibft_add=
r; i++) {
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 status =3D acpi_get_table(ibft_sig=
ns[i].sign, 0, &table);
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 if (ACPI_SUCCESS(status))
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return table;
> +=C2=A0=C2=A0=C2=A0 }
> +
> +=C2=A0=C2=A0=C2=A0 return NULL;
> +}
> +
> +static void __init *find_ibft_in_mem(void)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0 unsigned long pos;
> =C2=A0=C2=A0=C2=A0=C2=A0 unsigned int len =3D 0;
> @@ -70,35 +88,52 @@ static int __init find_ibft_in_mem(void)
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 /* if the length of the table extends past 1M,
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 =C2=A0* the table cannot be valid. */
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 if (pos + len <=3D (IBFT_END-1)) {
> -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=
=A0 =C2=A0=C2=A0=C2=A0 ibft_addr =3D (struct acpi_table_ibft *)virt;
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 =C2=A0=C2=A0=C2=A0 pr_info("iBFT found at 0x%lx.\n", pos);
> -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=
=A0 =C2=A0=C2=A0=C2=A0 goto done;
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=
=A0 =C2=A0=C2=A0=C2=A0 return virt;
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=
=A0=C2=A0 }
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 }
> =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 }
> =C2=A0=C2=A0=C2=A0=C2=A0 }
> -done:
> -=C2=A0=C2=A0=C2=A0 return len;
> +
> +=C2=A0=C2=A0=C2=A0 return NULL;
> =C2=A0}
> +
> +static void __init *find_ibft(void)
> +{
> +=C2=A0=C2=A0=C2=A0 /* iBFT 1.03 section 1.4.3.1 mandates that UEFI machi=
nes will
> +=C2=A0=C2=A0=C2=A0 =C2=A0* only use ACPI for this */
> +=C2=A0=C2=A0=C2=A0 if (!efi_enabled(EFI_BOOT))
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return find_ibft_in_mem();
> +=C2=A0=C2=A0=C2=A0 else
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return acpi_find_ibft_region();
> +}
> +
> =C2=A0/*
> =C2=A0 * Routine used to find the iSCSI Boot Format Table. The logical
> =C2=A0 * kernel address is set in the ibft_addr global variable.
> =C2=A0 */
> -unsigned long __init find_ibft_region(unsigned long *sizep)
> +void __init reserve_ibft_region(void)
> =C2=A0{
> -=C2=A0=C2=A0=C2=A0 ibft_addr =3D NULL;
> +=C2=A0=C2=A0=C2=A0 struct acpi_table_ibft *table;
> +=C2=A0=C2=A0=C2=A0 unsigned long size;
>
> -=C2=A0=C2=A0=C2=A0 /* iBFT 1.03 section 1.4.3.1 mandates that UEFI machi=
nes will
> -=C2=A0=C2=A0=C2=A0 =C2=A0* only use ACPI for this */
> +=C2=A0=C2=A0=C2=A0 table =3D find_ibft();
> +=C2=A0=C2=A0=C2=A0 if (!table)
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;
>
> -=C2=A0=C2=A0=C2=A0 if (!efi_enabled(EFI_BOOT))
> -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 find_ibft_in_mem();
> -
> -=C2=A0=C2=A0=C2=A0 if (ibft_addr) {
> -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 *sizep =3D PAGE_ALIGN(ibft_addr->h=
eader.length);
> -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return (u64)virt_to_phys(ibft_addr=
);
> -=C2=A0=C2=A0=C2=A0 }
> +=C2=A0=C2=A0=C2=A0 size =3D PAGE_ALIGN(table->header.length);
> +#if 0
> +printk(KERN_ERR "XXX reserve_ibft_region: table=3D%llx,=20
> virt_to_phys(table)=3D%llx, size=3D%lx\n",
> +=C2=A0=C2=A0=C2=A0 (u64)table, virt_to_phys(table), size);
> +=C2=A0=C2=A0=C2=A0 memblock_reserve(virt_to_phys(table), size);
> +#else
> +printk(KERN_ERR "XXX reserve_ibft_region: table=3D%llx,=20
> 0x00000000BE453000, size=3D%lx\n",
> +=C2=A0=C2=A0=C2=A0 (u64)table, size);
> +=C2=A0=C2=A0=C2=A0 memblock_reserve(0x00000000BE453000, size);
> +#endif
>
> -=C2=A0=C2=A0=C2=A0 *sizep =3D 0;
> -=C2=A0=C2=A0=C2=A0 return 0;
> +=C2=A0=C2=A0=C2=A0 if (efi_enabled(EFI_BOOT))
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 acpi_put_table(&table->header);
> +=C2=A0=C2=A0=C2=A0 else
> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 ibft_addr =3D table;
> =C2=A0}
> diff --git a/include/linux/iscsi_ibft.h b/include/linux/iscsi_ibft.h
> index b7b45ca..da813c8 100644
> --- a/include/linux/iscsi_ibft.h
> +++ b/include/linux/iscsi_ibft.h
> @@ -26,13 +26,9 @@
> =C2=A0 * mapped address is set in the ibft_addr variable.
> =C2=A0 */
> =C2=A0#ifdef CONFIG_ISCSI_IBFT_FIND
> -unsigned long find_ibft_region(unsigned long *sizep);
> +void reserve_ibft_region(void);
> =C2=A0#else
> -static inline unsigned long find_ibft_region(unsigned long *sizep)
> -{
> -=C2=A0=C2=A0=C2=A0 *sizep =3D 0;
> -=C2=A0=C2=A0=C2=A0 return 0;
> -}
> +static inline void reserve_ibft_region(void) {}
> =C2=A0#endif
>
> =C2=A0#endif /* ISCSI_IBFT_H */

Mike,

To get rid of the 0x00000000BE453000 hardcoding, I added the following=20
patch to your above patch to get the iBFT table "address" to use with=20
memblock_reserve():

diff --git a/drivers/acpi/acpica/tbfind.c b/drivers/acpi/acpica/tbfind.c
index 56d81e4..4bc7bf3 100644
--- a/drivers/acpi/acpica/tbfind.c
+++ b/drivers/acpi/acpica/tbfind.c
@@ -120,3 +120,34 @@
 =C2=A0=C2=A0=C2=A0=C2=A0 (void)acpi_ut_release_mutex(ACPI_MTX_TABLES);
 =C2=A0=C2=A0=C2=A0=C2=A0 return_ACPI_STATUS(status);
 =C2=A0}
+
+acpi_physical_address
+acpi_tb_find_table_address(char *signature)
+{
+=C2=A0=C2=A0=C2=A0 acpi_physical_address address =3D 0;
+=C2=A0=C2=A0=C2=A0 struct acpi_table_desc *table_desc;
+=C2=A0=C2=A0=C2=A0 int i;
+
+=C2=A0=C2=A0=C2=A0 ACPI_FUNCTION_TRACE(tb_find_table_address);
+
+printk(KERN_ERR "XXX acpi_tb_find_table_address: signature=3D%s\n",=20
signature);
+
+=C2=A0=C2=A0=C2=A0 (void)acpi_ut_acquire_mutex(ACPI_MTX_TABLES);
+=C2=A0=C2=A0=C2=A0 for (i =3D 0; i < acpi_gbl_root_table_list.current_tabl=
e_count; ++i) {
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 if (memcmp(&(acpi_gbl_root_table_lis=
t.tables[i].signature),
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0 sign=
ature, ACPI_NAMESEG_SIZE)) {
+
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 /* Not the reques=
ted table */
+
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 continue;
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 }
+
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 /* Table with matching signature has=
 been found */
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 table_desc =3D &acpi_gbl_root_table_=
list.tables[i];
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 address =3D table_desc->address;
+=C2=A0=C2=A0=C2=A0 }
+
+=C2=A0=C2=A0=C2=A0 (void)acpi_ut_release_mutex(ACPI_MTX_TABLES);
+printk(KERN_ERR "XXX acpi_tb_find_table_address(EXIT): address=3D%llx\n",=
=20
address);
+=C2=A0=C2=A0=C2=A0 return address;
+}
diff --git a/drivers/firmware/iscsi_ibft_find.c=20
b/drivers/firmware/iscsi_ibft_find.c
index 95fc1a6..0de70b4 100644
--- a/drivers/firmware/iscsi_ibft_find.c
+++ b/drivers/firmware/iscsi_ibft_find.c
@@ -28,6 +28,8 @@

 =C2=A0#include <asm/mmzone.h>

+extern acpi_physical_address acpi_tb_find_table_address(char *signature);
+
 =C2=A0/*
 =C2=A0 * Physical location of iSCSI Boot Format Table.
 =C2=A0 */
@@ -116,24 +118,32 @@ void __init reserve_ibft_region(void)
 =C2=A0{
 =C2=A0=C2=A0=C2=A0=C2=A0 struct acpi_table_ibft *table;
 =C2=A0=C2=A0=C2=A0=C2=A0 unsigned long size;
+=C2=A0=C2=A0=C2=A0 acpi_physical_address address;

 =C2=A0=C2=A0=C2=A0=C2=A0 table =3D find_ibft();
 =C2=A0=C2=A0=C2=A0=C2=A0 if (!table)
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return;

 =C2=A0=C2=A0=C2=A0=C2=A0 size =3D PAGE_ALIGN(table->header.length);
+=C2=A0=C2=A0=C2=A0 address =3D acpi_tb_find_table_address(table->header.si=
gnature);
 =C2=A0#if 0
 =C2=A0printk(KERN_ERR "XXX reserve_ibft_region: table=3D%llx,=20
virt_to_phys(table)=3D%llx, size=3D%lx\n",
 =C2=A0=C2=A0=C2=A0=C2=A0 (u64)table, virt_to_phys(table), size);
 =C2=A0=C2=A0=C2=A0=C2=A0 memblock_reserve(virt_to_phys(table), size);
 =C2=A0#else
-printk(KERN_ERR "XXX reserve_ibft_region: table=3D%llx,=20
0x00000000BE453000, size=3D%lx\n",
-=C2=A0=C2=A0=C2=A0 (u64)table, size);
-=C2=A0=C2=A0=C2=A0 memblock_reserve(0x00000000BE453000, size);
+printk(KERN_ERR "XXX reserve_ibft_region: table=3D%llx, address=3D%llx,=20
size=3D%lx\n",
+=C2=A0=C2=A0=C2=A0 (u64)table, address, size);
+=C2=A0=C2=A0=C2=A0 if (address)
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 memblock_reserve(address, size);
+=C2=A0=C2=A0=C2=A0 else
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 printk(KERN_ERR "%s: Can't find tabl=
e address\n", __func__);
 =C2=A0#endif

-=C2=A0=C2=A0=C2=A0 if (efi_enabled(EFI_BOOT))
+=C2=A0=C2=A0=C2=A0 if (efi_enabled(EFI_BOOT)) {
+printk(KERN_ERR "XXX reserve_ibft_region: calling=20
acpi_put_table(%llx)\n", (u64)&table->header);
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 acpi_put_table(&table->header)=
;
-=C2=A0=C2=A0=C2=A0 else
+=C2=A0=C2=A0=C2=A0 } else {
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 ibft_addr =3D table;
+printk(KERN_ERR "XXX reserve_ibft_region: ibft_addr=3D%llx\n",=20
(u64)ibft_addr);
+=C2=A0=C2=A0=C2=A0 }
 =C2=A0}

Debug from the above:
[=C2=A0=C2=A0=C2=A0 0.050646] ACPI: Early table checksum verification disab=
led
[=C2=A0=C2=A0=C2=A0 0.051778] ACPI: RSDP 0x00000000BFBFA014 000024 (v02 BOC=
HS )
[=C2=A0=C2=A0=C2=A0 0.052922] ACPI: XSDT 0x00000000BFBF90E8 00004C (v01 BOC=
HS BXPCFACP=20
00000001=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
[=C2=A0=C2=A0=C2=A0 0.054623] ACPI: FACP 0x00000000BFBF5000 000074 (v01 BOC=
HS BXPCFACP=20
00000001 BXPC 00000001)
[=C2=A0=C2=A0=C2=A0 0.056326] ACPI: DSDT 0x00000000BFBF6000 00238D (v01 BOC=
HS BXPCDSDT=20
00000001 BXPC 00000001)
[=C2=A0=C2=A0=C2=A0 0.058016] ACPI: FACS 0x00000000BFBFD000 000040
[=C2=A0=C2=A0=C2=A0 0.058940] ACPI: APIC 0x00000000BFBF4000 000090 (v01 BOC=
HS BXPCAPIC=20
00000001 BXPC 00000001)
[=C2=A0=C2=A0=C2=A0 0.060627] ACPI: HPET 0x00000000BFBF3000 000038 (v01 BOC=
HS BXPCHPET=20
00000001 BXPC 00000001)
[=C2=A0=C2=A0=C2=A0 0.062304] ACPI: BGRT 0x00000000BE49B000 000038 (v01 INT=
EL EDK2=C2=A0=C2=A0=C2=A0=C2=A0=20
00000002=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
[=C2=A0=C2=A0=C2=A0 0.063987] ACPI: iBFT 0x00000000BE453000 000800 (v01 BOC=
HS BXPCFACP=20
00000000=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 00000000)
[=C2=A0=C2=A0=C2=A0 0.065683] XXX acpi_tb_find_table_address: signature=3Di=
BFT
[=C2=A0=C2=A0=C2=A0 0.066754] XXX acpi_tb_find_table_address(EXIT): address=
=3Dbe453000
[=C2=A0=C2=A0=C2=A0 0.067959] XXX reserve_ibft_region: table=3Dffffffffff24=
0000,=20
address=3Dbe453000, size=3D1000
[=C2=A0=C2=A0=C2=A0 0.069534] XXX reserve_ibft_region: calling=20
acpi_put_table(ffffffffff240000)

Not sure if it's the right thing to do, but added=20
"acpi_tb_find_table_address()" to return the physical address of a table=20
to use with memblock_reserve().

virt_to_phys(table) does not seem to return the physical address for the=20
iBFT table (it would be nice if struct acpi_table_header also had a=20
"address" element for the physical address of the table).

Ran 10 successful boots with the above without failure.

George
>
>
> Debug from the above:
>
> [=C2=A0=C2=A0=C2=A0 0.020293] last_pfn =3D 0xbfedc max_arch_pfn =3D 0x400=
000000
> [=C2=A0=C2=A0=C2=A0 0.050778] ACPI: Early table checksum verification dis=
abled
> [=C2=A0=C2=A0=C2=A0 0.056475] ACPI: RSDP 0x00000000BFBFA014 000024 (v02 B=
OCHS )
> [=C2=A0=C2=A0=C2=A0 0.057628] ACPI: XSDT 0x00000000BFBF90E8 00004C (v01 B=
OCHS=20
> BXPCFACP 00000001=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000013)
> [=C2=A0=C2=A0=C2=A0 0.059341] ACPI: FACP 0x00000000BFBF5000 000074 (v01 B=
OCHS=20
> BXPCFACP 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.061043] ACPI: DSDT 0x00000000BFBF6000 00238D (v01 B=
OCHS=20
> BXPCDSDT 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.062740] ACPI: FACS 0x00000000BFBFD000 000040
> [=C2=A0=C2=A0=C2=A0 0.063673] ACPI: APIC 0x00000000BFBF4000 000090 (v01 B=
OCHS=20
> BXPCAPIC 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.065369] ACPI: HPET 0x00000000BFBF3000 000038 (v01 B=
OCHS=20
> BXPCHPET 00000001 BXPC 00000001)
> [=C2=A0=C2=A0=C2=A0 0.067061] ACPI: BGRT 0x00000000BE49B000 000038 (v01 I=
NTEL=20
> EDK2=C2=A0=C2=A0=C2=A0=C2=A0 00000002=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 01000=
013)
> [=C2=A0=C2=A0=C2=A0 0.068761] ACPI: iBFT 0x00000000BE453000 000800 (v01 B=
OCHS=20
> BXPCFACP 00000000=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 00000000)
> [=C2=A0=C2=A0=C2=A0 0.070461] XXX reserve_ibft_region: table=3Dffffffffff=
240000,=20
> 0x00000000BE453000, size=3D1000
> [=C2=A0=C2=A0=C2=A0 0.072231] check: Scanning 1 areas for low memory corr=
uption
>
> George
>>> [=C2=A0=C2=A0 30.308229] iBFT detected..
>>> [=C2=A0=C2=A0 30.308796]
>>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>> [=C2=A0=C2=A0 30.308890] BUG: KASAN: use-after-free in ibft_init+0x134/=
0xc33
>>> [=C2=A0=C2=A0 30.308890] Read of size 4 at addr ffff8880be453004 by tas=
k=20
>>> swapper/0/1
>>> [=C2=A0=C2=A0 30.308890]
>>> [=C2=A0=C2=A0 30.308890] CPU: 1 PID: 1 Comm: swapper/0 Not tainted=20
>>> 5.11.0-f9593a0 #12
>>> [=C2=A0=C2=A0 30.308890] Hardware name: QEMU Standard PC (i440FX + PIIX=
,=20
>>> 1996), BIOS
>>> 0.0.0 02/06/2015
>>> [=C2=A0=C2=A0 30.308890] Call Trace:
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 dump_stack+0xdb/0x120
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_init+0x134/0xc33
>>> [=C2=A0=C2=A0 30.308890] print_address_description.constprop.7+0x41/0x6=
0
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_init+0x134/0xc33
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_init+0x134/0xc33
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 kasan_report.cold.10+0x78/0xd1
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_init+0x134/0xc33
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 __asan_report_load_n_noabort+0xf/0x20
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ibft_init+0x134/0xc33
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? write_comp_data+0x2f/0x90
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_check_initiator_for+0x159/0x159
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? write_comp_data+0x2f/0x90
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ibft_check_initiator_for+0x159/0x159
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 do_one_initcall+0xc4/0x3e0
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? perf_trace_initcall_level+0x3e0/0x3e0
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? unpoison_range+0x14/0x40
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? ____kasan_kmalloc.constprop.5+0x8f/0xc=
0
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? kernel_init_freeable+0x420/0x652
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? __kasan_kmalloc+0x9/0x10
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 kernel_init_freeable+0x596/0x652
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? console_on_rootfs+0x7d/0x7d
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? rest_init+0xf0/0xf0
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 kernel_init+0x16/0x1d0
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ? rest_init+0xf0/0xf0
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ret_from_fork+0x22/0x30
>>> [=C2=A0=C2=A0 30.308890]
>>> [=C2=A0=C2=A0 30.308890] The buggy address belongs to the page:
>>> [=C2=A0=C2=A0 30.308890] page:0000000001b7b17c refcount:0 mapcount:0
>>> mapping:0000000000000000 index:0x1 pfn:0xbe453
>>> [=C2=A0=C2=A0 30.308890] flags: 0xfffffc0000000()
>>> [=C2=A0=C2=A0 30.308890] raw: 000fffffc0000000 ffffea0002ef9788 ffffea0=
002f91488
>>> 0000000000000000
>>> [=C2=A0=C2=A0 30.308890] raw: 0000000000000001 0000000000000000 0000000=
0ffffffff
>>> 0000000000000000
>>> [=C2=A0=C2=A0 30.308890] page dumped because: kasan: bad access detecte=
d
>>> [=C2=A0=C2=A0 30.308890] page_owner tracks the page as freed
>>> [=C2=A0=C2=A0 30.308890] page last allocated via order 0, migratetype M=
ovable,
>>> gfp_mask 0x100dca(GFP_HIGHUSER_MOVABLE|__GFP_ZERO), pid 204, ts=20
>>> 28121288605
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 prep_new_page+0xfb/0x140
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 get_page_from_freelist+0x3503/0x5730
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 __alloc_pages_nodemask+0x2d8/0x650
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 alloc_pages_vma+0xe2/0x560
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 __handle_mm_fault+0x930/0x26c0
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 handle_mm_fault+0x1f9/0x810
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 do_user_addr_fault+0x6f7/0xca0
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 exc_page_fault+0xaf/0x1a0
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 asm_exc_page_fault+0x1e/0x30
>>> [=C2=A0=C2=A0 30.308890] page last free stack trace:
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 free_pcp_prepare+0x122/0x290
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 free_unref_page_list+0xe6/0x490
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 release_pages+0x2ed/0x1270
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 free_pages_and_swap_cache+0x245/0x2e0
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 tlb_flush_mmu+0x11e/0x680
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 tlb_finish_mmu+0xa6/0x3e0
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 exit_mmap+0x2b3/0x540
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 mmput+0x11d/0x450
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 do_exit+0xaa6/0x2d40
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 do_group_exit+0x128/0x340
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 __x64_sys_exit_group+0x43/0x50
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 do_syscall_64+0x37/0x50
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 entry_SYSCALL_64_after_hwframe+0x44/0xa9
>>> [=C2=A0=C2=A0 30.308890]
>>> [=C2=A0=C2=A0 30.308890] Memory state around the buggy address:
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ffff8880be452f00: ff ff ff ff ff ff ff f=
f ff ff ff=20
>>> ff ff ff
>>> ff ff
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ffff8880be452f80: ff ff ff ff ff ff ff f=
f ff ff ff=20
>>> ff ff ff
>>> ff ff
>>> [=C2=A0=C2=A0 30.308890] >ffff8880be453000: ff ff ff ff ff ff ff ff ff =
ff ff=20
>>> ff ff ff
>>> ff ff
>>> [=C2=A0=C2=A0 30.308890]=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ^
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ffff8880be453080: ff ff ff ff ff ff ff f=
f ff ff ff=20
>>> ff ff ff
>>> ff ff
>>> [=C2=A0=C2=A0 30.308890]=C2=A0 ffff8880be453100: ff ff ff ff ff ff ff f=
f ff ff ff=20
>>> ff ff ff
>>> ff ff
>>> [=C2=A0=C2=A0 30.308890]
>>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>>
>>> George
>>>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/dc5e007c-9223-b03b-1c58-28d2712ec352%40oracle.com.
