Return-Path: <kasan-dev+bncBCX7RK77SEDBBL4UZ6AQMGQECK53FQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id EA5A7321AE6
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 16:13:52 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id e12sf9650510ioc.23
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 07:13:52 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1614006831; cv=pass;
        d=google.com; s=arc-20160816;
        b=nuot+JLPRh6ewA83R3LXBfJ3w2RlUY0ytgBoZ+PmEf11ciXfewes1dth0t2WSAPRaO
         dkSQsOq3td1FEbSjVSxE/B7MZ2xFTWpEG33jRM+NE5sK+BsNz++Xd0CAAf+0y9wB/FfM
         IrWl107Z8fi7hu4SN5S1lG1UEX2mk2n3zKJhTw1CMCqeDxiulxPyt/2EEWw4MH9vNm3y
         6ZbTxqn0ScvXeiK1NP5DHSr4D9ZQnJ/i5OJPhsE2tMIF7g60uw8TYXySoEN8cHgUmAnr
         8rqaAcwO8sYgULEoUSv2Oa6ZV9ACP3hrhyjnEoWXaAqrBRil1hzuJTShh7Oi3jQ2/kF4
         DjPA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :content-transfer-encoding:in-reply-to:user-agent:date:message-id
         :organization:from:references:cc:to:subject:sender:dkim-signature;
        bh=ddJWj8UkGaBwKyaLwCBJToPkIjD7cyatobnGH06wOjI=;
        b=OfTUHhuVQrt7y5pbkhFldObpIsX/ulAFOjjspPoRRjlNsxQOMpYYP3Sj1731KoyAhp
         vw3ZrPQcUESw11+Of11YSSUYVi67j7Ij22V79h2Agaz/SI0TCGgq1kH5s4/aoJBRG4tg
         8IbDtSNFcZHVYX6MMBoCJ9r+lRIgh1eMp6A7mR9K+LOsxiJLL9pswPU0XtMNKmd6YS0l
         3pNhEd9EIoCrXFFf4jwdtuEcS9htpxVt8eejjxwiEZEjtBCnRkuNUEmC0cmOI7qHz4eK
         VtQZdUdj64EmYLNf1hzE0iONLosHxxex5Bdp+/iwPLqB5FsniD1e2f5ttLL+psAS4rA7
         ME8w==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b="TXDRru/m";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=hUPUcc76;
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
        bh=ddJWj8UkGaBwKyaLwCBJToPkIjD7cyatobnGH06wOjI=;
        b=VW2LsdTmcXiFdhDfbrLIorCWuqZP/7x96vR0SbGoZXdGR1f/suSTc8DwPA5bSvu62v
         t1Mk8Gxgh4SGlaR+qwQcgm7rZ3jR4o9njFpulLbybp6X8CZmbeXtgKkBi0q7vXZujb25
         DKEUf1L1dXd8okehvjOO2Y/YRMywo19KxSob7a/pgz4v+2HMGbqZR8Pue2utHtONndZA
         Qzu++ySGd9k+qChbHbXmCaITOVYzFradbFlze9xSmh4FlTdSGkj6lxRu8gYNjWB41/4J
         mAWHdpFl4LcuQuBb+/g1uL9TAml3plquTsH7gb01N//9UF4OHEm+nGsQVGCwWNj2R62o
         3wtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:in-reply-to
         :content-transfer-encoding:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ddJWj8UkGaBwKyaLwCBJToPkIjD7cyatobnGH06wOjI=;
        b=OuRgOjh5IyrywRFekkr9sw7GzpvN2aNYzeNI9lvNrj9TPuJY9oW9G+X/BBTXvjv3U1
         pPORuKHNdQ3BVUBWlITE5lUtNWcAFKPZUkCCwjb9fmxQwRE598bvSHk/hlDvIKxVkyKU
         DWVl+tvcszaRb/4zQ1vpoFoJHQf7T9bgGiva9Pevk5rr1Y8D3NEV6OTpvxjRfm463Fl5
         uMoPKHB9J/Q9n4aJY9oS76WiKIC5T7NDG6qNQitYItDmFB0WSqJ3VVNsZnCXfpJ0QNSR
         eS0fLksjHmMpVsmk5U91gYfLVVBS+hoyz/JgJZ1KBY6q0zxI4pDRemPk2DF6pZq0M57W
         6Sjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533kGOpdAXkC/OR+Fj/3eivP6194y5L5YDM4WtZPP7zY3/O+cOYJ
	eDXC05ED4PPvKhG4sKaIcOA=
X-Google-Smtp-Source: ABdhPJzTfmX0xHZY9EpTjr+wAbCtgEzOh4naa6g2y+PvaF6Cifhiu3mvx0w4XYWNw7eXXLY0DLqNNA==
X-Received: by 2002:a6b:d01a:: with SMTP id x26mr15964282ioa.11.1614006831836;
        Mon, 22 Feb 2021 07:13:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9691:: with SMTP id m17ls3046020ion.2.gmail; Mon, 22 Feb
 2021 07:13:51 -0800 (PST)
X-Received: by 2002:a6b:8b51:: with SMTP id n78mr5340260iod.36.1614006831341;
        Mon, 22 Feb 2021 07:13:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614006831; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cqon8509lVLPr36korapk74rgfNHiH/FN3M2wxQtVWTTvDi/qBOC3R9QCvjhtIAygF
         dSFf0N8nK5LAfXRFdeVYd8qo/rEUx8Ba22g6aWkg9jJvbi6bQOLVCS4PghBGOZc8wMyE
         zU4hUxu8ZDWszuyr0lqs9SQUNzkLWgNyYhDmi42zd+EUYMKVWvtX0ZzlN5JxWMFdvwl/
         rAZmKmjZHR6ncDXwBuCXMsK/q0C9qrr9dlerqKRG8VGmoqF+Q9t6KCl3Po5hV07U54Ut
         +BQ7HbWPOfA8m6YBYDeIFSOvwxqSFHB4B4P4ITLnKn9RJ3BtAaMf+bocyf8f+aC36oCN
         xIkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:content-transfer-encoding:in-reply-to
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature:dkim-signature;
        bh=PL49800XynB1ag+q4I5efdc0o9QPeM6LPA0FAfW9WhM=;
        b=zt0tam8JyXa4aOCf5IN/gshWdBVrlafJueCEzSguBZHTtaQCJb20QcZM5ExjHuT2rA
         STIsbFzlah2e/W+LDJM06Xm8RHTBnijjRucZ0z7hjBEwUNodGJw8cgo0CiUWxB4M6x5y
         I/ptN5D5hW9ImcrBkQv9UMBDHTI7PDsILywXek2irQSPH2TJz1drek57R6wCpFHzdAVG
         W7qIj2L+bWDswZXhugjO4q5OPHTxsDAQXj0u7ZJA/3se7/sDwtMiK+rnsi03gMTpQwYe
         fYX+H3Ad8EPDAsV7IRMrJC0oFxvSnXEzTm7cGjG+kJsqIySDJ7VT8qfgNNEFDMyMsm8N
         bOvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b="TXDRru/m";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=hUPUcc76;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2120.oracle.com (userp2120.oracle.com. [156.151.31.85])
        by gmr-mx.google.com with ESMTPS id g10si490417ioo.0.2021.02.22.07.13.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Feb 2021 07:13:51 -0800 (PST)
Received-SPF: pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.85 as permitted sender) client-ip=156.151.31.85;
Received: from pps.filterd (userp2120.oracle.com [127.0.0.1])
	by userp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11MFAdlA156062;
	Mon, 22 Feb 2021 15:13:33 GMT
Received: from userp3020.oracle.com (userp3020.oracle.com [156.151.31.79])
	by userp2120.oracle.com with ESMTP id 36ugq3atw2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 22 Feb 2021 15:13:33 +0000
Received: from pps.filterd (userp3020.oracle.com [127.0.0.1])
	by userp3020.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11MFAA5K082831;
	Mon, 22 Feb 2021 15:13:32 GMT
Received: from nam12-mw2-obe.outbound.protection.outlook.com (mail-mw2nam12lp2040.outbound.protection.outlook.com [104.47.66.40])
	by userp3020.oracle.com with ESMTP id 36uc6qfrrb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 22 Feb 2021 15:13:32 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=JqTAJCzSklmVnvFcuQb5PGBMTbXgFkDgbnu6P/pFb/qvxFSaCezHsdoUUnZSlc30lgWK1e1mGd3kKd077sHKerhNgyW/a2V2eZ+FhbtBWo+UQs3W5C38RNuhdit70W+ryTQ2eOKT37hPFDqaQl2yhunBhFvPHO/ZgsSI41itLS1yt4hHt74MYlP5q09EMuLztjbKHI/5rFrgQzhfyvBtNdC4Ms4rX8D2IYFjyvdAt0uTOya9PWbhAOTTNfRu/xW9GXdP4HK8eJOqUxsQe6LN3TgVme0oS3X6BBWjw88Z95VhJLREtSRXUg/uff4xZfmLlCPZlXNG7MrYDPTsjPPhVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=PL49800XynB1ag+q4I5efdc0o9QPeM6LPA0FAfW9WhM=;
 b=Mnsg4i0t2Lm2OUsKuLnyM7t3NAY+EdnUwnmxYY0cju8in1uTFzfelpU5xJLBevwhRmlbDouaH/kFkNz4M7Nu0hngSW2WODKJuHCsEh2cauVh+Zhae+HKYHchNME+LlV+mllO57RmRUWfCKXYQ2hSzJZmHJnGMWLxKPofvmCkG4/vUMuziUhUkp/gRASajU+jIvbA+z5N9RDh4OY7/YjoF0bdz7YW7VuveqlQmomf7nisBnDTRuvQMFWiYF3uzuusGwTRUOSRsuoW6Gv1XE6t8BwtHNDfqdtZeG+K0R6nT4bvaYbwSzlFzpZ/KFXo03fMCnKEL0OV3dbUMXH6ffHupA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM6PR10MB3851.namprd10.prod.outlook.com (2603:10b6:5:1fb::17)
 by DM6PR10MB2827.namprd10.prod.outlook.com (2603:10b6:5:6e::32) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3868.29; Mon, 22 Feb
 2021 15:13:30 +0000
Received: from DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da]) by DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da%3]) with mapi id 15.20.3868.032; Mon, 22 Feb 2021
 15:13:30 +0000
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
To: David Hildenbrand <david@redhat.com>,
        Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
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
References: <487751e1ccec8fcd32e25a06ce000617e96d7ae1.1613595269.git.andreyknvl@google.com>
 <e58cbb53-5f5b-42ae-54a0-e3e1b76ad271@redhat.com>
 <d11bf144-669b-0fe1-4fa4-001a014db32a@oracle.com>
 <CAAeHK+y_SmP5yAeSM3Cp6V3WH9uj4737hDuVGA7U=xA42ek3Lw@mail.gmail.com>
 <c7166cae-bf89-8bdd-5849-72b5949fc6cc@oracle.com>
 <797fae72-e3ea-c0b0-036a-9283fa7f2317@oracle.com>
 <1ac78f02-d0af-c3ff-cc5e-72d6b074fc43@redhat.com>
From: George Kennedy <george.kennedy@oracle.com>
Organization: Oracle Corporation
Message-ID: <bd7510b5-d325-b516-81a8-fbdc81a27138@oracle.com>
Date: Mon, 22 Feb 2021 10:13:24 -0500
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.6.1
In-Reply-To: <1ac78f02-d0af-c3ff-cc5e-72d6b074fc43@redhat.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [108.20.187.119]
X-ClientProxiedBy: CY4PR16CA0018.namprd16.prod.outlook.com
 (2603:10b6:903:102::28) To DM6PR10MB3851.namprd10.prod.outlook.com
 (2603:10b6:5:1fb::17)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from [192.168.1.222] (108.20.187.119) by CY4PR16CA0018.namprd16.prod.outlook.com (2603:10b6:903:102::28) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3868.27 via Frontend Transport; Mon, 22 Feb 2021 15:13:27 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: fd2739f0-f04e-4703-8e79-08d8d744696e
X-MS-TrafficTypeDiagnostic: DM6PR10MB2827:
X-MS-Exchange-Transport-Forked: True
X-Microsoft-Antispam-PRVS: <DM6PR10MB282764A7A4DC9F366D773D7DE6819@DM6PR10MB2827.namprd10.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:10000;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: YkxBa8ptfutkt77k8WBYdgwWqjVLx+p8Rm2vbFHT9r2MdK5BmMJAD7XSrOKWFLUSFt7TchCwR371RnnQbjmVR4YYaba6y6qkVppZ9KCT4wyw9m1WC9hCeMNuL1JKmuRereTF+8xUj6tzThk67We4xGHbGl+EiWgu5U9C1/B9jLNgq5hAM8heU54w+942ZmIiubgAuKdJaOp4b+XuvwqHNgbz8O+pYI3y6JtytBiza9A6+Ami0QT1wOXHdoMJ2Mdi/tpFmuVehXKIxn6ux7J+J5APFGfaL3Tu18EXxcGAs4ZhKc0vhEvDaWQXPvjcOtKptB5xsxt8Jnv7E+WmWW3oD0DEwsFd1hc9P7itbwZ3F2Ngd4wOmxQNbs3hULDvsqfOlFAx75vRjAyi8G4QDxtsiZbU/RKQ16VTs8R7V+XHZXYHGEpPWKsaPWMDmFSeSxHqdHpVi/Wj2QOve5mcN+pKJGREmh+JU8xFTJb5v8sdcvjLedpjR78k/WVsMMx5H5d79e3Coy+6I9DeCjd4XdELhHxf0td58XgPOfZdeMSN/rMTVr9rd46SQr+BkYsDnXcBd3LUtN1iy2qLRm11R7mo2uj7EYVoyhKY1DRIEc9fTWelE967rSHI9bkrCvCf/AQ6ROf6qwLIGIH1ScGq1AH/eyL7gDIHEGQcl3aVMW2tuOe+IB5smVwmOTH5kjDQUejXJSfS/ZmPg5vT4mSYdbx3ZA==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR10MB3851.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(136003)(39860400002)(376002)(396003)(366004)(346002)(7416002)(16526019)(186003)(44832011)(2616005)(53546011)(54906003)(26005)(2906002)(107886003)(956004)(110136005)(16576012)(6666004)(4326008)(6486002)(316002)(45080400002)(8936002)(86362001)(478600001)(83380400001)(36916002)(66476007)(31696002)(31686004)(8676002)(36756003)(66946007)(5660300002)(66556008)(966005)(21314003)(45980500001)(43740500002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?utf-8?B?MGlKR25SQXF5TGk3NU5taDcraHQxYnZQU2FmWmJyNXhnS21UaStsNExHVFk0?=
 =?utf-8?B?T3YxVitnVjdaZHpQaENvRk9iZlZiZkVrQjMyL21iREZMT2NJblArdjBpMC9I?=
 =?utf-8?B?eWlvbyt3cThFZWdnbGRWUlBONm4ybm9oN1Z4UDBUTitTbG9TRnhDZkNWTXJC?=
 =?utf-8?B?RFpJYmNGcGdiTmh2aS9MTDhIaTRpMG1CRGhXV2RCWFhQV0pTMHllbFBjYTBH?=
 =?utf-8?B?SWwvZkNmUEdleUlyZ0JVTjRsMll4QkVWSHB2cTRSSjRGaGZJSW5jMzZNbzl6?=
 =?utf-8?B?NTVoRlovQUx0dnAyRGRlVllmRVFqa3NwcE1kTlRHNGRXRjFtYjdabmxWTFRB?=
 =?utf-8?B?VVcrS3dSUldrU3hlUE1EVnQ0Y3hKS0d1WkZ1Q21aZjBKMndiZ0x2VU1UdXNL?=
 =?utf-8?B?NUY4cUVKRXNLbzhjdlVJL0p5ZUJyZDFhZ0d5RXZxUGRYT05qeEd2N29xMjJ1?=
 =?utf-8?B?MWNLWHc0WDNqMFdEb0p5aGN2aUJYWHRLbE9zSlNaSFc2Sk82S2Qwem43Rkp6?=
 =?utf-8?B?b21KeU4ySHdRRXZkTWtUb3phV3FoUGdYOFVBeHd3cXZqSGVCaDZUYVk0T29o?=
 =?utf-8?B?MDZnZUIwMElXWFVXT05RWXhIb0YxdWNwTlNtTCtWcU9TVHZNN2dxOElOY01h?=
 =?utf-8?B?MUtFOTVycThISDIrcEhScnRYc1Q0c0dtZ3NhVk5DWUw1K3ZXS3VFemJ1Qjcr?=
 =?utf-8?B?WEtZYjNCWDFiQ1RuVnBKTFo3aDZGaFdoSnE5K01xa0FmQzB3MVFqVExiOEp0?=
 =?utf-8?B?WXZBSi9GT2lLcCtMcjlWa0RlOWtaRms5RUJZeUgvN2dmbWZMRVczSDZuVW5B?=
 =?utf-8?B?SnZUVFVlWlVSNEV3UXdKcVhkbXBkeTltMk5nWjFpZEd1YWJ6SDg3d1VLbVQv?=
 =?utf-8?B?N1Q0Y2NtRGlBWHY1U3hvdmxVY0xkbERjQWlmemlTS1RIaWh3ZEJzd1dXeUlF?=
 =?utf-8?B?bWQ1SHh1MG11TndFL3NFWm1pZHpHOWhUTENZdlI3MDlwRStlNDFsZUpqdlJ2?=
 =?utf-8?B?SFBSQnNrNkxmK0tNOWl6NnhERStCamZENGhydmlza2tubmJZcmEreDU5OVBL?=
 =?utf-8?B?dFBHOTEzRFBOQmNVUjB0UnNteWtZdEhKZHBsMkVSZ2JJMGRJNkRRYVBqTmdr?=
 =?utf-8?B?RGYvRmlHMW5jVlBCRHcrb2tWUGZFMHJSaHBTUmxTcllSVDZkQzRzR0xHc3Ez?=
 =?utf-8?B?WE1wUytObnJoNi9IclFCVTUzSTYxbWRNbFlDaExFeXZJblk3WmNpREdoT0F3?=
 =?utf-8?B?SDc0S284WVV3NmtUQ2hXR0R6UWdtN2VsRmkwOXFyUGJ2a2hDY2xGREVUUFov?=
 =?utf-8?B?dHY0ekpxRitYVnZKeTBLNkFHWkxENFRWUzdiUG0wcy9nQVVYNXZmTHhpUExv?=
 =?utf-8?B?Y3B6Z3ZxMWlzNEtpUjJZei9KSWZjeGJhM3pxSEUwQzBId25MTVpRRGp6OVhX?=
 =?utf-8?B?SDJPd1FNK2xRa1FxT3Jmd3N2T0E0SnhzYXdzS1kwcTVOeFdtRy83YTRHa2lF?=
 =?utf-8?B?T05hUWxwUHROM05hUS90ZFhpeExBVStadDRzTmd1ZCtGSTVUM0tZYWlsdFJa?=
 =?utf-8?B?Zk51VjlNQTlkV3ZQTnNlcS8zSHJrajFNVnU0eXkzS0xGcVZGeGZNelBqOU1D?=
 =?utf-8?B?dW8rYlgvSmVIRG9ndFZBaGZIbEVHS1BXU1k2ZXFNWVJ6TVBORGk3eHZIdFhV?=
 =?utf-8?B?NStrc1dnSXhDRHg2a0dEMXI3RzdLeWFYWDVXbjdUMUVZM2pITVhaNEZXMDhk?=
 =?utf-8?Q?Ii+FF1aZNUHf8NViETzp5pgtSBxguprGZVH9UNv?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: fd2739f0-f04e-4703-8e79-08d8d744696e
X-MS-Exchange-CrossTenant-AuthSource: DM6PR10MB3851.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Feb 2021 15:13:30.2254
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: tqVLG4Ck0X7uwtc+muctIJFlR4MJaCDm2ke/acX6efwISTa49jjJLgE1myR6rpEAM2NiFmOCIANVDK4//phXUCJRabxyR8vey48jPC734vc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR10MB2827
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9902 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 mlxscore=0 spamscore=0
 mlxlogscore=999 adultscore=0 bulkscore=0 malwarescore=0 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2102220141
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9902 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 phishscore=0
 malwarescore=0 spamscore=0 mlxscore=0 suspectscore=0 priorityscore=1501
 clxscore=1015 impostorscore=0 lowpriorityscore=0 mlxlogscore=999
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2102220141
X-Original-Sender: george.kennedy@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b="TXDRru/m";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=hUPUcc76;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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



On 2/22/2021 4:52 AM, David Hildenbrand wrote:
> On 20.02.21 00:04, George Kennedy wrote:
>>
>>
>> On 2/19/2021 11:45 AM, George Kennedy wrote:
>>>
>>>
>>> On 2/18/2021 7:09 PM, Andrey Konovalov wrote:
>>>> On Fri, Feb 19, 2021 at 1:06 AM George Kennedy
>>>> <george.kennedy@oracle.com> wrote:
>>>>>
>>>>>
>>>>> On 2/18/2021 3:55 AM, David Hildenbrand wrote:
>>>>>> On 17.02.21 21:56, Andrey Konovalov wrote:
>>>>>>> During boot, all non-reserved memblock memory is exposed to the=20
>>>>>>> buddy
>>>>>>> allocator. Poisoning all that memory with KASAN lengthens boot=20
>>>>>>> time,
>>>>>>> especially on systems with large amount of RAM. This patch makes
>>>>>>> page_alloc to not call kasan_free_pages() on all new memory.
>>>>>>>
>>>>>>> __free_pages_core() is used when exposing fresh memory during=20
>>>>>>> system
>>>>>>> boot and when onlining memory during hotplug. This patch adds a new
>>>>>>> FPI_SKIP_KASAN_POISON flag and passes it to __free_pages_ok()=20
>>>>>>> through
>>>>>>> free_pages_prepare() from __free_pages_core().
>>>>>>>
>>>>>>> This has little impact on KASAN memory tracking.
>>>>>>>
>>>>>>> Assuming that there are no references to newly exposed pages
>>>>>>> before they
>>>>>>> are ever allocated, there won't be any intended (but buggy)
>>>>>>> accesses to
>>>>>>> that memory that KASAN would normally detect.
>>>>>>>
>>>>>>> However, with this patch, KASAN stops detecting wild and large
>>>>>>> out-of-bounds accesses that happen to land on a fresh memory page
>>>>>>> that
>>>>>>> was never allocated. This is taken as an acceptable trade-off.
>>>>>>>
>>>>>>> All memory allocated normally when the boot is over keeps getting
>>>>>>> poisoned as usual.
>>>>>>>
>>>>>>> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>>>>>>> Change-Id: Iae6b1e4bb8216955ffc14af255a7eaaa6f35324d
>>>>>> Not sure this is the right thing to do, see
>>>>>>
>>>>>> https://lkml.kernel.org/r/bcf8925d-0949-3fe1-baa8-cc536c529860@oracl=
e.com=20
>>>>>>
>>>>>>
>>>>>>
>>>>>> Reversing the order in which memory gets allocated + used during=20
>>>>>> boot
>>>>>> (in a patch by me) might have revealed an invalid memory access=20
>>>>>> during
>>>>>> boot.
>>>>>>
>>>>>> I suspect that that issue would no longer get detected with your
>>>>>> patch, as the invalid memory access would simply not get detected.
>>>>>> Now, I cannot prove that :)
>>>>> Since David's patch we're having trouble with the iBFT ACPI table,
>>>>> which
>>>>> is mapped in via kmap() - see acpi_map() in "drivers/acpi/osl.c".=20
>>>>> KASAN
>>>>> detects that it is being used after free when ibft_init() accesses=20
>>>>> the
>>>>> iBFT table, but as of yet we can't find where it get's freed (we've
>>>>> instrumented calls to kunmap()).
>>>> Maybe it doesn't get freed, but what you see is a wild or a large
>>>> out-of-bounds access. Since KASAN marks all memory as freed during the
>>>> memblock->page_alloc transition, such bugs can manifest as
>>>> use-after-frees.
>>>
>>> It gets freed and re-used. By the time the iBFT table is accessed by
>>> ibft_init() the page has been over-written.
>>>
>>> Setting page flags like the following before the call to kmap()
>>> prevents the iBFT table page from being freed:
>>
>> Cleaned up version:
>>
>> diff --git a/drivers/acpi/osl.c b/drivers/acpi/osl.c
>> index 0418feb..8f0a8e7 100644
>> --- a/drivers/acpi/osl.c
>> +++ b/drivers/acpi/osl.c
>> @@ -287,9 +287,12 @@ static void __iomem *acpi_map(acpi_physical_address
>> pg_off, unsigned long pg_sz)
>>
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D pg_off >> PAGE_SHIFT;
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn)) {
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 struct page *page =3D pfn_to_page=
(pfn);
>> +
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 if (pg_sz > PAGE_SIZE=
)
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 re=
turn NULL;
>> -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return (void __iomem __force *)km=
ap(pfn_to_page(pfn));
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 SetPageReserved(page);
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return (void __iomem __force *)km=
ap(page);
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 } else
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return acpi_os_iorema=
p(pg_off, pg_sz);
>> =C2=A0 =C2=A0}
>> @@ -299,9 +302,12 @@ static void acpi_unmap(acpi_physical_address
>> pg_off, void __iomem *vaddr)
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 unsigned long pfn;
>>
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D pg_off >> PAGE_SHIFT;
>> -=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn))
>> -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 kunmap(pfn_to_page(pfn));
>> -=C2=A0=C2=A0=C2=A0 else
>> +=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn)) {
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 struct page *page =3D pfn_to_page=
(pfn);
>> +
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 ClearPageReserved(page);
>> +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 kunmap(page);
>> +=C2=A0=C2=A0=C2=A0 } else
>> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 iounmap(vaddr);
>> =C2=A0 =C2=A0}
>>
>> David, the above works, but wondering why it is now necessary. kunmap()
>> is not hit. What other ways could a page mapped via kmap() be unmapped?
>>
>
> Let me look into the code ... I have little experience with ACPI=20
> details, so bear with me.
>
> I assume that acpi_map()/acpi_unmap() map some firmware blob that is=20
> provided via firmware/bios/... to us.
>
> should_use_kmap() tells us whether
> a) we have a "struct page" and should kmap() that one
> b) we don't have a "struct page" and should ioremap.
>
> As it is a blob, the firmware should always reserve that memory region=20
> via memblock (e.g., memblock_reserve()), such that we either
> 1) don't create a memmap ("struct page") at all (-> case b) )
> 2) if we have to create e memmap, we mark the page PG_reserved and
> =C2=A0=C2=A0 *never* expose it to the buddy (-> case a) )
>
>
> Are you telling me that in this case we might have a memmap for the HW=20
> blob that is *not* PG_reserved? In that case it most probably got=20
> exposed to the buddy where it can happily get allocated/freed.
>
> The latent BUG would be that that blob gets exposed to the system like=20
> ordinary RAM, and not reserved via memblock early during boot.=20
> Assuming that blob has a low physical address, with my patch it will=20
> get allocated/used a lot earlier - which would mean we trigger this=20
> latent BUG now more easily.
>
> There have been similar latent BUGs on ARM boards that my patch=20
> discovered where special RAM regions did not get marked as reserved=20
> via the device tree properly.
>
> Now, this is just a wild guess :) Can you dump the page when mapping=20
> (before PageReserved()) and when unmapping, to see what the state of=20
> that memmap is?

Thank you David for the explanation and your help on this,

dump_page() before PageReserved and before kmap() in the above patch:

[=C2=A0=C2=A0=C2=A0 1.116480] ACPI: Core revision 20201113
[=C2=A0=C2=A0=C2=A0 1.117628] XXX acpi_map: about to call kmap()...
[=C2=A0=C2=A0=C2=A0 1.118561] page:ffffea0002f914c0 refcount:0 mapcount:0=
=20
mapping:0000000000000000 index:0x0 pfn:0xbe453
[=C2=A0=C2=A0=C2=A0 1.120381] flags: 0xfffffc0000000()
[=C2=A0=C2=A0=C2=A0 1.121116] raw: 000fffffc0000000 ffffea0002f914c8 ffffea=
0002f914c8=20
0000000000000000
[=C2=A0=C2=A0=C2=A0 1.122638] raw: 0000000000000000 0000000000000000 000000=
00ffffffff=20
0000000000000000
[=C2=A0=C2=A0=C2=A0 1.124146] page dumped because: acpi_map pre SetPageRese=
rved

I also added dump_page() before unmapping, but it is not hit. The=20
following for the same pfn now shows up I believe as a result of setting=20
PageReserved:

[=C2=A0=C2=A0 28.098208] BUG: Bad page state in process modprobe=C2=A0 pfn:=
be453
[=C2=A0=C2=A0 28.098394] page:ffffea0002f914c0 refcount:0 mapcount:0=20
mapping:0000000000000000 index:0x1 pfn:0xbe453
[=C2=A0=C2=A0 28.098394] flags: 0xfffffc0001000(reserved)
[=C2=A0=C2=A0 28.098394] raw: 000fffffc0001000 dead000000000100 dead0000000=
00122=20
0000000000000000
[=C2=A0=C2=A0 28.098394] raw: 0000000000000001 0000000000000000 00000000fff=
fffff=20
0000000000000000
[=C2=A0=C2=A0 28.098394] page dumped because: PAGE_FLAGS_CHECK_AT_PREP flag=
(s) set
[=C2=A0=C2=A0 28.098394] page_owner info is not present (never set?)
[=C2=A0=C2=A0 28.098394] Modules linked in:
[=C2=A0=C2=A0 28.098394] CPU: 2 PID: 204 Comm: modprobe Not tainted 5.11.0-=
3dbd5e3 #66
[=C2=A0=C2=A0 28.098394] Hardware name: QEMU Standard PC (i440FX + PIIX, 19=
96),=20
BIOS 0.0.0 02/06/2015
[=C2=A0=C2=A0 28.098394] Call Trace:
[=C2=A0=C2=A0 28.098394]=C2=A0 dump_stack+0xdb/0x120
[=C2=A0=C2=A0 28.098394]=C2=A0 bad_page.cold.108+0xc6/0xcb
[=C2=A0=C2=A0 28.098394]=C2=A0 check_new_page_bad+0x47/0xa0
[=C2=A0=C2=A0 28.098394]=C2=A0 get_page_from_freelist+0x30cd/0x5730
[=C2=A0=C2=A0 28.098394]=C2=A0 ? __isolate_free_page+0x4f0/0x4f0
[=C2=A0=C2=A0 28.098394]=C2=A0 ? init_object+0x7e/0x90
[=C2=A0=C2=A0 28.098394]=C2=A0 __alloc_pages_nodemask+0x2d8/0x650
[=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
[=C2=A0=C2=A0 28.098394]=C2=A0 ? __alloc_pages_slowpath.constprop.103+0x211=
0/0x2110
[=C2=A0=C2=A0 28.098394]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
[=C2=A0=C2=A0 28.098394]=C2=A0 alloc_pages_vma+0xe2/0x560
[=C2=A0=C2=A0 28.098394]=C2=A0 do_fault+0x194/0x12c0
[=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
[=C2=A0=C2=A0 28.098394]=C2=A0 __handle_mm_fault+0x1650/0x26c0
[=C2=A0=C2=A0 28.098394]=C2=A0 ? copy_page_range+0x1350/0x1350
[=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
[=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
[=C2=A0=C2=A0 28.098394]=C2=A0 handle_mm_fault+0x1f9/0x810
[=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
[=C2=A0=C2=A0 28.098394]=C2=A0 do_user_addr_fault+0x6f7/0xca0
[=C2=A0=C2=A0 28.098394]=C2=A0 exc_page_fault+0xaf/0x1a0
[=C2=A0=C2=A0 28.098394]=C2=A0 asm_exc_page_fault+0x1e/0x30
[=C2=A0=C2=A0 28.098394] RIP: 0010:__clear_user+0x30/0x60

What would be=C2=A0 the correct way to reserve the page so that the above=
=20
would not be hit?

BTW, this is running with Konrad's patch that pairs acpi_get_table &=20
acpi_put_table for the iBFT table which should result in an eventual=20
call to acpi_unmap() and kunmap(), though that does not occur. Could be=20
a possible acpi page refcount issue that will have to be looked into.

George

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/bd7510b5-d325-b516-81a8-fbdc81a27138%40oracle.com.
