Return-Path: <kasan-dev+bncBCX7RK77SEDBBE4IYGAQMGQEPH25CFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5ECF0320182
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Feb 2021 00:04:52 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id f140sf4588078qke.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Feb 2021 15:04:52 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1613775891; cv=pass;
        d=google.com; s=arc-20160816;
        b=QHTqYCmAAWyF4i9114hOi9Y547rVNRcdNUiaN9uUDcTc9b1Uj5FCMDMWcFuODS5m20
         VV9bDlqaiigIbIw+f9ZytVJ5j8iUr+1l29V1UYa23/2ebYFKHNmdQZTTYyprfuDyeLeO
         /GDwPHjZFsFTFYkefmvKHEFmosHMP6aRe91Qt+FoNjYsQtjyOGeYF107t4D+d6x2+ImL
         SfFXImIbxW+4bpF99FKS3joE043AkDhdgHovv65iHFICL0ROV4b53uFj71r57kXbNICp
         IEJqqw2+yH4Ea/gM4lY5mQrJIQzNFGPqltcY2+bYNczN/U5VeB8w893vllYtU9+iCGB+
         pdlg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :content-transfer-encoding:in-reply-to:user-agent:date:message-id
         :organization:references:cc:to:from:subject:sender:dkim-signature;
        bh=J9vAIs0/V6upHLHp3hwkamot6voiLXP9IwL4omzK0tE=;
        b=UPipi6jze6HT8BnEjFam2xjeUYFfTT+G5xGvvIVRsVC6hihbtjrYONTyxJI11SZNXM
         Nz/JNjzrIbejogV5rSF6aWMfSo7Pv47SK38CAs7tYiUJ7cmLXRKkzpenQeuFyRRRFCVg
         mLkS0N2K8ajOexaIqw9df2ndnHt7QzubIdKfUybo/VD+DdKPtaZ6IxX2/hncEaX8duWX
         sCn8vjO0yHzQx2swiicFClmzzt+uo2vNLcQOlXBeUd+e3l/bRqWJ6T8vClwvIqTwcGGo
         ACazGlwc6es/AMD70JjONRNCTTBMBy/ZJfxxwTx4gOdQ+rodFa5QwuzateqqCc0fpujF
         z36A==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=eyu7sxXa;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=pN4FkB9o;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:organization:message-id:date
         :user-agent:in-reply-to:content-transfer-encoding:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J9vAIs0/V6upHLHp3hwkamot6voiLXP9IwL4omzK0tE=;
        b=C0aksibN2Sgl1gdtBjy+Yl2VMt4+smDH1I9zxAbJgO7yO2EnEYaiiCLdqaR7dlw9YD
         Oln8XQNBjRMIfJX0Ik4ImasLEvILHiL23EmKZh39BIyOE13NHOa3lfLkJ8bETm0mtFx/
         TV0qmypnldT/iL+pBjDdIvev+v/Cw+c2FSvXJlMnrtbHvyWw7UkGm1yYjrJuBVS9mCNH
         V9cX5CDU04wqg+f28A2lJxJC2X1uPV7upx2IxBcWz0FR6nFZNTi70TS/0owk0UecWnk5
         TgdVmXfu8+6ZQbV+630k+w8njJ6KyZYO7u5mXB0JH0XjBKo3xVzOFFfrIkoitprkeQ6Q
         Ed/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references
         :organization:message-id:date:user-agent:in-reply-to
         :content-transfer-encoding:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=J9vAIs0/V6upHLHp3hwkamot6voiLXP9IwL4omzK0tE=;
        b=n3UsWC14BLahqY9hn4lb9ES1utYCy2iFh/d+YzcPJnRY4w+7j+QKEJrSDPmWP4dMzJ
         +JrKbNd3NKFtzJUcIkEAqG6QeRWqFJEUTX+Ehp5SdeKtZzuUmfcIGpNEs0B/NCUIuBfz
         rmLxhwmuRedOdFGT6t4/H3FbQ/u2CKZBkPdLOtjyobCiS8N2LzuMbAQJuzuG1+Uxnt8G
         KyTGXONIZZ+27zcPNz8wT3xEuG2MkFIPy8DdBrZRW9UCcmVJljFeGFeQANIeBN5V0CrW
         lutHLHrFxXbrEpcrtPjrv/vigRAP220GzVNSkkp1b7nhi0NjQjCdCmHvx/0fxUgrHYkh
         lV6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533kvl0WfStFafFK4ig8d7D+xpc23v53Y0pQAm9vHaYTXEUhOpk8
	AM3iFAYhudiJVMGo5ineC0I=
X-Google-Smtp-Source: ABdhPJwufvaSaWvD5Yc0rdvNwmB2SnWkHLDhV2n/r+V/oNI9lenPCGTO+KvYOJ6vR54aBS3HnBhhCw==
X-Received: by 2002:a37:a417:: with SMTP id n23mr11873359qke.188.1613775891466;
        Fri, 19 Feb 2021 15:04:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9c2:: with SMTP id 185ls5401622qkj.8.gmail; Fri, 19 Feb
 2021 15:04:51 -0800 (PST)
X-Received: by 2002:a37:ac02:: with SMTP id e2mr9692397qkm.222.1613775891120;
        Fri, 19 Feb 2021 15:04:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613775891; cv=pass;
        d=google.com; s=arc-20160816;
        b=I6yzZafWNgj9Q+62/WQbY6Xy152PhpgDiCMLo/lV9KR2d7B/3mwi32xyLyZYB3BfcJ
         MYX+0jy2EOHu0HUXNB4NFKSLyKNRSfK6zmVIx5our0wZb8R5E8WeGbqX+CHonpxcNsVs
         kJ7VWAlxS7AqXs4zEwf9TvwpXeFWaEnTgncEypJ4tQ0jsyASVzLbNuOSevuu41xd1IyB
         aIMNJNDMFqhTQd5aHjqNoux0rmhtnrtKDYKWQOsp0GC+pZv31vVjBtizuz8rSrdne9g4
         xhdHmHK6iKgPvQU8D1xFhvJB1X1K37ZC7nZxueOOlq150yLk9V70uIDJ40lYfQdI4FZW
         USHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:content-transfer-encoding:in-reply-to
         :user-agent:date:message-id:organization:references:cc:to:from
         :subject:dkim-signature:dkim-signature;
        bh=T1Pf7WpLNH5E4jFhK2IUStMlmWS7Q9wot4HrRySeEz8=;
        b=BVvCzyLR20iZ0scjNxmwAbN1Zz3DSZAqQUZINjkzcmDrwj4AdUKxVWkjTgBC7ylewD
         Jg/5BbI7uqY1nb7lE9KDt76yFSTnyjYa0PYdKO32WLkayFr2Fcu/fzmD3qjyaL33nEvK
         26Wm7smv7quVKlLKxc5PLSkWmrgDa8ywLbBKyNnwHec0qVRf/addWczznJinDFOj26Sp
         dYKbeFnfUnXKK/5G8QV6GT7H5oa5ftTKUBwKQL8qXP+j9yAD+SQUDGeQ/l13cU8oQFoz
         JidBdO7w4KyG7HQ+0JIP7wqMGY7ns8HyO5yJrQgn1C5eY+EoXMEy862teFElk4sZPqcJ
         1+yA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=eyu7sxXa;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=pN4FkB9o;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.85 as permitted sender) smtp.mailfrom=george.kennedy@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2120.oracle.com (userp2120.oracle.com. [156.151.31.85])
        by gmr-mx.google.com with ESMTPS id x65si564878qkb.2.2021.02.19.15.04.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Feb 2021 15:04:51 -0800 (PST)
Received-SPF: pass (google.com: domain of george.kennedy@oracle.com designates 156.151.31.85 as permitted sender) client-ip=156.151.31.85;
Received: from pps.filterd (userp2120.oracle.com [127.0.0.1])
	by userp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11JN4XOG029585;
	Fri, 19 Feb 2021 23:04:33 GMT
Received: from userp3020.oracle.com (userp3020.oracle.com [156.151.31.79])
	by userp2120.oracle.com with ESMTP id 36p7dntxhd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 19 Feb 2021 23:04:33 +0000
Received: from pps.filterd (userp3020.oracle.com [127.0.0.1])
	by userp3020.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 11JMxmA2100274;
	Fri, 19 Feb 2021 23:04:33 GMT
Received: from nam10-dm6-obe.outbound.protection.outlook.com (mail-dm6nam10lp2109.outbound.protection.outlook.com [104.47.58.109])
	by userp3020.oracle.com with ESMTP id 36prhw7re5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 19 Feb 2021 23:04:33 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=KOWHqj4FLAoS+5lT98SWdK3t3cnWAW2LH+cyNleBXUNSEUP2zXIoZ33jhEGmUatoYDMq+bxH6LTqEeek6ZktQSL4XbABIL1cxiQTJj8LEvp3gnycXbxOLAD8Ss0+PII1kvs/9WEzs++6R2FazIlNYUw3mQ26f61xKWp9WI6JyjPjCgge9NbQRum8qFmXvgOndpjgT9r1w3xlp2xky1GrRzYAo9020xnil48433xzRGK/Wrh/hYlJYpxthTcAI/wiRYr9hHkt0NQD4VQzPsN+f335tYxSiqd+Ync5h6A/XK6hoafp4THrLlAnnLEYkiHFCfcuGe1t9zq8tUxYRhxUKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=T1Pf7WpLNH5E4jFhK2IUStMlmWS7Q9wot4HrRySeEz8=;
 b=llWqNmvroSacDK4tXOZXE0dYHzmkEtqeYZmmm4agxsVvaCDUtG9mk/AlpixgUHKp16irYAZhCLabsybQ5wBIYwfXCIVHpRE4kri0qOl+D3MtkqNEH81+5Z0pmpqoCLj6rJg8z4GiBplGUyVR8UGYzL28LXduaDIqwdpN8qTu2dDbxJWl/xAc6W/MP2f+jPDStRY1q43NbizD2EYjqwlVvFfnxC3xxwKgzcK+AoA/KlQ6wMaRCgjONDKI2Mnx/aRSzjj9GEiuLX+MxfBKip8J54sXSSTqXy9VBUmGj2uNOoRwLF4gnUW+hMQmGjG0lbs6UqMu11x9zm/2mZIxQSEOOg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM6PR10MB3851.namprd10.prod.outlook.com (2603:10b6:5:1fb::17)
 by DS7PR10MB5087.namprd10.prod.outlook.com (2603:10b6:5:3b0::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3846.27; Fri, 19 Feb
 2021 23:04:31 +0000
Received: from DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da]) by DM6PR10MB3851.namprd10.prod.outlook.com
 ([fe80::5c53:869:7452:46da%3]) with mapi id 15.20.3846.041; Fri, 19 Feb 2021
 23:04:31 +0000
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
From: George Kennedy <george.kennedy@oracle.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: David Hildenbrand <david@redhat.com>,
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
References: <487751e1ccec8fcd32e25a06ce000617e96d7ae1.1613595269.git.andreyknvl@google.com>
 <e58cbb53-5f5b-42ae-54a0-e3e1b76ad271@redhat.com>
 <d11bf144-669b-0fe1-4fa4-001a014db32a@oracle.com>
 <CAAeHK+y_SmP5yAeSM3Cp6V3WH9uj4737hDuVGA7U=xA42ek3Lw@mail.gmail.com>
 <c7166cae-bf89-8bdd-5849-72b5949fc6cc@oracle.com>
Organization: Oracle Corporation
Message-ID: <797fae72-e3ea-c0b0-036a-9283fa7f2317@oracle.com>
Date: Fri, 19 Feb 2021 18:04:23 -0500
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
In-Reply-To: <c7166cae-bf89-8bdd-5849-72b5949fc6cc@oracle.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
Content-Language: en-US
X-Originating-IP: [108.20.187.119]
X-ClientProxiedBy: BYAPR02CA0020.namprd02.prod.outlook.com
 (2603:10b6:a02:ee::33) To DM6PR10MB3851.namprd10.prod.outlook.com
 (2603:10b6:5:1fb::17)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from [192.168.1.246] (108.20.187.119) by BYAPR02CA0020.namprd02.prod.outlook.com (2603:10b6:a02:ee::33) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3868.27 via Frontend Transport; Fri, 19 Feb 2021 23:04:27 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 4fd063a8-27cf-4c7e-b455-08d8d52ab6d3
X-MS-TrafficTypeDiagnostic: DS7PR10MB5087:
X-MS-Exchange-Transport-Forked: True
X-Microsoft-Antispam-PRVS: <DS7PR10MB50870CEBEAA518EA868660BAE6849@DS7PR10MB5087.namprd10.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:10000;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: PxvYfWrB3qRDIYvqP5YoFBvhFoxTvzcpfJvB58Qdzox3GLpvzXX/I0zhhdsb8vumaIwiqpCbzYis997gfuhj4gZO1Sh09y/i8uxIsGMces/RmS3retCaHPTg6rEVBDPuafMbq5stWvpJS1Xqvkq6UfeZ9rtjbNHvpIaWhqg7XBf15IJZQI65tXgkkfppBlNAbfgs0VstiJpYro6No1NutV2T3/dlA9OFWqf7/H2RI1km7/d2IHGuxojQuMpU7LVa9/NjdP6lU3Z4cu5Gwa61lTe2F1Vab0C+XhChhStimdlzwkCdYe8sKZo43hm2cJgERhpz79ZoZOxU8kE3lxhd9ytxfXZWZxMSFZVavcrjjgx63d+XNmIbxNxH2CGofuJO/jS+91HCELuoyYZYczgAoE0lIkblLQ2RcnrlUi2864YyZm0I/piTM5d7e0DNS3KWBGtjk0MSmQ5aQMC77WqYspYSheYewRNHE/r9tdBhaUcZPIQ0y0aVDhUYFVr3+602NJ6McMH961kf3dHISCM3ojSN51TPpntMfNcM25SOt3p133UEgPwrtHnWCQJTsCBHhuf5yaPZqBKJugRrCZRyFwN7r7H5CmoEifLwEcRoFtnPNdAL8nHpwD/X78xkslnR+r7oyUQe11OlU4444MBF1TyVPYkTx6+BJkgpwFFv9AsGzfqGzxTQzE3bY5FgUpG4
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR10MB3851.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(346002)(376002)(396003)(39860400002)(136003)(366004)(36916002)(2616005)(966005)(66476007)(5660300002)(36756003)(6916009)(7416002)(44832011)(26005)(31686004)(54906003)(8936002)(16576012)(53546011)(6666004)(66946007)(86362001)(4326008)(16526019)(83380400001)(956004)(186003)(6486002)(2906002)(31696002)(107886003)(316002)(66556008)(8676002)(478600001)(43740500002)(45980500001);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?utf-8?B?ZGgxR3NhbldmNklyM2lLOFhzNTRWanB3STJ4Sm9yYWhhL0JnT0phUldveUVl?=
 =?utf-8?B?eWd1bW00OHJMUEJNcVVDYzhQSm9lZ0NYRGJJbFNweS9YcUF4REk4MURacW8x?=
 =?utf-8?B?NGJnb3I4M1hqYWhOVVBCZDYzd1JneGRua1krZVh0NmFCUm5aVTRBdzJuYVFV?=
 =?utf-8?B?UUpLK0hEZ1FWZFdmTFdBM2liV1p4ZlpFenhsK1dPRzRJc2htSWxUMmhFaEQy?=
 =?utf-8?B?ajR5WWNGWjJlNXUzQnhySXlFZERsTUNIZE9ZRWRvbzRldUZ4ZXQ0bW9uc282?=
 =?utf-8?B?ZTMxa3cwdTZnTG9RRmloVWNWMDVVU0VhNDhYVE9jRHBmbnh6QVRRVFVrR09R?=
 =?utf-8?B?bHA3L3dwMmpGYjdJN2xUcnMxdjcrUFFLcnRaeGdYNTBQRUptVVVwRlNvUFIw?=
 =?utf-8?B?bXFkb0FjSlkwTTRwYVlwUmhLQm9sK1UwNG1PdHAyaUlDWnBRQko2S0FYZHhh?=
 =?utf-8?B?QTgvZ080Q0pCeWFDRlRQY3lUR2dzWDZDanBjWHlKRUhYOXY4bk9wRG5uM2s4?=
 =?utf-8?B?R1FkZ1V5NWFpMXB6bEozQzE2NjZuc1hwZVBWQk0vamRseTJxaTJmSmRQQlFw?=
 =?utf-8?B?Q3cxcmhVZyt6WlpJMFZ6elo4TWhSZ2h5QktIeE9zZ0xLY3Bqb2M3R2g2TThO?=
 =?utf-8?B?WWl4ZWRna2s4UjcxK3lzRHppRzk0Ymc2QWdkQkFlT0N3RUZ4WjAwRkFHL3Z1?=
 =?utf-8?B?a0VBbmRIdlRZYUFiTjlYVEtLaE5xU3F1eDJpRUxNMjlBNlNPenYyNUtlUnBX?=
 =?utf-8?B?eklkbytOU1N3SjdtWDJ1eHlNZE9DUCs1S1dSc2RQNk96MnJFRVNjL0cxTnFR?=
 =?utf-8?B?Wlo1d1hnZzFJMGpObmdDQVR1ZXFDZE1IM0RhVldQbE1QUUdRYXhGbS80dEk2?=
 =?utf-8?B?WWdYNUUrZi9oQXlzdHQxL1kwQlo5SG5Fb0NqVlpEUTVrZTdlb001L2xJNkQr?=
 =?utf-8?B?WDR1M0pWQXNRclIwMGU5NUlZVTZkR1g1cGEyVSttOXNrU1FheUxpbVBucCtU?=
 =?utf-8?B?TnNVckdCby9lb2Fsby85M0NEc1MxbnR4aU9rYklUWG9MaW9WUklSc0tjTjM5?=
 =?utf-8?B?cnl2WEFpbkNZTWNuUHZkT2ViMWZjL3MwK3RDbkxOTy80VVRZbXFSdVRWSGtR?=
 =?utf-8?B?akVQZTNDVldhc1dUVEM3bzhKT3R1ekEwWkNkV2ZVL0xkK1FZY3ZjbXN0bDJo?=
 =?utf-8?B?VDlFeURoNmZBQWI3UTRqMWdqSEc5ajVjd1hBU1UrOXJGWUljNU0vQ3lkcEZy?=
 =?utf-8?B?TG5tTXU3U2dNbTBQOHIrT1pVbE9Idmo4WGdhWlRxMTNaMkM0UVpkT0gwMmVN?=
 =?utf-8?B?UlZzMVJtOXV4NW9acEQ0MW02N3pkb291SkJsUlVDT0FLVEdXa1VLYi9wQXY2?=
 =?utf-8?B?bTFWaHMxb3NYc3crUmJNWkFjQlpIbDMrc0tBT3UzWDc0am1iNnpHUmVvOEtL?=
 =?utf-8?B?MVVnVnBZQ2NTTnpLU0twTnlqMlk4ODdveWhKSWxtM0NUUHJaa3AwTXduK0lZ?=
 =?utf-8?B?SWNUQlVVTDM3UUVTZSs2NnRPTVZ4Lzk1Rjd2bFBDRjZQUk4yaVR5N1pQSXJq?=
 =?utf-8?B?clVycW5razU4MGZ2QU5LRzFMcWRLTHB5K0FCMDlzQWVITFBGU3lndFRvY0s3?=
 =?utf-8?B?aUhCSmpUSW81dXRjSEFQSDlEWVdieHJvVHQ2WEhDT0VFNUZFU3IwblBSRDl4?=
 =?utf-8?B?bHhVaHh1bUZ5eUVndGIzN3ZrSnhPbnFhL29pck10QTU0cldvbm9lV1NEMEk5?=
 =?utf-8?Q?UHqtBSUFqsNnFZtoDR1dLCH6J/lqiPYvcPTqJic?=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 4fd063a8-27cf-4c7e-b455-08d8d52ab6d3
X-MS-Exchange-CrossTenant-AuthSource: DM6PR10MB3851.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 19 Feb 2021 23:04:30.8943
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: iZVfAi6pReqbANmjg0VHrdOSm2twugcRW3+Qvz7dQnAerzHb4KHJEH5OjB2CJX+KxlwKvkoadXlbjpP21/dSovRdA4siKOVlMZylAWoM/xs=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR10MB5087
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9900 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 adultscore=0 mlxscore=0
 bulkscore=0 suspectscore=0 malwarescore=0 spamscore=0 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2102190186
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=9900 signatures=668683
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 bulkscore=0 suspectscore=0 mlxscore=0
 phishscore=0 spamscore=0 adultscore=0 clxscore=1015 impostorscore=0
 priorityscore=1501 lowpriorityscore=0 malwarescore=0 mlxlogscore=999
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2009150000
 definitions=main-2102190187
X-Original-Sender: george.kennedy@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=eyu7sxXa;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=pN4FkB9o;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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



On 2/19/2021 11:45 AM, George Kennedy wrote:
>
>
> On 2/18/2021 7:09 PM, Andrey Konovalov wrote:
>> On Fri, Feb 19, 2021 at 1:06 AM George Kennedy
>> <george.kennedy@oracle.com> wrote:
>>>
>>>
>>> On 2/18/2021 3:55 AM, David Hildenbrand wrote:
>>>> On 17.02.21 21:56, Andrey Konovalov wrote:
>>>>> During boot, all non-reserved memblock memory is exposed to the buddy
>>>>> allocator. Poisoning all that memory with KASAN lengthens boot time,
>>>>> especially on systems with large amount of RAM. This patch makes
>>>>> page_alloc to not call kasan_free_pages() on all new memory.
>>>>>
>>>>> __free_pages_core() is used when exposing fresh memory during system
>>>>> boot and when onlining memory during hotplug. This patch adds a new
>>>>> FPI_SKIP_KASAN_POISON flag and passes it to __free_pages_ok() through
>>>>> free_pages_prepare() from __free_pages_core().
>>>>>
>>>>> This has little impact on KASAN memory tracking.
>>>>>
>>>>> Assuming that there are no references to newly exposed pages=20
>>>>> before they
>>>>> are ever allocated, there won't be any intended (but buggy)=20
>>>>> accesses to
>>>>> that memory that KASAN would normally detect.
>>>>>
>>>>> However, with this patch, KASAN stops detecting wild and large
>>>>> out-of-bounds accesses that happen to land on a fresh memory page=20
>>>>> that
>>>>> was never allocated. This is taken as an acceptable trade-off.
>>>>>
>>>>> All memory allocated normally when the boot is over keeps getting
>>>>> poisoned as usual.
>>>>>
>>>>> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>>>>> Change-Id: Iae6b1e4bb8216955ffc14af255a7eaaa6f35324d
>>>> Not sure this is the right thing to do, see
>>>>
>>>> https://lkml.kernel.org/r/bcf8925d-0949-3fe1-baa8-cc536c529860@oracle.=
com=20
>>>>
>>>>
>>>> Reversing the order in which memory gets allocated + used during boot
>>>> (in a patch by me) might have revealed an invalid memory access during
>>>> boot.
>>>>
>>>> I suspect that that issue would no longer get detected with your
>>>> patch, as the invalid memory access would simply not get detected.
>>>> Now, I cannot prove that :)
>>> Since David's patch we're having trouble with the iBFT ACPI table,=20
>>> which
>>> is mapped in via kmap() - see acpi_map() in "drivers/acpi/osl.c". KASAN
>>> detects that it is being used after free when ibft_init() accesses the
>>> iBFT table, but as of yet we can't find where it get's freed (we've
>>> instrumented calls to kunmap()).
>> Maybe it doesn't get freed, but what you see is a wild or a large
>> out-of-bounds access. Since KASAN marks all memory as freed during the
>> memblock->page_alloc transition, such bugs can manifest as
>> use-after-frees.
>
> It gets freed and re-used. By the time the iBFT table is accessed by=20
> ibft_init() the page has been over-written.
>
> Setting page flags like the following before the call to kmap()=20
> prevents the iBFT table page from being freed:

Cleaned up version:

diff --git a/drivers/acpi/osl.c b/drivers/acpi/osl.c
index 0418feb..8f0a8e7 100644
--- a/drivers/acpi/osl.c
+++ b/drivers/acpi/osl.c
@@ -287,9 +287,12 @@ static void __iomem *acpi_map(acpi_physical_address=20
pg_off, unsigned long pg_sz)

 =C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D pg_off >> PAGE_SHIFT;
 =C2=A0=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn)) {
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 struct page *page =3D pfn_to_page(pf=
n);
+
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 if (pg_sz > PAGE_SIZE)
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return NULL=
;
-=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return (void __iomem __force *)kmap(=
pfn_to_page(pfn));
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 SetPageReserved(page);
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return (void __iomem __force *)kmap(=
page);
 =C2=A0=C2=A0=C2=A0=C2=A0 } else
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return acpi_os_ioremap(pg_off,=
 pg_sz);
 =C2=A0}
@@ -299,9 +302,12 @@ static void acpi_unmap(acpi_physical_address=20
pg_off, void __iomem *vaddr)
 =C2=A0=C2=A0=C2=A0=C2=A0 unsigned long pfn;

 =C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D pg_off >> PAGE_SHIFT;
-=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn))
-=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 kunmap(pfn_to_page(pfn));
-=C2=A0=C2=A0=C2=A0 else
+=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn)) {
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 struct page *page =3D pfn_to_page(pf=
n);
+
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 ClearPageReserved(page);
+=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 kunmap(page);
+=C2=A0=C2=A0=C2=A0 } else
 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 iounmap(vaddr);
 =C2=A0}

David, the above works, but wondering why it is now necessary. kunmap()=20
is not hit. What other ways could a page mapped via kmap() be unmapped?

Thank you,
George

>
> diff --git a/drivers/acpi/osl.c b/drivers/acpi/osl.c
> index 0418feb..41c1bbd 100644
> --- a/drivers/acpi/osl.c
> +++ b/drivers/acpi/osl.c
> @@ -287,9 +287,14 @@ static void __iomem=20
> *acpi_map(acpi_physical_address pg_off, unsigned long pg_sz)
>
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D pg_off >> PAGE_SHIFT;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn)) {
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 struct page *page =3D=C2=A0 pfn_to_page(pfn);
> +
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 if (pg_sz > PAGE_SIZE)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return N=
ULL;
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 return (void __iomem __force *)kmap(pfn_to_page(pfn));
> +
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 page->flags |=3D ((1UL << PG_unevictable) | (1UL <<=20
> PG_reserved) | (1UL << PG_locked));
> +
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 return (void __iomem __force *)kmap(page);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 } else
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 return acpi_os_ioremap(pg_off, pg_sz);
> =C2=A0}
>
> Just not sure of the correct way to set the page flags.
>
> George
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/797fae72-e3ea-c0b0-036a-9283fa7f2317%40oracle.com.
