Return-Path: <kasan-dev+bncBAABBK552WXAMGQEEZKYNMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D5FB85CDEA
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 03:23:41 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-42e12a1fd69sf90461cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 18:23:41 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708482220; cv=pass;
        d=google.com; s=arc-20160816;
        b=c+y8mOtWtkkJd/yCzlW4SQXLgSWn4u5EBuDwK0AW50Qf/UmaOSc3+zc+I92YmcBjLu
         1Jl2bg8J2St98U5AfdMTRTrCbysN6xRlu3VD0MU4BqMyN9wi9RuYno2uqoSy4tmenicg
         AKpEgRrRYQD74F3AsLFlOFS2UaKtah2YG//jmE5v5AvbYUmxCi8bzgGPnAEj3Hnpfwp7
         NrA0y1Y+je4jQLnC83EspBwnCDu5BhEIYt7pnqlpKGgNB6bSolTzP6YfbDpGoa7wcb8r
         kp8ROmpkCWhlYXdGsLjqPDQxLbo7qP85mXTNLBAz+CueJEx0XudRfJngCU1c93oJYser
         72TQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=OSrK/nRyuGb4XMxspiZ+lujVOmlnJjHIviMMj1Er/hU=;
        fh=/ydOXMgKs4TFTvOozs64sQx+NTzoTQe39D9vWo7xqYs=;
        b=lrHKU0KgUy3w6YaOlBUqEiGL0kPEjQnjSJed0/ij4pnQtTSxl2qnAHg0wzerkSofqA
         RSoZjGcq5nXGi4UuLFnmW2FuaTvjq6bmxoGyd+nhbxtMcEaIsbO/i6YP02seGf/FSCbO
         N2550CsoZnCBu1lnJ1xUPdsVwvE/6nAjqAB8bIGab6oa89SyeIEnABvWBbCOsaeOzLFE
         DUVdOoaCd/fEQ/uWA7xzpegF6mQ3BvsdjWUURLYP/q5OL2f7cVo9+ybO0+kQ57owPOlN
         oXn6uU0fvQSeaU33ZdVBbDqtT0eQR91a2svNr/yxiuf3LR7kPf2qHQGkgY7EHVXEO8Wi
         /SqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@windriver.com header.s=PPS06212021 header.b="gitt4S/C";
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of prvs=27813ddd7c=xiongwei.song@windriver.com designates 205.220.178.238 as permitted sender) smtp.mailfrom="prvs=27813ddd7c=xiongwei.song@windriver.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=windriver.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708482220; x=1709087020; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OSrK/nRyuGb4XMxspiZ+lujVOmlnJjHIviMMj1Er/hU=;
        b=i386q9HKMACvlOJER0Ng5UI6iWI+uOh6qcR3gHn1mm7h2GPBQjBrpDGGwFioo7Fs/2
         KZ8nR/zIcm3uS05aR1us3OkiNUbQwazvmJTAewe4Bn9M4AJc6J9k2tQkTBxF98SYFWl3
         xfrX0EQ13NDWe0hR5Gkd8F9hl9lBc6e+XEPlbpIle2QTpAIfaPJCjyHPoEs3JPrr2gCc
         xU84Wx3emC8+UTGFUYD/2WYkqElEMOO26yX1KuY0Ys4Ao7DtK6HHq374kqEOFz42zxrU
         63BB+hCKil20gnzp6SeXkz7LMvpyW3H1JVzRtV/loedxaYmk+7/OwBy/8ovSXpC6LSxU
         eGug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708482220; x=1709087020;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=OSrK/nRyuGb4XMxspiZ+lujVOmlnJjHIviMMj1Er/hU=;
        b=eQ8rRcYRdYttUqLVrMwSGM3CorCInbIx/aNdIjE1/Fl0DfWVqIqJqbT3sIXS3fjjuC
         TK6d28E6zCYjt/cQmClMQ/gYLfPbupQeRLyQUW3abLeLZYpVlf2OI6vFfZZYEGM4gLlv
         PoLKhHGmqexG8KIBrHm4tooWZCF6xP1wFxdj2zIwTsy1snkKX2bD4yFTsRVp/dwDQ+04
         G62e76BrI2gdt1H8b6jL9FXFhbDjcSt1TQR5Qhd8sP/CYKNpHYqD81ECIUxP4xq7m+bc
         Fp14u/z3Q4X9oacB7/4BzH8kCbnMAc3KxpQbhB334TMhtG7TpeqHLkHoxuCH5JOvEzF1
         4bjA==
X-Forwarded-Encrypted: i=3; AJvYcCVCkqOr5JcorYtB6WXKNIAUWvPuuYJp8L3Crp9GdvHKZfQXtMpetR5/0qZCh1Jh4u3NGwVyRobX3YLrnfvdcCqOOKWDtH6tXg==
X-Gm-Message-State: AOJu0YzUcZqZhrMNeIlzApXVuYNjGCvye+L/D6Y+tlloD8rW+NxcHpd6
	k+lEiDCIlcdzXLoo/Mi/uioXUTmbW/s/xIw1KGYEXbbpfg0aHD8q
X-Google-Smtp-Source: AGHT+IHxIA8uRmuern2sP1B55MCe9Y6WAdliKmwz6RBj/EuAjy6SpZ20HFsjXmivCg/3ODetBLQlZQ==
X-Received: by 2002:ac8:648:0:b0:42e:2b90:a632 with SMTP id e8-20020ac80648000000b0042e2b90a632mr67244qth.19.1708482219978;
        Tue, 20 Feb 2024 18:23:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7d96:0:b0:42e:2493:b104 with SMTP id c22-20020ac87d96000000b0042e2493b104ls1475437qtd.0.-pod-prod-00-us;
 Tue, 20 Feb 2024 18:23:39 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVOFi54J34sT+ye8Hp5sEQpizYUs7Fr4XS2nrw8IFZviM+gYF6OLxg1E52MiK7sBXxgk7x2mbfoRUxzqWef92ayNAQSc182QmFa5Q==
X-Received: by 2002:a67:c48a:0:b0:470:3db6:430b with SMTP id d10-20020a67c48a000000b004703db6430bmr8890370vsk.11.1708482219329;
        Tue, 20 Feb 2024 18:23:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708482219; cv=pass;
        d=google.com; s=arc-20160816;
        b=neCK20gOQvsokU7ety14UsDhdKzZL1JfPbRvNyS+UpSfu79vQvwOZus2yqXI2ckN0U
         MImUkqilbzDJE7kw2iLr9BpgjNaocs6flH91I4QmuOOZpR2ih9fxJpfo+nImyzfwRQcc
         2UPMmZlvHMF2s3UMvTs3z85bAlhyiTyFV5roOR6984d7LQPtlUZtX75xPrrxVb0gKFIJ
         kuektnyllgdIV0eZiQwOeuU/S9y/CeycDXzhq+LUTEzlldwKqIYSQKEIj6pg3aYOmjX0
         pIunKRPOw9+YGWV8MVPDALle1UCp7zPlBDoxMwPdAnnElquYPKW/cl4gJMhqZTTVNjto
         X3nA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=0wZ01ZxEJQUKXVgIscLIuzag/LcN+HEsW3HBCvRHbko=;
        fh=Ah6r3UfbxXHVSN69qhRhgXePou4OMOfcO152A0MToiA=;
        b=JlD5FjMB0MgAaGlqDx466VTwLuZXeqHA5ywe/cY+xSfYxiONmweVKafdgXJFcSHja/
         4iaHcEgaOTi0NWsgd0YN9H3HU9AHtupx5VjpdzV8FVVQErll14GEAbMYC0MPesrLLOTq
         WPgVBuSrizLJnExJbCpRs9ruq+C//G3kYMtNlSDKl5U6y/vgXRIsGc+1ozKRs1IjL6t3
         Luxrh/Gq5CrTfyhvsEJhJAzq1J1w+dhGGNTdEJPdU2l/aAshozw9Z+oBWv0671CECmb9
         To/keCW4N8saE+3cTPoxB6PUrcChVdBfeRtFlo6xxbVyygWBz62bjsB9apb+XGbcdAvE
         9Luw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@windriver.com header.s=PPS06212021 header.b="gitt4S/C";
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of prvs=27813ddd7c=xiongwei.song@windriver.com designates 205.220.178.238 as permitted sender) smtp.mailfrom="prvs=27813ddd7c=xiongwei.song@windriver.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=windriver.com
Received: from mx0b-0064b401.pphosted.com (mx0b-0064b401.pphosted.com. [205.220.178.238])
        by gmr-mx.google.com with ESMTPS id z20-20020a67ec54000000b0046d3d08309esi770167vso.1.2024.02.20.18.23.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Feb 2024 18:23:39 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=27813ddd7c=xiongwei.song@windriver.com designates 205.220.178.238 as permitted sender) client-ip=205.220.178.238;
Received: from pps.filterd (m0250811.ppops.net [127.0.0.1])
	by mx0a-0064b401.pphosted.com (8.17.1.24/8.17.1.24) with ESMTP id 41L1qm5d006859;
	Wed, 21 Feb 2024 02:23:33 GMT
Received: from nam04-mw2-obe.outbound.protection.outlook.com (mail-mw2nam04lp2168.outbound.protection.outlook.com [104.47.73.168])
	by mx0a-0064b401.pphosted.com (PPS) with ESMTPS id 3wd2178ag0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 21 Feb 2024 02:23:32 +0000 (GMT)
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=TPBahXN7RX37s1gumNsxsNIJ1cJ/uHfMzhzqKZviIRk0+fvI3dZkQT+NKczhH9XUwZcKhkUIHJE3gKMJ4ASmojTcgWsHs3O7uGzdvLlChUTEOtUQyP+I7Rvqy0jTcQcLFsqj57IqN17pnZKZcU5ChzYUbagLnMZTOgQG4vnTsqIkVR06D5Ug7CP0ohSAoVm/myUT6XOXeYoLtIa4IT+bfqQbEh4sxGRWF9rFbhYRdZ5SIh7BAzqp03agDx9iNTiwU7qMu99YV7BPTW13ZyAJGiJ/Z+4X/OmOfwNQc5hSRMuHMs2K/FiSOWIm7n5Rn3JnbaCF2irr86aXi3DHvpvN7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=0wZ01ZxEJQUKXVgIscLIuzag/LcN+HEsW3HBCvRHbko=;
 b=PWZg2dwUw4K1oUU6L31sIdRgNs7cL0wavMObSrosx6DUtDvJuGfC6HDvFKLjAp2P8YPdoPtMjJYXjkXu7W8Py3UP5naAonFJ6phy8mWGhB7v8x/l47Wbt4pUY0YHTaO3vvI3AbDCtKALtJPRQmXd6sBxCqph+kbqk1rOrsDZkBOEA7BSVI6fDGtRJGQIyo2apeqzZLTrnT4749aLpnVu2ZG1hdXbU9sEnBL4fgMEsGmJC1Un+9OEfo0jAVnTLOKpR1pq1wtKuJVrTMx3CvbOnegJ6eySlDkMMH/zKk5rzaTBFjaBotbknEbKG8xDWu1gXWZqx/x/BMil5OTKj1GPqg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=windriver.com; dmarc=pass action=none
 header.from=windriver.com; dkim=pass header.d=windriver.com; arc=none
Received: from PH0PR11MB5192.namprd11.prod.outlook.com (2603:10b6:510:3b::9)
 by SJ2PR11MB8538.namprd11.prod.outlook.com (2603:10b6:a03:578::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7292.39; Wed, 21 Feb
 2024 02:23:30 +0000
Received: from PH0PR11MB5192.namprd11.prod.outlook.com
 ([fe80::230c:58c0:c3f9:b5f3]) by PH0PR11MB5192.namprd11.prod.outlook.com
 ([fe80::230c:58c0:c3f9:b5f3%3]) with mapi id 15.20.7292.036; Wed, 21 Feb 2024
 02:23:30 +0000
From: "'Song, Xiongwei' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
        Pekka
 Enberg <penberg@kernel.org>,
        David Rientjes <rientjes@google.com>,
        Joonsoo
 Kim <iamjoonsoo.kim@lge.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Hyeonggon Yoo
	<42.hyeyoo@gmail.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander
 Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino
	<vincenzo.frascino@arm.com>
CC: Zheng Yejian <zhengyejian1@huawei.com>,
        Chengming Zhou
	<chengming.zhou@linux.dev>,
        "linux-mm@kvack.org" <linux-mm@kvack.org>,
        "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
        "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: RE: [PATCH 2/3] mm, slab: use an enum to define SLAB_ cache creation
 flags
Thread-Topic: [PATCH 2/3] mm, slab: use an enum to define SLAB_ cache creation
 flags
Thread-Index: AQHaZB4Vv6+1rZm7vkyKrrwrlEStt7EUEDaw
Date: Wed, 21 Feb 2024 02:23:30 +0000
Message-ID: <PH0PR11MB51929679F8256CDE50F46F87EC572@PH0PR11MB5192.namprd11.prod.outlook.com>
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
 <20240220-slab-cleanup-flags-v1-2-e657e373944a@suse.cz>
In-Reply-To: <20240220-slab-cleanup-flags-v1-2-e657e373944a@suse.cz>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PH0PR11MB5192:EE_|SJ2PR11MB8538:EE_
x-ms-office365-filtering-correlation-id: ebc42f19-be8e-4ce6-b9a1-08dc3284185a
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 6goCws9gV2w92aV3QNH8pu6i11gPyfzUpPO+1EztW0rPXuNrqDw0YaY3vPJYxbToR90+oU/G4GFFDGKfnGAkNlVFGQ4pYEruoEJ9t9jYAX+8ileUR51vpYBW0KSfKKF8H2NyhEnOZcrKmpJ4TcFRbLGNzzE8LeF3NFDE9wMv48Gs5NeE80oVdC6f2YJvKXTAKNGvcD7dXBeivnlaDf4d3VCpm1gsDoCwOE3EdEo4U8+xXXBX25ufxv3jZ1swk8RXa4eMF53hOmHtP/aKJaj7Gja+CUr7zMDJobqdx+U/+RLIpOKIMOkOeGTLT8UA3btOr/IPcVDRTCmIR7oY+NC7m6EjjWpVk1u65ACR3PUPQkzwwg5wiY/LnWO3Yu7FfEapADTSQ4KY9//ZxAJMuIBZ19gZM7LN8p6pAAggzA8vA4hAN3/lpqblKqcp/XarNhhmpGuhxWkKGC0htEcugkGq7bQP7dnWJz7QJ6sWXp0fPKfDcJx2baATGXxcOXg8E4zBXxLQr2Eg5riOMExpX3ZrbT/GCXw+S2HYahxS5uy8UeWin8+VMiry862mPLSIogCixIVFHlVh4YBsba8sD+h73gXUwd3z8knmDGLagVCKyEEJqyMEu7VOAgZ/as4c8WBgrHFRpSqJURW030bReuJi6Q==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR11MB5192.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(230273577357003)(921011)(38070700009);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?cEpodTJEd09zYkkxZ25Cc0I3SE9ZNEpSOXViQzhXYWFSY2hHaHNsZjhzUGhL?=
 =?utf-8?B?OXpRS09TeXJYZ2R3dFp5cVZ1M1FGcUc2dUlIRlJneXB6S1dEUm1ySnBlWG9p?=
 =?utf-8?B?NjR1WDhwOTYwM3F5dEhGcVBZVCt6SlR5M1lWWXpEV0NSV3hMMm5WVERpdEdX?=
 =?utf-8?B?UmMvTkJoVnBPc2Y4cGJ4UjFzendjUjhnQm5tUitFRFh5aG8welFVdm9zekFU?=
 =?utf-8?B?VHpvZW1oa2Rja3FuWGdjcEgvQkNQSkoyNC9lL3dzcUtVTUZsR0Y3dWNrVU8v?=
 =?utf-8?B?aFJud0pRSUcrK3EyQWJOcUJhY0hhcUVra0kxUnNUaG5UMkxtWnNTdkJqajR0?=
 =?utf-8?B?U01vRk0wWW84WkRjMkVXU2xXeDlvdUN2UE5DcTd3N1FUcnBYazIza1BtMWZH?=
 =?utf-8?B?ZWRqekJlVGZkZVA3UzlIZVpJWnJPY1BST3hmTkdzNTRXQzA2Y3RQM0l2Mlg1?=
 =?utf-8?B?VkUvMDZnckJsRXpVT25ubHpyQldjOHcrYzVua01jd2piVUlrS21FVm5GOGRV?=
 =?utf-8?B?amluWnN3NzMrVkpGOTlHMTdMQ3pmQm5mRGorL1NCQ25BZWhRUk1OWEM0b1I0?=
 =?utf-8?B?RzhlRk5NSU02Zzk1UzFpQnJ3anhJa0x3czdXbHpFS0g1eDJrU3l1Ty9lT1Ns?=
 =?utf-8?B?eUtFZDNkUTJWOUw5Q08vN2tObjcwMEptZXVQK09WaXpmQ2d0NEN6SmZ3QUlC?=
 =?utf-8?B?L0F6bFBVY0p5aStLTmM5ZlhrQXN1MmJUbXRyOCtJd3V2L0phNEF6eldTNzUy?=
 =?utf-8?B?QmlrOWxoYWpqalVBNDZNbndRYTI3eTlwa25IbWJSYitDZDlOcXV3YlR2L2tn?=
 =?utf-8?B?UlpXQVpKaXdBL0dTUFRJNUd0bk9hL3hDZWpxTFZQdWhkV284TitLSEhDRVU2?=
 =?utf-8?B?SG84NzNycFd4RGJGbGNxMGZKdzFibVcrRDlkenpOU0l5NjdrSVp5OXh1ekR2?=
 =?utf-8?B?MTh2NlFpS1RqVkJOb1VmRG9jTlJsaHpQYXh0ZHlzRjZuL1pSendBQ2s2ZmRH?=
 =?utf-8?B?ZU16YkV2ZnJ0ZmNYcmxPb3NGZUlUSEdUVGNjT3UzdDVFUlZISjJsTC9TcnRC?=
 =?utf-8?B?Z0srUWV5S3JNRjA4d2owYm1lajB6QXpXalFJTDJCRWRkbHRvNzRBUEl0L2M0?=
 =?utf-8?B?NWhkSHh4ZnFGTUoyL1krQTdyRE1yR1d0K3E3bHc1eGVTVFg5Qy9VUkgvMzNn?=
 =?utf-8?B?MTV4YkdZcHlpVmQ2V1JYYUtkZ05sTE82b1J0UkFLNGxPNWVBTm95QTc3QjVa?=
 =?utf-8?B?TWtYYkdxeEtUNk5uMjNXTW5ROVprRXVoeXBHVFJXaXVXbVBHQXJyMWdmeXQy?=
 =?utf-8?B?TkNFQzFxdCtyUFlkbnVKUS82ZDB2Z2hPSFlsckxleGFjUWZxeHYvU2I1cnJ1?=
 =?utf-8?B?cHF1MGQva0pWbHRGYk5mUWhSWFBjU1lKLzBSenhnWlh1RFlRNUFBcGttVHUz?=
 =?utf-8?B?N3ZmV1JwNVBTTjNNVXoyUDIwN3dFd3RBK3pBM0NsY1VEZE1GK1hVSmY2RmRV?=
 =?utf-8?B?eFBZQjJZSlQ1bGZjZVVVSzF5TVdqbTNYWHBWcG5kYi9DYjBxQ1pBM2hCS1Rj?=
 =?utf-8?B?VEhkd0E3b3JpdkdEODZiZ1FjemNmS2s0Q1M3R1BOZU50NW5mUWp0Ym51clRP?=
 =?utf-8?B?Ri92WUxWb2lNQjlEWEgyUFI4dDR5blg3UFNnV0lkY3BVaURReXpIYVFVNzBm?=
 =?utf-8?B?Ym9DM1VhVVNaVlJ2N2duaG0zUHRad0pHeWhKMktOem1iZ1djTW5xQ2lGY083?=
 =?utf-8?B?WkFiajhQdGk5S1NvOGI1RDQ0VXFRTEd5NC90b2lQTjJZOXp5SWNaV0RKamho?=
 =?utf-8?B?S0NJSWtuS2k2M0tkcTNmWlFWb2VESDVVTUMvOGlhd0RmRzhEOVQ5N0pqVEpj?=
 =?utf-8?B?RkVxcGVyODBQTlN5bmtQL2wvYjNDUnkrQkhBeUtoekhFRVdLeGpwY2hib2M0?=
 =?utf-8?B?WHJsM0hzNWJ5Z043UThrbFZFWUdYVHE2TGwwUVlmb25JRjRhN0hiaWlpUHVU?=
 =?utf-8?B?c0FsSHRmMHlvM0cxVDFOY1lNOVhvQ3RWL2doalpZMFRZT2dQRmxEdGVKb25P?=
 =?utf-8?B?OHRGenN5emdyOUQ4MFkvMjErTjVIVE1wdVlVZks2RWc4Qk1ZZWg4cDgyWjY0?=
 =?utf-8?B?ZWxqZEhLRTJPWFMwd3IrckJkTm5JMVhXYWphMVIvR08wMWdSQnhjTFVIU0Jp?=
 =?utf-8?B?L0E9PQ==?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-OriginatorOrg: windriver.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PH0PR11MB5192.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ebc42f19-be8e-4ce6-b9a1-08dc3284185a
X-MS-Exchange-CrossTenant-originalarrivaltime: 21 Feb 2024 02:23:30.5378
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 8ddb2873-a1ad-4a18-ae4e-4644631433be
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: 3mRYSuu4oyzLtkZbgWcWLwkCq2dyrAR5ZpcmJGiof2E2UmlArOq28YGpV/Y65Du58p3VHPzuER5saNTp8p++poQbmSPwQ8+09ti/KMfWwb8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ2PR11MB8538
X-Proofpoint-GUID: 9sp9G0-TpCfdVYeyMRdhtZ2quAgPrmS5
X-Proofpoint-ORIG-GUID: 9sp9G0-TpCfdVYeyMRdhtZ2quAgPrmS5
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-02-20_06,2024-02-20_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 impostorscore=0 suspectscore=0 malwarescore=0 spamscore=0 bulkscore=0
 clxscore=1015 adultscore=0 mlxlogscore=548 lowpriorityscore=0 mlxscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2402120000 definitions=main-2402210014
X-Original-Sender: xiongwei.song@windriver.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@windriver.com header.s=PPS06212021 header.b="gitt4S/C";
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass
 dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);       spf=pass
 (google.com: domain of prvs=27813ddd7c=xiongwei.song@windriver.com designates
 205.220.178.238 as permitted sender) smtp.mailfrom="prvs=27813ddd7c=xiongwei.song@windriver.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=windriver.com
X-Original-From: "Song, Xiongwei" <Xiongwei.Song@windriver.com>
Reply-To: "Song, Xiongwei" <Xiongwei.Song@windriver.com>
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


> The values of SLAB_ cache creation flagsare defined by hand, which is

A blank space missed between flags and are.

> tedious and error-prone. Use an enum to assign the bit number and a
> __SF_BIT() macro to #define the final flags.
> 
> This renumbers the flag values, which is OK as they are only used
> internally.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Ran a rough test with build and bootup with the related debug configs enabled,
feel free to add

Tested-by: Xiongwei Song <xiongwei.song@windriver.com>
Reviewed-by: Xiongwei Song <xiongwei.song@windriver.com>

Thanks,
Xiognwei
> ---
>  include/linux/slab.h | 81 ++++++++++++++++++++++++++++++++++++++--------------
>  mm/slub.c            |  6 ++--
>  2 files changed, 63 insertions(+), 24 deletions(-)
> 
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 6252f44115c2..f893a132dd5a 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -21,29 +21,68 @@
>  #include <linux/cleanup.h>
>  #include <linux/hash.h>
> 
> +enum _slab_flag_bits {
> +       _SLAB_CONSISTENCY_CHECKS,
> +       _SLAB_RED_ZONE,
> +       _SLAB_POISON,
> +       _SLAB_KMALLOC,
> +       _SLAB_HWCACHE_ALIGN,
> +       _SLAB_CACHE_DMA,
> +       _SLAB_CACHE_DMA32,
> +       _SLAB_STORE_USER,
> +       _SLAB_PANIC,
> +       _SLAB_TYPESAFE_BY_RCU,
> +       _SLAB_TRACE,
> +#ifdef CONFIG_DEBUG_OBJECTS
> +       _SLAB_DEBUG_OBJECTS,
> +#endif
> +       _SLAB_NOLEAKTRACE,
> +       _SLAB_NO_MERGE,
> +#ifdef CONFIG_FAILSLAB
> +       _SLAB_FAILSLAB,
> +#endif
> +#ifdef CONFIG_MEMCG_KMEM
> +       _SLAB_ACCOUNT,
> +#endif
> +#ifdef CONFIG_KASAN_GENERIC
> +       _SLAB_KASAN,
> +#endif
> +       _SLAB_NO_USER_FLAGS,
> +#ifdef CONFIG_KFENCE
> +       _SLAB_SKIP_KFENCE,
> +#endif
> +#ifndef CONFIG_SLUB_TINY
> +       _SLAB_RECLAIM_ACCOUNT,
> +#endif
> +       _SLAB_OBJECT_POISON,
> +       _SLAB_CMPXCHG_DOUBLE,
> +       _SLAB_FLAGS_LAST_BIT
> +};
> +
> +#define __SF_BIT(nr)   ((slab_flags_t __force)(1U << (nr)))
> 
>  /*
>   * Flags to pass to kmem_cache_create().
>   * The ones marked DEBUG need CONFIG_SLUB_DEBUG enabled, otherwise are no-op
>   */
>  /* DEBUG: Perform (expensive) checks on alloc/free */
> -#define SLAB_CONSISTENCY_CHECKS        ((slab_flags_t __force)0x00000100U)
> +#define SLAB_CONSISTENCY_CHECKS        __SF_BIT(_SLAB_CONSISTENCY_CHECKS)
>  /* DEBUG: Red zone objs in a cache */
> -#define SLAB_RED_ZONE          ((slab_flags_t __force)0x00000400U)
> +#define SLAB_RED_ZONE          __SF_BIT(_SLAB_RED_ZONE)
>  /* DEBUG: Poison objects */
> -#define SLAB_POISON            ((slab_flags_t __force)0x00000800U)
> +#define SLAB_POISON            __SF_BIT(_SLAB_POISON)
>  /* Indicate a kmalloc slab */
> -#define SLAB_KMALLOC           ((slab_flags_t __force)0x00001000U)
> +#define SLAB_KMALLOC           __SF_BIT(_SLAB_KMALLOC)
>  /* Align objs on cache lines */
> -#define SLAB_HWCACHE_ALIGN     ((slab_flags_t __force)0x00002000U)
> +#define SLAB_HWCACHE_ALIGN     __SF_BIT(_SLAB_HWCACHE_ALIGN)
>  /* Use GFP_DMA memory */
> -#define SLAB_CACHE_DMA         ((slab_flags_t __force)0x00004000U)
> +#define SLAB_CACHE_DMA         __SF_BIT(_SLAB_CACHE_DMA)
>  /* Use GFP_DMA32 memory */
> -#define SLAB_CACHE_DMA32       ((slab_flags_t __force)0x00008000U)
> +#define SLAB_CACHE_DMA32       __SF_BIT(_SLAB_CACHE_DMA32)
>  /* DEBUG: Store the last owner for bug hunting */
> -#define SLAB_STORE_USER                ((slab_flags_t __force)0x00010000U)
> +#define SLAB_STORE_USER                __SF_BIT(_SLAB_STORE_USER)
>  /* Panic if kmem_cache_create() fails */
> -#define SLAB_PANIC             ((slab_flags_t __force)0x00040000U)
> +#define SLAB_PANIC             __SF_BIT(_SLAB_PANIC)
>  /*
>   * SLAB_TYPESAFE_BY_RCU - **WARNING** READ THIS!
>   *
> @@ -95,19 +134,19 @@
>   * Note that SLAB_TYPESAFE_BY_RCU was originally named SLAB_DESTROY_BY_RCU.
>   */
>  /* Defer freeing slabs to RCU */
> -#define SLAB_TYPESAFE_BY_RCU   ((slab_flags_t __force)0x00080000U)
> +#define SLAB_TYPESAFE_BY_RCU   __SF_BIT(_SLAB_TYPESAFE_BY_RCU)
>  /* Trace allocations and frees */
> -#define SLAB_TRACE             ((slab_flags_t __force)0x00200000U)
> +#define SLAB_TRACE             __SF_BIT(_SLAB_TRACE)
> 
>  /* Flag to prevent checks on free */
>  #ifdef CONFIG_DEBUG_OBJECTS
> -# define SLAB_DEBUG_OBJECTS    ((slab_flags_t __force)0x00400000U)
> +# define SLAB_DEBUG_OBJECTS    __SF_BIT(_SLAB_DEBUG_OBJECTS)
>  #else
>  # define SLAB_DEBUG_OBJECTS    0
>  #endif
> 
>  /* Avoid kmemleak tracing */
> -#define SLAB_NOLEAKTRACE       ((slab_flags_t __force)0x00800000U)
> +#define SLAB_NOLEAKTRACE       __SF_BIT(_SLAB_NOLEAKTRACE)
> 
>  /*
>   * Prevent merging with compatible kmem caches. This flag should be used
> @@ -119,23 +158,23 @@
>   * - performance critical caches, should be very rare and consulted with slab
>   *   maintainers, and not used together with CONFIG_SLUB_TINY
>   */
> -#define SLAB_NO_MERGE          ((slab_flags_t __force)0x01000000U)
> +#define SLAB_NO_MERGE          __SF_BIT(_SLAB_NO_MERGE)
> 
>  /* Fault injection mark */
>  #ifdef CONFIG_FAILSLAB
> -# define SLAB_FAILSLAB         ((slab_flags_t __force)0x02000000U)
> +# define SLAB_FAILSLAB         __SF_BIT(_SLAB_FAILSLAB)
>  #else
>  # define SLAB_FAILSLAB         0
>  #endif
>  /* Account to memcg */
>  #ifdef CONFIG_MEMCG_KMEM
> -# define SLAB_ACCOUNT          ((slab_flags_t __force)0x04000000U)
> +# define SLAB_ACCOUNT          __SF_BIT(_SLAB_ACCOUNT)
>  #else
>  # define SLAB_ACCOUNT          0
>  #endif
> 
>  #ifdef CONFIG_KASAN_GENERIC
> -#define SLAB_KASAN             ((slab_flags_t __force)0x08000000U)
> +#define SLAB_KASAN             __SF_BIT(_SLAB_KASAN)
>  #else
>  #define SLAB_KASAN             0
>  #endif
> @@ -145,10 +184,10 @@
>   * Intended for caches created for self-tests so they have only flags
>   * specified in the code and other flags are ignored.
>   */
> -#define SLAB_NO_USER_FLAGS     ((slab_flags_t __force)0x10000000U)
> +#define SLAB_NO_USER_FLAGS     __SF_BIT(_SLAB_NO_USER_FLAGS)
> 
>  #ifdef CONFIG_KFENCE
> -#define SLAB_SKIP_KFENCE       ((slab_flags_t __force)0x20000000U)
> +#define SLAB_SKIP_KFENCE       __SF_BIT(_SLAB_SKIP_KFENCE)
>  #else
>  #define SLAB_SKIP_KFENCE       0
>  #endif
> @@ -156,9 +195,9 @@
>  /* The following flags affect the page allocator grouping pages by mobility */
>  /* Objects are reclaimable */
>  #ifndef CONFIG_SLUB_TINY
> -#define SLAB_RECLAIM_ACCOUNT   ((slab_flags_t __force)0x00020000U)
> +#define SLAB_RECLAIM_ACCOUNT   __SF_BIT(_SLAB_RECLAIM_ACCOUNT)
>  #else
> -#define SLAB_RECLAIM_ACCOUNT   ((slab_flags_t __force)0)
> +#define SLAB_RECLAIM_ACCOUNT   0
>  #endif
>  #define SLAB_TEMPORARY         SLAB_RECLAIM_ACCOUNT    /* Objects are short-lived */
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 2ef88bbf56a3..a93c5a17cbbb 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -306,13 +306,13 @@ static inline bool kmem_cache_has_cpu_partial(struct
> kmem_cache *s)
> 
>  /* Internal SLUB flags */
>  /* Poison object */
> -#define __OBJECT_POISON                ((slab_flags_t __force)0x80000000U)
> +#define __OBJECT_POISON                __SF_BIT(_SLAB_OBJECT_POISON)
>  /* Use cmpxchg_double */
> 
>  #ifdef system_has_freelist_aba
> -#define __CMPXCHG_DOUBLE       ((slab_flags_t __force)0x40000000U)
> +#define __CMPXCHG_DOUBLE       __SF_BIT(_SLAB_CMPXCHG_DOUBLE)
>  #else
> -#define __CMPXCHG_DOUBLE       ((slab_flags_t __force)0U)
> +#define __CMPXCHG_DOUBLE       0
>  #endif
> 
>  /*
> 
> --
> 2.43.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/PH0PR11MB51929679F8256CDE50F46F87EC572%40PH0PR11MB5192.namprd11.prod.outlook.com.
