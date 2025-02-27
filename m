Return-Path: <kasan-dev+bncBAABBP6PQG7AMGQEZXOH4BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5ACE1A47F01
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2025 14:25:21 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id 46e09a7af769-72737f93386sf100393a34.3
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2025 05:25:21 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1740662720; cv=pass;
        d=google.com; s=arc-20240605;
        b=f5/FdMrdN0Vu+7ylZGVWTKyl/PdgEVkiRwa5O3PRVG5RNy87AYENwjeW75XoJvyuxc
         tBmVT9a01z8O7ae5GprAi5qETvVLAsBgxHNZ0Y4taVqCdDmYRexSQqY4ScKCkorBW6kC
         uH2xCJhapwocu4QhWUu0glpK1z//yjfnlfOTIweIV+O/dm/oenpMi1gfqZH94OOAopK3
         9Dd63FEQf9AxQ5GQUNjc3Gt5kxSogiWCWGR9OUXoosFIclcBhuQ6b04+bOAMqRQuaIOz
         1zZWBKudJXa7JJKNdddwfBhR6obguW8DPcmLYnDAuGqU9u0DHwZ4n/MTNxnbka6OaeQE
         LH8w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :to:from:sender:dkim-signature;
        bh=u3MKUlcsw/I6khXchWu/cTCwcRX6hWluZ6LDuy5SlUs=;
        fh=san7Sf1NfFnDfpYKg1Nk++OZSXFDspogrPam3vLM+lo=;
        b=TBP0bJsjshuxnTmZfJwuTLo5h84lfiH6D/AxjGWR9FTR2XmLlx+Hk6Wl7D7tw4Hp6s
         z8U7pDbblDZ9w8Gnnxrz4NmyZP76LA08r1RTge/WT5MaXUhdNZYV87gz1t/+LPffZHMx
         eFkfIFsdiw7q0xpZK4jYJmK5poUh5stAgFNSoAVYiUtEjTaxX+lnTzUiADO3FkTTZQw0
         dofbAxn6lWNcf7HVBgJMFBHY2M/WFv7n2hO8hPmgcfc95zzW+oZB7TV038/ATF5XqrAU
         qJNQWDB676uZa3Z2hsP1Sd+Za25aph5T523fTzHEbIAZ/beGnuhwfFgLpXVSJxgFsnRT
         QpqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@bigfatlinks.biz header.s=selector1 header.b=TvTyvOW6;
       arc=pass (i=1 spf=pass spfdomain=bigfatlinks.biz dkim=pass dkdomain=bigfatlinks.biz dmarc=pass fromdomain=bigfatlinks.biz);
       spf=pass (google.com: domain of lucy@bigfatlinks.biz designates 2a01:111:f403:c205::5 as permitted sender) smtp.mailfrom=Lucy@bigfatlinks.biz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740662720; x=1741267520; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-language:accept-language
         :message-id:date:thread-index:thread-topic:subject:to:from:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=u3MKUlcsw/I6khXchWu/cTCwcRX6hWluZ6LDuy5SlUs=;
        b=U0G7aplb0jmCpZzCg9FOkvGUMMJPwZ8nNJMOP4uqFP1E81d1/FvT/oYAvl7l9MKta8
         KJELM3f5jYEnlEz63fGZ6XC8CfjB+9b39RRcyx1bTgEObOlSr8zwr4irvSEoLQ6KgNJN
         sGxHud3hfuf2ZDFI9SbYIjT9QizOGJYQNwLJZkfGLuGUgaIhMbOx8ro1YQ0Rf3Qgy7lq
         jxZ1esUGEjQfqdHqxTghWJi76HmeNpjd7sqGqtOz1t9vxDQh1SltKCYs+dv+ywQMLZLs
         KDBquiH/S/cs7E+DSEgWau4dRfSomVgCZbTAQl9yKsecPtrdnReOrH8olrIS76bBjRdO
         QHog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740662720; x=1741267520;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:message-id:date:thread-index
         :thread-topic:subject:to:from:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=u3MKUlcsw/I6khXchWu/cTCwcRX6hWluZ6LDuy5SlUs=;
        b=OLiJwhPuHVHRPoQnjyj872+tlFiZQERIg4DYrgbe05sU0Ife3XkEhBTugNdBxIxlSV
         Rbs3bGJqFQ7hlJa8MK3vTtk4R3UdMCbiYZPcDVZGEGnKiUg+wO+M4mlqLyHa2ECC/S/M
         qL+FLw7LegZRZ/RQLsRO3JpHcVv42jdf7QjKnFpk6qN1ARUovaGX8oEUoz/xAf55Vff9
         8kqGkoe4QUvvhMV+b0TSpWHb0vnTOMcKChhUSVktNeg91FLVAzq4LFplwN19FYNnqTzu
         5s/RQAEIi7PSh65QUc8xzy3FXFFXxf9jpV79ehS+jaCg0WCOeNXR6SxUqCdgu3y85MvU
         pxBA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCWanRCsTXfM8mjPfL5IU7GKtmdJhKF9biFjpoYCHjbjq/+4zWa+FavV9bAAJKtOh5ZzDMEwEw==@lfdr.de
X-Gm-Message-State: AOJu0Ywt4qdhYVZmPnHTqiira0v0d1qmw1ikUHFscL2XCT4nOyFZbpVh
	x6giTOHlFv6LMilAXQgb9oxOFXGaZe4FVP2XKgc0gLaiGz1aTaEF
X-Google-Smtp-Source: AGHT+IFq3x2cdkxcSf5DUxXVC1qTp1Yau2zJRkBoS9vQsEwbFWYaIC7WOgq2NK+zRQtIDs3FwSVlOw==
X-Received: by 2002:a05:6830:6518:b0:727:4576:36f9 with SMTP id 46e09a7af769-7274c4b3465mr18297616a34.3.1740662719773;
        Thu, 27 Feb 2025 05:25:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHvM6ViMgX1xadeyb8Oa5hoN6ztlAR5k17EAkaYIckfFw==
Received: by 2002:a05:6871:530c:b0:2a9:5c2a:c3b8 with SMTP id
 586e51a60fabf-2c1541a8e0fls470389fac.0.-pod-prod-02-us; Thu, 27 Feb 2025
 05:25:19 -0800 (PST)
X-Received: by 2002:a05:6830:6a8b:b0:727:2dca:37c1 with SMTP id 46e09a7af769-7274c4c7b35mr18451590a34.9.1740662719002;
        Thu, 27 Feb 2025 05:25:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740662718; cv=pass;
        d=google.com; s=arc-20240605;
        b=FR6UI6XV2SPZ9T4Ul/8oLScx0UEDUtXQE/XJ3iNeoU+Jv6hyHhUBvgq2SRg4/g9+W1
         LnjstU+Fkk8olp+wBzd7rz8wq8vGbX99qeEX1WXPwo/DJpg+GAa2ssjT6zeSfz1fgUAY
         sX/0spjCKCFm1dO/wzmMhyVtWmKGetIoOs8lwHf6pzGIoDBckz41M3oyoOKs3TUPItYn
         WS96DxvOXLRLn+5A5N/WYbNL8DC8q4lPoEN3uXGBG+aK2SbDT93ESShrTn7FU92TsHNP
         5kobrwLjXMcYAOymCECfr0IihSHPiNtqkpTZYclX/l8QXb3mytKz9GI1xhkVz7bJO/O3
         um2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-language:accept-language:message-id:date
         :thread-index:thread-topic:subject:to:from:dkim-signature;
        bh=6mca+527CKprSCYUPdjxMAwrjmes+Xz64+E6QIXMyhQ=;
        fh=OrU1A52QFlqzmEXHI3jZ4sFKB3jfTCSfDFFkLeQriR8=;
        b=YGvI5bY5GSOGk3OW9X+/1pZ4nFChbGgsmv7TCAZPPsxPUZYtpbxtn5SkKo6JLsE3YX
         6VewmyDKZJCIK5Wj0HjE1E2L+56uF1v0ZGu0JVu+6kXZ1C1NijG70laizo7qKXCan6MB
         XpnIG18Ge8K1DkmLFlxlrHcKyFvWGiKPOscJlcUTB55UmxKtJu2DanlJHIzwTa3iqO9j
         7nVANCJLWQZSrED3uypOmDhn2hkSS7L32g6NUxH4XYLRZ1BRZ8cjQkXR7eamUOwqCqmd
         n1+iiz9jSjHFCAhMilVySoJrPRcxez7NcEnX/ufF9MMdxZK02o8hVt8+fZKRfgVS2RUP
         6OoQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bigfatlinks.biz header.s=selector1 header.b=TvTyvOW6;
       arc=pass (i=1 spf=pass spfdomain=bigfatlinks.biz dkim=pass dkdomain=bigfatlinks.biz dmarc=pass fromdomain=bigfatlinks.biz);
       spf=pass (google.com: domain of lucy@bigfatlinks.biz designates 2a01:111:f403:c205::5 as permitted sender) smtp.mailfrom=Lucy@bigfatlinks.biz
Received: from LO0P265CU003.outbound.protection.outlook.com (mail-uksouthazlp170120005.outbound.protection.outlook.com. [2a01:111:f403:c205::5])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-728afd69fa4si75046a34.3.2025.02.27.05.25.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Feb 2025 05:25:18 -0800 (PST)
Received-SPF: pass (google.com: domain of lucy@bigfatlinks.biz designates 2a01:111:f403:c205::5 as permitted sender) client-ip=2a01:111:f403:c205::5;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Tk8xB0YTUW5Oq18TsfXzatus3t5dxymjMO/Xhmv65014c8rpMa1ikaLAhCQ4WC3SWWslCuaN7SqA5Bm9aVs7JlGehV08keuBSjJqCunDYkAzspyhdtLVG3UaZZ5lfO3Xl20ya0jp0inJXiamYFb6f2vI/YPsOwtHNc6rBD2lxiwn13iwyk8v8lCdhhy4ONikHj9bzJNQPV0Bsnu/z8MuChG89CuOgrWHxZIWYNpNVTIOk7K+yEUQucCd+D8NcIGtzklZY4PhGpS3CWN6nbbwt20l0NUda7fcYZrG/bakRfb3gaaMeKtNFDcP1Ru6M9b8WkG8QI6PaUS3jIhgawP4YA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=6mca+527CKprSCYUPdjxMAwrjmes+Xz64+E6QIXMyhQ=;
 b=c9WxXM5sJAGOx7aX8P/EyeA2OYyykaPqgDFhAucgwXNKaplft0m2mGVOyAZJhXfHLsxNnyBRInxqsFCzG3Lf6L+gFuIhtaMuo5cyeGeO6hJwzVM+L6iKSqeUtfkWV3p2/icYZmBvX0PXPwoMo3hCau4fo/8ymO16CUVgw+0XEa39lyG1zsr2mJSrIbvUqy9+oRv5kZWadBFilwtmkoY6q0n7BYpVDyErcHJdmUrRG4D7+LTU1fnms3XELN7aBU3v15qGFL0+5yg0wavsscVQ3alZdo6gam21uZ6CjLmdEkr/XHXuu+M2ig2JWFO5wTSibSPFcLCKEE1GIPkeq29hqw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=bigfatlinks.biz; dmarc=pass action=none
 header.from=bigfatlinks.biz; dkim=pass header.d=bigfatlinks.biz; arc=none
Received: from LO4P123MB6695.GBRP123.PROD.OUTLOOK.COM (2603:10a6:600:2e4::11)
 by CWLP123MB3362.GBRP123.PROD.OUTLOOK.COM (2603:10a6:400:71::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8489.22; Thu, 27 Feb
 2025 13:25:16 +0000
Received: from LO4P123MB6695.GBRP123.PROD.OUTLOOK.COM
 ([fe80::8819:9f59:227f:8d35]) by LO4P123MB6695.GBRP123.PROD.OUTLOOK.COM
 ([fe80::8819:9f59:227f:8d35%6]) with mapi id 15.20.8489.018; Thu, 27 Feb 2025
 13:25:16 +0000
From: Lewis Green <Lucy@bigfatlinks.biz>
To: Unknown <kasan-dev@googlegroups.com>
Subject: Unlock Your Site's Potential
Thread-Topic: Unlock Your Site's Potential
Thread-Index: AQHbiRsJl/AXNKHKyEmVVkigubIxbA==
Date: Thu, 27 Feb 2025 13:25:16 +0000
Message-ID: <LO4P123MB669517786E95BEA70A33EFD8CACD2@LO4P123MB6695.GBRP123.PROD.OUTLOOK.COM>
Accept-Language: en-GB, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: LO4P123MB6695:EE_|CWLP123MB3362:EE_
x-ms-office365-filtering-correlation-id: 2c1815dc-9ca8-4073-db01-08dd57322c62
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;ARA:13230040|69100299015|366016|1800799024|376014|38070700018|8096899003;
x-microsoft-antispam-message-info: =?us-ascii?Q?aWuJKWcy+RSX3eqyyd4kLlZa3+oAu8OZ5IlEVE8g2Db69rIeXnXpbUpZdNh+?=
 =?us-ascii?Q?/GNqwuQX+QFwUv1yALerfsgfRA/YE2JrtHWE9FD8hcsHU43hks9D5a5OD3WR?=
 =?us-ascii?Q?Wgc76U7ihG6M57YRwQ8srJomoPsVcaX/DprqhAMMh0wl1c6BazNvex/BWaBX?=
 =?us-ascii?Q?/W+7mL1Sv1kAGFL4qfJli7uS2xoV7xbo+Dgz20Di6EIajtadbyyd6j/UIoHl?=
 =?us-ascii?Q?T13cED614obYMzifSGrEJlCCTHjvUXDDcJkK7/Q0UtInkp+4M2hW580D+R1n?=
 =?us-ascii?Q?gP7NudZIVEYOo2VU/9bGezUNNrhTaze98mTvi73Wahq1g3WRcbMjKflc/AIu?=
 =?us-ascii?Q?jCVFA+BMtFpZlbWapVUgRZquhrCgmk/fLHSj6I7d1RLo0Jc/k8owJboqomQS?=
 =?us-ascii?Q?YAgcc3cWFah4gpn5zMTucSb6HYYF6WTPEfLxDysNXlMXOFzF6WEAk52pTLFU?=
 =?us-ascii?Q?vG9AOgOEU9mqmAJuRubkgAJQK9qlg4liOto2NFhFi21S4A+PZh5VlJjhmPut?=
 =?us-ascii?Q?yPdbLK4zmTVxFcvggcE77JzTlxN3pzgGWJUlb8oGwAe4NkVyhTREy1isSkOK?=
 =?us-ascii?Q?k7c5qcxxha63jlhjX3FwS4aiTL5O8cRlQisg0PvgJONE2kI0tIHe125NFhf9?=
 =?us-ascii?Q?9qtWnvf8e/1aGh3YPWAOUZbXjj0uN1FlVTE6JU6OvPwslevAjrucQWOjMuRE?=
 =?us-ascii?Q?Dxm/3PBKY46+u0oLTSQ2hwzheNz8AnCw0nuP7GmWL7t6AXH93ob9T0EXzrzh?=
 =?us-ascii?Q?B7xnpQYMKx1YRlFRh2iQko03WoNHDoQuEVIukZ6DFKzASzzLCMemTVKAlCMx?=
 =?us-ascii?Q?UqQK5FX1aqCJMOOkCC6FbU6D/DLSnxfuhBNIyb7hhNueTG0HNBDvx1++BOmT?=
 =?us-ascii?Q?SZqMkWQ/cxueVfP+bri+RW9sEHKIsLrgfueuSHaLoGmypD7UEsnfUWPtWzuV?=
 =?us-ascii?Q?zGJwKrICjeVhvPn7HnJ1byDtiCldxpj3ba4/k8ga0acyZkELEy+2az7eTEpp?=
 =?us-ascii?Q?HBOESAG9EXlw6hncsHYKLp6CwV2hWHDjjbSasnvfAiZhXXuavsQ+DgFLOmZL?=
 =?us-ascii?Q?CspZew4Ox1H+0oVsRiHcExFawF7/oACl8eWa2X8oPfW+YON1cAsSh2SloiS0?=
 =?us-ascii?Q?FzcYI6Zi1lze6oAh/78zzWB6n+1w/1RclwHw4cfubOeh6RmaGnWajup1AOyx?=
 =?us-ascii?Q?Scqje8AZ5GLZ/bxx+gpg5sdRxCo/zBgW3hx4qNcc2Vw882whaEUb10gZtFZW?=
 =?us-ascii?Q?WxmhkNUJAIM0lma0NrP2mbm2hCqla0fAH98vlwP0Rx32HHnAW1JNxgtMf5P3?=
 =?us-ascii?Q?E1WSb7pIRfKtnXbQhWcuik9tcX4hG+M79chcNbB7qUZizfWPrY3UhNay3Ic1?=
 =?us-ascii?Q?hblv0yk2Qv+yTxQ4bZ6VIX6e23VV?=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LO4P123MB6695.GBRP123.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230040)(69100299015)(366016)(1800799024)(376014)(38070700018)(8096899003);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?us-ascii?Q?7ghE83/hkpiY0z5qAwNoxvc9KMxKUSONSM4lqoAiL0HvEtGFAuUSdGx2/V+z?=
 =?us-ascii?Q?SPqne5LwRefhb+qc2xlM/ba3fQKBQWQp5ZBdmh7T4sNRtWW5c5xO0F9ln7Es?=
 =?us-ascii?Q?R/TcDrZbjvXgScKyw4xvmp2b5bNgqUO+HdcqGVt7UQQOH3/+S15mZkGirIiu?=
 =?us-ascii?Q?3lv0fC7vG4NL81RSueOZKU6oHdtC9iG+GZPer2fwMcj/XQExkR8P3cWaV9Va?=
 =?us-ascii?Q?loUPWYQr+W3PssJq+flrUYdrH0eV46/f6uzKw5Oy7cGc9RGpNdArFvu/Ea4y?=
 =?us-ascii?Q?lPVBt9IlOAX7crjMNXuuXDOw5SwI8Uon2Yt9wtapWJ/Ls2ZpmwwBuJuz2uGR?=
 =?us-ascii?Q?FchSaGrCVyZov+RJxBmgLs1h6H05rxGwEcR2WTkwsUOZ1CYlB7c8G/7+tAaB?=
 =?us-ascii?Q?/nKdiMhtV8O/PkWJHOU8ILus4Py5465np/1vZRmXsZLy5C8lAGR5nx4DV09x?=
 =?us-ascii?Q?wRfQTV67Y4jfkNSHIyw5lI9K4WWeGQoXipS8eLO6ch3nPUitOjLPIh/U259k?=
 =?us-ascii?Q?Jx797FbBzCnItV6a38MTy/CDL3fgewbLYEf1GUBX1MTZ+LFol6dseOb1xcky?=
 =?us-ascii?Q?9GjVwvT0HBDtBZphyzyAt5UQkn7JHpRYQWiR7ZzGWwlBC0jSAzX25pkOuZcp?=
 =?us-ascii?Q?by/JmGEzdxoy+tLwAHsTtNNw+Gl6nfwXT9z0wZxtV8CZ1NjRwDx7wFPZqfqy?=
 =?us-ascii?Q?z/1t3oEBYjEvTA4LLnkw1qBAtatcvjwRFrZdSALlPXaV18m3vrw0mTv6IHeJ?=
 =?us-ascii?Q?5gK/26XMruKcZf7a/OQ4ceityuOor5FiMsIXtoF4FHWueBklHce1sWUfS1Xr?=
 =?us-ascii?Q?0EevakpW5c9S232NNWcwWbhXweLxJIvRncIqFEZOvWP0iOG0RF2DMUn/A9lY?=
 =?us-ascii?Q?FqcC618XmgW44glTD6iFFvIhUjXvT36Mz6ESWMCIVOJCJQmfsDfYkWksEpHy?=
 =?us-ascii?Q?N0h9582PUjMVQRxiv4OHB0dqDSxGhhd2HSfhfrpNaJ0Q81VDP7xObmi3eUs8?=
 =?us-ascii?Q?v25pBX++TMV8xdbdw5dUVQYrh6NJ8ijYl9yHuo/4teSaRr+oeZx5qQ4ajMy2?=
 =?us-ascii?Q?27fyes/QrKSP3P768zvnXzkKEJ3f1CmZXsQSHbBJZWdSATQdiHfgZM7udL6Y?=
 =?us-ascii?Q?UGKVnuuHWOTAo1SMUu6Cn6nUCjsNTA39TEv3Z0TR7Cu9yMlZsWsxv2IKkd1Y?=
 =?us-ascii?Q?DZDIQXVWHirGeW5WCgytjKgIJOQYt1EY/EIu1YDNBtcFYgHJ6YD1zpQ40rdL?=
 =?us-ascii?Q?z3HqqUIXMXGcAUjv4D56SzXPYtuYbnJnyRINopvPIQX3VOmIQ7DXuRqOkOce?=
 =?us-ascii?Q?OYoAjF2pp+m2zrWCqdzNVZTuiC/91/pfL0wJIRzg+u0Affzd5w4sZfiHpXTr?=
 =?us-ascii?Q?jt1w2ctRvR68i4N+oS31mT5Yywiq2hBxMNjHjbftjUpG6hcnMcul9yNl+DzM?=
 =?us-ascii?Q?wotHhw34lcPRLtTvshiNqe+St+4eU10Q3C7cHEMw05OJS4S30hHv9cInv2S6?=
 =?us-ascii?Q?ezS+M7Ie+66t4Ffw5evo25IkNeq/lKOTK1Fjx4fpatoW91UJeKCcN2xyhdGr?=
 =?us-ascii?Q?NJE0CyxNFkp3AKZC/VNYZjZZxSL+RWBkyYDSWCiV?=
Content-Type: multipart/alternative;
	boundary="_000_LO4P123MB669517786E95BEA70A33EFD8CACD2LO4P123MB6695GBRP_"
MIME-Version: 1.0
X-OriginatorOrg: bigfatlinks.biz
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: LO4P123MB6695.GBRP123.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 2c1815dc-9ca8-4073-db01-08dd57322c62
X-MS-Exchange-CrossTenant-originalarrivaltime: 27 Feb 2025 13:25:16.0687
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 8fac7e88-f5f2-4021-ad1d-c104f3f1d3dd
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: gt9bz5e389hM49I7E6530NdpO/erppGTwDXimOwvKIH8Xa+Vc65/gScoQaK50G2JQ6bBSI1XCXw9SaAf2oaTwg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CWLP123MB3362
X-Original-Sender: lucy@bigfatlinks.biz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bigfatlinks.biz header.s=selector1 header.b=TvTyvOW6;
       arc=pass (i=1 spf=pass spfdomain=bigfatlinks.biz dkim=pass
 dkdomain=bigfatlinks.biz dmarc=pass fromdomain=bigfatlinks.biz);
       spf=pass (google.com: domain of lucy@bigfatlinks.biz designates
 2a01:111:f403:c205::5 as permitted sender) smtp.mailfrom=Lucy@bigfatlinks.biz
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

--_000_LO4P123MB669517786E95BEA70A33EFD8CACD2LO4P123MB6695GBRP_
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi,
I hope this email finds you well.
It's been a few months since our last communication, and I wanted to follow=
 up to see how your SEO efforts have been progressing.
At Big Fat Links, we are not just about providing high-quality backlinks; w=
e offer a comprehensive, fully managed SEO service designed to drive your o=
nline objectives and boost your digital presence.
Your domain, googlegroups.com<https://links.bigfatlinks.org/b?y=3D49ii4eh26=
orjge9g74s3gc366dh68dhg60o32p9h6cpjap925gh748hq49k78t3g78niuprfdtjmopb7e9nn=
as3j5phmur92>, has tremendous potential, and our all-encompassing SEO servi=
ces can help you harness it.
From on-page optimisation to advanced link-building techniques, we cover al=
l aspects of SEO to ensure your site performs at its best.
Our link-building team secures backlinks from reputable sources that enhanc=
e your domain authority and improve your search engine rankings.
By partnering with us, you gain access to a team of SEO experts dedicated t=
o helping you achieve and surpass your online goals. Our commitment to qual=
ity and results is backed by our money-back guarantee.
Let's discuss how our fully managed SEO services can take your domain to ne=
w heights. Please respond to this email or visit Bigfatlinks.com<https://li=
nks.bigfatlinks.org/b?y=3D49ii4eh26orjge9g74s3gc366dh68dhg60o32p9h6cpjap925=
gh748hq49k78t3g78niugj9ctj62t3cd5n6mspecdnmq8g=3D> to learn more about how =
we can assist you.
Best regards,

Lucy
Big Fat Links Ltd<https://links.bigfatlinks.org/b?y=3D49ii4eh26orjge9g74s3g=
c366dh68dhg60o32p9h6cpjap925gh748hq49k78t3gect2ubr2d5jmcobkdhkmsqrj5phmur9f=
48=3D=3D=3D=3D=3D=3D>
[https://links.bigfatlinks.org/+?y=3D49ii4eh26orjge9g74s3gc366dh68dhg60o32p=
9h6cpjap92]
If you don't want to hear from me again, please let me know<https://links.b=
igfatlinks.org/u?mid=3D678909880f3bd60001e1335e>.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/L=
O4P123MB669517786E95BEA70A33EFD8CACD2%40LO4P123MB6695.GBRP123.PROD.OUTLOOK.=
COM.

--_000_LO4P123MB669517786E95BEA70A33EFD8CACD2LO4P123MB6695GBRP_
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Dus-ascii"=
>
</head>
<body>
<div dir=3D"ltr">
<div style=3D"margin-bottom: 8pt; margin-top: 0pt; line-height: 1.50545;"><=
span style=3D"color: rgb(0, 0, 0);">Hi,</span></div>
<div style=3D"margin-bottom: 8pt; margin-top: 0pt; line-height: 1.50545;"><=
span style=3D"color: rgb(0, 0, 0);">I hope this email finds you well.</span=
></div>
<div style=3D"margin-bottom: 8pt; margin-top: 0pt; line-height: 1.50545;"><=
span style=3D"color: rgb(0, 0, 0);">It's been a few months since our last c=
ommunication, and I wanted to follow up to see how your SEO efforts have be=
en progressing.</span></div>
<div style=3D"margin-bottom: 8pt; margin-top: 0pt; line-height: 1.50545;"><=
span style=3D"color: rgb(0, 0, 0);">At Big Fat Links, we are not just about=
 providing high-quality backlinks; we offer a comprehensive, fully managed =
SEO service designed to drive your online
 objectives and boost your digital presence.</span></div>
<div style=3D"margin-bottom: 8pt; margin-top: 0pt; line-height: 1.50545;"><=
span style=3D"color: rgb(0, 0, 0);">Your domain,
<a href=3D"https://links.bigfatlinks.org/b?y=3D49ii4eh26orjge9g74s3gc366dh6=
8dhg60o32p9h6cpjap925gh748hq49k78t3g78niuprfdtjmopb7e9nnas3j5phmur92">
googlegroups.com</a>, has tremendous potential, and our all-encompassing SE=
O services can help you harness it.</span></div>
<div style=3D"margin-bottom: 8pt; margin-top: 0pt; line-height: 1.50545;"><=
span style=3D"color: rgb(0, 0, 0);">From on-page optimisation to advanced l=
ink-building techniques, we cover all aspects of SEO to ensure your site pe=
rforms at its best.</span></div>
<div style=3D"margin-bottom: 8pt; margin-top: 0pt; line-height: 1.50545;"><=
span style=3D"color: rgb(0, 0, 0);">Our link-building team secures backlink=
s from reputable sources that enhance your domain authority and improve you=
r search engine rankings.</span></div>
<div style=3D"margin-bottom: 8pt; margin-top: 0pt; line-height: 1.50545;"><=
span style=3D"color: rgb(0, 0, 0);">By partnering with us, you gain access =
to a team of SEO experts dedicated to helping you achieve and surpass your =
online goals. Our commitment to quality
 and results is backed by our money-back guarantee.</span></div>
<div style=3D"margin-bottom: 8pt; margin-top: 0pt; line-height: 1.50545;"><=
span style=3D"color: rgb(0, 0, 0);">Let's discuss how our fully managed SEO=
 services can take your domain to new heights. Please respond to this email=
 or visit
<a href=3D"https://links.bigfatlinks.org/b?y=3D49ii4eh26orjge9g74s3gc366dh6=
8dhg60o32p9h6cpjap925gh748hq49k78t3g78niugj9ctj62t3cd5n6mspecdnmq8g=3D">
Bigfatlinks.com</a> to learn more about how we can assist you.</span></div>
<div style=3D"margin-bottom: 8pt; margin-top: 0pt; line-height: 1.50545;"><=
span style=3D"color: rgb(0, 0, 0);">Best regards,</span></div>
<br>
<div>Lucy</div>
<div><a href=3D"https://links.bigfatlinks.org/b?y=3D49ii4eh26orjge9g74s3gc3=
66dh68dhg60o32p9h6cpjap925gh748hq49k78t3gect2ubr2d5jmcobkdhkmsqrj5phmur9f48=
=3D=3D=3D=3D=3D=3D" rel=3D"noopener noreferrer" target=3D"_blank"><strong>B=
ig Fat Links Ltd</strong></a></div>
<img style=3D"width:0px;max-height:0px;overflow:hidden;display:block" alt=
=3D"" src=3D"https://links.bigfatlinks.org/+?y=3D49ii4eh26orjge9g74s3gc366d=
h68dhg60o32p9h6cpjap92"></div>
If you don't want to hear from me again, please <a href=3D"https://links.bi=
gfatlinks.org/u?mid=3D678909880f3bd60001e1335e">
let me know</a>.
</body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/LO4P123MB669517786E95BEA70A33EFD8CACD2%40LO4P123MB6695.GBRP123.PR=
OD.OUTLOOK.COM?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/LO4P123MB669517786E95BEA70A33EFD8CACD2%40LO4P123MB6=
695.GBRP123.PROD.OUTLOOK.COM</a>.<br />

--_000_LO4P123MB669517786E95BEA70A33EFD8CACD2LO4P123MB6695GBRP_--
