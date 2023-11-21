Return-Path: <kasan-dev+bncBAABBLFP6OVAMGQEAOOI2DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 442A07F3370
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 17:15:42 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-41e58a33efasf71604801cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 08:15:42 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1700583341; cv=pass;
        d=google.com; s=arc-20160816;
        b=PEUMZNLSGG5ml/c4hcnDzrKn7+JdJg562l0BrITaPeF+UP4csdcAMHX2Xls5tfXJeU
         QXNfNzxC5k5N5yX76pBQZ3Tsbfu8NHbQbxxSGWM3GYqwTfrP7Hq+/9RqbrpCpOLlY4WD
         vH5jJL8pQ+5lgPWGOdFp2NGt2lOXvOyWg80MnEt9M3olLZV++CSoI3Ra0gXz1RDbI63o
         dx9FefYznlhc5FlpEHJLvA1yxGp5bmWfU6maf4TybvobFaIoJxTj6PTf5Ynpgq/jltB3
         Ko0F2HVeIhVlyC4FFtWzlzvDkyJOpju3h6BECNvCDpMvvScySfZXdV65q82uozc2Mk9J
         O6KA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:date:message-id:sender:dkim-signature;
        bh=dgp8LmibDYH/ba4i1KQ/9autQJNv8yHWX9o/Wb/xYVg=;
        fh=PxC77I2mAcpdCi0Nvo4QY94RSHYBBqI4vgyiVskwuaw=;
        b=bHQKjM689Z/Te8/EbULauZ9iacV6ihUlEdVVW1gbYlT/Adz2cyPLvKYjyKNp9Jhchv
         RYE5ZII2w49YEsBJ+ifewgSPSUxhvshPuc5g2o/dMJgJd5A2ZHHl4LyqfgVoCZTEkgkS
         ukZst5706HpIiHl6luBOfAXPKixwiBr1CGpuxTuQsFk+LKT0sWQ9xlnOjIQYPLcT5yaE
         8pStRAQVPJqqfScy4F4RBV03uu3Hu/Qc1ngZHNf0I7HrYH84oxiJDaw25A3sZqTTKq/e
         rZyWuXvnBf3Eu8HdCox1g6YNlBsdRJuVmKNYF9bEb9wpoyc8eUMKtY/Vj8nffYVm9dnN
         cjJQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b="nCTJJq/Q";
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe1f::800 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700583341; x=1701188141; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:date
         :message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dgp8LmibDYH/ba4i1KQ/9autQJNv8yHWX9o/Wb/xYVg=;
        b=TtOtpN4ssOkWMyu8F9QiWk+7wLlTpqHrb5DnjqVfwOPtaph2Clo33Tk+/YczNd/nzV
         IfXG7G7TCVNZ7ZD+ic9qSA0EOINeYYeIvgRVJ/ufdb4VNNLmLjQ/UikwHVAXJBEno+uo
         j6EFXoKWJM0NoAM55NsDlKxksLhTPKUw2tHXoN5ophzkAhgSOuO1uLMAraSH+KkFF98c
         65QEWoUsM5/YlXa5mersr7bFfoEQI85y3MXMZkpQWEoNoTQgKpPBk9fWc7gwRv0Tl3X/
         7aWqrvW/pOWJVugYCqfag9SnADBf+haGhkbMKHJ48OlPPHfHbOsgxlaZTcJ2p1XGttWC
         HfRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700583341; x=1701188141;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dgp8LmibDYH/ba4i1KQ/9autQJNv8yHWX9o/Wb/xYVg=;
        b=tFWIXxsz3uShUp4mqjhlXmji5h/KyIKex5yaD1hYQ8d3TxHIOJiWJxOhgZcpM1PcKM
         l1Q1NdSlo4iE5v5bQvW7NezPGa8DlXduP2Kn0sK/L0lj96Z5y2JGAF+f0ku6PfbCO29J
         HkzhgTWvYzHj8hrjg+MqArmCgtQLoVJ/cyCX/J0ocHKn4aoTFctIDZ7sCN4ElMdUgruV
         dbJFjeGALxXgFCjBpN4dL7aN48u9yixEJBCIUGes9CqvUTB863hGp0b7lrO5p/V3dCd5
         iM3xfb74zg/2WUgpSs38Qi4CjAtdeO5/edGPzyHKoTD7QDNWoAJTi+BDJSxtPl4sVLPd
         kxsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy4gybzYh9g17vYQLsL9bUcVYxqx/2/kk0e2MmPtC4I0stzU88l
	4YwSOjA6fX7FOorvlK94gn8=
X-Google-Smtp-Source: AGHT+IF9kb/mshzGB0typCQPSt05EWOcp8Ojs98oHX+qck98c/FtyiU8Nmuhs7DV9hrZr1SbJbZr8w==
X-Received: by 2002:a05:622a:8f:b0:41c:c205:f718 with SMTP id o15-20020a05622a008f00b0041cc205f718mr14475391qtw.45.1700583340845;
        Tue, 21 Nov 2023 08:15:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a1b:b0:41c:c118:e752 with SMTP id
 f27-20020a05622a1a1b00b0041cc118e752ls202976qtb.2.-pod-prod-05-us; Tue, 21
 Nov 2023 08:15:40 -0800 (PST)
X-Received: by 2002:a05:620a:1434:b0:775:f1bd:f75e with SMTP id k20-20020a05620a143400b00775f1bdf75emr12065121qkj.39.1700583339963;
        Tue, 21 Nov 2023 08:15:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700583339; cv=pass;
        d=google.com; s=arc-20160816;
        b=j9ic216MYx837XJqn3EUTimoVzcsiLvOXY5EumCnyTpg/eZmw0BPYiTRboBasRgbGJ
         YGkULosF+dk+Hogk2l4+ukfsA56veDUDAY+WHXbupHnNBXuMzdHDGgZIF/P6GVFRzVpt
         rP7NjT3WhzlUBVlZHNMjgbY3QuVXqWVua3dGnhCWcorTcpLLLVRP8Vpc+Tzh5YLz/+lM
         rizNjQBx7cC/Pn4rAUT+7zR7J8oEqKuVmnSd2d7Rzk5seu099sSEKmdb0xNP9x5rRtc1
         DBqhnzg+c+DvaI0vns0Iohk683+sZIW6bykhQEsC9aJyXWG+Vcu+ZNNV0iOYIeLgj9D9
         k6ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:subject:user-agent:date:message-id:dkim-signature;
        bh=yUzNLr+cwGdy045lqg+bNpl3hY3ODB4hHXj2I01kkIw=;
        fh=PxC77I2mAcpdCi0Nvo4QY94RSHYBBqI4vgyiVskwuaw=;
        b=fpxPmoM9kJ6PFnkRtY5UCb5jt77/4sS2/1EMzgK4JE2YJhDg1rQ7GmokD6vD/6QASs
         f6GWWkPBO1LScOwv6FNcfax7+HaKuKecVMFsFTvpFuPkBAhRYkOqGTyk0n6drIbek1To
         viqjQBjcO2k1Cf5M6NSZbrSB5AGzkot3oi0n8veEtT2BpeTcMeEJ0/Eat6xz/gF6EEfU
         XxiAo+oHDp7Z1jhW8iGQcxIDgALdtq3cEM+a+7kYwE+EVCHiT525rMkSyxJiFfbt5EX3
         Uaix/Qh//P/ly90AnN7rCgQ0yTLvtWvD5eDXkkNNhauqD/8abt9cC1+nra55mQkFAKWb
         Uz6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b="nCTJJq/Q";
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe1f::800 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR01-VE1-obe.outbound.protection.outlook.com (mail-ve1eur01olkn0800.outbound.protection.outlook.com. [2a01:111:f400:fe1f::800])
        by gmr-mx.google.com with ESMTPS id bx11-20020a05622a090b00b0041790471199si1506737qtb.4.2023.11.21.08.15.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 08:15:39 -0800 (PST)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe1f::800 as permitted sender) client-ip=2a01:111:f400:fe1f::800;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Rz2IIS9VT+vNNypS5OTm+GAxfq2rx2j635xrLr1MEhveBspw3FziVv5XEHACPVdN5CJ6kepfgft2yNr2HSB+pC44flHv3t4GdqqDhCQHC2cv4Wcg09uxKqEGN5j9HtCRJnR0zbC7DVIBpfQy0YzE4ukcjXy6og42LzG+xFO36GEtS0ugSxLOpQgfCNipx87JGEI1vf+hPFXs4rV4rUEeHRMNr7kZSnGN+Iske/YW8y420McR1JZUvL3O8EZEvUi1k4LbgUsD03xuL6CzCkLtGLuJp+usKMsLGf3guZN0+88sqFS8VqRWfAnQUItaiPHicYBczOlh0Vh6FwEX+NEwBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=yUzNLr+cwGdy045lqg+bNpl3hY3ODB4hHXj2I01kkIw=;
 b=GxErmJjo2MhJkE5u3WE6CAdE93PmEpmf4/gNIMCjyxZholD6UyBLjx5875FubrUQ20xraY8+nsxHf7wVjWVUZq3cLjkRAp6F7B6v11Kz/hQATf2RlDlv3zwr3NQEueXtTTlVQl1Ss+U0KxTMuX9YrgOjt0t9E/r9q16+2AMdTGGa9QYqadJQSSVq/tbL5SEhBZ8l/eqhNHxzUyjcnYjG6y9fpe5jhB+yjb3dioHruKmICnnR4jtzl6ytoQ4ZyABy4ZsLS6n8i0kN1fMknaMoKxmG5LkQz89IKO74iec7IxLuVZbX4VVwJux7V6SXqnNTc9arJq0tO2vNNGO9DZQonw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by PR3P193MB1117.EURP193.PROD.OUTLOOK.COM (2603:10a6:102:a4::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7002.28; Tue, 21 Nov
 2023 16:15:38 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::fdd2:7dbf:e16c:f4a4%4]) with mapi id 15.20.7002.028; Tue, 21 Nov 2023
 16:15:38 +0000
Message-ID: <VI1P193MB07527A880D3276B6415F29E499BBA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
Date: Wed, 22 Nov 2023 00:15:36 +0800
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kasan: Improve free meta storage in Generic KASAN
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: kernel test robot <oliver.sang@intel.com>, oe-lkp@lists.linux.dev,
 lkp@intel.com, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, ryabinin.a.a@gmail.com, glider@google.com,
 vincenzo.frascino@arm.com, akpm@linux-foundation.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-kernel-mentees@lists.linuxfoundation.org
References: <202311212204.c9c64d29-oliver.sang@intel.com>
 <VI1P193MB07520067C14EFDFECCC0B4C399BBA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CA+fCnZfTJwfmO-OYcUst0fsWhRa+MzDtkv1N_bMob9_1BivdJA@mail.gmail.com>
From: Juntong Deng <juntong.deng@outlook.com>
In-Reply-To: <CA+fCnZfTJwfmO-OYcUst0fsWhRa+MzDtkv1N_bMob9_1BivdJA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-TMN: [qJuxwt9riZ4A+iesZwU7TztC3P0OFlIS]
X-ClientProxiedBy: LO2P123CA0004.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:a6::16) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <29437f37-f64b-4d40-be3f-3dd5f568a53e@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|PR3P193MB1117:EE_
X-MS-Office365-Filtering-Correlation-Id: 6610bd59-392c-44d5-0d4a-08dbeaad193b
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: G7il+3OTQjRSM4i0SxyTbBIytEMqcR6eWkSPbzrmC4JDOU32nhJmH24275QT5dRXysby6hqbyGcXO6yzlWrMg4DgNV8ue2vypL4NFiZE9xcjlBzfFCnIm5o0YD9TE65kCn1LlDNVjUaAVxm3qsd9FZ7bQcoaJ+Wylh+Vuxr5q0NefIE4F6bp7va/NAYFrRZVAJVdZOur3uvdFPH57ChC8dWrYuCnZGJdscTgsddWEETXIyDNOI7cqYfhdn7G3b5PfcRRTXgC8399cqnPtRyUseWxzDxfi7TaDDmho6ErvIe9sIYP2qX7ZUxDtpWzxsq7iGjoCjnWN6FB/Iawglkyv84XcRJ9pTk3cE4cQe+ZNbI5gBz+xP7QDsk/mWOcFfEPfcwAUWn1uBngQu84986fJL1tfeKh5+T/iZ37zEyRGevwAXoII4NuvTi2aQjJiXPGTs4jS2ge67MMYb+eC3UcTxzetxqRaOcDSFeII1sYLtkM9YzjLMG1ylTaMI+e7atvA2WcDqNUSCUIWLvDcxY1sdXcqQMn1UzGqC1F6FimZjwyhys6hG3vYt5tfQwePRVO
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?Q25rbWNIc0tUR2hESGVvVTU4a2hhd0NjQ1ZYYlFGaW1ock9uSWV1S1hWWk14?=
 =?utf-8?B?R3pZNlA1alFPTnZIS3MrbWJwZUVQRDVML3ZlY3V3bzN5R05YU1ZnKzkwTUFs?=
 =?utf-8?B?MEpNY2JiVDBzR3lZckVCVC9iR2I2RVRtZkxuNmE0Q2gyRnJDTHEvdGE2c2dn?=
 =?utf-8?B?V1JtQUJXWUlBd2xkamJzVGRBUWNxbW8yODQ0YnViTDNZTDBSSXhVTGlYRHNZ?=
 =?utf-8?B?UWZ6eVZTTW14c0tLOWZ2dUlWUlM4RnQwOUlEYzhpZnU0cDRITC9RTTVCSmcx?=
 =?utf-8?B?Qld0VnBtNG9DdEtreWRSVWNxc0VhREYvMUZucGFrTU9DU09Ha2JFNzExYjkz?=
 =?utf-8?B?YXNaK0VrTVNzQ1RlaXNUM2JRblRxR0VIOFV6ck5LUmdMY1JxbWZEcTA2UGRm?=
 =?utf-8?B?eEpvbW9KQngxOVloZ2NuY2JPaVhHQWhTMWxZdEhNcVN0WDNkOGcvN2ZibCtG?=
 =?utf-8?B?c1pqa0VrVFE3K2RrL1NVZTc5K1ZwT1lMVEtySjdEek83ZFdTTFV6ZUx5NGVO?=
 =?utf-8?B?ZjQwbjZ6K3N3WHZTTGdMUlVNSzhxWkJzWmM0RFA1d2NZTG9LRkdSbnF2NnhW?=
 =?utf-8?B?SjVZYTZxcDZKVG1zRXZuRmEvQko1cWNhSDFNdDRKcnpXek1zZDJiOVpua0I2?=
 =?utf-8?B?Vk55NVN4bzhIamtSZGI1Mmp2R2NIbVhNamtYLzBZU2dEWWkwZW1CUlpKU3Fj?=
 =?utf-8?B?VGtkMGZSam1ONHg3c1pQeDNsaDFFWnY4U2ZyM0tUcFVtOVJSVDhNOTNNczY3?=
 =?utf-8?B?eDVqbjZ5QnlyTncrU3VRRVpOdzZkcnJod1VKeDVzYU05OHZ0WFB1dzQvVWQx?=
 =?utf-8?B?SGsyNXZzN2Z5VFFEZ2dwUUJuOEVqdG9oREhyYnltVXI3NGt5WGtJcWl2S21J?=
 =?utf-8?B?aEhyVTVJM2hHUW9yK2ZCeUtZWVcyb0UvSlhXQ1hnY2MzZUlGMFpwVVFlU2dq?=
 =?utf-8?B?SFVnbUl4SFpzRVErMXFZY3FOVHZELzV2NDluZ29KUjhIc0dkNW5wa2tuNTNw?=
 =?utf-8?B?clczTEc0NUVQSGROWm5DTVZOQW1LVVdNdVMySVd2a2ZOMlBNblFLYkxiUito?=
 =?utf-8?B?UE0xcmVhc1dCd3o3eTJoQTNtNlJPaXByaS9PdGIxbk9WbTl4aElGUGlhSzEw?=
 =?utf-8?B?bUQ4WUxyTGNUVFZnUFdFRUNiY1lNaTlVQjR5cXcycDQwQ2xnV0JYUkp5dkVG?=
 =?utf-8?B?c1RKTzRUTXAyK0duaGNCcFZSVytlNHdmckZoN3V6b2lHVDZvc2lxNVZwU0dx?=
 =?utf-8?B?Z3FIWUZaQjhoc1dJNnlKZ1hqZjAyK3JJKzNHUE9wSUpUYmFia0FOM29ya2FY?=
 =?utf-8?B?M05zUnBydmxHVG15UURrdy9Ua3NLVlJ1UGNyZGpwUlpTOTlQcmtLVWxKNE5u?=
 =?utf-8?B?eGtQemdSZ2dIWnBGaHdScUdYaUR1a1hkdHRkZVFCZFlwdEpLT3ZDbU1JYVJs?=
 =?utf-8?B?MUxBWVRLKy8xalNSVE1kcWMyTDlBMFIwZ1BxOExsOGdEbmRDQ3BjR2tBTm00?=
 =?utf-8?B?YVFXd2hzeE5RUmZKZGx5ZWlvTkdrWXFSRmtOd0RZaE9iUzhZVkMwajZXcUlM?=
 =?utf-8?B?QzFDVEVFOFA0YVVlZlc0dS9OZ0pvS3FFTm1PbysrWXpyVTVIU2thY3FkdEF0?=
 =?utf-8?Q?FYcXP8rzkChSWAJNGoVJl82Sh8fFdtO3nveJToDJX7VU=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 6610bd59-392c-44d5-0d4a-08dbeaad193b
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Nov 2023 16:15:37.9322
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PR3P193MB1117
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b="nCTJJq/Q";       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:fe1f::800 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
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

On 2023/11/22 0:05, Andrey Konovalov wrote:
> On Tue, Nov 21, 2023 at 5:03=E2=80=AFPM Juntong Deng <juntong.deng@outloo=
k.com> wrote:
>>
>> This bug is caused by the fact that after improving the free meta
>> storage, kasan_metadata_size() continues to calculate the metadata
>> size according to the previous storage method.
>>
>> I will fix this in a separate patch.
>=20
> Hi,
>=20
> Please send a v2 with the fix folded in instead.
>=20
> Thanks!

OK, I will send patch V2.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/VI1P193MB07527A880D3276B6415F29E499BBA%40VI1P193MB0752.EURP193.PR=
OD.OUTLOOK.COM.
