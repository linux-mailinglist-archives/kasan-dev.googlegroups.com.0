Return-Path: <kasan-dev+bncBAABBYNI72UQMGQE4ZRF42I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id BF8E37DB900
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Oct 2023 12:32:51 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4083865e0b7sf31538745e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Oct 2023 04:32:51 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1698665571; cv=pass;
        d=google.com; s=arc-20160816;
        b=JwH8ZOfuEUzDaxcdPvXDdJEBLsQBWoVY7Q6YrnWEjs7LKwgjK8d53LvBc3SR2WnEKQ
         adt/RyuNfd2Eikv75Ct+qwvxMYNH+Yg5WPeX/mtwBuw3LmLJ+cQx/oyzH5GSzea+Qn0K
         qVg/JS7wwrBv+XQsQv/EaE3neGT7z7SOddOIMbqX+Uuy39Nld1qMKg/e6p82IluMjnKp
         CJhiotZyR/7u7YqdgUb0zaMnaFrBd6gLtkvdgGUh8BQLHjYgPEaxzPOai2m3SMAk2KM4
         Jz6NEHKMYJ+hNlLtQVACnXgpVI+gukLUiw1U/TX6FdDXPs9bOKRsXD0ZnI14rj2QbdyH
         dq1w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:date:message-id:sender:dkim-signature;
        bh=8WFIEBE4RFS1RVslwqwTlLCyc5l3HThT37fjMevxWr0=;
        fh=LWa2cBJS15l6HICmeAHPfNMRsjFSTs5tQYPE7n+sM1I=;
        b=NkZpEesH9QU6fWohTDb9otj33JjqfD9LqQKI3BBl6ldm82+rHbfRa/3rVCQBuUPYFC
         U6QHhdjy8ygxcRrbFfqyamoZMFzR+cWwYdXDzCihE6FbilrIX4JlSxFD9EFyomF38f22
         9BzCKPd0oNj8sYlp24ZdqCeweuLBQWcUdaKT7O4MyaAbO/ExHyDp4mXPH2q1tTEa5YeP
         8CL3NnnWr6vpMeT9CxP7enAZ7biRDXSsvY8PSIwTdfAsvYjSfDF3gwAT8vJJS97wVUzj
         eB3q1raob/GZ6ksNzBbwTqV3j2Fdy9pvA8gx7fmzfqvoPN0y3HN/9pzsHlLVSirMTsii
         kvvA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=mE8jRvB8;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe0c::827 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698665571; x=1699270371; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:date
         :message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8WFIEBE4RFS1RVslwqwTlLCyc5l3HThT37fjMevxWr0=;
        b=n6ADARZNtKryMRYlIfK/QhfbD1ux0M0eNLWerwP7USPb3FnZxsN4PdhOZHIjEvWOp/
         pdsZ37HqPFA3HLIgB0NTkoB3W/oJ0ei8ScldMYgN1W30diPRsiEjURY504ayAKWsIYO0
         EwByIV7RdZSbWBWSzBY/Frm4LIRqhnq+JcMFQjI9Y6ILiJQSFDHNweZZKFi9cH9uFNhb
         HNDtjUc4WCq5MsmRTxPxg0osTVbqt2gKATrLZ9vCCTn3z90bYuGH7TPYmYRRHkZaMSxC
         ofeaypG4C1mVqjBUxeiOfnBqV7tpaEfQCecsmnPdmoF49/Mtvvnc7jmU0hgY0W6Y8Aen
         AXEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698665571; x=1699270371;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8WFIEBE4RFS1RVslwqwTlLCyc5l3HThT37fjMevxWr0=;
        b=aN79rwdM7LoY3xcb9nyjcSWsTwMQVmHL9qhUYW0yTcnqB1I+k3B1l/tWabvAJSer/1
         60xalxxf3HnMSHyWSBY8r4AN6peHcUdlCH3br14ZHzwPgRt87AtdkSD0YNmUlO3eptLT
         A880M/F3vn09Fs+Y2/JodSEV+jUTBOH4NJAWoOM/W/1ONqBc68odHU8hLTczinDeRseR
         lnMdgTHI04jrvIRjPjVDgBQZzPXpwG6Jm+8l9nduseAY3tc0FdKZ6tVoGk6rHUwWkkfx
         CyUoEZbyKM7jm9mLQS9ikbL+tUPhK1lDMv+iQz8me+3zp78/Jye1z7ddMiGFeNgUIyxL
         uzWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy8ndbQ/s2clViNFkAEFden6akhAFhCZt4VWFYWcm1wS9ojOyX+
	Ln+PBocmED9bgFoQFnvZwoI=
X-Google-Smtp-Source: AGHT+IHHouP2izr7VQjWvEMrF8sqaAap3hiUZK+DoZdNKzErwCeZhqn0l7WC+8iao63T3Z0nCC/p/g==
X-Received: by 2002:a05:600c:5110:b0:405:34e4:14cf with SMTP id o16-20020a05600c511000b0040534e414cfmr7940789wms.4.1698665570142;
        Mon, 30 Oct 2023 04:32:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6009:b0:409:3542:341d with SMTP id
 az9-20020a05600c600900b004093542341dls854594wmb.1.-pod-prod-08-eu; Mon, 30
 Oct 2023 04:32:48 -0700 (PDT)
X-Received: by 2002:a05:600c:4755:b0:405:359a:c950 with SMTP id w21-20020a05600c475500b00405359ac950mr8049670wmo.19.1698665568695;
        Mon, 30 Oct 2023 04:32:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698665568; cv=pass;
        d=google.com; s=arc-20160816;
        b=jxkG9WqrDwf3NvDsp0hoqzN5jVZcTYMq5t4EkvU90g7t5fLgx59L56VHUHAhXwzZdc
         LFp0QLJ7/gBAk178MXWQN4t+TWkOVq1PEnzNNelJn0zdfaeBiO0RjiaMkcxQE3QQSRLP
         iz/0KJnalluc92CCwZtzs9eS36AWUxyIT9RkwT7eIFwRzk5OlZgzA4B1xY+GffcP6/oh
         Ymc+NOZvnbmTrtq39+/IP8RlxmaZf1ZF0i2JdyiXDmPZtzcuRWX681KgKinE9ghaSvZF
         mkecG93+I/HfaoM6CGYsokdnMOsh1AmQEZ8rFjEREVPuXEpEEDbmzxlthDGPRKSKokCu
         LmAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:subject:user-agent:date:message-id:dkim-signature;
        bh=P0sbShoVaCxZ4fIRI5i+82yMZNf2ZLJdT22vPfLNN+o=;
        fh=LWa2cBJS15l6HICmeAHPfNMRsjFSTs5tQYPE7n+sM1I=;
        b=ke41sCAKY60oXjfGWKizMesVh2xtFRKmf3+k2UgO5bmakw57HL9NDWO3/WLSUf6Ujt
         zvEGqCNAPpCJPcRELPR1JJlC/y1m3341kzpmzNezigjZzsuLZUf2JxV8lm4mvWr5r0S2
         GaLZaV+qvJDpWVNBTWdhdXaRTnLuYXavz+FqoQfzPG7JE19SjDqPgGyXGdULAwy2fZQG
         TB+jd4hsMvLPLgeITKC5ErMmjjArOY32PWrqdiUXI0yP67ewG2wruaTs3awRFXlft5xX
         7NfK6apFV8BIn8duP5wOXgAkWEjtEY2ouzJE3RtwEphKPk24kEAN2qpUm46Ts2pRR0eT
         w6hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@outlook.com header.s=selector1 header.b=mE8jRvB8;
       arc=pass (i=1);
       spf=pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe0c::827 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=outlook.com
Received: from EUR04-DB3-obe.outbound.protection.outlook.com (mail-db3eur04olkn0827.outbound.protection.outlook.com. [2a01:111:f400:fe0c::827])
        by gmr-mx.google.com with ESMTPS id bd24-20020a05600c1f1800b0040476a42269si384761wmb.2.2023.10.30.04.32.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Oct 2023 04:32:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of juntong.deng@outlook.com designates 2a01:111:f400:fe0c::827 as permitted sender) client-ip=2a01:111:f400:fe0c::827;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Bps1KWIhO6j3xEawxDykhW6Jd9Q9N6IJwllIFdSZWKkMhh5bImXzSFYWZKhBTKF0OZeq5aECQ5VcIJCah3oqhzeBj+oGfrAh0KWxYF/rvrOunUcGDh7+rtp9bfEzBsWDyOZj4+HzbsvOPm15irjMQTExKqjQ6IgtPxwlhFCaY8yDtxVSLtUj02ARKlJVOpWgXuHQDIOOuvT9XUowjUIpqFLDh/7Z8LCV8iOu+wTtYr5JObtnK8BmzwHk2I9H9vLRQUOe4D18fdn7EnK53nzCqfqM6TjiBWbmmDPnHqPophBLa/zzwF71f2v4lxGKgQlhed9opCRYZwkX3NkMwoMD7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=P0sbShoVaCxZ4fIRI5i+82yMZNf2ZLJdT22vPfLNN+o=;
 b=WWLvtRX1AJupGvWef8XFuDee1tBw3g3lfEhAgGzuPvIdhFSVPNjihTt2pFQLVn/PnBhJzb2qYs4yMEqFU/80j4kTg8RD3qKueSyNOjfcEWjsKiiGMzLHf1+9CJj2b0/Diuka5GSKG95BNRehajhuhfsZYK3bVH12u1teGDhun6572HPhaPeDJjnt53Qc+xYovG5LAG2CXL47hWhzJN8VGJ6hTgpwWEiOenJPyto4ILxqY7GD5TBXiYXSmcoxDIywx5rSSiPyH1xJZ+J66sLKN7DHmzvqTPR8fbj2QhNDmAW5Ao9qcIbaE83mQBOtxSK7r6d3c36aWQdiAzCpyE5UkQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM (2603:10a6:800:32::19)
 by PR3P193MB0976.EURP193.PROD.OUTLOOK.COM (2603:10a6:102:a0::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6933.28; Mon, 30 Oct
 2023 11:32:47 +0000
Received: from VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::2db3:2c11:bb43:c6e]) by VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 ([fe80::2db3:2c11:bb43:c6e%5]) with mapi id 15.20.6933.027; Mon, 30 Oct 2023
 11:32:47 +0000
Message-ID: <VI1P193MB0752753CB059C9A4420C875799A1A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
Date: Mon, 30 Oct 2023 19:32:46 +0800
User-Agent: Mozilla Thunderbird
Subject: Re: [RFC] mm/kasan: Add Allocation, Free, Error timestamps to KASAN
 report
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, ryabinin.a.a@gmail.com,
 glider@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "linux-kernel-mentees@lists.linuxfoundation.org"
 <linux-kernel-mentees@lists.linuxfoundation.org>
References: <VI1P193MB075256E076A09E5B2EF7A16F99D6A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CA+fCnZfn0RnnhifNxctrUaLEptE=z9L=e3BY_8tRH2UXZWAO6Q@mail.gmail.com>
 <VI1P193MB07524EFBE97632D575A91EDB99A2A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+a+xfzXBgqVz3Gxv4Ri1CqHTV1m=i=h4j5KWxsmdP+t5A@mail.gmail.com>
 <VI1P193MB075221DDE87BE09A4E7CBB1A99A1A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+bxMKEVUhu-RDvOMcbah=iYCWdXFZDU0JN3D7OP26Q_Dw@mail.gmail.com>
From: Juntong Deng <juntong.deng@outlook.com>
In-Reply-To: <CACT4Y+bxMKEVUhu-RDvOMcbah=iYCWdXFZDU0JN3D7OP26Q_Dw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-TMN: [OqsKE/zsmXY4SJnsYIcDvATGT24dPw4u]
X-ClientProxiedBy: LO4P123CA0556.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:33b::6) To VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
 (2603:10a6:800:32::19)
X-Microsoft-Original-Message-ID: <50303875-57fc-4012-ace7-38dfca2c3be1@outlook.com>
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: VI1P193MB0752:EE_|PR3P193MB0976:EE_
X-MS-Office365-Filtering-Correlation-Id: 31628e30-aa93-4b27-a5b1-08dbd93bf0c1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: uLvzONZU1cAG7w0PNz9V0zus3sIg3ZrbkfjO3+L4n9cVgAebTjVEX1PsZAivn5jK/a7pbDBmzV4TQHvKbg3kNstjA0uqkK8vNM6dnpwH+fUX1Nji34zvy1In39ZDrFzbWmmKWiGhZMMBVfnfOYNm5ib/SWsuHCbykH/AQuZ/KiCtnaCPlzsQavqTxeY5revHKE6Erozjt31TwvUdSP6CpzeS1WlujoHihyr2bn+JBvE44W3c70Pq0WvLL/3Yljc0H0NihA+9IWr2l/+8BJTfmRPThdQlB/JrLkmTXZa0o7csblLXrf1z26Z5s9gO2FGdKqnmoeHV1PgF30ydi6lrmNOJxwzmWPcDeUgmVRBN+uhbpQHjzcbYcTktG7qTevqQd+5k0FyoBIWpyE8+ZQ8fm5Azvub8bf7GEk0V7i2Dvxlm7NAnnG6mTEPWLr99usDh2NV0LhPukc+nu5ULEEvW6SHd+K7BIfoWDRnXSk9Dn/YhGvwCIatgq1nmLsJknBJ5b3IhPgR9QBQPNUBiFLK86z6OrkCW8rtsI/wvpcc+QUyjlax5zIznx0o47c1tkY14oh6vksY8fXuC2LpJT16P3wOqJtV/xL5JJFEP8Y2/OA8=
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?N2lGVk9kSk9kUWxjSE1XVFR6cG5SSlNrbStuMnI3SndHdjBqWVhjVk9KS3JO?=
 =?utf-8?B?S1dBMzRNODI4ekxDVG1vVTg2NFFRZFo3TWd2ajFpMjZnditGa21XckR3SWRm?=
 =?utf-8?B?VnFlNFdyaEc3UVRMb0k2UFZ0RkVVZ2NYb1RINlhaTTIzN0Qwa0t1YUxCbkNX?=
 =?utf-8?B?VVZxS0RrT25ZOHAxSkFTWld3WmJ5SCttOVoxQVJLQ0dpQVZyQlNXd0greGdp?=
 =?utf-8?B?V2VWSzhocTkyT1BFVTkrREJMbGorRG5TMEIzenlDcUpXRlBWL0tKQi85MFBx?=
 =?utf-8?B?UGN0dy9JOWsyUXBYTEpuMk5pdFllMkVERkhBaXlpbklWTG9NWk83ZHo2ZFR5?=
 =?utf-8?B?UTRqdnE1OTNyNGhQTXBFQmlpQUxJeGZES3ZMQjVVRHRRQ0cyUTBrNTdiYnRU?=
 =?utf-8?B?UFR4eDBXdTZXUjBHMGxXaE5qaGxEOURGRERrTGtRejF0aFkxMWs3emRtUzl4?=
 =?utf-8?B?YkN5N1RNUmdSb0ZNQkplTHI2UmxqNkxrY0Q1YUZCZzJjYmRjalNKOHJvZmtW?=
 =?utf-8?B?MjROa2tuYWYwdEVwbEZSWmxyNExXYm9nZmF4Qmswb1c4VVFMazFBREp5Qnlu?=
 =?utf-8?B?SkI3ODAvOUlqVkd4WENEek14aVpEVlFhaWMyVmREMW1PeG4yc2g2Q0U5N1Fu?=
 =?utf-8?B?dFBjRlRHRmdJaTV1WkpyLzJoc3I5dGJPQWdBY1A3ZUsvdGpTYm4yZkZZMFhl?=
 =?utf-8?B?bEZyTk53OTY3d1hZUzNrQzdJQXlmdm9uWnBjU2xWdUxORVV6Z0w1SU8rNFZC?=
 =?utf-8?B?VUxuMVVWT1VCanZzY0JFbnR0S0Z3TkFNdG1LeU9yeGtTdXlUalh4TEhRdkE5?=
 =?utf-8?B?TTBkQmpJblVUTGM3ZTRDMnRXbWdOYzQ4LzFVVGkrSk8yU0JPU0Q2dE1TY3JI?=
 =?utf-8?B?ejRZR3ZBTWhrU1pIcUxGcmRvTXFhRS9DK3VEQkN5VDdJZk9JR2N5Qk5WTEhL?=
 =?utf-8?B?MVRMellhc3o0VDFIS1EyeVFkVjNIbWdpaEJzeUhBaDl3bGo3RDVXbStSa3RV?=
 =?utf-8?B?RHRTTm9YKzU0eGUxM1VLYVhYMnlMWDZhSVFOMWxEL0lMZ2dmVWg4cWxNMzlQ?=
 =?utf-8?B?NGF0MlhBVEVQZmtyemp3K0ZicUg5UWp2WXFYWHNzQlFuK0c0NmFzUDVWK0JT?=
 =?utf-8?B?Um9BSHJtQWZ1SEtYZGlNYldnMWxQdmdxK05IVDJKckZhQzVlVFFXZENKd0xY?=
 =?utf-8?B?TXk0QlNMckhqVDNFOUttS0VWYndwN3VvRXFYbnR5ZTJwU1FuaUFaWlRpV3o3?=
 =?utf-8?B?ektsNDhLSWw4a1NBdHlXSkZmTGd4T0hXRHY4YWJLbER5L1hIczRUcUExbVNr?=
 =?utf-8?B?UzZvZGtpeU1iMWdxTFZSSWJLeWY3UmRIczF2OGxOYURVc1lNQUxBQzZ3S1hL?=
 =?utf-8?B?Q0oybFJMSndrYld6SVdVblo2VTBta2Y1U3B3aHdxdEI0a1lsWG4zdlU0Myt6?=
 =?utf-8?B?NGh5bTMvMjNvQUJSajl4bEtvK1BjQ09JV1RGdVZWODRxMjQxWGNjRzNJaSsr?=
 =?utf-8?B?MWJhU2lxdndCRzg3eTgyc1pGbU54bW9QMG5rU0NPVHFEV3lpb0lwUG9RbHJ2?=
 =?utf-8?B?UWh5T3p6ZVRRWHg4Q1poMWFSTmZUK2x5SVdFNEtCVysvb3c5bGc4amljOUZK?=
 =?utf-8?Q?R/ujq4WvnGQtE6GJaS4ZOSr7CC22kEWVvT6gKixGMKfI=3D?=
X-OriginatorOrg: outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 31628e30-aa93-4b27-a5b1-08dbd93bf0c1
X-MS-Exchange-CrossTenant-AuthSource: VI1P193MB0752.EURP193.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 30 Oct 2023 11:32:47.1352
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PR3P193MB0976
X-Original-Sender: juntong.deng@outlook.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@outlook.com header.s=selector1 header.b=mE8jRvB8;       arc=pass
 (i=1);       spf=pass (google.com: domain of juntong.deng@outlook.com
 designates 2a01:111:f400:fe0c::827 as permitted sender) smtp.mailfrom=juntong.deng@outlook.com;
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

On 2023/10/30 18:10, Dmitry Vyukov wrote:
> On Mon, 30 Oct 2023 at 10:28, Juntong Deng <juntong.deng@outlook.com> wro=
te:
>>
>> On 2023/10/30 14:29, Dmitry Vyukov wrote:
>>> On Sun, 29 Oct 2023 at 10:05, Juntong Deng <juntong.deng@outlook.com> w=
rote:
>>>>
>>>> On 2023/10/26 3:22, Andrey Konovalov wrote:
>>>>> On Tue, Oct 17, 2023 at 9:40=E2=80=AFPM Juntong Deng <juntong.deng@ou=
tlook.com> wrote:
>>>>>>
>>>>>> The idea came from the bug I was fixing recently,
>>>>>> 'KASAN: slab-use-after-free Read in tls_encrypt_done'.
>>>>>>
>>>>>> This bug is caused by subtle race condition, where the data structur=
e
>>>>>> is freed early on another CPU, resulting in use-after-free.
>>>>>>
>>>>>> Like this bug, some of the use-after-free bugs are caused by race
>>>>>> condition, but it is not easy to quickly conclude that the cause of =
the
>>>>>> use-after-free is race condition if only looking at the stack trace.
>>>>>>
>>>>>> I did not think this use-after-free was caused by race condition at =
the
>>>>>> beginning, it took me some time to read the source code carefully an=
d
>>>>>> think about it to determine that it was caused by race condition.
>>>>>>
>>>>>> By adding timestamps for Allocation, Free, and Error to the KASAN
>>>>>> report, it will be much easier to determine if use-after-free is
>>>>>> caused by race condition.
>>>>>
>>>>> An alternative would be to add the CPU number to the alloc/free stack
>>>>> traces. Something like:
>>>>>
>>>>> Allocated by task 42 on CPU 2:
>>>>> (stack trace)
>>>>>
>>>>> The bad access stack trace already prints the CPU number.
>>>>
>>>> Yes, that is a great idea and the CPU number would help a lot.
>>>>
>>>> But I think the CPU number cannot completely replace the free timestam=
p,
>>>> because some freeing really should be done at another CPU.
>>>>
>>>> We need the free timestamp to help us distinguish whether it was freed
>>>> a long time ago or whether it was caused to be freed during the
>>>> current operation.
>>>>
>>>> I think both the CPU number and the timestamp should be displayed, mor=
e
>>>> information would help us find the real cause of the error faster.
>>>>
>>>> Should I implement these features?
>>>
>>> Hi Juntong,
>>>
>>> There is also an aspect of memory consumption. KASAN headers increase
>>> the size of every heap object. So we tried to keep them as compact as
>>> possible. At some point CPU numbers and timestamps (IIRC) were already
>>> part of the header, but we removed them to shrink the header to 16
>>> bytes.
>>> PID gives a good approximation of potential races. I usually look at
>>> PIDs to understand if it's a "plain old single-threaded
>>> use-after-free", or free and access happened in different threads.
>>> Re timestamps, I see you referenced a syzbot report. With syzkaller
>>> most timestamps will be very close even for non-racing case.
>>> So if this is added, this should be added at least under a separate con=
fig.
>>>
>>> If you are looking for potential KASAN improvements, here is a good lis=
t:
>>> https://bugzilla.kernel.org/buglist.cgi?bug_status=3D__open__&component=
=3DSanitizers&list_id=3D1134168&product=3DMemory%20Management
>>
>> Hi Dmitry,
>>
>> I think PID cannot completely replace timestamp for reason similar to
>> CPU number, some frees really should be done in another thread, but it
>> is difficult for us to distinguish if it is a free that was done some
>> time ago, or under subtle race conditions.
>=20
> I agree it's not a complete replacement, it just does not consume
> additional memory.
>=20
>> As to whether most of the timestamps will be very close even for
>> non-racing case, this I am not sure, because I do not have
>> enough samples.
>>
>> I agree that these features should be in a separate config and
>> the user should be free to choose whether to enable them or not.
>>
>> We can divide KASAN into normal mode and depth mode. Normal mode
>> records only minimal critical information, while depth mode records
>> more potentially useful information.
>>
>> Also, honestly, I think a small amount of extra memory consumption
>> should not stop us from recording more information.
>>
>> Because if someone enables KASAN for debugging, then memory consumption
>> and performance are no longer his main concern.
>=20
> There are a number of debugging tools created with the "performance
> does not matter" attitude. They tend to be barely usable, not usable
> in wide scale testing, not usable in canaries, etc.
> All of sanitizers were created with lots of attention to performance,
> attention on the level of the most performance critical production
> code (sanitizer code is hotter than any production piece of code).
> That's what made them so widely used. Think of interactive uses,
> smaller devices, etc. Please let's keep this attitude.

Yes, I agree that debugging tools used at a wide scale need to have
more rigorous performance considerations.

Do you think it is worth using the extra bytes to record more
information? If this is a user-configurable feature.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/VI1P193MB0752753CB059C9A4420C875799A1A%40VI1P193MB0752.EURP193.PR=
OD.OUTLOOK.COM.
