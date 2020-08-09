Return-Path: <kasan-dev+bncBAABBIHBXX4QKGQEENMTZ7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id A850D23FC4F
	for <lists+kasan-dev@lfdr.de>; Sun,  9 Aug 2020 05:42:24 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id o9sf1906332lfi.23
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Aug 2020 20:42:24 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1596944544; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q5pBqARzH3ZfZx6pF5BpwXKY85fUkbrQIc4EC2XwtPiZ1YRo0kwcMEZxM49TcaBwb7
         h28vyr8zqKQtPcdBorwVIvW1a7GBGH9v+M3GTXhdq/KANUJPL3m3r+zra4x/J7Cal3ka
         39wg4l98mLn8XL+2eB77TDuZppWuxi/xShewmadygdbP2AblQBaJgx2wZH7GGTSFbpS/
         qamSTde3O2VOg17M1TI4BQxxJvq8imMkehBVZdbo05KGIyiJXRWCBowpFHn5C4MJBmMk
         QszLuQSJFbcM+WuVS9MflcK2ty9+KL2YdBgFWptSQe8ekZxE/DMs0SgTpZ/HqxmoGUrG
         dvHw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :from:sender:dkim-signature;
        bh=3MKP8BzLyucMn4XCqBs7k2RobJecDshayRjzMAwlqo8=;
        b=ISG5H87w+wFQbn2qx6AZQFaUl0b+3P8omu2CgCAQ8Z3K7RnFvRxDqZ0CX9BdszPQbH
         k1q2XEwArNY63yQbPlWHrsMoR6atCNSwV2vOo+62TU7w5D4LH4wfz6J9HBCo0R+b9G3a
         3ZmmvxZEVm4imeE4Gca8DFKwFqb4kzjRtNnlUqLvU1QVEPWwwrLiwIB/2GfkE4N5UxVH
         kuecaZ15WQoApv9NDAHW7jzM4vgZb7C8ZJqIo2moKvuYFy+t5pw9W1OMLZ8y56ytMVdp
         6aHbTqZtGgLO6M4FKlbUTrC6TLb06v099QzQFf9AxCmykw7Kr2nioYzoEwPnd/bj6GH0
         KvAQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@hotmail.com header.s=selector1 header.b=pHwG3zdX;
       arc=pass (i=1);
       spf=pass (google.com: domain of patrickmmgomez63@hotmail.com designates 40.92.91.27 as permitted sender) smtp.mailfrom=patrickmmgomez63@hotmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:subject:thread-topic:thread-index:date:message-id
         :accept-language:content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3MKP8BzLyucMn4XCqBs7k2RobJecDshayRjzMAwlqo8=;
        b=fRxsJ6auEEtmSLTZCnHINt1HfEADREqKg6H3aAFMu2+aLrd6ychmWWM7XgjqnIKRFW
         CxuZSUyrQixjTzzYSV4YIK+yxVR0kM9mNk3bRq7mB2SC8RlCAaHp6ZYOydDoEZEWPbCj
         OCEKir9Gu6bQKZGOdXf1asO29Br+InZk7KLh3EWEYX+zYG6m3lBMQ1q5rCOvumHysfl8
         QTFiLyQOCQP3YEQbcRFZ70mc/rR5C1gfjl7KjGnYLsz2cowT1zFc7f7ZjvbCHSwB1MUb
         2DKE9Co4aBF/Yf/pP9y0ZexHM3l5+rcCK0DWdle/gWbUe525JIR5LIXsZ2cay3vpyezV
         1nZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:subject:thread-topic:thread-index
         :date:message-id:accept-language:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3MKP8BzLyucMn4XCqBs7k2RobJecDshayRjzMAwlqo8=;
        b=mX5FgxWkpLdmYo2lezI5KRDl14W8L1WO3sQGTtZPe6KK3TELjf4CMd4TJt+7osl5dr
         2q/hqUcUh6CDsPWsQokHU5c8qI4tCL3rD/giB04tX2nqYtA/fV/cYXx2YTdbNgrzgTLm
         838UmIatLccXFPCiTwkHLxVMlgcQx3eVMfRevvwzb5vL1xMKfFKP1fGIbIaWQEcDIeGs
         sc3bo4HbSetFNKNKZ40anrejhU8mmC/r7JpN3A2Ak5Qyig8tphPMR7yinFU/mo1ib0Rd
         HjuURoXMmS20pmQ4RHXDitW9GjIY8wvYNMnZlDMo8oxXopVOvI0DKVZ6AMEgiyCsVQp3
         61/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530V1wpETVQPn5IjkqoWTlDodwehou3HT8tLiSj1SbntWOxxv6fH
	OSHL/Vqi+zLeWtx04wm6UNs=
X-Google-Smtp-Source: ABdhPJzyLdPg0XComPuHKoGmsCW3eeYAletBXtTxckWoHDUimmqbebXeSt0RXxJJJD/UWO4fY5gs5A==
X-Received: by 2002:a2e:990c:: with SMTP id v12mr4782449lji.449.1596944544113;
        Sat, 08 Aug 2020 20:42:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:6c18:: with SMTP id h24ls776477ljc.6.gmail; Sat, 08 Aug
 2020 20:42:23 -0700 (PDT)
X-Received: by 2002:a05:651c:d0:: with SMTP id 16mr9800641ljr.313.1596944543752;
        Sat, 08 Aug 2020 20:42:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596944543; cv=pass;
        d=google.com; s=arc-20160816;
        b=B6U3urGpryj5mpU/TqHBKpahXR47ojVTR++LuWyoMxYIBE7IZnx/n9rm+ykH6hio0L
         Aca/MA9akCcYlKiaIjVWXY6yM09scg1XPphKJG0gKkhrGnLJdT0Oy6+8EXBpp9l2TDDy
         F+gtlfm9VjCuUQTtWqeE6k9dd5YBSmTpAeSPusrvJKsh4kfb3VbhJ29DqqW5t2kHQJ3M
         k6RA/+pnZnVCoTgeqbjKG4xYMV7O++t13k0/sc1Y/jKOQnU9CIWGM1uAGwtNe0xdEW8q
         FgFdpvazfHdrK8YBrGtwHBQsUckBPNNvSIy3S3va7zqNihXRXNnJhkHjv2z5K6YeSseu
         gc9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-language:accept-language:message-id:date
         :thread-index:thread-topic:subject:from:dkim-signature;
        bh=ZZVgqPRdHa3mYC6h77JNf5U8WJjmc6pLcloPrHOl+M0=;
        b=lY8x/6uYJmjmHVGp0TzQP+c0Ow3O/l+LMlwIldnNs+enUHIZ1qKDJWB56l5t4Z5fJp
         ZypEgIle+npc0WP4pj/O1krEAcbhNk0hQ86FhrIy6YndmDvq8IjYf5odi69IZrcfRRv+
         CSuLHzdS6C/NbAtAZ3Y0wMjuCcARj2TJhV5TEboJCrYhYKAVkm2SRyEQfIKB2GOy2DIW
         d0m7D/loDGeoOyyHOEI5Z54OMHjZ0cIlDi5H493l15DXk3FX3NEh2P7R0YD2CddYvASa
         SFvkkuNML3oZNaYHwxchihmjQc4B9ts/6LVyQ3hBquwdcJbv+yHPbPEBFX1W6kIjjzrP
         7H6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@hotmail.com header.s=selector1 header.b=pHwG3zdX;
       arc=pass (i=1);
       spf=pass (google.com: domain of patrickmmgomez63@hotmail.com designates 40.92.91.27 as permitted sender) smtp.mailfrom=patrickmmgomez63@hotmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hotmail.com
Received: from EUR05-AM6-obe.outbound.protection.outlook.com (mail-am6eur05olkn2027.outbound.protection.outlook.com. [40.92.91.27])
        by gmr-mx.google.com with ESMTPS id f16si367733ljk.5.2020.08.08.20.42.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 08 Aug 2020 20:42:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of patrickmmgomez63@hotmail.com designates 40.92.91.27 as permitted sender) client-ip=40.92.91.27;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=j8uJRlQSiZgP2dg8S4w98M4Z0IzIfyD8NoMuVUIqD2mwNvRK46JgDDIeqddcPS4d8KuR9NfXPxyzLVKocs7qk6i5mIrxYmN8MIRmJYFTIpIa5APDP1iyA8RaHBhDevFFcfunaKvxEufU6UT7R3XR/x+GIKClwjt3OeTlAjHhQxm8tSv4tWu+MKSGjN6oH8WDUNsf+6d0tM10GZojHnsiChH+j+VFgaHxTDInQ1Dk/nsSwXgLwEravPS2pKC+eCNploSvODFDo/mM8V9xOveGNfJz3pW8VGsBvbBU6psY+yjFPn/SooYzeUAHXTEKqYSY/yP2H0u7/W+HN8B6fyYOJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=ZZVgqPRdHa3mYC6h77JNf5U8WJjmc6pLcloPrHOl+M0=;
 b=m79eWDj4bJE9l+JPP5rWcjalfBEjPUEoKKPZuWPKmLsep/DxOGHZl+QLOmpa/gdnAc0AubvX4UBz9uNSNRE4dEv8c4rI0Ri+HNRUOa34agbrtwrYi0MgFHjKfGkjgtr55wIAZ5jI6c0ko82mZ1AppqohO4UnMQtrVm0ggDm/UVd5oV5Xwin+3WzzeqHRCb+C0gkFQJgmeOhJ1M1ud5qczJfS8CvTlzOArRnk1pWUvbp+m0UlePqcJ/B33zyiI/G+EJ8y8T3ETR1ZRp5yFRkk5OJUesGMQpgiW8unsVYjmSqloGQODIgHwV+UZXXA03Ijq9plITybtBe0UQ8u8mgcLQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1EUR05FT008.eop-eur05.prod.protection.outlook.com
 (2a01:111:e400:fc12::43) by
 VI1EUR05HT043.eop-eur05.prod.protection.outlook.com (2a01:111:e400:fc12::280)
 with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3261.16; Sun, 9 Aug
 2020 03:42:21 +0000
Received: from AM4PR0202MB2962.eurprd02.prod.outlook.com
 (2a01:111:e400:fc12::52) by VI1EUR05FT008.mail.protection.outlook.com
 (2a01:111:e400:fc12::437) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3261.16 via Frontend
 Transport; Sun, 9 Aug 2020 03:42:21 +0000
Received: from AM4PR0202MB2962.eurprd02.prod.outlook.com
 ([fe80::a03b:db92:1e25:20f1]) by AM4PR0202MB2962.eurprd02.prod.outlook.com
 ([fe80::a03b:db92:1e25:20f1%6]) with mapi id 15.20.3261.022; Sun, 9 Aug 2020
 03:42:21 +0000
From: Patrick M Gomez <patrickmmgomez63@hotmail.com>
Subject: Re
Thread-Topic: Re
Thread-Index: AQHWbf8WYJJPl+uBuUeJP8wXY9ucFA==
Date: Sun, 9 Aug 2020 03:42:20 +0000
Message-ID: <AM4PR0202MB2962B44030A5937F363BCA03C6470@AM4PR0202MB2962.eurprd02.prod.outlook.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-incomingtopheadermarker: OriginalChecksum:56E1FC2206B9EECC82B96AE8744A21D1FC7E155AB86DB577BB2E9E23AE4A9F92;UpperCasedChecksum:43AC20586C5CCE4CD52333AB8A8E02668D714A2F02246008D5BE1EFCB51C533D;SizeAsReceived:9046;Count:40
x-tmn: [zZUWOi8sqqAAE2sgPyu3dAzVNUvMn0bF]
x-ms-publictraffictype: Email
x-incomingheadercount: 40
x-eopattributedmessage: 0
x-ms-office365-filtering-correlation-id: 7789c1e2-429f-4d22-0e8c-08d83c1638b4
x-ms-traffictypediagnostic: VI1EUR05HT043:
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: W8cpyeUODPUBBQpRh7efs+PBf9Clen8o02deT8Tse/q0TzxeKw0AULTizvn68PiHfql0Tn/JGpCS3JgrRMjr0Bs9+3NWP0Ks7VBnX9RB1f4o+GjQ4Ai+ZMTrhou+zojs7Nn1Ws3Fb8w1zWoDSWiFZDYbvEh4l78xRJiEs2KLYCUTi5BFifgw0De4KjIq+aTobdisO9K09ft6TtGWaRHfMg==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:0;SRV:;IPV:NLI;SFV:NSPM;H:AM4PR0202MB2962.eurprd02.prod.outlook.com;PTR:;CAT:NONE;SFTY:;SFS:;DIR:OUT;SFP:1901;
x-ms-exchange-antispam-messagedata: PA3/kMCHsXbOhzEsXzGJpROSXum0vbPSNPRA8/PUFFUVAxFjGlLwO0zVXoQJxa3qHasGZWPlMyRx+tZRAx/rT6siOZA/aqZXDvHO70eUavi3seOWN8+C79cAIv0bu33/a8UepnQqZNj9HlyAVaHIgw==
x-ms-exchange-transport-forked: True
Content-Type: multipart/alternative;
	boundary="_000_AM4PR0202MB2962B44030A5937F363BCA03C6470AM4PR0202MB2962_"
MIME-Version: 1.0
X-OriginatorOrg: hotmail.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-AuthSource: VI1EUR05FT008.eop-eur05.prod.protection.outlook.com
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-Network-Message-Id: 7789c1e2-429f-4d22-0e8c-08d83c1638b4
X-MS-Exchange-CrossTenant-rms-persistedconsumerorg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-originalarrivaltime: 09 Aug 2020 03:42:21.0047
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Internet
X-MS-Exchange-CrossTenant-id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-Transport-CrossTenantHeadersStamped: VI1EUR05HT043
X-Original-Sender: patrickmmgomez63@hotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@hotmail.com header.s=selector1 header.b=pHwG3zdX;       arc=pass
 (i=1);       spf=pass (google.com: domain of patrickmmgomez63@hotmail.com
 designates 40.92.91.27 as permitted sender) smtp.mailfrom=patrickmmgomez63@hotmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hotmail.com
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

--_000_AM4PR0202MB2962B44030A5937F363BCA03C6470AM4PR0202MB2962_
Content-Type: text/plain; charset="UTF-8"

Is this a Business or Private Email?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/AM4PR0202MB2962B44030A5937F363BCA03C6470%40AM4PR0202MB2962.eurprd02.prod.outlook.com.

--_000_AM4PR0202MB2962B44030A5937F363BCA03C6470AM4PR0202MB2962_
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Diso-8859-=
1">
<style type=3D"text/css" style=3D"display:none;"> P {margin-top:0;margin-bo=
ttom:0;} </style>
</head>
<body dir=3D"ltr">
<div style=3D"font-family: Calibri, Arial, Helvetica, sans-serif; font-size=
: 12pt; color: rgb(0, 0, 0);">
Is this a Business or Private Email?<br>
</div>
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
om/d/msgid/kasan-dev/AM4PR0202MB2962B44030A5937F363BCA03C6470%40AM4PR0202MB=
2962.eurprd02.prod.outlook.com?utm_medium=3Demail&utm_source=3Dfooter">http=
s://groups.google.com/d/msgid/kasan-dev/AM4PR0202MB2962B44030A5937F363BCA03=
C6470%40AM4PR0202MB2962.eurprd02.prod.outlook.com</a>.<br />

--_000_AM4PR0202MB2962B44030A5937F363BCA03C6470AM4PR0202MB2962_--
