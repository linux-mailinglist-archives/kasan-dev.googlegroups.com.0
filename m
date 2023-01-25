Return-Path: <kasan-dev+bncBAABBYNOYOPAMGQEKGPT6TI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 001D067AABF
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 08:16:49 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id p1-20020a05600c1d8100b003daff82f5edsf10496435wms.8
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 23:16:49 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1674631009; cv=pass;
        d=google.com; s=arc-20160816;
        b=WxMuOcvbcmVK9ZaQ1Lt1YRrXI9BGWbXVnZkaPXl4dGNnveBb/HryUoRhBpAlYNSsTC
         84EyolEW+B54sUUUR4NSlJvytkJYyjxslwu/G+V6aFIihoxqzuSA7VdNkNyibkUs+Uod
         +gWlJ8+jkhwGWkzyKHU1OYqOCvPCgglgEyXJZ4Y0gPMBefn4qhmuIq+ac0vdpjuNeJQc
         xNK2aFAIEK34J0VBcOffZunwT/V49QDbmlbPsshO70DIXcTB7fjPG3VUbPJX5jQHnrqi
         UUWjJ91CAPYZZzBJ5vKo1A6somva9oRNkdCIiqBCtOxEmayrpOnb9sYMTCoa2v7TGMC+
         CYrw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:msip_labels
         :content-language:accept-language:message-id:date:thread-index
         :thread-topic:subject:from:sender:dkim-signature;
        bh=JvpW8rZJIZ+u+8nic7c8ZVSDJKMqjCeiqcj9bL/RLcM=;
        b=fU4chfwQHY2sVGXIDlipfm9k3+KJWrcJJjkkfFybD04mjRBCc4ilCfCAn8tGPk9Ktm
         Q/QIlFrgEWckaVR/INf2AI6rmNFgahvcbq1mLp7tDimHSmxGrW8na6pPXWRdDRsSmcC/
         CCysvAvgY7+NXhxDlomq7UM1sJV4t5AfpBxA9YZMWAeNAirmZFFmue8ib8ofydv1bF0Z
         MMnTbnHTf1dhlMm6bg8Vlbjy/2oGqrlkAaujiyGmRdc/GNKGLKzDrgBStd7xcEzjqpzw
         3dMcQApRoK3G1e5gRXO7hNo7XxzEBjBWdr5VYA3z6xh9sIZnTh11AjtxrQdqrBsOy733
         mQ2Q==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@hotmail.com header.s=selector1 header.b=I0olGctH;
       arc=pass (i=1);
       spf=pass (google.com: domain of patrickmmgomez74@hotmail.com designates 40.92.75.63 as permitted sender) smtp.mailfrom=patrickmmgomez74@hotmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:msip_labels:content-language
         :accept-language:message-id:date:thread-index:thread-topic:subject
         :from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JvpW8rZJIZ+u+8nic7c8ZVSDJKMqjCeiqcj9bL/RLcM=;
        b=J16am8xrIjFyOULSxAtp1NiyAPOVA4iQRCiImKMN71eYak0lK/h66yiVQEfDpeUt4C
         3+/D/t7xFRvu3Z0P0pILQK44OuKMHyEXV3/gwvd6Gnft/GkxzO3f3/PQlOpocJ7wTSRn
         eK+LVTC7UzSFl+pvnKfJ0j8lEjSQoAIFJsjGJMBPd+tTro+MunMf46OZjWnr1so57c+X
         Ec7JtX7HQYNRB9F9TTMta+d2irNM352gRXn/S5U8iofNC40iMJ6v+7mhQrIRA1oVNpm3
         IFtqb0bWsmrAKw3FHztHoxrVwa2SToTv5eCi1C7m4ViVKtdiP+8edCAuSIBCXfL96qS8
         r+4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :msip_labels:content-language:accept-language:message-id:date
         :thread-index:thread-topic:subject:from:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JvpW8rZJIZ+u+8nic7c8ZVSDJKMqjCeiqcj9bL/RLcM=;
        b=XNeH9nTEnspboxP9ZD5rq/9YojWyEKD8UWCs2XH3uYhBZdjRESoORfWHBJglUIHuJq
         bdtFA5gqwCHGdHO6eX2j2HNQoYjmjQ5KypgQD2wgbt/KyZ4JpOy3fMsBodU3veBlt5E1
         19g8VHkqVqBcYsCqGjgtCe08EzoLafIanerKM1KDWzO/7EukwME3bVacmA8CgBae1xAn
         BuZtMkNmAhxjdsEDzE5eO5/Ez9Scs79KAmQBDftlvRAUjqCVpEWXk3bKIQ0NnJ5tT2mi
         74cVOniPqajswKmYxeMV5OnezGfuTB+Jv+aBVCKDh03oDjsCaTauzQSGLdS0U21v0sXB
         rEog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kr2Qea7azLD8QUZxQGFN6ol6l9Gqo7w4HWKY9IJsMfKsamKkBca
	Us0c8MWciPG1V8B6C5Nunk4=
X-Google-Smtp-Source: AMrXdXtcgbTKA6s11YvYbAjV6zGINdLlXZB2ny3oQ/2lrj1wsMH+U0U7Yz4sxFQJGsZDZh1CHb6uIQ==
X-Received: by 2002:a05:600c:4e0c:b0:3db:15d9:1484 with SMTP id b12-20020a05600c4e0c00b003db15d91484mr1747362wmq.200.1674631009521;
        Tue, 24 Jan 2023 23:16:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:3c7:b0:2be:34f5:ab03 with SMTP id
 b7-20020a05600003c700b002be34f5ab03ls98761wrg.3.-pod-prod-gmail; Tue, 24 Jan
 2023 23:16:48 -0800 (PST)
X-Received: by 2002:a05:6000:1f14:b0:2bd:c03f:c010 with SMTP id bv20-20020a0560001f1400b002bdc03fc010mr28169580wrb.40.1674631008780;
        Tue, 24 Jan 2023 23:16:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674631008; cv=pass;
        d=google.com; s=arc-20160816;
        b=IGJHJj3JzyPrXfaKoL5ga0Eqs4uEp1XU6Ibj3xAkTl+IBr74X2YsefQmHKBLP/Xq5b
         WgU39uVKLPNa6AbxwBKRVBTXleQgXSqcp0BD+K56nF4Sxub50jKwVrl9OwehOTsnNHp7
         8IrDiLp5R4+a78qZ8euipXwtuMkIvFW4J4LDUPPY2zVXjv9Ap97A1jij314CLjMxrVhu
         jBpXHoOc5Asa9cdULMldIHrX6TbHHY/d2eeHg9oQhjmTeBpJrUl85WpILM/fg4wmrbiP
         k1b1/I+uNmvvHKNDj4yjmPMBlVYSr4iOdw5Osn1diNqmrqPG3YdFaXUQA2bxVRNwKxUZ
         xh6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:msip_labels:content-language:accept-language
         :message-id:date:thread-index:thread-topic:subject:from
         :dkim-signature;
        bh=OM9acsoMAdVKPCV+lSj2vUvKSSq3VaAc8rnxHb459mc=;
        b=UkGN4n0aA+6hqX0TnJdL2+vfeMw30F8b4Sr59/hGGlWhjViZ3MK2YLFiGCSUgkvZdg
         SdzvYpg61Dg5wonRAWrnaF9y9TQMXu3G59TEX2jnBEuRuQVxQLK9PVb4IOaH0SYEiC+3
         RzV6B5/9WXlyoyv2+IMOxxlC5Kev/9iBKbrvjZgJBlE94PEq7lHkryqM+VP1n9qF8zMz
         jpgpW/JPHlu9r7yOQC2vQjXLYUrFFvqYzFmzHUdUWhv5S2HwQCog/KqgCJoChQ7XKJGS
         1ukjJI2l66KY+e2KUNBSeF9LoLDe8cwY7VNLt4MrtiB8JlPM3+ToXhOLMkbfNqtHqMOb
         78TA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@hotmail.com header.s=selector1 header.b=I0olGctH;
       arc=pass (i=1);
       spf=pass (google.com: domain of patrickmmgomez74@hotmail.com designates 40.92.75.63 as permitted sender) smtp.mailfrom=patrickmmgomez74@hotmail.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hotmail.com
Received: from EUR04-VI1-obe.outbound.protection.outlook.com (mail-vi1eur04olkn2063.outbound.protection.outlook.com. [40.92.75.63])
        by gmr-mx.google.com with ESMTPS id bo15-20020a056000068f00b002367b2e748esi204004wrb.5.2023.01.24.23.16.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 Jan 2023 23:16:48 -0800 (PST)
Received-SPF: pass (google.com: domain of patrickmmgomez74@hotmail.com designates 40.92.75.63 as permitted sender) client-ip=40.92.75.63;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Pk/K5tRonthHa+FC9aqWnCPBM362j+lPkCA/kwuGMvKn6gi9dK/YCl0gRKvZa/amOF2/CVmNOg9kANATYLF5s9DbQBNxwdtgY82YLI8Ta+pJe2y8JhuEmH9tXo1fbIAUpo3Vc2Ky87SX902dxN6VJjyZfGGfbk/0McDJzEB84Et5saiEWJhOCmxRFhBLMnhpaNxHg5SA3IvHDgfCmHyj3c/4jBHN1fMzLZjeb8nypMviHLvbwKhkXfjWT5niZfPr1V7AZxD+Vr3RuRpKmmmcOqKYoD32SdjZ2N/snOqkajg9TYHBu8DSIFLfrgytW1kQ2XY+fFr9DVOwdTA7BRXiaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=OM9acsoMAdVKPCV+lSj2vUvKSSq3VaAc8rnxHb459mc=;
 b=OPeyeq0OtkuoNy+AYSL5FJSHJvQNEDunBE6GVD3qh0VPgFRZup3zLYLS50EHdGfnTXeMx2QGY/sCZw981VbiT9M02ZvnLx4cj83gzFrotv6RQo54Y5kotthL1DrnHX7l4KtAsCSTZRZLI9aXbr9jgHXsE5ctAmSfdZhG3CN3YuEYg4EF1In/k8wiMK+WXWml6kM6jAOR07q8MG0Qtv8KyBn0VL1IA/Jm/dRZOdfyU5b7hzyoRGpqCDUB6SpGjPH+WgCxFfGi0v79KkENYbuMTp/uFFJUEGM+buHOY2QuPyzJ4yxGAYvQcpoF2mi8yWVmVDEMpXsplAaiuayuiS+LGg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=none; dmarc=none;
 dkim=none; arc=none
Received: from VI1PR04MB6111.eurprd04.prod.outlook.com (2603:10a6:803:f9::13)
 by AM9PR04MB8507.eurprd04.prod.outlook.com (2603:10a6:20b:432::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6043.21; Wed, 25 Jan
 2023 07:01:45 +0000
Received: from VI1PR04MB6111.eurprd04.prod.outlook.com
 ([fe80::5645:53aa:c9f2:5fc]) by VI1PR04MB6111.eurprd04.prod.outlook.com
 ([fe80::5645:53aa:c9f2:5fc%7]) with mapi id 15.20.6002.033; Wed, 25 Jan 2023
 07:01:45 +0000
From: Patrick M Gomez <patrickmmgomez74@hotmail.com>
Subject: LinkedIn
Thread-Topic: LinkedIn
Thread-Index: AQHZMIrjtb8CRjQkMUOf45WwDoaymQ==
Date: Wed, 25 Jan 2023 07:01:45 +0000
Message-ID: <VI1PR04MB61119572BE85724D708302EBC0CE9@VI1PR04MB6111.eurprd04.prod.outlook.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
msip_labels: 
x-tmn: [qNIYxo0TeRTnrAZwdJM4eb3j3QYumZ2f]
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: VI1PR04MB6111:EE_|AM9PR04MB8507:EE_
x-ms-office365-filtering-correlation-id: 649ca497-51c0-4f79-31e8-08dafea20588
x-ms-exchange-slblob-mailprops: 5mfCsI5gB0sKAs1DBgEjoJzDGs2XlCORqnRW+Xh35oIXwEMebqGvP06PjhgL/nJB/CkpprmG1JvjqgxMwOMIYq7utyiPDgRY6lMWvoyCUpbc6raHmArwVLFqGrVWpR+P40BeT6RMZFXW4bHZeI6PPnTZtOK0HbvJOV25R/YekYeQjbQhVdWNsnXyYlnLtGBbx5PPmXAFgxAyklsoGDITMdjlM9WL7/eJJGIcRgjuhOGAwAt7D68EInIhFCbdTDowUt6XwCOeYEGuID9Kl8GJtdFWWzqmZI4OOZ/oIJIAPz4XMjBl5eao+SYJ3HnBeGbMFPVK90dQKUQzGfFAdA08LIp2Uvx78lngfn+sYbPnKoWeZkdaUpsB0lseYRkyTDMhAk138b4kUUop4x0oR8S5iDn1dNCDe+IBwrsxpG/kaMcoOInpl3SmnYw4Zzx4SR5CYa1e0iOqUrAQjZc6MF+EFPVJVjPNskQTmAeVxzIalyUwGgltb6y4Gfmg1/CzqOwnH0dFfrzzGSg3JwH/0u29OyFN4bAMpjaomF81UnwVNLa27Ivpum4F+n50lFAeHwR49H6JN2T4GXrzN8fQcx7zhnYILIw1vQcsI3+vrK92dkAotvRP7zxcYQ==
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: MrQQ9x4RfCaeiXIqvdGlYHz/oDMMlHR6Nt+mClAWibtzsyP1QkV0TWRO6mTe5hjVJJw2cxgTyykmGJdRAYmMNOskxvwjRscaHzQNbCKX0C7037OuosRKqnzZJ2GusZnWVc2ZyojF7ZhoPihCJSxxa+tjOavXwelP/SCywqnVV5+nmq1CVAMR2FZr6+Oat4epglJz5xRt+dFQlHSLGnEkWwx8m9Eg9sa3BcFeQFTrdt2CqiRKhoVJ5iIguuNnGb10ATzBoXE4jL7N3r4RqNzTvpb0FhsyPmLGFzVuCihLiWz4z+ALVZGS2Ox1N0wAQbv64JA2O5DvMVRcezl9VdRYUyEdYc4lxrqODB1ZyBnkpJNm/qTIlfO5n9tRHv3iOngdJmJR6wmYaLjZyGcZjRTnisU8dWSI15S4BW+VmtZmmdS/zJmCHpxAumTCwk9fOKMqK70aRK9vViedf/7Gc31T8Hqk5o5GieWXEDATzdLCQw/dJbfNN710o1A1vYdOqerjVWdDGGSEM7fhAe2qr+45UrgjXgzYn/i+7uyrzwsu+kPFlK1F0X1sxXZCLdjS2opoa2oopBxWyc/Vvj7lLisXRYeoct2vJ+CIjmFZmDg78FQ=
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?iso-8859-1?Q?Y+ypnXgethinQTp+ewFRlA+ekhOu2BxOeuQGPc0moK1/dDVFO8wa7+Rgux?=
 =?iso-8859-1?Q?4f9Eo1t2qvdjPQ5JGuESNWhfyhlplNbSWcxtMqk3Zp90mF0zXajXyvfzrB?=
 =?iso-8859-1?Q?MKkv4Fhmm5f3lj6VME5uRa7V0WUs0ZCR8MnindlCpJyDVwUVR5wgJG0X7Z?=
 =?iso-8859-1?Q?DThptdqsDXc1jfR/qPs9qEY52qky0gX8EcBNRNOkNmQDAZoLpP5D0YKt8+?=
 =?iso-8859-1?Q?1kSYwjj7NGjvjrMJGbTQeWpXFIr5YdbXM/32wmQdn8jbiurFYhu+Otdhnx?=
 =?iso-8859-1?Q?hdZsajs9uYseGBY00tBEC7mM93ZZUWv5Uk5zUbjC+grzxqKEBVzc1RvnBB?=
 =?iso-8859-1?Q?GCQ9u+uoFtVYJGgMQ9TxSWOqF4uyZQMbW0I+sj6Yz/PlnOW4aGcZc+uFF7?=
 =?iso-8859-1?Q?qPARE3H0P6Jq3gZlzZvhjKcuLyX8L9vh0XAskZNhX55itoef/fAWiLKpMt?=
 =?iso-8859-1?Q?+P/92LF80MTHWEj0WhyM4XUE+fpWhSgNQjoTyVsuTgvOElJsN9CXsEeCVm?=
 =?iso-8859-1?Q?vbr0/6dMGHWMnxqjm8oMBv5xsd2XLbAFPqbLGSX7N0hYDR8C2UBIT16hAA?=
 =?iso-8859-1?Q?V4hS2ai8rBZBPae/jA4w/3gOCZrx3rLXJyCbzFiwhqHz4E6QPAy3rxdfG/?=
 =?iso-8859-1?Q?Lzfo5sHqpINyGRqTGKXG93SA/kLaY8mFEiTwzd1d6mBksG7YOp3nQwFjZ5?=
 =?iso-8859-1?Q?2GjFcA0d+l8W0/zVraNbUoHE2NMm0BpEw95DtqZOj34E305IXTusEVi2XF?=
 =?iso-8859-1?Q?SC8UKPV5RCuEztH35xmKO0MPRzNowO8+oJPZsXwLKgBwYrtWuAVDGWTNOQ?=
 =?iso-8859-1?Q?3From5lGEbVyjEkmfMxotYCTh+oAgP7eDURTRmJoXW9Fh2h1UD9gQcin8d?=
 =?iso-8859-1?Q?nSA6d01J4IN/CeuaZFw1omzo2qdCOs9Q0EJloFkKpecWsWc/quxAjUKwjW?=
 =?iso-8859-1?Q?uRj8LkXxAgDCQQ8DHMvnxb6rFmd7B7QY5I7rea19QtGG8lCgO4Tn0BdBWA?=
 =?iso-8859-1?Q?sKHhYnO/U/ygnNp67Wyxy/JSzea62UDwNaXrVpt1HpkxFLHyDWy5ME86au?=
 =?iso-8859-1?Q?VcbiXpaIMGmG6GUMZI0fV+qaOLvGOy3bXXNX+l7aoD5w5l3U9ZgavpDaz/?=
 =?iso-8859-1?Q?Qpx/z/ToVUkNX+5vg5Xq7dUR7HOHQD3riJ7nWpUFdRr5wouvZukYD/rGrt?=
 =?iso-8859-1?Q?MCiJf4CW34PahUtGDOUjBvp1X01TzuGfi3/7hmD+sDYxH0yEnYJybeknme?=
 =?iso-8859-1?Q?Fw905reHZ1yeSiYPewcZH+rcvRAPxJLYtAFDhG7RY1zDnssnltJ7ylicEB?=
 =?iso-8859-1?Q?GvtbubF5KePQHlSUKcB0yTVfUA=3D=3D?=
Content-Type: multipart/alternative;
	boundary="_000_VI1PR04MB61119572BE85724D708302EBC0CE9VI1PR04MB6111eurp_"
MIME-Version: 1.0
X-OriginatorOrg: sct-15-20-4755-11-msonline-outlook-03a34.templateTenant
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: VI1PR04MB6111.eurprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-CrossTenant-Network-Message-Id: 649ca497-51c0-4f79-31e8-08dafea20588
X-MS-Exchange-CrossTenant-originalarrivaltime: 25 Jan 2023 07:01:45.7159
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-rms-persistedconsumerorg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM9PR04MB8507
X-Original-Sender: patrickmmgomez74@hotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@hotmail.com header.s=selector1 header.b=I0olGctH;       arc=pass
 (i=1);       spf=pass (google.com: domain of patrickmmgomez74@hotmail.com
 designates 40.92.75.63 as permitted sender) smtp.mailfrom=patrickmmgomez74@hotmail.com;
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

--_000_VI1PR04MB61119572BE85724D708302EBC0CE9VI1PR04MB6111eurp_
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Bitte ist das Ihre pers=C3=B6nliche E-Mail?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/VI1PR04MB61119572BE85724D708302EBC0CE9%40VI1PR04MB6111.eurprd04.p=
rod.outlook.com.

--_000_VI1PR04MB61119572BE85724D708302EBC0CE9VI1PR04MB6111eurp_
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
: 12pt; color: rgb(0, 0, 0); background-color: rgb(255, 255, 255);" class=
=3D"elementToProof ContentPasted0">
Bitte ist das Ihre pers=C3=B6nliche E-Mail? <br class=3D"ContentPasted0">
<br>
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
om/d/msgid/kasan-dev/VI1PR04MB61119572BE85724D708302EBC0CE9%40VI1PR04MB6111=
.eurprd04.prod.outlook.com?utm_medium=3Demail&utm_source=3Dfooter">https://=
groups.google.com/d/msgid/kasan-dev/VI1PR04MB61119572BE85724D708302EBC0CE9%=
40VI1PR04MB6111.eurprd04.prod.outlook.com</a>.<br />

--_000_VI1PR04MB61119572BE85724D708302EBC0CE9VI1PR04MB6111eurp_--
