Return-Path: <kasan-dev+bncBDLKPY4HVQKBBUUP7KRAMGQEUIFYEPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F54C700EF8
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 20:39:15 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-30629b36d9bsf3951659f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 11:39:15 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1683916755; cv=pass;
        d=google.com; s=arc-20160816;
        b=zuUMpuh6dMBaaSfT/stf/AM2P8Ek33NmEZAofGMWUqDkUVTYKujIjtprNQszZ/8XwP
         8IlFb+XB2Hog5OrTe4fl9iq1le3BwDeat54hSFNwjCA6bPtqbQXhS2C9zyfoKs7bZSKe
         TX/CTGcA5FEL5B+efQFxqBJ6I4nVS22K7/Csh0VVDQkzDUpSKO9ua8XgYl+golLEDkEw
         aczmPmBM7FD1zhOxx4XL5CDjYAwQ2A4g/fw7c8kGQR0ZoO8vRwqsFHpVG9JFWjiVImQC
         jnZm/SjSY7+0YIhDMbpwI/ltn7XcBog+COzN7MeCuylaIjbb1t4JdIq3nJFbHioaUJTe
         WaqA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=9eiZP7BKRGFwUqViwhRPMiM+iOJgmUshG8ispre9wEk=;
        b=dLVua3vVsBGanjFapodEEpTb6JkGqnD5b8JycPVo6eRyvM1D4NMfAoieyMt/2w4g9B
         DBF0imBdvI4VnMQ76xsLEhX/8wy2aLVC0CYXvYR4wg9vRIJXolcFjhs+T66ckxorASOf
         pZ/8IrQP6u7CQ5K5+etUdyD+U7AdvAok4KXXwy2uhwEku35DXpEogNhl9o2D9LixatK7
         jpBurIDcgKP4xcEt1nXU65UsdCjnA5q5/aKZSlf2TtbLbWm1HiGg9A32dYlyg3yy1x0w
         le7chWL5kozLRA+ueBvi9AhwXZgCWoCYlZnbp4r/Oo+5IaFKSXD08j2KOovxR6o7f/IK
         Hk/A==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=p0L8NX2l;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e18::607 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683916755; x=1686508755;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9eiZP7BKRGFwUqViwhRPMiM+iOJgmUshG8ispre9wEk=;
        b=Ud+YC2kPrZgKjbE7SWVmgliVjpvPUShPPjWcQMGYk+vnufCWD3uo2BovRadIiBTu1g
         +8ZOkuPof8x4whLoCIZxDaPgnV/suR62oXin4kVA7BGR8JMY72v5rxDzi71xpZdA7dBq
         809mTmyY62npD0OpFnRy8VilscypaXmdeMwwiXVziHRp9gKxARYeWIMEISimJRABz4iL
         PvqPNDzmYp6MM4DwrbbzVfwzDONfNPhNeMJcMAGV8fyuQLANJjdA8IStyYVoRBpad2D7
         hN8ScgUv9CkEwDzd/NMJGlFtCYcIOSZptt4RRhwyOjtnGbvUt1CLu/i3nMXdJ/8Z52KT
         LNPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683916755; x=1686508755;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=9eiZP7BKRGFwUqViwhRPMiM+iOJgmUshG8ispre9wEk=;
        b=Z+I3mLZuE2hS/WmVcH6KjorFd23WCIb9meGqfqS04A2bQ5mK+zoxR4XYhNkCHEXjhl
         y3Wll0lc+RbZxrt2lrN8Vu82lHv+j40siWGPdd8Wqpc2+wcutNepXLCE8ls5VMz7q/pk
         tOQBJUo++elxuD/TSqVYi8l8WLd9VUwTmlIiZ1zOBuIftMoni6fWVtcx71VvtThknB32
         8JAwi9/KYsXrR1KlL2fTNIJw89OK55n+E/UUigCVegH3tq+ZiSl5Nn733HywA3SzADsy
         GKyIFd/onywdFR3KJOD/fPT3odCWWAzLQOkC05OAUXuIZf4XVzjqkxKIvkjHkF6zui7g
         CqQg==
X-Gm-Message-State: AC+VfDwCFjFCt1uAelkK53qQujTIu2iA8tX4i6YWdSNyTxZFJW67i2b6
	F89Sga4UyqmkKJFiF60Gkfs=
X-Google-Smtp-Source: ACHHUZ7kFvVsI8jHa3OtPSBsFN/t5pFJ2DUq8vsUl3hXE+3YzWhqQciFmBk8XTx91E+aL0IdTva1fg==
X-Received: by 2002:a5d:4004:0:b0:304:6c66:da45 with SMTP id n4-20020a5d4004000000b003046c66da45mr4269955wrp.1.1683916754815;
        Fri, 12 May 2023 11:39:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1f81:b0:306:28af:9a26 with SMTP id
 bw1-20020a0560001f8100b0030628af9a26ls2834692wrb.0.-pod-prod-gmail; Fri, 12
 May 2023 11:39:13 -0700 (PDT)
X-Received: by 2002:a5d:408f:0:b0:306:3352:5ba3 with SMTP id o15-20020a5d408f000000b0030633525ba3mr16087550wrp.25.1683916753641;
        Fri, 12 May 2023 11:39:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683916753; cv=pass;
        d=google.com; s=arc-20160816;
        b=qw4T/vL6S9bwsYsIodmLoJHOFBcB5XMu9GSpolSXIqxezNs4e2BHc6fZnbKlsEHp1a
         4L45c9SfGROawB2p+0aLgV1bhgnmmxgm8re8C5AJMf/3gFRb0ueuYICFNLejKzFL9n1t
         /OKyp0ZPDaJJ/ESL3Rxz5BSBr8jik867QLqRiXlW9qwQuCHlec98/rzuhpycdxfNxaNi
         NN3IjPph9HCn7T0wGgHNcD87bDg2gF+DSjEtquGKwc14bMvVfvU1zupBVgHGCwB/gLnC
         19o2fOvtRVok2VQHAraxQb47Sq/6n/9W+5jh+n9PkuDtJ+5ZehV1j8a/vTTMgNNOBS7V
         rV3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=+qfv6XuLwp5nIaz97l48PzMBiT64UrWO8h+pnOdJ6fo=;
        b=szvPOWV7mlpf2xlsM4iQ7xBe/MzV2MWegH9c1AtSSCSvhRSN8g63dUmcUE4kpFZtF4
         bKNRvENpNLjGbnfymLu7uKViZtelRT0Gi592PWowEgPhB7G05YjTf5BYPk2bzPp4+6Tx
         wbqf2aMjM6DdA26aq8UeJjunAHtbhir+92wdolyetGw0GvS1xVREW4+2mMwyq90v9Sjb
         dfYJDFe6cmBThPUiuqGvCJjJbKXwNg7GQQFjI6I++O+JIO8enffPIq4OMMxijsSSlqhQ
         7LrioMqr/NBemh1lcm0Z0iSjATmNBBE4A+USyOhykRnXQV+spXcSlH/zpeZfuXLiQRdA
         1Ccw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=p0L8NX2l;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e18::607 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from FRA01-PR2-obe.outbound.protection.outlook.com (mail-pr2fra01on20607.outbound.protection.outlook.com. [2a01:111:f400:7e18::607])
        by gmr-mx.google.com with ESMTPS id d4-20020a05600c34c400b003f42c1b8171si802711wmq.0.2023.05.12.11.39.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 May 2023 11:39:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 2a01:111:f400:7e18::607 as permitted sender) client-ip=2a01:111:f400:7e18::607;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=XfnGeh2JWyPoewlqWhC8XRs6p6avn/Mp9rkifgDvyOgZoKqTXkAx7HgYOx8HXsf6slki3ULtC0cKckaV/nAX5zLwFF5yBI4u1MhEQd7pZ5nms2iHcKOQFO9G/P/LQQ/FNdF/ZMOr6zMssJ788lI9UIhPUahGU8dTf1cKdLNQ+JC2uZfJG+Z62fsxyPDo6QryS4oOrvxaGnoCiYP5VTRkpsydOisIMPkUcsKq6VazICW7OEus5jZ7BKMJ7PYmfeKvF3f7WnyiPAervk+lxXaayQ0hQdGigtaSLKjCa/s8JFW9sB7MODEe6jb6QZGyqiOwqDT7gdGlBKuCE64UwKw8VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=+qfv6XuLwp5nIaz97l48PzMBiT64UrWO8h+pnOdJ6fo=;
 b=Mqb2bT0rZl9UhvdfD7YlSqeLZ/B5r1Pe8g39ZBLNNOZ9SOOJZeb7tKtoAkc7smfrmfL+TtLGZpJmYm2RSE5DRLbTfHVY2b2YEE5Kao6PSWngrhqcj0Y4cWOluDhOxsnHe+oguGsHJrOQoIFHCSgDrvvps3abarTTXmNbtX9aQfrtbUjBZLmrFWvgDdDQEC5ksd7IPhkHqYz0hYgJFI0cPgkz/ukqVriSrmUwx3lLu3+ZVAjOu9et7MKj0z4YItyvLRFpbj1OVbzAQH9pZged03IWqbDG+1DgfC9Pimnm+fGv0eWzL60rpg/8AhCBw9K15vKmQo7E3GQGSSP2aW9YXA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by MR1P264MB3169.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:3a::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6387.25; Fri, 12 May
 2023 18:39:11 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::447b:6135:3337:d243]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::447b:6135:3337:d243%3]) with mapi id 15.20.6387.021; Fri, 12 May 2023
 18:39:05 +0000
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>, Michael Ellerman <mpe@ellerman.id.au>
CC: Dmitry Vyukov <dvyukov@google.com>, "Paul E. McKenney"
	<paulmck@kernel.org>, Nicholas Piggin <npiggin@gmail.com>, Chris Zankel
	<chris@zankel.net>, Max Filippov <jcmvbkbc@gmail.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, Rohan McLure
	<rmclure@linux.ibm.com>
Subject: Re: [PATCH 1/3] kcsan: Don't expect 64 bits atomic builtins from 32
 bits architectures
Thread-Topic: [PATCH 1/3] kcsan: Don't expect 64 bits atomic builtins from 32
 bits architectures
Thread-Index: AQHZhObYG9e/mwHrHEeZ3NvtNork5K9WzokAgAAptYA=
Date: Fri, 12 May 2023 18:39:05 +0000
Message-ID: <662d074e-58cf-3bde-f454-e58d04803f34@csgroup.eu>
References: <cover.1683892665.git.christophe.leroy@csgroup.eu>
 <d9c6afc28d0855240171a4e0ad9ffcdb9d07fceb.1683892665.git.christophe.leroy@csgroup.eu>
 <CANpmjNMm-2Tdhp6rDzA7CYvotmmGmLUnZnA_35yLUvxHB=7s0g@mail.gmail.com>
In-Reply-To: <CANpmjNMm-2Tdhp6rDzA7CYvotmmGmLUnZnA_35yLUvxHB=7s0g@mail.gmail.com>
Accept-Language: fr-FR, en-US
Content-Language: fr-FR
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|MR1P264MB3169:EE_
x-ms-office365-filtering-correlation-id: 22ecdda8-31e2-4f21-d28d-08db531829ea
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: qQt54OYzxLswlRwhkrLzUIa8OmQRg1bmmGLwRrnB+tGZTobhblHYCdukGwN0CZ8heRKcGu85+JQ6dmbw3le7XACT0s5c8A/F1EIK6M9HNfD6BbWFQVFo9RucUJ9rSspQCRu5ECtF+bTh20fR7OT3ILEPdT8mdvw0PEtsC5e67jtxF8r2xS5o8tAY8wTsjaD13c5I8EPqOK5WXZnMKHl4L2MT7cDiHdQ+NzakkKrXze9bo5NEUYcFjaEQe0fXKqyjvMjR1yEOYQ3+2X0XFink+mkIwF7zb9jniFH5ErqnHQN2CGVXjsepLplMcXtxwqcVOYaRjWuy7KIdYI56/XsoRzdZ0XzJemcEFEiA14OR4Day3xHYbqQ6tA98IR6i/6rMiaanjVujk6AIAyzkRkrQKETpQ0d8CDCRVH2FKEEXydMcIybqZ1yA2ZxbeAopZO6fcUmUp4NqUEjX4pI2C1jOVuYBA5pJ+rNXNXds8id6F1lV1DyMJSYRjAfdRQTiSfogWJ6N7etVKxfiUFoLi6/ql7M0viNpeRqJym1586JxikXn5e54zbpUElVNlYIzY7wgDjrhmjDzi++DWQVj2UZKtfdaHoAhXiIkz2Ig7yuQe/5jFQi+W5a3ZrS8AqdFEhMSTd59/jUCeaG5edKAcz3o9DGTdNhCrEipdE4FeFGJzNBi5uCvOTu4STd2FhIB0zEh
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230028)(4636009)(376002)(136003)(39860400002)(366004)(346002)(396003)(451199021)(54906003)(5660300002)(6486002)(91956017)(41300700001)(478600001)(110136005)(31686004)(71200400001)(44832011)(8676002)(7416002)(8936002)(186003)(2616005)(2906002)(66574015)(83380400001)(76116006)(66946007)(66556008)(66476007)(66446008)(316002)(4326008)(64756008)(38100700002)(122000001)(38070700005)(86362001)(6512007)(6506007)(31696002)(36756003)(43740500002)(45980500001);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?djdBT1VSWGtKUDhmRU9qd1RRQjVtbEVuMkpLZVR4cG4yczBIb3JVQVlkWGJU?=
 =?utf-8?B?UlBCZ2tWc2k4VlNOQnZ4NVA0T1Q5SW5tMmpXQlM2YUpqRVBkc3ZRWlJYbndT?=
 =?utf-8?B?K1lLS21BWDYwUExKNitkTHc0cXg0Z2tOR1czU3VYVGVGNEZvdkdGMWlUUHpi?=
 =?utf-8?B?WEd3NllUMExyV2g3NWlmdyt2c1p3VGZ2azZ1aTR1RTNnOGgxNlpvRmthSjdG?=
 =?utf-8?B?SDRuekRyb2dWczIwS3ZqT1ZlcFR5KzRXK2dBZ3U2ZmtSTDU2NEZNT21qalh2?=
 =?utf-8?B?WGdKaEEvOGc1UEdGMktrM2M1TkM1dDI2ZUgySnVvZkhsM3FmSlgvWXhrQ1k2?=
 =?utf-8?B?Vk9vVDIvZ2ppVlRmZTVkZVM0MHVYcmVrdFF0TUZFMjRuMGJPeVluazNwbHF2?=
 =?utf-8?B?aEhZRHVrZlI5SnBtQm12N2xreUs1NjRBNXdWcE5QNWlVYjhza3JEcjBiSG84?=
 =?utf-8?B?anByL2RIYlBGb0dDZ214UXFQbVRWem9yZ0VxNU05UXVCVjRDOXdWblE4VDlR?=
 =?utf-8?B?KzBuWDg4ZldFTXJXUEV2VG4zc1VtY05sZzgyZStlVjgrMlc2b1NMalJJVHBQ?=
 =?utf-8?B?VVZLTFYvTTVJcG1Bb3V3aEEwYlM3clpkTklwQnRsRFRsNk9yQVFNaVBTS29s?=
 =?utf-8?B?enM4T24yMnRQMjllY1IvTVBma0d0V1dtb09kUE5Qc2JGck0xUTdWSi9CRXJ6?=
 =?utf-8?B?aEM0bkN6SmNQTFVsaTRQRGlLZXZnM1I2SWIzRjlnQndQVkh4MUtOaWxVRmh1?=
 =?utf-8?B?Ni9KalRFK2VxbFhQL0lpMTh6ZU92aEpTelV1ZzBwUVNNeVNkV2s2YnlSd0c4?=
 =?utf-8?B?SlRyRlVOaVZ1dDRxbnlJeUFMOW0rUlVBRm1ZeEo4emNFU0IvYTcrbGg0d3lW?=
 =?utf-8?B?VkxKM1cwdi9hdEpEaDNTaWtVZFp2Z3pnZTg0SUdRRVozTU43ZTVwZS93MjR2?=
 =?utf-8?B?S0FVNEZra29xcW1uSWNsU1Y1TCthRFVSbTRRTHZUQXFmZDJPSXpuVVBWaGNZ?=
 =?utf-8?B?SkMzYTZIQldLTXhLVk9jMmZ4MHVxUHh5T1NaRmlISFBhSHM5QitNSWI0K1NJ?=
 =?utf-8?B?Wk11YWh5MXd6Q0RGV2QxZlN4bi9OMDFMbytTMFhvcTdnMVBvb3luZEZNZzAx?=
 =?utf-8?B?am8yTjN0NVZkWVUvUG1pTCtjVmsrVTFKQTQ4QUlTN3RmUGRjWksyb1BQcHVN?=
 =?utf-8?B?S2NlcjhxTGl3WVd5WlR1T0xGM0VtV3VFcnBqdnd4YlNEMDdXT1JBMnFJa3Vy?=
 =?utf-8?B?aXg5Sy9Na1pXSmtyaTcrUW1qWFBGMWhyUmlUUzJFUGtYVElTMXNhdW1LVHNp?=
 =?utf-8?B?RDNYMGVGTkFHREFIWThvb3A2cTE1U0Z6QSs4U256UURXcCtOeUR0MEJqSWJ6?=
 =?utf-8?B?a3JvRzk3R0EySG5OeGpMMjB0cG9ERTl5WGgrekJjOEppUi8vQ3g1TSszZllp?=
 =?utf-8?B?eGNxb0lmeEZoclgzTVdVbzRvbU8rY3hvbGY1aWtHSThBZGZtQ2Z6anZpTmxo?=
 =?utf-8?B?Um1JamdCMElLcWdXOThrRnEydTA1VG9BNHh6OHYrOVdVRTFnM2ExbXFmTkF3?=
 =?utf-8?B?bnZwOE5jMk9hVFQ5RU4yMURNdXV5bEZGUExac1AxOVVVSjlqaEdxV1lVREk4?=
 =?utf-8?B?QTVvV09rMS8zZVRLNGwrU3hCZ3NLb0l0UFNkc2wzY29lOGN1QmZwWTF2RFlN?=
 =?utf-8?B?RjFuTjM3VFZjQmlwS0JWT0lEWGpvVldMQUVobTVuMGp6R3pYZmx5a1pRS1VM?=
 =?utf-8?B?eE1VdFRSK2YydjJDdnYxM1U5bjUvMHVueFB6aGViQzE1UjJpTTBIRVBUU205?=
 =?utf-8?B?WkNDNTd1T0xueVo3dVZvVWVnNlVwbTYxeHhXSGdWTkpCRDBzNkhHT3d3OWxI?=
 =?utf-8?B?MW4zbFBZZUtQVktIK0ZiVWtsTm9xeFZBam1YcWlPdm9nellyZ1JNVjhaOS9n?=
 =?utf-8?B?ZW4zRmM1bFV1TmxEOXRlb2dnK0JlQVErZEpVeGwvTG42TUJjR3RVSUlpV3l6?=
 =?utf-8?B?VlJISTRjQ3VvcXA5ZmFRWUpnVmF2dlYyT3VRZUtCVUgrekpQank5d2pWa2Z0?=
 =?utf-8?B?K0pSbGZQcDZlUExKZWMzUkdoekUyL0FTU2MvSFBQdnJSK2NUSllXNVllMTBM?=
 =?utf-8?B?YTFLQkZtNmFjSmFPcVZDbFp1TlpDSHJUT2JQNEUzdGlhVTBaWXpMc2Q4OUsw?=
 =?utf-8?B?NjgyclJWNzhUV25UZ2JFK3VHZG1yd2VadlhndFZRUnZFTlIxL1lqTVExUTJt?=
 =?utf-8?B?L1o0U1J0ejI4SmE1NFF4eTA5QWVnPT0=?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <CFD821636717334C9060DDD10CC0CED1@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: 22ecdda8-31e2-4f21-d28d-08db531829ea
X-MS-Exchange-CrossTenant-originalarrivaltime: 12 May 2023 18:39:05.0133
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: FzoLI5Mxw77jc80c0b2uWjGFN53Tua3WUJGHLYFZcUfPEr6olnRt5n2VW7J/AGcRB8bvKYwyOxbYuhU/WyRUdI7bTONnSaEnuSShZbgZgic=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MR1P264MB3169
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector1 header.b=p0L8NX2l;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 2a01:111:f400:7e18::607 as permitted
 sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 12/05/2023 =C3=A0 18:09, Marco Elver a =C3=A9crit=C2=A0:
> On Fri, 12 May 2023 at 17:31, Christophe Leroy
> <christophe.leroy@csgroup.eu> wrote:
>>
>> Activating KCSAN on a 32 bits architecture leads to the following
>> link-time failure:
>>
>>      LD      .tmp_vmlinux.kallsyms1
>>    powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64=
_load':
>>    kernel/kcsan/core.c:1273: undefined reference to `__atomic_load_8'
>>    powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64=
_store':
>>    kernel/kcsan/core.c:1273: undefined reference to `__atomic_store_8'
>>    powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64=
_exchange':
>>    kernel/kcsan/core.c:1273: undefined reference to `__atomic_exchange_8=
'
>>    powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64=
_fetch_add':
>>    kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_add_=
8'
>>    powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64=
_fetch_sub':
>>    kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_sub_=
8'
>>    powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64=
_fetch_and':
>>    kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_and_=
8'
>>    powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64=
_fetch_or':
>>    kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_or_8=
'
>>    powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64=
_fetch_xor':
>>    kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_xor_=
8'
>>    powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64=
_fetch_nand':
>>    kernel/kcsan/core.c:1273: undefined reference to `__atomic_fetch_nand=
_8'
>>    powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64=
_compare_exchange_strong':
>>    kernel/kcsan/core.c:1273: undefined reference to `__atomic_compare_ex=
change_8'
>>    powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64=
_compare_exchange_weak':
>>    kernel/kcsan/core.c:1273: undefined reference to `__atomic_compare_ex=
change_8'
>>    powerpc64-linux-ld: kernel/kcsan/core.o: in function `__tsan_atomic64=
_compare_exchange_val':
>>    kernel/kcsan/core.c:1273: undefined reference to `__atomic_compare_ex=
change_8'
>>
>> 32 bits architectures don't have 64 bits atomic builtins. Only
>> include DEFINE_TSAN_ATOMIC_OPS(64) on 64 bits architectures.
>>
>> Fixes: 0f8ad5f2e934 ("kcsan: Add support for atomic builtins")
>> Suggested-by: Marco Elver <elver@google.com>
>> Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
>=20
> Reviewed-by: Marco Elver <elver@google.com>
>=20
> Do you have your own tree to take this through with the other patches?

I don't have my own tree but I guess that it can be taken by Michael for=20
6.5 via powerpc tree with acks from you and Max.

Michael is that ok for you ?

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/662d074e-58cf-3bde-f454-e58d04803f34%40csgroup.eu.
