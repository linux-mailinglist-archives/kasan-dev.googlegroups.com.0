Return-Path: <kasan-dev+bncBDPOPFG66UIRBKWIYTZQKGQE3RW34DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B604188DEB
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Mar 2020 20:25:31 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 1sf715895lft.9
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Mar 2020 12:25:31 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1584473130; cv=pass;
        d=google.com; s=arc-20160816;
        b=FZC5WPKyJj44M5QmAmIT1bS8+R3bKj3n3FJ38A6A8lKf8Qpa/N3lEC+UNk9McxXGDC
         rd5IOsayQa66I/zMqzraDTCBVNTXIx4em/H/ktCQxbHnkIyKZcoIxvovP4yyF0IzwHyv
         BexgaFhgEQz907YSYSlZ/7XKRRFIhZsNQu+Ns5/zqN30c1/rM/IuUCAPJMqB90JhpeSP
         bmy3tGcR6QmsOiAaUo4eIsYORruki9sKYuseYDJHJA1SqfH0I5A40TZPXC1CTY6Tdr2/
         vDrPlat0G0DQkMft0QKL6zSoi95p3P+0HLKJFbwCQqq/iRkiCGne60vTAjcACrpw53M2
         x98Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=zKwrY/P5mG0zO9aDNKcU/aAHWlq9lY5Rp0obdXr3iYM=;
        b=iaBMfFpBh+q0A/5kcKiOclg62/mcSjIW/Q+OsIDKzcrnMNIQAhbXNOUSfLbpBjkPa7
         Hmeo9+PZpBsBZ1c05B6GYkyg2uIB6rot2XMowL+SHwinDmIcBYOjO29iglAk/qmsXoeZ
         00N4r+NkGHyAEch2miS6ehcfuxdcqcILBM9WmLEE/HlZyZUGI1AL/IjSIAiWoTWxRJto
         PzcSfHcW41+8+VCr2nCaQQXkpXP82EbWjebWevlGxu/FH8X5+NaZYEB2LObwr1gyTNfk
         JO23nmaVXbmHsoxr6f7ubgrlqzJ0unIE1Rj0OyWthPYsKpAHALA0rG14NjpaETPzGmUh
         mfzQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@nxp.com header.s=selector2 header.b=aP8lAyE5;
       arc=pass (i=1 spf=pass spfdomain=nxp.com dkim=pass dkdomain=nxp.com dmarc=pass fromdomain=nxp.com);
       spf=pass (google.com: domain of leonard.crestez@nxp.com designates 40.107.1.88 as permitted sender) smtp.mailfrom=leonard.crestez@nxp.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nxp.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:accept-language:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zKwrY/P5mG0zO9aDNKcU/aAHWlq9lY5Rp0obdXr3iYM=;
        b=V4jmiqYxNGNBk/bpYp9+wqUuqA7yD1P4ZtAhUcAlHAL12Lwk2uyXhMY8831mjkj9vJ
         Xg8mR2RoeHabNBVky8lCjuSMyf2DXKxakK/bvkga863e8XcM6r8ugNyAN29pqGCTAQQy
         ooopJ3lJoD2UVHOmvaR34/u5ROp6HoxtiZ0arv8GHGpKzJGFC2es26FttV6byRnYEbqc
         jJ+JycbwsnJnPiRoGEg6cpujDW3ZsdDDcXLdJDqcPxZxp6tq+58pnBbNWV6Kj9TSo4xr
         OmojAXmtnBQIWarJZcXI90RBKbnwoif6dT2BjWR4H5T0HYDFqhN69yKOekSgbMkyN/BS
         QIaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:accept-language
         :content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zKwrY/P5mG0zO9aDNKcU/aAHWlq9lY5Rp0obdXr3iYM=;
        b=UfH/liMpOFJ1QaUGDVxs46Clj47VwtqwO74rz/LrmpJC1lI1Pf63yH5SSY/UGXql+d
         gEABsTCPsSmAhH57QfE8vsgemGOClCh6X85da8961Z2B5ZZXZF47P2YiL0SkHrDjHxko
         WU605ySckxBkucM8u52Gb07+Z6V1zDCLb5eJmCcP9YRg1VA2sVj3i9I373C+jOYsCx+b
         2AADc+5LXo7f6GKrplhf3KN78E8LybavwD4sxPBuhmm1XYJKhFcC2cLxtcqKfK78KdFI
         DXwyuIw/eCnPQlNavyFoP+FxK/39sUtNQt+R3WJjRG1BuKhFlHILY+uyY3LRXQ52vlY4
         00cA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ188+noh3knnST31VFR1T8niDWrrIx4+KzqHFyvadk8Yvqaascw
	GP7IAnJ0FqP1BJBKBhtbMPM=
X-Google-Smtp-Source: ADFU+vtyxJpCXnMGDZY3idkGoOSCVvo22pjrE2M1nyGyL+M9rS23F7bKDFvXikjOxjQkFsEzGPR8HA==
X-Received: by 2002:ac2:593a:: with SMTP id v26mr546725lfi.109.1584473130789;
        Tue, 17 Mar 2020 12:25:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8941:: with SMTP id b1ls3371866ljk.8.gmail; Tue, 17 Mar
 2020 12:25:30 -0700 (PDT)
X-Received: by 2002:a2e:9d11:: with SMTP id t17mr165561lji.169.1584473130155;
        Tue, 17 Mar 2020 12:25:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584473130; cv=pass;
        d=google.com; s=arc-20160816;
        b=JdlFJ91/88MoQ8edMo0wtBl1TtwIiaqhkElMKjfn9Uj38YdvkHBjRcOlrE2FnV2fE3
         O7SxugJfic0MTAr+kI8UAv7uQGkMYC1bFfT9VTL1U5vg0F3XceXTr/MJSgSle24I2yhT
         uqQ5L6WN+2bpWBh2f/J0xLjp4ECn1ajs48uElLmlECG5/Qajyz4wcBx4zcKqJDBK/mmo
         lvpcHAAJmVmjeYtbE6Gai1g6Am7YmN5XxtcSOkNd4ASNhIM2cEbs0oe8bXywpXoS9Rw6
         EXdoWw6SlS6/iXEidA9LUMdr/fam1y9gZBFflsrOQHhvQuqPlb++tmZ3cC21bV6Fb40A
         Ylyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=zRr6IIQSfIOzAZex5zW8dYAPAp+aahvugMA72oRtshk=;
        b=XnAs0ue71OL7Oxh0rVaBwnWigSA4B79qPFMzRACnEf3DJS65MG9bYMcohpwmguD8BG
         kmksCAMlRzKBHfmoTqAV9oHcHJVsVpJUj9ZPgNu8/CCXYcRJYuqFZbh7HmnwuWpuxImv
         gnv7NMM/1JJXfb70+5b0vmPycuSxbMp2bMFuuaY/mYwsFZPhGYuYkS7HJjUiaqw3sTPo
         UpLPriI69XKRY0bAt2JJ/u5G80qr/xM8LpqdOUMjYT4bvfV+bZA7dqWSYm0zvee/FAwY
         UZUb8mdKvLBCYaKDx1pmxnTC6LXIzbuKHDg5b+a2JUo9UqVemI90AyyWU8PIwGw2CTpp
         wshA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@nxp.com header.s=selector2 header.b=aP8lAyE5;
       arc=pass (i=1 spf=pass spfdomain=nxp.com dkim=pass dkdomain=nxp.com dmarc=pass fromdomain=nxp.com);
       spf=pass (google.com: domain of leonard.crestez@nxp.com designates 40.107.1.88 as permitted sender) smtp.mailfrom=leonard.crestez@nxp.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nxp.com
Received: from EUR02-HE1-obe.outbound.protection.outlook.com (mail-eopbgr10088.outbound.protection.outlook.com. [40.107.1.88])
        by gmr-mx.google.com with ESMTPS id b26si152417ljk.4.2020.03.17.12.25.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 Mar 2020 12:25:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of leonard.crestez@nxp.com designates 40.107.1.88 as permitted sender) client-ip=40.107.1.88;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=YwUUf+xos9Fu38Il5Ft1rLlvrmPC6fjcRreRxdTqCE2keVf+j+tRV9vnEsU5nnFwr/WtdZshMValEqJYk7xXs1kGWlVfShJEILdlpM72OiThybODsaPSlZ7omAF11VRcI6B4iMDh98+h9NNN79cwsAswnOs5U/NwCChsintWAhzI2Fg/0w2WM3Xw+39kmwvn6t+tur6Im4sA34FWUnqRGv7/F0fApDr42yOm5ZH2h00P1lvhjH/H7VPyrf2inzG4K2b8tzdxI/cgg7CwV+50+qNaBJkx5Cu3cVEUa4uc/DX6wzPbntCN+4EfUT+SuHT3ESVktgIugT9D+cWOUBfW5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=zRr6IIQSfIOzAZex5zW8dYAPAp+aahvugMA72oRtshk=;
 b=ZU1KuehTWsi0WjIWcmQAAIXuCiw8UZTqeaaFaWa5GhghoQ+J25iOPOV5Bkp0rp6AwKd0l40kRFFtXLyJ1YANfteM0NvM3zQxxq6xXFlWp/hHztt24E4N5Mbgnuvzyjpod3jfR/99BNa/ztUk756cJz8zpjPHrdQ9IW3LLdcWGSYYfOdkFfnvvkGlYVbs1sZqg2kUuLLUbmi13OxQkK5Q0yx7YLS2FECr2Dx8Fi9pFt+qm7GON+/scQAXdBJDc59q5Hy2oW+1m/mxUzGMeOdgSKQJsvEcS7V6ch6ilgLr4aktJQX/60R2nyGghLNWG1jfWaMqTEYP6F/bNrHSOfP/Fw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nxp.com; dmarc=pass action=none header.from=nxp.com; dkim=pass
 header.d=nxp.com; arc=none
Received: from VI1PR04MB6941.eurprd04.prod.outlook.com (52.133.244.87) by
 VI1PR04MB4430.eurprd04.prod.outlook.com (20.177.53.95) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.2814.21; Tue, 17 Mar 2020 19:25:27 +0000
Received: from VI1PR04MB6941.eurprd04.prod.outlook.com
 ([fe80::289c:fdf8:faf0:3200]) by VI1PR04MB6941.eurprd04.prod.outlook.com
 ([fe80::289c:fdf8:faf0:3200%2]) with mapi id 15.20.2814.021; Tue, 17 Mar 2020
 19:25:27 +0000
From: Leonard Crestez <leonard.crestez@nxp.com>
To: Stephen Boyd <sboyd@kernel.org>, Shawn Guo <shawnguo@kernel.org>
CC: Aisheng Dong <aisheng.dong@nxp.com>, Fabio Estevam
	<fabio.estevam@nxp.com>, Michael Turquette <mturquette@baylibre.com>, Stefan
 Agner <stefan@agner.ch>, Linus Walleij <linus.walleij@linaro.org>, Alessandro
 Zummo <a.zummo@towertech.it>, Alexandre Belloni
	<alexandre.belloni@bootlin.com>, Anson Huang <anson.huang@nxp.com>, Abel Vesa
	<abel.vesa@nxp.com>, Franck Lenormand <franck.lenormand@nxp.com>,
	dl-linux-imx <linux-imx@nxp.com>, "linux-clk@vger.kernel.org"
	<linux-clk@vger.kernel.org>, "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v2 1/8] clk: imx: Align imx sc clock msg structs to 4
Thread-Topic: [PATCH v2 1/8] clk: imx: Align imx sc clock msg structs to 4
Thread-Index: AQHV6Ar29fUTh/h0xEeUNN9RFuY7RA==
Date: Tue, 17 Mar 2020 19:25:27 +0000
Message-ID: <VI1PR04MB6941383E77EC501E96D2CBB0EEF60@VI1PR04MB6941.eurprd04.prod.outlook.com>
References: <cover.1582216144.git.leonard.crestez@nxp.com>
 <10e97a04980d933b2cfecb6b124bf9046b6e4f16.1582216144.git.leonard.crestez@nxp.com>
 <158264951569.54955.16797064769391310232@swboyd.mtv.corp.google.com>
 <VI1PR04MB70233A098DC4A2A82B114E93EEED0@VI1PR04MB7023.eurprd04.prod.outlook.com>
 <158276809953.177367.6095692240077023796@swboyd.mtv.corp.google.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [92.121.36.197]
x-ms-publictraffictype: Email
x-ms-office365-filtering-ht: Tenant
x-ms-office365-filtering-correlation-id: 782aa1a2-dee5-4b89-fb80-08d7caa8f2c9
x-ms-traffictypediagnostic: VI1PR04MB4430:|VI1PR04MB4430:
x-ms-exchange-transport-forked: True
x-microsoft-antispam-prvs: <VI1PR04MB44307A11C734F634C6F033BEEEF60@VI1PR04MB4430.eurprd04.prod.outlook.com>
x-ms-oob-tlc-oobclassifiers: OLM:1107;
x-forefront-prvs: 0345CFD558
x-forefront-antispam-report: SFV:NSPM;SFS:(10009020)(4636009)(366004)(376002)(346002)(396003)(39860400002)(136003)(199004)(186003)(44832011)(316002)(26005)(8936002)(8676002)(81156014)(54906003)(81166006)(5660300002)(7416002)(110136005)(71200400001)(2906002)(66556008)(7696005)(6506007)(66446008)(53546011)(76116006)(64756008)(478600001)(66946007)(55016002)(52536014)(91956017)(86362001)(66476007)(33656002)(4326008)(9686003);DIR:OUT;SFP:1101;SCL:1;SRVR:VI1PR04MB4430;H:VI1PR04MB6941.eurprd04.prod.outlook.com;FPR:;SPF:None;LANG:en;PTR:InfoNoRecords;A:1;
received-spf: None (protection.outlook.com: nxp.com does not designate
 permitted sender hosts)
x-ms-exchange-senderadcheck: 1
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: lho5ObqdQ9QumK0hbpy8nzcTQp5OPuBIJTujmOjVNxDEWd6lzs41w1RGDbkUutxi9cyjGkQmvbqavLrG0ZFKEf1OJtzbqAyC+Tm51GbMRDSCmskHtf4816W6E84NDzgpYGoFI0WqzhnyAGRKG40QO+3rlUlFsc2u9oLV3R/E1fjDQrefk/yJuHuQiST6Xcbe1taFMmHojvg6lJBHSnQqporNf/cPzvzCafuLvqco+N1Q7PVfGe9LxXoqZ6Tx/0u6mn9KPenRUSEkoA8op5RiIRxnLekC+ZGkJvRAAv+w7TopQbp3Y3HdjiaXJJ0Mv8etDyO7XEIQIsNl2ZYu5ze2YSWFyEcvhSWGUKNWQTruQ6JPtrH+t9tg9ATOveU0xXx/Ci2AJUqWr++fxML81B64BXUNKm175C6ej/xpgj4ceoMpL98Dw6xxUJDjgto3OgL2
x-ms-exchange-antispam-messagedata: YMkPkaOe5AdkRaTySb+dJSfCThH+oCTZREqNFaoXUeqjzIqFMQqz0hs/Ekdef8LXzFG4NldAGPnTh7HHcDoadaFxtRX4i43hdF9TpYv2etfpUkjwJvVzSTKFJvn/Jil3boiVhrCUjpSgIOqdalepGQ==
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-OriginatorOrg: nxp.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 782aa1a2-dee5-4b89-fb80-08d7caa8f2c9
X-MS-Exchange-CrossTenant-originalarrivaltime: 17 Mar 2020 19:25:27.1351
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 686ea1d3-bc2b-4c6f-a92c-d99c5c301635
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: kjL3YHcLIkDqxJxcwD9HHp5SJiGzq0xdz9KuNyGvNhoQU2FzRstowWWjUFlSCfsnM+bmO5UPPvWIXDKYpXqWHQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: VI1PR04MB4430
X-Original-Sender: leonard.crestez@nxp.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nxp.com header.s=selector2 header.b=aP8lAyE5;       arc=pass (i=1
 spf=pass spfdomain=nxp.com dkim=pass dkdomain=nxp.com dmarc=pass
 fromdomain=nxp.com);       spf=pass (google.com: domain of
 leonard.crestez@nxp.com designates 40.107.1.88 as permitted sender)
 smtp.mailfrom=leonard.crestez@nxp.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=nxp.com
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

On 2020-02-27 3:48 AM, Stephen Boyd wrote:
> Quoting Leonard Crestez (2020-02-25 11:52:11)
>> On 25.02.2020 18:52, Stephen Boyd wrote:
>>> Quoting Leonard Crestez (2020-02-20 08:29:32)
>>>> The imx SC api strongly assumes that messages are composed out of
>>>> 4-bytes words but some of our message structs have odd sizeofs.
>>>>
>>>> This produces many oopses with CONFIG_KASAN=y.
>>>>
>>>> Fix by marking with __aligned(4).
>>>>
>>>> Fixes: fe37b4820417 ("clk: imx: add scu clock common part")
>>>> Signed-off-by: Leonard Crestez <leonard.crestez@nxp.com>
>>>> ---
>>>>    drivers/clk/imx/clk-scu.c | 6 +++---
>>>>    1 file changed, 3 insertions(+), 3 deletions(-)
>>>>
>>>> diff --git a/drivers/clk/imx/clk-scu.c b/drivers/clk/imx/clk-scu.c
>>>> index fbef740704d0..3c5c42d8833e 100644
>>>> --- a/drivers/clk/imx/clk-scu.c
>>>> +++ b/drivers/clk/imx/clk-scu.c
>>>> @@ -41,16 +41,16 @@ struct clk_scu {
>>>>    struct imx_sc_msg_req_set_clock_rate {
>>>>           struct imx_sc_rpc_msg hdr;
>>>>           __le32 rate;
>>>>           __le16 resource;
>>>>           u8 clk;
>>>> -} __packed;
>>>> +} __packed __aligned(4);
>>>
>>> Sorry, this still doesn't make sense to me. Having __aligned(4) means
>>> that the struct is placed on the stack at some alignment, great, but it
>>> still has __packed so the sizeof this struct is some odd number like 11.
>>> If this struct is the last element on the stack it will end at some
>>> unaligned address and the mailbox code will read a few bytes beyond the
>>> end of the stack.
>>
>> I checked again and marking the struct with __aligned(4) makes it have
>> sizeof == 12 as intended. It was 11 before.
>>
>>       static_assert(sizeof(struct imx_sc_msg_req_set_clock_rate) == 12);
>>
>> After reading through your email and gcc docs again I'm not sure if this
>> portable/reliable this is but as far as I understand "sizeof" needs to
>> account for alignment. Or is this just an accident with my compiler?
>>
>> Marking a structure both __packed and __aligned(4) means that __packed
>> only affects internal struct member layout but sizeof is still rounded
>> up to a multiple of 4:
>>
>> struct test {
>>          u8      a;
>>          u16     b;
>> } __packed __aligned(4);
>>
>> static_assert(sizeof(struct test) == 4);
>> static_assert(offsetof(struct test, a) == 0);
>> static_assert(offsetof(struct test, b) == 1);
>>
>> This test is not realistic because I don't think SCU messages have any
>> such oddly-aligned members.
>>
> 
> I'm not really sure as I'm not a linker expert. I'm just especially wary
> of using __packed or __aligned attributes because they silently generate
> code that is usually inefficient. This is why we typically do lots of
> shifting and masking in the kernel, so that we can easily see how
> complicated it is to pack bits into place. Maybe it makes sense to get
> rid of the structs entirely and pack the bits into __le32 arrays of
> varying length. Then we don't have to worry about packed or aligned or
> what the compiler will do and we can easily be confident that we've put
> the bits in the right place in each u32 that is eventually written to
> the mailbox register space.

These message structs are not as complicated as hardware register, for 
example everything is always on a byte border.

In older versions of the imx internal tree SC messaging is done by 
packing into arrays through a layer of generated code which looks like this:

          RPC_VER(&msg) = SC_RPC_VERSION;
          RPC_SVC(&msg) = U8(SC_RPC_SVC_MISC);
          RPC_FUNC(&msg) = U8(MISC_FUNC_SET_CONTROL);
          RPC_U32(&msg, 0U) = U32(ctrl);
          RPC_U32(&msg, 4U) = U32(val);
          RPC_U16(&msg, 8U) = U16(resource);
          RPC_SIZE(&msg) = 4U;

The RPC_U32/U16 macros look like this:

#define RPC_I32(MESG, IDX)      ((MESG)->DATA.i32[(IDX) / 4U])
#define RPC_I16(MESG, IDX)      ((MESG)->DATA.i16[(IDX) / 2U])
#define RPC_I8(MESG, IDX)       ((MESG)->DATA.i8[(IDX)])
#define RPC_U32(MESG, IDX)      ((MESG)->DATA.u32[(IDX) / 4U])
#define RPC_U16(MESG, IDX)      ((MESG)->DATA.u16[(IDX) / 2U])
#define RPC_U8(MESG, IDX)       ((MESG)->DATA.u8[(IDX)])

and the message struct itself has a big union for the data:

typedef struct {
          uint8_t version;
          uint8_t size;
          uint8_t svc;
          uint8_t func;
          union {
                  int32_t i32[(SC_RPC_MAX_MSG - 1U)];
                  int16_t i16[(SC_RPC_MAX_MSG - 1U) * 2U];
                  int8_t i8[(SC_RPC_MAX_MSG - 1U) * 4U];
                  uint32_t u32[(SC_RPC_MAX_MSG - 1U)];
                  uint16_t u16[(SC_RPC_MAX_MSG - 1U) * 2U];
                  uint8_t u8[(SC_RPC_MAX_MSG - 1U) * 4U];
          } DATA;
} sc_rpc_msg_t;

This approach is very verbose to the point of being unreadable I think 
it's much to message structs instead. Compiler struct layout rules are 
not really all that complicated and casting binary data as structs is 
very common in areas such as networking. This approach is also used by 
other firmware interfaces like TI sci and nvidia bpmp.

imx8 currently has manually written message structs, it's unfortunate 
that a bug was found and fixing required a scattering patches in 
multiple subsystems. Perhaps a better solution would be to centralize 
all structs in a single header similar to drivers/firmware/ti_sci.h?

In order to ensrue that there are no issues specific to the compile 
version perhaps a bunch of static_assert statements could be added to 
check that sizeof and offset are as expected?

---------------------------------

As far as I can tell the issue KASAN warns about can be simplified to this:

struct __packed badpack {
     u32     a;
     u16     b;
     u8      c;
};

static_assert(sizeof(struct badpack) == 7);

static void func(void *x)
{
     u32* arr = (u32*)x;
     arr[0] = 0x11111111;
     arr[1] = 0x22222222;
}

static int hello(void)
{
     struct badpack s;
     u8 x = 0x33;

     printk("&s=%px &x=%px\n", &s, &x);
     func(&s);
     // x could be overwritten here, depending on stack layout.
     BUG_ON(x != 0x33);

     return 0;
}

Adding __aligned(4) bumps struct size to 8 and avoids the issue

Added KASAN maintainers to check if this is a valid fix.

--
Regards,
Leonard

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/VI1PR04MB6941383E77EC501E96D2CBB0EEF60%40VI1PR04MB6941.eurprd04.prod.outlook.com.
