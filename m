Return-Path: <kasan-dev+bncBAABBD4T6DZQKGQETN4S4YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id AAB3919355C
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Mar 2020 02:46:56 +0100 (CET)
Received: by mail-ua1-x939.google.com with SMTP id 77sf1718694uaj.8
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Mar 2020 18:46:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585187215; cv=pass;
        d=google.com; s=arc-20160816;
        b=Aw1LrJ1JNvkEHkueUMGnuMveeiai79+KdMx3JKyZDvecLDRUScMJUdlpY2CLeL/7CN
         mgHJ6dc2C5U52aCy4Sk5/7WPpfH8buktyuGlv+rpo9qObhqAGJ4lAFEuOyuGXP6ZaEi0
         E7XZsgo58LIDuCps/N6NO4X5PryFi5MPOWInmwGMZB1FKP1WPr6stmrDfJuUacdyZEmd
         TLRr8LLkMqRAfKlP2yAxzXp9LoWDzhvy6W3dTHM5XZOKHZmk6uUrxfmdFsFRiwvZTZcy
         3sZIHfcLiiVTFi3moX/ToioI8ESrmyIBMbEKo6MRH+PiauZZObhZDgTklegElUeyALxj
         JtEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:message-id:date:to:cc
         :from:subject:references:in-reply-to:mime-version:sender
         :dkim-signature;
        bh=KB2qanR+W7WLUzaXFALdtpl7+J5tPNNVWHQOvuy2ZOw=;
        b=WOxhGouvL8JPMlK5cgwOIqUQLUkDc32q0BH30QPCUjuRmX4pQ3uvET76Qlmo4okiUc
         +k2wPWQrD6CY+lJn53cR7GGQuzhfFwtaw1rn/4X5k9DnAfcBr2ySpro9EKIZXYto8AfL
         4lyluxA0S3oKM5n37abatr7KQRIGFSf5BlSnBKtJP5nUIsYWxDEK44ShepaUzBSWaGYU
         YidxsvlYr6cB4iTBZu9zXIOv/+8mkwnox8twZwn8P8irwGADF34SRTHY40G4v8tbHepJ
         4E9WVXK/A8EZNuUVBHcyJyO8RrANJofFGwlJ0FiHURZsRlkbpqqa9EvV7iovGDDnl6z5
         RO7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=hY1tQ6HY;
       spf=pass (google.com: domain of sboyd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sboyd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:in-reply-to:references:subject:from:cc:to:date
         :message-id:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KB2qanR+W7WLUzaXFALdtpl7+J5tPNNVWHQOvuy2ZOw=;
        b=T9f4bdbQ5UlGFy1HrmBSzTmk3e9G86igNjW5mnscjH42Df7ce5ZjkS3DC02ZChh9q6
         DUsDSAX7qQhWOJFYS3o6z0Zuqo7JFonq/iLkrEcf69A7739lzZLhLE/Es00sr6bGjOJu
         LtoxfMYHlM+p1G1BhYBi3DEPOYWdKlM+qOQZpuKdFH4HH+FkmEuA1CtH0nIXXx5IHwGe
         gcuCaitIw9NaPIiSMPXzIX1cjmg6uoKW4TjEDsFTk7Nw760v2TBnP8LGC7pC1OjA3BMu
         UTTgFe6wHMoPeoFvRqeOaNZPr9XOneKXtHrEkh2rFLYuPXxFejydpILUm6MYEh3tOnr7
         scGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:in-reply-to:references
         :subject:from:cc:to:date:message-id:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KB2qanR+W7WLUzaXFALdtpl7+J5tPNNVWHQOvuy2ZOw=;
        b=NexD1cZPMRczFApropq68Iodum5V67kM/UOUOJXLfb3ZLkzw4Bgk+suxusPM9qpKQs
         JW8xnKjknXpmVmZwZaLrCZJWJlBdCowOg+VVIluuMenfa9TVwAtPPIAKYxOyA3f+i6NM
         q+axP1Drl3AGkd36yhBLEggDcxSCLgwVBtFDyCnyul0M/hfMXa0/UbD088q4AhBtf9y9
         3bFRtjc3sCZdisJDrT3kvragkRm29OKBvHCv9DuSIXCvZSxuku4QeXMufJ3fITX48k85
         +BP73Gp6NNOK99RRBvcAuQ1poSD8pVGavgsLe+ETBUokWVxD0If2NtPuzwKPGe6kOSYa
         xRsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ38/zh1KUTmb59pOumK9LCjaLKQgUdIG0hgSyJvKYY567nPUeky
	6lvAH7girqmrQwc347GVhMY=
X-Google-Smtp-Source: ADFU+vtp3OMh6kuz6aFqR/ZvuzHUrmzTaGIwYMUG3pV2FQdk1f+5Dw51naj1RJ/sB0a26Yp+EiDqAQ==
X-Received: by 2002:a1f:3210:: with SMTP id y16mr4612130vky.89.1585187215217;
        Wed, 25 Mar 2020 18:46:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6950:: with SMTP id c16ls335672uas.0.gmail; Wed, 25 Mar
 2020 18:46:54 -0700 (PDT)
X-Received: by 2002:ab0:718b:: with SMTP id l11mr5095371uao.100.1585187214906;
        Wed, 25 Mar 2020 18:46:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585187214; cv=none;
        d=google.com; s=arc-20160816;
        b=XI6MaZ/ksTJl9Y6yN7TraTW5o6N/Bwiu9tnKAw7wNiJeYUE9TsccQ562nfjg1S9W11
         Pkp66KzqjIHxom70lc1DXFeyvzB36B3Sh9TVVdRmmg2BfjYRxNPpb0m7rRRJ4M2tB9nH
         t3O9tuExei/txMDxdEbjFVFb2utESXs23hXjNjNJm1E2bhtFHlmQlTOXHobsBfDjFuL5
         LkF/M28ZocFR414zEVFslRVwx+/inFtJAqgxYadbolVKZ0Bg5Arh5rpCNMT8HmmyYr63
         DRHngx0yTWHGrTCuhxgMJTuLaf7SUsYv1NZ/o5qXTXMvSdEp9Mt2QUMg/Z8PTEc+0V4K
         /zyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:message-id:date:to:cc:from:subject:references
         :in-reply-to:content-transfer-encoding:mime-version:dkim-signature;
        bh=X1OAy3jmsS78OvrpJ3lAjwHqrT7Rldu6aC169zDmH08=;
        b=Q+YjsK/8dJgCL0G+f4PnJI+9W/+aBNGjcywj+G60DVaATWwaFwXKO9rpLflRx9CxNb
         Vd+yLIsvyI9efJuwiRfMq+JM7RWsCP3vdPBxt36kxQxYsqR9KxhqgyI/shEVbxACy26n
         3KCKFQPbp0foZpl0Te5oMS3f7l6zBAo3me5p2KIWEglPz9Ve6nLFu0ZywL1Pde2fje5E
         bY8v8JwITCDGpmf4yZMyqb4mIHODQvad86f7YLruYbhtjwV+M+6tIRkWsEOeq76Aiaos
         m2U1sHc1CmdYHkrMudLgqtBdw16jFQdVqrht8klNN+VLAkjXDHRWQMGNaKwosEQFIniI
         BIOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=hY1tQ6HY;
       spf=pass (google.com: domain of sboyd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sboyd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s124si58114vka.1.2020.03.25.18.46.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Mar 2020 18:46:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of sboyd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from kernel.org (unknown [104.132.0.74])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A48FD2073E;
	Thu, 26 Mar 2020 01:46:53 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
In-Reply-To: <CACT4Y+Yqrx+GXF9+_oPY+4HXhufN=eoghUcimSzhWsQbLz75wg@mail.gmail.com>
References: <cover.1582216144.git.leonard.crestez@nxp.com> <10e97a04980d933b2cfecb6b124bf9046b6e4f16.1582216144.git.leonard.crestez@nxp.com> <158264951569.54955.16797064769391310232@swboyd.mtv.corp.google.com> <VI1PR04MB70233A098DC4A2A82B114E93EEED0@VI1PR04MB7023.eurprd04.prod.outlook.com> <158276809953.177367.6095692240077023796@swboyd.mtv.corp.google.com> <VI1PR04MB6941383E77EC501E96D2CBB0EEF60@VI1PR04MB6941.eurprd04.prod.outlook.com> <CACT4Y+Yqrx+GXF9+_oPY+4HXhufN=eoghUcimSzhWsQbLz75wg@mail.gmail.com>
Subject: Re: [PATCH v2 1/8] clk: imx: Align imx sc clock msg structs to 4
From: Stephen Boyd <sboyd@kernel.org>
Cc: Shawn Guo <shawnguo@kernel.org>, Aisheng Dong <aisheng.dong@nxp.com>, Fabio Estevam <fabio.estevam@nxp.com>, Michael Turquette <mturquette@baylibre.com>, Stefan Agner <stefan@agner.ch>, Linus Walleij <linus.walleij@linaro.org>, Alessandro Zummo <a.zummo@towertech.it>, Alexandre Belloni <alexandre.belloni@bootlin.com>, Anson Huang <anson.huang@nxp.com>, Abel Vesa <abel.vesa@nxp.com>, Franck Lenormand <franck.lenormand@nxp.com>, dl-linux-imx <linux-imx@nxp.com>, linux-clk@vger.kernel.org <linux-clk@vger.kernel.org>, linux-arm-kernel@lists.infradead.org <linux-arm-kernel@lists.infradead.org>, kasan-dev@googlegroups.com <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>
To: Dmitry Vyukov <dvyukov@google.com>, Leonard Crestez <leonard.crestez@nxp.com>
Date: Wed, 25 Mar 2020 18:46:52 -0700
Message-ID: <158518721283.125146.731278488394587824@swboyd.mtv.corp.google.com>
User-Agent: alot/0.9
X-Original-Sender: sboyd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=hY1tQ6HY;       spf=pass
 (google.com: domain of sboyd@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=sboyd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

Quoting Dmitry Vyukov (2020-03-17 12:54:31)
> > static int hello(void)
> > {
> >      struct badpack s;
> >      u8 x = 0x33;
> >
> >      printk("&s=%px &x=%px\n", &s, &x);
> >      func(&s);
> >      // x could be overwritten here, depending on stack layout.
> >      BUG_ON(x != 0x33);
> >
> >      return 0;
> > }
> >
> > Adding __aligned(4) bumps struct size to 8 and avoids the issue
> >
> > Added KASAN maintainers to check if this is a valid fix.
> 
> Hi Leonard,
> 
> I think it should fix the bug.
> It's not so much about KASAN, more about the validity of the C program.

Ok I'm going to apply this and the next patch to clk-fixes because
nobody besides me seems to be concerned.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/158518721283.125146.731278488394587824%40swboyd.mtv.corp.google.com.
