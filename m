Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBPEJ5KHQMGQECNH2ZDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DA574A715E
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Feb 2022 14:18:52 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id n6-20020a05600c3b8600b00350f4349a19sf1216936wms.1
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Feb 2022 05:18:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643807932; cv=pass;
        d=google.com; s=arc-20160816;
        b=DCdljeE7of5U3rXYUNNcK+gS8NZlR7BDQjlOKqHzkB3sSN87Cf52Gb+pidVaofXux+
         cjvMvCd2XMU6qPzh+O9hAuUyQx8YbuIs8llAj7XTtsWwChnXJ4ULuzCi38bASIbDyHKd
         Ti23Gw5AgEIqylcWlVEA+4SQtyOkkF5sq9uAdov4TVLufzwNNEMts6yVCxNq0DlFQDLb
         fQeurdWFHYrOwdN/MYOgIXOEKGC22sN9BO0/+Mv3odrNFIXrfTx6VOudXbZXmfFuBeKm
         YtvnILmpGE5B7zWKzpA5Q7FksJGd1ro6JwU+bnssuY96UvPMoR+lV/W9oSSN17YH88bh
         mT0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=Sj2cxH6cNX5OY9lhJgmC23V8vZqOPC3feI9l7IwOUpg=;
        b=HbaUTMB0/LFsZY3v5KMGq7d0qB2dERTHoUIXOsaZ8Eu1zIB9fMJT58rsZYlpkIClMy
         3OwJwBbwcrQtITFXo7PNrgcH2pSuftmyRKuRVF5M0D8TBLqFo8bNpoltRR3hYzptMa7j
         N6326NIPGijSnk2oUm+7QgF58sqbBbiSj1TbeKLFlHvucqns626A8GjRVMG8ELE7yhv9
         7rEyvsfSCezQUQVv3eszBSdrcs66ofQSnOMyJIPD/gaHIvMxClDkNW+Wh7ddmoNNpA/6
         0qLGG5uGgPRcDEaVNYMnMAl3Td/Qy2VmAYCOInbIKV4lFaWwaPLVT5/tECjwl9Yp40gI
         uFVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=BMuX1U50;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Sj2cxH6cNX5OY9lhJgmC23V8vZqOPC3feI9l7IwOUpg=;
        b=cbSUcqEwuB7p/XtxuPbn4t0PAC6ExHZXD0W8n80Pnk8TKBJfIqKuDsPFFqYihs8SSM
         D2P8sHaGd1VZ7Gx6Cgxtn4QoCDOCuNcBpxxV1BWypPtTHQD8vejRLLlvvuvDad0XJc15
         kFf8f4dqLMvMdCae5gXXpAb0DEz2+7QcFjxVwQniAx2v3aBtueX/wiSgX1Bi2JFdK0/z
         FX6CFR/UvXLTPHQ2LTCkjwH6eLeElxLsdWWtifUOrspNk5kmKPmmXVtFf9da7oPKemqq
         J+YJcT2I2XrxE2LGTeyniJt+u6qheWbAugGm7PQiNavEEnbuWiJ3IhF9cEPNTmMzI9vh
         vHrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Sj2cxH6cNX5OY9lhJgmC23V8vZqOPC3feI9l7IwOUpg=;
        b=gTX6bXDDUHHZxI35KFgVxfwTuGZDDaBxcY7yoDBgKK05L7RfLz2ztUVjOEVpjzyK4Y
         O8gORlh10FwzcnV4fI3KXq2VbuaqcX6wGgVzRLKIDyEGLSTwt5G5/cvaVQ5r37JDJ5yp
         /HO2RS7I90xiUXN2siPePbyMM/7dg085QfIqmd0DOYrg77TMKrNDYrecniC/zhyolGPb
         K1wWf2hb/XDdESb7gjXc/KMYXlIxu1ZZi+2Oia1HJjNKb2IXXZowJTR6z9gLatNz5L6b
         OgHA6eclT3gyCEIbeXxVOzagOnaIwxAk8f503hsmpdia6Uhqh4lQzQU4Z+TENcpOHr3X
         jUYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326U/TeevJYvaGIXTmPnDDA8r7pAlkozRQCyKsxlsOLzy9mEgPG
	uaZKmYPC26cGscCQMBmBIcg=
X-Google-Smtp-Source: ABdhPJx9L7BHr9lJS2zxTNurpQyH5lrnam/M/CLs1zJoAK2S9ZrODJ5hEx/Zyb3m2PON+sf2jqTV5Q==
X-Received: by 2002:a05:6000:2c1:: with SMTP id o1mr2094322wry.258.1643807932181;
        Wed, 02 Feb 2022 05:18:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:500e:: with SMTP id n14ls2949130wmr.0.canary-gmail;
 Wed, 02 Feb 2022 05:18:51 -0800 (PST)
X-Received: by 2002:a05:600c:1443:: with SMTP id h3mr6159613wmi.37.1643807931297;
        Wed, 02 Feb 2022 05:18:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643807931; cv=none;
        d=google.com; s=arc-20160816;
        b=Clqeo4FUcdo44Lm/9xhlRu0siN1wGORRiLXyqAiLn4IHtXndsGxtr6q+kXGczd95hN
         3pHFN3Y4F8S4aGmv3DM3ip7YsoMUnEJbeX7U+PrRu7Mz+y5QbdInDiSmZKOgjPtGzb5p
         kPtrI0ofcUxc4RCMJxwXmHdXxrHbKpS6walXkAdL9Bhdh7A4VP5Ky11DncINJj3+atA0
         QSNOhpwkSAZpZ0j8w6V8XHC2yzozRSU1LTJupkUDp2hlc3KhLW1HupqkbmJ2LPiURRlE
         MukxM/sK63Seq6o9SOMyMFIFjiZCjcqk3UnUw+IKovPLGywgPvPIDKShrl+s0229MF13
         9zCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=snnqrCI4qkz8Hro6Gqsu3aM3hUykyWW5o1MMGnMsu4c=;
        b=N/JCm6knzNOaYV1dmf+RXk5VB4/USsb3+EvpiYZLClW7ap/dBj4/Mr+rmP11+NHjh8
         SaNdF9Swr80u5hFI4BHi316KzkInYSAKjiCZJ4B4UYhj71O0gStypW1WTIxll8lKclle
         +d9lBCRc3M3RkvxWpqPdaDar/kcv3gBDzP1SVOX9/9f4kJymfwRbqzUsDyqFh0c0Xciq
         QrxcaYd0O0juw2T+q19oG3ILCKxovBiIsH+di7bUSflr4VaXfc7Cmq8RXqeQzo8fUWo5
         gpf48jcW0Unqv6zA5I7MKsO7HskCttP1b8tyoSELrGN6GhSTCyGaO5pe3WfpyqNuxMRH
         K3jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=BMuX1U50;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id h81si244696wmh.2.2022.02.02.05.18.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 02 Feb 2022 05:18:51 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-ej1-f70.google.com (mail-ej1-f70.google.com [209.85.218.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 461163F339
	for <kasan-dev@googlegroups.com>; Wed,  2 Feb 2022 13:18:49 +0000 (UTC)
Received: by mail-ej1-f70.google.com with SMTP id gb4-20020a170907960400b0069d1ebc4538so8137915ejc.2
        for <kasan-dev@googlegroups.com>; Wed, 02 Feb 2022 05:18:49 -0800 (PST)
X-Received: by 2002:aa7:cd0b:: with SMTP id b11mr29885619edw.412.1643807928850;
        Wed, 02 Feb 2022 05:18:48 -0800 (PST)
X-Received: by 2002:aa7:cd0b:: with SMTP id b11mr29885596edw.412.1643807928661;
 Wed, 02 Feb 2022 05:18:48 -0800 (PST)
MIME-Version: 1.0
References: <00000000000038779505d5d8b372@google.com> <CANp29Y7WjwXwgxPrNq0XXjXPu+wGFqTreh9gry=O6aE7+cKpLQ@mail.gmail.com>
In-Reply-To: <CANp29Y7WjwXwgxPrNq0XXjXPu+wGFqTreh9gry=O6aE7+cKpLQ@mail.gmail.com>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Wed, 2 Feb 2022 14:18:36 +0100
Message-ID: <CA+zEjCvu76yW7zfM+qJUe+t5y23oPdzR4KDV1mOdqH8bB4GmTw@mail.gmail.com>
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
To: Aleksandr Nogikh <nogikh@google.com>
Cc: linux-riscv@lists.infradead.org, kasan-dev <kasan-dev@googlegroups.com>, 
	palmer@dabbelt.com, 
	syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=BMuX1U50;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

Hi Aleksandr,

On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
>
> Hello,
>
> syzbot has already not been able to fuzz its RISC-V instance for 97

That's a longtime, I'll take a look more regularly.

> days now because the compiled kernel cannot boot. I bisected the issue
> to the following commit:
>
> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> Date:   Fri Oct 29 06:59:27 2021 +0200
>
>     riscv: Fix asan-stack clang build
>
> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
> enabled. In the previous message syzbot mentions
> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
> For convenience, I also duplicate the .config file from the bot's
> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
>
> Can someone with KASAN and RISC-V expertise please take a look?

I'll take a look at that today.

Thanks for reporting the issue,

Alex

>
> --
> Best Regards,
> Aleksandr
>
>
> On Tue, Jan 18, 2022 at 11:26 AM syzbot
> <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com> wrote:
> >
> > Hello,
> >
> > syzbot found the following issue on:
> >
> > HEAD commit:    f6f7fbb89bf8 riscv: dts: sifive unmatched: Link the tmp451..
> > git tree:       git://git.kernel.org/pub/scm/linux/kernel/git/riscv/linux.git fixes
> > console output: https://syzkaller.appspot.com/x/log.txt?x=1095f85bb00000
> > kernel config:  https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> > dashboard link: https://syzkaller.appspot.com/bug?extid=330a558d94b58f7601be
> > compiler:       riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2
> > userspace arch: riscv64
> >
> > IMPORTANT: if you fix the issue, please add the following tag to the commit:
> > Reported-by: syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com
> >
> >
> >
> > ---
> > This report is generated by a bot. It may contain errors.
> > See https://goo.gl/tpsmEJ for more information about syzbot.
> > syzbot engineers can be reached at syzkaller@googlegroups.com.
> >
> > syzbot will keep track of this issue. See:
> > https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
> >
> > --
> > You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/00000000000038779505d5d8b372%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCvu76yW7zfM%2BqJUe%2Bt5y23oPdzR4KDV1mOdqH8bB4GmTw%40mail.gmail.com.
