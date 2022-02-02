Return-Path: <kasan-dev+bncBCXKTJ63SAARBG6M5GHQMGQENWHU3HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id BA0804A6F97
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Feb 2022 12:08:12 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id c7-20020a25a2c7000000b00613e4dbaf97sf38790339ybn.13
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Feb 2022 03:08:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643800091; cv=pass;
        d=google.com; s=arc-20160816;
        b=KmP0mD0O33ZKvQ6kJncFERhO+73I6Yl3K0IK1LONidPm/iUgkiLh1xZOCwf/2nQXvN
         5JOLLRo0Z0D2GUULIr04NBvqlrq322UCyWLoCeY6H6UwwXD51WINi8I2qBbgI5OCwCKH
         0uIvUnbVLospJ2YlFdkkiVf87MHPMwaj9w4er/Uk5D0w/XHHbCJoAKR3chSqv6jA0Yql
         Vk3Jr3RfnIlgtZVgYtoizhXdJDTgbQhLNHfZOe1u5Sm7XY51zxqGpjnNAo70eGxAMgeV
         M2ISGh6SFvNnfiRP2jlK7pcMLEfZQKEIE5nnezMvwwIFd9W1HKz8fZPGl5gS52Wa21Xo
         Ffyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=395J0569LnaRWA472v3puXPnrDtJY+kjEZaMTdKvSBQ=;
        b=ICSrk0XTZF18xRfWrEA9wzrIysx6al22LSQOqSEhbzsNLzWrL1DcGUtn0LCrTbrF0P
         kicNTBtGF5vtavV7l/72rPK4HBxZMLBqHpgjWQjfj1gNVxGAsuHM6A4VzZh3/7Qr+bsx
         6LKbkaPwlE6xYIblXIAyxtJU6xmB8makOIGRr+NlJ7OboAMp55LUhW6fmZhZjmEGbc36
         Pyixz4x28CbSMoU8Bo7LHp3PZgJJ8HYwEFx9BWU1GbWV9cZttr+7h/6WG0qK6V4Y/4hM
         1NgAAZLJu1xMZ9q33jtaT7nSmeiGS75OY/wDXoEWOJ9pS5RtPn9zLN9d4kN98sF3A4Ao
         Klsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hkqcAskl;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=395J0569LnaRWA472v3puXPnrDtJY+kjEZaMTdKvSBQ=;
        b=qc5btSVzgQhnUNwTrwklMgsWeeZyPneqW8m36lfUwFtEYnXkJFaq1sNpoq5O9Evk5T
         Ye+RJ4Zdu+guCgOagrGmBmGw+T5JW/gBJNg9+Xalr+IviHrmdSrN9lKAcORYUa0okxA1
         VUfzm0EGXovh1ZmLExpxkyc5FfSEHAANU4hQZTjSY+k+DX9maiA5Y9zPTQ6G2nTXZ+2h
         UKDSDY9QT+qyiTGhzM/l8TSgDPMHISy7P72+HyDMruqWRYI/JOjZ+Z875t/uuQd/tqnN
         SNaaWCphJL9hBhNcUU4ibyqr6B/mUyHGwxLW507sZICimReYLY7mEOZquLU0nsIuuc/t
         nwZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=395J0569LnaRWA472v3puXPnrDtJY+kjEZaMTdKvSBQ=;
        b=3RSIZ6QU5EetpNLXH0wqQ8y13XeHD4t+odQ1neKc9UupCvE4Sz3M0PBjtIrBbT2TDK
         gAK/yEKLO/nv8rwa3qmDqGoO7GOoD4HBeLyoVBdnuS5USMsIvFhAsJcq1mbEIYcUQ1hk
         HOM9B0T9RRzWw/Ce3Yo8hVX/ZTtp77kyUV3tMhWFJSbKsBy5N0AURhmgnnUmiOyaZFS3
         1bIlkWr9qonzJOwlUI2nsymRUxTZ2td7CDmBF9eWwU98EpeANWgk6PeIaflT6kmxwk8j
         FRqChvCHY3gMyj+FwtZNevVcv02tPEc4V9gJsZOvxXY12Ifh0Cg+AzZXmnI0dRRuWDzI
         D+0A==
X-Gm-Message-State: AOAM531gvOQ5B3boi75GxmSEg9RVGstmikI9StpiJFcHScSe/+27OTxF
	SBv5emYPvXgIngxFfppx+lI=
X-Google-Smtp-Source: ABdhPJxVgsFO3rKY9OzRJNNROixvQzJshHDT8ewdwIw7yfkAHgBZQ1DauiCoNlWmGchIdGypbKmAQw==
X-Received: by 2002:a25:4dd4:: with SMTP id a203mr45377370ybb.340.1643800091543;
        Wed, 02 Feb 2022 03:08:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:684c:: with SMTP id d73ls15296839ybc.10.gmail; Wed, 02
 Feb 2022 03:08:11 -0800 (PST)
X-Received: by 2002:a25:80d3:: with SMTP id c19mr41585355ybm.741.1643800091135;
        Wed, 02 Feb 2022 03:08:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643800091; cv=none;
        d=google.com; s=arc-20160816;
        b=oB2V0D0h/wyJbuQXVN3EM39XS1A7Q/J+Fs7YRR4pLhi6yZ6V24aMHskYy4+xbWXk5H
         vJDcywU9wVep7xHlVNrWPKRWS1sDfpJEQl2zHjWEjXW6Zbx6T50zX7lfMvEbNmuOcs9s
         vtZNndLmVZ7mE97HcnkF63KPV+ND+pbzNdZNQ57QgtHS4038slginVDm0ut5uXB2cDeH
         xDrQal6peRmcQb6gofkUKOjV3kNhT1KdXPVS220fAUM9/hRodxX2+61QN7nC6A/tqSNC
         tjPZGAfyXo5qOuat0V14d/lY9UmjBW82e5VD9Oufft5D3+KczNn+KoBaNh1HUvOOqrcB
         o6TQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KvwP2pq0A69XLEtJRHQeT2K6fCrFL3jZAy9726cRZ/o=;
        b=px5zeBmtpEViCtoyGYqFOO8EqyKCMDnj+rnMyZHr1J9jl4b8QDk+v9LAcFnDc0ythz
         9POeWMgg/mst9amAXPvnXDmy0DvIKmQlgjXvFNLixFdp5q7NsSJYgTxEzig8Qmbw7DlX
         9UeUIh9cyRzJWOOvcHyve+j516zuEBfNw+ciqOTKviIe1pjCUWLILDEE2ZefAmoXQpF5
         vZ6fbpCKAQiozv3/n1dFXxXYkSAuASVoOq38CC1ieEiLHBYOuCCvLgGPVEQnkUpI+f+t
         TmS5zcF5QsmSMOhwDAtOMznwGr0jYrUQhJ1hVH3INXVcszjVS6gNp6ZqTddbsPbvEPdG
         EiXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hkqcAskl;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x133.google.com (mail-il1-x133.google.com. [2607:f8b0:4864:20::133])
        by gmr-mx.google.com with ESMTPS id f5si1239907ybf.2.2022.02.02.03.08.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Feb 2022 03:08:11 -0800 (PST)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::133 as permitted sender) client-ip=2607:f8b0:4864:20::133;
Received: by mail-il1-x133.google.com with SMTP id q11so8530798ild.11
        for <kasan-dev@googlegroups.com>; Wed, 02 Feb 2022 03:08:11 -0800 (PST)
X-Received: by 2002:a05:6e02:1a4f:: with SMTP id u15mr6037825ilv.245.1643800090714;
 Wed, 02 Feb 2022 03:08:10 -0800 (PST)
MIME-Version: 1.0
References: <00000000000038779505d5d8b372@google.com>
In-Reply-To: <00000000000038779505d5d8b372@google.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 2 Feb 2022 12:07:59 +0100
Message-ID: <CANp29Y7WjwXwgxPrNq0XXjXPu+wGFqTreh9gry=O6aE7+cKpLQ@mail.gmail.com>
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
To: linux-riscv@lists.infradead.org, kasan-dev <kasan-dev@googlegroups.com>, 
	palmer@dabbelt.com, alexandre.ghiti@canonical.com
Cc: syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hkqcAskl;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::133 as
 permitted sender) smtp.mailfrom=nogikh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

Hello,

syzbot has already not been able to fuzz its RISC-V instance for 97
days now because the compiled kernel cannot boot. I bisected the issue
to the following commit:

commit 54c5639d8f507ebefa814f574cb6f763033a72a5
Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date:   Fri Oct 29 06:59:27 2021 +0200

    riscv: Fix asan-stack clang build

Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
enabled. In the previous message syzbot mentions
"riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
Binutils for Debian) 2.35.2", but the issue also reproduces finely on
a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
For convenience, I also duplicate the .config file from the bot's
message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d

Can someone with KASAN and RISC-V expertise please take a look?

--
Best Regards,
Aleksandr


On Tue, Jan 18, 2022 at 11:26 AM syzbot
<syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com> wrote:
>
> Hello,
>
> syzbot found the following issue on:
>
> HEAD commit:    f6f7fbb89bf8 riscv: dts: sifive unmatched: Link the tmp451..
> git tree:       git://git.kernel.org/pub/scm/linux/kernel/git/riscv/linux.git fixes
> console output: https://syzkaller.appspot.com/x/log.txt?x=1095f85bb00000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> dashboard link: https://syzkaller.appspot.com/bug?extid=330a558d94b58f7601be
> compiler:       riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2
> userspace arch: riscv64
>
> IMPORTANT: if you fix the issue, please add the following tag to the commit:
> Reported-by: syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com
>
>
>
> ---
> This report is generated by a bot. It may contain errors.
> See https://goo.gl/tpsmEJ for more information about syzbot.
> syzbot engineers can be reached at syzkaller@googlegroups.com.
>
> syzbot will keep track of this issue. See:
> https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
>
> --
> You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/00000000000038779505d5d8b372%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANp29Y7WjwXwgxPrNq0XXjXPu%2BwGFqTreh9gry%3DO6aE7%2BcKpLQ%40mail.gmail.com.
