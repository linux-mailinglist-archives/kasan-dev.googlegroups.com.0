Return-Path: <kasan-dev+bncBC447XVYUEMRBPHUWGIAMGQEAMGPPFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id C08FD4B7F2D
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 05:14:52 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id b17-20020a05651c0b1100b00244b873c6easf462492ljr.4
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Feb 2022 20:14:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644984892; cv=pass;
        d=google.com; s=arc-20160816;
        b=X3k0IlEEpUb+4C0q/Y+tnxrS0vxNRuJJ9ig9QdS5YKaFLTQmdJGDckMdf+uHBTNs2o
         pgmwGgPr+p4eGVaPyLsTnGS5wNTfc/bDjipPetPl0SGmrNDgO8FfIgvVRpvfLjoH/d37
         60tQQR0OyeTYYY1BEHZuqSyDVD9W8RjbYffmqm+e30OV/XoLYwXcl869lo4ueF41aZQG
         PojTmsfgQamEzZZkKHe4chGwnXwgaijPSlmtizz0DMb4s7WvgepCJpI8efX63JLheHCS
         NQ5CPruC9/wcErjrHm/9Pk+wCZU3uPfJfHzV2wIr8lfMXZ/Z77LWrChH2XJ1+c6f6xxC
         bwEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=YdV54mHHX7fYCtE7rAGwaSFuyN0vGTlZ6a5cTe5lA9A=;
        b=XQc7k14bc9Lda4ctXv5XMrZknhqwwUnOQnATr/myzs+ejgR+i+m3oriKQ2Hs4g/4mJ
         djNRMgvvnFZ57z1w+4iU7aHB1dYLl2VUd6zE/kuEn6hC35QiT43q0f6+Bo2zaXhTK+8J
         y7qgS745lSDlZEdiTsd5E+XcOsN3FlhNWNTp3WWRm05A3CMmonWUrg0YYt4+Ey7jd0lO
         5JToCLvK8ydowhyXU+zlE7fvAFcVkLLOgqCUwFwG1OlNDkGGCSViOomwiMy+hue9mmrP
         jIkWkR8ifRCRCJH5ST29EdIH9msP2acck33mnpYaSiwfDKePGtacwTh8gyE7JAL20wmw
         leIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YdV54mHHX7fYCtE7rAGwaSFuyN0vGTlZ6a5cTe5lA9A=;
        b=Q0AwFIWVvgvvOi9JA3oFcvIj8evwesWPbBqaQxplwOWmh8fkqq+C3qtrpFXIPnHfVI
         g4GFlRHaESxbEkbkuchyXSMbmzrr+FEOMmBrLJzQSOkXl9GCnIovqXJMqtIyP9td7iOG
         LJbYKXySdd96Z/D3KPzkFs3RbK6ZCMzFMVohl9Ra1QoKh1DDAp6UlctiQ7KhFMYDVREG
         PkK3Y8ooda8qjosj2PideWnwrcfc0FEPMODyAP4sF2PYg7Jfq33yTSIaPZCi3lA8y7eq
         DYFfOxsyZzaWhvXNKdvxi5zLHWpmGsTx1BUkf/kiHh8J0cI8d2LiCG8R0WR+M6eGnIdq
         XI/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YdV54mHHX7fYCtE7rAGwaSFuyN0vGTlZ6a5cTe5lA9A=;
        b=1duW39O7Eg2kOyVoSJNEx9a5JV7+TGeBgPIXv+iqV70sj0Nl90iGy65/4xG2X0Xz7O
         cCuBLcuJJssespDfSrHIuqEsDE7Nzh7KbbFYRQF7SfQ+gAm/KzW05wPoMYQane6K4TZh
         7rtOgCNZyMl8cnTCoXLAEgJn1QbVxuvEXJkKSlGcPhp2fb81lQPUy6nI9AQBvwQ5RB/Z
         c1OGQcy9o4CzDVDRXll6bFLCjNuSvPHXOpHmrTKDhK+78nAfyzh6FwyQMKvLJw+TADgn
         uH+pfRcnvrm0WHhlf9Ct+Cd/pUc3Rt2k/gnoKVfx/6MQS+znzmZnbZjKdPu2XArsXZew
         6AGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ZQsOxUNKjrYv/Gw/R0L7ZTE+s12YqEyrZ86zqmNUHkHkZs98E
	epf8CBE3qtLoD8c/IAMrD80=
X-Google-Smtp-Source: ABdhPJxKqkmmbkcgLup24dYPMFw0+XRjCuL8023BRX9OaT2TGAZ8328QqgQ/oNkITySWlOhDfPjMjg==
X-Received: by 2002:a2e:b8d0:0:b0:241:875:3c60 with SMTP id s16-20020a2eb8d0000000b0024108753c60mr677081ljp.45.1644984892201;
        Tue, 15 Feb 2022 20:14:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:b25:: with SMTP id b37ls967771ljr.8.gmail; Tue, 15
 Feb 2022 20:14:51 -0800 (PST)
X-Received: by 2002:a2e:bc11:0:b0:23a:b557:c092 with SMTP id b17-20020a2ebc11000000b0023ab557c092mr723317ljf.24.1644984891181;
        Tue, 15 Feb 2022 20:14:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644984891; cv=none;
        d=google.com; s=arc-20160816;
        b=TNUvG3D0YjV5iobn9Kd4NyTcWENIpAekNj+IoDW+QHWrxDANj1Z9xQkmcI6Vq4mR3X
         MfjUaOgy2Uk6xQhJG8Z3qA2CyaUSp2N2G6cf9f19FWhjWhC6DAe3lOzfRgNO4CiUEflv
         HEP6POFJ/Q7YqqM5Up9sgWa6tfwsi4xrXV1dU8CRkBQiQyKoPDSYDFUg/baUuA9+bwJS
         m1NvVYstPGCXNxwh8WvT7cE4nSfK7v4N4hW4qbI0nZi+uZNmdpjgUKWQsBti7HKvmgW6
         d9ZisdjWq25j3bOZf9yMcKw6Gf6BkHCqt1hJ3f4q9k2iBXN/JyQPNcrTgKAswg4yFf4e
         wjrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=PfnnfczvLput4xLIeGD1xmz0Xq5uYuS0DeG0fP8K3Mw=;
        b=bgoshC1N2mG0MjApoSc1oqtpwlWrHT9ylAJC+OP2eLOVYnldcz5tkWIpTsV8US1pRO
         xy90V9RAAUs14Ym3sN1pG22SKJPR2Il4XMp6NiyiN8rNssSI9CJlCu11RG48g9Lgg6pN
         HJubh75cbSnsDH5WGgTzjelmPD/8JeuB1tMHNtWgH5AapOWJPfLuk664lgz1ik7Et2zz
         dFhx7JCZRsI02RG2AQGp73y/Dbm4xk8OisyKPRYgvDtDlNhczbyiUXnsJxcWOcTBf8m2
         B89aWR5b4wIL/WCqNejqSB6HP5yHlt96tZRV3rjwfA811uyQbBHB6j3Wm8tOqepqeRQL
         cPmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay1-d.mail.gandi.net (relay1-d.mail.gandi.net. [217.70.183.193])
        by gmr-mx.google.com with ESMTPS id c24si261922lfc.0.2022.02.15.20.14.50
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 15 Feb 2022 20:14:51 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.193;
Received: (Authenticated sender: alex@ghiti.fr)
	by mail.gandi.net (Postfix) with ESMTPSA id B6207240002;
	Wed, 16 Feb 2022 04:14:48 +0000 (UTC)
Message-ID: <a0769218-c84a-a1d3-71e7-aefd40bf54fe@ghiti.fr>
Date: Wed, 16 Feb 2022 05:14:48 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.5.0
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
Content-Language: en-US
To: Dmitry Vyukov <dvyukov@google.com>,
 Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Aleksandr Nogikh <nogikh@google.com>, linux-riscv@lists.infradead.org,
 kasan-dev <kasan-dev@googlegroups.com>, palmer@dabbelt.com,
 syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>,
 LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
References: <00000000000038779505d5d8b372@google.com>
 <CANp29Y7WjwXwgxPrNq0XXjXPu+wGFqTreh9gry=O6aE7+cKpLQ@mail.gmail.com>
 <CA+zEjCvu76yW7zfM+qJUe+t5y23oPdzR4KDV1mOdqH8bB4GmTw@mail.gmail.com>
 <CACT4Y+arufrRgwmN66wUU+_FGxMy-sTkjMQnRN8U2H2tQuhB7A@mail.gmail.com>
From: Alexandre Ghiti <alex@ghiti.fr>
In-Reply-To: <CACT4Y+arufrRgwmN66wUU+_FGxMy-sTkjMQnRN8U2H2tQuhB7A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.193 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Hi Dmitry,

On 2/15/22 18:12, Dmitry Vyukov wrote:
> On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
> <alexandre.ghiti@canonical.com> wrote:
>> Hi Aleksandr,
>>
>> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
>>> Hello,
>>>
>>> syzbot has already not been able to fuzz its RISC-V instance for 97
>> That's a longtime, I'll take a look more regularly.
>>
>>> days now because the compiled kernel cannot boot. I bisected the issue
>>> to the following commit:
>>>
>>> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
>>> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
>>> Date:   Fri Oct 29 06:59:27 2021 +0200
>>>
>>>      riscv: Fix asan-stack clang build
>>>
>>> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
>>> enabled. In the previous message syzbot mentions
>>> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
>>> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
>>> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
>>> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
>>> For convenience, I also duplicate the .config file from the bot's
>>> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
>>>
>>> Can someone with KASAN and RISC-V expertise please take a look?
>> I'll take a look at that today.
>>
>> Thanks for reporting the issue,
>

I took a quick look, not enough to fix it but I know the issue comes 
from the inline instrumentation, I have no problem with the outline 
instrumentation. I need to find some cycles to work on this, my goal is 
to fix this for 5.17.

Sorry about the delay,

Alex


>
>
>>> --
>>> Best Regards,
>>> Aleksandr
>>>
>>>
>>> On Tue, Jan 18, 2022 at 11:26 AM syzbot
>>> <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com> wrote:
>>>> Hello,
>>>>
>>>> syzbot found the following issue on:
>>>>
>>>> HEAD commit:    f6f7fbb89bf8 riscv: dts: sifive unmatched: Link the tmp451..
>>>> git tree:       git://git.kernel.org/pub/scm/linux/kernel/git/riscv/linux.git fixes
>>>> console output: https://syzkaller.appspot.com/x/log.txt?x=1095f85bb00000
>>>> kernel config:  https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
>>>> dashboard link: https://syzkaller.appspot.com/bug?extid=330a558d94b58f7601be
>>>> compiler:       riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2
>>>> userspace arch: riscv64
>>>>
>>>> IMPORTANT: if you fix the issue, please add the following tag to the commit:
>>>> Reported-by: syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a0769218-c84a-a1d3-71e7-aefd40bf54fe%40ghiti.fr.
