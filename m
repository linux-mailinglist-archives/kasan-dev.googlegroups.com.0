Return-Path: <kasan-dev+bncBCMIZB7QWENRBJV6V6IAMGQE3IZ5WHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F1384B73FE
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Feb 2022 18:13:12 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id n30-20020a4a611e000000b002e519f04f8csf12953578ooc.7
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Feb 2022 09:13:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644945191; cv=pass;
        d=google.com; s=arc-20160816;
        b=xJeLYR5D6oUguTksLlc1Rg8G0Fdav+2FOFJL8jvVZqPGah1U6fhxLU1DV/WZrS9u08
         JdOH5EILk5JuIA+7509hHN5Qq0Y2Prk+4NRvIRcD8YFuNMbdrF1vpNoARy77Qtl7hfq3
         fBQiw4/Ji3h7c+ZyBmu0Mo9Dqunq6MyhQwMc+77JOYI9YhLkUJsEr6+bLiLSfGvOZ9uX
         /8lX2Q/Bu5r7FP8JKPebB9ZBL6uCk0OTR/yUI/kx7u921Ed0MgbaVplnUNmrRJFjSqIq
         S1Z/s0zcfqPdw+2HGtlHqiaURmx2529wZ8CT3Q/EMq0FCuYNRgylJmsQ9pNvTG0uCHp1
         KiYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Hc/wpM7bl+U6Eodvg5y6CAF9VeF49FnMat6zCGuD3Mc=;
        b=B5oba1AFoV449hrp3w+HFAuC4wKATiyEjtW6K8FbyKTIaAs5LG8nE6t3dPdelnAS0d
         m82K5Eiv8Bfh/IL7/z7sJkTvhKZHhPxCsJGS3+QB+U4EpCmfqOZZ4SN3yMQV1w1hSJHW
         G0z/F6zYaWrakOGY6dm9Z2UR5apb9jiSK+qEld8KmvmaXQRpXp+QwmaRY2VGcnwcrUPJ
         FE/2BP6BwGP9kaBiky/Ql1QJimvtDag8CCkTEcEnv7rMQty3THWpCpVRsVH4/0Rb6VUH
         d2xIBklGSC4eNs/deBu0B3J5dBKc546j6f4GiU0euZ5QMNylhxtds0dvTPYA9jbuKg5d
         cqQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Tl08YyyC;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hc/wpM7bl+U6Eodvg5y6CAF9VeF49FnMat6zCGuD3Mc=;
        b=Ojn7WRWriykYswPRP6+EB9m4/u3lxz7dDUrgZWm7uP3oQsLzdcHKfl+nG6Ee4vT7aY
         q2RzhdWz/Qg80QFqTvVpBgd9U/ZtvJvXc4Vev5Ar0C6tcuyt8I9+U7oSFg6lXTV2KQhl
         Xt3Eryg05IuDaz/otr3nPsEw9V/qbWkzqb7DJZ+gQ3h10HtWsoxVll+ynYipg2ry3IGm
         Zxzbe6rQDg1dbM38RTkk/ocgl7pT9ssQPX4mLNJu+ykqn0EqU2i2wSWIw1s/xBHQU3it
         9qPbDnXSvSSJJvmQkMd5xIoZUmhzC7BxcuCWh5HFFgsS34ytqu53quIaXcE/C+gjg7Hi
         sv2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hc/wpM7bl+U6Eodvg5y6CAF9VeF49FnMat6zCGuD3Mc=;
        b=zaoFtwksogMJlXZLgD1UtrTPCE4+UM5eabKI3Zs6ffeS3K/TBh9BPvMbzkdeqVz3Zk
         dCDbj8L2bwH6armn75NZ2/I3tuaL5zVtM4149KsXn6a9TbQ5arnH54NoE15GrZGilW84
         bmn0pPw+t06zII9uJUfawWiVGQhzCkil2dGGZHzYuxflf7FkZFsjU2G4MovZD2qk52oV
         VnuA1TTT5B5LA51ILeo8eMBeQy2QeIyhEtxpIihZ5HH7AdtB9LjRRnzHkObb1D0r39Ho
         FlI2OOb8EQsdVBTIc1uRBTVk1A6udDYFJWZ//x7EmfjuRKMIvqr3hjRwo7CwWoZO0c5O
         sdNA==
X-Gm-Message-State: AOAM531VnMeB0OD6MwXeH+5shpVbisckU9gKWh+6wzXoJlN3t/oh6OIx
	i0TGiSQo91vM02bgMVP/nZI=
X-Google-Smtp-Source: ABdhPJykIwXnJb+a+bzXax+SDLGecBWN5Q3X23+ycUjcytDj19QqlSRnrq9CA7jGQ/7Tp9MwyW9M7g==
X-Received: by 2002:a05:6830:1d72:: with SMTP id l18mr1669291oti.135.1644945191031;
        Tue, 15 Feb 2022 09:13:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:a8:: with SMTP id u40ls893423oaa.6.gmail; Tue, 15
 Feb 2022 09:13:10 -0800 (PST)
X-Received: by 2002:a05:6870:514c:: with SMTP id z12mr19194oak.207.1644945190583;
        Tue, 15 Feb 2022 09:13:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644945190; cv=none;
        d=google.com; s=arc-20160816;
        b=V9mq2h8XabmaNVgHqdZEZw+hX8tJWP+C/j5ygnnC0VQn8GrzCoYfjSIVli53CK3NM8
         vIimYVQw7xH23aR/IweOmlrkPTzpLYP/RBxg4c4YqxlsWBo+O/jHMgRlH04nIN+KdgVP
         LW4AoVc0j0Li2iuVhy8+J6DzAb3QC8nOzUWyDWudFQydTH7u+cthAoyTNHQO1YT3omYT
         BByD8lTklBsg7+fdKdnDtCZnCowg8KMByTP0jP093wHGyINf7GAVtXp7QOQNDSqk8X/n
         7cPGHMiaopg8A2eUQiS8uhrhFCRop/zgBIxOTSByhADZTZrNBjDK39cQpoJXsEhkBvbu
         FKWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dkNaB6kzC0t6gTi2pQx30aeojCMITTvkle2ZzaYqdBM=;
        b=imiXU+UHx5mwu2neJv3DIAHWc4VYSLInfLUPwiJV/ovnWDskCSWyu4UcAGW2jC/oGj
         38xNzOty7nYOSMbrrYDi4tt9aw6qKYiBiM4hvBsCWc4APPzybKj///Fa7Lw7hrbCmkOT
         Y0toCD0wJwZwbgLabdHqjK0XG8pLZnG2wpDx+7b8zmmUMo4dA4HXUE1KYS24fjSEAyxT
         lfi2C/ph2PFrMBtnFg8TsrRtpcL0jOsmojVson7mu+VnlerQX9mDeMZ7uocxQ4lRZy+N
         QGpxwEUgzyWp6IFyY3DhCFPVj3UER5xyfaWeVAC7OKAa4K8B0XNjxx3Nc1t/I2inDsmq
         TZJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Tl08YyyC;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id t25si3220973oao.1.2022.02.15.09.13.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Feb 2022 09:13:10 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id o23so1992194oie.10
        for <kasan-dev@googlegroups.com>; Tue, 15 Feb 2022 09:13:10 -0800 (PST)
X-Received: by 2002:a05:6808:3021:b0:2d4:40f3:6b30 with SMTP id
 ay33-20020a056808302100b002d440f36b30mr605011oib.31.1644945190003; Tue, 15
 Feb 2022 09:13:10 -0800 (PST)
MIME-Version: 1.0
References: <00000000000038779505d5d8b372@google.com> <CANp29Y7WjwXwgxPrNq0XXjXPu+wGFqTreh9gry=O6aE7+cKpLQ@mail.gmail.com>
 <CA+zEjCvu76yW7zfM+qJUe+t5y23oPdzR4KDV1mOdqH8bB4GmTw@mail.gmail.com>
In-Reply-To: <CA+zEjCvu76yW7zfM+qJUe+t5y23oPdzR4KDV1mOdqH8bB4GmTw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 15 Feb 2022 18:12:58 +0100
Message-ID: <CACT4Y+arufrRgwmN66wUU+_FGxMy-sTkjMQnRN8U2H2tQuhB7A@mail.gmail.com>
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Aleksandr Nogikh <nogikh@google.com>, linux-riscv@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, palmer@dabbelt.com, 
	syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Tl08YyyC;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
<alexandre.ghiti@canonical.com> wrote:
>
> Hi Aleksandr,
>
> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> >
> > Hello,
> >
> > syzbot has already not been able to fuzz its RISC-V instance for 97
>
> That's a longtime, I'll take a look more regularly.
>
> > days now because the compiled kernel cannot boot. I bisected the issue
> > to the following commit:
> >
> > commit 54c5639d8f507ebefa814f574cb6f763033a72a5
> > Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > Date:   Fri Oct 29 06:59:27 2021 +0200
> >
> >     riscv: Fix asan-stack clang build
> >
> > Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
> > enabled. In the previous message syzbot mentions
> > "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
> > Binutils for Debian) 2.35.2", but the issue also reproduces finely on
> > a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
> > 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
> > For convenience, I also duplicate the .config file from the bot's
> > message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> >
> > Can someone with KASAN and RISC-V expertise please take a look?
>
> I'll take a look at that today.
>
> Thanks for reporting the issue,

Hi Alex,

Do you have any updates on this? This is still blocking syzbot:
https://syzkaller.appspot.com/bug?extid=330a558d94b58f7601be

Do you use KASAN with clang or gcc? We can't boot riscv kernel with neither.


> > --
> > Best Regards,
> > Aleksandr
> >
> >
> > On Tue, Jan 18, 2022 at 11:26 AM syzbot
> > <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com> wrote:
> > >
> > > Hello,
> > >
> > > syzbot found the following issue on:
> > >
> > > HEAD commit:    f6f7fbb89bf8 riscv: dts: sifive unmatched: Link the tmp451..
> > > git tree:       git://git.kernel.org/pub/scm/linux/kernel/git/riscv/linux.git fixes
> > > console output: https://syzkaller.appspot.com/x/log.txt?x=1095f85bb00000
> > > kernel config:  https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> > > dashboard link: https://syzkaller.appspot.com/bug?extid=330a558d94b58f7601be
> > > compiler:       riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2
> > > userspace arch: riscv64
> > >
> > > IMPORTANT: if you fix the issue, please add the following tag to the commit:
> > > Reported-by: syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BarufrRgwmN66wUU%2B_FGxMy-sTkjMQnRN8U2H2tQuhB7A%40mail.gmail.com.
