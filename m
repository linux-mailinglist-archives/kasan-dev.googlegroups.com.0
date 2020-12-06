Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMVOWT7AKGQETSQP35Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 658132D065D
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Dec 2020 18:38:59 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id v12sf15186096ybi.6
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Dec 2020 09:38:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607276338; cv=pass;
        d=google.com; s=arc-20160816;
        b=qoFdFvDxvKWxPOgQLtqkjhC4nbwiniyGDkExeErIaIf7i47OzMjxhdHUxZ5ib6GE9D
         BjXyA8N9hr9VQkYST3Z6y/n1MzhDQhrwlfc2fvjN2vYZxE2ixFSxs4+ud47m8Tu1/Re5
         uhzDwRT5lJUrTHFGsIFAzvtjrOFHJuaTdruaYu6niAOhC0JUE5LUsp+/pnhxDubU4zYU
         o3DkwVGiDwSS/jhIhdXa2SZo5yciTEDo9ct3S2IgDuAKl7bXQgFgnAgBf/OjuiQbWgjA
         dVxnFocbJYu1M7Qy3mBss1NTlQcuom1ELJLR3r7B4AKZkOD4oZMd/054DbtiZBu31/7J
         V9VQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Wb28s2t6t+KglEOg23YEAVsTVqzLul5hs5g1Z/cxJ98=;
        b=ik519VXvY5SZF5m3zkXmfZae/dIkDCAfIJ3RrXVMxuThkFecrtRMk9l+G11GAhdlEv
         UZQE01ostf/+M2hX06pUKjTs8ECetovfq12YErjenqDA7K5WupDiQV3Vwglyg9FwKZy5
         C49AuriGiJcIaSS7c2mda8cvnEhKwA0jJQrYXdDK499oFSnkubXvcQNLwAy799/Tswnh
         Tox1sOqU4W/m6UVCrhSvwbBLegndChUHtlcvODWvJd62cf8L2Wx9SqaNnTwG0klSVWGu
         5Nmxb9UNh9y0t7G2fXv1EVZScDUS5SPXKopfuWuaigb3i0O3HN4JvDA4IlZGnD3FR5UX
         0b8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r00qjNvG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Wb28s2t6t+KglEOg23YEAVsTVqzLul5hs5g1Z/cxJ98=;
        b=QiunCb7uMkFMJG9dz+wQ7x974mavwUm7sA4P9+oOcPNzRe4AoSmJS83IoJnnZ1Wv7w
         UAQ26VA/duuVbE9y0YVSoPzP7e9OeLXlWkxnEm4KSXYiw5ymwF2z434fdOGMTLwNnfHO
         6ytSWAHOfofAPSjGHvtPNqI2rOIgzgNLpGO7nSw/snlJfsNadlqELumi/APbb2QN3xzE
         ezMuDN9mUD0aJxAKsTmTHuEbRS6UE5vRkesOTGNHuB9Ep2Qo3YfqZVaVdDTdhgTYnnmq
         1Z1mJItOGuMmRSA38PtGKRwJuL7KyGjFSMq1cdQ3+hHEbIA4EfzUnRAPRAzVTQabZcWV
         GR7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Wb28s2t6t+KglEOg23YEAVsTVqzLul5hs5g1Z/cxJ98=;
        b=Zon+YdVtH3tegwEWuJyh7B8ARe1NDdNK755AhRq1TfjcaD7mJ4MlK5V0z+ks32rWRl
         kvV1jGRVX8y+soZwBzmqJttLzHss6/ylFPMJYaSMRpI4dipe7/jW2EoBLHjbo859OQY2
         SEC3/X5ZKSGYk6irnHHY6koztoZ6lgtpZecEZUWycrAQv0XDc/jwdIM+7JG+HdSQPG+p
         B5s9WD3+1PWVmeWED2b75yWGc9iqg0UZ6B+Am66FIhZ2xF6R+r28t7i3hXDiP4O55M7u
         1MNJ1uOy6pszgu5IeNTimnosBPzkBZkmI42WRNYVdPRGuXjXdV6Tom6UCVKja+2vPC9q
         WGqQ==
X-Gm-Message-State: AOAM531/kPBuz74TV9HQ4jXNyi2t3hJ1Vgewy6PiCPkyd4pN72DC4Ksv
	w2rAXdb4mm6HVkXfGGdsJ4g=
X-Google-Smtp-Source: ABdhPJyolX8BRoIC3jT9cliybgTT93/kTy8Z1mWgoKr85cI6L4eUZjJ2fanM7P+pkTdIxHXg9hTJ1w==
X-Received: by 2002:a25:9392:: with SMTP id a18mr18810116ybm.330.1607276338291;
        Sun, 06 Dec 2020 09:38:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6908:: with SMTP id e8ls6987506ybc.9.gmail; Sun, 06 Dec
 2020 09:38:57 -0800 (PST)
X-Received: by 2002:a25:33c2:: with SMTP id z185mr8473989ybz.331.1607276337728;
        Sun, 06 Dec 2020 09:38:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607276337; cv=none;
        d=google.com; s=arc-20160816;
        b=OONActt8DSUWfDRfddIyd3qqLmKvp0++iJ4wSEgtTKJxOVp5SR/1trlVeurBM408+a
         xuguS3gt8O9yfYsxilFRO7eISKfzRbs+JxVgSApN5LZr6KYf4wHuHtINTsiyk87hSfod
         KNb5EeqXg/rwc8J1VKAuHXroKlMtJU8iOSjSgxTANF3n+vOVUtNjdjCFQvwgpFOeaypx
         Q7APAb3ciOOA2jE62ADYWPEx6f6WwAwPs5zQb+iCVYSFlYBa7/RsfgAHrJxrQgcCdKtm
         GqeAL+NVLh1fP2IF58pySN0Gub9YNbVekShIEhoy1Ot7QQkdggqS+D32saLHoieY7XcO
         RfJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/tJ79gzN79XlYTDKESq0VemxEVaOLSOflTOmsh2+0i4=;
        b=SqXZQaoDcf80YHsyeE8rAOzqEMBuEvLt7HCa9SG+vJ6xgBAUufXv+IiFjDKnpAPLE2
         GjugIUntlK7SFicX2Jmq9gEBG4BkeIAiIXAZ5lYGwVVDvdGMd6HM4wJ9SejqVusW41Dz
         xv7+BgpmA6xqbMGCmS/M6DA/EZMcpSijIXuncTqNih6RuXR3oxHyDnwHDtN2Cy/LxE2F
         hOVy641kpoZtW7i6rz6y6r+V+aT9nmEBdR2n1qRXV797X8kOKh1Fq6v+xEnQ4KtID+BI
         N/pWZWFEh+uNoqyBRoFGoM1vtcv55miAhDeFlUU4euLNDwqAZ2JUGw92nG/mjNb8pl85
         k1bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r00qjNvG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22e.google.com (mail-oi1-x22e.google.com. [2607:f8b0:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id x14si754651ybk.2.2020.12.06.09.38.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 06 Dec 2020 09:38:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) client-ip=2607:f8b0:4864:20::22e;
Received: by mail-oi1-x22e.google.com with SMTP id 15so1578466oix.8
        for <kasan-dev@googlegroups.com>; Sun, 06 Dec 2020 09:38:57 -0800 (PST)
X-Received: by 2002:aca:448b:: with SMTP id r133mr7649284oia.121.1607276337144;
 Sun, 06 Dec 2020 09:38:57 -0800 (PST)
MIME-Version: 1.0
References: <20201014113724.GD3567119@cork> <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
 <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
 <20201014134905.GG3567119@cork> <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
 <20201014145149.GH3567119@cork> <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
 <20201206164145.GH1228220@cork>
In-Reply-To: <20201206164145.GH1228220@cork>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 6 Dec 2020 18:38:45 +0100
Message-ID: <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
Subject: Re: GWP-ASAN
To: =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=r00qjNvG;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Sun, 6 Dec 2020 at 17:41, J=C3=B6rn Engel <joern@purestorage.com> wrote:
>
> On Wed, Oct 14, 2020 at 05:02:08PM +0200, Marco Elver wrote:
> >
> > Interesting. It's certainly more general, but adds a lot of complexity
> > to address 1% or less of cases. Maybe there's a middle-ground
> > somewhere that I'm not yet seeing. But this is something for the
> > future...
>
> Complexity isn't that bad - speaking as a person that wrote memory
> allocators before. ;)
>
> There is also the mining nature of finding bugs.  After a while you have
> caught most of the 99%-bugs, while the 1% bugs remain in the code.  At
> that point the ratio is closer to 50/50 or the rare bugs might even
> dominate.
>
> > > I'm leaning towards being more aggressive, but I also tend to receive
> > > all those impossible-to-debug memory corruptions and would like to ge=
t
> > > rid of them. :)
>
> On the note of being aggressive, I've noticed kfence is expensive in
> unexpected ways.  We collect CPU backtraces whenever we find scheduling
> problems and kfence shows up far more than it should:
>
>    CPU ns-before-dump
> B  0   3129268790 [<ffffffff810eeec1>] smp_call_function_many+0x1a1/0x260
> B  0   3129268791 [<ffffffff810ef05d>] on_each_cpu+0x2d/0x80
> B  0   3129268792 [<ffffffff8101eab8>] text_poke_bp+0xa8/0xc0
> B  0   3129268793 [<ffffffff8101bea3>] arch_jump_label_transform+0x83/0xd=
0
> B  0   3129268794 [<ffffffff81167f68>] __jump_label_update+0x68/0x80
> B  0   3129268795 [<ffffffff81168008>] jump_label_update+0x88/0x90
> B  0   3129268796 [<ffffffff811682b1>] __static_key_slow_dec+0x41/0x90
> B  0   3129268797 [<ffffffff81168322>] static_key_slow_dec+0x22/0x60
> B  0   3129268798 [<ffffffff811c159d>] toggle_allocation_gate+0x11d/0x150
> B  0   3129268799 [<ffffffff8108ada9>] process_one_work+0x219/0x510
> B  0   3129268800 [<ffffffff8108b0e2>] worker_thread+0x42/0x5a0
> B  0   3129268801 [<ffffffff810913b8>] kthread+0xd8/0xf0
> B  0   3129268802 [<ffffffff817c8d05>] ret_from_fork+0x55/0x80
> B  0   3129268803 [<ffffffffffffffff>] 0xffffffffffffffff
>
> B  0   3020905965 [<ffffffff810ef05d>] on_each_cpu+0x2d/0x80
> B  0   3020905966 [<ffffffff8101ea6b>] text_poke_bp+0x5b/0xc0
> B  0   3020905967 [<ffffffff8101bea3>] arch_jump_label_transform+0x83/0xd=
0
> B  0   3020905968 [<ffffffff81167f68>] __jump_label_update+0x68/0x80
> B  0   3020905969 [<ffffffff81168008>] jump_label_update+0x88/0x90
> B  0   3020905970 [<ffffffff811682b1>] __static_key_slow_dec+0x41/0x90
> B  0   3020905971 [<ffffffff81168322>] static_key_slow_dec+0x22/0x60
> B  0   3020905972 [<ffffffff811c159d>] toggle_allocation_gate+0x11d/0x150
> B  0   3020905973 [<ffffffff8108ada9>] process_one_work+0x219/0x510
> B  0   3020905974 [<ffffffff8108b0e2>] worker_thread+0x42/0x5a0
> B  0   3020905975 [<ffffffff810913b8>] kthread+0xd8/0xf0
> B  0   3020905976 [<ffffffff817c8d05>] ret_from_fork+0x55/0x80
> B  0   3020905977 [<ffffffffffffffff>] 0xffffffffffffffff
>
> B  0   2967463122 [<ffffffffffffffff>] 0xffffffffffffffff
>
> B  0   2912168143 [<ffffffff81051a45>] __x2apic_send_IPI_mask+0xc5/0x1a0
> B  0   2912168144 [<ffffffff81051b5c>] x2apic_send_IPI_allbutself+0x1c/0x=
20
> B  0   2912168145 [<ffffffff81048d54>] native_send_call_func_ipi+0xa4/0xb=
0
> B  0   2912168146 [<ffffffff810eef0d>] smp_call_function_many+0x1ed/0x260
> B  0   2912168147 [<ffffffff810ef05d>] on_each_cpu+0x2d/0x80
> B  0   2912168148 [<ffffffff8101ea6b>] text_poke_bp+0x5b/0xc0
> B  0   2912168149 [<ffffffff8101bea3>] arch_jump_label_transform+0x83/0xd=
0
> B  0   2912168150 [<ffffffff81167f68>] __jump_label_update+0x68/0x80
> B  0   2912168151 [<ffffffff81168008>] jump_label_update+0x88/0x90
> B  0   2912168152 [<ffffffff81168265>] static_key_slow_inc+0x95/0xa0
> B  0   2912168153 [<ffffffff811c14ca>] toggle_allocation_gate+0x4a/0x150
> B  0   2912168154 [<ffffffff8108ada9>] process_one_work+0x219/0x510
> B  0   2912168155 [<ffffffff8108b0e2>] worker_thread+0x42/0x5a0
> B  0   2912168156 [<ffffffff810913b8>] kthread+0xd8/0xf0
> B  0   2912168157 [<ffffffff817c8d05>] ret_from_fork+0x55/0x80
> B  0   2912168158 [<ffffffffffffffff>] 0xffffffffffffffff
>
> B  0   2805659204 [<ffffffffffffffff>] 0xffffffffffffffff
>
> B  0   2798513705 [<ffffffff810ef05d>] on_each_cpu+0x2d/0x80
> B  0   2798513706 [<ffffffff8101ea95>] text_poke_bp+0x85/0xc0
> B  0   2798513707 [<ffffffff8101bea3>] arch_jump_label_transform+0x83/0xd=
0
> B  0   2798513708 [<ffffffff81167f68>] __jump_label_update+0x68/0x80
> B  0   2798513709 [<ffffffff81168008>] jump_label_update+0x88/0x90
> B  0   2798513710 [<ffffffff81168265>] static_key_slow_inc+0x95/0xa0
> B  0   2798513711 [<ffffffff811c14ca>] toggle_allocation_gate+0x4a/0x150
> B  0   2798513712 [<ffffffff8108ada9>] process_one_work+0x219/0x510
> B  0   2798513713 [<ffffffff8108b0e2>] worker_thread+0x42/0x5a0
> B  0   2798513714 [<ffffffff810913b8>] kthread+0xd8/0xf0
> B  0   2798513715 [<ffffffff817c8d05>] ret_from_fork+0x55/0x80
> B  0   2798513716 [<ffffffffffffffff>] 0xffffffffffffffff
>
> B  0   2687622650 [<ffffffff810ef05d>] on_each_cpu+0x2d/0x80
> B  0   2687622651 [<ffffffff8101ea6b>] text_poke_bp+0x5b/0xc0
> B  0   2687622652 [<ffffffff8101bea3>] arch_jump_label_transform+0x83/0xd=
0
> B  0   2687622653 [<ffffffff81167f68>] __jump_label_update+0x68/0x80
> B  0   2687622654 [<ffffffff81168008>] jump_label_update+0x88/0x90
> B  0   2687622655 [<ffffffff81168265>] static_key_slow_inc+0x95/0xa0
> B  0   2687622656 [<ffffffff811c14ca>] toggle_allocation_gate+0x4a/0x150
> B  0   2687622657 [<ffffffff8108ada9>] process_one_work+0x219/0x510
> B  0   2687622658 [<ffffffff8108b0e2>] worker_thread+0x42/0x5a0
> B  0   2687622659 [<ffffffff810913b8>] kthread+0xd8/0xf0
> B  0   2687622660 [<ffffffff817c8d05>] ret_from_fork+0x55/0x80
> B  0   2687622661 [<ffffffffffffffff>] 0xffffffffffffffff
>
> B  0   2643854943 [<ffffffff810eeec1>] smp_call_function_many+0x1a1/0x260
> B  0   2643854944 [<ffffffff810ef05d>] on_each_cpu+0x2d/0x80
> B  0   2643854945 [<ffffffff8101eab8>] text_poke_bp+0xa8/0xc0
> B  0   2643854946 [<ffffffff8101bea3>] arch_jump_label_transform+0x83/0xd=
0
> B  0   2643854947 [<ffffffff81167f68>] __jump_label_update+0x68/0x80
> B  0   2643854948 [<ffffffff81168008>] jump_label_update+0x88/0x90
> B  0   2643854949 [<ffffffff81168265>] static_key_slow_inc+0x95/0xa0
> B  0   2643854950 [<ffffffff811c14ca>] toggle_allocation_gate+0x4a/0x150
> B  0   2643854951 [<ffffffff8108ada9>] process_one_work+0x219/0x510
> B  0   2643854952 [<ffffffff8108b0e2>] worker_thread+0x42/0x5a0
> B  0   2643854953 [<ffffffff810913b8>] kthread+0xd8/0xf0
> B  0   2643854954 [<ffffffff817c8d05>] ret_from_fork+0x55/0x80
> B  0   2643854955 [<ffffffffffffffff>] 0xffffffffffffffff
>
> ...
>
> We use CONFIG_KFENCE_SAMPLE_INTERVAL=3D1.

This is entirely expected. For production use we're looking at sample
intervals of 500ms or larger.

> I don't quite get what the static key does or how it is supposed to
> help, but my best guess would be that it is supposed to reduce CPU
> overhead, not increase it.

Toggling the static key is expensive, because it has to patch the code
and flip the static branch (involves IPIs etc.).

The reason for the static keys is that we've designed KFENCE for the
case where the branch-taken case is very very unlikely (with large
sample intervals). See
https://github.com/google/kasan/blob/kfence/Documentation/dev-tools/kfence.=
rst#implementation-details

> Since the rest of kfence looks pretty efficient and barely shows up in
> profiles, I wanted to switch toggle_allocation_gate() to use an hrtimer
> anyway.  We can go to 100=C2=B5s intervals, maybe even 10=C2=B5s.  Guess =
I'll
> remove the label thing as well.

At that point, you'd need 1) a very large KFENCE pool to not exhaust
it immediately, and 2) maybe think about replacing the static key with
simply a boolean that is checked. However, this is explicitly not what
we wanted to design KFENCE for, because a non-static branch in the
SL*B fast path is not acceptable if we want to retain ~zero overhead.

And KFENCE is not designed for something like 10=C2=B5s, because the
resulting overhead (in terms of memory for the pool and performance)
just are no longer acceptable. At that point, please just use KASAN.
Presumably you're trying to run this in some canary environment, and
having a few KASAN canaries will yield better results than a few
KFENCE canaries. However, if you have >10000s machines, and you want
something in production, then KFENCE is your friend (at reasonable
sample intervals!) -- this is what we designed KFENCE for.

My feeling is that you'd also like MTE-based KASAN:
https://lkml.org/lkml/2020/11/10/1187 -- but, like anything, there are
trade-offs. The biggest one right now is that it requires unreleased
Arm64 silicon, and early silicon won't be ~zero overhead. One can hope
that we'll see it for x86 one day...

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNNZDuRo%2B1UZam%3DpZFij%3DQHR9sSa-BaNGrgVse-PjQF5zw%40mail.=
gmail.com.
