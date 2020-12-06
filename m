Return-Path: <kasan-dev+bncBD63B2HX4EPBBUETWT7AKGQEIRGUTDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 286402D0607
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Dec 2020 17:41:56 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id y17sf4141002plr.23
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Dec 2020 08:41:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607272912; cv=pass;
        d=google.com; s=arc-20160816;
        b=0Qv7UBwtusOh1sbjqM3Fg4OfavNHcK0vjRRiVDdXmNCg2G+p7je5Ygy/F50ozBeE0S
         Al7oLx6wsTX/A9QtP3alm/bzFrf9bXRfv308MzxmwHgYTMS7V3mJuWSe3kC0+BVTXFMb
         1hRphiQNGbN1jWL06jJJoMs4DADy+F7vBug3jBkQRKdFjynrcEyLNoM8U+NeUua1MC2B
         2a4rEmhCBeuhv+9OxXD25g36JHEFKMm5CCmaczRRZ0ZH/Q+RGHDQhy6zi+9DkazrEePL
         ixEJhNBK6hrDO7zu5LBGXPj3zQP+pVSommmD5fhiRT5z+rLl9FETbOEIrDG1aOkHxbof
         Jlzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=9pjXiLFspJVCkeCHvXES8HlQH1F+zfWdZ/xqJ2WCPmc=;
        b=Q/FPjbX/0or1Vf8QEo9dRGwtKkpdszzub0aMwM2I+ZN28T3j2XY/JHwHIjDQMqTc4h
         W9pXVXZNwR+9AVS/D72RRxjCABRuHXDmTIFyApvmftpkK9LC99OBF/3ntmTVYRg8rtsi
         bN800SbZJxRsKNBwrtcgq73R7ocBK4Q3YBvc4wKnGlEl/4VigQ7Hcc6/3TBUxsFt1bTe
         rmI2yNoZ3wVNr5BDV2BE3y2wcaQ3X69kxjS7/V3NqObL4pntxL03MStC4sT2TGBN9Gcc
         /eFxRrYRAEyau/BLRmtbDy7EFvqs6aZDeKBsAYX6JOP0B3bvyH/F3beiwUN67mvP7Z/F
         H5lA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=G8QxPO4l;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9pjXiLFspJVCkeCHvXES8HlQH1F+zfWdZ/xqJ2WCPmc=;
        b=Y/eviE0PlsHgWcgotiJdOmmGR91atRtDswJYJRH6ReJ5MiMMeAOTZoRq/YJOwlR0h0
         HpurCBBNVA4/V3oL0I/3ZNAzolU3k3/ncVuJdnsML7N6lKnBGhHV/0/VNZGemOvTEwKk
         cozI2k3mwrzj8K7y7eecbr3k9WBiGfSRXunI3gKe15lqJJMDZ7nSNAMdG1YBewDW7DSK
         3huIgk3TIisB9UibMu+1VIPDsNgqR1mTh7Tx4GobjjDTD8Jyg1BBVMS0CfHu8TiXUtSz
         PMRDM/6fPXU68RsZUvNbeYWi5UL7HOKwgw2z1Nc5mT75Y2XXeKH2/CM6ovGUQTICc4jr
         gplQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9pjXiLFspJVCkeCHvXES8HlQH1F+zfWdZ/xqJ2WCPmc=;
        b=CaxZ+odMBxxeg8TCeOvhobJk/lTNUUuwz9UFcKTw7ZwQJaNOSCe3q2v3YyVagQfd03
         xdTgc9x1MuRueyeeUdW9l97vpxhAd0c8zrgvqR0wgNIMYDq+1tx96ahlKnQj6LFURho5
         Z827DhJ18EwUEn02QnVAym5kDrYSGVLmASfgmKEd6YHlao1vg94lwavOZcjOj94/xOfk
         M6kZKRPsS/7UgHyW90joJgnIsqBe0FULUXs5/ic4yo9IWmoW+b51zLv6VVFNqTN+T3We
         bwieFuiGkZlLMBoROYOK/8AnEl1jJKji+R5V6tqdSyaH1Tw8N4aHqsrJ7x7muzxwMolC
         FiPw==
X-Gm-Message-State: AOAM532ajXrcgVeQx/RX3mkXWmHNqLNACmyEbxON7dXu/JEiaO3gRgXW
	IG9ppZNgCUOBiqjzfMFE2u0=
X-Google-Smtp-Source: ABdhPJzVvSMaC6Mp1XCPkAJRs2p/qniFcJhYCrPTum01y4zBj5BqwjBva95+DJrV1lYX6cqLQmd8Yw==
X-Received: by 2002:a17:90a:67cf:: with SMTP id g15mr12538597pjm.24.1607272912363;
        Sun, 06 Dec 2020 08:41:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7f8e:: with SMTP id a136ls612987pfd.7.gmail; Sun, 06 Dec
 2020 08:41:51 -0800 (PST)
X-Received: by 2002:a63:3714:: with SMTP id e20mr1759854pga.410.1607272911851;
        Sun, 06 Dec 2020 08:41:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607272911; cv=none;
        d=google.com; s=arc-20160816;
        b=ALetwEdMyrmmntws1hUSZ0rc0c954v970hiw7qKJXsDObVTKILcTGj47eCcEkDmxaY
         BJ/CMY0ZxLBpdovFlPAQ1PwpZMxteo7mH3yECkMYddnING2U0miDJaDjmORUk2fqoBJO
         7gTdYqbr3K7gWGCtAGQNbL2AgY11DZKHUlVD00oPMvT6RyouIYPIgpQs4tsO4fg31/9P
         1Ty5q5HQPNvCMNithSO0/jxNruoLfR6FMXXNNuOO1De3tC0Daf0ktH66gbWmdaTEIwYN
         lblddY31vH70TittkeYN87PbWF4pp++HeTsQbV0du7eVVMh0CcMXlO7hy8eM2Renxj7/
         wmQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=9nRfMBLlqdXCc2uMXlWWvA9YShbjFj3h9u6Ma/5LVrY=;
        b=t8V0S+XHaiAOmMqLXBAP861trqn5UEOmQwDdpu+j5M6Lhko5WW2itQIgraq+cbfUVc
         RrRH2OPAEL/zBfYO1EFT+eIEfG0N+8yDB6e71AJm3voiIMyRWQ/2nQU598svPwUr7ELZ
         LzUdAN5xuqRhgl7gfH0uus9R2FwIPg8g1ASSyPBYVM5plDPzzCIxl6FJ5veH9F/EJbap
         VtmwycjvHIsoMaIrIj3+szhMSFNKgd+vx95/zw/UxGbpoYIXmw0JunXlS1yWVbgNbzN5
         mPaBvt3+YbewFHFiJ1VKTUQeaj6xLLKfxAsZZLxvRPebbWdaJ6/+B/SABPHU/6o/723w
         Z71g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=G8QxPO4l;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id o2si620820pjq.0.2020.12.06.08.41.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 06 Dec 2020 08:41:51 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id f9so6782674pfc.11
        for <kasan-dev@googlegroups.com>; Sun, 06 Dec 2020 08:41:51 -0800 (PST)
X-Received: by 2002:a63:d650:: with SMTP id d16mr15139247pgj.277.1607272911566;
        Sun, 06 Dec 2020 08:41:51 -0800 (PST)
Received: from cork (dyndsl-085-016-208-233.ewe-ip-backbone.de. [85.16.208.233])
        by smtp.gmail.com with ESMTPSA id k189sm12910749pfd.99.2020.12.06.08.41.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Dec 2020 08:41:50 -0800 (PST)
Date: Sun, 6 Dec 2020 08:41:45 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <20201206164145.GH1228220@cork>
References: <20201014113724.GD3567119@cork>
 <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
 <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
 <20201014134905.GG3567119@cork>
 <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
 <20201014145149.GH3567119@cork>
 <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=G8QxPO4l;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::42d
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Wed, Oct 14, 2020 at 05:02:08PM +0200, Marco Elver wrote:
>=20
> Interesting. It's certainly more general, but adds a lot of complexity
> to address 1% or less of cases. Maybe there's a middle-ground
> somewhere that I'm not yet seeing. But this is something for the
> future...

Complexity isn't that bad - speaking as a person that wrote memory
allocators before. ;)

There is also the mining nature of finding bugs.  After a while you have
caught most of the 99%-bugs, while the 1% bugs remain in the code.  At
that point the ratio is closer to 50/50 or the rare bugs might even
dominate.

> > I'm leaning towards being more aggressive, but I also tend to receive
> > all those impossible-to-debug memory corruptions and would like to get
> > rid of them. :)

On the note of being aggressive, I've noticed kfence is expensive in
unexpected ways.  We collect CPU backtraces whenever we find scheduling
problems and kfence shows up far more than it should:

   CPU ns-before-dump
B  0   3129268790 [<ffffffff810eeec1>] smp_call_function_many+0x1a1/0x260
B  0   3129268791 [<ffffffff810ef05d>] on_each_cpu+0x2d/0x80
B  0   3129268792 [<ffffffff8101eab8>] text_poke_bp+0xa8/0xc0
B  0   3129268793 [<ffffffff8101bea3>] arch_jump_label_transform+0x83/0xd0
B  0   3129268794 [<ffffffff81167f68>] __jump_label_update+0x68/0x80
B  0   3129268795 [<ffffffff81168008>] jump_label_update+0x88/0x90
B  0   3129268796 [<ffffffff811682b1>] __static_key_slow_dec+0x41/0x90
B  0   3129268797 [<ffffffff81168322>] static_key_slow_dec+0x22/0x60
B  0   3129268798 [<ffffffff811c159d>] toggle_allocation_gate+0x11d/0x150
B  0   3129268799 [<ffffffff8108ada9>] process_one_work+0x219/0x510
B  0   3129268800 [<ffffffff8108b0e2>] worker_thread+0x42/0x5a0
B  0   3129268801 [<ffffffff810913b8>] kthread+0xd8/0xf0
B  0   3129268802 [<ffffffff817c8d05>] ret_from_fork+0x55/0x80
B  0   3129268803 [<ffffffffffffffff>] 0xffffffffffffffff

B  0   3020905965 [<ffffffff810ef05d>] on_each_cpu+0x2d/0x80
B  0   3020905966 [<ffffffff8101ea6b>] text_poke_bp+0x5b/0xc0
B  0   3020905967 [<ffffffff8101bea3>] arch_jump_label_transform+0x83/0xd0
B  0   3020905968 [<ffffffff81167f68>] __jump_label_update+0x68/0x80
B  0   3020905969 [<ffffffff81168008>] jump_label_update+0x88/0x90
B  0   3020905970 [<ffffffff811682b1>] __static_key_slow_dec+0x41/0x90
B  0   3020905971 [<ffffffff81168322>] static_key_slow_dec+0x22/0x60
B  0   3020905972 [<ffffffff811c159d>] toggle_allocation_gate+0x11d/0x150
B  0   3020905973 [<ffffffff8108ada9>] process_one_work+0x219/0x510
B  0   3020905974 [<ffffffff8108b0e2>] worker_thread+0x42/0x5a0
B  0   3020905975 [<ffffffff810913b8>] kthread+0xd8/0xf0
B  0   3020905976 [<ffffffff817c8d05>] ret_from_fork+0x55/0x80
B  0   3020905977 [<ffffffffffffffff>] 0xffffffffffffffff

B  0   2967463122 [<ffffffffffffffff>] 0xffffffffffffffff

B  0   2912168143 [<ffffffff81051a45>] __x2apic_send_IPI_mask+0xc5/0x1a0
B  0   2912168144 [<ffffffff81051b5c>] x2apic_send_IPI_allbutself+0x1c/0x20
B  0   2912168145 [<ffffffff81048d54>] native_send_call_func_ipi+0xa4/0xb0
B  0   2912168146 [<ffffffff810eef0d>] smp_call_function_many+0x1ed/0x260
B  0   2912168147 [<ffffffff810ef05d>] on_each_cpu+0x2d/0x80
B  0   2912168148 [<ffffffff8101ea6b>] text_poke_bp+0x5b/0xc0
B  0   2912168149 [<ffffffff8101bea3>] arch_jump_label_transform+0x83/0xd0
B  0   2912168150 [<ffffffff81167f68>] __jump_label_update+0x68/0x80
B  0   2912168151 [<ffffffff81168008>] jump_label_update+0x88/0x90
B  0   2912168152 [<ffffffff81168265>] static_key_slow_inc+0x95/0xa0
B  0   2912168153 [<ffffffff811c14ca>] toggle_allocation_gate+0x4a/0x150
B  0   2912168154 [<ffffffff8108ada9>] process_one_work+0x219/0x510
B  0   2912168155 [<ffffffff8108b0e2>] worker_thread+0x42/0x5a0
B  0   2912168156 [<ffffffff810913b8>] kthread+0xd8/0xf0
B  0   2912168157 [<ffffffff817c8d05>] ret_from_fork+0x55/0x80
B  0   2912168158 [<ffffffffffffffff>] 0xffffffffffffffff

B  0   2805659204 [<ffffffffffffffff>] 0xffffffffffffffff

B  0   2798513705 [<ffffffff810ef05d>] on_each_cpu+0x2d/0x80
B  0   2798513706 [<ffffffff8101ea95>] text_poke_bp+0x85/0xc0
B  0   2798513707 [<ffffffff8101bea3>] arch_jump_label_transform+0x83/0xd0
B  0   2798513708 [<ffffffff81167f68>] __jump_label_update+0x68/0x80
B  0   2798513709 [<ffffffff81168008>] jump_label_update+0x88/0x90
B  0   2798513710 [<ffffffff81168265>] static_key_slow_inc+0x95/0xa0
B  0   2798513711 [<ffffffff811c14ca>] toggle_allocation_gate+0x4a/0x150
B  0   2798513712 [<ffffffff8108ada9>] process_one_work+0x219/0x510
B  0   2798513713 [<ffffffff8108b0e2>] worker_thread+0x42/0x5a0
B  0   2798513714 [<ffffffff810913b8>] kthread+0xd8/0xf0
B  0   2798513715 [<ffffffff817c8d05>] ret_from_fork+0x55/0x80
B  0   2798513716 [<ffffffffffffffff>] 0xffffffffffffffff

B  0   2687622650 [<ffffffff810ef05d>] on_each_cpu+0x2d/0x80
B  0   2687622651 [<ffffffff8101ea6b>] text_poke_bp+0x5b/0xc0
B  0   2687622652 [<ffffffff8101bea3>] arch_jump_label_transform+0x83/0xd0
B  0   2687622653 [<ffffffff81167f68>] __jump_label_update+0x68/0x80
B  0   2687622654 [<ffffffff81168008>] jump_label_update+0x88/0x90
B  0   2687622655 [<ffffffff81168265>] static_key_slow_inc+0x95/0xa0
B  0   2687622656 [<ffffffff811c14ca>] toggle_allocation_gate+0x4a/0x150
B  0   2687622657 [<ffffffff8108ada9>] process_one_work+0x219/0x510
B  0   2687622658 [<ffffffff8108b0e2>] worker_thread+0x42/0x5a0
B  0   2687622659 [<ffffffff810913b8>] kthread+0xd8/0xf0
B  0   2687622660 [<ffffffff817c8d05>] ret_from_fork+0x55/0x80
B  0   2687622661 [<ffffffffffffffff>] 0xffffffffffffffff

B  0   2643854943 [<ffffffff810eeec1>] smp_call_function_many+0x1a1/0x260
B  0   2643854944 [<ffffffff810ef05d>] on_each_cpu+0x2d/0x80
B  0   2643854945 [<ffffffff8101eab8>] text_poke_bp+0xa8/0xc0
B  0   2643854946 [<ffffffff8101bea3>] arch_jump_label_transform+0x83/0xd0
B  0   2643854947 [<ffffffff81167f68>] __jump_label_update+0x68/0x80
B  0   2643854948 [<ffffffff81168008>] jump_label_update+0x88/0x90
B  0   2643854949 [<ffffffff81168265>] static_key_slow_inc+0x95/0xa0
B  0   2643854950 [<ffffffff811c14ca>] toggle_allocation_gate+0x4a/0x150
B  0   2643854951 [<ffffffff8108ada9>] process_one_work+0x219/0x510
B  0   2643854952 [<ffffffff8108b0e2>] worker_thread+0x42/0x5a0
B  0   2643854953 [<ffffffff810913b8>] kthread+0xd8/0xf0
B  0   2643854954 [<ffffffff817c8d05>] ret_from_fork+0x55/0x80
B  0   2643854955 [<ffffffffffffffff>] 0xffffffffffffffff

...

We use CONFIG_KFENCE_SAMPLE_INTERVAL=3D1.

I don't quite get what the static key does or how it is supposed to
help, but my best guess would be that it is supposed to reduce CPU
overhead, not increase it.

Since the rest of kfence looks pretty efficient and barely shows up in
profiles, I wanted to switch toggle_allocation_gate() to use an hrtimer
anyway.  We can go to 100=C2=B5s intervals, maybe even 10=C2=B5s.  Guess I'=
ll
remove the label thing as well.

J=C3=B6rn

--
The odds are greatly against you being immensely smarter than everyone
else in the field. If your analysis says your terminal velocity is twice
the speed of light, you may have invented warp drive, but the chances
are a lot better that you've screwed up.
-- David Akin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201206164145.GH1228220%40cork.
