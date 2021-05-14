Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBPE27OCAMGQENGVZYMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id F1117381061
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 21:19:24 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id b35-20020a2ebc230000b02900e586a5ceaesf13931840ljf.13
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 12:19:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621019964; cv=pass;
        d=google.com; s=arc-20160816;
        b=GVIIOgh9SAlT0jpqj5S0yFsmnUWteJdWYhjNJZ9alpjBLSkFczKDsMOEmx+UKd5t/0
         8OxHp6zT3vZCCkBNrwiyBJ436VsMeEtSk+2ThykxiNL0UBLP2nuSLzJLfWZWZ7Es1qoV
         aMLyL+5VOlBZri7S1rFvlrmz20oCOy4tTviyn9I3jvSiYIvz6admCVKF5CZLMnh+yUP7
         jQ73SKQy8og0E5Rrh1PMSNHASJ2YavmACJfY6F7afQxw0YENDQe9azwQgae4CyacLSxt
         MKacRo67Q79eCAKUtSoPfeO+Qvyoe5CBRaU0zW1u4G4+eHz09SlYqted9d2ge4/Tx2XG
         OM9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=WXCO1lZkiBfXBm/tfqp182Af54Qgnkulhuf0wQV64Qw=;
        b=Drt5d0SzWVq/DU4Rbhp7o1KNpQWYEEbFc4KyDcfJ3pE4H3DrBPnkIYjueDlHKvApHg
         pn8b0ySl3+y/C5tI/jc0b7wjov85Hw4EOicFk0Xh6XibCynnCDDu4yRuDmVI/uaW0euc
         8rLIToJltrO9yMoCffkyri0TNgJtWRS7JGWVNSM0NzBhwH5ags6BWquQkucwYeOfztSZ
         cSGkP4NH/J9jOUfNDgS2J/VX6GXauUHFEQORQn3wJ2/J0TkSLCu31OAaUeEy6amEu0nT
         K8qTWrJQu4Mp32dxRxeHtI3iAojZsex3OkzT9Sn49IgYAr7fI2/IJdsy3uUWqWFydLqI
         E0GA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=FHhNFP0H;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WXCO1lZkiBfXBm/tfqp182Af54Qgnkulhuf0wQV64Qw=;
        b=kcJy3sbRS2RZyqPAmbfTVk7uuUmF1LyKbeshhAP/TPKsS0ck+H/v0wBO5JT1Pf/HEP
         DXUzjynyDqI0fnPPnA1lvgAEubT/a15EviZIrdMSGP3XrG7EhZOgjorIURNgQbHI9C1E
         i+EH2bi0bsGE3HAja83qXozMcIV6KXdh1yLBXBB/vQiSbSxJVEK+W7DhxueSyCbmtqVk
         0Snp3W5zYV38WAOWp3/iNtsqGJLmLEkWG4dCThoj+L83RtuCLOBeq3i2wVRTSwSK1MRx
         vEMID6ugNYTqQqb4779zAAKsWdjFkQdZa41M9hYJNQNp1xaPdV5Kq6975HrKOzDg3uHE
         OWjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WXCO1lZkiBfXBm/tfqp182Af54Qgnkulhuf0wQV64Qw=;
        b=b1FyQ8+eiRodwuOpz770wLBmc0p4Z33b0U66RHY3D+xQ0DpdMKhr+rl00uvT8qrwK3
         5oOwbBbC8GaCTNDX0iIRj2nkzPWU12Q2SfJfeemf/Waw3vhPhSATKxWId0ZWP9/N/PLF
         gTWpPad7+aJEt7x3saVaeIjHhJbXFbQQpKxc4cx4FDxG4x9xBMLBL81N3nRk//w8a0CP
         iNTCn4ym4y8MEvRkIvdv6Wmoo66bGIeFRz7jIV4H51nMV0fII6cpy+ZAyiI/6VTvrtsC
         ADPVOYe9GxVTPVE9Y9yMVlVCFlr+gYncbw03rRhzAe5XOVUTe/EYVekvNAfTeuEx9l10
         WbzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lgxl0uibZ4vTTSRVowdVgS4+0+TY81XyTI3vh+YLJuXi4jicZ
	qBTnjyEezIupmx7SRhXJcD0=
X-Google-Smtp-Source: ABdhPJwtsKAkAK5zNeMiTtLUW0i4q6mOHU623HarRlazLKTgmSrSIoyJ31TJvDLbTJweyQWTNo/miA==
X-Received: by 2002:a05:651c:102e:: with SMTP id w14mr40557583ljm.238.1621019964530;
        Fri, 14 May 2021 12:19:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6c2:: with SMTP id u2ls177782lff.3.gmail; Fri, 14
 May 2021 12:19:23 -0700 (PDT)
X-Received: by 2002:a19:c710:: with SMTP id x16mr879288lff.533.1621019963349;
        Fri, 14 May 2021 12:19:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621019963; cv=none;
        d=google.com; s=arc-20160816;
        b=fmk9Hle6No+apvD3sfT3PkPzCm3K9/KeRw3Odfz9JqOcYjj2Vv/ubZ9PHZievCqVDP
         Pz1ESWB/pyeG/YPy/Ro7hFjZeKonAGbSqKhLg1dRgCW6bu1mQ0uKo9aiuaqze4gR1mKw
         WjIEqh8/iC4DlxWvfxNZJvPFewR1uKjh0SnNBqJrgAYZnVAtuM3560QsbLfyyd2CEzci
         fDM2WZf/75PYH0pgh6/aeXzhLyfRXglPgybp8CLhitbgm0QPbv6MKa8fT8dlXzPQW1MY
         NedxxBD+uhTHoCjNstSCPKwLV5lsVWfJUOhzbrc+D16bnGuswFHBkm+u/7AS7h7W8siC
         2PDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WHGE/SI1tO0CAdU9DspiMRu/IcggidAjeljmucgj+1U=;
        b=CGLTr4wwJyjNxuJws4s6OVrJ2YkzaJJlzOlrFPbBe1eabIwlwYD006W+KmKcFnhhX7
         3D4pAqOju9Q816rMLruOA+MXYQ7mmXbQsK2RgoydMRilpXjkA/na7QDAGRTUzh3+QPWp
         QcapR/zbTjz4j1dUL2vzXTLzjy1ZGvWpjDqLsSKTUJFfEszZValATBW/8wOy20XU4rxr
         VTHWaPMIaw8U3+wM0terK/1LWQ52wi8B0g+Kks1ut77qX4Srm/owIKPh6amPYK1HfliN
         6ie3Ljkkj7T/ymNBcZtA8OfrHtInI6B4Qcxr6TYpj27FDBbZtZzLsgeoXzePWny7zJrP
         8TuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=FHhNFP0H;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lj1-x229.google.com (mail-lj1-x229.google.com. [2a00:1450:4864:20::229])
        by gmr-mx.google.com with ESMTPS id g25si277659lfb.10.2021.05.14.12.19.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 May 2021 12:19:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::229 as permitted sender) client-ip=2a00:1450:4864:20::229;
Received: by mail-lj1-x229.google.com with SMTP id 131so13673606ljj.3
        for <kasan-dev@googlegroups.com>; Fri, 14 May 2021 12:19:23 -0700 (PDT)
X-Received: by 2002:a2e:8053:: with SMTP id p19mr39273548ljg.312.1621019962865;
        Fri, 14 May 2021 12:19:22 -0700 (PDT)
Received: from mail-lf1-f42.google.com (mail-lf1-f42.google.com. [209.85.167.42])
        by smtp.gmail.com with ESMTPSA id f14sm1361674ljm.55.2021.05.14.12.19.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 May 2021 12:19:22 -0700 (PDT)
Received: by mail-lf1-f42.google.com with SMTP id r5so27307413lfr.5
        for <kasan-dev@googlegroups.com>; Fri, 14 May 2021 12:19:22 -0700 (PDT)
X-Received: by 2002:a2e:22c4:: with SMTP id i187mr38227020lji.465.1621019658636;
 Fri, 14 May 2021 12:14:18 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m1r1irpc5v.fsf@fess.ebiederm.org>
 <CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
 <m1czuapjpx.fsf@fess.ebiederm.org> <CANpmjNNyifBNdpejc6ofT6+n6FtUw-Cap_z9Z9YCevd7Wf3JYQ@mail.gmail.com>
 <m14kfjh8et.fsf_-_@fess.ebiederm.org> <m1tuni8ano.fsf_-_@fess.ebiederm.org> <m1a6oxewym.fsf_-_@fess.ebiederm.org>
In-Reply-To: <m1a6oxewym.fsf_-_@fess.ebiederm.org>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Fri, 14 May 2021 12:14:02 -0700
X-Gmail-Original-Message-ID: <CAHk-=wikDD+gCUECg9NZAVSV6W_FUdyZFHzK4isfrwES_+sH-w@mail.gmail.com>
Message-ID: <CAHk-=wikDD+gCUECg9NZAVSV6W_FUdyZFHzK4isfrwES_+sH-w@mail.gmail.com>
Subject: Re: [GIT PULL] siginfo: ABI fixes for v5.13-rc2
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=FHhNFP0H;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Thu, May 13, 2021 at 9:55 PM Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> Please pull the for-v5.13-rc2 branch from the git tree:

I really don't like this tree.

The immediate cause for "no" is the silly

 #if IS_ENABLED(CONFIG_SPARC)

and

 #if IS_ENABLED(CONFIG_ALPHA)

code in kernel/signal.c. It has absolutely zero business being there,
when those architectures have a perfectly fine arch/*/kernel/signal.c
file where that code would make much more sense *WITHOUT* any odd
preprocessor games.

But there are other oddities too, like the new

    send_sig_fault_trapno(SIGFPE, si_code, (void __user *) regs->pc,
0, current);

in the alpha code, which fundamentally seems bogus: using
send_sig_fault_trapno() with a '0' for trapno seems entirely
incorrect, since the *ONLY* point of that function is to set si_trapno
to something non-zero.

So it would seem that a plain send_sig_fault() without that 0 would be
the right thing to do.

This also mixes in a lot of other stuff than just the fixes. Which
would have been ok during the merge window, but I'm definitely not
happy about it now.

             Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwikDD%2BgCUECg9NZAVSV6W_FUdyZFHzK4isfrwES_%2BsH-w%40mail.gmail.com.
