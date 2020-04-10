Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN4BYH2AKGQEACA3APY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E695B1A44AB
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 11:47:36 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id a7sf1053686otf.13
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 02:47:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586512056; cv=pass;
        d=google.com; s=arc-20160816;
        b=mb+VzyODHU5+9hBthpl8eloFTRKT+89/Snu0ID+7Hrq9Ps7DNNmPXtWOHomgXTPnoY
         7QLSyKNGjTrETssFQ252t+9YUHX1e/HNcj4XjWujDoDj/+jfpA/hb3mR3JJvxQn4dITB
         v/gPoWpva6Dug/ajqva/t9Rh93C2gXd1AOrVRYR7WC+3J94PsuZTxCc+ClVYQ62g29lX
         jEuiCKlW0yisIeNjf3vIIcNjK2OA2wqbp4BoV8QuTLsfPN68vwP33gS+UerefyxBnKDV
         KS8Q4MxyU12eXLfPLfO6zlmECBBdJJ/ReiLVWMlGYzlo+4lqZe3AaSS7QbTkbb8GArkX
         infw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oCrvdb7ddF81iX+O4Cgv4hQx8Nm7t0Wfl6YFQYqzSUU=;
        b=elsFtqJ3wBrdhgjoRG8EjDcmjDsjbdMbrONCXQp9DDfkQzPDsIJGoLjSltZIPhcGi0
         XmvZxzD2D7YowXDlney+Z60CDRiybBDz9aOIBFJiW4ic92S2m990SUVqM6/vScZngBFm
         4FRQxY0BExOHHjWNY4hvkbLCFNzjOiFkkO7pDGGnkwcxhiacnlphUF39fKskl+dTNyYl
         r0Ju0j7vNkPAvbvqqEGbt2G2InjgI62lAhKNemztqDkB+yisAHOyzk9jHyZk4jQRXo14
         c4T0Xaiao5PtKVcYPPVp60qh6kQilpnX3yRTMeIdPjfj7wn7oq8PIvpmUJt4n2GoZc2x
         wT9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Dr88S+VC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=oCrvdb7ddF81iX+O4Cgv4hQx8Nm7t0Wfl6YFQYqzSUU=;
        b=sJhZ5CBzca0sxjTM80mpKQB1Dz9cc93NTi0ECQHiJzQBMdp+rm5FEY4W2ziDjkBvaS
         8bx8m9wkmymYW8PmI6/kcxgqg4+DHcSegZzcb1RiLYFnv5qCdG4M43m8sno3AUb0Iorn
         +/YmaPvw4sP2hn2yWKSMUhesSuaY6AM5hrf6015Wq/24JiTiBc2ncHdQOCFi/pDM0JXI
         99m9DWfcI3QX31lO9vJ7cJzpwrLkTeIgnAoQ5gvPZO9qW2ZQDgILOhDMaErNPCO6bMux
         KwLJV2PkmP55XLBDqimWl5sWqTYxJGjyAD38+fOmvQHNIWha7SQ0XLty64eQ+oNzGbIB
         tyGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oCrvdb7ddF81iX+O4Cgv4hQx8Nm7t0Wfl6YFQYqzSUU=;
        b=GI8olauSTWwqyWh6fYlAAbWaRKl/r1JNENXih6JNd9m6SznN62U1RBeKROWDVY65b9
         dCrwax/IKqKEe70lsbF/O7IP29rLrZLRCQxFYrke+/eloF7dW9bUrO1fJlZ5eh6YzVj2
         1nzNwbLKbjO6d6HGE4p2dBmnT+0oZIaYVxgPFV2iDmSVhPpKfmyoy2Wq8dHsBS4w1x6M
         rPlo0jL+hk1JGK3B/lO3K0KbDOictQ1LV0Zjkn6KmIW+5iJGFAXS8y4ZI5QCAOvw10Qs
         Jc38WmU6JhvTkoWZGRz2BRY8luvqTUBJKVCjzb7sfChrrFooMvCbHpt8DLNt6qJyiRE+
         Cd9w==
X-Gm-Message-State: AGi0PuacD2RZJsXKD/Nkm4MOSkE3invxq5EwhFoooftz1KkG2NP8F/uO
	d6ftNvsI30aWZdN4s28kYs0=
X-Google-Smtp-Source: APiQypIvpJlYWo+YUMyysFYdxwr6n1rZOxIvPEx7ZI4utuN1z7RiRSLAvDbz4S1EedFxSDlhATAO6w==
X-Received: by 2002:a9d:3b6:: with SMTP id f51mr3665463otf.255.1586512055733;
        Fri, 10 Apr 2020 02:47:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3b23:: with SMTP id z32ls5152290otb.1.gmail; Fri, 10 Apr
 2020 02:47:35 -0700 (PDT)
X-Received: by 2002:a9d:6d82:: with SMTP id x2mr3651659otp.50.1586512055345;
        Fri, 10 Apr 2020 02:47:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586512055; cv=none;
        d=google.com; s=arc-20160816;
        b=hC2L6TpmNIfCCJVqfh3GhpCaIwDcBnYVmQqir3mgptRMt5ety3hREWPcBlkxsMvEAF
         YgBAA1v8EwkcKJ/Fk+QqDUNmkmSGR664IyceLOxvNJpLQfcJgyikEsIQl1brlCKKno5j
         ZS1K5DsXCZnCkKx/SeOFGYGiwyY+Y8x5haplVa3l9zpx8vC+v2naG4zvsyaxSyXfyij2
         2IaM625sv2WxRp6eXmLvWE3vFuCNHHvt7oJr/COSal8vyWsiW9xMSGXuIqKaLxuS9nA8
         k5l9Kpn7jJ+UUGYPGE1pRW+1mP1Hb+VZZm3/DFcxRO5Zx2WgJJ2y06kF9vD5XLL+yQuc
         vR4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tzg1tHziELvZQ3o5qR7exMV835Cs9K0+FEoadxQ1B5o=;
        b=n8gDlMbEUZ1xtDj3+byRi7Abc+tHCH5hoKdWX2ZumyhKRZUWjlHdyDdu/rwSbCAKTW
         xfZIq88hkM9A/E57aE6i3eDth0uhzRXzfA8RgZAoLn40sATfMAu6+cxpS+/M3Iv6rdUx
         keNAeRQ/ktb9ZiDrUFdBLe1EwkIsU1bwbWl/0KCSLiyTuycgUDQE2U3VltYbyg/RVjdW
         WtyPt/Lbbu025CRii0PCPPystWsFZpUfPgzP+ozGUOeLVMsB3rUHWsoRQTzjTkPXa2yv
         /MK+by1TcgMDwCV4Rsm+Ndd2ntlvYuny9XluIvdAlDTaFZRECXfYFOICQ5vVNrw7ecbT
         lhYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Dr88S+VC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id x23si125799oif.2.2020.04.10.02.47.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Apr 2020 02:47:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id a7so986424oid.7
        for <kasan-dev@googlegroups.com>; Fri, 10 Apr 2020 02:47:35 -0700 (PDT)
X-Received: by 2002:a54:481a:: with SMTP id j26mr2758242oij.172.1586512054759;
 Fri, 10 Apr 2020 02:47:34 -0700 (PDT)
MIME-Version: 1.0
References: <E180B225-BF1E-4153-B399-1DBF8C577A82@lca.pw> <fb39d3d2-063e-b828-af1c-01f91d9be31c@redhat.com>
 <017E692B-4791-46AD-B9ED-25B887ECB56B@lca.pw> <CANpmjNMiHNVh3BVxZUqNo4jW3DPjoQPrn-KEmAJRtSYORuryEA@mail.gmail.com>
 <B7F7F73E-EE27-48F4-A5D0-EBB29292913E@lca.pw> <CANpmjNMEgc=+bLU472jy37hYPYo5_c+Kbyti8-mubPsEGBrm3A@mail.gmail.com>
 <2730C0CC-B8B5-4A65-A4ED-9DFAAE158AA6@lca.pw> <CANpmjNNUn9_Q30CSeqbU_TNvaYrMqwXkKCA23xO4ZLr2zO0w9Q@mail.gmail.com>
 <B5F0F530-911E-4B75-886A-9D8C54FF49C8@lca.pw> <DF45D739-59F3-407C-BE8C-2B1E164B493B@lca.pw>
In-Reply-To: <DF45D739-59F3-407C-BE8C-2B1E164B493B@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Apr 2020 11:47:23 +0200
Message-ID: <CANpmjNMR4BgfCxL9qXn0sQrJtQJbEPKxJ5_HEa2VXWi6UY4wig@mail.gmail.com>
Subject: Re: KCSAN + KVM = host reset
To: Qian Cai <cai@lca.pw>
Cc: Paolo Bonzini <pbonzini@redhat.com>, "paul E. McKenney" <paulmck@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	kvm@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Dr88S+VC;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Fri, 10 Apr 2020 at 01:00, Qian Cai <cai@lca.pw> wrote:
>
>
>
> > On Apr 9, 2020, at 5:28 PM, Qian Cai <cai@lca.pw> wrote:
> >
> >
> >
> >> On Apr 9, 2020, at 12:03 PM, Marco Elver <elver@google.com> wrote:
> >>
> >> On Thu, 9 Apr 2020 at 17:30, Qian Cai <cai@lca.pw> wrote:
> >>>
> >>>
> >>>
> >>>> On Apr 9, 2020, at 11:22 AM, Marco Elver <elver@google.com> wrote:
> >>>>
> >>>> On Thu, 9 Apr 2020 at 17:10, Qian Cai <cai@lca.pw> wrote:
> >>>>>
> >>>>>
> >>>>>
> >>>>>> On Apr 9, 2020, at 3:03 AM, Marco Elver <elver@google.com> wrote:
> >>>>>>
> >>>>>> On Wed, 8 Apr 2020 at 23:29, Qian Cai <cai@lca.pw> wrote:
> >>>>>>>
> >>>>>>>
> >>>>>>>
> >>>>>>>> On Apr 8, 2020, at 5:25 PM, Paolo Bonzini <pbonzini@redhat.com> =
wrote:
> >>>>>>>>
> >>>>>>>> On 08/04/20 22:59, Qian Cai wrote:
> >>>>>>>>> Running a simple thing on this AMD host would trigger a reset r=
ight away.
> >>>>>>>>> Unselect KCSAN kconfig makes everything work fine (the host wou=
ld also
> >>>>>>>>> reset If only "echo off > /sys/kernel/debug/kcsan=E2=80=9D befo=
re running qemu-kvm).
> >>>>>>>>
> >>>>>>>> Is this a regression or something you've just started to play wi=
th?  (If
> >>>>>>>> anything, the assembly language conversion of the AMD world swit=
ch that
> >>>>>>>> is in linux-next could have reduced the likelihood of such a fai=
lure,
> >>>>>>>> not increased it).
> >>>>>>>
> >>>>>>> I don=E2=80=99t remember I had tried this combination before, so =
don=E2=80=99t know if it is a
> >>>>>>> regression or not.
> >>>>>>
> >>>>>> What happens with KASAN? My guess is that, since it also happens w=
ith
> >>>>>> "off", something that should not be instrumented is being
> >>>>>> instrumented.
> >>>>>
> >>>>> No, KASAN + KVM works fine.
> >>>>>
> >>>>>>
> >>>>>> What happens if you put a 'KCSAN_SANITIZE :=3D n' into
> >>>>>> arch/x86/kvm/Makefile? Since it's hard for me to reproduce on this
> >>>>>
> >>>>> Yes, that works, but this below alone does not work,
> >>>>>
> >>>>> KCSAN_SANITIZE_kvm-amd.o :=3D n
> >>>>
> >>>> There are some other files as well, that you could try until you hit
> >>>> the right one.
> >>>>
> >>>> But since this is in arch, 'KCSAN_SANITIZE :=3D n' wouldn't be too b=
ad
> >>>> for now. If you can't narrow it down further, do you want to send a
> >>>> patch?
> >>>
> >>> No, that would be pretty bad because it will disable KCSAN for Intel
> >>> KVM as well which is working perfectly fine right now. It is only AMD
> >>> is broken.
> >>
> >> Interesting. Unfortunately I don't have access to an AMD machine right=
 now.
> >>
> >> Actually I think it should be:
> >>
> >> KCSAN_SANITIZE_svm.o :=3D n
> >> KCSAN_SANITIZE_pmu_amd.o :=3D n
> >>
> >> If you want to disable KCSAN for kvm-amd.
> >
> > KCSAN_SANITIZE_svm.o :=3D n
> >
> > That alone works fine. I am wondering which functions there could trigg=
er
> > perhaps some kind of recursing with KCSAN?
>
> Another data point is set CONFIG_KCSAN_INTERRUPT_WATCHER=3Dn alone
> also fixed the issue. I saw quite a few interrupt related function in svm=
.c, so
> some interrupt-related recursion going on?

That would contradict what you said about it working if KCSAN is
"off". What kernel are you attempting to use in the VM?

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMR4BgfCxL9qXn0sQrJtQJbEPKxJ5_HEa2VXWi6UY4wig%40mail.gmail.=
com.
