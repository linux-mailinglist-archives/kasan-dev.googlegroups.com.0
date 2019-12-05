Return-Path: <kasan-dev+bncBCMIZB7QWENRBZOXUPXQKGQE2ZA3I4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B6C4114035
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 12:37:11 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id u6sf1614284pjv.14
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 03:37:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575545829; cv=pass;
        d=google.com; s=arc-20160816;
        b=VWNrEqRMK1fNM2DtHJsZHXWyKpY22PvcT9N7HoLwaPVEvFrXk/+7CBLkXSITZ/0BJJ
         OdjhGRVIQUYRdklX8uyBIl7u/Q1XulLE/oqQfi+WIKy8HPUlkhBDIp+jpyGl5Jw/KQ/q
         9O+jONVcKw0XIB6Ta0sSpPmrM6FHMI/TCwAkPYR+1HwfNGx1DRj1zu6KfJCrA3SVhxXg
         3GT7oV+4fLsKbGeRbAg3PxA9pkzwuOb3F4VftZFbcu1uEbP/SviY9uN7km5SLQeqQAAe
         eR+NrU3iYuMGSSEm/ZuUkdR+Ak75KidHk+UeVhQVSmIi/X1wjfoyf6um4Z6wkMWZeGar
         +e5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8oWoFgR+oG2XStLsHzsG1slEjiv03yjrr79sBLjQ3w4=;
        b=PJBMJ6YMZ6OglfEYUBPwGMbixWZapf4b/Da8u5r/wSMl3VB1Z1UO6+NxTI8pTgym2k
         LoTAM58QtHoKlWjU3+tvZh3KQC9r6WKJg57K7UTC8uyAeZrmcjH5kba9q717EVSgpJoz
         XUH0uUbX9GydZKihqMHb5rfzGxUjMMYa+z/M5/MMuQ6ZyFVJo/FVBKXsKZree1yjXHDk
         ePN55whuxfptyOzhKTAgrgFWyzA8+L2k8hsUPIg3euJr/sLElT80oVlYUFbGPrl4ouO0
         p5XifLMwZHjwIazrYQ24kbiLqk/AeAGX4zWLrjo6t43eBz2PJW614k99l1d2Pzuw2vcZ
         kiyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FjAqSfZW;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8oWoFgR+oG2XStLsHzsG1slEjiv03yjrr79sBLjQ3w4=;
        b=lFAFBJtJkDR4VE+ZNZq1s0UdpFIxLEzQPlFiKhvtNJhyiooBx5FZNKduh4FaCbC3Ca
         /emiLLUnbi10cu7qRX9lejfMBikEjPSkzbhW6PuXnuGpUUFm2+y8lfdEAh3knqBTuTDO
         ysg4U9vOdlnBYQIAnkiNOtZVkim49fGfPO664zkFdGVolrFDPxiLXXIMTs0AfOEOmlxx
         Cf+75Vqury7LNcHoE1VnO+JKcD1ow7hPJ4kmi1xK4W4qsIRxMsAtbIlHJ3783dCoJrT9
         9MsX1KkwgYG4CX2fk/QEKccDvtiuPj6Zt9/eQjS1yaGagLBnUaxSVu+09+GQ2zQit/9v
         8czg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8oWoFgR+oG2XStLsHzsG1slEjiv03yjrr79sBLjQ3w4=;
        b=C2L3wx/GBFlkEYznRkPib/hVdDvcdT/Lb3gNV2v/4FrtPZ6e+Jvc725Tk0DN4VE8HF
         0A51fMR22CZ6d0rMb5YuSoefJIe+iZMx7aI5gaA9YIbXzDoa+7tLgJ5Qjxc/TSeuBpvZ
         I3FHRQy6FsHoRybY3eRs8oaIO/mzCiqw6RCNQFtdDktmJ8pCrfI3tXcgHPOuyuZ4Z7KS
         Ka07twd3LavEAiS9v4nU4rsGOLYgh6JwYO7/KbP1Lh1L5gP5ljlGWg14UNAxP0INcX7B
         JKM59GbawHoKGg6Xwyvlx0Rjsskn+BMpo7HDkgnNEEIxVxMbNsV5HGsd8oScsdd023Rz
         TuSg==
X-Gm-Message-State: APjAAAW/2vjqjoFqnxLTwSUzYJdSYCxmAEGPXQab6DQAO/Vhi73cxiEY
	97Cm3N6XUlwDNcXkgGinaHY=
X-Google-Smtp-Source: APXvYqzT1BPL0Y7lKSc2oUl83Q5Ifod0mcmhWbQAGkQDjZM410+fH/+n1WnRYeD5eO9e7HqCjLXSWA==
X-Received: by 2002:a17:90a:c982:: with SMTP id w2mr8729963pjt.125.1575545829634;
        Thu, 05 Dec 2019 03:37:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f8d:: with SMTP id 13ls732494pjz.0.gmail; Thu, 05
 Dec 2019 03:37:09 -0800 (PST)
X-Received: by 2002:a17:90a:e98d:: with SMTP id v13mr8845873pjy.107.1575545829298;
        Thu, 05 Dec 2019 03:37:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575545829; cv=none;
        d=google.com; s=arc-20160816;
        b=GVFxIoBJe84lg5QkLrTnib3LAG0VE0gEKLlhywW/pJdWaXDQD5SVrtcJEuZIFvobIM
         H4GUB1KCrZRFdvmjfGpRNkd6Xn4RpgTk0gOnryZV76i1tt0Ss0P4sbDM127UCt802nqH
         Lrb0nZElaG42WFBUn4EBIf7oHlRqhlL6J94SyiNymnNsVyZViSojZPfMQ7FNlHzQD4H0
         /iGn+xNcLT0nqNCdi6TxV1mZK37b2bjitb8lX/bUe/eRKAP+ZgnOd9xryKem6u3b0GiY
         I98Q9dP5LK9CyiZVIE9HLkmE/kaEyaWO/pRLhc/mI9FeUMbi4+/JUVNx5LrpK0ygEtM8
         ukog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TfYIZA1x1hWCQA6g7oQ19DH7tEX6ualy3pbm/P3Lk+A=;
        b=uifb+CvfvCM6nLbLRQYelJ3mC9HeE2K0oL5cbbphBVB7RXryr8LG+HSfW4XnG1cahk
         UV5fFHmYUNNcwTdFmX104kybghiQh7gyAmOlC4Q9QOrdkyjAWcrrTeJqa7VCXculd2c1
         1UgtCSO3nNJXVHJaOF92A/RrmWFq33dpbAqGyOPu+k4r+JTd5uU4AmwXucKBorZUh7qn
         LFZaqjLn22Ts8YNkh4uyoQ2+h8pi7Glz2MCklXjLkQy7tuSl3yfpsr4Yxn5BpMwHgJtO
         V/ryCw7Qd6au6Gp7gvkEc0LN2LUQZxtBES3RvKEF4lDydceirU6YBt3LZVlR2YtzUlXE
         qb4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FjAqSfZW;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id t34si26765pjb.3.2019.12.05.03.37.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Dec 2019 03:37:09 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id d5so3253215qto.0
        for <kasan-dev@googlegroups.com>; Thu, 05 Dec 2019 03:37:09 -0800 (PST)
X-Received: by 2002:ac8:ccf:: with SMTP id o15mr7086616qti.380.1575545828141;
 Thu, 05 Dec 2019 03:37:08 -0800 (PST)
MIME-Version: 1.0
References: <0000000000003e640e0598e7abc3@google.com> <41c082f5-5d22-d398-3bdd-3f4bf69d7ea3@redhat.com>
 <CACT4Y+bCHOCLYF+TW062n8+tqfK9vizaRvyjUXNPdneciq0Ahg@mail.gmail.com>
 <f4db22f2-53a3-68ed-0f85-9f4541530f5d@redhat.com> <397ad276-ee2b-3883-9ed4-b5b1a2f8cf67@i-love.sakura.ne.jp>
In-Reply-To: <397ad276-ee2b-3883-9ed4-b5b1a2f8cf67@i-love.sakura.ne.jp>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Dec 2019 12:36:56 +0100
Message-ID: <CACT4Y+bUkzJAezH9Pk=c1amtzO0-r1Hcn3WmDuS+Drn-R3GAQA@mail.gmail.com>
Subject: Re: KASAN: slab-out-of-bounds Read in fbcon_get_font
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Paolo Bonzini <pbonzini@redhat.com>, 
	syzbot <syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>, Daniel Thompson <daniel.thompson@linaro.org>, 
	Daniel Vetter <daniel.vetter@ffwll.ch>, DRI <dri-devel@lists.freedesktop.org>, 
	ghalat@redhat.com, Gleb Natapov <gleb@kernel.org>, gwshan@linux.vnet.ibm.com, 
	"H. Peter Anvin" <hpa@zytor.com>, James Morris <jmorris@namei.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, KVM list <kvm@vger.kernel.org>, 
	Linux Fbdev development list <linux-fbdev@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-security-module <linux-security-module@vger.kernel.org>, 
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, Russell Currey <ruscur@russell.cc>, Sam Ravnborg <sam@ravnborg.org>, 
	"Serge E. Hallyn" <serge@hallyn.com>, stewart@linux.vnet.ibm.com, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FjAqSfZW;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Thu, Dec 5, 2019 at 11:41 AM Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> On 2019/12/05 19:22, Paolo Bonzini wrote:
> > Ah, and because the machine is a KVM guest, kvm_wait appears in a lot of
> > backtrace and I get to share syzkaller's joy every time. :)
> >
> > This bisect result is bogus, though Tetsuo found the bug anyway.
> > Perhaps you can exclude commits that only touch architectures other than
> > x86?
> >
>
> It would be nice if coverage functionality can extract filenames in the source
> code and supply the list of filenames as arguments for bisect operation.
>
> Also, (unrelated but) it would be nice if we can have "make yes2modconfig"
> target which converts CONFIG_FOO=y to CONFIG_FOO=m if FOO is tristate.
> syzbot is testing kernel configs close to "make allyesconfig" but I want to
> save kernel rebuild time by disabling unrelated functionality when manually
> "debug printk()ing" kernels.

I thought that maybe sed "s#=y#=m#g" && make olddefconfig will do, but
unfortunately, it turns off non-tristate configs...

$ egrep "CONFIG_MEMORY_HOTPLUG|CONFIG_TCP_CONG_DCTCP" .config
CONFIG_MEMORY_HOTPLUG=y
CONFIG_TCP_CONG_DCTCP=y
# sed -i "s/CONFIG_MEMORY_HOTPLUG=y/CONFIG_MEMORY_HOTPLUG=m/g" .config
# sed -i "s/CONFIG_TCP_CONG_DCTCP=y/CONFIG_TCP_CONG_DCTCP=m/g" .config
# egrep "CONFIG_MEMORY_HOTPLUG|CONFIG_TCP_CONG_DCTCP" .config
CONFIG_MEMORY_HOTPLUG=m
CONFIG_TCP_CONG_DCTCP=m
# make olddefconfig
# egrep "CONFIG_MEMORY_HOTPLUG|CONFIG_TCP_CONG_DCTCP" .config
# CONFIG_MEMORY_HOTPLUG is not set
CONFIG_TCP_CONG_DCTCP=m

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbUkzJAezH9Pk%3Dc1amtzO0-r1Hcn3WmDuS%2BDrn-R3GAQA%40mail.gmail.com.
