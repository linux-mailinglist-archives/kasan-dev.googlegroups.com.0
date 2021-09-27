Return-Path: <kasan-dev+bncBCMIZB7QWENRBTVEY6FAMGQEIKMQPBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AD3E419610
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Sep 2021 16:16:47 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id bl32-20020a05620a1aa000b004330d29d5bfsf73297050qkb.23
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Sep 2021 07:16:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632752206; cv=pass;
        d=google.com; s=arc-20160816;
        b=UlBc0H3xQYUOFKlkqUhiGuWRvs8ACQtWOyRQe6s70t0m5Ez00VBgizHOuKkOY/ZhOI
         JktNB0gTEylnbxjMEIy7kZhNkG7d6lp6f9Mslrxvr4rdG6iRppYWmY1wG2fggclGZ1q+
         mjySPmd1GO91yyed9/Kdd7q6smMoidInwjNsFyBRvVtz04ctRZyz2lPGPbEEC6hPKitH
         YkoXstsHt02Je3PEhkh2UEn3/e/wlmTm1N8ebzfWM/bFAgCq3oHftiW+n1QlnajwniuF
         7wgFzDCvM+Dx02D0B3gjETEQcZ6GBDCnp1ghmim3qWEahjO3J4Vls2F04ZuYhtXVK4UR
         twAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=I4qf0DLBLGzom0Y67a6ctScfOk3N00aKbjnuVFolLIY=;
        b=NVD3vL2Vxhrz0KvcLYJkc0N28ok0RqUH692VwRi/OmsM0gjG85WOLO+ezUVmNslnGH
         Ayw5CrQbm7l0ulXNg+LeGolZHTXDw1KPH+CgWJ1/tybukywjvjASILE/SBsV+GrT5q+p
         TuCLpQjEHmkpZ9xtf8cAJqSAtjinid78ieA5mWpUkp8e2GJ8UsOE2hgMO48n3f0K4BoT
         4YpV4VollEMw4t4KO7+zMXjKZlcqraNfwVhC2ZAJ5+NMCGf1MmDFV2VPZuWlhEc5dtXn
         Aj3TkZRAtKpg8sdxB04iSpuYb4prCCwhEBwtu80DbW/HsYYhE6yMuI/mBE+kUmDOH3c2
         1TBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="tUsn/YgJ";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I4qf0DLBLGzom0Y67a6ctScfOk3N00aKbjnuVFolLIY=;
        b=pNd/qJ8qsF+PcdPEIZLM9EoUVTPeNQKTn0JcUvpG7bMQXY7gk9Gzh+a8XbEX0Jlhdt
         OOGrS3CxKS8Q/1YqbIPte3V05SVp+PqrXkIBTPGM1G4ukEpex3y1xknejDrt5KGFB0UU
         VlKispbYIJ6iah4XaaJRkodoO94JQpqBr8Iyh9kis7neYnjgs5TXEt0QP56joMGxbn36
         pNyAWbclJdy9/+TFfgnel582cQjAQrJL+Rzu7NdVBjQqiLy5SKKMM66hVxZLh6s3Q4r7
         I2T8WdkTmY44o3dYkoxYU4VLPathVwo3nD+8wM3F8VMa/1m1nUKI0QuMIxXeSiqUgMtQ
         uZug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I4qf0DLBLGzom0Y67a6ctScfOk3N00aKbjnuVFolLIY=;
        b=4f27MUHPzFTzbJV9TCElS24AMh0hQ8j59rwtSe3daO36K3nhQEYVw4kds8eFlrAbdQ
         z5lKI83A5Mki3tLltw8h+XZ+NolBIscbUja82P24+Y7s6FGac/tKv2p4EN1XWihi0pz2
         vO0e0eYmVgmYz1bDMgp2m9Tf0MA8yh325I45gKf9RgBrzYclEpeDgKJPW9e/m7abHcKe
         M47uPJKb80eWq4BxgsSSAtUW0mB+pk83Uw+ypiPo8dpLl6eeKFlceRVXCewcXCFUxp6h
         vMMIHDXXtaWa/N+7d5sDdGctAWUa+n5zZGSb+2reZilqhCfIkyLKXzv2kwoNHZyv6Bsw
         vJ6g==
X-Gm-Message-State: AOAM530AvBCb7PD6zbI6l/Wlyhn5QGSHsA9j64Eke0ySkSPQAVcJdthS
	GU+BrVnkxa6s36D12ZuSkDw=
X-Google-Smtp-Source: ABdhPJzNVYS+Wbo5VnwSfLaZpNwNSEsCgej2L9rZg/VVvb3cRD0lUox26dKIwR5sdC9xVAr2bbrDqA==
X-Received: by 2002:a37:444d:: with SMTP id r74mr120815qka.405.1632752206469;
        Mon, 27 Sep 2021 07:16:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:181c:: with SMTP id t28ls9221617qtc.6.gmail; Mon,
 27 Sep 2021 07:16:46 -0700 (PDT)
X-Received: by 2002:ac8:4e4f:: with SMTP id e15mr73249qtw.186.1632752205979;
        Mon, 27 Sep 2021 07:16:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632752205; cv=none;
        d=google.com; s=arc-20160816;
        b=pfn6VjZU9XDmIUbDsYdLtzBiAWowOGFiHMhVAVBcjuG+bBe/NKagLadHW4iPeYFA1m
         x8SRO1X+hUHHzxZp5WFBcsdXd/31M6RAPcQcOOahRpijAlkhuEkXvYMzrmGSxbpWduyf
         gD4Bq8hqYBPuH9ryGb2+0atuZnrkrMlZ9+qj0xapunRJEe38kgb2r7y4E2og3NE9qiq8
         ddU096mIZlEmMVYRhOGvQUD7dF+Ka+Qd2dRHN8uymvq/UUbXzha9zSB+IQr8uEnMNz/H
         GyvjkkPIyxWFzYaUmC0Zow9TNNoslOfiuqEmMMOeNy7bvK1UWOpsRHut4Neb/zf1OpFQ
         /I4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qTD1IG+YmWnt3+MCGA1ZnJmy0L2DQARzYfapPSB4ZVc=;
        b=U6wH9FKlu3MM8sXvafDNzFzaO7e/YDC3vCBsoqmUW9/eat5thCGhLHb2z9ZAWrK6dZ
         IlDvU7Rde1sKbT+u1t3M9Jf8bW7mLHNs+d1hjkbuegGgoHX4Wh598T8Q3ike9z4ItpdE
         yFZ1MNNdWvtSQ43SDudE3PVp8wFFnHshRndWJGKXRZFFa1wB8tbmrraZCzW2HZqgHdD3
         UZI3uKZcZvk6/6Mv9Cgv01bewRLF53OuGwZ3RfcITqxUmvpkmPMcv157uEvMFJQAj9yN
         dZKFgbeV/OVWJW+LwmHfy+dAXzy/EdY+vjiUU63P801NmiTkZMTkcJbrK5FUCf/Exk6r
         BSwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="tUsn/YgJ";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x236.google.com (mail-oi1-x236.google.com. [2607:f8b0:4864:20::236])
        by gmr-mx.google.com with ESMTPS id n27si886060qtl.4.2021.09.27.07.16.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Sep 2021 07:16:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::236 as permitted sender) client-ip=2607:f8b0:4864:20::236;
Received: by mail-oi1-x236.google.com with SMTP id s24so23161849oij.8
        for <kasan-dev@googlegroups.com>; Mon, 27 Sep 2021 07:16:45 -0700 (PDT)
X-Received: by 2002:aca:3083:: with SMTP id w125mr110205oiw.109.1632752205257;
 Mon, 27 Sep 2021 07:16:45 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000d6b66705cb2fffd4@google.com> <CACT4Y+ZByJ71QfYHTByWaeCqZFxYfp8W8oyrK0baNaSJMDzoUw@mail.gmail.com>
 <CANpmjNMq=2zjDYJgGvHcsjnPNOpR=nj-gQ43hk2mJga0ES+wzQ@mail.gmail.com>
 <CACT4Y+Y1c-kRk83M-qiFY40its+bP3=oOJwsbSrip5AB4vBnYA@mail.gmail.com> <YUpr8Vu8xqCDwkE8@google.com>
In-Reply-To: <YUpr8Vu8xqCDwkE8@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 27 Sep 2021 16:16:33 +0200
Message-ID: <CACT4Y+YuX3sVQ5eHYzDJOtenHhYQqRsQZWJ9nR0sgq3s64R=DA@mail.gmail.com>
Subject: Re: [syzbot] upstream test error: KFENCE: use-after-free in kvm_fastop_exception
To: Sean Christopherson <seanjc@google.com>
Cc: Marco Elver <elver@google.com>, 
	syzbot <syzbot+d08efd12a2905a344291@syzkaller.appspotmail.com>, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, 
	syzkaller-bugs@googlegroups.com, viro@zeniv.linux.org.uk, 
	"the arch/x86 maintainers" <x86@kernel.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="tUsn/YgJ";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::236
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

On Wed, 22 Sept 2021 at 01:34, 'Sean Christopherson' via
syzkaller-bugs <syzkaller-bugs@googlegroups.com> wrote:
>
> On Fri, Sep 17, 2021, Dmitry Vyukov wrote:
> > On Fri, 17 Sept 2021 at 13:04, Marco Elver <elver@google.com> wrote:
> > > > So it looks like in both cases the top fault frame is just wrong. But
> > > > I would assume it's extracted by arch-dependent code, so it's
> > > > suspicious that it affects both x86 and arm64...
> > > >
> > > > Any ideas what's happening?
> > >
> > > My suspicion for the x86 case is that kvm_fastop_exception is related
> > > to instruction emulation and the fault occurs in an emulated
> > > instruction?
> >
> > Why would the kernel emulate a plain MOV?
> > 2a:   4c 8b 21                mov    (%rcx),%r12
> >
> > And it would also mean a broken unwind because the emulated
> > instruction is in __d_lookup, so it should be in the stack trace.
>
> kvm_fastop_exception is a red herring.  It's indeed related to emulation, and
> while MOV emulation is common in KVM, that emulation is for KVM guests not for
> the host kernel where this splat occurs (ignoring the fact that the "host" is
> itself a guest).
>
> kvm_fastop_exception is out-of-line fixup, and certainly shouldn't be reachable
> via d_lookup.  It's also two instruction, XOR+RET, neither of which are in the
> code stream.
>
> IIRC, the unwinder gets confused when given an IP that's in out-of-line code,
> e.g. exception fixup like this.  If you really want to find out what code blew
> up, you might be able to objdump -D the kernel and search for unique, matching
> disassembly, e.g. find "jmpq   0xf86d288c" and go from there.

Hi Sean,

Thanks for the info.

I don't want to find out what code blew (it's __d_lookup).
I am interested in getting the unwinder fixed to output truthful and
useful frames.
Is there more info on this "the unwinder gets confused"? Bug filed
somewhere or an email thread? Is it on anybody's radar?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYuX3sVQ5eHYzDJOtenHhYQqRsQZWJ9nR0sgq3s64R%3DDA%40mail.gmail.com.
