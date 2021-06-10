Return-Path: <kasan-dev+bncBCF5XGNWYQBRBJUNRGDAMGQECQCQONY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id C21483A31B0
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 19:06:47 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id q3-20020aa784230000b02902ea311f25e2sf1677573pfn.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 10:06:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623344806; cv=pass;
        d=google.com; s=arc-20160816;
        b=bKxO5+KgPAJE6xDM6ZOcvssTrneH/0dSWRrRJY07BV1iPvBEx6eiRaUpm9VUQX8Kfm
         An6fIM66N2IJy5oWSz9XsbFudmfZ7sKnbhjAcU4BSQdAs62Z67ehIW17Tbb99qGjZvLU
         sAs7XRbMXxgKni1tNdR3mNHGS8DPCIXYpzZB4Am/U292oMEBxShztlAT9uZ8eQ1DT83q
         T6q8s125vVylWb3EwnlExcFI7QGuWVQPcOb3JgzbxsqppwE3ABIk381OsWdUvUE1AhHj
         h4h5aYabF4PGrOGxC8G4MBhGIFqFXuny9Pp6hDekW8Anz+E/30eXApRxoT08tfG6wPbO
         GyoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/7e6nw5tWNRpJs/Fiv15Y5U/aH+6QZON3jPaLmefueM=;
        b=nFLa9Xp1E4L/cpctwPJR+EiBWSmL00H4+KeHB0H/TnKwi4DYUX3X3P+3zHjbP/91qc
         XbY4duB7awiq9XeDLcJMGYOGK9IcAeqBxZgoeOMIvyKji9N+/7KtaeB14cA3xZTnaV8y
         waYxpiwaWqnmrUye5pfVvTXJapn8H75Cb/cnl+IlxNH1RSXc08D0Bs8VGU3fX2ssWzVn
         AtYvEY+cHHG7FqHglcKWq1dbJcQkRlRj5a1lCPcxcdNSxxXPig11Ub5Y/nJavZkOgVVR
         EN9r4dXaQUl7o7QGk+HevBAiEPaf6Ylp5i5+jmihbq5kEnxqHTArMslOM+ajLE8dxw0o
         56YQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BQ5qUY22;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/7e6nw5tWNRpJs/Fiv15Y5U/aH+6QZON3jPaLmefueM=;
        b=AueJzRGH9hhPBx0SjGJiUDYQRVCaJVxk8qyv6vvEwTwsNYfrkqK/TfqVZCpI7ISo6b
         cpwKGH5xJmPEA4ByCwCXfMlpjo+8MNkVXu0ZNrwKCMruSgsz6kNQFoMdDV+J+S+qseDr
         OBhw/Ch1xZG222+/VyTL0j8T2gxf7kybDdFIp8dKfnYopA31F3U8jNeHB6vFuJTw2mVV
         Tq15TbuMobXbDq5sSZ8SyUoK6ageVgISh/3z/apryCHqV1hwf37OPpTkFRpgvGAkKcYd
         XvlJuuvTi5TeKLx0gsO0YEmOq3lQvaxR1wQRPd9fTw9seMrphwiDjn+qQ5zwuwKTBpX+
         jQqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/7e6nw5tWNRpJs/Fiv15Y5U/aH+6QZON3jPaLmefueM=;
        b=A28k1AAHaQ9d1BhQUGiheycd0/8DNBCPqcKBNcU2cAKrYMQj8GdogOgkO+3wflSXDT
         wMlyNAqSeGBkYm4nxdHp4ev1wBrzicJKmGqwYdvgvfqqAC/zKvHIGT6f3mvqhdueje8b
         FhHf413EBYS4Ir0vHasvmT+FGvnNrQxmlBgQLBORkqykycUBnITbNz32+f8bhXosFROU
         Ib6Oe9gDyTYDmFzZrXHKjrYDKz681hkakoMI1LwQv7Nm0dPB1tGXuRH32L7wRkQZItMc
         Ohumkmn/zxXMmGdIRFXBXLZH59z8xwVgI5tHqvRDT4h27KPPWjEo7FdT1ctLyrCuwYIS
         5jSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530CWzcAaktYWsKe0+ePtnnCK1DG8k6k+AtUU8ADV50aRu319B1A
	O/ONYBc4VOWL95446ownKZI=
X-Google-Smtp-Source: ABdhPJyoO6Ome5ZbDZF2VYNbgUDnKQQ+TGZNOfIQ+WTd8ReUeGmIAyvHt85CDi/OHI1gjzTZvQ0YNg==
X-Received: by 2002:aa7:9af6:0:b029:2e9:dfed:6a59 with SMTP id y22-20020aa79af60000b02902e9dfed6a59mr3916984pfp.37.1623344806109;
        Thu, 10 Jun 2021 10:06:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b708:: with SMTP id d8ls3822391pls.3.gmail; Thu, 10
 Jun 2021 10:06:45 -0700 (PDT)
X-Received: by 2002:a17:902:7c03:b029:f0:bbde:fc1e with SMTP id x3-20020a1709027c03b02900f0bbdefc1emr5628032pll.57.1623344805569;
        Thu, 10 Jun 2021 10:06:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623344805; cv=none;
        d=google.com; s=arc-20160816;
        b=EvxcwO0ckUgduR8Lvc+EZSQe4d8aQjXiZU7d8x7GjjiTl5FmbU/xCOAljATsv3Nzyz
         TMI65fAq8hj5sQBGZCA53tAQG1uaBX/sIDDtNF/qipvjGJ+JbKWlEwJggCMaaFkNdpLZ
         HFIZMosNybyR4uNzAkc2YxRjtQI1+vWgJ+w7Bi6ieoT5govQBpSRSQrunWT1T1NUhyLL
         TEJyWX1ygURB9bWIUGbxOt2/3/zWYzcBbWYWCI9m1iPhfsOg7A6k7ZqOxrlrbXlRWBfD
         3uj7sLqoEEbUyuGgq33I0e7PHFVexs9d3G47qWcFJFbGg5rZSfUWq+SxmDI1oY61cds9
         IXbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Tf6j48/EA7psoQT0Xa+Ykp/HBTN3iYdEAaBd6YZtNzA=;
        b=o702W8Aaxsrl2z8ETHzGfbP6feoUl7ZWVXXvcDvEJkmf84bl9VmVekcI+f8qFrf5wo
         I79Insk9Da7TG8lUETWgfnZjCmNb2ydMxzs3b0CucF0SIRjVCcaYA0I6Pu/gVp/HjBuL
         IbB8/3SLfx+bhLVAhHrDjy/mq1kmdLyuXCHJOeL1hg4fXvoqI6H5GFeu2P1siVKMTyQU
         THvQVFyMxwjSAK7oCYKN+fgwBW6i+SNG6S5dhuWwPmwpVLtqr6l1vkbba8NmzNUXTJtO
         8DQmY5Iqol6LmeQ0cUctqVPGy6IzjiYYcTtjTWXALVnku2eNdsCDgJhalIGeH15zA9mG
         jDWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=BQ5qUY22;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id d123si346145pfa.2.2021.06.10.10.06.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Jun 2021 10:06:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id y15so2152621pfl.4
        for <kasan-dev@googlegroups.com>; Thu, 10 Jun 2021 10:06:45 -0700 (PDT)
X-Received: by 2002:a63:5d66:: with SMTP id o38mr5923418pgm.444.1623344804696;
        Thu, 10 Jun 2021 10:06:44 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id k25sm2852989pfk.33.2021.06.10.10.06.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jun 2021 10:06:43 -0700 (PDT)
Date: Thu, 10 Jun 2021 10:06:42 -0700
From: Kees Cook <keescook@chromium.org>
To: Yonghong Song <yhs@fb.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexei Starovoitov <alexei.starovoitov@gmail.com>,
	Kurt Manucredo <fuzzybritches0@gmail.com>,
	syzbot+bed360704c521841c85d@syzkaller.appspotmail.com,
	Andrii Nakryiko <andrii@kernel.org>,
	Alexei Starovoitov <ast@kernel.org>, bpf <bpf@vger.kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	"David S. Miller" <davem@davemloft.net>,
	Jesper Dangaard Brouer <hawk@kernel.org>,
	John Fastabend <john.fastabend@gmail.com>,
	Martin KaFai Lau <kafai@fb.com>, KP Singh <kpsingh@kernel.org>,
	Jakub Kicinski <kuba@kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Network Development <netdev@vger.kernel.org>,
	Song Liu <songliubraving@fb.com>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, nathan@kernel.org,
	Nick Desaulniers <ndesaulniers@google.com>,
	Clang-Built-Linux ML <clang-built-linux@googlegroups.com>,
	linux-kernel-mentees@lists.linuxfoundation.org,
	Shuah Khan <skhan@linuxfoundation.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Kernel Hardening <kernel-hardening@lists.openwall.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v4] bpf: core: fix shift-out-of-bounds in ___bpf_prog_run
Message-ID: <202106101002.DF8C7EF@keescook>
References: <20210602212726.7-1-fuzzybritches0@gmail.com>
 <YLhd8BL3HGItbXmx@kroah.com>
 <87609-531187-curtm@phaethon>
 <6a392b66-6f26-4532-d25f-6b09770ce366@fb.com>
 <CAADnVQKexxZQw0yK_7rmFOdaYabaFpi2EmF6RGs5bXvFHtUQaA@mail.gmail.com>
 <CACT4Y+b=si6NCx=nRHKm_pziXnVMmLo-eSuRajsxmx5+Hy_ycg@mail.gmail.com>
 <202106091119.84A88B6FE7@keescook>
 <752cb1ad-a0b1-92b7-4c49-bbb42fdecdbe@fb.com>
 <CACT4Y+a592rxFmNgJgk2zwqBE8EqW1ey9SjF_-U3z6gt3Yc=oA@mail.gmail.com>
 <1aaa2408-94b9-a1e6-beff-7523b66fe73d@fb.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1aaa2408-94b9-a1e6-beff-7523b66fe73d@fb.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=BQ5qUY22;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, Jun 09, 2021 at 11:06:31PM -0700, Yonghong Song wrote:
> 
> 
> On 6/9/21 10:32 PM, Dmitry Vyukov wrote:
> > On Thu, Jun 10, 2021 at 1:40 AM Yonghong Song <yhs@fb.com> wrote:
> > > On 6/9/21 11:20 AM, Kees Cook wrote:
> > > > On Mon, Jun 07, 2021 at 09:38:43AM +0200, 'Dmitry Vyukov' via Clang Built Linux wrote:
> > > > > On Sat, Jun 5, 2021 at 9:10 PM Alexei Starovoitov
> > > > > <alexei.starovoitov@gmail.com> wrote:
> > > > > > On Sat, Jun 5, 2021 at 10:55 AM Yonghong Song <yhs@fb.com> wrote:
> > > > > > > On 6/5/21 8:01 AM, Kurt Manucredo wrote:
> > > > > > > > Syzbot detects a shift-out-of-bounds in ___bpf_prog_run()
> > > > > > > > kernel/bpf/core.c:1414:2.
> > > > > > > [...]
> > > > > > > 
> > > > > > > I think this is what happens. For the above case, we simply
> > > > > > > marks the dst reg as unknown and didn't fail verification.
> > > > > > > So later on at runtime, the shift optimization will have wrong
> > > > > > > shift value (> 31/64). Please correct me if this is not right
> > > > > > > analysis. As I mentioned in the early please write detailed
> > > > > > > analysis in commit log.
> > > > > > 
> > > > > > The large shift is not wrong. It's just undefined.
> > > > > > syzbot has to ignore such cases.
> > > > > 
> > > > > Hi Alexei,
> > > > > 
> > > > > The report is produced by KUBSAN. I thought there was an agreement on
> > > > > cleaning up KUBSAN reports from the kernel (the subset enabled on
> > > > > syzbot at least).
> > > > > What exactly cases should KUBSAN ignore?
> > > > > +linux-hardening/kasan-dev for KUBSAN false positive
> > > > 
> > > > Can check_shl_overflow() be used at all? Best to just make things
> > > > readable and compiler-happy, whatever the implementation. :)
> > > 
> > > This is not a compile issue. If the shift amount is a constant,
> > > compiler should have warned and user should fix the warning.
> > > 
> > > This is because user code has
> > > something like
> > >       a << s;
> > > where s is a unknown variable and
> > > verifier just marked the result of a << s as unknown value.
> > > Verifier may not reject the code depending on how a << s result
> > > is used.

Ah, gotcha: it's the BPF code itself that needs to catch it.

> > > If bpf program writer uses check_shl_overflow() or some kind
> > > of checking for shift value and won't do shifting if the
> > > shifting may cause an undefined result, there should not
> > > be any kubsan warning.

Right.

> > I guess the main question: what should happen if a bpf program writer
> > does _not_ use compiler nor check_shl_overflow()?

I think the BPF runtime needs to make such actions defined, instead of
doing a blind shift. It needs to check the size of the shift explicitly
when handling the shift instruction.

> If kubsan is not enabled, everything should work as expected even with
> shl overflow may cause undefined result.
> 
> if kubsan is enabled, the reported shift-out-of-bounds warning
> should be ignored. You could disasm the insn to ensure that
> there indeed exists a potential shl overflow.

Sure, but the point of UBSAN is to find and alert about undefined
behavior, so we still need to fix this.


-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202106101002.DF8C7EF%40keescook.
