Return-Path: <kasan-dev+bncBCAIHYNQQ4IRBXOYY6FAMGQELHJDCKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 53775419887
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Sep 2021 18:07:59 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id g8-20020a05660203c800b005d58875129esf22381719iov.2
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Sep 2021 09:07:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632758877; cv=pass;
        d=google.com; s=arc-20160816;
        b=qY0q9RufaL/tDbiWn3HNhnFhDUNwbruwmti1PHHXPKlNvC2cem1Etcmc46Pz98llsY
         Mruh4RI+hjwaqgbE9ezh4yjTZUcKaFjwRKM7NN6DveVrO++Tw+YjI8IVHjrLq2rblPMI
         O6D9Kggtiv12a/GxWgPiYDn5fjRjxHAHUn379IdvtRWIJXckox6c63I16akL+41Y73Jn
         GeGzIt00mr8HX6vXd7eDP65DG+QEnRf9Ee75cQuUobtGBgRJN1mZ9dG/V+DDolrxFXzT
         5nly0LC8uGs+I0JAE4ZYSdhlLvctf4jdA8UP1me5pxFWul20W0EkxtD7smWE3PpnZ89o
         AmNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=nmUMZ2kngpm0h6QRxwAx8189UBX5gquSTUvFf+oWYZA=;
        b=doHW4z9+Ujt/5dDVlJprTdCck9xXemd1fgYslddLV9GuOx1K3UPMDKhpgNvbX6w1CR
         LYKg8fFKSe9WDnbAMkdVat9rZph2Pi4nblqMQPWaYReTplsfjxp+fnjnavhE7WIpv+pC
         aoPipltuE5JWXI4oqI/67efnWkhAhCFec/pKretUBuOWMeqqny63nojEPIvfxWFaOXnt
         NqnkO5vUk+VugARcQC3WpAP8cWiTpo/ELplxTLQJBy2V35q5dSKRItfvYdXSvT4fIL5b
         kHbIgOx1YDzsZlV6TBdySk4pK9oUVoGsc0Yu37hIEk+NoLu2Wx2XSXsUatsh8CnREEYX
         9cjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=T7xGNAbI;
       spf=pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=seanjc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=nmUMZ2kngpm0h6QRxwAx8189UBX5gquSTUvFf+oWYZA=;
        b=etN+EiJge5X+gDG3N1WoAD8+swSEF3gyQXJA0wRsnyoRWYM6Up7DGqlCa7EhJA70VY
         ELz/BOi4fz96FLe6zc8uV82WUN72xkobcz/8zDZcL7ocosYeY+VjUjJ9OBfn3swRTyZ2
         3NZDFVVrXH67NVxYFCj0+v4QolelJppg2sjEQt9ndIA45SjcUVYZPvCYZOghJMQcIXK5
         soIF6pogBq0xxTpbPveBfC6QI1RZKH89isjG2X+HO7+BTGeNtAjRimUe0PR8KqpIbvee
         sEmzhVUA2dIsLMgYtv/GO34bxVYi/5Pg92SHOWWZfV1FSB2Xfq4Zvzu60u8nIBYHvZXG
         Qc8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nmUMZ2kngpm0h6QRxwAx8189UBX5gquSTUvFf+oWYZA=;
        b=NASGypnp3zxic0/JL+v/++/5z3L2kjic3OyTEMhPuElfzyeTtQDqFgipUOIO/ZORmY
         U7uog5z70bbZwENsPKzoJDkGBBImg2CO5DjBy7iIZIk7OfC2YT1H578rWbfJDcaPvjd3
         TA4+zoZSogQYOa9Slpp0jTvLeS/n+in/yAQWt8bvmOlx1z8wFL8Tx0KINKczSMyrONT4
         T1DlT9sIWuTju4TWjDluRssrucgpYvyKzZZpD1QSvFzmIfFYPmgpZFM3cfnA1gfjfbaz
         9a2UEGu//m6fF0FV4KXh8K/lbRYIBU6G8MfAGLA0xUqys/agksPoxE1SZOgpti7XQrlF
         vOmQ==
X-Gm-Message-State: AOAM530uxMYxGFEM+utHQcwN17AZGBIWA6Vb1Bd6Rdo/okk2a9qwpEjw
	izLUOTtfPgpJd9FVHMbd3u8=
X-Google-Smtp-Source: ABdhPJzGgQPx74q5+hmV1hUth1FD3XhalOMZSXQ4908quTXi4xj0rKrEKBiPeiTtIUeJ7lTrad572g==
X-Received: by 2002:a92:d5c5:: with SMTP id d5mr662295ilq.36.1632758877751;
        Mon, 27 Sep 2021 09:07:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:741b:: with SMTP id o27ls2743343jac.10.gmail; Mon, 27
 Sep 2021 09:07:57 -0700 (PDT)
X-Received: by 2002:a02:cf39:: with SMTP id s25mr645920jar.40.1632758877390;
        Mon, 27 Sep 2021 09:07:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632758877; cv=none;
        d=google.com; s=arc-20160816;
        b=oXyYAfvjvPEQSxtFbXC9OFcUjnOWSPWVS/E3ZeWlUA1CF/WPb6Fks4ZzREVidCO27y
         fbjhSTYFKY4t1BXSvR3fXXNfD3edquw7KoJlTFVUfyAd+aGBGwj5Pd3dshPyY6KCnZmF
         0bGUThkFKIbK8u4oIQ9upHFyrve0H96S82WmcqDWzy/VzuDCF+CrUQD1oAuORxjb9qcW
         YbwdHJACkwtPuKVydf/W47igTKiuGIEeZ2771GOsmEUJp0Qq8dWiDmUP4F8NKK0byNRY
         yWiGl5m2c1+w+esFeSK/oad+zKdQeFjrEUDNLS8qTvOO+SIRNBOmCBwiqzV4kbTYH/xe
         7v7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=CBaIVDF4UN9VVYwJROukTIUHRk1VcAmSIyvI/1GuY6U=;
        b=Wx/toBldpxt4FWjYTTYe7JV+r45Wu27JN3dM218D+YK9uf4WExemGKR/W/YJ82zf3E
         OyJGDv+xq/P2u6PylW0/HFUkzgLnJfN2ySLZwLQgOOfbHp3AvxDw6B4EDgmz29DRw5lK
         lHEYFvI2Rbrdw0hOxO0/dHf1huUA//xaZETt0KJ/nbE2gNPByPzliow8zI9AgYbajyui
         0DyFFX+QKOKMtr30Mc4CcuCQtBZcANXJz7pxPb41Hig07UqrIeKLMaJO7Bh7ultHfQG6
         p0g7WyiHE46PvYzHxGcpl+s30NMNs3htbLdcTkBq9SEce0c2mJPNqUhBnPFSyIbexj9a
         8KWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=T7xGNAbI;
       spf=pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=seanjc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id p14si368193iol.1.2021.09.27.09.07.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Sep 2021 09:07:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id t9so4060151pju.5
        for <kasan-dev@googlegroups.com>; Mon, 27 Sep 2021 09:07:57 -0700 (PDT)
X-Received: by 2002:a17:90a:ca96:: with SMTP id y22mr9642043pjt.115.1632758876549;
        Mon, 27 Sep 2021 09:07:56 -0700 (PDT)
Received: from google.com (157.214.185.35.bc.googleusercontent.com. [35.185.214.157])
        by smtp.gmail.com with ESMTPSA id i2sm16110859pfa.34.2021.09.27.09.07.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 27 Sep 2021 09:07:55 -0700 (PDT)
Date: Mon, 27 Sep 2021 16:07:51 +0000
From: "'Sean Christopherson' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>,
	syzbot <syzbot+d08efd12a2905a344291@syzkaller.appspotmail.com>,
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org,
	syzkaller-bugs@googlegroups.com, viro@zeniv.linux.org.uk,
	the arch/x86 maintainers <x86@kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [syzbot] upstream test error: KFENCE: use-after-free in
 kvm_fastop_exception
Message-ID: <YVHsV+o7Ez/+arUp@google.com>
References: <000000000000d6b66705cb2fffd4@google.com>
 <CACT4Y+ZByJ71QfYHTByWaeCqZFxYfp8W8oyrK0baNaSJMDzoUw@mail.gmail.com>
 <CANpmjNMq=2zjDYJgGvHcsjnPNOpR=nj-gQ43hk2mJga0ES+wzQ@mail.gmail.com>
 <CACT4Y+Y1c-kRk83M-qiFY40its+bP3=oOJwsbSrip5AB4vBnYA@mail.gmail.com>
 <YUpr8Vu8xqCDwkE8@google.com>
 <CACT4Y+YuX3sVQ5eHYzDJOtenHhYQqRsQZWJ9nR0sgq3s64R=DA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+YuX3sVQ5eHYzDJOtenHhYQqRsQZWJ9nR0sgq3s64R=DA@mail.gmail.com>
X-Original-Sender: seanjc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=T7xGNAbI;       spf=pass
 (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::102f
 as permitted sender) smtp.mailfrom=seanjc@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Sean Christopherson <seanjc@google.com>
Reply-To: Sean Christopherson <seanjc@google.com>
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

+Josh and PeterZ

On Mon, Sep 27, 2021, Dmitry Vyukov wrote:
> On Wed, 22 Sept 2021 at 01:34, 'Sean Christopherson' via
> syzkaller-bugs <syzkaller-bugs@googlegroups.com> wrote:
> >
> > On Fri, Sep 17, 2021, Dmitry Vyukov wrote:
> > > On Fri, 17 Sept 2021 at 13:04, Marco Elver <elver@google.com> wrote:
> > > > > So it looks like in both cases the top fault frame is just wrong. But
> > > > > I would assume it's extracted by arch-dependent code, so it's
> > > > > suspicious that it affects both x86 and arm64...
> > > > >
> > > > > Any ideas what's happening?
> > > >
> > > > My suspicion for the x86 case is that kvm_fastop_exception is related
> > > > to instruction emulation and the fault occurs in an emulated
> > > > instruction?
> > >
> > > Why would the kernel emulate a plain MOV?
> > > 2a:   4c 8b 21                mov    (%rcx),%r12
> > >
> > > And it would also mean a broken unwind because the emulated
> > > instruction is in __d_lookup, so it should be in the stack trace.
> >
> > kvm_fastop_exception is a red herring.  It's indeed related to emulation, and
> > while MOV emulation is common in KVM, that emulation is for KVM guests not for
> > the host kernel where this splat occurs (ignoring the fact that the "host" is
> > itself a guest).
> >
> > kvm_fastop_exception is out-of-line fixup, and certainly shouldn't be reachable
> > via d_lookup.  It's also two instruction, XOR+RET, neither of which are in the
> > code stream.
> >
> > IIRC, the unwinder gets confused when given an IP that's in out-of-line code,
> > e.g. exception fixup like this.  If you really want to find out what code blew
> > up, you might be able to objdump -D the kernel and search for unique, matching
> > disassembly, e.g. find "jmpq   0xf86d288c" and go from there.
> 
> Hi Sean,
> 
> Thanks for the info.
> 
> I don't want to find out what code blew (it's __d_lookup).
> I am interested in getting the unwinder fixed to output truthful and
> useful frames.

I was asking about the exact location to confirm that the explosion is indeed
from exception fixup, which is the "unwinder scenario get confused" I was thinking
of.  Based on the disassembly from syzbot, that does indeed appear to be the case
here, i.e. this

  2a:   4c 8b 21                mov    (%rcx),%r12

is from exception fixup from somewhere in __d_lookup (can't tell exactly what
it's from, maybe KASAN?).

> Is there more info on this "the unwinder gets confused"? Bug filed
> somewhere or an email thread? Is it on anybody's radar?

I don't know if there's a bug report or if this is on anyone's radar.  The issue
I've encountered in the past, and what I'm pretty sure is being hit here, is that
the ORC unwinder doesn't play nice with out-of-line fixup code, presumably because
there are no tables for the fixup.  I believe kvm_fastop_exception() gets blamed
because it's the first label that's found when searching back through the tables.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YVHsV%2Bo7Ez/%2BarUp%40google.com.
