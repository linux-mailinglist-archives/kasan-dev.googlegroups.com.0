Return-Path: <kasan-dev+bncBCTMJPOYXMJRBB5MZ74QKGQELX6LQUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id C93D62428DD
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Aug 2020 13:44:07 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id e12sf805801wra.13
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Aug 2020 04:44:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597232647; cv=pass;
        d=google.com; s=arc-20160816;
        b=iPCqwCqXpXd0vAJ4QijGztcK7ukIki6qnaIOpaNXc5DJ5WCrSYjTsRwpSEPqLW6PbP
         aXfnezsWifAn18dcJYfQgndlHgXyi3ctKhFe9KqOWy9Rrk8E0gikZP8zrK5jJoO7d/z1
         NtClhdWitU0PWpyu9/iD16+jbBVsk4fZYSdRk0ZfdxtpI83p6mZMb9dw/iNlN84UNgDT
         ObSjKiAuEjpXZ1Fpz/VBfFNx9Vgm4BptenZOHfw1rghWhbHjGwa4ZW/xK6qvVO6sLBGu
         0R8ppJJiyWatCaMDXsNS4ud3u6bfyFpdFZbb5Zwqayw2sxqJ3fhAbNQWVbL8RAvjskrx
         1oZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=v0W58uoc3+3BHdyKDnzJ7frI2Z3rPv+FT3KhryQrZww=;
        b=g/S0HgZtUYfLFOe6WPol0rbk4aELJO9/CASBvSyBzWroyhRstKOGXMOwoDtI8ZDsw0
         ELsLIa9Jmt8WGz2yATZ4by5GXuO56wDEtA8p2/IxxwQieVCgRphBNDbvg0a6nUMT6JKa
         maXJA6sgsTai39knSkSZC2F+CxuYHjlnvI9JX4bRgfaTyZsLsij2FAzI+LkqEMdV7b7c
         kqi60ztIy6THT23JRx+NhptupR00JNcLH/fMEdkVD/axzdthj+FYLgYwliPnr4KXDiOy
         OVenhV5kSLGNScCAySicPbFxDCz9IbbqXwaJxNVZ0Y8GFt9p2GMIju5SzrjBkPpRiEbG
         cb+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=sOYdoEYv;
       spf=pass (google.com: domain of bigbudsupply1@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=bigbudsupply1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v0W58uoc3+3BHdyKDnzJ7frI2Z3rPv+FT3KhryQrZww=;
        b=row3fbRMLi1rxFoUj9rXZG/3h8b5Ty8l2dIzKJCWJm7oO64WwPTWVozIbxzGWU4Pvr
         yoguMJygNrW4n/KvQrw+qYdISJGpWkRQpb9l7eS/59FaovcEnvHNS8gUeNRluk2nMgig
         RpSpl/91IbnpL5lqnNNGoxklXP3kz1fTExxKfSn6gud2t8o6I1ygNe1xeT3mCnzPSDLO
         Ypzurd/hJP+yd6KWh1hwPOddcookUeYD7IsMBslhvWjImbEguCt8RnuvtgpC6kv1VUOp
         +NqsnqnYpNERZntCMSO89g67F63Q11yzDUz36fT56RJ6LcdCzCisH2Gd5xXlgBSLN/ZK
         zFQg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v0W58uoc3+3BHdyKDnzJ7frI2Z3rPv+FT3KhryQrZww=;
        b=GbA/S9LAFsOsLTEp+NCDVgUCKVU+cTtdNdgTIR3kEUWX8Qqo5NMQZhLbE59h1Psqbk
         ETjMBYTE0oq0PZzkhv+Bb3VHDR7+t9P/bybqA+Gqd4etYC4Jz/r2Pso7YOG4m29gs7E+
         rreAjVQmhyVL3jI8ePyenGJxS/btIWBFF1UyCoCj6ggfPVNO38KD8Gk7tW+g5HgGFYTj
         sHc92a38nw8iDKTyPZDk4PSBY+ziESxlkO26X6VCxUcOi5ghuxJLVytjSF9b2tOyWs3P
         d8/4ZZbEgEqGq23XQmBwwtsE079JZKVvL+pWNOtnJ58QNJ2bYzYh4T/SNXBGtt1JIiYy
         1lzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v0W58uoc3+3BHdyKDnzJ7frI2Z3rPv+FT3KhryQrZww=;
        b=k5I+LRZ3pmG+HAg4baqH/oEA2afVJ6UFcR7aV2bLiahBb1RKUAkwBoJiiEOt7gDDkp
         1i6YgAMarHWbGHB99uJLyB6053J/8B29jwm+vr/hFN8seWB5LSS12ZXa2u3Ed5CUrUrj
         4wd43VRX10JMi93NTHCX86oU6yd1ihfHFNzrZ6vIkuJXWSL6BHdKyHEYd+g6UYFPSFKg
         XUdNNuCG75IPYFF8baOBX/Zt/NG/5OHzoA35gKELNfKISsFRssYP5jKJYwUx2vwwKzGg
         ne0WDbbywx0ZPfhH0U6gW8m1zN4w7wG+CUxFoVmRmpz46YAzAehsltB/UnvjNkWoYrP4
         8Wdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531B3WjHx2YLDi80mXZhwVBCmZvGs//Y24ZArWsA08ybfBhp2BlT
	iziIEDTuk8D+2nIyH5MXxwU=
X-Google-Smtp-Source: ABdhPJzLxqkq029VkI/roEi7nSwb7Fs0EjHyuC/XSYehGxouKbuagae/LsXAMDX9toponP9lBc6ckw==
X-Received: by 2002:a1c:5451:: with SMTP id p17mr8754033wmi.180.1597232647539;
        Wed, 12 Aug 2020 04:44:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2049:: with SMTP id g70ls854493wmg.0.gmail; Wed, 12 Aug
 2020 04:44:07 -0700 (PDT)
X-Received: by 2002:a7b:c7d5:: with SMTP id z21mr8508774wmk.145.1597232646983;
        Wed, 12 Aug 2020 04:44:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597232646; cv=none;
        d=google.com; s=arc-20160816;
        b=ziC7RUVndqjafZ60k3Ch70Vmbrdn/ORLsmQoReJ/jy7GF62X0dkUncrEWfeFbg0O4l
         XLviF/BoWb+DLBAnS33iuI0PRE5bmkaxO3ihyoagf5/bv0lTzyVPjqlWiwzHeCuKLs3R
         tnvYYuLh9wFrggpbSV4yuupxMRH3AjmY43//fwe3bbtf0d+Ga+eQXyonDrc6+mL9Y7DF
         5pfxKLPd28yIf6t9lEJjYOsAM7mrJwJ9ANGX8xahvSi4hXwuP4P5ezNs+etJn0v6aGYC
         PYl++RLFaDPYF7vmLMxFDWgi8QE1CdFBAdSjy2JMcCJwSBwbsYJZSgmFapp7yvfCBuwm
         0F+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JpehBVAXJ/qs7yAnkK4NWJVEUVDeH41wRBqrkyBuGwo=;
        b=aUYQJFOrbRSSviYcXdsRdhPZxQycxdz2rJweQP3BWhkpTeVlTpEbgsH2ir0f+an9wJ
         xHZhJXkO8U8qstBddqZfEV752t3WRlxvb6iTvXnyTuU5jWuRwJMVLthoj3m4wOdooWcN
         1fEuWEkgJ5WwWeMmzFCBxAOjXQ/DyM39pmsV/90uxa83QTyCNfR+nNTAqbB5T2TWZOmg
         u0kvfvysasIkcB6neI527mSbRgT2/aJeqxt6n4DUgto9Iro4bSlcdeFac4m85JZyptFp
         FC6USnfJWrAqzNXNDkW7T0mGxeiDm3DPGO+TEbBCH0XTpvsiEDU8cPhmF+KH9MJYCm+M
         2vJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=sOYdoEYv;
       spf=pass (google.com: domain of bigbudsupply1@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=bigbudsupply1@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id o134si75108wme.0.2020.08.12.04.44.06
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Aug 2020 04:44:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigbudsupply1@gmail.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id a5so1715331wrm.6;
        Wed, 12 Aug 2020 04:44:06 -0700 (PDT)
X-Received: by 2002:adf:9e8b:: with SMTP id a11mr9964559wrf.309.1597232646622;
 Wed, 12 Aug 2020 04:44:06 -0700 (PDT)
MIME-Version: 1.0
References: <20200807151903.GA1263469@elver.google.com> <20200811074127.GR3982@worktop.programming.kicks-ass.net>
 <a2dffeeb-04f0-8042-b39a-b839c4800d6f@suse.com> <20200811081205.GV3982@worktop.programming.kicks-ass.net>
 <07f61573-fef1-e07c-03f2-a415c88dec6f@suse.com> <20200811092054.GB2674@hirez.programming.kicks-ass.net>
 <20200811094651.GH35926@hirez.programming.kicks-ass.net> <20200811201755.GI35926@hirez.programming.kicks-ass.net>
 <20200812080650.GA3894595@elver.google.com> <20200812081832.GK2674@hirez.programming.kicks-ass.net>
 <20200812085717.GJ35926@hirez.programming.kicks-ass.net>
In-Reply-To: <20200812085717.GJ35926@hirez.programming.kicks-ass.net>
From: Big Budsupply <bigbudsupply1@gmail.com>
Date: Wed, 12 Aug 2020 12:43:54 +0100
Message-ID: <CAHwJNhNjk61qCm=zPE_kXOYYtK4Uy7qp_BNiW_pNai4z4zEvKg@mail.gmail.com>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*() helpers
To: peterz@infradead.org
Cc: Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>, 
	LKML <linux-kernel@vger.kernel.org>, "Luck, Tony" <tony.luck@intel.com>, 
	Marco Elver <elver@google.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, Wei Liu <wei.liu@kernel.org>, 
	fenghua.yu@intel.com, kasan-dev <kasan-dev@googlegroups.com>, sdeep@vmware.com, 
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	virtualization@lists.linux-foundation.org, yu-cheng.yu@intel.com
Content-Type: multipart/alternative; boundary="00000000000086928805acacb4e3"
X-Original-Sender: bigbudsupply1@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=sOYdoEYv;       spf=pass
 (google.com: domain of bigbudsupply1@gmail.com designates 2a00:1450:4864:20::443
 as permitted sender) smtp.mailfrom=bigbudsupply1@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--00000000000086928805acacb4e3
Content-Type: text/plain; charset="UTF-8"

Hello guys hope you are doing good! we are Bigbudsupply we grow and sell
the best medical marijuana product, we are looking for long time customers,
you can Email us /Bigbudsupply1@gmail.com
Text/+14432672189
Looking forward to working with you guys

On Wed, 12 Aug 2020 at 09:57 <peterz@infradead.org> wrote:

> On Wed, Aug 12, 2020 at 10:18:32AM +0200, peterz@infradead.org wrote:
>
> > >      trace_hardirqs_restore+0x59/0x80
> kernel/trace/trace_preemptirq.c:106
>
> > >      rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074
>
> > >      trace_irq_enable_rcuidle+0x87/0x120
> include/trace/events/preemptirq.h:40
>
> > >      trace_hardirqs_restore+0x59/0x80
> kernel/trace/trace_preemptirq.c:106
>
> > >      rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074
>
> > >      trace_irq_enable_rcuidle+0x87/0x120
> include/trace/events/preemptirq.h:40
>
> > >      trace_hardirqs_restore+0x59/0x80
> kernel/trace/trace_preemptirq.c:106
>
> > >      rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074
>
> > >      trace_irq_enable_rcuidle+0x87/0x120
> include/trace/events/preemptirq.h:40
>
> > >      trace_hardirqs_restore+0x59/0x80
> kernel/trace/trace_preemptirq.c:106
>
> > >      rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074
>
> > >
>
> > >     <... repeated many many times ...>
>
> > >
>
> > >      trace_irq_enable_rcuidle+0x87/0x120
> include/trace/events/preemptirq.h:40
>
> > >      trace_hardirqs_restore+0x59/0x80
> kernel/trace/trace_preemptirq.c:106
>
> > >      rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074
>
> > >     Lost 500 message(s)!
>
> > >     BUG: stack guard page was hit at 00000000cab483ba (stack is
> 00000000b1442365..00000000c26f9ad3)
>
> > >     BUG: stack guard page was hit at 00000000318ff8d8 (stack is
> 00000000fd87d656..0000000058100136)
>
> > >     ---[ end trace 4157e0bb4a65941a ]---
>
> >
>
> > Wheee... recursion! Let me try and see if I can make something of that.
>
>
>
> All that's needed is enabling the preemptirq tracepoints. Lemme go fix.
>
>
>
> --
>
> You received this message because you are subscribed to the Google Groups
> "syzkaller-bugs" group.
>
> To unsubscribe from this group and stop receiving emails from it, send an
> email to syzkaller-bugs+unsubscribe@googlegroups.com.
>
> To view this discussion on the web visit
> https://groups.google.com/d/msgid/syzkaller-bugs/20200812085717.GJ35926%40hirez.programming.kicks-ass.net
> .
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHwJNhNjk61qCm%3DzPE_kXOYYtK4Uy7qp_BNiW_pNai4z4zEvKg%40mail.gmail.com.

--00000000000086928805acacb4e3
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div><div dir=3D"auto" style=3D"font-size:1rem;color:rgb(49,49,49);word-spa=
cing:1px">Hello guys hope you are doing good! we are Bigbudsupply we grow a=
nd sell the best medical marijuana product, we are looking for long time cu=
stomers, you can Email us /<a href=3D"mailto:Bigbudsupply1@gmail.com">Bigbu=
dsupply1@gmail.com</a></div><div dir=3D"auto" style=3D"font-size:1rem;color=
:rgb(49,49,49);word-spacing:1px">Text/+14432672189</div><div dir=3D"auto" s=
tyle=3D"font-size:1rem;color:rgb(49,49,49);word-spacing:1px">Looking forwar=
d to working with you guys</div></div><div><br><div class=3D"gmail_quote"><=
div dir=3D"ltr" class=3D"gmail_attr">On Wed, 12 Aug 2020 at 09:57 &lt;<a hr=
ef=3D"mailto:peterz@infradead.org">peterz@infradead.org</a>&gt; wrote:<br><=
/div><blockquote class=3D"gmail_quote" style=3D"margin:0 0 0 .8ex;border-le=
ft:1px #ccc solid;padding-left:1ex">On Wed, Aug 12, 2020 at 10:18:32AM +020=
0, <a href=3D"mailto:peterz@infradead.org" target=3D"_blank">peterz@infrade=
ad.org</a> wrote:<br><br>&gt; &gt;=C2=A0 =C2=A0 =C2=A0 trace_hardirqs_resto=
re+0x59/0x80 kernel/trace/trace_preemptirq.c:106<br><br>&gt; &gt;=C2=A0 =C2=
=A0 =C2=A0 rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074<br><br>&gt=
; &gt;=C2=A0 =C2=A0 =C2=A0 trace_irq_enable_rcuidle+0x87/0x120 include/trac=
e/events/preemptirq.h:40<br><br>&gt; &gt;=C2=A0 =C2=A0 =C2=A0 trace_hardirq=
s_restore+0x59/0x80 kernel/trace/trace_preemptirq.c:106<br><br>&gt; &gt;=C2=
=A0 =C2=A0 =C2=A0 rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074<br>=
<br>&gt; &gt;=C2=A0 =C2=A0 =C2=A0 trace_irq_enable_rcuidle+0x87/0x120 inclu=
de/trace/events/preemptirq.h:40<br><br>&gt; &gt;=C2=A0 =C2=A0 =C2=A0 trace_=
hardirqs_restore+0x59/0x80 kernel/trace/trace_preemptirq.c:106<br><br>&gt; =
&gt;=C2=A0 =C2=A0 =C2=A0 rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1=
074<br><br>&gt; &gt;=C2=A0 =C2=A0 =C2=A0 trace_irq_enable_rcuidle+0x87/0x12=
0 include/trace/events/preemptirq.h:40<br><br>&gt; &gt;=C2=A0 =C2=A0 =C2=A0=
 trace_hardirqs_restore+0x59/0x80 kernel/trace/trace_preemptirq.c:106<br><b=
r>&gt; &gt;=C2=A0 =C2=A0 =C2=A0 rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/t=
ree.c:1074<br><br>&gt; &gt; <br><br>&gt; &gt;=C2=A0 =C2=A0 =C2=A0&lt;... re=
peated many many times ...&gt;<br><br>&gt; &gt; <br><br>&gt; &gt;=C2=A0 =C2=
=A0 =C2=A0 trace_irq_enable_rcuidle+0x87/0x120 include/trace/events/preempt=
irq.h:40<br><br>&gt; &gt;=C2=A0 =C2=A0 =C2=A0 trace_hardirqs_restore+0x59/0=
x80 kernel/trace/trace_preemptirq.c:106<br><br>&gt; &gt;=C2=A0 =C2=A0 =C2=
=A0 rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074<br><br>&gt; &gt;=
=C2=A0 =C2=A0 =C2=A0Lost 500 message(s)!<br><br>&gt; &gt;=C2=A0 =C2=A0 =C2=
=A0BUG: stack guard page was hit at 00000000cab483ba (stack is 00000000b144=
2365..00000000c26f9ad3)<br><br>&gt; &gt;=C2=A0 =C2=A0 =C2=A0BUG: stack guar=
d page was hit at 00000000318ff8d8 (stack is 00000000fd87d656..000000005810=
0136)<br><br>&gt; &gt;=C2=A0 =C2=A0 =C2=A0---[ end trace 4157e0bb4a65941a ]=
---<br><br>&gt; <br><br>&gt; Wheee... recursion! Let me try and see if I ca=
n make something of that.<br><br><br><br>All that&#39;s needed is enabling =
the preemptirq tracepoints. Lemme go fix.<br><br><br><br>-- <br><br>You rec=
eived this message because you are subscribed to the Google Groups &quot;sy=
zkaller-bugs&quot; group.<br><br>To unsubscribe from this group and stop re=
ceiving emails from it, send an email to <a href=3D"mailto:syzkaller-bugs%2=
Bunsubscribe@googlegroups.com" target=3D"_blank">syzkaller-bugs+unsubscribe=
@googlegroups.com</a>.<br><br>To view this discussion on the web visit <a h=
ref=3D"https://groups.google.com/d/msgid/syzkaller-bugs/20200812085717.GJ35=
926%40hirez.programming.kicks-ass.net" rel=3D"noreferrer" target=3D"_blank"=
>https://groups.google.com/d/msgid/syzkaller-bugs/20200812085717.GJ35926%40=
hirez.programming.kicks-ass.net</a>.<br><br></blockquote></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAHwJNhNjk61qCm%3DzPE_kXOYYtK4Uy7qp_BNiW_pNai4z4zEvKg%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAHwJNhNjk61qCm%3DzPE_kXOYYtK4Uy7qp_BNiW_pNai4z4z=
EvKg%40mail.gmail.com</a>.<br />

--00000000000086928805acacb4e3--
