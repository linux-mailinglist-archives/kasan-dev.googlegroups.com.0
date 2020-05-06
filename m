Return-Path: <kasan-dev+bncBCMIZB7QWENRBRWVZL2QKGQELZSIASI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id C026B1C7024
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 14:17:11 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id v3sf589695uat.21
        for <lists+kasan-dev@lfdr.de>; Wed, 06 May 2020 05:17:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588767430; cv=pass;
        d=google.com; s=arc-20160816;
        b=htJ6Lki/s876wT7E4guphi/BlgadP7LTGMzxbSioe5I6M3ly+yZZjx+vsZJQcq9UzV
         1WODt5vOLHWphq8veiNj2S+kFQZVzylLFfu4MHlYNnBSWKnb/ojsMiGpVLS/iM6nyfVQ
         JlimKm6ZUYbXfCaZJPZvETktMMw1af7BcXQkGo1zBSa6vfGF1iQnuEhQ3Cso4g6oVugL
         fBsWUdm3Eu6S9EphbLs671r1EbQ9sEp75APuezycaUME9nQxpjF/Hae2NHfnPjhmsFiM
         9sym2/DhCbfXwfaKg14Qa3Xv37kox70mD6boLfWQD6KjWv+dv0Z2FmpEJl9XsxXqw2l6
         JklA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wbJHsxbOSMEiFlc5x1tPKIic4OcY6zZtPEHxgmfH6Ts=;
        b=ycuJ2hJFizL0MHtiDHes/E2/DdiirnRpA/vHVzcNCHWN+NNIiUzsK1vYj26GjhZH0o
         SHZ3XGh/FBpgpQt5WTCzAoRA9FF1qSJNzhyNqoRCrrOlXYBe0ynHUZK3idXL8N79Qi+z
         jqn3yUSijMA7r4dQlH3mcKb2GiTTipl3sbV38SiA422d3sdsciAXbWBL0bpY6dzBWo6I
         ss3/A2d89jg8ayZLa/6jdrC/2wihWlp94M3mARc0eBNXrqWLCIrV6kLivwxSX9nvE+ja
         yQLV4Ts9kORcn89gquxuk6DDNYZBycqyOLB4TnbWujUwDlQZpj6QUGdBEgPrtLJdb9yE
         Of4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BHr6Q2jz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=wbJHsxbOSMEiFlc5x1tPKIic4OcY6zZtPEHxgmfH6Ts=;
        b=ASouQuJZnDmcx8wyew3Q35QNntJax3x6qTtgbp03pSqAHYXovuaC1AV231lxWWXAYu
         7uR0KZBN3vDOgJAXuY5vjc1WOF73PIJ4lCuX2wf2BGVX6gDF9NGo8i7zD8leA3p2M6OZ
         5n+I7XxMrPGd1BNM2X+XqSykmkrbYVRxhL+YKVT6KC9R38Cy39h/AA4QU0q0kr2J4Z6b
         uDUjRy0tv8CE3MCwfxQ0amjSilz1ZA8+vGmFHDoCG5BB/pivnxydwgl/TDxnxWiTVoDD
         uN75ddqQ6+eB8D+MpAGYqg6YpeyiXAUOGMJyR6XtZBtm1s90ni8kN1W/NWqaH/Jx4p2E
         ehQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wbJHsxbOSMEiFlc5x1tPKIic4OcY6zZtPEHxgmfH6Ts=;
        b=D5GvLLj6AioRqkMPwXSm2RtU5WZZvdxlM0hWkeTsAGotIWvF2zN4HH1xE4Rh3kBmLA
         XSQNwNQrcoLV+LKYhkdwSoqJfAAK1qAmrT6xBns1z8U5d9j+eqwlRgsDQQOKracalwCY
         ScL3ivfg9OUTVJqnUSpzQssPRgHD2PFGP4k3aOb5JJfWBWfoZRWMjBYa3PLIr06TRedN
         F3dXQahflqSkLPviNx+k+ijksnjIAuuJy0895cDKoP4JeJeja7gAdIvxPRMb8e69v4e+
         ddUGhNihkcMmnuf/pT4vhWB3xv/kJXXSqjvwALa3u6OjLy9uubnxYIvIhapJfJGGsdH1
         L4Ww==
X-Gm-Message-State: AGi0PuY8HfIsOZoSsbcCC5M5TEuHY1053CV/FrhYIcrWd4yCO0eab/kT
	BMREX3govclOxGc1OiRE+Tg=
X-Google-Smtp-Source: APiQypJ/kp0J1oPjv7Ztld8uTl5oeuBVKVTzNTTImuFBohFZNzUEGNUw8RYZI+828g46YCDJpvDWBA==
X-Received: by 2002:ab0:6855:: with SMTP id a21mr6732281uas.30.1588767430598;
        Wed, 06 May 2020 05:17:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7902:: with SMTP id u2ls249006vsc.9.gmail; Wed, 06 May
 2020 05:17:10 -0700 (PDT)
X-Received: by 2002:a05:6102:409:: with SMTP id d9mr6639270vsq.220.1588767430254;
        Wed, 06 May 2020 05:17:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588767430; cv=none;
        d=google.com; s=arc-20160816;
        b=vuZCdr6xDmORc72PraV1C8FZl8m09C0vnnchGJwka2YgpIvMrxo9/hstJoH2rd5YHh
         VTC4pwfyVGSiiScAIpDo8FnvpskKRRZZKQ2agPXPLmfAeyuV8RxDFV2HStFEIgD1E5me
         5lrhT2LnmGWdj3yp8maGsW6/G1fjjOuq7PVQ773ccw0WwJ4BS0NqCMiSLBYDNJfPxPLq
         Kvn5RTXSRbcqEgb6n9PSFQ/R0kB6C0BCYSd55JvyM0NmRIzbKkTsa0zQzzDFuifhAKjL
         NKuvAqgyT5/32p+1JlITj8aEYG3LsvuAULeVralE9nOYFmgScu25fgQthNpQVfHEFRVy
         8xkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2a9aw64zHH2XF20M2Lyiu+UmzKecSTayjdQ/idjqxfY=;
        b=PpXb50Uo7yHpStAjNxNDwl24HXmQg/DuRP1SE2iR23TQbIU+wYs3qXD46Z+SJ/QdNU
         dKJXiat42mwYbr0cK+8MVj424zzY0xqGwBCJOFsOWZ/Tp8TW3QJ7Lf7Yun/s5UgO8Rmw
         aNqo55Y99j/rfWY+7BfbwR24Kp+5+Rsv9q+nzyKoHu9XemMjYkl5CLSU/gUiCbBWZ8DB
         7Z2uxiwTF2xFaJrlTjFDk508d93qkGLMuq4kB3D/RlkvEzk+bxhCvRzrBCj5X2a+tdmt
         tTvDxCyk86mWOEmeBdcqC8AH2AwJvY+viAMO7QzEpDKHWcuBAwKFx9UL21EVo+Zz2QvL
         KDTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BHr6Q2jz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id i18si7842vka.5.2020.05.06.05.17.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 May 2020 05:17:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id fb4so541681qvb.7
        for <kasan-dev@googlegroups.com>; Wed, 06 May 2020 05:17:10 -0700 (PDT)
X-Received: by 2002:ad4:4d06:: with SMTP id l6mr7710326qvl.34.1588767429553;
 Wed, 06 May 2020 05:17:09 -0700 (PDT)
MIME-Version: 1.0
References: <20200506051853.14380-1-walter-zh.wu@mediatek.com>
 <2BF68E83-4611-48B2-A57F-196236399219@lca.pw> <1588746219.16219.10.camel@mtksdccf07>
 <CACT4Y+atTS6p4b23AH+G9LM-k2gU=kMdkKQdARSboxc-H8CLTQ@mail.gmail.com> <1588766510.23664.31.camel@mtksdccf07>
In-Reply-To: <1588766510.23664.31.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 May 2020 14:16:58 +0200
Message-ID: <CACT4Y+baJtLf=ppLjjYtcZNQwPW0daQYcQLTmYe-WU2-FxPHEg@mail.gmail.com>
Subject: Re: [PATCH 0/3] kasan: memorize and print call_rcu stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Qian Cai <cai@lca.pw>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Josh Triplett <josh@joshtriplett.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Joel Fernandes <joel@joelfernandes.org>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BHr6Q2jz;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44
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

On Wed, May 6, 2020 at 2:01 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> On Wed, 2020-05-06 at 11:37 +0200, 'Dmitry Vyukov' via kasan-dev wrote:
> > On Wed, May 6, 2020 at 8:23 AM Walter Wu <walter-zh.wu@mediatek.com> wr=
ote:
> > > > > This patchset improves KASAN reports by making them to have
> > > > > call_rcu() call stack information. It is helpful for programmers
> > > > > to solve use-after-free or double-free memory issue.
> > > > >
> > > > > The KASAN report was as follows(cleaned up slightly):
> > > > >
> > > > > BUG: KASAN: use-after-free in kasan_rcu_reclaim+0x58/0x60
> > > > >
> > > > > Freed by task 0:
> > > > > save_stack+0x24/0x50
> > > > > __kasan_slab_free+0x110/0x178
> > > > > kasan_slab_free+0x10/0x18
> > > > > kfree+0x98/0x270
> > > > > kasan_rcu_reclaim+0x1c/0x60
> > > > > rcu_core+0x8b4/0x10f8
> > > > > rcu_core_si+0xc/0x18
> > > > > efi_header_end+0x238/0xa6c
> > > > >
> > > > > First call_rcu() call stack:
> > > > > save_stack+0x24/0x50
> > > > > kasan_record_callrcu+0xc8/0xd8
> > > > > call_rcu+0x190/0x580
> > > > > kasan_rcu_uaf+0x1d8/0x278
> > > > >
> > > > > Last call_rcu() call stack:
> > > > > (stack is not available)
> > > > >
> > > > >
> > > > > Add new CONFIG option to record first and last call_rcu() call st=
ack
> > > > > and KASAN report prints two call_rcu() call stack.
> > > > >
> > > > > This option doesn't increase the cost of memory consumption. It i=
s
> > > > > only suitable for generic KASAN.
> > > >
> > > > I don=E2=80=99t understand why this needs to be a Kconfig option at=
 all. If call_rcu() stacks are useful in general, then just always gather t=
hose information. How do developers judge if they need to select this optio=
n or not?
> > >
> > > Because we don't want to increase slub meta-data size, so enabling th=
is
> > > option can print call_rcu() stacks, but the in-use slub object doesn'=
t
> > > print free stack. So if have out-of-bound issue, then it will not pri=
nt
> > > free stack. It is a trade-off, see [1].
> > >
> > > [1] https://bugzilla.kernel.org/show_bug.cgi?id=3D198437
> >
> > Hi Walter,
> >
> > Great you are tackling this!
> >
> > I have the same general sentiment as Qian. I would enable this
> > unconditionally because:
> >
> > 1. We still can't get both rcu stack and free stack. I would assume
> > most kernel testing systems need to enable this (we definitely enable
> > on syzbot). This means we do not have free stack for allocation
> > objects in any reports coming from testing systems. Which greatly
> > diminishes the value of the other mode.
> >
> > 2. Kernel is undertested. Introducing any additional configuration
> > options is a problem in such context. Chances are that some of the
> > modes are not working or will break in future.
> >
> > 3. That free stack actually causes lots of confusion and I never found
> > it useful:
> > https://bugzilla.kernel.org/show_bug.cgi?id=3D198425
> > If it's a very delayed UAF, either one may get another report for the
> > same bug with not so delayed UAF, or if it's way too delayed, then the
> > previous free stack is wrong as well.
> >
> > 4. Most users don't care that much about debugging tools to learn
> > every bit of every debugging tool and spend time fine-tuning it for
> > their context. Most KASAN users won't even be aware of this choice,
> > and they will just use whatever is the default.
> >
> > 5. Each configuration option increases implementation complexity.
> >
> > What would have value is if we figure out how to make both of them
> > work at the same time without increasing memory consumption. But I
> > don't see any way to do this.
> >
> > I propose to make this the only mode. I am sure lots of users will
> > find this additional stack useful, whereas the free stack is even
> > frequently confusing.
> >
>
> Ok.
> If we want to have a default enabling it, but it should only work in
> generic KASAN, because we need to get object status(allocation or
> freeing) from shadow memory, tag-based KASAN can't do it. So we should
> have a default enabling it in generic KASAN?

Yes, let's do generic KASAN always memorizes rcu stack; tags KASAN
never memorizes rcu stacks. No new configurations.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BbaJtLf%3DppLjjYtcZNQwPW0daQYcQLTmYe-WU2-FxPHEg%40mail.gm=
ail.com.
