Return-Path: <kasan-dev+bncBCMIZB7QWENRBW7C336QKGQESGOUS3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id A96552BA9CC
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 13:06:52 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id r192sf4123269vkf.21
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 04:06:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605874011; cv=pass;
        d=google.com; s=arc-20160816;
        b=GpCa6gu3AcWqSMjk6F8N4v20/7Fw9/O4+z1BHcurEceLaxnmSD5/vxrXXIHm/Z39LA
         C1eCs6jRiqiL2Hze/fMmXEv/Ke7++qy1tmt1wypTis5dY0U0MWLZ1wkVdzIbmXHH5P5j
         es2JU5i6+FHY5VTqVWv/lIAYsGjjfCn2+9m4sn6JzBH1C12O2HRLJUHjOVxwAUbDw3b1
         ZoccV6yZFYECdDp1Vnt8swJ1oa5WvygrbiXjrFEkxB5Ei4nuS/RnaL9KeZpG8J98JZ4L
         Z6DLtqg+FIjfaOnczqZWAwQkWb4XvSkMG3mZnbrCDqENxn2JsSeGaMb+D0+w8eEOXKc0
         IVIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QJKmhv2a2NS/lMnIq+CeWgnqrRvQTrsvnXo+06cjpQI=;
        b=0qyGov4pAUmCI5Z8XHmG/ev1OWsWbefdrfIkEa8s77p9GOeCh6Qv06G6MU31AnS8y3
         +Hq5EPJmP8zHUP1ENu4O3zRuh9fvGVqZ9VshZGNMp4RGeMfsaeASYoNZVsWKxwqJO8Dz
         Tk7WkgzlLva7CgpBe/CKTPgvwusBHr41zszdDejrsiAsbRGvGXqxIs8vJ2oSlQDxt5fU
         0yFFzIIeQiekWsWtg8MR2IZZbOUNa3RaDZeEn/HaW1iuok9a5aiGrkvmIFZ96ASL8p9h
         CxICBBSX7D+nAXRpP7LJXPYD8q0/EqvqNWMBzYysR0vMWjbUV+D7r/hXXvvkOIuHk/X8
         pIgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MljDJCHk;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QJKmhv2a2NS/lMnIq+CeWgnqrRvQTrsvnXo+06cjpQI=;
        b=o5tjYBlmGCv6zdnxvqA2IkBJYZcA7rGVfkkL8X/8Ko6aoXGXdrHX7vvSkumcCSQkNi
         lfDwva3mI0074kJ4qhAEtpERoKtDnzOOscTdxX/YA5yTF1/T5hNWlGnCUHkMqWlDssBR
         /zLkqweIxAcWPjspslHvaOCEC8hYl6nGQixIIM+5GP5VNbFCaXkiAgFGHj7PeDs/g7mD
         nmJPBAU0+tQ1KFt30yfqQ9Z5d1t1iX14P6hZOoDrGOG971xyRuG2YlT/3flpj7xpnm+X
         W0Ro6tavKSTIlVtdJGCoM40wYG/3rahzxoRW09r32vRGMWFKZNX98PRH8DgcAX8mqvvV
         ai2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QJKmhv2a2NS/lMnIq+CeWgnqrRvQTrsvnXo+06cjpQI=;
        b=BSfY5PmAI7hGDoazPkUEELp3AkIzsExlA+TPdBzbob7NBcT9+DLJiU5SSMP5H1ljon
         F8BvwYBZJGapgd3yYOFv8yrb4wk5NURsn/6tUFOK91ujZNLdM1dbK38ntevTgQ39mKst
         5ZNQe6lYK5na2W7xIVPH8zJ98/Iu1Hbb+G2xdF7m5Af1/J4oJTCkjYJ1bS58v7R0fw8A
         mvitK2pgHgf0SKyhIHBambZEAnCUpDaXniNAaa2H3cc/W9Fo5E1/5F+QNI4gDAgN9bGG
         oZ6M/Ln6gTAsmJ0UGudcgn3IrivwGzq7NCko3IQzBgfcNKVIzwiiwePX8IvIZrgHxcW0
         YPAQ==
X-Gm-Message-State: AOAM533xl5twFgeJsvJs+9t8B613z755U48Yo2JfQkn6QL10Ogo8tMYY
	vnxGPfaO/627AMqNaxt96no=
X-Google-Smtp-Source: ABdhPJy6IMCE3zYpBp36UNk/vaCY92YDxTOl0gpttEFmGSIbADABCq+zYh93R45tmBcvqbkqBnCjQA==
X-Received: by 2002:a05:6102:1144:: with SMTP id j4mr12309369vsg.13.1605874011720;
        Fri, 20 Nov 2020 04:06:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e985:: with SMTP id b5ls894721vso.11.gmail; Fri, 20 Nov
 2020 04:06:51 -0800 (PST)
X-Received: by 2002:a67:2783:: with SMTP id n125mr12296032vsn.47.1605874011064;
        Fri, 20 Nov 2020 04:06:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605874011; cv=none;
        d=google.com; s=arc-20160816;
        b=cTIUqikqE7bAPdyCYHNkF4jbNZxdpvGWXixvMaCd74YKkamtxQCm4Xv89oOrcwZCOU
         FAGEXl0mNZQfqu+Wq+ExNWBsT0+WZjJzfgzYYKhpXoMYuuMfdt/SX5juqSKDayZRqswY
         qKhLUxS5Jywv0fHKQ7PdA3vFGcsEKbxVjjN6xjXYfc8NnYEFskySTPHUqLopGMmywqs4
         +Mn/tZm4QvMUQMseXn5kdVE+CsBzVuYhLXJlQ1bcFeh8H0SWsVpBXAlZ+WvViCYj7NAX
         VjZcLEOQi5/tYCk0BtM4JhAkMKH7UixBN77fSeqGwgje8A66c+OrlkwyVjzYyJE9RSg8
         Jf6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ONlxph66vinoq7WQfOgvS0BntK6G4N++ZL2XryVnJQ0=;
        b=WOdJP4vHX2nIHKes8tO7MYaVjaNgBpKelSh1aoTR0nZeShkLsIyO/3W7MJ6BvJ0fL8
         bKZt1Y/elSjBqtSVcQ8i/iPAGA+xXFBZRnk1mbSQoQfaonsUDVUQmDH3PjJsWmKxR5bX
         mnDvph7fGQu64MkOnIpm4pIhfh9zYKByv1fvC7sL9EQabS1NLwvuP4i+GXnK74S5H09Q
         sabl9dhuekO6sCrzOzJVS7vUBd0J14G2JiKFUOIHh3sfxdGNf+X5Y/f7VUhOC1s7GDrm
         3DZ3Fc1f+NDPIiiOsT9oTnRqoKS2vvi6rUwrvjquRZz9736UgO9srm+pb3FmRusLPIQ0
         whxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MljDJCHk;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id a16si233467uas.1.2020.11.20.04.06.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Nov 2020 04:06:51 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id u4so8567512qkk.10
        for <kasan-dev@googlegroups.com>; Fri, 20 Nov 2020 04:06:51 -0800 (PST)
X-Received: by 2002:a05:620a:15ce:: with SMTP id o14mr16608080qkm.231.1605874010482;
 Fri, 20 Nov 2020 04:06:50 -0800 (PST)
MIME-Version: 1.0
References: <20201118035309.19144-1-qiang.zhang@windriver.com>
 <20201119214934.GC1437@paulmck-ThinkPad-P72> <20201120115935.GA8042@pc636>
In-Reply-To: <20201120115935.GA8042@pc636>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 20 Nov 2020 13:06:39 +0100
Message-ID: <CACT4Y+bHpju_vXjdtb46O=zbQKTFaCSuoTKu1ggZ=CZ9SqWhXQ@mail.gmail.com>
Subject: Re: [PATCH] rcu: kasan: record and print kvfree_call_rcu call stack
To: Uladzislau Rezki <urezki@gmail.com>
Cc: Zqiang <qiang.zhang@windriver.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Josh Triplett <josh@joshtriplett.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Joel Fernandes <joel@joelfernandes.org>, rcu@vger.kernel.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MljDJCHk;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

On Fri, Nov 20, 2020 at 12:59 PM Uladzislau Rezki <urezki@gmail.com> wrote:
>
> On Thu, Nov 19, 2020 at 01:49:34PM -0800, Paul E. McKenney wrote:
> > On Wed, Nov 18, 2020 at 11:53:09AM +0800, qiang.zhang@windriver.com wrote:
> > > From: Zqiang <qiang.zhang@windriver.com>
> > >
> > > Add kasan_record_aux_stack function for kvfree_call_rcu function to
> > > record call stacks.
> > >
> > > Signed-off-by: Zqiang <qiang.zhang@windriver.com>
> >
> > Thank you, but this does not apply on the "dev" branch of the -rcu tree.
> > See file:///home/git/kernel.org/rcutodo.html for more info.
> >
> > Adding others on CC who might have feedback on the general approach.
> >
> >                                                       Thanx, Paul
> >
> > > ---
> > >  kernel/rcu/tree.c | 2 +-
> > >  1 file changed, 1 insertion(+), 1 deletion(-)
> > >
> > > diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> > > index da3414522285..a252b2f0208d 100644
> > > --- a/kernel/rcu/tree.c
> > > +++ b/kernel/rcu/tree.c
> > > @@ -3506,7 +3506,7 @@ void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> > >             success = true;
> > >             goto unlock_return;
> > >     }
> > > -
> > > +   kasan_record_aux_stack(ptr);
> Is that save to invoke it on vmalloced ptr.?

Yes, kasan_record_aux_stack should figure it out itself.
We call kasan_record_aux_stack on call_rcu as well, and rcu structs
can be anywhere.
See:
https://elixir.bootlin.com/linux/v5.10-rc4/source/mm/kasan/generic.c#L335

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbHpju_vXjdtb46O%3DzbQKTFaCSuoTKu1ggZ%3DCZ9SqWhXQ%40mail.gmail.com.
