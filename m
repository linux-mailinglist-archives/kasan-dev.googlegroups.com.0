Return-Path: <kasan-dev+bncBCMIZB7QWENRBEEH336QKGQE27XNXQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id F1E532BA517
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 09:51:29 +0100 (CET)
Received: by mail-vs1-xe38.google.com with SMTP id f23sf1923754vsh.7
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 00:51:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605862289; cv=pass;
        d=google.com; s=arc-20160816;
        b=vGCKb+Ll+BzG35nL1gbHtvtOG5+WcQlVb/tiao1HO8rKdDAWbVdhDYGVf5wdlkRzmz
         2pTmLOl5iiC369FlB+mF47JUPbUU6b00UFnePLxAu6+u02DHDhyHT0e8aQMLL/ui++m6
         iQGVCDvtRDRG+JG9U9GnoOZU9N5aJzMScHNo+jbWjM6SGSDYb89x+A+aoATNTAmusFCU
         XgHUGRZANHR0qZN2d4iC77nbQfLOgsGgTbxs06XbIPdrVF9oCtcPdriGcqeNn8HKM9fr
         xKsJGWRl2m0kEcy9wVz1Y2DQYEPEHwZ9EUt9cnejr3Y47lCLhXzdmNjTektibKxblwIx
         gAOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YDPQ/CvCPswXqDKgz50X8PtWypbXSupVP3Os67ElUTk=;
        b=jdggLMi+1EKNACIsWv2k/uNtvp2IPcat5MCjJjrA1CAV2v8KDXQNlxJ+kcrCN46BXz
         C6HDourCNMztEj7iZDd8aB3HJ/21stArbva0at7IPi/kj5IlR1sh+ynvjMH+NiS44Eak
         MhdXqkVgqV5bifCgrYMR6YAAelGBjrwVKxWBQpTqGnEcWDhaD0BUGuOmRlwWh0/ZoBD9
         tmMUke1Dfv00+sz3Nn3Re3gXYfcY8P/bZdBpGAjuTKG9eAtUvh5/n1U98yta2oYMuXVt
         Q9UFKh6xS12nOAyDZuWcZoBrYWfTjP72XkgMQxCM7BOkv3lP9XB7zsJtIMUt+j4Fg+vF
         M4og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="mms/xhSW";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YDPQ/CvCPswXqDKgz50X8PtWypbXSupVP3Os67ElUTk=;
        b=cm5PtKt9GQUb6T+78uV/VpwIgG6LzAZqhKBrAM78nzu9xbK6CfutV/JufNENZtlxxI
         q8MBmASr0EOgzSsZ1GlJBpvIJGui4xoWYL92SRd53Lnj9E02jXp2jBNZsDQegI33ALdc
         XyP5LdyJ0Mzm5k8p7dNLdg9bt8z1b/G6lmXl7Ufj17JtPf52+dnJF2Fa4oVqrN/ICTvA
         yqjd2f/tHjSQKtmuk+wK5AvdylCdHtDaazX1oFR5GAjcUKW7g2BgZFCMIoJABayV3T2K
         pk83IWC4U+EzgwUCZjYkgTqoSKoSV8LBtTMmpYKh7kVNvuEi+5MyIIqhMCU1f7FWrJS9
         fqiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YDPQ/CvCPswXqDKgz50X8PtWypbXSupVP3Os67ElUTk=;
        b=rt4sh419jkZuKJ7y59QX8n1W5mX3/BWIMW0E8AALKJJUfyUjFLWkBTH2PLJKQaxj0u
         l+amB/bozmRGvRXr+87+1deUDJgLjnnRSKRioC3pXQ0jmiKpDc+xFf9y5cXxbPXmSVc7
         5YHGiak37HlZD8+e1vSBXvQQRCNj+PwDI0t+kzuZ5WiNVz2d4nn1DlS9hGjUyboSVixf
         BqafH5yJMPbzgdNf4mF6k7rfnYXwhW9jFs1UUl8L17XQ0K0KHqbzFBg89GQ2YmB+t4d9
         DM2dzgsynJ7C5FQQd+LMn2OQaXH+bixhhv/q97OwY4TJJLVSmyAlyvf9lZBWmuh9i3y9
         HwGQ==
X-Gm-Message-State: AOAM532esKtarIx3/jflGbWqPH9jL+VDhOotekYxRoLvS8GAG7vIOxw8
	s7Whs0Ab2yKll69TI3hUiCY=
X-Google-Smtp-Source: ABdhPJwFLL0gqy528YbokluhWXv2psoBv+1Bn35ZA449DWsFLljfNl4unOcg/bIKvRvvsF4pEtoHug==
X-Received: by 2002:ab0:542:: with SMTP id 60mr13064811uax.29.1605862288836;
        Fri, 20 Nov 2020 00:51:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ef8c:: with SMTP id r12ls852148vsp.7.gmail; Fri, 20 Nov
 2020 00:51:28 -0800 (PST)
X-Received: by 2002:a67:6587:: with SMTP id z129mr3111206vsb.29.1605862288352;
        Fri, 20 Nov 2020 00:51:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605862288; cv=none;
        d=google.com; s=arc-20160816;
        b=Zqo3vtpnsQr9ZetE54/P8upBzPO66iTFXjktEDfAg0UBvcztKW98xMjdeJxkqu/QxT
         /dNkl3cKKSfsuEN/UYX9EWQ2kiHB5zgfdDH1CXn6qMFGeOTaHhbEi56XOE2zcZeib6+l
         PmqPXgi7WMsWGJzmcO6d1u6UvhlaMtm3vEAUKQqOcfbAVJVHxcYKkH0NcvWczS6aVfio
         06+IvCanW6VKnE+YrbVHfcrul7yQhnpGCx795gZzReNC0S3IT1ih/6T2m4ZOqoYcJNAD
         jUFl93K2pL2g6Fg6tzZcts6po3OYiFufPYPmhiYvo4GrQ7nAIu/tdcbAdfJJLH/2AluK
         IK2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TgKQ0jWCyLF8z2NTHwlOXu9zgvtMphj2U7UOjEtl2cs=;
        b=FvzWIfjpeDwrHZaQcaDtuD31W5UTsVngWW/cOgQtgLP7QFoZ9PjEIr1wnJ+7fMQn7Y
         Tla1ykrT2HW+YccU+Bfr0DX2WN8iSdLmw3++1ZU1TOmhOlutUkifBykCkWhRd3hXaiBt
         45Jk3mKUJD7Y7AiUi8cjfXBsAIDl6TEZoKtHgJuyjgfbq673v0A0m2WEAQOsLMgm/KOw
         gAVnLG/zRIEWjPkQtBO+1SoJtTIvcLoKWEzEnTZmRCTnQaUYjdZKmIJQLmD5ZhmmN6Iy
         WrS/N+ESugbF6RDxO1Utsp61cjnfj4nEg6g60xxWQUH3lUkY+GndGR6ZSQlRUWwdaKmi
         QlAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="mms/xhSW";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id n1si135230vsr.2.2020.11.20.00.51.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Nov 2020 00:51:28 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id p12so2154882qvj.13
        for <kasan-dev@googlegroups.com>; Fri, 20 Nov 2020 00:51:28 -0800 (PST)
X-Received: by 2002:ad4:46cb:: with SMTP id g11mr15564762qvw.37.1605862287761;
 Fri, 20 Nov 2020 00:51:27 -0800 (PST)
MIME-Version: 1.0
References: <20201118035309.19144-1-qiang.zhang@windriver.com> <20201119214934.GC1437@paulmck-ThinkPad-P72>
In-Reply-To: <20201119214934.GC1437@paulmck-ThinkPad-P72>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 20 Nov 2020 09:51:15 +0100
Message-ID: <CACT4Y+bas5xfc-+W+wkpbx6Lw=9dsKv=ha83=hs1pytjfK+drg@mail.gmail.com>
Subject: Re: [PATCH] rcu: kasan: record and print kvfree_call_rcu call stack
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: "Zhang, Qiang" <qiang.zhang@windriver.com>, Josh Triplett <josh@joshtriplett.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Joel Fernandes <joel@joelfernandes.org>, rcu@vger.kernel.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Uladzislau Rezki <urezki@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="mms/xhSW";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Thu, Nov 19, 2020 at 10:49 PM Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Wed, Nov 18, 2020 at 11:53:09AM +0800, qiang.zhang@windriver.com wrote:
> > From: Zqiang <qiang.zhang@windriver.com>
> >
> > Add kasan_record_aux_stack function for kvfree_call_rcu function to
> > record call stacks.
> >
> > Signed-off-by: Zqiang <qiang.zhang@windriver.com>
>
> Thank you, but this does not apply on the "dev" branch of the -rcu tree.
> See file:///home/git/kernel.org/rcutodo.html for more info.
>
> Adding others on CC who might have feedback on the general approach.
>
>                                                         Thanx, Paul
>
> > ---
> >  kernel/rcu/tree.c | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> > index da3414522285..a252b2f0208d 100644
> > --- a/kernel/rcu/tree.c
> > +++ b/kernel/rcu/tree.c
> > @@ -3506,7 +3506,7 @@ void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> >               success = true;
> >               goto unlock_return;
> >       }
> > -
> > +     kasan_record_aux_stack(ptr);
> >       success = kvfree_call_rcu_add_ptr_to_bulk(krcp, ptr);
> >       if (!success) {
> >               run_page_cache_worker(krcp);


kvfree_call_rcu is intended to free objects, right? If so this is:

Acked-by: Dmitry Vyukov <dvyukov@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bbas5xfc-%2BW%2Bwkpbx6Lw%3D9dsKv%3Dha83%3Dhs1pytjfK%2Bdrg%40mail.gmail.com.
