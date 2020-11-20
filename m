Return-Path: <kasan-dev+bncBDK7LR5URMGRBS7W336QKGQER32ZR4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 948FC2BAA72
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 13:49:15 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id l12sf3668258edw.11
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 04:49:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605876555; cv=pass;
        d=google.com; s=arc-20160816;
        b=JZsiM6boNhn4Lbg+Q03WGIRGNldQd7CYaW89UNoUfTubX/d96bM+1mzv6n8e4+E0qs
         JreIRHBV/lWoE2i0RdDUEzCY3+Gr7it1wxIm391ybvoD5MVF7KIEjiXXnsyndTc0f2ke
         kBRQAvA40eJdTNgPU8K72AzPmmwyYZb+abNDnMsgsFZSs8Eb/J8q3+4c0dsB005vm+O2
         Iyxd1XMVOvHB5gPsoA50sWlX8B9HQRmOeM1bMu7JNnwaNntGnKBzUYLWWRdbJS8jKSRK
         DcPQXjlWeDQ1S2VdBCgoCV6M2ltVvOs/quERqY9Rth1MP+79+5DADyiZVjTxsGxfyxWQ
         pzEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:dkim-signature:dkim-signature;
        bh=3MCMnWJNmMkq/BjfpWsrDGJC5OzLXuibvEffaFwlkFg=;
        b=TahYGRoDBE5tohxzuWIqc8FSBKs8QlHgrH5PUL1CDsAsjLRQ+nCrXtMlyqi+J6lNPJ
         x47eRl3AjEzcsMWWnaCwYrlnYiA5Grg9RlnQRmo1m1VaCdGOhyrHz/2doqRbm4wQ7jhm
         oHJV4zUc4hrJ4xbFYCI5KOm2xcBy5JMinuveh7WxPoQepUIPYp8mHsCG75KkR5vmNG6Q
         6B6UuyGoplJQEXDg6gU9NdzJpGAGvctlIHEZDMyKFgZJeRkmLe4ZQz3QyYYx/khJMq8Y
         T9YGdYM/LLmxWjvWQY+XwzeCHyK6ssrJ5uhcI0hWE1aqfphTYmrjeXh741VNkoKLwmiQ
         zuOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=XkvDhMzs;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3MCMnWJNmMkq/BjfpWsrDGJC5OzLXuibvEffaFwlkFg=;
        b=il7vNdZUWVHKgCWlRkjhJ8aPfih87R49T+mk8UqEf7wXV5UHslcMLWHx+Ua+bogLl9
         ZSQGaNdh5s5Gy3svUjlqvlr9QbZU6PUb89vlLhfQpZUNCR/Po7zb4ciPfMj0fvXCHaaq
         2syPk4MsCwmKYsz5meegmISBZHGEO3MnVx/kdvVOaH6iih3ODZaeLwxJEQcRQn9BJ7br
         muxc6HUF51aupcuaeTmp/ekl66gXv/pM1ROcRtA9uQ8SRKp5Y5sOLA8P0aHjOUCKqko0
         FWI4GuXeeRk+0oM4XAD7jLPbjls8zej0SwuPNXGeetZSvGC92NWnJ6+HMsAJL0Src0eA
         fvgw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3MCMnWJNmMkq/BjfpWsrDGJC5OzLXuibvEffaFwlkFg=;
        b=OfwfuRIaXNXkEjccnF80YjDg7NM6djAt6PlfDehbbV44svWxA9Y35bD7SFQOc51Bg3
         RX/67WdY1zkYXosLkT/RMlR/iNOjcwM2pIoFeq6YH8cas2jZIqRqbdiikxbQrOLkQ5g0
         ROG3KgO9lwLXRAmq+jRdzkb+JqRiQ9ht2Nh5Eo0qNmQFkoVbU35wbEF7A7kKVq8iUUBr
         vQZpu6eeDS4EdgznrboGpOe9EgoegecgWBW/nkJArep47tR+xQfnq403tqt1rnPs4Bq3
         T3BvpDW/Dfbot/Ad8SdlugnEGDbcDnb+A8sywdkrUmq2f29hh0WTFEXnJgeWwApirzr7
         RoHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:date:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3MCMnWJNmMkq/BjfpWsrDGJC5OzLXuibvEffaFwlkFg=;
        b=kRRLK8v7pbY4o3TjQ56rCFeistkNcdWUzf1IXYHhLhGJ83XyVzhfnLjCM8+yZgg9Xx
         a4OCWKfKkBjeJqS8WJHHu0UIZbsPz91lkh50jsi6OFbSgqRKEsRo6YJNe3t9uXTDbOTq
         zCDWSqurTXsPqggFf0rzc5/CLnUlZYrTwKCKzy7iYMB1mKv0yyFHVasEsJa11ElQwHCR
         Mq2rmQhX5HmYf0iXQ2Zn5aWWfCsQfSL7cxDUhsKsnUow2aQEAwpjZqj6i83vS6YyG9xx
         0d5JajyVoVVbvj/hY2gcn6ClicjIz+Ah7U7nngpn42FgaJKyRFYjiuhl5fX5bNuymYAI
         QnRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ASFsw/EltdbI294UCiU7aFbIv7Xh9o5lroO5/18aQ6ZLpGDpK
	tGAwK60CEIoHWON7m2DHxYw=
X-Google-Smtp-Source: ABdhPJwL7I1LoMQHRBRhbh9chB7ALQ4CChTcZHycwjLsfGKDgpxU9NwSwbIY524u0bJGrPY0Hmg1TA==
X-Received: by 2002:aa7:db8a:: with SMTP id u10mr35943479edt.204.1605876555379;
        Fri, 20 Nov 2020 04:49:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:9f27:: with SMTP id b36ls888745edf.1.gmail; Fri, 20 Nov
 2020 04:49:14 -0800 (PST)
X-Received: by 2002:a05:6402:491:: with SMTP id k17mr547079edv.370.1605876554491;
        Fri, 20 Nov 2020 04:49:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605876554; cv=none;
        d=google.com; s=arc-20160816;
        b=0cGe6AqIsfTgqSCqySkj7gvOOgRZUirNYB80yLUh2UlY5uaeeZNI7FmUCIUgd7PHOR
         GXfIDJa3gSjnwv6wSZtP1/WvrsUNgk3uA6UQ05hBnwcmE0jbMxUbzTOtCinqtyih5ngP
         1SpJs1rJTkFrqmhtBqJPgpfQsa7VwaQP//SbIVWLsA79VlwrVczGI467AOrQsr5Jw4dn
         DF/tMFCAfchOAiVteT0yN+AsMdC4ftbvYJWeUK2V4yHv50k+7YWbQFvvyvMalq2UpQlX
         Lb9mEhD2dFDNsRoD1/T7o0fquTMyWplr2vgg+IGcIeZ3jr4AZClFpqjWCACUp+6H3uC2
         yaRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:date:from:dkim-signature;
        bh=BQlgWzTS/+xbjjCU0RmSKrXjRhY7m9Mf0HlrozKYR4s=;
        b=nICxmyFxckL2ouKbVaAlSiaHhbHOw+feufKgj4gE1coheHssjuFUcYUWtkOH4tJS8a
         KkF6HRFWFCstJM7a4utWoUgDez2rm63YZIXiQCwLBfwjFjWMLzwOQg3uhf6sAUHJkvV+
         iht1I/Zfm/OKtgS2MIcwS6Q5tCS16VSCLW1gfy+8yc5KJkKI0MW/YjmPUW1ToqDply5e
         IjVsDRJrT1+xXQZ0Zy3jW48cHOjiiYmd4dfzM91AFJAgEqB/NqnmMVVuyuV85IR+/7GL
         OGq5JBzzhroT9LlfKfBllQDQKIoGk0v6QDHmoNS7cKMVaAfWihcWjddRakqtgCBzuvcJ
         snHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=XkvDhMzs;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x143.google.com (mail-lf1-x143.google.com. [2a00:1450:4864:20::143])
        by gmr-mx.google.com with ESMTPS id bm8si91657edb.2.2020.11.20.04.49.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Nov 2020 04:49:14 -0800 (PST)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) client-ip=2a00:1450:4864:20::143;
Received: by mail-lf1-x143.google.com with SMTP id w142so13268840lff.8
        for <kasan-dev@googlegroups.com>; Fri, 20 Nov 2020 04:49:14 -0800 (PST)
X-Received: by 2002:a05:6512:3049:: with SMTP id b9mr7427795lfb.554.1605876553951;
        Fri, 20 Nov 2020 04:49:13 -0800 (PST)
Received: from pc636 (h5ef52e3d.seluork.dyn.perspektivbredband.net. [94.245.46.61])
        by smtp.gmail.com with ESMTPSA id o84sm329975lff.302.2020.11.20.04.49.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Nov 2020 04:49:13 -0800 (PST)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Fri, 20 Nov 2020 13:49:11 +0100
To: Dmitry Vyukov <dvyukov@google.com>, Zqiang <qiang.zhang@windriver.com>
Cc: Uladzislau Rezki <urezki@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Joel Fernandes <joel@joelfernandes.org>, rcu@vger.kernel.org,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] rcu: kasan: record and print kvfree_call_rcu call stack
Message-ID: <20201120124911.GB8042@pc636>
References: <20201118035309.19144-1-qiang.zhang@windriver.com>
 <20201119214934.GC1437@paulmck-ThinkPad-P72>
 <20201120115935.GA8042@pc636>
 <CACT4Y+bHpju_vXjdtb46O=zbQKTFaCSuoTKu1ggZ=CZ9SqWhXQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+bHpju_vXjdtb46O=zbQKTFaCSuoTKu1ggZ=CZ9SqWhXQ@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=XkvDhMzs;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

> On Fri, Nov 20, 2020 at 12:59 PM Uladzislau Rezki <urezki@gmail.com> wrote:
> >
> > On Thu, Nov 19, 2020 at 01:49:34PM -0800, Paul E. McKenney wrote:
> > > On Wed, Nov 18, 2020 at 11:53:09AM +0800, qiang.zhang@windriver.com wrote:
> > > > From: Zqiang <qiang.zhang@windriver.com>
> > > >
> > > > Add kasan_record_aux_stack function for kvfree_call_rcu function to
> > > > record call stacks.
> > > >
> > > > Signed-off-by: Zqiang <qiang.zhang@windriver.com>
> > >
> > > Thank you, but this does not apply on the "dev" branch of the -rcu tree.
> > > See file:///home/git/kernel.org/rcutodo.html for more info.
> > >
> > > Adding others on CC who might have feedback on the general approach.
> > >
> > >                                                       Thanx, Paul
> > >
> > > > ---
> > > >  kernel/rcu/tree.c | 2 +-
> > > >  1 file changed, 1 insertion(+), 1 deletion(-)
> > > >
> > > > diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> > > > index da3414522285..a252b2f0208d 100644
> > > > --- a/kernel/rcu/tree.c
> > > > +++ b/kernel/rcu/tree.c
> > > > @@ -3506,7 +3506,7 @@ void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> > > >             success = true;
> > > >             goto unlock_return;
> > > >     }
> > > > -
> > > > +   kasan_record_aux_stack(ptr);
> > Is that save to invoke it on vmalloced ptr.?
> 
> Yes, kasan_record_aux_stack should figure it out itself.
> We call kasan_record_aux_stack on call_rcu as well, and rcu structs
> can be anywhere.
> See:
> https://elixir.bootlin.com/linux/v5.10-rc4/source/mm/kasan/generic.c#L335
>
Ah, i see the check. Just a minor comment, please also add a
clear comment about intention of doing such record.

Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>

Thanks.

--
Vlad Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120124911.GB8042%40pc636.
