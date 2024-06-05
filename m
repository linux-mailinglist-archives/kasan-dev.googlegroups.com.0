Return-Path: <kasan-dev+bncBCS4VDMYRUNBBM6QQKZQMGQEXP2VDKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A39F8FD4D6
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Jun 2024 20:02:29 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5b997b9319dsf619eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Jun 2024 11:02:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717610547; cv=pass;
        d=google.com; s=arc-20160816;
        b=gNRlEWIh2cgKDpef4AbiImKmUbRmPd/1c/O4cehGYH/LPDmFWMBO9wKbhoor5mzfze
         u9JURML2RSHDJCAMCWuE9oVLtcfRmaZNtna2WOZGQx+Fchu1uXFS0TltIja0k8HRyPxm
         Kv60QO6M+SIYZtJFphTrlPY07kFzclkPFPrCM1sSL9Y8U/vfAPKWcZS6Xtau1qlwzTFy
         G7RJTiQDmIGWBnqiH61nWq2jYmGg+gMUbYiENxBVnd4LmfpnpnERq0z6wCTvkI8B8JgP
         ft/jhpozME3gcLRM4kNqgJCE913PoFMB6L5dK+hEFQcDjEPnBr+ubw572hgKXjNBXwdb
         kMbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=M9SO7Ch25aQfA8i/owYJyyVvDD+BzFqXZ8GIKigrNPI=;
        fh=CW1CVjoHb1WFTgMNeJb6lJ3Sj84D+prItB4wmX6+YYc=;
        b=uHT6N3i7mTm1rvcttyo65TzqpvqzB+CXPJCXmZYfWo2EmZXPjGcnv4yRCdi986t4i7
         9XMzZ1fkEWw0Q0e+UKPRWBJUbD4PEBZQhIOi5Aa7o4+Wvfif2GW8oJGIEtoOClQ1B6vH
         gHHcyd+6eYK4/yiHuCr8+9xGCTjgex/dqeX/cfNYML3MfCJcRHBu9RdlKMcz96jIwx7t
         U4NyiOPMy9RDEeN6VS1JoKlbYCAggZaK5QHkxW7dMpnVmrbspAuJoddmNZOYIGdSxSY8
         rAfZAoSUYdhBS2n3Wanvp5xOmwkqSjmwtrop2UBbS/4OBiI7WkmUjNYMMUM1RfaD8+qb
         pXLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=k2FCUM3j;
       spf=pass (google.com: domain of srs0=pug/=nh=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=PUG/=NH=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717610547; x=1718215347; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=M9SO7Ch25aQfA8i/owYJyyVvDD+BzFqXZ8GIKigrNPI=;
        b=f+GwIqL8MyuM/QTY6FpRN7zjWvGq+LlBJkMrkULAvpg3Zin9rgKZnm5+P+Yr7hzz30
         u85dp/rWJPFlQogPxxJ9ZL3epZ4dbE7vck4CsRPNijyKgCYxa0Of4z7cXy9G6bI79q0O
         gg3cRY9h2lrwck0xNGvgIBkJ1nnWTHonLpZipfb/BAtgjMNZ83grgQNqtZTASd+Nvv3+
         BwgN1asFHu9fGY4nkvRw3EGg11dbG3SsZU8EBH/1jMkkx+ErN8rsB4mCyD+MKriu4yl1
         Yjha4V66Me6m8j+yRG2TPkpNsI9gFbRTAXj97BkfNtJO5LVwfh5I3GmD8aPMIMlFnVps
         l2Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717610547; x=1718215347;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=M9SO7Ch25aQfA8i/owYJyyVvDD+BzFqXZ8GIKigrNPI=;
        b=F7qZXxzPbLGQIwGrwNi8UyCEuPC1YkQgoqsMcl0w0dimRUhvYXye/WDuYzO9HWzlLu
         K2WhNdO3WHEbj3vAdWNEy+M8WXuhqG7jE42hgdLHJBKya45fTiW06Td2jobTMEHuCoyK
         rvD1dx0S3SSucJv0o2qHzYYIyLC9oXVc8rkyfjuy6imBIaywYOqxpF/SvyuWwIRd4rjw
         dt8rfC6P/28AbODeK8XzM0i5XjmNs2CJ874tsQCh81plZbzZg/Ofq/Eu5ht77mSJ1aUe
         VtqJaHdtNOPGCf71VcwEkihj7cxnBtpHq5Sfcp+LbrMdjEIRo09wBEPp4NEA3FpTZDmX
         6BEw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUN/uOOyl6j/qZSxNCXikCsL84aRGRZsjhvalvyfk/c7y0wUB8w4qEbzTO/yI4N7FicUkFqHUGafH+vfklrFeJKMadLYCYgRw==
X-Gm-Message-State: AOJu0YzddFayLEhB3D1wyhgRS+RtRdR8HWPeC1iED02yltOEjfJlDdeB
	KRFYONWUoyxAAxuffXZUI6TXeyz6wVQUb5VlruK1+9K0rHeYqb0q
X-Google-Smtp-Source: AGHT+IH6XBSA6K3Lz8Q2VnI2iWHekkOg875ytgNvDdElfK6G8IjIuE1xIBERwcvzz19E+LrfUBizfg==
X-Received: by 2002:a05:6820:22a0:b0:5b9:fae1:75b6 with SMTP id 006d021491bc7-5ba78f2ae0cmr3331108eaf.1.1717610547486;
        Wed, 05 Jun 2024 11:02:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5b02:0:b0:5aa:18dc:5145 with SMTP id 006d021491bc7-5ba92de1e16ls46890eaf.0.-pod-prod-04-us;
 Wed, 05 Jun 2024 11:02:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXxVqKZlnawkG6lWdrbo/NCAhVMUQCqPb0XW2uvxSElnJrMYwDgtBkH6s/giOfC47YWSPNttxL5t7cY6GHlq9xcbq6pgGYvHKGaLQ==
X-Received: by 2002:a54:451a:0:b0:3c6:943:e0ad with SMTP id 5614622812f47-3d2044de765mr3227006b6e.51.1717610545660;
        Wed, 05 Jun 2024 11:02:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717610545; cv=none;
        d=google.com; s=arc-20160816;
        b=fTW8QYbhSwwHlY15t1xakUXTbelu/LQm1XcAzzUzTD+wGJu/j9wDzBdsmc0PstBiuZ
         yDS9G9gJ8FAshbeU95SouGRz6dFZ5z2rJfHl0LVEStSRFT2/RyyhjQujmER2TY3eNIF+
         oF1mxWUxtUC78ZMfNi9TQ4iNSNl4B2BXr0YtUpZTo/8jcsAxtZo0yYPjqwA/mDelDs2l
         CAbF5aGOVxBzZb5Q8W66Cyw+PyFE3Z5XlpX+lVQjCif94H7BPAUMKo0olzpmTaXVTNlE
         7oy416Ud4NLzZ95YFj7jfwYN4luRuI22aXhOpXsU9gUPsr51pan/uTJsXmQSMO3bmxIl
         UtNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=72XRH3fs16colXDnarHCupgoVHglpLyASO/xR+1nDMk=;
        fh=LToqKqEk+yzgCvOsxFtHwPCoP5FGiohf+vfJvPaMjsE=;
        b=w17PJOwOjHIZ2N/TVxAeloEqwlm1uXAwG7eXgEaHk+Shf25YFnUoj1YNGdVLKSPq/g
         K88mWUFpb3K3qb7VDwaNAmdb18+4ZYWRGZZ+3JYOe6czENVCn4JWMFXyaQhB5Gtj9Fpz
         nLtc+Q1O44+bCnLm7bn2eYU8JTwxMHSarBCRYKgVHok8m3U/4iXgVuHXzxDuifNd6kw4
         Mm2ZkonJ35bw1HfeqNaLgietXlt8TPjQlwyHRhWLvzIhV9VlVgFRfLpC0+glyTPPw+OR
         r1BmBIf05frRS1jGn7JcZT20cW/5HN+6yn9nXTX2wYkhxXflBuSw6J5vP4HKU2EKzTBz
         d+Bg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=k2FCUM3j;
       spf=pass (google.com: domain of srs0=pug/=nh=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=PUG/=NH=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4eafedbb0f5si391608e0c.2.2024.06.05.11.02.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Jun 2024 11:02:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=pug/=nh=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 0DA986188F;
	Wed,  5 Jun 2024 18:02:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B3F80C2BD11;
	Wed,  5 Jun 2024 18:02:24 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 56D38CE0A72; Wed,  5 Jun 2024 11:02:24 -0700 (PDT)
Date: Wed, 5 Jun 2024 11:02:24 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: rcu@vger.kernel.org, linux-kernel@vger.kernel.org, kernel-team@meta.com,
	rostedt@goodmis.org, Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH rcu 2/4] rcutorture: Fix rcu_torture_fwd_cb_cr() data race
Message-ID: <35f27cc8-85b5-4b30-8f7e-cbd29d3adb48@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <e14ba19e-53aa-4ec1-b58d-6444ffec07c6@paulmck-laptop>
 <20240604223633.2371664-2-paulmck@kernel.org>
 <CANpmjNOLuAZfjiNZqZ8zUrziOUiXw-7zOxRpOrwqYP_rgrEgJw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOLuAZfjiNZqZ8zUrziOUiXw-7zOxRpOrwqYP_rgrEgJw@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=k2FCUM3j;       spf=pass
 (google.com: domain of srs0=pug/=nh=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=PUG/=NH=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, Jun 05, 2024 at 09:56:41AM +0200, Marco Elver wrote:
> On Wed, 5 Jun 2024 at 00:36, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On powerpc systems, spinlock acquisition does not order prior stores
> > against later loads.  This means that this statement:
> >
> >         rfcp->rfc_next = NULL;
> >
> > Can be reordered to follow this statement:
> >
> >         WRITE_ONCE(*rfcpp, rfcp);
> >
> > Which is then a data race with rcu_torture_fwd_prog_cr(), specifically,
> > this statement:
> >
> >         rfcpn = READ_ONCE(rfcp->rfc_next)
> >
> > KCSAN located this data race, which represents a real failure on powerpc.
> >
> > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > Cc: Marco Elver <elver@google.com>
> > Cc: Andrey Konovalov <andreyknvl@gmail.com>
> > Cc: <kasan-dev@googlegroups.com>
> 
> Nice find - was this found by KCSAN's weak memory modeling, i.e. the
> report showed you that a reordered access resulted in a data race?

If I remember correctly, yes.

Even on x86, the compiler is free to reorder that WRITE_ONCE() with
unmarked accesses, so one can argue that this bug is not specific
to powerpc.

> Acked-by: Marco Elver <elver@google.com>

I will apply on my next rebase, thank you!

							Thanx, Paul

> > ---
> >  kernel/rcu/rcutorture.c | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/kernel/rcu/rcutorture.c b/kernel/rcu/rcutorture.c
> > index 44cc455e1b615..cafe047d046e8 100644
> > --- a/kernel/rcu/rcutorture.c
> > +++ b/kernel/rcu/rcutorture.c
> > @@ -2630,7 +2630,7 @@ static void rcu_torture_fwd_cb_cr(struct rcu_head *rhp)
> >         spin_lock_irqsave(&rfp->rcu_fwd_lock, flags);
> >         rfcpp = rfp->rcu_fwd_cb_tail;
> >         rfp->rcu_fwd_cb_tail = &rfcp->rfc_next;
> > -       WRITE_ONCE(*rfcpp, rfcp);
> > +       smp_store_release(rfcpp, rfcp);
> >         WRITE_ONCE(rfp->n_launders_cb, rfp->n_launders_cb + 1);
> >         i = ((jiffies - rfp->rcu_fwd_startat) / (HZ / FWD_CBS_HIST_DIV));
> >         if (i >= ARRAY_SIZE(rfp->n_launders_hist))
> > --
> > 2.40.1
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/35f27cc8-85b5-4b30-8f7e-cbd29d3adb48%40paulmck-laptop.
