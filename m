Return-Path: <kasan-dev+bncBAABBOEX5L5AKGQEWSII7OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id DF8E42650AF
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 22:25:29 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id p43sf4971199qtb.23
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 13:25:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599769529; cv=pass;
        d=google.com; s=arc-20160816;
        b=MHPNE2SAJMvj+IjCWS49eZN9YBaihd7WLxkC3EqKbqybTyF2rOILdsWZQE6BzbwLO9
         JOPAkaumbrl0IZFYvUAt1I8z/cOcKTfEPrHU237pZ+SGBwZ7BRB05YIAT0hcUk7V6UFE
         eVT3xmfn7fRrBl8TEvW8baYRtOdw2aCmZvtAodUGAwHtpc29iwHl2XB7Oksb5uQGSAS4
         X7ZeWLceEeLr1np0DBzCo7vqanU8hIUhDjG0mfFGj1I0sxbSp3fuEtWskXvfLcoDeoL6
         vDxU+rebKAf2cLEuPFJINmHCGBhuukF1YePsSYMjQL7HqQ3o+OQbpHfGoCVOsaKOc/m0
         DpPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=AcgzGMtlLyNLEKO4mQP+4NEwVvugnfWXDKsfOFhjwpw=;
        b=tMOuJ1cv4PlXztY0TF0Ok0ZQuSd8tM5XzpswdIL5zFM15YfZ3TqhBAU7pikkgr71Nu
         Lcw5T5PXVk2CFr+bXD8LcnlgBIw3p1AoxQRQ+evPp21xsYnKkij4r91KoG25BXOp7rBI
         iUnbfCNRKV5nkFtIcLzMW2pYr1YYK61S885fwAZuJxdMm2YM8Z3kaRmc34TdkYF/hNFR
         XOTsXIBdq3VILwGTBFmeqoxuktrBnuxGJFfwuSI/eZduETZw+xGsgo9nOIHnE7H2fOnm
         fiVyzKIYV2nbqqts82u9or+yDr00VPr4et6iDw4ldt0Zt+KRyDvml7Hjzxl/OWYnB6c1
         PnFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=doPdBnJs;
       spf=pass (google.com: domain of srs0=fq9y=ct=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=FQ9Y=CT=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AcgzGMtlLyNLEKO4mQP+4NEwVvugnfWXDKsfOFhjwpw=;
        b=TGIi2NjkM4Lf06a9RgGATvILSHakPkM1ItQ6WcnBKetczrZICcKVlEbE8sm7a0grxU
         mNrHhih0Oz3C6OGnkoo1jKhK+kvLg5LhRp+FzVGNSd0NZAPUlhPo1EL+AC8xkACYqmmx
         DwDjGhDEzdhFjz/GXbqD8yW1RmqzWOWhRrCAlk9cMUCmGghIKm+q/cpOQFqcl/+CsWK5
         YVEiwB551aRlwAzRHVwA+gzJC+XdZyP00h92mBaAZTdZULEePtVauzm7PWp0NW7PrkiT
         OBWy52ZWw18O1jn39m/470ZSOzLyVYfEA9LGmB0sACzxPV8rUM5XDSLEYihpf1BZcnx8
         ye1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AcgzGMtlLyNLEKO4mQP+4NEwVvugnfWXDKsfOFhjwpw=;
        b=jgdlWeZ298qO+HiCE+w/U+F+2dyIQgAjmZs/4mV/PBNQHgC2c8uBY78neoy/Ii3ihl
         vY6dP5dc0nerxFNjN749FuJ5xxDaC58O3Yn8u+SbqM8flWWl1bqkDMvkcXf4P6pk5fGC
         R0MUoqWmSH2sah0sGko8pjW9Es57Dv/W9nX9AEDtum4h1NS3skpN/dQ/675zFdqo1fwE
         8AeWfNWRgi8v8QEKDYwNBguynZCNSYu+0lzY7nYoiQMlEL+Xiq4YnJkt9aLIfWYcse6T
         83VjHu9paF8rfMcDdquafiwOfjvZr8O+fijQ0R/04eid/T7v5elr5b3yDWFj+c+kOo5V
         5xBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5329RKCp2Tl4RNxeiVw9+WYBzqkMC5aAo9lB3OAiINcYO/+Ogwkf
	0YX+eINYCUgUCX5jYkS1ODY=
X-Google-Smtp-Source: ABdhPJyzNMp65o5Co9pb8SwYGrTvYu1YKQOPPPQ7ygL/tMax6dYBUK5smvzMxU9tsTMgMURDwJc1lw==
X-Received: by 2002:ac8:7414:: with SMTP id p20mr9842379qtq.128.1599769528998;
        Thu, 10 Sep 2020 13:25:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:23c3:: with SMTP id r3ls2977923qtr.11.gmail; Thu, 10 Sep
 2020 13:25:28 -0700 (PDT)
X-Received: by 2002:ac8:33ec:: with SMTP id d41mr9836097qtb.390.1599769528611;
        Thu, 10 Sep 2020 13:25:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599769528; cv=none;
        d=google.com; s=arc-20160816;
        b=DG+/vdBM14ROaIto1JjvZ3FTc8NOJ54qtMMJqfWLqAAlcS/sAzWYEj0GsoC8GxUOYC
         /elN3pJBjRyGmIbo6PRBYd/UdYPZidxtL48J2zQ1RSG3Dg8efkyaMiYQ7R6u7PEnIs4O
         K0LqihJAbYfB88+IeyMLpL8TJmyazsof+6pUe7xe4dyryOoyOVtZ5fC+4ehGXygKGPVb
         V9OKQ23L11Qb+s9VSQtCFx9BFOcZHvcdJEAJqERhJ0//usHL+Tp2DX93H4Uodn/Dj77w
         XnA6ns6pMVXqWHn10G9Sh/3CyCQJ4RVKRSesgpp5yaN9MCzPwMEvP7tMHfZ2Xk3yHLQ0
         c+ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=pcMZpcyT0RX6WRJ/eVgBw1q/30QSiMDMGqssPVfjeUk=;
        b=JACMDViDGJuD7WsTz/Wm3pZkq1hDaDcVJnJ0e6E4Dh9TOH68dIp+5CIk/9A+vYuvBu
         MhKd2QOjC814p3lbflh3zOJPOrXVF/iFdh44SZanICZFiJ+bqWwZKopFNdssMkT6rH1S
         fs0HeDDtfqujmuiQofK6sJOwXDVwOLfiIAQh4VPyJNgAjxT/Axh5SV8FSs9bK354ZCZS
         sa7uc15JFp3ug6QKsOrAFnAgXgl19WouKMP1W4fmvjsvtyrMWWQQQBqehlq9rUOYMtt9
         SNYYqz65pVNmIbOdGRt8JXhIB0y3Cr12JB1AUlqNjbYNDDT3Zek1jxlZUSn+u3RrKJg9
         0NaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=doPdBnJs;
       spf=pass (google.com: domain of srs0=fq9y=ct=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=FQ9Y=CT=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a27si1769qtw.4.2020.09.10.13.25.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Sep 2020 13:25:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=fq9y=ct=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 4E83E20829;
	Thu, 10 Sep 2020 20:25:27 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id CF0923523080; Thu, 10 Sep 2020 13:25:26 -0700 (PDT)
Date: Thu, 10 Sep 2020 13:25:26 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Pekka Enberg <penberg@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>,
	Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>,
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux-MM <linux-mm@kvack.org>
Subject: Re: [PATCH RFC 01/10] mm: add Kernel Electric-Fence infrastructure
Message-ID: <20200910202526.GU29330@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200907134055.2878499-1-elver@google.com>
 <20200907134055.2878499-2-elver@google.com>
 <CACT4Y+bfp2ch2KbSMkUd3142aA4p2CiMOmdXrr0-muu6bQ5xXg@mail.gmail.com>
 <CAG_fn=W4es7jaTotDORt2SwspE4A804mdwAY1j4gcaSEKtRjiw@mail.gmail.com>
 <CACT4Y+awrz-j8y5Qc8OS9qkov4doMnw1V=obwp3MB_LTvaUFXw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+awrz-j8y5Qc8OS9qkov4doMnw1V=obwp3MB_LTvaUFXw@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=doPdBnJs;       spf=pass
 (google.com: domain of srs0=fq9y=ct=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=FQ9Y=CT=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, Sep 10, 2020 at 07:11:41PM +0200, Dmitry Vyukov wrote:
> On Thu, Sep 10, 2020 at 6:19 PM Alexander Potapenko <glider@google.com> wrote:
> >
> > On Thu, Sep 10, 2020 at 5:43 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> >
> > > > +       /* Calculate address for this allocation. */
> > > > +       if (right)
> > > > +               meta->addr += PAGE_SIZE - size;
> > > > +       meta->addr = ALIGN_DOWN(meta->addr, cache->align);
> > >
> > > I would move this ALIGN_DOWN under the (right) if.
> > > Do I understand it correctly that it will work, but we expect it to do
> > > nothing for !right? If cache align is >PAGE_SIZE, nothing good will
> > > happen anyway, right?
> > > The previous 2 lines look like part of the same calculation -- "figure
> > > out the addr for the right case".
> >
> > Yes, makes sense.
> >
> > > > +
> > > > +       schedule_delayed_work(&kfence_timer, 0);
> > > > +       WRITE_ONCE(kfence_enabled, true);
> > >
> > > Can toggle_allocation_gate run before we set kfence_enabled? If yes,
> > > it can break. If not, it's still somewhat confusing.
> >
> > Correct, it should go after we enable KFENCE. We'll fix that in v2.
> >
> > > > +void __kfence_free(void *addr)
> > > > +{
> > > > +       struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
> > > > +
> > > > +       if (unlikely(meta->cache->flags & SLAB_TYPESAFE_BY_RCU))
> > >
> > > This may deserve a comment as to why we apply rcu on object level
> > > whereas SLAB_TYPESAFE_BY_RCU means slab level only.
> >
> > Sorry, what do you mean by "slab level"?
> > SLAB_TYPESAFE_BY_RCU means we have to wait for possible RCU accesses
> > in flight before freeing objects from that slab - that's basically
> > what we are doing here below:
> 
> Exactly! You see it is confusing :)
> SLAB_TYPESAFE_BY_RCU does not mean that. rcu-freeing only applies to
> whole pages, that's what I mean by "slab level" (whole slabs are freed
> by rcu).

Just confirming Dmitry's description of SLAB_TYPESAFE_BY_RCU semantics.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200910202526.GU29330%40paulmck-ThinkPad-P72.
