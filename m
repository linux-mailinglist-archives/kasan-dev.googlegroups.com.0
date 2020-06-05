Return-Path: <kasan-dev+bncBCV5TUXXRUIBBPHJ5D3AKGQEWESN5XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 114861EF6FB
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Jun 2020 14:04:14 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id f1sf11508822ybg.22
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Jun 2020 05:04:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591358653; cv=pass;
        d=google.com; s=arc-20160816;
        b=OoUYO6mtGGwJxbk2oeyVO/Eq5YSUSsQW4yA+acO5XKa1WS5o2SMgrHVV8JNxoSpE7u
         FaLWLKFUov+7Op1F4ymvvBWU08zUGfKuHm/4jpWYedzE9ypvVSjZ56RJ5rO+21LNnsfK
         bz0LrWMtRHx0D3f00eDOCk4KO9KJ+eSnJcqoIUiU+S8ckfFGBepxIGU1El8DcU1SpJqU
         4OrDzV4DZ4qcsYFWh/0iLi6ejw7WFBxELu9F1lflBcVWuCrwD/+GGQC+iARNJZLCoIf0
         4EJ1z4sKc7uKwPQXkiBOWHY7yz26Gp3EGSF0JlsMvw7wu7CuwNj9/HGWUKfqQmw/ZMxx
         sx4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=y/9ziUif8WtxWjnuhuIOWuv24UAZZqWigY/PoNc/Xlw=;
        b=VV5Zw9mjg/aJj5pQbYEppxCa79LWcEeG1MuKpbaBiUq6ajQ8z7Iay1tf4ycpZLvOUl
         oUuyVjMxqUsGPXbXcx410FYGPP+kza1bdO/XAx9dn/BagZkHbDiA0MqfcLgKsgmSTUbU
         wVpOYrbL2dYocadXoDLlOyBAbxXlEtjPdF4mj13jAZ283K7hhlHQn/KR4LDogIgzYTE8
         qDjX0qAZmi9IhYYT/MqZSbq+WPl8ll7LE4XDA/NkZh+QqxIB//icZzJO8JAJBDYL9DuY
         MoVYewj6Lz1ukJ0/UzTZMUEWAzNMqvPeFAtRLcA6neZSSx1CakPIe3KJl+MhdoswFPs6
         1i5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=KaWM5eMS;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=y/9ziUif8WtxWjnuhuIOWuv24UAZZqWigY/PoNc/Xlw=;
        b=R/Q0UtjEqTQ7gysi7VpqqIO+qavWhvp8BxrmB5aV9qaH9X0gPHonTXH5bPeSwws/rO
         2y53m6FFFDadFA1c7mP+88E3TcWweHYqTqhF4vUQpt4jg2JLCK5CsDP9NzK50wmYVgl1
         alD42aTMkDlzj6wNatk6i4ncUsMdPOwJUXLWLjZlCcvj9+WHB+SKwcoMaiepyPldQYsS
         F6zAvEdZtYtHOz/Sx524rbFQRT6TdLRBT/TJ/GwCHpA3T9ZuadwFTa3O0WGtg1TiL0Ft
         Y2UFhTGQwFipw+diP/XpKFMETtagqfm6zEajRQ5GzarcwtK5Wz/RhEQevIiB1ebgqfW6
         6V9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=y/9ziUif8WtxWjnuhuIOWuv24UAZZqWigY/PoNc/Xlw=;
        b=Zpjnx981crJzuuRmmuU9ZLfzr13pcAz3Go+dxMKQBhVf4tjzHgeiKwj01tmUcTMLdB
         QDVFcidX8WksPEBpjujQTrPGg0vZukAIYq9v0RHXrpH30YKyIQgHx25QazZvz91QvdYd
         aYt5G3l+23huPBv8uUPm6QAIM1mqjfsEd4TgQQXhFOnNvnNvrsM3Molf3BMRVooksKUG
         KaZa+n1z+mcog9XHFBtV2QROU30gkdwK0Y6MNcl+ib1NcLjKbVFD5XDhTV3NvLNOkPdt
         ZxsgvDwcDDHbcesfIR/+os0b1x1SGx5BGORB68vF1ZeYI23N90OLFyyssGSvCObr8t3d
         VHKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532jSKoo22Wq93xx/CoHzsM7aFPON/Wkj4grGnUMzZOomRkS2kZz
	Fepe1M0lLqBZVK+Gzp6Pqs0=
X-Google-Smtp-Source: ABdhPJw+8MnI6W4VvyIpXFHWQNMR7afroV4mBH3FGnsHNmXF8itXWEaqrMS9wblTWPuFsk4QLCIcsg==
X-Received: by 2002:a5b:5c3:: with SMTP id w3mr9127152ybp.15.1591358652942;
        Fri, 05 Jun 2020 05:04:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b18b:: with SMTP id h11ls655351ybj.4.gmail; Fri, 05 Jun
 2020 05:04:12 -0700 (PDT)
X-Received: by 2002:a25:ba13:: with SMTP id t19mr16619298ybg.8.1591358652642;
        Fri, 05 Jun 2020 05:04:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591358652; cv=none;
        d=google.com; s=arc-20160816;
        b=uLgc7FFAqigppPKPHgnU7PR+7WdCz7lhf/zXnZX9rGfBoOZvYzsioEMW/om1rXtnuk
         A8DxsUHuIWPtNRtRYzUoUvD5JNxlhKgM0JDI4SAkArM2ICdK18y118JE4xbFYJ4G4RzO
         x+ulAx3cwJaFgqQOJsg7KtH2sEEC2f+YaTIpDO1cYYf44lpL3DvY8ficjDG2VeUq3skG
         X0QfUU/xtDBK++piEmNFAgF1KDB5Pmzq1TU74PlkucXDhu8w8IVZiTZswXP0+rTDVhB7
         L/KQDdvACpTTTg7l1b/L9aQE6W4V7+Sj06ZZLyA5530qxhT2gn0CYc/ma2NitaBkgS4N
         CEbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KZz+sQK4LPHja6YFeoddpUkcV49dBXnT6yLG+sR4tCM=;
        b=bAaaJgboISQUKTjYUbjQ5mGUoOolHgcHxiTnRhJ0EyZlG2irPYXhfcCmRVePLE++iy
         o9+HJrvswO/dVpTCFdYOfEBTrHibyX9CqTVksx6LQZT7ClYmFpcHlLaxm3f1AEhSbksg
         Ap1WoEYlZqtafsNzR98jE3T9qin6fPBmaKVf53OB44SXQDl58SFQzTmhujqj+EOCsQ6A
         7LRLWSYP4kyOikTz6JaJvdyckXNOm7yq/nqfyquiItkK35m7Znx2he7CuAzsk9+abWwJ
         I55KnNBYOGMoKabee5OjGDyXkhbL8uhCB9amlrYtWv4hJW4WmHRMCpXpJZwUUherD9Q4
         nzdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=KaWM5eMS;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org ([2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id u126si659473ybg.0.2020.06.05.05.04.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 Jun 2020 05:04:12 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jhB4l-00084B-Iy; Fri, 05 Jun 2020 12:03:56 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id BFF74301A7A;
	Fri,  5 Jun 2020 14:03:52 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 8847A21A75216; Fri,  5 Jun 2020 14:03:52 +0200 (CEST)
Date: Fri, 5 Jun 2020 14:03:52 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>,
	Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions
 noinstr-compatible
Message-ID: <20200605120352.GJ3976@hirez.programming.kicks-ass.net>
References: <20200605082839.226418-1-elver@google.com>
 <CACT4Y+ZqdZD0YsPHf8UFJT94yq5KGgbDOXSiJYS0+pjgYDsx+A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+ZqdZD0YsPHf8UFJT94yq5KGgbDOXSiJYS0+pjgYDsx+A@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=KaWM5eMS;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Fri, Jun 05, 2020 at 12:57:15PM +0200, Dmitry Vyukov wrote:
> On Fri, Jun 5, 2020 at 10:28 AM Marco Elver <elver@google.com> wrote:
> >
> > While we lack a compiler attribute to add to noinstr that would disable
> > KCOV, make the KCOV runtime functions return if the caller is in a
> > noinstr section, and mark them noinstr.
> >
> > Declare write_comp_data() as __always_inline to ensure it is inlined,
> > which also reduces stack usage and removes one extra call from the
> > fast-path.
> >
> > In future, our compilers may provide an attribute to implement
> > __no_sanitize_coverage, which can then be added to noinstr, and the
> > checks added in this patch can be guarded by an #ifdef checking if the
> > compiler has such an attribute or not.
> 
> Adding noinstr attribute to instrumentation callbacks looks fine to me.
> 
> But I don't understand the within_noinstr_section part.
> As the cover letter mentions, kcov callbacks don't do much and we
> already have it inserted and called. What is the benefit of bailing
> out a bit earlier rather than letting it run to completion?
> Is the only reason for potential faults on access to the vmalloc-ed
> region? 

Vmalloc faults (on x86, the only arch that had them IIRC) are gone, per
this merge window.

The reason I mentioned them is because it is important that they are
gone, and that this hard relies on them being gone, and the patch didn't
call that out.

There is one additional issue though; you can set hardware breakpoint on
vmalloc space, and that would trigger #DB and then we'd be dead when we
were already in #DB (IST recursion FTW).

And that is not something you can trivially fix, because you can set the
breakpoint before the allocation (or perhaps on a previous allocation).

That said; we already have this problem with task_struct (and
task_stack). IIRC Andy wants to fix the task_stack issue by making all
of noinstr run on the entry stack, but we're not there yet.

There are no good proposals for random allocations like task_struct or
in your case kcov_area.

> Andrey, Mark, do you know if it's possible to pre-fault these areas?

Under the assumption that vmalloc faults are still a thing:

You cannot pre-fault the remote area thing, kernel threads use the mm of
the previous user task, and there is no guarantee that mm will have had
the vmalloc fault.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200605120352.GJ3976%40hirez.programming.kicks-ass.net.
