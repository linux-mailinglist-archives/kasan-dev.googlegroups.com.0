Return-Path: <kasan-dev+bncBCJZRXGY5YJBBT7YQCCAMGQEHW532VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AA9D366E84
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 16:53:05 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id c5-20020a0ca9c50000b02901aede9b5061sf1730417qvb.14
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 07:53:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619016784; cv=pass;
        d=google.com; s=arc-20160816;
        b=OQ/KW9fty/ViKdJOiu9/fwMlFAdFWOcO3iuKsw0ppxBSBZlRTOReZe9c04WspofZGW
         +6U1gQS7LBEKflWW5uEori3t/xHXkV8GyFq8JGY3ruhDEdWw6zX22jz3gijHOyAJb+ce
         Dni4rTXZs3CiHjGKDSgZufS0HjvuqOF270nIJ8UKruXr9SHZFRfj9/Y2nOyBSZA/QJnL
         0HB6qRoy4ANlasVWvbSSQ+KsGtWZMuls0Anp4Fxv+SU7APWcbSfnbrKfZP6n//Pi4USi
         XZ9fKMBhzQtKnICElU8KShB+cbm2KhQ0VjiOYPqwLHHkX1lDBRUjiWhrSJIREYkw7vgm
         Onmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=WX6FEsUndU60Dve4E8e/G/7pCpj2X6b+RpZFMUPVfcc=;
        b=y8G7o4f2u0yE4/lMr0xV5u+nnDukMSJtfLZO4ef6JidDrydAzw2qFDFi50Y+s7PJK0
         bPnbmjQKnUtLjeD4fHfjnkYiUXHlBb+xrAG3hDUJL0+yvkpd6c5hROt3yJg4U8T4gDx9
         Q77j/BoECWNgB6NqbLU0h1MmpQ4vc4jLE7w0hwByf6pmzZrhOd3V/xoXG136dL1Ttr1m
         JqTTS8EyIcPuuz9gOtlvqhK9QzVNBEBO3XMqmYfOp4nrUBEZvOg641Xv9fZJe6mwihvy
         kGMP+W0iTLxOkVlbGAAdUT2+7KG+6tjmNXu7k45IN1wbeUzcwVhV9KCiEiW6uMFoTn5H
         NvNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=d9Yfkhq2;
       spf=pass (google.com: domain of srs0=tqrp=js=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=TQRp=JS=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WX6FEsUndU60Dve4E8e/G/7pCpj2X6b+RpZFMUPVfcc=;
        b=ZwarG/MR/Kh9de5vmohOQj0O/C+exKXkPHV5nOGMP+Z6IvJ7t2RJ54mKSWT3JUeczk
         3GuD2wuLNzUqkCAEt3WCQFNw+h70N67egfpS0i1WO05H5O33Zt4tJA9fEsbXSwi1DPmm
         qVK06v00WlDJaFtI8OqRjRLt0o7PdJNfByH5gFCl9ca+xYBOhuWeRmPQsZTd3CdELY6H
         k0Ha77RLxLc45Zsyw4TIkmh53ybF5gEP2W9jGch16zEO19RDlDPIHHSExCQB+V3qsyLS
         oXU6XgVGp3sgL9uLRTDdRzC4kXd7XGcUZDP6X7nG/n9KwW/iHvx1ImOWW7X81h89NVpU
         USaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WX6FEsUndU60Dve4E8e/G/7pCpj2X6b+RpZFMUPVfcc=;
        b=ubzMbautNulKuxIzzPQU8zdQZRzTLZ2vphu/3LNn835BsKx6NEmQikNwS9k3UoG1rM
         ycWUXjNbbwMWgRUt22JBcQWmOT7kryiB5IA5LwgiTxd4/CHRBMKty5BaTBYTTb/ig7kc
         GOdzdyoY5ZsuCekEsRw4YjdwVQhjjD5v9N62PKyQ6whbaPTs4c+3tIsUj9YxT1Rfv7da
         kx1NWDeq1LYbAVCC0oyeyEB1wKY6ek/6I9V82m3bq2jk0JuPoAzJIUp6tpZL2wjBTisB
         P31WuylmxTdnkxUUphOv5Mjy939AOVDTsmdd0P3a11pgdow2XQWpCXjQliVkK8cUFA2b
         /4Ug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531AZvRq1ojepBeUBikNtAA7Gr+PoxXCrRu6O/66c4fryh9je1wc
	wFJXsFzUuiNu7NTjf/AL1L0=
X-Google-Smtp-Source: ABdhPJxBIFf9civxTD+FdY0Sw2U5MGiHyJ9AD33ehPVQMhKxdDYAOdTy2aCSSsk7N3zLjVdvdAWb5w==
X-Received: by 2002:a0c:c245:: with SMTP id w5mr33441984qvh.12.1619016784174;
        Wed, 21 Apr 2021 07:53:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:d91:: with SMTP id 139ls1368262qkn.11.gmail; Wed, 21 Apr
 2021 07:53:03 -0700 (PDT)
X-Received: by 2002:a37:bb42:: with SMTP id l63mr23668539qkf.127.1619016783649;
        Wed, 21 Apr 2021 07:53:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619016783; cv=none;
        d=google.com; s=arc-20160816;
        b=YfrUGcbQf6qzMZqWuqfnfyLRsW2yNvWAC13N0LtqdCbQXDhrhcH+dYn0/UASzJifpB
         BJ/NbMCUO631Nr3Lov/PDuTxlnvVSR6jXW6sI5GveGcxTTGQsZCLc8YecghXawgliOK3
         q//An05JcpYMyB1CJ6e7Z7sIt/tA5qUliFCM0HhhRfKd9SdhyuuFNPQAr7+T16swWN98
         WiR3dnKNhJRAnSDeM/U0WTR2l8igyLdvDW7HTdLgtR1Ghe4RZJaEudQRcaIlSBU46nMD
         j7v7RH0Q9trUvUhRBo+qOKsKzRXGy1Bs1fBCTSq7Pgk6UAJIA3LYVxfFIVekHUHj6UJq
         MYJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=x1fI9PzLouOe54Nk0C8pEcv62aSr5GyG78E7/Pxksfo=;
        b=nr6XHBEDhw7SOAayPG/O3Cen6ocmLz/NMzDGr/I+h96/lOwcKS52q2IDyWUFDjzwPM
         gMUwqczBetS9lLdEMJcZlHg/sI+o0kzuqmVNqkuD5ouyrogpVoHTq7F+FB0vJ3JtojOH
         dQPr5aSi1I4UWOR9wt8P4JhiTy+KjlfJbzYV107EAjQFNrNZVVuSAHsJTNv3GsY0o7uU
         ocF2GspvXvA/6yjDWu90tqjYhHQpMuTyS5Qi6RY7NTw32FYiA219+ECYKW3u42oBy3E+
         mVFGOcR1U8DtH7AlC1TkRX3UNe299xlb5gSuXLGAp+yRLKSHDesWu2fOkZiCUByEBvT7
         XQqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=d9Yfkhq2;
       spf=pass (google.com: domain of srs0=tqrp=js=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=TQRp=JS=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y8si126305qti.5.2021.04.21.07.53.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Apr 2021 07:53:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tqrp=js=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 77127613B6;
	Wed, 21 Apr 2021 14:53:02 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 23F335C0267; Wed, 21 Apr 2021 07:53:02 -0700 (PDT)
Date: Wed, 21 Apr 2021 07:53:02 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@kernel.org>, David Gow <davidgow@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, Ingo Molnar <mingo@kernel.org>
Subject: Re: [PATCH] kcsan: fix printk format string
Message-ID: <20210421145302.GS975577@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210421135059.3371701-1-arnd@kernel.org>
 <CANpmjNM81K-3GhDmzUVdY32kZ_5XOwrT-4zSUDeRHpCs30fa1g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNM81K-3GhDmzUVdY32kZ_5XOwrT-4zSUDeRHpCs30fa1g@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=d9Yfkhq2;       spf=pass
 (google.com: domain of srs0=tqrp=js=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=TQRp=JS=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Wed, Apr 21, 2021 at 03:59:40PM +0200, Marco Elver wrote:
> On Wed, 21 Apr 2021 at 15:51, Arnd Bergmann <arnd@kernel.org> wrote:
> > From: Arnd Bergmann <arnd@arndb.de>
> >
> > Printing a 'long' variable using the '%d' format string is wrong
> > and causes a warning from gcc:
> >
> > kernel/kcsan/kcsan_test.c: In function 'nthreads_gen_params':
> > include/linux/kern_levels.h:5:25: error: format '%d' expects argument of type 'int', but argument 3 has type 'long int' [-Werror=format=]
> >
> > Use the appropriate format modifier.
> >
> > Fixes: f6a149140321 ("kcsan: Switch to KUNIT_CASE_PARAM for parameterized tests")
> > Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> 
> Reviewed-by: Marco Elver <elver@google.com>
> 
> Thank you!
> 
> Normally KCSAN patches go through -rcu, but perhaps in this instance
> it should be picked up into -tip/locking/core directly, so it goes out
> with "kcsan: Switch to KUNIT_CASE_PARAM for parameterized tests".
> Paul, Ingo, do you have a preference?

I am good either way.  I have queued it for the moment, but will remove
it if Ingo takes it.

Acked-by: Paul E. McKenney <paulmck@kernel.org>

> Thanks,
> -- Marco
> 
> > ---
> >  kernel/kcsan/kcsan_test.c | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> > index 9247009295b5..a29e9b1a30c8 100644
> > --- a/kernel/kcsan/kcsan_test.c
> > +++ b/kernel/kcsan/kcsan_test.c
> > @@ -981,7 +981,7 @@ static const void *nthreads_gen_params(const void *prev, char *desc)
> >                 const long min_required_cpus = 2 + min_unused_cpus;
> >
> >                 if (num_online_cpus() < min_required_cpus) {
> > -                       pr_err_once("Too few online CPUs (%u < %d) for test\n",
> > +                       pr_err_once("Too few online CPUs (%u < %ld) for test\n",
> >                                     num_online_cpus(), min_required_cpus);
> >                         nthreads = 0;
> >                 } else if (nthreads >= num_online_cpus() - min_unused_cpus) {
> > --
> > 2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210421145302.GS975577%40paulmck-ThinkPad-P17-Gen-1.
