Return-Path: <kasan-dev+bncBCMIZB7QWENRBBOCQ7ZQKGQE5FQEUYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C5CB17B66E
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Mar 2020 06:35:03 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id j19sf843367oij.20
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2020 21:35:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583472902; cv=pass;
        d=google.com; s=arc-20160816;
        b=yy9RNWxO4VzQJYgaspgclPPNsMGn+Q43zKNjCvLgpULDxzYJ5Ooa4c/uQ8Du5UU7l/
         rMFjaKzfgvwToLFsc/pXAnjqg7IamVGmAsszJ9ZjFQz+EjVcxLWzVDB4pXLfTXWHJ/cv
         vTrYAVN+lPH34F3bmFJudfvK5m119m1rnFskwfj9kaQtTAQzqEmASpcFRjaFz7VfHDWK
         QBIfvqWIe8b6oHsz20XxfnCptB54pwrfCxp53OATCEVHtZ52eay7hDSQ2ax4IQJvRwj0
         PrydT3lfd5iihVprxM6lKryluJoX4OS8WvQnq8hrzGjKaw1dMsNjNF0xMt5wGUh3II37
         1vzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+PSxIIgfRQB9S9kukRHWEQMqn1rtLIJzmghiXppi3zE=;
        b=e3sfG1+WVWDgK8WGbcve3nYFVfaYnRwq9CFhUGyEQ9DsNHODVJLWzXMu3BedQtQ/NZ
         wScRbhYu8e4R+mYAefM6azupViWB+EKnOBkNpqwvcqCzZnsYj4T4NTQStrKj1V8Uasau
         Ht6FhCUp53eQSu83zHAepQMdRecroAXf2ZoP+PTR247vX8ZC6zixvPHT7wJHx/7fnYMY
         IdLjV0wx/2EVb1i2oZUFTVv8wNclB6Lmd1p3Nokhu2OCThYtuq+FQEj2i14DsEZ04ovj
         k/OSiq6QxqKhRrufaWnyM3l7EfikhgsSZfkuZOPIyF3hwkX7dpSGv300n1hCok7uie1m
         M9mA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WadwKtqj;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+PSxIIgfRQB9S9kukRHWEQMqn1rtLIJzmghiXppi3zE=;
        b=Hu2VmuO/gyOIbgvRFNum/r/TLmk9VCzZKrxnbspuAHi/XU1SVuuWfzyjUg+FFSwBRZ
         qKHFRIzQ6OXYv8L1+zEb4A/yzYHMCkRSHxXSJ3H0wD8Th7oUF89H59oLs1hr5jUNpL75
         VjGBLXEYHPsJBNkh0mtX9w44K9VlU05en+8pzAk545/G8SEPXqq3bbzhykN1QDOVI1MP
         9lwPvTtd4FrgLVlvL36VYfx01YuP73Q4Nhtbj3dndNuqc5TdA6acYXmIevWg1V//PaNG
         lwsZ5EVYBX8dBIhcUDxWbVzNq8RlDtMtcfTyVmUynegX92I4D1WIeFJaGesjXWS35/P9
         Fngw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+PSxIIgfRQB9S9kukRHWEQMqn1rtLIJzmghiXppi3zE=;
        b=mDs0+Xa60UuxMEJRZBjcmsLcfdrWmdOcG9txkkKa5LXAQ+Z65rN3MwVNCDB6Kab6Ai
         I/v5HoJT1QVkdh5p86x4jX8RivVvWK5IZniS7iMKIgcHiEDxWeZG7HuAym3l+2sBZzm8
         WVPr38fZob/99tYjfQ2ROA5PwezIEUqEXcderU91ujjk+FHy3aKwRDx+nFEoCnYztO80
         OthmHEWM71YobZ+IQKBb6lDrz+NvzLdk4DDQLN5WCTJ7c0cJoGNZ/NJv2g6DOZRWqsAU
         YYBCIS5an4ZKq53STDAVtfcR+AwMT4NjMGPAlHb+LH5co3GEOjwrqE3tII+ero9cA1PB
         i8MA==
X-Gm-Message-State: ANhLgQ27wZtxuTDqSAJHOyOCubt8x+v8Jp2S88H7NsgeK2N6SLxYw3nC
	xMm5v/tKpCSlKJ/AjIydow4=
X-Google-Smtp-Source: ADFU+vtYscSRyb84dF3vXTAqfgffu8LE5kvmRE0c0aKXgwYYyWESXIo6ymyUeix8rm6N8PmJL7KsiA==
X-Received: by 2002:aca:1c0d:: with SMTP id c13mr1440321oic.94.1583472901885;
        Thu, 05 Mar 2020 21:35:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:51cf:: with SMTP id d15ls396838oth.11.gmail; Thu, 05 Mar
 2020 21:35:01 -0800 (PST)
X-Received: by 2002:a9d:62cc:: with SMTP id z12mr1207026otk.119.1583472901403;
        Thu, 05 Mar 2020 21:35:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583472901; cv=none;
        d=google.com; s=arc-20160816;
        b=q27icnvrrsBCp5d6wEljAweB9H+27GeGKYLCRByX2U8XoGX78qovfrGaBY3M2SJzPu
         b0YeHID1NUhoz21ufiODo7jwKmGkUw9col8EN9guFpNsJre6hkNTycCKd1RBMHQwcdqR
         dbBUEfEPIFxRSrx7NHAwzaRIIwKv+KOJMgyoMlTv0/meEqGFhOZ1EIG1Y0NPJpY/VYCP
         RVzO53aAemA48cN+cSiVFKxrSLWMYhY0o4Xs3IXGANCWo4CHAfxxoVbN/Pp7x+2BYPgM
         +nQzvTiQuH+N0tkbmBjIWXNtIuPxRLftalpYCzEDgH5SaqidGopTL/WWB9woNsqVDWzt
         MzSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BOcsWIjUk5EkoUJHKNZz0adMiC95AwogUHWj+FYqu30=;
        b=nm+G6TBH6gPSppUZ/DbAFUMUVLIOx8eRzP2jgU+4ao3h3FuPCqazHJJZVFvah6DGoK
         nY7at4biAToa57WC8n9VYhI6FgvGuZnwwcnmTmig8mPL7vZvFHhRuZs5akpXXe+Brtxu
         2oaAd/UhrRrOCBZ1boaacf9NJMK7PMfddNNS/zK/ILXCXzgvkNbiQ+ld30txRPaQGmH0
         rCLQ+J6Fd4sYC12gnVTnimbeVEUyCql59C1MHo715b3wnekoXQoBJ7MskGswtjB4P0+d
         430fIBUE+Zhspfs7U6VTG84tdrg5Ym9INHSmPkYtWRrlo0qKcJvF2Vrci6ljI9c8CVDt
         O/Ag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WadwKtqj;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id n22si74824oie.0.2020.03.05.21.35.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Mar 2020 21:35:01 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id a4so893207qto.12
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2020 21:35:01 -0800 (PST)
X-Received: by 2002:ac8:3533:: with SMTP id y48mr1534846qtb.380.1583472900550;
 Thu, 05 Mar 2020 21:35:00 -0800 (PST)
MIME-Version: 1.0
References: <202002292221.D4YLxcV6%lkp@intel.com> <20200305134341.GY2596@hirez.programming.kicks-ass.net>
 <CACT4Y+apHDVM7u8f660vc3orkHtCXY+ZGgn_Ueu_eXDxDw3Dgw@mail.gmail.com>
 <CACT4Y+ZuGLqNaB+C+VJREtOrnTZVyHLckdAHRMSHF3JMDTg_TA@mail.gmail.com>
 <CACT4Y+ayJrm6ZrkQwybGZniP-xwtxjkmMpYVdCoU4mKzDUWydQ@mail.gmail.com>
 <20200305155539.GA12561@hirez.programming.kicks-ass.net> <CACT4Y+ZBE=FDMjXxOkmtn0rd8oRWvNaBGnRgXKKSjuohuqd3=A@mail.gmail.com>
 <20200305184727.GA3348@worktop.programming.kicks-ass.net> <CACT4Y+axD4ZjEPdekgVkkUGu6V0MMR9Q1RNcVA9v6dOSi8FHzg@mail.gmail.com>
 <20200305202854.GD3348@worktop.programming.kicks-ass.net>
In-Reply-To: <20200305202854.GD3348@worktop.programming.kicks-ass.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 6 Mar 2020 06:34:49 +0100
Message-ID: <CACT4Y+Z=qy9MjhqOMNr2kYLwHy=gRXo0yqHBWBZpX2foRJBpMA@mail.gmail.com>
Subject: Re: [peterz-queue:core/rcu 31/33] arch/x86/kernel/alternative.c:961:26:
 error: inlining failed in call to always_inline 'try_get_desc': function
 attribute mismatch
To: Peter Zijlstra <peterz@infradead.org>
Cc: kbuild test robot <lkp@intel.com>, kbuild-all@lists.01.org, 
	Thomas Gleixner <tglx@linutronix.de>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WadwKtqj;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Thu, Mar 5, 2020 at 9:29 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Thu, Mar 05, 2020 at 09:13:26PM +0100, Dmitry Vyukov wrote:
>
> > > Right, but then I have to ask how this is different vs inlining things
> > > into a __no_sanitize function.
> >
> > We ask compiler to do slightly different things in these cases. In the
> > original case we asked to sanitize user_mode. If we have a separate
> > file, we ask to not sanitize user_mode. A more explicit analog of this
> > would be to introduce user_mode2 with no_sanitize attribute and call
> > it from the poke_int3_handler.
> > Strictly saying what you are going to do is sort of ODR violation,
> > because now we have user_mode that is sanitized and another user_mode
> > which is not sanitized (different behavior). It should work for
> > force_inline functions because we won't actually have the user_mode
> > symbol materizalied. But generally one needs to be careful with such
> > tricks, say if the function would be inline and compiled to a real
> > symbol, an instrumented or non-instrumented version will be chosen
> > randomly and we may end up with silent unexpected results.
>
> Right, so I'd completely understand the compiler yelling at me if the
> functions were indeed instantiated, but exactly because of the
> force-inline I was expecting it to actually work.

But then the compiler will start to silently and randomly sanitizing
functions that developer asked to not sanitize and not sanitizing that
developers asked to sanitize, without any developer visibility and
control.
It's just happens so that in this single, very particular case it's
what you would need. But there are lots and lots of cases where it's
the opposite of what you would want.  Say, consider, poke_int3_handler
gets inlines in LTO build, and compiler says: you know what, I am just
going to silently ignore your no_sanitize attribute to give you fun of
re-debugging the issue you think you fixed ;)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ%3Dqy9MjhqOMNr2kYLwHy%3DgRXo0yqHBWBZpX2foRJBpMA%40mail.gmail.com.
