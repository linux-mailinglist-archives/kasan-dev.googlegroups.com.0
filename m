Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU4DS7YQKGQE3FIVS4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FC75142E50
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 16:05:56 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id m7sf12171556oim.14
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 07:05:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579532755; cv=pass;
        d=google.com; s=arc-20160816;
        b=PyDq7CzV1lwL38mDeMO9ek3PiPOw4rsKYIQIP7iL60P5JqDOHV9PpVQ2c4XUVZms6z
         51od7x49fFFrwj9RmOBbRgG8YILcwkzD+M/wiWCytw98I0SePHBhVbp0MbU/tnBS+w3R
         mqkAF855XA05pTBUUHoviq8r469XUSsI6sOQoqjV1lW2jVXh/tpcDQJpiTD9kVWANbDg
         sIZPt+lroTQkMW+W1OX118GnBgDvcSrNOEMsu8jhhl3fMtgLh+2IqVWLFdES+Qg8Z1Aw
         TrC87q4RAGWux+K1Vz7K0KuV9kDdBi6glvJwyAX8/6IqNEffcB3eO8s4mmC4PNPSa0VH
         XDMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iiGTjKrtc+i8bz9/RhSNPBosfAfYHAUn9CHBmWgUCVo=;
        b=llmNYAvKILSFAeet29LXhnFCktW0Nd9+zraiFuLPbZmVsPhmGv6nen+Zmbs1+76irG
         7ldYg6AZvr3nNNrZ+GLFGA5II9r2WFhZhSgZ/AORG9YjdAlf0RT38T/cD2TFW1T1yRhF
         6/GmgbNRY8qpkiJE6dGVoVcYV6o9LN+zxgHld0Lup9+3THEsymGpFEpGXYZ/RbFDtUjI
         rUCQacCRaDfh3LEv9CjWkHG6KDMG0MkTwn4g9n2J/wKPgMJ6RVOXbeXmAIVjVbZUYRkZ
         v4/CdikjTdT98m/9o6KIaENLLAYSVrBfT9+xtpcyQ7CJy47dQeELZYXqHPhtogc54Ln1
         qAPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tojSwQu1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iiGTjKrtc+i8bz9/RhSNPBosfAfYHAUn9CHBmWgUCVo=;
        b=qWfpFIL7EAjhUQTMRhEODa4UGcTNZ2UZkKw8MaGtUccKW8LC8Rt7whr0+QkzkWS505
         DmO0iXXELEzqCF3r2nKgy8XUy0twx1VPCxWHv2UmHF3nsoDU1CscpKu3EPDu4CMSpJFg
         CihjC0ehLLQgBmw4MW350vZwfSUgHIiOlTQj0Mrauy4atEERoLBgZgnge56rCZKbqnAw
         3dRGS1tYWu8IDrueP1BruQRJEcB+GuXMIOjr4zqPCe7H1VcZTOSCDwLD8iptLb8iMF4X
         JB1fsaavy78PYmPrWky9vRYmjTdG4axFh9k4nYYPWo7AgxavlyubK29WTRMk3wqwHkiZ
         /4Ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iiGTjKrtc+i8bz9/RhSNPBosfAfYHAUn9CHBmWgUCVo=;
        b=Ui3Bf+oji9DYv3aXOF0t5vocSPlIzAI2QAS+TMG2mU5g3BBeFHVbLbsXQTisMMDyzH
         CKd91aCDabCbdm/1Uqa+IfeMnSZaPi60iVRLCTrSsvA+8q2TLqSBeBIxMh7T4ltQ8lOj
         CEKhBwQqzKBtwZ0L7u2BT4HmF0zzGEg68ASttsovONzdHVDKI+jSRhAsLVK+mwCO7W1F
         oO+EV0vCGKUtuXe+DCK6plAipe8qX10rT6kLohOxKppeo5OndKi+722/9Jke0xQ6K4Va
         xCyakYlAEcLw+faF90+ftNn1prRYhzRaSs+Qg/BXUkb/gfPY7+3LFuQrSfBlKbpnXx3S
         9MVQ==
X-Gm-Message-State: APjAAAV476FM+S3LV8KLleBkqPLL8ub1CUuwiWDhrOHiF6U7ZZtBT8Sa
	RM0ZLcz7AW76UebqYdYVtG0=
X-Google-Smtp-Source: APXvYqwy//Rja95jxOx6wG85RZl7maWUr6+CEL/SjLXEaQXrLBXz2wYKzaZUBLUIAN87cR2OlBQJ9A==
X-Received: by 2002:a05:6830:2141:: with SMTP id r1mr16314513otd.39.1579532755412;
        Mon, 20 Jan 2020 07:05:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:611c:: with SMTP id i28ls5915571otj.3.gmail; Mon, 20 Jan
 2020 07:05:55 -0800 (PST)
X-Received: by 2002:a9d:7616:: with SMTP id k22mr16466488otl.364.1579532755018;
        Mon, 20 Jan 2020 07:05:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579532755; cv=none;
        d=google.com; s=arc-20160816;
        b=KM5hoJEAiuXz4W2FLQPYe1Gsrs2VYejDOHg1AkTG8DSKknM+99bzzh7vxvtVCy0aMS
         8E27vpktjr7GOlFFK/9MgAg8IQ9C97pcjgXgMOdVTo84ROfOGMc9tHOBb8hsmnxju2Te
         b6K8OPptTR2l2n7PhSDtKERYa21aVD5LgR86I53nK8c+qJ8RYARZ8p+nN/VmXxPA+ViQ
         nqwfr6nRkRNcSqHgHMd7+8PpcNGZaaBMAjwnCzpxpxKkUGZwGtA5uxgeaS74P0Nk01/P
         /v4CbkDKeDtPNMmnkdE1hP0QCB92bYGuTV65MaChCkbyVmKOcsxkfd65+jHteQ5BcMHb
         b28w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=smLCZaIYcQF0/52Z19iYa5thG5yG//BBZdb/jdacqzg=;
        b=DvWG91EaAxpYS0rAWKrJGfbu/iGruoFscX4E/VamM//KDEX7z6bfiK/iXnxkMGi6ic
         BtH1C3LvJDKxe2v24XYFLF60dWL+3L2gqcrfft6INyiUPxHrTMiWmSMy0hs92wjuSzP3
         jMKf8wyVzU2OEqeJ2DdCq2wHY2rhgn5Rjxqmx48ZXagH0jUHt6d7z4I67RI/LcDqGF64
         BAchlFvfF7EZSFxO86xmySZfwIPmaa5hhL+kajcmsKKwrRIC3zibCpThqnpArO3/zOkN
         xi0v+DieYgh/l5WtF7KPqPQywynDhm39Reqna4wwTHn30MFLJ30gTibW674pqTuFwRpj
         IbiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tojSwQu1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id p5si1513193oip.3.2020.01.20.07.05.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 07:05:55 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id 77so85oty.6
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 07:05:55 -0800 (PST)
X-Received: by 2002:a9d:7410:: with SMTP id n16mr16771057otk.23.1579532754151;
 Mon, 20 Jan 2020 07:05:54 -0800 (PST)
MIME-Version: 1.0
References: <20200120141927.114373-1-elver@google.com> <20200120141927.114373-5-elver@google.com>
 <CACT4Y+bUvoePVPV+BqU-cwhF6bR41_eaYkr9WLLMYi-2q11JjQ@mail.gmail.com>
In-Reply-To: <CACT4Y+bUvoePVPV+BqU-cwhF6bR41_eaYkr9WLLMYi-2q11JjQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jan 2020 16:05:42 +0100
Message-ID: <CANpmjNMZpLfNKLOs7JVxP-S7oWbkvyg=bt=uYGU30bMZXYtUHA@mail.gmail.com>
Subject: Re: [PATCH 5/5] copy_to_user, copy_from_user: Use generic instrumented.h
To: Dmitry Vyukov <dvyukov@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Arnd Bergmann <arnd@arndb.de>, Al Viro <viro@zeniv.linux.org.uk>, 
	Christophe Leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	Michael Ellerman <mpe@ellerman.id.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Christian Brauner <christian.brauner@ubuntu.com>, Daniel Borkmann <daniel@iogearbox.net>, cyphar@cyphar.com, 
	Kees Cook <keescook@chromium.org>, linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tojSwQu1;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 20 Jan 2020 at 15:52, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Jan 20, 2020 at 3:19 PM Marco Elver <elver@google.com> wrote:
> >
> > This replaces the KASAN instrumentation with generic instrumentation,
> > implicitly adding KCSAN instrumentation support.
> >
> > For KASAN no functional change is intended.
> >
> > Suggested-by: Arnd Bergmann <arnd@arndb.de>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  include/linux/uaccess.h | 46 +++++++++++++++++++++++++++++------------
> >  lib/usercopy.c          | 14 ++++++++-----
> >  2 files changed, 42 insertions(+), 18 deletions(-)
> >
> > diff --git a/include/linux/uaccess.h b/include/linux/uaccess.h
> > index 67f016010aad..d3f2d9a8cae3 100644
> > --- a/include/linux/uaccess.h
> > +++ b/include/linux/uaccess.h
> > @@ -2,9 +2,9 @@
> >  #ifndef __LINUX_UACCESS_H__
> >  #define __LINUX_UACCESS_H__
> >
> > +#include <linux/instrumented.h>
> >  #include <linux/sched.h>
> >  #include <linux/thread_info.h>
> > -#include <linux/kasan-checks.h>
> >
> >  #define uaccess_kernel() segment_eq(get_fs(), KERNEL_DS)
> >
> > @@ -58,18 +58,26 @@
> >  static __always_inline __must_check unsigned long
> >  __copy_from_user_inatomic(void *to, const void __user *from, unsigned long n)
> >  {
> > -       kasan_check_write(to, n);
> > +       unsigned long res;
> > +
> >         check_object_size(to, n, false);
> > -       return raw_copy_from_user(to, from, n);
> > +       instrument_copy_from_user_pre(to, n);
> > +       res = raw_copy_from_user(to, from, n);
> > +       instrument_copy_from_user_post(to, n, res);
> > +       return res;
> >  }
>
> There is also something called strncpy_from_user() that has kasan
> instrumentation now:
> https://elixir.bootlin.com/linux/v5.5-rc6/source/lib/strncpy_from_user.c#L117

Yes, however, I think it's a special case for KASAN. The
implementation is already instrumented by the compiler. In the
original commit it says (1771c6e1a567e):

"Note: Unlike others strncpy_from_user() is written mostly in C and KASAN
    sees memory accesses in it.  However, it makes sense to add explicit
    check for all @count bytes that *potentially* could be written to the
    kernel."

I don't think we want unconditional double-instrumentation here. Let
me know if you think otherwise.

Thanks,
-- Marco

> >  static __always_inline __must_check unsigned long
> >  __copy_from_user(void *to, const void __user *from, unsigned long n)
> >  {
> > +       unsigned long res;
> > +
> >         might_fault();
> > -       kasan_check_write(to, n);
> >         check_object_size(to, n, false);
> > -       return raw_copy_from_user(to, from, n);
> > +       instrument_copy_from_user_pre(to, n);
> > +       res = raw_copy_from_user(to, from, n);
> > +       instrument_copy_from_user_post(to, n, res);
> > +       return res;
> >  }
> >
> >  /**
> > @@ -88,18 +96,26 @@ __copy_from_user(void *to, const void __user *from, unsigned long n)
> >  static __always_inline __must_check unsigned long
> >  __copy_to_user_inatomic(void __user *to, const void *from, unsigned long n)
> >  {
> > -       kasan_check_read(from, n);
> > +       unsigned long res;
> > +
> >         check_object_size(from, n, true);
> > -       return raw_copy_to_user(to, from, n);
> > +       instrument_copy_to_user_pre(from, n);
> > +       res = raw_copy_to_user(to, from, n);
> > +       instrument_copy_to_user_post(from, n, res);
> > +       return res;
> >  }
> >
> >  static __always_inline __must_check unsigned long
> >  __copy_to_user(void __user *to, const void *from, unsigned long n)
> >  {
> > +       unsigned long res;
> > +
> >         might_fault();
> > -       kasan_check_read(from, n);
> >         check_object_size(from, n, true);
> > -       return raw_copy_to_user(to, from, n);
> > +       instrument_copy_to_user_pre(from, n);
> > +       res = raw_copy_to_user(to, from, n);
> > +       instrument_copy_to_user_post(from, n, res);
> > +       return res;
> >  }
> >
> >  #ifdef INLINE_COPY_FROM_USER
> > @@ -109,8 +125,9 @@ _copy_from_user(void *to, const void __user *from, unsigned long n)
> >         unsigned long res = n;
> >         might_fault();
> >         if (likely(access_ok(from, n))) {
> > -               kasan_check_write(to, n);
> > +               instrument_copy_from_user_pre(to, n);
> >                 res = raw_copy_from_user(to, from, n);
> > +               instrument_copy_from_user_post(to, n, res);
> >         }
> >         if (unlikely(res))
> >                 memset(to + (n - res), 0, res);
> > @@ -125,12 +142,15 @@ _copy_from_user(void *, const void __user *, unsigned long);
> >  static inline __must_check unsigned long
> >  _copy_to_user(void __user *to, const void *from, unsigned long n)
> >  {
> > +       unsigned long res = n;
> > +
> >         might_fault();
> >         if (access_ok(to, n)) {
> > -               kasan_check_read(from, n);
> > -               n = raw_copy_to_user(to, from, n);
> > +               instrument_copy_to_user_pre(from, n);
> > +               res = raw_copy_to_user(to, from, n);
> > +               instrument_copy_to_user_post(from, n, res);
> >         }
> > -       return n;
> > +       return res;
> >  }
> >  #else
> >  extern __must_check unsigned long
> > diff --git a/lib/usercopy.c b/lib/usercopy.c
> > index cbb4d9ec00f2..1c20d4423b86 100644
> > --- a/lib/usercopy.c
> > +++ b/lib/usercopy.c
> > @@ -1,6 +1,7 @@
> >  // SPDX-License-Identifier: GPL-2.0
> > -#include <linux/uaccess.h>
> >  #include <linux/bitops.h>
> > +#include <linux/instrumented.h>
> > +#include <linux/uaccess.h>
> >
> >  /* out-of-line parts */
> >
> > @@ -10,8 +11,9 @@ unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n
> >         unsigned long res = n;
> >         might_fault();
> >         if (likely(access_ok(from, n))) {
> > -               kasan_check_write(to, n);
> > +               instrument_copy_from_user_pre(to, n);
> >                 res = raw_copy_from_user(to, from, n);
> > +               instrument_copy_from_user_post(to, n, res);
> >         }
> >         if (unlikely(res))
> >                 memset(to + (n - res), 0, res);
> > @@ -23,12 +25,14 @@ EXPORT_SYMBOL(_copy_from_user);
> >  #ifndef INLINE_COPY_TO_USER
> >  unsigned long _copy_to_user(void __user *to, const void *from, unsigned long n)
> >  {
> > +       unsigned long res = n;
> >         might_fault();
> >         if (likely(access_ok(to, n))) {
> > -               kasan_check_read(from, n);
> > -               n = raw_copy_to_user(to, from, n);
> > +               instrument_copy_to_user_pre(from, n);
> > +               res = raw_copy_to_user(to, from, n);
> > +               instrument_copy_to_user_post(from, n, res);
> >         }
> > -       return n;
> > +       return res;
> >  }
> >  EXPORT_SYMBOL(_copy_to_user);
> >  #endif
> > --
> > 2.25.0.341.g760bfbb309-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMZpLfNKLOs7JVxP-S7oWbkvyg%3Dbt%3DuYGU30bMZXYtUHA%40mail.gmail.com.
