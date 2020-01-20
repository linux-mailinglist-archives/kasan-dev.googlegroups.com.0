Return-Path: <kasan-dev+bncBCMIZB7QWENRBEP5S3YQKGQE7JRUQAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8049F142E0C
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 15:52:03 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id d9sf12161216oij.4
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 06:52:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579531922; cv=pass;
        d=google.com; s=arc-20160816;
        b=orG3d4Croyoo0ao+Ua+AolcUby2GUvEAl0l9dJD6Bwu1VSRtrNFfc/giLh4h66OkCR
         X0PGnzOaVmwgsLB21Jb0LLru/Q21qQ05reuwn8fxzSRimG7PmiCnjhLWWU59+2ccpXoA
         3NDQvyStumzdE0+4qCLx5AryIkXXFT9cfSLJJwwIwwVG+TPiprYvw8soNNqLnfDE/v7c
         H9u10mWKPXHDvwDfqtXoTsJrJG8+JiHHsbhDUHdvPv36hD1ID5gZKGVsQcSmiqtkfcEs
         7ynYqRb0Fhf/HyonMxZL11WEupwvtoCIcQu/av0LhXwj+Pu8o328cjn3KHQD9GVtwHKZ
         rZvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rvoUyNWh9dY3Sn7faisCKtoW+bdcxrdaH7IwIn7/pvY=;
        b=hXrp3XJ6Cog4dJNg0LuiQWSQSvFjCsJ0wygurHqeOdtg4SRB8AlGapbYTE+PF2wmuj
         ERpS/gx3NvVnDWBSuSasF4O54RJTBARaErhyIh+STxbie58+lctMao11D4agf7+xraQb
         NZzTbJ45blv/UnfJhJxzw0Dgolxr5kLK5IZEFKVv6f2gjPk9GZHA8byEYAbpbkHHUV/H
         a5akQA5zHXGNIMAnlG3scFUBD1aBMruOboD6aAjSPYpyob/b98sbQ4dK01U5VBjczess
         C7XrmwBrCPaqoGMsiAStpYw9GdtKrHXwyWfCD28NUuamSzICRIqnihsZy6DvLQ9c7+kC
         1CbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A33lYU15;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rvoUyNWh9dY3Sn7faisCKtoW+bdcxrdaH7IwIn7/pvY=;
        b=Bq05JfUzKK6jRvm0e/bocRCtJtFoMuY6LqLLGu7Gn3A7e6Vq9bvta6727N9wjeXCXL
         1E6BUukQKRM//hH+xDIoADBAfluoA4P96jyFYjANB18OXr5GD9FZ/5x7uZNn2QDy3E5a
         zTUr46JaDBDxoQ8Tf0RaU7YLzRNDnApj/+/mTXAp46peiJP4fERlSSXYxqOGI7XbvtKG
         IfC6/aTvzllEdBaqe96X68ChfPUR3HNXhFk78/W8wDQn3CdScqpejK0SnL3BVtcTuUGD
         NyOEoq5iD9T6n7/Qn96ge8gAqy2MMSEhZvkZMDKevuS5ePM/WdzVUrsgQwsXeKr0O7An
         mJiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rvoUyNWh9dY3Sn7faisCKtoW+bdcxrdaH7IwIn7/pvY=;
        b=U6RqS77KlIUKuDrU5zuLB1Q5geoKzOi9tDEupWVxIPOIpvNQBnolPAUe1ubf0V54P7
         /SGGdE8pm1uyMg4GNd/jwCLOJTQ567skHiK1CU7rb5bXzx0HXrW471rPCvGfCagjrlnf
         NApmVFyXP8Irm2DLw+Mv+mtu6DKqN/FVFOTfsaR4llCfwzYqk/X9FXLTu+M22pWJ/aiw
         youFqUOcMZfTqBUcSJGe6EMGS60peXJwxHMJVAGpnrOdZS2y5CVsN78Fs5vjMVjzx3SR
         nZgoazT8ipcPGjBzXQY2J8mFmqYCT/pVI5scjeG3tDbA/TJJ8EVhLbSC6EcptNOBrCdp
         Z6BQ==
X-Gm-Message-State: APjAAAXqxQ/Kb2mMvcsdMeGyCX4sZXWb7u4ZeFpmMw9jg2hlGjNCpaI8
	KbFS8jdRWmpf5BIvoEcZ3Zc=
X-Google-Smtp-Source: APXvYqzbrlg5KVHFpmuiqL6PD+60g+oNZnDsZ9C1xEDvbovUD7SOKH31hwI1/y5q4YQ7zn7/XzlJTA==
X-Received: by 2002:aca:4309:: with SMTP id q9mr13185481oia.158.1579531921979;
        Mon, 20 Jan 2020 06:52:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:f515:: with SMTP id t21ls5798907oih.0.gmail; Mon, 20 Jan
 2020 06:52:01 -0800 (PST)
X-Received: by 2002:aca:2118:: with SMTP id 24mr8569414oiz.28.1579531921526;
        Mon, 20 Jan 2020 06:52:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579531921; cv=none;
        d=google.com; s=arc-20160816;
        b=afBNTqQeoVz4d3POLvYhx+jcyvY1MhqtXQLuICLxhPNsO5//qE7M+UVI7HitxNMTcq
         fq71by3GMSxKCjvGOb2YoLqm5n42YHVcumgt/ajopeiuwY2gn1BeI+epZBvs95qqaAJb
         SOlDQ8WezVVTTr4MwWu5gOf3U4ICM/ZKtvgIGafaR6FXoQgIT9ZZUcEkqm8ihvnDyo8I
         y7fFtC3q+v5AZ2q4EHUHefbuDw6Rj9GzLQ7QVHwHp8kYN2ebj6Aa689RYu8u3ivwWaIT
         ESdqzdmSa/6aK/d3BSHQL2n31NTsM3Jz7+pClmsDIOBv/ukla2bmqrNC/7o7zH3VX+FX
         NAIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9r7hLAzJ5XLPlBLlLKXbueYWLmX6BTOI1cJJxqLCq6Q=;
        b=jgJMSgXOzuf4CkhmpGRdTZaVBmyBKWDtBiyeMUnGkbYPZQkJraIhPTrWQtP9f5hgKZ
         OOyjSRZXGxZQPHVrA3WawB40KjvO+P60Kwi2mBNETJIxlaIKxyr3a/hCfS+AJNRktcBU
         tqhbGnniD/AuX66hyXcF8VwpXUwhhxo1Ku+i3WC15Tm+4XgSIBtED6wT9ctShBTJLAGk
         fdazBQEIVDj/JGziS2cAJA7H31QxPZJUK4srd3kGNT9l1EDxMOmcoyclemMCpmQBsWwY
         v4G2+QLNrISpVQ9rXk5dFgsvB5B0aiQ6+o153x5/MoOjFdHxShPK7npin+ljp8CClqwX
         ZRLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A33lYU15;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id q188si1026250oic.5.2020.01.20.06.52.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 06:52:01 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id 21so30353052qky.4
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 06:52:01 -0800 (PST)
X-Received: by 2002:a37:e312:: with SMTP id y18mr52657374qki.250.1579531920632;
 Mon, 20 Jan 2020 06:52:00 -0800 (PST)
MIME-Version: 1.0
References: <20200120141927.114373-1-elver@google.com> <20200120141927.114373-5-elver@google.com>
In-Reply-To: <20200120141927.114373-5-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jan 2020 15:51:48 +0100
Message-ID: <CACT4Y+bUvoePVPV+BqU-cwhF6bR41_eaYkr9WLLMYi-2q11JjQ@mail.gmail.com>
Subject: Re: [PATCH 5/5] copy_to_user, copy_from_user: Use generic instrumented.h
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
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
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=A33lYU15;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Mon, Jan 20, 2020 at 3:19 PM Marco Elver <elver@google.com> wrote:
>
> This replaces the KASAN instrumentation with generic instrumentation,
> implicitly adding KCSAN instrumentation support.
>
> For KASAN no functional change is intended.
>
> Suggested-by: Arnd Bergmann <arnd@arndb.de>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/uaccess.h | 46 +++++++++++++++++++++++++++++------------
>  lib/usercopy.c          | 14 ++++++++-----
>  2 files changed, 42 insertions(+), 18 deletions(-)
>
> diff --git a/include/linux/uaccess.h b/include/linux/uaccess.h
> index 67f016010aad..d3f2d9a8cae3 100644
> --- a/include/linux/uaccess.h
> +++ b/include/linux/uaccess.h
> @@ -2,9 +2,9 @@
>  #ifndef __LINUX_UACCESS_H__
>  #define __LINUX_UACCESS_H__
>
> +#include <linux/instrumented.h>
>  #include <linux/sched.h>
>  #include <linux/thread_info.h>
> -#include <linux/kasan-checks.h>
>
>  #define uaccess_kernel() segment_eq(get_fs(), KERNEL_DS)
>
> @@ -58,18 +58,26 @@
>  static __always_inline __must_check unsigned long
>  __copy_from_user_inatomic(void *to, const void __user *from, unsigned long n)
>  {
> -       kasan_check_write(to, n);
> +       unsigned long res;
> +
>         check_object_size(to, n, false);
> -       return raw_copy_from_user(to, from, n);
> +       instrument_copy_from_user_pre(to, n);
> +       res = raw_copy_from_user(to, from, n);
> +       instrument_copy_from_user_post(to, n, res);
> +       return res;
>  }

There is also something called strncpy_from_user() that has kasan
instrumentation now:
https://elixir.bootlin.com/linux/v5.5-rc6/source/lib/strncpy_from_user.c#L117

>  static __always_inline __must_check unsigned long
>  __copy_from_user(void *to, const void __user *from, unsigned long n)
>  {
> +       unsigned long res;
> +
>         might_fault();
> -       kasan_check_write(to, n);
>         check_object_size(to, n, false);
> -       return raw_copy_from_user(to, from, n);
> +       instrument_copy_from_user_pre(to, n);
> +       res = raw_copy_from_user(to, from, n);
> +       instrument_copy_from_user_post(to, n, res);
> +       return res;
>  }
>
>  /**
> @@ -88,18 +96,26 @@ __copy_from_user(void *to, const void __user *from, unsigned long n)
>  static __always_inline __must_check unsigned long
>  __copy_to_user_inatomic(void __user *to, const void *from, unsigned long n)
>  {
> -       kasan_check_read(from, n);
> +       unsigned long res;
> +
>         check_object_size(from, n, true);
> -       return raw_copy_to_user(to, from, n);
> +       instrument_copy_to_user_pre(from, n);
> +       res = raw_copy_to_user(to, from, n);
> +       instrument_copy_to_user_post(from, n, res);
> +       return res;
>  }
>
>  static __always_inline __must_check unsigned long
>  __copy_to_user(void __user *to, const void *from, unsigned long n)
>  {
> +       unsigned long res;
> +
>         might_fault();
> -       kasan_check_read(from, n);
>         check_object_size(from, n, true);
> -       return raw_copy_to_user(to, from, n);
> +       instrument_copy_to_user_pre(from, n);
> +       res = raw_copy_to_user(to, from, n);
> +       instrument_copy_to_user_post(from, n, res);
> +       return res;
>  }
>
>  #ifdef INLINE_COPY_FROM_USER
> @@ -109,8 +125,9 @@ _copy_from_user(void *to, const void __user *from, unsigned long n)
>         unsigned long res = n;
>         might_fault();
>         if (likely(access_ok(from, n))) {
> -               kasan_check_write(to, n);
> +               instrument_copy_from_user_pre(to, n);
>                 res = raw_copy_from_user(to, from, n);
> +               instrument_copy_from_user_post(to, n, res);
>         }
>         if (unlikely(res))
>                 memset(to + (n - res), 0, res);
> @@ -125,12 +142,15 @@ _copy_from_user(void *, const void __user *, unsigned long);
>  static inline __must_check unsigned long
>  _copy_to_user(void __user *to, const void *from, unsigned long n)
>  {
> +       unsigned long res = n;
> +
>         might_fault();
>         if (access_ok(to, n)) {
> -               kasan_check_read(from, n);
> -               n = raw_copy_to_user(to, from, n);
> +               instrument_copy_to_user_pre(from, n);
> +               res = raw_copy_to_user(to, from, n);
> +               instrument_copy_to_user_post(from, n, res);
>         }
> -       return n;
> +       return res;
>  }
>  #else
>  extern __must_check unsigned long
> diff --git a/lib/usercopy.c b/lib/usercopy.c
> index cbb4d9ec00f2..1c20d4423b86 100644
> --- a/lib/usercopy.c
> +++ b/lib/usercopy.c
> @@ -1,6 +1,7 @@
>  // SPDX-License-Identifier: GPL-2.0
> -#include <linux/uaccess.h>
>  #include <linux/bitops.h>
> +#include <linux/instrumented.h>
> +#include <linux/uaccess.h>
>
>  /* out-of-line parts */
>
> @@ -10,8 +11,9 @@ unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n
>         unsigned long res = n;
>         might_fault();
>         if (likely(access_ok(from, n))) {
> -               kasan_check_write(to, n);
> +               instrument_copy_from_user_pre(to, n);
>                 res = raw_copy_from_user(to, from, n);
> +               instrument_copy_from_user_post(to, n, res);
>         }
>         if (unlikely(res))
>                 memset(to + (n - res), 0, res);
> @@ -23,12 +25,14 @@ EXPORT_SYMBOL(_copy_from_user);
>  #ifndef INLINE_COPY_TO_USER
>  unsigned long _copy_to_user(void __user *to, const void *from, unsigned long n)
>  {
> +       unsigned long res = n;
>         might_fault();
>         if (likely(access_ok(to, n))) {
> -               kasan_check_read(from, n);
> -               n = raw_copy_to_user(to, from, n);
> +               instrument_copy_to_user_pre(from, n);
> +               res = raw_copy_to_user(to, from, n);
> +               instrument_copy_to_user_post(from, n, res);
>         }
> -       return n;
> +       return res;
>  }
>  EXPORT_SYMBOL(_copy_to_user);
>  #endif
> --
> 2.25.0.341.g760bfbb309-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbUvoePVPV%2BBqU-cwhF6bR41_eaYkr9WLLMYi-2q11JjQ%40mail.gmail.com.
