Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLUIY32QKGQEKFGMBHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id E9A2D1C5AE4
	for <lists+kasan-dev@lfdr.de>; Tue,  5 May 2020 17:20:15 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id x7sf1971663qtv.23
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 08:20:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588692015; cv=pass;
        d=google.com; s=arc-20160816;
        b=kJm//1lbJBL4R/QaYkKHfbokNlY/un8djjGduc8GOziQhLejdi6/gXOMu7I49b+wHq
         IgCxDlvstvJksT4rYg0Y7UkOLPhZvv+OtRoTwKHlP8P2rvj2ZNRMf9oj+0OMaPCPi0b1
         sJNmK92FCL2zFj1mq3NjVGMyZVYG8AA6flH4LfZlgaVV7Kpz53vkFz8r3lrEDp3qzMmu
         a0COP6CjYfDrK9zHWNbbZ6uWiAagxTLVOki4BCkfq2Xk9aDvLaIquig4kELEtQ6uz06j
         Eedul22V4H8BrPyK17z4utbeiN7AWIORStkhOs1+ehMyhHG7A+jIIiqDn9QtV5OjS17a
         fimQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WENjqF4hjVY08SC8rjaAKVYGfUwHulTGk45KyJ+rDb4=;
        b=HYT0DaLjCo7pwyB4wkffbSHsAD6XBCaN5IaEWIGXg+CoyK+6qk9Tt22cMXuUX4kyRf
         1fBGw4u+qVamZywzm9yK9b2oRmVwy6V8vFHpORqBmeR/3RJVHho3PxgtvSiX8Nl9ST7t
         vr0xPzCCwmoHwyfybIOFHfLac+zfHjJo0Fm5ZIYtzTporQvVi6OlpFnJkf7tQXraM8cd
         gHEOVDr3r0bXMvndkl2R13Y+76MhWcdgef9mrqCz4wChOgjcpsiitqOr7JQgtbnskpvk
         40OhS+5tzoiTDfmL6NiQAaxHvwRWCDmuR1T6/5VVRErW3cFo78Uo0Eh7mTgsrjXVlqEF
         41Sg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lxBGwppW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WENjqF4hjVY08SC8rjaAKVYGfUwHulTGk45KyJ+rDb4=;
        b=MeEbmlIeMLsu3knej9l/OssfXaan81o+cTebcVICy6fLc/J/O6rI6pYIj6zzL3k38V
         KDglEFz3JXY4mvcJKiXD3bOU4RowkyHPGFklMq14fuuv19E/nLxMneW7gBKjU30MkA4E
         M0B0V+5otJun4youDXOM7O8Q6i83kwMhvTZ6hMnVujV32gW56Qkxia8J73wxahkEA3zN
         jh6bjFXUaRQFL3bpjaiXz39zrm/AZlUw9qkDa2Mrxuc5vt3Vq94XhRTIw+18iW1zBET/
         266rWoA34RArgqoDmb6txns9UuUnKkxHG73zznWQMCdzZ0hyEvrVNO3kJGV7FKyD497T
         BP2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WENjqF4hjVY08SC8rjaAKVYGfUwHulTGk45KyJ+rDb4=;
        b=GPq6J4wrPpq9MyrHX7E+UQ9+lSGxcoPtTwoCa5EWlqfLERMSdxphi+/fF/Kj7deQMV
         p+sOguK333fwherQiBf1Khp0fHwFFPv+/w/M2qfp3u2XDZ37cWpSolHtdQSdPkb4eK8z
         RF5ZlzFml9VlP5z8cOBNGhZXGN2KJooJLnGrEIPnHGg8RoGh+wtLC8copiU2hFq6zFc1
         zKPQKYSPjO5gVb+Q7Msb6q75jLIB3Ef2u1eaQgVHgL7//hpe8BWNekJY1kmI5ZwsNVmR
         d94kJFXbehh0WVZ2nNI7wlsxOpKlJkrff0gP0zNWk6VXXtsvpBfSztc2kBlcRbWBVE3u
         T6DQ==
X-Gm-Message-State: AGi0PuZA1/yxjEyaP+hGmjDbaWkVau4FGxEkCYmqtqmx15J/5E8mcUIk
	2ykFgm6uaXOmWNIYrMals5g=
X-Google-Smtp-Source: APiQypIDesY/liu+VqsmeW65w0xoT09I78OGH7MZXD8rfZVUVwuuahYtz1czIn7NoChDCVjzslvJeg==
X-Received: by 2002:a05:6214:18c9:: with SMTP id cy9mr3233661qvb.35.1588692014867;
        Tue, 05 May 2020 08:20:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:44a1:: with SMTP id a1ls1755845qto.6.gmail; Tue, 05 May
 2020 08:20:14 -0700 (PDT)
X-Received: by 2002:ac8:6f11:: with SMTP id g17mr3201376qtv.361.1588692014480;
        Tue, 05 May 2020 08:20:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588692014; cv=none;
        d=google.com; s=arc-20160816;
        b=n5jZntCQ1wXfxRbd2QcxqZDp18ArwiMsjXETAe0HyJrifJq45Uj4vMel6M8ihejlss
         eet+/8HERAaRLb5QzBUDJ93RZ3HLvvWtBZiXcAgqSUmohGsnluhZjbpdt7MdnwUyLPJ/
         k/j7jnFJozL+lIerbcToE3iLpum4Sw1yzGLcOXN9itPbaoBri1OC1Tx6fsAgb0g4974n
         TvCg4IFcytA4rR9KyUIyX/2xiR3QWrUdGYw8DRWtPb8f+9/kTW4G87DkEdY7c16WGG2p
         VgUXVYDoBy4gjNbIPbP9Ikt8PZh4KcIwrwQelKasEWFXpO665VVUWINHZiKAtC1xUaCd
         bZ6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=V8efal+sgU1en3J4nQ9rg/ceJ49rrnhyDi/kAbpO9w0=;
        b=l4DRh+zCjclH3mGUIEjWU+e/GWdex9ZZbHp90gIvlDjkZCJGQY0uD2MS3gv6V1Y0zk
         zeh2ZRdX1Re9Cr3zPUJmyVgBu58RGdB+3/sL5haoqJuYT65AYRx6W8Duz9qe3teKXPyi
         fKgIwj6DF785HBvkh/m164amGUb1Nx0jtVLygSjVP/dUOGO6LoBxZ2KBTXguIbI8iyrv
         RDoeuScZFLr+dIn0TfEa0px2JqkPgcWbGToFQZriJuVrQs6fU/fH7XqxyRxG9rC5aW5h
         yvcrXFtRNOcAjeSqRbdlHiqy/yeyRp7m9YWb1HbqsauGGGmt3DI9NS2Uy2CNFW9JsDoZ
         p3sg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lxBGwppW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id l23si149903qkl.0.2020.05.05.08.20.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 May 2020 08:20:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id z17so1964305oto.4
        for <kasan-dev@googlegroups.com>; Tue, 05 May 2020 08:20:14 -0700 (PDT)
X-Received: by 2002:a9d:509:: with SMTP id 9mr3055453otw.17.1588692013635;
 Tue, 05 May 2020 08:20:13 -0700 (PDT)
MIME-Version: 1.0
References: <20200505142341.1096942-1-arnd@arndb.de> <CANpmjNMtGy6YK8zuqf0dmkykZMt=qkxkZrZNEKde1nbw84ZLkg@mail.gmail.com>
 <CACT4Y+Zpp=+JJedhMpunuUh832eJFu+af-r8631Ar0kE2nv72A@mail.gmail.com> <CAK8P3a23XzLhZQNuFbeQhaSNru1abPwXV_mXR_P6N6Dvxm6jFw@mail.gmail.com>
In-Reply-To: <CAK8P3a23XzLhZQNuFbeQhaSNru1abPwXV_mXR_P6N6Dvxm6jFw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 May 2020 17:19:58 +0200
Message-ID: <CANpmjNOE+GUG7O=WaJKQg6rdUOn+YMBhdS8enNWkD_8mdtaSBQ@mail.gmail.com>
Subject: Re: [PATCH] ubsan, kcsan: don't combine sanitizer with kcov
To: Arnd Bergmann <arnd@arndb.de>
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Kees Cook <keescook@chromium.org>, Andrey Konovalov <andreyknvl@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lxBGwppW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Tue, 5 May 2020 at 16:59, Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Tue, May 5, 2020 at 4:50 PM 'Dmitry Vyukov' via Clang Built Linux
> <clang-built-linux@googlegroups.com> wrote:
> > On Tue, May 5, 2020 at 4:36 PM Marco Elver <elver@google.com> wrote:
> > > > Clang does not allow -fsanitize-coverage=trace-{pc,cmp} together
> > > > with -fsanitize=bounds or with ubsan:
> > > >
> > > > clang: error: argument unused during compilation: '-fsanitize-coverage=trace-pc' [-Werror,-Wunused-command-line-argument]
> > > > clang: error: argument unused during compilation: '-fsanitize-coverage=trace-cmp' [-Werror,-Wunused-command-line-argument]
> > > >
> > > >  menuconfig KCSAN
> > > >         bool "KCSAN: dynamic data race detector"
> > > > -       depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN
> > > > +       depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN && !KCOV
> > >
> > > This also disables KCOV with GCC. Why does this not work with KCSAN?
>
> My mistake, this should be kept enabled for gcc. If we can get the combination
> to work in clang, that's something that should also get enabled.

See my suggestion below how we might dynamically determine if the
combination is supported.

> > > This is a huge problem for us, since syzbot requires KCOV. In fact
> > > I've always been building KCSAN kernels with CONFIG_KCOV=y (with GCC
> > > or Clang) and cannot reproduce the problem.
>
> I have some local patches that change the way we pick the warning options
> for each compiler, and enable more of the warnings that are normally disabled.
>
> Maybe -Wunused-command-line-argument is disabled by default?
> I only started seeing this problem recently. It's also possible that there
> are some other options that interact with it so only Kcov+FOO leads to
> KCSAN being ignored.

I see. It certainly seems quite bad if one or the other option is
effectively ignored.

> > > Ditto, we really need KCOV for all sanitizers. I also just tried to
> > > reproduce the problem but can't.
> > >
> > > Which version of clang is causing this? I'm currently using Clang 9.
> > > My guess is that we should not fix this by disallowing KCOV, but
> > > rather make Clang work with these configs.
> > >
> > > Dmitry, can you comment?
> >
> > FWIW I can reproduce both with clang:
> >
> > $ clang /tmp/test.c -c -fsanitize-coverage=trace-pc -fsanitize=bounds
> > clang-11: warning: argument unused during compilation:
> > '-fsanitize-coverage=trace-pc' [-Wunused-command-line-argument]
> >
> > $ clang /tmp/test.c -c -fsanitize-coverage=trace-pc -fsanitize=thread
> > clang-11: warning: argument unused during compilation:
> > '-fsanitize-coverage=trace-pc' [-Wunused-command-line-argument]
> >
> > with both my disto's 9.0.1 and fresher 11.0.0
> > (7b80cb7cf45faf462d6193cc41c2cb7ad556600d.
> >
> > But both work with gcc
> >
> > $ gcc /tmp/test.c -c -fsanitize-coverage=trace-pc -fsanitize=thread
> > $ gcc /tmp/test.c -c -fsanitize-coverage=trace-pc -fsanitize=bounds
> >
> > Is it a known issue in clang?
> >
> > Can we somehow disable it only for clang and not gcc?
> >
> > This will immediately break KCSAN on syzbot as it enables KCSAN and KCOV:
> > https://syzkaller.appspot.com/upstream?manager=ci2-upstream-kcsan-gce
>
> I can respin the patch with this fixup if you like:
>
> --- a/lib/Kconfig.kcsan
> +++ b/lib/Kconfig.kcsan
> @@ -5,7 +5,7 @@ config HAVE_ARCH_KCSAN
>
>  menuconfig KCSAN
>         bool "KCSAN: dynamic data race detector"
> -       depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN && !KCOV
> +       depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN && !(KCOV
> && CC_IS_CLANG)

I wonder if we can just add this:  depends on !(KCOV &&
!$(cc-option,-Werror -fsanitize=thread -fsanitize-coverage=trace-pc))

Similarly for UBSAN.

That way, once Clang supports this combination, we don't need another
patch to fix it.

Thanks,
-- Marco

>         select STACKTRACE
>         help
>           The Kernel Concurrency Sanitizer (KCSAN) is a dynamic
>
> As you both say, the combination seems to be quite important, so maybe there
> is something else that can be to also enable it with clang.
>
>       Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOE%2BGUG7O%3DWaJKQg6rdUOn%2BYMBhdS8enNWkD_8mdtaSBQ%40mail.gmail.com.
