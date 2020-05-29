Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVNMYX3AKGQEHLOV54Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id C777F1E86BF
	for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 20:37:10 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id a186sf1860187oii.5
        for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 11:37:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590777429; cv=pass;
        d=google.com; s=arc-20160816;
        b=EpBzT4i8zk1lMZbqBrPXvOHkHV3kqLJHM21iytx5hPU48J+x33VcG8VCIq+kVduJ1+
         ZfOyHdmK5h3K0Essf6fGe8LKCgVC0vIVlzHG14QHLSFsHJzTs3L8hjiK5gv2a9rEE1lS
         9Ljq0RSKYj2lFo20KGfWYzIDtAp80W1J94BPuZBFI9NJJDqUq1Nvq0lQXM9QWqLsPArW
         bwxn1wa6SIMglLysdk0iuNvufdX9l+iIQZIAKWWX72Cp7TQOGbBP8fWPKIzlkiG1j2WG
         y0BAdESs9wRPiqub2mps39gKu39dq+M3EiWIKybJRka2Be9mqlPj0oIkNCSFQ9qJGwP1
         BIcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fkGoIEE42UKdaJ0GLyCbzt/rXTzW2FeziOWpei8CWd4=;
        b=yleQRCWlnTEtNNCXdrDK/P1uGelDhSQHlLX4jQ0WfM19QE9qZ9GvP6IH6Vny9ZFprN
         Xb9HUCJZVVOu7aWEY0vKwJ/ew3+j8Bz997lgI9iGMH2aqAoXrNCL765lN0+cazd8nUBm
         E1f+NL1gQCyg/eFtj3QBzRC61DAD6veCLksFJqZrfXH0D7nStLe9EOSJJ99J5COf1+KO
         URVf9XwyHENVi9IPo1om/I99X67oQfRrgTestHWRWN1nuzMZM3UoBwfG5Zl7LLAaRKvY
         nBHRvcv6NBKSHWOJLHS6gGXaNzZEHpUXiP3WcFBHM9yVD9Mj7otPlo7XjxWiGtYxSLf3
         3BnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZMny2DF2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fkGoIEE42UKdaJ0GLyCbzt/rXTzW2FeziOWpei8CWd4=;
        b=adw6N8po3fsRviZa5PJx2KFUMJ9S8wN57R1i2fcHZLcrZZUbShs8rCq4COEzw4XOXO
         VIRfrAm3stgwVIjZqh6whXJwSCCKEczmu3g7wCFqpYALlsBIa1P2CzzvZWBskppIuG7w
         I2CHY2banlwH8R7ANJkXF6N+ZTvnRF8338AlMoRQwNLRKfZSe9in08HrUG33vPZYGnPR
         lnRh9RIOFloRxA/8BLfXznoT1oyY+SR0pwBO0z+34jbpXHT+og84Kyv8A2np+ARiFenx
         hYhY251yvSovVD/VDNMzBuIL3bn/VpxIaCuo9N16wggrqEPgzeD2TkATu1XWKn6i77Hn
         tJTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fkGoIEE42UKdaJ0GLyCbzt/rXTzW2FeziOWpei8CWd4=;
        b=Lc0kaRvQ1evLD1R5FUlu7PdjhEkvNwkyQz+0Hc3TteFw0COGdLkmY9SapGtkHkD4RT
         Ltnea9cfmX6JxmWweCr9zKXR6hw9wyuBOiWyVa7AqgoHizYDLte69Dejv8MIXVeOmma9
         gWFX8uK/bp/24aUU6a6x+bMghgifcjDIQX2xyEYcxjzIPToMVm39cQrRX+DqMtTpFUTe
         nQ1ENywUjtI85qszrSDGlErDxAV5olXOJlt95YXgjSXJY5fB38JyJqTF7cqj73L/u5x4
         xoRibCctUETY+zO9YwZ3X2VlhsNDVuPm+ERP03xclYPJd4n7yzWuFWH2ccsiqEgBc0pY
         w4qA==
X-Gm-Message-State: AOAM530h2TF33ymzpCtB87n2h+0jIjwjZVImnb5CkalLRWNahXR7LNXB
	+xKSBVv0W8On4BeM+evULLY=
X-Google-Smtp-Source: ABdhPJz0ZOiB04tBfk/jUfHo/08VQYiAKk5gNV05s7Hci37Abzjsf0YxY+txb8C0hCqDvGU+LLwAow==
X-Received: by 2002:aca:aa4e:: with SMTP id t75mr6970932oie.18.1590777429609;
        Fri, 29 May 2020 11:37:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:19af:: with SMTP id k44ls1430705otk.4.gmail; Fri, 29 May
 2020 11:37:09 -0700 (PDT)
X-Received: by 2002:a05:6830:14c4:: with SMTP id t4mr7541209otq.79.1590777429247;
        Fri, 29 May 2020 11:37:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590777429; cv=none;
        d=google.com; s=arc-20160816;
        b=vQxP+MyA/mbGBX9GXZrRPJRsRDVA+POS7xmMPX76zUlBdU6WfuveuuGzQZaaMyKMo9
         UEEEAM9jd7p4l0Nb77CMr26RyDdLOtMCDgszn2QUrhDrr2obO40L0KEg0z/nXUfEvALc
         KOgS74bVoGGymJ5YqtJYuoJNipg/8bF9G1eY9dSbNNJm5uDgpudR5sQy5Iuae82zf9+h
         9gTM2VYi/RxXLjIAkUBi/4OWiIqgKNxsFGm3b1R5EdNguBnD361jGWfXmrPz/8M6PBmv
         HOGM3GHSNIROAZNrLMiLCUw3+icZQKujZZZgFac3OpmXLuf9rZ3pyArTOFdU/bDAPDf9
         0tvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qgm4s52vNNhERtvdEgwZpi9/hHsa34APX0EThyas0Hg=;
        b=UTGdUJiiaKfoHEEUbqKMDhHF2cIrrexWQ/XUiZkncVhxPGLYUdXtu/v26FrKGcUBou
         03ZQgizjw5EK79MHz2lTf+TmT+vn1oyoxlAcoDKjNThf63w/J2zaxEHUcQ/5LozoMyOA
         9YcTRtNtBMjwxO2RukXEpffqMhSvfU4YDfbNcb0t5o4PRcGKuru6vGYlba1QN9pvyLlG
         BP1NG+CXWrE2qTg3EP+mWoyWO9re9FdLVSZzmEbQkR+lf9lCn60Vgfp0o8817NaziygZ
         zrPfsVAnA8ASVGayR5KBRYYmWMnFLx1Xh4XLl6RZJXzIGEn8Cu03hHEleX3ZGLw/TnUl
         VMMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZMny2DF2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id e23si646720oti.4.2020.05.29.11.37.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 May 2020 11:37:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id l6so3462601oic.9
        for <kasan-dev@googlegroups.com>; Fri, 29 May 2020 11:37:09 -0700 (PDT)
X-Received: by 2002:aca:d0d:: with SMTP id 13mr6951426oin.172.1590777428688;
 Fri, 29 May 2020 11:37:08 -0700 (PDT)
MIME-Version: 1.0
References: <20200521142047.169334-1-elver@google.com> <20200521142047.169334-6-elver@google.com>
 <20200529170755.GN706495@hirez.programming.kicks-ass.net>
In-Reply-To: <20200529170755.GN706495@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 May 2020 20:36:56 +0200
Message-ID: <CANpmjNPaL=HRvaJOC37_Cf4S4kskZezmgRiDSGn460rO2dM4+g@mail.gmail.com>
Subject: Re: [PATCH -tip v3 05/11] kcsan: Remove 'noinline' from __no_kcsan_or_inline
To: Peter Zijlstra <peterz@infradead.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, Borislav Petkov <bp@alien8.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZMny2DF2;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Fri, 29 May 2020 at 19:08, Peter Zijlstra <peterz@infradead.org> wrote:
[...]
>
> Doesn't this mean we can do the below?

If nobody complains about the lack of __no_kcsan_or_inline, let's do
it. See comments below.

> ---
>  Documentation/dev-tools/kcsan.rst |  6 ------
>  arch/x86/include/asm/bitops.h     |  6 +-----
>  include/linux/compiler_types.h    | 14 ++++----------
>  kernel/kcsan/kcsan-test.c         |  4 ++--
>  4 files changed, 7 insertions(+), 23 deletions(-)
>
> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> index ce4bbd918648..b38379f06194 100644
> --- a/Documentation/dev-tools/kcsan.rst
> +++ b/Documentation/dev-tools/kcsan.rst
> @@ -114,12 +114,6 @@ functions, compilation units, or entire subsystems.  For static blacklisting,
>    To dynamically limit for which functions to generate reports, see the
>    `DebugFS interface`_ blacklist/whitelist feature.
>
> -  For ``__always_inline`` functions, replace ``__always_inline`` with
> -  ``__no_kcsan_or_inline`` (which implies ``__always_inline``)::
> -
> -    static __no_kcsan_or_inline void foo(void) {
> -        ...
> -
>  * To disable data race detection for a particular compilation unit, add to the
>    ``Makefile``::

I suppose, if we say that __no_kcsan_or_inline should just disappear
because '__no_kcsan inline' is now good enough, we can delete it.

I think functions that absolutely must be __always_inline would break
with __no_kcsan_or_inline under KCSAN anyway. So, let's simplify.

> diff --git a/arch/x86/include/asm/bitops.h b/arch/x86/include/asm/bitops.h
> index 35460fef39b8..0367efdc5b7a 100644
> --- a/arch/x86/include/asm/bitops.h
> +++ b/arch/x86/include/asm/bitops.h
> @@ -201,12 +201,8 @@ arch_test_and_change_bit(long nr, volatile unsigned long *addr)
>         return GEN_BINARY_RMWcc(LOCK_PREFIX __ASM_SIZE(btc), *addr, c, "Ir", nr);
>  }
>
> -static __no_kcsan_or_inline bool constant_test_bit(long nr, const volatile unsigned long *addr)
> +static __always_inline bool constant_test_bit(long nr, const volatile unsigned long *addr)
>  {
> -       /*
> -        * Because this is a plain access, we need to disable KCSAN here to
> -        * avoid double instrumentation via instrumented bitops.
> -        */

Yes, we should have reverted this eventually.

>         return ((1UL << (nr & (BITS_PER_LONG-1))) &
>                 (addr[nr >> _BITOPS_LONG_SHIFT])) != 0;
>  }
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index 4e4982d6f3b0..6a2c0f857ac3 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -118,10 +118,6 @@ struct ftrace_likely_data {
>  #define notrace                        __attribute__((__no_instrument_function__))
>  #endif
>
> -/* Section for code which can't be instrumented at all */
> -#define noinstr                                                                \
> -       noinline notrace __attribute((__section__(".noinstr.text")))
> -
>  /*
>   * it doesn't make sense on ARM (currently the only user of __naked)
>   * to trace naked functions because then mcount is called without
> @@ -192,17 +188,15 @@ struct ftrace_likely_data {
>  #endif
>
>  #define __no_kcsan __no_sanitize_thread
> -#ifdef __SANITIZE_THREAD__
> -# define __no_kcsan_or_inline __no_kcsan notrace __maybe_unused
> -# define __no_sanitize_or_inline __no_kcsan_or_inline

I think we just want to keep __no_sanitize_or_inline, for
READ_ONCE_NOCHECK. Having READ_ONCE_NOCHECK do KCSAN-checking seems
wrong, and I don't know what might break.

> -#else
> -# define __no_kcsan_or_inline __always_inline
> -#endif
>
>  #ifndef __no_sanitize_or_inline
>  #define __no_sanitize_or_inline __always_inline
>  #endif
>
> +/* Section for code which can't be instrumented at all */
> +#define noinstr                                                                \
> +       noinline notrace __attribute((__section__(".noinstr.text"))) __no_kcsan
> +

Will this eventually need __no_sanitize_address?

>  #endif /* __KERNEL__ */
>
>  #endif /* __ASSEMBLY__ */
> diff --git a/kernel/kcsan/kcsan-test.c b/kernel/kcsan/kcsan-test.c
> index a8c11506dd2a..374263ddffe2 100644
> --- a/kernel/kcsan/kcsan-test.c
> +++ b/kernel/kcsan/kcsan-test.c
> @@ -43,7 +43,7 @@ static struct {
>  };
>
>  /* Setup test checking loop. */
> -static __no_kcsan_or_inline void
> +static __no_kcsan inline void
>  begin_test_checks(void (*func1)(void), void (*func2)(void))
>  {
>         kcsan_disable_current();
> @@ -60,7 +60,7 @@ begin_test_checks(void (*func1)(void), void (*func2)(void))
>  }
>
>  /* End test checking loop. */
> -static __no_kcsan_or_inline bool
> +static __no_kcsan inline bool
>  end_test_checks(bool stop)
>  {
>         if (!stop && time_before(jiffies, end_time)) {

Acked -- if you send a patch, do split the test-related change, so
that Paul can apply it to the test which is currently only in -rcu.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPaL%3DHRvaJOC37_Cf4S4kskZezmgRiDSGn460rO2dM4%2Bg%40mail.gmail.com.
