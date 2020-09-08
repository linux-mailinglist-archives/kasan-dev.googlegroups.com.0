Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTFC3X5AKGQETRQ6ITA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C223B260ED1
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 11:39:25 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id c78sf15028849ybf.6
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 02:39:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599557965; cv=pass;
        d=google.com; s=arc-20160816;
        b=ShvMyYKmRsta0Zuomoy43TKnyMy/ryy7wwcUsDFFg5MM0BuvRLHH3L9D7F60USkg/J
         lJ02d6tkg0F2HJz1jmXmSSIkA4lqxE4WwOqzNHVKjD8+hz1tNIF6rWaEXgh2LQ+6Buu7
         vwia8EIpAM5fC8WLuVBDqu/6WKIjWcMwbGAxFOqYmyyiCCuUQDqs/lubIxQDt9aZ7zvt
         3dYjFzIjb3bWMcb7DTXiteBq8+9VmrdQcdNn31tRW0EHGIW8ZV4E7cxVze40YC7YIvSD
         72SUw8C0aLwvLZZIKVeWWnTpCWeBxwDGDVc0x0/Bu3BN0D0QvvfevY1B6vqusDjGxHkW
         Zmmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kva+OvEc66p0Mn/l2QuVC1auIhha1ej2R3tBFi1kp4A=;
        b=Y6+rQy1VPB+cIWC2cVUOB5EpwVAzAUUQ9KOWWgbB3COtsGCGUq/bzgK5EnGE2mtsDg
         /4GHjVyKThA72Xw2X2I7NTBl72e2yPm/kiXIvwx44WseKaCn5RN4wQPEXjS4I99pQGTM
         ujmsTwgDWBcS7ilWLwoUIPGu8u+fZm+pU2MEUxtBK6Zs1HJFj6bCz9ElX4WlT9GCP8nN
         91ODLlOjG3dnjJ0WmSONf5n0sNiJJMZIPjtK+IVVkypDIDSLBArUh4aaUKwS8PI+bnhT
         wtweUQuFSf5TLr3bzbeowTiftNKL3wx1fu4VagddGYebJ4BQ20157HZhAnYP7U32SK4/
         QSuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DsHA4dEc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kva+OvEc66p0Mn/l2QuVC1auIhha1ej2R3tBFi1kp4A=;
        b=KkFuyRZURUV72cEuP6z0Uf6TScxH29dNkxTfRFP4AH60/oyPtLGoHEiNzNMJv78J0B
         FJimDuKj2uAuBmfWVUx7p6fpbhJKlS354zQqlm/NiR+ckkmyGHmAlMjAsAmrbQNdcQkl
         fC+rdMFffMcOjJ2/PowBTX/l+SxQT2x1G28tLsBcl5VbLl1i68C/kK+pNM7T0qnWTjb4
         QIZUKTUraBu6PP4P0jq1wETgupFj5cBNzDQujay+ayCoZHKcd1XN6Yxc9y3ueTFJUPHU
         fKi6QAodFb2jpTeXi9dvUGsEWncJzeKJ8vuUcnmlqjAeCV6NDNpbqZgEMqtU9vhG/yuC
         NJkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kva+OvEc66p0Mn/l2QuVC1auIhha1ej2R3tBFi1kp4A=;
        b=kmLChvaD82qEj9/NCEgJspCc58i5IhymeOdHe+/H+V1FyOX/gQG5RVCGYxRKQtXir4
         4FQMK4k5eRHCZFRyI/r0oV+8VwTIIDze19dFR4Xlb4Bzjja6xtPxWjIGshvp7CmKnyk1
         l5Iw361bsjE1fhfHEMsXjqc04kbSlDw1gFD4JI2xdG+0Wt+nMNC9lYrIaKIk1PGDoEdT
         BnPhCikPCHqt1feXyoUKtoKYqFYSUQJn7tWyFcs/siE3zDwdObbDiWVY5odO/iWMhh7J
         o/GIvLN6lEEBK220How1RE+2SN36BFZlh+fx3eHaUCSjW/PEjwH1TbBsC4M9WpXD6plE
         LI4w==
X-Gm-Message-State: AOAM533mmTndFeNuJrU7o+93+6++6y29szlHUx04pVdUT4f8+ajEQ2S4
	/42HtMH7oITP1P2WVi6ZDY8=
X-Google-Smtp-Source: ABdhPJx3JyWwU5r/cAmmPGzenoXPwv1WmW/TVJy0RaZX1ljIs/DfSOoZdvmaX5HZcYAdVqH8ZSv3HQ==
X-Received: by 2002:a25:3d6:: with SMTP id 205mr23064276ybd.456.1599557964827;
        Tue, 08 Sep 2020 02:39:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d4d3:: with SMTP id m202ls3809486ybf.6.gmail; Tue, 08
 Sep 2020 02:39:24 -0700 (PDT)
X-Received: by 2002:a25:4d2:: with SMTP id 201mr26061519ybe.150.1599557964279;
        Tue, 08 Sep 2020 02:39:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599557964; cv=none;
        d=google.com; s=arc-20160816;
        b=Jmh+CtGa3iH9XC+qw1HUjk7unXDibNXr769lAR6OZgSiMmL/jEOi7e2YXv+4To8N5q
         vlNxvXcwriYS0AZrT0RGmW8V/xpavObGgughGnKxCJH4789zGxP2rXBg8OCqiuw9e3QP
         HXJYnHNldVsXTMWl6JuRzLNUKui4KA/gSsd7V04DwrrJvoL0Ux03eVl2zSAKcTq/kdYe
         dggpnXG8aoTfXdexvXKqagk7/klZxeylfQa8vRgVTIc1S6x/REysVDdwOsWpEtEl3Kko
         2tyiFSUIOfCeQlCHy2Eq1GFixrlbGlBNfAo/sfeW63w0IQVo1x4iGdiw7IMjEncDkTgI
         VFpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ti/MkgxNUqOT9JqnKGwbINcNBIfh+eLyLU5FCjEJEmk=;
        b=o37yhocB69NIBsj0uaX8YejFgoXa18xYdnEMUSxPLd4Spj31UKyfWqJloo0bFkDxiw
         8s9oHHvTMeiaK7490ckDIxeuX1IRy/rZ0hgAe3jotl6RbY14dHC0AWTuqVfSZ9scxmlP
         Vx59xWa92NnQ6hgku6CBhAKHuy8DoXZGhKOqpoI8EYJD28IvrQmegMXmSnGWLUEM3rlI
         9XhvCypuUiKs8UaRFT0oW/S6H//gUrKER5peC3kHGV1iwT8ZpITatBwS5hz9phvE41Oh
         aB8q6RKm6ElFk8Q2RcrkQuPrv8DwLIHGfZCqg//Po19L3fk+ngpaEIVKEMkWloYvU84Z
         1Grw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DsHA4dEc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id s9si521531ybk.3.2020.09.08.02.39.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 02:39:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id 11so7523340oiq.6
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 02:39:24 -0700 (PDT)
X-Received: by 2002:aca:54d1:: with SMTP id i200mr2085966oib.172.1599557963595;
 Tue, 08 Sep 2020 02:39:23 -0700 (PDT)
MIME-Version: 1.0
References: <20200905222323.1408968-1-nivedita@alum.mit.edu> <20200905222323.1408968-2-nivedita@alum.mit.edu>
In-Reply-To: <20200905222323.1408968-2-nivedita@alum.mit.edu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Sep 2020 11:39:11 +0200
Message-ID: <CANpmjNMnU03M0UJiLaHPkRipDuOZht0c9S3d40ZupQVNZLR+RA@mail.gmail.com>
Subject: Re: [RFC PATCH 1/2] lib/string: Disable instrumentation
To: Arvind Sankar <nivedita@alum.mit.edu>
Cc: "the arch/x86 maintainers" <x86@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Kees Cook <keescook@chromium.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DsHA4dEc;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Sun, 6 Sep 2020 at 00:23, Arvind Sankar <nivedita@alum.mit.edu> wrote:
>
> String functions can be useful in early boot, but using instrumented
> versions can be problematic: eg on x86, some of the early boot code is
> executing out of an identity mapping rather than the kernel virtual
> addresses. Accessing any global variables at this point will lead to a
> crash.
>
> Tracing and KCOV are already disabled, and CONFIG_AMD_MEM_ENCRYPT will
> additionally disable KASAN and stack protector.
>
> Additionally disable GCOV, UBSAN, KCSAN, STACKLEAK_PLUGIN and branch
> profiling, and make it unconditional to allow safe use of string
> functions.
>
> Signed-off-by: Arvind Sankar <nivedita@alum.mit.edu>
> ---
>  lib/Makefile | 11 +++++++----
>  1 file changed, 7 insertions(+), 4 deletions(-)
>
> diff --git a/lib/Makefile b/lib/Makefile
> index a4a4c6864f51..5e421769bbc6 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -8,7 +8,6 @@ ccflags-remove-$(CONFIG_FUNCTION_TRACER) += $(CC_FLAGS_FTRACE)
>  # These files are disabled because they produce lots of non-interesting and/or
>  # flaky coverage that is not a function of syscall inputs. For example,
>  # rbtree can be global and individual rotations don't correlate with inputs.
> -KCOV_INSTRUMENT_string.o := n
>  KCOV_INSTRUMENT_rbtree.o := n
>  KCOV_INSTRUMENT_list_debug.o := n
>  KCOV_INSTRUMENT_debugobjects.o := n
> @@ -20,12 +19,16 @@ KCOV_INSTRUMENT_fault-inject.o := n
>  # them into calls to themselves.
>  CFLAGS_string.o := -ffreestanding
>
> -# Early boot use of cmdline, don't instrument it
> -ifdef CONFIG_AMD_MEM_ENCRYPT
> +# Early boot use of string functions, disable instrumentation
> +GCOV_PROFILE_string.o := n
> +KCOV_INSTRUMENT_string.o := n
>  KASAN_SANITIZE_string.o := n
> +UBSAN_SANITIZE_string.o := n
> +KCSAN_SANITIZE_string.o := n

Ouch.

We have found manifestations of bugs in lib/string.c functions, e.g.:
  https://groups.google.com/forum/#!msg/syzkaller-bugs/atbKWcFqE9s/x7AtoVoBAgAJ
  https://groups.google.com/forum/#!msg/syzkaller-bugs/iGBUm-FDhkM/chl05uEgBAAJ

Is there any way this can be avoided?

If the use of string functions is really necessary, we could introduce
'__'-prefixed variants (maybe only for the ones that are needed?),
a'la

static void __always_inline strfoo_impl(...) { ... }
void strfoo(...) { strfoo_impl(...); }
EXPORT_SYMBOL(strfoo);
noinstr void __strfoo(...) { strfoo_impl(...); }
EXPORT_SYMBOL(__strfoo);
// If __HAVE_ARCH_STRFOO then we can probably just alias __strfoo to strfoo.

But if the whole thing could be avoided entirely would be even better.

Thanks,
-- Marco


>  CFLAGS_string.o += -fno-stack-protector
> -endif
> +CFLAGS_string.o += $(DISABLE_STACKLEAK_PLUGIN)
> +CFLAGS_string.o += -DDISABLE_BRANCH_PROFILING

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMnU03M0UJiLaHPkRipDuOZht0c9S3d40ZupQVNZLR%2BRA%40mail.gmail.com.
