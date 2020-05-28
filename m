Return-Path: <kasan-dev+bncBDX4HWEMTEBRBM5EX73AKGQECAL5UPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id B0BD51E6520
	for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 17:01:08 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id w24sf18111026pfq.10
        for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 08:01:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590678067; cv=pass;
        d=google.com; s=arc-20160816;
        b=cIgyocy2jXAZ4CjxsgnGkDudQ/eAac93qaLQCnQMzjJmtJUShdQoJ/9pIx20BxmU+Y
         vRbaAaO1JNb4fzAnBeDFU8Lt00J17ZhcxMGPaBd2+KZJJsYNU3EMtayEd3K7ov9bLUyo
         +RB9B1lQJAfbV8WDffyeM1x3Lguh97Iub6OycRSAOu2iSLHrRZAsmxoP4gKsbUEWi2r2
         P1a3PQgrbD5WTzcC77Iq+6TVn1E6ntSLXwJxu9RJ+VS/RkZUyAmtqc6mNTjM+rQBtRlW
         NwX5QhwBmRbitaOryUx+2YzqnjqjcH3i2W0LrFjfho2ZTX4YsjA0BU9PcTmReNvcnltQ
         Ah0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tHlOBfZ8tGpi4vV+7UU1DLDqxJxNmPLn3UxW2w4JuWA=;
        b=j9ZQPHpY/LN2UxkvHUyS0a+uvlBHab0z8UkRGGjpmn227HYhh6XD0IEzn9lqvcDEim
         uVqNzXldhczhJIbeRf6yqUL3wfazfI5hg0mqj1tAm9dqJ/GEsn/9VleyNaWliki1eLar
         Gpq3eyHrTdD4xxyTGRHQBVjSrAf7dGny6nsjNEz/EqKvX0xEIwDLoLHQZlxWqLo9oL+m
         7oTSXqfI4DNMgFRuGTwmoRpTaPi+UPE9G5tog0bzSE3TqtQ1J+NcEKUV+zFtq6Xdt868
         0qggsrhFB0FU3lbh+4+2Ja9An1E02d6EQstnuBw5H1LEJnuokXmGeeK8hCxVfEGn1Yih
         6LVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OYx1azbF;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tHlOBfZ8tGpi4vV+7UU1DLDqxJxNmPLn3UxW2w4JuWA=;
        b=Xl97uk+ZXaZNRJxKMMoMLPixvM0t90UDn4qBy+J0cqbtb9OrBxwiasnqevvst/ivAf
         qD4z31/ZDURTXpCazctf6EWoOFKawqlcbU06E3gJAFwG6IwwQnM4JI76mbaX5LDiItw9
         i586dVVXwhcGl2mr8oM49yUICmtW8QcPA2NILd2gQLus+quoxePstdXgEJMZuhBRz+Qg
         KXPWoBG0rqSvDxo6EwTmO/Fjgc2veqboC1zp4FkmMlS6VVjBxJ1v8Etwm4U542hfY80u
         RGpwQ7uDiVtNO9jCmQOb7aR0bxVjHmOHRWxvypDMHo5+nFXXy75IS8ItAKHDJQeyOctu
         FtaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tHlOBfZ8tGpi4vV+7UU1DLDqxJxNmPLn3UxW2w4JuWA=;
        b=QomxmZoi5y0kbzsWxoRSbtLn5pLzGrRm79qOYjhS2QIW+LZFqNmMAO4I16bR4SdrPE
         fNvq3KHWZ1/qTBq1KynTSm+4+OoFE+Gknv/E+9qV402NPMxFYG/tmE7XQoA0EG/Q1q14
         Y4j/v3N6vixzbhQB/z5T8RbV5m7M1OYiqt6/BjvEMgN368sf1/D8o3omhTbx1m9Ecqmx
         6CgYTx1DXDGyM8ktv+wLMSYNi3VYoTnm3voEb4zdAOzgX9C3/wk2imUo6bbFy1fZxeZI
         +Qd76p2cePN5tLdkkcHz/HCNfyHntnZiAgmufaEvLVMdyqbgr5nWBF3jPF7wC6uN7rSh
         sGgg==
X-Gm-Message-State: AOAM532XL8J5E9DZgJqOhBvCkS+cAJj+maiR4RNKg9HO2BQ80SVYvJWa
	C+mRfV9ikN2+u7C0zuAX7QU=
X-Google-Smtp-Source: ABdhPJwHiqzv6Kor8xZ4qJLoTqaBJKAa9tDvomV6rIufuZq+aG1E7tg3ymAO7bVwJq6J7Wal7Efs1g==
X-Received: by 2002:a17:902:148:: with SMTP id 66mr3783046plb.226.1590678067267;
        Thu, 28 May 2020 08:01:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8f8f:: with SMTP id z15ls1048213plo.8.gmail; Thu, 28
 May 2020 08:01:06 -0700 (PDT)
X-Received: by 2002:a17:90a:1a17:: with SMTP id 23mr4384230pjk.198.1590678066613;
        Thu, 28 May 2020 08:01:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590678066; cv=none;
        d=google.com; s=arc-20160816;
        b=HdwsGiB0D66ALmiMU7OfVYEH2Z+CCQpHot3vYbXTAETufCXN7daPGKBlqayibAzuKx
         n9wuOXZjq201j8o+neNROG1HdachDeBlJP9Su9ygbY2GcM2UQwyjZ2AQ7rPflgf1Z0SH
         Kq3YQpRQCKVwX2A4n+r+zscu2UaDJPPTsJVE5Kg1mk8QggELkJDD+2rvaJ8vtWx9Udr1
         Fst9jZKeO3XRY+VehCoLuMNWMXixumF3jNcvBGM4CZeF/4QEX95pKowqmxWJG57c2Fe9
         rXSsmxUoH9ggsZ8MjG8/Xc3iG+5BCM8kaReU+TVn4XSgRmKMPxP7y3jLzOMgdcgGZirB
         upYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=k4gasz7E8Vka0VphamQPgsMwOl6rPaC5hW405KW6cAI=;
        b=ImpotFFruExmKrZb57cdyMjmNLDLfdnqzH8gnQGk9YgvC0+G7iH5Is6VRj4dRD9raw
         RiFBH+I/EcqCL7LFEjCz7LdHXhUeEx/sny6oovWMVHWYDM043AaYsiGMPcP3x9hSt/S2
         023OqukiMSuJK5+DfUhd8VhZK5sWINl0E2DGeEMAIo55n48mR06OaOG4TyWRNmry7d6f
         TGub7DMZ2U54D9m5O6ATRizuqi701Bz+igdV2xj21P97szL32vXviaQpSy5uzx1AkB7R
         OIfnPouKuGEOXY+LNzQ/YIn392Isar+/fkXKnRi7fFkFTi/OgoxSwWje+I7VMzJi7z5U
         yHkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OYx1azbF;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id kb2si267786pjb.1.2020.05.28.08.01.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 May 2020 08:01:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id nu7so3297875pjb.0
        for <kasan-dev@googlegroups.com>; Thu, 28 May 2020 08:01:06 -0700 (PDT)
X-Received: by 2002:a17:90a:2a8e:: with SMTP id j14mr4202521pjd.136.1590678065375;
 Thu, 28 May 2020 08:01:05 -0700 (PDT)
MIME-Version: 1.0
References: <29bd753d5ff5596425905b0b07f51153e2345cc1.1589297433.git.andreyknvl@google.com>
 <78a81fde6eeda9db72a7fd55fbc33173a515e4b1.1589297433.git.andreyknvl@google.com>
 <20200528134913.GA1810@lca.pw>
In-Reply-To: <20200528134913.GA1810@lca.pw>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 28 May 2020 17:00:54 +0200
Message-ID: <CAAeHK+zELpKm7QA7PCxRtvRDTCXpjef9wOcOuRwjc-RcT2HSiA@mail.gmail.com>
Subject: Re: [PATCH 2/3] kasan: move kasan_report() into report.c
To: Qian Cai <cai@lca.pw>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Leon Romanovsky <leonro@mellanox.com>, Leon Romanovsky <leon@kernel.org>, 
	Randy Dunlap <rdunlap@infradead.org>, Josh Poimboeuf <jpoimboe@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OYx1azbF;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, May 28, 2020 at 3:49 PM Qian Cai <cai@lca.pw> wrote:
>
> On Tue, May 12, 2020 at 05:33:20PM +0200, 'Andrey Konovalov' via kasan-dev wrote:
> > The kasan_report() functions belongs to report.c, as it's a common
> > functions that does error reporting.
> >
> > Reported-by: Leon Romanovsky <leon@kernel.org>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Today's linux-next produced this with Clang 11.
>
> mm/kasan/report.o: warning: objtool: kasan_report()+0x8a: call to __stack_chk_fail() with UACCESS enabled
>
> kasan_report at mm/kasan/report.c:536

Hm, the first patch in the series ("kasan: consistently disable
debugging features") disables stack protector for kasan files. Is that
patch in linux-next?

>
> > ---
> >  mm/kasan/common.c | 19 -------------------
> >  mm/kasan/report.c | 22 ++++++++++++++++++++--
> >  2 files changed, 20 insertions(+), 21 deletions(-)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 2906358e42f0..757d4074fe28 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -33,7 +33,6 @@
> >  #include <linux/types.h>
> >  #include <linux/vmalloc.h>
> >  #include <linux/bug.h>
> > -#include <linux/uaccess.h>
> >
> >  #include <asm/cacheflush.h>
> >  #include <asm/tlbflush.h>
> > @@ -613,24 +612,6 @@ void kasan_free_shadow(const struct vm_struct *vm)
> >  }
> >  #endif
> >
> > -extern void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip);
> > -extern bool report_enabled(void);
> > -
> > -bool kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip)
> > -{
> > -     unsigned long flags = user_access_save();
> > -     bool ret = false;
> > -
> > -     if (likely(report_enabled())) {
> > -             __kasan_report(addr, size, is_write, ip);
> > -             ret = true;
> > -     }
> > -
> > -     user_access_restore(flags);
> > -
> > -     return ret;
> > -}
> > -
> >  #ifdef CONFIG_MEMORY_HOTPLUG
> >  static bool shadow_mapped(unsigned long addr)
> >  {
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 80f23c9da6b0..51ec45407a0b 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -29,6 +29,7 @@
> >  #include <linux/kasan.h>
> >  #include <linux/module.h>
> >  #include <linux/sched/task_stack.h>
> > +#include <linux/uaccess.h>
> >
> >  #include <asm/sections.h>
> >
> > @@ -454,7 +455,7 @@ static void print_shadow_for_address(const void *addr)
> >       }
> >  }
> >
> > -bool report_enabled(void)
> > +static bool report_enabled(void)
> >  {
> >       if (current->kasan_depth)
> >               return false;
> > @@ -479,7 +480,8 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
> >       end_report(&flags);
> >  }
> >
> > -void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip)
> > +static void __kasan_report(unsigned long addr, size_t size, bool is_write,
> > +                             unsigned long ip)
> >  {
> >       struct kasan_access_info info;
> >       void *tagged_addr;
> > @@ -518,6 +520,22 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
> >       end_report(&flags);
> >  }
> >
> > +bool kasan_report(unsigned long addr, size_t size, bool is_write,
> > +                     unsigned long ip)
> > +{
> > +     unsigned long flags = user_access_save();
> > +     bool ret = false;
> > +
> > +     if (likely(report_enabled())) {
> > +             __kasan_report(addr, size, is_write, ip);
> > +             ret = true;
> > +     }
> > +
> > +     user_access_restore(flags);
> > +
> > +     return ret;
> > +}
> > +
> >  #ifdef CONFIG_KASAN_INLINE
> >  /*
> >   * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
> > --
> > 2.26.2.645.ge9eca65c58-goog
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/78a81fde6eeda9db72a7fd55fbc33173a515e4b1.1589297433.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzELpKm7QA7PCxRtvRDTCXpjef9wOcOuRwjc-RcT2HSiA%40mail.gmail.com.
