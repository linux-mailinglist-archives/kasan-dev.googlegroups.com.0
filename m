Return-Path: <kasan-dev+bncBDW2JDUY5AORBSVDRWJAMGQEVV6Z6LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id A94064EB371
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Mar 2022 20:36:59 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id x6-20020aa79566000000b004fb3bf117dasf5327785pfq.17
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Mar 2022 11:36:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648579018; cv=pass;
        d=google.com; s=arc-20160816;
        b=yP2ZUpm8OD5Wy57ldUinjAiEPBtI1mUB5wuwbv4dzv5LaZ+LEZIkvoWw/lG0llpnds
         dS8NgeZ8M1mqy8L7wPhtFICFdkxEStcm2jG90n3kPQFbfEwfcl4iLFQyzaobsAmXvyk+
         yXatQhzgVlNLmIM7kTB2hWqrI7oab1HqNHeQKla1r54477R+sEX1//2uamiyEDl8rjtr
         LAyNEYHys1icuqHG8uF9ebZlZwL79lD0TGKRm2Hwd7VicRddpyRwn9WUIURufIR4kDx0
         ZLt4yuj9ufyJJEzQmQ/yZNMdNZT3AJgs1vPqVeaoWS4ZpLnlg3fQcRxVYCqWHB4UTsUP
         Lotw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=mlgL8e37WQ9w4OMP6AOhRdi379SU7fFtbQ2i06fRnIg=;
        b=katSq6e2zKkXAK0j0yfc2sdDPzQcqk08GjrUkJYupv4b8LmScvRWCH/YFSbY6R83nr
         MpAQQEDDyAIrMZ1nSF0vlufK4atJAKzXw/zU5mbwr12uOHhmTDHQFPBMI0kY29vv21eg
         BLqUEVwxdyFWKFG0l1M3ntMXUbFsFQm+RWjlGIvVkHHr6c2eErzrD/ykuHg3RgGws9c1
         2FyHHIXg0VcdlR4xN/guTdYdB2T12aLQ/G42tONLOAni5m+4TPspmzq7aN2SfpAToE2c
         4kjnhm6/r5TK+UZtZOCvYtsmSvwCFXzV5WabH8nEj91+Cc46XpAHw0Qha+ex5L9aEz0J
         svLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=hIo45tQd;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mlgL8e37WQ9w4OMP6AOhRdi379SU7fFtbQ2i06fRnIg=;
        b=JvGxXtQcu6M/XiWEQLlktB4+jV/QQEmtzKDaJtAKL+KMWpGzM6GlnPDFM/p1GwEj1b
         bmgf93dvMHGCTPcwdQOha1rasunNIKvKcf+UJODgxJuprJDhe81fHN39u2hBD5OBHaoS
         UX7UXQZBiZE8Pb6wLQboCFD6zLM5EHqSFf8KDcIiRq8yaxYPfQnhhxle4MpjRg8hJr6l
         i7Lgm0C1ulqJc2Dr5Q+F0shUzH3aQ/5vhWM1SgLKw1vPMN+JV8tZguJ1Rwxpjd/zutPq
         5qIgz7BJGjVWNBEPciw4I64O/OfIadWTCis/V6CtCs1kKY/maLZIQesWlKaEEkhaQNSY
         Ipsg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mlgL8e37WQ9w4OMP6AOhRdi379SU7fFtbQ2i06fRnIg=;
        b=ZBZnaSDuJwu2hxHJe64Ya1WOnedzr+TQeY08IYd9YSnasarp3YNadUM7mQLMgLK8jb
         Mup4eLf3Pw9phj72z20ZyDZU7qjmAUPhBBQVozzWEGda+oZYzg2RgNsF9EWpyMtE5I64
         5ajzkKb4hmSlfEQJ5+hh8320sWhSWr28gkiu+Z9zJNqI/SwqzU2gG25XnyjQeOdSAD9H
         3ql7XsqCYhwXvCUiRyMOYZtjQdZeR0DM/G9mqmSobbxEeZ1JRdjZGxlyBCR8ls7WGB88
         5YpHxdk/jV7znyyc0X8YOcCcsPUnHdzYgv+6WR/XkNofIkQsAX7I2WI8giH7SwyoEO34
         XkLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mlgL8e37WQ9w4OMP6AOhRdi379SU7fFtbQ2i06fRnIg=;
        b=iG2ZKyjVYcefuSEQ/75TU8jSyQ8KRH/b75NeoAu9wYNZGKFv2yiX2fopBm9ILWTZFk
         rYHqJjhJmhWVDQms7qCuRjdEUGmnzW50WqSGJVWfS/zCaR5Rm+5ihFdG66TOqMG1i7nj
         Zgg1ejrtYcSIou2h3Qc4/QJl68M12IHuBnwq+VIf8CL74m6POgbPRuNJuUi3rGNYTeDz
         uDqcLgT9W/eex72zrxcg1BzB7gGx+VKIaa7ZwWZJN4Jjlx3vFSXeNuv+vBP4T+38EB9L
         6rUG5dK+XUjSz+2Ofxt3nQrk5Mn83OLLj2PqtBl1mm1eAamcX2luq6IxfgUv1tp+eytr
         Moqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XMQFpqRX1RJliPimL+K0cK5PcCsz6UeBp++22H8xPCdY/ARpP
	JYmB5SbaYPy+/VGnw4Cp0/s=
X-Google-Smtp-Source: ABdhPJxErZzAsA61R8/2yZre6qRQVG4tVcNAPYBpSJCdwb+qCMo6DoeHoUYslFwWtoTTYUum8dKd1A==
X-Received: by 2002:a05:6a00:2354:b0:4fa:f195:b0c9 with SMTP id j20-20020a056a00235400b004faf195b0c9mr26449860pfj.33.1648579018298;
        Tue, 29 Mar 2022 11:36:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1307:b0:1c6:9790:ee97 with SMTP id
 h7-20020a17090a130700b001c69790ee97ls2441394pja.1.gmail; Tue, 29 Mar 2022
 11:36:57 -0700 (PDT)
X-Received: by 2002:a17:903:41cf:b0:154:25bf:7d0f with SMTP id u15-20020a17090341cf00b0015425bf7d0fmr30996887ple.41.1648579017611;
        Tue, 29 Mar 2022 11:36:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648579017; cv=none;
        d=google.com; s=arc-20160816;
        b=XRxZuj0N2+ySXCXUzPBJBYjeH9+Ou1j4Am6SPbikAOq8wM8IMBeEjUFhXKYZXVMj1G
         qauxyNBf064wXiJSqf1geEvGfdzmt3VAVf0QDy7eINEjzW4pMAoogxiWTaRuRK4q1tGx
         a8PsrBS9Hi8vVkQcyVrY2c0LAdqwwafnsR+x612i9hi3D4ZLDLqQMOORLpQZCn3szv2G
         C5vIsSmSXedN7JHILiGTnOHWljoZMyCiMfgNbY0acYd0L7no4p21v2PoY9aLB/Z0H6sn
         1P/0q0QeOrQoYtAFZvUbFX2zT9KDyOsVTKefAYhVsvL+0p/4rEGV12QCnD4/V+aRQ6M9
         svpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZahETGQ5QFUGU9cdr5iIBFtuwsgQ6vA8xk/koQJqNS8=;
        b=R2oKRmUiuALpdn+IawNzJYsxN5LkDlamLHOiJk9wmN1vDHph+BJyvzLeR9rOY3fV9f
         2gzbMFcRo2Fv8jMtaYi0rqZVM7JZeXY9Bo8i8K1XfPpKcqri5HELMs2UvRAZTfXOCRN2
         a9TyWsDf8MsU2XIicr6UkJPMlJAp4MmHOYxZrwzwwYRbmZnBCSrxFX/p6BphfaZQoaC0
         A5dbZFD9yzZSlVrBWnrk2XhPpzufRy64ZWq9dtYm8C8ZM0o6wMc4TmS/gL8LmWtJ4kZr
         uQlaX1CBdkJGthtKi8IUFVgnOyadI1jDDVlLxE2v2b6BN8+nxjstciHPBGP5b86nKIAQ
         3Htg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=hIo45tQd;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2a.google.com (mail-io1-xd2a.google.com. [2607:f8b0:4864:20::d2a])
        by gmr-mx.google.com with ESMTPS id o20-20020a17090a9f9400b001c62073e04asi175472pjp.2.2022.03.29.11.36.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Mar 2022 11:36:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2a as permitted sender) client-ip=2607:f8b0:4864:20::d2a;
Received: by mail-io1-xd2a.google.com with SMTP id g21so8868800iom.13
        for <kasan-dev@googlegroups.com>; Tue, 29 Mar 2022 11:36:57 -0700 (PDT)
X-Received: by 2002:a05:6602:3c5:b0:64c:727d:6e95 with SMTP id
 g5-20020a05660203c500b0064c727d6e95mr6978541iov.118.1648579017088; Tue, 29
 Mar 2022 11:36:57 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1648049113.git.andreyknvl@google.com> <7027b9b6b0cae2921ff65739582ae499bf61470c.1648049113.git.andreyknvl@google.com>
 <CANpmjNPJkFOMn1pL-=gx+x_YHgg72QH5iqe561+Geiy3JoOg1w@mail.gmail.com>
In-Reply-To: <CANpmjNPJkFOMn1pL-=gx+x_YHgg72QH5iqe561+Geiy3JoOg1w@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 29 Mar 2022 20:36:46 +0200
Message-ID: <CA+fCnZfOGRh67SUNxQ2cyZLK8JV56GV_sa8AnNeURcgHif5Yzg@mail.gmail.com>
Subject: Re: [PATCH v2 4/4] kasan: use stack_trace_save_shadow
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Mark Rutland <mark.rutland@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=hIo45tQd;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2a
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Mar 28, 2022 at 2:49 PM Marco Elver <elver@google.com> wrote:
>
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index d9079ec11f31..8d9d35c6562b 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -33,10 +33,13 @@
> >  depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
> >  {
> >         unsigned long entries[KASAN_STACK_DEPTH];
> > -       unsigned int nr_entries;
> > +       unsigned int size;
>
> Why did this variable name change?

So the lines below fit within one line. It won't be needed with the
other change you suggested.

> > -       nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
> > -       return __stack_depot_save(entries, nr_entries, flags, can_alloc);
> > +       if (IS_ENABLED(CONFIG_HAVE_SHADOW_STACKTRACE))
>
> Would it be more reliable to check the return-code? I.e. do:
>
>   int size;
>
>   size = stack_trace_save_shadow(...)
>   if (size < 0)
>     size = stack_trace_save(...);

Sounds good, will do in v3.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfOGRh67SUNxQ2cyZLK8JV56GV_sa8AnNeURcgHif5Yzg%40mail.gmail.com.
