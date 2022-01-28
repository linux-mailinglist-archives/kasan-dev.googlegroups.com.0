Return-Path: <kasan-dev+bncBC7OBJGL2MHBB55RZ6HQMGQEOIZLSYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1358949F8C2
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 12:52:24 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id h17-20020a9d7991000000b0059b4230fc63sf3093720otm.13
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 03:52:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643370743; cv=pass;
        d=google.com; s=arc-20160816;
        b=x84RDqW9ew4Sy1fNzE+Qy0NgqnJUfbk0io5owG4Zb8YHq5ThkapZ9QjKL4vfg4WJ8Q
         6dSBKytY3F50qHvULiuMr1+XOOduGD1ObruIsEsBBoBaSOiPG1xdx7hl+Nh6AaS7pRHn
         UY6MriomL8l9K6ZQm8oe3kK75goV+5Oq2s9NdlO+K8WjIHoNySUAi2aGH7JFyYAzRPWY
         QwgJ5q+2XmT9eyLSm+u8/LOWiLrqnN0/craWx10I93V8wRTKekn8zXrF104ns7NrgFoJ
         hFJz+3KSbku3XhFjOShfMb++c1BJ1k5GE4qfNu7qfPufhm/c06K0Ft2GvwSAEr7PWOGf
         3JtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Z44Ah09jue4qAujR4MrfG9GOvCS/29n0ZFbL57iU5Ug=;
        b=oyboGPwMoPgrmh3RDDbgMdQpME1OCSdJX7pmzHWK7Vg4rA4TOb7an9efrNWU6H029J
         nM60Kyx6gyv5htk/bbIYowIA0IA4Wc8mEbejwHuAibhDTtJcyo/J6Izw+H+UAhGQl+EW
         NX1AU4w53aLl5bdjvFbkozcmtaxTkzSDRMKlQUmKTJ4wGGPoYXclNQGQDU/kBwcStBU9
         6xnru28+Kg8zjrTd60wLhNTjx+1k5u54yxpKvJ4UuSx6vLx0fM0VQg3/GhdspGt/DvU4
         jdGADSt/6uHvVcRa53eLgsXruz2Y1j5oXrRqSD4bQhIeB8J8OVpOmqL0ikiURK7Apocq
         p5ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=P6xylPxu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z44Ah09jue4qAujR4MrfG9GOvCS/29n0ZFbL57iU5Ug=;
        b=GbfuBhqg3YXKEXn4ZUO5gW4nnp6PzgB0eHj5/+4ur18XRKnJTnr+BxUuqw6VE7pwZ9
         BKbghE5sdtA8/oe+2lQp13I3U7csIwinp7w1BF3hU1jYEf4Zmd+cr25/kKGIzg4b7/Tf
         0N6M6Y+0K6oNQ8PGNi5dfz3Nt2zyfrIeubEamQvGh9DG7y9wnK39BsWZR1OxA2BsVsVn
         6otRV2bdJrDMj4DssE2aTzqJcH4m0OfmYZnLWyDeZUbEwLbLYe5vo1W8akHlJIyHb+Dd
         yxIMzZnPSoHNuOI/3l9gOUkNbaCzehAdx+QXDCGmxJBr5kL6Kk2XNr0w2u7eAEhU7Lh8
         PhfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z44Ah09jue4qAujR4MrfG9GOvCS/29n0ZFbL57iU5Ug=;
        b=yXQ2Y92oX4n6IPBIOTCWN9zF7KwDeXpw/p+GvgVj+K83SIeBwLXniytyiAdJXG1oRj
         1B0jomV38m2pT04CzhoabYyRAEsTZgVgGDyoh2PMk714rOYR2f0rKY3UV9pIhmJYPTnG
         yku6xYGK0TOyMYEJQOFTvJJU/TeI/ezb95/v9LniUa9QloQO5MXtEyyqemo0zXsMv7+0
         v7M0/DquWwpCEb4xk58guMqnlicqMRVVscvy3uFbrsJ0koqAOwYarnBEuevE+Xi4d305
         +SBpE9tlS7BIphV8FvUic4hayblqdHmDUwUBDAxvaaDl9Y1uhvTpRxWgyul/ut5GLcRY
         22pA==
X-Gm-Message-State: AOAM531FT54XOS5nx9C7OTQ52wSepXJr4nnVx1IZ9KFyiVigX9YD+B6Q
	Rn7M7nvVGrRJKiCas1M7GDY=
X-Google-Smtp-Source: ABdhPJzCZFVvv7wlLuwZciYR4C19Eja6jElL1q9WplAczIsnEP6ooEbed2GhDEjFoD8b488fvjrHZQ==
X-Received: by 2002:a9d:755a:: with SMTP id b26mr4462747otl.230.1643370743080;
        Fri, 28 Jan 2022 03:52:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5d0e:: with SMTP id b14ls1665700oti.7.gmail; Fri, 28 Jan
 2022 03:52:22 -0800 (PST)
X-Received: by 2002:a9d:5f11:: with SMTP id f17mr2266132oti.382.1643370742718;
        Fri, 28 Jan 2022 03:52:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643370742; cv=none;
        d=google.com; s=arc-20160816;
        b=FNp6Z+sBxCQWQAyfTap59FdAaC2U617k7Nh3Ai44+OC/fe3G4PY/tJASOeu/ef9TUj
         Gujg3Xw7kx78Rc5GZGe+jNnJ5IZhv/inrkoJbSCJ4ptPmcxEK8IaebTiP2opb0mFT5AY
         JTT8YGgd2nXYbv4PZllcM/BHh/DyluGd3pOY4AlOzqEIioy/+WVOVUla3qJvozoQaQ0Y
         yskM3Z1PzN3yQZj8TtkPtvDFAilCadOEigtHLMQD9lCEKsd8Bl9atPZbYrLe57dTUswY
         SPSx070FnGEtqbeYksLMCArXm5LnZzwxowTG159PpXbrkCzQa2MTSRASz8rT9bDYRjuo
         a3pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=O60yGiuWnnbcMYfMLAv37vqkxweJf6XzlR6Lpk0bdI0=;
        b=ZteubsprsLSZnsFUVT2ympIRXrXVgml8T58DvMIar6l2ymqrke1YoCaA/xdAlFkDmg
         s8XLewFDd4Ylih9GU1MO0yEPLxEpj5xyqcrSo8cYVsgJvPupUnmj69BqB8lL609mgUK/
         HrHVMUYim+lH5wD4XZ6tJwD7wQvuqbF6nC0zkRz1I2CjXSHCQCSmLBCsOg4dcJnZe1CC
         qWtoadg4mbQvMkRHsoxKWAeaE28XHxk2EzL7aB0LS1j47m1X9zdnIMc6UwFm6l9ZSkzv
         SHY0SL0mRsGrjDTQhB9zGt/3IdqFSzvvkN0SWK9wvp5LXASOGwRjMFnZjgojcpt3gOEK
         OHtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=P6xylPxu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32f.google.com (mail-ot1-x32f.google.com. [2607:f8b0:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id x31si407588otr.0.2022.01.28.03.52.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Jan 2022 03:52:22 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) client-ip=2607:f8b0:4864:20::32f;
Received: by mail-ot1-x32f.google.com with SMTP id o9-20020a9d7189000000b0059ee49b4f0fso5469077otj.2
        for <kasan-dev@googlegroups.com>; Fri, 28 Jan 2022 03:52:22 -0800 (PST)
X-Received: by 2002:a05:6830:25d5:: with SMTP id d21mr3350658otu.246.1643370742236;
 Fri, 28 Jan 2022 03:52:22 -0800 (PST)
MIME-Version: 1.0
References: <1643370145-26831-1-git-send-email-yangtiezhu@loongson.cn> <1643370145-26831-5-git-send-email-yangtiezhu@loongson.cn>
In-Reply-To: <1643370145-26831-5-git-send-email-yangtiezhu@loongson.cn>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Jan 2022 12:52:10 +0100
Message-ID: <CANpmjNPYYAy2jy_U_c7QjTsco6f1Hk2q=HP34di4YRMgdKsa+g@mail.gmail.com>
Subject: Re: [PATCH 4/5] sched: unset panic_on_warn before calling panic()
To: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: Baoquan He <bhe@redhat.com>, Jonathan Corbet <corbet@lwn.net>, 
	Andrew Morton <akpm@linux-foundation.org>, Peter Zijlstra <peterz@infradead.org>, 
	kexec@lists.infradead.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=P6xylPxu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as
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

On Fri, 28 Jan 2022 at 12:42, Tiezhu Yang <yangtiezhu@loongson.cn> wrote:
>
> As done in the full WARN() handler, panic_on_warn needs to be cleared
> before calling panic() to avoid recursive panics.
>
> Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
> ---
>  kernel/sched/core.c | 11 ++++++++++-
>  1 file changed, 10 insertions(+), 1 deletion(-)
>
> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> index 848eaa0..f5b0886 100644
> --- a/kernel/sched/core.c
> +++ b/kernel/sched/core.c
> @@ -5524,8 +5524,17 @@ static noinline void __schedule_bug(struct task_struct *prev)
>                 pr_err("Preemption disabled at:");
>                 print_ip_sym(KERN_ERR, preempt_disable_ip);
>         }
> -       if (panic_on_warn)
> +
> +       if (panic_on_warn) {
> +               /*
> +                * This thread may hit another WARN() in the panic path.
> +                * Resetting this prevents additional WARN() from panicking the
> +                * system on this thread.  Other threads are blocked by the
> +                * panic_mutex in panic().
> +                */
> +               panic_on_warn = 0;
>                 panic("scheduling while atomic\n");

I agree this is worth fixing.

But: Why can't the "panic_on_warn = 0" just be moved inside panic(),
instead of copy-pasting this all over the place?

I may be missing something obvious why this hasn't been done before...

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPYYAy2jy_U_c7QjTsco6f1Hk2q%3DHP34di4YRMgdKsa%2Bg%40mail.gmail.com.
