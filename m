Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZ6PSL5QKGQEUP32TCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AEBE26FC79
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 14:28:25 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id fy7sf3017722pjb.6
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 05:28:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600432104; cv=pass;
        d=google.com; s=arc-20160816;
        b=GSjtjjksOi8QmfErn7EHqXYYN2iuSUUdPNtMG4Bn6/8Ga6Hu2fo7EU3r1gAs8wRABC
         lApBVX8M1ZizQGMABB7Y3mIzS28lv/5W58W7YLRxz5eQ1CN24XeRcEyrt7N9I3PgIyGb
         Fy6hzAw6nHxi3+p+EWAOQ1wakZEQHftTtFktBjkc4OxBkxamVcpQ7FIgIL+0KAvdKqbg
         Q/zsStAZXJiS9p9e2IWPNonMx1fitM4OvWvjZiyuDdZ9mt661pIwF9lb8b2xS0g8AoCg
         xS9azxwrUOOpT7lrVE8qBZTSgMs9LYhRDenV1TDxh1fCTSWVeBOKQJ+3AjhpC2VptlSu
         hE7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Oq8Exg3SKswTWANB1hcVdnaK0CFa/xvZZPwHk+1zlbY=;
        b=ouCPg5B0IMltejrSQdZtEhM5S2lBfLzvAgU8Vk4U1Gfl6XDAPhlPZIOEDTmznSlNw3
         AUHX0WF5+HLUWv8GKo1y8Ewu01BqV1i3QD6N8f8v/8kVYUGtV8mev9BU++Arg5eBXtgD
         iYaZ3o1TT321PCOR2qEBMGxJCXEi4M45szLMR9/YsRuONS8TQjPl4IDBqd1en9VMOMP4
         Bh1RgaoMv1AI/3eavHdEgUAdaUtqQPJ5YBrtAebs+Jc5cLvfpf6hQP19kflt6as2Nf+x
         I2FQD2xphO+UW7NxBg/ahe0pPuPhUzKAbxT7+cLdAzZygekVl2E3ZZTKeJTFk1x7NkBD
         8JnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="u/tah1Kn";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Oq8Exg3SKswTWANB1hcVdnaK0CFa/xvZZPwHk+1zlbY=;
        b=fI4z76K/2SUsvVeyVyfYrPwZ9m5d8nhU5ZkT5+OGizhUrvI+RZe4UvLDFFzTR/uTcI
         /lV4BxVo/XFyEUEq5c6210nLNQL5VAUJ2ZMcWcGVnGWxe0i4svZKCZGlbOVR7RE164I8
         9+I5uqrnjDDajRgmLYzucBdsS0phpNWRQm00CjcGaRnEUREDjsbuZFBWVluMTvLsRjYf
         XzftuaZv5Nw3kwdJToBYUz3JNdyPsUOkJarqnXcm3hM5ZM1C3GOlLXtjYoISJRuC851U
         aYGAPI53qHgJ2VI8TJOkDMt1imEhb69pUFsmgKC95TSNl0pP3TMrmi6pxeXh4WI3pDM6
         X+vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Oq8Exg3SKswTWANB1hcVdnaK0CFa/xvZZPwHk+1zlbY=;
        b=OQspo/1puydQWOer28HvtKVO3SOA4BllYuvw7pkerFvE1aZ9qWSqx0ss32z5xNRcvg
         hSQMGaq4eLC0K98Z5Oc8Buu86gDOLt6/DspqbQ6DcDgo9cLnQM5ryh6uDqGQnBDVq3zW
         T6EefCno2TGc2bA2S7f1FuQWPM997eDE767A+61v1iaRRWUcN47mBNSjUHeoLh63nQO4
         MQ1M4It6lWFKYvA29JcmJMqp7FGO0RCmfX3Bz1yq/Y+PSfF+D09G6kgDNIhogU/Gln2f
         uK2IZIWmIEUoRr5H4BNiR+oTPQAICGerhgOCRr0DPjO+lf0lql59PjD2a9UPbcysRj+d
         cCRg==
X-Gm-Message-State: AOAM533oypDYj17IAkFWfxRsRhnopI9a2KW7/WoJxxa1gxu5o2KF5c0e
	Wp9blTgmwRN4QvvzMUvGvGc=
X-Google-Smtp-Source: ABdhPJykQvSLl5xQkWO2Amw3/blMT/gsYQMKbyeQqNB7l8I3TVn1tKU/2BYUZRertP67l5SgwrMasQ==
X-Received: by 2002:a17:902:6bc1:b029:d0:cbe1:e706 with SMTP id m1-20020a1709026bc1b02900d0cbe1e706mr33267799plt.20.1600432104082;
        Fri, 18 Sep 2020 05:28:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8d89:: with SMTP id v9ls2692039plo.4.gmail; Fri, 18
 Sep 2020 05:28:23 -0700 (PDT)
X-Received: by 2002:a17:90a:de81:: with SMTP id n1mr13048386pjv.92.1600432103500;
        Fri, 18 Sep 2020 05:28:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600432103; cv=none;
        d=google.com; s=arc-20160816;
        b=EvLaSLdtP64yV2CHji1XbA9gtQOFWgJrnAvuiraq/Mi+5H3Wc2lbZMEYv+q5FqIsTf
         D1FRkaUgEKC7H9JxGEAR66JvOzHLXajwwqnuntopR71SJ0meVNEBBzsFuhSuZD8CuM9e
         2Zetc5tmc9Nl0Hv/NSMmc+NT9YlXIpOpf1sBjdJOdWrrf+l6Uss3rXmrjphC5BIfCpkK
         F4pFx+uBeSXiA5YOnTOqek6A/sgZblrvV8+u0QrzYOUzT5OdUTNVc2eKUXctQEOEccNt
         sCDTJrNp0NbPjJQFAAStcMiNgB1cAsGT/p7gLbvg5oUNkpuHGuBMyE7Pq2jqSsfN+qjr
         4Ycg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P7ycjQB8Qf5Z6caxe0rnViEryCtRi9d3yDaiZcexIRY=;
        b=Yi/JuYMpD0CVcSoxAJ/YMNPR3kGAPO9g0dGXGr2TmjMfGUcK90TGdRpnQ3pknQCo1d
         as8C9uzDdZbz0F/UnaNF0d7fgTDcMYUmlakp8s64X++kx7TDGWqJ+mFVE7s52L9868ve
         go8XQoxyAqF9bj25x9+Uo1EftkOpl46tzZchetcb6M059iY7lBvW5INZaaPEFRbjgPIe
         e6m5jwgFEO7EqRd4Gv3pMu5baxS93MfelBz0LMxUOyEF5Qo0lEegJj6TVY8Xei7ABT0Y
         4lSGnWgQ1fzvkUVwQN9hVKavyZ0Gw7W5lIEP9RWRze8zMJ3i5h1qeYgYnmAysOiuzP7O
         GO3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="u/tah1Kn";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id 17si73834plg.2.2020.09.18.05.28.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 05:28:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id k14so3376423pgi.9
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 05:28:23 -0700 (PDT)
X-Received: by 2002:a63:2209:: with SMTP id i9mr21795613pgi.130.1600432101917;
 Fri, 18 Sep 2020 05:28:21 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <74133d1a57c47cb8fec791dd5d1e6417b0579fc3.1600204505.git.andreyknvl@google.com>
 <20200918104650.GA2384246@elver.google.com>
In-Reply-To: <20200918104650.GA2384246@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 14:28:11 +0200
Message-ID: <CAAeHK+zxJqQ3v_K7UkMMMrz73+3LQwZctDGngrJabXtiXU5YvA@mail.gmail.com>
Subject: Re: [PATCH v2 33/37] kasan, arm64: implement HW_TAGS runtime
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="u/tah1Kn";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542
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

On Fri, Sep 18, 2020 at 12:46 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Sep 15, 2020 at 11:16PM +0200, Andrey Konovalov wrote:
> [...]
> >  arch/arm64/include/asm/memory.h   |  4 +-
> >  arch/arm64/kernel/setup.c         |  1 -
> >  include/linux/kasan.h             |  6 +--
> >  include/linux/mm.h                |  2 +-
> >  include/linux/page-flags-layout.h |  2 +-
> >  mm/kasan/Makefile                 |  5 ++
> >  mm/kasan/common.c                 | 14 +++---
> >  mm/kasan/kasan.h                  | 17 +++++--
> >  mm/kasan/report_tags_hw.c         | 47 +++++++++++++++++++
> >  mm/kasan/report_tags_sw.c         |  2 +-
> >  mm/kasan/shadow.c                 |  2 +-
> >  mm/kasan/tags_hw.c                | 78 +++++++++++++++++++++++++++++++
> >  mm/kasan/tags_sw.c                |  2 +-
> >  13 files changed, 162 insertions(+), 20 deletions(-)
> >  create mode 100644 mm/kasan/report_tags_hw.c
> >  create mode 100644 mm/kasan/tags_hw.c
> [...]
> > diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
> > index 77c4c9bad1b8..5985be8af2c6 100644
> > --- a/arch/arm64/kernel/setup.c
> > +++ b/arch/arm64/kernel/setup.c
> > @@ -358,7 +358,6 @@ void __init __no_sanitize_address setup_arch(char **cmdline_p)
> >       smp_init_cpus();
> >       smp_build_mpidr_hash();
> >
> > -     /* Init percpu seeds for random tags after cpus are set up. */
>
> Why was the comment removed and not updated?

Will fix in v3, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzxJqQ3v_K7UkMMMrz73%2B3LQwZctDGngrJabXtiXU5YvA%40mail.gmail.com.
