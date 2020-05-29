Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYN5YX3AKGQEZMUCSNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 34B521E8765
	for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 21:13:39 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id a9sf1043494uas.14
        for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 12:13:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590779618; cv=pass;
        d=google.com; s=arc-20160816;
        b=lu1d/gdwSUTIxYrUfP2M30ZjLYviu/O55IsFipeyJVLgFl+0nxgbdqpsacR9OmPl+A
         dzDFs+ieY4Udf6tfqOJLazQBBcBKMthD0OdKd70Z30AoQHs/89VhhOGRMje921Zo0TCX
         EUJDaXHBc7WM3H+U40tP4eugs78SZDnt8NakcdQ0PMVoYj3tkeM9NZRRfoekApBMhxN5
         RRnNW4ksHhR6KMps8gaf1zojzx+XhSJp0ot+qDDB51CVqNpVuBNFC65fLvmL3Cgo5Scb
         1ohQWcrfG3pt34jXZf/DiwmF0Kdk3U8EvB9T3iIUidWzN01MNRNjezHq4w+BftAma+xj
         rsXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gQgdjGGu+vfa/0eTg0jaqzbnb6T3xuXCgjS9JWoFZeY=;
        b=nvS7H6+4MTN1pdRxaWR5/xZWg3EuW+v2jjp0Q273yjcz6jbvDNOJsnhk5CY2Xf/Gz9
         V2WbG8BtEtdkcXAtBLtMItmgkL/g6POlqV+3uBcZeA3JqQ9RZCn6xmJ/54yE8iLch+ZW
         8RD0VnadtfmGTVCxg+EImVWSeR+vQm8WdG6p0y7nenj3Irre/mfLTH2IIJxStyllYMpE
         7vkYRZjyeJsfYzeiMkqnm6hNBDed4dtDHVW2WdF6d3Wqv/tffKqIwUMnjRaQfl+OHib3
         bRKy5eFPuChU8D07PPt6kXGEopdytxjKbY0+aKGJD4VK0EQGgYt6yoJC823AVCyq7GOI
         IShQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SV7JaaRY;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gQgdjGGu+vfa/0eTg0jaqzbnb6T3xuXCgjS9JWoFZeY=;
        b=iTnAoPGtQSbjQXR8FG8Xts11Uet6dUao0cgnRhlRNSvA2L82Sr7LKhKcJQGztaRjke
         gf8PrhOaDtu/VX6dKtQ7SSO9IzKI0FB+dz3cToIwMTKsWXiF0wfdaUfNrqAtyIdKEgK/
         HTMGioadNAREhGPccJ8tMWHGpxSIOnOgu5D1xf0Q9V4yPbj7y0U5Yl+JS3LPOgNoo5Jr
         q49LI5/3RmePqTqoqIPQkqJBinBsjfcWqBsQ/Pd0+1F1ZiEMToZFaSyQ2lt4V1jZBdsL
         zyBB7yWmz8DtonF5Yg/1CZgc+XJzpLSMkTmrwGw1ITSxosr0X46pLT5Ht28BtDggO6wi
         PzhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gQgdjGGu+vfa/0eTg0jaqzbnb6T3xuXCgjS9JWoFZeY=;
        b=bC6tQBYKAeoyYOyAst6ylzCgZg6Vjoxg5L+hcHweDWIXW7/aGdyso11A/Uhl4lkLJ9
         KKBMtjmUBBQUByVToFAOUYNYw/pFuEVYATYz+UYbUW/mMjhLLaM0wrJOtKpS/Ox5b/Ek
         cl2IkbovD0FCR6bYs9eV5hHd03XKWhpUf8fsFSOV0nazhB3GxOq4SIjLJe+xUR8uPhiW
         ck2YBLgGrDggkpsP6PFqk5c1WsCBAVeyViVcQ0DiEMH63mXw+RBSHVf6HjILWxVDhoSg
         iZ8MzCzspHe7BFnwEOoCjjzMLBFNhKNOSxgQPCWr9Lx415qQUX0gB+gZ4aTCu9JG/lrY
         4sQA==
X-Gm-Message-State: AOAM533BOtJ92n3IxkM7JzWTgI7pvJ+uv6K1q3KLXpbaJaQRFx6ep80C
	BmwvUcPVRaf+NtOT+UpXT7I=
X-Google-Smtp-Source: ABdhPJwHXeS5JGv2fL0HOR50z4iIWvvGx4tJCxI1zWYuLbK+nG2H7kZU+KiaB4kTlV3XQv4S+VvbjQ==
X-Received: by 2002:a67:f557:: with SMTP id z23mr7351826vsn.32.1590779617927;
        Fri, 29 May 2020 12:13:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:3092:: with SMTP id w140ls832837vsw.1.gmail; Fri, 29 May
 2020 12:13:37 -0700 (PDT)
X-Received: by 2002:a67:f499:: with SMTP id o25mr7151557vsn.0.1590779617495;
        Fri, 29 May 2020 12:13:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590779617; cv=none;
        d=google.com; s=arc-20160816;
        b=auCEkj/Z95404vm367bqYC7WIF3I4mTb5mGoeMlXcs2oi4ClO7gBBpiPX/rzqpMmQq
         J/Az+V/9MO9QXD/LTB3zn7WwdF+HuuPqyPLKk63QXd0+1IZF9pvvO90Oh3dkoVZAtQ4v
         0d0J57c7DBxDztNhsomQ9zvb4aVxgvB8oIIAe2wlaEKFesS7bSqaDb3Sc1fMCLQJ8dds
         c2ifhRj3/YJRp0+K8dRmNOqR3E1Jdm8qUFC2JPOt5O2kDiuGJXp7t9gQIR6Fx7zxQPV9
         oRITUT3fGNMVR2y65qQ/Jur8s/JZkGxwS0RhbC8zpJ7k25LUr2IHemodR6wjPq6hvakU
         bq1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oaFnjUA4dY+z1OHe26Jg20HjGUXEg7dL6NAWsqRKEyg=;
        b=WxKWsY4BKtJGbMzugFuXQFIOdEnmuFvxSWwEqwNGgsIJblEV/Harhq3AoMwtjoIehW
         1SAxP4HMZuIEDZf1eRANZHryfp+DekkJ2Yogmdxo/2j7L7HerBSIDv17GUjlB00sYmOe
         xGr9j+/XMNofvmFIdMd2cAUUHFfc+jBUK3p+Y8ZX59geRPQbDodPfXE4sqi+8nNr9sJK
         3Lf8kBhat97BCjnEOIt53nf9+aV5oBc0chZC+d82aQBrc9u4ibkUzGO2EwVfGNLksD3p
         3921NzXzH9VgiYU4HWYZzAnvyrZC+6NMK0osQuKGHyPSp/WP4PZYIM4MXfgtumUUtdnO
         Gztg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SV7JaaRY;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id b20si461828uam.0.2020.05.29.12.13.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 May 2020 12:13:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id d3so1619864pln.1
        for <kasan-dev@googlegroups.com>; Fri, 29 May 2020 12:13:37 -0700 (PDT)
X-Received: by 2002:a17:90a:2a8e:: with SMTP id j14mr10688817pjd.136.1590779614972;
 Fri, 29 May 2020 12:13:34 -0700 (PDT)
MIME-Version: 1.0
References: <ced83584eec86a1a9ce264013cf6c0da5e0add6a.1590686292.git.andreyknvl@google.com>
 <CANpmjNPr5MrwPFOW10pRkUgxwktXNiUweNj+pGJMunoZKi7Cdw@mail.gmail.com>
In-Reply-To: <CANpmjNPr5MrwPFOW10pRkUgxwktXNiUweNj+pGJMunoZKi7Cdw@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 May 2020 21:13:23 +0200
Message-ID: <CAAeHK+z_b+EEX+raj_WQ9xVG11HrQDb5nMGJpyvFS1t=x1MFKg@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix clang compilation warning due to stack protector
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SV7JaaRY;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644
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

On Fri, May 29, 2020 at 4:56 PM Marco Elver <elver@google.com> wrote:
>
> On Thu, 28 May 2020 at 19:20, 'Andrey Konovalov' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > KASAN uses a single cc-option invocation to disable both conserve-stack
> > and stack-protector flags. The former flag is not present in Clang, which
> > causes cc-option to fail, and results in stack-protector being enabled.
> >
> > Fix by using separate cc-option calls for each flag. Also collect all
> > flags in a variable to avoid calling cc-option multiple times for
> > different files.
> >
> > Reported-by: Qian Cai <cai@lca.pw>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
>
> Thank you! I was about to send an almost identical patch, as I
> encountered this when using clang.
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> >  mm/kasan/Makefile | 21 +++++++++++++--------
> >  1 file changed, 13 insertions(+), 8 deletions(-)
> >
> > diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> > index de3121848ddf..bf6f7b1f6b18 100644
> > --- a/mm/kasan/Makefile
> > +++ b/mm/kasan/Makefile
> > @@ -15,14 +15,19 @@ CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
> >
> >  # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
> >  # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
> > -CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> > -CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> > -CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> > -CFLAGS_init.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> > -CFLAGS_quarantine.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> > -CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> > -CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> > -CFLAGS_tags_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
> > +CC_FLAGS_KASAN_CONFLICT := $(call cc-option, -fno-conserve-stack)
> > +CC_FLAGS_KASAN_CONFLICT += $(call cc-option, -fno-stack-protector)
> > +# Disable branch tracing to avoid recursion.
> > +CC_FLAGS_KASAN_CONFLICT += -DDISABLE_BRANCH_PROFILING
>
> Note that maybe CC_FLAGS_KASAN_RUNTIME could be a better name, because
> other flags added in future might not be conflict-related. But until
> that future, it doesn't really matter.

CC_FLAGS_KASAN_RUNTIME is a better name, sent v2, thanks!

>
> > +CFLAGS_common.o := $(CC_FLAGS_KASAN_CONFLICT)
> > +CFLAGS_generic.o := $(CC_FLAGS_KASAN_CONFLICT)
> > +CFLAGS_generic_report.o := $(CC_FLAGS_KASAN_CONFLICT)
> > +CFLAGS_init.o := $(CC_FLAGS_KASAN_CONFLICT)
> > +CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_CONFLICT)
> > +CFLAGS_report.o := $(CC_FLAGS_KASAN_CONFLICT)
> > +CFLAGS_tags.o := $(CC_FLAGS_KASAN_CONFLICT)
> > +CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_CONFLICT)
> >
> >  obj-$(CONFIG_KASAN) := common.o init.o report.o
> >  obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
> > --
> > 2.27.0.rc0.183.gde8f92d652-goog
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ced83584eec86a1a9ce264013cf6c0da5e0add6a.1590686292.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz_b%2BEEX%2Braj_WQ9xVG11HrQDb5nMGJpyvFS1t%3Dx1MFKg%40mail.gmail.com.
