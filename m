Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLUKT33AKGQE2CAYQ3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id F075E1DE158
	for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 09:54:23 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id r137sf7566291pfr.17
        for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 00:54:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590134062; cv=pass;
        d=google.com; s=arc-20160816;
        b=NW6Pm0ERdnoUpIsm/9GuLbaty31fRE/5Gc254cI4Kqz0zat2Qyg7SXa2wOxT3WiMiN
         pK3CjeOtxSjY0ypkXmxxDL42RoF6OYE2HluqI/2LGtUgasBmOTAnuu4nK/wbrsrBBDwe
         zW5LPqFssJczCo9/GJHbxZSLEu7JZ2p9+5hJCfg4S6bkgWGYSXWrB7ceT0Mfjk1pvN0c
         RKyfHT+O1udQlG3g0IKAMUgjFMeDn5yGt5cSyQY9yR2kOI1Mi7bB4QRl6ng2F/xai4ms
         g7n7k09YP+SnUycILxZQTRd4pzjjWbHylBpnbFeWsLdVlWzvqxUwwYoW3/uJqAyEr/T/
         kJdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XRTEHQ4W/ApAjCyxPGry5KO4IGC0uXzUZFKe9nF/KGQ=;
        b=s+RK/Q6JLh2sAoX/ZOk5HBnFbUNme4OA2JMEaD8AbTdipKq++gs2jTpeZz0pQz0DIX
         awIbBkIVf8QiUMRlkewFXTgA0EyXeno6J5TSueElgt6ol94nmFizPq5w+BPRGtbfnVVS
         sxI9z2hl43SXqYEuMvARrEYXYedRC7jkfAGrEYkED8To5t0osLxBPgl3hyBidscOH+qc
         tPG1JOW9fKehS7J7ZkL1jlFzcDmEMyJkWXmoTW3/V9cqKrYCbZeAf7zLtFdm6W0WNFDG
         5/wfDZ/WlaRUEV5vty0tpuX6q2euc+yahQaaLeH01lm26lq1eqmvQvR6FGVoQ6kSxWiy
         JQYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Js0gHi2D;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XRTEHQ4W/ApAjCyxPGry5KO4IGC0uXzUZFKe9nF/KGQ=;
        b=kx6Mp73YA1eyLyElufau2fRLdoOG2kNHN6pSb8cvV2njDFmXD+1I6mGVLf4AKZU3yH
         hqVzlwagYAueR33pyBL3j5tC0oauSteQ47cholFVHuOHD1Ec0OelG5O11JC6gvqRtRjS
         OseniM31mdXKto8lhioPoeWWTvYWBaQ9qBqoCmBb36PvGgtsedK3ZtAFTIDo8aBNJV6v
         6Z5Ex0jZ3u9Sh/CGmNwIxi8IewNYaWjACgJPdniCWh1dMsDZ1lY7Pam2Nl+pW8zQ6sf3
         Y2m+niFZHw3+PMaQAfIb+1tnDLswAyqy+jxX9Q3+AA4YoJxeODyU0lZM75aSLAf/MDIV
         gyGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XRTEHQ4W/ApAjCyxPGry5KO4IGC0uXzUZFKe9nF/KGQ=;
        b=f4Tb2v4rP2S/sj5XRoVMzkDEFkKjhdXfLeRTcZkzYkCxf5HvgCkcuXJzv1qWe8lOxo
         i3ypQgwC8ccaTECTbHJMBl9a05284SkiAhk059KatPhoRDjKTIDYw91GtX+CR+mPfSgd
         W+xUn5xxp2DUrl2wSyZlh2s42WDFdlxwxrC0n2V56jV2EQ9u64K4a7vsHJmSWOY1X/8U
         HCXwKVkb2mMzJizw5qnr6CzuX85oN78Vx5PzKGroD9bg7Z3raCz+ASW7+zqrxOWcKKPP
         71rqvYp3xerccdHBbW2E5BFb/mIfBfHSI7FPlGq9QCwKft/z87wSJ6KsjJUx/wGZWY4V
         9qWQ==
X-Gm-Message-State: AOAM533JVRCouvQf6K/oel9v/dOrtZKMryJ4e6uWXqWszzAuU6/SZ86F
	XLvln8xYSqK9jj8cIMUyNdQ=
X-Google-Smtp-Source: ABdhPJwJZARhR3Ma36+3VTRykXjcLHD0s3vp4f579wEBewpmq+JrUYm2Slrmj+9tWYpoYU6qMIM2Tg==
X-Received: by 2002:a62:76cc:: with SMTP id r195mr2667151pfc.116.1590134062457;
        Fri, 22 May 2020 00:54:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8f8f:: with SMTP id z15ls294841plo.8.gmail; Fri, 22
 May 2020 00:54:21 -0700 (PDT)
X-Received: by 2002:a17:90a:3228:: with SMTP id k37mr3126624pjb.118.1590134061889;
        Fri, 22 May 2020 00:54:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590134061; cv=none;
        d=google.com; s=arc-20160816;
        b=MHF4jtKdLShJrvnAcr21t0fVYLtP2Kxmg3/tCfM5/XsV+J3MELD7SA10+64r+w8iSz
         XDBCf42eDHCC2JoakRqVUXhiDdYC3kLlkiJLlNawp8ar2DovjEIYDIeePHBxcGmKlNRl
         lj4hrwYILlmzJPAWHQ4bVVp/g6SgDfxYtIeyY805v8c61NKSq1Y3i4DDRw4ggQrVVSY0
         b+VVQh+eWH7tfcyuBtLClMLnh3KlI0FbEJN+iemQQYk7uRTdPVVm0UYMTzfdbfDLsj+n
         QaGSqhQqcD1ymL6myk3/dPppEU/6kXgF7jLYQfNEbeebz5tT/r8JQl1RBlCyZ0/sJXsf
         7a0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HDvjesLpXeZbOqZwVDwcodT/WLJvvTdpPsS1Pe0Kvbc=;
        b=cK0Sv4CILeHEXFQVxm3NYQWeJEqGfEPiVQQaeciVLWAH/oEuF5NwszWpRLW9nm6GiL
         QxQTXyFI/OGImwvlUxKxR1UN4RBehGMWtUrfC6rMmsUJAk24Lql0wFxXBZQbWFscLXaP
         GkYXZ4eu61cgCAgIzE4cOOoFx5vLuDcDvvmViyz6HoBPNkcuqR6z6GZ2Ctd9RvCKLgt0
         gEt0LBWysygYk2kOfByUw5odf/vjZAyzd17xsTPTgBToliKPjh7TlwMRtNVtGVGStqEh
         3LJUe+zBxUPzWHPVqMu228nLQQJ+TsnSXnog2gkoprvDs9MezUZLnXz71MZbzz0FrEX2
         mbKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Js0gHi2D;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id a1si535494plp.2.2020.05.22.00.54.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 May 2020 00:54:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id s198so8573080oie.6
        for <kasan-dev@googlegroups.com>; Fri, 22 May 2020 00:54:21 -0700 (PDT)
X-Received: by 2002:aca:3254:: with SMTP id y81mr1737976oiy.172.1590134060936;
 Fri, 22 May 2020 00:54:20 -0700 (PDT)
MIME-Version: 1.0
References: <20200519182459.87166-1-elver@google.com> <20200521221133.GD6367@ovpn-112-192.phx2.redhat.com>
In-Reply-To: <20200521221133.GD6367@ovpn-112-192.phx2.redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 May 2020 09:54:09 +0200
Message-ID: <CANpmjNOi4yx8guwUeYx_NZUEiNVtSXzWmW5Zq1DWJ2bvuwFTgw@mail.gmail.com>
Subject: Re: [PATCH] kasan: Disable branch tracing for core runtime
To: Qian Cai <cai@lca.pw>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kernel test robot <rong.a.chen@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Js0gHi2D;       spf=pass
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

On Fri, 22 May 2020 at 00:11, Qian Cai <cai@lca.pw> wrote:
>
> On Tue, May 19, 2020 at 08:24:59PM +0200, 'Marco Elver' via kasan-dev wrote:
> > During early boot, while KASAN is not yet initialized, it is possible to
> > enter reporting code-path and end up in kasan_report(). While
> > uninitialized, the branch there prevents generating any reports,
> > however, under certain circumstances when branches are being traced
> > (TRACE_BRANCH_PROFILING), we may recurse deep enough to cause kernel
> > reboots without warning.
> >
> > To prevent similar issues in future, we should disable branch tracing
> > for the core runtime.
> >
> > Link: https://lore.kernel.org/lkml/20200517011732.GE24705@shao2-debian/
> > Reported-by: kernel test robot <rong.a.chen@intel.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  mm/kasan/Makefile  | 16 ++++++++--------
> >  mm/kasan/generic.c |  1 -
> >  2 files changed, 8 insertions(+), 9 deletions(-)
> >
> > diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> > index 434d503a6525..de3121848ddf 100644
> > --- a/mm/kasan/Makefile
> > +++ b/mm/kasan/Makefile
> > @@ -15,14 +15,14 @@ CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
> >
> >  # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
> >  # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
> > -CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> > -CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> > -CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> > -CFLAGS_init.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> > -CFLAGS_quarantine.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> > -CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> > -CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
>
> mm/kasan/tags.c:15:9: warning: 'DISABLE_BRANCH_PROFILING' macro redefined [-Wmacro-redefined]
> #define DISABLE_BRANCH_PROFILING
>         ^
> <command line>:6:9: note: previous definition is here
> #define DISABLE_BRANCH_PROFILING 1
>         ^
>
> This?
>
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 25b7734e7013..8a959fdd30e3 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -12,7 +12,6 @@
>   */
>
>  #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
> -#define DISABLE_BRANCH_PROFILING
>
>  #include <linux/export.h>
>  #include <linux/interrupt.h>
>

I missed this one, thanks! Added this to v2.

v2: https://lkml.kernel.org/r/20200522075207.157349-1-elver@google.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOi4yx8guwUeYx_NZUEiNVtSXzWmW5Zq1DWJ2bvuwFTgw%40mail.gmail.com.
