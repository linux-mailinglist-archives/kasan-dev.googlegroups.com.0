Return-Path: <kasan-dev+bncBCJZXCHARQJRBAPVSH6QKGQENXWQXCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3461F2A899F
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 23:19:47 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id w79sf2387329pfc.14
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 14:19:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604614785; cv=pass;
        d=google.com; s=arc-20160816;
        b=FSDkKdYDhcvB6eSgBbi9pp1PTGMDVbt69v6u0eAezfh0LBkxca6y3yJ4WVDT4Dmvdm
         lic3uuMBrPt9PbPTpWlBxkgxaRzzATt92DErIMQKc11T+ggOf5T9K2afN7xgaiQBNMTs
         37brdntpsXRRzY/0yCVGYdXJMXnafj509lGLQVim6j1aks5sPINNO0VvrD/1DkAgNgKq
         Px+aKbLSLvGWUrBA6LaKCy8qcIUB+8vj506fnEg+ZgDNsdEp27aZ/mHCk20Qfvib0j4U
         OhdzkJMilhw2KvnvuqOt+LFde05MyCbe14ANP8qldHAbToj/hQU+lqUc4nmaSqZfIDtd
         enPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xJo9I9qiRnmd6Xwhgpw17aRnI8r3ftCbgPwabPGKQ1E=;
        b=qMpBKRGpu6iIAIxgf/n+4g86mAnYJ3AG0ZfJ9YL4zOtgnpgsyd/hGz4bqzQssMjJel
         1O14Uy3cOo6dfl7qfty6LgTB+2iXzmDbLCQDTtz8nfc1JufWkzkNz+UW7b4nR6x+Arf6
         NoKw6yZn9GH+GZ/JlF9gpN+5lMxApxn1EXxxGw7yR4YPFaBUZsWfEFHYhwVKDzogE9bM
         ghit53Pv8AHyTWgJ/dcn02eLOUYFatIStYybNryy1DY5zGIz3U4OhJdujas2YWapN4lZ
         /2VgfDbyU+c71Z3egrHW/vfKZ/c2yWnMLRKzAjQbZQ7CrmUvTm2jWVAmw/nH9gul4D3x
         XNCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bSu7029B;
       spf=pass (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::b43 as permitted sender) smtp.mailfrom=eugenis@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xJo9I9qiRnmd6Xwhgpw17aRnI8r3ftCbgPwabPGKQ1E=;
        b=b1fVkB88P9es76O0gmzyARA/Dy0UvxIIJS9+v6qHHQK/JIRRzbStW2UlR7v/s5p3zH
         cs8v/hyWnAryc+imIyCpJfOirf+3PEpUms2uHldy7joNa7uZ/doQcM3TbLByAc/HGcYE
         m8rxjdteVKofvFovr7liKT0RjwcDHIP7qMcxXoXrDYesWHN0iTJIyVgCcS9Ck5/zmCxG
         X2CgocveacWt2+a0J5IdmNtCfpG5R6xcnkrbHwo8oNC2Xc7Z9OK6mAC/8rJiDDrAE8gc
         ZqQc5jtGM5tV6QUaY3skKNlrZT0sznygl5FytWTiwgQZtwVbLULbXWl5p5EpqZQ/7L3u
         lA7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xJo9I9qiRnmd6Xwhgpw17aRnI8r3ftCbgPwabPGKQ1E=;
        b=JWToKHlSDq2cKdlKB++rk8ursPUPBg48uDWSrrdl3TAnlg2+wGe3X9JmTpkdAYl7wr
         ZkhNP4n6SuQMsjmZETVR4tUtkRWIjrUjh7BHEOVBVwcbbYb2j0ukkiafm4tmhXFLAW9p
         p/0dYIP2oNOLeCr1XfzyW8+D/LipeYkZq1aKIhDYKIz6PXXafFTcgbKuiSGXEOBye1PL
         W/3XYgHAh177RJjbaoM18FKTMcvODZNwFUH3dcfFENLShr9wX+/9Y+Ei8FAB7YIllMGp
         KAVPg+Seh07DH4ugzaHiAUghnVO2M2DPyUWIgBhas2g0ywZ5RGihFDhvfQV9wl1Dq7KQ
         +RAw==
X-Gm-Message-State: AOAM532+I/ZfxbPpU4VGYYE0NvToYYusbZSm2JrI1J601vNyZ+7S4DUB
	WjqhAOU8D+TaukP7pgw8rJw=
X-Google-Smtp-Source: ABdhPJy0U81zYSquFF/2Fj+JsZXxkWb+cio73SakY/mIsZROen9RyYGBxLLBvjjqzB8BYaE57QyZpg==
X-Received: by 2002:a63:b548:: with SMTP id u8mr4247780pgo.356.1604614785603;
        Thu, 05 Nov 2020 14:19:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6a85:: with SMTP id n5ls1271975plk.9.gmail; Thu, 05
 Nov 2020 14:19:45 -0800 (PST)
X-Received: by 2002:a17:90a:af82:: with SMTP id w2mr4591723pjq.77.1604614785023;
        Thu, 05 Nov 2020 14:19:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604614785; cv=none;
        d=google.com; s=arc-20160816;
        b=U1le+4dz5atLWL5maYnJnGJaf5dDaC2eIjWFDz77bKfEGLBWNWcEYH0GdCeah7pDtP
         lsLWStHxreQtWX2N0rFLLA3rnXVkaDbaxnx3Opm8y3w56sLpVTOxPXyuAevwzQkFRS87
         fDAxYZQwGzCNDhoEnNyZ+FoYM1RFLj0RNb7bpnBQEcR+t94urLLyfW1ebUj628dQJRRx
         hsvMy7rAV1Pz0XDcauYTGxEoqLGxu5Z9IGg0oGc3qoFMtjvRVsu4qZ1Tza5NGU1pEwGM
         EUbcXqwBUqazCz7dJHHUINJ0Wo4r7L2v1HLI2r99sKHMggHIDxFn36SUPX/kmYc56OJo
         Cvkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=R99YW6naQkjTKNrYbkDdoRsHBx6NElPxT3Iw4sTWwBI=;
        b=hKGdRcVJaVYBOt+bZTod3DEQQXlx+rKGZyl3tuqJqe2QqyxXf2HcNhRVUaZ2i2AXOX
         rB3gEQoMe7fmB8jZl9/A9JTPDp9C8i/j8Wk5gwxa+zW1dJ6k72f5ACor84LyuMc65KFY
         azUUx6wVl1zr27HV8lIeakx10zg0D7I9NVo1D+DuP33DzAkpU1r7FOMU5Gdfnhdpq4ZH
         Ruywl1imdYFJSE4dbsIXiFyf/Hvy7OqsdWF5ybGshTczLv4Ey79X3hImeEC5skvpNr5l
         ySMuIHduB0sc2X65kjLiVOKrikbg2KAgFuc6n/o5ixChlb4ywCzgEZOtImrekDyzYZNZ
         ugqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bSu7029B;
       spf=pass (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::b43 as permitted sender) smtp.mailfrom=eugenis@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb43.google.com (mail-yb1-xb43.google.com. [2607:f8b0:4864:20::b43])
        by gmr-mx.google.com with ESMTPS id l8si21834pjt.1.2020.11.05.14.19.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Nov 2020 14:19:45 -0800 (PST)
Received-SPF: pass (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::b43 as permitted sender) client-ip=2607:f8b0:4864:20::b43;
Received: by mail-yb1-xb43.google.com with SMTP id f140so2730521ybg.3
        for <kasan-dev@googlegroups.com>; Thu, 05 Nov 2020 14:19:44 -0800 (PST)
X-Received: by 2002:a25:9c87:: with SMTP id y7mr6858310ybo.314.1604614784094;
 Thu, 05 Nov 2020 14:19:44 -0800 (PST)
MIME-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com> <CAFKCwrgCfx_DBf_b0bJum5Y6w1hp_xzQ_xqgMe1OH2Kqw6qrxQ@mail.gmail.com>
 <CAAeHK+zHpfwABe2Xj7U1=d2dzu4NTpBsv7vG1th14G7f=t7unw@mail.gmail.com>
In-Reply-To: <CAAeHK+zHpfwABe2Xj7U1=d2dzu4NTpBsv7vG1th14G7f=t7unw@mail.gmail.com>
From: "'Evgenii Stepanov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Nov 2020 14:19:33 -0800
Message-ID: <CAFKCwrgvPD_EvCnzOsCvdMRW0uYPmUd+FRwugU0VBJOeRHtO8Q@mail.gmail.com>
Subject: Re: [PATCH 00/20] kasan: boot parameters for hardware tag-based mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: eugenis@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bSu7029B;       spf=pass
 (google.com: domain of eugenis@google.com designates 2607:f8b0:4864:20::b43
 as permitted sender) smtp.mailfrom=eugenis@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Evgenii Stepanov <eugenis@google.com>
Reply-To: Evgenii Stepanov <eugenis@google.com>
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

On Thu, Nov 5, 2020 at 12:55 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Thu, Nov 5, 2020 at 9:49 PM Evgenii Stepanov <eugenis@google.com> wrote:
> >
> > > The chosen mode provides default control values for the features mentioned
> > > above. However it's also possible to override the default values by
> > > providing:
> > >
> > > - kasan.stack=off/on - enable stacks collection
> > >                    (default: on for mode=full, otherwise off)
> >
> > I think this was discussed before, but should this be kasan.stacktrace
> > or something like that?
> > In other places "kasan stack" refers to stack instrumentation, not
> > stack trace collection.
> > Ex.: CONFIG_KASAN_STACK
>
> Forgot to update it here, but it's kasan.stacks now (with an s at the
> end). kasan.stacktrace might be better, although it's somewhat long.
> WDYT?

I like kasan.stacktrace, but I would not insist.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFKCwrgvPD_EvCnzOsCvdMRW0uYPmUd%2BFRwugU0VBJOeRHtO8Q%40mail.gmail.com.
