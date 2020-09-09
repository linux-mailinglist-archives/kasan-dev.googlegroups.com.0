Return-Path: <kasan-dev+bncBCMIZB7QWENRBJGM4H5AKGQE6TC6J4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 26F722626BC
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Sep 2020 07:20:38 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id 139sf765382qkl.11
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 22:20:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599628837; cv=pass;
        d=google.com; s=arc-20160816;
        b=FKQ1xhHXL8JPplPgvBWM/9q+sF2kJX9/+ONa55g0rE1vLj9CE9vFm/uqSYQiW4GxFy
         d86edafJ+5rTiu6v21dksgPXR+V+Z0UV5JaZTjoRjysRzuFcw9oQHATivA827btkvYzS
         MBdIoQN4OGfZjJdUmK2cG1R5QfB2DMG/kqZ587BwAzYz8buN6tcm61vnZXmzUxHTmPDF
         uZGI6bDqoj6lPnwu83Uj4OZjWCs2iI79ssu4PlU2sGmUZox0NurjKNW7x2UqBo5sACq7
         d5fk0JFcYG5rIOuN3m86KUCDOJiCgNycFf2ZD8M8vBQyj7KT3PxDJG2/0+6aiVAyw4ZU
         0B/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wIL5OsLmOXDp+gO6SBsSRdzFutjPDQnPn/LB9M6MMVU=;
        b=JcI2yzx/+7xm5LbTTyPxwq3eEgmO1W/X4sQdtOYw5kH78saAe0b7l2fsCn905AnW4K
         EmsyE5ewSV/VJZQ2GA7NYvQunu0+jwRQxd5ThkhhtgpVvZ9hcdK0Hfu7U7hRwdFxNMX5
         ygI4DmZmql/lpR5cF/oB5DYV8dELf7uwb11bwzpQcPlsepgSB8R9S4MJiAETeped0b6k
         juSudmjgsw/Zm1lzwrYl4K0fK08yEd9tDYVucJ7RsNG3kjKpVdFB3+xq6GlkXeuZmU/m
         xkmV8VDHc1Yh0MWC3c1Tfezei4GLKUDb0g3rS4kMpZFqrTYKU5a2vwhOd3QlQnN5iqrS
         Ap1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=upBkhNC7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wIL5OsLmOXDp+gO6SBsSRdzFutjPDQnPn/LB9M6MMVU=;
        b=mh+E0P9eWHrc84ymn3nvTj7qBUmKiw6o+w6ncxjq7sG9s7b7Db0IIrRsjCAIHMsxH9
         PAyMx4yVTYYeskSf9nNnBd10TvBqBEN0VRLHB0VgkTJheRf9VVMuSgJDEgqlqbNIWAAd
         WdvnfZE1gwu3dWozoDvaV4suv+yu0czM7jFrVvns2m4PPFPm5/VKt9P3+Cnd80tNMjSN
         0f9CNVkkarOhYNas4N0YV9NUOv3lJh/ijGSm/fAaeUk6JK8+4godfwzlS0P0MNGHrXSg
         lMyn6Uv6WXwXe4q6gg6dqKfPysuzx3B7tJbR8qUNwp1I6XhadJOv2LeYwhlZzkc5nMiZ
         erVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wIL5OsLmOXDp+gO6SBsSRdzFutjPDQnPn/LB9M6MMVU=;
        b=t54/TrVbE8YmJp24jFIMgID+JW0WkhscjiTkFQYsPvyujaDpNKAYkv803rvCXU2fWV
         lAF8zowpzXM+zzLtiQpxYEgmzW0yEqDTTdgCEvrrWgGg7rg42AJLVfwpY44uhOFpFako
         7Y150E4jDb0hIQkM7RwjU4aNt944yHD5xFnVis8wiNdVS8UCTRh+Oc5yyt8XbDfi8pdh
         C3cSHoUNJGE6x+SIcTS+ZbCSquEt3RgBOYD/wrJ+kMwMviS7eZe2SEHsbD9NTBx+m/PP
         GN6qjNj4TqRcnBEw5i8GW34JWrpVACGbwjGSFCjDvPehO++AdPHkclVQnyKp+kFMk6F2
         SnqA==
X-Gm-Message-State: AOAM533Af0sc43JQOGa0VwV7Ni25+LzJ32Wf48QNBdr00DrYIdKZL/Sb
	oAYy9nchsFe01q9p+/hrZpA=
X-Google-Smtp-Source: ABdhPJyTVNFyZYv/Kl2VUdsoXI05JViV919ZhqxW/c7RNpeC6XhcBqo3+Zonv4fpMPvfh45LOk/S5w==
X-Received: by 2002:a37:ad08:: with SMTP id f8mr1769135qkm.207.1599628836910;
        Tue, 08 Sep 2020 22:20:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5749:: with SMTP id q9ls374298qvx.8.gmail; Tue, 08 Sep
 2020 22:20:36 -0700 (PDT)
X-Received: by 2002:a0c:f704:: with SMTP id w4mr2546640qvn.79.1599628836446;
        Tue, 08 Sep 2020 22:20:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599628836; cv=none;
        d=google.com; s=arc-20160816;
        b=q7bRxxnBZarzioRlEdL+WPjc02GxMbvYxZQfURkcbKydzXTeYOuY+yb/g5NdxWoBLO
         CslY8Ajjk86WXuepyGy2m0KgcV5x1zFKYAmwAb5DXPPu6fnAf8Wb/Satl7y5uayYs02E
         UIs6c4FdhvRwmXUgx4MGOwuOym1eQJS2zbu7oIPA8zUz+wT3+bMTBfbYOCxLGvf1QhWf
         Y41XkXbZopuWxEcqUQ6kOlUdNaS+DBRInUbodvqfqzYhbgqKX2nhIGZSLPLw+KWjoMAD
         AsplYpT1cky3f1flbwKzEdxYLdYgWNJJy55NFepgXZ+qVZs/9XSnKMUnFdvdNXDyPdTJ
         2zdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yrPV1rE9Q8aFyvmS+tTixzz0jds55x17Dqqm+UKxJfk=;
        b=Ss0YMFH0y+Ios7JUm4qx6Nur2N+I8JlRJC6ue0+8Y6dJ/cbHJbCnJhepWfQYLRq4D0
         zkYCPp4bCT6eAIhsv7FXAqS7qquOf2y5vV0OqBaL3de+9awdvPVDf2eilvGS/VDVmag6
         8Nh9sBjMYXDXdpchPBlg1ASB4/FXb3J9o6nH45DcPeqKZaNV9FJ+6iXBALBriGtQcKW7
         db5/p6Ba5Fv2hzaPrCI/BL+DQiS7OD3uo1I1/Nu2kExnYv2Q7GDCp9Y1AKJUGobSopsD
         q30Je4luJAsbQf5zy9Qm5gOoxOeYMOFJFv+2ld13cCTPUXXlbhl04dYuccjMk+GKEA2s
         rgqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=upBkhNC7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id h17si94128qtu.2.2020.09.08.22.20.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 22:20:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id db4so939431qvb.4
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 22:20:36 -0700 (PDT)
X-Received: by 2002:a05:6214:7a1:: with SMTP id v1mr2544395qvz.19.1599628835784;
 Tue, 08 Sep 2020 22:20:35 -0700 (PDT)
MIME-Version: 1.0
References: <20200905222323.1408968-1-nivedita@alum.mit.edu>
 <20200905222323.1408968-2-nivedita@alum.mit.edu> <CANpmjNMnU03M0UJiLaHPkRipDuOZht0c9S3d40ZupQVNZLR+RA@mail.gmail.com>
 <202009081021.8E5957A1F@keescook> <20200908184003.GA4164124@rani.riverdale.lan>
In-Reply-To: <20200908184003.GA4164124@rani.riverdale.lan>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Sep 2020 07:20:24 +0200
Message-ID: <CACT4Y+aCa0Y8t198GSwEFShUPuOsqFV5eP8GY_7TK8fi_pML_Q@mail.gmail.com>
Subject: Re: [RFC PATCH 1/2] lib/string: Disable instrumentation
To: Arvind Sankar <nivedita@alum.mit.edu>
Cc: Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	"the arch/x86 maintainers" <x86@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=upBkhNC7;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Sep 8, 2020 at 8:40 PM Arvind Sankar <nivedita@alum.mit.edu> wrote:
>
> On Tue, Sep 08, 2020 at 10:21:32AM -0700, Kees Cook wrote:
> > On Tue, Sep 08, 2020 at 11:39:11AM +0200, Marco Elver wrote:
> > > On Sun, 6 Sep 2020 at 00:23, Arvind Sankar <nivedita@alum.mit.edu> wrote:
> > > >
> > > > String functions can be useful in early boot, but using instrumented
> > > > versions can be problematic: eg on x86, some of the early boot code is
> > > > executing out of an identity mapping rather than the kernel virtual
> > > > addresses. Accessing any global variables at this point will lead to a
> > > > crash.
> > > >
> > >
> > > Ouch.
> > >
> > > We have found manifestations of bugs in lib/string.c functions, e.g.:
> > >   https://groups.google.com/forum/#!msg/syzkaller-bugs/atbKWcFqE9s/x7AtoVoBAgAJ
> > >   https://groups.google.com/forum/#!msg/syzkaller-bugs/iGBUm-FDhkM/chl05uEgBAAJ
> > >
> > > Is there any way this can be avoided?
> >
> > Agreed: I would like to keep this instrumentation; it's a common place
> > to find bugs, security issues, etc.
> >
> > --
> > Kees Cook
>
> Ok, understood. I'll revise to open-code the strscpy instead.
>
> Is instrumentation supported on x86-32? load_ucode_bsp() on 32-bit is
> called before paging is enabled, and load_ucode_bsp() itself, along with
> eg lib/earlycpio and lib/string that it uses, don't have anything to
> disable instrumentation. kcov, kasan, kcsan are unsupported already on
> 32-bit, but the others like gcov and PROFILE_ALL_BRANCHES look like they
> would just cause a crash if microcode loading is enabled.

I agree we should not disable instrumentation of such common functions.

Instead of open-coding these functions maybe we could produce both
instrumented and non-instrumented versions from the same source
implementation. Namely, place implementation in a header function with
always_inline attribute and include it from 2 source files, one with
instrumentation enabled and another with instrumentation disabled.
This way we could produce strscpy (instrumented) and __strscpy
(non-instrumented) from the same source.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaCa0Y8t198GSwEFShUPuOsqFV5eP8GY_7TK8fi_pML_Q%40mail.gmail.com.
