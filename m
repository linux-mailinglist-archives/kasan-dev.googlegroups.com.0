Return-Path: <kasan-dev+bncBDYJPJO25UGBB4V7TL7AKGQEBGMOTKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2640A2CACCF
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 20:56:36 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id v12sf3754430ybi.6
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 11:56:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606852595; cv=pass;
        d=google.com; s=arc-20160816;
        b=dQIxIcdSSFLn0kRugcGxbOBGLIeStBaSX3DJ7uA08J5ce9npKogvsHi5YmkWBMtK+i
         3hT+Qr5n818QElPjYuJqNkJtlTyN6hSvWDByHb3fnELNthDRiy77zh0XzS/hm3eIBprm
         BAmB0nWcyhSrmveeN+hbXJrYay70jK3HgSG+brXdRCtCluR/ySKOUzDwg2VXJXGonmic
         WkC+rJA6xSGLXO7K7RMO+Pbl/9zdRdFLz94Zq1i7TFxMZKpwmUAdz5sFowrBeh9JE+4d
         2wH+z5liuP+qMEmafP+usp9TlcBOH11RYaCge8Afm1HTbAcwwRuoG9n6HLIGgoVGFBfQ
         58NA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jwYkkH036xWSzHtQLDheXni2qTdr6+QPa41SMJJTKaE=;
        b=zixidKq6VXZqMbn6NxNrpjXmFqJ2iOkkkVl3khuGx0tdCl+KesnOLvjfRhSh5ivJrK
         tSyW4ce1xD0hfyNJwYOlY7+TfDGrSgmsUnv+KfLsesjx/LSb1pGp4XTXp8k175s/VrPY
         5cqoa95cIXQb136t/o/LvQhcx6Nn/WAHjTWLH4gbkP6ZmHd7TDd6WC/kEtdNeBqOQIue
         D5EIIW9syGhNSv9wh3x8gzHYylbEWk6isgEQPNCV7nTD0no8Bn1WhaLDFcZRRdbgy/at
         Wjdz824AdXNFCANEsyOuJhLLYG1IM+tdIoLNhWoQtgLvK5SnJGu1OenGr+ZY8m5GnChf
         eeOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C70FTDvU;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jwYkkH036xWSzHtQLDheXni2qTdr6+QPa41SMJJTKaE=;
        b=Fqd99zGEzY0D6iwvrHgM6ZYoDpvd6k/PRPXcXBIJW+VWNjn2HV6UMlpNFSgVW86vWA
         qR9ToBWdKXkOPlCBdZ++Zl9HbRKhySv2LyQyNcFEeUMgVhc3IrDHX2cEUvAk23tQ9BYe
         J9Yb/r8NWjRuDcvmGlXGiTDcyStr2o3YflK23jpQUffKydBeVQcFpyOLplAqG2aGJF3l
         NujYXi0MDAHzjXdSZnG3CJDRZJYPhHbSsqhZDR1Cct6vKmnnGcYvCZRVHLpSc0/5bZxH
         1BNBgfXOcvDVG4/e02LS6/Z8VZfYn0AYIrWvI822N3N9tKNxPBIPDjz+6Xi44W7h54o5
         Kuxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jwYkkH036xWSzHtQLDheXni2qTdr6+QPa41SMJJTKaE=;
        b=Q+tQPwj/dkJFSFDgEkd/0Udj60NYfqJnagXYpGi/LbTjJCZZhqrrDlu9NwA/AEtzOd
         HbAa1hsaks4LAH6Lk7lkZOQqknG2eAAQqjIqLTpmQ7OElEFhkIC8viJJF1gKgod05AbE
         phvFf9E+ftqUEz3jR+ozUXQCi/vB4Pfj1NQ2dU+2Jh1pgwzLW8K94OAyrwq5/CNee+GD
         gIAKG88z3rPP6poqnePdeB8KI3MjptdS2MVjKZc6gph9xMHFc9ZT5lN04xOM7eQTO/Dr
         AUFvHLCqFfM1VlPRkEyx/cxgasazFUxS1whHAS7nFPvDq0DxsbIBVcE9cyKDA6T18cC6
         YA2Q==
X-Gm-Message-State: AOAM532VKP1B6X7+c3qq6WF+op37lyvPcXGKfnjsTXG2NlgV5oYwwYc1
	HCPH3pK+Ru7S21BzEfIDugc=
X-Google-Smtp-Source: ABdhPJzfi7gb0VYQ5jYwjJrQfKJDvjjI6eQfJ7cpZIUruxifn7DFHui64nfP9upT96eVw3hP3V8KRA==
X-Received: by 2002:a25:61c9:: with SMTP id v192mr6465287ybb.354.1606852595032;
        Tue, 01 Dec 2020 11:56:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:7cd:: with SMTP id t13ls1531878ybq.8.gmail; Tue, 01 Dec
 2020 11:56:34 -0800 (PST)
X-Received: by 2002:a25:504c:: with SMTP id e73mr6292861ybb.376.1606852594621;
        Tue, 01 Dec 2020 11:56:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606852594; cv=none;
        d=google.com; s=arc-20160816;
        b=wT2YWYQg3hVXVsUYm0+d3hApCFUg1Nihb/jEc6qZQ+fGG/y1vqPCvEkm0Ff/vQoyY/
         hFZfu5qB8vE/cOM/Cf4WPaCD8mG/f5E8vXkYCZOLRRqpt8Y46E8sEZsj7JX0xRlv2Z7u
         wzyTEqs00U0BU1aYVHQmkyXD8w+LbQYGKyn+CM+3CL39PvMSwxokHhrwJfNkkPNxIc8L
         dPAKu+jeA45w7rBp4LzSOi6aaCF/sVgz5Zr424+Wdkc9V1bgyPx7zUuua/veclUqFd1O
         ZBEB3DX1HtTXRUVw91+mhNidDfF5ZGL4El/kuScFCCP3DoeLth5L6Fr9ysq303s6PXkR
         /kaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wNrUoO5GhGjJ+F0ga/x1uzDpCFyyeAqcGZvey2hPlFA=;
        b=fUEIZC1bx6VTRK0h/t7zP/Zl8VMI7D3EG9jlA8O4/Bke8H0qhjlhrFh/dTpNuSDyIu
         svjWpsLSwKzuysuX84LAVQB4HQutM+Be1y5mq1ud7AdTptMEVGpMs1FE79F0cc1GI+kw
         N8P5EDzXvAZWMPZvO86xAG6iKs4PdlPddctDbdjkCSTUWXzooFtlKc6s8kCgxveuJ0yp
         J89p/BKGdIn+ckYghakhoIRovtL8CW+Gb4kekr1y92Dnrb/fp3w/G5Ey5gDHoYkckU5p
         cFEwEwTuJF6SRnN3xt4NA99+6NPB/Zzlbt2CSCP7EC/VJgyJPaCQJqaVEKaxOVtaJQ7b
         s9Bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C70FTDvU;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id m3si73641ybf.1.2020.12.01.11.56.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 11:56:34 -0800 (PST)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id u2so1750771pls.10
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 11:56:34 -0800 (PST)
X-Received: by 2002:a17:90a:dc16:: with SMTP id i22mr4567464pjv.32.1606852593726;
 Tue, 01 Dec 2020 11:56:33 -0800 (PST)
MIME-Version: 1.0
References: <20201201152017.3576951-1-elver@google.com> <20201201161414.GA10881@infradead.org>
 <20201201170421.GA3609680@elver.google.com>
In-Reply-To: <20201201170421.GA3609680@elver.google.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Dec 2020 11:56:22 -0800
Message-ID: <CAKwvOdkhBTjjtEm9dc9irp8hpWoEDEAMj_Zp4ntKspgDkjrATg@mail.gmail.com>
Subject: Re: [PATCH] genksyms: Ignore module scoped _Static_assert()
To: Marco Elver <elver@google.com>
Cc: Christoph Hellwig <hch@infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Joe Perches <joe@perches.com>, George Burgess <gbiv@google.com>, 
	Rasmus Villemoes <linux@rasmusvillemoes.dk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=C70FTDvU;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::643
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Tue, Dec 1, 2020 at 9:04 AM Marco Elver <elver@google.com> wrote:
>
> On Tue, Dec 01, 2020 at 04:14PM +0000, Christoph Hellwig wrote:
> > Why not use the kernels own BUILD_BUG_ON instead of this idiom?
>
> BUILD_BUG_ON() was conceived before there was builtin compiler-support
> in the form of _Static_assert() (static_assert()), which has several
> advantages (compile-time performance, optional message) but most
> importantly, that it can be used at module/global scope (which
> BUILD_BUG_ON() cannot).
>
> From include/linux/build_bug:
>
>         /**
>          * static_assert - check integer constant expression at build time
>          *
>          [...]
>          *
>          * Contrary to BUILD_BUG_ON(), static_assert() can be used at global
>          * scope, but requires the expression to be an integer constant
>          * expression (i.e., it is not enough that __builtin_constant_p() is
>          * true for expr).
>          [...]
>
> .. and there are plenty of global/module scoped users of it already.

And to proactively address the inevitable: why do we have both?  We
looked into wholesale replacing BUILD_BUG_ON's implementation with
_Static_assert, but found that they differ slightly in the handling of
integer constant expressions; BUILD_BUG_ON was reliant on some
compiler optimizations in expressions making use of
__builtin_constant_p that cannot be evaluated when the compiler
performs the _Static_assert check.  So the current implementation is
more flexible for expressions that use __builtin_constant_p than
_Static_assert is.  If we needed a rule of thumb, I'd recommend "use
_Static_assert unless you're passing an expression that relies on
__builtin_constant_p evaluation, at which point BUILD_BUG_ON must be
used."
-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOdkhBTjjtEm9dc9irp8hpWoEDEAMj_Zp4ntKspgDkjrATg%40mail.gmail.com.
