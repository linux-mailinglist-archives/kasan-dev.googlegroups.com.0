Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS6AR33QKGQEYSVUGAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 10D811F7AF6
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 17:33:33 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id b10sf2645720vkn.22
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 08:33:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591976012; cv=pass;
        d=google.com; s=arc-20160816;
        b=XTFCed7uQ0f6b51Q4CiI8rs0HIvkHK1GuMzVouB2th042ttf/2eowIN3326OmkbmjT
         vVDJ6MuHXLQ9ynIzT9bpTFLNizbo8qWG070INP9I/r3Sjlgw7q/VZEDRAN1gn3hDLBb0
         la5jA3bSO+QPsWlqZ2Jd5nInD4F9jBXC74rRZX5hadlCFh2YrypDeM2d9ys7asyWowpr
         FmlydhMUROZd8btTyisf3ukiLBv7Q8ZElobpxUG/P79kThn7hX8wPQBxBtnUc7BvCYQd
         K7IcRwP8Sw5Fvx5OdSPaK4JGjF1d6naUyq96UXHYJEZJXCyVOanom2zdTjMZFY5ViOjL
         axpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CbyPDGblBAN2HHcYJexGRRfmLLmuOSUZR11aweVoBgw=;
        b=bLDv7LDn4P0hHkPRXfKWIj4AfJ5zXcHPJJMk3abePR3bMweXPitOAhsq7k/XReJnhL
         v+O/U4uAScjlUkZsvUq9GuhsVnK2y4LBI72J+txJyuuxDzp2z0/ZwRv1IM0+BVaW+a3E
         q4lMmYA2fmcBtFabPjHEwYxdttfw6/ohkLM4mXoRKbXh6fIv4tQadNt1kzsKdFcL8qIs
         J9v+I0zx5yzc/+4vhAR9kORc3orcwDZ+PBWqhDKz1hQy904+qMBBzBtICUsk92rccsUL
         bpushxpgo7kzq1uAsyJJAzdDApLnizAJcw40I3HxLvvaR0e0aSZeeAzkG9AYHryR4aBz
         bx+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tdC51OFY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=CbyPDGblBAN2HHcYJexGRRfmLLmuOSUZR11aweVoBgw=;
        b=Sgf81TBom0KgLT1PowCbGQxacD4sgVwt7tR9XVqmMa0BmKySer5pOvmQpbicw/Wvnb
         1BA/CsfDZ+EMCIdT9ecxOdyrzUUDKSBxNQ7MJXOs/KhdXL/vp4NENmWDJANrPtnC9TB+
         nZpS+BzbDgNcsBt3ZLY4Vf148a4hVDDhq0MV/tYkQKst325bh3+8FqW1C+ruUe8J7CNd
         Ww0CcoiGfeOU6HED2OGQbuxHwfuKjCjrRMLBVagoZKyOEb+cSZTmxpe7XB5KaTijOL1A
         bmInUb3qUXN6olAayO44ZkrFeEZ8ROEdpURyRBjPJjt8hqx/jg0gYsexNKAfvATTzDOm
         URbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CbyPDGblBAN2HHcYJexGRRfmLLmuOSUZR11aweVoBgw=;
        b=Hs3xSO69xKhmkdOMylNpLD6ipyyX692+iPpOy4X772yWsUU2fg+SNYfSs9Yn3cDNWW
         wCDvS+42HV9EONrF6gjlQOYES8e0KFHRdjwy46vwViDmEHYcIZozXMqMOxRL+dyACkyB
         SqZG0WiXtHmVBx3GW6RnYzd4yOkvZb0uMndiA2ADQzgFaEIffFhFyrvEU7D8jR3EzYS4
         Lu1+LGu8au7Lg/Vvr9yU+5E7W5RLqR2Wqa6jQ5JFbwr6BNkHWc8O+/0uHCzVRvohbkce
         +jJZjfvVwqoZuMH/R/RK3Ccw6b7CtB83cxm0eVu7UjPgajN8q3+PCMkGqhD1gGJd54cW
         +llw==
X-Gm-Message-State: AOAM533lAJlewAlB8g0OZ3xE4BfzXgD04W/QreDsn5zzoipDW+bT/BVH
	gWNXeQH2Khe4ELzyczsIass=
X-Google-Smtp-Source: ABdhPJy4aUM57PxEAaLP0De1oBjxSG8NCE3FRcubB0MAngJ9u5ErF/7JeUzbARjCZ+d2WvRW3p2FIA==
X-Received: by 2002:a67:d381:: with SMTP id b1mr10747699vsj.148.1591976011840;
        Fri, 12 Jun 2020 08:33:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e417:: with SMTP id d23ls719676vsf.8.gmail; Fri, 12 Jun
 2020 08:33:31 -0700 (PDT)
X-Received: by 2002:a05:6102:672:: with SMTP id z18mr5236774vsf.100.1591976011453;
        Fri, 12 Jun 2020 08:33:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591976011; cv=none;
        d=google.com; s=arc-20160816;
        b=vdX3dVvDpMZb14XdQVCfjHEjfOGh+8B3zdX4BsneMCC1/zQgdukIhjOTmpM3WsxpqR
         O2/Icf3G3oDNK9QWkmgNqQgNZTIArGuMDjBUAYuiuh3sN3GDmNi7YBaW1tlVC++p9BFB
         UtflTk9MOrmylZ/LyfMYPGetmSL3mWTHQPMn5AqPjjVT5iuf+8qGr4YIywqY1DHVrd5X
         ph5WajaCTXhwHw35bjhSrpVgQajdFTC1jJC+mpuTzzr0LQF82ZGej9/PDr4cQM32yEY+
         MDhdndsYizPIIFVXGHrdQpFOWVBwLUQBp46cl7YMMnaJTm+1piTEH7Pivt2GiCcsLEc/
         PdFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dL6cfbdxNbzwAwfTaM272YkAAUiX5SbJA5349TtzV98=;
        b=lYlfoChsbVjieXkXKZ/ZBpjeQyc2G49AYjHl2GFrf0Q56PhI3TsAXN2ACFFmWJkJ/x
         ww4OUFn37BKOv6Meq/P6NyvL7uhsSV3TPYnrTTHiVlZCcrWZJhQfXE3vV5x84kOAz4Yo
         42Ji1Wbx5BsxMldfgQSCeGDQXNOQYrzGdUVX2W/jJFTn4ndKUbBwLj/dWA7pSE/mcMYK
         iNSne8PCZjnMOYR1/+mmmoRrLWAtVzwlSMls4O/I3+RBLbtq8fKk0URDfgZxD9nW3K3j
         NmSUVnTrMkFl7ft2FPJvRn1EirEGpRLYtf1GrhJl7avQnUUmikVtAIq/Fx5E/YZDwbCS
         E+Xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tdC51OFY;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc41.google.com (mail-oo1-xc41.google.com. [2607:f8b0:4864:20::c41])
        by gmr-mx.google.com with ESMTPS id q20si81769uas.1.2020.06.12.08.33.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Jun 2020 08:33:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) client-ip=2607:f8b0:4864:20::c41;
Received: by mail-oo1-xc41.google.com with SMTP id e12so2014537oou.2
        for <kasan-dev@googlegroups.com>; Fri, 12 Jun 2020 08:33:31 -0700 (PDT)
X-Received: by 2002:a4a:e89a:: with SMTP id g26mr11165663ooe.14.1591976010720;
 Fri, 12 Jun 2020 08:33:30 -0700 (PDT)
MIME-Version: 1.0
References: <20200612140757.246773-1-elver@google.com> <20200612141138.GK8462@tucnak>
 <20200612141955.GA251548@google.com> <966abdc1-23c1-08dd-87e8-401ead7a868b@suse.cz>
In-Reply-To: <966abdc1-23c1-08dd-87e8-401ead7a868b@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Jun 2020 17:33:19 +0200
Message-ID: <CANpmjNPCgFk0Ax+0R-AVzaT+19SUpM+E0TPo7H15gEo6rBA8Ng@mail.gmail.com>
Subject: Re: [PATCH v2] tsan: Add param to disable func-entry-exit instrumentation
To: =?UTF-8?Q?Martin_Li=C5=A1ka?= <mliska@suse.cz>
Cc: Jakub Jelinek <jakub@redhat.com>, GCC Patches <gcc-patches@gcc.gnu.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Borislav Petkov <bp@alien8.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tdC51OFY;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as
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

On Fri, 12 Jun 2020 at 17:27, Martin Li=C5=A1ka <mliska@suse.cz> wrote:
>
> On 6/12/20 4:19 PM, Marco Elver wrote:
> > On Fri, 12 Jun 2020, Jakub Jelinek wrote:
> >
> >> On Fri, Jun 12, 2020 at 04:07:57PM +0200, Marco Elver wrote:
> >>> gcc/ChangeLog:
> >>>
> >>>     * params.opt: Add --param=3Dtsan-instrument-func-entry-exit=3D.
> >>>     * tsan.c (instrument_gimple): Make return value if func entry
> >>>     and exit should be instrumented dependent on param.
> >>>
> >>> gcc/testsuite/ChangeLog:
> >>>
> >>>     * c-c++-common/tsan/func_entry_exit.c: New test.
> >>>     * c-c++-common/tsan/func_entry_exit_disabled.c: New test.
> >>
> >> Ok.
> >
> > Thanks!
> >
> > Somehow the commit message contained the old changelog entry, this is
> > the new one:
> >
> > gcc/ChangeLog:
> >
> >       * gimplify.c (gimplify_function_tree): Optimize and do not emit
> >       IFN_TSAN_FUNC_EXIT in a finally block if we do not need it.
> >       * params.opt: Add --param=3Dtsan-instrument-func-entry-exit=3D.
> >       * tsan.c (instrument_memory_accesses): Make
> >       fentry_exit_instrument bool depend on new param.
> >
> > gcc/testsuite/ChangeLog:
> >
> >       * c-c++-common/tsan/func_entry_exit.c: New test.
> >       * c-c++-common/tsan/func_entry_exit_disabled.c: New test.
> >
> >
> > -- Marco
> >
>
> Do you already have a write access or should I install the patch?

I do -- I just pushed it.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPCgFk0Ax%2B0R-AVzaT%2B19SUpM%2BE0TPo7H15gEo6rBA8Ng%40mail.=
gmail.com.
