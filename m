Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUOPXKUQMGQEQQUEYZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EA387CC770
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Oct 2023 17:27:15 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-d9a541b720asf7483767276.0
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Oct 2023 08:27:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697556434; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wfd0mnHW4BVtmeouXfBdnOukXfozzAxcW22KOXvdFncvf3I9nHH8dPDfAj4bd0nLNU
         A/EGVz40Af1MW4HkLFdONSjF0jA20fMCyPJNMzf+T0Uex6GNAVAsoKvCb4OW74d8/1po
         AqlQr4o0oojytazCi/hSS7f124ypjRnfFKKa0FgkB2b8emNuObYWbzi9wrGbp2mCNg7k
         UZ8y7xRyksGRrsFUrEtA/4/qCoPqtKb6Qdux0ChrqYVxLhYVj0NI4jK166oYrrHWDwhX
         e215cfkU/lAtGP97AH9l1JqxoB7r7aAwnwFoFVRkcHK7e8UK7w0+HCzlSBfxKHO/7OJg
         yKDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QsB53kqN6C2dFTEeCReEgUqwPTAnXtCA68IW9/cAw6E=;
        fh=fWEurnJyE5o8MpVxRNx6VAQhXs7QcKE49dy8TPFDpCs=;
        b=a6ldXkwqIo0b/EhvNa6RvI/8v3f5fCcpRw21Y/o1QLdRRGfj4/JM4ajpUb6pdgCePI
         yV25rbwUnrfKtf4dcMyV4pMOQacjZd8UW5T5ixg1GPdBA/kLfq3wMEsXy57OUVP+Iypz
         uLNZt/Dz3obHsBXAjZdIjioKnMcve8ii53+Pr6PP5sasxviifZOP4zbamVoJdPJkSgN8
         +WfbvKOa+880XJ08hilb/QoEWA/DdHCAJzWoFNRavW8EiwX3RXinSZHCJBTDbMzMwjDq
         3ZS5Hsjcu1yf62bSQLFq7peqQdQNfF0ksR292/DxUOLDq7Z53KZ4Mj6N9DZs2VSc+F19
         RBjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="uUaPA/RX";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697556434; x=1698161234; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QsB53kqN6C2dFTEeCReEgUqwPTAnXtCA68IW9/cAw6E=;
        b=QZpriIm12QFAxdz1AqYFjViXnWuGbwaOpHETSaJYUF1uQ7fWKfqwCMMbwdIo/dfTmy
         WUMeQgS+mlxhSpuRJH09YbgH5IrQ8D3qDtzu0BLmvw4xul3kGaOkZIRddd3aBY0V2Wsh
         KkH4Q+mj1t1b00rKgQGOQGI7mO2WNKyAH/CThSlsjAKDS27J1f119Wnwb+w8lW3lTuBW
         30V++iUsjoWKHQ7NYY9tIGO8NxyrJj+eDllEC2UMFhSjxEpW74YEcQ1W1xp/aUDL9Wa1
         iMn5sidhAfcilKEvy7fLOV3RZ7Pgb4bix8n32C2qolnKZaFXGLwblhMv4U0pgvQkddqD
         FVAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697556434; x=1698161234;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QsB53kqN6C2dFTEeCReEgUqwPTAnXtCA68IW9/cAw6E=;
        b=Ummgd272kXANatx5dnCRtpsGwOap/A8f3avuseqchRpflKOjuCGDR20pogCO3i2jgG
         lRELZ6oEM37NMy5uDF7mlL93hBJ1Pdxle5AfbnJICAHP+m2gh1f9VqslKP2inT9U8cgA
         BfVbV3WmuevmRVLECZ/qZJksBOnXTh7A1UtqtAz0H6a8VGlVw0TTkzCWg8T8kVXcN+f7
         Dw62xlunU4fwdgemSrxjyh+29RsF5MQXC8QkX3TNXTbLPs+jk5Y2QE/k3L/rzgpIeXuU
         a6J7a/dB6bx4/LrnwuOkL0U2vTJ+kVIsRH5+mWHZ1WgobDroxIA+yIhs1ZsBKnK1nmaZ
         iPZA==
X-Gm-Message-State: AOJu0YzbUjMb9Ng93IK+/UNZLMAhzm39/JPwVA8CFio23/e7HoAiYyhA
	c62KQ7ybbKaV+5UFSa0UyUc=
X-Google-Smtp-Source: AGHT+IFygI/6vF8NBm9Yha26q34QFo8ZvDFiBZrKmvfRB1KSCJ1u2ixgXF2UXJI+cG+74dbjckGC8A==
X-Received: by 2002:a25:ac96:0:b0:d9c:1ef5:aef with SMTP id x22-20020a25ac96000000b00d9c1ef50aefmr2571225ybi.9.1697556433918;
        Tue, 17 Oct 2023 08:27:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3992:b0:646:f0a7:568f with SMTP id
 ny18-20020a056214399200b00646f0a7568fls3033303qvb.1.-pod-prod-08-us; Tue, 17
 Oct 2023 08:27:13 -0700 (PDT)
X-Received: by 2002:a05:6214:234f:b0:66d:d6b:f24f with SMTP id hu15-20020a056214234f00b0066d0d6bf24fmr3626662qvb.50.1697556433168;
        Tue, 17 Oct 2023 08:27:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697556433; cv=none;
        d=google.com; s=arc-20160816;
        b=crSbChz/307XLYssN61S2EbZn3sYmHydo5qsGMHtY5/WVMhw3EX8g9aF0QP3SdJJy8
         kNlXH9Oq/WEVT5yqTx5Zv4JUcrVDVpNweQxqvVkeMi7IcPWako9p6bmIbMwtIUJgSUU6
         k916cVpAz31TktObVMH9Y9IDSrqp4jNk7uqodTnVXJXIUq5eVqrlNCw+9LISIKQfq3Xx
         Y23bvwXF4Anyq7RuJyNFMU+6ZZLtC7YojimLsWgCQ3+NCVaOXnzwT+676pM3BDmp6Gsd
         mLPH52sc2fATs0+lnSkgNMp44EFJAjM67bU58r7++UKTKAsiOHbE1sc8Bs8hSLk7dlgb
         KuXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=C8cg6jGLFG7A51F+ARcwLcIxkWY8BQUYMBYpLmYj4Ek=;
        fh=fWEurnJyE5o8MpVxRNx6VAQhXs7QcKE49dy8TPFDpCs=;
        b=zd8IZFxSV9wlVepU3kF20qMbxTsQtAX4FWLBWLGTiJG9Qk2EmuQnaVitKTmIt2yyJl
         toehqpZxhg34I9OcDJpauNXeoM4BoOQItNPfNvP4QQKWi3mv6prSsNTOH7H/VZ6xklaB
         YhFVM9cELAfPo08eqJRUKP0cwy8S1G+OHLe+dpUO1QH3gzqU8A7J2J6G0ArhAZvW/HsP
         y0Wpcdt6Crfs93zZL4sn4qGkMigUcNI9gx/5JrGXG7qrVE3EUNY3PELs+nxdLka13V8g
         XOAMwpM5EzE1ioXn7AULzmfKWeYJ23FOalwMGr964rrzFasLLkgCf7hLaTGNSjKqfrUB
         0U4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="uUaPA/RX";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe34.google.com (mail-vs1-xe34.google.com. [2607:f8b0:4864:20::e34])
        by gmr-mx.google.com with ESMTPS id a8-20020a056214062800b0065afd3576a7si86638qvx.3.2023.10.17.08.27.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Oct 2023 08:27:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) client-ip=2607:f8b0:4864:20::e34;
Received: by mail-vs1-xe34.google.com with SMTP id ada2fe7eead31-457c441555cso1788867137.3
        for <kasan-dev@googlegroups.com>; Tue, 17 Oct 2023 08:27:13 -0700 (PDT)
X-Received: by 2002:a67:c10f:0:b0:454:701c:7717 with SMTP id
 d15-20020a67c10f000000b00454701c7717mr2625620vsj.5.1697556432713; Tue, 17 Oct
 2023 08:27:12 -0700 (PDT)
MIME-Version: 1.0
References: <20231012141031.GHZSf+V1NjjUJTc9a9@fat_crate.local>
 <169713303534.3135.10558074245117750218.tip-bot2@tip-bot2>
 <20231016211040.GA3789555@dev-arch.thelio-3990X> <20231016212944.GGZS2rSCbIsViqZBDe@fat_crate.local>
 <20231016214810.GA3942238@dev-arch.thelio-3990X> <SN6PR12MB270273A7D1AF5D59B920C94194D6A@SN6PR12MB2702.namprd12.prod.outlook.com>
 <20231017052834.v53regh66hspv45n@treble> <CAKwvOd=pA_gpxC9ZP-woRm2-+eSCSHtwvG3vsz9xugs-u3kAMQ@mail.gmail.com>
In-Reply-To: <CAKwvOd=pA_gpxC9ZP-woRm2-+eSCSHtwvG3vsz9xugs-u3kAMQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 17 Oct 2023 17:26:36 +0200
Message-ID: <CANpmjNPnP2_4oHSnhEO89ZhpqNfUg51XzL0awWVkYGNhxUayhw@mail.gmail.com>
Subject: Re: [tip: x86/bugs] x86/retpoline: Ensure default return thunk isn't
 used at runtime
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: Josh Poimboeuf <jpoimboe@kernel.org>, "Kaplan, David" <David.Kaplan@amd.com>, 
	Nathan Chancellor <nathan@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"linux-tip-commits@vger.kernel.org" <linux-tip-commits@vger.kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, "x86@kernel.org" <x86@kernel.org>, 
	"llvm@lists.linux.dev" <llvm@lists.linux.dev>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="uUaPA/RX";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as
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

On Tue, 17 Oct 2023 at 17:24, Nick Desaulniers <ndesaulniers@google.com> wr=
ote:
>
> + Marco, Dmitry
>
> On Mon, Oct 16, 2023 at 10:28=E2=80=AFPM Josh Poimboeuf <jpoimboe@kernel.=
org> wrote:
> >
> > On Tue, Oct 17, 2023 at 04:31:09AM +0000, Kaplan, David wrote:
> > > Perhaps another option would be to not compile these two files with K=
CSAN, as they are already excluded from KASAN and GCOV it looks like.
> >
> > I think the latter would be the easy fix, does this make it go away?
>
> Yeah, usually when I see the other sanitizers being disabled on a per
> object basis, I think "where there's smoke, there's fire."
>
> Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
> Reported-by: Nathan Chancellor <nathan@kernel.org>
> Closes: https://lore.kernel.org/lkml/20231016214810.GA3942238@dev-arch.th=
elio-3990X/

Acked-by: Marco Elver <elver@google.com>

Instrumenting these files really doesn't make sense. Thanks for
catching this and the fix!

> >
> > diff --git a/init/Makefile b/init/Makefile
> > index ec557ada3c12..cbac576c57d6 100644
> > --- a/init/Makefile
> > +++ b/init/Makefile
> > @@ -60,4 +60,5 @@ include/generated/utsversion.h: FORCE
> >  $(obj)/version-timestamp.o: include/generated/utsversion.h
> >  CFLAGS_version-timestamp.o :=3D -include include/generated/utsversion.=
h
> >  KASAN_SANITIZE_version-timestamp.o :=3D n
> > +KCSAN_SANITIZE_version-timestamp.o :=3D n
> >  GCOV_PROFILE_version-timestamp.o :=3D n
> > diff --git a/scripts/Makefile.vmlinux b/scripts/Makefile.vmlinux
> > index 3cd6ca15f390..c9f3e03124d7 100644
> > --- a/scripts/Makefile.vmlinux
> > +++ b/scripts/Makefile.vmlinux
> > @@ -19,6 +19,7 @@ quiet_cmd_cc_o_c =3D CC      $@
> >
> >  ifdef CONFIG_MODULES
> >  KASAN_SANITIZE_.vmlinux.export.o :=3D n
> > +KCSAN_SANITIZE_.vmlinux.export.o :=3D n
> >  GCOV_PROFILE_.vmlinux.export.o :=3D n
> >  targets +=3D .vmlinux.export.o
> >  vmlinux: .vmlinux.export.o
> >
>
>
> --
> Thanks,
> ~Nick Desaulniers

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPnP2_4oHSnhEO89ZhpqNfUg51XzL0awWVkYGNhxUayhw%40mail.gmail.=
com.
