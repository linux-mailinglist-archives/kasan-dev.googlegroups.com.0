Return-Path: <kasan-dev+bncBCLM76FUZ4IBBCMC4TAAMGQE5NIOY6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E42DAA9B53
	for <lists+kasan-dev@lfdr.de>; Mon,  5 May 2025 20:18:51 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e639763e43dsf2083619276.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 May 2025 11:18:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746469130; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fl86qpI28odcs1y0IjTZuLmMriR6/d94i5Uq0H9kKAt1ehA598TzTSFCRLG3LFOhch
         cfEwZ+QOvvTF+R2iNAq6tjatocwHQDUeClLtm8rDwcD/6ME+jJcG5yzhE7yycdO8qYKc
         YwOytZUGbWuoIqr49k3rPhqxzSkdwBKkl8mvu2PyiYdiBmID+3ND7qLAMJHBRmdtakv7
         89rrwsUHhgv3roomQWtQVYKK0HepeDU1IwmRibhTs3e9jLlPEBuWOzjfEyZfv6nP6/3x
         3f3U7iBKopKWZIO08qU9vHL+WGjlG7XLq+g0kAvQHpH7Cit77G8efIj2WdBCSIGQ3a3j
         ALJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2mMIvVsx0Lb5hdZvhMv09kaHudEq1fHOcvUR7mq0HrU=;
        fh=TlAt4i7W6O3A6onP6j42qgoRywTnCPr4hl6OBInziKQ=;
        b=SlmOuAW7LafG5GmFfNZhQTbkc/ak8Pd4gEcMtTBKvUjyWkRXBqbZ5HzAmvBCVgy1c2
         NUJTdhOkmQMvCBu0d3RAzAvRXaQmdWSCDedxlAbzC1uSjvrm7wK8G5YR0VIrv+dPHsIk
         n7QI4Dj/mbYjLR2bwgj+IbZrmpICuPH8YgmJae2Xa5FiPbYP4NnDF2Fiv/fhfsBHTFSd
         Mi98CMDHb72bX5yoJCrGVtwqEL+r3WYRZgDRpL8/xdZ4ckjiMHoqsLNwbRksjmM+WCPU
         HXLYUJvNumET4deqWoUIz4MoBIQOg+WyR+q1q+dtPya4cNuzo8YNuqZ4tkMB0Qumi6Rw
         9YLQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=saoxBVtc;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::92d as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746469130; x=1747073930; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2mMIvVsx0Lb5hdZvhMv09kaHudEq1fHOcvUR7mq0HrU=;
        b=ILsjcy/Ts9Dp/Hqz0m1J0HGCSjctnTO3BraiTzyiMUFQPNF3xGhYG0efHSek/k1aYE
         Sh4bSZDFS4n4Q9gzcMAcl9k5MJVZFCVLX15kxvW0cz1WleRRUWxjgzawA0IAsg5YW6M8
         ShtOd52dlld2jNtJ8XlyHCigkBLQwqdx6teG/dRoyF1bBRaKjsDMPmCELRQBztrxkxHm
         tjP38BQqzPaYS6T+TKpmrvY3s+7Zz0v3JTdcuBsI2+1galQif1FDuiz2XIZepjzTLBnZ
         WoOUAjyqa+AbvTRpAWRVs0Xq0CIGHBaICB9lmkFOnV2Ksjgz3HdSksAMyCwUQRktyHN0
         UnVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746469130; x=1747073930;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2mMIvVsx0Lb5hdZvhMv09kaHudEq1fHOcvUR7mq0HrU=;
        b=V/MT7onKSBPF5wX+EsYpMEYvgF02ryJjmaoFIERpsMKFqleSg8hD0TkOasoTBEV9/7
         qoLa3XCNMdlqePqIT/n7exKGMTQFge7DQBkxmb+u27ld9XjxuvB6NFIEvFbczBHbY2np
         4wdzagsb5LvGgQi6J8op2OolvMkcEycd8v1miMus8XqDYRAXuXeBMBldIUG5Zcv5gDTf
         a8FTNjGvz+jiRqHBJCWunYl4UNUGHTuB76ZRRiiU3BIRyQmFXri8ALzmoOwx8Shnp5iX
         dtqGTh2WQfs/F7/rndiZk7bzjFMI8YTDMsqYCVXM8xuxoBUq1WiL8OWSK9bs1DS+GMJI
         cbTQ==
X-Forwarded-Encrypted: i=2; AJvYcCX0lHKbtZpLkavlKC3A6cBB9rACW6K9ltbJ064P/6n1cn9yurL/P7WBdP3yiAEz4SQhdN7EwQ==@lfdr.de
X-Gm-Message-State: AOJu0YxtX/6UKMiCNaVL3yvQOZ1esxV7BzRnBcaLPyolHpolkWiJlsUl
	aJINgGHbhq4vUe4tPDOAuMMDR1Xc12lySZrWM3AnRBCmQCZ5TEuv
X-Google-Smtp-Source: AGHT+IFNgobnwSwVhOLVcdGPqHcbSviruwkUF8d8m+mcN8qgt8sT6pPG3K8H4zDkZwML/FwJ6Q/E2g==
X-Received: by 2002:a05:6902:1087:b0:e73:2b56:c41 with SMTP id 3f1490d57ef6-e7571a47ee9mr12663713276.12.1746469129806;
        Mon, 05 May 2025 11:18:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHQu2ICKqg0lq6ZbGu91+bPoGrNZSJ2ZsBn04eQ7fwyDg==
Received: by 2002:a25:2d20:0:b0:e74:32a2:edc6 with SMTP id 3f1490d57ef6-e74dc9b9c90ls775245276.2.-pod-prod-02-us;
 Mon, 05 May 2025 11:18:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUP8J10bsQ7PJTeNzLsxAiPfTaYM1JWHQYw3TZzzKnpnrVyMxIOJhH8//T/0MWI+d7t3TiHwzUb678=@googlegroups.com
X-Received: by 2002:a05:6902:e0c:b0:e75:6019:3648 with SMTP id 3f1490d57ef6-e7571b0d5ebmr13241082276.38.1746469128783;
        Mon, 05 May 2025 11:18:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746469128; cv=none;
        d=google.com; s=arc-20240605;
        b=gvkjJ/lXnYlEGD0isiQ7I67+S7n7gx+ktrBeWNhN4KTQC6NtNaS/Wn9NxvJYlLCn0E
         v7r08o8QgkXOf8GSF09TurIKkCKzHd7Z/9gnaljgi4hO9yozX5u1y2iX8E3amoLNfqxp
         0TaZYDecQTYyE4cSgUb/rHcYu/NGeNmnbhDMMs7QjpiuKZIRcp8GKPoJEx/AWCtNB9b1
         J6SFwAv/CQVAYpvVXJYryCfHpCljYrASP5CJkZJIGWflrYxs4Gx9aEKhgWlICEPGQpu4
         V3Vi9nt4ZnrPn3S1Irp+OVlval/w3HoJmpyXMSwXTGumqmmIc19QEwbgBRAovTCCb87Y
         wwPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=v+HucxVqpGIDINeSE6fmLZw1CWi4pwr8swaylTY9CLM=;
        fh=YDwLr4/LER+lZTkfj2qTSGgkViIbxnbXgHcniRSXT8s=;
        b=eyyWZmntD30k5/1lnyFkvEqIcdBBA0H+HmmLkguImsiGxpMAXdGU+A94k4UgrTdwPG
         3d5HUYvcUhLV2X9N9Q66O0k6vbsaa7K9bff1cJusw8rmUUe7sLQo46vGJJJeH4pOqlwR
         E9QOiiEjpRRLWTWkELTMTnYiyaPlpRSbqg4YrSj4Dx+WzT+jwIHOdcBZ2MXGCtJbY3DB
         aXcjsFPG32hjSQGweliYNY9AnTz/Lwee9fpR6dEQnXAdHs4wg4hX4t5qYyFRQ1NaZkfh
         T6NtmxYmfv8uLD7puT/vahPiuwa0rxjTQAYv4Bhu1Yha8UFxaz+onx0fXvBQrYI6ER49
         VpfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=saoxBVtc;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::92d as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ua1-x92d.google.com (mail-ua1-x92d.google.com. [2607:f8b0:4864:20::92d])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e75bcea1256si18673276.4.2025.05.05.11.18.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 May 2025 11:18:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::92d as permitted sender) client-ip=2607:f8b0:4864:20::92d;
Received: by mail-ua1-x92d.google.com with SMTP id a1e0cc1a2514c-86d2fba8647so2964729241.0
        for <kasan-dev@googlegroups.com>; Mon, 05 May 2025 11:18:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX9sn/aXg6wxj7PuKvSUNwul7Nj9nG1zbs81R9Je/PtKWDuqZVtsbay+TSRu/wJYpv0eZ8/g1Frzck=@googlegroups.com
X-Gm-Gg: ASbGncv2R2QbU+rldw5CDo53vLbqHd7DTYAf/OsCtu8CDuz10XKC554qDTImUcjhDwA
	dYWDks+ofMLN6XYYZVhCfUuTJxjA166XMcqPxZDYkk4tEFWYbGRYAFDcsKv2ZiIqVIYNiUbGdQ6
	jdWykS1PRzG8TYjCSM20J6SOLIl/xRiYc=
X-Received: by 2002:a05:6102:3c8e:b0:4da:e6e1:c343 with SMTP id
 ada2fe7eead31-4db0c401beamr5914771137.23.1746469128196; Mon, 05 May 2025
 11:18:48 -0700 (PDT)
MIME-Version: 1.0
References: <20250503184001.make.594-kees@kernel.org> <20250503184623.2572355-3-kees@kernel.org>
 <CAFhGd8rGJcveDn4g1nS=tURe-uT1+PFm2EQeWpUrH_oy763yFg@mail.gmail.com>
In-Reply-To: <CAFhGd8rGJcveDn4g1nS=tURe-uT1+PFm2EQeWpUrH_oy763yFg@mail.gmail.com>
From: "'Justin Stitt' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 May 2025 11:18:34 -0700
X-Gm-Features: ATxdqUErCVMDsByK3bWIsvMoTcLY1TL44fldHiGpe0ueZmfJS819NKbT_lTgAuc
Message-ID: <CAFhGd8qL8ttBaPGH5Cx39MN46OgxsLSgqhWN4rwCwf9bn33NHg@mail.gmail.com>
Subject: Re: [PATCH v3 3/3] integer-wrap: Force full rebuild when .scl file changes
To: Kees Cook <kees@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas.schier@linux.dev>, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, Petr Pavlu <petr.pavlu@suse.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
	Bill Wendling <morbo@google.com>, linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: justinstitt@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=saoxBVtc;       spf=pass
 (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::92d
 as permitted sender) smtp.mailfrom=justinstitt@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Justin Stitt <justinstitt@google.com>
Reply-To: Justin Stitt <justinstitt@google.com>
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

On Mon, May 5, 2025 at 11:16=E2=80=AFAM Justin Stitt <justinstitt@google.co=
m> wrote:
>
> On Sat, May 3, 2025 at 11:46=E2=80=AFAM Kees Cook <kees@kernel.org> wrote=
:
> >
> > Since the integer wrapping sanitizer's behavior depends on its associat=
ed
> > .scl file, we must force a full rebuild if the file changes. If not,
> > instrumentation may differ between targets based on when they were buil=
t.
> >
> > Generate a new header file, integer-wrap.h, any time the Clang .scl
> > file changes. Include the header file in compiler-version.h when its
> > associated feature name, INTEGER_WRAP, is defined. This will be picked
> > up by fixdep and force rebuilds where needed.
> >
> > Signed-off-by: Kees Cook <kees@kernel.org>
> > ---
> > Cc: Masahiro Yamada <masahiroy@kernel.org>
> > Cc: Justin Stitt <justinstitt@google.com>
> > Cc: Nathan Chancellor <nathan@kernel.org>
> > Cc: Nicolas Schier <nicolas.schier@linux.dev>
> > Cc: Marco Elver <elver@google.com>
> > Cc: Andrey Konovalov <andreyknvl@gmail.com>
> > Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> > Cc: <linux-kbuild@vger.kernel.org>
> > Cc: <kasan-dev@googlegroups.com>
> > Cc: <linux-hardening@vger.kernel.org>
> > ---
> >  include/linux/compiler-version.h | 3 +++
> >  scripts/Makefile.ubsan           | 1 +
> >  scripts/basic/Makefile           | 5 +++++
> >  3 files changed, 9 insertions(+)
> >
> > diff --git a/include/linux/compiler-version.h b/include/linux/compiler-=
version.h
> > index 69b29b400ce2..187e749f9e79 100644
> > --- a/include/linux/compiler-version.h
> > +++ b/include/linux/compiler-version.h
> > @@ -19,3 +19,6 @@
> >  #ifdef RANDSTRUCT
> >  #include <generated/randstruct_hash.h>
> >  #endif
> > +#ifdef INTEGER_WRAP
> > +#include <generated/integer-wrap.h>
> > +#endif
> > diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
> > index 9e35198edbf0..653f7117819c 100644
> > --- a/scripts/Makefile.ubsan
> > +++ b/scripts/Makefile.ubsan
> > @@ -15,6 +15,7 @@ ubsan-cflags-$(CONFIG_UBSAN_TRAP)             +=3D $(=
call cc-option,-fsanitize-trap=3Dundefined
> >  export CFLAGS_UBSAN :=3D $(ubsan-cflags-y)
> >
> >  ubsan-integer-wrap-cflags-$(CONFIG_UBSAN_INTEGER_WRAP)     +=3D  \
> > +       -DINTEGER_WRAP                                          \
> >         -fsanitize-undefined-ignore-overflow-pattern=3Dall        \
> >         -fsanitize=3Dsigned-integer-overflow                      \
> >         -fsanitize=3Dunsigned-integer-overflow                    \
> > diff --git a/scripts/basic/Makefile b/scripts/basic/Makefile
> > index dd289a6725ac..fb8e2c38fbc7 100644
> > --- a/scripts/basic/Makefile
> > +++ b/scripts/basic/Makefile
> > @@ -14,3 +14,8 @@ cmd_create_randstruct_seed =3D \
> >  $(obj)/randstruct.seed: $(gen-randstruct-seed) FORCE
> >         $(call if_changed,create_randstruct_seed)
> >  always-$(CONFIG_RANDSTRUCT) +=3D randstruct.seed
> > +
> > +# integer-wrap: if the .scl file changes, we need to do a full rebuild=
.
> > +$(obj)/../../include/generated/integer-wrap.h: $(srctree)/scripts/inte=
ger-wrap-ignore.scl FORCE
> > +       $(call if_changed,touch)
> > +always-$(CONFIG_UBSAN_INTEGER_WRAP) +=3D ../../include/generated/integ=
er-wrap.h
>
> I'm not sure how this fake header stuff works to ensure builds deps
> are tracked properly but we do need scl files to be considered as part
> of complete builds, so:

As in, I'm sure it works but have personally never written or reviewed
a Makefile+generated header snippet like that before :)

>
> Acked-by: Justin Stitt <justinstitt@google.com>
>
> > --
> > 2.34.1
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AFhGd8qL8ttBaPGH5Cx39MN46OgxsLSgqhWN4rwCwf9bn33NHg%40mail.gmail.com.
