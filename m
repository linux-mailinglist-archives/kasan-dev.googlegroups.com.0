Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5ET2LCAMGQEIAF4QUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 76429B1D669
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 13:12:08 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id 5614622812f47-41b4a69ddc2sf353332b6e.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 04:12:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754565108; cv=pass;
        d=google.com; s=arc-20240605;
        b=YneleJ9jezEdVLGAZ6mkTFrKs+0TTSbYx6mlcp5g3AuizJLHZNH5ALiPhp5NYFf2iU
         7UQk2+e6PuRyxOGPhHhRNgV7hKlf+KW2sMskMIlh/6CFP5Xe8vmD8MeqFqu/nL3zbBBI
         sEf2+bcTBoKadXvFZAskwDyULzI6oXpegqMyuhvHUwshOP17z0KAkEmRQV8N8awYnbIC
         ET+uEsxnNciz4k4//jwBLyeUheK6HmbdS/8HsyVBPyEy+D8CCs2c93Ltd89ceIPF9SRL
         +kK/nbw/Dn+OVoPt9yGNFOOhZOXM/Hdn+HYuYkTMybe7n5nhJNXLFnUs60K5QOw12dfa
         Pigg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aqXmBzWaVQ5RGh4bOTEaXT7KdYxRbAEnLdBe/WCYPto=;
        fh=Asa0LKAfuUZyij6A8r7mTb65brqdEqFDZpkVhvbw1zc=;
        b=MM1dMFvXHLzrXqu6XlRwL40battBIwLxyDxuSjl4cNQEPYh6DRie1T59Qk0fiF5GBF
         P9nnSC9NfPzj0nlH4fgpl3TDA8RqzytQSZ4CYSTHVQr4Ji1lx1JUQ26FGM/fPuLHsVsR
         lJRNSxG4AQM/p/Oc/SKhD/4sYClPGYhrp9Foo+Ej5mhD67eOLiugVycXBlptpu/oHkNo
         lwv7lNqNz85wKnBZxtIfqTdPW3Y7Pt0YqHC0mGjV1thutfzNix0y6N9yVi15dpEp40bp
         NJIQ70sozmmW6ZirBdz9FOWKWUtoQXt6+gHJIWkMdZatcVmuPGmBJe5qwk35OZx1EQi6
         dZ0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="A/drPS1O";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754565108; x=1755169908; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aqXmBzWaVQ5RGh4bOTEaXT7KdYxRbAEnLdBe/WCYPto=;
        b=uGpmI9OC/cFo+fwUlLekKrL2wgR/h/b1JhGPXLwI6nuGn9rwB4glviwFbz52FWdvU+
         8X99DF4IKgL9m2rwsOfa03S6NoDmCZgz0ldiGBvkiAcHFJ0RCCyBTQ4wQs4aw/WjT1ZO
         D21adjw3djqK51kCzl+eI1QiIRdAunx3tAxB4lBp+dxUzIbEVZJmJdul5lYt7Cx+3JYR
         rd3R4ndhfQiRBd0kZxhbiWnR0neD/X06RuoaSBJe6oiuzXtK56bvRpCbD47Mdka6ejEU
         23jeo82lki/sBBpB2fYHDzF7r5lOWsUCbp0QBYK2gziPDwYhyRqNYazwLzmW/WyH9gn3
         dvBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754565108; x=1755169908;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aqXmBzWaVQ5RGh4bOTEaXT7KdYxRbAEnLdBe/WCYPto=;
        b=aJZhGi1LU0FqtUYTw7cfwvznjB6PkxWY0NaWuUavw1qiE7DQkgpcDSDL0CsZ+SaU3/
         zGRNTx5sAI8uuAo4rHKPCVeO7I6M8xdwWB0PYdVvwgudnqKOp4SkGW7yz4+KLsW7nwvY
         xxvn9pUW7B0ftO80VI4fbNW5JkC3TwXqY8Vg8iyoEa0zStCnaWcTE9D9tCn1/HwZ+Iix
         DQyk1VXcivEJi4ToimGROAumMieadp470otYsOf412q4BejANQI0yL2NSDhnKpwBvELQ
         MkgXcVbmv5CGnFEwkc+Piuo1ltD8TiqWiM8Q3yBmikFmILRIGSwOGs6afFiAWMXvzOPD
         ahbw==
X-Forwarded-Encrypted: i=2; AJvYcCWFpM7R/GioJ0+wAqfGXBmj69P7H/K5UgSdF0UGlV4GWLZSubxWJRmK+dyscVvBOEj4EWNApQ==@lfdr.de
X-Gm-Message-State: AOJu0YyU1XUlGFKOcz81VNgFfJuo+ji6LN3+9Zxa6IkH4uytEwyjkE12
	eDDDzek7nPHU/ithNPTtOMmbv3yNJuwYbbFyYI1YGgNgC91zRoFSA/5U
X-Google-Smtp-Source: AGHT+IEtE1Hdpx+ruZtcsCnhFVBrxh6kTfxQ4UUqrOQUt3y8oCUB5Lo9/lJgx2jhv58hBnLTrXz7BA==
X-Received: by 2002:a05:6808:4f2b:b0:40a:f48f:2c10 with SMTP id 5614622812f47-4357a072400mr4598228b6e.10.1754565108319;
        Thu, 07 Aug 2025 04:11:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZet0+b4SWYeUuL0s9/IkJmKtni7aILGC8dayj2d1hhakw==
Received: by 2002:a05:6870:c791:b0:2ef:51df:c05d with SMTP id
 586e51a60fabf-30bfe42819dls313732fac.0.-pod-prod-02-us; Thu, 07 Aug 2025
 04:11:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUvKV6DZE0rlZ/xkkJxei+BogShOUjlu3BhIpv0LcAZT/VBa8Iu5i2F6yrIhzP/3xixC8JJDWJ71nw=@googlegroups.com
X-Received: by 2002:a05:6808:22a5:b0:41f:4155:2fca with SMTP id 5614622812f47-4357a0723c2mr4167181b6e.13.1754565107444;
        Thu, 07 Aug 2025 04:11:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754565107; cv=none;
        d=google.com; s=arc-20240605;
        b=ICcQciubDpqF6QkWqC1XexJ93Pb+qjDhJX2mJtkNwNUUGTAsIqNJoOmcX0Iv+R++6C
         Fr6BK4lP703vAxa2KAqIqJJqDkRDYfv+eBQ0S1hMDYBIedL/CCG17oDT1NmRu8h87pEC
         Fnq1k0abt2YAS0KwNzPJmfqIfMHuXYmAGVcEYLjp5QMs4qh60S7agHnzvblyuRHMr6RV
         ZiTnc5IkzC5nJ2x00K5L7V0ZdSdHiDvv1SlCubjzzlbpyOE0xa9ViC/zHWOk2fje4u/I
         eT96ge3cGwhr+M48vNz/Ub7W1T1gm0M1uM9JMp8PkCKHGEVYpfhGxsrYoqoDqzhK85iZ
         rEGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CoXNXUKeiOUNFFg2C7vkQ9nmMli8YvVdClg8JNyIxRk=;
        fh=6mbV4UH35NOoUDLvJi+NSMqfHoq0dqjzFbA1ksX6DJs=;
        b=KtGPiPHMqB60ZWSa1alEto+Elgc/1v/5NIXnpbkYIU/t197JHmRwzdcKRXhMEH3PC2
         5o/oPi/sEffVXQo1bSAP3iZquVckS/ImlnK2pYhWwUHef0XpQt87xZvbqvQoxGopJbow
         LXJv2f9ElfVW5tlkQVW7H90214VGkC/HeReHXAGqvrUonPF+5rBKD+OM5itK5cAZogKG
         Szp9VH1p2j60tj2wiFXTvOco14CrQvdlbBKKuxW3nBt6ktHQ6EUotQpu81FJTCuclxJq
         z3CN5cjBjmXhzqG04bOB9gsUYHavVp/dW/Uhm8AazRkus+iX0biNbb64r5gYR5M5b2DO
         1PCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="A/drPS1O";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-742fadf6a58si213894a34.2.2025.08.07.04.11.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Aug 2025 04:11:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 41be03b00d2f7-b170c99aa49so515189a12.1
        for <kasan-dev@googlegroups.com>; Thu, 07 Aug 2025 04:11:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVHe/moRUicItq5zT/7SrFYldcIqkdwjWUXgZ0/brDmgI9fZjqV485nwgKTrzoEdiiiGY5fq1Bug+Q=@googlegroups.com
X-Gm-Gg: ASbGncumj2VHzFKN7ELut/jwdbvVR1z7CGLcUzjoaxMDgmWUtDUjGgWRxgh48eLs6/E
	bUngg3BsIvzsHdYLCo1wFjAzIV+rmgNCAZI9DS+ygxe4YTE+EZLD/lAj4HqRhuJPlZCNfZoo89/
	pO4Z2SBgYc9sFkfjYpVdz3RgXdiGyx12UI9hv3rYO5e3DWovHWktJTuAb6wy6QxT7pv/kkYygFf
	9m0foF81DDUMb37bTtY1TsX0y0R6FA5A+JwOFg=
X-Received: by 2002:a17:902:f54b:b0:240:8f4:b36e with SMTP id
 d9443c01a7336-2429f30a072mr90455775ad.34.1754565106720; Thu, 07 Aug 2025
 04:11:46 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-5-marievic@google.com>
 <CABVgOSnmtcjarGuZog9zKNvt9rYD2Tsox3ngVgh4pJUFMF737w@mail.gmail.com>
In-Reply-To: <CABVgOSnmtcjarGuZog9zKNvt9rYD2Tsox3ngVgh4pJUFMF737w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Aug 2025 13:11:10 +0200
X-Gm-Features: Ac12FXxEPQeFs5tHqqfxXkjXiWaH8qt7LNAFX9V6D-alLoCQyoAF_FdJ5KU_fBk
Message-ID: <CANpmjNMkcZaZ_dbXdd40dHrD3Wo2muv14ojmz4diwLG68LiFyQ@mail.gmail.com>
Subject: Re: [PATCH 4/9] kcsan: test: Update parameter generator to new signature
To: David Gow <davidgow@google.com>
Cc: Marie Zhussupova <marievic@google.com>, rmoar@google.com, shuah@kernel.org, 
	brendan.higgins@linux.dev, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="A/drPS1O";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::529 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Sat, 2 Aug 2025 at 11:45, David Gow <davidgow@google.com> wrote:
>
> On Wed, 30 Jul 2025 at 03:37, Marie Zhussupova <marievic@google.com> wrote:
> >
> > This patch modifies `nthreads_gen_params` in kcsan_test.c
> > to accept an additional `struct kunit *test` argument.
> >
> > Signed-off-by: Marie Zhussupova <marievic@google.com>
> > ---
>
> This is a pretty straightforward fix after patch 3. KCSAN folks, would
> you prefer this kept as a separate patch, or squashed into the
> previous one (so there's no commit where this is broken)?

Normally patch series should be structured so that bisection does not
break. Having this fixup as a separate patch means that bisections
where the KCSAN test is enabled will break.

This is a tiny change, so I'd just squash it.


> Either way,
> Reviewed-by: David Gow <davidgow@google.com>
>
>
> -- David
>
> >  kernel/kcsan/kcsan_test.c | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> > index c2871180edcc..fc76648525ac 100644
> > --- a/kernel/kcsan/kcsan_test.c
> > +++ b/kernel/kcsan/kcsan_test.c
> > @@ -1383,7 +1383,7 @@ static void test_atomic_builtins_missing_barrier(struct kunit *test)
> >   * The thread counts are chosen to cover potentially interesting boundaries and
> >   * corner cases (2 to 5), and then stress the system with larger counts.
> >   */
> > -static const void *nthreads_gen_params(const void *prev, char *desc)
> > +static const void *nthreads_gen_params(struct kunit *test, const void *prev, char *desc)
> >  {
> >         long nthreads = (long)prev;
> >
> > --
> > 2.50.1.552.g942d659e1b-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMkcZaZ_dbXdd40dHrD3Wo2muv14ojmz4diwLG68LiFyQ%40mail.gmail.com.
