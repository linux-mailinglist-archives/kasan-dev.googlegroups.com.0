Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2MDZWTAMGQESVTV5PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 558A6775442
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Aug 2023 09:36:15 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2b710c5677esf70854291fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Aug 2023 00:36:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691566569; cv=pass;
        d=google.com; s=arc-20160816;
        b=jyynwzp/LDTSDKyTiMoF6S2WiwCio+zhWG7uN48ZDizfjFyGBO1AwmFz9GcW3xEuX4
         N8P7NWSElgtYgs/JAGzjQU+48zGLkSQPowfyBsgrKr7/hjUuOow4SwNsz3/HDIx9+4z7
         qvrd4P2E+t81p2nlRJt+o2+mWLlfMZSo5sgPgWNwv0PppXjNkXie3gP0dVEhgpP3+y1D
         lAj1Rx8zQ3+om+oW7IN6+61nnhbZ83T9wccxoMsP0V73dihlWz9urh4Vay/ex18Uootq
         d06AFPpPedew2F/6Lr/afhmKShdg9Rvv/t/N9mlNhPfGqSSWJ2VLb6hulug0JurqEt2a
         OFcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FEDXufi0ZjiNAeWXlCPcBb6y8TiMCr0Bsvr0I6rR3uE=;
        fh=cwzY8x7dDHilKeHMNJDjnqowd6448fHrWFIOQtERjqU=;
        b=Rukx493FrHC9F08nUUH47I+Rcyx+Zf3aVYP2I4GICsnn7PT0qvpFv7UIw/Hq6rcjHi
         qmS1lOxdcNWADvbmF+Cq0s+czDUUeEnxnyRSoaoQbbG45ilw4TAfcekE7GRDil8I/9lx
         ryKq8rKVqxMzxehCw2te8Bk23133mjMpORq429C+VttOQrIRhcZZ2ZL9lrE/J3Pp0GoU
         k4BH7kx2HXzGpYdR3Ukaj/jAvIdNNdBDeCY9BiljmR1kaUdI+XX8w37oDlGbkuZOvu3u
         +4foC0ae2ghSeoNZLmz6FDD/3bMO/gcqDLAyxY23YX/iD2PsfDZAlAkBHaWOO0jyNFfs
         adyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=P1SYKGJX;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691566569; x=1692171369;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FEDXufi0ZjiNAeWXlCPcBb6y8TiMCr0Bsvr0I6rR3uE=;
        b=nICn/ZXn8DEzQzqdYclaDjDw3WTDyF17FTk1CZ0BxgVDQWj6yhN9F/UOVJqoqt330K
         77Xi0sulXujj09g/dAjNxQ3IAEPr0bf5ZtB2NhVyKSKMSqdMG9/ovxrGFWAWv9heZpwY
         L3GDZKeAU86uZDAnVU4z9TgctDs+RSeO2lKiHOO4PQbC4ge9vVLzKo64E/sVt5oZ81uz
         j8sLB9+QEtU/QM+Py5hP2oauz/c+H/e8J2l5vdw2Wz1UvMynQQyzSwMCaDsUKtUc5Yqn
         Wonn7KBDNVSuC2rS6zNthBxFQVmI1cDNS81utgzuQcBnfQn1dHpLaWGKUjimmm2CnI0o
         Ztbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691566569; x=1692171369;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FEDXufi0ZjiNAeWXlCPcBb6y8TiMCr0Bsvr0I6rR3uE=;
        b=kJWgLlzrDHpXiKpYRofYQVmd+8/59e/Go2T+s8W/BKPOl5LW8KMTovwUJ/X/pWSxpk
         fozAhYoHfbCGZfa/V36NDpMA8bM3oQx5wHtZOIRsnyp2Vv/c0DFEWWmdzsaHayEkuvbd
         qhCECLw6VhTAQ7mld4J9mLc8gFQljnwJtKdicjaguruX8O8YBzX9IelNrnSA9BgYNx9D
         UuFer2ruRlo8NwIN9xGbtaUb+/ko3bb2Ci2UB7OkZePfyYec3ioLsSyMEIYgPLdjJzzg
         vsWnARSgzSMMQEtNw3IGj1lxoP6/SOBrJav47NxCHFx8heigFG7DKVDYf1/XyKlWu3S0
         iC6A==
X-Gm-Message-State: AOJu0YzhUzraWi+3sS3xCC/CcoU4m9ZiUZMZufc9KMV7eGXvhQ4jTLdf
	3BUn1jc6sKP+dYrAM1kfeeA=
X-Google-Smtp-Source: AGHT+IE/3kQEVWDh6eER2HS3PZzVZTe9rIg8e/SMxJhepxSD6slrQIinsdZp8uPe/pI3zXRtmvlriQ==
X-Received: by 2002:a2e:9415:0:b0:2b9:d2fa:e8fd with SMTP id i21-20020a2e9415000000b002b9d2fae8fdmr1149822ljh.49.1691566569279;
        Wed, 09 Aug 2023 00:36:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1c4:b0:2b9:631f:ac29 with SMTP id
 d4-20020a05651c01c400b002b9631fac29ls14311ljn.1.-pod-prod-08-eu; Wed, 09 Aug
 2023 00:36:07 -0700 (PDT)
X-Received: by 2002:a2e:884b:0:b0:2b8:3ac9:e201 with SMTP id z11-20020a2e884b000000b002b83ac9e201mr1169565ljj.40.1691566567134;
        Wed, 09 Aug 2023 00:36:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691566567; cv=none;
        d=google.com; s=arc-20160816;
        b=Bx8G9EUTqkKWCb4IhXZWGgX60XiTaP8EsBuUw5n6Dwb+fSxG6hvSb5n1EdP+ZMIMLH
         vncliwwIQ2rgSMGfFEaYlLYA7dkuvLoXv1RuKTLs/34sOB1F1caBAIVEtckTVnWNWZM5
         MAwVAS+7Qsrz39lzoc8O8KWAaFHcEG8j2Jpe1k/G+bAXgharb/gflj7nq8ykTQos5ePB
         Lzdouv6E5kcwBrzIHlhzOpYvUZd+vI4RJcO0ZGcl/5e04YRL+343z2D/sNAL1T2PdOvc
         iuqa7Sq9EcQvr+KI1kNkFXfmfu7fn4f3JYfwP68EUx5zoSt2UIqlvWNgJD2Pbxjousun
         BgrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9g6zXd3UY6FR9mRGo0YLbshWp2Mg0VfIdE8xLRYTWgY=;
        fh=OhVD7+5q5gV7DhBXNYxg3SR/gDmJhPIj0bBm5u8U3nw=;
        b=Znlr8nUZ+ufvBLWVsi2J+H3wacvHplAzEVnhP9ryvbrFtGTAivkBQ1uFVZzP9FxeKI
         k6yQBxWv4azIOGSOCEtWFFgY8yN1Qe/FKO6MslAMegMgzNuHzgXy8EUJhhTdw/gWprC3
         EowcQ1pT7o/eALGZbbwrDpX0Pc57/dF72TgPPCQgs1QWYC8QJj4on2gfjpyAiiX5p56I
         c7LvJWtzR0AtbnGV7RkyeyUMGcDZFibqF8dCmXL2VwdAc24jx+464SbjWgU6500EtmTc
         60zeOrkCSCT0StPfpAfl2PdAa++WTnHayMeI3hj2aQU6C74oNDvLkKdVYJ158Uj+syz0
         hxVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=P1SYKGJX;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id k18-20020a05651c0a1200b002b945894b21si920568ljq.6.2023.08.09.00.36.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Aug 2023 00:36:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-3fe4cdb72b9so36253505e9.0
        for <kasan-dev@googlegroups.com>; Wed, 09 Aug 2023 00:36:07 -0700 (PDT)
X-Received: by 2002:a05:600c:ac4:b0:3f9:c0f2:e1a4 with SMTP id
 c4-20020a05600c0ac400b003f9c0f2e1a4mr1498745wmr.34.1691566566341; Wed, 09 Aug
 2023 00:36:06 -0700 (PDT)
MIME-Version: 1.0
References: <20230808102049.465864-1-elver@google.com> <20230808102049.465864-3-elver@google.com>
 <202308081424.1DC7AA4AE3@keescook>
In-Reply-To: <202308081424.1DC7AA4AE3@keescook>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Aug 2023 09:35:29 +0200
Message-ID: <CANpmjNM3rc8ih7wvFc2GLuMDLpWcdA8uWfut-5tOajqtVG952A@mail.gmail.com>
Subject: Re: [PATCH v3 3/3] list_debug: Introduce CONFIG_DEBUG_LIST_MINIMAL
To: Kees Cook <keescook@chromium.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Guenter Roeck <linux@roeck-us.net>, 
	Peter Zijlstra <peterz@infradead.org>, Mark Rutland <mark.rutland@arm.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Marc Zyngier <maz@kernel.org>, 
	Oliver Upton <oliver.upton@linux.dev>, James Morse <james.morse@arm.com>, 
	Suzuki K Poulose <suzuki.poulose@arm.com>, Zenghui Yu <yuzenghui@huawei.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Sami Tolvanen <samitolvanen@google.com>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=P1SYKGJX;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
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

On Tue, 8 Aug 2023 at 23:27, Kees Cook <keescook@chromium.org> wrote:
>
> On Tue, Aug 08, 2023 at 12:17:27PM +0200, Marco Elver wrote:
> > Numerous production kernel configs (see [1, 2]) are choosing to enable
> > CONFIG_DEBUG_LIST, which is also being recommended by KSPP for hardened
> > configs [3]. The feature has never been designed with performance in
> > mind, yet common list manipulation is happening across hot paths all
> > over the kernel.
> >
> > Introduce CONFIG_DEBUG_LIST_MINIMAL, which performs list pointer
> > checking inline, and only upon list corruption delegates to the
> > reporting slow path.
>
> I'd really like to get away from calling this "DEBUG", since it's used
> more for hardening (CONFIG_LIST_HARDENED?). Will Deacon spent some time
> making this better a while back, but the series never landed. Do you
> have a bit of time to look through it?
>
> https://github.com/KSPP/linux/issues/10
> https://lore.kernel.org/lkml/20200324153643.15527-1-will@kernel.org/

I'm fine renaming this one. But there are other issues that Will's
series solves, which I don't want this series to depend on. We can try
to sort them out separately.

The main problem here is that DEBUG_LIST has been designed to be
friendly for debugging (incl. checking poison values and NULL). Some
kernel devs may still want that, but for production use is pointless
and wasteful.

So what I can propose is to introduce CONFIG_LIST_HARDENED that
doesn't depend on CONFIG_DEBUG_LIST, but instead selects it, because
we still use that code to produce a report.

If there are other list types that have similar debug checks, but
where we can optimize performance by eliding some and moving them
inline, we can do the same (CONFIG_*_HARDENED). If the checks are
already optimized, we could just rename it to CONFIG_*_HARDENED and
remove the DEBUG-name.

I'm not a big fan of the 2 modes either, but that's what we get if we
want to support the debugging and hardening usecases. Inlining the
full set of checks does not work for performance and size.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM3rc8ih7wvFc2GLuMDLpWcdA8uWfut-5tOajqtVG952A%40mail.gmail.com.
