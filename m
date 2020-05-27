Return-Path: <kasan-dev+bncBDHYDDNWVUNRBGWOXH3AKGQEFGDXAHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 574CF1E42F4
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 15:11:55 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id o16sf25728165qto.12
        for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 06:11:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590585114; cv=pass;
        d=google.com; s=arc-20160816;
        b=w+bc6kbBTJBzcRseCzNQHRU/v0j+pNSao92MqtQLLlp36l5CSV4lHV8KN3jLLRSJwS
         3Pe0+Aw7RqcVqv9BvRknqmfqS87MfvVqR6RyGr8HdAmf8oA9+FYF2hFU4YS4kFbfYcGk
         IhgR5Nh2cEFd11+awqAOipW5084FtT7SInOxrEcgHu4hars1mSSj6lL4KYvYQnhtZQa/
         gzlt4L7jEYh/bmqfGXw2XGI8uTnG40N03uoTcmpW3tmQESOKMrDSUbOZnSJqXmxTRnQ1
         lfotlqcuiTiir8bUf2LSg4jrD8WQKDT0l7+okr/QzWmGBOTeJ07F2h46S0LPsJkapHj3
         aClw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :reply-to:in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=/y9eE/IQ8XWtQI7TzRyv8a4S5xh6+mjqL1poCdboyAk=;
        b=L2lJ8fJ/UpLp9qop5JuaaRLRzXe2uhLG3PeKCfOpGDjY2yE7rBntXaf7mxIsItFzD7
         D66U3sgNH+UtweavdX5d2NHzLZN+46bnWaEf7Jjp4UBCcHedJmOgHCh9JTPgmcW1E+CS
         15eZZC/rOWP8o5fGXjjFuQeKa7S9Tra9d/3Ci91ighD/C/43gPcfpvVRxO3dXVijh6A+
         kgcJgBFGSigNqKcrtvs7f/UpFKNmjpvmsGmZK3ANpjQZOHCFO7ArAXtqAPJVCRWdtH7k
         erwDvhhhUq2Rmd7Sm3XY2EFdMVjxcfM6OATEDYRMQ8XrnxHWaW/eNJ+BUIQ/mJtTdbFj
         bS8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=t0Us1PcW;
       spf=pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/y9eE/IQ8XWtQI7TzRyv8a4S5xh6+mjqL1poCdboyAk=;
        b=dzfUy88TiHf2T/SgoIKn9ihLlY0a/IEZePkOLsrswdJEnovNLE5rwIWTORUsMzHvoZ
         kJ28t6bDEz8lS3VLibyWX1fwyiW6ed2Xw5yG5oru/OD6oSdg5CaufcG8a2TMmGOjeTkf
         x4xkg9j1eIInk4Pf1IzOSVI4mTyXe22/CRQ4XH7MGogUls6g/FQV4f+VWlt60eN1S6mo
         m8+7lLV2r4zm/nqc77I7M8oJ45pLSEaR1gNVAB59rDEds6FH7Ls/TFfcyixB+XRmFw+8
         MBICFeC89saZ3/GcQAgDV0HpcegDIw/2O9QvwAGSE7THSB8MA+TcVM1d9xPekBWlAUOH
         D3FQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/y9eE/IQ8XWtQI7TzRyv8a4S5xh6+mjqL1poCdboyAk=;
        b=ZOyEETZPb6rZGW3FHRZPGnXjHkJYFBlEd97GHqUNhdcAA9mRr0N/gkHVh72GI2nqz1
         CSZl33B7YBLe00WauBiOwmTjkvpBnTdOsTCW7oIrrLWGFtDEytPgHigVQ33IYmLmqzFE
         3EpcHwuoYmFUNE/mFYOb/tHuN+sa7JI5vPYe2f4WaKqETWY4a8TTb/HDNkN+SN7zElV6
         RJWVq0iiBC9FuYmGy39wN1TD6XuD2R8C9xypkYFeWJO6hI3ce1pjfr2h8hdQ05GjxU6s
         wRjdATBh7IcxTN6vY+uMNMmWNl2LnIOLOYpAYAQCEK3pygYHtax9cTSq0IPOimxtiuIf
         9l9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to
         :reply-to:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/y9eE/IQ8XWtQI7TzRyv8a4S5xh6+mjqL1poCdboyAk=;
        b=pnmHbyhGLawlSlyn1z11hW2m9+TdNp13A6MnhOwBOb7Ckk9nF+0F5O1MHQnc1lFDhc
         iqIctzn62scs63EDYhYfwZVYgC+bAGOSdQuYC+HDxBSbTryamx6f1YPvIp3rUIu8qC2X
         zx7bcBfNNYUkJiwxd7OIk1GIcxUilWISoxB7XHPPP3QUZzf0fT2tUdcst4ldr13Er62Q
         gMsZpaV683InCaq9dq2INQSLNMl6dMbCqujTqF6+f2ty+81dBCj5dj2NACtiMvycBLns
         c/LBse6YJO3IOT8GZoe6VHHjscnU/piiIepWx6V3BVuoID9Lyr+iYmoY0AxVR9swEvy0
         vTxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532eWO9i+tgOaqJBliqmki7uhBO5MAhESSEReHHb5wNuvbBb6rYJ
	Ja10sDbS5685C72+2vnGoJc=
X-Google-Smtp-Source: ABdhPJymrIPw0BULdGW5Ra2gqGMXl+as72FliBAc8sNKMIF6DgbB/LREQs3wFRenJZusE6uTt7NZTA==
X-Received: by 2002:a37:f517:: with SMTP id l23mr3977095qkk.475.1590585114327;
        Wed, 27 May 2020 06:11:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:5a3:: with SMTP id q3ls1988813qkq.2.gmail; Wed, 27
 May 2020 06:11:54 -0700 (PDT)
X-Received: by 2002:a05:620a:7f0:: with SMTP id k16mr3951398qkk.18.1590585113921;
        Wed, 27 May 2020 06:11:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590585113; cv=none;
        d=google.com; s=arc-20160816;
        b=Gb6PdnirueIhMGuDy2bF2m/d8rGjGTqZSFm9nZH1+lQIyRr3LdkzkWkL6vt4kFa1s4
         Mb77L3c3LLbOaWIPFkz8nq2kOzbEuyqedcdeh8tjE8DuF85+IjITyuZyfr6L6FzKJrdA
         TLvIMpFvHCIi+5gYNlQxaUCSApQXB1INlPO9VMTFG0zWF4raZBLDHg5HsNgXacTTIPDf
         5Wz8CBAvqzQAR5G3qZT4ZbY+th8mtZKyoKOQqRutp2iq2Qh1qp5lyd7myvZSbBV3rZze
         5XzazEC8BJemLl0XkXs29aKQ3/qIKEsmAa1DD+Agy4Rks5UWyXy5rMR58AZXGLg7y2UF
         naeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:reply-to:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/FeAxSqyr5/D9IayOmiy152xGFi7mH1sffMEBtId3Bk=;
        b=vCHjoQgTN2HgVUUvqYVfBwAmiU830m6NyPFxyz3BKRUf5XE+7rdv1PGDLqoX/NQ1xZ
         jNPy8OrmT5DaAKcHXBJdpeTAr6Da55EtmQ+xofnTUQz9ZGIAKpW0Q6VYQHgp9nuWiDX/
         PKZ2MZMpKH9g7p+wchenCVtS1/IIEVhneMZA/twZzCtIssQmwXwmQnu/t8nqzb5SPFlt
         LYrEMtz2sCXUo3k7uZbI32TBGWyg0P3idwT5RM95o4et0WgQc9rYkNkGz2IbWfst94ky
         ytOGIFMGG2kylhk/7yOC6XCvTRkUyZj1Mj0xVYMJ5iIEmgyAWqWpMQtlV77SRlfEx6MM
         HU+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=t0Us1PcW;
       spf=pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd43.google.com (mail-io1-xd43.google.com. [2607:f8b0:4864:20::d43])
        by gmr-mx.google.com with ESMTPS id m1si202000qki.3.2020.05.27.06.11.53
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 May 2020 06:11:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::d43 as permitted sender) client-ip=2607:f8b0:4864:20::d43;
Received: by mail-io1-xd43.google.com with SMTP id y5so2998864iob.12;
        Wed, 27 May 2020 06:11:53 -0700 (PDT)
X-Received: by 2002:a02:a494:: with SMTP id d20mr5442362jam.23.1590585111991;
 Wed, 27 May 2020 06:11:51 -0700 (PDT)
MIME-Version: 1.0
References: <20200527103236.148700-1-elver@google.com> <CAK8P3a1MFgRxm6=+9WZKNzN+Nc5fhrDso6orSNQaaa-0yqygYA@mail.gmail.com>
 <CA+icZUWtzu0ONUSy0E27Mq1BrdO79qNaY3Si-PDhHZyF8M4S5g@mail.gmail.com>
 <CAK8P3a04=mVQgSrvDhpVxQj50JEFDn_xMhYrvjmUnLYTWH3QXQ@mail.gmail.com>
 <CA+icZUXVSTxDYJwXLyAwZd91cjMPcPRpeAR72JKqkqa-wRNnWg@mail.gmail.com> <CAK8P3a3i0kPf8dRg7Ko-33hsb+LkP=P05uz2tGvg5B43O-hFvg@mail.gmail.com>
In-Reply-To: <CAK8P3a3i0kPf8dRg7Ko-33hsb+LkP=P05uz2tGvg5B43O-hFvg@mail.gmail.com>
Reply-To: sedat.dilek@gmail.com
From: Sedat Dilek <sedat.dilek@gmail.com>
Date: Wed, 27 May 2020 15:11:44 +0200
Message-ID: <CA+icZUWr5xDz5ujBfsXjnDdiBuopaGE6xO5LJQP9_y=YoROb+Q@mail.gmail.com>
Subject: Re: [PATCH -tip] compiler_types.h: Optimize __unqual_scalar_typeof
 compilation time
To: Arnd Bergmann <arnd@arndb.de>
Cc: Marco Elver <elver@google.com>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sedat.dilek@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=t0Us1PcW;       spf=pass
 (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::d43
 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, May 27, 2020 at 2:50 PM Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Wed, May 27, 2020 at 2:35 PM Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > On Wed, May 27, 2020 at 2:31 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > On Wed, May 27, 2020 at 1:36 PM Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > > > On Wed, May 27, 2020 at 1:27 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > > > On Wed, May 27, 2020 at 12:33 PM Marco Elver <elver@google.com> wrote:
> > > > >
> > > > > This gives us back 80% of the performance drop on clang, and 50%
> > > > > of the drop I saw with gcc, compared to current mainline.
> > > > >
> > > > > Tested-by: Arnd Bergmann <arnd@arndb.de>
> > > > >
> > > >
> > > > Hi Arnd,
> > > >
> > > > with "mainline" you mean Linux-next aka Linux v5.8 - not v5.7?
> > >
> > > I meant v5.7.
> > >
> > > > I have not seen __unqual_scalar_typeof(x) in compiler_types.h in Linux v5.7.
> > > >
> > > > Is there a speedup benefit also for Linux v5.7?
> > > > Which patches do I need?
> > >
> > > v5.7-rc is the baseline and is the fastest I currently see. On certain files,
> > > I saw an intermittent 10x slowdown that was already fixed earlier, now
> > > linux-next
> > > is more like 2x slowdown for me and 1.2x with this patch on top, so we're
> > > almost back to the speed of linux-5.7.
> > >
> >
> > Which clang version did you use - and have you set KCSAN kconfigs -
> > AFAICS this needs clang-11?
>
> I'm currently using clang-11, but I see the same problem with older
> versions, and both with and without KCSAN enabled. I think the issue
> is mostly the deep nesting of macros that leads to code bloat.
>

Thanks.

With clang-10:

$ scripts/diffconfig /boot/config-5.7.0-rc7-2-amd64-clang .config
 BUILD_SALT "5.7.0-rc7-2-amd64-clang" -> "5.7.0-rc7-3-amd64-clang"
+HAVE_ARCH_KCSAN y

With clang-11:

$ scripts/diffconfig /boot/config-5.7.0-rc7-2-amd64-clang .config
 BUILD_SALT "5.7.0-rc7-2-amd64-clang" -> "5.7.0-rc7-3-amd64-clang"
 CLANG_VERSION 100001 -> 110000
+CC_HAS_ASM_INLINE y
+HAVE_ARCH_KCSAN y
+HAVE_KCSAN_COMPILER y
+KCSAN n

Which KCSAN kconfigs did you enable?

- Sedat -

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BicZUWr5xDz5ujBfsXjnDdiBuopaGE6xO5LJQP9_y%3DYoROb%2BQ%40mail.gmail.com.
