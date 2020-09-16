Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7VBQ75QKGQEH22JNVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5019526BFA5
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 10:46:55 +0200 (CEST)
Received: by mail-vs1-xe3a.google.com with SMTP id g5sf1838233vsg.14
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 01:46:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600246014; cv=pass;
        d=google.com; s=arc-20160816;
        b=W81xi7iDJ8jcEKxfsFF77ofcxRwPob89NJdo5OpnjJIyOS+9LACOS3E+FGSHIBJlM+
         bcgr+7At7S4Pxab5ajJubgl1yHoWwL3HXGONYdnJPHjKEZmqtuKPuBPCr+t3JfK+VLxw
         5i+HgZTUoZopKcHZfNXl0uqDjiwkgXSAsVVADDFjatHW8ylVNrmvD/7ituO4OqZs6AI0
         O9w7gRmiEb2nx/IoAYJqkPGW9fY/hP8LXBINgkJy/aiTCHRtwvzAhPuC/9XY6DXp9+Z7
         G+JqDyT3EA199ZI1PZkcfMJDKbpIfQbeOC2SK/ZgA1SkQyyusbCyAdHjZ9Dwsj7Z35Qv
         Ddew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RDU9My2rZgcZER6enqXZ038F6OHrBVor5TvmfOYGHBc=;
        b=LyVv7Z0AiHO1XBlWAi6EXR6naF6wnLKu5pj3PbcauoUIBQeRQLQsC3e2ZAy+bUoCHj
         J8Yw4Cz8craNED2pr/inF9tGGPHZpw32cWpRka7pvo0LOpFxf5vCuZJXXgGt+uB+2ayb
         0md/zMqQ6nrK4/gchoW+435fiF8EHtSqOJ2UpenjocLMcJcbf/Vy8QswJmwW1tRQPJ8B
         nu9qeAvLNU6WuCOSgSzfkXxBFNQcmbq907P5Ws++hapnYmc1uWNjcLfNXKi72CvofvJc
         YvCf/kNkngr+2JVonM4twmWwxmsURNjx58Ftb1e2RTrx4RCf6E9tVn8nQCUq32leHYXb
         VV6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s3aJCgj3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RDU9My2rZgcZER6enqXZ038F6OHrBVor5TvmfOYGHBc=;
        b=cQY2zFCunJqdk4EZqz49zF2I9mlL1i2S39kYXzz3LIbQHEDB0B2j1CvB2nwsC71KAC
         4HOluzVpYCzfwBHUiilNigirIIrFsc+TKtN7/jV2C6Zt0OOKQxA3Nfq65AFNSiXZ8cNX
         jtZqSyy2/4jEOSJX17Qy7vxQHjv1kqXgsLErYOC4npFhSXpUXnLQRl4kgiKYqLq27ey5
         v2dXjmqN5GT2nZDBC2Hfhekehs9uKPlFjwxJ1aIPIGKtbmMQqeqPxAKKLT9xOZdtMzTZ
         qv01Myrp0Kn0vOPCFy1o92t4VYqdcmHxyBj8JKc94Xb68cwwWrVq7kw95Y674NV9pyY1
         5erw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RDU9My2rZgcZER6enqXZ038F6OHrBVor5TvmfOYGHBc=;
        b=ugKNpQkAXxW5BzLCp9nmR+A8AM2/u7z8EyIuaG1xLWVcwEGmVfOSeOWhyCzY/msQ76
         zw7SV4JWLovzdVu9X3N6WjYkFYDZ/WDaFq927HID6Hf/lvnbBuA34W6jgJXdj40efkUA
         ZcGXcs4sR9utxDlzHdlBu72EHW0cmQuE31Ag3yORB92tzaT4ezSBSNpAda5LIvLEWiDi
         qSPu47bFZaxjgyKzamT4TQfNfcObpgmk+8HjId5FXat/IdIn098b5lF6KlHwH01rHudl
         V7HaD5PD2VbFzOGdL5eJBpsPHAwp5svoCFtUP96iRUoEIRXxxLt8Kp2l8wr/H4jdflg8
         AXjg==
X-Gm-Message-State: AOAM531hsET5DxFaGi9o1oP22pGoSHuQn0nF4d33m5BiCQQvwYsWEXhn
	bjj3TOA/edOV5eK1JEJ8Swo=
X-Google-Smtp-Source: ABdhPJy7uEW4OjjFHvu8pBh8MamCAjK+kn6CXx3bNfbNs+39CyRDxWUgCDkEkN8HOxp7MmVd9+g5wQ==
X-Received: by 2002:a1f:2cc:: with SMTP id 195mr13166791vkc.2.1600246014231;
        Wed, 16 Sep 2020 01:46:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:3602:: with SMTP id d2ls58583vka.0.gmail; Wed, 16 Sep
 2020 01:46:53 -0700 (PDT)
X-Received: by 2002:a1f:9c12:: with SMTP id f18mr3840234vke.14.1600246013761;
        Wed, 16 Sep 2020 01:46:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600246013; cv=none;
        d=google.com; s=arc-20160816;
        b=WZ6Lhl0qgSJ7vHgGqvIkFLhZpARBb4w7w8+i36qFOciX8uTIJaGIjsj0a9HyRHR3v6
         ysuIyicdaQiLEYG1nkAjmwKIR0inJAhtaB1rKySWT8b7HbAQ8vMc7uEdKXCwfqrPD5Wf
         n79nMGudVVxpyrvxrwyrsScDdAPOwnB6PrYbEO10OZoUTyy55eu3AgHG7gK5vJ3lPSCH
         LNoxzFOJBleGINxrQ/WG/9PS7iR6TX2nZEReuEcNAJ79USti5yREfUDrNepeXc6+3saP
         Zl1OEsDdjqh/NzX7ylkiOW2gFCDPFg3sxLUSfTiBk/zCwrgE1tSHckvcUimyXoog+yiz
         A+FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mFHlsqUTp6bF1BGPzUjg3LJj5CvZI8A5XHbHTxJpfjI=;
        b=sXWphiw/GkhSD46oJzK9buU4heXLveCuSYb5ME2zZKIyywyH2dx1n8qIs/OnthE+oG
         ByadnjdNGABwMG3Ds30HA+QXZ+tzA0CKfftfK4FDfYB80y0vMK/YzwftxApSrDTNjx50
         grNEOe+E6mwgVZMQ7e4z9HxDnPDUQaj7KWbeBalkRAgD+Jg5uDLiMYIGIgC9UqQXk5oN
         k02V1UTbwr7W70xCQ7x4Z4PMHRlUO4qbBO3Hr1w7MZUq/+HEdVFO6Flk7/kQsOJXU9FT
         0wA5Fdr2lNTLT0WTVkzNmUbBKI26CMn2Z0VDZ7wcmDkuaw9dNnzmXeeJT229HFGhqGGb
         mHXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s3aJCgj3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id y65si1150921vkf.1.2020.09.16.01.46.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Sep 2020 01:46:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id c10so5915059otm.13
        for <kasan-dev@googlegroups.com>; Wed, 16 Sep 2020 01:46:53 -0700 (PDT)
X-Received: by 2002:a9d:66a:: with SMTP id 97mr2793069otn.233.1600246013074;
 Wed, 16 Sep 2020 01:46:53 -0700 (PDT)
MIME-Version: 1.0
References: <5f60c4e0.Ru0MTgSE9A7mqhpG%lkp@intel.com> <20200915135519.GJ14436@zn.tnic>
 <20200915141816.GC28738@shao2-debian> <20200915160554.GN14436@zn.tnic>
 <20200915170248.gcv54pvyckteyhk3@treble> <20200915172152.GR14436@zn.tnic>
 <CAKwvOdkh=bZE6uY8zk_QePq5B3fY1ue9VjEguJ_cQi4CtZ4xgw@mail.gmail.com>
 <CANpmjNPWOus2WnMLSAXnzaXC5U5RDM3TTeV8vFDtvuZvrkoWtA@mail.gmail.com> <20200916083032.GL2674@hirez.programming.kicks-ass.net>
In-Reply-To: <20200916083032.GL2674@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Sep 2020 10:46:41 +0200
Message-ID: <CANpmjNOBUp0kRTODJMuSLteE=-woFZ2nUzk1=H8wqcusvi+T_g@mail.gmail.com>
Subject: Re: [tip:x86/seves] BUILD SUCCESS WITH WARNING e6eb15c9ba3165698488ae5c34920eea20eaa38e
To: Peter Zijlstra <peterz@infradead.org>
Cc: Josh Poimboeuf <jpoimboe@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Nick Desaulniers <ndesaulniers@google.com>, Rong Chen <rong.a.chen@intel.com>, 
	kernel test robot <lkp@intel.com>, "Li, Philip" <philip.li@intel.com>, x86-ml <x86@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Kees Cook <keescook@chromium.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=s3aJCgj3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Wed, 16 Sep 2020 at 10:30, <peterz@infradead.org> wrote:
> On Tue, Sep 15, 2020 at 08:09:16PM +0200, Marco Elver wrote:
> > On Tue, 15 Sep 2020 at 19:40, Nick Desaulniers <ndesaulniers@google.com> wrote:
> > > On Tue, Sep 15, 2020 at 10:21 AM Borislav Petkov <bp@alien8.de> wrote:
>
> > > > init/calibrate.o: warning: objtool: asan.module_ctor()+0xc: call without frame pointer save/setup
> > > > init/calibrate.o: warning: objtool: asan.module_dtor()+0xc: call without frame pointer save/setup
> > > > init/version.o: warning: objtool: asan.module_ctor()+0xc: call without frame pointer save/setup
> > > > init/version.o: warning: objtool: asan.module_dtor()+0xc: call without frame pointer save/setup
> > > > certs/system_keyring.o: warning: objtool: asan.module_ctor()+0xc: call without frame pointer save/setup
> > > > certs/system_keyring.o: warning: objtool: asan.module_dtor()+0xc: call without frame pointer save/setup
> >
> > This one also appears with Clang 11. This is new I think because we
> > started emitting ASAN ctors for globals redzone initialization.
> >
> > I think we really do not care about precise stack frames in these
> > compiler-generated functions. So, would it be reasonable to make
> > objtool ignore all *san.module_ctor and *san.module_dtor functions (we
> > have them for ASAN, TSAN, MSAN)?
>
> The thing is, if objtool cannot follow, it cannot generate ORC data and
> our unwinder cannot unwind through the instrumentation, and that is a
> fail.
>
> Or am I missing something here?

They aren't about the actual instrumentation. The warnings are about
module_ctor/module_dtor functions which are compiler-generated, and
these are only called on initialization/destruction (dtors only for
modules I guess).

E.g. for KASAN it's the calls to __asan_register_globals that are
called from asan.module_ctor. For KCSAN the tsan.module_ctor is
effectively a noop (because __tsan_init() is a noop), so it really
doesn't matter much.

Is my assumption correct that the only effect would be if something
called by them fails, we just don't see the full stack trace? I think
we can live with that, there are only few central places that deal
with ctors/dtors (do_ctors(), ...?).

The "real" fix would be to teach the compilers about "frame pointer
save/setup" for generated functions, but I don't think that's
realistic.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOBUp0kRTODJMuSLteE%3D-woFZ2nUzk1%3DH8wqcusvi%2BT_g%40mail.gmail.com.
