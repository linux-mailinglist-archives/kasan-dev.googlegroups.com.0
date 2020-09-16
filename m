Return-Path: <kasan-dev+bncBCV5TUXXRUIBBMM2Q75QKGQE3TSTLPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E51826BF4E
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 10:30:43 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id di5sf4184567qvb.13
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 01:30:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600245042; cv=pass;
        d=google.com; s=arc-20160816;
        b=aE6ppn6as3VICKLZ5aONk6Bg6jXDB3IPsvgjBzWA1/YAUcDmoa2zcCYtCopBzhrvFS
         w79p4rWVEE28SbDBnXAYLewst/oJ0UtBziOdYMDzgMvSGzG91NBi3FpUeWRmkGrXhNg+
         MwnbOVvyF+OURmv8E1wUovuiMhJad1QrDTR6FXJWcXvZL8g33/oEHcQ3AJ+QWLQdpt/2
         fXS40CsCeLBB+Fxz5Yp8c/yhtnqVZ6IvDZfSECCUlqNU2O2bvLclLrZKOh1/foUaWfB4
         s3Oej4Drph2DgSmOo3dyT6cMcXVS7AIqWTKD/GafNY58RFy0sFKqchbjsSdvkOEpHqOn
         9kbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ynNM+gDV7RuZPZ3Pyl43ACRY6EUIfe9slbmUTcjkVrw=;
        b=0nnuPuhTKc4i4lSHJT8UTiidCcYAz+aDWdkSUSM4287Va6U7gfjxelTUda8tdf0GkL
         ojp2xSy/LVmrEqudsgO2cLv0W8Be+R2ovDDAjHXi1+C4FWT1I4l5szUxt1CAeGzrg7eK
         sTluyVHHBZPOhBrCO0j44skLxiIof1SN+3rKoHxcAKsb4KjBynu7kE/f5MnryVNp6i28
         U8Bw+hMy9rFu+C3muAjIYwWpdjZttTVltjEGneUDPAMD6PH1XoE3XyUNHzJ/sIy7zMm+
         dKXytZ2d0DVavplTN71cXwPCelxezajYm6hfeEPrxTEmDB2BkGzxLJrzPB7JYnVjMj0D
         H2qA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=o3PNTI1B;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ynNM+gDV7RuZPZ3Pyl43ACRY6EUIfe9slbmUTcjkVrw=;
        b=agODmYfXmAqA13Zyfybx1PRJpOrLMYJQScQK5pT2MVydCW3ONjXDtqfmJELcu6fbTS
         mAZlwSDPfpAGXvfbc5ZZTlTKY12bCGcS57wgl+a+uRWzByG9emZrh2DTOpoWBbvBqi4A
         2DCSZNve8Ydic0F/GWTH3WLmPaklXRbUGoSAwSXjN6/quzQqErUdHPeq+roQY6/3y4bK
         f2AIsIh4/huyIMXw6ANJZoicLL6PTIknNGNO2AWvt3hjhopA7RSwwy0w5ijx2htAKLzs
         sMfs2HZAeGsfpYEVqm2nnwfToqLreoHPbPTp5hEN/nXWIPMNIEcAzkpBaOEYUvkC+hPm
         9yvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ynNM+gDV7RuZPZ3Pyl43ACRY6EUIfe9slbmUTcjkVrw=;
        b=QPSRGZsNz1ZifZmmYejMNvl9Wr+0xYxWBej+8M+VySnAOcZJ+Fmzi0MznNfNEb+HAm
         TpOrzONfRGTSD34K13cJIP8ULzUi9WV3pSYvB3nLY7/WTqB0YEtFxaVltYknE+vuR5ri
         EmMdbq2RQmUcldPpOe4TDFC3WY8W59+07TvPgJGaSSTPZ7VE3oBmtud7DZwVx/34vQX/
         G8mAHE9Nc24l0MDDbEnq+LejnbyVQoBpvuMHHlxmE5ojWJDY+Da7hBQN4KwWYybHK6Kx
         9+rqud/3vVLOimY/D+xLqos/UThs8BlDDB1Tagj1bc2oz4rW18hqoReJVNEQ8qbyVhLy
         oYZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533KFmPngfWPOVU3xXJFE907i1p3MU/iYBtP0HjsoNCkOJ2uMo3l
	Z+f8unKt2qnPKg87AWyYogs=
X-Google-Smtp-Source: ABdhPJyx29Xbt5j/9JpQijQO+Rtznn6y2cXYaS5/9RMvE6ZFtTPLRfAzqn4j5nZVlsOV7EBFMV8VNw==
X-Received: by 2002:a37:a781:: with SMTP id q123mr22358914qke.436.1600245042032;
        Wed, 16 Sep 2020 01:30:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4ce:: with SMTP id 197ls770065qke.1.gmail; Wed, 16 Sep
 2020 01:30:41 -0700 (PDT)
X-Received: by 2002:a37:2713:: with SMTP id n19mr22235160qkn.497.1600245041532;
        Wed, 16 Sep 2020 01:30:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600245041; cv=none;
        d=google.com; s=arc-20160816;
        b=g0mOf8pjb6sisbkO4iy0zef9I7lG+hVxpyvaWAHDECBIlR41tNvbBgrmOvLE5sQhD7
         97x4okYqCWEcGTeV0VhRV59o+x22/SgHogA5Nv132DAiCJO5TCMCb+UuptAwxRmodEUi
         avY3VSBdDoefrGgRQ+M1ky7bli4jnrO4euAxXVOz7KEAH15i+jnzwP4mDzrconNJB/1G
         xFFA1/iFcqOfEjSgHF60vIrVBHD9aPBHgEJub4F8S6jUXQzYjAfEC1DEpcQCZKYPAXsY
         3IXxfLKbGjcnKtp2P1ghO3YHwq1aMdb+lSrGHFB4h3yylQVbGT0Hij4HDZFdzIpZIs+E
         1s/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=QHHY9c/6O+Ni91iKJG2q/1GSjFd3jc5M8UDRptkyw7M=;
        b=wkXdBOXgE3P0vDaTQHK/210az4zc7RODR0qmAtTiUJIjkx/+EjN8luxZ0uFbDPHErJ
         EhJsYG5l9FsgU3l/pbjrQ8eQ3JvGF5iPyVfo0qVfgIBpuoAuwlJF0g1VvfaCQfOf6rgq
         2KrNUAwoB+dKBHn29NpZpPw3DVar1QFFVIF1sTZDwd4rSpa2nWNif2nL/DcaKmZCq6Ed
         R9YiT8wrdwp7RH6P3Ngnfwj7Z6ri0OIU390g+TH7GiWcWUuW6DfzSPjqodB6Ux2XvRYW
         0QIB2dRGz7LNEv8lC+3QQACjcWAgrf3XhH42nB1nlzsJKEj5jDun6N/x3hzAfCaj39XT
         HcHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=o3PNTI1B;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id a27si971603qtw.4.2020.09.16.01.30.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Sep 2020 01:30:41 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1kISpo-0000n5-I0; Wed, 16 Sep 2020 08:30:36 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id A1A923050F0;
	Wed, 16 Sep 2020 10:30:32 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 8C9392127D319; Wed, 16 Sep 2020 10:30:32 +0200 (CEST)
Date: Wed, 16 Sep 2020 10:30:32 +0200
From: peterz@infradead.org
To: Marco Elver <elver@google.com>
Cc: Josh Poimboeuf <jpoimboe@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Rong Chen <rong.a.chen@intel.com>,
	kernel test robot <lkp@intel.com>,
	"Li, Philip" <philip.li@intel.com>, x86-ml <x86@kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Kees Cook <keescook@chromium.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [tip:x86/seves] BUILD SUCCESS WITH WARNING
 e6eb15c9ba3165698488ae5c34920eea20eaa38e
Message-ID: <20200916083032.GL2674@hirez.programming.kicks-ass.net>
References: <5f60c4e0.Ru0MTgSE9A7mqhpG%lkp@intel.com>
 <20200915135519.GJ14436@zn.tnic>
 <20200915141816.GC28738@shao2-debian>
 <20200915160554.GN14436@zn.tnic>
 <20200915170248.gcv54pvyckteyhk3@treble>
 <20200915172152.GR14436@zn.tnic>
 <CAKwvOdkh=bZE6uY8zk_QePq5B3fY1ue9VjEguJ_cQi4CtZ4xgw@mail.gmail.com>
 <CANpmjNPWOus2WnMLSAXnzaXC5U5RDM3TTeV8vFDtvuZvrkoWtA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPWOus2WnMLSAXnzaXC5U5RDM3TTeV8vFDtvuZvrkoWtA@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=o3PNTI1B;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Sep 15, 2020 at 08:09:16PM +0200, Marco Elver wrote:
> On Tue, 15 Sep 2020 at 19:40, Nick Desaulniers <ndesaulniers@google.com> wrote:
> > On Tue, Sep 15, 2020 at 10:21 AM Borislav Petkov <bp@alien8.de> wrote:

> > > init/calibrate.o: warning: objtool: asan.module_ctor()+0xc: call without frame pointer save/setup
> > > init/calibrate.o: warning: objtool: asan.module_dtor()+0xc: call without frame pointer save/setup
> > > init/version.o: warning: objtool: asan.module_ctor()+0xc: call without frame pointer save/setup
> > > init/version.o: warning: objtool: asan.module_dtor()+0xc: call without frame pointer save/setup
> > > certs/system_keyring.o: warning: objtool: asan.module_ctor()+0xc: call without frame pointer save/setup
> > > certs/system_keyring.o: warning: objtool: asan.module_dtor()+0xc: call without frame pointer save/setup
> 
> This one also appears with Clang 11. This is new I think because we
> started emitting ASAN ctors for globals redzone initialization.
> 
> I think we really do not care about precise stack frames in these
> compiler-generated functions. So, would it be reasonable to make
> objtool ignore all *san.module_ctor and *san.module_dtor functions (we
> have them for ASAN, TSAN, MSAN)?

The thing is, if objtool cannot follow, it cannot generate ORC data and
our unwinder cannot unwind through the instrumentation, and that is a
fail.

Or am I missing something here?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200916083032.GL2674%40hirez.programming.kicks-ass.net.
