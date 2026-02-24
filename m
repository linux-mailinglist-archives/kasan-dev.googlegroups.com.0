Return-Path: <kasan-dev+bncBDCPL7WX3MKBBBPI7DGAMGQE22YN6KA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id VQahAAg0nmmFUAQAu9opvQ
	(envelope-from <kasan-dev+bncBDCPL7WX3MKBBBPI7DGAMGQE22YN6KA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:28:08 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 83C6418E24A
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:28:07 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-67999893008sf36426507eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 15:28:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771975686; cv=pass;
        d=google.com; s=arc-20240605;
        b=JbsA0pRI3X+660vDKFVfV0MmkIiZTo3qsD0jSXgph1r13SCs+K7qoTkfo+7vWQ0jfm
         B/21RmFts9DIygjg9cqqtiOZgUylhsdBJrziufrwBR0VSdNJCo7qEwgx50EAdJTRqm3y
         OawNsH8KD85TW72mcpZgx3NC6wVnnL6DKydxd3KNQK0HeLQFqRJne2kBtNIhxoiHhIOy
         sXyg2IoEKiHDVn/VerICl1LJs14WaZmMsSGQY4jRCpHByYnXnzL5WUTo/jZNLxr4JlIn
         GT/e19gGv1m756lN8S1zsMo5GkYoqYKMRjHQgCI4FiFDIrdvI8S2lXRE3XytvZwIc9QH
         xw4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=xxU0/xueLjYo+7ARwW51KCg/XIP9N+V9HehrTkXHLwk=;
        fh=6l4mZrJco74hAJd+cSCRW4q8vRA3K+oRc6s/WGdaTNM=;
        b=jy2OsirjhS9E7ipfDDHopPpRiqxUQ/jhN8nzRTSNfaEFoUPd4m+XcvI554JOeQtMBL
         urt5jC/P3804evFhUa8bO1du7/Ky/cpx3WzFIiU9XvSmB9slF7kUZkSJY8kCV9L15vXK
         Ab3ul/n1f9pwlwjCNvBuc9qmAtSkY5lvPjC62McuNUpwC55k27Xfv5hYlcI4KEuYFByc
         RtSn6fZDBJnljoCiWIIjLg+43oE5K3Mu69SO1IKicNrqoykKFNByqu8R+z/sm5eRM3Zb
         vASdiuL/SAgT9XtLTig1J48UHOB6hfwPLX1w1LxtdkadsrlgVOiCh/AlIvwUnvwGjgBi
         2H6A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GcDxK2Ij;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771975686; x=1772580486; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=xxU0/xueLjYo+7ARwW51KCg/XIP9N+V9HehrTkXHLwk=;
        b=G6G8l80ZZCMqoA2E43xezAQ9ffA+O201akV8v9eZPoBw3Ot91HsRCCLe3FKHHYiXJp
         UTfSVdyJDn7XVzwRrbITXeeqdESymkiZOqR+hk3QTEEo8EOahSj/NErUqIuieJZLifcF
         poMHBaSC7R8vilpX/mjFwbhdg97sIEJ6PLcofvGPRVZChI9CNBOSuaulIgAYLH0jQNMK
         k6Bbq/WecDJKBwjGTyFLFx04pYQN9bfC6JZ0F2BdcBPwkYqlcX6awLwsUdCG6OghUWI7
         WzN1kGPCbZb4oLCH4Xs8zvO4Q74bapmLQ4z3oR2QiH/5Ldrqc6sF27EEps07nLHkx/Kb
         fBDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771975686; x=1772580486;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xxU0/xueLjYo+7ARwW51KCg/XIP9N+V9HehrTkXHLwk=;
        b=s4uIQ5P70AZsLp6yMM9+s+RsecealAQ6ib++2/bTJAR5VaVbvRQu9iR6IzRxKpFthl
         Vz+2PjNwp/0MXiULVe0lTTDJQ0ufIjkrOcnJH103c6MGqFLSBC+HH1ZcOJ9QsKLR1sR2
         A6RBa3TEXgT4bvoHgPGajOFdKtGTorG6EUkorGFTz/idgLZ1Ef42C7pTVe5v9UlgISPQ
         Fn3JfLXa2V8B4Vg4QZRaDq1DEP3okF1ccvpzMuO8LG7ivZejW7v1ekb2PdtUcYXo5Yp5
         whpytbmyqOMN3/Gf+8FGmzdf5pQjTe6+kRQ0d9qalfwWpf3bBdrn1IajHPA2Hc2tr+Gy
         eCJQ==
X-Forwarded-Encrypted: i=2; AJvYcCVXar8Y4S0+RUQPLugZSGoWHnBarZPyBPiWTVD67J/WSdK6FssF2oZJOfAq2noV9a0GwpwVlA==@lfdr.de
X-Gm-Message-State: AOJu0YwEuCZsecw1MWb7Jynd/iufBVeC0ebTArPGcWBQDpUsVvl4MGR/
	IafWhUImVegp51X/7lOJWho4uUeuS6tffzp9sUEDfkzCatobOhjnLt6v
X-Received: by 2002:a4a:ec4a:0:b0:679:a4fe:f01e with SMTP id 006d021491bc7-679e9ba93aemr227829eaf.1.1771975685677;
        Tue, 24 Feb 2026 15:28:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GE25IqKoYraDn8Ta29cOXZVRbzG7fUBI6l2HkoxjhYtA=="
Received: by 2002:a05:6871:2917:20b0:40a:60c0:3a93 with SMTP id
 586e51a60fabf-415f060ad83ls10278fac.2.-pod-prod-06-us; Tue, 24 Feb 2026
 15:28:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXYDX8tOhWP1XHmeZATOxAtN+b1F4E6z2cfV3of5itC/3cPXacCHgzETxg3LSMPGnvz8PTSag4N+wY=@googlegroups.com
X-Received: by 2002:a05:6808:bd4:b0:450:b8da:b800 with SMTP id 5614622812f47-46491478685mr174843b6e.47.1771975684605;
        Tue, 24 Feb 2026 15:28:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771975684; cv=none;
        d=google.com; s=arc-20240605;
        b=EjS0CYw4mUXHYsj3RdepQVpw6fDrYvT78+KWto4VkwJDTfd97q2fr8X2rZmSUKpe3y
         Qsdfpw1SUFqQnmqe4Lo7mPX4PI9eSOKjfY8j/bfSt3Zyumi56V/AaDwz2z4SpSEp4+Pw
         ij4L/aXX6wCDRaeqlQjkYemmvoC4nfJQIoLjFP+g+74p65TiaXmsT9YOSOOU1tdxPElT
         7jUwtPl2vOtUfHSZg705ylBwExBI/q/cdgtosaCLfxgbCF4kEtV/ey3wTymVSKdxFvVo
         51BHAL5HpEVpXDO/DqB7UeqgNHyrplcgi7K4DIfxLX2Wik5b5ru02loZ44ZIZmscK3c0
         rxXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=x+8JGJ6OOJGG8YBEqq6329WZ0ZxT4Ni5dK+ONFSWX10=;
        fh=N79l3JJ/JpQkjLdBAS4x2O+gTcUEzMBEZ+F6wZlk9dA=;
        b=UCEz3ppvkLgKSE8MXnqwK4HBnLyMwD7esZEtlOfZZMd4RawDjGiSWQ0EzpvQPcyerb
         lCj6DzeFhzzMXK0FO2lmo/Wes9vYdZ1EOn4GXQWZPBldFPBfCFAQ/5JN0I7MbnXnGje/
         +Uxtcjfzf4YCLixmDgQ/gl/itDzbu/hIBw0X/kHqWA3oV5jAKbBo9TGcFz4mTH29C6NQ
         Kd7iktTdyHeXIBMsgYExJ9cN9bK9wfgs/2kYoYLb5Oz6eUshM/9fp7mIpuu0hKFWB5QS
         4Na9Sv1vzbtz0NXJF4StFqkON3+k1tY1Kqq3Yxv8HC4iirmPMlMMcYPK0/v+anCgiEuR
         vYFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GcDxK2Ij;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7d52cf741a1si459533a34.2.2026.02.24.15.28.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Feb 2026 15:28:04 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 0630560051;
	Tue, 24 Feb 2026 23:28:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A86B7C116D0;
	Tue, 24 Feb 2026 23:28:03 +0000 (UTC)
Date: Tue, 24 Feb 2026 15:28:03 -0800
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH] kcsan: test: Adjust "expect" allocation type for
 kmalloc_obj
Message-ID: <202602241526.AE3F2F4A32@keescook>
References: <20260223222226.work.188-kees@kernel.org>
 <CANpmjNOpXe7tCP7tyR04Hm+a8zdiBWWQdK=US-qTL31mm+Yzkw@mail.gmail.com>
 <202602241316.CFFF256ED6@keescook>
 <CANpmjNNZ-U4hT8LaW=V+q+NRPHb=fsxai86CBb1VdV8Pyo_xNA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNZ-U4hT8LaW=V+q+NRPHb=fsxai86CBb1VdV8Pyo_xNA@mail.gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GcDxK2Ij;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_RHS_NOT_FQDN(0.50)[];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDCPL7WX3MKBBBPI7DGAMGQE22YN6KA];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	MISSING_XM_UA(0.00)[];
	RCPT_COUNT_FIVE(0.00)[6];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	HAS_REPLYTO(0.00)[kees@kernel.org]
X-Rspamd-Queue-Id: 83C6418E24A
X-Rspamd-Action: no action

On Tue, Feb 24, 2026 at 11:39:45PM +0100, Marco Elver wrote:
> On Tue, 24 Feb 2026 at 22:48, Kees Cook <kees@kernel.org> wrote:
> >
> > On Tue, Feb 24, 2026 at 11:09:44AM +0100, Marco Elver wrote:
> > > On Mon, 23 Feb 2026 at 23:22, Kees Cook <kees@kernel.org> wrote:
> > > >
> > > > Instead of depending on the implicit case between a pointer to pointers
> > > > and pointer to arrays, use the assigned variable type for the allocation
> > > > type so they correctly match. Solves the following build error:
> > > >
> > > > ../kernel/kcsan/kcsan_test.c: In function '__report_matches':
> > > > ../kernel/kcsan/kcsan_test.c:171:16: error: assignment to 'char (*)[512]' from incompatible pointer type 'char (*)[3][512]'
> > > > [-Wincompatible-pointer-types]
> > > >   171 |         expect = kmalloc_obj(observed.lines);
> > > >       |                ^
> > > >
> > > > Tested with:
> > > >
> > > > $ ./tools/testing/kunit/kunit.py run \
> > > >         --kconfig_add CONFIG_DEBUG_KERNEL=y \
> > > >         --kconfig_add CONFIG_KCSAN=y \
> > > >         --kconfig_add CONFIG_KCSAN_KUNIT_TEST=y \
> > > >         --arch=x86_64 --qemu_args '-smp 2' kcsan
> > > >
> > > > Reported-by: Nathan Chancellor <nathan@kernel.org>
> > > > Fixes: 69050f8d6d07 ("treewide: Replace kmalloc with kmalloc_obj for non-scalar types")
> > > > Signed-off-by: Kees Cook <kees@kernel.org>
> > > > ---
> > > > Cc: Marco Elver <elver@google.com>
> > > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > > Cc: <kasan-dev@googlegroups.com>
> > > > ---
> > > >  kernel/kcsan/kcsan_test.c | 2 +-
> > > >  1 file changed, 1 insertion(+), 1 deletion(-)
> > > >
> > > > diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> > > > index 79e655ea4ca1..056fa859ad9a 100644
> > > > --- a/kernel/kcsan/kcsan_test.c
> > > > +++ b/kernel/kcsan/kcsan_test.c
> > > > @@ -168,7 +168,7 @@ static bool __report_matches(const struct expect_report *r)
> > > >         if (!report_available())
> > > >                 return false;
> > > >
> > > > -       expect = kmalloc_obj(observed.lines);
> > > > +       expect = kmalloc_obj(*expect);
> > >
> > > This is wrong. Instead of allocating 3x512 bytes it's now only
> > > allocating 512 bytes, so we get OOB below with this change. 'expect'
> > > is a pointer to a 3-dimensional array of 512-char arrays (matching
> > > observed.lines).
> >
> > Why did running the kunit test not trip over this? :(
> >
> > Hmpf, getting arrays allocated without an explicit cast seems to be
> > impossible. How about this:
> >
> >
> > diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> > index 056fa859ad9a..ae758150ccb9 100644
> > --- a/kernel/kcsan/kcsan_test.c
> > +++ b/kernel/kcsan/kcsan_test.c
> > @@ -168,7 +168,7 @@ static bool __report_matches(const struct expect_report *r)
> >         if (!report_available())
> >                 return false;
> >
> > -       expect = kmalloc_obj(*expect);
> > +       expect = (typeof(expect))kmalloc_obj(observed.lines);
> 
> That works - or why not revert it back to normal kmalloc? There's
> marginal benefit for kmalloc_obj() in this case, and this really is
> just a bunch of char buffers - not a complex object. If there's still
> a benefit to be had from kmalloc_obj() here, I'm fine with the typeof
> cast.

Honestly... it's because I can't figure out how to make a exclusion for
this (nor how to get multidimensional array types) in Coccinelle to
avoid this case. (So re-running the conversion script will keep trying
to change this case.) And it's the only place in the kernel doing this
kind of thing. :P

I've sent v2 with the cast and a better commit log describing what's
happening.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202602241526.AE3F2F4A32%40keescook.
