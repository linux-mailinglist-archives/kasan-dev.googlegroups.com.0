Return-Path: <kasan-dev+bncBDCPL7WX3MKBBBWS7DGAMGQEG67AOYA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6AZDFAgpnmk7TwQAu9opvQ
	(envelope-from <kasan-dev+bncBDCPL7WX3MKBBBWS7DGAMGQEG67AOYA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 23:41:12 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13b.google.com (mail-yx1-xb13b.google.com [IPv6:2607:f8b0:4864:20::b13b])
	by mail.lfdr.de (Postfix) with ESMTPS id E76BF18D8C4
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 23:41:11 +0100 (CET)
Received: by mail-yx1-xb13b.google.com with SMTP id 956f58d0204a3-649d34b88d3sf6949816d50.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 14:41:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771972870; cv=pass;
        d=google.com; s=arc-20240605;
        b=DKX0CtUwwBKwdJeWX81wMNL65YRE/LDmL1dVpF3IGdLZodbztIpHGBNtGnaYfaKbUR
         7G22NLeivLxXRIYgAGxvFHX1VLfnBZslWvW0QNeDl2xKUHU7cFW1J2iwtd+OFEob32Cb
         tpLb3FfJ5rAAX7LeG8mnTJnzu+/UyiGJIEwSsyJ0PexF7DdCW2530K7/rQOS/9NS6tq/
         SRUNDj6GzfJWqjlgeCIMPdPaeZfx4iVdp1zKYEOXK+jcX0sHqwpWZwKy0N3WH9P83zLB
         xKojSjDDDTCsw+gMnKIOn/QGQ+QVa6X0zujt0fozPvO047cJD2Cwf1DwBKnyJSrQvkvN
         ThKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=YlGpCytbCxjKXYdUbie+YOWbmdgeaBIQMm+gDBVol10=;
        fh=DuOwYK3CmOBk9YHPmw/In7J/Ega4KBbTgjFUg2DlTwU=;
        b=bhmpMstg/yt6DU/ucUdznMi/fEsLm3axYZbYOHHRVgbcxri9FkaZ54n4rmqv3kYsic
         O7d7SuKr8nIiVIJbp4D5DAVc0n0634apYMzvhyzOJAYsDQMkF9hOMDDeg/bgJDHZfS9k
         0v8JdpiEArAOk1g3fFuBKm0KG27K5hTlGNjvSJrJQgyLSbOd0YZITa8xzD24pi7N6VA3
         gxsrKvZViOgIWbXKCEd8mKtTKP7cxg8K2bwq/i4S1gsGZq/bu6zM3N+QpOlCjFuodNKm
         oouUb6t2J0tWklxBJTsibIbyrSx+lDKMcKvXRjripJHbh2Od+1/xkXFr5PNhprJlKS6a
         hEmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qXOqAJIz;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771972870; x=1772577670; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=YlGpCytbCxjKXYdUbie+YOWbmdgeaBIQMm+gDBVol10=;
        b=qgnq6x5P9VQFyz/pmIbpa1rpXkv97eBYTGqGesUWpoSEzoE638pcU7QkymfbNqYHO1
         f4bWmEMoQ48ZFFRF7AdTnRxwSiD8DEuSplShECy+4VQbkc3pOGlE0ZxVmjz6vn0+yrnd
         f1lMrUrOVjiskG3fp3FsoQzpPOrhxouQnXc6g3fi49cCerDYfpHmn/aNDFz6Toesr1u8
         jUwv0bn+Uj4Pi7b6pHSGQNkeUiEX9pHtOkdUssHxYVam6Om2SeboZGukEbxvfrgT/eXC
         usDhsbyDIiw/7cksw0VXEyqqDgw4apUDBtAwrAuF6M7uWy7ln8BjOH/LZcFmsA44/GcH
         i5+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771972870; x=1772577670;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YlGpCytbCxjKXYdUbie+YOWbmdgeaBIQMm+gDBVol10=;
        b=EmznZBKdyuRLCKRXxPDKMSa/FdQPijzEnCi7Im0io6wpQRApd1Fw/1Cirn+IZQaH4Q
         E78v7U2TXDKa+K8r6FBciyBu7Fh++cIUZEkFkFq6awNqiO2/85toYsBfDwPaiPmt2O74
         c3AzIFoCjTqE34bAQMnKYl0NUibn94y19Z8p/ID9SJ5Ine+V72Q/wr0TtUlrrjIOvUj6
         yKr+Hkjrb0+BLTVfbmRowvs7dbjVYCcMtzhRoA8KpPzbnQKjI3AkM1e+PmdZhA6pYTX8
         G4bygN57mGFpbboPM1yiKeUvDjcCzXwxFX89jSX7ZhnNWw+Y9WPR6hTrcGCyPe9rjbSh
         1zZQ==
X-Forwarded-Encrypted: i=2; AJvYcCUKjNp+lZjBYR+lUij4i/1z8C8mQelPL8Ft7ey0Mh9UvWgfonk3bEYx1H4ha0JyDyLihgfxkw==@lfdr.de
X-Gm-Message-State: AOJu0YxbtvYxTcm0zAB7/ZT3IjhfsWig/CeXRT4MmMajiVqX+/El21Hw
	2WtnfAUQSagWqdZHIEtWyLGsAAXvAHAdDa8bdLLUOSTBegpgAudJRDs8
X-Received: by 2002:a53:dd11:0:b0:64a:fd80:85d with SMTP id 956f58d0204a3-64ca8d0cd0bmr271879d50.65.1771972870488;
        Tue, 24 Feb 2026 14:41:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EpkE7K0PPRyuS2K8eZDFFoURpS2pV3gla/v4Jkjt1MBA=="
Received: by 2002:a53:ee45:0:b0:646:7a94:ce27 with SMTP id 956f58d0204a3-64c084b82fals8750455d50.3.-pod-prod-05-us;
 Tue, 24 Feb 2026 14:41:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXVhxTAqDfKC9RPojS/cydKceDXyhgShU3uEE0DUYBSoS5lTqUmzHuYHAbPlHUEWyxoaBDYz41Hb70=@googlegroups.com
X-Received: by 2002:a05:690c:e3c1:b0:798:6542:30f6 with SMTP id 00721157ae682-798681c5a39mr3068187b3.37.1771972869597;
        Tue, 24 Feb 2026 14:41:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771972869; cv=none;
        d=google.com; s=arc-20240605;
        b=BDywRHKRW40d3UVM42lndbwH+pgxCpDT2MkmhSDMk21WDLkt+a6T0FcEWgcx0bJzdq
         yKH074OmJQ1qpKb1t4OahaAyhGaru0+/gLEdIVd5Se5ic2XsA+vt0mavhWsSPLSSvBr6
         YSSrySt42/EgwlctojWTmTpDDsgb1yXN9U3GUqj+HFPzODaR3ZdT2y0vMkWBEojYi7/L
         /QYewfHIZsUTVzn2osbqYzKx80NSJ92MLyz0ruz11IgsrpqUIAr4cDUfYudET+O0+fK1
         RtdCNnuYgYl37E2Sab6qhXZk69cG7UC/zuzrvJD+mDX+gnTLS9lavwvEt0anIWTLjVyV
         Ky1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+6ZDuRamO3lJWw33Pp04KKdJkOLtwpwzZYjrgnF5ln8=;
        fh=N79l3JJ/JpQkjLdBAS4x2O+gTcUEzMBEZ+F6wZlk9dA=;
        b=WV4XGz+39gbqZvZhzqpSJFj1SWpXPKf2WGuEg/W3WQveeAAOlDuJ9V14QwhiG5PCs3
         UD9um561sctQKQs1HU4TOa7BWRM8TfpFk/Tnwl+SWcbl/k1WP9of+QEz6eIdinfoIqi6
         rmvBvOK+cBlyvOBAha0GL4djPvTf+Dy2PP2ohuWaj/tPJvxup8o/xgag8gH2Dr0gsaaA
         FhamUETwbNafUWqdkBSLPIU77anfHagjGf0XaDT0trJZRjKnwygv/y1lZjM6BnSuhwlZ
         Tsh4Ar9PiyYzwx4VQ7Ec/VxB9QvINI6UTBMWfvSnncL5RjQGpfmpqmxWX3cS77O5WI0D
         f7PQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qXOqAJIz;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7982de20a71si4278177b3.5.2026.02.24.14.41.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Feb 2026 14:41:09 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id C6DFF40AC1;
	Tue, 24 Feb 2026 22:41:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A0A3DC116D0;
	Tue, 24 Feb 2026 22:41:08 +0000 (UTC)
Date: Tue, 24 Feb 2026 14:41:08 -0800
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH] kcsan: test: Adjust "expect" allocation type for
 kmalloc_obj
Message-ID: <202602241440.1D885B8@keescook>
References: <20260223222226.work.188-kees@kernel.org>
 <CANpmjNOpXe7tCP7tyR04Hm+a8zdiBWWQdK=US-qTL31mm+Yzkw@mail.gmail.com>
 <202602241316.CFFF256ED6@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202602241316.CFFF256ED6@keescook>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qXOqAJIz;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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
	TAGGED_FROM(0.00)[bncBDCPL7WX3MKBBBWS7DGAMGQEG67AOYA];
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
X-Rspamd-Queue-Id: E76BF18D8C4
X-Rspamd-Action: no action

On Tue, Feb 24, 2026 at 01:48:51PM -0800, Kees Cook wrote:
> On Tue, Feb 24, 2026 at 11:09:44AM +0100, Marco Elver wrote:
> > On Mon, 23 Feb 2026 at 23:22, Kees Cook <kees@kernel.org> wrote:
> > >
> > > Instead of depending on the implicit case between a pointer to pointers
> > > and pointer to arrays, use the assigned variable type for the allocation
> > > type so they correctly match. Solves the following build error:
> > >
> > > ../kernel/kcsan/kcsan_test.c: In function '__report_matches':
> > > ../kernel/kcsan/kcsan_test.c:171:16: error: assignment to 'char (*)[512]' from incompatible pointer type 'char (*)[3][512]'
> > > [-Wincompatible-pointer-types]
> > >   171 |         expect = kmalloc_obj(observed.lines);
> > >       |                ^
> > >
> > > Tested with:
> > >
> > > $ ./tools/testing/kunit/kunit.py run \
> > >         --kconfig_add CONFIG_DEBUG_KERNEL=y \
> > >         --kconfig_add CONFIG_KCSAN=y \
> > >         --kconfig_add CONFIG_KCSAN_KUNIT_TEST=y \
> > >         --arch=x86_64 --qemu_args '-smp 2' kcsan
> > >
> > > Reported-by: Nathan Chancellor <nathan@kernel.org>
> > > Fixes: 69050f8d6d07 ("treewide: Replace kmalloc with kmalloc_obj for non-scalar types")
> > > Signed-off-by: Kees Cook <kees@kernel.org>
> > > ---
> > > Cc: Marco Elver <elver@google.com>
> > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > Cc: <kasan-dev@googlegroups.com>
> > > ---
> > >  kernel/kcsan/kcsan_test.c | 2 +-
> > >  1 file changed, 1 insertion(+), 1 deletion(-)
> > >
> > > diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> > > index 79e655ea4ca1..056fa859ad9a 100644
> > > --- a/kernel/kcsan/kcsan_test.c
> > > +++ b/kernel/kcsan/kcsan_test.c
> > > @@ -168,7 +168,7 @@ static bool __report_matches(const struct expect_report *r)
> > >         if (!report_available())
> > >                 return false;
> > >
> > > -       expect = kmalloc_obj(observed.lines);
> > > +       expect = kmalloc_obj(*expect);
> > 
> > This is wrong. Instead of allocating 3x512 bytes it's now only
> > allocating 512 bytes, so we get OOB below with this change. 'expect'
> > is a pointer to a 3-dimensional array of 512-char arrays (matching
> > observed.lines).
> 
> Why did running the kunit test not trip over this? :(
> 
> Hmpf, getting arrays allocated without an explicit cast seems to be
> impossible. How about this:
> 
> 
> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> index 056fa859ad9a..ae758150ccb9 100644
> --- a/kernel/kcsan/kcsan_test.c
> +++ b/kernel/kcsan/kcsan_test.c
> @@ -168,7 +168,7 @@ static bool __report_matches(const struct expect_report *r)
>  	if (!report_available())
>  		return false;
>  
> -	expect = kmalloc_obj(*expect);
> +	expect = (typeof(expect))kmalloc_obj(observed.lines);
>  	if (WARN_ON(!expect))
>  		return false;

Or:

	expect = kmalloc_objs(*observed.lines, ARRAY_SIZE(observed.lines));

I think the quoted cast is probably better...

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202602241440.1D885B8%40keescook.
