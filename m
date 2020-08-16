Return-Path: <kasan-dev+bncBDLOR25HUUDBBJFA434QKGQEJY727AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id C61EB245969
	for <lists+kasan-dev@lfdr.de>; Sun, 16 Aug 2020 21:59:32 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id o10sf5851272wrs.21
        for <lists+kasan-dev@lfdr.de>; Sun, 16 Aug 2020 12:59:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597607972; cv=pass;
        d=google.com; s=arc-20160816;
        b=TYsuQhtVu84D6gDi1t7Rwo9GM1DJuc2JPUhAV1i1Ovyc5yRri0wO6509A25/bjC2zl
         F7LbJEt2V5Ev8H9f35KZNumz40ArFYef+l4CM1xT3YA3w8kP1FEHH/HfaZoIX6qhQSmh
         s4xEcf8cbBQiPDR/wl1gPgMA0bGpgORaLRA+DDk1ExOKHXf6pF0iyHG5xM1fn9x5NIK1
         i9GrdsXRp9K/4tjtpoe4fCPJ4r14uEj3zrKh0a/7DvSqK7hY27HuWJL7q9hnV/lOC6Xq
         zwl6ERRzrgiNjF4OrGvFy5XWrwWKRfpmiFLVm1Y6xeC544BYW7IGYicVYgeaP9GWTcGm
         zgEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=QwP+TS64ikPnEoz8wNRE+A8Ea3riPEewfaNrgP3aar8=;
        b=TRJqfcd3Cu31rcBUAMad2tek+RWTx7eEy+ohlUx/np5R51Fc80HNOMpI/IxpYzQcKx
         4GIwn/jS4Z8hW2EYvidimxy6Vo9bCtpwxCqKnXXa19/KnogblF9YjaCOUGe4684nQsBQ
         rUDDll8a85GCNO/P1cWR8Ng/kU2s8b6HFK+sK+ptHstH+oTke4sfuMNlZdWivpTP3tIj
         EXnYf+ROU4tBCFI3mCAIgKm/c1ph1d7XW6Urg405daD7mXIF13IRBJ02RWksmmj0Hkwr
         3yQBh37rPPKf2yeqgjOnhIptS0Wf3C+tmj4w6MsluGIrnd9uETrFJnMFAcRRiBCR2jcS
         +E0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of pavel@ucw.cz designates 46.255.230.98 as permitted sender) smtp.mailfrom=pavel@ucw.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QwP+TS64ikPnEoz8wNRE+A8Ea3riPEewfaNrgP3aar8=;
        b=FqVr5+ncQd4svCMjBKY5SawDJxdP1FU1ScoB6fb55fxyZdEHpz6HBvsqgjPk5mX/Gy
         E0j1YYOp9kw65HnKToGt64K5GJozaNMzIfIetpEWc8Rfbm3nSmeLX6SsbKgAIGpEYtED
         QYWW4rWQwia+10WTQ9evdeBA5Tta/+riorVchgfSwwBYR1MnsTal3MTuogCVUZkAuJuW
         O2CKoyH3T7saCE4I2tW9XPgDZz53JG160mCLUIJddPRwJAbjNYPXYxVCaJATAxma1RPQ
         oHu5nPVWVDKryOckRqG7wJVJ+a9Emh5acdnUdzyYnltzPfzq8uAhI4GROA6Su/peiMpv
         oNag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QwP+TS64ikPnEoz8wNRE+A8Ea3riPEewfaNrgP3aar8=;
        b=Tqt+u30vypqF1TCGz50LD5s+aKHZ+Fvd3xnC0eu2hUkn4GWaNsOKWJEHlnkA2riY7H
         rML0w6F+B543/4m1CFHGJQKdUncZFJVf4az3HpOZ0G9Z6Xs8rHHMANnUPWR6ZEcrdGKE
         gUMfNiBT1/dWHTciC1Jxc8v/C8EO/xpXP0y0cADlSyM9REc93wV0Jl13mplhK1kLVZAP
         EwOp2TiYQNt6IhCxNthT/x9PJfXepbn8EyU7m6aOpUOGWTW9xVxRcJIoOouePCku1OTW
         3xtkzbpXT4GgbdFN1Wngiw/kazu2lDgdyur3ffaG7m558VLew8HAqQzOjOHNNobgzzwJ
         DVnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331RyRoNOBZ8/wTLerXItrX3c2Grarmwoq1R6UAlDgPQKzMD2Yk
	AEzR+UvxUY4zdZgBq9edniQ=
X-Google-Smtp-Source: ABdhPJxDdVAovlGEvgJwqCRK6v6Z+f5DeXZ+sRVBAM/hPiam9i9vtOcG3SKhr5tt/M03Hq2aojbPnw==
X-Received: by 2002:a1c:493:: with SMTP id 141mr12383851wme.131.1597607972466;
        Sun, 16 Aug 2020 12:59:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2356:: with SMTP id j83ls6580898wmj.1.canary-gmail; Sun,
 16 Aug 2020 12:59:31 -0700 (PDT)
X-Received: by 2002:a05:600c:2888:: with SMTP id g8mr12252917wmd.118.1597607971868;
        Sun, 16 Aug 2020 12:59:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597607971; cv=none;
        d=google.com; s=arc-20160816;
        b=KKE6AQOhci5NMPImGBGMjeRvXaP8dAHpEzoqZt688ItCb6ZclvcKErtB+n5seu+bLF
         37zZHTjUojIJTCkntw8vU93qgVc+gAxGMZbDfDd/S0pYUOnpvYDdOCA2jpeA/pN9/1PP
         LCxDG/0SLbrqxJ9SaXS+zKl1Ql9wK6ge6PYyHlhKnnYdmsvuOvA4lpL69weyzSpJp+w4
         0xIb9562gErL6DWDJGkvEuz+L8pCtYqEOb+9XIXXh01Y2x4hNEWi3SSkaegUGQe7yIEG
         PrI6UX/D6ngLSmzL40Em2pf+yne/fnn+NM5fnNNPawLUnbW6dw+kA1vVxOVLPEyE8Gtq
         XDKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=jE/Jl64BOvgj9LP7xJg6xC/9wBN72Wf035OYAvVL8lM=;
        b=GuUHU6n+ow7oZaNesoNyqv9TLx3hGGbNFo/QyG52zD5XdiqTIJB+sD5S9Dpa/FTVIc
         AfpFQ12iiJBFO+n0hXt6lkVclT6CLAvX+Jy0u4oHcvZew90/F5DG2J90BKPnbvvQ1099
         1af1zXk1rOpgcsYOJrlMAaSNKu34biNZg7S6D++vv1MOYPecTX/i7QX+mpX/nVHgWBfW
         Cv7Eeh4TkPf7MHBtcbIMnGpmBlBPLyEoOZbmwrrpc04FRJsrGYD9OlIv5LBSfkrVzxls
         ulZtZE3bcsYAQpIv5l9/URQz2NsBpgiwga5f+R1Bs28l1xwRTP5XHeVPhgCKtGDG6oSQ
         TALg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of pavel@ucw.cz designates 46.255.230.98 as permitted sender) smtp.mailfrom=pavel@ucw.cz
Received: from jabberwock.ucw.cz (jabberwock.ucw.cz. [46.255.230.98])
        by gmr-mx.google.com with ESMTPS id y12si521806wrt.1.2020.08.16.12.59.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 16 Aug 2020 12:59:31 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of pavel@ucw.cz designates 46.255.230.98 as permitted sender) client-ip=46.255.230.98;
Received: by jabberwock.ucw.cz (Postfix, from userid 1017)
	id 4D4C71C0BB6; Sun, 16 Aug 2020 21:59:31 +0200 (CEST)
Date: Sun, 16 Aug 2020 21:59:30 +0200
From: Pavel Machek <pavel@denx.de>
To: Matthew Wilcox <willy@infradead.org>
Cc: Alexander Popov <alex.popov@linux.com>,
	Kees Cook <keescook@chromium.org>, Jann Horn <jannh@google.com>,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Patrick Bellasi <patrick.bellasi@arm.com>,
	David Howells <dhowells@redhat.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Laura Abbott <labbott@redhat.com>, Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	kernel-hardening@lists.openwall.com, linux-kernel@vger.kernel.org,
	notify@kernel.org
Subject: Re: [PATCH RFC 1/2] mm: Extract SLAB_QUARANTINE from KASAN
Message-ID: <20200816195930.GA4155@amd>
References: <20200813151922.1093791-1-alex.popov@linux.com>
 <20200813151922.1093791-2-alex.popov@linux.com>
 <20200815185455.GB17456@casper.infradead.org>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha1;
	protocol="application/pgp-signature"; boundary="cNdxnHkX5QqsyA0e"
Content-Disposition: inline
In-Reply-To: <20200815185455.GB17456@casper.infradead.org>
User-Agent: Mutt/1.5.23 (2014-03-12)
X-Original-Sender: pavel@denx.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of pavel@ucw.cz designates
 46.255.230.98 as permitted sender) smtp.mailfrom=pavel@ucw.cz
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


--cNdxnHkX5QqsyA0e
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Sat 2020-08-15 19:54:55, Matthew Wilcox wrote:
> On Thu, Aug 13, 2020 at 06:19:21PM +0300, Alexander Popov wrote:
> > +config SLAB_QUARANTINE
> > +	bool "Enable slab freelist quarantine"
> > +	depends on !KASAN && (SLAB || SLUB)
> > +	help
> > +	  Enable slab freelist quarantine to break heap spraying technique
> > +	  used for exploiting use-after-free vulnerabilities in the kernel
> > +	  code. If this feature is enabled, freed allocations are stored
> > +	  in the quarantine and can't be instantly reallocated and
> > +	  overwritten by the exploit performing heap spraying.
> > +	  This feature is a part of KASAN functionality.
> 
> After this patch, it isn't part of KASAN any more ;-)
> 
> The way this is written is a bit too low level.  Let's write it in terms
> that people who don't know the guts of the slab allocator or security
> terminology can understand:
> 
> 	  Delay reuse of freed slab objects.  This makes some security
> 	  exploits harder to execute.  It reduces performance slightly
> 	  as objects will be cache cold by the time they are reallocated,
> 	  and it costs a small amount of memory.

Written this way, it invites questions:

Does it introduce any new deadlocks in near out-of-memory situations?

Best regards,
									Pavel
-- 
(english) http://www.livejournal.com/~pavelmachek
(cesky, pictures) http://atrey.karlin.mff.cuni.cz/~pavel/picture/horses/blog.html

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200816195930.GA4155%40amd.

--cNdxnHkX5QqsyA0e
Content-Type: application/pgp-signature; name="signature.asc"
Content-Description: Digital signature

-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1

iEYEARECAAYFAl85kCIACgkQMOfwapXb+vLxYwCfbn811vr0Zj6oofab9u8xfms5
WYIAnjboCM2RGhT/UoknoFiLV5GpOKEC
=c5uZ
-----END PGP SIGNATURE-----

--cNdxnHkX5QqsyA0e--
