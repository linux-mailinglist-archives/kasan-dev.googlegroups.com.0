Return-Path: <kasan-dev+bncBDAZZCVNSYPBB2EKTL3AKGQEKOJPBOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CF5121DCE57
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 15:43:05 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id x10sf5306771ybx.8
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 06:43:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590068585; cv=pass;
        d=google.com; s=arc-20160816;
        b=cYOgpUTMxyEPJRt0YOg3ddIu+JORdS7iaFhgBIAM1qlOLpraPGZwUfAOB/zxtQRMm7
         RE9oCEO7pAlhHLmwFM+ONjY0V2gLhgXPBXNYOtJGrScAbPEtTeAyp5s4CrHhNIqjdhSM
         hh8C+2VM5Q0+yHZo08V1D3+j1YWlrS2TTC9XgC2Nkf1YkARa6nITEE7JuCLHU7jwW95u
         mV88H5uiu+QFQ+COC7Zw5Ot4xUTcqBsbDb7cpgbKvqXsGvRyQEV4ry3/cX1BnEXLgNhC
         O3z3QgbdjU5gTgGgQeBQMMKU+P+6I98fZhkKsnkDmnXC/7Y72V/X2NBUq1usuytEfBH/
         ZnMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=CX6T/IQz5sHYcDViN2Gcw3qJ4I0Ti4t0qWN+3oF6Kes=;
        b=G0sElhp0YS8kvwnVLrKdFJTS/r54gzuch/exbyyzPI9PkwUe91HplWLD7Gu8PCfB3t
         cxSvPg5O7jcYL3PWbfpuzi+hQXcnAj8SRnuJ+aRdu8bQI8bl0CLGrXkPGayzeJ0Jy+wd
         ZzJQii6gDRNHN4tATsL38WMSayX1ofxnmd0WemjAtrUYNkm064OugyhU4KvVNKf4uc5X
         d/8fn8lhllv2e22lw4o8L0/nVvJ4TgLRyn4v/HvgalxU08nPy5eMgRadl6zbfUshsJBC
         ZkPw/DXzf3fec7CtB9vzziI/oL3yV0TysGAe2QT1uEO/IW7Dvcd5D0plkw+3OynPvV6L
         JtNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ToaY+1My;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CX6T/IQz5sHYcDViN2Gcw3qJ4I0Ti4t0qWN+3oF6Kes=;
        b=IOReQfJXzgqUJ/xA2beLJN0OH0ynz4EcN5kbD8tsRWATnGkCwUqvJ2oUfynQKkLSWd
         yoxjxuhRp/7b4v8opZFj+PIYamLDULv7byobPx+y/gPjTGXz9kgwQWVYpukYDlhOuwRa
         hjpB/nBtGxMVXY+M5lNSp4eYBL0Tht911qHjPOsRqphbWqwClVlu2kh70cJRDTRhVv66
         1qSJzrppCLHPolRn0U98lws7dpybdQUJs86pTmLhUv1DGF++11bVbGprFp2ZucHWfx7o
         6WBNBWaaIG3aswwkJoUdMtjarBOKiCpY3pniEihsNTy0g9lBSyOyNHHkI1R6VwFQRw4a
         YJtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=CX6T/IQz5sHYcDViN2Gcw3qJ4I0Ti4t0qWN+3oF6Kes=;
        b=h1ic8CxMpJ/w8WvEnAorY2hvyd7z/f56ezv6tL1bZjNWnPuUmrlfLuq2P4yVeUx94C
         8pDaxki32iNy6+qLxfNNU1y/wESAxmuJ+rgbfEeaER6HUXPmf+L8g+pHIALT8BY0DLD9
         stY78ZBb/TAvYlH5Pk7kjCX6lLc4C1kLvljAZdgbTZ8RGDUm0vq7hUdWqw+L20TshnDJ
         j0NMDQ0T89gBtKZUsvaf9xcHKXXOefcIagyewxzB9wHjJXpnUCy+EU8c61KWNVESDLxk
         LuUOSprfomHKWErc/+SxTR1hJlV38Oart8v48vMuCj+HYZX7U3il4VtixVQU+jb6766O
         R64w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530gITghII/E6NfMaCOxI+GPfYZpD3SkhFJIF59Vh1WiTQHz7qzc
	NfYiIo4WR5nDoBySDGY0YWc=
X-Google-Smtp-Source: ABdhPJwi/ap0JPl2oO2vVpVRxZb2t7bMSSovGj2t1T8SWo4i3FTJR880s5uwdlzXQldddKXX8EifSQ==
X-Received: by 2002:a25:9805:: with SMTP id a5mr10320782ybo.26.1590068584855;
        Thu, 21 May 2020 06:43:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6892:: with SMTP id d140ls765931ybc.3.gmail; Thu, 21 May
 2020 06:43:04 -0700 (PDT)
X-Received: by 2002:a25:f505:: with SMTP id a5mr15265347ybe.195.1590068584530;
        Thu, 21 May 2020 06:43:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590068584; cv=none;
        d=google.com; s=arc-20160816;
        b=ZC+Vbzr/Hj+FZ3qry+KpRiAIi47Nygcyd2yQyv/l5N/qb3iNRego08H3X4HxOB26uC
         jnDWgfEaJ4Tvu8fjpYTIcmHq5Ri7Dzk43xN4Ay5jZvsjkyXCsRDWE0M9+iXar5zcZygT
         aXF/CO7S1lc+SKAX1O4OhDgBdm+V8/Aav1umOdx+NkiKf94e6ZbfW5Xg1Qz8r+qn9+ul
         qtwCisUGYVPELKYfJU12wt9Al/xcM5KVjuUG+TLzPxM0orG17+oiA94PWIKGvNXd79D3
         STrdfMQ8GtFJgIfBRjVTHQWj6zP5mP8YoOM/t/vefPlHsoWyfgSRxHy21CdPTLFlIqXO
         a0DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=0V1aLxnC9b6nqBNZK6HTyYbgl3Uy19QD2eqD+7FzkYg=;
        b=J0LrnIyowpPNabjQAfnEhL1ruINTEADX7YonvdtWRBYLLzu5G/cLDvC3tJh2rieQQg
         h9qbBMReAzdA5Bqq+XTcPbLhSQmVLXzhHtLKi4AbcmGGiALedwyWCzpoHEMv8EUkz7Ni
         PVGW9iBOCQQqezFVDk34CSo29lUo+vPKlsX/c8pabEMKqGne+4Co07otESChPxp4tr5E
         pqKPUMNr6SbVPX0Q8aYhQlog9Zyb3gYg8dAqW2KofBkQw03VD+4AlSdkwRcRe2vNBrog
         ooQ021AQOw7aTvRJCmi49oLYAlVO1nLwMznF79Os2jApc58K8pjq/+d1/qfHFPSgONZo
         NPpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ToaY+1My;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a83si478633yba.1.2020.05.21.06.43.04
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 May 2020 06:43:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 938BB2072C;
	Thu, 21 May 2020 13:43:01 +0000 (UTC)
Date: Thu, 21 May 2020 14:42:58 +0100
From: Will Deacon <will@kernel.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	Borislav Petkov <bp@alien8.de>
Subject: Re: [PATCH -tip v2 00/11] Fix KCSAN for new ONCE (require Clang 11)
Message-ID: <20200521134257.GE6608@willie-the-truck>
References: <20200521110854.114437-1-elver@google.com>
 <20200521133626.GD6608@willie-the-truck>
 <CANpmjNMf7JRG4P1Ab2qsCy4Yw6vw2WC7yCgqUSBBOsBQdc_5bQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMf7JRG4P1Ab2qsCy4Yw6vw2WC7yCgqUSBBOsBQdc_5bQ@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ToaY+1My;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, May 21, 2020 at 03:42:12PM +0200, Marco Elver wrote:
> On Thu, 21 May 2020 at 15:36, Will Deacon <will@kernel.org> wrote:
> >
> > On Thu, May 21, 2020 at 01:08:43PM +0200, Marco Elver wrote:
> > > This patch series is the conclusion to [1], where we determined that due
> > > to various interactions with no_sanitize attributes and the new
> > > {READ,WRITE}_ONCE(), KCSAN will require Clang 11 or later. Other
> > > sanitizers are largely untouched, and only KCSAN now has a hard
> > > dependency on Clang 11. To test, a recent Clang development version will
> > > suffice [2]. While a little inconvenient for now, it is hoped that in
> > > future we may be able to fix GCC and re-enable GCC support.
> > >
> > > The patch "kcsan: Restrict supported compilers" contains a detailed list
> > > of requirements that led to this decision.
> > >
> > > Most of the patches are related to KCSAN, however, the first patch also
> > > includes an UBSAN related fix and is a dependency for the remaining
> > > ones. The last 2 patches clean up the attributes by moving them to the
> > > right place, and fix KASAN's way of defining __no_kasan_or_inline,
> > > making it consistent with KCSAN.
> > >
> > > The series has been tested by running kcsan-test several times and
> > > completed successfully.
> >
> > I've left a few minor comments, but the only one that probably needs a bit
> > of thought is using data_race() with const non-scalar expressions, since I
> > think that's now prohibited by these changes. We don't have too many
> > data_race() users yet, so probably not a big deal, but worth bearing in
> > mind.
> 
> If you don't mind, I'll do a v3 with that fixed.

Works for me, thanks.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521134257.GE6608%40willie-the-truck.
