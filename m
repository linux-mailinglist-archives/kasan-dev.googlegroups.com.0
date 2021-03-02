Return-Path: <kasan-dev+bncBDV37XP3XYDRBWFG7CAQMGQEVIX7ZXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id C16733299E7
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 11:28:41 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id 130sf4222507qkm.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Mar 2021 02:28:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614680920; cv=pass;
        d=google.com; s=arc-20160816;
        b=Us0ilxaWBb+61027YNuxJlCQDkUCmi5zPJ4c5b3zyXz2wbGDzUbjVjHS01A5i9Suvj
         AneH4jYdN6nPG59niAPVR4Yrns9tem/Yyn88TIDcJgI7a6mG9EVvYn3bfCcpV7NIleAy
         i84RYgjsS9DQ5i08yC0543wWMSJ4ph6N1lHSGQcd4vq9lIVFn87N4Lse91XS1uz91rwY
         aOCj0a0vtzFn+vg6k1mJDxl0FggHGlb3nxqV5YMwrma9fgCrPenk5y44pcRG0rw3jgAA
         4FwkFk8tfkwKMwqpcnNMKMVu6vkCz4UhWa6ueDlq1lTnVAYBCdBMhwCvKwxLJ5TiRhLU
         hF6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=My5XhWc4QQME8tEYF3vJvy/GkQ3ZBzoABwC99OwFr7g=;
        b=IPUpkl/uTnXAJ2pUmr+NNSA7IMedUIVRgfhUFuZoS9iejw4t6U/k5cMIJd/FpI+Kb6
         dp7duEo8B34yOShciAJ5l3EWPKMPUSld88jXHvbng9evJ5q/pUPcBunN2OkyK/n8Jtsw
         psbMxVIMMKJy7YRIxfDnmw2sXqWGfvItMTfSNWL0We63dhEOcZCDpjWmbk6B7RUw4Gsg
         JkQRCe86OieoxYdAZXlcxWVg9/YdvPpW1AHrQbubZhGSpciVjYL7STIkBVL9oBc5kV2A
         FurTobr3R63hkaqyJEgTnH/17wOAtW1q+7tHMmNq136/q/tNmFfCe/jnb053xxhfVLY/
         K3jQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=My5XhWc4QQME8tEYF3vJvy/GkQ3ZBzoABwC99OwFr7g=;
        b=PDnZFDyJbLhJ2S8kG2ANlhdSE0kCGtAsiuGDVo/BXqNtYKgVl5ixf6JCiO62wZfdym
         ae6zbhYWXb0i1hpaP9pmqXmUJW8qI3PxOrH7qyk1+ssSmDN0zEbKHQ/BdGlYFT+dMK1X
         FjwRyxkcpwweIi/5YL3YUpG8y7czP8DOUwHoqYBGa+eQUVn4/Xcl+KwlzlGcQXEnmM3a
         z8uktJOEZlDUeyU7OX3uPzX5dxjHr6vPIXbnV5M5zqcO3SWrD36zN8OxLfgsks1F0O4+
         /Vi7q+JoxCq2GvWPZGwG2kbw/qZp9XiHOyLJUTcxKGqcmkPXHUBccgA3qFSw4vi4H4fo
         TTnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=My5XhWc4QQME8tEYF3vJvy/GkQ3ZBzoABwC99OwFr7g=;
        b=MZAMPv7wrOhxBwzJNTfVzp2iHnNHdl/KDyoci+o7A1k5PdHA45/SZ/AzTinQBWWH31
         SENQz7zmWqaSRJN0ag2Fy4lzeUIBwSyHEegH3A8jQdbBIcvgSXYuzDIWecsq26lqNMk3
         AGBNx8MQiVc4dsp7v7apG1tTFOA1Lu7M9GXKS38TDOvTIYxgtV8yG8uwqlxdOuSqedt3
         dHJIKnlsJKReTL3nFli35smR8TglhYKxeDfobA1ko4qOq+Z25+SNw581vXj0GmB2Bw6g
         +JjRt00+tEpSbN1nRY7/LDlI+mniyf2K2NwlgymuXs+Fl5iofS9MYkL2BRMdIZ/4ZqfG
         N+DA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Ot9bui1fCAH0EEdHGlygq6m7MXtONu+39EDFH08Oy06oUCr+j
	swD0q5l53pFwJBhX82HQCZQ=
X-Google-Smtp-Source: ABdhPJyNPXO4rPJK1Nu72OHxTul0bZdvGPm39crcpAQYjA/pmYRTHGwUwlMNMZjymJMZ/MW/24vwgA==
X-Received: by 2002:ac8:5a86:: with SMTP id c6mr8682995qtc.88.1614680920615;
        Tue, 02 Mar 2021 02:28:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:34c2:: with SMTP id x60ls3227089qtd.5.gmail; Tue, 02 Mar
 2021 02:28:40 -0800 (PST)
X-Received: by 2002:ac8:36b7:: with SMTP id a52mr18269350qtc.18.1614680920140;
        Tue, 02 Mar 2021 02:28:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614680920; cv=none;
        d=google.com; s=arc-20160816;
        b=k6IM3/O7Nq1sJ/VuO/DIJxUfd3lNL3LsNAphY2wI4HDJiB7ju8MIy0b46hXf5Ri2Qe
         WDL2vh8der9R3FSPKCX+UTMWzkR9qNNvAUJxlLvgFHy+qJDPFOKP2KMhM0E9D80A9+6x
         r5s1HiyW3UPV4XMU75YiYpL44Z+l2ibJYeM/7am/UjAEHYhOr06lJzmuFLaFmUAjsgtm
         Zeu18+b1UFGAp5rs0Vg6d4GN6+oBrMiU6iCHDTpPUx+GXfZQ5juInf3/i+Uk+GRWvy12
         aah8EMa3jcqZCVy1zAyJRCckhMTOZMeYBjtjsKhvz0Al2cVbG7PxoXB7zmgU8nSA8297
         umEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=Ig3TmQQTXfQmp21TNMzLZ/1jVH4oNNUAov+YAEmETnU=;
        b=hUZ/jprunNM8XjbKHmwnXNTTTHV2VJ0Sx0vfF12giWD2PXX0NpxmBJz/kWfMRNXqF8
         5DCjrgBN/wOBsXz7w39qk9CiLfjvqVsdj4f0IJYpHpz5GD88rwpH0Z1QRVNcUZ+jMzm/
         Jsj8so+/QTrrboL+utp+skJqL4ogjYsobto2/wzN5Nw70WaBoBatPs82RtYXArs65hZF
         zrBKpgD7LnIqZSzTNCnGOsjxfYHHpP0y4FYbjpmlLmJZvQK2X9tsOiY3i937qpYPKa2a
         S20PRZNQj2zR89H9EuVTDBGp60PlwBmJJ/sTAVm++nwslTXrAj5zcypDPWirFLcpntA4
         bi9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d29si643166qtc.5.2021.03.02.02.28.40
        for <kasan-dev@googlegroups.com>;
        Tue, 02 Mar 2021 02:28:40 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 643F4106F;
	Tue,  2 Mar 2021 02:28:39 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.50.217])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1DA3F3F73C;
	Tue,  2 Mar 2021 02:28:37 -0800 (PST)
Date: Tue, 2 Mar 2021 10:28:28 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: sgrover@codeaurora.org, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>
Subject: Re: KCSAN Support on ARM64 Kernel
Message-ID: <20210302102816.GA1589@C02TD0UTHF1T.local>
References: <000801d656bb$64aada40$2e008ec0$@codeaurora.org>
 <CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM=YGYn6SMY6HQ@mail.gmail.com>
 <20200710135747.GA29727@C02TD0UTHF1T.local>
 <CANpmjNNPL65y23Qz3pHHqqdQrkK6CqTDSsD+zO_3C0P0xjYXYw@mail.gmail.com>
 <20200710175300.GA31697@C02TD0UTHF1T.local>
 <20200727175854.GC68855@C02TD0UTHF1T.local>
 <CANpmjNOtVskyAh2Bi=iCBXJW6GOQWxXpGmMj9T8Q7qGB7Fm_Ag@mail.gmail.com>
 <000601d6909d$85b40100$911c0300$@codeaurora.org>
 <20200923114739.GA74273@C02TD0UTHF1T.local>
 <CANpmjNNk8MHXNsHdyWqcO1VxREv+LP0sxid9LZOy+2Pk8i9h+w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNk8MHXNsHdyWqcO1VxREv+LP0sxid9LZOy+2Pk8i9h+w@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Mar 01, 2021 at 02:09:43PM +0100, Marco Elver wrote:
> It's 2021, and I'd like to check if we have all the pieces in place
> for KCSAN support on arm64. While it might not be terribly urgent
> right now, I think we have all the blockers resolved.
> 
> On Wed, 23 Sept 2020 at 13:47, Mark Rutland <mark.rutland@arm.com> wrote:
> [...]
> > The main issues are:
> >
> > * Current builds of clang miscompile generated functions when BTI is
> >   enabled, leading to build-time warnings (and potentially runtime
> >   issues). I was hoping this was going to be fixed soon (and was
> >   originally going to wait for the clang 11 release), but this seems to
> >   be a larger structural issue with LLVM that we will have to workaround
> >   for the timebeing.
> >
> >   This needs some Makefile/Kconfig work to forbid the combination of BTI
> >   with any feature relying on compiler-generated functions, until clang
> >   handles this correctly.
> 
> I think https://reviews.llvm.org/D85649 fixed the BTI issue with
> Clang. Or was there something else missing?

I *think* so, but I haven't had a chance to go test with a recent clang
build. I see there's now as 11.1.0 build out on llvm.org, so I can try
to give that a spin in a bit, if no-one else does.

> > * KCSAN currently instruments some functions which are not safe to
> >   instrument (e.g. code used during code patching, exception entry),
> >   leading to crashes and hangs for common configurations (e.g. with LSE
> >   atomics). This has also highlisted some existing issues in this area
> >   (e.g. with other instrumentation).
> >
> >   I'm auditing and reworking code to address this, but I don't have a
> >   good enough patch series yet. I intend to post that prework after rc1,
> >   and hopefully the necessary bits are small enough that KCSAN can
> >   follow in the same merge window.

On this part, I know we still need to do a couple of things:

* Deal with instrumentation of early boot code. We need to set the
  per-cpu offset earlier, and might also need to mark more of this as
  noinstr.

  I'll go respin the per-cpu offset patch in a moment as that's trivial.

* Prevent instrumentation of the patching/alternatives code, which I saw
  blow up when instrumented. For KCSAN we can probably survive with a
  simple refactoring and marking a few things as noinstr, but there's a
  more general unsoundness problem here since the patching code calls
  code whihc can be instrumented or patched (e.g. bitops, cache
  maintenance, common ID register accessors), and making this watertight
  will require some more invasive rework that I hadn't quite figured
  out.

* I have a vague recollection that there was some problem with atomics,
  and that in some cases we'd need to use arch_atomic() rather than
  atomic(), but I can't remember whether that was to do with the
  patching code or elsewhere.

> [...]
> > > -----Original Message-----
> > > From: Marco Elver <elver@google.com>
> [...]
> > > Let's see which one comes first: BTI getting fixed with Clang; or mainlining GCC support [1] and having GCC 11 released.
> 
> If Clang still has issues, KCSAN works with GCC 11, which will be
> released this year.
> 
> Mark, was there anything else blocking?

I think it's just the bits above, but I haven't had the chance to look
at this actively for a short while, so there might be more issues that
have cropped up since I last looked.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210302102816.GA1589%40C02TD0UTHF1T.local.
