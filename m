Return-Path: <kasan-dev+bncBDV37XP3XYDRBY6NWXTQKGQERU7NOSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1699C2CCA0
	for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2019 18:50:44 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id r48sf33929541eda.11
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2019 09:50:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559062243; cv=pass;
        d=google.com; s=arc-20160816;
        b=mo03rGPNDTKVu7QQCu/Ryrw8sRAWlzuw+dmqcpL6UNEIK4mk/aujndygDdsAzPcXKt
         L33PP6/kSSTj16WyZMk7Czrf67mIWZL0oMLwpy25Do8zpjUOHD170hMAQh5QPCRJHDST
         zD5oPK/sX23cgh7PTzqVim8sejlEzU4H0N7xpfzlLxJc96HIbFH356eErhhPkal+rk8A
         jNDR2LzoeDwZXs4X9DWFBbLAhzZB9TLeV+59ARhCbKzwQsgk7L/VNDCgCSqSPWokhecH
         2IP3XXtceeNysdp2hnUBx4aJavd/iDos56R2l7ygiAAFj0XTtVgyujYlgSjoKbhoSFOf
         ScVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=XHzEx7w7s/cxdXTVmFf1LUNFi88QM96oF409eK5RCI0=;
        b=m8wPMNQzeU3ES9QcF1rZ+I4tdspkY+PtlzUjabOZWIPFG1Uozy9UozmDkpd6C+ZDmq
         M1r8Awsn4WvgJ0458NLFqaclok+a7rT6E25lgy15oZQGvbOpf6p0yXW7rJ/03Dlz2O46
         6svyrsMgKU349k8ejsJPmkOB0BWsOaLjwnBYv49rBCe3pCvmg4s871Dr6sWKly7II4D9
         sbysVQX0qYuMbecKqTIT8PbdwBriEiEP4FRFp8wu2tRYXnFUXIe/ehp9Z90zBLQjnDPi
         UrjhqWV1zmwFAiTjFc1ZXXtFz3jVx2kV7FSPHol8ZZRzwTP/gd0FxX8mfh8FOKKvzcIY
         Qdkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XHzEx7w7s/cxdXTVmFf1LUNFi88QM96oF409eK5RCI0=;
        b=EszBOjPGGhOfZuPFoH7T0qQkpaq1vXJq4Vh4KKOELNub2ZiqZyPcH9fFzNvgx2RfpB
         VtLTNAuNJZIETnmYBO9+/Kb5bBHavwrXyEJ7GIrqKAi+zo1LWjZhDod0kdZ0zDC1j0GR
         Mk6XgHvGasf9/9ypHb3EITjbbTXDLkEiYVTKdFZWvw9vcU6xBlGf8pMKbDXZ76WmHlih
         oc4Jmn5xb66zit8vcYsyRRc5315Fkwte5dEp68S/COdXPfe2uESL1YwRv4LU0f34VuhF
         zzrfnku7oVGz+9crQmvMtltXZBtYwkSIjry3oGOyjpaBvf95dsmGFZUNowrCB9G+IlGG
         9oBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XHzEx7w7s/cxdXTVmFf1LUNFi88QM96oF409eK5RCI0=;
        b=NERi0/1/uq7ks0KHKHwQZqlx3m+qCTVLYj2rSC+NWzmHfleGbtyPyhGWJCHd1wSR2W
         9XMsw4AiA5YSb6ai555WJS0h+jqqUibtDnHrdzoQ8bm0l5YPScEHLtAwYYWsvN4RzceV
         1KfxjmmqBd75BkGmI77UNY7zZq32XpT6HSdh/6x2vIdV1qdfexIlnamktjoWyOF7he+e
         5G1raWYL4l/PODUfyepRddUC4eUWYOFOaWXu5tBjXaIHOWgugRpk6rr7062EUIWR7v6f
         zjHrQvVDQeo/420xpiRQ6hyYyDfwXtMFdPOA3BZVQlioTbOy9/5g3S4cD44a1xHrcQyK
         Zp2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUISs91SJny3lQCgV9d8rTFX8G14T3DU+VFP1nl68kQ9ak/OfpA
	9EZuouf1E0VJeC7y+bwNvQo=
X-Google-Smtp-Source: APXvYqzt5nwJi2tjWI+I0QY57LvWW/oSuHPlwbyYs+DsedYTSLssXwdz3IsmI1zDKOJbjv/Ddkvh9Q==
X-Received: by 2002:a17:906:7cb:: with SMTP id m11mr20475687ejc.311.1559062243802;
        Tue, 28 May 2019 09:50:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:4ac7:: with SMTP id u7ls803380ejt.8.gmail; Tue, 28
 May 2019 09:50:43 -0700 (PDT)
X-Received: by 2002:a17:906:6c8:: with SMTP id v8mr42031927ejb.14.1559062243006;
        Tue, 28 May 2019 09:50:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559062243; cv=none;
        d=google.com; s=arc-20160816;
        b=IKLv2We7aOS4WiuFsVHt1GvQmmqe30NPBGvwn56lvKcOy4792ikgxCA1Tg8/bg7hGh
         vNyvCsK8xryuzIW62R1+rN/9KMKoo0oNlgxxtQJ+k1I65yr/hl1OQZ41Dh4OBbgOGCRI
         1tOkvHHSJWAx+Y86YJmI3oq5LGrgI1RTonJPZNXLyZCFrdBFNyGXQrw/hrGmnIVRVNBZ
         TBTWcFCOwCq25ba1fTh1jNWc7Et8xD7+NCgiYp/W5EYVcvRYLcdJH6tdqaPElDerV4Or
         oIWOfq+CHQEyhvnQgYImQg2IhUpDIU8y5BYrd8YSiy06uk5Oo+IonMGRLbxGj+1JtVGN
         dRYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Lh6HbvtQGHu8McWklzgX0xrByNhgbXJW78b3kvmV5uE=;
        b=vv+vuRH/uiJQRyaMGAviNgBd/dhPx+S2m63uQOXr1HZL/pBvh4ZC2YqMGOHO23tp5N
         /6nGC9swgjpG1njHgKhwbeg0xA0f3Y2uIiWfvlGA5HxSN4U25/eloKXcWrvdRKkMQz6u
         IJBxKRsz2CVS5WXaNwRxctqcYmgMunBgcF+VpkVcNlU+3ol8iGq8B4oerms1iOF3FyTI
         t/XvcSDErTCJgYP+NFehG9iPspXwYwJc1UsKtaPZs30kyEnAkymRc0iVPvTFdmistmjj
         7B0YFSj84kyqOpeH8gftosfblLVsaaKmwhoBjOX3GTsqTINdrs8qGeFTW+fX+EASP83H
         nJzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.101.70])
        by gmr-mx.google.com with ESMTP id f42si935440edf.2.2019.05.28.09.50.42
        for <kasan-dev@googlegroups.com>;
        Tue, 28 May 2019 09:50:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) client-ip=217.140.101.70;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.72.51.249])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 27DBB341;
	Tue, 28 May 2019 09:50:42 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.72.51.249])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 3200F3F59C;
	Tue, 28 May 2019 09:50:39 -0700 (PDT)
Date: Tue, 28 May 2019 17:50:36 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com,
	glider@google.com, andreyknvl@google.com, corbet@lwn.net,
	tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, hpa@zytor.com,
	x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 3/3] asm-generic, x86: Add bitops instrumentation for
 KASAN
Message-ID: <20190528165036.GC28492@lakrids.cambridge.arm.com>
References: <20190528163258.260144-1-elver@google.com>
 <20190528163258.260144-3-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190528163258.260144-3-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Tue, May 28, 2019 at 06:32:58PM +0200, Marco Elver wrote:
> This adds a new header to asm-generic to allow optionally instrumenting
> architecture-specific asm implementations of bitops.
> 
> This change includes the required change for x86 as reference and
> changes the kernel API doc to point to bitops-instrumented.h instead.
> Rationale: the functions in x86's bitops.h are no longer the kernel API
> functions, but instead the arch_ prefixed functions, which are then
> instrumented via bitops-instrumented.h.
> 
> Other architectures can similarly add support for asm implementations of
> bitops.
> 
> The documentation text has been copied/moved, and *no* changes to it
> have been made in this patch.
> 
> Tested: using lib/test_kasan with bitops tests (pre-requisite patch).
> 
> Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=198439
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  Documentation/core-api/kernel-api.rst     |   2 +-
>  arch/x86/include/asm/bitops.h             | 210 ++++----------
>  include/asm-generic/bitops-instrumented.h | 327 ++++++++++++++++++++++
>  3 files changed, 380 insertions(+), 159 deletions(-)
>  create mode 100644 include/asm-generic/bitops-instrumented.h

[...]

> +#if !defined(BITOPS_INSTRUMENT_RANGE)
> +/*
> + * This may be defined by an arch's bitops.h, in case bitops do not operate on
> + * single bytes only. The default version here is conservative and assumes that
> + * bitops operate only on the byte with the target bit.
> + */
> +#define BITOPS_INSTRUMENT_RANGE(addr, nr)                                  \
> +	(const volatile char *)(addr) + ((nr) / BITS_PER_BYTE), 1
> +#endif

I was under the impression that logically, all the bitops operated on
the entire long the bit happend to be contained in, so checking the
entire long would make more sense to me.

FWIW, arm64's atomic bit ops are all implemented atop of atomic_long_*
functions, which are instrumented, and always checks at the granularity
of a long. I haven't seen splats from that when fuzzing with Syzkaller.

Are you seeing bugs without this?

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190528165036.GC28492%40lakrids.cambridge.arm.com.
For more options, visit https://groups.google.com/d/optout.
