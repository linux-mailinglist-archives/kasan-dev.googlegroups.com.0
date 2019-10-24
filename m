Return-Path: <kasan-dev+bncBDV37XP3XYDRB25FY7WQKGQEBT6PFIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 55C18E37FA
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2019 18:35:56 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id l2sf3108646lfk.21
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2019 09:35:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571934956; cv=pass;
        d=google.com; s=arc-20160816;
        b=VLVCyMw9Dcmx6XZmxRGjv36Oq3StlyDWaUfL3YC2FjeUN5pwEmDTZXgygab/SM6kYg
         CK7GIpustlvFrIiXTT1wfBsZhnZkLXNTqOjCVwl2UDEK5GgsKn7/lHWde1iKs3lir9w4
         slbJV0vomXzkPBvoTUADxG/VSXNlscVeFhM71ZMmIzN3/Ra7nBEhlHRZmb7a/1xNzRYV
         ZjZg7Kow38UsY3B1ZUWXxHSx6LfsU/lEcNM4O4hfLuZIVYA4GOVlKzlqcA9GMJsL1Bu2
         vMJLH+7oxviDZeFRzodvd8GXaWUjW8CGGYWTZQ8zp5yjZ2RWXSTkWJ5vLlk+AeJlnhw5
         yQ+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=AHP8Ku/mXMBsSqvxGEiBAY1Wa4K65tOrJYigvxV2/dg=;
        b=PLdSUyDMh0GtDiZ1sGaEMonBiGakPOifIdcI6efjbJySN14WwVesYX4ONTOEU1dYHp
         kDbQ4M7rEDJgg/MgjnKMHIw4o7j7wCuFfUwdkom9X8QceXyoTnJIJZ4fvuJoXlJJbFfd
         s4p7pTekqZL7PLtjrfPaBRFhKA3e5vCeQsnJAXPpweB/iYh6tQ0dPAmAR2L7QgbJBuEE
         h18x7uLK/4eyfDwYzYMnUGs/FO69UppBH3Ieq1nudt02Ef6EsyeMfAK41Rg6geuf9mF8
         aYqPuIp6jIB+FFwfYGxqCOhXZLSCPKm7nx9sF9RejddgQkaDXrSwBfms3zGRVCZ3Zkrx
         sUjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AHP8Ku/mXMBsSqvxGEiBAY1Wa4K65tOrJYigvxV2/dg=;
        b=BpZ69+CxajDaIrnMZTz48ISaCini/NCaQqsSjqKmjvRFkvf3vAatbH85RPAQYgCSnK
         0HuxBSkSpEyxjAsWEuqhgOTE8M3oLgNDlz9YqeZ4dVoo4YUxRe6dCqyhxfQjVAZf4bcI
         YLxAWmS8ZY7OmScD3y2Jo8S4XsErISLrAZEZKubcT+8xFNsXOna8u9OVDxOQpeI5Yiko
         7dBbtpn9qrO4HMaxeqVqxw/iyFO+kgIyhnvGeadnKbd4VU3VoEaqS0aG3EpvOrJs+VYJ
         1lSMd/WTR9zKFPYw0JQxmGl7/1xZX7O3Ksf12T9p3QE6dpZNOPa8K5/SdHxfS8Xy38Q/
         6+Nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=AHP8Ku/mXMBsSqvxGEiBAY1Wa4K65tOrJYigvxV2/dg=;
        b=X9OHgKJ1c91JftvyAv2UD6GlulV3I3p8vmYTbL1YQ/gG2pbC+SZmRS+tqah+NeCnSk
         bpoVJRNnFjPKlR8qN4o3scBcLaZPJEYbUXm5RHJqGSRObfYb2CuAPedlpaiixdzmX7so
         K0e06CdFN3RTK5dcQ1YQkfwi/eP6TyVoFG9sgUXuVzWTs90ghj6cR1IbI+Z527HLBH7p
         4WnOKVbXovsekNPitYMZFV8tqI2BsaU0TZaLHD8iqQL/PKYc2nVQuEgAzOlp7XVgmgrX
         UJ2LbnL5YMEdZPkl6505WLGwlJLlYPtOki1edqqfgj+gvgPevkp9VBm/vFzwgy+Dh9BS
         3g4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUDdit0bXdT8oBftYKyNktNQSczylNcDpgF6wpMsVUgWBuAdU8q
	qgDP9vx8eGzD5rwtQ0+eMaw=
X-Google-Smtp-Source: APXvYqx1E0efvuNEyaqHNln/HtSaU1uamlXnljQez7P2rbGiy1NG9nsjSdjRvy8kP91kjm6MkTC7QQ==
X-Received: by 2002:a2e:81c7:: with SMTP id s7mr6416629ljg.40.1571934955899;
        Thu, 24 Oct 2019 09:35:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3101:: with SMTP id x1ls863289ljx.1.gmail; Thu, 24 Oct
 2019 09:35:55 -0700 (PDT)
X-Received: by 2002:a2e:b010:: with SMTP id y16mr27410633ljk.147.1571934955085;
        Thu, 24 Oct 2019 09:35:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571934955; cv=none;
        d=google.com; s=arc-20160816;
        b=lv3fjxY/95DbVXqV0CvHhfYH/Zb/4E0Fdzt6vUVPJgdQAvozHgvlNLPyi8s/1JWi6X
         NtqLjYpoa/eLCHIP7WdAUGERzy4nhpS55BUCwqg5lbV6eKCfoh2ww9QortuSudeRhrBi
         nGEPDSi1apZZ4K1vlKu9QuPwFy/+bSePxZiaXqeoDkSA5S9xLrYOBoeCKxQhj+9geNM3
         KLceiyjKrdQblgsVgzQCriT4/54iGPAgjo4DIrCz12lqI2Fszk5kOuxPapKkamlaLYO+
         Nts83ngJNGyeD6umUkiW6I9yYehwbDnbDWxRQWpzf+G/VQvCrE5BmnIM46B7QFvlhyH0
         E6uQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=SLG90vrRbLQUwAGkENlhgTDPP1LbndlcrswFZqOfJxA=;
        b=urU3emRfPAS5Vt3bGU3CBOXdtm1iw1V+EBDN92oHVJfeA3RQP1yFX9F6FHLpsHSEVG
         UJCrCA/Tck+8AtRZwyOYIQ06YOTdIFDXAfX+0DhBqMMm9sME4EbOu5BlGiBi0eS8aixt
         mkqn2RtWt+FcAKtEL2Jq+wfElAJSPPzLaXZlwQ5+tkTmgYBPxDOoIf8l0qAsbBu6+vHF
         zdwX+Q596hWpTNqWxGKH/mkYEc3QFSEaO7VROIPpCxg4PySxoa0ER+j+h/cLO3Cfk/1K
         YSPUROryZ3PeIZfLthX/uGeLVg96+pp6GdybRfc8sCHNquFpRJVrxP8OV1GSE1lW86AS
         lbxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id o30si1091690lfi.0.2019.10.24.09.35.54
        for <kasan-dev@googlegroups.com>;
        Thu, 24 Oct 2019 09:35:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7D418369;
	Thu, 24 Oct 2019 09:35:52 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 459D93F71F;
	Thu, 24 Oct 2019 09:35:48 -0700 (PDT)
Date: Thu, 24 Oct 2019 17:35:46 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	Alexander Potapenko <glider@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Arnd Bergmann <arnd@arndb.de>, Boqun Feng <boqun.feng@gmail.com>,
	Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>,
	Daniel Lustig <dlustig@nvidia.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Howells <dhowells@redhat.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	Jade Alglave <j.alglave@ucl.ac.uk>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Luc Maranget <luc.maranget@inria.fr>,
	Nicholas Piggin <npiggin@gmail.com>,
	"Paul E. McKenney" <paulmck@linux.ibm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	linux-efi@vger.kernel.org,
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	the arch/x86 maintainers <x86@kernel.org>
Subject: Re: [PATCH v2 4/8] seqlock, kcsan: Add annotations for KCSAN
Message-ID: <20191024163545.GI4300@lakrids.cambridge.arm.com>
References: <20191017141305.146193-1-elver@google.com>
 <20191017141305.146193-5-elver@google.com>
 <20191024122801.GD4300@lakrids.cambridge.arm.com>
 <CANpmjNPFkqOSEcEP475-NeeJnY5pZ44m+bEhtOs8E_xkRKr-TQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPFkqOSEcEP475-NeeJnY5pZ44m+bEhtOs8E_xkRKr-TQ@mail.gmail.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
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

On Thu, Oct 24, 2019 at 04:17:11PM +0200, Marco Elver wrote:
> On Thu, 24 Oct 2019 at 14:28, Mark Rutland <mark.rutland@arm.com> wrote:
> >
> > On Thu, Oct 17, 2019 at 04:13:01PM +0200, Marco Elver wrote:
> > > Since seqlocks in the Linux kernel do not require the use of marked
> > > atomic accesses in critical sections, we teach KCSAN to assume such
> > > accesses are atomic. KCSAN currently also pretends that writes to
> > > `sequence` are atomic, although currently plain writes are used (their
> > > corresponding reads are READ_ONCE).
> > >
> > > Further, to avoid false positives in the absence of clear ending of a
> > > seqlock reader critical section (only when using the raw interface),
> > > KCSAN assumes a fixed number of accesses after start of a seqlock
> > > critical section are atomic.
> >
> > Do we have many examples where there's not a clear end to a seqlock
> > sequence? Or are there just a handful?
> >
> > If there aren't that many, I wonder if we can make it mandatory to have
> > an explicit end, or to add some helper for those patterns so that we can
> > reliably hook them.
> 
> In an ideal world, all usage of seqlocks would be via seqlock_t, which
> follows a somewhat saner usage, where we already do normal begin/end
> markings -- with subtle exception to readers needing to be flat atomic
> regions, e.g. because usage like this:
> - fs/namespace.c:__legitimize_mnt - unbalanced read_seqretry
> - fs/dcache.c:d_walk - unbalanced need_seqretry
> 
> But anything directly accessing seqcount_t seems to be unpredictable.
> Filtering for usage of read_seqcount_retry not following 'do { .. }
> while (read_seqcount_retry(..));' (although even the ones in while
> loops aren't necessarily predictable):
> 
> $ git grep 'read_seqcount_retry' | grep -Ev 'seqlock.h|Doc|\* ' | grep
> -v 'while ('
> => about 1/3 of the total read_seqcount_retry usage.
> 
> Just looking at fs/namei.c, I would conclude that it'd be a pretty
> daunting task to prescribe and migrate to an interface that forces
> clear begin/end.
> 
> Which is why I concluded that for now, it is probably better to make
> KCSAN play well with the existing code.

Thanks for the detailed explanation, it's very helpful.

That all sounds reasonable to me -- could you fold some of that into the
commit message?

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191024163545.GI4300%40lakrids.cambridge.arm.com.
