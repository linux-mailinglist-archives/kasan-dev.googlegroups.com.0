Return-Path: <kasan-dev+bncBCV5TUXXRUIBBK7JXHTQKGQEET7EEKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 824322DC50
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 14:01:47 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id j17sf880420wrn.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 05:01:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559131307; cv=pass;
        d=google.com; s=arc-20160816;
        b=reLiUEjthHEq5X+bcuKYU1r8rXSYth6FX85Ocx5OHyAcofc/mk5ahLrXngN9V5FRyK
         B8lme7dIle6C36MzFIdYgR5Wpeb1SZ3B/PCuQBejKywpj9GJYjKIWeGOPESUAAQp/NvL
         q7FBFyhg19uMuQGkkaxaqBWZ16oqniWWLrBMCVS0OcScvNnjPPqZjO24vkyoYZNSDKhW
         8SuhRbM957KTTOqwHZZdG7e6uhn2SqXKQtYJ0Rnnn8WR2Bzrku3PAlg+b+3eWwmk0wVl
         J2nMUt5y1fEtgpSlYJxoq6uLt9WeZkwba1NP5Xrotdgyp/mf6JjnvlcGrrdiBXJt0b0B
         Royg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=y2mwoZToxNRtgRTrcU47K/6EXJvh33vGbAjV/P2Wk0E=;
        b=dlb/eKLg/yD/tz9ojaJMENYLbbDjbYyPyxo6j+BvC6DLGuS4IUPeQxcmkoJxOelK1q
         Ys2/IbVFywc0/w9lh9Dy0JNhjz6iPKkwJmNWVgYtryxiyhGwWpjCAW0eCCvymrxYM6q1
         BBByRtJpqoftSfbPUGyj6XSKfKsNg/3uKWctjg3ymKcpS8q8vPT9S7nTQHHYWfShp26i
         ekXwKjpFt2DCw28Bgl3UCJ57I+vIio6CmcXM7/DGgn0Adlry+GoRc6dtTE9AcGcJskn1
         BeANXh1uxXRrFdpyLL5bEN2X+0JFvmXpe/6hTvSOM4UkXL/o3dLW2l0SULTj+H72c2kd
         3Cxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="Pp+auo/B";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=y2mwoZToxNRtgRTrcU47K/6EXJvh33vGbAjV/P2Wk0E=;
        b=GQyzbqmQr2eezrZh/uFmjreA0Rqco2LoYUewXhbwqpl8lMPQTa5EySluyaROLrdTd9
         khqMQgLUGoFW6XK9XSrEobhvqaM2edBPiKMp0uV/c7QogxJhGWSQbOuP48t4dr88gVN2
         E1rqIGh+vlhbPM+SUOHonwyxzrF3yv0EQFfYHGzavvKaTHDRtbmhpX06UZxAx5SKDcZR
         SKXQycngi6Fqcv4JDRQ57Ju0YMFNUOFg2ll0wLuuoxFVTS2VHQMy+VhpAYUo+rmXRwp+
         ZGmr5BBqsyKwIx/VSGVGmitt4BR4GaGfR/yFbX5RlC8mxY6cYe5KnnQQs4KI2Y6u5Irs
         8HXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=y2mwoZToxNRtgRTrcU47K/6EXJvh33vGbAjV/P2Wk0E=;
        b=fDuRMOdGvC+qGDm/ycpSTZrkHV1UL6Zyz+RGAJoiA3ecxwI+exOw+O5RTEpUIBEG59
         c1p5id6M/M5TgmO2f1D3A/Av6u5b5pM2Lqe/t4rFE+q9mUA9NRAMh7jTv8+uyCjniwev
         IF6xKVxeaJ13EnMYpkP1H56tiQ5nAgJwsvvtH5yzxTYGml2IUHcrjeI0xnudvwSGNPSB
         YbjfNSr73u5Jkim+t6xIZ1qOlWBIlz5K7IX4G56UNnwJJjzYO4OFdYSy4tmoXANvgs/s
         ACXnhOGs4gFDO+JwFDYs+59S7O7YiGKAvNw2JQSdKwT6ptmiuQ5j5nV4pl8KZeCjWTTl
         sx/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUzSEI/Pc+h82P9sXUDAQ02G2qvdRQPk9a5rN87aZgiSMvjBU0M
	7Ak9ifnbNBzGf1lnnbw9PRA=
X-Google-Smtp-Source: APXvYqwCcJYOxWZBbFsRJDac2yOvyEH3QOoltOWUPKInggz8Vm82MvvJtfr7XPlDP2tgKSxnE74+Fg==
X-Received: by 2002:a1c:305:: with SMTP id 5mr1482353wmd.101.1559131307243;
        Wed, 29 May 2019 05:01:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2203:: with SMTP id z3ls594926wml.5.gmail; Wed, 29
 May 2019 05:01:46 -0700 (PDT)
X-Received: by 2002:a1c:cb49:: with SMTP id b70mr7110514wmg.80.1559131306642;
        Wed, 29 May 2019 05:01:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559131306; cv=none;
        d=google.com; s=arc-20160816;
        b=Do+FnRPDDB1p1K/5OCOT0PuQi2sz5mO5WkNKxORv4vaDXOAJsZUcCkpjzfgQMy1Ylt
         8+Bm7Ic7HJ+cYLs2X+qh53/fPbdHvLLuIquOUHBWDT7fPDMiKJuIoZA+XpfS/PpYko2J
         rh2/6PK0o0DTTglaHrUAqG/ahTDCVoI43NSbqRVKIf6bkiBZNTDo3gab0JTccP9OeRM1
         TjP1a6cHYRDF6A+T3xSLTEPU1E6WS2bQHJ6kW7Ze8DLq28EAdCLWcmj6OfXenXQfP2Tj
         1LWa5eTGyzZqpZHmU5wXGFteoWJFGq638F/j6S8jQ4qclb8DOVt8c6FLc+6DYMSz4jk7
         eyyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Z74YCGIX51kpVCW0eNEXPC/LPXMVSjCPWicAYebjk78=;
        b=ejr5XuBbWjkKOSHSM7m9NcThG2EQ51w/zAOcpfOlq8x/QaLHUN5DkjTVYE4XDzlaGc
         d+hldYez8/b4vtI3td48xysec5l5sxXkCGxaYpzwnb1GGh1lSZs2erTM1dCmCAeCL0bc
         TzLZoPrVnHqb3mHIeDew/CCDYaNLZymVTzlIbFPWgkYcXcs/OamxFJHDxHle7A1XNMFt
         UO2PjZgikT/rNdRy88DyQnM3zBPC+DdfMJa6oLAexzpAjpXwNf3cO5FpCR2xGUAjaM3j
         FwEEnTKhCTBlIiI090RLaUcGFRhf73mWZWbUdzzF+hRjVmlH61LBWSvx5qe6fNRVxF4u
         lVYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="Pp+auo/B";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id x4si226988wmk.1.2019.05.29.05.01.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 29 May 2019 05:01:46 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=hirez.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.90_1 #2 (Red Hat Linux))
	id 1hVxGy-00049Z-I3; Wed, 29 May 2019 12:01:36 +0000
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 2C456201DA657; Wed, 29 May 2019 14:01:34 +0200 (CEST)
Date: Wed, 29 May 2019 14:01:34 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	"H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>, Josh Poimboeuf <jpoimboe@redhat.com>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 3/3] asm-generic, x86: Add bitops instrumentation for
 KASAN
Message-ID: <20190529120134.GR2623@hirez.programming.kicks-ass.net>
References: <20190528163258.260144-3-elver@google.com>
 <20190528165036.GC28492@lakrids.cambridge.arm.com>
 <CACT4Y+bV0CczjRWgHQq3kvioLaaKgN+hnYEKCe5wkbdngrm+8g@mail.gmail.com>
 <CANpmjNNtjS3fUoQ_9FQqANYS2wuJZeFRNLZUq-ku=v62GEGTig@mail.gmail.com>
 <20190529100116.GM2623@hirez.programming.kicks-ass.net>
 <CANpmjNMvwAny54udYCHfBw1+aphrQmiiTJxqDq7q=h+6fvpO4w@mail.gmail.com>
 <20190529103010.GP2623@hirez.programming.kicks-ass.net>
 <CACT4Y+aVB3jK_M0-2D_QTq=nncVXTsNp77kjSwBwjqn-3hAJmA@mail.gmail.com>
 <377465ba-3b31-31e7-0f9d-e0a5ab911ca4@virtuozzo.com>
 <CACT4Y+ZDmqqM6YW72Q-=kAurta5ctscLT5p=nQJ5y=82yVMq=w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+ZDmqqM6YW72Q-=kAurta5ctscLT5p=nQJ5y=82yVMq=w@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b="Pp+auo/B";
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

On Wed, May 29, 2019 at 01:29:51PM +0200, Dmitry Vyukov wrote:
> Thanks. I've filed https://bugzilla.kernel.org/show_bug.cgi?id=203751
> for checking alignment with all the points and references, so that
> it's not lost.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190529120134.GR2623%40hirez.programming.kicks-ass.net.
For more options, visit https://groups.google.com/d/optout.
