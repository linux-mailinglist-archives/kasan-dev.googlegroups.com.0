Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQPW26TAMGQEPYOQCIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EA5277897A
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 11:11:31 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-4fe52cd62aasf1994883e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 02:11:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691745090; cv=pass;
        d=google.com; s=arc-20160816;
        b=A8MhPIWjjoiJLBjshldOZGI6pODlGRT4yJAQWlBxzVHLZPlHa0X/EaacZyIgNh86jn
         SgwKF0hmpNUKduJYMD8+1Fo5RIoZ6GSFVEFVIH5gBcjF79wb7UiDvxXB2r1p9t8u3LFE
         kiECDXiuqD+pkkv3i+2Y4G3N/bevvZOL3oajramD0voa4Kjc59ORpcf1KlrTHdn17bux
         XpIOxL+W5nT1FnqwF9jsOLJpJZon7NSgCnPgTuOtMd6Hh9l0cNhgsa4Dv6Do3XvzbiN/
         JVW3GupBVzoU9E5bA9w5tpa2r2G5mloFoXZgD9Vkfk3FicrPVpPQeRzL8gZo6xHxKX2W
         Meow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5fKpRXzytq/KXeCg+9TR53VlEdQTt80XuZExJgddxmM=;
        fh=vmdFMLKDZK/wu+BJofufY+1eGg6sPdOV1xSEm+/W2OE=;
        b=Ru/txjbI1ZV+Ogo+ryqGBhrXSLiSzkgyOjQhCyO6EBQquDzdXl8dl9sWp78V3C0PtK
         MmpG2QYIHUsFl+REOT2E3CIYvMTBgDUbAeJq9tOpM2nI7zcdLKME9uVX3rWyK6ozlb3z
         4kiWcVXLqD4NPODw7RAndAVO+iZ/J0LAODbDK7OCsnAE4NsuM2MUpZv6WxDPXKPts+DM
         C2HErhD67u2UB3B87gp9lZMK4zTKho42Op6eeTclE7AkeSgKhz4Tk4NcePIoK9jxU49z
         rA9y7Zk07wO2QLARQ5nSODvGVXcSLcC8wdsiIRzAYnrKu03rk80nF3N7lOAzsWm8QY+u
         ejdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=xOeEvMhu;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691745090; x=1692349890;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5fKpRXzytq/KXeCg+9TR53VlEdQTt80XuZExJgddxmM=;
        b=Nf42tJAtp/GmC0gxxMX2VjLP87xokJe87JTvWq1amyYw5bPTUm79v5UjWbxC+i0TV3
         Zne22YcWVbDIcOshf83H/BxWvkqMLGOlmS/bsv6JrEj9KRuVRbQaqendJzb8VwOPuDHT
         JrT749mf+6TqWThEG6tTH754GzKYpxJfae5fscAXRGfQGAnIf1mnMsgwKnazQ53OnAKZ
         aWYtVM8txC7CIr5Q91ez8f3hXDkIVoiBlUKBbZP8l3M8/TCOYYcbzUEJZF37RJNUg1Dz
         6gMbWSL8jYFuIjNpPDi3DQAxoT0FBVyh37EJTBiousak+dDiFj8GclyXhcSgOPgNgwMK
         hlAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691745090; x=1692349890;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5fKpRXzytq/KXeCg+9TR53VlEdQTt80XuZExJgddxmM=;
        b=VEVbmUHrk2YWbP329+f1q7bLNSgWS168Y0kvThxueoA1gZI2H28ia62fRHzTKuZpYe
         Q89SQBQXxEd5xWmdJ46q6OEAur8Rf17Am39lNXStHrJpPIvyBqT7ZM0CPHOY3xeecxOI
         aL9axZDpuqkz8Y4Ovdd+Kt3IQyvuvtbzioEQ3schIdswURdtdGPWyuTeZcFBKjvHHa0X
         Iq9ZuvlcO91TKYY/LHXba5hFGiZDzeu7gesnItuZpjxKn5cTppWdlGmwClQYG22Ah9y7
         Vp0lX4xhiPXdOu01Ijl8ARd3VXmIv+RvRQ4pI5V7UQB6LFkaIQP7QZw8srClOAaVpVLr
         Teyw==
X-Gm-Message-State: AOJu0YytEKHv1Zbx6bKEXBbNapfMGHBSUX1pXKs332WYUgv63JDxJabK
	bM0/fnTdZMdljPfor13ZBo8=
X-Google-Smtp-Source: AGHT+IFZ/RzUyUpa/6hw1aCfQGa2bhlNTNK1C8O7FN4Mfb4nCk1W+/yskRpuCR74f1ZT/nb3FLu/gQ==
X-Received: by 2002:a05:6512:329b:b0:4fd:f590:1ff7 with SMTP id p27-20020a056512329b00b004fdf5901ff7mr848512lfe.40.1691745089623;
        Fri, 11 Aug 2023 02:11:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:381b:0:b0:4fe:28f1:9bff with SMTP id f27-20020a19381b000000b004fe28f19bffls653674lfa.2.-pod-prod-07-eu;
 Fri, 11 Aug 2023 02:11:27 -0700 (PDT)
X-Received: by 2002:a2e:3e14:0:b0:2b9:54e1:6711 with SMTP id l20-20020a2e3e14000000b002b954e16711mr1070535lja.7.1691745087330;
        Fri, 11 Aug 2023 02:11:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691745087; cv=none;
        d=google.com; s=arc-20160816;
        b=m33HkvI+pbF7UrwqieH9CMDlsKrHMDeojewfn1Oi3q2TyuzCB102omXKploEl2kkm1
         uoXJux3fUnmJA0TAdh1QB+hrPGUpqCz8A5lwoOp5NIhMm1nzUEtCTPsFUga9eeSNxtsC
         YZC2v/ncf61QBRaCV/zx3BNnajJYpuPVdDZHZoRsHMxfhOcbaLbqOeD9ZK7jx/N0IM5B
         i6jxICY1ulLImHzKC3toZjPOgKArdJwHZFnaqNMg7V5wmIVfn6C51jcb4fdksXtm6Hh6
         4fXtduNTSjjI/yziKxAVaF8n0hybuC8s7S9o2A4JC3P/YeCYWl5foX1pQhZQvGoEyRMJ
         8gtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=msB7XSMQKNAACWPZ/GwjszE60e79zmFAGxGoY+G/BRc=;
        fh=LKaigW6kcaoBEobqMDAGmBYUOoG9ezBMyQ26msU14yY=;
        b=tzdilQt1VnbBdfk5LUVh1klwzvodGb+9DaTYrcbddmbdrNm+4J9yuj0dduUWClQZOW
         cKOI51DJPve0ih2t4wdIJRU4pJf1JrQrMBiFAGAr7hARIp7eN4XVREzVIQXTjxl9xJQY
         lksl1eOiaB4lHfylCW2X1qLgqhAcuZHMKLJ2HtYbGf+uo2ykQOhZIPYA9H7iEovy8X2/
         yyAyweYs9trpwmB304IM65lmjUuEAzrd4x0JhrMGFKMquISQIh+b/ASywRx/7iKZS31n
         zu5N8+EdEIrpAgnZuNqmFBuyjALKyedmIAWkiJYs7Xd9Cf+HpCuciGucngMK2QHACVGY
         mQcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=xOeEvMhu;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id j16-20020a05600c1c1000b003fc39e1582fsi373278wms.1.2023.08.11.02.11.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Aug 2023 02:11:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-3fe2ba3e260so16013515e9.2
        for <kasan-dev@googlegroups.com>; Fri, 11 Aug 2023 02:11:27 -0700 (PDT)
X-Received: by 2002:a7b:cbcc:0:b0:3fe:10d8:e7fa with SMTP id
 n12-20020a7bcbcc000000b003fe10d8e7famr1164390wmi.41.1691745086680; Fri, 11
 Aug 2023 02:11:26 -0700 (PDT)
MIME-Version: 1.0
References: <20230808102049.465864-1-elver@google.com> <20230808102049.465864-3-elver@google.com>
 <202308081424.1DC7AA4AE3@keescook> <CANpmjNM3rc8ih7wvFc2GLuMDLpWcdA8uWfut-5tOajqtVG952A@mail.gmail.com>
 <ZNNi/4L1mD8XPNix@elver.google.com> <20230809113021.63e5ef66@gandalf.local.home>
 <ZNO/pf/pH5jJAZI0@elver.google.com> <202308101259.D2C4C72F8@keescook>
In-Reply-To: <202308101259.D2C4C72F8@keescook>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Aug 2023 11:10:49 +0200
Message-ID: <CANpmjNN84DGUSutk1FxcVmPGDhgVa2PrOuFTzGYu92mv+WXUeQ@mail.gmail.com>
Subject: Re: [PATCH v3 3/3] list_debug: Introduce CONFIG_DEBUG_LIST_MINIMAL
To: Kees Cook <keescook@chromium.org>
Cc: Steven Rostedt <rostedt@goodmis.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Guenter Roeck <linux@roeck-us.net>, Peter Zijlstra <peterz@infradead.org>, 
	Mark Rutland <mark.rutland@arm.com>, Marc Zyngier <maz@kernel.org>, 
	Oliver Upton <oliver.upton@linux.dev>, James Morse <james.morse@arm.com>, 
	Suzuki K Poulose <suzuki.poulose@arm.com>, Zenghui Yu <yuzenghui@huawei.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Sami Tolvanen <samitolvanen@google.com>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=xOeEvMhu;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as
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

On Thu, 10 Aug 2023 at 22:12, Kees Cook <keescook@chromium.org> wrote:
>
> On Wed, Aug 09, 2023 at 06:32:37PM +0200, Marco Elver wrote:
> > On Wed, Aug 09, 2023 at 11:30AM -0400, Steven Rostedt wrote:
> > [...]
> > >
> > > I would actually prefer DEBUG_LIST to select HARDEN_LIST and not the other
> > > way around. It logically doesn't make sense that HARDEN_LIST would select
> > > DEBUG_LIST. That is, I could by default want HARDEN_LIST always on, but not
> > > DEBUG_LIST (because who knows, it may add other features I don't want). But
> > > then, I may have stumbled over something and want more info, and enable
> > > DEBUG_LIST (while still having HARDEN_LIST) enabled.
> > >
> > > I think you are looking at this from an implementation perspective and not
> > > the normal developer one.
> > >
> > [...]
> > >
> > > That is, if DEBUG_LIST is enabled, we always call the
> > > __list_add_valid_or_report(), but if only HARDEN_LIST is enabled, then we
> > > do the shortcut.
> >
> > Good point - I think this is better. See below tentative v4.
> >
> > Kees: Does that also look more like what you had in mind?
>
> Yeah, this looks good. My only nit would be a naming one. All the
> other hardening features are named "HARDENED", but perhaps the "ED"
> is redundant in the others. Still, consistency seems nicer. What do you
> think of CONFIG_LIST_HARDENED ? (The modern trend for Kconfig naming tends
> to keep the subsystem name first and then apply optional elements after.)

Naming is a bit all over. :-/
I agree with the <subsystem>_<suboption> scheme, generally. I think
initially I tried to keep the name shorter, and also find a good
counter-part to DEBUG_<suboption>, therefore HARDEN_LIST.

Let's just change it to CONFIG_LIST_HARDENED, given the existing
"HARDENED" options.

I don't have a strong preference.

> One note: do the LKDTM list hardening tests still pass? i.e.
> CORRUPT_LIST_ADD
> CORRUPT_LIST_DEL

Yes, they do. Though I need to also adjust BUG_ON_DATA_CORRUPTION to
select LIST_HARDENED, and the test should check for the new option
(which is implied by DEBUG_LIST now). There will be an additional
patch to adjust that.

> > [...]
> > +             /*
> > +              * With the hardening version, elide checking if next and prev
> > +              * are NULL, LIST_POISON1 or LIST_POISON2, since the immediate
> > +              * dereference of them below would result in a fault.
> > +              */
> > +             if (likely(prev->next == entry && next->prev == entry))
> > +                     return true;
>
> I'm not super excited about skipping those checks, since they are
> values that can be reached through kernel list management confusion. If
> an attacker is using a system where the zero-page has been mapped
> and is accessible (i.e. lacking SMAP etc), then attacks could still
> be constructed. However, I do recognize this chain of exploitation
> prerequisites is getting rather long, so probably this is a reasonable
> trade off on modern systems.

Sure, it's a trade-off for systems which do have the bare minimum of
modern hardware security features.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN84DGUSutk1FxcVmPGDhgVa2PrOuFTzGYu92mv%2BWXUeQ%40mail.gmail.com.
