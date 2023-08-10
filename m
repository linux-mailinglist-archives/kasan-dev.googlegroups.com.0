Return-Path: <kasan-dev+bncBCF5XGNWYQBRBEUJ2WTAMGQEX55T7AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E393E7781F7
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Aug 2023 22:12:03 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-63d1bd6dfebsf17220626d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Aug 2023 13:12:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691698323; cv=pass;
        d=google.com; s=arc-20160816;
        b=YzTJGYqeNojJu5Uvme58YRkFESMEThYfgLnUh9oT+geD5tltWQ6k89/jAILoRrueWu
         iWAeJyAtHyJzQO73qnfJEeHClbQ3kAUprYpW/rFQq8zwzJAj+nPP39qaadQMx4va8ifo
         C++HgZS8eUozVDSibDZW8j6b5GFX7i+HxL+ySWmclICmCZCAxvEjwmre8suV1KnuHV+b
         bO6g/DLUlWWgIz+TyqaoiJ6GIQFOxKschHgIU0RNss2oxrZa5wDW6y8YJ/QTCHprDesC
         89puZAj4HhvbwTEZXMzoTY4fMAEEP4k3pntDSBjC+nHXFqqyvJocyZ5AB0oMWTHE+QL3
         OakQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=g08yDwAlRDzJHr2Wc7TA1aKUgFUy91NQtZEb5Y9cGCM=;
        fh=P4dVSS+vj9+CVfUXmAlYMPhh81xLnb2BjH39mxrHU+g=;
        b=WszsAqFKwm8MeH5oiORaUN5UkHfbwrRgx65YXDEoUryLp2jG2zy8nSPOJt668bskLB
         t1jSdaYF3tmp8V4/DU0go8vnoeXtmRf+2KvqbzXVq4FUEO8ABErqYxG5cwIiYJkKW1Q5
         r+i73lIfnIqL4gzL3th94JGaYnqjNDrsDB+FTX9kUGGEd5NDGDZy6XErOMVdXHi/qVgR
         32LTxqqUXliCXch66mCz2a/znjMFm3ba2K2IRTIeRFnkU4tYEzf/EfyT9Xwe0nrsSJ1L
         iogY7qkQ1RZP9b1sEuEZZuzP30MXPh8uSIPVgArKvQLCoc/htHtGKwHfZ//d2eR20aUY
         /UNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=fyUQ4xBf;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691698323; x=1692303123;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g08yDwAlRDzJHr2Wc7TA1aKUgFUy91NQtZEb5Y9cGCM=;
        b=MlywgR3pd57o7KXFNpwtgTJBG8HimtiUY9Woh7IIiwg2qYav95zDbTT7uTn9T/OLi/
         Uq4DI43tg2yR4x9+KSvGx7LYsn2EX2aN2dh1uEf9UV0PqfK0DHUKO7x4gdfb8diYU/mU
         okultJS+TH/q2yRIUsqqqSsBF6h0CvH/eKYqE1k2SlWYxRifE0ueeSnJp8/nOkXt3HwJ
         AbNScO05P4UeQoYXiFmv+M82wHjbhNW2v9jHGWafNxcKG9fPylwN80IharudAz7UVluY
         0tepaBRyhYdDqXvfo6wopT2+x6/bQ/cPHFmcuH3o5dOS7icfREMU9khsZ0XAk09/lkMG
         ktkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691698323; x=1692303123;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g08yDwAlRDzJHr2Wc7TA1aKUgFUy91NQtZEb5Y9cGCM=;
        b=DCNQHeFPhSmSCI/LKe0Lg9LHdMagiP/c1gBfZRlpDtJJZZ4kKWR0bazkIiWmVtWl8A
         Rl+josdlsP2p93bF4PKe6rP/wKA0McM9qIQ3V71KAyAr9p0LeyMI6nTRthj/r/CrlQ4R
         SRxDMnRwhVtUO3c76E8rzLtKPVwfgIhbhTS5HLRiWhGS8JOajJBwRSrsWrKXfisgzK9z
         aFvIFz+8FPqsbyxaPPsPLMc7NGAwirouiwM/c6hvhTs5Oiwr1vQB2RPPwa/p+qiciBKM
         v8SbAQ+Ha4GNSWJv7l9712LalYpaH3stkMjN+1j9z5nXIVNT7iLnQMESmwYJ6lF9fFbx
         QVMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzhsXJcqOssRmPtZs6c3dQK/AOX5Im+7FTMSUcf3dbMiJaS5e53
	/X0A0P06yWR1qP35vP9XRv8=
X-Google-Smtp-Source: AGHT+IEKJ7lt4SQWoCG2HxpLk/cBRZ2PtB3skBAOoSIK8eB6XFAXnDoEJVwievhq+o+ebDhjYJzYZg==
X-Received: by 2002:a0c:e40f:0:b0:63f:7a94:8797 with SMTP id o15-20020a0ce40f000000b0063f7a948797mr3249601qvl.46.1691698322663;
        Thu, 10 Aug 2023 13:12:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f1cc:0:b0:63d:218c:2e31 with SMTP id u12-20020a0cf1cc000000b0063d218c2e31ls1647654qvl.0.-pod-prod-09-us;
 Thu, 10 Aug 2023 13:12:01 -0700 (PDT)
X-Received: by 2002:a05:6102:3bca:b0:443:7935:6eb5 with SMTP id a10-20020a0561023bca00b0044379356eb5mr2822755vsv.15.1691698321628;
        Thu, 10 Aug 2023 13:12:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691698321; cv=none;
        d=google.com; s=arc-20160816;
        b=GaQ2IapTBJtZhENPb0s33FyFZMliq5WRy2b8GXoI+jvgXX1k2YOANOZdYWThvHEetu
         AJsCJiqFIFTKc0jbM2A80giztc/KxMWiLc42t4PsziofNGs4sAS8C+qqTOnQCpNPEvCr
         vidAD9sa56ks5XuJvTkHxdn+rR6VWsnWlWI1CCZF4N7x2yOuw7n8fnjoJiFm552cSibr
         PZiWWhe72e1R0UL1cEbA5QVqG/WNCtEKbyq5WXtUIL6AWdvyNxX5Uqv6YxpGjfd0ixTX
         F+4poL/NbVdpWYhE1VQNuV7dvODfR/CDXGIS8KPxUUuwE3orPczKKvnnPcMs2jAj5o1e
         IpPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=YgXTJGJNIG5brUNilbYvmAufJFTfjCt86nj6wBgTVtw=;
        fh=P4dVSS+vj9+CVfUXmAlYMPhh81xLnb2BjH39mxrHU+g=;
        b=UM2JW63lSjCDdwQfAZlefxf+Z50N4tx7nM4sEsj1WmPlh5TTNF98CexaTq3YDUy/ZK
         nIrhYqECBBUXk6xPNnN1fPwRraoUMnPi0IrsZnEXN/pArisyZKt4bCu+v4+1Dvo1y1fd
         YQ35u0dEqE/wG5dsqXWHtbCblu0EKTa9vHFi3uLtfWQRrw3rUSA54s6Tm1ji6yd6FTt/
         U+KMbQA4xzkpNqI9fvu371SRLyKKHRqP0IsC1aVAYHupSWxlad10cKn2QQOh7GvCwdkF
         XEtgCQO8I422eZEY8oMMA9dqDZR2vC3nv0de3Fv61xL6arKOVdUCgLvFR8yUWRQ0eeYT
         Dqcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=fyUQ4xBf;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id dc25-20020a056102559900b00447ddfb3cafsi266467vsb.1.2023.08.10.13.12.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Aug 2023 13:12:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id 41be03b00d2f7-54290603887so889459a12.1
        for <kasan-dev@googlegroups.com>; Thu, 10 Aug 2023 13:12:01 -0700 (PDT)
X-Received: by 2002:a17:90a:5d91:b0:262:f09c:e73d with SMTP id t17-20020a17090a5d9100b00262f09ce73dmr2794613pji.34.1691698320688;
        Thu, 10 Aug 2023 13:12:00 -0700 (PDT)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id 5-20020a17090a1a4500b00263f446d432sm4004127pjl.43.2023.08.10.13.11.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Aug 2023 13:11:59 -0700 (PDT)
Date: Thu, 10 Aug 2023 13:11:58 -0700
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Guenter Roeck <linux@roeck-us.net>,
	Peter Zijlstra <peterz@infradead.org>,
	Mark Rutland <mark.rutland@arm.com>, Marc Zyngier <maz@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	James Morse <james.morse@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Tom Rix <trix@redhat.com>, Miguel Ojeda <ojeda@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev,
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v3 3/3] list_debug: Introduce CONFIG_DEBUG_LIST_MINIMAL
Message-ID: <202308101259.D2C4C72F8@keescook>
References: <20230808102049.465864-1-elver@google.com>
 <20230808102049.465864-3-elver@google.com>
 <202308081424.1DC7AA4AE3@keescook>
 <CANpmjNM3rc8ih7wvFc2GLuMDLpWcdA8uWfut-5tOajqtVG952A@mail.gmail.com>
 <ZNNi/4L1mD8XPNix@elver.google.com>
 <20230809113021.63e5ef66@gandalf.local.home>
 <ZNO/pf/pH5jJAZI0@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZNO/pf/pH5jJAZI0@elver.google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=fyUQ4xBf;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52d
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, Aug 09, 2023 at 06:32:37PM +0200, Marco Elver wrote:
> On Wed, Aug 09, 2023 at 11:30AM -0400, Steven Rostedt wrote:
> [...]
> > 
> > I would actually prefer DEBUG_LIST to select HARDEN_LIST and not the other
> > way around. It logically doesn't make sense that HARDEN_LIST would select
> > DEBUG_LIST. That is, I could by default want HARDEN_LIST always on, but not
> > DEBUG_LIST (because who knows, it may add other features I don't want). But
> > then, I may have stumbled over something and want more info, and enable
> > DEBUG_LIST (while still having HARDEN_LIST) enabled.
> > 
> > I think you are looking at this from an implementation perspective and not
> > the normal developer one.
> > 
> [...]
> > 
> > That is, if DEBUG_LIST is enabled, we always call the
> > __list_add_valid_or_report(), but if only HARDEN_LIST is enabled, then we
> > do the shortcut.
> 
> Good point - I think this is better. See below tentative v4.
> 
> Kees: Does that also look more like what you had in mind?

Yeah, this looks good. My only nit would be a naming one. All the
other hardening features are named "HARDENED", but perhaps the "ED"
is redundant in the others. Still, consistency seems nicer. What do you
think of CONFIG_LIST_HARDENED ? (The modern trend for Kconfig naming tends
to keep the subsystem name first and then apply optional elements after.)

One note: do the LKDTM list hardening tests still pass? i.e.
CORRUPT_LIST_ADD
CORRUPT_LIST_DEL

> [...]
> +		/*
> +		 * With the hardening version, elide checking if next and prev
> +		 * are NULL, LIST_POISON1 or LIST_POISON2, since the immediate
> +		 * dereference of them below would result in a fault.
> +		 */
> +		if (likely(prev->next == entry && next->prev == entry))
> +			return true;

I'm not super excited about skipping those checks, since they are
values that can be reached through kernel list management confusion. If
an attacker is using a system where the zero-page has been mapped
and is accessible (i.e. lacking SMAP etc), then attacks could still
be constructed. However, I do recognize this chain of exploitation
prerequisites is getting rather long, so probably this is a reasonable
trade off on modern systems.

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202308101259.D2C4C72F8%40keescook.
