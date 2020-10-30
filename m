Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBO765X6AKGQEPTEIKJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1340229FBA0
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 03:49:32 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id u207sf688677wmu.4
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 19:49:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604026171; cv=pass;
        d=google.com; s=arc-20160816;
        b=PAhpDrrnajR145qqmC2+DrwKpAukEk4Ca1B7h0CSOaQW0OfmZXr+p9AaQjt1hhysKF
         AXJfiwL92UuxLTW75hVkwB+p6hiTWHWCmuNsNMOa+uAFBj2TfzR+fsN5HIFSmAuXwYO1
         d7cd9PMHyrGGIdAlWiKdIs0aq4TynRdrA/EChQTl1KpZwz4mmMT/TC352OuhetR4bcuf
         0tIVs7WfjNP7q0OE/gzrymHyAkq8CtfeiCpCNkrmI2lSzWS7+N5SA+hLTd2xwUiaSUha
         46hbHo3QC4ZH/hVIxzu+aPWUYIah/RSnPpnkOXWPHO6TJ0Qu4v3ZIiMfRJ/ri6ohUlpU
         /4ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ai0/4Oyo1S0g+ugfFZNW/70Zectdhr3fbxROitJjZcs=;
        b=Gb00btVB17bUKBBy29vLuqZCWKd3JNZmYety/rajGrVEE3sJ49mjZDy1G8rUF8PTwX
         0hkGtX2M3gVvbYr7E+kPkcO2bTBXJs6xutdsg+QseH1C5PQC9wZc1s1FJiwqPYqRuB0l
         xsnx5VIlm8K3m4N1UMTNuZGweBM6/D1qyMn1Kor+sit1DssrxtnJUDz2x7I6OCWbpgqv
         zopoCgxy2fAxLkD2E0gEetaQp5XF4zT1gT+V4wljPJWhwLW4vZR+dt8qhQqhRzF1Oj+d
         PyC4FIVfGuPT5GKzyxJbr5s2qhBxCBSPtalGwGuho3YyZcnc2VegJ3XiILkZ9VybkSed
         xpNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZzFLUcJs;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ai0/4Oyo1S0g+ugfFZNW/70Zectdhr3fbxROitJjZcs=;
        b=C808TX1TCc8VxXkUew0PPjSFfUa3ss66F8TBJv2bIFK3bjH9mPwmFiiFoxrBEfm+nm
         Vbyja/tzuoUeNiyNRQrzOxjsITi3qvnDJDAEZj0ElRvcqHeOCl3ANqmqKOTJbuxUiHMG
         YzwOhgwWSM4qYHSbz5GY5syANvIDwCQbxpYuS9gk6BlqRxffpEif5QG92xlul0TwY1jU
         4mZl1HsvW6rZOay0gyxSZHwr8KZQn0d9DdBXZIqU3n/fzRIpq+RCpYFiDEXBQxluSXp5
         4cezU3NLmob9mzu4WBfKwBuBNdXTCmQuXAu3h4W3uOaTIJTQTykImkL79eSkT4ULNi7C
         s8HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ai0/4Oyo1S0g+ugfFZNW/70Zectdhr3fbxROitJjZcs=;
        b=c3LrvUL/ZT5+DNMFMjpsd0ROJrLNb8SJyhMf2jAeQLDI1hrc458Avqk/wEX63Sf7Te
         3lxWvHGY9q/tbWM3fAgPus+nviCQcL8jTnK14dCsK93JW3ZGPpWGdujx14FcA2iuqcR5
         7BiabFtuiKpoUOt1iN+soaaoScTdosZx0gkllp5TmqSVora2fX4uXTMZw2TczN1dDx9p
         NHUL4ZQ/IpG3SfSJSgfG3jSA9es3Fl5o1MzKatru4WGS+i4zfa+rIwsR4W80mNQ9KSvD
         xt3IL1gA7a8KW1grsH1YVr+N2kwT3VxXZ5rzl12zURZWvWXjJ8t+I2GwU5gtZMhsAdsQ
         MLKQ==
X-Gm-Message-State: AOAM5305V/AUOlcymkEqYUbikANvAa2K41V2s8fdt/FClqjgMasa5rUC
	8xnQIXPXIzaz3ZsjxE3ZqCE=
X-Google-Smtp-Source: ABdhPJxQUu6Xk7eFq5bn6XMzw/B5+ObPLaVDJhWUHOKYynsQ4MKFrHGXPhEwJRpWkSu/oXV1diKD8g==
X-Received: by 2002:adf:deca:: with SMTP id i10mr195211wrn.96.1604026171835;
        Thu, 29 Oct 2020 19:49:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:3d87:: with SMTP id k129ls863774wma.3.gmail; Thu, 29 Oct
 2020 19:49:31 -0700 (PDT)
X-Received: by 2002:a1c:4306:: with SMTP id q6mr38455wma.189.1604026171030;
        Thu, 29 Oct 2020 19:49:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604026171; cv=none;
        d=google.com; s=arc-20160816;
        b=lzfhre64wAvhMxhMeccGSAAo/9oNGWjsfExhkD+7ILHBoJZVsDr+V4BPrQv7sO3muY
         nDBSK1sPi4E+npwPEOI7zLpwtYbqQDZf4f4L1kHc+ckDaAoBNDqEIh3VBSaQ1jxztiR5
         ZL9NDKI9jRcrYqgiotVnExhlBpWgLdIhiTUPXvpFicnBFigUJ3NHCvZCR4IqTKm2AMTj
         kOJmRqNMvE7abOJs5ZtIoUlB1IguJnVnThrpdjsVDPuLgZ3Fj0boTfIZLKqMRWHqjz3f
         ByWrlGm7NC5qWm5r4fthO/JsZTSvnpZpcaHhX8TWmmlPkTosA+ITiXvQlDuOmKlaHpvH
         XaWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fnNcEaVlmZ1zwBSm6iv/h6d4SZP4svNibhnGn9WMLZQ=;
        b=pW7dE6ZnP2rwULi3o3cdA/M/sOkVhjdkaDjLJqleAIpEt8XKnO+R2LsUMs36/7asBL
         HnN4djDwHzcL2eS0ELQUZ0LiSDC7iGdgQOmobrllU7+HtF31IOwsERtz6FZ+V6jBLs0A
         YyaBAOPAKfLtDtD7vp/+GEGI7oqetdrzbp823xspJueWIsOlb/uBZzTFaipIa7V8CUU8
         lgFIFXhrHG1MF/tnrk/afTQyd8+90uqa3prYE7Tmj+p0DhnOhm2wvobRfy3VxzlUpwpQ
         h7yglKFRtGcRPqjI+Bhs9sf7DGRQHOIfk/htvqFdI92U1cvtC4y+IWJILwrJ/7T24VzT
         xnhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZzFLUcJs;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x244.google.com (mail-lj1-x244.google.com. [2a00:1450:4864:20::244])
        by gmr-mx.google.com with ESMTPS id y14si162718wrq.0.2020.10.29.19.49.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 19:49:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::244 as permitted sender) client-ip=2a00:1450:4864:20::244;
Received: by mail-lj1-x244.google.com with SMTP id d25so5308133ljc.11
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 19:49:31 -0700 (PDT)
X-Received: by 2002:a2e:9a17:: with SMTP id o23mr110783lji.242.1604026170432;
 Thu, 29 Oct 2020 19:49:30 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com>
In-Reply-To: <20201029131649.182037-1-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 03:49:04 +0100
Message-ID: <CAG48ez1xg0uRV6LqYOO-ibVqOO7jNRJGLVLrQfGW=s8TcbPGoQ@mail.gmail.com>
Subject: Re: [PATCH v6 0/9] KFENCE: A low-overhead sampling-based memory
 safety error detector
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, joern@purestorage.com, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZzFLUcJs;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::244 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Thu, Oct 29, 2020 at 2:16 PM Marco Elver <elver@google.com> wrote:
> This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> low-overhead sampling-based memory safety error detector of heap
> use-after-free, invalid-free, and out-of-bounds access errors.  This
> series enables KFENCE for the x86 and arm64 architectures, and adds
> KFENCE hooks to the SLAB and SLUB allocators.

I think this is getting close to a good state, just a couple minor issues left.

Now that the magic "embed the memory pool in the BSS section" stuff is
gone, this series looks fairly straightforward.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez1xg0uRV6LqYOO-ibVqOO7jNRJGLVLrQfGW%3Ds8TcbPGoQ%40mail.gmail.com.
