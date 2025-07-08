Return-Path: <kasan-dev+bncBD7I3CGX5IPRBU6EWTBQMGQE542PHTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DF29AFCC73
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jul 2025 15:51:18 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-450de98b28esf25707935e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Jul 2025 06:51:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751982677; cv=pass;
        d=google.com; s=arc-20240605;
        b=RcS0HWBXUSdwPPWwcWvWR9rVpufz7jwtOnoEi3XoQY+SV1IhWuIFSwk2w6qTtDreLW
         fTxdWYaX3agE/JcLnkgQ3T4s9dSEeJIOpZOqE5Vp2qN69VsUvDhyKWuQp4qaXaBdwbbP
         5EzezLQuiG+IxPMUHvYKKlm2ii1VVMmUnX9bJPM7lfgKuhSF36oYz8OWjoLk7liouZF5
         JP/f4OtQLwTfGJgSGnKBXmhNK6tYNQ2piEXtZwLpUbPcOWSQ9xH+lDiAatLhLAd6dtPN
         AFVH8N3nBwriZi9hR4+Cw2SvH9RJYmAdThnRtUa5jDv2ityLf/kXbRy4PYRRvOH1Wg5x
         cqxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender
         :dkim-signature;
        bh=siSKEq3DLdYaS7G/5uDVIvfqm/nOYoNltH3+qM2nJpI=;
        fh=gKKnG4EKxfJdoY490b5Hqwp+vkrtRlekK3Ak4y61Su0=;
        b=ewDz0L+raniEiWxZQCLWwYyABCogJfn1WPrBH9w5o2d7s9ymbjN+CY74Zmd2wdyY1c
         bDUhCTsuJh/mbVfFvWl4qcbbiA/xhvh93P/EyIrGG8B8Q9ZXGcEqYLkkUG4QlxGXkyQg
         Jetjxl7Aik2b9WuCdRACZBxZ4AM6Mqqj1W/0xyhFjjuoWV5/Euix55SrxKPrbJdHtKsV
         ixZm3mSkbfNrGRhS81bqKomWaZTVeIw/3mJGV2yLa7LsbpKWszNjshPWtXjlGeHJ4SLl
         opP2X6L5YFVZAG9b+0oFgGkeNXvXw/qA18M2eT5nsN1Su3j7g78Vtevb6QG64+A75m/3
         metA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=JjscOaZE;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751982677; x=1752587477; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=siSKEq3DLdYaS7G/5uDVIvfqm/nOYoNltH3+qM2nJpI=;
        b=jjAlX5nZp4xXZZ8iU9c1Cll5M2A+eyPCCrv/MAvp1DZc02o1nsxIJ4LUK/qok+EEWU
         TmnnVsTfuuIpo0OLMYgXgsTK+85O/AzsWG68oZkCoWyCcI21B+MiHRvQalXwU5GVFn+g
         0SCkzHF89TUX1osX2zC78EZjEsHTGNFC3zCA/d1fgmlXlk4J0c4tUzMtdFuWbsyY5wZC
         sV8lw1r8A1J1yG6b/PxnDiUVaFLtHwEgVgj9zODM/nqxTAlHSmaN8pA67NQlBKgHH+rL
         f3VYg+o3/8iEM6oujG0i7bLSnOsM9ywzKYjTVvxk8BPigmjZioggn6gmVrIZmz5/btUy
         GWMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751982677; x=1752587477;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:date:references:in-reply-to:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=siSKEq3DLdYaS7G/5uDVIvfqm/nOYoNltH3+qM2nJpI=;
        b=a1rGMt2zbk7YMJvPJ9JMf8gxGIUUjFwAFYzwnKbVuy8bN6Bqq/UNe8rEvzoyIz2FPA
         lZcytt/kKbeALkj9EeWlG3lYqEAiR7vpDLiXoYCTqbecFzqZutUG0AnRVDiSA49lbAes
         I0YfDAaQ9Nm03a+2/l1C1Ip9qUKNkpk7KNNaq5D5mtY95TsxAgvZtw9GV+6KpVBc75Cx
         Dl00k7gYv764w8ehB9mMQPcEnlMDYluoxIwezWlSIEAP6a8lT2j6RYZL1zAVKQCMyqxt
         HvUI7yjJxXk7LSeYKbsoYviZNTrj4PP3HryOJqPIdBMBLxXk/FOfTCYuF+6k3WbM9URu
         1PmA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVbpkn+PMFUdzUMPcQqfZhJ+ge1iuHjeguj0HsTqGQVhqLj5dglRIpctrrgrWzgwluAGey3DQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz+afEhj2rHdDy845M7mN/CayyxwRFAD7oIRKB+hsQc/R9qZXN4
	/sGYpQEKDehpRizyzQi+zP02fvMVC688D3s+nrpQxhafq/WNq4hNolBd
X-Google-Smtp-Source: AGHT+IFeLIhZPe01+0WMiYOMXSQzEpmcgP+FXr7mPSbtQPiptNlj8Rv5a1tZ6EGsIcU+jFFtceY8dA==
X-Received: by 2002:a05:600c:6285:b0:453:45f1:9c96 with SMTP id 5b1f17b1804b1-454cd691a7bmr30736275e9.14.1751982677111;
        Tue, 08 Jul 2025 06:51:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcEZI9W2a85rd9ilGlEPzIj0Zt76HHzf2htwlzEhNBPXQ==
Received: by 2002:a05:600c:491b:b0:453:607d:fa18 with SMTP id
 5b1f17b1804b1-454b9620834ls5510145e9.1.-pod-prod-00-eu-canary; Tue, 08 Jul
 2025 06:51:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/yNE8fukqTWkX7H444s99lf8aYRzRxqzJihE3S3LbsH5TvrG720cLwYieWLINyJHcLw6IbGDFxZU=@googlegroups.com
X-Received: by 2002:a05:6000:26d1:b0:3a4:eb7a:2ccb with SMTP id ffacd0b85a97d-3b5de01606fmr2298401f8f.16.1751982673066;
        Tue, 08 Jul 2025 06:51:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751982673; cv=none;
        d=google.com; s=arc-20240605;
        b=AG69EbDU/18XH2MnvKKGUeMkv7p30WLp7OnJB+T26nXJzS1KgwSEpSDOmy0nAN+qBl
         XiQQExVzeknFKOdGpoGenhvvw4s3FESaPtxc+YZhRkiTSt+gIyiHcXyePNRBeUC7ycgF
         RXZEqDOlEV6/vXGjU/FulriXUJqV5uwpTpXJ7Nav4buBir37OZIbtNDhyGhuGdn4NIh1
         lvRTsX4n7+iVG909EU8F1G3LMneNUQ+ALk0zBB0W5d2RUSvLJAlLnSNz/zcDDTfKHO98
         zrenljEWtGR/r1I2jv/pN8Nr+8CsJmrhhg5JsfJ8SS3Fo8s2Fa//XgN0fBgg6GmL/P/X
         uDqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:message-id:date:references:in-reply-to
         :subject:cc:to:from:dkim-signature;
        bh=31MqR/E8gvc45qHOvdbZr7UXtdSXHcy53Qh8ZwjxaD0=;
        fh=kI7mlpjl+Uqkns56rK4pQa9pUDei4q4ZGLgBOnk8cdA=;
        b=frR3utx0eAinTwS/n2HFJWoCnnZ50W4Qj9dFZeVFubnop03MOPM2AAfN5OzVbG+k6N
         bNefk3OqiIpGGYkK+/G5O8FQ4LvHCUhVPIP9jZTXx1/H63nPguBYb4X4SmHlBSUvN3hy
         gkahKlsihloivK+a5UwL8RokQ2thUyRyS7EdzTYFHgE/325ppuL/53ZH5vZMzA8dxRPb
         GDxyVtdXMbnJv60Lps2QCtc/pSsd0CtOE5c5w7bjGfcy5bGUj8kRzSJH2if/HxPnICJu
         XgWMruRFIivDb2mlHiXKaPPclIUNw1UtdHrenectkMpz8n2EOscSyOUguSSAXMkKVFOw
         0afg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=JjscOaZE;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b46fe3b52csi355932f8f.2.2025.07.08.06.51.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Jul 2025 06:51:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id 2adb3069b0e04-553d52cb80dso4055795e87.1
        for <kasan-dev@googlegroups.com>; Tue, 08 Jul 2025 06:51:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUZORh890uTKh3BR+r8UT+xhBQ3PyG8QbQah93wMOQzwlti8Y6JaKOMD6QNWdNxnDfok5x4Nxi82SA=@googlegroups.com
X-Gm-Gg: ASbGncug0oF5uM1XrIOmd1k8k5RYoo3sjWwtadPVKocOdmwk2+y6Dq8MHlVJMzQyNFQ
	Um11PaPq46Q91PBBXcbeZ/N4Q1T/HYcHsM7Hw7dhnsy+Ajfny/2A1KJm9t+mz7tGBQXbysUei1N
	bjeZ2sZ6TROLDZa4a66E6870gNFmiOtRTs09GgN2WPWWfdDJsFsImGrKwOcar1glmIQyTnO5kIv
	NXhgsDICuE7IFZ/TqwI8VItypA/w4tfipPDVf+blhCjnpCX6FmTuT5148P40mFa8LHbJ5vYWk2o
	rK2vrDT3RsfQZeKv2PNOd5Qu3X9aNuvqGmqCk2qOBiL7KgK/sZv43xzrFwxqagH9
X-Received: by 2002:a05:6512:2381:b0:553:2308:1ac5 with SMTP id 2adb3069b0e04-557f8d6a9efmr1017578e87.4.1751982672246;
        Tue, 08 Jul 2025 06:51:12 -0700 (PDT)
Received: from localhost ([81.216.59.226])
        by smtp.gmail.com with UTF8SMTPSA id 2adb3069b0e04-556384cdf6fsm1699987e87.242.2025.07.08.06.51.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Jul 2025 06:51:11 -0700 (PDT)
From: Rasmus Villemoes <linux@rasmusvillemoes.dk>
To: Alejandro Colomar <alx@kernel.org>
Cc: linux-mm@kvack.org,  linux-hardening@vger.kernel.org,  Kees Cook
 <kees@kernel.org>,  Christopher Bazley <chris.bazley.wg14@gmail.com>,
  shadow <~hallyn/shadow@lists.sr.ht>,  linux-kernel@vger.kernel.org,
  Andrew Morton <akpm@linux-foundation.org>,  kasan-dev@googlegroups.com,
  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko
 <glider@google.com>,  Marco Elver <elver@google.com>,  Christoph Lameter
 <cl@linux.com>,  David Rientjes <rientjes@google.com>,  Vlastimil Babka
 <vbabka@suse.cz>,  Roman Gushchin <roman.gushchin@linux.dev>,  Harry Yoo
 <harry.yoo@oracle.com>
Subject: Re: [RFC v1 0/3] Add and use seprintf() instead of less ergonomic APIs
In-Reply-To: <ez7yty6w7pe5pfzd64mhr3yfitvcurzsivjibeabnkg457xu7x@tkompzcytwcj>
	(Alejandro Colomar's message of "Tue, 8 Jul 2025 13:36:57 +0200")
References: <cover.1751747518.git.alx@kernel.org> <87a55fw5aq.fsf@prevas.dk>
	<ez7yty6w7pe5pfzd64mhr3yfitvcurzsivjibeabnkg457xu7x@tkompzcytwcj>
Date: Tue, 08 Jul 2025 15:51:10 +0200
Message-ID: <871pqqx035.fsf@prevas.dk>
User-Agent: Gnus/5.13 (Gnus v5.13)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linux@rasmusvillemoes.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rasmusvillemoes.dk header.s=google header.b=JjscOaZE;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates
 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk;
       dara=pass header.i=@googlegroups.com
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

On Tue, Jul 08 2025, Alejandro Colomar <alx@kernel.org> wrote:

> Hi Rasmus,
>
> On Tue, Jul 08, 2025 at 08:43:57AM +0200, Rasmus Villemoes wrote:
>> On Sat, Jul 05 2025, Alejandro Colomar <alx@kernel.org> wrote:
>> 
>> > On top of that, I have a question about the functions I'm adding,
>> > and the existing kernel snprintf(3): The standard snprintf(3)
>> > can fail (return -1), but the kernel one doesn't seem to return <0 ever.
>> > Should I assume that snprintf(3) doesn't fail here?
>> 
>> Yes. Just because the standard says it may return an error, as a QoI
>> thing the kernel's implementation never fails. That also means that we
>> do not ever do memory allocation or similar in the guts of vsnsprintf
>> (that would anyway be a mine field of locking bugs).
>
> All of that sounds reasonable.
>
>> If we hit some invalid or unsupported format specifier (i.e. a bug in
>> the caller), we return early, but still report what we wrote until
>> hitting that.
>
> However, there's the early return due to size>INT_MAX || size==0,
> which

First of all, there's no early return for size==0, that's absolutely
supported and the standard way for the caller to figure out how much to
allocate before redoing the formatting - as userspace asprintf() and
kernel kasprintf() does. And one of the primary reasons for me to write
the kernel's printf test suite in the first place, as a number of the %p
extensions weren't conforming to that requirement.

> results in no string at all, and there's not an error code for this.
> A user might think that the string is reliable after a vsprintf(3) call,
> as it returned 0 --as if it had written ""--, but it didn't write
> anything.

No, because when passed invalid/bogus input we cannot trust that we can
write anything at all to the buffer. We don't return a negative value,
true, but it's not exactly silent - there's a WARN_ON to help find such
bogus callers.

So no, there's "no string at all", but nothing vsnprint() could do in
that situation could help - there's a bug in the caller, we point it out
loudly. Returning -Ewhatever would not remove that bug and would only
make a difference if the caller checked for that.

We don't want to force everybody to check the return value of snprintf()
for errors, and having an interface that says "you have to check for
errors if your code might be buggy", well...

In fact, returning -Ewhatever is more likely to make the problem worse;
the caller mismanages buffer/size computations, so probably he's likely
to just be adding the return value to some size_t or char* variable,
making a subsequent use of that variable point to some completely
out-of-bounds memory.

Rasmus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/871pqqx035.fsf%40prevas.dk.
