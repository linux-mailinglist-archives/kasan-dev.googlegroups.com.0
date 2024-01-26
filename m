Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCWJZ6WQMGQE2QVKBAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 5662383DF54
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jan 2024 17:57:48 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-598cba51c4esf513269eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jan 2024 08:57:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706288267; cv=pass;
        d=google.com; s=arc-20160816;
        b=xSbb9G0Eo4XV4OlFhLXmCre35vRNH1gvZu0TXV5+duAelPx6m+QOCksc7VzyKbRBJI
         zqs8+kdZODHei9tHFe/Euka25Sie5VAVLYf/szdw5x/V9DHEJdy4iH/2UiVw3z1UEN32
         EAqmXREgKqfxr6+EyfM7c51yioxFHt943Px/BEfSz3jJo4wRFBbBAeB5Lu/3E7JezuIq
         T5N4IOQBm3sWuBvw2SvF8856QTaJ1XyZicTydkHiFikWri2pJ1/dgyNtAq78om4873hJ
         PDI0TPsVRXCoRYCPZ9JLEsGDl/ZY0ssZP8paPcIB3vgjEyHWIWe6eA15d+ka/djhN0Ii
         Osog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ECATTw6ao33hWRWzxnJde7OFiGG+yWfqBhMvAXT05xA=;
        fh=Gi8QN8lcYcChPGxnE4J+1Rkj3OWOJKHIyqbcukBRJ1k=;
        b=EYn6TwFUc7xKS8aOiq3jB1N4aW9SWZVYfGcKCK7o5Htm99Wt4DCsk6/ztg+0JGtDWX
         gb+FW7qpNymGt9XBVXcUsPWbiIW0ktzPlVf7s1Y+0VPJR/xt2YW9eEMLfSJOgX8NN+hv
         0FIdGnr9NZemELiNYfpdVJDTbv9TLuvJa1T7N+WBt2B2YdQdihCqsEKxfKyD3FzAk4I9
         cmQh+JN/T2RCpKOOAZjqswHngIKemwtkH2ODpC0ckNtw5blrmZD5Zl2e5DNN5m3JsMIN
         tOf+lUkUtx6XtiuuHn4LSlPw+uwaasVcdZLh5BGasYq/aU6/cSYr3my2bEQcIpqJStao
         4jRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Hs6zffTG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706288267; x=1706893067; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ECATTw6ao33hWRWzxnJde7OFiGG+yWfqBhMvAXT05xA=;
        b=D0w1Mn9AcIDswcd49xBz4fwFCd5nh8L0AODGXgZW8JjkiDR1NBdw+6cFw/bNWIFdNZ
         y85O26c2BUdsaY9kI6BpOoFHWvwga24QsCCvFk0hWEusPWBnytA+VmELykSOXUpYSEGC
         Tmi2WUJx8QKgKXUiF5PSxoCaHAzsEOuKOfiLs3gXezj2TZLTjZutuWqHln2Tv4dO06Ai
         ezpu0RYZvRhhWmYq3dGza+UvBvhvNk6V8TtV7+TGT+U3eU2SPHyDXApMxER92jP3IbZK
         iYBFXj47l4pE/ou12vvSo/ppA6TgqLWW16ydgwipCed/V8WdqK77rQRnN0/znUeBMdoQ
         DvEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706288267; x=1706893067;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ECATTw6ao33hWRWzxnJde7OFiGG+yWfqBhMvAXT05xA=;
        b=Rmz6ou9CZsTDsYNXgXKTjefB3/T9HXQTZnRKZCmaoINxuYfLHu6gu11YLPc1Nhoxwl
         SdXh8SW0Se2r7UtptZNHtzWwMgYwX3LZvNbsW7BieWlJ6dTU0y9Ji046MmPhOZFkU/7f
         T0rkjx2ASyjk8WqDNGtSKmFqqAsOhjR31TiCfXy/wCLsU7c5DnPCAbuKsniZqlWypltF
         +B3pGA8DL38g1nAWFZqLgG12HuHOUG3ckNa5+e2WDpcx6pm259BrSrUdn/JJH7YK7rhq
         JM/JlzIUy3O8tbNa44nMLfAaBNFBKGdR5oQg85R3r1njxRw8b7zH3AJ3MoBYL6EqGbIt
         su4Q==
X-Gm-Message-State: AOJu0YwGv4Rc7+oPRtXJvUO1SNUs/qplpePzzOO3fdMG1r09udiVVfeh
	RuiGEz5+Gnt31ppeY6GT9MAZlECbuy8331VVWi9d5dKUf3xFwUI/
X-Google-Smtp-Source: AGHT+IEEIKr5Q/0Y8q1JDNjqGl7a88Jpyi/ag8kwonmDTNcsQwYTq/5vgwgZBhK2IbnZoIviU6dCww==
X-Received: by 2002:a4a:bb08:0:b0:599:bcb8:87d0 with SMTP id f8-20020a4abb08000000b00599bcb887d0mr1240768oop.3.1706288266740;
        Fri, 26 Jan 2024 08:57:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e9a5:0:b0:59a:a4a:21db with SMTP id t5-20020a4ae9a5000000b0059a0a4a21dbls363875ood.1.-pod-prod-06-us;
 Fri, 26 Jan 2024 08:57:46 -0800 (PST)
X-Received: by 2002:a05:6830:194:b0:6db:e349:f82e with SMTP id q20-20020a056830019400b006dbe349f82emr1651451ota.66.1706288266023;
        Fri, 26 Jan 2024 08:57:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706288266; cv=none;
        d=google.com; s=arc-20160816;
        b=ZfeolZaTK9OdqoVcwzhkR86uRH8QBmi/OicpfawWnBHtG0YkRxK+hxiHFNRjQ1fZyH
         06smOcHivWUA7ofjfeAVpE5KGfCzOVTCzXTyfrgcGKRtVILCHWqu2U3ePo5Vl4Wfc4Nm
         f0wNyNJoXLsIkYruM+m/HbveZF2wpPn57hGNGezoG1apeUy7ZAiY58qkLA7r5FLe6Q6L
         5ifFZgRLLOSgdYqQ8NV6F6CTGMATPal4w7YfLJXhmSSucrHw/1sSPum8GEAWW8Gv6naH
         umpEdOQ2QXEpsCUy7XKRsaYXuif3xBDvLvDeKNtm2ARBtDmeZGrO+fsIS60bGhtTKkU6
         x7Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=W8wQho2kzTpQJAHRtDOw4DoWvclzdYhTLnZmTHKhh5A=;
        fh=Gi8QN8lcYcChPGxnE4J+1Rkj3OWOJKHIyqbcukBRJ1k=;
        b=E/dJGhi22zzeZSITOeikp12CvTe6pB228/uRmZdAK55ZP1NAYnLeuPF+upxTUrX/6D
         zW2sKcCBkxBQO62xygIZnwocXEguNJ5K0NTaNUfxqqPwIfHpu+pyJnYtYRQ/nIFlW2jv
         jClXvw9IzcWJsPsER3VVaDdHNnWZPoiddz1QnaESTpsBR4ReXDfPoxPi891lX+lW+/C4
         ptbY2Buh6Ql+p0y9T7F2RxtuOGxiixEukKowalH6/dITUcXbgFYiEYe8R9RqQZPStpxm
         1H4ldUo7qIMPThPYdBLCLMFqjHCrh92kmROrIntRZJC/4E9dC8of4/iVn8SyCbwpeo1D
         idVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Hs6zffTG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id az15-20020a056830458f00b006e112c9aa65si47213otb.0.2024.01.26.08.57.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Jan 2024 08:57:46 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-dc6424880e4so503125276.1
        for <kasan-dev@googlegroups.com>; Fri, 26 Jan 2024 08:57:45 -0800 (PST)
X-Received: by 2002:a05:6902:1003:b0:dc6:48fc:65e4 with SMTP id
 w3-20020a056902100300b00dc648fc65e4mr125320ybt.40.1706288265435; Fri, 26 Jan
 2024 08:57:45 -0800 (PST)
MIME-Version: 1.0
References: <20240124173134.1165747-1-glider@google.com> <20240125173448.e866d84cda146145cbc67c93@linux-foundation.org>
In-Reply-To: <20240125173448.e866d84cda146145cbc67c93@linux-foundation.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 26 Jan 2024 17:57:04 +0100
Message-ID: <CAG_fn=VBPy9vYTUvdW5Bp9MHF3F2kAhqBKeEg6GHXk0_MG-fiw@mail.gmail.com>
Subject: Re: [PATCH v2] mm: kmsan: remove runtime checks from kmsan_unpoison_memory()
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Nicholas Miehlbradt <nicholas@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Hs6zffTG;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Jan 26, 2024 at 2:34=E2=80=AFAM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>
> On Wed, 24 Jan 2024 18:31:34 +0100 Alexander Potapenko <glider@google.com=
> wrote:
>
> > Similarly to what's been done in commit ff444efbbb9be ("kmsan: allow
>
> I make that 85716a80c16d.
>
> > using __msan_instrument_asm_store() inside runtime"), it should be safe
> > to call kmsan_unpoison_memory() from within the runtime, as it does not
> > allocate memory or take locks. Remove the redundant runtime checks.
> >
> > This should fix false positives seen with CONFIG_DEBUG_LIST=3Dy when
> > the non-instrumented lib/stackdepot.c failed to unpoison the memory
> > chunks later checked by the instrumented lib/list_debug.c
> >
> > Also replace the implementation of kmsan_unpoison_entry_regs() with
> > a call to kmsan_unpoison_memory().
> >
>
> "false positives" sound unpleasant.  Should this fix be backported into
> earlier kernels?  And can we identify a suitable Fixes: target?
>

Surprisingly, I haven't seen these false reports before, but the bug
has been there since KMSAN's early downstream days (at the time we
might have needed to have those checks).
So it should probably be:

Fixes: f80be4571b19b9 ("kmsan: add KMSAN runtime core")

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVBPy9vYTUvdW5Bp9MHF3F2kAhqBKeEg6GHXk0_MG-fiw%40mail.gmai=
l.com.
