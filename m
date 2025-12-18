Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBVAR7FAMGQE2YS4KTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FDD3CCB476
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 10:57:28 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-3f9a5b4ae58sf766432fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 01:57:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766051847; cv=pass;
        d=google.com; s=arc-20240605;
        b=NPb7hInMGnpk4jkVn+dy1aU0BFyFo3j3eVllhhZZv44anCu6R8+sVPBNHL6cPFi6fF
         A9y3Gw1/YD/zasP6yG47sJ7coNZXGo0yazk5jCpFu29ldG+gByI+iy7EG7IdLOPi6OfJ
         PAlO5PKuZpT6k8i/szQdNuq7JjdEfF97yZ5eduXjgoJPY5/MOT3lPPedv3V88/8SivMS
         y5XcUrS+DLok7V2fo4V7awVa/6MihT09+p1//qnV6fyEEEM2BCYgPVcyCadV+ZKnCuaS
         nMhA96pcMHBRFmt1rDibgoI2LyLpe1mlnFmvmQuBtCNDB6EIGInhkoChKa1YHcuaEMQ/
         hb2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IUHuVIDkoAfgMN5kOXtqmxmpKWeMoRKv70y5NRi8Af8=;
        fh=8TFT+59vRauEdc+sW+y74Br76NeVJM+GbRm2WA3ds7k=;
        b=POFa+UjmgHQtfuS8EXsUSoTeH/MmuBavUXxm4Z+z/hWyQBfQpQlpHQ9i8m5zFHI2TZ
         1I8zw7cg0bVmzDX15aOqbuaS+iAYz12h/5ifRqvlOZi6LWVsDfYuXrUmhXw/51AFRQuU
         futGKR2Mnhzz9fSuKGLpYW9yy3E9Xto7Ykh8fP5IeQKLNeMtEMqCW8yPB9z0Q3eTj9x9
         7CHg1KBxV0r9l6Ptabryxxgin0DVo/gWX4auSIzrwYCMrJQXYbX2qJW4f/URhSbV8UJ4
         GuPViCNjLCa9cNzNCIScZg9On4NOwI0DpSZTcmTyzmg6uFDwgo6o2KbFY3yYPoecu0j0
         7ndg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D+5iGv7E;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766051847; x=1766656647; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IUHuVIDkoAfgMN5kOXtqmxmpKWeMoRKv70y5NRi8Af8=;
        b=PjB+W5R9JgsqLws+KEaW0eAKRzqS2NzI2Zvkaq5MdPdYxBkuiDeA5r6iLoxTwqrNLW
         f5qI3CuTX4b4QIinxhvCijBzakHY/xEhNfCynyq1+kNcNj+s/t1Amu8LxIxphULqI+q7
         loe+FWbZZH3UA7OO7inteL6fKEp4iPUEVVGH2yGBb18JOaHu17d4rAV/L7gnYN2iApk3
         n7bEg2lC2dOvATbRPCKoROPVVNeFLvifC/gBXpLHBLUecP7xn83K/YmbsOBae+C/cLJv
         ap9t293PO8iyXMntTSBS4X+qMT5J/wMexhSlLVeScDjR95JAXwJN/JAwrr9F83priiHH
         pafw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766051847; x=1766656647;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IUHuVIDkoAfgMN5kOXtqmxmpKWeMoRKv70y5NRi8Af8=;
        b=fFMHw4/3kRP52/J+ncVRTKOpvFK+kWieCmwjkEjttmTaQYn9AqASWNLvT99WVTdip/
         HRgxHw7S5/y9RpiM8QjD7ixEw9r1YqRocl717BAyznAaxfZ58WiWS+KtxPEbOm24/BF0
         nrZDBFoOLKm41zQ/iViVin2hYnwnQFPQHRQcgoLJr0HtUsuGhuxMsbLWN64KKZKy1sW8
         IIwnBOi6deLfdZ5888YxuomecATn7qfEJLCl6dKD0RVTk/NQKfuCqjwdJ1V3bj/PE13H
         39stbHkctexIXTYDjT5gXI3S4ntvmvJl8llWW4hFyDuXPZskl6F/OSfUBtJZiggmsUXy
         gxWw==
X-Forwarded-Encrypted: i=2; AJvYcCXDU7c0M+txKqFYGmNIRN/shDphkDuscUmVRXYsQeToAbnFesnsgvMluZhhNh/2T/fd+quNmQ==@lfdr.de
X-Gm-Message-State: AOJu0YyrPoqN8WMF8GngBvM0d1dJmkyEjb5r3ln+luelm1OUt1Y2jm77
	iIsdTBVREC48rSpv0gddGTJ9azoMRROkAiTyzMpaszsp5LXG0LrpWfMQ
X-Google-Smtp-Source: AGHT+IFV8TTWey20hsxa3m/WQfepRgDdhnXolpw/uZIGeSxaMCUaALa8bWBG/qBYSClMMW8ZD5XzzA==
X-Received: by 2002:a05:6870:8091:b0:3e8:98d7:72e5 with SMTP id 586e51a60fabf-3f5fc5db5admr9785910fac.46.1766051846990;
        Thu, 18 Dec 2025 01:57:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZtw25c83vpRZr99TlpWOYIlVxXdEkq3xielleFvyVVTw=="
Received: by 2002:a05:687c:56:20b0:3d5:54c4:3245 with SMTP id
 586e51a60fabf-3f5f87f2400ls2837472fac.2.-pod-prod-01-us; Thu, 18 Dec 2025
 01:57:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWloz4tFZbx4Uf1kp7xLFWX7islzM1qjuJdJ2r8xvx+GAZ2mvGBZGqdYiArHDZjdaY3XBjXED1MWh4=@googlegroups.com
X-Received: by 2002:a05:6808:bc7:b0:450:7df:e90b with SMTP id 5614622812f47-455ac957fe4mr9209482b6e.52.1766051845503;
        Thu, 18 Dec 2025 01:57:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766051845; cv=none;
        d=google.com; s=arc-20240605;
        b=Bs2m6r5Md4I96R/QhakOX2RCG/PAoQxVdja9UdDcJCArLatSFqx8CuIIHTcYfBckfQ
         92eRNBqqyfRAQSl3dciwFyoj+COdg3BgB9UIDbarFaz0milyWBouR6WEuus1VQGDbzVi
         Gd+hmRSYIH/pZj2q8Ce3u2sbDo5R202XeS4gLwe22MFBS6P5hn1RkCT/UujMDXgeTCsO
         97gBuZ9b/4zComsTEGLdmzv73B4hVbzV40CgX+U//jGQF+ISy86dF4Tk4uivWn0OBLhN
         sx8BfBoNIsHt8nXxWmTLJVs0Xi5kpAUP7JL8re1b0A4ptlrFz5LrB0mDe1RpKbEctoJZ
         0NjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=er4C6n+LMe8qHQb7Jvc7VyJrjunVBHKc91qoRJ/pdTY=;
        fh=O/e5CnhDV0OuOcdZQs5PgZzAhn+SezKF0XXDWbSzUVs=;
        b=LqCHKuZAF93S7OmrRiJ8QGu0TDbj6mw/UG6C8+dHbSyQm29BYDIBYUhJoJlMwwNvO3
         Ck7NN9/DKIvGGOFfSXSz0ycwLTrWrWRiXPq6WdYroiOhhOWi1NegeuzkBIoh4en6ZEza
         8+YrJ4BxmKa7z1i7pVQ9KQytNaHwgneh06Et5ZdYdhwa8a9TAO8Pz9aOXkDclN7fo+O4
         zJ+z9FZoahFH7OgBIrkv+/N276a3WwjJp5jlbPNdOJ99OQU1JEaf0Wk/m4QB7T5sUBTs
         YvmDtaYHH8KfyMwWkmQ4EdCoFlYoLz1eSnpc8x7orH99zexfPMhNwShfMj3COIBjvVW4
         YJ7g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D+5iGv7E;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cc59b5e4c1si99198a34.7.2025.12.18.01.57.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Dec 2025 01:57:25 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-7d26a7e5639so558589b3a.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Dec 2025 01:57:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUNR7omf20toCo8fzdwaGnH1AOmXbVEwuXxP5KxE7W8X+gRrkmhjuZwmAUi/76wpgPDYWev3jxzfUo=@googlegroups.com
X-Gm-Gg: AY/fxX68TEOMgtHroU5x+e2VBXC7JsGJjsfeWZt5PS9+qjGIXBPhME/JWEjtlCwV6Ow
	CdfvJuMJVhfvQXdONjcncCNm6yPbh5PaLqGugd4STA0gflJYvUTkoXm94RWuUQJLEmKOAlYo7gu
	uWBHsbFKFA9SC+0n8dGHz1nnytIX6nPSq25WxhGVXR1ewvzZ+Jtep/ZkGlMxG+JNhkG2TSmXkfO
	3fK+riUa5ugyM4a0nKqVoFCRmSyMhJnWCaab5xhWQ2G1KgAJRRwoAPDNm0A18fMuXtRw8XDFmiS
	G8++9wNyx1l/Wd3FI4kijXZG9M0=
X-Received: by 2002:a05:7022:6194:b0:11d:fd26:234e with SMTP id
 a92af1059eb24-11f35486022mr15580553c88.16.1766051844530; Thu, 18 Dec 2025
 01:57:24 -0800 (PST)
MIME-Version: 1.0
References: <20251208-gcov-inline-noinstr-v1-0-623c48ca5714@google.com>
 <CANpmjNNK6vRsyQ6SiD3Uy7fNim-wV+KWgbEokOaxbbd02Wa=ew@mail.gmail.com>
 <CANpmjNPizath=-ZUVTDFAdO_RZL1xqnx_o24nHA+3tJ4-FOg+Q@mail.gmail.com>
 <DET8WJDWPV86.MHVBO6ET98LT@google.com> <CANpmjNOpC2kGhfM8k=Y8VfLL0wSTkiOdkfU05tt1xTr+FuMjOQ@mail.gmail.com>
 <DETBVMG30SW8.WBM5TRGF59YZ@google.com> <CANpmjNNc9vRJbD2e5DPPR8SWNSYa=MqTzniARp4UWKBUEdhh_Q@mail.gmail.com>
 <CAMj1kXEE5kD217mY=A7vtbonvLYPN_u5xHMWrr01ec4vvP++4Q@mail.gmail.com> <20251218095112.GX3707837@noisy.programming.kicks-ass.net>
In-Reply-To: <20251218095112.GX3707837@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Dec 2025 10:56:48 +0100
X-Gm-Features: AQt7F2q8z5XK_xanH1X4VEucRsDHj2RPiGmny86rpMpwFR9HCzqzIuAmFlsrllM
Message-ID: <CANpmjNOQJVRf5Ffk0-WMcFkTfAuh5J-ZoPHC+4BdXgLLf22Rjg@mail.gmail.com>
Subject: Re: [PATCH 0/2] Noinstr fixes for K[CA]SAN with GCOV
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ard Biesheuvel <ardb@kernel.org>, Kees Cook <kees@kernel.org>, 
	Brendan Jackman <jackmanb@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=D+5iGv7E;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::430 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, 18 Dec 2025 at 10:51, Peter Zijlstra <peterz@infradead.org> wrote:
> On Sat, Dec 13, 2025 at 08:59:44AM +0900, Ard Biesheuvel wrote:
>
> > > After that I sat down and finally got around to implement the builtin
> > > that should solve this once and for all, regardless of where it's
> > > called: https://github.com/llvm/llvm-project/pull/172030
> > > What this will allow us to do is to remove the
> > > "K[AC]SAN_SANITIZE_noinstr.o := n" lines from the Makefile, and purely
> > > rely on the noinstr attribute, even in the presence of explicit
> > > instrumentation calls.
> > >
> >
> > Excellent! Thanks for the quick fix. Happy to test and/or look into
> > the kernel side of this once this lands.
>
> Well, would not GCC need to grow the same thing and then we must wait
> until these versions are the minimum supported versions for sanitizer
> builds.
>
> I mean, the extension is nice, but I'm afraid we can't really use it
> until much later :/

Unfortunately, yes. But let's try to get the builtin into Clang and
GCC now (for the latter, need to Cc GCC folks to help).

Then we wait for 5 years. :-)

There's a possibility to try and backport it to stable Clang and GCC
versions, but it's a long stretch (extremely unlikely).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOQJVRf5Ffk0-WMcFkTfAuh5J-ZoPHC%2B4BdXgLLf22Rjg%40mail.gmail.com.
