Return-Path: <kasan-dev+bncBDBK55H2UQKRBC7CR7FAMGQEW6JPXVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 30074CCBC31
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 13:18:20 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4775d8428e8sf5469925e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 04:18:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766060300; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ir3QHd7rnO/JJQ1CrAhr7dlHIJZv5BalUzqSkhquMdkR241i3Fek//xx3jnZHA8V4Q
         bUuCTSacdwyWYM7+0PrAb1joGmV3R0GkkGNc7tSHHTgKP4qx6NYqoyMw9u8DL5LzuK5j
         PZEcRYqCb88ZxnzU6FPiqLndGpoTZj5Tt4c3xseEtK2BX9BpCI3/UPhcGJ8V7L0xYqZ9
         CtAdizE7tt0vlXILGMSWD2PiWt/+kIGX+gnb3njjiJGILjavihcFck42TPahETQRtChU
         39lHi4CJsTaSYkUH4hHvm/i7lz+NxdMQdKZSK5+Bsg81MJHeDvx+x/1Ha1Ns1S4Ycsuj
         lR3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Uoisc40QWaN586WXcZFMiOsTfpCKu/adjy9uh64LIzU=;
        fh=BEV/jjSSyiWy+rrQMiN4WE9Mk+vb/LgskhM6EvgCxM4=;
        b=NRCqHlbGjtnDKbG1lBotZ6d21QRW1Rd3ue+zkPW8KUHCp2A+YHf40AvMRGt0JM8XM+
         8iw50WhKSVvumLqzp8KZgeuCLOA0Njf47RxP2cOADyWI5cbi8WifQvKjEwwYSd+3vZgA
         mk5veWzvirQlIPjl1ky7SK8daoQ82l2Z+jXNRtMo7TlYuVUWCLl9BL/ygEnVDHGWZVDz
         zn1qso8EFuv8HOLLfIFDB4vMZe8PA8LpaaEBDFOCkTkTjeyJ+57z/MNA9UP6jTJGiKKC
         BFXyyoJq2GgY7cTYRORxFAQwDlgi8c8qtqao5B6zUMlu7xOOMLktEDCdT6Wkdi693faR
         wfFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="BSCU1ti/";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766060300; x=1766665100; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Uoisc40QWaN586WXcZFMiOsTfpCKu/adjy9uh64LIzU=;
        b=hKbixDaFW8k0fnt0AjlpYO2QXEYaNTU6sM2dJhlSphwhwM7B5kj2n9g63VidLNT5Bh
         kJvNk8dKz5ZzEeUQqrWOjEOhfkfRoVngKqtvBdQb8pJsC9L3qsJmiXEti3GM9fYgboBA
         aE7mvnyYUUynbsWOgDJ8F9cW0OD7vFOlevqmvxsIirF+zt0PxW8GZtDjW3WREOV5Ipie
         +uwOjTrObAJTrfF/MPShSts08qWUQyNwCX7lO55qf1knj/byq0oMgMQmS12VZgK1rt65
         kTSHusBAX3gurYPvdrLeWD+vqdSGq8ZZIDJsmlXy9W2mf+f6cNwxeUi/EnhALlZTFflO
         aBIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766060300; x=1766665100;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Uoisc40QWaN586WXcZFMiOsTfpCKu/adjy9uh64LIzU=;
        b=fWEK8dRL5ttt+jZVfnW8kJoQJtU7L6+bu+xT0Cd+b4B1iVcXczwoIts0I1ZrYGSBgL
         cS7pNCEotO3omYH1VHxKENEZT70Nv6F815Cx4X9JzMzCAbs1jRy5vmkZIF093YA5sW+4
         KytBFBIl92q+xeQoeLoNds5MlCgZ43MmvAZTXBSiCROsh6KvScB5keeHdGGX/V/hQgnw
         GTPAWCWEyP/zb5EChnAKXWeQh5ZJcA+glwCEszGrtUMPc/HBDDQEUKDe93Mtqh31rlQe
         Whr//NohWzRjXaQriFEQaeYwKc0s29uw7+Z7e4ZGzplHpXtsRAN453aS2LknY6O26cnQ
         +yiQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVLqsh1L6k/1IEVkS7V+R7z2CcUaygOW3B65toALoEvmI63EQpC7Qy9Wim7TVWAraP6Dsv43w==@lfdr.de
X-Gm-Message-State: AOJu0Yz7DViuHx898JbAI6slb9yYwydp5FDJizmG9eR0pyfQoXIHiWYD
	VMKMLtWV0OkU6C9mlEAFNzUJI3mpYGVxT/ZKAWfXwrQXy9gqeMqQXJe5
X-Google-Smtp-Source: AGHT+IG6Mbs2/hpPGRAPHgOJXYP19XLiZLSNIq9+buHPCXFOqNGCUphUU2hBIpYzg3bb/HgVIjCTcA==
X-Received: by 2002:a05:600c:4e09:b0:477:9c73:267f with SMTP id 5b1f17b1804b1-47a8f914a25mr251758385e9.33.1766060299686;
        Thu, 18 Dec 2025 04:18:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWa3EMcQroj8ip+NrP0lEABHHbHaTnPmB3TYKwkViod5GQ=="
Received: by 2002:a5d:5f89:0:b0:429:ba6a:3a77 with SMTP id ffacd0b85a97d-42fb2d86d55ls4419898f8f.2.-pod-prod-02-eu;
 Thu, 18 Dec 2025 04:18:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUADUEH6Sfuews5dIGmPKj8xBwI8hFk3xuv+cvvOmrwq83XtvfX8NHOH0dKg1mxAFvs8Ah3vpLbh1g=@googlegroups.com
X-Received: by 2002:a05:6000:2881:b0:431:a50:6ea2 with SMTP id ffacd0b85a97d-4310a507014mr6387268f8f.44.1766060296559;
        Thu, 18 Dec 2025 04:18:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766060296; cv=none;
        d=google.com; s=arc-20240605;
        b=lUmmzL/SrDJ/t+T1ivnYa0DXb4GKLW1/5vBz9ZdH7wTBtk1ejDcvcPte2KN9oMGAzk
         uTO9tei3lmwiRl4xL/XEWhrPFqtfux//sDn848wp8s363GtcvZfmMSNfjCy0XO2YgD9q
         2KzD2JooGaIOYldq/tQUoNotFZ5IrO08PUWwDofyw8+s0OJmgLNgZRRz46pzIGVDC3ai
         aAIDnh16wQh+Jv1D5yl+Cnsy0DQGSieL3gaMGOmy2ibtQVmKzzpUEsK72oHhCtvanhTd
         QZIFCQXKi6Lsou9oEGo6XptP5w8mlJ83/uOa7aLAXq+Q2f+YkwOisik/0vVk3RMUmF2E
         /bQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=bsKgXTZ+tb+AhWIqsTzP9CTPtabmhlq02esL6zmQnio=;
        fh=jSGIb67fldWOrhUWjA4Dhlczpndq67fojpSFxWRfyKE=;
        b=QhxxeyLAs14LXl1mkAKQC6EooYv9LUbrch4Smmavsh/5n4F+MytHgEZQXO7bQOMXz6
         KkyI2vKgGH74XCzX+Nk+yeWkwmSR8CnBSTyOO81FfHnq0ieXdI8ld+2GYTgVrQMm5Jhn
         iy1zE4HitFKGNRvxhMnojixazjk/I0hjECqWF8XVVCXjnhPf36mbdohp138IsiX2u2y8
         noLSq2ZPrhedJTBkX5EmB39Ygg9JgjkU6T+d1007WE+O8g3q6Pov+s4uBb+f/l8HmzFZ
         IqQFd6/HwegX6L8di8AVNO4rBQXcGgcRvKK0FvsCbdHbdMVSa/s/chMLtlbw4M/jL9Bt
         zn2Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="BSCU1ti/";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-43244990f2esi42209f8f.9.2025.12.18.04.18.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Dec 2025 04:18:16 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vWC60-00000008jZG-1sGj;
	Thu, 18 Dec 2025 11:23:00 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id EA0CA300578; Thu, 18 Dec 2025 13:18:13 +0100 (CET)
Date: Thu, 18 Dec 2025 13:18:13 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Segher Boessenkool <segher@kernel.crashing.org>
Cc: Marco Elver <elver@google.com>, Ard Biesheuvel <ardb@kernel.org>,
	Kees Cook <kees@kernel.org>, Brendan Jackman <jackmanb@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-toolchains@vger.kernel.org
Subject: Re: [PATCH 0/2] Noinstr fixes for K[CA]SAN with GCOV
Message-ID: <20251218121813.GA2378051@noisy.programming.kicks-ass.net>
References: <CANpmjNNK6vRsyQ6SiD3Uy7fNim-wV+KWgbEokOaxbbd02Wa=ew@mail.gmail.com>
 <CANpmjNPizath=-ZUVTDFAdO_RZL1xqnx_o24nHA+3tJ4-FOg+Q@mail.gmail.com>
 <DET8WJDWPV86.MHVBO6ET98LT@google.com>
 <CANpmjNOpC2kGhfM8k=Y8VfLL0wSTkiOdkfU05tt1xTr+FuMjOQ@mail.gmail.com>
 <DETBVMG30SW8.WBM5TRGF59YZ@google.com>
 <CANpmjNNc9vRJbD2e5DPPR8SWNSYa=MqTzniARp4UWKBUEdhh_Q@mail.gmail.com>
 <CAMj1kXEE5kD217mY=A7vtbonvLYPN_u5xHMWrr01ec4vvP++4Q@mail.gmail.com>
 <20251218095112.GX3707837@noisy.programming.kicks-ass.net>
 <CANpmjNOQJVRf5Ffk0-WMcFkTfAuh5J-ZoPHC+4BdXgLLf22Rjg@mail.gmail.com>
 <aUPsdDY09Jzn3ILf@gate>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aUPsdDY09Jzn3ILf@gate>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b="BSCU1ti/";
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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

On Thu, Dec 18, 2025 at 05:58:44AM -0600, Segher Boessenkool wrote:

> You might have more success getting the stuff backported to some
> distro(s) you care about?  Or get people to use newer compilers more
> quickly of course, "five years" before people have it is pretty
> ridiculous, two years is at the tail end of things already.

There is a difference between having and requiring it :/ Our current
minimum compiler version is gcc-8 or clang-15 (IIRC).

On the bright side, I think we can be more aggressively with compiler
versions for debug builds vs regular builds. Not being able to build a
KASAN/UBSAN/whateverSAN kernel isn't too big of a problem (IMO).



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251218121813.GA2378051%40noisy.programming.kicks-ass.net.
