Return-Path: <kasan-dev+bncBC7OBJGL2MHBB26VYSLAMGQE7EUB7TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 62230575DE5
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 10:53:00 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id a9-20020a2eb169000000b0025d6ddb274bsf1022981ljm.23
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 01:53:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657875180; cv=pass;
        d=google.com; s=arc-20160816;
        b=dMafA+8iOTrqNLoMr2ALvVDqsqhPxf06r5EQmLSdfRCRYVoApSO30WTbGzsQzX71kZ
         vLP8tUBhHGceMPkYLhcJbE1NfZbR6/w2ElgYOGlYL1c0+2JUuKeGbT6gYCkru4EN0tyP
         zhJ5hdtRzvBEwm37mJ0lCkfhBPRlxqb6KwDdzV1xhhL+1hvhKeGnbFFUfqp6uALO3V29
         9wMm6wqJgUxCHXwvleYCLqmkYAR8zF1A34vdjCyFH53GCpnaY54Nkx24bGj/+rh2QH5g
         xtMMQXlOfjiK7oTM3lP69neeGD0t548xaLoX0Xm79UJq8VvTovtAlW7foUFzk4WZvJob
         7PjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=OllGuHKoPdjfFbbjCf9pH0lMHF+GS3M54w4s1NrXi4c=;
        b=gshgl1UPnKhYJLLeRZi5SNtkIGjpF4ok8/S+uYAct+NGTRHVmgbhsJAb2a+ENxUwol
         nBy5VrVu0QZdxKg5cDi4S/t7771/GyKoL2F4oRCqoqLxoGKOFRsGuPkk6Hzi8zoeHkov
         vg05Or/qD3rfolY1U8ixns5t5Y1hNwpxrdYKoLe7COA8Vc7P6cNntQSONi1hy3cnQGnS
         GvA8/xucjakx0OxwP4Hv53g6VnqG5cnWy/qhhqQMiK4IkyowX0DWNLnSsU39v0zr2kqL
         jmNh0/2ChdoB6V/+sGSdeEAciKCO5oRIonyOLQ27ZcymWdnbp4bfQvkNNzPxMZHImOWm
         QfyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EPbgaSiE;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=OllGuHKoPdjfFbbjCf9pH0lMHF+GS3M54w4s1NrXi4c=;
        b=jyoZ33iANfV+zTuIINYigHY9DjOV86+tev7WbJ/kPeJW+z7dAhTuLmpmf7d+vpcHcB
         lijV1U/draocvJH9L7av0KxCQqV3u1ce8PEv3DMP88xan1xAfqnv3Uz1V9VSfKE4dJAr
         TEMIwoDJ5BxYUx8wqBh87sdLd3lM8XCqvwyA2+HTxGxR6UolBMIQZZPBT/0Pmb36cc6s
         Q9uArCgQONB9g2s9lhs1qZOgFIqa5zX460ec1oThAgjzmO3Y+v/CeuoDhH8VBGgk40cq
         zaKGNmt5C/a1dG2NMRF2QCK8We0pCApcWEn+t1EGz08+l8+JhqzY+uOtxnyc+nxIIK0x
         WPTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OllGuHKoPdjfFbbjCf9pH0lMHF+GS3M54w4s1NrXi4c=;
        b=c/nh7bwlVz8j4Vi/51cgVHXViV6N5Z9hjtpgf4sYXZp/1tIZG5Og47DJ5qDqWykSKx
         +MJSUIn0pl2uROxp7QAzOuXjNYJG020kscWrs7Ns9Xam2fMnMSwHVTsvJWfDmE5eEGUH
         SawlVJSFTXdeA//X+fxaLSKcYFSlS9MrLyukv9NQ7o5bEeHhd4pZrX8WKSR5OdqDEWf3
         5SA0elYx75dC4+HSBUiScGXcaNKcHsxJmsOSeG0YOi99tEii7rvNQ0GWowkl/U76jjTm
         0u+M3rDg6YxPgY/c4Nuc9TuY57Yi2IZT/7RLe2QpyoEzAexOFNS55x3rJGJmO3zrd0Kh
         pEnQ==
X-Gm-Message-State: AJIora+GnzcU0syEwIj+077+MpypEv+KPJYD0wKe2qrbrPqRhWOqEkrm
	DqdQhiuvWfjSsysLEO3GSQE=
X-Google-Smtp-Source: AGRyM1t2Z5kndfmxAspwYcvc2b3F5wqcuJ1pfGr2SoZ5IkRwHnMalnoWPZkOEshIzDln+MzmGver5w==
X-Received: by 2002:ac2:530b:0:b0:486:6982:5ab5 with SMTP id c11-20020ac2530b000000b0048669825ab5mr7745973lfh.138.1657875179598;
        Fri, 15 Jul 2022 01:52:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e34d:0:b0:489:dd8c:5436 with SMTP id c13-20020a19e34d000000b00489dd8c5436ls648397lfk.1.gmail;
 Fri, 15 Jul 2022 01:52:57 -0700 (PDT)
X-Received: by 2002:a05:6512:39d1:b0:489:d408:c0ae with SMTP id k17-20020a05651239d100b00489d408c0aemr7373314lfu.114.1657875177854;
        Fri, 15 Jul 2022 01:52:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657875177; cv=none;
        d=google.com; s=arc-20160816;
        b=js2HoF84y8ZQt6QpvC12ctcylLKqhpIk5hc2Zf24J6eAZA5SuV6blK5u/pYYFIVC4q
         QhipczWYZhA8Zm0G6cIY+8zqTpI9MD452NbIRYEJn3tXUhFjMmdFpl4yFgFHmzJ8nCwm
         Mia+NGDXuMPOoywZw6LFwrW139uAhL7gU1WfDPqUPh9GKb443nA2kNfRRypJirKMbgBw
         sLcALSr7lv0J7uRMjd4Nu4gYiUPGBd4q0Nuu1Uf1Q5ziyP14KdaDXjeT+GbOMvjNRccV
         5clmYcPx8KVzqzfcg1AOSDDGZv0M0uv1HnW+eJ0M2U4mGfyUVPK/9bgX9tMEjfV1SgwF
         kAzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=lnbKwcn88f6NuJinTbm+K+QRokDztEAvNGDk/1bg6OE=;
        b=ycLtwVf/iUrmf+4gDVII75g54YyzGhaHD+cGhbIrOIydsV4OTImdGNJlNYDYb5WrAX
         Kk/j9V7fDyr0P1m2lEhWE0+ExdxRe4o8DKR3GfLzCvAXK1MqJg8RWFS78jaI7/zpXFE0
         9LpiIKE9cQzn2shC5oEDtmF4d9tNcEm8c0nP1SMLP+TiQr/Pfzee/OzDxARlPtYyBrFq
         mo1ZKLao3NncFKqtsma6VWAsXjSMfoPVje7cYjqlpz0F+jM1LdtX2ZVJ3+ndJ7Dl+0L3
         ZBdw108FWOhkBFt42l8FUabyEAbLqbe6qTMbXXVzI9iAG16c5Z3UOkA2rIZVQgk2sSK2
         aeuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EPbgaSiE;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id b4-20020a056512070400b0047f750285c2si115424lfs.5.2022.07.15.01.52.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jul 2022 01:52:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id l22-20020a05600c4f1600b003a2e10c8cdeso4432390wmq.1
        for <kasan-dev@googlegroups.com>; Fri, 15 Jul 2022 01:52:57 -0700 (PDT)
X-Received: by 2002:a05:600c:354e:b0:3a1:9ddf:468d with SMTP id i14-20020a05600c354e00b003a19ddf468dmr18784274wmq.145.1657875177165;
        Fri, 15 Jul 2022 01:52:57 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:b388:52a3:7014:22f5])
        by smtp.gmail.com with ESMTPSA id i15-20020a5d438f000000b0021d4d6355efsm3285703wrq.109.2022.07.15.01.52.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Jul 2022 01:52:56 -0700 (PDT)
Date: Fri, 15 Jul 2022 10:52:49 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>,
	Alexei Starovoitov <ast@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Matthew Wilcox <willy@infradead.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Vegard Nossum <vegard.nossum@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux-Arch <linux-arch@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v4 06/45] kmsan: add ReST documentation
Message-ID: <YtEq4dFk/NvE43iM@elver.google.com>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-7-glider@google.com>
 <CANpmjNN=XO=6rpV-KS2xq=3fiV1L3wCL1DFwLes-CJsi=6ZmcQ@mail.gmail.com>
 <CAG_fn=X5w5F1rwHuQqQ9GRYT4MiNGQLh71FRN16Wy3rGJLX_AA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=X5w5F1rwHuQqQ9GRYT4MiNGQLh71FRN16Wy3rGJLX_AA@mail.gmail.com>
User-Agent: Mutt/2.2.4 (2022-04-30)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=EPbgaSiE;       spf=pass
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

On Fri, Jul 15, 2022 at 09:42AM +0200, Alexander Potapenko wrote:
[...]
> > This sentence might still be confusing. I think it should highlight
> > that runtime and compiler go together, but depending on the scope of
> > the value, the compiler invokes the runtime to persist the shadow.
> 
> Changed to:
> """
> Compiler instrumentation also tracks the shadow values as they are used along
> the code. When needed, instrumentation code invokes the runtime library in
> ``mm/kmsan/`` to persist shadow values.
> """

Ack.

[...]
> > > +Passing uninitialized values to functions
> > > +~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > > +
> > > +KMSAN instrumentation pass has an option, ``-fsanitize-memory-param-retval``,
> >
> > "KMSAN instrumentation pass" -> "Clang's instrumentation support" ?
> > Because it seems wrong to say that KMSAN has the instrumentation pass.
> How about "Clang's MSan instrumentation pass"?

Maybe just "Clang's MemorySanitizer instrumentation" - no abbreviation,
and "pass" is very compiler-implementation specific and not everyone
might know what "pass" even means in this context, so I'd leave it out.

[...]
> > It would be useful to move this section somewhere to the beginning,
> > closer to usage and the example, as this is information that a user of
> > KMSAN might want to know (but they might not want to know much about
> > how KMSAN works).
> 
> I restructured the TOC as follows:
> 
> == The Kernel Memory Sanitizer (KMSAN)
> == Usage
> --- Building the kernel
> --- Example report
> --- Disabling the instrumentation
> == Support
> == How KMSAN works
> --- KMSAN shadow memory
> --- Origin tracking
> ~~~~ Origin chaining
> --- Clang instrumentation API
> ~~~~ Shadow manipulation
> ~~~~ Handling locals
> ~~~~ Access to per-task data
> ~~~~ Passing uninitialized values to functions
> ~~~~ String functions
> ~~~~ Error reporting
> ~~~~ Inline assembly instrumentation
> --- Runtime library
> ~~~~ Per-task KMSAN state
> ~~~~ KMSAN contexts
> ~~~~ Metadata allocation
> == References

LGTM.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YtEq4dFk/NvE43iM%40elver.google.com.
