Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVNLQXDAMGQEXUU6D2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 68FECB51427
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 12:41:27 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-31d65745a59sf6289429fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 03:41:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757500886; cv=pass;
        d=google.com; s=arc-20240605;
        b=P2rTnr2Aw+tZKotoMflvMJbCHVBEAkdogK4e8zy6IbZ+hwQyCGV7QekDV8ZK2IGE/R
         +JVddXBolAyysWBolVz4Y4x/mwpcrDM+4vk3L79DkGVzJkN34oMgJpptmKYcmgzk3tfZ
         D3n67qAsWjL4sBx+kmhzmKp59c3OhNv8/c+KZB1CzU3XHhIDxBUq2rnclBksPq8uO9OQ
         NmqNawFPIk/sI53vKt939KQ+kVYjFvmBuJwn9POGE5HbP+ghTK74bNng5TRW0q5L0oa3
         7/CS6wgOPOEoUPiGWQgaLaZ5lSiasTH7dGqA1PRourndZHNoPpEn2OOFaX+C7/JjWItN
         prUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=W8+PXeKd9NXCU3qtyfOGNnBFajSJafpOmblptLwvL38=;
        fh=8/jV6IWxk4x/8k493ol8DCP1zvsIF+x+V53dzgl2cF0=;
        b=jqXq+H7Y348HcEN/XeK22/6kzZv0S4u/HzToyYZlj3YP+Rew3ovvWXNFPgDlLvHgAP
         3uduiouRwPQUkbNsMIG6cB7+t031I2vGOCEvyw9MfGE4THseXMN5EXDVjRVsJtJML5Ej
         eiCSteeRVvuynIde3YqTuTv7dHsZDAMJX1BBw0V5kcmBBuG0kqtzj5IH0Vgi7+Am1D8j
         YCi0EBQBO/nlnwcSEN/E6JDivwtUpaP+7hOh1f/JyXg/pa2cMXeW5lqkHNOAuVmqMJ/K
         CMjpUr8Idv9O1OBDqDMFnqQ7wvVYd176ympz0gHQok9f+lTH5vzQjWfapa/0CcQjd7bB
         Motg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="b0NIf/7I";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757500886; x=1758105686; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=W8+PXeKd9NXCU3qtyfOGNnBFajSJafpOmblptLwvL38=;
        b=MrqKSjILJyrfSd48y6xJ+KVBlRgI/b5q7ZbUl8eeF3BiKwdvOyIhLlFurRgV6DsJPH
         avWB0Kx8FBf7pbOkYTehmTuTJACUgwJ2GdHMSBNZ6Vegpq+QOKsiVfdhRuNeN8e0Pf3S
         h1ij7jsKX2Dr2yJN5dGor/yHJuXIdgbNHE/jyd4J2EvAXHjbdU4O2ADpOMjaHdiRfYjM
         5zAPtfIOXcSDjj6NAZ+OCWEfmG6rRonmpQqIijW4hljfpB7wOHetHGmB98Fi+dRfkiNw
         hQIU9/npIiZ5zWBRSISBci+yuihHna/9nCTyWwBWjiA3oAfMNwM3onYicd7mpy0jkoFx
         HTBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757500886; x=1758105686;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=W8+PXeKd9NXCU3qtyfOGNnBFajSJafpOmblptLwvL38=;
        b=wzsIGCSIIKgJMROhNclhlv0IvaPYaRs39s2MFBMba3DHLz9xwhlIXZqvTNU69B28u8
         NOtMDwT9mC1JvQ2nj6UFw11EIbBIGl8OJ8fb2c3R+eOjOGBGjycGoHh3kWWqDOEpI3ly
         ZoArFGlxFUvRqrKF371bBtP30zFILXAKwgLK5NVdUlkU3ys/BsJPQSMC7xto38/j9s3R
         w/U6PkCfgqdjJ7rzXJvfD3mCR6in6L3PYkQRQ0boJTzS70WENlT4+5ml6PmTKetLv4Sm
         PHYIXxtNc1sYkumwi+UgWgP6R2u9moR1OCZrZkm8uVEFTCPn7KJW6Rl8fxXsAxTva807
         OszA==
X-Forwarded-Encrypted: i=2; AJvYcCVQCW/mD0qdpyVD/Xb6VquIfi6HJ1B+hw2CpLO8k0sxN4efOC+2nGYubbHw2HPIWCR7wlYlww==@lfdr.de
X-Gm-Message-State: AOJu0YxeBpTKJCvEgyw+do+TZYGRvjAXUcaFLE8NBFI+WLlyC9LIOx8g
	0WCGhHHp53iEBf2tfSH6FXVwe5lfVwLg8Pv8gz1kbWEKvuIJPdI3iYl+
X-Google-Smtp-Source: AGHT+IFAMpLZXdmC8ej69shUKK7S9n4iOJQxGHMr8aq6DeTdvqfvhA13GT6nY1Dclit7EAQWlqR/sw==
X-Received: by 2002:a05:6870:6125:b0:30b:af6d:f92 with SMTP id 586e51a60fabf-32264b2013bmr6992381fac.34.1757500885887;
        Wed, 10 Sep 2025 03:41:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfjmKsAaYl1mraLBS4+8NlCwJKJTrDFRnes1Oc8LN16Qg==
Received: by 2002:a05:6870:e0a7:b0:2ef:3020:be7e with SMTP id
 586e51a60fabf-321270fd0a0ls3050607fac.1.-pod-prod-06-us; Wed, 10 Sep 2025
 03:41:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2SZAeRkkaeYcoqvaiVGMIFs9k2RJs6hgeWtLZWwHkMsTCUfNxL81N3xhF6yM7AUQOULyrw2jrArw=@googlegroups.com
X-Received: by 2002:a05:6871:186:10b0:328:8d7:d566 with SMTP id 586e51a60fabf-32808d80b27mr4368305fac.38.1757500884393;
        Wed, 10 Sep 2025 03:41:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757500884; cv=none;
        d=google.com; s=arc-20240605;
        b=g318TAqwSMCH53KekMBe6n612MrvMjdyVtb/yBWnJt0uMqqWxvYRkwpYGJASylWd3l
         kyZTcivWjJTpMIJBW18ghZp4zHQx3eeHL35alOSN3qWlGK5aufIroIOVqfufDz8mK8NM
         2ZRtjhKoz7TGufLdGYY3Ov0zXktrDZ1OMyFghLFux8nd72KU3UjYsXp+aul/krDQtiMW
         0AG46iuUYL2iEuArm9bFdfWjr+Ln6qbQIsfNe/Yj9PQUKF3bTprhVU+chKY4LeyDsMMP
         QN1wiHvLSgnX6fACHiYN8XM5ta+/raxso3iS/YqdSsg4rwOpLCJ16TUQrMMpKNbE4jWC
         MM7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ep6DHmBHgd1kpbChAS+R+dvVahzWEZwGQlVUAbmwU28=;
        fh=Y6GIzejbelx8URfBNgrctbxTGOvY4V/EERAxh6Xxw2E=;
        b=ACSR4GwnLWlLYc73bpo9RojVCwXuWdLs66doOWxauq8Hh+sbrymO3ThmLnPhrw6KOA
         n0zRBAw4j+faW5ApmBfpEKhbLAEphwqHyyngNr91Er/X5iIUMPrGRcwy85MLTZgVrzxD
         T8gm8bmp3uCQztRF7p0G2nlq0if1o5h+O75Tm+Vz4l0eHGAiv30yWtH/3P6S8QWW+SqI
         idGpInTApT6WQrK1uy/hLmgxPpAWmZLSwMHujfTL/MGzd31GgEfUyALZh0qNd9q7V042
         ZBYPPxZTUi1Jx9HmRS5vI4g40thfUpMXWsOGIHKucIlSCtUfHPIkScE/JffQONZxCFrh
         9X0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="b0NIf/7I";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-31d895ec2c8si662950fac.4.2025.09.10.03.41.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Sep 2025 03:41:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id d75a77b69052e-4b61161c32eso36697271cf.3
        for <kasan-dev@googlegroups.com>; Wed, 10 Sep 2025 03:41:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXjW6ttflM8NwIjhav3BN0mmwqoYtLOYeNjM2TVHHSOKOafqoUmuuyA6FBV3DrVqpLlfSdr7OV6bEw=@googlegroups.com
X-Gm-Gg: ASbGncvD1szZuu9eLyleV3BQzLCJBnM/AOenBykFZXlo42q0YZc7yWK8sX7dq+nhw2c
	aXrdgdLACUNRZDpcL3377Kl1ApUrVzMGK86pOAgiQLdmOrh7be6uFE/jDudJ96BljJbsRCUL3vt
	TCt49BegIc8aWpA86E2zf/g83l20psY6f0XTN3z5mQtR84WHd+WVXtm5rbIqAGe23uUX4axwrjs
	sf3GYeU9Nj9Ty1WLHok0biIjeBgQZVXNd8FDPrzdkyC
X-Received: by 2002:a05:622a:40e:b0:4b5:e49d:8076 with SMTP id
 d75a77b69052e-4b5f84676e8mr170436381cf.56.1757500883119; Wed, 10 Sep 2025
 03:41:23 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com> <513c854db04a727a20ad1fb01423497b3428eea6.camel@sipsolutions.net>
In-Reply-To: <513c854db04a727a20ad1fb01423497b3428eea6.camel@sipsolutions.net>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 10 Sep 2025 12:40:46 +0200
X-Gm-Features: AS18NWD9OOMFghsEyUOQIKKsq3tKxaVXVh2dSpezbvyYolCB64CRn-65yckShSU
Message-ID: <CAG_fn=Vco04b9mUPgA1Du28+P4q4wgKNk6huCzU34XWitCL8iQ@mail.gmail.com>
Subject: Re: [PATCH v2 RFC 0/7] KFuzzTest: a new kernel fuzzing framework
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Ethan Graham <ethan.w.s.graham@gmail.com>, ethangraham@google.com, 
	andreyknvl@gmail.com, brendan.higgins@linux.dev, davidgow@google.com, 
	dvyukov@google.com, jannh@google.com, elver@google.com, rmoar@google.com, 
	shuah@kernel.org, tarasmadan@google.com, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	dhowells@redhat.com, lukas@wunner.de, ignat@cloudflare.com, 
	herbert@gondor.apana.org.au, davem@davemloft.net, 
	linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="b0NIf/7I";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Sep 8, 2025 at 3:11=E2=80=AFPM Johannes Berg <johannes@sipsolutions=
.net> wrote:
>
> Hi Ethan,

Hi Johannes,

> Since I'm looking at some WiFi fuzzing just now ...
>
> > The primary motivation for KFuzzTest is to simplify the fuzzing of
> > low-level, relatively stateless functions (e.g., data parsers, format
> > converters)
>
> Could you clarify what you mean by "relatively" here? It seems to me
> that if you let this fuzz say something like
> cfg80211_inform_bss_frame_data(), which parses a frame and registers it
> in the global scan list, you might quickly run into the 1000 limit of
> the list, etc. since these functions are not stateless. OTOH, it's
> obviously possible to just receive a lot of such frames over the air
> even, or over simulated air like in syzbot today already.

While it would be very useful to be able to test every single function
in the kernel, there are limitations imposed by our approach.
To work around these limitations, some code may need to be refactored
for better testability, so that global state can be mocked out or
easily reset between runs.

I am not very familiar with the code in
cfg80211_inform_bss_frame_data(), but I can imagine that the code
doing the actual frame parsing could be untangled from the code that
registers it in the global list.
The upside of doing so would be the ability to test that parsing logic
in modes that real-world syscall invocations may never exercise.

>
> As far as the architecture is concerned, I'm reading this is built
> around syzkaller (like) architecture, in that the fuzzer lives in the
> fuzzed kernel's userspace, right?
>

This is correct.

> > We would like to thank David Gow for his detailed feedback regarding th=
e
> > potential integration with KUnit. The v1 discussion highlighted three
> > potential paths: making KFuzzTests a special case of KUnit tests, shari=
ng
> > implementation details in a common library, or keeping the frameworks
> > separate while ensuring API familiarity.
> >
> > Following a productive conversation with David, we are moving forward
> > with the third option for now. While tighter integration is an
> > attractive long-term goal, we believe the most practical first step is
> > to establish KFuzzTest as a valuable, standalone framework.
>
> I have been wondering about this from another perspective - with kunit
> often running in ARCH=3Dum, and there the kernel being "just" a userspace
> process, we should be able to do a "classic" afl-style fork approach to
> fuzzing.

This approach is quite popular among security researchers, but if I'm
understanding correctly, we are yet to see continuous integration of
UML-based fuzzers with the kernel development process.

> That way, state doesn't really (have to) matter at all. This is
> of course both an advantage (reproducing any issue found is just the
> right test with a single input) and disadvantage (the fuzzer won't
> modify state first and then find an issue on a later round.)

From our experience, accumulated state is more of a disadvantage that
we'd rather eliminate altogether.
syzkaller can chain syscalls and could in theory generate a single
program that is elaborate enough to prepare the state and then find an
issue.
However, because resetting the kernel (rebooting machines or restoring
VM snapshots) is costly, we have to run multiple programs on the same
kernel instance, which interfere with each other.
As a result, some bugs that are tricky to trigger become even trickier
to reproduce, because one can't possibly replay all the interleavings
of those programs.

So, yes, assuming we can build the kernel with ARCH=3Dum and run the
function under test in a fork-per-run model, that would speed things
up significantly.

>
> I was just looking at what external state (such as the physical memory
> mapped) UML has and that would need to be disentangled, and it's not
> _that_ much if we can have specific configurations, and maybe mostly
> shut down the userspace that's running inside UML (and/or have kunit
> execute before init/pid 1 when builtin.)

I looked at UML myself around 2023, and back then my impression was
that it didn't quite work with KASAN and KCOV, and adding an AFL
dependency on top of that made every fuzzer a one-of-a-kind setup.

> Did you consider such a model at all, and have specific reasons for not
> going in this direction, or simply didn't consider because you're coming
> from the syzkaller side anyway?

We did consider such a model, but decided against it, with the
maintainability of the fuzzers being the main reason.
We want to be sure that every fuzz target written for the kernel is
still buildable when the code author turns back on it.
We also want every target to be tested continuously and for the bugs
to be reported automatically.
Coming from the syzkaller side, it was natural to use the existing
infrastructure for that instead of reinventing the wheel :)

That being said, our current approach doesn't rule out UML.
In the future, we could adapt the FUZZ_TEST macro to generate stubs
that link against AFL, libFuzzer, or Centipede in UML builds.
The question of how to run those targets continuously would still be
on the table, though.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DVco04b9mUPgA1Du28%2BP4q4wgKNk6huCzU34XWitCL8iQ%40mail.gmail.com.
