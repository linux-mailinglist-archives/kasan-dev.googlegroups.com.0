Return-Path: <kasan-dev+bncBD2NJ5WGSUOBB2GAQ3DAMGQEYIVGFSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id C7C7AB51CB6
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 17:59:37 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-61d1327a8besf4752924a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 08:59:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757519977; cv=pass;
        d=google.com; s=arc-20240605;
        b=dOF5vjOMRGFRoMYONL4cli0ZL5cqI2Rl0iPY1l9AoU2N4STweenhsdrlDLxKmYLJEY
         2UWaOIO6DN0vtiltzwqYcaN1kpZ9uQ6a7rtuhaezaQADyA17b37x7WtZOq61wWTJcW8t
         dOv4zlqILU1Qw6Czqrifk/zbogEujo7YWZ+hWITLuo8PmA3V9MdYjQAYWHfDWLDKlY84
         t/d8NKGukQTGGRF+I9TIyf28HP/yteuduxMUV/rjkbntJhbmZVKVxZeAUeA3OcbtUEt6
         19YPeU2BTSCO4FwHGnLKmrP0ROvhvrhyiWrYaiI5UAi+83BNVShSOmEa1NxdGk65Cd19
         N57g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=FPs57gckjjVyxCrw6mfu00IekyiGfgZ7B370yJcjr0M=;
        fh=uO7s1EjujYZ8Ey8qcLw56SAIHJYy1kihLH60ICecbPo=;
        b=VeHfR0bQKkJNOuNiZ2zi4cEWIiU40mpcL95kDNpMtQNwP+WXm2dtuaZRswDSmrz0pg
         euMDezsGFLjdSwsck89lepRQ7Jkl++mPhhu8uXNy4cncGOm4VFFynx7wbSNk66pS6N4k
         Sk54kkmBioz3IFEJcKHtI84hpD/j7z7UTAMPZpmDKVLKIXUDU5g6NH6z53GCDliRLiAu
         VNWBGDJ+HHcTTZcCJhVY5CkqKj1ny8xsgklW+Jv0MSBfLYRalbVxTXxp6FAU+FfCDOtm
         6oHtWNtlHz6iEF6n5TR3DkfEG7gTsR40A5YLp/jnf0mCukGmB3Vs7DXuj21s9KfkWbw4
         vdYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=F8HYmZwF;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757519977; x=1758124777; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FPs57gckjjVyxCrw6mfu00IekyiGfgZ7B370yJcjr0M=;
        b=LYobyjZEIzoDDd9S8ZZptJzJQ1szzz6nHA1bRjnCul3OX0/QwmRFnJuaip99LHKpxu
         hxR51a9dxNXkc2P8OONv6P+3/r3+oZkC+xABKxNrz2KugyzO2Olx9PiV3gWTgr2Mv0cv
         g8hAKHMUbZ7XAHCBGhjZmqHFzVmYjy8nqeRtTPytNDkUSiEMC1cXt0XvgWHKRjjlIc9C
         Sps5rXegJtDZB0UzW5Fg9jZcS+ODrT2ehRs+bI0ZnJ2f3PZPi/WQLHT3SEyDWUDUstPd
         grJJyPmiZvJyJDTVkH6EPdIv9Un324+v+hKFM1i0uLzLfP/tH4xaz3rk0MKutfVy4m1m
         4lGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757519977; x=1758124777;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=FPs57gckjjVyxCrw6mfu00IekyiGfgZ7B370yJcjr0M=;
        b=kUT9RgiBJDpSCu9rwtGFLcgyBOHfc1c7Ik2qT1RT9vBBWWasQ1JkNA4HSYG6IPd1dT
         v5OciVUNPJeaYJwJ6ewI3YY4n5M2A48nD4WIXsMB5BGVx7GFyMHBJTWYOk8axwPZB0em
         m9umZJ5rHmc7d6A5NJ421g2UFDLIL5pa33PZPOVsFgoLZ8bGQAP43NIP3yROE9skBMld
         H/IPU5lm/FGgkwAAKcQUKRN+1eF4PBxij71hvfnLdPJxz1eRJ3ZKRYn0QCnHYHwnUH29
         aCJzDd+pIgU9CWcx9AE676euFivMtjv3yVgJKEAeIGFOuo6qzv0XaSnOa+LSmy6cBHZB
         f0zw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV/3OG6lAtn1L4H3VXmk3bd0+F6SjRWflfIvauS17pekJiXb7sQy4+Ehwspdq18xCtWID5iFw==@lfdr.de
X-Gm-Message-State: AOJu0YxTwsBE2pBFuL5sP2DUxu3VMuaUFS4RxOUnEwCJGcp28MMo0fLe
	/JascQiz69wwkfYxATr9IrvWmwhOahlUHroHQ1imwnf5XMPihqkJb1ol
X-Google-Smtp-Source: AGHT+IEJvFReJ+yLxXlhE44KoSE7t2zn2SlTtUepJ12rVOHgvmZI3bYAM4b1OdIfZysNABr1Hfjk4g==
X-Received: by 2002:a05:6402:50ce:b0:62c:75bf:6501 with SMTP id 4fb4d7f45d1cf-62c75bf66a4mr4730136a12.15.1757519976888;
        Wed, 10 Sep 2025 08:59:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd67sykICpbOKkcINUaBMkG/lKtmqaqzjbjq2QvFPOZx8g==
Received: by 2002:a05:6402:44c6:b0:628:46e0:3cd8 with SMTP id
 4fb4d7f45d1cf-62846e03dcdls3071415a12.0.-pod-prod-02-eu; Wed, 10 Sep 2025
 08:59:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU7AZCayzNuU5aVRA3M37TnNEzSYBSyZGiupwGZGLqN00juIWgd/3mQtzKPUd/CwPtyiJW0yIbs0Ow=@googlegroups.com
X-Received: by 2002:a05:6402:2355:b0:628:7716:357c with SMTP id 4fb4d7f45d1cf-6287716398amr10370151a12.25.1757519973952;
        Wed, 10 Sep 2025 08:59:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757519973; cv=none;
        d=google.com; s=arc-20240605;
        b=hVqOqgyBLtmS+dMoKxJyCTF4k+1fU30Q/zFtwMLLlci4jrWE0cZZV62GxLzKpBvXqu
         jaeC+/q8kDFIATKwtyDtFVfuEIGyLcoMSPqxYazmwpFrjdm+iz688vXG0ILzQdWwEj05
         D5vKwORuL9mrLjC960mH/AK9b4ySrjBizPHqVlCFjBdJVxsKYbZVzfTD6vddT9p+ivYh
         43PylVv+P3akj+iI6rCOXO5QeFVfcto2JQ3XtW8Gr1shlK8TZGIJBKV5BuqmXBDLBC/c
         5U69HZQ/9lfhP5JOwE5GRCx7x85Z6HLzZbm27hHG7uTo3EfCBc4GHd4JJe9tiUmA+PDV
         17dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=rLlleifu0thdpPhsg3VNchjcqxHN/buCBymoJpUNlHE=;
        fh=YP+DEuyyQJUxw35gMltrpE/KiLFZ4UavdZBWehXpHn0=;
        b=VxSnc8bZTfzrbDZAtPfkawVF7yEzKjykKA49reqvKTjbogBe8tmvU9p4gt1E+y+8hR
         80PYT8ijxt8gQpMJ0+Sp2Q78vylmigKmTNZqfXgabCkfhnPXk8PA0COJdO2bg6NbTRkc
         GbXwEK4s4c+YI11R4v4rUGKwjzT104HSpvGMmSQlsbhWDMnd1+A27Vgxx27BPPgFxJGW
         vrX8Qy3PBrrS5m9+8e7E6q+Kzkm4SHxnXDaeBKB3fKKxgLcpd+I9VMGba5yVVr81w2zU
         B7kpvLJxOmWtOEkHfBSzvQHRvOlUqhmyerio9d8pG9HoUl/W1PpBtAGpexFPxJq5xRQk
         QZBA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=F8HYmZwF;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6284ebdb151si271443a12.2.2025.09.10.08.59.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Sep 2025 08:59:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98.2)
	(envelope-from <johannes@sipsolutions.net>)
	id 1uwNEF-0000000D9a5-0csR;
	Wed, 10 Sep 2025 17:59:27 +0200
Message-ID: <6eda1208c08130e00cb54e557bc4858ce10a4a94.camel@sipsolutions.net>
Subject: Re: [PATCH v2 RFC 0/7] KFuzzTest: a new kernel fuzzing framework
From: Johannes Berg <johannes@sipsolutions.net>
To: Alexander Potapenko <glider@google.com>
Cc: Ethan Graham <ethan.w.s.graham@gmail.com>, ethangraham@google.com, 
	andreyknvl@gmail.com, brendan.higgins@linux.dev, davidgow@google.com, 
	dvyukov@google.com, jannh@google.com, elver@google.com, rmoar@google.com, 
	shuah@kernel.org, tarasmadan@google.com, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, 	dhowells@redhat.com, lukas@wunner.de,
 ignat@cloudflare.com, 	herbert@gondor.apana.org.au, davem@davemloft.net,
 linux-crypto@vger.kernel.org
Date: Wed, 10 Sep 2025 17:59:26 +0200
In-Reply-To: <CAG_fn=Vco04b9mUPgA1Du28+P4q4wgKNk6huCzU34XWitCL8iQ@mail.gmail.com> (sfid-20250910_124126_320471_24812999)
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
	 <513c854db04a727a20ad1fb01423497b3428eea6.camel@sipsolutions.net>
	 <CAG_fn=Vco04b9mUPgA1Du28+P4q4wgKNk6huCzU34XWitCL8iQ@mail.gmail.com>
	 (sfid-20250910_124126_320471_24812999)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.56.2 (3.56.2-2.fc42)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=F8HYmZwF;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

Hi,

Thanks for your response!

> > > The primary motivation for KFuzzTest is to simplify the fuzzing of
> > > low-level, relatively stateless functions (e.g., data parsers, format
> > > converters)
> > 
> > Could you clarify what you mean by "relatively" here? It seems to me
> > that if you let this fuzz say something like
> > cfg80211_inform_bss_frame_data(), which parses a frame and registers it
> > in the global scan list, you might quickly run into the 1000 limit of
> > the list, etc. since these functions are not stateless. OTOH, it's
> > obviously possible to just receive a lot of such frames over the air
> > even, or over simulated air like in syzbot today already.
> 
> While it would be very useful to be able to test every single function
> in the kernel, there are limitations imposed by our approach.
> To work around these limitations, some code may need to be refactored
> for better testability, so that global state can be mocked out or
> easily reset between runs.

Sure, I that'd be possible. Perhaps I'm more wondering if it's actually
desirable, but sounds like at least that's how it was intended to be
used then.

> I am not very familiar with the code in
> cfg80211_inform_bss_frame_data(), but I can imagine that the code
> doing the actual frame parsing could be untangled from the code that
> registers it in the global list.

It could, but I'm actually less worried about the parsing code (it's
relatively simple to review) than about the data model in this code, and
trying to fuzz the data model generally requires the state. See e.g.
https://syzkaller.appspot.com/bug?extid=dc6f4dce0d707900cdea (which I
finally reproduced in a kunit test a few years after this was originally
reported.)

I mean ... I guess now I'm arguing against myself - having the state
there is required to find certain classes of bugs, but not having the
state makes it easier to figure out what's going on :-) A middle ground
would be to have some isolated state for fuzzing any particular "thing",
but not necessarily reset between rounds.

> The upside of doing so would be the ability to test that parsing logic
> in modes that real-world syscall invocations may never exercise.

Sure.

> > > We would like to thank David Gow for his detailed feedback regarding the
> > > potential integration with KUnit. The v1 discussion highlighted three
> > > potential paths: making KFuzzTests a special case of KUnit tests, sharing
> > > implementation details in a common library, or keeping the frameworks
> > > separate while ensuring API familiarity.
> > > 
> > > Following a productive conversation with David, we are moving forward
> > > with the third option for now. While tighter integration is an
> > > attractive long-term goal, we believe the most practical first step is
> > > to establish KFuzzTest as a valuable, standalone framework.
> > 
> > I have been wondering about this from another perspective - with kunit
> > often running in ARCH=um, and there the kernel being "just" a userspace
> > process, we should be able to do a "classic" afl-style fork approach to
> > fuzzing.
> 
> This approach is quite popular among security researchers, but if I'm
> understanding correctly, we are yet to see continuous integration of
> UML-based fuzzers with the kernel development process.

Well, chicken and egg type situation? There are no such fuzzers that are
actually easy to use and/or integrate, as far as I can tell.

I've been looking also at broader fuzzing tools such as nyx-fuzz and
related kafl [1] which are cool in theory (and are intended to address
your "cannot fork VMs quickly enough" issue), but ... while running a
modified host kernel etc. is sufficient for research, it's practically
impossible for deploying things since you have to stay on top of
security etc.

[1] https://intellabs.github.io/kAFL/tutorials/linux/fuzzing_linux_kernel.html

That said, it seems to me that upstream kvm code actually has Intel-PT
support and also dirty page logging (presumably for VM migration), so
I'm not entirely sure what the nyx/kafl host kernel actually really
adds. But I have yet to research this in detail, I've now asked some
folks at Intel who work(ed) on it.

> > That way, state doesn't really (have to) matter at all. This is
> > of course both an advantage (reproducing any issue found is just the
> > right test with a single input) and disadvantage (the fuzzer won't
> > modify state first and then find an issue on a later round.)
> 
> From our experience, accumulated state is more of a disadvantage that
> we'd rather eliminate altogether.

Interesting. I mean, I do somewhat see it that way too from the
perspective of someone faced with inscrutable bug reports, but it also
seems that given enough resources/time, accumulated state lets a fuzzer
find more potential issues.

> syzkaller can chain syscalls and could in theory generate a single
> program that is elaborate enough to prepare the state and then find an
> issue.

Right, mostly, the whole "I found a reproducer now" thing, I guess.

> However, because resetting the kernel (rebooting machines or restoring
> VM snapshots) is costly, we have to run multiple programs on the same
> kernel instance, which interfere with each other.

(see above for the nyx/kafl reference)

> As a result, some bugs that are tricky to trigger become even trickier
> to reproduce, because one can't possibly replay all the interleavings
> of those programs.

Right.

> So, yes, assuming we can build the kernel with ARCH=um and run the
> function under test in a fork-per-run model, that would speed things
> up significantly.

Is it really a speed-up vs. resulting in more readable reports? Possibly
even at the expense of coverage?

But anyway, making that possible was indeed what I was thinking about.
It requires some special configuration and "magic" in UML, but it seems
eminently doable. Mapping KCOV to a given fuzzer's feedback might not be
trivial, but it should be possible too. In theory you could even compile
the whole UML kernel with say afl-clang, I suppose.

> > I was just looking at what external state (such as the physical memory
> > mapped) UML has and that would need to be disentangled, and it's not
> > _that_ much if we can have specific configurations, and maybe mostly
> > shut down the userspace that's running inside UML (and/or have kunit
> > execute before init/pid 1 when builtin.)
> 
> I looked at UML myself around 2023, and back then my impression was
> that it didn't quite work with KASAN and KCOV, and adding an AFL
> dependency on top of that made every fuzzer a one-of-a-kind setup.

I'm not entirely sure about KCOV right now, but KASAN definitely works
today (not in 2023.) I agree that adding a fuzzer on top makes it a one-
of-a-kind setup, but I guess from my perspective adding syzbot/syzkaller
(inside) is really mostly the same, since we don't run that ourselves
right now.

> > Did you consider such a model at all, and have specific reasons for not
> > going in this direction, or simply didn't consider because you're coming
> > from the syzkaller side anyway?
> 
> We did consider such a model, but decided against it, with the
> maintainability of the fuzzers being the main reason.
> We want to be sure that every fuzz target written for the kernel is
> still buildable when the code author turns back on it.
> We also want every target to be tested continuously and for the bugs
> to be reported automatically.
> Coming from the syzkaller side, it was natural to use the existing
> infrastructure for that instead of reinventing the wheel :)

Fair points, though I'd like to point out that really the only reason
this is true is the syzkaller availability: that ensures fuzz tests
would run continuously/automatically, thus ensuring it's buildable
(since you try that) and thus ensuring it'd be maintained. So it all
goes back to syzkaller existing already :-)

Which I'm not arguing is bad, quite the opposite, but I'm also close to
just giving up on the whole UML thing precisely _because_ of it, since
there's no way anyone can compete with Google's deployment, and adding
somewhat competing infrastructure to the kernel will just complicate
matters. Which is maybe unfortunate, because a fork/fuzz model often
seems more usable in practice, and in particular can also be used more
easily for regression tests.

Regression, btw, is perhaps something to consider here in this patch
set? Maybe some side files could be provided with each KFuzzTest that
something (kunit?) would run to ensure that the code didn't regress when
asked to parse those files?

> That being said, our current approach doesn't rule out UML.
> In the future, we could adapt the FUZZ_TEST macro to generate stubs
> that link against AFL, libFuzzer, or Centipede in UML builds.

That's also true, I guess, in some way this infrastructure would be
available for any fuzzer to link to, especially if we do something with
UML as I was thinking about.

Which is also in part why I was asking about the state though, since a
"reset the whole state" approach is maybe a bit more amenable to
actually letting the fuzzer modify state than the current approach.

Then again, given that syzbot always modifies state, maybe I'm changing
my opinion on this and will say that I'm not so sure any more your
intention of fuzzing "low-level, relatively stateless functions" holds
that much water? If in practice syzbot is the thing that runs this, then
that doesn't matter very much apart from having to ensure that it
doesn't modify state in a way that is completely invalid - but to some
extent that'd be a bug anyway, and e.g. memory allocations of a function
can be freed by the fuzztest wrapper code.


I guess I'll research the whole nyx thing a bit more, and maybe
reconsider giving up on the UML-based fork/fuzz model, if I can figure
out a way to integrate it with KFuzzTest and run those tests, rather
than my initial intent of integrating it with kunit. Some infrastructure
could be shared, although I had hoped things like kunit asserts, memory
allocations, etc. would be available to fuzz test code just to be able
to share setup/teardown infrastructure - I guess we'll have to see how
that plays out. :)

Thanks!

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6eda1208c08130e00cb54e557bc4858ce10a4a94.camel%40sipsolutions.net.
