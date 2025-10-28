Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTH7QPEAMGQEPFAGWBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id E8DB2C1638B
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Oct 2025 18:39:30 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-2924b3b9d47sf56075545ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Oct 2025 10:39:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761673165; cv=pass;
        d=google.com; s=arc-20240605;
        b=jLySXjH56QQucpYU88xqbSWlBpx2/96mVmg0KwAKTIgUUnbP6A2oPle+BhfeQ7MrNA
         g34RIFSXm1aXPEfLKILh7Dnw4aCIS9IhpFCL4gnU44uILhUHjurcG8hh0901tbwfJt+N
         rbWlmvxuryDmnNNfND6WBsWn2w8mqlD9TqBaT4AMfMG/UaPWxj4MhxrB+tQe1t6cenyJ
         hWAr2tlgCWJxsoiq7O8RXKkKe4E5RTqPP1JgTTeaUx89iwtiA9oDk9Ot8ygZ72qrQbGh
         fdn+g8xk4tpPrS5rbShS7+V8xnB+blgPUmMDm8iYhMB361PJWHU9J/l4+ZmNeKhga6tW
         JU1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GbKMW0SigRQzoCN2imTE56bYMoZ2zpGUnyZSdqXQk/I=;
        fh=MTf3I4BRp32yfhcvYSiPVgAQusZydGKtMFq2qdO0LJw=;
        b=doWFZrhDSmiJ6UKl9V0dHfMrr2ToTdozNxR7HX5xaeQ207pzj8QrYUVeRGJcodC+Id
         nINUpH5pPt5d1Qfv0GHZD1IgDpAmqMGxjEWmdUqNsPUAxI10KW9EF0iRU378vfw46FUZ
         6wZI8ZkEx3TnwDAW4o+ywG3sh9nkIMaIoE/xH+zPNNnHr/HWYIR1aiiA7dB/tVepwFkg
         VBG2dovZ1MoW9cIVbW6knPkAEP6rIG5x3nzL5aFlfKulY2Y+UiyynszQlvoq9Vtiyxm3
         ltKjBhiklrzTUXFmVjbDzuXhO3SLGh9I4waImejyC8YHQEGFFQrxDXlP8qpoRbPMMpvL
         EwCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FN3vOGNF;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761673165; x=1762277965; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GbKMW0SigRQzoCN2imTE56bYMoZ2zpGUnyZSdqXQk/I=;
        b=ZT0L4wMJ6mxuwOmFFR44wcRO+mfKfRXZXyvcDtPvw+W7N88qOldoB0wyxITMcSa3pW
         bRX+FhtQj/2Fc3O3D8c6hbnwGNSRMPZ/CEeUvbzb9TM2wqsadzZM5KfY4g+ft8dnUMqc
         hC0P9onv44BxiMoNewlOYivuXFyINBlbjV/1BS9J01sPtN+2ghBGMD9HYYEKJZdVOuh5
         0tWZfd2/fjZ2gv2BJ1EElaKdbbcf+XTthHa/NBEqcjn7hKcCtt+XMZiYzXkktnfujphC
         u0qY6rdagfGIrhZWrb3VmSp7h0Qv7NTDYn4dGTFUuMPdwU10ob80NNkIdYbm5WhP0ufH
         uYhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761673165; x=1762277965;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GbKMW0SigRQzoCN2imTE56bYMoZ2zpGUnyZSdqXQk/I=;
        b=CSzKnMgusXd8rGviBI3bde93IhZMxpzBcMIjl3JpdCH5YT5MWRU8gNwBAjuqjNk5Dp
         TS0vbdsvMOM7hDEuM5Bx9e/SFfWfTqskViQxyMYwiomJ+lmFe2o+KL2y7+8rvoer219V
         8+hdhq11F4/cCxcTGD6QbF4AagzyR0gidPehiWmQ8a+iJrYuPVK6y/6GLtpTwdNyVsBJ
         4CXTdtDu4+xY8utcXo3W0Wz7lU6gp33KjZaZd3J63QfpQk4qGB7FtEw4GP0Rk+jd49LA
         QKJ018vjJxos0Fc5cZ6xg6uRWJ5oEthsXGYIUzxEAjDwDFusM9Kq8ox5mZuWlMOuY1dH
         LpNQ==
X-Forwarded-Encrypted: i=2; AJvYcCWvZlhEWQ/INX1Sw4qq2xB0qRsdVw2gahwaUVsWBP6+zLjnTC8v2DbwQhWwQ42Tuc5e/sOexg==@lfdr.de
X-Gm-Message-State: AOJu0Yz/dfeGfd+Bhq/EqZRANwyDBvwkAWVc+2CasLIhA75LSplUd6t7
	gkjKwYoiucuDX/TtVXJwjMZEuI7AX+QTYHEFhWCNkFNvVpCNj0ZBITG9
X-Google-Smtp-Source: AGHT+IEcg56+Is8a2Oh+rDdntI7uHVeYMnSSt4rkuTls4LaIU8VpfNU0M9wQtkFXoSdkZ7bfSTK8DA==
X-Received: by 2002:a17:902:da91:b0:288:5d07:8a8f with SMTP id d9443c01a7336-294dee143e3mr154855ad.24.1761673164905;
        Tue, 28 Oct 2025 10:39:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZkK/kbrxsTvadcZ2DjCvse5LyHMDISboA/wGDYxAD/2Q=="
Received: by 2002:a17:902:b095:b0:292:ff46:4f22 with SMTP id
 d9443c01a7336-2946dda89e0ls50103085ad.2.-pod-prod-07-us; Tue, 28 Oct 2025
 10:39:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU7RpbKCsf2L5Vr8on6xrfLb83VRiTRSQ362M3PBJrxk256JsSZyp8KDdPtYGspcKpB5Bhuvljv7ik=@googlegroups.com
X-Received: by 2002:a17:902:db0b:b0:294:cc1d:e2b5 with SMTP id d9443c01a7336-294dea0756amr765385ad.0.1761673163292;
        Tue, 28 Oct 2025 10:39:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761673163; cv=none;
        d=google.com; s=arc-20240605;
        b=XKhebg6xlNpvTDMzTOpV+MMH8WP5PxHRxBz2oZZwQy2tVnUJpbSxtFJc00kFLxnzUj
         36kfwX0lape4TCabix9JnkfA3QtimKZwwS849hlFx8GyvyrWCr0o7gmfcCz3vONYh1fS
         N04A/FgkzwLjE/mKnGG6F/UzS4BO1XObrR8rh/+BZegrgCGqK5KXYz3sNgrI5cJGf0Z6
         H/+YxFgzDAUV/wUaI84a+5DAi9FIwshWjXrLzdaVvuKchy5vQE69klCmzYuDqLkbo94y
         5tPraMUAj4dYze1GuZENqzWPuIUb+mhmvw2EhpTCP2tVHuzrPa4r2Q0YIeDXp21Yl7GW
         l5Fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=e5GKgH/UTKYoqeaateNe5qxhNdabeLnlG8oSSdUoad4=;
        fh=HF/Lfpgr4dRg5Jt5wwc7t5iLw+N9ykMlCzjvaDtx6zI=;
        b=gF/tExyDaj9w8ciDZAJIMj8UKzBt+K0Bx9YO87952pkB5u7Ei3ZzmiFW2RGV0QUuqg
         eMLu8BVE/omNj0u+XxMx8ffYIQuwGhE9DzqNk67jQ81bfk9F9/897b+mulMe1fJw3gFi
         Kc8BpN2fNRMn0zwuJY8YquS0Rgz4SdcLx/ELUwcFmFoLrY91KYH0YycmMxPV+i06Gkcj
         9cu1o0CsvaTh4MzNm6aBQsW3r3Y7SAH3S7QQroYW3cWeez9eEuVT3oksZheg2vHRJp1e
         /DX7jjAITvehu8iT9Qdo26Ku6qMIcyN+ef6ngV5bAjMJI41w8lEzHW3OytCj+t3VqyDa
         tq6w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FN3vOGNF;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2949a8bd5a4si5743165ad.6.2025.10.28.10.39.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Oct 2025 10:39:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id 6a1803df08f44-87c167c0389so70252036d6.3
        for <kasan-dev@googlegroups.com>; Tue, 28 Oct 2025 10:39:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXhq3pJ2pUIbdl+SnlkBedkcAdcc69psusLF5wkTLWdj8FqEZ65p6MIdrwl6/7keXSJoQopi1n3zug=@googlegroups.com
X-Gm-Gg: ASbGnctlHgOSRrZiEkQ23UMZKRMp06zdUXEfP7KAVwHI/aoxDijeYVcS927tPrAlfMD
	Y0tg3mOthAGUC3gyLHIa+5u1Z0vztwJ5nWwbHYi655sT2SpDFvqbBMBT7ddBRH3Kwky6b4bjRS2
	mFR3Gjkp94gqjXbbLaYrMO1m0sUwjwMc0j0l0QIM7T6y6pDpRyL8HL6tjgo+nL+cQAZdZ+M1swf
	OG1vHiKgVs8HGQ8hwAQUaZAStx8C9Yo8uj4yWjs3vVvnvG1FwXYi0/04YSkDhiqfwJQUCDpe+jc
	h1lL2vBMwYP/P7wN6pdoGfS3Vw==
X-Received: by 2002:a05:6214:40d:b0:87c:2b29:2613 with SMTP id
 6a1803df08f44-87ffb13ae3fmr67954756d6.50.1761673161744; Tue, 28 Oct 2025
 10:39:21 -0700 (PDT)
MIME-Version: 1.0
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
 <3562eeeb276dc9cc5f3b238a3f597baebfa56bad.camel@sipsolutions.net>
 <CANgxf6xOJgP6254S8EgSdiivrfE-aJDEQbDdXzWi7K4BCTdrXg@mail.gmail.com> <438ff89e22a815c81406c3c8761a951b0c7e6916.camel@sipsolutions.net>
In-Reply-To: <438ff89e22a815c81406c3c8761a951b0c7e6916.camel@sipsolutions.net>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Oct 2025 18:38:43 +0100
X-Gm-Features: AWmQ_bnW72aQYooWWGflqdYTwRU7KZczsY8iNyINpHaHoghSdwZyWmyrA5jTR-Q
Message-ID: <CAG_fn=XSUw=4tVpKE7Q+R2qsBzbA5+_XC1xH=goxAUZiRD7iyQ@mail.gmail.com>
Subject: Re: [PATCH v2 0/10] KFuzzTest: a new kernel fuzzing framework
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Ethan Graham <ethan.w.s.graham@gmail.com>, ethangraham@google.com, 
	andreyknvl@gmail.com, andy@kernel.org, brauner@kernel.org, 
	brendan.higgins@linux.dev, davem@davemloft.net, davidgow@google.com, 
	dhowells@redhat.com, dvyukov@google.com, elver@google.com, 
	herbert@gondor.apana.org.au, ignat@cloudflare.com, jack@suse.cz, 
	jannh@google.com, kasan-dev@googlegroups.com, kees@kernel.org, 
	kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de, 
	rmoar@google.com, shuah@kernel.org, sj@kernel.org, tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FN3vOGNF;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as
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

On Fri, Oct 24, 2025 at 10:38=E2=80=AFAM Johannes Berg
<johannes@sipsolutions.net> wrote:
>
> Hi Ethan, all,


Hi Johannes,

> > I would argue that it only depends on syzkaller because it is currently
> > the only fuzzer that implements support for KFuzzTest. The communicatio=
n
> > interface itself is agnostic.
>
> Yeah I can see how you could argue that. However, syzkaller is also
> effectively the only fuzzer now that supports what you later call "smart
> input generation", and adding it to any other fuzzer is really not
> straight-forward, at least to me. No other fuzzer seems to really have
> felt a need to have this, and there are ... dozens?

Structure-aware fuzzing is not unique to syzkaller, nor are domain
constraints for certain values.
https://github.com/google/fuzztest is one example of a fuzzer that
supports both.
libFuzzer also supports custom mutators
(https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing=
.md)

> > Since a KFuzzTest target is
> > invoked when you write encoded data into its debugfs input file, any
> > fuzzer that is able to do this is able to fuzz it - this is what syzkal=
ler
> > does. The bridge tool was added to provide an out-of-the-box tool
> > for fuzzing KFuzzTest targets with arbitrary data that doesn't depend
> > on syzkaller at all.
>
> Yes, I understand, I guess it just feels a bit like a fig-leaf to me to
> paper over "you need syzkaller" because there's no way to really
> (efficiently) use it for fuzzing.

When designing KFuzzTest, we anticipated two potential user scenarios:
1. The code author develops the fuzz test and runs it locally to
ensure its sanity and catch obvious errors.
2. The fuzz test lands upstream and syzkaller runs it continuously.

Ethan initially developed tools for both scenarios on the syzkaller
side, prioritizing simplicity of use over the diversity of potential
non-default fuzzing engines.
However, because smoke testing does not require a syzkaller
dependency, he added the bridge utility (I believe David Gow suggested
it).
That utility is easy to use for smoke testing, as it requires only a
one-line structure description.
I understand it may not be suitable for users who want to extensively
fuzz a particular test on their own machine without involving
syzkaller.

I agree we can do a better job by implementing some of the following option=
s:
1. For tests without nested structures, or for tests that request it
explicitly, allow a simpler input format via a separate debugfs file.
2. Export the constraints/annotations via debugfs in a string format
so that fuzzers do not need vmlinux access to obtain them.
3. Export the fuzz test input structure as a string. (We've looked
into this and deemed it infeasible because test inputs may reference C
structures, and we don't have a reflection mechanism that would allow
us to dump the contents of existing structs).


> > This is exactly right. It's not used by syzkaller, but this is how it's
> > intended to work when it's used as a standalone tool, or for bridging
> > between KFuzzTest targets and an arbitrary fuzzer that doesn't
> > implement the required encoding logic.
>
> Yeah I guess, but that still requires hand-coding the descriptions (or
> writing a separate parser), and notably doesn't work with a sort of in-
> process fuzzing I was envisioning for ARCH=3Dum. Which ought to be much
> faster, and even combinable with fork() as I alluded to in earlier
> emails.

Can you describe the interface between the fuzz test and the fuzzing
engine that you have in mind?
For ARCH=3Dum, if you don't need structure awareness, I think the
easiest solution would be to make FUZZ_TEST wrap the code into
something akin to LLVMFuzzerTestOneInput()
(https://llvm.org/docs/LibFuzzer.html) that would directly pass random
data into the function under test. The debugfs interface is probably
excessive in this case.

But let's say we want to run in-kernel fuzzing with e.g. AFL++ - will
a simplified debugfs interface solve the problem?
What special cases can we omit to simplify the interface?

> I mean, yeah, I guess but ... Is there a fuzzer that is able generate
> such input? I haven't seen one. And running the bridge tool separately
> is going to be rather expensive (vs. in-process like I'm thinking
> about), and some form of data extraction is needed to make this scale at
> all.
>
> Sure, I can do it all manually for a single test, but is it really a
> good idea that syzkaller is the only thing that could possibly run this
> at scale?

Adding more fuzzing engines will not automatically allow us to run
this at scale.
For that, we'll need a continuous fuzzing system to manage the kernels
and corpora, report bugs, find reproducers, and bisect the causes.
I don't think building one for another fuzzing engine will be worth it.
That said, we can help developers better fuzz their code during local
runs by not always requiring the serialization format.

> > You're right that the provided examples don't leverage the feature of
> > being able to pass more complex nested data into the kernel. Perhaps
> > for a future iteration, it might be worth adding a target for a functio=
n
> > that takes more complex input. What do you think?
>
> Well, I guess my thought is that there isn't actually going to be a good
> example that really _requires_ all this flexibility. We're going to want
> to test (mostly?) functions that consume untrusted data, but untrusted
> data tends to come in the form of a linear blob, via the network, from a
> file, from userspace, etc. Pretty much only the syscall boundary has
> highly structured untrusted data, but syzkaller already fuzzes that and
> we're not likely to write special kfuzztests for syscalls?

We are not limited to fuzzing parsers of untrusted data. The idea
behind KFuzzTest is to validate that a piece of code can cope with any
input satisfying the constraints.
We could just as well fuzz a sorting algorithm or the bitops.
E.g. Will Deacon had the idea of fuzzing a hypervisor, which
potentially has many parameters, not all of which are necessarily
blobs.

> > I'm not sure how much of the kernel complexity really could be reduced
> > if we decided to support only simpler inputs (e.g., linear buffers).
> > It would certainly simplify the fuzzer implementation, but the kernel
> > code would likely be similar if not the same.
>
> Well, you wouldn't need the whole custom serialization format and
> deserialization code for a start, nor the linker changes around
> KFUZZTEST_TABLE since run-time discovery would likely be sufficient,
> though of course those are trivial. And the deserialization is almost
> half of the overall infrastructure code?

We could indeed organize the code so that simpler test cases (e.g. the
examples provided in this series) do not require the custom
serialization format.
I am still not convinced the whole serialization idea is useless, but
perhaps having a simplified version will unblock more users.

>
> Anyway, I don't really know what to do. Maybe this has even landed by
> now ;-) I certainly would've preferred something that was easier to use
> with other fuzzers and in-process fuzzing in ARCH=3Dum, but then that'd
> now mean I need to plug it in at a completely different level, or write
> a DWARF parser and serializer if I don't want to have to hand-code each
> target.
>
> I really do want to do fuzz testing on wifi, but with kfuzztest it
> basically means I rely on syzbot to actually run it or have to run
> syzkaller myself, rather than being able to integrate it with other
> fuzzers say in ARCH=3Dum. Personally, I think it'd be worthwhile to have
> that, but I don't see how to integrate it well with this infrastructure.

Can you please share some potential entry points you have in mind?
Understanding which functions you want to fuzz will help us simplify the fo=
rmat.

Thank you for your input!

> Also, more generally, it seems unlikely that _anyone_ would ever do
> this, and then it's basically only syzbot that will ever run it.
>
> johannes
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion visit https://groups.google.com/d/msgid/kasan-dev=
/438ff89e22a815c81406c3c8761a951b0c7e6916.camel%40sipsolutions.net.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXSUw%3D4tVpKE7Q%2BR2qsBzbA5%2B_XC1xH%3DgoxAUZiRD7iyQ%40mail.gmail.c=
om.
