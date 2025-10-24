Return-Path: <kasan-dev+bncBD2NJ5WGSUOBB4XV5TDQMGQEH236MZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 88505C05155
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 10:38:12 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-470fd92ad57sf17936415e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 01:38:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761295092; cv=pass;
        d=google.com; s=arc-20240605;
        b=RAQNzDdtfpSkNv/DLbJLLLPWvp+gTBKFwcckHtKLIdzJNRBsRMO67hPLx1dSEhcLbB
         rDMKDeCfOBaI247pxwxGNNB3jDxP34qFSGSJdedy6DIqKdLXs+Fi1ZNAQjrfcNDWb8D8
         5QgEhnlYvpfJxK8haIyRq7V7MXQgA+1dOtVcXydUCPU38A8M8AKXW+6sCy/azVS1xsos
         0LviWsChKcKrRkziXKP04L1Ds/cDdnVcfkUEpEvYEd9TPo0uCZWh8I/c2HI5i2nmn31K
         xoBODcRgJArJAwbnheDEF+IvaByYEPh7O6uaVJj9H88LeuPk7LUGHHzQFvkqHrEgUQCa
         KAIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=7Ggt0CPUd0OheiznM8HPB8oT3GiqAfqGqqZbS1yHfGc=;
        fh=RJZmOv67QU6RLWSOr6n256lYSjYDB3gaUky00BwOYHQ=;
        b=PzluvvSaxlTwOLPjNNsuYY9YwuBO7y2dGmQWuqIwd+xiCeccSLdr7iGWEsX43TlzEQ
         djZj+5z9pjA1jSXsbgvmiM6D4/yRclk63rmg/ApX7Zf6NiO/e3AohGlw2Ryae8PhBhc4
         RCxQRtMneLR7L9DSK6fY/8WjoC2PoDqNBbJCJmWZi1oSUtbIHMmK4bOka38gXBLVxTaX
         KY+7E1ioNJcarsjLMDrjvQLbezXpXGTfspnvU/dWESqP7PSS7Sdf0+eMAE8w257U1gam
         1EpepBNwtXIj5VLZ1qoknplILdJ2xXldU1t9BWDjeXVw0Ec4zta5gb0WNFp32d+VieOP
         cdQg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=C9g0Vqbd;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761295092; x=1761899892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7Ggt0CPUd0OheiznM8HPB8oT3GiqAfqGqqZbS1yHfGc=;
        b=O/FBlyhf1J972wVD0YMYkXC2SWRdQlKQJ9WelANpYxKvBeb21Sa7h4LMnpZ0x3QQxJ
         KchMmm+ppmfdTYhI3qOI5gscyO3sFr3sWzWb1XyjioRatxWMV5gT6K1eK9h2XHI2MdWa
         cS8j0p9JcNnO76+nWE6bbhmIALcBMkDRF1mc1kfAzUZfzveETdtAvYmSVaSXWo+louMD
         I8RI7R2gqzIqwBPmPmFNdH1OY/XARMR+4tYo3CWKWcgibCp4ht1DLFJzoILY5/kfdMKF
         Qf8+3MMS19LUKOHZMGmVe+IYpBQJrJAQFFVeqfDQRpEjsPIfpXemno9rD8gWZw1zl0M4
         zHFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761295092; x=1761899892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7Ggt0CPUd0OheiznM8HPB8oT3GiqAfqGqqZbS1yHfGc=;
        b=Z//BcuZ8sIWS41biIIfY8jtk0DZmIb3mXqdLIQ3uwj8htHCB5aE49pVbmTSA8KV/S7
         JvM8IgjwPG5Qp2gTg1MuUB4+rZw6OpNAHzTiUH9mJaJeke/rxofIMwLbckXAcKGKxPrF
         i7pBc6fvM+GMQLg6uMFiPe6xmjh34RcztOqjED8GGOdiSQC7XmfiGY19iqrBs0gEZgVz
         aqfe79wYZdSO4Ch5IbnKvHsRr/Vec+srEWoHtW3wtIKhX1h1q/mBEoVn8THpXk1K7366
         m4B7OoopfLGCK0+0dj6rMm/gYrjGGqq+lVWe63tQ3ruIX3yNzfStVTtB8SJJ49ann/x5
         FUzg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWlJt7ImoyqhKVQu+R4ruSuf5e/uvK32HcUltJ9h752cSX2eBoWPYRHZYajKu2HblaTF/ZEDQ==@lfdr.de
X-Gm-Message-State: AOJu0YwRfo42/gIA0HtJYpxbR8l3rroyFiSx2itP0ROVsAypvMWEdoau
	fIvE9uS5TYs1VWL9K2GaKqLQ4nr6575qgRgcgo9kEE3BdCi2TK1iY8Nn
X-Google-Smtp-Source: AGHT+IE3Bk+1qy1I81SsDQlLCSYdUvZ/Jl3MogbaHZlMp5fUaN1qstbOAGEYeECN4gZhEPj6pq0hgQ==
X-Received: by 2002:a05:6000:420a:b0:429:8bfe:d842 with SMTP id ffacd0b85a97d-4298bfed9c7mr2596940f8f.4.1761295091594;
        Fri, 24 Oct 2025 01:38:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bKtZjpFCWCu7+6A9MfUoNeb79yHOH4guk1iWOINO0ALQ=="
Received: by 2002:a05:6000:2889:b0:3ec:2d76:38c0 with SMTP id
 ffacd0b85a97d-42989d9b9eels842852f8f.1.-pod-prod-05-eu; Fri, 24 Oct 2025
 01:38:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUWVMGP8PHtpqdg86IVyrEjh5Kd8PzTlTDCwymKEfoeemqRao4sofBiL4Gjcon+xte6KkF0nZrzTbA=@googlegroups.com
X-Received: by 2002:a5d:64e7:0:b0:429:8bd7:774a with SMTP id ffacd0b85a97d-4298bd77939mr4028628f8f.40.1761295088807;
        Fri, 24 Oct 2025 01:38:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761295088; cv=none;
        d=google.com; s=arc-20240605;
        b=RSiR0cIeZkmGgs6rPx53Jwz3XRfxXUbVwM1K6KtXnLc4o4SA7qJTTWxuWvvYs/bmwt
         rUrYj/SqYXzJs0SYR9NjeAwzK7TncpKzU8daVWHUmCzz1XjvsUdXKt6pQeEVNQHL7L83
         Pkgn8gW7CTVgUuMsIlz8V1kwS+pyOZXh1d+SVKWXbST/G4vB1N8ABmul1fwYnFEdd00s
         jcKGbWT6OOJ5JqI4hZt2+rKKHXfmtwjeDc45SywmXu35a42FyOsx27u80myR4y5GcH5X
         9n6KnDdVfJWCQvQ4N8Tr3kkUUFg22dYduGi5f+1TFolxtBhkupXx872GJ9l/tyjh5Dot
         uGBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=L7lT/wMZ1LMdwxMJTrMezCGdtazbt1qIWepTcDamS+o=;
        fh=wYDXYPGc8/Q9lXYvp+m9p1nduNpQ1NFwCnMrps1pwww=;
        b=U/5kIhW7VYGQcmNMbQIgD0Y/s4Hyu77yy+yxUEFIcsepZXXGMaPhFnfuJIDMZTqYo1
         gi0HbaCc6a4UuGh/6BWFIW5wNRknv9i1vF/uU4Gk/FEAMZvJ0N1SQPKys4PEcIfqRDQJ
         tUojDqp1eFN8jOg631GVkLOyx3Xr1A/t7Vbtcn7ijE2/CGV/T7aFz3pJByyUgSxaf0mK
         3PwuEcYHxDQwpQ6beBmv9t5fAv2sS0fuZ/YjZ/s6IAgnqkxZbTy/1VYvOQpgu6hFmduj
         gwiRq1yZ9FGRoxpK2JHWS7QZOZNItoSvEMOx1OTPpV7WxGTzVODgFHIm5pRqR1OLdx+i
         PlnQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=C9g0Vqbd;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-429898a0117si92756f8f.5.2025.10.24.01.38.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Oct 2025 01:38:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98.2)
	(envelope-from <johannes@sipsolutions.net>)
	id 1vCDJ9-00000002PD9-0Qfp;
	Fri, 24 Oct 2025 10:37:59 +0200
Message-ID: <438ff89e22a815c81406c3c8761a951b0c7e6916.camel@sipsolutions.net>
Subject: Re: [PATCH v2 0/10] KFuzzTest: a new kernel fuzzing framework
From: Johannes Berg <johannes@sipsolutions.net>
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, glider@google.com, andreyknvl@gmail.com, 
	andy@kernel.org, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com,
 dvyukov@google.com, 	elver@google.com, herbert@gondor.apana.org.au,
 ignat@cloudflare.com, jack@suse.cz, 	jannh@google.com,
 kasan-dev@googlegroups.com, kees@kernel.org, 	kunit-dev@googlegroups.com,
 linux-crypto@vger.kernel.org, 	linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, lukas@wunner.de, 	rmoar@google.com, shuah@kernel.org,
 sj@kernel.org, tarasmadan@google.com
Date: Fri, 24 Oct 2025 10:37:57 +0200
In-Reply-To: <CANgxf6xOJgP6254S8EgSdiivrfE-aJDEQbDdXzWi7K4BCTdrXg@mail.gmail.com> (sfid-20250925_103550_253525_F09A62BB)
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
	 <3562eeeb276dc9cc5f3b238a3f597baebfa56bad.camel@sipsolutions.net>
	 <CANgxf6xOJgP6254S8EgSdiivrfE-aJDEQbDdXzWi7K4BCTdrXg@mail.gmail.com>
	 (sfid-20250925_103550_253525_F09A62BB)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.56.2 (3.56.2-2.fc42)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=C9g0Vqbd;       spf=pass
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

Hi Ethan, all,

Sorry, my=C2=A0current foray into fuzzing got preempted by other things ...

> > So ... I guess I understand the motivation to make this easy for
> > developers, but I'm not sure I'm happy to have all of this effectively
> > depend on syzkaller.
>=20
> I would argue that it only depends on syzkaller because it is currently
> the only fuzzer that implements support for KFuzzTest. The communication
> interface itself is agnostic.

Yeah I can see how you could argue that. However, syzkaller is also
effectively the only fuzzer now that supports what you later call "smart
input generation", and adding it to any other fuzzer is really not
straight-forward, at least to me. No other fuzzer seems to really have
felt a need to have this, and there are ... dozens?

> > the record, and everyone else who might be reading, here's my
> > understanding:
> >=20
> >  - the FUZZ_TEST() macro declares some magic in the Linux binary,
> >    including the name of the struct that describes the necessary input
> >=20
> >  - there's a parser in syzkaller (and not really usable standalone) tha=
t
> >    can parse the vmlinux binary (and doesn't handle modules) and
> >    generates descriptions for the input from it
> >=20
> >  - I _think_ that the bridge tool uses these descriptions, though the
> >    example you have in the documentation just says "use this command fo=
r
> >    this test" and makes no representation as to how the first argument
> >    to the bridge tool is created, it just appears out of thin air
>=20
> syzkaller doesn't use the bridge tool at all.=C2=A0

Right.

> Since a KFuzzTest target is
> invoked when you write encoded data into its debugfs input file, any
> fuzzer that is able to do this is able to fuzz it - this is what syzkalle=
r
> does. The bridge tool was added to provide an out-of-the-box tool
> for fuzzing KFuzzTest targets with arbitrary data that doesn't depend
> on syzkaller at all.

Yes, I understand, I guess it just feels a bit like a fig-leaf to me to
paper over "you need syzkaller" because there's no way to really
(efficiently) use it for fuzzing.

> In the provided examples, the kfuzztest-bridge descriptions were
> hand-written, but it's also feasible to generate them with the ELF
> metadata in vmlinux. It would be easy to implement support for
> this in syzkaller, but then we would depend on an external tool
> for autogenerating these descriptions which we wanted to avoid.

Oh, I get that you wouldn't necessarily want to have a dependency on
syzkaller in the kernel example code, but in a sense my argument is that
there's no such tool at all since syzkaller cannot output anything, and
then you need to write all the descriptions by hand. Which is fine for
an _example_ but really doesn't scale to actually running fuzzing.

So then we're mostly back to "you need syzkaller to run fuzzing against
this", which at least to me isn't a great situation.

> >  - the bridge tool will then parse the description and use some random
> >    data to create the serialised data that's deserialized in the kernel
> >    and then passed to the test
>=20
> This is exactly right. It's not used by syzkaller, but this is how it's
> intended to work when it's used as a standalone tool, or for bridging
> between KFuzzTest targets and an arbitrary fuzzer that doesn't
> implement the required encoding logic.

Yeah I guess, but that still requires hand-coding the descriptions (or
writing a separate parser), and notably doesn't work with a sort of in-
process fuzzing I was envisioning for ARCH=3Dum. Which ought to be much
faster, and even combinable with fork() as I alluded to in earlier
emails.

> > I was really hoping to integrate this with ARCH=3Dum and other fuzzers[=
1],
> > but ... I don't really think it's entirely feasible. I can basically
> > only require hard-coding the input description like the bridge tool
> > does, but that doesn't scale, or attempt to extract a few thousand line=
s
> > of code from syzkaller to extract the data...
>=20
> I would argue that integrating with other fuzzers is feasible, but it doe=
s
> require some if not a lot of work depending on the level of support. syzk=
aller
> already did most of the heavy lifting with smart input generation and mut=
ation
> for kernel functions, so the changes needed for KFuzzTest were mainly:
>=20
> - Dynamically discovering targets, but you could just as easily write a
>   syzkaller description for them.
> - Encoding logic for the input format.
>=20
> Assuming a fuzzer is able to generate C-struct inputs for a kernel functi=
on,
> the only further requirement is being able to encode the input and write
> it into the debugfs input file. The ELF data extraction is a nice-to-have
> for sure, but it's not a strict requirement.

I mean, yeah, I guess but ... Is there a fuzzer that is able generate
such input? I haven't seen one. And running the bridge tool separately
is going to be rather expensive (vs. in-process like I'm thinking
about), and some form of data extraction is needed to make this scale at
all.

Sure, I can do it all manually for a single test, but is it really a
good idea that syzkaller is the only thing that could possibly run this
at scale?

> > I guess the biggest question to me is ultimately why all that is
> > necessary? Right now, there's only the single example kfuzztest that
> > even uses this infrastructure beyond a single linear buffer [2]. Where
> > is all that complexity even worth it? It's expressly intended for
> > simpler pieces of code that parse something ("data parsers, format
> > converters").
>=20
> You're right that the provided examples don't leverage the feature of
> being able to pass more complex nested data into the kernel. Perhaps
> for a future iteration, it might be worth adding a target for a function
> that takes more complex input. What do you think?

Well, I guess my thought is that there isn't actually going to be a good
example that really _requires_ all this flexibility. We're going to want
to test (mostly?) functions that consume untrusted data, but untrusted
data tends to come in the form of a linear blob, via the network, from a
file, from userspace, etc. Pretty much only the syscall boundary has
highly structured untrusted data, but syzkaller already fuzzes that and
we're not likely to write special kfuzztests for syscalls?

> I'm not sure how much of the kernel complexity really could be reduced
> if we decided to support only simpler inputs (e.g., linear buffers).
> It would certainly simplify the fuzzer implementation, but the kernel
> code would likely be similar if not the same.

Well, you wouldn't need the whole custom serialization format and
deserialization code for a start, nor the linker changes around
KFUZZTEST_TABLE since run-time discovery would likely be sufficient,
though of course those are trivial. And the deserialization is almost
half of the overall infrastructure code?

Anyway, I don't really know what to do. Maybe this has even landed by
now ;-) I certainly would've preferred something that was easier to use
with other fuzzers and in-process fuzzing in ARCH=3Dum, but then that'd
now mean I need to plug it in at a completely different level, or write
a DWARF parser and serializer if I don't want to have to hand-code each
target.

I really do want to do fuzz testing on wifi, but with kfuzztest it
basically means I rely on syzbot to actually run it or have to run
syzkaller myself, rather than being able to integrate it with other
fuzzers say in ARCH=3Dum. Personally, I think it'd be worthwhile to have
that, but I don't see how to integrate it well with this infrastructure.

Also, more generally, it seems unlikely that _anyone_ would ever do
this, and then it's basically only syzbot that will ever run it.

johannes

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
38ff89e22a815c81406c3c8761a951b0c7e6916.camel%40sipsolutions.net.
