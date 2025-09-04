Return-Path: <kasan-dev+bncBC6OLHHDVUOBBUNP4XCQMGQEFRT4QZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id E90AEB436B6
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Sep 2025 11:11:46 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-8874f33d067sf91823739f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Sep 2025 02:11:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756977105; cv=pass;
        d=google.com; s=arc-20240605;
        b=OiNeA0bYrDTE+D4yiunclCRnTJWN8LeEdLSinoYLsf8CLSLj5MIy4yVb5V7hVtqmf2
         4JH4kmfzs+H/dD+bgk/BnPgCbboAEmzvoQyd96MnESD168Unn9VASjdDvSUo/knGlqvC
         iWiEFLBG9sDuUuX00ikbugTgWHHfStaINeSTAkD0qy9DL+sp56R6j9Nz15R4UKOW4UPG
         QQxhno95UF13sIgm06n+KL59E7FHy0keuwjW/Br+Ctyxa/Dev8WUPQOJLK/3nWKMHezu
         eA9r6sDwBkMDwqXbwRoa7GztdsfaMWjkPCAUagZ/ahQ+FXjFynT2Jpojv6CPn4qjODr5
         Ix7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Jaxl79cV7AnlX0poZbwlmOGRhLOdtJvToJbqEFrEK14=;
        fh=6NoJqZNavfS35BdEuhLpNGqbuRh4LoNO6A/U6/SIPV4=;
        b=AapkPEpstK1M/fb7+y/IDxxd5w20ImSXauEc9L6DbhxQNOmw5G4XcmQEVH/hHwBQ1c
         svvBt338L6QW/wmDXjumVvmhhFFNNy+BdkHAJs9c+bPlQndpPGzCFhXsWVu835AILHn3
         /90ofVn3e6XmB0M/A4HU/IRSS8aeYBV3bNmDbBcqBNvjgc5ls0M2eArfo3xG80nwj0RZ
         JoV9JIGucv1AAUjwVahZGJPHsTqTHRGY2mP513SgbCQGrNTPH41aBintYAftgoDOXDbH
         rukeOH2MNcwjWbDUQ8iU8Z7kSkrH5jLbfu2a/3IF4rwYmu232gy2V/CLzuGO6WgWS6l/
         /WLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="E5M/cR94";
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756977105; x=1757581905; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Jaxl79cV7AnlX0poZbwlmOGRhLOdtJvToJbqEFrEK14=;
        b=eQ/k/9pM6TYuPpMzHc4rP6yhhYS+dgUpSEJRoAUWj0pIpRaxUpxMDwdx2XvN5R3Dyx
         4gFiLAQ8sUHtUfhgCG1bjDK5rDDLIi72E6qoYJO5Xq6J1Q5KLEYPM8WR36DPFjmXwwar
         3LMl31hAQPENXolIICJcrU6WnQKlkmpb/1ik0IlHYlBrkssarHxhbqWr6Oi6jG+e0Yol
         8f0ut4FLH3o/gEv39XGR4mfNwLty83c45n0YMGJ91Ttt0zrw7pF8+c3dDS/ebfK4FhB/
         kQlMpmidMGpNTJi4pdyWfjRtYe7wCqRUmAxNeFPx2YCvzkNYKMmBOnuK24Fft9+rsKNe
         s9Ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756977105; x=1757581905;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Jaxl79cV7AnlX0poZbwlmOGRhLOdtJvToJbqEFrEK14=;
        b=gsturxxeukM5Af/niYEOSHfknu3ZsNFn1HjtJ92mDKaJCk6g6SoMl+hSLPQAFNlqKC
         IMWzQnxHQPe6NpgHI29bh0zbFxYaqwCz3gKDwkAs4GZ4ycbu88LSC4r4Ep1VkPSd9taE
         KRLUgG3giU7/JA+oHGM0qHi9BNRC+7hh5ST9/1O4i7VR3cEHHNsgj3mMQagN7CcTNmIS
         rCID4D+BffpJqxFBegFQ860vGVriFxN2E9yFR09U2Mg4PYOLinGCKSRu2wh4X5Y9MscS
         z9d6zqzvOapSfoIuRLO3052vi6fQw5z460KxKqcQOG+Mxlp9Vw3KvFZ3PxbBTUtqI4Uj
         0Jng==
X-Forwarded-Encrypted: i=2; AJvYcCU/UnmSntTIvJ9wjTCEaLl8GOpTZKqZFHhoehNNHicNRQCMz2b/PCKJAqvIwbTH3mjCN1nG8w==@lfdr.de
X-Gm-Message-State: AOJu0Ywlycp8liWI+K27JPD7qlgWXh5av37oFykBFZe9isBpwO7L8hTd
	qtU1nMGHnx3E+AoDh5qE0wtmQRgHD8OZISvXdVKXPV5o+TKkGXApb/KO
X-Google-Smtp-Source: AGHT+IF++qKMuf+EVRqpvMjmvjKjQcFRAEBLdhJV5nebwyOLoXWzr7ax5i8+J/WReZ/e1Z7+IJy8CA==
X-Received: by 2002:a05:6e02:3c06:b0:3f1:dd7:24a7 with SMTP id e9e14a558f8ab-3f4026bd93cmr349498815ab.29.1756977105257;
        Thu, 04 Sep 2025 02:11:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdt6aoIQectwpAb94ZNC2e1mB5W12seqX/D6ohYw5SriQ==
Received: by 2002:a05:6e02:4712:b0:3e5:842c:aa0a with SMTP id
 e9e14a558f8ab-3f13a5ef32els61527625ab.2.-pod-prod-09-us; Thu, 04 Sep 2025
 02:11:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUDVsgHzFlYTZhm7Z2gEs4T29WSWunBi+mnHnYOuJkhcryRWQ7kv6sbezgjif/oRqza8Y7sQZWpBec=@googlegroups.com
X-Received: by 2002:a05:6e02:3a06:b0:3f1:e16e:f5fe with SMTP id e9e14a558f8ab-3f4021bf204mr301150965ab.26.1756977104377;
        Thu, 04 Sep 2025 02:11:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756977104; cv=none;
        d=google.com; s=arc-20240605;
        b=D2EYotp8AsAHbCF/2yWVb7Aib4CwnYa1hChyKW6raDS1EQc4usCR86tg3CyqDUCHjS
         vC5maf/tTIM6/VzHLHg+8D/gXW4WQSPNoPHNxGj9HxShb7KkFCo5raN4oJlpb0uisLBc
         e1PUlgvooe6elbCEJWla/aS8DGmOLGLTnH8DpyUv5FULyoYausgS3DmVbRFMr4OWz2aB
         ojTlpNykZwoWyd3rpp8v7kVG/kbNfCfcIPJf+ExFF9poo/ag2K52GeNKrJvzlm4L2gdn
         2Ryk+/HWVei7SlLu+v5gJd5l+LtFWesR050f4zakH+dHoUT1zOoA5fAe4rrsIhI5pRiX
         htaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OiBL4xUOfg7gCGVbKRZ2miCXhQoK6jtoEjlt5pZuFFU=;
        fh=lMktDqeWHK3tU3M53jp9L6ifIUaH5JLZQb7uT0s03EE=;
        b=WN5tQHeYUEzIwEt3CdltAkt3LKYuzLHDbDfmSN+EPy2kTs2sSO0B4t3Tg8h77MkEJa
         rOALU5ZzlYr6c7swNNmq8kPeHPLx+k9uHCwhBTVgL7SxC7W6LBK5f+LNBgiI2fU3J7ve
         aZsuvwcAANwR7llaeICE1U4PqS6sNMaTfX0rMN+8QPLoMYOzId0o2pezV1ph6jorlrAH
         cpgvd9Nig0EgHR18sJ0nVdjjzoTAEDJ87NaVhil3L3kDOxzZ1Vx+1KGdZ6Q/yjtNMe8o
         pzuCiwuqb6/Esyu+lbNw8GMa79ETAsesZOK/mTIQwlHROaC8luGaVVS/QoZHAIzkPh+H
         SS+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="E5M/cR94";
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x731.google.com (mail-qk1-x731.google.com. [2607:f8b0:4864:20::731])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3f3d9be87f5si5163315ab.0.2025.09.04.02.11.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Sep 2025 02:11:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::731 as permitted sender) client-ip=2607:f8b0:4864:20::731;
Received: by mail-qk1-x731.google.com with SMTP id af79cd13be357-80e33b9e2d3so71036985a.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Sep 2025 02:11:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVQXRYK1JqKsuZJWww3yiX/KBKhKqBW0PXk9e8Wz3s6fZYAA/K17CPg6SxhuiN7Y1CAJxNXziC629U=@googlegroups.com
X-Gm-Gg: ASbGncsRSjmlLbwTL2TKLdRS3UcAd7SkO7NIy+5OcJN+ltoMCJ0PWliDqphMAiZLCJH
	cCcsGXMadu7RyPcEAB9R6ngrsxM2pP9K+3FrfvgB+gRbRoxTIlWmJuWGJUtM1UDYFCVQxlBCWRi
	p9YQo3q3C7QL/+VZcHOYFwNiOOvf4iVLW3b77rMJGpNZTGh8pH+Yu4Zs1c5xwu+0SMmfgvzlr1b
	TenscOwoawi2qv2lNB2gu8=
X-Received: by 2002:a05:620a:284c:b0:7e6:572d:abe9 with SMTP id
 af79cd13be357-7ff2869bd22mr2202626385a.37.1756977103394; Thu, 04 Sep 2025
 02:11:43 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250901164212.460229-1-ethan.w.s.graham@gmail.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Sep 2025 17:11:31 +0800
X-Gm-Features: Ac12FXxFg-YSHUgrBqJ-5TrzXWGp5KCpZbo80fhtQ-VWPd3R1wCW9QCV-W4F-oA
Message-ID: <CABVgOSmZffGSX3f3-+hvberF9VK6_FZYQE_g2jOB7zSMvVuDQw@mail.gmail.com>
Subject: Re: [PATCH v2 RFC 0/7] KFuzzTest: a new kernel fuzzing framework
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, glider@google.com, andreyknvl@gmail.com, 
	brendan.higgins@linux.dev, dvyukov@google.com, jannh@google.com, 
	elver@google.com, rmoar@google.com, shuah@kernel.org, tarasmadan@google.com, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, dhowells@redhat.com, 
	lukas@wunner.de, ignat@cloudflare.com, herbert@gondor.apana.org.au, 
	davem@davemloft.net, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="E5M/cR94";       spf=pass
 (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::731
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Tue, 2 Sept 2025 at 00:43, Ethan Graham <ethan.w.s.graham@gmail.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> This patch series introduces KFuzzTest, a lightweight framework for
> creating in-kernel fuzz targets for internal kernel functions.
>
> The primary motivation for KFuzzTest is to simplify the fuzzing of
> low-level, relatively stateless functions (e.g., data parsers, format
> converters) that are difficult to exercise effectively from the syscall
> boundary. It is intended for in-situ fuzzing of kernel code without
> requiring that it be built as a separate userspace library or that its
> dependencies be stubbed out. Using a simple macro-based API, developers
> can add a new fuzz target with minimal boilerplate code.
>
> The core design consists of three main parts:
> 1. A `FUZZ_TEST(name, struct_type)` macro that allows developers to
>    easily define a fuzz test.
> 2. A binary input format that allows a userspace fuzzer to serialize
>    complex, pointer-rich C structures into a single buffer.
> 3. Metadata for test targets, constraints, and annotations, which is
>    emitted into dedicated ELF sections to allow for discovery and
>    inspection by userspace tools. These are found in
>    ".kfuzztest_{targets, constraints, annotations}".
>
> To demonstrate this framework's viability, support for KFuzzTest has been
> prototyped in a development fork of syzkaller, enabling coverage-guided
> fuzzing. To validate its end-to-end effectiveness, we performed an
> experiment by manually introducing an off-by-one buffer over-read into
> pkcs7_parse_message, like so:
>
> -ret = asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen);
> +ret = asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen + 1);
>
> A syzkaller instance fuzzing the new test_pkcs7_parse_message target
> introduced in patch 7 successfully triggered the bug inside of
> asn1_ber_decoder in under a 30 seconds from a cold start.
>
> This RFC continues to seek feedback on the overall design of KFuzzTest
> and the minor changes made in V2. We are particularly interested in
> comments on:
> - The ergonomics of the API for defining fuzz targets.
> - The overall workflow and usability for a developer adding and running
>   a new in-kernel fuzz target.
> - The high-level architecture.
>
> The patch series is structured as follows:
> - Patch 1 adds and exposes a new KASAN function needed by KFuzzTest.
> - Patch 2 introduces the core KFuzzTest API and data structures.
> - Patch 3 adds the runtime implementation for the framework.
> - Patch 4 adds a tool for sending structured inputs into a fuzz target.
> - Patch 5 adds documentation.
> - Patch 6 provides example fuzz targets.
> - Patch 7 defines fuzz targets for real kernel functions.
>
> Changes in v2:
> - Per feedback from Eric Biggers and Ignat Korchagin, move the /crypto
>   fuzz target samples into a new /crypto/tests directory to separate
>   them from the functional source code.
> - Per feedback from David Gow and Marco Elver, add the kfuzztest-bridge
>   tool to generate structured inputs for fuzz targets. The tool can
>   populate parts of the input structure with data from a file, enabling
>   both simple randomized fuzzing (e.g, using /dev/urandom) and
>   targeted testing with file-based inputs.
>
> We would like to thank David Gow for his detailed feedback regarding the
> potential integration with KUnit. The v1 discussion highlighted three
> potential paths: making KFuzzTests a special case of KUnit tests, sharing
> implementation details in a common library, or keeping the frameworks
> separate while ensuring API familiarity.
>
> Following a productive conversation with David, we are moving forward
> with the third option for now. While tighter integration is an
> attractive long-term goal, we believe the most practical first step is
> to establish KFuzzTest as a valuable, standalone framework. This avoids
> premature abstraction (e.g., creating a shared library with only one
> user) and allows KFuzzTest's design to stabilize based on its specific
> focus: fuzzing with complex, structured inputs.
>

Thanks, Ethan. I've had a bit of a play around with the
kfuzztest-bridge tool, and it seems to work pretty well here. I'm
definitely looking forward to trying out

The only real feature I'd find useful would be to have a
human-readable way of describing the data (as well as the structure),
which could be useful when passing around reproducers, and could make
it possible to hand-craft or adapt cases to work cross-architecture,
if that's a future goal. But I don't think that it's worth holding up
an initial version for.

On the subject of architecture support, I don't see anything
particularly x86_64-specific in here (or at least, nothing that
couldn't be relatively easily fixed). While I don't think you need to
support lots of architectures immediately, it'd be nice to use
architecture-independant things (like the shared
include/asm-generic/vmlinux.lds.h) where possible. And even if you're
focusing on x86_64, supporting UML -- which is still x86
under-the-hood, but has its own linker scripts -- would be a nice
bonus if it's easy. Other things, like supporting 32-bit or big-endian
setups are nice-to-have, but definitely not worth spending too much
time on immediately (though if we start using some of the
formats/features here for KUnit, we'll want to support them).

Finally, while I like the samples and documentation, I think it'd be
nice to include a working example of using kfuzztest-bridge alongside
the samples, even if it's something as simple as including a line
like:
./kfuzztest-bridge "some_buffer { ptr[buf] len[buf, u64]}; buf {
arr[u8, 128] };"  "test_underflow_on_buffer" /dev/urandom

Regardless, this is very neat, and I can't wait (with some
apprehension) to see what it finds!

Cheers,
-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSmZffGSX3f3-%2BhvberF9VK6_FZYQE_g2jOB7zSMvVuDQw%40mail.gmail.com.
