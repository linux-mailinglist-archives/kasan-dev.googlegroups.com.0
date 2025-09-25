Return-Path: <kasan-dev+bncBDP53XW3ZQCBBZP52PDAMGQEY46BZCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B776B9E12C
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Sep 2025 10:35:51 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-358a9fc11d9sf523328fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Sep 2025 01:35:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758789349; cv=pass;
        d=google.com; s=arc-20240605;
        b=X4umbEE5GctJyoUlfYwuVchlxeyZi0JMdLBsd9Io/5TrtbBthqUIaEW9bxD1lhX/KF
         7215UzdrPvXRjJ7V7ExXONAzNHQF5I484ljpicn0NV+GTre35OCfdu9jA7bcp9pk2BxG
         S4HIAoRG1xvOAZtws1B53CYo0UYiKtsD6kUz3srcg9HMDFrXGhbtubth+39Y+xTFKSAc
         8VC5ronTmzL1RkhfPQKrLu3Bjhsmv9OoN7ZTN8Ot8zv/NBD3b+XtwDvkWz6wcw7ClN43
         2hHY+uN9NiFLrOidlTzLcqFVrPlYbLjWGX+r4hRRS48MB1t/clnFZsc+rcSZDX4DJwNX
         JzgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=xHKXDHjuaVsXSmgRmX8LHPocIAuJv/zjFsiVt1z3sBQ=;
        fh=2zMTT5oMliN8gc0vufMk4+tiEdqFzQJJwDxrKd0L2+A=;
        b=W2oBsnKbpDRyTdfn9oP/PwI9dSd6dWr8YqIIOV/fwGn26yVUaoJzBEfbvqljnpxgZ/
         HF8st3z0n9E1C3+ow4nz7oLjhgKno/svm7HaPGnFN+YedPY+OH1CGMhdEI8XOENGX98k
         oOMaezN1QlXizzIefJkjXEEhOl0kSLWcCkL7pUG2K6Ebkee2slDHfwymnWYJGpaoU65/
         yc/NTjQXI5tphrVasoRgYIHWF/TdZFgohfhSoHyrb+VfJeu8NhtM6dTm8kb9+OOS7X36
         NIjYPhIUetlOXwkow1/4SiJ5U1fd5s/+SpSHO3xQfCCM5s0ynh/wEoraRqhTGgAI3wTX
         QNSw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RddhLTTn;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758789349; x=1759394149; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xHKXDHjuaVsXSmgRmX8LHPocIAuJv/zjFsiVt1z3sBQ=;
        b=ou6Tbg7ogEaVv1SnBAW6PWtPbBEOmAw83knijUqytUC5a/UAS5AnqJ+KZC3LCL9wb1
         e/ioLfjlf+YG4wwQmoPtT1P0jTJsmgd3YEuErUIH5Pta2aY8qiPOuVVIBSDwTxsPYq37
         CRAonR2g11jcwwnqVtIbSvKygxXEmTYOzpPyRlA5mBy38cVIns28GoArgwXvt3xC+K6M
         MoA2gZ7x7bul9CNhu6tuGWCvRnXvKwTVSE7TZqu1I6Njg3jkBLx3MA63AIpxWrNCCpWG
         TUEZVWDPNfXVvXRj0HvsYSZRbWnNAITqvMJ7Zk9lYPKnQGl5XZ9XkJlMiSro9WVjYsOS
         BzVw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758789349; x=1759394149; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xHKXDHjuaVsXSmgRmX8LHPocIAuJv/zjFsiVt1z3sBQ=;
        b=LJ9DO/4h4WUpGQnmnru/ZbkSmcHAf0KuIbB+fVRhrKDWutMw0uwFEy9fUpl0vERe0S
         1q1djNPD/87Lkem+YncDrw2X1B/UEmeti1tYKBXJE7CNsRZiKomYtCiJOad8NwAh3Tdd
         q9v0PnTyMqOie9amtbuYg8V7v7KN/QDOecV4PTgVkDJgBJrYtZYqIv85tEMpK6K5GecG
         AOQp59UZ0FflPNfEjYeG9JaF1fxzg3Y7JCsbeSFL85YoNaRQBXwL4EQFav0uQiWfXpb4
         Za2HQwy5k7FZENxjXWZABeYkoV58l8BfdZP1m8TlIuTxU7z9M09K/+QsoqXxufRDGqVy
         RWdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758789349; x=1759394149;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xHKXDHjuaVsXSmgRmX8LHPocIAuJv/zjFsiVt1z3sBQ=;
        b=XFJxIkx+MvJdlBdjoY0tGInVHhPF8v81KB//cU8cQumSruzx9EuHH3Aa1FFMjFM+P4
         g1EGdnuXuLlzyMtAGOTM2rGeLm+pZmxzmH5OkJG5HPfapMD5ir+5flfNgIqJhKRE15Hl
         osNC5OP1otwfiZ1b4dchYcbgt3MQzzafkvWlLL8IEqXXBPnkwG0den/AkIyLU4Eg9AGE
         fw6U68lbjadxruHc8phLw71hACqfGxNt6G1gXMXrdb9Am/X5krK/n+l2cs8QtfTGow55
         1uht8pXo/eclnVkxH6yEqePNp6gZzzzXJxTf5BDPiQhe4bnfydfxvMHkblzglWo6ghdn
         NduQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX9rdApH0LeNlPAKm3OSbSBZ8B6fzylDqMZ1v4rBXZvigOonYskGDxcZaY7DItkUmOCYkT/1Q==@lfdr.de
X-Gm-Message-State: AOJu0Yz9ioK77HhRTmdI5NVG5ScCKk5CzsYUj62HnmbxmOyQKOtyArDM
	IaD7m7baKl8LHhlcZbPC2O0x8f0Ynarfn1OhIR0qv+06uMiuI9D47mWA
X-Google-Smtp-Source: AGHT+IFdVzArJRuQGCrNtmkwqk7k4smFbeoSKzY+22SOicI8jybaCCt9aQK5cIHNSfLOhmdqD8V5rw==
X-Received: by 2002:a05:6870:858d:b0:31d:6e38:e138 with SMTP id 586e51a60fabf-35ebe954671mr1263284fac.7.1758789349503;
        Thu, 25 Sep 2025 01:35:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7TlTVvq8apgJXLM52hUQrYSj8PDBMVgfH75lKzMuDgDg=="
Received: by 2002:a05:6870:178b:b0:363:4ae7:c37f with SMTP id
 586e51a60fabf-3635945a0d0ls202325fac.0.-pod-prod-05-us; Thu, 25 Sep 2025
 01:35:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVk6zmQimK0ZrAn+cTLhL4STTkww5JbgHTGq20H06g3jIqXUhC2e7HNBWnxVh9fcURCtIUiiW8iiCY=@googlegroups.com
X-Received: by 2002:a05:6808:f88:b0:43f:14d6:82b4 with SMTP id 5614622812f47-43f4ce73f8amr1473869b6e.35.1758789348215;
        Thu, 25 Sep 2025 01:35:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758789348; cv=none;
        d=google.com; s=arc-20240605;
        b=MLfkBZ1m/6qPsKFlZhKeZk8muRetgsqEno7Xwnz7LIgLGop0TCAPRJLXj3Cp3B9mwB
         zKEDpNLFfv5bSY7c8zu01GWnDcdhaJVe9ZE3YcQ005tJnznwVvWandWnAq1AIQxzneGu
         QBvBhGXupz5oq2yH79U+kAT/UdzbNnqMvJXIvx5l0uri2SjepW0EzrMEjlKEifAtCcx9
         FqNlVwWfK3S61C7fUOdHujHBNaOoLjbJNS3CdweGsCeRYgaskNMBLeqJGXEyZXNiEjo4
         oVcHaDZNSg665AraOG0nX74CAsPJmVejEp/iO68tR7d4nR2wSpvoqxKTi3ENEWhF4vmN
         8/Mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=MDyXKD1mpeXok68wul2g//tY5b9PgvJaaF56RchZKHQ=;
        fh=dTjSHmV/TgDl7wFIlkraUYuFMxjE1/vD6KnzQbevZ9w=;
        b=fzptVGOVgMN3qHtPaZSJ+atzNkWhlpGE6mQq9kHTbP91Ek8/9B+hSEM7D/I0rCc+Vd
         QJ3XKS+gapOPRmdwsYKruBO8T6ZY6McRV7AWrK2iuob1COM0vCdV6vdr9lU8MaJiSCEF
         x6jLYWhi0+3WDM11njf4cx5UXbVrTOz4THplryJdxa3psKFyv4Oms+C6VfsUPWyM8sy8
         Agj9J2VfB5Fxc0v+oqII28VNFLf+fX9UWjzFCeTVSkrmrd9+0MLyCuOyoEK9ES+v2K5B
         pPcWFZPSg1OD9fX1d3q9fE/3Tv2F7/DpEzfZO5I0hrfZ78+Y3r5AXxQ+CthPLqMfAfzp
         YukQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RddhLTTn;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-363a2bec849si67650fac.1.2025.09.25.01.35.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Sep 2025 01:35:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id 41be03b00d2f7-b57bf560703so553474a12.2
        for <kasan-dev@googlegroups.com>; Thu, 25 Sep 2025 01:35:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXcudQYBb8AQNlrT9NLHvlySidaSWsXAr2MvaYPEppnu/dUM+zFhUShb02rsIbTeqSoYG6Ni3ytOQY=@googlegroups.com
X-Gm-Gg: ASbGncu7Yn81gDnQ/LzlGDzThWPXdYeElX5WH3zeXpQq5N4Pc1LLtCobb4cHvbpgbUH
	FNxp+/oY8dVJv6tPJau1xQWakKgg7CGbDruwZUOu0gdlexxr/YtcS7JlML6ZTO5fllSTzklfRNI
	uJtcqG8gOTTrokearGikLJb4lI2mT/D0/tkTll1GhzfnRdPp7bKdn6B1FQl1XkzobOpUnKUFVxf
	Pl9D5w3kL+246XzKvJXQe+TmJn6kQWHOH1yTA==
X-Received: by 2002:a17:903:3201:b0:26e:146e:769c with SMTP id
 d9443c01a7336-27ed4ad75c2mr30527635ad.52.1758789347230; Thu, 25 Sep 2025
 01:35:47 -0700 (PDT)
MIME-Version: 1.0
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com> <3562eeeb276dc9cc5f3b238a3f597baebfa56bad.camel@sipsolutions.net>
In-Reply-To: <3562eeeb276dc9cc5f3b238a3f597baebfa56bad.camel@sipsolutions.net>
From: Ethan Graham <ethan.w.s.graham@gmail.com>
Date: Thu, 25 Sep 2025 10:35:36 +0200
X-Gm-Features: AS18NWBFmYuT702hOj_C5JBwnZByzVghQRTr5ikBT0AN32tqz1vkZcQ1S7Omg5I
Message-ID: <CANgxf6xOJgP6254S8EgSdiivrfE-aJDEQbDdXzWi7K4BCTdrXg@mail.gmail.com>
Subject: Re: [PATCH v2 0/10] KFuzzTest: a new kernel fuzzing framework
To: Johannes Berg <johannes@sipsolutions.net>
Cc: ethangraham@google.com, glider@google.com, andreyknvl@gmail.com, 
	andy@kernel.org, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, elver@google.com, herbert@gondor.apana.org.au, 
	ignat@cloudflare.com, jack@suse.cz, jannh@google.com, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	sj@kernel.org, tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RddhLTTn;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
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

On Wed, Sep 24, 2025 at 2:52=E2=80=AFPM Johannes Berg <johannes@sipsolution=
s.net> wrote:
>
> On Fri, 2025-09-19 at 14:57 +0000, Ethan Graham wrote:
> >
> > This patch series introduces KFuzzTest, a lightweight framework for
> > creating in-kernel fuzz targets for internal kernel functions.
> >
> > The primary motivation for KFuzzTest is to simplify the fuzzing of
> > low-level, relatively stateless functions (e.g., data parsers, format
> > converters) that are difficult to exercise effectively from the syscall
> > boundary. It is intended for in-situ fuzzing of kernel code without
> > requiring that it be built as a separate userspace library or that its
> > dependencies be stubbed out. Using a simple macro-based API, developers
> > can add a new fuzz target with minimal boilerplate code.
>
> So ... I guess I understand the motivation to make this easy for
> developers, but I'm not sure I'm happy to have all of this effectively
> depend on syzkaller.

I would argue that it only depends on syzkaller because it is currently
the only fuzzer that implements support for KFuzzTest. The communication
interface itself is agnostic.

> You spelled out the process to actually declare a fuzz test, but you
> never spelled out the process to actually run fuzzing against it. For

Running the fuzzing is more of a tooling concern, and so instructions
were left out here. For the interested, the syzkaller flow is described
on GitHub: https://github.com/google/syzkaller/blob/master/docs/kfuzztest.m=
d

> the record, and everyone else who might be reading, here's my
> understanding:
>
>  - the FUZZ_TEST() macro declares some magic in the Linux binary,
>    including the name of the struct that describes the necessary input
>
>  - there's a parser in syzkaller (and not really usable standalone) that
>    can parse the vmlinux binary (and doesn't handle modules) and
>    generates descriptions for the input from it
>
>  - I _think_ that the bridge tool uses these descriptions, though the
>    example you have in the documentation just says "use this command for
>    this test" and makes no representation as to how the first argument
>    to the bridge tool is created, it just appears out of thin air

syzkaller doesn't use the bridge tool at all. Since a KFuzzTest target is
invoked when you write encoded data into its debugfs input file, any
fuzzer that is able to do this is able to fuzz it - this is what syzkaller
does. The bridge tool was added to provide an out-of-the-box tool
for fuzzing KFuzzTest targets with arbitrary data that doesn't depend
on syzkaller at all.

In the provided examples, the kfuzztest-bridge descriptions were
hand-written, but it's also feasible to generate them with the ELF
metadata in vmlinux. It would be easy to implement support for
this in syzkaller, but then we would depend on an external tool
for autogenerating these descriptions which we wanted to avoid.

>
>  - the bridge tool will then parse the description and use some random
>    data to create the serialised data that's deserialized in the kernel
>    and then passed to the test

This is exactly right. It's not used by syzkaller, but this is how it's
intended to work when it's used as a standalone tool, or for bridging
between KFuzzTest targets and an arbitrary fuzzer that doesn't
implement the required encoding logic.

>    - side note: did that really have to be a custom serialization
>      format? I don't see any discussion on that, there are different
>      formats that exist already, I'd think?
>
>  - the test runs now, and may or may not crash, as you'd expect

>
> I was really hoping to integrate this with ARCH=3Dum and other fuzzers[1]=
,
> but ... I don't really think it's entirely feasible. I can basically
> only require hard-coding the input description like the bridge tool
> does, but that doesn't scale, or attempt to extract a few thousand lines
> of code from syzkaller to extract the data...

I would argue that integrating with other fuzzers is feasible, but it does
require some if not a lot of work depending on the level of support. syzkal=
ler
already did most of the heavy lifting with smart input generation and mutat=
ion
for kernel functions, so the changes needed for KFuzzTest were mainly:

- Dynamically discovering targets, but you could just as easily write a
  syzkaller description for them.
- Encoding logic for the input format.

Assuming a fuzzer is able to generate C-struct inputs for a kernel function=
,
the only further requirement is being able to encode the input and write
it into the debugfs input file. The ELF data extraction is a nice-to-have
for sure, but it's not a strict requirement.

>
> [1] in particular honggfuzz as I wrote earlier, due to the coverage
>     feedback format issues with afl++, but if I were able to use clang
>     right now I could probably also make afl++ work in a similar way
>     by adding support for --fsanitize-coverage=3Dtrace-pc-guard first.
>
>
> I'm not even saying that you had many choices here, but it's definitely
> annoying, at least to me, that all this infrastructure is effectively
> dependent on syzkaller due to all of this. At the same time, yes, I get
> that parsing dwarf and getting a description out is not an easy feat,
> and without the infrastructure already in syzkaller it'd take more than
> the ~1.1kLOC (and even that is not small) it has now.
>
>
> I guess the biggest question to me is ultimately why all that is
> necessary? Right now, there's only the single example kfuzztest that
> even uses this infrastructure beyond a single linear buffer [2]. Where
> is all that complexity even worth it? It's expressly intended for
> simpler pieces of code that parse something ("data parsers, format
> converters").

You're right that the provided examples don't leverage the feature of
being able to pass more complex nested data into the kernel. Perhaps
for a future iteration, it might be worth adding a target for a function
that takes more complex input. What do you think?

I'm not sure how much of the kernel complexity really could be reduced
if we decided to support only simpler inputs (e.g., linear buffers).
It would certainly simplify the fuzzer implementation, but the kernel
code would likely be similar if not the same.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANgxf6xOJgP6254S8EgSdiivrfE-aJDEQbDdXzWi7K4BCTdrXg%40mail.gmail.com.
