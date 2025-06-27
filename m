Return-Path: <kasan-dev+bncBCCMH5WKTMGRBS6H7LBAMGQENBCA5DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id DA8DCAEB95C
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 15:59:43 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-7489d1f5e9fsf3006060b3a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 06:59:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751032779; cv=pass;
        d=google.com; s=arc-20240605;
        b=dkWAW/4dWIA4EJ9uLYcNefWo3FKsWi68DVKMtiB2ikoytxYjzG8qWBMm0BBzI6j4uw
         9D757OTDKL3sQb1V07iNEf8uVQ4dKE4b0KpbDmo8JeQ5Ft3nkCe4X7uYPChgH/hzXboQ
         AEFwRUdMba4zMW+mHaOmEWcTmJQfTLgaGwWToHAbYubfKpy4kMvLY6mmCSZKSIr8likD
         s4+/+tO8YWc+yA/7GTmEJGYvn4wZEkoCDcg7TUwivPNwf0XuzJ16L06ooelPZJy+pjQs
         YXoT4ckgF1s5ZXuj0zkIRl8TbPC2bW8ldAlGfPDqYz19xvUCg6p4oKwfq5LZ1oz5cwFN
         Koww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4TP+nTse+kfB4BElB42byuXvCKxRyskFcZtis33kN6o=;
        fh=udLJmFwFQjvjFUfOBR6jtq8AZ3j+YPzyTZYBEe8NCT0=;
        b=GxTTWhyQqF1vPEWvkxchNWSMvVwPHgNcz0lfYhTqCkX/o5breOrInIMf89kXeABeHC
         UzHj6n/9tuU5F64bCeIJ7qT/lXuBQM1e4ram5KmICfYp2sGUO5Op1/2uXlwx+bMZau9u
         OnoHYea6f/fhNXg+bTG0WWm9Wq7CKyRwTRfEiIQqktxQch0nwejNNf8prtzRxTkqFjqw
         JW/Xokp+qcQrU2wbW+mbPwERAA9Zystj0p3tkWtghtspP7KDkzCG2GecDbI8UHCMcyc2
         ToD6YSRA0mIc5b4SfAuXinyOil3APqnZ24yBjlzevDvVh0gpkOQjI/+9G3s5C+o7AciO
         OS1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rDrxTjPA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751032779; x=1751637579; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4TP+nTse+kfB4BElB42byuXvCKxRyskFcZtis33kN6o=;
        b=Hzww1+Gg8pjFtZzoAcxddwKCzf336CMB97asE114TqIIXVCzV3jCr22I/GcWqkefuX
         GKyslLgBfmgX86UI32hS2At3ah8cnzjk4gDjfFdEUylg4Oudzgq4MnGABCNG3o1RwGZU
         lE6SGFNehSYZQUCkxYIAW5Ihtwoiz4XpmKkza7L95MKfjmnxwtvo4cdmBc0Kri3KxcKb
         DMaY63wds8ScZvCSLTFccNuB/eNNhSqvPEE3InGWoyETPua+PhCRFdxj80x5JiNqHFCK
         T+mEGPdMHn+JLmPdGAWPWSZPRYAKB0RJj6C7UfFf8VsD7sEIstwPlPjSGQ0yj9M2K2i7
         eNgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751032779; x=1751637579;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4TP+nTse+kfB4BElB42byuXvCKxRyskFcZtis33kN6o=;
        b=fe7qSPEqyyhaTK1L3h9vO+ddV/Q4psPREQ7yzBYxYBwwYAUPBI0SSVUfcmNJAojM0w
         NQx6xrC6J8SiURO8/Q4FK+PBc/mIn23X4FB4h+aO+CTo/4hCGJfyKjDgAzU1KbIwkRSW
         ujr5AWUrsMR8gPcJKkn+Cj99HsIGdTNBzzz0D/FUnZqCpa6pYlgRAlEzL/8iYKS9k8Mw
         4A5kLNwKpiZYtnULho78Rjtqk6lzt1x6EruHW05blwcGV3V56qqienSBseUVCJ98uwe1
         8ktKblELFgOdRygMwTtwywYR7+jorNzraUVWlOULRSZsJgS/gcfHYlb7Cv7zO0umqxaY
         ZumA==
X-Forwarded-Encrypted: i=2; AJvYcCUSRJJpL7Ic6pQR/NCYVNg8Ob86TqgjcN7oPi1Atpi3ip9R6F4e8n4ATFsO+n1Ky68GxjjrVw==@lfdr.de
X-Gm-Message-State: AOJu0YzkvqIEGb2nHkL2WNAlgHoH9eGqhFjBN8LRyPkMglQbmlgiDlzy
	i60lcqVEvVJ8Hik8Pgz4ihuC9xGIr9/bu4TFcPiQsLCS4fOndcD4N8Vo
X-Google-Smtp-Source: AGHT+IHJwLsQvrY6egU0QnGKBe0ECS78gYQey/pJWZr/V/LcNsnYbm6c4sgoT129KQxxD/bAc7HvRA==
X-Received: by 2002:a05:6a00:1955:b0:748:e772:f952 with SMTP id d2e1a72fcca58-74af6f6dc19mr4515623b3a.17.1751032779338;
        Fri, 27 Jun 2025 06:59:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe/ZMreygsTbfRB+BX/bgtWhhf8Gsq/BI6sgyAgocDVTA==
Received: by 2002:a05:6a00:240d:b0:730:8472:3054 with SMTP id
 d2e1a72fcca58-74ae386d561ls1984569b3a.1.-pod-prod-03-us; Fri, 27 Jun 2025
 06:59:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWX82HwcO+5dj1rpGct7IFHjvCYDOl1cI/YKwEFdMYxbUCiX//exDb3vjvJYrMQ0SGScyrtqGqLmtA=@googlegroups.com
X-Received: by 2002:a05:6a20:394b:b0:215:e60b:3bd3 with SMTP id adf61e73a8af0-220a1833acfmr5127290637.29.1751032777932;
        Fri, 27 Jun 2025 06:59:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751032777; cv=none;
        d=google.com; s=arc-20240605;
        b=KL9tFbPJRHoPpv2YC97sLnhFzzu6V0WB+YTJ33Rg4CU3kC5P/8572NONEKudZTqOKR
         iEXwyJDb93lcP5MtTvnAD8+xZ0wjKoYn8NwV4CVucfLME5vEXERzXkMkhQ7n2MoGYMBM
         sX9TXouyTn3Yxp9GjHuhDicG5LH2FkToRGmbdy75USVgWw6YPA/YlWnGut2CTfIXghmq
         9hb2IFaiv0lZEaO8X9u67Fhd8YsOonkH0vKiFzjJarH1A8E92gaQ/l4n9k2lN3gSAzfi
         lFYteFYc/Rk6Q4wCWztfWl0oEsixgRpDtBGoCZc1RLeSTYvYEVez1ZHirP4gbYtdGJI8
         1Iug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=nQ6o3V9npnsh5kXG6EvAXWC21LHYKK26r/BWHZxcoSc=;
        fh=9Q863kaWbFuxLvUJP0dJJFsxB1bJcTYcglW7dXBxxGQ=;
        b=XhV34BZlydgqXNF7TO05WCIeo+7QVnYTN2kAZq887DgpCFOB2L+EeMCk3jeQ1JmLR6
         nIK6mQ8bimXMsNPuoNXEa6P32LO8u77Xw11lGH9EnH61Fo5oKCJ3aRnkBn3V5E2aTJKa
         gMH0Lzxyp+V4MLC93Z9/pCwg6Wr9A+KEucqnWlaV3Mi0VyPU7owuiP4YmZd9VY1ONzDQ
         25jCdNNyyo13KGW+wFTSyQC8uTaqspkbuUNTCIQiDGeAvtoxAmbUab4RPW9AgH3XDXF9
         TXSG3J3dj59NfAsVePeHeM1QAhTU3fpVl7LREQiaHsv3MjJTixXr/mRdNJgpxFGyfdjW
         UJDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rDrxTjPA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf30.google.com (mail-qv1-xf30.google.com. [2607:f8b0:4864:20::f30])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-74af51f574esi126623b3a.0.2025.06.27.06.59.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Jun 2025 06:59:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) client-ip=2607:f8b0:4864:20::f30;
Received: by mail-qv1-xf30.google.com with SMTP id 6a1803df08f44-6fad3400ea3so20070206d6.0
        for <kasan-dev@googlegroups.com>; Fri, 27 Jun 2025 06:59:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXubqZOIrJaJrULZNv8MhTF6lVeTekDbKfzAecpcyMKDlHuuhH3AraDjkWuSMlmfgI13LUvQswmWdI=@googlegroups.com
X-Gm-Gg: ASbGncvqdhwlNCgXcoNKXhvhXvBlLnxEzoa/fJA/wXedehZupWAQU2LuZ8ejnjsdB/W
	RWS+nBFYpSLYYrWdZXEfS5x8YmXM2zXWW2ivzWxuwSSvyiblw0t+dzzedZtnxhq3VaeLVDB9+Ka
	sgOAGqvFt31yvD/OvAnnL/VHC3/guIDfjvfz24MN8R8jLKZbnaTCUZEt8EwMS3i6WnIW8T3BG9r
	Q==
X-Received: by 2002:a05:6214:2266:b0:6fd:1687:2e1b with SMTP id
 6a1803df08f44-70002ee6947mr70996486d6.27.1751032776825; Fri, 27 Jun 2025
 06:59:36 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-9-glider@google.com>
 <20250627082730.GS1613200@noisy.programming.kicks-ass.net>
In-Reply-To: <20250627082730.GS1613200@noisy.programming.kicks-ass.net>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 Jun 2025 15:58:59 +0200
X-Gm-Features: Ac12FXxMNEt1qGUjodKMiPINFABXeRDpEWe9lZCBGKZ_sY2yk46vnyO5SyFSoxY
Message-ID: <CAG_fn=Utve6zTW9kxwVbqpbQTRMtJPbvtyV3QkQ3yuinizF44Q@mail.gmail.com>
Subject: Re: [PATCH v2 08/11] kcov: add ioctl(KCOV_UNIQUE_ENABLE)
To: Peter Zijlstra <peterz@infradead.org>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=rDrxTjPA;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as
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

On Fri, Jun 27, 2025 at 10:27=E2=80=AFAM Peter Zijlstra <peterz@infradead.o=
rg> wrote:
>
> On Thu, Jun 26, 2025 at 03:41:55PM +0200, Alexander Potapenko wrote:
> > ioctl(KCOV_UNIQUE_ENABLE) enables collection of deduplicated coverage
> > in the presence of CONFIG_KCOV_ENABLE_GUARDS.
> >
> > The buffer shared with the userspace is divided in two parts, one holdi=
ng
> > a bitmap, and the other one being the trace. The single parameter of
> > ioctl(KCOV_UNIQUE_ENABLE) determines the number of words used for the
> > bitmap.
> >
> > Each __sanitizer_cov_trace_pc_guard() instrumentation hook receives a
> > pointer to a unique guard variable. Upon the first call of each hook,
> > the guard variable is initialized with a unique integer, which is used =
to
> > map those hooks to bits in the bitmap. In the new coverage collection m=
ode,
> > the kernel first checks whether the bit corresponding to a particular h=
ook
> > is set, and then, if it is not, the PC is written into the trace buffer=
,
> > and the bit is set.
>
> I am somewhat confused; the clang documentation states that every edge
> will have a guard variable.

There are two modes, -fsanitize-coverage=3Dedge and
-fsanitize-coverage=3Dbb, with edge being the default one.

When instrumenting basic blocks, the compiler inserts a call to
__sanitizer_cov_trace_pc at the beginning of every basic block in the
LLVM IR (well, not exactly, because some basic blocks are considered
redundant; this behavior can be disabled by passing
-fsanitize-coverage=3Dno-prune).

Now, instrumenting the edges is actually very similar to basic blocks:
we just find critical edges of the callgraph, add a new basic block in
the middle of those edges, then instrument basic blocks like we did
before.
For what it's worth, the number of coverage hooks does not usually
become quadratic when instrumenting edges, we only add a handful of
new basic blocks.

>
> So if I have code like:
>
> foo:    Jcc     foobar
> ...
> bar:    Jcc     foobar
> ...
> foobar:
>
> Then we get two guard variables for the one foobar target?

Correct.
Note that in this sense coverage guards behave exactly similar to
-fsanitize-coverage=3Dtrace-pc that we used before.

Consider the following example (also available at
https://godbolt.org/z/TcMT8W45o):

void bar();
void foo(int *a) {
  if (a)
    *a =3D 0;
  bar();
}

Compiling it with different coverage options may give an idea of how
{trace-pc,trace-pc-guard}x{bb,edge} relate to each other:

# Coverage we use today, instrumenting edges:
$ clang -fsanitize-coverage=3Dtrace-pc -S -O2
# Guard coverage proposed in the patch, instrumenting edges
$ clang -fsanitize-coverage=3Dtrace-pc-guard -S -O2
# PC coverage with basic block instrumentation
$ clang -fsanitize-coverage=3Dtrace-pc,bb -S -O2
# Guard coverage with basic block instrumentation
$ clang -fsanitize-coverage=3Dtrace-pc-guard,bb -S -O2

The number of coverage calls doesn't change if I change trace-pc to
trace-pc-guard.
-fsanitize-coverage=3Dbb produces one call less than
-fsanitize-coverage=3Dedge (aka the default mode).

>
> But from a coverage PoV you don't particularly care about the edges; you
> only care you hit the instruction.

Fuzzing engines care about various signals of program state, not just
basic block coverage.
There's a tradeoff between precisely distinguishing between two states
(e.g. "last time I called a()-->b()->c() to get to this line, now this
is a()->d()->e()->f()-c(), let's treat it differently") and bloating
the fuzzing corpus with redundant information.
Our experience shows that using such makeshift edge coverage produces
better results than just instrumenting basic blocks, but collecting
longer traces of basic blocks is unnecessary.

> Combined with the naming of the hook:
> 'trace_pc_guard', which reads to me like: program-counter guard, suggesti=
ng
> the guard is in fact per PC or target node, not per edge.
>
> So which is it?

The same hook is used in both the BB and the edge modes, because in
both cases we are actually instrumenting basic blocks.

>
> Also, dynamic edges are very hard to allocate guard variables for, while
> target guards are trivial, even in the face of dynamic edges.

All edges are known statically, because they are within the same
function - calls between functions are not considered edges.

> A further consideration is that the number of edges can vastly outnumber
> the number of nodes, again suggesting that node guards might be better.
>

For the above reason, this isn't a problem.
In the current setup (with edges, without guards), the number of
instrumentation points in vmlinux is on the order of single-digit
millions.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DUtve6zTW9kxwVbqpbQTRMtJPbvtyV3QkQ3yuinizF44Q%40mail.gmail.com.
