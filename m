Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUOARL6QKGQE6IGY4LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 53E6D2A6471
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 13:36:35 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id b17sf13781745pgd.16
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 04:36:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604493393; cv=pass;
        d=google.com; s=arc-20160816;
        b=PuR52oSo2WDvQob3xy0JulVw+ETVo0Fjvz58kJ9LZeG+b96XN6TmJ5+47jP3Kmpy/y
         UlFjYOmn+DdQU7B0WrT16osF9P03h/KKGyCk5P6GEWoPRxmqdaHJ3G0RNhFs/DM+yPEw
         Js6vwTXjsn5Lt1sB9/HammWYh9mklDUPzWCi+rClo+h79Di7vZ2qpUunZh7A4CQ5Gq98
         wF3vA4kvA00PQJ4kGiQn9lzRYIsVs4O0o64htbBI5Rv9jocIe4TPyYKq4m7bz6Nc3x09
         j+4QkxKW1rkOSpCieTn/6wGEd2PU80cPWIrsvIApR4CKtbaWoLmo8PshbVLJga4/A9RQ
         GPiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=EnObeunKtLVA9HuusNL2H01icmS79YVbpOEMd7PE1hs=;
        b=mCQSh+vkCGBgo45hP4REG4zmnwwOb/d2+Q7jcF7uScGHZ6xQ9qwyh7kL8xXJLgXe4v
         2mgzAuAhApf0BMc8AKkBM52pveG8s86wCmdqeCna6JXEsyonggW2Wyn9pSTOxA8ieNuo
         kgfuy2YU72B9JvkqVeSV2V0ySa3aLaBtG9NdHyr0+3/QfiJKnTqPqcfPfMYSW9tZdwrP
         Pk2QG2S6IU6dNabLlGrCW43cbYy9cyIqWTdHz1yAcrhqBUXfOpcQzA/HpSed6Hy6Oueh
         AqjqHxLvsxN1xBGb/ZFc1H5BkK1mTroOHO2Vk/An1n0xXJKD5+TbSulHqpeDNswSMoL1
         pULA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LFGjSoCf;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EnObeunKtLVA9HuusNL2H01icmS79YVbpOEMd7PE1hs=;
        b=WWwt1Kio5tpuDJKEMp+Rbd6XRlmBrgJ4LtIeQ6RUQ5w41OBh/10xuVHc9oLl8s6ALu
         aNJBWq/ToQEiNPgLk7RyxY97kWdQnkaMTbu/wPjb9ulARRKSM6JSI/Q0zV8XFWPju/SV
         T6PHOlb6rz6cLLC3dvkRM1KgBxmWE7MwjiS93wekQGwQLmbcFahBLP6BONtJJgQkVUVb
         EVfzqbpjyBMfBAaapY6RtQj5u2fStlI0TZ3W1V/50/h+gb9lxXLc0GWnsil59CEMs1/C
         +Y/B34cCqBqXjWcumyAxBiBBDdr+CScdOmOAePcbGarUZSG7xDOmvoVnjoNp1Zcx2qFa
         1wbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EnObeunKtLVA9HuusNL2H01icmS79YVbpOEMd7PE1hs=;
        b=TnDH5/PKc14NVj0gIP3UcnbVyIFi2CW4wnSpB4abkkuM2+Cm9lNBWa+RU7XSZF5yar
         ual9WN+O3WJGz9ABjOkE9IYfyio9fP8R1Sr/QvVFZ5NvHxuJwpkY6HeT1Fv/ilu/y7CW
         M9f/pvqEgP5Z+r3zVZ0Uf4evxOMhwDsw8HwygJKHGKFPMdGR7Dd3VcMl6xol5l4wE7qd
         b+xwozhT0e6nEiKOnrwTd+XehALlv1mae8oM+jTzsq6Rx2kbHa77hY6LCMXsBernatDP
         5xjBVK/+k2OFtKeiG5WHQDfCGTowrPe7KSNuDYHAe+Cd1PGfa0BYFO/hJmbsNh1XCJ0h
         wr6w==
X-Gm-Message-State: AOAM530giNEphYe8NeHG3zCNoMVvs8j8pQASShyYucd90H0JJryUXi96
	IK4rqXJLPjpWQIytid431bM=
X-Google-Smtp-Source: ABdhPJzjac5m8PjUxsKTIq5PNoONJqSaK1ZAy27p+GGnhMnT4jeL/Knzmt4Qn7SdTWYXrCraPMbxQg==
X-Received: by 2002:a62:7e14:0:b029:18a:d515:dc47 with SMTP id z20-20020a627e140000b029018ad515dc47mr17036081pfc.78.1604493393733;
        Wed, 04 Nov 2020 04:36:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ae08:: with SMTP id q8ls860284pff.0.gmail; Wed, 04 Nov
 2020 04:36:33 -0800 (PST)
X-Received: by 2002:aa7:870e:0:b029:18b:f46:9ca9 with SMTP id b14-20020aa7870e0000b029018b0f469ca9mr10496526pfo.3.1604493392932;
        Wed, 04 Nov 2020 04:36:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604493392; cv=none;
        d=google.com; s=arc-20160816;
        b=JOe6Oy3eNjAsj491D1lo4orjC/7o96srEEzRQa+/j8GugFG+X51JrBisGU1Mgm/O94
         YWogqgFQ6Rb0P4xdO1NpM8MKWB7allbXJjJNyKWqkPtJ6PUIhp/oM4yIjN6pBLEsoLzU
         SPWMw2HBd9qy4/qsQ/H/RhUu83lgUK6q3q8lm26jS3TWlhgUWtdpTWL/BX9rTCQYCSCZ
         7i2FG4syO5x2go/F1l3DhJYUORlHUbgXI2ulOVoLqTScqQ/EYQuYdLWfsXvJGJ1gdlC3
         7Qcu8KmX3/NKGhR8GShsv//sdsl1JYfv0PHQMfEQGuvrWOHK2Vk459idNT9WJdJm9qiV
         qo2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wVb8/RbNDJYhkorSN6bimCxe79UOkbAUrQdoTOawrjk=;
        b=VBa7twuQOb194YxyhxMKfU2jCW1Q3wOuUGE/EIJtfw7O6Bl2oSt4jvJv4KXH1hvY9D
         4XSn2iiHbO/F0l81EaHFDXLHP5pYWvUiRMbY24ukDvsdL9ol80gzTIk1/qt9MYiuXJfB
         4Y0TTWBAhK1IQwRnkLUCabw0byH2it69bPCUk4OgLpHZaVGN3fvoB/XmIHpf6WjzqoFB
         NYOmqaJNgme5DT6cXk5BChA2SifxFjMsdKnNVAWYkZcFgyCF1563fSzLKkJ3VztfWMVj
         Sp5yF0JRqtph4hEWfbeXAe9UNVNIvND7+6JY4v3JUO6ccpw1p3noL5lzfvb/w2qEh2+F
         VGwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LFGjSoCf;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id l7si95238plt.3.2020.11.04.04.36.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 04:36:32 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id g19so9709554otp.13
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 04:36:32 -0800 (PST)
X-Received: by 2002:a9d:649:: with SMTP id 67mr19396919otn.233.1604493392047;
 Wed, 04 Nov 2020 04:36:32 -0800 (PST)
MIME-Version: 1.0
References: <20201103175841.3495947-1-elver@google.com> <20201103163103.109deb9d49a140032d67434f@linux-foundation.org>
In-Reply-To: <20201103163103.109deb9d49a140032d67434f@linux-foundation.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Nov 2020 13:36:20 +0100
Message-ID: <CANpmjNM1HQ_TwqJ6Ad=Mr=oKVnud-qzD=-LhchPAouu1RDHLqw@mail.gmail.com>
Subject: Re: [PATCH v7 0/9] KFENCE: A low-overhead sampling-based memory
 safety error detector
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, "H. Peter Anvin" <hpa@zytor.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, 
	Jonathan Cameron <Jonathan.Cameron@huawei.com>, Jonathan Corbet <corbet@lwn.net>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LFGjSoCf;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Wed, 4 Nov 2020 at 01:31, Andrew Morton <akpm@linux-foundation.org> wrote:
> On Tue,  3 Nov 2020 18:58:32 +0100 Marco Elver <elver@google.com> wrote:
>
> > This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> > low-overhead sampling-based memory safety error detector of heap
> > use-after-free, invalid-free, and out-of-bounds access errors.  This
> > series enables KFENCE for the x86 and arm64 architectures, and adds
> > KFENCE hooks to the SLAB and SLUB allocators.
> >
> > KFENCE is designed to be enabled in production kernels, and has near
> > zero performance overhead. Compared to KASAN, KFENCE trades performance
> > for precision. The main motivation behind KFENCE's design, is that with
> > enough total uptime KFENCE will detect bugs in code paths not typically
> > exercised by non-production test workloads. One way to quickly achieve a
> > large enough total uptime is when the tool is deployed across a large
> > fleet of machines.
>
> Has kfence detected any kernel bugs yet?  What is its track record?

Not yet, but once we deploy in various production kernels, we expect
to find new bugs (we'll report back with results once deployed).
Especially in drivers or subsystems that syzkaller+KASAN can't touch,
e.g. where real devices are required to get coverage. We expect to
have first results on this within 3 months, and can start backports
now that KFENCE for mainline is being finalized. This will likely also
make it into Android, but deployment there will take much longer.

The story is similar with the user space version of the tool
(GWP-ASan), where results started to materialize once it was deployed
across the fleet.

> Will a kfence merge permit us to remove some other memory debugging
> subsystem?  We seem to have rather a lot of them.

Nothing obvious I think. KFENCE is unique in that it is meant for
production fleets of machines (with ~zero overhead and no new HW
features), with the caveat that due to it being sampling based, it's
not so suitable for single machine testing. The other debugging tools
are suitable for the latter, but not former.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM1HQ_TwqJ6Ad%3DMr%3DoKVnud-qzD%3D-LhchPAouu1RDHLqw%40mail.gmail.com.
