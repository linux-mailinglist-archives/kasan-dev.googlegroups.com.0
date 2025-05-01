Return-Path: <kasan-dev+bncBDA5JVXUX4ERBU5DZ3AAMGQEUVYKNFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A1B4AA60A9
	for <lists+kasan-dev@lfdr.de>; Thu,  1 May 2025 17:23:01 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-39131f2bbe5sf339486f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 01 May 2025 08:23:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746112981; cv=pass;
        d=google.com; s=arc-20240605;
        b=IA6UOsIfceCAgDydNQ2mD48qA7k7qmGT2bWQ+6D553HgISYQQZm0pzCowJMm37hgWv
         I8jzIoZDpwgpROtyK3cAhK8fF1Vuo5qz59Xm+tNxYKpKyyL1Zs/EFx/gMMZGDGuuc2k2
         uTlC5J0iU/ohpY3Z2xyFUO9h/dQYCOqPT1no+wtZ/+/51gE120L1oyrgNHMXFZL3gMMt
         5z6owsdecacSrBx+eyXTMAyDVyTl9lZPQ2S7O4IYiyQpliQFdaskxERKM4qU+hlO+alj
         k9cOX7Eii1Z/vKwRg59CC1kQBEgwCS4dFvbN3Ty6OQJub27fSokXNG+2ENK9AqbZML17
         DRHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=tdmeuL2l4fKPWk+NANY1HvkUJ+O8TVw4WS7mBWIgH7Q=;
        fh=ubgv9p7TLITqnFLFn4PSk2i6z0XjFcKntTkBC1ZVOoo=;
        b=SbM0U5Rj80PA+GTNjUE8aRs0YNv+vhSe62JFzynAQJaHl/G5h3LA6K5J5zlm6ghhVQ
         I797DTY351RflhsKW0C8XXg++mbTmAoj1kigZ9lsQpJoc1Xmr9fgcB32ViEP4voA9fjs
         74fMLpVsxvk92HjAbCLXSNsU3iqESs11ZkIdcYdYNz7AsymsN0IzClUqH1XwBGcwKvDm
         2B3I+edon/jemtQi6IWSyoi7xgFOmKlVtvpzmO7IDOoJn4AW0ciekAYEcoBi+JNMlqGf
         bIn3PneounF6Qe5G1zf2OvWnx59OjQSrGUMUncOp8vvZXSpFn1Tz5be9wWvpLQMEa6mG
         sTDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="nC6d/kP8";
       spf=pass (google.com: domain of 30jetaagkcykwnpxzn0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30JETaAgKCYkwnpxzn0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746112981; x=1746717781; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tdmeuL2l4fKPWk+NANY1HvkUJ+O8TVw4WS7mBWIgH7Q=;
        b=maCfE7aDx7OeIMYsCwg4CQQOqftlb4e8lA4OcilJABLP+fL1AyCsaPDUt+ux4oSWDT
         H3/z2ftSz4BDrjZOeetD5NAMBb068Ma4JOpKq8K7slecTirlZXGrt4Z1SLd0DAPquM1q
         V8GpkwEm3AwqKN1bF5OQaKy+cRsBL1YSiD/CpW9v2QAgomxuCTyEo48hhvOvZ1X1a8B5
         JT+JDpHysfyzEw6PI+kgjyYIvoZldRRfqCrSAvZlDBgX7l3xd+7Ci90f8JrKQXJhq3N5
         ePaDUw5SV/6wVS+QkNzqJZZPsKGz15s2fRbAHsbwmTejQX6aq6O1gGKX7OPHuEdjaMre
         YfVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746112981; x=1746717781;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tdmeuL2l4fKPWk+NANY1HvkUJ+O8TVw4WS7mBWIgH7Q=;
        b=UVPHI5dGtL1M86jSPxKhlwrvgl8Laj65iTLZcgO9eU8jHYPN/3ANJmxIC79rx/2cPq
         aS7SDiIqe96K5zZsNJj4+02u5ckg9g5T6a4tx/mpKFqP09i7G1s+9p/1lxK18xJ2eoIB
         1IlrEAJhGYhTOewSuny5EoM27QQArdb7K2Vv9T0a130pL0yrt/vOc6vq+x2/TVNjR4Wo
         sBRZ/Vi2GUNrMeqBZyj1k0swtVDovnCk49GnDC3GQ35JOs0Dpi/j2g8L36PO1qAK0n3E
         aGZLdr4umJOn6V+54hfyRqFwug/SjENci3F6clC6M7jG5JTIduMxbKOtTcSr/uPECBHA
         273w==
X-Forwarded-Encrypted: i=2; AJvYcCU5N8RVUPtfoEqqtlLkxqV6otImp185IJyZd6Kloq7EcJNe1NXl+jwW2EiCw24B5ZooNOU3bg==@lfdr.de
X-Gm-Message-State: AOJu0YykjbC6J05yr8D7B7EHUN4WBFrZMdL10/604lxE2TJ4XuAJgQiV
	03E485uD2MSRQb1ku1UiWHneNEht6fc/pgKqnkkOSt2hCFx+OoQa
X-Google-Smtp-Source: AGHT+IFAu4qCgfYHiHY6EcC3f1Rqnls3+EHo0ljt6TZelOnCebMxU9SsWqBSFQ7dnvhqpFbVCJcu1w==
X-Received: by 2002:a05:6000:420e:b0:3a0:7d15:1d8a with SMTP id ffacd0b85a97d-3a09417a04bmr2325056f8f.38.1746112980119;
        Thu, 01 May 2025 08:23:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBE5S/CaNeMGLZly6gh3OA3ULyrVd1gdLvBYtqt2aIpcsg==
Received: by 2002:a05:6000:310e:b0:38e:dccf:edc2 with SMTP id
 ffacd0b85a97d-3a092c3ab7als431534f8f.1.-pod-prod-08-eu; Thu, 01 May 2025
 08:22:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWKxSEleRNUgdVtAS0JtjYWG6/wO7ZN9nukQeUI4Sd/O0zWZBHXs8RKbWK3fbE0vra5iy7eALh0VlA=@googlegroups.com
X-Received: by 2002:a05:6000:40c9:b0:39e:dbb0:310f with SMTP id ffacd0b85a97d-3a09417a069mr2789125f8f.39.1746112977489;
        Thu, 01 May 2025 08:22:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746112977; cv=none;
        d=google.com; s=arc-20240605;
        b=L+SXyEaK8bohjVVxU0DcR96lfz9eS7WbInSFnvEBG68SxDQJoesNfkb8GS8DsrrD+P
         /pkFk0uMTo4W7MJsP061yXNDPezqBqbLRy7hwT95bQ74P9zWeAk4WSjMVhSF7S+wKThL
         M2zGjwPyrcgNWYJfV8AyQkyZaU4MZLtZ/6IQMSnD9vygD8DyEw8WUCf9COYncgguBot9
         5jBvQ4UCy39LwU7oVXW9OvKYiwFwYQsTzCpqKwY1O9dAsDq2bg0PBPs8dU7rJGdZQ/+Y
         HbQ57qWVat4ClBqO7lCPdfqiXZJQRGLqgRjxrzyijpMOkj7CK4YAbPFmc3RKiIuVgmfd
         vYcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=wm8HDKzWcPs/ZOJ7u1MGp3oUtkY4RQR0TPLRQCBj5DQ=;
        fh=Y9T9yqwMBH3IMwt6uni6ykr7yJ4kQGXUA4AxXWIBeH4=;
        b=PCBVo5LxTA1E/EAI5uHA3lo1OMoMDftopQROC7oDK0qPtWiJmBIcmpqDovcRgut3Re
         y585U0OcRNgwxpUaj07LmAbpQjddhfrbb2rClC6OjClJE3nKxsH38od+ep+8ig3idG0d
         FWsRMtwqbZ7GFwZDEan2oRn2Bi+wHfi0BCLYGDTNtjs5cGgWeW6gW8Q+RDZMnMBSk4lJ
         dNH/sVhy+dO8kne+YFK3mHZ7ICSh4eCaB5oYMvVAYArgFTA3k2OhlRzsd6h4UQ8dObu1
         QiF8pXs0RnjCFlRMSRBkTqM5KF2Vr8Skm7ycGuF981BgwGC8imhH41EYtPDTjE9dGo0N
         5QpA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="nC6d/kP8";
       spf=pass (google.com: domain of 30jetaagkcykwnpxzn0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30JETaAgKCYkwnpxzn0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a095a85535si24787f8f.5.2025.05.01.08.22.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 May 2025 08:22:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30jetaagkcykwnpxzn0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-43f405810b4so4944205e9.1
        for <kasan-dev@googlegroups.com>; Thu, 01 May 2025 08:22:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVQWaCQXGwKt1FaPkA2i46jKjgZyuILBOljHimf1yG76WZKi9ohHpb5z7j6ObLg3givEMhxNM/+1bA=@googlegroups.com
X-Received: from wmbel14.prod.google.com ([2002:a05:600c:3e0e:b0:440:5f8a:667c])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:4ec6:b0:43d:a90:9f1 with SMTP id 5b1f17b1804b1-441b2635482mr61130455e9.6.1746112976936;
 Thu, 01 May 2025 08:22:56 -0700 (PDT)
Date: Thu, 01 May 2025 15:22:55 +0000
In-Reply-To: <20250501150229.GU4439@noisy.programming.kicks-ass.net>
Mime-Version: 1.0
References: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
 <20250429123504.GA13093@lst.de> <D9KW1QQR88EY.2TOSTVYZZH5KN@google.com> <20250501150229.GU4439@noisy.programming.kicks-ass.net>
X-Mailer: aerc 0.20.0
Message-ID: <D9KXE2YX8R2M.3L7Q6NVIXKPE9@google.com>
Subject: Re: [PATCH RFC v3 0/8] kernel-hacking: introduce CONFIG_NO_AUTO_INLINE
From: "'Brendan Jackman' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Christoph Hellwig <hch@lst.de>, <chenlinxuan@uniontech.com>, 
	Keith Busch <kbusch@kernel.org>, Jens Axboe <axboe@kernel.dk>, Sagi Grimberg <sagi@grimberg.me>, 
	Andrew Morton <akpm@linux-foundation.org>, Yishai Hadas <yishaih@nvidia.com>, 
	Jason Gunthorpe <jgg@ziepe.ca>, Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>, 
	Kevin Tian <kevin.tian@intel.com>, Alex Williamson <alex.williamson@redhat.com>, 
	Peter Huewe <peterhuewe@gmx.de>, Jarkko Sakkinen <jarkko@kernel.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas.schier@linux.dev>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, 
	Johannes Weiner <hannes@cmpxchg.org>, Zi Yan <ziy@nvidia.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Juergen Gross <jgross@suse.com>, 
	Boris Ostrovsky <boris.ostrovsky@oracle.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, <x86@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, <linux-nvme@lists.infradead.org>, 
	<linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>, <kvm@vger.kernel.org>, 
	<virtualization@lists.linux.dev>, <linux-integrity@vger.kernel.org>, 
	<linux-kbuild@vger.kernel.org>, <llvm@lists.linux.dev>, 
	Winston Wen <wentao@uniontech.com>, <kasan-dev@googlegroups.com>, 
	<xen-devel@lists.xenproject.org>, Changbin Du <changbin.du@intel.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jackmanb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="nC6d/kP8";       spf=pass
 (google.com: domain of 30jetaagkcykwnpxzn0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30JETaAgKCYkwnpxzn0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Brendan Jackman <jackmanb@google.com>
Reply-To: Brendan Jackman <jackmanb@google.com>
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

On Thu May 1, 2025 at 3:02 PM UTC, Peter Zijlstra wrote:
> On Thu, May 01, 2025 at 02:19:47PM +0000, Brendan Jackman wrote:
>> On Tue Apr 29, 2025 at 12:35 PM UTC, Christoph Hellwig wrote:
>> > On Tue, Apr 29, 2025 at 12:06:04PM +0800, Chen Linxuan via B4 Relay wrote:
>> >> This series introduces a new kernel configuration option NO_AUTO_INLINE,
>> >> which can be used to disable the automatic inlining of functions.
>> >> 
>> >> This will allow the function tracer to trace more functions
>> >> because it only traces functions that the compiler has not inlined.
>> >
>> > This still feels like a bad idea because it is extremely fragile.
>> 
>> Can you elaborate on that - does it introduce new fragility?
>
> given it needs to sprinkle __always_inline around where it wasn't needed
> before, yeah.

Right, I guess I just wouldn't have associated that with the word
"fragility", but that's a reasonable complaint!

> Also, why would you want this? function tracer is already too much
> output. Why would you want even more?

Yes, tracing every function is already too noisy, this would make it
even more too-noisy, not sure "too noisy" -> "way too noisy" is a
particularly meaningful degradation.

Whereas enlarging the pool of functions that you can _optionally target_
for tracing, or nice reliable breakpoints in GDB, and disasm that's
easier to mentally map back to C, seems like a helpful improvement for
test builds. Personally I sometimes spam a bunch of `noinline` into code
I'm debugging so this seems like a way to just slap that same thing on
the whole tree without dirtying the code, right?

Not that I have a strong opinion on the cost/benefit here, but the
benefit seems nonzero to me.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/D9KXE2YX8R2M.3L7Q6NVIXKPE9%40google.com.
