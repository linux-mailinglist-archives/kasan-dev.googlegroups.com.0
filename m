Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBPWJ535QKGQE5LOAIFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id C65972842B1
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Oct 2020 00:57:02 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id d23sf2103246ljg.21
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Oct 2020 15:57:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601938622; cv=pass;
        d=google.com; s=arc-20160816;
        b=gVg4otaNPCC6v1ev8PDflL4xYcwu4yB+OJJDciN8kmiKGXJugdIc/Qx5epkY2YubFB
         ecmBVBxZUfUru6fRh2bUv7Bx4+qo0Wc83jHlx7N47mAXFrEhwyBOGywyERnzCiBJEXTq
         7E7HysdhP7VUM/umCd3TVg6CqBIVTmVJ3bXg//c6N0SqobEBoEnk5Jje+ybj17ceM2cI
         6dLZsDgoLQirJpdjiFG8qDupVQ/kzwAJd5n6b07ibL2SOAbqOMGG+T6mqmCTZ3dOlXiA
         sxMcQq+fEkCXk2ol3iaQfwrhQj/Wo01EObEF2b9YP/2yJSM4wYCFK3ymD9vtrFXVTXm6
         e2wA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rdPz+L/LuFfxLWHSmSbvEz5SCGFXtAOms5azrMPk6xU=;
        b=tXmai5kbtpiaoZW1P0GoHG9jVHUhvkd7wuOzp+d/m8UTc/zUI2FirM/7YeFX0eC6D1
         YXIDAw84HZGrpAQxTj+xn1FLRBM+yMj1/eY2Nvp/XF9yziX9GOAgmKxk2Xju2p457l7y
         T8J3uA6icOQPMwMYkoEX+yUqdVV8ToJTa08RzeK1AzZkTVQNiIEzW2UQ7VD+amVRre/t
         4lEjBiHNlGoKaka4EL6BrOwmz3lfp/s6+zzj8C6VKQcue5ACmOkDy4f8eZWW7t0S1nQu
         Uenqlkr+5eIH6IVclUWaOFLS/nWFxORhcYEBczsFPhOF+nYHA77e0d02bVNQ0/dYQyo2
         f54A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LzInzBBk;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rdPz+L/LuFfxLWHSmSbvEz5SCGFXtAOms5azrMPk6xU=;
        b=F32vA31x8qx6dZTWpmcwGyt2cRyZggS7dBId8vn50eZag9sHUKCOShf4c2YbhidFAZ
         YC21FvPBT3jlvYYbjdYRY8X5gVD0eZahc2a16n3mZE0ZU7svDPXcH6OsH4wQODE+qMaq
         ea+vpu9BfJHT10gvh7CwDT16TgBarzkUtbVPYs7oZTBDrhjDnfYZ0dyd7MZnkV1hGZPR
         DErl+kuwyg2H03R9A2tFe1l0PD0VhseguBUx9hB88SMTOlte+Up+7eo7ZA2NonsDscSh
         TU6rnQ2GBlAaLn0NI30Rc8JBQ2n7vYkVddepjWejiynNF5CpYBJN3+Gslp79hdIVCnRg
         Vzzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rdPz+L/LuFfxLWHSmSbvEz5SCGFXtAOms5azrMPk6xU=;
        b=MuyImOPDA59ReVf+e989pDNQJUuaVkA/1LIaxYKVpvdWS2yOFS5JGnXYfaYIxaXdJ6
         PEmqTRDUYr0x6XjAF/mSR3JrtjrMiIOAgCQDsHozGe22fVLriZMcN8YqdeznOIML1sUU
         h1ptx/eoiJEFzGt/vf+s3ea4loAFiOCi/jWPKGOVUADMKFIy9J9ODkHD3juPeZjubUTu
         S1+Z9EaxJkjU4TLSXswQVeBYoQXq0DrEOCeUTjjMzsnoz4+hdV/iqJcl4P48nTA7oMbH
         uE+e+NVE2Iu6tzW6139Pzw3RtcG1+KC88WKRu+towqYPz3q7QbumrYlldIASghy3yp2c
         5LsQ==
X-Gm-Message-State: AOAM531sH1yjXuTIixdm04M8rq+QF5LifLuQrvK6b3czx9sxjm0a7/Fr
	MZcgrQxszG8aecQs3cdUsIY=
X-Google-Smtp-Source: ABdhPJy9qcQ8/VJjMvsyns31EeXLhfFxDzqAusG4Nu6+oobM+6fMro0dWrWuQ9aCQHF/6rU0QAKLsg==
X-Received: by 2002:a05:651c:505:: with SMTP id o5mr655045ljp.177.1601938622334;
        Mon, 05 Oct 2020 15:57:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c7c8:: with SMTP id x191ls1006145lff.0.gmail; Mon, 05
 Oct 2020 15:57:01 -0700 (PDT)
X-Received: by 2002:a19:e4c:: with SMTP id 73mr600347lfo.286.1601938621179;
        Mon, 05 Oct 2020 15:57:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601938621; cv=none;
        d=google.com; s=arc-20160816;
        b=ZNPGxcTqfINsJHDxcfu9dVMfd/ajdZWuJAi5gZjSXNHeKnMCDg3K9ZQUNrHMsSNjbw
         J7Nw9xyFAPK70cDzZSVJkCxmxMmhvgVZ+fGKcaEHRGuJAzFzJw9jdIDJK6t7aUkFMRKQ
         6dE/24LwJvjM0mLASmaS2E/HvqkejTK/h84rKy3ZF4wHKmGSzrZ7ihp9/cO2q37q9gzr
         RzXFntKzsq1yLU50fg4j/xREEtI1PvxDIc+AO7EBOPBcm7CIbPdvFE019rAQtq5BdEKN
         ABLb9Wude7Z7Td0AUHSyw4VwVy/AZjF8UyeAJBUW5qhERhkDHMN+dFI0cvtz1iJivoWQ
         TgTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Plwfd7H8tCYXAG47Hb1jocyHIm5qQosjRcCwHQHMhLQ=;
        b=Sijnp8NpZ2EuL7acqPAwKxx309CeDf3dwzMd7CLIc4mioRv97HtBlAXNrE+w+1hscl
         19UEfOn/sxa0OpyhYajI2P5qEu2ETnpSwzAwHJCnffIbYyR5oK1uv1vmxE/cgwQ4Ff5Y
         PaaTiBdRBKSRUZqLf6v1GNMau/g08Cd+OwvFKTDknHO8y4xStBcc17qnR2qPod/zLJW6
         zR34xNFSL+Kcaj5w4iQTc5NxfuTuWG2u19C4W2z0Ir3qAZB8IDVd/fBWkUQ4Yp0YE8us
         yJRcnU28bjmt1iMhV0so1LOvzeZyy60wb8S/LMI34vZmEKOgOPQiOsX3PnYmOeQa2zDg
         KefA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LzInzBBk;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x642.google.com (mail-ej1-x642.google.com. [2a00:1450:4864:20::642])
        by gmr-mx.google.com with ESMTPS id y17si40102lfg.2.2020.10.05.15.57.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Oct 2020 15:57:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::642 as permitted sender) client-ip=2a00:1450:4864:20::642;
Received: by mail-ej1-x642.google.com with SMTP id cb21so7873775ejb.13
        for <kasan-dev@googlegroups.com>; Mon, 05 Oct 2020 15:57:01 -0700 (PDT)
X-Received: by 2002:a17:906:86c3:: with SMTP id j3mr2078310ejy.493.1601938620315;
 Mon, 05 Oct 2020 15:57:00 -0700 (PDT)
MIME-Version: 1.0
References: <20200929183513.380760-1-alex.popov@linux.com> <91d564a6-9000-b4c5-15fd-8774b06f5ab0@linux.com>
In-Reply-To: <91d564a6-9000-b4c5-15fd-8774b06f5ab0@linux.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 6 Oct 2020 00:56:33 +0200
Message-ID: <CAG48ez1tNU_7n8qtnxTYZ5qt-upJ81Fcb0P2rZe38ARK=iyBkA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 0/6] Break heap spraying needed for exploiting use-after-free
To: Alexander Popov <alex.popov@linux.com>
Cc: Kees Cook <keescook@chromium.org>, Will Deacon <will@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Peter Zijlstra <peterz@infradead.org>, Krzysztof Kozlowski <krzk@kernel.org>, 
	Patrick Bellasi <patrick.bellasi@arm.com>, David Howells <dhowells@redhat.com>, 
	Eric Biederman <ebiederm@xmission.com>, Johannes Weiner <hannes@cmpxchg.org>, 
	Laura Abbott <labbott@redhat.com>, Arnd Bergmann <arnd@arndb.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Daniel Micay <danielmicay@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Matthew Wilcox <willy@infradead.org>, 
	Pavel Machek <pavel@denx.de>, Valentin Schneider <valentin.schneider@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	Kernel Hardening <kernel-hardening@lists.openwall.com>, 
	kernel list <linux-kernel@vger.kernel.org>, notify@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LzInzBBk;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::642 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Thu, Oct 1, 2020 at 9:43 PM Alexander Popov <alex.popov@linux.com> wrote:
> On 29.09.2020 21:35, Alexander Popov wrote:
> > This is the second version of the heap quarantine prototype for the Linux
> > kernel. I performed a deeper evaluation of its security properties and
> > developed new features like quarantine randomization and integration with
> > init_on_free. That is fun! See below for more details.
> >
> >
> > Rationale
> > =========
> >
> > Use-after-free vulnerabilities in the Linux kernel are very popular for
> > exploitation. There are many examples, some of them:
> >  https://googleprojectzero.blogspot.com/2018/09/a-cache-invalidation-bug-in-linux.html

I don't think your proposed mitigation would work with much
reliability against this bug; the attacker has full control over the
timing of the original use and the following use, so an attacker
should be able to trigger the kmem_cache_free(), then spam enough new
VMAs and delete them to flush out the quarantine, and then do heap
spraying as normal, or something like that.

Also, note that here, if the reallocation fails, the kernel still
wouldn't crash because the dangling object is not accessed further if
the address range stored in it doesn't match the fault address. So an
attacker could potentially try multiple times, and if the object
happens to be on the quarantine the first time, that wouldn't really
be a showstopper, you'd just try again.

> >  https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html?m=1

I think that here, again, the free() and the dangling pointer use were
caused by separate syscalls, meaning the attacker had control over
that timing?

> >  https://a13xp0p0v.github.io/2020/02/15/CVE-2019-18683.html

Haven't looked at that one in detail.

> > Use-after-free exploits usually employ heap spraying technique.
> > Generally it aims to put controlled bytes at a predetermined memory
> > location on the heap.

Well, not necessarily "predetermined". Depending on the circumstances,
you don't necessarily need to know which address you're writing to;
and you might not even need to overwrite a specific object, but
instead just have to overwrite one out of a bunch of objects, no
matter which.

> > Heap spraying for exploiting use-after-free in the Linux kernel relies on
> > the fact that on kmalloc(), the slab allocator returns the address of
> > the memory that was recently freed.

Yeah; and that behavior is pretty critical for performance. The longer
it's been since a newly allocated object was freed, the higher the
chance that you'll end up having to go further down the memory cache
hierarchy.

> > So allocating a kernel object with
> > the same size and controlled contents allows overwriting the vulnerable
> > freed object.

The vmacache exploit you linked to doesn't do that, it frees the
object all the way back to the page allocator and then sprays 4MiB of
memory from the page allocator. (Because VMAs use their own
kmem_cache, and the kmem_cache wasn't merged with any interesting
ones, and I saw no good way to exploit the bug by reallocating another
VMA over the old VMA back then. Although of course that doesn't mean
that there is no such way.)

[...]
> > Security properties
> > ===================
> >
> > For researching security properties of the heap quarantine I developed 2 lkdtm
> > tests (see the patch 5/6).
> >
> > The first test is called lkdtm_HEAP_SPRAY. It allocates and frees an object
> > from a separate kmem_cache and then allocates 400000 similar objects.
> > I.e. this test performs an original heap spraying technique for use-after-free
> > exploitation.
> >
> > If CONFIG_SLAB_QUARANTINE is disabled, the freed object is instantly
> > reallocated and overwritten:
> >   # echo HEAP_SPRAY > /sys/kernel/debug/provoke-crash/DIRECT
> >    lkdtm: Performing direct entry HEAP_SPRAY
> >    lkdtm: Allocated and freed spray_cache object 000000002b5b3ad4 of size 333
> >    lkdtm: Original heap spraying: allocate 400000 objects of size 333...
> >    lkdtm: FAIL: attempt 0: freed object is reallocated
> >
> > If CONFIG_SLAB_QUARANTINE is enabled, 400000 new allocations don't overwrite
> > the freed object:
> >   # echo HEAP_SPRAY > /sys/kernel/debug/provoke-crash/DIRECT
> >    lkdtm: Performing direct entry HEAP_SPRAY
> >    lkdtm: Allocated and freed spray_cache object 000000009909e777 of size 333
> >    lkdtm: Original heap spraying: allocate 400000 objects of size 333...
> >    lkdtm: OK: original heap spraying hasn't succeed
> >
> > That happens because pushing an object through the quarantine requires _both_
> > allocating and freeing memory. Objects are released from the quarantine on
> > new memory allocations, but only when the quarantine size is over the limit.
> > And the quarantine size grows on new memory freeing.
> >
> > That's why I created the second test called lkdtm_PUSH_THROUGH_QUARANTINE.
> > It allocates and frees an object from a separate kmem_cache and then performs
> > kmem_cache_alloc()+kmem_cache_free() for that cache 400000 times.
> > This test effectively pushes the object through the heap quarantine and
> > reallocates it after it returns back to the allocator freelist:
[...]
> > As you can see, the number of the allocations that are needed for overwriting
> > the vulnerable object is almost the same. That would be good for stable
> > use-after-free exploitation and should not be allowed.
> > That's why I developed the quarantine randomization (see the patch 4/6).
> >
> > This randomization required very small hackish changes of the heap quarantine
> > mechanism. At first all quarantine batches are filled by objects. Then during
> > the quarantine reducing I randomly choose and free 1/2 of objects from a
> > randomly chosen batch. Now the randomized quarantine releases the freed object
> > at an unpredictable moment:
> >    lkdtm: Target object is reallocated at attempt 107884
[...]
> >    lkdtm: Target object is reallocated at attempt 87343

Those numbers are fairly big. At that point you might not even fit
into L3 cache anymore, right? You'd often be hitting DRAM for new
allocations? And for many slabs, you might end using much more memory
for the quarantine than for actual in-use allocations.

It seems to me like, for this to stop attacks with a high probability,
you'd have to reserve a huge chunk of kernel memory for the
quarantines - even if the attacker doesn't know anything about the
status of the quarantine (which isn't necessarily the case, depending
on whether the attacker can abuse microarchitectural data leakage, or
if the attacker can trigger a pure data read through the dangling
pointer), they should still be able to win with a probability around
quarantine_size/allocated_memory_size if they have a heap spraying
primitive without strict limits.

> > However, this randomization alone would not disturb the attacker, because
> > the quarantine stores the attacker's data (the payload) in the sprayed objects.
> > I.e. the reallocated and overwritten vulnerable object contains the payload
> > until the next reallocation (very bad).
> >
> > Hence heap objects should be erased before going to the heap quarantine.
> > Moreover, filling them by zeros gives a chance to detect use-after-free
> > accesses to non-zero data while an object stays in the quarantine (nice!).
> > That functionality already exists in the kernel, it's called init_on_free.
> > I integrated it with CONFIG_SLAB_QUARANTINE in the patch 3/6.
> >
> > During that work I found a bug: in CONFIG_SLAB init_on_free happens too
> > late, and heap objects go to the KASAN quarantine being dirty. See the fix
> > in the patch 2/6.
[...]
> I've made various tests on real hardware and in virtual machines:
>  1) network throughput test using iperf
>      server: iperf -s -f K
>      client: iperf -c 127.0.0.1 -t 60 -f K
>  2) scheduler stress test
>      hackbench -s 4000 -l 500 -g 15 -f 25 -P
>  3) building the defconfig kernel
>      time make -j2
>
> I compared Linux kernel 5.9.0-rc6 with:
>  - init_on_free=off,
>  - init_on_free=on,
>  - CONFIG_SLAB_QUARANTINE=y (which enables init_on_free).
>
> Each test was performed 5 times. I will show the mean values.
> If you are interested, I can share all the results and calculate standard deviation.
>
> Real hardware, Intel Core i7-6500U CPU
>  1) Network throughput test with iperf
>      init_on_free=off: 5467152.2 KBytes/sec
>      init_on_free=on: 3937545 KBytes/sec (-28.0% vs init_on_free=off)
>      CONFIG_SLAB_QUARANTINE: 3858848.6 KBytes/sec (-2.0% vs init_on_free=on)
>  2) Scheduler stress test with hackbench
>      init_on_free=off: 8.5364s
>      init_on_free=on: 8.9858s (+5.3% vs init_on_free=off)
>      CONFIG_SLAB_QUARANTINE: 17.2232s (+91.7% vs init_on_free=on)

These numbers seem really high for a mitigation, especially if that
performance hit does not really buy you deterministic protection
against many bugs.

[...]
> N.B. There was NO performance optimization made for this version of the heap
> quarantine prototype. The main effort was put into researching its security
> properties (hope for your feedback). Performance optimization will be done in
> further steps, if we see that my work is worth doing.

But you are pretty much inherently limited in terms of performance by
the effect the quarantine has on the data cache, right?

It seems to me like, if you want to make UAF exploitation harder at
the heap allocator layer, you could do somewhat more effective things
with a probably much smaller performance budget. Things like
preventing the reallocation of virtual kernel addresses with different
types, such that an attacker can only replace a UAF object with
another object of the same type. (That is not an idea I like very much
either, but I would like it more than this proposal.) (E.g. some
browsers implement things along those lines, I believe.)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez1tNU_7n8qtnxTYZ5qt-upJ81Fcb0P2rZe38ARK%3DiyBkA%40mail.gmail.com.
