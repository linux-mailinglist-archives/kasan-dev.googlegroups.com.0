Return-Path: <kasan-dev+bncBDW2JDUY5AORBROD26LAMGQEZ54KECQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 19284578DAD
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 00:42:15 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id w33-20020a056830412100b0061c790f13b5sf7152985ott.17
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 15:42:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658184134; cv=pass;
        d=google.com; s=arc-20160816;
        b=rg+xxz2beCJlSqIS7Yk6DTCWI1HYVwniXkkcjMQLV2J6EgYHuQE4f028WDWbJ9O0XV
         fNKR9Jn0cC11n5fhHcbIzRVfEU4dctuEuCrqjXUeBMYFM0GwliB/d2FsO/FuksPNM9Aq
         jxOVB8+LHkXCNQrSB+Azu0guUx8GnYHrmX7v3R2QBBrKz2lJkCZSCUOI+h7RgLVcIJoK
         GoZnkGhQ2pQyd0J2M57ge7uwElpE+FDHTmT/nMDSDxIL53izgmnZN8J+X8y3d+vX2vI9
         xliJwW0OE67DcgoT9TJf0jkUEJbW8FteGzptFjT0m12RgYz72EiIlsbEiiJgG6FBAItE
         gsRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=5OH0s5zdgkvCpUWLDymfKIAGml6O58+KPe+wYOmKl2A=;
        b=o5pgt9JY444D+qF9BX+GuY//JNyvTuPIUC2e3H0uVbwM1WLqZjZqdXl9l5msoBDbXE
         oW4m0QQdQMNFaC9gweEdpY1h0gdHv0aBW/IEwRro/ctIyXns4wI7Y9sSyzOXAAw3e3Ga
         a6xjA9N0mA0YkGxn7LuGRuuXvk1nn7YJ99uaRkxvB/VhvdrCxPUVv5XCpRrDhn52gkjb
         TeUpZyDQjkc325/O+a4S1R/oqEAqiyFP2YuNcXnD6icZEFUPLBuo356vObflxgtqANXZ
         qSMkN0CbhKJcblOwd5CwMj1qNRC60EdcMYmFud5cE9Blvdzi9uSu6MvHvKZ1j+YeTup/
         k7yA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=TMkZVh5c;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5OH0s5zdgkvCpUWLDymfKIAGml6O58+KPe+wYOmKl2A=;
        b=L5IJN4Hob0+cA0G3P9Ia640rnAoNpkwaaxbzKIV2NFCdzRYFeaJt5wvcls8Ge0Oafp
         zE+ktVrQAZfZBWhqSiX1pNrvihn8OXkYcSVWIFg7gp9J2L133473TwgiglxbZgHsJCcl
         GR3upSwoKbBGj7kL+sYz9g/eIeToj0MYhF/WCT6heUvVSl5fLKMmVlzwO6In6j6nIrG4
         NcIFfs20rn6QBy02piLbHQXVcnDkSdXAuY7AHllm3/zfxUQ2BAEAljJ/IwlOTvrYjwfc
         wL59gkfDwZeaBTpw9Fdo6Q8rJB/3ydGSzBEeiCmhmZo+9Xi5SDX7rY4qvWFQnDlWmmTG
         DTiQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5OH0s5zdgkvCpUWLDymfKIAGml6O58+KPe+wYOmKl2A=;
        b=hhmh/rsr+DNBAuwV3bO8xhlHzJPhPf+v2zeSMdzVT37+3FxDshDXJbRlDXFpga2yX8
         hxKith3hUR1je8Cw4ZSgqJo2wgZVlANpZh7+HXsKpIJDMUbiTSFGwkbNVzGOoYdKFLhy
         f6HrqvRXX9ls9+AkrjrkEfoPePBsKcRCLYroD9cAUhwktjNuf4MKyp7lp17C/0fD3zFP
         Zoixz/MuO+nF67B3LIMT/wcvQJzF9E4d9CBA7BBPT10gyGAwVygcdaa27KCj5ZRtDuSM
         0PdwOSd0Hlm7bAHJcsNvobwxwZtE+/VMvZvQQYKuvwMGs1ztl956dCw+8clT2y3gp/Ak
         AF/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5OH0s5zdgkvCpUWLDymfKIAGml6O58+KPe+wYOmKl2A=;
        b=Gud7UaHD4J/OIQ0q4CPMR9ZAeGd03rPPSiMK8yAA7U9Rmu9/SxN+sBiUP7pMV3v7c3
         PLPOL4/wlBAy6Bh9z5e+VI2cxFBnk2mbo2azrdlFMHckBliyxls7Shi1N1ZUSi4ydQhx
         MryVOqiOE9SHvM9Y5EC5eGCw+EIpwbYi3E545CXAORw5P2iMFTP9861oDXNyiqruHBDG
         MmgyukvcT0iCDIQoNj2jOozK8ybh3dF20pm+oDF07rHB1/RzwiLRlmO9CljneQYYo74q
         yFrUcj4Sxyl3dlHGtSHLCFMjeb1g01abiflIwuh6etpYEnZAebyNBjG6gumOBx/WRMc+
         7Juw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8HB8WeLFoBcx4Dphqw/UM2MlESIVrWT9kDzLCm4/Elm9k1MPTy
	Vd4v1AxFs15Qch/hMYrw5CA=
X-Google-Smtp-Source: AGRyM1tfZgGnXtIXE3sCzr+RnLyqyyOxHG8NYHGZKtYjsa2e5eMMtZ236tBeF27Sdp0l8f1Er89hWg==
X-Received: by 2002:a9d:4e8:0:b0:61c:565d:2c6b with SMTP id 95-20020a9d04e8000000b0061c565d2c6bmr11481726otm.264.1658184134034;
        Mon, 18 Jul 2022 15:42:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:829:0:b0:61c:8fed:3912 with SMTP id 38-20020a9d0829000000b0061c8fed3912ls1167999oty.2.gmail;
 Mon, 18 Jul 2022 15:42:13 -0700 (PDT)
X-Received: by 2002:a05:6830:2705:b0:618:ba52:86fb with SMTP id j5-20020a056830270500b00618ba5286fbmr12266282otu.202.1658184133662;
        Mon, 18 Jul 2022 15:42:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658184133; cv=none;
        d=google.com; s=arc-20160816;
        b=ZFWf3fWXlEqA3Y+ZuyMXqK7VE98wvbtChPTQtRPC7R+xQno6wUUjWJtGGzlVJKvMuX
         2RDiclULHRZZZDFCfPnbNvs/ypjo+4xYn2iyjkdJxXkHC5BPbx8tj3XQJNHmc+T+Rcqp
         gg6Be4ha2wM2NTM/rFKMWXjmtR8XBvWy40WkDIHApTS82KHRPF4seoPzVrLytecrukjs
         ncvUKeRQM4O8fO9diSKVqWijjoPyZ82mvYFazdXfTAJ6URKW1kFJqMFygEM9dxoI0niY
         vI1xxySWL3fu5Z6kdBgqF+heF8NigcBDyjX8gZnwuqfx0pUKma0j3q2weM1SFz2trMUK
         ukvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Srf+AYvhoPZ4SANiE5r//Mtt56L7Cxm65IjKMxEOpbM=;
        b=w090gOqe1CVlBxR3+fAcIs3r2lVHY3EKbHrpi3oNy/87L6bMatqr35ko/WbboeMf1H
         ZlWBgTn8mWXAQomSIYmlqtTqOPjdnjnF97r0tq+npyIUDQux4tG5mdAG4visYQgwBzWn
         Dfuznv0sh4/bspFvcG9kkkbwGBFSqzUrTQ/6NztMRxQCVwkptoj9Zvk+DdxYUVYOm3pt
         2WTFU6ejQBAJ2X8rR8zUH2NlAvCdEkmCnmF/5mOrqohrozV2WTOnnZRnBOZh5aLgB2GE
         NiYrqOT375TFNSwUWTSTtJsmyDA4YguWV1CiQv6lk+mTxQvOxVBaFLYAEqVmrYoYE1RM
         oYjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=TMkZVh5c;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x733.google.com (mail-qk1-x733.google.com. [2607:f8b0:4864:20::733])
        by gmr-mx.google.com with ESMTPS id l125-20020acabb83000000b0032b08d1cffbsi670950oif.1.2022.07.18.15.42.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Jul 2022 15:42:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::733 as permitted sender) client-ip=2607:f8b0:4864:20::733;
Received: by mail-qk1-x733.google.com with SMTP id f14so9987984qkm.0
        for <kasan-dev@googlegroups.com>; Mon, 18 Jul 2022 15:42:13 -0700 (PDT)
X-Received: by 2002:a37:4644:0:b0:6af:271e:a510 with SMTP id
 t65-20020a374644000000b006af271ea510mr20013693qka.515.1658184133183; Mon, 18
 Jul 2022 15:42:13 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1655150842.git.andreyknvl@google.com> <3cd76121903de13713581687ffa45e668ef1475a.1655150842.git.andreyknvl@google.com>
 <YrB3l6A4hJmvsFp3@elver.google.com>
In-Reply-To: <YrB3l6A4hJmvsFp3@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 19 Jul 2022 00:42:02 +0200
Message-ID: <CA+fCnZd5iataHnyBv9CVaXKN-2Ac=yLdODweMDiQB70nHZtpOA@mail.gmail.com>
Subject: Re: [PATCH 31/32] kasan: implement stack ring for tag-based modes
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=TMkZVh5c;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::733
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Jun 20, 2022 at 3:35 PM Marco Elver <elver@google.com> wrote:
>
> > The number of entries in the stack ring is fixed in this version of the
> > patch. We could either implement it as a config option or a command-line
> > argument. I tilt towards the latter option and will implement it in v2
> > unless there are objections.
>
> Yes, that'd be good, along with just not allocating if no stacktraces
> are requested per kasan.stacktrace=.

Sounds good, will do in v2.

> > +struct kasan_stack_ring_entry {
> > +     atomic64_t ptr;         /* void * */
> > +     atomic64_t size;        /* size_t */
> > +     atomic_t pid;           /* u32 */
> > +     atomic_t stack;         /* depot_stack_handle_t */
> > +     atomic_t is_free;       /* bool */
>
> Per comments below, consider making these non-atomic.

Will do in v2.

> >  void kasan_complete_mode_report_info(struct kasan_report_info *info)
> >  {
> > +     u64 pos;
> > +     struct kasan_stack_ring_entry *entry;
> > +     void *object;
> > +     u32 pid;
> > +     depot_stack_handle_t stack;
> > +     bool is_free;
>
> If you switch away from atomic for kasan_stack_ring_entry members, you
> can just replace the above with a 'struct kasan_stack_ring_entry' and
> READ_ONCE() each entry into it below.

It would be a bit confusing to have two kasan_stack_ring_entry-based
variable in the function. I'll keep the current code if you don't
mind.

> > +     bool alloc_found = false, free_found = false;
> > +
> >       info->bug_type = get_bug_type(info);
> > +
> > +     if (!info->cache || !info->object)
> > +             return;
> > +
> > +     pos = atomic64_read(&stack_ring.pos);
> > +
> > +     for (u64 i = pos - 1; i != pos - 1 - KASAN_STACK_RING_ENTRIES; i--) {
> > +             if (alloc_found && free_found)
> > +                     break;
> > +
> > +             entry = &stack_ring.entries[i % KASAN_STACK_RING_ENTRIES];
> > +
> > +             /* Paired with atomic64_set_release() in save_stack_info(). */
> > +             object = (void *)atomic64_read_acquire(&entry->ptr);
> > +
> > +             if (kasan_reset_tag(object) != info->object ||
> > +                 get_tag(object) != get_tag(info->access_addr))
> > +                     continue;
> > +
> > +             pid = atomic_read(&entry->pid);
> > +             stack = atomic_read(&entry->stack);
> > +             is_free = atomic_read(&entry->is_free);
> > +
> > +             /* Try detecting if the entry was changed while being read. */
> > +             smp_mb();
> > +             if (object != (void *)atomic64_read(&entry->ptr))
> > +                     continue;
>
> What if the object was changed, but 'ptr' is the same? It might very
> well be possible to then read half of the info of the previous object,
> and half of the new object (e.g. pid is old, stack is new).
>
> Is the assumption that it is extremely unlikely that this will happen
> where 1) address is the same, and 2) tags are the same? And if it does
> happen, it is unlikely that there'll be a bug on that address?
>
> It might be worth stating this in comments.

This part will be removed in v2 due to the addition of an rwlock, but
I'll add a comment about the stack ring being best-effort anyway.

> Another thing is, if there's a bug, but concurrently you have tons of
> allocations/frees that change the ring's entries at a very high rate,
> how likely is it that the entire ring will have been wiped before the
> entry of interest is found again?
>
> One way to guard against this is to prevent modifications of the ring
> while the ring is searched. This could be implemented with a
> percpu-rwsem, which is almost free for read-lockers but very expensive
> for write-lockers. Insertions only acquire a read-lock, but on a bug
> when searching the ring, you have to acquire a write-lock. Although you
> currently take the contention hit for incrementing 'pos', so a plain
> rwlock might also be ok.

Will add an rwlock in v2.

> It would be good to understand the probabilities of these corner cases
> with some average to worst case workloads, and optimize based on that.

With the new synchronizations and checks added in v2, the only
problematic issue is when the stack ring overflows. Please see my
response to your cover letter comment wrt this.

> > +struct kasan_stack_ring stack_ring;
>
> This is a very large struct. Can it be allocated by memblock_alloc()
> very early on only if required (kasan.stacktrace= can still switch it
> off, right?).

Will do in v2.

> > +void save_stack_info(struct kmem_cache *cache, void *object,
> > +                     gfp_t flags, bool is_free)
>
> static void save_stack_info(...)

Right, will do in v2.

> > +{
> > +     u64 pos;
> > +     struct kasan_stack_ring_entry *entry;
> > +     depot_stack_handle_t stack;
> > +
> > +     stack = kasan_save_stack(flags, true);
> > +
> > +     pos = atomic64_fetch_add(1, &stack_ring.pos);
> > +     entry = &stack_ring.entries[pos % KASAN_STACK_RING_ENTRIES];
> > +
> > +     atomic64_set(&entry->size, cache->object_size);
> > +     atomic_set(&entry->pid, current->pid);
> > +     atomic_set(&entry->stack, stack);
> > +     atomic_set(&entry->is_free, is_free);
> > +
>
> I don't see the point of these being atomic. You can make them normal
> variables with the proper types, and use READ_ONCE() / WRITE_ONCE().
>
> The only one where you truly need the atomic type is 'pos'.

Will do in v2.

> > +     /*
> > +      * Paired with atomic64_read_acquire() in
> > +      * kasan_complete_mode_report_info().
> > +      */
> > +     atomic64_set_release(&entry->ptr, (s64)object);
>
> This could be smp_store_release() and 'ptr' can be just a normal pointer.

Will do in v2.

> One thing that is not entirely impossible though (vs. re-reading same
> pointer but inconsistent fields I mentioned above), is if something
> wants to write to the ring, but stalls for a very long time before the
> release of 'ptr', giving 'pos' the chance to wrap around and another
> writer writing the same entry. Something like:
>
>   T0                                    | T1
>   --------------------------------------+--------------------------------
>   WRITE_ONCE(entry->size, ..)           |
>   WRITE_ONCE(entry->pid, ..)            |
>                                         | WRITE_ONCE(entry->size, ..)
>                                         | WRITE_ONCE(entry->pid, ..)
>                                         | WRITE_ONCE(entry->stack, ..)
>                                         | WRITE_ONCE(entry->is_free, ..)
>                                         | smp_store_release(entry->ptr, ...)
>   WRITE_ONCE(entry->stack, ..)          |
>   WRITE_ONCE(entry->is_free, ..)        |
>   smp_store_release(entry->ptr, ...)    |
>
> Which results in some mix of T0's and T1's data.
>
> The way to solve this is to implement a try-lock using 'ptr':
>
>         #define BUSY_PTR ((void*)1)  // non-zero because initial values are 0
>         old_ptr = READ_ONCE(entry->ptr);
>         if (old_ptr == BUSY_PTR)
>                 goto next; /* Busy slot. */
>         if (!try_cmpxchg(&entry->ptr, &old_ptr, BUSY_PTR))
>                 goto next; /* Busy slot. */
>         ... set fields as before ...
>         smp_store_release(&entry->ptr, object);

Sounds good, will do in v2.

Thank you, Marco!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd5iataHnyBv9CVaXKN-2Ac%3DyLdODweMDiQB70nHZtpOA%40mail.gmail.com.
