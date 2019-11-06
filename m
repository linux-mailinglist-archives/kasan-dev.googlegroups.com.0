Return-Path: <kasan-dev+bncBCMIZB7QWENRBC5JRLXAKGQEJJOCPSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B06DF1276
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Nov 2019 10:38:21 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id t20sf6868414ply.9
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Nov 2019 01:38:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573033099; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y9k7EhhM1NFlwKpgAJipKQL0E6yqx3ZSFbJ5UgFmbZa+F221KpBkIY+pLbVFcSme4t
         DYGS3RuNTMD4rAUgwDeBVjnpWPDjAdFQq8CpV9vIbNsYlQaeu/XDUnhSSv+NOYREl2l6
         duUkQlkORF5cruYGs76eHwIsKCHB5vkk6MEdjplOrN146f8QpM6xw7cmibaiXPAROrY3
         kstyDuslDRLA5pzaNB9I7Xkly86WTC8FORWfpnVGUaCtX4sIqzL/YeAfGflYwz3aGo2J
         As3TVDTbH4Qox4jj02VeXqh2tex6g3DNZ5Nt0EjSWh0mW4tIodZwOfHXn1NxJTnnB2hO
         LLwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=881gbCZiduVuDYcxfxBBtQC+/UGqhPttFUoiJaVxeKE=;
        b=GftspJHQ+BHwbibEU5OE9WBOMDwApUdo3kBxzlnRYL1+hZMpSSsNgwn5V5i7goJdrj
         YEza1nxFWyNGj0MNIj3b3xu3IZkyWiahV3Hcc+WlL1hYAyHcdpNyWZZAcnWbrznRHvhh
         PZrnkKBwjQD4X3oLrcsrkXp5d7Us8yC8Hs0BnoMETpB0zK5eLjyK9oTZmI/+F1oJbJKw
         U9EXbxqVZjsbVAaQcGNpe8Ah4sVhjeKCxswCQ0+GAnoORvjmTbnfvyj3wAumSVl9V4I0
         jgkIXt4GfuprkOwPP9Y8ryF7GKCPpOmmpve1lQPSIpYzesig7NrzWIHSE5qLtEg4/XS3
         fZ5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WyLOeEaE;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=881gbCZiduVuDYcxfxBBtQC+/UGqhPttFUoiJaVxeKE=;
        b=p6VGXZgt4yP/d4OSwgA5UpIjxMIMYbegUoF3CtkIDKz7jmGre5lxHn9sVSQRL9duKY
         UbqAULwPqKP0BALYRZh0urgTOkca6/9GQWNCNH3BtIzL55y1T+GHMaZTwUOZ5osDPmYd
         hpEGR3omKWOGU7wf6aRNC7B1FhyonNGcsJ1n4D34BRcFf3pRYAZVTpIr+i9eiSeEZGdj
         DSe4ROV4h+Yv+3gmHrpW0B2bZrJZofpsrRqq7WATJPQWXxkDiMVlpGRf0h4fjkRAfkKp
         M8hPtRO5OD84tFvZH661w5Xtk4J7KCoFW0rAclvdEb0bGthOZMFRo9IxlQygrtG4BNyA
         lvhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=881gbCZiduVuDYcxfxBBtQC+/UGqhPttFUoiJaVxeKE=;
        b=PZAlqsw6wCVmVeG4Jj1aD8Yhk2aDITB09VG6ZkLHoijezKGIYScQs402tPLV4K026U
         ZMWstxNpyG6zIgckvTVhtAnqhVcPdCRRiYAqNb+gj53koyylvftrh9BX/oRzk/RjwLqd
         hPVu/5dQhKjqSa/5QZqsT/kCbqxASDViBZm9t1vHFAFs8Z0v6aowLuCXmRHUN3mJbwZt
         uJ9B0t3XnOKu6x/quiTotuRop3wFlBMYenKqMqMxMwSBCVMK194UEbjfnbZve/zoWSoT
         bSEKj9Njghm+rMoRox/Bzq4mNtF9jkZuMRvTHamtfqCqQfwyuOlYoBnug2WWHobLNE4h
         qLRg==
X-Gm-Message-State: APjAAAVOb7Mg9gWyxJzU9REJtl2UAVrqepfsuQx5ngbB9gbmDbyuwW8H
	+1AYmc2XPUDolCNieAuJALc=
X-Google-Smtp-Source: APXvYqyVAfLy5b6Rs6v22Bnk6tPNG1LSmZQN9MoC0No9EGhQ9Yoi17MtUwGMD9D6p9ASt062v630Pg==
X-Received: by 2002:a17:90a:ca04:: with SMTP id x4mr2499604pjt.103.1573033099707;
        Wed, 06 Nov 2019 01:38:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5107:: with SMTP id f7ls478589pfb.2.gmail; Wed, 06 Nov
 2019 01:38:19 -0800 (PST)
X-Received: by 2002:a65:404b:: with SMTP id h11mr1803585pgp.28.1573033099158;
        Wed, 06 Nov 2019 01:38:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573033099; cv=none;
        d=google.com; s=arc-20160816;
        b=qxw4YAZUyC9f84Zgfjxa8ql83dGYwBQc9kQrRMlkxKY5mkm+2/HctSSB9wvmUfK0kv
         qAeXKc0D9P/1i0ah0OqywhjFOtmhSKlckHDP0CI9GdTCB2P9ZTL6+LWCqFP/xKuO86NK
         3md7sKQjMHU1onwnq7+tsb8cZRyOGxDn9YKwIamUaISdD6QqBipjoTJrFqFunnPbFVZz
         re0Wo96xUNh8+Xkh9MsV9PlHs6k/qelAKqHGQ97BZRV1sXKA233FjrGiOZ4LwGdj5iGp
         8lwV16Fcx2Gu4pxUcjWK85ryVyYpURW8ciMv1HPgmNzSUbgjCGR3+fCwRgeph8OpK2QW
         1wdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qhR5UVinklxMuAplLCv9Zree1TqFXmJG+VTPQkm46Kk=;
        b=JUkZhywLVSQx4E+UrJlg9n+S/HLUPnijheZJTqGjSmYmqYltaxWjxOktyfzu9ezD6F
         mmN87T67E2/jTCAamGYqhwIWzZfzJxDxyD1OU3smNoHCIJLW0HScC/ZVhcFUoynL9Uxg
         7MZxwGUvdcub9ZaqSlOABuOONFk0/hMx4/54FihJNXqFem/t4N5u3buwMPFra/LmSW0I
         7EqFQbVqu9U1HAKkRhoUJMIUUB+OjVsk/mvLNrW2n1SO3kV0xVJ2dmUK1NZoUd01ZXVU
         z9IBSpepPX4JWGenrbF6AUZR5W3tWBXZ9gKvYO0aR7Qyk1O98NPmZ7RE60jdqbRXPzna
         sksg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WyLOeEaE;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id be9si951420plb.3.2019.11.06.01.38.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Nov 2019 01:38:19 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id a18so6336101qkk.7
        for <kasan-dev@googlegroups.com>; Wed, 06 Nov 2019 01:38:19 -0800 (PST)
X-Received: by 2002:a05:620a:14b9:: with SMTP id x25mr1198400qkj.8.1573033097365;
 Wed, 06 Nov 2019 01:38:17 -0800 (PST)
MIME-Version: 1.0
References: <20191104142745.14722-1-elver@google.com> <20191104142745.14722-2-elver@google.com>
In-Reply-To: <20191104142745.14722-2-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 Nov 2019 10:38:05 +0100
Message-ID: <CACT4Y+a+ftjHnRx9PD48hEVm98muooHwO0Y7i3cHetTJobRDxg@mail.gmail.com>
Subject: Re: [PATCH v3 1/9] kcsan: Add Kernel Concurrency Sanitizer infrastructure
To: Marco Elver <elver@google.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, 
	Jade Alglave <j.alglave@ucl.ac.uk>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Luc Maranget <luc.maranget@inria.fr>, Mark Rutland <mark.rutland@arm.com>, 
	Nicholas Piggin <npiggin@gmail.com>, paulmck@kernel.org, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	"open list:KERNEL BUILD + fi..." <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux-MM <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WyLOeEaE;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, Nov 4, 2019 at 3:28 PM Marco Elver <elver@google.com> wrote:
>
> Kernel Concurrency Sanitizer (KCSAN) is a dynamic data-race detector for
> kernel space. KCSAN is a sampling watchpoint-based data-race detector.
> See the included Documentation/dev-tools/kcsan.rst for more details.
...
> +static inline atomic_long_t *find_watchpoint(unsigned long addr, size_t size,
> +                                            bool expect_write,
> +                                            long *encoded_watchpoint)
> +{
> +       const int slot = watchpoint_slot(addr);
> +       const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
> +       atomic_long_t *watchpoint;
> +       unsigned long wp_addr_masked;
> +       size_t wp_size;
> +       bool is_write;
> +       int i;
> +
> +       BUILD_BUG_ON(CONFIG_KCSAN_NUM_WATCHPOINTS < CHECK_NUM_SLOTS);
> +
> +       for (i = 0; i < CHECK_NUM_SLOTS; ++i) {
> +               watchpoint = &watchpoints[SLOT_IDX(slot, i)];


The fast path code become much nicer!
I did another pass looking at how we can optimize the fast path.
Currently we still have 2 push/pop pairs on the fast path because of
register pressure. The logic in SLOT_IDX seems to be the main culprit.
We discussed several options offline:
1. Just check 1 slot and ignore all corner cases (we will miss racing
unaligned access to different addresses but overlapping and crossing
pages, which sounds pretty esoteric)
2. Check 3 slots in order and without wraparound (watchpoints[slot +
i], where i=-1,0,1), this will require adding dummy slots around the
array
3. An interesting option is to check just 2 slots (that's enough!), to
make this work we will need to slightly offset bucket number when
setting a watch point (namely, if an access goes to the very end of a
page, we set the watchpoint into the bucket corresponding to the
_next_ page)
All of these options remove push/pop in my experiments. Obviously
checking fewer slots will reduce dynamic overhead even more.


> +               *encoded_watchpoint = atomic_long_read(watchpoint);
> +               if (!decode_watchpoint(*encoded_watchpoint, &wp_addr_masked,
> +                                      &wp_size, &is_write))
> +                       continue;
> +
> +               if (expect_write && !is_write)
> +                       continue;
> +
> +               /* Check if the watchpoint matches the access. */
> +               if (matching_access(wp_addr_masked, wp_size, addr_masked, size))
> +                       return watchpoint;
> +       }
> +
> +       return NULL;
> +}
> +
> +static inline atomic_long_t *insert_watchpoint(unsigned long addr, size_t size,
> +                                              bool is_write)
> +{
> +       const int slot = watchpoint_slot(addr);
> +       const long encoded_watchpoint = encode_watchpoint(addr, size, is_write);
> +       atomic_long_t *watchpoint;
> +       int i;
> +
> +       for (i = 0; i < CHECK_NUM_SLOTS; ++i) {
> +               long expect_val = INVALID_WATCHPOINT;
> +
> +               /* Try to acquire this slot. */
> +               watchpoint = &watchpoints[SLOT_IDX(slot, i)];

If we do this SLOT_IDX trickery to catch unaligned accesses crossing
pages, then I think we should not use it insert_watchpoint at all and
only set the watchpoint to the exact index. Otherwise, we will
actually miss the corner cases which defeats the whole purpose of
SLOT_IDX and 3 iterations.

> +               if (atomic_long_try_cmpxchg_relaxed(watchpoint, &expect_val,
> +                                                   encoded_watchpoint))
> +                       return watchpoint;
> +       }
> +
> +       return NULL;
> +}
> +
> +/*
> + * Return true if watchpoint was successfully consumed, false otherwise.
> + *
> + * This may return false if:
> + *
> + *     1. another thread already consumed the watchpoint;
> + *     2. the thread that set up the watchpoint already removed it;
> + *     3. the watchpoint was removed and then re-used.
> + */
> +static inline bool try_consume_watchpoint(atomic_long_t *watchpoint,
> +                                         long encoded_watchpoint)
> +{
> +       return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint,
> +                                              CONSUMED_WATCHPOINT);
> +}
> +
> +/*
> + * Return true if watchpoint was not touched, false if consumed.
> + */
> +static inline bool remove_watchpoint(atomic_long_t *watchpoint)
> +{
> +       return atomic_long_xchg_relaxed(watchpoint, INVALID_WATCHPOINT) !=
> +              CONSUMED_WATCHPOINT;
> +}
> +
> +static inline struct kcsan_ctx *get_ctx(void)
> +{
> +       /*
> +        * In interrupt, use raw_cpu_ptr to avoid unnecessary checks, that would
> +        * also result in calls that generate warnings in uaccess regions.
> +        */
> +       return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
> +}
> +
> +static inline bool is_atomic(const volatile void *ptr)
> +{
> +       struct kcsan_ctx *ctx = get_ctx();
> +
> +       if (unlikely(ctx->atomic_next > 0)) {
> +               --ctx->atomic_next;
> +               return true;
> +       }
> +       if (unlikely(ctx->atomic_nest_count > 0 || ctx->in_flat_atomic))
> +               return true;
> +
> +       return kcsan_is_atomic(ptr);
> +}
> +
> +static inline bool should_watch(const volatile void *ptr, int type)
> +{
> +       /*
> +        * Never set up watchpoints when memory operations are atomic.
> +        *
> +        * Need to check this first, before kcsan_skip check below: (1) atomics
> +        * should not count towards skipped instructions, and (2) to actually
> +        * decrement kcsan_atomic_next for consecutive instruction stream.
> +        */
> +       if ((type & KCSAN_ACCESS_ATOMIC) != 0 || is_atomic(ptr))
> +               return false;

should_watch and is_atomic are invoked on the fast path and do more
things than strictly necessary.
The minimal amount of actions would be:
 - check and decrement ctx->atomic_next for atomic accesses
 - decrement kcsan_skip

atomic_nest_count/in_flat_atomic/kcsan_is_atomic can be checked on
uninlined slow path.

It should not be necessary to set kcsan_skip to -1 if we _always_
resetup kcsan_skip on slow path.

> +       if (this_cpu_dec_return(kcsan_skip) >= 0)
> +               return false;
> +
> +       /* avoid underflow if !kcsan_is_enabled() */
> +       this_cpu_write(kcsan_skip, -1);
> +
> +       /* this operation should be watched */
> +       return true;
> +}
> +
> +static inline void reset_kcsan_skip(void)
> +{
> +       long skip_count = CONFIG_KCSAN_SKIP_WATCH -
> +                         (IS_ENABLED(CONFIG_KCSAN_SKIP_WATCH_RANDOMIZE) ?
> +                                  prandom_u32_max(CONFIG_KCSAN_SKIP_WATCH) :
> +                                  0);
> +       this_cpu_write(kcsan_skip, skip_count);
> +}
> +
> +static inline bool kcsan_is_enabled(void)
> +{
> +       return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
> +}
> +
> +static inline unsigned int get_delay(void)
> +{
> +       unsigned int delay = in_task() ? CONFIG_KCSAN_UDELAY_TASK :
> +                                        CONFIG_KCSAN_UDELAY_INTERRUPT;
> +       return delay - (IS_ENABLED(CONFIG_KCSAN_DELAY_RANDOMIZE) ?
> +                               prandom_u32_max(delay) :
> +                               0);
> +}
> +
> +/*
> + * Pull everything together: check_access() below contains the performance
> + * critical operations; the fast-path (including check_access) functions should
> + * all be inlinable by the instrumentation functions.
> + *
> + * The slow-path (kcsan_found_watchpoint, kcsan_setup_watchpoint) are
> + * non-inlinable -- note that, we prefix these with "kcsan_" to ensure they can
> + * be filtered from the stacktrace, as well as give them unique names for the
> + * UACCESS whitelist of objtool. Each function uses user_access_save/restore(),
> + * since they do not access any user memory, but instrumentation is still
> + * emitted in UACCESS regions.
> + */
> +
> +static noinline void kcsan_found_watchpoint(const volatile void *ptr,
> +                                           size_t size, bool is_write,
> +                                           bool consumed)
> +{
> +       unsigned long flags = user_access_save();
> +       enum kcsan_report_type report_type;
> +
> +       if (!consumed) {
> +               /*
> +                * The other thread may not print any diagnostics, as it has
> +                * already removed the watchpoint, or another thread consumed
> +                * the watchpoint before this thread.
> +                */
> +               kcsan_counter_inc(KCSAN_COUNTER_REPORT_RACES);
> +               report_type = KCSAN_REPORT_RACE_CHECK_RACE;
> +       } else {
> +               report_type = KCSAN_REPORT_RACE_CHECK;
> +       }
> +
> +       kcsan_counter_inc(KCSAN_COUNTER_DATA_RACES);
> +       kcsan_report(ptr, size, is_write, raw_smp_processor_id(), report_type);
> +
> +       user_access_restore(flags);
> +}
> +
> +static noinline void kcsan_setup_watchpoint(const volatile void *ptr,
> +                                           size_t size, bool is_write)
> +{
> +       atomic_long_t *watchpoint;
> +       union {
> +               u8 _1;
> +               u16 _2;
> +               u32 _4;
> +               u64 _8;
> +       } expect_value;
> +       bool is_expected = true;
> +       unsigned long ua_flags = user_access_save();
> +       unsigned long irq_flags;
> +
> +       if (!check_encodable((unsigned long)ptr, size)) {
> +               kcsan_counter_inc(KCSAN_COUNTER_UNENCODABLE_ACCESSES);
> +               goto out;
> +       }
> +
> +       /*
> +        * Disable interrupts & preemptions to avoid another thread on the same
> +        * CPU accessing memory locations for the set up watchpoint; this is to
> +        * avoid reporting races to e.g. CPU-local data.
> +        *
> +        * An alternative would be adding the source CPU to the watchpoint
> +        * encoding, and checking that watchpoint-CPU != this-CPU. There are
> +        * several problems with this:
> +        *   1. we should avoid stealing more bits from the watchpoint encoding
> +        *      as it would affect accuracy, as well as increase performance
> +        *      overhead in the fast-path;
> +        *   2. if we are preempted, but there *is* a genuine data race, we
> +        *      would *not* report it -- since this is the common case (vs.
> +        *      CPU-local data accesses), it makes more sense (from a data race
> +        *      detection point of view) to simply disable preemptions to ensure
> +        *      as many tasks as possible run on other CPUs.
> +        */
> +       local_irq_save(irq_flags);
> +
> +       watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
> +       if (watchpoint == NULL) {
> +               /*
> +                * Out of capacity: the size of `watchpoints`, and the frequency
> +                * with which `should_watch()` returns true should be tweaked so
> +                * that this case happens very rarely.
> +                */
> +               kcsan_counter_inc(KCSAN_COUNTER_NO_CAPACITY);
> +               goto out_unlock;
> +       }
> +
> +       /*
> +        * Reset kcsan_skip counter: only do this if we succeeded in setting up
> +        * a watchpoint.
> +        */
> +       reset_kcsan_skip();
> +
> +       kcsan_counter_inc(KCSAN_COUNTER_SETUP_WATCHPOINTS);
> +       kcsan_counter_inc(KCSAN_COUNTER_USED_WATCHPOINTS);
> +
> +       /*
> +        * Read the current value, to later check and infer a race if the data
> +        * was modified via a non-instrumented access, e.g. from a device.
> +        */
> +       switch (size) {
> +       case 1:
> +               expect_value._1 = READ_ONCE(*(const u8 *)ptr);
> +               break;
> +       case 2:
> +               expect_value._2 = READ_ONCE(*(const u16 *)ptr);
> +               break;
> +       case 4:
> +               expect_value._4 = READ_ONCE(*(const u32 *)ptr);
> +               break;
> +       case 8:
> +               expect_value._8 = READ_ONCE(*(const u64 *)ptr);
> +               break;
> +       default:
> +               break; /* ignore; we do not diff the values */
> +       }
> +
> +       if (IS_ENABLED(CONFIG_KCSAN_DEBUG)) {
> +               kcsan_disable_current();
> +               pr_err("KCSAN: watching %s, size: %zu, addr: %px [slot: %d, encoded: %lx]\n",
> +                      is_write ? "write" : "read", size, ptr,
> +                      watchpoint_slot((unsigned long)ptr),
> +                      encode_watchpoint((unsigned long)ptr, size, is_write));
> +               kcsan_enable_current();
> +       }
> +
> +       /*
> +        * Delay this thread, to increase probability of observing a racy
> +        * conflicting access.
> +        */
> +       udelay(get_delay());
> +
> +       /*
> +        * Re-read value, and check if it is as expected; if not, we infer a
> +        * racy access.
> +        */
> +       switch (size) {
> +       case 1:
> +               is_expected = expect_value._1 == READ_ONCE(*(const u8 *)ptr);
> +               break;
> +       case 2:
> +               is_expected = expect_value._2 == READ_ONCE(*(const u16 *)ptr);
> +               break;
> +       case 4:
> +               is_expected = expect_value._4 == READ_ONCE(*(const u32 *)ptr);
> +               break;
> +       case 8:
> +               is_expected = expect_value._8 == READ_ONCE(*(const u64 *)ptr);
> +               break;
> +       default:
> +               break; /* ignore; we do not diff the values */
> +       }
> +
> +       /* Check if this access raced with another. */
> +       if (!remove_watchpoint(watchpoint)) {
> +               /*
> +                * No need to increment 'data_races' counter, as the racing
> +                * thread already did.
> +                */
> +               kcsan_report(ptr, size, is_write, smp_processor_id(),
> +                            KCSAN_REPORT_RACE_SETUP);
> +       } else if (!is_expected) {
> +               /* Inferring a race, since the value should not have changed. */
> +               kcsan_counter_inc(KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN);
> +               if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN))
> +                       kcsan_report(ptr, size, is_write, smp_processor_id(),
> +                                    KCSAN_REPORT_RACE_UNKNOWN_ORIGIN);
> +       }
> +
> +       kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
> +out_unlock:
> +       local_irq_restore(irq_flags);
> +out:
> +       user_access_restore(ua_flags);
> +}
> +
> +static inline void check_access(const volatile void *ptr, size_t size, int type)
> +{
> +       const bool is_write = (type & KCSAN_ACCESS_WRITE) != 0;
> +       atomic_long_t *watchpoint;
> +       long encoded_watchpoint;
> +
> +       if (IS_ENABLED(CONFIG_KCSAN_PLAIN_WRITE_PRETEND_ONCE) && is_write)
> +               type |= KCSAN_ACCESS_ATOMIC;
> +
> +       /*
> +        * Avoid user_access_save in fast-path: find_watchpoint is safe without
> +        * user_access_save, as the address that ptr points to is only used to
> +        * check if a watchpoint exists; ptr is never dereferenced.
> +        */
> +       watchpoint = find_watchpoint((unsigned long)ptr, size, !is_write,
> +                                    &encoded_watchpoint);
> +
> +       /*
> +        * It is safe to check kcsan_is_enabled() after find_watchpoint, but
> +        * right before we would enter the slow-path: no state changes that
> +        * cause a data race to be detected and reported have occurred yet.
> +        */
> +
> +       if (unlikely(watchpoint != NULL) && kcsan_is_enabled()) {

I would move kcsan_is_enabled and the rest of the code in the branch
into non-inlined slow path.
It makes the hot function much shorter.
There is a trick related to number of arguments, though. We would need
to pass ptr, size, is_write, watchpoint and encoded_watchpoint. That's
5 arguments. Only 4 are passed in registers. So it may make sense to
combine size and type into a single word. On the inlined fast path
compiler packs/unpacks that statically, so it does not matter. But for
the function call it will just forward a single const.


> +               /*
> +                * Try consume the watchpoint as soon after finding the
> +                * watchpoint as possible; this must always be guarded by
> +                * kcsan_is_enabled() check, as otherwise we might erroneously
> +                * triggering reports when disabled.
> +                */
> +               const bool consumed =
> +                       try_consume_watchpoint(watchpoint, encoded_watchpoint);
> +
> +               kcsan_found_watchpoint(ptr, size, is_write, consumed);
> +       } else if (unlikely(should_watch(ptr, type)) && kcsan_is_enabled()) {

I would move kcsan_is_enabled check into kcsan_setup_watchpoint. It's
not executed on fast path, but bloats the host function code.

> +               kcsan_setup_watchpoint(ptr, size, is_write);
> +       }
> +}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba%2BftjHnRx9PD48hEVm98muooHwO0Y7i3cHetTJobRDxg%40mail.gmail.com.
