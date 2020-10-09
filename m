Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDOBQL6AKGQEYINYSIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id DC8A0289024
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Oct 2020 19:40:29 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id g7sf2236630lfh.20
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Oct 2020 10:40:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602265229; cv=pass;
        d=google.com; s=arc-20160816;
        b=rA51pz4kHtmbcX8+a6Ec6z3TFocfnDsNmlmLOTIvDS6Fq7mnQ1Lh552beQ2crollPl
         DIPXUgpqNZBpD8JWdr5arT8etWsDRZpkmySkMMhc9ZnT6lyTYbsHraw7Q3MlyQ16D6cY
         FoWtGIe9W0I69GssRYj6bLy+8ggShA4Ld3wYWT6vDt0ZFSCL9xnj7rMBGjM/7HCuMW1c
         bsVo28uoGpU770WmfHbSB1BE2KUJH5ZuqjuIlT9b3EUsFt1yuovC2n+9PePIcEA4S92Y
         W3fu+KzzAX57u8w8K8Ebn0jsAXnSUhyMRUKFTN8LhhaQVpTUESq0l0fx9S+R/ln5FQIa
         MhJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=QyVmqnyO3BLnws6tFvWudZm5UEkm0CCBB9eQhotXEe4=;
        b=tyt37XCF+LKYi3z/Wi3FWMg1RK6KErvaxyv+1HLctYMDliLZqj+ZBGCXPT4DmoYe/H
         8dKfj4dp6Q693G+rQcycEZAL32n+UvM7uQV/5npqf3dgKb5cJ4o4NtTlfi9ILlJL2Fzl
         mIYHqxwcfxaxAKGhSKdjpiRD/mMYUP9tvAqkujvW5aGCSDl3/T6HLBxs8kDmsUrF/+yO
         +f2EjtwewCm/fJoR+eelSgLwRooo6zaE8DiM2NcyPfrXouO2xnUdmoPKqcjDnq7aio21
         GJg38Juyo2PytuNd/sYENpgJXtbUGSGsW3mYf3t83t/GbJ6BOAvbIJ8bixlsqChXkjZe
         +Hlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=teg3EY+1;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=QyVmqnyO3BLnws6tFvWudZm5UEkm0CCBB9eQhotXEe4=;
        b=qfOlYCS3z+u3MzbiCo+35AbUWmNQpwQrZI2kApwreSj4LrhXCwF3SRSDMp/ZP1gUPW
         Xg8J4BwFi0k3SVMODMV44al9IM7jcUl35/R9P/LrZYTlhGvJF+0jPJa4ccZ8Ky24h+Ki
         KLTjeuJrmMQZx5o4fsOYuHF+nD89LHJiV0NlLTOvJUHXz4epTfdylBBZRmGTNtjhTf5A
         C2UApRnH3SweaN98mxRP3TBFH5EVnY6HRm2gwfaLyaleTnBhRCAsWJve3yeMXXSc9ObE
         YAVm83JF9g65BFlK+Xq41XPtMMI90KLstF4wE1Cj6CQO46kfbw3MxVNEm7tei07NCvNX
         ybAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QyVmqnyO3BLnws6tFvWudZm5UEkm0CCBB9eQhotXEe4=;
        b=pRJ4xD3kDiQNQ4ytHJwGlPwPsCGZrIe9Dan+3B4vq/76k0yOkXBPteRQwjUjvy+eLX
         ZNgncfXzJmLsOyor4fSgR7fkfNaPSk1ttvh60rGsosSjaTWOazQ9JcHbzNVqP/Nc15wS
         eMn/YlfS12QoHxOGuoLps6V20UZf5XQndsReAcA4dtQk+l17zQA31LNJgvbn635Ykijg
         s4Sje0RBhtEU0YXdSLVUdhCrQsCcChK06dnNFlH888byEGKH5aC5CDs/RBisSeqlcPtZ
         XSMiJfQRdyGmg0+FB0voDRzFRVsYh1d8KbOqibmw9zHlgTXb0JsRuaahlmJgWp4g5aQO
         Jqtw==
X-Gm-Message-State: AOAM533YSZrwdI6S9lTPT8AGWxtLYWGmwqHytRkC6scmdhUASfXA2NRL
	MVwis4ZtSQn+9ZF7fcXyBY0=
X-Google-Smtp-Source: ABdhPJz0tQ3AKyyGmHuwbkrZLGS1PrOgBXQlczDDUuqLOtFYGCaD9AQF0+yBgxltr4A84Pm+6kuFxw==
X-Received: by 2002:ac2:5597:: with SMTP id v23mr5154696lfg.301.1602265229372;
        Fri, 09 Oct 2020 10:40:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c7c8:: with SMTP id x191ls5675634lff.0.gmail; Fri, 09
 Oct 2020 10:40:28 -0700 (PDT)
X-Received: by 2002:ac2:5dec:: with SMTP id z12mr5141715lfq.15.1602265228182;
        Fri, 09 Oct 2020 10:40:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602265228; cv=none;
        d=google.com; s=arc-20160816;
        b=0K98k/Ft/AuWBvrLz1qKjyIanoeaKy9GeY7yBiLzc+UvWwHN+FWnsxY1lQINCQfkPf
         fKd86rDXTZZSJ6wV0Jjog0kZPwrz3OGOiNP8SwuViyBXG2F6aVdTRvK1J/sZn4z/8HHF
         GeZDzn1kNWRY39dUzaJiZMS7TtQbV0WbGxvXT7KW9X34Ivv58j4w4BF1Z5bQXHUXAA3F
         3krSBnGTU4/wvgrUw3c5jG1XbxIgvwlSkZXRYijQYfmd+JddvrwpH7avnxiBuODipxtE
         imjafwDnmSU3rdwi5d329LhdGiRjMsVdLhkk6I+p7lm6djUDYH8RgxRfwUxOOsQ17OyR
         MYmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=jlGJz5/Gwof+W4rud68ka3SNYNEZKejaW6R1zlgBIpo=;
        b=T8gW5uLTNXXJIPstG9VIR5/zvjw9FuFylBJsyDJhnjNYc6/pV86T+/oqrP8YS1ymVE
         mT2niBrDpFlUQZvXw3MkMD6sFG/1Lx1iM5z1NynnyM4PpImth/3rTsmJk7lPs1Xr7XW3
         Cd6qZpZcUa43Op6qWdBaW6f1C6r/tiOy26Ypza3JvEFehBsiqwGma9Ll+KYlPSygkayQ
         c7JQnNKtZ0da6vNXgbjY53DN453NSx/4u+9b9ixGovlQWTZwzJtXdAAeJDVLu3h0B9xm
         wKpEK/5SHiuAozKqZ3RJoSp/uNpodzwb/rcGsjdJYRwNcQp9a6cjWyoPezo998agw6hf
         cZ2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=teg3EY+1;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id y75si307355lfa.3.2020.10.09.10.40.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Oct 2020 10:40:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id d3so10624018wma.4
        for <kasan-dev@googlegroups.com>; Fri, 09 Oct 2020 10:40:28 -0700 (PDT)
X-Received: by 2002:a1c:c28a:: with SMTP id s132mr16271717wmf.13.1602265227336;
        Fri, 09 Oct 2020 10:40:27 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id n9sm12465852wrq.72.2020.10.09.10.40.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Oct 2020 10:40:26 -0700 (PDT)
Date: Fri, 9 Oct 2020 19:40:20 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jann Horn <jannh@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	"H . Peter Anvin" <hpa@zytor.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph Lameter <cl@linux.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Hillf Danton <hdanton@sina.com>, Ingo Molnar <mingo@redhat.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	SeongJae Park <sjpark@amazon.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>,
	"the arch/x86 maintainers" <x86@kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	kernel list <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux-MM <linux-mm@kvack.org>
Subject: Re: [PATCH v4 02/11] x86, kfence: enable KFENCE for x86
Message-ID: <20201009174020.GA2263081@elver.google.com>
References: <20200929133814.2834621-1-elver@google.com>
 <20200929133814.2834621-3-elver@google.com>
 <CAG48ez3OKj5Y8BURmqU9BAYWFJH8E8B5Dj9c0=UHutqf7r3hhg@mail.gmail.com>
 <CANpmjNP6mukCZ931_aW9dDqbkOyv=a2zbS7MuEMkE+unb7nYeg@mail.gmail.com>
 <CAG48ez0sYZof_PDdNrqPUnNOCz1wcauma+zWJbF+VdUuO6x31w@mail.gmail.com>
 <CANpmjNOZtkFcyL8FTRTZ6j2yqCOb2Hgsy8eF8n5zgd7mDYezkw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOZtkFcyL8FTRTZ6j2yqCOb2Hgsy8eF8n5zgd7mDYezkw@mail.gmail.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=teg3EY+1;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as
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

On Wed, Oct 07, 2020 at 04:41PM +0200, Marco Elver wrote:
> On Wed, 7 Oct 2020 at 16:15, Jann Horn <jannh@google.com> wrote:
[...]
> > > > > +               return false;
> > > > > +
> > > > > +       if (protect)
> > > > > +               set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
> > > > > +       else
> > > > > +               set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
> > > >
> > > > Hmm... do we have this helper (instead of using the existing helpers
> > > > for modifying memory permissions) to work around the allocation out of
> > > > the data section?
> > >
> > > I just played around with using the set_memory.c functions, to remind
> > > myself why this didn't work. I experimented with using
> > > set_memory_{np,p}() functions; set_memory_p() isn't implemented, but
> > > is easily added (which I did for below experiment). However, this
> > > didn't quite work:
> > [...]
> > > For one, smp_call_function_many_cond() doesn't want to be called with
> > > interrupts disabled, and we may very well get a KFENCE allocation or
> > > page fault with interrupts disabled / within interrupts.
> > >
> > > Therefore, to be safe, we should avoid IPIs.
> >
> > set_direct_map_invalid_noflush() does that, too, I think? And that's
> > already implemented for both arm64 and x86.
> 
> Sure, that works.
> 
> We still want the flush_tlb_one_kernel(), at least so the local CPU's
> TLB is flushed.

Nope, sorry, set_direct_map_invalid_noflush() does not work -- this
results in potential deadlock.

	================================
	WARNING: inconsistent lock state
	5.9.0-rc4+ #2 Not tainted
	--------------------------------
	inconsistent {SOFTIRQ-ON-W} -> {IN-SOFTIRQ-W} usage.
	ksoftirqd/1/16 [HC0[0]:SC1[1]:HE1:SE0] takes:
	ffffffff89fcf9b8 (cpa_lock){+.?.}-{2:2}, at: spin_lock include/linux/spinlock.h:354 [inline]
	ffffffff89fcf9b8 (cpa_lock){+.?.}-{2:2}, at: __change_page_attr_set_clr+0x1b0/0x2510 arch/x86/mm/pat/set_memory.c:1658
	{SOFTIRQ-ON-W} state was registered at:
	  lock_acquire+0x1f3/0xae0 kernel/locking/lockdep.c:5006
	  __raw_spin_lock include/linux/spinlock_api_smp.h:142 [inline]
	  _raw_spin_lock+0x2a/0x40 kernel/locking/spinlock.c:151
	  spin_lock include/linux/spinlock.h:354 [inline]
	  __change_page_attr_set_clr+0x1b0/0x2510 arch/x86/mm/pat/set_memory.c:1658
	  change_page_attr_set_clr+0x333/0x500 arch/x86/mm/pat/set_memory.c:1752
	  change_page_attr_set arch/x86/mm/pat/set_memory.c:1782 [inline]
	  set_memory_nx+0xb2/0x110 arch/x86/mm/pat/set_memory.c:1930
	  free_init_pages+0x73/0xc0 arch/x86/mm/init.c:876
	  alternative_instructions+0x155/0x1a4 arch/x86/kernel/alternative.c:738
	  check_bugs+0x1bd0/0x1c77 arch/x86/kernel/cpu/bugs.c:140
	  start_kernel+0x486/0x4b6 init/main.c:1042
	  secondary_startup_64+0xa4/0xb0 arch/x86/kernel/head_64.S:243
	irq event stamp: 14564
	hardirqs last  enabled at (14564): [<ffffffff8828cadf>] __raw_spin_unlock_irqrestore include/linux/spinlock_api_smp.h:160 [inline]
	hardirqs last  enabled at (14564): [<ffffffff8828cadf>] _raw_spin_unlock_irqrestore+0x6f/0x90 kernel/locking/spinlock.c:191
	hardirqs last disabled at (14563): [<ffffffff8828d239>] __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:108 [inline]
	hardirqs last disabled at (14563): [<ffffffff8828d239>] _raw_spin_lock_irqsave+0xa9/0xce kernel/locking/spinlock.c:159
	softirqs last  enabled at (14486): [<ffffffff8147fcff>] run_ksoftirqd kernel/softirq.c:652 [inline]
	softirqs last  enabled at (14486): [<ffffffff8147fcff>] run_ksoftirqd+0xcf/0x170 kernel/softirq.c:644
	softirqs last disabled at (14491): [<ffffffff8147fcff>] run_ksoftirqd kernel/softirq.c:652 [inline]
	softirqs last disabled at (14491): [<ffffffff8147fcff>] run_ksoftirqd+0xcf/0x170 kernel/softirq.c:644

	other info that might help us debug this:
	 Possible unsafe locking scenario:

	       CPU0
	       ----
	  lock(cpa_lock);
	  <Interrupt>
	    lock(cpa_lock);

	 *** DEADLOCK ***

	1 lock held by ksoftirqd/1/16:
	 #0: ffffffff8a067e20 (rcu_callback){....}-{0:0}, at: rcu_do_batch kernel/rcu/tree.c:2418 [inline]
	 #0: ffffffff8a067e20 (rcu_callback){....}-{0:0}, at: rcu_core+0x55d/0x1130 kernel/rcu/tree.c:2656

	stack backtrace:
	CPU: 1 PID: 16 Comm: ksoftirqd/1 Not tainted 5.9.0-rc4+ #2
	Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
	Call Trace:
	 __dump_stack lib/dump_stack.c:77 [inline]
	 dump_stack+0x198/0x1fd lib/dump_stack.c:118
	 print_usage_bug kernel/locking/lockdep.c:3350 [inline]
	 valid_state kernel/locking/lockdep.c:3361 [inline]
	 mark_lock_irq kernel/locking/lockdep.c:3575 [inline]
	 mark_lock.cold+0x12/0x17 kernel/locking/lockdep.c:4006
	 mark_usage kernel/locking/lockdep.c:3905 [inline]
	 __lock_acquire+0x1159/0x5780 kernel/locking/lockdep.c:4380
	 lock_acquire+0x1f3/0xae0 kernel/locking/lockdep.c:5006
	 __raw_spin_lock include/linux/spinlock_api_smp.h:142 [inline]
	 _raw_spin_lock+0x2a/0x40 kernel/locking/spinlock.c:151
	 spin_lock include/linux/spinlock.h:354 [inline]
	 __change_page_attr_set_clr+0x1b0/0x2510 arch/x86/mm/pat/set_memory.c:1658
	 __set_pages_np arch/x86/mm/pat/set_memory.c:2184 [inline]
	 set_direct_map_invalid_noflush+0xd2/0x110 arch/x86/mm/pat/set_memory.c:2189
	 kfence_protect_page arch/x86/include/asm/kfence.h:62 [inline]
	 kfence_protect+0x10e/0x120 mm/kfence/core.c:124
	 kfence_guarded_free+0x380/0x880 mm/kfence/core.c:375
	 rcu_do_batch kernel/rcu/tree.c:2428 [inline]
	 rcu_core+0x5ca/0x1130 kernel/rcu/tree.c:2656
	 __do_softirq+0x1f8/0xb23 kernel/softirq.c:298
	 run_ksoftirqd kernel/softirq.c:652 [inline]
	 run_ksoftirqd+0xcf/0x170 kernel/softirq.c:644
	 smpboot_thread_fn+0x655/0x9e0 kernel/smpboot.c:165
	 kthread+0x3b5/0x4a0 kernel/kthread.c:292
	 ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:294


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201009174020.GA2263081%40elver.google.com.
