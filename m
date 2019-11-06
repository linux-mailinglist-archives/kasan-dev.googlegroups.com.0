Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7VVRTXAKGQEBTT52PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 20E45F1E4D
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Nov 2019 20:11:59 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id h3sf4493623lfp.17
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Nov 2019 11:11:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573067518; cv=pass;
        d=google.com; s=arc-20160816;
        b=MZl6sE39SAT0Noj1GwG+UNV03gMk6JL1J0GcctRCq6mo11DJLG8FJx1/2wci9p71KY
         NvJ0dGdzEXA+6TCdfN+OviE9/n7gxkepyu9B/S7aAi/QesZ/6dd325T2uoGtgqaz9iho
         gydyW/UCH+4LthUeem96N89RsR1DJxMn44mKaeNs85ThqkvFfLwISZKydw7JR1ak8hrW
         Pl1hFgVzKxzXl/1xiZr9kErzzW+4mDik8Jb/kPbmaaNk+D8dBHzFVjngVqtpN2E7NANo
         bTQ3/e4CzQ3GCxZn2pAtNPuc1qnmnHSb83+7sAVsqaaxqxWX9vastj8JgoTqBXMh86ue
         4DWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Vc3tcDSLqvNixdYBn7pozXB0CDYp7L5P0rDe34fGtMI=;
        b=su3v1b1pZwTKwA8HWUIxXRVZDjeW+Ew6g+4FvrjFEHvMynh8Rt+1WztehIQ/UTeBNs
         WO/0swWSwXjbFoD1DdwJl0uSFFybBXpUJJY8aUhYPLCfXO7sceQtoxc/iX78h7pc9d8c
         0HD0U4RK9m4tzTqyJWKA6MR9+vT7Zk2Lm/ZUg7XizoQ5Csi5whBkWYuqxh0e+GYzJnpj
         L8iOA7oOQCnyFcju9r2iHUIqeKwulUNy+rvYNplnz8QDsd1gh9w6s4BW3AyaLXZIoilP
         cv5xHRji7KcpT9nx8dJDgjzKTg2xdTt18WBsCbCv/Z8bpcUwphLp1eYifAQGGGl7kUJ+
         TgQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rgRyO6x1;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Vc3tcDSLqvNixdYBn7pozXB0CDYp7L5P0rDe34fGtMI=;
        b=Xz6sU7N/Y/9Xr4S+wXSsjyEc/g/DbY24h3OMmCvdQb4OVN6IhNmr7AibtPmtdO8Tu9
         /XKAdd3BUih3nbMd7EduTxJlnPYITo0uhda2vrzOp5oZopdU+BM3j1QdeyitgLH/vRcl
         9ZpMoEBoXsggH+N48aP8U2qyuqQrfZl6/XKL5zXLlUKVO4Gs5SCYJWL3xxgBNJsZo7kh
         QAQorGZzo3XkcaX/YWEvjuHXCqh8t6urC/ymYPW3gejqBzAWXc/XvNMualHihakn046l
         bXAai1ZpZV+N+Qn8b29lmVPKdLJulFdiAyJtxKqcfH3seD38gyiMUSRUJBnRSsQHfxhU
         WsbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Vc3tcDSLqvNixdYBn7pozXB0CDYp7L5P0rDe34fGtMI=;
        b=CCefn1sIoH7/3ut4pPy3OFvkiFzWiFjsWIg29eiUWgpGXn8fIZEqIzruDH+KXfEqmR
         Pc5LYZ6J1oUc1bZwr4YCVgJLBPmKbTgXwiBFsaoVFwKwK8ZFsI5+q1WTNKFCVfoy5Jk1
         M1zes5kdSp8Qk9N+5mmuerGUfizeX9KPc3H6SkJdsskjaG+tYKSyRvB2JbKkHcgsNPx+
         pDexCKc1+JBBOm1C3cNN+5UevLiMwCL5fdt6nCtzOLVn+PGPRg8UNiNa1MJAXvVpSweV
         /kuSKBr8OGWxI9OTVhlObeeG1jLx1Xkj0ShTFb3yFOR+8bVo7jaAmTUrEsl6n8Zo+MVj
         YVfA==
X-Gm-Message-State: APjAAAVqwjrjMWPpo2ngG8Ox2aYdukddq7ZRv+pHLUpCkd2yhcTFZQcH
	TQFfukMeMDbDdant03zgEmw=
X-Google-Smtp-Source: APXvYqy3TaB/9oc0yahwJcKmiekTnZHMpiwvAFDslmz0CpYRle9POh0/rLy50vk90BntBNsnQCU50A==
X-Received: by 2002:a2e:9e97:: with SMTP id f23mr3153721ljk.89.1573067518599;
        Wed, 06 Nov 2019 11:11:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:1d6:: with SMTP id 205ls791638lfb.4.gmail; Wed, 06 Nov
 2019 11:11:57 -0800 (PST)
X-Received: by 2002:ac2:5295:: with SMTP id q21mr25077603lfm.93.1573067517911;
        Wed, 06 Nov 2019 11:11:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573067517; cv=none;
        d=google.com; s=arc-20160816;
        b=hNwKABNMWqyT+7qeKk+ZNij7j1s/YFTIGTjNhB4DPOeXVvfZ2m7ojJTFhazR6KVTE3
         rCOt8OzA4FViWuTP/kAnxx8eOC9XaypIn6Ao0ZI/Yl+zoKl+Gq36Ac5IOHhWimhr0yb9
         tGCU0Mgp5/T546b82+DBaYgLLeMwPPCF3KuBOF17oMKoRinaY3oYKh44Q3iYptIPry/Q
         7uKfWGNiUUowMLJ2BzTm4C5lM3hFRkSOVnTBJu4O91oLCR9JeDgmmKXz9SIRzai9wXZX
         lA3iW+/b+jJoOneKBYx6ZLwmg+Nj/Dah0fjAL/rUxoLANhfS6+vvFixh6aTR5hUh7lsG
         j25w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=EcgRR3fhItj7MngTpAkKZQgz86ETXxndudb9oWnZwxg=;
        b=zQtAC/jio3zIbnMaQK7rletq1U+dJQQwDQbV9evFlyWi9NuhzHlQ4wHHGgayfVTfSV
         OQJHMDdtIxHF6LGWMoy8J7Pf1UC80/0VGdzcj7CJ4iYYqanxgQllrH7bE2ofk9DQI+Kc
         /DUip67N2SIxTKdSJUGH3qWbBkM2ueQCvo6sinvSLFlUXOkyZgC/0yybK83/iwYf1Ih4
         YQ4gji6u7rP8QaEsoQYPhyVQ4nuYvTheEdx/0wI2UjZ8zihsTjBvClfQNldtljm07Ykt
         mk2pcvgieCDJRnsnps2d6jTxIGLCq3uwtNpikKrGdmNwmneSyVOPDf15UrGuC80k2BV9
         oLbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rgRyO6x1;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id j14si1452443lfm.2.2019.11.06.11.11.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Nov 2019 11:11:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id w30so4663143wra.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Nov 2019 11:11:57 -0800 (PST)
X-Received: by 2002:adf:f743:: with SMTP id z3mr4041566wrp.200.1573067516685;
        Wed, 06 Nov 2019 11:11:56 -0800 (PST)
Received: from google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id p14sm16143410wrq.72.2019.11.06.11.11.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Nov 2019 11:11:55 -0800 (PST)
Date: Wed, 6 Nov 2019 20:11:49 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	Alexander Potapenko <glider@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Arnd Bergmann <arnd@arndb.de>, Boqun Feng <boqun.feng@gmail.com>,
	Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>,
	Daniel Lustig <dlustig@nvidia.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Howells <dhowells@redhat.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	Jade Alglave <j.alglave@ucl.ac.uk>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Luc Maranget <luc.maranget@inria.fr>,
	Mark Rutland <mark.rutland@arm.com>,
	Nicholas Piggin <npiggin@gmail.com>, paulmck@kernel.org,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	linux-efi@vger.kernel.org,
	"open list:KERNEL BUILD + fi..." <linux-kbuild@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>,
	the arch/x86 maintainers <x86@kernel.org>
Subject: Re: [PATCH v3 1/9] kcsan: Add Kernel Concurrency Sanitizer
 infrastructure
Message-ID: <20191106191149.GA126960@google.com>
References: <20191104142745.14722-1-elver@google.com>
 <20191104142745.14722-2-elver@google.com>
 <CACT4Y+a+ftjHnRx9PD48hEVm98muooHwO0Y7i3cHetTJobRDxg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+a+ftjHnRx9PD48hEVm98muooHwO0Y7i3cHetTJobRDxg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rgRyO6x1;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
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



On Wed, 06 Nov 2019, Dmitry Vyukov wrote:

> On Mon, Nov 4, 2019 at 3:28 PM Marco Elver <elver@google.com> wrote:
> >
> > Kernel Concurrency Sanitizer (KCSAN) is a dynamic data-race detector for
> > kernel space. KCSAN is a sampling watchpoint-based data-race detector.
> > See the included Documentation/dev-tools/kcsan.rst for more details.
> ...
> > +static inline atomic_long_t *find_watchpoint(unsigned long addr, size_t size,
> > +                                            bool expect_write,
> > +                                            long *encoded_watchpoint)
> > +{
> > +       const int slot = watchpoint_slot(addr);
> > +       const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
> > +       atomic_long_t *watchpoint;
> > +       unsigned long wp_addr_masked;
> > +       size_t wp_size;
> > +       bool is_write;
> > +       int i;
> > +
> > +       BUILD_BUG_ON(CONFIG_KCSAN_NUM_WATCHPOINTS < CHECK_NUM_SLOTS);
> > +
> > +       for (i = 0; i < CHECK_NUM_SLOTS; ++i) {
> > +               watchpoint = &watchpoints[SLOT_IDX(slot, i)];
> 
> 
> The fast path code become much nicer!
> I did another pass looking at how we can optimize the fast path.
> Currently we still have 2 push/pop pairs on the fast path because of
> register pressure. The logic in SLOT_IDX seems to be the main culprit.
> We discussed several options offline:
> 1. Just check 1 slot and ignore all corner cases (we will miss racing
> unaligned access to different addresses but overlapping and crossing
> pages, which sounds pretty esoteric)
> 2. Check 3 slots in order and without wraparound (watchpoints[slot +
> i], where i=-1,0,1), this will require adding dummy slots around the
> array
> 3. An interesting option is to check just 2 slots (that's enough!), to
> make this work we will need to slightly offset bucket number when
> setting a watch point (namely, if an access goes to the very end of a
> page, we set the watchpoint into the bucket corresponding to the
> _next_ page)
> All of these options remove push/pop in my experiments. Obviously
> checking fewer slots will reduce dynamic overhead even more.
> 
> 
> > +               *encoded_watchpoint = atomic_long_read(watchpoint);
> > +               if (!decode_watchpoint(*encoded_watchpoint, &wp_addr_masked,
> > +                                      &wp_size, &is_write))
> > +                       continue;
> > +
> > +               if (expect_write && !is_write)
> > +                       continue;
> > +
> > +               /* Check if the watchpoint matches the access. */
> > +               if (matching_access(wp_addr_masked, wp_size, addr_masked, size))
> > +                       return watchpoint;
> > +       }
> > +
> > +       return NULL;
> > +}
> > +
> > +static inline atomic_long_t *insert_watchpoint(unsigned long addr, size_t size,
> > +                                              bool is_write)
> > +{
> > +       const int slot = watchpoint_slot(addr);
> > +       const long encoded_watchpoint = encode_watchpoint(addr, size, is_write);
> > +       atomic_long_t *watchpoint;
> > +       int i;
> > +
> > +       for (i = 0; i < CHECK_NUM_SLOTS; ++i) {
> > +               long expect_val = INVALID_WATCHPOINT;
> > +
> > +               /* Try to acquire this slot. */
> > +               watchpoint = &watchpoints[SLOT_IDX(slot, i)];
> 
> If we do this SLOT_IDX trickery to catch unaligned accesses crossing
> pages, then I think we should not use it insert_watchpoint at all and
> only set the watchpoint to the exact index. Otherwise, we will
> actually miss the corner cases which defeats the whole purpose of
> SLOT_IDX and 3 iterations.
> 

Just for the record, there are 2 reasons actually I decided to do this:

1. the address slot is already occupied, check if any adjacent slots are
   free;
2. accesses that straddle a slot boundary due to size that exceeds a
   slot's range may check adjacent slots if any watchpoint matches.

In /sys/kernel/debug/kcsan I can see no_capacity with the current version stays
below 10 for kernel boot. When I just use 1 slot, no_capacity events exceed
90000, because point (1) is no longer addressed. This is a problem that would
impair our ability to detect races.  One reason this happens is due to
locality: it is just much more likely that we have multiple accesses to the
same pages during some phase of execution from multiple threads.

To avoid blowing up no_capacity events, insert_watchpoint should not change. I
will change the iteration order in the fast-path (avoiding the complicated
logic), and add additional overflow entries to the watchpoint array.

AFAIK this generates better code, while still addressing points (1) and
(2) above. This should be the best trade-off between absolute
performance and our ability to detect data races.

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191106191149.GA126960%40google.com.
