Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBPA576AKGQEJJ355ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id D89802A0345
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 11:50:46 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id e82sf2491150oia.15
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 03:50:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604055045; cv=pass;
        d=google.com; s=arc-20160816;
        b=fBBnlMInBtFk4/ZFwE/WinBnC7OdW4eCt1bH0NYvyjd+pnWvc7ZP0JzWMLv0sgQ4av
         lRW8XpJfDshIt/Ec9CWudsE8673ChKxJN8leXx5tdM38qZxVHjk8PNqB2Y3XTLT25YKc
         k97QwwedOs3Tz+c3reUnGtzq+9O8otJ+QorrIV3RpOhaBPxYx1tlIT8xNUA9u+nUu/yE
         9DRdPnhMzhdlNXGNI8PObNFFTXU4OiLPVdH09EBxs++WNVVeTznY55f7D3ZOrKTg/H+1
         XSRM2tT3mZAtf9B+PhQm1wI9Fcpgt9HOTcc9kpI3T6tw4Vns+WerGkNFcaMypQl2Nlbe
         u2sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oId60VBY2hSzbjNZEa27PwzTDUQLkH3gBooroN+1yDg=;
        b=jVJ03INeCFzAJKTp/8KyS9yEFpanBmb3dRUBHhQkmV6sjQgInGTEwcScA0EGc0LG51
         6HOrxc/NnQQRmBQssSkD9DZEq4Ef5t7OF/QMJdTyJmy/MTM8SQfxdnQJfmkTQavWJNsD
         ve9csbux0V809GLEzzD1KZ7T4BMAHJnMfkib+DxkdVFxvqmkWz7G1Omx1uefqlAc+mWo
         8lrVPAjSMB0SwdI3tMdWbXTkpmk6jFGWxYJqMZqeJ3h+SG16UXo3hajKQM8uZzSPkJI6
         GmB3wvMumTC6hEvoh8Ih8VKSxTZjupwPK3IHtvlHHXNPBJ8hCFSdQ1tQAXzOfEMjHUVs
         qZRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mCyFqjN1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oId60VBY2hSzbjNZEa27PwzTDUQLkH3gBooroN+1yDg=;
        b=mr3r5guyAwSc49tdvE1R7YnL4KMWoQOl5xQdYy/IaRffKaZbvHNScuIZVG+khnbnkv
         lZLIOuq8FotErR4Zs8Ktt9GmGUqve6GldQZO3uG3/84Suhh+j8z2JWhLhn4MteI6H2Hj
         +xe8DgvxSYAbp6sNpnS6GEkLurnx/IDjxaHT6WA7sAapuxaq4VIfWY++Uph9npqMskcr
         9cKq7XHRyS83jzNn7yh6sSZCu+rO2nJOU3uBUu/DrnQSBpJgM1hNiQ/VG5CcAf7AsUuE
         sJLrY9D7o2UDaM+JjqF1ebokj1M8KcSV/8UcykDObhmxR7/TsL8yBWA+fzCyaTWQh40R
         HWew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oId60VBY2hSzbjNZEa27PwzTDUQLkH3gBooroN+1yDg=;
        b=CWza9zqfpAYcjJQItvCwdMLw05V3EA7l7PEsr9Eh8xL/12a1i6/BYsJ1jKe9OJ3SFq
         0A3V7aaoqRGyUW2RWdv+gi45qe6ynDbbcwzqLXKm5cB0t/xLB/A+uhBb7OfZnj3UBxCY
         0Y2qh+9qrd5cHnqgyTddU20KBw4Q2Z7/5cuZUqtFnmtdQR00/BjOvwIQ/f5bD0dc9aqq
         RFVK1kZXMpi/nWX7/3Qot9cxMevI5P4HdIRX9ai04ub+uiG5d74R8Nub+St80FIlnH80
         Bq6SIg9JJRgvn8JDYEek9RPvfUCDMd115Ia2dCsVFbUpLob1MGxs4bH3SkU42OOWfzwa
         2Hjw==
X-Gm-Message-State: AOAM533dYWi3RFUNiaagaKOFFL0sRovbt2GlupG/lOaKjxZg2RZte8n6
	Re2qRQxNip3yj43g2PzFa1w=
X-Google-Smtp-Source: ABdhPJyUond6/5DiHrv+qr5NK/XeaLSR11lS7xbw57Hl+icYXT4T4UXbydkbdIB7Eu+CFRNcTgp1Hg==
X-Received: by 2002:a4a:dc0d:: with SMTP id p13mr1301168oov.2.1604055045868;
        Fri, 30 Oct 2020 03:50:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6949:: with SMTP id p9ls1498948oto.6.gmail; Fri, 30 Oct
 2020 03:50:45 -0700 (PDT)
X-Received: by 2002:a05:6830:400c:: with SMTP id h12mr1244266ots.102.1604055045501;
        Fri, 30 Oct 2020 03:50:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604055045; cv=none;
        d=google.com; s=arc-20160816;
        b=IIx3V+XbzA2d/2eHKXUdafWqnuQIE/Im4FQFWjNAYm/WPuopoeVJK6Llk1/lfjFzEU
         BTz1xLAXfqqKnriW0JxNdavQB6eAzTGyhmrGMs5OcJ8EjaXEhpGbVckksQ0aTovSbQnt
         71MnkPwL4zD6O6S9cgmoduoOujprrVSX68YvtWCIiBOFXjspRBnoLQz2fY+C6cbTbtZQ
         at5Nht/BotYdGw6OZiWjpOtfLDdtiD2DGO15wocVeqIQjPT4gnK2MKZ/NQvTqlhww6OK
         eCZ4mo9BgH60RCXxo31NbzHwTtKl47EHdRAhY9hD79tSu3W3R+XD5wEAqywN1MjYeQHU
         Djwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hvuWYo7Yuy4+Xoosva2YfT/B6vDa7o+k5TcZrFjzw2I=;
        b=ROeiRKH7fb7qlzk5V+QKdLUgJobMbCGNkY7AL+OSdalEXNhit2v3oX24DylfHkZF7q
         Dpfja6HPp/NJ6qMb0pNMxX6ku95gTNU2PyUqQ75oKvmz53dSX4ixHDSLPYzO/hYyUtu8
         32pDF7OsUPlhjIoCSc0wU0l8riDh8tcomGbcIn9A7WQOwnVaOd/3o0lVxSdryD1CNORJ
         DvinIC5Oat98eSoG1K/tRCDEelWMvPtVsVOCoWT+ZEqYACJ7cy2aj6vMuFDHf5CUZNQH
         agzCnXAIo/LszSdChqhKNw8LI7xC4+lGX9oZES7i7r0+TLXVbLNZ1NlSZcsWdc0txsBC
         bZTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mCyFqjN1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id d20si534548oti.1.2020.10.30.03.50.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 03:50:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id x1so6174613oic.13
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 03:50:45 -0700 (PDT)
X-Received: by 2002:aca:4f55:: with SMTP id d82mr1138528oib.172.1604055045058;
 Fri, 30 Oct 2020 03:50:45 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-9-elver@google.com>
 <CAG48ez071wf5kvBwpmRk9QiSDzDDN7zh17zEcZjPDWKUjbqosA@mail.gmail.com>
In-Reply-To: <CAG48ez071wf5kvBwpmRk9QiSDzDDN7zh17zEcZjPDWKUjbqosA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 11:50:32 +0100
Message-ID: <CANpmjNPDksUk1BLS9BuYrx4E3Lf+m2jWXn0yn7zO43c9PboAmw@mail.gmail.com>
Subject: Re: [PATCH v6 8/9] kfence: add test suite
To: Jann Horn <jannh@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	=?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mCyFqjN1;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Fri, 30 Oct 2020 at 03:50, Jann Horn <jannh@google.com> wrote:
>
> On Thu, Oct 29, 2020 at 2:17 PM Marco Elver <elver@google.com> wrote:
> > Add KFENCE test suite, testing various error detection scenarios. Makes
> > use of KUnit for test organization. Since KFENCE's interface to obtain
> > error reports is via the console, the test verifies that KFENCE outputs
> > expected reports to the console.
> [...]
> > diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> [...]
> > +static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocation_policy policy)
> > +{
> > +       void *alloc;
> > +       unsigned long timeout, resched_after;
> [...]
> > +       /*
> > +        * 100x the sample interval should be more than enough to ensure we get
> > +        * a KFENCE allocation eventually.
> > +        */
> > +       timeout = jiffies + msecs_to_jiffies(100 * CONFIG_KFENCE_SAMPLE_INTERVAL);
> > +       /*
> > +        * Especially for non-preemption kernels, ensure the allocation-gate
> > +        * timer has time to catch up.
> > +        */
> > +       resched_after = jiffies + msecs_to_jiffies(CONFIG_KFENCE_SAMPLE_INTERVAL);
> > +       do {
> [...]
> > +               if (time_after(jiffies, resched_after))
> > +                       cond_resched();
>
> You probably meant to recalculate resched_after after the call to
> cond_resched()?

This is intentional. After @resched_after is reached, every failed
allocation attempt will result in a cond_resched(), because we know
the sample interval has elapsed and KFENCE should have kicked in. So
we just want to ensure the delayed work gets to run as soon as
possible, and just keep yielding.

Added a clarifying comment.

> > +       } while (time_before(jiffies, timeout));
> > +
> > +       KUNIT_ASSERT_TRUE_MSG(test, false, "failed to allocate from KFENCE");
> > +       return NULL; /* Unreachable. */
> > +}
> [...]
> > +/*
> > + * KFENCE is unable to detect an OOB if the allocation's alignment requirements
> > + * leave a gap between the object and the guard page. Specifically, an
> > + * allocation of e.g. 73 bytes is aligned on 8 and 128 bytes for SLUB or SLAB
> > + * respectively. Therefore it is impossible for the allocated object to adhere
> > + * to either of the page boundaries.
>
> Should this be "to the left page boundary" instead of "to either of
> the page boundaries"?

Thanks for spotting. I think it's "Therefore it is impossible for the
allocated object to contiguously line up with the right guard page."

> > + * However, we test that an access to memory beyond the gap result in KFENCE
>
> *results
>
>
>
> > + * detecting an OOB access.
> > + */
> > +static void test_kmalloc_aligned_oob_read(struct kunit *test)

Thanks, will address these for v7.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPDksUk1BLS9BuYrx4E3Lf%2Bm2jWXn0yn7zO43c9PboAmw%40mail.gmail.com.
