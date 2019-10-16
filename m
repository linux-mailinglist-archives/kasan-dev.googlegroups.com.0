Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOXBTXWQKGQEO2QBNSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc37.google.com (mail-yw1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id DFC0ED9A25
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 21:34:19 +0200 (CEST)
Received: by mail-yw1-xc37.google.com with SMTP id i199sf19684324ywe.4
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 12:34:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571254458; cv=pass;
        d=google.com; s=arc-20160816;
        b=EzHrbzxjdVpf/KeFJpoRryNSgKwaE6n8ZKQH5nnZdMvY9SNQ/pAbRuJ/p1Huw+AIZQ
         PMwI7NqoLjwnXcqvV2KCKJGTPxLmHGuYQE02NV6yfNvOYG2ejawIU9UiyBDEukc9/9ED
         dWZrLC6GcI9Bbmj3d/mn3uV3c0C368UTU3wlcZGwaDqEt/gJNNmF31Yr3s8qNiFaFJzc
         Vv3xpoIO0bBdlbxU4ZlPk/gU7DeR3ZJGj0zNxTqUKKZN/WLKYIlNhQaWuOz3k7dNsPnm
         zmBTz3oVatUj5L9CZ8XYuiOpIWzGzzjbqkHz7RMssxn7I18Xh5XN5M6aUIZbFhQYyNvf
         goGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cGDv63mde4pP5NPyDgWwtTtLG3Z2n6GWJHioNpnuZgQ=;
        b=XVKsaTsTlTsFa8fyCSDZBMskdo8hjTD1iLy7oIV7OK559GmLVb36M/rKbwJBJgVrNh
         tesmbiTUd4EF1Dsgtn61/HItZDNUU2wu1f95v+n4Qw1/ajGEF7fdH7eNhJzEvzkB3S+Z
         YDtnfb7XSp3rFUUqUcE3cVHMXcVQWRqRupjLJAd9FiKaVJ374sEgyYqk3x5+wXkupP2F
         wY3v28CwEAbQUF5H7z47N3RnVsIozU51s3QlKUZjvyAD4Fe/NyNSYM2iqSAlbpkkeM5D
         ErrkOBJ3cZzE6UfI5ZtTXlhAJNjOJMM/Id+3kRmSgFv6cz1MAVcSlCWYTD0xWm7DE5fD
         UANw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=U7NFsQMF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cGDv63mde4pP5NPyDgWwtTtLG3Z2n6GWJHioNpnuZgQ=;
        b=BP6c92FA7Jhrw59cECen8e3mIEp7d38OMAXHYZeMhtCThgx/fmxFNqRe6Dl7I8VYhu
         oD1UOPTAmi1c/ZuU8qe/Rmh5wrzBszjUDksh0uHwnlmej8lMt6UaWg1I9wmZr1d3aNcN
         bkz3vSEJ0uZ+7c0iz1OTkwdnmcw5FC3ZGL885RwUPkgFe6tX69e+UdwrTwCCzQgl6WYO
         CMy6SnVo+xZqFxRjId653MJu9S0QkQlEUl456C5cMIDkRD+FQ5hYYRewTGU9sL81xFZ0
         t6ncUCT1HVeKFsFojABdzBhqwMPAa3VCTa2M0Qj2Hmwmip4TuPkAn3XXtJkamJXMiMFP
         zH7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cGDv63mde4pP5NPyDgWwtTtLG3Z2n6GWJHioNpnuZgQ=;
        b=uZh7G8KnODMEnTT9GmTzMs632gJHZ0VI2uOa4aqvQms8+wb1vLnrAVqhk6ajJExiaS
         Zs6+T7ZLDCkCE6RimSrxuDNMAnasCi70tVc4Qokbq+BYE2LbLfI2MgTDoz+ToeeAPpMY
         hCpVIYveeNGhN6GP+4jUExBNfbRg2qfGAFdD1vzXFd64LWsw+wUApOFvA6biTPzURPei
         wRlssBbIWJRXVNbcEJUHPG1t7z9PAMCghis72n4li3Ubh6osr/jvsaLXjZc3xTeCj9Lx
         mjQSz7yuxyMTPr+mDUYut7hf7m2aywyFNfAoU60RZp7tdlunOoQIRkpmGKTpnnGsLr3a
         Nuug==
X-Gm-Message-State: APjAAAVFCCvQBwqbIOCO+r9o41gOYkJuXN7lU5PGygBEtt4l0P16+Xso
	ounCzey9PwTntn02DhcTVYw=
X-Google-Smtp-Source: APXvYqxnCDQBrZMtvorKFfdqTimoel9XlgFsx8WiYeltuq21BoN5aiHYqOQxvxyfeJ2JrMMnBLxK3w==
X-Received: by 2002:a25:6343:: with SMTP id x64mr233592ybb.114.1571254458526;
        Wed, 16 Oct 2019 12:34:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:c442:: with SMTP id s2ls3804286ywj.9.gmail; Wed, 16 Oct
 2019 12:34:18 -0700 (PDT)
X-Received: by 2002:a81:ac0d:: with SMTP id k13mr17464ywh.448.1571254458106;
        Wed, 16 Oct 2019 12:34:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571254458; cv=none;
        d=google.com; s=arc-20160816;
        b=BChg0k5v7qFTfcaHyXiE7iogoGy1Jje7O/dB75G2wN+sWhyv0pXT/3rf3gjZgmGHcN
         sbVG+uZkIHLoOtUlUbUR/cdniRi1lw7PNSk0mKAEDzTw1YYhi5I6YdeIHdEZ5Z/z5hcF
         zAV9DWxvp1osTF9xS9CF7nbEsUQGbcTv28ZFfcxqUA/Df9+l+39zlV/sPo7JpLoqtC6y
         dny0rW6oX5Dq8EwZfVBc6yaxW61+JpZx+qs8MHmyjrBv9M8zWZxgmmm3BUDncXazOetf
         BljFLicZGsFr/W6EaMUwe5b4MSRoZFzt9J79UN/gkumWxRpLja3T8Ah3jSEUNeyNAKgm
         UUxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RXr4UV4kEHsq0yeWfqjzxiqcNiJQEejUfsbyhCIH4rQ=;
        b=qZrzHtD3hekyohWSHGmJlCmEv8tVMytKmtrqNYehDcgmDVXY+A/J5c1Csd8YzJ01lh
         CvDn1k5V0tZiDowNN4hAYR628n/0gOoRIcTe44VJuG947cvUIpp4Rv9QlGkr7iEQjk1l
         CEJc7GiGDwOu8x8iRc4t3X+GEWT9Llo5+hWFGdcgLNVqxfy3HOslwDFTf2nj4wNERRWc
         vbOx8j8Of4USABrAAFlq8IlQwJXZrnKZsjfgGYuvkadA8p4mdlNSo3qN5dH2YlTgii01
         H0+CPyYqi6mmPF460Vh7hgsHBm1eyrIschKGLcvRPlqHDHxcrFGZORFA5o7DsFhuOOO/
         hKZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=U7NFsQMF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id a1si1817193ywh.3.2019.10.16.12.34.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 12:34:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id 41so21204235oti.12
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 12:34:18 -0700 (PDT)
X-Received: by 2002:a9d:6d89:: with SMTP id x9mr31120620otp.17.1571254457140;
 Wed, 16 Oct 2019 12:34:17 -0700 (PDT)
MIME-Version: 1.0
References: <20191016083959.186860-1-elver@google.com> <20191016083959.186860-2-elver@google.com>
 <20191016184346.GT2328@hirez.programming.kicks-ass.net>
In-Reply-To: <20191016184346.GT2328@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Oct 2019 21:34:05 +0200
Message-ID: <CANpmjNP4b9Eo3ZKE6maBs4ANS7K7sLiVB2CbebQnCH09TB+hZQ@mail.gmail.com>
Subject: Re: [PATCH 1/8] kcsan: Add Kernel Concurrency Sanitizer infrastructure
To: Peter Zijlstra <peterz@infradead.org>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, dave.hansen@linux.intel.com, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Mark Rutland <mark.rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	"Paul E. McKenney" <paulmck@linux.ibm.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=U7NFsQMF;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Wed, 16 Oct 2019 at 20:44, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, Oct 16, 2019 at 10:39:52AM +0200, Marco Elver wrote:
>
> > +bool __kcsan_check_watchpoint(const volatile void *ptr, size_t size,
> > +                           bool is_write)
> > +{
> > +     atomic_long_t *watchpoint;
> > +     long encoded_watchpoint;
> > +     unsigned long flags;
> > +     enum kcsan_report_type report_type;
> > +
> > +     if (unlikely(!is_enabled()))
> > +             return false;
> > +
> > +     watchpoint = find_watchpoint((unsigned long)ptr, size, !is_write,
> > +                                  &encoded_watchpoint);
> > +     if (watchpoint == NULL)
> > +             return true;
> > +
> > +     flags = user_access_save();
>
> Could use a comment on why find_watchpoint() is save to call without
> user_access_save() on.

Thanks, will add a comment for v2.

> > +     if (!try_consume_watchpoint(watchpoint, encoded_watchpoint)) {
> > +             /*
> > +              * The other thread may not print any diagnostics, as it has
> > +              * already removed the watchpoint, or another thread consumed
> > +              * the watchpoint before this thread.
> > +              */
> > +             kcsan_counter_inc(kcsan_counter_report_races);
> > +             report_type = kcsan_report_race_check_race;
> > +     } else {
> > +             report_type = kcsan_report_race_check;
> > +     }
> > +
> > +     /* Encountered a data-race. */
> > +     kcsan_counter_inc(kcsan_counter_data_races);
> > +     kcsan_report(ptr, size, is_write, raw_smp_processor_id(), report_type);
> > +
> > +     user_access_restore(flags);
> > +     return false;
> > +}
> > +EXPORT_SYMBOL(__kcsan_check_watchpoint);
> > +
> > +void __kcsan_setup_watchpoint(const volatile void *ptr, size_t size,
> > +                           bool is_write)
> > +{
> > +     atomic_long_t *watchpoint;
> > +     union {
> > +             u8 _1;
> > +             u16 _2;
> > +             u32 _4;
> > +             u64 _8;
> > +     } expect_value;
> > +     bool is_expected = true;
> > +     unsigned long ua_flags = user_access_save();
> > +     unsigned long irq_flags;
> > +
> > +     if (!should_watch(ptr))
> > +             goto out;
> > +
> > +     if (!check_encodable((unsigned long)ptr, size)) {
> > +             kcsan_counter_inc(kcsan_counter_unencodable_accesses);
> > +             goto out;
> > +     }
> > +
> > +     /*
> > +      * Disable interrupts & preemptions, to ignore races due to accesses in
> > +      * threads running on the same CPU.
> > +      */
> > +     local_irq_save(irq_flags);
> > +     preempt_disable();
>
> Is there a point to that preempt_disable() here?

We want to avoid being preempted while the watchpoint is set up;
otherwise, we would report data-races for CPU-local data, which is
incorrect. An alternative would be adding the source CPU to the
watchpoint, and checking that the CPU != this_cpu. There are several
problems with that alternative:
1. We do not want to steal more bits from the watchpoint encoding for
things other than read/write, size, and address, as not only does it
affect accuracy, it would also increase performance overhead in the
fast-path.
2. As a consequence, if we get a preemption and run a task on the same
CPU, and there *is* a genuine data-race, we would *not* report it; and
since this is the common case (and not accesses to CPU-local data), it
makes more sense (from a data-race detection PoV) to simply disable
preemptions and ensure that all tasks are run on other CPUs as well as
avoid the problem of point (1).

I can add a comment to that effect here for v2.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP4b9Eo3ZKE6maBs4ANS7K7sLiVB2CbebQnCH09TB%2BhZQ%40mail.gmail.com.
