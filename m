Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5PEY3WQKGQEY7UQJSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 71294E355A
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2019 16:17:27 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id a6sf6654293otr.0
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2019 07:17:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571926646; cv=pass;
        d=google.com; s=arc-20160816;
        b=LXfewBHOz9/EC30Aq1nsDMPWGumg6POpwcrviopw1/N+VU1JwOkSpysiUtFROFejoB
         +GZvKlYFCsCTm6z/6iGv3Xbw8JClLQJKSW6uW8lF2/PcL6V9DcT6DAgzIj6PsL9I15UK
         0Jfy6bL0Ar68qQmHsfIyy+oIv24lLNFTDRI3szpRx0GjdYB9w8HmxKR1tBRL+Ms7RkJT
         NL0fLAx/QBeOWKopJ7tRXhR+Z3gwDhQam9mFltBqu2NLhwWvkFoCThrxYzqx3vJICX3I
         BGygY+J5Q3RFVvVDUR2OcqmG3q87kfnP6+peDPmvhOyQ+uudF8mdMXP9UaynN7RYDi4X
         yF1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SUaDcNKIiq3IJ/D/N/Ub2wrofqd5Uua32u5h9/iTC/U=;
        b=wJpd8FVuNh+kwIjh4KuURQ33telXIXjN0e7DMh3FBALRUDn8ILU02iMtDO2QreBZcv
         ibkdLQWiLur8vw7BK+lHAqtdNN7mA1O7TRlHsrOYHCUF98YyIeC8FrJjKyUQL0hivyJz
         cGtGhh4mlADVXE2q3AM6nam2vrE0MllfH5Hb2igdWfMQtLNlFOLn42KITVr5xxTEYoEG
         rG9TyqZv+0MeZ8BDNJEeWGqaLck5t+lDkOxl5gGAiyDU+DOOPV4O4NkNSNpNPoVKfei3
         v3iN7XDaPoHsU6cdgiA1clu3/+ZXIrwJawBUDR22VDvVoS/SGz3Q6CqyU9Kgy98aY6gP
         d+DQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="rjhd/M55";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SUaDcNKIiq3IJ/D/N/Ub2wrofqd5Uua32u5h9/iTC/U=;
        b=A35cw9RzXZZ4snkdOdxpNybycNRYDwqkklxJYrUHPb9Px9TCnSVrowpmxqkTjyh+6u
         H6jEBybagSiFeYBR6EaxamXqcYfn20uNhy9psvl7k7pp4lY5TcPxdvIDm6dEwLHDJwJo
         3ZVLMXVzjyMynIec6rConGO5eGg3w4eZaSvxPrWx3obKb9QttUYLzSv6Jl1fMxnJh/s4
         K9wxRuvF/qUVpHG+dj1lPMwayCGnWD5J5CBYDOKtY+QWjW3KxaszIwLiO4YRw5GiiH80
         Q9Eoi4PNbWB9xi7u6h/m1z+yKupNxODJXjvM/kedKun51ctJ/gk7hD/jPh2BCkYBK2Jn
         2THQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SUaDcNKIiq3IJ/D/N/Ub2wrofqd5Uua32u5h9/iTC/U=;
        b=axNg0cjKGsH1+S9xF/rakINNE0jWEWdbnMK2b7uZbC++hHA5p4qDasZTBj83RUlOCt
         3IUCXzJZq+36uPKDgD/URUC+l+2T6FxJDBzgasrOpBTni+0cOd7eFJ0m8Xt+pPTCb8fL
         UvKI2Pwa2TO8ZIUhXgLB2sMxoUj/xV2CBCATeuShTfc/tVrXFAGGw8dfiKDTrDU4v6zj
         OZnZbt+ZeYr+wCxcWJQcIFe/6GvctZo2QchVaQBvqK+zRRuhYxWPlTjlXoBxJKvoK6+0
         kHaAwom16hnJDflUanxGqLMq4B+Ux941zthxqR09QhsuDji+nmjAHpP1h979Sp9oXRqc
         7Tvg==
X-Gm-Message-State: APjAAAW3A+rjOP+PxnVMBsTGBnCXuBmqIZBmCOhCc1VAGVQh9mslYKGj
	+YSDszaueM3XGrUan5qO9fA=
X-Google-Smtp-Source: APXvYqyC13YFUBs76/ZD3I9iPi61HcSKCorP04pbTTG+dRIpTAotEvbCV90FdLfVdgd4Lf7o3hUkDw==
X-Received: by 2002:a05:6830:1be3:: with SMTP id k3mr12261027otb.180.1571926645975;
        Thu, 24 Oct 2019 07:17:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4783:: with SMTP id b3ls1757005otf.5.gmail; Thu, 24 Oct
 2019 07:17:25 -0700 (PDT)
X-Received: by 2002:a9d:37a1:: with SMTP id x30mr12419910otb.49.1571926645452;
        Thu, 24 Oct 2019 07:17:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571926645; cv=none;
        d=google.com; s=arc-20160816;
        b=bJHcFPc5Hc8ruKXqLiIiN2zg5xngBQq+62q3DiDKemghgtAVMjOR7pWH2n5vhvg769
         rk/ot+CsNtFiFwv73+Jjx1wuJ8csAwQXEYURZx3H0Q/VXoMymSGcrFkNEkIexVChS8Ut
         T8uUDT8TKabVFOLeGyVo2kVVNp04z8lnrHgJVOcpqVEwC9CEZshDhRjjEumkv6bjLctY
         SxnGEqEmMDH3iLLqxtTpm+spwwapL7uD0+OdOk7skwBOD2yZH8aCbIEwwobTJTnzFTST
         b0i4il70+Ykz0jGs6rYC/d7MZuMn9d5er9ao4NRNbbWoJ8xFpP5yPeD2wFpzu9hCmYLs
         /Qhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=S8i+kPsaZWRIBXyQ2g5/YSOuQEjiriODMzIUUPGICqQ=;
        b=Gs0tLnsWXfwoj+CBXSjULzsTa1XAXQ7CrxfunJPvHtbcS7GaFACFW1DIyiTr2PWf4s
         IoQ+XsMpSt9rem7Wq8QrWgPsLk0ITJ62n5wZ15Zh19UL5Tmv8hRIbbTRkgpfNVECacfy
         ItSZXHag36JQEip9C6Z7qmILifQiPsx8Va4R00BJ7zbP41tgeVhU9mAcLwYV2rTscAm9
         eBcRFK6aB7CRFiWZ7lc3Z/Od5UcnNU/HkXTnJQ7fw9XABTBoozCCPDrDxRkwDLyffv3e
         oMrR5V5jdVDMdIRLDaL1JNGuiYDf2eKXBaWusfeHdDX7Ac1TXuH+y5it2LUMPFCM60G1
         sQWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="rjhd/M55";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id n63si1315181oib.3.2019.10.24.07.17.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Oct 2019 07:17:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id 41so20774663oti.12
        for <kasan-dev@googlegroups.com>; Thu, 24 Oct 2019 07:17:25 -0700 (PDT)
X-Received: by 2002:a9d:5f0f:: with SMTP id f15mr11239283oti.251.1571926644575;
 Thu, 24 Oct 2019 07:17:24 -0700 (PDT)
MIME-Version: 1.0
References: <20191017141305.146193-1-elver@google.com> <20191017141305.146193-5-elver@google.com>
 <20191024122801.GD4300@lakrids.cambridge.arm.com>
In-Reply-To: <20191024122801.GD4300@lakrids.cambridge.arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Oct 2019 16:17:11 +0200
Message-ID: <CANpmjNPFkqOSEcEP475-NeeJnY5pZ44m+bEhtOs8E_xkRKr-TQ@mail.gmail.com>
Subject: Re: [PATCH v2 4/8] seqlock, kcsan: Add annotations for KCSAN
To: Mark Rutland <mark.rutland@arm.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Nicholas Piggin <npiggin@gmail.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="rjhd/M55";       spf=pass
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

On Thu, 24 Oct 2019 at 14:28, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Thu, Oct 17, 2019 at 04:13:01PM +0200, Marco Elver wrote:
> > Since seqlocks in the Linux kernel do not require the use of marked
> > atomic accesses in critical sections, we teach KCSAN to assume such
> > accesses are atomic. KCSAN currently also pretends that writes to
> > `sequence` are atomic, although currently plain writes are used (their
> > corresponding reads are READ_ONCE).
> >
> > Further, to avoid false positives in the absence of clear ending of a
> > seqlock reader critical section (only when using the raw interface),
> > KCSAN assumes a fixed number of accesses after start of a seqlock
> > critical section are atomic.
>
> Do we have many examples where there's not a clear end to a seqlock
> sequence? Or are there just a handful?
>
> If there aren't that many, I wonder if we can make it mandatory to have
> an explicit end, or to add some helper for those patterns so that we can
> reliably hook them.

In an ideal world, all usage of seqlocks would be via seqlock_t, which
follows a somewhat saner usage, where we already do normal begin/end
markings -- with subtle exception to readers needing to be flat atomic
regions, e.g. because usage like this:
- fs/namespace.c:__legitimize_mnt - unbalanced read_seqretry
- fs/dcache.c:d_walk - unbalanced need_seqretry

But anything directly accessing seqcount_t seems to be unpredictable.
Filtering for usage of read_seqcount_retry not following 'do { .. }
while (read_seqcount_retry(..));' (although even the ones in while
loops aren't necessarily predictable):

$ git grep 'read_seqcount_retry' | grep -Ev 'seqlock.h|Doc|\* ' | grep
-v 'while ('
=> about 1/3 of the total read_seqcount_retry usage.

Just looking at fs/namei.c, I would conclude that it'd be a pretty
daunting task to prescribe and migrate to an interface that forces
clear begin/end.

Which is why I concluded that for now, it is probably better to make
KCSAN play well with the existing code.

Thanks,
-- Marco

> Thanks,
> Mark.
>
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  include/linux/seqlock.h | 44 +++++++++++++++++++++++++++++++++++++----
> >  1 file changed, 40 insertions(+), 4 deletions(-)
> >
> > diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
> > index bcf4cf26b8c8..1e425831a7ed 100644
> > --- a/include/linux/seqlock.h
> > +++ b/include/linux/seqlock.h
> > @@ -37,8 +37,24 @@
> >  #include <linux/preempt.h>
> >  #include <linux/lockdep.h>
> >  #include <linux/compiler.h>
> > +#include <linux/kcsan.h>
> >  #include <asm/processor.h>
> >
> > +/*
> > + * The seqlock interface does not prescribe a precise sequence of read
> > + * begin/retry/end. For readers, typically there is a call to
> > + * read_seqcount_begin() and read_seqcount_retry(), however, there are more
> > + * esoteric cases which do not follow this pattern.
> > + *
> > + * As a consequence, we take the following best-effort approach for *raw* usage
> > + * of seqlocks under KCSAN: upon beginning a seq-reader critical section,
> > + * pessimistically mark then next KCSAN_SEQLOCK_REGION_MAX memory accesses as
> > + * atomics; if there is a matching read_seqcount_retry() call, no following
> > + * memory operations are considered atomic. Non-raw usage of seqlocks is not
> > + * affected.
> > + */
> > +#define KCSAN_SEQLOCK_REGION_MAX 1000
> > +
> >  /*
> >   * Version using sequence counter only.
> >   * This can be used when code has its own mutex protecting the
> > @@ -115,6 +131,7 @@ static inline unsigned __read_seqcount_begin(const seqcount_t *s)
> >               cpu_relax();
> >               goto repeat;
> >       }
> > +     kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
> >       return ret;
> >  }
> >
> > @@ -131,6 +148,7 @@ static inline unsigned raw_read_seqcount(const seqcount_t *s)
> >  {
> >       unsigned ret = READ_ONCE(s->sequence);
> >       smp_rmb();
> > +     kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
> >       return ret;
> >  }
> >
> > @@ -183,6 +201,7 @@ static inline unsigned raw_seqcount_begin(const seqcount_t *s)
> >  {
> >       unsigned ret = READ_ONCE(s->sequence);
> >       smp_rmb();
> > +     kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
> >       return ret & ~1;
> >  }
> >
> > @@ -202,7 +221,8 @@ static inline unsigned raw_seqcount_begin(const seqcount_t *s)
> >   */
> >  static inline int __read_seqcount_retry(const seqcount_t *s, unsigned start)
> >  {
> > -     return unlikely(s->sequence != start);
> > +     kcsan_atomic_next(0);
> > +     return unlikely(READ_ONCE(s->sequence) != start);
> >  }
> >
> >  /**
> > @@ -225,6 +245,7 @@ static inline int read_seqcount_retry(const seqcount_t *s, unsigned start)
> >
> >  static inline void raw_write_seqcount_begin(seqcount_t *s)
> >  {
> > +     kcsan_begin_atomic(true);
> >       s->sequence++;
> >       smp_wmb();
> >  }
> > @@ -233,6 +254,7 @@ static inline void raw_write_seqcount_end(seqcount_t *s)
> >  {
> >       smp_wmb();
> >       s->sequence++;
> > +     kcsan_end_atomic(true);
> >  }
> >
> >  /**
> > @@ -262,18 +284,20 @@ static inline void raw_write_seqcount_end(seqcount_t *s)
> >   *
> >   *      void write(void)
> >   *      {
> > - *              Y = true;
> > + *              WRITE_ONCE(Y, true);
> >   *
> >   *              raw_write_seqcount_barrier(seq);
> >   *
> > - *              X = false;
> > + *              WRITE_ONCE(X, false);
> >   *      }
> >   */
> >  static inline void raw_write_seqcount_barrier(seqcount_t *s)
> >  {
> > +     kcsan_begin_atomic(true);
> >       s->sequence++;
> >       smp_wmb();
> >       s->sequence++;
> > +     kcsan_end_atomic(true);
> >  }
> >
> >  static inline int raw_read_seqcount_latch(seqcount_t *s)
> > @@ -398,7 +422,9 @@ static inline void write_seqcount_end(seqcount_t *s)
> >  static inline void write_seqcount_invalidate(seqcount_t *s)
> >  {
> >       smp_wmb();
> > +     kcsan_begin_atomic(true);
> >       s->sequence+=2;
> > +     kcsan_end_atomic(true);
> >  }
> >
> >  typedef struct {
> > @@ -430,11 +456,21 @@ typedef struct {
> >   */
> >  static inline unsigned read_seqbegin(const seqlock_t *sl)
> >  {
> > -     return read_seqcount_begin(&sl->seqcount);
> > +     unsigned ret = read_seqcount_begin(&sl->seqcount);
> > +
> > +     kcsan_atomic_next(0);  /* non-raw usage, assume closing read_seqretry */
> > +     kcsan_begin_atomic(false);
> > +     return ret;
> >  }
> >
> >  static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
> >  {
> > +     /*
> > +      * Assume not nested: read_seqretry may be called multiple times when
> > +      * completing read critical section.
> > +      */
> > +     kcsan_end_atomic(false);
> > +
> >       return read_seqcount_retry(&sl->seqcount, start);
> >  }
> >
> > --
> > 2.23.0.866.gb869b98d4c-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPFkqOSEcEP475-NeeJnY5pZ44m%2BbEhtOs8E_xkRKr-TQ%40mail.gmail.com.
