Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIGVU64QMGQETWJGYSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 728EC9BC997
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2024 10:51:30 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3a3c3ecaaabsf66106195ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2024 01:51:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730800289; cv=pass;
        d=google.com; s=arc-20240605;
        b=G/jGIBf+PgwgAvi2LCE2b6NuN1T8dvLn6BVupfWe7NCJkAvyufSBJCV8vZYMtIdVYX
         SwWFnFCZqUB94SzjnL7PRsu1BeUEL0DR81+ECVaNDWLqbn7Vc//BUdRbS4X2X3lfTW5U
         YiP7C17cFYcKee8FitQGjBKtPzrs9WCJMDjqOW5SffeMECe9sEr1eZrmqy7TRaUNoTZz
         2SId5lJ3rQxcGHuldMQidbVIzWENoCLXZnLPjz5MOwlCP9k80eOg7NIHDLiTiF9dP3g+
         XYatd6Nts1DvoImuyUMSe5sxO+aAq/60X6CYUk7JweEZnigE18bXuvQb23BCQORaiV9n
         l74A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=u46tZG197V8gazlf+FiI43F4hiT4JUu8BRmOGpmHl+8=;
        fh=lTO4HGKi8RKpvqxt7hEMmDZqAac6oTYh7EbXp0hZlz4=;
        b=GleLrHDN4pzubk3XpULdjx2RR6KeYw+QVGYQ85Sy4Xun22ae2XMi+mYsXvANfkqMl5
         ZkAlrrE6DI16+wkBJJvHaLtrLFjbMFpl/yiIPmL6Cz/4wwYyNW5Mq8bz7sRoLHYrL09p
         Jx8EV4tyCd97x9cQqAadRYDocJMOEEi3N3yEvUhZJJ9bVGIwtzYqmkkG1+JMPKHQMAe3
         c11uihEhZx7QAkBic7KjECC4RgHv4LXvutTxsm/S9XAM509tlWp5QTB+dfjJigbcQliq
         Pfw0u6t7H5eWlYv4B4l9gkyu4/xqRJOT/qsIOCE2MiTbWyBIPkWlbd/TwfQfOJ+NUk8x
         kNrA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RDIMLYAr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730800289; x=1731405089; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=u46tZG197V8gazlf+FiI43F4hiT4JUu8BRmOGpmHl+8=;
        b=de28t1W5qOLsP6oZ+jlaj+ajnvMZnSISs90ApYul35WF7zGP85Hymb/c+uzst2NSTS
         HDTnQms3jfr6z7dz1SmynBc3I9GFNSW3Jq4LR4Z3GI8T4GSt7Y0Sd2tHuQR1GfWCbdnc
         2nOQwFLSD/TEVHHlRCHChmHcPqCE1fhmTzOvtdrKFHWu2vV+L5x01Myi0n2RdoeCH86q
         9chccV0tUFAheVvTLpG/7Alr0BgWt2Z07tg4zBIwr7UyGZvhmgBmwPGG/2HBOeOTBXAC
         f5xBsR8vfggs4/ar26yKhPSTnAjtTJm6Lvl5xKVwQd56A75LOAron/efXtfLTQIT/fk9
         j7ZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730800289; x=1731405089;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=u46tZG197V8gazlf+FiI43F4hiT4JUu8BRmOGpmHl+8=;
        b=ghDDCdL1rukcYs3CJno01jr2C7PY8YywDc7Y0wCG+hMo7+JhtWCSRTtNaUvSTG3e94
         9Ybw0AoxfA0IBTbvt4XmeODcznFvxkH6dkQm+HqJCSbUu/TF5KY4ApWI63Vtini9wZpZ
         OToDJUi/d/TLLU8+AZEMBReGzyqW9p2UGezKhSJHYHFE7riN2NJ3jMlra8tNIANmq9lL
         0GQfz48bg/axgMxTUImM5cNJiDVP5TlS+3V8xAb8qYxzsykmjddeqYJ+ygyZqduAxdsx
         idfn6KyL0I4E4rDBQc94FoJSOXBCcuwIDTde0s0kZ51+JPQ3HcuLUMomax01Z+cW/hiw
         jZiw==
X-Forwarded-Encrypted: i=2; AJvYcCWI8OGYi/NAnouotKMRK1JDZ7V9Qk/+QBPpCg3dzSirXw4Ita7ERx1Wn/DOL6HXgE96fzI8JQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz77PLF3LARdTUwpMF6D3fQ4ssnjQ4FFkRawPIO0VRZ3lZMmgo0
	1Q5hZ7k7ALcVi589q0c97liZ9LhBt/M8TfbPOFE0ReEaPdYzRkoY
X-Google-Smtp-Source: AGHT+IEsHK0C/3HPwlfmSteVfPo+ZMFdzi3zdOHFVMGOCoIXu0ONNqPAwfpNv/r219mgZD2IFlqP6g==
X-Received: by 2002:a92:dd06:0:b0:3a6:ac17:13e0 with SMTP id e9e14a558f8ab-3a6ac171705mr131892345ab.14.1730800289236;
        Tue, 05 Nov 2024 01:51:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:214f:b0:3a3:daaf:d989 with SMTP id
 e9e14a558f8ab-3a61c51b941ls28655115ab.0.-pod-prod-01-us; Tue, 05 Nov 2024
 01:51:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU8UXpnh6L/mjeNvW6078LUXmyBrIajYuvkn057BwEfeG44G1G8/07vvnB8zFJe+dRm1K6xgch8VY0=@googlegroups.com
X-Received: by 2002:a05:6e02:1749:b0:3a0:5642:c78 with SMTP id e9e14a558f8ab-3a5e24ab419mr226789045ab.15.1730800287983;
        Tue, 05 Nov 2024 01:51:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730800287; cv=none;
        d=google.com; s=arc-20240605;
        b=PyAhLvLHxtSkFLIqAyu5WBzCFck4M34FaqxADJwwDDoWm8EJJyNQ9vNs+Xi9J0R7ba
         VOJlMB6+VhOTUKfcvGSpE9fYT7cCW9uSxbm2EF0THvEHEYIKcUtKT3ZfPiXWKV9Ugqm6
         gI/UBVy33/MMr/O8TE9txKIXvWnMbY/9bEirgUiwVtsLWca8/IcXmWEeBWALp5HNkpae
         LulTCqywJrgBz3f2X64e2RF4VffAlC3iwIacm9LAtfwNcewOnC6PCVcvkH6Zhu1nUhtv
         Hp/MSB1glAK0eWTPcCbmbKjs3jFp590zxXFW+Q+Nr41DKiQKbHeMPFv3qEHhsG6YNSVo
         9jeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jwaGk6EDoKX/mSWj1TE2Or6j7PpZkwghT6OhNz4FoQM=;
        fh=tYduffzIgIzvYBxfnHy55rjf2cIPPy3JnlUeKBkncOM=;
        b=cM3lMCnF88AGPQGm34Fu6oRxyaxkD5zGw+dgKKCnZ86pDcBMUZsp2s9NedBKYeQ/j1
         IZJGZj0uN8pX2j6jCmiz7uRIRYfHrJIFSmLUdLt4iDd4l/AU8byWPII6D1AMO/GMg8qC
         G/5H7sBQjoG35owGpkCRfQvNE6Rh+B/2iv1s0epDW7Hy9zYiFyvkLz8glrhSIA7nKCof
         geogs6g9ssiETRG7QTabHR/xIhNhMIFIQjkzR13OdwPJ94IOjiGEt0q7h1ajvCFjpN2p
         83ltBvoGh2I2+7QaQT65MHmHuOXAWh99LLPydN0UvrEg24KdxREj/H5OHcho5l4SVHKq
         6GoA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RDIMLYAr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3a6c2abbbf6si2247605ab.0.2024.11.05.01.51.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Nov 2024 01:51:27 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id 41be03b00d2f7-7e6cbf6cd1dso3520163a12.3
        for <kasan-dev@googlegroups.com>; Tue, 05 Nov 2024 01:51:27 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWf30hYz0VTudDBbObBp9QKfXDy1MZ0e+0a9tf3O16rzuJxFoXJmkXo7DA3JgPtk2i4vcz+Ak/HHtQ=@googlegroups.com
X-Received: by 2002:a05:6a21:78a6:b0:1db:d980:440e with SMTP id
 adf61e73a8af0-1dbd980462emr8904949637.14.1730800287064; Tue, 05 Nov 2024
 01:51:27 -0800 (PST)
MIME-Version: 1.0
References: <20241104161910.780003-1-elver@google.com> <20241104161910.780003-6-elver@google.com>
 <20241105093400.GA10375@noisy.programming.kicks-ass.net>
In-Reply-To: <20241105093400.GA10375@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Nov 2024 10:50:50 +0100
Message-ID: <CANpmjNOyE=ZxyMEyEf6i7TX-jEvhiJN5ASFY0FTWRF3azDAB-Q@mail.gmail.com>
Subject: Re: [PATCH v2 5/5] kcsan, seqlock: Fix incorrect assumption in read_seqbegin()
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>, Waiman Long <longman@redhat.com>, 
	Boqun Feng <boqun.feng@gmail.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Mark Rutland <mark.rutland@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Linus Torvalds <torvalds@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RDIMLYAr;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, 5 Nov 2024 at 10:34, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Mon, Nov 04, 2024 at 04:43:09PM +0100, Marco Elver wrote:
> > During testing of the preceding changes, I noticed that in some cases,
> > current->kcsan_ctx.in_flat_atomic remained true until task exit. This is
> > obviously wrong, because _all_ accesses for the given task will be
> > treated as atomic, resulting in false negatives i.e. missed data races.
> >
> > Debugging led to fs/dcache.c, where we can see this usage of seqlock:
> >
> >       struct dentry *d_lookup(const struct dentry *parent, const struct qstr *name)
> >       {
> >               struct dentry *dentry;
> >               unsigned seq;
> >
> >               do {
> >                       seq = read_seqbegin(&rename_lock);
> >                       dentry = __d_lookup(parent, name);
> >                       if (dentry)
> >                               break;
> >               } while (read_seqretry(&rename_lock, seq));
> >       [...]
>
>
> How's something like this completely untested hack?
>
>
>         struct dentry *dentry;
>
>         read_seqcount_scope (&rename_lock) {
>                 dentry = __d_lookup(parent, name);
>                 if (dentry)
>                         break;
>         }
>
>
> But perhaps naming isn't right, s/_scope/_loop/ ?

_loop seems straightforward.

> --- a/include/linux/seqlock.h
> +++ b/include/linux/seqlock.h
> @@ -829,6 +829,33 @@ static inline unsigned read_seqretry(con
>         return read_seqcount_retry(&sl->seqcount, start);
>  }
>
> +
> +static inline unsigned read_seq_scope_begin(const struct seqlock_t *sl)
> +{
> +       unsigned ret = read_seqcount_begin(&sl->seqcount);
> +       kcsan_atomic_next(0);
> +       kcsan_flat_atomic_begin();
> +       return ret;
> +}
> +
> +static inline void read_seq_scope_end(unsigned *seq)
> +{
> +       kcsan_flat_atomic_end();

If we are guaranteed to always have one _begin paired by a matching
_end, we can s/kcsan_flat_atomic/kcsan_nestable_atomic/ for these.

> +}
> +
> +static inline bool read_seq_scope_retry(const struct seqlock_t *sl, unsigned *seq)
> +{
> +       bool done = !read_seqcount_retry(&sl->seqcount, *seq);
> +       if (!done)
> +               *seq = read_seqcount_begin(&sl->seqcount);
> +       return done;
> +}
> +
> +#define read_seqcount_scope(sl) \
> +       for (unsigned seq __cleanup(read_seq_scope_end) =               \
> +                       read_seq_scope_begin(sl), done = 0;             \
> +            !done; done = read_seq_scope_retry(sl, &seq))
> +

That's nice! I think before we fully moved over to C11, I recall Mark
and I discussed something like that (on IRC?) but gave up until C11
landed and then we forgot. ;-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOyE%3DZxyMEyEf6i7TX-jEvhiJN5ASFY0FTWRF3azDAB-Q%40mail.gmail.com.
