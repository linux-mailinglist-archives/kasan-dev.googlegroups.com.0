Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQNMWGMAMGQEWWE66SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 14D015A42DB
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 08:01:39 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id l15-20020a05620a28cf00b006b46997c070sf5943990qkp.20
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Aug 2022 23:01:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661752898; cv=pass;
        d=google.com; s=arc-20160816;
        b=THkOw+s0HrcT98CcJVMyAesoKRolnEtuAIa4CDTENAC3rNpjzYU4d+IVetMe9/Nerh
         pOP2YfYWmanuj0M9My0Dpk/kbv+Qy9lxck1/5Qxt4XLUPnposJY9ySzidj+XNKRNakSN
         O9jX4R+IkcLm/wqfqkdI6oxRZdFptZXyozDVzhwkiIikGgU5dME51DHMikmDTzTgkxEM
         AKwo6yZZfK9X0BVrNC5RgbOcCyqc+JFL4yfwGbtyWNJGYpgvxkx4ujynjMdZOEQgZvkB
         ZUP4EPmTQSREhOzXkZ73gFUJqmoT++Ff7ozEi/1IOLHyeaT8WyOxJqlDUfSQ+0+keTtl
         +e6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Pz5nxu1GegpViUZTM0KsHqR9UCE1CamEkGBAm6ALRgs=;
        b=TnOofXRxmDLY+B0iKSa2TkcoJxKiQU3/t9IUkgjQbkBHByAQvW+oCDyN8MecEFiMmU
         zTDekTn/9kKTzYcZGK82nFOUniDfjDkf11rLupUJJze3cPfnNerHTm9tniFty8tX67aG
         XeEAzZEo57teAAoV7kZLdyYNh2yjL32+wy/DO6fR/MiiDfG7CMrvhPZQFwVx/HOrsJDo
         ywtbQz4MpMjzZKUprT4zCp17aKjhrB3SRuCbmy7nZxocibNuAgY+xHatm1Q4vfEYuQ3o
         OL5F1oA6sSneP7W11GOylWW1nhZM2iJ7vUMWqaQgVqYeJ7wcnRCgsaQezZ2UjqPHaAYZ
         ouhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XY395wkd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=Pz5nxu1GegpViUZTM0KsHqR9UCE1CamEkGBAm6ALRgs=;
        b=B1zQmppjSNQ53pQTyJOr4r0t2CBri32NlSjcUjW5nTbvv56JS0gIdszIuSTyMzdogl
         0RKQVvFyYT3T5gisKAjKiweN6501OgXfY1kQ6uwJrW+cw8+awaayLYZrXr4mTuJkuVYs
         wWY1rHnmW1bjz5LGlFZMXjP0iVnFJ4KSUaUlDT/qTgmyMuLvBBU9VwIMgxL8BRkONFve
         JmkQUc7XsC8cIDWm+ICHLcEsUuTdwKP7yy8pKulbFg+pKuteBKdxTGpTZEA+2VXTe0Fu
         haScgi+99Ihli4rWuXgvlgP9X1k1FVXjL7wr9ZK55ekLTA5r4xALxGxmPdjiL9Nnmqwb
         qcgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=Pz5nxu1GegpViUZTM0KsHqR9UCE1CamEkGBAm6ALRgs=;
        b=fqvfuicErmDtHLe2+jSmJ3FWgDPyUwK/IcWabOGYhM+UJ1Esadi0O0Y0Ql+x2sr8CN
         8gdKxnN5dVS/3NKybljBJCej4VkpV66Ab8UoBLaONjiisSFNG59AT8lfr3l+7hSx51UV
         Aq5L3h0SEYeDxP7GSvIXOLMBDkkYG+cup+Y29OC8KufAAgrwmSOMMA22MSebWwaii6uH
         iuhBxayENf8WA9MR6pyYiWaqFUg6pQqO9Koyz/IVIUvPCk2zsCQ0QJrFpMp4aBua7jv9
         sDp8r3vnK/8tCGNLdI5JzNb1MOU6nFNxbvQH50i3Cgi0eNKy0cO0omM+MjHv5gYqZ0J5
         ETeg==
X-Gm-Message-State: ACgBeo3Qc+4pgfE1Bn2OjbWPibQGU6NHRLCF1Ny+L7+liMk3OaYc9vGe
	H9VQwtZCA8i32yjNJU/DKEE=
X-Google-Smtp-Source: AA6agR4YBYlqunUbjxd7xW+P8HDHV34WlGWSnqvp0upYGD6fKtlExLaP4my23nINaKGNyEuCSkK/ZA==
X-Received: by 2002:a05:6214:1c8c:b0:473:408f:ddd6 with SMTP id ib12-20020a0562141c8c00b00473408fddd6mr9567084qvb.74.1661752897874;
        Sun, 28 Aug 2022 23:01:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:118f:b0:6b9:57ca:5d1 with SMTP id
 b15-20020a05620a118f00b006b957ca05d1ls3447486qkk.0.-pod-prod-gmail; Sun, 28
 Aug 2022 23:01:37 -0700 (PDT)
X-Received: by 2002:a37:ef0d:0:b0:6bb:4ec8:b312 with SMTP id j13-20020a37ef0d000000b006bb4ec8b312mr7124488qkk.249.1661752897252;
        Sun, 28 Aug 2022 23:01:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661752897; cv=none;
        d=google.com; s=arc-20160816;
        b=Bud6qpiFbkizLdn8AvDl27NaOD3qHsfuQ6pO18LBNUUr/nSW2DvCrbSxA3aLpj7w1y
         71mc8s4cjS7ExFSiqKTmANT/4dz1lprNOHe/8rPXooP8jBQ8QImc9qZ8s65YM/uXcKgl
         ClQJWEn3f1tME+dwRj41Ll11LgaXoYIGGX0YUhKzJtvzi6y6fJu9XRoyhbK+WAvZh8xp
         7jmcXdrM1F5RrJIKnHRNBH+NfokNO8C5IqPdtFeeZjVGNwLKTkl5oOhabj4o8BKaVvEQ
         X1HGI/zVCH4YeCkrQ7ByTWivZITLwCfXaJ+KUcC5A6RiMcsM0WKaSWX7M5NUHZ9+BrDP
         qzkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GcD+HCTsL9PhfIoNQS6OfBy4IaHMHLVbPkWLbk6HzGE=;
        b=lXzjAejVnAzysy35U8sqtHBmMGdQwdmuAugkU1o6mPYZNxS4TuQTE/dp8ZqlaVgTJ8
         xwPXfZIKFDIqadFuPVJ7qB6aUfC7zR5WxjZzAvcKFRN7ugzlPk6/V+nTjSmgNju1xzfO
         jAqsZNyRuWRP2FWq4JaeuWso53gWpVQbxVBnJEf9jVDAXCdrjTvsHoEdNZ+iDxnH9M1T
         Y8I9JG6ou9hPLKY3BaYXWOpK8fLY8IC86X8q7yyYvlj0NwCpiXK+cGQhw981M0OvMAGk
         IZEGbxf1fCa6oPTFkyi/kgrqeB+KJ4YH3XxDVz1oodxZwaBqXs/PmnDf2ShE847M69N5
         2wfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XY395wkd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112d.google.com (mail-yw1-x112d.google.com. [2607:f8b0:4864:20::112d])
        by gmr-mx.google.com with ESMTPS id w14-20020a05620a128e00b006b95a1880d8si211862qki.7.2022.08.28.23.01.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 28 Aug 2022 23:01:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) client-ip=2607:f8b0:4864:20::112d;
Received: by mail-yw1-x112d.google.com with SMTP id 00721157ae682-333a4a5d495so170110667b3.10
        for <kasan-dev@googlegroups.com>; Sun, 28 Aug 2022 23:01:37 -0700 (PDT)
X-Received: by 2002:a0d:ea49:0:b0:33d:bce7:25c2 with SMTP id
 t70-20020a0dea49000000b0033dbce725c2mr8651338ywe.267.1661752896882; Sun, 28
 Aug 2022 23:01:36 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-11-elver@google.com>
 <YvzjeEHYX9d5dhAt@worktop.programming.kicks-ass.net>
In-Reply-To: <YvzjeEHYX9d5dhAt@worktop.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Aug 2022 08:00:00 +0200
Message-ID: <CANpmjNPSOnMN3Fc4yxoArTytQcW4n6sPCN-LnisTn58xLU=4HA@mail.gmail.com>
Subject: Re: [PATCH v3 10/14] locking/percpu-rwsem: Add percpu_is_write_locked()
 and percpu_is_read_locked()
To: Peter Zijlstra <peterz@infradead.org>
Cc: Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=XY395wkd;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as
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

On Wed, 17 Aug 2022 at 14:48, Peter Zijlstra <peterz@infradead.org> wrote:
> On Mon, Jul 04, 2022 at 05:05:10PM +0200, Marco Elver wrote:
> > +bool percpu_is_read_locked(struct percpu_rw_semaphore *sem)
> > +{
> > +     return per_cpu_sum(*sem->read_count) != 0;
> > +}
> > +EXPORT_SYMBOL_GPL(percpu_is_read_locked);
>
> I don't think this is correct; read_count can have spurious increments.
>
> If we look at __percpu_down_read_trylock(), it does roughly something
> like this:
>
>         this_cpu_inc(*sem->read_count);
>         smp_mb();
>         if (!sem->block)
>                 return true;
>         this_cpu_dec(*sem->read_count);
>         return false;
>
> So percpu_is_read_locked() needs to ensure the read_count is non-zero
> *and* that block is not set.

I shall go and fix. v4 incoming (if more comments before that, please shout).

> That said; I really dislike the whole _is_locked family with a passion.
> Let me try and figure out what you need this for.

As in the other email, it's for the dbg_*() functions for kgdb's
benefit (avoiding deadlock if kgdb wants a breakpoint, while we're in
the process of handing out a breakpoint elsewhere and have the locks
taken).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPSOnMN3Fc4yxoArTytQcW4n6sPCN-LnisTn58xLU%3D4HA%40mail.gmail.com.
