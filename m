Return-Path: <kasan-dev+bncBCMIZB7QWENRBNHQ7SGAMGQEBWETBXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 797AE45D547
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Nov 2021 08:16:06 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id bi9-20020a056808188900b002bc4f64083asf3270637oib.7
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 23:16:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637824565; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zh7OenfT3v89k8UGdVqBRbKAd1qjHaWhekT5HEX6xV0iCWAx7gCwbfpTvEjKOtPC9t
         FtmysMhrmbADbSpFRwiuk2ZE8DqsHZ/J3EDQEZsAiTgh11srr1cEV5IQRwj/UUxynSxZ
         IDKS16zPY2/KCo9vOkHwyLAlEgfoX6KD8uTWJRyFenNhz/SzpmZxE4ddZYwqO+wd+6wI
         KgHqYqqdK/wKeGtJCyeAJzqsToLvDRohIMx2R3YK0hzoePTJupukw2MLSVmJJ8lv/9Qh
         p4PY5gydibF/3V8rxV4ceun5AGp1HTc+3abTUqKPRnE/9bdtY2x/dOJaIQi9YR/AWWb2
         ZOcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kIMOwo99KLD7zu4iHjEyOJMVqZhN5t2xFGmFG/IF9Wk=;
        b=xAxpdTA7o6bo3C2ly3Ta52aRDRFvtg/cSrB57tNnPqXihBruYcKCIG/AdAfV2EDu+6
         FeLYBf7ManMS+QwKp1Rwx6SMveiSSMKc3OSJx5Lo4710P8UzQqCj76MiRIq8Lw7u5ZlL
         jdN5C2EUafJU4YRKFlH6aowBEWgI+rMFo+0b5z4qhFUMeTfmW3AnTV+TXuoigRghmrKb
         QmFR3ezOvIP9zd1S3cPjbOb6LRwmyxgDjr+l+lvQaAdT1CSDhxuDspGJ0bEB6V22gLGE
         F3raSbKIoJI5xBZSgH3BGQm1Fst39dw0+2r/+fXfrJqYMj0h2GFFzkDM/LovGCzxwEhW
         qzuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GzRzqrIB;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kIMOwo99KLD7zu4iHjEyOJMVqZhN5t2xFGmFG/IF9Wk=;
        b=baPHk6ezwChqzY1RKouRzff3Y35bJrCiQAeigugZ10pwvjiydC/ML4YB38h/iB19Hu
         eZCZ9EqzMzHesaYmrWKktwjBmYH+CCoMk3x9njA7Hzez+fBcgd/ZonJOcbzq3TEeqKPf
         9+LG+HiVbS500SJQJyUOzcVHNW4dcX2WJkHsh6rQthgohRYjaZJjstgJjfzXxxY/HNLg
         DbSW1FSgQv/thRhLIINV+pJ5re+NJBuJwqN+c8ufKl+Up0Gkr7jUIX08VUMytUz0Qikt
         NfdBdyAGNCtYfq7+L480w0zqlYgcN1eXRn3mnNOVbsGyCB0NirRvA3CkkNC51IcsGIOm
         KS8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kIMOwo99KLD7zu4iHjEyOJMVqZhN5t2xFGmFG/IF9Wk=;
        b=I20kORdfYGwAfKaim6kiS9qfLF4+sO2FYlh9R7HznArqTQAhacOSwqdY8OaWjX9chi
         CgbNfcTcwCtOR6Pw5y4ZEnC3qWXsZlQB27AfhDwuDBwU5Au5xpg1zKdOdNWPDr6x9pX8
         SX/YtXWGTjnpjpsXym7A02XBIVpP62t6/RH7K/UACu2c0kVebM0w/2mOyDafuDOFfdih
         kck0LSp3vyIXfM8leTuRVyRqUZAEnF4OU13PcYcF5YVi06Pa8/2QthgVFCAcw3OifZ6V
         eTUcFIcdQb+h9SKEy/nnuIFW3PSOyrdir5bZIDMBxA59Mk96doVSksggehp4esMPFFwW
         OKUQ==
X-Gm-Message-State: AOAM533Fuwlrid8mewNM87rJZ3oBoAgB91eRp3rTFzJu2j7OKuz1tJTS
	h994YsswtuzH7DeFsdJcI/g=
X-Google-Smtp-Source: ABdhPJwe2GhYiUwj4fMsRL002Z4kOwxAJ5FKz0sCqveCJwQoITbIPSkfOuUWUhfCqQKgg0dMY88yNg==
X-Received: by 2002:aca:add3:: with SMTP id w202mr13261446oie.100.1637824565013;
        Wed, 24 Nov 2021 23:16:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2690:: with SMTP id l16ls923944otu.11.gmail; Wed,
 24 Nov 2021 23:16:04 -0800 (PST)
X-Received: by 2002:a05:6830:138b:: with SMTP id d11mr19646070otq.235.1637824564683;
        Wed, 24 Nov 2021 23:16:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637824564; cv=none;
        d=google.com; s=arc-20160816;
        b=QgAbTRYKc1T5bN0Z/orzgMTu1RXNydymcGstYiQvymlMaajxNSB4b0FD3SxUSi8VEy
         EnOEVVds8oOUttAaLdC/uLYGZrj1jDqlcwU2z5CjUqi0zg0tLMRu/J1uqKoYGxjEvTvS
         B1pIFM9Skw1xQxOOtmimy8kUnUHUJ+WwUkS01dwS/mbY+pXxBTHrhWtb4RIf7P14OnEA
         lXfsnIfAL9wy4dnlAmSZI4Qx3SnELC1lDUZYIunFTe+Czbe1R9yv9BpDeY4cKmOHcap3
         BJ0gFdL5VSUTjWCpy1scFmGhUCj8Tb+mx99ZGN/Vd0H+AgpozwKefVflxg983K3Ykylc
         F1ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1Q5EhbqpeXowwDK0bUK5avmicbNdhuUZQON4VKkJTMQ=;
        b=zCMEvy9s2Py2zgbWoXTFKS28x6BLjg6HIAVucH0qP82twanSh6dBnnGrPfvB0EO6TA
         wJchv1Hb9oLhCbxWmY4hF1roCxsvVSiHruxVx88PukJtWn4g1hh9v+QkBF+YCjK6nbI0
         UCUFOK8CN70h5U5K44p6/qTQPsDxAYYjmu51fxE82f/UP+dDs509aWS6N1uTnC7UoTIc
         4v2ZMKBaN+kawzHz1ltiNQLH9kjf0EItqQO8j4KlnlP5+sF7TRQO/DP6JjXOOsauJ7qJ
         3sd3c7Dz6h7N+YiXG7Nw+d2TaV5TFKCIR7duWI2sWT42JA1tmEuom3YrPkx+yFSd5I+m
         KWTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GzRzqrIB;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id d17si421452oiw.0.2021.11.24.23.16.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Nov 2021 23:16:04 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id a23-20020a9d4717000000b0056c15d6d0caso8120019otf.12
        for <kasan-dev@googlegroups.com>; Wed, 24 Nov 2021 23:16:04 -0800 (PST)
X-Received: by 2002:a05:6830:2425:: with SMTP id k5mr19508104ots.319.1637824564135;
 Wed, 24 Nov 2021 23:16:04 -0800 (PST)
MIME-Version: 1.0
References: <nycvar.YFH.7.76.2111241839590.16505@cbobk.fhfr.pm> <CANpmjNOHN7SWu-pKGr9EBb3=in2AWiGmqNb6sYwhebGtRk+1uQ@mail.gmail.com>
In-Reply-To: <CANpmjNOHN7SWu-pKGr9EBb3=in2AWiGmqNb6sYwhebGtRk+1uQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Nov 2021 08:15:52 +0100
Message-ID: <CACT4Y+aZ_qtMXYiWgLmEgpceookbwUAtKq33rspc+XJNQg4y9A@mail.gmail.com>
Subject: Re: [PATCH] kasan: distinguish kasan report from generic BUG()
To: Marco Elver <elver@google.com>
Cc: Jiri Kosina <jikos@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, jslaby@suse.cz
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=GzRzqrIB;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::335
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

On Wed, 24 Nov 2021 at 19:06, Marco Elver <elver@google.com> wrote:
>
> On Wed, 24 Nov 2021 at 18:41, Jiri Kosina <jikos@kernel.org> wrote:
> >
> > From: Jiri Kosina <jkosina@suse.cz>
> >
> > The typical KASAN report always begins with
> >
> >         BUG: KASAN: ....
> >
> > in kernel log. That 'BUG:' prefix creates a false impression that it's an
> > actual BUG() codepath being executed, and as such things like
> > 'panic_on_oops' etc. would work on it as expected; but that's obviously
> > not the case.
> >
> > Switch the order of prefixes to make this distinction clear and avoid
> > confusion.
> >
> > Signed-off-by: Jiri Kosina <jkosina@suse.cz>
>
> I'm afraid writing "KASAN: BUG: " doesn't really tell me this is a
> non-BUG() vs. "BUG: KASAN". Using this ordering ambiguity to try and
> resolve human confusion just adds more confusion.
>
> The bigger problem is a whole bunch of testing tools rely on the
> existing order, which has been like this for years -- changing it now
> just adds unnecessary churn. For example syzkaller, which looks for
> "BUG: <tool>: report".
>
> Changing the order would have to teach all kinds of testing tools to
> look for different strings. The same format is also used by other
> dynamic analysis tools, such as KCSAN, and KFENCE, for the simple
> reason that it's an established format and testing tools don't need to
> be taught new tricks.

Yes, lots of kernel testing systems may be looking just for "BUG:" and
start missing KASAN bugs. Or they may be doing more special things
when they see the current "BUG: KASAN:".

> Granted, there is a subtle inconsistency wrt. panic_on_oops, in that
> the debugging tools do use panic_on_warn instead, since their
> reporting behaviour is more like a WARN. But I'd also not want to
> prefix them with "WARNING" either, since all reports are serious bugs
> and shouldn't be ignored. KASAN has more fine-grained control on when
> to panic, see Documentation/dev-tools/kasan.rst.
>
> If the problem is potentially confusing people, I think the better
> solution is to simply document all kernel error reports and their
> panic-behaviour (and flags affecting panic-behaviour) in a central
> place in Documentation/.
>
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaZ_qtMXYiWgLmEgpceookbwUAtKq33rspc%2BXJNQg4y9A%40mail.gmail.com.
