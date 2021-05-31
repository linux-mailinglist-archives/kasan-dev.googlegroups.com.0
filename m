Return-Path: <kasan-dev+bncBCMIZB7QWENRBKXT2KCQMGQE3ISS4SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BB243958EB
	for <lists+kasan-dev@lfdr.de>; Mon, 31 May 2021 12:25:47 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id g26-20020a4adc9a0000b0290245ac709537sf307741oou.14
        for <lists+kasan-dev@lfdr.de>; Mon, 31 May 2021 03:25:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622456746; cv=pass;
        d=google.com; s=arc-20160816;
        b=DDAuyui0TFp0BZjGa1mfBn7c1Vo4miVEvuVyeGsK8Szf8nG1uz1jrjvl1hTA3A7V+u
         svmqsLPC60CWctDtjUfkzcau1Q6SaUE+4SlEclLvUbpS6WxFgYLrRgkOqummMbDn1Zru
         HWAeD3JLRplEiQ8TzxiJNjCPoAzfcLrc7yIWzBBv6rICDtTzaizDqV/wdPW7/lL1kXhG
         ut+0fjCLARpXNSPfT4EW58VH7BBMmUSzDwmCh+YS2rgIfNTrm79XdFoZ4eEcP5YdVXe7
         3JIeGzs7XqCNdDAt3acy80kkBuhGA0IUjYutKAOVmjS+X7h3rjW323SRID00vCqa4aX+
         dSNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NXDCS3cTAzaTzB4/0x+qB8B2eBhIyayxT5t/oVwJK4w=;
        b=o6yei52FE38RxaiOUhunipDteqnbCQb0ojH1ZiS6XT2LLAkVfvV1vqoUJx3lMtq9qz
         WETMmWeMwbDqLMmD3x2uiqd4E/2kQAu/+0cWO0A8vCLGg8ScgIPDgS70Q3wEybteWpKc
         DWyl812VoevWqWJb3Yjgab2HcWsfCBJLRoSZVoUX91GRIqTmlzF8OLSotMCF9vNs3ypd
         nYKgWGy3U/eTnaSNcyGnZNIIUMQAwXJwP5jdoOVGi0uQthcXPVJd6JUD08nxzn4MZiIt
         //R1QPU5qW4q0JncnwbjFqcFmL5i5VWF4uS5eBizM6wszHayi5QTZ0YsLBq34Lj2QV63
         7jTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VvX5faym;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NXDCS3cTAzaTzB4/0x+qB8B2eBhIyayxT5t/oVwJK4w=;
        b=GsQqRsjOaA5m7PeFoJKBs12woHgDYz9AvH8fKwmrKOaoTEFeAj112vL6QgdtrsG/oT
         f03rlMJgYGku0LNYGDb687mc+P96Ad3n210YYPQ74bEwPyO8BWV7IkeP+gEodT4pQZvl
         8AEUlqZYPBNIfWGRP3z5ANNZFjvCKie7iRRCeyEDUtThA9TvC8SPP4ngQ8UbX1RhM/Pr
         fONdAOX5/s5MCuChiPTP477mKi5wBj17rkBWgKEy91Py0N4qW0+rrWsxWQpU5NtYN7OR
         GgBiV6LIz8IEN3C0NTNr425eolLTrdu73QnplA3WQBnFg7GWPrsQvfjPAE5QEbo8xGL3
         9ZHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NXDCS3cTAzaTzB4/0x+qB8B2eBhIyayxT5t/oVwJK4w=;
        b=an898R2NYqYQfnNJ/HMQ3iecZz4fZqTeW6G8h2FgQRw5gSmbX+J+HzVyPP5+CFkQwk
         yH6sRisev8WiL18LxwFkhHH0C8rZahVRNNPOD7CEv7SA6cXLxjQitBnTnCMKwdR1ziLO
         pwAC+JtQA9M1IrMdu7IXmq4sNgG6DljTeF5BeT3NeU/EeumyqDjtcmC5XW8IC3uk0S4K
         zj/AE+v049MEMlWeuQdyMBLls+h/nCQm2ZorCb/8kbnKCLiNxnEX+ZKPWroSY3R5ShO8
         6V1wq/uw20RskzrRiyVvrbt3hFl1U96vmFMndYj44rP8fPFSfUgTPKu0oO0K5oW/Cl5p
         2xhA==
X-Gm-Message-State: AOAM531h3Ww/qlu9ySkF1lArlWVjDSvqMmEfVl3IHzPSIT2cx/2JFY3W
	7MgPCDZMbMHY9rx/Y9Xgcd4=
X-Google-Smtp-Source: ABdhPJxWeQYjn5slPztQm952C90JNngE0KfGsRz1isfjur34aH4IakAPPw28tq9v0eR9NVOlg3iNjA==
X-Received: by 2002:a4a:2b12:: with SMTP id i18mr6581378ooa.37.1622456746527;
        Mon, 31 May 2021 03:25:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:bd6:: with SMTP id o22ls4030493oik.1.gmail; Mon, 31
 May 2021 03:25:46 -0700 (PDT)
X-Received: by 2002:a54:4385:: with SMTP id u5mr13411967oiv.30.1622456746167;
        Mon, 31 May 2021 03:25:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622456746; cv=none;
        d=google.com; s=arc-20160816;
        b=QHELsU6QdvOAG0opNKIA+K0QWAqH4oVfbRj9I2XZ132RbFHNaXWtc5JXlEtSgxy56S
         gG2t3bMjaeYjOBgn5GQ4s6ezIsN4q7vNnaNNyLXj24yEzD10SUiOwI7M4LNV7VKfQWxd
         Z5T6a+s2/g4xT8olRgzrCDHsI17lm0LxzaSnnCaL2B6nlA08hH9XRFb4tBgSeFA6xBOL
         ydnf2k3wY22zXxxaXch98NMsRYLlMqbNrK0IMSsJ4x1bCV3eeuilnBG1MVB9zmuD8Vpo
         6tmEbY2i8I70j7XDmsi+Uz0kswm2prh6gr+qG0U/RUazzQldCLGnUJSmZ9MBTRmnGgba
         0dKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aeSnmbdhJZEVCTECigp3a9Q6Gua/F/iMUMujatSb30w=;
        b=PwHDOSC8XkSCSHltF46oF1kl7W9DRn0rQ4NlUX3aHu+SoN0QvknPv4+h9p9czDmyIW
         Ql/OZ6Yud1XMcZS2t2a4+e0zaQZUf8+a2/iAnrZYTm42v3kM3GlwYhdDBcM9/PUZ4eW7
         M0+0ceVRCAlRXzO9Yvz0QgnHA96fNgJXN84YHkN6JAz+DuayUCVkAEqMK92RiAFntGGO
         1qh2nMkue//TjpxkEF9zq/i9oFpomeG55XSQApNppqvKMKWcQ8T/tyS9b5BbsJ2Dthwc
         IJ2lWx3Tyus6uHLW6Vsjq7+I744zFZaOI1urCWWRFvmw5KbRp1lmKl5+ZxgjgX/8NaH3
         ofGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VvX5faym;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x733.google.com (mail-qk1-x733.google.com. [2607:f8b0:4864:20::733])
        by gmr-mx.google.com with ESMTPS id 12si1239237oin.2.2021.05.31.03.25.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 May 2021 03:25:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733 as permitted sender) client-ip=2607:f8b0:4864:20::733;
Received: by mail-qk1-x733.google.com with SMTP id j184so10746641qkd.6
        for <kasan-dev@googlegroups.com>; Mon, 31 May 2021 03:25:46 -0700 (PDT)
X-Received: by 2002:a05:620a:150c:: with SMTP id i12mr16042824qkk.231.1622456745339;
 Mon, 31 May 2021 03:25:45 -0700 (PDT)
MIME-Version: 1.0
References: <YLSuP236Hg6tniOq@elver.google.com>
In-Reply-To: <YLSuP236Hg6tniOq@elver.google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 31 May 2021 12:25:33 +0200
Message-ID: <CACT4Y+byVeY1qF3ba3vNrETiMk9x7ue6ezvYiP8hy2wWtk0L1g@mail.gmail.com>
Subject: Re: Plain bitop data races
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VvX5faym;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733
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

On Mon, May 31, 2021 at 11:37 AM Marco Elver <elver@google.com> wrote:
>
> Hello,
>
> In the context of LKMM discussions, did plain bitop data races ever come
> up?
>
> For example things like:
>
>                  CPU0                                   CPU1
>         if (flags & SOME_FLAG) {...}  |  flags |= SOME_OTHER_FLAG;
>
>         // Where the reader only reads 1 bit, and/or writer only writes 1 bit.
>
> This kind of idiom is all over the kernel.
>
> The first and primary question I have:
>
>         1. Is it realistic to see all such accesses be marked?
>
> Per LKMM and current KCSAN rules, yes they should of course be marked.
> The second question would be:
>
>         2. What type of marking is appropriate?
>
> For many of them, it appears one can use data_race() since they're
> intentionally data-racy. Once memory ordering requirements are involved, it's
> no longer that simple of course.
>
> For example see all uses of current->flags, or also mm/sl[au]b.c (which
> currently disables KCSAN for that reason).
>
> The 3rd and final question for now would be:
>
>         3. If the majority of such accesses receive a data_race() marking, would
>            it be reasonable to teach KCSAN to not report 1-bit value
>            change data races? This is under the assumption that we can't
>            come up with ways the compiler can miscompile (including
>            tearing) the accesses that will not result in the desired
>            result.
>
> This would of course only kick in in KCSAN's "relaxed" (the default)
> mode, similar to what is done for "assume writes atomic" or "only report
> value changes".
>
> The reason I'm asking is that while investigating data races, these days
> I immediately skip and ignore a report as "not interesting" if it
> involves 1-bit value changes (usually from plain bit ops). The recent
> changes to KCSAN showing the values changed in reports (thanks Mark!)
> made this clear to me.
>
> Such a rule might miss genuine bugs, but I think we've already signed up
> for that when we introduced the "assume plain writes atomic" rule, which
> arguably misses far more interesting bugs. To see all data races, KCSAN
> will always have a "strict" mode.
>
> Thoughts?

FWIW a C compiler is at least allowed to mis-compile it. On the store
side a compiler is allowed to temporarily store random values into
flags, on the reading side it's allowed to store the same value back
into flags (thus overwriting any concurrent updates). I can imagine
these code transformations can happen with profile-guided
optimizations (e.g. when profile says a concrete value is likely to be
stored, so compiler can speculatively store it and then rollback)
and/or when there is more code working with flags around after
inlining. At least it's very hard for me to be sure a compiler will
never do these transformations under any circumstances...

But having said that, making KCSAN ignore these patterns for now may
still be a reasonable next step.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbyVeY1qF3ba3vNrETiMk9x7ue6ezvYiP8hy2wWtk0L1g%40mail.gmail.com.
