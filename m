Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW5HUGFAMGQENOPCIYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id DAC384111E5
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 11:26:52 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id r18-20020a056214069200b0037a291a6081sf181565699qvz.18
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 02:26:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632130011; cv=pass;
        d=google.com; s=arc-20160816;
        b=WcEkB+4ATepu4bHsXK6CDJuG3rIMQwpMizmiNydvXDbpv4+V1mE3zu/4TZM/SSTN0f
         9hLZc/Nb2YjmzI06BkFGONJ4ouNtRClVoN0GKoj3tJyCpxj9dojAClGFny7SBisHV7Dk
         nvk3dTegenRtA8oDlnVM0wO91Reqx7DqXSFBYtlDFBanavI9Gzdy12xidhj3nVZqQ6bI
         M62XhuGwjMHpRqaKv5Y0CfW+blNtjriehM2673zombWqsvoVVLBXqXaEhsrlhYQ/shri
         xL9O62FOsZifPii1/yVIqlt+rwDlsoRDEmV6hkiCoytqnegTa5OLgvmCaX7iP20u8a+j
         An9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hzkUY3SCLpg80KBvbEgUfvhHSzHBtNpGUkj2jj8Thdo=;
        b=DX+Jdd1jnwLZKLMaAiHtjC8AZAjJ+pQWonbZwe2tNTN3dX5mCXgIrpINGe5HxtoIUb
         ysEnLJiazdbL7CPH2Kj6SligmMdWYMDP4e1mG1bNKF55maGWDE9ooNkNnPnNCZQmrHz8
         w8OrOwuQNqOZAICTJKI7aRX2VnPuGDH/0TlCSCW8me136UvItXR66h3R5rwdOLsVsvTC
         g+5G7G1GTyk+fI/Cmep43n2waAvfnx9k6/6d2oiw6pt6LgR2Uy6ECV/i+ckMBMqhlxt4
         aaGq23wvFCp2GML4TVmgZtAWSCabWxN2G+ZJTuirTXP2x6Jd0ryRUgUftv7DeLk2xWOk
         Q7DA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JsmIateb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hzkUY3SCLpg80KBvbEgUfvhHSzHBtNpGUkj2jj8Thdo=;
        b=CWxRevOLeFWll08MDB5Ev7B81HzSFnxXIdKfeveZfGrHHhUPVHKVlCGmhxoxrXI9dr
         +zIf2SqMhXajbVsWYVLhfioGf7Yf05VYJQlQPhoRyko4qSPejr/VjNVARnZ90hLv2/tq
         JE/NOIWwxDy4Uxl4ZYfH/6Jpi+UCqnvBo6T9F21MVgT6kAm9vCmNLWY0z72KQt2SsAo8
         NZVuPWZqEKNYfIGprwWvcMd/nlWhty0rtk/rdt1xC3ZtkG4sxBzCdUet7HWXv99R4xIw
         GNawf7Zc6ER7VKn7OoP57XxdUSmBh/cSaDsr/q7yf/G5QJHNC1tHUGojiKN65Y4V7QFS
         2+aQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hzkUY3SCLpg80KBvbEgUfvhHSzHBtNpGUkj2jj8Thdo=;
        b=jhpz/CGLmwvSxuLR4BkHDkH0qf97+WA/LCxbFDJJ86N7SBozZ2XpSYLIukWYyzbRNg
         9jSk+7vfd9qUiIfsadNbOIiqWixYWYHPYKFeGmanH/2vuLHk1LhnSCa8j6oTdPGewbM1
         GcMCbCB4M+PNFf2n7p7s0nq2IxImuh8Wbo4XzEwvIkLYIEngfQk71L8bpHKUAAyen9cM
         irdYJSrK8TgWOWOPz/9/lA/NqSxqbAl8+ivHXUGCaNKscAjD41Ze2nJAi87/Ky3FWa4n
         Zd+ethupFhss6WAWR8VuvaWR4P+HibT7LmfmwOJbIsTgY5eXP8a1k2u5rS7SO4Svc6du
         xOXw==
X-Gm-Message-State: AOAM531rHxzK2L04/saLbC0zLoOvp9s9FFD9vAgKHGxLj98Fj4oGiodX
	rrWvmGZL0nWS816P1UYvbmY=
X-Google-Smtp-Source: ABdhPJwRcbesysQ7MjmxzwsmHWp75a/sDfEnpkJcN8v7yJy9X1smOc6/BF0BOdifwjKxJlUifnu9og==
X-Received: by 2002:a05:622a:151:: with SMTP id v17mr4887549qtw.325.1632130011536;
        Mon, 20 Sep 2021 02:26:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1582:: with SMTP id d2ls18568499qkk.9.gmail; Mon,
 20 Sep 2021 02:26:51 -0700 (PDT)
X-Received: by 2002:a37:6215:: with SMTP id w21mr9892407qkb.354.1632130011100;
        Mon, 20 Sep 2021 02:26:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632130011; cv=none;
        d=google.com; s=arc-20160816;
        b=oiAqWp79U8NCTPm3QYcOFRcTQxPWR3/tLEskUWCxpkDbcsdZ8NZi0LsVmf8zzdTbtb
         KU9TjfCoXGUudq6MyKHt+F5Qd1/7i5XxQJjgM7PVVQ458c8Ci+DQJPRyMS0woqVJaogR
         6p9tzYdoTEKXSujdQ5ecKA5W3RQVZSm0QamDWvTRwNC7F4p9gHyL4Uvk2ibQRSk4XGl7
         NNxrZGr5esW5foAuPW2mFOq349W1UZ0n9PFT+I+bXavgv2wQN1PYTqzDI8M1VdKS9VpF
         jPHSjIwuLY4v7N1Y4mFW5BY0YAFD9bgDC0wqoO12MTfnfwDrCeevMKKkffP2ht/wtrbS
         k5xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ztJqpqKIFJVTKg15+ChKCf+OE4ZJoAKdKeksq77RwyY=;
        b=r+H4sfcBuOI02/oyG86qxhf0+bDbN2/lxtuYWikdDUqAZbA8+6HWqwZgDXJ0zd0OMq
         hR1F2fRQufwWiK/1QG/PUsgZhT8mwF9JgBu/Fj6h5XX8CpIYXiApXWr/DUDLfczNBZNT
         STx3H2KZfYwfXeGMStWbWRb7SHc6gtsQOo99q1k8ZSA2vOKE7z8fbNq0dhs3cvMw3Veo
         nO4YdMVqmbomnOJF0jpwVk+684SUOVZo7hDhONbTT+qtY6+bNEaMtEywax3eQNUkZ9mb
         HqSk4coAkJjg2QH+Z/SsO/9gmx4erYeNnOTbHQOOP45GXvyGGyaOVlfBOOgWrFIUgcLA
         5kMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JsmIateb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32f.google.com (mail-ot1-x32f.google.com. [2607:f8b0:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id n27si1208545qtl.4.2021.09.20.02.26.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Sep 2021 02:26:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) client-ip=2607:f8b0:4864:20::32f;
Received: by mail-ot1-x32f.google.com with SMTP id c42-20020a05683034aa00b0051f4b99c40cso22779035otu.0
        for <kasan-dev@googlegroups.com>; Mon, 20 Sep 2021 02:26:51 -0700 (PDT)
X-Received: by 2002:a9d:20aa:: with SMTP id x39mr1794305ota.292.1632130010114;
 Mon, 20 Sep 2021 02:26:50 -0700 (PDT)
MIME-Version: 1.0
References: <20210830172627.267989-1-bigeasy@linutronix.de>
 <CANpmjNPZMVkr5BpywHTY_m+ndLTeWrMLTog=yGG=VLg_miqUvQ@mail.gmail.com> <20210906162824.3s7tmdqah5i7jnou@linutronix.de>
In-Reply-To: <20210906162824.3s7tmdqah5i7jnou@linutronix.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Sep 2021 11:26:38 +0200
Message-ID: <CANpmjNPn5rS7MyoDtzJNbs9Gxo=26H_z7CX4UDQcwLRtJfZa6A@mail.gmail.com>
Subject: Re: [PATCH 0/5] kcov: PREEMPT_RT fixup + misc
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Steven Rostedt <rostedt@goodmis.org>, 
	Clark Williams <williams@redhat.com>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JsmIateb;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as
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

On Mon, 6 Sept 2021 at 18:28, Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
> On 2021-09-06 18:13:11 [+0200], Marco Elver wrote:
> > Thanks for sorting this out. Given syzkaller is exercising all of
> > KCOV's feature, I let syzkaller run for a few hours with PROVE_LOCKING
> > (and PROVE_RAW_LOCK_NESTING) on, and looks fine:
> >
> >     Acked-by: Marco Elver <elver@google.com>
> >     Tested-by: Marco Elver <elver@google.com>
>
> awesome.
>
> > > One thing I noticed and have no idea if this is right or not:
> > > The code seems to mix long and uint64_t for the reported instruction
> > > pointer / position in the buffer. For instance
> > > __sanitizer_cov_trace_pc() refers to a 64bit pointer (in the comment)
> > > while the area pointer itself is (long *). The problematic part is that
> > > a 32bit application on a 64bit pointer will expect a four byte pointer
> > > while kernel uses an eight byte pointer.
> >
> > I think the code is consistent in using 'unsigned long' for writing
> > regular pos/IP (except write_comp_data(), which has a comment about
> > it). The mentions of 64-bit in comments might be inaccurate though.
> > But I think it's working as expected:
> >
> > - on 64-bit kernels, pos/IP can be up to 64-bit;
> > - on 32-bit kernels, pos/IP can only be up to 32-bit.
> >
> > User space necessarily has to know about the bit-ness of its kernel,
> > because the coverage information is entirely dependent on the kernel
> > image. I think the examples in documentation weren't exhaustive in
> > this regard. At least that's my take -- Dmitry or Andrey would know
> > for sure (Dmitry is currently on vacation, but hopefully can clarify
> > next week).

Just for reference, this is what syzkaller does which confirms the above:
https://github.com/google/syzkaller/blob/3d9c9a2ac29573a117cde8ace07d0749eeda991b/executor/executor_linux.h#L84

> okay.

I saw Dmitry responded with Acks/comment. Did you have a tree in mind
to take it through? Usually KCOV changes go through the -mm tree, in
which case please Cc Andrew in the rest of the series.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPn5rS7MyoDtzJNbs9Gxo%3D26H_z7CX4UDQcwLRtJfZa6A%40mail.gmail.com.
