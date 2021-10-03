Return-Path: <kasan-dev+bncBDW2JDUY5AORBP7E46FAMGQEVK3BBXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BD5A42033B
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Oct 2021 20:11:13 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id m26-20020a62a21a000000b0041361973ba7sf8075957pff.15
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Oct 2021 11:11:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633284672; cv=pass;
        d=google.com; s=arc-20160816;
        b=mhdpXx9/rxcOM0nqXAasEXuerqNMonzpquosbQZyXuvw5Lgh/ZtykDDuHEoQ7M5suQ
         rSrvpGBF6IZ6Ob0iVE0SLnEy1SsX4c4uXXM8/fPFuKos/CE6SYpzw/iME7b0TAjVTudn
         VRCNuh5a+8vTLM49nusT7iJyuKwvRNYSQjC/7nSCbRGA01zEfcuuNUEsUN/wyloriH36
         z5QjVqBK9Gx0KxE15JiqtEW9bisEkmv6ahK10TuGzlz5nP9BcCBlhuQHQFtyceamqJFD
         x1s6Kc83dDVZirJiirECUfVQq/8Gu37oRRcInOjG/7I/NHXNMytjIUDlqmXn2g6qZGA2
         oqcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=5NX3axgbpVgX7NXu8mH0MPrnNRoAqbFDIjDTB56ke6o=;
        b=MDrcnfB63FqS3suVPk5uQEPgEFde1aPTYaZYCbxPQP8pe+0BJEawe+fB5rW3WSq5aA
         kayAQnMgaug1BWGKIjKKC1mOMOyZwVPMaAn0SgqZten1sPRMcjL7cN8yCeZOLcQoFfMl
         tAdrfLTZSIC2F76sfDqvmFMooIVrCEwjdV35Gya1sdUFNAzAgfe5/l9o8uTPRpRrJrYp
         Iivp0w3iqhOwCweO2fBhdETqVFA5g63bRUQjhRFm3pVPr2ItqwE9vhFA9u65jN0RDh5q
         ExKIT2ZZHDuPctUQA8SyMTWQGByX53Wnbx0PvldkDYgHw62Xo1r8TVRc3h20SmD36xha
         57Qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=EBng0Dgq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5NX3axgbpVgX7NXu8mH0MPrnNRoAqbFDIjDTB56ke6o=;
        b=KcuEhuQmI1yG71lNF45DZ6Om/GwkKE+4mS4Pbr4WCVz6QyDj0MF/HLF8oI237MBwtC
         VRbam22C5w8hPaQ6incK7mef+87OOV6Rg5BLM46byQw+Rj9LLvjeOKs2bHj+CWD6ioRM
         yneI7GVI37QpYJu7uQ2Ti/SkoLbiqxRNmo0qf/F01H9dCtmsJlz5/rlDNBBCLns62bEh
         qKIGjLDtNmk2mNGotSg1rG8XiiPCgTEcNFuglmGS9fy+vYnUg3obqhM+78Zl+8QtO4Ly
         jI66vgYps0jamn43mIIH+XS6lnaIBZPs6EASUtGHcjWVPcskurCs0hxdezc9HKJgqhKE
         Ad8g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5NX3axgbpVgX7NXu8mH0MPrnNRoAqbFDIjDTB56ke6o=;
        b=DyU0lTtwtwXopKD4AaQZuFy9/xt1GKcSpNWGahlcqgZgdXK93jIx/TpwdQviNnAXLg
         FMK5POoNE2xb5o9MpcLfySl3TDJ3VqhqR//imhPbBalila4L9LHalGLmX1QpXIlk7rfn
         6Bkl+T1rEgLUx5bpcQOTZQ92orXF2vFqh9Z8JcGtTwOJpxB3lkd5eQQ741fAHO2h09Hm
         ovmgN1Ccf00/Zyiv1dy2+bhYw4BZSvzsvyJPhwZ3wtsS4tH6GamV46AdByGQM9bdwyuV
         Krvo+sSeNvx2TorjFWYybce24qNWkCa0h13fm/O8LEl83fLfQ7lxfyeHqMTatY0OZAnU
         OW9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5NX3axgbpVgX7NXu8mH0MPrnNRoAqbFDIjDTB56ke6o=;
        b=Ls2WH+g1ypbefctDB//7i5i633xr9Ebk4PbTD1Nl4wagIdzUgTVgP/D565Ua/9F8eC
         H28nTBYAR0BXHTCZsWuR16KDhtBtiESg8ZEE0ue5QYh0jALDoS7yoxXXABCFKuwfoXoQ
         +45t3E/YcvSfoet/xLZewO2ed44WhVhaKc6uMwUHIh4mEfm6oTm4scoPtGz/1WVhEmHX
         xR2vn0JXqHI+zfEBgOEvUFJYfJpKTmhu6Qxt1kjvdxZ2+iLsYjv9BEyd2/21qgYpZUSp
         m4k/Losb3HHBaZ3k6GhdRrQ/JvEBzEEuADrNkqiIdfSaJ9VeKui6vilvanmaR7AHS15H
         tm7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531O9MzTu55vZyGtgM7M8D6l2p1tDQ2FoPBRwUKm7DuXps0t+HVI
	Krsw0ZxSGBpF78LlZNgt1fU=
X-Google-Smtp-Source: ABdhPJwM6kC5X2Uc+ox/9HPfldPhWXRQ4rlAdE90SKXNwrBjycxjqSzgryEE7rUwxhQAUAZ4NQyPtQ==
X-Received: by 2002:aa7:9739:0:b0:449:56c4:4268 with SMTP id k25-20020aa79739000000b0044956c44268mr20735489pfg.43.1633284671883;
        Sun, 03 Oct 2021 11:11:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a708:: with SMTP id w8ls8217404plq.6.gmail; Sun, 03
 Oct 2021 11:11:11 -0700 (PDT)
X-Received: by 2002:a17:90a:4290:: with SMTP id p16mr31899057pjg.112.1633284671355;
        Sun, 03 Oct 2021 11:11:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633284671; cv=none;
        d=google.com; s=arc-20160816;
        b=yO1dlzbbM33ll9wboSm8rD0g8xdgviLDrX2Zd8R51WZxE1WTthGtXaz04p5YzORYWV
         LQRVy2OG4jdo99COo68YBCdQkf/J3cd4fDyS0hsmHJia4zHDe7GP36JBwy8+InNsXGy8
         PtPDvnfHfnf1hzh+SMrABkETeaFiXtlu8PcPcB6fulXQBv2LQiPmkbgBHGpozy/+kG0v
         XZ9jTQhh5sXu0aIxIvq1JTaunhKdusu5doFUC4LcsvBsCCrx0aNpiCXoMn7HYgjYK3nv
         q4Fls6fmhsOd9d1aMPecdzlZhMijE96FSCISU5ASlcHGdZqogyac+H8JlXWAtImEkMDz
         AaBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=03zSPuwgcyuPWlzavMUzzry8631FQwG9HWEfh5JVqAo=;
        b=cSNQkYid4c9ilpjmdk9hZQk3GXXxHY4eGwySGC8lCUZgi+mIXPNfL+XNO1urw7/qO3
         Ogj715nFGLBLeE1rEwM166tVTMBhbKjxkwjCSWQdsHlpurKAJEByieQ+1ziv+wZ5gz7+
         7DgK7pTbjYkUspvAxINw3KxFESYM1u3uRI/U1c6kezYi0F3vux6otuYKYgyeWdyzF+BN
         wbCOoC/0MIWmS20PJUeLpSQHh/49yrl5QNd3O2uKQnP7Ptoo3Q4Uc6N6gzhPe8S73GQf
         qid+Qc494IzNL/6DkBC3FdkqMr7Z6FTZOxaak6Wx+xODxbvSTrb30EpEXLUd2GQpgncq
         I9ww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=EBng0Dgq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2e.google.com (mail-io1-xd2e.google.com. [2607:f8b0:4864:20::d2e])
        by gmr-mx.google.com with ESMTPS id v7si520419pjk.2.2021.10.03.11.11.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Oct 2021 11:11:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) client-ip=2607:f8b0:4864:20::d2e;
Received: by mail-io1-xd2e.google.com with SMTP id s20so17702816ioa.4
        for <kasan-dev@googlegroups.com>; Sun, 03 Oct 2021 11:11:11 -0700 (PDT)
X-Received: by 2002:a05:6638:16c5:: with SMTP id g5mr7675904jat.130.1633284670747;
 Sun, 03 Oct 2021 11:11:10 -0700 (PDT)
MIME-Version: 1.0
References: <20210923164741.1859522-1-bigeasy@linutronix.de>
In-Reply-To: <20210923164741.1859522-1-bigeasy@linutronix.de>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 3 Oct 2021 20:11:00 +0200
Message-ID: <CA+fCnZcJ4YeTR6ZRZUrr0NYWZC+OVpUKdnHg-Tjf_DCG0B1H3Q@mail.gmail.com>
Subject: Re: [PATCH v2 0/5] kcov: PREEMPT_RT fixup + misc
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Steven Rostedt <rostedt@goodmis.org>, Marco Elver <elver@google.com>, 
	Clark Williams <williams@redhat.com>, Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=EBng0Dgq;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Sep 23, 2021 at 6:47 PM Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
>
> This is a repost of my initial series [0] with collected tags.
>
> The last patch in series is follow-up to address the PREEMPT_RT issue
> within in kcov reported by Clark [1].
> Patches 1-3 are smaller things that I noticed while staring at it.
> Patch 4 is small change which makes replacement in #5 simpler / more
> obvious.
> I tested this with the snippets in examples, Marco Elver used to run syzkaller
> for a few hours.
>
> [0] https://lkml.kernel.org/r/20210830172627.267989-1-bigeasy@linutronix.de
> [1] https://lkml.kernel.org/r/20210809155909.333073de@theseus.lan
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

for the series.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcJ4YeTR6ZRZUrr0NYWZC%2BOVpUKdnHg-Tjf_DCG0B1H3Q%40mail.gmail.com.
