Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTHS52EAMGQEERTKMWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id AD0383EED56
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Aug 2021 15:27:41 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id q40-20020a9f386b000000b002ac424902b9sf198706uad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Aug 2021 06:27:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629206860; cv=pass;
        d=google.com; s=arc-20160816;
        b=v/tVlhgF2q8G/5sxqi2zSsPCaJVHqk6PYXxlhlUabvdcf8dTjYJz+vPndSfvrdEgZC
         XkwW19YLjVzPCQnyOVG7mYCQvc+iBKFSr37VxE2xOZgAkrufAu06TMXsKGJXaVyVFmWT
         UxyHIjQB56wIJYBQ/H6oytXNngpfyW47jE+gbFkPEDBglThOhHZc19SajT0qubNFpWOB
         KWaBos3i63lsu580HOGOOupuZYIbuLmNSOP1AaZvEMJEd8h7fenShXbwLne+NTfjon4G
         /VeVjdMu9V4+xdKWvqV04haGoPRnMkElz04aiyYWuSD2TKMyP3zG82r6c923yL7R6VIs
         x2CA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uVSGEfnkniiEpsfSFeayGwfFVdB10elJqYLpE+NtG38=;
        b=sXSzjoBOkpFSwoWG9aKvvHqlNTUE+4th4djqEJKW6y0DVuGMPrTLFJ+oybo/TSvmOD
         uLHqr3cpnx/3Wq4nZ5c3kkSjiX5de3uB0X2C6Lu1rcmh42m5u08xwE/H/TtiEH0G+fmg
         qTVQkku6wetwrydChw6cAgorC1Jg+WVfTqK70naSBRJuTIuOkaYdruK2ASuQcdRZDDhT
         Q6haDyVDnG+i38D9xgOa4ptneEYESKjgCoHuXBMteWaYCakcSdstKujAv9z4D6LZ0PoT
         nd8K+zPlWJ8+9okpSEepO95/CemNjcz+u7WIdLIe2YdHVgM69rFcnURdLNAql/OaMPaJ
         ONaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dg9OG94A;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uVSGEfnkniiEpsfSFeayGwfFVdB10elJqYLpE+NtG38=;
        b=iGIMGZWf6Yxu7236pK/lIqZcvbHYhDnLcDJSEuVz14HXeTCnQgxl9Lkk4G50AI7I7L
         3jLgVGQs9XuQESZZ34Fpz9KZRs/dtKWD46MwCojX0jmqV3woahY0QECUs0UZR8+09flB
         PFhdea7H0lX54lr+vbdUlquQ6vVN1hlPgXHK1hm+jXwYGk0apOGa0MLZ+o47IxRD2YUS
         EMOuq0sKwuT+sBa2k1QJGs9wloMc9K6jZfmAlbVwvtYv+VWuBk2DkDqBEsbt+a+jlIuW
         pgF2tdutXMmaoC3/UGQlmN4y2NJV1Vw5NHQ9QA+F2v8fjPtN6PMqLdUOX1PZOOq7MKRt
         VWkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uVSGEfnkniiEpsfSFeayGwfFVdB10elJqYLpE+NtG38=;
        b=NFipLWE6zE7dGBJZB6NgKcuvWFZ/g4YeGJGYx39MwammZ69cDVEVhBlmhtmKXJxK9X
         fm3CrL6bE7bCyTj1q4pPasVQ4rbDWDKOKhuLrlLoKdnGkaoVdYM1f2waC2LvA8ZzMwXI
         EUml83hPT5PO6vVQtUiVyqCmxm5An2DY0CYVcNKJLqqzuuMD3cGzPKXghtsNDoMWMZT7
         jeziKLx8NXQ4J8vrJzYX7BAvnRlWaRql1e/dUl/GMXxvJFW8QkISeXoUDJj6KjwXVtu1
         VU93745eNBz7WywMdqy+0IB0HQkFVgX4EUplNhNUgBnNuW/9KEA1zLOgAVJfjA9wKPI6
         UZhg==
X-Gm-Message-State: AOAM531bTfFatI6oc5mwtJ+q8cLy+ZRV3QpsoTDMdP/11K5fWVuNx5mw
	zAcqIv2jnJ8gce5cwN5LHNQ=
X-Google-Smtp-Source: ABdhPJw+9I0CgeRcozPnWrWZ7VFZuw3jq2KUcrVv+uniLMk3kJDoHCAlFRUXdztdSl6EqyZtLz8gxw==
X-Received: by 2002:ab0:14b:: with SMTP id 69mr2250651uak.116.1629206860615;
        Tue, 17 Aug 2021 06:27:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c89a:: with SMTP id v26ls367308vsk.0.gmail; Tue, 17 Aug
 2021 06:27:40 -0700 (PDT)
X-Received: by 2002:a67:1d07:: with SMTP id d7mr2462467vsd.25.1629206855916;
        Tue, 17 Aug 2021 06:27:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629206855; cv=none;
        d=google.com; s=arc-20160816;
        b=R06Rbljw9TJkW0qhDEfKvR8Z9wzU3wGb4TeHWI+QupP4s9ILcacM22iTkjVw7gSx39
         0fb4SPbtKdEAcvmf16kjqlrazdYeOigNWRynxP93Mbfs5b6mbWcx/J1Vh1/y/lCt2lmi
         QKEW/lo2hJB6P+WCjDoYECAI1rx6j6VZLJSkJ82LpQ/kVsOcfR8A/56RsYahyoQn/jDB
         TiWvxbTfVUShmX7KRhYNUKvYlGSDWuVHjloYxfdLPeeWnEw9BGHu+oGoxs1DPyjIR105
         0MwtjdlB+kihv62XtbQg/+Tm6OACrLBio1giObfd+uBBfarB9GgDuEtTgatUdO3qM6FF
         Hw6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zWHDjIJawTHtbmwaJcKwdk8W++TJIaWlzkrKoGu1IaU=;
        b=fL89lyMbMQ8+6pw23Sd17UqiXzcH1RBTrEquX9GDw2EW4ISXLQcGK39fl08VfLwxnl
         XXzWHCdJExhJ02HL4MOZNlU8jkWFZDOLceI7chq513OFRZP3hswoXyaQLSZbR/OSLeuh
         h/MSTfBBazlZd+UBG4v0muTVebscUiUhJYZ7MikezSpxc8NggPYDD7IWhW+02VFdED6F
         Grn3lFjnTzjPrr5PSX1f5rkA4xhYXip4GqzyPd82x9iXZj7JNomAw4sm5x8F6XQmsP9S
         j797z0JL6QY8QzJxgAgILxwBhe6GSZfcpNOSrggCBrBjZCwG0Le+LizVxspbjgfav1J3
         BotQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dg9OG94A;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x334.google.com (mail-ot1-x334.google.com. [2607:f8b0:4864:20::334])
        by gmr-mx.google.com with ESMTPS id c5si103146vkg.4.2021.08.17.06.27.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Aug 2021 06:27:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) client-ip=2607:f8b0:4864:20::334;
Received: by mail-ot1-x334.google.com with SMTP id c19-20020a9d6153000000b0051829acbfc7so10011910otk.9
        for <kasan-dev@googlegroups.com>; Tue, 17 Aug 2021 06:27:35 -0700 (PDT)
X-Received: by 2002:a9d:d04:: with SMTP id 4mr2775588oti.251.1629206855297;
 Tue, 17 Aug 2021 06:27:35 -0700 (PDT)
MIME-Version: 1.0
References: <YRo58c+JGOvec7tc@elver.google.com> <20210816145945.GB121345@rowland.harvard.edu>
 <YRqfJz/lpUaZpxq7@elver.google.com> <20210816192109.GC121345@rowland.harvard.edu>
 <20210816205057.GN4126399@paulmck-ThinkPad-P17-Gen-1> <20210817122816.GA12746@willie-the-truck>
In-Reply-To: <20210817122816.GA12746@willie-the-truck>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 17 Aug 2021 15:27:23 +0200
Message-ID: <CANpmjNMZxiyFbua2ck=0u7cJnHhtG4RY=Db=ry3COEED_sm7Xw@mail.gmail.com>
Subject: Re: LKMM: Read dependencies of writes ordered by dma_wmb()?
To: Will Deacon <will@kernel.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alan Stern <stern@rowland.harvard.edu>, 
	Boqun Feng <boqun.feng@gmail.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dg9OG94A;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as
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

On Tue, 17 Aug 2021 at 14:28, Will Deacon <will@kernel.org> wrote:
> Just on this bit...
>
> On Mon, Aug 16, 2021 at 01:50:57PM -0700, Paul E. McKenney wrote:
> > 5.    The dma_mb(), dma_rmb(), and dma_wmb() appear to be specific
> >       to ARMv8.
>
> These are useful on other architectures too! IIRC, they were added by x86 in
> the first place. They're designed to be used with dma_alloc_coherent()
> allocations where you're sharing something like a ring buffer with a device
> and they guarantee accesses won't be reordered before they become visible
> to the device. They _also_ provide the same ordering to other CPUs.

Ah, good you pointed it out again. Re-reading memory-barriers.txt and
it does also say these provide order for other CPUs...

> I gave a talk at LPC about some of this, which might help (or might make
> things worse...):
>
> https://www.youtube.com/watch?v=i6DayghhA8Q

Nice, thank you!

> Ignore the bits about mmiowb() as we got rid of that.
>
> Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMZxiyFbua2ck%3D0u7cJnHhtG4RY%3DDb%3Dry3COEED_sm7Xw%40mail.gmail.com.
