Return-Path: <kasan-dev+bncBDR4DG4XUQGRBXFX2CGAMGQEDXO5IFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id C255E453B5D
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 22:00:12 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id g81-20020a1c9d54000000b003330e488323sf1046549wme.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 13:00:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637096412; cv=pass;
        d=google.com; s=arc-20160816;
        b=bjRR3bc2rpBDZpag+a0oCTPQrMYhwhBxL2EW/cUpLcIu4lh0llnJLb6yShlTklC66z
         a/LNy6NoKU7MuAUa3MCNdAzcy0YIhUZJUF3MORQ9a2MkgdGC+Bzjcg1fSXMnfGGGBs5C
         QE8SKwu05FExsCFbY/mY2ufl/LyluaUhj0Ja0cXl6UuhNDxQyTYvby9u5Y3mT696cCpR
         Pp2pxX3PBo1Wski7mpoZfwY3/Bmbyk/3BRk42RsaXaFWzIF+ECBzkfoyetmEtKYtk/IZ
         qlrtFJCiI1FeouQlsjkVdPWJrfEOoOFi1Pcvlvyyqvk5lsWZaoYo/6r19kaykTokpAZC
         F+dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZNzqvm11cI5YFuWfpu9BaIe6Alu7FhccxeEjCbokUOs=;
        b=kqo9XMTR+NW2rxrPtLabt2UYzZfpSwXpaIpymz7oE4Tob0aBBUQVZNzQZj0WUCbDI+
         pyiI1BXRGuNOLF/+rS18RMXUzz0dvXPRw19GVZQHO7A15Lhr+55JixZotp0RdrOIJ6tX
         Q0JxABqszeWxgdQhd1n+sLCh3ahTQtCnH1blOpFFsuLcHtL2y3vXZObA4WpjReGvvnR2
         COT3B3DLOc8GLNyBwlL0qYPh3w1ModvoHlLB+CfhI4dSo/I13ytDmNsfzo8nhyIePhq5
         JnAhsws/MThbi3HXPL6Gh2Wy4WePEgqsCVFTsU1koMdsktRdlAbkuhgJlCFZ7PGJU2Dp
         knVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rmlE9LF9;
       spf=pass (google.com: domain of shakeelb@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=shakeelb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZNzqvm11cI5YFuWfpu9BaIe6Alu7FhccxeEjCbokUOs=;
        b=YWVnFKcu/w57BJke4dfMR3OlDjuOljIfbknyYggtcvlr997GAy0vOilG2J5v3SjhYX
         3FScYFlP0yzYF9P1+2MBKgpgG04I5DAnvj5PoQqOGmtvntpH+6eNFG0x4B8uMWIbY7oB
         uSjYKTHsKcQMZWjiMvb6XY5zadWt9UB5fKjxJD1vwV5VzlSrYSwpnCVeJgO1vRS3TAhw
         nu6iFSmCmx/rX6elo/EDzHPfRZABTV+MijuFGkDEjAz3IxLp29e6hEIvuKPNBPSlvSAO
         5auvERu9EVbf2uWSEHdq1YLMB+5ETEVmHmRp2vBJd71mI5y9r6EWDiYnvaGZ9GzIBe+r
         34IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZNzqvm11cI5YFuWfpu9BaIe6Alu7FhccxeEjCbokUOs=;
        b=GDB76QuEbHwkyZXUFVptLvwT045EH2ByTKuUszIQekGl+9sXHepLnjd/jWwgatt2E+
         NenRDTs/HjXIhatd2Uv8UWDGz8aXMaenlbOqzltfz/NJ55O6fyrH/dYpibIzG0nr4wDz
         MfN3Pv2Ug2hDMAw8e1L+tzM/p/mjKAyL8711ixnkoPmtQ6g8zeAW3ZDcpj9jB890u0Cb
         nslB5i/4EllBPLXx5+irNuM4VoqIYeKSnIVD0C+ehR+1bn5s3IIqVao+rJSnI6PfbEwL
         v42arneB00nxp1of7IHecWORXEoW1fPhVqQd3kyAa1VLsoF5D0SqsugSwRkg23dpZIqG
         OAPA==
X-Gm-Message-State: AOAM531Y4yZJw+Dp/Rd3qGLwp2BpAOZnYnRtwsduttYOu/H7LbpsmQRr
	3xXK9roswFyGzH5w2YB/IWQ=
X-Google-Smtp-Source: ABdhPJwUxAyTm0xryX4EULBHLYxDTYmTrUz0OcdgS9nGv4ddRd2CmfZYr9M42+bRpqyvIlfsL3RquQ==
X-Received: by 2002:a5d:4563:: with SMTP id a3mr13467147wrc.130.1637096412519;
        Tue, 16 Nov 2021 13:00:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1943:: with SMTP id 64ls1743308wmz.0.gmail; Tue, 16 Nov
 2021 13:00:11 -0800 (PST)
X-Received: by 2002:a05:600c:3ba5:: with SMTP id n37mr72352784wms.168.1637096411502;
        Tue, 16 Nov 2021 13:00:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637096411; cv=none;
        d=google.com; s=arc-20160816;
        b=qbJ4VS1rpb6WB9dmVwACMP6MnWtWtB97iSJXLbhlof8880lOukgA2dEX8vWYtgIN3A
         EXsQLoJ9BGSGbjrqmBu8enuoUhMyi2h6ykVI+MToDQxzyW2S55vzQkz9X1T5TQBfvELx
         xM0EO6pWtY3eNe2fAtedTHWSk0/UZgbb3hvslRvCV499PPyNSLq55ajrN+0yJmawAMKD
         yIGqq9FEU99eBRDnDBtgL8rydhv7iqmVxsZXCcl0zHIvkuHh7+gj3mXxMqUDQnr/xzPl
         yYDoAJlVHCeqzSNJnrzul7ll4oveDFuRdeuuVGlZ7BDuOUm5dy6TtP1prGix5t5MGHYG
         lLsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4ho2YimSshTIlWxN1DU+R1DWkXdd3pS7JkTLwXCA0Rw=;
        b=AeDpqG1nSeahhq5ozsHfao+/Owk1XShTLK0SsrqCv0AAuyW+VzLzK/QZLdSFb9x/Pl
         GfNKgtroP546dZtXV+cjrXNEaRhJ/nMvfF2HIQlsibq3r/pQzA/fKEtN2/mO+MBrCQ5w
         TlhQCiEeDE/2HAjcjfTtUelX5PP+2uyxTI9I8deGaH9S/in6W/ua8CY4jbN2vLI0fAF1
         KkK6GDrnMMUlHw+tJSo5lp0mq5OE8ogysrAQPGXYCxsPXSfxxoGAnIHPMRrYDYrR/hNT
         lC72ulcuKf3l4+sZvhNo6YLw9rGpCfqCkYh0L5+00meb1+f2fot0iBf6zQCk6R4ipCgA
         PdQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rmlE9LF9;
       spf=pass (google.com: domain of shakeelb@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=shakeelb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id p11si249733wms.3.2021.11.16.13.00.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 13:00:11 -0800 (PST)
Received-SPF: pass (google.com: domain of shakeelb@google.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id bi37so954839lfb.5
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 13:00:11 -0800 (PST)
X-Received: by 2002:a05:6512:5c2:: with SMTP id o2mr9476625lfo.8.1637096410679;
 Tue, 16 Nov 2021 13:00:10 -0800 (PST)
MIME-Version: 1.0
References: <20211111015037.4092956-1-almasrymina@google.com>
 <CAMZfGtWj5LU0ygDpH9B58R48kM8w3tnowQDD53VNMifSs5uvig@mail.gmail.com>
 <cfa5a07d-1a2a-abee-ef8c-63c5480af23d@oracle.com> <CAMZfGtVjrMC1+fm6JjQfwFHeZN3dcddaAogZsHFEtL4HJyhYUw@mail.gmail.com>
 <CAHS8izPjJRf50yAtB0iZmVBi1LNKVHGmLb6ayx7U2+j8fzSgJA@mail.gmail.com>
 <CALvZod7VPD1rn6E9_1q6VzvXQeHDeE=zPRpr9dBcj5iGPTGKfA@mail.gmail.com>
 <CAMZfGtWJGqbji3OexrGi-uuZ6_LzdUs0q9Vd66SwH93_nfLJLA@mail.gmail.com>
 <6887a91a-9ec8-e06e-4507-b2dff701a147@oracle.com> <CAHS8izP3aOZ6MOOH-eMQ2HzJy2Y8B6NYY-FfJiyoKLGu7_OoJA@mail.gmail.com>
 <CALvZod7UEo100GLg+HW-CG6rp7gPJhdjYtcPfzaPMS7Yxa=ZPA@mail.gmail.com>
 <YZOeUAk8jqO7uiLd@elver.google.com> <CAHS8izPV20pD8nKEsnEYicaCKLH7A+QTYphWRrtTqcppzoQAWg@mail.gmail.com>
In-Reply-To: <CAHS8izPV20pD8nKEsnEYicaCKLH7A+QTYphWRrtTqcppzoQAWg@mail.gmail.com>
From: "'Shakeel Butt' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Nov 2021 12:59:58 -0800
Message-ID: <CALvZod6zGa15CDQTp+QOGLUi=ap_Ljx9-L5+S6w84U6xTTdpww@mail.gmail.com>
Subject: Re: [PATCH v6] hugetlb: Add hugetlb.*.numa_stat file
To: Mina Almasry <almasrymina@google.com>
Cc: Marco Elver <elver@google.com>, paulmck@kernel.org, 
	Mike Kravetz <mike.kravetz@oracle.com>, Muchun Song <songmuchun@bytedance.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Shuah Khan <shuah@kernel.org>, 
	Miaohe Lin <linmiaohe@huawei.com>, Oscar Salvador <osalvador@suse.de>, Michal Hocko <mhocko@suse.com>, 
	David Rientjes <rientjes@google.com>, Jue Wang <juew@google.com>, Yang Yao <ygyao@google.com>, 
	Joanna Li <joannali@google.com>, Cannon Matthews <cannonmatthews@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: shakeelb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rmlE9LF9;       spf=pass
 (google.com: domain of shakeelb@google.com designates 2a00:1450:4864:20::133
 as permitted sender) smtp.mailfrom=shakeelb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Shakeel Butt <shakeelb@google.com>
Reply-To: Shakeel Butt <shakeelb@google.com>
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

On Tue, Nov 16, 2021 at 12:48 PM Mina Almasry <almasrymina@google.com> wrote:
>
> On Tue, Nov 16, 2021 at 4:04 AM Marco Elver <elver@google.com> wrote:
> >
> > On Mon, Nov 15, 2021 at 11:59AM -0800, Shakeel Butt wrote:
> > > On Mon, Nov 15, 2021 at 10:55 AM Mina Almasry <almasrymina@google.com> wrote:
> > [...]
> > > > Sorry I'm still a bit confused. READ_ONCE/WRITE_ONCE isn't documented
> > > > to provide atomicity to the write or read, just prevents the compiler
> > > > from re-ordering them. Is there something I'm missing, or is the
> > > > suggestion to add READ_ONCE/WRITE_ONCE simply to supress the KCSAN
> > > > warnings?
> >
> > It's actually the opposite: READ_ONCE/WRITE_ONCE provide very little
> > ordering (modulo dependencies) guarantees, which includes ordering by
> > compiler, but are supposed to provide atomicity (when used with properly
> > aligned types up to word size [1]; see __READ_ONCE for non-atomic
> > variant).
> >
> > Some more background...
> >
> > The warnings that KCSAN tells you about are "data races", which occur
> > when you have conflicting concurrent accesses, one of which is "plain"
> > and at least one write. I think [2] provides a reasonable summary of
> > data races and why we should care.
> >
> > For Linux, our own memory model (LKMM) documents this [3], and says that
> > as long as concurrent operations are marked (non-plain; e.g. *ONCE),
> > there won't be any data races.
> >
> > There are multiple reasons why data races are undesirable, one of which
> > is to avoid bad compiler transformations [4], because compilers are
> > oblivious to concurrency otherwise.
> >
> > Why do marked operations avoid data races and prevent miscompiles?
> > Among other things, because they should be executed atomically. If they
> > weren't a lot of code would be buggy (there had been cases where the old
> > READ_ONCE could be used on data larger than word size, which certainly
> > weren't atomic, but this is no longer possible).
> >
> > [1] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/asm-generic/rwonce.h#n35
> > [2] https://lwn.net/Articles/816850/#Why%20should%20we%20care%20about%20data%20races?
> > [3] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/explanation.txt#n1920
> > [4] https://lwn.net/Articles/793253/
> >
> > Some rules of thumb when to use which marking:
> > https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/access-marking.txt
> >
> > In an ideal world, we'd have all intentionally concurrent accesses
> > marked. As-is, KCSAN will find:
> >
> > A. Data race, where failure due to current compilers is unlikely
> >    (supposedly "benign"); merely marking the accesses appropriately is
> >    sufficient. Finding a crash for these will require a miscompilation,
> >    but otherwise look "benign" at the C-language level.
> >
> > B. Race-condition bugs where the bug manifests as a data race, too --
> >    simply marking things doesn't fix the problem. These are the types of
> >    bugs where a data race would point out a more severe issue.
> >
> > Right now we have way too much of type (A), which means looking for (B)
> > requires patience.
> >
> > > +Paul & Marco
> > >
> > > Let's ask the experts.
> > >
> > > We have a "unsigned long usage" variable that is updated within a lock
> > > (hugetlb_lock) but is read without the lock.
> > >
> > > Q1) I think KCSAN will complain about it and READ_ONCE() in the
> > > unlocked read path should be good enough to silent KCSAN. So, the
> > > question is should we still use WRITE_ONCE() as well for usage within
> > > hugetlb_lock?
> >
> > KCSAN's default config will forgive the lack of WRITE_ONCE().
> > Technically it's still a data race (which KCSAN can find with a config
> > change), but can be forgiven because compilers are less likely to cause
> > trouble for writes (background: https://lwn.net/Articles/816854/ bit
> > about "Unmarked writes (aligned and up to word size)...").
> >
> > I would mark both if feasible, as it clearly documents the fact the
> > write can be read concurrently.
> >
> > > Q2) Second question is more about 64 bit archs breaking a 64 bit write
> > > into two 32 bit writes. Is this a real issue? If yes, then the
> > > combination of READ_ONCE()/WRITE_ONCE() are good enough for the given
> > > use-case?
> >
> > Per above, probably unlikely, but allowed. WRITE_ONCE should prevent it,
> > and at least relieve you to not worry about it (and shift the burden to
> > WRITE_ONCE's implementation).
> >
>
> Thank you very much for the detailed response. I can add READ_ONCE()
> at the no-lock read site, that is no issue.
>
> However, for the writes that happen while holding the lock, the write
> is like so:
> +               h_cg->nodeinfo[page_to_nid(page)]->usage[idx] += nr_pages;
>
> And like so:
> +               h_cg->nodeinfo[page_to_nid(page)]->usage[idx] -= nr_pages;
>
> I.e. they are increments/decrements. Sorry if I missed it but I can't
> find an INC_ONCE(), and it seems wrong to me to do something like:
>
> +               WRITE_ONCE(h_cg->nodeinfo[page_to_nid(page)]->usage[idx],
> +
> h_cg->nodeinfo[page_to_nid(page)] + nr_pages);
>
> I know we're holding a lock anyway so there is no race, but to the
> casual reader this looks wrong as there is a race between the fetch of
> the value and the WRITE_ONCE(). What to do here? Seems to me the most
> reasonable thing to do is just READ_ONCE() and leave the write plain?
>
>

How about atomic_long_t?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALvZod6zGa15CDQTp%2BQOGLUi%3Dap_Ljx9-L5%2BS6w84U6xTTdpww%40mail.gmail.com.
