Return-Path: <kasan-dev+bncBC2OFAOUZYGBB66Q2CGAMGQEH4DGKCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B813453BF8
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 22:54:05 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id d7-20020a17090a7bc700b001a6ebe3f9cbsf1204437pjl.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 13:54:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637099643; cv=pass;
        d=google.com; s=arc-20160816;
        b=XAGFd4FOUqYCRQcDO8xpTkk7HOaQ2YU1J2kCspSDyQPFxWl7drKzAToI9pMKIFtRCI
         cT01uLyLi4z3u1LjVVbcZYBAXZZ264Kq7lEkzEDaJ4rT27ATdY9jYF9uGceOE9xeleEM
         pOYgYCwvKwq3D8kqcdUslFIuenFG+UFXpYCa1eHUD/Dw0Gal6gi+YGgmf5DyTv4mrUad
         rPmSZMt2y78oZS85FrEazX54Zl6gKEvAs0RNddNN4lIBw0njaXvs1GvMUaz9Q3jJfSuO
         MfiFSBhFGjIXsXrY72BogFPENySIeUMoMcSMjCynnaBo7QXkndzRhcwkNfd9sbVu3TSI
         33Yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=x8npC8BzcqD+JyTD3AyjZz04PRjuW1jwqLxFuydonlM=;
        b=CXEx3NfO751WphgSikcosrnRbM1o4jPEYZX7W0yMgF9x226WCbLQpuLpi6wlzfiIu4
         oYNbnDwTa5dYCNPEB8S+kk17ZSTQ5bPuJb2fPDMo1dvlTk2USzLiiTwV7gGCjNeUb30a
         r3Y2Jr1txoIgmBm3DROwDGPFshUCeFeov+QJBcXSEgiX/qsTvPx+4o8hHi51vdrjjOf3
         a1cY6wx6O0KvsY5Ph+08/cMoPhRsa+XxKdud09ruo9WGZfx7A+8EyGEykakiCnQc3vvE
         iIqA8g18lXhiqKMcjCT2X9w8VvGTDhOAMMNef47Bxf1VK1DYCUN2bmB3Pd5kqnMm0fzb
         QN7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=J14Gg3v0;
       spf=pass (google.com: domain of almasrymina@google.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=almasrymina@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x8npC8BzcqD+JyTD3AyjZz04PRjuW1jwqLxFuydonlM=;
        b=R716a1VTcp0Rms0TFY26jwtYEvrWMc/MnMCTZyhhEER66QZ8XzvxaA5KmhYmSdpu2g
         /d/yRV0p7yQ+gGXqxiOvXFWvn9ekHFh9cwBqSpxyK2nhBm3/i9cNQ61gMxVs0Mccfo9y
         lhJBd+yuXfHhRspB9FabyguydjO9oFQuWntRP1HbBemlP7d/rLHxZ0DOxfSftGe+gpKR
         0JDGX6Fh3jirPUYoqprWko3/hX7NmUt4J7ZX6zrkcJntq3fWyVkGy0wvtV1M2R1Ms+qX
         yLFZ8yvgLbB6wKeLTDL9CBJ0HkIxCKpAkHkTo6mO142ToRB1nQy2U54CU4ni23/Tb+vj
         Ff1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x8npC8BzcqD+JyTD3AyjZz04PRjuW1jwqLxFuydonlM=;
        b=homARYIPA2ZJkYXccNb8DNb2DoXNvoxqBoyuztG5/01HeBwRugP72G9ocdww5Tq5zP
         Hyc8In6BubkjX0kYfHJk1V5bO4sD3Bgzu3B3JhK0e/+3Wmx1mYBAybhtDhJ4yjFbTJCM
         wW1H99GZ6OX9PJneDsei9MKtoXtILVqBdae2MYLXf0nSQTZ/zAf6GCm32Wuq2PoeiRLm
         ssO4sFWpv0lR6iSflw/PSiTfqCXH3pnYnv0kleDK/UHyK+N2Q0V5MgKIykH+8kF+XheZ
         8gPlp+CeIa1eUtZKAX87L0pKHZrGcHgWdrELsy4k7iGKogaUgQx8yz8bez08eVA6QGKI
         2pLQ==
X-Gm-Message-State: AOAM531LL4ZEI6diH83iRjzGFHV64IoHvLwMLuuX6WDmbJ2x1l86G67a
	fM9SksdfcwWNNeuBRXWlnbg=
X-Google-Smtp-Source: ABdhPJzt0S1Ffj02sqnsR4WebdLo6aI/Mpdeh8l6F/JC7BKj4GStwGkm2XLCzxiqicT26LYHpupJBA==
X-Received: by 2002:a05:6a00:248b:b0:49f:9d7f:84e2 with SMTP id c11-20020a056a00248b00b0049f9d7f84e2mr43820084pfv.40.1637099643467;
        Tue, 16 Nov 2021 13:54:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1946:: with SMTP id s6ls6613779pfk.5.gmail; Tue, 16
 Nov 2021 13:54:02 -0800 (PST)
X-Received: by 2002:aa7:9903:0:b0:49f:e368:4fc3 with SMTP id z3-20020aa79903000000b0049fe3684fc3mr2436708pff.1.1637099642770;
        Tue, 16 Nov 2021 13:54:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637099642; cv=none;
        d=google.com; s=arc-20160816;
        b=EAgIsA5Vd9BDf8OMaz1UQilbtHrJ4ToIUOgU5hkW13DVpwtiAJ2GNfm5l6LCMTw+eK
         RpBSgd4vaFQwaPRM7hcuSgr1Bno0ZcgKjz8WSRiNrFLrWABN3Tu7pY/NXOQaI7jrnLZu
         6tH04ahu6TmkpAGtFXY9x8SEhyqymQwMRedl1tLD3rgC3a7aZ3gXwl4rtIJeyHyEsZrN
         v3RMz5p7AjRIzbNPjpzmBsGobti5GJQhLO30F4f14ionjXhiGdS9UpFE6psYzpVu7xmH
         UQxJv9Hwd7cYExr3RRRmJEhqF/zqEcRdQS9vCCaypLqIK96Px/co8pbVoZ3INB+X9vP6
         oodw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NZVUIohL2barCI4V/DC/WSWlEx32HYD+S0UuqJH4pmw=;
        b=AnLP2E1pjiKPJgANtaCtjqogaFlUOywpwEim9wndRz3tz4w88gLh3VQ3iT+jMKFTwn
         wR1blpAOO2DPt7Ml0kh8k7Yn9f6IFu+Zen8yWQ8MTwGYYiS7tPEr8NGubnfQM+ZLuwAt
         Y7o+ZwhQKJQI8zlj0tBZd6rIeV3o6A6iaSONLi7cc0EUPUebtSinin+F+9uogM8T1GEk
         JsQiz4bZ5VE+dphRa11YvGDUbdP2ptRcNF7vceHKww6LFcyqyg9JOm0qiyYpWXoA4DFZ
         G3gWKVGasqNlMGXwCiCOtau4cZRVMwbm8PhXbJ3skGcypYYNk0CF/dw9/mPgGPSv+pco
         RPHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=J14Gg3v0;
       spf=pass (google.com: domain of almasrymina@google.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=almasrymina@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x12d.google.com (mail-il1-x12d.google.com. [2607:f8b0:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id c3si127253pgv.1.2021.11.16.13.54.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 13:54:02 -0800 (PST)
Received-SPF: pass (google.com: domain of almasrymina@google.com designates 2607:f8b0:4864:20::12d as permitted sender) client-ip=2607:f8b0:4864:20::12d;
Received: by mail-il1-x12d.google.com with SMTP id h23so660872ila.4
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 13:54:02 -0800 (PST)
X-Received: by 2002:a05:6e02:1c46:: with SMTP id d6mr6886998ilg.79.1637099642366;
 Tue, 16 Nov 2021 13:54:02 -0800 (PST)
MIME-Version: 1.0
References: <CAMZfGtVjrMC1+fm6JjQfwFHeZN3dcddaAogZsHFEtL4HJyhYUw@mail.gmail.com>
 <CAHS8izPjJRf50yAtB0iZmVBi1LNKVHGmLb6ayx7U2+j8fzSgJA@mail.gmail.com>
 <CALvZod7VPD1rn6E9_1q6VzvXQeHDeE=zPRpr9dBcj5iGPTGKfA@mail.gmail.com>
 <CAMZfGtWJGqbji3OexrGi-uuZ6_LzdUs0q9Vd66SwH93_nfLJLA@mail.gmail.com>
 <6887a91a-9ec8-e06e-4507-b2dff701a147@oracle.com> <CAHS8izP3aOZ6MOOH-eMQ2HzJy2Y8B6NYY-FfJiyoKLGu7_OoJA@mail.gmail.com>
 <CALvZod7UEo100GLg+HW-CG6rp7gPJhdjYtcPfzaPMS7Yxa=ZPA@mail.gmail.com>
 <YZOeUAk8jqO7uiLd@elver.google.com> <CAHS8izPV20pD8nKEsnEYicaCKLH7A+QTYphWRrtTqcppzoQAWg@mail.gmail.com>
 <CALvZod6zGa15CDQTp+QOGLUi=ap_Ljx9-L5+S6w84U6xTTdpww@mail.gmail.com> <YZQnBoPqMGhtLxnJ@elver.google.com>
In-Reply-To: <YZQnBoPqMGhtLxnJ@elver.google.com>
From: "'Mina Almasry' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Nov 2021 13:53:51 -0800
Message-ID: <CAHS8izNH282748JeKeT_W6KC9G9=mJww4k9n5WrtoStDqTfQqA@mail.gmail.com>
Subject: Re: [PATCH v6] hugetlb: Add hugetlb.*.numa_stat file
To: Marco Elver <elver@google.com>
Cc: Shakeel Butt <shakeelb@google.com>, paulmck@kernel.org, 
	Mike Kravetz <mike.kravetz@oracle.com>, Muchun Song <songmuchun@bytedance.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Shuah Khan <shuah@kernel.org>, 
	Miaohe Lin <linmiaohe@huawei.com>, Oscar Salvador <osalvador@suse.de>, Michal Hocko <mhocko@suse.com>, 
	David Rientjes <rientjes@google.com>, Jue Wang <juew@google.com>, Yang Yao <ygyao@google.com>, 
	Joanna Li <joannali@google.com>, Cannon Matthews <cannonmatthews@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: almasrymina@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=J14Gg3v0;       spf=pass
 (google.com: domain of almasrymina@google.com designates 2607:f8b0:4864:20::12d
 as permitted sender) smtp.mailfrom=almasrymina@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Mina Almasry <almasrymina@google.com>
Reply-To: Mina Almasry <almasrymina@google.com>
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

On Tue, Nov 16, 2021 at 1:48 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Nov 16, 2021 at 12:59PM -0800, Shakeel Butt wrote:
> > On Tue, Nov 16, 2021 at 12:48 PM Mina Almasry <almasrymina@google.com> wrote:
> [...]
> > > > Per above, probably unlikely, but allowed. WRITE_ONCE should prevent it,
> > > > and at least relieve you to not worry about it (and shift the burden to
> > > > WRITE_ONCE's implementation).
> > > >
> > >
> > > Thank you very much for the detailed response. I can add READ_ONCE()
> > > at the no-lock read site, that is no issue.
> > >
> > > However, for the writes that happen while holding the lock, the write
> > > is like so:
> > > +               h_cg->nodeinfo[page_to_nid(page)]->usage[idx] += nr_pages;
> > >
> > > And like so:
> > > +               h_cg->nodeinfo[page_to_nid(page)]->usage[idx] -= nr_pages;
> > >
> > > I.e. they are increments/decrements. Sorry if I missed it but I can't
> > > find an INC_ONCE(), and it seems wrong to me to do something like:
> > >
> > > +               WRITE_ONCE(h_cg->nodeinfo[page_to_nid(page)]->usage[idx],
> > > +
> > > h_cg->nodeinfo[page_to_nid(page)] + nr_pages);
>
> From what I gather there are no concurrent writers, right?
>
> WRITE_ONCE(a, a + X) is perfectly fine. What it says is that you can
> have concurrent readers here, but no concurrent writers (and KCSAN will
> still check that). Maybe we need a more convenient macro for this idiom
> one day..
>
> Though I think for something like
>
>         h_cg->nodeinfo[page_to_nid(page)]->usage[idx] += nr_pages;
>
> it seems there wants to be an temporary long* so that you could write
> WRITE_ONCE(*usage, *usage + nr_pages) or something.
>

Ah, perfect, OK I can do this, and maybe add a comment explaining that
we don't have concurrent writers.

> > > I know we're holding a lock anyway so there is no race, but to the
> > > casual reader this looks wrong as there is a race between the fetch of
> > > the value and the WRITE_ONCE(). What to do here? Seems to me the most
> > > reasonable thing to do is just READ_ONCE() and leave the write plain?
> > >
> > >
> >
> > How about atomic_long_t?
>
> That would work of course; if this is very hot path code it might be
> excessive if you don't have concurrent writers.
>
> Looking at the patch in more detail, the counter is a stat counter that
> can be read from a stat file, correct? Hypothetically, what would happen
> if the reader of 'usage' reads approximate values?
>
> If the answer is "nothing", then this could classify as an entirely
> "benign" data race and you could only use data_race() on the reader and
> leave the writers unmarked using normal +=/-=. Check if it fits
> "Data-Racy Reads for Approximate Diagnostics" [1].
>
> [1] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/access-marking.txt#n74

Thank you very much for your quick responses. I think if the usage
returns a garbage/approximate value once in a while people will notice
and I can see it causing issues. I think it's worth doing it
'properly' here. I'll upload another version with these changes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHS8izNH282748JeKeT_W6KC9G9%3DmJww4k9n5WrtoStDqTfQqA%40mail.gmail.com.
