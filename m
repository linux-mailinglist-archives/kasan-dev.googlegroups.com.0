Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDWO2CGAMGQEITHTPRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F369453BE3
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 22:47:59 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id z1-20020a056512308100b003ff78e6402bsf207864lfd.4
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 13:47:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637099279; cv=pass;
        d=google.com; s=arc-20160816;
        b=msGEwnyCvPnEoo2o41y2BsMlQPcbZB67BFfXPTpkoUyRcJ295oH9QdDh3Mx44mA9ko
         D/onxcC3TFE/zbbxumVUchpAFFU7cL/btpbN7Bhp9vqbn3by4v8PNMn3tORBr9LiHDZs
         GtfOr4T1fxngleDaYuNEv4wSpW7WMl0nnOB0s56yTHpgZytv5efrtSRBHmEVUoEEe/Gn
         JOsqz8DHmqq9AC2C+SsshnGPFAmVhSle89nguJK7QEpKStBCK9UMJREwUGYHOWYEIUrn
         OV3XeM5wje7meK43eelejmGDvFH3/77A+cqScjT8V+PiBHTx/gxwoSMtLy+ocNzkPgNR
         aFUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=EuJGtbSRYBWuutFCXngMr9nVEZQLRQi1Lm0wRMo5YSM=;
        b=G30SisUERmdqnYDrlAvyJHq5bSeQNIJ5uKl1OoPEGCYvNHaNuIfkiBlfR56dN1h682
         gl5b2eqPUhCIxXQJTOSEqxhmRppXR2bWiyopVxAh1spCVaBHMqlyZeh3vzjDR2ltPuXa
         XiLdTksAu5P98J/qr9++eiZQ/omJMIieEEEfXVp/Qnc/fKMzZwqgyYxShGwOBpRQJd9x
         ypSWQShqGOtq18QwnfMbwmKPpLCd7DewIKvbyhBC9OzsClPYPHwY7D1yd08Uk2YrNMwx
         JXEC2HPinFX0YeUzafyMYsZeJVBHVrLH/QEYHYdeWBpfOp9vLhKK4ZvAT9QqkEPwjcc2
         CwJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qEwFgJ4U;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=EuJGtbSRYBWuutFCXngMr9nVEZQLRQi1Lm0wRMo5YSM=;
        b=YwEsOW1ZtSrOkf6IgHdWg6pYby1qAn0pqHOEBBglsUWQHgjHHThyZ4FKChvbe+FEFp
         qzB/If+4bRG7KMtwTb3KYPYpChQ0Ry8QUoFgavaTqaAwM+I/wsl2IUb4uqGOp1KSimEG
         vt8IAfRGxO2rXpmGcxHWEN/2hrxDIop4DmrphzTy/FS2AeL+i60SShzYEMzuIhQhBH9c
         COu4hp6HEXccTOyTEpWsBtZr3hLZf79l3B62aunCVcGqVytJongeU0NauMnSMh0xJLeE
         6Ffg44J64TuapHLVGX4t5fgv8QHbM7Q0/XNXGi/P3XQzo1R5biwanq6rrumXEQ7Y1EY9
         P9tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EuJGtbSRYBWuutFCXngMr9nVEZQLRQi1Lm0wRMo5YSM=;
        b=Hoz8z9cR/UizG4qR+dVJeGwa7XZ5GHTmX7Z3oOrarKCYYv8uGAaiyq/Qi5iSIGqbMD
         QduP8aGNluUU+FvoZzTxr391AFTVj6AD3R4Bk/fLcJ2WU7Onl6WnQAx1qiRy6QhKY4To
         XUQLZPUs/U+W6FuM+gl7um5jSrCQ13zZ8gubtyNlOhoZlpCUbly9dSNFsr5KsF4ty1tP
         43uhNSGgcqtftsmoxbx9QimPPBYaMrmxb7PGHvBP9jhUM44S7PnzUrq7BQnLMAjfQ89w
         lX9M353TVMiQ8qciJpJe+MXFRB2oN+L/CCFxvszA1dUnGhmi80O66wQI/dGeIjwM+g8k
         J0Tg==
X-Gm-Message-State: AOAM530c8SuxOwmPJm1evLIxa/sBNjkwHSB2PU+U1wzRRT5MVDlnXQHK
	3bqlHXyQYt5++VsvoyuzoXI=
X-Google-Smtp-Source: ABdhPJyvTJb1oHZKAPRQAVf0lqyq3bdHeSVWNEi/5ZjOqDI849dYlp5NUXaPpiSoJYsmUD7TDSzEPg==
X-Received: by 2002:a05:651c:c3:: with SMTP id 3mr2566968ljr.170.1637099278821;
        Tue, 16 Nov 2021 13:47:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c4:: with SMTP id x4ls2772988ljp.8.gmail; Tue, 16 Nov
 2021 13:47:57 -0800 (PST)
X-Received: by 2002:a2e:9d09:: with SMTP id t9mr2577047lji.400.1637099277715;
        Tue, 16 Nov 2021 13:47:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637099277; cv=none;
        d=google.com; s=arc-20160816;
        b=GRIRE9en69u27RGt7DLCpbgVcjtwpI3yA8CCqg1pGNpUK5qRJjp5UFUOCaATJjHKNB
         WVUJPntXpUhKP5HKCHmarrazB+onue7DiRsueMgFGNgBB4X268a/hNdkGjhzJ+7am2Zg
         U3cYcvuk1OsZ6cKZfV352J2qjuidGM1YqHYnsBmE818n4vzuKw4Af3O2O5gKgxcMxPw1
         onSmEtSmynre+afVOLhP4n6TWuj+BO+0vuyhVGiaHQbia2fyMsSug0rPT/vdASlqlD59
         S/5HQJF7OG5ydAmT4JT9xwLkPCxrTF4GFGdITQ1wjDI0h0ke3VyLIbeyMjWEEffo27ZC
         UXQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=CH+wOU8IkpDGfrPMJt+XhHiyZDF6T70EhzybBc8lVmM=;
        b=Nr2ElQLcDyoo1Vbf7FKlg3e1M/a45mgUzPq3U1vEB0O/ykStCGs8pFugHZsWxED2lv
         HAF45oFq28PcV3mJaTU1cwvXpbzhMnEwWj3TvsUMlGdPI9f2zuLhi5vHkdgxOOz5EQIr
         T/3fCwax3xlCFR/fsskJFY6sAQGAAlmIBZfkvylrIjMJsJCt1Lu5CYw4LPdAQv1HiT3D
         reANb2+0ggsL7nxDVqaQmzYzUb4btmEnTE6zblfh+jMoV6CshXzAnMUkaUmu27Vf9PNr
         ojAO43bKcTfE/Y30ytfKsA4D4uZHXP16bW8SU0QZruVQtB51WEBu5kgmZBRwL1+b2ngt
         oFzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qEwFgJ4U;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id t71si1116706lff.6.2021.11.16.13.47.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 13:47:57 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id az33-20020a05600c602100b00333472fef04so3125884wmb.5
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 13:47:57 -0800 (PST)
X-Received: by 2002:a7b:c4c4:: with SMTP id g4mr11223073wmk.93.1637099277010;
        Tue, 16 Nov 2021 13:47:57 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:ee27:74df:199e:beab])
        by smtp.gmail.com with ESMTPSA id v7sm18040254wrq.25.2021.11.16.13.47.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Nov 2021 13:47:56 -0800 (PST)
Date: Tue, 16 Nov 2021 22:47:50 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Shakeel Butt <shakeelb@google.com>
Cc: Mina Almasry <almasrymina@google.com>, paulmck@kernel.org,
	Mike Kravetz <mike.kravetz@oracle.com>,
	Muchun Song <songmuchun@bytedance.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Shuah Khan <shuah@kernel.org>, Miaohe Lin <linmiaohe@huawei.com>,
	Oscar Salvador <osalvador@suse.de>, Michal Hocko <mhocko@suse.com>,
	David Rientjes <rientjes@google.com>, Jue Wang <juew@google.com>,
	Yang Yao <ygyao@google.com>, Joanna Li <joannali@google.com>,
	Cannon Matthews <cannonmatthews@google.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v6] hugetlb: Add hugetlb.*.numa_stat file
Message-ID: <YZQnBoPqMGhtLxnJ@elver.google.com>
References: <CAMZfGtVjrMC1+fm6JjQfwFHeZN3dcddaAogZsHFEtL4HJyhYUw@mail.gmail.com>
 <CAHS8izPjJRf50yAtB0iZmVBi1LNKVHGmLb6ayx7U2+j8fzSgJA@mail.gmail.com>
 <CALvZod7VPD1rn6E9_1q6VzvXQeHDeE=zPRpr9dBcj5iGPTGKfA@mail.gmail.com>
 <CAMZfGtWJGqbji3OexrGi-uuZ6_LzdUs0q9Vd66SwH93_nfLJLA@mail.gmail.com>
 <6887a91a-9ec8-e06e-4507-b2dff701a147@oracle.com>
 <CAHS8izP3aOZ6MOOH-eMQ2HzJy2Y8B6NYY-FfJiyoKLGu7_OoJA@mail.gmail.com>
 <CALvZod7UEo100GLg+HW-CG6rp7gPJhdjYtcPfzaPMS7Yxa=ZPA@mail.gmail.com>
 <YZOeUAk8jqO7uiLd@elver.google.com>
 <CAHS8izPV20pD8nKEsnEYicaCKLH7A+QTYphWRrtTqcppzoQAWg@mail.gmail.com>
 <CALvZod6zGa15CDQTp+QOGLUi=ap_Ljx9-L5+S6w84U6xTTdpww@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CALvZod6zGa15CDQTp+QOGLUi=ap_Ljx9-L5+S6w84U6xTTdpww@mail.gmail.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qEwFgJ4U;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32b as
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

On Tue, Nov 16, 2021 at 12:59PM -0800, Shakeel Butt wrote:
> On Tue, Nov 16, 2021 at 12:48 PM Mina Almasry <almasrymina@google.com> wrote:
[...]
> > > Per above, probably unlikely, but allowed. WRITE_ONCE should prevent it,
> > > and at least relieve you to not worry about it (and shift the burden to
> > > WRITE_ONCE's implementation).
> > >
> >
> > Thank you very much for the detailed response. I can add READ_ONCE()
> > at the no-lock read site, that is no issue.
> >
> > However, for the writes that happen while holding the lock, the write
> > is like so:
> > +               h_cg->nodeinfo[page_to_nid(page)]->usage[idx] += nr_pages;
> >
> > And like so:
> > +               h_cg->nodeinfo[page_to_nid(page)]->usage[idx] -= nr_pages;
> >
> > I.e. they are increments/decrements. Sorry if I missed it but I can't
> > find an INC_ONCE(), and it seems wrong to me to do something like:
> >
> > +               WRITE_ONCE(h_cg->nodeinfo[page_to_nid(page)]->usage[idx],
> > +
> > h_cg->nodeinfo[page_to_nid(page)] + nr_pages);

From what I gather there are no concurrent writers, right?

WRITE_ONCE(a, a + X) is perfectly fine. What it says is that you can
have concurrent readers here, but no concurrent writers (and KCSAN will
still check that). Maybe we need a more convenient macro for this idiom
one day..

Though I think for something like

	h_cg->nodeinfo[page_to_nid(page)]->usage[idx] += nr_pages;

it seems there wants to be an temporary long* so that you could write
WRITE_ONCE(*usage, *usage + nr_pages) or something.

> > I know we're holding a lock anyway so there is no race, but to the
> > casual reader this looks wrong as there is a race between the fetch of
> > the value and the WRITE_ONCE(). What to do here? Seems to me the most
> > reasonable thing to do is just READ_ONCE() and leave the write plain?
> >
> >
> 
> How about atomic_long_t?

That would work of course; if this is very hot path code it might be
excessive if you don't have concurrent writers.

Looking at the patch in more detail, the counter is a stat counter that
can be read from a stat file, correct? Hypothetically, what would happen
if the reader of 'usage' reads approximate values?

If the answer is "nothing", then this could classify as an entirely
"benign" data race and you could only use data_race() on the reader and
leave the writers unmarked using normal +=/-=. Check if it fits
"Data-Racy Reads for Approximate Diagnostics" [1].

[1] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/access-marking.txt#n74

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YZQnBoPqMGhtLxnJ%40elver.google.com.
