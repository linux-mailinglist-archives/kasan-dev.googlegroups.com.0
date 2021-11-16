Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWF4Z2GAMGQEAP3FECQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 711F14531B8
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 13:04:42 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id k24-20020a2e9a58000000b00218c7914524sf6144972ljj.17
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 04:04:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637064282; cv=pass;
        d=google.com; s=arc-20160816;
        b=pNeQksEM9cpAx2vRt0Qt2LBmcb57JVM37Qux2OZu/9wpQsAhLZQObjsxc6JEFVUr9r
         ZLYS2o8n1vAC4b0vXkiSMuF50aP8TbuY5QYTHh8wtBHPDuHl3S73Tr1Bg45XhmV+5FmO
         PadKIhoCQSypgacL+aYkknmESv313B61pknH71UJNc0pmfHdEY04wPzURH8/dUyDDMxf
         XewkWBsLHKs0+PZ9BjMSp6x22slnTcZkLKoms7OstaiP48DyRUIUNYBhNI7IqJ/dcvTj
         zEeAULlj/gg5BDX1t0zAx4VfKMVSsNwLT579Nw5ikyDZ02OgnFSybyH1OSBeNZZQHf0/
         eoLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=yENPkDq8c+eqB5zqHJzb77bGwDuICaCvO3sT5bSXiAo=;
        b=gcSbbTSWY8p4tg/Kh0C8EKjOi5odSGO7v6iZ9OHUsHcwKZi2Z6o1Dor6moUJTmsA1s
         hUV//Se6rexeXpsW/VSgn5Cn3Znz5Z/WNF26KyQruqCfz04aXCOzdHZabVLR2BjuMa6F
         qTPmbGIBMg5dE2hna13DnjOPdW+A0O1abSlrAPVO9LLK+4zsgmbH1JVMXgmzFlNJi6wR
         shbk16vLGEJdSGsie/T7A5PSPpmL94yZNTsEIwnBsmMbvTSXNjR86x4qI1dSQPRD+6C6
         ZRWX5oRlgnx8Ksld4mAI7npNMK7Ab7pnvFYjNBBEJ4H9UNsLesiSxocpKpzYLSQVckze
         yy+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mgCBiXpI;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=yENPkDq8c+eqB5zqHJzb77bGwDuICaCvO3sT5bSXiAo=;
        b=pBcSAlx7D19S44xNSjX0FkPOgydFXINWOWpQbnNEGF4a62M7n4FnuMRtN+wLCbwG82
         8K5gLy5zQdWQIYCKwhor8j9iyvu7fyrTV3uJ25fVSs2HnMsOmj/vz0AvhKDKb+0KMcbM
         knYCXE3eXnaJAL7INgW/oXdWP8rvF/39EDqtTZ+P8df8d+fFxmj1R2yHG4tM96uSWvtC
         AUClBd1Um2kqSVGMMhUQqxwzZcOJ2gxmOBaiGkG6cl4OxggprEb/4rhtHmKpansOlxPB
         UKqNquv6v9fqBgtyP7GQSNBeQ57vjtzJJYi0lMh9+Vi9hN0ltoB9K4PpoX41FBv7pLLp
         6OyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yENPkDq8c+eqB5zqHJzb77bGwDuICaCvO3sT5bSXiAo=;
        b=e66BimsdE8VNn1UWAw+0tmBbsnWfpel8bdVStuBZ3UyFax0PEMhUXv1XWx10Htpqfh
         psOfhtHRO4zafVOrj5f5jn3Gi7p2bclO9rfKd6jDXGQ5rl13/NrT4CjT+G80I6aFyV/O
         tROChPSxHN6927tHGndVhD1ERQWp1u2vaVBZ6Bn8SC6PJsb+EPXgSi/+XAkI1cmBE/9+
         yr1OkuzzL3Z/lQGIk3pJZeRQZ0p2gd57o+omK4eV1cC/5GDG39x0QfO1Sn78OecJXNBC
         /BvvM6Fmhb1U4t3tbnZ1HXzkOk33he06mDbmiVjX4v86GpgVUdsUVUpiUVPSp70dgoAo
         doIA==
X-Gm-Message-State: AOAM533w4hRBZz38zROscM8dYsg66BlOrV4u/pzbGrjYaFXKOLYidiEc
	KEmNA6TLKvSLQfQgSnD2dmY=
X-Google-Smtp-Source: ABdhPJyZJFJhDnAktIEX+6UfLNE4hNQ1BzBhW573tBpUw/kQ9CvlfE6C9FP1s/KKKbyGOBTsvtqYbw==
X-Received: by 2002:a2e:9699:: with SMTP id q25mr6526453lji.6.1637064280473;
        Tue, 16 Nov 2021 04:04:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:b1f:: with SMTP id b31ls2787649ljr.0.gmail; Tue, 16
 Nov 2021 04:04:39 -0800 (PST)
X-Received: by 2002:a2e:83c4:: with SMTP id s4mr6115977ljh.445.1637064279269;
        Tue, 16 Nov 2021 04:04:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637064279; cv=none;
        d=google.com; s=arc-20160816;
        b=M7mE/qj5948XgTfpCv59XHbsHEVbzbLXJPcSD+aYqe20tgmFSthcC6kieGfvObwDXT
         X32pt3FozzY9MPN+Mvp9r4KpVAp0pLHV/ufwtbs7plQ8m6icDJe+159+nIk73b1PccI5
         yGpArkYsUeVhjDlueOuyxxlszQwDzegoJn6YY46hZYScabtU/TUdmbPBa9SWa9/9W2ea
         UTsu2LIsQ7A8FYUnGevx+J5L9QGFEYbxsefimd4cdBgVleFsK06I+Kn/MpNhe2uoekPG
         31uYxb95vW0N/IEh9Cn8STt2E2fhptKBMfuzSsdwdfo1H4BuC/u0tMIiyeXjhFy6Oxsh
         145A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=V9Y9KcPa2lBrD3VwSGoo5xYPKSJ2jtX2bGgZ++EHy0Q=;
        b=IjEDkVfkIhob/l2SNvhmQ9VMM+MunNN3pUsHytlrZhAU7+3/IHa/zyVtPTFDL0s4lN
         euv/zWUA/HT00BBH+Ek/iIxCLEwMBzmQ7byn+JKX0KG1If7xJc5luUxvf3pjUR7c8FdT
         +biWsnaaCy56SMLdimWcuS2pta22qoaL0tJPAnVU3U5Y/CxpEplHMmCtIwWzZGUMx/VW
         hyFhf0Azi4kSJjLJjdRl6J7hA+7lshD+5ubcbbC/zclugZvdk7SS/Z0EWIm6oMV2IO00
         2QoYSbE7fStFe1DDphL7BsP2vvQ2GLuHnbcLQ/VXk6AXSyBWgqz5Tr+MuCDQJ3/uFtrT
         lAYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mgCBiXpI;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id b11si912268lfv.12.2021.11.16.04.04.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 04:04:39 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id b184-20020a1c1bc1000000b0033140bf8dd5so2181951wmb.5
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 04:04:39 -0800 (PST)
X-Received: by 2002:a1c:80c5:: with SMTP id b188mr7359307wmd.57.1637064278455;
        Tue, 16 Nov 2021 04:04:38 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:ee27:74df:199e:beab])
        by smtp.gmail.com with ESMTPSA id f7sm3226528wmg.6.2021.11.16.04.04.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Nov 2021 04:04:37 -0800 (PST)
Date: Tue, 16 Nov 2021 13:04:32 +0100
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
Message-ID: <YZOeUAk8jqO7uiLd@elver.google.com>
References: <20211111015037.4092956-1-almasrymina@google.com>
 <CAMZfGtWj5LU0ygDpH9B58R48kM8w3tnowQDD53VNMifSs5uvig@mail.gmail.com>
 <cfa5a07d-1a2a-abee-ef8c-63c5480af23d@oracle.com>
 <CAMZfGtVjrMC1+fm6JjQfwFHeZN3dcddaAogZsHFEtL4HJyhYUw@mail.gmail.com>
 <CAHS8izPjJRf50yAtB0iZmVBi1LNKVHGmLb6ayx7U2+j8fzSgJA@mail.gmail.com>
 <CALvZod7VPD1rn6E9_1q6VzvXQeHDeE=zPRpr9dBcj5iGPTGKfA@mail.gmail.com>
 <CAMZfGtWJGqbji3OexrGi-uuZ6_LzdUs0q9Vd66SwH93_nfLJLA@mail.gmail.com>
 <6887a91a-9ec8-e06e-4507-b2dff701a147@oracle.com>
 <CAHS8izP3aOZ6MOOH-eMQ2HzJy2Y8B6NYY-FfJiyoKLGu7_OoJA@mail.gmail.com>
 <CALvZod7UEo100GLg+HW-CG6rp7gPJhdjYtcPfzaPMS7Yxa=ZPA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CALvZod7UEo100GLg+HW-CG6rp7gPJhdjYtcPfzaPMS7Yxa=ZPA@mail.gmail.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mgCBiXpI;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as
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

On Mon, Nov 15, 2021 at 11:59AM -0800, Shakeel Butt wrote:
> On Mon, Nov 15, 2021 at 10:55 AM Mina Almasry <almasrymina@google.com> wrote:
[...]
> > Sorry I'm still a bit confused. READ_ONCE/WRITE_ONCE isn't documented
> > to provide atomicity to the write or read, just prevents the compiler
> > from re-ordering them. Is there something I'm missing, or is the
> > suggestion to add READ_ONCE/WRITE_ONCE simply to supress the KCSAN
> > warnings?

It's actually the opposite: READ_ONCE/WRITE_ONCE provide very little
ordering (modulo dependencies) guarantees, which includes ordering by
compiler, but are supposed to provide atomicity (when used with properly
aligned types up to word size [1]; see __READ_ONCE for non-atomic
variant).

Some more background...

The warnings that KCSAN tells you about are "data races", which occur
when you have conflicting concurrent accesses, one of which is "plain"
and at least one write. I think [2] provides a reasonable summary of
data races and why we should care.

For Linux, our own memory model (LKMM) documents this [3], and says that
as long as concurrent operations are marked (non-plain; e.g. *ONCE),
there won't be any data races.

There are multiple reasons why data races are undesirable, one of which
is to avoid bad compiler transformations [4], because compilers are
oblivious to concurrency otherwise.

Why do marked operations avoid data races and prevent miscompiles?
Among other things, because they should be executed atomically. If they
weren't a lot of code would be buggy (there had been cases where the old
READ_ONCE could be used on data larger than word size, which certainly
weren't atomic, but this is no longer possible).

[1] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/asm-generic/rwonce.h#n35
[2] https://lwn.net/Articles/816850/#Why%20should%20we%20care%20about%20data%20races?
[3] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/explanation.txt#n1920
[4] https://lwn.net/Articles/793253/

Some rules of thumb when to use which marking:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/access-marking.txt

In an ideal world, we'd have all intentionally concurrent accesses
marked. As-is, KCSAN will find:

A. Data race, where failure due to current compilers is unlikely
   (supposedly "benign"); merely marking the accesses appropriately is
   sufficient. Finding a crash for these will require a miscompilation,
   but otherwise look "benign" at the C-language level.

B. Race-condition bugs where the bug manifests as a data race, too --
   simply marking things doesn't fix the problem. These are the types of
   bugs where a data race would point out a more severe issue.

Right now we have way too much of type (A), which means looking for (B)
requires patience.

> +Paul & Marco
> 
> Let's ask the experts.
> 
> We have a "unsigned long usage" variable that is updated within a lock
> (hugetlb_lock) but is read without the lock.
>
> Q1) I think KCSAN will complain about it and READ_ONCE() in the
> unlocked read path should be good enough to silent KCSAN. So, the
> question is should we still use WRITE_ONCE() as well for usage within
> hugetlb_lock?

KCSAN's default config will forgive the lack of WRITE_ONCE().
Technically it's still a data race (which KCSAN can find with a config
change), but can be forgiven because compilers are less likely to cause
trouble for writes (background: https://lwn.net/Articles/816854/ bit
about "Unmarked writes (aligned and up to word size)...").

I would mark both if feasible, as it clearly documents the fact the
write can be read concurrently.

> Q2) Second question is more about 64 bit archs breaking a 64 bit write
> into two 32 bit writes. Is this a real issue? If yes, then the
> combination of READ_ONCE()/WRITE_ONCE() are good enough for the given
> use-case?

Per above, probably unlikely, but allowed. WRITE_ONCE should prevent it,
and at least relieve you to not worry about it (and shift the burden to
WRITE_ONCE's implementation).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YZOeUAk8jqO7uiLd%40elver.google.com.
