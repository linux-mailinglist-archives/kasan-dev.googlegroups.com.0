Return-Path: <kasan-dev+bncBC2OFAOUZYGBBJ5S2CGAMGQES6GL54A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E31E453B33
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 21:48:40 +0100 (CET)
Received: by mail-qk1-x738.google.com with SMTP id p18-20020a05620a057200b00467bc32b45asf137092qkp.12
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 12:48:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637095719; cv=pass;
        d=google.com; s=arc-20160816;
        b=GK4CRdeTSRJEUawvNySMj4qDIN+EYpXudAV7sm+4q46krzW3seezX7t+3EOSQJLjXU
         l9C/7++IzYxjuWVzAzpEvXDVPfWhuN15cGiR8UjfoVnlUaBRjudv2fEwRrPovm63UV1l
         HuuVUvHWpv+mpAMZYfbaiV9KsFYzRVPdzYtBhHEz0+fi10LFVgP0H7G9iHKkjnzHcC9p
         Zx/C3cKK8fcbbZE8ScakQSswBlP9qQN1Uom5I408WNRGIVMDWJUpMkI/+eNslHG6EyNl
         apftS8HPKEAizsavSgQSyadjX6ZVljOnnXo2s2QUZ4WtezONcftqU8/h9IGnODaNU73j
         KT4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aPfcu4md4MX6GxgwyWlCxclJ2fvL558KNODj4fWl3Aw=;
        b=vJqGw6z4l5ggNHU8OEDaAclDaKdldfxXRJ0iP9msHb56z+zHWydObjzrpNchB2Vw5f
         onKvapcXULA17CdSwSdLmoArtYG4x0N7vrLCGzFq9JiReb5q7JCSApkZpXzlcplpG1/D
         gNny/aJmUbQJBAiDH2652DZmtOX42tdSdsIJ2B5S7p/I2fdRwuBd0TdEKV3Lu8m4NiR2
         jmnfQ+xnVgpVXgwQbE6K/GCFtLTZUKYbbMLnds06bBO/CLEomNBj1klgDibXVtP4EzjS
         XWTl9EanXEJpagNcT4zu/rUH3h+zkt294F2wlSIamUEG2u45poxj6oSXAlX1QFlAYUNl
         GjvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=d0QjB9Or;
       spf=pass (google.com: domain of almasrymina@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=almasrymina@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aPfcu4md4MX6GxgwyWlCxclJ2fvL558KNODj4fWl3Aw=;
        b=EumzQlzpzZpvfoNBT5M2qGYN+09cMTdejyr+fxhsCDv1FlfGVRbDR5pxy1Gcnkcgns
         KiAMBnUM7WJAUCfeAMZjyEyoFMTKoZ//kizZPQlwa/6hKLWh2Esv2ilfS60wkPHrlHt/
         TSBtfQdWV5mves1Bq29y53tCV8AcDbmXE8AbJ389zF39f2oT6uMXjzOEVp2PvfRrheJj
         rSyAEciVOU7bzYfvVigSfrrWNlC/YfdUg/WubMs9XSI9CHGUurCvLKQAOAGXcq5dOKxS
         6xpGHyBvvqWsFsogdageM0wO0EF7BthbojPzfgxG+pQgqoc/O+8SW9bTOIpYNnaqRxLv
         ykVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aPfcu4md4MX6GxgwyWlCxclJ2fvL558KNODj4fWl3Aw=;
        b=vmcWwiW49ldqrcV2Bk1amp4UzKjrAEl4M2ExRr3LZyLGo63Af8R4EHUFtK9LeJRVVx
         Z/+UB4hZHP2Xxp9O5CLmK0etjnQji7MtgRLBBMS1jQUgNflSqSXoW6ukfm4TUG0l2nVI
         Bau3RvHjPXJ5mpxsOTRpalZn8SY8Drz+7aFULDhgso2gnwitcXe70NfwM8L/07UiyusG
         iNExYPNiZWIbr5+29a9m3ncdUSJIt4uz8mAYZxeZlPvgNNIeMnsCsFUZjNHGfeWEZiQf
         78wlOEOq9T5IH6vk+atKPyoF6R+TnczyA5KdXWyI0TWjj40G2CJ0Efjuqeeo90zyCEyN
         kQJQ==
X-Gm-Message-State: AOAM530GBJxXJEwVjq2SpCtbrZ4JyToCcU8OBRegPWvhxvWTTt7Tq0oa
	xk8w/ouE/1yk+xUz4mvjwjE=
X-Google-Smtp-Source: ABdhPJyx9Qb89R7xAQLoXXDU30sMe+we3/bsBX3LBh6D9kgVUOYBsWimKEKvGN9O3Dxd1lUoIaYH3A==
X-Received: by 2002:ac8:5803:: with SMTP id g3mr10644107qtg.317.1637095719179;
        Tue, 16 Nov 2021 12:48:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e705:: with SMTP id d5ls6236566qvn.4.gmail; Tue, 16 Nov
 2021 12:48:38 -0800 (PST)
X-Received: by 2002:a05:6214:e83:: with SMTP id hf3mr49646151qvb.52.1637095718679;
        Tue, 16 Nov 2021 12:48:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637095718; cv=none;
        d=google.com; s=arc-20160816;
        b=e9bqb/6cobMBy4GSbqJvwa09pWeiJ6gfnShZUMzULVE4KtMUV6huxZ4U43CCqyGTgy
         Sfk2+bmYaAHLtMAua5Of7mHtjfdygn0nSWxHn4Z2oL7KFdI+jWIFWB6rNpA0tl/kbr1Q
         MKlznJZUNqJObrLlxgKnzEIuoLN+gmqHRw0a0MejTfDrXM1Xh1l9i79NBD+9NJH3PbzS
         ibdIS+rL0TOeD9jrLa9o+5ppOj/dm6DLRNTAijJOa8387S0SUPni6l3TQ/dwJLQeHaFn
         aNDk46FdRi6qtj9OXv1OFGEoqMmHlv8ANHlWG5w9jwIYnczXDajOKw3khCfzKjp6d6ne
         0rCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jOfzVabuJm7V2x9GPx6NulAgjy/f+/1BiIEsCRGFw8Q=;
        b=C2X7tq7kKCdbl86OA4pCwtVmLTCP1v2ZItQhpSd24AgFaG6n02rotlRgivcTLZ4hQm
         ga8dH88ElL61dtP+TzRH0k/h49krqGEUUc0iAR0Tx2ML8fmtillHChJThtsu207//aRB
         x7+5JoknoVoFwaTsTMeFSdd1DSfe29xnjDisQB1whDpmCXPdC+4vPvlxlgnU4Hg7dHcO
         JdwPZcKbR3IC5NIS0suNtI0EIzdHefNMQQoenaI34N0c2pLIYBpNrwKN+5KHde/BCvmB
         IWQ15vU1+OSa3XpYYWn2qQl/JqWLLx6dmGJDu7WiTbIqOIABYEwGdxzq6ZZOWMXKEO7g
         jwWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=d0QjB9Or;
       spf=pass (google.com: domain of almasrymina@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=almasrymina@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd36.google.com (mail-io1-xd36.google.com. [2607:f8b0:4864:20::d36])
        by gmr-mx.google.com with ESMTPS id d17si1919960qtb.2.2021.11.16.12.48.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 12:48:38 -0800 (PST)
Received-SPF: pass (google.com: domain of almasrymina@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) client-ip=2607:f8b0:4864:20::d36;
Received: by mail-io1-xd36.google.com with SMTP id m9so323170iop.0
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 12:48:38 -0800 (PST)
X-Received: by 2002:a5e:cb0d:: with SMTP id p13mr7165308iom.71.1637095718250;
 Tue, 16 Nov 2021 12:48:38 -0800 (PST)
MIME-Version: 1.0
References: <20211111015037.4092956-1-almasrymina@google.com>
 <CAMZfGtWj5LU0ygDpH9B58R48kM8w3tnowQDD53VNMifSs5uvig@mail.gmail.com>
 <cfa5a07d-1a2a-abee-ef8c-63c5480af23d@oracle.com> <CAMZfGtVjrMC1+fm6JjQfwFHeZN3dcddaAogZsHFEtL4HJyhYUw@mail.gmail.com>
 <CAHS8izPjJRf50yAtB0iZmVBi1LNKVHGmLb6ayx7U2+j8fzSgJA@mail.gmail.com>
 <CALvZod7VPD1rn6E9_1q6VzvXQeHDeE=zPRpr9dBcj5iGPTGKfA@mail.gmail.com>
 <CAMZfGtWJGqbji3OexrGi-uuZ6_LzdUs0q9Vd66SwH93_nfLJLA@mail.gmail.com>
 <6887a91a-9ec8-e06e-4507-b2dff701a147@oracle.com> <CAHS8izP3aOZ6MOOH-eMQ2HzJy2Y8B6NYY-FfJiyoKLGu7_OoJA@mail.gmail.com>
 <CALvZod7UEo100GLg+HW-CG6rp7gPJhdjYtcPfzaPMS7Yxa=ZPA@mail.gmail.com> <YZOeUAk8jqO7uiLd@elver.google.com>
In-Reply-To: <YZOeUAk8jqO7uiLd@elver.google.com>
From: "'Mina Almasry' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Nov 2021 12:48:26 -0800
Message-ID: <CAHS8izPV20pD8nKEsnEYicaCKLH7A+QTYphWRrtTqcppzoQAWg@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=d0QjB9Or;       spf=pass
 (google.com: domain of almasrymina@google.com designates 2607:f8b0:4864:20::d36
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

On Tue, Nov 16, 2021 at 4:04 AM Marco Elver <elver@google.com> wrote:
>
> On Mon, Nov 15, 2021 at 11:59AM -0800, Shakeel Butt wrote:
> > On Mon, Nov 15, 2021 at 10:55 AM Mina Almasry <almasrymina@google.com> wrote:
> [...]
> > > Sorry I'm still a bit confused. READ_ONCE/WRITE_ONCE isn't documented
> > > to provide atomicity to the write or read, just prevents the compiler
> > > from re-ordering them. Is there something I'm missing, or is the
> > > suggestion to add READ_ONCE/WRITE_ONCE simply to supress the KCSAN
> > > warnings?
>
> It's actually the opposite: READ_ONCE/WRITE_ONCE provide very little
> ordering (modulo dependencies) guarantees, which includes ordering by
> compiler, but are supposed to provide atomicity (when used with properly
> aligned types up to word size [1]; see __READ_ONCE for non-atomic
> variant).
>
> Some more background...
>
> The warnings that KCSAN tells you about are "data races", which occur
> when you have conflicting concurrent accesses, one of which is "plain"
> and at least one write. I think [2] provides a reasonable summary of
> data races and why we should care.
>
> For Linux, our own memory model (LKMM) documents this [3], and says that
> as long as concurrent operations are marked (non-plain; e.g. *ONCE),
> there won't be any data races.
>
> There are multiple reasons why data races are undesirable, one of which
> is to avoid bad compiler transformations [4], because compilers are
> oblivious to concurrency otherwise.
>
> Why do marked operations avoid data races and prevent miscompiles?
> Among other things, because they should be executed atomically. If they
> weren't a lot of code would be buggy (there had been cases where the old
> READ_ONCE could be used on data larger than word size, which certainly
> weren't atomic, but this is no longer possible).
>
> [1] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/asm-generic/rwonce.h#n35
> [2] https://lwn.net/Articles/816850/#Why%20should%20we%20care%20about%20data%20races?
> [3] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/explanation.txt#n1920
> [4] https://lwn.net/Articles/793253/
>
> Some rules of thumb when to use which marking:
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/access-marking.txt
>
> In an ideal world, we'd have all intentionally concurrent accesses
> marked. As-is, KCSAN will find:
>
> A. Data race, where failure due to current compilers is unlikely
>    (supposedly "benign"); merely marking the accesses appropriately is
>    sufficient. Finding a crash for these will require a miscompilation,
>    but otherwise look "benign" at the C-language level.
>
> B. Race-condition bugs where the bug manifests as a data race, too --
>    simply marking things doesn't fix the problem. These are the types of
>    bugs where a data race would point out a more severe issue.
>
> Right now we have way too much of type (A), which means looking for (B)
> requires patience.
>
> > +Paul & Marco
> >
> > Let's ask the experts.
> >
> > We have a "unsigned long usage" variable that is updated within a lock
> > (hugetlb_lock) but is read without the lock.
> >
> > Q1) I think KCSAN will complain about it and READ_ONCE() in the
> > unlocked read path should be good enough to silent KCSAN. So, the
> > question is should we still use WRITE_ONCE() as well for usage within
> > hugetlb_lock?
>
> KCSAN's default config will forgive the lack of WRITE_ONCE().
> Technically it's still a data race (which KCSAN can find with a config
> change), but can be forgiven because compilers are less likely to cause
> trouble for writes (background: https://lwn.net/Articles/816854/ bit
> about "Unmarked writes (aligned and up to word size)...").
>
> I would mark both if feasible, as it clearly documents the fact the
> write can be read concurrently.
>
> > Q2) Second question is more about 64 bit archs breaking a 64 bit write
> > into two 32 bit writes. Is this a real issue? If yes, then the
> > combination of READ_ONCE()/WRITE_ONCE() are good enough for the given
> > use-case?
>
> Per above, probably unlikely, but allowed. WRITE_ONCE should prevent it,
> and at least relieve you to not worry about it (and shift the burden to
> WRITE_ONCE's implementation).
>

Thank you very much for the detailed response. I can add READ_ONCE()
at the no-lock read site, that is no issue.

However, for the writes that happen while holding the lock, the write
is like so:
+               h_cg->nodeinfo[page_to_nid(page)]->usage[idx] += nr_pages;

And like so:
+               h_cg->nodeinfo[page_to_nid(page)]->usage[idx] -= nr_pages;

I.e. they are increments/decrements. Sorry if I missed it but I can't
find an INC_ONCE(), and it seems wrong to me to do something like:

+               WRITE_ONCE(h_cg->nodeinfo[page_to_nid(page)]->usage[idx],
+
h_cg->nodeinfo[page_to_nid(page)] + nr_pages);

I know we're holding a lock anyway so there is no race, but to the
casual reader this looks wrong as there is a race between the fetch of
the value and the WRITE_ONCE(). What to do here? Seems to me the most
reasonable thing to do is just READ_ONCE() and leave the write plain?


> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHS8izPV20pD8nKEsnEYicaCKLH7A%2BQTYphWRrtTqcppzoQAWg%40mail.gmail.com.
