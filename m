Return-Path: <kasan-dev+bncBC6LHPWNU4DBBEF6XCGQMGQEVR4KRZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3922646990C
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 15:32:50 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id o8-20020a170902d4c800b001424abc88f3sf1780297plg.2
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 06:32:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638801168; cv=pass;
        d=google.com; s=arc-20160816;
        b=u+qgf1AMyRO77+h+q1wyEEQVjIWKmH/GI74WdVbTEc5GkFPvhfAHnSRRBemhMen6kJ
         3KvdAkEaAGirzE5Lh2PWkMw9Fv0kbtFlhsEtJ3mizj53Fkp/UL20RUFQEoQo51aJchMq
         Q++m6XbDYhMUyLWUZDKMuzhhcYYLW6bTUg6hB0EsR+zRJzphGK+BKpV9PoO52LMZHkw/
         gvgWYJk1UIitG5SYD3R/QO+j8rGU9g8RZ8GI32cgwCEG3D49z69IdqNcj5f68HPq/y5x
         Iq9JaDOwV0Ml7FWX8Ipb4rMSjeTDZnhMDXWZLo1V51ds5ps+j1BqYm3hYzSxx3/LT14t
         H1Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=28az3iR5b64gdhvybvPozzAkChp8JlAhG6PUoALtmmk=;
        b=EATkFtXqpVbH1O118TVI2FmNxntu4W3bdrwBj1snYpcFsuqSo12bawMI6ANe2hbCQN
         LUBa9x+/dxrIaz7cdsKdAxezeyO3XUT5et7PE9cyw22er4vsUP/05HM8ArHulGogCDPo
         l0Ww0EBjPWc080IX6X4UPGJoYvIyMt0NTc/866+f5S4gt5XM0kBBQSz+oSTu111bf5o5
         UfUYjvwbZTBMSi4RpWQw7mJXl1DTrwJmHMRQ+Sl+71BG+plB2AhoCigbUlxXBNf9Wk0z
         6BF3m5jubZZGC9Bot1wgz1arXwXCpMeT2zkL7qabK4ug5mwdct1E2/eJfz7KbgORL5tY
         CvFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=GXfZLWEr;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=28az3iR5b64gdhvybvPozzAkChp8JlAhG6PUoALtmmk=;
        b=OxyFvTluTMd2trCr4eUjNVtRoB7r5HtI3tHMzEs38HRvv1zn6vVrzFw9chqA9/VozF
         lgmhNgNlaMtDnKONN6GSv6i5+Ijays2uqL88883qOHudc7+7DWnnTaKeZzys+nJw3+XH
         yyRGoJ27WYd/Z2kLxslScDDIveATxdwhjEzlccmB3RL+/VR3I+GCBfqcYrkL0PvxmS8a
         Db/waj5lx+yMT9dtoHbIZ/IGGynzvFD/LzOOlN9FLPCjijRV85gBo32+WLKCUg4Bvrg8
         NSm3iffQAqNG1vNEkk+XK8Xvg5EklvodApiahhJiPsJdfHifF3W1+7ITGkQz/pBK0m5h
         6l5A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=28az3iR5b64gdhvybvPozzAkChp8JlAhG6PUoALtmmk=;
        b=RjaTdRAfidmGvhNPtlZl9ukdHL36wt43JWjGKSNc1f7mP3EJ+itXciHMCgZ8msC0vx
         8/Z36rKrP5hCv9i2uOcRR4J5tal4bWtbOXS4tK+FgopsPOoVPTwYZgVik3UJJ9ZrD4W1
         TlHvgg8LSH86OkMheIHE25JKV1tUKUcQtqBEo94Vi9u/DKrRwGwf0mplp3GXMaqwCr6U
         P+WzsSe4diRAgvjIlqIo2aeFynHPmF8IR86OoIl3UwV1mS9vAF5qlsVdk9SVhlKvCEEN
         276tJzaqozTfrP6C+JAaMrUf2yElVqFM7h58D6nGbp3zhVisuaTw+J8E7j9hIb18IE/u
         AEcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=28az3iR5b64gdhvybvPozzAkChp8JlAhG6PUoALtmmk=;
        b=P6yrWehoJNvHBu3LEnR5q89XBcl/x090HIn/AplNSMmuMj399sUeuHt5lseFvKSLKm
         CLJ271NZieKey1Bx2wIlEIJ4djFUYSVDEb0o/0ahxakt/GemDchyIOqNe42At5z/tNzD
         JbURrlObUNZyO5YThH/24PxC0mVvTPZVBYVULaeQh3F4SN1M5aVvx8BzQcOdtjRPxH74
         O+l9B9lN/1FUT0ARL4YGeLWd6GCAhThU1e9NwZlpYo/dAPCH/31aHEGyro0dtxZvuhXn
         yfY5HiBlMKn426gHkc0N1LHUkhFyoJUmva90y/qKsJaUSOp/tm79keKDDdMK4mww28XP
         nuqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530TDhgtOv4hrxuy1AWdvSXqgtdattAxo8YR6J8TS9T8nM0TksKH
	unx0fY9Oa0zlcIPCWYoqSTw=
X-Google-Smtp-Source: ABdhPJyPMKXoJ7EUGOID5Fx2aPjmryqZDfGpOmYdVL7AedL6jX3xQ23p6F/XykdnFL5EhX6UFginzQ==
X-Received: by 2002:a63:874a:: with SMTP id i71mr19438154pge.93.1638801168534;
        Mon, 06 Dec 2021 06:32:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d4cc:: with SMTP id o12ls8463221plg.11.gmail; Mon,
 06 Dec 2021 06:32:47 -0800 (PST)
X-Received: by 2002:a17:90b:4c8d:: with SMTP id my13mr38524222pjb.107.1638801167822;
        Mon, 06 Dec 2021 06:32:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638801167; cv=none;
        d=google.com; s=arc-20160816;
        b=QxrdECkPkALPSFBiyBxbFvR6FTTBVm7EMdpfUBd0qYFJPCviwod8DOMn/dTurjHNMv
         gYzDqv4/NTZVFJQLT8OUDl4IiNT1wYOULtCQlSAS1GZSLfXCxuVrb9GbfM4zoka/qwbQ
         7xcouzSB/HmL/Zfjid94Q8LGBx0NDUyXGQTXGQJyYSSB7HozNpfQ1VDR/lwjryHeoT1d
         mtj1cscftYZIQWvotV8/Xd1WIGox5J26i2RHaHy7vGqCSeusWmaKa9z7fPiNYpYTB16V
         NAfCDFbqDckOSLwR/ZrZ9+6OgQwRzBeW8hWl1NSyTmAmQbl05mWbrMfpleS0GKYRUAe5
         2z3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FHezbGrYlKxA1aTrkxNXSkuk1RduKCiWsmFP87kNHNY=;
        b=rPO11NdSia8SAMfe3C7sPmEFEzlZjOAhi8Iuu8+uhjwodi9jDcMEGjCPFE9pz69rby
         Tbz1sTwIujtKqjbZylZZ8s0kZdwzll3u1KpI5fMrRLQJxfzAO09PgN52rO7KksYC8sBm
         cXPhJM2x6OhJC4LuEwtHBPJDtHAR3hjIgFUPI5oFVKi/QdpsWKA7qvcc5BZM3tuVVZXe
         LU4HW4BojE3rkWFmMpKi+4KGxV0rFlw0ZZu4CITS1gY25IHrmaiLB1GjfN3SrZIvI3L7
         HEv9afeM7tRXaXjkMoyrxMTDpeiHfXS8qEiDSqP1m1S6gypXot4hQFVTojI5injpq+1m
         H6yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=GXfZLWEr;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd36.google.com (mail-io1-xd36.google.com. [2607:f8b0:4864:20::d36])
        by gmr-mx.google.com with ESMTPS id l5si1088449pfc.2.2021.12.06.06.32.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 06:32:47 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::d36 as permitted sender) client-ip=2607:f8b0:4864:20::d36;
Received: by mail-io1-xd36.google.com with SMTP id m9so13224959iop.0
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 06:32:47 -0800 (PST)
X-Received: by 2002:a02:a708:: with SMTP id k8mr42965751jam.26.1638801167426;
        Mon, 06 Dec 2021 06:32:47 -0800 (PST)
Received: from auth1-smtp.messagingengine.com (auth1-smtp.messagingengine.com. [66.111.4.227])
        by smtp.gmail.com with ESMTPSA id y8sm6337176iox.32.2021.12.06.06.32.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 06:32:46 -0800 (PST)
Received: from compute6.internal (compute6.nyi.internal [10.202.2.46])
	by mailauth.nyi.internal (Postfix) with ESMTP id 8E52D27C0054;
	Mon,  6 Dec 2021 09:32:44 -0500 (EST)
Received: from mailfrontend1 ([10.202.2.162])
  by compute6.internal (MEProxy); Mon, 06 Dec 2021 09:32:44 -0500
X-ME-Sender: <xms:Cx-uYQs85A1MMXJYGuWqEJ7Z5H0fYWyIBMsroi5ZcJYhDA_0sXEVKw>
    <xme:Cx-uYdeOOSQTLomCC91P6fvNfLUaBzynTvS8S1IJqe42v_kaQOsPATPLrlpxDh5K-
    VsJpX9OMQqwUGTEww>
X-ME-Received: <xmr:Cx-uYbxTazrQNhAmwOJDGcwBcZKt0G6ftpVDE7070sHyD2fzk1MP_1dE6sw>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvuddrjeefgdeihecutefuodetggdotefrodftvf
    curfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfghnecu
    uegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenuc
    fjughrpeffhffvuffkfhggtggujgesthdtredttddtvdenucfhrhhomhepuehoqhhunhcu
    hfgvnhhguceosghoqhhunhdrfhgvnhhgsehgmhgrihhlrdgtohhmqeenucggtffrrghtth
    gvrhhnpeevieejtdfhieejfeduheehvdevgedugeethefggfdtvdeutdevgeetvddvfeeg
    tdenucffohhmrghinhepkhgvrhhnvghlrdhorhhgnecuvehluhhsthgvrhfuihiivgeptd
    enucfrrghrrghmpehmrghilhhfrhhomhepsghoqhhunhdomhgvshhmthhprghuthhhphgv
    rhhsohhnrghlihhthidqieelvdeghedtieegqddujeejkeehheehvddqsghoqhhunhdrfh
    gvnhhgpeepghhmrghilhdrtghomhesfhhigihmvgdrnhgrmhgv
X-ME-Proxy: <xmx:Cx-uYTP7IMvllYtCuW-96zpzDKmquPq_Oc0AMq8B6-3JLGB89W1FVQ>
    <xmx:Cx-uYQ-LAihlYOGwm6Zoiy1lOqxm_kftsSxg_LPN5by606Y0o4ftaA>
    <xmx:Cx-uYbVLvwYrqkFwFZoM7PbDfKREKDylKP9K-SP5OD6QDsGQMr7wcg>
    <xmx:DB-uYT3XFpOMXfNRE9xfxrXZdDXokmbhrddzAfQotajWX2sPWXYz3F-Xqns>
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Mon,
 6 Dec 2021 09:32:43 -0500 (EST)
Date: Mon, 6 Dec 2021 22:31:24 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>,
	Ingo Molnar <mingo@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	llvm@lists.linux.dev, x86@kernel.org
Subject: Re: [PATCH v3 08/25] kcsan: Show location access was reordered to
Message-ID: <Ya4evHE7uQ9eXpax@boqun-archlinux>
References: <20211130114433.2580590-1-elver@google.com>
 <20211130114433.2580590-9-elver@google.com>
 <Ya2Zpf8qpgDYiGqM@boqun-archlinux>
 <CANpmjNMirKGSBW2m+bWRM9_FnjK3_HjnJC=dhyMktx50mwh1GQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMirKGSBW2m+bWRM9_FnjK3_HjnJC=dhyMktx50mwh1GQ@mail.gmail.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=GXfZLWEr;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::d36
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
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

On Mon, Dec 06, 2021 at 08:16:11AM +0100, Marco Elver wrote:
> On Mon, 6 Dec 2021 at 06:04, Boqun Feng <boqun.feng@gmail.com> wrote:
> >
> > Hi,
> >
> > On Tue, Nov 30, 2021 at 12:44:16PM +0100, Marco Elver wrote:
> > > Also show the location the access was reordered to. An example report:
> > >
> > > | ==================================================================
> > > | BUG: KCSAN: data-race in test_kernel_wrong_memorder / test_kernel_wrong_memorder
> > > |
> > > | read-write to 0xffffffffc01e61a8 of 8 bytes by task 2311 on cpu 5:
> > > |  test_kernel_wrong_memorder+0x57/0x90
> > > |  access_thread+0x99/0xe0
> > > |  kthread+0x2ba/0x2f0
> > > |  ret_from_fork+0x22/0x30
> > > |
> > > | read-write (reordered) to 0xffffffffc01e61a8 of 8 bytes by task 2310 on cpu 7:
> > > |  test_kernel_wrong_memorder+0x57/0x90
> > > |  access_thread+0x99/0xe0
> > > |  kthread+0x2ba/0x2f0
> > > |  ret_from_fork+0x22/0x30
> > > |   |
> > > |   +-> reordered to: test_kernel_wrong_memorder+0x80/0x90
> > > |
> >
> > Should this be "reordered from" instead of "reordered to"? For example,
> > if the following case needs a smp_mb() between write to A and write to
> > B, I think currently it will report as follow:
> >
> >         foo() {
> >                 WRITE_ONCE(A, 1); // let's say A's address is 0xaaaa
> >                 bar() {
> >                         WRITE_ONCE(B, 1); // Assume B's address is 0xbbbb
> >                                           // KCSAN find the problem here
> >                 }
> >         }
> >
> >         <report>
> >         | write (reordered) to 0xaaaa of ...:
> >         | bar+0x... // address of the write to B
> >         | foo+0x... // address of the callsite to bar()
> >         | ...
> >         |  |
> >         |  +-> reordered to: foo+0x... // address of the write to A
> >
> > But since the access reported here is the write to A, so it's a
> > "reordered from" instead of "reordered to"?
> 
> Perhaps I could have commented on this in the commit message to avoid
> the confusion, but per its updated comment replace_stack_entry()
> "skips to the first entry that matches the function of @ip, and then
> replaces that entry with @ip, returning the entries to skip with
> @replaced containing the replaced entry."
> 
> When a reorder_access is set up, the ip to it is stored, which is
> what's passed to @ip of replace_stack_entry(). It effectively swaps
> the top frame where the race occurred with where the original access
> happened. This all works because the runtime is careful to only keep
> reorder_accesses valid until the original function where it occurred
> is left.
> 

Thanks for the explanation, I was missing the swap here. However...

> So in your above example you need to swap "reordered to" and the top
> frame of the stack trace.
> 

IIUC, the report for my above example will be:

         | write (reordered) to 0xaaaa of ...:
         | foo+0x... // address of the write to A
         | ...
         |  |
         |  +-> reordered to: foo+0x... // address of the callsite to bar() in foo()

, right? Because in replace_stack_entry(), it's not the top frame where
the race occurred that gets swapped, it's the frame which belongs to the
same function as the original access that gets swapped. In other words,
when KCSAN finds the problem, top entries of the calling stack are:

	[0] bar+0x.. // address of the write to B
	[1] foo+0x.. // address of the callsite to bar() in foo()

after replace_stack_entry(), they changes to:

	[0] bar+0x.. // address of the write to B
skip  ->[1] foo+0x.. // address of the write to A

, as a result the report won't mention bar() at all.

And I think a better report will be:

         | write (reordered) to 0xaaaa of ...:
         | foo+0x... // address of the write to A
         | ...
         |  |
         |  +-> reordered to: bar+0x... // address of the write to B in bar()

because it tells users the exact place the accesses get reordered. That
means maybe we want something as below? Not completely tested, but I
play with scope checking a bit, seems it gives what I want. Thoughts?

Regards,
Boqun

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 67794404042a..b495ed3aa637 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -324,7 +324,10 @@ replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned lon
        else
                goto fallback;

-       for (skip = 0; skip < num_entries; ++skip) {
+       skip = get_stack_skipnr(stack_entries, num_entries);
+       *replaced = stack_entries[skip];
+
+       for (;skip < num_entries; ++skip) {
                unsigned long func = stack_entries[skip];

                if (!kallsyms_lookup_size_offset(func, &symbolsize, &offset))
@@ -332,7 +335,6 @@ replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned lon
                func -= offset;

                if (func == target_func) {
-                       *replaced = stack_entries[skip];
                        stack_entries[skip] = ip;
                        return skip;
                }

> The implementation is a little trickier of course, but I really wanted
> the main stack trace to look like any other non-reordered access,
> which starts from the original access, and only have the "reordered
> to" location be secondary information.
> 
> The foundation for doing this this was put in place here:
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6c65eb75686f
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ya4evHE7uQ9eXpax%40boqun-archlinux.
