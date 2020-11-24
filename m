Return-Path: <kasan-dev+bncBC6LHPWNU4DBBSXO6H6QKGQES6ZQTKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 49E842C1BCC
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 04:00:28 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id p29sf3100290oof.19
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 19:00:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606186827; cv=pass;
        d=google.com; s=arc-20160816;
        b=YkRlFxZ7PE9zdwfdofRDtaIL7tQ8/MrQfT+hBjLCtSA13q1Bqdj9rxVdbKS2CPfcAC
         xSCy9vZPQSfTywnt+HIX7oh5zcJBclQD0hAK7XtHWET2mkg5aq1rSVkmnCYJ2KogLQXk
         4wqdXm9jYgcI2NviKAA8I5jl12Q9m47nw267ZeinpioOO4dOrUzJkQjolYarBznWEzRP
         pZTuonjmW0p61z+JhSNjYtf1xCR55Y0SMuA26v8CKiiaPVqu1gVaZjexlGTscAtFpmpR
         Ozg3mmARGeqVfZSqoQ1Nkbu4vsFJhef2tzd/m01ChnJT/tiKkq7BExPvSFIl/IMHxlCp
         D8gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=GRrE34Q7T//7KkylK11Yw+vmlwq3Sz9HFcGZbaHVQrE=;
        b=ryyfKP8y0LTezfFTeWu3FJNOG9sif9LnkRcjB0ddYIqc6PmPMV1x6/tCpsPy8Cmvif
         BZutORfI5z6UJzX53hAndDccXnx/P+je5ltMG2/oE6rcQdDAp29I+J6oGXXZBrgD8hTE
         SBEP0OnimhK908ens2VJfy6jWMw2DyrjFC2+3xQv+7YO+fNp8bPH68qw9q3PWWkeK/sD
         8kLmXCEafUJRJum6lL3GfOP3grnol+LTl0iWNwhCF8Lbk6xnHKo0OwCMkbqgUlVeKlYk
         wsUwTqDNCr68zBNjYXuuxgStETS8YgfbbwcGQhkpOR7OejX8qogrx7dGajyoypU/wxiL
         vg8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=WEqloDj3;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GRrE34Q7T//7KkylK11Yw+vmlwq3Sz9HFcGZbaHVQrE=;
        b=C3CISBIcnktL0t74RX9xrRU8WU1bF8NIZWsButgs8jiQOZJagc/WXPM7rhHboo5Bxg
         AVMxuu7wivRRNoegGFnwDiJwCfJG44g1rKegqijwSJv8H6rYo2DqnR4M2Khq+M/MdZ9I
         QEF/pXGwHTXImDvaPzvD9g3SCl0tommz159GjyfOxu/uCPYx+rrH+XJmHxytkK5oW+Wa
         gH8Hu3ePB8bKo/E/9O/VNUphhwFKXgne73wkcpY/s4tDICv4d1UXX98GuVycCwODFXmR
         v+BZN3l9lJ4bDzaHkl6K49hEciyzA/I346n9chK9f7T5kHoqIxcshQ78dXy8QT+OErto
         DB+g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GRrE34Q7T//7KkylK11Yw+vmlwq3Sz9HFcGZbaHVQrE=;
        b=TWoO3JXNF9U2Xiu5MjZ9RU6/8lqvFGhk9Cih7+w5Tn5ohQqlEoecLqIyjXZGWj9q8z
         CvxM9iae8kdxOu8ebYarai4hN8t9u46YLeZslFxKJ26kXXcUX31XUG+mSkEJya6G4odf
         4VKjfjRA9eZq0aHT4oPDyCKNN2T+tJJM7uMcZZBBaZj4OngCTsXz4XybUhl1zGGGJfEk
         7x1WrCdTAOv1FqLpti4hOgcLuD8/v4sBzNTGE1UEWaSt7YE4RjuDLrzxqyjkGG5J92bh
         O/EiPupkDSDXml90WpLn8g3oPEkHnwZ/HgORzvHG/Z3DQfDD9TRvUhhLLZ/DvVbKjrVp
         wy0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GRrE34Q7T//7KkylK11Yw+vmlwq3Sz9HFcGZbaHVQrE=;
        b=s7yIiLBXAV9bq2UaFR4mrA2la0E4r9XTY4d8lP7FMC0MTnqvBpciTyvgxbV/dV75cj
         urIp2pJj8n/lC9D4DcWg8xCywzS2j4goLMwr676EUDq/9D/+yPoE6G/ftTDZOZMKE5uM
         8RkdIHyT6nkOg3qEg0jqz877CRc5x99kNh9NsBg1iZ/hBat0PPRxobmjpzkk0zlyq66s
         EfniSBxuubgYk+Tk0Ea/pNru5mLw2F4C8jEl1o3EMiKL0W5cQGEgwsY/BibAirnNYqjG
         VcqIqzb+W5kvmdjTRapQcMwgcNAjg3q/ikAszH0+/4sl8Ma2l26U9ZdqS5y7L1N1duw3
         P/4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XPRHX8pCREnsSk1YRrzZLVdhujdCryf2vEUusv4RzGgiXDKPH
	mfDadQnDGybKzOk6hDstEY4=
X-Google-Smtp-Source: ABdhPJxnh0qCU6eYEw9/fUhI3R+rWqNcw1g3Tzs6QTNWbXLX5+YvPW0pE5fJPg1CmRjmEKsE27k1iA==
X-Received: by 2002:aca:bdc4:: with SMTP id n187mr1385129oif.154.1606186827059;
        Mon, 23 Nov 2020 19:00:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4e95:: with SMTP id c143ls2069638oib.11.gmail; Mon, 23
 Nov 2020 19:00:26 -0800 (PST)
X-Received: by 2002:aca:6502:: with SMTP id m2mr1459455oim.105.1606186826708;
        Mon, 23 Nov 2020 19:00:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606186826; cv=none;
        d=google.com; s=arc-20160816;
        b=zWZz9eQzBOkIByIIWSJWmYyvUqp2wSIWU911SACKDtam4ddBqp6QwE33pfR08Lawlr
         qBYE3B6vdglfyfr+LqQ0QOnieat48nfHcINQXpV92F4/kwKYo7UVKhGLdK4Ax6T3eBqJ
         x3qMypK0e59QQVXzgikTr9/Ons342TzWjtXzot2NIuaZhlIw3Urr7GhQ4DBJuRCbhygw
         sj0njH2G4HPQAxgf01DxagCJKsSXHExNpPPx8KH+YVM8ZpdC3yXO08RiVgDG6n9nQlkY
         HJFaqI+O8u2p/3jvMkYrO8rbfNXP//edAWrAjibBk10jDKpROJR7PVmUkGv36EiGjW8x
         eeuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9dXI24aC8NvP/kqZdopSzP2LewH/N8Z0aB66LTLcHvE=;
        b=zI+bZfgADzROcT2xoW1nY+Xvj9WVOdgXG/PqJevn8KSN7rXc2ENHHra5tRLrSLH1g1
         t4uHGJ+OKYJRNDKOteRWUJFFmP8MAa6BgwTSl0542MSJDwyhy2K0JxsHNRug6Aoydbct
         0NbagXMYk5KQG0qQZkq1qKe2F4CtPpzQkFnuwk/sBEbSPJc0/JDLr7PCHvKOebmYLqBK
         k7fHbQ9jc5kHetboeBA5P4hKFAgVFOCiH0/GQxcLyH5n7BvTmx/n4xLRoC77aUtSbWZ/
         3GHtMwOJR1sE0j+Gjxo9Cl+lbnwrnswtoO9autHmFkftSG+CjnM8G0YAfyu67TQbJd6u
         L7ow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=WEqloDj3;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id j1si833105ooe.2.2020.11.23.19.00.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 19:00:26 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id k3so3115477qvz.4
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 19:00:26 -0800 (PST)
X-Received: by 2002:a05:6214:1150:: with SMTP id b16mr2543732qvt.46.1606186826260;
        Mon, 23 Nov 2020 19:00:26 -0800 (PST)
Received: from auth2-smtp.messagingengine.com (auth2-smtp.messagingengine.com. [66.111.4.228])
        by smtp.gmail.com with ESMTPSA id h8sm7294688qka.117.2020.11.23.19.00.24
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 23 Nov 2020 19:00:25 -0800 (PST)
Received: from compute5.internal (compute5.nyi.internal [10.202.2.45])
	by mailauth.nyi.internal (Postfix) with ESMTP id 657D527C0054;
	Mon, 23 Nov 2020 22:00:22 -0500 (EST)
Received: from mailfrontend2 ([10.202.2.163])
  by compute5.internal (MEProxy); Mon, 23 Nov 2020 22:00:22 -0500
X-ME-Sender: <xms:RHe8X8nhjwC9ixhL5bNug7kbvlycNZqxon1X4wu5mNxJu7Pz5XHf0g>
    <xme:RHe8X73UXz0fmmgs8tu8zgbAr1Nw9mYh8NkzcJoj8rXKvEDuTFXL9vwkZTK-ASN3d
    QZDjJiw2DCbpfpDkw>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedujedrudegjedgkeduucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepfffhvffukfhfgggtuggjsehttdertddttddvnecuhfhrohhmpeeuohhquhhn
    ucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilhdrtghomheqnecuggftrfgrth
    htvghrnhepvdelieegudfggeevjefhjeevueevieetjeeikedvgfejfeduheefhffggedv
    geejnecukfhppedufedurddutdejrddugeejrdduvdeinecuvehluhhsthgvrhfuihiivg
    eptdenucfrrghrrghmpehmrghilhhfrhhomhepsghoqhhunhdomhgvshhmthhprghuthhh
    phgvrhhsohhnrghlihhthidqieelvdeghedtieegqddujeejkeehheehvddqsghoqhhunh
    drfhgvnhhgpeepghhmrghilhdrtghomhesfhhigihmvgdrnhgrmhgv
X-ME-Proxy: <xmx:RHe8X6q6izYmjBpKOcIsrU1pCgaFljAMLFUewdqAuRkH2_JLAJyAOg>
    <xmx:RHe8X4mizohZZSst8rd3803nXlAmHpd2ubbbKKyTvK355jE_sqivHg>
    <xmx:RHe8X60OksZQ7bAe_ACtVM2KqOSGytjaaVAx5Qkma08-c0seT1M-gQ>
    <xmx:Rne8X12Cw0YTpE8tjQMdP_-IxdAg7c8bUkFwq2Nq7z4bvZi5_SpwtS8GpAc>
Received: from localhost (unknown [131.107.147.126])
	by mail.messagingengine.com (Postfix) with ESMTPA id 816D83064AB3;
	Mon, 23 Nov 2020 22:00:20 -0500 (EST)
Date: Tue, 24 Nov 2020 10:59:45 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Marco Elver <elver@google.com>, "Paul E. McKenney" <paulmck@kernel.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>, Tejun Heo <tj@kernel.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201124025945.GG286534@boqun-archlinux>
References: <20201113175754.GA6273@paulmck-ThinkPad-P72>
 <20201117105236.GA1964407@elver.google.com>
 <20201117182915.GM1437@paulmck-ThinkPad-P72>
 <20201118225621.GA1770130@elver.google.com>
 <20201118233841.GS1437@paulmck-ThinkPad-P72>
 <20201119125357.GA2084963@elver.google.com>
 <20201120142734.75af5cd6@gandalf.local.home>
 <20201123152720.GA2177956@elver.google.com>
 <20201123112812.19e918b3@gandalf.local.home>
 <20201123134227.6df443db@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201123134227.6df443db@gandalf.local.home>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=WEqloDj3;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f43
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

Hi Steven,

On Mon, Nov 23, 2020 at 01:42:27PM -0500, Steven Rostedt wrote:
> On Mon, 23 Nov 2020 11:28:12 -0500
> Steven Rostedt <rostedt@goodmis.org> wrote:
> 
> > I noticed:
> > 
> > 
> > [  237.650900] enabling event benchmark_event
> > 
> > In both traces. Could you disable CONFIG_TRACEPOINT_BENCHMARK and see if
> > the issue goes away. That event kicks off a thread that spins in a tight
> > loop for some time and could possibly cause some issues.
> > 
> > It still shouldn't break things, we can narrow it down if it is the culprit.
> 
> [ Added Thomas  ]
> 
> And that's just one issue. I don't think that has anything to do with the
> other one:
> 
> [ 1614.162007] rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
> [ 1614.168625]  (detected by 0, t=3752 jiffies, g=3529, q=1)
> [ 1614.170825] rcu: All QSes seen, last rcu_preempt kthread activity 242 (4295293115-4295292873), jiffies_till_next_fqs=1, root ->qsmask 0x0
> [ 1614.194272] 
> [ 1614.196673] ================================
> [ 1614.199738] WARNING: inconsistent lock state
> [ 1614.203056] 5.10.0-rc4-next-20201119-00004-g77838ee21ff6-dirty #21 Not tainted
> [ 1614.207012] --------------------------------
> [ 1614.210125] inconsistent {IN-HARDIRQ-W} -> {HARDIRQ-ON-W} usage.
> [ 1614.213832] swapper/0/1 [HC0[0]:SC0[0]:HE0:SE1] takes:
> [ 1614.217288] ffffd942547f47d8 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x7c0/0x17a0
> [ 1614.225496] {IN-HARDIRQ-W} state was registered at:
> [ 1614.229031]   __lock_acquire+0xae8/0x1ac8
> [ 1614.232203]   lock_acquire+0x268/0x508
> [ 1614.235254]   _raw_spin_lock_irqsave+0x78/0x14c
> [ 1614.238547]   rcu_sched_clock_irq+0x7c0/0x17a0
> [ 1614.241757]   update_process_times+0x6c/0xb8
> [ 1614.244950]   tick_sched_handle.isra.0+0x58/0x88
> [ 1614.248225]   tick_sched_timer+0x68/0xe0
> [ 1614.251304]   __hrtimer_run_queues+0x288/0x730
> [ 1614.254516]   hrtimer_interrupt+0x114/0x288
> [ 1614.257650]   arch_timer_handler_virt+0x50/0x70
> [ 1614.260922]   handle_percpu_devid_irq+0x104/0x4c0
> [ 1614.264236]   generic_handle_irq+0x54/0x78
> [ 1614.267385]   __handle_domain_irq+0xac/0x130
> [ 1614.270585]   gic_handle_irq+0x70/0x108
> [ 1614.273633]   el1_irq+0xc0/0x180
> [ 1614.276526]   rcu_irq_exit_irqson+0x40/0x78
> [ 1614.279704]   trace_preempt_on+0x144/0x1a0
> [ 1614.282834]   preempt_schedule_common+0xf8/0x1a8
> [ 1614.286126]   preempt_schedule+0x38/0x40
> [ 1614.289240]   __mutex_lock+0x608/0x8e8
> [ 1614.292302]   mutex_lock_nested+0x3c/0x58
> [ 1614.295450]   static_key_enable_cpuslocked+0x7c/0xf8
> [ 1614.298828]   static_key_enable+0x2c/0x40
> [ 1614.301961]   tracepoint_probe_register_prio+0x284/0x3a0
> [ 1614.305464]   tracepoint_probe_register+0x40/0x58
> [ 1614.308776]   trace_event_reg+0xe8/0x150
> [ 1614.311852]   __ftrace_event_enable_disable+0x2e8/0x608
> [ 1614.315351]   __ftrace_set_clr_event_nolock+0x160/0x1d8
> [ 1614.318809]   __ftrace_set_clr_event+0x60/0x90
> [ 1614.322061]   event_trace_self_tests+0x64/0x12c
> [ 1614.325335]   event_trace_self_tests_init+0x88/0xa8
> [ 1614.328758]   do_one_initcall+0xa4/0x500
> [ 1614.331860]   kernel_init_freeable+0x344/0x3c4
> [ 1614.335110]   kernel_init+0x20/0x16c
> [ 1614.338102]   ret_from_fork+0x10/0x34
> [ 1614.341057] irq event stamp: 3206302
> [ 1614.344123] hardirqs last  enabled at (3206301): [<ffffd9425238da04>] rcu_irq_exit_irqson+0x64/0x78
> [ 1614.348697] hardirqs last disabled at (3206302): [<ffffd942522123c0>] el1_irq+0x80/0x180
> [ 1614.353013] softirqs last  enabled at (3204216): [<ffffd94252210b80>] __do_softirq+0x630/0x6b4
> [ 1614.357509] softirqs last disabled at (3204191): [<ffffd942522c623c>] irq_exit+0x1cc/0x1e0
> [ 1614.361737] 
> [ 1614.361737] other info that might help us debug this:
> [ 1614.365566]  Possible unsafe locking scenario:
> [ 1614.365566] 
> [ 1614.369128]        CPU0
> [ 1614.371747]        ----
> [ 1614.374282]   lock(rcu_node_0);
> [ 1614.378818]   <Interrupt>
> [ 1614.381394]     lock(rcu_node_0);
> [ 1614.385997] 
> [ 1614.385997]  *** DEADLOCK ***
> [ 1614.385997] 
> [ 1614.389613] 5 locks held by swapper/0/1:
> [ 1614.392655]  #0: ffffd9425480e940 (event_mutex){+.+.}-{3:3}, at: __ftrace_set_clr_event+0x48/0x90
> [ 1614.401701]  #1: ffffd9425480a530 (tracepoints_mutex){+.+.}-{3:3}, at: tracepoint_probe_register_prio+0x48/0x3a0
> [ 1614.410973]  #2: ffffd9425476abf0 (cpu_hotplug_lock){++++}-{0:0}, at: static_key_enable+0x24/0x40
> [ 1614.419858]  #3: ffffd94254816348 (jump_label_mutex){+.+.}-{3:3}, at: static_key_enable_cpuslocked+0x7c/0xf8
> [ 1614.429049]  #4: ffffd942547f47d8 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x7c0/0x17a0
> [ 1614.438029] 
> [ 1614.438029] stack backtrace:
> [ 1614.441436] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.10.0-rc4-next-20201119-00004-g77838ee21ff6-dirty #21
> [ 1614.446149] Hardware name: linux,dummy-virt (DT)
> [ 1614.449621] Call trace:
> [ 1614.452337]  dump_backtrace+0x0/0x240
> [ 1614.455372]  show_stack+0x34/0x88
> [ 1614.458306]  dump_stack+0x140/0x1bc
> [ 1614.461258]  print_usage_bug+0x2a0/0x2f0
> [ 1614.464399]  mark_lock.part.0+0x438/0x4e8
> [ 1614.467528]  mark_held_locks+0x54/0x90
> [ 1614.470576]  lockdep_hardirqs_on_prepare+0xe0/0x290
> [ 1614.473935]  trace_hardirqs_on+0x90/0x370
> [ 1614.477045]  el1_irq+0xdc/0x180
> [ 1614.479934]  rcu_irq_exit_irqson+0x40/0x78
> [ 1614.483093]  trace_preempt_on+0x144/0x1a0
> [ 1614.486211]  preempt_schedule_common+0xf8/0x1a8
> [ 1614.489479]  preempt_schedule+0x38/0x40
> [ 1614.492544]  __mutex_lock+0x608/0x8e8
> 
> 
> The above has:
> 
>  preempt_schedule_common() {
>    trace_preempt_on() {
>      <interrupt>
> 	el1_irq:
> 	   handle_arch_irq {
> 	      irq_enter();
> 	      [..]
> 	      irq_exit();
> 	   }
> 	   bl trace_hardirqs_on
> 
> 
> I wonder if the lockdep logic got confused on ARM64 by the rework done to
> lockdep and tracing with respect to irq entry / exit.
> 

I'm also staring at this problem and another thing caused my attention
is that there is a line like the following after the lockdep splat:

[...] BUG: scheduling while atomic ...

, which means preemption count has some inconsistency too.

Given this, a possible case cause this is that we got preempted inside a
rcu_node lock critical section (I know, this is quite impossible, but
preemption count and lockdep data are maintained quite separately, so
it's unlikely they are broken at the same time...)

Will continue to look into this.

Regards,
Boqun

> Or maybe there's an rcu_node leak lock that happened somewhere?
> 
> -- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201124025945.GG286534%40boqun-archlinux.
