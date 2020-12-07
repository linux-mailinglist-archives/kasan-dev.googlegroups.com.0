Return-Path: <kasan-dev+bncBC6LHPWNU4DBBUXCW37AKGQEZWE4WZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 92CDF2D09BF
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 05:36:35 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id w22sf3050540uau.9
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Dec 2020 20:36:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607315794; cv=pass;
        d=google.com; s=arc-20160816;
        b=zy3wX+7SY9ewbPiLR9smokzwbwWZzHqG4zv7LwobE5nkLKQbW1C6wv/pcjPt4Q3Wkk
         Jg9v23kNyvlVnUQ0Nt0HUzppPVzGerbfWwsHdH7CW5a78md3PlQxDvScsZPNcR2thAWp
         H6yl1rFlKJq9KwlGn9i23bM8IPEQnYfJzAOUAWrMgucuZOpY2Lvhez/I5iHO2GuxoXrx
         mgW++MCIyQnRxGfidA6M9NM606qC4QD9vf6f83ziCCOodvjGwP3adsRQ13Jzs93IRHVq
         OxOnoWOuM0TlBV9uBY5WHaESl/aX7UpXZZeZmk0O8mAZKdPnMucz6PX6qYoH9+bCSH7r
         bmoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=eozDSdAJ2pVN+SNukkEa5zTlGJI6tUTVvxZ9xfqvziI=;
        b=E85GDxJdEc30XFxAWmiejXxh+OVO9PXPEJ9C0Rrxg859wHC1Zv2Q28iG+mEml4p0Zo
         VAfYRY9t4qGSpfrkspOMb00pl5M5VAPz0EgquITepnDBY5yX8EnPu+Pt/Mywo90uDY7r
         6KjknhWJW2a0Lk15sgK0mVUtws2atVoR19N1DpvQcWAlyrQO22ZZZIVK6j9ADAqtO2yK
         8bcM1TxHyw31rEStoiWo0CPYMnNXXpAn5OQ6MgoJj0ReTzrjWGDFjpnpu9sRih9Lc4GT
         dSfr3Z+r7w72iEgIOuTBqmk1oB7lBDklcGGRYE4julGpfzQaaSVqEBk71sKcOYNJFDp1
         1kZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=sj1rdYyC;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eozDSdAJ2pVN+SNukkEa5zTlGJI6tUTVvxZ9xfqvziI=;
        b=BSbuwqnBwNF0smWI+HjM0P6ivUF0ao+WRLS78TLq0CImE1dst32u6W8inW1P4cJhG0
         yCzAqOTBifoB6Qik7/iAdcryqVV3qz2zK1/LiI9CZO78O4mk8n3SfQjaWGOjjp0XFa67
         +ddOD5CDdXSy3aHKvV9dcY+yYAe2TmDiDhU0WxH8+Kx2tz1elz69Tvg3mfwLTP8lGpZO
         H0L/C0QZVO3w75CuxTRs+3ks44UL7Xs9jlylHMfEwQe6T92hwyEQcnVZ7cWPCwH88n9c
         43zqLTVlI2MFH3VUQsUAF+/mMETri3SGB6PpqyAGavJjNepkz/uTCAOQiMZ0O4V3yxm0
         rVUQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eozDSdAJ2pVN+SNukkEa5zTlGJI6tUTVvxZ9xfqvziI=;
        b=id6PDG3fHUXbn462WPuyFk8j/PuRBDsfUHg/YfeGhiaeJHJs3KPCbwC79IGVsYIsC0
         QxEeTNf3EH8CmgfgP8SGEHCTEK43ZVAEzT/Q0SzVeVyZcPsv62Ncq5oXK17qrzRqCsk/
         taGJp4aXRj6TG4S2khfvj9nuGXJG58IBobqnl95a2x0zW3R3QUcIUAhQk6tWTNiaHRFx
         ZRI4uunLMPrTOrg9lDRHz/Gl6LZCnVR41dL/+TT+eo2ZN+DhiQlFIuVRYXuJt4Aalj0/
         c7+v64qC+4IjOd8oLyxy6yw+0dpJsWYY7+qh1ZBwm9vey6gVBi4l0xGlM7ViAdGqTK7s
         1/EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eozDSdAJ2pVN+SNukkEa5zTlGJI6tUTVvxZ9xfqvziI=;
        b=VvQDRm4s1aiYhTEFQ/toEHofvoHYx3wiPbkJG+OKkFIwIXQnH7BkLi+XfoIZDPb+Vi
         SEYw6XXZE5C9Yw2L3AnniCMM7St4hp6l9y7XAw+CrdHfYKyjFYxwCAX1WJiju2QfA8R7
         uHc0H9eEb/5j2Owc71tNMDuqpdhkxUXMwu/xMW8VDh+XJNM6QngmgYNd1VQepAYvamN8
         lDlhJgIUB7ViSomfOI0D2eLaVwWEh/Sb8fm94PjDTCb83hAjrGBLe1kmCcoOHIP+M3h6
         keTqQvHqiIOlOENhC3gfuOGMwdK6sXEueN6SDslXtPeYgV89HW1aVcDMVMCJdoH2KxEU
         Rndw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531+E69OQTz1tqsTUesjx9l47EOeG5Sogh6DFcufB4Zrr+vB+xgO
	zHvnEoR247ciWz97ZLdsTeM=
X-Google-Smtp-Source: ABdhPJw5xsc5rIaOirnz7gcUV9hcXPuM9KMboudcbFx1qW1YoNOCUpzzvzygZyXV1WfZ/OftnMtl/A==
X-Received: by 2002:ac5:cc66:: with SMTP id w6mr11798995vkm.8.1607315794265;
        Sun, 06 Dec 2020 20:36:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f315:: with SMTP id p21ls2007868vsf.6.gmail; Sun, 06 Dec
 2020 20:36:33 -0800 (PST)
X-Received: by 2002:a67:e90d:: with SMTP id c13mr11167885vso.0.1607315793648;
        Sun, 06 Dec 2020 20:36:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607315793; cv=none;
        d=google.com; s=arc-20160816;
        b=EJn5+8t9MBA4/EHCXLfW5KXXpq/mJB2NKbOZLLIFoTsUJn54iJCfhH5sBFmQ2mdFhM
         1y1t0tghAn19s8D5LFInOBR0F/wNY1eksWpWQ8AAzJfT1qRIBynVetwxu02gRN6JbAyn
         cjBnlkv8sxk3QNnBfupPFsu2MV6g1OQLr/ETZkgBfTMxRNqCgpGu9md3qBS5b83+G1DF
         vdWzhj/STnyUh9ITjHg8BsRhHqlzMUg9GTmQagjcSpN8W0iM548Eeow+43XsSTz2+5LT
         Y3+jT+YGV7u+pj98AVEj9p3Ryp4Zoj7P4O7MOi/WwxSJHk2YwMQcg9X0oJFHFPziJqw6
         Xahw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=PoCu/gkPCtJA4+Ph0vwwuZbEYcCZQAZIGlTEAffIyVI=;
        b=FW1uqgTt0UB88Oqa4VVc2Zx9myksU93dvU5tQyk11tIRys1+SyLmC7btwyUiU/TsrO
         T004wjtvWZiuQOf8VAJsXba3wV6uf20urjcKDBzc8NrfHXkSrlrVLdhGM5aFCCmxGtoQ
         /VdjPN1HA//7eT66IjfzdniW2jWwTgQpiF+eaegVCTq3V52HPqoR4i+ZWROSTtJAPEZO
         /UE/BQlwR/wWlwMAzf2eMcZ7TjVx7bTE/0fUfZaXg97k2h3r6Ad3Yg05rqt/WO/7szgK
         7UcHKSwzlqQDq327fNvFYBVsxgjCsoyEB9Z10DhZmgEYwFGXxQxPmTLSs3JfF8mkdhld
         1KzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=sj1rdYyC;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf2e.google.com (mail-qv1-xf2e.google.com. [2607:f8b0:4864:20::f2e])
        by gmr-mx.google.com with ESMTPS id e2si887602vkk.0.2020.12.06.20.36.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 06 Dec 2020 20:36:33 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f2e as permitted sender) client-ip=2607:f8b0:4864:20::f2e;
Received: by mail-qv1-xf2e.google.com with SMTP id l7so595551qvt.4
        for <kasan-dev@googlegroups.com>; Sun, 06 Dec 2020 20:36:33 -0800 (PST)
X-Received: by 2002:a05:6214:a69:: with SMTP id ef9mr19584244qvb.50.1607315793282;
        Sun, 06 Dec 2020 20:36:33 -0800 (PST)
Received: from auth1-smtp.messagingengine.com (auth1-smtp.messagingengine.com. [66.111.4.227])
        by smtp.gmail.com with ESMTPSA id 97sm11085298qte.34.2020.12.06.20.36.31
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 06 Dec 2020 20:36:32 -0800 (PST)
Received: from compute5.internal (compute5.nyi.internal [10.202.2.45])
	by mailauth.nyi.internal (Postfix) with ESMTP id DD31527C0054;
	Sun,  6 Dec 2020 23:36:30 -0500 (EST)
Received: from mailfrontend2 ([10.202.2.163])
  by compute5.internal (MEProxy); Sun, 06 Dec 2020 23:36:30 -0500
X-ME-Sender: <xms:TrHNXz17NTmjBd8wE76nEExPyjVL6lPim4p_iQJ2LiGO9Y3Iv7xrTQ>
    <xme:TrHNXyFjsDKFbiFgp836LESHmqxShyHh9KpcYDp7FBt3vcXtDdeEbByhK_J2yqfOI
    ymILOeETSU7JU1Muw>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedujedrudejfedgieelucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepfffhvffukfhfgggtuggjsehttdertddttddvnecuhfhrohhmpeeuohhquhhn
    ucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilhdrtghomheqnecuggftrfgrth
    htvghrnhepgeekgeffffefudeuhfekveehieevffelteegffehhfelgfevteeukeejfedt
    keefnecuffhomhgrihhnpehophgvnhhsuhhsvgdrohhrghenucfkphepudefuddruddtje
    drudegjedruddvieenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhl
    fhhrohhmpegsohhquhhnodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdeile
    dvgeehtdeigedqudejjeekheehhedvqdgsohhquhhnrdhfvghngheppehgmhgrihhlrdgt
    ohhmsehfihigmhgvrdhnrghmvg
X-ME-Proxy: <xmx:TrHNXz4z9gXfO61knisO6uYhQ3gfwVcQsRbv15dBy9p6pHa8OYd9nA>
    <xmx:TrHNX43x6AGLWgzDFMqkv2tD-VVYN2W4OrY5Sn4kC8kMLFFRApmYdQ>
    <xmx:TrHNX2FLc0lMUpaTZq1SbS7OF3dldQ9DDOXaCrAuyFI64YZo890Cnw>
    <xmx:TrHNX5337Hyf0XU_a0Afmg1VqVFhaO_zWbVePRTYIB0fq28Na57fRQ>
Received: from localhost (unknown [131.107.147.126])
	by mail.messagingengine.com (Postfix) with ESMTPA id E2F96108005B;
	Sun,  6 Dec 2020 23:36:29 -0500 (EST)
Date: Mon, 7 Dec 2020 12:35:18 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Richard Weinberger <richard.weinberger@gmail.com>
Cc: LKML <linux-kernel@vger.kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>, aryabinin@virtuozzo.com,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>
Subject: Re: BUG: Invalid wait context with KMEMLEAK and KASAN enabled
Message-ID: <20201207043518.GA1819081@boqun-archlinux>
References: <CAFLxGvwienJ7sU2+QAhFt+ywS9iYkbAXDGviuTC-4CVwLOhXfA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAFLxGvwienJ7sU2+QAhFt+ywS9iYkbAXDGviuTC-4CVwLOhXfA@mail.gmail.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=sj1rdYyC;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f2e
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

Hi Richard,

On Sun, Dec 06, 2020 at 11:59:16PM +0100, Richard Weinberger wrote:
> Hi!
> 
> With both KMEMLEAK and KASAN enabled, I'm facing the following lockdep
> splat at random times on Linus' tree as of today.
> Sometimes it happens at bootup, sometimes much later when userspace has started.
> 
> Does this ring a bell?
> 
> [    2.298447] =============================
> [    2.298971] [ BUG: Invalid wait context ]
> [    2.298971] 5.10.0-rc6+ #388 Not tainted
> [    2.298971] -----------------------------
> [    2.298971] ksoftirqd/1/15 is trying to lock:
> [    2.298971] ffff888100b94598 (&n->list_lock){....}-{3:3}, at:
> free_debug_processing+0x3d/0x210

I guest you also had CONFIG_PROVE_RAW_LOCK_NESTING=y, right? With that
config, the wait context detetion of lockdep will treat spinlock_t as
sleepable locks (considering PREEMPT_RT kernel), and here it complained
about trying to acquire a sleepable lock (in PREEMPT_RT kernel) inside a
irq context which cannot be threaded (in this case, it's the IPI). A
proper fix will be modifying kmem_cache_node->list_lock to
raw_spinlock_t.

Regards,
Boqun

> [    2.298971] other info that might help us debug this:
> [    2.298971] context-{2:2}
> [    2.298971] 1 lock held by ksoftirqd/1/15:
> [    2.298971]  #0: ffffffff835f4140 (rcu_callback){....}-{0:0}, at:
> rcu_core+0x408/0x1040
> [    2.298971] stack backtrace:
> [    2.298971] CPU: 1 PID: 15 Comm: ksoftirqd/1 Not tainted 5.10.0-rc6+ #388
> [    2.298971] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
> BIOS rel-1.12.0-0-ga698c89-rebuilt.opensuse.org 04/01/2014
> [    2.298971] Call Trace:
> [    2.298971]  <IRQ>
> [    2.298971]  dump_stack+0x9a/0xcc
> [    2.298971]  __lock_acquire.cold+0xce/0x34b
> [    2.298971]  ? lockdep_hardirqs_on_prepare+0x1f0/0x1f0
> [    2.298971]  ? rcu_read_lock_sched_held+0x9c/0xd0
> [    2.298971]  lock_acquire+0x153/0x4c0
> [    2.298971]  ? free_debug_processing+0x3d/0x210
> [    2.298971]  ? lock_release+0x690/0x690
> [    2.298971]  ? rcu_read_lock_bh_held+0xb0/0xb0
> [    2.298971]  ? pvclock_clocksource_read+0xd9/0x1a0
> [    2.298971]  _raw_spin_lock_irqsave+0x3b/0x80
> [    2.298971]  ? free_debug_processing+0x3d/0x210
> [    2.298971]  ? qlist_free_all+0x35/0xd0
> [    2.298971]  free_debug_processing+0x3d/0x210
> [    2.298971]  __slab_free+0x286/0x490
> [    2.298971]  ? lockdep_enabled+0x39/0x50
> [    2.298971]  ? rcu_read_lock_sched_held+0x9c/0xd0
> [    2.298971]  ? run_posix_cpu_timers+0x256/0x2c0
> [    2.298971]  ? rcu_read_lock_bh_held+0xb0/0xb0
> [    2.298971]  ? posix_cpu_timers_exit_group+0x30/0x30
> [    2.298971]  qlist_free_all+0x59/0xd0
> [    2.298971]  ? qlist_free_all+0xd0/0xd0
> [    2.298971]  per_cpu_remove_cache+0x47/0x50
> [    2.298971]  flush_smp_call_function_queue+0xea/0x2b0
> [    2.298971]  __sysvec_call_function+0x6c/0x250
> [    2.298971]  asm_call_irq_on_stack+0x12/0x20
> [    2.298971]  </IRQ>
> [    2.298971]  sysvec_call_function+0x84/0xa0
> [    2.298971]  asm_sysvec_call_function+0x12/0x20
> [    2.298971] RIP: 0010:__asan_load4+0x1d/0x80
> [    2.298971] Code: 10 00 75 ee c3 0f 1f 84 00 00 00 00 00 4c 8b 04
> 24 48 83 ff fb 77 4d 48 b8 ff ff ff ff ff 7f ff ff 48 39 c7 76 3e 48
> 8d 47 03 <48> 89 c2 83 e2 07 48 83 fa 02 76 17 48 b9 00 00 00 00 00 fc
> ff df
> [    2.298971] RSP: 0000:ffff888100e4f858 EFLAGS: 00000216
> [    2.298971] RAX: ffffffff83c55773 RBX: ffffffff81002431 RCX: dffffc0000000000
> [    2.298971] RDX: 0000000000000001 RSI: ffffffff83ee8d78 RDI: ffffffff83c55770
> [    2.298971] RBP: ffffffff83c5576c R08: ffffffff81083433 R09: fffffbfff07e333d
> [    2.298971] R10: 000000000001803d R11: fffffbfff07e333c R12: ffffffff83c5575c
> [    2.298971] R13: ffffffff83c55774 R14: ffffffff83c55770 R15: ffffffff83c55770
> [    2.298971]  ? ret_from_fork+0x21/0x30
> [    2.298971]  ? __orc_find+0x63/0xc0
> [    2.298971]  ? stack_access_ok+0x35/0x90
> [    2.298971]  __orc_find+0x63/0xc0
> [    2.298971]  unwind_next_frame+0x1ee/0xbd0
> [    2.298971]  ? ret_from_fork+0x22/0x30
> [    2.298971]  ? ret_from_fork+0x21/0x30
> [    2.298971]  ? deref_stack_reg+0x40/0x40
> [    2.298971]  ? __unwind_start+0x2e8/0x370
> [    2.298971]  ? create_prof_cpu_mask+0x20/0x20
> [    2.298971]  arch_stack_walk+0x83/0xf0
> [    2.298971]  ? ret_from_fork+0x22/0x30
> [    2.298971]  ? rcu_core+0x488/0x1040
> [    2.298971]  stack_trace_save+0x8c/0xc0
> [    2.298971]  ? stack_trace_consume_entry+0x80/0x80
> [    2.298971]  ? sched_clock_local+0x99/0xc0
> [    2.298971]  kasan_save_stack+0x1b/0x40
> [    2.298971]  ? kasan_save_stack+0x1b/0x40
> [    2.298971]  ? kasan_set_track+0x1c/0x30
> [    2.298971]  ? kasan_set_free_info+0x1b/0x30
> [    2.298971]  ? __kasan_slab_free+0x10f/0x150
> [    2.298971]  ? kmem_cache_free+0xa8/0x350
> [    2.298971]  ? rcu_core+0x488/0x1040
> [    2.298971]  ? __do_softirq+0x101/0x573
> [    2.298971]  ? run_ksoftirqd+0x21/0x50
> [    2.298971]  ? smpboot_thread_fn+0x1fc/0x380
> [    2.298971]  ? kthread+0x1c7/0x220
> [    2.298971]  ? ret_from_fork+0x22/0x30
> [    2.298971]  ? lockdep_hardirqs_on_prepare+0x1f0/0x1f0
> [    2.298971]  ? rcu_read_lock_sched_held+0x9c/0xd0
> [    2.298971]  ? lock_acquire+0x153/0x4c0
> [    2.298971]  ? rcu_core+0x408/0x1040
> [    2.298971]  ? lock_release+0x690/0x690
> [    2.298971]  ? lockdep_enabled+0x39/0x50
> [    2.298971]  ? mark_held_locks+0x49/0x90
> [    2.298971]  kasan_set_track+0x1c/0x30
> [    2.298971]  kasan_set_free_info+0x1b/0x30
> [    2.298971]  __kasan_slab_free+0x10f/0x150
> [    2.298971]  ? rcu_core+0x488/0x1040
> [    2.298971]  kmem_cache_free+0xa8/0x350
> [    2.298971]  ? __ia32_compat_sys_move_pages+0x130/0x130
> [    2.298971]  rcu_core+0x488/0x1040
> [    2.298971]  ? call_rcu+0x5d0/0x5d0
> [    2.298971]  ? rcu_read_lock_sched_held+0x9c/0xd0
> [    2.298971]  ? rcu_read_lock_bh_held+0xb0/0xb0
> [    2.298971]  __do_softirq+0x101/0x573
> [    2.298971]  ? trace_event_raw_event_irq_handler_exit+0x150/0x150
> [    2.298971]  run_ksoftirqd+0x21/0x50
> [    2.298971]  smpboot_thread_fn+0x1fc/0x380
> [    2.298971]  ? smpboot_register_percpu_thread+0x180/0x180
> [    2.298971]  ? __kthread_parkme+0xbb/0xd0
> [    2.298971]  ? smpboot_register_percpu_thread+0x180/0x180
> [    2.298971]  kthread+0x1c7/0x220
> [    2.298971]  ? kthread_create_on_node+0xd0/0xd0
> [    2.298971]  ret_from_fork+0x22/0x30
> 
> -- 
> Thanks,
> //richard

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201207043518.GA1819081%40boqun-archlinux.
