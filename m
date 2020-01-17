Return-Path: <kasan-dev+bncBCD3NZ4T2IKRB7OPQ7YQKGQE2AZFOVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id BC94B140F7D
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 17:59:42 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id u10sf15859114qkk.1
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 08:59:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579280381; cv=pass;
        d=google.com; s=arc-20160816;
        b=NQH0e7tzUBCtn3dDPRuGu5J3RE3O0sTc0pyQDd6Q81vYWrSRy5xcX9vwA2bGNKRYKc
         AQMgNHs1cXin+m27LV9rEuUqRrPn8Qe79MP6rhS92rN7L+PvMRBFwiyl7RQ8t+rV8bIx
         R90Wk9TVkKTUrcQp+VXSX/aqIT3z31J+J71/kCaUZVYAX9EkHvmXnH6mo9eHAZKRY2Cy
         Gpqn68dKS+ZDPWoqXWrkA44VMwfdZ055F8wgChd7jOyvCh1sSAY7ISLtTxsG8SIaLDS2
         Ap1yjOQWfL1IoaWgQeEwbGQkofD4/sZahxBEwMt1THAqjcou6uCBa+4wP26sVi7pocX5
         RSqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:sender:dkim-signature;
        bh=ayRqe+5RZ6AeqOZ8lTQPZ1yIbtr6H+AYzlBIjWeW1JU=;
        b=anPorJVA84MgM34VTRUtFE7Ao44CBxrsFJNZnpo8ZVDTQYRGXHKv63rFh04snDlSn2
         SJEi2SGHHNktS62fi5opvtMCtd9tpyBOItlxD/iXmd6jK/PshQro7Ayg/hUPNqbfdNd7
         01fHhREjsV/P2TMBYRtuMfDI0awaP51aNA/ym9Rno75kPkOW87aHwa9f5Cohud9f2HOc
         UZ21JDCEqq/BE0Caa9D4j/MjY5k66kyZYBEb/NSYlQ7jrjz6lo0P2pd122Kn5txM+bXF
         ij2nzO64fhNUkS0X0gWpM1mEO968S026C0y5+yG+wwu189TLnMpK8rL5O10SeZE8UyDV
         bIMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=fC8+V8B4;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:mime-version:subject:date:message-id:references:cc
         :in-reply-to:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ayRqe+5RZ6AeqOZ8lTQPZ1yIbtr6H+AYzlBIjWeW1JU=;
        b=BmoLulCbFGepWVRB2CB+V4LQUVBKXMObOp8r2Cb8mlhNDSTHv+lIGi3qBwTK4CWSFC
         920asPapIaQxGbMmW81JY4I/OnLc0rOenyZuZBvMCvDb13Jt+LXRWcesd6XU/+0hWH/3
         5npvtvpMs+skw2gFd1iamAGyaFywRzE+43Z/z8qlHmyco0Fim9KCMFhcqH1OA4Q6hcrE
         +2/pllvIhybPqgw7K1fYiRQvPiCMqsBj0shLMHhZTMhrTaVk2ZJ+C3kPfToZYi6eecNF
         gMJjMlVWGHeoQLEOy3uSk0KOe3EEYe2irogp4KemavVw0DOw3r4VuHhxueFXujqmNuki
         vYvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:mime-version:subject:date:message-id
         :references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ayRqe+5RZ6AeqOZ8lTQPZ1yIbtr6H+AYzlBIjWeW1JU=;
        b=UR9RNsdi+MuuZU+6azbQaLpwL03W+XKPB/B7UF1GKCPe9Pv2yRWWGNJpsPIazayMlM
         Df0m+mIWYejlfQigZwUFdi8L3tXSCnZllzh+aft+fmYZCbHOKjpm/81ieXDC4jLZfoct
         egEG0hhkz4XW9UXc7eTZbjZdmBadC1sQ791fmM7uHxrawVQf8znJQ6pRu0o96waQ9qRC
         EhsKVaVVYqYksmPEHUlQwi/0lwhuOQC4n2Uig5Dr/gRvlSdsjs+Hh8PKyx/oQl2nGixe
         0lnS8gp3ZSJw3WTEk5y7AZvihmxaytrZpsNOEtGjcUbofFS1bYBwtOBpRHWYQns0/82s
         x+RQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVCVcBeRfeVDg/B6KJLa70wSb8AGjVKsGryQVEaUdI5H9TwN4pn
	Vd/KxJilEFTOwDSd3Dp46bA=
X-Google-Smtp-Source: APXvYqyvlBBW34MW/IooLsP1OslUWchF8sCosFTj+Mx9ys52Vr2dO65Wxl+zV0T/VCY1T+kOc+DXyw==
X-Received: by 2002:ac8:21ae:: with SMTP id 43mr8466298qty.223.1579280381778;
        Fri, 17 Jan 2020 08:59:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1763:: with SMTP id et3ls4908508qvb.5.gmail; Fri,
 17 Jan 2020 08:59:41 -0800 (PST)
X-Received: by 2002:a0c:b38b:: with SMTP id t11mr8302892qve.192.1579280381063;
        Fri, 17 Jan 2020 08:59:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579280381; cv=none;
        d=google.com; s=arc-20160816;
        b=RV09YZc71pYl6lJeDytD+iVRjurxd3R4hkyxFYb26d6NZfT+P0abk5Zkz1EIltDmCN
         jpdfHTicXlDYT4UQjc4xC4S2kJmKl0GmdmeTZFUEdT72GBhwW8X0909sW6xP4oDNXSHY
         bcusLOeVEEEALziDwd8TtMGs5wFOxbOdj4VgNIb/pWI9dWfUpYKBE4iJfob3qhjN7G3W
         zyeYPlWVsiLxhBH+yJt90RY0ZCn5LdL+2O+6/O9QQNYizhjj5l7+Z5FuJahf+86zB+9G
         Xz3c74xCiBR0OONcPrCOzMZNYxAlcF7jOar9eTxz0Ge47E7TUNkAdK5F8DiKgZtUcZRi
         p+rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=qmz6hTLuOQmdpf5d+5xaf/MlGzIX54pPDySUObs3zSo=;
        b=Zna4qSbreOtO9gQb50e/WhYqw9yJ1Hd4fMj3An5swHxf+wQqpPHSGNAbpOJhdrV1MM
         1z1CnCjeXp76fiKQ56Nkmp8A8xZ1wAR5MnJRFY2mdltfLvSPuoItJtfjC0Z7osDWBVzs
         ULa1v3QrzdtTR1f/tFmHBAnimMdo5feC6xcTcGZqJalrIOuD88+NobQlDeKTXNXhfwy1
         fCEaOcT+Xl+RxvBArYX5glb3hzMSlI0/9c07KaJh20zc2BWv3H3YDjxfNbeAiwtAdTrC
         fgtiypj85HPDnOe3hOF42iLx7nOjMqCPt3W/g9Ag4TXtscrbQl4WCdLpMG+XiScj2+BU
         uFsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=fC8+V8B4;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id y2si1228579qtj.5.2020.01.17.08.59.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 08:59:41 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id c16so23323439qko.6
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 08:59:41 -0800 (PST)
X-Received: by 2002:a05:620a:164e:: with SMTP id c14mr37395038qko.19.1579280380505;
        Fri, 17 Jan 2020 08:59:40 -0800 (PST)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id 21sm12014926qky.41.2020.01.17.08.59.39
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 08:59:40 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH -rcu] kcsan: Make KCSAN compatible with lockdep
Date: Fri, 17 Jan 2020 11:59:39 -0500
Message-Id: <3760F60F-4133-4FE1-9A4C-F335A8230285@lca.pw>
References: <20200117164017.GA21582@paulmck-ThinkPad-P72>
Cc: Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Dmitriy Vyukov <dvyukov@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>
In-Reply-To: <20200117164017.GA21582@paulmck-ThinkPad-P72>
To: paulmck@kernel.org
X-Mailer: iPhone Mail (17C54)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=fC8+V8B4;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Jan 17, 2020, at 11:40 AM, Paul E. McKenney <paulmck@kernel.org> wrote:
> 
> True enough, but even if we reach the nirvana state where there is general
> agreement on what constitutes a data race in need of fixing and KCSAN
> faithfully checks based on that data-race definition, we need to handle
> the case where someone introduces a bug that results in a destructive
> off-CPU access to a per-CPU variable, which is exactly the sort of thing
> that KCSAN is supposed to detect.  But suppose that this variable is
> frequently referenced from functions that are inlined all over the place.
> 
> Then that one bug might result in huge numbers of data-race reports in
> a very short period of time, especially on a large system.

It sounds like the case with debug_pagealloc where it prints a spam of those, and then the system is just dead.

[   28.992752][  T394] Reported by Kernel Concurrency Sanitizer on: 
[   28.992752][  T394] CPU: 0 PID: 394 Comm: pgdatinit0 Not tainted 5.5.0-rc6-next-20200115+ #3 
[   28.992752][  T394] Hardware name: HP ProLiant XL230a Gen9/ProLiant XL230a Gen9, BIOS U13 01/22/2018 
[   28.992752][  T394] =============================================================== 
[   28.992752][  T394] ================================================================== 
[   28.992752][  T394] BUG: KCSAN: data-race in __change_page_attr / __change_page_attr 
[   28.992752][  T394]  
[   28.992752][  T394] read to 0xffffffffa01a6de0 of 8 bytes by task 395 on cpu 16: 
[   28.992752][  T394]  __change_page_attr+0xe81/0x1620 
[   28.992752][  T394]  __change_page_attr_set_clr+0xde/0x4c0 
[   28.992752][  T394]  __set_pages_np+0xcc/0x100 
[   28.992752][  T394]  __kernel_map_pages+0xd6/0xdb 
[   28.992752][  T394]  __free_pages_ok+0x1a8/0x730 
[   28.992752][  T394]  __free_pages+0x51/0x90 
[   28.992752][  T394]  __free_pages_core+0x1c7/0x2c0 
[   28.992752][  T394]  deferred_free_range+0x59/0x8f 
[   28.992752][  T394]  deferred_init_max21d 
[   28.992752][  T394]  deferred_init_memmap+0x14a/0x1c1 
[   28.992752][  T394]  kthread+0x1e0/0x200 
[   28.992752][  T394]  ret_from_fork+0x3a/0x50 
[   28.992752][  T394]  
[   28.992752][  T394] write to 0xffffffffa01a6de0 of 8 bytes by task 394 on cpu 0: 
[   28.992752][  T394]  __change_page_attr+0xe9c/0x1620 
[   28.992752][  T394]  __change_page_attr_set_clr+0xde/0x4c0 
[   28.992752][  T394]  __set_pages_np+0xcc/0x100 
[   28.992752][  T394]  __kernel_map_pages+0xd6/0xdb 
[   28.992752][  T394]  __free_pages_ok+0x1a8/0x730 
[   28.992752][  T394]  __free_pages+0x51/0x90 
[   28.992752][  T394]  __free_pages_core+0x1c7/0x2c0 
[   28.992752][  T394]  deferred_free_range+0x59/0x8f 
[   28.992752][  T394]  deferred_init_maxorder+0x1d6/0x21d 
[   28.992752][  T394]  deferred_init_memmap+0x14a/0x1c1 
[   28.992752][  T394]  kthread+0x1e0/0x200 
[   28.992752][  T394]  ret_from_fork+0x3a/0x50 

It point out to this,

		pgprot_val(new_prot) &= ~pgprot_val(cpa->mask_clr);
		pgprot_val(new_prot) |= pgprot_val(cpa->mask_set);

		cpa_inc_4k_install();
		/* Hand in lpsize = 0 to enforce the protection mechanism */
		new_prot = static_protections(new_prot, address, pfn, 1, 0,
					      CPA_PROTECT);

In static_protections(),

	/*
	 * There is no point in checking RW/NX conflicts when the requested
	 * mapping is setting the page !PRESENT.
	 */
	if (!(pgprot_val(prot) & _PAGE_PRESENT))
		return prot;

Is there a data race there?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3760F60F-4133-4FE1-9A4C-F335A8230285%40lca.pw.
