Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAVOS2WQMGQEEA77NLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B71F382E1D6
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jan 2024 21:35:15 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-204e4adcf72sf14590690fac.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jan 2024 12:35:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705350914; cv=pass;
        d=google.com; s=arc-20160816;
        b=olgPicU+t2KgmLre1CGBw9JKq+Jw7xBIx1F+WkE4r6Pg5cRyc+UcnLI3oSZMaKaPgw
         M7F16qV5h5GPSHTeHNJShWconuwHZnrlnOo9hFLvk8289H4RMjD8QQmozqcveNSabm3C
         IeKQTZ2zQEd0w8AHkWdLGiQEmIbxQ/6XbaoHXJAxKEXAeMeBD7GkOItxYEpxH3dI+SPx
         pLIMOkObHKuTDUeDbfawahq8cpULxiwqeAlvv2s39fOqdB1KiKKrKiyfRW5a/5WA5Q2M
         2lPgG/mj+pjZOuJ3//69IvmnGSPhW/LNWIgQ9pAFhaZ72mGWz0j6buQmXqlk2bmFEwyn
         5JqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wuAHZzXl3nMAb7o17O6BPUJGrpEllsuXO32FtrH+9Y4=;
        fh=V/YoFzKlSwVzG1uyqPUWUAENm7zViGv6IjT7j68hIPU=;
        b=V0ICHX6+9ok6XvitqlGSk30zfWhtacrZMwXV6YAa6+e7jdeM2LB12DOUW3OG0z09Ph
         Adsd2oJ1lXhqtHcRq3i10hBdCsoNmX22v32Xu1H79neLVMbZg0IQ6hJbcnRjkpH+Y7Rk
         X7bAMGWDTGBwyTQBh16ZTRtRphD5bKUHFm12n8sZmTh31WzVvg7I2iHaRtWelQGP/oxh
         aBRiWDvg+HeEFNiiPFV4nj2OUZb5cCAAeFhLt9LHNUYMcEwcHXC+ZPhR39qWFv+qdf63
         Bilg6ajKJwP373OpMSrXKq0AOubXd2f6CzlAe8krUndl2sh4iJkm6ZpkjXQPZkUx6qa5
         lnWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4N2CvjQm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705350914; x=1705955714; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wuAHZzXl3nMAb7o17O6BPUJGrpEllsuXO32FtrH+9Y4=;
        b=b+1ihrfI+VOXAdArInM2DSt6U5Ih/ECe39h1X+AOmahT6okfrc2xHiEihxxMw8MW6K
         MlEcA5GjsG6cyJXYlQrVk0lVbwnya0j0w5JtYMNzB44snBI6M9vPH+aJEKK1MSpxJUfZ
         uWDQg2mCI2m/Z2IYC/vYO8RO/UCuPNxBSTtsm43b03KxqeOrkgCCg6vNFIEq6ZeEjtVQ
         sWlipwCSlyX35laW6k3K6VEEPdan2VC2wukrcvw6k9BaW8+fhxUU/7K6YKbd5R46xnqw
         ZjhMmQewxYhOpiajHMp0YvcfZId+mvJiQqXNd9iVo10ptK3mgwqyv8gAO5gEcI+SuLBK
         O3yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705350914; x=1705955714;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wuAHZzXl3nMAb7o17O6BPUJGrpEllsuXO32FtrH+9Y4=;
        b=ih+efTJ3MViza7dH6KlsegeXenx8+OMXPk8YEFR6g8mue3z5mHHJRBVmbUCJl+Mv/2
         Ffm6lk78hDXG+9R17oNOV9QqEycqWG0TKAM/we24hBaMIujIzU+IShG7mfDDNIN/qj7/
         y0jn9JqybZE1fir6K2jESvkzGYIxyExYU2Tr8YkrOZPik9KvIhvqDnmD+n6sLA8oe2Lq
         i02UTkGBk6dHOeEmyn6mtSls3Rc919l1lqyYGBtwvh0zKDZGYDMH6eDwMEbZG4JDmrni
         bmSbQu4SAkrwBwG374op06hSlM+5GoxbA+RNWOmEvjZQ09GIya00zSAwyr3PpkRd79bP
         laFQ==
X-Gm-Message-State: AOJu0Yz8lC+SYd3nwGmYzwkOIxGs6jA++pZNrKHa4NMUeBJ0THGYlCL1
	mo0UyilRv3FUSQf80fS5HqA=
X-Google-Smtp-Source: AGHT+IGPe3rWo2BdRqmgiF/+J0YXqxNBsGnYZzy/PbIarx7p6nE1rwaORUkjbFFINlf3RsNTWdGgag==
X-Received: by 2002:a05:6871:4308:b0:204:308f:cecc with SMTP id lu8-20020a056871430800b00204308fceccmr9741692oab.116.1705350914173;
        Mon, 15 Jan 2024 12:35:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:e78c:b0:206:9c61:8284 with SMTP id
 qb12-20020a056871e78c00b002069c618284ls1043189oac.0.-pod-prod-09-us; Mon, 15
 Jan 2024 12:35:13 -0800 (PST)
X-Received: by 2002:a05:6871:5207:b0:1fb:1904:bcdf with SMTP id ht7-20020a056871520700b001fb1904bcdfmr10307131oac.16.1705350913540;
        Mon, 15 Jan 2024 12:35:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705350913; cv=none;
        d=google.com; s=arc-20160816;
        b=hLRDKl/b+JFYqobzZXNM7xhSm/8N05C0EYu+tGMVNse7MZtUgeQYWllRFxOrNuf/jC
         63YSR6VMxdKQWgB9xHhsPZyrpVbJy5+hhLTk5yBZgUK8xy5P/cssJ5eDW/VRymiU7R/6
         AlbFD/0aUOIVrrWOHQirOX9PkwR0wIbbuRTNTb7T1+jkpT3+T3xSk5gReHDj4l1LW8dJ
         bTmG9daLvXbjXX7SUU3CmxLmiw6U11Juy55kdQO0mDdqNbKiKozEe0OuQ0KVKIlxnOqA
         bmgI4i3BkGss6dJ81AjPj5wd2RwUqP/JoKuGSyHNNn43h3DPetdbmmEA3XsmpvgKaN6K
         aY9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vMS0J/7CyXgLKOAf0V+IWQO6ynhdDfGM83qwFs2ZDn0=;
        fh=V/YoFzKlSwVzG1uyqPUWUAENm7zViGv6IjT7j68hIPU=;
        b=jLD2iIzcbZj6aQcmM+xuEK2+A+8CPYLwqnEZFJNntvy9xpl3/2oTgcZf8j/0ocooOA
         XDKelvy8epNSoHbgpJole+3Jx0mVK8f014aq5JolV5QvGFrytjdFiDONhrtr8Ovbjp0j
         jcQ5MZu15ZIltuRGJoXmPigHVkK33ovGbEz+giQC+9POugwhfL0Px2Uk/aK16Nf9JLdg
         SsK/XSkseCaId4w/g9wtrsM7WRZM8XWLBRRRSfHxABQZYBxDbGRFSgd1zNqgyAHjROU7
         QAvEUcjZ4DVeKpfaP3XidjtJ8AvF/cl4FHPlzc4OKw1ao9VIsGoC1sqIPIbIUJ3tRb+t
         O75A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4N2CvjQm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2a.google.com (mail-vs1-xe2a.google.com. [2607:f8b0:4864:20::e2a])
        by gmr-mx.google.com with ESMTPS id d186-20020a6336c3000000b005c622d1ef04si587572pga.2.2024.01.15.12.35.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jan 2024 12:35:13 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) client-ip=2607:f8b0:4864:20::e2a;
Received: by mail-vs1-xe2a.google.com with SMTP id ada2fe7eead31-469531dd926so330818137.2
        for <kasan-dev@googlegroups.com>; Mon, 15 Jan 2024 12:35:13 -0800 (PST)
X-Received: by 2002:a05:6102:48c:b0:468:dca:dd58 with SMTP id
 n12-20020a056102048c00b004680dcadd58mr3124255vsa.17.1705350912977; Mon, 15
 Jan 2024 12:35:12 -0800 (PST)
MIME-Version: 1.0
References: <1697202267-23600-1-git-send-email-quic_charante@quicinc.com> <20240115184430.2710652-1-glider@google.com>
In-Reply-To: <20240115184430.2710652-1-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Jan 2024 21:34:35 +0100
Message-ID: <CANpmjNMP802yN0i6puHHKX5E1PZ_6_h1x9nkGHCXZ4DVabxy7A@mail.gmail.com>
Subject: Re: [PATCH] mm/sparsemem: fix race in accessing memory_section->usage
To: Alexander Potapenko <glider@google.com>
Cc: quic_charante@quicinc.com, akpm@linux-foundation.org, 
	aneesh.kumar@linux.ibm.com, dan.j.williams@intel.com, david@redhat.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, mgorman@techsingularity.net, 
	osalvador@suse.de, vbabka@suse.cz, "Paul E. McKenney" <paulmck@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Nicholas Miehlbradt <nicholas@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=4N2CvjQm;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e2a as
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

On Mon, 15 Jan 2024 at 19:44, Alexander Potapenko <glider@google.com> wrote:
>
> Cc: "Paul E. McKenney" <paulmck@kernel.org>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> Cc: Ilya Leoshkevich <iii@linux.ibm.com>
> Cc: Nicholas Miehlbradt <nicholas@linux.ibm.com>
>
> Hi folks,
>
> (adding KMSAN reviewers and IBM people who are currently porting KMSAN to other
> architectures, plus Paul for his opinion on refactoring RCU)
>
> this patch broke x86 KMSAN in a subtle way.
>
> For every memory access in the code instrumented by KMSAN we call
> kmsan_get_metadata() to obtain the metadata for the memory being accessed. For
> virtual memory the metadata pointers are stored in the corresponding `struct
> page`, therefore we need to call virt_to_page() to get them.
>
> According to the comment in arch/x86/include/asm/page.h, virt_to_page(kaddr)
> returns a valid pointer iff virt_addr_valid(kaddr) is true, so KMSAN needs to
> call virt_addr_valid() as well.
>
> To avoid recursion, kmsan_get_metadata() must not call instrumented code,
> therefore ./arch/x86/include/asm/kmsan.h forks parts of arch/x86/mm/physaddr.c
> to check whether a virtual address is valid or not.
>
> But the introduction of rcu_read_lock() to pfn_valid() added instrumented RCU
> API calls to virt_to_page_or_null(), which is called by kmsan_get_metadata(),
> so there is an infinite recursion now. I do not think it is correct to stop that
> recursion by doing kmsan_enter_runtime()/kmsan_exit_runtime() in
> kmsan_get_metadata(): that would prevent instrumented functions called from
> within the runtime from tracking the shadow values, which might introduce false
> positives.
>
> I am currently looking into inlining __rcu_read_lock()/__rcu_read_unlock(), into
> KMSAN code to prevent it from being instrumented, but that might require factoring
> out parts of kernel/rcu/tree_plugin.h into a non-private header. Do you think this
> is feasible?

__rcu_read_lock/unlock() is only outlined in PREEMPT_RCU. Not sure that helps.

Otherwise, there is rcu_read_lock_sched_notrace() which does the bare
minimum and is static inline.

Does that help?

> Another option is to cut some edges in the code calling virt_to_page(). First,
> my observation is that virt_addr_valid() is quite rare in the kernel code, i.e.
> not all cases of calling virt_to_page() are covered with it. Second, every
> memory access to KMSAN metadata residing in virt_to_page(kaddr)->shadow always
> accompanies an access to `kaddr` itself, so if there is a race on a PFN then
> the access to `kaddr` will probably also trigger a fault. Third, KMSAN metadata
> accesses are inherently non-atomic, and even if we ensure pfn_valid() is
> returning a consistent value for a single memory access, calling it twice may
> already return different results.
>
> Considering the above, how bad would it be to drop synchronization for KMSAN's
> version of pfn_valid() called from kmsan_virt_addr_valid()?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMP802yN0i6puHHKX5E1PZ_6_h1x9nkGHCXZ4DVabxy7A%40mail.gmail.com.
