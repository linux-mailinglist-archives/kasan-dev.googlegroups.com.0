Return-Path: <kasan-dev+bncBDN7FYMXXEORBZMB4O7QMGQELH55ZHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id BC917A85505
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Apr 2025 09:12:39 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-ad50a3a9766sf1278295a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Apr 2025 00:12:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744355558; cv=pass;
        d=google.com; s=arc-20240605;
        b=W9Dg+8LSKbR8UiKgVDjxd0xTHunSowwZ6ldNkC7G6IUvRt718ozjy5EbIYfs7O5L06
         p2uI6LXvHeas0Xkxq4PZTBZdudZVFOM+nNgpo2U5P6Co6EPMtA1OtiFjT98AC8/bppKz
         ksvVsVR/VGH8w4I7Osflp6EAdhL4w0gJRiEu6cxDanZ2OhfC7XkdaXN/V6FyaxSrHOch
         WKlZCbj+UvVmHiaf9UCTauJqMPT6kbWsZdWkw1LHixB6krw9zoOkKfX8pomfYH14dXiO
         fFoH+6azCmMNlqjVVYwarqWjZgSaqN0Irx8IJXWCEA585vBcH07+ruYquWVB89uALJkS
         cN3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:to:from
         :subject:cc:message-id:date:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=z7I8WagN1UDXzj0L/wGW9tDwMxuwAOrOIcDHfDnM05M=;
        fh=O2RJlg9RVRg1mUEUukVdORum57O4eXHsVm4xmQRRy4g=;
        b=TgGgKjFllRUlNHkAJlmKpXMCqoTBT9jofeVNxV4B0U7qI1G8hZBQphv09OjW2SZiHp
         ZCj+CqMZQ5+TCfc6+z+3Q1ywPKNuNHSVpEBBkD01w3Ve+mcDHBfpUXrZX0bb1RAcDMIh
         FV0jnQhoW360qOSw8nTRk2BX8EI4C+uhfnDYPKfDp/1TgLOodERm+dLklgMdj0G4wuVv
         G/FuhL6QDTpA9CqlGjvjiTK88KCZ7UEfSpPLbtTU2bdbjw8/aqN4MGeFS+ivJFsUCC8F
         G9zmheoE28aRX6CazprCrRmu3WAVJsTzYIAG0IvuNstJrxWv7jS72kpWegJe4krkZFs6
         A8/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fwXChmiK;
       spf=pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=npiggin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744355558; x=1744960358; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:to:from:subject:cc
         :message-id:date:mime-version:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=z7I8WagN1UDXzj0L/wGW9tDwMxuwAOrOIcDHfDnM05M=;
        b=liY5/5EtBoNr4b/4rsJSejnerL5c0dxjGM04iOWq9RTokBfm+56dL9rSut5sR4tmw7
         5CkRQ+dzmPcJcsYJxOZJwLHMoNhCBH9R/8WGS8qntTy9UXgQVXalVR6sPhyh8RlqI9Bu
         JHA11rnxx7dNAKeO09S5NKyIozgx8vdxw/EYyqCVh5B+a1sjWTjEzWXpCFrK8eLy9WJx
         5aiDjDxxhzv5+wDvQ0kGnqZsrJ8eE15Pq4+LajD0OV6YlqWgbk+pbXW7JfsGjw4w0bch
         d4T/7HaSdi3IAzgizROln92BMCEi+lrHmxPpF32KyPSI/9FbrTxXMmCHqXeACgN611OZ
         2gTA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744355558; x=1744960358; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:to:from:subject:cc
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=z7I8WagN1UDXzj0L/wGW9tDwMxuwAOrOIcDHfDnM05M=;
        b=Z+g4Un5/BDlI4OeNg1HRe4i637AIcBeLId+6V8pdIlYCX2rQHs0Aw3aTwWBFESslLS
         Uh7HcV1QQyYoFDL9X9acAgKlfPXBjwkRW/1K1mQeCVbby5BQRMzQ4I3DzKxt7xYEdBB/
         sVEZ24iw19NGGxA5Atj1+YE1P7qAo0dsMpLz2HVXdmN0GFJbJt+NzBzS6/nrQ5lLvq4X
         QtTwsYiPQuWK22Mm5GnBdKE18FnMGTb72rMUZ92rVJVtOY05dF/dZUuWNnRvJZ6XW9tI
         gpOJUm1W1Dqt7YONVOD4U8jawXokZOVYuoj9X3ILbUWGucnFztgcRe/9YGw6tb9+GO/d
         hlOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744355558; x=1744960358;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:to:from:subject:cc:message-id:date:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=z7I8WagN1UDXzj0L/wGW9tDwMxuwAOrOIcDHfDnM05M=;
        b=PIMvTbMX8ovGcCe+d+u+LaNcoyd5uFcOxiavtqVkL1xOTq0PAJCczMoMVC7uvbjRJm
         8u3BylBhBnIxpAJkdHrXMd9LFEpM0SY+VNin7rYEo6ApHjevWjYL1FtfF3Ei33EkKBGs
         XkNfko1d5k7k4orQ930r85QTLAVVNxSLh3s7LXnVTDuZgM93sYNOJphbitWQvgfG/QCW
         OW5XGar8aotdsmKCdNC6bGeJob90EWjOZFRw5MWrV/BJOKSMnEEmchsWpq5U4h8kyk6H
         ESIlQ1uVsqYHmy5NMhentMOVXB/YJyhBZV6AdXUbQbtzui4O6WTP7GiXlel1FzQRDckj
         d8MQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVTicb7F7nit7LGe85uNjmTmo8BW0acBfWsfaakaavooNk156LrmqeU5esSx/ba65GjKIMSxQ==@lfdr.de
X-Gm-Message-State: AOJu0YyWFSeAMErp22SDlZL0pEwOHzi/nXG1zhoRtt0Emk1o4cRGaHhM
	MkN4tdZFDkqKLvXx/iddTdRq9GvPfTTbHKxrOv6nj22ZglNjK3+7
X-Google-Smtp-Source: AGHT+IHOxaOAt4h/UzxXdIy8dFbZbfnPSRxeSr+7gRJQ3zYCQK1FzgS8M4S4UQawRtcVg3MA9g+eDA==
X-Received: by 2002:a17:903:246:b0:224:216e:332f with SMTP id d9443c01a7336-22bea4ff158mr27211895ad.48.1744355557770;
        Fri, 11 Apr 2025 00:12:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJs0BJvOJo+UEjBbKdLODb0ybrcD8Sm2wIwyaOWpJFK1g==
Received: by 2002:a17:902:d50a:b0:216:3440:3d16 with SMTP id
 d9443c01a7336-22acf283929ls13684075ad.2.-pod-prod-02-us; Fri, 11 Apr 2025
 00:12:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUx7uNOFQb+HILi2AaBhxBpT1TYlEF+j1jcB9F4Q7wkZ5bQ84oC3r2w1kXiIVkLJ7TPFXvczfaJpus=@googlegroups.com
X-Received: by 2002:a17:902:c94d:b0:223:47d9:1964 with SMTP id d9443c01a7336-22bea4f39bamr25586635ad.34.1744355556027;
        Fri, 11 Apr 2025 00:12:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744355556; cv=none;
        d=google.com; s=arc-20240605;
        b=SiCux3ZwlPzAAEKG9PJxi9nSfWGvVzKiL22hGVOw34XzS80uAbU4pjMl/Cls+Ii5HA
         oh+G0sYZrHxQmVrJbUTNDowge1e5btVaQAvJl3MLPBXv7mkwQhuyF4vDPT0nem7J4R2v
         HADkYzozkrisHEwV+Yfmx87wFX/+Yn9WqvLdISk+JKtvBj1U3Zq4dd7lGQ6Dba5NCRfj
         hu5Zh1iaiRcnwTF2vqKBVKbDQEiWFDFo8BtiRox+4D9GXFfoXDIkAKtsGPfyCJ5r4WkB
         DcBbgopZprmmEhJtwIje7Eg5c+fxhRhIVhhtJtjNTV+b9le0cfLURqU50uegqOo1gpiS
         7jbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:references:to:from:subject:cc:message-id:date
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=KzShCwppEme7OMOnT5z5FD+rJw9aaKOfx1ISsPkjuh4=;
        fh=27hJoTHOVNe2SDV1tu0ddMdSV35/Ie1SrISjswNwNVg=;
        b=Cg49NSF7TU2I3KOz/v1P9s04zlagiWvxotzzsD21GXkqS/UD3PdI6ZaVD3ffE3zJKN
         KWU91U8ZSQ9Qnq8h5fvPnR1Lf//6E1lRbmRddeJRb4r8XfkNtwCxE0cMvRPc/sgLFjcQ
         PHALieQnVo7ulHuxnzXPdQidvITIcl/3DA+EvGO9pWc6lBMOC+3rg7jx1TBx/geTvDJd
         TFbXVhIQ73x7t6t5cUOBp5ipjCeRW0F8U+WF2P6kBgYmy3hAXQOSlVX2TeXtrwGRNaUd
         puPpu4f/nMApG/3eTLZKXWaJ+Zi8ZEeL3fz0wrbQqjB98/KRCw4KuiII0frxQmAKaDea
         h1oA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fwXChmiK;
       spf=pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=npiggin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22ac7bbe8efsi2532275ad.5.2025.04.11.00.12.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Apr 2025 00:12:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id 41be03b00d2f7-af9a6b3da82so1179977a12.0
        for <kasan-dev@googlegroups.com>; Fri, 11 Apr 2025 00:12:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUlwdWaUpIvJFFiNbF518SWhmqDyJp8wUet3cmMSK9tFjVosNxQn2ZLtzYB6hvELXSKNXlWBmQPaRo=@googlegroups.com
X-Gm-Gg: ASbGncuggHz+PfNt0AbUCR5hw/QE7rAnhI7rcGd2hA6aCcWyfowTL3bHNj536WONzXT
	GqrHaVmC81I2I64hI5X0yza8n3b750ApNlXCGp5q3nW9K6hOiStp7onVX4G5jYEcCJ7LoNYErRR
	1dQLBlxIuebO5qC5PdAFGZee9CQM2Vz080OW9y3SqnBfTuxYsN3mDjMFcqpeYW2MYXQIKG1wx1s
	BlI7PiWbM3CIhz0j6xQ1QWFbDpQzfs5SFo8tHzDr4cIWRQhgICI49L8u00qF28c9u1zFAd/OwAJ
	CCfRI/g/Xqp9/s3qPVBXBBkSZ4KKXHT4wA==
X-Received: by 2002:a17:90b:5245:b0:2ff:784b:ffe with SMTP id 98e67ed59e1d1-3082377c271mr2980340a91.11.1744355555591;
        Fri, 11 Apr 2025 00:12:35 -0700 (PDT)
Received: from localhost ([220.253.99.94])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-306dd171942sm4948139a91.33.2025.04.11.00.12.30
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Apr 2025 00:12:35 -0700 (PDT)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Date: Fri, 11 Apr 2025 17:12:28 +1000
Message-Id: <D93MFO5IGN4M.2FWKFWQ9G807P@gmail.com>
Cc: "Hugh Dickins" <hughd@google.com>, "Guenter Roeck" <linux@roeck-us.net>,
 "Juergen Gross" <jgross@suse.com>, "Jeremy Fitzhardinge" <jeremy@goop.org>,
 <linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>,
 <kasan-dev@googlegroups.com>, <sparclinux@vger.kernel.org>,
 <xen-devel@lists.xenproject.org>, <linuxppc-dev@lists.ozlabs.org>,
 <linux-s390@vger.kernel.org>
Subject: Re: [PATCH v1 0/4] mm: Fix apply_to_pte_range() vs lazy MMU mode
From: "Nicholas Piggin" <npiggin@gmail.com>
To: "Alexander Gordeev" <agordeev@linux.ibm.com>, "Andrew Morton"
 <akpm@linux-foundation.org>, "Andrey Ryabinin" <ryabinin.a.a@gmail.com>
X-Mailer: aerc 0.19.0
References: <cover.1744037648.git.agordeev@linux.ibm.com>
In-Reply-To: <cover.1744037648.git.agordeev@linux.ibm.com>
X-Original-Sender: npiggin@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=fwXChmiK;       spf=pass
 (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::52d as
 permitted sender) smtp.mailfrom=npiggin@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue Apr 8, 2025 at 1:11 AM AEST, Alexander Gordeev wrote:
> Hi All,
>
> This series is an attempt to fix the violation of lazy MMU mode context
> requirement as described for arch_enter_lazy_mmu_mode():
>
>     This mode can only be entered and left under the protection of
>     the page table locks for all page tables which may be modified.
>
> On s390 if I make arch_enter_lazy_mmu_mode() -> preempt_enable() and
> arch_leave_lazy_mmu_mode() -> preempt_disable() I am getting this:
>
>     [  553.332108] preempt_count: 1, expected: 0
>     [  553.332117] no locks held by multipathd/2116.
>     [  553.332128] CPU: 24 PID: 2116 Comm: multipathd Kdump: loaded Tainted:
>     [  553.332139] Hardware name: IBM 3931 A01 701 (LPAR)
>     [  553.332146] Call Trace:
>     [  553.332152]  [<00000000158de23a>] dump_stack_lvl+0xfa/0x150
>     [  553.332167]  [<0000000013e10d12>] __might_resched+0x57a/0x5e8
>     [  553.332178]  [<00000000144eb6c2>] __alloc_pages+0x2ba/0x7c0
>     [  553.332189]  [<00000000144d5cdc>] __get_free_pages+0x2c/0x88
>     [  553.332198]  [<00000000145663f6>] kasan_populate_vmalloc_pte+0x4e/0x110
>     [  553.332207]  [<000000001447625c>] apply_to_pte_range+0x164/0x3c8
>     [  553.332218]  [<000000001448125a>] apply_to_pmd_range+0xda/0x318
>     [  553.332226]  [<000000001448181c>] __apply_to_page_range+0x384/0x768
>     [  553.332233]  [<0000000014481c28>] apply_to_page_range+0x28/0x38
>     [  553.332241]  [<00000000145665da>] kasan_populate_vmalloc+0x82/0x98
>     [  553.332249]  [<00000000144c88d0>] alloc_vmap_area+0x590/0x1c90
>     [  553.332257]  [<00000000144ca108>] __get_vm_area_node.constprop.0+0x138/0x260
>     [  553.332265]  [<00000000144d17fc>] __vmalloc_node_range+0x134/0x360
>     [  553.332274]  [<0000000013d5dbf2>] alloc_thread_stack_node+0x112/0x378
>     [  553.332284]  [<0000000013d62726>] dup_task_struct+0x66/0x430
>     [  553.332293]  [<0000000013d63962>] copy_process+0x432/0x4b80
>     [  553.332302]  [<0000000013d68300>] kernel_clone+0xf0/0x7d0
>     [  553.332311]  [<0000000013d68bd6>] __do_sys_clone+0xae/0xc8
>     [  553.332400]  [<0000000013d68dee>] __s390x_sys_clone+0xd6/0x118
>     [  553.332410]  [<0000000013c9d34c>] do_syscall+0x22c/0x328
>     [  553.332419]  [<00000000158e7366>] __do_syscall+0xce/0xf0
>     [  553.332428]  [<0000000015913260>] system_call+0x70/0x98
>
> This exposes a KASAN issue fixed with patch 1 and apply_to_pte_range()
> issue fixed with patches 2-3. Patch 4 is a debug improvement on top,
> that could have helped to notice the issue.
>
> Commit b9ef323ea168 ("powerpc/64s: Disable preemption in hash lazy mmu
> mode") looks like powerpc-only fix, yet not entirely conforming to the
> above provided requirement (page tables itself are still not protected).
> If I am not mistaken, xen and sparc are alike.

Huh. powerpc actually has some crazy code in __switch_to() that is
supposed to handle preemption while in lazy mmu mode. So we probably
don't even need to disable preemption, just use the raw per-cpu
accessors (or keep disabling preemption and remove the now dead code
from context switch).

IIRC all this got built up over a long time with some TLB flush
rules changing at the same time, we could probably stay in lazy mmu
mode for a longer time until it was discovered we really need to
flush before dropping the PTL.

ppc64 and sparc I think don't even need lazy mmu mode for kasan (TLBs
do not require flushing) and will function just fine if not in lazy
mode (they just flush one TLB at a time), not sure about xen. We could
actually go the other way and require that archs operate properly when
not in lazy mode (at least for kernel page tables) and avoid it for
apply_to_page_range()?

Thanks,
Nick

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/D93MFO5IGN4M.2FWKFWQ9G807P%40gmail.com.
