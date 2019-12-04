Return-Path: <kasan-dev+bncBCT4XGV33UIBBQPDUDXQKGQENNYQEUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 68B28113789
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Dec 2019 23:22:59 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id w17sf438116plp.4
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Dec 2019 14:22:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575498178; cv=pass;
        d=google.com; s=arc-20160816;
        b=YVvmIjg+iPxDyI+fXqGhLtk9HULKatYz7J2jk9J0QBVWAAf5up8nbpvIvJO3pzdc31
         cCFAkGrIdPomFvQicjZ5sCoYcB3rPoZUpWkjAhYz6WrczC4y606FCS88lz12u0PT/+5E
         Z8AG/jHsgLqcZH0I4EJFECyDJ9O984UvdrJl55SLVbx9sXo/DDdkGNULxx4nUZg6sHTu
         lJVGGFBYBa8x8k9ziBiFVAGO//ev0MwSzVDwgaNGJLVWgfU0x+vJIk4ZhqETQfwG6aJS
         tnIAKK5lFuMlFIM2m992eNxjXCfS8WlYhQKdMzRlgUcXlCAiEw/JWUZe2sIWuSJf6GuZ
         1REA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=1kXKg2WVzFXDvEarjEqOoFKcaZQbyijCJwFvFsEoTN0=;
        b=IB8HDjojV1hhYz6e84R1KZT6JkxmxLNvMb0NxEgSq8Va6DV+PjSnhC8KqFUHYO41aF
         c7V7dJl8fsFO7X9py8gw+8X8xSaFOifRo6B6YY0hmz9SnnkOW3hSUTwuTx/1t2PlTgta
         yo450UWqv+ngxVfo6RUDxBRpead/xUBz5HgbCnTCI3HcYM5rnKtDqILbMlTDJ6X+OYsu
         /ssGgnw6VMtOMgQBwljX5wsl26dHGqtAkGUj5Gy40X3M86ZHF/qzJNKASrnJvwIYKEqg
         pUrybTwR0puAU0p0NOxQXtq/KlhMdy2UUs2t03ir5umUSMDt5N591mU5VBuphQJahk5J
         6NfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="JT5/M9L4";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1kXKg2WVzFXDvEarjEqOoFKcaZQbyijCJwFvFsEoTN0=;
        b=E3hJiWti5RlZPfYq+gds4wi72ygwfrWhkLhoOpnmwXgP5I51O8bzhQLztceH7vQLA4
         AovbR1eApsmxAHwBnkXuNLk47hOvNFLRSyChapEtw6Wc8PxAKRLGaNWZ2ktF0VqILaM3
         FY8N3Uy1yGQ2nnc4ZiTlP56IAIrWIBC9i5e3JyZ/FXlGw+kOkU8caDHZJGSP/HAjoSzq
         iluVqI9ZpaUJgQVTI+g0lWR1b1w3MJ37p3SlDA+KTb7vtCysEj3JCmcMsuIOFlYhiCfG
         kaYuYDoivlFTPJitEcvuV1dpAbI/hBOPqCt+F9nauzdl6/E4vlUPeyFPf7vtxvw+crgz
         kwHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1kXKg2WVzFXDvEarjEqOoFKcaZQbyijCJwFvFsEoTN0=;
        b=oNa6s8gFZYlNSsqz7CgD+Lw6Q0HDrgGSxEpM8CyXcpzehPdVjfamaGFbsfnKOwH3bb
         CIsypt/7fPJfQvUqNnB5ZvRR6x4grJB5a9dHW4IZqVbVClkEpkji4S917++7/gtfoiWw
         OFZsbxed14BvUdJtjdz1Q7rxieanpRZvEqVNtbgm1AuSDBrK57gFnpMuq+V3voH8+dAn
         ixz/18VRKm7K38tUfjQJZ/Ry3WXsqq7x1XRBSoRSuAK/oQT6Fu+FgoPAR3B/PxjxsbUl
         oA5weS6ZnY8PKIxJM/+XH9MdA2phjgMgRhwkz/BG8zySztLzeDEZiMfKbWyRQUpR/THp
         EiWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV7iAv1ned6GHnBuo8E9lVp/IUcoihZctmC+b2vVagNKL4ajEO4
	Se8XDdA8dpX1GXc/t0Tnhyc=
X-Google-Smtp-Source: APXvYqyKHfHgm/qjNz6UeD7efSC2m1uS6tgDla+qIgdXTMpgp0X1P7HthOk/HMINm0BQ3HdKBMz2jw==
X-Received: by 2002:a17:90a:8a8f:: with SMTP id x15mr5803121pjn.87.1575498177895;
        Wed, 04 Dec 2019 14:22:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3b42:: with SMTP id t2ls189228pjf.2.gmail; Wed, 04
 Dec 2019 14:22:57 -0800 (PST)
X-Received: by 2002:a17:90a:b009:: with SMTP id x9mr5711468pjq.124.1575498177430;
        Wed, 04 Dec 2019 14:22:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575498177; cv=none;
        d=google.com; s=arc-20160816;
        b=PxTuVRhs85txNs2S6i2J16jVML5xVMWNq9oPGByeRsF0KbdVp77ymZTgNN9Z7d7Hlm
         4gJ5Kpd33ccZ678279bWuKggkX8DctLuA7yvFM3SmitcKZKFxX63J14P0fXjDr64D/Zx
         AoIYfaqsmBIA3WxaL/3k4xYNKtDzwqrlhtOIuYL6G+v6OVl7SMgGgybxQjf64FkItCri
         ir1WdPC0daViJ2YdvSVvV253XBkT9cqe5M6X4RLH67umMVHIROh+N7V4VTLKUjnYhN4K
         3pM4QKZ0DIWcz7fQGYGW7//NEhzQ8dMnbFhmiPblwWK/Q+9pkR4rBf+WWkmO2OLrLAg5
         tvOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=45AqkEbN0JrIcN/4ETFG5VZG1l7DdiWmYUV2kNT9LII=;
        b=QeYjF1I9DE0xR9ri7UMGeQBs8vDu0ZdcLke6A6HXqMt/JRuYYgR9O2xruMAvQ5Nflv
         IUKIhESpHeulbXY1INY5tNRiYx8+Hy3NlAsyNo1spXYVDg9RK8DpJYIOcrs2nvjooWua
         N2OOijtbDQ5zCu+SDjT7BERFMnS3p02y3M73PyDKbFzb/q3i2z561ysF8hFPiivj+UML
         aBNwHkfYvAMYErket7/zBqKJESgBdYSOVN5EIUMrqvriMOCvLnX0rPF9fqakK5DLABNG
         WHJoNOekT7Y68LqRqIjtdZFNmn4Lw9yzwhvhH1zZ7kcGH4TzjWE4XC96Y3YAhxS/wemm
         nHSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="JT5/M9L4";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f23si159268plr.0.2019.12.04.14.22.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Dec 2019 14:22:57 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost.localdomain (c-73-231-172-41.hsd1.ca.comcast.net [73.231.172.41])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id BE40E2073C;
	Wed,  4 Dec 2019 22:22:56 +0000 (UTC)
Date: Wed, 4 Dec 2019 14:22:56 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, kasan-dev@googlegroups.com, Daniel Axtens
 <dja@axtens.net>, Qian Cai <cai@lca.pw>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH 2/2] kasan: Don't allocate page tables in
 kasan_release_vmalloc()
Message-Id: <20191204142256.567b143cfde572acd804544a@linux-foundation.org>
In-Reply-To: <20191204204534.32202-2-aryabinin@virtuozzo.com>
References: <20191204204534.32202-1-aryabinin@virtuozzo.com>
	<20191204204534.32202-2-aryabinin@virtuozzo.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="JT5/M9L4";       spf=pass
 (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed,  4 Dec 2019 23:45:34 +0300 Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:

> The purpose of kasan_release_vmalloc() is to unmap and deallocate shadow
> memory. The usage of apply_to_page_range() isn't suitable in that scenario
> because it allocates pages to fill missing page tables entries.
> This also cause sleep in atomic bug:
> 
> 	BUG: sleeping function called from invalid context at mm/page_alloc.c:4681
> 	in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 15087, name:
> 
> 	Call Trace:
> 	 __dump_stack lib/dump_stack.c:77 [inline]
> 	 dump_stack+0x199/0x216 lib/dump_stack.c:118
> 	 ___might_sleep.cold.97+0x1f5/0x238 kernel/sched/core.c:6800
> 	 __might_sleep+0x95/0x190 kernel/sched/core.c:6753
> 	 prepare_alloc_pages mm/page_alloc.c:4681 [inline]
> 	 __alloc_pages_nodemask+0x3cd/0x890 mm/page_alloc.c:4730
> 	 alloc_pages_current+0x10c/0x210 mm/mempolicy.c:2211
> 	 alloc_pages include/linux/gfp.h:532 [inline]
> 	 __get_free_pages+0xc/0x40 mm/page_alloc.c:4786
> 	 __pte_alloc_one_kernel include/asm-generic/pgalloc.h:21 [inline]
> 	 pte_alloc_one_kernel include/asm-generic/pgalloc.h:33 [inline]
> 	 __pte_alloc_kernel+0x1d/0x200 mm/memory.c:459
> 	 apply_to_pte_range mm/memory.c:2031 [inline]
> 	 apply_to_pmd_range mm/memory.c:2068 [inline]
> 	 apply_to_pud_range mm/memory.c:2088 [inline]
> 	 apply_to_p4d_range mm/memory.c:2108 [inline]
> 	 apply_to_page_range+0x77d/0xa00 mm/memory.c:2133
> 	 kasan_release_vmalloc+0xa7/0xc0 mm/kasan/common.c:970
> 	 __purge_vmap_area_lazy+0xcbb/0x1f30 mm/vmalloc.c:1313
> 	 try_purge_vmap_area_lazy mm/vmalloc.c:1332 [inline]
> 	 free_vmap_area_noflush+0x2ca/0x390 mm/vmalloc.c:1368
> 	 free_unmap_vmap_area mm/vmalloc.c:1381 [inline]
> 	 remove_vm_area+0x1cc/0x230 mm/vmalloc.c:2209
> 	 vm_remove_mappings mm/vmalloc.c:2236 [inline]
> 	 __vunmap+0x223/0xa20 mm/vmalloc.c:2299
> 	 __vfree+0x3f/0xd0 mm/vmalloc.c:2356
> 	 __vmalloc_area_node mm/vmalloc.c:2507 [inline]
> 	 __vmalloc_node_range+0x5d5/0x810 mm/vmalloc.c:2547
> 	 __vmalloc_node mm/vmalloc.c:2607 [inline]
> 	 __vmalloc_node_flags mm/vmalloc.c:2621 [inline]
> 	 vzalloc+0x6f/0x80 mm/vmalloc.c:2666
> 	 alloc_one_pg_vec_page net/packet/af_packet.c:4233 [inline]
> 	 alloc_pg_vec net/packet/af_packet.c:4258 [inline]
> 	 packet_set_ring+0xbc0/0x1b50 net/packet/af_packet.c:4342
> 	 packet_setsockopt+0xed7/0x2d90 net/packet/af_packet.c:3695
> 	 __sys_setsockopt+0x29b/0x4d0 net/socket.c:2117
> 	 __do_sys_setsockopt net/socket.c:2133 [inline]
> 	 __se_sys_setsockopt net/socket.c:2130 [inline]
> 	 __x64_sys_setsockopt+0xbe/0x150 net/socket.c:2130
> 	 do_syscall_64+0xfa/0x780 arch/x86/entry/common.c:294
> 	 entry_SYSCALL_64_after_hwframe+0x49/0xbe

Why is this warning happening?  Some lock held?  If so, which one?

> Add kasan_unmap_page_range() which skips empty page table entries instead
> of allocating them.

Adding an open-coded range walker is unfortunate.  Did you consider
generalizing apply_to_page_range() for this purpose?  I did - it looks
messy.

Somewhat.  I guess adding another arg to
apply_to_p4d_range...apply_to_pte_range wouldn't kill us.  I wonder if
there would be other sites which could utilize the additional control.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191204142256.567b143cfde572acd804544a%40linux-foundation.org.
