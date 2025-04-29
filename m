Return-Path: <kasan-dev+bncBCD353VB3ABBBO5AYHAAMGQE4BME3XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 691D9AA0114
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 06:06:21 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3d94fe1037csf28040995ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Apr 2025 21:06:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745899580; cv=pass;
        d=google.com; s=arc-20240605;
        b=L5Hv/l/wjiR2oVOep20YqA6J0t3WvqhOAEzYSfrP2AAfkuzV6DAm9ZjBpWXCS0mHoq
         mieF31DQEG+2uXr10s82y7AUrYYHCSMptLxEQjh6Z7MuztFFq/ABR1e5L1EJSQC5R8Wd
         FCyFn7pUYKTUd2Mjo4rjQ8xKE/teoRha/MYa3eFyF/AaywoKzm3SwrPvXMotGZyartlT
         lzmJpxV9TMOyPUfycMlM8LqGst56k0WgytHouBoGVt3WLfd9C2AFTksYoXu8H5OhUVWE
         S4Jo6aKeWU81XDLmpitDrRUMbadUesv67pDsp+VjFwwsgs2aBvhZ6brKPibrE7QGsWfp
         soIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=zMq36nsr7SsqCsUnShXE6Ae36iK47jXUjp9CEIe9jg4=;
        fh=KKy1EyY5VPskwsbARIlWNxtT2owUMYeH9E/h0RcK+6A=;
        b=cw3P+6Qvs45Jhrypj4SSR11zSge/kQkDHxzHhOc8QVgOg9a1iRP2tEPZh1LuVBCehu
         CnPYUpbEdz/rq8RfhetlB+8HbBPRQnUsC2tTVslUHWjDIwoZ9ByyEoh+lDjtuU0KnkKf
         c77z3LNo7DSclSkFyMgQcJ57iSIMEj14pavm1ZCEFJRMVZDcfAoLo4RxktoCCvvSlj2E
         NkC6LToQC3Bxdz0+X6ZQJY6B2RmSzQ93NE9eFYSlayZa0K0Xegen9nJ7J01DR34l15Sj
         D0xwp0kMEo7aT5mtGH+JV34t5VmTUHzSV75P68Mx58tJqW4Bs9NpOGLunNVQr/uyTCkV
         VLJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="c0NlFGD/";
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745899580; x=1746504380; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:reply-to:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zMq36nsr7SsqCsUnShXE6Ae36iK47jXUjp9CEIe9jg4=;
        b=wRn2Cqw9fh6J2OfjsDEUmi7UUezr8ps14ETxL1nRXfiopiOyMXLBxeXvhMAF5rmJAC
         memSAIBoVzbBPjLB1okH7XG6NiNrxRGuL9o/qhAULjvGWHY16p0K+vHhsNLtc8e1/mDY
         YywRGf8y7Yf6/9psrwJG8cNZwg/Rkj2gOGwrKTksBeENhJ+IXFO1s/YgsSxKUNYdOivO
         T2A5rRKckv+/YwiV22D8ZnhFAeHva1lm0BTaYNyivm1JXAU7Yz1eh/8CIY8ZRxlpuz5U
         vNrJg34HDCHthYHSjF1KebqPadDd1j9VCC2IkQ9HcrA2Gy6Qg9Wan9h1M22BDx1cMZkP
         ysVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745899580; x=1746504380;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:reply-to:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zMq36nsr7SsqCsUnShXE6Ae36iK47jXUjp9CEIe9jg4=;
        b=Q44hjNIuMuYaOBty79/HdveeoUpk9KBrUkrXLWDqCGmhPxMTTiyOxocp/Du+mMVD1K
         teESBo70O1W3lKm9o6Ji9x5VD2g359s+n51y9nlWQqnIG9DLXe7koPngWtDkVj8h7T8A
         7tiXkIPkTlcMe+K2n2GpiqulFzRfB75yX59DuVvjzv3QYtnFnkT6A/87FHUIAQZ/ksrT
         jtNV279R8tBCEITCcboiG1JvtnwtCOrqxIkm0oRWHMYh490Shc+cPRKLwizi8JqiakvJ
         JxozWEsyelfMWzLYTL1BICocVV7lS1n93gliVA+6sKAY5TdZ/xnlB8nYyxVEMdV8IBNK
         BJ3g==
X-Forwarded-Encrypted: i=2; AJvYcCWZ13fcxJAGE/B9GgKEIiumMAlgIQJTgS9I3bmxZ5HYAS4aj6/739DEte39UDGI4a+dKoHYZQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw4SsnhkDqpCHtDFYJxjt0vd/RByiR49tRMLmdqKOqVeCQjvZTL
	Z5LZFcZfgNx0JBV5doAyPNZ0Ljbzyy0bRPQSt308hp0XIqs+mF0E
X-Google-Smtp-Source: AGHT+IHOs2viECXD9IERR2tSTbBUU5nej+U1xiihvkmuDTcvsz7df4ufJLZkk/poPIDnpDno2qMTkQ==
X-Received: by 2002:a05:6e02:3cc6:b0:3d6:d3f7:8826 with SMTP id e9e14a558f8ab-3d942e3c3e5mr126120735ab.20.1745899579894;
        Mon, 28 Apr 2025 21:06:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFfr5ruC7sMCV4AIGmKg2ri20SwuVPgfd3g23JLQZd8+A==
Received: by 2002:a92:d2cc:0:b0:3d5:e479:cca0 with SMTP id e9e14a558f8ab-3d92eb438bels28457935ab.2.-pod-prod-06-us;
 Mon, 28 Apr 2025 21:06:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXqrUP2KIwoDY62YvlKw3LAu/VylACpJ5dli05lkAPURhq+2YsXp7kscU4/w6Wtui62aXI1K7y3+dY=@googlegroups.com
X-Received: by 2002:a05:6602:2b8a:b0:85b:4ad2:16ef with SMTP id ca18e2360f4ac-86467fac251mr1166070939f.9.1745899579252;
        Mon, 28 Apr 2025 21:06:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745899579; cv=none;
        d=google.com; s=arc-20240605;
        b=CLm2/z308J5Qu85CVsBCJ7DboHjOAlnznPRpqa382w/6sYG2qY7Bxby5+lCyyk/Ycz
         Miss6kajH13NnEfHcRCBgjUXNLEmrG7yrTkA/jqJs37zCEiZf3Bq35b63mg3Bej/F2AM
         xA6h+2YU7gSv7d2nlYY0zjy8Ow3/tWr2znE9oqH+WPJ2vUBlhi/J7gnMNJzXRpLKwXMz
         rF8lR7NLHKTBXnup3dr6E7WI5IE9RG9U7NXw5DuSYQCx2WsUtcdG/ugZNQfPksPpiKfg
         QHpS6TTXXF3CJmwzcHnZ5IHk61zBzqlBJitAm9dGzg0bzyawMGXVt+o99X3HkZ5PnjnM
         OFUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=reply-to:cc:to:in-reply-to:references:message-id
         :content-transfer-encoding:mime-version:subject:date:from
         :dkim-signature;
        bh=g7sk4q6Sp0j7WMJWmbDXr1gH90ymfRktmXXkTzZ9J5o=;
        fh=/bs3vO5UrVqo8T78tIeeq6rdQWrwj5Jc7+dDXJAvsfQ=;
        b=fIZPmgiRGTFEmPqKoY1U4C0lZCih/16ECIqT8xe9/6kFVbOPfF/uDvmw3IVHiXVcvu
         ogg1ShCZzOhzTEUfoLlgDDHPYAatUBVCB/h8sI8aP1SP2FbXQR67hz4pa059iPu0hGYC
         oeohWSlmK/Gi08Hw0RFdoUVNBLQASjWfNxRq7agmaL0b14/5Fe7MmgasK1hORuMnvH/w
         MEJdaBmlcZGpV/KQcC0OiNB2YY80qzEfPwsN5qZ9VS441RY3EcPb02/b06tewH5uyQ3B
         8TbU3941MRS3E5RN4EmacSZ2smDsVhvJxQcXmw4H6RmATFiWJa5/wjYrFCdrrb2wOC1t
         A9Tg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="c0NlFGD/";
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8648c087b3esi2157239f.4.2025.04.28.21.06.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Apr 2025 21:06:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 637724A2F1;
	Tue, 29 Apr 2025 04:06:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 469C7C4CEF3;
	Tue, 29 Apr 2025 04:06:17 +0000 (UTC)
Received: from aws-us-west-2-korg-lkml-1.web.codeaurora.org (localhost.localdomain [127.0.0.1])
	by smtp.lore.kernel.org (Postfix) with ESMTP id 3A16FC369CB;
	Tue, 29 Apr 2025 04:06:17 +0000 (UTC)
From: "'Chen Linxuan via B4 Relay' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Apr 2025 12:06:11 +0800
Subject: [PATCH RFC v3 7/8] x86/xen: add __init for xen_pgd_walk
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250429-noautoinline-v3-7-4c49f28ea5b5@uniontech.com>
References: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
In-Reply-To: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
To: Keith Busch <kbusch@kernel.org>, Jens Axboe <axboe@kernel.dk>, 
 Christoph Hellwig <hch@lst.de>, Sagi Grimberg <sagi@grimberg.me>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Yishai Hadas <yishaih@nvidia.com>, Jason Gunthorpe <jgg@ziepe.ca>, 
 Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>, 
 Kevin Tian <kevin.tian@intel.com>, 
 Alex Williamson <alex.williamson@redhat.com>, 
 Peter Huewe <peterhuewe@gmx.de>, Jarkko Sakkinen <jarkko@kernel.org>, 
 Masahiro Yamada <masahiroy@kernel.org>, 
 Nathan Chancellor <nathan@kernel.org>, 
 Nicolas Schier <nicolas.schier@linux.dev>, 
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
 Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>, 
 Michal Hocko <mhocko@suse.com>, Brendan Jackman <jackmanb@google.com>, 
 Johannes Weiner <hannes@cmpxchg.org>, Zi Yan <ziy@nvidia.com>, 
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
 Peter Zijlstra <peterz@infradead.org>, 
 "Paul E. McKenney" <paulmck@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, 
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
 Juergen Gross <jgross@suse.com>, 
 Boris Ostrovsky <boris.ostrovsky@oracle.com>, 
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, 
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>
Cc: linux-nvme@lists.infradead.org, linux-kernel@vger.kernel.org, 
 linux-mm@kvack.org, kvm@vger.kernel.org, virtualization@lists.linux.dev, 
 linux-integrity@vger.kernel.org, linux-kbuild@vger.kernel.org, 
 llvm@lists.linux.dev, Winston Wen <wentao@uniontech.com>, 
 kasan-dev@googlegroups.com, xen-devel@lists.xenproject.org, 
 Chen Linxuan <chenlinxuan@uniontech.com>, 
 Changbin Du <changbin.du@intel.com>
X-Mailer: b4 0.14.2
X-Developer-Signature: v=1; a=openpgp-sha256; l=1213;
 i=chenlinxuan@uniontech.com; h=from:subject:message-id;
 bh=lLv+eC36iR+BfXD2pJvuB8T7k1wRLfuYuYg6Rtr4yeI=;
 b=owEBbQKS/ZANAwAKAXYe5hQ5ma6LAcsmYgBoEFA0cu56sCmDMkf/pntxUHuMuekP/XRkxukwU
 9g4TyNMqLaJAjMEAAEKAB0WIQTO1VElAk6xdvy0ZVp2HuYUOZmuiwUCaBBQNAAKCRB2HuYUOZmu
 i6oqEACNTdOu+wT9VWzDqaJxYPJzTDzhyaDgOrIaxGP72CExKq84a645B1Jl3TWZN1v4YEQN+Ex
 U4BBfSuuQ9Yh0TKak7F0oJPgeJp4PeTVBP15tbocmZJmYUHXdJX5kcB6+MgIe90/7/tlKRXQlN5
 uY8GMIazOdRrWgafA6k6G+0lJvn3E3R5v7129rFXvHWCYC7Nvp2Vr8gyxE2IYJVHEfZx/+ua0oe
 z4a0WQgFS0t6W9PacgGnUTntuj/TGKVYb500Jwut0dBDJITdWXpackuvyCzviwumgxcGnbW66J/
 sPOW9GIhrql6r3JIF1vU1iTJ1wxWyv8Al2Yy2Y7j9ypL0F07+xTB5euDs2A9h8HHd2x+0MwnqRD
 4T62VOpuvuHAy1CMHBv75g1GHhwTGMN1KwfuI0Pf0TXrf9JM01deVHQ7vjI5kZhyeYMl537pJVJ
 0itemi/gfnvcGViZ8usYXjp9yKtWO3JsSCn31sNT7BwsAtjyIUQl+DeQyQADc9wUchfIkTRw2AT
 nXmGd9l2kspY+Bd3KtnokiL1Gm1q49EmDFnwJw+FvsjxRdcZ56x9pI1MXcoOzCJNGSxYn35Witw
 vt49LNms8G/08qnrm3qBl6k+q0+gMBVS+JCmJst68knEU97MDg5chkLEEiEkEAzZLrlhGHN4eU8
 gFY2uFKRqDDEdqA==
X-Developer-Key: i=chenlinxuan@uniontech.com; a=openpgp;
 fpr=D818ACDD385CAE92D4BAC01A6269794D24791D21
X-Endpoint-Received: by B4 Relay for chenlinxuan@uniontech.com/default with
 auth_id=380
X-Original-From: Chen Linxuan <chenlinxuan@uniontech.com>
Reply-To: chenlinxuan@uniontech.com
X-Original-Sender: devnull@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="c0NlFGD/";       spf=pass
 (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org
 designates 172.234.252.31 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Chen Linxuan via B4 Relay <devnull+chenlinxuan.uniontech.com@kernel.org>
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

From: Chen Linxuan <chenlinxuan@uniontech.com>

Presume that kernel is compiled for x86_64 with gcc version 13.3.0:

  make allmodconfig
  make KCFLAGS="-fno-inline-small-functions -fno-inline-functions-called-once"

This results a modpost warning:

  WARNING: modpost: vmlinux: section mismatch in reference: xen_pgd_walk+0x42 (section: .text) -> xen_mark_pinned (section: .init.text)

As xen_pgd_walk is only referenced in xen_after_bootmem(void) which is
also in .init.text, I add __init for xen_pgd_walk to fix this issue.

Signed-off-by: Chen Linxuan <chenlinxuan@uniontech.com>
---
 arch/x86/xen/mmu_pv.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/x86/xen/mmu_pv.c b/arch/x86/xen/mmu_pv.c
index 38971c6dcd4b78b6b14f51bc69c4bf6b70ebd622..53650888be0a7b1dba170a5b7ba9c654244b5125 100644
--- a/arch/x86/xen/mmu_pv.c
+++ b/arch/x86/xen/mmu_pv.c
@@ -696,7 +696,7 @@ static void __xen_pgd_walk(struct mm_struct *mm, pgd_t *pgd,
 	(*func)(mm, virt_to_page(pgd), PT_PGD);
 }
 
-static void xen_pgd_walk(struct mm_struct *mm,
+static void __init xen_pgd_walk(struct mm_struct *mm,
 			 void (*func)(struct mm_struct *mm, struct page *,
 				      enum pt_level),
 			 unsigned long limit)

-- 
2.43.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250429-noautoinline-v3-7-4c49f28ea5b5%40uniontech.com.
