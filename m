Return-Path: <kasan-dev+bncBC24VNFHTMIBB7MKT73QKGQEEKWDUAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 667581F9FD6
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 21:01:18 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id v14sf12721709ilo.19
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 12:01:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592247677; cv=pass;
        d=google.com; s=arc-20160816;
        b=E8V1B/BWD2dKbwiM1bud2Jt0Ul9ZYmI9jzEkqcUyjCiAKtELZl8MnEUnDXFwbTAeDL
         r6hMhmUH5SMdTbjgjhCaoWem36rNXC5hWRsWecdN0QtqKN45bVY05HS/iVBrQ3Qf9V9b
         fK55J7vgOGeSzR3OLE6Ys7/3C4lkVDido5Ok9jhtbfUgVNb0DRrmK5DD4bcYGFWsETsk
         u2IJTc5hObHyaSke7Mkw4IX+1PnYdYwkJX8gdSVj/ClGsWqq6+Z+YfU4+ZAFLkkGxWtO
         j40VgCPRKafE1Ril0Ym6/z9xvg9u8UWOO5z8OLHRzjTf5K86H/IzufdTDERtsDBFCz0D
         IGdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=/mhI8Giqlzfd0han64kN16sjHV7bKdEq/9Hj5rwABfk=;
        b=O6nsU9GS4uHnJs1YhrB6k15qgth9DTDWEMwJGgWMlGtqKI4q6E6tVgJI3+RmOZW8Ci
         tdRiWIZqXYldB1IdFVCDKYcgJtNXC5j0hgCj86WYrccaV1lbg5ZD3YT8fajMHtsuF5yy
         /S5LQmCAutFyI0+2IFdW9eiitbxia8opIdz/r7GMX5U8D4dA/pX0Ppxe6AUVvrOYo+F7
         5QZTWTomvaxyqurRwkdsSuDWDbv6GnPYOUR+of1lZ0OBmKJDHGUIDsAxrxzA+3A64IZ+
         WV40/1C2iJbnaME9Z8jKpXa0QSGvisB7B13nN84YHxGpGdrIz/rBer48sW5G/m8oCDMh
         JBSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=roh1=74=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ROh1=74=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/mhI8Giqlzfd0han64kN16sjHV7bKdEq/9Hj5rwABfk=;
        b=e4j8+inqb3uip0iJazbmw1nQ98LDbV4W2eix+5gohaSXn4z02TmaAik0LmKcPJm8Kl
         qO9LHendZ4LbRy5U5jDbHWRGhxZ45Gpcip61z7WY4kWMHFx0YGQpI+sUw1XS5vIjqiBJ
         X1euZ7ed+ZpwR/ldauuPJU9a4Q62F9vdTSY0KgQ9KDkTzEgCOo3qYiceOdFFDSS57VBB
         x4RguK0tlxQDDLvqRmb4j/W0CBs7McHN6YFmjADeKyWRnE7UqwrFy9Ryawdoe4Sm3lXr
         SYg56LVd68uCbxBvWgOT23TcYRB9f4tIWYEF9N69uxFxbAZf48XnmD31ES8OXeC7Z3hF
         tTDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/mhI8Giqlzfd0han64kN16sjHV7bKdEq/9Hj5rwABfk=;
        b=eIOOG3nrKS5yjMokc8CsU5xno8/ANZco03mUueyKU44rORnWfA9PdVipX7ocpYDPrz
         TApNUdVOj8T8qFx+zQEopLToxBThiHWYJA6Yj6PMq2XuvFAyL6gEZqinLrCDYMMFtwm8
         hxCWoDdyS/dTx+ZD4VUFEr50kO6R5XQcG9na6pJOU80w08O0jfTLe+iZHunMCiKbIqEz
         B8tQGMlc/OPigUduTakt/j8eJ854e3WQklVt0uKuq/LN8zXUowgllKV4xy9GXIM+jeNV
         HgQJFI2rlKmWBfXF9zGApGlaJ6uTTZEP5jhUdgPeQ2OcAmDEAyfIe71LgQxKRLXOkrbz
         5Txg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533LQJI+12cScMbtzemP7R7+KUN+UzahGWCIJ3gb+KYqXG0rB8Y2
	JY+frjf/z5/FwpG5OTn63lE=
X-Google-Smtp-Source: ABdhPJwI/e6tFCIRBkQOzTueFWcIPScElZXHGqYg9px9T68dyb0zn9giSsKuU/0JOMt/8KZ+orBSiw==
X-Received: by 2002:a5d:8e14:: with SMTP id e20mr29867855iod.156.1592247677385;
        Mon, 15 Jun 2020 12:01:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:d0a:: with SMTP id q10ls785764jaj.5.gmail; Mon, 15
 Jun 2020 12:01:17 -0700 (PDT)
X-Received: by 2002:a02:c802:: with SMTP id p2mr23188066jao.111.1592247677063;
        Mon, 15 Jun 2020 12:01:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592247677; cv=none;
        d=google.com; s=arc-20160816;
        b=XZJh9Z4CoB8gXJ4muYn0KndanOZ5P+mXjTaIDG8oTdj6R8/92lr7vu6EVXZLKI7B8Y
         +kMM0GCZ7GwT8om8wsn3LoscCzn9p/W9zuP02xrDeQZxPug2jLvSnCakhwBoWtm9fWxo
         WKfSgvG+ECdPhFvaLYqX0TqqLB7LNXFs+XPZsN9aJxPko43C9vg0ZmBHY5IQWs9OPBvx
         NeuVTODWFQL/LNq5MSFdUm0R5LINzvWM/FOByjb+KRe9rMJDYI6VLkS8MZVmKu5+IkGl
         f6l7Mwpj++udDtowkgWlDNEdwlgqTCywTNbEtg4HSXKSMVp4FpuViqRB5HbXUVI7IIOE
         /Clw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=6XsOt8dIA46603jvdYNKYOhvM3dCYGgp3Rnh4dM2dNw=;
        b=Gx3y9xIbB3Lff0WK0V9Y8dYpYZCR/xG+Efk5PcaaBkfjiSRIUiF0XhSoySbGK2mUtF
         o1v8uc/YZ+3OGzGqVRbLLI+HxFZPkNEaxRoY/VidtHVQ+tT74qTar2+M6pv5V4GUNoFz
         oG9yQDSb0hJo+cEV5uFpxglDhm3XP4r5VzBh9RV5keo91xM9msjZ5bSNtCQFxOxGjPTG
         gwr8l6J9EeZ6Z9xDOthXD48E6009XYc22+b/yQ0q47uBq2WnsQZ315u3Fy9y5U2Im9p0
         +suof8dx0tlg4MRPxl2Ts3kwZfqzlb7JBJlYmYctU4+MX8aRsKzB1BArezBCd341+JLg
         BDNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=roh1=74=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ROh1=74=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k1si959285ilr.0.2020.06.15.12.01.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Jun 2020 12:01:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=roh1=74=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Mon, 15 Jun 2020 19:01:16 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203497-199747-iw8ugFaM92@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=roh1=74=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ROh1=74=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=203497

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
AFAIU the issue here is that HWASAN instrumentation doesn't expect the sp
register to be tagged, but with KASAN it might happen if the stack is allocated
in slab memory.

This patch should fix the issue:

diff --git a/kernel/fork.c b/kernel/fork.c
index 142b23645d82..c9c76a4d1180 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -261,7 +261,7 @@ static unsigned long *alloc_thread_stack_node(struct
task_struct *tsk, int node)
                                             THREAD_SIZE_ORDER);

        if (likely(page)) {
-               tsk->stack = page_address(page);
+               tsk->stack = kasan_reset_tag(page_address(page));
                return tsk->stack;
        }
        return NULL;
@@ -307,6 +307,7 @@ static unsigned long *alloc_thread_stack_node(struct
task_struct *tsk,
 {
        unsigned long *stack;
        stack = kmem_cache_alloc_node(thread_stack_cache, THREADINFO_GFP,
node);
+       stack = kasan_reset_tag(stack);
        tsk->stack = stack;
        return stack;
 }

However even with this change there's something else that's wrong, I still see
the following crash during boot:

==================================================================
BUG: KASAN: invalid-access in start_kernel+0xd0/0x568
Read of size 8 at addr 63ff900012337f90 by task swapper/0
Pointer tag: [63], memory tag: [ff]

CPU: 0 PID: 0 Comm: swapper Not tainted 5.8.0-rc1-15086-gb3a9e3b9622a-dirty #64
Hardware name: linux,dummy-virt (DT)
Call trace:
 dump_backtrace+0x0/0x2e4 arch/arm64/kernel/time.c:51
 show_stack+0x1c/0x28 arch/arm64/kernel/traps.c:142
 __dump_stack lib/dump_stack.c:77
 dump_stack+0xf0/0x16c lib/dump_stack.c:118
 print_address_description+0x7c/0x308 mm/kasan/report.c:383
 __kasan_report mm/kasan/report.c:513
 kasan_report+0x19c/0x26c mm/kasan/report.c:530
 check_memory_region+0xa4/0xac mm/kasan/tags.c:127
 __hwasan_load8_noabort+0x44/0x50 mm/kasan/tags.c:144
 start_kernel+0xd0/0x568 init/main.c:854


Memory state around the buggy address:
 ffff900012337d00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 ffff900012337e00: 00 00 00 00 00 00 00 00 00 00 00 ff 00 00 ff ff
>ffff900012337f00: ff 00 ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                                              ^
 ffff900012338000: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
 ffff900012338100: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
==================================================================

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-iw8ugFaM92%40https.bugzilla.kernel.org/.
