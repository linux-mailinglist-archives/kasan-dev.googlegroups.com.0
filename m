Return-Path: <kasan-dev+bncBC24VNFHTMIBBEHOR34QKGQE7JSLILA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id EFF52233EED
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 08:15:45 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id w8sf20824165plq.4
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jul 2020 23:15:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596176144; cv=pass;
        d=google.com; s=arc-20160816;
        b=BN8z2zmLwI9NAmeR0GnJDNipf5/8opboKk79liUP5f7P+QA64yIl1AHvmSRW3SMbEn
         EW53zdpJZADmwsmpboJQbIIcw4Mt8mU8ANal5thAr7jeywmF6AyRoA1LHLi+dA3R1bLa
         kIDim5U15OGHr7bjtk0xPQo2lfK2znPWtx9ssbFT+HSZPHmu6fqvuheSOLYT8+5m/Uqh
         oR6lnVtwvsG+qx/mRigVC5rtu9aDpNpvWQ2X+/Gc9fbGOdleVDjrA8ydDHkiUZkBdFYv
         3PsBI4q8l+qb4t5+m+qbo/q8qQmsRIrR9QlfuLYGJB+DJvKZ8A1280K4dUghtoAVeo7R
         Drug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Xto5OLf0IisHaXOkxBj/yuIwKD6AISovfKa97cg9fI0=;
        b=I+tYm7NBBLn3udp+nn8y7KF3f7xA8RrfzQsbCMNAkWiqr1BPlcVFB9NeKV8bOxT4Kw
         GdQD0ikbycg0Gep7Kn8E2BSStOSWS93OZSfrMSqL7PQ3CQp9paTsVLiP+Xl7PwsPhvBY
         qnMHIPCMK3UlhXOPV2zkWN4v4AwR83hMcxvygcTj/n6VcvUBPNrVLPRC+2cn/KbQJM6L
         kIztQjbiLbl7LVY5+o9RrzrieBuCzJkENX4KZFSgliJziGEjTs8bP+TVt+PL6AHa9NWT
         BTx1siEEwm0okPXn687tLnVQYvBDCgxSBIsnPPT3SRUI/z4PXecfhedlD7jJORYC87c+
         +tNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=quxo=bk=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=qUXO=BK=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Xto5OLf0IisHaXOkxBj/yuIwKD6AISovfKa97cg9fI0=;
        b=HbxpXXUwnJNpsOIOewrS5oNOKB1H2s5pusljEn6rZOKFh8xOLkICVoLyLiJeAeZuF5
         5+VVlXnzNFXcMimmYMDYX9rjEkKBppSVUtGo6mSS/0PWbUba0kuqBFqbxHOSW+enAYPc
         ICkfevGKUfvfV+2WiICifwEObTq1lXh8iSo4kjC/VuStFWvbl/K+HVsgmktxfC7952Fx
         tRw7V30a1Q4+l4dicgZbYzhTuXUodUzZo0SGPcJLd1lNYWP1mmeiTKpOEKJQBoAGoCV7
         lAOLER0oPRNSJ+DeTUZGZuLYTBjn+pZCcqMwWcMX4OvvdPZyb8oHQ04+H+qw7ol51shS
         ouNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Xto5OLf0IisHaXOkxBj/yuIwKD6AISovfKa97cg9fI0=;
        b=S/PWsIqu9O8HB8S2X/BoIUyLiOEOxjdr4ZgwhTB7AOXJj/gYZpfpleqh3UVACF2jYc
         bpEHtTvOB75knvBYP81ysf2z17jQO9FrhhSXZ7XqgEwTbeXo8N61dWybH6scmdAjuyzK
         HHOeumxnvdF7bUvw3+RYWew7S2zHzHpZW6zJ/G4bfSwHmNKd/2Wz/loO/TLg+7KT8rLH
         FmJpSy8CJDgD27SlVaQ9AeHvzWxmOad3yJGLxlsofLHEX5zllMb9VRQL04yGjhzqiZZT
         XXHoYf2tFzMULC/OOIlG4K2xgOjdxql6/+3ZI0qHIuhOG6pX7OntxhXNmIKXyjPjWz6I
         4p7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HPryCYf0+W5je3TIpi374fw87cIlwbQMD2S4iSzRqqS3mYqf5
	ExAhTRTiqdOyymWWteS/pMA=
X-Google-Smtp-Source: ABdhPJwuf9B8IO1tUvDqKgDJhqeTIYo7a/QJ233cREGsB1cZkW0DJBzACvCOB3zl1Vfo9GTDzPvm+A==
X-Received: by 2002:a17:90a:cf05:: with SMTP id h5mr2486542pju.219.1596176144611;
        Thu, 30 Jul 2020 23:15:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1c96:: with SMTP id c144ls2698828pfc.11.gmail; Thu, 30
 Jul 2020 23:15:44 -0700 (PDT)
X-Received: by 2002:a05:6a00:78e:: with SMTP id g14mr2257333pfu.171.1596176144238;
        Thu, 30 Jul 2020 23:15:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596176144; cv=none;
        d=google.com; s=arc-20160816;
        b=O20CXC/iLzyOXy9Ouk0VcT4QTtHbs9u18tyLQqvEAEgmEqNrskUFgFtGm0D+2Y8FoQ
         fqidr1gl8KynfKG6WwyTI7JAXZmxZLehuS36x9W8EUzefH0DBGj3HgB1h36LREDJqcCC
         SQx7uUKTmkv/y76QCb0DEQiAXRViKEqPuPcVUlgnK+LYzXlg7Sotm1GcerbuuZTlfKZa
         1NzwCKhvENrzh/J3j+nJuBOYtgAk5WfcQzxDrYk8TBOqdxlHZos17lGjSXQJvyEVO0iY
         KhyQJHGsy8uNqxCb1glAJLAITwO6KwdTW2S8k6eOC16wh0tWuytRfrT8Md+vVxH6yVyT
         xSLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=NHSD5S2+bHxLcFD0M9PjTMLTEoW/ZXlaCGymUpNLGlw=;
        b=ivRdunqCNibot+XbEohmbkJZYKFHvZPdM1KimYxzL4YNvPRAJ1WRD/6Orp8a/uccGC
         ESZKzixfcbz9kJINcWkKQZcsN2f05+mEJ2DUm3pBk5vElxFUU74GyuXwdlohuMjRZdbu
         /lZIWsKGSMXt0Au4mnAhp8WihFsSTMn84mYdwWMjG0S8wS6u2Fx/XCrb4FD92qeasjcK
         UvgeV+fRz8vU6SFeeo6hwzfUKNZ1WqAmd2gFDD8sWV+998v+Rm4pyl7xe31SNKjSBdzT
         SxdRvnF1TQMnUqEZErARgmymvxYSxT0dG/TsROsT2fcIQf5Jtn0ZqDK3yc7BUSUcPVHe
         GYNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=quxo=bk=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=qUXO=BK=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d16si413020pgk.2.2020.07.30.23.15.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 30 Jul 2020 23:15:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=quxo=bk=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (sw-tags): support stack instrumentation
Date: Fri, 31 Jul 2020 06:15:43 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: walter-zh.wu@mediatek.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203497-199747-eGZdtRmwhg@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=quxo=bk=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=qUXO=BK=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

--- Comment #22 from Walter Wu (walter-zh.wu@mediatek.com) ---
Hi Andrey,

Thanks for your help.

It is workable for me. It looks like no false-positive issue, and I think below
patch should not need it. because it is fixed by hwasan-use-short-granules=0.
https://github.com/xairy/linux/commit/a48d20d2397d084af3790dfc5ddfc83b788ddd9a

After apply patches, I try to execute KASAN UT to verify them. The stack oob
test should need to be fixed. Could you send below patch together?
Thanks.

---
lib/test_kasan.c: fix the stack OOB test for tag-based KASAN

With tag based KASAN, the stack OOB test doesn't trigger out-of-bounds
memory access. This test need to be fixed.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -488,7 +488,7 @@ static noinline void __init kasan_global_oob(void)
 static noinline void __init kasan_stack_oob(void)
 {
        char stack_array[10];
-       volatile int i = 0;
+       volatile int i = OOB_TAG_OFF;
        char *p = &stack_array[ARRAY_SIZE(stack_array) + i];

        pr_info("out-of-bounds on stack\n");

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-eGZdtRmwhg%40https.bugzilla.kernel.org/.
