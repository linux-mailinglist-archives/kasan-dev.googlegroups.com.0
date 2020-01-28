Return-Path: <kasan-dev+bncBC24VNFHTMIBBD7AX7YQKGQEUJR7GQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D29914B0D5
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 09:25:52 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id e10sf8212248qvq.18
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 00:25:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580199951; cv=pass;
        d=google.com; s=arc-20160816;
        b=dOBZlpCVxktHRUhxeP5DrAl8svSOm4pGTvl4oVEEXBY3HwGdK/lXJx+g07dOHoLOre
         OrzPKrxi4AB7Bqd/b+GXOvia1zCQ5HSnbDwYTsoJh4SpYcWqecy/kUYXglHa4+zCndbf
         hBSO+GfJDSphbfw1xU21xMphbjc0nHFQFAU3nG19TFPiLns7gx7cwCCWjeOKVEp21JPF
         UFDp7pYSV5xB1sQCzJ0Ltzty2bOzaNk3RF4ObWGShu+TYM0MLjZmrdwi01ECb8mu6m6z
         K/aWOUAI9nsnDoE3djS4huwYhuZ+id1aLhY8/JD8gCa0VU0me/CnQVCD9NJCKt+27swo
         wvkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=lAMq2CIw4wYZRlmdrNMWTgdyPjym/3RwcZB/glf/NRo=;
        b=VdIyW8nhN/9R0ms8RS0vTq3/YVjMYAv2Z0eQExl4AEd8NasvzofeahDoQML0ZYgY44
         O9CRJN0nmmKF3kCxxE1r1x2FRkFs0E2FCqfMC2zoRKO4TZXnJajKSQxksBXxE5OvhpOB
         vsQrmuJuc79gGFP0H7llTpmb+dzvjQi+tqpnyLhvzi/FFh0xpAvCfcKtl/1e35Vg+BFd
         iJABGgaQSN5KoL9l+nurYECQRqql39gYoOHQr9tbOg05J1tRS8xiqomuXothpx0tG06K
         7ygfINtBh0XIYlEJZ99gSJPRYveYF+h7oNYWL/XOdXQvNh4/dcVZwJV5tbwtfUW4QvLY
         /POA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lAMq2CIw4wYZRlmdrNMWTgdyPjym/3RwcZB/glf/NRo=;
        b=oR+Kd2+e2pjBeXZjV2MhyREaVVSvAHkApXm5WrAuBlcLgwb+H/tUTTMOLVx8HpZAlk
         uh4wxZTYu5r1BfMFad0d0uvzFYKP0uidIh9R/oP1NWZQCuBmR9Hn/Oj4XMIS+MC3RyDI
         UvcZ1sn2MhDx3J5fnaM3G404kHlesSAZCwNd9lfDv0dB81JrRi6jHq4ygi7RLhZK9Y8n
         hPc8elQ/qMz+BUtmzEbW6A1hts/Jch8ji44AEdCm0ESEeI/YC4AsgabAoM8s7EwT78Rx
         1aI9xybJP3QyImgzcyNUpaT3cEsbFqV9mKPtvP5zI2yCeq7wyGIhVDwJAfdpQzKqKifp
         cnBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lAMq2CIw4wYZRlmdrNMWTgdyPjym/3RwcZB/glf/NRo=;
        b=RMa3zxQkG96JKdC7e+f6p4Vm8h49Po8SD+qdyBWrPwA/vYN0k6Ae/yyY0vsteuE6WJ
         QO9mqwJs7M2EPAcQmr+SKHgNs7uiRS/vZCpu48dSGl+NwItGmFB+jOOLiLtvug3SnX37
         9fmRhhj+0G158I8AQnLyNWzx1BoSE0DLQeSSndTWWr0wNz4kdmql6fGvo8lS42gA7S3V
         8XEc0c/nL6wwJ/s2W91+WYFBoOqEahZ2wGHXu5LRkwvA4u4xH1nB8LTRCl0hJivPz+9Q
         HNeSnABnCfA//1hCd/b17kPpnQbOluIH+Qbho+eMc3tzXxKxIBEZCrGikl1nKWDls+Yu
         OZJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU8ptDocZQVaQDVhRwfq1p2Ql8lstQ2NzdAVi2BWhiXyaP3EqNK
	8P4cWN+CKc1aklwP+OXzj8Q=
X-Google-Smtp-Source: APXvYqxPWes5Ud9qBgI3q9yd1SVs1HROf5QXl0Brf79PRarPqWRUW5JuxxuxVeLWVJO+szfiA5U4UA==
X-Received: by 2002:a37:a8c2:: with SMTP id r185mr21707236qke.455.1580199951321;
        Tue, 28 Jan 2020 00:25:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:42c4:: with SMTP id f4ls1412431qvr.10.gmail; Tue, 28 Jan
 2020 00:25:51 -0800 (PST)
X-Received: by 2002:ad4:4f8f:: with SMTP id em15mr5249273qvb.169.1580199951027;
        Tue, 28 Jan 2020 00:25:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580199951; cv=none;
        d=google.com; s=arc-20160816;
        b=JlIVjQk+ZOntkdBNsb4ajVcNg0h8N6AG9baiLX/sAbOCNSUWIYjmxwv/KHqOXBD8CH
         s1IHs66zWZdVLlFQxFmLCl4LXOxd0REl3vGbWRxphhipfSiqmT/mKGNA6VcGLWSQrKGg
         B3FOB3Y3rCOVhC+A6xd4PzEL1SV8Lcm2mfKGC2UUMVfNd2iiEy40MSuu29tw/jq+G2kI
         Ylfwf7QWgd1BIBUFQ8de/UHMhid59LStuH+i0OffF95y73VXxZO6bl8P5HsZtVvbyuJI
         XdNWB7PhgQgnSaFEy2oHC0yzCZM2uELkPGuYp7RD8tRvV1LUfZjnDZG5R5W3Vqwbl2Qj
         AYrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=pw+qwh6brSvc0UoqMQaTekSHiSkJ36B1V5OEdK0C6No=;
        b=PhtO/e1WHPJ/DeKfFaz7ePNfRv9avJ3ve2vgpLBhtdviKX1/L/oW46eFsFpkuWNdb+
         AkYp02iJ4S6IwAi5FZI1hlZLNh15AS1kBHJxkJaPKY8sDZVM0lP3RjZfQTpTGutd8wKZ
         lnKKZJUsoeBWEZpwsvMKWp9usC6wenHJ4xMw2N24G8z27PWj7ti1aaaxO4uLmp2cWT4I
         RchMAaqx2HwficrVgjF+sacXRuffEWSeP1FdlCmFEvXHwZ5rLEPL02wMVLtM9MkUl/eZ
         VZYG9MRvfvt2VlzDZWnj+TzfG4O6iYrbd8R5V/aRTcgJmcYTO39+Z2FvAuF0qkwiZhEH
         r3Rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c22si447573qkk.0.2020.01.28.00.25.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Jan 2020 00:25:50 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206337] New: KASAN: str* functions are not instrumented with
 CONFIG_AMD_MEM_ENCRYPT
Date: Tue, 28 Jan 2020 08:25:49 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-206337-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206337

            Bug ID: 206337
           Summary: KASAN: str* functions are not instrumented with
                    CONFIG_AMD_MEM_ENCRYPT
           Product: Memory Management
           Version: 2.5
    Kernel Version: 5.1+
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

The following commit adds the following change:

commit b51ce3744f115850166f3d6c292b9c8cb849ad4f
Author: Gary Hook <Gary.Hook@amd.com>
Date:   Mon Apr 29 22:22:58 2019 +0000

    x86/mm/mem_encrypt: Disable all instrumentation for early SME setup


--- a/lib/Makefile
+++ b/lib/Makefile
@@ -17,6 +17,17 @@ KCOV_INSTRUMENT_list_debug.o := n
+# Early boot use of cmdline, don't instrument it
+ifdef CONFIG_AMD_MEM_ENCRYPT
+KASAN_SANITIZE_string.o := n
+endif


This is way too coarse-gained instrumentation suppression for an early-boot
problem. str* functions are widely used throughout kernel during it's whole
lifetime. They should not be disabled because of a single boot-time problem.

We probably need to do something similar to what we do for mem* functions:

// arch/x86/include/asm/string_64.h
#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
/*
 * For files that not instrumented (e.g. mm/slub.c) we
 * should use not instrumented version of mem* functions.
 */
#undef memcpy
#define memcpy(dst, src, len) __memcpy(dst, src, len)

Then disabling instrumentation in the single problematic file should help for
direct calls (I don't know if that was a direct call, though).
Or do something else instead.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206337-199747%40https.bugzilla.kernel.org/.
