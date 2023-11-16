Return-Path: <kasan-dev+bncBAABBW7426VAMGQEOGGWBPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B53B7EDFEB
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 12:34:52 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-35abb017f61sf6288315ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 03:34:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700134491; cv=pass;
        d=google.com; s=arc-20160816;
        b=rpU9iYMxPr7u77/nVYdDEtwXPWPCMd7CJrYpXETi+2PMNbVevPZHVtQC3OGyZc55bL
         idHbgdG3ry+f6oiFkVBh9VWNNcjXrvb3B16GCj0flD7jW8Qm2jmIFyKiPEcMZ2ejYxDL
         ddpqQd54Dise2x/K8UBDPSYXx7c/7H+nXvwQXMcQCQNi5J23uJOKJqVjYGWHS/amq12S
         zM12XMfHcYQZG1r/8AV5Y6ALyGttqQ5PaVKTwLhTXB1iVdBMwfUw74XO5LyCbNH9zpgc
         kSsbZx7SNO7L0VIcIQlbCHiO3+ZhKuN+Qsm3FQURgghB3xOhrCzzhn+Ob6PC89LPtyPo
         PsOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=oJ7G6n1XOXRylJKkLWwrKvUZyPxzVYh8aP/YDGNwSWk=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=D7M3Ub0AhUoLGXuHykxHU5teVi5xl+756JB26+sBOgOhcOeGBm8xaB73+OnGshLhhA
         lOXf01w8nWFmJHm11ud7BMZQCORc6JtZgfJLpomIEJxnr72x1xNH8gn7GCU1I86eEbbK
         U/mLhXPiNPFK8ggp3Kpzpr5YTyKrPOCtzFI2FKI4ZmcL/VPOWNO8DoanoMHqVsmCJRsZ
         vTabd6ZiczLpMhI0r0atRnYEY2ERm2s0K2PMBfdSZGbIizMNLkm9boHWK7NU3GwyHPot
         Xwhi8sbdMYk8uVn5FfqXD62lqr/dGiRy87n6saQkyZEDpqxeRjF58SSY215EzWhurKQ1
         5Yig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LXDB25iY;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700134491; x=1700739291; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oJ7G6n1XOXRylJKkLWwrKvUZyPxzVYh8aP/YDGNwSWk=;
        b=a9WakECTvax32BJBeyDjMsEwmztrPaiacXKXVE8V0LW4L4SH9/LYRQpylvtVufXOnZ
         W6JDvI7rTuPROvUf1cCKIG2RoRKpJapQKhrsJEw2O+Y42RSp9Fjp4UWH758YaeJ611B3
         Em0PN3P4ZPopNg6w0y+6pZKQxoAoOxs7e9T4UOgjRE0cYzleluR0qDiR1hQmV2c3Uhwb
         ZGaqQOv8fLNUL7rIaKIftuNQNVmDFdxHStnA2EukJcXiKcnpWpjrBplign4rS91/FVKU
         /rTXk/QCDFmCdAj/0Yrdm8aidUTi/QrQ4uUUi8WPJL2G8iQjTUn+Sx92pnHxq031nwtT
         AmaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700134491; x=1700739291;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oJ7G6n1XOXRylJKkLWwrKvUZyPxzVYh8aP/YDGNwSWk=;
        b=TV213aUlkO2JnpgJr/eKI9z4EgJ2sJJdgn5uhlmH6cUMtEyeQ7WPvr2rjX8KYuM5Hq
         Wq+T501z2s8DUH2rtri9FkMH/1Yyl1WUnGS4bhw2VaeCCz26io4xrenpHwL4j5ZIcP1O
         C0RkhiV4iDZA38yXYpySrM6rAkm7xihtvV0QSBhbq7WJkDzWWsCt++RT1td5lxPeAFk2
         Snk4g6HJq1jBIPMzjmu2aEcShtQVwsDnsa2kgQtZb3QFU2NePEA2yN51qnLPE7qEP6Cb
         Iihju3jhqgOoKHf7X+HCKiZtOdopXyMIawmnvBMah4PA3rVqUwJq+2uUZtnD9V+cipIf
         Fvtg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzBmzI1kEdeyHXSUZwSBaqUcS85eRE443QYiE8cVVP0huAwGVjd
	T92GJToQNT3dSpMJbd3r/nc=
X-Google-Smtp-Source: AGHT+IFkxdvdcNKPcscOI8QpxYkKvWyQz0V1p+2HuCgSpFLCbL3N5EicMgPijOEQoGa8bOdFfQAbag==
X-Received: by 2002:a05:6e02:18cc:b0:359:a77f:2903 with SMTP id s12-20020a056e0218cc00b00359a77f2903mr21877124ilu.1.1700134491384;
        Thu, 16 Nov 2023 03:34:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:351d:b0:357:3d9d:209e with SMTP id
 bu29-20020a056e02351d00b003573d9d209els392313ilb.2.-pod-prod-06-us; Thu, 16
 Nov 2023 03:34:50 -0800 (PST)
X-Received: by 2002:a05:6e02:1c22:b0:359:cbff:fc69 with SMTP id m2-20020a056e021c2200b00359cbfffc69mr20478546ilh.12.1700134489820;
        Thu, 16 Nov 2023 03:34:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700134489; cv=none;
        d=google.com; s=arc-20160816;
        b=E3EnX+urin4sqh2Am7JF/cA/WfTR+ODlJVh6VWSNYpYsGgPacsYyn/S+5x35aJtN6r
         bGEZmwTt+QndaS19K1MtUYy8ks0sbhaT2mgm5cTFjzM5fSZGmip/aOODwv7QWFTKA5dB
         AakgMzrsoT97c7a32bXjdS/wXUnhSnssigdq630VAuR7JrzILv4e9k6BR+iFpnDnhx/9
         CbSSez8aC5OHVhgMzHlvP5mCMSBjZ8f9Ad1JgTUp/l1q9SCHfPPB34dQaFBD9bar+M1v
         5/nKkFnVSBTBlRVNbJxN4vdTWuOBRMEv15n9BuaWsLmg3x+FI/NjASZWd/94iL/YbKH1
         bYKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=iBGYvOxzUOn0FBOWi0ufMFTGmP95RkkjeREjaf4wYOU=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=bUJ5hKU5cXpATweXH8VM0DSDpHKHvVB12rBM6Cxv6PAKUcmX9/PlpEkq577OlR4F/N
         Mk4sGJFaJoMi1G/qku6B9Iel1qWL7LGvu+cIuS7HvrtLTPLQtYtr5f5NDuLstoJxEt37
         fKyMYdkAc6nHtjR4BLkUTVw9hHXSlnphrQZCge2edX3Us+H4HZauIL30DB6RnG5dM2tZ
         zBZFyPCoCfQi4xxwaWiKMp4pLoh10VHT6V8bnAqlQn72zAAltJiiUWrr8Rg+Tez+SQYb
         k1IfXJV8eCUywGDaEHKMk+rmztuJHJP5NFkquODC/9L2S18Dxr2g/vMJ6UMbhFL+ovFq
         JMMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LXDB25iY;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id bp13-20020a056e02348d00b0035ab283d159si1378783ilb.1.2023.11.16.03.34.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 16 Nov 2023 03:34:49 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 5C7116153A
	for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 11:34:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 0E3C4C433C7
	for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 11:34:47 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id E5AC7C4332E; Thu, 16 Nov 2023 11:34:46 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218153] New: KASAN: detect accesses to user-mapped pages
Date: Thu, 16 Nov 2023 11:34:46 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression
Message-ID: <bug-218153-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LXDB25iY;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=218153

            Bug ID: 218153
           Summary: KASAN: detect accesses to user-mapped pages
           Product: Memory Management
           Version: 2.5
          Hardware: All
                OS: Linux
            Status: NEW
          Severity: enhancement
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

If we have a use-after-free or out-of-bounds that accesses a page that is
mapped to userspace (e.g. with a normal anon mmap), then currently we do not
detect it as bug, since all pages returned by page_alloc are unpoisoned, so
pages allocated for userspace are unpoisoned as well. As the result kernel code
can freely corrupt them.

We should try to keep these pages KASAN-poioned.
But need to double-check what happens with non-anon mappings, and what happens
with kmap.

For future reference: current path that allocates pages for user-space is:
handle_mm_fault -> handle_pte_fault -> vm_normal_page -> do_anonymous_page ->
vma_alloc_folio -> __folio_alloc -> __alloc_pages.
Perhaps we could add a gfp flag that tells __alloc_pages to not unpoison.

There should also be an eager allocation path in mmap(MAP_POPULATE).

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218153-199747%40https.bugzilla.kernel.org/.
