Return-Path: <kasan-dev+bncBC24VNFHTMIBBC6Q2D4AKGQETS55RFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A104225170
	for <lists+kasan-dev@lfdr.de>; Sun, 19 Jul 2020 13:01:33 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id a205sf9361408qkc.16
        for <lists+kasan-dev@lfdr.de>; Sun, 19 Jul 2020 04:01:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595156491; cv=pass;
        d=google.com; s=arc-20160816;
        b=FJpp2nIBNCvWUK4MvEAvTSDmV+3JPAY2fhA+FO+YATU3t34stbSjIol/12Cs4RDXtn
         /xxaDKKqN6KQxEwV4AT/aJOMHavxnC0zE+Caa7iPHskSWDC8w9WuZy+RB5cE3NPu73VB
         o0K5uv13yOVjhGJcF8IZd4sW7i/13M9zxQm1PiyX96OyAyX3Qh92DudHPxmvxZvHJi/Y
         8kFgqRVo7TEiYhdP7VR8Hw5qDTYvt02sD7GJbmOj4bvX38hucOTpztKaBnN8HEMZc35M
         z9nHxj5mm/ZWquvwZfFzX6XehcYMzgecm9WMMm+/ZwXHOYK8Kq9nJmgA9XaAH9gMY803
         Id/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=kPgkBxUDAteTbKHFwhFyHiYIFGifAa83pdwDebaDIU4=;
        b=gFyko06UltDdG0CaEzWXDAbxHXqlIxaWB6YeATbxavXtq0TuZYmp8NVhejU2uQUXn+
         2+wVGc1w8ws+H7RSd9TmLfw3yK+hZuGEzUOECUtXM3/BhNpdXG/1/lt3ZM40oT/nKiGV
         BipnNfEzsF+/zL/g6bwmXYYGPkMPcC9YCbXMzHnljVIOIWBdskDripBXStvhPfEciTWy
         KIPTEANpGjc5M8H+TgKcQlZdRN2EktvD4if+SfkbgHjG6OzrHinhkGDVa+NxD1Y/g4XK
         I5M6e4EX/dTEP93FQh83DaoH5LmntpD68eKz7QdAUtI3Bgbbn8qFBasj26QS4Ark6vHM
         UdFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=d/lx=a6=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=d/lX=A6=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kPgkBxUDAteTbKHFwhFyHiYIFGifAa83pdwDebaDIU4=;
        b=K2jho4U1K1oO1+BwlFSJX9TmSca9Z34AhfV2bLN8PEEqLELxywDuFvBp9X73d6qAo6
         /+9kKyHINaR4BdOjAsS1GLFHcflvJd0Ezgyb2naX/fqdly2bfXLrq1BvitkWkhjUgDAX
         p4W+ka1ZHwHwEqH8lY/FFLMNn8bbfcKv3qP39XDeufHfOvifosk8V6oBFljf5oTE4dsB
         tRBCAtdhVwfLcJA11+H47ujW9SoRGK/CItyYAmMoiW0OMPZ5TlWYWvdUCz981oXQNDE2
         cZSA6PEC7UFmWcvtMn1pne1WacvBdIfcg0K3JtCyCcpaaiKCqRNJawLG7eBUOgdrLX/6
         kIPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kPgkBxUDAteTbKHFwhFyHiYIFGifAa83pdwDebaDIU4=;
        b=S8+43O2k0FhrZFhw/sK1baN4xoVaEJ4E0cALdSrtl55JvsdpaNhpoBcbq4sEV65JT2
         9Pv1eGLrA13EQVXaHNxnRPUbVzsws4/AnuiSvnZiLtJ0Jv6+oe8hdWmTj5lOCs/oUDzG
         kyqPzKXCU+BX/I/gAU7oWnMSAJ5/pwi0wmZJdmKQZHg3obcorOS0vuIyEhoNEZXNkD0z
         c+FSvatDb8RPvx94Er7CQaCbBsEOLNpSKAmfos/IsVCuqwI6v+JCUTNmZmz2sOgiE4v/
         Ti8vNAADe9oWpL91yalpXaBZ7I4Opu6/HOO4mJC3JqHhkOb56RJmSDxXwp9+9778Nrt1
         7SAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533WlTukJ44gpbLfPH4onZU9Xw+5ZZEBEv/qfrzlhvEvxaQoUSWl
	3AusX5leQGPxtu3e5M99lnE=
X-Google-Smtp-Source: ABdhPJxHF+zj6BsZC7FwntMfOxGiV2phlkyRHxZUbSQqegMgR4zu2gVB3bxzlcLf1qktQPebF8YwRQ==
X-Received: by 2002:ac8:1972:: with SMTP id g47mr18835813qtk.180.1595156491748;
        Sun, 19 Jul 2020 04:01:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f307:: with SMTP id j7ls1000940qvl.2.gmail; Sun, 19 Jul
 2020 04:01:31 -0700 (PDT)
X-Received: by 2002:ad4:5490:: with SMTP id q16mr16473342qvy.58.1595156491403;
        Sun, 19 Jul 2020 04:01:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595156491; cv=none;
        d=google.com; s=arc-20160816;
        b=O6dX2YNmNuOjqAHFidj8/+wGqrgLQtSEh+IiC89YC2iEWWzScg803Rng9+pqmK7op3
         dAmTaRLBC42DB9Od1NmG/2I5V+4pWN/Iai3LGj3P4rvP7nq+0BbnUDDj0DEzU67v1N2q
         p3cAdUe3zs5vmi3hNr+9gI0HbfvP4Y2Wb658H0yYelGpGLIUVtCC1YgYQQkKVR2VpIU8
         omwHPTf6yMe0OCyPentrIxvD+H/LlOudvqQ/Jj/EKa2VYYI2StJIAt6sEuRPytROtfVc
         arEwcOTzuQ61uOHESJKK8yTDs/bUWQ9Vqi0coKemAK2eMET2bfO+pE+/1D5a4UULmY8s
         Ad9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=ByT837waf1ajM2KstJssyMZb3EOfSeMlxWJfrU54tzQ=;
        b=nCRiD6JraxiUFIeq09nFGSCRQ4+G6AgDhIjHL52C1CNjRL/PnUW8lmXSp/K5bc8fyv
         ke+A/wjhDdJO40Lm3V1HoaQegHF+VlQuhY/r8UgKtypw5F4y28flIWHxAhqZkuvYH3GD
         Q7CxWX6azzkDHTs2S9FMDdmLb2I/XohFMgg/T3/72XZa40umMZ+Pmz+h44baoQFo4LJP
         0Dgv8ViDnl+Z7BojoW/hf932gNJ0P5vwgk1mwhVfsRV4XTxKmK3/U3oV/lhxdlp1/6G5
         hl8T88VHlq1lEvKscTDkfqMn8v655m0zpQa5OQP74sNryWqB8YVeztvcwB9P72LCxpdD
         Yrnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=d/lx=a6=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=d/lX=A6=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j10si305987qko.0.2020.07.19.04.01.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 19 Jul 2020 04:01:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=d/lx=a6=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208607] New: FAULT_INJECTION: fail LSM hooks
Date: Sun, 19 Jul 2020 11:01:30 +0000
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
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-208607-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=d/lx=a6=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=d/lX=A6=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=208607

            Bug ID: 208607
           Summary: FAULT_INJECTION: fail LSM hooks
           Product: Memory Management
           Version: 2.5
    Kernel Version: ALL
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: enhancement
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

See the following issue for context:
FAULT_INJECTION: fail copy_to/from_user
https://bugzilla.kernel.org/show_bug.cgi?id=208461

Similarly we could fail all LSM hooks. LSM can fail all of them, but testing
this systematically with an actual LSM is hard.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208607-199747%40https.bugzilla.kernel.org/.
