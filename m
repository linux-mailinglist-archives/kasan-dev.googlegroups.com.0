Return-Path: <kasan-dev+bncBC24VNFHTMIBB7WPWHTAKGQEMBCZHAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 31056131E0
	for <lists+kasan-dev@lfdr.de>; Fri,  3 May 2019 18:10:41 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id z133sf1395018vsc.8
        for <lists+kasan-dev@lfdr.de>; Fri, 03 May 2019 09:10:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556899840; cv=pass;
        d=google.com; s=arc-20160816;
        b=BBAv3wBOSMMNP7nYKn01CINx0G+qxBGdFqOjsHQxmue8lCwFH9+7ZkfwMiZV8t4Z7R
         xsGQBwK1PKBJDBqsUUIM8Lh/Wzr0Rv0V6K23NwjsSqV8k/eNhKfwW71Gf1RUx3J38MRl
         NJUNwDaFniWEZDlfnF9mqEJi7jz3bOdetE/y1wdxey6yKnwAB+mTN1/PcIvHmL1v+2YB
         87ASA+hUCr3WqH35gFNWyBzfXeCuiceT1tkXvknlOznTqxosMdBwnU8ftylEcbQq8XtR
         L3l3ceVO1EYEWPAIq/KjdhCADYY9LKsomTY0/VsEhh6GO0KoRsf35B6+lSNU3fxXnUF9
         09+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=WTTUjpHtsiguds+WOBcKU65FuYic1uqqeblDkNeRbzQ=;
        b=xwaqOIK4icRdwtQJjKgQNcpXu/IngiipNefEnwP9DbdRNYp2WKs06dXoZmcXqPB6s4
         GB0R4lBZ67uwKp1BsUswAdSdyqZlnb9fOOSJSlUW1/YyElEF5FfT9eACsdUsi7X6fxKD
         +6zFvUCOmnoi9txGd0IZIlJYLznRq1dYCFMq+BBo0WkZdJoGcKHUQzdKw6H8Iu9mFjx3
         3IDkHgBZ9mxetMFmCfw1t0+xQ5NQOBFTYXITB9d5i6Hcoevs57eVYwRYgJusCDBJAj95
         0dd4+dvJJjyd2mLryMCJ4erUt4pfOYWvtiO6R3pY065yASwZlf9Rs/IH8aCkzAd9TgdY
         FuUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WTTUjpHtsiguds+WOBcKU65FuYic1uqqeblDkNeRbzQ=;
        b=MrsAEVHk2S3nixHsMHegROLkHvmxMlKM6h7z3aKfYwT+tk4vNp/XysB5CR+C/MHnpw
         1WDoWtp5XDJ1w3696JxWJ+GItLk91a0J49+3fFPEj/A/fcYKj7p4+xSnUXhEisbteOvo
         cI5c4gd8PTdMLGhCn41G0qhPQhp/rcPpefir+vZL/0vohbcftTPT6zgVe99uqPpjP2MH
         9fcfCqD15792LFSzEqwo/OqCvp0WIltcajuqUTQtmr/XXqplEJdLkruAG7H/n7bnXnLv
         vzCJnOBfRb3rShMjt/07mTpXgknYw4daVm/ZuXmeYWLy0qH8splJMBUYTfxplvoFmzpL
         OltQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WTTUjpHtsiguds+WOBcKU65FuYic1uqqeblDkNeRbzQ=;
        b=uZEnSAA7ohfXZE5RAy1DervjNk01YAAXcrjQ16LK4cJebrDJ9uH6QfXzULT+pdv+M1
         99z5A2CirABVOz62hPEuL39xbnTSVMA/LJjMmfVTr/tBvs2KJ0+TnGCO/nIFkU/MUbGy
         eHtOtpXYQABApQ/gOF5xiHsx4hGXyt2cpdRLVOPVq0pj0y1uUBF0JVjf5oP4LuT8lUEX
         irCYLNqAx7Ybw3ke3HNWykGZED7p24r/QdUwoXsnkwSAORkujASN9Phd92D5HsDhcbLR
         JYZW1giNuyBzKJrS/RQA8hhOqkvkQfd1ipDaVMZ+HlDriXLYbQC7kcOio/cpUdhd+L/R
         zEVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWkzUh/n6rTo3pCl9pJqb+bzjuZqgIakxD0WfC7iGlCjn0a1MF+
	F3gbJ6NiVRxpReH1OUb1zgY=
X-Google-Smtp-Source: APXvYqyk69du+wspWhmHK/DR9qrPVS+BLmea3G0djV6I/5FrgP8mrtIjy0+oY4UuLNrRqbF4nku3nw==
X-Received: by 2002:a67:de83:: with SMTP id r3mr5622545vsk.236.1556899839059;
        Fri, 03 May 2019 09:10:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:1588:: with SMTP id i8ls319845uae.15.gmail; Fri, 03 May
 2019 09:10:38 -0700 (PDT)
X-Received: by 2002:ab0:6994:: with SMTP id t20mr5761470uaq.105.1556899838743;
        Fri, 03 May 2019 09:10:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556899838; cv=none;
        d=google.com; s=arc-20160816;
        b=Eg1E3mLqkF4H8gAF2DgJd6bdR0Jqn9y0wgXMUyRbdzhFg4Dn82eEod92AY2snAdQwe
         +FYO02vJeILo6S+8XWfrgV23M7jA1hTVLOqDAjJRRQjoAr0tyV0ITAL2uEK7eqvxJ6Z2
         j1v92v92YGemFeYrbMLYH2T9yqHd00I3pUWmTDZJfhXHGTbA0HlfaXQ21GgynuqGCeci
         2mLYb/4Myf61ueG4vGimmiuHS0T9wPgr2x4kHdZXtF4whBrZlXs59/ZIj7C9EQpg4+T3
         HYvt8N5ZSpgCL8VePo+an1zigLi53k3BLxedtx8IDIVcxLvoY88hCkQguslvy+US+ibp
         Zz0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=eVeCCe5gNCjYSW5c7UtDzHHoWTxa7rS7OdHMCWSaxoE=;
        b=w/dzg0wh6tkC8MrEGeT6mYatWkuzxMklxg3lhwtEDTe8fCNf2EDnpZDhmWDoabkv8g
         KgUb108Tm8rzte/UVy6ijjgNI4toiLTymkhjDlB52svfAocEqrEpdY5mVfZHNYDFbjKX
         TSDLtjq9ZrBJddldn+M8YzMorYV8pgqdpNdyrJbK/f4PW1L/bCu9BLMyYiNo3KvKFFio
         YOH5sASYx/aWns6W9HKo2T7xfd5KI0n0LrJbW2L4mC+QspF9+88g7WKG6oN4ci1Ex9z1
         OHNZoY6LcagonsQfXUGQ3zhYCs1B27HrvQWn4B+bgzec7P0GIxTydhLcXsbPAgHHe2G9
         HCkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id r138si147298vke.1.2019.05.03.09.10.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 May 2019 09:10:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 674C42870E
	for <kasan-dev@googlegroups.com>; Fri,  3 May 2019 16:10:37 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 65EF8285F7; Fri,  3 May 2019 16:10:37 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203505] New: KASAN (tags): guaranteed detection of linear
 buffer overflow
Date: Fri, 03 May 2019 16:10:36 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-203505-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Virus-Scanned: ClamAV using ClamSMTP
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=203505

            Bug ID: 203505
           Summary: KASAN (tags): guaranteed detection of linear buffer
                    overflow
           Product: Memory Management
           Version: 2.5
    Kernel Version: upstream
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

It should be possible to guarantee 100% detection of linear buffer overflows by
giving adjacent objects distinct tags.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203505-199747%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
