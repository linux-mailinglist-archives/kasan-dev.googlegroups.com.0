Return-Path: <kasan-dev+bncBC24VNFHTMIBBLWPWHTAKGQEEQDHBQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id BD6BF131DE
	for <lists+kasan-dev@lfdr.de>; Fri,  3 May 2019 18:09:19 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id f4sf832887qtm.18
        for <lists+kasan-dev@lfdr.de>; Fri, 03 May 2019 09:09:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556899759; cv=pass;
        d=google.com; s=arc-20160816;
        b=NJvUgBP/w1B2OXDq6JJPt7hqx8BbwDCa2yIbjnPmr7OPEUS/tPvBvfcYHLQ3Mg9Q3n
         9+n9kV+mAH+7mpQLiv3VC2hTZ2e4SEqvOef8u+x/AW/LrB+PZ6/5Vyc6hwaLCk97r0Vs
         Pi9HgLnbeG3P4RPRTPkQ+BXqOAaivKeMBHNGqxqsfOe65yTF8KF66+WvbSbMGPPD6sVd
         0bxS/pwF6FMK/EGCzaOV3sl6LXzywWDLwAnToBKoWDNe+XQrBct1UgemVRpJ1VI3xt5O
         mTC6ItkCxzbgyVcKSXALOnwJeAaEwIKDWuF7scKES1e2I5KtWDhUPyFGhSBpkfazH9QZ
         yI6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=ZuUv0j8e41Ci502lZxnkazEM20L/XBB2iAI8zhQm/Ek=;
        b=ggxrPSJkIGryswp8Tl7Ifxo+e/KHoLwuFceMA3oKsx7XzL1CL6COrpW/V2ua1waIe+
         ywn/VEc2JaYW+rmSgY8rP3xtFUXv1gqQod+NSPbfcLr0ek1TGfw9AFMztVvpJQrccV+X
         Fhix9QesaMgBaZ9Lgr3DsktVstuvSKNPw/sG7zXGUjHcgq6jvt7TIS1bUMWok7kG0Sef
         HrZszh+E4gxYLFCiB01Ebdh4DOoJuE9GWC7//q8VVCmRra81BRM4Rgv9NNKt7fjv6WbK
         gySCMljQ9BSpdEaQe7cpMCp2nL4/z/iW9GevQGxPTnYai9Ifh7fnoYo7xQnGs3fc5Rcx
         i8iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZuUv0j8e41Ci502lZxnkazEM20L/XBB2iAI8zhQm/Ek=;
        b=qrk4ux+hNZ60ukavDnCpok2/fzgPuPht9ciSQbSbz2uUy/diDxbhS2PMW0eah9fJ62
         4HlSIYPoWIxRj7mUySKpSSrV4uavDtRafmOnE0CboYM8+Y5Ys0GxvpzhzywkqIMRk9Xe
         AJCrjzxS4S8F6Q93yQsoxO6aPfCdQqpRT4TbFjXcb6+H56x2AyhwufxDyjzW613vILPt
         lfufpfIhRGv0qkHf7WyjzL22XgQUt8Z+73ygAWH6Z9bRdTXHAex+U2bD88Kll6W0j6m1
         3nE8VPZPsCmqRgbLjwUEYV/vrXQU29gwQ1Hk1rY/QudqT3KjcJM6qPa6ZhI5l9sprdd8
         ksxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZuUv0j8e41Ci502lZxnkazEM20L/XBB2iAI8zhQm/Ek=;
        b=kGenlNL7rATB1ET7ov2IlusTkFMDnXt9FoQaj6jUT/BTN5rFW7hyIvgiwP15q1Clue
         TRnOtrhN7hv1r20H9Oui1DEeGRsE8QBpUhiValrS71Wy0oqqHvw79ritoCL0F65RIriG
         +pd7pPNB34Kj/e5Tcw0jmK2C3xDnd3vwPxSz/LJ7oPVahjJ0cX85eE83ftsDTZmYvb1k
         KApOLBTuR7l53255Onx2ELiGZC2MdIaOBZj8tVRLUM/E/eHhtj/z5o3MEvqxZnerNGSW
         EiiPWJdI1zdaXQYt00numWALUtryUmACmTZwo5s5bt+PP0KXY8OsX7o0Qh2/nuDpvNjK
         bIrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXHEj4euetxMTA+eCQkrwJKS7NmGfIJZdDVZsmKa/z3HGb7kenD
	Mn09iR48dLCLNa5CWJm4Sh0=
X-Google-Smtp-Source: APXvYqzcuFvYbOjJa2iBnqSBP6LMRzl0dstO82z9Ce9pTpZnaZXYBjaPi5m6pV6BuOrYTziyAdvE4w==
X-Received: by 2002:a37:4988:: with SMTP id w130mr8288715qka.262.1556899758788;
        Fri, 03 May 2019 09:09:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:2ae9:: with SMTP id c38ls745071qta.11.gmail; Fri, 03 May
 2019 09:09:18 -0700 (PDT)
X-Received: by 2002:aed:25b7:: with SMTP id x52mr9342701qtc.5.1556899758526;
        Fri, 03 May 2019 09:09:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556899758; cv=none;
        d=google.com; s=arc-20160816;
        b=ZQW1fZ6OHnruQkPmjc6duinmF7YWa0Ck4Fcje3kdeH0M6xDBO6OtMN6w4ZGc20Y0z2
         9HCGRvTGOkDzmJbrr4kvw7KoFT0OikOAzWD+oFqKIFGXhqUJZArgaBAOa+q9yj+R1dMV
         twGAu+bxnO5DbSRcm9i3MFVivrFiC94lPJqCTuLzPPmEjhnQq5CYLmpPlXxv2Ua/uZxu
         DFlAgmxY99n/tMSDSpoOunb9ZqqwT/pebFh6B7RpZeBwC5V9klDEPUtTfmnlidjwoDo9
         f5PLTzChE9Q+ydACXNfDWEslj2vJCgvfDvPnWdnUZHrORYoCNLkEek4kMnfwrnPGQ960
         iFOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=bP2CBOxo0JZZtOcxFohHO6sYEpWAg+Ca2/N4XfWMvDo=;
        b=HDEuG6GVutujwHE6pGlZorpmGId75PgQLnCL4t49uCw1i56eJRTsHSwktVCfOSpWrd
         EGUVOi5Oo34NrROoJ5jnYul6zEPlBolHnPMODDmheeMIcApnJmgiy5xKAySnKyYOQkQ8
         SKzqyDPNwVK33GrpHNbeBtXCUgM56HFDM045duVxzGPQQBC4bb80pZ1He8AgAwPRKe1Y
         H8o4DpjHfv5Cx5NBwxqKsUnVdgbRVznqAbWxvbruzyZkLGERrCxmIJAtLBCuzifD6ULK
         vsBfr4IZcWxwMArkc8eE3nqhIfcVOQv1SeB7NLxVEi+9OIJxVwN932QRvp60KwGzFd5R
         nxMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id w83si144691qka.0.2019.05.03.09.09.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 May 2019 09:09:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 6E7512857F
	for <kasan-dev@googlegroups.com>; Fri,  3 May 2019 16:09:17 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 62B55285AA; Fri,  3 May 2019 16:09:17 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203503] New: KASAN (tags): add 16-byte aligned tests
Date: Fri, 03 May 2019 16:09:16 +0000
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
Message-ID: <bug-203503-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=203503

            Bug ID: 203503
           Summary: KASAN (tags): add 16-byte aligned tests
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

Some of KASAN tests do bad memory accesses, which fall into the same 16-byte
memory granule as a part of the allocated memory object and therefore are not
detected by tag-based KASAN. For each of the tests like this we need another
one that accounts for this, so the bug would be reported by tag-based KASAN.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203503-199747%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
