Return-Path: <kasan-dev+bncBC24VNFHTMIBBSPBT2BAMGQEUFDVAFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id C273F332D45
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 18:30:50 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id k26sf9567487otn.5
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 09:30:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615311049; cv=pass;
        d=google.com; s=arc-20160816;
        b=D/kiMCkK8GXqvM91kgQ4W5jaM82Fx9TfxTSYseq9lHK70VGHEKHRIdQ9sfgbSvIcyL
         KNA+DNaNkuEiQ9xkLnphxcagDQzZpW7ys5GO8BzMQYV6U+YGwE6H8a8adkGwfeyW4Kbf
         0pI5ykFIjRPFF199+3Pnrcgp4KcLuaaa1qpMjOZL6pxiOBOwfva398NQ8JzKEm4k8ziw
         GXRz8FHTNS7jLqaVY8cH/MtVe0wiQl5PGqX0BDTGg5rlB/sa/lF5CB+vebPnB5zPEduF
         qqgKWCdwn1dcoPreuMRNgy+9G0dfi/3ON5eToEeiZN4rJfZZ6RgAk9iGXW63ty2cROTm
         lnEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=lS0MZKmajKNw99Wn9dPplVfxe8N8IJMvho79ERtA8t8=;
        b=eH9rRbnW5g8FJnh1a7q3YpqTL2ysaOMO629HU4GBgpYSh8CdH2UM+RGgNkKGANuReZ
         Gz5RZET3D5qJldzMtmuWGXQio03KqKFpYw5l0foSKeICBBnjpRiDNUTAqIuQ0HDD8LRK
         KmbcQrmECh0vtdL3kGFiUm9g5f81ovv3eazrAs+fuXpolERb03e5slxBzlCDeP3ARVrF
         zxLE+1wMzlMV/R924hGDOHSbHob22infUGEOWFb7fOW3oacGNV4FgjOeC+j1uQhZ5MCW
         FGuEGc5D8HS4mVZmTd++0DKhMKM0Yu61/SSg/NHgz3QDd5J7avjAzFYgvhuDIW1BN9/y
         b1hQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nvEoO0kC;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lS0MZKmajKNw99Wn9dPplVfxe8N8IJMvho79ERtA8t8=;
        b=eYuBpAQMmvCmTMituiL9SmGnARQAMgCR+sPDyTHWp35zySFxkpEVbWlttJbqmC/6hd
         Bp3/WVUY5p6HQhCVyf20GAiu3D4+9DYmsw9+fxOtVFQuSIMIBmQxcKLjo7k0/02ACRzP
         e7enuCu+ZaL+5JGMC5Ozxcwn0PlKLEKYLSGl1xNFwqb95SStJGGg6RnBmLWAD8atkq8y
         4mU9YI3EYUKytF2v2TbuYfoJ4osUoGfR4hwK2oYToN8le12vs0N9U/CZp8ktltBKgluw
         ZvMKV6xXHg6TKW3pMTtMcGjH6Ig6/MTM/0UCWGV5/szbGuktn8XBthkCwgFlHr/SD8VA
         yBtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lS0MZKmajKNw99Wn9dPplVfxe8N8IJMvho79ERtA8t8=;
        b=QfELrUhaarbApGTMAT5pIa/L+T/5rmyAQYLzQWfYauyH38zYAmgtafzAe0r30JlGtp
         DKUM4JGIQgMAOEBLIAgTdwiYxD+j/lUNWiJP4AAFH/1S7//OzW+C1UVBGoMh+Sp8rTqV
         ujZpjDPAZG9Odg4re9KZg1pHiF8eOhwOB+jTyaymtXfZFb9O9I6FepoTL1Wycg7Ai/LA
         Z1ZqK46pieRaGsPp8y2LRU1vTS9w8ay1REOj++a0hfR04K4hZUDBzO+jSbdHLTYHImqw
         SdYFLhBqwjCjbBgyMdw/uQI1MU83xrTRmPwMpxPXxFTBrE/iTgFBYs9hUMT3YFfgaOS3
         5/Zg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532HazU4LHGIpy/ndcjhRiYyjTUonxdp5HYQnCoIcB2eU8ItNrMs
	jZdhcQriQY75RP95Jln0ock=
X-Google-Smtp-Source: ABdhPJwvO0aiFH5zOs/ZqvTnZwCes3WVTB5sk/LMsG9p/57+Lf3UCGTeLOJVkdbe0fkZ2Rkb4DJV3Q==
X-Received: by 2002:aca:1a0d:: with SMTP id a13mr3633166oia.31.1615311049809;
        Tue, 09 Mar 2021 09:30:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b303:: with SMTP id c3ls4372884oif.11.gmail; Tue, 09 Mar
 2021 09:30:49 -0800 (PST)
X-Received: by 2002:a05:6808:b21:: with SMTP id t1mr3740387oij.35.1615311049536;
        Tue, 09 Mar 2021 09:30:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615311049; cv=none;
        d=google.com; s=arc-20160816;
        b=ZEi2TmGQpYmdTtPNqOIlejCAB1APpm30VHKWqY/rE27mCZ9w3xIC/L9XsB3AKTuqcR
         +3cEvbKbV3cajXxvLpfqfdc9QKm/dQe27WiLkEiRU2iYMv5hXZPbnnVBxsdv7hBrEK8J
         E/YX6s1AlunVq6lyD9hEXfnECt8vZFqF4MxTuccpkDAGC2IwdrzJR64HQRMxqedfcCKQ
         BxtOwMHtwkt0tCFod3tGagkts8M3E6i33uSSXMJKFIw5dZJdWAOdFNWmvZ4VTvnOLXsK
         MBBDQJKeINhySatmu6GbEnMjtGGor5UBhhszzuYJen6o7g2EJ3bFnuetCYi9cpe5au0g
         ZOYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=VIxuyDOFVt1C6icF1NPGbWMqzvyCE9J56dZow5x/TGY=;
        b=Nr8xvLrAjGg+4XRL7iOpqOyWdeOq7htQEWLB3TSAxn7AJ3LMS7UhcFWVUZ2wYUczJr
         FgWtUs+IHCeuO4/AeRYEc5mVW+XokPWKQcUtMg81yiGas+kemrL3iTFcSBto5xJjEFjo
         +zisXtY6QQSMxtcTaFAB2vSq1QY7/Rp0A6Ftmv88xvixAPLR5pgyCDbcc06+CPh+cJDv
         kmq3tCma2hvNCeOefBCQUxBy20TU5IIV6NPyDqngi5EpXXbtgngpUK/aGowBvb8jzWS9
         oD8/U2CVI+AHE8Qa+j5EZn+mZ1sc3Ni4I9g6Zdnp43/+dHbT4aa9WsnsS24vKQs67Ycs
         xr5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nvEoO0kC;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v4si1409627oiv.4.2021.03.09.09.30.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 09:30:49 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id A3A4265244
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 17:30:48 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 926E0652DC; Tue,  9 Mar 2021 17:30:48 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212211] New: KASAN: check report_enabled() for invalid-free
Date: Tue, 09 Mar 2021 17:30:48 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
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
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-212211-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nvEoO0kC;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212211

            Bug ID: 212211
           Summary: KASAN: check report_enabled() for invalid-free
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
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Currently, KASAN only checks report_enabled() for kasan_report() in
mm/kasan/report.c, but not for kasan_report_invalid_free(). While suppressing
invalid-free reports when current->kasan_depth is > 0 doesn't sound like a good
idea (that suppression is for ignoring metadata accesses), having proper
multi_shot checks does.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212211-199747%40https.bugzilla.kernel.org/.
