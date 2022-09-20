Return-Path: <kasan-dev+bncBAABBHFIVCMQMGQEYC5KYSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id AEFF65BEDB6
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 21:27:25 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id v4-20020a2ea444000000b00261e0d5bc25sf1232394ljn.19
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 12:27:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663702045; cv=pass;
        d=google.com; s=arc-20160816;
        b=fOou02lJDcgR1iQLHoX6sUNPrjCqIotBM+A/XgzjhiKQV2oik7prSi2x82IdJ/2qBt
         +tmL1nNNTaGUJqMKp8NSjQTpJsCKjHXwRP2J42kuO0W4mx7EOcGB1mEwmsycW6ZOhyRp
         dTW5JuCcjjwprPbvum5SXaiX818a/A9Oe8zok6M9HvESjHng9GSkbB7tYQAdthgwz+Xs
         qaL69QjQWPkIgMcVfwtKAnKssn7GxyBzge/lF5S0YgnAtGAigjUXWm5SgShxiIK0AF0Y
         ClzIEJfvIwALkGrFTnWgTUrpJTt1lo8bwbwdiLiLzh5NgUrjwFO0d5TY232GpRAJFTxA
         g0VA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=8G6n26QjyAv2rd18mzpGR3MZS6HeVRg/G6YHGWDdGc8=;
        b=WXKnjU2tXii6rtNaV0C98xDIoAr/1DQ0gATSUNSQE+y1XfO8d6J2sP6G08wh7JtHi8
         GG+L5q8HE9vpM4naLydmiZA5zJtDCZKuwCyyY3B+OVEjukwCENQiQYiBMZG0eAMJzitp
         RVCmL+nwqblM5Gqr1SijHE/cx7Z1pgjeoJzI7RztTjAXzhghfZbfwHBYA+4m5liXZdWM
         8SGxe1iXRtB9Hw+me9F9zRTEuQrt8lC0EnpDkwS3mqW/HNTmE10QcdEzc5cmD+fEyx/Z
         ZXboKiiUotbazQBrfsFWCF0JqNAXFD3e4PmRUrSZdbv4e+ZAfzfcYWNvIesTjtb0Wy3V
         6/zA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PXWRjyRM;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date;
        bh=8G6n26QjyAv2rd18mzpGR3MZS6HeVRg/G6YHGWDdGc8=;
        b=Pcfec/mJQBO4ZpReesZPoaKnNK0hRt6cdr03K2uFcS29+lxEENp7RCbb7V4K+lavcW
         ZzQ/NR4ryHZ95zfeuTAvQRC6p8db31fIGdENGy6lW7S0zilp1LYHysBxeOhZVpEknnJd
         F7naB2nwqoSKrdH+4vDI64ZevPLBfZSS6MuplfYgYSWI/vk8V5UPMd1q92wR4WgqecxM
         HGXhEEVUZoJEfAZnSIvQnz6oNSYKhcKEEry00u3J/wRG2Hx9Yzv6LxkcDHGCzomdFjiq
         9Fa/D5Nj/FmZIx/7ajcvKHyKvRu1whXhR2bnLxDqrsIQq8r7G+RT0PQzdAWYRh/8AjFY
         nleA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-gm-message-state
         :sender:from:to:cc:subject:date;
        bh=8G6n26QjyAv2rd18mzpGR3MZS6HeVRg/G6YHGWDdGc8=;
        b=YKQ30W7IgDqKoMcFPHcYei2kkUbE5iTu24jm2C+ePWpvumgrlKpFbq2d7ZlqUED66d
         ylzCUhN13dpYbVSmbxsAnQaWmE7yWJLGXLGMuhnAOYuq0/ciE2zH/IcVeyHH+4Z413cw
         myIKhYx506Ichzu+n8aRw+S01ulI3S+ZYUI4dWdTShXkq0F2aBbb+tFIX/MTmSyCC9xH
         N+EJdhpTftOhx4zULtdMBMyh2sitzUpZt56YkqoeDK1YHOLk3i/wBaDrGSl2usrPyfpc
         v2COpgMZ9/eLn3GVZA/p5LAsWg/ckPBwXV/rfjCJAGQH5TDHf3J2zREGsgOyNYpf5dMk
         ZXRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0FrQoqFHrPHtO7AmeMDkCw4CbBXxrHTETUqzDrCVPwaFrajRB5
	pBRalpBeAKlceR3uLe4MfXg=
X-Google-Smtp-Source: AMsMyM70iaL3Gwy4c03VulhyFTnH2evYK94iz9aauOMFlzCxuR1u32VwlbiU4MI69OhfFkg0PAFMKg==
X-Received: by 2002:a05:651c:1591:b0:268:f837:2821 with SMTP id h17-20020a05651c159100b00268f8372821mr7776738ljq.323.1663702044971;
        Tue, 20 Sep 2022 12:27:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58ed:0:b0:494:6c7d:cf65 with SMTP id v13-20020ac258ed000000b004946c7dcf65ls425933lfo.2.-pod-prod-gmail;
 Tue, 20 Sep 2022 12:27:24 -0700 (PDT)
X-Received: by 2002:ac2:4463:0:b0:499:5802:8ea9 with SMTP id y3-20020ac24463000000b0049958028ea9mr8238022lfl.344.1663702044106;
        Tue, 20 Sep 2022 12:27:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663702044; cv=none;
        d=google.com; s=arc-20160816;
        b=Fv0fJS9i/V0Oz26UAFhN/2d1/tIEJ/1bXd1mfXaqI0m5O+27wIAmEIvjpx9eqFSGhc
         nIibRjkMT7Pxu80Toyc6kyQZ76dFEajvlsHrkH1TCQj4/NAnIe9lWWoOLv3AYfkfap0c
         MMF2erSCtJeBAwPj3q4DHe1jI5xMmlWO04kTzeYgJw5OdqWVJchXXyidDPj5CqFX2awa
         ATletRsl488xsdmrk9BCE8xff45hRaUw+0CcHdInqfWsxZJkp1YhZjY6cod/gzP+qZl+
         0rIvXsfCr400h6nvU66o49z3ooxXJFce2t+JHtH1iJpbPQYEb7HFKvghO/mYBmySumWu
         jjAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=ACT+87zrJQ0zdzA7KdrMy92ocYYhMuYsDwTfIeVg2Gk=;
        b=cEpQ++IAavTzdDLhQLz/WQ+bTE8BfD9E36CtZGMIrWUjYTwGJfoSW2HX2tmW4zSHWs
         tXzhKMEKhz2iRIWBrdQdGKZjxzObYtbAoLL/kSQTpnX4ar2KHeKPlO1gQlKOWwh1/z7V
         infcGCVx2ojRt0/1K6C1AFIl6F0LTCGZtBP6FwbPnrn2m3JTy84LtH2Q1VIqb+8wosgj
         n5tLcKAbsYvu6NFV59ujMXvsnw7EgFIo67D1f/SG/kGzYWioh7JrHKBxJ9+/i+zXL/0k
         gS6UY6fS/kuRwaiJBkwhZY9JdHDF2tJWiJuxuafejMvXfA9fr2wRYf8a+35TZpB4gMut
         hP/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PXWRjyRM;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id h4-20020a05651c124400b0026c2cb5925esi23772ljh.5.2022.09.20.12.27.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Sep 2022 12:27:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id A18A7B82CA2
	for <kasan-dev@googlegroups.com>; Tue, 20 Sep 2022 19:27:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 550A9C433C1
	for <kasan-dev@googlegroups.com>; Tue, 20 Sep 2022 19:27:22 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 3BA2CC433E7; Tue, 20 Sep 2022 19:27:22 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216509] New: KASAN: add tests for kmalloc_track_caller
Date: Tue, 20 Sep 2022 19:27:21 +0000
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
Message-ID: <bug-216509-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PXWRjyRM;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=216509

            Bug ID: 216509
           Summary: KASAN: add tests for kmalloc_track_caller
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

As per [1], KASAN has been missing annotations for __kmalloc_track_caller and
__kmalloc_node_track_caller. Add KASAN tests that check that these functions
properly poison memory.

[1] https://lore.kernel.org/all/20220817101826.236819-6-42.hyeyoo@gmail.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216509-199747%40https.bugzilla.kernel.org/.
