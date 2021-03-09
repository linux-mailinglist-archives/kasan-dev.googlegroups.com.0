Return-Path: <kasan-dev+bncBC24VNFHTMIBBBXYTWBAMGQEEGWVORQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id A5BF1332774
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 14:45:43 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e16sf10150919ile.19
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 05:45:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615297542; cv=pass;
        d=google.com; s=arc-20160816;
        b=ul44XzfLvT1XJK+cuSmvZ+lQej4C3SPp0k7tQ0kyVIy9T3IYFuOa2K+3b7+eCmV1Gy
         7aKoO0j4ZnbIliTPJqBo2/3Q/dQkMAAWJ9mmy1+D9TMfIxWPyJAjYYZCNo0b6vo2JyHM
         CopkjkdYyR7V0qZVaUMqwWbSNN5xKEAIyRTuyBEXb/YMWKY4N2JHvJvLFf5iwnryHxS2
         iQ/SmAsCOzaaWXlq0R7m9BKQkiLR9SF+wuFzUro0om0s9puCZ5JY2D0bnGTFHwuThdY8
         ubjhwwBvmJ5hgh14eUXjjv4c98FHbX7JbZoK4FqHMrvIlvA6CymZXj/3y0RCxRcU4Ph4
         Bm6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=wCtmzNwxnQbHnsgPbVPsV3G6JHKtJllCr21KGDkEEJk=;
        b=v7TKkC0wj4kdP/9+oY3EWkj9KFk5i3MOP0vdETENkvvycOR1c0dDcq1OCo08hrj1/E
         G05qA7ujaAHjNjCkGKOjIqWEZSDpr5mbbNSuNjl28Lj/DgjK45ZSd9eHM30XDBxPi1tx
         rlgDmVxEq37IJ7UEo6m2fteqV5d2Wbnog3ONIIP8cwAiL8i9mO3cqbfTuv0WrXt3FSXy
         DTG4F/UoUdENaCXV7B2kdd6Cog/E72hhOZkDJNTxFHE94hjb/ECHdWip2r6XyFKzaKY/
         hkk9jZGrfLBBXkn+kI3j6lg4XxYlNl1tiyQO9MZ5hZuzPGaH15aZ6pDZ2oiT41Rm+CAn
         /d2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VFpyhdXd;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wCtmzNwxnQbHnsgPbVPsV3G6JHKtJllCr21KGDkEEJk=;
        b=Tog8KhCisAMsv7zcpt99mZ8cFK2O3O/zHIqZDFPD8YUiJURxyuE1uVbrtTCqeYmXZ4
         M7hPLeAFMhFKredlYj+4notl8ciWiixECu2KiAdu4r+n0Uf/+3vXzNi5BpPjSuTblaXI
         ZJHmHSzvcFic0zFoZDP2e4M8FttPM8VBiQ+k+VA7l0v2gY+TR8kve1EwmdNnaYjqsn91
         dshqTO5tBfKq/JTAksa7skR/fqUCp8/jBcCXIMo8YGVZ8mGK73v9q5KWiwS3/BeXjyOK
         6oAM56e7Y2F2MUIxySaUUdncENfUGEBJ2UIHs7bqDXfhk/hClRUiF4IHWUZij0q9Qd9d
         ei4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wCtmzNwxnQbHnsgPbVPsV3G6JHKtJllCr21KGDkEEJk=;
        b=c1OGjF/1D3ufmZRXpuAyq1hHBbrIxCTEglP4ewmCZUj06mstMOO4nwd4XYR77i4RfK
         2+v3aepNJv0BwlB/l9DzVZ7YrmEBNaAtnMhSUJwQNGG206gD8e1yVBEEzYlbOx+hO/Q5
         wtVcM29i4RwO9xRFrUEV0IqRGMbqVNpRRPvgw8ikPF34BHlP5PP7BTq085nW4VNWLKqU
         fmN/436zMSlXd4L1b2Fi+UJqbqpkdm8BhGzlKIqNksbAwqbYOPgCs3fZQZtNC9fsqfkT
         Iu7Dt7zG3RXRpJvmKzeJfeB3cTAOuBjD+ZR/HPHEgiufDAZU9xrIdvlxgwxe7wKoan8J
         Sirg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531j6ns6x1/220vad5bNIwj4efWnhYwkVtiQ23Y1/ufOT8e+CQlQ
	ii9L+Tl67wWIpnFmBv3eL0g=
X-Google-Smtp-Source: ABdhPJxvJi/KPcTHDoBGzu14ZBzhMKZkaxc8PCUoHHx1azUM5XFbNNr2OyMVZuFvhA4nIBWCXneczA==
X-Received: by 2002:a05:6e02:1a0d:: with SMTP id s13mr3969611ild.43.1615297542732;
        Tue, 09 Mar 2021 05:45:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:980a:: with SMTP id a10ls1059244iol.4.gmail; Tue, 09 Mar
 2021 05:45:42 -0800 (PST)
X-Received: by 2002:a5e:dd0c:: with SMTP id t12mr22371862iop.50.1615297542432;
        Tue, 09 Mar 2021 05:45:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615297542; cv=none;
        d=google.com; s=arc-20160816;
        b=IBeGWVQY4qBVRI5SwqKxgMSEwsa+ZPdHwJGccFtllWKjqxkXhw7mbO4GyEYlTRfRYy
         G5HTXHObtsrkIuw1cE6o8NWP/cFhR+qGiJlzUxDLbKNI12zlK5mca0xJuVrjuA+CoLgP
         3ILwEtJvZooh0GMgGHR7Npt+7PqFReKPGtkxIDXR2aA+fsd8FyszCngASPmq3STy1bnP
         bZ6nRT5HTyXPjIi6nYfiVrlQQ9ZEaezNq3SCAJzZfZ6F2vK+JMRdOTMdVBx7EMGGij5M
         71nAWWMx3A2dP4oYQS/x2VoJHsz7svRXFXRna8Lw7x2YpwEjw7ocBIJXwz7W9yMxUQj2
         Pq4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=6P+yoek0AoeXl+TAW0DWNSy4qvmuXE+EEOYUpIagnNQ=;
        b=LHMXzYa8E6Bn7lzsfBIPfwlgCAyUYufJ6DA+wH/jteoWVr5Xg6QIb0EOccmwgqvSjd
         ArHqKHHr1njK872jybbcEdMe0H6/662ZoVQXGNB/RZ+dChT7Se/jZAP7NFQmaRzgmr3h
         +lZRu3GJNM50Zvl4FY1frd+YrzbHqv/rbfMcGmLW0+drHAwYInPOk4WFsNBFtThRj9gf
         p1cIYcipF35gu3+kK+GbY6hPoPheEkf3TGCpo7Z9PIwFNNYOzzhW/lVIXZToncU8cpm0
         4rfIdI4kQKGAMYsCRcIlQYyJXJY3mfQXWHKIdxDXxe0XT88gZTnt9ORJditLDboXTI1e
         Q53w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VFpyhdXd;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c2si989007ilj.4.2021.03.09.05.45.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 05:45:42 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id B19F364F51
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 13:45:41 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id AB59365368; Tue,  9 Mar 2021 13:45:41 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212171] New: KASAN (hw-tags): use kstrtobool for bool
 commandline arguments
Date: Tue, 09 Mar 2021 13:45:41 +0000
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
Message-ID: <bug-212171-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VFpyhdXd;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212171

            Bug ID: 212171
           Summary: KASAN (hw-tags): use kstrtobool for bool commandline
                    arguments
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

Currently, kasan and kasan.stacktrace commandline arguments only accept on and
off values. Using kstrtobool seems to be a more universal and widely used
approach.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212171-199747%40https.bugzilla.kernel.org/.
