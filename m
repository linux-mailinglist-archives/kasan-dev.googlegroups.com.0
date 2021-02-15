Return-Path: <kasan-dev+bncBC24VNFHTMIBBWVFVOAQMGQE7WPZE4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A92531C2C1
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 21:00:28 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id v16sf3039998oos.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 12:00:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613419227; cv=pass;
        d=google.com; s=arc-20160816;
        b=la3mJe9mE8q7b8wVv9uG40V7DMxBT0UodnbOtQNiWPm1JLoz2tu69kELSCVRju5rDq
         HY43VZ6QvIMGxFVf8p1s3HyI2zlFffts4ILFcBPv2xvJhBO+vkl9YWG86+jJPtdWg9cd
         GYJR9cYuENDdJjTsl3GSj92e6CQsyoMf6Lftw+Gf7E4JQ+D1RKrutjpAxMzHidoOV6aR
         J4oU7WnGrk688Vz+qoAxETvblwhC+9YqoEdjrl68WMOI9tthuI4W4WkswOtl1jQYn7ic
         y+dQNrmnpWHO//QSwgfqrHFIgGUNr9hRu6/4EN0UrV0vudBe2voqxSuTZvHkgsyoeKF/
         CzGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=IDOjAJgAzYmTkT27octvWbhBrxZ4hh/ZcTCld7bqRRg=;
        b=yYiFZHqdjlYg7EQRVRn1FGjHpf+BnKiA9ATjwJA9yFgmGqU63oDTMjismghoaBm2CP
         qrdz1/3JIP5bxInAL4aYbXROUeb8OaFPKo1hN7VJ35iB0mKvSWH6iTKi105f70s0dTgA
         TprDH9tTAFlv2J7g7T2B7uYgS7tPG0jBt/Q9WqvR+DFDjBsnGtbKlrNQ10vbM0cBcDlL
         vYnEtwqTDyUpz36lu9TudUL2lq1B4med6uLP5SCSQvsVqlFv5WB2ZlRSFHDuXVSuA6Zr
         Zre+0Z1jat7L4Rvu3JE4nXnzAxyEvY+Dc+aoyAAxG3jdVJKL6rWIll8r91d7N1HVVyAt
         Q1og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="hC/H1tVx";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IDOjAJgAzYmTkT27octvWbhBrxZ4hh/ZcTCld7bqRRg=;
        b=Ie49am7/wYiNHmH0+kYtXRRgLMEZHR+NfEpb6B15vuUuVzDsFzj8bxabuyQOFF5wTh
         SwZbyA3c20DwvG5qNdXkDORWhPVBJUbPPkFuRpU0jsJihSi3NnHdNrTxelworuCa0NVf
         PiDdXD9E3EyAcuPJlvRDBLqUgJ5AhBro8sB+cQ9zSMidDj5oeEVeTbzfChf7Djm5+bVB
         xrD+HC2wEHUh4tLncvWqs8zMyeSWBhz1NIpkEfHChLadaVqv4UfFuiW3itwT+dpVpw7S
         LhqAQlUMvZHMdALOOs/Z4SMnSoaQsgPq5Xnt6N4DYHjYCSVmmbcdqoIWZRkQV7rLS3E2
         wGtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IDOjAJgAzYmTkT27octvWbhBrxZ4hh/ZcTCld7bqRRg=;
        b=WAWbh6H7xcaraAjVqcYJQJev9x4IQiZ136irOFpr+IkrgBBxg7asMZ6mBsYb8rtM/+
         3E85MuByYgeKKKIwV5EFfAQXVRg7cd7VtZhDzzQHcVRWuk8LUtXz8lQw4aBqgO7qBGga
         mgS9ZOG9tJqDEhaJcQGq7arbdk0WCrMjfU753GeYkaBR9we1iY0hpvG4Msxs7ALBL+UZ
         gJgRsy/6GWgHoygMGhaerPM8jXm0med4LxDnBc8eVFdApM5iZivhnW69sqg26eiMZYDC
         zLLz2aCs35N6d0rGD6mmbCsPMsxhjRinQDIvTEZKvrHjY2UWzm50hIlYcQ22ZKAPOPko
         CC2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532wq46xMOLCHoryMdxcWsmVyiQFP1K1tBdkv/WKuROnnCx2+FYi
	w7BlTMwSMlVhCFy5fTi0Yv4=
X-Google-Smtp-Source: ABdhPJymbMM5m1RVIptFpv/plWq2d6lzw2scMUeHInJ4dD+5AHFq9xMfZD3XHfLV7MofQjp0Fec2cw==
X-Received: by 2002:a05:6830:1d63:: with SMTP id l3mr12339094oti.314.1613419227008;
        Mon, 15 Feb 2021 12:00:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1156:: with SMTP id u22ls4159919oiu.6.gmail; Mon,
 15 Feb 2021 12:00:26 -0800 (PST)
X-Received: by 2002:aca:3742:: with SMTP id e63mr367657oia.158.1613419226718;
        Mon, 15 Feb 2021 12:00:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613419226; cv=none;
        d=google.com; s=arc-20160816;
        b=kd62csVca5SphEKf8yumqNFdZsuizcGLWc+NJktmCEuaiYfaUM/Xzx2NOvvzWydoMA
         CXu+QazPZXHFf79q4FtsUpPzxzVVg5GljNp7CmOjc15JHHankv77Ynbd0hAMnlLOm9ci
         x+BSIYUY0iIGQywNns2FMPjeH/Xhi8gMnHRRulEEgWBZq+IHwhZDvj1d7L7KMdz89O8l
         qNmWHLRzx+EMRQzsP7I3kvSDdu6zWJxUr0mGj/GB+NtoaLjzXIurx7WE+yU2kHIrhp99
         4biXKKAFXiEckk3RFJWOJleJ9iMKJRulr6oayQtKxQreT/UCeqKHXAPGhsDb/6LutPCl
         hyKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=zPMAsf1RGoF9pSh2yT49LTBLlbIP/nEGhvZQuFE2GqY=;
        b=oYllOx0rLhA258ZwpNI1LC0o+qNh3AiM0LytiuuPIVnZwD3zx20UumevsYubmlDkBx
         BfGPMV1wnLy/imErLFSk+cb19vq+LETIdiDVfjMD0h7o1LQLLnizpmMgvcfB8lU8muUX
         Sh/P/UL6CoOhSc/zx2w/Ynp+Gfy+fYSdb/yRawf398DNw+yAs2vjVFlPHmljP3Jj9Qdr
         Ify2PIH0bmMsoljNEUWgCm+7od85RClEL/X6t5psCIK3GdplhLPGHPS/5wg4UCc/dSRM
         F70S+KxxZYG4GpEZ1dmW4uT7u5mQGl6fL1HfqBVTles3LOJ7pknITQIiRlTUr0JfBPe/
         GZEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="hC/H1tVx";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y192si1050852ooa.1.2021.02.15.12.00.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Feb 2021 12:00:26 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id DE10B64E1E
	for <kasan-dev@googlegroups.com>; Mon, 15 Feb 2021 20:00:25 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id B7A57653BA; Mon, 15 Feb 2021 20:00:25 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211787] New: KASAN (hw-tags): don't leak kernel pointers
Date: Mon, 15 Feb 2021 20:00:25 +0000
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
Message-ID: <bug-211787-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="hC/H1tVx";       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211787

            Bug ID: 211787
           Summary: KASAN (hw-tags): don't leak kernel pointers
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

As HW_TAGS KASAN can be used a memory corruption mitigation for production, it
shouldn't leak kernel pointers in its reports.

At the same time, as it can be used as a debugging tool, it should show all
pointers as is in the debug mode.

The current plan is to do what KFENCE does [1], and only show unhashed pointers
when no_hash_pointers command line parameter is provided.

Generic/SW_TAGS KASAN modes should always show unhashed pointers as is.

[1] https://github.com/google/kasan/pull/178

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211787-199747%40https.bugzilla.kernel.org/.
