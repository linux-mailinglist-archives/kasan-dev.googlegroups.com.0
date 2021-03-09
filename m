Return-Path: <kasan-dev+bncBC24VNFHTMIBBINVT2BAMGQEFUJU6TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 36F34332B23
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 16:56:18 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id o8sf10384320qkl.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 07:56:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615305377; cv=pass;
        d=google.com; s=arc-20160816;
        b=jWYpJKAqHAyuuIlYzW+RUpyW/gNaeXSl8fsJu3bySbW4VF9rkQXu5swNPdTjFgiZTV
         sMJ5arpxvyqdWws/CkP33kEQ/qh35o9w/tXDA4kA8qcY2LFiWnDwanfLJkTiIwhDgSQT
         T+B+6kqt5M5kvuhAcbdQggfJ4FgxHKMSxgBXw4TSxmfu6ohqz9JmYrQhnNHynZbMvDdP
         658PLQ7UHNsj3yOD8181GBbtK19ts85BjJTH358kFcRpy992viUQAE+sa7hYqdp5JV8f
         HB3LLWYxGiPdgSxfx39MTnXFbdeZh/gMZRkjx8VJ+zxn4xWIIJDLrvp0F1HM3c53UA6P
         Od4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=l7/9MQqBMDc0rmVPr5CIuBVd3d8dXL59xfy/WGiEnXc=;
        b=rOjmufWxCXSqfpJpAT9+PjNi1Co074OuDEv6K6wqIulnk6f/UBLiPezbIAWU/bdc3U
         hkGtl+IPDD+4lpTohClIZyTMSl/MACqD7gUot43t9zp5FH1BSveMosqlIQZxzj5FJFrB
         JtrtwB14ohQdd7ngeRSM7Ik13wS8EWWzbOJhV8jCaIW+eVmGxDgRD2edbL1GiqbPzqWv
         YFlQYv5nLd6UkKZFbeRZB04EUrdYkd/tj2e+yEgAoS7FURsA55QSBO5jWR+OH0f40m/c
         l3I16CUkjLa+AzM+gqqgffu6zwEURlsDbravdvs1WUti2yo5SeS99zppJ0GsH1qTjSKN
         /3Aw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oIku0BQd;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l7/9MQqBMDc0rmVPr5CIuBVd3d8dXL59xfy/WGiEnXc=;
        b=EFzKtJpGL+FnaXErGy3vyFcLSujMBLEcJ0t4V2VEyaRSnU/BiUpK7Y6DUQMI8i/ckH
         D0g902DaRCNwwBTIT12uPVGRAtiMwIV7Xsx1zWWv0N3quHNu7TDsWMJwd6lPpzbQMt1b
         pdEWWDsDlbB4OIgQ3mVhxI5R/BMX/f9xDyU+UbPj8T/U4zgvMPMxV3QT/3xckPmCbwD4
         iZo0GMr4kUWXDCXIkBXxWRcrk02Yd9dm9+i1WzTz5/eJKg0M4k0vMLVABU1ZHQwt1aeH
         IZad3EJkIxxpTIOPcxVAHU7JdNCvKFTqNKjnKnWQi751YFkGAKW5dAttPIUduuPv/fYG
         Ca+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l7/9MQqBMDc0rmVPr5CIuBVd3d8dXL59xfy/WGiEnXc=;
        b=aAy/owUHRgMsXyqLnZf0Ie/+mrr7ELjVuQ8ago7yh2J6dgkEVySkyhTer69Q0wi0kM
         u/8JkbsCXZik81TECqLTokT0RxqdZp0qUT8tSzVZXgWZWSjkIJ5E1ggI3295qwWB1Fuj
         tt0YMZlnaoAdaG0o/9dTG0eRZf0FgkkYx6/jtFY1w640QemFW0iJqUTrd6IJ0Qmn9jaH
         QMO3lZBfiFIsDb1TXUfeKSD/+9ym1LDIyGyXKaFWhhBUPzE0lk/965mNcWaR1TmeDGNg
         6i55uIXpRoU4/th3VswtAJqDd6HaYZmvGqr1m9yyvfDcD1Uc+nV32UQtnI/LfMkUfp6a
         ZYnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53345RHvAswCuLMH9uMEEsvzyibQ0k6IhJuJk0+ZBsYJHR376wcx
	TusNBSd5z6s7+7VSuEDl4Lk=
X-Google-Smtp-Source: ABdhPJwbfnkxJohldvzXnCkTN/4UxVnJzR8qxPjP7+MG2sQbhxplJuwEkap0OCpUMHqUl42d/3r+yA==
X-Received: by 2002:a05:620a:4152:: with SMTP id k18mr25854896qko.446.1615305377365;
        Tue, 09 Mar 2021 07:56:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5501:: with SMTP id az1ls5368591qvb.11.gmail; Tue, 09
 Mar 2021 07:56:17 -0800 (PST)
X-Received: by 2002:a05:6214:1484:: with SMTP id bn4mr26827604qvb.8.1615305377003;
        Tue, 09 Mar 2021 07:56:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615305377; cv=none;
        d=google.com; s=arc-20160816;
        b=HLuja9CPfFgX5uaVDHfIoCzM4RDfQZOdHmIqfRRPboZkLLOCUK7wZDoeEuLH4QqoZR
         cCIgwAEC3pV0TYgtKr1sTeQlfPdX1Iog+xB8i7cZyJyciA1gMDRemybWLC5lpyCUag38
         kWlpYWtT65a4a4aE60ZjWCzT65RvrAZ3bAgeehiLay0yoJDooNP4tPcwHweWrqX6Nj+n
         JqRNG7gHVgEhi/d22Khh/jjWZIxeDjSwI/DIn0XY9Wdp1QgEZrwfLn3cpaV8B7XaEkS3
         31iIeomc8q5mPdj6rAySZCPCaaFoK1ywnDgPZYp3+htcOaOWizKSQbcUwKOi07A0SBpF
         ZSHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=x8FFoj3IluSfmv079XiLbW++UWmZ0lPxA46obYschxs=;
        b=rI0+GuE4ZL7YJ3039ZLjJhG3JZd52m31HS999AeU601BuA+9l3DLEhnMFtxUmoUnYv
         zeUNPG1jdsfQp7X/+MdlDSMBF+GFv/+qLE+3ZUoI0mdJ2UJUgl+fBL3fplcWWmdxCBFE
         VW+ZRssAqRJQe7/mHx6GspGqDyFYpVf39ZYkSXYL3UcA8MWqT0k4H9uRRKRCy5pemIu0
         TVjVnfimhcEkr/2muxKrHbjJSgPYHhHE+oIQk4CkQ6gttiKa8wGe0HasZMr77/Zrk8O8
         49W7EJqU/x8VG7bjyh4Ze8Sh2d3fXR3utiu6gF/3TNDWtzq1bN2kq4aAonfDA2MMCa9Z
         XDfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oIku0BQd;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w19si1080631qto.4.2021.03.09.07.56.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 07:56:16 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id C0A4D65253
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 15:56:15 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id B2FA665349; Tue,  9 Mar 2021 15:56:15 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212197] New: KASAN: save mempool stack traces
Date: Tue, 09 Mar 2021 15:56:15 +0000
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
Message-ID: <bug-212197-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=oIku0BQd;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212197

            Bug ID: 212197
           Summary: KASAN: save mempool stack traces
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

Currently, KASAN poisons/unpoisons mempool allocations, but only saves alloc
stack traces for mempool objects when the mempool is created. KASAN should save
alloc stack traces properly.

KASAN also needs tests for mempool.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212197-199747%40https.bugzilla.kernel.org/.
