Return-Path: <kasan-dev+bncBC24VNFHTMIBBBEGVOAQMGQE2R7ANBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 4ED0A31C1F6
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 19:52:54 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id o8sf7237244pls.7
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 10:52:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613415173; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fexm1E5iB2AK2vLocvlbJ6vGIat8/DMeVo9wgvjgsUchyLR/UxbnCkxhKKA/48M42Q
         F2+IjbQW6Len9EJNEt7hN4YQWHjlhzYAh5DhH5ya1awJsvkiLTHR3i6Mz+XtjM3r8XfP
         oUib5Uk5u8J/rdj/SR480GPR4t2kMszZMw2PHo57LQbpXL+MoEFfij5h73/PtEaoe60J
         uSPdFG70sbtUSKo3SgcvbyNtbW6loJYOuh/jfb0nLwXs7e+giF1zZefhk5FbkrVDlBnB
         uP2L/Jb1/5TeRpFpURs6rR9HDWGbqYWarf3652UJrPGQCFX6wVfI14uACX0IhFXGUpaI
         uf3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=9xkRN9TRPP5UEVgSvonN8j0sxGKAmTlJClxn8OGiv7o=;
        b=uXJ6y26zu5YtXvFcsYRVSlKIDezu9jOdQ8GMTPynABX+gKq6+TOeUvMlP0m8Z1556B
         97GkYHwpyHjj3s/IdAO4bGNLJsyfafV8xb2Vmw9JdahvLjrW0CA2p+QzH/CjUQsTVqp2
         yOXvIC5qPoXybRo/peJQb6FEWKjlsJ1pOrqxPgTlK2b1HiWfftekCWnqi+/F3UGYKPpw
         LoSDjx6vW+8mg0eDYs2t8aZSKelssMYHhjs9OxDBPrXhY2s/eYErZ09dzBcR2eqzy7OB
         bqx0G2ynh5KfhilcFAexkcN6FwCLroj+uH2ZIx8nN9yBSaTuGO6RmJD4bPGZM2U3jYMA
         s77w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=n5YIOGwg;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9xkRN9TRPP5UEVgSvonN8j0sxGKAmTlJClxn8OGiv7o=;
        b=XK2RjIcZIaYPY3pkFDw//AGswvcIcPlVE7w/xrsQrdJDJeOVethhRlBX4kc6Zcd6mE
         GcZG9HlWGbYOpZ8bq0NuTjTbG9t/uuQNkVUPU+4VPa7G+Rmmn0nE+ah+bAf49iRteD8h
         vWSug0XZrWZVgO14VPiu29RDqpRTTfjEUtRjsuJ8Ehn6UZRgz5MKX6isTnFi7VNI10H0
         Xj1mtfWmWIwfyqerGOx0L5VEpQ/Cp9Ri8I63H+wONvUAp54K11GRHbU2vRDpD8pZX2ui
         b9fi9a3CUFLxY0OOtuiPwMgDnO2Dt+CUJL8m/wrTuJGX7FQNGVIQDKS7E7BhQSgGJTHv
         gdag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9xkRN9TRPP5UEVgSvonN8j0sxGKAmTlJClxn8OGiv7o=;
        b=odQr2pf9h0pwWlNAkHk6z+X09dN67erszDDWL4DvzuKzhOHSvEsOWAW+hXdfNQWI0N
         PGR60l5v9ehire4+XVeIJ1CE2YhV5dn7DFxn8zC0rnMJAZuxV+R5LF9W/JINaeRMv9Hm
         YzWACPioWJd0LE9xsKSm21/5yYTxTlll24PmR55qab+otTbMDVtDUwVUbefYvL9aaD92
         YWVN3Ng1o8E8YUVaeDgPNf+cVv7K9q20LRxOqV5VL/iDupskUZm2zc7QPGdmBvmXwt/w
         19xYDXTzOvME3xkI40Mv/tvTe6YIqYib+FRNMTEbjtIymPWxTjHbOAJlrevXSlwaDsN0
         XwfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530449UwwbQ/xeLRQXwGE2rWVnRJdG2Z5MVrEWaHgM82+AmcOYRq
	QpJvZUFqOWX03bVpAsy6m+c=
X-Google-Smtp-Source: ABdhPJwOyjmy6+9/YWoetTybxscFNY/ljW8Dpquk0ICOM/Hvjy+qZJaR4v1IBE7UO8xUt+CXsxOgyQ==
X-Received: by 2002:a17:902:9e98:b029:e3:51d0:14e0 with SMTP id e24-20020a1709029e98b02900e351d014e0mr6752446plq.13.1613415173037;
        Mon, 15 Feb 2021 10:52:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4f84:: with SMTP id q4ls100673pjh.0.canary-gmail;
 Mon, 15 Feb 2021 10:52:52 -0800 (PST)
X-Received: by 2002:a17:90b:1081:: with SMTP id gj1mr230818pjb.231.1613415172441;
        Mon, 15 Feb 2021 10:52:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613415172; cv=none;
        d=google.com; s=arc-20160816;
        b=H2aNuyz8hPrVg56lUGYCSnoyFj1O3HossrkdAUTnLkcEmAQj588mNJ0dE2egW4Ejtn
         lLSlh8JRvsjH+SmhPxwvQwOAorqEhc4+OF78ogGHt0dQlhcToSN2/FRyFAnPhVcb5/L0
         EPS4gpT0mAJvFtsgpE9VHcbFPTGlqSN4Aqbnr3wvovRfW54Fl7LzwJ3UlmCQpgyXA4xt
         WvhL0467SkpPEIAIUsn3ZHO7vwpBteevAzjcp8Lh73Z3Onk09RqCgAnbCnKfJ5TmeTPL
         MtFTXqA1Es24rsWgVzPZ8XtmuX4bgfuS8s8lJb7KF5DATNjjwRw7T5sjUyaAoRwGwDgl
         NhUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=wkp/s5AluTOrB87jDqo5H0dmxIeiaEMA1bdT7w/fMLU=;
        b=yglbw5iE5yeizs2p+6OIWGmy9j4WrqM1n9b1gluUk32rgc8W2TE4fGbdu6sOli5/Rv
         ElWyMfAu7Q8PBbGT3W6WbD9xTgh1iv1bCGCH5TBhHviNBmj//MwoeyfWrDwbL2Rss+S6
         QRO7xVSrtVxeQdcmHZUPnViO883zK5Iv7GK0ubaFginjrS1QvFrCULGUcZ1698tsMiZi
         6sK9y2C3DcKzgP4W8hDmrBeFTXfZG6bJ8yPNQ7J43nf3Lg4Vs6+87G3fs3V5XL+oqLJo
         ttDvQbNEuE75T481rrPPzHXrilmkio+Yn1j60Z0tieqzBeJRGKxrJXQWAKoVfH23sOdb
         CiDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=n5YIOGwg;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p10si1040574plq.0.2021.02.15.10.52.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Feb 2021 10:52:52 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 1CDB564E34
	for <kasan-dev@googlegroups.com>; Mon, 15 Feb 2021 18:52:52 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 08C64653BA; Mon, 15 Feb 2021 18:52:52 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211777] New: KASAN (hw-tags): support CONFIG_KASAN_VMALLOC
Date: Mon, 15 Feb 2021 18:52:51 +0000
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
Message-ID: <bug-211777-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=n5YIOGwg;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211777

            Bug ID: 211777
           Summary: KASAN (hw-tags): support CONFIG_KASAN_VMALLOC
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

Before working on this, it makes sense to add CONFIG_KASAN_VMALLOC support to
the generic [1] and SW_TAGS modes [2] first. This will allow to only focus on
the interaction between MTE and vmalloc internals.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=208515
[2] https://bugzilla.kernel.org/show_bug.cgi?id=211775

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211777-199747%40https.bugzilla.kernel.org/.
