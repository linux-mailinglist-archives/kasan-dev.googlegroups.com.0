Return-Path: <kasan-dev+bncBC24VNFHTMIBBVOIT2BAMGQERKZ4Q5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C8754332C3E
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 17:37:42 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id u8sf7187254ooe.16
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 08:37:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615307861; cv=pass;
        d=google.com; s=arc-20160816;
        b=uTQldgMC1q2HoeAiW+eiXsVDo1UJZ2QZpoBTyONjMMmmZ/wwW+L3R+qFkWkDLBgQ1L
         L4+Z542xQ3ekM/8S0zoHzndDoQVJRvRD6QqAXQ/yO+4OgQHmW1CBHlR7yhwK9xneP87s
         NirUYyI30T7VH/BwavBy3ASHM/mzklxNanmxSldngHbZ+LwWHPVIurs8PFuLUjihXCJE
         19qehXBzu+kFjqGwZATfb0O8nGLpU8lCZe6HvMVazAlpeTU3WCvbQZQoXPjt5cElMGC8
         /6VERiHysaii/6mvwzlsyXwD7ylzll6+WqlHvixx49y7NiJUBRpM40HMnppsSQ/fOrdZ
         xuvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=XQf+iBPimjF/Bt+FngZL/Db8OyslTdhHHxh1CsJKfzg=;
        b=TmZPtJMyjfwTOczl/tY5klNW41Cv+m39lq3TJB6f31/Z3SoPXJ4hVpzqPAu+ubI1Yg
         /Ba5WOQ5S9964eODjJN3gHi1bIJBxu+goJa5eHrr8OZztlXdrLGoOj+nbxRBuhdlNVNX
         XzF27Ri8Tz6Dksr04CUfj1kxeei7u0hU4veAug7bBfLjOdCHrPr12MgbLoHidYVk2Q+D
         0G6b2R4Yl9pi/kTZF6fZtOc1FYY0RyxcE02lnK9OeUnBtAxUuhhEjoj4J/K3qc+rVb4f
         6jhRPo4i2YNkLKlZEa/A/hhdIETruSqpe/QW5KH3yCt6xy0xTN54zyTOP+hzu3M+Sy/+
         Prgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=efCpc44F;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XQf+iBPimjF/Bt+FngZL/Db8OyslTdhHHxh1CsJKfzg=;
        b=h7CkTyjCVvA248cZwCJ9ImzUHiLb6T3OZr2XyZ9p34HCqqAWkPiNSt861qKPqbbXC+
         sX3W2TXuZJjaDhNsLBtmNIgeTF+rHVwx72g1HwbjMjKGkXEEWneHxPISIWcK6E3jmtCU
         typcIgiejXFZWJ+fgnQZ8v/cdzlC2dWKRAbC0tv/E70U7WMY02bIaRTfJGXBdpa1CvVL
         0T8ZXHJxAj3VLetS+aHVlBvfx0oaeiGA+TxhIW03TAb5QgEMulJei8hydv5KEyP+fRtH
         DBUG+bdZ+16c9Kbwpg/kIzAxCRtNbsWJJ/XA9bo9MjzJzbLO0nYR9rDzNbe1zNlOTHX1
         iGsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XQf+iBPimjF/Bt+FngZL/Db8OyslTdhHHxh1CsJKfzg=;
        b=YIF3ImXxMeSFfYXgyNoTE31rXh0tV5e7yTnyy0ZcOGmV+PEaDHu+PJG4YVHZtXrKik
         59RGXt7RCqax4WTFKjZ/6MglC8ZvlGTQmLXnncz/IU8X6Js/be7Jlh16OXJAsLzGe2EJ
         KmJmfRuj16PF3pkcl1pt4OKzqCi4PfaE110my3dyckPbrnbTThUBSCa669ce4koAnWUx
         b+ys8YQ48Vrkb/mtR8MjJdSH/DhgtjgbsirfeK07V+9zuRt3nPh2S5KsXB/ISAmj7l0P
         tmyMvj6Sw+BkZAJZVNrsIxF+UIwQvrHHahlaPlb6nWhqgsLT1EQhmvBWswd6hUehyC4Q
         Kp4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53369kIGZ/1L0SOBpD/4WGzlaAvurvuuHdK5AcMi81jg8oAumM+c
	3pDrCq/kjtlw4wCFdbjELvc=
X-Google-Smtp-Source: ABdhPJyJcEhulu3+8Ne/yYJnkIiTE5e6XFt4YkrFahDrDFUYtrDnjkTnWl94mIB8p6rI84n07bI3ag==
X-Received: by 2002:a9d:6416:: with SMTP id h22mr24053797otl.193.1615307861730;
        Tue, 09 Mar 2021 08:37:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2470:: with SMTP id x48ls1581688otr.8.gmail; Tue,
 09 Mar 2021 08:37:41 -0800 (PST)
X-Received: by 2002:a9d:4b8d:: with SMTP id k13mr23888363otf.354.1615307861359;
        Tue, 09 Mar 2021 08:37:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615307861; cv=none;
        d=google.com; s=arc-20160816;
        b=EbDxtaRytsBDpUp7yCPhxA8IN+yNUST78Li+s0Ln117TU+sZFor/6gAJmTYuGYJ4P+
         ambLuaBcP1Myu5sT7DbyzauO0u4+2DnNpvO9ynw2OjD1E7nfmiaPyeSlP+yA3HQDwoz7
         uA9z8ztimR6POMNSy70ZsldyD/TClUzCFAXZhHeBpapS46WpmXFW8jd1Ts91P9lEUATI
         uJHP1xlgASq4uWMsQKhwFM+vF8AWQg5M+rxov0M9GBvt9a7UXpNwrNmWXA2eDwJZu2vm
         BL+r63Xg9NKZerwXq5b69yI5fSiz/rvIDVwXqqSJ/Zz0TAwPABAuZ5o7vjQhpb4LQkax
         mBzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=PSIFocnWVh/+sucqbaw6isgdyod+G2/YGBs5V3K7XQU=;
        b=Ld6Tdk49RkzwutGyaBKj/lH42mQQ2ZcZY7q9n4cQi0620Rl3exioMaUxscDacrq3S2
         Kut+lIy1Wmp0BH3aySPixZFXubSPyyHWw7JaN3ymoHkr+n+WsjFROuct89gr+Y4xBBT0
         /6DfhvVgnYEXD2nNiKD1Ty0tujR6yvmMuoBS9zMba1fLGc1VOClLVnQ/fr5ZE8ypiO85
         0IlfIaosLLisr6rVJBF/boUjtIuxaUks7CQTEkJ/bippEQRwSeoJ6BOJTXo384SP7RJR
         +AKNwVqYcei9X0G4aZh3/F+uiO9BmcKCRSC2RQbN9CFqJX6MqkF4EHyO6uEjhpucTjSe
         i2Fg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=efCpc44F;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c10si1044328oiw.3.2021.03.09.08.37.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 08:37:41 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 95A9A65238
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 16:37:40 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 8257E65368; Tue,  9 Mar 2021 16:37:40 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212205] New: KASAN: port all tests to KUnit
Date: Tue, 09 Mar 2021 16:37:40 +0000
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
Message-ID: <bug-212205-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=efCpc44F;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212205

            Bug ID: 212205
           Summary: KASAN: port all tests to KUnit
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

There are three tests remaining in lib/kasan_test_module.c:

1. kasan_rcu_uaf() and 2. kasan_workqueue_uaf() that trigger KASAN bug reports
in a different task than where the test is run. Porting those should be easy
once tests start using tracepoints instead of a per-task flag to check for bug
reports:

https://bugzilla.kernel.org/show_bug.cgi?id=212203

3. copy_user_test(). The issue with this one is that it requires a user context
to work. It's unclear what's the best/easiest approach to port this one to
KUnit.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212205-199747%40https.bugzilla.kernel.org/.
