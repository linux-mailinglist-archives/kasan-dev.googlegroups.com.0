Return-Path: <kasan-dev+bncBAABB7G5RWWAMGQEOUKJ4MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A1D581A953
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Dec 2023 23:47:25 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-40c25f7963bsf64765e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Dec 2023 14:47:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703112445; cv=pass;
        d=google.com; s=arc-20160816;
        b=ERX+lsDpTG4BM+LZZU2G0Ur4k6W5esW8avokR9lwJhZ08ik2OKn/vzGIisOXLE/vKG
         6NUu7/JQcxhcD1HsEGh0kZWtPhMHR+HvOlcd6SFUWixtJY3TDd53rcBdZsx4f6UQgyjA
         oZeYO5hDxLbcz4nw/gbD2f3zRLygeXJ5kEChwxiN9UGWm64AEtqD7PEKZjrhQBjy1t+q
         BtZ67v4UnIdFYh2A1bpKORrAAwdx3uZG00zP+i44OcY57zYE3ibMf86MuUwRyV3hwoWA
         aLWAGScgkGSQc2AHNGL7OLhyEouRolNd0lJ1cOH3D6ku0QrdEbIF+QKAw7S8ytcpvdjj
         n0Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=Mx38yiJCaxlitKKpx83tWjtl9ypYSYPigcbi1GQeOA0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=mHfCUqGF1yrQN8m+lfdNbPkLBBkukv8xKl5oNodVUftAlmQEucBSpm8e7Y34fVxAKF
         a+ekwjhNqrD0GdlS9b9gEQw8ag/Z9T+5XbnRDm4YAqccO0BZhJTKSTe5/g6hhpIR0zCL
         BVu7xx6fnUI1AZ7UoH9+Q72yUsumSLOUIK2c/XSskwdTzi3v5VSxoaC/hwmglD62QvwJ
         CEtQxtnhkVd9JE5J0q5I8HkAMaLkDTpsW5+2QVImm3Ku5eHFNn1DviwVNWnXiL5dkP2w
         JwDW6dF33EITrluSVy+h0zGn3674/FOlZWA9Sabiqe9f6NOp44CDEWSDXvnw3T4BiLYv
         niCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=a+umf1oR;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703112445; x=1703717245; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Mx38yiJCaxlitKKpx83tWjtl9ypYSYPigcbi1GQeOA0=;
        b=W81hB442VBsYKVMJuflMs2J7rMMubTEjooo383tjDpFUHashftHpuS7oNiln1Qz9Xg
         Has7e4dqles1MqxPq9kZQiX8aI7dcouwSrAYLsRZHd7n+mTgTJEFTjMtwAC+DPVf4F1z
         44BdYuB61+h1YG0cOsZ8ofpjSnA2AwbLQbYmWmYdB1YrWRhN0z1/LLmj11kKyCHnKUWL
         zdoN/AhYcDjsAoVJgATz2bdxV6yYDK469voE8vkYfRNLOy12jCa1qouvmCFZSTjIy5+z
         INJdBnI2ohcxC2lQfRzFEFDv+OZf7FhonOxxNkt0KwDgK3zolyk8IdLLDAeYeUV53+GN
         3NLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703112445; x=1703717245;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Mx38yiJCaxlitKKpx83tWjtl9ypYSYPigcbi1GQeOA0=;
        b=I8QqWo23mQfXoUIpu7tGVLzhVR7EBavK172WLKcABaVbV+QpPmR7H1wSCg9NZ8bd6m
         ldknaue7pp8+XvmdPr+PhNYDSTtbWD67kavkh6jFDqA+rCBQrqegQREpQsMz+5I0TuV1
         3Z7Ez46+XXUK2hpDXalwN7pN+ifUBl2SSn/3f/wN0tPImRlNigj0CEUFujQrMy5eppGa
         metBUN9rkb/qtwHhUNeplxZsJWBf9mPUvKNbWysLlrgfKXRh2GnRnHF/Kwq8nN0M583R
         eTqkGDDKCNiJFDV0gqRDloL9pOM31NwoHZ9gw3QaG3gT9gbbhtjyfo1RuDH7lQJaT8E8
         +ZOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzsT6sSc4pqiGMGqlgakYNgjCa8dpf6+52eEpOMON6Lk4oUXJ0T
	Ci4e0PqMTJQajb2f1oP2oa8=
X-Google-Smtp-Source: AGHT+IFIry6U0jR5qaxbFWeqtBAgvyVFDGLv2xurEyUVVKY67e1MoWmk/ws8j0OEYuUBz0vJKM17/Q==
X-Received: by 2002:a05:600c:2047:b0:40d:2bc7:e9b with SMTP id p7-20020a05600c204700b0040d2bc70e9bmr43744wmg.4.1703112444490;
        Wed, 20 Dec 2023 14:47:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d13:b0:40b:425b:2bd8 with SMTP id
 l19-20020a05600c1d1300b0040b425b2bd8ls91203wms.0.-pod-prod-08-eu; Wed, 20 Dec
 2023 14:47:23 -0800 (PST)
X-Received: by 2002:a05:600c:5023:b0:40b:5e22:2e0 with SMTP id n35-20020a05600c502300b0040b5e2202e0mr103012wmr.76.1703112442967;
        Wed, 20 Dec 2023 14:47:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703112442; cv=none;
        d=google.com; s=arc-20160816;
        b=Z/rNtxzlptOvYyODpIHRxKgijIwwkYFRNr9m5nDwPbUHm3EJJPOBYCxJv4TqC8v1PJ
         dI8ofULUonXkirjU3LZnE2AOSCv2HuJ6bbi6jcbTpl7ScIwQ3qjNQMlLY30svi2epZpF
         7XGUlaxvtXYId74VHNQQ6anR4E9oyeO1y427qIyC7LDyglVVtz+hiEIxnqZsR6OrlapV
         N+K0vcSK5PIyxawwZqTA0IKTPrZF9+IZEAOOxCai4g0/I6oyw59UZycjfVrAcT/1rYyd
         J5RreuJjyOa29RZQijMpLBzmeXw3pDXUlb0lPFagtLZjAY8JzevKoeXBnDn+dBvh/Eid
         UBEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=Wpg720g1OR54WKdTpmCL43l8y+bWsGk/Vrc3L4dRwTI=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=DyT6gWUVwlSlSRWXMHbNtCkcBX0YzBXxKVBepbWFxjClwSE5ALLlS1h4QSdi/gzyp5
         R1vA4NOvkQ2HGohL+nUo8i0J7zOl0QgtrnNw8YykkL7xTnZgBzBEL5EbjFBWj4yGW8Nh
         snjg/AyvcqeBGNH2nfjcrt2Mk8seayjyF8ILALNRB6cQXT+M3eXlC90NO6kgTRZD4Cr8
         ry77D16MW58Veo3IhUeR8MMTUYL9B0180V05ofovjpBXfIAF0M80K/QZpPzZbgLYy9/o
         /GT3uzwPIIEHJbOrE4APAMVVKlan2bsVzpBQ5fLNff4GtXTT5G6LgPTm4QvMN5wrBHRG
         rXjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=a+umf1oR;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id h1-20020a05600c350100b0040d381febc0si93860wmq.1.2023.12.20.14.47.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Dec 2023 14:47:22 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 9FAB3B81F20
	for <kasan-dev@googlegroups.com>; Wed, 20 Dec 2023 22:47:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 053C8C433C9
	for <kasan-dev@googlegroups.com>; Wed, 20 Dec 2023 22:47:22 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id DF4E9C53BD0; Wed, 20 Dec 2023 22:47:21 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218295] New: KASAN (hw-tags): fix false-positive with shared
 userspace/kernel mapping
Date: Wed, 20 Dec 2023 22:47:21 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression attachments.created
Message-ID: <bug-218295-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=a+umf1oR;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=218295

            Bug ID: 218295
           Summary: KASAN (hw-tags): fix false-positive with shared
                    userspace/kernel mapping
           Product: Memory Management
           Version: 2.5
          Hardware: All
                OS: Linux
            Status: NEW
          Severity: normal
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Created attachment 305636
  --> https://bugzilla.kernel.org/attachment.cgi?id=305636&action=edit
Reproducer

syzbot reported a false-positive in HW_TAGS KASAN:

https://syzkaller.appspot.com/bug?extid=64b0f633159fde08e1f1

If a userspace application attempts to create a non-anonymous mapping (by
calling mmap on an fd) with PROT_MTE, tags on the kernel memory that should be
mapped to userspace get incorrectly reset. And even though the mapping is
rejected (as non-anonymous mappings with PROT_MTE are not allowed), the kernel
can still trigger tag mismatches if it accesses the memory after the failed
mapping attempt.

See more details and a potential solution approach here:

https://lore.kernel.org/linux-arm-kernel/CA+fCnZdeMfx4Y-+tNcnDzNYj6fJ9pFMApLQD93csftCFV7zSow@mail.gmail.com/t/#u

The problem only happens if a userspace application attempts to create a
non-anonymous mapping with PROT_MTE, which normal userspace applications should
not normally do.

A slightly cleaned-up reproducer for the issue is attached.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218295-199747%40https.bugzilla.kernel.org/.
