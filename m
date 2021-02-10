Return-Path: <kasan-dev+bncBC24VNFHTMIBB7O3R6AQMGQECWLTELI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A0ED316928
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Feb 2021 15:30:22 +0100 (CET)
Received: by mail-vs1-xe3d.google.com with SMTP id v22sf308582vsm.7
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Feb 2021 06:30:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612967421; cv=pass;
        d=google.com; s=arc-20160816;
        b=WBIQ4Bl+K9QWbqZaEcnt9BBjKWh+ERB2JcPXl/0EdvmkjNMJXRJ3t9nefVjPT3Anal
         OonEhzGZV1Wr0D/svBUboHuOFdo9wwFsgb5KsiM2qmtf9CsoXqx1frEVgVlrqRemo/vV
         KvBV1EDs+dedwVZoS+LNrvF2KFPyHUC3oagkjijdO6T9Ug4HayEegD5QM3vKCTUCv/WV
         SGR8RaoS5/Jzm2XTF/IpqvCu4Wxg3UB/wQAh9pwyzpla9kBwkAcnpY28Nnx2UXn5d0b7
         b1wrVZHzOSP/sDSUhTBqioIMwYhr6zwTm5jQzhQmiBQkbIoxl9kqeRnBJANE0LdzGMK0
         zORw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=n35dWmUGJOUDfF3UO6H2FLxu8yF5z2ri4Jdn6PQi2pQ=;
        b=D8z/v+AYBmMLriIhzbE8nmzj3V+m7GDyC8zrif7tDTPCzaWRgK4HSEgSzOWeewqy11
         2axrqUGGM779sNepeV7jdtUWTHGzkB6wGcZWWwO0jgA+P3YaccB+tSS0KZ0xZc5YhXYl
         HAV0i9LK27AUAYPVKnm5uYPnCwagI/ivJ2d35vs//Qfq5eddIJDmlV+l+w0cp0NQWvEi
         lUmj/rj/OmiJL5VuIp+iV80YvppoGh78chLFE7vogAFls6xG+RUHSWeUx1TOiaXYMZ+x
         XkOI4+NzkTPbbYyPuHYvnip63EoDVy8oxQXSlbdTa5646K2X2XCy7Lbv99kDVW6KetIy
         yJ8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SiYftTPX;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n35dWmUGJOUDfF3UO6H2FLxu8yF5z2ri4Jdn6PQi2pQ=;
        b=EvBPw0NlU99GZEQQpZ1PAiEKXbWYx9jehDZqf4Bi+kJq+7rV7pfSs1p9l+IIKk7mBb
         h0qoWru0zR5YkxI8gbnOpfZQdcZiqbcLdNrs6gwLat6oTnnXfWvGu+m1QeokdceKwdK4
         tjyerPtCx/i3Eg3dHDv55QOiSr8hB46t7CZXLt0WKns/sl6lT+daVT0JknXQNPiTPqtp
         eoZPAomjeASJgFLUJBvU0iCadrQ/VAy8ShHfOdvtVOQnmUVHJYIhRxKKOSXerbCeX4kJ
         e1joUsTnJm0QFtJRk49RjA2tHASoR3Em/bE2KBUibn0larLB6BTArDVR2KplKgv6wswS
         ab1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n35dWmUGJOUDfF3UO6H2FLxu8yF5z2ri4Jdn6PQi2pQ=;
        b=aiH4inrlw6zaMImR/i8/41o999xaQ6sMsfeBSdo2W1ze6cpLCUy25kGBtL5M6JCYBP
         wcIMzwybY7xihvN5EC+vI4YxHZ3lHL5elEThb6EtGiIo9aHLL+qhD0g1ika+TWOIpNy5
         cGWFkb8TiWGJgTt2MuibURMabj3/e/TyTjxHyknd1j1CRrgTA35T+lk3splgVgdRjjWP
         1Qhu4l28lxwech1or8vjOo8cjk79sXZhVVIZgkOmtKC/+OU3+wNWTh3Yal8c/Rdo8JAi
         fRvUotJvd1PKyZNjoS0Vzmkj6uVCPog8t74vQZPrarrhR/7pQzkKRsUp/AjgX6VDFQM7
         Cbjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532d40u5NIG6D0BvrqGj23WFB55fboT4E2u31KN95s/oe2animqd
	WaVbvR9Pk3FZqZgZZJ+KjAU=
X-Google-Smtp-Source: ABdhPJxsaQ/i9Omm9RGMqaCNqyTxuFr+MlRiNFd4cg+bLYXKFE3mZ8gFnRz3M9O7/puIsEHv2ab6iQ==
X-Received: by 2002:a67:2f90:: with SMTP id v138mr1807337vsv.2.1612967421400;
        Wed, 10 Feb 2021 06:30:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:bc14:: with SMTP id t20ls236659vsn.6.gmail; Wed, 10 Feb
 2021 06:30:21 -0800 (PST)
X-Received: by 2002:a05:6102:a1c:: with SMTP id t28mr1992355vsa.56.1612967420963;
        Wed, 10 Feb 2021 06:30:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612967420; cv=none;
        d=google.com; s=arc-20160816;
        b=BnNO1C8XB0gq3t6rCZdOuws8hMswtuIvA3PVyk7t55xEF51yn5u471Bm58gERfgIR/
         AviTTdeR7rOooFTmZungOPCA+DlJKqld8RqT4O/ytFfVtZdYkRniDLK6s7w26hlBRLCM
         dJOQbsKywECghNHFHlme3seremm23PJiLvOA77e+gA+y2AtzH/LCwjIgRbnRi9JSB1By
         xXGN1sBYzO1QxahhMVxW3KhiMme5EwOjJNS4XKgUMLRP2Gmaci09M6YeU6Fpustirte7
         740e/8nVEjOIAcvSh2d8vVp5+P2EpbqRaw6bdxwzAkZu718jiVP08bq8VyEKKdoZ8jJh
         ASNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=NodgeNV3NKSARS0IyfKCAhR15jszSUFSQ7XY8fRYHgQ=;
        b=K2bqOImDaZMMGUU4W1qwz4IZGWvv9NezCj6pfUm/SVv2/PWY99mwkNzdiWXTRpzZ1p
         yXyjFyN+PkxbFOppdoZ31uI+kIOIDxMHOVCB/dxT99gakYG71jjByQjMd+WPWuYvAZgJ
         0nK1ODinDyit6CgqnXO4aPYg/gDUQyNcnlb8J1RcS2Vfl8zTBdie9lujG+XCrP46XV0M
         zfHZ+WP5b5QzRwAEze/cSAGQ8w9rD66iYjYMV03JMaRiWq/1WIAQw4+pQRS65ax3kal3
         J3dS8V0sSzmg78wRFVg1es6rudpr7qtbarMVCHCnLfnvM/KzUTYHtvV6fFXZ/unRGPAJ
         kwiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SiYftTPX;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l11si125211vkr.5.2021.02.10.06.30.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Feb 2021 06:30:20 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id B509364DC3
	for <kasan-dev@googlegroups.com>; Wed, 10 Feb 2021 14:30:19 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 9BE2C61479; Wed, 10 Feb 2021 14:30:19 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211675] New: mac802154_hwsim: support net namespaces and phy
 flags
Date: Wed, 10 Feb 2021 14:30:19 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-211675-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SiYftTPX;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211675

            Bug ID: 211675
           Summary: mac802154_hwsim: support net namespaces and phy flags
           Product: Memory Management
           Version: 2.5
    Kernel Version: ALL
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: enhancement
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

drivers/net/ieee802154/mac802154_hwsim.c is a 802.15.4 emulation device that is
very useful for testing.
It would be useful to improve:
1. Support for network namespaces in ieee/mac802154 subsystem in general.
Currently there are lots of checks for init_net namespace and nl802154_family
netlink family can only be accessed from init_net namespace (no .netnsok flag).
This does not allow to have isolated devices per test namespace, no isolation,
not reproducibility, possibility of badly messing init net ns.
2. mac802154_hwsim does not support phy flags (WPAN_PHY_FLAG_TXPOWER, etc),
this limits test coverage that can be achieved with mac802154_hwsim.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211675-199747%40https.bugzilla.kernel.org/.
