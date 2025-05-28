Return-Path: <kasan-dev+bncBAABBWF43PAQMGQEM2JN7BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 12531AC6674
	for <lists+kasan-dev@lfdr.de>; Wed, 28 May 2025 11:58:57 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6faa53cbc74sf60026046d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 28 May 2025 02:58:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1748426328; cv=pass;
        d=google.com; s=arc-20240605;
        b=EVjvWRL4XVR5vKazJkeiDjFhRbWm7yHi/IDt8KPqLVay86j09L9NoUH/lvwm/xatSW
         R1cEHfYxry7BUjn9Ub1Yy5WRpPSSSyjKUDlyRth4iG0RjBhg7RZgppG5CJsixGDH1re+
         8jlfr/0vAv+Xlw8PTEgwAKC9O+TwpSRxrCL1gWHZrDU26Ranq7HN5la0ae+RlZyuHze7
         tuswx8iB8s+60mIVyPJIIFGEeKabwjFngVj/vW+6M9VhegboEUrFkR9eYc5B/x5AtrPh
         cuqsDzMZ3fNqzbudyUr7RYcKUE+rtc3qDpPJWhfepGfC6oDwY60JJ1j2y7IaEdE6cc2a
         JzHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:message-id:date:subject:to:from:dkim-signature;
        bh=fs8LdEITWowljssr3CqcAKkTVJjVo2iJvnIR8bk7L7w=;
        fh=nlL8q3+X2vIp9626nA5zxoG5cUv6RXxWAUyldzF0Mtc=;
        b=hvY0/+r0xytqDxu+fQRZn24AKVCByrC6IB9edE0MXDJ14X2QzjtRNlznnqan/CANfO
         D1uyqLeJ37vFrN1Q+Wg6m8bz+FFgqrlHaEhaYEUyX0+ChL7k+PBqaJv8+GJ/ucRiN5cj
         jIAjyI1fCTCklIHE+zEEdEaqAxGU0JQ3PXg+8k4z4/a1dWGPAtnN+gCtBxDAuPxg8xLg
         iFM8KbnbYQrs6PyKTYZCdgz0q94f6+orHHiWo0dbG/klePAZ9b53YJMZ1BJ7viBbZ6Vs
         bNPaR6+/DOsIsuK4Ekm+TZwkxf1dzdWl2ObjcQ+0OSQVLkREWN+YLUOzp963g8LESs0C
         /w8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=D4slhf3N;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1748426328; x=1749031128; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=fs8LdEITWowljssr3CqcAKkTVJjVo2iJvnIR8bk7L7w=;
        b=UedRWFgeek/CsIRCGMQREyUaSoohag568f0WzgiGY9V7PjCIDzJ5YDwrx+BVnbCd4K
         6Y7t82JGsyqriLuoQzzfAYdhlL8LmsztJWk8erznBkBn+SGDjPSE8eJNa6gfQp7PVPna
         ZNMSkYFYSibANMrg9jUUD0nvRpnz6KWtCsR7sUlqRRVYRBiXCN5hcsJvaom8UdQHfoUY
         AK8phi4wgxVb+ri09UqYuZOXP2rB9z8rZO5Med898mMJbho+cdYS/AR4+IVlR9Gn2f/i
         YWw/EHugg6Gj0fZoz7guJclhq6wM6PiVvl87kji/PELApa7l86sBxI3dxV19w51VeVvk
         B/uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1748426328; x=1749031128;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=fs8LdEITWowljssr3CqcAKkTVJjVo2iJvnIR8bk7L7w=;
        b=LOUDQjavE+McLw9aw5aqlYf00McTI7GA+2SnC19zQXcGXHHjQp1vV0Tq+3+tfUGEvy
         ewS1IIMm61PBipI0QiwyftdfKfCpsRoyBwb3OXGYY3b9Egt+VofY/I79bE0NFaIA4Q5P
         Z/66tBBnskRcI6i47fzVYOZfPlA6gzFURrQ9DQ3pC2P2xtaKA2hfEunoBOZd5GhdOr7v
         qUu/HlBOenciUfgQSDt09dXEFqSFMeYPo1gW8XLawwYVgGj2LXe6ocfjLQNmKC7HaGx5
         i90GaWbNeRjZ11/hjE2pCid1FjCfkxYMTxvWJ4jmRfviw7Rf8k1Ry7YjRP3MChvhtZhz
         wpJg==
X-Forwarded-Encrypted: i=2; AJvYcCUs8PEEZwYUy/6QsKsNooxUvBBpJ+LZqgQHU+l94jNc0bNzbup0uDpCZqSm3JnppA6pHO355g==@lfdr.de
X-Gm-Message-State: AOJu0Yy45lIA+6DXMkEBo+Bpqp0zC+Q6S8/cIsduW6K9vjuzyxld/pQw
	1vGQup6V8DlmYmY+4/c/Jq9KIMONDiGXoe45pr1+m2ZHhVLl6zgDkwXh
X-Google-Smtp-Source: AGHT+IGMySrb76VBIr17NjDX82/d6s1o9/xqB6wydINqN3HyBwfNy7omJd9Cne9+/l3+usguaTpo1Q==
X-Received: by 2002:a05:6214:f04:b0:6f8:d223:3c32 with SMTP id 6a1803df08f44-6fa9cff5fdbmr245442176d6.10.1748426328573;
        Wed, 28 May 2025 02:58:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfiv8TGWEb6BmMo8m4h57uVoCABn2bzA4zvnnILLsh/GA==
Received: by 2002:a05:6214:91:b0:6fa:bb85:f1b9 with SMTP id
 6a1803df08f44-6fabb85f1f7ls10396916d6.2.-pod-prod-03-us; Wed, 28 May 2025
 02:58:48 -0700 (PDT)
X-Received: by 2002:a05:6a00:1482:b0:740:67aa:94ab with SMTP id d2e1a72fcca58-745fdaf1dadmr24383693b3a.0.1748426317329;
        Wed, 28 May 2025 02:58:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1748426317; cv=none;
        d=google.com; s=arc-20240605;
        b=ET3kL7y56XSrY2WTlrvVBGTnPt3Zh2pfjTDY5iyZ3n1GCYzE66JqQ9TJqeLgFTtzyl
         E2eJ+jq6gD02PVFOrgtlgpJ1XxbkQbxFj1kwb8C2I47Uf4n6KybE0ZxfobFQqstOZ+0h
         Ag04ooL0sayafsjubImPg0d+Slef7grNI9qE9pTIktMB5EUhdBO4ocThOIgEFvlNfx0H
         9LWGuMFQ7Qei3uXbYIw6XmaFBja5K73mErlJKoA7xZRM1Lq4p2eAadxy+VK5maLI489t
         PJi41f79wu8DW2AUEC17FYvQBBSfbS59I60SU64HmLwtvANvQGkOC2S/8h8D/q+hl8jC
         9fww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=yipCcSwyNVvj5m4Sh+dlVbnmdT5kkSgwwg7YAbyvFyw=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=QwEF8WU28T2d2BIar1s83sTYMaAmffxd04WBT6XHJfq1MAcCSF8PToH7t7Ks22H6nz
         W1aG7OnM1zLpJN9g2AfzFIzeHZ5qtz5IHR3d4nGcnTiWYNhHFxABsUy1oTfx9WP2h+Qz
         kCSTzU3YoJM5+WR4ZwSlLxf6IpfzmbSEPLUW7dtUEgTYrTPO/MND1UDN1bDmSKFrX40s
         RcypDUDR9GZMvk8APKWJJl0yyOfnsffAw5aBmVjhCyfogv7EPkX2iTyzZ3zG29wmf5Fm
         /qG8YOVSht85XXna00p3JR1mWX3Jg1p61oNfPkTQ4YPvfUp5PW9aMqDnl2YkXJXM4oZv
         306Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=D4slhf3N;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-746d5c63963si49850b3a.2.2025.05.28.02.58.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 May 2025 02:58:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A42185C53DF
	for <kasan-dev@googlegroups.com>; Wed, 28 May 2025 09:56:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 5622DC4CEE7
	for <kasan-dev@googlegroups.com>; Wed, 28 May 2025 09:58:36 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 488DCC53BBF; Wed, 28 May 2025 09:58:36 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 220167] New: KASAN: disable tail call optimizations to improve
 the report call stack completeness
Date: Wed, 28 May 2025 09:58:36 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: tarasmadan@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression
Message-ID: <bug-220167-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=D4slhf3N;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=220167

            Bug ID: 220167
           Summary: KASAN: disable tail call optimizations to improve the
                    report call stack completeness
           Product: Memory Management
           Version: 2.5
          Hardware: All
                OS: Linux
            Status: NEW
          Severity: enhancement
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: tarasmadan@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Some call stacks don't provide enough details to locale the problem area.

Example
 kasan_save_stack mm/kasan/common.c:47 [inline]
 kasan_save_track+0x3e/0x80 mm/kasan/common.c:68
 kasan_save_free_info+0x46/0x50 mm/kasan/generic.c:576
 poison_slab_object mm/kasan/common.c:247 [inline]
 __kasan_slab_free+0x62/0x70 mm/kasan/common.c:264
 kasan_slab_free include/linux/kasan.h:233 [inline]
 slab_free_hook mm/slub.c:2398 [inline]
 slab_free mm/slub.c:4656 [inline]
 kfree+0x193/0x440 mm/slub.c:4855
<<<--- MISSED calls here --->>>
 process_one_work kernel/workqueue.c:3238 [inline]
 process_scheduled_works+0xade/0x17a0 kernel/workqueue.c:3319
 worker_thread+0x8a0/0xda0 kernel/workqueue.c:3400
 kthread+0x711/0x8a0 kernel/kthread.c:464
 ret_from_fork+0x4e/0x80 arch/x86/kernel/process.c:153
 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:245

Two additional calls we want to see here are:
batadv_forw_packet_free net/batman-adv/send.c
batadv_send_outstanding_bcast_packet net/batman-adv/send.c

See
https://groups.google.com/g/syzkaller-upstream-moderation/c/ZBKf99ttDiM/m/MdYkOYYVEgAJ
for details.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-220167-199747%40https.bugzilla.kernel.org/.
