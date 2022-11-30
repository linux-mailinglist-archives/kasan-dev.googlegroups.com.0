Return-Path: <kasan-dev+bncBAABBUVGTSOAMGQE7ZL3HMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1853263D070
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 09:24:52 +0100 (CET)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-3ceb4c331fasf48364527b3.2
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 00:24:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669796691; cv=pass;
        d=google.com; s=arc-20160816;
        b=qxe6jxqoqdhUJpkM+U2zrA+hnejVG/EbTbbpa21uNwRVhaakjJbF8nwX12ztT4VAG3
         /QIWVvSLSq9vcHyAxo4ukb3NKWpmv6SWUtNYjXnuU6RFoeLCYsl6JRujjp5GPr8qDcrr
         EDZQyD/IDPOqBH8bLZbBdvFFtgOjWLMi2WUUFKZ029wF/O5pOs8eI3GU/05OszFyWoOq
         QigWMe3zXeG6Wo9f12uTcBpibmSxzly1VN4jlpsRzT+HZ9wjOL6daK0J+NBBQVuRuQ+W
         i3WHXqJb5cfPiFzh67j6que+LRb75eO3YGQ+ZGEVItwUEkLC6J2IIhnyP0c1uMUt9eAE
         X4IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=Y+koOG44Zet/Yz3t0FJixUj8f2r9fRpQeLe0O3e9pJk=;
        b=HYkjy3huRucU7W4lBSi0swHOtC6n+RYuUcYxTZLYEwcYHxX3vQMdY2hbtiaPgc+vxH
         9qeMjG9P7z6E4Diq9GVXdUpaowZPLxY5rGhXeIbNWLjHzxo5dA5tOiBOK3LtSyL9UcfU
         jJomLiPsWLS88VqZzTf7H72fd78ouB5aXFxIZLMTvpw2sMnex1BaSowVD05KmnM/0w4x
         6uL9+oGM1cQ8y6uIYogNnsVm7wFMnPyul6diPxTovKEzaxUfPCB0ygU42qO72SHFTq9Y
         srnB1j0daCZ2ixog7ZBPt9aeQfPLGFfoUGljNRDIHZmmz4hrpNMIfL0I0UVfsC7jebxD
         vJIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Urh5f2Ky;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y+koOG44Zet/Yz3t0FJixUj8f2r9fRpQeLe0O3e9pJk=;
        b=QXArn8jK2zFlc5OM6K5UVWN/CGU5RipAjdugoCCWn0qSwnTnKLj9m/rAMVXC9jCZj4
         2GDIRN0/lQX6BiSCY3geVK7svnqqxp42JOLz9wrC9pcwWp+HHkLkMxr3kUyLCOw8WnDS
         nx4ozknp4Qavuu70S4QpVNYYDpcrzLlMufSXObHt17fGQiStykpB/raN0Ws7DA8iPQOv
         2peB6LkILs1vakOduUUCeSDQPkRhPfMk2qQDo15Ooo4v7fmacRvvFkZ9pj+W4ADGczbX
         Zs2ExMWkyOCqgzPB/2fmuu+U5Um5bfQcSmU2VZ4Z1ghYdZqHLKMdutnrw76d11fFS0W5
         D1qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y+koOG44Zet/Yz3t0FJixUj8f2r9fRpQeLe0O3e9pJk=;
        b=d94nI615u+HStuRpbqnVxZtqNXN8vLIEZ7RelxL0Jv3w+4KFM9CD3ebM409OZd7e7x
         iVVaeEHaF4EpPKxaCuy1Cqv+Fqi6VXHoAiaSLe6jmbkyCvgzTBnpeeT7FMWhtxBwEPKy
         0f28Oqpb98SOdX+/T5f3Q/PUdxh/7ht4qH8nkXOM6rfYefTqpcdmAuMx1oYAHQ2EUmWK
         0BO02cB46Ec1UMfunCiW1ko5chBkHBa1P9jBoua7vX9bMEGmD7Oeg26Wv4xQudcYgsn/
         QwcvFZHjqWqo4pSufCx8r8QgwEdVnl5NjON1AtXEp9UKmtaiAKpWUpsbvpCQ0SYcbrCP
         AqNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnDOqkDfPrQBCqWUiDt3A1zlZsnncPkkkoLZHjAzFqlmX156ldt
	8VoYJRMnjPPgOqJ9uTspLgw=
X-Google-Smtp-Source: AA0mqf42jYN0b+iWpxgRX5UuVuKTbC+teGTgLjQFBF8t/LFOq6fqK6pJBIzcWtTcLlgV/TM7VFtQRQ==
X-Received: by 2002:a0d:d491:0:b0:3cc:5892:fd07 with SMTP id w139-20020a0dd491000000b003cc5892fd07mr10239135ywd.420.1669796690887;
        Wed, 30 Nov 2022 00:24:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:c0b:b0:3c8:b520:2fde with SMTP id
 cl11-20020a05690c0c0b00b003c8b5202fdels3626550ywb.1.-pod-prod-gmail; Wed, 30
 Nov 2022 00:24:50 -0800 (PST)
X-Received: by 2002:a81:1a4c:0:b0:3cd:e53d:7bc9 with SMTP id a73-20020a811a4c000000b003cde53d7bc9mr8548528ywa.287.1669796690371;
        Wed, 30 Nov 2022 00:24:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669796690; cv=none;
        d=google.com; s=arc-20160816;
        b=qYlxpG5t2k082fUG/8CBNjqvIuY54H1si4aE1h9Fn7Chd/sA44udso433gdLD4SHWl
         PoYlldcWlK3oRScDS7BPHPu0ANHxFrPKGyNQldiDxTG73zyUNyowadq2XM9Nzd6phwbN
         sPeh45VluRajV1N6oCCBJvjrSig3ut34ZNFLOmTukz3f+ld2UP0Ee15iMjQ46FAqYGor
         GLjzJRI43A8gPgHcWxRO6d/t4l+4+Ojzt5OPPGRnd2X7AnOBAlhKv8T1L2P89w9kCx1S
         8NYVn4HaeMTHmJ2UjE59jXeM9B7puUw0X/l7NRKU2MYiTxWEvScsTs6wOWfyQUk/TOau
         O1Kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=+PIBG5cwj9CztGn0v66NeBwjyR0I5KBFP8K/GtecWeQ=;
        b=Y66Rpy9eBNlSrhz0OnUhu5n8GIZc4Y4QxIy6P5RjzW5XobVhg52p3aZksreYt3Ky3X
         robLpIZCwPG554hY8O5OXRl5oV1Qosn1UKbxctTHfep8SWL46lQIHMcuoCkysTHJMZnD
         m5TKslyEXrftk1F5NqNOGy8ANT0grORQMomrOHTYcNVvw0chv8dLiw3wGSz/Jjysvu8i
         dSurflKA33K69aVYnGDmVhVLIkLHrDkvbuTyIKBwMRNj4AxjwE432ph8PBXDqGcw64aE
         84gYDIPlmjLCFwQ8DPD/gJ0d17JwxkqazhZzCHIktLnucs2VAXNs4F6tFJ0SeU19qOkr
         Huuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Urh5f2Ky;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id bo13-20020a05690c058d00b003cb4ed85900si44268ywb.3.2022.11.30.00.24.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 30 Nov 2022 00:24:50 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id EBE8961A5F
	for <kasan-dev@googlegroups.com>; Wed, 30 Nov 2022 08:24:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 5D814C433C1
	for <kasan-dev@googlegroups.com>; Wed, 30 Nov 2022 08:24:49 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 43063C433E4; Wed, 30 Nov 2022 08:24:49 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216754] New: stackdepot: write-protect filled pages
Date: Wed, 30 Nov 2022 08:24:49 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-216754-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Urh5f2Ky;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=216754

            Bug ID: 216754
           Summary: stackdepot: write-protect filled pages
           Product: Memory Management
           Version: 2.5
    Kernel Version: ALL
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

We are seeing some crashes in stackdepot that suggest a previous silent memory
corruption:

general protection fault, probably for non-canonical address
0x1337b03f314bd700: 0000 [#1]
CPU: 0 PID: 2509 Comm: syz-executor.0 Not tainted 5.10.0-syzkaller #0
RIP: 0010:find_stack lib/stackdepot.c:208 [inline]
RIP: 0010:__stack_depot_save+0x189/0x4b0 lib/stackdepot.c:337
Call Trace:
stack_depot_save+0xe/0x10 lib/stackdepot.c:416
kasan_save_stack mm/kasan/common.c:50 [inline]
kasan_set_track mm/kasan/common.c:56 [inline]
__kasan_kmalloc+0x125/0x140 mm/kasan/common.c:461
kasan_slab_alloc+0xf/0x20 mm/kasan/common.c:469
slab_post_alloc_hook mm/slab.h:507 [inline]

To catch such silent corruptions and prevent confusing crashes, we could either
(1) write-protect all stackdepot pages and temporary unprotect them only when
adding new stacks, or (2) write-protect all completely filled stackdepot pages.
(2) is somewhat weaker but should be easier to implement and faster.

Suggested-by: Eric Dumazet

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216754-199747%40https.bugzilla.kernel.org/.
