Return-Path: <kasan-dev+bncBAABBZN6UKOAMGQE6JXW7OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id CC5B863F0A5
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Dec 2022 13:34:46 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id h13-20020a05620a244d00b006fb713618b8sf5627687qkn.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Dec 2022 04:34:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669898085; cv=pass;
        d=google.com; s=arc-20160816;
        b=1AErjw+2X/oKnqlfjwbjtQhgmApS2OEdAlUgeU6GHoH8UgPHxW0SRIZ2E1ZZ/FLcOR
         WNoWpxSXBZkdC/5PeUEG06eLE4q+IuYPB73IYTwfsJsaDvHQ4j+5N26BSebkhFpFK0Z6
         AWBY6MECy0U50ZNnhu0qM0vfCL4o7KkzpjVDH5u5K53IhDmpFJQ0Kg45ysxFFPfhTCrP
         nITA+iP8DLed6b0glTQlV68KLW/P9LzYAlIjqs/DWZlowxOrH0RZoz7JjB7Ib4ESORjS
         vl19uiF2T2DUJUaEamoX58Q6axTlAtX14IItR8yettavJC0tchUHoLONyrbCyYGcORI2
         ihfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=Seh0hPTN/9OOZYzSH760iIgNdX+cag+wOY+vfWEc57o=;
        b=1F5PQBsqJICf9DIPzVPIPMdeI1hD7qBAD5+OtAAhWOHc6HpALW9UV+Hiu0p50lXWm7
         szQzldcI+TDxxqJtBUwroCLv+EJtRBE0GUkTEkhRbfURcgddhZm6JDcjbyupKO7wDhtU
         9UnvNdJXvNStxPkJfoY2qFDGefO2lDb0qlwnF09WoaTEsPs8yYjcODXrCwPm4gsjbxl/
         uLrBsT7gJq3ZxHNNtt/MNPgSPKUe7xem4DxoLv9kxfyBwMcY/jxROXZBhPiXQ/D4pMGO
         ofHqSH1wHUhUj9YOuYYcWGIJ/AnhJOlOXoXVdYLVj/Pgpuad6hXmOaXlaAdAreuzZUcu
         EqWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=vH1ljwZU;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Seh0hPTN/9OOZYzSH760iIgNdX+cag+wOY+vfWEc57o=;
        b=OlGyEpTsnrxBVjBOhypzx+2ClPMtAGP9rT6Z5/yjLthCZDTur+bc7Ospv/8QtOHzB6
         DzModJtPpfxPbNDBAFr9kkEHHioqMOldH5v7VCOcpKyUWdlhF4nBC5o9sr/+QI5hOOyZ
         P2nQ5AVUKq2f95XiW5n5kw73jIS8fB2d2zCWHj3HvpBe0HZzsKZLsuWuh14GTfYiuO3Z
         1WQgCUBfo56qmg2yGPvZ8k4P/OdvyLtXNczI1CUXHmYY+tGqSFe2CNRCpTchIequxw53
         UPcWJhi0aq3zPlON76nGgd+NaOrTHigBtbtoj2H7SQU7lAQSRefmCOxGVgom1DlVA8XZ
         ycZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Seh0hPTN/9OOZYzSH760iIgNdX+cag+wOY+vfWEc57o=;
        b=K2exknmrlYHVNw4UY4O9aif1CCygE5qMHJWCSoUo05rHfg+W87XwQadUN4XpxpP6Gl
         1FmAEHH15n1jcAP1FpEBKCA4JQBK+gi8fF2e9IIoEitu4UVlFaEhmafAzzydY+rdaF/Z
         AnUhG9buUszefRG1lAuaFgTLtZ1f93Z1GmCcW0Axu8ekRrVHsgoDbG+KbFUjXog+7nKP
         u3lfr2auO9HQX3XxZ8uZUsAM3xxbti1SbRwQTjNsytWcopmxSl2wVHit7yYIdHazBQcW
         dXbt2+Fx7UDl3jjH5fIkUQN0tRdMoERTU7Kw5t0wNFUK2sLdd7j9p+dE+R0aM8Ctm0Di
         tw2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pn/L5ekjZ7wfa47acY4E1DMiyvZPGpZfr1ADS8WpNri/5qKc0PY
	jbhhuUgyvc9ryIdbnMudi7o=
X-Google-Smtp-Source: AA0mqf6f3/X/zJUSa7nrbMc0fAWfvJwwa4Ijs/kAHHWrwbMiV6yjL8nxkvMYLUdMAi1IslBRqQbyZw==
X-Received: by 2002:a05:620a:811:b0:6fa:1185:4e11 with SMTP id s17-20020a05620a081100b006fa11854e11mr58554223qks.395.1669898085575;
        Thu, 01 Dec 2022 04:34:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4a03:0:b0:3a6:7278:b9a with SMTP id x3-20020ac84a03000000b003a672780b9als1159072qtq.4.-pod-prod-gmail;
 Thu, 01 Dec 2022 04:34:45 -0800 (PST)
X-Received: by 2002:ac8:6c3:0:b0:397:19ab:699f with SMTP id j3-20020ac806c3000000b0039719ab699fmr45411592qth.177.1669898085107;
        Thu, 01 Dec 2022 04:34:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669898085; cv=none;
        d=google.com; s=arc-20160816;
        b=w0qCeboLS7RUa8YXvbzLAbto8FckDw7zAIJFRiaExURLcOVRKhDnxU0LJ8Lkl5ihpK
         RmfC5rnKl+hXOLOZ576kuTxVY8F7Ja+1ai5QcU9us/x8whVEhzt0iw68ONnwKz2wY0/1
         xTxRoVsbjhL1ThZGwPD55pJ2GS+iaMxzxVjMV4Pxl55XD9+p3gC9/yOkNJDU9iN8vumW
         QYzrvdRxRwzzloEEgddZ0KUiWUzn6nkZ70l58ZGR8QJ0IIgdKxxtyga8+tlP4o0WZ9yz
         OhVlesDXw9VNGoZxdGVnCE666HhXzkH/QYFioFqDO3EiT53YD3QF/B9+Fs1ifxEEfwWB
         Enzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=rJXRGqO33D3b2dmEIiGlseMyit/gdzNf+P8QDvbBEmI=;
        b=A40qNHhA1M2kHoZ0A909h6YroSVp8KeqPrbHmJyIFJurd5x4QQGRAm+DLCWihTpx+3
         p18jHEiD1UtwOLR/E5Phv0Yc5YngbkHYswAMwAu7/nV5c8kVRqzSXzWYAzrmpxtAP+H2
         5POzPy/ivQo+i2YCl1aohjk4LlPEsMFB8jk7F4N7lfEZltpYBFMtYX5AqrEjVijrfsxW
         EMT7quvE7PtPzXnCo8vW8JXIjjIAoS3BqCPROb3MNcWP/KdtFxIHeOQVKTShY1AHUQV2
         wmjgWp3zYMGpo1WMt2L6zXddb1hARkEv95KG8MInoOrA7Fx2yyf683lsm1zYcwlhUEEW
         DxtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=vH1ljwZU;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id a20-20020ac84d94000000b003a528515a76si150793qtw.0.2022.12.01.04.34.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Dec 2022 04:34:45 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 8909DCE1CE5
	for <kasan-dev@googlegroups.com>; Thu,  1 Dec 2022 12:34:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id B8744C433D6
	for <kasan-dev@googlegroups.com>; Thu,  1 Dec 2022 12:34:40 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 8C9F4C433E4; Thu,  1 Dec 2022 12:34:40 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216761] New: KASAN: confusing report for page OOB
Date: Thu, 01 Dec 2022 12:34:39 +0000
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
Message-ID: <bug-216761-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=vH1ljwZU;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as
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

https://bugzilla.kernel.org/show_bug.cgi?id=216761

            Bug ID: 216761
           Summary: KASAN: confusing report for page OOB
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

There is a number of confusing reports related to page allocations.
Here is one. I think it's an OOB, but it's reported as UAF and potentially with
wrong free stack.

https://lore.kernel.org/all/000000000000e3af1a05eec2e287@google.com/
https://syzkaller.appspot.com/bug?extid=55b82aea13452e3d128f

==================================================================
BUG: KASAN: use-after-free in leaf_paste_in_buffer+0x739/0xca0
Read of size 80 at addr ffff88806fa50fe0 by task syz-executor881/3646

Call Trace:
 <TASK>
 dump_stack_lvl+0x1b1/0x28e lib/dump_stack.c:106
 print_address_description+0x74/0x340 mm/kasan/report.c:284
 print_report+0x107/0x1f0 mm/kasan/report.c:395
 kasan_report+0xcd/0x100 mm/kasan/report.c:495
 kasan_check_range+0x2a7/0x2e0 mm/kasan/generic.c:189
 memcpy+0x25/0x60 mm/kasan/shadow.c:65
 leaf_paste_in_buffer+0x739/0xca0

The buggy address belongs to the physical page:
 prep_new_page mm/page_alloc.c:2539 [inline]
 get_page_from_freelist+0x742/0x7c0 mm/page_alloc.c:4291
 __alloc_pages+0x259/0x560 mm/page_alloc.c:5558
 folio_alloc+0x1a/0x50 mm/mempolicy.c:2295
 filemap_alloc_folio+0x7e/0x1c0 mm/filemap.c:971
 __filemap_get_folio+0x898/0x1260 mm/filemap.c:1965
...

Memory state around the buggy address:
 ffff88806fa50f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 ffff88806fa50f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>ffff88806fa51000: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
                   ^
 ffff88806fa51080: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
 ffff88806fa51100: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
==================================================================


I think the root cause is that we assume all objects have redzones (mostly true
for slab allocations, but not true for page allocations). For objects w/o
redzones difference between info->access_addr and info->first_bad_addr is
critical, they belong to different objects.
It seems that we print "UAF" based on metainfo from the second object
(first_bad_addr), but print the rest of the info for the first object
(access_addr).

Here we find first_bad_addr:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/kasan/report.c?id=04aa64375f48a5d430b5550d9271f8428883e550#n408

but when printing object info we use access_addr:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/kasan/report.c?id=04aa64375f48a5d430b5550d9271f8428883e550#n395

Since we crossed page boundary, I think this is actually OOB, the second page
just happened to be freed, and we did not even print the free stack of that
second page.
For an unprepared user this may look like nonsense report.
I think we should check if first/bad addresses belong to different objects and
report such case better.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216761-199747%40https.bugzilla.kernel.org/.
