Return-Path: <kasan-dev+bncBAABBC4K4GMAMGQEDBP5KPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 793015AFD3B
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 09:15:24 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id f10-20020a2e9e8a000000b00261af150cf0sf4219051ljk.13
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 00:15:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662534924; cv=pass;
        d=google.com; s=arc-20160816;
        b=i5Ycm3QF/rK2zkYgSfZj8MYcTe+OV96N5t6YdkS/KXwLIlCDfjoz4cynnQX263I+or
         lFL8JULlaBJyyxSc5IrEX1k0+3XIj5OR08vN534A8Bsh35KEsWxJ4qdR1R7x8WCtXOFQ
         +fzJHpvMFdSJVNrS/zH2D7gXEBM/0HD0kyOxnV8LgSB/xrLClZBfwAna2cEsFRnlBOlR
         cTgCGvFcEJNPWRG0uuQF1ssAhbY9Rp1FmhP/vo2R1IHe1ttb8YKjLtq4kZs62dYdbR2n
         GB6U2h/5T2fJnGXVrlkHOYfz9J0xj80cCPYrpdxR0pd46V83Ip9XOySsAzGkAv/DVcR3
         az0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=O3rBYJDeFIgodVgOKT3gzx65lJNGYVgBZALSyMxiJdo=;
        b=dsWx+72ok9N/5pQ5Mp7JbeTia6W8r9JRjtZ6f9l3gq8hv10Sj+I+5V6nTcDHBm8SYz
         YZJMZXU5Ib4nkj8GW2RKWxAmTfHy6RPzHoMKbWw3j/BE09bj4hAvr01wndEeVOgPSrWj
         uBkhzLkhkqZRGYH01EtC7Ejjuqhc9FD9wxysYUbQVoFjZI4KGYBWP0f93mqfbwm6Nk6A
         E8LPGuQKxDd8heykLFdrq49+hBXjNsgZPKfWHsS2PHihMT5i4eLTrrf+Yll/Htd+Kja3
         e9yH/yfGKa9gFvwX3wBrqlXdLqaX+zU/mLDkSjJQ8slOKAKoPN00Eys9Tn8W38rO9FdZ
         grmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=enfSi0x7;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date;
        bh=O3rBYJDeFIgodVgOKT3gzx65lJNGYVgBZALSyMxiJdo=;
        b=BCdvVDL1Z/l6tpDV28msdhbGWbER14p5FrhuN/NPAfqA4+SJIyYaZ+HWXLYHMXIKep
         MgqB1+slO0bjbAEDQ6uJr7WueELl91OYG35zgEbNgWt7Renj3wYiRdx517zYgp6BH4Mw
         bQXN5hEcbXARzEFJeVfAPp0QPdk/+GhowCvoaiti8u5UHatBrCXWRLhAYB/ivtnl8ZVa
         ZTt59FZqmqDIDm5PfkG8XxYenYOSVuImjU2EnoaUi4OXdfB6hdcKjgTHsKj7Y2/0+QQo
         EA00NzAgdcMF3GQyJSizhOYzP35ALoKpTil88CYjFZ21/xGOt0fdzKcNJKzxIaijZgOX
         skhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-gm-message-state
         :sender:from:to:cc:subject:date;
        bh=O3rBYJDeFIgodVgOKT3gzx65lJNGYVgBZALSyMxiJdo=;
        b=Tv4i4baF5X0/mcbbGUFa+mqSV2Vt6BgxvQWNsapJOCbjlvqtjLaBub2//Kd43LU340
         KIHsWqjbh3idqroUuOoAf1iZ0UbwBJGev/jHaj07Ldq5kE0zsLStAEWljB5FMmcsGqmp
         vHnlGiWRIACaJkT2Ie5F7jauB0JYHTSM5hj8vYBJLb/HPJeGwXEMbin0PykW06xF0Aji
         7vglaCPI4DYMcAzAxbSljxefAJJpSF8Q5DCv/rP14iAuK81K5wu6YpMqeqn9mchkZcYY
         Kwbl+gBgvg29XSzYqm7loW+zeeyyKSPpupbsCQsfJbKHSEFjEfA+B1IolUF9b/gSBP+E
         khzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1vdYxzxGdV8AXF0IQEDp6zIHH02nciSgALHgGUXSBBRkT5vj7N
	iSIxE9JFnZTNyMC8ATqmc94=
X-Google-Smtp-Source: AA6agR7DgXkylHezkwuUxHK4Jn8+31o/r2ZzFdTNUFyhIpxYmcRzJ2KNWFFXz92CpKSxDrBB4qszYA==
X-Received: by 2002:a2e:8344:0:b0:263:8194:9a83 with SMTP id l4-20020a2e8344000000b0026381949a83mr576363ljh.368.1662534923754;
        Wed, 07 Sep 2022 00:15:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:57c9:0:b0:492:f1b2:ac20 with SMTP id k9-20020ac257c9000000b00492f1b2ac20ls2397512lfo.1.-pod-prod-gmail;
 Wed, 07 Sep 2022 00:15:22 -0700 (PDT)
X-Received: by 2002:a19:ad47:0:b0:494:846e:bf0a with SMTP id s7-20020a19ad47000000b00494846ebf0amr664966lfd.576.1662534922890;
        Wed, 07 Sep 2022 00:15:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662534922; cv=none;
        d=google.com; s=arc-20160816;
        b=W/z7aKpkl+mltG7VM1Yxx0cGOEaDpHf5Px1NsgHQOemqSungipJam/xdHY9eGLWNKL
         IaSIzWMU/ov9lxAMQPIzIl8Vqzm8zuNYMB1KgL6DFe+BoY7P03n/wU7qYI5HiDcDBs3n
         IginuOoiMuaHDOHQybBgyfb7y8WhrwQYn/vCMWYoNpS9aSZ/LssoLdAZ7pXiSdHrAIYa
         pc11c7l9rCL2KS+Ih8xxFhlIH1tkMEqUX3CXdlbsCm5bQuFZPdyd6XraWZJxIm+Goe7C
         1tbjztbAMXYhK78LkZ7R8rpZEm+LKkMBeNpHQ8+N0RIgmj+yMVNkXJPMNnVQ2l5kvBP0
         wQRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=obmK0yaWbR6J+LTwEGOqR9Qq74v/rSJnOyls9hET670=;
        b=0zNiVUbb+B69aza9ZDtioSCjcmVzq3BmNKazmvExZgFO7UxzaaiuAtWhfIFPghFzwp
         evAX3wbjnoEQ8+n8WB2VmPg9fE0kfVkrdstAa0KNQ/DNbcA/aXiZujbnEIQUl8Grv9z6
         FsaB0GQmsmzWGazcek3YXCGXwB5hPAvYBRnNg2yzt5xj6tjP9WfAkYYRMi4KN4hwDxin
         0d5YXgO/1N/vwqou0D6pB7XsNq9/1mNaSZrov2sPXVdZ4+uc5xdg3Oq+25Rg9NR9tl5b
         ByoC8TAH1fHRyFpGkBN2Ltl0a/ql6BYmOsti+JbKeC9rH0kaoorKz9ZZJBLpzNwHS2Te
         a0Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=enfSi0x7;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id k9-20020ac257c9000000b00492ce810d43si712049lfo.10.2022.09.07.00.15.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 Sep 2022 00:15:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 27EB2B81B82
	for <kasan-dev@googlegroups.com>; Wed,  7 Sep 2022 07:15:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id E4DB6C433D6
	for <kasan-dev@googlegroups.com>; Wed,  7 Sep 2022 07:15:20 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id C9AEDC433E6; Wed,  7 Sep 2022 07:15:20 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216457] New: KASAN: confusing object size description for OOB
 bugs
Date: Wed, 07 Sep 2022 07:15:20 +0000
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
Message-ID: <bug-216457-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=enfSi0x7;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=216457

            Bug ID: 216457
           Summary: KASAN: confusing object size description for OOB bugs
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

KASAN says:

==================================================================
BUG: KASAN: slab-out-of-bounds in _find_next_bit+0x143/0x160 lib/find_bit.c:109
Read of size 8 at addr ffff8880175766b8 by task kworker/1:1/26
...
The buggy address belongs to the object at ffff888017576600
 which belongs to the cache kmalloc-192 of size 192
The buggy address is located 184 bytes inside of
 192-byte region [ffff888017576600, ffff8880175766c0)
...
Memory state around the buggy address:
>ffff888017576680: 00 00 00 00 00 00 00 fc fc fc fc fc fc fc fc fc
                                        ^
==================================================================

This "address is located 184 bytes inside of 192-byte region" is confusing b/c
it does not look like an out-of-bounds access.

What happens here is that the allocation request was for 184 bytes, so the last
8 bytes in the 192-byte slab are poisoned. But KASAN does not store the
requested size in the object header, so it just prints the full slab size
everywhere.

User-space ASAN does store 48-bit requested size in the header. But KASAN uses
additional bytes in the header for:

struct kasan_alloc_meta {
        depot_stack_handle_t aux_stack[2];

So we don't have space for requested size w/o increasing header size (currently
should be 16 bytes).

We could either try to infer requested size from the shadow (count poisoned
bytes at the end); or improve wording of the message at least to make it clear
that 192 is just full slab size.

For context see:
https://lore.kernel.org/all/20220906173154.6f2664c8fc6b83470c5dfea1@linux-foundation.org/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216457-199747%40https.bugzilla.kernel.org/.
