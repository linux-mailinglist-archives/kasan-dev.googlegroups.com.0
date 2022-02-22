Return-Path: <kasan-dev+bncBAABB55B2WIAMGQEYKP7VPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id E70344C0389
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 22:09:12 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id n4-20020a17090ade8400b001b8bb511c3bsf415893pjv.7
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 13:09:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645564151; cv=pass;
        d=google.com; s=arc-20160816;
        b=g2euTWDEJH+zoIRVaD0PjSOKX2Hs9o/Iyp8XJEnVdvh+BNWgplPcezJRd2WZ64DhUp
         mXEJWaLd51wB3Fo3q1V7iax5yvMTg8o/LvHu80O7mqLjBeY1bfa+vVtaiDLpicT+3X7g
         dEu8tlN9/d/v03ML47oV2QNO+PzkRE1IkV7Ot5oAZA324Bb+Q7Ct8aybQOBR26wyUOr/
         I2NbfiqhKK5ueWEuYkyIFXBgeCrNK2MixQFAdaHOVJ+D8XEfUZdly/Ym09xBpXWGen//
         EWZq1x9qj3uXqLKBGgLcckvT9K1g55qytXrsIyq7Jo2kieFy3HQs6NfwwGxC+moCbwpm
         S0dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=+BX6trb2q/LzmusY7GFDsOw/pbzKLkenTc1663jwoZk=;
        b=z9yIbTWbIoly0Rp52QP8HMqbRi44vzdQORlrtkTXnvaDwFgGs33juzs3cEeuwtrUfx
         7eyn1NpM9XZRWAUKNehCZJ/BPJQg4ATKquQ1p6iJatNiEUlHXeixkydVi32jh2RA2g70
         susNtLSS0+5KrxYdr5jktmakjMliXMgvzdZIIdbp3GN5xAmttFZj0wqbPkCxfvFfH4J9
         ox+c5KzOrroJhSNDlDVTXXMZenE0x/Lh65G0c150WfHD9yc5QaSvLHIdRxpcG/2yVGNx
         KHeFXuIezqp/zhqsoR2K81n3L5JmJrBykAA7j2TYqPZCf8UNtcgeMeHh+dtB9NdRZtQ3
         CmkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=vIvZbQKQ;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+BX6trb2q/LzmusY7GFDsOw/pbzKLkenTc1663jwoZk=;
        b=PltJ3lUIuUHSStOGmE6J1wkGqJ9QQ1ijKqwV7HtqxzQyLWrFlE9gEQzIjNXs2d8+mS
         twZRmr86uPhyczpT3+txyWqfyR2P0Z82qxEZXQgLKfmAYkA3d4bgBeEpAewkuRVxQ1gU
         v0/+N6GIHlCGx/Q16sNp6c9Eb2pDcZScnLuRSE/Siy+myk0iIQXJbtcxeOKItWeGZlgt
         WzTAwGzUWwS5dCCKwj8SZqbfjZuOZgUF4q2MxXp4mCsIsWdu8oK1jKM0HER/tsElwXZK
         ym5bVOMjf9nSnXLzPsZ2uzAZOITGFQ+huLcqSQ5NfFJjutb5stykg6p5cgcvr+tcrDBE
         AIPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+BX6trb2q/LzmusY7GFDsOw/pbzKLkenTc1663jwoZk=;
        b=yJi4sKMoZ/YkBZwlawDCv8Hwzfv2VJgX+Z1v2vl8IEqz2ccvxzxNU3yaSPFeJ85oxB
         iEVU+0JZ3KoQti5rZYjR8WkmxtFZe5hFUEs8qXQRzBd6wwpgUOStqNa6skPwZwhE+NLa
         xxyj1WYR1k9aQIDZ9h3bl3URvxjkbLPzyviVAjbWJWVrkBXnCB2rl2d9sBi5gZWxPWxs
         zBhwwqRFh6sm2mUs60rmmgMACASi3bHhpoi7hcWgM/ppFbk8shH7WIfRqECh2by2I8pg
         NVEhAkMw9iFM2K9l1fMSMD0F1BJaRmZtG66w8QRJp0hRTz8StG1hDxZFuZvC3uuBQYOD
         yrsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5305s/PQBXRo/ztfBZvo3kjz2OhhkOoVTBFEkMDg3rskbXGKBrdS
	oYBP4woGtmJBtuzCzTi/9rg=
X-Google-Smtp-Source: ABdhPJzMMycYKKVzGFvlW8ioeUPeFN8f3fCNk6QRz2lOqdTzsUA7aFZ6TFiKRGO+uPFlJhnx5Bx5gQ==
X-Received: by 2002:a63:be0c:0:b0:373:9f38:928e with SMTP id l12-20020a63be0c000000b003739f38928emr21031329pgf.241.1645564151445;
        Tue, 22 Feb 2022 13:09:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4189:0:b0:373:4c33:1291 with SMTP id a9-20020a654189000000b003734c331291ls6096128pgq.3.gmail;
 Tue, 22 Feb 2022 13:09:11 -0800 (PST)
X-Received: by 2002:a05:6a00:2cd:b0:4e1:1989:5b7f with SMTP id b13-20020a056a0002cd00b004e119895b7fmr26198973pft.3.1645564150923;
        Tue, 22 Feb 2022 13:09:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645564150; cv=none;
        d=google.com; s=arc-20160816;
        b=Q3JQAhno4G6xxQfiHUe4EqmbdYnhQO8uJTZgNDoP++vFdFphHlgsCnJ0etRfGYUM3K
         CB3JICoXX7+KLA3UcwCDhBiB6sJn08ucXPdAw7BGHLlZ4gKA+N8WxO877bKZTlwCH13u
         abNn5H/Kg7RVAq7U8E7CI7ZxQX3mp7MtkuiEZbBC7ApVy29FeYnA55+7Xcx71jYspxEV
         9ffFCth5OPq6dqu8fnomDAe4yrYETG0I4QtytBVDIbSuqlXcc6mJ6JNWqJqtn3wuOWRm
         cTwQDNG+1A4svuqQKNwGtslO6WLahH6OJgcveL+Yen38lI5JIzXm+CpeeRZ8wUeSyTFa
         btUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=3EofFeeAaC4YazKYk40LL0J9kk0MXPNz5zFq5udZKYA=;
        b=VJP3c1KUsdlwd/KoFGYe2G80ha/IZvhjp8wu4p9vt0wJEVKbY6N6wW78+THvgsbRca
         F1ID7ya/saRNS1/J+BduPvOUWX5obgdfVasxNZ0JZLUf7ooTsk/F2/f1CV2XFa00tP/6
         ySBW/upw8arNnYYmWNH7RfvxcdgiZN3cQZh2bpHgteA75MaqCIlcgX5InUcsH0+DcSYZ
         n6NgZkn/83ZA6jrtMpwbwh/sCyppCcM2InCXzqGehVZqHkq8u7CNjIdNtPYT14PJEje1
         WkT7h9VRDO2F7QpNjf2ML+llk+XRfzvztPgEmMHlV8+aCFMob7zXzxsty5y67XCTRFVh
         cY8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=vIvZbQKQ;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id e14si1066423pgm.2.2022.02.22.13.09.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 22 Feb 2022 13:09:10 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4F8B961742
	for <kasan-dev@googlegroups.com>; Tue, 22 Feb 2022 21:09:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id AFDB6C340F1
	for <kasan-dev@googlegroups.com>; Tue, 22 Feb 2022 21:09:09 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 91A0CC05FD4; Tue, 22 Feb 2022 21:09:09 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212199] KASAN (hw-tags): fully disable tag checking on the
 first tag fault
Date: Tue, 22 Feb 2022 21:09:09 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: INVALID
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-212199-199747-rvajS8Bowp@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212199-199747@https.bugzilla.kernel.org/>
References: <bug-212199-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=vIvZbQKQ;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212199

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |INVALID

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
Even though MTE tag checking gets auto-disabled on the first sync fault,
assigning tags to pointers and memory still keeps happening. Thus, a
kasan_byte_accessible() check only fails when a memory corruption is about to
happen. And it does not make sense to ignore that.

(It might make sense to not print the report in this case, but this is
addressed by another issue:
https://bugzilla.kernel.org/show_bug.cgi?id=212211.)

Closing the bug as Invalid.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212199-199747-rvajS8Bowp%40https.bugzilla.kernel.org/.
