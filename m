Return-Path: <kasan-dev+bncBC24VNFHTMIBB4WGT2BAMGQE53VHHTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 65BB5332C26
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 17:33:56 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id oc10sf2512980pjb.8
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 08:33:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615307635; cv=pass;
        d=google.com; s=arc-20160816;
        b=mviOH3OlF+uStchVsGS7PMcNyM6ap5rj1GyyomCLaIUa3x7edKDheK1ZWdSkfrGLz4
         XaGWhTZlkwNsHTkt/yWoovy5OGL8wkjHbxdMGG7CXIc5McP/OxaTFsP6rBVqVU2mNe2J
         y4gtrcghu2UyrdN71ym/9FSRPJG9apWIV8Q5X5gX1Nw3m7gqpXUcl35ooW2AfJeXhiG8
         LkzDFigyxj/bZQJfdn1IpxCPRccBZq+LixEFu0xFsNoWTqThFzj+QJiDJIOM/mObrTaQ
         IdXHI8CpnJQSMBnV1eW7NBdV0918JtHvHgNrGOkwhkxHqKFbbc98N8wv70FqIPfhGB0J
         X1JA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=r9u42hUdmxFnTzfy6Sc6nXnwQKmhYI02WQgReCDlfdk=;
        b=m188gM/CVLRqi2J819yFzElAvSVGZBbNic6VC2HjqZyf1J3FWZ6Zp69MO0imjvkK6/
         SutKrIoh2XTGKwMnDvpuwj/W0BekRYtxgKvy7oNgCDen1TIQPzgHkN3jYNsYBJLTbgLA
         MCUXRvzICP7oRxLqvgpG8cwR5CXQ0mNVqzO9MCp/JTLnzHkXe+CT1QMPG8xClPXrprqz
         wsmeMxhBFM3gti5DHsKYVWmjEqSu21W2Cn7/nFe6jSiZnD+Es0R9zYcnUD9ONAm/eTub
         +LSUqe93dL7maiLURE2Efi8dOe7OupzdTNk8bUuCjTxMRJous3Any7yek4BiJq3hBT5T
         YbHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Z4FWkcZd;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r9u42hUdmxFnTzfy6Sc6nXnwQKmhYI02WQgReCDlfdk=;
        b=eIxVhbgATV6qvge5MoFa1SNJJvcpJ3FTGGRbxxqcEgcECQupwrqKn4xeKk9azWbJuE
         OP7wJ04z6oiPJSfsEz/ha8b/4Q2OBF+eJ5LLXlJnRTH4urrFGrvFjtOdoQCAqIQD5GES
         GYduSDbsaE//rnE+H6a0B3x1Y5o6m9j0+aTtgG57Lbm1mpflIGORUiFAv+8MpNzUHXO3
         wCkrXwR9F0KagMHS+jhg2l1gUAb39xZPCDq0lwDKxkI7pdeFeb3cTtyFVE8LTARc9UW1
         4Bym2jaZNYpwCjorluUcGRAt0/smLjyQNLhbM7E1q91A8661ajUowhe14xqe5/wyeS91
         EN+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r9u42hUdmxFnTzfy6Sc6nXnwQKmhYI02WQgReCDlfdk=;
        b=Pa5Ar1wc2M5d+KOuzKeW2qoLGLQd1fordhwtNUiit/8GKighT5WjANtkZsei4VDBkh
         D86YWiX+BG7QEUHT6EDt7QAfn8k7Mty6sXIjRj3LTXtiiqrkAo2PvyRV2a/1WekvJGnE
         UHcEWSgqQ5xkqkdNxChGycwhxcMVH6kwBAzF0SxhN519HN1wfP3yQQgQYKm+OjlBjbbF
         uS4RCrXGe83DEn0K0+Kx2sgrM/S5jGyvIUbGttCO5b5qgfYye70qMQjmqJZjP7OoNxmO
         lxzKS5+kAu3/oBLmz1dgzKNrXq+P+BKHOew/f4Uij6U8+V8FTE8x5zttfh3sqbMsX4TF
         I12w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533CxWX0v5celL98cdPFTulkS7PermNT60/SHR4aW01GZC/xCl3x
	h64059jALVeneAf1SYMvhEY=
X-Google-Smtp-Source: ABdhPJxGuOToNSQzw/8k6I8l1k6FPpO0qEMB46pLz3rGLT2kWApDcXhcrmSxlZ5Z2l4vD2xdqTuwAg==
X-Received: by 2002:a63:4956:: with SMTP id y22mr26236108pgk.309.1615307635149;
        Tue, 09 Mar 2021 08:33:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1417:: with SMTP id 23ls4078828pfu.9.gmail; Tue, 09 Mar
 2021 08:33:54 -0800 (PST)
X-Received: by 2002:a62:187:0:b029:1da:e323:a96b with SMTP id 129-20020a6201870000b02901dae323a96bmr26994436pfb.28.1615307634438;
        Tue, 09 Mar 2021 08:33:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615307634; cv=none;
        d=google.com; s=arc-20160816;
        b=x5Hi6RqTlwudVNf13a98E157z2fjgwdczT9N6jZbBbRj2hf4Quw8lpVJvygKhL1LoF
         lLgxD4riTIRP+4gIWd4tNRMqncY9PP0VKE/uNZnQdVHCqK9BPc2U8Ag6NPhqIUvAz+yX
         4HXwzrOOWOQmX6pcZtCLzrshPqg15jkSwT0xn8EBcWVSFU2X8XySPDESKzmsqHBLJqLQ
         E89YKUEBg7oGaN+OJLe9rfN7o7t5Hf6upALlBmsuLC1Y2OA4IZ+t1Rrv6OVGdtLdhmvQ
         zNfNsJ7SUANmLMfqiL1Kjyygox0Xo52QY5UMaMfRUZiYc2u7rKTNJiLwakbQetYXm/fv
         GvJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=s61THEdTzxFpUADuGYVk2ARNQBGdpP4fVGT7Vfk9MyI=;
        b=p8vRDMTxvaCBc6iUE3fl7Vvpdu3ZaVRwtz90SSDEV118RvLYFj7xLFlQ6JIiqeWp92
         7somMAxmJY0zGq65Ylx3qMjh4fEqxCWX8wIeFvGXj2mBJTi/vSJud9CsYA8W0egclWqr
         Hxbqz7/uRixQHg7U2DJLXvFjYxu6rIb6InI9rljksXJSynhWXmhcBwzgAy3eLlSqDIa3
         LAiYIFgppxLJ+glG5PRqztq/0pMi0LIV8Qx3hQQxHX/z15aGetnky1gC3wHcaKU8H6uX
         aMSwbeuP+v2c+H0IAtQv+Sxr1eBgM/QYmQ13IQlJzsz6pdoNE3ILwFtU7UgoKC68aeqo
         SLqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Z4FWkcZd;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 145si162397pfb.0.2021.03.09.08.33.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 08:33:54 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 1B83A64F35
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 16:33:54 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 09DA765368; Tue,  9 Mar 2021 16:33:54 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212203] New: KASAN: use console tracepoints for tests
Date: Tue, 09 Mar 2021 16:33:53 +0000
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
Message-ID: <bug-212203-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Z4FWkcZd;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212203

            Bug ID: 212203
           Summary: KASAN: use console tracepoints for tests
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

Currently, KASAN-KUnit tests check a per-task flag set in KASAN bug reporting
routines to make sure that KASAN can detect bugs as expected. Instead, KASAN
could use console tracepoints like KFENCE/KCSAN do.

This will allow to port more tests to KUnit, like ones that trigger a KASAN bug
report in a different task (see kasan_rcu_uaf test in lib/test_kasan_module.c).

This will also allow to be perform more checks on the content of reports.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212203-199747%40https.bugzilla.kernel.org/.
