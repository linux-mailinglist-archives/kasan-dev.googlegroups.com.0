Return-Path: <kasan-dev+bncBC24VNFHTMIBBXVQT2BAMGQEH2ZG3DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 434A8332AEB
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 16:46:40 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id p18sf2286841pjo.8
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 07:46:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615304799; cv=pass;
        d=google.com; s=arc-20160816;
        b=A1N5YyGY6Bw228YKpFY+VYT6ZbP+yCEDUOix67+HVf3P5LIXgkowXAZM1BIKRpqoaG
         EjCPaDf4IJrvaLOMQ4lkpsytpGxKNZuIe6R/MSzcPw+OXEtXKoTHUG6bbygCta9B6XgH
         0aT7JhSnrG+Avy1b8wBeOzo38Uoqnmwvbn+dGQU1fxqpYbHxxtBCFzlyGWwTFLkAPFUW
         4NGNj8xY41A5CsqwTPrs8PauUOY3vqE1Gd4kLUu4gDzN+tvoG3Chir73JUSBqFNqSzwd
         PcvnjetfQe5Hob2diJyQi8GC9coK0DYiBLvBBfvZZBEGJu7EmIGzvfRU3y4DNlT90nHi
         yjwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=QG97aufq3Peo64rp/ar6+Di0h+PLOf9Yp4MzSOr6i40=;
        b=Pr7vJJ8wy7KWggmAZxFIUR351HiJX6C4AKAjHsUOURZNEM9ITVZbR4vE9gZD0BLj9d
         xNuJisjBuDcUVDWE1bONYcic6SJmjW9WsAxF3+ZKVvhwLx8C1yPuL0FpBkQajnh+jA3S
         5rXL9qL9Gj4FGrtO/AsT51BESmAPoSBRq1kda/kFeUlwDQSGjq85RDF14+Pz+QqqdwUB
         bKu/7z2cioVWPMfSJRhqwpkjBIektjyjtdi6MbbUvYHprH2CGNw8+bJmY7INPeCAyEVt
         O00PiF37hdmmvHiHzpJw33Mw6J1zJ9bs3nnP5NtdXj8ZW2y5HMAVz5kg/hdhUjycj/nj
         OUtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bL7SRt7u;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QG97aufq3Peo64rp/ar6+Di0h+PLOf9Yp4MzSOr6i40=;
        b=pZhNq6rgcm0QkBNLCBQrKrTbhydUzqoxDm8OHl0fFQ5CK47Q2XCTb7WdcWcEwjou4g
         1dSuwrWheyEYuMKkZ+MCyw8STGHy7P6fMT5aBIYf5ol2E60uBxjJxYvlSCuGWMTSxJDY
         U4QKHdRLmYgfTmdalJfyg4YdVyg7HNF1kyVM0MnYWc2sEuU9s5tEtSlDASuo5A+02l4f
         Ja+V2Sp73AB1stJNkv9HxJbk5j/9yzWIb/lQWGd51E5vxHWMgV/6eSm7KOOLbMT58dCa
         43oLyIT28VeCutG58f5sqWyK5SKzCXTxWYTVrJ2j74gVBDoHgX8UvodypCD9SAEcquho
         up0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QG97aufq3Peo64rp/ar6+Di0h+PLOf9Yp4MzSOr6i40=;
        b=az5AeziggTz+mgtsMMnT6+0QyWIa9aDgwA28F4+Lg1twNg2MTDEKdNZivVzi+kc+K2
         3wg8eRT02m6neooTXAQQTsg7Bu6BD2wFySnuYFSXZUuCm4hfFttQecIAFzSQYevGKlAw
         3uLyPxavBl0w1vpvQjgDx3fyVyplZ1uJfKqyPbDKRhsqlAlXSVpfmcJ8LxDT+qTCNIDc
         nBE2/zQbAu8vf1xr0NWMD1/WRKL0yeN6TQmWJav5PRZnOkLm/LneXjkKnl3mnmk3jBvs
         aZ7Bf7Ubo5TfbGKFC02t8nEuH4QKTuG4cnEKqHcPKxIhY48QFCddigy++iudijjn5E6j
         mlFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5303hM9Tr75bgtGrGKH5m0zkF+Hutlp/HMvwpbp7EhuFtIhwQt1W
	GKt65HrAvljVCg/8c2CCq0k=
X-Google-Smtp-Source: ABdhPJxsKk6Cjio8qHj09UwnFRY7WBTBdkuTAyQ5V0131m359CC0qaW6vaqbiYnKkjIm/ibNsfOBJQ==
X-Received: by 2002:a62:aa0a:0:b029:1ef:fe5:b172 with SMTP id e10-20020a62aa0a0000b02901ef0fe5b172mr26130400pff.9.1615304798956;
        Tue, 09 Mar 2021 07:46:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1b43:: with SMTP id b3ls6667580pgm.11.gmail; Tue, 09 Mar
 2021 07:46:38 -0800 (PST)
X-Received: by 2002:aa7:8d8a:0:b029:1f8:aa27:7203 with SMTP id i10-20020aa78d8a0000b02901f8aa277203mr6518505pfr.64.1615304798427;
        Tue, 09 Mar 2021 07:46:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615304798; cv=none;
        d=google.com; s=arc-20160816;
        b=bCb8cAagF8ZK4Sz/XmwK1RGltug0J1mw4wz3Q7Fd9LbfpjiG+wIYchR8cqfwi1OeCJ
         fQplfWM24fFCyqRQ5y4Q30lj+rvnJ2pp5o5dK37ddTspo6vTItcpWX/k3ujqiaE21mUf
         YbKhR2FJfgJ6WzMRS2uYSwXCvi3iMDjkAv+zubjJRfPBcLElmfieHgA7R2sk3kZZs73g
         aBJudqfeSbUJRPbdBeakLF80lY/ALeKi26fbavrckjQ2rYcDz6ebR66OHfB84Jf6wu80
         5bldjh3aok8+KXaTmyXpGFs4FGym+7WwShkhG5Jjuu+SVFkQGmQOOknLS1kyJtaNmPcp
         ud2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=rPvJVWiDiEIM5wuVMWEnxzp8frpvnm4kbdPHcpWcjKk=;
        b=PKpDNGOENTjkzdtzb9lFfe9ml8zVYuNWtQiJp2l3xYD9gJNSDcBgInbbkCA/BWdK2W
         4GQkag8e8PSRK/4e3w23NPYy5aX5/K05toGHAuWSqcfN7+17mezeRNCC+VyP0nG2hiVF
         3uSa97FDPk+FKUDQNKYoWLzYiyG8ou/LHH72gJ3ZDYIBDzcIs1223RIPSI7ozpyjq3Ew
         yDl1MkLU1dVFKs4Dmli6UMEY0QgrKLYTLCkJS8c9Rp0rswRYXlEAY70VgywRtmZGLMaL
         Vn2jkbVhMQ71EyBiBmZXM4aVreoRepc4ig6JAbiuIcIb9ATa3QCDsf59eyhwtKlXv5F6
         PAcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bL7SRt7u;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e4si1415348pge.1.2021.03.09.07.46.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 07:46:38 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 0869A6523F
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 15:46:38 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id E996465368; Tue,  9 Mar 2021 15:46:37 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212195] New: KASAN: mention used mode in init message
Date: Tue, 09 Mar 2021 15:46:37 +0000
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
Message-ID: <bug-212195-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bL7SRt7u;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212195

            Bug ID: 212195
           Summary: KASAN: mention used mode in init message
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

As there are multiple KASAN modes that all work differently, it makes sense to
mention the enabled mode in the "KernelAddressSanitizer initialized" message.
Something like:

kasan: KernelAddressSanitizer initialized (generic)

kasan: KernelAddressSanitizer initialized (hw-tags, mode=async, stacktrace=on)

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212195-199747%40https.bugzilla.kernel.org/.
