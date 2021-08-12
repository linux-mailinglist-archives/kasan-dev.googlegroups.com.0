Return-Path: <kasan-dev+bncBC24VNFHTMIBBDFX2SEAMGQE46A2FIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id CB1763EA50B
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 15:01:02 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id p5-20020a170902a405b029012cbb4fcc03sf3691308plq.19
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 06:01:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628773261; cv=pass;
        d=google.com; s=arc-20160816;
        b=NSiN0POyPtTj6gIVq3AaDy5aphvqUxkI9NFLGWGWVY5i7k3Go9CJ46xoxOWOIIyBbz
         088mkD2mDnjEgOP+1QxgADG3qeEgiSxm6HJVowctzPHyZ9XqhtBdQTVUnBDwK4/lKbkJ
         c+1+J6wNkAlPXJcu6YF7038xV+CRD/h+Fzo1vB5i5C9i2Xwv89N6PwydRWDKz4Zj1lLc
         DqwYxsiGnx6vUgGcD3hWcrZjzd72yY1NwxncLzX0WKolJp8WMtowG+J0FKaATcp5quhs
         /6SSHDnILI+ObLhRk8qt212qdbyVZayHE4FWWiraOZGd3UFt8JLgjLFYRLJlt49w8Wsa
         WNFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=f8VoQVuNC618TbWTe8pXSn1pWw3UUj+mEm/h20YStp4=;
        b=ynlv2NcfnZK58mgtG8t5jLUi0+cy3uPTEvuGHljcaGqQMfPC0IfmqimbwLt9M/VEi7
         4stUX8Ii+GCKlV5yfPjxempnuDVx7Y2aNkoqsJiE64FHvrTKHUBr61icOAcYxNW/2bQk
         xFQjbbTOQ+WEuASxZhkU/I2dD6JwKu1wF5fqijqLSEMUamjeBPQa8wpFsKsLSX94jg8k
         NzLtxfHB85aJI1PYLh8ldfyKQ9v1P3C4LbrBS9dpvshusO3AogGvHtQB58rrlVy3U50q
         4kGVJ95Mg3O1V/7IJ+JbsiBZ24yl3gdaJHTJSaYX8eq8wjyppyVmsJEo3/Kt5ydyGy7m
         X6UQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eeqiOF0S;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f8VoQVuNC618TbWTe8pXSn1pWw3UUj+mEm/h20YStp4=;
        b=bgLRagoqdVVMk2YrRfzmI1swTksWDmvey9GjsauFur/fo6C8DXG63nFk+7/ljnVxjU
         7msc4nDS1jl+QrtPJpSfeOs2eH0IXsj1FeCBr7o2Fe9SOKZcJyTUSzEd1t0AbQ02YGl5
         NkbrLdNvZao0s2Wete+c1UKf3R1vkwR765U6BYOkHhd9RRyr3WrKc5mfc6Ba5WVrxQft
         RwgmG+8nI/DI/u7XeciLWcLN/VHjIsBPLO7y/T5NtEcYKg3F5xweIpj1098+AcGWBjnY
         hqiV4X5f1XUXM/Uo8sVZ/FPyAsQNmds2YU5c565bm+0RTkDkyoDlTei/SwbFCq+JF3yV
         wIxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f8VoQVuNC618TbWTe8pXSn1pWw3UUj+mEm/h20YStp4=;
        b=D513rEhpoNe6moeabsN5qUJPxplI9+X9dJykggepykcjzaaGhzCmAiD79uam9XgbsU
         +lO8DPwHgwBcfZvyv5QPtFcEgwu3KHiXVqsSd44w2Gh2LvMqqx+y4aCJ9iUOCZcoagSm
         TyjYsyZ4r78uA31P9Ep/LFQHbkrdQH0wvSCXIy/TC1hM4mXuUxL/1qL3cyXXqg71U9FL
         GRAe2UC14vZzuKVDA8ReQq5IRbM/n3dMDCHhjOhrePmD2SrpF9E7NuUI2LJki1K7KAfj
         gZenQ9FJgYirO3edcVIAl1eSSouc8Bq9tSnfCSUid+QUH5fzx3ajPHQ8KittR99Fb1xE
         nAmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530BPdTs2O9JEQIPcM3CndVdkbbkvfqfeImCy3iEfz3S73aw/Z2p
	jF1wAbR53TgfIQh3W0BUkGI=
X-Google-Smtp-Source: ABdhPJyD1Q5VMCgKGPDy9KtjIk5LbSxeMmBrMfD1YsxiJ6NJ9o44Xew7bNVqEHBrS14qmoll159img==
X-Received: by 2002:a65:5c89:: with SMTP id a9mr3772805pgt.433.1628773260960;
        Thu, 12 Aug 2021 06:01:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4e24:: with SMTP id c36ls1476270pgb.5.gmail; Thu, 12 Aug
 2021 06:01:00 -0700 (PDT)
X-Received: by 2002:a63:7883:: with SMTP id t125mr3716237pgc.243.1628773260381;
        Thu, 12 Aug 2021 06:01:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628773260; cv=none;
        d=google.com; s=arc-20160816;
        b=XX4FxFrcEfSCfwv1aeDXnW73an+2jNPZv8D/avhc7ZoZzWZ2TNzI+rDMO9IC3Qwak4
         YdHfLyTb+43d5nz7a0OKIbjR1SxGoOaDDZ90l/iEInizQSaqUDmxENh4yCYbUnFVtRSx
         o2jPVg5ztcDByATGJ9uVybkuhOcPigGypzk7M6n4USCtFDO7LbYerFrXV2v+hQmT0cAX
         922EDzy1k8o+JoQFDJwQAAg6MrBpLvwfQBw7LuXx3JF8RUeiGjNcl5kHgJVcX/6NSTFJ
         60ZjRMzX0P+YDolLMGBV/3JT/J9h1p2TjAGiGq3lBs/zeIxXabmNhv3pGvsLa6zjR+pB
         Xc1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=n8SskBYsNcCkFuwqVmhNExSgKGN9DWYuMXg6u3mQ8JY=;
        b=f5Rr/iib+zPFu4Kq6rvNVVnzq3O6zR7GpCTlemp56LLQWsZyfxDliLhqtAW8FtcnmT
         /7tJNo0EKrEye39G83WeWKO5SY9m5EWvlH9FU3rtnK6N6283qZWj1cgISB7ydAbFMz4L
         +6wp9VwjL4Y5G3Ge2mVu1uyQoeOf4ZRnBgk2cZ/8yiafiOaYQHAxSaByy/FgDR3Lxmrw
         oAlz2DD3g8OZndwgLiZXI/C909GwUaoGkmaq7nzu404pG5OGiseKBZqoNHPwFHqf7LQe
         Ztdq+4VTTTMsqtCZzh3m70coNvrr3oehuBH7AD12BL5FrQ0qeUidHDprJhhVhbDG54u7
         y1uA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eeqiOF0S;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r9si125610pls.4.2021.08.12.06.01.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Aug 2021 06:01:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 042CA61059
	for <kasan-dev@googlegroups.com>; Thu, 12 Aug 2021 13:01:00 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id E824B60EBA; Thu, 12 Aug 2021 13:00:59 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214055] New: KASAN: add atomic tests
Date: Thu, 12 Aug 2021 13:00:59 +0000
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
Message-ID: <bug-214055-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eeqiOF0S;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=214055

            Bug ID: 214055
           Summary: KASAN: add atomic tests
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

KASAN uses annotations (see include/linux/instrumented.h) for atomic operations
instead of compiler instrumentation. It makes sense to add tests to check that
KASAN can detect bad atomic accesses.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214055-199747%40https.bugzilla.kernel.org/.
