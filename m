Return-Path: <kasan-dev+bncBC24VNFHTMIBBTGK52DAMGQE6MOB55A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 670453B7A8D
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 00:57:17 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id s5-20020aa78d450000b02902ace63a7e93sf376181pfe.8
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jun 2021 15:57:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625007436; cv=pass;
        d=google.com; s=arc-20160816;
        b=HNx8GCoTB1HN8kH69e6gLSS60yUjgIHLuLC7HLuGneZbxugTBpk/PCCbcMTF8n5h8e
         NmftKIemnVxnBUYla1bR+ZE3VpwQIFLgzgEadUZZFRrBz3Jzmdxrg/SI8FZLOSAPzJaM
         uKfa+uEsAminRqyUHnZ7ZzVwO2y4jBfYIbRWa9/ASfI8Kmld+L1IEaXsuNKPjvwjAE7J
         FLYFlN8rcA0bB/nnV4ilYceDhtXei9ogM+y4ryGoNEIi2K/X1axwhRZIgpBLEML/1pfx
         QE8lrYlYsz4I4HClSdYwAJsrleCL4srdXQG/3DldWYpeO8UuleRypKbs3IS56DA1hwO9
         ukSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=wG0N27Z7Ag9qHNrcmXrSEGXlcVKttnuU1Nwr5vNMY34=;
        b=jtZLs45Xg6EEAJMZIkG6+H2oFpScoeS2b8GoaQanPUflPnwj+XTE2aj8KCuZRQk03q
         VP6N0hRVPXMiENoXkLblIuLQoXBK0T7G/3RYH/U3LkDX4HcQRsXsbzvc9ZiRMGLIKltJ
         cnffTUFLZuk9qNjx7RJ/O2ySoRvDpjS50pbayvK/ZRe3ZzCxfpsGesXjQ1ZHtxeL1E5N
         npGQuW4aG0D9mxaILaCO4qZqO/ZkfqmfPfJ2l7i9xMAIXhrV7D/CHGE4h4VOFNx6LEjX
         6XrxWRoSJvOEHqR7p5OVT7o8bgw4XEkPxxHoaA4XpcgoSrN75m3Pt8hF2h+It6VfctKp
         sSxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bUjfGbs5;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wG0N27Z7Ag9qHNrcmXrSEGXlcVKttnuU1Nwr5vNMY34=;
        b=TRqmTxkUkapmX3PLMHg+1BCmfEp6/L/sXzKZJx/EGCH1OVhbHRcz6ROv9pL/ZWgxI+
         rLrmYoBNadLucsujCeeBaCd6eoFC9ywf9Vw9PcgaMCyGVW0QKqJ9D/D4qqrGYrwrjtiR
         GxFLPAIe0NCDmyLpR0TLJjIIlHRNaSV23fLALjgryqP5UzD+OsFriZGEooGID7j8/5Ai
         P4Ked4zQQkfqHnkkxu7cxlvnE4lPN1iXOiu9FBykxklAnzZx0PHRJB5s23MHfnhLcSjC
         aF73EXTprxvFDbB5O6+fvGnhxQTclbzDhaPYtV2rmrRxRwibHix/ctHSwJiAcUGCNy5G
         /dOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wG0N27Z7Ag9qHNrcmXrSEGXlcVKttnuU1Nwr5vNMY34=;
        b=CawwEhuhMvwywZzmr6wYVFHLK6J3E1O8KFFqRbT1IlFn8Ep4D1Sx+5SMt09eecj/dV
         Ry+LKZnzeqOpLdoVllKGyqeBxCAm1vfHww+v7/llxrtTICIW+08B2SaiF/f+V3lDqg/I
         LzfdGN+GbasjKpscHQJ5fCdiQbfdLTgaQrSGvu/9pqGeAbZMYsTXVsUvEH/xQRaWOQ8A
         DqtcWyl5OTbSSPCb28cdLVwKoPCKxY0zFMhQJ/1B6174wu6Lc7XCQjCjVPr5Aet3L+8r
         Il84F1lsFy9m9WqHP4fx18QVqPT7HM6HFqIcgH+5YC7daI0SSSEl1Jn2YVQG5ZKPFVfJ
         EicQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530eJPHfgYl+/wUHNNqUskmQVLFwS0P+JwBFCnVXyvPe6AkJkWxo
	YyGyGXmGqar3KAoaf9/NWyE=
X-Google-Smtp-Source: ABdhPJxi55nelfRqDRrPdPKK/XIqxNPGTsPDK5D8sp6F8Wz9Ya6KEXD475qY/Ck53rBptVwRmK9xEw==
X-Received: by 2002:a63:da04:: with SMTP id c4mr30702061pgh.348.1625007436150;
        Tue, 29 Jun 2021 15:57:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1824:: with SMTP id y36ls76868pfa.11.gmail; Tue, 29
 Jun 2021 15:57:15 -0700 (PDT)
X-Received: by 2002:a63:5966:: with SMTP id j38mr30291217pgm.451.1625007435653;
        Tue, 29 Jun 2021 15:57:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625007435; cv=none;
        d=google.com; s=arc-20160816;
        b=ByhTPXKPcak2EWU4DKvaEGi5x6Ik4PSOXOXmSnrwDTNZYm4qpzbjkh3buUmP2o9BNh
         1/S4mpaGeD/qiuv048AqkICLLgTThVn919f4MbC8wcBP104L9hazdXatsJq6Kq7mqDXv
         KTzg0mIpWzzt8NkFg3GGYq5nPQZ8S3TOHv6g6ba+ytMkLeJgMxaXsYrF1+JSLg7KuJua
         RomePguKFnNs5Qomjysc1OrOY2ayb5vBA+OfcNRycd2yH8d79h3Bw4m6PZjUNQuaBjtL
         PJ5rL1CBbixtoqdV7n8517K/I8AEAqGVVZRZNM4V6BU8ahhft7da9SMysufBfIp8rmAJ
         ZgPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=AE8nla94yEbvgsVZ5twvIx+T1n64XYUQDwmTbRMu8uY=;
        b=H5UhNU0DaiwKk/xNqk/H1pXVCg35PXPmorrUOtkv4xuRjrksxdtcO97q0jbDK4mbzw
         n0/f6Ts0hhlAK0szM5rVXzNxLYQITg9GvdgQ7A6WDKlAgxO6vVSVq03i2luB+4pE1taO
         zf9yYjkwAN1pet/1OeKfV1lMdH6N5RzDh6OyLd+rZAlkVqRRAboJAqPRxL4DozGFxVdJ
         C5Gp0f4W5OqQZ4KMyzeOaQF2JLi+Hngyw2g8BsllMMKkME/OVdPOo8tSEnEyhvOgyhrw
         S7hPggTbUdo1B8ojhZb97yn3Jq3fZpvUctmu+KQ/fQ+9PrMVU3U57XpPAj2FFmXS5iA+
         CVVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bUjfGbs5;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r7si1917045pjp.0.2021.06.29.15.57.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 29 Jun 2021 15:57:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 642D061D0B
	for <kasan-dev@googlegroups.com>; Tue, 29 Jun 2021 22:57:15 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 568F2612A6; Tue, 29 Jun 2021 22:57:15 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 213335] KASAN: vmalloc_oob KUnit test fails
Date: Tue, 29 Jun 2021 22:57:15 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: davidgow@google.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-213335-199747-jFReUcMq05@https.bugzilla.kernel.org/>
In-Reply-To: <bug-213335-199747@https.bugzilla.kernel.org/>
References: <bug-213335-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bUjfGbs5;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=213335

David Gow (davidgow@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #6 from David Gow (davidgow@google.com) ---
Confirmed this is fixed by
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=7ca3027b726be681c8e6292b5a81ebcde7581710
in 5.13, thanks!

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-213335-199747-jFReUcMq05%40https.bugzilla.kernel.org/.
