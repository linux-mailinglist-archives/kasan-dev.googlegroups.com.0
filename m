Return-Path: <kasan-dev+bncBAABB2FKVCWAMGQE5ELQ3DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id E6A3B81E2FB
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Dec 2023 00:51:06 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2ccc1c5f200sf6977381fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 15:51:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703548266; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z5l7Z9kubmF0le6mnvb1WAXjvVKpzzusQ8TU3cbLh93Rgr7qlI9jDer+zuD5KN4mid
         cpfMW5KjUIDNN3otaLUjk9Gx3fz1tIq3FpRv1XYC3NroPfpuOm9UmEKJSh1rps59MA9b
         XsYJHxmHDUYFPQ82wrUEwOYR75D6opDCNi2LDU6wXfbW5DKCfWYREfDbWad+fSQk+aXd
         l9SrAHjtMZvhJ4gqAaGGlUYOLz5tHZfBSw9muLCP5WFfxOaG1BUCVgDZKg6MoBy26jJJ
         WYGo5TvpLjX6U6hayfHxHgJvwWVRI9z4Sz3gUxBWuKX4+8ghvBGpJTFuIRVtS1Epmv47
         fkQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=DxD0BcXvCEWip8BIEmiTlfHRhFu1hXkiXcO1uz52Ll8=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=codRKtHs7jHQhpx3inbnPXwLehUXRyNdRqoKRnpEL1W5KkGDnOP4kXwnacd4yegosA
         14ieM/F0K+CQjPkCr2pRCaNxFGK5pNrnXittbkuuPL5QHdb1HiXj81qOiB1Ed7xRE0+e
         fxXv5HdNyzfHI+B60PaquTtki++as3CqGn8B03cStyOJFaAixX2x9erXvIkjxuFenFGR
         ARxIlr3KnFnE5UhLhSS16dkcAy2RdjtUWvJzrVeGW2Z3STIaQo29woLupjkaoxYPNGjs
         LoL2P+2EdXQrQZ339GtSNl8mdrn87dslc0hCEghSHpPCNPk+Oc/DH/MS41ckVlmEsojT
         mJYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uzQ6XQoJ;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703548266; x=1704153066; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DxD0BcXvCEWip8BIEmiTlfHRhFu1hXkiXcO1uz52Ll8=;
        b=cPh0EnjCbz5uHHAZlIksZ+pM+JJEJqsXLGGIUFbk3aBeJp/8vOLwW/uHOVViHrpHsT
         r51DlzCXPprI+QZm4XJ1agA6A/ovSz8HmUc9xxY3nEeJDbiHOa6JsdQ3QYx1AiRu81A5
         wLhrpT07lr3F27yoIAEuc9Vqx0sxsTZVWpYMNzjimvAViId48Upwto+rpvahssCcBKnT
         L/OdETvDZ1jIz0C5qPlL4PrkubxODhQ2wCQxEExpq3he6ehxJfCYbYAzYmBcqy0WFKRm
         LhqQyLcgalUiJTtqfv3Swf780a/zbX/mqn7DLgLUpTYbJSfUW6iq5G/f10aWxwdqZBiA
         nzeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703548266; x=1704153066;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DxD0BcXvCEWip8BIEmiTlfHRhFu1hXkiXcO1uz52Ll8=;
        b=ZskydYWMe9LY+riuZOOjZ+DttjL4Wq4khpD7oIMGrmfFgTN2limOKE25z20MqrQ7Rk
         cvLr+woH75QtEmBgkSqS1ekvk+jWTQLNR9tFrXOUR8JnUK+SMUv4+eQv9XdLI1D+v9yy
         mGb8h3d1NsIyivfR/LlK6+dpiNVL3mZYxIUL1txS86NwXR3LtTFYsgfe/J8VxtW815ZK
         9N5Q1lS5V6MW6LFcsCHVaaNPikKdqW8rOmKXZqWpHXElWBOIj57QL+gRWyIMCOOG4ezS
         GNo4apiJYTNZrDsE4V8a8mETA7HegTHc2pcQ5D8aeCc91P1q/ogZZTayuzeFtMCccnso
         G4Rg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwSFEesKwvD3IdqsGN82tzHEZ+qC6GbB6+ExGGA35O3n5xvZkdh
	4FwNGAF2H+ewXfDOFzSo3BA=
X-Google-Smtp-Source: AGHT+IGzr51UQEOGAY15/XuVzK95A2ryvcHIvbQ6+1/yLUUOMBLRstdPpnQzgunyVt2eGen8vAHh1g==
X-Received: by 2002:a2e:8648:0:b0:2cc:9808:2706 with SMTP id i8-20020a2e8648000000b002cc98082706mr2638225ljj.92.1703548265018;
        Mon, 25 Dec 2023 15:51:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc1f:0:b0:2cc:cda7:f76c with SMTP id b31-20020a2ebc1f000000b002cccda7f76cls93434ljf.2.-pod-prod-05-eu;
 Mon, 25 Dec 2023 15:51:03 -0800 (PST)
X-Received: by 2002:a2e:b0cf:0:b0:2cc:81d8:5ee8 with SMTP id g15-20020a2eb0cf000000b002cc81d85ee8mr2375675ljl.56.1703548263184;
        Mon, 25 Dec 2023 15:51:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703548263; cv=none;
        d=google.com; s=arc-20160816;
        b=IoXxSrzMM7rkVG1VJ8qtcDm4L+flDgQqHAoGhiGzEL7uZcB48xPuwQ3VaQC98M/ABw
         SLcFbDWK6LOb9uGa5xCyYx1EFZF4T5OzTjtYFixGT1yzrWJy0XT4MpRQXKSCiaae9Gm2
         ClgdvWBrXZNFVrquBLNPAxLQ6IYqvhKqtFH18zvLmBOL/7Q1QdgI7TrrG4mXX30iuIiu
         sc+OBOZK87r6NHIK9k5Oxlfw0Fxl6vpzQrqHElVhqKYgp35crOF5fpFRU8ESlfvfnU1g
         +luMbzE0AHWGIpEIHS78KfQOEhiAlHrlbxm677RvaKEJGZQiWI0dUt8WvAyeYVgVGzVE
         KooQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=HLYKoBpIwwj7e/FoZHFKAIOU1MtRLTGW6b23X+yv3ow=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=o8ZOCbWhpRr0n7p1YSgNV/fVRITvo5TlFiLs/zZE3/fFAVJmrAS6ftTXgTUPhfN4Rn
         6rXs5RMmY4W6hZMJTs1Yjl3TBLQ1EZ2e8/8J7Z6AyQ8sCEndM+uHEgzrbp6u65qbwtvY
         7+VqfqxrjOOfzsONXHLnaDoLSnpvCNNRfaXP1FvE8UQTKl+Q8IAEZEEDk/aLF0VGlPdI
         tIlubZT0IhVdgc+D/zA23RNiBTc6Mx7lHOj4qzBhoXtpLdFevheWChMELCSfB9mfBw7e
         gTkLXsLUqUhHQUk+K+gG8Z0Wz5TxN2QV6Sr0b1zXa2vJ4usFZimTXHBHbii5OlbgK94c
         neiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uzQ6XQoJ;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id s24-20020a2e81d8000000b002cca88507basi291484ljg.0.2023.12.25.15.51.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 15:51:03 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 5E54BB80B24
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 23:51:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id B0144C433C9
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 23:51:01 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 9A698C53BCD; Mon, 25 Dec 2023 23:51:01 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218321] New: KASAN (tags): skip poisoning new slabs
Date: Mon, 25 Dec 2023 23:51:01 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression
Message-ID: <bug-218321-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uzQ6XQoJ;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218321

            Bug ID: 218321
           Summary: KASAN (tags): skip poisoning new slabs
           Product: Memory Management
           Version: 2.5
          Hardware: All
                OS: Linux
            Status: NEW
          Severity: normal
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Currently, all KASAN modes poison newly allocated slabs via kasan_poison_slab.
While doing this makes sense for the Generic mode to poison the redzones within
the slab, the tag-based modes have no redzones.

We should skip poisoning of new slabs for the tag-based modes. The objects get
unpoisoned/poisoned on alloc/free anyway.

For this, we need to:

1. Stop poisoning slab memory via kasan_poison in kasan_poison_slab;

2. Skip unpoisoning of the page allocation for the slab via the
__GFP_SKIP_KASAN flag. The flag is only functional for the Hardware Tag-Based
mode right now, but we can extend it to the Software one too.

Once both are implemented, we can drop page_kasan_tag_reset from
kasan_poison_slab, and we can thus make kasan_poison_slab no-op for the
tag-based modes.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218321-199747%40https.bugzilla.kernel.org/.
