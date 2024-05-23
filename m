Return-Path: <kasan-dev+bncBAABBBE2X6ZAMGQEKGD64FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id C3C3C8CDD34
	for <lists+kasan-dev@lfdr.de>; Fri, 24 May 2024 01:11:02 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1f32359a229sf6632015ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2024 16:11:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716505861; cv=pass;
        d=google.com; s=arc-20160816;
        b=UCfwZtu0mihQjvQE7zMf6xOZ2xePIpj0BokIFoUNBu8bzsrAZtp9yYJDqK/7SZorGD
         JSssPzhDo48BBWuYeUaobTZzo9XTU+O33AyjJwDJYQlj4eugWwkh50HOkPI1QmwJHNzm
         afy/cyJTdyK1Eshh+b/bA5u2gGTghaZgJRHNjm5V3uWey3fU1kSar3eyGakEGZBPvtbg
         kW0WWEz9rp/9W0a463YQzxS8kPR+KcTmnHQoDLZaeNqyi12C8UhjMSnjx63iLDyYfoR1
         racVrA0Re3xlrA8TXz94jnm7/nuI9vkDBdzub8JIWk05QEFkKpxoTk8Mlpqu66BSeOBH
         WX2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=9/hPMs3XoqqXzkZrFqDrUkR35HcF0srWl8QKfyfVLh8=;
        fh=1rix6HyHhA6rj0x4r+x8zeDR/Y8RD+HwBLsknKxSt2w=;
        b=fXR41Lo+Kr+ccWfP9l6x4qlFwABsLSk7b5JQRl3ZYnjfg9hRGBKcfsAEX3VL7R7S/1
         wLVevn7OoGNkYN3QtoD2Ng1JhSM8/YB0FI6ypqIQAox/04a/jRqL63IXyltMqfICqtCt
         iZtNw3kQvdM/leKXyKbf0db3Kdr3UQVm81VQuzz3sOlIBvBpmEu0ziTjHsUJkCmMw5/1
         mTuf6TW5KBgmIrQXnb7TuJ3q/qjnECJ4i8Rv0iWMHqd0tDsr/ZeCNRiQxsFtILTu7vxl
         nlFQCphThYzzpAiPnFoZ9oV4GgJp+zW3vqtdOx08EM1Gf9awz6IPacwCxqN+mCimyOX/
         5oew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=a70UlrPD;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716505861; x=1717110661; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9/hPMs3XoqqXzkZrFqDrUkR35HcF0srWl8QKfyfVLh8=;
        b=QFr/IzafAJ/mtFYu9MmUI4VSvDAwXH1rwbXMCrNMKaV6GfmWlZ2QuWL6U9jq4Gm6yn
         vzTnvO4BrslJ9CmbznYqxM7va7gB02yJOPYDCj0BWQbuhpWOBKL/+Zn2/exvl7I4ArL3
         hcwiMuRWlhCMGPD+X5F15jtb4jBHDvEyJS9eHxcnm/ogE6ev5Il4kQ+LNaRVH2gqU+7k
         3K1Lp+/XvbakHRScrVTttvkPMklNYvlTKKgQgg1zjGvgodyvAPkoOqCY0Mkw7QVSz231
         KAJLTgDN5EpIEaz6uPomF2+VZ5cvuM6zhDtDOEqIEb+4b5RdGJWRbOcD4Y2jJNYl0Lfa
         Zsrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716505861; x=1717110661;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9/hPMs3XoqqXzkZrFqDrUkR35HcF0srWl8QKfyfVLh8=;
        b=Gqbyh/oF2yFIiqyulGsQy8dYCYGmxEfYS4J8ON8GYl68AZUpH8n39f8dzxv5bZ/LKS
         T2qVzNLELg/XJzExHripsj8r93/ohgMIOteCMBD0XOmtAgTqseUnGhabzb+GpGSdaMQD
         YmFET0xRyAZNnR3VdbySFxOVLM/kxbFR9inN2lTBz6CCWI2iCa0815UwY6ooQOJbNS6e
         cZoVJ3ijE7A7H1lubcyceSUSv8xElS7ug5vHMzfVYc7agvodznxBIx0GqgmsveUFsEE3
         /W0TCF9Ul2DLRe7aLEZ1TM4RrXiCnqxTjjR+1aJ5bn5STyCyrBwNgWPZYkThi9ya2hoY
         aP8Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU+GUJ0y4ld4j11wmdUCrbvZp1l2BOdBT5UtXcItYRPw3xzKKdWIz45PetruGDGUHVKl93q6XAifr3L5nvlN5Q8kHplyH3L9g==
X-Gm-Message-State: AOJu0YwykvGDKYzyiJ/PiwKzAFecczhrhfHnCR8IklDM6ekVH8q9nCxg
	ZEVXGDi7kBeyYLedW4NLglEZpJNd2P76ijjJP/xQ6hmZEg7GPBh3
X-Google-Smtp-Source: AGHT+IGyiitC0Ea/BFKY5gTN67RCfsfMVXMgZuM7/Y7kNk61pZBnwJjdg2FbvO/so873dyX86S+6Jg==
X-Received: by 2002:a17:902:d482:b0:1f2:ff28:c751 with SMTP id d9443c01a7336-1f4497df4demr7902545ad.47.1716505860864;
        Thu, 23 May 2024 16:11:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:eb86:b0:1f3:2c68:5bad with SMTP id
 d9443c01a7336-1f446302fa1ls3093605ad.2.-pod-prod-06-us; Thu, 23 May 2024
 16:11:00 -0700 (PDT)
X-Received: by 2002:a17:902:e80c:b0:1e3:e1ff:2e79 with SMTP id d9443c01a7336-1f4497df7f9mr8671195ad.45.1716505859796;
        Thu, 23 May 2024 16:10:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716505859; cv=none;
        d=google.com; s=arc-20160816;
        b=hE8kpDuneaf52itPGsqsvxcvlYAbFvC8dpBHipx489iZVSD/vc+lrHfRTKmF4FAKjR
         UUoY4WiWKy9cVeeOTUYtFH8qaGL0xNZ5NKEvq11soMzCApup14fQR/7LBgZFe4IOJnc8
         8U1kZmZHvM0wkvMS8Jcj7vzSvSCC9No2jhU7lVluqYGlv2zAXKjb0BQ4Bt93Tgf5LcMe
         /4b+C+XlSQx342OTgOhDXqy71ajorV0pLfKpxxwqvczfaCup/fUwPU2US0iIhHCwSQJe
         hao1nYYRdBwyvQLR3cv9C3pGwLMRGXZTC4rRCjfF051qJVsuwHOyPWd6D7b37H6N3fpt
         atDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=+KNvDoXRH3iC3FpkfKWuByuEG2zndkippfSbPapRAc4=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=koeoioCovvNZo5O/rC6B8dHyunppAKMcyuiNli9+59gXqKoPKAdixbU9ELJO6ywQMc
         AT7hSY/iNuPXi/Y+8V4FstQYbTuF8Fur3ZRkyJk4mp2MlFqYMNa2TJnFu2aeBQyTF0K/
         XyzlrUKLwN4k1g+brcvAPOT++uHqWL+rg7w8zddl3/UjA9MT5+Vd/LEkGFFHBOk1Vek4
         yQFplolcyeqkCTgjcFYMZvljA44HJe99zvTNTQWPKpxlBwMdHd7fULiSbEFmNBa6lh6R
         ANJMa9wjUoWHc3MlMrDrYlTTVM/n+LNzklWpYFkVw9TB65FR2OWkl8ATplGWHEv4YwGG
         dDQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=a70UlrPD;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f44c9734b2si104585ad.13.2024.05.23.16.10.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 May 2024 16:10:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id CF392CE17FC
	for <kasan-dev@googlegroups.com>; Thu, 23 May 2024 23:10:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 07944C32789
	for <kasan-dev@googlegroups.com>; Thu, 23 May 2024 23:10:57 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id F1B6EC53B50; Thu, 23 May 2024 23:10:56 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210293] potential kernel memory leaks
Date: Thu, 23 May 2024 23:10:56 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Slab Allocator
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: m95d@psihoexpert.ro
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: drivers_network@kernel-bugs.osdl.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-210293-199747-z3kbnMea3k@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210293-199747@https.bugzilla.kernel.org/>
References: <bug-210293-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=a70UlrPD;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=210293

Marius Dinu (m95d@psihoexpert.ro) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |m95d@psihoexpert.ro

--- Comment #17 from Marius Dinu (m95d@psihoexpert.ro) ---
Hi.

Also on Turris Omnia. After the recent OpenWrt update to kernel 6.6, I get
paging request oopses. Trying to debug the issue I enabled the kmemleak
detector too and I get these reports:

unreferenced object 0xcbf64000 (size 9408):
  comm "netifd", pid 1468, jiffies 4294960307 (age 4261.650s)
  hex dump (first 32 bytes):
    00 40 f6 cb aa aa aa aa aa aa aa aa aa aa aa aa  .@..............
    aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa  ................
  backtrace:
    [<46e969d7>] __kmalloc_large_node+0x98/0xd0
    [<9aa899b8>] hwbm_pool_refill+0x54/0x80
    [<02450ffb>] hwbm_pool_add+0x6c/0xe8
    [<bcd0e1e5>] mvneta_bm_update_mtu+0x64/0x1ac
    [<38f2fadc>] mvneta_change_mtu+0xe4/0x160
    [<72b1860b>] dev_set_mtu_ext+0xd8/0x1a0
    [<f76c6e10>] dev_set_mtu+0x40/0xa4
    [<bb141b8f>] dsa_slave_change_mtu+0x150/0x1d8
    [<72b1860b>] dev_set_mtu_ext+0xd8/0x1a0
    [<f76c6e10>] dev_set_mtu+0x40/0xa4
    [<beb02cca>] dev_ioctl+0x2ec/0x640
    [<065ccb48>] sock_ioctl+0x2c4/0x614
    [<e23a4d3c>] sys_ioctl+0x25c/0xbb4
    [<c8e7ed15>] __sys_trace_return+0x0/0x10
    aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa  ................
  backtrace:
    [<46e969d7>] __kmalloc_large_node+0x98/0xd0
    [<9aa899b8>] hwbm_pool_refill+0x54/0x80
    [<cc6581df>] mvneta_poll+0x350/0x73c
    [<4c312754>] __napi_poll.constprop.0+0x2c/0x180
    [<14d6e295>] net_rx_action+0x218/0x53c
    [<c955d39d>] __do_softirq+0x10c/0x288

--- and ---

unreferenced object 0xce15c000 (size 9408):
  comm "softirq", pid 0, jiffies 348025 (age 1002.510s)
  hex dump (first 32 bytes):
    00 c0 15 ce aa aa aa aa aa aa aa aa aa aa aa aa  ................
    aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa  ................
  backtrace:
    [<46e969d7>] __kmalloc_large_node+0x98/0xd0
    [<9aa899b8>] hwbm_pool_refill+0x54/0x80
    [<cc6581df>] mvneta_poll+0x350/0x73c
    [<4c312754>] __napi_poll.constprop.0+0x2c/0x180
    [<14d6e295>] net_rx_action+0x218/0x53c
    [<c955d39d>] __do_softirq+0x10c/0x288

It seems that the problem was not fixed and Armada 38x looks very much
abandoned.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210293-199747-z3kbnMea3k%40https.bugzilla.kernel.org/.
