Return-Path: <kasan-dev+bncBAABB6HDR6NQMGQEFWGQEHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 16AE0618556
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Nov 2022 17:53:13 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id i7-20020a1c3b07000000b003c5e6b44ebasf2884812wma.9
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Nov 2022 09:53:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667494392; cv=pass;
        d=google.com; s=arc-20160816;
        b=eVLcfkhfBvPeicNkITAnIoHwx03vM49qYH2v/6X6EsaQ1QIAkqEwUB/w8D0KAVyfnw
         FXGx3lsrzeT5A0LeIKJ407nWmpJzJXf5tsjJfslNobOzMNghChPSORF8S2tryIp0zQD4
         p04xKii8KcLEhPWRkL3WOu8i8f0qawIR/pHDceE4W2GZsRUVoM348uAbzye743lXKmY0
         vU4CZBdQmkWf393YalVfUNU9gyN7k/3T+20V3/+NtoZv2V4OocfJLPHmmtXrB3JsJ69N
         LRdaVPHwgxGmTA0PlX1Y0hTmwBt0v+kz3PB0W/dVV0UE62382MNfVUP4JWTL3j57e4X6
         kP7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=Y3h8fCppE5bVSEqWK6dcpQPd+Pdei57ljm9VeIOxC/E=;
        b=aQdc6jJz3Tu3FDETBd7lcXwOzDI5s/6KfWgzjb7ttKr1Adeaem7Ko6VTCA8gEj0iu3
         8cfG8PpbbztzItk5YuekbdxvGP8m4dqQOt6H7ob1PQTVGA+/qD+9+Cw98flAW6zZcSxz
         84Es+EjdFVCk11b3bjXUeub4RId3h/0xccfdzVOX7Di6P8Yxv8Qa4feM8m+/UJan/Cpm
         iXCtP+MB4asLx1CZ7x0FAOdBNWyF9Or2obZi0f07gC4yE49YIfUPPwwOAncJNn7PFeHE
         PjFB3Ks+1UJWQXZey2QUY/MY01cZ+AiZ7NCCTzsZW5ZGeVWOlqdKctjDoJArE6GYYci4
         dMcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AwF7OWY6;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y3h8fCppE5bVSEqWK6dcpQPd+Pdei57ljm9VeIOxC/E=;
        b=iFEc+EuPNBLKwBMnbtE3xrjldDjYXP+OMCdCtmG8s43S+13eaxx9AOnpZ/hcBS/Z8/
         f1KXVYza6Ymop3ykhAvwsthTY7zBOsLI0aZKJPb4S3orz5Z758p1gsKUV0BgAHFGs+gW
         FTACR8W2VM55wysaX6WFpv4I/4srjtI62/H3r9/7dkcH1TeD484/16GfsaWZNrouGj6x
         MOp/z/ZHBk6jeZGsGenwXE3dDb+1/Ymk+TTZ8pdHGTzBddD2dax8ZcNL391YnjJr8LOc
         NdAypE1KxW8Y5Y718Om90GJ7gSsWTx75M4KRbI93H+FWIiV4SeYmSU8bzCoI9nD0yRw9
         CSXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y3h8fCppE5bVSEqWK6dcpQPd+Pdei57ljm9VeIOxC/E=;
        b=IQG4uOSAgNPLWs4II03XjAGZR963D9kjOarlJzfMMUwzr49h54RfKkbEWe7llLuUft
         SsBldscv1S3W64ORuRNuSrSW2Qt62Ia7bUQPac1JkbOnLpe9X75hrawxesy7coOK0ie7
         zZF7ULzl6cEtEN8hNGDYldGy8/3GHkP4hVWuafsLGiiyeqJmPaNGghVZhJT7ERoiuMD+
         wFK885NbVrhNtxk9QVU3yGLfghUUz6z8Cf4fjKtEPPrpgNKv/ECYd3FnL74qI5ib9JFO
         jiSjjzGRHPX/MUeqHD0Xj+nFrLVaS87lq07G7pEC8K+YQYWRi3NGmHVTu/W5lrX4CoGd
         4acA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2+VZCMyLeeKOdQ4s0KHNrwafd9AJsfeukVHufSKfO/BNRpX5xG
	nmLOVw+nGOEfYOHRwVxQqnE=
X-Google-Smtp-Source: AMsMyM45/Ugg+mfWwFP914RQSNCN4cFAV8MnFaCzfXILqD9P9S8VeX3nXPMM41Wd/JF4JVN/L9eurw==
X-Received: by 2002:adf:e38d:0:b0:236:7217:827e with SMTP id e13-20020adfe38d000000b002367217827emr20225801wrm.652.1667494392510;
        Thu, 03 Nov 2022 09:53:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1f07:b0:236:8fa4:71d1 with SMTP id
 bv7-20020a0560001f0700b002368fa471d1ls1022737wrb.1.-pod-prod-gmail; Thu, 03
 Nov 2022 09:53:11 -0700 (PDT)
X-Received: by 2002:adf:f392:0:b0:236:2c41:d3f5 with SMTP id m18-20020adff392000000b002362c41d3f5mr19934292wro.596.1667494391759;
        Thu, 03 Nov 2022 09:53:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667494391; cv=none;
        d=google.com; s=arc-20160816;
        b=gRErJYnImjB2y4I8BDH5i5FK/zJmskd2dcSvbaDBQyEAW0RCSnYKajE8r6YVdrwg53
         ubbnXGjtKwVN7VU2Zr7nwqtFFHVm3kZcy/nPVVCA8xfCkb/hmgxDI5VwmHwQY6y2WdlW
         W5Fzl2UsH/VNaIci587EtT4aWrlAbMXbC+MyCLJLZjVE1g7y459k17kuFslcJ8M/f1e1
         oK/DRUCw7cMO6JenrgITWPNKU82xYwRMnQLk51H0YEOHbJ8Tb6MTbSIZuAWGUUbxYvne
         nyhZjCiamYWVonDoH61BnGSVYjrWXNS0XCI0R3ziOkCsJMC3XQI0ujVQCzpnroy+9EuT
         SFCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=S1N8er1zMsMojfOPOk0jSs3KBsm3pK2C7NRfWEMQCas=;
        b=MtPHnjOGWNWsYtvK2ukgd4u8LA5FVFggwqd6Ehqeo24cmM8RqOPz9nyH1Gcyit9hC0
         XjAj6rHmQRr8BbPKazfSFRFAgBaiAjN8wELH69T3jXOo8HBZqNfeSYEzzjX1bCAMQS4v
         fo6cpsr6kcF6TaoE42H4viOWwI+ALPTqkHzrLn+NDw7PHUOKNj2Z/ZLLq19r4XIhPAX2
         cnIGp5UFisPvLPwOYvTl41ZN3TQ/LKTmjJ7Glzd7nidkt3l8bScUYjqaAe4jY/+9l+gp
         /fF2vh6pmKH2cYZ3DmDL0IcnSi9jxerKYKI7+nEZnXsgVycDycmZMcb3MoLudFPZ+Z2M
         PxtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AwF7OWY6;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id l125-20020a1c2583000000b003cf537bb09esi188144wml.4.2022.11.03.09.53.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 03 Nov 2022 09:53:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 71695B82924
	for <kasan-dev@googlegroups.com>; Thu,  3 Nov 2022 16:53:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 219E3C433C1
	for <kasan-dev@googlegroups.com>; Thu,  3 Nov 2022 16:53:10 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 0DBD0C433E6; Thu,  3 Nov 2022 16:53:10 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216657] New: KASAN: catch object/redzone overwrite by
 uninstrumented accesses
Date: Thu, 03 Nov 2022 16:53:09 +0000
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
Message-ID: <bug-216657-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AwF7OWY6;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=216657

            Bug ID: 216657
           Summary: KASAN: catch object/redzone overwrite by
                    uninstrumented accesses
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

Comparing KASAN with slub_debug there is one type of bugs that can be caught by
slub_debug, but not by KASAN.
If freed object or redzone is overwritten by something that's not instrumented
with KASAN (uncommon asm, DMA, VM guest), then KASAN won't catch it, while
slub_debug still can catch it later (with no access stack, but still).
To achieve full parity we could fill object/redzone with a pattern and check
that it's not overwritten when the object is evicted from quarantine. We will
still have alloc/free stacks + quarantine gives better detection for UAFs.
But not sure how frequent are such bugs.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216657-199747%40https.bugzilla.kernel.org/.
