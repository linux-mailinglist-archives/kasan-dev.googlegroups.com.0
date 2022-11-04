Return-Path: <kasan-dev+bncBAABBEU2SWNQMGQERAXBY6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 624AA619ECE
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Nov 2022 18:34:12 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id q10-20020a170902f34a00b00186c5448b01sf4010173ple.4
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Nov 2022 10:34:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667583251; cv=pass;
        d=google.com; s=arc-20160816;
        b=JCZ984YwlF9lQZYysL2uyS+BLGDDAyxXbBDn94GCPLmWKJXLKTuORcUKJia9JNcdjQ
         FsfeYubdzJYysDloVaxFCBszKjAlIQhLBMRUYWGwX+5DOs5vCXF8sBPzCGmVqGxuKhpV
         /+yMWVCHi9sBsgfOcgIKtDitnaiqoi04Emuxq9KKVNt0GGmiow5DxE3zNGTnvCi4Rlui
         3FLTazRvoVRhLDtTM4bbZBczpE9W/77gGCX6OaJqJJMv+48LylYiIW6r7e9//vmE3dXA
         fJkFY6y8LJn9ERI/he87lGw2iGpvV9gFPz/Q2jc5hmfNJw7PEWN3sLMFCBbFGZq3aDFc
         xvQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=eebGq5QxDsRbIa/mDOGSMuG2Jdz+0j/LTYzkUeojI1M=;
        b=vsdq2/Ia3tk8f1PfWToquLQt8Af0Lhfb1SKPBYZWpMxrhL9U2m+lXzFSxqvz5sUQF/
         ljkXdnoRDF+uUmZH/LEZ+e5PCn3J2Yd5OMy/aGCgbGPhowx9WGS40jKP2R5VihFypuSr
         XzYz4McNJNP8tonKb0RPqFDiaVW000CNDOz4zWTv0w+JXaGmacaLM38n2cUoN4t5Skyt
         WiE91kk4CRUq5qSqRTlKph0yOnbg29SwzsNCq9tliWgkG+mH53YM4nEUlO1eAivBcMVV
         lkysw4Us1ykJh2zjFFoJYiKG9YEI/IrMbELMkx1ZP+kHe4pcX9Gzu1HNLJXKeZ8ULPZo
         qE1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H4nb0qeu;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eebGq5QxDsRbIa/mDOGSMuG2Jdz+0j/LTYzkUeojI1M=;
        b=rAAWWivMsX+c+d0AqAza/1kG6Xawm74QOUo5B1dIO9pVvOO+3Be77J39FygfLc50cJ
         F3Rdj0Co8MccnazJMgjYl5UsRrS/AbVvMihVb4c22oH84lFdDpG4S+3Qnokg2ryjt5uW
         sMKzjTrBAxN3DJz6bYzNRKEzRNbVN7ojoL10bCLBZjuuUKJCwXBTg1H5SlNW5RzxyO0t
         Tnj7rJcglBcQifBvmbLPFTc9nNoYfRygncWGUf1yQmc6oqn99avoN7WbQ6rb6oTdurbo
         DxUwpvjP1FkMiLzCq41LAqFtYsP8oSPz2QASC2fy78VSw4JETkl6nNuRW0MPP/zfP2ZH
         ac1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eebGq5QxDsRbIa/mDOGSMuG2Jdz+0j/LTYzkUeojI1M=;
        b=sUxxRyZaMDsSHIZfX9C2w/Zhc2e+2wdcNpuga5xNAiGZkYVAsV3xM3gTolwo/5hn8f
         fmwQ5UGXntZtMegzkKW/cBcZHWW4mLGlIeLx5LOUT54UPxd2L7kI9oUIfpBGjK6VGABD
         CTc1eZjrng/iO4d1wJfHnZj7/MmgZsvYhoZfJnePJzkMkUWF3s16XAYB1XotZ/7rVhQT
         Ij7HB0DSWcwBtga/ape2cAiWra9cZNrG9xwC7ax1B5y0P0D6/gJsHKqDXg85qg8DoFkP
         mUbmx+D2ToyT4qlz4TpeDTrLuP4rQWM/gn3ZAvmIyw9NP/T4/11YScLs71SkgD8ezGAo
         2TPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf29X3oncSkcPmKXMswX/WTi0bRfeKPkwRlSBpmdTPKyjOwh5k5Q
	7voml009ItNTOKM5MeJs6wg=
X-Google-Smtp-Source: AMsMyM5czkNOTvYpLo/kUrkNc/puQ1O8vJiCUQ/RG3m9QOf5gpen/VuLAhJoXM3SAd4iefHrZMqAfA==
X-Received: by 2002:a17:902:d484:b0:188:56f3:d374 with SMTP id c4-20020a170902d48400b0018856f3d374mr8819171plg.121.1667583250675;
        Fri, 04 Nov 2022 10:34:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8c5:b0:213:e:b27 with SMTP id 5-20020a17090a08c500b00213000e0b27ls6677306pjn.0.-pod-canary-gmail;
 Fri, 04 Nov 2022 10:34:10 -0700 (PDT)
X-Received: by 2002:a17:902:e212:b0:186:e9bd:d51b with SMTP id u18-20020a170902e21200b00186e9bdd51bmr36382966plb.58.1667583250064;
        Fri, 04 Nov 2022 10:34:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667583250; cv=none;
        d=google.com; s=arc-20160816;
        b=CrV4bFHjpiByHEuTeiRssHfPPjuu5l4w4zXtJKyE/S7Z3jgEhlb+CpygNg7jYlaiZ4
         afkKJ74XWetQPL8ewz240QNFhhIPJVvryoaZOZGqZvvlUVMWi0D5nJeBwVCci77EQuMa
         I70E2vBbUm57FdGrWXzIWG+1IcvAfqD+3XdkIBHTK3RmL5kHFrgbD+KclesGZ31DQwTA
         meUPZrh4IbUvx+HWToEWqIIapUzyMsx7HC8hKJ40Muz2e5vAdaAHEy2x1k0pQbl4c2xC
         cRsPsRUPcVyE5R9Xzn2SFPmtWBCX3rbUAQOAPFNu7XTnCProVHzvGJXNDOmLsfZ05Drh
         NCfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=5lcNf/2fdZyf6sN7Cf8S5APd4lY4crw3E8oYCnYrDrM=;
        b=DbTMwR4pWtxlMp+BLWcxVKLDSELK66pv0bl8QIpSvru4SA0L840P8Nve66w4Ur9nNZ
         fovdrNuZk61UBka02+/OBO25++fX1yIeXFkJUX4Cq6P2ZzDyE7k/rCJKuNQByyvXs03C
         iR3eLcVjEKCTa/HPv/3vgcrcNteNDtRcTfr0vaXZedPn+ato3U0g8bLp1p3SQ6KIFvO8
         b+RpdzSz0ZOFhnp+H2NNB9KIALf6twCrmHowdB+zKmCkrBn3QDoDTxcSODb0MGVm4HwU
         qBJEszVeIOy9jjiPBck6fBUmaOgScJ22gwUNZfz7/sof+H22lj/4Vzxwk13y23v8HXKX
         SqyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H4nb0qeu;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id x29-20020aa7941d000000b0056ca3420e5dsi213250pfo.6.2022.11.04.10.34.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 04 Nov 2022 10:34:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 740F2622C1
	for <kasan-dev@googlegroups.com>; Fri,  4 Nov 2022 17:34:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id D6E69C433C1
	for <kasan-dev@googlegroups.com>; Fri,  4 Nov 2022 17:34:08 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id BFE71C433E4; Fri,  4 Nov 2022 17:34:08 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216660] New: KCOV: don't fail own copy_to/from_user
Date: Fri, 04 Nov 2022 17:34:08 +0000
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
Message-ID: <bug-216660-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=H4nb0qeu;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=216660

            Bug ID: 216660
           Summary: KCOV: don't fail own copy_to/from_user
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

Since we added failing of copy_to/from_user KCOV may fail own reads/writes:
https://elixir.bootlin.com/linux/v6.1-rc3/source/fs/proc/base.c#L1400
https://elixir.bootlin.com/linux/v6.1-rc3/source/fs/proc/base.c#L1425

Potentially this can worked around in user-space, but this is very inconvenient
and needs to be done for all KCOV users. I think we need to not fail them in
the kernel.

I think it can be done relatively easily by setting task->fail_nth to 0 for the
duration of read/write.

Reported-by: Jason Gunthorpe <jgg@nvidia.com>
Link: https://lore.kernel.org/all/Y2RbCUdEY2syxRLW@nvidia.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216660-199747%40https.bugzilla.kernel.org/.
