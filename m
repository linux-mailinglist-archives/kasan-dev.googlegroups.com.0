Return-Path: <kasan-dev+bncBAABBZMNRWJAMGQEHP552OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 48D4A4EB2EC
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Mar 2022 19:50:32 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id v13-20020a056512096d00b004487e1503d0sf5578308lft.4
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Mar 2022 10:50:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648576231; cv=pass;
        d=google.com; s=arc-20160816;
        b=pjADuK0hqOf8XypBiMbt1yPg9+gO/CscZAErHm9KPhOhijWfz+7T3uCX08ZKMBH0TT
         KAZi9zDD1u4TLmkrWLIk9ktYaqiyRsKEz64YyPCeRFQJM0W1eO0tLsaCCxiP7ISiz0/V
         9gF8q48cKTcsEtlo10MAYct68RLLjFPVnh/EszTTjZY7V9nt03lER3Lad61dKBysPjBj
         gTVeenAfFBYGj0lzUqN0ju/pSwIrvHAOhg8bDDcpXf1ZSvUcgwrhSDZKgyULAyfu7pe2
         Hkn+rradfDoBqE/z8mTVOt50Cb2qfHXNv7I6PuCwu9Sr9dcbfRqlkTO9Zz6qJ0R/zEYc
         SBfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=THkRaxB0jSV1E6iwcQCjwEkWER7oCwnUNOYOp0WxXV8=;
        b=gwg1jxPmZBlM6IFy7yiSfbRApIp6W0MQA92pqKujwxi0EHGI4ATBF6hk+/UJdOVveL
         bPMkf1WTHT36RLH8Kx/PEEZ3cUotDKb/WDId932vIitEPVhu/JzZuoW2c2GAfES1kBJO
         GuPlg7ozw03YqTL+6z8kDMRsqwEL3upTyFrSH56jrey+1z2GNseQ54VzZZlMaL6yIRvo
         FFILROv+0T8AeN0HlEL+QkAck72FIjNhov3VMq5alu3sVkNxAVCtkYYrWw70nnTIv8AI
         +0XkQYxHKSDjFb5Z1RqhzFgmU8GctsMlEpi45MaPk+JLNOYYk79qetrK8wqNrhijSb7X
         GGVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ioI2ynK7;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=THkRaxB0jSV1E6iwcQCjwEkWER7oCwnUNOYOp0WxXV8=;
        b=tyWbMArB8pAAWnmu77KiLWjh2gwm9Vw6tTAiSQO1bI7D+4UEhAhXv7AY+L4wv8UYZZ
         nIPu93g+3OFw34GkcWMak5Tk6gxXJXe/8BQyvpV9uUTJD3q1Ue54HP08fo+GFCWGg1DK
         LMidD5wDlB19bPUiXkea6aEgdSyFXllrIH+XvUDx1KMIjR/fGSAmz6EXFB8QKXeLEngU
         jqvC8ia0TKYZ8Q/Ym/BH/jygMtdVFFP58LalI3uxr9cHmY6NbOZzDUH4+99JzabPSea5
         JcsTSzwB5fM0Mo1RxIfDqEw8lAoY/YSja0CXh5RrYC++1rTQ/J/eQqqh2G/SHSDzBCku
         pNVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=THkRaxB0jSV1E6iwcQCjwEkWER7oCwnUNOYOp0WxXV8=;
        b=rdUGtXYPPtal8gQ6Vikzocjrc1a7z8w6OlgtAz+BSc9fw5i4Dg5Rqt2eetytZpFUz1
         CguZXMFyXRbKBspI9XT94ApRpOcaRCjlYrjIlqGJvWkHrA9YWpc/p6Q2IbLPAs7S5nZy
         Lerwwa/I3/lfjw1RBFrJSLxJNYiqYhxSW3gZRetFVct4/84ImDr/8Iva80zN6ai0N5gN
         ooaySVU+zUfcVriWBaZmRU8NH8Z5/d9rRIOBGIA1y6Lr/7YfL0jGOW13H7ki//Id5F8J
         HwS+tN7M+lUnoSeDGk7Rmnh00MogbR7f/S5ts16EPC7UtTHp3Cxn7FgMCVJiN8mIF0E6
         cQww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532u0TAW+HnPIq7Rs6qZSr46f524gWQ89peXKEvNUWFoiakOArd8
	KqvjsPgWaxOYW5JFNZFWBlg=
X-Google-Smtp-Source: ABdhPJyDIx96IL2g6iJW7xmNtIY2E16/jn9COVbeLb5qLse/d/GTEFnQNWq1AlKx4dlLeB8+iqnUpg==
X-Received: by 2002:a2e:90ca:0:b0:246:48ce:ba0e with SMTP id o10-20020a2e90ca000000b0024648ceba0emr3778928ljg.401.1648576229758;
        Tue, 29 Mar 2022 10:50:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls7688147lfb.1.gmail; Tue, 29 Mar 2022
 10:50:28 -0700 (PDT)
X-Received: by 2002:a05:6512:304c:b0:44a:5bad:820f with SMTP id b12-20020a056512304c00b0044a5bad820fmr3749687lfb.68.1648576228891;
        Tue, 29 Mar 2022 10:50:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648576228; cv=none;
        d=google.com; s=arc-20160816;
        b=H/liPGFa5+OWo56jyfxdhv5p7+1ozKVb/MO21AiTKn3utx0NyLIB4fwTgIiVPCpVjl
         tDLWqp4YZWHT7l4/SNNn3tmIRneYhiVeA52iutlp2PD6XjKKa6BwTwJ9JNd/8T6jMxcK
         njt9lvrdx/ERRQvyYquoGvccwKpp2VY/G1ilQ3U4pcYpYS3zAJr2vMmXBH20TSTxjqq+
         3a6jgjRPloibtVTSqqxzg1V5LxX5KwkUITxDCCwOObTrw9PQ08VEs3IbxGK/vkH3ujDh
         s3ljMaXDsz5pAkUbRYi0r8zoHNF9pY9ZnP5Uxfr8t17myBNr4ksXea7/mhPIrMcEa+wc
         jbJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=pdhWHx7ZInun31ni88Br3Nmm1abRbyRLC0vMFPu9CQ4=;
        b=Z4UthUCYjTwvawFO1FhtrTQyNSBXWcuN0kbhyjFYVv6uV1VMYbBx7ilhRv9nkzupAE
         8BxXCqshq8+n6T0Jcyv/tpcOFRt9dbfV0uC1RZPGz8bVxdwBHIc0OVSqtiKNwEjwcrO+
         eTatm5GXRGB1jpHEB8SiN59bpmUng9DrRyicu5cFVMu3Pwva/1Ci2w8JS2DoVFCUzdIL
         ueVmW8Vdp/myOIN/2zneLM/Z9z+gpu+8Cx/Kvo0mi9UtCJcRUyzgIJc4dPtyrW/qmC9n
         lcAREGoSxFKz8kMaAzJatVQmsKkhtBK/LwMeW7lq3Smlc3I6I3B5GsipZMvX3yT+NM4+
         4sqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ioI2ynK7;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id w22-20020a0565120b1600b0044a9928e3edsi307947lfu.10.2022.03.29.10.50.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 29 Mar 2022 10:50:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 494CCB817F7
	for <kasan-dev@googlegroups.com>; Tue, 29 Mar 2022 17:50:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 119C5C340ED
	for <kasan-dev@googlegroups.com>; Tue, 29 Mar 2022 17:50:27 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id E2B14C05FD2; Tue, 29 Mar 2022 17:50:26 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212163] KASAN (hw-tags): support KMEMLEAK
Date: Tue, 29 Mar 2022 17:50:26 +0000
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
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-212163-199747-VaTzxzgWiM@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212163-199747@https.bugzilla.kernel.org/>
References: <bug-212163-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ioI2ynK7;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212163

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
This is resolved with [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ad1a3e15fcd3b8ba0f5f60f6a2fe3938274fdf65

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212163-199747-VaTzxzgWiM%40https.bugzilla.kernel.org/.
