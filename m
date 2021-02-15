Return-Path: <kasan-dev+bncBC24VNFHTMIBBRVAVOAQMGQEVY7MKLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id BF94131C2A2
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 20:49:27 +0100 (CET)
Received: by mail-ua1-x938.google.com with SMTP id t3sf3609757uaj.14
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 11:49:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613418567; cv=pass;
        d=google.com; s=arc-20160816;
        b=wgvCCsFdXLsEki5TTFg8S/yM7MbePOoPj9a4rvVvKE1DSrOvFJzaxzuCtgflLJlmwf
         AXvWeTDU74/oNHUwk8CJeWagmn9VTMqg469ecDSIgkO6ry5F33FEeeThR0g01J9gUaDR
         69amnA4oyHBWHzzkfy/KeHJOv2bbVkCU+Xjt+wKK5+fM3K/vuW9Hxvx7nk561LdWaPT7
         KCsVhyQi3JFmturDAKKfwYoNngsYCKm/O1TXKOEPHwT6L6PATTk59/9bzD+PlUmf/xxM
         qhSODTNwjUCt9XCqJHiLVyNsn/hk9Hrcp17IpX0xZ/rLwUgfKFUQn2oqeCZ6fGqSaNXx
         wAbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=E1glizTl5MlmPugybPfv/Ray387t5NYJWHiPrrxQdto=;
        b=iZcobgqzpJZKNslmQ+LUwdX7oDHSZ68s4EtKGXRZ+tyGkPoSi0MJg6mtrajApHz281
         mskdnuzD95THzz8sFsr0xJjKpr4ayogVNIkqPqMNse/sNnGTXjgIkticd69Stm4g8Qdy
         T7c8HMfwTQ9s6FrNLBlyG3N3WOHWQSzyoQI8v7z+uZ9YvMEc7swxiCtZ2G7iqs78eUQ3
         jWBXrLrn2yjsUEtE2wROfUOfhlOuSrIAM3C/VOKlzXg60xrjmkhGEVtsrPf8zmGIUm/y
         her2tdXeCC4bqqYLM9eWwAVtDMwkv2DXk4WdG8Mk3ZMMXxbERtDNRS4Ifrf1BbX5jUzg
         74Xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YBBmBsoI;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E1glizTl5MlmPugybPfv/Ray387t5NYJWHiPrrxQdto=;
        b=ggdF+ncyLzlEtAFVSPZ/z9Oj4M77mcOtf3b2eqBGZLccHNTw3YccfvdAVl/HLjKVVD
         xu7njZdu9PPcpsQ+O4li5jcMuGfpqlOOa0OSrGL0gQu0y555jWWdSRz1FNZpftpFTKcJ
         xcMMWN95/x9nLVt0UnuaAVjBcZwKpqsgc4GAxq/0SZeiUEEq++++8sY+1xMutBMqNABS
         2D7Yr4lLm6Gl5agXC56w3uoPaE69jkee6zLe8GRy0gbQa+0clQJsfFYoECu1k4rP4PNr
         0NpcHLV73OiDqIrsx5BfxE4EJAgGUfJgh/u+f5jt4pcUlQj94DlsSufMBqFtPkCSRSs/
         kaWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E1glizTl5MlmPugybPfv/Ray387t5NYJWHiPrrxQdto=;
        b=GQfLZkb3cCkcOJHjOETmChs4t/icnGvnXi8ZYKxFGhlEuoUeE03FEqHAkkIYjLC5++
         3Wi5wzyboKd7enrB78XHWyJNJNy2i1zFZmccJdjMKOMFZSsW6jKvw8fY40OdkEY53JtH
         NJwm0E7oVoKMUJIjBJQ1VpDm8rbAcqotZyl2fl1bAYOiwYHL9GNLuw6j2rPwA0Q0UkC5
         aQOiXli2GRAw8GkyuPymCqySIrBjQu0U+pwou8uoMJsBOJZJYlDjtSZnEueox1RMEqF2
         G17Ud3RkiMmbGbXzRlAU+W4JfoNLnawYy33PoMpVZBg0vL9WzVaMId2nd6y73tsr75p1
         fj4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Y/FLVxhCa1A9UzY+v8t5PehX1Ner9/flrVwY9qCMDoQd2nBFF
	lBaMtLNhHnjjbPGn+1uuq74=
X-Google-Smtp-Source: ABdhPJwu1SPI+rcFztYjgZCvhRfA+MYy/SrpBcDFChQuFF7LauK7CQzrA+uzLbaVsH8RjNOSKaSKgQ==
X-Received: by 2002:a67:c89b:: with SMTP id v27mr10033499vsk.5.1613418566823;
        Mon, 15 Feb 2021 11:49:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2f92:: with SMTP id v140ls1984427vsv.9.gmail; Mon, 15
 Feb 2021 11:49:26 -0800 (PST)
X-Received: by 2002:a67:7c95:: with SMTP id x143mr4195295vsc.1.1613418566408;
        Mon, 15 Feb 2021 11:49:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613418566; cv=none;
        d=google.com; s=arc-20160816;
        b=Tt5b8mu6SitzopvXZ/gutqSXCeEXH2+tcKNtwBwks2ZvKUaPDUA2/sNS19SPo2MuCD
         DgvXfbjhsd75hwZXBgpirZged48zpZd018QHLdUC2o8mKSbw15XmL0DOhNMpxY7t6RqB
         EE2Bd0qKUtfrDMRcyPzJKxHo/3hxbbEX0B3haIQdjoyndUaKKER8hU0VsGs4ahbWS6yQ
         7kklQ0/gDglhHMJf+Dom28XEKx7YOjU+WbTymm5TOUb+FH8HQFfa7ivCdaE7aI07W1t+
         uiI5bt07k3tK86kfbYKnSJ3lJqJBRn9b6vntsy1oOZbzjpPURADlFm75HrQpadRoXMGN
         Ciiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=TBPH9NH1D8tcfhurFlh1GZipI+sZ9m70iJoVYcNgo9A=;
        b=KUW/aeecygVPXVY1LmzdMlNrk9uowRD95ac6z1c2k4rj/lwQg/RlDRin4W3uqf0fyQ
         /Q4j5sMfde61k0U2QvCPuvwTvCBpewvf7ByLv4tUC7RVnBpigAtjktkn4YkV5sqHL1GO
         OMhSVwayFvfH3tq55otkgeykTXaLlKRdCpGgN4u7omCJixKDrHokkNFHbTm3ot1aT1QS
         rv1txpKy44CXnbmdllvUz+HDkJybTq8AJisqKQQKKPZLjAnvgaCf4KVNl7aqF4Q+1vW1
         9hIzyzwtXMVDxkw6K2HsCevov4rGSmgtLA2rbDEP05DSkm7ZKGS4rpFgkVUUTz411FOJ
         iX8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YBBmBsoI;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l5si1178565vkn.3.2021.02.15.11.49.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Feb 2021 11:49:26 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 5F75A64E1E
	for <kasan-dev@googlegroups.com>; Mon, 15 Feb 2021 19:49:25 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 5C154653AC; Mon, 15 Feb 2021 19:49:25 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211785] New: KASAN (hw-tags): production-grade alloc/free stack
 traces
Date: Mon, 15 Feb 2021 19:49:25 +0000
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
Message-ID: <bug-211785-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YBBmBsoI;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211785

            Bug ID: 211785
           Summary: KASAN (hw-tags): production-grade alloc/free stack
                    traces
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

Provide an implementation of alloc/free stack traces collection that's suitable
for production use with regards to both memory and performance impact.

The limitations of the current stack traces collection implementation:
- 30% perf impact
- Stack trace handles are stored in redzones, which doubles kmalloc allocation
sizes [1]
- STACKDEPOT only saves new stack traces and never deletes obsolete ones

[1] https://bugzilla.kernel.org/show_bug.cgi?id=209821

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211785-199747%40https.bugzilla.kernel.org/.
