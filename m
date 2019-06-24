Return-Path: <kasan-dev+bncBC24VNFHTMIBBBM5YLUAKGQE3DZOJVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 38120504D7
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2019 10:49:11 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id w137sf6082400vkd.21
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2019 01:49:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561366150; cv=pass;
        d=google.com; s=arc-20160816;
        b=0gQgyXZqWlFbMdeSiuqZ6Dkg0If3UGhZ7eKdKQorJWs89e7ToZiz97CgWm85jXo46H
         VnFgLBbkW5AP0Hq4vYlaYNKUprwY/2mYmMuYi7TOzELyn4m/+xRKD1b3Qda8H+d73f2U
         nH6vZOx07jC90KywuXfjXkDbe5DdNMbWmqf6ie/CVaj762XCJ09eM85hA+OCqvRCOuX9
         BXPcq3VGgBW6ofdSvK0e7Xbd3vV5yAWqpcr1uRPawOWxI0tlhlVYPg74polGyg06Qyft
         r+MRQwZHazHjW83++LN9aQ31MEMRbrdiu0EJUHae0EpkyPLY1WR1w1amfEtj7maJaAV1
         sfRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=6dR7s+1aJ/mAxH0BzKLw3EmmHwh6Apki0AJmH5+lB4Q=;
        b=OAEgNdxI8qj9m3Y5tJUxuR7qycbxXMkDU6qTJ8pnCZdTiU30SbHoJblVok6grwc6h3
         1rIERUi0Q1360ObCMf1+ykRaXuidMPcslC+TpIMnOivysWGMLCp7HUcP6qbZtX2y3QNY
         CWK/PLtIcVdIdnL4tkrYPNdEDr2vxo9C0XApMwQG+xHPqIiAqSC0sFIgufWgCOFMsG4s
         oIWvPB5OVbfliMRQcWMt09HZYc16WamhvS+bK7PodachwVgDe9w5pF6Wj4MqNhOL1Ymu
         Fh/olCp3PtKBV092pLYbJ5fYMKOslcaMhwUI3s1C9RuyL/54gpfBPS0FM/pQuw2P6ZQH
         NhNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6dR7s+1aJ/mAxH0BzKLw3EmmHwh6Apki0AJmH5+lB4Q=;
        b=KHojU7KrD2zKqOo3aXYwB4F6j/XcWxX3LdaK9THuyRWdVdorAvWPxMz2huQ043mWiV
         2XbQat7eb3IZeO1nBTZ7+FtB4rw/377cpTcWXdA9U+nrE0NvtVgD9v7j5hxyipv+nEYb
         cV4/oE1l2htxmiUBgF0R4qd6SwjtI4eerOximfeYqxnkztNWTdAYJWcOVuPdaDqRC+ib
         5wlUur8+Ih6Qyzs/F8irOPUnrscqMoRMG/totc7xV07L6qdGA4v5tbn2ihePTgda/DZZ
         vDJfs/ncHxR0HJb4qHhal5TYxVF7Y9gwIjZUzOhi3Sz1YrlgtDtE3Y+iiTBQBSAQS+HJ
         Lu4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6dR7s+1aJ/mAxH0BzKLw3EmmHwh6Apki0AJmH5+lB4Q=;
        b=qVgLKky/j+bB0FcOj4S31D3IVFpLf996u+NFNFZ7zKP7TmZTEUus3+Xhgi3Afhh2Hv
         WsciAWNF8JVYIxQtEkUchTrscWt+FQuejn13fBlUaEgQaXiOSGqB119fcmTMdS5YD2oV
         NUdOTtHs6xDpxY44xzGAkvSSN+i8KmO26gmWHzWplmS+DAUHztLNbpcFlDEquQbN0b/E
         6i/SuuH6yA/vqMJ1FVQFCwukqYRpYEfnSIGkplb93YquQ70vfhxOYa9eQPtgA+BQZ0nA
         JY5c7aSy/0Mgz64JdWfYbmnin+chWQocvwWEmn7zX9Bi7UfiRALISkJWttXwFj85zwPN
         a4CQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVkW54/9QcsZs8vBADO+ReJgA+0nPuj+lvuoFV5SKhKHSZDUm4G
	ZEADvgiTolEvVCDbCnlYcsQ=
X-Google-Smtp-Source: APXvYqxNMXMGrFaAXAJcAWG4sMxXBnuvOzZ1hrB1CDlBniHw8JAL0OLIwuySyz0VAKuyqWEUuJ6dAg==
X-Received: by 2002:ab0:18a6:: with SMTP id t38mr776224uag.83.1561366149871;
        Mon, 24 Jun 2019 01:49:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8782:: with SMTP id j124ls1583121vsd.3.gmail; Mon, 24
 Jun 2019 01:49:09 -0700 (PDT)
X-Received: by 2002:a67:ea44:: with SMTP id r4mr7648vso.86.1561366149692;
        Mon, 24 Jun 2019 01:49:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561366149; cv=none;
        d=google.com; s=arc-20160816;
        b=nslmT4nbOcjVSdhGdha37korI61FsqkD2AFOKHigz/XG+d0cYEMT46Y11cIhiSPmMs
         hNSkABE/h4FT58P6Ygb2yfTk0z1ttYudb/6lBUgRpVzTuP2HV1xTpQU9hkbjYNmokIkY
         3Htp9wm/3xq7vK5oHZNPJ/2Tre5AHh9C1TFq3UtKXizO3JKt3SztZH+Ezpbra5Ed0AcC
         Ad53XFr7qZe2gk/23PbzuBFO4WzC6KtXBP9kx3LLRQkbZmHFhvlhhR3gYJSGnj4jVBF4
         5joQFd+v2qLr0Hc9sj5wohKJejRixxlf87dFe7NmwmGVlWqrfvHVmb7ezUbqgh9Lu2wn
         FZKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=teosAZwrsKB4lPct/HGlO7jLkrcvuux1R4pExZWaYes=;
        b=Uodm3r/83IkneqgU2/weWBUnlvQo5fzOz9IHRO8bjUXxAJHQu4unrHKPWyJAtf9Z9p
         JBMcCd/To/JFFy9zUktJhDl0qYJziqLBCdR81zQYUphjqmSyiOAkXENQNwoE/aYE9n5S
         Z3/+tleBRZSsc4h+St03FO7zrOcjKok2s7Afu4uo1kefPjhM4vD5WE63xUzcon5Uc6uI
         uuky+Rr+Y71s1HmnPmaaygKem0AlQMV5BxQDxHKqv2cTf2m81PkvEbe6GktnlJAszuNA
         dyi1pOpRRLQAvXBugw9hIziGsOGFhQ3L4IQVaBl9WIugkAlP1Fmp1M656haRSZyEGxhd
         3s9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id 192si100551vkc.2.2019.06.24.01.49.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jun 2019 01:49:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 79E3E28B8A
	for <kasan-dev@googlegroups.com>; Mon, 24 Jun 2019 08:49:08 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 694BB28B80; Mon, 24 Jun 2019 08:49:08 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203967] KASAN: incorrect alloc/free stacks for alloc_pages
 memory
Date: Mon, 24 Jun 2019 08:49:08 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P2
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: priority
Message-ID: <bug-203967-199747-T3qJ3mlvpw@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203967-199747@https.bugzilla.kernel.org/>
References: <bug-203967-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Virus-Scanned: ClamAV using ClamSMTP
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=203967

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
           Priority|P1                          |P2

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203967-199747-T3qJ3mlvpw%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
