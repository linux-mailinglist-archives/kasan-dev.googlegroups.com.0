Return-Path: <kasan-dev+bncBAABBHEDU6WAMGQE7GWJ2CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 05C5E81E1E8
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 18:53:35 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-40d4a29dca7sf27604425e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 09:53:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703526814; cv=pass;
        d=google.com; s=arc-20160816;
        b=dWPvserB4pasjy8yAS6bDj8w4ZEkNU36Gwfj+beBliUfJxLnTwLet17NKKHhnM53kj
         7D2HTIxTMe9pzxH+2MBrKL1TFQ4ReALycn/1isE9KYKIgfMSBnChCkkNxjXW89+KEwOP
         2OnFMz2qEifE9sNjg2BUjozpZJimA3hmPec4NruqNQcOPBtRTTbqBCX6dzJ2de7RvfQL
         D6UECdt2HNTdXwwYHPeqJ3EbCLR5BMM1nwRbsLZwYCdhFBDOfIT+yN6mBzFAWRXeR1v0
         KqN8es5Z1oU7LkAwcFv6sKYCeA3vRjK72b6XYO2puGdiSpLdwjbggEv3ujQVyf6OiOCc
         cxKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=lOlk7XMk++MiPTxXUCrcUoU6xjhJ0PGakFq6elT2ZbY=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Ylrc04qXuATASPG/pHWtOg/YxQ4HgRtVX/o4Fdhn3KZPGXdokhNCbfFzDe3MZwFW1V
         nemeDBZLME9RL1KhXHZ3gomzNdskGy87jxVqiun1V64IQpa42xLQn0cd6HkchtRNX6zP
         raVsX55t+jyE/DOA4kJcYYLaZP3DExi6RwP6dKt/IrFwUMm5TgH8+Wg0nZJ37xfeF+oG
         D6pbCWLdFnib6rVn02zwqqtOJs8xkrZxdYGNsRFFNnW5ii3SpI5xOKwGwwtbEC8yLQPs
         KXYYM4am1cFiyFskDtiCGNwaf2Ryn/qYZ37PYnLfmqPO4y6msT7UQQdrFLtXFdHYIkLi
         sdsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=obCTe8XK;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703526814; x=1704131614; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lOlk7XMk++MiPTxXUCrcUoU6xjhJ0PGakFq6elT2ZbY=;
        b=h6bbEd5jL/GyMxjb3lnm0x2Iqixvtd8lDCZZIOYIwwKwwTM01MxPrcvo61Pz5JFmI1
         x10oxvICFtYZVD4ndWfBuGKsi2WwVxS82i0FtuT7WfjxVxfeJgov1CSXt1GHD7kOR59X
         RFGTUMrENrdGOYSlfeOhg00BMieczk8geTxjjCTIMJrsfF5jJsAQOQGAF/qtjKZS33rE
         s0tk2ekPdpO1RIXvEAb1B5W9s0EcIucvfCWAXXy1JBvG9gAnj5M0RXYkTUgGpTD4XN7F
         QlhryNiJ/1MljNh2pv282Laqd/D9AcyXO3bl9oIxGPI4wP8m0kDRD9QyRKEI5BbEy/lw
         7fPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703526814; x=1704131614;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lOlk7XMk++MiPTxXUCrcUoU6xjhJ0PGakFq6elT2ZbY=;
        b=Hx7pUyxvb3svxKGekaWHB4pDtaM3BzqsEXElGD+6lEfLErilt65kJcnzLTuttkVFs1
         5wr/WyhTwEMYGB8CNZBoC8dxU7yhEFeV6g97i/agTHveRyNAwLLf0gd7OTZNJPGJvpvO
         pKYHKbO1xT3i+QgOKtIaaFpNTyk28mPK0y8BPNI4GFC6FtqY2miM0LjJjPIh+v7cUMEY
         wNcVPWrzM8QP/wTOMAAOz6BDt9M1U7Ou+0pRdpI0fdP0rGFjx701L4QvYfM9mbSfZtj8
         u76mbbCSbJwKfCBjYymGvcSZsBqb5/PIoQiuFPUUyzQRZTXNcn64mks0F0brJbpJ09nC
         YRsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyNvp/I1Mxq2qRf53sfIOP+Gjb732MkmifkAeiYx5/l2nbpn0T6
	zQQVqpK7ghZuQad66vLg8iE=
X-Google-Smtp-Source: AGHT+IEdfUHzKaUhBggcLN+nvZM8DOpgZ/xpMBRl/K2vOhudFdjidD2I5PrQ74Q5Z4QNoD2Ot5TslA==
X-Received: by 2002:a05:600c:695:b0:40d:2376:d4e6 with SMTP id a21-20020a05600c069500b0040d2376d4e6mr3347989wmn.101.1703526813126;
        Mon, 25 Dec 2023 09:53:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c13:b0:40b:2a5a:203a with SMTP id
 j19-20020a05600c1c1300b0040b2a5a203als72263wms.0.-pod-prod-06-eu; Mon, 25 Dec
 2023 09:53:31 -0800 (PST)
X-Received: by 2002:a05:600c:b87:b0:40d:3a10:3d98 with SMTP id fl7-20020a05600c0b8700b0040d3a103d98mr3452363wmb.139.1703526811617;
        Mon, 25 Dec 2023 09:53:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703526811; cv=none;
        d=google.com; s=arc-20160816;
        b=jWSV+sEaDp6RBozoy9m85D4hTg6EfQieGrj2zr7vpi1g73rINyfqn8AFjZaHAkKAKi
         H1fKpbnOmg6ytZeM8HC/nfI81mzdm540N1Un2fwEItkfq6rXrtU54ZFgRG35KNVcZQAs
         Vo//NNnuS5T8+j61PfClV9wDhTzvlpg3NeUS0+AuNnJjO2TFWW1X179EJpNCpU/gFIuP
         CMmp441i+J4FidqEq8jtCgY1rDQXfNZsqpHs26AItk57Vi4LfyjVoV+sDM5O7GBzfqwN
         0nbGCTiodmu1i66WmcM6kui24GUrv/Aa8GESqBGFtLf7St/TLwweRKkcZRODS69DWIT0
         i02A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=pBeo1+Q51R9S+FStw6jAZp4VLpbVuxHKoOBOQwqKECs=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=zyoGsp5YoHCcCBFYxEme796/nKfwCiKqFuL7t/Lild9jK+vynhdIea/QnnMQ9qou54
         3RZtKEmYOnkWeKojRUiIp6+6HgpI0D6sZUuEg7MdMEVwZ4raUinvoogTIWgkFPhfrR8o
         shherMyoU9udmHaDneUEiJiYlEuXObRyBdSJxVX+xqcYz5GqJ3u0iCjwQgIS0vQ2zu1u
         mMy7iLZztagKQeu5PeYCF/Y/j/T9mmwAswF2GIOCNp1h+qxA/QuES7Wsh0Vifqzva6sF
         n8AabpyCWxm3Ms2GDo1z1nkDLIiGQCP9KUZCDj6AcyJVBmo7VZpZ6GR4nBujI83YHf8e
         T8tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=obCTe8XK;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id j24-20020a05600c1c1800b0040d3d072c75si266384wms.0.2023.12.25.09.53.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 09:53:31 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 3B617B80AD1
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 17:53:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id C6886C433C7
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 17:53:29 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id A91E6C53BC6; Mon, 25 Dec 2023 17:53:29 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218316] New: KASAN (generic): quarantine page_alloc and large
 kmalloc allocations
Date: Mon, 25 Dec 2023 17:53:29 +0000
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
Message-ID: <bug-218316-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=obCTe8XK;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218316

            Bug ID: 218316
           Summary: KASAN (generic): quarantine page_alloc and large
                    kmalloc allocations
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

Currently, KASAN uses quarantine only for slab and normal kmalloc allocations.

We can also quarantine page_alloc and large kmalloc allocations (the ones that
fall back onto page_alloc) to increase the chance of detecting use-after-free
bugs in them.

Adding quarantine for mempool allocations is questionable: most of the time,
mempool allocations are taken directly from slab/page_alloc.

Adding quarantine for vmalloc/vmap allocations is questionable as well: they
are unmapped when freed, but the same memory can still be remapped for another
allocation.

Also see this somewhat related issue:
https://bugzilla.kernel.org/show_bug.cgi?id=212167 (KASAN: don't proceed with
invalid page_alloc and large kmalloc frees).

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218316-199747%40https.bugzilla.kernel.org/.
