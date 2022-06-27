Return-Path: <kasan-dev+bncBAABBGN34WKQMGQEGHXDIDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id CF92055B83B
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 09:34:50 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id m17-20020a05600c3b1100b003a04a2f4936sf1175411wms.6
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 00:34:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656315290; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wz/s/kGDs1rqlYxQZF4kgE41awm8A486QWsFTQwdse6k/ELLCE84lAhXqmSrB0EHuR
         aELCu2/HjYDPkTd3Jah5s1F4yxf6/QMD1kgl0SyAKeEUMD3RJZ5AOFyLBxr8WXJXUOXA
         UPo+Z9wqdHUSXijVILm9erVj6S4mVIMyMKYCYj9VG0i2U3uSvGA59rC7KZN8qjc8fc/H
         g5Tzhea0loUJVphDQadNrmfkAy9LqgtU4bEhko4iUV5o8V0ONB+2vGt15iRdbPO+I18m
         /FZ9KNYIxAfu3PoREhLJnoLmj6cAW2IZ5ZvsXiyGPmRftoacsspX4R7H0mntmWhFtPaU
         HKOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=DieN311Lyyvidtu36IC3jnl0nHHUBgcQBAND1Rr0L24=;
        b=Ok7JsZitbDPtAPOZMKP90dkqTZEQvL9+JRTm/gTcCk6J2UUVDpBgU5Zf+5LRHSkGfm
         Nk7c33lsN4//wtxg9s7SoUKk/tYpyLxXkqfuBzKDmcFZ5igazdb6rn5zOEjThAmIU5bn
         DqFZwxn/IjbFQ3M/HETEA+1B5e5t1soiCd9MVTTCj54EXj8Gree42ltdHrTKvn6cEzhu
         d4BJmBXBt8wrR0AcTTCSrucmHdc6mQ01LoFu5i9voR+zeEDeII0Uut2CwOYuFU5RWj2v
         xQMQOUbLfuzydz8esoREwaDRsqxPAAPh8ffGuZJlxQeDu6W4m6gQSbp5o42jhiZKgrr/
         kV9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LSiBxu+D;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DieN311Lyyvidtu36IC3jnl0nHHUBgcQBAND1Rr0L24=;
        b=Md7WMIUllHD37KgAXd7rfhuWC0H4V8FYRRxh6nNWCtX+1KUcBEAhvEru5dPYM9qHhS
         ZTZ3mqjWEWCOWrv5OK255Z153rEowvpr3xOgeLeajzvtHTvPj9GDEWBHyMLMCDhSmYBT
         3zgWh2cpzbekG6F8a1MLPiPlChYIDgguytcINnF24lE6Pe2Ygd2tplugv4TXKhyUh6gS
         GK4/6CyC+zRePuTTcvdJlqCNzYcBQyVE87l7ATfxLDTUDP3hcR6+/UZCH9lzMScfqmeO
         eWhVxNj+K5C6kF8XtaoueasgopnKfZRJ6S8iL7u05BLFuxLi/jqgpgMdzyF16w4OyoiC
         5iLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DieN311Lyyvidtu36IC3jnl0nHHUBgcQBAND1Rr0L24=;
        b=v0E0IL2kUT82uyPUOz4osarwfWoMnNg9ahnpPwnw1b+WeNHs1KneNqJd8a1KXeLi3P
         JoEYSwEWXxrvVgbCP3lHDRvZhs2vKANuwpu7Zfo45AHNKg+ZgeXBvYLDOMhRNN11HRgu
         qPlwmGEZyBKzviCJMrwG3CeeXTA/D9SN1oe9Lz7Y4eN5CQMIu9N52TdTex8LhQLAJUdF
         Qdn9Di6GxHAXjG+72OVcgcjggzaXOoj2//gxo6a1E+Ayr7s7MTfeSihg5DMNWcqKyRtv
         iaXMiNdviDEgOpm3Av20vxpAjzp5caXjeDd3Q8YiK0wLA3eVPuLn3fX1rQ6QUuCfHXXi
         3VAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8ayjy7+BTPraApAHGV5LIr42MODBFpa2HfZ4LDFJIJaMc8LALh
	K0XqdZDqRUXIJRoZyaMFOW0=
X-Google-Smtp-Source: AGRyM1vmmxMdnUcz46onTcVXNHkFj5YKAfE6FE0tFILozwUp6JBIGC+ovZ2GThfecvfh66MCv1IUKg==
X-Received: by 2002:a5d:5887:0:b0:21b:c5d0:fd4b with SMTP id n7-20020a5d5887000000b0021bc5d0fd4bmr7195770wrf.244.1656315290157;
        Mon, 27 Jun 2022 00:34:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eb04:0:b0:21b:b3cc:1640 with SMTP id s4-20020adfeb04000000b0021bb3cc1640ls11569184wrn.1.gmail;
 Mon, 27 Jun 2022 00:34:49 -0700 (PDT)
X-Received: by 2002:a5d:584e:0:b0:21c:ea0c:3746 with SMTP id i14-20020a5d584e000000b0021cea0c3746mr2685284wrf.199.1656315289439;
        Mon, 27 Jun 2022 00:34:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656315289; cv=none;
        d=google.com; s=arc-20160816;
        b=DCQQOiuNzw0Nkl3K7gFDXRR9doFaSp/M2aFphjqAjH6tRLGfozlcHO771U/2aYDHNm
         gPB9xVa+4qFC58zUZV/cZ0Nkc1E58eHR74hgF974WYfB4cWBbs7sL26lQFCMFS3+ZNWD
         WHNsRcVNViG0lJRjy9YEtPFEzDDYJmzc689kp8a8G1oei6EAkw2+fLLcVHqvtwmnUqT9
         xzE7tSIm32/cOXrBtYc9wsk+k7tfZWY3yp3czzJDZhttOocF5rBrLK/pCiYeW3NIwSt3
         BsZBH+j4wS7Dv2rUvPbk5TvNS0MCeDCWF05JXlz8q/FUoltYTC6B504SdicBxk2f8BxI
         Pxdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=+YOi6aathT4D+xno+DDZY8vuujVIN9YVOX/O9RLgitg=;
        b=UGyaO+wlbXLJzqpGvn7C1D7QCpulaFb94dGL7Yl+f9HfJ3W4In3TQflgK9y70Re5K0
         KqcerZkp1TjaGRlYIpe7NmR/WsCQVRqEWyel35RGptxoMNduyUH8L8Z1V1yt3Y7SWam/
         E6YNUlahIDHI8i3MznusaMBJ3SPmHh8vzepY4uLrvhL4DHUijguYmFRkHvL/uvEhn6je
         aXAjRWd4nfeFyEG4uaLLKa6g1nWdHBjn9UL7bcM3qJCv5J/4l05DdowPVanApdeMofdL
         tNjEJGj5jX4wI3kg+myN5jLC9XcTh4uvVo9Lawe3zkjdrcxchNyubd1Tc6+7oiLaIYFX
         1Ekg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LSiBxu+D;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id bg3-20020a05600c3c8300b0039c51c2da24si501119wmb.1.2022.06.27.00.34.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Jun 2022 00:34:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 24B45B80F98
	for <kasan-dev@googlegroups.com>; Mon, 27 Jun 2022 07:34:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id D10B7C341C8
	for <kasan-dev@googlegroups.com>; Mon, 27 Jun 2022 07:34:47 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id BDB61C05FD5; Mon, 27 Jun 2022 07:34:47 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216180] New: KASAN: some memset's are not intercepted
Date: Mon, 27 Jun 2022 07:34:47 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression attachments.created
Message-ID: <bug-216180-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LSiBxu+D;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=216180

            Bug ID: 216180
           Summary: KASAN: some memset's are not intercepted
           Product: Memory Management
           Version: 2.5
    Kernel Version: ALL
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: enhancement
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Created attachment 301283
  --> https://bugzilla.kernel.org/attachment.cgi?id=301283&action=edit
.config

syzkaller produced the following report on commit 92f20ff72066:

BUG: unable to handle page fault for address: ffff8880789a6005
#PF: supervisor write access in kernel mode
#PF: error_code(0x0002) - not-present page
RIP: 0010:memset_erms+0x9/0x10 arch/x86/lib/memset_64.S:64
Call Trace:
 <TASK>
 zero_user_segments include/linux/highmem.h:272 [inline]
 folio_zero_range include/linux/highmem.h:428 [inline]
 truncate_inode_partial_folio+0x76a/0xdf0 mm/truncate.c:237

KASAN should have been intercepted memset, checked the range and produced a
KASAN report with more info.

Is there something special about this memset call?
Does it affect KCSAN/KMSAN?

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216180-199747%40https.bugzilla.kernel.org/.
