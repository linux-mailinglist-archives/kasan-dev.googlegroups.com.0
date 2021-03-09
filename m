Return-Path: <kasan-dev+bncBC24VNFHTMIBBFHXTWBAMGQEC6LZW5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A9EA33276B
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 14:43:49 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id o8sf10040871qkl.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 05:43:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615297428; cv=pass;
        d=google.com; s=arc-20160816;
        b=oMiG61lO4sEVHZPNOFvA1d4Gu2paZF3iJ6I+otZNM2RxcOMPRNnZO+KRQJy/5MaWMh
         rm15QtwDFcVP0FQw4JfA+NrmvYjF0+fnMkgV7zhr/h16REgv/pXW7YEatN4as1ZF0Re3
         Ci6Lz3c0gKaoDHBGBAZjC9efKjGsnFcQ4JorI57Weaz6u51R1D9DHC9+Tu7L+Zl9znxl
         8usiY6WdH5sPqBJRtbbHXb3kzK5NIbRgpNYa5XIYRqdPOZggNKA8+4ny4xL0ykmyYuNl
         xI4ZpmtspqE/g3blBqjnr0h5aZgNVkJULr7JbgkQZmHFN7Cf70c711FMFBosQK5/Sgym
         EMgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=LjVysE0QQA0fCL/3AoxMObOw4IsBfEFD5WYLXG8ojxI=;
        b=oEPI88P3o7SL2YfAT2y/RL7obiBYwgtKsFvgVcDbK+9fl8yg5J5twUPz8MSU5W6WiY
         9u3+xNuZcv6CdNw+htlyLTPiNgYfNLJLt+8uaJh3Gvi+Vjesd9SV66srOiVGIn4FLLFG
         +S97PBUCkIKniguYpoEc1t55l8GXbHGmc+Q7sIbLLWcb1fngEnbQykf+SkuMLIENquS4
         YQ/KNfxEdzW0dUEEZUlE0cs2cXkPRgJZqaxZ68v/mMIjBuBzPDn/MYUi9chTwtdIXC3e
         e9n7npG8zJT1nKRMNX/raAP/AROcX9ZBzJ+8Zc1aAxSnBzVlcl+QXsh7lz4GPSy7Qrya
         om0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VmZgcnhV;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LjVysE0QQA0fCL/3AoxMObOw4IsBfEFD5WYLXG8ojxI=;
        b=o8hDY7mkvMHzHb818Nn7sQmvHliAwLfuZYZk64gDE8JPViUN4dpam8/o1rpjNROHJ6
         qQVyI+2no0I/u1g8lDALtyP6fhzDFIK79hFoFbqu6Ll3n/MANsVTszuK1DSHR7bvYJuQ
         t6TuPL1CISoVHqMzxy0ZnH+YcIcIIhDMKg3wLO2Ds3haUFwKuyC65XfjNDdV5Y9ZrgGP
         F9bagRdd5VlEk+6eDLg2qOOj/chURqaMeLdgSR+4ysHSBhQePC6S7VKbXwDGTvxResqQ
         dbhIgx84q+MiynvkBtKCojQ0zepw8juN3H6vPTcJKC3Az1VmEY8JxsssbwZH7050zRjS
         zjEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LjVysE0QQA0fCL/3AoxMObOw4IsBfEFD5WYLXG8ojxI=;
        b=Rr2nGlayIIgRJ7TPAbo8d2/XjghYZpnfyM+f5YsJ/zOdbdIFagSCysAk8RsEjWTwzS
         e9N4bTwg+3kHQm/vHS6WgGSpd17owVmj2YTTJRn9QlI5dReodIHLfFYlByDYmdzC7nuk
         A3t8RFOy6J+jscqj5pI/mZ4zjGppAVdoMLEytYt2jvSMeDH9J+FnflbdzUpdCMIjUUQE
         nMpFCz89KU+XYJQPxsLfP6u0Sll22slOqUsVgsJ0ET/n3MurMbQLQvQB2P/FViorun+c
         A0FzJ6KU1Ftv+ASlBq42043V2e69AWaujKZj6eNhC+oxXlPdr3x3OQyP81NAV+7caXGF
         KwSQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326j2FQ8N3PxQ9kYucaN6EQKFuH2FOmCrYnKufGtxR6bD1G7p43
	jgxqZq+nh5SxAx6YZKruZkw=
X-Google-Smtp-Source: ABdhPJwQhlY/MMfeWu9IXFNNfNIobKlYk7ysHoXIm+kqeP9lKZ2TGtk1Wk5g1QTWO5po9DVgmWHLaw==
X-Received: by 2002:a0c:b929:: with SMTP id u41mr3744658qvf.30.1615297428631;
        Tue, 09 Mar 2021 05:43:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:d8e:: with SMTP id s14ls8018452qti.7.gmail; Tue, 09 Mar
 2021 05:43:48 -0800 (PST)
X-Received: by 2002:ac8:5704:: with SMTP id 4mr24726528qtw.26.1615297428214;
        Tue, 09 Mar 2021 05:43:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615297428; cv=none;
        d=google.com; s=arc-20160816;
        b=K69fCVxBgJIuZxQOcgV5o3VUEhfSTGTZl0ocz9NJzxAkTbpxgr8524SE8no0Sacyn5
         45t/mLw2TjLCB/DoDgipF9nH9r3nTMPzmk/fgpbHYcIqLXJDQkcS6B3cv8x03APsVA+E
         Uh5xKT9p9YFfjbmiOPTUi54w1J9a7zQdMBLi29VWrt25BcLEa3jT34+S3U5J6mNd1rq8
         Lea3QJlezCglwchPS/r/Ea4klgzRN/NdlMyKypscGk7zhRpcFp1L316LfZHjjYjdRZL6
         kmw1saD27Qzs/JI8GtNlPiqhXt9UK27ghM3+vO4xg/0S7ER4MQAen7S+cnF40uZdmIhW
         iETw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=myT3XFTcCo6LSac8MPIzGyXfsRkUPYj7lCtqukcSgEg=;
        b=zFrDneRqFERscKPUqBHDJ1y9v5AeR19ZbKSjXf9X3CHtgHno7tUZ5e5lJcVOBW/USI
         1tKswnm/3Told10LIt/VijToOwZpJVCBcwNzmJtqI/dhWiwJUE0oxAc3aqaJ2S3OnrV2
         fJQoDyLGORVlT3dewIAM6JXerrneR3E8Vd7i57NOzBMUZyeF7pT3ke6qoqLnwekRxDz6
         M00aTE8Kb//xurmI7M/XvBth2ROho04ErIc33TSHd7ibe/wUIRsBoStbet6JI28cSG8u
         bU1Wd7S4nE83KOSYOexW+m8eNkqBKYgkpxEHM9BvS6hu32+mMfDvgWwebpNtCPqsswqJ
         xBVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VmZgcnhV;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j10si802491qko.3.2021.03.09.05.43.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 05:43:48 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id DE5D464F71
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 13:43:46 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id C709865368; Tue,  9 Mar 2021 13:43:46 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212169] New: KASAN: consider supporting commandline arguments
 for all modes
Date: Tue, 09 Mar 2021 13:43:46 +0000
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
Message-ID: <bug-212169-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VmZgcnhV;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212169

            Bug ID: 212169
           Summary: KASAN: consider supporting commandline arguments for
                    all modes
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

Currently, only the the HW_TAGS modes supports commandline arguments. Some of
those - kasan.stacktrace and kasan.fault - can be implemented for other modes
as well if there are use cases for them.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212169-199747%40https.bugzilla.kernel.org/.
