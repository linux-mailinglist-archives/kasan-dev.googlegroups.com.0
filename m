Return-Path: <kasan-dev+bncBC24VNFHTMIBBSV3T2BAMGQERZ2KNXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AC75332B96
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 17:09:47 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id b16sf2689352otl.13
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 08:09:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615306186; cv=pass;
        d=google.com; s=arc-20160816;
        b=vHICdvBjWHsX4hWTdWXwFjrPhaEoJQUhI+xY65NvAxeHnrdyoywXtZ1xS2d6ys76dv
         8D51wN7EMBzoDF7ItjShfkXDX4g5hv8SB37iSR3yvQ3lM1D2SWXC+a57y7ZLnhNu9nwf
         /Zz6OLi3ni55mE3axv6ozRsDVtv7dZNeFFut+HB3UvYaM1GKJ7tOO8k0QA4YH1JrtJ/7
         htOYzYc38oQul1BRtG6/mzwR+2kgpRuZW/TLj074hkXS8OywPQNR1WhO+olUyGTrmSVo
         lfeRuAV5cHAUVH9kShg9N2RlyFOWQeiRkFCwDo8f/Td1jZjhOqirtuYwQmE6HwOCSbX3
         VIOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=BtGA1vR/IBCqDwhGrdeTZm/hm2P2TITTwnnmOZixYqw=;
        b=kUgkJgtDvWGJDyYe3vUSWghxJjR3krDse2kguXaAmcmqL/k4WhE/kpruF09xP0kOD6
         ut8H+Onz1Nwpqehg1GzEy/02aueZ0Y8+IzfkdunwGQy3bM500wUs5RxWSd9V82PinijM
         53fIdU+opfkok4oZXsEWAFm2FWZocEoXDvyuAV8BC6Le4qbxLgS+WhD1hDg+CoEwc5eV
         dTYRnqHmGkBcrjsLu9l1AU/e5DMb8oQ51GEVLyZKRGRsLG11s/4JB/UHUo/JiFwfoB3v
         TH6HUTZXcNups0Cum7+10CK7dR1gzhUmnTEUmLpgj3j25jvkr0bmfMBpydXv3aKdARKe
         H6Yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sF8Zhutp;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BtGA1vR/IBCqDwhGrdeTZm/hm2P2TITTwnnmOZixYqw=;
        b=lW0BuZ4uixA40RW5Qt2LWG60Hs038+ZzP01qBZR26JXhnpTjrOouKUEmsdB6rqpePR
         HxwcaPG30CyHZI0bGLpWjsjfzGuFiIvbadvVqnCMdbYz7+xHcU5/Ie7W75M47BaOxQoh
         5hNuInJ/GLPsMmvxP9f9gowy6D6VsZed7zZ5havcluQgKTQcAQpeo817mrcyTZDMyl7l
         e+O47iF8l5Z21C12xZ5eWb7kFATz5oLTky9nlOdNE7FAFp+1/+LBW/F/TzjKEMwJFz8s
         +UxG9j4uDWej0dXztgREhQWapPkhICyJhj4i/AZrzKBNckbrYvd3zs9khbLvWWhkTh7P
         BCow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BtGA1vR/IBCqDwhGrdeTZm/hm2P2TITTwnnmOZixYqw=;
        b=oS3JpedUtJZCOP2etwjpe3MX/4jFT7SlML8QJYeu4LtxmWcfzpc4WqEOmZa8+/qkC5
         //X+7gMJQ7sW3DP13ibs8s/ZIx+VgJHjP40npT8iMOf+dzbrRHM6zh2rPwwuaKXo0NhR
         BIcOqW7pPYgDe+aHvuWVWXVudWfwQhL08ZW+fvGwMVZjWFThgZRp1F9yAvltwvWTySmy
         UjVUDktOJ/3VZRkMOIbSaiL9tfC3E4Mw5eG8WOlGjWKp5NLoiJ17QC7uezw3D07VPrHd
         mGB5pqUAGRTBQavCVy9flS21xw/JtUMPJj7ACEmBFk7girHDVaqhaqOBV4YPffCQn+sJ
         P+Og==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531S31UDYJlg9cIV/6h5lsnPmbo6nUGpGyYDjVss5p4AsD9k4go3
	CmunEBZwOyx4wEp1hteczMc=
X-Google-Smtp-Source: ABdhPJwhOiUOjfHq25rRj7tNVuykOxIpM7NqBt9UsDPV/sinviWHmF8j13KbpK+YNJe+t6n24UR9KA==
X-Received: by 2002:a05:6830:1e03:: with SMTP id s3mr14080356otr.321.1615306186344;
        Tue, 09 Mar 2021 08:09:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d755:: with SMTP id o82ls5442460oig.2.gmail; Tue, 09 Mar
 2021 08:09:46 -0800 (PST)
X-Received: by 2002:aca:cfd3:: with SMTP id f202mr3426789oig.155.1615306186037;
        Tue, 09 Mar 2021 08:09:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615306186; cv=none;
        d=google.com; s=arc-20160816;
        b=MUSsmca/+b3lv30eXjSJKGBAodD+qYwjWmK0EHDj//dK3/yma8GSzwrN4Phv6qN80s
         WP0l4bkgKLx+C1KiyAecz3uW2ykKYoSN2Qfzr+sUCln0KRIf9RSxmQVtxHqtsl2aLPOG
         +O1FWdtMn+CBBJsN/yLMzKdCPDjz0ebrquO4mh+Pb2knb4hebRURDIbW7Qk1CPkCKiuC
         WXNf+ajC8nZ0GOYTUZa+GQfAFlRM+tTQ7bUTdB0wY/zWPGbstEA3/yWjCUuopeEbUZfg
         BRyAOfv7QGzrbWm1PhiYuXmxMc2rR/GNme+SfAeAkx4gDTCdX4B7lPbX9lbFR4hCEzgL
         J65A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=wulpAFCuoX3gzFkp9ICJ6OLAVvMiR3u+m0kmFgsAPoA=;
        b=p6je/bYeAXQT+Hc121yM3gBt+kwOQMQs8faxZnCK4CM4bnG1brcMkUbhOWyEelhrKf
         xSHxTxX3wAx4BY5YI1H5W02YYJOnQ76vIT96mcaz3cCp94jnL5yhSGi7//ZOjw6Mfavi
         kV1r9ebftC9LTo4QkUJLdnsJmnsBvgahPk8dLxuzsd8pLutpnbxtSbuQPCfiekPHwW8h
         CyG1MUjOZ+8Q9PLki4HeZ+w+QMKw7CPl5Fa2wDLZ1GVZa9UCMMDTIIhEXgzt2rleCiUE
         VYH1iaP3eCNX24O40zhM1/vwDhaAQZDcpCiPjrEpBDTsifiucws140TxRDFc3JjuLTS2
         bp+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sF8Zhutp;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q10si1183834oon.2.2021.03.09.08.09.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 08:09:45 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 2B59E65279
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 16:09:45 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 21D1A65368; Tue,  9 Mar 2021 16:09:45 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212199] New: KASAN (hw-tags): fully disable tag checking on the
 first tag fault
Date: Tue, 09 Mar 2021 16:09:44 +0000
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
Message-ID: <bug-212199-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=sF8Zhutp;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212199

            Bug ID: 212199
           Summary: KASAN (hw-tags): fully disable tag checking on the
                    first tag fault
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

Currently, when a tag fault is encountered HW_TAGS KASAN disables MTE tag
checking in CPUs. However, tag checking via kasan_byte_accessible() calls is
done independently. This leads to double-free/invalid-free bugs still being
detected even though tag checking was disabled in CPUs.

It makes sense to fully disable all kinds of MTE checks on both CPU tag faults
and kasan_byte_accessible() failures.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212199-199747%40https.bugzilla.kernel.org/.
