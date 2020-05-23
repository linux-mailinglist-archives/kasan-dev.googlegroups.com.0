Return-Path: <kasan-dev+bncBC24VNFHTMIBBDXBUX3AKGQEXYHCJJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DBD91DFA60
	for <lists+kasan-dev@lfdr.de>; Sat, 23 May 2020 20:50:55 +0200 (CEST)
Received: by mail-vk1-xa37.google.com with SMTP id b137sf5921074vke.18
        for <lists+kasan-dev@lfdr.de>; Sat, 23 May 2020 11:50:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590259854; cv=pass;
        d=google.com; s=arc-20160816;
        b=PcM5d7wHIz6yrtzJXgRoWUS1NQ1XYyCZSj4IbVnKUj0vVBmmxqJWx7t4bWq5KV0vGc
         JemPN7rd7S5ErAUTZIiY8poDpzvTQSNv1cCjbbnO0m6MOktPWjW0G0ObEAocLgHECtVF
         jSFQZz2LofXII9nWp+Cqvv5L6DDpwE9MUu/bDNkVg7DLj93uxJroM2bw+RFnn7Jwp9jE
         4kuOZW91Dq8quSc11zfgMCH9KM2H73qrDQvQD7FYUL0zs9ZVweHY34auv0VbfL9mjWFI
         cpx64uCiSeauYiEaAx2RHaBrZcdDLL7pXuo5k6Pp6khdKP8cB4LoWshhF/vZy2zhzM09
         dK8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=5150MH1HgAYOiRY0vYu3dGAa7R1lL3lzLfHJDz15MWI=;
        b=DQC+WvYHiqpbJoxllS+D7TTaAH3W6lTwA9q0g9nkYxsKdmSL+dqvGGEXudQDw2SE9y
         HOU21VzTury6YpFGnkoI2jUUKXxj+9SVc6f51E/YV8qdRZYhS/QjsKJ3f/8aFbhyBK4/
         6eb5ygQAXhwa2XB3mhpyJFh4RTWdGgvH5JPkJOa300zhEVS8mtf6ybj4Cg5Kf+3TSEtl
         xn9RHP2YJyVcULnN59VizhiZahnHBYZZd/0Wv9O74FKdROvgCLw2v0zWnyk69J6HqXTK
         OPnqAYhoOxAD3zHL/l7si3Y0OYGtyYKmMXSPaaE9sNremYaxPoLU/mC2qAPQENHELmAd
         5sDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=abjp=7f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=aBJP=7F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5150MH1HgAYOiRY0vYu3dGAa7R1lL3lzLfHJDz15MWI=;
        b=sJa0Rq+6L53BL3WHWQSN/w3ZKv4wV2bKgNHZ7a0bBULI3lYF6VxVQAMkw34IO8flH6
         RjaoD4/pb1ia7RmB64brRdtRzX538lARSQ4Le0lTZzHXJI40S3llTD6Mp4I90mA+d+VY
         aNkL75A2rAEj2eWWrYbl4TOBVm3R95a4wMijhdE7O91euhtiTtT34X3bFoB0dTTqTAyK
         ezbij6fp9rVbtFR2DwRIgM+7U6P0tohyZT+czhGOsuNZS3EYYexnK28T6nCJOApAliCd
         yq4NAdLm3PvRb5xQbroP/eHDWo1OV+DgRY9QkAz9ZT9mgzwGht1Q9bvP/syYWnmRRXkQ
         FKDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5150MH1HgAYOiRY0vYu3dGAa7R1lL3lzLfHJDz15MWI=;
        b=k77nxbyWSEjypPMtavUj4O83qOVpcy4u8KNQ/OZvKzIv9kWgA8STjvD9O22H+/05HV
         GfvUP05F5SRyzZmhybLH+L0PvxtRj6uc7OnvaxmhigB7MK0mQPs3+L5UHgWC2tTbBGV7
         /EVQweiMQn8150iJQ90n+vX6oHUNWQkSay9KtyUP7Naz1v0mWnE90XAn1/R/MDin+q+F
         CAp9BUlDVxJatxIZJytx8OB8CMLMT3S1WOWyEDfjdjAtdf0kkqre0+giCUQnb6W+VN8c
         bP2hbqltYmef+2as8V3QgNZoR14/OKZFkYrRingHs/NxTrtH3mvpkXm1+dHS8ubDu70g
         OOjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531XTaSVOPEQJsIHZGEBNG7K39IUYkmIOE0fA1ucVjLe7RJDbJHW
	wgnoKjLpy5ws1++BF36VgNU=
X-Google-Smtp-Source: ABdhPJycSGkitUufGkRLK+jFnGxpN4umV/zwCw71R6wTG5oUpDgb5ZZQK159KCSFmdVyYeuXWuMqbQ==
X-Received: by 2002:ab0:548a:: with SMTP id p10mr1003891uaa.35.1590259854477;
        Sat, 23 May 2020 11:50:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:9a53:: with SMTP id c80ls45663vke.0.gmail; Sat, 23 May
 2020 11:50:54 -0700 (PDT)
X-Received: by 2002:ac5:c54a:: with SMTP id d10mr14954223vkl.21.1590259854116;
        Sat, 23 May 2020 11:50:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590259854; cv=none;
        d=google.com; s=arc-20160816;
        b=QkymE6kQ/qItZqzSnyMOWeu1OaeaSoK0EaEnlaPyNqpFU3vcM5pU346uCffZgqQSP7
         wxU/sYDmaceDq7CiwnmPZIsXqC+qHqs9LhvYYTlXTK/DdK+tR6rVjzyKn+vfYqiB0/kt
         FEvWyNTRbob73m904e7XSq9m+S1B05/QrZl6005Bi0ERQ3rtByCTqbqnQQV+oRd0bGKK
         Ho3xcv9Ejog+xmDPR0yy+RlfzrhowfCs0766Hh02HHfq7J28FkQ9ktjDCJtH2a3Q0I2e
         vk6cSQFemGn7lE/c+w9gu7thBoFNd31IC0rH/4Nt7OoOMFJYFP8sH42Vj6aURugKnjqU
         aPMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=V1/cxojhpkgzdXG+2CQGRZ1vyNgJ9E+QNL+k7DnE6aM=;
        b=ZZMhB1CDsrXZNqTd9N9TYQr7OCwq4ixFOIcKKcmMq0EkcBU8bQc/oeC8yswAiQrw03
         x7TNzbg79rNU+UM9cnBS4wYbLyiy+/MuYbW2Qw3afTwRVC00OpDHK5pgLrk52u6+7Fpi
         U8mLWDwTVFBOjfJagFusMMJb+fP6M0lNQgOisJj6j1it7nsE9ejS+v0QiMy4HquVY+Uy
         I5+H/OYPXQtt+uy8rrp7VY2R3A41BhYMPURTZqLh0Xahva4KvBVcdtHp9vP49tuiqnKR
         lcPYpcUI0BToumEAs78GF789VXNcEXcMLxVLEA3/oDXiK1UcdIB4naHFWFfmXjaTIt6m
         Cvrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=abjp=7f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=aBJP=7F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e10si550325vkp.4.2020.05.23.11.50.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 23 May 2020 11:50:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=abjp=7f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 207869] New: KASAN: better detect oob bugs for modules
Date: Sat, 23 May 2020 18:50:52 +0000
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
Message-ID: <bug-207869-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=abjp=7f=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=aBJP=7F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=207869

            Bug ID: 207869
           Summary: KASAN: better detect oob bugs for modules
           Product: Memory Management
           Version: 2.5
    Kernel Version: mainline
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

Moved from https://github.com/google/kasan/issues/31

"""
Right now when a module is allocated KASan only maps the shadow pages
corresponding to that module's address range. In the case of a buffer overflow
touching the memory past that address we get a GPF that causes the kernel to
crash.
A better way to handle modules would be to map the shadow for the modules'
range but poison parts of it that do not mirror loaded modules. Redzones around
modules are also nice to have.
"""

It seems that now this is only relevant for non CONFIG_KASAN_VMALLOC builds.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-207869-199747%40https.bugzilla.kernel.org/.
