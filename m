Return-Path: <kasan-dev+bncBC24VNFHTMIBBCHVTPYQKGQEW5UILXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 28979143DD7
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 14:20:10 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id z12sf2052696ilh.17
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 05:20:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579612809; cv=pass;
        d=google.com; s=arc-20160816;
        b=KpUSh6sLad5YCjuo+6XKBS2TY+81flL8r5MOq7ByDPZ5ui1ggvB5E/cfHNpocSWs83
         innwFEcavBW8rNQw9idsn55tOf7qp61lXU9Fa58XrK/bMavaStgqh90TOQv73FzWCwHE
         6lgicLaApz/jqyCfYzJmLOPpvI62F9I+oJ1h1gs/ONbklDze0ugWI4TVtt6lPOb8ZjYT
         mkd87ppFhVpBhLhov3fYkqKc8d6JCbvjbHBFEW4zB6+c0YEJNmHvAh/6B/rRqhhbAFUM
         L6xUL3bH0lhVrvqMRWXiBxHGxj3eXeuEPsI35TVM3lFuXZ8ax5TbjoAc6cEcEZPhDe7q
         Bf8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=Hf5liq5og/uTp2tDhRD2vqm9rcEXguS9KCyTgnYphNE=;
        b=aow3h+zveSCc1/IUNyfpbyZmc3ALdVIi+LhByJeNurADL425cs3M7NnHbcddkVKUNT
         rEx3YwnmMHn3A8d8WLqqdLDjJo9oZs7oZ+ra6oyVn7zwZN1Agg+IkvHCC2409J1UDP4v
         dHVus54RC1hX2atmTEAm1usQ/H3ftgcaDCU2hqBQmCsMjeN9wIjdAIsF1EuYlWW2toSo
         6lK4thWjdW8+Cmr1wtan1BEnm8fzUdfRe3udoY/n+1Jk8vYtnau9ZFABt7ZGGGJcSu+z
         e4kDZDWZ4sE1Y7qr1Hal3BnGRxdLeAPjDCsy6PLiY+17UAYklYZXmxtXgvKAoF7EzluK
         nm/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=dqi7=3k=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=DqI7=3K=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hf5liq5og/uTp2tDhRD2vqm9rcEXguS9KCyTgnYphNE=;
        b=YhKegZqv5l3Ikw4yoZ55kij7hsWu30Xkx198dQvLaR0fYWjyISMjoSGKKDgEcnQgg5
         cuJYtnPTwLDFwknIndGt2D6qkicYRK2Jr542+MA20j3YXORuK2BFPUjp09DMoLQwxfkf
         fpvclIeMFY9n6Ou6e3tkfOg9V4flfU1ZTNeGkfeFrkXRlCWF1QVAKpYoGIH53Ggt1MgR
         D/tQEN+4UlnVJYM32PpcBaSJBcLvDqV6pIOEWekYZ0heV4SC+OCnBtlsOCUW9Z/wz6Wl
         dgKW9RjZlWsu/e+oPbnMgD0qWxtjaGg/wtee7Pp47RYNZYDekzvKZs6ymzSpjKF+CTcG
         If8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hf5liq5og/uTp2tDhRD2vqm9rcEXguS9KCyTgnYphNE=;
        b=HTx1IUbNcjSum+QgAMf8SW8VqV1kGnmV4brcbZc+zLpNeGPi6kP60nn+KH+z670D+c
         d41EfEQ1ZCpuK5KsnwF+1AaV6Qvk/tiUGHTd+anIdhlwMctG+ILP+4FGb2zHHKIqGA/H
         HdmCP7y6dfWF7SJPP89oQf3kkDcdc2ktR2OAJUv6jyTd1hLKO2g7sBsvtPpJar+M3qZz
         mpqQjgDluRSwofcu4VpkxDro0KPucI/asP2eTIfs7sbQmOm/lKgS9p4DU+p/tNgaML4C
         x+q/gyWfTabIk7mPfWaT18CFDuUKOTMRh9WHW+ESjdgEQAczWiUJiXVpUdpzqd4g6E2X
         oXOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVjefjXEGf+FXCVagxS13a0dj7xmkOAO+CkX8ir4rIfHUtAwdfS
	uC2sNBOtNHbyzbBPda+rnWo=
X-Google-Smtp-Source: APXvYqzuKH3vIIMJlZXMLQuVw4BspGSoDADYmpIqOZJB+ih4L5TTSZU0uSh9X4i5LPIIklsdGeGZVQ==
X-Received: by 2002:a92:ba8d:: with SMTP id t13mr3508677ill.207.1579612809046;
        Tue, 21 Jan 2020 05:20:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:7802:: with SMTP id p2ls2931377jac.11.gmail; Tue, 21 Jan
 2020 05:20:08 -0800 (PST)
X-Received: by 2002:a02:84eb:: with SMTP id f98mr3146090jai.36.1579612808654;
        Tue, 21 Jan 2020 05:20:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579612808; cv=none;
        d=google.com; s=arc-20160816;
        b=YAxqNGY3+QNAW03tOKvWdwUvEwYvTRcv2YW7CkQrvNgILNqCbJPQEZT5oPgkCzrIBx
         jSXd1Ww+2Iqo6RsDZEIUD67LxinFQ1jnaltBZdnW+ZIn+tIOpuOarLIhaxLEd/D9EU1p
         iN7QkXGR/Uwjd0+QHeZ9dY1BZB+Dr2s5Nh3xc3Hwm5iqE9rlk+0SUcLfGojwaHV4OvKs
         gIcou//bIIFMJBm53meX0bSvFf/LJoFgWQldDgx+b7dVq8Hthefect8pcJrT0XXyAZra
         VSju7f139Nui+g/nyHP4flqyF9Sa9Tgnf39RX9eM+tOYk5lG9iBBvX39RevL1JzBui/7
         mq3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=tj/ixYiZI4xH7YhFlro7dKf7aBo+sq1ENniaWvcwbEw=;
        b=x5CjlkVdaQidP97urzOcYsr+ag2iandDNA/iG8DKVMBsnaxZwVuWEo8uGix1p28sbT
         LBKywOIX508DBdiT5P0AZUdZydjGjEspMZMDbG5YxArG/zlncoGJ398y97WX/+qzxt9h
         KAWRsbs7FdiR0gdQ8fDe57+zOm/Lao9r8yL647diBF8LUQVPjfJv4J779mGV5BVKmfQw
         aSYR7a5w/nhuYjgYodT52vzOwj618lnjAxMlFi35XwI/RztRYyulfkgFQYiA8wycV61t
         PoH1d7JdVNnseCWSBKVtArI9xClZlJMuyxxV4CJLKR19iVsLYvDf8PF1sb+vZH8VxY6t
         FMAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=dqi7=3k=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=DqI7=3K=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g12si1214929iok.4.2020.01.21.05.20.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Jan 2020 05:20:08 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=dqi7=3k=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206269] New: KASAN: missed checks in ioread/write8/16/32_rep
Date: Tue, 21 Jan 2020 13:20:07 +0000
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
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-206269-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=dqi7=3k=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=DqI7=3K=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206269

            Bug ID: 206269
           Summary: KASAN: missed checks in ioread/write8/16/32_rep
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

ioread/write8/16/32_rep are similar to copy_to/from_user (for KASAN purposes).
We miss checks there, we should check that we don't touch bad memory with these
functions.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206269-199747%40https.bugzilla.kernel.org/.
