Return-Path: <kasan-dev+bncBAABBXWFU2WAMGQELCU6YWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 47B3581E16E
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 16:42:24 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-35fc8389a58sf48389855ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 07:42:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703518942; cv=pass;
        d=google.com; s=arc-20160816;
        b=cZDcNQ1Ggd1SpNLnZMSkaNAKWfiVp6i2gju4Jyn7HX2VeOHBiBhrM762OPnA5/nlUZ
         2vrYioT03iisZe2N2c6KVyh195prAdHVKeLecoK4qg9xmpZ5xF/avngItRRZ44UksFj/
         +SjkjyDHv9cZM1QPUXGN/i6u3npEuCLcKhakTLLDOrVuesMGJ/gl5LP4vIti6UgyHDd4
         WJZBmoUmjOPJKbdWoKiZYGrTbWQS7PTyCqhVH4LK3JOR0D6FURXhS5ue+9o02MI39A2t
         Rcu0uyjkFY75yoU/7vmD++ee+IP3AQq+6aIrn1D26WlCV87ji+ofmDhAeIOAMX97TPTJ
         k9iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=7MQzISEhPo+uc/6uAqR4KURWdwCJIZSxo2b4SmQo3lk=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=sk1wCnOijBCyqzAXZC8y9HcDy7K05F0y8JeEbfWEQKKn6U+x2gvya817yLrhNSQceu
         Ql0vbUuDiZ2TA3enr/O95YeheCVOCZA3XaLbqg2GMCzo4+HD2mZcR9DDofSqieZuP9HZ
         m8ci0899UrZJygNQslH+3sy8SFe3HXnQ+xSNeuE/hGkACqCRE9WVN8gESGs8P6MVPNyF
         1zult2sxdDBF63is3f8TE/VimWYo5Ni72uyVejsdiAzzCQvx5kYU8jSeOmbUTHiQAkJy
         wklVz4UzyEYUL2EpQJKEwEP3ewTwjKr3E9zTgOwCiKshyVRYpqylHV0vb7Mq1b7ppADS
         Pq+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KLQVBq79;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703518942; x=1704123742; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7MQzISEhPo+uc/6uAqR4KURWdwCJIZSxo2b4SmQo3lk=;
        b=B3bV8Wzi+4EzfXFrhY2J2oCOvysQKLTzKappzklxE6aTaJBLcOnKqdOAl/SrWez+tx
         TnSOjyN1UlPpJDnOpcjrpTRfyg5IGwAT2lD3UjpRxpipVRFCr7lAI6ZpT6yO+DanW6au
         gT+sM0NJ35ULaIjlnHP9lKiDrO7FQRtveilKBckJf/Bc2gxD7EFl2OY+TlmY4KsJsycW
         uErSbVRqJ43rhLbRN3j+tBg4WIgh2K/ttSS3jqvJ215KupgFnSDd5M1BO0CWyUaXOUdj
         MXz4QpOKF6wpQ/q8mFZMWnTx/obQEyqghIRXkFiuMwgtDhQPidcpH/j10sLLl46ypEUq
         o62g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703518942; x=1704123742;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7MQzISEhPo+uc/6uAqR4KURWdwCJIZSxo2b4SmQo3lk=;
        b=lfJovL7GPg1k2rD2EPQvp38cIL5QNVI/k9qXUoJKp5t3CDGA8O+xPFPsUZpW3iDRW5
         a8j52KHW0ic8aCAnL8X8RQ0z+PzUCOtpKIfKkdx1KX9aCBzcXGenUjEA3Zlonc947R3y
         1WVIYa2nT4H0XEC4JU/95mra9wy4IBxwAj1bcn1leXIK2+iSn55D76evbW7vYyWwCIwe
         TC67kKFGiwIW/kZEXfCYM8W6ofnt5BJQWec39i3rjneUPjOdpIbNJ3+xGGgaDVR8aP09
         9grDOJzpreYu1tXpkcwp4ql3hxnDjPum5BULIqxX3wkBQvYIKpdZLNRm7ZGXnHbQ1otL
         +AVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzUSddmoRpaiJONbK9SFUbi8iO5bl9rwvKgGfPIpydHPqG3K447
	8zi/LuzeXwovZ7nUjtF2xIk=
X-Google-Smtp-Source: AGHT+IEUnBSlAgOsHjx6qmm6nr2Oio8ebscMdnV1/v+yqTSwz5US+tUt0+kBKKoclqb3XskmATSa8w==
X-Received: by 2002:a05:6e02:1be8:b0:360:197:55d1 with SMTP id y8-20020a056e021be800b00360019755d1mr2129298ilv.23.1703518942654;
        Mon, 25 Dec 2023 07:42:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:b003:0:b0:35f:fd04:f60d with SMTP id x3-20020a92b003000000b0035ffd04f60dls1065336ilh.0.-pod-prod-01-us;
 Mon, 25 Dec 2023 07:42:22 -0800 (PST)
X-Received: by 2002:a05:6e02:1544:b0:35f:6a4a:cbb0 with SMTP id j4-20020a056e02154400b0035f6a4acbb0mr10539061ilu.25.1703518941926;
        Mon, 25 Dec 2023 07:42:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703518941; cv=none;
        d=google.com; s=arc-20160816;
        b=qlwLtfQpeijO2zPDVrnT2EewYIrz1zkIBwx/HjH/vOxB95bgDSDzvcdb2MtchaKYmK
         veGaQ1nsUTeuXMGgNzNQAf+5UZWbmZkT07tv9U2qrgAXiuC2yaTzqjS1vQAu8lfPa2lh
         68YlCW9Qn+ePk5i2uC+fuRs3wug+agHk3uU1CBCxvAmGt4KMAwFs11/SrjKr9Xb0EVA8
         KRbga5AIhqeC9dSurlK+92Vd+SCfrWf9cn92O9Nt2I0J92E3wrjSPNrtH2IfeFQAQo14
         eXFM/BiPi/4cvlzi+I837/JB2bMKkgPzHW2XEkATbZZvwtWyEwoFsPg529AEX71klWQU
         FMtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=k6K0nBvxULJuxBtZEi73xQKgg5ChIBGslN3u9SewCCY=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=M9PKCWfR7SmP8TwyTLrfjdflXVSXJ3Qwt/Ew2mF5iPLma9DMwvlL2tQP9XGBqnOnoE
         W9vVs0pnRqUFFb3u95PLYlUUcXqQq0sBxUxh1uC4WiJGT4XnvVJf3CxYjHcr9tl/tDlv
         MJVioIO54WZQEMrDjmcpjB8eJociE4r9CpnuoUGsv193IPCyh60+1bUnQxrbuOapOuxq
         zGwQjNkInYaOzXqHgKoC9SEnR3vpSNMNdHExsgkSIIYNXR/3tmjnDFHqDyfEjxLbczjD
         VERzJvkjbvtTfoBEqk+hqYmit9g1Yoa4LlUqTqtE0Fi+C653Gu1Y9R/B32jGtTHOPv8o
         KUog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KLQVBq79;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id y7-20020a926407000000b0035c823a9411si571681ilb.3.2023.12.25.07.42.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 07:42:21 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 68D1060C4C
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 15:42:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 1D730C433C9
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 15:42:21 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id DEAF2C53BC6; Mon, 25 Dec 2023 15:42:20 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218311] New: stackdepot: use STACK_BUCKET_NUMBER_ORDER_MAX with
 KMSAN
Date: Mon, 25 Dec 2023 15:42:20 +0000
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
Message-ID: <bug-218311-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KLQVBq79;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=218311

            Bug ID: 218311
           Summary: stackdepot: use STACK_BUCKET_NUMBER_ORDER_MAX with
                    KMSAN
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

Currently, the stack depot code uses the maximum number of hash table buckets
STACK_BUCKET_NUMBER_ORDER_MAX when KASAN is enabled, as KASAN saves a large
amount of stack traces.

We might want to use STACK_BUCKET_NUMBER_ORDER_MAX with KMSAN as well, for the
same reason.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218311-199747%40https.bugzilla.kernel.org/.
