Return-Path: <kasan-dev+bncBC24VNFHTMIBB2HUTWBAMGQEJXR26TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B40E7332754
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 14:38:49 +0100 (CET)
Received: by mail-vk1-xa3a.google.com with SMTP id l2sf3799192vkl.5
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 05:38:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615297128; cv=pass;
        d=google.com; s=arc-20160816;
        b=mfPD8u6er2S77vXXa6luhN7134Voq5k7mm5MvvtG8Fjz9A07ExDo6Jq5jVz0gUumlz
         fmnTtICOnji3kOaWSh+MlYpj4QGp/UNdLjQdMBbIgra2OyAxQo4cuXsbi/oBBKlEqpwj
         lxzGoWQpTj5qeS/EQukGiyXITy+4XKrWKTQUmyxAg/a3hRv6mtYaLPTnCWY482UiPAdK
         NEFNXBO/MqR0Oa8g2Ambfj5bAimHDmFuVzbN0qX4WXkHkc+DCgdHQRYON2dm1GPZgepI
         GdGLHucGSoVS4tPEJKbjIaX0M//q3FEZCREp8NXkTNmoc8Rcz72YyL4bqKsQM99THmy7
         KzuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=phfdMaYkeI4GHyaLZz/mm4R5TFrkBgVPuX9ODh0I8K4=;
        b=l6R6ltz/fh0zUDBk5iLPypeTAb4REbXDnM8f2bNLPPkF0SQAyX43Z46bJz6zmYjbhs
         2QsiEa+s1Zd1MqvWT5AowDx1AVLeMd6o9natMyWVt/I7UxqKGQ9JJLH9b29OAplWfxaS
         XDCUyWB2r1CdqUh1HGC9VRDoo1tl53bjpXLBAjVqdyo9MAVmkcpMd3/VukNbdSDDP6Ba
         yZB9vQrw8wLpHXBo3r/IGrExUF1W8oDArvgTdVy2DmiaemVxj4+x5MXmJpRc8Pd5vPwC
         gy/Zy3klYTSYDhRAAlX9GKjgs8ClhpVHawY+WWT1urUBedc2yqWEf++6qxXhyopuc+Tl
         297A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Fi2td3Ms;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=phfdMaYkeI4GHyaLZz/mm4R5TFrkBgVPuX9ODh0I8K4=;
        b=UrmQ/HPL4xS1fyZoz5uhT/uw45p4MTIOFxIpdkg1jHWBxulUkOyv6SCHjb0hqXbAD3
         h3HtvSjLeeSRi/OHvr3q2lOOELwChV3yjBLEgfNALApbQ+Gqjnbl7n0FECJhf9ZwFe/4
         /MPwO8YL9CHviBzRb/TThdHN2XqBzSIXJZ1l5mIAGnmH8/vXtJpJPPi3diHtSqc+bRU8
         nGRarnF4Sxpgg/FGnnMgbc0Tz9uZ2fFrn2CF1wQDQvJd8zi5G+B5l34+6YZe0URk6vEK
         n5wu282Kq9tfMwkHnGftGeur+NYQ2b2h7cFw6jxRK1chkKzqbkzIEu7FOFJMaQfyKB3g
         SrLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=phfdMaYkeI4GHyaLZz/mm4R5TFrkBgVPuX9ODh0I8K4=;
        b=k8qwikWels4HuIAy84ux5aBzONirnUYrTvy17VEfLtJ149OflQdit6Th+C2Ktaahvm
         U3Vu2rufLPuFmIX6e7aIJ4rpj3bI32cViQzu/TOeuDJhL9wT+5rsjUwY0Er0LQ4E9tYr
         ojxYcIr6Tl2cFKCSUyz5wc9CSGPcYk+nOkqDfETI+dgOHwpOgmPcsE2u0CHu3CXss32Y
         gXYiGtUH42KwkR9u1fuZ8Ya1u+cqUiAJDv+ng3CYzneSEVr2lW7/vRkavcRiOcci5Yzf
         /p6mlAZ7FfgplFBgaRVDJar7fIEKPQ8AmIxT2j7e2eoGOb1+U0pjc/6XblNTPmC+6pER
         gVAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Urqz3pod2MDOZi9lTZqrVbO2Sb++LSDfEFCFVBit8EqiT6RK0
	Ak60EkUfGe53zBeidJ6HeC0=
X-Google-Smtp-Source: ABdhPJxms8QgEHnQzP9YkEvrf9JBpuxIqfpfu7aXLz8caR63X4+xfWY0vgkXqfTW/Evr+Iu/ISmUyQ==
X-Received: by 2002:a1f:3646:: with SMTP id d67mr15634152vka.12.1615297128544;
        Tue, 09 Mar 2021 05:38:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:3917:: with SMTP id b23ls1324896uaw.4.gmail; Tue, 09 Mar
 2021 05:38:48 -0800 (PST)
X-Received: by 2002:ab0:23c2:: with SMTP id c2mr7276115uan.49.1615297128062;
        Tue, 09 Mar 2021 05:38:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615297128; cv=none;
        d=google.com; s=arc-20160816;
        b=ie1zYohvpypt1xHK0uzdN9WudwVvFSEKAYlZQzY/y9S/8oKtVHoAztUc9Qrgw5bFA0
         GZxEdG732cEDxh/V5vuNIt01IAJ0+qav/7mItEIgrZ98uKM+ji1wYZOvLJOgPihQwlzi
         IBywoTxAyEMLZ6qhX8p1+n1i8U70NTljNUwYQu0vTLSuCQd9JenR0cwnLMo78JkRSk5I
         1W0tZMHC24lUs/xP+KhgkbMuHACigFOKfp4zjGnPHBumdIUOjEjXfdf4T1wItJMN8yhO
         5/3iTcOSMxLmb/14CnqMXSKKHAi1jbYbUVKbDBkHGuopafHCXQ0st9REmYEzjcObEAzU
         LhfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=Tzb5A7ToebC9hvIOQWmRSoTTM5olxe4eE3I+h/Mq6wk=;
        b=WhAUFmDSb53dRE6XW7d9Z/OWMf1mkguwQdmQsFUzZDqOCqmV3uxx8MNtchgTrVwvNE
         BryHvUfYxx8auRlpfFwFieIWZYiFpKB6Cv0bAsFxBuAVZ43O1ep8CtHcxs/hUFjPRsj9
         NYqW67VZNaB1CEtO0+DbXTgdFzQvar/lJzB6SCS3YwwpTzFSsZwQFin2pB9kNZ1J7E4/
         /nSsd9sP6pkA+CGDRivEpaEY16d+vYavvluQFA7LZ6SzfnIMahNH39pJAvp3fKgcTMMw
         Xa9WejQ0h7NN4B8STzxjtQyTCqU0hp3cwMfiKCXOHsL1PQdORSiq84EMTkafSWmsUEe2
         TWwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Fi2td3Ms;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j11si682130vsi.0.2021.03.09.05.38.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 05:38:47 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id C2A90651C7
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 13:38:46 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id AE68865368; Tue,  9 Mar 2021 13:38:46 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212165] New: KASAN (hw-tags): print bad access size
Date: Tue, 09 Mar 2021 13:38:46 +0000
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
Message-ID: <bug-212165-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Fi2td3Ms;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212165

            Bug ID: 212165
           Summary: KASAN (hw-tags): print bad access size
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

MTE faults don't contain information about the size of the access that caused
the fault. The proposed approach to getting information about size is
disassembling the instruction that caused the fault.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212165-199747%40https.bugzilla.kernel.org/.
