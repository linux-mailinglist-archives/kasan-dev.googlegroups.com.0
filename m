Return-Path: <kasan-dev+bncBC24VNFHTMIBBT6MWHTAKGQEQYN24HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc37.google.com (mail-yw1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C2AE131BC
	for <lists+kasan-dev@lfdr.de>; Fri,  3 May 2019 18:03:28 +0200 (CEST)
Received: by mail-yw1-xc37.google.com with SMTP id j14sf10361088ywb.2
        for <lists+kasan-dev@lfdr.de>; Fri, 03 May 2019 09:03:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556899407; cv=pass;
        d=google.com; s=arc-20160816;
        b=KI17HzW/gcrY2gwUKSMBAQDH9RayoY+BGi23RiA3myEkFBEhCkwg//pxDsROTcoh3g
         MLczMPvK5yjmo+m3DX/cRVHFoU/zocnbvUyZ/eARY1eMEDl1MgD81FpBYsTjuBpIF/9i
         rY8t5J9BLaLT7lhFgqJmWLgXYtyzX0bRWUHE6pZNOuSE0jzL5UtKhIs98ECTL7tNj83h
         woqf4eowfVpobnXJXHVkDiqnWH78QKSXw2f3z0L+Xbi7wBW/h0fkvrEefRZjbZuA02vT
         ODuXnbSMOSte3JmaswAedE29Idgi3A7diAN38rnBgVVfxLFt567S0JDhJefs6llXwx6k
         K/sQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=UI9Mu809rZhegQRBFBahW05GrQVT2SAGWU/YmxQAHrE=;
        b=eG2xjeamOiPS8mNmI14lEl/006SnMEG4qyLKUz2ol2P9XnFb5dJo0oAvbTmsFhcEaq
         kRiZQI+0opZWmxkGRvkaz+NRFzdUVWjG0Pp0Um8wqGKEZaHkurUdO4i5vK57yIyg9dmM
         u17cFjMoq3E4fZZp6aXbbM2DnFlaee2ERXft/MAj/VwV3v0+8St32SLAG8s6hdNSLPpV
         rO5AJNvbGcAWZ6ZNoKRKHPCpTb8EspWoYyVwvRmKWhCc6j8fYSdgMtw4q+zjpZAF5SlG
         xxp3bGA31gJWZpUpd7Xl4EMfxgI3eeM/frnJC9l5zr1OPb75pEVhBaAeMHmnMTC8qhuv
         0Jwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UI9Mu809rZhegQRBFBahW05GrQVT2SAGWU/YmxQAHrE=;
        b=d3h49s/NNDxnr2vzZvgsDS7qiN7iI6azjaHTZsCx8mmYbbxy0IkrbOAXFG4XbKmcuW
         CTa6aZAZ6ij+lcQ5AShEtyOELbcErGX0nVrSaEEGzLTipQ1FSTtgo/ppPwyBw6M/OidJ
         tW1+V8rjtIH9/xbnjXeQ5y2sJmZRDg/bd3hzg8sPJfiDLPJoF/ktjJCKBlcAlG9YjS9U
         H4LT70s1tcjk1NJ51Si2iOWf0rvxyQ5CrknJORVQg/TQVSbZBXHtKNgS4owDnFoTLhDn
         yCSU2EXV2ICiP9RSMbDCiXuL4cIvhazCgwFqzjsk2fAq3ggMFjc8mAknLFbdz6WnVUpx
         Hiww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UI9Mu809rZhegQRBFBahW05GrQVT2SAGWU/YmxQAHrE=;
        b=cGz3wZ7ZM7T9Jyc7ip0qmRvMRAwJy4fWE5QaI0UKe0W02uAfgXOqJ8LhYuyI+symVo
         ZU3aowwmbw+VGPrBZQZEMCX9TcEo7UVb/1pWfcS7jzGVsO/mZuTwwaKFQSXNp1k+1IkY
         LOc7rbWzuciPiTJwLwMtgBPgcjp7QWORyp0y6IjhZnlwzv2ky0o7RZfDgNZT42Y5Lw9a
         uJiKTEYADBVi27y8CwexFsZMrxe88KhUjSK+v0DD7733S0vfDeq9kQTModbaHkdSXmB1
         YenCe6D5/a6P1LWs1/QJx03jH1/asjQa4eRnP0k52DbuYhTNuGdvp7qBIT9mDQnShIf6
         JBxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWNkULYzHuQENBGAy8rt1ZmH5kA773FI9cPEiDCo/wP4ChLXjfb
	2nM0nIuJSjfYi2iqsDMlNvk=
X-Google-Smtp-Source: APXvYqzgMU6Be6b0uMoDp5RfMBn95J/OgZjqMt0E8zGCEASNV1vOe6Bmb5Xibk7KqRE2yYjyDoGPtQ==
X-Received: by 2002:a81:79d3:: with SMTP id u202mr2235231ywc.288.1556899407445;
        Fri, 03 May 2019 09:03:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c041:: with SMTP id c62ls1310388ybf.0.gmail; Fri, 03 May
 2019 09:03:27 -0700 (PDT)
X-Received: by 2002:a5b:c4b:: with SMTP id d11mr8276710ybr.380.1556899407183;
        Fri, 03 May 2019 09:03:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556899407; cv=none;
        d=google.com; s=arc-20160816;
        b=HMEvvJS4fq8aaLWZjqEyQ6rRFRtsicw/BsKp0oZIU6rK4A0zzqlSEIbsCuhoYrghu5
         URPSDrEyOqpKUZnC2iFqgdkqr+NFLSRcXBWIaOSsi3T5SfBdBYHYSW497Wcxjxzk+8CT
         hzeWHYUhALMmmAJcz1RTj3YxmpnRIfCScY0YskJKnsagFdwk8IWUNZYgPMQyYlrWyV86
         gFXeVPzxgNyG4laTJGR7RO7L+0N+7/z2eMFCD0FqeCloLB49lHY+0ivfPr3IEnPZcdTO
         UR8vWte88E8HMiZYW2I9P998as84Frr9cum3xfCDWVdBU7AEoXGud2BbJoPYkEVfRWl9
         iYhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=gVoKxYWwnJfwhdYaYj6j5nGHnkSusK8uCCnUEsKDCRI=;
        b=uEvpz8v2M6CfFSg+oQINcjUxxkLbMHrzUpcA9hqBENLt9ZpJajkSzSsZ9p79NdGjxJ
         Jcjx+o6K0hZuJVxmimOWo8GqU+jaUtIM+Z86ooTGNF2LFQGgGwnvsqOc41/dsrfhLJet
         nyA/1UhHN4AgMR7bEnpZwCiIOgiXqkJaLOFRoJCPaWDpzjU1aE615MaZcaRyo/qN8dGA
         8QqOeKRunGG9TvAlPTZ+X4384UKVCMWeB5pgaxuiZ0id9g1xDrTZMW618b2WPCHlCT84
         kT5Z+XqrWWRQL4WJyGOWZ5vYTRSOOEnyO22jzJFuNG6UjiSZBsbGUmsPlk8JdUeGPVyB
         CUqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id h192si154296ywa.0.2019.05.03.09.03.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 May 2019 09:03:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 426CE284A3
	for <kasan-dev@googlegroups.com>; Fri,  3 May 2019 16:03:26 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 350312857D; Fri,  3 May 2019 16:03:26 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] New: KASAN (tags): support stack instrumentation
Date: Fri, 03 May 2019 16:03:25 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-203497-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=203497

            Bug ID: 203497
           Summary: KASAN (tags): support stack instrumentation
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
          Reporter: andreyknvl@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Currently it is disabled via -hwasan-instrument-stack=0 by default.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
