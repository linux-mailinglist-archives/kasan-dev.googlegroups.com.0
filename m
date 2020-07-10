Return-Path: <kasan-dev+bncBC24VNFHTMIBB2PBUH4AKGQEJIEUSDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BF2C21B6D6
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jul 2020 15:45:14 +0200 (CEST)
Received: by mail-vk1-xa3a.google.com with SMTP id p72sf1182338vkp.4
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jul 2020 06:45:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594388713; cv=pass;
        d=google.com; s=arc-20160816;
        b=XHT5g92DGxY/FqzwPHd2pYvHnbbGmVA6TiFLnVG8Wb1JYLbHnQovA0Jry61XHvpS5I
         0urROCrRSxMeBf+hMypNzUwbvaLaWzdbj01JotQvewk4+L6a3vm9B3NWJCOlZ+UndPZ3
         vlC2X6KdapWguH6A2SQTUAIF69KSUd+Uzl2mL127YGQe0KcNQWSXt35HJC/+ZLqNZNib
         P+F1E27Rwvprr37JeEuE5JgiLr5azoKS2TKuZUaGo1C7exBFFHLFuTgn6t1jd0nomhnL
         /PwejRIX7O/gHnc2tUGjuWkctZwpdVwwn6Pcb1TKvdbzq1JSdhK/YFBKKmuu9QrXRRr7
         w3/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=DnipCsm8Ws5CAnAia49o5Sm3P+BF/7bbPVnjjwOqMZY=;
        b=lGaOy1qYrC1fhq3ZqpyYV6cNX4h/KZcZajTACyeiBlKgeT7QO/V+eIpuLGh1ymzTaV
         PwMl8F+u7zK9/vPhd2ROTQiqLQgi8sxTVFrmwIsNrAlSBkMNob3JL0JTP0VbzPWOTVCt
         wQBz3M3hl+X83Ex7oqutwuMG1lP3TgHTn/GN/0CzjWFDZ0u4gNKjRKAEADJftZMY0FUP
         mvjRLB8aVUHOY5pMdW+XisG1ZOPKDbYxnms0QiwALBRbjRC/A8kANn4qvnHNJRy01FyH
         /n0Jb4W1970f34HeeuHSqUw+DJ+KcDZ+KHdu2QvtRLX7CZFJuFE4ZltnWg6Yphd/WmnZ
         WdjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=q2nw=av=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=q2NW=AV=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DnipCsm8Ws5CAnAia49o5Sm3P+BF/7bbPVnjjwOqMZY=;
        b=ODCyMmTMOmzjyt/OkDDrU/aQ45zD5Y+vVkOQ2bxcVOJp/dDQjPcnq+VuvcLhOcaRrU
         2puAwngQ8/E5qDThos9fFfNBzc8Kk+neRwIyiFHYApEguWHrUfS6DLSDpCATJKP/z8Nr
         tKV/YwJA71a42jfjJq1Kxcu214xmXSHmBIv25XDJFfl7TF1M0m9no/cFu6+Q0BEC2SEo
         lpN1dD97s0/EhJHigOX1S2Y5WAPBAK9ma1DV2kTVaXptA7nXOsyvmYo/+58fan6o2ntH
         z2AMXIN7762ygDd/yNk3FYSiSRDJlCeUcNtfSDdcJJQGd8EHLt0mKiUnmTaRJUki+68D
         A4wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DnipCsm8Ws5CAnAia49o5Sm3P+BF/7bbPVnjjwOqMZY=;
        b=kMnsnvM8qu2yhgyNtjuaiihm5P2ntbP2DzPI829GIg+z2x4zoyOU9I6UOtaibuDbKy
         kek5ITeatxHlBNsQBdT9AZ70v5JK0TiO1TTfFPWS3KgQT1qreuRZfGF5z/f97jSfY+F3
         VuKhWITPsIA0FXKbuvpUeQZU2b48f1Th+6BPM0emhdxH7eGQnmhJe45S2jMirI3TrPEq
         EeqfRiMqNlHbANAVJILrGtYmJ2McfXYK8CoTKV9ijKpvACM+DomclEH3yiEy3k6a08lv
         um3WfjLpDSGTdrdEL04oaNDOMo5mfHbJ/RLcASf5J56eiieNXpY8sqcg1yoZx+lUFpA4
         IyNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530h4OMDJsuvMy0ifeeU/aBDOc/rtXTZeZJS4iveGmoxYDqZ65a1
	l9ZgW6wPQJy2BgNa7Shaz40=
X-Google-Smtp-Source: ABdhPJxVFasUf4/z71MOJwf7JHGlP57RV+BbZaRmocSWCNz4N6+ifxSgxsYbvuGupngl1j0qnN5KPQ==
X-Received: by 2002:ab0:4d67:: with SMTP id k39mr9623501uag.132.1594388713174;
        Fri, 10 Jul 2020 06:45:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2ed3:: with SMTP id u202ls1141380vsu.1.gmail; Fri, 10
 Jul 2020 06:45:12 -0700 (PDT)
X-Received: by 2002:a67:747:: with SMTP id 68mr21102403vsh.69.1594388712856;
        Fri, 10 Jul 2020 06:45:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594388712; cv=none;
        d=google.com; s=arc-20160816;
        b=ZyZoRqvbgNFLhL56EYusSYsY9ODzeAmNtV8Vb0ADvQgYvbVtzMfUmvkmnjVpqYa7XN
         W+/rkUlBvF+rfbuFG1l50ffhQKYtMdifziWTBWnY9um+qDoTaRGoyftj/wIGX7jcysYI
         eK9hDGye8VzioxlWQBSxbcYbrAwN3lhTtWgn96yjTH+IgVv/srL2udoyCFQwxdrxcWtu
         r1FsWw2Pe09eKPS+Un8Ub+gej3n2jIAyfxdTiRO4x/Jv8l+fCyTPIqJ/pBztr/6Hj1Jm
         6cX39hCb674VAIsmpmps77R4XW5/S10haq0OtSamBEMXp/RE27ShX5+JLVy++9iU//mj
         +p/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=r6PJcucBFyDfeJtNc/jxU9pOUWDOBHz4PqUbwd7v0oE=;
        b=X1ourh1KSRJO4MmWz7mf/NYvsfBRCv3/SxnDJp89oR1+y8y9OFbTfEid6eEAynzQPx
         xlhu3tFJzAN+4cHnWjQlUu5mj/7X0i/HJPXMCr0FM+8DPmbMV9YjCS/jBwf5/l8B3WBu
         5JoOyEkGhCWT6zN0CoJa6Yp+uyo0Mmxs1fN/f3v0CjzzW5A9ctu0VVMfEXDNQvO9J5kt
         mZjoGWKs/KYxAmreA6ET3zrbJwbjE+ofa70bksZ3yeYk1zVWwK+ClVZ/ieq0OsbO+Dpt
         SNx5T67PGqsrsug1q9gYfjqh+566wzuyFRCcKSIyLtdCMpLL686eIBwbC5B/gCePTbZN
         6n5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=q2nw=av=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=q2NW=AV=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o9si284090vsr.1.2020.07.10.06.45.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Jul 2020 06:45:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=q2nw=av=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208515] New: KASAN: support CONFIG_KASAN_VMALLOC for arm64
Date: Fri, 10 Jul 2020 13:45:11 +0000
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
Message-ID: <bug-208515-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=q2nw=av=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=q2NW=AV=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=208515

            Bug ID: 208515
           Summary: KASAN: support CONFIG_KASAN_VMALLOC for arm64
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

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208515-199747%40https.bugzilla.kernel.org/.
