Return-Path: <kasan-dev+bncBC24VNFHTMIBBK42RSFAMGQEFIQJB2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D1BF40D602
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 11:23:56 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id d2-20020a0caa02000000b003784ba308f1sf39760047qvb.9
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 02:23:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631784235; cv=pass;
        d=google.com; s=arc-20160816;
        b=eOHMVMqd+dgxdMir8H7JAFi2wrzVWFrPmspQIp65Kd6MYfR2q/hGd1aq6i2DZG9zGL
         gt8RY+QHjC81e3sxibCw63IxUPHF9HRBmWQg0Vd2EyNAnOKQ07mi5oPUV4PkmgUwm4TX
         Mnx+J29ZpDdl7AZQqqL7aPG1nFCdzF/4bO2mxqZIo9cd394AOVQKOJPOfFs80Nc4UHfA
         ILB1YDcW/EFJ8//q8BF9Sy21QiQDLbVnbhLBe1DTw3BKORrOBu3274JVh+HSxrtH34rr
         5uAcCdmsCIPwLrDIIJ43fuVXmsKeU6+9ncLtu0awFND8hWnFJJLgx4AoHxJLS8cRHTY4
         Vhog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=sB1cZQ6Pvf25zFFDedX0RtLRJUQAtD5S4hNJ7JwFlT4=;
        b=yBC+c46tY2vTWFR8EFTNz87otn0hKhgQCrAmp1J9XrlScsPJVjVli16Zv+RcxL1R8/
         Z7pxCa0dcXj8E36byeizjDRiT+h87hN9Zqb+sNRyA9e11xpgBSOTg6vGqqsixgGgE6TY
         o/mK6PSpaL18K1TqudOQFvA9jzxWT8InssGpS0G1kCxxRf0S1e+v/8LyyXNzP4JmLMeT
         I3AkCA+cbDiSu72+3gqgzphSsWHxh5z80LjYBcPfTxGo416ad18asb8Y7jlv7rZ6rPFw
         WuI6tAPatXi4k0NO2YwtQ/XUGEm0Kl42+KMqYCLsiikC4NiXIa3EbVRGD7cL1QWJsuUX
         yi6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="mF7PD/UR";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sB1cZQ6Pvf25zFFDedX0RtLRJUQAtD5S4hNJ7JwFlT4=;
        b=rsQ+tHdXECzn+co5WMzOKtiEgYP64O0Cgm+asRQ++KbF954u9lViVXf6BcMV1MXIFC
         upCb1X+yDmTol9iIWam4AIUnWtf6kpj9VtEk9LGBoWeScjJXUpo5oGamjZFFEVciMMr4
         9OzRBvMlAUiZESF63XsnpOsyiHfhZrNNg8WzMBb8zVR5hGi2t1hkGOVbZHe2lGlW3Hi/
         NwfB+zbCRXR+4sVVECZV8kwEP6VkuCioG3RbPPXiW1I/13pI/zEQpgYlbEQA6OW5F9ZK
         QYZ4WYaBNyu7ud6VyPo3uMXniu+D23z0hBKQrDpSIBaa+4EyvH4G7HTnfspKHRceQLg+
         HQaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sB1cZQ6Pvf25zFFDedX0RtLRJUQAtD5S4hNJ7JwFlT4=;
        b=Szcm9gHJRzm8I08PuJrhSPhMeDEP5SkozsOqyEPzLPZlYX8N9ua/VbOiBrLElHv2He
         35EuTi6TA4OO4sUgoalQILi+dUBatDDHVjoqV86aouWGhewcARxpb7uM4uz8TT5hIcYO
         /yeioITTWpURR59HRzAXHM5IInncDaR7yBCPwokcYWVD79krAH9er6/beHop0cEMdbvn
         S7zVgMPsZbSDvNG81zt4mTswjdx+kl1+WwPS3m299ElmkEQYYmjhl+NQlEX3THwc7Hne
         q/Vi7zRFEkrdkh4L1RTHQtG4X+PSlTRTUlvwoUDSFH22m3dTW1CxdmHfRlzbJ8jogNv4
         mXdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533IkNOGZkbSe33i/3wXFkd0CxEuJ5CFZe/ajNpTjPCenggxa0gj
	ikcFyoclF/q25F6Vbuv0t6E=
X-Google-Smtp-Source: ABdhPJx3zgskDnc4wDZN0CHQIw1Okcb5+V0ioW46sAlLrsmixmkk2MoGhi/n10MDPM2iGCtM7zzpig==
X-Received: by 2002:ac8:59c5:: with SMTP id f5mr919595qtf.194.1631784235242;
        Thu, 16 Sep 2021 02:23:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e014:: with SMTP id j20ls1188144qvk.0.gmail; Thu, 16 Sep
 2021 02:23:54 -0700 (PDT)
X-Received: by 2002:a0c:f3c5:: with SMTP id f5mr4093251qvm.9.1631784234850;
        Thu, 16 Sep 2021 02:23:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631784234; cv=none;
        d=google.com; s=arc-20160816;
        b=iyxj1XxtO7hYsFJa0yFCC7dnOAsqo63gHhxpGalFTJYPGsaHunQrT5Uz/d/0FRw0DQ
         SEIzXnOV2y+nEmcZmgPRCjUC9MrIN4U4vCdDiuxTxZlWlTfVLOWJWpsd/n1hyckxjLGE
         DcwqErbCLl+Tub7XBG14ey2JqF8snoxbKAR4I64N/xPPR+26d2CUszrWFzvbLtGgjoZz
         3Z7Lg0OZjr4FELUXSholFr+02hjnedRfW/wDlmft6eSbfgiY1WTqVpqC6y9vrGzdTTDG
         TbwFiKeNH4PtsInuNF5zQLFnOUz904y64TAjXKFMIQi+gwU7Ow1umn/vvPYLuyFPoK/H
         7XFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=GnOt5q9eFq0XZX24jnb54NbJaF9+iAF6vybdEb0ZmE0=;
        b=bE7dIHNjxvHt6xf5Fp33OrX8UkMeurSG6Sg13KSO8Pkv5zEOyo50kv7MNuuQ5+Yiuh
         XyQln3NFAFMdoyb3FYbR4XCWs1FgDPes3zBCubQP2qFOdozjcr/CNXasN8Sew7NN5kup
         xzeY1A3IbpbtuD4nmPhiMyW3naT7DL8t820qdQk3RO2JS3y+TUD+mu753SgZ8VzPs8P6
         Nz5iuOb/6HTiy5ygR8Ph83CchLbmQ/yzLKxl+SnAP3KHjMHCRhKdqr0U9MDWRpwg+NDl
         ySv2geIU/Ip0anDbRc5aHSQvMV1KfBjbv2jvEvmn7hvsEMmHciC/l/mEKP9eIXo3P3GG
         LQ1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="mF7PD/UR";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n78si499831qkn.1.2021.09.16.02.23.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Sep 2021 02:23:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id B342960F93
	for <kasan-dev@googlegroups.com>; Thu, 16 Sep 2021 09:23:53 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 9CA2B610A4; Thu, 16 Sep 2021 09:23:53 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214429] New: Detect periodic timers re-armed too frequently
 (leads to stalls)
Date: Thu, 16 Sep 2021 09:23:53 +0000
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
Message-ID: <bug-214429-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="mF7PD/UR";       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=214429

            Bug ID: 214429
           Summary: Detect periodic timers re-armed too frequently (leads
                    to stalls)
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

It's quite common bug pattern that code uses user-passed values to arm periodic
timers w/o any sanity checks. If the period is too small, it can lead to a
stall.

For an example and some discussion see:
https://groups.google.com/g/syzkaller-bugs/c/25N568UIeiU/m/X2D1tdKoAQAJ

More examples:
https://syzkaller.appspot.com/bug?id=2381cedf5b083d4bc6d7c6ede3f71122dc08e0a0
https://syzkaller.appspot.com/bug?id=c86299f456763a2d2d23e00ccb83358cb8b8aac3
https://syzkaller.appspot.com/bug?id=c221fb80ac5f345a561da41310eb464b21186e2d
https://syzkaller.appspot.com/bug?id=2efed281192be57df66a3fd0163bfc2ceb42260b
https://syzkaller.appspot.com/bug?id=51feb020e071521675188d73f4c6b70b91aab361
https://syzkaller.appspot.com/bug?id=6943b91d83ff6eb451065e71192e93ddf8fb0ce0

We could add a debug config that would detect timers/hrtimers (what else?) that
are re-armed with too small period. The config must not produce false positives
to the degree possible (e.g. don't warn if the timer is re-armed once or twice
only).

Currently this is detected as stalls, but stalls are harder to
debug/localize/bisect, sometimes they are misattributed, merged together, etc.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214429-199747%40https.bugzilla.kernel.org/.
