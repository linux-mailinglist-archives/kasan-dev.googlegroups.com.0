Return-Path: <kasan-dev+bncBC24VNFHTMIBBRNQRP4AKGQEFGPYBMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id D2364215383
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Jul 2020 09:52:38 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id 75sf12800627uai.21
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Jul 2020 00:52:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594021958; cv=pass;
        d=google.com; s=arc-20160816;
        b=FDPEeLB0rjFIXMAaty48/Lri5QiNkbsXIgDYWmHHPFSymy16/3dQ+z1KNduHeBT9Kr
         HFdNM2efSoEbd+NEr76CLBuh+4LtWIirZ7FDqLC2X0Ocq2FjlJvcWno8gHBndmrxs4bw
         M9C0I1j+Lp6rbZr18YdcjglP5m+QNek+5Oc/4at5OtGQMA+Ni2mIJVLQsMbb0+sNN5YW
         cbo8ye3u2kwYMSkwX2o7zVkZl3UpfsKx02B9kOYhDvTg+i2JFy53xV/25BXL4VqXWBYL
         NwvmIOTlbQ8kLD8brSNKYOUmQwh791ZpM/2jNuv15IvGBhhMSEAR5w/ayZ8intkz03Vq
         MYfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=ZCvzlYR/8TecUy/TvSMEjlNMTF3H1kqsDQzX4cLJSXY=;
        b=UMUrmi7lP/JK+rz0Syq9F+T+PrN50QjvT1hVJTw0QYXvfjwzZZy9thTvvT7NB3OnkD
         NiI3ZTrMITlbTDeYlZG8GtFZF6DivOEf24bv543CiGzxld8kaQtEApIIwvPJYek3a8ZF
         qGurzUOiWqB+loieSm6sgS/MncmLAgZ5jXBtjX9tjnfKHJ+rKBhI//klJIloXO8gZ8Y9
         JC9PeNvXldoZOeJ560kfxrf6Zn8CfMgFCdAprzsEzc/LOkcEeLVaNYNVI31CgR7Pxb9z
         IlbP+w6BcZH8Cv3Nk6C+aM+a0e69fQF8v7jXYZPlc0aZpRPERhNA8Un7kYmatuj98uwc
         bPIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ck6p=ar=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ck6p=AR=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZCvzlYR/8TecUy/TvSMEjlNMTF3H1kqsDQzX4cLJSXY=;
        b=CGe/CfHMOg4Ie8vyeVY+aMOSrMS2jzbwrHzwJ+zV9sYsfbshm+oF5l7xJRKHKO1QXL
         jiUXAqb/0bkuqL6fgvaaNQ2PX9irrl31FG2DHIxKriBiG9SFMsJL08rQDHtdpfgKgyRS
         HM0AX62cM/2e440f6BJ9mEs08nPcgyX6LXbGilHCn2t2TKUdSzHHnQ4nc5G4hiMFXpJK
         Accu9uDtnjniSKrJWbOVyyJPPDrbEZi2XjuzGKaU0cx8d+Yi3/ROm7s44R9ietvb1dkG
         ZvvzWwMLciYReVf+QsGu2hUbJqRGD06BiGzFwZa6owXxOEtzYFAUYgoFpNW5nuMtMaUh
         6+ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZCvzlYR/8TecUy/TvSMEjlNMTF3H1kqsDQzX4cLJSXY=;
        b=nmPbc7TlXOR7PxLSEF5f4NbDa/fgA10szfzErQNheNayPDHDfHL7CcMqxdCRS6iLoj
         YMa+m8CbaHspzprBu/BiG3mitleftsRNp/CLBG4MfpVYqnB5JfMP4AdyV+XvhYiw8t2y
         pcJMPTXjgkFmUcVaRV6XcMyXiD6x9ZQJA4w1Lz3oXs4OXy9g6ouA8XPUEedGW7xwTR1I
         QeXeMd/kQmEOEroOReQQDQ9Oi4HoT5wIK6IU/ijf2dBaCZ30LUAia+6reJq2fXbvPAmP
         9Bg2VW520Kwxnj1YDxsHbGH8rYUoHlvaDsfpKJF9PgkoKHs23E41f/1CDVuNtpBHK5PS
         77yQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HL2y2Tc5jBgHM3UUkRs1o9eabRR3SfCXLQ5vWY8eUTfQq6Juo
	T4I8IhvII6XYseYPoPO7bNs=
X-Google-Smtp-Source: ABdhPJweWSa4fScA/S6dU1ERWTsvhe5GAuHsH8EPd638G7Z+QsH8k6E1iOzOOXTYFKfW5u+tI2EvQQ==
X-Received: by 2002:ab0:28d1:: with SMTP id g17mr12825508uaq.57.1594021957908;
        Mon, 06 Jul 2020 00:52:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2787:: with SMTP id t7ls1061550uap.11.gmail; Mon, 06 Jul
 2020 00:52:37 -0700 (PDT)
X-Received: by 2002:ab0:3753:: with SMTP id i19mr28977372uat.58.1594021957535;
        Mon, 06 Jul 2020 00:52:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594021957; cv=none;
        d=google.com; s=arc-20160816;
        b=PCuyXMFueCZsUufm4TFgCDbqdQXLWM2lZDse0baGMYydkqRJPDmf+stw8RBg26Dioh
         MIn75rajGp1I774jTgwFva9LxZFZXdrZRCk9N5cLjehdzK6Tzh8M1nViDIB7Q1oJM8y3
         MoXY8Wmlg/llEyhm3FRtmvt0TviEkCPticvfBZC4OyYXoGJaZA7Hgt90q5q1qLAfATDf
         GuWBmvFwVttdX10xU+g955aeFaNi53nO8LL3Bu5xl2Cgclwd34iBUq1fy1j82N88mzaf
         9KZHkEoMFoFxVkaViGvsRcEtdlU5Du/OxDIqkBT2sE+lgCu8NtYFOhTggoJ5GYfWPO4v
         EJ3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=lyB3UE8QKlTFMdtXMjmw+MSNx3Vr3WZeqk01bIh/ARc=;
        b=Lwu1tw0g8eVOma9/ZjU3G5c/Pu1Tl4Hos0zN0jYGHEpGgPRY1k9453j74VRLa1papa
         qqipMlP0VWwmnBzkeBxAPOO4aXrwTrHOkHYJDMdZP7kHqaTO1+8FN4TH4QLZOc0m5J7b
         7IqWjeeXaPEAMmFUp1g83dXAwk/G51s4+myURuhkVOMfme/OMhNSy1DOuitgNyb7q3J+
         iMoJw59hi+Rg0DBHN5/AiPWXyDZPvF0fW323+PgDObozhYz9KYd+KNuK13xhchrokkoz
         U6lfaTfO+WLrdo3ceSaNinEGSXGdVYYa3TxId3Ek0gNSiOQf/3AmELgJEXiAWiRmRANA
         I2kQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ck6p=ar=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ck6p=AR=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o66si1323085vkc.0.2020.07.06.00.52.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 06 Jul 2020 00:52:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ck6p=ar=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208461] New: FAULT_INJECTION: fail copy_to/from_user
Date: Mon, 06 Jul 2020 07:52:36 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-208461-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=ck6p=ar=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ck6p=AR=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=208461

            Bug ID: 208461
           Summary: FAULT_INJECTION: fail copy_to/from_user
           Product: Memory Management
           Version: 2.5
    Kernel Version: ALL
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

See https://lkml.org/lkml/2020/4/13/870 for motivation.
copy_to/from_user is another very common set of infrastructure functions that
can fail. It would be useful to support them in the fault injection facility
for testing purposes. As opposed to most other failure sites, these are easily
triggerable by user, so any bugs uncovered are higher-severity.

copy_to/from_user return not just an error, but also number of bytes that were
not copied. While returning different number of values may result in new code
paths/bugs, this does not seem to be widely used. I found one case where the
returned number is really used -- kfifo_copy_from_user. But generally all
callers just check for success/failure. So I don't think it's worth supporting
in systematic mode. These subtler cases should be tested with unit-tests.

Need to be careful to handle all variations of copy_to/from_user: put/get, with
underscores, etc.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208461-199747%40https.bugzilla.kernel.org/.
