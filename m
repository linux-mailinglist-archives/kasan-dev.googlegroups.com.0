Return-Path: <kasan-dev+bncBC24VNFHTMIBBS5DQLZQKGQEHVC4ZLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 07808179F6E
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 06:44:46 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id w6sf3085756qki.13
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Mar 2020 21:44:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583387084; cv=pass;
        d=google.com; s=arc-20160816;
        b=r+JJvfZu0AO3rUJyRX7oBuwYkccrL2+MhkUU1+6YTz/hwZeMh9bJ+J9k59vLqUIOgv
         RnLz8cPHRtBJKwgAiLt3XHLB5fVLt2v2qTzF9yPpXcBMeOrjX/7rEHGeU7tGs5efL8+9
         x8qbFd/H1wE6cwlzA7y5yiKvdbS3RaHWrO2kjXr597a4UwWGUGwKep/ny2R3kqV+EIyd
         GQQKQ0B/6uuhoJTOiMV9VNyIhXItAoxu1bAPwCivY285YZ/ohwWDeNXhdW8FV01MjESJ
         c44++wEFj149oVwe82RiHuTGasVmXObDj9jUcHX/HdZJksLZOXDBn/G1LMQILT7jVGKv
         6+Sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=TuvqaU4FeccDVlXoDeoEoYWcq4Uy5Zp28ePOc1a/OMM=;
        b=yPgDhLSgxMqM0ERcYYE9yZtYeKp0uPDmMsdyQWJNhVOGQSR+y/joaMU9ts0giqFbmh
         NrFQ8O8Y8pD8rC9dE6lih6YtCUjAOzsWFPJP42uBf00fpB7ZhSL8kSlO9IqrvgGqaFTP
         CzHALke5J0j1eVLYs32F69i63tIKb7OHynDRfFfgTPMN26nG4dUl52RV7NuD23JlLwci
         /iL0yGRuD18QIYCdbl8r5TYcsdY7xIyVWjLxdpj6AELYUhiea9tKS1XQb8EAIVC8tBOz
         nhwJLlIOq4SrmRssDq5jB4cx/AilwDTMpIW2c7mr5Z1AyMZ66BpLTs6V6Syg2lIvgqy5
         febA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=azl9=4w=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=azL9=4W=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TuvqaU4FeccDVlXoDeoEoYWcq4Uy5Zp28ePOc1a/OMM=;
        b=GURvwfxWySd0CtQHJzwjUDLb1wwdkJYOaLg8mnd4d8b0iqZyn3dZLHQKs+G9FqZVrw
         7isXSLwjujux1aeSo235PmbUZ62q12yEZE8OMVdbgi1YenYqwuPm+SpEhfYIRX2Jn4I1
         AlKu+UbpwxLdbj4pWZlejkNre79u2XjxXiB14uRZ88tYGb4fdU6iygMdIjD2dSK24vCN
         bblhJYtgIGRZPpHiPY/UridMD9FWkpPpmnOGx7tEeQN9OOKsoqnQ8rntEs3gK1ySCJBE
         92FMJ/wVzIgfBZ8T5NqfRRsUXeKGJqA6sIVbv2KC6QhDtce3C79Quy2cCGu+umDAbCTL
         qGYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TuvqaU4FeccDVlXoDeoEoYWcq4Uy5Zp28ePOc1a/OMM=;
        b=m2R7uWtzeUqiQm29MTeMhn5apC53V+TratFJsdmSh8h8mhSiDjn8iK3wecWukgcJJT
         8ljNGte05OznUon6/SBbng7T+HHG7/Y4dWozhAWT8F94eXfYMK0YnFdIuxNm/2HYu2Em
         Qqp4Rh+JHqdu71NswvFPkppVo6Yienz6+tQhHPXNTJnQ9+piSxkoVAFC+WbeDn9MJtea
         xKDaMQ56xZY1X23L1xADVQg7DJ+DsVM8yyW+Ltz5nJdN1sPuij2Ot4WuXmnNIBx3Zyud
         AeK2Ba8Y+X9ZqOsSpyGfE/O8MiL/BRh1OYyuFmRGzm+5NVekvbJcX6WACPN81ifcVm2F
         PE1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1BkNooqGQlIfp8KmWcnzyU96gsYBBq8vdgprKihoqbigZOCE0Z
	K9/m7DavyMDZMkOARku5Y+M=
X-Google-Smtp-Source: ADFU+vsvihqZOGkUeKCDOM6PuBMT+DNkbPGV3bVyVrrk/VE3ta/9v3br8OMtH5YAYL5VLZAn8wvh6g==
X-Received: by 2002:ac8:4883:: with SMTP id i3mr5879826qtq.106.1583387083524;
        Wed, 04 Mar 2020 21:44:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:3479:: with SMTP id v54ls483053qtb.3.gmail; Wed, 04 Mar
 2020 21:44:43 -0800 (PST)
X-Received: by 2002:aed:376a:: with SMTP id i97mr5728748qtb.44.1583387083219;
        Wed, 04 Mar 2020 21:44:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583387083; cv=none;
        d=google.com; s=arc-20160816;
        b=JH5CMUJplbKwnoPJq3G0HiWWD+1cWikOpjisHXf7d3mf3YYCPDRknccd+kfliwmimd
         +bwdZuZoy+nKlASCHr1qNkUTfK1NaI74K/JPuGZDNj9MhTrhgZMVH6rdrkCAPRodhl7V
         aP585NQp2FJ0Ofiv8bpEoN0mVrFzS5NsYNbKPEwJx1X2N4Af0PmqSydXwz+UDdkWEKTh
         g/o2kDqgB0RzBIqextUOgkM9TKTvGS/kBGIbOm7mraaFlJdBvnDBBAUMxnJBL8olY3CA
         4Fv+3PTcJgf3yatUhwryoEDwXFLnEIvL/juOzxe+KTW44LChYsVa6C1qK/JHcMmFv8VC
         WDbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=KRUsYLlo6DHmcgBRxxBbxSBDHwojrxEADWd5QaAVZOo=;
        b=E4vm3DSmX40fvGYnqVDMZpb3/gmMr/nnzFx42rnezBOqHCPtv73QP9JJ+XfoapUM/E
         7DlJa8Ka/5SmJhNeLs8jzdxITbwnvhcLD9XUut1bzWDTwtSgU8ONGaeUMqoLhefB9gVA
         uMIbdri5Oxf5Ra0PHPguFypJn1uhJkeGe1mpsNfTjwxfX5yOLwiCPOLP7bNC62EROxEI
         5LKVSKEiDTzl7yM7hECa2E29N45I8lp7oJWSv7Fevh5AGs6wHzuZJWrUbOvWwBVp89Jg
         Eww4m21KkRQEa4dX3lk7o/OVGrND6DCnlPIaBtwgmsJtao2z/mg8iwWiCt5voHuxwONk
         sAcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=azl9=4w=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=azL9=4W=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x5si288871qkh.0.2020.03.04.21.44.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Mar 2020 21:44:43 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=azl9=4w=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206755] KASAN: some flags are gcc-isms, not understood by clang
Date: Thu, 05 Mar 2020 05:44:41 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-206755-199747-rfYli7CHzI@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206755-199747@https.bugzilla.kernel.org/>
References: <bug-206755-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=azl9=4w=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=azL9=4W=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206755

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #3 from Dmitry Vyukov (dvyukov@google.com) ---
Doh! Somehow I was looking at very old kernel. Fixed by:

commit 1a69e7ce8391a8bc808baf04e06d88ab4024ca47
Author: Andrey Ryabinin
Date:   Tue Feb 6 15:36:08 2018 -0800

    kasan/Makefile: support LLVM style asan parameters

Thanks for pointing, Walter!

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206755-199747-rfYli7CHzI%40https.bugzilla.kernel.org/.
