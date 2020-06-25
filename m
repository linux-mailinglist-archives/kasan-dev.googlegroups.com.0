Return-Path: <kasan-dev+bncBC24VNFHTMIBB6EF2H3QKGQEDZBNT4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id D7F3E2099CE
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jun 2020 08:23:53 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id z7sf4946762ybz.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 23:23:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593066233; cv=pass;
        d=google.com; s=arc-20160816;
        b=ltFhWvXxlHLOQug9Kmsff6a57fiQXU6P/m1ZVza+mO2tFoVQrHrbEh8zSZ2eYY18Rx
         x/yPC5AnKaCbeibHPyRd6g7SvdueVtnrRjyg85hVSqRCO7Ihiw4hnVw3LSZhcP/mXL5D
         t2IymckFCUCxPEVNZ77jyo1e10kNlASuTLhlAe5n1b+HB0ziPM3pAfZ9vs7+Qf0iFXq9
         0F03P2jjxjOf5wqeyzLUsGGTWTx0TXKg9Ka6xjL7mcIpO0hBhNLRkujnZv6K/PoiKGRr
         mRTvgySs9JaKIJfO0Dra6UAaiRGrhTb0RidsHO6HSPM2YRJ/k9PSg/8jK35dFLfSR9li
         xv/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=kw3DYaOwHpWbuS2M25LLrulySgpg9P/NQoHRBnehQvs=;
        b=Ccetx+Yb9/ZJogK1NvHtiVMkP+7zQFHI+tJCj5UnRfy3SN89vk3u/dYms1iOhHBdLe
         fZw0jhkQI4/13JtJzzbAUPZ2ag1RZs2DtEkvwGcJKWP/lKVGll5dY9t4K7+kNBTRI8u+
         k4ereDLC5Qk6z5encQzEXZA1BscPts6lZzTq8NqwUh/6A5tBjivsf4hNDpng7/2PVCwM
         4aBr9Ret7WLYLx4k3TWq+gBrF0SR7+dOfYvNk+rfpdNOAv8y72c/qEcYjsLih0LgFJHd
         f6XvkP1zJrw2qFMcvc2I2FJnZi5N5OrldB71h45awOII9aIr8qqF/lF/2OEjlzSdfp6z
         3XiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=51ld=ag=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=51lD=AG=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kw3DYaOwHpWbuS2M25LLrulySgpg9P/NQoHRBnehQvs=;
        b=K+XTHMXt9c46fTXKmxiXcpqP73gmRVI1/FVVn435QtoEAXJEkzIYg3GeBPT3xF1G5f
         5Ca+fnYlfDAnW+3qbwDbNOhRRKRHpUQnhtqm3lk92jy6eR7k1C1kb4AwkpI4SbQP7ZGu
         kM6HY3xdBGbZX/HZJ1Y3KF+9XFnAdn2xjn3qIAOsH98TM3abJah1EIu2/g7ChPc+1SCT
         0FEEHcEj0C7ljAjBZjUJvFyOf6TgNoiCOTAD3kxBp74LbGP6r9bum7FfepfMJRNtLy22
         LCWmMVGgUYawgG5+H9i82W18qj8KiRIiuc7ABy0HoJy5LETwG6xi/wWqhHIfdTrtIwzg
         LAXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kw3DYaOwHpWbuS2M25LLrulySgpg9P/NQoHRBnehQvs=;
        b=YxquOJAfAjR5gCbdpqs3+2Epju+y6LjyG4KlnYkxMAx17cpbL4mM1kZa4+2fZedK+g
         grQzbBwJA9rl9k25+WRMTMXcEEZ16H7sszYOnY3j0qo7vtI74cbcCmPF5YXgAKkjDgyx
         x788GoLI85BcwOrmuKEkv7vodlI2/1/GBNWKFHuxzIdL4UFwlwNePL7IDhCxnmLZ9SvM
         0Q3dJSd49AahDJf7tIoaqFZSc2sfJGjpFs+H3DBXeNWYPw7MTyYj5st0TaGOhWFoWjdd
         Z7mCz8bpBIfVwodeq7LOsN7UZerJtU63d46IREIJKfqh10A7Pe72CDOiV+BCE++IkZZT
         kp9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531XSvXH+1Pmub4TBanQqk2rXauPSySMxAzQtWfKQeyM/vX3wDCN
	yh52IvFnw6N87AeaqDZz/zo=
X-Google-Smtp-Source: ABdhPJzu/4HDiL5u407z/4WZM9WFde8scEugua7xk6KOrxR7krWKDsO9RRw9LatLjj42can6AKR77Q==
X-Received: by 2002:a25:8384:: with SMTP id t4mr46937823ybk.430.1593066232915;
        Wed, 24 Jun 2020 23:23:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ec5:: with SMTP id 188ls1662712ybo.11.gmail; Wed, 24 Jun
 2020 23:23:51 -0700 (PDT)
X-Received: by 2002:a25:3203:: with SMTP id y3mr52458995yby.77.1593066231397;
        Wed, 24 Jun 2020 23:23:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593066231; cv=none;
        d=google.com; s=arc-20160816;
        b=QclcU0OBrqUQHz6OMaiHy9Lb5okUF3ppqAD0ljv6ZCK0dBPimd57tCxGe3xmwB1BjX
         +4cVstTvnNnNwLjEPaz5ou1Bdk21UnN4cuWdpKn/D5pw+jYucRylE7+Eu9gHtjkxM6rb
         d5nJG/lMrz+iAqb1HydP2NIWT9ctp8FEXrf4/uSn2HLNQp+KsMpGiKAXHPpeMKUjzchv
         y40YkFSTj+2TaHspx5CPCXJPKOZd+Xc/k+Jxha7zn+N/6cSpY33F4N2/0QSTFPKsrQZ8
         9AyBor+GfkASphh0CK4cfjlNqWl5y/6dKv82nodKCWDbs7M4W0pxypsWrFk/HbI+frof
         UoRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=3Bp2rxkVLIlTABgkUMT4AYakmynG00RBKdCfhUsH9cE=;
        b=dJSI+8MVzeB0Q16WYbOMTeDoNP+XAS/JWYa1XLNBwfY1XYfI8GGpaXKgbcHRtSIZul
         DZKNp838KEfUItz26hQ1wgMU8PZ8rPr0+XzH3cAe13hMcZgvJ96rbp33OMt2cXkgLEX8
         Gwni8eJ7BVVncJ8Vv4p7adePPKUSrcHfn9vRKp5HlvlCsm1Z/2WAWi9ZGHvwzShJdZ7P
         YTdf3vnF7WwDjpxKYoNtlz0CavCtRjpNztyKKGgHjf1Vog/05hNODAumRP1vSd7SP7NH
         G/iniZL0A8hGKDlMI2Z7JC6zTzOenlFzPfNma5wNw0rf0NY/rwk/HPPtLcVT/wrrk95n
         Al7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=51ld=ag=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=51lD=AG=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k11si1707375ybb.4.2020.06.24.23.23.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jun 2020 23:23:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=51ld=ag=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Thu, 25 Jun 2020 06:23:50 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
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
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-203497-199747-qAtt3AYCM2@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=51ld=ag=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=51lD=AG=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |dvyukov@google.com

--- Comment #15 from Dmitry Vyukov (dvyukov@google.com) ---
Walter, please pass the stack through the scripts/decode_stacktrace.sh script
to add line numbers. It would be useful to understand what exactly variable
causes the report.
In comments 8 and 9 you posted different stacks, which of these do you see and
when?

I would try KASAN_SANITIZE_STACK_init.o := n anyway b/c it's just cheap to try.

One thing I would is the following. At the end of kasan_init we do:

        /* At this point kasan is fully initialized. Enable error messages */
        init_task.kasan_depth = 0;

I would try to move it way later, say to beginning of rest_init.
Regardless of result it will give some additional information: is the problem
related to start_kernel only? or it affects later execution as well?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-qAtt3AYCM2%40https.bugzilla.kernel.org/.
