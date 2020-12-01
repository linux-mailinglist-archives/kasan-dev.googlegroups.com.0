Return-Path: <kasan-dev+bncBC24VNFHTMIBBSHQS77AKGQELS7MX4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id A6B7A2C98C0
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 09:01:13 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id 141sf694303qkh.18
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 00:01:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606809672; cv=pass;
        d=google.com; s=arc-20160816;
        b=d88leKH1oQpKCRTDlfcrN48/nSww3czEUawflSBDtPZKtU1l6at9FfEIZciR6WIfju
         MXk5z7vW0jYiH0iAY+HoAnSQFSy9IAJOHxDMjPvY+i4Z6/V8X4ZJ0jcDqbbOXyRD3nNP
         lrpeu7qDyK7IfB+t/alaYxy+0fJMeOogxDocXC7CvcK+7Qnhk9YvRKlJNmm871+DdQcY
         tzxQ+/sv0yMpDGdforxisKWT/NmjnXt88BfHrjknmPnjeD1G9NMwSbmYPZJWaR83sT11
         J+jxpb1/9+YzmnQqFBuAS4ZRhBvE18mGWz91hp0gehQ8ZMDwJ49NXIbNo3v9Sfnlx2Wv
         8Avw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=iSWoFdS0XroG8HyRZXy8LZlULPgRX8N+Qx3mFA+4XJE=;
        b=K7RL6YvnE1Zo2mQ1RrSPTN/d5EIFu//r0I8zXwJVzQfcGgy5VWZvCm2g6hCzn34YZY
         KOYZ/IGr1AiERdbrcGzwkhltbE1eEYWW1IHljeGr6JYgi0SxP82cW75TkYYbynNNuHS2
         IGaQURCy3zY1GX+Ka8u65tAJset55N/Yq/nLSUeQnbRCnL0Vt8djEUoUMtXQSLezh3eh
         3mK9hWrr01F3h7ryn0dc3ZtacriG3bd4Qp6dHxNVCE7pCQAu3EMBaFpChjiHbWgkBZ9P
         LRL5I1kBxteyCN5rmggCB8sYNaQF0YBtcjdFSYmkWLrzoQuLNmVvgsbRxZIwZXpeoaUW
         GisQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iSWoFdS0XroG8HyRZXy8LZlULPgRX8N+Qx3mFA+4XJE=;
        b=s869VbdL1KmEIjBXaXB7pwPHil92a0taVzbSyPN7ATRhNSK25nVDYyvw92cEddiVTq
         4Ef+2UvH4czNQO7S49A3NrjQBNeYP/e6ViEDDfIzj/KcqLSX7ApRF5eCtNEJ81c5ohwY
         XUdByeICCOwKMsbJcPu6Q8258+jAO7dut+vc6/7ls+vA/yOKkBg0iAHVG2DVOoKMfGTC
         L5X7SlkXs2JT3CMj4Mof8YH0QlGLSfPa/l+ntUAjRVAvT4JBqrpSO+MSedcPinO0VhwQ
         RW2E3JWyEg4xkk0KJ57TnVcW7ONkZZBFjNZzPNhsOmSChrBoe3oiU0ULy7zBWC3i83Q3
         rJRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=iSWoFdS0XroG8HyRZXy8LZlULPgRX8N+Qx3mFA+4XJE=;
        b=k4w6OuMPOKK4gtIY9Aj1flHNkxrSUfoSVuzf6jtIoQ4BqUm2gjUeWx3mXD9NBr+99+
         SUW6PsxCoCY/enIRBjekfL/yEJUZtWlrDQAs5kQ26rK5fHdxFUOr4It3vThK35MS0vJC
         G2ZC9cpNVqh6dSeT6v7G+AKKGP9HFDm4wr93QQ51ySsynwJ/4705dHzKb8+VCoxZNNir
         H7eYX4/16xcGB4hSbVlQNExEGZRot5xha7o9uTp6vxGr4FxHfuGlVa6PKe9vH2Pk8jnn
         WwfmrWZQezUfG6ag3vR4kSLbgcxjnKjMWhwEbewQXSSI9vvipNBN9OCb2NCU2f9Uh+JG
         Y3Ug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530I/Tr4SuG3YT0j7rddANM05QKvrmOKrhXU2XjhCj6Xo+Ie7O65
	btVgHhCBpF8DfCCGJkPIrNA=
X-Google-Smtp-Source: ABdhPJwmPvlyd6umi4yFQhMup1i6Svq8jEg138vpe4exEll+5His5bXjqYw4uKJi1QiUyuNBXL/VMQ==
X-Received: by 2002:ae9:f509:: with SMTP id o9mr1637829qkg.253.1606809672614;
        Tue, 01 Dec 2020 00:01:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:52d:: with SMTP id h13ls565271qkh.11.gmail; Tue, 01
 Dec 2020 00:01:12 -0800 (PST)
X-Received: by 2002:a37:6f07:: with SMTP id k7mr1608790qkc.476.1606809672228;
        Tue, 01 Dec 2020 00:01:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606809672; cv=none;
        d=google.com; s=arc-20160816;
        b=cCU9yYk4oEVFJgh4h7Rqv4MsyuDGo0yAm67e+VqfZmnIDoD5irWIahECcHgG7dauAZ
         X+ZBjPxHKPx+ewa6qmvUsp5Qtc47N6MtNpQNqDGdXs9AmFSFJlRuXocHemd5kHFtsGoS
         L0eAnZKA1CTURJMVgfFFTw7z2GmjUQqGn5wj2vyWuL97Q0ctTqtnlh4P7QFLL6bdRr8w
         7KnZPre79mWrl+IDzQqaSVUAW2vV3rpRhN9lkuBnIpyqewGO3yz9q8+eGgm5ARFyvLZ7
         833eppvMMC1lEwfvv2Jzunc9v0rulsPUUJm+rJoogKmDA5iCrs+UCPFMESQ2KsXSP4GX
         CuOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=4wyiCzh8xk2lN9JC3KapbRFlcklqJazv6LN4X2FNmaE=;
        b=FEcIEB12ewabx3JP1LZB/Tggb10gr7F18h3q4TbIOUxVJEolQ0JKDNQw8kbgzHqx8X
         qHuC83eWKcMxnZBb6Q4Q80ElApASX8sY9XM3I7coCzwiHVKtWgD173gruyQ+Uy2Tri9+
         U/RV7mcLfEicxnvu8pqh6zjXH7V2X7vjasqKqAs32xswGuvmzXe91AXH+3BkqsjnUf6p
         XTgqVc+60QsJoa3HwzeO4TK3AsOKvyTmROJfzlV8LPO15yl6NT0xERCjyTPRfzEhoE7v
         9v8P9rCibh+zGDahfza0MmGSPsKx4RieOMRo26YW5PJV7MkpAnjR8Jdm7lnJN1a/XG+C
         NB9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h185si58285qke.7.2020.12.01.00.01.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Dec 2020 00:01:12 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198437] KASAN: memorize and print call_rcu stack
Date: Tue, 01 Dec 2020 08:01:10 +0000
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
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198437-199747-JYdSs8EYcl@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198437-199747@https.bugzilla.kernel.org/>
References: <bug-198437-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=198437

--- Comment #8 from Dmitry Vyukov (dvyukov@google.com) ---
The following commit by Walter Wu addresses the main part:

26e760c9a7c8 rcu: kasan: record and print call_rcu() call stack

There are also these patches mailed, but not in linux-next yet:

[PATCH v4 0/6] kasan: add workqueue and timer stack for generic KASAN
[PATCH v2] rcu: kasan: record and print kvfree_call_rcu call stack

Once they are in linux-next, I think this issues can be closed.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198437-199747-JYdSs8EYcl%40https.bugzilla.kernel.org/.
