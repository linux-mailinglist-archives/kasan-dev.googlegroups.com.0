Return-Path: <kasan-dev+bncBC24VNFHTMIBBD7SS77AKGQEH3VLVGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 770702C98C8
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 09:04:33 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id e14sf751026iow.23
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 00:04:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606809872; cv=pass;
        d=google.com; s=arc-20160816;
        b=IsfJhLp6RNk+TCIhrcHOjYW9mZOZpJymMwWa/koOqClcjil4/I/BIaNmWAqG1j3V0k
         1FIWyFc6rYbAB/173TZXdlzA4IS6oPODPScDYGf3vPx/dn9Fa4cCM2ayUSiZvfvgBuac
         FNQ0wYKpcaOK8CuHYZpQ3P/epiHzYmPTikRx8/JNz6o3dPzXETt3S5G3+mwYMi8rOskA
         K7XgqbsmYrswt32XYcPYP0GcyS+8U9kTU59JsJM7CMLraiqiFp750FoXbLus4HYiKV1g
         43J+i8exoh8vryy5uPy9dsptzG9zLJNbzvBTf8bNMFNbWfTnNr9BRMECDIw4SviWPJvA
         wjqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=102wNJcC4Y58NQ+5g9Onn0ZZjkYhGbUuUGBKKglBmU8=;
        b=JByLxh7LZnjUysxNlFIxL/DdOyvD6d08QU+tYhfiWmjhLczz7HU3y/0srTh9gk4y9a
         /Whm1bd5iaDeL62eqeTDzJ8q/VHvGar38Ri3NjWkpPyrMOyo/UfHKTDJpbNe8FP+IG3f
         UdXp07XgtkiyPVnjX0bR1RIeSN96GyUURThgbrmihxkLpGqehVK7cowRGNwF/YF/7EMl
         wov0Jjh/6rD4iHpNyyv9vXHg7IdrsNKmk8a7dlUCNVYn1mwVp94CyZ7MN0Os7fd36Qh7
         LNAkRGvzU0lEJaD21bc8rPo7qJxUafU7BpN2dxHx8s1RYXtt1XyoBPZFWpsbn0IVlzZq
         +HLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=102wNJcC4Y58NQ+5g9Onn0ZZjkYhGbUuUGBKKglBmU8=;
        b=MB2vx0YVrTCUpfN/OdVKOBK0LlyhIGOBS4Rgtn8Hv/2FiKFMARSQeowlCZ3+wyNgRu
         N6vpENqgm42zupASFyVHCjUSTMpE007JadGiVTM+uYzAUrop8mlwc+xV5GYzxD4uee0+
         lRu/Cnfwo1Wpqe13z/NktLH+arAmB2dcg/54Neo+5rEJJJfMmsewsVU1UzQhODZrUouT
         UvRASKOvJARy/3F1GVPFfR13gorEtb83lJqFX2CIJn7isGetqfWIb9fsn3aN3DiYlbTJ
         FhbX5v+CAo+eAp+pFKMJrsx+cdjZmvATuwzHdCMmH1BxBM1nuVNO1hSRnpn0/KQxNpkZ
         ludw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=102wNJcC4Y58NQ+5g9Onn0ZZjkYhGbUuUGBKKglBmU8=;
        b=fuc5ycnzaxmmc4gk2WdDj8oXNVmqDRNLuTqO2D2IwpZ93ACWiNaSyCsa3KgvbHXL4x
         q0o/R1BxM2a8Zw93OTxeJSMNylpfQkwkccOrG/qinmDPv3p4j4Zztmw7XGhn1DqNWPjS
         MO09Lb7BblztqQh9CwDacwo6kMC1Kg594209iJPrqV/RBv43vndgfI34PsLrX3qaB5mS
         fcTE1sCsTtyVAcC1ETmBiUvK51iOq4vVRW8wytI+EtMWzp/73t61w9hojZMqjkevci70
         ithPBQfaP7JtCp1MhZa6SsBsnN/UamGzJ+rzf0k2Qfmcml6alYADr6EXLswfC2R7Ls4W
         vndA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533K8Fzv0KeTKmCaGaixtQbdnraNbnD+P8lkrakTmOIWA7emYD4C
	RWa/cQH0FzTrqAk00GXCh2M=
X-Google-Smtp-Source: ABdhPJzoeleDLOc/vH6y8kTBjMEyZEcl3XgOZZED4GsvrS4Nxdg5zCdKoF26aMwtmatEa6AqKdJOLQ==
X-Received: by 2002:a05:6e02:926:: with SMTP id o6mr1522983ilt.65.1606809872037;
        Tue, 01 Dec 2020 00:04:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:ac8e:: with SMTP id x14ls141730jan.2.gmail; Tue, 01 Dec
 2020 00:04:31 -0800 (PST)
X-Received: by 2002:a02:bc9:: with SMTP id 192mr1662764jad.50.1606809871715;
        Tue, 01 Dec 2020 00:04:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606809871; cv=none;
        d=google.com; s=arc-20160816;
        b=s3bX3q17mUeNTe5fAzYxRyN5bx0Cyu5bJE6X87nl4uXoHiG+b7AhJId4sdUNEtkMvy
         qmtUuios2p7b30uOVSbhhtpaFyJE3aI8fxxy3uJS8+D2OOCVJBGfp5QKA2RcxMcvZxpw
         olon5vLmYPtLFwJw53QUZWEakaxjehHzMP6gn6btRqk1xGmhmd7n+55i6szzTTVldBf7
         MvS05AiKl7qlMTcIYihvIwDlKPCNh6oaBh4kISjgnbjGrOW1yVjTyzYIAiIPWXGnKD+T
         QvFIk7VUygI0fR7IWuqaYX/2QnvTYSphjxu1XRzdpkIdT8yIvHjAesXgr3RqzRxVWtmJ
         6abw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=SnHqUgHx49JyWtDjF8qMEkNEjG/bRvZ4y/w1zafJO1g=;
        b=sFaO7Fc1rt/DJBaJtsOx5aumVahqcYVhK27uqZrhXm6i1wQikEmN5FOnEMyf3lId6i
         GhtxhrtIGz9k+zOFDZkSR2VpLSt6tfAMzyMBt+p7emZP8Y2sCtsznCeoFJgSUnmPqRpC
         341ohL21CD+vHyAKPGengNHZ7BzWhQK+uMMWG8UdQAqRCMVzRfjfBTvgpqLtR63FKoq4
         0RVjtek1hLReyS/yoKSSNmHnvVpy9wGBZJZYzkH1q76yPF0S18DXCI0ijH+m5xuj9jZi
         zuN+D+5sy486FuGBfYdEyHbdYcA2ZTzCeUjJwUMtVjoI0PRhfDjNO3eNQG2EEESBi36O
         pALg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b14si75789ios.2.2020.12.01.00.04.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Dec 2020 00:04:31 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208461] FAULT_INJECTION: fail copy_to/from_user
Date: Tue, 01 Dec 2020 08:04:28 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-208461-199747-1zoLaIiGs1@https.bugzilla.kernel.org/>
In-Reply-To: <bug-208461-199747@https.bugzilla.kernel.org/>
References: <bug-208461-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=208461

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #3 from Dmitry Vyukov (dvyukov@google.com) ---
This is implemented by Albert van der Linde:
2c739ced5886 lib, include/linux: add usercopy failure capability

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208461-199747-1zoLaIiGs1%40https.bugzilla.kernel.org/.
