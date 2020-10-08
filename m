Return-Path: <kasan-dev+bncBC24VNFHTMIBB5HJ7X5QKGQE5RDO6ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B5E9287CFA
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Oct 2020 22:22:14 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id y24sf4407032plr.20
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Oct 2020 13:22:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602188533; cv=pass;
        d=google.com; s=arc-20160816;
        b=WopOlWvrUW5QAsG83GGJNsqfxa2hsXBQZLMpC4ut6GAmaZv55Sv7tBz753uSPaxnNH
         Q/VCekNWpGGGDbc/OhbP6ygaEpZmq5aRSFxvf81nCR4S7vu5GtXfDcsUpZxdAdG5N95W
         45UnqydUuRoYr0Hh82cdKQBcGjNJ0parKzi5YpCU/syPZgUbJ6oFt8LqwkoGMCTwOmVP
         oFVM+xiwtUX+q+MfRg3VAapEJLhuoVhe9g1wFllZ6GZvZNM7nUdiy1N+7PbSCKv4aZYZ
         3YVb5hnvUXBx2L//WKqhhNMauWPblzz5+1501m93UZf+N6fF3WMtLEANYIV7DEXXpqIL
         NNMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=gsDksZGJSJCN7jzo1qk5uFxYZjuRgaSBVtP3oywxh1Q=;
        b=xUvVyx1lEBitTWrdkIrPxOVs3rKFe/ujjgZ9Az08WmN3jXzL8uYeQzy9xqqNrB/7EO
         9kRggDlAJqrHqwCgakxx5VLx95Sr8R4DULVFnLdR5XA2lP2h191U1rZvUYmBoOlQMtKP
         V4PQnhe8pfsNI/sybR/whambkKSg0YZbK5wvnDyaaAbtIbGZrPeV4JOg9zr/LVop1ofw
         g9yqj7w9K3WiUjsIvcXWa3q11qYDizVRR2+9uH6CApsvIDR9vtUu5BWsr3NdDpayZUL7
         6SzflFW5s9/9pX30WF9FW8cJAwsqYhOOwYtQTcSpjxgoSeJmyYmWVsIPmzu61LsBVaGA
         SnnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=mmdr=dp=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=MmDR=DP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gsDksZGJSJCN7jzo1qk5uFxYZjuRgaSBVtP3oywxh1Q=;
        b=Y9iFa/JU9cUGW2Y8eFLB5KKILb22OtAEW+mjimsJgUikjcqWL9aKr1ISpbtQ9RR0mf
         fJVprWeqHQsirl9DiMGLJRLee+pMg1GvzyFV8LWVCPMSU8Vb/8zBnRRvmdhjtiYdqbHg
         jEQPQ8ySb/Kjsfa/ue/93DbJ6UWr4atFXINI4LtX9Alz1J/i1vLw3h/aNyCsVVQAo8A1
         vs2OTki794LoQ759x5rNIFntmBaylQu3p5g1dubDnNywCAvd+izerA2CtfxoO7kr2dp9
         kiteBRaySkqWO/Hc3Lbk8S7NebHWbsLUofprhFI3gBnYYoHJjZrc6+D9IpSuBixdadN5
         1W4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gsDksZGJSJCN7jzo1qk5uFxYZjuRgaSBVtP3oywxh1Q=;
        b=W+xaR2aIujQS9f8f4lJ1ZDugeRQ+ofPiZP5uKqz3plaX8K6i8KJOO1Le3wt68mJk/u
         1hP9zUqHX8/KvqPWbm1aFEXYXyc6tyun5ZN/L9rdqNPIm+i3W5ZbsUc0uAi14yiSACBi
         /l8qmeJ6pG/W3B9UnznKc9nFYpmAjXVPfx946J5TK/jh0kkylxkpkjSkRC7vyx3lj7W1
         QDiblUU1/w99mo7Ti54bV4XKb+plfi8exa21NhJR8VPX4a3LgAHwk8vM9fBLSQUm9MyO
         ufzdenAOdEwmPh+oCOmEj8pJf9Qg5g04ikv4actPhT2IYSE+nBsbDKSfAWAvyshH2iB7
         sEiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532FnmaY+KzP9Bw0oz3vZN/Jr9FW6NNG4/1TR7ka8tHmG99dlwYz
	wencorOHD0Bcr1qvG4cv2nM=
X-Google-Smtp-Source: ABdhPJyMt+ZsH6Uv1vt62xUt2i6QLO6ByhHCPZ3drztVamxahIfv87ol+L1Q4mABBdprdyr7OTlQtA==
X-Received: by 2002:a17:902:bb85:b029:d2:21cf:dc77 with SMTP id m5-20020a170902bb85b02900d221cfdc77mr9367355pls.66.1602188532881;
        Thu, 08 Oct 2020 13:22:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1b4b:: with SMTP id b72ls2405198pfb.2.gmail; Thu, 08 Oct
 2020 13:22:12 -0700 (PDT)
X-Received: by 2002:a62:7d4d:0:b029:152:1b09:f34 with SMTP id y74-20020a627d4d0000b02901521b090f34mr9465581pfc.76.1602188532336;
        Thu, 08 Oct 2020 13:22:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602188532; cv=none;
        d=google.com; s=arc-20160816;
        b=DprUUkmTYlnmMLlcNHtkehpXDqHDjYAr6M3YbInD3O2scdXX4pCIUfZLVw6ZYY6s6E
         +2WM3pQdQVWIKP7ZoU+7tgQiAzjQKZUnD58OnkXjcopyFV4ksHD42tWOaA9dUDUJOQda
         jFjKjELl1AIUUfbkTwOhc/NCzPdwUgaVtbrgcf3xGZ6MsLwgZUshfjZFvfHfNeArp761
         pV7LxPVqwPodlnZOaJBAV0MArh3v6qbiidFTf/gfSw8iZKIPrIWblJuQEjMrlHaYDVVy
         ztXU8yjFAke77mq5PBwsSIox8/YOvm6mqWFo9EDVN8qhv18kUMo31pc1JfcDPYhTDc7S
         aQxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=rkhAIROR8QYMiek8IEdSUvvKUBhKefe/BixN2PbEVt0=;
        b=DrujTbWCc1uanqeCBMjqW3egFbiDJHbcYG8kbfAK11K1eTDUg3wv7O/XxBuQORTnGR
         I1VhfDcHoD21oXaij7QXtmILF0iAhjJxPmdRSjRAZr8IQgVFkijSkqDdldZXIBV+4ykE
         mJyIX0pXK4vG+XJDxu2s5swpcOtQNzOixIe6Wbi4pp2rAtfmgY+z5afU+U6zGVC/P4tJ
         YC+zv+uDEM3o6xIHU8wstY6SXoPptAwF1CJeklm8RTmHreFakH1uHdDhlgt0dcMlWXqw
         MTVtK/taLb/V+dFhUbvw8ZRo563Drtajyfkr9yPwIfnCarP3oybjQvkSqTnv9diT6AdD
         PZeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=mmdr=dp=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=MmDR=DP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b9si242901plz.1.2020.10.08.13.22.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Oct 2020 13:22:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=mmdr=dp=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206269] KASAN: missed checks in ioread/write8/16/32_rep
Date: Thu, 08 Oct 2020 20:22:11 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-206269-199747-9MmGBkihHH@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206269-199747@https.bugzilla.kernel.org/>
References: <bug-206269-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=mmdr=dp=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=MmDR=DP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206269

--- Comment #2 from Dmitry Vyukov (dvyukov@google.com) ---
By following call chain:
https://elixir.bootlin.com/linux/v5.9-rc8/source/lib/iomap.c#L328
https://elixir.bootlin.com/linux/v5.9-rc8/source/lib/iomap.c#L278
https://elixir.bootlin.com/linux/v5.9-rc8/source/arch/x86/include/asm/io.h#L79
https://elixir.bootlin.com/linux/v5.9-rc8/source/arch/x86/include/asm/io.h#L61
https://elixir.bootlin.com/linux/v5.9-rc8/source/arch/x86/include/asm/io.h#L47

I am getting to these functions that are implemented in asm:
https://elixir.bootlin.com/linux/v5.9-rc8/source/arch/x86/include/asm/io.h#L47

Perhaps I diverged somewhere to a wrong function?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206269-199747-9MmGBkihHH%40https.bugzilla.kernel.org/.
