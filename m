Return-Path: <kasan-dev+bncBC24VNFHTMIBBL6UWDVAKGQE7KD7UAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B35E863C2
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Aug 2019 15:57:04 +0200 (CEST)
Received: by mail-vs1-xe3d.google.com with SMTP id o23sf1465344vsj.6
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Aug 2019 06:57:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565272623; cv=pass;
        d=google.com; s=arc-20160816;
        b=n/PJIfRo3OXkbNtPB1vbbeUiE84bu+RT3H9aUolhoRXTG9f5w9UKIzoFIdnqamtSB3
         MzG1rPo37QXv6YbhVHAlIqG22zQbKfD8N0xa3IvfJzUzai+1dWgqUdQzPXGgqt6i5Mjj
         k4Kqp5p2IRsk8hS/uwLIRE5iAs+Evia+64xXJbxNnln+ZjTKzc9pG8C0QakojAawK8pi
         Hy2Zi++INRrHchrypH2A6jK/P0yUncv1Xzi+0n7e2mbwC48LeDFHsZu9A/lKnCR3PENf
         o+/EPhSe/QWi6gg1xvdlqlX20AYYxdlelp/uoM5FS/O8lcTvD1mI0pRru5VyML324RJg
         mM1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=4BrdjuCwGxvRFuXKxS0ibwFzaQU1pXQBdOixylRu7UQ=;
        b=Iez/ZWrlhJRZoNenRlcbzvQqUARB9kr6U3KIooODJIK3PUOs+BuLZqz9s+zNBWQOJr
         MtqqY6q3d4k+x1JV42uBG8qV7A7/FN80AZSCgoh2kg5mvOD66yw8m2b0hVzaQQAB8HIJ
         s3afubOTCvQ842Sb68rhZLS/xG98wWp/CAM/cNgbYV5DzEQTQWDAL8aX6FD/akz0rCvr
         rPc7spjMhiLiLYEJc/18VhWTTrpN933rNLTtM+HU6Pqk0/W2YDCrulRUimvkFnm8fMl3
         h/uK+pK2P4uBEnQPHdycNzFS4xu8g+zAPZTF/GFUfQqsS0dqgokb0A8nlw1EbcVkBe3l
         IPxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4BrdjuCwGxvRFuXKxS0ibwFzaQU1pXQBdOixylRu7UQ=;
        b=WEPMCMepZXbVc/MQwN4H7McMwaJEgp0lZhbCPn8CfGX+iOCOaHBwJAF+mfoSgbpAz8
         sfiPRDBXFvpJwGEpIAkp1j+GurBj3IBASbjnRSeB7MCRVbpKCBJTSc5cOStFFW/C4D9C
         gtY5n3YQhSDLKfJfiYCe4mCckoFUcR5W0DprmgemKaqLt1lRZFQp5unrmVP3xt8vMyCn
         U+Iw+H3v4yH2R2HEdpLZOJG23JdSkEpuqdYEVYe9nl6mjxN44dYLod6XowlkBUMcAhBE
         EI4MgDLKdgxuBYMEmkfVjbXeut+eaPl/7LZ1SKfCJSVOi7ksBbIdJrPqcDtXJwGqW6jK
         mTmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4BrdjuCwGxvRFuXKxS0ibwFzaQU1pXQBdOixylRu7UQ=;
        b=gqZ0Xh2Zdr8BSLZ/tbYmKsA2D225qfepw/ybs1vLfUQ+QwqFBvBreoD37V1QXnn2Ci
         +hbl3QPewng1hAhmyPkyG644exg1Rna7r+k8VJpkiPVE34PFJ5w0VtgfOPmiPawMQO9p
         jo9B8wpfe2iuNzk3m3YbJPSSfAsD81ZfxdgsnFaFCCgsGBKQ1Vsx20J1FpdMLQsuukF4
         ELYJkCO/FfEUxj9D5ybd2HGwOC7h2RVhtNnB4NUvZfVxCpr65FxmYBVl1jJvOGBcRG+B
         P7RFeEjSuvvHI4Gqz1kgaPLki0e+EZKlF0bRVOxutI5x+SYEcUc5hzXqpIy2N5jJfbO0
         4UBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVgqpv5vwOpJcBD1TpAvVBd0KU+rLfXCim1eUc6U+8+KYOMHFUY
	bW8osZF9RtJvd4PydUJVocU=
X-Google-Smtp-Source: APXvYqwnqQRchpC5kNFZwenbe/jNB8PTM3GEpPJLGduOe8OWrxDviewxPCXda4Yl8tWlIfMxY9ZnxQ==
X-Received: by 2002:a05:6102:409:: with SMTP id d9mr9613735vsq.51.1565272623525;
        Thu, 08 Aug 2019 06:57:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:218d:: with SMTP id 13ls4065uac.13.gmail; Thu, 08 Aug
 2019 06:57:03 -0700 (PDT)
X-Received: by 2002:ab0:7782:: with SMTP id x2mr7000304uar.140.1565272623310;
        Thu, 08 Aug 2019 06:57:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565272623; cv=none;
        d=google.com; s=arc-20160816;
        b=emhz54yOGItja38ZTx+3o4Eurt7mdBHjRImD24lbWmUT9Yj26mXN+BKRJS4reXRxU1
         od4GZSwybQJUoIJj8MS4i5hSJA6oNSTc34Nk2zseNX9rwicGzo0I1PL/NIH/wqQUtN9u
         7n950lVT4XqW9CgaWgeILaJX7KDnJMBnc/3FGvzcyirL/kYU83mLq8h/Qd1WvSWeJh0d
         fVNbnhSurJFy7xvbUSeZ/Fdhjf++c3Ek/hfa+VfCZjmeASSCpvd63hKnbJD0adqEQQ6w
         ZYdIdujfKGqTXStmiogDJft8ygpNGVZtzi+jg+/zPBObGUVbH7wfJR9qvcczgOXPByK5
         LnwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=crZVW6qLDkEYdswHPON0Te6GMwLGBJQrAQd+8YlH3cw=;
        b=i5FYF0LroCealychKRCts69ArF+L1WofAoLAaHyaNvdlOJtdKRJCdtwAKCA52yMM25
         9Kkgtp8MVthGU1RNJApbX12DIxDONqgRqpABq4/1VNjTeEBgQujgPJP/R6eAr1RDvbIw
         SCdmdYwZ8SmMd7aw8okBL1x30OzH4okj8yvF+gCycfSLctyxK9ucjJozkgaEslXL6sBh
         l1/PHHR7YFz3hzpJdCXB4lGC7Y7GeYbs4Ch9+FRZVeq+s+HpXqbh8PWWavQGuHdWEomB
         tG3By4fxNggMXvUKjKXoMZsoyovG1kEmdwW9USYPmIXhSN1oNgRXwD8vrDHrKkVBxIoo
         9jpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id d8si4327695uam.0.2019.08.08.06.57.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Aug 2019 06:57:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 2FCF228B6B
	for <kasan-dev@googlegroups.com>; Thu,  8 Aug 2019 13:57:02 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 2DA8228B66; Thu,  8 Aug 2019 13:57:02 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Thu, 08 Aug 2019 13:57:01 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Drivers
X-Bugzilla-Component: Flash/Memory Technology Devices
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: christophe.leroy@c-s.fr
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dwmw2@infradead.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-204479-199747-yGYCwlUABp@https.bugzilla.kernel.org/>
In-Reply-To: <bug-204479-199747@https.bugzilla.kernel.org/>
References: <bug-204479-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=204479

--- Comment #4 from Christophe Leroy (christophe.leroy@c-s.fr) ---
We need to identify if the allocation of KASAN shadow area at module allocation
fails, or if kasan accesses outside of the allocated area.

Could you please run again with the below trace: 

diff --git a/arch/powerpc/mm/kasan/kasan_init_32.c
b/arch/powerpc/mm/kasan/kasan_init_32.c
index 74f4555a62ba..2bca2bf691a9 100644
--- a/arch/powerpc/mm/kasan/kasan_init_32.c
+++ b/arch/powerpc/mm/kasan/kasan_init_32.c
@@ -142,6 +142,9 @@ void *module_alloc(unsigned long size)
        if (!base)
                return NULL;

+       pr_err("###### module_alloc(%lx) = %px [%px-%px]\n", size, base,
+              kasan_mem_to_shadow(base), kasan_mem_to_shadow(base + size));
+
        if (!kasan_init_region(base, size))
                return base;

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-yGYCwlUABp%40https.bugzilla.kernel.org/.
