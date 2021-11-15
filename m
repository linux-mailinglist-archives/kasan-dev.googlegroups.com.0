Return-Path: <kasan-dev+bncBC24VNFHTMIBB74TZCGAMGQETSHSFVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id D3B0144FF29
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 08:19:28 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id s22-20020a056a0008d600b00480fea2e96csf9568422pfu.7
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 23:19:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636960767; cv=pass;
        d=google.com; s=arc-20160816;
        b=CeWdnyXStFBWxo0wemV7E0WAy5hq1WT0l2mvoA5ST+UgQqz96JC50ihFsIf8R5poCo
         o81GJnuru4vlQP0kZ6eUmjbcpGjwWHwRsx7AGtCH15SEZFacwqgTyi2EwBkBbQI7ph0i
         AtmBMLoQiaLZnfBvgt57V06vcM3zUkR1jmWgbLglZMhxIuOpSignE/hyF4UhQFonRh9c
         BjDW4pyx/cifuGiOPC974so6/IQKrc7j1/bZXJt+0uXCBi5Jyn6q5gL3M6J0oMlwLP4q
         dlOauitGsmH0wqZuyxCK9Ww780LaPVFSQcx/cMFcI/rCc4NwPiNdHu4i/X8L9ILJ3IMl
         hfoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Tre9o1KSLix34hqJIVTsHw4maPge1g9hbgk0QSJ9mls=;
        b=yp+gZV8MYXtphdNTRml6CMF4K9jtlxSLyF8F/okCcv/Tt8VOitam/CLS/zkjO99Rx2
         +szcGZrkw3l764o9O9V/uodtNXJba02DyHsmW2Q815u/C+LVyRCxenZzB+eeyHSjyAHI
         ZwEit15gm8cQEOJb7GwxqbYwnxAmvTM2qva1QHZFBAW98SUSTK1cqBZzP9E5lRGHMz+i
         j/Z0PuuyzQOSEQ9RX5jMBhaKanoYpe/yObJWxg6R/cghpCNKmwgDqHWaEtdZlzp5J3dx
         K+U+r5aA2rlzbCfWhlHlmqEbv34wXy9CAd1l/M2GtD+Lla9kiLoxlV0sSXTXBoTnDclR
         IrUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dUgbvweN;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Tre9o1KSLix34hqJIVTsHw4maPge1g9hbgk0QSJ9mls=;
        b=CXZUlqhAjI832emaytmR7aH8MehftaHq4WxvHVm93VmwyX63YUbHtCUGUPVQCKFFFH
         Dg5U0azJ1XHtFS+zRvp0HYMNNaVcfKhKdNoRYd1YqZwUMr4lt/LOY3cgG2TtIW8UsdHK
         eiAlOKgXHmZqN53fmbJN85Pwt8PJD6oUvhKq7sXVSagqS3uuBKKYOvRWAOx7TNu/vOSv
         1UF+QIGKU0WiylSzwqOCHwgkl1AGYrdBVa2OYgkyGmVdQZfXHzNNcGBhSLfmx1iBeFbs
         C33gWPIGvfJBk9BneQ2+T6WAY8W0fgfJq7F44IcgIpSOIBkoqCAwViiPRKFkdta8L6iA
         vuJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Tre9o1KSLix34hqJIVTsHw4maPge1g9hbgk0QSJ9mls=;
        b=KBV6MNdZrVTg6dYMMgBZpIUc00o4jDt3OCKlCUWhYnM24Q3OZf9aPe/MuudA5CFHnX
         3Elsqz/X35DA+VbjAwQnUchKOIV2Xp1LC3804fN/fr+73P9Qv00ldhIRg6jlG7sm02pJ
         MOy+gtt1oxfdy83ip18qbBbrYPSnE+/6XhQMJKpuhS6k8Lat5AYd/OZqBudKYkYrlRvU
         8fVYZOcE8p8+p4tPPZO/dCKx2hunDY7r1UvOMxmCFvSifRnePDYN1sFLjyCEvWZbJZIQ
         6ZWoSSoC/ynYTSoQLmV+gNPi+ch8fQ4bCR2oc+8wMqd5RcsfSBud7iscZ+pOxTQD1WIk
         UArA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531I/op9Lvlwr6QIKWdrZu7yg1Oj0KrOoa8wMCZXo5JcGoIwR6mD
	zroz2wboWdV/+WLKbisSH8k=
X-Google-Smtp-Source: ABdhPJyWKVOz1iX1gy7QlZh+bzD/o5udCcEaFXHyt3cvW2KE8iqWszYsXwx5txxvSLhDig/lU6JBsQ==
X-Received: by 2002:a63:bf46:: with SMTP id i6mr22535229pgo.218.1636960767188;
        Sun, 14 Nov 2021 23:19:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e5d0:: with SMTP id u16ls8669603plf.0.gmail; Sun, 14
 Nov 2021 23:19:26 -0800 (PST)
X-Received: by 2002:a17:903:2283:b0:141:f858:f9af with SMTP id b3-20020a170903228300b00141f858f9afmr33181592plh.80.1636960766696;
        Sun, 14 Nov 2021 23:19:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636960766; cv=none;
        d=google.com; s=arc-20160816;
        b=dQaV8pncRIZN3FhVhIruz+CVDk3cIEOVCE1h6BEZoh/2obJFqZOC2a/1wxdD4PrPI+
         cjNPb3dYF/vqXBMg8T6GlBuyaqejAWWqzFZWqxjpgUqA9BbxSpzeTKoOMGrVn0P66byc
         Chf5tZ2Zi8dFM5fboA1oobgQPaj5tKVD+cRzPMv1Tnes0Xwmwxuas60aqa0O+deOfjOT
         kFSuSao7o5UX/GrmMh/EMM9s/ezU1Hj4EmJCkysdZm1sAOJq81n2t0RDcQZeJmSw06B7
         r3wywl9UfssLkU3Pdw4jZJyt7umO353YVZQtPFDIiVb/NxvqDf81FVjc5w20qXbf3ber
         s8YA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=TgSCgDPnBGjvvByPUGwiThXFqtBH1gARYNMubXzla1A=;
        b=UtcFjGKYO2nknS1+0gFxTwjCQTkZrcWTGDQTyVNCkAwVgWjAk1iGczAN6/xwwdqyLG
         LE/be4NhIbeXU/q/Vu3XaPdXjzKswhXehw+EdF7BbLeh5LSDrEazOlfalxjkAL5YG7mw
         s31yZ9G7Qbqp2wNd9G2COyvzOpXddlXJPiufV132ByfKGH5e0tC+JCLnHttqzGVlZIAO
         G4bABt7UDIwK6h69Io0pw3FE7lhziPzQGnaXdpLcV/ESlwFVhXfVKwBffBH6LljLFByd
         prOc9i7OTHuu6/y8D1Tx6uiTVnVUvdtt3dytJGk3GcVu6HIbVYD2VgDmmr8Jgri0cMKp
         TL6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dUgbvweN;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q20si1080204pgt.1.2021.11.14.23.19.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Nov 2021 23:19:26 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 6509463218
	for <kasan-dev@googlegroups.com>; Mon, 15 Nov 2021 07:19:26 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 5093B60F43; Mon, 15 Nov 2021 07:19:26 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 199341] KASAN: misses underflow in memmove
Date: Mon, 15 Nov 2021 07:19:26 +0000
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
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-199341-199747-D3WXrSKotS@https.bugzilla.kernel.org/>
In-Reply-To: <bug-199341-199747@https.bugzilla.kernel.org/>
References: <bug-199341-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dUgbvweN;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=199341

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-199341-199747-D3WXrSKotS%40https.bugzilla.kernel.org/.
