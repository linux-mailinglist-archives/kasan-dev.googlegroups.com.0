Return-Path: <kasan-dev+bncBC24VNFHTMIBBWGT32GAMGQEQYPDQTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 621E5456FCA
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 14:42:50 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id x6-20020a056e021bc600b00292aa8bec6csf5845278ilv.21
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 05:42:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637329369; cv=pass;
        d=google.com; s=arc-20160816;
        b=hWbQBchQEqavlVm1OgoQleS6O8CHd6HIVa/tkWDMpWc9SoYR4wOsQVz/W/5tL+xelZ
         37zVXxr+yMCX/SJ5iXvnsJkKxJmtnYtS3JlVuwhDT6machPEFucG9JdDPJYEzoigRCH6
         77I9bGyYWUHXcg3veWEOJhAoMWdAEoJUkCakHPo9xEhh7nk52lRuxWWQZITwENwX9tei
         5c2X7kH+qcod2+/foUIs6VU+h+ZkI4eBHy48iHYDLJoj7IiDDRkOONHzDFGhHFlrMgsA
         b8AKCQf6D/AtlhpgUjYDHwU3YOBHq0tTHSRxedEOD+RqTJdaRCil/NZkE/q6vdbclaA9
         aaBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=LgBuiaa+iJl8Jpu/YJNHh/9rlu4CXEvUAkJfJgD4LSE=;
        b=A6uGumn6yL9FQ4dKTOSDPi0TQC1Qb2+XEywLiYzmepkseWFfdrK6a4d70mcRAJAowi
         r7vTgUMFJ6GyTf4TznZSbLRIgVZ1TjrKHpyJluKalKNoKmv6vq1tZNi6GFum5Bj3K/md
         UmanEctmCBLPljimNhfOdWaKJtEDOv3a/G6qI9PmYotCgY1bsTzGXudD1+4kIPZf9Tfc
         IKfxtS2YQ2hxphph5uu2/4WzZLXaYtSDzYemD6vXxc50ZolZtcO9c+0e4hBCDFVmCr01
         Kwwy+3TRt3d1m6Q/Zg+LLZz5apqeDXCX9ao6MrrJ4WPsF3tOVJdS5HljazrjttrXEn/4
         yqOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=X7477qTu;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LgBuiaa+iJl8Jpu/YJNHh/9rlu4CXEvUAkJfJgD4LSE=;
        b=NHu7sbEcI1MFjK0xW0XU01UgNssxwUdYNNguYeDNfctJ9XiHKaO22V0/JHR+s4TGqD
         CJTUyptt8yhjLSYwGlOPOfNOkFzZQ17pc0TnSrWqD8rT+Ul3cG6HzB786CeED1wqQihT
         S3nMqd8zzhoNlyZXADMdm1yrbgLSK0xIaHx64j3CRWidHOTc7hPyeYMVDVrOOsh3GoFS
         mcvMnUHu0nh2lJwot4sK4dgFo17eq0muICEQzeRvLnUamJkFobEU5BuT18DYO8LgY2N3
         yhAs/+05AkCJvZI92oc1vXFR/gYJkBTIP1pvzxGhPXtRau3xkJDJs2EmfyBcM+gpItsK
         bxUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LgBuiaa+iJl8Jpu/YJNHh/9rlu4CXEvUAkJfJgD4LSE=;
        b=2NMGCzK/s83qZhaIzi8+BpapRQb2P9cvXGL0QoulitjPxvTQGmP/HRcAyGdo/pNARk
         aLr5PRWEf/iVhMksqvMWB69WzYO4/KIMVini6UMQfEwrOcJE+nXE8ywM96UMDMdizQVk
         W7EawOLdOOE3p5jlLmpOYgkYSQ++plQpIcqY+M3zUtAYFFQzfH8nkhBhwwd3A33mHqGC
         76s4DbC3Nzv5XMwToY75Utf2nPEnLrnpuNk4wHHYRr8U7qYgrpPymfMNQ7U6fkMxMPYH
         OYcH0/GnI/h+SzFZgMhHoTm0BNmYQDm/bCNoZfyFeESpz1nyckcfEw/G9pyJZPBFA0T8
         ZjiQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532eWaPomiZKelPeySIKThiyBkdl4e8zwc+UP2aa+jnA5597QKga
	56ypM2PhyEJGouAM5VQagss=
X-Google-Smtp-Source: ABdhPJzDmVdJofGX5Ocjn+gtPHhVb3EpT0Sn5gfW1+/SG30BRHmV76hbudyK8RYL8PhBb/oIMQyWBA==
X-Received: by 2002:a92:c541:: with SMTP id a1mr4853950ilj.5.1637329369113;
        Fri, 19 Nov 2021 05:42:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1ca7:: with SMTP id x7ls558664ill.5.gmail; Fri, 19
 Nov 2021 05:42:48 -0800 (PST)
X-Received: by 2002:a05:6e02:1886:: with SMTP id o6mr4915747ilu.13.1637329368641;
        Fri, 19 Nov 2021 05:42:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637329368; cv=none;
        d=google.com; s=arc-20160816;
        b=dtxuXepqbIhpkkVbXrAeuXmdq6LuJdhVMWmzS0R2TxIoMSYcx2g5Sv28oTKQRdYANF
         vcw5Q+ZacUBqyZa0j8ec36/T5oGWeoUrqu1n4yAPJDp0JfbFkeBSOp8BYTRO2vH1GaAs
         if+JykKRQIKEfR+8Hp2sdGc2SSVs10pMpZqE8+axtcjg0lMIfwL1F9f0+44gDWkuJm1E
         X2ZORHvl4kOdiWe+F2aprf9E5RSIfjshiQnJhJNbriL00XnKYyRAUJqQy/xgWa/mfJGV
         e6tSj/g6sXwE8w2mTBuC7hkiVTxm+NXwtYJV3POmgScl1HfTl8NGDere8eheEKtCZ7l3
         Rv0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=O47RMinIkokGmEvihNa6WVJ5ngiQvtOnpTARnaga5jM=;
        b=P7MW4NZHTaKfX5GkrxQeYIokbwxvoW3eY5jSHcGhAUuAXBKclh3l+1YzFCGi363LNh
         pxxSmNdkRn1Nx+m8yaAjXxpupf0uS0D27TLPHysmsx859mtMyCGvCSbgzmKX+yWQqwJZ
         ENsvG1rXRqc7trA9i8ANFnx/9WLJWBW5DDsv/71PlBzuEPnjn7NNblrdftRnjnMhovIW
         uuU2ATzzA6EZzxq4x/PtPFPnhmZMdap2n/V6hXG/3tJGnPFajrjsz/gomyrObQoWcc6a
         KDb975iYO9HoeFL1bUmrWmCC7IhMAobQsHR5Wtz69ydTQvc/QcnokoQFGTESTeIpTp/I
         DgVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=X7477qTu;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s4si103270iov.0.2021.11.19.05.42.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Nov 2021 05:42:48 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id A466561AE2
	for <kasan-dev@googlegroups.com>; Fri, 19 Nov 2021 13:42:44 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 959FA61004; Fri, 19 Nov 2021 13:42:44 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212181] KASAN (hw-tags): use read-only static keys
Date: Fri, 19 Nov 2021 13:42:44 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: melver@kernel.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-212181-199747-ThaYzTrijX@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212181-199747@https.bugzilla.kernel.org/>
References: <bug-212181-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=X7477qTu;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212181

Marco Elver (melver@kernel.org) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |melver@kernel.org

--- Comment #1 from Marco Elver (melver@kernel.org) ---
Fully solving this requires reworking static keys itself and how it maintains
the list of locations it needs to patch, which is infeasible.

The problem is that any static key that is EXPORT_SYMBOL cannot be read-only.
That means kasan_flag_enabled cannot be read-only.

However, kasan_flag_stacktrace can trivially be changed. We can leave this bug
open just for that static key if we're sure it won't need changing after init.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212181-199747-ThaYzTrijX%40https.bugzilla.kernel.org/.
