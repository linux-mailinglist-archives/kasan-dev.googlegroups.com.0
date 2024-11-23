Return-Path: <kasan-dev+bncBAABBEP3RC5AMGQECVQY4AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 18E4A9D6B7B
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Nov 2024 21:39:47 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4608e7a1ad2sf58078321cf.2
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Nov 2024 12:39:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732394386; cv=pass;
        d=google.com; s=arc-20240605;
        b=EG7KpS7HFRVJQXf1mt4Pv9wt8+L8IHhu7ZciLVJsZj41GTQgZSd1vDmk5o6cmxMba9
         0Gfed5as069Hyho+btXgCAA1NtLCCCN7EKSVGkYfU1WLzJtWi53qO3+EaNLCFMLrx/t4
         /yOH1a4PLLlVDwBzCRgfGCCol9gKxbI46bEHd3a5SpoZo3qoAG7NB60sc9tYYKeDvqYZ
         H3NtTEqSIuv0xSz7+2Wwhg5s+mAyP8I+gGsOKYmRoGO/XzHcG1E9Ecl5ALWx6z+Z1+BB
         Z+Z/JCz/dJdnVwnwoX9RWXC8WopRtlGlfJX72KSm80XBaH2hkgU0v98xUVIGR0xKT4pX
         V5CQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=cCrnR4VGQ57WaL7V07L4ROk6AndKfrysvpmtzG6ZaV4=;
        fh=sr/B5yhJKetqFxcLZ+IxtcroITyAQUMHOmyK8t18PJA=;
        b=WPWYPzZooR4t/P7GhZYIDRAN4FCvsvVhWpn8imyt2BNAa2ZOPmgSyS/IPK+Txhs1Gl
         YNMckgofemuKRaO5Ohn4V+Ah1N3OBBNv5HPMbhWXHeCe8OxsN/qLL7m3Zfm/NfSbmsfp
         0ipMgvBigThsTYIv3eP9dhitKqARLl8yHXmsQCGll0BbPAD4vw8tNZagnQqGn9LTw4gi
         hTe9EpQcN7JFgR92jG+I6ewZ4QSR2Gleo7EkD4XG2QaUHptlxI+pgZsBJiSGSd1iIqXQ
         f/TQR8Dt47DMh2vqcUEI8XJwa9OT+njVGDx894nNPY8S0iNgFBjQcq2qNGc94GdlGxfF
         oXiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=k7CxdwWN;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732394386; x=1732999186; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=cCrnR4VGQ57WaL7V07L4ROk6AndKfrysvpmtzG6ZaV4=;
        b=WmiP3jL+fmROmtrRC/xtII4uf3ZHhko7k2KT05DCt6hvHoIKKUIzVDYKmHqb4mwFo+
         sSkUW7rYdSLop5N+F8fn9uUc0u+WTIm06xAJ31v1Yh1fIZFC2Nl/aIUHJTTuDwsiTTZt
         1zcS5606EZQQXJVOv8tL74X/0SC1FInd/GzOonoEcoRaeSXFpmluoBKfXXMHAda8Mjqs
         JBXLmBy1m8uqErVSxW2xRsjtuxgRthFSUemv9+6a4PUpt5Prv08+nT60h/9jDDiJMaJ4
         VCbG+4/9kaE8gvUpb6WYWeQcKf1Yk/eIH2UH5K8ps7huweCQgVT90Gof/wNPhTVdsJFj
         5rtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732394386; x=1732999186;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cCrnR4VGQ57WaL7V07L4ROk6AndKfrysvpmtzG6ZaV4=;
        b=cxiQTk14LL1oO6f35RFXR5c2WWOe4VpJkE70ClHZ0KTG2+uAf0HgrYLHHRDYhILdtq
         Cm8p+pNH29R78yGJ0+nEAFEnGLX8HLu6OTJWWUiu81LH5IJH80nEbkHIyhqx58UlmQM7
         TK2g9BzjAcRH6vBoVJ0JRaqQBxiA9HYBf+BtDwAva5fRVIXogwrrfZ9siwvV7Otoi674
         6gupm9efqmUakt6+OLBLKbKhmLnyRizc9D8aL1QpCeke+hgXV5etrqsFznUnfHu2fCK6
         VZOJ3+08+FzZ1rQIOt2ZbPW2l56JloxoRqO0wU7his4wVlDRqNb96xc1XafSV/eLDpn8
         PYAA==
X-Forwarded-Encrypted: i=2; AJvYcCXryhBGe6UO3aThWECZWIeTQNVNcZg5A0y7liZuG/FF0KpoNrQWZFH8JVOYiGm5lTis3CGVuQ==@lfdr.de
X-Gm-Message-State: AOJu0YwbMbLFrb521JRD4NvY+mOir73L4300F/Eyo2QD6fG1TWnEXa7D
	HZ3svNBEwedpnaNz2hagGsA+dpuLdWRepty1o/gwQrrvhFPngsz8
X-Google-Smtp-Source: AGHT+IFxHjv3N2nJ/+fcmJpSqUkgLqsVBqYaSJ3OoLALNeh724gEwqCPi8vH0v1Gdm0GQuj98zDA6w==
X-Received: by 2002:ac8:7f0f:0:b0:460:9d81:4bc8 with SMTP id d75a77b69052e-4653d616b17mr118273701cf.42.1732394386064;
        Sat, 23 Nov 2024 12:39:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7d45:0:b0:458:2e21:e400 with SMTP id d75a77b69052e-4652f48390fls42612851cf.0.-pod-prod-04-us;
 Sat, 23 Nov 2024 12:39:45 -0800 (PST)
X-Received: by 2002:a05:620a:4727:b0:7b1:45ac:86be with SMTP id af79cd13be357-7b5144d1966mr945329985a.23.1732394385532;
        Sat, 23 Nov 2024 12:39:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732394385; cv=none;
        d=google.com; s=arc-20240605;
        b=QeAbYxhCigxBiuxA9jLKrLbbX2eLbwsHsMuvhdDF/E3zWUNF1zGjgo98Pfef66FIXS
         JV078KODmUCuwJKx/bFbXmR6NyGbsIBT6dGJ0SUnb45ZFiAyvUSK1xeFIflkveOnR3AM
         HQIijSU8b+txRhU/7Aanll1UZ0ogOL5t8k9k2Vn+5IpF+FffhvxZv8yySgdVXRUS6c+n
         ByG95dxoijlhlPjdRzx4BZKQXUJKVhkHQk4UDEhRF1QyEoRrRGfKSkV3cmqmfdYovpm9
         4JyzFPahCONZpcMUVsbxdKk4raGMnKxq8yYcB3n72OhySJtdUiDXYYRWG8ZnRTciAqyT
         pA0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=3QBQKxymKBwxg2iSOHFxXoV+IjUCG6qajKbeD61qvho=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Zva0NV91gWPH8J3QaNVc/lR96i0Au9Rba8rKu45WlkNqMw2W3NRjk+hlcv7orKsbsH
         3HYj3zQXxpJvi/xrXHRRnlypFhFe8TAC2Bqow0HeGrdFsusip5C5Wm1fChZ11GbwscT5
         wcy5W4HmVL5D4gSLiyu4Ov0C95QAMzWB9C6kqQZw64Uug+N4bJyMKPrv2nWCjxzsIzTP
         mWfKya+8Iqc0RdJna8CrBhfa8JOUp1jGpcV8qyFLuPOCXd+BHGEZyIluI1brjAgPmSdC
         sSbYJWuocwuosU7njf0x9ohhYl2HYxcN4aE5gLQ0UIDvN7kSPrHL96LdN07p7mcbZm+W
         haDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=k7CxdwWN;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4653c3d7971si2401011cf.1.2024.11.23.12.39.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 23 Nov 2024 12:39:45 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 697805C48C3
	for <kasan-dev@googlegroups.com>; Sat, 23 Nov 2024 20:39:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id BB954C4CECF
	for <kasan-dev@googlegroups.com>; Sat, 23 Nov 2024 20:39:44 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id B0168CAB783; Sat, 23 Nov 2024 20:39:44 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 212205] KASAN: port all tests to KUnit
Date: Sat, 23 Nov 2024 20:39:44 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-212205-199747-rsAmDPbhDR@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212205-199747@https.bugzilla.kernel.org/>
References: <bug-212205-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=k7CxdwWN;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=212205

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #7 from Andrey Konovalov (andreyknvl@gmail.com) ---
Resolved by Sabyrzhan in [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ca79a00bb9a899674a63018c6cd155a3730c3509

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-212205-199747-rsAmDPbhDR%40https.bugzilla.kernel.org/.
