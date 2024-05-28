Return-Path: <kasan-dev+bncBAABBXVY3CZAMGQECQQLNBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 88A6A8D22EC
	for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 20:03:13 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-43fcc9b4a5csf13308411cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 11:03:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716919392; cv=pass;
        d=google.com; s=arc-20160816;
        b=rQ45ukNLTy3icRfTkwJxUTkDRmjqOKzQQM8gkuLFcTlrj8IeFI4W/esQDSMirgfRxk
         IRZg+M31MD1NbjsutIRx3W6UHQhpXQVBVZsHa8IurOKglhCompBTVBnVwJgrketL19s7
         li8b0rAn6uzVgxlxrMDZf9WWqwYS2Bgshz8QNj16t9DC881tAhUrK6ZYieDOIsImT7Lc
         HsgBlTER5EnPH0jsnh0G7HUjDT82wBGxv6IfFJGRFEpt79pmlaP2mShav3CNzA6RnR1o
         iM2RZEpDh0aEm85YpKKMGEQTIv1KZ9vHddHuWuPZ54HIXYYELmnYQVB39Y60avEKcb8i
         4kpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=+JzZWszwPrQaeKIyot3q+dxrJhjOrJ+WQJ3gn78kSJE=;
        fh=TPNVyfHULCVeovJCReNNS59FzlU58A1V/bVP8yTRpkU=;
        b=nq57Nmkm43w2i21U0Rt3NSz/1YQvnXCKDQEIoiLDnaWAeVEUggXYI4Osc+GDZ7IPtM
         yB8vh6J44wopKjCIwCLR+4704RJ7CydOszB7pDXo46ZJhN2WeoF4dVBFD7C5NBRNzt8n
         D7zEI0QNEJ6yV8cqNOPpgbgt8yfmELGg0KVT3iDI1Rxs6JPAzCu8wVND1zWKVpEgGVWi
         RE3A5ZKxmePtPvwx707g5MopZ5gZQSwzvlkQZeEj6reGMufQWoY1EZk0qCBRNoeSciHJ
         z5fk/WTflsvgvfygJEpwvXRWbDaxJ2WzUd39ryoY8nj1hQGn775q/G3zipix3pA9v5qW
         Hsfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fMfaTLpd;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716919392; x=1717524192; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+JzZWszwPrQaeKIyot3q+dxrJhjOrJ+WQJ3gn78kSJE=;
        b=bS9qgazT09R0o+zpl35Uuf1u90QzAmDYmFuoQ93XpCijNmrIa3Q2cyZ212p3BXUe6V
         grfYbz+vKaew4nG/A7PfEEutZxwzzbhE4fAtsfGIa53gV2bH+N9t3FAwJb+SS/TtTkNI
         grdilOPlNRtr2cLet2lwx6IeRpgB2CNNYLdqApooRHrzU2MbNQe32obDSEOA4dcHX7E2
         IRthFUsbYlgQZjNUhrMI4dTTdtiPpZS/f4NXUdRhkyF68vbjrsA+kq8PY4opU9YJasRk
         /d28EqDyG+hjWidYvklLSnTdCa9TVGjmUIfTByQmXR1vlI7Gq5rBMrbTXHGZWzAb7OcR
         fvXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716919392; x=1717524192;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+JzZWszwPrQaeKIyot3q+dxrJhjOrJ+WQJ3gn78kSJE=;
        b=fNmnbFHquoI50xZx5tMxRjNWF5AVubv9kwbayKL9Mg0KFuOC0oCTx83U4wnWcxJNIM
         0As3Z28OeqH8WvZFrQ+1SOXNqKyIzM6MzHRuxAFf+kaqGnliWgLre5kedb77Jo1WRWqj
         p8ZADDPAaO4pP8YHQ36SymFF5N0naDs7aHsE/55Qg51OEuksn/OSRq8inJZUB4omhg6x
         8TUe6JtR8wY6JQRwDhTsIYgs5MzX0SJwxxrqOEEaKzCpBfw6qq0bUBGygO9ag7iuaPwS
         gv+g8T1QxIyf6jaiKzSTVXClt3JqEmRTrlRb73HEuICu71MqHZox1lYODUR34qaQnm2P
         04JQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVaJ1ng7yT6l8BKQbMMb89fDCPjqG4oghIpTxOR+U0FhTtNfGbmdU8iM6p7LQN3snql0PYqQ9psBCO2eaqINDn6Zs2nXelwtg==
X-Gm-Message-State: AOJu0YxU2YH5C0IpKTCrQ27Zq5qAldDkHobPb2AXJc7QImvg2GChoyxR
	pcVvR1dFDZ1Xw1WfUTJZ8PKJtvpLzj6Lus2BBUK4iiqu5PoxxJu2
X-Google-Smtp-Source: AGHT+IFlGfLZ+rFZyrjRmQ15jnAdNgNy2WBxtKwtd/mNVqW/j7qrNTbnr3eECbweS6jJnPWDP8HeGQ==
X-Received: by 2002:a05:622a:5c7:b0:43b:4bc:6606 with SMTP id d75a77b69052e-43fb0e88b2emr124172531cf.24.1716919390783;
        Tue, 28 May 2024 11:03:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:188e:b0:437:bede:6e20 with SMTP id
 d75a77b69052e-43faf01fee1ls61082761cf.2.-pod-prod-09-us; Tue, 28 May 2024
 11:03:10 -0700 (PDT)
X-Received: by 2002:a05:622a:1882:b0:43d:f4d0:1c2a with SMTP id d75a77b69052e-43fb0f24ecbmr159433051cf.55.1716919390064;
        Tue, 28 May 2024 11:03:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716919390; cv=none;
        d=google.com; s=arc-20160816;
        b=pm2i+/ymoU8CRqRsuIeCwUGwFNHGrq7by4eHabcjD4AqBuMUkHGj0M13C33eYykZza
         1gsQ8HS8GFqRUutnF8WQpJ1a1HLY6fBhyYT1CqgyFx6ehCV7yx0ZVi5r7pdK8UO87AAN
         VXOh4Np7Md95bHKx0dQ4YKuvBfCtnLsVX4C4mKELmqT+IwZOuGhwrPZTSlKpFdOiCXjS
         Cbvchzi6n0jV+Divq5/RHP+KTbq588ukJvUmttCCqO8KOtt6ORWiE8g/1w7PGBf9bNxf
         hx1RPWMhD3SKZeCSOuBpdM4ZG5Po0/P+pdZDxwms8n5sPNMtRqCM6UDJOiKABcpeojwR
         g9dQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=FJC6ZcfWFNFAxsT5SxbROpFUBfnaP7v3FqJv5cqaHjw=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=vDHkSd7s8wsrgKcTUGTCp2bO4u+bihs2Monp0Z111E0WOiv6jtOmtW+MhiEAd8+5GO
         94sr5ZXQoOnQ+BQVMXJnjFbYPp41+NlCWlBRBdV0BkqzbQZ3hF0+gIkggxMpQIuP/Jhg
         81w45EXcWuJArhZNBLXAn1g2BfOX3eCTvJNcWBpZWVWoVljDTRGoUACDhRbhVlUFMpxD
         KeODgXYEV59sAm7vYKwhbAlBuHoqSIHjQjJmz8K4010RnjAeJKkb+oxtescgoR8k9ZKo
         Ynr8OWAWbH2of/gc6IMLwkahW7eXWp3JX4mwhOtfpGQY6xWMWwaLtaiz7O3FEEwPCreg
         DU4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fMfaTLpd;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-43fb16aa38fsi6817101cf.1.2024.05.28.11.03.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 May 2024 11:03:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 96F35622EF
	for <kasan-dev@googlegroups.com>; Tue, 28 May 2024 18:03:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 4CD5FC32782
	for <kasan-dev@googlegroups.com>; Tue, 28 May 2024 18:03:09 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 44014C53B7F; Tue, 28 May 2024 18:03:09 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218887] RISCV kernel build fails with CONFIG_KASAN_INLINE=y
Date: Tue, 28 May 2024 18:03:09 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: jason@montleon.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-218887-199747-H93Xp4n5Xk@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218887-199747@https.bugzilla.kernel.org/>
References: <bug-218887-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fMfaTLpd;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=218887

--- Comment #1 from Jason M. (jason@montleon.com) ---
This is due to the issue described here:
https://lore.kernel.org/all/20240527153137.271933-1-alexghiti@rivosinc.com/T/#t

The vmlinux file was over 2GB with CONFIG_KASAN_INLINE=y
$ ls -l vmlinux && ls -lh vmlinux
-rwxr-xr-x. 1 jason jason 2455700072 May 27 18:17 vmlinux
-rwxr-xr-x. 1 jason jason 2.3G May 27 18:17 vmlinux

With the patch for resolve_btfids applied I was able to build and boot
successfully.

$ uname -r && grep CONFIG_KASAN_INLINE
/boot/config-6.8.11-300.1.riscv64.fc40.riscv64+debug 
6.8.11-300.1.riscv64.fc40.riscv64+debug
CONFIG_KASAN_INLINE=y

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218887-199747-H93Xp4n5Xk%40https.bugzilla.kernel.org/.
