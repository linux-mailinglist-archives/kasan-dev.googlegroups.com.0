Return-Path: <kasan-dev+bncBAABBTPY5G3QMGQE2FKHEYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EFE2989F4E
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2024 12:24:15 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-e25ccea54e0sf6249445276.3
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2024 03:24:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727691854; cv=pass;
        d=google.com; s=arc-20240605;
        b=NnpTaJWupsT/jozNxJEfbduMFQSjlU5EswgtvIY4j7gPs6XGXH2Bw5anEBYAT8xDO3
         FK7eNBQUTYxpFYNaDW5Mm/UqJlAKYGHiT6KhOLGgKodVemt68d6qT7UEXeM2g8keE85K
         T78hK7Hc8JX9Xnp3QiCfYawBSyZ9vCNG7NPCkkHwnahRf+88NzuERyxqvF+YQjxMKl7E
         2SUqfhslTwU4BDwPjxQi2jzFvb4V4Ht2ahrHFerdLRtsFJLWNlgzW3iUC5kXnDHu13vZ
         skuZ9hOIl9Ue264kE3acQxmu4uvmezHrW0UKfXy+rKRLEgLCCvpvzd2YA5xiXd5GAG1G
         UNvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=SjWKqFty4pGHi64t04E4OZKruusrjFoeMD3gJyerJ90=;
        fh=jMyRKfxchB37UpYDhXVIQGL9hlvt2VLGfnDR0J5oKNY=;
        b=J/MWgIjUCdVM/FtjkZH27vzXqrmfvgjd2EExo2AnEt5zpcjqoNFSca5aMPpgKbYCk7
         o9EKwvjPYucothNUN9OIGc0CQB4SlW1VRzg+gQomZ5ZsEw3AWql9XUoVnd9LC7txImgu
         noiCElwdZ+N82xNrEYUarHL82vuQ+Ux1Ap7hkaQxhfOPeCcKbGGXBtLqG6149XBxSP1Q
         9W7Y/fygpcgbKzFoyH0Zi4+oT2daPgkTzhcgBYU3NNNjExnUPnye4pm9bJo6INWAnzaD
         MOaaV3dmw3ky3Kn+mp89bP8tRUy+eYemA1QtXYQIKPVsXY4vjuzM6K9eOvaE9qc7rsmq
         L91w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OHFFsZe7;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727691854; x=1728296654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=SjWKqFty4pGHi64t04E4OZKruusrjFoeMD3gJyerJ90=;
        b=FM8g18Lpq8rXYIgK5vTMdXBM8iU8zL1E9wF0lZB21eQ4HH5qxtaY8DytY+tERjovi6
         cbuT9jx0ecEwvI86G5V890C00OjK08Sd4hZqyqtDSN1aVSjdh1ou9WL5ZBF2KYvkZ+jY
         gBuZWcFJug9WmBrJKGj2ko3S4L/33d9URdBBcAx/crsviFSIBz5H/lonCkHD//q2fD9f
         mTgDN6OFgKam+koHFWivjv1HoCUofjlZ00S4PHVEMlAri1qN0sr+YF/lWbLXEFyrL51V
         O5LYo+4+YHZxCq6XO/ufXDVDtd4Oem9PwgGyeHquDKV+KhkNxb/7b9WWUYUTGZ+I4iLX
         8oUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727691854; x=1728296654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SjWKqFty4pGHi64t04E4OZKruusrjFoeMD3gJyerJ90=;
        b=Na9kyoz+1acZcbAwkG9BaQeVFRGuFt832QgZ7jZJgYvoX2zFewzn0B8ddsK2Fo5mFF
         WktTEtzaIhmxPo0YVXU72xl2pMtsmwBUNi1Y1xeiXMuqP9FBrj5NUktjInbcQX2SLgLo
         Hb5kfmS102jfpHUl6+jjdP3JByRxySW0fqHpsD3P6loSJWVxw4RTcopN38tPWv2BdXou
         f2pVrGHQKFFpn1MU9EC1c4rUhWwECPgLua/1Ry/HEs+7qzMLBywDaJmBJMUM+UA21lh6
         SNYXGaVcN5gmEUVgC8skXxwLSaL887tKLq8WutqpxdRxIu0qCtPAfw4oE8sCv+kolST1
         99jw==
X-Forwarded-Encrypted: i=2; AJvYcCXTZgzJ0Hqh3LprX3qLMr7spN1rEa9S2FDiHYY0dCOQ/zdh54sZdRLmXJlED5VaB3HX7PqwKw==@lfdr.de
X-Gm-Message-State: AOJu0Yy/mnDD2yp8ZJpmE/WiQp0da2yOhvqbkbJbvwae19Zk2PLhIcVO
	jlyG7Z2B0f1Uwn7ZkUOXxJfcOH+4C/DXnZIYBcuOF5AQerC5ldSL
X-Google-Smtp-Source: AGHT+IFNPs+e87F5Zi45zGOmwHctnGFgJOYWBYU8kE8ssEg/N8dyyumgGywsK8Ci/0012HHSLdcb5g==
X-Received: by 2002:a05:6902:150d:b0:e25:cf54:65d5 with SMTP id 3f1490d57ef6-e2604b280d0mr9009050276.12.1727691853680;
        Mon, 30 Sep 2024 03:24:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1501:b0:e23:d08:82bb with SMTP id
 3f1490d57ef6-e25ca7d4eb7ls2600073276.2.-pod-prod-08-us; Mon, 30 Sep 2024
 03:24:13 -0700 (PDT)
X-Received: by 2002:a05:6902:2212:b0:e25:cac5:f466 with SMTP id 3f1490d57ef6-e2604b3e68emr8338379276.18.1727691853075;
        Mon, 30 Sep 2024 03:24:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727691853; cv=none;
        d=google.com; s=arc-20240605;
        b=buWE3e3zyuur0kxd0Kg/hgTcsu7c9Nlk7/tzxEYGQXtkeQhnHs4MeRjVVG0Ga0rrf9
         DFvOYI0GutpmJviVYnjxfw2Sh/qLNeW9z1iz0nIuMEn9dGtcnlRFZ+UfOpT2c79n948V
         gv3wmiemOQwjdyqGD7nINKY0WGVwbjIzvK1fTnffMJd86NPZn5Mo2AAJvSgmuiCgyi+9
         cuupFTH+AnQZ5rH6URCcQywMSWekK+mZxff9V32hgHaPnD+MjPuUROdkgXKiJtEXsPPf
         NDgWE/70pOiKdr10e6+ZkJloWQjfngvVvJnt2f1gd9+HR9A7eqkipQnbvO+sfD3dpV+O
         kTAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=x0eKdxCeS0iEQztdv/TitMPzOk+KEEx7bwUxr4Np2iE=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=JJCq+nQDpoTaMcIo3t/HYSV0g8rG3miuDQAEz745JYa95zeA7p4QmXiva5e7fbytlf
         u/yWclBt4iZSqEWb7n17QbJ81wO2v7F/7usFl+KJG7+azG2QBLKFpVZ1Ux0baATJovkC
         AIFk73FVFP2ZmB7/4sFnYZ2OoBJFVLbPhYptSc0XULdUlDK1FfXeyhoKu9CrJ199cRtO
         M9sbAmH0p4TkL+oLunIYvbCa90vlKnqHhD8StPZjgs2DzJwWHsR9DTrofSGvFhMUMaU/
         ZbUsC+iBfUyyXJluohK0LUFmBeYVvE/D38b/1vPo8YYrQyOHv/UqmLZEsBfQxUwaTGbC
         qk4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OHFFsZe7;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6e24548e6dasi2413047b3.3.2024.09.30.03.24.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Sep 2024 03:24:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A66585C0FF4
	for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2024 10:24:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 6F1C5C4CED1
	for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2024 10:24:11 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 629A4C53BC9; Mon, 30 Sep 2024 10:24:11 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 210505] KASAN: handle copy_from/to_kernel_nofault
Date: Mon, 30 Sep 2024 10:24:11 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: snovitoll@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-210505-199747-QmVSWeeO8F@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210505-199747@https.bugzilla.kernel.org/>
References: <bug-210505-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OHFFsZe7;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=210505

--- Comment #6 from Sabyrzhan Tasbolatov (snovitoll@gmail.com) ---
PATCH has been sent. Please review
https://lore.kernel.org/linux-mm/20240930102405.2227124-1-snovitoll@gmail.com/T/#u

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210505-199747-QmVSWeeO8F%40https.bugzilla.kernel.org/.
