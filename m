Return-Path: <kasan-dev+bncBAABB4OCZK5AMGQEDZ6BFBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id EA7DF9E678E
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Dec 2024 08:02:10 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4668d3833a4sf66171791cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2024 23:02:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733468529; cv=pass;
        d=google.com; s=arc-20240605;
        b=CHBQlsmbJ0y4idBeLYPmuz9zAp51YwZDjRK0jeWPEK02GazZRamH/viA1M0xy9cwyl
         K4z9u8FLNiogpLRGQP1jOULyA2CG/3AAZAXKisWTkqCqMa/5t9u7Mzp15IDClMBMFTFs
         DyTJF/5Oq5Kgb2Aj4T7PMdvEbBI7VKFOxtnTxk4ojEWFa5jbNyE+ezM6jmAJgDfveYbq
         3X7/nKf3062bz8FwHRSXXkQGpiMWkdacanL14u00XHlRWIhMMxd47e3lsZq5Q22AUKIC
         /eEp6QqvvGYujGbzJFND7qwSNb1EW6zj/5vgu+Vy2C6qzAg96FMQNJA1Mwd7bSz+XJCb
         pmLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=/+RDvZTABZJuc0ttfeRBH7NirL2sD9yibkgVHDzt7U0=;
        fh=xw/6ZJDrKCLAyAJhmjMh/jPPqY7bZ+BQcAGY9XqjD9A=;
        b=LhkeoSeMnYrFfx87cFhBKboZrhzGVHAetu7z6ksNT8ZcmXLEd38icy7mJ0aj49Bx/m
         CiwEqECuKJjREGxIG87C1ZcI1/zCFEKpjbgQObc350ce4fKVArP6zK8z5KnFkghBNevW
         dvyUrgSk2tRLVBMAWFp/hqDEZBQS+HVpOmXveRn3Mtu2gJ8KYTKeSpylyYn2WzODyWyJ
         BJ6eJo3qXF1b2EEipsCEI923FcUJw9BCCxbnWgga9AiEaNB7N3fg6CxwT/+Xw9eR+ZXa
         Xivwlx66AiL1dENI6n6sdzZW4uRWfKzcpKlJzE8nEsCZnbgWOsKGaivRGeurMunbu1wg
         dklQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rZfSMt8B;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733468529; x=1734073329; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=/+RDvZTABZJuc0ttfeRBH7NirL2sD9yibkgVHDzt7U0=;
        b=IE7qMmN7ic0on2rzrBUxj4PT+/56WXSG4KvtDY7vbAO0NyNgFueNs6QlNpwlTsFRTB
         1+7igXY1RX7oslt9SeUdBWqylXMoiPufbVCecCyuG7aZI8qYdITE2zd7VHwj0M3OBU6j
         SKDYPUZx1yLfIZsUxjELLfXQ1clnTXDoz+LJKJ7ypbtel1yhU2It191iCwLWrNY9pkIb
         v1t1fbYE5X86GpWgfkHn/3wxemKVVPj43aDX45d2PoBmB2SSDbPknv47eJaBsrN9QTKd
         uWtw7+x0DMUht9pitkhFBhqeBYY0x2bydqAx0PYjN7QqL7HVsWzMVjkQ3zr/c2VdQA0R
         ut+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733468529; x=1734073329;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/+RDvZTABZJuc0ttfeRBH7NirL2sD9yibkgVHDzt7U0=;
        b=eO3iknQsPb6DvdRmHiOkUo6GXxzccAF92X7mKwGZlmKMrxscG5mqf+ONLKldrBLwTR
         QHdP2H947mGEPJ/N9NP3mor/69l4sofUZoq260DKDvgaPVyntsjxn1JAMsMyTUIaZdGk
         6+xeG64jpsqFLINCvCAucwuOSuBdJ79YBLRVQJX5K7vmIOTxoRPA1bXqgaa6T0XQh4Dy
         V419Jt4H0j9eBazjQCpJhTW8gNVzajaYZDEV7pnwV3JnwXJm14yMj+tnkW7COXbW6l1U
         szfhI4WJeCTD83N8U8Ksjk3R4xdu62xyM75I+uKu1rhVeIr0sTcXp9TKd5a5j86L8tDT
         Vr+g==
X-Forwarded-Encrypted: i=2; AJvYcCU6ZnDVBZGFp0KiuUlNx+RrL+DeNakZgZGBw9c/vPX7d5nsv063ODN+v4bSWFaLOjzoPxnwTA==@lfdr.de
X-Gm-Message-State: AOJu0YydHObUtDLZasfmrGJtYhyiU/MBIN9HbOjRg+rWrVU9AZ8dfRXf
	jAqrHS3KRVSQHH+FiZCsxU4vBWDKTZPzDIExSF9Z2sBkH6Kx4bZH
X-Google-Smtp-Source: AGHT+IH8e201V/ms/4mPMD/0KNMPteocRzYWirctEy0PcrE+CWHK50IAexckHlFHO2rUzJNKcdclcQ==
X-Received: by 2002:ac8:584e:0:b0:466:9018:c91f with SMTP id d75a77b69052e-46734c9e97amr35506431cf.1.1733468529259;
        Thu, 05 Dec 2024 23:02:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:107:b0:466:b34c:8811 with SMTP id
 d75a77b69052e-46727afc9eals31132571cf.0.-pod-prod-04-us; Thu, 05 Dec 2024
 23:02:08 -0800 (PST)
X-Received: by 2002:a05:620a:2b85:b0:7b6:5d83:122c with SMTP id af79cd13be357-7b6bcad4abbmr330957785a.16.1733468528723;
        Thu, 05 Dec 2024 23:02:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733468528; cv=none;
        d=google.com; s=arc-20240605;
        b=PblT+QcEbUWJv9CJ4+Tj6iBsAGW/hivS5bPqNrKQR9xXrVWNDLj0QYMO7rkPKxzv8X
         376MfxM8qN1ywcL0Ew85kjq63FKpzFk/hvsv9G0DRPiC/3qeemqdhhumLuTcdMufnKoR
         +j3YT9KSSvZgNE4gSAfdUBrMg4CpKXeeHiroF842DCMB05PmocdjH5ap4p0LVVJQiLNF
         C+n5AeNPlzpvIsGbPmhwZUy3qF171/fuBATmtjAdNHu1bsyL+yztWspEy6JSlkPufbvq
         LBCyNochaQQKN1vxgdr22KareOTucgULLYBTyGGZdNpTNGrWHppBRi3oWeLQThVkinDd
         uu8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=LGHq6KzF2RQ9d3joMp6AWK8RNb3QtZX60y5nyRJS0vk=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=QOZRkXsal3wJdsfnknUuL3on00Mg5iut6eIIzitsRSOPdmGuU3d8MC4QCvffZUpFvS
         68HmsJRl8ncUAJuk4urEHN+MU6r2o+u2cYMFNQ5CE8jtOT69aVYfe+gsqYtoSdd9iuUg
         hlLdxXTS4nyz2qPKeuL6H3c1V88uRrkHCQNWPXJxm74nWopTGDNmCYeO9LrwIP1lJpKy
         FXuGVm/+n8uqDBsHba4nCNeXkD0c6wAiYXyIjzSIBbxXcSZoXLQVEanFOMczMxYw7Yli
         5ImALkxGJnMpaZKBJqdHDWe2bwazKDQNWBkVa0j1wL3y1jVM5/zPLvj8DoTJsFZF1Q1J
         cEOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rZfSMt8B;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6d8ee0ca03dsi184546d6.4.2024.12.05.23.02.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Dec 2024 23:02:08 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 60F97A44022
	for <kasan-dev@googlegroups.com>; Fri,  6 Dec 2024 07:00:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id CF377C4CEDF
	for <kasan-dev@googlegroups.com>; Fri,  6 Dec 2024 07:02:07 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id C0B0FC41614; Fri,  6 Dec 2024 07:02:07 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 198661] KASAN: add checks to DMA transfers
Date: Fri, 06 Dec 2024 07:02:07 +0000
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
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198661-199747-uNuRg9awK8@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198661-199747@https.bugzilla.kernel.org/>
References: <bug-198661-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rZfSMt8B;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=198661

--- Comment #6 from Dmitry Vyukov (dvyukov@google.com) ---
FTR implementation of this idea in barebox bootloader:
https://lore.kernel.org/all/72ad8ca7-5280-457e-9769-b8a645966105@pengutronix.de/

It also has some details of the DMA API.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-198661-199747-uNuRg9awK8%40https.bugzilla.kernel.org/.
