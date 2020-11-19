Return-Path: <kasan-dev+bncBC24VNFHTMIBB37R3L6QKGQE7QZYJLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id A43262B9A8F
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 19:26:56 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id n21sf4629549pfu.9
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 10:26:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605810415; cv=pass;
        d=google.com; s=arc-20160816;
        b=o5DlufiWG/7nJGl5QwCyzrmGmhf4D9Kd45rBCWIKL6UlYDETgGUU5I2CimNCDI/5ju
         VYGnWDNz66p/kqo5Ch6DJSMJYCBV5C4UrCpXbXpI8sncszRudH87Jrjn7ACHlW7dIx1d
         dptX8VxKtX1L8OX++GIngL2jEVJdCsmiYyCmrkhnt1FqbNYdiVua+0hkLj7lQ9qbNLlb
         Xg4NtIt2pnYSr6uW5hxMIFHhd14RPo1fb3IId4zQJoEPgmBICeYYuaa8GTFDTrymoeve
         WLmRKPdGx0dhMCO/rZGaaa7pMREmBz+cAAfnsthexrjls2Qi4MgH+wwsDSlT5xTE3uHP
         Ku0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=vnE6O1YtyRcKHfU++w0kGqd67yI6Ici65R8Sc0Ihpd0=;
        b=vNp+dFE9MQiKuA7wzBejqUOl3238VT9i0hCnx04ArAXedLqdja8ZcBBirypFK216R2
         op+rZt+FZzb4lgaQqrCsr3rAtJo3tye0dt3Sk1tjDWKwMtmBaX4dccbt5ZHRN3RdeMMH
         9cukkuedktyzOLpncuLgLcnhGNY8FKtrRJ0C1SfJm4PQSjB3NpGd1OyGlh+rIgNjtX3w
         QQRTjquoy1NNDTmj3CC0EKc8Ebc9mkM5v5f0BeZDw8fBLqyKUWHITydViT3vVK78wqwX
         LRaAl1akYfUpsjOES0D2KgWXbqHI0UWLgeK/NUOORIr1fL5g76mqUk9wlQuqObnBbBtZ
         j8DQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vnE6O1YtyRcKHfU++w0kGqd67yI6Ici65R8Sc0Ihpd0=;
        b=ZRXvnkpofkWFkpkJmUU/szZFiYHlnBwUTV+LphR/e01QETpk86P7iTAXi2wbdLtP+z
         Wb5exMxbRd1DWa6ziT696QRAn+8EQKOwNNydsSHybToII7I+HR3njcH75dsubKkAciRc
         yimRQAIyQOMkRv+nTYY7rjaAK3T/4GCCpxh+hpzJz8Av/3rZ0pvbeokGKGvjdVJOB1+6
         HAoLh2C0eqYJho3T3BxzplGDXP2JnfexTbVFKg15nq/xZ2bRIkgjYQjUTZpeQ1JBH1ni
         YDfTxjcnE7fLgiQJoQ0lwF3RbCQkJFQ+MOERF/1u655MD6pO89aIiEvQOku/8M4Qr72f
         Mplg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vnE6O1YtyRcKHfU++w0kGqd67yI6Ici65R8Sc0Ihpd0=;
        b=KD6N/2JIZJRB280scn+cuJhz7J11SLueC+TVKsnBVfiF6uMXIegl9y+0IkHtSvkkbi
         lZv+i6zrEJqvrAHo3NeGpA8GRwKA0Szlc6hlklVm8E8V0dVltA/7mMTZll4hoCrbRcAB
         S0aVv1HLdN1IX8p9xx0JoceH6v2+AaK/bHNGAgWweWaaGQkMN1qP8Rr7HnXuFpXdz6pt
         cHk4McrcQmiXLugzr467VtaG8YGEDYncO5GhkpKhUaET+/e9ounNwp1i99L+fZtGQA1W
         pkQfNCm4eY4ZXWd4Xe3PR4KuegqaVTRnR2rugoCMBqQd3Q5xlZMSVpmc4lBIXp7bJSN7
         wHCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/S3qeGcexJAni17Tavi02TXs33dPmE2AeBmQ3hGGzfokpMvTV
	GhhHM2/QUMRsVQAly5q5zBM=
X-Google-Smtp-Source: ABdhPJziiGJ26zLzBNkpeaaZmadua1malAg1hvka6K/YetCLE3b2sVhPspbXyHsowRc5UFiayoBG0w==
X-Received: by 2002:a17:902:bf0c:b029:d8:86aa:eb4e with SMTP id bi12-20020a170902bf0cb02900d886aaeb4emr9807347plb.82.1605810415370;
        Thu, 19 Nov 2020 10:26:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5621:: with SMTP id k33ls1295349pgb.2.gmail; Thu, 19 Nov
 2020 10:26:54 -0800 (PST)
X-Received: by 2002:a62:8449:0:b029:18b:16d2:9ea0 with SMTP id k70-20020a6284490000b029018b16d29ea0mr10300617pfd.26.1605810414839;
        Thu, 19 Nov 2020 10:26:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605810414; cv=none;
        d=google.com; s=arc-20160816;
        b=ORMiPcRIuwl5ijVasrItFmS4k6SJdUKb8P6CHopAszYpJ5ZzWZ0CFb8mLMfb5Qn/EV
         llS5+VWg0zzpsk/jlOZKBa2FW9SH8DDTcbqMdezMkMH3Ps3REh6REjhYapahnSlrnnqo
         +YKKW0qnQgMZnIWQ1+doHUR6uWK0M6eJOt+rUbcxUI2cYQB54jT3NskE0zyrIMEkbJOp
         D+4QGd57Ex4udHl616tAVe/crvW++4qxsjEmFAHlHYLv8tDlL8JDPXy35oXySKJ3eKr6
         iPQmU6/zHtv+U5MncTVZPlYrFNhMxJbHNLQTct/lCr1dHz7PSCoHarkyZ3Rm3N6FLozF
         7WeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=TyrclcTQSaPICF6q2F/asG6r8BLEFYXSiG4KOTAwAZg=;
        b=QTuboMlSoBCeXprOdQcWAIn+ILpdsVrq7ucQWFkCjMZuCr7LeHF4/B3VyQ906OLhca
         tsZ1EiK72uPUA1PCL+HD08YsjOG+BDKEgLzIEif/oJgUcZ2TVgueLFevkSQV7sxGDwN1
         A5k59TIdZNMnhpnma5ExsZcTDScD1/LzIxBJUdT9aDBDvTPN+bxTSY0F6PZguPj1YoMN
         Jpfu6BtsYreLcesU/h76c0hc8Hb00XdXf7YWBxQrxFXnpW2gsVy+G3UF8rBiHfv3ZguA
         azR+/pTTiSbrNp22GRKK6C6GNepHmsTbBHONwxLEnFBokxA82HPCOr11pRCVQLma4o8m
         iIKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s9si76376pfm.1.2020.11.19.10.26.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Nov 2020 10:26:54 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208607] FAULT_INJECTION: fail LSM hooks
Date: Thu, 19 Nov 2020 18:26:54 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: a.nogikh@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-208607-199747-Vh8be7Nxep@https.bugzilla.kernel.org/>
In-Reply-To: <bug-208607-199747@https.bugzilla.kernel.org/>
References: <bug-208607-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=208607

Aleksandr Nogikh (a.nogikh@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |a.nogikh@gmail.com

--- Comment #1 from Aleksandr Nogikh (a.nogikh@gmail.com) ---
There's a patch series that implements this feature

https://lkml.kernel.org/r/20201111104409.1530957-1-a.nogikh@gmail.com

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208607-199747-Vh8be7Nxep%40https.bugzilla.kernel.org/.
