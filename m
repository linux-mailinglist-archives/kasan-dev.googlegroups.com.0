Return-Path: <kasan-dev+bncBC24VNFHTMIBBXVLT7VAKGQENB4HEVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A237812BE
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Aug 2019 09:08:15 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id m25sf74721289qtn.18
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Aug 2019 00:08:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564988894; cv=pass;
        d=google.com; s=arc-20160816;
        b=xQsbdjI1K/1JZqkoDPPCqAu0JCTwWKoFG0eRCOJDpU27r9wxXCsYddVcfbqtScGT8g
         W1hQdgZofyZ2gaYespMSfXDkzE6v6GzOZ19vW/Z8G14dQapBE3a+H8soPnD2Ws+FSpQB
         HxIi7aLPWXl5uruMt8veYX0LukqlQZFR2oAhXYFQ6nCauez/FbTaKzSa/wGoz+rdACmU
         9U6VOpVnDuOZPVZDXvOvXYhVvnAzoxiOBllgU5G49oya0H9GJhAxh4JaLV0wIYkB3wn2
         BI5BD1J0DuAAuiEMybOFqz3krA2nisH44bUuJ1UM5ekVK556RJqk3BsPr4tLG5X9hk9b
         5NXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=YwgWvIH9SmTLgpO8c93078hvXuYAHmKdk9ZUcKYqFPc=;
        b=VIuzyVQGqnzQynTinNuj7aQQ5slvSFUkbSaPR1e9IL4r6SS8BpvIiMX9EhKFOZ/Hf4
         DoY9BSxZypCRgAd+Y8N4nRmwE1PvSKBaK2bcgj+8d+Jo3k5tu36DHd+Z/p5hsrOojCZn
         Xd+uq8DaNvONx2AveoG6T+piiyHUMKsmiO2Uq5HTE98eYyJB/kGHiLMjEXyNIqz9rY6p
         r5uP2pPMKr9hbw0L55oXuQRwgm1OnLwKYe9pRThlwFLjuZ1g0yIf/QxUGpRdX8cSHEFi
         8FXy62sEvpB2sDETabXEjKQLRHQt6n/HK+Q8eRSsaNFLHfMqebXc4aIv/vJerOl/bMi/
         bVWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YwgWvIH9SmTLgpO8c93078hvXuYAHmKdk9ZUcKYqFPc=;
        b=FmqN+M1dt5xIT10WPLjiItNkPNPJgHD4DreRMOxytKsFs+lrXxTOJ148MOElOEZ6Xm
         Mz/8KiQy3M0u9XUDKswHU9343o2XNNoded+uycR4m82/0gHjz7qOWZD05V31D2jmNRU8
         zgy28Ioo869zrE6Ds/5oM+RrshrJtZ/FiY6jhbP3dW51l+A1Sna3XLF+M5TX54PEcnnY
         K9xEaiN11hk9Nl7jJWeOKqBE4t51JRzI5ZAfsyvwBCHaODEkO9uJ//Y+yJoFuMNyyzue
         s1labHiviCO9cuL7SC4uMMzcnwny6eehauWJbFHi2mMOZGVppNeFPMldrt6GVp7xuqdF
         +MqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YwgWvIH9SmTLgpO8c93078hvXuYAHmKdk9ZUcKYqFPc=;
        b=F7PoBd7b4iZQuN+W2mbG8nN5guH+F/UzkXVEiz1FzN5pUj2RXPrXAp6yV7NsTfKfyd
         urbSvpf7A8GLIjmta9k7nat80Gd6O593BHFXn8SDPQVRIv7f0z2bVcXf+8t1rEZxkszd
         SizhEAxfOcir3srP31DJpjWaCbnJPM3iD8IZkVqd3fbtY79YpCQM/WCpqg0e+/CFoOh7
         WCLWDA+aVocMdcY3FgRjW3k+s1mi+AAt6uJJkiJ6yDZwE8QjDkGTUNGGDeN+K2E+Rfvk
         IvASKpUAK8R4WWOU2/M0tuL9wntkXyD639oKugpDt1EsoUuQr22/jn0BmUrRqlUl4T4H
         NpOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVt1m87LtExlqzEEEjCroMlxB12eeJlrixcoZc3oyfVAucYIBsz
	S/JwRM03pEVfbEo+3BZwDv8=
X-Google-Smtp-Source: APXvYqzC4CKLNiJxlgNdJrMSsD/I55Mx4xsnNF/MApPKKKzFEr9elbh3xUuZP9LIYyTzXhMD+mpgnw==
X-Received: by 2002:a05:620a:16da:: with SMTP id a26mr21692162qkn.376.1564988894766;
        Mon, 05 Aug 2019 00:08:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:10b:: with SMTP id e11ls1620502qtg.2.gmail; Mon, 05 Aug
 2019 00:08:14 -0700 (PDT)
X-Received: by 2002:ac8:41d1:: with SMTP id o17mr78489460qtm.17.1564988894584;
        Mon, 05 Aug 2019 00:08:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564988894; cv=none;
        d=google.com; s=arc-20160816;
        b=e5CURCvz8PlhU8rlLSrFp0aHKiT71Gehb8d0MjN1EPuFEzUEN4vh3DX7p5PciSsaJ6
         exyTs/7aULyw9017FPvWp2LbJ3BMB+McN3dTosMTyYBkjAlEviFVPl7Ta6EaWiL5k3JN
         tQZQG1gGzRs1PQdu3G/98it/lB61uRuD3t/7eM6OKRylpXvM3kdabiYhqj9bzl7Dcluz
         sT6ZxsnR7qoRaEuniFGHo2YF1M7W5N2Vjaxya4F2EuqwQVlT1P1sgdIwSFR4r8mkyra6
         KG7wluynaE53v5VbBXe4pRaxZfeD9QQVtWXZiGhJ/EdXB7+7l/8wbX1O60d0J675pBob
         zwXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=p2IwWTDIOhcn78kaK1YMqi/v2exfcL/46fqgCwtZcps=;
        b=yE3iv83MH/5sZqorl9mPxP7/EShFsN70isPqyVm3tDCXKJacNSTX8IaouxVpsLdBGt
         6nxMT0fAjbinV31JnJnPJF6lZqcAmFwssRe1xXxuzL0mYU0WYaFMX2NwKITDKlDp3jhN
         WeIrZqbaTtIKt14jH90h98EAJazL9o/M1r0GKsMVHOWu1Tkhy5V6XrUeU5gxrwAPy08C
         kE98ED9b4CW8K8Cl/UZs+p2vvGN/TUbe1cP8MsQVAeZXEcQkx1bKJoJ0g3xzTm+jppBx
         WEXqSIdpTnW6ggyF5DCT4zqSVsn2cD5E2EM/47AEieDxLAyusDo6e7RzFTVMF4uqQvu0
         i4MA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id c23si2886750qkl.5.2019.08.05.00.08.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Aug 2019 00:08:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 6FB842879C
	for <kasan-dev@googlegroups.com>; Mon,  5 Aug 2019 07:08:13 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 6364628877; Mon,  5 Aug 2019 07:08:13 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Mon, 05 Aug 2019 07:08:12 +0000
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
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-204479-199747-fF9dBJnaIF@https.bugzilla.kernel.org/>
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

Christophe Leroy (christophe.leroy@c-s.fr) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |kasan-dev@googlegroups.com

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-fF9dBJnaIF%40https.bugzilla.kernel.org/.
