Return-Path: <kasan-dev+bncBC24VNFHTMIBBS4NZP6QKGQEF4SXPGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6235F2B4FE0
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 19:37:00 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id g9sf7077404ooq.17
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 10:37:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605551819; cv=pass;
        d=google.com; s=arc-20160816;
        b=qju2w5IA5yAgSPHi++wIgd99O+yDjh8NrUytFlK8sOnBjvJENO6vyyWcLFZHk2Pl2F
         4UZZ0qdc00RUGN43KijcttyCKroazuuaibrp1bx/t9z+p2KQ5/h2RXVuEbKU5ITi8aNs
         q2YX2mANZcsdFuMF3NNq9ZkC8vQifgTCPj2Q3HzYkZm7rptcoiQTBfeT5z1UBQBvHkTz
         raR+fO7ahkmaEes0uT1QgHXjFBpvh3knoroTVwiREHciFD5/ZXbXlUb5U0W7sfmI6yVV
         GQtFvmi7XMVVfukPd8yJ24tHGDtM4EbPLLW2oUYqVhgmUOfkvESxY1r1jq0dzCPErtrV
         m+hQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=MC7asO/mOrnqxrYedVuquoNntZEgNdL2UFX2c2x+qBw=;
        b=DEUq20Av8r8BpDfsmmvKeY5SIhIEWgj9eDqgAdWr20kR/9olTytTLpYw5BLKNHG1TV
         UbS0itPNsJsvRhI38qnr8++ltQrpn2PMkUQzSftlMH7RTF19mPJSrH5txoNdFzLagkUI
         sGmdaFca+qX7Mnpns5VfOB1xhQ36mm7J1W0ceo3T3qaToxNyRn3YnLk4Brlmhr3rPEVw
         rkw/n9Fv3+DsooY1l5n+PNSr7DgJAmLuMRVs6wCgqGvdRKcdVijRGcpJtW7k2dc21q4q
         +3gSqlElfu1KkNk5I6tCxIB+INLavLfLuBmo57HT87oTDOSv36Ypo93WfBZOt6bASlLN
         /FeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MC7asO/mOrnqxrYedVuquoNntZEgNdL2UFX2c2x+qBw=;
        b=rbehKA55HJJOzTRmvTQ8MGNcKGnBL9kvjo6544m4kMigEN5VbtY0HPZEGqdVl3fD/I
         XMj1wcKzj1gaXDYEvYlBT5DTMt4ZlY0dPuRjXw33EGPgdFjff7x7NeLwlfpiWTZV6XPT
         RXAkENnefQtFwZp/9T6TNiTR8NyRp2VMVFDcMAhS2MvtFVnYg0PKr1bHzi3GjSOIHWr0
         TjZb9btPQZgs/i6+Y32BTeSTRi7Ud2n29Tk3Y2ypen1e0J1EDCFlZb6lMO2jIwsbZ/Wr
         sgfQTAQlIyJYiwPiPjAIP0HNnB1fGamaPzsJGanFp3qjMmeDIIUOHg9orryGcF3JrQyO
         G3ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MC7asO/mOrnqxrYedVuquoNntZEgNdL2UFX2c2x+qBw=;
        b=R1Sm1ng53vTT0ocRILXRyZYsJNSWvz9EIwDwriC5/IOJZsFPzyKX7a2Ak9xaShEOGT
         i42Bv5BNApWifIfIKGrmw84nEAN1riCjRp+yLmJE4bEelZCQv/pHGx1XF0UsZP0CKdUI
         5AO6dUv9GBIurW1Nwf3UKH617YP2Ag29IuL3hJ5dNuSoxP8Z5X7Kjfa05Oo6bal7378M
         hulK/Iac4+qzwCP6vxJ4ESSbygmWi2TkDtZtHIc2sAG+QqEm0zIC0GRKCOBCzKGCU0KP
         trZWtGoSKePVwuHzh0HXCArPuF67fiptvxxmdv7b+9vf5u0MWVih95vXwgRjlw4lzjVZ
         s40Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qBqzgHinsM2N1bMyYIRe+AsaUvWpIp2iWryo5AGuoQIw5ZvGo
	dRXiFuWu/GrnmAAKUXJgem0=
X-Google-Smtp-Source: ABdhPJyOeHj8Vcas//mxPQbC//GkIZoZkTT9jQzJNzOZT2krCpmdxBSFFkpe4F0s5pnArflT/lgurA==
X-Received: by 2002:a4a:e1c6:: with SMTP id n6mr510731oot.68.1605551819367;
        Mon, 16 Nov 2020 10:36:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:e102:: with SMTP id y2ls3400342oig.4.gmail; Mon, 16 Nov
 2020 10:36:59 -0800 (PST)
X-Received: by 2002:aca:1e03:: with SMTP id m3mr2919oic.107.1605551818955;
        Mon, 16 Nov 2020 10:36:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605551818; cv=none;
        d=google.com; s=arc-20160816;
        b=mc9T0VBIG2woVO4p+qGoAO9TIMlXj1pMBV3MQscJ4BjRaXyXWzPalDKnO32ACRySnt
         CEGChwc71LFnw+nh1EaR3nGIT+ccnbEKhay9v9uog6jFK4i/wOAKA+7poBQ8W6Vf/M5z
         hkh4VWjDJDOw+FKpBQWziLu7ntOoezGU+KUmGqFAunmjH/wW03N8SA0x96L9is1Td0BL
         C/Ls/M9YIFqTDJa3n9MA8IYl9AM9gwE0NuCJQM5PTq27qcVjAABGfiCnBWXciCiZl8mz
         R5iBHkFgFx8cU6caxCwCQK+SaraObqrx4vWeQQNCRlczW1DLc4PHasFGnGZvb6e9cQIT
         tMZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=td/0Z9mvD6ZsTdSUlIRgAQ9aiB603TStIhzUzx11Ibc=;
        b=Znippxp77Yt9iTLLVa8YcmwhAjibJTaHemk0kRGXAOY6CMtYEHuzz/4dmBVDr4pNmw
         YD1rFiaUKNQoAzBGgHfgxP5+jYfbWBkIuLnII0yh64qh1RJQ5okjZxeF+AQWoEWrxmz4
         ItXFbrJ9/162Y7b309KYU8GYi936XoJUwAQRRuVo/YAxQ9azWUDqd4WKKYxa5sAl4WY0
         26zI75xT/yCnbu+zk6QI2K7KZRogeI23L18tME7pwPPtddmpt/rikpON6OBfetdg6dZM
         M+VFoYNeUatLnLJEevhgf5RtLnUlzdld7BD4PvEhPiTzhecDrX8UBeGJr9E5PDGDve1/
         66lA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d20si1797624oti.1.2020.11.16.10.36.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Nov 2020 10:36:58 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203491] KASAN: double unpoisoning in kmalloc()
Date: Mon, 16 Nov 2020 18:36:57 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: a.nogikh@gmail.com
X-Bugzilla-Status: REOPENED
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-203491-199747-jcs6LJfsOA@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203491-199747@https.bugzilla.kernel.org/>
References: <bug-203491-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=203491

Aleksandr Nogikh (a.nogikh@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |a.nogikh@gmail.com

--- Comment #4 from Aleksandr Nogikh (a.nogikh@gmail.com) ---
It also seems to cause stackdepot to save two copies of the allocation stack -
as both copies will sligtly differ in one of their last elements.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203491-199747-jcs6LJfsOA%40https.bugzilla.kernel.org/.
