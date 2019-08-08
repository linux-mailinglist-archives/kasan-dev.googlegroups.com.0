Return-Path: <kasan-dev+bncBC24VNFHTMIBBZNVWLVAKGQEWFRSVLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 2889086CCD
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Aug 2019 23:57:59 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id q9sf453857vsj.0
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Aug 2019 14:57:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565301478; cv=pass;
        d=google.com; s=arc-20160816;
        b=YhNQRG4HvHmSZ/EUWId3dGUuM54QKPz618DdQn1+ZYBkN2OqZ2MYy1xrtNTpKrV91m
         CsmiOGJFTdBKq0Fn4FBdh+DQzBJzS8MThPLmElFtHUTeVRRFFYic5oen8hYmEYmjnc0F
         liVDZDbvzaUbWDsP6LUr0ewq0oFBPmxN4OsilL3gfx188BswIh4usFRlGftRVW9NyIzM
         KJ8wqb+vikRCp7KzvxGNn6ptXdBv9pl4mhm53G2zsWEw9ypruH+JidVZfvIUPTQFJtjp
         asAIj9HeChgg9V0fH+BFyLJst4XStQv6SK6wksV/JeOpQhDo6bvaSmuHARgQtv8t526Q
         8UmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=17JtA2o8mdh8rwo7yfzGifr+eq2Z2i6jhoLnTSnKxII=;
        b=KlcpvRWx808OXY8beQNW0mOVkqZm/XAZR//hNmQOVY+MvKgdGHZM2DvnsQ1wamHTan
         W+NAd5Bvh9BLE2+jtJFLrnn+jfOZhbSmp4d03+QGxVob5uyXy71OHZHrJn8XmCkw+8yo
         bImFelb3XsWtSAKv4stGvXYFY5A+4hp+Qmstt5D5R35qdN0jSB8E1bOUQWoiLkjWUt3L
         gVM7Z11gDa+Yxpcl1r38J/QY7L6trgAl88k8Q6QJZXaYQYfPlORDHkAvt70vz2aaJA3X
         QAddm6tiWzPSuxlc7I9wyRgNny4MEV1kqK6Bl4nMlcxNpnxKzYVXU0kiobbhYER5Avj/
         RSOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=17JtA2o8mdh8rwo7yfzGifr+eq2Z2i6jhoLnTSnKxII=;
        b=ozyQ+DD4/U26lnl4ceQnSTU1UO98hPqBHtpkOW9JUL3kMMJiTKGfKjWFEXCarRbHC2
         WY5w8kaF9EFAF6XqM5O7+g+QXKJiBmLr2LcYscFQuHEUA00IfP1X45e38r6V2MNSLXpT
         cnTDG+AoqIfLtUffIKpvnXrjxUEV06Kft1H6rF0hTeNEern0zO14JhjhliZnVu/ksd9x
         tUNr/JGWBEcIalEIYXzVOuylX+jWMVBKcLN7wVgygs3i8GN2t89hYTW3zCXbB8q6+P9n
         4k57XyGtwmIAjpiBRxJ3dSqQ1VadDDT+wAYM4Vqal0cHSTv9pct/3Jxkj4ttzOZbIFBy
         nvIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=17JtA2o8mdh8rwo7yfzGifr+eq2Z2i6jhoLnTSnKxII=;
        b=XjvUyjbLhbV3miQSfwYN+UUvpTYVlDyV02ZSLRx+3Jshcpi6xqYhS9gjfQHW5Ns/f/
         oglqVfU/rVBqRjIMItZc969MJaB6ix/m6h4PdIw18Bk/8CJ68k85x9VcfAKWNJPmYpxl
         V9Tr8UMo3eOMAFHpbJ5a4XJ/0by+5RSvEa5rSPTgx79mMyDgAHlmzptr9XUMIBtD29hb
         V6xcu7dKqF8FYIzwXmaCZ+rZyPdM6+Psohd1KJx9TQ3ft6TJTBcuB4GnxqEhCy0+/ATa
         cFoTcOB41FroQcdK+SPqoekPsPAAQdzMISVD6YgHESGZn17YxeS0q/Ux8/nud400hrT8
         IW5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXnPHM60eJwPV4O+QCk+DgNgTERBYLvpW+W9ttz8Mu3JLX/iAox
	dx/KjoWZ+wDTug8pR5RmVEI=
X-Google-Smtp-Source: APXvYqwMez1pnkE61hvoPwuJqTPyXWqZuvaCr0bGtx+lik4sGGtYrCv5ceoM4DM/scLgtb8E3SwQkw==
X-Received: by 2002:a67:f911:: with SMTP id t17mr11483898vsq.128.1565301478017;
        Thu, 08 Aug 2019 14:57:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:e83:: with SMTP id 125ls4007479vko.2.gmail; Thu, 08 Aug
 2019 14:57:57 -0700 (PDT)
X-Received: by 2002:a1f:1d58:: with SMTP id d85mr6900584vkd.13.1565301477703;
        Thu, 08 Aug 2019 14:57:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565301477; cv=none;
        d=google.com; s=arc-20160816;
        b=LFoxGs+tfzByRe56FXVESMpKxMZSiMS91m3qid9ePuRiQxxmQCqpXj5chhOtK4dzfi
         c1PPVNGMyagEmMHJJ6lgAJ1rsq3ELEJKKQwAO3WSCSKmkTXTi8ywOwo0lURFMAieEdRM
         ykxhAJVqSMjITHVvBskIBZ7I8EaRoslqjgfGsmHILEU0K3R2UT0bGFUNufoOhEVeYFjt
         KqsxIHor6WVYAtgmxpu1CDC6ECG2XuFfddY97gMnQpWmYF2UVMZNmImKhK8QG5leXnfM
         xx4h6IyCcUhZQq32Per+Z0IMV/Ml7pWlcMQM3uhVxMI2BpLUYGXnNTjxNArMNllXP15X
         bewg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=HJHWjvAtP0pYj+UmyNUhGjnkmaOJJ0he4lagn1Bn0C0=;
        b=OZyZlEjLNtfAuhfo9Tl276dV5F2oGqFbHhJOnC7Jf1iroC5MrehVlR46s3Urb/srZR
         K2AwFSHtrqqDBpr3ugXYOJzuJEENpj5qyu4ag5BicUUxA/Z9lzCW06Bbehy3L0Ch+KaV
         Ii9R26VzGtm3LLUYR7J6dHB+H2tmWX6ut/jiEi3gW6pazIyb26+dwUAEpskSeskts5Ue
         e0DKCMjBIryDXE+67NQQ6lFqKa88N0NOPsRcUJG5CK0QEHxfUScdCLqS0oLcys+xp5/7
         6xOq4lDoDt5NWsu/wdJgnWYLkWeN1IVt38clnwegf/KN3lEL4wAPmwBlUPQB9Ior1Wyk
         jwGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id d8si4384732uam.0.2019.08.08.14.57.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Aug 2019 14:57:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id A472128BCF
	for <kasan-dev@googlegroups.com>; Thu,  8 Aug 2019 21:57:56 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 98DF728BDC; Thu,  8 Aug 2019 21:57:56 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Thu, 08 Aug 2019 21:57:55 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Drivers
X-Bugzilla-Component: Flash/Memory Technology Devices
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: erhard_f@mailbox.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dwmw2@infradead.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-204479-199747-M5wlCCQZDt@https.bugzilla.kernel.org/>
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

--- Comment #6 from Erhard F. (erhard_f@mailbox.org) ---
(In reply to Christophe Leroy from comment #4)
> We need to identify if the allocation of KASAN shadow area at module
> allocation fails, or if kasan accesses outside of the allocated area.
> 
> Could you please run again with the below trace: 
The patch did not apply to the mainstream kernnel with 'patch -p1 < ...' but I
inserted the code manually. Please find the new results attached.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-M5wlCCQZDt%40https.bugzilla.kernel.org/.
