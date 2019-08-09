Return-Path: <kasan-dev+bncBC24VNFHTMIBBONQW7VAKGQEY6SPOGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3423A88413
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2019 22:31:55 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id q9sf60313639pgv.17
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2019 13:31:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565382714; cv=pass;
        d=google.com; s=arc-20160816;
        b=F2woOIoX0QC4al0dAZNkIWRWg5JSgZ+VC4O6l7jrzMlr3kKiwwDkB3VIZP4j7TAJb2
         PebwKYkaP+eCdayEpytqNbuxP1yN7DZ41ID9gCAAdG+7qHeEj5sEX5GQk2AFKyXUfDkw
         N3SPEWzXwt1fN8kVlYr5RI9RVx0aGv2Xw1Cz1XQDoprKiNwTh5x0yZk177pBWHNKUbWn
         Ulco36WMb4xxH4uX1v+OEFeEIvP9j8CG6idS+i80ZFy+I3zIMYNtM9NCEYvLkAgpkEJc
         GbhNzGUbn1yX2QixMxiY17MmzpFE6IPQ1ESQb/e2CWldL8v1rzwG8Xg+5UgT/kVc9Slf
         CIQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=GkUgKcsjTK2eEtKIT/x/sPTZ26xNen0HD8rooruIEn4=;
        b=jdXNNfWr9wurcBtHiaXEV4+xRSKH0EEPyB9DMLETayZVGb+C3NINApg5w1b99DJKbi
         JGUBR9B5p0AOmyj8oMp/0sDRX9ZI/+eU2yoy0jkbmE2b244f6H1vNC+eh91RRfH1TU1R
         ZacVwd1M+GoJy7J6/nkhoT0GGx+qKz+XSsUeOdbEnRGKxzimOdTP0GmJlvh40Mbg+3Ya
         fSkbUisAN4CPWNbH2hXR5oXRFNn0PmgM6CytGkZrPOecJrE0PVl4PQyEaG+6UDL6Ayl6
         LuLDOwdrGXqe2dz5dwSe83EeNU3lYsbItJLOfxTozpmq1WPL5h6IqKgjqHVMbLNwJhNi
         0RUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GkUgKcsjTK2eEtKIT/x/sPTZ26xNen0HD8rooruIEn4=;
        b=BP1Ukb7Uk8m6Lvc9OBYsq6UJ7FTDWovweqpZRETdSoGRs8qgUZRnBJOGMKBhp/Q2u0
         e/HkbFvfk/evQupGYBEZ3pxbokd9Pj5/dIH7cGdeng/KK821fR9bD1XiJrrUyY8DzOoZ
         VycUsZS9mwdAg2VOkss8jsUJakMD7HA5HZWchMQfgFvuXwbZuCq4pOTkz1ZGlDNN3bRa
         k3rE+7V8o3XH4mOfwzvJV+pFh2FYtcVAmjKQQv3WnFKO575vSEsT6LVeNMnkQPUzXgTO
         rotTFfOXS3bJLBP/DJZ4kXPy8jKUwooaBwCJKrc/a9Al9dDXeaWB7Wc+kwSvknflJ5Fd
         3q/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GkUgKcsjTK2eEtKIT/x/sPTZ26xNen0HD8rooruIEn4=;
        b=GHd3QtWjNMDTPT96vMBWOWa9ct02wSHd5eEA4QEjs1BiLx93PGTEG0UKF00e89ZfvL
         8ELu6OzRkZOvOFgYgIUbXngymdXz8ApYbkAc3KXzb7SI8iUct3B0LXfx2G51gAOhmvH+
         M4bGSgtmBAw0TRVRH3bujEdt18iS58RBtyIwz/057y+6xpzRN1Hq/ks3VrCvAWtnrXve
         Toco+ql1YX76XLH8St5zSp23nXZaXxwDJ/DB+jDRFIq7u6e+4XJoey9l/pDdq46N3pjT
         F2f18Eu9dazNaDeoTus0koQjnWFEedt8Z9WH7MRyWW0DkZFrxCPlyqgpmk5YYSPZ92b2
         O1aQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWcQJwiBTEHzDeOTKnjm+7AMHIeH4CExUUMeCXM76tsUhh1CrZ+
	gimUR0A14ghD4X3BwSintYs=
X-Google-Smtp-Source: APXvYqyYJhASZ2Cu3WWxW6CqvFypBAQl/AiwbYyK2E/C3NZYRx502DvpffWXHfSaMfnZhMO26Zy2Nw==
X-Received: by 2002:a17:902:aa41:: with SMTP id c1mr20544177plr.201.1565382713961;
        Fri, 09 Aug 2019 13:31:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6b81:: with SMTP id p1ls26142598plk.6.gmail; Fri, 09
 Aug 2019 13:31:53 -0700 (PDT)
X-Received: by 2002:a17:902:e30f:: with SMTP id cg15mr21013696plb.46.1565382713684;
        Fri, 09 Aug 2019 13:31:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565382713; cv=none;
        d=google.com; s=arc-20160816;
        b=skYsLD/0TILWlBkiZdrOdp6tBJHEXd9YHie2s+4mqELAxk4zSXp/HdNmj9Y7BBb8y+
         +vpy7INQMEQ5J9/B0oP7kNYTh8AG41u9JdV27c5ITx1EtDR7ROZKFuFsJ0wFTZradvw3
         /IhKWgp8WmW/KWCXLw9Y8eLYWiceVcPM4JQkoIBo8ZWybvW19PDvJbLIvmVbjRlEJ6Uu
         hdK28hlhZHEse9pz5Okw66m3AwiMd3D389QtzsK7WiygWFy7s7O8yuGmyMNm+x6z8mXp
         DXv9T0GHZlJo3TcY1mqJ3V+AM/0MPNatNaSw2yIkxcFjv0CTRobP7zCLRETPDMhTopia
         Legw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=6Eb/yFvQ6BtzT9sBqYbs3vP4dZWYw8LbGe/kHSUmBNQ=;
        b=JpLU+wlM7i3NQnm045jv4S3JPSHOcxPcidwTrtaBYgPIRu0Z0F30bD7DuJLZ5qAVQ4
         HS2gO7HSfu5DcBqhMpbfJJGH1NlX7Wjx73RcqZL50PxeIKwHF5ewGpgOMXVLjCYBsgxH
         CLbnLD2/9f8VX74+SbLZkEv4YgvS700T8lUgUAh0EiWTk2p5cks7IgK7Pw2Zr09pasyN
         2slzKWHgsF8QnKaE+l9ictqBvlQxz+xc7OkN8r0soXHiBDJnZ4YeHOBEYNQ0WSALSY0T
         1gwougUVHuYDLB63jpd1L4SNduKcWECazbMSXvCAbPuLr44nSnsR+Cj/BlUkXwclzoTq
         goig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id r10si85799pjq.0.2019.08.09.13.31.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Aug 2019 13:31:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 5BF2C212DA
	for <kasan-dev@googlegroups.com>; Fri,  9 Aug 2019 20:31:53 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 5062F2228E; Fri,  9 Aug 2019 20:31:53 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Fri, 09 Aug 2019 20:31:52 +0000
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-204479-199747-snvCHPA30w@https.bugzilla.kernel.org/>
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

--- Comment #15 from Christophe Leroy (christophe.leroy@c-s.fr) ---
As far as I can see in the latest dmesg, the Oops occurs in raid6 pq module.
An this time it is not anymore in kasan register global.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-snvCHPA30w%40https.bugzilla.kernel.org/.
