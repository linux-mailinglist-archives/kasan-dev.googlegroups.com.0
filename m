Return-Path: <kasan-dev+bncBC24VNFHTMIBBPWY475AKGQEMF57WYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 742882640E3
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 11:05:03 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id l6sf4022831ilm.14
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 02:05:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599728702; cv=pass;
        d=google.com; s=arc-20160816;
        b=eAPGqLIfEgza7eKisVE0uA3UyWnMuY0/3gXHG53u434oPgCJXv8XHxtCGfV8s4t7bM
         0cnoQi5zRtJndgOGHETY8cmX+Aj4eZ0WtDgOZP2vhQE3F96VTZZsU0coqETmnUjIWaPX
         RPw8vMiuAo0o/7j0K8GsR2sUU3/t5iM33SIIikWTCIc7dhcFB8V9Q0oNBPriKg0rP/J1
         yLIBdm3sT1gWgUp8nwzUOwrSGmSysxysXcBl0YYoAKghvesLDAW3h8yFjCxUWpP/QZYP
         18YkatwXMgME1LVDFW6TodV6TQ3vcgvgwmNMUMfbG/pIfNHusA9sxHA6ArCY+389oYMX
         KQmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=MSNvRmYpVovHQxgGhO97tGO+/Z+y+MydaSWezIxBSvA=;
        b=ciO9A+rp/bHIuS0UVq6N7yuRrF1Omu3R+ySSn0cfqp1p4CLrZCU39+sFWMC+tQksf7
         gEpeVmDzo/tslec3W8yTSSoMMYFxwZ2OJlRjuiTB0yfX1LDMxncgCaRLxg91xGuAvgwZ
         5vkjvHK6Il5paUy3tSB2WDAVokMxF8dd9l3o5L0dMmqA+2D6JNCptqFu5QW2FhzMwunZ
         1f11hPSq4YhamFpXPDIE6BT2+pqQlhVd1a/gUezyoTKZfXJEpidTWB2d0NypkM3RpyKm
         Ki+b91Ca45E3XkVK6DO2/Z253HQK9Q5aUf6FawEfBZYcThdRwnpFJ4syYySs44mjTgvK
         eMLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MSNvRmYpVovHQxgGhO97tGO+/Z+y+MydaSWezIxBSvA=;
        b=fal/sy4eF6hZXSP7rwfXDJlov0y661FoloAp6i9IwXrM/b5HkPTpqur4jKJ4oR3QF7
         fSWajxftQXuzILr77FevdrvBcKX24f947xTZ49wV8REEsebLTmllfQCJxTdXk6/GR1qV
         oy7KUfXJkF8POg/6Cjo1noizsPG+ef3bz3Z/PFsi+tNQak1GwcrXJBfKMZqsk8cYF25i
         2LKe1cT91Z7dbJkb2cA2cLxczwErBWjBT1g0Dz9DR32jMawxLyvKKkMtJFg8Xu3Hz0q1
         lSZX+TW39Ps0lqZUQ+hPfaw+5UjXQ8s190dUTxLksdAFKzIVJ1FiL86aVg7pY9qh47gE
         HVOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MSNvRmYpVovHQxgGhO97tGO+/Z+y+MydaSWezIxBSvA=;
        b=d6lthTIe2GX0a8035Cd8cXvpsPiVh5b6ECa9WphvtOhXPztbaAw3qrmUXBacaci68v
         UqJUzcaMSz1G7aPoBV76ksbrrM2eI7olOEhiblqMq3NIqHKZTGaGHR2KWzSQYh8iFAV1
         R3b43SxLpJBPoJPSX0428q/TrTSl+0yXUWAZFrlT3YlMi0bq6jIHrQjYw3T9oWYODi1P
         ryL9A5CTCKxRbz0chk4TyHCf/smbbO8GB2C7Z+SGlRuKpRrynE4oqXVH8TBkkKKiLXzs
         pMP1b8quRfAq4p6MlkgfAOXvf/7uaB6giogWQA2UxauGEfqqOpVknhrxUI83O/zIHvOe
         rksg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530+aw0zgoQhb94hzL5U1IjEV3+OBjDmHwo4Z9DRnxhgm7mfTrUJ
	tlF53bcwcHGrWZROq+UzDHY=
X-Google-Smtp-Source: ABdhPJxSAV0OMpwbifaGLXI8kRZ0Vr2FNGCHrU4h8bT5NnoRFswvbIydqZS09T7tvODdUwALD6An6A==
X-Received: by 2002:a6b:ba86:: with SMTP id k128mr6836801iof.131.1599728702479;
        Thu, 10 Sep 2020 02:05:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1655:: with SMTP id a21ls701452jat.2.gmail; Thu, 10
 Sep 2020 02:05:02 -0700 (PDT)
X-Received: by 2002:a05:6638:d02:: with SMTP id q2mr7627825jaj.98.1599728702149;
        Thu, 10 Sep 2020 02:05:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599728702; cv=none;
        d=google.com; s=arc-20160816;
        b=GBCSi0LxacY3vah30cc+nIivitsflL/1YmbvL4rfJWP8TGT8TBl5+zhVOfQnF9d1si
         D6mHBwKONvsiFiuXnvn7J5fBqcH+IdzrR8ps8TD/B1y+lxjNNEby5WoyEoZru7d9P+xb
         Cz8fZ+LjihXmx/3+onFTM9jHiGxXldWilraLPdGdnSrxXR9IBUn20CJh1n5sEsuj6+Lk
         j9KX+b8Sbvt7IpZnsBiD8kbmRTUB3EH37B9g/n7klOj/Crt111ULLI6nBN+nJ3gEMvii
         Hmfm6zjGdQ0ZaUsJFpp3YFjwuCMfKzPyyoktM42h1pQUyVM6lVqO66feBoi6IjADT3TI
         jckA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=5aAa0QzLYsPzjXV+DnYNVI+/EtFw3UtPnW2jx0hfbI8=;
        b=WULjVaW6cBNzXVWivHDEfjIt0WTtbGKCzWCKjlkKhaQo1nAZVVHeYZIcRETtkGbTEA
         AKPN5zxul8D/wenCxE+7DF+DE15W13LUs/XaKqn5y7LSjj/SJC/MMLUG9G56BluHfC1c
         XzijJHMBwWFCoFrlqetg7wXvkAefM1CWZrOHrmQBAYmxPvUu8qr8Xm2FOC7ABYfgZG70
         9Z+51MjR3GZIdoyhMa3AgYGf00RESq7lq4GtSS0FbkqdzGdX2KGNo/jqF/6CaElAWEWh
         xdPrPClYpcPElKla+w69rTnEzbbZiynURDNZvuG5LIxL012mM7cOJK9m8SaeyZ4jjaUw
         8wDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k88si456402ilg.0.2020.09.10.02.05.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Sep 2020 02:05:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 209219] KSHAKER: scheduling/execution timing perturbations
Date: Thu, 10 Sep 2020 09:05:00 +0000
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
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-209219-199747-Ueg5XfaaP0@https.bugzilla.kernel.org/>
In-Reply-To: <bug-209219-199747@https.bugzilla.kernel.org/>
References: <bug-209219-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=iyom=ct=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=iyOM=CT=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=209219

--- Comment #2 from Dmitry Vyukov (dvyukov@google.com) ---
Right.
I am not sure it's possible to inject NMIs anywhere besides qemu/kvm and
special dev boards (i.e. not syzbot). But even there it's controlled from
outside of the machine, while we want to control this from inside.
Even if we expose a special kernel interface inside of the machine, it won't be
possible to achieve right granularity. E.g. on a machine with 1 CPU, user-space
can't issue the request until the executing kernel code will be preempted for
other reasons at an uncontrolable point. And at this point it's already too
late to preempt it, it's already preempted.

Having this in kernel in cooperative way seems to provide much better
portability, precision and effectiveness.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-209219-199747-Ueg5XfaaP0%40https.bugzilla.kernel.org/.
