Return-Path: <kasan-dev+bncBC24VNFHTMIBBBP2UWBAMGQETZGCM7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id BA14A336A11
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 03:14:30 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id h21sf14359424qkl.12
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 18:14:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615428870; cv=pass;
        d=google.com; s=arc-20160816;
        b=jay/sC5be4FgfkexwomCYpAS8M5p6eTHsav+rlceqplJemf0ROin9rCdXmJjGwms06
         dFYQOywpz2UzpF9L4+sh9/7y4hvUc2pcsvgFQ4rxq+S7QUf4Nmi5ETnffuLNcPqYx3gb
         km63BLmBS9zcIGq5j9VGhFz+OnXcUt9G4m4QunnqGtIYNT6OAXMNOejyKwWsGPbQQeG9
         Vs8WF3W1TDmONGKNKyLVFKzLgPsdyGO7GmeN+yx1DpUekM/FEyyYfSvle1snfA5YDGMt
         44hxgAJn5UUy8KGa8VMBRxIJT3mweLrc/heNI8Rz8hOId4zswORYFiTuGVxTKsidznW+
         cm4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=nl2A/T7oiUXgD0NoytxrkeRh+HZwGFXu/c4U8n8xigM=;
        b=d81RPNRZj/5b/JSfLg1yW02ITgZjMkVMUoyYDqUXcN0wuIapr699nhC8RCAMnE0FbI
         U1e2WE62bUqiKA0jY/6O9lsPezb3+IlZz39z/UbrzosDOcKlqryK97n1j47MnCpwO4Yu
         YgBYcMl9Rwn36gxTZ4drQoOv5I+TXu7j85l4tSaxD5SNaeOS6gwx9eOXOxLIm/GRReU4
         DAzX6DzjYBkAHLwnVvjpyzlIeMIkIu2st71dtBSHLqgMWdX8MOOH6RtGRrNw+TfbgjU0
         BHJEVMMDektFf4AWWBVFdlGJ0KTvZkfOhs0JQ5trrzALtj6mFDb1jVZbww88zx5XuhS9
         S6ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DBGvnC83;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nl2A/T7oiUXgD0NoytxrkeRh+HZwGFXu/c4U8n8xigM=;
        b=QOa5f61n6GcD3Aj1/T9eL8vdOFgkwZgc8VwsCZgBIJvkm3bRfEh3xf1fgegvXMrVeV
         /IaEofrT1ceemHE+m1L9aY3QRJ9oJt4vsKv6Z9VK+jF1UwXoisndX31MTvZQuzyBWZey
         wQPsbnN+DayWnGGWNpHKJej3AiiMXISx2YEdBwXivi2ElYXkmokti/K3obKbooP0x3V+
         hCqrdqQVf9w1025fIp1Qay3iAKSoTrrwRqLQ4iekLT6UPBWPkn1x8AHb14FaAL6+z9S4
         kLpXveUiHa7K+pk6LMNIqSJjRQ+IV4NsbP5Zf2STcm2l8v4VJvA5knxtZLq6XqjyYib7
         XNFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nl2A/T7oiUXgD0NoytxrkeRh+HZwGFXu/c4U8n8xigM=;
        b=eWeDb8XJW1zCehQMBx0QOE9G64M0qdcGMStOBRWZGynCLnwMZ9yDDblOYOgN20ncah
         A56/keiO+B9RoKmkH34OX1/7v5iKbWKktf0SyOzonEY9rZB9arONayRMapY3qFTJ/BE+
         AYDI8G6hSqw6+syfx4IgjXFRFRcRcuXbnojVeDKME8pLVLq5MpAgs6ozkG554w4LvTJq
         3JPczLbt7lDlgPlNjsiveTp7Vgr1Wr+W5IIiiN+2TvM8Jqw2nvc2XTF5yluo/0XG5dGf
         HrtM3A74iToLM2dnv6EPyhP4t22V61gosd+coDGGDrhVwIxlFHZ5rO9cQHXR0z6PIHUm
         9V9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533YU/BPejMM/Kp/b4j5rYF6D/Kj9OZbwPCQefPUSPqoQtXqjxOk
	MV1WaQedwTHwECuIfHTCHJo=
X-Google-Smtp-Source: ABdhPJwORnt8mlBF0HnKLRlyo+bT0ZOP+ccThDxt663Ul/egNGmWWtz2Rw62+kiOIba6KE1/EfbgNQ==
X-Received: by 2002:a05:620a:152c:: with SMTP id n12mr5700600qkk.334.1615428869877;
        Wed, 10 Mar 2021 18:14:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a050:: with SMTP id j77ls2257203qke.10.gmail; Wed, 10
 Mar 2021 18:14:29 -0800 (PST)
X-Received: by 2002:a37:a8cc:: with SMTP id r195mr5503369qke.86.1615428869512;
        Wed, 10 Mar 2021 18:14:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615428869; cv=none;
        d=google.com; s=arc-20160816;
        b=aqhESISuyaY1GXPMz0gNX/q4xFYjdyn8gcedRAfEDD0WZLGfkbU+4/0wvYPm3OPD0w
         N2e9eJbn3l+2+OcP15K1J/kkWCFkAdDO6I+3SDEcwldkE3HfTiucNdcUcJvYGBUZN89Q
         Gjpe6W7wQ3xg4JO9q8+N5jfvMn/BG/Mj/ZAkuVm5JSujjxaV3tc3oZ3WyKaP0JPTegLx
         YMdwVkz6vti0AZd9FJOJds6lUpSA6ySXuwikDm7cxkNtXfAOLTPgsCKbmDvz2PZJVHlq
         eS0d7RrXnO8UeaWSHdITxHl+UG5zRmfw6+QYs+k0Bd3kJI6JGF8v/SKhDIy/9ZnBBzvz
         4tOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=htIUkVeXpuoLIb/VWUNoSErzX6YKk9rae6tuI+I6DdQ=;
        b=fT1yU65ZD+lCZ6akq+XXhSvTPvra9hjMZDV6GQls8/qLjb3Ye/rC5IeKNlhsVgu08t
         p9VwugiSyEeji+C24htH6ranUGHfMWsEqBNEihYQDUxw34e/5g93xzr770XRNDhNkwSb
         f4jNVOdhLUSUUj6WuKKvdE5VIEkHOPhCZMoFL/Or7NXdGujNoL9nOIK6nsMXVeDFrpua
         Q1RVWwJPFyb6AMoFIewVwD5wZR6kdDBjxt0BrN3ZHG1IIHsFgEDouWVjhl6iNW3ymRYh
         K8baPsxkvxMzvRrgawDqRNT0+hosBWkJgrc4MTY+hfb4Zwz6ALPQe4Bu/3D5aqHmsuDf
         87xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DBGvnC83;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d12si59142qkn.0.2021.03.10.18.14.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Mar 2021 18:14:29 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 616A864FAF
	for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 02:14:28 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 4FC066535E; Thu, 11 Mar 2021 02:14:28 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198437] KASAN: memorize and print call_rcu stack
Date: Thu, 11 Mar 2021 02:14:28 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: walter-zh.wu@mediatek.com
X-Bugzilla-Status: REOPENED
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198437-199747-iegz6tfyeh@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198437-199747@https.bugzilla.kernel.org/>
References: <bug-198437-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DBGvnC83;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=198437

--- Comment #11 from Walter Wu (walter-zh.wu@mediatek.com) ---
It seems to be needed if we want to solve the UAF. I will send the patch. 

Thanks for your information.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198437-199747-iegz6tfyeh%40https.bugzilla.kernel.org/.
