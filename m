Return-Path: <kasan-dev+bncBC24VNFHTMIBBBET7L6QKGQE4MFEVOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CDF92C457B
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 17:42:46 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id h9sf394996ybj.10
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 08:42:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606322565; cv=pass;
        d=google.com; s=arc-20160816;
        b=YPhrP4/fBCLY9Yjwsf+kz/EMBlDoxgKvtVb25i0lxzjuIJMH0syssQeYS9IBV6ONXS
         o61m7AYKhGih2CiCaMCOf7eWo/rf3wlULrTZCUmLeQe5JAsAQLA55w+/Ub8mDLND5Z3J
         8/EJtIZ2Ei39GzJgJo4mPazOVOmO9+2NSsNgvO8hOXuXQRINSZf4drTVP5B187Q7JGmh
         OvX/EcCVMIYwQFO5fPFR+UkUTfg1hWPxpCtz7Khg8qLQn656kSDGljX6eQtRVgqAPZ+8
         Fy6V+f61OHVOLn9ykozX0kIHMd8NQkMylh2tv9lM13h54a2ke0pLq4kTeIdjcqBP50gL
         2j4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=60GnwNKnqmsFjM5dIM4oFwRB/XYt39RACpx4vR/RLjo=;
        b=vIH4332eiEY0g0qP2hmhOnoox7Z0NHnHaimQaoIZ1963c92iODiDVG6Oij8NAMc7b1
         xW5dR03ecxgLSaz24FlDmZSPOXAuE8c5OykBZpGQFEKFt+2rx/OF2wbjYTAjuKwnyC5R
         CGiVTkJCQe4FTXomDxjUiD9KHAFfCiwNPBH2KX2ffpalQU6FpdyYe61BcBg8rdRI5ddV
         zH3Gvl0xK8Hl2p03DONrmgPLB9NR933Iw297joqCL2XGG7o1Xalx3y2zdvplp5J2HyDg
         vo8VXWhj93HzNUX8Qp9cDsRmGx26Mf3s3Uozvp92Z419sNEVowgA4nUZAne0szNDc4Pf
         k5Jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=60GnwNKnqmsFjM5dIM4oFwRB/XYt39RACpx4vR/RLjo=;
        b=XaA6HhwOklLbA/VQ+aMVg/Q8mHLd333DFQsykDYzQZMd+/hVJO/xK3T3FyOMz4dO+O
         anONYsOmcxuTuTxasSlm0aiE+McOeda40kLewhFdn7WcdFtewcRI1iQazlO0NKoq4JMY
         nvG2gk33gJ/5sBJ3g7EtnVLVxPgg9Bod09gMVmWCIQ/DYafSCcpNYKYvMCTGrlxuf5yW
         vMO7WnWdyCjaEFdrBkdlYT4WCbOs9+AHb2nNRn0XdmCpEhzL+brmEEgaywt1Yia0zvX8
         Xf4bLgopbcIBsqjVPsvXz0xRM5sCbZrpNduA2wfOyp6z4+Ih0ccMD8Eo6qRxEyUmmBKj
         XPmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=60GnwNKnqmsFjM5dIM4oFwRB/XYt39RACpx4vR/RLjo=;
        b=V8cvZjOIc3UVt7e46dAvSDpTrfUCpSQBWSH8GMUTp26c/quQwc+Usoy4jWxWZUiO/r
         NKymNefeQWHl0cvd9ahIn6kSysdxgz5DGuPnlK7mwfH+7XITaAPSDmnAKHFt4rT8h12v
         ZBh8axdvUeiK3dqsR2AYZjjnscjq8wocw6cEs3OLTO2yR5gsCJCgLyPZu+9RK3Js5HsA
         7Y6Hdzt/YfBJOC3K5A/2hSuQFD/PxdMyaNGvcUjJKdItchAarb0XCYMQw5d85iEQmCfJ
         ZGSepXKCdCzYbHbm870mArlf1tNzN1ovWFrSo0FugC7mvKS6v69nmAO6Gfgbl4/gWkaU
         /gyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533h+fVnSqkpxKhf5iBMGMZsC3IoM1YBLsNpEBNHGbx61sIDuN7i
	k+iODwMW8ZfMxHUzg4CRKEA=
X-Google-Smtp-Source: ABdhPJxRU9/NqvxwfEAvb9EV0dBwHqwTRN8wUqFJo+0auMW7aU57c2U4ee/3MQtcrcyNUY6SSCx3Zw==
X-Received: by 2002:a25:830e:: with SMTP id s14mr5822909ybk.213.1606322564913;
        Wed, 25 Nov 2020 08:42:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:344b:: with SMTP id b72ls1516150yba.1.gmail; Wed, 25 Nov
 2020 08:42:44 -0800 (PST)
X-Received: by 2002:a25:e8b:: with SMTP id 133mr4221682ybo.146.1606322564491;
        Wed, 25 Nov 2020 08:42:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606322564; cv=none;
        d=google.com; s=arc-20160816;
        b=zGzOcqzWg2uvVazgO5us5kiekuigyuB9Ad4Ogrswljr8QviT5Iw2Ca25vsD+BQXGgx
         DQGxw7a/sq2m3zrHp+El8XhADskwU3+3G3tyKcDjCjqRaO/7ttVMEkmreLLA7ToZO6s8
         +FoissvuuWYRyjWdET4AeZEBqk2/ydRV9UBKeWpO3lu5bYn0YutB5UEb3UMUAS2jLJB1
         H3RytbPXQAdMqMuNFAdQAnvHPSu0ajAxlTL1FvS0trERiw7JfKnh5Qlvm5z1FCghbXoU
         Ek63apgvRMDGFQC9u53yF1OKjD0GwiL4b4b5pUfpCO281Z2duTEJogiPywONNvP21wUe
         S2cQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=YNyDhL+q/78FLv4ZKmM+wr+B10OmAnx1RWAKLD7WWKs=;
        b=coMa5S8tq/EtqlRfWsGQs8VvkuOjNpG77ZYBoy4KCGZgxsETZztvpKFJCzP8yUD/aO
         BnoXmnUFCMCwMNnMlePVzyAsJReXtIlBlnWNeBKSh9VLC9D2yirlGpWLzb+I3r1uSOGG
         Qw9JXTkqDhoDEmRQSUrWRV7m3E5FZkjHmXF8YxxgaDesnzMsjmJFh5j+T3oaq82IYfLc
         cb+7zcgo5UBKGYDz+o7YhoenrcH40UIC0XEgwniqLmEMTIvpZ7Z5j5km8ugl3txzX7p+
         LRymHpGnaXh8a33xl2ZuK4fiyBXzoMGfs84BUkFjCEDml91kp/mcaWm1f9NRQPeHz+Ew
         H0Eg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u13si135851ybk.0.2020.11.25.08.42.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Nov 2020 08:42:44 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210293] potential kernel memory leaks
Date: Wed, 25 Nov 2020 16:42:42 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Slab Allocator
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: kubakici@wp.pl
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: drivers_network@kernel-bugs.osdl.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-210293-199747-jhIQixTqG7@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210293-199747@https.bugzilla.kernel.org/>
References: <bug-210293-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=210293

--- Comment #11 from Jakub Kicinski (kubakici@wp.pl) ---
>> Why do you have KCOV enabled?
>
> it is not enabled

Huh, then it can't be the patch Marco pointed at. All KCOV code would be
compiled out.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210293-199747-jhIQixTqG7%40https.bugzilla.kernel.org/.
