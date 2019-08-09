Return-Path: <kasan-dev+bncBC24VNFHTMIBBRH4WXVAKGQE665JPHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id AFD9E87C4E
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2019 16:08:06 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id y19sf88949795qtm.0
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2019 07:08:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565359684; cv=pass;
        d=google.com; s=arc-20160816;
        b=OxDHU0ebq4oEqSPF2jp34G4/As9uk9+vs3M3Xvr2ovbkAlJjtT07oATRj2siXM/Ig4
         Fb6K+RjExYhvlL1zfeAK09Jw7yVVWUQxRYdUNaH62H1Syt/KezL/vmT/7BFt2dxGTuAF
         F8I79dKIs55KN/EkuIlzINn3wUoOBmODKkxPl3CvmYum9xG8L7gkfalOYNJbb0YJV4G7
         DKKvU2JWARbmP5iO0tx5rvK2asge999tH55ylPLSIBcLaHROSf9ZIPjnJikUgto2aDME
         6JheOUYeIQqWnhpTUm4zEM6ZqB54t9XWQ2A5GQtA+uBQ4KOJgyPloNavbzEPB4DE3ExN
         Zqog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=PN2OS1L0xbAaWs3jNaMqG0Q1gG5TcHXCcnHgAMXeLmU=;
        b=za9YlxQuES1ddDrB6MKj/AIQ56TpP8Ob02wcS3GnGPJBSlFqCHxZzotVMGWSm2WeYV
         EJcWnb6XdJkjBxURBfMvSgq5/C7xeXjX/nI1n1FuY9C8G6gq1ahkcTZDoidN3CDuYGSv
         +uXjaw7otoZt8lYEyAtCclDYaXn8HZOQ+nIqQlOGp3CdMS2kz2CEMLMrj/+QT9FTN+b6
         M0erdKvOeEocQicYV1audN7HGvlMQ15Wvb85zb3YBmv5UKH4FvebwEte8AL+wRNMlhPt
         5J88aaXIHvi8g53eEbYvEjpVz3sMMJr3gSN7llZBoF239eF2A12FdtPFfrulUAkUqwf8
         AakA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PN2OS1L0xbAaWs3jNaMqG0Q1gG5TcHXCcnHgAMXeLmU=;
        b=OaZPAZfL8A/lK70USF+/ALO4HovMzAmDwrBB1C9zBQVG3Coex4AH/sClRd5iNXvAvz
         2KZ1Z0QKgNu8wX/HBjQYaEZnKKmwzalYsjZt1gQfVbLjwA0FPgodcshLIkxCcw55rDck
         G2Wu1mCb8312oZLIqA169rL6J5SfVFpGq1ZdiK6ChbcibQEzOY1DRO//MeMv9sgz6Nk7
         td1T1NZ39lqA4O0l7+xH4whwMDyaRSJfpEpJ0e7Rp7KfrhMy9Gb5AWazyP7Ddk1SidXT
         q5YqyFG6WJGCLA0SD7CG0+PcmbF+cXS/D1cht/nwQ2T3yY7PG0yNmej3P/Afmn0SruaR
         uBZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PN2OS1L0xbAaWs3jNaMqG0Q1gG5TcHXCcnHgAMXeLmU=;
        b=ARxk8jNEHV5hL+EMc0sICaeZDbCIcnFn/cpagCQRCX0vPrtsm/EDafhKLYxVDFLjpO
         44p/vkE7GQCpL6ATrXq8aBt7T6dkrIki1A06ebNdhHOAdR/AlJ9+rVG7mTGXu7jUYZ4M
         rppBaJ+JZaUrBI8ohrYyQsFG24+baI3Y2BF3qt5+7s67NXcLL6+w6IH1gZEJ74J4xwGi
         XcLsVGc9AcVPgRSYvlab89/OVMLrXz6WubTe5yg05dY9Kg0tUap1nG0T4sJzMw1TgKH5
         8R0OqOOEeJI9tx3zEsJ8L5v33MpzAXCsfYAclD6zB2IAv631Il2tGx4hfAt6ys7lOrte
         rJaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUM+3BXCMfBmD1G080BBA9VfT9hKqdCNAcpowpEtVbk2RrH72Q8
	LCzJx6xwRClxqEZZbPiDbSA=
X-Google-Smtp-Source: APXvYqzFZGAQEWflY1i9TIxd4HpUh+sytBXf6VUesQ22rnOJwKjAG7s99vTKsY2YIvSV3ZPX7Ku69w==
X-Received: by 2002:a37:9fc1:: with SMTP id i184mr5973088qke.289.1565359684251;
        Fri, 09 Aug 2019 07:08:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5502:: with SMTP id j2ls2211334qtq.14.gmail; Fri, 09 Aug
 2019 07:08:04 -0700 (PDT)
X-Received: by 2002:ac8:7549:: with SMTP id b9mr17740655qtr.198.1565359684050;
        Fri, 09 Aug 2019 07:08:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565359684; cv=none;
        d=google.com; s=arc-20160816;
        b=VhSK5FG9/9hVz2miuSNJG/xoK5Zzp8uj62dumitsuEk15UCmVa2IdeecpAHpifHg1X
         JaP2KrOu7i8TkBpphe4mOXkvY79mgBBbc6Vk+pMpdu+uL2fHQzJ8s+GPGeG76tQri5zU
         xyZS96ORRNsD9IGNzqwwIRzqikMb6smQsBCHN4Zf3O32XKXHLHBgrSZQwdF1Xs2PLF7E
         PzAHX5LyExzDvsdP5Z5aeGzbh5TIvog3s54T4k7r2kR6e/8iLwf1ujcagFuAKeWkCcFW
         GF78xUXowQ1kwQvAKA3LHvVzq6TR1us2gtyDSqKE6gUzr4UdRLtPP++FS1jhhQTX8rmz
         HE9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=U4KHowQ9wb9HhOQcwSHJN1yRIslf97XI+OEhmDZCpeE=;
        b=rOpIOFKvt0bCcxsh9mvBfHj/9fCfIQizzaGS7vb3T5TBVVw84I9fi59aYeEKD/gcGw
         cytGWLBZjVmynDMpCcgzWc2zGYB5839vw5iBCCXL1gnWZY6Ne/Qm3mwuMWlMleKhGYaj
         Zk6tsWZEF1DSRZsr41EYddS9DMuxdNoqcJ3UiwHcPjjzbfhKkc1eu7T4oF50BJElc5ID
         ao4yLTveJ9yeZYsyVnRJ2FFivP9ECwPRSV3u+pYQIo7CYvvVpStxrKjh1AU7UzJjDmEN
         q4HIcHOdvzo+3Hiz2URGBeuupbYuHj67m5j/750BtfgO1iIrtI42RAOXtuztuIOYJ7Tq
         ofkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id c39si4652221qta.5.2019.08.09.07.08.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Aug 2019 07:08:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id DF9D328CD2
	for <kasan-dev@googlegroups.com>; Fri,  9 Aug 2019 14:08:02 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id CE47A28CDA; Fri,  9 Aug 2019 14:08:02 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Fri, 09 Aug 2019 14:08:01 +0000
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
Message-ID: <bug-204479-199747-6ByTnsOweP@https.bugzilla.kernel.org/>
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

--- Comment #11 from Christophe Leroy (christophe.leroy@c-s.fr) ---
Thanks. Then it is not about SMP allthough there's anyway a theoritical problem
with SMP that's I'll address in another patch.

I think I finally spotted the issue. Let's take the first occurence of the
first log:

Aug 08 23:39:58 T600 kernel: ###### module_alloc(4718) = f1065000
[fe20ca00-fe20d2e3]
[...]
Aug 08 23:39:59 T600 kernel: BUG: Unable to handle kernel data access at
0xfe20d040

In kasan_init_region(), the loop starts with k_cur = 0xfe20ca00 to set the pte
for the first shadow page at 0xfe20c000. Then k_cur is increased by PAGE_SIZE
so now k_cur = 0xfe20da00.

As this is over 0xfe20d2e3, it doesn't set the pte for the second page at
0xfe20d000.

It should be fixed by changing the init value of k_cur in the for() loop of
kasan_init_region() by:

for (k_cur = k_start & PAGE_MASK; ....)

Can you test it ?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-6ByTnsOweP%40https.bugzilla.kernel.org/.
