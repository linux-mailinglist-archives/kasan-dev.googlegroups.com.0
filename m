Return-Path: <kasan-dev+bncBAABBL7BQGJAMGQE5VWHU5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id E70C84E87FC
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 16:12:02 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id q8-20020a656a88000000b003810f119b61sf5584827pgu.10
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:12:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648390320; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qm2Z7JgQIHh4UnpOzEWGzBs6x76SxZaewkkh/RyVEXJdTc/qa81SOAoTvH6dWjw5Mr
         nIkE8u2FQpBRy9aRTymV1wVpFEiKSt6X9GVZa3++vTfwFxKsvbxPi7SJm/WJDimksB5H
         q8eWcIuI2oM4rZJNDJFmClfKuWETD549vxQNPTTj8XR/wZEtUScQB2Kwx5wHjxi6rw+B
         hb7B4YsUCujnRgmnWQhygbpcEADp8eWXAXczIgKYj2XYvvQ05YzK6jj10wgMFtRMQ3c2
         ZSgUwQuFC9l7nMeWb1MLWTwnw8PH4XIb3ckp92XuEOV6ouKM+SWvqxqQGUtJ74M5ib4n
         Kvaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=hQ6eCnuTIA9WCueqLznMFNychT2Zbfe15fM5CID3eRk=;
        b=Mce6/YJ4kZ+BY1NcqzRrpjorUMWbagsOdeXEVqFa5FQKmHCXjO/uSo3htSj5olbnbv
         InWSZLKJyYJYHflWvsmqYdYrxprQbx0q1AIslH9AhdJauzCYnpN7XSeOVoXNYrqlG9Nc
         bc9VTtFi91CGmZiSGjNdCO+3cEaCnuG7N23oQ4sMHE7OQaYtgz3nRZuGefF1IGPai2W8
         Ruo58MtSAvPufXeNbZZzvZGLXOhVBK9IzSyihrTjFjJ/zWwA64owlPwMJ8eB0Bt3ydOU
         BPD8gcoGMC0J2Kt430gqDAinnpa936P0SCBFqc0Aiawc4vFM38G85Ri8pm0n95H9MUDy
         b6xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ubmw8SI1;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hQ6eCnuTIA9WCueqLznMFNychT2Zbfe15fM5CID3eRk=;
        b=PpNHoDyo5r3+6+kAHYMGW1UZ6RbJ1RN7h4PdM3lVsvx/D68eP+1Xx8pz8TbK8UTMDM
         5zJKrcE5f2jH94wf+Q4Y08V1uf8lSMRaOLj9/V5lduwWV3tsLn6QvjqUfpcAPlCPb/Gu
         4Vu4hvEOfXaLqWzIgaumpLHKJT0bJl4Fl9EoaCZynqtzO+2C2gexM4HoLTYPCr2bbbzb
         huihW2Hgm2UB8iYeBP0/d9AsdHWd67cUsM6zP0cR/5CxU/MauXQ1fqBnbRl5GufSKc2C
         87rPlbH7DHHWbjkOVPCUo5QDemOM+pTposjUNki5sI0sh+GmJklALObgV+uSDAIwqQet
         f8EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hQ6eCnuTIA9WCueqLznMFNychT2Zbfe15fM5CID3eRk=;
        b=lQ7L7JITnpSecFrfnzJqfmJCTd9oQv4aDm3gQ/eqGz1I3XFr/D78UZ37imVgEy7AqW
         OAqd81vlPgiIJT05G1JAVIr9BogUrfbfgKrMY/OEADqhzkQhX/wi3cZsJCeDpL/NMvJD
         VOq88Sfe+7R3S39K1ZeQz1ueQGYIicFt1HuzeKp91yKHWRridiZhehK8gyd9rAwyFMKB
         UdlohP+EvxVSXWJzJvNj5veWLpNrxeLo95/VQpQWC50LugeFmzQQggt65/mwLdM4pvfk
         4M71rnrD1hut6SByzTLMn+C/jV3lcF+qmUSdwv70gRhKB6N7zpIzyBzgNAFRErJHec6u
         U7wg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531I0D9VZon/26iNB1FrLzi+jn84XLu6IIM4ra7GavQ1kqou+UwC
	pipk4UHK28RaYF+kETUShgM=
X-Google-Smtp-Source: ABdhPJxtarlJrA8deN65lKzYm+WVJkDz76B8x4R3Ou83Z9EU8BT+6zFNLJzUff39kJ5qA3AqOi6pHA==
X-Received: by 2002:a17:902:ef46:b0:153:81f7:7fc2 with SMTP id e6-20020a170902ef4600b0015381f77fc2mr21909910plx.26.1648390319132;
        Sun, 27 Mar 2022 07:11:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:10c3:b0:4fa:d532:5fb9 with SMTP id
 d3-20020a056a0010c300b004fad5325fb9ls4370535pfu.11.gmail; Sun, 27 Mar 2022
 07:11:58 -0700 (PDT)
X-Received: by 2002:a63:1243:0:b0:381:6713:241b with SMTP id 3-20020a631243000000b003816713241bmr6809684pgs.76.1648390318554;
        Sun, 27 Mar 2022 07:11:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648390318; cv=none;
        d=google.com; s=arc-20160816;
        b=PP56GBbLNpCBpdJCETWAJUuOPn93G1tSSrC1pzOxV5udH/vFYewUsBhGq6U+VGASox
         QRoQKezj4wgQeFTnhy+pUYns9tumChRnqVo1tQ0zpPFcgls5Pv9ZiUHeJOtU2pqMQqXN
         PvdCCSaKUGxGzlduMytc18g1gHRu8+rL9UTt1esQ60rx2WUYr58lQOotvS+kOokSnvRP
         Hj3ltmCkbUEed/9dSyGtlTPTYibTCpE2d8NooTcsWvtJ/HDWvig0tIF+FrTdceoCsjos
         5XlewI5d0PphmZNzE3QyV3POQljjJu5JcuV2WT1NdZWn39ktSE1KRDIB3n6inFMVy04s
         Qqqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=tPigUCStZJcg5y0RjwrEpi16bURJvFddLph3Hmveq6w=;
        b=sJ5PKNvro+VI7PyXHRFeKyhnIvR3GNeuGVrJsX1Z2VJmvwybZnEb8UQDzBx6ywleHV
         3ee2UPO7MghzwHl76zLqRIMH3X/+toYrlmBNo+sLeg7G+uCy8mdWvxeePZs/MgTljGp9
         ToE683l4eiEfXbemA9VYYSWOfucSXuWyPKSYXVJwn5zmkhITFWIieTgZLOKT2ikUjqwe
         eUs4oGm+zATwO7b7poR7NaRSxIKA6OGC0GKJq6z2GX1qdQIm+DyvfuRpewwifcAdwIMv
         m1iu2NTNz63FBAfbnrpvoY0INkkflLLKql3yt/Qqu6LgIZvoBr+t87zJROGiCmBw5rhg
         7p+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ubmw8SI1;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id z9-20020a170903018900b0015431c64dfdsi579552plg.2.2022.03.27.07.11.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 07:11:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id F1E6C61023
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:11:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 643A0C34100
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:11:57 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 520D1C05FCE; Sun, 27 Mar 2022 14:11:57 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212211] KASAN: check report_enabled() for invalid-free
Date: Sun, 27 Mar 2022 14:11:57 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-212211-199747-QV6SfNbii6@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212211-199747@https.bugzilla.kernel.org/>
References: <bug-212211-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ubmw8SI1;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212211

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Resolved with [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c068664c97c7cffa9df706e247046aa5c796efc9

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212211-199747-QV6SfNbii6%40https.bugzilla.kernel.org/.
