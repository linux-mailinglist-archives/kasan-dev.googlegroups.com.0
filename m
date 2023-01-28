Return-Path: <kasan-dev+bncBAABBIFH2KPAMGQEHFHNDMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id E564F67F447
	for <lists+kasan-dev@lfdr.de>; Sat, 28 Jan 2023 04:16:49 +0100 (CET)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-509ab88f98fsf66322087b3.10
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jan 2023 19:16:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674875808; cv=pass;
        d=google.com; s=arc-20160816;
        b=oQi2W/Dv39pO9SPGJkGWwUfsMJRHb9/MzI/Xbzg1tqaO+aX7AEw4/F+6NM/FI/4ENR
         uAcrT+S6U2h0DgGallGeQSwKn6zdm6e4SFTFcgiEzIfomcz69yAocA/bfxLxCoriN+i4
         ehPT/uT81qb4JVccHWgSFzoXwNki592c7QmNN12rmdb/3EEkiT+IZA0pJQXy132F3cUI
         ble4GZ+/LwL2+NaOoeE8OfJ59XK0/wAY1dCB3U9EjzJYm7/yNetIQR25u8C1ZoqfWRAI
         IIZO0IaiLqO0kLeDt00DBz4P5yBhwWDrYtYyl8hv5QIghU91+z82QuxRHTuqFnvMjPmT
         OuNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=Wl+1NihOpDyUKCNbgQyl10QCwCuNI0efPbYhAgUVT/s=;
        b=kVOvlp2EKJoutf/NGRZvRbfnUhqsZsx2yjtAwHtpyMcHfwvjSmf5XvQ+KN+u27qLRc
         0LQuRMencas2Ld1lFwsoX2Arx+LOK9EogamQsHshJIi5Y0Gs+8BEs9KaBa15RftEB+E8
         Agi9LEYWg45aNXbDENzlb4ln1/0fNkzQcZYgoJI1A6H/wCt8ua+D/MdvHafxRAGIDa+Z
         UBVKUl5dUmrlEfvIWop4hXKED1iJMkrQ7wIwkKwhsw9ivz2lwOvLgoYFIbSwxmsurfIQ
         ls8p+9SvErEUAJs8JhDhpWuuEQbQeoETNfw9b8VhR8ST5ban3VebajQAjn6GxZYoIKV8
         wQJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NpruOuBu;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Wl+1NihOpDyUKCNbgQyl10QCwCuNI0efPbYhAgUVT/s=;
        b=Si54IpKqc/pGjOIYyaR295kXBBpF0Mf4Vs6E3zv5HtKJtN0zs0GsZ35GJ1oiM6V3mJ
         unaVuhRrCNtrnAGUgnL2di4QhXkhva7NmmPYZkPYKX91mbZJZ5yE8aUFwVXeIf4UjVVk
         H0fkGONcSsWw2+ZA1duTVmXVNzUSMEwaTL7SciM2Zmw3KyHLREkF8sPRdmQskAxOxpjL
         bMQKQ56wpbKvAwss5m8X0fRFP8FDwqcMOErNcT9vmEvi6Ytm9ocW9VtzG4RiJ5d3I2TH
         OGu9rle7DpSPLm7hIhBGIjVLJJFKkqsGHSLv6eENLAk7RKfk+grent8JWO1J6h4tKksQ
         Zb6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Wl+1NihOpDyUKCNbgQyl10QCwCuNI0efPbYhAgUVT/s=;
        b=LI+vjW7JHIgq+9yM7d7QorrTfwBCjMgsSgdNXmGaijkEE9aWtzQpvkG98QaAwcXaeI
         19GIwOPGZ/e0i6+Mtt8bQOb06tqfea56j2oc43hOubh7yOn/MRyxerXAFBQPvEGPhRXd
         PihpIzlOEu6/Q6HkfmUnBVzUMt2jjl+YdoEYSfsHuvqIbVeFB9SjP3ln5Hi1/VyH81F5
         ncF9oGlYHFpbIzRequOrMKVPP9qJ7yBX+B9eqMs7v1qjnvCVDMNivh3RmMd4Jl1iaW6i
         h5UbeE0g0/cOGiJ1n20BkDcPxEkNuyUVPtTOKQBoISilphbDlO0w4CVKMMhOcHfFTNBH
         AGuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqYtM+bvnOvUcIsR2fseDIV4VGL5oWMsbWaTxTeF6zUM1aR19jW
	5lZondRh275bbMkFOlXZbvg=
X-Google-Smtp-Source: AMrXdXsoXo0PAnI7shKVRMZhx6CorQi8YGgVKgu0GeHFeYfzhTZ5c0xsIj7iyarhThd+EFQb5SEWNQ==
X-Received: by 2002:a25:8b11:0:b0:7c3:8ff0:88e7 with SMTP id i17-20020a258b11000000b007c38ff088e7mr6070148ybl.139.1674875808640;
        Fri, 27 Jan 2023 19:16:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:23cc:0:b0:7ba:b53e:630f with SMTP id j195-20020a2523cc000000b007bab53e630fls4458504ybj.9.-pod-prod-gmail;
 Fri, 27 Jan 2023 19:16:48 -0800 (PST)
X-Received: by 2002:a25:bac1:0:b0:741:8085:50ed with SMTP id a1-20020a25bac1000000b00741808550edmr25670306ybk.38.1674875808124;
        Fri, 27 Jan 2023 19:16:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674875808; cv=none;
        d=google.com; s=arc-20160816;
        b=FphCQ7HUJpduMNhitNra79D+K80cAc67/gqJmcwUA9iLKX0tDqi6NPVNNCqKmvjz7q
         PyAKwKj4adTz0PJJgXIbfjgpIVphaRObhBW7Rah8APMHNVyYeBLG633QhHSyDTzLK+O7
         H1Txi+zcaoWsUChSZFjw/BnaQXahYItKBjKsPp3ZmiLSpTuIPxarzNB5a6FbIQL28xW3
         /YvaUWf6ZIrXUYcMZa//30Kfr61zRsyw9pzLH4Ex2K1f2vZ1rgXZM0ZRTlVvp9kJn7un
         gp6QoNFIny4259PaKHTNfbMOaZ2vH/4XTmDN1k+3NGvn7W4M0A2oZ0Zh3oPfnBAArI4/
         VS3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=L/Xg3pvitln0qmRQAfV0QSxvjuGTim7n4RHDOOqFiBc=;
        b=rQyOs9mmDGnELAn6n1wFwUH107s7GEKPpX2M4Fx5KgR8FtCdicL8dHYkpQHAZUhjG8
         RuT6bNPk4VLUCgHToCoOJ0oNly0DYxdQTQsSrrKFp/Tvz94BOV+hgiP5A7mPY57WpLA4
         AT52OoveeRpWHft/09fZYN9Gyu55I4UwX503Ea+PCszKskCv1cL/N5HlYGraWJBiXiPg
         Ekdr2DpAE4mdFj5eftxkmQJ47a67OqARRkNquZRas45GOVKBrpGO9t9GIQhM8Yxp4CUI
         4Bsf6Sgxaiqh87Sx11H8c+HGjElNaIalxqQFIM1aaSe222sXPcHA42LusmVX8G0WPr0E
         RJaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NpruOuBu;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id b204-20020a2534d5000000b007b62d9cf791si528440yba.2.2023.01.27.19.16.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 27 Jan 2023 19:16:48 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id BAC3F61D7C
	for <kasan-dev@googlegroups.com>; Sat, 28 Jan 2023 03:16:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 28D6CC433EF
	for <kasan-dev@googlegroups.com>; Sat, 28 Jan 2023 03:16:47 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 12281C43143; Sat, 28 Jan 2023 03:16:47 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216973] New: stackdepot: do not drop __GFP_NOLOCKDEP
Date: Sat, 28 Jan 2023 03:16:46 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
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
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-216973-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NpruOuBu;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=216973

            Bug ID: 216973
           Summary: stackdepot: do not drop __GFP_NOLOCKDEP
           Product: Memory Management
           Version: 2.5
    Kernel Version: upstream
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

From [1]:

XFS is telling the allocator not to track this allocation with
lockdep, and that is getting passed down through the allocator which
has not passed it to lockdep (correct behaviour!), but then KASAN is
trying to track the allocation and that needs to do a memory
allocation.  __stack_depot_save() is passed the gfp mask from the
allocation context so it has __GFP_NOLOCKDEP right there, but it
does:

        if (unlikely(can_alloc && !smp_load_acquire(&next_slab_inited))) {
                /*
                 * Zero out zone modifiers, as we don't have specific zone
                 * requirements. Keep the flags related to allocation in atomic
                 * contexts and I/O.
                 */
                alloc_flags &= ~GFP_ZONEMASK;
>>>>>>>         alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);
                alloc_flags |= __GFP_NOWARN;
                page = alloc_pages(alloc_flags, STACK_ALLOC_ORDER);

It masks masks out anything other than GFP_ATOMIC and GFP_KERNEL
related flags. This drops __GFP_NOLOCKDEP on the floor, hence
lockdep tracks an allocation in a context we've explicitly said not
to track. Hence lockdep (correctly!) explodes later when the
false positive "lock inode in reclaim context" situation triggers.

This is a KASAN bug. It should not be dropping __GFP_NOLOCKDEP from
the allocation context flags.

[1]
https://lore.kernel.org/linux-xfs/20230119045253.GI360264@dread.disaster.area/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216973-199747%40https.bugzilla.kernel.org/.
