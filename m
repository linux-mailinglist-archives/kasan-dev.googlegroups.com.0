Return-Path: <kasan-dev+bncBC24VNFHTMIBB5XTTWBAMGQEX4U4BPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F51D33274A
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 14:36:56 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id h17sf10133551ila.12
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 05:36:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615297015; cv=pass;
        d=google.com; s=arc-20160816;
        b=ztBA0p6MX3P6wSjYxmEWAf4MBWRDhzSHMwgd1aOzHRrIkyKnfx/IHgiJzOZMjk19fk
         xKo1CRwrinqgViGgmHcR4/ojFO9DW1p6kriFnTBnETHR8h6lCSUh8VwxXS2F8MxHmURz
         BwCTXsfKRJ+a+stjNqtLOVDQhH41tb+lMgvXm29TQGZmOK/JnPD1JWN1bHOQlWYYmq+P
         qZfR9q5Xmouig1Q4Cs7gDQx8oeDqFEJqxbRj5ZsVJj+Nt4K6UC2eY499LRQFPuFSgRlA
         KwVXKsEjB6fOys/iDDTUsBDJvS3u12QJlkewBEMVvzKgpI1UG5KPe+YzQczdZzX/RrxF
         QVzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=uOTWiYoHbPpTG/5FkLJGNkSC9gpGRg1nM12PT6RM18k=;
        b=qJ7q415760J7w9EAT2yJYZzFUOvVjSaR5YxBXrH599eKXVq15I5ltkR6AaUlAIE/cU
         V5yFiVy8JZZoHSrlANwEyhEzfEvk7vmz5hFSuGMy0pQxuu08ioBvVRHIflC02ubV53U7
         wA0XMPqvcI/BCedwZwc2a2c/OiF5/jDTKg52IGCqaWXnUbi7KKyi/wpjaiehorRd+z4/
         8OXX8k2GwKSgUfbCo5qY6CDhKcZuxRoc5onsXUDdOnNWc5dKlX5BgtpfPZ1uVKmd+KvC
         0dGJGL+IygltMItjqwEJv/godn7o7CrUcus76ccH/ukf7cW+PZO3WVYb4d1vjWzaF8OO
         DM6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XlDk3nFy;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uOTWiYoHbPpTG/5FkLJGNkSC9gpGRg1nM12PT6RM18k=;
        b=OmqXeGydL4ujqCBox7OAcLOzRhyZ8MTlp7JnDRDiXNa4D8Vn6T1l5uvos6NMtbp5qG
         OAXX+PGUJZaRNlTXE/Ov6V7XbC7OrYZ21be9EXS89bX9LbzdyxPwlG+dyPMQwfbZeL2o
         +aNcLnXNmoHW9mmb0HDzJrZOLcgTl7RSlWpDzQICUVHOe+enxs5+vDFYbSRRRfvX8ypf
         rq6ZIs1uIw3AFNOfeh7S2+cCUSLD5mJ21317otdh1tIkg+4q1gB3O+B4aBrm4TFNCJL5
         QbFoaMoQgm8RosXg3BR+bMF6micvm3zdp19IpJmpSfp6DJ5tttLaCw795/N76E5embw6
         madQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uOTWiYoHbPpTG/5FkLJGNkSC9gpGRg1nM12PT6RM18k=;
        b=cHjHSScwLtmi5NbPOp2EEXGhQrbWGH6QiKsKudsQZSKkdbpFEfhqBQXyG5pVNTdDe0
         JmNhIWshfqw8cnjcoTCjPfJ2j+M/gNBTsJUqN0P91XLPucSDRAcNgtt/34qYX0NOalxM
         AzJTb5Sy22c5rWiaj52qJFjDNmma1ZhcbwcCuEEvyzCnk494TMJGDlX16H811lI/XzlT
         ysgzq3d8GKPtxwYpy5VdHd4KCzz1KeYJ4p8C3hHP5+yP4htPLy8mdeR/bxMl6vZVTXa4
         0OBKZxG+13tSfVjQIHibd4l+koeV/ON1yo49jXjHPvCjjbtVmaY7+DtZzFN8EcRC+0YV
         dvvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533OgS/1uzbNk0hLXB/3ohYkZ1QyudpOefaHq6vCck7v0fal3o5f
	LBzp23XP9uDVUKmhPVRPPvY=
X-Google-Smtp-Source: ABdhPJyC8BpNCj8vBfaZFAjUz8cZB4O+K/PQLUp6vhF2Fy418c323NzH80O9QlM+bGmEf87r0cOzHQ==
X-Received: by 2002:a05:6e02:1564:: with SMTP id k4mr24407309ilu.282.1615297015039;
        Tue, 09 Mar 2021 05:36:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a85:: with SMTP id k5ls5210809ilv.6.gmail; Tue, 09
 Mar 2021 05:36:54 -0800 (PST)
X-Received: by 2002:a92:2c04:: with SMTP id t4mr25046015ile.99.1615297014712;
        Tue, 09 Mar 2021 05:36:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615297014; cv=none;
        d=google.com; s=arc-20160816;
        b=kFpZ079gynTJqmnA1uV9nVrbhxGxZ2qfWn8HZE3T0U2EQen3EdTTTcHeLFtJkIk/aS
         uvU6yTZbc+vUrjpntE41f8PgVOL2Ry7VN/26UnKsf7YwEicKJaHF3sV0bhOszPC8HN8H
         tchhZX/mDqNVDPusjmdq0NoFL74qQ3QEP2J8UFX4kVExBvSWZmkYSzrnx+P+F3vmnoCR
         PR/0gdNPCcV7G4HVtyw3FjwqQAnUSO3mjirl2bK165kxHCaT0HFKkgl3ubA6u0RGHEpR
         dgoE7Z7DpduD8CMvsu8FhzmSvVU5sxLU4WDYVkV1VWzbeFjWeFdff8pw3PnO2j1ZPsj5
         ZHbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=+sfGu9skHfeaSiOp8T27fq+nj2lk5hS5EG03cdCjxKw=;
        b=jn/V14ddtaTBTME288AvdVnCVFsUvMFIhiCMe3EUtBgST7N0+2lfXnLemgOKWoUuLj
         GAZb9Lcf7EY354nEI677y5mezog4B4NZWqhR4h3H/S/7D6IN0F92X800nMshe9464Jeg
         1DN8CBp+Fus3KQTCyhsLdYy8v8uBtOJUw60xjZvwKrETl5SlZbKaclt04JiCMxqPxxqA
         p2PoMxg2ey5n0gSgpfso8+xwkkp1zS6UdbDthWHVyW4ktgi4MZ1Ms12gVI30BwbB/6bV
         D60IcYZO09j4a6Ym6EilKskUV4+JgwQHKglpuJX+Q/dRo1B7lQ0jLFpeml4K+L1lnEZc
         0LhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XlDk3nFy;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o7si590936ilu.0.2021.03.09.05.36.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 05:36:54 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id C15BD650ED
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 13:36:53 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id BC270652DC; Tue,  9 Mar 2021 13:36:53 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212163] New: KASAN (hw-tags): support KMEMLEAK
Date: Tue, 09 Mar 2021 13:36:53 +0000
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
Message-ID: <bug-212163-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XlDk3nFy;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212163

            Bug ID: 212163
           Summary: KASAN (hw-tags): support KMEMLEAK
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

The change needed for KMEMLEAK support is marking metadata accesses in
mm/kmemleak.c with kasan_reset_tag().

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212163-199747%40https.bugzilla.kernel.org/.
