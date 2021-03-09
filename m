Return-Path: <kasan-dev+bncBC24VNFHTMIBBLUBT2BAMGQEK22CDRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id BCFE133280F
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 15:05:35 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id i12sf6706625plb.13
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 06:05:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615298734; cv=pass;
        d=google.com; s=arc-20160816;
        b=KV7BGaflbbwPOt4SBHEdLK9aqTgOsllTFn6Vx/aYzh6wl9e2vUuuWv2hcCL8nNWOEU
         zS49YTUNl1AJYWpijcuW4OzuYWW1hKD4Cd8nUbiwqsc4ICYArfcwv5Hhd//9st6LObMq
         7TaCXN90OkRT0Dv+lOZT9ZwnKfjEvjJfS7ZP2JYoe9/2gkbINmWjri/zKMv8Bv3TJI/k
         DoLZthuDiNNR21vVznf0XsEe0vxtdw1vIP7oAJTLW4RwXcKvoPeGPH4RbRtxrAW0O528
         aNOvBSPiwaqFkj3BZhHgY3mZ4UkEQA+RGyB2Gd3hwoaKm+t6LfT9nnxhrlo6HyXiPCGZ
         0S9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=az+OPWYjMAqY+OcZzXiBVgK7mSY6gZ8hNWqNElvMYug=;
        b=f2E9NN/41ZME7xbPsKITXi3ytOp7hV+Ukea0ineRXC6iO7SRK3eGkgx0WB4Hm5K/ry
         mx7itqIzb3jlA6oD2v2A/f9YC8JBdhyWD2To7ZVWBc5/f8v+a4RaZClA+spAxPlYhq4G
         tYPvzrijXJZhxEEXlq1Co6wWzr8BRimgWu8HKBZ9chgh+XQv442ZTqCFh7Fla6Gru7RU
         yjlDWYsm/5WS5arT3NRkSlekon4x8Ov4kU4kAPRHv3PornqbTWfGXa9tQEozqsSTzm8U
         E7n+pPiUZ/GUqQqG2cIKtt/K0JSgTMmAe9dHNaBLB1Roh4EWJT/hRWOoufg/h1002Gkw
         wJmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UHnXKptV;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=az+OPWYjMAqY+OcZzXiBVgK7mSY6gZ8hNWqNElvMYug=;
        b=PFBfODad4izxdxaPfdUT5Q0Hgd0I1W8jEzABMpO898ZANKqtUAOWxrWnzliMNgl1Yu
         h85U4IFMFUUPxtgzpjbLSynVV0IjqLoGAwc4NIgXJ6rlSUPnjp8b9+aZPtnKGSnVl5Az
         0Opqe+z++/y+D9b6dH92q9Spx8t27a0CpJu2xK61c5eEdy1iBUAIyamFlpptua01nTlc
         1gL/6ndYK7a2icXUdtNaXszoSt6h8srY9u1SMpyDJMsbVvWAzQloScGdZe3+Bv8wKMLO
         NXFPuhCCas6Y6ouTji+1XKbg0i2lq+S3CXDYhI4b6y3QfMudk5Emrh12fNYSq2ydL6CG
         w72g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=az+OPWYjMAqY+OcZzXiBVgK7mSY6gZ8hNWqNElvMYug=;
        b=R7cXSjqHLNsFd4J8H100A8g2YxavwG5SrnpF6+EFKlTZrzvzcloPmmmae8On8MMbFX
         F9wSWIJ/DAOkUTNfArC5YIEHn4utLW4WAEKTTm0MQd7jhTcQDuhNYa/AQlJq9amzhFG9
         9FD/NZYGJH+sodKl4rQHmhXkTlEzuynZ/NGnMn0fJHEJndz+CtcEklcBasK5Rvc+EmON
         X4AZ5RS+enMZJBjjlddqqB1iKzu09WOYsICalvM7k2uZhI864spdoH/OJq/x5XhZw43h
         pdUvdDFrCsAER+6wjiyTXRsmpRqMbIyLxy2lsclZSNv+Mip1Bym+odw9w28jG6bWP5xe
         79mA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530xMZsQINVvUqyhIt6T2eNGbKfrp1JJcUazuVvdbS5M076zZMNe
	c9xmiwZek95/l5ltmO60OyI=
X-Google-Smtp-Source: ABdhPJxFfGuoKCww9zFSTSC/wctz1kP55MGhqF6WOiVRQbyRnpcMCwWWkA6FZRoUT3yaXoLdrExYKA==
X-Received: by 2002:a62:62c1:0:b029:1ee:7ad:8cb3 with SMTP id w184-20020a6262c10000b02901ee07ad8cb3mr3802115pfb.21.1615298734159;
        Tue, 09 Mar 2021 06:05:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9106:: with SMTP id k6ls2055830pjo.0.canary-gmail;
 Tue, 09 Mar 2021 06:05:33 -0800 (PST)
X-Received: by 2002:a17:90a:cd06:: with SMTP id d6mr4819275pju.138.1615298733524;
        Tue, 09 Mar 2021 06:05:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615298733; cv=none;
        d=google.com; s=arc-20160816;
        b=EUzpYHtTzvrq49VHFCqLJsHThMayCgSGHVuXgrGluKIS7BWyrx472BCsW91ilMjgOz
         zpCOfmbcmD9Q4BHiQ8G0MGditK6G4tJ4l7ZoHVzDRSMWxfxJHR7hb/mbhAvzP/LVYY18
         VDRMlb1U9UoObej5dImoAiAHh35dcjtwQongd3PEHjim59KWgcmkOOMgqsYrnQfBv4aJ
         /KAkmtUMoCnFngTOj6EVgC0zsxxIF6zEspAZLBJPSGk40CibblqldpZ+iwQ12GMtZInt
         qxgHqPCsrtYHQI/UCMs9KD4AVTMmdrBD9ZgfmjXt+d8p9FxCX11NQVZC1YmebjRvusCq
         hCkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=PWqkvF0MvQxB+aRbFmITeTwFx+X1QxyvomsQfT7y4S4=;
        b=sXDmim10JJUTpJOoIeXOxrgtePlMTqcayD3ukDKg2ZwareHZNZ+BNtZxJoZ38H7YYO
         7cbxkeNRR1r3llb1FDS4TB2wW7q1ytF9kd2LTxURtR8IZa/3xK/tKVOMcbos6fNSqc2K
         XNbKPCS+SYpeeVCguhARHyEv6fX9OSqklYIhvpK3JlgCHeMFOKfPiVgKjHFGHQBMZHUU
         ldWQqnA84Z9cWcMAK1cd6Boopm/DkI0VqRwodulAYLm1JvRv9ZANa13yeg6tuThm0Mls
         UDyj36djJuKthLmoZpdVBJwIpjeiUqZCQVCcxjXpZKn7Av43Ugvndz7wAIFtsZSgj0Wq
         SGeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=UHnXKptV;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e8si787584pgl.0.2021.03.09.06.05.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 06:05:33 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 3AB6C650FD
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 14:05:33 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 2C3C965368; Tue,  9 Mar 2021 14:05:33 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212179] New: KASAN (tags): scramble tags for SLAB allocator
Date: Tue, 09 Mar 2021 14:05:32 +0000
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
Message-ID: <bug-212179-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=UHnXKptV;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212179

            Bug ID: 212179
           Summary: KASAN (tags): scramble tags for SLAB allocator
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

Currently, tags for SLAB objects match object indexes in a slab. Using fully
random tags is difficult, as SLAB stores its freelist as an array of object
indexes, instead of a list of pointers.

KASAN could either assign these tags randomly (which means there's a need for
some way to store tags alongside the freelist), or still use object indexes as
a base, but scramble them in some way.

SLUB is unaffected by this.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212179-199747%40https.bugzilla.kernel.org/.
