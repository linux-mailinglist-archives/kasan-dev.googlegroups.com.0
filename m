Return-Path: <kasan-dev+bncBC24VNFHTMIBBA4IZP6QKGQE7V7SQCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 940952B4F2E
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 19:25:09 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id q5sf12236531pgt.0
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 10:25:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605551108; cv=pass;
        d=google.com; s=arc-20160816;
        b=jf4OjKx5r7/X6AdORictsqViSYdgNrmxAKxD2ZgbIDOYAzmMH2e7UUSv8HH47avjqh
         Do5wJ+/trqzWKQL04mbrxBIjIBk1lG6yAlaCp5pipdKWNCYZs5Sp03Ao+z+uJSmRQZfO
         kqfLcwc5xQYtqi/L92YtpY7SyIJtWlYgUvv5N7Ol48iZZl3Xy529wOTFXIC0boCDQTqE
         QTvy1BDwBJyRwZoF8mo7MpE43gC0Cjk15E1f3TNJFeZ6yrSqgrJ+37JDPLtpVvtk/x98
         PNbPwqOuRExXrUBXPqczyWRa5roBW/H004hDzdSiCS1IWxD7K2HnwOlDuDF5oR8aRAUp
         pEjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=87+2ttP6+HECHqXkbb8NaWXZzb4ICjFl4tpGvgvMA2Y=;
        b=ziR73Zo4kkc0qpfS1fU2mHOCMnnXD2GjHsZ88JgDkDzHgu/g6AmJ7qjmyuCPVelWFQ
         bvttGtvEEcIQ41zKuy1uZGT93Xu0rvvHyjzuMVAqp7tUxcrtI7BztHuC5+yuG7QQc9EJ
         JlhGtdE6GbDKnVVavpErwISArdQH6HeOu7rM65PrFxUi0evs9SvQZjKzg1bBZKDvcL3E
         wQSehbONwCO/i4ohQcLFispYKmPhmPiBStO+3n0I00zMWBjlslEHlQJF7Z0521PQtWoy
         i/oGp/qlQeapjmWnsHzFHSX3P4oWliUm/o6F0WvSAY/eNFZvQX3HgfjudtHvt0SFy1h6
         hUBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=87+2ttP6+HECHqXkbb8NaWXZzb4ICjFl4tpGvgvMA2Y=;
        b=OGkI5/fQxZ/0Ruv4OczEVoTrRzA5MkMS3K11PsQ4/J4XR26A8Z3Qs8NhJYaSk/ag1q
         9XoyKBmK6fBKhwugpwKBeUIoA3hcXSguaBFK8MnK8vQOIW1YgO1YLQolxqlHU4+Qzg8L
         fHCB5VVvxbsedXfJyVDIvbMhuJWo9OnjvILAM+i7pclmMbWzj542LhFn23evvg0tQjb2
         JgxA7xER8LNbzaLqh1OKhM3bIjIvk5tQ98u3YapPF/nwD1RvAr+Dq78EWC2YKAv81GCt
         3T/zhJXrl3KYZwmdiKeKhNygGxkRaBzznpberRmJbAKAdOBwOwKhn0PRjr1Qf6dq/XDD
         WSSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=87+2ttP6+HECHqXkbb8NaWXZzb4ICjFl4tpGvgvMA2Y=;
        b=e0LDC5HSqynoGMYFK+runaZY9T7+M1WVNxATTLK9FThyjo2iIhq7DDlA2ZuvV2eEPx
         tGvFEovrmNWNqRHqJBy3rCRa5Rk9mVNwdjCcwxcdKEhiyeZI6urMYTscfgOWjAzQa3oS
         ETUfi/Hb99eypr7ZxSXZgjiRJryP+KyzynkmK4KOa7ORKbSlM8Xqz6A9Lmgx9FS66xos
         6fDclDyJPTNMf974tVHb6+QIOasMxPAlnM+V+KhUc9ZjY/N21IvuO5GiijOwoYEXP98+
         t7PDeSnfT8CKOVlHSVONmb5biDXOUyfDjIVDmuj/1NIMzTnRQ6p/DoUqZHarfuekm4OS
         OGFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533unCEBgmKVEADR7TSZ0fK1ykFefuCK7ZnAEnk8F47pcfxHkaTf
	fLTwaoY5qkZRfSIPYo87Wi8=
X-Google-Smtp-Source: ABdhPJw8scbr5yZ5XQflsLCBPdPdb12kq1Q/+zgNYF5Sxwp7IK/XsZxKV3wNknfhnHW1W9t/6r7W3Q==
X-Received: by 2002:a17:90a:5309:: with SMTP id x9mr201325pjh.98.1605551108086;
        Mon, 16 Nov 2020 10:25:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c253:: with SMTP id d19ls40365pjx.2.canary-gmail;
 Mon, 16 Nov 2020 10:25:07 -0800 (PST)
X-Received: by 2002:a17:902:8d97:b029:d8:94dd:43ea with SMTP id v23-20020a1709028d97b02900d894dd43eamr14482576plo.43.1605551107586;
        Mon, 16 Nov 2020 10:25:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605551107; cv=none;
        d=google.com; s=arc-20160816;
        b=Y2PuP7NQngjdSDVLQY8lDRybDrkYx7uSvSp0TEeELCRDxXlqrXvccidsLrHQiZfLB2
         w97BITdYaorpeZe8YiIC1cxyjIS7z+Nj6OOizAA+sFDGyvUI30xo2xNLG4w7frRBeO8l
         7u7IsPZGQAVL/efyQwAP9BUlJt+pzT0PCE4h5RVUhDG6ARdyXDgqZWrRkn/2BrSd9JzP
         s4Qqmak+hwObErMsvIjckew2EF1JXzody1ykw+w3ypOEZ0Q2z07VMSD92aiyIEqNsZgH
         q9V62/y8XlZdN9s0FicmY40qDD8jclpS6DREn0dGuj1CjVCNVqeDWcAR+yMkvxMur9e6
         uv3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=VycJYfdxvDrxF7Lp3W5032N08IAQC+YwXqHwZhUZgs8=;
        b=0o23tc133cXzkjGvXokXjLN5EJgvmAwsqxVnYkOCrJW9cd81CPXQlOpZmv6Z8HGf6p
         Pd1cS3ZJTiHgO23yk2pfaRr0EQF6pndBKZkvMUizPvD4aQrGYAp88HWcXFOsqp3mrvWO
         1zrM6qxUw+3dS8yKPOmyOvtqnJvOnr2GbjOYn0SWF+Tgy0o5PKaQL4RmRLgnIABCPyID
         GMjEugKbv7amBANvJHlz5fExJCO/UixH/nhaYqC1Of8MulgkvkxLVvLNp1jwSboqCMCI
         E7PfTszLoQOUWBzK3WiNRQvfHA19rTi5Ihb3KyC27wsKbgaOayNrL9alGRNW/+c4E5RF
         g99Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g4si12571pju.0.2020.11.16.10.25.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Nov 2020 10:25:07 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203491] KASAN: double unpoisoning in kmalloc()
Date: Mon, 16 Nov 2020 18:25:06 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: REOPENED
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-203491-199747-RhqApDU37B@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203491-199747@https.bugzilla.kernel.org/>
References: <bug-203491-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=203491

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|RESOLVED                    |REOPENED
         Resolution|CODE_FIX                    |---

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
This was only fixed for SLAB, not for SLUB.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203491-199747-RhqApDU37B%40https.bugzilla.kernel.org/.
