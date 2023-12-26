Return-Path: <kasan-dev+bncBAABBBVTVCWAMGQEMEC5EZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 273D781E301
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Dec 2023 01:08:40 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-67f6f90587asf89744096d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 16:08:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703549319; cv=pass;
        d=google.com; s=arc-20160816;
        b=D9meJ+tiFqUO72vjFwadP2rMyAXDcOgXv2VGI/7a2QCC8FWnh8p9yToeMTL8+Y+N2F
         f/9BqdUXcbdjUdugh8u2qQlsn7wa8/o8FH6r4Q3CpdOgYjW1lI29I/mBUpIZFKtmJCPD
         QGD4O9raMOtbco5vu5u4dgGYu+Ch4kJ2Z5IkbvG18HhosQ67GWMjJHwUwiAfCigt/Efn
         AHUlyCEnY+UjdyK9Qxw9v3eAfMI4LVoHKLoJyaZGAf33+S4wsn4BeYs6XY9ZVuwSlrtE
         U7O/0BbeGtg/E/OkKD7y/0exNVyP9UKHgvjcpwzshiheZ412i93PaSWi4b4NTnFC5jQX
         DZQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=xXzCV6DfwxrYS1tupX8O5aBaNwXDbZ4qsWJf/xH6Vc0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=hu/gRQsPxrSnrLfp1kOXi1FyX9EE7gd+T+zdZFtiLroGfeNgD94BcOI98X0ALTRQhL
         64E6chofzG8u4i9SDPVdoa0G0WDdoYmrQI/89OCs8+ZANCjqfEEEe0oDwwlqZyUgpsoG
         D3OOR8kknr4EA0l7pnaeqh5nXV7L2I0n6+2XeY9LAMhIjCU5T9KGridaOfomtkN+q27s
         JIHDTrQpUCUkCVudH60ST8Nvr8srw/bF9b0IQ0NcGsd8oldZayTBb7MY2GClolqQe4SB
         7iZ66JDa/y4RYiKDTqFhhtP/bWHIMvLfE5G6MRfIvGEoStg6AltU7i4wBKLzAKk+4TbX
         b8zA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ssjRXx60;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703549319; x=1704154119; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xXzCV6DfwxrYS1tupX8O5aBaNwXDbZ4qsWJf/xH6Vc0=;
        b=F8VVdh4LVXdY5lzhljab6YMhO/CfOS47+9g8MO8sCsFA/K6/3EbMd4gPGdfWt6U9Oa
         SrbKHtCmpLYLELx355q8MQ3JkX2Gpf9hSZdp60o905shDWTO/xZmWjVniSpnxnpYNeRU
         Yp+g7eo4X6VD8wJw1CT6XjbtuFDqlf9nMg66pSIbJ6VeAVQVKXAQWY9bFgoRikEv9zK4
         h7A4nEUZWRS8VKP5w761RjDZapRVJ/j8Q94SubHWZXMVzBwmmgnnkcWIxtThBUsicuk4
         UfnuKHW6GznjIvPt7pFBEjzb0qyma82lpVVFwvA7R8lJ4E6qbyC0eYDdF9/o885opLQi
         Z7ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703549319; x=1704154119;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xXzCV6DfwxrYS1tupX8O5aBaNwXDbZ4qsWJf/xH6Vc0=;
        b=Bc7yQep6MqWaqQlEgwqgvYpGfluKiWyepq9aSj4wfCmX5zgJVXuMBYmoxPvGJQhSy/
         s3pXfYxi88RjNKSnqvIc8wXdww6IWdWFJd7MhHcKJynhe83P92oFs76NFgpa+P9quWf+
         0m6R47I4NYweXHXJnAQADfE3znSNC6A0Lk2IjykYh3cXBqDQB/wSuOMfpXTpluRgt3ra
         Dgb8Iqgc3NDFJMPSvKbLa/tMYewC0giykeRbbe60uplUAQ8p1pJLsGdEo233fAh4MstF
         e+CR+yqRZjKs007I2afd9Z4K2j/Qz1APFP23/DEd2QqPpcXx+nAFyhM6bmX2bYDAwDH6
         +Yrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzgwGM+3OHJRGU6HZ7H9d1uU0WUEf86gkzax1HlT1kllVE/igOy
	pWdIcIjFKfBdAqYlgD73Jt4=
X-Google-Smtp-Source: AGHT+IH6lEg48VMHyd7dVQfQsS7yG3MahkFVQgBsLl84rBKwao9yiw71VB3cylz0qeTDWc8F3fCGCA==
X-Received: by 2002:ad4:4ea8:0:b0:67f:953:f3a6 with SMTP id ed8-20020ad44ea8000000b0067f0953f3a6mr11180734qvb.58.1703549318782;
        Mon, 25 Dec 2023 16:08:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:c49:b0:67a:203f:dbc7 with SMTP id
 r9-20020a0562140c4900b0067a203fdbc7ls3105693qvj.1.-pod-prod-06-us; Mon, 25
 Dec 2023 16:08:38 -0800 (PST)
X-Received: by 2002:a05:6122:88f:b0:4b6:ee74:8b4c with SMTP id 15-20020a056122088f00b004b6ee748b4cmr1755144vkf.8.1703549317842;
        Mon, 25 Dec 2023 16:08:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703549317; cv=none;
        d=google.com; s=arc-20160816;
        b=WYpTsNbi2GbiZsu6ISItPux9qqBXP632HEBQJXgg7CFfs2PKHAfy/PEFKCttVBlKy+
         KdPCjDbhrIekGvwqT38Msz66nopW6ShFOb+0bZR+6lQIkeC7gCegZpah6SyXjFWON82k
         PWnivrBMxCcNzibmvdh4QK4CTsHFhxOFV/wzjzkb1KdAmTcJA9Vww4xGnGHwh1bSjIH4
         XxbI4hfYXgrJfd2nMPz10Ijy5YCwjFaUyJPwZrybwfgreqeuzNcrPqhvCAaNaX0uOYJz
         isZ3c4yAR8ldkOVwpmojtMZXM67fAwyeTzdiGBY/PeG/TK6Xgv6Xu0FuDHlgse1K1N6k
         7niw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=kQJtyy8KJQ/Nc58ckQnMJUqYLpP+rfjyGjYpztLzbFc=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=ensu9BSu3Gvexchv+r6RQS1PSFxZ/uqEvxZazGRDPb7vIsKGJiE9oxIrn494fYCgq2
         7yR3Xmft1edx6eDASNKATQvt9YUGZ7rswdWLpmFzoN33NTxxdNet3uh9R7BnjTzT+BYi
         ItRYC7dQyebpM1sjOGkOH/PshGMzaVPvA5qzpNg3pHiH+Di9m44roYM8sf4Q/8QggLpS
         Ra9IFN5sOKzxor3002SMzVX9LhIQrBGHxbuswhMF7Wq88fqYY9tLJJXm0ZutI8q69RSr
         s88fn2iuRUCZhZXPGbLyyIQHYANx4YpCQyAfcQBVASLD5/V2aXALNCb44LMRuJXxLPmz
         mrBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ssjRXx60;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id ay27-20020a056122181b00b004b6cfa3a59esi1252592vkb.5.2023.12.25.16.08.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 16:08:37 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 2AF6C60C7E
	for <kasan-dev@googlegroups.com>; Tue, 26 Dec 2023 00:08:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id C719DC433C8
	for <kasan-dev@googlegroups.com>; Tue, 26 Dec 2023 00:08:36 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id AB0E9C53BCD; Tue, 26 Dec 2023 00:08:36 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218322] New: KASAN (hw-tags): skip page_alloc (un)poisoning of
 large kmalloc allocations
Date: Tue, 26 Dec 2023 00:08:36 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression
Message-ID: <bug-218322-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ssjRXx60;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218322

            Bug ID: 218322
           Summary: KASAN (hw-tags): skip page_alloc (un)poisoning of
                    large kmalloc allocations
           Product: Memory Management
           Version: 2.5
          Hardware: All
                OS: Linux
            Status: NEW
          Severity: normal
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Currently, the tag-based KASAN modes rely on page_alloc to poison/unpoison
large kmalloc allocations.

However, for the Hardware Tag-Based mode, page_alloc might skip unpoisoning due
to sampling, which shouldn't affect large kmalloc allocations.

We should skip (un)poisoning of large kmalloc allocations in page_alloc via
__GFP_SKIP_KASAN and (un)poison them in kasan_kmalloc/kfree_large instead.

Or we could document that the kasan.page_alloc.sample command-line parameter
also affects large kmalloc allocations. This would be, arguably, confusing, as
the parameter does not affect e.g. vmalloc allocations even though they rely on
page_alloc as well.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218322-199747%40https.bugzilla.kernel.org/.
