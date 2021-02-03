Return-Path: <kasan-dev+bncBC24VNFHTMIBBFUH5KAAMGQEKXKOC2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FF3C30D81B
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 12:05:59 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id h192sf14201187ybg.23
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 03:05:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612350358; cv=pass;
        d=google.com; s=arc-20160816;
        b=J2JbBKgLPcVleaBngoPJ7UEysRcWpLH6V2uaS5hp3vA+Y2g0wq2BRJMX37Q3nJxbv8
         bpaAjGMXF13YrtdmCZk1stAGF/CISfy3fLFOCecyjXdeFRzYHrhcy/2+y/+T9ne8MRRd
         hXDUqqJTcd00dwYvYCZBp9SN6qHEO+PZyjZFI0Dny++4CgZWqJjupQn7zjB5P9wLdfCH
         0TpYDMQHobOfEaEpZfiaGAunBAYZ10c72V33gbXgahZOcGo9UDpI/69D6Vr56PBckwwi
         fwz4wuZdJN3puLTUGpzIOUIxEoDQFZEvZzO8V6z7qoAzajtVK7i9B1ow1WbzwPrJj3Zw
         D7Nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=mijAfqUU012Zl5HQ4mi9Z4lHlMxak6juY0OmsyFq+QY=;
        b=bTlmNT+WBjE03ctRDVugOXZbOoLKVJdxvXHX4oihdj98m/AscfEU2yh/f8AUYkhaaX
         /GvI/JhFs9KNK86PeRhTSgDe6aIivqiBg+DsuwhHzeKqG9U0HHbHMa96/RCJWrRJrqjO
         zv7yGV9PZdTASVuavGAJQ8R3tvtHtkhoDpxs4glOtkH8ov4zZrhUR1Iytzx+KDtmyN1L
         c1ib1Q3K3onpoTtcBZXHOVd4pGlQoUCg3G3eyASQQ4NXQ02bBWRSke/vKFRa/nu0CEGT
         g4UMoThBBr7v5nZtT/OhoLqpGPNMcGuGiEdSQ2d3z0PhFNhzA//vM+wbzUZS2penk9N9
         mHbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Kw/i4Phi";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mijAfqUU012Zl5HQ4mi9Z4lHlMxak6juY0OmsyFq+QY=;
        b=oDNMU7OQokjofQ5NTkY40CkRIPMd1AItMB9+grpmqcbmGOv9pFIQFuyj3iACFUyiLY
         4fippUEesaU6lHo2H4sVKglSGu2+Ha3+3rhjqNJ2JqAs6+A3jyshROK+GBW3gp8XzKY3
         3Go09/9oVsnMtSfLpHE5S7OvxOF/zRVJQFlk5UiwmtdyxUvVQtTYvd2LSBMWXK6F9Cha
         fKEuo7CBm2g++EGXwmgVOZCOQngyM8uHFbrfB1ByW/7pVO7dWnqQo9JEagz1KBS7yKZb
         kSJ+LXMEd6SX6CUvt4mH0s1vKxmrj5x9KZWH30mzdgjh2rMgEaLs1pjRxYjgs3ptuP3I
         y6eg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mijAfqUU012Zl5HQ4mi9Z4lHlMxak6juY0OmsyFq+QY=;
        b=shkbNaDiaiZ0OgU3UpR30XKqkhByH3RCG8ECUk8tszuD/n9ZOZqrQ7Z2YpsRfRR6RG
         Smuf8Ka4HlUF457t0/TAjYAjF1M7PnZ9Z9W8R5S0f6c5yMcr3raXOEenQVmqdY3jcqZP
         T8qJCYQyn3I0+FYUxlLVXHZlouq1Tns7KA6aT2qfUBrcINWwINi8NADVyBGsSC3/Dq03
         74y60xZeF0AYok9iRGSaRKB6T9FOI1YlO3ndo4VTGOVuQiTPQ1KiM0uLdYwTv/nbbtCX
         bfXt6zxpzCBhggxaiY5HsgxEuf71EQqQ7+NOSNdBnYiToLBahIFPScdWKwFpNb3vkrYM
         XOdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532vP48FkJ9m+jg2Q98tl/7cERoQcJZxCK9JHMaNMhq4bYYVAe5q
	Ll0hAc3lnPaJqz1hml5dFTU=
X-Google-Smtp-Source: ABdhPJxC71jDYjpYuLClGOuEmX7aakbhZQGcR3xrY8ZDCXk70q4zjjVMakRREUwyOHOEaEoFwZcz7g==
X-Received: by 2002:a25:542:: with SMTP id 63mr3727586ybf.204.1612350358210;
        Wed, 03 Feb 2021 03:05:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8b88:: with SMTP id j8ls897874ybl.3.gmail; Wed, 03 Feb
 2021 03:05:57 -0800 (PST)
X-Received: by 2002:a25:ab61:: with SMTP id u88mr2096551ybi.143.1612350357819;
        Wed, 03 Feb 2021 03:05:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612350357; cv=none;
        d=google.com; s=arc-20160816;
        b=saGw3DzGECgh/KeV9J6jdNKcMTjwVFFttKg7Rm2xzp5Ir/aAqLvGCXvUfCihaXuuaN
         IDZYIGY69R5ZEr25sJRbnC7erWHf+48A/HyO1Wwij99LAEQ07Kt9jSFfsLwtBk4jrhL6
         CuPowx6gBcNMTPJA1//Z91tcEq0it0fsLZk6goyBVwKsGakUImyR1Pzhnhkb/d8CPWu6
         QZSFQ8p7t/jLU0eXL8ImAv9aq//qSrb4km9v2LTyLF/xDHYCBHoB0hHrocfZ/slFjXxr
         DRLWgIMiOXFDOybNKugF8oQmu74JX5asD2IXBqhv16odNPsje2P4COgmqreRqB/T/4gl
         HK+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Chh3s7b0sC4sUTd5+ElLyJntZruXFvFVKJZF5VToyHg=;
        b=vspWK2mcioU+z/2kvMYtMUKK0Rq1ct3WfB+OZq5At/ZhD0gtMrSbyiEAnOtAvpyzJd
         o8+QaJYJbO+XnrDvZ/J0Js+BU88vJhvk/7AeH80bfPL1K5lJD/es7iXsPS76bZXbdWwU
         ZfscH/WLaE0T1XOl4YZWXpSYJvQjWkTtgWmJVEGj72Kuhs+Ha3sjw1hMGMBUxL51uDVU
         fIA5HWBffV54XB7e3HEYVt2nbJ5bTTnaB9ldmxHL62gTfP50PDsr9xj/9OKxv0qaxnoo
         mn+XZvMHHuURwCkaMCByE4kWydmsZSYN6uQhdxsnpbhXV0BXWAcO/vZdKNeiouO4Vzfx
         55BA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Kw/i4Phi";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o71si73034ybc.3.2021.02.03.03.05.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Feb 2021 03:05:57 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 9522764F65
	for <kasan-dev@googlegroups.com>; Wed,  3 Feb 2021 11:05:56 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 83CBB65332; Wed,  3 Feb 2021 11:05:56 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210221] KASAN: turn CONFIG_KASAN_STACK into bool
Date: Wed, 03 Feb 2021 11:05:56 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-210221-199747-QGE0o5UKJX@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210221-199747@https.bugzilla.kernel.org/>
References: <bug-210221-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Kw/i4Phi";       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=210221

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #3 from Dmitry Vyukov (dvyukov@google.com) ---
"kasan: remove redundant config option" is now in linux-next.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210221-199747-QGE0o5UKJX%40https.bugzilla.kernel.org/.
