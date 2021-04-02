Return-Path: <kasan-dev+bncBC24VNFHTMIBBG7CTSBQMGQEHJZN4BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 88ED9352BA1
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Apr 2021 16:58:36 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id 50sf4060713otv.6
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Apr 2021 07:58:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617375515; cv=pass;
        d=google.com; s=arc-20160816;
        b=FbUb/UkelR8bBcqQ3pgPNuAfRL1HEEs3WGRr5gvzaOj91sHPgBVAJot4n3+ovk4Wuw
         +q1aBArQDIX75AKH6ff6juPCucQb0b7EBDBNzN3Ajug4V2emchAIOs1MP/jA/KuBucHc
         aZJJ1P6xiMfhxBTmhLYTMGbwdOzrkG8nwUNW+EmEAjS3XffK2QAQmW5z78CvxCemtMhd
         Ml/kXlWNJm6iL2A3yXI0je+IYDn4l4DR6G5FdAxKySsJ5DfZ2zQGknP4sQGutohkx3M9
         dEZC4LO/HlzgeR3K+MDLouhDV4Ydo8DHg4EB6+FNXj1qMh1Zyhtmb0+Z8H8vwvVxCJNp
         GkAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Ehn9JPiC0D0zGiXzAW9woL8EzoCvxXbGkowTHUmKZxI=;
        b=g122noRTN+1HAVRrAIzREdeJHl2JVoTNz8tCNfBRqcSCK+LGri47ofO+t1R0G67Xwh
         sOBjANiWe+aLtKu8e8RNXR4hAO0alBVBhfY/10eDrTgw54bv+kZcVgzHVqtt+j2+0Djc
         HW8GIo4FipkziOQLUgYW96hMufWJI2nlGL+2CS3YFqjPIDkhC8dztOFECqNgQR2ysckH
         TJZeU6rJUPCaNqnmeavR4d4kEV/1FiF18Kb3zoKh8XoxtiBwg6wInYLo/4tvZLB6KJ80
         /OXiAShzd/AYB70tL7H6S2MRJRKoxLQp0GDRfPHNXvT3g2S7ZkjQsrH8sHpFeRy/h8kh
         lqqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nXln2k3l;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ehn9JPiC0D0zGiXzAW9woL8EzoCvxXbGkowTHUmKZxI=;
        b=dShvL4wiAqXqia9aZVEQtlWbp5MFSAbaN1ZhFYK2AJiv13xjbqw4hgDLGReThH6H77
         qAWv8mQIMgSPXI/4kG2adVkPgMq7ZjN1Sr2qGXchxNeVhwtppAf4203NclimUjmdijKe
         YbwJAdxF0iBmg5Pvhm4k019cz+3CcueGJ1SSaJw+AXi0q0BFEY7K9TC7b8aTYgvmw2jj
         dcGlYkejMO+oGeeAdNzh8ek7UZ+Agn3IPTk7VfqYTDceWqzS4t/Q00Pu4Pw2YkqQRDpH
         v8nd9DZF6j1ziwhD7DE6NXxj4GNm0sG+KT34dc2cWf3jClQFUoxflAr0HEJ7im8FORWv
         8Myw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Ehn9JPiC0D0zGiXzAW9woL8EzoCvxXbGkowTHUmKZxI=;
        b=OzDnqttVIw1Er+PXQvHmRBkNRYej9OFQ9nwZ3R9dBcCevlUpr2G/6l4kFwt6IXC4IX
         d7TO9tyHMNMo0d8+QxsYJeWHn4J+ixDktWnh8p2iZLZOq6+3Q2tzo4LEnLsXwQDQnQFO
         cjlIJ6furvN0Y0n1lqVcxiErK9/4iPmYfAXoJ2AWlygDcVV3+5fhSHKJ4ecYkEEp42u9
         0bhnS8kJkAt3YZKJZUliaW9PdRK0UQsGtDx5KgLqQkuJv/KtBWsN5A4Yi0r0CdR+6ASG
         W3JzYNXKpfXHrZAKg28KoHqB1kQpuKE6tI6hcaEXhUBEeYfu9aZ3p0k3HoWqP1coGL4G
         y92A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530UWoubUKp8kgllT68OUftHwEWbNTU+NwSQHUU3G6VppIcf9I9F
	bSTBCaXj7Nc8ND3NoDGMu6M=
X-Google-Smtp-Source: ABdhPJwP17Hjvlb/mefHyur7MIQeOlzZ4X1Rst3RksJ+ZL/6BBlpTzKpOW00RxZQDM4FOdFgXn2cow==
X-Received: by 2002:a9d:6a8a:: with SMTP id l10mr11304546otq.107.1617375515444;
        Fri, 02 Apr 2021 07:58:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:65cf:: with SMTP id z15ls2165526oth.10.gmail; Fri, 02
 Apr 2021 07:58:35 -0700 (PDT)
X-Received: by 2002:a9d:6249:: with SMTP id i9mr11494275otk.166.1617375515118;
        Fri, 02 Apr 2021 07:58:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617375515; cv=none;
        d=google.com; s=arc-20160816;
        b=AewqU9Gpvm1xwMYMzBbKN0wsb2LxGwc98P2bZkkfVYkmOC/vpItLLckKGaiX5ykz0Y
         dhP1mIaKgrT0vfEJRHw0cwd7ycOUFdX+Vy6VAsBa5Yl4cfEOtqHzTQ3TQKf9or3eBiud
         c2267JAQE8i/q5gTxNMuutyiq3zuw8OB18/NOHjzBPEU7pbMLweYJ5j25AggEkw5R0/M
         rqVkSYa4/ZJouAl5oEwIhr6cIKaR6vIRyHgte1f6xbDoX4tTsWF3rE5/1cTe4z+PCrjk
         3CLOeDkB+amB5xJcdH46eqD2XYbanm/mr7Zf14L+5IU2ZASo7HgXgjyQ0PUp2GeynJ5x
         GDoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=UCF2pPS5jnLfc5SLrQCP3pxB4xT/4B0ArkXGYuPxe4E=;
        b=SmWUAI6Biv55NLO4ZVY02t8aLeUKPtqDMM57Uy1ZV9Sz9sMtvkqNmkt0k3+C+sfT62
         A46Qp8pgaEy4GiQsojNegQxbRkWE7NasX+0QDXagCjVo6GtCMZieUIRGYxBIhDjMxPo3
         ROl0MMeCe+kEMbaVWFl6Jyvk9vXw7mK/9R3b2dBRtNW6NMyZwdBQAqT2nbkUesiglFOy
         fGTbq8GJgu5FYI0UlQ8TN+gZsaDJ2o9V5m//joGiKmRlnevdbOrzNTCvI5JQEt1oBfZQ
         +sVvRh6UQwTMtOLSPsbD21tG8KTHx6YOTbLJOwOj5orAeN12dXiG28vv4X2bG5gFppta
         O14w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nXln2k3l;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w4si467471oiv.4.2021.04.02.07.58.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 02 Apr 2021 07:58:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 4BFAE6112F
	for <kasan-dev@googlegroups.com>; Fri,  2 Apr 2021 14:58:34 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 430B861027; Fri,  2 Apr 2021 14:58:34 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212513] KASAN (hw-tags): annotate no_sanitize_address functions
Date: Fri, 02 Apr 2021 14:58:34 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: pcc@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-212513-199747-jCJ1bChzLR@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212513-199747@https.bugzilla.kernel.org/>
References: <bug-212513-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nXln2k3l;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212513

--- Comment #4 from Peter Collingbourne (pcc@google.com) ---
One complication though is that it would need alternatives in order to support
hardware without MTE, which implies that the compiler would need to know about
alternatives.

Perhaps we could use __attribute__((cleanup)) to run the code on exit instead
of an attribute. It looks like this attribute is allowed in the kernel, e.g.
it's used in include/linux/kcsan-checks.h.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212513-199747-jCJ1bChzLR%40https.bugzilla.kernel.org/.
