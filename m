Return-Path: <kasan-dev+bncBAABBX5WSWNQMGQEAON5X2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E3DC61A010
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Nov 2022 19:35:13 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id s17-20020a2e98d1000000b002771cfb868esf2019462ljj.5
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Nov 2022 11:35:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667586912; cv=pass;
        d=google.com; s=arc-20160816;
        b=z+uZ3GrbjIlkO8gYZb937gVxLW4vPO1nwO6hiKr9ggeHiRek9xVdyHUlVCwZk/PFle
         q2V4jna7rrWr5kPmfAaeN2JbinWhnalh6av8nUfylVlEuMTmdsg9tWiKatAcaaaPUyjl
         eZqGXCK8gYFjaGV6fMRaxmVr9T6W8PmxwafrMu2alNAfPIc5O5+BRUaPuYaw8M+dIlJD
         P1/Q2xNFprmnvu0kb39HFCJ0V8n4zZuGm0k+tIvlgtxFkdm37S7FrknoXjK42c8Sr9wY
         8D18zdi7Y5F5ZDMQPOyGDvuQm2U+QQAo4bBEYMXpfoRJMaNe8NQ6W3EkgLHawkaiCfyu
         pyaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=zIdvSIGotaSbFkq5qUHCip2ewshe7cxWSMLbkIAkHlQ=;
        b=lg9c7zMc6vRVcbqTMC5+9NmSZgvaTHRV7+LgthWwKo3fAVy5a1UurzGQSLlDNOiuMN
         elQDkfplz8VXF3SlNND/AvpWoo6xFdj8T2Dqshw2Mdfdo6nNHKX2lknVxqSEah0N6rmk
         AlBBIn65S0n2Dl0kjJ/U1zo+2SUAnT1Wh+y8eeEMJOt6Brs3v0UCrKmf/VM6A3fgDmAe
         KFyA9WfFcazeP4tBhshSu1+HP1IwORGUOmzxv9wSeOlYwrb1+L+sjaw0AvQBqJBRGyck
         igdrg8yfZ/ee2jXmu0P0f9/+S2Zvt+RrPpG3C/etn0bLbw3yfA2l/Yf21EE/4q9z9ehn
         ed9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XR7ORxcF;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zIdvSIGotaSbFkq5qUHCip2ewshe7cxWSMLbkIAkHlQ=;
        b=AFOZZOQvNllSqfM3GXctJb/GWJ/kAGGfib0Qm64MVh19MXFnwTYbUx3f8asqPtCjb9
         5ch9MByQqnjeDpx4BsmtdyJveFFpcrIELN3PPCQwbfEEhVCr+tDV7YDOVZFIBrKi78hT
         wDtCBhQxf2/ETDLwOaUU90F/UydardNm3GCmrlgxYLT7b1RFJNmf0ACwtdVw05d31nJ7
         qNyRVVlSBtYfGW//W1Ck79Ea0HWrPON9rc89MsQ4uzxyow7U9wdmLpCnQfZCSk2o6YLb
         IooBG9ewtu5y/v+tP3tqjpz+Jb1gpNQEi6Bk0tAiZxEp1MuzzmHQRTHD3qM7lHoqrmA3
         Xr6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zIdvSIGotaSbFkq5qUHCip2ewshe7cxWSMLbkIAkHlQ=;
        b=iAT2enhC9S73ETaRly3gPoQkIg3EbFKybtroc206bZudDyJcr+AQ/J2n9h6nViATiA
         RJ1hhAhqQ7ephdIi48h+2T9/hl48dUmMwwGE9Z6sYizI5WztoNfxyVT8TfXBveKU27OJ
         ooE9CTEj9hO0TKYOEoEZXX2QAPWbXjG5p73CryjhimQ9SHR5/TNwOr035usy6v1yJ1Zw
         /LiCyrtwHlfAlhlRmb5H3Lr034T66eKaS01KaMCn0OKVwDbYUpAcihalYG6/W0Y1KoEU
         M/Z7cqqugWrs+CGE9qdXdpwK01bcC35Tx417noejkJXYcvh14n2Sc4cjazAtQGiHzKmX
         2ZCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3nPVBsCnKdJY5k41lSbJ0tlhjaMvy0IlBci7RbY8UEw3RqtpaV
	nK8ScJYQethrXh34P62gQsI=
X-Google-Smtp-Source: AMsMyM50TjVoCAOB7DkOj4QCxH15XxP7cw+CdcosYMtjEuId1Jj2rWozF/T0xdoTW6qhgYvGgvU1Nw==
X-Received: by 2002:a05:6512:3684:b0:4b0:4ef:dc39 with SMTP id d4-20020a056512368400b004b004efdc39mr13503732lfs.91.1667586912164;
        Fri, 04 Nov 2022 11:35:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:23a1:b0:26e:76e9:3567 with SMTP id
 bk33-20020a05651c23a100b0026e76e93567ls1210785ljb.11.-pod-prod-gmail; Fri, 04
 Nov 2022 11:35:11 -0700 (PDT)
X-Received: by 2002:a2e:9d5a:0:b0:25e:2c67:edaf with SMTP id y26-20020a2e9d5a000000b0025e2c67edafmr13827441ljj.437.1667586911253;
        Fri, 04 Nov 2022 11:35:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667586911; cv=none;
        d=google.com; s=arc-20160816;
        b=0j61LPwsGPMOxQ7k3fD/t3KpsB6WvdLiphDa+03y9VGn3I6Z5yt/SQiD+gm6vNltZT
         /d57unLeZcbNp9Faq2IRuHTdSKbrf93+/KB+vJgnoV/I0ORtDUMq2cKkspySWuiRaesy
         tfMCfbZl/zkuxg6xmDr/CZZzANqwJqsZedjgQHJgwmw09k7SL3sHSRJkpMdoOLp6Y/ji
         QFHyim99Pl5XAAYsw+jmP+a5ISLeUnlcwrW5Gta5dpNF2akyGyKZzhxkR7qbFwW/BX1J
         KhT9nEUcLiK4zGe97GXMkOB/fBou08/pSzdJ1bFABTiN+/TlVvXYsfldGqyo3trvJF8q
         kQKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=MnEuZ2UWyxzlQWhc4Bl5F3HzvMLnVNyuA4KT7Pngn6U=;
        b=AblGzM7DdbJdrPyJktsqNpFfNdRZBnztBuCZwwsW5V7NnVeCme1+GMFjAXcGLEyaLW
         149XP6ZLpAmKJd89Vfen0BI2nXpsQwzXj3Zwv8Q2ryE0jAuL4KgB+8PFLen565XykotC
         1ozbeO0FGQ/BNxivClzfMOrkOobm9IRyVgrT50g9ZN8K3IOnjZjmjPRTQhdRNKf5/a0y
         BJOCs74zm95i/bt5K8PhZTAj5qoumjEUs86ourxyBjXOBc46fRj1IuxCO9XfWW+qFoIv
         vXOSyZD7P5CwNrqy/iDwzg5VTta//L51YLcWJi1Qn1y3AlxFmVBeLwKrvwUC7ce08tow
         /9OQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XR7ORxcF;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id u9-20020a05651220c900b00499b6fc70ecsi141168lfr.1.2022.11.04.11.35.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 04 Nov 2022 11:35:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 63C1AB82EFF
	for <kasan-dev@googlegroups.com>; Fri,  4 Nov 2022 18:35:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 1540CC433C1
	for <kasan-dev@googlegroups.com>; Fri,  4 Nov 2022 18:35:08 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id E7650C433E4; Fri,  4 Nov 2022 18:35:07 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216663] New: fault injection: add GFP_NOFAULT
Date: Fri, 04 Nov 2022 18:35:07 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-216663-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XR7ORxcF;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=216663

            Bug ID: 216663
           Summary: fault injection: add GFP_NOFAULT
           Product: Memory Management
           Version: 2.5
    Kernel Version: ALL
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Slab fault injection also fails allocations in other debugging features
(KMEMLEAK, stackdepot, reftracker, etc). It's not very useful, makes fail-nth
do pointless iterations and may reduce effectiveness of other debugging tools
(e.g. some allocations won't be tracked for memory leaks, since the KMEMLEAK
allocation failed).

There is GFP_NOFAIL and it does prevent fault injects. But it also means "try
to allocated as hard as you can" and never return NULL from kmalloc() (I think
it will loop infinitely and GFP_NOFAIL may not handle errors at all).

While for debugging tools we just want to prevent fault injection, but
otherwise don't need the memory allocator to try as hard as it can and can
handle failures.
We could add GFP_NOFAULT that would just disable fault injection.

However, on the second thought, perhaps the existing GFP_NOFAIL is really the
right thing for debugging tools. KASAN/KMEMLEAK/reftracker are heavy debugging
tools that do relatively small allocations. So perhaps it's not bad for them to
loop infinitely until the allocation succeeds, rather than degrade quality of
debug checking.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216663-199747%40https.bugzilla.kernel.org/.
