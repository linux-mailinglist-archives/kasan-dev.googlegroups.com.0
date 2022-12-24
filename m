Return-Path: <kasan-dev+bncBAABB5N2TGOQMGQE2J33U4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 85E70655800
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Dec 2022 03:01:26 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id l44-20020a0568302b2c00b006782da3829esf3415351otv.16
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Dec 2022 18:01:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671847285; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vh+0EbHAx8j/D8mGYqxEooiiRcj2k/gaZ2pFLataTzhMj1l7vWlJUqyx1DEWrJDcwW
         DXxEDqY/MI82odi0GqeR3x7vSdfyPwRXLPHCqbL2QB1Du4WlnP6EshSJnAalUsLNkMCw
         hJIAoAnvI5E/Mck7NqC7xD9PcskTbMwbe0o+5k3jrw+TY9nRY1zfHifgpr0lkxNW7+BZ
         OUXHz7ZDOwIAUOApLTEuZAIEfrv8IJupldasI2na4Q0NY5Z+V7CvFEhovFbWtTl2+RHg
         pnCNH2OofXxhwC7mZToQOnDBY55iySb2P8+/sBlDnwAPq80LbEApnWtlxUrxntl/qxfc
         hrFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=6ml12ipjwiVWcW3GYxHoo4RN19hE+2iCxrOpqq/5/Go=;
        b=j+VwgXp75ESAQWkBuNybzIuOHxQa45t5SvCpJCi03hL3SD66Y1U2T7F7L9P9MSlQat
         0KjIZDxsxJ05NtXXfSl789KrgBVyXFe6cOAzMRhjUrWCwX5fRS/V7OG3RNTuksSQubO4
         8kDyfZ25l0PPl8grTFbn/aJDajaw8baJbPgUnpImwJBSKuBBGpDyW0AJV110Zd1J/6tF
         PtEDfbGM12ZAFsBBL8E/s0vu+DubDXaJXI87GH6mrWKT8GpYJ5byO4BkMxm6VdkLvhZp
         UbAGpg1ytwHIF/VLYFMzyxOjnYX91KC3mm8+C70WZHZAIUA8sSl5Yad5jk6RI/L5+KBs
         fjcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=J8jur566;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6ml12ipjwiVWcW3GYxHoo4RN19hE+2iCxrOpqq/5/Go=;
        b=S3GInq49xReuWBBBY1o1NSML1Cz55XVgrrlPbVxaTuznCaD67EaJWfbIDPZcXgHe1A
         m7TeFQ7R0fY+4T0k0A3441IAHFYb1ClGxGkOnUBc2mUaOLU4hQq6pys0Pc7LwcE2ajiz
         LGL3ycnY8LbV8d5C41CzZJTO9/JIlDsawAUenImLHcPovVzgr4BcntwVAj3gCwgVBr0U
         NgN8WAvGeKIOs6z4uwM3C5wzsTI4YJ6mD96lWzgQSr14IUNIPpFf+HHIn4cAQUIFg28N
         t2diuhtdOPDTCB+xE59dsSZLhXVgPspJ4hTzcMXNmaJjRQ6oiMH42aIlWnt0nYWR19Pa
         CdjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6ml12ipjwiVWcW3GYxHoo4RN19hE+2iCxrOpqq/5/Go=;
        b=S+6+VGmXiTSsUjwTPAS5k/080ZsksVRddd2TDt5OTTNxqOdXmvuVZKtlWfgptmbk2o
         WojKGdcVo/2biM/Z55WwWvoCHutF59HtJmHcPKb3D2lnNys/sUrA0In1PF87w4mgg7F8
         FosAL1MkJaDL9KkAUlqAJUBsFyIlDHJRuD1EmXhaYo0aUNX+k7GOUrOkb/67jYAeqBlK
         55SJNA5QFAYvXjXcebhyTHwwnO1ifOTSeJbxToaLr96xo1Fr4RrABJgE6GubJ4UuuuZH
         +BQRQ6YaIMRmkohv2LSQLBjxYq/2nwLXyoBsKoHAdMvK3TrU8U3Itb+E6LkJOe5xpK5q
         Df8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koDUoBsdXT7VtPt+NWrSKB8zFzAgwOxoBExbxp00ugTZkq+Sb91
	cMuRTbRqMvUpPpN6Qwd3lyw=
X-Google-Smtp-Source: AMrXdXuQ+LnlWgWqZWs3CG1Xh9JCxkDPLqqDyob/3gVXJAx+9taCDUjJ+RL9M/9YKX8HUTR0ruX8Vg==
X-Received: by 2002:a05:6830:1244:b0:672:ff4e:5dd4 with SMTP id s4-20020a056830124400b00672ff4e5dd4mr655950otp.146.1671847285149;
        Fri, 23 Dec 2022 18:01:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4f0b:0:b0:363:19d3:70f7 with SMTP id e11-20020a544f0b000000b0036319d370f7ls1386737oiy.9.-pod-prod-gmail;
 Fri, 23 Dec 2022 18:01:24 -0800 (PST)
X-Received: by 2002:aca:bbc1:0:b0:360:bcf7:c442 with SMTP id l184-20020acabbc1000000b00360bcf7c442mr5458850oif.59.1671847284814;
        Fri, 23 Dec 2022 18:01:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671847284; cv=none;
        d=google.com; s=arc-20160816;
        b=fh/V+s/pp6VfzPDGQrb+YCkvhnnuOSnwrig6k1cPaD7vaOG3kLA/pbHifZdSf6MdIX
         7+BHOikmcPQDZ05Ng0D4m11TLcXfUapG5Mh3xuiL5BuAwKtjExdnt2SGiZ6HM9JYFXcm
         bC20H9jQhAkgyM1ZRb1FZrTymTZeB8juJ0O6Mv6Pxv7F/C9xMozM0If/W9X4fHbdtMax
         3QhUB/kal6P/0JaYVBYZUdRRKURH6Z7gES+Rxdd6DayrQeI9hWVVir6rlDbOe5Kx9lok
         tR7r6DYQJsarMSqBrI+FYCmEqLoM5tHaej9mqopPjV3a6V6nYdO4y3LSImZHqXgb461M
         F+OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=ZwuvNvaZELd0eZtbIbidEhF0kg9hcY6PhXavRnohKwI=;
        b=iuwN5bR7UF4P6nbenq2TCc/9Co+D99RfvOCVPwZ0v2K8zb80Jm+CCXnhIp8tpB6kN5
         MzxmA1QTssp/KZa9IcgyBVLpyzlQz+90wF5/TUidTUpP45GZJgTqBHoTldVAPs6+/JvY
         jykB7KSXW6UkRyPnaVNy6Yf7+pqEvtuUWxJsj5vKaZg+VqGgq7noSo6AoMlOLeMPPMY8
         MSsRl4ykXMW9HZt5b9drtOgpd9RQVsrmMG54JCOW/tG5q/EXOr0IbYKKZ8PHusNSL3xr
         gkArdbyci5XEQN96/WvRCjjQQZrdBA2m7B/gsyyh7FGwWHayRXoTFmoJghKpiK1Hwolb
         OWlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=J8jur566;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 14-20020a9d010e000000b0067054a075b7si489234otu.2.2022.12.23.18.01.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 23 Dec 2022 18:01:24 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 8D83361E5B
	for <kasan-dev@googlegroups.com>; Sat, 24 Dec 2022 02:01:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id F01F8C433EF
	for <kasan-dev@googlegroups.com>; Sat, 24 Dec 2022 02:01:23 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id DB159C43143; Sat, 24 Dec 2022 02:01:23 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212169] KASAN: consider supporting commandline arguments for
 all modes
Date: Sat, 24 Dec 2022 02:01:23 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: INSUFFICIENT_DATA
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-212169-199747-fNdFIJQ1FT@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212169-199747@https.bugzilla.kernel.org/>
References: <bug-212169-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=J8jur566;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212169

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |INSUFFICIENT_DATA

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
This bug is not actionable until we see use cases for supporting particular
boot parameters in particular KASAN modes. Closing.

FTR: kasan.fault is now supported for all KASAN modes, and kasan.stacktrace is
supported for both tag-based modes.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212169-199747-fNdFIJQ1FT%40https.bugzilla.kernel.org/.
