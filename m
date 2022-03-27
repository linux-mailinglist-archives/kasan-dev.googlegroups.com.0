Return-Path: <kasan-dev+bncBAABBCXWQGJAMGQE2NGVUZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CE9C34E884C
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 16:56:11 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id f5-20020a6be805000000b00649b9faf257sf8818078ioh.9
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:56:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648392970; cv=pass;
        d=google.com; s=arc-20160816;
        b=hj2ASYiYgH9IoZ+80b6O1lx119LnQGE2Og31jRMkW1iXAjv29gWyEFoPMISa86GLXT
         bKAuL+GKAn9PzrsfjxzFAEZDqiA68CynzVuhk4JZQbOBphVZ0BCwPPjUtBtHPyGNeUQN
         8GLoW7nUzNp3T6NI9j/lSXZX6JnVWaJC8heIFzsP2ObsPlBoeLxnOKRzO/uHekLSmA5t
         4E6eoOmUaQ9MLbQbmuKbeEJaAtQfq9vnJV5xh6Rw7qnGiP84qbluSty5w7vSuBk5yVam
         omehyCzocFkBZTqsMDftcNkr0s9/9DGuUeQa0ekR8neWVycRUCLJIVYZ5xgNwZ7zSP1O
         jmtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=FP4+Upb8EQCHI5c5h446JQTV+O4MErAnY53HU4NGbD8=;
        b=QZlDW1b9dmzvnbJF2/4re1mjLShQE2Pt/vJJ5CSJyp54CjntgP6OgjS7iANnhHvbBE
         FojlWgUI1MD9wf1BqSOdEXjhUEE0Q8ECZ2pHL5UwbS1kE7qIZTYsQBTxoPsaZYejuUK+
         v/M1nzNz1z84UtmdZzN7IHvEldyQn6116zBr+hZocGGR0Oy+IRsRyl8CPrLk4chNaLwl
         2tRhp4OCWWhpjTRVJAqJqEJIMM5uw0ZdZJzzK/ovDTPCkxfgMMGRK0XicSreH5eMduYV
         NBYCh3QhS6xKR5Bx+7rPrZdbfzEnhT0R8KIog30XYKL6kWsoq66z1uc30tTjzhoIy9Ey
         mVzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Bm+UuWp+;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FP4+Upb8EQCHI5c5h446JQTV+O4MErAnY53HU4NGbD8=;
        b=ArlZF2JHFvu68m0K7aCPpOw/9fa3JB/58/FNX/1cUDsGovB87coEhiGo67PArx7ZGO
         HnoXuwA7hfwjNg4qfUGC6WpRA+isxDc7S/NRoch/aWb98lWDNGWU/xKhzIDJYnvCOozv
         S3n+qoVoUB/wTLh1Wb7Q3XeHuQm8a1+2pHjmZ2KTofJ2THFhEbUjtXqZvi5tokM//gsR
         aKPJphrNOPu7HQhX4Q7+JZEN3qny+m6EBH1QAiXDIw1FZFyuSar7e6eKF5VH9ifZz3I0
         gVn4spjTxvJ/s9HXkUQ5mJndYf1PV02MMg6+Wom6d4RnyWfjbxRxZnX3mD9o//R7Q2Iz
         vhHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FP4+Upb8EQCHI5c5h446JQTV+O4MErAnY53HU4NGbD8=;
        b=Qlf3/hjeT0H4D3ts5FWu1UNiPAsSjKJZ9adcZKjholULArGlrmoT72CqBrzRadHrnO
         hYL4A1RJ8C1UgJpOVFHoXhhprDlyku0LY1BsmySx+3+EfHmq0LMpIF0odUsEgqcCf8X0
         0EXpAqYYtGbaJnml4uf2pQObmM2yTTp5gUWs/wA3HeOTZbw8xoxp1lBG34cQeSwH70py
         D4teD0ym8V5G9OpeMpqa9Y7852iBPjVti7/NeDDC0MlxhQ2+eVQSnvutl6ZxqbxqMrtM
         r2Gf75qXTck8Ic91QEYjLdV4WtQ/+tE12yCwhbgU33OuANZxcoyN6Th7e9bes+KW4QJO
         0T7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Bea/h/FOYG9OsLRdHnIZ2GJvr0doQ0LLFJzX/kZIgDgPxzKZb
	y5a8U7l0ZY4CfsWV5lhjXM8=
X-Google-Smtp-Source: ABdhPJyw+c/zGY1Kv1hEKoAT+bP4id7gwqWI7N/AIk84vIx0E4m8iwkUoogofAu6gaFzhqp2GLCeyw==
X-Received: by 2002:a92:d9c7:0:b0:2c8:7bf5:b85e with SMTP id n7-20020a92d9c7000000b002c87bf5b85emr3496719ilq.275.1648392970859;
        Sun, 27 Mar 2022 07:56:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1bcd:b0:2c9:bac2:b140 with SMTP id
 x13-20020a056e021bcd00b002c9bac2b140ls34720ilv.6.gmail; Sun, 27 Mar 2022
 07:56:10 -0700 (PDT)
X-Received: by 2002:a92:7106:0:b0:2c6:3167:ce83 with SMTP id m6-20020a927106000000b002c63167ce83mr3809768ilc.138.1648392970439;
        Sun, 27 Mar 2022 07:56:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648392970; cv=none;
        d=google.com; s=arc-20160816;
        b=QT0VlYyAXRgrOjz7FR+iaEcYfMZvOzPG1BmFPhBRBh2qcQ1Vv1550HzZ3oIQTGKwi1
         ttn2WOylgp7Ta+JoR5fpEUIthoIlTvz6nShMq4F5K/+KhI8eswXNhu8wPIQ20SrLuHkH
         3RBf/iDISP/OWTulLiKNWm+Sjm1rkEa3snKddq6URt3ewOG1XxpZwt+6eXnAQQYFFmbu
         4XOIP0fPSvNRXBoFgC47ff/rv9kcmgPER5kzkwJ+svt6btJt374IA7Mfp6Oco2/2DLie
         /PV8JpiK/C1extLKwZKhhjg6HfmCZ2b3CgHPgaw9k9+90Fle30yQAYC932LWnX7csiWE
         mzAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=B29EbVT5F7xeH7IJPcemI1vw4raUezNt2aodTEVK9Iw=;
        b=dY1fcQ+5BoVc1z7v5Paepd2Krsq6FEcBpUI0kY1X4MlEivynywRETfIncuhnbrNIjv
         cqoouu5kk2JBRj3xV3GrfbyJKqVD405xeCPaCOdvttinlFjp7wCJ+q+ZqP8O/tS3zcvR
         wK2JJHiMfzKMhfgD5k+Zd2t9OdoAHGQwSVN2W4EcE44vttUF3dL2o0qiM6D3Y+6Oj00I
         Uz/PWyD/7LvAzOyNpMd78rbUqzY3E6Zyj65XV8uZGWEFl+nuUgUTeQbUGXhQk6INF2lm
         uAUZdsDpedCYfkOc2U/2zdG40dx/RBSkng7u9mtLXpK2ybOjv9mHhk+annKZEoY1rl3J
         Id2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Bm+UuWp+;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id y11-20020a05663824cb00b00319f24825f4si897161jat.0.2022.03.27.07.56.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 07:56:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id DA89E61028
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:56:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 4B65DC340EE
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:56:09 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 338F1C05FD4; Sun, 27 Mar 2022 14:56:09 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215757] New: KASAN (sw-tags): investigate disabling recovery
 compiler option
Date: Sun, 27 Mar 2022 14:56:08 +0000
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
Message-ID: <bug-215757-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Bm+UuWp+;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=215757

            Bug ID: 215757
           Summary: KASAN (sw-tags): investigate disabling recovery
                    compiler option
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

For SW_TAGS KASAN, the instrumentation allows to control whether we can proceed
after a crash was detected. This is done by passing the -recover flag to the
compiler. Disabling recovery allows to generate more compact code.

Unfortunately, disabling recovery does not work for the kernel as is. KASAN
reporting is disabled in some contexts (for example when the allocator accesses
slab object metadata; this is controlled by current->kasan_depth). All these
accesses are detected by the tool, even though the reports for them are not
printed. If the recovery is disabled, KASAN will not be able to proceed after
the first of such accesses.

Investigate the possibility of disabling recovery, or update the comment at [1]
to say that it is impossible to disable.

[1]
https://elixir.bootlin.com/linux/v5.17/source/arch/arm64/kernel/traps.c#L1032

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215757-199747%40https.bugzilla.kernel.org/.
