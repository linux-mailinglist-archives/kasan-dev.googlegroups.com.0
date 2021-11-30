Return-Path: <kasan-dev+bncBC24VNFHTMIBBMPMTKGQMGQELFXEDNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1090B464392
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Dec 2021 00:39:30 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id ay34-20020a05600c1e2200b00337fd217772sf13691046wmb.4
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 15:39:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638315569; cv=pass;
        d=google.com; s=arc-20160816;
        b=jSXX/ds2I5gPwh7SeJrqDpXlz32tRAO2hBWSnpE66nl4mxxutYyVzzVjO9YfHqZa2z
         94LIAeP33Gggb8p4rnpLEpmBqtw6blxu2WIeVVifFUJ+jFPY3pwX6Zv26ditmSFhqjQJ
         PB7bdP61BrMMycFt8Jrttbm6Dm5XyVld35H6GFXJhO/ews1KCKRzmB2Ctchscq1hkqRa
         RPYSLiV2nqTz1n61JS+8occzsidsPYguQfQjCTR8f1qjotQ0bc5iF6hZ9Y+d5bXZi5yM
         NKqsCfzj1alKHT922UayYsEMD8s+ZFtpXKFx6XTv9EFKdm8rIoI+7ljJKZjr7vGIc3Cy
         t6tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=xlfMo5ivSeUagw+Z7QEFqJH5vfEUkxmAZ4nDz0x1cfs=;
        b=KcUOEwTGtGqGXjIfZWY8KrmqNzLCTm9Pui2uD6eitfz62x9hCBxgYtncR6IbuOVK9S
         1+qcBG7tF35zVeDfSPtQEdteauE0aquRu2KR+lRqwmK3mVUzYP1k+UXOh5loDoFl0EOo
         tCP9ooWjf9Nexxg2psAD5v/JdhMnRu1Cp2569ijef2L3vRtRyAMA0sWg/aqfRBRXDsJF
         HyomwGf/835dFGMyxFIAcKWDZ6wL3H+bxbZof4vVLFS/hwjckDvTm/LJGkjXTEjgYZag
         ggak9wLVT0Wa2D6ZwJJzcQwzTLSL9YND00NJwUMHp34J87amEDpRC532s8RKjhQNia7a
         +q+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JdlM88Tg;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xlfMo5ivSeUagw+Z7QEFqJH5vfEUkxmAZ4nDz0x1cfs=;
        b=CRXUBeV8g8SMF7I0QmJMaRl2k+B1GwmmG1+7TtWvTcPsz+A6uXN1ibweiFv2XpwNzn
         JS927/OqUOAObVAkovzsBZ3NOxTiUyFE2hA1opgvNIagZDf6GWOY8J+TsIDtz4rJRQI0
         rHgCwBzBMK0mTvAq3Q+t1H+iyGpmpSUD/AVfOjs6fTiQ9LePiSrwMIEohiDAWgMheYLQ
         P8aWkz5lCdYbJY9eo0MhV+n7euibjtbxE/dLyhYkm13siRmI2fugej3CqP51vEvRnfs5
         XU33M6AVo2mlNRk4zBJBqtDBiIBuUhoolI7pLKSN+Gz7GR8wSVTMBgwWOsT1b9Con7F2
         CALA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xlfMo5ivSeUagw+Z7QEFqJH5vfEUkxmAZ4nDz0x1cfs=;
        b=tBLc6va28k+sMLi1/eIXknA6fSb7ZuZxQQlv/QfdCNLXQEn0bx+5UA/tpR0PBBLCUm
         iSKxUr/C4hjPBOAAvohEffgjpyJNynQP+3PNKRurfXA62K2bkyz4V1oLXmAFHAKK5PSY
         vVNutRsE8nMKAyCoeNCcv5k4l3mLx1BV/rJBMbgypCvdnYxjKEfhWPNMbnKYGQ0v+bRC
         cAI64nQbrEkBlVfiZcpvovhdWH5HR2ROlvrWXejf85FjUG0p0kZu6gX+f3O47RGjtahM
         F9IHP2MZJ6QmDvhvgLK/g0U9Yl0ZodD02CsnccfNh8b6s/tcQKdiblv5YRtRp/Zt1uRE
         U6KQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Ja+ybZ5Y/60SdcuR3+rRGKdfuUg0473Qk/K2csmHSIUj2l2e5
	khhgX2BniHWPsC86c4U2JB8=
X-Google-Smtp-Source: ABdhPJxBIClCDqNErv32tBrqknbiTqKpZvbzXDji/jPoHSTHeQde69xiH0Hsj05PE07KTX3yWsf81A==
X-Received: by 2002:a7b:c844:: with SMTP id c4mr2289082wml.148.1638315569861;
        Tue, 30 Nov 2021 15:39:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:23c8:: with SMTP id j191ls176309wmj.1.gmail; Tue, 30 Nov
 2021 15:39:29 -0800 (PST)
X-Received: by 2002:a1c:a592:: with SMTP id o140mr2366592wme.10.1638315568983;
        Tue, 30 Nov 2021 15:39:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638315568; cv=none;
        d=google.com; s=arc-20160816;
        b=g0iYaDiaol+SQGnwJvlZfKBTcUkYdyqje7eZYYB0fTv/yfDLET3MjYAXBKg47v8IRE
         K8Zjat+RFb2eLxJ25Zobfu3bN4h63pqlwYYrTGE9uIRiaIzVuk/hiGlLQ7gTK8CJ3cam
         tOzMAWN2HEayoiG9ykvhYISa+jwEWblN+aSViHo/ossstZS1dQcJy/zy8SWstc4UYFTn
         GSmwHccyk26ppghJ2K03AKT1VBib63r1QlkIYs8qfRMcHpjhvkDsA8WQ1WHnGbSFS+EA
         R/h9psvzczFQQMyizEVHnT7BMmK/azGteHAvmhiMN7D1RLXaWdJJnHOBKNjVjWYLurgW
         r9zQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=z4izbkBtt0cwddp9l98nW4hYp9pidLxP35zE/aXVRNY=;
        b=kp3amb8Lk5C+t2z1t1Q9RhJZgenKCqeRG+XOBzYolWkn8cOXJu8WvpROoyL32Jjl5x
         ddLFfkTO6OveHfn6evOGpwkis1Y6JSIG3XpHwLkYeMWKmrBcMIFp8AnTRoDvVNK/FaOr
         htZh1gcWydTOqnqv74d4GkyoN3JItpHh2e/BLJMiPYDmyi43LOaMXt7V28CJFVA16owJ
         MbMwIVizMcLgttLi56RqwvZmpgdNxD2jFxvliLQrqo4MihhAj9wzjm4e41mHPYMtxWTl
         1fPuzx+l+StHVog1haFZ1sB1K0jDJ7L0j9rp2ANfoFI5gTuwGsWhs0v7qew8h4SAGrel
         ehpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JdlM88Tg;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id d9si919065wrf.0.2021.11.30.15.39.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Nov 2021 15:39:28 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 8ADB3B81DA6
	for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 23:39:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 3BF1EC53FC7
	for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 23:39:27 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 188EA60F54; Tue, 30 Nov 2021 23:39:27 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214861] UBSAN_OBJECT_SIZE=y results in a non-booting kernel (32
 bit, i686)
Date: Tue, 30 Nov 2021 23:39:26 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: melver@kernel.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-214861-199747-bW58rdLOTG@https.bugzilla.kernel.org/>
In-Reply-To: <bug-214861-199747@https.bugzilla.kernel.org/>
References: <bug-214861-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JdlM88Tg;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=214861

Marco Elver (melver@kernel.org) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |melver@kernel.org

--- Comment #3 from Marco Elver (melver@kernel.org) ---
Thanks for reminding, there was a recent patch that also highlighted that
UBSAN_OBJECT_SIZE is broken:

https://lkml.kernel.org/r/20211111003519.1050494-1-tadeusz.struk@linaro.org

I've done a preliminary analysis of fsanitize=object-size, and it appears that
it's only rarely reporting real UB and could in fact be a compiler-warning
instead. I'm pondering removing UBSAN_OBJECT_SIZE from the kernel. I'll update
this bug with more details if I confirm my suspicions.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214861-199747-bW58rdLOTG%40https.bugzilla.kernel.org/.
