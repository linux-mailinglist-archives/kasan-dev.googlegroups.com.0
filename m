Return-Path: <kasan-dev+bncBC24VNFHTMIBBZ4EVHUAKGQEOPGJ3DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id D8E094BAD6
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2019 16:10:52 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id 5sf11770175pff.11
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2019 07:10:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560953450; cv=pass;
        d=google.com; s=arc-20160816;
        b=jlTbdXaQPuNkt2e415AAWzk5m54MnmAKemJT6LD1mIuI9TiekxpJyVqIFngejHYDSr
         Et2iMoUJCRxTqa8ktLb1swtHHDvJT9U4oeAH64a78SiTAJUnxuv9NQFySU2beyVh82sp
         zmXSeQYr/N0pZZxgJKdxpLkOi4V3wUrVzSRdocdkklCNv/H1TwUiwEMR2EtuqNOuIMsg
         VFqz+ldHJ9GxKYw9em/xbO4k1VoHmVe3ceVOIUg/u4KV8QFozTdfa0VnLXnelVdTVrfr
         ZoSu/CXc/oKPlN0Tbq/kyibF9J5VHG/F4DdS18AuTiVZBBlSLoN2Iag5K36+IP37hmzP
         G+FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=yWZEXyEXSQeeObUSDXd2RAIypl9HS2CdBd+JMndVqig=;
        b=nQpefg8A3JldbElDa3gqMUwh4d3cOxvDtgyzEZbxVjQDFlQ5Ilwik33twGlmV2dWDp
         xB+3yAr1Msw4ly2f51VkNepg6QpHSxtVHwJS/iSprIgYqAsZwoJ7FKsmm78G3tZng8L5
         +F8GXxMScYvlJKzXkquuAd5nJkzJaZckRidmGUnQ+p/LpcmZw9JqEiG08owabGvFvGJM
         AiuBQnY0MDc0MPjwt9vdSP17oShdSPIhz0mtNHiqCJENGUrsyDPWG8GU+quX2wJKTMFx
         6XMBGDtp8pkc7hyK3xGZgNDKJFs9j6GSdi6SX/hO7wYDj32AQi32sEULfrK2gsIKET1u
         TzNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yWZEXyEXSQeeObUSDXd2RAIypl9HS2CdBd+JMndVqig=;
        b=iBX892K3uk4BszgmvOzwiBw89vTxAyuXlBwX7QZA7UX69xM4wn/B+JDgObiJIKbHAx
         aDj5L0D4QKBic20p4utEDYN9Je74OIwZ7OMvg3bWIuzG3Y5fYWPivlZPvN2zED/SLoAQ
         zKTJywJ6HTO3W8fhlRZnFhtExlQOBiR+cCJRZw8TDeTTpskY/z85WM0Mar5tuLR87nFd
         HY840TDIGA1fzy9DLOFXez9cRRvaBhAoFlzn7suKmCpL3X2NyE2tgBHgphTRykALERH+
         gRAXAcmtDG5GK2UX+7bCbxDhNm4q4GqgGgV7HNWAAeiDksPe+0/xuDxizWJTomtu4xiS
         QjZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yWZEXyEXSQeeObUSDXd2RAIypl9HS2CdBd+JMndVqig=;
        b=coH5ZZX2xOVC7XSOMdvaghzRKrQTVmpDHb2+Y6j1YQGW18LYoaRtKF5sK/Fb+8fITC
         vBdegPvxYDvZSdGc1Y+0DjyEvA1UcLYaPWbB/uf2lEnnHcPQPg/X0Qfxgj6leQpjzqgU
         c1wMS8xkVbkK1kSBROzIjw0QVYAO2BY1LDiBKtBiJjeCJtsYvTppI/bjr/uAqnpmd83N
         +cB3bDxy2abXu1tqECtQyPHS7n3F/h5W1qiOJ/EnZZnkEB6JMBYsfS5P+2gPoFj2lNl7
         V3wzGtqPYktmvfvTeNbrNQ48b1a1Kr1COAnm8IXmkvPufn2/8OEuqR+Pl0+28OwazKEu
         /rZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUzK0f8uOS1ASpFXp8py4A33YVXfKqv6KeHm3Ne6jIPxqvYdOko
	j52Ol0GclnZg/7OSuYBZcn0=
X-Google-Smtp-Source: APXvYqx7WFZ3rX0XW+NI6Ug4iBlUiTs7Cz/EBwsySgl00APzFeeQG/s0hdBXZoFJduG8n4DAiEdrqw==
X-Received: by 2002:a17:902:f301:: with SMTP id gb1mr63445104plb.292.1560953447748;
        Wed, 19 Jun 2019 07:10:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:63c1:: with SMTP id x184ls570892pfb.5.gmail; Wed, 19 Jun
 2019 07:10:47 -0700 (PDT)
X-Received: by 2002:a62:6344:: with SMTP id x65mr21648459pfb.111.1560953447377;
        Wed, 19 Jun 2019 07:10:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560953447; cv=none;
        d=google.com; s=arc-20160816;
        b=It8/MyrkHEDIHnTmM3Py7rM9BQVKvWu0lOXO8dj0Orm+vkYYV4ohelYrJ+X9Hp+f1c
         zQlxmI9zGo36FvITMKXlv3nb9OFihMIBG7Ij7zwjYej43jrV82DgapH9s3cey5pd6KMN
         u9cFwrN0w9mJ0Vijq21jg6EoxSSJ6Qudd35lfy6X27srn7aEbIoz9+VrfGPHdcVq4rZu
         j+1xkipSvBjEWA2w1rvXVlSEATZCZHMBzEjPr42L4lZl5AM9sYGR5eFZtBsdfO7woyDx
         /Whf5EDA5XHGM0UNyOmvgP2pMnvLBKgAh8CetOBMwaXLoix1AQMDnYM8ChwttEsh7XlE
         HXMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=M4FrT1/DmWTVJpJqpdpFVFrpbuym8SIRvI3CGby4a/k=;
        b=1H+EYCIrcn95y7uTArWqOqEmsBV28gqr9BBKHq+fqxPYk21eeW2Y39wWBg/XwiU68K
         FehQuzKq/W46V6m2xIdliW5oLauk8d5Md9PUgrBuCYosbvmyBG+xDy6/JBRIcDdn7OXF
         v8U6636T/t7dMJucCXNoZXTPnsipeQBW2i1gHJcIDuiyIv7HrT3VVMY5vE160rmr+T9h
         drqRIEBwQT1quJ9rfgoch2Ihvz1ohCwsZU0FjZ015SbujnJxxNZd606VrFDGLgwcIKC4
         GpiIxRIbqTD9uJ1mLwVMbWcitJKFLByYqfR8aUZnXnU6xN+5pTNzzMLw6Q+7ROiwgrrt
         uGRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id s125si1043567pgs.1.2019.06.19.07.10.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2019 07:10:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 1BFB02859F
	for <kasan-dev@googlegroups.com>; Wed, 19 Jun 2019 14:10:47 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 0D2FB287DC; Wed, 19 Jun 2019 14:10:47 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198439] KASAN: instrument atomicops/bitops
Date: Wed, 19 Jun 2019 14:10:46 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: elver@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-198439-199747-g6JFvhaGEq@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198439-199747@https.bugzilla.kernel.org/>
References: <bug-198439-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Virus-Scanned: ClamAV using ClamSMTP
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=198439

Marco Elver (elver@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |elver@google.com

--- Comment #3 from Marco Elver (elver@google.com) ---
This can be closed:
http://lkml.kernel.org/r/20190613125950.197667-4-elver@google.com
Landed in MM:
https://ozlabs.org/~akpm/mmots/broken-out/asm-generic-x86-add-bitops-instrumentation-for-kasan.patch

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198439-199747-g6JFvhaGEq%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
