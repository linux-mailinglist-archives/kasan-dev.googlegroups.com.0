Return-Path: <kasan-dev+bncBC24VNFHTMIBBVM5QL4AKGQEKSVJE7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id F2DD921465C
	for <lists+kasan-dev@lfdr.de>; Sat,  4 Jul 2020 16:14:46 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id bk16sf22275620qvb.11
        for <lists+kasan-dev@lfdr.de>; Sat, 04 Jul 2020 07:14:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593872085; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dw8UX25Tqq7+Jx1R/ZEVDvuvuL+5W8n4Zr3vZ3CBexbmlKlrAkeV4VDFriSjamthOj
         keHvJAJEc2nFpXhuF62pmLbRw1vKDF/gn22U2bl+ofBjV+m7R3u545e4f9JALFpHg/Kb
         ft3aqs6DfybadrHPDVPR0EQIHAqkHioO/ECQrPRFCx4grDNX+iCztSB5ZyJtNkbZed4l
         P21mT2xUXxbxDgrSzFOTBza5vDzRh2uFtXh6djD95VsmOa8ePQC/XDl39nnrOKiWo6AK
         QOKk0gmpkbW0v1jMgyqUsxCwJzCF+Zfpd83RuxubxgFWypTDz+/DYi5CWZ2lUKCHjoEq
         Locg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=DnokxO7uD09qFHsV/abFtom+wVwG9+Pe6MTsx43pqf8=;
        b=HP+c3LJu3hiBTaMerB20z7cigEQ9FjjxeLdFl9WD8CaGSdeYNzqXUFdUmmjEb4UqCC
         Xv7w08X5qhsdZmvx9/ipHNsJc/PFdW/OINvBN4ubuzSuIDXOmBV0T5pr4HVWnEfOXflj
         XanWaMgcm2LHY3jSuDQu0UHpZBAZg34IoiaUizlqYb4iTW8ychOkNq8isAHxqByiCh5Z
         sNmYe3ltgkog6+H+YL2zekmMMCtxS6KdDPsyqazpvNbNM9ZiTco9or3ACMw7NzE82XP8
         A3x3k2Ejqar/+iRh9YOVxD9arlVJL5V4lys7VMspWAyE9bEXq77NkykY6ZdIJoZsHGWa
         Vgcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=xml2=ap=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xmL2=AP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DnokxO7uD09qFHsV/abFtom+wVwG9+Pe6MTsx43pqf8=;
        b=j4cIdN4C5L5cprFzojl0zQFZhQoakSPWXWuZ0h86CO2WWWewu9S8PF8uhszd9CKzRx
         SR1+7wY0gfSc6Q4G2FORtJ1xeSAqvmdah2e1h1pG4bzvKsQ7KDQve0x+42MC13/QB/WX
         DcGhsMGu3+xqQibqe8iPzOFT6cfkvl1xbx92Uf/sYJGxHrd8TyydpAXRpHQ0f11cS61X
         Sw+V0FOtr3k0pP4xUccNFMRhVk+Wa2ueipsu+CGGYP3fiBw5LMT/h7qogiXRrFuVJ5bx
         lTqZadASUakPZA3vYgfnxHD+fTUZTlOwhe6dB9l8qQ6o3dzxsc18d/mWIsOhO1hAwpVw
         60XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DnokxO7uD09qFHsV/abFtom+wVwG9+Pe6MTsx43pqf8=;
        b=Zuhu0CMjIgIiemIj8OJHtngdxuLulp5n1I17eXDY8HKCgJjAbULOYQSnhaDFLAur9N
         tqjqo71SIQcMg8NUKGK5zMdKxb+nzMobpXvzdaFaCbFyXatEIpUowCLsRqXVXVvas0Rm
         aEP9xNebGbcvx8iVyQ5r1+45j2aow8js05WnHZbx2nA4Hvki/JtT6tG6gUCfM19RcOF5
         qSW+lHKr53N6nQlv75IJp8NWmXEqDe8J8s9Sc+FtW+0Ag0PymBqjjdoHI63zq+c7T2nI
         Nfn7lKUBKjTZf8EZxrl9S/HuuYJNfZXN6sBjxaTbssi2NIM5IrpB1mnqCE/swVy9CXRp
         nbSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531SZzF2sYazOiaTPfveTWGTefg0B902i5DsVs+ZyRS3Q3hMDgfu
	hYYUPCrJ9IavLyiVt5C7KEM=
X-Google-Smtp-Source: ABdhPJxWNo7b2RohM8aUi5C0SRbVUeFyLzRX73rCvMwI9g/9Kj6meHbxJ8h3iq1pfJkzfU7Kt/Bs2A==
X-Received: by 2002:a05:620a:144d:: with SMTP id i13mr25853025qkl.323.1593872085412;
        Sat, 04 Jul 2020 07:14:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:38f:: with SMTP id 137ls5667647qkd.2.gmail; Sat, 04 Jul
 2020 07:14:45 -0700 (PDT)
X-Received: by 2002:a05:620a:2150:: with SMTP id m16mr26189208qkm.500.1593872084939;
        Sat, 04 Jul 2020 07:14:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593872084; cv=none;
        d=google.com; s=arc-20160816;
        b=EKBy8A2XFDEqucpT71HlNCzpYaZb7LJAWdkz8XS017EdRBgwM0jSem9NwMNsllFPMQ
         6/E9ySaVwZIhi9pMGP9uPLVtrVkM9CkHZhs1It1It7D059N+SyIDVI8LeSZ4l7ml+JL/
         MKs4RWuu5LhxGkpLEyBGYabidTqVuTKEGH2Hts2TtJr/Yu7dmw0ywZPcaKPD0Qg2W3mO
         tydQHljRBH175IXGPp2jKIirkLtoT/Rijbm77TGrn3nv0fcoPreWFSpQWmPlVrjKBpZt
         N5PxjhUraWeYs8HtuwTuIwlB8XKZaD3XVbMqd9+/2NuHj95XLysGlkwrb0oy+PPH5GUd
         bFWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=bdWnf0VTRwKFu+BV58FXv3FeRiQZ37tGAOHLVAVIjjk=;
        b=TQUN0+THbjcUNi+8XAIhW1gQp1isXwfBeulylD43mXCJvJ3vhovFdl83+/ZE4ylsut
         UrspYynnMgjBtIXJlWR+W9jYh96AjlgTuYHXlv/oilyJWVHETBgJFhub2tICAwtbVlCP
         zXpZWhccUDL1AQIkAp75AC0PWhsJSR44kEmOVVsvl3szIfItE7+WwI7kzXNqB/fbZ5cv
         uSmKh9Pi5Ezw3dDZno3E9UqEd2kkhb1cE6XPIolTegFl+3YSkGRJZefFhtTIX/TUfqo6
         QKowlPzsC34HBDMGd4h/S3fgd1XL1SGdE7BjjWpjLbPQ8wLoWyxHO8dRgzYIWQNEQreD
         UwIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=xml2=ap=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xmL2=AP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f2si894747qkk.3.2020.07.04.07.14.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 04 Jul 2020 07:14:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xml2=ap=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198441] KASAN: need tests that check reports
Date: Sat, 04 Jul 2020 14:14:43 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198441-199747-KvBCHRuT1T@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198441-199747@https.bugzilla.kernel.org/>
References: <bug-198441-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=xml2=ap=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=xmL2=AP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=198441

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
"KUnit-KASAN Integration" patchset [1] (not merged yet) addresses checking
whether KASAN is expected to detect a bug for each test.

[1] https://lore.kernel.org/patchwork/project/lkml/list/?series=447332

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198441-199747-KvBCHRuT1T%40https.bugzilla.kernel.org/.
