Return-Path: <kasan-dev+bncBC24VNFHTMIBBWPOU76AKGQEIAZVA2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id BB30F290C60
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 21:41:14 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id g10sf1930814plq.16
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 12:41:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602877273; cv=pass;
        d=google.com; s=arc-20160816;
        b=bZhpyklmREozCcWLyvwG4I+YtYsJRCpQUlSChAUvsNJO22FGMXxZdRhAvWHpq8ZefQ
         ggEvwAHmMKi2xEfjUYvtyUAEst4tdUs0N2JNDurvlWpahmGDGgxPDLpUIam7hP2LbZ74
         bv/fuUcAN+MsCabhinek2uYk/DASfxEXh5Yb0wRLRQeK7ABL2toWrxPpc99r9pADm/fq
         do2uqv2MP3wwek/GMLabuqNJtvFfRY8IWCcEV5GO0rn/ywXs9uAQAAK9aKv1lCimWO2f
         lEC4V12Zt7TaBbxIbvCFZklsuaVDiAV3rxNsgE9gLezzV321T7WSCap2rRpgp8mWPLLO
         YRPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=M1z7IldJU0Kb8ih2CTTBefGgnrbhii5XVQVrTWbpy4Y=;
        b=tBjFY56LgO3kCumlKMsAFzWQQw6PSfApSxu0Lbf2l0Iv/L4E7Gn2Y8JZLEZdgmJrWh
         6uJjPZLvi4DGPXwb/MXxrzn/uiF80NFiejNo5YthNmzKCKM6DADcXkmPhI+iNW727spQ
         j7KnyBS6lqm1bmbgXRNn1g7xF9gHVexHLTInxSvs3ZtEsvz+yDvyCbknuQ4vFQE1bsNN
         jFFsHWdtzc1+ra89262OIharK31nWSdIAJrRNvGxmzdsSbo7GwV5RhrP4AgkmHteeodG
         sBJ3K2aQKzO+ghWidqOEZKqjXXiK8OTvDI8EgxW7eEN0nvxwKO8EY/o8spSX/Z3p+y0g
         lBog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zKmU=DX=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=M1z7IldJU0Kb8ih2CTTBefGgnrbhii5XVQVrTWbpy4Y=;
        b=LswuUN0DWdRRvhY5egJs4oevjQwKL2ZgFkfKNg261hl2aun40X7aT13/Ie7yjyI3sk
         9ONWoEWPmrq7gvae+2M5iiUU1vlQyjpMX95/DJg8NQqDS0SSxuBJ/4l41+jSdmWCcEAB
         ZuQ03YxyhJ7Zmk3ZvHPZYg7h24hWANJ+Ys7OxMEZbDG++Qv4xHXfHEYJjNDj64P15EBo
         yXh3vgM9NOvdobxauO5Cwx18bNlCZfufnlJptuXf3ZIJ/mkOGZZSw3VeuUozh1UzDNBd
         RZs6d5F3zbnFtsqZ/CX/GMacpRLegBCDPu1/XG3XlXH9QU9kDNJ+sra6fHA0GLbHt+wt
         jsPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=M1z7IldJU0Kb8ih2CTTBefGgnrbhii5XVQVrTWbpy4Y=;
        b=G5uqdmcashBJW11qT1jymNKt/k+MevkaCD2twbMRMjQsr936T4Tkqbg4eQQcz3zZNG
         5OpbYT5FWjPrDHt1LZWza6GybCGPSRgE8sOnTDS0O4861qcxl+x8DQh1b3Xin0gU2K3o
         yVKfF7zKHkojm8viTga92sxulHelcZPtROR6TgjTCGtSHjyijxJhpn5il+sygy4JK2nR
         4aDTqHZLBxU6PZ/95fxGZFigTKwgQyTA2xV0mccrHAGUqHiMlr68lJ1Nl6lUipfMRSbg
         uSxVHIcwBVuRI4RT3pQ6r6YSWpNWTPUnQfMYkM5vE4z/TOpi9FDpmSkMfEjLK+F0bUuJ
         0jPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53042xkZfYPrP4h+tUrWHacBMhKyF3IxC7ztMieQEHIa/y9Wbu89
	mf905laAm5IVF5Lq/W+aHho=
X-Google-Smtp-Source: ABdhPJxr9rzH5a4wPrv+BthQirfBG89uwlR0K3qoRa4EJwT43io2l4TX95NKnOQTiIVVcdUxAhJV6A==
X-Received: by 2002:a17:90a:64ce:: with SMTP id i14mr5479479pjm.97.1602877273506;
        Fri, 16 Oct 2020 12:41:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:16c1:: with SMTP id l1ls1223095pfc.1.gmail; Fri, 16
 Oct 2020 12:41:13 -0700 (PDT)
X-Received: by 2002:a63:2051:: with SMTP id r17mr4429420pgm.191.1602877272955;
        Fri, 16 Oct 2020 12:41:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602877272; cv=none;
        d=google.com; s=arc-20160816;
        b=y2wL6f+KXzO5faEiVrhOB5Mh1jMMWAY/OMT7OcmyL/FDmxVJXjKxPH9ZVAGGIFDsYR
         Bt8yVlDwCITKVMyYA41b/JtPX5PYjZwcvm/dqm5i0R8hD/lBjFlmZPQZHSHLpMyO8ACG
         mOQs04LyJsXs83fFM/70/wbYC1Pu4aBg4CuGD5lwXw2l90nloALcCgJQCE3rV6jIjqkm
         Eh1/wL5YPznHRyjEYYd75B2USS3Fy6P+M+jrwvpCk6d3bsB1xX4SwyaqS8y14yg1TNmP
         u4OZgQhISDW7lIxJZfVoFCy9K72aVr4mLiwtxDMg4FW0qVtt4+hevhqK1eIb351GkiIT
         JR4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=oLtjA4t6XPW73dz9G8Ea9+MBttKpcGd3ooL50KlrF9g=;
        b=W0FMk1rUpIesC/pCuxzsOKwBTi4vIRAuUHdCwj/HTG7ILO8Sq6hz96bp3m+EjPxlzM
         iWnxyYRMkToh/qz7jCKDjH0JWXRllaLY4HdvHAlUz6usTRGwLkBNZQmAXFFb7DN90GHb
         GSVWhlCYgWyEMbLAQYvwPhl9H+JlATIxYMIxKj2X4U9iO28LSkg0KtK9v5A3sM83gpvX
         iT+6dKlbAz25tK1V7a2paskwXNR+gZuhW8MNjjoIfUIoTa+7mh4TzZij9mW32A3riCh5
         lfGjkuvc/c6cecBxv2DcR90CccyHA7PlgWplNum7Pdx8JLa27hw7VRglCgDJu7Bf1zEw
         fXzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zKmU=DX=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id np11si184864pjb.1.2020.10.16.12.41.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 16 Oct 2020 12:41:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203503] KASAN (tags): add 16-byte aligned tests
Date: Fri, 16 Oct 2020 19:41:12 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203503-199747-qINpFBOLFC@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203503-199747@https.bugzilla.kernel.org/>
References: <bug-203503-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zKmU=DX=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203503

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
Actually there also was patch #1.5:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=51dcc81c282dc401dfd8460a7e59546bc1b30e32

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203503-199747-qINpFBOLFC%40https.bugzilla.kernel.org/.
