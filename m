Return-Path: <kasan-dev+bncBC24VNFHTMIBBSUB6LWAKGQEGYVFIWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BEF2CF9BE
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2019 14:27:55 +0200 (CEST)
Received: by mail-yw1-xc39.google.com with SMTP id n71sf10875133ywd.16
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2019 05:27:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570537674; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jlb6nt1UN9Wy42fqgm4hbaToSuMry44u4wIIT0P0765za1pP8gQse+hq3sJCozty0I
         N8NTbSjJCkZRyzhO0OdS4tNM/ciMt/p1SLjCzxEwj9t5jI5BUjPelXgllQujlFa8z6XV
         F/TtiyA4GTwx/FRjP7uo4erScW5OIQdl2qFHiTiYj8xqh9CR/qaLomxnxCq08N8CbpAn
         N65QkcJFVD3evyUWg5senVQGgCW43av1axxb4D80Gt70PSLX0Zmz8gQCOx7xtRLNwiVZ
         dTbG/l4ko8prRP2YlIymq9brIQGcZP/2+QnVGQbKYJSZ/IMIpO3+pJegH0Ope/Vapwgp
         oLcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=VuXkhdJ6h+9fs+MRQmpV9RqzCIf3VmhseF0R3dEXvR0=;
        b=D6F8YBIU/p4OSHAo27Z23Fau46HAbR0U92ME6N/gD/Jk/mN2YE2Feqjp76rsza01BO
         3pC6jnW8hnlSM8jT/qqU14A4Y9jFWTk3HiTVqUoxq2evMO1jeHwETK6VzKm6dV7BZ4OB
         zVqjPlSuNalD3oR1pa6RsnVOGWTVLUJ2hoq3J3HMo+xLGP1T3k62hE5KbkNQ+1+4/0wp
         EH/NZqo0M6rQbzw4Bdi4pqza91wb1t5wC2R6znKiAuX0UbPBPq0jAvyi1aDiPXSYurRo
         wbiBwBMCYjWsUp6v6AEwMavgG6aFrkyhx+yGEDeXMFlUvpVNgg4JvOwZkJyUvNO/YSdc
         lDiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=x906=yb=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=x906=YB=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VuXkhdJ6h+9fs+MRQmpV9RqzCIf3VmhseF0R3dEXvR0=;
        b=tkfTBvg+xcBxYXdadIqlcFMyOHZaBT6DfRNTA9bvSF+GZ2Ha2Mi4HZfKi1ryuJImo3
         sDprqGzqdaz3mNpFk/MGh8hD49PYCTVdlJ0bHkpStrUI8QJf4oYz/zpWFRu1yU/qurf3
         HLBjt3AciPMUWDbn6U3CeBCgZWV/ih3UrHBkjunl5rDjVcmMr59Gd516WncNLVMKUac1
         k0u75loEOj2KCoIUzOHrm7LjewBbkRRaqmzbXAucIpL3KbUrxo9A+DZg6i/i7EgoI2Oz
         IPbL6/9X+rnTeJ9Dxv8GeE5bOqbrtMZJZOGHE0QA1WZrmfIkPQbbWT90xGMviG3tiMnQ
         j4/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VuXkhdJ6h+9fs+MRQmpV9RqzCIf3VmhseF0R3dEXvR0=;
        b=HAZx+zuVf4PWobaoZYeo/7hStfHOlPbyyrKZBBEBZfpc8LlX2dSejkf7FipkdLP81x
         0FAXo8yh8fIBQMuxVxErWkAJyMNTJA8aiy1Y9pSxc72gj7KrMYHXJ8G97sBlokdMUo3g
         Xc6wVZAdy5A2obMLk+FnQhgXUsr/bW/s23UoM03AtjnBbh1N9gLoA5eQYQlSA2PWHE60
         /tMa7yj++csGxctTtMoUbqTg6h8ObwIh8/mjrxmSiT5JDLUo6KUTPlGi/QOkIm+O7dS3
         axi+UpfLmGZNZ64Cu/bHS/yf+dq0PUcUIk+fDxuq9ql7QqIXpt/jGmBfW5Ff1yViv5iG
         V9rg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVKL/I1z6Pgp7r3iDEkF9LSuJkvnvyYh8gBymKnNBqXcEsAFdF+
	/d+1NYt8yAsKuwoyo2YLr2c=
X-Google-Smtp-Source: APXvYqzSTzpt9+m2pJUFcuXvKXsVPD0GG1wPhxQ0bwx9L/7A2qV/6tANIlnC8TmiSKBHg+/pwqgNbw==
X-Received: by 2002:a81:4a54:: with SMTP id x81mr23496793ywa.167.1570537674349;
        Tue, 08 Oct 2019 05:27:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:77c4:: with SMTP id s187ls546214ywc.7.gmail; Tue, 08 Oct
 2019 05:27:54 -0700 (PDT)
X-Received: by 2002:a81:1701:: with SMTP id 1mr24857458ywx.482.1570537674009;
        Tue, 08 Oct 2019 05:27:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570537674; cv=none;
        d=google.com; s=arc-20160816;
        b=ZpoXhwlKVS2lVsyEECSYC6hma8SZcsQX75NUeA4XAyKq3UtlXyHqfaV/gnWimZJitY
         3ZAx/1SHyaSnMbeHTjMxWdiRGTGb31m1hKAU+bvyaRynYvc9Qe78d5UzGoSQQTAOqXqv
         x0hOfGNEE1JPDnOl+wIqFaq8hopfJ783D9Jqp7em8/El8llPFwo4JPyNrruuSBvfSHom
         2VhJNg64reQNMXinXIkdVcSB1nrm+XxO1Dlv7g4/ER0+5QU61GkV4p9jHfacPDV9tvcZ
         mGdSpG/YoBLUY2c8fQjvF/2unuTT9MEyXbrdKl1dn7GPAeEemLbUadMcqwqX84VjsB6q
         ik5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=DHFAJ0LYCyZoXO7jdGnWyWhlJjURIqH8LguGEYoq1nc=;
        b=s7T1zoacvoU1BaUV6HfrbDhW7gPxRH+78TFJyrk0M0B43cS3S/QJy106GTHkOxXVti
         /3XsVqlRwhYUzVr7b94DE2Vgmei3gfMSiZcTwyBOaZTNFWnnJsDR2BqFjJcEP6OfbjCP
         RaY0OQMFP+eG1X5ZnUG/qc6i/yXwSBabNbQ8zoF79b0aKwAlTUvTFLMEVbkaudmcQ8EZ
         7Q5tN9AroLDqr/f6BYsUem7zeevDU+PWX5ghSwkSfmp1UODI1pSg6fdxmAZh3MoGusHK
         TFcrBIx82LNEnGGHmrBYwtKw82sVfh74PIolKenuc+9ycX7Z+407eTVaBKd382EvCpaL
         jeiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=x906=yb=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=x906=YB=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j136si490094ybj.3.2019.10.08.05.27.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Oct 2019 05:27:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=x906=yb=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203493] KASAN: add global variables support for clang
Date: Tue, 08 Oct 2019 12:27:52 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203493-199747-9AQwNVbXW5@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203493-199747@https.bugzilla.kernel.org/>
References: <bug-203493-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=x906=yb=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=x906=YB=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203493

--- Comment #2 from Andrey Konovalov (andreyknvl@google.com) ---
Hi Walter,

Yes, this issues is still valid. This definitely requires changes in Clang and
probably in the kernel too.

Thanks!

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203493-199747-9AQwNVbXW5%40https.bugzilla.kernel.org/.
