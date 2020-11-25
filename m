Return-Path: <kasan-dev+bncBC24VNFHTMIBBZX47H6QKGQEV2T6VQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F00A2C4486
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 16:55:20 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id x23sf626619vkx.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 07:55:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606319719; cv=pass;
        d=google.com; s=arc-20160816;
        b=z8XB3hrQoClCTrEh0QpP3BNsPiKPOx5JaDe1a7Wu5HU2VC1UnB6pfYcFUIBMVB/9x5
         q4nUVhhOiyeLlfK/pL4rHi+uiIYwuA3ZGJuS6LsyApxa0qxiRMrl2shUEtBTl3E6vtd5
         a+Z+htlq5Orj9RDc1fOcddZOv6aqODuLRv1jXI7OeJtyh8VChN+HCZgsaXKPduVky8Hv
         ly1PwFU5Hxl72Y/GY2eTqjJqcvv0eHXNzUhbabIs6WUmz45NoDKL5Xh6DAqPz+ivuA6r
         4ouq8JI6YOX7BeNG5CjyI1tX/Mr7NQKb14OAnICMoGqLTPkfOqinqpllZaE77X0+mrC7
         aHUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=D1+OA2/fgZpKaWPKlIwAU5IexvPzF6sgNMxtuNtjBNk=;
        b=Wjc97tgSkKOPnsrbPNtBJVOelbmrX+1ApVBvAEr8LR87NTnMnZnEh7UY/mbpUUh5UM
         QP0eTgm/2BsHG0xKuLK77Sih0NK54ElhL2DW6fd0yiACoXkYitBezNVV2dB4jN/4Htjh
         HLN+xsYtf1Pne0u3IJRVpn/mQfL0GZpCfmLx5sbXsqp8n/PCh1EeK2nqozrr4WIOF+34
         pSKu2jka+KDhMbdASnoLRD2LCJ7jUdsMeyWHopH4VyE6GiQOZneyT1U+meg2AMt08jx1
         3MFAH94nS7OKOIE4kXGVC0GKaBd3bTvFUZJNkzSot8XSwS7NYwyO0EKxJKwCvZuSyE51
         azRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=D1+OA2/fgZpKaWPKlIwAU5IexvPzF6sgNMxtuNtjBNk=;
        b=fqjUSjLbmVW8q0pvi+sNTwm3vtV/NkPpdsKQ1sVpgBSuKBatHcOXyqkXSmfvz1K+Tt
         G7hPH68LBIrYN2H+tW1qQPIJFo5zKxoqvKyDO/wJAuDNb/9aB9zwg+pUvhKJv0eFk9RD
         EKUwo+XwK8ZDM5e2vRCe1eiyVOEwhOFC+ap3v9cYLMjIaXvolvoFuGPAG8YBM1WARtsC
         +ywaIW5A9Cx+l7HtTI7nfmH44Rlvqu1yOiSwtXjMAyaWf5Hk9tNI35DDID2XIHLByOG+
         Ltpaz935g8QiYTQdRfhwUxPoB40vsR7b5XTt1CTT2/NSFfNs+OhGx9A4el2NduAgXZgp
         GlRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=D1+OA2/fgZpKaWPKlIwAU5IexvPzF6sgNMxtuNtjBNk=;
        b=MjXNluU9cJBN1fPWEniBULQ1ZZLunllFZ/gOPByc7x70KtX0PnI5NbgAt1M7QCWE+u
         Em/bQx/Baki2wOMnGYySF8NFNdHQSI8nYGakPpSasZ4xxBHKR5fMxhVTIFyEQNDRxk+2
         e8bSHnhbT6L+nDiJU8wTNmGiZfFSoU49y7DONLUwraDtUyyc8neGAtKj6g4OHk+gZj/P
         HbAEyYuLZmfUjG8ljW8yRaQ3vKqHRjeD5YWINC/NTq94P+KeAE57fT7Ipve1TAPsxxHm
         nnYAcupP/+zmLXRMYlznSfl1niCgAkKQuaRglY0xHUeVUo0+dBm3XtlHtZJEtxgEg2zP
         1Oew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533aVvd1V1xbdS40Y8kqeIMrhoTVLcxBGndnKwtIIfrGWo4CufZ5
	H4wD14OtEl1qz2hIPJKvITE=
X-Google-Smtp-Source: ABdhPJzG0p3i+xd2z4UzTw2VIYjRMc0T4uLPGif1e6o58w1UN4hAisZME65ko8tjqE1O2VylvmjJdg==
X-Received: by 2002:a67:6587:: with SMTP id z129mr2565332vsb.29.1606319718955;
        Wed, 25 Nov 2020 07:55:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:1145:: with SMTP id 66ls150350vkr.2.gmail; Wed, 25 Nov
 2020 07:55:18 -0800 (PST)
X-Received: by 2002:a1f:2757:: with SMTP id n84mr2899682vkn.4.1606319718496;
        Wed, 25 Nov 2020 07:55:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606319718; cv=none;
        d=google.com; s=arc-20160816;
        b=caSbG9qKz9spshj5HLCKU702ZUbCrULXcuTm8/oDs84EaWQVK/YUnL76MJruEa2dym
         EsQLzpF56kACiEsxtfSM3uVcV0D9NFLwkI+gkv/8R2MwJtEqLw45PSZ53dYhKmbvUl7W
         tdvMRRJNYVg/iEp3TMAnzlY56v2Vca4qnDHUkCV6KMt10lfPsRbEE0K7DpOLTq96qg83
         q7BJWwUeNjIf8ZH7d+8OoPoPwe0vTAXfBYhSAUcLnVii0pGJp9zQcnv8IyscwvT75bI0
         JKhtncTMdc6rXYWr18RavLO9MYO+A3NQS5yWu4fdY7QujFxomFUk0DAFXafPAWETDzPR
         GHuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=tE6S3sY6uavWcOTkvRrXxccJXyC1jMm2IxefEl2xMYY=;
        b=YUvnsu6EfWsA4JOi3cjPWu0UAY18d6J2vM5Y7KgeVehTb3k3FC030UBQxDDw/Y2Y/6
         Grlw/sjSECvIWdfflDyE/gVpZ/+PE4WgQgfv92g71RsGzkY0U/gFg4toI2ptSnYaXEi7
         VbYKNULY06vJaJ0CGJb6NAUkVeuTNkC9Lozh8dN6r1UQVcl8WrEQ4LeS/za94Y65Xb7b
         AhQrIY7ZIVDk/ES7h9R4kudCYCXKlNPQzQwEFjdClOxNgViFr3gjhD44guIIinvvaJsz
         a7eUqKnEGcy6dugHjHfmDa8BLQIbnmBshHCtxN9aZQkf9BmpiYQXxrP4HhNRwXIfZZ5L
         CYFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f26si138692uao.0.2020.11.25.07.55.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Nov 2020 07:55:18 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210293] potential kernel memory leaks
Date: Wed, 25 Nov 2020 15:55:16 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Slab Allocator
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: vtolkm@googlemail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: drivers_network@kernel-bugs.osdl.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cf_regression
Message-ID: <bug-210293-199747-dXXaSZqTsg@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210293-199747@https.bugzilla.kernel.org/>
References: <bug-210293-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=210293

vtolkm@googlemail.com changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
         Regression|No                          |Yes

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210293-199747-dXXaSZqTsg%40https.bugzilla.kernel.org/.
