Return-Path: <kasan-dev+bncBAABB54O57BAMGQEB5V3OMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id E6F36AE7E29
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 11:55:07 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e812e1573ecsf1508489276.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 02:55:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750845304; cv=pass;
        d=google.com; s=arc-20240605;
        b=a/1tHFHrgYbz0G799/Gza0SxIEXwUhfPvnDy6Modc62JTvdiw4IEhUES5xn1GQ5oRb
         gif8aWku8H7QNvplt/hBxG25FL1tSmj+rkDA9ZMaqTR9YhNbf8j8nPGJEY5eTI0nk2Nb
         fEvkE6W2Eq5R8gniXjk7h/fxTrWygaTxYy90s1ZYKbJJC/0FOSmb9ZGsze4lo9QwcrXv
         BacpCh21ZvofkjZGBdR/g6hDP/oCLtW1QI9KoXL5anPaK/Z14cB9fNzIqX2aVgy/p8X7
         j5axe0tIMyX5uCJMxhrIxWclDhEB3Y3uqpy5CoW14zb+HnyWmpNUAq60kaic18jtOeL/
         nxYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=ySxEeX+gZj3SDORmXVn2IsJJ7p0IW4UFqMTkdu1GfIU=;
        fh=RVIQeNfLP5OUYeYkdt3sQFM7LqK8m9SwaO9GD7F3kuo=;
        b=WlhwF2PtYm1vMUa5Y+3jtEkAJT6Z5FtoUDVofv4pogKFS7eFxAksvbyRQ8E+Ux3kZw
         uiFzqjIy0ERMGkRudWBoXLfgpopMwzhx6keZvpkHO6AumHBOOpFyeg0aErDFEEWBCCeB
         Wjjgvy8kZnRY7X9xSN/b/bs9zkHMizZuwwm3nJv7lnHVjYT8046/KeikryvrUPtpY6+o
         v1rysAvvC/7VKyzpSUT7EFjzOl1HKdnkBFtIeKR7nWldgQ1ena+c7l7hNZdnW+/b7F2z
         nF4ZM+uaegBtO9f/Io3iG4lG4WZbDWHQ0t8ZXd+0PfE9AeCm3Sc3+mNma/ANzP82kHlc
         5toQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Y3jHx7AR;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750845304; x=1751450104; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=ySxEeX+gZj3SDORmXVn2IsJJ7p0IW4UFqMTkdu1GfIU=;
        b=vgmY4Q84izV/beTuW20vj7l0aiSMaIxlDy3oc2/05Z1kN8HfNoTWAb9F53HjTLbS6o
         dRJUVi6Q/dEv43craoys6d605MPxeh83t5kRed0R3Ejb0R11s/9cbuvjOMuCevelVCpa
         ipgzGl70R7Wg//ImgsKVBHJ4JhRGpgEa/VwoSGota5aMBHWLb1BtWKG/suKcJ8WDqtuv
         STHx630YaHYgzPn1qFlws+MJhsGfDredAFZotsmNZycD0XODJbMxdmG3sWI3TK1/e0gZ
         XXwDWAQkv1nRWpZ7QfRl1jqniWpQO8IR6WxQnEHGvLH9Ti4OU+0ECi/L4jLB40Luxs/7
         gyRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750845304; x=1751450104;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ySxEeX+gZj3SDORmXVn2IsJJ7p0IW4UFqMTkdu1GfIU=;
        b=NcdWEKs5zNYp7+wXQgc45j2qDMQ2LhhkAv0R37oMj+mISbmxQxodO+x/2E7SZdQTmf
         PMxbZZxyiuQGiycYNUAhf0NS05d++rENauxsI7YZem5sHMSiKGSA9dwd3YMCB+dCR3B5
         r1XHwB6/lhV4Hl0SeD5OIY1PnLoQgk1iqb77xMNChF0L4kr0sNg5kbLBkjHDj11AUhET
         uQDWszMQtv+qCVF91KM9dC45QPCG8bmfNuHX7v9ggsnkKhMz5DSlcFG0346BxD6PoMHQ
         ro8elzm0RrXQwPvPIUwvnaoSc5DfLEUvDjuKoiBahmmhlE5gqEKF+WqSWHyjzhJrK5hd
         7o9g==
X-Forwarded-Encrypted: i=2; AJvYcCWobM0Ra72FcLis1wXSKRd4ar9wBWPSRe8pTicnJF7Rbcwns1XGQDwZ3iXII6IQIdJE0n4DHg==@lfdr.de
X-Gm-Message-State: AOJu0Yzzjj9XaUZEiKeLP0awccugLUPlg6FrG6F2R+fqVdj330OBjUiU
	rzG4rIcNQlge+BhbQTRhabJKL/MeOEkQQ5b+DOZfsGpJ2Njm+cOXycsK
X-Google-Smtp-Source: AGHT+IHtO+T/nDd/d5lOx6LD903srk3MJb4+EFNKZfZMeghJNCRsj7jR9m5sawCMqYct9zKg1SjosA==
X-Received: by 2002:a05:6902:704:b0:e87:9736:c8c with SMTP id 3f1490d57ef6-e87973611b0mr768735276.40.1750845303231;
        Wed, 25 Jun 2025 02:55:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeIEWWjQ06G1If4huMwJJtXU4cmWls7tZmoJArNVFGANg==
Received: by 2002:a25:c89:0:b0:e81:d280:4c15 with SMTP id 3f1490d57ef6-e841d44a31els6521965276.2.-pod-prod-01-us;
 Wed, 25 Jun 2025 02:55:02 -0700 (PDT)
X-Received: by 2002:a05:6902:1790:b0:e81:b0ae:43c0 with SMTP id 3f1490d57ef6-e86017b8c15mr2872557276.27.1750845302389;
        Wed, 25 Jun 2025 02:55:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750845302; cv=none;
        d=google.com; s=arc-20240605;
        b=Pw1oFdin29r1g4T3rkt4YyMHG6wlpvyofpPw7701WoKAvZKYbIOm+xUzhTfjMXQ0MI
         o85gd4YKZZ8XMnxL82HljioO5OLVxVVSzPZohG34a/yiqDWgCfTOUxuFo9JrgcA9YW0s
         bypX40TO0SMjHlSUyXHmXLvwuwSHkGN44qeF0Hyz7s5Gan4dF3RGMvg9WKCyJNcpNcli
         CgeUczkt/IV4oNqJr7cuxF4Tuyc1u5oVlViiKjo6NN0r9DvB+w6e1K/dpScxa2XqCpZB
         i2kUXgocfWCLIPNMZAO2ayT/zmXFTpV61CBMMiNRq266nqAscPET3fecGcBDldETgQmm
         uMag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=SDU+I7D3XVqzkhMzCdF7LPHVG0exdEJwo97l+9VdWPY=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=lwL0zgo0kO7U6AwfP3BFt56B48w0K75epoo5zqNlIrgUzTkh+PearNhxxxD73bZKy7
         T9FOQrVNnw7pRbOvZAWq+o4i0eARc/2cAg67ikYAL/5fnodwB5gTRB+G83TQG6eXsrsf
         9OasoeQus/YNv63xU3x2qlM16iT37a2uuN4J5FEg2EutA42um3V4bGFBtFiMecRLm3Y4
         auERAr8f5cqJptFRSQ59nAPkfTECr30QHBXvP40kF4qikRJ5jXesA3+ClGM8QdfHmR4Z
         STE572vrDp2p6SFv1z5Pw6/3v+3QBl6IEPLjeMMKNGSkuhuwN8MbTJtyBqyWaZbRBgT5
         wMoA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Y3jHx7AR;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e8538163894si374292276.3.2025.06.25.02.55.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 02:55:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 0DDC3A520D6
	for <kasan-dev@googlegroups.com>; Wed, 25 Jun 2025 09:55:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id AC043C4CEF5
	for <kasan-dev@googlegroups.com>; Wed, 25 Jun 2025 09:55:01 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 9E513C41614; Wed, 25 Jun 2025 09:55:01 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 217049] KASAN: unify kasan_arch_is_ready with kasan_enabled
Date: Wed, 25 Jun 2025 09:55:01 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: snovitoll@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-217049-199747-Nuth3N6noI@https.bugzilla.kernel.org/>
In-Reply-To: <bug-217049-199747@https.bugzilla.kernel.org/>
References: <bug-217049-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Y3jHx7AR;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=217049

Sabyrzhan Tasbolatov (snovitoll@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |snovitoll@gmail.com

--- Comment #3 from Sabyrzhan Tasbolatov (snovitoll@gmail.com) ---
Hello, I have sent the patch series:

https://lore.kernel.org/all/20250625095224.118679-1-snovitoll@gmail.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-217049-199747-Nuth3N6noI%40https.bugzilla.kernel.org/.
