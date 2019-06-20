Return-Path: <kasan-dev+bncBC24VNFHTMIBBZNJVXUAKGQEQ7AJUZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E9F34CB23
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2019 11:41:58 +0200 (CEST)
Received: by mail-vs1-xe3a.google.com with SMTP id m186sf703667vsm.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2019 02:41:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561023717; cv=pass;
        d=google.com; s=arc-20160816;
        b=PQIoDE2qk3Z6CzlQs9t4x5iEEZ7mExbRdia5LWd543oEMmudqTpdS2IIIWZ8GRUYe4
         2Y9QJrauAgykeRJSyohjzY6IktfNfSg75K4f+BFeu3heoi5osN2P/EkFXehJp3vqmWK6
         FQX2hkridWHbrZ4yL1oi9DNP36O0DBgbEQyFE/lxnVCiYjfC6MGMmPQwd5Bf7Ijlk6MU
         CUpAIKWvGHsbG7UrJupzymEngFMCEHfEJSBCxWoND4erHXUMYoZPRn2QIpywk/WFLE0y
         7kgp9IUT2yLrPaBrYH5AW7/BSIl91mIMum1kHmiGJEELEUYuhA7c/kw08YOIdYsc2ZsF
         8BUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=blMX8iAoKv6mlzxqa6Z0oXHBUP+ZWk2cSB6kxuSR918=;
        b=rW9n7u9JmXLwKIZfSYJmTz+UjegdG/u/jl8HQP1aecjaDsaO9n++WqxX+X3UVr15YL
         pZbuUPk+kNRh2wnlZJ6RoBpw5pW7Bxfglk302r4pHtV8MnNT2hHaL9jHEjc+sM197/Sk
         PuIs+VRI/1gVVR63o4q8xXHKdiM4sc9eLpLhuF3wHeZkzLXIG2A2z08uJwbB2WW7LO3m
         k/QJbu69WD8msBX7Q+gF/1D+z+S5vUTNAMtpX7vPZXx78EfcvU2cVI0jNhYYOxanc2uT
         bs++lX3wxxCd28VdqzmHe3p/BCnr37fUnaYqNY1ACgCweqTL+/wqVDl8fB2qLQ5asb9C
         BdIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=blMX8iAoKv6mlzxqa6Z0oXHBUP+ZWk2cSB6kxuSR918=;
        b=DaQdSCRW9bqdpd3r1IKoMNv3OiDo6YQ/SwwXPz5+dsHkIZGGGiYR1Bg33Eo8nBSLuy
         hvD9IixDeUR2TzDP4wdLHT8/D+lRH8MDLlAdneqKuX/gW2FGqCB8Ywoi9UQAiQXTx9Sg
         ddOVU2dNyDKQlpcBA++cnxQXDdr+vDs64uE4of2ucfyEJ8/N3u5wCBbKyG99UrOLhQwO
         qaO8Poxn2omM66vjRHddVeoApxBjWeuR8rqbPuif8BSibknthZlwLqqPzzoiQ/0KZOFq
         ohSJ56mnybh6RutyP072hiJ7IwpHR0TZrPoI0/0bUD9O3s9oYl24oyPmA0nQTe1vDLw7
         6Zjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=blMX8iAoKv6mlzxqa6Z0oXHBUP+ZWk2cSB6kxuSR918=;
        b=TCxFLY+COYzreqVBKp/EnmjNqDesxGmen4DRXxxBAZ2FYILDvyaaVpJlOVI0yu1pVY
         rDZfyhGegENBYRihzQ9kcIloEMO6WqktDueil38MNwTtEt1kpHZhSUe4//aNvngrYmRB
         ZTw/pUxXqYDEELVKXqcuEE0oadnA+EsZ4L30j4WyoofeYh24EJxEtfaFmKh+jgcjxtkL
         ZgYf+eA3MV0OqaCjqBcuM4D329HhAzylaPySy3GuERF6wk+WOf0ABFobr5srsqKdkzFz
         muJZvY1wVLgMnyBxOHKOk2f1NSWo6qXQ7mKgRoKnSY626//0Tibo/aQ6JuF6tT+2SSct
         4mBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVw8FkCEvSpT15ddvzujvcqXq+njQM9UHtLs41uM1XfkkRQ9cI6
	rW1QyrgxJ/RviA/KMcgUFtQ=
X-Google-Smtp-Source: APXvYqwElaZVJzYFT0adxn807O5KdvMPTgJ69Oe4XeAhc8ainLQ7pqVPwgcdYUNOYZcc7Z2daY8r8g==
X-Received: by 2002:ab0:7442:: with SMTP id p2mr53640731uaq.92.1561023717148;
        Thu, 20 Jun 2019 02:41:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ecd7:: with SMTP id i23ls557300vsp.8.gmail; Thu, 20 Jun
 2019 02:41:56 -0700 (PDT)
X-Received: by 2002:a67:874a:: with SMTP id j71mr72080966vsd.40.1561023716750;
        Thu, 20 Jun 2019 02:41:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561023716; cv=none;
        d=google.com; s=arc-20160816;
        b=Fp9Hng1yyH3Ld6nPNevN57Sl9223dbLMn5PoP5ipRByj4s5sNUAUU+/agEyvJGanpz
         4xqqDq9D9+O+RGco+ICCSeGPQjO+5UZdKapfctlVK2nMiVVYG4EiWeB3aqT+Kk3NmycQ
         9BL/5QZioOvW0v+qJzBFYD9RlhJFWSLbai9dSrhV4Dlye1GTlsSDqgAPK07oBkJsRR1z
         ynWg2exKICBNGkgKZ7/LKiybJT3j2NdRhHbYzO14nV1MlxIEn6OAHEPn2/T0h9btqnSN
         k0vlp/I6Ns8hK+8rjFOgXmzhfLy2yKZAAyiA9XWCD5PI9cxdwjXCMtKsF5jseZm/YHwY
         3wzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=FLn9LD1CrpAXOnLzRxMW97OxAG7kNPYDrC5LR9PX5Xk=;
        b=0LmgQaFqVo7rkrh6bLBJXgOSIs/XTVvdpZHkDk1VN2UTVbS8H/FfNRXjXzc77zJH2f
         pP48WTYS8TSOLyTO7YRyka+tDgJH62MeqV8TzZW+Tp2ylxxPYb6IqXssr86VNH0I9em9
         YH/WzJHkI7rJhE08M41YkN4M0WKMVLktxFKczZMov+iHWW/42vM2qKR24zFHPHQxJvcV
         3z2HN2yM9lpDQv/H/iypjZUYcgQ9+LUKxObRO2dcejNcP4u1EfEBd+bgqSWcBJdSWJKy
         u8EC0znLgvahYHFrsTTrCfRQoxMn7mdX7URyP8al2sjc6G4GPjVpFC5UY07JZNaokZMg
         afBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id 63si1493769vkn.0.2019.06.20.02.41.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2019 02:41:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 7745B2239C
	for <kasan-dev@googlegroups.com>; Thu, 20 Jun 2019 09:41:55 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 682BD28640; Thu, 20 Jun 2019 09:41:55 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198439] KASAN: instrument atomicops/bitops
Date: Thu, 20 Jun 2019 09:41:54 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-198439-199747-JZrp4djvbF@https.bugzilla.kernel.org/>
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

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #4 from Dmitry Vyukov (dvyukov@google.com) ---
Good

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198439-199747-JZrp4djvbF%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
