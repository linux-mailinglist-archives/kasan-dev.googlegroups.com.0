Return-Path: <kasan-dev+bncBAABBBXBQGJAMGQE47N4A5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 304574E87F7
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 16:11:19 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id l14-20020aa7cace000000b003f7f8e1cbbdsf7574820edt.20
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:11:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648390279; cv=pass;
        d=google.com; s=arc-20160816;
        b=X8931e/M6R4b1G2gCMXWiw9zJWvGzWKf29D4uVZRPKr5Yrz8ehTwavkqS6eNjp3gOS
         0AEui8Ob/jfFIsXdSsZeW32Y3EiB78Kjj6o7HCgnakEFYPGcIcJkuKRlOAMvJIXl0liD
         c7KD2H7paRRAXNqGb3vSVn5u0QXMDCUGlNaaNKORrvmMBSaHL+fq2r9qLDBv4vVgKbPw
         AChjsmXTFN3STVHhXwkGq3GLc5+M1ZFMcaBydLBWOSBG3OM3o+UYQmPt7N2RBPhoD2Ur
         B48p5huhSNZeo1zpOL0wuP0+zD5fKWzXDRkbFT2rIHYEtwlO+9gMuBt86/sfCW6w6hrS
         VgRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=qI+QSgKW3wmiDzjzbetW5hxnAG0wMeP5Kf8LuUdGUwg=;
        b=CuZfGvkUxv3p1RYlPSR+esN9gZu0BHz7x450iCDpEvBxqQhEwUW1ZSqfC+FecJ3ifI
         Q19DQLMaRC9RIYIzpJIEo4GGckekk5zdOw21FTVr6V7nl15WM8PrXsCIUbJCfk3NpwTI
         1MWO3Y7ooolrlZZBSAa1k3USzyjlM9nEbHfC7kWMPNmwznpnBLok2EDT1bRbp78mcerx
         sDx85Z/dF5/J2/IxOsy72MI0pVZ+aLYT3uaSANNnrsMbiiLF/gYzGBDQv7YCi88VrkLb
         gjNxaVIT15MHu2FBZ1vi2yehDCM5DuIdbWO8FfWTzhD+OdqV5KR4tK2t423ZwpB3fF9v
         g1mA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lHFX9WOj;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qI+QSgKW3wmiDzjzbetW5hxnAG0wMeP5Kf8LuUdGUwg=;
        b=rUlOZn6wAJM/Tm+GedBHCCevVMvQ4t3PU+1TvPJGhZtUTLDt1wqSErJLi2HZriwhu/
         eBgLvD3UDqUB31nk3fn9gIFtM696buZpnbhH02qvgEqvOhWBp3nYPh0eyL6LL5lAZ/oT
         O8LT+3npZufGoSbSuWxDZHr0JzqlFPltbDJwJICRZyZVri+b8Ch/E6i0bSmcqkxKCrYj
         6mNPBixDFsD5jQoWnrGEYUMJ9KsD67rJlOSHX44320JsOzhJFnQCtTu5lGFtRcyjKdr7
         eNN8v9Z5kffb47E/mlO7TFVeoidXHSF+Hc2kV99uZUHL3JP7hzYjmDkYgQXlA/CPKgvY
         SOrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qI+QSgKW3wmiDzjzbetW5hxnAG0wMeP5Kf8LuUdGUwg=;
        b=eYKpYa4tDtbPl2JpKK9ES0UW7QUacRTJf8pvWLNW+tXQ6FcVCqc22BlIlzpLcWeZLd
         XqwigENluJ2I/5YbOaQgJpxGx9qJzf4WePu6EdnRUxQI0gVZrcTJ4ghfWb5maNnCrR8q
         GyVOmEKhjUhvUT55Fyucg9BIxYNOL2WDSEcIfv2IhdPNtYcuYehiDx7SPAOurj4NqhBc
         4w5JNm4XtEvWu6vNWZo5kDrUbK1/UKKys8K2q255B2y+5p6/9PuTULLHBcUlG45mr0eX
         eq89fselHnwuOJfdiNPRJ3oMHsHqGa98HPu0ZTVMYqtNkInVeSP3HzBzTnSVg1zIYrK9
         q7cw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530WWWEvM1vGOSWINvLpOYmyFDWSLSgauGorjzaNKOj3U+xeIHSz
	2INouw/oza33zvVgZPtuVzE=
X-Google-Smtp-Source: ABdhPJxx6t8EG9Nd4pc8cOOjVXthiptM83rhiv62AB3O8CWp/R8xXKJF/vaEeA7DDn7Zm4cbYHgIYw==
X-Received: by 2002:a50:d64f:0:b0:418:f142:5d1c with SMTP id c15-20020a50d64f000000b00418f1425d1cmr10608458edj.192.1648390278830;
        Sun, 27 Mar 2022 07:11:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:2d11:b0:6e0:2a56:5615 with SMTP id
 gs17-20020a1709072d1100b006e02a565615ls1833588ejc.3.gmail; Sun, 27 Mar 2022
 07:11:18 -0700 (PDT)
X-Received: by 2002:a17:906:c147:b0:6df:f047:1677 with SMTP id dp7-20020a170906c14700b006dff0471677mr21890670ejc.4.1648390278035;
        Sun, 27 Mar 2022 07:11:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648390278; cv=none;
        d=google.com; s=arc-20160816;
        b=RfI+D/0Uxwt9BcAojgKb3ZAMC4rknhDXjzh4gtTJTIZAutC5ukQP2b7UAUh/bEq/jJ
         gbXVPUgq7/zlxamt9ay/h4uJKTqzYIbJOJmHkWXXHsoRZMEgvcZz1dlxwG6i3iN8GqmE
         nkslehawxioxp95gcacXyU/Ff4IHPd48Yu/AWH0o79lASwFfp7gIcvm1ZOZ/ffINw+dj
         6Gqv5Ma9xap8bAZOp0TQuXeYbLfYkkFBkOSCubXchzesi7JBFXgkQ8gCoGszT6zblvsa
         Q6XFLS9CMqhqzZP+XvFkhF4YfApOYfAuiyrXHy+EhjjifUmuFZh/bpNZa3sFMctT61u1
         qkMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Qh/EFe6RQKH6q/zFgwO9PMcGvdo/zuDN1NdG8GUmtt0=;
        b=P/FsfCDX/24fPrb5NSd2uHvvxi5rclplJrYNBmjuvkFI3Pa1DD0jQhi4EUjZuJqgYW
         DSXdmpKqkrN4D8O+fKJ+ZJK9goSp2+FQ7kAjJB2twUqUtCHATu6Il9DHTBnFYbYOPn0A
         +46N4iB0DWyA1VPZ66SwhcYUjCR5Rm4lf1fRczKG4+eCzyvnqbGmmMvu1Y5g0zfwLnxH
         S0bnkzyqga8w6ibnD/BGGpDL8KKx5PBkg4R5CEFCQfdIMoJzIXj+hv6yVCettKO9ipjj
         O/PhFX6eah90AeNOLuabAbO+lSwaC6ifqNEmd++HASQwal3lB+1NSH6jafsuqh4QfYge
         gIrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lHFX9WOj;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id bm16-20020a170906c05000b006dff891c710si649843ejb.2.2022.03.27.07.11.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 07:11:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id C4D89B80D11
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:11:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 8F6AAC34100
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:11:16 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 7C14DC05FD4; Sun, 27 Mar 2022 14:11:16 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211777] KASAN (hw-tags): support CONFIG_KASAN_VMALLOC
Date: Sun, 27 Mar 2022 14:11:16 +0000
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
Message-ID: <bug-211777-199747-4ep0Om64Ot@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211777-199747@https.bugzilla.kernel.org/>
References: <bug-211777-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lHFX9WOj;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=211777

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Resolved with [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f6f37d9320a11e9059f11a99fc59dfb8e307c07f

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211777-199747-4ep0Om64Ot%40https.bugzilla.kernel.org/.
