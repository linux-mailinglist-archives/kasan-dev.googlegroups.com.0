Return-Path: <kasan-dev+bncBAABBE7MXONAMGQEC6NGKCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 046E56032D9
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 20:53:09 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d18-20020a170902ced200b00180680b8ed1sf10139120plg.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 11:53:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666119187; cv=pass;
        d=google.com; s=arc-20160816;
        b=n0GEyd9+sKdB/SegSQpMP7zfSqcVuHGmCKlYsfIM2xrfrAbZ6oYLU0h/c1OlImIw+e
         ShwThHymqaD+tOGWRBD6LEigE6sFUCXQCHMkLfE8mZUxmr7Ch6uq92Plv9ZE047l3qcL
         HcxiNlPTX/pN5XPXHoGTV5t8X6MOFsg8Ny+/zo6BYBTKMnP7zNsVxy7uZ5CsG+N5R0Tx
         Ihb83i1ofzt4SytBzqjSW2/8FqU9FfGu+zPmjEmH8VsIW8YotYfqnNl2FYlt0debWxE3
         qVNEIBq7MA0fQXzCixYKravB32kwqfHya9w8nQsmv7E/MuYMklHhIphVM+A9Q2IEvt2e
         5MTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=dEoOSJK1uvMBH3UZhe9XZX2e3EPbe8+EIArn8o5YgV8=;
        b=1KgJNG+bkN76AQSVVuWh8YwGplX+1RO4k93WUpF2kPkpzAGxODxf2qgoZT3Gv0VfNP
         D+apdbQzqZaxYVFaEBtEkims0/xyK1G7ErYL6kB3U4/+ajDQRu9UyULJ5UMvekOZzRRf
         WrzSAXL4T7HTX9QQr2WT8stiBo7ZjGWZy44WqgNe8wCsB+TN05s3kUUNAMHjY/+rxdia
         Eu3f0l0T7wBcYZ8WTlvyfPhIv5DY2djmSr3kn9X00NCN+Fy0yVRcvwqMmOAVB6AnuVG7
         oN/UO/pn71j2iYwSxkmkzQxOkoykbzyTnxYAbuLobz7stoKnoRoZ6LOL03kmKO4gorqB
         gk7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kciT6WXz;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dEoOSJK1uvMBH3UZhe9XZX2e3EPbe8+EIArn8o5YgV8=;
        b=Phz2ZHtBuga4I8g9vksk5iA0v50C0hDravTtuS0u/wQjh91XHYWXmj8CDyn+pewXjC
         KKzevR24Fe2sARhgGeUCCPDZkCT8lIkB7YPPvIBz6/HvF8abYhjFe+EM+gKHUxf/v8Gg
         y5Znxp3gFhu3n0YyYgnXH/i02gXJbdSfc15KtR0sBwMZJG9/JC5pWlRskyUGO+cRRS0X
         DSaC42mNcNo6gLv0WrnCNX94EigkxM//rbqospNRBhe2o/pjghBzGtNIkPM6Tu28gnSB
         GsJv+yYznhnff7mkNXTG/Z9HUk8dzVN4FwddZ1WguG6H8PDBRXKpFjLqY96BR/9pxizW
         XA/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dEoOSJK1uvMBH3UZhe9XZX2e3EPbe8+EIArn8o5YgV8=;
        b=upRa9BgGjIRdtRQIZ4YcsdTi+AucpaRVtHZv/DKOg2omKvgN0Bcupnzero3bfsOfS8
         dYZJPQpj/Kz6UVi0bJNAnaQP8041kgGl4N34Ssc0or7UXV+dKFhiUp3fPCaQ1EQ+AND3
         JWK4beAra1jIGaMXKTsNXZp46sdn6TEbxpQzZoV8olp6BFQ5x+6YF9sVDUOkOnhpekAI
         cx0ruRS62iXgY2tEHn6oPKZFhpp+FIofzHukgqRPaOKHHLkZQYNTezAzugi70LHUtSO+
         yJCCY8WmHKVS+pJYFw2xAyx3moRaB3fPepzsEC8OgXn49h1qKkF+COaBd77e42Pokx5P
         mP8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0fM8X7V3ju9HCTBPj8S4G07mgpXT0Lulr5+XpLzoHFyzOOHRM1
	pwAnoA58KRUkUPrepcrMDuQ=
X-Google-Smtp-Source: AMsMyM4KOgKNuNOopoNvO03tx286vk4xyt/ZmzBs+RgqykO/x09A3+9TG+ERQGN1GUo7Kqwn8QbGXg==
X-Received: by 2002:a17:903:3249:b0:181:150c:fcc7 with SMTP id ji9-20020a170903324900b00181150cfcc7mr4500256plb.119.1666119187415;
        Tue, 18 Oct 2022 11:53:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8410:0:b0:552:637c:1282 with SMTP id k16-20020a628410000000b00552637c1282ls7913547pfd.3.-pod-prod-gmail;
 Tue, 18 Oct 2022 11:53:07 -0700 (PDT)
X-Received: by 2002:a05:6a00:114c:b0:528:2c7a:630e with SMTP id b12-20020a056a00114c00b005282c7a630emr4617591pfm.86.1666119186891;
        Tue, 18 Oct 2022 11:53:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666119186; cv=none;
        d=google.com; s=arc-20160816;
        b=pMsRCfrZjK9/1WSWbFpegtR8etSsXFi8qkuhGuS82WBNtNlth7pcAQ6BTh7FSR9eqH
         /QmTD/kij7LtInq1G9q+KU/DyDz2de7Mbd726o3L1bT/PDFX/fnRcDqJXjrK4xROCBas
         RZ14PKaLD/19F45xUI/oKgPQO59uzdDI4YJkrsothrowsuaUqR4PucuKp/JOQSANxhIi
         wZWL2bg6tw0N6y00VJj+mJ9q5qg3g6ZNv79mTtZ5zPgGyyHlTyCStaW77UJilMAiB+td
         geEoUy+3/GyjLt0EVm4/MjOgK57kA4lNfK4LUMbeGcqm3MrJjectMon2VruIoOvo+pD6
         jjTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=IyZrGwu8/J8Tz+qtKSD12fDPwV7NKLQkItlxOiK2kqE=;
        b=eT1NhKagxiz911zd15t4hGE3YjutJiTrpj6q/K6mnT9YDLthLAK0avpnpBfNtY/Y3/
         EM/AjcuIsNbXnolnEpKfZnqx02YrEoGe2UlRbT4QOdl/mBQTabgvDTLh2PPC7sSGOjRu
         KgT5iNPNVEPa66OL3i2kDG2a1fsa+GHrpDDND7U6gI4Sk3G8SqVq+iuCcRsTg0QsMkWJ
         3lOWhaR7cMtDEIEmPbjfTfidEYuolcx7jD9R1nxFsqGkNG/pygpqnh1BQG5XPAA+u6xo
         vjdlm20Nf6Br06kbGtrbf+l/5bTAi5BFqpa2fCo2FsWW1ljgPW5lidM1nbe6Rm9BKD1Q
         v9Xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kciT6WXz;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d2-20020a170903230200b001811a197774si512567plh.8.2022.10.18.11.53.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Oct 2022 11:53:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 5C18D616D5
	for <kasan-dev@googlegroups.com>; Tue, 18 Oct 2022 18:53:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id C3A62C433D6
	for <kasan-dev@googlegroups.com>; Tue, 18 Oct 2022 18:53:05 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id AAA3FC433E7; Tue, 18 Oct 2022 18:53:05 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212201] KASAN: move tests to mm/kasan/
Date: Tue, 18 Oct 2022 18:53:05 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-212201-199747-cnCa2ipahL@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212201-199747@https.bugzilla.kernel.org/>
References: <bug-212201-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kciT6WXz;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212201

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Fixed with [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f7e01ab828fd4bf6d25b1f143a3994241e8572bf

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212201-199747-cnCa2ipahL%40https.bugzilla.kernel.org/.
