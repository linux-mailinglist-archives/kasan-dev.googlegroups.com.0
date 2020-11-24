Return-Path: <kasan-dev+bncBC24VNFHTMIBBO7T6P6QKGQEI63JRKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 352AC2C257C
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 13:17:00 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id x85sf17122826qka.14
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 04:17:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606220219; cv=pass;
        d=google.com; s=arc-20160816;
        b=frDpllfEcNAnF7hSxeKzszftj8cXmQOmwqAE7+YIHrV0xJDjUYEIXfS44rfCOsB7hh
         2EIXJOBMAb+9qS6M/h/yId4QRTwB7zr1Kr7zrLGxCmqDIfiEIiWoO/XDnhcKnMqd8VOk
         9JsVnyBU2yoxnRwYPVy+Y8673DZ5+AMykWD/EefOJC+X6kdujaBQykWOd2Qs77P4SnuM
         hx7ya8N/QcJKINB05BfKpoyhPQdDEDHIBbrFWQuBxJxkzw9+ELxgTCwweqwhrLb8LZch
         wPrfBAaY75LEW8yKkUJb45BfL9CMySIcFmDX+R98x3r/l8QBfMcz+E6x3EFYhMrKhFiP
         kEpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=VcS9xey/o50JXN18/txTbRcmUiOeIO4FNXi28+UlzVA=;
        b=TFrnCu4Qf0+J0ez87pGHB1Oi7QZWT/IF5ox+UcRYkpDyYDpe5sZqLJFZn+J8m93Cs5
         J6PhKFqUKJsTC+M27kzmNIwxbs4o8lHuA+I2IMkqE8/CxmzWshDyh7/9P0erQSZiitBu
         63jmBRTESt9oJUANG3ik9rKZX7nrpWbDyy6zLr64pAseHqxd13utHrTparmkR9m7PZGD
         vt/7x5g7zN7AMZ0TPbBeOw+BQs2/k26zFLGKRCrn40PXHWEw2tK4GTVsrjX0gCdSpcLN
         nbGogYsrrqQh1Aj7SklBBVe1RTH69pQDnEUspAa0NjURT5BkJePw522uVOL/yYpM5p5I
         aPmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VcS9xey/o50JXN18/txTbRcmUiOeIO4FNXi28+UlzVA=;
        b=ipJza1eVPSp1MCcodb7jxoBuqtvw7/D6pKbN6KlM44UOFSGrlzwWpcmK4P+43rrZxz
         EAGnUBRqsqaPz/1xbNQ8WlfvOHPPO/VrZUw6j8tMYIzpIHkW/Lx6iIDIG04Uq90wajkl
         ZLPEclvsw+k/ULoCE5bC1qT6KrYIcpjVr/N5w1Q+o5sPKV+ne6Ja1xD8dr78IMpmZUBI
         V+m5CSa8cXERwnIJAA+9Whx/E0KzfEXnd0wFrPAwcy7NovX9zDeKHXezUIh94h65zwCk
         LNGqU2PsiDRzHMZBYJ7dz/myT/WMu3jUKElt+M0Q3gHmp0dn5Q/Wj/w1wyFVx4/TPZRm
         gVww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VcS9xey/o50JXN18/txTbRcmUiOeIO4FNXi28+UlzVA=;
        b=P3lDd9hHHSUWSR98hsc9S9rTPaMSUlPVB7Xq+5FEUBIeUsXBRPXWWvVO9uZyo7X3EK
         2kVNSwgD6f6G7UWvD3OTwU2rpE3RNhDO17t5I6Qe5ZNXjOHoyg5M8Qo1IfRO8DuW+OyZ
         CA+1PUQilYM1YNo90cJftAlqFnMpKD8U1is40bODxYgcnEUEv9ofBSNo8buLnDEGVGpc
         mp/QGNVgdF9/ew8VpKT7RvkgGaitrzQXM75ntvg6UDyZZm7VgwXWOIAH4se7MtuHbPbG
         xWZW6p6N3o6itwEM8I2zis7IkQ7S9/qQg1Ef48YFI6nPwAc7/ZZ7nq90TLlpd7SvSn9G
         JSxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531eUEiiKW1f5vy5/OqHiWc2Hfxnsk77UGOQd1d3ajsfCoCnhVvW
	SDxOjhfaTPt8Ryg/PwGJIHw=
X-Google-Smtp-Source: ABdhPJwt9aDL0lvpnD4xaCGDO0/5M9lAtrhc4o82vFYe9iBETNwbn61P3KUVGclgd5nwOTTUuvE0rQ==
X-Received: by 2002:a05:620a:1478:: with SMTP id j24mr4244616qkl.207.1606220219197;
        Tue, 24 Nov 2020 04:16:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a493:: with SMTP id n141ls8071278qke.8.gmail; Tue, 24
 Nov 2020 04:16:58 -0800 (PST)
X-Received: by 2002:a37:5f42:: with SMTP id t63mr4585846qkb.449.1606220218778;
        Tue, 24 Nov 2020 04:16:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606220218; cv=none;
        d=google.com; s=arc-20160816;
        b=VAWT4GER6CNoEriINFpw8KwesExkzaOgcpmioOeUfS9cL8eBdwUDciTQyUfXkEp02V
         aeJNOxEe7HTwQdHE1hEZU5j5N8hySKp+kV4GiyjInrJXCzJjYmiQ+yN07f4rq+zL4mam
         p9DCPKzH4HaVwyfcTPnXXwQheYLvF5jqtTU7hgD05YJKoteyyH44v0RpgjKcPhyTczvR
         vR3KjWzxbUJJxTvAiz3udkHpD0sObOeSS5LsHWKBTBIbL2d/j3hbBgpMW76bRATA7psG
         uXtqd3yGL8Wvt6nt0Vpz42ddqGpOxzrvczcsVO7ipueEqXwhy69czplrEwNYS2ui2TUf
         DJ8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=Bb9Ufip9aFajlKJczBMrG9pi82RlZaomZkkMqC9QEhI=;
        b=TEbz5dTrOXih7uqmW1jp/heiJl931cm2s5r9mj5oQ88adcseZ45vyMtFIEv5vrIAig
         L0EjBFSa5n1kUt1biLtbou59JC18qHD7ckulTMh30/hqsAe78zLkvqxEsIpg8mVHYMaO
         otk/0vEwNeyupRkl2DycnbZTfV1uBZNe6V8E2qaz5VyEi9J+SidceTgFgGEYoLb/VFEm
         zN+6Xxuve0iFEKxBFq7J1XIr14AjcAMt7lW9hKv/0B9s15t96rB56l5q9/W8EKEJAXqb
         ohSwXesZj/6plFdm7am+ncCc/snFZpeLM99xen+CvnsO0mzsuQe+6/zdYCwLDxpY6foR
         rP8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g19si696261qko.1.2020.11.24.04.16.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 Nov 2020 04:16:58 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210293] potential kernel memory leaks
Date: Tue, 24 Nov 2020 12:16:57 +0000
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
X-Bugzilla-Changed-Fields: component bug_severity
Message-ID: <bug-210293-199747-FPAc7UoDZ0@https.bugzilla.kernel.org/>
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
          Component|Sanitizers                  |Slab Allocator
           Severity|high                        |normal

--- Comment #4 from vtolkm@googlemail.com ---
Pardon for setting the component section to Sanitizers, which is apparently
wrong...

Not sure if SLAB is correct but would seem to be most likely one

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210293-199747-FPAc7UoDZ0%40https.bugzilla.kernel.org/.
