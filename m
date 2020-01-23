Return-Path: <kasan-dev+bncBC24VNFHTMIBBYF2UXYQKGQEZLSVUXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8320C1463CA
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2020 09:46:25 +0100 (CET)
Received: by mail-vs1-xe3e.google.com with SMTP id k6sf233351vsq.11
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Jan 2020 00:46:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579769184; cv=pass;
        d=google.com; s=arc-20160816;
        b=TgF5+65d/FGSgKfYL10UWHed7LvEzkbBwy4nG71diS/DH+0KGKUTQQYd7TPc4PFCuc
         TS5yTan8LzI8Mx4spUQNMXJIIhwfycGZuMEe0Op7Yq5Tu3RL9vgAjKBRKDe0ZGfMJwZ3
         le/WgpgsWicF8WOkzQt4Uo/Knl+7SWUnBtcoDgRq7OW3JjCI2YymYhjb3n5CWbafhIwN
         U/fV66q61fTLpeY/gn3NetMSydP8SB2XAPH7ej2eqcqjY33uCcAsNb9fsiR8hH/EIJmw
         pTvLuTh8EopS4F64kR3KI4iJxkEQwjSZmQp+YK/Z0tsmZtHzxECq6jfyRNtntUcYBWK4
         1z+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=9NxPZhfvAI4nzMc3zJP7ztDL+rn1vW/J7feQRZtceiA=;
        b=UUTiGkt2hJBbsTbizmDxYQm96hx57ZaRDTRYAa/HunA+i6Za61RYNX7SqkecCH6rQw
         cNmyxGDA6uIKmBEQ2G2+uQIDPVgkp/TeWMSwpcgLjxb6RB1m99K2NKgQm+sxxyf9zJjW
         guUodF2/dPJgnjO2l4isseGYJsds8i5oi9JJlf6wiBf4evCZqLRFnlnZHdVJPKWYlguw
         HAmrzIKtK928HH+Xw259JGgJljImRbD+nGzRJQUyh1YsjESmlqVWUlBApRx4FxKQCuXT
         lAWQu1RWwCWCQ0xFafUYvvloEsPfvj98kn0TDV+KltkNZSBntAim9Ab4AhuE4oT/SJSy
         7Vzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ny16=3m=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NY16=3M=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9NxPZhfvAI4nzMc3zJP7ztDL+rn1vW/J7feQRZtceiA=;
        b=RGNp1pY10os4etbuD8EfNDwNrH0iJzZhzixhnOY30/4qZIZg5WUipY8XzFr4YyKlYA
         M5ZYR1QLiwnYHN5VNPU1zYEs0eX1XOUT1jba3nYTL1LHcur36FcZ0YhypPPLAzvTKjTv
         83PSW7iEJtqqKaf/+SFB2NqTYWvzXJ4oeMSQXMiTh8ZfNDprM6YgFjZDGQynrsFM5xkU
         RWXd3/IZBPnTQ626IqGe8r3SGxCutD0LPmvJrzDlzp52opAr6U4oXfUtludhe4BQ6SeX
         Y8WLbCq76UVdLuvs+wem/HLuDunPm4u5b2c+R6gnVp3AeEvaas6qT3xfnrvrlB1mrMID
         QZow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9NxPZhfvAI4nzMc3zJP7ztDL+rn1vW/J7feQRZtceiA=;
        b=X4fesHt3AD31H3SSaLa3pmcSLDOj0Bk27kaqF98PI7qBfX53QOn4IO23tN4MnuU710
         QXsKPJ7sfLoeYLu8VEDutba/b35kP2vIvSbTmMxJQTW/8/J9u0LzblemjsYKVErjqZnZ
         WoXuGmrpIbc65sJqEITjbidZfLjzjQNAN1bSK+9BB3eHRm+9LowS0dSdfK/u8kZvUXzH
         ojlKEpUTmKSv1h+2myflTg6/52OA2rqXP/qm+LGlXh1no1b+SPD1M2S1PldlKC91Cht+
         NHqbrMYkoYoLpe40cukB99t2U0To9ewh0gBAnTLN+6yGKrw0RGbyaGGxXOUL82DhrNt3
         7i8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUVRUhYuVfHIPqM9fIYsszy1XUgsLjtxpufqhkfbvF+scKfsjFp
	KptqsWFOETp0999UejQAMXo=
X-Google-Smtp-Source: APXvYqw474LpWlbpodjR4I6LMIHsFJ9q6gBieGUY/3BIkCROXDBXIVREPCsV0IGO/E9tkC/Mt/s1Xg==
X-Received: by 2002:ab0:6881:: with SMTP id t1mr8929492uar.88.1579769184603;
        Thu, 23 Jan 2020 00:46:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:7807:: with SMTP id x7ls2463584uaq.5.gmail; Thu, 23 Jan
 2020 00:46:24 -0800 (PST)
X-Received: by 2002:ab0:143:: with SMTP id 61mr9390689uak.85.1579769184287;
        Thu, 23 Jan 2020 00:46:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579769184; cv=none;
        d=google.com; s=arc-20160816;
        b=Vqh9/NaQ83ngBibL/V0DMS1VWmT1FKkKpB9/1UBPCrzdu0r4fv67OLiSjtc4x2H2gD
         wctW7r4llPANJoxxzitJ7dICqUvaBXqQHCCCk+zfRvcBLRsR2Dp0GxXgXbadPIybJ2iz
         1ijGWErPupWgk9+VEz70xeLvrBEIizDGzKqlMmlUwsN6XeScZLMSU6ePZwhDtUHTwaj6
         qJTBfeI/+0lt5stOne7HYBLE53fxWnqSp31H4zrd/qKx2PyftDGqy7iQYNugH73NOX4w
         sB0WkydF1elW/Z8cONyDAotRCM7Z1kYj40cIR8dX+FrCiKYyayxZ+tSW00/m1GWDSDdG
         Ey4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=w7ZZgZHFbMrUKeAhiBi9NxfsffC72mY4KfHgIUHDvuY=;
        b=ks2AiWG2IcD5VhQj0sMlux0FvochKhYDFnq3yfpAX/Kqi1bxih5Zfp79n7ZVdrg2MI
         WhOb9B9xINEWh4LdMDFdSG2F46XcSuyl9/PbqLFydHTAeY9WWuyFxR9okBR19kzrcEvd
         DZFnQLB7N68e0i/8PieuvmxKNdh1FFGlSKo5gaFTQ9/Z/op39aaym/YP/zmlaeSipI+X
         5IHq/WJK2PxIK3HlvjJ6OgGM9Jd0DFRA3az3J0spWINPZdcrIvMzD0xG1BViw/QYOwiV
         WmG0eW0FyhcgKQ79dJdFZT/nVCMKDk5rZU5AhwYbchHNVErV2Pom0LlPk3ItQy/M7h4Z
         aurA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=ny16=3m=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NY16=3M=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o19si80326vka.4.2020.01.23.00.46.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Jan 2020 00:46:24 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ny16=3m=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206285] KASAN: instrument pv_queued_spin_unlock
Date: Thu, 23 Jan 2020 08:46:23 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-206285-199747-yRBoGWyjzd@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206285-199747@https.bugzilla.kernel.org/>
References: <bug-206285-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=ny16=3m=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NY16=3M=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206285

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
Worth doing a quick grep for other similar places.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206285-199747-yRBoGWyjzd%40https.bugzilla.kernel.org/.
