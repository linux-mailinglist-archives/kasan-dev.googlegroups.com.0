Return-Path: <kasan-dev+bncBAABBFWBUG3QMGQEOYYZHBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 76D8597A62B
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Sep 2024 18:45:12 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-718d5737df6sf5641833b3a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Sep 2024 09:45:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726505111; cv=pass;
        d=google.com; s=arc-20240605;
        b=Za/p5qccnBP78M4TCzPSKzeOHMU1KgesGqWycyvhl+XaxazDTSPrH9WMjsD1gHvJ0T
         AUg3D+uTiIBkLZnxlEzuTTUxiGrqmpudPCzR2lWlKhmRcTJhdYFcI3wcbYyClA6bEE0b
         G+GmWHoqvli3mkiL/uyaVN4rdT7bDvHXaFOGW7MyLMyPg9fAK1PNDayW9RYCwyHtKNiK
         R5smukTOLXIOv8UETcWvZferXmnh3EfRZqeZxMVOQKoZxjkA6FVy/PMrQEhRm5vHXv86
         Zhf/VyMWmKDAcEyjebQiti+8HDVAkFRm3IXEAgQr+oRpfdpXNBuHZ3nZ5mBSkZWQqv9s
         7AqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=QPpZvjiJGIy3NZqXMDZp9fwApCyjRqZ98QUrHfwh4dk=;
        fh=IoANo6R1z+5RnOs+iU2uvPzZO4bjz0iMwwyZTwSB/Gw=;
        b=SAMoQsirSmAetnbiLHDcKh8I8ef8ZBfHMt29s27Wp2Y3pyH0dPn5pfETXYc6VI/fkl
         FM+ypCDiwLvDFj+h8jVgU8COWARvFnkO4qtNOCTGzhoJGdhRI1x8eJLNENsIfW0S8Mpj
         dL0VVna79uo9QJnNp+qUe7ynqpssHlD+ebs47b8jelCpwPNriXs1mBQP+hKAO65DNngF
         dpRsTVdIdWJrmlRM25ez4TyTIvs4wgnFCPZBGLuqiXQUvxuM5pBV2VKzSEQHOaYAK5Ic
         5iYt7mlZmurYDJJUGunypp/8QJPOVjUx2o5xaXCTuVkvubU9ForZdXrsUx/HTh+OaDhq
         XQhA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=M8N337X9;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726505111; x=1727109911; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=QPpZvjiJGIy3NZqXMDZp9fwApCyjRqZ98QUrHfwh4dk=;
        b=gbUrdeucHfLizK1p9DQMenSVRtZqsTcE/FHhc9Sr9DTkKAQOYaZ2y7dDSBB2fnxpQM
         vnEikMNehgK5C6PDETgDE2bEsXR8ZYO7oqZE9+BaQ44XR6CAcqBborszEkoxogZeSoEp
         quKmOlMzpEglegyWbow78bEvMLY9P+tR0yI6Ko0XUH5rUDhVkPqJ5EG952Ydj0HtZpPO
         +e1Cw+VKEBzSL3kXygo14qfsBNVnI+SpJJ4DlNY9pALOstJ0nqjtQG6pIK5PiYVxy3I/
         MApRt8JjCant02rOoFBXLaW5CiQyOxlVD3PsBN2+6OJco6L+mTtjUfRT/M6BprvtuKlA
         lfHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726505111; x=1727109911;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QPpZvjiJGIy3NZqXMDZp9fwApCyjRqZ98QUrHfwh4dk=;
        b=F4mfmhZNgFO7ulQpJUOQbyFa/P3HYHeheetce2J83tMF6aHlz08DRrqtgdBcPbao+/
         yPD45vWsA1ErTyQzifRRLIzle7qg0fR0aNdsdv3y0V8ArNKI+Xk3ZcEjCDYlEAfPEF1U
         404i3JzoTCPaHgc031MJmUmhQZhp/6wLPNKINLAEB8ZvoSGQNJAS10K8MIfICyK0HMp5
         APb80W0niwLfu4fU55PDIiLbj43BqHI0dwncVetrMO2e/Jc+u+GKBaNymyK4Lhxa+Nop
         hvsXq6IEeJm696YJp8JLklLxrdg6DC8/30Vp2NJfWBnZdR+I+i9v+spG0XLJ+QtLVsg4
         vNEg==
X-Forwarded-Encrypted: i=2; AJvYcCXmKEv+/juDwduWAXv9m0TiN/KBEsr4ZkNAonkKAEa04l613xgtDV1zgmMzM2FlDcxYpldrdA==@lfdr.de
X-Gm-Message-State: AOJu0YxX3jCpMXKB5sHqhA4TBkhUDglrG0jbUdQRkOQYx/G+GxmX4c7r
	rcmv4xMJm1wQJekxVlo7k8Aw7K70pL2OGhuA1EqZp3npfH4I/go6
X-Google-Smtp-Source: AGHT+IGgzThwQJU77iiC0qQbE+rPKgg7/J+9XGWJL6yWEs1a7AncBOMu9dJb6q+o8hnRxhinr7gFzQ==
X-Received: by 2002:a05:6a00:228d:b0:707:ffa4:de3f with SMTP id d2e1a72fcca58-71936af6673mr20649306b3a.17.1726505110399;
        Mon, 16 Sep 2024 09:45:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4b43:b0:706:a89c:32b4 with SMTP id
 d2e1a72fcca58-71925850b67ls4074900b3a.0.-pod-prod-06-us; Mon, 16 Sep 2024
 09:45:08 -0700 (PDT)
X-Received: by 2002:a17:902:c405:b0:205:6a9b:7e3e with SMTP id d9443c01a7336-20782b7efdamr155022215ad.56.1726505108386;
        Mon, 16 Sep 2024 09:45:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726505108; cv=none;
        d=google.com; s=arc-20240605;
        b=YVILUjtUDjizb9FFw7gbaHszb6CZ26minkclswLdBmlZnEOgoxiqE0C+T7QIPtyPKM
         njfdgDNxz8UF0v7DMqQoDfycGKw5RqiWrTFhuX2EVwHQfuVCoT/GOKOPmGc+Jqof1OaN
         9DR57LjwHyxCsKzrq3kqOo3YCif1PjNTbgOTayY6GSbhctiFwcm336lxTTb7OdEvlG6+
         e+7IEXZZ9Nm2JpOCi+NE48U2L+8boYcYHEIO/JsicqnK4kP9uTTXMFWGtx8yX71yGudz
         luSZ6aw8njc68UCM0CB4JnYamc8ie8zM8FdW2k743+i6V27oB4pMqsV31aLTKQJNfOvM
         Vxqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=lR7Yu0CyBgojprfozbv1SOrXi1Asrdv6+cZQAJbJ+AQ=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=ESuHzCd0aQmFcR1DJCzlZMx753TuMLGUU+lJnYytA0+LKOmyWPWpmfzoZlfdA4YbgA
         cpnOPdV+8Be/NecKYhmVAsm7xdcMJxXU4ozSuFSgErWJ0muWkchdBXvfQ4ITYBRgnDX4
         jaDwmSHApbyyK8EVeVtuo86V/KErc0KIkFSqeeeaxvfclKm/I+mnFLtKge4DbAO8ZqCe
         vgy8l3f6k37m8L93TCQ0GEzA+Hc7KXGS6ajFy7dN81DVAR9yqtzyO7lMsIgdXs2oRiuz
         mx1u0UtKvytG6/ZWG/1omD2BmrTdAjY5ZO3xhiqoKdXTizQJ1pfnKbn+4BW1Gmq35TdQ
         3eyQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=M8N337X9;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-207946c2f7asi2092265ad.9.2024.09.16.09.45.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 16 Sep 2024 09:45:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 0041A5C5C71
	for <kasan-dev@googlegroups.com>; Mon, 16 Sep 2024 16:45:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 53A0FC4CEC5
	for <kasan-dev@googlegroups.com>; Mon, 16 Sep 2024 16:45:07 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 41556C53BC5; Mon, 16 Sep 2024 16:45:07 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 210505] KASAN: handle copy_from/to_kernel_nofault
Date: Mon, 16 Sep 2024 16:45:06 +0000
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
Message-ID: <bug-210505-199747-D3XZgNZbs0@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210505-199747@https.bugzilla.kernel.org/>
References: <bug-210505-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=M8N337X9;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=210505

Sabyrzhan Tasbolatov (snovitoll@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |snovitoll@gmail.com

--- Comment #1 from Sabyrzhan Tasbolatov (snovitoll@gmail.com) ---
I've checked this kunit test on the latest 6.11.0-rc7 version,
and it does trigger KASAN on copy_to_kernel_nofault via
x86 macros call stack:

copy_to_kernel_nofault_loop
        __put_kernel_nofault
                __put_user_size
                        instrument_put_user

, though it does not trigger KASAN for copy_from_kernel_nofault,
which x86 macros call stack look:

copy_from_kernel_nofault_loop
        __get_kernel_nofault
                __get_user
                        __get_user_size

__get_user_size was appended with "instrument_get_user()" check in
commit 888f84a6("x86: asm: instrument usercopy in get_user() and put_user()")
but only for CONFIG_CC_HAS_ASM_GOTO_OUTPUT.

So I've tried to add "instrument_get_user" in __get_user_size
for non CONFIG_CC_HAS_ASM_GOTO_OUTPUT condition -- it didn't trigger
as well.

I think, __put_user_size and __get_user macros should not be
in __put_kernel_nofault and __get_kernel_nofault macros at all,
as they should be in user context according to the macros naming.

So for these {__get/__put}_kernel_nofault macros we should use
either existing kernel-context checks or introduce new ones.
Please advise.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210505-199747-D3XZgNZbs0%40https.bugzilla.kernel.org/.
