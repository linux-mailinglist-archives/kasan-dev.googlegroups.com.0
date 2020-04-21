Return-Path: <kasan-dev+bncBC24VNFHTMIBB7EY7T2AKGQE6VNKLKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 02DCA1B2AAB
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 17:08:46 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id t18sf6877796pgi.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 08:08:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587481724; cv=pass;
        d=google.com; s=arc-20160816;
        b=tXK2ygLuhU8rOJu/2o55OF800t0HEULNzM+AKpICCnnlJ2zQl1269LyxCYYd8E0foN
         IA9DsCra109Iq8ia/bUwKU6rpfF6ljMoJtRIs25EzjqLL4oKRFkJBwysiyDD4atnOCRC
         l9BoBFdTZ3ZfZQUmaExTJc2pBj7paicQW8jB4EA9w5DKTBPctphng13SxdKeccL7SVmd
         GFaJM2zRWJm+ig0aHMCRhs/Gs1e37BNeo6Ek4aAz7q1OQOioFv2MKhHm6blW5pTAcDKN
         xWGkeMST5qKuEPcONYSP89ZOQpFlfiJlPGAIxhJwpcLq8MR0Zpc9LPsKJR6fZUzuasjh
         nGjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=zugyHkNpdxi2ghpAn/mgVx/uxSHYmKnc9n2N6U9HcyU=;
        b=xbQxV3Lyyf/SplpnFdPPE/kRlM0RoFYGJzT/jmzL26qvT694KmWDcmf/mA/wn7XFCy
         REb1ScWL46e6xsVgBbwEhxl9ugKL8SvL9kdJYrRS6El/COrDr/91V8TW2DxNO2ow5jf5
         12c622cT7z0qTjY4+GrBkuO6Yp6uV9IW0R4sA0jAsTYlZkcfSGZN5+C4n+T+EFt461uz
         i1O6T1edMYL9iNFSXn1o/I2YqjUlJyeKkr+vpJgLfe3Sgo+IKYqGRjBZA8cZpRBBrm/4
         UOwrJuYT/odubcLVWzCQ98JXebTOEZkyj9T7rkMv8eJGmXmtA8a9061BhYQ6QkC+J7PU
         GlBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=06v3=6F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zugyHkNpdxi2ghpAn/mgVx/uxSHYmKnc9n2N6U9HcyU=;
        b=DT+4SvurLgi2Nh+EkpFrqSvj+Ngtj0HFPS94piOFxbOvHk16QSIYpemLf5CM0VQWu4
         5yebtUCTZpv9MFpcbyn2AnrzuLIGvdcZ0DM1WinDRV4Vh9YMAXw6BG2xKZM3sWG/SEs9
         +uVsdu5RI3ieuuEwubXcwjk0SODRTovNvTQRgN/FZ60I0zGQb9fPPfCussvb4NzbR/V0
         XNtJDTJuH16cXZ3dUeKn3vEzql9Q6YalO6NZ8ILf6G4pLa1l02eAMJknMM58BUuFxcv9
         /IWuC4Jo2EGRJtwoACgefHbD14+S5oy1eb9mvsoLac5Xf+J8Jvfj5k/upMTkvd04eaE2
         bM9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zugyHkNpdxi2ghpAn/mgVx/uxSHYmKnc9n2N6U9HcyU=;
        b=q1mcwIGaZMc/1ozllUcYvnydjq316Dt76SYUUxt6dRaJT8L9R1Gv/YQx6EXpSykLiC
         dPz9QWVV7BIbSRqpE9VzGzDh4flpQwW6DO968AsiRWmSqSm9Or1oP6nsIIT+d8/lh5mi
         MwU3bbQYODhOkeSpUXJhZPSP3TFE2N4vnw+0RgT2w3nTWW8ZOckV4IFn/NQDopv3aqLZ
         r/afDX1mrv9mRZRKHTOakZ0W7fw5DwE+iRNxLlTAZBivboyVQZEreGMncOV6os29tb7y
         Crbi+xB7ZzWqkZR6Q70QVtBUsWgYdBw+N9R35/V0ivjDlGeRU7jIIuHUGSm0E3DfkM5F
         lrHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubJC2LEbIQn/JUqI2afd/7z73eVSiN3F6mBtzEA2YaTSEK1N1jd
	ILHI962ro9KYTrkFQpzkH/c=
X-Google-Smtp-Source: APiQypJnAw1cgADhPggawOe9QdgfpbENhnd9gaCmZdjn0Or2Kx0ymRs6Hpry3saTrkrF6EGsjpzdgw==
X-Received: by 2002:a17:902:8eca:: with SMTP id x10mr22626009plo.60.1587481724731;
        Tue, 21 Apr 2020 08:08:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3543:: with SMTP id lt3ls4118996pjb.3.gmail; Tue, 21
 Apr 2020 08:08:44 -0700 (PDT)
X-Received: by 2002:a17:902:aa43:: with SMTP id c3mr10181762plr.7.1587481724350;
        Tue, 21 Apr 2020 08:08:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587481724; cv=none;
        d=google.com; s=arc-20160816;
        b=bCyuQSGW/1UaDecQYoiRIq0BiJ541RmjBDeqAmfGGhpXQQpOD7tSQ3C+ZbxLkCoHHk
         71z+pvXcqOEFO0wBH6/nS+tlntnZuAT4uO0Dr+YvnIIRaUz3QxCooI47s7cwYrbDfbE7
         Al2aMU51tzhz084dHD4Wg5Kcb+hqICOmTmJVAwlljLl3WtsCC6+doNhDqVsc3rm7TWze
         UneScUo9aQB230yDJjYme05ptctFsYByVj8ewI23fe8QqwMDarSKPmGMadrH9Jou3Ojz
         u+QjusNZMM91VKuTcKH7bv+s5d5/xCNkh8hIeFCkWB6TJhRFsD/sDWX/qct6mxalYI6K
         IiGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=mc18UzWu1zAfprIsCmt/vXUe1eLzEZDgZbeFd8jOfiA=;
        b=fQdoCfemEtPyQxW2ZSwH4xXopwHineGtxByDmk3r+GF8TAGQIJD7niC+VPbQeU9Ex5
         ggXNISOMD98ldzNGFQ/VJC30ehdun5YZqLHX+EXnmtGddA9HghRtLKrcv5VSJqfpGoKN
         zWd8gayF4AFt73OdEaoe0YeU5BFo4Y6tJGyMMGRBWorAc9RMoTWe3977Y0+B7s/rFc8z
         0C9q4fn0jnNKJN6bysHIooAl7kh2Pv8ALk44hOE/D/HXTNzl9ZXBX6eF1yTng7I+hKra
         19rpUFuxsSY6c4/ZBnJLzoy4OwpnqLdSq4h3Asx5rUWSexXQ/qb3ta1lqpXnrB6SfSpx
         Xd9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=06v3=6F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a13si215445pjv.2.2020.04.21.08.08.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Apr 2020 08:08:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203491] KASAN: double unpoisoning in kmalloc()
Date: Tue, 21 Apr 2020 15:08:43 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@google.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-203491-199747-M7L10zPQQT@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203491-199747@https.bugzilla.kernel.org/>
References: <bug-203491-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=06v3=6F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203491

Andrey Konovalov (andreyknvl@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Andrey Konovalov (andreyknvl@google.com) ---
This was fixed by
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=557ea25383a231fe3ffc72881ada35c24b960dbc

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203491-199747-M7L10zPQQT%40https.bugzilla.kernel.org/.
