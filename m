Return-Path: <kasan-dev+bncBC24VNFHTMIBBLGZ7D6QKGQEUABDGGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D2C52C3D2F
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 11:06:38 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id b4sf1415586plk.17
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 02:06:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606298797; cv=pass;
        d=google.com; s=arc-20160816;
        b=SkrFX6c/BesOpwg7dDdRug5gGhpHSLgcQk9/vSqEETIvktSdBmkqjntWsR1hTzTADd
         umriIGzoPcGYQhL3c0TkctLV9ft4VyDM2cGPU2LocVGFqUftHLfCnFwQ/YqR/IfQcxIm
         2fHdSFVR+XX0t8RLlh3Dvoah5i9+eOU1hQAVVDqp8urQADiXhHczsTiPimo3laP7JyCS
         UELahhd5jrzeEpWVytBQiROh/CbIXGkjmYYhaPB0DQY/JzB/9bQermuUMey0mqa54bEW
         GicPnMap8rqmPls0mySLlktTKWo9E/4Qcw/dcyor8gVdyizfDbYWawG9wJ+zdfmeqOaf
         PJbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=b4l5Mmjhg71MTG7LJGXYc6XhTJdGNDRqFveyDndTu5w=;
        b=Mlai4WTbryFs++HytqykO5yXvA7aw9vqv0RerZyOeH4BUS9RkIEED3iTCqgmvubsLI
         GkNJa1gIU9DvlRZGST2uVhYgPFpUyK87h4arUGHEmJPArpOGWsIpUFna50KiDTX+d3sz
         kESvcmFosyvEx+7YBUiV9Z11dii5/Pk6orMONrnlPDD34BgrxxZv4u7Ws34WXEiELLsL
         QINUq8YXwNW8XJ/pfWA3js8zOMy9x/ml+Nv9FF0NeCuPLXj1zZqyNrvyvXWP+bJTUQBS
         s/LLQYlZ6VPm9+b6jb7q5GPXrdkZc7hmsfG2kUXgdyuhAei+WVK1tke8MJ44aJgiZ0nA
         aC1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b4l5Mmjhg71MTG7LJGXYc6XhTJdGNDRqFveyDndTu5w=;
        b=hog4PeRfu7w+WjYmhnBoL2h0hFZcOpDufXqwog3s5TZabu2k819zbY6yOMDDjjKIB9
         Wv3D4utliOa8cbct4jyrEyvNxOYrPvGjzDGHeojoaAKPoJe+KwM8rKE+Tf9RcLCnW4AW
         8eUohKIazHIgzPuie0u07oc2/XcsQYbKixN+3X8OryPTtZD3tMl0xfGSui9kDwAApkdS
         sTpgWUt9uND7eDq6dGOtbC80/rNixkY5UfjZ3djAOAQkQCMvAYGP39oqeJUc9Gm6WrJ5
         UtrGo5jQhDKHvccSM9C0F3RoX7ZGYcXtl23HtEgu3oV8XNNSurGsLhIQi9KrLPwf1Pnk
         OFLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=b4l5Mmjhg71MTG7LJGXYc6XhTJdGNDRqFveyDndTu5w=;
        b=M3nZr3Dm5SD3jrX23qH3oi+WOr4b/N5GXuxx9ZZu8mug99Umbv+UxnWe7FZvXfT6u4
         r4Q5XwLYgOI+wrlzSghQ4SHxkslJl6N+fxRRuQ6Yop3PDJGFWMkqFiBMh6Wu3coPkUy/
         JfxaqSH415kup19V1ImZxXVtbvcAoRjoEDfA69StkHkJW924z45p5VLwCosxvKbqG/sF
         ZGiOPcsf2GSNF5msh4jnsZvlQiJsKz0HVBxJpLyYBHEG4MsmhsD41+TblnxAgNtw4dDx
         eJj0OhPnXjHYnxLB51i9oayoin3zH06SwU2fFiZAIloJPA0aXjztta8SvLXv0LXbUhro
         0uyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532/alN+K77wLSi+N3oR8ruc79+aeK58m+X9gaWZH0yhZYUcIz8A
	OTHa3fKeddq4s3V5vWo0LUw=
X-Google-Smtp-Source: ABdhPJxb6RSgrRXiTyfY108Xzf94qzAjozgqi0FPKv1n7GQGoVscHL5H95o36GvHJEtAvst3qXsXSA==
X-Received: by 2002:a62:7905:0:b029:197:f300:5a2a with SMTP id u5-20020a6279050000b0290197f3005a2amr2441455pfc.30.1606298796852;
        Wed, 25 Nov 2020 02:06:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ee90:: with SMTP id i16ls1232881pjz.1.canary-gmail;
 Wed, 25 Nov 2020 02:06:36 -0800 (PST)
X-Received: by 2002:a17:90a:17a2:: with SMTP id q31mr3341437pja.51.1606298796380;
        Wed, 25 Nov 2020 02:06:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606298796; cv=none;
        d=google.com; s=arc-20160816;
        b=AOzLAUH+vTxUpzggWyyUupuDksUb55ozTQ1wK6D5nNuUn0aXa+r5WvuVZhPEpzvrnw
         WNArNyctTmHeIaNhIeh5OOCfmMZ2cf8f+mv3VO7GzgTxLLgpVwZEVS9CtzZxSdQaveR/
         IbfxgIcPkhFdOyLvojtkR5fBHpcIVWS9GVp3mJfdL9vDBj9LKwcP0E5dhA+emUvlBD0L
         Qsn/+ayuHj+M29wdB7TtRu5nVzlTK41fRUQ90WaOU/v92HE9gpGS8lqQBlYDN4T/kvHz
         y339Dyq8VMTHFMTQtTmXMHz6DdpA7XQ9CD+3K/njKB8i0mapy/uV6yKQVpM/y9+F5tjn
         YInA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=y/vgrGNb5w4mt04GLptV5XZnOujGwvPa3dAHg0iwkjo=;
        b=ue3K3/pDoEmdpDXFuLB5NTnhnFvFNG7qD0AJeeDzFfpqzpEUxEE+bwOi6DhdZ9tK6U
         9rw/f+Vc/PQo94xkUVxgyyELFQqQHuYlHAeMWbjjMgZwt6dEaLxugYol5XY2CiedcCq+
         BONBUHCLbp8qONmmXCa37GZctFK9LGoKsJ5eB+ucF7+snktbhv9uf5Khr5LIR62PpovX
         TMWLTprV/NGXs1yXZqANU+Byccmc+zEKMIs0bZDRXejTMvcJAAA5/HhrHjJc4auHzB+H
         tcyKNHw47g5NJPMJy2jku+CtI8rrhSlt2CCuG+Bb9dh73usoPbvTdDXfkmNZkJF0cvFr
         hSGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e19si89605pgv.4.2020.11.25.02.06.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Nov 2020 02:06:36 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210293] potential kernel memory leaks
Date: Wed, 25 Nov 2020 10:06:35 +0000
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-210293-199747-FLJ3YYo91s@https.bugzilla.kernel.org/>
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

--- Comment #6 from vtolkm@googlemail.com ---
Thank you for the pointer. It seems indeed that the patchset is the cause. Hope
it will be remedied soon and not progress further on the 5.10 RC train.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210293-199747-FLJ3YYo91s%40https.bugzilla.kernel.org/.
