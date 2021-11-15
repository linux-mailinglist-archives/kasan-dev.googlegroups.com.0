Return-Path: <kasan-dev+bncBC24VNFHTMIBB64UZCGAMGQEHIMAOWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C27F44FF2C
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 08:21:34 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id i5-20020ac85c05000000b002ae12b76e64sf12784819qti.6
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 23:21:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636960892; cv=pass;
        d=google.com; s=arc-20160816;
        b=BLYhTC9az90Z6/PixyQeUBbmfnX2pFSPZZltmT6VIPCtK/ElGBV9h2OwyrLevsMccU
         flLtYSHAxKwkLu+5HcGKnECtprDuLM0QroIs+f/vb0No84/4HbTH7UEVYlGEbQGTvHm0
         B9taQkBP4jt7VpjNPLX68UTS14ORfXJXRZLzjzzX6NxTVd6N/o0pSJ7vuVtxY8XGXUT2
         G4/rHdZ7dr6onKAuDLUvexm1hctJSUvdn+e+juNJrR/Ts2Qt2HA3fUYHJMWdNoatoUYS
         Z5I98vhkGN7Qpq5PnyFT3SCKqktxeThtHP+j2i5XN6UZ3kUX0luKzO1xE78KORObNlvh
         bptw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=txVYACVitVCQ8h4AGKhn1r6VezLPRZ6agtWowl2GIA8=;
        b=dAUjKT+fuF+v6SrUoOnz9orFzMcuZBIuUxTJpia8DEDoOXCLAbxgnj3a2m5LQc+xmc
         QrcXzk3L7opNITiUgrjWniflu9iFJZcWOzpAK50ZFFiA2TIhmwmahQ3gN5NcuVM/TGdr
         /+fARKCbih4WRigtya/ImyAsLWoFxYElzlHrz4Mhxxlgpggl/xrB+Ia0noPFoH5qFkoE
         dhH38IjsOPCegijP480fwCnPN3Y/4mPxx13NOgvpX42feOapARg+DPDxgHUMEi+31wYx
         FhRjq5KnVsTPigJieu0Onby6FQmbraEfapPfeZYUS6SEQ/RFwkRJpem7qvClhx6C/J+r
         QTiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZMg296ZO;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=txVYACVitVCQ8h4AGKhn1r6VezLPRZ6agtWowl2GIA8=;
        b=WG+E+Xb24OUSK1eIkjvNGGRIGzycFicpTE5/deK0l4ERBrVIHMnqqKW9XnKICbRvCx
         puKieA1H8QsVxehj1fSebj/fRdxNj/olm8ctyXba5vISdujAarJZUBoqqnOtB0BFgMFW
         YfHETCmy3ZfdTapMFNz2yKfCa+3QUGAM/i0YrokbHb+s6wCp0jxtx3Y006VIC7rZ2Hld
         h+RDXMRszAa3atOjSBMU+jb7lQQ0Fur6vb/oUmUxrne9gHZ/OgyU5KQtUIx/c0CKF/g5
         2UEFkNsWr3JzyVMH3ULmpD+utnOYZFq6KSZ7jTls39h11riOMp/I4FTEdkrfpHOQUxbX
         V9kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=txVYACVitVCQ8h4AGKhn1r6VezLPRZ6agtWowl2GIA8=;
        b=QNuDtLrYsES7P6rpXSLSxkQIRfVabdd7IuNL8SgSUzwU9d46KU5qGpFwaO9DZ6+i/z
         UY1uEVeWvkK2W0wsEpFSql+sTbn5UnOSUkN+uyhorgTFO5pNOgtnQzjg7QvtWgpAxAMs
         jhJ/yroGX+eedOojzfdJNR6sr6F4soploXw5g8MBIxLREmh77GekiEylqqdgl030b4mf
         PaDQzU4xNiuRGfN6QnosYOWxpAdxngGeZoPRkUwx9xaM7H0soVtKa6aJR4imBtnndYw8
         hDdd6/47PRUdLucBqcjd2HB4KHDxynEvkJyLo52tZY/tivuqjI5AX2U4wYeV64CS9mLr
         Lsug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531dxVn1DbiZ18nLcJKQNhi8dt33Git9aqxGDXYiU3CL3agtvnSm
	Gc1DbmPmLoWCJQZPdGnhMb0=
X-Google-Smtp-Source: ABdhPJyl+k4QXUweohViHJwKZeGehy6Hdsi3NISV+jcb5UyasyvXcxLpwJuWA0dBnV+6WN4sX8eINA==
X-Received: by 2002:a37:b781:: with SMTP id h123mr27571914qkf.491.1636960891207;
        Sun, 14 Nov 2021 23:21:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5fd4:: with SMTP id k20ls7394735qta.8.gmail; Sun, 14 Nov
 2021 23:21:30 -0800 (PST)
X-Received: by 2002:ac8:5c03:: with SMTP id i3mr16319722qti.107.1636960890850;
        Sun, 14 Nov 2021 23:21:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636960890; cv=none;
        d=google.com; s=arc-20160816;
        b=yJKD3SecNAGXxyWaxmbXneKaEcICLk7fY+dRMZ5bWcmBHa2BV+ntjdpQUA+f63zXJD
         nE3HF9Wxq7g3YyLeI0AoY0DaEFFziGMwP9zghfClB5B9F3AgOQxfKAqS8j9TG+AT8DuR
         Br/mw7Rh83KViZf3gi+fC9B8+luiJRPbJogjRDUoyprUILrG7qDAPTnJ06EL+C8zGEyN
         +GSAFSb8vF61zaflb9IXb8g+dLnVd+9N7il5bIRI7P/+8W9f7vGrgS8ZzzlLRcbtwIKI
         CFhWGydGAS/yWRtCtC06EO2e6oTudskpgUPui8Z/jATPVf/Vy513f4QTitCZHAdKINfS
         W8Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=y1wC+K4l88SFyrfyngo5WEI98ogUfoclVpocwftKDnA=;
        b=G+FUBHKQrYQWUU3F6FRdVCpFqaYA5wMIvZgNX1c2IvZvbUCFGFuVoDz8+Fo/SeQoxj
         lz/2XIbICrl/hmFr2hHdwJ5v9mIV5MOwiiqpm5ZRuDSlZ918mAURSNOAi0YrFLJt8sKK
         zaHNwFJM8BsrRZ8DohD+7Ok6IJ86OmiiGUOxh9d+LWe1TYwG1IjqShyxy2z1QJfkXmTV
         maX288AfxnH0n/zBB0XCMoAN/LHuFRRkZnxDgSuosJKbai9NsCO01Vjg48FZlST/mjAj
         0yx/38WPhN0VepWu1UuABkMFM0Y4Imx6TjrxOknhbh2whT6hfMAEPYQ00Re8rJJNqIhd
         jdcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZMg296ZO;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d14si125343qkn.4.2021.11.14.23.21.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Nov 2021 23:21:30 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 3991C63218
	for <kasan-dev@googlegroups.com>; Mon, 15 Nov 2021 07:21:30 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 3608B60F51; Mon, 15 Nov 2021 07:21:30 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203267] KASAN: zero heap objects to prevent uninit pointers
Date: Mon, 15 Nov 2021 07:21:29 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-203267-199747-qdol4dSgA1@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203267-199747@https.bugzilla.kernel.org/>
References: <bug-203267-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZMg296ZO;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=203267

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #3 from Dmitry Vyukov (dvyukov@google.com) ---
Yes. FTR the config is CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203267-199747-qdol4dSgA1%40https.bugzilla.kernel.org/.
