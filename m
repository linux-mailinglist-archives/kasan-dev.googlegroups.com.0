Return-Path: <kasan-dev+bncBC24VNFHTMIBB55P46CQMGQEBPQ7NXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 3114B39B410
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Jun 2021 09:36:25 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id i6-20020a5440860000b02901f1ccd87497sf3497019oii.10
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Jun 2021 00:36:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622792183; cv=pass;
        d=google.com; s=arc-20160816;
        b=QmHcdGy2nocP6YEKd4finkVQlQI+/jj7ru607ZRq5z8C9YgKfnL40UdLYMYniEZtKj
         NvLyeJrRla258VMF6lLaG7J/xslX5TaiBvuPsDX0Ck/HqovZns69b0rbAQdGpCzVxnrx
         adf2U2gTdtwI0U+NyJFYHgTbPbQMA5AdGDtv6BJnhBC5MbVYb3VkcnFF7rw7CY5RQl+h
         KX0OEFa+Ay1B78yYTWqfPzk2dGE6aSo+hTS8Heaq3x0PiiZiwsCm12WE+4/TQseLGvtK
         3HyUoPze7ifqEgO6x3zQMPM/FqIl2IvAIkjHU9hZZqNoD8Dz8f+P2Sn56vGkmz79VKwM
         PDlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=lQK9ScX45fMg7G1CdynizeVNZsyIh7gJSjXHIp2W6R8=;
        b=n83+Zv6hGqfawMQahripwVB7qSTD3fGBXf7AkuW5ridw4bIiTzWgMgw5kQFzJdrEbM
         +d0vvAfUo3FdnYtPt67VNyiF6ZJt1ao9pMqP3YZvqxdzC3ivR1htTD2OQnuIsH1JY2/x
         zjvFDhghiukfxC74edFrUprulpv6Lpgqsdx/y/6Ois0umtp77fJtB0MSvbybwoNKq/TK
         h4BxgwzVtAAoR2U2zoYUXEQUlzGuE45IxrfY4+26naDSGN2mH0WvOftGmAZYef6L9Eo9
         /GG3GVda7tF/M5i9QAYOU2z6A6z3OLYD1BTsivFrg7AEi1E12666aYv/7UWE/VgN2ZMa
         +lLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=R7jl3ScO;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lQK9ScX45fMg7G1CdynizeVNZsyIh7gJSjXHIp2W6R8=;
        b=rMbk9CYJujrD7w+dTiLf8ZC/CMYyC+jAFbOehxccDg8ELyIwp1Cz9zo57+mUZxow9T
         7b6i4caBR83qqbo3JY24d5iad5Q2H3RuwSXDJYxNNIxKlbQUo7dBXoqi42bLWCUspE7o
         KOq9fJurRcFTHXUlBQSLtjBMzUmH6KqyVhx1exZNYwJOM309n9Rgk1sfZJYPMg86XdV1
         N7lcLFkI8VLMNKdjgY+p881SSlAoRScgdw0o0aRjN9MGWUzek3bproM6XDclmEZSq8BE
         gADvGPfebi/0+oryaFVLi0o7VXfvqgO6CQF6J8k8VXkLiKzuVPPoeS+e2C6eYK3GUpV/
         IenQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lQK9ScX45fMg7G1CdynizeVNZsyIh7gJSjXHIp2W6R8=;
        b=FFodPDoUuOsG8P4lxVA+44G8DeTyInh4PmSH6SWaHVJFYttgxoIuBN2Qs1jYjtzWr5
         gP7LodFT0FvLvYOaG5Xbk1KQEUXvvdzxPXyUhOvSfPK47wfREvNj/7Z8NLHuRG+nEGey
         cu9bOeth2Ak6Y8/nGoAskJEwpENBOY4TjzU82We/oWTH0aKr7Z0C7Zrnt7VrxPomrY88
         S2AhmYrh7GhiUJgShgIGkHKYdb5eFqS98DNEV47SUcXW8nq3TydkfRV6Nhlsb/B4HOyZ
         ehrw4xeZqa+lPhNtgyQd+Ane/qe3mna+V1a31ERLScjxpM/mA7u0wNIC5X60yYshjZ1o
         MTig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5305Tj+dYTIXGfwVHdTQrkpE3souB3aO2X57Oh9gxc6KYvlf7L/+
	I7HOmQoC7QS6S9ZeeIqB274=
X-Google-Smtp-Source: ABdhPJwUmuo24f5fhuY7vfKp5pSxDh/F2Kn+KwawcJ3ObZ+6Hc1WbWy5e6wSSZz+j/wDt7mrI0JRGw==
X-Received: by 2002:a9d:4046:: with SMTP id o6mr2626385oti.189.1622792183818;
        Fri, 04 Jun 2021 00:36:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b102:: with SMTP id a2ls1044616oif.5.gmail; Fri, 04 Jun
 2021 00:36:23 -0700 (PDT)
X-Received: by 2002:aca:5701:: with SMTP id l1mr2139115oib.128.1622792183497;
        Fri, 04 Jun 2021 00:36:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622792183; cv=none;
        d=google.com; s=arc-20160816;
        b=c5waDdTxbpyO75LkM9U2+O3vt84x/b5gvgAxZya6oIllDguc8hXUAOzoIyzeGkoIyG
         Zu6gGJSWTPp3cD2HpfLwhHnVG0myhXALibjIeHgJpE0xCmUyrRnoaEzMVqYJWczrMvGh
         LGbsMDdCKH1wixNfaq/Ho3IeVTlnUVo1a++OqIzynF0O9HA7TQWJ4t6NWzZbEqIWNTmu
         HnKqO2Qm6VBQfDcC08gadtjLJ3CdndB3rcMKvk1Pks97IqJkuhyPgfL8UT5FAiqOH7sJ
         ASqw2iDl4jxeLmHmX7iW1VdcswlU/xdUZPnkkzHhoIWSQdIi3lgjQpoZRf3MytuyMQru
         3FeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=uIWijQPSa78JzY/PNC9FrXVFY61Uj9XhwA3He/S4rDs=;
        b=lNB3ca1TjjGSbBLZP3fsjoMvwg8KcHCLKS5zEgnlAPE64GLrn376j8SP92OUFHcLhd
         pKQrL/O6i9YNzsn913FocevTD+eqGjCDQ2EIq5hAxKmfqsuUImo1UIGDDFLXjS6oN4of
         zJ0J8ABh6e2CdiVKjIytFWAiJL1qCBbQOsGXUd77cvahBckkPIS5293Yp6xBgGpXKv8J
         BQchcqtIoabwdNVEJCH8FmcEknbqvaYvqvvUK8n5jEd93STpXqljpVQQJzQQP5cpI9wU
         K7n2vQhdHX0kvnJRnBD7L6fDv5mV7NELnmYlU3eLRQuQ+osbuoyBtHsUYg/oh7y30WUo
         Zi1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=R7jl3ScO;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 88si145536otx.3.2021.06.04.00.36.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 04 Jun 2021 00:36:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 9C31861417
	for <kasan-dev@googlegroups.com>; Fri,  4 Jun 2021 07:36:22 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 8FCB96125F; Fri,  4 Jun 2021 07:36:22 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 213335] KASAN: vmalloc_oob KUnit test fails
Date: Fri, 04 Jun 2021 07:36:22 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-213335-199747-55woCHksdN@https.bugzilla.kernel.org/>
In-Reply-To: <bug-213335-199747@https.bugzilla.kernel.org/>
References: <bug-213335-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=R7jl3ScO;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=213335

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |dvyukov@google.com

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
Stupid question, but to rule out simple things: it may require
CONFIG_KASAN_VMALLOC, do you have it enabled?

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-213335-199747-55woCHksdN%40https.bugzilla.kernel.org/.
