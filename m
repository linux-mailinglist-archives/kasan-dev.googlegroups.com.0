Return-Path: <kasan-dev+bncBC24VNFHTMIBBUWM2CEAMGQEF2PZEBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D1023E98D6
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 21:34:43 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id w11-20020ac857cb0000b029024e7e455d67sf1850136qta.16
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 12:34:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628710482; cv=pass;
        d=google.com; s=arc-20160816;
        b=ug2qA01xFGd0TD64NKMwtUuX4LP7SdPGMw1VHgpHHxy/aJzuNCYB2tk/WUU9ci34PT
         ovOiF5aIIBsm01lV3TA3GIvKsb+i+ZnktZE3izJe+QL5OXsRKhp4+klf72Kal1BQQR7T
         DAbD4zuYMnOGkHHwAnyZgLeoBezOxzXxMPdJ0BdagX4GLhc+/6reTbrBQn73nkWqJvH+
         KaXndpC/z6meQu4RXCcZXWH4pXBVt3UkERmCK38cd/kAknpf3PWmh0D1+htiZXDJlBqR
         IFNlGYu8CVt8Y5nyrzv7r4JoA7CC6BaQGxRGYBVNCi0ojcXSPvmizJ4UnQS/58ShNvuD
         OriA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=7ArcDHeetap1HjzzyBfbUDEaFqMMXrb7r1O5FDF19HE=;
        b=VeDE+SlRnvbRaXixTaqZlX0qEiGRY6ZBId8cooqBxqCs+dGnAHiXJt8cFTj6LCjknI
         5YmI5g4x90ZjarrS77+D90L8Fm5Pp8PxTUTnu0HFzfy6DDC2AYIIHkaFjiG+cykpvHgO
         l9DLCjHfumpAZDv3WpKs4BUUAZipVvEyiqpsRzCEoMxfFFDFlqYMH/La8ya/2msuFVw+
         EfaTkaqeiy13BkkfUypE5u4bSEMdAHhH5LVIXuw+P0M3bEbAZcylEBNPAjLQSCpirssY
         FBW7GrYhmGm3AAM4qBwinlDkM17CX2KSMxg+3QewOjbvn0F7Yw8CQYGw5K3f0yyxKG64
         zFiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AAAasb8G;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7ArcDHeetap1HjzzyBfbUDEaFqMMXrb7r1O5FDF19HE=;
        b=dgjscXUfzLnSjVLJ4DxpKLKldXZf1TRVPuRfHfTsS7uxM0l46yn8W9jM2fKvaWKs8L
         lo6Xw87fYbmhflD+pBWvqn1ivBbQC+BYYgU6/8ooI93msRW625lRgl3KFiD3b23ic5Lv
         0iRFy17QqeVaVVFjHZHD89KSN7LvZzOvcIkJOdwyk/Osnk9vCSmCcf3nNadhSAjZo1vY
         9YVrE9VfLvzo6bVqs3u9DZhob4yhJgFCJmnNJi/LniGx9NcFOHmoED00P2ydYlBWVws+
         UA6AsFSdsvYjuvZAIkkl+Z8WsnN1I/r18GPTwowIo7ScgE0lfH28IR29YKZoNL4q7dxo
         vAPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7ArcDHeetap1HjzzyBfbUDEaFqMMXrb7r1O5FDF19HE=;
        b=L0la4x9fYY15v7NtnuqiIgugOjrgkPkv+nwnDHxllQ2D4on6MWyaGmPrc2Fv6sh0Lq
         QpZo1aF21Pz0+WqQqtN/WRmHhlrHYkp1SkFYSf/6cL4a5Q0uD+6iYSLQy97VF44b8yYU
         PnbV8dtdH1MWEdrOzYg9xR8GJcu50CKY6GbU1Z+txNDQ+wvKcPk28GcgNpjfkT/XEMSV
         +v6mD7rFHQfDrzhaS7NQ4slyNe1kYoB44aG/q6ddOy/nsqmrmyI9uPX/sCeeZJsUfyLz
         it/t3mbNsIFq032zrUMRhu1nKfBOhJJRbIxGrCh5LZkufZSCVCdVUoQaMehVOEEXR6Jl
         M3XQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+c7wLWfXeXEnZzKPqeg8NXNwBiYu3P7f7RYOAMP6cpz44ev8c
	Oo3WDVe2WU3UzWVqWyXgqq0=
X-Google-Smtp-Source: ABdhPJxEikShsVZrwfvfXDcqDO/5uRIHUmXYjgC8fytLhpLYM1txTxwPoIdJm8VgujECZna9jvMIiw==
X-Received: by 2002:a37:a888:: with SMTP id r130mr692826qke.78.1628710482674;
        Wed, 11 Aug 2021 12:34:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:d619:: with SMTP id r25ls2082678qkk.3.gmail; Wed, 11 Aug
 2021 12:34:42 -0700 (PDT)
X-Received: by 2002:a05:620a:811:: with SMTP id s17mr664990qks.350.1628710482226;
        Wed, 11 Aug 2021 12:34:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628710482; cv=none;
        d=google.com; s=arc-20160816;
        b=pcT7bUSf96QB2X/QEe2nYq53o5HJknA2rvHRPmm4sw7QtJ2++BMyZfPGTWgpmLtGkz
         OpQ+ZPBJPP0m1uKyNzkEaySGAw11F6g+7ERz7cK5s3cSF0ZSpuC83QpsCl9N20HdJt0C
         qiO5mR50RM27TI5ouhRGUwQ2XPzG73XUVzqyBhv0eNQhD+8VxWtnvGzR4ZTHi8LB3Ni1
         nxzRXsQCK83PZ/DAxeGOfQxEd43w12vP+5p96cYzY/LPWzIYttq73EdafIf2ndbwldEi
         wLvOjqhKi+dYh6lt/AQKJLsG0x1TUKJFIRjHaWDypGMPdmbRNZSiAiHoQ06WCyySgTNz
         nFlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=NoVnVMRUkB+Dn2oBFaCAAnYxZLjWymF0NfLXu4eBgME=;
        b=Q+UAr5IexEDN3XNrmuyMEvv/9NC2Nk/XA/HoqwnT7fRScg60Riv3kLgR6WZGv3t2d/
         rGhgE3EKP3MdnGxQG5Zcq0Qs+sO1lqjakZ88b8wC7SDGi+CNwwd+RY+FAGTkfT+277Wd
         PMy5BlUIzbqXUUVVmbXhW+snVGalcUXbNZfNQhvh5axsogl+zW/arFXRIdlSBKyAbxPY
         Hc6C2xvkMqmQXQYHtOa86NfvglHir7rrVPXTpi9RrwD94H/rruacX/CQeQnKH/kPtvnj
         K2mYbkgyb1drv/UWLKEKrrUAaDRlbFVV8Ar5ZfXLa98bfTsX4IX8xh71HmduAl/PCNIU
         6lJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AAAasb8G;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i4si22368qkg.7.2021.08.11.12.34.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Aug 2021 12:34:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 1A61560F35
	for <kasan-dev@googlegroups.com>; Wed, 11 Aug 2021 19:34:41 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 0EF6060ED7; Wed, 11 Aug 2021 19:34:41 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 213719] KASAN: don't corrupt memory in tests
Date: Wed, 11 Aug 2021 19:34:40 +0000
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
Message-ID: <bug-213719-199747-X9euv8YeZc@https.bugzilla.kernel.org/>
In-Reply-To: <bug-213719-199747@https.bugzilla.kernel.org/>
References: <bug-213719-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AAAasb8G;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=213719

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Series sent:
https://lore.kernel.org/linux-mm/cover.1628709663.git.andreyknvl@gmail.com/T/#t

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-213719-199747-X9euv8YeZc%40https.bugzilla.kernel.org/.
