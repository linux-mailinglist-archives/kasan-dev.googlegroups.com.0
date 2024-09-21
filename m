Return-Path: <kasan-dev+bncBAABBSHEXS3QMGQEJUDJXWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C6BEA97DEE3
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 22:53:29 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-e1159159528sf5850226276.1
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 13:53:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726952008; cv=pass;
        d=google.com; s=arc-20240605;
        b=UfozS3qRHxynUGreDhDk/reP7RqaGtbqlE98K0eecbslUSfsRg1o3k81Gqlnl8s3Tw
         /q+2N9WtgVTsxM1BRw4HSGJm00qbBcF4uXhgZRTlsvs5654Dcp0zLvCx2My7fWfEosXv
         nTQu3Z9eDEuPJpTFqkTsxnGFAcL9b33B9me7c/5GYAFz7DYXBZ1ddelyvuf9nf66jvh9
         NY0iA8Z96QXs2g76nQbKR937Pv7AQO25+eNsDExHmRXHmoeRJv3nCnT/zdgjUH3AxXnu
         7x9cp0MevicIfET+OorpLPWC8qY2TYBglhNojGV3pK+devlr5P8jKqTTXUHpSEkbtzEF
         x3RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=N8+sle0QauiaeoxoWSVDLqjDAkU+pJej//h12wziXaY=;
        fh=4FM8N550L6P771c4E9D4EEbakd6QUyrK2zDzegVUJa8=;
        b=aw69/fl+ScMQ4p8woat2ZMVixfiTt2Y6PMsBW+XHrgAapdQa2aUOAhPGmoK3LCMnmE
         e3yJn6EQQShu+CraEzKhKGX2+p7kXeKUAe2Owg6ig/MM+TMdLEM9uf9RPskLmGceOEQL
         fBn/xG69mm3Bsj0NDVzugQfUmhw6RtdrzD7lbllMuF1vL+1TC2+WihEXMlu1qKdE7q7v
         GdA59nL5YaARkj9TXIp7g6L8kR5+gSt3vYC3Hl5KNbfDuHDv4qVjKB73SUd1crmuEiJJ
         37zXp+KAF6SOahKN1e9mGcByvGbyqSrSZ1B1b364OGQRH/EXaycAGEOkkGiaPIG9iFDH
         V0vQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Jz+HKmAU;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726952008; x=1727556808; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=N8+sle0QauiaeoxoWSVDLqjDAkU+pJej//h12wziXaY=;
        b=WX7OFzMnGqsQxz8HXOgBv/HpMehzSZQyFlBU7Kv5fj3LNhcJquxb+1tM4Z6fuGn2iM
         uZBnAKhCjn68k6AgBOOVelMmtwn3R7P7wXbO6P6IlyP7uX4IGiAku6bkXkKr/WtkD4xD
         9dj83LN6yLFsBaMilHMoByOiAtN14OTbjo+Hk6iQ9dQjhFrsWEvk/wRz6Dh5MEM8YpsY
         KCt5ND5A2urnf8XhBI/NQfDRyQBo8TaFnPyiLdMlaHCSEB5pv7CReDStPZvm2kQPpoYu
         AHrnM2YgopyjkAEiIyPRuBMb2aWT5ZuUcMsYBotxU2otvx/w7WvgSNAaEIB3dyCsMzJH
         xMdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726952008; x=1727556808;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N8+sle0QauiaeoxoWSVDLqjDAkU+pJej//h12wziXaY=;
        b=sNDXt2sP0igS5HSi0NWn2ffIYBRorjUNai9njmW+tfL82cwjzZivCP5VU44mkuJMbt
         g0sMZj4hRVoi552RC8O1qtFKlokblAA+8zwlqgiA5cxDZbxfebfxpqPzBweXl319gohE
         0sreEZVgYdkSXekXJ8Uminl1reuR/2AzfLgUq+ZDAbfBe/6LhVUZD69QR/DLDDfBCEft
         0NYqsoT+rbKHZVwTqOwCtHDmM0uPq3+47vmzgZX+QgTJkjn8wuRAnclV20ujMioKCo9k
         6HGWL5xsGEDbTubjA9++3THNVR76r0Qu5YNhU9hUIzMA1bwZ3Rxmn9Ktatu0X2p4FH5M
         7y7g==
X-Forwarded-Encrypted: i=2; AJvYcCV613NFg2PTujN8e0LGiUa0D0mJHclYgP2W5ejjsyGV3UpSVHdpObTEF8VyhGAwqmGnNEgNIA==@lfdr.de
X-Gm-Message-State: AOJu0YwvmrhY8TwFgwY/+9pt3nDIu8EOQdu3o3rKD/MMfKHtYlZsg++O
	J93eqfxvxoGJnB5yP2BBOQbfkbP5glF80/CO+wPad0Vz6iLpc4iV
X-Google-Smtp-Source: AGHT+IHIwEkD9887mg+KPLmdshqPPGTvndqUA9sKvwzeByfvXvxwuQgnIlil78O1PM0Xjj43ow45zw==
X-Received: by 2002:a5b:8cb:0:b0:e1c:f0c3:ce1c with SMTP id 3f1490d57ef6-e20276b54e5mr8496985276.14.1726952008295;
        Sat, 21 Sep 2024 13:53:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1542:b0:e03:64a5:8bb0 with SMTP id
 3f1490d57ef6-e2027e5334fls186268276.1.-pod-prod-00-us; Sat, 21 Sep 2024
 13:53:27 -0700 (PDT)
X-Received: by 2002:a05:6902:220b:b0:e20:104a:5422 with SMTP id 3f1490d57ef6-e2250814ec3mr5119375276.18.1726952007721;
        Sat, 21 Sep 2024 13:53:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726952007; cv=none;
        d=google.com; s=arc-20240605;
        b=Q0KVzXO52JSgVh85dPkX6MH6VlV/sB2LuiMUGW3fYtRlMkAgpobBMbANnh1jeZbgXF
         t6o2FNfuUKBbs+Ib7u4HGYo1xhEnzyWYQxWA8RVk2YQV2BDB95llFC9lNOyrfA9IOL3u
         xC9GVbIOvLIuYD3IqNWuigMFQx4JfFV71x+t93zQiG1wXaxlpZ2bg3faa7HiDldqZTj4
         hiAeZnks8/wpJ9H2XTR0eq8pEu9NxQMmDNUdtVeRSrfj2zfAQzmcRe18eKhtjtbDxNA3
         9uyf70MeAbTe7jK4oezYAiwKVWLV2WwbBcr0/kWNL5LeNcJvunBUBRYBUxEuDSpSWwjp
         p/xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=4RIKfkQoSFdP/cqYseigXNuQBnE3YyBq70A4TVXhiqU=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=KucZK/RCmjcpAhw4qmiRiCXyBhWXaTPRBPrvTHFMHcDvvyqZMSBhkcC7vPFZ9KNaf7
         aG4Xjv6sA1swuRw7VnW901qf0rUUGQuUQG72reAZsbP+qIXP32HgsJMsmplQrtN8p3QT
         seOhlCGlh8w+WJNwuavayF7WkkEXmYan5angfO6552sQEXk9f7O8GeIVF8OKtDGc/SCA
         C7afnt3Gd3Zko8jy/D33odImd+R1Bez19+BfKi26qCOhobRlFT4ri2FwpYWUoEp+84LG
         WY0FKsOIBsR9yB6aVAILPMiFch/CJJvXlFpuXEOgvH3qyM6RM4yGiLV1CiM04ihcHjDN
         Mkjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Jz+HKmAU;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e1dc13a3d91si207909276.3.2024.09.21.13.53.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 21 Sep 2024 13:53:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 783CC5C03A8
	for <kasan-dev@googlegroups.com>; Sat, 21 Sep 2024 20:53:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id CE21EC4CECE
	for <kasan-dev@googlegroups.com>; Sat, 21 Sep 2024 20:53:26 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id BEC43C53BC7; Sat, 21 Sep 2024 20:53:26 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 214629] kasan: organize cc-param calls in Makefile
Date: Sat, 21 Sep 2024 20:53:26 +0000
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
Message-ID: <bug-214629-199747-FRh5u9RiWo@https.bugzilla.kernel.org/>
In-Reply-To: <bug-214629-199747@https.bugzilla.kernel.org/>
References: <bug-214629-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Jz+HKmAU;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=214629

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
Resolved with [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=78788c3ede90727ffb7b17287468a08b4e78ee3d

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214629-199747-FRh5u9RiWo%40https.bugzilla.kernel.org/.
