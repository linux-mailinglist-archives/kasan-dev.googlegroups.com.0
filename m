Return-Path: <kasan-dev+bncBAABBCFC7C4QMGQENRP2QZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id BC35A9D4042
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2024 17:40:42 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2ea6b37ed73sf995304a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2024 08:40:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732120841; cv=pass;
        d=google.com; s=arc-20240605;
        b=bOPfmjOPmCHBP7qGjkguVRjgyqvXj0oEctFlr5Yp4tL2SufToVKsOfDlBI3QkQolHs
         n2ImL54y2zE5Ua3W38iKRTpUz5d7w+2OXI+6bjw4T7IY6g7AOzgAoyu/QMyZPNEvNyyw
         ITOJMA7dQYaKw512BdlaMxxL7HacTI5+dMnOB3mnoVscL9Y/RHh51sseZ6g3bK4feYxq
         Tsj+hhv3pICuYjMNYksrt/QFpTTqY+UksKJkEsgVStJjRtzXrYVA7ft/OFehSf/6GdFy
         DJrvHJO9LZUCoMllwU7Q1HqVJLPvTzUnbOIYYiJ/gtVhwxbE6jrNby8U+NqQ8N1ta3P3
         gkCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=wI6iYMs+TsmJstKkGxDT0E8L35N+otnsezeuhUn3azQ=;
        fh=yc5uqSEUvjspmdNlyJhHp8yUfdx4IZMdDJPLZOizXEI=;
        b=bdDbDnleyOQ2vpHMPxIz0+VmZyBPILKMjxyk7Ohqa0zb0U8r0GU/ehDSCvxP6rcRRg
         Em6ERUAF5FTchpnH1aT50D9xMayj0gtpjSM5p/IUtbywtAwC+C6jLUnqQvWxXY1fIyhI
         Rv78sKgVUaLvuZsW/IAGxxXMvpxZrmeExCQHizmKaO+74L1UdwAEBHpjh50YzHMYOez/
         iOBEYwM/HZ7etsgKOmJERXZGpTdcQaW5styYmWNVh2n6b9GcJ3golhfQccCdSRhZtjTh
         SW1eJx8CqMK50/EvVLmbbrw/bzmZse2x6vV9C6QTirHQcXq7eP9CO6WD5TkFCzBYQyOv
         8hoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WMp9yvU0;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732120841; x=1732725641; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=wI6iYMs+TsmJstKkGxDT0E8L35N+otnsezeuhUn3azQ=;
        b=M2SfqfmAhvVqKgpZgUe5MjN7q6iEMV53de9LMq9OzWkfk5bIDFwiAnU5MAEDVdZSVY
         IbGe5KxdjFXJuN0q0pBkPccnYspdhUiItJuF+/TMqfj4dSIqh6mlqHdzjhU4kmiO8vZN
         r0v8leUU09pKsF97ycbFIXd2Of3SR+RHQqtqUppcBq7VsGFHKzxnt+rEJZFQdtXYXVAh
         0d1n6o80y6iqoDp2SwzJbe7NCUBP8M2pPvgoeNBlymksAoBlnWcqfxLlkJmYquwmP2di
         0kHSk7oMz9wIzFJDD1ZnnciIJQQQhUeK4moU5SfMi80za/tHxeY4ZndaUlZFaSJhRCZ8
         u3pQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732120841; x=1732725641;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wI6iYMs+TsmJstKkGxDT0E8L35N+otnsezeuhUn3azQ=;
        b=XDg2P1xtPv7tBkSjMBCmlWKPECJGMYchBDFhdI4jOICxeOyHcs/rsGIOpUy6TLYfAt
         dreOP/PlpKWEmedfyDhIcV735ZLREXBpM0xn0x6PjfmpVHHycpkGY7juDF2DsAuCqPWU
         X6tmLYwZP1aZ/qoBjNJ/pp8AC3XZ3HWONfJvzzfrgNHLsUznfsrzn+oCZDAf4jnmY4cJ
         bP44JpmlCUzAprtyjQqxtPH51z1VGo/yClkG39chqXJv53JTb7W0MfQwSMVzjecXuTz+
         S97iaQuQiGgRPRURbkv7xNWOmAtJRfFOA//nCTFrtP16mDNIzss8YEKkcyRXRymNNab0
         PPtQ==
X-Forwarded-Encrypted: i=2; AJvYcCWrATQkkSLc5qpo7W/bjaPBnjMHJwUcl3dDsEvgQ0d+/dtOkf0lphjh/uIs+w+sMVxdx6D4Bg==@lfdr.de
X-Gm-Message-State: AOJu0YyalayqPN+rVTKMGYh1WUCeyKOj7d0SoOMjaKX1wSK9EjC3gFkl
	XwheN3SEF6W7upWGgCXgvhHG6YjE/HcWOyHd4imNrZ2CLnaZLb9D
X-Google-Smtp-Source: AGHT+IFEn7llbVxbhY5GHASOjcIib6RttvkKHptq+f1zTzk4LEmCPpjlUx2OBjZTAoNwLyvG6xxduQ==
X-Received: by 2002:a17:90b:1d46:b0:2ea:5fed:4a32 with SMTP id 98e67ed59e1d1-2eaebd8c810mr1079a91.11.1732120840787;
        Wed, 20 Nov 2024 08:40:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:374e:b0:2e9:ecba:8b35 with SMTP id
 98e67ed59e1d1-2eac82c1070ls22533a91.2.-pod-prod-00-us; Wed, 20 Nov 2024
 08:40:38 -0800 (PST)
X-Received: by 2002:a17:90b:1b4e:b0:2ea:7ba7:33b9 with SMTP id 98e67ed59e1d1-2eaaa7e79c0mr12392320a91.14.1732120838461;
        Wed, 20 Nov 2024 08:40:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732120838; cv=none;
        d=google.com; s=arc-20240605;
        b=lQ3BVvGGxBHLw55VpuMtA++cqbG+UJng9+dologQaPuGsS+HZhS9XrbwXzprfWvyVK
         HIpEVvITfD9Nnj8uxb4ZtYRq4+K6UppgZg4igSaDcUL870PF2LtXpEgaBCLm3laoTxVc
         G6qSKUjWgLctvj10rPJUv5KxvoNQQvVUMZJT3R1vNIFUGNkEKn+oFwhe28sao1nG6M6E
         Q54eANKKSDhgsLAvnkTTJbuK9cJlBFjBvtB1f0h/Dzr6KIzRKXJ/hdccbd3QJx+LNdxg
         +X3xEo2NWamx4aEhnTsKrcIUrIKfaxu7XTqMkEHtQxIKw8DlP2GVC2HWXOAD5UevC00D
         Y8YA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=6n6T0iDrIRrpYrBkiatCHfN3WRURZCtVF8tFHopP+Lc=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=S0Tt30oTiOKxnT2oYBSd3+IoaEaZ6bwUDGLcSuAxDpDaEYXD0hCRdVmF/+rH1QXeEK
         D0YzixjXxvR0lNkTqkQaiIzkH3uYFT0SDudDyKwnK5a7GPI0IK2m1NicYVpBH95zNqay
         1keITqkTpEgtQf6lWn6/YB6pGkrBG7ZtK8CVtE4SKTsiOApleQYQzoCV9HbFyOeo20aZ
         jL791I8OoiZahUz2BFxOd67vOzxem6jpkT+Xmby0D0G0p6FAa1aGUZZutgo7A4xQCUA3
         8/KppvmS0P24vfR+sp9+fcML7++HEa4lXfq37A3hcwp1ZmLP6Ixng25/SYs2CGyFeJvY
         RIlA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WMp9yvU0;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2eaca6fce6dsi265807a91.1.2024.11.20.08.40.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Nov 2024 08:40:38 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id D6C665C58D1
	for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2024 16:39:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 7CA37C4CED3
	for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2024 16:40:37 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 722F3C53BC5; Wed, 20 Nov 2024 16:40:37 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 218854] KASAN (sw-tags): multiple issues with GCC 13
Date: Wed, 20 Nov 2024 16:40:37 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-218854-199747-VPS3fM8xo6@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218854-199747@https.bugzilla.kernel.org/>
References: <bug-218854-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WMp9yvU0;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=218854

--- Comment #4 from Andrey Konovalov (andreyknvl@gmail.com) ---
Issue #1 fixed with [1]. The rest still stand.

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=894b00a3350c560990638bdf89bdf1f3d5491950

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-218854-199747-VPS3fM8xo6%40https.bugzilla.kernel.org/.
