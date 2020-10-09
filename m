Return-Path: <kasan-dev+bncBC24VNFHTMIBBDPHQD6AKGQEAABIMLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id CA48528866B
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Oct 2020 11:55:26 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id t5sf73365oie.10
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Oct 2020 02:55:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602237325; cv=pass;
        d=google.com; s=arc-20160816;
        b=uKGo0JBlSBW1SMpvB+azReCnM5qHtfYHQsTwfUYgb0HfRasT7xacbvQrEpYrCpaFkQ
         eD37RX5diF6T4sfGTUvk1Cx2wKNwEFmh69v/Jl+eLkUmPK39niRGgYwuYPJO2DrcqRh4
         BjDiT5MZGIkbKlwE+kukWKgwOj2RRUkd44zIig9EwpNkacpSlIoW9NAL5/r1E+uJGAox
         +4Yix9xp0Msl4RfCk9her9CoMZyuyDatnR/e+PPw4xnC7NQwMaplFcRsh/CcEHpGHQ8n
         8eE4pAN1N/9D2/WjaLoarwIDtNh2fN+KPWjX5LGwnLSmFXBdKbAn/5vjyaWqiFWHnHmV
         2/eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=bJonPX1ICKDOEutWqLskHIy8FOl5t3fqGWhBAmLs24M=;
        b=GDmSGiJ6pb4J3F8f/2xLtV4d4HYb4rP6cQ0Dv+F1vQ2/PrZKS54hcGCIdwpteiief2
         qZkK197bkjJBLAoWrtT3Hs+E6myPqhbMuM7f5ljf9FgY57dVcPgSHnUZdAcSphtMZXhj
         l7MjOadjnXNzG6EDppecDwp+IUJs5Pnnwc2eDyExAyS5uwa1GLx3iMpNdhutOIOZ2DAs
         XlDU/dep06g8chgbfe5GVlIxmQA5jR4S+55tRKmenCkZcG5yfr3Dn8ud3Nx/KACapfTa
         Ba7X+KV3y79tx/R5G2QfnKXQZ0gU9BIy7o3YyexR/g7fUmvugkcHZIL45lTF8owYyKy9
         87kQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=666f=dq=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=666f=DQ=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bJonPX1ICKDOEutWqLskHIy8FOl5t3fqGWhBAmLs24M=;
        b=kq1ZuRKf6X4MmWer92abmV/+mAsGT80aPqwcn9ZYtoX78xY0j2TndnZxAB1Wz1GxTu
         tQmCTXOw1e++iG/KDXCIXg8PueuF+lcVQWMRYXtxn3+F2YfYD466xIoyjQqsrXCRHnOz
         ejN6HlRYDb8sD87SHmk4PzGYPCNLfm2xG/aPwsFcUKxhI1wc14/U+sLGagOJUjHb2f/y
         umSJvatsareSkbStnoCSSORpKS6Gd2LcKtIgT579N0mTXu3J2NnbUV30oDipdFz1LZcH
         PgKaBS3WlGxduiYSibPUQMu5onc9H8EGsb9ZHURBxiqGWYah2dck2Q0EAgPo+Z9jwljw
         O2Yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bJonPX1ICKDOEutWqLskHIy8FOl5t3fqGWhBAmLs24M=;
        b=tHw7xkDG01zYo7jh3SzFhktuzv8Jer/EWG1wy6uRIQqkryrVYRJb6RPb9Nw6IkbNXF
         y3J63Bn6hZVZ/PexF3sHj8M1agZM66Vktn6nehe7mWKppkDhmwtwBX5s/sVa47p5wMgd
         PISH10kJDe9Z8EQs/dVwOyRirGpbpolgHVI+SHhL9AdEfY8mLKyzgO5YIZ0IJAVr99dj
         68vkG1+kfGPUjKn4KLmANb9dhSxWp3Iw2M0BRjSRNIe0DIMukJjyZnUpJ4edIrerNTF3
         yFDLgYc/lvcYjUsAZgD/XM6T8q0VJ5HiKHCJdc2wyIMGghMBoDIaKN/4TPVQvgXPk3en
         i89w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531iEoCYZ4BvcFpF73od0SLCcNeFLytscoehKTDo6vGejIEM6lhX
	GtEqm7/ye8ovEy/XOvIOm1E=
X-Google-Smtp-Source: ABdhPJyDmqU/CbQOyJoZABr/KDUAiyzHNwy59sq7pFGIcrEHtlGEkE7oHmSk2uXHneBpYNkUgMwiiQ==
X-Received: by 2002:a9d:7b59:: with SMTP id f25mr7937125oto.306.1602237325346;
        Fri, 09 Oct 2020 02:55:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:3741:: with SMTP id e62ls1948617oia.7.gmail; Fri, 09 Oct
 2020 02:55:25 -0700 (PDT)
X-Received: by 2002:aca:a810:: with SMTP id r16mr1996420oie.114.1602237325018;
        Fri, 09 Oct 2020 02:55:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602237325; cv=none;
        d=google.com; s=arc-20160816;
        b=S62azlfCoOKRe66zNckuEgJqmD9bSKKBOI4x7v4WidDJFmld/e+FIJT54DbB8AFjbe
         1HOHeQHL4URZMbtafF4kNgWQPQKG2y26j8QRpaC5PqLEemmCMlcGwuWrVqxDpSdao0Km
         UKvmSA4e3oipKI9PzONMLaeWF8m86tAqhbOvVIhJkikhtdyTpPTogTXJEA1swBxgk+ai
         zrotflX9JqGcjhu3ADe4TlXfDM/RfhBdyCYo0rDQluedVpWK3MsFZz+cGNnHCnacvCua
         eHruIyBtuPM5qurhF1G709UkQR2dxbPL2SPzOm1PwoNY36NSRAL6PWhZfwqbGK58Tj3g
         dz/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=Oa5P7hpz/nTl0QPDp///PwTw2kYDepj3+CfTdZVK6Ss=;
        b=YD2Dt73jY0EOabUyxm5a6ns2zliVCvKl2ikImhdzIvGt6hUm/EV4x8jlFb18E/CYbq
         viQCdwMk7fet120XkjKZvYV2qUnlpYq9pmcd2YLlQzuKzV6HUy7QNif4V74EdQNUrmtc
         Zge2Egm/L994ilelx0ETeOZ5Lk97rBpm8F3LoeRJK/zZD27Ud0zDl1orrM1UbpQ10Pgf
         gx9Qk8D20qn5/o9edJC9f3dKJ/+vE4m8rNNYnvxaX8N0YZQsbYpLtDX1t+TLkZ5wE1Uk
         eqi585UuuUbrnsu6m/HRHysg6nXBXp2S6lol2jNOLTolDEjbmz8uSVMWzt0MqzFQ0ptj
         w+eA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=666f=dq=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=666f=DQ=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d22si672283ooj.1.2020.10.09.02.55.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Oct 2020 02:55:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=666f=dq=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206269] KASAN: missed checks in ioread/write8/16/32_rep
Date: Fri, 09 Oct 2020 09:55:23 +0000
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
Message-ID: <bug-206269-199747-Vv46wjVIWG@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206269-199747@https.bugzilla.kernel.org/>
References: <bug-206269-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=666f=dq=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=666f=DQ=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206269

--- Comment #4 from Dmitry Vyukov (dvyukov@google.com) ---
Humm... I can't figure out what exactly I meant when filed the issue. Maybe I
assume that the access to the kernel buffer also happens in asm and is not
visible to KASAN (otherwise why did I mention only _rep versions?). But it
seems that it does because the loop part is implemented in C:
https://elixir.bootlin.com/linux/v5.9-rc8/source/include/asm-generic/io.h#L356

Hard to say how much value there is in checking the IO address.
I see at least in some cases the IO address is loaded from some kernel data
structure:
https://elixir.bootlin.com/linux/v5.9-rc8/source/drivers/net/ethernet/smsc/smc91x.h#L1109
So potentially the IO address can be bad/uninit/wrong. But I don't know how
much potential for such bugs there is in general.

> Probaly we should check the target IO addresses agains memory ranges
> allocated by the ioremap/memremap functions, not just the usual KASAN checks.

Good point. Such check is stricter and does not even need KASAN, and can be
enabled with a separate debug config.
It's worth asking maintainers of this machinery re addition/value of such
check.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206269-199747-Vv46wjVIWG%40https.bugzilla.kernel.org/.
