Return-Path: <kasan-dev+bncBDQ27FVWWUFRBQHM6OFAMGQEAZFTWXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 05FF1423553
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 03:05:06 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id n2-20020a1709026a8200b0013e2253d774sf530383plk.14
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 18:05:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633482304; cv=pass;
        d=google.com; s=arc-20160816;
        b=lJVyi9ViJWmK7QmCF4OUZ6ST4CTTG+sHH4DlRzxLB2y4ZsoRGohms77rfeCYnwPCDP
         eN2Rt6XmUsecJC3WclL6ghppZ6mCRR/jnG+tT+AaNWOXmsz0q7S0PpimfrGETOsvR1a7
         TD5rkpmMjNLLZ60CGVhoWx3eYi+Rkjted/zwCPTj3k15Gq7H82zPeY75NikV+PItmIY2
         PF46tcmL5ErYDOPhtXRi4sXMpXDP8aa8rcxzKpOiR1g7/hIfIe8scCH/0BYF1MeEBBpy
         Vzu2fL8o82ZzR5AWyC/l3IU0iiPQyahpJvvjAQ00PO57fwiXv0uzvXfWdla8GRrFnvlL
         ttOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:to:from:sender:dkim-signature;
        bh=F7z5zy8pjqmlKa1NMgIoqsSomyCkz7CeKMuFqWcnb2o=;
        b=M1CoMkGjyj2IjAiQcl0pjPoz7FnsKeZTujr5lHezPYZKu/eo/EPDx8DbGMXbs9vV/5
         jth2wocPocIjTUEpY5CMX4O3R7Bbqfjkj2GnU2FVxF2ShXQF1yAfhPX3pWCexz61ab1p
         Eqd2xyh0MeeUc3y5TsPoetToYBrh+Q2VsF/Oe82hWZ76JHz99FHJtX4oejtvBEfka6el
         96JzpJC9jAgnmBCRq5q5yK5G2HIqIbLJGeofdqQu2dkNZv6WLTkkyCqX2n/X7Zb36FwM
         uVIxuQa6RznYvywmoThwgOeIAfCsZYtod8tHZ1mdBLIuIBYgAAks7iCPfxg4UOT1QWKB
         ix1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=TH36DqQf;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F7z5zy8pjqmlKa1NMgIoqsSomyCkz7CeKMuFqWcnb2o=;
        b=LpI1LKHGaUrC6FErHdfgIw6sm7fkmjPugGqzAa+hKjKg5a/nJje3SGLsU3HlQ2ocSE
         qjWT6ZujFKPIZUOFjMaHeXSah981T8nqrTGhHeGJyFN0SOT1EnFEtnj411LVBO+Yytx8
         JuOYPTKsdW6T7H71nazlnbgf58RvFsk1MPq0htHWpnwWl4bABuE9l1ZSOfkr5V+FULw6
         HAiVliK/2w+F5PswrxBmmKBPgErFyTGVrLZS1U6O8COL4L1ZqadY6AUxrlZ9s8rfkW6F
         /f/SwLhyJf5bp8SSQIzToczdWUudLor3fAf9NpADsTGDu7g+5PMfxllugYat0ks5xULd
         29hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=F7z5zy8pjqmlKa1NMgIoqsSomyCkz7CeKMuFqWcnb2o=;
        b=U/x3rWPwzaeXwaxgj+juLc9co3q0iTOpjjjMWkUbdinOpUpwR2jRlmmV7ScOg3goqH
         SEJuObdm4J2dn94WOtBqm857kkknkNI8A0d4R4r0lPXdfrKZjxLeXz5XyDyXyjmdgvx0
         Be0qNkddTKncZoD+ccOfmD+PKgcLS5GPZ90GWWcleJk7Xx4uSZq8vICwm2a0sgXtW7H3
         1+N4cJ6GousQmhmm0LVSRkvn3c4QuljV8REoCw7igvL1CiWt8OK9Mfv/OCv6YY7Smo23
         M8pXxd5K4JS5g7RKu/WeBA1aT+a2g7IPO6C16KgQ5K4DeUN/s+sdR2/Whiqz3eUdHzt1
         0DEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Mq5W7ODVyROeKHryxL7uTAgxoHtcp4aJmF7GqWiV+JxUUZ2pY
	u8xOJm1NqyGByZkYiIzhKdc=
X-Google-Smtp-Source: ABdhPJzi0fMcQDVdBeLI67gUZDE+osC7xEpcM5R1eJjRcq/JaiLgHzJs4RMMLqk1LM3wyVbuntN6ZQ==
X-Received: by 2002:a17:90b:354e:: with SMTP id lt14mr7403687pjb.244.1633482304406;
        Tue, 05 Oct 2021 18:05:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:dad1:: with SMTP id q17ls965969plx.4.gmail; Tue, 05
 Oct 2021 18:05:03 -0700 (PDT)
X-Received: by 2002:a17:902:7c17:b0:13e:2dd5:e5c4 with SMTP id x23-20020a1709027c1700b0013e2dd5e5c4mr8190007pll.68.1633482303834;
        Tue, 05 Oct 2021 18:05:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633482303; cv=none;
        d=google.com; s=arc-20160816;
        b=sHNQW1nkYh9mcBH/hqWCLFvLcZXB7XlzYreEHax8t2Bt4I3w6qv+phBulZ77QrtL75
         OXp5lwoVqxX/SYSGFo4BDtsxABnJxNsrtYEW+tN3MjUG24kZjDnTe4ARm8VZIIX26AJ8
         /2UWZgW9NIwOU1TIoZ6hxMZAi/4i7iVIueRtKBpUnKXC2wKWE1w89fl0jpT3fsAkQdzK
         pmhtOmz2ABdMY4aulRM4FCJH+gX7IlMb8vgA2hzMzKOXvlqs2nSPHo0M3L+8ezPtvN3B
         fdMskTDRvEB9TZhQeW2SvX9c3u4bQfyN9ht3KEvM6yLx3rTlbeZJFPJZW4yUnbJjh8JA
         TWQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:to:from:dkim-signature;
        bh=A4VJniHKXgRvhM9CB9NqAoMDuZnGdMIB2tESsniPS5Y=;
        b=NVTg0LAgH/xAFxYAhnaVFff/X1utvQKhYDTKcWEua4/EvweouqPNZqjzLVRKXsvzXT
         nOc4YBiM4P61W/PKDPti/pyY7QBn4QwdeCq5ikY0F2+oaC8gbS0YHUXd9MO+uyyd6Lkr
         9CxFIanOi9Fk8h4+cZpuASkDRATM5qUdHnXEIsADwsHQ2FBlSyBEcz2fRYOiSqjzBa8c
         AjE/6SPaQ85cwA2LrKrwGUIk3Gkmd0BvjBp3x/AB7q4yXKHorGv7gTkXQ5plXFt9YIUE
         thO0EFCeGE6G7kz31qNy5g1O385aApN/IbfbtEI3rgwVL4VbvnU2WTHdoy9I1hmqgV7K
         4MIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=TH36DqQf;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id m1si420185pjv.1.2021.10.05.18.05.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 18:05:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id oa4so216496pjb.2
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 18:05:03 -0700 (PDT)
X-Received: by 2002:a17:90b:4a07:: with SMTP id kk7mr7417246pjb.37.1633482303184;
        Tue, 05 Oct 2021 18:05:03 -0700 (PDT)
Received: from localhost ([2001:4479:e300:600:ce15:427:ed6f:99de])
        by smtp.gmail.com with ESMTPSA id e4sm14781238pfj.130.2021.10.05.18.05.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Oct 2021 18:05:02 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, Peter Zijlstra
 <peterz@infradead.org>, paulmck@kernel.org, rcu@vger.kernel.org
Subject: instrument_atomic_read()/_write() in noinstr functions?
Date: Wed, 06 Oct 2021 12:05:00 +1100
Message-ID: <871r4z55fn.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=TH36DqQf;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1030 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi,

commit b58e733fd774 ("rcu: Fixup noinstr warnings") adds some
instrument_atomic_read calls to rcu_nmi_enter - a function marked
noinstr. Similar calls are added to some other functions as well.

This is causing me some grief on powerpc64 while trying to enable
KASAN. powerpc64 book3s takes some NMIs in real mode, and in real mode
we can't access where I'm proposing to put the KASAN shadow - we can
only access it with translations on. So I end up taking a fault in the
kasan_check_read path via rcu_nmi_enter.

As far as I can tell `instrumentation_begin()` and
`instrumentation_end()` don't make it safe to call instrumentation, they
just tell the developer that instrumentation is safe. (And they are used
to check the balance of _begin()/_end() blocks.)

Is the underlying assumption that the KASAN shadow will always be safe
to access, even in functions marked noinstr? It seems to undercut what
an architecture can assume about a function marked noinstr...

Kind regards,
Daniel

P.S. On a more generic note instrumentation_begin()/_end() is now
scattered across the kernel and it makes me a bit nervous. It's making a
statement about something that is in part a property of how the arch
implements instrumentation. Are arches expected to implement things in
such a way as to make these blocks accurate? For example in
arch/powerpc/include/asm/interrupt.h::interrupt_nmi_enter_prepare we
currently sometimes call nmi_enter in real mode; should we instead only
call it when we have translations on?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/871r4z55fn.fsf%40dja-thinkpad.axtens.net.
