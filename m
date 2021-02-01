Return-Path: <kasan-dev+bncBC24VNFHTMIBBUOB4GAAMGQEHH5IOHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id ED0CC30B175
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 21:13:06 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id z5sf7069643ilq.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 12:13:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612210386; cv=pass;
        d=google.com; s=arc-20160816;
        b=zYq5L6vfEqMO0AyTOrq9CLmFXgIttVzI/uak5Ad8cNmielV1PrKmnMWf8fSfw9GV1d
         /c43uXW3k0Az45akzq7lGpFBlfTHb+guCw6IuqbVib/8RAvAx9tmGUYvx6iWMqOEk7bU
         WeIbsnI+FKlLxJnd1/TW4JwAH7Mlpp6/nj6JOZPAYdM12VH+04/zsv0J9TGKoGFszj4Q
         hEXUv8pnnqESMVtBTGt4uiNSy8lRwjeiZZlTn1LWIvrg62Pg+27fW9tfPVOREqlRF22j
         ZhFiSoOswvMJcGH3r41Homk5w5D7vKJeJqNtDueZaNoMbOKdg1gM/7GHt2oGAwHnZsvh
         rtLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :content-transfer-encoding:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=+WrOnP6p8LSmOOvijNjmF0GOe9x6nrW4z+dRCAp9fF4=;
        b=PyEjGhSTToV4c7BtBKbgte7rFS8Yh4jbZkvPq3Vn7xxrRH0FunYa8PpIq9FGNiLQ9m
         FXfzL1FWyRDdaHufGe69ke1MEhR8ch2oMo0zvZBShzEnNATn0qsSA7A/Wa+SZ9gc6Lfn
         L8NL/qo9m0qz2axPrAWIuTFQfxsJFPq9yYR1wZn4CTEyMKT6e1PUjkyW4ADBKwwoWyBt
         jN6Ai4i7OGRpzyAs8cFF4+9t59qjN4TDtq8ebykNun3xFrQCg0P+dSXRVQ02aq5KnyvO
         H3rc5R1qo4qHeFEE+DgdwxMvPkXYYLcHGQ1RVZ0eZpdnzG4mhzq74ZkZQWLJnE7WpGN2
         THwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="dVAw/fPX";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:content-transfer-encoding
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+WrOnP6p8LSmOOvijNjmF0GOe9x6nrW4z+dRCAp9fF4=;
        b=FeDytBMml0XelMZ0hgAGAWP+Eih1FNjLkL4NO6r5vlZnEJrv/ZZHMhXeqObz4nGQOi
         sBdsKqNDRhVJ/f7dgzSbqOBdfA6Lcjmh723cbSbGUqEZL5t+GWFuNnFkUk3aR5icUNgq
         WLkoDCO/Of4zvNZYkdC1YNKh+042C50qz+Ss86GFpRyU38zgu5vAvQMKwt7WRCZu0KYR
         9Y8GV0N8acGeF5d2BGJdYSq+ss5Kem9sHNIZOepCINL5UYix3Xg6VDFNkYXCtvpocgAf
         Lp3xnq481YWEXpuJ161uLrI8lHIpFUu86K8uZSPnQrMVg8hghjl8svkjRpsKl8uSwE3n
         jYYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :content-transfer-encoding:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+WrOnP6p8LSmOOvijNjmF0GOe9x6nrW4z+dRCAp9fF4=;
        b=RO98dybWaAlKD5yQS8Pko0kwoXe5ANIb9r46f/jxbu8THf3hP8qv8WfMLsHhXWA5M0
         +a5hpOtdxd6ESLcTipTvM7pB0hx43OXuTYZ8J2F8YIaFQaOlywfVqwknzhlRKn9h4YOz
         z/+1FDFfbknhdphotz8dc3Zoo4ASBTT5qsKAMv0OPGqdl4BkQCPtlDqpQc6edgjLB4nf
         vtD+d6dQMnvOVBrAzF+psaHh/K/8PhmvsJi3DNgcIweJi/4dUUF5OHFUK3FkUG6wY6mZ
         veGTcVW8ffvHdzoy2PhyFLzFkKQUBe7AfPE7sMmJCE71lpuIfhIJVtm8SueB7rldyAf8
         w3pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5333DSDVcP5zUxqJTczanW2CAl5RkEKyMxCK37ux18la8RIBwTLt
	FnAUNjik0s2UAwkqbyoyOL4=
X-Google-Smtp-Source: ABdhPJwFGoU655F0YuKktIBJTBBMNDa3w8j0pRffXx+R/znWHtKr51yHgKr5Zt7xSLBsB9V1qEuu0g==
X-Received: by 2002:a02:b897:: with SMTP id p23mr85059jam.59.1612210385925;
        Mon, 01 Feb 2021 12:13:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:5ac:: with SMTP id k12ls2391721ils.7.gmail; Mon, 01
 Feb 2021 12:13:05 -0800 (PST)
X-Received: by 2002:a92:b751:: with SMTP id c17mr14613378ilm.172.1612210385507;
        Mon, 01 Feb 2021 12:13:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612210385; cv=none;
        d=google.com; s=arc-20160816;
        b=ZlcxDatz+mZxZuCcleM5ZatOkboKnz2ahOqryGuEpHdyaVrclb0CgKByi2Yha9bMdG
         n6UbNq98XdGnoDIk3Ln1HNX+gj/2tvx5+LAO2ga+RGa9AGfU0+/PjgwnsuLNCOJ1dDG5
         B4UUfjrA0n9KZBS2RRwD4XuQSOiuVFhPqLOufcrEiLiOZDjA1HqJPKVXOj/F9bbgdBLL
         POe6wSKeSVtFpFmfUOmAQ/h2R0tbiGeGcXxBLcrPAUXekgOXg56XNURGxgKMjDpFn18L
         Iyw8ujtgfcegv7SBUuH/QYsEhFJIJBOutueO5MiUa+KeUiUdjKdYymxA18loCO3ICR/5
         XWaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=urFdhnya/8Z0Dy53TTY2f8IYXimuRIUe1nU9yLVMBjI=;
        b=va80zBX/O8C/CrdpnvisqScDqdMHmeUY9F+Y13XH0degoO44mY8kk+6uaLz7TroYF9
         y99SBgkDyu36HfAPskPKrAwi7qAW4k7X/+pzIcUvI3rafencvNGXaKHDNqM+EWDKLOKd
         GWXm9rlQzAkAtqHp1q32KDJ5WHqalv8+wUrx4AeLiMYSqkm9PLsyuVIcQvtmLWLRlWAt
         37VDcLwY4SacLOyOxzi2cW+Dx20EsQEv24K67jTmcQyi4br5UFJ9RW44FKFN3/RJopax
         0Ox3dg7SUX1nWXlkKp90Txgk8GKYE12ou8TohH+1qV99pFPer1DA9IfRfkfdG0MN6h/F
         rDmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="dVAw/fPX";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o7si885077ilu.0.2021.02.01.12.13.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 01 Feb 2021 12:13:05 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 9BA8C64DDB
	for <kasan-dev@googlegroups.com>; Mon,  1 Feb 2021 20:13:04 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 8310B65300; Mon,  1 Feb 2021 20:13:04 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211517] New: KASAN (sw-tags): support GCC
Date: Mon, 01 Feb 2021 20:13:04 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
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
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-211517-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="dVAw/fPX";       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=3D211517

            Bug ID: 211517
           Summary: KASAN (sw-tags): support GCC
           Product: Memory Management
           Version: 2.5
    Kernel Version: upstream
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Looks like GCC has acquired -fsanitize=3Dkernel-hwaddess flag. This allows
enabling CONFIG_KASAN_SW_TAGS, but the build fails with:

aarch64-none-linux-gnu-gcc: error: unrecognized command-line option =E2=80=
=98-mllvm=E2=80=99

We should either disallow GCC explicitly, or add proper GCC support to SW_T=
AGS
KASAN.

Reported-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

--=20
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/bug-211517-199747%40https.bugzilla.kernel.org/.
