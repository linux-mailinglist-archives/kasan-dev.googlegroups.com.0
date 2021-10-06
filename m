Return-Path: <kasan-dev+bncBC24VNFHTMIBBZU662FAMGQEOOQDFNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id D652B423D5E
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 13:58:31 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id hf12-20020a0562140e8c00b00382cdfe644esf2448021qvb.23
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 04:58:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633521511; cv=pass;
        d=google.com; s=arc-20160816;
        b=H4VuneokPC8p6FQmoTe5jxzgUiA8myqQFTUr+zy/WT6NFv2nzBBMQ+hUhpy4Tql2gT
         EnHtjop8uBgnl8VgkGnUqXZL7zxo49bbZVMX1fF8/JiELKqMhVYTC+vzTP9hmAxTDewv
         UoK7Fj+AQjdgPALWHUK2sf+QxCXPzu8dECTgnyhRpQSDD0N0A7Er+pYldvAfx2F7xhNc
         jWZfRmicJ7l1FSE2+cNqHxurDM1b8z2eBU1nQ/yUvT0ihDODEx9YuTPKQmMB5IluYKsl
         U+RdeN7CFyov8o1wTGr12c9ZxKYDUWnENcqfR7Z2b7vDWtWq8NRQTnEAf4IqK9Qxelr/
         u1MA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=fUkuhodkmaMFoffV12IT1TSqds0aZGAStQTnNhKqn/0=;
        b=JedHknuL36IXJjf2xj9scnxZiZWqrUrFUEVk/J9w159HJ5lfr9eTa5XXi0MKSOF2gW
         vnMaH46HSBtK8+R5YC4m6tmIuevwifLWGsAZv4h1STfRVGnvUpR4uc1OrjRBgZG6Un6E
         bh6sBvnzqLhN/B0Qthja7KQ/sw3gRMuotCF09HZbOog1QN9rn481jtPxlHwTlrNWFbJt
         6Yvz1SkHff1ciZw5a/nbJtGPRue9ossGFfbhE0ycrmrmxVjgT8CdXAm+ZflrJr98jJOO
         Yh2lcVg6hsRRi8u+FCrDlrnkZsvwqdOfnpHwJQxEAciM5N3Z360On3Fh5xeNSiXBG79/
         dt/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jZHKBBW2;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fUkuhodkmaMFoffV12IT1TSqds0aZGAStQTnNhKqn/0=;
        b=QvkxuBk4v+p/KOL41FZC1iWvg5X78b9/E35811I7kdKSiMfGIkfcd47VpfBFxm/F1P
         AYZl0XXyatDPK9e4gMpwWMTwUAfbXtfjZdjMeagKPfcQy9hjI8izwDb41aSTQennsJeE
         7GqbU04/Xj+lHCjg+O/t5aeTDlwDRsecgqpG+kwbOuRy8R+utld0usigLylguT/BWbvk
         HS7TO1Z/DVuyPSsFha+QrJ2k9Wak0mEr0gygkHrMwyDfLs8uRkbOoItT2u+NYgMjGd/p
         q92jbnSlQ5PzF9QpewpNpL+L7UlWrt7m9hyJodW6Cq8btuUrxBK9YGnuKCSxj8FN6+QV
         dJ+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fUkuhodkmaMFoffV12IT1TSqds0aZGAStQTnNhKqn/0=;
        b=ApJ+c2+rviHPUCmVb+Ng/IR1Ukaw3lUCD97OsfAHs9SEZ26R3eKV59985Nc/KZK7JB
         zaQpx1QlTe1fgh4mPeqce0Fg/ximDcSscFBSiQ6LD5KVKsnTe47JPFQtwP3/WoGRp0dq
         YYEbqOmgBQ+Pfasp0XftG/SSFp7OLEzLjzejUn64PfX4Bimek6KbwXM0umNWHxM/h6M/
         JsjPvMwa6eXsI5r9l0DwhfncwEuvYbEJUN4dnGn9oPk7w8sE+/FDQvdUR9wTdmEuZPwp
         lURTbW0iFiASEerSQ98ufHCjo9TkH/uUhvCemHAlG7LDd9rtXrnCPfY6Q60a1Vzzialx
         37aQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532liPdxVVNA27eUjIvFGKZ0nmZ6ul1/9Zpz9KjLgkYZOuohdJlC
	Joq+rvN8P+VoJkjT+0kvrJQ=
X-Google-Smtp-Source: ABdhPJwhuHQlWNJeE4/FmWS/TuJfaiRKCmFHpA/rVrXdWl5o6RWoODdFOJdfY7ejLGhvEBWAlX5LXw==
X-Received: by 2002:ae9:e857:: with SMTP id a84mr346290qkg.226.1633521510882;
        Wed, 06 Oct 2021 04:58:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:198f:: with SMTP id bm15ls2587796qkb.2.gmail; Wed,
 06 Oct 2021 04:58:30 -0700 (PDT)
X-Received: by 2002:a37:b1c1:: with SMTP id a184mr19234101qkf.177.1633521510466;
        Wed, 06 Oct 2021 04:58:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633521510; cv=none;
        d=google.com; s=arc-20160816;
        b=T5X7FtYH6ajHy89AyObf6wNrivuMERarAMLIi0Au9mEomUVucEwIO2lzVbu8ti73TR
         aGVGADkb5VmShYw8Knr8fnTzQZ6d+eZ/I5TEgZ2DtTzigz13Uhk5PMPR87Qb38HtADRB
         agQ95HVwZUZvDcLO4M9kKwdcIHrIywrvtU3WdLlFpnr7zZEEa6ySrfa56eDvKhcOXfS/
         PVrE6PjsdCXmsGmV4rIw1oUg6w9fxRTEb5RzNGMSwS7Vec5lWMVCiqskkLuFImOEGONT
         XLio+0bVAXr/zfhgwj95PZd5DmHOFzoXuH+2VdQC13M/jJ0Z/t1a+9JX67oILUC1EZW4
         9MVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=wz9OJTE7RW0Kcd8hJijroHNpvDA8TXVr+USN2BKywF8=;
        b=1IB5HGiuJGTP1dgXm7Qd3L+ZJCdCBRZa2sFUzZNIghMxJdodP0l/lAVUk07mH+sC61
         80Ug9ZGQc4m1vdJPHpUIuh44at32WfhNIyWYNf7PXfD/x6y5l1KBOIOAsDUihcVbvFD6
         389+6mIvp7HQhxdTUBJJKuAvBO28bYFgHQ8uQf+keujRGS10rSrpHjrDG8VGxAN21zVl
         JLpjK71lbxXt7/ijDvW4fM1nqF2uh1xapMB6eHDkGeQxCiWpjRKjAZhD2bzi+8IwEzB7
         KHG4+Y5WrP9R5SpR7WYocISaIPaxd8ZwF89rCpjqQ6e/UC3KPhE1OATr3u0LgciW9qHE
         B5IQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jZHKBBW2;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 4si213574qtu.1.2021.10.06.04.58.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 06 Oct 2021 04:58:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 78E836115A
	for <kasan-dev@googlegroups.com>; Wed,  6 Oct 2021 11:58:29 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 674CD60EB5; Wed,  6 Oct 2021 11:58:29 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214629] kasan: organize cc-param calls in Makefile
Date: Wed, 06 Oct 2021 11:58:29 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: elver@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-214629-199747-qIS9cP5RbO@https.bugzilla.kernel.org/>
In-Reply-To: <bug-214629-199747@https.bugzilla.kernel.org/>
References: <bug-214629-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jZHKBBW2;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=214629

Marco Elver (elver@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |elver@google.com

--- Comment #1 from Marco Elver (elver@google.com) ---
https://lkml.kernel.org/r/YV0NPnUbElw7cTRH@archlinux-ax161

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-214629-199747-qIS9cP5RbO%40https.bugzilla.kernel.org/.
