Return-Path: <kasan-dev+bncBCT4XGV33UIBBDEETLFQMGQEP3SLEAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id CF202D1AA69
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 18:34:06 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-2a33a163c97sf35048305ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 09:34:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768325645; cv=pass;
        d=google.com; s=arc-20240605;
        b=P800cU57QHfeThH3le1d2sWeXOhBz/xU1szKnzs4rlv4xGrZSi5bvqzPKfYliocEGh
         gxTogOv6AgQeurUDIS5TIGwFaW615O8svh4pcLB6GS0bnnn/P1p7RxnCt1IvCVDk+4iC
         Qt1FlJWKGrkVY9sKzEm+syzvTEm9EErRlG+f64wDKUXV7zEl6p1iqY87f69dNV4ayYiM
         B4TtPBPyat0VdTuhlWQxt2lXUc0WuoxmYqCgucvfIVvc2oMeq37T91V30RT4VU7J9dCw
         4m2rvxmrecIqa1gJI/BhfOqq/JEbzSAW8QcTu/Qjj34zIvVP3b9l7dxFoR6harUUk3AI
         vsSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=uU0m9dxHdicz+Ht3k5UT6xa2Itc6dLcLHnlMee9WLM8=;
        fh=NxQvSE1+QY3i7oY96q4JXd8AyksR6hq94H5fuIpn6p4=;
        b=jIyNunQxg0bCxcDHJsUWbrh7+RlsZQLpNgr6a+dGRTLfR9RkfBlSuyGVROumAPr8Mg
         V8QHtDtIorvoiRpd3ynwiShF3yrIyID6O0Hu6jJpNnt/rZFeBifrjOOGf7GbLC00TXgZ
         3oD1wUeIo1IsSaerQPj+//q4dGTchrVVh1ZckQJxOpOhAvG1B753c844ZNbX0IXg6n//
         75GHmeveVJW6Iqe3mCzSTh+48oXFcAOefZlzX85gbQa/qzbYn3dK13h+6/XODFxgukxi
         dHU99FfJD/DbGVZhD4VzKKCkIU9jx8eHFTKuLWb95GGEG0JHmOyAFyHW1lY/1INn0Hig
         M27Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=WbyA3+Fz;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768325645; x=1768930445; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uU0m9dxHdicz+Ht3k5UT6xa2Itc6dLcLHnlMee9WLM8=;
        b=rcEgP5vWTNUtFrU8YQ4h40nu/E+WiGQKnmS3Kf1f97IlSOCeulRdXIUZ/Jkj25gp8F
         +4xyALY3JrUNa5iB9fSCtvCrb38lxWPir2I3KrFeVihrlJ33KCfpOO1IH0hlHYr+LauH
         7Lc/FYXntci1oadgGBSS5D8MaBinVOEuwEdSvQxyTBKP6St9bCBXUUcitaz72V1qWD3u
         ONS1zNeSfQh6EE2OXrOwycFxZWMMX81Gt087vxnOBhMjXkbFEX4Yb23nk9tBiTfR6D+W
         1pRSTzZBlCLxZ91o4ApFfGEuPVBshEbzfV4EkwcOM34dhtaCBTarPmIRHM/xFFt/Qi/G
         VZyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768325645; x=1768930445;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uU0m9dxHdicz+Ht3k5UT6xa2Itc6dLcLHnlMee9WLM8=;
        b=Z0u2uBxNYLKbc1gWxhQyDXm0q72iPWnaVEGl40vQNOy+Pd3V8TBvR0G6TldWO6xqta
         //0CGpvCx2Bw7xTMqFEGm1kDnXxiJ90c0oK8TlzCUFC34xrd7BL3r9rvjFA2RpDYHb6a
         JB6nUQMyuxBTsIQ8lyKevLtYHxpbKs/80UBUiAWpuukXtZmEZfHBDaz2BdUMuRtccNtV
         azY02ReG8QJ6XqSn0Covx0eZV2zBmUijM2r0pLEq396G9MiqUtvfCzyuHbj2a1+5EvjP
         8NaDoM86lwB5n5z2vnJuEd/5oopRtPfKMO6ApljlsAQulLlfYBWX2MwEBzhzgIEWxh76
         iZsg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWNHeabKuFfdbbytCWacZ4DaA28sHu1sk3dlys1I9gbX8ApX5xS70iveqQMCr5RtfJWWSQKDA==@lfdr.de
X-Gm-Message-State: AOJu0Yy2sWy5bFXvdwp97qyOCBaKw5thYDw9X9svAk/i8GjhdXfOcWeH
	sx2LK/ACoxVlzTGxB/jSyNYHmHDGOy0eewVbrhto3/RGMKi7N5sNowZ1
X-Google-Smtp-Source: AGHT+IH4oViiOmCSjt1r7zkrFhCWC3wZIaBmi+/v7a9WwBogMGDzwP3mwD70gpePNdVAvmNo3E7U8g==
X-Received: by 2002:a17:903:3d0b:b0:29e:3822:5763 with SMTP id d9443c01a7336-2a3ee4d8267mr152140885ad.9.1768325644667;
        Tue, 13 Jan 2026 09:34:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fu8Q243loLXJpaWhug7lWLMvmVHATqib5sk9Y7J/PRFw=="
Received: by 2002:a17:903:428c:b0:298:e5:d986 with SMTP id d9443c01a7336-2a3e2ab99fbls61720505ad.1.-pod-prod-09-us;
 Tue, 13 Jan 2026 09:34:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVJuLMn+OcHKnEVhcK9EImexV3SlFCnOtq7hxdEBbi1fKxjjMsdDydf4D7Sx7PLSjLKWpJm7FGc+aw=@googlegroups.com
X-Received: by 2002:a17:903:198b:b0:2a0:d5b0:dd80 with SMTP id d9443c01a7336-2a3ee4da351mr208283005ad.54.1768325642964;
        Tue, 13 Jan 2026 09:34:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768325642; cv=none;
        d=google.com; s=arc-20240605;
        b=CctUrJ00rMIhSykXyxjZgWBcJN/PiEJdlwAnSscooeeve7G3rBfE1+fn1Sn6t7Qt37
         Fo4Nk9CUWqX+uVKuiRuZ81cvjXYHbrDOciCYKzpfFz3quLIy4dsABrzHQhi203JGqIHb
         13cmNEt5w29I2hRorhvpkvCqZ81C7J7pjAMtlHPEvwJUt9x5VduYvscnAFV9B2o8OqGM
         67S8oZ6uoqn7UUgBUPynzH1NpD29rz/OqKM/4TngWl8wpDZN9Om4u0bB+b9X3p3UJFCC
         D0hbb7EUPSzhQvHKAba8vdMkoDkR2xy+xREKhNc6/E9KAS2bzjLgNTHki2RhoN9Oaju8
         Xrjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=0kn45G2Gwx7itxvt4tA3iBGO8Mgl7hnoy6Lgc+69p8w=;
        fh=wl70P/HrvxLyJJ9VjmzSwkP+0QENuuH1ECWwifytkYI=;
        b=MPL09PZQHjPg9AOm7f9T3n78AHswFgnk228GYJzYierH9UqtwVeLPfy77Xj5aWsUrE
         vq28diYJhBpBeUuw0eAmfGWVxi3SrojqOhIEn26YIBKQqR6qHH997Akunhje/7f5jrv2
         e0rQCUqDoCgx1ve7DzLkbuY38kNerMGdjOyLDZvCzFLSszBBs8/6fFjsib2F+HlR530g
         D5VhTxxwH2jt5zjYWpC2oTQJqwLA7KrWVixOFFmv3PW2F1ZE9TzA+d2zEt8tFE6s/c76
         Y37SP2ri27rIxF1/wFdt3fxoWMiMj2uaxvPq/WoNaX4FoV+hIhjYRo6p1XkfDbTfUCFO
         LpbQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=WbyA3+Fz;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a3e472609fsi6525235ad.6.2026.01.13.09.34.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 09:34:02 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 9E204437EB;
	Tue, 13 Jan 2026 17:34:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A7658C116C6;
	Tue, 13 Jan 2026 17:34:00 +0000 (UTC)
Date: Tue, 13 Jan 2026 09:34:00 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Borislav Petkov <bp@alien8.de>
Cc: Maciej Wieczor-Retman <m.wieczorretman@pm.me>, corbet@lwn.net,
 morbo@google.com, rppt@kernel.org, lorenzo.stoakes@oracle.com,
 ubizjak@gmail.com, mingo@redhat.com, vincenzo.frascino@arm.com,
 maciej.wieczor-retman@intel.com, maz@kernel.org, catalin.marinas@arm.com,
 yeoreum.yun@arm.com, will@kernel.org, jackmanb@google.com,
 samuel.holland@sifive.com, glider@google.com, osandov@fb.com,
 nsc@kernel.org, luto@kernel.org, jpoimboe@kernel.org,
 Liam.Howlett@oracle.com, kees@kernel.org, jan.kiszka@siemens.com,
 thomas.lendacky@amd.com, jeremy.linton@arm.com, dvyukov@google.com,
 axelrasmussen@google.com, leitao@debian.org, ryabinin.a.a@gmail.com,
 bigeasy@linutronix.de, peterz@infradead.org, mark.rutland@arm.com,
 urezki@gmail.com, brgerst@gmail.com, hpa@zytor.com, mhocko@suse.com,
 andreyknvl@gmail.com, weixugc@google.com, kbingham@kernel.org,
 vbabka@suse.cz, nathan@kernel.org, trintaeoitogc@gmail.com,
 samitolvanen@google.com, tglx@kernel.org, thuth@redhat.com,
 surenb@google.com, anshuman.khandual@arm.com, smostafa@google.com,
 yuanchu@google.com, ada.coupriediaz@arm.com, dave.hansen@linux.intel.com,
 kas@kernel.org, nick.desaulniers+lkml@gmail.com, david@kernel.org,
 ardb@kernel.org, justinstitt@google.com, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, kasan-dev@googlegroups.com, llvm@lists.linux.dev,
 linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org,
 linux-kbuild@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v8 00/14] kasan: x86: arm64: KASAN tag-based mode for
 x86
Message-Id: <20260113093400.412cb4c5596ff3336ac803fb@linux-foundation.org>
In-Reply-To: <20260113114705.GJaWYwubl3yCqa1POx@fat_crate.local>
References: <cover.1768233085.git.m.wieczorretman@pm.me>
	<20260112102957.359c8de904b11dc23cffd575@linux-foundation.org>
	<20260113114705.GJaWYwubl3yCqa1POx@fat_crate.local>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=WbyA3+Fz;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 13 Jan 2026 12:47:05 +0100 Borislav Petkov <bp@alien8.de> wrote:

> On Mon, Jan 12, 2026 at 10:29:57AM -0800, Andrew Morton wrote:
> > The review process seems to be proceeding OK so I'll add this to
> > mm.git's mm-new branch, which is not included in linux-next.  I'll aim
> > to hold it there for a week while people check the patches over and
> > send out their acks (please).  Then I hope I can move it into mm.git's
> > mm-unstable branch where it will receive linux-next exposure.
> 
> Yah, you can drop this one and take the next revision after all comments have
> been addressed.

Cool, I removed the series.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260113093400.412cb4c5596ff3336ac803fb%40linux-foundation.org.
