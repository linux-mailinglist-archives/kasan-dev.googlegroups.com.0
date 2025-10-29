Return-Path: <kasan-dev+bncBCT4XGV33UIBBS5ARLEAMGQEV4UHYEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id E1A9CC1D8FF
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 23:08:13 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-87c247591ddsf10693346d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 15:08:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761775692; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ljad+Gg4q0wj1ntUm6WT8RfakXs8J6NCF86zdCBT++CD8FRldQX2gT9LU8T0gbJP9q
         r8h72J7y2tY64CQ/8e1Rjt/QBgSt5tQlpMULZJ+E5Ot7LI6D/l+t92cSN17YIYj0CG8E
         e8h5kkPJVwRN2ijVl9dusPH37R0EmqB7J+nHWm9UlFguqN+SwsZcrILaHDIJszY1iutv
         aFKHQ50k8yzLwpnwR1U8t1ty673NF50SzhEvfcCQez0iCR6ajlP5oK9mmJz6K+Zw8GNT
         QSDJUs4cpt55uwpywZ6ybEW5yBRq9kxney/oRxhnB7lEdgxjxJYzkFLryMxiKktTerNA
         QuzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=pT/+Y4LcuyGiysQ+ofAZ4ukOcpsk8EXToqf4Qj0GtZM=;
        fh=9caPdW+XBlTB4oqiIVvTVskStGMWE1piPdjlZsWdICo=;
        b=aQG25p+vGEIruj2Am4oYouQC5Os2L4jwVRvgfW9N2C8VH+jtYDiCc+Sv4EtTEWeQeE
         nXhk+q2+4RhDo5ALMmlJVacDccSM/XRZKHSlefvFcpFAZxC1t5ZP8wI7NeArFrP3jTcS
         DXCMSzlEFigizJKSDbuNpZbgLgm0RAQPpSJgx8rz8Iq51ouKXt8qfuP6ctcn4buGwhmy
         lkb4b/xyNoqBZClLYG7MXFaXdgs5EmZA8EUq+KhhsuA3hosNB+av8VYCY9Tu16eh6cmu
         36CqcZ3OTiccslvQlwhnHmTJ+vB7v5pw/kFPxZnkNTa7IzB0d/hcd0pUT+p8CkQtK4G6
         K0gA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=lhbf5xPG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761775692; x=1762380492; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pT/+Y4LcuyGiysQ+ofAZ4ukOcpsk8EXToqf4Qj0GtZM=;
        b=c1fzb64+hVyCyTrErLy015z/UhR2ctjKx7UpjPLi3lCWiHMblS7CuW06nVG5yUhmQg
         poFkfYcOhC/Cp/NpPlZf0U0NqikrN2zN/tCn5yjpyRANMM98sU1eY72YvXStKS7LeNC/
         vIK81vqWdE6GW8pfJZ2kIoX+94JmTmB26uwQW8Q9RvrdNXOt6SW4MulcYgUyS0lyruwi
         Rey4ZIz2Iz9uhyCWeQqRhFNtr9ADgBIgLPL1hBUFNSl4Gc2BBzIlqZrY4p7P35XBAKPs
         OoV5UCPPZB5w+kTB4wA5dmqM/0Eu/TX8Dp0nseyiAH73X7dwIFLK29+LV/bXsfpol8xV
         szUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761775692; x=1762380492;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pT/+Y4LcuyGiysQ+ofAZ4ukOcpsk8EXToqf4Qj0GtZM=;
        b=WbjqcGPEkRrH1MFccRbhn0Q1EMi7imwzi9WzrIpvYLnO/UtcfljdyslWhr7d783WDh
         TVFnKPVGkb5tVXUFHQjrUNHCdw2ab5s5Ab5Bqdsti9LbYlvfz8mETiFk1Wx+L+08gYPb
         1zuIWpdUvwLTv0TNr1B3xNeui/OdDAfLVVSy9KM1PgLShFwDroOCwIh2nnoBKTFp/2aM
         VteWwotl52kGRZnO9YdlPfTW1H9slyhb/SmOGw40xul9p0KDlyGpy49sU7BUqc8sgoZN
         S78ttTseu6+Y3azLAttWY+/S+ItMD7sGLsUoW/BUdne6J5HQmPM4QK5+t57aaVn4CvY+
         Hk2w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWCKctvPBuj3uHAv4ds47OhQGcGiqIxxvBJ45I9x5sZLDOFz+QMRyMFzROpldL/BC7M3wPk1w==@lfdr.de
X-Gm-Message-State: AOJu0Yz6BtmYdf4mAVMqUWc5hvbPi6WVSqejndB4vEQYK/u+IUxETFmG
	xWjmccty9ckxVJejWWdxeuIL0FReue19KjGbyeuLvsv16Eqe/LBGSCcy
X-Google-Smtp-Source: AGHT+IGD2Nb5omldk/4O59NltrBG0Y3enrjJL/0M3jB1ikVV0BZ/lHMKKssyv6Ut6OAHPXLC6EGzYA==
X-Received: by 2002:a05:6214:2506:b0:87c:1fd9:da4a with SMTP id 6a1803df08f44-88009ad134emr65425736d6.2.1761775692144;
        Wed, 29 Oct 2025 15:08:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z3FXpJwZ0RBZw1IV0T9mSWCh5JyVmVoCG0WzTZtycEOA=="
Received: by 2002:a05:6214:2a4a:b0:87d:ff09:f720 with SMTP id
 6a1803df08f44-8801b32dcfcls6595196d6.2.-pod-prod-02-us; Wed, 29 Oct 2025
 15:08:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUa0c+jmDxWbU2bxXSoZg5P73MnIq+at62SJN8BKFT7Fhpz5O3OFPNYTTPMoC8XjzyuwXcRoLjmHUw=@googlegroups.com
X-Received: by 2002:a05:6122:c90:b0:557:abe1:fc1 with SMTP id 71dfb90a1353d-5581411b57dmr1488855e0c.3.1761775691285;
        Wed, 29 Oct 2025 15:08:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761775691; cv=none;
        d=google.com; s=arc-20240605;
        b=jUNGSSN77jrYYu0TDr0+VOrjpt+u2chguwZBSC4OzQQ0KNwxMoLB6L++xJjFeHKk2J
         BNI8hG4N7aRcYRMvPYyTLWKV7phCjaQx9JdUqfHtXek/9lIJ2a72MKqunQAFuWNOnjjk
         uIT64I+HlEnQKk6PeRaRr7g6Vxv+byN8x3l04Vt96kkwUZdcNSefJYmpHozf1TDh+BxX
         ureINmHmJTvf3iUB8lr8vXqlZk4IGejF3P0EydeJmSTMm+HTzFqCgHQBRlBM5pG1g/4t
         9zsohg1P7PwxOTj8h/W/5DXFlllHPo/CJfaTTppSIUaKB+MjQHOXygoj6U9xRETdWMsT
         +Kfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ExTQZGDiDmJbpXrA+01Zvu38e8DCkOuUbSd3zuP3MfA=;
        fh=Qa+YGUliS6SftNKNwHB2cUz7DWnup0SLN3OcPYllx8w=;
        b=aCQ8gFkPTa7AWDs0xFGGWORTW15GKXeJAKGC3QCrfx8eNkPou595HjddJZo+kY7UUx
         rSrdJFvnIjY8gXVnxochAD+VZxKn6T+7dXaHbg9fIg1MUDCbuVnZyZRAcFyxERiPDIV+
         xlVQGG2TSSX5M+pG5UwA8n/XjXCBCv8faXA8r1HaMVtMGafbe3HB1OwrRoDDl3OhDVsV
         5SyhV0IGCU1/4EMeIKKapCMgPRUMrEC8UWp80oftq/R2qybD241/NGO4PpdIMe/Elkv3
         14e+woMh1IgluYFhQKEV8DWAdQHPjGKaseJosoLHUuFC0lEAXKx4z9xw1UDg3YfhtxwB
         XP1A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=lhbf5xPG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-557dedc01acsi894334e0c.3.2025.10.29.15.08.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 15:08:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 24C9544786;
	Wed, 29 Oct 2025 22:08:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3F3B9C4CEF7;
	Wed, 29 Oct 2025 22:08:07 +0000 (UTC)
Date: Wed, 29 Oct 2025 15:08:06 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com,
 kbingham@kernel.org, nathan@kernel.org, ryabinin.a.a@gmail.com,
 dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com,
 jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org,
 baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com,
 wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com,
 fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com,
 ubizjak@gmail.com, ada.coupriediaz@arm.com,
 nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com,
 elver@google.com, pankaj.gupta@amd.com, glider@google.com,
 mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org,
 thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com,
 jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com,
 mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com,
 vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
 ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev,
 ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com,
 broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com,
 maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org,
 rppt@kernel.org, will@kernel.org, luto@kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, x86@kernel.org,
 linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev,
 linux-doc@vger.kernel.org
Subject: Re: [PATCH v6 00/18] kasan: x86: arm64: KASAN tag-based mode for
 x86
Message-Id: <20251029150806.e001a669d9dad6ff9167c1f0@linux-foundation.org>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=lhbf5xPG;
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

On Wed, 29 Oct 2025 19:05:27 +0000 Maciej Wieczor-Retman <m.wieczorretman@pm.me> wrote:

> The patchset aims to add a KASAN tag-based mode for the x86 architecture
> with the help of the new CPU feature called Linear Address Masking
> (LAM). Main improvement introduced by the series is 2x lower memory
> usage compared to KASAN's generic mode, the only currently available
> mode on x86. The tag based mode may also find errors that the generic
> mode couldn't because of differences in how these modes operate.

Thanks.  Quite a lot of these patches aren't showing signs of review at
this time, so I'll skip v6 for now.

However patches 1&2 are fixes that have cc:stable.  It's best to
separate these out from the overall add-a-feature series please - their
path-to-mainline will be quite different.

I grabbed just those two patches for some testing, however their
changelogging isn't fully appropriate.  Can I ask that you resend these
as a two-patch series after updating the changelogs to clearly describe
the userspace-visible effects of the flaws which the patches fix?

This is to help -stable maintainers understand why we're proposing the
backports and it is to help people to predict whether these fixes might
address an issue which they or their customers are experiencing.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251029150806.e001a669d9dad6ff9167c1f0%40linux-foundation.org.
