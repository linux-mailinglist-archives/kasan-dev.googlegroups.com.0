Return-Path: <kasan-dev+bncBAABBWVIX3FQMGQETXVVPVQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id wBowJ0ukb2n0DgAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBWVIX3FQMGQETXVVPVQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:50:35 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4003F46BB5
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:50:35 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-64d5bec0e59sf9392519a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:50:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768924234; cv=pass;
        d=google.com; s=arc-20240605;
        b=aBpieKCFMuubUURQF7Ac6wAKKauYrUvVepkcC7aDVsHsGM1JMNTqulB5POlixqiBA+
         021D9lYlW08lS4jNvyi1zbAepk4RtMq01XZy/x67y+gng2mxUUGTuqaaQFnifp0/IUKU
         MulhuXRHPBsXPb1n3DNwWPpuEUliASsBknPAg4Fb8EaA/i9GPWw8LmhU2MqJxmZRbYVR
         5ntrH0MzNlIzWKK66NywV0sa4Ang8vnyZ2C0mSPfV0yVFTYiILQ3IZA6w+BfEPiZhcjz
         8QpSFRg3XUgS73Ky+Z1vQLRG5NMvWoriQ8wR/zjcTqgBnqWn6VCsGJ6//FdNxfaDdfZt
         7hMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=IQUZTtnh3Fxb0Bv8F06lOn9ItWSCPw+3y/sI+iPzjKQ=;
        fh=BPnpUxi94OQ3Smj3bcTLNcARI94avxyEo68V61A0XY0=;
        b=i8fIU7vrCnvpXrNDGR6AyNh7/susmYCOZrz0wTYLodE8RccrEPSZd7tTx+onXTVL5C
         K4CS5yu9pHRrQjEP3REen1EansSGwvEQpT/fwjo05NUfgoXQQ6KqRasSrXL6Nq3fMSqb
         NJ0EbVipovisDUIUW3i0ssFJsbfxs4Uj32UHVu7dX/Y/Dp/hW4KiSe5TA0kwb0xDoqdf
         z/9qXCqwHm+blIw6KdJp08Nc4mBkfzjrV4dJ1c4BJcRhWuofMUYeR/BDbJWgOoUAGWoA
         /mIoZvEGJDhABtVvqq45pTgTa4Bn1nSESWA9qrUz8TorXwCjfRel4AUBuoi/fidIyQA7
         iY7Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=JlfL63bJ;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768924234; x=1769529034; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=IQUZTtnh3Fxb0Bv8F06lOn9ItWSCPw+3y/sI+iPzjKQ=;
        b=qabCSKjsYbU7sE7yKvWddCTMxglIUDvtitY5XU3nQRWPh4BNCM8/Ev0dTf2lJVEJIu
         ThhoZE85oxkgK9z7ILQ+9yIxHJjsgsByN8OXoJ6iYtOUaL6m1maNXCedc1KfapRPk1CN
         LiyfFhDHkbYQO8L5yDvadpZuypQoErqiugdS+0WRZKXqQ+2qUfRrNXLGOutqpYg2/GPk
         vzhzDUh+7TbD8U+RLFabPIEAjYJ9fwn0jze8U9z4jL/bmQerqMNAMS9XNHAqJ+f8w91j
         7l20vD9951mZ8GbH04JV8Aey1nfG+LDRYLy97eaA6LrW1myrVQp69Q9K4MGipc5siCiz
         0hyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768924234; x=1769529034;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IQUZTtnh3Fxb0Bv8F06lOn9ItWSCPw+3y/sI+iPzjKQ=;
        b=DXqvJfPuaLeQPdUhAgdA2fwNDiBiFfT90Wj1ojahXAbxKz8/QeBVlq87L2cqJWWaSR
         0tZFIREtbO3vW1yf9+X8SGnyptVah8Kep6i/qeKEwGwaAogDFb1anzUxkvHXafxnXtKs
         Nuze5REOMQzP80rrUDSu6ANHDr0vRstcc3t0yClnXw7PL1/G3EWGeq9Klz++CRkhMD1K
         S23W11IC3tnm3DP4mxn0DSmSbWZHKBwxm2c+DANao6ynCvxN7vwfI/qCd7PFqDUzSjEr
         F3OgWgbCWXAzLHvwaDrfzuW/dmSAankBZoHP5fRp2mnPStD8rOA60exkZq6khzaX8fbI
         oP6w==
X-Forwarded-Encrypted: i=2; AJvYcCUwVpr907g/pJrHzK/XMHH5foR+9Mfd0MCI7/Xqz9RzsJWYE1Q4I+UMCBdXelJEZYmiZ3EWew==@lfdr.de
X-Gm-Message-State: AOJu0YwIgf1rneA5F3DzkPFW6r/+9zSjl3TVMjV1G+njehNHQ4nZbRjI
	WpOi48hNUmMdUC/pzMEvt+hD/zthZ7WmbEioem9zkNHoHStk6zHE/Pjd
X-Received: by 2002:a05:6402:26cf:b0:64b:5c4e:e695 with SMTP id 4fb4d7f45d1cf-657ff4e112cmr2015772a12.29.1768920154681;
        Tue, 20 Jan 2026 06:42:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EgzujqjP5RfiKXW1hI045VhkoZnSkUvv1ygpCqVYOn+w=="
Received: by 2002:a05:6402:3246:10b0:644:fc33:37b6 with SMTP id
 4fb4d7f45d1cf-6541c6d5e11ls5719880a12.1.-pod-prod-08-eu; Tue, 20 Jan 2026
 06:42:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUxvN2rDTgXY0k6t95ktdJhN258vObir7czdcUCu7sLsTWvRu57YWhYA/nRzKwFuI7rHSbrEeUOhis=@googlegroups.com
X-Received: by 2002:a17:906:fe42:b0:b83:3773:e72a with SMTP id a640c23a62f3a-b8800236557mr188280466b.1.1768920152799;
        Tue, 20 Jan 2026 06:42:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768920152; cv=none;
        d=google.com; s=arc-20240605;
        b=fvpD2M0M2VfDhHdWMn+fyi3QRMEO54Gw8dNYVR1nN7B9WO2cHS11r3AVOuEeEUkjjk
         W4YgCwdbNXNCWSzfa2HRlbVx2iDOgmiD6AsVNCA4Z3+s/3OHAIJqQiYoUiED2KeCvjsQ
         FOznNp/CqvFjXSypJ0YXoNCpBtNOQYReWVGwyAwTOswoSFECvzi8eMTdRg5yY+9r57VD
         jFH7ArX/tbEXbHMEjtfJzb7SMZDlO7NoES/zG8y2NI0oCnfOuRZTf9ljWoarUdIZuJog
         1FAuqrQBWurImvVBkxUe0bE8PtqnT7O5nL1NZoMGrSDwKmBF18JtWDn8NOzgP9lNpNpq
         BijQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=bmUmrOlKhI6wNEzER1H0s0qiO0fQKgJ0/TqrNEAdJVI=;
        fh=U0OOTr31LAvjJ8HIdSeHP6HnrUH+XWUEkxuVYLDBF9c=;
        b=iPFR2xWrqNeL74NUVzOWNjIp0iotJt5RQ4t0II7z1DsibU2jR7GXhihG71JpZE+pZF
         Afoy/CSL4mMc82R5yPNmWX+SIXcxHRSsh5fi5E9GSY0EOWF+5ZQ4yiyD7BTq5Cpt14gW
         kxWDLRkJU3OExsZh1/zmmgrjOE4aqdijwojQsrzZgMSvdolLoQ8xTAPo3jUkGt067qMU
         6/A+ocPABPJ7x5R3NWQvmqoQUzf/7Dysl8h0QrbXqtf8+UZRShsqrE9YVIiAFkiLb0Wb
         oKm5V6KD/QG5R29zWxqU0R5hAGVm7NH8wn1nTVSL+1FtWaJn3qqJDL1arGpy8ILHRbQG
         d2SQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=JlfL63bJ;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106121.protonmail.ch (mail-106121.protonmail.ch. [79.135.106.121])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b87959619dasi22789566b.2.2026.01.20.06.42.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 06:42:32 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) client-ip=79.135.106.121;
Date: Tue, 20 Jan 2026 14:42:25 +0000
To: Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Jonathan Corbet <corbet@lwn.net>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Andrew Morton <akpm@linux-foundation.org>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, linux-doc@vger.kernel.org, kasan-dev@googlegroups.com
Subject: [PATCH v9 13/13] x86/kasan: Make software tag-based kasan available
Message-ID: <4853c70ee54710d0d9500377f981e6ef790c1a67.1768845098.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1768845098.git.m.wieczorretman@pm.me>
References: <cover.1768845098.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 12c243cb5af5d544eac521e988f40f02d4f80de1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=JlfL63bJ;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_TO(0.00)[kernel.org,redhat.com,alien8.de,linux.intel.com,zytor.com,lwn.net,gmail.com,google.com,arm.com,infradead.org,linux-foundation.org];
	RCPT_COUNT_TWELVE(0.00)[20];
	TAGGED_FROM(0.00)[bncBAABBWVIX3FQMGQETXVVPVQ];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,pm.me:mid,pm.me:replyto,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 4003F46BB5
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

Make CONFIG_KASAN_SW_TAGS available for x86 machines if they have
ADDRESS_MASKING enabled (LAM) as that works similarly to Top-Byte Ignore
(TBI) that allows the software tag-based mode on arm64 platform.

The value for sw_tags KASAN_SHADOW_OFFSET was calculated by rearranging
the formulas for KASAN_SHADOW_START and KASAN_SHADOW_END from
arch/x86/include/asm/kasan.h - the only prerequisites being
KASAN_SHADOW_SCALE_SHIFT of 4, and KASAN_SHADOW_END equal to the
one from KASAN generic mode.

Set scale macro based on KASAN mode: in software tag-based mode 16 bytes
of memory map to one shadow byte and 8 in generic mode.

Disable CONFIG_KASAN_INLINE and CONFIG_KASAN_STACK when
CONFIG_KASAN_SW_TAGS is enabled on x86 until the appropriate compiler
support is available.

Lock software tag KASAN behind CC_IS_CLANG due to lack of proper support
by gcc resulting in kernel booting issues.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v9:
- Lock HAVE_ARCH_KASAN_HAS_SW_TAGS behind CC_IS_CLANG due to lack of
  support from gcc.
- Remove pr_info() from KASAN initialization since it's now done by the
  generic init helper.
- Add paragraph to the mm.rst to explain the mutual exclusive nature of
  the KASAN address ranges.
- Use cpu_feature_enabled() instead of boot_cpu_has() in
  kasan_init_64.c.

Changelog v7:
- Add a paragraph to the patch message explaining how the various
  addresses and the KASAN_SHADOW_OFFSET were calculated.

Changelog v6:
- Don't enable KASAN if LAM is not supported.
- Move kasan_init_tags() to kasan_init_64.c to not clutter the setup.c
  file.
- Move the #ifdef for the KASAN scale shift here.
- Move the gdb code to patch "Use arithmetic shift for shadow
  computation".
- Return "depends on KASAN" line to Kconfig.
- Add the defer kasan config option so KASAN can be disabled on hardware
  that doesn't have LAM.

Changelog v4:
- Add x86 specific kasan_mem_to_shadow().
- Revert x86 to the older unsigned KASAN_SHADOW_OFFSET. Do the same to
  KASAN_SHADOW_START/END.
- Modify scripts/gdb/linux/kasan.py to keep x86 using unsigned offset.
- Disable inline and stack support when software tags are enabled on
  x86.

Changelog v3:
- Remove runtime_const from previous patch and merge the rest here.
- Move scale shift definition back to header file.
- Add new kasan offset for software tag based mode.
- Fix patch message typo 32 -> 16, and 16 -> 8.
- Update lib/Kconfig.kasan with x86 now having software tag-based
  support.

Changelog v2:
- Remove KASAN dense code.

 Documentation/arch/x86/x86_64/mm.rst | 10 ++++++++--
 arch/x86/Kconfig                     |  4 ++++
 arch/x86/boot/compressed/misc.h      |  1 +
 arch/x86/include/asm/kasan.h         |  5 +++++
 arch/x86/mm/kasan_init_64.c          |  5 +++++
 lib/Kconfig.kasan                    |  3 ++-
 6 files changed, 25 insertions(+), 3 deletions(-)

diff --git a/Documentation/arch/x86/x86_64/mm.rst b/Documentation/arch/x86/x86_64/mm.rst
index a6cf05d51bd8..7e2e4c5fa661 100644
--- a/Documentation/arch/x86/x86_64/mm.rst
+++ b/Documentation/arch/x86/x86_64/mm.rst
@@ -60,7 +60,8 @@ Complete virtual memory map with 4-level page tables
    ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unused hole
    ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual memory map (vmemmap_base)
    ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unused hole
-   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory
+   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory (generic mode)
+   fffff40000000000 |   -8    TB | fffffbffffffffff |    8 TB | KASAN shadow memory (software tag-based mode)
   __________________|____________|__________________|_________|____________________________________________________________
                                                               |
                                                               | Identical layout to the 56-bit one from here on:
@@ -130,7 +131,8 @@ Complete virtual memory map with 5-level page tables
    ffd2000000000000 |  -11.5  PB | ffd3ffffffffffff |  0.5 PB | ... unused hole
    ffd4000000000000 |  -11    PB | ffd5ffffffffffff |  0.5 PB | virtual memory map (vmemmap_base)
    ffd6000000000000 |  -10.5  PB | ffdeffffffffffff | 2.25 PB | ... unused hole
-   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory
+   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory (generic mode)
+   ffeffc0000000000 |   -6    PB | fffffbffffffffff |    4 PB | KASAN shadow memory (software tag-based mode)
   __________________|____________|__________________|_________|____________________________________________________________
                                                               |
                                                               | Identical layout to the 47-bit one from here on:
@@ -176,5 +178,9 @@ Be very careful vs. KASLR when changing anything here. The KASLR address
 range must not overlap with anything except the KASAN shadow area, which is
 correct as KASAN disables KASLR.
 
+The 'KASAN shadow memory (generic mode)/(software tag-based mode)' ranges are
+mutually exclusive and depend on which KASAN setting is chosen:
+CONFIG_KASAN_GENERIC or CONFIG_KASAN_SW_TAGS.
+
 For both 4- and 5-level layouts, the KSTACK_ERASE_POISON value in the last 2MB
 hole: ffffffffffff4111
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 80527299f859..877668cd5deb 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -67,6 +67,7 @@ config X86
 	select ARCH_CLOCKSOURCE_INIT
 	select ARCH_CONFIGURES_CPU_MITIGATIONS
 	select ARCH_CORRECT_STACKTRACE_ON_KRETPROBE
+	select ARCH_DISABLE_KASAN_INLINE	if X86_64 && KASAN_SW_TAGS
 	select ARCH_ENABLE_HUGEPAGE_MIGRATION if X86_64 && HUGETLB_PAGE && MIGRATION
 	select ARCH_ENABLE_MEMORY_HOTPLUG if X86_64
 	select ARCH_ENABLE_MEMORY_HOTREMOVE if MEMORY_HOTPLUG
@@ -196,6 +197,8 @@ config X86
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if X86_64
 	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
+	select HAVE_ARCH_KASAN_SW_TAGS		if ADDRESS_MASKING && CC_IS_CLANG
+	select ARCH_NEEDS_DEFER_KASAN		if ADDRESS_MASKING
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_KMSAN			if X86_64
 	select HAVE_ARCH_KGDB
@@ -410,6 +413,7 @@ config AUDIT_ARCH
 config KASAN_SHADOW_OFFSET
 	hex
 	depends on KASAN
+	default 0xeffffc0000000000 if KASAN_SW_TAGS
 	default 0xdffffc0000000000
 
 config HAVE_INTEL_TXT
diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/misc.h
index fd855e32c9b9..ba70036c2abd 100644
--- a/arch/x86/boot/compressed/misc.h
+++ b/arch/x86/boot/compressed/misc.h
@@ -13,6 +13,7 @@
 #undef CONFIG_PARAVIRT_SPINLOCKS
 #undef CONFIG_KASAN
 #undef CONFIG_KASAN_GENERIC
+#undef CONFIG_KASAN_SW_TAGS
 
 #define __NO_FORTIFY
 
diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 90c18e30848f..53ab7de16517 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -6,7 +6,12 @@
 #include <linux/kasan-tags.h>
 #include <linux/types.h>
 #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define KASAN_SHADOW_SCALE_SHIFT 4
+#else
 #define KASAN_SHADOW_SCALE_SHIFT 3
+#endif
 
 /*
  * Compiler uses shadow offset assuming that addresses start
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 7f5c11328ec1..8cbb8ec32061 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -465,4 +465,9 @@ void __init kasan_init(void)
 
 	init_task.kasan_depth = 0;
 	kasan_init_generic();
+
+	if (cpu_feature_enabled(X86_FEATURE_LAM))
+		kasan_init_sw_tags();
+	else
+		pr_info("KernelAddressSanitizer not initialized (sw-tags): hardware doesn't support LAM\n");
 }
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index a4bb610a7a6f..d13ea8da7bfd 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -112,7 +112,8 @@ config KASAN_SW_TAGS
 
 	  Requires GCC 11+ or Clang.
 
-	  Supported only on arm64 CPUs and relies on Top Byte Ignore.
+	  Supported on arm64 CPUs that support Top Byte Ignore and on x86 CPUs
+	  that support Linear Address Masking.
 
 	  Consumes about 1/16th of available memory at kernel start and
 	  add an overhead of ~20% for dynamic allocations.
-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4853c70ee54710d0d9500377f981e6ef790c1a67.1768845098.git.m.wieczorretman%40pm.me.
