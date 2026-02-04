Return-Path: <kasan-dev+bncBAABBEVYR3GAMGQE5OTQVVA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6IT9MBScg2nppwMAu9opvQ
	(envelope-from <kasan-dev+bncBAABBEVYR3GAMGQE5OTQVVA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 20:20:52 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 6261FEC09D
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 20:20:52 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-88a2cc5b548sf40149616d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 11:20:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770232851; cv=pass;
        d=google.com; s=arc-20240605;
        b=iOvkC8IDB/xL/8Ggro8KBA3ajK51Gsv/X4tfFUKTOU7U7F0Ryk7i70dMLNgyAvvwtu
         EI7BCQQv2lXUBM9nBJpgAilOGlalT5NSK5uf6i5TN7zQ8TkTu4LdFK6296t/9jJwgJ2H
         3cLZUzeaBEH8VpetXZy8VcULd9rc2Vn9EsajKJC24TOL3sK3WvzWjKUWnc73esgSGzDY
         6xjn2wt1o792SzKdZCEeOub7XereDEcBXlAHpNb8N+WfwJhrJi2Iq/3nA/tjtTq5RM75
         7eofJYKkUOygarz0HykmSWA7uGxlqAp1nCvzkKTNbDK1hJDIM6IxYVJ60DpHza0KXJmo
         n9Sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=btqOXfmUYe9dZt1ojwnuiPwFQ6+WV48L3/rFaok/ud4=;
        fh=GM1+fUuP5Kd8sQzajoq+HBveZTPgpc21W9LHvn6tXNk=;
        b=F68L7DDXarAmsOWJoLhw8ivFfaSrWcYK5UgpjsfREhNHoXf9+WOV1rX2N4dEfqrHfI
         6E3FAErWeLFFQX/5a4JnfB9Km15KUWv4AV0sNnUj+MbUK9ISzA88K/Po8T+ynDl6Wy5G
         W86VH5CjPxigGf8bnI5gdOTDZoAQUm7lzAgn7//L9nuV+DapNJGQFlzZOXEP6+OzRjNP
         k1kaWoqOpne7iKBLoqTLpzCdZpUgTqQyf4fZxDBFwdQnL8ItcIzAg7O9SMxhhsyNy/WX
         b+SK+3HW2i8LaULsDYkP7r5g99Cvst4rmNZVQeQ7Ugu+2taN1iKXX/6Pv+i2145FOpQ6
         AtLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=WB51Kor4;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770232851; x=1770837651; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=btqOXfmUYe9dZt1ojwnuiPwFQ6+WV48L3/rFaok/ud4=;
        b=PMDU7AdViHgR88Ua9lWm9oUHIBo9Ev9B7sZR763DAN4Px8cTifWccowYObL0yjiipq
         2Z8NW79X5gXkF08xqNt10WlKipZP3bTmpS1SjEs7H8jGC5AN5qs7oV5nmjdiYcp5jUmt
         m3DWpqRjjRb0WnNLZg1Rqz0YB2iE/nbHClctGxe18g3jP1MYQO7sA5+8KjjPAjMMXw9g
         4a1HTb0C+KzG4iT8N8S31HMzdP0rG1MyQwQYpCkcof0D7vtUFG6bLR7ubUoldLY5kxBU
         gomlhqfyVIJlo5dSWiBMbGTbpP4qK+6yUaMPhk8qkT0zPPOinWcmoH422LqkUtwjTbLr
         5Cqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770232851; x=1770837651;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=btqOXfmUYe9dZt1ojwnuiPwFQ6+WV48L3/rFaok/ud4=;
        b=KUqs3Pfk1+nr/+f2nskQNDSZCHR0mJ/9KKA/cCN9bOE7TxXyXh+zFXu6m1h/a6Xd5/
         YXTh3c/gpZA8/NPw2v23Lk3STdWaxYILrhm+PKZFZVpRJqLaZJcegMUhpmjaHPvjgJ7v
         PZdwIZW6si+MKXfDYIArdCYsAXUeakwHtvK5e3H80T/dALhV4n4rPej5wDZPPAcoo24h
         qkajb/12ra4U/Rjztg1Z2/rX1cfDybyd400b6cnsV7mfImB3XpjFVfXHsREk3Dd/uObe
         E3lk5KvktYu3BH2cqVZwSi+j3qokpqdcpMPdvKb8nLiDhsePFEMHctdXjcp5nzfI+xjT
         JjlA==
X-Forwarded-Encrypted: i=2; AJvYcCXBDzcW2eEpSO9QHySRRcYrUzCOkK+UwXr7F6XrqoDOrFrbRoMbYXkXNEDlJBFe9ZTWAgKWiQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy+8gqlXyCEydjfLHmYmOE7hD49Mw+jis4uDD/3JVTOGAHo/tz/
	7cWPYcgk8Bqw5qIx9Bat1qRw+h3SSZFiUwbn5h1EeolRU/qjTnrf+AyU
X-Received: by 2002:a05:622a:1888:b0:501:3b85:272c with SMTP id d75a77b69052e-5062adf18femr5986671cf.31.1770232850797;
        Wed, 04 Feb 2026 11:20:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FkMGVhw7HUKtf60xtyUnFZ+eG7dPJj0yHxUfWt1+UvSg=="
Received: by 2002:ac8:5f09:0:b0:4ee:234a:302a with SMTP id d75a77b69052e-5062aaeed4els1349921cf.2.-pod-prod-00-us;
 Wed, 04 Feb 2026 11:20:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW8k+vgMrLHwC3dP2ETQR447QetmsqtqxLw2mDXbrgak0tbqHEtZx5BX1YWyj3VEY2OXF4FCmFAiVg=@googlegroups.com
X-Received: by 2002:a05:622a:1993:b0:501:4b9d:ad19 with SMTP id d75a77b69052e-5062aad1bc6mr6501361cf.22.1770232849816;
        Wed, 04 Feb 2026 11:20:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770232849; cv=none;
        d=google.com; s=arc-20240605;
        b=U5m1H+FpDo0CsBQerMtPg5nWSTGNpwCOtnymJOBxG8nm7z/QU9SLHqkIvYxd2HbOzU
         8q4PNau5lWTyzB8FEc7sDweEkbi1Vemwt14zP6+UKZgP+64RVNXKeNQzuCxgZxuiXqs4
         p6T6YQwZDwvLQnCiSkq8WvQyrDnLHhkRAcR6tp2HtGAdxygOuPUW4wTNYguTgwcdUcxu
         HkmgzFs30XcmhmAVFFu8hGtbN4FFQnPdXT/haqaGXKe1nswFf8IN917dx9jea/xTwUV0
         QNHHKSx/wp1T0Qfa9yuUXaCNsn8on65rs4zO7FH7stjyD/Uj8MwLe7iXVmaLm8/V4d9P
         UuyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=6UueFZCcl3mzDKHsOfQJ62w7Ldj873Wqx02eAw9623E=;
        fh=7mL5IMqAA9naQcecupuoQCIzQ/Vkgcl0Z33M2vYnOww=;
        b=TCNCafj8AFH6j5qU11gnVIHAbYvhp8piAFwv5BQMqHZwNO1gLPeoXSB+eLbwPljIff
         cAeTI9Uu8CROZLjCPhP99IG/HoLRXiHHvvkISB5QQg81pnxQZR6RqAaVbZPKrN1C52Ci
         j011p2PTLO/m/Mi2hfoTzTpFJ7MYqH6GjAaDctb93CWRXvy40ELGVIabKCJPsU5xUn/l
         kQWAp2Sp62XbmZkpvxq1vbYBUpg5WOFOg/cVIz8NHN2FqAFZVFfiJA17MrGm1q7p9xMA
         XuLBnTuyAGB9WIYa/OaFafiDN9lpV7wmGNSTUeDDGIyIHFuUZb0X3IEuHWfPoOz7rXaj
         FItQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=WB51Kor4;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244121.protonmail.ch (mail-244121.protonmail.ch. [109.224.244.121])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8ca2fd41351si12271285a.8.2026.02.04.11.20.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Feb 2026 11:20:49 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.121 as permitted sender) client-ip=109.224.244.121;
Date: Wed, 04 Feb 2026 19:20:43 +0000
To: Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Jonathan Corbet <corbet@lwn.net>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Andrew Morton <akpm@linux-foundation.org>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, linux-doc@vger.kernel.org, kasan-dev@googlegroups.com, workflows@vger.kernel.org
Subject: [PATCH v10 13/13] x86/kasan: Make software tag-based kasan available
Message-ID: <8fd6275f980b90c62ddcb58cfbc78796c9fa7740.1770232424.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1770232424.git.m.wieczorretman@pm.me>
References: <cover.1770232424.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 7a80a741d11cacf4a5ea15ef58072bc9dc6c640c
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=WB51Kor4;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.121 as
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBAABBEVYR3GAMGQE5OTQVVA];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	FREEMAIL_TO(0.00)[kernel.org,redhat.com,alien8.de,linux.intel.com,zytor.com,lwn.net,gmail.com,google.com,arm.com,infradead.org,linux-foundation.org];
	RCPT_COUNT_TWELVE(0.00)[21];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,googlegroups.com:email,googlegroups.com:dkim,pm.me:mid,pm.me:replyto]
X-Rspamd-Queue-Id: 6261FEC09D
X-Rspamd-Action: no action

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
Changelog v10:
- Update Documentation/dev-tools/kasan.rst with x86 related
  informations.

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
 Documentation/dev-tools/kasan.rst    | 28 ++++++++++++++++------------
 arch/x86/Kconfig                     |  4 ++++
 arch/x86/boot/compressed/misc.h      |  1 +
 arch/x86/include/asm/kasan.h         |  5 +++++
 arch/x86/mm/kasan_init_64.c          |  5 +++++
 lib/Kconfig.kasan                    |  3 ++-
 7 files changed, 41 insertions(+), 15 deletions(-)

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
diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 64dbf8b308bd..03b508ebe673 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -22,8 +22,8 @@ architectures, but it has significant performance and memory overheads.
 
 Software Tag-Based KASAN or SW_TAGS KASAN, enabled with CONFIG_KASAN_SW_TAGS,
 can be used for both debugging and dogfood testing, similar to userspace HWASan.
-This mode is only supported for arm64, but its moderate memory overhead allows
-using it for testing on memory-restricted devices with real workloads.
+This mode is only supported for arm64 and x86, but its moderate memory overhead
+allows using it for testing on memory-restricted devices with real workloads.
 
 Hardware Tag-Based KASAN or HW_TAGS KASAN, enabled with CONFIG_KASAN_HW_TAGS,
 is the mode intended to be used as an in-field memory bug detector or as a
@@ -351,10 +351,12 @@ Software Tag-Based KASAN
 Software Tag-Based KASAN uses a software memory tagging approach to checking
 access validity. It is currently only implemented for the arm64 architecture.
 
-Software Tag-Based KASAN uses the Top Byte Ignore (TBI) feature of arm64 CPUs
-to store a pointer tag in the top byte of kernel pointers. It uses shadow memory
-to store memory tags associated with each 16-byte memory cell (therefore, it
-dedicates 1/16th of the kernel memory for shadow memory).
+Software Tag-Based KASAN uses the Top Byte Ignore (TBI) feature of arm64 CPUs to
+store a pointer tag in the top byte of kernel pointers. Analogously to TBI on
+x86 CPUs Linear Address Masking (LAM) feature is used and the pointer tag is
+stored in four bits of the kernel pointer's top byte. Software Tag-Based mode
+uses shadow memory to store memory tags associated with each 16-byte memory cell
+(therefore, it dedicates 1/16th of the kernel memory for shadow memory).
 
 On each memory allocation, Software Tag-Based KASAN generates a random tag, tags
 the allocated memory with this tag, and embeds the same tag into the returned
@@ -370,12 +372,14 @@ Software Tag-Based KASAN also has two instrumentation modes (outline, which
 emits callbacks to check memory accesses; and inline, which performs the shadow
 memory checks inline). With outline instrumentation mode, a bug report is
 printed from the function that performs the access check. With inline
-instrumentation, a ``brk`` instruction is emitted by the compiler, and a
-dedicated ``brk`` handler is used to print bug reports.
-
-Software Tag-Based KASAN uses 0xFF as a match-all pointer tag (accesses through
-pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
-reserved to tag freed memory regions.
+instrumentation, arm64's implementation uses the ``brk`` instruction emitted by
+the compiler, and a dedicated ``brk`` handler is used to print bug reports. On
+x86 inline mode doesn't work yet due to missing compiler support.
+
+For arm64 Software Tag-Based KASAN uses 0xFF as a match-all pointer tag
+(accesses through pointers with the 0xFF pointer tag are not checked). The value
+0xFE is currently reserved to tag freed memory regions. On x86 the same tags
+take on 0xF and 0xE respectively.
 
 Hardware Tag-Based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
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
2.53.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8fd6275f980b90c62ddcb58cfbc78796c9fa7740.1770232424.git.m.wieczorretman%40pm.me.
