Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBBUPYTCAMGQERG2BGIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 63BC8B1A96E
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 21:18:31 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-6158623a4b7sf3749592a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Aug 2025 12:18:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754335111; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ruv27jAuEAkHQe1kSOxAu/jV1w3QaBoOalcuvKZTbGqGigW0u3C2cKzS/SSRfXmaUy
         NQDyzcc5cR3VL6zpaBpFHJkiQrg/wQ2aJasA4Poq2TfDYW/CcvFgC+ANWoczK8GLySLE
         /g8MUskiZyxZZkV3Gn+btur3dViNe35ucAtu5z88gZQ7SUWyVZDroRIgzdLduavK3D/V
         wOD2+IeodRyDOBdtisLzwslul2g4AnjyDEXipNkH0yvT7Zz4ZN5o4URFsCw5PBlxVLq3
         pCLKsUvoQGcVw21zKXmWpe/PmNf8Q95/eYce+53W7qH+fFI+M2wLvJnqVbLlEDFFsESS
         rN9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=Eol4mnrFlmz3aF/O4rb5iRFAjvXnFEwxh/cwP14IJGE=;
        fh=BjB0O67/Vosx8luzvRHfDEuIu6oJlu28O+9MDlHbAVM=;
        b=N1iLNjTSNqrmH/19rSNIEAjP0Bb89rrXBVdHkvFKkY3q2fBbP9Bu7PsIYGzdTVAMK1
         lp6xP1tKO+NaOqJZMGydovj/ytNluGEllPGWPFNAgHf8zHoLA4YAElbqa1l5u5XyMm1F
         /+Jv3DbW4np47kdP9wLpGfeeLOaRLbMPBBNchliIEwO+Fx5+Ec/Vzj2RPw3ZQnG9w2gS
         jSCem5koUjiVP2TXqKMzBstIF1gRKsT1FfqTF7GiafIiAsb3vlvBhDgJ4RsSygJUuCvi
         7BEHawNHJQ+BmRDirUYk+26H1waOsVQkOfCfkOhC9LFqekE0jmxrSRHEx8GpcWtggOmV
         /nbg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oDThClsh;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754335111; x=1754939911; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Eol4mnrFlmz3aF/O4rb5iRFAjvXnFEwxh/cwP14IJGE=;
        b=aDyO7HIRyQE8brcWQUhJlNtYOl9K8rDQjfTqgMQu0Yz7Rr84z3iGllN1zurVzmowTj
         T/eyhDSQAjo1sNZ7PrkhHToiA0vKo8nKJ9jue5xZcFXuK8UQBdZV4o4wYRM6wQt2DTJq
         QaEn+UNAem+RsA4yK4Ri31JjNlXK6OJXGgALytHGe6ji8z1ayx0cx7Qz277ttBtF5JwY
         61aBYflb05aYDUTlzjyqlK6zOV2lB2Yq4wOvGX9GyqsYUgz3ZHTJcwzHy/TvmimrgbAe
         ZCgD838CEYsFtz9kJOf48tT2rHL7dTAlGxnT7JTaCXYq3RMMzOZudaF4I6RanqUtt4tZ
         +EEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754335111; x=1754939911;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Eol4mnrFlmz3aF/O4rb5iRFAjvXnFEwxh/cwP14IJGE=;
        b=AMCCvYLi82Wj19FSotUvl2nHJnFLhHhDec+qv7VnOTCXpjh0sTa8mlgS/uiJfN5p+I
         NAeRdeVbNavA2zOCd7yYt06J+xkpNcMiLemhq2vtQgZU/9WdSv+l5tvHs4/RIVMmDlSF
         9oMIhAdLBu41cLt/lh01j115oqYz+7Z4rwVTiyWJOq1wJH7l3h18rhGGzJcu8jROp+9r
         CXYaay2t5OViFp3Up2rmJMJyrDn36lcI2EtKUnEUWK4Y699N/IlHxS15s0hdmGsRFBJy
         4w7BfDr16Zbc+Kv+o1b3lRsoV8NQQFHiu6ejfwFwpeCgUsU4KZ3+rMPd9NEgTwZpFxrt
         tWFA==
X-Forwarded-Encrypted: i=2; AJvYcCWy42V5n6vypqkp7bs35uAi5MpnxOMpEI/yODPvuvXz/7fYBWLC94DaU3K8l06MgQgqhqMBmg==@lfdr.de
X-Gm-Message-State: AOJu0YznIh4QUAONeLq3BukgX+/U4KscCWBW2/EqO217piNLAxkpAvyx
	mloDr+byVDF6H7Ij36CEPtm/+zqgjjZHNt851MH/+a+If6oiOzM2Vet3
X-Google-Smtp-Source: AGHT+IF1bOAUfCRipg19Zo2TLxcNhSCSWfSAjpH1AF132EwYIsvcczrPpKL/NOLCm90BC08suHXrGA==
X-Received: by 2002:a05:6402:848:b0:615:dc48:1e9 with SMTP id 4fb4d7f45d1cf-615e6ef3687mr8914538a12.15.1754335110643;
        Mon, 04 Aug 2025 12:18:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeJfp5cWqOT4DsasZi+TXQG/CGzAmrSP90CY3Xqu1dqtQ==
Received: by 2002:a05:6402:5206:b0:615:a4fc:cb6c with SMTP id
 4fb4d7f45d1cf-615a5c41473ls3863103a12.2.-pod-prod-05-eu; Mon, 04 Aug 2025
 12:18:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPBZdoyQ/8gFrQnm42F+3D4HLqpP3lbvWzyRYHpmgf+b5g1q4hA/tIPOqghTggBHRXStd8HonQVyw=@googlegroups.com
X-Received: by 2002:a17:907:3d9f:b0:adf:7740:9284 with SMTP id a640c23a62f3a-af940273730mr1048503266b.57.1754335107848;
        Mon, 04 Aug 2025 12:18:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754335107; cv=none;
        d=google.com; s=arc-20240605;
        b=cd7bERL238ZPuCe6TN72aJsgUmI1BRh7f0IzfQIKW2CBLt2x5F0USitShq0UBL2jsJ
         d9soED+99eWEYvhaqI1xQT28AehksYeUIRg07v+AZowuStAqSCXnNCOM9SAQkpHxPweX
         4Nu4aPR+9xgGl0eqfL0Udg+rjoFkT6LtUjMO9fGSkQTPPnjJ6PsRdk6d0tiiQyskoxEM
         2TZpZ/zn2UdYFjdyCd4G9PO4xTY+b5tvRZ4ZS0/nunI0gX0UCBSWj2ILVLMtv3X5QvQn
         wnBw9hflvv7CkfOnz69wHqfOP6TybQgCmdXaZvnmY12uWwBhb6APCQUMcbi4Q874C+DK
         8/rQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=WLpMpvoA1z4oTuimkC9AbHvBIqL/ABDs45bxwTwR93E=;
        fh=a0vmTc7+OI0LeO4tNbh6HP4aR+WYGaV03nsKSShlSJs=;
        b=avJNMGeRxH851aC6C0YtDMQjtMnzdSxvU2boIk/6UXfEeN60Gu7HyIH02wvJtHIGLH
         3JHuWvOTc2pBwIA0I2ogk6qAfyi0dm6pljtDLpU9fUI9iDs1k4bip+M6exc6VT2PolGp
         qaEYwSN2XemtQuM50HlcDuiTA+077NTfGe7cs9Z4+JJr5eI8fBIyRFxYE99cNoTQRbwf
         8zhap3O23qUrahSdUZ9MNTr6krcE9KkywVCpW/p6lUmoxipU4pA4hX/2Tyme1cbTqjNK
         SHAxkydx2yyXjAjnUPjQP/CEH9crcCle39ep3r6tTQQ61gF8zNOHX6lxDpdjwzsP3knI
         3bfA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oDThClsh;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-af919eac6c6si25974366b.0.2025.08.04.12.18.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Aug 2025 12:18:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-459b3904fdeso155e9.1
        for <kasan-dev@googlegroups.com>; Mon, 04 Aug 2025 12:18:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWu0157aPeuImt+0SFgULvAgbst1pFaxh2sJaM9oeVLkohjuCt+rPx4hTmEkHSQUtwzwPUwUwl/4hc=@googlegroups.com
X-Gm-Gg: ASbGncvfbpM8XIpY8JAj3ls65hm59A5G/9YE+5F0MO0KBNr8sqe4X95lWO5BKl17oNH
	+iY7GxNQNLopAwi8zzD1E4TqWvwQ/GBigS5pXGN1KJ9oKBUTJDydRv4DKsY0IkvsoTnQBe3dRjo
	nsyqS8n5IR5XDMZL8HwW7MyXnp/756Q2zK41fxq8u+4PlzY31a7dxtSY4B3ynZG6sbk1rtt9ilP
	ZYb4G4530LA9NXQWn0ltW0e0nc9jf2THKki5SXrcED5yNT0wQmfxCZXIG3Dzw/VcpoPT7wvXXHE
	HfH6FbQVtLO0Anbu2Tl38v03/Ozau4KBadsj3nzgq/y16XlvLHmZXAd62gtdWE5Z5fAvySR8qAh
	OWfLQsOw+3Q==
X-Received: by 2002:a05:600c:3b8d:b0:458:92d5:3070 with SMTP id 5b1f17b1804b1-459e13d16demr154465e9.6.1754335107203;
        Mon, 04 Aug 2025 12:18:27 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:2069:2f99:1a0c:3fdd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3b79c4a2187sm17020318f8f.70.2025.08.04.12.18.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Aug 2025 12:18:26 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 04 Aug 2025 21:17:06 +0200
Subject: [PATCH early RFC 2/4] kbuild: kasan: refactor open coded cflags
 for kasan test
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250804-kasan-via-kcsan-v1-2-823a6d5b5f84@google.com>
References: <20250804-kasan-via-kcsan-v1-0-823a6d5b5f84@google.com>
In-Reply-To: <20250804-kasan-via-kcsan-v1-0-823a6d5b5f84@google.com>
To: Masahiro Yamada <masahiroy@kernel.org>, 
 Nathan Chancellor <nathan@kernel.org>, 
 Nicolas Schier <nicolas.schier@linux.dev>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Vlastimil Babka <vbabka@suse.cz>, Roman Gushchin <roman.gushchin@linux.dev>, 
 Harry Yoo <harry.yoo@oracle.com>
Cc: linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, linux-mm@kvack.org, 
 Jann Horn <jannh@google.com>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1754335100; l=1736;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=NjE72AJfCjjPyCkru/f2MOaH1lg7CZ5EkGcOF4OBDks=;
 b=BDqvSo8zU4lISb3FEBItz3PSoNVV4TwDjBHeB1I690t0v00wbQL0cLH2axC58YYT1CIBDzJMN
 B6MMKb0Zo8SD3vG6eifgKNbCFz0c5cSCDSxaGd5VhvQ+hGbZMmExTSZ
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=oDThClsh;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

In the Makefile for mm/kasan/, KASAN is broadly disabled to prevent the
KASAN runtime from recursing into itself; but the KASAN tests must be
exempt from that.

This is currently implemented by duplicating the same logic that is also
in scripts/Makefile.lib. In preparation for changing that logic,
refactor away the duplicate logic - we already have infrastructure for
opting in specific files inside directories that are opted out.

Signed-off-by: Jann Horn <jannh@google.com>
---
 mm/kasan/Makefile | 12 ++----------
 1 file changed, 2 insertions(+), 10 deletions(-)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index dd93ae8a6beb..922b2e6f6d14 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -35,18 +35,10 @@ CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_hw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 
-CFLAGS_KASAN_TEST := $(CFLAGS_KASAN)
-ifndef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
-# If compiler instruments memintrinsics by prefixing them with __asan/__hwasan,
-# we need to treat them normally (as builtins), otherwise the compiler won't
-# recognize them as instrumentable. If it doesn't instrument them, we need to
-# pass -fno-builtin, so the compiler doesn't inline them.
-CFLAGS_KASAN_TEST += -fno-builtin
-endif
+KASAN_SANITIZE_kasan_test_c.o := y
+KASAN_SANITIZE_kasan_test_rust.o := y
 
 CFLAGS_REMOVE_kasan_test_c.o += $(call cc-option, -Wvla-larger-than=1)
-CFLAGS_kasan_test_c.o := $(CFLAGS_KASAN_TEST)
-RUSTFLAGS_kasan_test_rust.o := $(RUSTFLAGS_KASAN)
 
 obj-y := common.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o

-- 
2.50.1.565.gc32cd1483b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250804-kasan-via-kcsan-v1-2-823a6d5b5f84%40google.com.
