Return-Path: <kasan-dev+bncBCMIFTP47IJBBP7C6G2QMGQEL4JA7CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EFFC951722
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:56:32 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-e087ed145casf10793622276.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:56:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723625791; cv=pass;
        d=google.com; s=arc-20160816;
        b=q+WroiiHg+Cj8FvsxPDWo3H/bPrf7qIu1FUu8FZ3EaO+K//0Serke3EapntgM7rnoA
         3nrkwqmdPW5yjBT73zjMIKG+ZzRAKKUxVNKx8kCtgJFs3jnOZfHyyejmU0MviPlKLemF
         4hDPlG3vzTfREWQlp+sQx8WTq2VYgVPzJFmAv+LMPRMjn5WITosWBdD57wRv9RlVhOgA
         QhTLFDeacQERwDTKu887HBwa5hNw4jV8pBBYQY2Nc1J7TB9Zv/pl35Blvb5gHhZt7P+T
         io2JemYYjXuqCuQjqRBJ0XYBmEgI/j/2UPM73aerNNQNkfCr69vL5sVAmgiQ8qw+Bxik
         147A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=KBB1JR4H1a+/jqDTgSsMeb5P0vv35e5myfbCgcBBqz4=;
        fh=4M9zOXaV5RY5qcQmhbuAX6MnyRGIZvN6HtgWtNb6kzM=;
        b=pIe15xDsQacpJHaiOrsD1FBOOMfWN82d0GbvXS1zVJd4qaVxf1OXjBIjoRnZh8KPeJ
         voHNnmhq+7QFRQNkcfE+c02ArecsMMdOwdQikSvb500mjsKPNAIUT0Hp/6SVE4JKHaVZ
         8gjq11ieJEtzUn6VXYRBtRq+79Y8MFEo1zA+/td1IkyCPN9Pv3Oys3RDBsk9MqWpmUw0
         RjCf/eIC/SCO7vHQDCh1bRXGtTmAooj8r22AzNF3OlcwYW0oYqFyTJEJY4TjP4R/8XGW
         Egj4tGybUh4rQkpGE6jtbPWill7tw0Z3yZeHhR1Z5kNOCYuZ4Su/dhvE7MiJwcPCSQ5f
         F6ww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=SYfAveZl;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723625791; x=1724230591; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=KBB1JR4H1a+/jqDTgSsMeb5P0vv35e5myfbCgcBBqz4=;
        b=O0txirGriexGprJR8cioDCjSzdUepxMp5kdV92lJPJ+BR0YOOXrEG5W1zt561hjhOo
         2MMlcluVs9lq0O+tqNkOCLIJowGJpMY2sM6zl9HJE5RSvwerHDTFv+LT+OXQKUnX4dIk
         llt+Rmro29KjWqlpJkafijqL+HbBUyO5P7v4YwW646MgHIcMKScGyLrR2efmI0SZcBsW
         /UDh5otApn7D9B9SGSVjO25qUgwpRvdKmWRMAv2bQk+IfIeF8Vdb8xOYWdeCqvV6++w9
         PJuoHqPucTyDXzMyXxjXfWnh6ulcseyAQr7k/4L9NWrILi3yCj5rCICUVq3OtvnC4RV+
         EOyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723625791; x=1724230591;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KBB1JR4H1a+/jqDTgSsMeb5P0vv35e5myfbCgcBBqz4=;
        b=iGnNzYqhzGPbN9TUn9FHX4fwL2LIZMjsTavxc3yrRVQmSdhLTDvmMJiixT+d0+WOPR
         ZIwFEWoRovgRAv/pbAAM0k3UfJgNy1dDi7BlPU22JTne5xcMkYY0a6Vq2NO3uT59fc8o
         seRC/pyl+WGBQ3O7OIRunaDfeqbRFdqxYyM0ogZrVyKdKTwSqEzDihS4Nh/hOQZ9+UUl
         9RYMkIuTPpcPe8UVChsJn+V7lvVhlPTFjvtfqmwS8sUIuKg1jYhVBrIpmM0A4aRoHXff
         L/r6pYJIp8reoWJic+g8Fvl0iA2yCsKQyVkXrr5LHrvsr3GJ+eVkC1blU1wVMLbzBu45
         9feQ==
X-Forwarded-Encrypted: i=2; AJvYcCVaQRshStqhzpzRmdJkCTedYri5W4h/7B0Ay4ZH8wU6ivgskW/pIous3RGY7uGGf9Cj5uPC0pJFzffFG9x6BGwXqNbg65RHmw==
X-Gm-Message-State: AOJu0Ywi7+Fm2F23grCB4ftBcNoDz42MprY7Dbfxt+IC3L4CacgSgtGd
	cPRCm/o3sXUzUJUwmAWTJV55nTq2PV89XhmN+w8H+yxdBty85qmM
X-Google-Smtp-Source: AGHT+IHw+3WIU+GsVyukY02MmBSxY9QNAiVnkWVb2Cyq1sYqqrPeSPmO9Mo0Of0oPnlJV23DX/yXUg==
X-Received: by 2002:a05:6902:1706:b0:e0e:46d1:174e with SMTP id 3f1490d57ef6-e1155b8593cmr2436052276.44.1723625791187;
        Wed, 14 Aug 2024 01:56:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5ed0:b0:6bd:7218:a1a6 with SMTP id
 6a1803df08f44-6bd7218a2c5ls82483966d6.1.-pod-prod-09-us; Wed, 14 Aug 2024
 01:56:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWicoL4Wd/j1+F9YL14++fBQgYo6B4c26l6H8t/Ci6VNxn8W37gzP4QFQTQpWwIOS71uwGZD1inRxNj/RBW2tmjYXL5nsbDn8vI3A==
X-Received: by 2002:a05:6102:f12:b0:492:773e:a362 with SMTP id ada2fe7eead31-497599eeeefmr2740121137.25.1723625790356;
        Wed, 14 Aug 2024 01:56:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723625790; cv=none;
        d=google.com; s=arc-20160816;
        b=TYR3UVfWMqCcKiHNOylcZr9wgS/gptem2S8B/TMJ08xe4PxqAKTexdexs7EuA4hWFH
         SPLoOpakdwgiTSWrUAFV3bK6I+sXrjlA7b9TMMdhIGi3cQJLiG/JjzO4pRBgLzLh7ulL
         ZoZx5LXq5S0DmAgDvSq443JG2PBEhPPTuPezGjPR66NvtUrTKBVyanXMBA87eJu5g3Ds
         aAaBWvzgubFyD432iQj7ymVgGivUK9R85K1n8optMYB5WW1kk+5V3S73dcq2Ycnp6wzv
         mvW8kMw6TWEi4CL8ARXAZwh7tYZYBxoH1MNWA70zbhNg8pocHGdlTJpMllf1UWRGiSbg
         NfTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BtxoKtjWvRqhjS0z2DQnl5gBuyvoRF+9CVzVIMvmZ6E=;
        fh=SaHcmmGZylsXyjL40ucCbj7ciJyzF0JJ1MRYwlsuolE=;
        b=wAllN9sSfpPl/03TC5YaXnYPOWJaIgyechYtD4Bd/JdnzFHkLfeQNDuRMkKwjNNuD7
         oLgh5//OYVQtQmkJPWX8XChjDrMZpLE9EVcSHEjNIT3wFUL4sB4DPvBdpgiAifjn4loS
         87avMqyXsQX1f77IBHQfEuSCKV1yMzijL87GRQiG1u3qTzqO+vQVtc3r13aXAeeEMmZY
         u1TUOtKoYXI2gwRPcnJCFdoc/jfuJSPi1Xsl4aA2zqV5uCsUv8BESH47AQBZtf2kKMW/
         yq/n3hlLf1PbuiH7b8sQoNi/cMAnCNLVCGksodZg7/zZ16UD56Y6oMrYJGJXnD/wnBNr
         7FDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=SYfAveZl;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4970a0ca5eesi536379137.2.2024.08.14.01.56.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:56:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 41be03b00d2f7-7a18ba4143bso4236721a12.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:56:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVrgJAxA+8Bt11Zz7jE1SD7Ad6Ef1nZkpU0s0u8ydnciKrPhz5Lv2CDfQ7ZqTtRJQFHjQdL0MUFTHqfcBBBJ9SsZmabjzJY6vWM+w==
X-Received: by 2002:a05:6a20:4f25:b0:1c8:edba:b9ca with SMTP id adf61e73a8af0-1c8edbabc7fmr1261808637.1.1723625789313;
        Wed, 14 Aug 2024 01:56:29 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd14a7b8sm25439615ad.100.2024.08.14.01.56.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:56:28 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Cc: llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [RFC PATCH 5/7] riscv: Align the sv39 linear map to 16 GiB
Date: Wed, 14 Aug 2024 01:55:33 -0700
Message-ID: <20240814085618.968833-6-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814085618.968833-1-samuel.holland@sifive.com>
References: <20240814085618.968833-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=SYfAveZl;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
Content-Type: text/plain; charset="UTF-8"
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

The KASAN implementation on RISC-V requires the shadow memory for the
vmemmap and linear map regions to be aligned to a PMD boundary (1 GiB).
For KASAN_GENERIC (KASAN_SHADOW_SCALE_SHIFT == 3), this enforces 8 GiB
alignment for the memory regions themselves. KASAN_SW_TAGS uses 16-byte
granules (KASAN_SHADOW_SCALE_SHIFT == 4), so now the memory regions must
be aligned to a 16 GiB boundary.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

 Documentation/arch/riscv/vm-layout.rst | 10 +++++-----
 arch/riscv/include/asm/page.h          |  2 +-
 2 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/Documentation/arch/riscv/vm-layout.rst b/Documentation/arch/riscv/vm-layout.rst
index 077b968dcc81..ed71b3b1b784 100644
--- a/Documentation/arch/riscv/vm-layout.rst
+++ b/Documentation/arch/riscv/vm-layout.rst
@@ -47,11 +47,11 @@ RISC-V Linux Kernel SV39
                                                               | Kernel-space virtual memory, shared between all processes:
   ____________________________________________________________|___________________________________________________________
                     |            |                  |         |
-   ffffffc4fea00000 | -236    GB | ffffffc4feffffff |    6 MB | fixmap
-   ffffffc4ff000000 | -236    GB | ffffffc4ffffffff |   16 MB | PCI io
-   ffffffc500000000 | -236    GB | ffffffc5ffffffff |    4 GB | vmemmap
-   ffffffc600000000 | -232    GB | ffffffd5ffffffff |   64 GB | vmalloc/ioremap space
-   ffffffd600000000 | -168    GB | fffffff5ffffffff |  128 GB | direct mapping of all physical memory
+   ffffffc2fea00000 | -244    GB | ffffffc2feffffff |    6 MB | fixmap
+   ffffffc2ff000000 | -244    GB | ffffffc2ffffffff |   16 MB | PCI io
+   ffffffc300000000 | -244    GB | ffffffc3ffffffff |    4 GB | vmemmap
+   ffffffc400000000 | -240    GB | ffffffd3ffffffff |   64 GB | vmalloc/ioremap space
+   ffffffd400000000 | -176    GB | fffffff3ffffffff |  128 GB | direct mapping of all physical memory
                     |            |                  |         |
    fffffff700000000 |  -36    GB | fffffffeffffffff |   32 GB | kasan
   __________________|____________|__________________|_________|____________________________________________________________
diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/page.h
index 7ede2111c591..09d15567b0b8 100644
--- a/arch/riscv/include/asm/page.h
+++ b/arch/riscv/include/asm/page.h
@@ -37,7 +37,7 @@
  * define the PAGE_OFFSET value for SV48 and SV39.
  */
 #define PAGE_OFFSET_L4		_AC(0xffffaf8000000000, UL)
-#define PAGE_OFFSET_L3		_AC(0xffffffd600000000, UL)
+#define PAGE_OFFSET_L3		_AC(0xffffffd400000000, UL)
 #else
 #define PAGE_OFFSET		_AC(CONFIG_PAGE_OFFSET, UL)
 #endif /* CONFIG_64BIT */
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814085618.968833-6-samuel.holland%40sifive.com.
