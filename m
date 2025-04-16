Return-Path: <kasan-dev+bncBCVLV266TMPBBYHC767QMGQE247KMTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 54310A90ACA
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 20:05:22 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-3912e4e2033sf3207909f8f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 11:05:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744826721; cv=pass;
        d=google.com; s=arc-20240605;
        b=XGwLfaI6BhARN0ilqJouuR4Omentp2hIirKt6QRJJDNJ2yCT44L8s+9Jt0ngWn8WR6
         r2A4WxJh0LwwQ7KAZo4OVO9A097TsrNoIHyo9K7yaVHpKS27Q/zG5OhTUIeRhB0mpyZv
         MJnsbd5P1dXQk7UwdC9eBnwuVQwZUGpKcDoDe8y87kt84+//TVB1ZmZWm3uci2/ceuWK
         TOG1ZVBwpTUHZ49YytP7mFI9asLztURdXwTNrRikWS/cVfPK+rh+NpWepElw338cmKMh
         S4botE99/AfOroKK4ixbFjYkzCsFKUyWfmaWOpJxDIkEGZzPNTkFGJEkNBTAqw2Sf3AK
         dDwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=W2/hs3GZg2nhE1DUnBvo0LA/7zTtmeTRdls6EtawAUc=;
        fh=QT81Y9xxPQwia32e7cT+I51hxn+SdsdEe8S9MIdQbZ4=;
        b=Kn2rnrS+NnOoBpYdm2Mcc2Z25uhE+Ru5fiuBzIIZUzE+v5fKYlZRq5GENNaUQiGKIc
         8i6BUlrwqJoodsMchN8DT6WXxqQ6Z1soQRr/TlzP3ZN+vCuXqw3rV3zAlg4636yNhn4k
         7VPD4f9rdcoAXIus9O4W5z8MLSmQC1yptRpEtEAVtJRdB5VYng8HDsH4uYuhHS4WJNe3
         obaIcgBaaFxw17bCItOW0kXhBQhiN+bdwEsGaSuBxEulTPOOwZX5SZXIfWv1VZ8KpAFM
         BQC/OdI13qW+cZNMgDuoTvNBVBEu8bFnJU46/ML9+GSL3yCNR5NjVSK6Qzw8vgyW86La
         jh8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Bg7AiPUh;
       spf=pass (google.com: domain of 3xfh_zwgkcyy2wy23kpkqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3XfH_ZwgKCYY2wy23kpkqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744826721; x=1745431521; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:from:to:cc:subject:date:message-id:reply-to;
        bh=W2/hs3GZg2nhE1DUnBvo0LA/7zTtmeTRdls6EtawAUc=;
        b=phTPGPJrvz/lDrROpRg6der3EZwE5M4E1KOK02jSX0AqN61WDqLQg7OEvuNKCr98Iz
         xyedZrUvmnvU98SbcNoaWUTWGww/F0dKAGwJMzBKcp1gLL5bL0DPSip3Z+Y+k0DGBRBE
         oycRnlyWLSabwDcD6u7az1vPrEA5ptHve88SuWI6nQUzqjQiH68S4e95sPgfY9RTkwwf
         MmLoRr2HvB/KybO8kdOcbmFSgxWCbta4/gDTmMYQfAiUra/LB4jrJr7c/3vkr+edT5SZ
         X73gLzPESgE9Rm/wJFZ8EbA8kQFoQaQYgXCNCdrSPFV0DmNoK59Mu+HFI2zeQVUup1t7
         cUNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744826721; x=1745431521;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:x-beenthere:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=W2/hs3GZg2nhE1DUnBvo0LA/7zTtmeTRdls6EtawAUc=;
        b=sWBjOu3n+o2tHKOUmholjx/tXHW/3hOWzZDG6oYhg3lESPuE/gpyAfNxLx8tHgB/Hf
         9r5fqM1s872jk7xXHsk5bB2ZJPBIUdR918wNT/SryLxi/OK6TYiqg/mxqJGipCSRTwn4
         M13wqo2BY3Y6+8SWqCRfPl/Rcx45qjN2sLVaHhSJBzLgAAQI1+oh0qUcfRzP8W7DSbDb
         CiD/KxaKWPsnvKYhn0x1zbHYdi17Gir80Gw/KBtPNLqFop1dHJ2BpJKJNbQKYgNj3uxF
         MatYKGC5qWFL1xT5CoL3ySmqTAzFqqYxTzj+QHlL3i91EaqDqEQ5wmQMzvrjFMD4oAEf
         jIVg==
X-Forwarded-Encrypted: i=2; AJvYcCVNksxZJ0SJ3nSZEDMaJYbb54qS1+Qym9BZP2EmX0Fu/Vj6mU4CVo+nk2iWldB7pkPA1ybA6g==@lfdr.de
X-Gm-Message-State: AOJu0YxjI315S4pjhUy2CkMkfD6g8FiNGZgvN4CjREXLr8SXahkL00pD
	vYzLxoi+Sg9Z0d71DT3ZGjKHbg328V40igxOWe4gZ8P7ANDxEMVv
X-Google-Smtp-Source: AGHT+IHqcwvK5t+4qkZzpDMTR5xPobxOf4O0THB7iQnhq1ldfbbjhEksYi8NNvkHmt1b49ep2lXA5A==
X-Received: by 2002:a05:6000:420d:b0:391:3915:cfea with SMTP id ffacd0b85a97d-39ee5b993c8mr2385573f8f.38.1744826720908;
        Wed, 16 Apr 2025 11:05:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKm5piu+xC7Dv5KcuPgJTcdaicIXQdexoOR9eBY4yKi2g==
Received: by 2002:a05:600c:c86:b0:43c:e3ef:1640 with SMTP id
 5b1f17b1804b1-4406227a85fls619085e9.0.-pod-prod-04-eu; Wed, 16 Apr 2025
 11:05:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVatgLtvIw29brksdIAQfzngnz38hrsr0ephzxi4Dj9QWdztTh7NegklcQct/4iB/UNycpdMdFRIiA=@googlegroups.com
X-Received: by 2002:a05:600c:1d2a:b0:43c:f513:958a with SMTP id 5b1f17b1804b1-4405d62506bmr27899735e9.13.1744826718048;
        Wed, 16 Apr 2025 11:05:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744826718; cv=none;
        d=google.com; s=arc-20240605;
        b=ElA0X3MzFeUZSIzWB3ODXW3y/Jdx7pUMNVorv9g8BUCD1xh/zja5oHvz3LdebdY3ql
         E573s93t5KVbfiSsvRribf828rj2SE2MGEZ4UeTzIz5Lk6MEuCPaBpm7Z0Fx20TO2M++
         KuNjoqyRwfUfOVmgwOlMO7CYeC5j3EdvNlLfiDHIFzDdqFVSTQJPuM5oobZtXcE1IBUf
         C72SGZlqPhTK+eK3PZ39jfulNrhHB+rrDeXufv8zGoHUgZjtvTXdl5ipZoMWUHdg2u8g
         dtozz0R5FjGdxKTzjBPpsx83K8MQOERW+pwwuKDcEY3s49w7gLzAHanh9+59AIrZH+O+
         7Chw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:dkim-signature;
        bh=l4zrBJJLCZeJhENR6VmafxLFJBE/IGwmNNec6pbe9xA=;
        fh=cOwMQpGgBUiVsnhHk3lImzocmoIoi0/fHZDA8KTlvJE=;
        b=ePWjh29+JG16yDOU+JMiU5VdQ7alAiFkb67vb8yHO0L75EwPeIHK5eD+tpkkC7yc+G
         U5ihtfG01aZ2BoCZ415ZBAoXxN0HOezu2UAyOcueiJKn09xHiwQEPA382GAIerod42Ic
         ZOy2SJ3yBBsOn/2a7y7mdS41bzSj7T37ncHptRg48KwxC+vrnMLlx28jfwfICjM6+LGp
         T+zBnK2CB+qSDyYj0rAv0CR/Qv1sUZAVIC7FcnNCHRjF0CVlxRFJZcOHW2OBkPN0DDK5
         AA1XK4FJZFHMyVqBlLsjLSAHiSi1Jz4gYULzxbDc9gc6M1LXG9ZRs2jNxsBy3VzeEC6C
         Uzmw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Bg7AiPUh;
       spf=pass (google.com: domain of 3xfh_zwgkcyy2wy23kpkqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3XfH_ZwgKCYY2wy23kpkqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-44045a6cbfbsi3305745e9.0.2025.04.16.11.05.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 11:05:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xfh_zwgkcyy2wy23kpkqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-43d0830c3f7so53788595e9.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 11:05:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUdQWvE/mkebqUE77GJZE17mKR5LDmSFsscR2Dfwk6r3tTU16pJb14iNzA0PAtCkKQsCKn9D7LFowQ=@googlegroups.com
X-Received: from wmbbi11.prod.google.com ([2002:a05:600c:3d8b:b0:43b:bf16:d6be])
 (user=smostafa job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:1ca3:b0:43c:fe85:e4ba with SMTP id 5b1f17b1804b1-4405d637b49mr28449355e9.15.1744826717658;
 Wed, 16 Apr 2025 11:05:17 -0700 (PDT)
Date: Wed, 16 Apr 2025 18:04:30 +0000
Mime-Version: 1.0
X-Mailer: git-send-email 2.49.0.777.g153de2bbd5-goog
Message-ID: <20250416180440.231949-1-smostafa@google.com>
Subject: [PATCH 0/4] KVM: arm64: UBSAN at EL2
From: "'Mostafa Saleh' via kasan-dev" <kasan-dev@googlegroups.com>
To: kvmarm@lists.linux.dev, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Cc: will@kernel.org, maz@kernel.org, oliver.upton@linux.dev, 
	broonie@kernel.org, catalin.marinas@arm.com, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org, 
	hpa@zytor.com, kees@kernel.org, elver@google.com, andreyknvl@gmail.com, 
	ryabinin.a.a@gmail.com, akpm@linux-foundation.org, yuzenghui@huawei.com, 
	suzuki.poulose@arm.com, joey.gouly@arm.com, masahiroy@kernel.org, 
	nathan@kernel.org, nicolas.schier@linux.dev, 
	Mostafa Saleh <smostafa@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: smostafa@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Bg7AiPUh;       spf=pass
 (google.com: domain of 3xfh_zwgkcyy2wy23kpkqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--smostafa.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3XfH_ZwgKCYY2wy23kpkqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Mostafa Saleh <smostafa@google.com>
Reply-To: Mostafa Saleh <smostafa@google.com>
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

Many of the sanitizers the kernel supports are disabled when running
in EL2 with nvhe/hvhe/proctected modes, some of those are easier
(and makes more sense) to integrate than others.
Last year, kCFI support was added in [1]

This patchset adds support for UBSAN in EL2.
UBSAN can run in 2 modes:
  1) =E2=80=9CNormal=E2=80=9D (CONFIG_UBSAN_TRAP=3Dn): In this mode the com=
piler will
  do the UBSAN checks and insert some function calls in case of
  failures, it can provide more information(ex: what is the value of
  the out of bound) about the failures through those function arguments,
  and those functions(implemented in lib/ubsan.c) will print a report with
  such errors.

  2) Trap (CONFIG_UBSAN_TRAP=3Dy): This is a minimal mode, where similarly,
  the compiler will do the checks, but instead of doing function calls,
  it would do a =E2=80=9Cbrk #imm=E2=80=9D (for ARM64) with a unique code w=
ith the failure
  type, but without any extra information (ex: only print the out-bound lin=
e
  but not the index)

For nvhe/hvhe/proctected modes, #2 would be suitable, as there is no way to
print reports from EL2, so similarly to kCFI(even with permissive) it would
cause the hypervisor to panic.

But that means that for EL2 we need to compile the code with the same optio=
ns
as used by =E2=80=9CCONFIG_UBSAN_TRAP=E2=80=9D independently from the kerne=
l config.

This patch series adds a new KCONFIG for ARM64 to choose to enable UBSAN
separately for the modes mentioned.

The same logic decoding the kernel UBSAN is reused, so the messages from
the hypervisor will look similar as:
[   29.215332] kvm [190]: nVHE hyp UBSAN: array index out of bounds at: [<f=
fff8000811f2344>] __kvm_nvhe_handle___pkvm_init_vm+0xa8/0xac!

In this patch set, the same UBSAN options(for check types) are used for bot=
h
EL1/EL2, although a case can be made to have separate options (leading to
totally separate CFLAGS) if we want EL2 to be compiled with stricter checks
for something as protected mode.
However, re-using the current flags, makes code re-use easier for
report_ubsan_failure() and  Makefile.ubsan

[1] https://lore.kernel.org/all/20240610063244.2828978-1-ptosi@google.com/


Mostafa Saleh (4):
  arm64: Introduce esr_is_ubsan_brk()
  ubsan: Remove regs from report_ubsan_failure()
  KVM: arm64: Introduce CONFIG_UBSAN_KVM_EL2
  KVM: arm64: Handle UBSAN faults

 arch/arm64/include/asm/esr.h     | 5 +++++
 arch/arm64/kernel/traps.c        | 4 ++--
 arch/arm64/kvm/handle_exit.c     | 6 ++++++
 arch/arm64/kvm/hyp/nvhe/Makefile | 6 ++++++
 arch/x86/kernel/traps.c          | 2 +-
 include/linux/ubsan.h            | 6 +++---
 lib/Kconfig.ubsan                | 9 +++++++++
 lib/ubsan.c                      | 8 +++++---
 scripts/Makefile.ubsan           | 5 ++++-
 9 files changed, 41 insertions(+), 10 deletions(-)

--=20
2.49.0.604.gff1f9ca942-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250416180440.231949-1-smostafa%40google.com.
