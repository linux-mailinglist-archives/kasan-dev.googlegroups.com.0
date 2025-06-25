Return-Path: <kasan-dev+bncBDAOJ6534YNBB3EN57BAMGQEQBP2H4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B6C7AE7E0A
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 11:52:47 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-32b500a9a28sf26432831fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 02:52:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750845166; cv=pass;
        d=google.com; s=arc-20240605;
        b=G6kuQX8HP4Z6vWGMySoZWTzWnMnPgH3/Xk17swFQnlFIN9hzxcgfjGuAAGv2tsbfi1
         HrkiRLv/i5BtqaUzm5H4zGjIukY5XVnia3+77TOsV/U8Rf4JsHpTWbtI4R2uMyAJmnqb
         34YXJQATnerBAVW44GJKoaIM3SzvIar79744t7JCTZQy+fhbIAye3RYQoDn4L/Ra43nw
         ggQSk9/PyeYobEjWvZX3mUmfnvoGtnPREek1knhKGkYlWoNTob7ao+eXnMLsgiOUyJC+
         x2sXkCqkxfxA06PtzH+v/ZztlefKQnQH082IHrkhTt6phHVsdmc6DT/IdcZu3nYy1O5r
         YJsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=u+z8P8uHV40GuP8/XSGExD6oZJshYos349jW3QfcMxE=;
        fh=zia1dAyPQbLrmAlzp84TkFAZhE8tsZcQ//dfwZAtnaQ=;
        b=jUsiFSfp7zwca2+YIb8+gFopAW+Cr518l8Z1fqNoPCPechZyF6s5ZVEL9DIHe05NGn
         pxoy3L7RXr0CvcGrUKlSruS05nt4vASi7JGJQy6aecSkxiFcUc8/aThe/Nt16nSS9xP4
         8P5ZF7R/pzkic4LL0ANFbOZeOd7B29o8WbSGXXpPfQ7YSbjVG2gWP6DyWw7rKaiGs6pZ
         YTUG8cpdqe287r7tSJDtNBql1ggXYWEP/GigVUyOjqHQ9bE2yfyWXm7ZuXu3VKdoNMcK
         hrJAWWgUTlbxzl2avAmaLJX/6M+kvKIXXvCNLKCazqGC1YbKtFrx5SeSs4P/O6bG5lSB
         lTkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FXJeLEOg;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750845166; x=1751449966; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=u+z8P8uHV40GuP8/XSGExD6oZJshYos349jW3QfcMxE=;
        b=Wz5CUl4d/WluhUfMDPdEe6lyHeoHu3v6lraSGnLQ0sQo+/6tTIKb6aKA2qPFkWFPPK
         LTf1G7qgmkGkgeOE2r6jA3RpdxUszYhVtkNmqQpIt8TuyHcwQXu3OdJnoZW1QyDJ3Pgm
         Yp+kscUGqLF8EMXviCnCKNOAOD67qjhO2ljf6jwcTrL1UPWAxrn2OpOH871uaMIhm5Lk
         Vj3+xFa6RFN3ODJAT8a1dyyWAVQ+087AAYU/cfDT3A/1k7Tyzxd5n18lzxbdrqv/32gq
         y1g6GNzEQjtlkzFXScvewFkHWN4QA+dsK7rMY8pEi2cp8xpwh2EJcgbckyLiqvyUsqO5
         888A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750845166; x=1751449966; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=u+z8P8uHV40GuP8/XSGExD6oZJshYos349jW3QfcMxE=;
        b=eLKUNrm4VGL9zl0rDy/OxJ8Y0d5EFvPO84Am/OzQZi0zV61GqqxqfZsB43bzxiJgWj
         /FB/OItFdgnMZjAQId7SVqYDdEmQQVaNINJxk6wc0qQ3zlOHRFU6AuH/0SKm615EiQnZ
         CAA3homoiu4qV9PCKzi201ZqwjX9jZC+oMDtZdQC8Lgo+7VTmEK7Htvuln/JglBhMKFq
         ioz0zNPN5I4OwK/ZSzvB61IIUHNWnNuLI1j4RYHNjKn9D9pUD6t/mo39cpR6ygA+Taw1
         jPIAb5feYo1rCYZAAR17xfMWtPkGza8YHubTD80lzr2nbCp8j8KD7MuPhALWo8nWe7BG
         NiJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750845166; x=1751449966;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=u+z8P8uHV40GuP8/XSGExD6oZJshYos349jW3QfcMxE=;
        b=PoCQMIr+PV9dEBun2CeHwW0iRFGVZoBi6U20I+T+hw1xZ/DLhUPon/Tv2pm/fRx2hJ
         b1+rqPavzKk6MlK9iej+mqnlueMS1cMdKVysDI+DiyBQ+qBMysSO0V2XKBB8Z3iXsRgG
         6f96YGlBy52tz/MWPJovzZOi4WhmIXD/taZj0B39dZ4LxvZH/xtlYJAkV9UHpCjy9Jrq
         9ngXOyoEA66Y7wrJdw87ZPmpD9CGYlhQy7WO0nnEEslRXKFOOF3qBxfzS8vHHumOweyM
         Sy+ZACJua1i6GOuucyD+3w/0pWwAxANUzP7ehCIRTM8wRA+rBfnd4J13EF9iF4n7lFZB
         GcgA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVpK5u+1NVIs3ytAZof8d44txLAtmUH2ufDc2ovSomOrYePpRpPb3thg+jzoImaGzN/UN2SNQ==@lfdr.de
X-Gm-Message-State: AOJu0YyaVCt0ed7Z6r6UztGBfELbs8b6ypFEby65WLVQ87UXGyoekqQz
	eWe5kOwWf8XPw2rEav99lLSfK2DITwAbl+0e8SG3o+dfMKLbxS2IQUTo
X-Google-Smtp-Source: AGHT+IEQcOY1OUowuhaSVFrLMEZvI6RAbWZnTR1aQhCbi5kFn4TQrCgw6cPOf3Ws3vEQjspWr7VbRg==
X-Received: by 2002:a2e:be9e:0:b0:32a:88b8:9bf with SMTP id 38308e7fff4ca-32cc64f7088mr6390981fa.9.1750845165408;
        Wed, 25 Jun 2025 02:52:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZedMY17pM84henwPCGau/YgGEl3Pa0qBkqQ2n4tTvNFYg==
Received: by 2002:a05:651c:221e:b0:32a:646b:ac65 with SMTP id
 38308e7fff4ca-32b8939e671ls19618821fa.0.-pod-prod-05-eu; Wed, 25 Jun 2025
 02:52:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUWBQP/TYhbVCJwWc7+5/nbzD5jujQf/Ah158QgXY6Gz97kgd+o1FX2vl0U29a23SxWGJmRlGYlx/k=@googlegroups.com
X-Received: by 2002:a05:6512:4024:b0:553:3514:1a53 with SMTP id 2adb3069b0e04-554fdcd60aemr708561e87.4.1750845162410;
        Wed, 25 Jun 2025 02:52:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750845162; cv=none;
        d=google.com; s=arc-20240605;
        b=dksouzLQlYjnzWBRL8qPNWmT1pItmtrYfzc6ky8yA4MgW8ymCfRwFSOCUNcmnZK57S
         js2AfcyPR5aj8ElWL3cTVj2QllbZiMJdyESG1Rmf4PAsMpGUrvo/sHRdAxmEy+RLyFuc
         UDvD7vl0aD4eHY7J0ZAgWPD0EXEKKkqSaIQ+hH5XCpq7321m9VZJXZyjpULEaJcggWO4
         w9Ye2XnxVFy9N5NK9jmgq6nj/vGdOZUh30Ougmm9Q+cCkv3Xyp+tVncJ2C6XaECfeQkt
         SVBVyMfm55GpAHHEHxPacwkNyNNMNH3uounzyH4LBVfNm7/h8UDcK/agCz0C1rgNZg3C
         j93g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=7imy3yTxK1noZpQDmXpRegf9/Y5dUmZKs6ukLVxlc1E=;
        fh=gljltb6ysCMIaKrogBuYpHruJBKVx6EqgxSjrAnYtRw=;
        b=Q6leZ/8kpSHvCYhOxZeT5uLds6dhAIkZ423u++CNvv35nahnFbnJiaH4E8KT2jlph8
         WRzn4lu+6QNre+l4f676NyqDm6S97p3FQUWPgmhpVaIsltkUIRMLEULw6t9T5+GZ5zc1
         W3lYaV1xczX7aWKGOY/3nNlHxh1YFqZa9YbAyFU7ODt/6E75G4aRBfFNS1zSpoPgpYFj
         +wpptqBZqCwPtIgnEhnWnRGvqNIUQVT6u910unTxcw8lG42UhwkESQ0lvJA7GTURcMwd
         PqYgFylyXYvVg7phsc3ZwRvleCTCmOv5kVsRn6WdE1lygjPbCYNiCfcP4e24dolDCu7s
         X4aw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FXJeLEOg;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-553e4141a7fsi434210e87.1.2025.06.25.02.52.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jun 2025 02:52:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id 38308e7fff4ca-32b7123edb9so60875211fa.2
        for <kasan-dev@googlegroups.com>; Wed, 25 Jun 2025 02:52:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVc+ZBGiLI7N/JPaR+ahN6omo3uqMLE1qHiOOGuJyqCNPXCHRwei/TKmffeorjTbC5MYHD/hZTayi0=@googlegroups.com
X-Gm-Gg: ASbGnctcqCOalyyfvoREJIbY6x7cvjeW9bFRMohbqdiihptXtuik7nXcXJMWt8qKNeX
	i4UB+4gT805T7QO4G/+wcnODJTgZqEwyEW5S3TlQKYRnqB9hgda6iwjsV5ZhC084RW3DBuNQxtO
	a3rWCkQqoik8knP1VS2ofvSmLlnlvDiJuRJhg8QS1MoA3jtsuNNLuBYifvC+rxQz+5lnsnn6gFj
	prt/VTuUb0VEOhCQqHkS9FUyuc/l9+8RLcVe+DUmCIVocPT11zIfQNhRpgdILtZuVvMbr8fiRPI
	vOKcBFTLcZ0eBx/2Tx7kla4lt8b2AWRzdTBbCzpVsscipog08jQTUye8N5eKcP3UMQLCwK/hBfD
	ExIcg6+2JZb88jJsgH+T0jhMwrBHctQ==
X-Received: by 2002:a2e:be03:0:b0:32b:3879:ce7f with SMTP id 38308e7fff4ca-32cc63451f0mr7075061fa.0.1750845161589;
        Wed, 25 Jun 2025 02:52:41 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-32b980a36c0sm19311851fa.62.2025.06.25.02.52.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 02:52:41 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	catalin.marinas@arm.com,
	will@kernel.org,
	chenhuacai@kernel.org,
	kernel@xen0n.name,
	maddy@linux.ibm.com,
	mpe@ellerman.id.au,
	npiggin@gmail.com,
	christophe.leroy@csgroup.eu,
	hca@linux.ibm.com,
	gor@linux.ibm.com,
	agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com,
	svens@linux.ibm.com,
	richard@nod.at,
	anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net,
	dave.hansen@linux.intel.com,
	luto@kernel.org,
	peterz@infradead.org,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	x86@kernel.org,
	hpa@zytor.com,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	akpm@linux-foundation.org
Cc: guoweikang.kernel@gmail.com,
	geert@linux-m68k.org,
	rppt@kernel.org,
	tiwei.btw@antgroup.com,
	richard.weiyang@gmail.com,
	benjamin.berg@intel.com,
	kevin.brodsky@arm.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH 0/9] kasan: unify kasan_arch_is_ready with kasan_enabled
Date: Wed, 25 Jun 2025 14:52:15 +0500
Message-Id: <20250625095224.118679-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FXJeLEOg;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::231
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

This patch series unifies the kasan_arch_is_ready() and kasan_enabled()
interfaces by extending the existing kasan_enabled() infrastructure to
work consistently across all KASAN modes (Generic, SW_TAGS, HW_TAGS).

Currently, kasan_enabled() only works for HW_TAGS mode using a static key,
while other modes either return IS_ENABLED(CONFIG_KASAN) (compile-time
constant) or rely on architecture-specific kasan_arch_is_ready()
implementations with custom static keys and global variables.

This leads to:
- Code duplication across architectures  
- Inconsistent runtime behavior between KASAN modes
- Architecture-specific readiness tracking

After this series:
- All KASAN modes use the same kasan_flag_enabled static key
- Consistent runtime enable/disable behavior across modes
- Simplified architecture code with unified kasan_init_generic() calls
- Elimination of arch specific kasan_arch_is_ready() implementations
- Unified vmalloc integration using kasan_enabled() checks

This addresses the bugzilla issue [1] about making
kasan_flag_enabled and kasan_enabled() work for Generic mode,
and extends it to provide true unification across all modes.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=217049

=== Current mainline KUnit status

To see if there is any regression, I've tested first on the following
commit 739a6c93cc75 ("Merge tag 'nfsd-6.16-1' of
git://git.kernel.org/pub/scm/linux/kernel/git/cel/linux").

Tested via compiling a kernel with CONFIG_KASAN_KUNIT_TEST and running
QEMU VM. There are failing tests in SW_TAGS and GENERIC modes in arm64:

arm64 CONFIG_KASAN_HW_TAGS:
	# kasan: pass:62 fail:0 skip:13 total:75
	# Totals: pass:62 fail:0 skip:13 total:75
	ok 1 kasan

arm64 CONFIG_KASAN_SW_TAGS=y:
	# kasan: pass:65 fail:1 skip:9 total:75
	# Totals: pass:65 fail:1 skip:9 total:75
	not ok 1 kasan
	# kasan_strings: EXPECTATION FAILED at mm/kasan/kasan_test_c.c:1598
	KASAN failure expected in "strscpy(ptr, src + KASAN_GRANULE_SIZE, KASAN_GRANULE_SIZE)", but none occurred

arm64 CONFIG_KASAN_GENERIC=y, CONFIG_KASAN_OUTLINE=y:
	# kasan: pass:61 fail:1 skip:13 total:75
	# Totals: pass:61 fail:1 skip:13 total:75
	not ok 1 kasan
	# same failure as above

x86_64 CONFIG_KASAN_GENERIC=y:
	# kasan: pass:58 fail:0 skip:17 total:75
	# Totals: pass:58 fail:0 skip:17 total:75
	ok 1 kasan

=== Testing with the patches:

* arm64  (GENERIC, HW_TAGS, SW_TAGS): no regression, same above results.
* x86_64 (GENERIC): no regression, no errors

=== NB

I haven't tested on the following arch. due to the absence of qemu-system-
support on those arch on my machine. So I defer this to relevant arch
people to test KASAN initialization:
- loongarch
- s390
- um
- xtensa
- powerpc

Sabyrzhan Tasbolatov (9):
  kasan: unify static kasan_flag_enabled across modes
  kasan: replace kasan_arch_is_ready with kasan_enabled
  kasan/arm64: call kasan_init_generic in kasan_init
  kasan/xtensa: call kasan_init_generic in kasan_init
  kasan/loongarch: call kasan_init_generic in kasan_init
  kasan/um: call kasan_init_generic in kasan_init
  kasan/x86: call kasan_init_generic in kasan_init
  kasan/s390: call kasan_init_generic in kasan_init
  kasan/powerpc: call kasan_init_generic in kasan_init

 arch/arm64/mm/kasan_init.c             |  4 +---
 arch/loongarch/include/asm/kasan.h     |  7 -------
 arch/loongarch/mm/kasan_init.c         |  7 ++-----
 arch/powerpc/include/asm/kasan.h       | 14 --------------
 arch/powerpc/mm/kasan/init_book3s_64.c |  6 +-----
 arch/s390/kernel/early.c               |  2 +-
 arch/um/include/asm/kasan.h            |  5 -----
 arch/um/kernel/mem.c                   |  4 ++--
 arch/x86/mm/kasan_init_64.c            |  2 +-
 arch/xtensa/mm/kasan_init.c            |  2 +-
 include/linux/kasan-enabled.h          | 22 ++++++++++++++++------
 include/linux/kasan.h                  |  6 ++++++
 mm/kasan/common.c                      | 15 +++++++++++----
 mm/kasan/generic.c                     | 17 ++++++++++++++---
 mm/kasan/hw_tags.c                     |  7 -------
 mm/kasan/kasan.h                       |  6 ------
 mm/kasan/shadow.c                      | 15 +++------------
 mm/kasan/sw_tags.c                     |  2 ++
 18 files changed, 61 insertions(+), 82 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625095224.118679-1-snovitoll%40gmail.com.
