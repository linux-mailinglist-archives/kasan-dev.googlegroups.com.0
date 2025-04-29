Return-Path: <kasan-dev+bncBCD353VB3ABBBO5AYHAAMGQE4BME3XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CBBFAA0115
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 06:06:21 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-224192ff68bsf48997935ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Apr 2025 21:06:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745899579; cv=pass;
        d=google.com; s=arc-20240605;
        b=WncdXDqZgrxZHEbV6P3RAM+oXU9UKuCD1JVlE3l+1v4KwdEXh4nSnhCwmVwkXjSI5s
         Ls1YPhl2SnXNIXdigu0ARBK99iyDmHk2y3m0L28qSuALF/9MrTW7hnb/bthBM6r00fvp
         jBm6FR+FkExPNyFdR6vJdrW/5a69MeXY4r1NoafOyedQlLvb1uyTz/5xYuzTc3YVzZ4K
         W8B0+HGQIkgrz7L4hl2+Jx74conHRIpBV8LiwkydTJsjNTYRpZzErAh90Ycm3Lg0CKax
         GRUSaYxFykKgL+1EMds30B2QGeq7r43PD1KTs8k7D4IXl4oXyZjBx1yZ2UxQH4rOopu3
         6mMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=HP/jp+ANGUUBzC8j8Q9OSnm2YtExEpQlOrcMqz/1vKc=;
        fh=pY3H3zFvWduE2jUOeGdhvHsWAB9KXYbCJUE9D2fuhCM=;
        b=M2aIDIwHAEkHpLwqBDAEUi2GQfhTztC8jMlrGyMR2tk8Fy3rtpmkOVFCnzF7XRGHWp
         7+mB0A0cU2V1UNLPsP6W4iZX56Gg4L4p2wjRM0PrCu653FVMMuciE7coj1I+R7RCs6Mr
         eZde5LlZNT0kLWaI21eGh+R2IgpZymDz/4lVn4Z2g+IPH/VtRm6KFXTGDIoa8amUKYUV
         XN6OW7EwKYvBK/2i0YAJfAnlQ/tiQ0Zaq3H1MD292oWOv5QVHypojrsZ/y4+7iUoB5Ug
         DqA2BNlgyj9ttGFzr7JKqhY6ZjAbjfW1ox3uOezFpPyMmd2ZV5IV6A1FcOStKpncxbOD
         +5Hg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ImSxOheg;
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745899579; x=1746504379; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:reply-to:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HP/jp+ANGUUBzC8j8Q9OSnm2YtExEpQlOrcMqz/1vKc=;
        b=u+uFXZEbtNN1K6IIg5APF/jS6bW4uGGW/zPPo9ucH22AJNA3AUvbABCIJIqq9fTYcL
         M9xm0jRINhTnJNXH5I4jBZ+IfTLN+pwZzoc5XSbCyGjWvtstfZBN91106bgAQz0XtAdr
         txtuihcUt91TdmVfZK2mbtyBYClwCqvOG++xP9PDeVnEquYguvvnQt1GGwhr5vfLcDsf
         TiA8SaOKRVJaFPYPBV5n/Yeb8sKnhRqlwgOAIlC2HqIUq47X03XdynYCSjgULclxGWTK
         fe56+FDZsisu85IRIBUbAlIWzgPs2hJCMZTnly7m8LWa3Xm14UFG6CUi0ktjW3yj8o89
         T/bQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745899579; x=1746504379;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:reply-to:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HP/jp+ANGUUBzC8j8Q9OSnm2YtExEpQlOrcMqz/1vKc=;
        b=K6yBjTe8LgD9h3YX65ilswPUb/0UejYwrXkW0OFQY5n9MnDkiFsIa1Nbp589533wWx
         we+q2GR+c8fn0oYNt/0v+60F6Qqux/quAaaBQ+tFeDMiD+Z2jhS0OH/4FCQMUvNAcBs3
         C3CDef7sdDyvPoErYmomkDZSWIOHa7znqmgWfXHFKCUEvq2smyj/G6yOz23X6YsoHZ8T
         unQ9sIdqpOvYAmVlD1YtTcTCJq2bTse73IlYSVZGGrDBNZyLdnFKfLHWon8vXFO4Dvpr
         cdO0PpTe06kJET6LFq+Pf80sipbatWUgGJBsQexsfSM5lqmck87RHa/PPb1RgCuBXf0M
         +NZw==
X-Forwarded-Encrypted: i=2; AJvYcCWVZjcIRrT8IMBQ1Yrv4E97B4Hgd6nc4WcNnDPHl2154YxmUtI1JoP/bPLMbZcL5lwvoSsHdQ==@lfdr.de
X-Gm-Message-State: AOJu0YxZ47C/snqw7bB4TlAnUa7L9B+YLC3ErhyYywr18v7udw3FDsxt
	8GRuFbA7a5cA2fKTSIiyPHMvyHSJ6hDlxjDAoSW8SzuFhgBQytlD
X-Google-Smtp-Source: AGHT+IHC/ExjPJ8rUAL7/7DvK0tMhUoESzoh/zEyhBqW95ndDtbUUsUejNJtTbG+IAoM/mvBxwUXwg==
X-Received: by 2002:a17:902:ec89:b0:224:1c1:4aba with SMTP id d9443c01a7336-22de7096811mr19931525ad.50.1745899579383;
        Mon, 28 Apr 2025 21:06:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGhdj8odeQjU6+7Bgp6CuMBuzXxPe9dKdcdA9Dmy23+0Q==
Received: by 2002:a17:903:19cf:b0:215:7e7:5e20 with SMTP id
 d9443c01a7336-22db12f264als12112295ad.0.-pod-prod-02-us; Mon, 28 Apr 2025
 21:06:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWU/NZMYEGih4m55wcK006esyH3WQtpBIoha4cxr9De5lO51DtDLvZFBPeoYdjSdDhSC7/FCqMynII=@googlegroups.com
X-Received: by 2002:a17:902:e5cd:b0:220:fe50:5b44 with SMTP id d9443c01a7336-22de7037cb5mr19469625ad.31.1745899578071;
        Mon, 28 Apr 2025 21:06:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745899578; cv=none;
        d=google.com; s=arc-20240605;
        b=Y62+VCvjaFcZ1wSmaO0l8FRjQ+sT088MQ9rUj89fL+hpQRbdGBbout98/I+gz5f7AO
         3wN+izmu1nd2HQqTSLpNaIetiAMh8LqH+Ye+k0+7EqtS3vU3X/mALg4UGjkmWmden9WQ
         InczkYPIMxSpWg1lAfI6C3bHNoFAI3vgyE4tm0kQqTIo0l+aB0Jy3+CeKcH61arcXZVq
         +VxExsDuYQPC5lgL20vPTz5jDMX8B1cFJyQMWQL6X5pgBA88qNq3Vt9sYZEvCvytDcXA
         z6qiJ0rCSeuLWOvYlNW2DLPTmKHGTp/2ZEwB1samMcvszQn+BlQAdJI3bKCu6eJT3TW4
         cG8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=reply-to:cc:to:in-reply-to:references:message-id
         :content-transfer-encoding:mime-version:subject:date:from
         :dkim-signature;
        bh=myVfGyM4QWerr4szyQd4EaWR6WV2JkWhStZMnwWd3T4=;
        fh=/bs3vO5UrVqo8T78tIeeq6rdQWrwj5Jc7+dDXJAvsfQ=;
        b=FhH1HLCflRu8LTI3vcVHNy0/KyU6QAOThsbUGgc+RsVOP3exfTtREm7hqhsYwaPDIT
         4uXAULZBo5uakkE9DwY04D3jVPARkp8RgY1KnykNfwVfeyxUnzoXzl2eVebs5x+UiLpf
         kpLABZ+5sPTRB0nefrv8GcfLZC0Hjxe00iIsxm1kGqYGwHOVGFxpGfUdI/laIFgG4kAc
         n5gZW1+sD16LC1RGy/PnGEZju40WjfANnJcruHhCMgBG8kP9uiHLDTFqTEwtf8bs9jVd
         Fergit876y4De1692w64qZsSFEI3d6EinVcG5kynsEFQmtvBCByXCxbRuF7g/u53IuAY
         aZpQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ImSxOheg;
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30a267d107asi20507a91.1.2025.04.28.21.06.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Apr 2025 21:06:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 3DF6D4A286;
	Tue, 29 Apr 2025 04:06:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 0B92EC113CF;
	Tue, 29 Apr 2025 04:06:17 +0000 (UTC)
Received: from aws-us-west-2-korg-lkml-1.web.codeaurora.org (localhost.localdomain [127.0.0.1])
	by smtp.lore.kernel.org (Postfix) with ESMTP id F4210C369D1;
	Tue, 29 Apr 2025 04:06:16 +0000 (UTC)
From: "'Chen Linxuan via B4 Relay' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Apr 2025 12:06:08 +0800
Subject: [PATCH RFC v3 4/8] tpm: add __always_inline for
 tpm_is_hwrng_enabled
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250429-noautoinline-v3-4-4c49f28ea5b5@uniontech.com>
References: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
In-Reply-To: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
To: Keith Busch <kbusch@kernel.org>, Jens Axboe <axboe@kernel.dk>, 
 Christoph Hellwig <hch@lst.de>, Sagi Grimberg <sagi@grimberg.me>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Yishai Hadas <yishaih@nvidia.com>, Jason Gunthorpe <jgg@ziepe.ca>, 
 Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>, 
 Kevin Tian <kevin.tian@intel.com>, 
 Alex Williamson <alex.williamson@redhat.com>, 
 Peter Huewe <peterhuewe@gmx.de>, Jarkko Sakkinen <jarkko@kernel.org>, 
 Masahiro Yamada <masahiroy@kernel.org>, 
 Nathan Chancellor <nathan@kernel.org>, 
 Nicolas Schier <nicolas.schier@linux.dev>, 
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
 Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>, 
 Michal Hocko <mhocko@suse.com>, Brendan Jackman <jackmanb@google.com>, 
 Johannes Weiner <hannes@cmpxchg.org>, Zi Yan <ziy@nvidia.com>, 
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
 Peter Zijlstra <peterz@infradead.org>, 
 "Paul E. McKenney" <paulmck@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, 
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
 Juergen Gross <jgross@suse.com>, 
 Boris Ostrovsky <boris.ostrovsky@oracle.com>, 
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, 
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>
Cc: linux-nvme@lists.infradead.org, linux-kernel@vger.kernel.org, 
 linux-mm@kvack.org, kvm@vger.kernel.org, virtualization@lists.linux.dev, 
 linux-integrity@vger.kernel.org, linux-kbuild@vger.kernel.org, 
 llvm@lists.linux.dev, Winston Wen <wentao@uniontech.com>, 
 kasan-dev@googlegroups.com, xen-devel@lists.xenproject.org, 
 Chen Linxuan <chenlinxuan@uniontech.com>, 
 Changbin Du <changbin.du@intel.com>
X-Mailer: b4 0.14.2
X-Developer-Signature: v=1; a=openpgp-sha256; l=3942;
 i=chenlinxuan@uniontech.com; h=from:subject:message-id;
 bh=kxFAxUbcgxKFCXw3/ErTxJwPqpRyvp2FJuqCBA7VzuY=;
 b=owEBbQKS/ZANAwAKAXYe5hQ5ma6LAcsmYgBoEFAxPbGcLXiOi/dV/SoVEXm3HRnbi5/8nSvZh
 +e82+25uS6JAjMEAAEKAB0WIQTO1VElAk6xdvy0ZVp2HuYUOZmuiwUCaBBQMQAKCRB2HuYUOZmu
 i+71D/9hbbS4WFdBy9iBvtGFu5uSk9QxvEUgVVEszHz05+5HiG4ksE8wbutqqbHRzodOZ4fTRqw
 FBgWQudMTfmZ9Fzj2OyQSpBDCrM8FsKFEp555qc9ICcP/+NEGCSsRMIq6JHxaZziOrAUiqsMpl7
 PDahCNl1FroL8m5qLyTgyojpMOANxIr1af/VNJ8bPL6C+kt3UbvxE1BQxJaGaFWwu4tuA6W2H6P
 99dM27ARBneT1Ci6a8VKJuN083PUS0DxYveGnH1FdDIjWVzoNOuccgzNF0F8v4/nl2tP84KxlLQ
 oPDVasKXAZJN0tEcMKQIwEAC+r1bcpKYHpMRVEYDYmBa264Q5nFxMISnjvLEJCKf83yqHDECcUe
 tggtJisUCNA23s3fRH1vFO5aVh1wasktvWFK0rezqWKiiSOynNsUWjQButCpUZofWo4wTHmJihb
 Ia2GiI8yLBpkdorp4xsf4SL4zvcLOzgirApNORHtHhkb9txKJ20L2WHS1VhiW7xpl3ejCcR9CpP
 YW9L2nkVmlDG0qngRaNtWv3EZCV/wN9/811wqZzwMQLNekcn/t8lq9fv9RB/bPjq7aCVZESyGER
 OBAzAGQDg3kym5GaVrbjje99pIap2zj0QwO9eZHif/0av9uHNFusDMAZGbKPHCqaEevUMehhBGq
 Eom+AMw7eNH7lTQ==
X-Developer-Key: i=chenlinxuan@uniontech.com; a=openpgp;
 fpr=D818ACDD385CAE92D4BAC01A6269794D24791D21
X-Endpoint-Received: by B4 Relay for chenlinxuan@uniontech.com/default with
 auth_id=380
X-Original-From: Chen Linxuan <chenlinxuan@uniontech.com>
Reply-To: chenlinxuan@uniontech.com
X-Original-Sender: devnull@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ImSxOheg;       spf=pass
 (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org
 designates 172.234.252.31 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Chen Linxuan via B4 Relay <devnull+chenlinxuan.uniontech.com@kernel.org>
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

From: Winston Wen <wentao@uniontech.com>

Presume that kernel is compiled for x86_64 with gcc version 13.3.0:

  make defconfig
  ./scripts/kconfig/merge_config.sh .config <(
    echo CONFIG_TCG_TPM=y
    echo CONFIG_HW_RANDOM=m
  )
  make KCFLAGS="-fno-inline-small-functions -fno-inline-functions-called-once"

This results a link error:

  ld: vmlinux.o: in function `tpm_add_hwrng':
  tpm-chip.c:(.text+0x6c5924): undefined reference to `hwrng_register'
  ld: vmlinux.o: in function `tpm_chip_unregister':
  (.text+0x6c5bc9): undefined reference to `hwrng_unregister'
  ld: vmlinux.o: in function `tpm_chip_register':
  (.text+0x6c5c9b): undefined reference to `hwrng_unregister'

With `CONFIG_TCG_TPM=y` and `CONFIG_HW_RANDOM=m`,
the functions `tpm_add_hwrng`, `tpm_chip_unregister`, and
`tpm_chip_register` are compiled into `vmlinux.o`
and reference the symbols `hwrng_register` and `hwrng_unregister`.
These symbols, however, are compiled into `rng-core.ko`, which results
in the linking error.

I am not sure but I think this weird linking error only arises when
auto inlining is disabled because of some dead code elimination.

`CONFIG_TCG_TPM=y` and `CONFIG_HW_RANDOM=m` set `CONFIG_HW_RANDOM_TPM=n`.
This causes the function `tpm_is_hwrng_enabled` to always return
`false`, as shown below:

  static bool tpm_is_hwrng_enabled(struct tpm_chip *chip)
  {
      if (!IS_ENABLED(CONFIG_HW_RANDOM_TPM))
          return false;
      if (tpm_is_firmware_upgrade(chip))
          return false;
      if (chip->flags & TPM_CHIP_FLAG_HWRNG_DISABLED)
          return false;
      return true;
  }

When `tpm_is_hwrng_enabled` is inlined, dead code elimination
optimizations are applied and the reference to the `hwrng_*` functions
will been removed.
For instance, in the `tpm_chip_unregister` function:

  void tpm_chip_unregister(struct tpm_chip *chip)
  {
  #ifdef CONFIG_TCG_TPM2_HMAC
      int rc;

      rc = tpm_try_get_ops(chip);
      if (!rc) {
          tpm2_end_auth_session(chip);
          tpm_put_ops(chip);
      }
  #endif

      tpm_del_legacy_sysfs(chip);
      if (tpm_is_hwrng_enabled(chip))
          hwrng_unregister(&chip->hwrng);
      tpm_bios_log_teardown(chip);
      if (chip->flags & TPM_CHIP_FLAG_TPM2 && !tpm_is_firmware_upgrade(chip))
          tpm_devs_remove(chip);
      tpm_del_char_device(chip);
  }

When `tpm_is_hwrng_enabled` is inlined and always returns `false`,
the call to `hwrng_unregister` is effectively part of a `if (false)`
block, which I guess that will be then optimized out.

However, when the `-fno-inline-small-functions` and
`-fno-inline-functions-called-once` flags are used,
tpm_is_hwrng_enabled is not inline.

And this optimization some how cannot occur,
leading to the undefined reference errors during linking.

Adding the `__always_inline` attribute ensures that
`tpm_is_hwrng_enabled` is inlined regardless of the compiler flags.
This allows the dead code elimination to proceed as expected,
resolving the linking issue.

Co-developed-by: Chen Linxuan <chenlinxuan@uniontech.com>
Signed-off-by: Chen Linxuan <chenlinxuan@uniontech.com>
Signed-off-by: Winston Wen <wentao@uniontech.com>
Reviewed-by: Jarkko Sakkinen <jarkko@kernel.org>
---
 drivers/char/tpm/tpm-chip.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/drivers/char/tpm/tpm-chip.c b/drivers/char/tpm/tpm-chip.c
index e25daf2396d37bcaeae8a96267764df0861ad1be..48cc74d84247e258a39f2118e03aa10d0cbb066a 100644
--- a/drivers/char/tpm/tpm-chip.c
+++ b/drivers/char/tpm/tpm-chip.c
@@ -534,7 +534,7 @@ static int tpm_hwrng_read(struct hwrng *rng, void *data, size_t max, bool wait)
 	return tpm_get_random(chip, data, max);
 }
 
-static bool tpm_is_hwrng_enabled(struct tpm_chip *chip)
+static __always_inline bool tpm_is_hwrng_enabled(struct tpm_chip *chip)
 {
 	if (!IS_ENABLED(CONFIG_HW_RANDOM_TPM))
 		return false;

-- 
2.43.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250429-noautoinline-v3-4-4c49f28ea5b5%40uniontech.com.
