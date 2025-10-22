Return-Path: <kasan-dev+bncBCU4TIPXUUFRBAW54LDQMGQEG4ASRSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id E1130BFB594
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Oct 2025 12:14:28 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-7848b193cc5sf14106507b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Oct 2025 03:14:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761128067; cv=pass;
        d=google.com; s=arc-20240605;
        b=XGy2GpBGJQe5pd2HtkXT5/aNskPumd2KnrlBoOhJTWgkftVq1NmorGsus5v3cCLwEW
         eZZReES4sVAUuBTKvCU9FjITKYWcPgLsyD9zSRGZBCj4BSPSrh+sM2lTIwBuRnItd5sS
         u7+cwKG8LxWHL3Hj8WBmsJIf0vUaNYPLMqKeXKFCBbFAGpdfJtpI2rfQtbEoIzL9cX20
         CyZS9pz7rJzm71RKuGrfquIzuOsRU4QtaMfwiyV4Mrn7i0rRy4ACIXJzZ8EbYpSYiAiC
         2QvSJRdNgieo+MMXR7g49SM1P6ewl1FImWALF4PJtyO1WFEIORVqcHcBCZV2/SmmoATb
         tQNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=a1UpeoP1hsDizUf8XhqqEvOtiTm1B3oUomjEVNX9yZU=;
        fh=2xnfHrLRgwwTx3nnJoxYjaLZYVXf660Fdc/LPUH4SSQ=;
        b=Z+eXEPI8LaL5lRFYA/jQ0GutqKI87B7LicgGMPRdFhuTrcLEcJhUPiHovO7rnscxjN
         /XKaobYI8Q4tghLeeHz16KUNYaYF4C52I943wfCyD17as7VPNeyrUYdu4Y5RHdPyz8kw
         5sQadYfztaeH/8qu7mmysbC5ui3TxVK7oZKmZkeitTKAVXrdOxdcrxdL7jLKjMdoZj4U
         TsMn+i6HPsPfFMbCuBHg7HwT/4NDQ34Pai0kGLdz3NMY0XsPWP7pPeJtTEoGjLvx9IlA
         R8bfY0t7WWjxozmPwpPljApAMItkcLaDuNNWzfRBvnU2zsAnPT6fvvSOpjZD02jzRYou
         rmAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MFXjCo9z;
       spf=pass (google.com: domain of ardb@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761128067; x=1761732867; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=a1UpeoP1hsDizUf8XhqqEvOtiTm1B3oUomjEVNX9yZU=;
        b=isatOa16jKQqmMY1NDLdMqe1HyR4eZ8OSrzlJ3DjvSh6zA9dXHPSdFMp2x5W7shUzN
         Flyu6/6UoN6ULp4NJLqWKWe4o31qF8Mt8SWtnORKpvH1rhBYfJDf2YuNF1UhMg4DMTYW
         FKMsEEjyyyz/7MaK51ryhJnMnR0wi79W06FKfz+8xwyuSyxvlEkVx/nOAcNWnWwRgQGW
         IVJbWwTzREz6BrKSMwvG5pALtQxGB/ZGtabtDDeODYc8jhV4eLkFXNzVuZhN+QBFcaLN
         aeXkvqbVtCNixyqzfffYajA26qaE+aftRcntqRDQtdKs4nwYo5CeDlBOCoLpLk7ykZ3u
         MGnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761128067; x=1761732867;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=a1UpeoP1hsDizUf8XhqqEvOtiTm1B3oUomjEVNX9yZU=;
        b=s8enWdAiUxoslLAKTRF5/OX5TVsfMqQ4XTefBaYV07QCP8FFdtZ8bEKxNpSEbZrO14
         4GD06XIfSa1HA/XknYq/F0r5k8mXWo7gdDMM7kbeoaeV9LbZ1kULkYANw16E9G7Tkxyd
         XJ6BSKA1ZrMenD4w1akqHR+SRdIN3UKNJa4Tk5tvNHdmrb8NOCXLtrcmq/YX3zNctc8q
         8wXixZZsWuvtE8Ro8q5RnlgDavXI/grDwGJN5ss5X/HU/oAJDKyD22IfbV5HpypYlLm6
         CZmNP455nXZ4Cg25gsCbzz9Fp0ZomneWRfTItGeT5ejUcOEMM7s9uBGhhxPFFQAvtpn5
         o3Aw==
X-Forwarded-Encrypted: i=2; AJvYcCVdATOMaFHDTnBmAdABtFs0ECnaSzccay692WnTOqAtaiwW1RYkd/0g9KBmv/f1hXoD0Mr3xw==@lfdr.de
X-Gm-Message-State: AOJu0YyGishm13E/sFFOrnbuoj648sZEg9wS2TYQ7E+mTeVLXB86gtYq
	ZRCVouu+FexiNQwtVS3OcYy4OsV64KJ/QSPZO4UZelAIjtBJDFdNRKse
X-Google-Smtp-Source: AGHT+IEG/YSbmEBEF8PmCcc+t8xDTT+ddOSxOqmWgBXt294kGOhwe1iB3ATFnyBxoUZwgz8vcjwnqg==
X-Received: by 2002:a05:690e:151a:b0:63d:83ca:9e53 with SMTP id 956f58d0204a3-63f2823c6f3mr2001566d50.4.1761128067108;
        Wed, 22 Oct 2025 03:14:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7es10xinkewP2g4E7A8FPI4eLn5qAv6SPNAgY583/jEA=="
Received: by 2002:a05:690e:141:b0:63c:bedd:3afa with SMTP id
 956f58d0204a3-63f28af080als410820d50.2.-pod-prod-00-us; Wed, 22 Oct 2025
 03:14:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVoawzxlYdRomFQ5e8YqLr1CuNsTTlJCzPb+iaW1OvQWOqMDTfvfZpJGfax7CHctywd1sk2Pi0r0lM=@googlegroups.com
X-Received: by 2002:a05:690e:2514:20b0:633:a6fa:386b with SMTP id 956f58d0204a3-63f2829ff16mr1772052d50.9.1761128065931;
        Wed, 22 Oct 2025 03:14:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761128065; cv=none;
        d=google.com; s=arc-20240605;
        b=bA2d3X78S8Klp/HWw5bgud45YqKHFDWp0VM2CqukQCJpEDcj722Wec/SIcnhsKdRhv
         Epicg+EuoFdO7TIi7neqDAghyeXGu0UMJx6tMoKEU5hnFIYEVpY/zkJBpUzSUx9fdN9q
         6iryozPvTOY/Ax6XAFOC0vGmhIUkuZ4HB70HbDiXlZ2NApeNqAKfwftrrREqvPstvlMz
         ATC8kAHQfCwbGFaX0VdDWFJt2zXs3/R/JqJBN/Hcn1V7GhAeJhSaC/3ZZiArXtF2AfqG
         JR+8SELYnw5wEWt5M3LAZwUwYFFn2EW6YMJoY+1jOYUQlO0nts6vX18QwdHuVut4SP0S
         Ss4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sZfYX+Oj2G0IFK8wm/HdwhknS176NiznuineJy4SZe0=;
        fh=3Xn9mYIlQMedG7eeZB8jMfXLuC2pd747YiM2HPF37rk=;
        b=N2HV+NAzFmc2Ce/KVuzg3OO3LmhFW0KXF6vm1HUx4lsi5Q9yKrCIC9Ft+5OCQPk/oq
         e4LXoLC0shWgucxXa1Hn4iHNfr5g5ltFczMzZFga0IKIHNPuOR9fknFl0xcVFIypXhFI
         VBYZ6jwZcNrqCJT5nAbJ6eFBAIcVGOvLW1dt09JELaLHszu5x0UcgGfY1iLWPCn7ARB4
         O7pOo7EloigbwEyKeZDTMfArPxO0/kNWTDHvMvfnABKNf8mo68NuY+gr5nKl4OE2Tphi
         1PsL23fbSmTjFW8gq9qDkFPtz6B2dSlWulK77EHKHArJmQyKsSmjd3HstD8a/kOcVdP5
         D8QA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MFXjCo9z;
       spf=pass (google.com: domain of ardb@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-784a531f31csi4258007b3.0.2025.10.22.03.14.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 22 Oct 2025 03:14:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 400BB62366
	for <kasan-dev@googlegroups.com>; Wed, 22 Oct 2025 10:14:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DC88EC116B1
	for <kasan-dev@googlegroups.com>; Wed, 22 Oct 2025 10:14:24 +0000 (UTC)
Received: by mail-lf1-f46.google.com with SMTP id 2adb3069b0e04-592ee9a16adso1106811e87.0
        for <kasan-dev@googlegroups.com>; Wed, 22 Oct 2025 03:14:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWT3hU+hIRKMKYD0QDMmv0BvXLF2/fnn0KHSomepa+Ioj3EGFTSVDz3ZxfICgDCUuNrCQ50QC21w7A=@googlegroups.com
X-Received: by 2002:a05:6512:3d92:b0:57b:5794:ccda with SMTP id
 2adb3069b0e04-591d84faa97mr5623451e87.20.1761128063284; Wed, 22 Oct 2025
 03:14:23 -0700 (PDT)
MIME-Version: 1.0
References: <20251022033405.64761-1-ebiggers@kernel.org>
In-Reply-To: <20251022033405.64761-1-ebiggers@kernel.org>
From: "'Ard Biesheuvel' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 22 Oct 2025 12:14:11 +0200
X-Gmail-Original-Message-ID: <CAMj1kXEjihuC1Wa8fWUqsvsJM6YJZ0wmuhkqicNAfQiHvnWkYw@mail.gmail.com>
X-Gm-Features: AS18NWBSXzD203ZzkosAKi9Rr6vw53-JkbJxJJd1qk8yGMrx1SL9k2NwvTwhKzM
Message-ID: <CAMj1kXEjihuC1Wa8fWUqsvsJM6YJZ0wmuhkqicNAfQiHvnWkYw@mail.gmail.com>
Subject: Re: [PATCH] lib/crypto: poly1305: Restore dependency of arch code on !KMSAN
To: Eric Biggers <ebiggers@kernel.org>
Cc: linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	"Jason A . Donenfeld" <Jason@zx2c4.com>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Pei Xiao <xiaopei01@kylinos.cn>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	syzbot+01fcd39a0d90cdb0e3df@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MFXjCo9z;       spf=pass
 (google.com: domain of ardb@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Ard Biesheuvel <ardb@kernel.org>
Reply-To: Ard Biesheuvel <ardb@kernel.org>
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

On Wed, 22 Oct 2025 at 05:37, Eric Biggers <ebiggers@kernel.org> wrote:
>
> Restore the dependency of the architecture-optimized Poly1305 code on
> !KMSAN.  It was dropped by commit b646b782e522 ("lib/crypto: poly1305:
> Consolidate into single module").
>
> Unlike the other hash algorithms in lib/crypto/ (e.g., SHA-512), the way
> the architecture-optimized Poly1305 code is integrated results in
> assembly code initializing memory, for several different architectures.
> Thus, it generates false positive KMSAN warnings.  These could be
> suppressed with kmsan_unpoison_memory(), but it would be needed in quite
> a few places.  For now let's just restore the dependency on !KMSAN.
>
> Note: this should have been caught by running poly1305_kunit with
> CONFIG_KMSAN=y, which I did.  However, due to an unrelated KMSAN bug
> (https://lore.kernel.org/r/20251022030213.GA35717@sol/), KMSAN currently
> isn't working reliably.  Thus, the warning wasn't noticed until later.
>
> Fixes: b646b782e522 ("lib/crypto: poly1305: Consolidate into single module")
> Reported-by: syzbot+01fcd39a0d90cdb0e3df@syzkaller.appspotmail.com
> Closes: https://lore.kernel.org/r/68f6a48f.050a0220.91a22.0452.GAE@google.com/
> Reported-by: Pei Xiao <xiaopei01@kylinos.cn>
> Closes: https://lore.kernel.org/r/751b3d80293a6f599bb07770afcef24f623c7da0.1761026343.git.xiaopei01@kylinos.cn/
> Signed-off-by: Eric Biggers <ebiggers@kernel.org>
> ---
>  lib/crypto/Kconfig | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>

Reviewed-by: Ard Biesheuvel <ardb@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXEjihuC1Wa8fWUqsvsJM6YJZ0wmuhkqicNAfQiHvnWkYw%40mail.gmail.com.
