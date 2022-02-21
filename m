Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBTHVZ2IAMGQER6KGTZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id C4C0D4BDAC9
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 17:16:12 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id h21-20020a05651c125500b002464536cf4esf918722ljh.23
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 08:16:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645460172; cv=pass;
        d=google.com; s=arc-20160816;
        b=sLy0CFMxlFo1Oa0drMcghRhwekLojN9QJO5A2SN7wGTDMEQ2HnVRy83EcSgXmCnB+u
         9QKE+0mcgsy+vcewNcqS6njAOsmZNkzYKx2CXr+ZIvicC/TgyajwZ6wMVNxDrCsngep2
         GtNyrIJHPCYzD4Os/QyokcJFPlyfPVqaLEeWTC9Xf55fklGnqZyd3jjUeKrPQpMtYw5n
         XRtQ49tm6DwRof1JHOlNQPekKq/AQZjy7t8e7qKZy/3y9JRTg4tQo1LYNUb+nlkrwpe0
         jDTtzYvcLmVAOIHNaLjPkGR1ylrAbqHITkOS4y939aR3pXiBZXDm6bfQx3hCcoaoA1yM
         4OqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=XX6+bK8tkp6etAaStRg9gkh74ZJ+lNtBpzl+KY8AODk=;
        b=YBhWD2z1mwQPqdChjet8N8UqafCTNhhtEM1Uj8d0why9waL9SgTcD3oviiMNQBJYQs
         kyb7hOy3jRx7oxXo6mf20kq/fh/Aj0Ly3mTosJmCwY7n6xzOu6Zc+50QTgKvVj0Dwlxt
         OE6UEbqqu+MuoALjHKMbyFIe2dCHUGfFA4QsmpyfrNqWtGA+858fi/jZcvAtwBpZ5HBn
         bYjtKVkZ35t+Vcu0+nSnD8EIRFzfYyLIG9AxPiYlJif7dkKjjoR4FwJHDv8uZC/hNzwW
         JxYVe2U+CE1sHca6B1BQNnU1ldvFNzNRWL9IrrIPj43F2PGWveK8ZOKjBLMMB8wXiUuE
         7RjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=a4EFzjDZ;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XX6+bK8tkp6etAaStRg9gkh74ZJ+lNtBpzl+KY8AODk=;
        b=X+vliwf4VSws8dc9P3Ncz00z/PXsw54GzrHd+HigQ2xc3wngA3iv+8DVIyH8JpM/3p
         yTLJEJVevBu+QcuR+oGaVBjAvJaqTX75ixZ49nKLg+6bvW+2JF4/+unkGuanpcI8Zi6D
         aDfEyS7NyKfCNARo+N65WyiYqlAce51Q0VD4GHsviDijWF28F+N1JImp3v3o8Di1LHal
         9wyKj3l7ddrnfjy9c09KhkDRfzxneNmaHvUixSGvgqEO7Rxgz9C31kdZEqEnDtoiiJCl
         nzf+rBo1H/qS5/7Juw3xxje3dFVsJXKUjVg1eEkIduZdRQsolptCx/o+uliIxA5Ka09F
         tWPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XX6+bK8tkp6etAaStRg9gkh74ZJ+lNtBpzl+KY8AODk=;
        b=7Oa/hjlY7sICqfN+uiLQvJUpW0lcCWAgkvgLh1Q70voa49BunDTJgB5BvahgWCojYe
         f7NGLZEonNrt5E6V4sDBQT48pXBDwpkEuQZ3WrI5FAN22gmsPU3VVAkV6l/r74B4R2+y
         lDZ+Y8sLKBWgaCJlrTYRbKxWRKCcUVL7xdHcYpliTaTigxG5wpoSaNBusRdXXUcsQPIV
         EPNacUCrXdz5SVzP7GARyYkTXZsDBNz4y6mvXj2kIpHPKwEsMMgdnZ6bap1NTW48Zqsl
         U2OyB05ZxtxR9VVIAsJpsFtiBOGe6HmX4zeiBBXFP1E1ywRSsQb3++xK9G5sQaREhE7y
         0dmQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533mA82002jDaBmLyIYUYIgDI5RKxOOxLl6oLUOFOhSKT85ujC72
	XgZ5rvK4nKJDen8oK5uznvk=
X-Google-Smtp-Source: ABdhPJx0Sn49eYlKBOA+ihcCKzEvWM7w+sT72xM4gsa2LSLahRkiQXAB/FcJX6oTAA+YItPsk1MAvg==
X-Received: by 2002:ac2:4e11:0:b0:443:b076:460d with SMTP id e17-20020ac24e11000000b00443b076460dmr12144386lfr.209.1645460172370;
        Mon, 21 Feb 2022 08:16:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:211b:b0:246:3700:8bf with SMTP id
 a27-20020a05651c211b00b00246370008bfls804785ljq.9.gmail; Mon, 21 Feb 2022
 08:16:11 -0800 (PST)
X-Received: by 2002:a2e:a60c:0:b0:246:4739:4b40 with SMTP id v12-20020a2ea60c000000b0024647394b40mr1094009ljp.526.1645460171090;
        Mon, 21 Feb 2022 08:16:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645460171; cv=none;
        d=google.com; s=arc-20160816;
        b=aMIwWxE3wlPs/m07Wf2hhdmkk8LCC/LPTTGJnO2wFsfsAvXYZXBy1TSmmTJ3jsp6c5
         xj1evOGzicMTGPHgFraewvb0khSfNl97S3oaGCR3RR3I8W1ydKJEKfQy0P9kPhRpsWq0
         frPUu5gqdznG668hG1CfSt/LBz1ziTWPF8JHtMxzx5I+GT4ILQ4dWuYqsDwIAgUSK5/z
         lai4+EEt7jFMDw6lIOLYt+simzlqc23Q0tqfKUx08bnCIHE1C7oxo/btdjUFlvhMIhkq
         TSImW8X459x6eU/UfT/abiQBVe1ZPFtN6D3dK2LZP/caOI9cT6cA4A6r1BbSskgmbRMf
         HomQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=cguSXJTSK/jUGjEgH9bI1vq5RLn1H9fQDOjhSSVs79w=;
        b=DGUSvCh2Slsamt3uzHT4YphAfRz7nFAjoATPtwS8cfxgxEKXlS4v3yZKg5UTROvUA+
         H9S08YAEaoqbVGTvaD3SUbJAdUxyw7Wze/LUHZzOjFjUEw26skaCFKWDfpo1GN0rlNcv
         MCETJzB+l1KnViwoL/DvPyJv18UQpWCo66wKYCe0vDAAvV6uY41+7HmOvpKMgrfeSgJA
         4GnHwoaDLwa50Gh+7rYq6FVFjpCBjOUsYr/5HsFlMzl0gGvhUW32UHYvQqKuJnpdyvhq
         ny635xRFJQX1GkNHJkj5WF49QzSRCVnKPfY9b0aJBwKtBfp1qwlvmQYmcKz1RcGXkUC4
         RZ/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=a4EFzjDZ;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id d35si401239lfv.5.2022.02.21.08.16.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Feb 2022 08:16:11 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com [209.85.128.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 6830C3FDC7
	for <kasan-dev@googlegroups.com>; Mon, 21 Feb 2022 16:16:10 +0000 (UTC)
Received: by mail-wm1-f69.google.com with SMTP id 7-20020a1c1907000000b003471d9bbe8dso87974wmz.0
        for <kasan-dev@googlegroups.com>; Mon, 21 Feb 2022 08:16:10 -0800 (PST)
X-Received: by 2002:adf:f14e:0:b0:1e4:a64c:c1f8 with SMTP id y14-20020adff14e000000b001e4a64cc1f8mr16542835wro.512.1645460170156;
        Mon, 21 Feb 2022 08:16:10 -0800 (PST)
X-Received: by 2002:adf:f14e:0:b0:1e4:a64c:c1f8 with SMTP id y14-20020adff14e000000b001e4a64cc1f8mr16542818wro.512.1645460169981;
        Mon, 21 Feb 2022 08:16:09 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id r2sm10098731wmq.24.2022.02.21.08.16.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Feb 2022 08:16:09 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Nick Hu <nickhu@andestech.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH -fixes v2 3/4] riscv: Fix DEBUG_VIRTUAL false warnings
Date: Mon, 21 Feb 2022 17:12:31 +0100
Message-Id: <20220221161232.2168364-4-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20220221161232.2168364-1-alexandre.ghiti@canonical.com>
References: <20220221161232.2168364-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=a4EFzjDZ;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

KERN_VIRT_SIZE used to encompass the kernel mapping before it was
redefined when moving the kasan mapping next to the kernel mapping to only
match the maximum amount of physical memory.

Then, kernel mapping addresses that go through __virt_to_phys are now
declared as wrong which is not true, one can use __virt_to_phys on such
addresses.

Fix this by redefining the condition that matches wrong addresses.

Fixes: f7ae02333d13 ("riscv: Move KASAN mapping next to the kernel mapping")
Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/mm/physaddr.c | 4 +---
 1 file changed, 1 insertion(+), 3 deletions(-)

diff --git a/arch/riscv/mm/physaddr.c b/arch/riscv/mm/physaddr.c
index e7fd0c253c7b..19cf25a74ee2 100644
--- a/arch/riscv/mm/physaddr.c
+++ b/arch/riscv/mm/physaddr.c
@@ -8,12 +8,10 @@
 
 phys_addr_t __virt_to_phys(unsigned long x)
 {
-	phys_addr_t y = x - PAGE_OFFSET;
-
 	/*
 	 * Boundary checking aginst the kernel linear mapping space.
 	 */
-	WARN(y >= KERN_VIRT_SIZE,
+	WARN(!is_linear_mapping(x) && !is_kernel_mapping(x),
 	     "virt_to_phys used for non-linear address: %pK (%pS)\n",
 	     (void *)x, (void *)x);
 
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220221161232.2168364-4-alexandre.ghiti%40canonical.com.
