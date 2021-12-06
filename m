Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBFW2W6GQMGQEAH26F7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id A7442469499
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 11:59:34 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id y4-20020adfd084000000b00186b16950f3sf1899676wrh.14
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 02:59:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638788374; cv=pass;
        d=google.com; s=arc-20160816;
        b=yXRpFxDkk8l7560gJF0cXs3RceMbVvWgcO7jaH4gM3+SuPE5uPnP3XfAeNjGr026wh
         8fijEUKYO1yKokR5hoClSigHYTIo37SMHqeyxFl8UALcxRwMBDbVIvEu0/wJ5wEh0uhk
         8LNJFOu9TIaGU0jMigQUNHFEBoSTzECp5XrUtQLbjvU1+rT2q2GyyxWJDOGQs/9rWeZu
         urZgz1tdzGBCrVrXL9Nlevdm5+28AfXBq9xI9qsahYKx/OyrysQhotlQe4Xkdp9BJ/y4
         Tuxz/AEOjPV9i9rZRerV/yb1p1X/+e4N4ClUpJswmJgnDnQRZz9PvEHjX8qVPPstNXsh
         jvdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QuPy2V6Y7n0b/gZt+bog+t6MvfrJVAOZk+BFGMPjE/c=;
        b=Mdm8/wRjOkQgxHll8rFJfQms66pKDY+XpHwgUpbj3xP+v36YTQsXg+jDxr12+lkxJ4
         nbRK9NWz27aFg3FrRQbMtlkmu5AqAYbrnZPncH+N1SwnPsTwv/8JMwb1o1s8wurfhTWX
         qAxuSXDo5ZWmfRfkvSaqMeCP8IBl/NmQ81HdOCzVkN55JmM818/BRw1DjqUqI7gJIcMo
         d+3hrnxpk5ge33dwNDsf6Ct4FtJspsdMx/9KbnUkRAzXs5TXioft+hGpmOJVlPDf5Yjw
         1dtNBhC5tgWDIe4cDpjAwPgs9KSWaJVYPNwsWQ3e86AJQqx8XwGTV9ExfcWe55Hh+hWQ
         FX5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=dXCclNLR;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QuPy2V6Y7n0b/gZt+bog+t6MvfrJVAOZk+BFGMPjE/c=;
        b=iiNIbig3ueEY2zELmQJf/1Ka6/pqtNVrKtdw4OKrEHP3Lk1c6VdLCUD4a4FMe0cE+Z
         4wsuuVLhoIkhmaG0h/0KvpbHQfmbhA5YkkGCv4Krw80V4UXXC4mGqbfZDVniyZbvST0Q
         jLpwJkXhqDdNTlgo2JQC0JnH6Xfwl6SkrD//daFc1r3w5oq47IDdBa5zJMzwcyFCm6wg
         ++vj3qlUE6JEkanDz8U+FmdU+5TOJVkiOlCvf2iYVfldLilL/++OaMV83kQoYmg/Tpyh
         QMn/vLa6yUb6jQ4tSayeTXG5W2/QtIZie/ISMIkTEWDCC3wuT3ynmxMy/vZvS/aNk36N
         2UfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QuPy2V6Y7n0b/gZt+bog+t6MvfrJVAOZk+BFGMPjE/c=;
        b=gHAH1NyDZJ+4Ly5qRpZt0h+N53ZY31bIOwUjggNeTCH9U4tA4g1qkuIcKaF3s3Wo6z
         7udSvroBajJ20m8s+CgbUbjeW7Gp5C/XImwp6bpj5muXY7xf4h/HmdMaPMIVpDmVmXBs
         xYsomZDMKLSbT33wd8sNn7dlaGH2pi1kH9In+/ZkaRvebZVN3LH86+GbueNsI5D1wJH5
         /MWfh0eni2/OIvSbq6jszb53wseCYwVOjy7aqalcy1QRfM7PC39kNB6mRsYbK/S64rV1
         GZxVVUNtMyHdzoEVvgS1RGO9R7rMBH9J04tAiVao5O30zo4iqcS0RuOsmj1zmxqYHAz7
         Djpw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533mEA7QEgxzxb8K6aqUqWiyaeNfy7t/UZk42NPxqNn5Wr62ND9F
	VlBQLQu5TPN8G86uc1j6H1A=
X-Google-Smtp-Source: ABdhPJwQ9EiMPYXlI+7zvC8d8vEY60zKjzrDeBUl/Ih06csXD04IlrVXIKmO3AChf05ucHkhnpMDqg==
X-Received: by 2002:a1c:4d8:: with SMTP id 207mr37939152wme.23.1638788374426;
        Mon, 06 Dec 2021 02:59:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f1c2:: with SMTP id z2ls363488wro.2.gmail; Mon, 06 Dec
 2021 02:59:33 -0800 (PST)
X-Received: by 2002:adf:df89:: with SMTP id z9mr41847286wrl.336.1638788373544;
        Mon, 06 Dec 2021 02:59:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638788373; cv=none;
        d=google.com; s=arc-20160816;
        b=naSB2iLU8+SX6n02+PohHGUKaCEGqNIcxI0sNnQiY83JmT77ZvlYEouKyGopMz9JAB
         Zn9pfV9nHMC1ebl4KiJeR4D1ZBY2wRDog4IYCNdBgSKLxIDbK30397KZ0Fw9+WcKoW/F
         RWv2OdeT8a0pophYbXv9tczcctUZN9RnO+ywI8Aw8B+gtADVZb/Xnl4GW4MckhDzlW5T
         LEPuviSFMVD7Tz67WdSMzDDVPTD7b2o/gUvrtpVZo30RYmOsKIoG90zPoA4g97Fh2Gk8
         sXqk0YARdNR2Hej2AWu+JGjQOdm4TEilGKOUCbQuLDACTLbB2EUXDbtjapKasa3It8tP
         G3Bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Mpf1+wFXToHvdF/Ol73oVGZ3N1s6PxZDoxH3qziN9eQ=;
        b=s07RrnIjELmee5D5T1OOb1TwTrteBYVxP0fYv2wJUpE7w/LAdC+mmX/kxaGMBCQx5k
         MLRypWH76Wq7ydrJ6jV3VJ+bw0G1Ezd8UY5hlhp6xItFk9ZuFwHDDbt2FLg5ylUo5m9n
         GdALAlKPmjMG/IICfOGr10J+DZarTR1QnlvYYVKFC0QRXPi/JS08jeQ8DSynPrXWdeeF
         HNtAwdDNDK3j3zRRHsrjRvGdtO5Z7/ishAZHjMC+6sVC6Q7VzlVzjeDbLSaMPc8ZZX1b
         oYIE7mewmr/yn6NfwwlFKw56b49vXPtnlPAU0cseTd3xaXE7TaVVwNj19xf6GWZp5wy2
         a+Vw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=dXCclNLR;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id c10si707732wmq.4.2021.12.06.02.59.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:59:33 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com [209.85.128.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 56B0A3F1F9
	for <kasan-dev@googlegroups.com>; Mon,  6 Dec 2021 10:59:32 +0000 (UTC)
Received: by mail-wm1-f70.google.com with SMTP id a64-20020a1c7f43000000b003335e5dc26bso5917762wmd.8
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 02:59:32 -0800 (PST)
X-Received: by 2002:adf:c146:: with SMTP id w6mr43633006wre.541.1638788371828;
        Mon, 06 Dec 2021 02:59:31 -0800 (PST)
X-Received: by 2002:adf:c146:: with SMTP id w6mr43632986wre.541.1638788371627;
        Mon, 06 Dec 2021 02:59:31 -0800 (PST)
Received: from localhost.localdomain (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id l15sm10625964wme.47.2021.12.06.02.59.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:59:31 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Zong Li <zong.li@sifive.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <Atish.Patra@rivosinc.com>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Kees Cook <keescook@chromium.org>,
	Guo Ren <guoren@linux.alibaba.com>,
	Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
	Mayuresh Chitale <mchitale@ventanamicro.com>,
	panqinglin2020@iscas.ac.cn,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arch@vger.kernel.org
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH v3 12/13] riscv: Initialize thread pointer before calling C functions
Date: Mon,  6 Dec 2021 11:46:56 +0100
Message-Id: <20211206104657.433304-13-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=dXCclNLR;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
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

Because of the stack canary feature that reads from the current task
structure the stack canary value, the thread pointer register "tp" must
be set before calling any C function from head.S: by chance, setup_vm
and all the functions that it calls does not seem to be part of the
functions where the canary check is done, but in the following commits,
some functions will.

Fixes: f2c9699f65557a31 ("riscv: Add STACKPROTECTOR supported")
Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/kernel/head.S | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/riscv/kernel/head.S b/arch/riscv/kernel/head.S
index c3c0ed559770..86f7ee3d210d 100644
--- a/arch/riscv/kernel/head.S
+++ b/arch/riscv/kernel/head.S
@@ -302,6 +302,7 @@ clear_bss_done:
 	REG_S a0, (a2)
 
 	/* Initialize page tables and relocate to virtual addresses */
+	la tp, init_task
 	la sp, init_thread_union + THREAD_SIZE
 	XIP_FIXUP_OFFSET sp
 #ifdef CONFIG_BUILTIN_DTB
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206104657.433304-13-alexandre.ghiti%40canonical.com.
