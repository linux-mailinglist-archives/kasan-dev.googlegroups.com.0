Return-Path: <kasan-dev+bncBDXY7I6V6AMRBDVZ6KOAMGQEOONGAKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D9E364EF0A
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 17:27:59 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id c21-20020adfa315000000b002425bf67a87sf604169wrb.19
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 08:27:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671208079; cv=pass;
        d=google.com; s=arc-20160816;
        b=iyL+jUPg+EMUbkCtgrB+rO1ILh+7Jr8AtEYWkR8URcx28il+Z/QU5mydLBNz/UtKyY
         M09GkivwosAbii6mAOZ+Wt/fo1/9nNJQT5g5moVu3pWGDBCQTjl2HeiU6vmRHOEbb9dD
         ke164HhCr5OOBJUTtvnGqxCY8Hx6QQkwmM77ZicjUsEbu8ZrjvxVgmy9XPH7PSMZymKt
         1ZsEwggD8Rn7qGe/9cI61Kd3sK1H6iJ3ZqW9UrCDBkWU/ekq/Yb7G14o9bE7PSt+WOsj
         U+L16pFqzs8jZgSOvj9332rW/OOyapcVyzUlQSl1RXKN3dSllESjBWnUbFFjZInLI+ha
         aHyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tyCr42r42/AhYizS4AZt3cLROyzAtlv2IVpxjL1BYhM=;
        b=GJWyYG9tc/ml6YDR2RM1kI6k9HaJZpr0T9FAxwDzcnZpQQuRk/MR8QM5pfqkGszuAT
         kQHlhe9MUGU2Yo05nnxYxkDsBLJ7cbaTzUChC/Cc02N0SL3W1mJz3NwjSYdxnI+g/L3G
         rKUYeHoVpYixYbiVDGG5tuxnQDwL8x6t003gG3UzQYkqMF4JxdkMUnqbB1sb8rs1g5xQ
         M94rh2lRJjmysk7gqRlE6t5aLRm/1s+ZOTa/pMPsEDZXwe5r95OfbETpgFCC+mhVHAr7
         TYTvJujiavAoyRbnS7q18nJDglghaLD9Xgf0P5aw/XWUkKPyE8/AFmI9YmPOlQ9rj0Y8
         ERhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=vhEZGm1Q;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tyCr42r42/AhYizS4AZt3cLROyzAtlv2IVpxjL1BYhM=;
        b=Cl8mZiMVV1JFsNqiVUzinpuU5k2F1wivccetgcUaV2JRq17PaJyhMgiM2+Jht0U3gp
         CSEiD2U879af1Z2iLaETnK3+1fSLQOy8nlJSe0kYFHgxC82C7VNGKcW0oWayvy1YgjxX
         8DK6zflLZgBgBN7PnAa4g7Zidw5kv6p+Ae/RyAnoyuIrWVN1M60UlqvEYAgFaRmwqAxg
         fF7DOl5VQjDlw/rhqrTt3QnRvpQoutBZaXZnmpfwy7/RrjKfwbY7JdXAWGjcli8SssFt
         Pv2gwAgkJYNp418OV1jGLA08GPIV8tQTHf0HRzWgiJy7iC/T6qgPeoAMMGsA8I51RHOH
         /JqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tyCr42r42/AhYizS4AZt3cLROyzAtlv2IVpxjL1BYhM=;
        b=4c7LGfk2BE0zboU+hDw/4wH5HH4CQdh7ZgFVBvU+yR8SIbq+GQXw7I0O0sNmU/ImcP
         Z8ffUTmkvtb6h65PgtobJWjx8/zq5xgOBBz/LCRhyvBQictDg296p44GGOYAu71g9QqZ
         9U7xPohWwDzz0YfQpgVWW/gm2pc8q+outAPXQyllxC9ElED6Kzadedz0+wNBNMNQMF+j
         39BCL9qtpmko3YaYk0m7UmzjnEJxrARQ8eQ9ZV93a9lPDZ5TwijHK3aj6htGLWb3NlA+
         +pnhG8+VSwyfxNZtBNqq4o5j5XxxpX2BYcuAVbE7CvZrdZiC7ItTriAYZ6kMYXHUckth
         IDUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmtAPmXRBHAbH18B7UddaB6T9rT/D6SHEq2R0Qt7SMuVTielRo5
	ftdANDHLNqPSfR39vnagtoE=
X-Google-Smtp-Source: AA0mqf5Xs0oO5MvuLY44AEvweSS5Z1Qzl4nY3MSMJ1/S9CMluALxKIz5J1oDL5aJcyJ+SF35DHWagA==
X-Received: by 2002:a05:600c:3496:b0:3cf:d70d:d5b3 with SMTP id a22-20020a05600c349600b003cfd70dd5b3mr714204wmq.202.1671208078877;
        Fri, 16 Dec 2022 08:27:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:ac7:b0:3cd:d7d0:14b6 with SMTP id
 c7-20020a05600c0ac700b003cdd7d014b6ls1563939wmr.1.-pod-control-gmail; Fri, 16
 Dec 2022 08:27:58 -0800 (PST)
X-Received: by 2002:a1c:f216:0:b0:3c6:e60f:3f6f with SMTP id s22-20020a1cf216000000b003c6e60f3f6fmr25933260wmc.38.1671208077911;
        Fri, 16 Dec 2022 08:27:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671208077; cv=none;
        d=google.com; s=arc-20160816;
        b=Lwes1O2e1A2T35VXHMFryQ2E5M+NyS8vcmuQrwYD3PpyNXIdSHvNI9VDxfNiOpgQcj
         fk+6Fj/AZZMQHiA9pu5sdANQFbGO3HpO+3ulmCgCJFi43kUvXnMwTAjKfcN+HDVbDaYa
         4vTHowxlFLAlkzX0NXU6GZ5E9bwv1KMIjPlYJ2DXWCQ9JhwSucgT1G4eM+nx1KCS/WGH
         lvzJIrRfGntPvrh/G8Bck/q4DE4m7Peu0b2/9bk2sPzt0vWti7sRgThmDS1ITIbjX3nU
         RXoNrTG2QFrgqalmUz7QLU14CzgiXOLL7T7HUD0dF/NrH3MaFRf+4W3pkzfEsJsiPa/k
         ebeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/qYMZscnhg3axVtI2bTNdXZnKgui98AcKoWlQAnIeCs=;
        b=wLAMXXyQzJl8RyDSRNnK+VqcStQepB6oCNfCFHiLxARRbiYkNXN3eM9QWsDXI3IYTu
         Lb6tkYkFckbwwScADqbyMzkjI9+jniFnRnUj0rdFCus07O9Eg/0OAihIoxNvOvBxUV4Y
         VOZJQI50gfhhVAm9itQGXDeo8w4ioOmAJRnMhkIUhIEklmZ4gpd56qQVKC4pJ+XKsbfH
         4TVC/c41afuxE7B4ojM3walsHtzqGRxCz8FdoAw2f/5KRd7v82tli0rAdegdERDHP90P
         BVJYM7zQxblfkiESPnMFT4tinnTP9qLRutz3H+MKnox+nqIRnuEBMpHN0gfozwgPzn0n
         JYoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=vhEZGm1Q;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 4-20020a05600c22c400b003d2051f87ffsi408363wmg.2.2022.12.16.08.27.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Dec 2022 08:27:57 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id i187-20020a1c3bc4000000b003d1e906ca23so1573080wma.3
        for <kasan-dev@googlegroups.com>; Fri, 16 Dec 2022 08:27:57 -0800 (PST)
X-Received: by 2002:a05:600c:34cd:b0:3cf:c2a5:5abc with SMTP id d13-20020a05600c34cd00b003cfc2a55abcmr26558882wmq.17.1671208077738;
        Fri, 16 Dec 2022 08:27:57 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id i27-20020a05600c4b1b00b003d220ef3232sm2784387wmp.34.2022.12.16.08.27.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Dec 2022 08:27:57 -0800 (PST)
From: Alexandre Ghiti <alexghiti@rivosinc.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH 6/6] riscv: Unconditionnally select KASAN_VMALLOC if KASAN
Date: Fri, 16 Dec 2022 17:21:41 +0100
Message-Id: <20221216162141.1701255-7-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20221216162141.1701255-1-alexghiti@rivosinc.com>
References: <20221216162141.1701255-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=vhEZGm1Q;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

If KASAN is enabled, VMAP_STACK depends on KASAN_VMALLOC so enable
KASAN_VMALLOC with KASAN so that we can enable VMAP_STACK by default.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index 6b48a3ae9843..2be0d0d230df 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -113,6 +113,7 @@ config RISCV
 	select HAVE_RSEQ
 	select IRQ_DOMAIN
 	select IRQ_FORCED_THREADING
+	select KASAN_VMALLOC if KASAN
 	select MODULES_USE_ELF_RELA if MODULES
 	select MODULE_SECTIONS if MODULES
 	select OF
-- 
2.37.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221216162141.1701255-7-alexghiti%40rivosinc.com.
