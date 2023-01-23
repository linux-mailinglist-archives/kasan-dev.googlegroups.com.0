Return-Path: <kasan-dev+bncBDXY7I6V6AMRBZ53XGPAMGQEJVZ5B4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 08F126778CC
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:14:00 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id f14-20020a0565123b0e00b004d048024c76sf4835768lfv.17
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:14:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674468839; cv=pass;
        d=google.com; s=arc-20160816;
        b=r+RovUzl5kQwSzrn7sYbRDThLirR4o8pq6HZNP1QVMavuOe/E26GD9liMHGsBvvAMq
         G4aLXbqHdX+lWTiEjeIHNFoMHQnqpNc0cYrFArtLCouTOfEAIZFPFtcuATlrAA8VCNl6
         99S24kcQoOtYYtN8rib6HJkg9PXVkBTA5mz2nQVi2NC0Ts4w7swE0Yr7qp25C6NtUOEP
         ipQK0T4sOEbHWBjApa76EnLLOJs8bNoSLUBK109m5JResBM6YwGnl3NNJgDq7DsC2BiB
         5UVbhnMCxk/FMfLoB2Hrk2Fvx1IQf+1MNhMPXaeNWm07S5X0UOfbvUEYMF0O+sEt0EZ/
         4MIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WvDVTKzVKVPvr9ZQn0lW8oVquTKDI5A1O4a73cX/CRM=;
        b=d9ho2KSb6mx0NTFBTCLI80uScNjv5/j1W3TQApjiSSq+Zv/MYw10ThF+MrKaFr/Jgm
         WFbGab9v451UhIvCvxxVhP+JAZJi6CMwBiatWVEoR2EmP9aWuWzGDDNdAtPydXiBgwRF
         XqApMuXHfUHLHHCOuwJDswowzw2LFrgqyAdzqMXXhFnepvmUB6mO5T+UFGYq50ij8ey9
         BWNa5VkP5lADL3pn5o69e2kQOyusGzkY4Ri+DPjtIdgzdeZnAdmbicVhT98dYuM80z5s
         DA6UeFWEuwKNY3YwKwLNk112Tp3lq0GcL7y9+Se5+SnAuc9gqbvuYsK+Eo/QwB3n8KJG
         BXCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=mObKqyJ3;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WvDVTKzVKVPvr9ZQn0lW8oVquTKDI5A1O4a73cX/CRM=;
        b=GH9P+vyY7xBeANpAYnT1yTSovex+TS54DPeC6l6BEFQGG4Qcdz8u+T+UZpgdVQr5E0
         uqg/d70oTY1Cdl38C5qgVs9Fab7iWnonp1Bml0SPRb7LuDb79Yh4d7AhHB7LlObQq4vc
         wNnp1++ENyh10XfUP2wvzqpx51TzewhKCrf6rfndzrSRnuUcB2AFjaHsRGHL64gGCA2I
         wFkH+YjO8Eh58fWqIH52uwNNRO5aApcr/IV4F3zfUQM0/iX+BCbpJ7EUQb+H61Vc2yWa
         HJn80OTICT0BBJoQPuiwsi9oCliUMWr4009V5zaa+DiQB0iacSFe+2scIbP3IDdXluxT
         T0HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WvDVTKzVKVPvr9ZQn0lW8oVquTKDI5A1O4a73cX/CRM=;
        b=xqCB8y8DEtcOuhQTKZIA3HIXppDP1tGLbRgxnyKJ4DYjRHcriOQl9wTDz0XJ0vz36T
         BgYl78PJIhDONIe8xiIwGr+9/KrQgRUblKdDXQHZyXXnvv6Rz65PEv7wmZPb1FL0V1us
         m5+FR/Q0/SfmXzJLlU2iIOhVlVdH1f0NlmQrGfZfhSGnDyJlUxyMVh8i0DqU01yIeHXT
         IHTN8+JBJgaIuLyFViQp/l9uUymLdKXitwo3bHaQglhudyRXSXI9itvggRuGRH9uJ/bb
         pFspzx1FGoRedM4rOfyc1TSyDbAj8CO3Bvu/1zdowBZNesBnF3V6xjOHkSpQO2Pb908r
         JYEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpW0JkblX7kMrbNnOh9FdPru5a0WADR2DjRHC9mzbXNvbtbPaDy
	Uv6ZmwUuSrCAAb7+QxCUD3Y=
X-Google-Smtp-Source: AMrXdXsODnlRDJhg+wD2e7pKMnVqBfoBMRJdWJn6N9MdFXSdtvSZtsTH8sY/dc0MBE+JFbinWCNbyg==
X-Received: by 2002:a2e:8ec6:0:b0:28b:a983:d7ec with SMTP id e6-20020a2e8ec6000000b0028ba983d7ecmr1368636ljl.432.1674468839288;
        Mon, 23 Jan 2023 02:13:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:6804:0:b0:28b:86c7:a456 with SMTP id c4-20020a2e6804000000b0028b86c7a456ls1446873lja.11.-pod-prod-gmail;
 Mon, 23 Jan 2023 02:13:58 -0800 (PST)
X-Received: by 2002:a2e:8810:0:b0:280:64:b5fa with SMTP id x16-20020a2e8810000000b002800064b5famr5875001ljh.27.1674468838187;
        Mon, 23 Jan 2023 02:13:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674468838; cv=none;
        d=google.com; s=arc-20160816;
        b=sNRdm1+JKzI44bWuIj6l1ABLZ3we2gOmBfk3qTzOmRtX4xK9I/ORtH/b9BYgQLbw/b
         dwvvSlk67RTTUKAAJDkDPJY20CHtPpnU4cyb78ogXXd4cdMIY22491FfnFRZ3JvD2T75
         wtlVb7OlCWFNtFVWLgXj22S3yLEqGmHUJU5Z650Rc7Jk5c/5ZqGEIUHVzSiKzHiIcXS9
         vhTEfBuulJqIjYvPuoaelYloLz5KZqVoTJlZBWRXDMZUEuXMhdEVwzJIx3sccsf1wuih
         FfiE03EZ11TxlxrqMvE6sb7SdTG6r1xbmaFMtbHY2qUXy/zkpBZD0rYudqTq9hTw94tK
         si6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fzQuCSnEBk5gMM/0cxqbCinBRYL7OsazNWf1U0bm1VQ=;
        b=fdzvQu/g75kBfZT2U2pUbhEaiklC3vUJewTEnZmsoL54DBhWoprlR+CjMuB0bqtREq
         tpsT6Y6q+Mgbkbz7BjcQ8eJWQ5t+2BgS/i+003wHxwpq+Pu6ItFLg8543mZsVntAWmw2
         6twabmuu45cn2GuRnS/TAS19mBHa9uhzaOlhQ8OqkEH8Zj6GpQ/58z5dx0qIhwvJ8P1x
         3mIDo4uGATlO8AmfSw8EPIBz7RKu54L8rXkC609t+FS0IU1qFzP6rMiUtEeCO8uWBbqk
         wWxN2UlS+CdrfXEQQNi3ItHepF+E4ZGO1lgM3mTvpv2uWR5iPRwgi9NmLkCS9CChLzgu
         sw1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=mObKqyJ3;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id j23-20020a056512345700b004d5786b729esi1075772lfr.9.2023.01.23.02.13.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:13:58 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id bg13-20020a05600c3c8d00b003d9712b29d2so10213463wmb.2
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:13:58 -0800 (PST)
X-Received: by 2002:a05:600c:3d98:b0:3d6:ecc4:6279 with SMTP id bi24-20020a05600c3d9800b003d6ecc46279mr19967175wmb.27.1674468837652;
        Mon, 23 Jan 2023 02:13:57 -0800 (PST)
Received: from alex-rivos.ba.rivosinc.com (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id fc17-20020a05600c525100b003db1d9553e7sm11373283wmb.32.2023.01.23.02.13.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Jan 2023 02:13:57 -0800 (PST)
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
Cc: Alexandre Ghiti <alexghiti@alexghiti.eu.rivosinc.com>,
	Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v2 4/6] riscv: Fix EFI stub usage of KASAN instrumented strcmp function
Date: Mon, 23 Jan 2023 11:09:49 +0100
Message-Id: <20230123100951.810807-5-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230123100951.810807-1-alexghiti@rivosinc.com>
References: <20230123100951.810807-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=mObKqyJ3;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

From: Alexandre Ghiti <alexghiti@alexghiti.eu.rivosinc.com>

The EFI stub must not use any KASAN instrumented code as the kernel
proper did not initialize the thread pointer and the mapping for the
KASAN shadow region.

Avoid using the generic strcmp function, instead use the one in
drivers/firmware/efi/libstub/string.c.

Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
---
 arch/riscv/kernel/image-vars.h | 2 --
 1 file changed, 2 deletions(-)

diff --git a/arch/riscv/kernel/image-vars.h b/arch/riscv/kernel/image-vars.h
index 7e2962ef73f9..15616155008c 100644
--- a/arch/riscv/kernel/image-vars.h
+++ b/arch/riscv/kernel/image-vars.h
@@ -23,8 +23,6 @@
  * linked at. The routines below are all implemented in assembler in a
  * position independent manner
  */
-__efistub_strcmp		= strcmp;
-
 __efistub__start		= _start;
 __efistub__start_kernel		= _start_kernel;
 __efistub__end			= _end;
-- 
2.37.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230123100951.810807-5-alexghiti%40rivosinc.com.
