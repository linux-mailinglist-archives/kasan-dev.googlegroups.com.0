Return-Path: <kasan-dev+bncBDXY7I6V6AMRB7WQYOPAMGQEK5EOIYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id CC05467ABB4
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 09:29:50 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id e37-20020a5d5965000000b002bfb4cab735sf493428wri.5
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 00:29:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674635390; cv=pass;
        d=google.com; s=arc-20160816;
        b=KAdlScg0FHDi9ar9N54NInr1z4JvanVJA99TNTgtHImZIdTpTN4X9ttAXz+2Xa4hfo
         zlavNB8ugg/JsuSF0oVDHtnqxK5RUEQojWROjePORVEkQ6bBuTGV1K3Gfy2zkT4dU8Xb
         Nh8TJEjhTxScfU7YqsySwogCMN+wv2aQomJ7Z5/8w9++PYJSPWUO82GIDn2sKmNVZMlJ
         HnJCT38MOKNsoKa+qgthevn9QIDeNBStkN3P9cyZFZhxjMKZCslaWrapnOY2AyYzQXnt
         6ULCdtzCA99oOogz4hiBZq4VofAHdrjVQXdOvcZXSyDxl3mGWtDUnpiQGZY+j9EERJCK
         ZX/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=B3TJ4lEeocpBa/T4dQ+z247tLgMJMlKibNZeG1DIkiQ=;
        b=f3Q3vqjgVIT6VG5Qk6XDmoIQXPmZWS5oIBUgk6amIGFz/7hGPKFMx0O8xJH8wFzgpP
         hfa13Yq0mSYSBg9UNQmEHIcoq3Hg/atKb70BXNMQWeQvb3ImFJZoyfLorZOzWYgy2xSP
         RQlxWA3+Uhs8FF2YfS1EMfgGV/LlLsFGyNlS5oGJGnd/odrMvmlDNsMryk5RZchHWN+W
         aJJEcOtkFl3k5zMHWirr6R2mr5NNzmG4+NSz7MrIHzujpZIEZnFudJiIdYvn/7l4dyZh
         ipVT0bzO0AF1BfkQncWO6WSnpG1CAZjZRmGIZoJoX5jNoZwmer1f5B+wOIHpkAOo5yTk
         2auA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=C0wvOpQb;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=B3TJ4lEeocpBa/T4dQ+z247tLgMJMlKibNZeG1DIkiQ=;
        b=qHSo1Ito9K/qZWsIxnXAPm85LDowGhUkXOfEHRyIh7LnC+0OCIfT3o+xIMPJu+p5/+
         R5stg69j5f3UiN+g/qHjIeOa2M6iI9xV7dt9enaO1SIrGdVZYym+7W+P+wAC71yIbbvK
         fkeDBq812/xEwfm+gOyHeFw3RmqpZ7G+bIZyWyKEkknjERoF2dErEifteZw6xUDXBRS6
         ADr4iQQNdMaoYno0iaU//ERaa2kSebb3X1UaiGHpip0A2XH3oCFq29bmZjsWjjqlgd9g
         WmvJiJ4GtTPNAgLlWMdBwIFFySKbvJBf8f+zg9cIKinC93cyU7lXCYd75fhYHpDRmXCv
         JcOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=B3TJ4lEeocpBa/T4dQ+z247tLgMJMlKibNZeG1DIkiQ=;
        b=wzS98rX07pB3OYfbxG2uInA8BOX45fRr7XdC98ARMFEbtUxUSO4Oju8rSYuHTZ+Sau
         spdUYLZ6Ugr/T/Vr5tDQGH/Z8bs6EYqSGyW4Rr2eGuKMnRU+PsVtCUSUiaFQtdmqI+oH
         nU5GlUqhMgaKgIb1y72yg4LKeINSMfJW1LpQ4gvs+D3TvLhesMo0oX4ytlUixTWhKOEw
         gW+LPYXHdhf4EA2rIV/BaYIn69NLhKYCyJ9RZzUx+LAhodJbfPr7P0mZ5aidbAhedC9S
         1gyg8m4xzdty2xzbUDtCBLfwH3SBZhygsDOlQiGMs1elLABHAxSml7d/aqmqF1dnFX2V
         EHDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kp3ViU5tMyUHjDk6BwX08IpXqe5ZlpdNPduulGdYxpBZ4riPjLQ
	FsCGimkuM1jBsKBO48Tpcoo=
X-Google-Smtp-Source: AMrXdXseIq1L5yU4rDBqFc2m0GsLR9/3KmlpmIHDOqvfq80gcNDZCafsJX5fBIMqigg87FtEtQzyLQ==
X-Received: by 2002:a1c:770b:0:b0:3da:f653:9e95 with SMTP id t11-20020a1c770b000000b003daf6539e95mr1757116wmi.154.1674635390401;
        Wed, 25 Jan 2023 00:29:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4ed1:b0:3d9:bb72:6814 with SMTP id
 g17-20020a05600c4ed100b003d9bb726814ls646799wmq.3.-pod-control-gmail; Wed, 25
 Jan 2023 00:29:49 -0800 (PST)
X-Received: by 2002:a05:600c:310e:b0:3db:eb0:6f6 with SMTP id g14-20020a05600c310e00b003db0eb006f6mr27468643wmo.13.1674635389392;
        Wed, 25 Jan 2023 00:29:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674635389; cv=none;
        d=google.com; s=arc-20160816;
        b=x6eMNxxvB/uga7ZIe/8sAiHYqj+hqcKBG32TUjZsOanx2kGBZEp4CmtvXC2Ok/PF+F
         BP8wXkquNQoCyAYL/NKngnnuJx0QDFfKE2Zl3T54MCvv7ZSH1Zbpa5/cu1pDPkqxuiJr
         MZBxEIiZeyy4ad/k/RU/8zB5PM6DzPO0HC0tuR8scY4SsL+1MuAHIU3ondaSAPH4sPOI
         WW+szcKi+bEmcKVROKpqeaGiOAqUKb09fMZiOfQcnIBH1whBvfz9nMAoIGPvqlprEehV
         5RAevSDV2bgp/WU7y4mdAK44elK6VNIb9u2w1t75WkvTqlIJwE3RGDF2dnNEsmE/L+CY
         idFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=871OGCI0aHwZZE6OKggKudWipUlPKXToB5Kn7OlT7Ew=;
        b=NFYlcBerCc9MbkEpLpU22Gg5qYh3hPGBPqPHyhQUtholHxZD8bWJl05YoBGVDdeyCc
         OOFuMGK2/2sDT6rZNisoVCh14/sjCX1/9/XPJT0ylVgdK2ovd25fJTNhbBhsr0rYrJmY
         Zj8l/UcGq5braRRoovtiKmrrizBPZ5ch8DPNfykZMUWHP2PLqTUox8vTdMID30HPqBkA
         KLuXvmSrwlAw41BRrXTizTCY6QXhA7HDCKUvkS2TXanS4jXBfnPQvpRVabkIB8qDscrg
         VJLPCVrL6TUvCfxR9JyH0dOjMhuRhIrJ77nffrlgkAOu5V7XDz2HD6BQa6J7zNpOJW9Z
         nP0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=C0wvOpQb;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id o41-20020a05600c512900b003d9dfe01039si268605wms.4.2023.01.25.00.29.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 00:29:49 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id f19-20020a1c6a13000000b003db0ef4dedcso676018wmc.4
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 00:29:49 -0800 (PST)
X-Received: by 2002:a05:600c:3b9b:b0:3d2:392e:905f with SMTP id n27-20020a05600c3b9b00b003d2392e905fmr30562318wms.24.1674635389029;
        Wed, 25 Jan 2023 00:29:49 -0800 (PST)
Received: from alex-rivos.home (lfbn-lyo-1-450-160.w2-7.abo.wanadoo.fr. [2.7.42.160])
        by smtp.gmail.com with ESMTPSA id d24-20020a05600c4c1800b003db0cab0844sm1070737wmp.40.2023.01.25.00.29.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jan 2023 00:29:48 -0800 (PST)
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
	Conor Dooley <conor@kernel.org>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: [PATCH v3 6/6] riscv: Unconditionnally select KASAN_VMALLOC if KASAN
Date: Wed, 25 Jan 2023 09:23:33 +0100
Message-Id: <20230125082333.1577572-7-alexghiti@rivosinc.com>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20230125082333.1577572-1-alexghiti@rivosinc.com>
References: <20230125082333.1577572-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=C0wvOpQb;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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
index e2b656043abf..0f226d3261ca 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -117,6 +117,7 @@ config RISCV
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230125082333.1577572-7-alexghiti%40rivosinc.com.
