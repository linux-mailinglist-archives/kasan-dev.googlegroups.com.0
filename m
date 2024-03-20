Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIXQ5KXQMGQEPELPEII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E4D9880F7B
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 11:19:16 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-6e729f8e8c1sf2542196b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 03:19:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710929954; cv=pass;
        d=google.com; s=arc-20160816;
        b=b5LMX1vn6pl95y7GubpC9dxd1t9zjcnufxEU7EYuhtV8KFQ6gQ5ME888C7cSns+gfZ
         OocaEkGVUwNn8DpG/6hPyakmkdGYH5c5/2cAPv4XIpGzRBGIIbSpEw7+SEhQVbKwJSG0
         OHGv/QcxJRcNMphRjEIBMH+VxFexLCkk4jTbHj9/h1wn0+wxJWYG3QyGO2I52cfV+nmo
         rUen9fmHyrEEv2ZPlzynSDqz2GsglhIqnvcLQiTue/BfmxyVIDMtau2RwuEqWlb3sigi
         5RpLADYS4wmMVciIvIHwnSPCuJLJzpU2Ou7pGVlYnb7g0EVdo9zns3r9DnPGrTTn2hID
         cmnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=tJigTA+Mgii2rNva+b4xnMnb6otsh/AyRHiTSC3h+rE=;
        fh=5+F1uvaLGUbGsPVjpATI1QWvmpEOZ4kNp7aqsKL+WHM=;
        b=o2kfF2nHWxFXvK4zFOGw/T+PjLcndp6PMEy2tjH/IJ/hKavZPTkduY4TdAXEm0P0bh
         ssz+IgSMQV57zY6G3mt/mma8zO9/U1MU8T7piaWHvpOMLLx/vAVoDFt414F6nqIU/pj+
         yU+kiIBu5VPsTEElGocuEG0Lz6996fjC5w+4H5L2PQjt5h5sjQ2gTxFaG/3BJTZSdtkd
         aP4N2w6RMzWd/yJcQDJ42yU0+toztnMvNiZH2mCnNMEWgecGgX7JQPCDbxF49K+3Efwr
         /jSjDZw+h5oqqnnvFec8XJynPCTKxSLZMSe8kehSn8d+Jjdr9f0G//ZIoPjgpv9nYHUp
         lQaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="mz7/2Izf";
       spf=pass (google.com: domain of 3ilj6zqykcbexczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3ILj6ZQYKCbEXcZUViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710929954; x=1711534754; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tJigTA+Mgii2rNva+b4xnMnb6otsh/AyRHiTSC3h+rE=;
        b=HyjhSUMnvahfGQdCVM2IGjRYshsvdYnJaaECbfIS24NorB8AsHNDIZh8LIuhtRoZ1n
         CFTtIomJSQfs2cQtAYJ1+JtQiBgvCdaXML7QFhA0mw+pTK/TgsMVSNMyVsq9tBe8QAhl
         2wPuo0gPezlPOQ8X/c/kzXPhPQDKNFb6TQQTf3ffoPkwjA18SQ7cp1KcUozCoSAMNTer
         SJW/5ASRIwywyCYQHuF9gqteouz3uxapN5YxRSTfdvY1ln0INlZ3RDayZpZ6bOtLn8S8
         SqCFJU4dmtJmoIWlZ/SNS332nnhA4olso5GUgSyVlYtIFBzFFY6K18nPFfaft5ygBpTC
         QpGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710929954; x=1711534754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tJigTA+Mgii2rNva+b4xnMnb6otsh/AyRHiTSC3h+rE=;
        b=NLPEtFR1XQHDSPS9w8MeMguHmsCrrUbJ9YjNxPZjsH4H2WQPM24h2dGAaM//4ZCWoX
         ZRTr9cJy6Tdo1tN6NuLHqL4ExsLZebpkLKU90GY3S1Lqm+mLPtIvcONMfB8ylhcIQR1a
         NnPkAO4xTIQIN5tksguqCPQeT4FNaT5MlY3anzujSV0pPU6GLJnHHUQ5GE6l/0bgMesB
         1FPaKcoOIER+ZdiKLylzfMbH/zLdkiw8ZJcewEJO21H+Cxj82qScJ04fLTxdzLmAPXlF
         e29ygeBxaTSS4ozD4u6GRlxkipPtDQBLYZG/kAUjPm0j4RWLlg3MxAc4okFZwKzKQCzo
         O/1w==
X-Forwarded-Encrypted: i=2; AJvYcCW7/oTjeUGZKQ6KL0qlE3kNGGN7HxDoQEIrCK2ezgjOXxSVB1c6uvR1X6BHVubBHl2yMNkW0W4xF3tJHPeDK8AFfZIiO1CKKQ==
X-Gm-Message-State: AOJu0YyRusImGGOIteC42IU/MZVUFYXvJd6Jk2+xtTIgs6oajxl283Rc
	MvTriBelN4+o9Qdg0d+JxLIw0eJXP7S5y9k0qqIfNA2iAn0xwwqC
X-Google-Smtp-Source: AGHT+IHIR2Bu0ere9GEHNSRG35fyMYpvKpXd6xi7mRdoHcGrWB9IU42m9dwa6y1a4zAl9UYFw/UR3g==
X-Received: by 2002:a05:6a00:2d04:b0:6e7:386d:ac95 with SMTP id fa4-20020a056a002d0400b006e7386dac95mr6189151pfb.1.1710929954295;
        Wed, 20 Mar 2024 03:19:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:9a4:b0:6e7:7e1e:d78a with SMTP id
 u36-20020a056a0009a400b006e77e1ed78als652763pfg.0.-pod-prod-09-us; Wed, 20
 Mar 2024 03:19:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV10rLSVDrjrTdEhFE0z04RgVz2Zj1d0QfetjaRb2dCkvtq/qbTXshTwH+gONhiK3tygsOVqParzNjVaFOke1CwHARjET4ZOuLe3Q==
X-Received: by 2002:a05:6a00:1950:b0:6e7:2093:32fc with SMTP id s16-20020a056a00195000b006e7209332fcmr5871093pfk.6.1710929953129;
        Wed, 20 Mar 2024 03:19:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710929953; cv=none;
        d=google.com; s=arc-20160816;
        b=fi5logvcsZ9xaXGbLv2fujPZ2De48NQ0LARNcMwIEC9KZ6Rs9TrYLmuJPQM0ZuUBSK
         2PMEot018QNK9kPRG/jiOAPHR3ZDrn6xJGQ5fsyogu9Ljcxme9pFkaWQU6aOVcp9c6IN
         PWlDAwAsc/bqh2+2mm4XWB9v1PShpW/ih8OOgBGxHO4veIsYHl0XDKj+5BJOBzBE2iAL
         xOdiqJozMINTZMvpz0UY9t9aNALzlSX3TwKHm4jv9otzQUW9Tob3NvQrvDAeseHGUp/s
         sUFTpukogISopm4NiUQqQ3phnwIR5LkOb2ZFS2kgyaz5iIXpz3XfjcDrzEXbsb/0BRDI
         gqIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=m0vBJz04bRZVs+p5tf5O60PjHz2OHj3PY0354SOIqxk=;
        fh=D6idi1CgRoZsCaX6ekl7Ovxv50aOp7Z1jx4LoEkrupk=;
        b=E5DEo/fW2rhhh4X+QRrIxR2PXD3exW6FPV0RhggKAt4DjAX5BApPUuZCX3wmLzkF7c
         LJpk6O7GKx5nVpsw+MSYeW5nEhYzcFB2jozkbpe4XdEVt+cld5pD1xH7JH0NltzbIiCy
         wp44KOFtDZGBmh436I57JWfIKs6KOoKSOds573YwcnQiThBUNuC8Z7GxZg1AAHcrL4SM
         hy3VF7hjDwSNeUwAC9O7yVXIm8+Wb82V32j2qzgeNu97ijHtjPY3NQmSFLMeJePKKzJp
         q+fJazvSrjCV0Wb57TVK6OxFPVGuyXtUq7z1PXmTRubUH1teje/EakchpcggsnMMZw7C
         GaeA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="mz7/2Izf";
       spf=pass (google.com: domain of 3ilj6zqykcbexczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3ILj6ZQYKCbEXcZUViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id q13-20020a63e20d000000b005e5038c57c3si1591949pgh.4.2024.03.20.03.19.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Mar 2024 03:19:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ilj6zqykcbexczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dbf618042daso9967140276.0
        for <kasan-dev@googlegroups.com>; Wed, 20 Mar 2024 03:19:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVVQqvav3NAShgW87Z7OGdHsxVo01rWnu8ojcVfTi7P6g0wS/XntKwDQH/jqnC3YkYCiGXUetP8zp/QatZeJDnpRMO98aGrZnN8jg==
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:2234:4e4b:bcf0:406e])
 (user=glider job=sendgmr) by 2002:a05:6902:2484:b0:dd9:1b94:edb5 with SMTP id
 ds4-20020a056902248400b00dd91b94edb5mr625397ybb.10.1710929952333; Wed, 20 Mar
 2024 03:19:12 -0700 (PDT)
Date: Wed, 20 Mar 2024 11:18:50 +0100
In-Reply-To: <20240320101851.2589698-1-glider@google.com>
Mime-Version: 1.0
References: <20240320101851.2589698-1-glider@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240320101851.2589698-2-glider@google.com>
Subject: [PATCH v2 2/3] instrumented.h: add instrument_memcpy_before, instrument_memcpy_after
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, tglx@linutronix.de, x86@kernel.org, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="mz7/2Izf";       spf=pass
 (google.com: domain of 3ilj6zqykcbexczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3ILj6ZQYKCbEXcZUViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Bug detection tools based on compiler instrumentation may miss memory
accesses in custom memcpy implementations (such as copy_mc_to_kernel).
Provide instrumentation hooks that tell KASAN, KCSAN, and KMSAN about
such accesses.

Link: https://lore.kernel.org/all/3b7dbd88-0861-4638-b2d2-911c97a4cadf@I-love.SAKURA.ne.jp/
Signed-off-by: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
Cc: Linus Torvalds <torvalds@linux-foundation.org>

---
 v2: fix a copypasto in a comment spotted by Linus
---
 include/linux/instrumented.h | 35 +++++++++++++++++++++++++++++++++++
 1 file changed, 35 insertions(+)

diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
index 1b608e00290aa..711a1f0d1a735 100644
--- a/include/linux/instrumented.h
+++ b/include/linux/instrumented.h
@@ -147,6 +147,41 @@ instrument_copy_from_user_after(const void *to, const void __user *from,
 	kmsan_unpoison_memory(to, n - left);
 }
 
+/**
+ * instrument_memcpy_before - add instrumentation before non-instrumented memcpy
+ * @to: destination address
+ * @from: source address
+ * @n: number of bytes to copy
+ *
+ * Instrument memory accesses that happen in custom memcpy implementations. The
+ * instrumentation should be inserted before the memcpy call.
+ */
+static __always_inline void instrument_memcpy_before(void *to, const void *from,
+						     unsigned long n)
+{
+	kasan_check_write(to, n);
+	kasan_check_read(from, n);
+	kcsan_check_write(to, n);
+	kcsan_check_read(from, n);
+}
+
+/**
+ * instrument_memcpy_after - add instrumentation after non-instrumented memcpy
+ * @to: destination address
+ * @from: source address
+ * @n: number of bytes to copy
+ * @left: number of bytes not copied (if known)
+ *
+ * Instrument memory accesses that happen in custom memcpy implementations. The
+ * instrumentation should be inserted after the memcpy call.
+ */
+static __always_inline void instrument_memcpy_after(void *to, const void *from,
+						    unsigned long n,
+						    unsigned long left)
+{
+	kmsan_memmove(to, from, n - left);
+}
+
 /**
  * instrument_get_user() - add instrumentation to get_user()-like macros
  * @to: destination variable, may not be address-taken
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240320101851.2589698-2-glider%40google.com.
