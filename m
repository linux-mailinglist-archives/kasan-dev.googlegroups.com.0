Return-Path: <kasan-dev+bncBDBL5ZE5QANRBC6B5XAAMGQE5ESYQKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id D565FAAE0C4
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 15:30:52 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3da717e86b1sf17487505ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 06:30:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746624651; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y02tUvNLUsNiZk7h9TyjfUSCArurBbVj6hJvSYxGBa7B+ZuvqM1+I2ad1mzR7ttp07
         rh3A1c5vA5q38XLrZBbr+RoRCkytqBhYwNjlR882vlHYwGrp37HIhTn1r/CyVnsFHQ/2
         WLTG1A/yzvcpdfcujLo0nDk1XVRiallNP+/rk4hpLZ5Ws2mUvNpPyJCdXYn1tiSIg3Ez
         BvGP1uWNRgtjLmJLH3qaXPnEIoXUg78YMHrrEldULtQ0YrCz9liONJ5Y1YrglHJ7eUOA
         rWi8nzUVOESuwf8UujOxC/NMcNtYH01le5L/mlMWeqCeOwpb8MiLGFd+VRmVrMvVXQb8
         gF/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=vLdTJD4lAlRcNOKylv5Qjeb+00aDd8nO3Hcx50ynrk8=;
        fh=OawTm3v8W00OHoIN1dmNFYxAmBloMaYHHyJzjaNCNXs=;
        b=QOnzCvh9KDRDTQNnvLqFRQ+m67V7Pn4WMbTHSzsTUWC3WeRSPTDgMYlaI4YXgzzxPZ
         DQsx48ZcsPo+hhjWb4UTgwM3EnoQIwdBzUQ5qIAGCP8igrcdZj6RWddIThF30Sx5npMN
         enIInOZGN/WemWxjPMMqq3fUM8ee244gz9J7knL+oWtHppWoqDKfonjCQrr2Y4NHRwBO
         lC+AdxM98ASJb1dJVLcl699Em25NtD27LIt3P+PG6DRTcbQDg9ddRbTd27nyGFkklqyD
         dWXWeCMb5yHby3KyD/d9a6t36EwuWllt/fpGFR7ys0pbNqLNYa3uwIkZl2x01M1Dzvvp
         fRDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MSd+NFHV;
       spf=pass (google.com: domain of lbulwahn@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=lbulwahn@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746624651; x=1747229451; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vLdTJD4lAlRcNOKylv5Qjeb+00aDd8nO3Hcx50ynrk8=;
        b=PGz5JJA1HdxSLhFvOmLazlQ6rnnmCN5EmAUhLP9Gb7hf49OGx/7R76JmPIpKurO7tt
         7nmmhmonA+hKL60u6J1rFY4+oSdk0F3wxqe0X1tKpiZG+HqO3/DftLDbyPxwjBvcxx5x
         mBpIN2LYpNg8cMzZZZ0yf5DcthARNoZYysxFR3djsQpmAmABOkQbp8bOzCTH2SwTtAMP
         MAjgIxMdUP7c9YvUjTdR61At0ftEQPhFtIBuV+A6DkQa9oLfxJM4KP4lc6YVPDxZEkqC
         ePomS4PUfLVUu+YIjqWJgzzCV7iEvRtax1CRqIvY5b7dR3t+Lh87fxIdK0PXyuXP9sSi
         XygA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746624651; x=1747229451;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vLdTJD4lAlRcNOKylv5Qjeb+00aDd8nO3Hcx50ynrk8=;
        b=KTadQ0opvIvKYq8qDfdwBtJLGChSPobDyZOxiEYRYnpbfL8p41Y1gFsl3ZEEPRnNES
         GW4lRFv5V1liBphexGyCCpIOpZZXxOEtYp6cFN/81D9ekXwHcBhZ3dBThofCq0NGV2w7
         mYg8nFp2XNdOZqr1z2c9ur6hE3ImGqQAlnIINZSBuGQQ+y5Rmvc6HaONxHYMGJBDt0Zk
         PptzUvGB5c/0+rqkkOCahEkxQ3f0EO2qM6U7uXMTI9Zc3wq7Sguze9Z6nWlJd/6ebewq
         I0PmtGHxtYh8lcjCFfwukMdcGLnaI4bo/TPlv7bXElhBhvb14RLC+ealFmtjb5o+d1Tl
         i+uA==
X-Forwarded-Encrypted: i=2; AJvYcCW/crjP5aNzBIuBBcDmqe3tVissYtKJ8M0JIN4O7oqal7TpUHx3LssoyIw40V9lYWP8qApCnA==@lfdr.de
X-Gm-Message-State: AOJu0YzApqQ1WS+udsxKWNjyPGh8D76HFXGw88Ehew+kqkCtWbhE718f
	+/8TcyEQl+M+O58Vkh/vWc2SgcW0Tm+b7XPGcSldjzuaiFDP9iOI
X-Google-Smtp-Source: AGHT+IFSo/eBFdTIAiAAdGNy8ifC5WwaLXvNabbiqDLc0qgv0xSzxwpVSw5pxVBRtb8/Ls989p0jzg==
X-Received: by 2002:a05:6e02:12cc:b0:3d4:36da:19a9 with SMTP id e9e14a558f8ab-3da73923209mr32464475ab.15.1746624651315;
        Wed, 07 May 2025 06:30:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBH164covPKqST3nDE4JdTCq2h20kR35GOB3wyNqgz1zuw==
Received: by 2002:a92:db49:0:b0:3da:73a4:e1ed with SMTP id e9e14a558f8ab-3da73a4f4a9ls4454605ab.0.-pod-prod-03-us;
 Wed, 07 May 2025 06:30:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUa69+LQbJ+lhLwuUMxxr5j920Xmmo4mVAg4hquP5Wq5DvmG8I+9cbl9afCQN3Yvsy5Xi7p35wtdsA=@googlegroups.com
X-Received: by 2002:a05:6e02:3485:b0:3d9:6cb6:fa52 with SMTP id e9e14a558f8ab-3da738f0dafmr36462995ab.12.1746624650440;
        Wed, 07 May 2025 06:30:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746624650; cv=none;
        d=google.com; s=arc-20240605;
        b=XaL338GJKLx/kpOSj9OcgQ55hPe7N/PosGzO65Uv0UK2WO8z3cUJ20reJhh/LpjpOj
         OgYPA9lov7t2WNWdm0DdwlO4IrlBSQU/2ldbwZ4qHHMHNIWkFRENPmI1jZpF8vE8O4Nn
         yfZ+o96+4MPJeM/TsgP/ZmFn8M1kP0xPBSiml92tJxSfLX9iqqQCYQHuKcNeH4FKhlrO
         3x1wSbyrvDe05JLV6LlHxRXrTBn/H5oI1LABjq8cW4vAtsYRnypOzXqIa2iObcF4hvin
         s4vTy+gj31hR62JRJXfaVLlsNaTQSJOZF9mTkph85b7Nb0JoexAawMMldWgr92eNdfVu
         aVIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=EAnx4zdLWH9vKEKvll8glYQPHtlqprMuZdEbIAz4Nx8=;
        fh=4qH+5g86PsvbWC9FXn8AJ2lFT2gvxllWXNlnsDH0coo=;
        b=KP///5MKzNtEh8VPbVOxozoTvq/uYCjNlAJOr6S+7mrhVypDoK27E0GWKx5YeU3ggA
         eA0RjpR+LIQ1qpKTQS2uPxQX3NyIoiA60wXCuN4E9C0HwMQcbYQktHnuBZuvNEot1pNs
         CLXNthtfUPdiUi/YeJVhv5ggFwoH0GY6b+TFCCmJo2gmGQb4fPe8OU3MMCxigkvM5UXx
         /S64VLUeRuGv3SNRLFgzf89QxsOmbj13oHWuyB/tBUwzXtGEd2YVtRgwhdvRedyCFQyk
         I+mVNlXiXm5rGCSxfWxuMETSq4q+JmcjQhkrR3A9y+hO7bbQAZ96Ue8NoD5qUuD7O9lh
         1CZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MSd+NFHV;
       spf=pass (google.com: domain of lbulwahn@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=lbulwahn@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d975e6eefcsi157535ab.2.2025.05.07.06.30.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 06:30:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of lbulwahn@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com
 [209.85.221.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-371-NJCprdf1OXi6PdJJqvgUsA-1; Wed, 07 May 2025 09:30:48 -0400
X-MC-Unique: NJCprdf1OXi6PdJJqvgUsA-1
X-Mimecast-MFC-AGG-ID: NJCprdf1OXi6PdJJqvgUsA_1746624647
Received: by mail-wr1-f71.google.com with SMTP id ffacd0b85a97d-39c184b20a2so2289364f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 07 May 2025 06:30:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVs3oFObJpHASdIHTZtWzYhw82JjteQ1kFlV4e3+C9kEYP9zj4WEJm9r/QkU6zaG5QkdcRqzp0BgxQ=@googlegroups.com
X-Gm-Gg: ASbGncs9V/AyeDEv2Zix20Yt8CHmBeLzu6+JMfJlRhIOKw2Fo8ynmQx4AGp5/E9Zb2N
	nUSGhbN5I5Tpn3l1JqZUWXOu+Xmby9KFzwpl3uQkZ339opKRKdmRo5fD+8wzjIuJt8DWtS/4EX2
	uI2N7z7c8vy2REfg6sM9zcJee/Hn+orrK6RY18pXyoYWBvRifQGLyCd4l4kmGd5WkuBtI9oauJd
	LjHlR7g8wWNOdXv4Gh5khaY+3UOwkBTxlnEXr/3qcdy61/vLnUQm+uZ1xJStfZWl2iwBoQBwiA/
	/eXqHKfEQF4OuxOpJvTlj6Shx+PLzYXrfoSBD/MLqSjzw9Wf1DoMjkULHg==
X-Received: by 2002:a5d:64c4:0:b0:3a0:b3f1:6edf with SMTP id ffacd0b85a97d-3a0b4a05cadmr2433707f8f.21.1746624647384;
        Wed, 07 May 2025 06:30:47 -0700 (PDT)
X-Received: by 2002:a5d:64c4:0:b0:3a0:b3f1:6edf with SMTP id ffacd0b85a97d-3a0b4a05cadmr2433678f8f.21.1746624647048;
        Wed, 07 May 2025 06:30:47 -0700 (PDT)
Received: from lbulwahn-thinkpadx1carbongen9.rmtde.csb ([2a02:810d:7e01:ef00:b52:2ad9:f357:f709])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3a099ae3ccdsm17111024f8f.38.2025.05.07.06.30.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 06:30:46 -0700 (PDT)
From: "'Lukas Bulwahn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Arnd Bergmann <arnd@arndb.de>,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: kernel-janitors@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Lukas Bulwahn <lukas.bulwahn@redhat.com>
Subject: [PATCH] Makefile.kcov: apply needed compiler option unconditionally in CFLAGS_KCOV
Date: Wed,  7 May 2025 15:30:43 +0200
Message-ID: <20250507133043.61905-1-lukas.bulwahn@redhat.com>
X-Mailer: git-send-email 2.49.0
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: 7y5z0lNVwk51n-R43eANp3OCd630vqffpvMKlQeQAFA_1746624647
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: lbulwahn@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=MSd+NFHV;
       spf=pass (google.com: domain of lbulwahn@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=lbulwahn@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Lukas Bulwahn <lbulwahn@redhat.com>
Reply-To: Lukas Bulwahn <lbulwahn@redhat.com>
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

From: Lukas Bulwahn <lukas.bulwahn@redhat.com>

Commit 852faf805539 ("gcc-plugins: remove SANCOV gcc plugin") removes the
config CC_HAS_SANCOV_TRACE_PC, as all supported compilers include the
compiler option '-fsanitize-coverage=trace-pc' by now.

The commit however misses the important use of this config option in
Makefile.kcov to add '-fsanitize-coverage=trace-pc' to CFLAGS_KCOV.
Include the compiler option '-fsanitize-coverage=trace-pc' unconditionally
to CFLAGS_KCOV, as all compilers provide that option now.

Fixes: 852faf805539 ("gcc-plugins: remove SANCOV gcc plugin")
Signed-off-by: Lukas Bulwahn <lukas.bulwahn@redhat.com>
---
 scripts/Makefile.kcov | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
index 67de7942b3e7..01616472f43e 100644
--- a/scripts/Makefile.kcov
+++ b/scripts/Makefile.kcov
@@ -1,5 +1,5 @@
 # SPDX-License-Identifier: GPL-2.0-only
-kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)	+= -fsanitize-coverage=trace-pc
+kcov-flags-y					+= -fsanitize-coverage=trace-pc
 kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)	+= -fsanitize-coverage=trace-cmp
 
 export CFLAGS_KCOV := $(kcov-flags-y)
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507133043.61905-1-lukas.bulwahn%40redhat.com.
