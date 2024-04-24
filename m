Return-Path: <kasan-dev+bncBCF5XGNWYQBRB77FUSYQMGQEGDLAPWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id F04B78B0FBD
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Apr 2024 18:27:44 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-36b3157ffb1sf594895ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Apr 2024 09:27:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713976063; cv=pass;
        d=google.com; s=arc-20160816;
        b=BhvcYFfEW6KKh6HOr0vFMiXnuWib8EvZY1sM4+TpL14QjSCZf6nf7HEmrVd24Orkvg
         g7EQNzfDZabbjEDXlLMXcfrghn4V3JnNcVSH91igBiZ46L3Yz6p2tduXo5D+OL6bVgYb
         9zSbxs7NbbxY2XXfVdB7TltFL9vYRR2PiuZODRVl3Yac2e/EVBkTSefF4OQhnZOpreAV
         oWaxEqr9eKO+Gdig2wNu4VYTPgqpMBSR0UzbrxTLJW+AatJDv7ZNfTFQe75EO1UAZx03
         Zr8k6D9VzjlAhwYQ7gJQe+EqP5HWwoJh4zivz/PKNcR83ixJ9Krp7QfP3F5biL3B6z/y
         oLtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ZiyryMhkcVmfidUJgVjZg0xFcyZ7bwH5YvN9ZCxllIQ=;
        fh=H0ZNJ0IyKHIbcbAvhdvRSWd1KwQcMZK7iOYZAX6KeMk=;
        b=TpOOZ1QExVeVNSS3afmiwZFh5qnfNlRLdOFC2fAHfeY0fI0LPonU4i8sqq/x83S9NP
         e0i6Qr2rB/YHcacp2LliQnBPKwNovGVDTgqsSgGaNQ3nlgOuYeU/wmNLOeZILOH27c81
         moLyOji0Z0ICK709SxfDF4o+i/L7BWww0H/npnN5gJhzBX9+tS21W5w4a02TP1a1QFPR
         Qqq3VHdPrOMue+0gISfFkoaeY7N5NdrVTVTvGrZCrqP8hG7od5OwOV5Li3bmT8Gkatbo
         Xb+6lLsSDI5KyI9jdXvGQmi/HtwcuZJtzEMS8c/Yem++McfPVYYv66yROttLT34uyL/j
         MpaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=l8LFMaCt;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713976063; x=1714580863; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZiyryMhkcVmfidUJgVjZg0xFcyZ7bwH5YvN9ZCxllIQ=;
        b=ach2mddccclwE1gVZWFX1PJ0x9sUEjtBPEUtut3o7PnWLygzCzNt4tkz63qUCVbOvs
         m0onJ5F7frx1WRFkiQE6/n373EF94/Xot3XvhBho0xeR3cbA4oOXzQlYplzgRQzeeqlc
         F4Vu3gL8gPPT2qPnaCCLHZzKdS9hVAUvvBWKuaABWGgOLRmVvNX1pEZYt8hiJhWT14L+
         DDZa3EYsnc+SJy7GoAw0u0BV+zK14qJ/flrLoahg/HNTDvroC0UJflObUwSOFO3haRTV
         5iAdJJtMvIgGeTlyCoNZRCWGrepWRD+WzezzydoLOMxNUQUa1/XvQ8WG2AIOCOhAaKtY
         ShfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713976063; x=1714580863;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZiyryMhkcVmfidUJgVjZg0xFcyZ7bwH5YvN9ZCxllIQ=;
        b=UpFqsoorxEkpL7TBQ4L0IIvKEMrS/8bD5bscvkHBvj6kGuYOZGjyd3f2rwYbQCGRv0
         7m6sqqTBOgS4FtfGMnH3qz2edQHrUvDpcX04kWqNssXEu34Pbpd3JT/7AygEU5ib60zE
         khDKq3Y+4pi+p/L4KcdzL1Wm+vvm46+G6esPJga54Y8jMEfOhgqiz08iX0DKE89KLMAC
         75dPjX09xPgFhp96tTO8JurhmX9wDdKORbFIbTdLPJ1hHZuVQJ7sf+vbP/wQVTh3I9W+
         0EbKgDBxQ80nS1K3AJ2Agtn9plgt7TqiN3FdDPdetpmw0u/MbDS6RcPonXqcz2Nwsvu7
         eD7w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXUEUcH3i4f3QImAhOpSJiqvYPzhorhi1x3SairY5GgiryWR1hhD+uUergMysSsIbp2qggC6QtNI4JE0jQERR+x5OgLFonYxA==
X-Gm-Message-State: AOJu0Yy7JLgM7Xw7iExDSO+x5UZQqw8AqmnumUTz2tExSlPXIGqPJ+8t
	WsFPpPL6FwbKzOCS/2IfcFlTMrtwk8QtltM7Z9zYvF5viUH79FbC
X-Google-Smtp-Source: AGHT+IEVDnO7oS9++pKDobJtrRpt4MdFSSX++87CuSJSwMl/rssOYgucixLWoRuiM978xUJo839cFg==
X-Received: by 2002:a92:c56c:0:b0:36c:c8f:893 with SMTP id b12-20020a92c56c000000b0036c0c8f0893mr3880568ilj.14.1713976063504;
        Wed, 24 Apr 2024 09:27:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1686:b0:36b:1231:be16 with SMTP id
 e9e14a558f8ab-36c29ef1d97ls327115ab.2.-pod-prod-06-us; Wed, 24 Apr 2024
 09:27:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWEuJYQKJ6RDawPQQ7SJ9FfwPjX0MCH+a89QqeD7VHWAi8+noZ81Yd/76CviIn+oTMQhIgugUWkdCGASqfYDUeYnIDQP2wtuz6B4A==
X-Received: by 2002:a05:6e02:b4e:b0:36a:fe5f:732d with SMTP id f14-20020a056e020b4e00b0036afe5f732dmr3847777ilu.12.1713976062588;
        Wed, 24 Apr 2024 09:27:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713976062; cv=none;
        d=google.com; s=arc-20160816;
        b=KYvuiKbjb58Q9TmNnFzzDUmlYojf0+tlh+B43A0gR+HJCW2ullM8aRDKuRyUPXjrY0
         EcnxL1rWwKDn2OyieyobjwqQrdpMjtkmGgU+JNlLoeq5Fs69HJgdt2zXPtDpmsfA3dLc
         Z5zyxKd+Inhqgijb0ZjtB5Z91E1w3L7k1d9rueN2NpWQBSeR88Vu0h85bq6DbgTvFW2g
         AH7DjR1dAiuQOg6wQYUWKa3oXhQYZ2KqIQlumg52kH41QyvK64C268dcfjHY+ZYpDAnp
         TwJ91oQMUyVVqWFJlTKmaMls9u6v+hAVxV/ya37Ugr3th11T4ZO6q2NrFg2Jbp/AA6YG
         lGRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=NJ24k+/qZiSqDjoeEMQOGzQq3ctUR4NA3Oy/Wx9fzCA=;
        fh=a0zGafOz9i0RfbuuhA0wtmwnc8CvHOVtI3U5/QejLTU=;
        b=TjpmSFMeqP487Z9u/q9PA8J8pgEZ14/eqRzKL3arJKAgjVpmUft/CzMnGK62hiCbbn
         OKgZ/MhKUf0dI251MIghcQUPQHgxg3JhEqBgi26a/oyX2zJzgcErCxFL2oyzgygHv5fE
         V3gMq6yBLKWHS7Bm2foMXC0hGwIxSnmyy1J2qTYuHRPSjP/Rt5i8obmX5UR2A4oz55R6
         jMKUCbrKwS9wr1+8vixcrjyoGrCNoM4HsxEgqSaLTmC0Q65wULqNVI9t+CXyWGMe+rlA
         Rw8dJouYGdAWD/SQMYoq0tHIuDcC8kGyG4BImCEhnItkl2WJxzGJw6lZMp2cknOPYIKe
         DCiw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=l8LFMaCt;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-il1-x136.google.com (mail-il1-x136.google.com. [2607:f8b0:4864:20::136])
        by gmr-mx.google.com with ESMTPS id o15-20020a056e02188f00b0036c0b300857si638327ilu.4.2024.04.24.09.27.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Apr 2024 09:27:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::136 as permitted sender) client-ip=2607:f8b0:4864:20::136;
Received: by mail-il1-x136.google.com with SMTP id e9e14a558f8ab-36b21e8c6ccso298345ab.2
        for <kasan-dev@googlegroups.com>; Wed, 24 Apr 2024 09:27:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX+znUV9bvxA5kgPI0850apK8kl+SalpG7Bk5HYP/rabfPZLumEAxVPokugTMkzX6kNiH8f/wuTcQjvORVygG1nMFbTMdgdVa1L2Q==
X-Received: by 2002:a05:6e02:1546:b0:36a:1f88:d73a with SMTP id j6-20020a056e02154600b0036a1f88d73amr3206319ilu.15.1713976062260;
        Wed, 24 Apr 2024 09:27:42 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id s195-20020a6377cc000000b005f807af5156sm8550559pgc.41.2024.04.24.09.27.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Apr 2024 09:27:41 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: "Gustavo A . R . Silva" <gustavoars@kernel.org>
Cc: Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-kernel@vger.kernel.org
Subject: [PATCH] ubsan: Remove 1-element array usage in debug reporting
Date: Wed, 24 Apr 2024 09:27:39 -0700
Message-Id: <20240424162739.work.492-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=870; i=keescook@chromium.org;
 h=from:subject:message-id; bh=GEZVzNOkB+uh4/dxLc6pmPztMxbGqhWXyqveAW752b8=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBmKTL7qVV+POqCFN5Rg5p5AzaXPsrUUStXl0AY0
 2/iCDgk8fyJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZiky+wAKCRCJcvTf3G3A
 JgZ6EAC1YjVsmehwoEeiwKbZH8CtHwwDua3KkjoeAjnsa4JmT7FMyssqFdeYvghQLki1LEFQiJL
 mh+ewYa7wqJrHiNFUNAArgaFSXfav0zG0N7Li4WkqyIMyzK3O//6ZLfupr8H+KeORJgutmWoYUX
 Sr80DS2sinwNvIceHPt4KoMM8kzjmKavQSWB8hcUXfgW1TiFqYtuZ4dWh40UZZbRZYa1KrdyLwM
 vQ6GDVlVabhwqM9Aue0rPDePcMIHe+P9ta34JQgNs7sBZIBMz6XGus87lAr3W1BFXeSEIqTYACR
 tTUE32k877NlLRBgX0sKixZgtggKOxdq5y9ZgTegc4FWD3abPH1eV0rS0G/v9D1MKoAb4gWXNxT
 k9jqLyabuU69r55bgnMDS+XIK/EoO8MBA40PznF1o255GhHJNy0G8ZI5E0mRSmOqr+T5x4oWdUR
 /ozw9paaPxEasFkFubkgOZYA8O0AcyKfRiWxwoD9iYUSSbuchLX8AflMIVIJYVZdgviE0zkXv47
 6oYNTpPFaGfes3IfGsqSSbPscFym2MSl5CAqYonhrpSfj7N3YYly2u4uIYSvsf4fnMqBk5UzZLi
 /7z1cQ1+THvaMMuEHto0W1BAKlcdZAT9SwSDKgDppVnz4Wo2ZJrRwGO5R26+6lv/F8ZHx/5jaix
 B5cxn5f5 9FQsSKQ==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=l8LFMaCt;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::136
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

The "type_name" character array was still marked as a 1-element array.
While we don't validate strings used in format arguments yet, let's fix
this before it causes trouble some future day.

Signed-off-by: Kees Cook <keescook@chromium.org>
---
Cc: Gustavo A. R. Silva <gustavoars@kernel.org>
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-hardening@vger.kernel.org
---
 lib/ubsan.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/ubsan.h b/lib/ubsan.h
index 0abbbac8700d..50ef50811b7c 100644
--- a/lib/ubsan.h
+++ b/lib/ubsan.h
@@ -43,7 +43,7 @@ enum {
 struct type_descriptor {
 	u16 type_kind;
 	u16 type_info;
-	char type_name[1];
+	char type_name[];
 };
 
 struct source_location {
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240424162739.work.492-kees%40kernel.org.
