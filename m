Return-Path: <kasan-dev+bncBAABBMX35SIQMGQE44F4F5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id EDBF84E554D
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 16:33:06 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id h14-20020a056512220e00b0044a1337e409sf725572lfu.12
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 08:33:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648049586; cv=pass;
        d=google.com; s=arc-20160816;
        b=F1k5esaQLJCtgZHG7dpQNnph2WWalXv5jyURShzrrUbQdUm79lO1CVTKN0VvTMAZI2
         YtjH5q0SY3ldzPFXWyUyE0LBvGCK+9F83gsDG8eeipZvKvsY2TEGJn3sxmszIqMntf4Q
         daMGjDKfYDoh8FQMcnUc2nMyqesAqNsisuEREVjyCMoi/SbXhvnsMSo9y4m7deHzuBa3
         UCpvYAVTZmQuN2Vliw+vstmYUrP2CgqGJBCr5yzy3fDczCHMz86DRZyx1jHY7kganUj3
         o1qtwQB5Ktb17knpH0bG0oDOpIkK8PE0ghXaVyM+XjegIA0dX28V15SXvoWQA4//CtYa
         cOuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Q+YCBfWS2Aj0q5WSHkCIVDmIZtmgfXscyhVRk8wbYlw=;
        b=YZPbK8+E7J3KK0VYY2FdFaFqkF2+Cl8jy5qy992uTvSJhvS64DL7/HSglnM7qoeQm+
         n1wL5mqv3Z2jnVbain8A4vOFe1iYfLuekJWV+M1ZLQW0mjcZFa5KjncEgrFxpJFKBrdI
         DNRt13SlT3ezXyfKCWZ3JEGHxNPawRyGG6NDl9G3vooSL0rruUdslNTGCtfLWwqvzqjC
         UQXjJz6quskDvuSO9hsheYUQ5xuwG1kHDn42aKLPHlfIAFO3ScvsLMZzkJToMI2auv5e
         2JtHCfViewAmItjFXV7LKZ7bymo/u/w+mpEoNNF/cZlntT00MetWJAmgheVe1xQqCIlp
         ygXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=BHH7IXDo;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q+YCBfWS2Aj0q5WSHkCIVDmIZtmgfXscyhVRk8wbYlw=;
        b=VOTCUX/tTD0jyjVQUkITrhK4l4aTKQpWbq5z/wZiXpU2pD1TwwaFTdTsGCUIkQYlfX
         ezw/b3TcNP0Q/6W3IUINnowFU7zmTZR9GDE2+F3lf4JpUy2WMY2X9GNfhZbHpabnJvtz
         DA1ah2U5rw67WfZzgrwADbwQrOKDwTiCExLYYDV8AXaILQWR6wztfjbd1vwowBqCQjXu
         HrBiJUs5ONILjzsD/4ZDXSa0zpHZopfZU6REJLaMcDiimZ5IjmU7LCYTLG9TwvLZ+hJN
         FXJARGbpwGJpG6yEQxwEkTCTzPys7o/MN7HzScFhejL2/iYN4RdlrTeXJ2Z59PLq2Oo5
         LPgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q+YCBfWS2Aj0q5WSHkCIVDmIZtmgfXscyhVRk8wbYlw=;
        b=qBG2JrN+KvpozQCEuI/DSmJTAicgdKqLM+lgbDFcbKgpBKDdF3UzsiOjJrIzU0cIci
         zgyN7zVfRudZ7a6RL2MPBTBLu3V9OTsWz8wzeSikfavnHSybxIq1O0+o9ZeDjxx91BNu
         OYwdeEK9dHX9xTTzz0QSRNEnqICsTFO3JT9juv1503Ct1lWT6CFLela7M86VIS9GHR4s
         IT6KKkfslElhIs41fN+166vv6fiqTJi4gCNln+PAbgJhwH1q489uhKmiyE18Xb80Tmme
         kUGrx6UqE5nqdn4woilG5urcBL3+WsHsXsxEdnMWex98BhTOxc5vBYokIgomnX2zbkux
         gRiw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530a2uIKSC8r9YdoBP5IY0ZD4hRWtLiJ1dC+gQN0YPgzFnBLAzWY
	NvMCdFObh5C3GXV5U6p3JVw=
X-Google-Smtp-Source: ABdhPJzVAhwFVPFiVJMpZQs2g8ly6QaDDdl+zn9hSAeZkEDd6jNbEx7FhEhC4wQ2xBUTejSxnoXSYw==
X-Received: by 2002:a2e:2a44:0:b0:243:6b73:1c0 with SMTP id q65-20020a2e2a44000000b002436b7301c0mr432102ljq.376.1648049586522;
        Wed, 23 Mar 2022 08:33:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b951:0:b0:249:181d:ceeb with SMTP id 17-20020a2eb951000000b00249181dceebls4093291ljs.2.gmail;
 Wed, 23 Mar 2022 08:33:05 -0700 (PDT)
X-Received: by 2002:a2e:9b96:0:b0:249:8705:8f50 with SMTP id z22-20020a2e9b96000000b0024987058f50mr452846lji.73.1648049585704;
        Wed, 23 Mar 2022 08:33:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648049585; cv=none;
        d=google.com; s=arc-20160816;
        b=fwaZIC2qCYjVtiPWoOttKthKjk9B9uv2tnubG+ZgWu31hUDQmsNacTB1fiorTsS+FT
         eL3AOHou8HDND/6tD0cLvQZ21kaSuLw375MOEgi2tFp0xp7Cm5kEcpOSEEOpOPMqYovN
         M8dExgp7OoB/G7eiZzTW4L2A10C1xS5XkI7idtjxDwPwBjP4IgAs4E1inmJktn+THgzZ
         2+vBtSAsTvQYHZeX2u/67sRbXy/FlQS6A2r5/cqN1syP64ABU+fgBb/cNhwCUQIo79Zx
         GgxKG7BHVhnLyawegk7zFXVUDya2ZVJx6sRGOkE2bpRuYE6qYP5MIq8XFP9FMpfAwYr3
         tqwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BKf6jB0gbxzfxKMTwtGAqqdjGZr2rSaHYmUmfoDqc2M=;
        b=fiA5S4B2Erraw53BvcBbQxItBMnJ8zls69Rhz7cUON0f6kvaORCzg3Lh3K50QgkFqG
         SfT9L8myZphJVtm4zHms6vxxNNan5+WXrLqJFz4VCTT3Tz3iFTCOOzmtCvCphooOnIHT
         iwzwBInKqpUs0QrwnweSWC0UX1qI43c9IhjWFwQ19ZOLlwT6z+5rtR+UiUwJlbm3tmdG
         8CWq3jTOXdhMcOEKjMMF1FZE/3WSRkvGLlnmQR6m3nbsLsnBjuksi731tr16GdsJ07NV
         hpEf1do4rYSRjdGd4KD8L1QTQtnGcOBlaD+j5dSC/ytg5m4p+YDUe9eutOtszKxB94hH
         v8mQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=BHH7IXDo;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id h20-20020a0565123c9400b0044a24244804si17417lfv.12.2022.03.23.08.33.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 23 Mar 2022 08:33:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Mark Rutland <mark.rutland@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 4/4] kasan: use stack_trace_save_shadow
Date: Wed, 23 Mar 2022 16:32:55 +0100
Message-Id: <7027b9b6b0cae2921ff65739582ae499bf61470c.1648049113.git.andreyknvl@google.com>
In-Reply-To: <cover.1648049113.git.andreyknvl@google.com>
References: <cover.1648049113.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=BHH7IXDo;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Now that stack_trace_save_shadow() is implemented by arm64, use it
whenever CONFIG_HAVE_SHADOW_STACKTRACE is enabled. This improves the
boot time of a defconfig build by ~30% for all KASAN modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 9 ++++++---
 1 file changed, 6 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index d9079ec11f31..8d9d35c6562b 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -33,10 +33,13 @@
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
 {
 	unsigned long entries[KASAN_STACK_DEPTH];
-	unsigned int nr_entries;
+	unsigned int size;
 
-	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
-	return __stack_depot_save(entries, nr_entries, flags, can_alloc);
+	if (IS_ENABLED(CONFIG_HAVE_SHADOW_STACKTRACE))
+		size = stack_trace_save_shadow(entries, ARRAY_SIZE(entries), 0);
+	else
+		size = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
+	return __stack_depot_save(entries, size, flags, can_alloc);
 }
 
 void kasan_set_track(struct kasan_track *track, gfp_t flags)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7027b9b6b0cae2921ff65739582ae499bf61470c.1648049113.git.andreyknvl%40google.com.
