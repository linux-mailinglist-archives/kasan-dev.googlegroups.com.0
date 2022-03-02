Return-Path: <kasan-dev+bncBAABBYF272IAMGQESCVTQLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 42D3C4CAA79
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Mar 2022 17:37:53 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id j10-20020a05640211ca00b004090fd8a936sf1286068edw.23
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Mar 2022 08:37:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646239073; cv=pass;
        d=google.com; s=arc-20160816;
        b=pZx7/Jjg6KqUBpibaBx6OMVzqkjoR5yftsDCeFh7Dy7h6MutTakgl/yX8WmGud2lsb
         w75FbTB6irTH+YjPSO1aoDOzQFgxA1a/tzeMY5gkYKYCmxKUvPclTqrNniv0wgMWR/YE
         lJI3URdpOO+o1Pbmn6EWxrEVQktlrNFv3h/mnpSoM2KV0D0DX8wd/DQmAEaguhXBYTlo
         WC3y8+NHL8xGw/JZHiw+KJSYlKcCDJck2eYKNoRVSFvhYqQk8KGpQkuOKaM++NhLlBbd
         oLLA7587Q0UVFxpGOgHBdKfcrbkCew6sMowhUTebLp77Q6MvHmxjnqdnaTkQV91CmuGG
         OvKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NP4xjpBZkX/mIxBixRNmUJcIrbys5BErll5bubcUHO0=;
        b=o0BKZSlWm3Gwa/XUpszLFSt6TYcDgodkLv7OQNi6Frm5CaF6eoURCJapXqc9uHx7aw
         xoMF7ssdiD0yeuPQL0ZcYBDCq7yiKs2oOhAXRWzL2q5PwcCQtiaAVaf6o8TYYCKlaqXb
         u35xzH8y3w65tMXQQBK/aFLBELf5dtLDn/0vCqqWH6P3IrKUAt+siN+m015M3mVDeTt5
         MNSKvMPwB4Tx2ty2zKVxkjbNz2W4kemjZL3up8GgGP4/xJs2F1lSNAfpezHzsCarsN+A
         i8Pl4+maVTpVJoT2WS1ryMAVrWMGzFVq4UAzv6m3Oru79Pv/39Og6KjPbCO1IFkUuAwm
         knfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=EoZSAVxP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NP4xjpBZkX/mIxBixRNmUJcIrbys5BErll5bubcUHO0=;
        b=lXluHBVkQhhmh/xXyrTnWqAK360YUTXTc4V4rlC564RD8Q2GO3qwcFXvnh6XlgUyf2
         JJ22FpMXmdqWKkZbJbV9uB9taW4HdI3Z/63OLWCjqyPHBqFk3QDExTX3V+t/8Aj64x18
         rhfcIinKU+um7lyneCfiYjPM7rDDJxI6MCS5aHxfZqodwbOxyv/DtyIrIBhavv5mskdF
         f0EXG5n+H3km8+qLDm3K97gLlCmlQYt978gKzjiHUN9roV/WwelThYO8IrUjmN3RZ2nS
         VIry3XyktQ1C8bfvATyoKZxXrU/zMVlDMrFeEiBptVwGVFMx/dsBjnnbc9kL9dO/rX72
         YFdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NP4xjpBZkX/mIxBixRNmUJcIrbys5BErll5bubcUHO0=;
        b=ryubx2gVgPn1aslJQJ6BWQ7m097sBTIQ4KjOvVbFVJ7orUyqqPTdw571wSq4XD+rd/
         KDny1E0E9oYmaK6V/vTYqvT1e9buVCM04sQ+IQzutlErIpGBNuB7saaOcrmbAj+uymMA
         0b858234ixRfbTCsRKZ9O2kT2V5Whs4GFVrrEHA1zdUqwDoMHYHZ2A5grc+SAvlbjf19
         a0PIlcIpB+TeJSYyccfVbgLgxUe968JxLXEfkMgvKGIOEuEvgz68N7LQ4yASzQyDUErw
         4S+D/RSJl1x2NP/IyENocoJOtbX0d2Wneo4UxR+vUSmDUaw9mb60HcTwAQuZUQiJLXp8
         s/Vg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53330nNmAU3+oFKOpHm6cDw+hyw2NCP0zUsAGyyV7DCRHds+o3U8
	HH/5vHskksRi7f0jNlpjm3M=
X-Google-Smtp-Source: ABdhPJxRyb7Vz9BhG2F0VJxVJB34IW50V/b4bWH93Hu1EcOwRtSFXJd6fL8/lRoy69z7xOKKWqsPzQ==
X-Received: by 2002:a05:6402:b37:b0:400:500f:f26 with SMTP id bo23-20020a0564020b3700b00400500f0f26mr29844932edb.301.1646239073036;
        Wed, 02 Mar 2022 08:37:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:90d5:b0:6cd:ed0b:7c49 with SMTP id
 gk21-20020a17090790d500b006cded0b7c49ls2892102ejb.10.gmail; Wed, 02 Mar 2022
 08:37:52 -0800 (PST)
X-Received: by 2002:a17:906:a145:b0:6ae:e45d:15b6 with SMTP id bu5-20020a170906a14500b006aee45d15b6mr23936364ejb.714.1646239072236;
        Wed, 02 Mar 2022 08:37:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646239072; cv=none;
        d=google.com; s=arc-20160816;
        b=Vsj22N8kVZ/AibSmMFPTeccHy14st7YuGHTBiHtwgyN2Ati2rUrnGjNTeTvmEINW5v
         H/prgeXcVt0KBEi3ztwGN+D5v3ie1sGRoaFIEzDo4TMMIecyAdZZ39puv80fTt5vUUmu
         ojT1/nuzo2l4l+dJArR3AHFM9tdMPrCinmZZhaUMTBdwNr+Xqb069RLusMKd1+QVAroX
         HfDSOa0OtSSTpnsoYC2fTM520L9aG5QVDCV3JvBXfiovGPLqX7/6oRtuhED1iWQM/XxC
         nNgts5QmHaHCx5uXkpqotj6L5hJacC59GjCA81pxTMJ6IKx3gx05/9Ho2gaLN/j8zbaj
         NQIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=I05J+o+7HT6Q0jFo6xpWdgjFaYldkohtghm32sfnKb0=;
        b=CvDTh/I/AxzplY3+7ucea/0WMW3GdVKyMyu3gh9l1THxjcstvK/dkgRWwvqiTmVyWD
         uYcM/yd2XXFRZgv0EjVdmRjjnWYgAHnOOV34R+MzCuvJuIafsGC6ltQ1EaNgifWM9Wuz
         dLBxwc4PsLor/UBmeyibwJ+9jFMhSM0LDuZHsbvzc26UJCINeXJFu3OGBKG0/x3LtxbV
         s5w/GVP5VlZ3vjdqroj1VhH1vlyQ3OxJXkEJt/sd8QD/gUCmXU6d1B9ECFoe3rk2EOUu
         gWousUjtPjr1akL554I5+mTGmFU0iZNyKQS8pl292MFzqhLTGyauKwUPdj7KWY1sO9n0
         jQ6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=EoZSAVxP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id et1-20020a170907294100b006ce69d31a32si1206373ejc.2.2022.03.02.08.37.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 02 Mar 2022 08:37:52 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 06/22] kasan: simplify async check in end_report
Date: Wed,  2 Mar 2022 17:36:26 +0100
Message-Id: <1c8ce43f97300300e62c941181afa2eb738965c5.1646237226.git.andreyknvl@google.com>
In-Reply-To: <cover.1646237226.git.andreyknvl@google.com>
References: <cover.1646237226.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=EoZSAVxP;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Currently, end_report() does not call trace_error_report_end() for bugs
detected in either async or asymm mode (when kasan_async_fault_possible()
returns true), as the address of the bad access might be unknown.

However, for asymm mode, the address is known for faults triggered by
read operations.

Instead of using kasan_async_fault_possible(), simply check that
the addr is not NULL when calling trace_error_report_end().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index d60ee8b81e2b..2d892ec050be 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -112,7 +112,7 @@ static void start_report(unsigned long *flags)
 
 static void end_report(unsigned long *flags, unsigned long addr)
 {
-	if (!kasan_async_fault_possible())
+	if (addr)
 		trace_error_report_end(ERROR_DETECTOR_KASAN, addr);
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1c8ce43f97300300e62c941181afa2eb738965c5.1646237226.git.andreyknvl%40google.com.
