Return-Path: <kasan-dev+bncBDGIV3UHVAGBBNW7WKFAMGQERGSPGWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id D89D141638A
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 18:47:50 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id i4-20020a5d5224000000b0015b14db14desf5621598wra.23
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 09:47:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632415670; cv=pass;
        d=google.com; s=arc-20160816;
        b=CiRU/NsbbNpQn07R3FrRI4voEDoSU8sJ0Ho7fpJTc/wvFOOBmrJqz6yD8cuIzioB4t
         NwDHkGEhlBkVevTTQ/eyJHxaRed+1LGwPyDaXrT9w46k9uCw2Urb2+PFGQruZEbQcTdi
         eS4qkFzKM28kSmrXT+9HvZCHjQW7r+d/xkKhDbt8CWoKJH5s4TQp8XNZbHnIXUkAIFFU
         sDOvLGYw2M5Dt9ayME5oS+FTL91OjL9NXwnJtSg/EtuBIbngu4U3nS5ISQvAzmd2kiz0
         +R/S4DFQsh5yxm1PviTTKljlqUhD3IbrGZwQ1ezMRVtBOKci7dGi74dgP4B7P03Zw1A1
         OlNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=V5ng/2Tbmd8otxPeW+WOZB40WyDyqK4mRdBiM+wWH5E=;
        b=RCy7nORPb1Y5DbtTRfeGQIRXBI6mYCGOIzEjjZvAaQaLf9QKAtgawCGpd7jGjTaURS
         kH1Q2qc9nWtWuPOqMKPPJuxqDvf+nYrMeo9vSxH+6k1jR6nMiIG1Bf0QXzaYIsbYS9Nw
         po1Kjx+dtxZs6ykYf9a3FC5HAAAcrZd+OoYJvP2w2Xq/ukBBm28DWw2TcHtNyyaRM+j5
         flUE8djGFAqia/UDleWlvfK3ctrmVA50Qg2yuok3Df40HkMjEL+2Mnq0qQv+UTxbh5Bg
         e5rXMNh2Fb01RyTg1aEalrVwNw0JoyqA68oXuPwcQ1shj1KqlvWKvDkb9P0sGVMpIJE4
         lkew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="pZXzZdc/";
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V5ng/2Tbmd8otxPeW+WOZB40WyDyqK4mRdBiM+wWH5E=;
        b=M39Tmd1OoYZIwfe3r/wRBbi0FXrFFzKYGW7OFd9MKemeV1QCKz+HiHze8p40dz1OM7
         4vcUnDoBNwWyBfFaxltdZy/QcIdm/RndInxPUHxwjpRpytu3vzQvaZH0AC70PwF0BzXh
         keBXymO2ovnHwIb2/UOTm2SRYpRhAf1+moNUFb+aGUWGxCJ9pXLw+qixbmTApiFHYMAw
         SQLHOzqxd56hm7kUf1I302+/wr8EkjEihTXHIeBwNvsxugN3UO0EzycldRPG+5aWjwFk
         oFXzecdi1LcqLjzmMU4UH12ZHmiKklwwrzobC8YH2bsgSKMpgJO/pyp91zxkSy88g2dP
         PU7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V5ng/2Tbmd8otxPeW+WOZB40WyDyqK4mRdBiM+wWH5E=;
        b=DY5UH9IyCwdN7Sbdd19is2lCfl8Otrb4Aw9zsqnoj6OND8dheZfU8O8ljzgNrhMtDA
         0mkGi/Bvb62AvAuye/WROh9rmMJGa6/GniQ92OYxaUe0lGWl4SL7ub//kuxqKDEdqSvW
         DPpHCbe8WkJnvat3gdelZAgaMq8+N+zxwv6J01lAhWSDtSKnUTp3Vsev1CtA13PoZKAq
         PZxwOwZO/Ebfd3CoVZM4dtFRpPqPI5DHsAWxQoIN8CykJUJzZCMVHSeA9l7TbiSfavR5
         aVVMnar1/S+SAOyRPDeCh9U78lfmLMV1WCR3Oa4T1CV0htjHYkRDkr1Z81Tr0lg8uvIt
         r7sg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530g6lwgNpLyrswoSkAulZeYXajKH8b2W27dEkH9z6OoGIVaayFX
	XffXidsSxM3KYskKMKi3/UY=
X-Google-Smtp-Source: ABdhPJzCRu8J7WDYFcg7xtEaG+fBkk0JiRtz5SBwKbxYmqdA0te6586l4DKSZ4U0dHaxwqWwwcXMtg==
X-Received: by 2002:a5d:6288:: with SMTP id k8mr6425613wru.137.1632415670650;
        Thu, 23 Sep 2021 09:47:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f8e:: with SMTP id n14ls3298965wmq.1.gmail; Thu,
 23 Sep 2021 09:47:49 -0700 (PDT)
X-Received: by 2002:a05:600c:896:: with SMTP id l22mr16908843wmp.173.1632415669791;
        Thu, 23 Sep 2021 09:47:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632415669; cv=none;
        d=google.com; s=arc-20160816;
        b=Ak0BvcNdcnPZFzX2a/u3GZHj8tquhC5T9XHZMlGgNOBnb8CLYwBTvF3kFuux8G3RAK
         gbLL9oMypEDi3vq+8mW63xTaXvP/fGQ1EOHe/6wU+3kkM/KSoBBETlt5Jvd1EQsOki+L
         bTjLp1ap3Cb6wZGxgr0WjZIR+Vva4Yc8duspzniB2Hj0vS31YU2htalbR2idfbP7YF9p
         hJDe2ta9l4DgjY337ZUvuz8Ey8aaA4h/V6UwGCINksxsS6Ij5zWDyj5qBloWRHeG9Poi
         fhYt1eJYDnJnlk67+5ryXFm1xJZK+Kb5fKP4YaiyKON0F9KzkcF6imfmg1F6fXM8EwRQ
         gvPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=ItPVdW06jesRja28cAhDZ6mhsonko7BV4wLY07tRRTQ=;
        b=n3v9WrtZnCqXivl6ZduIiucRQsUu+RG6kUZQJFyWCkGoOqmmdzYjF/HBvztr8xkUUW
         cXBt1MjR4DLweGWpjMZqmhXQ5EKQdOoxoYkdcUs5/WsD++W6q6AUpPcB7Ll7nNdltnjU
         P3uiNt6zRP4QivuQ3MTbT8oD4ONT8uU7TxNaITn1PNaNl35FmGDErO6wscci2hMmzM/2
         3pPES/2HylZqOuL4b1Y6bNw8c+eEqopYj/nLZ4cZTfEJDuJBdeVkJZ+QA5ChkjZVoT4M
         SQFSpHxo/gfqOYkz6ikU7DvDiYgOi19GHOU0gRGVUwM4/q0DvbO1hERO+CU1cKtytwHw
         KYeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b="pZXzZdc/";
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id l11si55888wmg.0.2021.09.23.09.47.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Sep 2021 09:47:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Steven Rostedt <rostedt@goodmis.org>,
	Marco Elver <elver@google.com>,
	Clark Williams <williams@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: [PATCH v2 2/5] Documentation/kcov: Define `ip' in the example.
Date: Thu, 23 Sep 2021 18:47:38 +0200
Message-Id: <20210923164741.1859522-3-bigeasy@linutronix.de>
In-Reply-To: <20210923164741.1859522-1-bigeasy@linutronix.de>
References: <20210923164741.1859522-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b="pZXzZdc/";       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

The example code uses the variable `ip' but never declares it.

Declare `ip' as a 64bit variable which is the same type as the array
from which it loads its value.

Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Marco Elver <elver@google.com>
Tested-by: Marco Elver <elver@google.com>
Link: https://lore.kernel.org/r/20210830172627.267989-3-bigeasy@linutronix.de
---
 Documentation/dev-tools/kcov.rst | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index 347f3b6de8d40..d83c9ab494275 100644
--- a/Documentation/dev-tools/kcov.rst
+++ b/Documentation/dev-tools/kcov.rst
@@ -178,6 +178,8 @@ Comparison operands collection
 	/* Read number of comparisons collected. */
 	n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
 	for (i = 0; i < n; i++) {
+		uint64_t ip;
+
 		type = cover[i * KCOV_WORDS_PER_CMP + 1];
 		/* arg1 and arg2 - operands of the comparison. */
 		arg1 = cover[i * KCOV_WORDS_PER_CMP + 2];
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210923164741.1859522-3-bigeasy%40linutronix.de.
