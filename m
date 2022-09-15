Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHP6RSMQMGQEEAD7A7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 78B9C5B9E04
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:02 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id a5-20020a05651c210500b0026bfaff5357sf4425119ljq.9
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254302; cv=pass;
        d=google.com; s=arc-20160816;
        b=FkDHS/kECkbjp64SyOZ2Oh0G5YmUUSwvbtDg6hofhHXi1y6C5uD+3nvghVKHQRenZD
         raUcnUL6S7cxEGcK3ztelGsn+KTxRb69OXz1+Js1awv9WjeT+4YTzl6Rjafja/GSRd/N
         dt3Tge817N7b5WJkff1BQQT4D+48up2dlVUy3YqYIEFT+Efx451Hfh0z8kfF3c509NBs
         aUVwuZ89vAaJjMc/8jVJFhQZnDgGjQF5gnN7lhQSQp/KoQ4dR4ICBbZ+KmII6E3RYyED
         xHKClqS5aK8I4TEO28ZlWRoHzROFac0Usm7w4aq7UuqXk6MBtiwd0M86Uhic2tuVJFBD
         QHcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=PLzCTdpW9xZpTvCoEXeKCoI6qi3dSUGneXgCe/lYkJA=;
        b=yYcTSF1uZj6NLghPvzIaZMSKeaBZM+Rb6/h4e+1wlXzppLlAcaQS5ctXtos33OBOnt
         JH3qbt5QcFp6380sgYiijM6dyz4Mr6+2hQM0Es1ybweii65XCp4RrRXtwbd2yJRLV6ZG
         5Fc5wM86v5NHJYZRg9B6+SQj6qf432eLRwlDBv1YPsQptiR/HG/vswO+WFOb8Nj4XOmN
         rqXHAVJi6fZAv1wKeK6I6Dm2+IebFBjL7tVLv3eEpdrwN+mXTusiFlRELbzVgz6hfuIw
         DB0XIRAJCgh8GF7zQKqifD5P+/0cHPHucDVG6fgmJX4x4xeV3/cJrIol74o9SiVYMlk8
         eFnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XJ1NrdN4;
       spf=pass (google.com: domain of 3hd8jywykcucpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3HD8jYwYKCUcpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=PLzCTdpW9xZpTvCoEXeKCoI6qi3dSUGneXgCe/lYkJA=;
        b=Q245DTYRVNLvTccgWTH6w/wBavGKjvxEVGhIUsKl6EyGL6H4NAZK9sZ86imMOvnz+q
         V0y622zzaRKXebRAOXdhh5N+bKs2CQYNIAUjR573kxoHwn/TXzxx1vSFCirIXHT6ZD3B
         nJd4t+hByaZBslPuS8yL4HcyLiShrKvfvK13GHGDeLeypiscHSP43vftcorMXMgVjuK2
         5gRQgeq/DXaVZuTP9dVpfSeqdpmBZ8exNdN+uUm1PYKaMvlFd0GchEXH16tMtusrglbv
         9hmKyjuai2NSqegdyLnqQbXQdfnSeIB2jeFZZLCIhdc1bA1gIXyx4qw69ZhNQGH2A5K1
         FwAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=PLzCTdpW9xZpTvCoEXeKCoI6qi3dSUGneXgCe/lYkJA=;
        b=QyiZ1zMbAAByX59W31qfesWUbmjL/HogjlYVCwU+zfDXZ9IAvko5QUwGbQ+1em53mq
         pAFFkkSt+KKGxiYDlZirZLn+EZk/97nyVkoyFg13Fc8wlxRrATWYryurCoY6SklB3asK
         shtqXpNpzhUZxG9cvd1PymJhQXUo46lo689XLmRgj78OhlIJxmsaZ9sBSGrNMHmx3nr9
         MxkRbryShf6w/q4plaN4IfafrGdCbrTc4XIlgemsuw5OXoGhmp9jPEs+oCP+ihcuUnJe
         kVW22ydJnnyvqoRNrf2cIvZgeDaLi1ntIhyC8bXtXQzSQqIGTHAiILfJXzsJ0rmWRYzU
         3HgA==
X-Gm-Message-State: ACrzQf0GXeBQ5Vhw7MrJEEiAfyc40/uHQV/YdGj1e87ociXfqKEArEdx
	ZIXJNQStoNDMy2i+JMeDrGs=
X-Google-Smtp-Source: AMsMyM5jguNz9RyjcMatpTZQEieSgE3Y2xmJXEY042SW3vkgW1c5D2+YPMZ/yw7k5tFLnpLJ3w/2ZQ==
X-Received: by 2002:a2e:bf01:0:b0:25f:df1a:f39d with SMTP id c1-20020a2ebf01000000b0025fdf1af39dmr50402ljr.365.1663254302004;
        Thu, 15 Sep 2022 08:05:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:879a:0:b0:26b:e503:5058 with SMTP id n26-20020a2e879a000000b0026be5035058ls2677035lji.5.-pod-prod-gmail;
 Thu, 15 Sep 2022 08:05:00 -0700 (PDT)
X-Received: by 2002:a2e:2f03:0:b0:261:cb0e:c329 with SMTP id v3-20020a2e2f03000000b00261cb0ec329mr61267ljv.106.1663254300720;
        Thu, 15 Sep 2022 08:05:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254300; cv=none;
        d=google.com; s=arc-20160816;
        b=aQMXuB0X5k2BhFNQsYR1/pYV3ZGKEGxLFM88Nee8IZYrPFmFXRfjgJ6JgRrJ2w3bAu
         22X45DfHNzVtJyaqkq6xBGniFDtzGOC4j+PVZeglI91XHTmN/R17QRMm/VLMhLwfhN/s
         mYmVJGasenAD7bLmHuhUfFEfJVdrmXbsSaQ/BgK1YMze/Gvh9sJVDEWq2kGG6K6+mLH9
         GJ3IUBxwjW6c9Ci91eagaOCjnE/a1puFzO/gTgl/lhfEQtroO47lttw6XR2TQYwWFlIf
         CNhJwpYebBJ+kDEde9BZAT7S+BXLPL75ftCohu4UYp2zaQ/vL9dmf1i0qFXnWrDYh1ES
         PEGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=eIK0S734s+WuMuzHGxUrnoQabUzsOPxTYvMm/ke78tI=;
        b=Kcx4hnbnHL/UqVPxrwyhW9QtIxyuzbpVACIrB1giITNZN00cqZIBb43eBDk/nsOwM3
         BFIItO3qp4T/eYAEUQSKPkpC+VdQZk6T01cpwaRWN1IyTWP3JX5PlP6qWJtRbv93Y3k1
         ZLS+OAjAWSDj7MyWMAWrFz5gqdqsGQNE1POntx/vKGlyEe/KrAyWj3w1R8M17VTYFKeU
         gbjd5jot+PIhjGqIMbeNlgQ3Xj55tSy+edt+IuJ1ecNAOvxrnqZWdhvIRlvmzlp8IQLl
         icoMRNGThGEWojx9zhKPTLCnIfH4adzH7Aq6u/ocRjPwCsIILdlUteYBHVsMw0WAE1sw
         SNwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XJ1NrdN4;
       spf=pass (google.com: domain of 3hd8jywykcucpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3HD8jYwYKCUcpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id a15-20020a05651c030f00b0026bfbc4be3csi382510ljp.7.2022.09.15.08.05.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hd8jywykcucpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id s17-20020a056402521100b004511c8d59e3so12872293edd.11
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:00 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a17:906:9bd3:b0:76f:8cce:7a61 with SMTP id
 de19-20020a1709069bd300b0076f8cce7a61mr282972ejc.345.1663254300266; Thu, 15
 Sep 2022 08:05:00 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:42 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-9-glider@google.com>
Subject: [PATCH v7 08/43] kmsan: mark noinstr as __no_sanitize_memory
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=XJ1NrdN4;       spf=pass
 (google.com: domain of 3hd8jywykcucpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3HD8jYwYKCUcpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
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

noinstr functions should never be instrumented, so make KMSAN skip them
by applying the __no_sanitize_memory attribute.

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>

---
v2:
 -- moved this patch earlier in the series per Mark Rutland's request

Link: https://linux-review.googlesource.com/id/I3c9abe860b97b49bc0c8026918b17a50448dec0d
---
 include/linux/compiler_types.h | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 4f2a819fd60a3..015207a6e2bf5 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -229,7 +229,8 @@ struct ftrace_likely_data {
 /* Section for code which can't be instrumented at all */
 #define noinstr								\
 	noinline notrace __attribute((__section__(".noinstr.text")))	\
-	__no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage
+	__no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
+	__no_sanitize_memory
 
 #endif /* __KERNEL__ */
 
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-9-glider%40google.com.
