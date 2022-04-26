Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7GCUCJQMGQENYDLMHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 3991C5103E3
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:44:45 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id dn26-20020a05640222fa00b00425e4b8efa9sf3780725edb.1
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:44:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991485; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fr31imcsRECkmDU+Nsm/uA1bQlaxaqtrMgdFbNzPxe5sH6zrG0dJmEM242VRS7u6vY
         dA/+/9DgQ48EnqASNZb8RU2lISDrfWxu1eUG6heGZk9Meajhu5Pww2GgleN/CUvWrvog
         ZwpU1VfoE9wPEATTJu1u11XQL8EtNTjI6UiQMDk+lJtpsyUXIfCchwxQ7nP2cfNoW42b
         xSod6Og/gnxGuTbnPsSN7K7uWj1+mc3O3EqcOAwaE0Q+0/cj5+9V6XvxCfT0v/KL6JD0
         0TXkhi/Igh6PTNg3ioS0wvZmxlRiY9QeWtpxp923YVxSE3dZ/dOizgnXG8I0jyPefjje
         Kl8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=V3hnTXqGoXm0TpB+uocLXmZdM6f1fy09PMu6/O9P5Us=;
        b=javHk9gYxhmazsRKuikZu7BJ0pbpUzfhQHSIuo+AYUvkUgbR9VXRJCEanpyi6F5Zmv
         g7ldn1CsZ6YHI8umNAATHm7gfXTj8kBXkxG516NPsRgLCx9vA1uUTYTPLuTImSrMHde9
         2s92tJmwHzbZH74ozTDfTGL3V7ztOpJ2snNIwMRxoOqqlF6nE7GGGZvVtgaS815i44rw
         oDQYpayE4FjbNDblrRdzI1CYFx2cMjL0MlRBdTMKZ24R9jUS95xekBxlMQ5f8j7SpyUp
         DeiQ1j7YG6YCI3U/irnFxZBIBdOl8k1sQEbZAK6hWc83NhaYlKu/VkIm6Z+feUz1nhX5
         T9qQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=s7nDKeE2;
       spf=pass (google.com: domain of 3eyfoygykcxgchezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3eyFoYgYKCXgcheZanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V3hnTXqGoXm0TpB+uocLXmZdM6f1fy09PMu6/O9P5Us=;
        b=fhn+u8bokces7KONYp5PoT9P8JI3Uc1ZUClKLA6PjDIc0zplz8xKSYAk97rXZJhaHG
         NapXq0reBaR98VDILO6NgbbhVaxm89Wp1EfZkW7vV68IkmaEaw/1xwktZUJN6IAztkj9
         hvwF+GW5uf+5ppPCUVKba4NlbdC7kmYiwE4yHjFvuqs7HgEnMFQV23sl1dT/23XrO9NR
         kfJF+A0tLS6TtDaPh3hE36+nUYLxTV7XJZOZ1L0TGL99FgKWBgQouVc7uffEXCuqpBle
         4ouJHfeQtcM4cylRA8nxe8gWhyiaOT2PCULGhlTs3fkQMBUEN5iBm/KTcU2hDzEVtAKt
         rVzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V3hnTXqGoXm0TpB+uocLXmZdM6f1fy09PMu6/O9P5Us=;
        b=b98ldtM/WuFusE6Z3S6koY24YoNrY+EqkEqKmVdPE8UtsRG53fABiB5QHD0EoD9w/c
         ySfEdvXoTxQYE7ClT9k8SvGpXeFl1TvySsa30uLBsO9Xb8E8dh4MVaP1uNcPFSVUQCEe
         8ZgADm+3utD8AZ4X7brob+3br9H5OLJDK0nyS0qqEKnmgxbgZnDSpZEMn/2XDbacJY6K
         K7c1DwVn2n5pF4NjYpzu1hFyFra5TbGCZ8KJpVQF7qRjmCL/+IkMsGK5ZR7ECELt0OsL
         jlJNYUzbQe806DPM6BIqyQ4aEKa5MA/fxwVURZcs+ZaFckKfhz68pgUgUfOjgiK6TnoT
         sHag==
X-Gm-Message-State: AOAM5323Iz34Ml8j2ePqxIBQn3dGckX+u0D3vpUdrrBNlCQPXe11LFWh
	lIHzRMcU8lZVmJeskEYqcDc=
X-Google-Smtp-Source: ABdhPJx/KGHmOR3BS7jXFT/cakTvv60UXUk3J1AJTXrmr79ugt4vvh8J0niuYVrYyM1Z1oqNb2Aprw==
X-Received: by 2002:a05:6402:5113:b0:423:f5c2:cffb with SMTP id m19-20020a056402511300b00423f5c2cffbmr25359966edd.174.1650991485052;
        Tue, 26 Apr 2022 09:44:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2741:b0:41f:7eee:e393 with SMTP id
 z1-20020a056402274100b0041f7eeee393ls1367972edd.3.gmail; Tue, 26 Apr 2022
 09:44:44 -0700 (PDT)
X-Received: by 2002:a05:6402:270f:b0:425:f061:bab9 with SMTP id y15-20020a056402270f00b00425f061bab9mr9600757edd.262.1650991484013;
        Tue, 26 Apr 2022 09:44:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991484; cv=none;
        d=google.com; s=arc-20160816;
        b=b2t/piFfW2JJd8bUudLHH31WqRiklTfyA4trF7BSFXehyM0a63HQOfJmj7kpnyg0m1
         grPzyq3B38Qdg2tVjZP4KM/pFcdqbnjKcunfj7i41hXJkSGIga1X6lrLAYUxHs3+6iby
         5GQH5t08ZkUyNsR8+/HgnoiXPD9xORBnKtura/UuIoeXfKEyOdxdfbfecnxmXJNuSV0l
         46U/I7/TQhprh2RFg8DQL8mhWQQ7aNZ8tDpglLvldk+OCSv4JDpOMStPeYwxz8xuH0h6
         LV56f/sExn16XMJXeLMByeMyoJhPPFufrhl9NqZtBwtlu90YKpS7kXuYeDl69qcXUTET
         OS0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ednioRVQi+463GyxSxojLtYXRmMb4k6reZrR8s7PDTk=;
        b=whAkYjskVNmfF5/EnZiLcSqL63Vd7+yx27mUDXW2YZv2HOMPmw06slRe8pWqUBF452
         2RJRYLgN1VT+fv9IykwX7mNbQmYicQAK0b4e1j3tvawn9Ym2c1Od3VfLI13SG/eAc0En
         SLADuFb419doQ2x9ZbAG+dUd7yovxZc77O9cUnihxGJC8LfiR0PYRTJvBmG4JCHHFeA5
         LrgESqk2vdLAsQNndJIqJ4G4W1csPiDgTAyrLHHtlmybLbH2o9N973wJZhAFwyrOLTym
         WYAZdhyY0knvl6hAgjdanUn3ic7zmdTDhgW1XArgIVhr/qMliHdrr6wo3YqeaK0phT40
         osLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=s7nDKeE2;
       spf=pass (google.com: domain of 3eyfoygykcxgchezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3eyFoYgYKCXgcheZanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x149.google.com (mail-lf1-x149.google.com. [2a00:1450:4864:20::149])
        by gmr-mx.google.com with ESMTPS id z23-20020a50f157000000b00425ac5c09aesi708891edl.1.2022.04.26.09.44.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:44:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3eyfoygykcxgchezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) client-ip=2a00:1450:4864:20::149;
Received: by mail-lf1-x149.google.com with SMTP id x36-20020a056512132400b0044b07b24746so7890043lfu.8
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:44:43 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6512:114f:b0:471:b097:4a29 with SMTP id
 m15-20020a056512114f00b00471b0974a29mr17572189lfg.93.1650991483323; Tue, 26
 Apr 2022 09:44:43 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:38 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-10-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 09/46] kmsan: mark noinstr as __no_sanitize_memory
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=s7nDKeE2;       spf=pass
 (google.com: domain of 3eyfoygykcxgchezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3eyFoYgYKCXgcheZanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--glider.bounces.google.com;
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
---
v2:
 -- moved this patch earlier in the series per Mark Rutland's request

Link: https://linux-review.googlesource.com/id/I3c9abe860b97b49bc0c8026918b17a50448dec0d
---
 include/linux/compiler_types.h | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 1c2c33ae1b37d..a9ba5edd8208b 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -227,7 +227,8 @@ struct ftrace_likely_data {
 /* Section for code which can't be instrumented at all */
 #define noinstr								\
 	noinline notrace __attribute((__section__(".noinstr.text")))	\
-	__no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage
+	__no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
+	__no_sanitize_memory
 
 #endif /* __KERNEL__ */
 
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-10-glider%40google.com.
