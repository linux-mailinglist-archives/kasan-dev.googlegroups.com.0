Return-Path: <kasan-dev+bncBCCMH5WKTMGRBRWEUOMAMGQEPO6RVXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id B324D5A2A8F
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:58 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id k24-20020a7bc418000000b003a62ad689fesf618038wmi.3
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526598; cv=pass;
        d=google.com; s=arc-20160816;
        b=OaQ68GU69Fj46aXBGPK1tC5Q3yv6VyO+4UB39155MCLBx/OMIJKVDS+aaGcgLr7QBA
         qyQ0Ifxu7t+Q6jyFNY8PASamJFyuTGmX/7AgjiIYDObfSubHqJmOVkNgzWSzL8jb/L42
         fVkhRnBWEiUM/Ku0D1rsaPqyy71nGo4LdPJSp2ReSxQqL4i+3SJ2V3LtMwNlX0PHCwI3
         vvcLrSLbgDCsZj+jaw6JwjcRVJ+0Bolwym/erDfWviRlYupONZbSGZ1jNPVyjprLyu2w
         j6R2GcwsoIdoupU24+XZojA6l2Z1EHK0fTpWVSuhBqmRisXjyPgC5eHDzehwNEc0UdNW
         87jQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=fVJTiaVPAi3I98i/tKTSo9DzXE5wF6H2hRCFQN390Io=;
        b=L6okx1+euPthUUSjkYmQpKvuTl7fLYtoiiiyPVsGo//WRFbfh+N60hwEoGHGVU1s+6
         gJgbhxIHWgs9JF+wRepo1SuoYv6SNTO/0bf26fqoo2WJKxUVXYbeW1FlfBSkYBHqZLQC
         P84QyzmFdtgWfC8cz5n8Ri8EP/oyTaxF28MTpbq2L4qrw6m4+ALNZsU9ZE2DxJfvjXHs
         WIOEXxZ5RbQWtXGUkGYupk4ZJ3a50FZsG1l6z33XivIi2/k/FWeALAbTQtnz7q7t4AK2
         M5bmhHatxsRB81AbIbcgbsU5GrwuyeYjUEawsLxBtOwYNiW4y9j35ohejzzw/m0Lemin
         nhjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sAVtSR5T;
       spf=pass (google.com: domain of 3reiiywykcuwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3ReIIYwYKCUwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=fVJTiaVPAi3I98i/tKTSo9DzXE5wF6H2hRCFQN390Io=;
        b=ItSyPP8E8PJrlFu6uvwO/FvzGeH77fQ985jliMYn05oRPVAFm8BKnwnNr2uV1M1GHc
         lkdc+XrSSUjzMY1Jnpzv0jEl2NQ4QQdAFupjO54hubuSpJy/GkJHVOvdSAphrOAJSggl
         1ljsliLdhnFUJXepUyEBu/Hq3LITZgeJd7Z9BcK92S3JmPWd7Zn+3flj9MPEekJt7qQr
         IiL+fnmQpBgr9d4v5tbasKQbtt90gFNlzKhaVN4+lilEfm/6CBBz4mteWIbgdKtiDtSf
         Kamhofo9SsvgY02/bOe2ky+ipuoEaZMRBCA/9TpNTKAlNHJw4jZAJ7cKPj3tJD88QTJz
         SQug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=fVJTiaVPAi3I98i/tKTSo9DzXE5wF6H2hRCFQN390Io=;
        b=sk5REF1fifOnkQutY0uLWtm64PhF4UPT1/Me/kLvNFl6diR7hXjuK/3j/TlVI1bblq
         AGhGtMXr+4SYoMstnriG1MxTRl2Owz7CfXOhvaCLp2rVMeUY9sewW2N0zL470F9y4ujF
         N7M4UYxhIxEzAFhAMCzxYOlGw8X3zCJ4JKkoN9oQtBIv7I1sWC4+pAqkvrbhaVjXTpoo
         RwnaYTBzIhyn12bVM3t3m7sx9kpz3IG7qQRaBOGqjPAwQfStCVvWxmQufZw0toC33Tmz
         Ox7Y8QhILoXM7Uy00tdpigvfZf2ldublRnlLUTi7DNw7YyLyF/ZJeS+veO4enAyRzIAi
         YX8Q==
X-Gm-Message-State: ACgBeo1RiG1o2bNSoij6b4XY22zcQFqR/A2tIHAYjjCanl8sgvCz/FSM
	WsIvQovx29VKS0owRcC/1+M=
X-Google-Smtp-Source: AA6agR7IVNhT9ndTpOMXjMFRJS1CipYjz/R7T14Ta87v8jZLM021QSFMoYkMGKYF9bpIA13tMz0TjQ==
X-Received: by 2002:a5d:508a:0:b0:225:54cd:6a6f with SMTP id a10-20020a5d508a000000b0022554cd6a6fmr67171wrt.658.1661526598435;
        Fri, 26 Aug 2022 08:09:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e4ce:0:b0:225:6559:3374 with SMTP id v14-20020adfe4ce000000b0022565593374ls93654wrm.2.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:09:57 -0700 (PDT)
X-Received: by 2002:a5d:598f:0:b0:220:8005:7def with SMTP id n15-20020a5d598f000000b0022080057defmr51909wri.435.1661526597557;
        Fri, 26 Aug 2022 08:09:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526597; cv=none;
        d=google.com; s=arc-20160816;
        b=Cs8hLBRQseNqhrVKsHs3HPyVzJWvpc4pq8wJHVt5imLZImwnKb8P2Srem4Ncn9QyZM
         i7P1bz542oBBo/EfV1RMFpA6unjKNSshkxXZ5BD/QSnJBzrx6fQRss92rszV8L/oXvri
         Rl8LuPP00+nEKrPWWbjnFARUNTN2nA7gGEncz6jwqCcHB0qVIMz4+rgrXgvQjwi8j1+i
         vtn1IGQHiSGT7HLmqMAWQCWmrygrpym5GvNYCC48bftb68X2tXHJdbhT4Vq00Hvy94g0
         XxPc3CiAcqwTXCcurKOkeH3k4lFUoqoI4G4fn88G/gvReEQOmKGop5r6mDbmH7oZMWgX
         vWbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=03rMp3Lo5JUXz6YDRuTXWFQl7G4ZPrO7G1beymmSRqE=;
        b=WGuJcgRdZFFGKNLsC8tVHXxz7HprC1LiokGxHbYXxrJgJwTD/u7JC/MyziWQVLWzOP
         fXWWRAQTNyUJhMb+nfCUwoaeJb5+J95v2vexZxck9pmF8wc9/OPE2FL526RQoWuTgsY0
         wvNrhZf7xRewyWUdbYOBt0btxD27ck0x6S5WQHQSXISjMiNfSrGX3ivlyxN9qRh8WZ48
         /xhN0Ad+lDBmFjLpD+CAKPktK21w3DugmEV8hQa6ea6BKpeZ9qZcOfJTeWQ2fWbfwF5m
         Tb4W9vomvtuVlYCURqGDsAHXKj6OkZzNNKt0WteBCemQVF/3O5x8SbF4UFj4rrYU37lk
         2sGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sAVtSR5T;
       spf=pass (google.com: domain of 3reiiywykcuwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3ReIIYwYKCUwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id r5-20020a1c2b05000000b003a66dd18895si573789wmr.4.2022.08.26.08.09.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3reiiywykcuwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id sb14-20020a1709076d8e00b0073d48a10e10so726715ejc.16
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:57 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6402:26c6:b0:446:b4aa:5d00 with SMTP id
 x6-20020a05640226c600b00446b4aa5d00mr7346330edd.63.1661526597110; Fri, 26 Aug
 2022 08:09:57 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:08:00 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-38-glider@google.com>
Subject: [PATCH v5 37/44] x86: kmsan: sync metadata pages on page fault
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sAVtSR5T;       spf=pass
 (google.com: domain of 3reiiywykcuwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3ReIIYwYKCUwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
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

KMSAN assumes shadow and origin pages for every allocated page are
accessible. For pages between [VMALLOC_START, VMALLOC_END] those metadata
pages start at KMSAN_VMALLOC_SHADOW_START and
KMSAN_VMALLOC_ORIGIN_START, therefore we must sync a bigger memory
region.

Signed-off-by: Alexander Potapenko <glider@google.com>

---

v2:
 -- addressed reports from kernel test robot <lkp@intel.com>

Link: https://linux-review.googlesource.com/id/Ia5bd541e54f1ecc11b86666c3ec87c62ac0bdfb8
---
 arch/x86/mm/fault.c | 23 ++++++++++++++++++++++-
 1 file changed, 22 insertions(+), 1 deletion(-)

diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
index fa71a5d12e872..d728791be8ace 100644
--- a/arch/x86/mm/fault.c
+++ b/arch/x86/mm/fault.c
@@ -260,7 +260,7 @@ static noinline int vmalloc_fault(unsigned long address)
 }
 NOKPROBE_SYMBOL(vmalloc_fault);
 
-void arch_sync_kernel_mappings(unsigned long start, unsigned long end)
+static void __arch_sync_kernel_mappings(unsigned long start, unsigned long end)
 {
 	unsigned long addr;
 
@@ -284,6 +284,27 @@ void arch_sync_kernel_mappings(unsigned long start, unsigned long end)
 	}
 }
 
+void arch_sync_kernel_mappings(unsigned long start, unsigned long end)
+{
+	__arch_sync_kernel_mappings(start, end);
+#ifdef CONFIG_KMSAN
+	/*
+	 * KMSAN maintains two additional metadata page mappings for the
+	 * [VMALLOC_START, VMALLOC_END) range. These mappings start at
+	 * KMSAN_VMALLOC_SHADOW_START and KMSAN_VMALLOC_ORIGIN_START and
+	 * have to be synced together with the vmalloc memory mapping.
+	 */
+	if (start >= VMALLOC_START && end < VMALLOC_END) {
+		__arch_sync_kernel_mappings(
+			start - VMALLOC_START + KMSAN_VMALLOC_SHADOW_START,
+			end - VMALLOC_START + KMSAN_VMALLOC_SHADOW_START);
+		__arch_sync_kernel_mappings(
+			start - VMALLOC_START + KMSAN_VMALLOC_ORIGIN_START,
+			end - VMALLOC_START + KMSAN_VMALLOC_ORIGIN_START);
+	}
+#endif
+}
+
 static bool low_pfn(unsigned long pfn)
 {
 	return pfn < max_low_pfn;
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-38-glider%40google.com.
