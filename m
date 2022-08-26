Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5ODUOMAMGQECCZD57A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id D75AC5A2A61
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:08:37 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id f10-20020a2ea0ca000000b00261cd1f1f60sf659802ljm.2
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:08:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526517; cv=pass;
        d=google.com; s=arc-20160816;
        b=au3hSy42LlJdfgZ6XBe99M6x8aRoJ+AS2TYknq2hdYnR2IoOjowZWY83xOTTdpd2td
         EvQR0SlTi5KZgTQSTBB63y2yoEbbh6uRx55fXR9znYYHDMNiNu3PHCCXAmB0U+B38h0N
         vEI5ZUYei3XjELy8KvDdlC5JsjRNSEPlIU7p9M768bidXHoQEMwDP2a5A5V72lPSyq1E
         X24MqanaS5BV5uctBt6MhTj2u1qaeWj6a7jWu/b1iiGtvW2/woBfRhY4f9B9d3IYhZJJ
         qmxR6YZsxnnC5X3HNVJA1ATDENlvvdDflv6PEoMKiohWQ955CHLR6KIi+5bglF/A8UHJ
         QVlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=CD2xw8KlWsOWwzJxwlo/sYqcynKykHX1tgOa3Zmg0Gg=;
        b=aPISasooYIVcFjFoYayny+Af46X34/hGjW6hapjOB2ihcufnWMqK6onVsmRUvecp3c
         Z5W6WaUvpOjhDe8IAeduGTh5k4yifroQn146CxecihqagSyuxKRr3Y9dAlIyQ37y3ykX
         CRaSaGVw08rytLf3K2h5l/ePs/teSsvhiYZcj8of3p85qOYrJOWZzNtHo5Cg0XahuD6P
         yQ51vWv/OvEgWjiQxrUKaC0WDSoPZE7U/1f5UePGRYH/FlRQ4D3TI8fCaqL0ISXr2e/h
         VGyJtn5bSGo0rR0XCp3HI8bmhuInWQHJl/paIub0FWXqHJLj9RtXX//BFRSntnyc+iNv
         c5UQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XhlU5hNd;
       spf=pass (google.com: domain of 38-eiywykcfglqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=38-EIYwYKCfglqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=CD2xw8KlWsOWwzJxwlo/sYqcynKykHX1tgOa3Zmg0Gg=;
        b=kcwJ0Tk41hihqz4Ws4/HocGvTk1xtfWCC5Zh7wcaG0bU+IXxQ/8Mf1sIc6lVIQuTyy
         w7FTHVC1vLtb2hnrmh7j+GMLR+vUxAMSO7PIVKnuidOtPtDIvUVIjntRrgHX0ivdb6IS
         jemTCM4PRPgIlmSCrRtjBdD9gL4OmevajhPt+9lbWI2JP79JjgyfdFClstw5biYThcBp
         IXkmWcyyF5HRPCNhWW5uv2bGDQVHmDSZdpN4XBgqWd/97SC9ott/xXWL/Xw7G++0Bk9y
         SFJq1wnEsPEixGXXNw53miCthJJKLZgl09noSPS5ZGVRCT/BQeIN73zonYI54nwGqkoE
         6B3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=CD2xw8KlWsOWwzJxwlo/sYqcynKykHX1tgOa3Zmg0Gg=;
        b=ioQH5u/2ykVYAvgIEr3kXr3qrYZZcY7t1bPONJKcW+RzAqav9gpCSu1mBxxNvGBVJ1
         I4iCUQFlCkxbuJJsUQhNUJRRHo4+5sPfP0VAqwDeuZGfqe0bLnxeQOFiyhqTGjOeTejg
         ckaalCTonOUKzgI/lsopv1P9Y93yrIkL1OYIdTdcTAGsQRooVLt59690yE65nnr0A4FO
         O9QeGfpzJ31i4/veNQ7ZotBzQSbpB5zWWbXAloOU+QYpdpk+RO4PgTVrAsrzPXCuNmdO
         udjsoEtP6HZpZKICOiyrYGQcMtc1RxD4ma3ogy9CSAvK1eCsU62Ri1KsOLOe/HIMQFs0
         DOxA==
X-Gm-Message-State: ACgBeo0OkeWjGfhJILeKACLs+QGLNrGml8zQMWoTwFlVU9h/PQhe5jfF
	SoYIluZjmLoF70VyqSFcc5c=
X-Google-Smtp-Source: AA6agR5/gcUbdt3W1mwLZBDRs34OrPW+KnjyhNyTopSW0bEAZVEF08H3/wZNeeQY20xTVpqKVMKqmw==
X-Received: by 2002:a05:6512:234a:b0:492:d80a:e570 with SMTP id p10-20020a056512234a00b00492d80ae570mr2486423lfu.652.1661526517370;
        Fri, 26 Aug 2022 08:08:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bcc1:0:b0:261:ccd8:c60 with SMTP id z1-20020a2ebcc1000000b00261ccd80c60ls706556ljp.10.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:08:36 -0700 (PDT)
X-Received: by 2002:a2e:894e:0:b0:261:ea54:6c4f with SMTP id b14-20020a2e894e000000b00261ea546c4fmr2072974ljk.191.1661526516107;
        Fri, 26 Aug 2022 08:08:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526516; cv=none;
        d=google.com; s=arc-20160816;
        b=0atcpOCxS9VIqMp5p617x2E1E9T9ATh1P95h2869XnzwM5xS7aIyIOJ2T4OrgaOTAL
         p4i2Fhv6VJtvk3gOMfte8WdDExXK961oq+XzC/XmeYM0yo5MVhjiluUydP0yvocAM+p/
         T2UC3sVOAcKYbHjJBZ3jZtdoSyaxc/+Djjry+rbALM0jGwBylp4r8XLW8oY2iW8uUEIe
         O/wHa19cxe7NYfnELiVpNV1ZRix4llKD44o+IObT7cE9tBop25cjEWhiUz/O1ecq7wOu
         ZydAet3HW3yyTnN3sme+ow078+00sI1dDh06z5bZIvmnKWcvk1EBy39Kh0o69Bm27jMz
         mHEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=TLtEZ0bDABRCjn67uEnKqh55BiGh6mAGtPfpqU3Dom0=;
        b=tIhl5sm/uy4hTPwmBI4VCcQWykmnBJa73bFlyXsIHxZ7zEpWG/8esy7cpH4CVXTe9+
         trzGG4AhWrk0Rtc3UNe7g/XIwdKq6pCfu+LiYbj6GfETtLG8qvPwVZsaog24i72zV1Za
         7uqsT6dXQaXJqqxh8ILa04qFswcLiXcszl+PS3C0ZA709lDwx6nCIFH9N0oBHdZ9lNGl
         a1LEj9DVE48f9qNBXE3n7InwWl8OjsCq/e4lSKVAHRXkrPZCJqEYg+fMicjxd2xNWh4M
         CnKRie6kV2Opfex6UvwHZzUTbBM4oy6aFziU6HSXDLXBwc1YKY9rWohjhuH4POQzhkce
         BOdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XhlU5hNd;
       spf=pass (google.com: domain of 38-eiywykcfglqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=38-EIYwYKCfglqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id c7-20020a056512074700b00492ea683e72si66502lfs.2.2022.08.26.08.08.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:08:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38-eiywykcfglqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id w17-20020a056402269100b0043da2189b71so1225639edd.6
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:08:36 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a17:906:9752:b0:738:364a:4ac with SMTP id
 o18-20020a170906975200b00738364a04acmr5783646ejy.759.1661526515449; Fri, 26
 Aug 2022 08:08:35 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:31 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-9-glider@google.com>
Subject: [PATCH v5 08/44] kmsan: mark noinstr as __no_sanitize_memory
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
 header.i=@google.com header.s=20210112 header.b=XhlU5hNd;       spf=pass
 (google.com: domain of 38-eiywykcfglqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=38-EIYwYKCfglqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-9-glider%40google.com.
