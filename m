Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLGEUOMAMGQESYBQCYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id DC8B95A2A86
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:32 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id d4-20020a2e9284000000b0025e0f56d216sf664183ljh.7
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526572; cv=pass;
        d=google.com; s=arc-20160816;
        b=HSdP44/O1KGyS1GfEzx9feRPbOuv8IpvZXh1D+YGbZ8bipnFg38ClrUic/iEvPbluZ
         DrRb3rMK8KSIJPQ7FYqQiuQ95BPig/hEo1r8cP2+2idjf5N/R0h5CDYF1rk8KC+7TkBM
         NN+MlFU04OiGCY4fm3kSP6lpST4dCEUQRwkd1qDTWQzVzvMvkp63D4LIr95TYoMqGOjq
         X7hwYDolPFR+ytpxP/9YcY2pQdeVtPFnOzHQcuKu5mobvIkxYm8fCBkcjUKfY1fhdYdC
         K0IH36g480/CcfU7SfBbgPEhi/21PZ/fH0Ed1H2DQ7nsMlUJYCHhYGt1QSChrruUlQpm
         OEPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=VhSsU/SLeLzEnVf5kpnednHntS9nzniNjISIDr5lY/c=;
        b=pGWNrrXwKjANdck8dMNzMO4qnmayu8qivBH7t8B0vsbVp+qFz+Tn5MvhC1ia9DaT0D
         SOLI05ih07cl85dh7fr6uGd/kT1BT9ox8i+hgWAZCMV1G9N7ZPC89xUFsfRsqXQ8jnWI
         M7FXMP9PSYNU1YSheUUcfS4FeGg4jZJ+1SN9Z8n43GsOgBgIo7G3fAb0QfbzhsD0MdTZ
         S/YRnDrFcmS/7Q/v89v61uW2Vo+kQwZ2pDgr+4WwdPUw8OXfr5ekWI3rt555dpiUTOgX
         5Lj4ugvWuHhHWqV0JfvGrtAggZzKddJbO0Vl/Z5CBEKi0+IFLoUp6yByjgcmeZLaJvYK
         uVFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=psU325Bc;
       spf=pass (google.com: domain of 3kuiiywykctetyvqretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3KuIIYwYKCTETYVQReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=VhSsU/SLeLzEnVf5kpnednHntS9nzniNjISIDr5lY/c=;
        b=hMsI0jXXPQp/erOGNsKP5aL8xfpVc/HGZQPwKibHThU2Qj5Wzjrn9IhhOG8PGTr4Nt
         prnbYXhqCSe++k1dCHr2z59Nqa7ZgAspeNOexS/zsajSiDF96qfWvIwpmY0lixb4TACX
         gIyIEXwML7gcYXH8I7BYdpNOuBwBDdzIiNDX6E3wC2gyVSeMBn7SMq8Ma4b3HGgKBbFN
         7C048y5nKK3XdNMhyhsIDeuWyy+zzbwmcoYRdZ6+JH0hk4pxp1sHoGLhA4jD5Xpa2E4j
         E2XAUzZmkRuHe887zfCKe2cjeNNPTYBllunJiFK8quQtk0UVRfJ7RbaG5jHNtJlpN5eG
         7nFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=VhSsU/SLeLzEnVf5kpnednHntS9nzniNjISIDr5lY/c=;
        b=H9mNimBocdKAFi5gd7ahoGguhugpbPw6pxP2/QlqZh3Nr72cEPx858Dqpr1mqx/ngz
         AnPk3tzg0O2peubhWgnTxw0iWROfjCtwNPb/wXUeO1IzcOJ9UFWKE8G6fIVWsNCex77H
         4liSQjKIqQJNw0cJ7AY29e2rThJHRgdL5CSADOXMPAE66sK50HLrnx9eznc+6oLe2eYv
         4tMvhiFBaGtTNeVmjtiEUDdFANJTv3ty8Nh4tFa8OfgemFMdiwmYk3bCBMICLt/QNOsx
         WlRpx8VHEJk7jBcoowVMMg44davjGEcpSvvaQ4CsLkMyRxma87sWirCJ50de6qH10S9b
         tJtQ==
X-Gm-Message-State: ACgBeo0JhXmpFP5qOk04FbSbJAQy3jNI4fPA/avFWnCj+d/MZXGP/tPa
	ZGlnZR/9Ke4pqoTSvqPzMNs=
X-Google-Smtp-Source: AA6agR6ZrtReNm12o+aRhGiwE5zYrP65oOByb8makg61/RQhr4imRu65UkaOl2Kfh+Wa/dpWfS/scA==
X-Received: by 2002:a05:6512:ac9:b0:492:d800:713e with SMTP id n9-20020a0565120ac900b00492d800713emr2707275lfu.486.1661526572457;
        Fri, 26 Aug 2022 08:09:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f53:0:b0:48a:f49f:61c4 with SMTP id 19-20020ac25f53000000b0048af49f61c4ls1132344lfz.2.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:09:31 -0700 (PDT)
X-Received: by 2002:a19:5e02:0:b0:48b:1870:dc4 with SMTP id s2-20020a195e02000000b0048b18700dc4mr2867444lfb.4.1661526571193;
        Fri, 26 Aug 2022 08:09:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526571; cv=none;
        d=google.com; s=arc-20160816;
        b=cMgX2owK+GgPSNwZMYP1oAyABjInweqZ3aGrdjYThRu1FwwWTtV2x0tz12txtlHVaY
         brX6EAQ+UagB2FSnkG0iqfL2TEbSCrVqWG5h6TpZXbirFcHetwspAN7PmQFsPFodjp4z
         WREQ7cyJxFe/YoBy/rb6T4UYrp5V9+C+CCIgs16bh/WnacKX6YxLBd8WLjNDGrB2GkzH
         JU0wTnWODYgQxeO0XlIutZkOs72XYOjWAbvOnfnM5NR5T4+n/XYq7N+2bXxvI+M/zJ19
         PELs/5XCbdRr6fu1GWW/ya0mKipEbh6OamUUJY2GDCOsGdMDiZBGwvBca4uq5i10Msjv
         ZEFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=+5QrT5xfdlDeiLaqkJXiB84dUzsqj5PxvneJHk/QPSg=;
        b=yxRVZZ83VoWS7AzUyxLb+1uZea1fSLwt3oxgCBkACpPLXX3SymhfK9MhBTwa9YXgiq
         gToxZWd6yAlv0mS5ehNqyCrrszvda4XLXIgZIMccm2QS1egjNXW3fgnMWXpyttJfYs8X
         M3s9H1zp/HYQp2fT3lPakDWB+NxVtvWxL+RSfsa4MQzkHD1K4xJnrNZ6YLaYi8bnEsrr
         3o/RS6Zn/us+qTz/cs6UU1vdk3vQtN82JSEtVo5Xks2w1ZIKoQPNIvRtV1TVqh4M3xXC
         vilAHoaP/aG8astdnrizgBbQSeun1JFANSh8jXav3Kowjpm57jpp00zu6CUMCFG+WGiu
         5kMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=psU325Bc;
       spf=pass (google.com: domain of 3kuiiywykctetyvqretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3KuIIYwYKCTETYVQReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id p5-20020a2eb985000000b0025e5351aa9bsi74196ljp.7.2022.08.26.08.09.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kuiiywykctetyvqretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id q32-20020a05640224a000b004462f105fa9so1239569eda.4
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:31 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6402:496:b0:443:a5f5:d3b with SMTP id
 k22-20020a056402049600b00443a5f50d3bmr7388597edv.331.1661526570674; Fri, 26
 Aug 2022 08:09:30 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:51 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-29-glider@google.com>
Subject: [PATCH v5 28/44] kmsan: disable physical page merging in biovec
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
 header.i=@google.com header.s=20210112 header.b=psU325Bc;       spf=pass
 (google.com: domain of 3kuiiywykctetyvqretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3KuIIYwYKCTETYVQReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--glider.bounces.google.com;
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

KMSAN metadata for adjacent physical pages may not be adjacent,
therefore accessing such pages together may lead to metadata
corruption.
We disable merging pages in biovec to prevent such corruptions.

Signed-off-by: Alexander Potapenko <glider@google.com>
---

Link: https://linux-review.googlesource.com/id/Iece16041be5ee47904fbc98121b105e5be5fea5c
---
 block/blk.h | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/block/blk.h b/block/blk.h
index d7142c4d2fefb..af02b93c1dba5 100644
--- a/block/blk.h
+++ b/block/blk.h
@@ -88,6 +88,13 @@ static inline bool biovec_phys_mergeable(struct request_queue *q,
 	phys_addr_t addr1 = page_to_phys(vec1->bv_page) + vec1->bv_offset;
 	phys_addr_t addr2 = page_to_phys(vec2->bv_page) + vec2->bv_offset;
 
+	/*
+	 * Merging adjacent physical pages may not work correctly under KMSAN
+	 * if their metadata pages aren't adjacent. Just disable merging.
+	 */
+	if (IS_ENABLED(CONFIG_KMSAN))
+		return false;
+
 	if (addr1 + vec1->bv_len != addr2)
 		return false;
 	if (xen_domain() && !xen_biovec_phys_mergeable(vec1, vec2->bv_page))
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-29-glider%40google.com.
