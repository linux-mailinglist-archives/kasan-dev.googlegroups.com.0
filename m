Return-Path: <kasan-dev+bncBCCMH5WKTMGRB6EG7SKQMGQE57F3QSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 143F0563513
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:23:53 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id h125-20020a1c2183000000b003a0374f1eb8sf3101459wmh.8
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:23:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685432; cv=pass;
        d=google.com; s=arc-20160816;
        b=LiDyfd/6nFazoB5+FiLLI6TXF6OLOMQKbWEnU27FDqzX4+h6ajEXGiZV2ntkjPwYc8
         dNZzTf7vRs9Wgk971Glp76FJP281TM4DfniojgE31u43jEc97hRS/j3c8pesWNImsoIG
         iPi+7dAg+IQmcl1KGM8e2RBVLVgGualdvYumHOOBAb1E/JCjiV5cRteuss+0kGNsmaxN
         EfeI05ne3die3JiEGs24+yffShpnbkV0ZUZXS7HnLbbe3MruKQYIrc5hDKkkhCT4J4ln
         zgVvPHKcUhmKemACl3CahmNF/pYzRtgatqybKJcZ6sRpzyhPxclGpu9spILq9GR1JgDh
         28QQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=jtty4Z4dq1TbrhSJAdKMf1Z6jeRveFkjAm+qG60lj8Y=;
        b=oJd14j1Nj0fquvWKjBd+if9IkXZR4EhuEhENW5IfuddzgNgsQ+ctTUS5cl7f7nnZzp
         grtm17RZuL7pSwrhTIk8gPV2GWti2cntFebS9NC7PBXt2tlVQfFCt9DMv/u7OJg8wIhp
         neqUwqcIEW72LMN6N/5f4zNEzX7lW9mHC1R+TBMvekdOD8gmno9onKNxKXTKnnWIAz4n
         LbNn2CvPxwOJ9nJHIPoWqLxOtHaAoOiWG09I2G5HeUP3TZC/nNDHD/v796TRA7C1Hzxl
         rFSR5LLaN1bGhpRoJjowUFC9MrPs8+BFyIdcyRVETOPrt21d0CjPmLePsJVz0E5u5Xw4
         1jsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=At0kpR+7;
       spf=pass (google.com: domain of 3dwo_ygykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3dwO_YgYKCZY6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jtty4Z4dq1TbrhSJAdKMf1Z6jeRveFkjAm+qG60lj8Y=;
        b=TFUkXk3rB1pdxZPmcH3CZC1DEvh7SdP7H5Jeb1SlRReWL4LytgO7IdUictaL1h58zi
         we2XEWUB8eKE2UlE02M7WSBjGPZPKE+/9ARow7E1nXfvKd/9b/eiPHUT4/BebvJGahNM
         HugH34sRl0msdPe0JYfa4s3uV6Rc+UykKcy0mkJln8mXutNfdX2Sh4a31yolmoq06S7Q
         YKRKIv3ExD1ukqhY/Oim7qnB2CmTzzuNwZvl8jMVha4J1VVXN2X87fd1rendocPy6iwN
         qD4m0Ft0LinBj9908y/KnUJMCktu3pnDqzTaB5jjJR1qGKNsgE28z16TICI6BCRx89VH
         krUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jtty4Z4dq1TbrhSJAdKMf1Z6jeRveFkjAm+qG60lj8Y=;
        b=o1XKhef0PhW6wVrTfzvfcC1qbQfsFbDdTyIgl/kPdoC2KDU9bpUiVYY95gmNwJunRs
         9l0QBkdyIkQrbK/fuJ3hL0GYEbx+mFeibF0/DvyVodlvo0U3OsC5Vf9IqEsLf4WVzBU5
         X21R7vqMyR781iP1hFHyotlVavV0goCg3GyDu/kcp1QAMfBJgb80ga8StBF7D4Shgfyl
         TYfvIOt96fPK3AHt+SPzP1li+g7p3T5jNnN9452uZ0AhpvMRD0Js45zJTLM1KQ/EoiG1
         7QVMJf4OgT+zRopFoGODwhq1g9P0xWMUSQny3IyJmm57jBlfmpIGsw4Te4Av1bq6jS+Z
         3WDA==
X-Gm-Message-State: AJIora85FaWdPaOrL5aklucv/YWNBJgkWKmvxW84lzxg4RZBJ5E2OhK/
	bD2eob1PYYrETngXeHeONVk=
X-Google-Smtp-Source: AGRyM1tTWkYzREOf2vDeAKcKZtXx9hEIBpKALmge/xzvZK9bxeqDqymO33tcn5BVu5qiv1QpIQUlsA==
X-Received: by 2002:adf:dc91:0:b0:21b:89bc:9d5c with SMTP id r17-20020adfdc91000000b0021b89bc9d5cmr14176171wrj.159.1656685432803;
        Fri, 01 Jul 2022 07:23:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:178b:b0:21d:350e:23a6 with SMTP id
 e11-20020a056000178b00b0021d350e23a6ls9194816wrg.2.gmail; Fri, 01 Jul 2022
 07:23:52 -0700 (PDT)
X-Received: by 2002:a05:6000:1acf:b0:21d:1067:a1df with SMTP id i15-20020a0560001acf00b0021d1067a1dfmr14415567wry.198.1656685431976;
        Fri, 01 Jul 2022 07:23:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685431; cv=none;
        d=google.com; s=arc-20160816;
        b=jrEul3bYn3eHGMwixNhRfF6ce/glde9oIntjUTm6+EB+1+ASqtugTgl9nZ/FbwMLNE
         FEbZTnVQsUxeWkSFQPMJqSuPbBUXCy/+4VwGqdLcXk3NXpVhr5yJWJ9Sqh+zNOq1kGUw
         GenoZ9zah8/ox6a8ZF4rdnt7cnQC0Z2SPeQutifqqXECLQAdGTsiHg+2diUV4KXo1b3t
         p6nl9BNVLWA4Osx2/fCF5sgzDAyqLlUaEz0j/KNKl63MEM3KPuNCPsf1tFQLtt1/BAVV
         pNi8oobEZP1APEFVeUvzfkdDRxHYYORTIW3VKTjJMZ+p8u5m2PQdr4t7zMNf1SdhJSDj
         +EFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=PCXlNDV7asGuiYne5zMLVF95C5LbNPo0tZu8h92qf24=;
        b=bBR3p+p/U0Hf5ja4TC4nVZ9t1bXq6hTIZvkMkQ9sOIWnOVq2xOKAK3f3jC6hQwjI9M
         Rnto2VMjFv1SdOijp3Lct5PO12EmaG4EjKsMvekZ7vPxyKe2H4aQF373dhobzBhGEXai
         SgZWL6hkFOsaZxJH7chu4dp1n6ht6RD2iwovUs0d1MqAENyQLlzYuH4QehNLY6RQd6i4
         eIEZtiYiHHqyDgXx0iz1JFQVK/Pp4sYdzIlowaXJ70CcGlIDodA0QHja6rQ0ZS7CoS/P
         nM7Xq7laPF6hzzGw5194DyqX/5L2KvFadeE19H+pKu8wueVDe6+LMwA65WZvM+3C97g+
         t3wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=At0kpR+7;
       spf=pass (google.com: domain of 3dwo_ygykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3dwO_YgYKCZY6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id az15-20020a05600c600f00b0039c903985c6si215368wmb.2.2022.07.01.07.23.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:23:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dwo_ygykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id nb10-20020a1709071c8a00b006e8f89863ceso837597ejc.18
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:23:51 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a17:906:c781:b0:726:c967:8d1b with SMTP id
 cw1-20020a170906c78100b00726c9678d1bmr14665371ejb.54.1656685431730; Fri, 01
 Jul 2022 07:23:51 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:38 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-14-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 13/45] MAINTAINERS: add entry for KMSAN
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
 header.i=@google.com header.s=20210112 header.b=At0kpR+7;       spf=pass
 (google.com: domain of 3dwo_ygykczy6b834h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3dwO_YgYKCZY6B834H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--glider.bounces.google.com;
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

Add entry for KMSAN maintainers/reviewers.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/Ic5836c2bceb6b63f71a60d3327d18af3aa3dab77
---
 MAINTAINERS | 12 ++++++++++++
 1 file changed, 12 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index fe5daf1415013..f56281df30284 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -11106,6 +11106,18 @@ F:	kernel/kmod.c
 F:	lib/test_kmod.c
 F:	tools/testing/selftests/kmod/
 
+KMSAN
+M:	Alexander Potapenko <glider@google.com>
+R:	Marco Elver <elver@google.com>
+R:	Dmitry Vyukov <dvyukov@google.com>
+L:	kasan-dev@googlegroups.com
+S:	Maintained
+F:	Documentation/dev-tools/kmsan.rst
+F:	include/linux/kmsan*.h
+F:	lib/Kconfig.kmsan
+F:	mm/kmsan/
+F:	scripts/Makefile.kmsan
+
 KPROBES
 M:	Naveen N. Rao <naveen.n.rao@linux.ibm.com>
 M:	Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-14-glider%40google.com.
