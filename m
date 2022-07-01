Return-Path: <kasan-dev+bncBCCMH5WKTMGRBI4H7SKQMGQEY3OHHYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EA4A563530
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:36 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id h18-20020a056512055200b004810d1b257asf1183102lfl.13
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685475; cv=pass;
        d=google.com; s=arc-20160816;
        b=gp7CPLaB8Q5czY/Xxl3BsTH48EVq+EfFvXfMR5dHiQbp5k3PF9baoclHS5X002BiSI
         cfJ1h+7sPptB+/xRa33noZTuMl/sZ3QDlIBpZa00zkJnnpapKF+9ANbpr3v0r+zxU6vT
         HuH31J39ujXzoMrdKOWhvLE4YThwfY2v0C6nezSgP0uIRUOR0rA61zJ43po1CPOLzeco
         WE/7/5o3e7mZPWvqeiBvQBVWUbL4Is8erH6HohtUdwsm12iXqpbMnfHaw0VPL+MCoqro
         Ac4UpawPh2pir5u4W2vRy5f235rO3qSK6eE7UYFu6ytTTBwyQ7tt2gY81hg7UfE2DmID
         lXRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ePWxvZc2Sc3BwXuPa9GqohQr0n44UVXiRskAaMUcZNE=;
        b=epOOg0HwFnwq1CV1OtQ2Vyo16JElOi/N/PFnd/uVVm09hYZE2aTXsClDRiXpyN81PU
         TodwccsoDedF9d6VJfrhSQTZPXSIqvHJixpZXKEkOvsnmmB08H+4Dg7yuQntQ4Klc7+u
         qnhCm84XG3xfE5uAqM4iiTGnNMs2UTKj2Ft8bh88/+a4ZdomhuIG+j+KD6l5CV2jkxsC
         pRWSa6IaLVm/PqTB10ZHEOrvCbYU0zSRC64ejMUAu2ilo6oVBgWwTfmru+9Jc3QXiP/c
         VcGldgJvygB3xt6bvXwjNbRwsvE00RKfvjLbnLRuD4iCbE3TQiPnbGMhjCoG2K15Uraf
         sMNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fBpJ5slq;
       spf=pass (google.com: domain of 3oqo_ygykccamrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3oQO_YgYKCcAmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ePWxvZc2Sc3BwXuPa9GqohQr0n44UVXiRskAaMUcZNE=;
        b=Xjcck9hmHhFykcmxD1xW4EDYvMb684b3mnrL6n6jbsmq1BW3T6Qg4sygPYiSX5Nv+G
         mk16k0WukyjQXnNgLiTzJxcp7TF/6BATNsMGmCOKZAJ7jAcXsTLbm4uUr/SFz40MQvH5
         0OGnJ+nlaVPDB0311jRp6WjqlNweAgxvpBjDh6e7nsGOE7OkCBsRTN5p0L+fDQme3NNx
         sbCkgZxvlQJWbH/0abSVlz5wRzEmNVZg33GsqpObXB/pg4xO6XZDWMauCT6Vbsn0GnlI
         AoIL7pUg5a+MzHd04d3+xMCBrbGfd4Ji0dKUwD+1eDMOAVy3geZA7WNsS9oxDj5+ZKjb
         84gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ePWxvZc2Sc3BwXuPa9GqohQr0n44UVXiRskAaMUcZNE=;
        b=TMW9O/RI+K162LVh/J56b/yVg9DFr0+G+ifVAN/CIHJYGAhTbGl26adVdyJ0py6hK7
         34e/JLIvASPBgGLc2xiH05ZotHutjLcTVsuuTEYR7E/Oy6i7OLFU+l3NE82lnEyUTTPH
         vRDkW44uk+Ab2kbx790kOF9yE0f9Nv+kY9YLGxvq8CSK+ZPtzpejR0neSUV9XDd2IQ+n
         ctKHuNU7Vzn5kY6KHeEnTp9/QVk3B10hPUCtVi1glchpj+EwEtKdMGWCz/U3qxCJb3Wi
         4XPCvQhMfks2jJ4F0Iru30KsWrkp+6ny0GAWbNPm6zr2UQMDcEWej1WZDrjn+YV9rpw4
         ahTQ==
X-Gm-Message-State: AJIora/+jUQgDm4EX3n/cWEFH158kfRfqSO6k1K3hqlGOiEM51eHdhGD
	PkTIq89grzdURslam52HJkc=
X-Google-Smtp-Source: AGRyM1sK8czqSrNVx7kIN7GGil7K9SIUoezdPtXQUs8HpqxZYCqzYpuEjtMVar1Vx+YoBEKAHB3nWw==
X-Received: by 2002:a05:6512:2385:b0:481:aa3:181c with SMTP id c5-20020a056512238500b004810aa3181cmr10104174lfv.195.1656685475639;
        Fri, 01 Jul 2022 07:24:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9c41:0:b0:25a:993f:5820 with SMTP id t1-20020a2e9c41000000b0025a993f5820ls3955044ljj.4.gmail;
 Fri, 01 Jul 2022 07:24:34 -0700 (PDT)
X-Received: by 2002:a2e:8910:0:b0:25a:7eda:e4df with SMTP id d16-20020a2e8910000000b0025a7edae4dfmr8343388lji.316.1656685474245;
        Fri, 01 Jul 2022 07:24:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685474; cv=none;
        d=google.com; s=arc-20160816;
        b=xqBPgSiqmKosWjlmNOg7OjcLaFwuYySfi89/ry5GAY6twWup5tE5GDeXaIEMXy+Soc
         WpHDMauDAZ0dcjpfKVOLPRejAM+Qm0c6KFDLB1LkBrvEo9ggXj9N/ra6N/DQDaJ/sCOy
         S4Olb61Yv1+B9XTyuyb30bYux2ecjrzRm/5eJE822tTrjs8zgLcb/W2kqDc6BiWfjvH8
         gGZo5xGv1IwyLtBGqVGb8N/4UQ3W9AA7eTfCPQpkZE8TxgVopyYKADPtDnFoUwLwJ+hx
         v+Exv9BUENFZjLW8wYJgQ+fdjbjX9dGyeSrVP9u18+9TZgVew0R1Q2CsUpUNB+5Jd4tT
         Fxbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=tSPSuwfCBJYINsR4GH3IgbP5patOgmYnzcC5xbF5jrk=;
        b=dx6Rrniz4Y2E42yP3N6jo69aLPQ0PD3IQUi3UyByR033Oxd4HrROkmPn5dnFLOfSJh
         v+yhdfuDO5zMWUuvr6M8mxZWXzfsvnRn3iPheGFR3ec4JrVHuGnquY1TvO2KjtSVwa7F
         RukZZpMXzT/gOhsEdywbyNl9xigQqNzFFSdjnlJrZ1Xpoq0NVm7gHA2FCIHvAph3kJK+
         lIZDAM8GMWnp9sAdtmYPFWUK02rbkSkjhFaSs1yumV8r01ygvQb8FrxGCJh3E8O8x9YX
         flSSo6pjT0MjssxawQSok8qwS+yTtk0wukp4VaW7jWk2ASW4QApgYa29PM+T89kTh2uM
         j9yA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fBpJ5slq;
       spf=pass (google.com: domain of 3oqo_ygykccamrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3oQO_YgYKCcAmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id m7-20020a2e9107000000b0025594e68748si982234ljg.4.2022.07.01.07.24.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3oqo_ygykccamrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id r12-20020a05640251cc00b00435afb01d7fso1871418edd.18
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:34 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:1f15:b0:435:8a5a:e69c with SMTP id
 b21-20020a0564021f1500b004358a5ae69cmr19068159edb.90.1656685473944; Fri, 01
 Jul 2022 07:24:33 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:53 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-29-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 28/45] kmsan: disable physical page merging in biovec
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
 header.i=@google.com header.s=20210112 header.b=fBpJ5slq;       spf=pass
 (google.com: domain of 3oqo_ygykccamrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3oQO_YgYKCcAmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
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
index 434017701403f..96309a98a60e3 100644
--- a/block/blk.h
+++ b/block/blk.h
@@ -93,6 +93,13 @@ static inline bool biovec_phys_mergeable(struct request_queue *q,
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-29-glider%40google.com.
