Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPWV26MAMGQEMU6TSPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E1355AD259
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:35 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id g19-20020a056512119300b00492d83ae1d5sf1852751lfr.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380735; cv=pass;
        d=google.com; s=arc-20160816;
        b=uMFYTMsNjmwGxS1QwGV6BesgmD+zIgZrRDf3Bn/87o96hXB/5ZVwmkzaxv60vtQA70
         7QzRBnAwBT2OE8I37hB7kW5tL2pP+gGMl3igb5s4YarYOcbkKMRnaCvfejwlmKTY/jfd
         UevQUBMq5M31Z+9JA0JFQxstYfgAzf1fI+/aWUzG5McQYbgKzc5BEuGZ48dSxN54IFP8
         qxME0ai6BsQr72WTwQd0z443T9HYJQEx+2boVFhFvXPRzAAzS634f6z2oJQILdlO40EH
         0NfjDARi25FaJZ5zVfU15QZyAX+KLTqkmmZ6zmfqp42FJyZQyVsJ2aJgqxIeJaTrXcsB
         BWWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=OmRIr5AdnQx6q0Mci2BBaptd+Offn54xWO/JDeQ0brY=;
        b=Iz4fWRBh/TSUwzMgWM/5n4oLBe/x909kRrhWsu/8SbRmqv8ScqPTFB6vu6tO2vPXQq
         w8/sQnODFzkv0ds63ga8+WOx7Gq5l7q7DPq8jY7it9COjslJCb2TKlFlGCf8Gn+IfCLx
         kQaQ9+mdEk/vt7BO6YTDlv5DexHXnnY4BMyRw7aE0RSN+zhtC8roPMgEDLZg3piz2fr2
         uU/sPHHxLs3/VyxPUEEvl0SK0j9XtVw7oVoe7tUCvobZWvRyPRBYlOPEYpe1baONMiZL
         RBDQkbpGcg3b5RcYKEuXAM3D0XZWqf6Z8TM4uBzerMdY9vf9u/xEmoUP90OIQYofCDhw
         2lsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KmmCnyB0;
       spf=pass (google.com: domain of 3veovywykcqoqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3veoVYwYKCQoqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=OmRIr5AdnQx6q0Mci2BBaptd+Offn54xWO/JDeQ0brY=;
        b=Ft6MtxJEa9FwCTH8dE+3Y2zelGOqrX7fsCc5A1vd2TF990SJI5JsQjtz2G0Rp0Yeig
         soXBlO1JDwf8DgP6+CAF74an1kME7zcSuqvqfPUOvNBVIbb0fMrd5TMISQayZUulbfSh
         ABH0iBs6D1k1CwIZ2AaTw67SgB3Stwvar6KLXsKp6ATx4z52pfuiP3rssUqJsB3fa2XM
         WInUigu1Zv+iGzlCiMe0VUdcdgIKidSq9qxGQ2xlmxQyoWVInx2SPkXE0ZGzoww1+Z1P
         8I/cag7em6lwY+31FfQCTGwYa3a8wLfAkqZ+hyZ6dIi0JPJhKA0Zpzylx+N1jx8uewwB
         CvkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=OmRIr5AdnQx6q0Mci2BBaptd+Offn54xWO/JDeQ0brY=;
        b=SKPeBYmZOxiV6yn0pHRu1hG5Zp1zMbWV7+wKvIovMEMkPYxYSL6yNA9rX/2g/IuYJW
         0uyKUSLxeyTnZ1OQuH/Uhh/h7z7mOfjy3DuFvvYXg4f261QBSfR+DVv0yUsy1pyE85jr
         feyX39OYZofJjREwDNjW84Ih6NzRtTl3PSDgjQUQyQ/QJGY0H0soYvhxZ5FQM31ZI9dv
         MwxJh6Fm2jNI1BZK+zL6+EfCoR1Vm6oj3XRkEm+d+Yfk0jSQuHIkm8I6cfSwcP9dKVKj
         spX97A0H++49it6A8C1WEMHv3dVK3BMVAxEjc7/pFCkrBuu/6VKUuErnRuS5CizbvkSA
         F7vQ==
X-Gm-Message-State: ACgBeo2Y+cZWo5appSwyBvJlgR2BDetQ/HX0DmvekxOhbcBAOI5o4Jsa
	+RW733ctcfeMvlBq7UE7xYo=
X-Google-Smtp-Source: AA6agR4zR94GvzE461cAaxPy4WWaDWGzBWHaZo41IN+XX/A1lKx5Phn1Sr1ht5NO6dxS7ExrteNltA==
X-Received: by 2002:a05:6512:159a:b0:492:d0c8:aec1 with SMTP id bp26-20020a056512159a00b00492d0c8aec1mr17804414lfb.275.1662380735175;
        Mon, 05 Sep 2022 05:25:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc19:0:b0:268:a975:d226 with SMTP id b25-20020a2ebc19000000b00268a975d226ls1563723ljf.7.-pod-prod-gmail;
 Mon, 05 Sep 2022 05:25:33 -0700 (PDT)
X-Received: by 2002:a2e:92cf:0:b0:25d:d87b:1af6 with SMTP id k15-20020a2e92cf000000b0025dd87b1af6mr14709801ljh.474.1662380733567;
        Mon, 05 Sep 2022 05:25:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380733; cv=none;
        d=google.com; s=arc-20160816;
        b=oYohL1Hl5WfoFjSjmv5bQLF382IGh+Th1KgK3auhWWmAFUi+yXZq9pYjYCKnmoafOu
         6q0MLOExfUTwxqb+BRGHbDgg8PD8Lxg8ainvlxdM5O5ArtahBkrWyo/VhduJsG4oStka
         1rRDx18pdmTVfzfexsmCtYp7YEe2NBXm1WBv1xoFMhOm3rkuNPP4TImBMXRYBIFOAJcW
         8V4zDeLA3kVT0VEL0Y0vL5Drrat/QyAT1bRkhHHQK5fvJle3ZmiAvvM6+9YRVfIsn7Bh
         8dop6NosJtJfiFqbUD5oojVvIGIos8T8hgoHYlqys6cZtuOkOvjCQivPACGbUkTQJirK
         tKlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=TshE4y0aie2V6V2+uLUqxx2CJ+sNpnEg6whn5GrSFP8=;
        b=GL4rU4VU09bwKn0U+slVS7Z6MOtIGEmgQedFrl6yT57IK2tkI+6rRO51jDJDIj2X8q
         QWM4FMea7M9H7z2Bu43CXd1Wbk7EOp7c4MTYplCr1JnHEMf41YgfkzP2ata5qk1NFY1I
         uemM2UR2OWeANqJ2GmsBzLnvd73vDETU8jbEjvK2WyR9FfMj8tSJx8EVp2ikzoroo54s
         hVWQ7/nL8xTiRBHCZBMeGkZb2rblfhEorp51bEd62gCJyxXOgrMBtHm2Mb4qQ4mO1ujo
         VHh+Lf75Uo5fcl+Yhp+YwUYj9aNXCYoYc423H13hply9zY6RSwZ6nllyq+TDqrRh7J7e
         wGiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KmmCnyB0;
       spf=pass (google.com: domain of 3veovywykcqoqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3veoVYwYKCQoqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id x20-20020a056512079400b00492ea683e72si345650lfr.2.2022.09.05.05.25.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3veovywykcqoqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id y14-20020a056402440e00b0044301c7ccd9so5696495eda.19
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:33 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:aa7:d0c7:0:b0:44d:f0ed:75b8 with SMTP id
 u7-20020aa7d0c7000000b0044df0ed75b8mr6971238edo.50.1662380733016; Mon, 05 Sep
 2022 05:25:33 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:21 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-14-glider@google.com>
Subject: [PATCH v6 13/44] MAINTAINERS: add entry for KMSAN
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
 header.i=@google.com header.s=20210112 header.b=KmmCnyB0;       spf=pass
 (google.com: domain of 3veovywykcqoqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3veoVYwYKCQoqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com;
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

v5:
 -- add arch/*/include/asm/kmsan.h

Link: https://linux-review.googlesource.com/id/Ic5836c2bceb6b63f71a60d3327d18af3aa3dab77
---
 MAINTAINERS | 13 +++++++++++++
 1 file changed, 13 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index d30f26e07cd39..9332b99371c5b 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -11373,6 +11373,19 @@ F:	kernel/kmod.c
 F:	lib/test_kmod.c
 F:	tools/testing/selftests/kmod/
 
+KMSAN
+M:	Alexander Potapenko <glider@google.com>
+R:	Marco Elver <elver@google.com>
+R:	Dmitry Vyukov <dvyukov@google.com>
+L:	kasan-dev@googlegroups.com
+S:	Maintained
+F:	Documentation/dev-tools/kmsan.rst
+F:	arch/*/include/asm/kmsan.h
+F:	include/linux/kmsan*.h
+F:	lib/Kconfig.kmsan
+F:	mm/kmsan/
+F:	scripts/Makefile.kmsan
+
 KPROBES
 M:	Naveen N. Rao <naveen.n.rao@linux.ibm.com>
 M:	Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-14-glider%40google.com.
