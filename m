Return-Path: <kasan-dev+bncBCCMH5WKTMGRBL6EUOMAMGQEFRBUUJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 62FE05A2A87
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:36 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id k13-20020a2ea28d000000b00261d461fad4sf661321lja.23
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526576; cv=pass;
        d=google.com; s=arc-20160816;
        b=OYqxJjlmg1kXfFwccScC1d19Z4Ba2J/RHKycNP6eCb+bXfCB5SdsRuY2/M4ZC33+qA
         Edegapqx490pBmnb8WaD+emB2CVjSWwJpFNXC0h7uwUww/FWySSJN2wl2mayLR4DJx9P
         1o9RoHhzKcSZ5iuxm7HmGTm5bLbL7e0zoylTWBRYkKTt+0JI1hEIwdqQ/ueoOz/uaxaT
         rzOBuwe92k36cOUrIWYbgyDzWjM1fLV/SLTMqCkBp/5JM+9NzGmbqpWh/0OFphYwRIHP
         c77j4WzlLEU30JBT1vR5l4TB5wrJ8uSxr7Rthmk7rgMMg/ubvcn1XLUqd8M/Bh9jvMec
         tBaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=7ypPG6sffpkRMfBqv7q17dSYJegVgazM+tZ9aLixdZI=;
        b=oNozb5o4aH9s7H0H5IcDjdTE2yD5upGIjDOd1V+T8nHWntE/hoYLIjJyP8Qzived6M
         RfXFvUZ+cRnlYsiQAYrX5C6hV/MkMVXPus/5lUx8RnP2Bbit2UiwidyjJiQdDg0qo6XD
         Gc1b5dH+VsNCE/dkHnLtYP6k+Ek4MD7z6upYsn59uavTt78/0PNrv4B+8MhMZ4K51brU
         lOVOLHaiVmPudWoxNNuHlU+7OLvoq5zGaNJ0n/bQGoTFMHmTztk+vBLvGTruAk7drxPf
         GFe+MO+nxgRTg9jLXlSdhnFQ5MRx55uet9SPFmgD/HW3K1f8Ogophp/IHLUvj8BgBYJJ
         jomA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qQ2U4pH+;
       spf=pass (google.com: domain of 3leiiywykctqwbytuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3LeIIYwYKCTQWbYTUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=7ypPG6sffpkRMfBqv7q17dSYJegVgazM+tZ9aLixdZI=;
        b=oGUmmZVlvUsTZiIXUrtF5vA4whRu4xDTWPCzaAkRftcDMHeRar2OlHexSi9ldE+FLo
         wVLQznRNENrRan1HQDcRlmBXJndexsSCrd72gBp6i1nZ0FuZ7IKSjrZVDhMglMl/t7ZJ
         0X437T52Bwmg/RvhlLPvjf9ojCHrN+4N3JO2EsIEUB4exqrkk+ZbbXreKH8z7seHfZwi
         n617Mk6EX1JA0D+fsSIvTPc92yehhgskFRoizPJS+NFT3hXz1JnwRqgnSVdBw6XorY2g
         XjFjOrIOtMw5vn3fS3ehaKzbD+JIPSKMCkVKau2Zfj1kMhN9+xofRRPs5GbPRAIv1ts4
         Oj1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=7ypPG6sffpkRMfBqv7q17dSYJegVgazM+tZ9aLixdZI=;
        b=y24KJO++KaWhj4uQKhR8mlx7wwIlRo0UFdsLQOXGxKEqc4Z1w1Pcu8+pAOp0YQKwSE
         nO/DMIDcavbgqduTvqMp5Z/1eFIj73s+s48JobiizVa2qqKCdXvRhCHc41LuRMDB5Ojt
         HpdfHqqUVc+/NI+FcR+iMqT09KuXv9E56maud1lq49jPiuGRNe1XYPkqPENIcQ8V3N4a
         OocZNn7EzZHgUQjNq42+4/12bugAJ4kUd5tPcC56TSwurZKgBO9pp/+43fs2K4+8kiIZ
         yes6P4uXdcyaJSxhZYRWOps2WEFd2JlzKrwdjXH36g27cVTt+ILfexDWvHNZFZO4bj9h
         GODg==
X-Gm-Message-State: ACgBeo3A5awsqGIRyzzK/beEWs1ZSMpkiJVRZeMmiPea3ltRH12QdqET
	m+jg7KFnDzxMZsuhl4kHKaY=
X-Google-Smtp-Source: AA6agR4ZYMPjRFQwTsUbl68WzjLWeFjHeN/iAyoPxXn5ayiVv9sryZu05b0UfRv5xN6SHII73zBKfA==
X-Received: by 2002:a2e:a808:0:b0:25f:f326:f2ab with SMTP id l8-20020a2ea808000000b0025ff326f2abmr2663541ljq.152.1661526575895;
        Fri, 26 Aug 2022 08:09:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f53:0:b0:48a:f49f:61c4 with SMTP id 19-20020ac25f53000000b0048af49f61c4ls1133287lfz.2.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:09:34 -0700 (PDT)
X-Received: by 2002:a05:6512:200d:b0:492:c4d1:b4bb with SMTP id a13-20020a056512200d00b00492c4d1b4bbmr2799071lfb.316.1661526574014;
        Fri, 26 Aug 2022 08:09:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526574; cv=none;
        d=google.com; s=arc-20160816;
        b=cArvTROtuVz+OR2QaNx1o8a09XcDZmJL20hBrQlhUywuWdLoM2b28dESm1jNIoP3c8
         7xOGZNQrd4LycKnxWS7sBS70pjCtGLejR55DT/uDP9yk9y3zow50SzqIJJ/M9sUQH/nb
         Gczt1g+7STGPXEEnM8X0ki6HNN6nDrD64Lr6GPMNMe8XyyQKpMmEnPHtpZN7Wa2qZBzz
         cUfAeLGSx6ofQ7TF8S7qBueK3Ah4Yb/c4htwwbw7VHNpzfY9wLAVxDmCZmc+XsGlWmoU
         4A/TY2bbZKthookxmk3+r1QG8q7VCBfn0Hn/QKcXYEPrGJZIqaq0dp7xO6JHm5tB3CHf
         lLyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ThlNJAw9Kex8KZrskRhHj0vt2sXcunlblCUmHxCmdH0=;
        b=XUCU4zP297C3sUaeEADnT2hD6xAyx3NsmmoDr1IUpuX02QKv/Xhgn5RIu7BeUkXva6
         AcMaoEudY6KwB0gWqR62o67TuG4cRmTX3a92E3SASi99aAk2gZgWKUDqLomVsmD8tUkz
         4A1fXBHvi2dK2wmS45l4mLo5ZTcZgxD+0cKbmb4kJKl4chxK0PDjtpuITNqFzmQ0ey7T
         L9s5NHb27mcY+KyMxi95+x/uGf+QTvs/LwKTiWAxDYO6VjrBOgk3dC9vyeIUk8zCr2xe
         yqe2soXtm4/sOYYZtda3mm0/kW/wjUf512+dgTiBsVtT4llLEX9IHc/73a0ExnRURK27
         dmXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qQ2U4pH+;
       spf=pass (google.com: domain of 3leiiywykctqwbytuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3LeIIYwYKCTQWbYTUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id z19-20020a05651c11d300b00261eb78846bsi70544ljo.4.2022.08.26.08.09.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3leiiywykctqwbytuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id y14-20020a056402440e00b0044301c7ccd9so1220961eda.19
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:33 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a17:906:9b16:b0:73d:af6f:746e with SMTP id
 eo22-20020a1709069b1600b0073daf6f746emr5932849ejc.32.1661526573448; Fri, 26
 Aug 2022 08:09:33 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:52 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-30-glider@google.com>
Subject: [PATCH v5 29/44] block: kmsan: skip bio block merging logic for KMSAN
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
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Eric Biggers <ebiggers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qQ2U4pH+;       spf=pass
 (google.com: domain of 3leiiywykctqwbytuhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3LeIIYwYKCTQWbYTUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--glider.bounces.google.com;
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

KMSAN doesn't allow treating adjacent memory pages as such, if they were
allocated by different alloc_pages() calls.
The block layer however does so: adjacent pages end up being used
together. To prevent this, make page_is_mergeable() return false under
KMSAN.

Suggested-by: Eric Biggers <ebiggers@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>

---

v4:
 -- swap block: and kmsan: in the subject

v5:
 -- address Marco Elver's comments

Link: https://linux-review.googlesource.com/id/Ie29cc2464c70032347c32ab2a22e1e7a0b37b905
---
 block/bio.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/block/bio.c b/block/bio.c
index 3d3a2678fea25..106ef14f28c2a 100644
--- a/block/bio.c
+++ b/block/bio.c
@@ -869,6 +869,8 @@ static inline bool page_is_mergeable(const struct bio_vec *bv,
 	*same_page = ((vec_end_addr & PAGE_MASK) == page_addr);
 	if (*same_page)
 		return true;
+	else if (IS_ENABLED(CONFIG_KMSAN))
+		return false;
 	return (bv->bv_page + bv_end / PAGE_SIZE) == (page + off / PAGE_SIZE);
 }
 
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-30-glider%40google.com.
