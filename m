Return-Path: <kasan-dev+bncBDKMZTOATIBRBBEH627AMGQE2JVLQPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3767FA6BE27
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Mar 2025 16:19:35 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-39131851046sf930082f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Mar 2025 08:19:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742570375; cv=pass;
        d=google.com; s=arc-20240605;
        b=Pj5jCDQ5HBcQWjlzdSyH0xq19OGLyp3+rduQuw/j49VA9mJO8+hL27a6Atu2Mmx2jW
         pb+qnAUWcCfDkIDriMpMVMoFu01pdKMwuwGxFiPTwUlv3bHaMkHpngzM1hvczz3NutO9
         wPWQbxN9RwED+3R+Fh50+72WBquGM3Yhasf+Mqz2AIi8uERtygx4HJqvyrTnQ3ss/mBO
         Ojt/TnR9cmvtRaWrflA7Anp52ubGgHpzH2kEici7FJ4IcFe9ouFgCHQa9DHUZOmtWr/C
         1eXzp8gZYoFIDlJtlJRjhVwV+aeRjieiwk1UxR4tFdZ/OgQBSuJ8SKtvsE/g3s81j1Mt
         +GfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=NU7VNQEHkpH9vb9uYh0+st1fOV3T1AEoxqAZA+jC8Bg=;
        fh=uZadtc/wUSvFOKVgRQYwHExYxwiBunQNhJI4YYaEGTE=;
        b=ZaaSg/rOystFq2gno8umVVKTnh5EYdD3rQm2gYuwf/aSNSUQ2jQmuDEK/qoTqhEgOH
         KWGWEGb2iDcLP7U7XlmTbwa5rhc4DZJKU+mbMafY7eF0ARL+XNikFLb3oC/cmFJqkMLX
         G2PGmNpfxDJPS93PY7E+aL+e7tDQJKSE0sCUvgi6S1JsxZXiKubZGtuY5YyFebG/sM0Q
         ALMJgZ9e7dNj9+YCGD9rL7S6zlL3EygbceS80POuVzC42Vdn7yvXaUNa3uOen07A+ecF
         Z22bLpP5YViArYUWmUgzSxEh3Nsi/96k0bjiknSqrHuSzPMRCOhF5ZghcvF0C0BaZwHL
         3Amw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ad5Qlthe;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742570375; x=1743175175; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NU7VNQEHkpH9vb9uYh0+st1fOV3T1AEoxqAZA+jC8Bg=;
        b=J5OYuYvQRMYeP2y/lefwioK3ze/Ll2EJ3Aycf6e/NTk/FXhvxC3oKNCf9tV9I1mlJi
         2AJxFj8Jnft3j/iGpYz0cJQlEYe+U4EOFNyfzB4rWx3VQEw/dD0JBOO1aby2QCf2qm9k
         ccyUleY9Qc+UceDjOr1Ms3wedZxCTsWcHRAlUP7TRvs4eWzD/nT3GjL8k1Nzrn5r5NjP
         yXSK2BNo0bfZFADjyyb9AruV4NSe4oAlurJzfn79Bit6FvwQ/7lX9wxGD18LPwD0Qn9T
         ldrWgyY9oEAj5eLcyDe/Kth4KMYfhMYwbkkf6/uQfjS47BTu2xEf+AZT86o2ZPyICoNo
         p5Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742570375; x=1743175175;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NU7VNQEHkpH9vb9uYh0+st1fOV3T1AEoxqAZA+jC8Bg=;
        b=ZYqN1RAGlqh5/LVGAv2TKkchm8EZp9QRSROJPrZIM+3OfWv+KyUuj2rPZcDiMeWy27
         5u1z2CzEULaE9KULs/82gkJlYyBHnDKPj8PhkXcgJM5usVu/OxzEvMmpjrBzzocgAJ9f
         XaHLY/Qu3PSvbebeoLVoq4PKcH5k/le5DxgDa99AzyGbuLaTCvXQtGVtsKlxJ1Yyj0zx
         vrQYSPp83dZVLnglY3y7YwUrcXqtRkD4JFhwaFAaNBou53+zhbHlgd9ShLRpqzU711Vn
         Mg3dX7vzzyuxaOCGhjzJv44dJqABHoM7hZ/QBYOvDUIdu2DAJuwLKDgLuNdnFPZ0aemw
         wxyw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUaMhsEeMn1AT1E+uXxMcvqY1C6N+y8E4Uiml4uAW4d83SfW/ywzmHs5WJtmbOKarr1snk2rQ==@lfdr.de
X-Gm-Message-State: AOJu0YyyX3Ts91oA5rzC8yoMmRIljbC3XiFH/qH2DTiFbaPHppeqFJ2/
	tAtA4ktYc2Rb10fp2oZFZPkmtnxxwbuCNMjH8H3H4Ge8FhuEHKPQ
X-Google-Smtp-Source: AGHT+IEDdBV3KvxPkBTY6ol6eZoMEdHlOaofjJEnxiXdIoQPVSjjtVkbUhhs4F86jLCEl69Xb+Tm5w==
X-Received: by 2002:a05:6000:2a4:b0:391:ba6:c066 with SMTP id ffacd0b85a97d-3997f932dc7mr3654199f8f.35.1742570373481;
        Fri, 21 Mar 2025 08:19:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALrCR6A+UaumWIHn0luovj5UPLKCawzPRj2IT0w0uHnaQ==
Received: by 2002:a05:600c:4182:b0:43d:1776:2ebe with SMTP id
 5b1f17b1804b1-43d4ecac340ls6729855e9.2.-pod-prod-08-eu; Fri, 21 Mar 2025
 08:19:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmde1gLxuCqYv05GJjHDC9Vu0Zejj5HKItJ89FTGUv71oGRLGEqoEy+sPZ+vozHNJQCzyfHoXnphg=@googlegroups.com
X-Received: by 2002:a05:600c:4e8e:b0:43b:c857:e9c8 with SMTP id 5b1f17b1804b1-43d50a553fdmr34350435e9.31.1742570370410;
        Fri, 21 Mar 2025 08:19:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742570370; cv=none;
        d=google.com; s=arc-20240605;
        b=dLtdqOtE1J4MXGlGwNX5qaDHXf89WTMnVtJ2y4nXzn4svEfOMAU4OFotK69kYmuv5B
         tR3ACU4EroRlvcSGzJnlqdzOE7TFSeYSnUAo1mS/HoZ6iBRZMFesLCGDp2NG/GBpM7II
         aCxIKsL27artYst4SG0JLVXb4yO8l5Kl0wGjfyWmnFV6HWLWIwEaRYYXVChTvMrxomMG
         0Uhv+BjiK1MDgrLH723d7Br2pecBx8vdmjs/x3Tk0pxyq6vhCARi7+QrmVofZfGmZ4Yp
         qs91QUuMuRopyODiKWyPPlJydeSAVThPPZ4E71R7GQYKZ+xjmH7xIdnLxLk7nalGOyy4
         j4IA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=lBxw2htHgnZZOPZ1kV+4yA/Whj5g2X0dF9eVqQ43F0k=;
        fh=eQVvRnaowjFhecodQw9rb17bJq8PyzUXPk4LtBZjfdA=;
        b=kwocQF1FHWvwhFG2MWxtJO5IxzQrM7mxXNVZ81qv1tV6cfLXN63ri2troT2u/B6XCg
         N4pV+qw8E3by3R4Q2zXnzQ77+gORrYqI7oIIEfYICSlUQe6jftr2Zr/b/zk/K9CcI4/m
         OOelAkx0OzkZE+Ig/6tmgJ0RbffSAmJpyI38ifWT0qINE8MIzsaexdr/NltWlFU4sOaC
         wQgoqBo4hxa/9R69U3AjGjhujOc8kWgZuZuE2XvUt6J3cFIIxsNqJ+JqXn8aZQ2sYL3G
         7mEqHRgTQ7mXYxnaV6CNOBeXIanwEpwF9H/BDg0QnNpBRCBu8kvJ5c0MIIZqntGWqtG6
         Vaig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ad5Qlthe;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta1.migadu.com (out-179.mta1.migadu.com. [2001:41d0:203:375::b3])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3997f97cfcfsi56938f8f.1.2025.03.21.08.19.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Mar 2025 08:19:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b3 as permitted sender) client-ip=2001:41d0:203:375::b3;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: 
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH] kmsan: kmsan_check_bar()
Date: Fri, 21 Mar 2025 11:19:16 -0400
Message-ID: <20250321151918.3521362-1-kent.overstreet@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ad5Qlthe;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::b3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

handy dandy convenience helper for debugging

Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/linux/kmsan-checks.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/kmsan-checks.h b/include/linux/kmsan-checks.h
index e1082dc40abc..0849646aa386 100644
--- a/include/linux/kmsan-checks.h
+++ b/include/linux/kmsan-checks.h
@@ -95,4 +95,6 @@ static inline void kmsan_memmove(void *to, const void *from, size_t to_copy)
 
 #endif
 
+#define kmsan_check_var(_v)	kmsan_check_memory(&(_v), sizeof(_v))
+
 #endif /* _LINUX_KMSAN_CHECKS_H */
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250321151918.3521362-1-kent.overstreet%40linux.dev.
