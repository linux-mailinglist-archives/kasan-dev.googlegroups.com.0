Return-Path: <kasan-dev+bncBCT4XGV33UIBBWW6QW2QMGQE6TQFZVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 25B2D93B872
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2024 23:17:16 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-70d2e68f5c3sf230563b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2024 14:17:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721855834; cv=pass;
        d=google.com; s=arc-20160816;
        b=VUeLbrVfvTtDgDxaumJC/Qwuh5Mbpr/K6ZBwFS6GeHfatG3+1cxjYluoIB0X8mfmTL
         LPSH2vcU+rOgIAfuMss7aoji+YCleSQFyFjlBDWVHERZ68iSUFbUziJ842/QwtNMcoLl
         USbcmKyCsdzum3QcL582TtJe02f+HjfP9yKjLNCSlaARPnJNUIuRAa7beqoZ1JEkv2WG
         CyEpLjs4rmlYt+IVq914o/Em7kd2sO9blq4KX+G2ewPWnRBOuLO0zeC/WjWZH40crE1v
         Tbtn75z0XQ5HjzVSodoxpuYXMxvnRwFh+/xujMtoRIJUH4w9k5lff/4nfl/oEUzqT2L1
         9USQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=A9no8T/gQL3O2kJ6ofLmRwBxYLt/e3e53gq5nncRc3k=;
        fh=5ALOMCqHyV1UkUf8BmTgQkCWE79J+50E2wsNzUG/yCQ=;
        b=cy0iITNK6cXRBhsvos4J7bQ1QZHAbRjT9+66CCgdjeUK4K7+QL3Idm4R23Nm6Ldc6k
         3OPDkQHZPmQZkaq7t/UMillfZEBeFdRyajRPXwjiSjPpE2Gysn7yqtGv7ca2BUYXtaH3
         kDjbo9h74enLzbv9R0jHhp+Q3yF45Bpc7UxSe/8qFPQTjAKDORs8t4ookORD49+YeaKb
         Z6IULH791A73axlpMeR2t8fZhKMcaOhMAOz/5cSpBePNCLGB7aZRKolklol1k4f2YXKD
         aEd6HdqjktB4pv12LZf4OUqDiUP3cmT+8OFHCB1ecOm+P8OP15W7YKjmVw9OMwV+dk4r
         4BHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=P7Y7O8l1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721855834; x=1722460634; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A9no8T/gQL3O2kJ6ofLmRwBxYLt/e3e53gq5nncRc3k=;
        b=gRVflkUfvTVhHx/24RfDRGxTgpnBQSI0gx+0WxPQw9gkKIiTRgO0rHT1s8tVsBqX6R
         CJK1dHRvrWCFzYUWMWuGMAqdbPwQIr2PTfQDZrUULBL87lQhR4AKNg9/iQifEnA5OD0H
         Z3XhJLXeAYuNMT7xmGHBZfwTEJXP6AB8pqwUtVHxepFD/gyCGMvrIMLSG4/bwawq/SkG
         qLoK0IGuQRjsyocac5RyCnwXoPHJQsMboswQO58BDpq0uKLNZM8YjFzpBPiT6QHBI3mK
         HxN9DrpQYQTBmI0zBbyxw+9mMri+LN0XGg+JoQLA7bnWD13GjN79MMINj7ZA39fsNA4K
         cpDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721855834; x=1722460634;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=A9no8T/gQL3O2kJ6ofLmRwBxYLt/e3e53gq5nncRc3k=;
        b=pldxg6D5h5ppA6pYCAk2bv+EeAIh2rXnNzSpUdZ2vvo3LKpxk8FtfQM2TJSx4ozfi4
         oEDfLfRHTh46R8ovb822spu4C/TApE9cUqOUYQgnKiO4S2f6fHBONE5GKIBGzKBZLz9Y
         gWjn7XdyuoP9bM2saWrzgeqCEWe22iDLL69IkUmnfXefgw6aWu9W9nj84XYvun/rO30/
         DZ/UASA7vjRvf0i+K8dkWJKi+vnoVUAxeAPWwNrkAJTg/q7zb6pOZQMvBYUzcYsTLVVO
         07/TxaTo+cYM67Bb6Di8xzuxRN8ffrBRa7g4CK3V2PEC37jhkhlv+41LlIWR7ZuEQyW0
         uQxQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWWqJzvKX4GRJgLYJ1uYIWVV21Iu0Inokn60hwilI10+JovYYTLcqKUmWbY3U7F/Thr8vd2KAzeAGSJf7EQVYXCXDfwaVDY0A==
X-Gm-Message-State: AOJu0Yz+MfkY+7ZBxbrKSK6pWptbC8WqBPtwYfmFVd3qTsCrvlc1LzFa
	YdOKGUjvVjd4q/e6IjS/4TS/XdZmXyYfWYHoWHPSe5jFSA5Y2Z/w
X-Google-Smtp-Source: AGHT+IEYRpUiNYQ8NSx6/qhTHvnAsmkNU0ewy4txQZLKWag+t0neO4KT9OxZY70+pIHlpiOOUt14UA==
X-Received: by 2002:a05:6a00:194b:b0:705:bc69:385d with SMTP id d2e1a72fcca58-70eaa859b0cmr1090741b3a.8.1721855834330;
        Wed, 24 Jul 2024 14:17:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:784:b0:706:7c96:9d31 with SMTP id
 d2e1a72fcca58-70ea9e0afbals168394b3a.1.-pod-prod-02-us; Wed, 24 Jul 2024
 14:17:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX1FbM9rwbfs5F+dwOVdkVfxUHW3vfle6DOBrOBJSWpaoMpfZ2rZTiFXLnjeKUKaWDs2re0L3WgCJpINBJelD7SBvXVo8N3Xi3kiw==
X-Received: by 2002:a05:6a00:855:b0:704:32dc:c4e4 with SMTP id d2e1a72fcca58-70eaa8347d5mr844788b3a.1.1721855832765;
        Wed, 24 Jul 2024 14:17:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721855832; cv=none;
        d=google.com; s=arc-20160816;
        b=SbRShSIzmmLTc0OLqmA7lFI02Lhs62qyf4ETLodUamC/YNcHaPtJ+WcYwes7Aaqs8v
         KxplZkjk2UH0bLKDs33I3u0gr95ewPbqqEjs86meo59z7AFi9aSxM11vN4p9xGkIcDzS
         OozmRroWq+Ohp8t2GLdhDc2KjIc2fiZOzszOYsjZNR07W2bhs3p8IsRdGLAmxh67yFwo
         QgqIwZjAziFUs2UhnE8eFK0bxGXYe8syGBJNg8Q+hbP3zMSHypStq+MVYFafRsIZfuve
         dksS1U3qiPNsUYHHUlsvU3PYgfEoJVROkIqREduuRAwOdtpp+cdW/ctGgeS8D1dxkelW
         qO9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=33jHwZQKsKsI96L6IRoFs6G93mswFxjWZc8vGx8w+wI=;
        fh=VAYYubKOPG4PnZZrQPhn7B7nr1s9cbjGDHHlsVeXUW4=;
        b=JPQnewIk0Ywd6fRUeD/Blx9nPOLgDE43Mz7hS6pu5zsoXIzExidLbk4qwQI6qaj+aF
         z3ygNWABWqG+RD7TCjS049ponq+pLq2tyLT27fTMZ6gGlTk5wyL6z4n/Jn0U/nBDPUxd
         +PZyMeMrxqoSD6PHnAFWrkSi6kNOiMhbSAGmwsCHQM+mCJgS30cyoVHUnDPRIpzDHeSx
         ybR4KbpvCMwcprTpz+kkgeSPpJWeetngImA13Az4Eg8/jID5FBN/5GjxcgvBhV6wIODE
         apHhcLJJZHCINs3RON1ObtZNfVH3o5OPnqK9hEK3xqhyISZCcc9Cg4EOerJ4h8TgcQcj
         aNEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=P7Y7O8l1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7a9f5f2d1absi7386a12.1.2024.07.24.14.17.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Jul 2024 14:17:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id EC592CE12BD;
	Wed, 24 Jul 2024 21:17:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B9AB2C32781;
	Wed, 24 Jul 2024 21:17:09 +0000 (UTC)
Date: Wed, 24 Jul 2024 14:17:09 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Jann Horn <jannh@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David
 Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Vlastimil Babka <vbabka@suse.cz>, Roman Gushchin
 <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, Marco
 Elver <elver@google.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH v2 1/2] kasan: catch invalid free before SLUB
 reinitializes the object
Message-Id: <20240724141709.8350097a90d88f7d6d14c363@linux-foundation.org>
In-Reply-To: <20240724-kasan-tsbrcu-v2-1-45f898064468@google.com>
References: <20240724-kasan-tsbrcu-v2-0-45f898064468@google.com>
	<20240724-kasan-tsbrcu-v2-1-45f898064468@google.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=P7Y7O8l1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 24 Jul 2024 18:34:12 +0200 Jann Horn <jannh@google.com> wrote:

> Currently, when KASAN is combined with init-on-free behavior, the
> initialization happens before KASAN's "invalid free" checks.
> 
> More importantly, a subsequent commit will want to use the object metadata
> region to store an rcu_head, and we should let KASAN check that the object
> pointer is valid before that. (Otherwise that change will make the existing
> testcase kmem_cache_invalid_free fail.)
> 
> So add a new KASAN hook that allows KASAN to pre-validate a
> kmem_cache_free() operation before SLUB actually starts modifying the
> object or its metadata.

I added this, to fix the CONFIG_KASAN=n build

--- a/include/linux/kasan.h~kasan-catch-invalid-free-before-slub-reinitializes-the-object-fix
+++ a/include/linux/kasan.h
@@ -381,6 +381,12 @@ static inline void *kasan_init_slab_obj(
 {
 	return (void *)object;
 }
+
+static inline bool kasan_slab_pre_free(struct kmem_cache *s, void *object)
+{
+	return false;
+}
+
 static inline bool kasan_slab_free(struct kmem_cache *s, void *object, bool init)
 {
 	return false;
_

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240724141709.8350097a90d88f7d6d14c363%40linux-foundation.org.
