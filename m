Return-Path: <kasan-dev+bncBDQ27FVWWUFRBKENUCDAMGQENLWXYXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id BF7163A7373
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 03:47:21 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id a5-20020ac84d850000b029024998e61d00sf8571963qtw.14
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Jun 2021 18:47:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623721640; cv=pass;
        d=google.com; s=arc-20160816;
        b=rMMoUbae51jR4JEDAswAgnY3om/T1WLelrS0DNr3ZrqXeZEPitKbFxSdHQAClq2HuF
         0BQ6AL9LN+9Ftt6PJ1oRK81+W4IkKQJtJVU1yQCP8+F1TUC89oSvItwOhulgnJzATe5r
         HOetu4Sif+Zpmer0l9IQhFUuV49aZ/4kQTg1TwRogfOW6UmKkYscThSxko8MWMsKvDa6
         zH2yqlKDRajty0t5pn0689AkDrI2wzqrWxCjzZUJEDVmdiAkxS1bZfp7X4jXSTHxo1HL
         9pghszR4GWZwah0pEQRaSAvsOAftbgpR48u93dtM0QusF8DcxbfPDh4q+wQ118JgAhIX
         IUMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tFlgGVn6ZJl2AK5iLJsr8yVdyp71coG07rBxCsMpzwI=;
        b=bIpN2LbuQpXj5gaeXjBL5EJLBmAu1d1n55JQxmJeJjSHgeF9MPfcuaD01Oetw9EWMd
         /fW6f6sbqYRwiTHhl2wXWWvtYQjIgHlUnSp5rs7IyMDXG6BU0dEhUyH9WD8qxgSJSKMU
         plR4zrz5v0XFSU3VtV0MVN+MrB44fqc3nOuq3qBmzcB62Fshw8TGJC7KI9CGze9mAeCt
         wMsayhup6CmjFLDt/UsLEck0PrfIawrDwRlpvz7D2mNWqY8bhaL+Q3Iu02YWG36di8+0
         rdG+3ke+nSB8z3WzWRhLwSROZ37sEZ2K76f7c0TBc1r+HKcCq+EXjG4ceBEoBNTvQQtI
         AUkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Zp8KnLUS;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tFlgGVn6ZJl2AK5iLJsr8yVdyp71coG07rBxCsMpzwI=;
        b=RTCwGtEADz4qaWqwr1vqbFtHH6EjrEMTh3jWyKusEgr/tXacHccLvmtvU20D5OEIhL
         DkXok9daAXP095CbLfINLxGrWnE4g49FImcF9SoiKpnfsxCj/jcSmc1lzB30c5cQ2Grw
         Te5V9WNAHsQsCT9vAIOVb3OFDEVFgNaI1yl/f6T45NQ02f/U9VI2XnUUClzzAD1UhWY4
         BpQvOK7sv6tiFYlGRgWdfAAlYUTK0hd/pXdhJ+FCqiyYm9ajX6GBofp4wrnt5T2ESCGA
         ZZQkIIH76tyeMsd7V0ffXQBDGY3tHU4DK8mgjN2hFkeQJoM234ypDuDMRSn4yW0nvYRz
         zW8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tFlgGVn6ZJl2AK5iLJsr8yVdyp71coG07rBxCsMpzwI=;
        b=MKb73k8KNrYoAJaPVdGa0wDhF2He0Kwqenh9fR+BVCDGl8hPFT5W5FKyNzouz/bmwz
         OS/1Y7R3FGtaA7iArpgne12WBoOItm7DKfYsTXamhavu8KDl1I3u1KmMyq5hUg/y5ZOz
         BYYOENkrgvHKMovmKqlmgxe7cJzrCuM8dZCCTnfHBRDcV4c0QGi75QPvxj9Pw5iANumG
         CnxYQBll3gVPcTd2i6HwG2/2sLzTyc6PMULol6yQULLLRiPE3P9xriKVRddGkJDbLUou
         9SzB4zwxS3Hs83HXSTBORNhzuKK57JEV3apUpidi4cI3a8m+GVetHaDJKZifNYulmOfS
         gxsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53302xPX63kMvVzAfqap8Wkns0RjMU/WRI0320hTF5LXCHWhanzi
	Vs4D+HWwH2+ItjUh6QttKcE=
X-Google-Smtp-Source: ABdhPJwN3Wdtm30P47INMeMz8ZLfjA8lLdfYTEhFuXBWmFwr4s7zQtRSY2UQZ+i//WHMQT6L/aN46A==
X-Received: by 2002:a37:6851:: with SMTP id d78mr17210820qkc.483.1623721640678;
        Mon, 14 Jun 2021 18:47:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4f30:: with SMTP id fc16ls6333928qvb.8.gmail; Mon, 14
 Jun 2021 18:47:20 -0700 (PDT)
X-Received: by 2002:a0c:aa13:: with SMTP id d19mr2340083qvb.3.1623721640182;
        Mon, 14 Jun 2021 18:47:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623721640; cv=none;
        d=google.com; s=arc-20160816;
        b=hCJBWurh8XVuoDId0WRqFCkREz+Ks6W++pzmEqa8vncyBgt0i1MZ+6xUuThDFFvZI/
         l1uG2McXVN+vhWc/5RTS9GdWPXTkTfj0e5R4nLQuonoJ2xGW3uvl9kQ5uit64BwTcago
         lqVlPXwJD3Q0T0+5Ng9KtdPEmuKzIATlo/d7nq8h8ZoNCapjy9GYJ6PI4zhJatM0oE8w
         3ah5Rt0p9ewmyuOCeC4GHibDxNCH28DR03UxW+FXBqXch5CH1OqA2FQ7lYyfA12oa9FW
         85aR3zp+2gWlJ3zqSkQhfs2TgFueQBtk2PqjisG6nY0pjqhWILxlFD1lMcO++lVrgMTV
         vLvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9yfG43b2K5TzVk5ZU+QSFD/NukUJWMplQuDr+tXNhQQ=;
        b=gYfUpW2rUZ3+9YMQ4adWC6wdCYPYaL/NFWz62TAQnhQ/EdSv04j0m75r9PBXHhGBX8
         nF8ZPTaYUwFJAqPlDvX57o4aMTPPjmz+NT2+XGxg0TwWsoAufUznTcZ5GZqPq6mbCl8m
         9udshP15icL/OBdU8YMabyzkzgCIzDxDdpm1tU59mn5oT5oEJdoKbcVN3uv3xa0g+L6V
         UVqQiA0yn+QGcdEaHOJd/MuhnDt6RIFDC4jmU9b42CKjO7szVPPxlZs1XNu+JEDMFEYT
         i0u6Aob7FJHrG39PFzFxrwzEkf/ziSGPd1lGwEREYrTIwmBlABnpEof2AYpkZNv2XayJ
         hq6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Zp8KnLUS;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id m9si140708qtn.5.2021.06.14.18.47.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Jun 2021 18:47:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id bb10-20020a17090b008ab029016eef083425so388711pjb.5
        for <kasan-dev@googlegroups.com>; Mon, 14 Jun 2021 18:47:20 -0700 (PDT)
X-Received: by 2002:a17:902:d888:b029:11c:1010:f0ea with SMTP id b8-20020a170902d888b029011c1010f0eamr1621088plz.68.1623721639363;
        Mon, 14 Jun 2021 18:47:19 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id n14sm13096115pfa.138.2021.06.14.18.47.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Jun 2021 18:47:18 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: elver@google.com,
	Daniel Axtens <dja@axtens.net>,
	"Aneesh Kumar K . V" <aneesh.kumar@linux.vnet.ibm.com>
Subject: [PATCH v12 2/6] kasan: allow architectures to provide an outline readiness check
Date: Tue, 15 Jun 2021 11:47:01 +1000
Message-Id: <20210615014705.2234866-3-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210615014705.2234866-1-dja@axtens.net>
References: <20210615014705.2234866-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Zp8KnLUS;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1031 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Allow architectures to define a kasan_arch_is_ready() hook that bails
out of any function that's about to touch the shadow unless the arch
says that it is ready for the memory to be accessed. This is fairly
uninvasive and should have a negligible performance penalty.

This will only work in outline mode, so an arch must specify
ARCH_DISABLE_KASAN_INLINE if it requires this.

Cc: Balbir Singh <bsingharora@gmail.com>
Cc: Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Signed-off-by: Daniel Axtens <dja@axtens.net>

--

I discuss the justfication for this later in the series. Also,
both previous RFCs for ppc64 - by 2 different people - have
needed this trick! See:
 - https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
 - https://patchwork.ozlabs.org/patch/795211/      # ppc radix series
---
 mm/kasan/common.c  | 4 ++++
 mm/kasan/generic.c | 3 +++
 mm/kasan/kasan.h   | 4 ++++
 mm/kasan/shadow.c  | 4 ++++
 4 files changed, 15 insertions(+)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 10177cc26d06..0ad615f3801d 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -331,6 +331,10 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	u8 tag;
 	void *tagged_object;
 
+	/* Bail if the arch isn't ready */
+	if (!kasan_arch_is_ready())
+		return false;
+
 	tag = get_tag(object);
 	tagged_object = object;
 	object = kasan_reset_tag(object);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 53cbf28859b5..c3f5ba7a294a 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -163,6 +163,9 @@ static __always_inline bool check_region_inline(unsigned long addr,
 						size_t size, bool write,
 						unsigned long ret_ip)
 {
+	if (!kasan_arch_is_ready())
+		return true;
+
 	if (unlikely(size == 0))
 		return true;
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8f450bc28045..19323a3d5975 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -449,6 +449,10 @@ static inline void kasan_poison_last_granule(const void *address, size_t size) {
 
 #endif /* CONFIG_KASAN_GENERIC */
 
+#ifndef kasan_arch_is_ready
+static inline bool kasan_arch_is_ready(void)	{ return true; }
+#endif
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 082ee5b6d9a1..74134b657d7d 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -73,6 +73,10 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 {
 	void *shadow_start, *shadow_end;
 
+	/* Don't touch the shadow memory if arch isn't ready */
+	if (!kasan_arch_is_ready())
+		return;
+
 	/*
 	 * Perform shadow offset calculation based on untagged address, as
 	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210615014705.2234866-3-dja%40axtens.net.
