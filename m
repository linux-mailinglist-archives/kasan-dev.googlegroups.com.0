Return-Path: <kasan-dev+bncBAABB3WAWPTQKGQE7DPRZPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D0FC2BFF4
	for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2019 09:17:04 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id h7sf15058407pfq.22
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2019 00:17:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559027822; cv=pass;
        d=google.com; s=arc-20160816;
        b=zvSzIQR/64T1s4qTmKnGraeYumkHhepMeGfcw4ry3XayRMPVINl+R3ROr12g5778O2
         1DUGr3cl82Por1ALl70EO5puNjy83uiCu5tRllyY48RwekXUj2T1Vh8AhQxzCHlqlUcE
         Se16jtM4KcvtgTlZVOzN0V89Dp1FD+sWcxxeM043gAXyhPCCSwdtowePClH5iWEWqaJq
         a/GYta8aThfbEw7+XMNNELMzcRvoz/2q+gDSmw+PTBNZEZwy5J4KTPfH3XLZ+s3FKwxo
         VQXD5c0H1qQA85kvCZuHwajvz8dCmfRGz79F2gnmTaL1gJs8qga3aRLsjLq+/ws2XAWy
         lYlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=LWYRuZLrpEN6Jrap+8LUMHJ9XPaR/8/7TN0gLBQ9ZoA=;
        b=Ik8WJuvcgIx1lwsNxnLhc8UhCrhCbkmeDdCi8DW7PTZa5c8uMAC4zv7W4Pck7drahu
         lPexwZBWH4bViJ+ty398epLK45GzEuJjDVRpas5YoGj/YfAOsd5eZ7qdgqSjYST80WZg
         wXnheXkqPXbqzeYC6y+Z9Dne8Y9bEmifQsV8vQBAEk3I7jeNV6DgaP0jrg7vnDOTPfoe
         4p/n9VAcAMklQCChA02g6VkF2leoHIGEFqWQHdExAjWimtgvFwDyswrKHg1eVs+ur0i+
         9SmsVRKFIxR1ZlFhOk3a8bRyf9KcRTHUi/L8SDcZ/GGLdVNGx2K6ooVU/fs4yJd4EiyM
         qQGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LWYRuZLrpEN6Jrap+8LUMHJ9XPaR/8/7TN0gLBQ9ZoA=;
        b=FHvOnm2IPFAq4aqOQjIN1DlkmT3tsZor/5NSoEoBVOM/c7cJSRC+IybS5eKnBUlgzM
         3ZuzmX51wl6gfbDuYTOTG2d1U2kTkekxLUfI9nVHpI5Et2031ON1/S9VWNk0dF4TtEBY
         BS9tuF4n0/AsitKrLh2o+IdwziQhRw9/XwAFHNyYU1wbTX8EkZNkMj11xM1yeKUYqTYb
         +2FPLUN2dldhLgeBt9owaAN5Y0dUyV9x5sZj15qRym28YjbGBsfBOnWRzgLwfFztHhyv
         bRws3x0kk72mrmRM7qgJGIWECHIWA5qepRLHL7Oywyvv6h07r7g31DQtPyT+AwlPEpGF
         oqiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LWYRuZLrpEN6Jrap+8LUMHJ9XPaR/8/7TN0gLBQ9ZoA=;
        b=cq0haaaPjgf9CJyULxdpmP3QOUOyXiZXlU93iQYv54oetCECQizVjxGGYXrQu9ys1O
         ObcLQyINNh9skLxTp9X7OHvYgv0hh9MYuxfU5pIpD3hUcDNqah5I/sBE9p/Dg1BcZh1T
         EI076rxLyvN4Ajp6ww8WUJNQv2WsVeUmLDu3tpNWLfpWJlDGMWqVbEY/7y7XjCiMhbk3
         zq8P4c3lLkKyXUtXPBZJR7PMlqeDh3nFt0iTsoB978WcUduSP6OLvDeLqIZwZr/DG2WP
         fjsrbn4k3c8PYsDt5Sl+t72KIX3UhXDU08ujUZkiENvvqysb2uF+hTMu/D3W9EjBkSpF
         gzfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUP773AJjLhYq2Ba6Fdv00cDEhC/8rpVge3IXGkFJSO425EIUvA
	a6osAOc2GE+2j8Q0U9VTFbg=
X-Google-Smtp-Source: APXvYqw86lNrkjJc3VpCqxZUxgo7gIZjA/0K73fUX5Sii4FRIm92UgvI5SuKb7sC1yG4XOTVyK/8uw==
X-Received: by 2002:a17:902:b402:: with SMTP id x2mr17873994plr.128.1559027822248;
        Tue, 28 May 2019 00:17:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3381:: with SMTP id n1ls527878pjb.5.canary-gmail;
 Tue, 28 May 2019 00:17:01 -0700 (PDT)
X-Received: by 2002:a17:902:b089:: with SMTP id p9mr15643160plr.38.1559027821944;
        Tue, 28 May 2019 00:17:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559027821; cv=none;
        d=google.com; s=arc-20160816;
        b=g+6/u+yROmSY59SbDFix0ZcId7Wsi70v3Is+Bpj2R+3d+dUiZcoBmlx/MlHuew+oWm
         g0aKK8CL5v139VLMvQqJVprjOf7jJXktxk4Yu98ZXLgZaGePj+kthokX5cPcmajvW7LA
         WUtwMHRLsIsZPJgZVIgfNpHb4B8ty1IrFb1mJIoEbnBN/G6wbquHYcsnKjY/gRz1zsq4
         ke4Q+sD9w0M//CFQOUG6PdSrC2Deon8WUaCHQSTRJBJDFMxSDgelE6cTH/Ge/T/bQvQO
         +sa+ezaqwYuTqmJ8x5kATi5TK9LAtRdLQcgcao9gVJt7M2Y2cttHg3DAm7bos19L/JD7
         6orQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=DLCMy4jwn3WcpJxS2LLTHYS4OXl6UhOnnJyw1DlBVJM=;
        b=cWnweY/hBGNG86f/70g00pfg5RTKnj4rw1YRlnfkplkQjXNfxA/x0tj/i9/ZCeG6xQ
         3vWCAWrgAa48x2HsyNhP2zmWO3gkWyiFJeQu9g0TVmgp+hwWA+9EtE5uZh52Gu9i0pYH
         PvuCf95bEvAUXVaqfHUDY+Ts6zCEdoNQ3N6qLfIBhA5H/zoByK2scdo5aOyrmFMjxF3o
         UYhfBVd0d3klKvFNnQO89GX7Yso8HWb1uzdU6haxj+gaJ71GgRldcGVOfdM3aPFsOCs0
         00n3bynhbFYeyJsk+0uq2HAdrQHxlylFSksFniApjWinWj91w0UGZcX6YTMsi8zc7VxV
         FG2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTPS id 142si170481pga.4.2019.05.28.00.17.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 May 2019 00:17:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: cdf0d49e3d6442ae89fbbd5f804196e1-20190528
X-UUID: cdf0d49e3d6442ae89fbbd5f804196e1-20190528
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(mhqrelay.mediatek.com ESMTP with TLS)
	with ESMTP id 1412742451; Tue, 28 May 2019 15:16:53 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 28 May 2019 15:16:50 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 28 May 2019 15:16:50 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Christoph Lameter
	<cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes
	<rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Miles Chen <miles.chen@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
CC: <kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>
Subject: [PATCH] kasan: add memory corruption identification for software tag-based mode
Date: Tue, 28 May 2019 15:16:37 +0800
Message-ID: <1559027797-30303-1-git-send-email-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 1.9.1
MIME-Version: 1.0
X-TM-SNTS-SMTP: 75507E45C2D09C15D485661FCC398184E24D50AC9E07FCC16D63C7A739DEEC0D2000:8
Content-Type: multipart/related;
	boundary="__=_Part_Boundary_005_2032766234.1374939665"
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
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

--__=_Part_Boundary_005_2032766234.1374939665
Content-Transfer-Encoding: base64
Content-Type: multipart/alternative;
	boundary="__=_Part_Boundary_006_1170253316.1644507556"

--__=_Part_Boundary_006_1170253316.1644507556
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<pre>
This patch adds memory corruption identification at bug report for=20
software tag-based mode, the report show whether it is &quot;use-after-free=
&quot;=20
or &quot;out-of-bound&quot; error instead of &quot;invalid-access&quot; err=
or.This will make =20
it easier for programmers to see the memory corruption problem.

Now we extend the quarantine to support both generic and tag-based kasan.=
=20
For tag-based kasan, the quarantine stores only freed object information=20
to check if an object is freed recently. When tag-based kasan reports an=20
error, we can check if the tagged addr is in the quarantine and make a=20
good guess if the object is more like &quot;use-after-free&quot; or &quot;o=
ut-of-bound&quot;.

Due to tag-based kasan, the tag values are stored in the shadow memory,=20
all tag comparison failures are memory corruption. Even if those freed=20
object have been deallocated, we still can get the memory corruption.=20
So the freed object doesn&#39;t need to be kept in quarantine, it can be=20
immediately released after calling kfree(). We only need the freed object=
=20
information in quarantine, the error handler is able to use object=20
information to know if it has been allocated or deallocated, therefore=20
every slab memory corruption can be identified whether it&#39;s=20
&quot;use-after-free&quot; or &quot;out-of-bound&quot;.

The difference between generic kasan and tag-based kasan quarantine is=20
slab memory usage. Tag-based kasan only stores freed object information=20
rather than the object itself. So tag-based kasan quarantine memory usage=
=20
is smaller than generic kasan.=20


=3D=3D=3D=3D=3D=3D Benchmarks

The following numbers were collected in QEMU.
Both generic and tag-based KASAN were used in inline instrumentation mode
and no stack checking.

Boot time :
* ~1.5 sec for clean kernel
* ~3 sec for generic KASAN
* ~3.5  sec for tag-based KASAN
* ~3.5 sec for tag-based KASAN + corruption identification

Slab memory usage after boot :
* ~10500 kb  for clean kernel
* ~30500 kb  for generic KASAN
* ~12300 kb  for tag-based KASAN
* ~17100 kb  for tag-based KASAN + corruption identification


Signed-off-by: Walter Wu &lt;walter-zh.wu@mediatek.com&gt;
---
 include/linux/kasan.h  |  20 +++++---
 mm/kasan/Makefile      |   4 +-
 mm/kasan/common.c      |  15 +++++-
 mm/kasan/generic.c     |  11 -----
 mm/kasan/kasan.h       |  45 ++++++++++++++++-
 mm/kasan/quarantine.c  | 107 ++++++++++++++++++++++++++++++++++++++---
 mm/kasan/report.c      |  36 +++++++++-----
 mm/kasan/tags.c        |  64 ++++++++++++++++++++++++
 mm/kasan/tags_report.c |   5 +-
 mm/slub.c              |   2 -
 10 files changed, 262 insertions(+), 47 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b40ea104dd36..bbb52a8bf4a9 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -83,6 +83,9 @@ size_t kasan_metadata_size(struct kmem_cache *cache);
 bool kasan_save_enable_multi_shot(void);
 void kasan_restore_multi_shot(bool enabled);
=20
+void kasan_cache_shrink(struct kmem_cache *cache);
+void kasan_cache_shutdown(struct kmem_cache *cache);
+
 #else /* CONFIG_KASAN */
=20
 static inline void kasan_unpoison_shadow(const void *address, size_t size)=
 {}
@@ -153,20 +156,14 @@ static inline void kasan_remove_zero_shadow(void *sta=
rt,
 static inline void kasan_unpoison_slab(const void *ptr) { }
 static inline size_t kasan_metadata_size(struct kmem_cache *cache) { retur=
n 0; }
=20
+static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
+static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
 #endif /* CONFIG_KASAN */
=20
 #ifdef CONFIG_KASAN_GENERIC
=20
 #define KASAN_SHADOW_INIT 0
=20
-void kasan_cache_shrink(struct kmem_cache *cache);
-void kasan_cache_shutdown(struct kmem_cache *cache);
-
-#else /* CONFIG_KASAN_GENERIC */
-
-static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
-static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
-
 #endif /* CONFIG_KASAN_GENERIC */
=20
 #ifdef CONFIG_KASAN_SW_TAGS
@@ -180,6 +177,8 @@ void *kasan_reset_tag(const void *addr);
 void kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
=20
+struct kasan_alloc_meta *get_object_track(void);
+
 #else /* CONFIG_KASAN_SW_TAGS */
=20
 static inline void kasan_init_tags(void) { }
@@ -189,6 +188,11 @@ static inline void *kasan_reset_tag(const void *addr)
 	return (void *)addr;
 }
=20
+static inline struct kasan_alloc_meta *get_object_track(void)
+{
+	return 0;
+}
+
 #endif /* CONFIG_KASAN_SW_TAGS */
=20
 #endif /* LINUX_KASAN_H */
diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 5d1065efbd47..03b0fe22ec55 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -16,6 +16,6 @@ CFLAGS_common.o :=3D $(call cc-option, -fno-conserve-stac=
k -fno-stack-protector)
 CFLAGS_generic.o :=3D $(call cc-option, -fno-conserve-stack -fno-stack-pro=
tector)
 CFLAGS_tags.o :=3D $(call cc-option, -fno-conserve-stack -fno-stack-protec=
tor)
=20
-obj-$(CONFIG_KASAN) :=3D common.o init.o report.o
-obj-$(CONFIG_KASAN_GENERIC) +=3D generic.o generic_report.o quarantine.o
+obj-$(CONFIG_KASAN) :=3D common.o init.o report.o quarantine.o
+obj-$(CONFIG_KASAN_GENERIC) +=3D generic.o generic_report.o
 obj-$(CONFIG_KASAN_SW_TAGS) +=3D tags.o tags_report.o
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 80bbe62b16cd..919f693a58ab 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -81,7 +81,7 @@ static inline depot_stack_handle_t save_stack(gfp_t flags=
)
 	return depot_save_stack(&amp;trace, flags);
 }
=20
-static inline void set_track(struct kasan_track *track, gfp_t flags)
+void set_track(struct kasan_track *track, gfp_t flags)
 {
 	track-&gt;pid =3D current-&gt;pid;
 	track-&gt;stack =3D save_stack(flags);
@@ -457,7 +457,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache,=
 void *object,
 		return false;
=20
 	set_track(&amp;get_alloc_info(cache, object)-&gt;free_track, GFP_NOWAIT);
-	quarantine_put(get_free_info(cache, object), cache);
+	quarantine_put(get_free_info(cache, tagged_object), cache);
=20
 	return IS_ENABLED(CONFIG_KASAN_GENERIC);
 }
@@ -614,6 +614,17 @@ void kasan_free_shadow(const struct vm_struct *vm)
 		vfree(kasan_mem_to_shadow(vm-&gt;addr));
 }
=20
+void kasan_cache_shrink(struct kmem_cache *cache)
+{
+	quarantine_remove_cache(cache);
+}
+
+void kasan_cache_shutdown(struct kmem_cache *cache)
+{
+	if (!__kmem_cache_empty(cache))
+		quarantine_remove_cache(cache);
+}
+
 #ifdef CONFIG_MEMORY_HOTPLUG
 static bool shadow_mapped(unsigned long addr)
 {
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 504c79363a34..5f579051dead 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -191,17 +191,6 @@ void check_memory_region(unsigned long addr, size_t si=
ze, bool write,
 	check_memory_region_inline(addr, size, write, ret_ip);
 }
=20
-void kasan_cache_shrink(struct kmem_cache *cache)
-{
-	quarantine_remove_cache(cache);
-}
-
-void kasan_cache_shutdown(struct kmem_cache *cache)
-{
-	if (!__kmem_cache_empty(cache))
-		quarantine_remove_cache(cache);
-}
-
 static void register_global(struct kasan_global *global)
 {
 	size_t aligned_size =3D round_up(global-&gt;size, KASAN_SHADOW_SCALE_SIZE=
);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3e0c11f7d7a1..6848a93660d9 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -95,9 +95,21 @@ struct kasan_alloc_meta {
 	struct kasan_track free_track;
 };
=20
+#ifdef CONFIG_KASAN_GENERIC
 struct qlist_node {
 	struct qlist_node *next;
 };
+#else
+struct qlist_object {
+	unsigned long addr;
+	unsigned int size;
+	struct kasan_alloc_meta free_track;
+};
+struct qlist_node {
+	struct qlist_object *qobject;
+	struct qlist_node *next;
+};
+#endif
 struct kasan_free_meta {
 	/* This field is used while the object is in the quarantine.
 	 * Otherwise it might be used for the allocator freelist.
@@ -133,16 +145,19 @@ void kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 void kasan_report_invalid_free(void *object, unsigned long ip);
=20
-#if defined(CONFIG_KASAN_GENERIC) &amp;&amp; \
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS) &amp;&a=
mp; \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
+
 void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache=
);
 void quarantine_reduce(void);
 void quarantine_remove_cache(struct kmem_cache *cache);
+void set_track(struct kasan_track *track, gfp_t flags);
 #else
 static inline void quarantine_put(struct kasan_free_meta *info,
 				struct kmem_cache *cache) { }
 static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
+static inline void set_track(struct kasan_track *track, gfp_t flags) {}
 #endif
=20
 #ifdef CONFIG_KASAN_SW_TAGS
@@ -151,6 +166,15 @@ void print_tags(u8 addr_tag, const void *addr);
=20
 u8 random_tag(void);
=20
+bool quarantine_find_object(void *object);
+
+int qobject_add_size(void);
+
+struct qlist_node *qobject_create(struct kasan_free_meta *info,
+		struct kmem_cache *cache);
+
+void qobject_free(struct qlist_node *qlink, struct kmem_cache *cache);
+
 #else
=20
 static inline void print_tags(u8 addr_tag, const void *addr) { }
@@ -160,6 +184,25 @@ static inline u8 random_tag(void)
 	return 0;
 }
=20
+static inline bool quarantine_find_object(void *object)
+{
+	return 0;
+}
+
+static inline int qobject_add_size(void)
+{
+	return 0;
+}
+
+static inline struct qlist_node *qobject_create(struct kasan_free_meta *in=
fo,
+		struct kmem_cache *cache)
+{
+	return 0;
+}
+
+static inline void qobject_free(struct qlist_node *qlink,
+		struct kmem_cache *cache) {}
+
 #endif
=20
 #ifndef arch_kasan_set_tag
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 978bc4a3eb51..f14c8dbec552 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -67,7 +67,10 @@ static void qlist_put(struct qlist_head *q, struct qlist=
_node *qlink,
 		q-&gt;tail-&gt;next =3D qlink;
 	q-&gt;tail =3D qlink;
 	qlink-&gt;next =3D NULL;
-	q-&gt;bytes +=3D size;
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+		q-&gt;bytes +=3D qobject_add_size();
+	else
+		q-&gt;bytes +=3D size;
 }
=20
 static void qlist_move_all(struct qlist_head *from, struct qlist_head *to)
@@ -139,13 +142,18 @@ static void *qlink_to_object(struct qlist_node *qlink=
, struct kmem_cache *cache)
=20
 static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 {
-	void *object =3D qlink_to_object(qlink, cache);
 	unsigned long flags;
+	struct kmem_cache *obj_cache =3D
+			cache ? cache :	qlink_to_cache(qlink);
+	void *object =3D qlink_to_object(qlink, obj_cache);
+
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+		qobject_free(qlink, cache);
=20
 	if (IS_ENABLED(CONFIG_SLAB))
 		local_irq_save(flags);
=20
-	___cache_free(cache, object, _THIS_IP_);
+	___cache_free(obj_cache, object, _THIS_IP_);
=20
 	if (IS_ENABLED(CONFIG_SLAB))
 		local_irq_restore(flags);
@@ -160,11 +168,9 @@ static void qlist_free_all(struct qlist_head *q, struc=
t kmem_cache *cache)
=20
 	qlink =3D q-&gt;head;
 	while (qlink) {
-		struct kmem_cache *obj_cache =3D
-			cache ? cache :	qlink_to_cache(qlink);
 		struct qlist_node *next =3D qlink-&gt;next;
=20
-		qlink_free(qlink, obj_cache);
+		qlink_free(qlink, cache);
 		qlink =3D next;
 	}
 	qlist_init(q);
@@ -187,7 +193,18 @@ void quarantine_put(struct kasan_free_meta *info, stru=
ct kmem_cache *cache)
 	local_irq_save(flags);
=20
 	q =3D this_cpu_ptr(&amp;cpu_quarantine);
-	qlist_put(q, &amp;info-&gt;quarantine_link, cache-&gt;size);
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS)) {
+		struct qlist_node *free_obj_info =3D qobject_create(info, cache);
+
+		if (!free_obj_info) {
+			local_irq_restore(flags);
+			return;
+		}
+		qlist_put(q, free_obj_info, cache-&gt;size);
+	} else {
+		qlist_put(q, &amp;info-&gt;quarantine_link, cache-&gt;size);
+	}
+
 	if (unlikely(q-&gt;bytes &gt; QUARANTINE_PERCPU_SIZE)) {
 		qlist_move_all(q, &amp;temp);
=20
@@ -327,3 +344,79 @@ void quarantine_remove_cache(struct kmem_cache *cache)
=20
 	synchronize_srcu(&amp;remove_cache_srcu);
 }
+
+#ifdef CONFIG_KASAN_SW_TAGS
+static struct kasan_alloc_meta object_free_track;
+
+struct kasan_alloc_meta *get_object_track(void)
+{
+	return &amp;object_free_track;
+}
+
+static bool qlist_find_object(struct qlist_head *from, void *addr)
+{
+	struct qlist_node *curr;
+	struct qlist_object *curr_obj;
+
+	if (unlikely(qlist_empty(from)))
+		return false;
+
+	curr =3D from-&gt;head;
+	while (curr) {
+		struct qlist_node *next =3D curr-&gt;next;
+
+		curr_obj =3D curr-&gt;qobject;
+		if (unlikely(((unsigned long)addr &gt;=3D curr_obj-&gt;addr)
+			&amp;&amp; ((unsigned long)addr &lt;
+					(curr_obj-&gt;addr + curr_obj-&gt;size)))) {
+			object_free_track =3D curr_obj-&gt;free_track;
+
+			return true;
+		}
+
+		curr =3D next;
+	}
+	return false;
+}
+
+static int per_cpu_find_object(void *arg)
+{
+	void *addr =3D arg;
+	struct qlist_head *q;
+
+	q =3D this_cpu_ptr(&amp;cpu_quarantine);
+	return qlist_find_object(q, addr);
+}
+
+struct cpumask cpu_allowed_mask __read_mostly;
+
+bool quarantine_find_object(void *addr)
+{
+	unsigned long flags, i;
+	bool find =3D false;
+	int cpu;
+
+	cpumask_copy(&amp;cpu_allowed_mask, cpu_online_mask);
+	for_each_cpu(cpu, &amp;cpu_allowed_mask) {
+		find =3D smp_call_on_cpu(cpu, per_cpu_find_object, addr, true);
+		if (find)
+			return true;
+	}
+
+	raw_spin_lock_irqsave(&amp;quarantine_lock, flags);
+	for (i =3D 0; i &lt; QUARANTINE_BATCHES; i++) {
+		if (qlist_empty(&amp;global_quarantine[i]))
+			continue;
+		find =3D qlist_find_object(&amp;global_quarantine[i], addr);
+		/* Scanning whole quarantine can take a while. */
+		raw_spin_unlock_irqrestore(&amp;quarantine_lock, flags);
+		cond_resched();
+		raw_spin_lock_irqsave(&amp;quarantine_lock, flags);
+	}
+	raw_spin_unlock_irqrestore(&amp;quarantine_lock, flags);
+
+	synchronize_srcu(&amp;remove_cache_srcu);
+
+	return find;
+}
+#endif
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ca9418fe9232..9cfabf2f0c40 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -150,18 +150,26 @@ static void describe_object_addr(struct kmem_cache *c=
ache, void *object,
 }
=20
 static void describe_object(struct kmem_cache *cache, void *object,
-				const void *addr)
+				const void *tagged_addr)
 {
+	void *untagged_addr =3D reset_tag(tagged_addr);
 	struct kasan_alloc_meta *alloc_info =3D get_alloc_info(cache, object);
=20
 	if (cache-&gt;flags &amp; SLAB_KASAN) {
-		print_track(&amp;alloc_info-&gt;alloc_track, &quot;Allocated&quot;);
-		pr_err(&quot;\n&quot;);
-		print_track(&amp;alloc_info-&gt;free_track, &quot;Freed&quot;);
-		pr_err(&quot;\n&quot;);
+		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) &amp;&amp;
+			quarantine_find_object((void *)tagged_addr)) {
+			alloc_info =3D get_object_track();
+			print_track(&amp;alloc_info-&gt;free_track, &quot;Freed&quot;);
+			pr_err(&quot;\n&quot;);
+		} else {
+			print_track(&amp;alloc_info-&gt;alloc_track, &quot;Allocated&quot;);
+			pr_err(&quot;\n&quot;);
+			print_track(&amp;alloc_info-&gt;free_track, &quot;Freed&quot;);
+			pr_err(&quot;\n&quot;);
+		}
 	}
=20
-	describe_object_addr(cache, object, addr);
+	describe_object_addr(cache, object, untagged_addr);
 }
=20
 static inline bool kernel_or_module_addr(const void *addr)
@@ -180,23 +188,25 @@ static inline bool init_task_stack_addr(const void *a=
ddr)
 			sizeof(init_thread_union.stack));
 }
=20
-static void print_address_description(void *addr)
+static void print_address_description(void *tagged_addr)
 {
-	struct page *page =3D addr_to_page(addr);
+	void *untagged_addr =3D reset_tag(tagged_addr);
+	struct page *page =3D addr_to_page(untagged_addr);
=20
 	dump_stack();
 	pr_err(&quot;\n&quot;);
=20
 	if (page &amp;&amp; PageSlab(page)) {
 		struct kmem_cache *cache =3D page-&gt;slab_cache;
-		void *object =3D nearest_obj(cache, page,	addr);
+		void *object =3D nearest_obj(cache, page,	untagged_addr);
=20
-		describe_object(cache, object, addr);
+		describe_object(cache, object, tagged_addr);
 	}
=20
-	if (kernel_or_module_addr(addr) &amp;&amp; !init_task_stack_addr(addr)) {
+	if (kernel_or_module_addr(untagged_addr) &amp;&amp;
+			!init_task_stack_addr(untagged_addr)) {
 		pr_err(&quot;The buggy address belongs to the variable:\n&quot;);
-		pr_err(&quot; %pS\n&quot;, addr);
+		pr_err(&quot; %pS\n&quot;, untagged_addr);
 	}
=20
 	if (page) {
@@ -314,7 +324,7 @@ void kasan_report(unsigned long addr, size_t size,
 	pr_err(&quot;\n&quot;);
=20
 	if (addr_has_shadow(untagged_addr)) {
-		print_address_description(untagged_addr);
+		print_address_description(tagged_addr);
 		pr_err(&quot;\n&quot;);
 		print_shadow_for_address(info.first_bad_addr);
 	} else {
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 63fca3172659..fa5d1e29003d 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -124,6 +124,70 @@ void check_memory_region(unsigned long addr, size_t si=
ze, bool write,
 	}
 }
=20
+int qobject_add_size(void)
+{
+	return sizeof(struct qlist_object);
+}
+
+static struct kmem_cache *qobject_to_cache(struct qlist_object *qobject)
+{
+	return virt_to_head_page(qobject)-&gt;slab_cache;
+}
+
+struct qlist_node *qobject_create(struct kasan_free_meta *info,
+						struct kmem_cache *cache)
+{
+	struct qlist_node *free_obj_info;
+	struct qlist_object *qobject_info;
+	struct kasan_alloc_meta *object_track;
+	void *object;
+
+	object =3D ((void *)info) - cache-&gt;kasan_info.free_meta_offset;
+	qobject_info =3D kmalloc(sizeof(struct qlist_object), GFP_NOWAIT);
+	if (!qobject_info)
+		return NULL;
+	qobject_info-&gt;addr =3D (unsigned long) object;
+	qobject_info-&gt;size =3D cache-&gt;object_size;
+	object_track =3D &amp;qobject_info-&gt;free_track;
+	set_track(&amp;object_track-&gt;free_track, GFP_NOWAIT);
+
+	free_obj_info =3D kmalloc(sizeof(struct qlist_node), GFP_NOWAIT);
+	if (!free_obj_info) {
+		unsigned long flags;
+		struct kmem_cache *qobject_cache =3D
+			qobject_to_cache(qobject_info);
+
+		if (IS_ENABLED(CONFIG_SLAB))
+			local_irq_save(flags);
+
+		___cache_free(qobject_cache, (void *)qobject_info, _THIS_IP_);
+
+		if (IS_ENABLED(CONFIG_SLAB))
+			local_irq_restore(flags);
+		return NULL;
+	}
+	free_obj_info-&gt;qobject =3D qobject_info;
+
+	return free_obj_info;
+}
+
+void qobject_free(struct qlist_node *qlink, struct kmem_cache *cache)
+{
+	struct qlist_object *qobject =3D qlink-&gt;qobject;
+	unsigned long flags;
+
+	struct kmem_cache *qobject_cache =3D
+			cache ? cache :	qobject_to_cache(qobject);
+
+	if (IS_ENABLED(CONFIG_SLAB))
+		local_irq_save(flags);
+
+	___cache_free(qobject_cache, (void *)qobject, _THIS_IP_);
+
+	if (IS_ENABLED(CONFIG_SLAB))
+		local_irq_restore(flags);
+}
+
 #define DEFINE_HWASAN_LOAD_STORE(size)					\
 	void __hwasan_load##size##_noabort(unsigned long addr)		\
 	{								\
diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
index 8eaf5f722271..8c8871b2cb09 100644
--- a/mm/kasan/tags_report.c
+++ b/mm/kasan/tags_report.c
@@ -36,7 +36,10 @@
=20
 const char *get_bug_type(struct kasan_access_info *info)
 {
-	return &quot;invalid-access&quot;;
+	if (quarantine_find_object((void *)info-&gt;access_addr))
+		return &quot;use-after-free&quot;;
+	else
+		return &quot;out-of-bounds&quot;;
 }
=20
 void *find_first_bad_addr(void *addr, size_t size)
diff --git a/mm/slub.c b/mm/slub.c
index 1b08fbcb7e61..11c54f3995c8 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3004,12 +3004,10 @@ static __always_inline void slab_free(struct kmem_c=
ache *s, struct page *page,
 		do_slab_free(s, page, head, tail, cnt, addr);
 }
=20
-#ifdef CONFIG_KASAN_GENERIC
 void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
 {
 	do_slab_free(cache, virt_to_head_page(x), x, NULL, 1, addr);
 }
-#endif
=20
 void kmem_cache_free(struct kmem_cache *s, void *x)
 {
--=20
2.18.0

</pre><!--type:text--><!--{--><pre>************* MEDIATEK Confidentiality N=
otice
 ********************
The information contained in this e-mail message (including any=20
attachments) may be confidential, proprietary, privileged, or otherwise
exempt from disclosure under applicable laws. It is intended to be=20
conveyed only to the designated recipient(s). Any use, dissemination,=20
distribution, printing, retaining or copying of this e-mail (including its=
=20
attachments) by unintended recipient(s) is strictly prohibited and may=20
be unlawful. If you are not an intended recipient of this e-mail, or believ=
e
=20
that you have received this e-mail in error, please notify the sender=20
immediately (by replying to this e-mail), delete any and all copies of=20
this e-mail (including any attachments) from your system, and do not
disclose the content of this e-mail to any other person. Thank you!
</pre><!--}-->

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To post to this group, send email to <a href=3D"mailto:kasan-dev@googlegrou=
ps.com">kasan-dev@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/1559027797-30303-1-git-send-email-walter-zh.wu%40media=
tek.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/1559027797-30303-1-git-send-email-walter-zh.wu%40mediatek.=
com</a>.<br />
For more options, visit <a href=3D"https://groups.google.com/d/optout">http=
s://groups.google.com/d/optout</a>.<br />

--__=_Part_Boundary_006_1170253316.1644507556
Content-Type: text/plain; charset="UTF-8"

This patch adds memory corruption identification at bug report for 
software tag-based mode, the report show whether it is "use-after-free" 
or "out-of-bound" error instead of "invalid-access" error.This will make  
it easier for programmers to see the memory corruption problem.

Now we extend the quarantine to support both generic and tag-based kasan. 
For tag-based kasan, the quarantine stores only freed object information 
to check if an object is freed recently. When tag-based kasan reports an 
error, we can check if the tagged addr is in the quarantine and make a 
good guess if the object is more like "use-after-free" or "out-of-bound".

Due to tag-based kasan, the tag values are stored in the shadow memory, 
all tag comparison failures are memory corruption. Even if those freed 
object have been deallocated, we still can get the memory corruption. 
So the freed object doesn't need to be kept in quarantine, it can be 
immediately released after calling kfree(). We only need the freed object 
information in quarantine, the error handler is able to use object 
information to know if it has been allocated or deallocated, therefore 
every slab memory corruption can be identified whether it's 
"use-after-free" or "out-of-bound".

The difference between generic kasan and tag-based kasan quarantine is 
slab memory usage. Tag-based kasan only stores freed object information 
rather than the object itself. So tag-based kasan quarantine memory usage 
is smaller than generic kasan. 


====== Benchmarks

The following numbers were collected in QEMU.
Both generic and tag-based KASAN were used in inline instrumentation mode
and no stack checking.

Boot time :
* ~1.5 sec for clean kernel
* ~3 sec for generic KASAN
* ~3.5  sec for tag-based KASAN
* ~3.5 sec for tag-based KASAN + corruption identification

Slab memory usage after boot :
* ~10500 kb  for clean kernel
* ~30500 kb  for generic KASAN
* ~12300 kb  for tag-based KASAN
* ~17100 kb  for tag-based KASAN + corruption identification


Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
---
 include/linux/kasan.h  |  20 +++++---
 mm/kasan/Makefile      |   4 +-
 mm/kasan/common.c      |  15 +++++-
 mm/kasan/generic.c     |  11 -----
 mm/kasan/kasan.h       |  45 ++++++++++++++++-
 mm/kasan/quarantine.c  | 107 ++++++++++++++++++++++++++++++++++++++---
 mm/kasan/report.c      |  36 +++++++++-----
 mm/kasan/tags.c        |  64 ++++++++++++++++++++++++
 mm/kasan/tags_report.c |   5 +-
 mm/slub.c              |   2 -
 10 files changed, 262 insertions(+), 47 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b40ea104dd36..bbb52a8bf4a9 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -83,6 +83,9 @@ size_t kasan_metadata_size(struct kmem_cache *cache);
 bool kasan_save_enable_multi_shot(void);
 void kasan_restore_multi_shot(bool enabled);
 
+void kasan_cache_shrink(struct kmem_cache *cache);
+void kasan_cache_shutdown(struct kmem_cache *cache);
+
 #else /* CONFIG_KASAN */
 
 static inline void kasan_unpoison_shadow(const void *address, size_t size) {}
@@ -153,20 +156,14 @@ static inline void kasan_remove_zero_shadow(void *start,
 static inline void kasan_unpoison_slab(const void *ptr) { }
 static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
+static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
+static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
 #endif /* CONFIG_KASAN */
 
 #ifdef CONFIG_KASAN_GENERIC
 
 #define KASAN_SHADOW_INIT 0
 
-void kasan_cache_shrink(struct kmem_cache *cache);
-void kasan_cache_shutdown(struct kmem_cache *cache);
-
-#else /* CONFIG_KASAN_GENERIC */
-
-static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
-static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
-
 #endif /* CONFIG_KASAN_GENERIC */
 
 #ifdef CONFIG_KASAN_SW_TAGS
@@ -180,6 +177,8 @@ void *kasan_reset_tag(const void *addr);
 void kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 
+struct kasan_alloc_meta *get_object_track(void);
+
 #else /* CONFIG_KASAN_SW_TAGS */
 
 static inline void kasan_init_tags(void) { }
@@ -189,6 +188,11 @@ static inline void *kasan_reset_tag(const void *addr)
 	return (void *)addr;
 }
 
+static inline struct kasan_alloc_meta *get_object_track(void)
+{
+	return 0;
+}
+
 #endif /* CONFIG_KASAN_SW_TAGS */
 
 #endif /* LINUX_KASAN_H */
diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 5d1065efbd47..03b0fe22ec55 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -16,6 +16,6 @@ CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
 CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
 CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
 
-obj-$(CONFIG_KASAN) := common.o init.o report.o
-obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
+obj-$(CONFIG_KASAN) := common.o init.o report.o quarantine.o
+obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o
 obj-$(CONFIG_KASAN_SW_TAGS) += tags.o tags_report.o
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 80bbe62b16cd..919f693a58ab 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -81,7 +81,7 @@ static inline depot_stack_handle_t save_stack(gfp_t flags)
 	return depot_save_stack(&trace, flags);
 }
 
-static inline void set_track(struct kasan_track *track, gfp_t flags)
+void set_track(struct kasan_track *track, gfp_t flags)
 {
 	track->pid = current->pid;
 	track->stack = save_stack(flags);
@@ -457,7 +457,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 		return false;
 
 	set_track(&get_alloc_info(cache, object)->free_track, GFP_NOWAIT);
-	quarantine_put(get_free_info(cache, object), cache);
+	quarantine_put(get_free_info(cache, tagged_object), cache);
 
 	return IS_ENABLED(CONFIG_KASAN_GENERIC);
 }
@@ -614,6 +614,17 @@ void kasan_free_shadow(const struct vm_struct *vm)
 		vfree(kasan_mem_to_shadow(vm->addr));
 }
 
+void kasan_cache_shrink(struct kmem_cache *cache)
+{
+	quarantine_remove_cache(cache);
+}
+
+void kasan_cache_shutdown(struct kmem_cache *cache)
+{
+	if (!__kmem_cache_empty(cache))
+		quarantine_remove_cache(cache);
+}
+
 #ifdef CONFIG_MEMORY_HOTPLUG
 static bool shadow_mapped(unsigned long addr)
 {
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 504c79363a34..5f579051dead 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -191,17 +191,6 @@ void check_memory_region(unsigned long addr, size_t size, bool write,
 	check_memory_region_inline(addr, size, write, ret_ip);
 }
 
-void kasan_cache_shrink(struct kmem_cache *cache)
-{
-	quarantine_remove_cache(cache);
-}
-
-void kasan_cache_shutdown(struct kmem_cache *cache)
-{
-	if (!__kmem_cache_empty(cache))
-		quarantine_remove_cache(cache);
-}
-
 static void register_global(struct kasan_global *global)
 {
 	size_t aligned_size = round_up(global->size, KASAN_SHADOW_SCALE_SIZE);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3e0c11f7d7a1..6848a93660d9 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -95,9 +95,21 @@ struct kasan_alloc_meta {
 	struct kasan_track free_track;
 };
 
+#ifdef CONFIG_KASAN_GENERIC
 struct qlist_node {
 	struct qlist_node *next;
 };
+#else
+struct qlist_object {
+	unsigned long addr;
+	unsigned int size;
+	struct kasan_alloc_meta free_track;
+};
+struct qlist_node {
+	struct qlist_object *qobject;
+	struct qlist_node *next;
+};
+#endif
 struct kasan_free_meta {
 	/* This field is used while the object is in the quarantine.
 	 * Otherwise it might be used for the allocator freelist.
@@ -133,16 +145,19 @@ void kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 void kasan_report_invalid_free(void *object, unsigned long ip);
 
-#if defined(CONFIG_KASAN_GENERIC) && \
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
+
 void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
 void quarantine_reduce(void);
 void quarantine_remove_cache(struct kmem_cache *cache);
+void set_track(struct kasan_track *track, gfp_t flags);
 #else
 static inline void quarantine_put(struct kasan_free_meta *info,
 				struct kmem_cache *cache) { }
 static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
+static inline void set_track(struct kasan_track *track, gfp_t flags) {}
 #endif
 
 #ifdef CONFIG_KASAN_SW_TAGS
@@ -151,6 +166,15 @@ void print_tags(u8 addr_tag, const void *addr);
 
 u8 random_tag(void);
 
+bool quarantine_find_object(void *object);
+
+int qobject_add_size(void);
+
+struct qlist_node *qobject_create(struct kasan_free_meta *info,
+		struct kmem_cache *cache);
+
+void qobject_free(struct qlist_node *qlink, struct kmem_cache *cache);
+
 #else
 
 static inline void print_tags(u8 addr_tag, const void *addr) { }
@@ -160,6 +184,25 @@ static inline u8 random_tag(void)
 	return 0;
 }
 
+static inline bool quarantine_find_object(void *object)
+{
+	return 0;
+}
+
+static inline int qobject_add_size(void)
+{
+	return 0;
+}
+
+static inline struct qlist_node *qobject_create(struct kasan_free_meta *info,
+		struct kmem_cache *cache)
+{
+	return 0;
+}
+
+static inline void qobject_free(struct qlist_node *qlink,
+		struct kmem_cache *cache) {}
+
 #endif
 
 #ifndef arch_kasan_set_tag
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 978bc4a3eb51..f14c8dbec552 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -67,7 +67,10 @@ static void qlist_put(struct qlist_head *q, struct qlist_node *qlink,
 		q->tail->next = qlink;
 	q->tail = qlink;
 	qlink->next = NULL;
-	q->bytes += size;
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+		q->bytes += qobject_add_size();
+	else
+		q->bytes += size;
 }
 
 static void qlist_move_all(struct qlist_head *from, struct qlist_head *to)
@@ -139,13 +142,18 @@ static void *qlink_to_object(struct qlist_node *qlink, struct kmem_cache *cache)
 
 static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 {
-	void *object = qlink_to_object(qlink, cache);
 	unsigned long flags;
+	struct kmem_cache *obj_cache =
+			cache ? cache :	qlink_to_cache(qlink);
+	void *object = qlink_to_object(qlink, obj_cache);
+
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+		qobject_free(qlink, cache);
 
 	if (IS_ENABLED(CONFIG_SLAB))
 		local_irq_save(flags);
 
-	___cache_free(cache, object, _THIS_IP_);
+	___cache_free(obj_cache, object, _THIS_IP_);
 
 	if (IS_ENABLED(CONFIG_SLAB))
 		local_irq_restore(flags);
@@ -160,11 +168,9 @@ static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)
 
 	qlink = q->head;
 	while (qlink) {
-		struct kmem_cache *obj_cache =
-			cache ? cache :	qlink_to_cache(qlink);
 		struct qlist_node *next = qlink->next;
 
-		qlink_free(qlink, obj_cache);
+		qlink_free(qlink, cache);
 		qlink = next;
 	}
 	qlist_init(q);
@@ -187,7 +193,18 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
 	local_irq_save(flags);
 
 	q = this_cpu_ptr(&cpu_quarantine);
-	qlist_put(q, &info->quarantine_link, cache->size);
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS)) {
+		struct qlist_node *free_obj_info = qobject_create(info, cache);
+
+		if (!free_obj_info) {
+			local_irq_restore(flags);
+			return;
+		}
+		qlist_put(q, free_obj_info, cache->size);
+	} else {
+		qlist_put(q, &info->quarantine_link, cache->size);
+	}
+
 	if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
 		qlist_move_all(q, &temp);
 
@@ -327,3 +344,79 @@ void quarantine_remove_cache(struct kmem_cache *cache)
 
 	synchronize_srcu(&remove_cache_srcu);
 }
+
+#ifdef CONFIG_KASAN_SW_TAGS
+static struct kasan_alloc_meta object_free_track;
+
+struct kasan_alloc_meta *get_object_track(void)
+{
+	return &object_free_track;
+}
+
+static bool qlist_find_object(struct qlist_head *from, void *addr)
+{
+	struct qlist_node *curr;
+	struct qlist_object *curr_obj;
+
+	if (unlikely(qlist_empty(from)))
+		return false;
+
+	curr = from->head;
+	while (curr) {
+		struct qlist_node *next = curr->next;
+
+		curr_obj = curr->qobject;
+		if (unlikely(((unsigned long)addr >= curr_obj->addr)
+			&& ((unsigned long)addr <
+					(curr_obj->addr + curr_obj->size)))) {
+			object_free_track = curr_obj->free_track;
+
+			return true;
+		}
+
+		curr = next;
+	}
+	return false;
+}
+
+static int per_cpu_find_object(void *arg)
+{
+	void *addr = arg;
+	struct qlist_head *q;
+
+	q = this_cpu_ptr(&cpu_quarantine);
+	return qlist_find_object(q, addr);
+}
+
+struct cpumask cpu_allowed_mask __read_mostly;
+
+bool quarantine_find_object(void *addr)
+{
+	unsigned long flags, i;
+	bool find = false;
+	int cpu;
+
+	cpumask_copy(&cpu_allowed_mask, cpu_online_mask);
+	for_each_cpu(cpu, &cpu_allowed_mask) {
+		find = smp_call_on_cpu(cpu, per_cpu_find_object, addr, true);
+		if (find)
+			return true;
+	}
+
+	raw_spin_lock_irqsave(&quarantine_lock, flags);
+	for (i = 0; i < QUARANTINE_BATCHES; i++) {
+		if (qlist_empty(&global_quarantine[i]))
+			continue;
+		find = qlist_find_object(&global_quarantine[i], addr);
+		/* Scanning whole quarantine can take a while. */
+		raw_spin_unlock_irqrestore(&quarantine_lock, flags);
+		cond_resched();
+		raw_spin_lock_irqsave(&quarantine_lock, flags);
+	}
+	raw_spin_unlock_irqrestore(&quarantine_lock, flags);
+
+	synchronize_srcu(&remove_cache_srcu);
+
+	return find;
+}
+#endif
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ca9418fe9232..9cfabf2f0c40 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -150,18 +150,26 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 }
 
 static void describe_object(struct kmem_cache *cache, void *object,
-				const void *addr)
+				const void *tagged_addr)
 {
+	void *untagged_addr = reset_tag(tagged_addr);
 	struct kasan_alloc_meta *alloc_info = get_alloc_info(cache, object);
 
 	if (cache->flags & SLAB_KASAN) {
-		print_track(&alloc_info->alloc_track, "Allocated");
-		pr_err("\n");
-		print_track(&alloc_info->free_track, "Freed");
-		pr_err("\n");
+		if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) &&
+			quarantine_find_object((void *)tagged_addr)) {
+			alloc_info = get_object_track();
+			print_track(&alloc_info->free_track, "Freed");
+			pr_err("\n");
+		} else {
+			print_track(&alloc_info->alloc_track, "Allocated");
+			pr_err("\n");
+			print_track(&alloc_info->free_track, "Freed");
+			pr_err("\n");
+		}
 	}
 
-	describe_object_addr(cache, object, addr);
+	describe_object_addr(cache, object, untagged_addr);
 }
 
 static inline bool kernel_or_module_addr(const void *addr)
@@ -180,23 +188,25 @@ static inline bool init_task_stack_addr(const void *addr)
 			sizeof(init_thread_union.stack));
 }
 
-static void print_address_description(void *addr)
+static void print_address_description(void *tagged_addr)
 {
-	struct page *page = addr_to_page(addr);
+	void *untagged_addr = reset_tag(tagged_addr);
+	struct page *page = addr_to_page(untagged_addr);
 
 	dump_stack();
 	pr_err("\n");
 
 	if (page && PageSlab(page)) {
 		struct kmem_cache *cache = page->slab_cache;
-		void *object = nearest_obj(cache, page,	addr);
+		void *object = nearest_obj(cache, page,	untagged_addr);
 
-		describe_object(cache, object, addr);
+		describe_object(cache, object, tagged_addr);
 	}
 
-	if (kernel_or_module_addr(addr) && !init_task_stack_addr(addr)) {
+	if (kernel_or_module_addr(untagged_addr) &&
+			!init_task_stack_addr(untagged_addr)) {
 		pr_err("The buggy address belongs to the variable:\n");
-		pr_err(" %pS\n", addr);
+		pr_err(" %pS\n", untagged_addr);
 	}
 
 	if (page) {
@@ -314,7 +324,7 @@ void kasan_report(unsigned long addr, size_t size,
 	pr_err("\n");
 
 	if (addr_has_shadow(untagged_addr)) {
-		print_address_description(untagged_addr);
+		print_address_description(tagged_addr);
 		pr_err("\n");
 		print_shadow_for_address(info.first_bad_addr);
 	} else {
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 63fca3172659..fa5d1e29003d 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -124,6 +124,70 @@ void check_memory_region(unsigned long addr, size_t size, bool write,
 	}
 }
 
+int qobject_add_size(void)
+{
+	return sizeof(struct qlist_object);
+}
+
+static struct kmem_cache *qobject_to_cache(struct qlist_object *qobject)
+{
+	return virt_to_head_page(qobject)->slab_cache;
+}
+
+struct qlist_node *qobject_create(struct kasan_free_meta *info,
+						struct kmem_cache *cache)
+{
+	struct qlist_node *free_obj_info;
+	struct qlist_object *qobject_info;
+	struct kasan_alloc_meta *object_track;
+	void *object;
+
+	object = ((void *)info) - cache->kasan_info.free_meta_offset;
+	qobject_info = kmalloc(sizeof(struct qlist_object), GFP_NOWAIT);
+	if (!qobject_info)
+		return NULL;
+	qobject_info->addr = (unsigned long) object;
+	qobject_info->size = cache->object_size;
+	object_track = &qobject_info->free_track;
+	set_track(&object_track->free_track, GFP_NOWAIT);
+
+	free_obj_info = kmalloc(sizeof(struct qlist_node), GFP_NOWAIT);
+	if (!free_obj_info) {
+		unsigned long flags;
+		struct kmem_cache *qobject_cache =
+			qobject_to_cache(qobject_info);
+
+		if (IS_ENABLED(CONFIG_SLAB))
+			local_irq_save(flags);
+
+		___cache_free(qobject_cache, (void *)qobject_info, _THIS_IP_);
+
+		if (IS_ENABLED(CONFIG_SLAB))
+			local_irq_restore(flags);
+		return NULL;
+	}
+	free_obj_info->qobject = qobject_info;
+
+	return free_obj_info;
+}
+
+void qobject_free(struct qlist_node *qlink, struct kmem_cache *cache)
+{
+	struct qlist_object *qobject = qlink->qobject;
+	unsigned long flags;
+
+	struct kmem_cache *qobject_cache =
+			cache ? cache :	qobject_to_cache(qobject);
+
+	if (IS_ENABLED(CONFIG_SLAB))
+		local_irq_save(flags);
+
+	___cache_free(qobject_cache, (void *)qobject, _THIS_IP_);
+
+	if (IS_ENABLED(CONFIG_SLAB))
+		local_irq_restore(flags);
+}
+
 #define DEFINE_HWASAN_LOAD_STORE(size)					\
 	void __hwasan_load##size##_noabort(unsigned long addr)		\
 	{								\
diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
index 8eaf5f722271..8c8871b2cb09 100644
--- a/mm/kasan/tags_report.c
+++ b/mm/kasan/tags_report.c
@@ -36,7 +36,10 @@
 
 const char *get_bug_type(struct kasan_access_info *info)
 {
-	return "invalid-access";
+	if (quarantine_find_object((void *)info->access_addr))
+		return "use-after-free";
+	else
+		return "out-of-bounds";
 }
 
 void *find_first_bad_addr(void *addr, size_t size)
diff --git a/mm/slub.c b/mm/slub.c
index 1b08fbcb7e61..11c54f3995c8 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3004,12 +3004,10 @@ static __always_inline void slab_free(struct kmem_cache *s, struct page *page,
 		do_slab_free(s, page, head, tail, cnt, addr);
 }
 
-#ifdef CONFIG_KASAN_GENERIC
 void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
 {
 	do_slab_free(cache, virt_to_head_page(x), x, NULL, 1, addr);
 }
-#endif
 
 void kmem_cache_free(struct kmem_cache *s, void *x)
 {
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1559027797-30303-1-git-send-email-walter-zh.wu%40mediatek.com.
For more options, visit https://groups.google.com/d/optout.

--__=_Part_Boundary_006_1170253316.1644507556--

--__=_Part_Boundary_005_2032766234.1374939665--

