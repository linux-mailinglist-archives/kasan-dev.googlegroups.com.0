Return-Path: <kasan-dev+bncBCS37NMQ3YHBBBH5ZX5QKGQEBNHZZGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id A396027D5D6
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 20:35:49 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id a81sf3379094lfd.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 11:35:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601404549; cv=pass;
        d=google.com; s=arc-20160816;
        b=xy61PDuqRDqDp1tYdzTaCePoKFOTLAxVeduPg9Eukv8NVL7IWu8G7zFHnsBDFjP1a0
         5wHIqttc40B08w06iZC2iD0b8CAl3KznkFWlof2tIJyH+74by7ZCZPaNjVR+5Fs297Pu
         x5+kbAo42uT1BCyFKZUky5zFUea8oq2XM3zR3cHeIEVel+NMgzlU7UrclH8Y2hMT3C1O
         tpyKTHDcazIHw1ZKSHSNon6lMU7wzLZ0r6G1bxEGtE53nOAVE3sy+TCXjm++X6TQNUC6
         34AIUvc901kOaLdvVw08bZo2MCl5RfXJEAzlbYm+1Vhfj3Jkl5L2DWI+IOXBn8Fpxdy1
         8gVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=VT490J7UimgVUyEPUR6oiLqYolYPStikgUnFS8DqWiI=;
        b=gqQ9Xrb/x4FW/ry99orbxYk71CCRsJfnB3+SS5XPcDqp1AQTrF+qA1SPVfs6bRFJ9C
         90jQ3ypJhlfoyB+/hTh+qTzfhCc4Nl66ungVDkrgrEX76lzlEnufmkhLh1f2MZtj0lfR
         G+sKVaAYoyorniolKYgNeE3W0wRfm7Ov4N5ktZgWBHgoLJuZh0LFDBV6OKp1Y1hCSR63
         1TZ9yKDE+HFCpW8SIV8zOPoxSw7sLgRnJrm3mUBG74hFQeX+0GB9Zh0QGJ0BYH/qLyjo
         VvukOwIuwmy1mBQ3NJj37pEjS6/EyYZQpFYcL2beQzCPngQYWNI8LrSENdRg9fMXgqio
         nrag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.67 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VT490J7UimgVUyEPUR6oiLqYolYPStikgUnFS8DqWiI=;
        b=IqVgZi0YPQa7wyr54z/x4cD3cfcroMMUbfqM/c83N7/bjILgSsKdA9J8UUpOkHsn0j
         Gw9oh+q/92u703/EnOnbjSvHyy8tXyYC3rhzHrX+rHlhw21eLzG6m2PtgUEgu9oHgGeX
         kEmS/XXXf8i4VD5X24gw/EOGt34Q2iRoxfJi9xUiC9m0o7xDLsj0hgP3sWOjVoibBxEr
         gp2/6EhrnFaqAu3DzN2UY7fyJOOGTJhhsqZk5eOleQfck7cHt1rfglplOsx0DJE4YNnX
         tESqRLpQ32jeAnQt7zYeW2cxqZQebMOhh8I7FWgEj/+Qtl9rTd8o3GCs1qxbZXdl4a7n
         RRhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VT490J7UimgVUyEPUR6oiLqYolYPStikgUnFS8DqWiI=;
        b=iyNoqsL8kRIoApPEEATVsQYwwGJDhIVQQussrNY4nbZS3IvMMlnLSl49hZ9ShZ+JaS
         zSbIj4w3Utan6YLwz/nrBXiFag130g4yp1hrp5oc+3PxVQ9f0MaYJVjN1XVrBIvSfRRK
         tG7uq85SjM920zWuet6Cdm310UhiuFZv4PVc26D/w/4ubrMh7wUvHpi7M8ETr85lY48n
         aMkQJ7IMZUXVG4CZ9Xnl92a4vq+kCTYle57tci8WBf7HwYkst5xT+buVJ/dUPsc/uNTR
         57JhoH5eSSXPzOCNKnU1Wp4jnJmId9Dm8puo0AVOYjQXITZqlt7Z6cvTUnFQ0UnYNRMy
         svPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532AKXUAnPGRiNIkw/hmWP7NJI7SK3zQGWPqr+TJjxLgTTpOgYkh
	nsNSTHvICg+WmQfDh6slKJk=
X-Google-Smtp-Source: ABdhPJzvP7N5YDj4tIgZ5C8b9JlLYLNZpeXtxdGSkJiWfAlyMov3tEMwVN0vunS+1EblvbklCpXe/g==
X-Received: by 2002:a2e:804f:: with SMTP id p15mr1653507ljg.199.1601404549215;
        Tue, 29 Sep 2020 11:35:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls1311654lfn.2.gmail; Tue, 29 Sep
 2020 11:35:48 -0700 (PDT)
X-Received: by 2002:ac2:4944:: with SMTP id o4mr1807328lfi.374.1601404548295;
        Tue, 29 Sep 2020 11:35:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601404548; cv=none;
        d=google.com; s=arc-20160816;
        b=jTPAzJRV/9IXibx2SwThNGmWaHMFTwCrBMPXX1GoDGJ/uevYPO813P8xUAM3/TY1nq
         DkFsQGDbjIhSBqXXdvqBJjaU3oLQT3FFGQoY5lZHlQcJQ/kaXxMfI/VuH1AzFQM8++e+
         65Sfq5fJxztMFnjT+5uyJcDoGpYxuSt92xb3l3WDQmEid90vlVkaN2qEgWUyBhz7Lui+
         wglFyn8Em7n2g4sy9q4+xGsXt10asqT5QtWDXkS3Oikvj+6BgLBC2CDhSbHCsaer2Kce
         FFy9PYtajuAZDOgw9wTLFcA5SsS7eiSDTAjMYfvIIZbSTIHj7sh5wF4xpdANM6Ni5FXp
         ruNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=MskjPp6ZpujaNwi4yQltgMjSnkxLjmoI3z/cZXeO2Hw=;
        b=vnJXkHhPZ4VGDrvVVO1DNYlDTvfU9vFEizsLUXIxsEvYsBqxcDkgGGoAAFzkrQESiO
         NyvrlOJkVvYIvck/5DCRNJds/xG3pYhigXAitXmOID8U+vocg2FEP2TGeBHWJzzVdmrT
         lqRQsBiQI1zIcZ8Ue4eo80kkLKBP7V2g1mGIHRX+rkqbNsiQlUU/F60AIgMiPuDtF74H
         i57UuKWVY/nTcG44WQWn5lEgxrRctnMIipmagFMPECUwPTpF4xNDK4KjEQXeGOqXwms9
         zUHUbUZb9/f3bIgEAY0IvzvWoag/9Znl0KXlD6z4EO4PtQyOJhj0lPsbpUBZGrNPOQcn
         N3Mw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.67 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wm1-f67.google.com (mail-wm1-f67.google.com. [209.85.128.67])
        by gmr-mx.google.com with ESMTPS id r6si300163lji.4.2020.09.29.11.35.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 11:35:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.67 as permitted sender) client-ip=209.85.128.67;
Received: by mail-wm1-f67.google.com with SMTP id a9so5895214wmm.2
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 11:35:48 -0700 (PDT)
X-Received: by 2002:a05:600c:21c4:: with SMTP id x4mr6092766wmj.107.1601404547746;
        Tue, 29 Sep 2020 11:35:47 -0700 (PDT)
Received: from localhost.localdomain ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id b188sm12151271wmb.2.2020.09.29.11.35.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Sep 2020 11:35:47 -0700 (PDT)
From: Alexander Popov <alex.popov@linux.com>
To: Kees Cook <keescook@chromium.org>,
	Jann Horn <jannh@google.com>,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Patrick Bellasi <patrick.bellasi@arm.com>,
	David Howells <dhowells@redhat.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Laura Abbott <labbott@redhat.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Daniel Micay <danielmicay@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Matthew Wilcox <willy@infradead.org>,
	Pavel Machek <pavel@denx.de>,
	Valentin Schneider <valentin.schneider@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	kernel-hardening@lists.openwall.com,
	linux-kernel@vger.kernel.org,
	Alexander Popov <alex.popov@linux.com>
Cc: notify@kernel.org
Subject: [PATCH RFC v2 2/6] mm/slab: Perform init_on_free earlier
Date: Tue, 29 Sep 2020 21:35:09 +0300
Message-Id: <20200929183513.380760-3-alex.popov@linux.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20200929183513.380760-1-alex.popov@linux.com>
References: <20200929183513.380760-1-alex.popov@linux.com>
MIME-Version: 1.0
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.67 as
 permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
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

Currently in CONFIG_SLAB init_on_free happens too late, and heap
objects go to the heap quarantine being dirty. Lets move memory
clearing before calling kasan_slab_free() to fix that.

Signed-off-by: Alexander Popov <alex.popov@linux.com>
---
 mm/slab.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/mm/slab.c b/mm/slab.c
index 3160dff6fd76..5140203c5b76 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3414,6 +3414,9 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
 static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
 					 unsigned long caller)
 {
+	if (unlikely(slab_want_init_on_free(cachep)))
+		memset(objp, 0, cachep->object_size);
+
 	/* Put the object into the quarantine, don't touch it for now. */
 	if (kasan_slab_free(cachep, objp, _RET_IP_))
 		return;
@@ -3432,8 +3435,6 @@ void ___cache_free(struct kmem_cache *cachep, void *objp,
 	struct array_cache *ac = cpu_cache_get(cachep);
 
 	check_irq_off();
-	if (unlikely(slab_want_init_on_free(cachep)))
-		memset(objp, 0, cachep->object_size);
 	kmemleak_free_recursive(objp, cachep->flags);
 	objp = cache_free_debugcheck(cachep, objp, caller);
 	memcg_slab_free_hook(cachep, virt_to_head_page(objp), objp);
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929183513.380760-3-alex.popov%40linux.com.
